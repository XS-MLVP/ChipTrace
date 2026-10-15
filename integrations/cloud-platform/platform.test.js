'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const { ChipTracePlugin } = require('./plugin');
const { createPlatformServer } = require('./server');
const { ChipTraceClient } = require('./client');

const run = promisify(execFile);
const binary = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/debug/chiptrace');

async function waitFor(plugin, id) {
  const deadline = Date.now() + 30000;
  for (;;) {
    const job = plugin.getJob(id);
    if (job.status === 'completed' || job.status === 'failed') return job;
    assert.ok(Date.now() < deadline, `job ${id} timed out: ${JSON.stringify(job)}`);
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

async function fixture(root) {
  const output = path.join(root, 'fixture');
  const result = await run(binary, ['self-test', '--fixture-output', output], { maxBuffer: 16 * 1024 * 1024 });
  const value = JSON.parse(result.stdout);
  assert.equal(value.ok, true, result.stderr);
  return { root: output, captureRoot: path.join(output, 'capture'), objectRoot: path.join(output, 'raw-object-store'), usage: path.join(output, 'sub2api-usage.jsonl') };
}

function decodeProjectionJsonl(bytes) {
  const text = zlib.zstdDecompressSync(bytes).toString('utf8');
  return text.trim() ? text.trim().split('\n').map(line => JSON.parse(line)) : [];
}

test('inspection and paged Turns preserve unknown source records without claiming delivery', { timeout: 60000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-context-'));
  let app;
  t.after(async () => { if (app) await app.close(); await fs.rm(root, { recursive: true, force: true }); });
  const data = await fixture(root);
  const marker = 'private-unknown-session-content';
  const batch = (endpoint, raw) => {
    const rawJson = JSON.stringify(raw);
    return { captureId: `cap-unknown-${endpoint}`, recordType: 'telemetry_batch', telemetryBatch: {
      schema_version: 'chiptrace.telemetry-batch.v1', endpoint, raw_json: rawJson,
      raw_bytes: Buffer.byteLength(rawJson), raw_sha256: crypto.createHash('sha256').update(rawJson).digest('hex'),
      source_records: 1, derived_captures: 0, unknown_events: 0, conversion_errors: [],
    } };
  };
  const extra = [
    batch('otlp_logs', { resourceLogs: [{ scopeLogs: [{ logRecords: [{
      body: { stringValue: marker }, attributes: [{ key: 'event.name', value: { stringValue: 'bootstrap' } }],
    }] }] }] }),
    batch('otlp_traces', { resourceSpans: [{ scopeSpans: [{ spans: [{
      name: 'bootstrap', traceId: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', spanId: 'eeeeeeeeeeeeeeee',
    }] }] }] }),
  ];
  const segmentsRoot = path.join(data.captureRoot, 'segments');
  const segments = (await fs.readdir(segmentsRoot)).filter(name => name.endsWith('.sealed.ndjson')).sort();
  assert.ok(segments.length > 0);
  const segment = path.join(segmentsRoot, segments.at(-1));
  await fs.appendFile(segment, extra.map(value => JSON.stringify(value)).join('\n') + '\n');
  const bytes = await fs.readFile(segment);
  const plugin = new ChipTracePlugin({ root: path.join(root, 'platform'), captureRoot: data.captureRoot,
    objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace' });
  const token = 'platform-test-token-with-at-least-32-bytes';
  app = await createPlatformServer({ plugin, token });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  const client = new ChipTraceClient({ baseUrl: `http://127.0.0.1:${app.server.address().port}`, token });
  await client.submit({ id: 'archive-unknown', kind: 'archive', archive_id: 'raw-unknown' });
  assert.equal((await client.wait('archive-unknown')).status, 'completed');
  await client.submit({ id: 'inspect-unknown', kind: 'inspect', archive_id: 'raw-unknown', session_id: 'thread-self-test' });
  const inspected = await client.wait('inspect-unknown');
  assert.equal(inspected.status, 'completed');
  assert.equal(inspected.result.delivery_ready, false);
  assert.equal(inspected.result.validation_status, 'not_ready');
  assert.equal(inspected.result.session.delivery_ready, true);
  assert.equal(inspected.result.integrity.delivery_ready, true);
  const audit = inspected.result.source_context_audit;
  assert.equal(audit.schema_version, 'chiptrace.source-context-audit.v2');
  assert.equal(audit.session_id, 'thread-self-test');
  assert.equal(audit.sources.otlp_logs.unknown_session_records, 1);
  assert.equal(audit.sources.otlp_traces.unknown_session_records, 1);
  assert.equal(audit.unscoped_otlp_records, 0);
  assert.equal(audit.sample_limit, 0);
  assert.deepEqual(audit.samples, []);
  assert.equal(JSON.stringify(inspected.result).includes(marker), false);
  const page = await client.getTurns('inspect-unknown', { offset: 0, limit: 1 });
  assert.equal(page.delivery_ready, false);
  assert.equal(page.summary.delivery_ready, true);
  assert.equal(page.total, 5);
  await client.putUsageLog('unknown-usage', await fs.readFile(data.usage));
  await client.submit({ id: 'export-unknown', kind: 'export', archive_id: 'raw-unknown',
    session_id: 'thread-self-test', release_id: 'release-unknown', usage_log_ids: ['unknown-usage'] });
  const exported = await client.wait('export-unknown');
  assert.equal(exported.status, 'failed');
  assert.equal(exported.error.exit_code, 1);
  assert.match(exported.error.message, /source context audit .* has unresolved records/);

  await app.close();
  app = null;
  const storedFile = path.join(root, 'platform/jobs/inspect-unknown.json');
  const legacy = JSON.parse(await fs.readFile(storedFile, 'utf8'));
  legacy.result.delivery_ready = true;
  const reopen = async bytes => {
    await fs.writeFile(storedFile, bytes);
    app = await createPlatformServer({ plugin: new ChipTracePlugin({ root: path.join(root, 'platform'),
      captureRoot: data.captureRoot, objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace' }), token });
    await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
    return new ChipTraceClient({ baseUrl: `http://127.0.0.1:${app.server.address().port}`, token });
  };
  const inconsistentBytes = Buffer.from(JSON.stringify(legacy));
  const inconsistentClient = await reopen(inconsistentBytes);
  assert.equal((await inconsistentClient.getTurns('inspect-unknown')).delivery_ready, false);
  assert.deepEqual(await fs.readFile(storedFile), inconsistentBytes);
  await app.close();
  app = null;
  delete legacy.result.source_context_audit;
  const legacyBytes = Buffer.from(JSON.stringify(legacy));
  const restarted = await reopen(legacyBytes);
  const legacyPage = await restarted.getTurns('inspect-unknown');
  assert.equal(legacyPage.delivery_ready, false);
  assert.equal(legacyPage.summary.delivery_ready, true);
  assert.deepEqual(await fs.readFile(storedFile), legacyBytes);
  assert.deepEqual(await fs.readFile(segment), bytes);
});

test('HTTP service and SDK run the real CLI archive/restore/inspect/export path', { timeout: 60000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-'));
  let app;
  t.after(async () => { if (app) await app.close(); await fs.rm(root, { recursive: true, force: true }); });
  const data = await fixture(root);
  const plugin = new ChipTracePlugin({ root: path.join(root, 'platform'), captureRoot: data.captureRoot, objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace', concurrency: 2 });
  const token = 'platform-test-token-with-at-least-32-bytes';
  app = await createPlatformServer({ plugin, token });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${app.server.address().port}`;
  const client = new ChipTraceClient({ baseUrl, token });
  assert.equal(plugin.health().ok, true);
  assert.equal((await fetch(`${baseUrl}/v1/jobs`)).status, 401);
  assert.equal((await fetch(`${baseUrl}/health`)).status, 200);
  await assert.rejects(client.submit({ id: '../outside', kind: 'restore', archive_id: 'a' }), error => error.status === 400);
  await assert.rejects(client.submit({ id: 'paths', kind: 'archive', archive_id: 'a', output: '/tmp/outside' }), error => error.status === 400);
  await assert.rejects(client.request('/v1/jobs', { method: 'POST', body: '{'.repeat(32769) }), error => error.status === 413);
  await assert.rejects(client.request('/v1/jobs', { method: 'POST', body: Buffer.from([123, 34, 120, 34, 58, 34, 195, 34, 125]) }), error => error.status === 400);
  await assert.rejects(client.putUsageLog('bad-utf8', Buffer.from([123, 34, 120, 34, 58, 34, 195, 34, 125])), error => error.status === 400);
  await assert.rejects(client.putUsageLog('empty', Buffer.from('\n')), error => error.status === 400);
  await assert.rejects(client.listJobs({ limit: 101 }), error => error.status === 400);

  const archive = await client.submit({ id: 'archive-job', kind: 'archive', archive_id: 'self-test-raw' });
  assert.equal((await client.wait(archive.request.id)).status, 'completed');
  assert.equal((await client.submit({ id: 'archive-job', kind: 'archive', archive_id: 'self-test-raw' })).duplicate, true);
  await assert.rejects(client.submit({ id: 'archive-job', kind: 'archive', archive_id: 'another' }), error => error.status === 409);

  const restored = await client.submit({ id: 'restore-job', kind: 'restore', archive_id: 'self-test-raw' });
  const inspected = await client.submit({ id: 'inspect-job', kind: 'inspect', archive_id: 'self-test-raw', session_id: 'thread-self-test' });
  assert.equal((await client.wait(restored.request.id)).status, 'completed');
  const inspectedJob = await client.wait(inspected.request.id);
  assert.equal(inspectedJob.status, 'completed');
  assert.equal(inspectedJob.result.delivery_ready, true);
  assert.equal(inspectedJob.result.validation_status, 'delivery_ready');
  assert.equal(inspectedJob.result.source_context_audit.schema_version, 'chiptrace.source-context-audit.v2');
  assert.equal(inspectedJob.result.source_context_audit.session_id, 'thread-self-test');
  assert.equal(inspectedJob.result.source_context_audit.sources.otlp_logs.unknown_session_records, 0);
  assert.equal(inspectedJob.result.source_context_audit.sources.otlp_traces.unknown_session_records, 0);
  const page = await client.getTurns('inspect-job', { offset: 0, limit: 1 });
  assert.equal(page.delivery_ready, true);
  assert.equal(page.total, page.summary.native_turns);
  assert.equal(page.total, 5);
  assert.equal(page.summary.schema_version, 'chiptrace.session-view.v2');
  assert.equal(page.summary.turn_source_coverage_complete, true);
  assert.equal(page.summary.incomplete_turns, 0);
  assert.equal(page.summary.delivery_ready, true);
  assert.deepEqual(page.summary.unscoped_source_records, {});
  assert.ok(page.summary.turns === undefined);
  assert.equal(page.turns.length, Math.min(1, page.total));
  assert.equal(Object.prototype.hasOwnProperty.call(page.summary, 'turns'), false);
  assert.equal(page.turns[0].raw_capture_refs.length > 0, true);
  const allTurns = await client.getTurns('inspect-job', { offset: 0, limit: 100 });
  assert.equal(allTurns.turns.length, page.total);
  assert.equal(allTurns.turns.reduce((sum, turn) => sum + turn.model_interactions, 0), page.summary.model_interactions);
  assert.equal(allTurns.turns.reduce((sum, turn) => sum + turn.tool_execution_records, 0), page.summary.tool_execution_records);

  const inspectedProjection = inspectedJob.result.interaction_projection;
  assert.equal(inspectedProjection.schema_version, 'chiptrace.interaction-projection.v1');
  assert.equal(inspectedProjection.session_id, 'thread-self-test');
  assert.equal(inspectedProjection.interactions, page.summary.model_interactions);
  assert.ok(inspectedProjection.runtime_spans > 0);
  assert.ok(inspectedProjection.links > 0);
  const projectionManifestResponse = await client.downloadProjection('inspect-job', 'manifest');
  assert.equal(projectionManifestResponse.headers.get('content-type'), 'application/json; charset=utf-8');
  const projectionManifest = await projectionManifestResponse.json();
  assert.equal(projectionManifest.schema_version, inspectedProjection.schema_version);
  assert.deepEqual(projectionManifest.parts, inspectedProjection.parts);
  const turnById = new Map(allTurns.turns.map(turn => [`${turn.session_id}/${turn.turn_id}`, turn]));
  const downloadedProjection = {};
  for (const [part, file] of Object.entries({
    interactions: 'interactions/model-interactions.jsonl.zst',
    runtime: 'runtime/runtime-spans.jsonl.zst',
    links: 'links/interaction-links.jsonl.zst',
  })) {
    const response = await client.downloadProjection('inspect-job', part);
    const bytes = Buffer.from(await response.arrayBuffer());
    const metadata = inspectedProjection.parts.find(item => item.file === file);
    assert.ok(metadata);
    assert.equal(bytes.length, metadata.bytes);
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), metadata.sha256);
    assert.equal(response.headers.get('x-content-sha256'), metadata.sha256);
    if (part !== 'manifest') downloadedProjection[part] = decodeProjectionJsonl(bytes);
  }
  assert.equal(downloadedProjection.interactions.length, inspectedProjection.interactions);
  for (const interaction of downloadedProjection.interactions) {
    const key = `${interaction.trace_context.session_id}/${interaction.trace_context.turn_id}`;
    const turn = turnById.get(key);
    assert.ok(turn, `interaction is not assigned to a persisted Turn: ${key}`);
    assert.ok(interaction.raw_capture_refs.length > 0);
    const refs = new Set(turn.raw_capture_refs);
    for (const ref of interaction.raw_capture_refs) assert.ok(refs.has(ref.capture_id));
  }
  assert.equal(downloadedProjection.runtime.length, inspectedProjection.runtime_spans);
  const toolSpansByTurn = new Map();
  for (const span of downloadedProjection.runtime) {
    if (span.span_kind !== 'tool_execution') continue;
    const key = `${span.trace_context.session_id}/${span.trace_context.turn_id}`;
    const turn = turnById.get(key);
    assert.ok(turn, `tool span is not assigned to a persisted Turn: ${key}`);
    assert.ok(span.raw_capture_refs.length > 0);
    const refs = new Set(turn.raw_capture_refs);
    for (const ref of span.raw_capture_refs) assert.ok(refs.has(ref));
    toolSpansByTurn.set(key, (toolSpansByTurn.get(key) || 0) + 1);
  }
  for (const turn of allTurns.turns.filter(item => item.tool_execution_records > 0)) {
    assert.ok(toolSpansByTurn.get(`${turn.session_id}/${turn.turn_id}`) > 0);
  }
  assert.equal(downloadedProjection.links.length, inspectedProjection.links);
  await assert.rejects(client.downloadProjection('inspect-job', 'unknown'), error => error.status === 404);
  const projectionPartPath = path.join(root, 'platform/work/inspect-job/projection/interactions/model-interactions.jsonl.zst');
  const originalProjectionPart = await fs.readFile(projectionPartPath);
  const tamperedProjectionPart = Buffer.from(originalProjectionPart);
  tamperedProjectionPart[0] ^= 1;
  await fs.writeFile(projectionPartPath, tamperedProjectionPart);
  await assert.rejects(client.downloadProjection('inspect-job', 'interactions'), error => error.status === 422 && error.code === 'ARTIFACT_CHANGED');
  await fs.writeFile(projectionPartPath, originalProjectionPart);

  const usage = await fs.readFile(data.usage);
  assert.equal((await client.putUsageLog('usage-1', usage)).duplicate, false);
  assert.equal((await client.putUsageLog('usage-1', usage)).duplicate, true);
  await assert.rejects(client.putUsageLog('usage-1', Buffer.from('{"different":true}\n')), error => error.status === 409);
  const exported = await client.submit({ id: 'export-job', kind: 'export', archive_id: 'self-test-raw', session_id: 'thread-self-test', release_id: 'platform-release', usage_log_ids: ['usage-1'] });
  const exportJob = await client.wait(exported.request.id);
  assert.equal(exportJob.status, 'completed', JSON.stringify(exportJob.error));
  assert.equal(exportJob.result.score, 100);
  assert.equal(exportJob.result.session_view.native_turns, 5);
  assert.equal(exportJob.result.source_context_audit.schema_version, 'chiptrace.source-context-audit.v2');
  assert.equal(exportJob.result.source_context_audit.session_id, 'thread-self-test');
  assert.equal(exportJob.result.source_context_audit.unscoped_otlp_records, 0);
  for (const counts of Object.values(exportJob.result.source_context_audit.sources)) {
    assert.equal(counts.unscoped_turn_records, 0);
    assert.equal(counts.unknown_session_records, 0);
  }
  assert.equal(exportJob.result.effective_turns, 10);
  assert.ok(exportJob.artifacts.length > 0);
  const artifact = exportJob.artifacts[0];
  const download = await client.download('export-job', artifact.file);
  const bytes = Buffer.from(await download.arrayBuffer());
  assert.equal(bytes.length, artifact.bytes);
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), artifact.sha256);
  assert.equal(download.headers.get('x-content-sha256'), artifact.sha256);
  await assert.rejects(client.download('export-job', 'nonexistent.tar.gz'), error => error.status === 404);
  const jobFile = JSON.parse(await fs.readFile(path.join(root, 'platform/jobs/inspect-job.json'), 'utf8'));
  assert.equal(jobFile.result.session.turns, undefined);
  const turnFile = path.join(root, 'platform/work/inspect-job/turns.jsonl');
  const originalTurns = await fs.readFile(turnFile);
  const corruptedTurns = Buffer.from(originalTurns);
  corruptedTurns[0] ^= 1;
  await fs.writeFile(turnFile, corruptedTurns);
  await assert.rejects(client.getTurns('inspect-job'), error => error.status === 422 && error.code === 'ARTIFACT_CHANGED');
  await fs.writeFile(turnFile, originalTurns);
});

test('platform plugin persists failure and recovers queued work after restart', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-recovery-'));
  let recovered;
  let plugin;
  t.after(async () => { if (recovered) await recovered.close(); if (plugin) await plugin.close(); await fs.rm(root, { recursive: true, force: true }); });
  const data = await fixture(root);
  const platformRoot = path.join(root, 'platform');
  plugin = new ChipTracePlugin({ root: platformRoot, captureRoot: data.captureRoot, objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace', concurrency: 1 });
  await plugin.start();
  const failed = await plugin.submit({ id: 'missing-archive', kind: 'restore', archive_id: 'definitely-missing' });
  const failedJob = await waitFor(plugin, failed.request.id);
  assert.equal(failedJob.status, 'failed');
  assert.equal(failedJob.error.exit_code, 1);
  await plugin.submit({ id: 'recovered-archive', kind: 'archive', archive_id: 'self-test-raw' });
  await plugin.close();
  assert.equal(plugin.getJob('recovered-archive').status, 'queued');

  recovered = new ChipTracePlugin({ root: platformRoot, captureRoot: data.captureRoot, objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace', concurrency: 1 });
  await recovered.start();
  assert.equal((await waitFor(recovered, 'recovered-archive')).status, 'completed');
  assert.equal(recovered.getJob('recovered-archive').attempt, 2);
  assert.equal(recovered.getJob('missing-archive').status, 'failed');
});

test('writer lock excludes a second plugin and lock loss gates new jobs', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-lock-'));
  const first = new ChipTracePlugin({ root, binary });
  const second = new ChipTracePlugin({ root, binary });
  t.after(async () => { await first.close(); await second.close(); await fs.rm(root, { recursive: true, force: true }); });
  await first.start();
  await assert.rejects(second.start(), error => error.code === 'WRITER_LOCK');
  first.lockProcess.kill('SIGKILL');
  await first.lockClosed;
  assert.equal(first.health().ok, false);
  assert.equal(first.health().failure.code, 'WRITER_LOCK');
  await assert.rejects(first.submit({ id: 'locked-out', kind: 'restore', archive_id: 'a' }), error => error.status === 503);
});

test('failed durable ACK degrades health and cannot expose completed work', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-disk-failure-'));
  const plugin = new ChipTracePlugin({ root, binary });
  t.after(async () => { await plugin.close(); await fs.rm(root, { recursive: true, force: true }); });
  await plugin.start();
  await fs.rename(path.join(root, 'jobs'), path.join(root, 'saved-jobs'));
  await assert.rejects(plugin.submit({ id: 'no-ack', kind: 'restore', archive_id: 'a' }), error => error.status === 503 && error.code === 'STORAGE_FAILURE');
  assert.equal(plugin.health().ok, false);
  assert.equal(plugin.health().jobs, 0);
  await fs.rename(path.join(root, 'saved-jobs'), path.join(root, 'jobs'));
  await plugin.close();
  await plugin.start();
  assert.equal(plugin.health().ok, true);
  await plugin.submit({ id: 'real-failure', kind: 'restore', archive_id: 'missing' });
  const failed = await waitFor(plugin, 'real-failure');
  assert.equal(failed.status, 'failed');
  assert.equal(failed.error.exit_code, 1);
});

test('bounded history applies backpressure while identical job retries remain available', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-capacity-'));
  const plugin = new ChipTracePlugin({ root, binary, maxJobs: 1, maxQueuedJobs: 1 });
  t.after(async () => { await plugin.close(); await fs.rm(root, { recursive: true, force: true }); });
  const request = { id: 'first', kind: 'restore', archive_id: 'missing' };
  await plugin.submit(request);
  assert.equal((await waitFor(plugin, 'first')).status, 'failed');
  await assert.rejects(plugin.submit({ id: 'next', kind: 'restore', archive_id: 'missing' }), error => error.status === 503 && error.code === 'CAPACITY');
  assert.equal((await plugin.submit(request)).duplicate, true);
  assert.equal(plugin.health().ok, true);
  assert.equal((await fs.readdir(path.join(root, 'jobs'))).filter(file => file.endsWith('.json')).length, 1);
});
