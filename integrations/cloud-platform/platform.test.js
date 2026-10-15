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
  const plugin = new ChipTracePlugin({ projectId: 'project-test', root: path.join(root, 'platform'), captureRoot: data.captureRoot,
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
    app = await createPlatformServer({ plugin: new ChipTracePlugin({ projectId: 'project-test', root: path.join(root, 'platform'),
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

test('platform inspection and export reject conflicting duplicate native identities', { timeout: 60000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-duplicates-'));
  let app;
  t.after(async () => { if (app) await app.close(); await fs.rm(root, { recursive: true, force: true }); });
  const data = await fixture(root);
  const marker = 'private-duplicate-native-identity';
  const raw = { resourceLogs: [{ scopeLogs: [{ logRecords: [{
    body: { stringValue: marker },
    attributes: [
      { key: 'event.name', value: { stringValue: 'codex.sse_event' } },
      { key: 'conversation.id', value: { stringValue: marker } },
      { key: 'conversation.id', value: { stringValue: 'thread-self-test' } },
      { key: 'turn.id', value: { stringValue: 'turn-self-test' } },
    ],
  }] }] }] };
  const rawJson = JSON.stringify(raw);
  const capture = { captureId: 'cap-conflicting-native-identity', recordType: 'telemetry_batch', telemetryBatch: {
    schema_version: 'chiptrace.telemetry-batch.v1', endpoint: 'otlp_logs', raw_json: rawJson,
    raw_bytes: Buffer.byteLength(rawJson), raw_sha256: crypto.createHash('sha256').update(rawJson).digest('hex'),
    source_records: 1, derived_captures: 0, unknown_events: 0, conversion_errors: [],
  } };
  const segmentsRoot = path.join(data.captureRoot, 'segments');
  const segments = (await fs.readdir(segmentsRoot)).filter(name => name.endsWith('.sealed.ndjson')).sort();
  assert.ok(segments.length > 0);
  const segment = path.join(segmentsRoot, segments.at(-1));
  await fs.appendFile(segment, JSON.stringify(capture) + '\n');
  const bytes = await fs.readFile(segment);
  const plugin = new ChipTracePlugin({ projectId: 'project-test', root: path.join(root, 'platform'), captureRoot: data.captureRoot,
    objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace' });
  const token = 'platform-test-token-with-at-least-32-bytes';
  app = await createPlatformServer({ plugin, token });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  const client = new ChipTraceClient({ baseUrl: `http://127.0.0.1:${app.server.address().port}`, token });
  await client.submit({ id: 'archive-conflict', kind: 'archive', archive_id: 'raw-conflict' });
  assert.equal((await client.wait('archive-conflict')).status, 'completed');
  await client.submit({ id: 'inspect-conflict', kind: 'inspect', archive_id: 'raw-conflict', session_id: 'thread-self-test' });
  const inspected = await client.wait('inspect-conflict');
  assert.equal(inspected.status, 'failed');
  assert.equal(inspected.error.exit_code, 1);
  assert.match(inspected.error.message, /conflicting duplicate context attribute/);
  assert.ok(!JSON.stringify(inspected).includes(marker));
  await assert.rejects(client.getTurns('inspect-conflict'), error => error.status === 409);
  await client.putUsageLog('conflict-usage', await fs.readFile(data.usage));
  await client.submit({ id: 'export-conflict', kind: 'export', archive_id: 'raw-conflict',
    session_id: 'thread-self-test', release_id: 'release-conflict', usage_log_ids: ['conflict-usage'] });
  const exported = await client.wait('export-conflict');
  assert.equal(exported.status, 'failed');
  assert.equal(exported.error.exit_code, 1);
  assert.match(exported.error.message, /conflicting duplicate context attribute/);
  assert.ok(!JSON.stringify(exported).includes(marker));
  await assert.rejects(client.download('export-conflict', 'buyer-package.tar.gz'), error => error.status === 409);
  assert.deepEqual(await fs.readFile(segment), bytes);
});

test('conflicting native tool payloads prevent delivery and Buyer export while preserving Raw', { timeout: 120000 }, async t => {
  for (const field of ['arguments', 'result']) await t.test(field, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-tool-conflict-'));
    let app;
    t.after(async () => { if (app) await app.close(); await fs.rm(root, { recursive: true, force: true }); });
    const data = await fixture(root);
    const segmentsRoot = path.join(data.captureRoot, 'segments');
    const segments = (await fs.readdir(segmentsRoot)).filter(name => name.endsWith('.sealed.ndjson')).sort();
    const records = [];
    for (const name of segments) records.push(...(await fs.readFile(path.join(segmentsRoot, name), 'utf8'))
      .trim().split('\n').filter(Boolean).map(line => JSON.parse(line)));
    const original = records.find(record => record.toolExecution?.source_event_name === 'codex.tool_result'
      && record.toolExecution.call_id === 'call-2');
    assert.ok(original, 'the fixture must include a native OTLP result');
    const marker = `private-conflicting-tool-${field}`;
    const changed = structuredClone(original);
    changed.captureId = `cap-conflicting-native-tool-${field}`;
    changed.toolExecution[field] = field === 'arguments' ? { target: marker } : marker;
    const segment = path.join(segmentsRoot, segments.at(-1));
    await fs.appendFile(segment, JSON.stringify(changed) + '\n');
    const bytes = await fs.readFile(segment);
    const token = 'platform-test-token-with-at-least-32-bytes';
    app = await createPlatformServer({ plugin: new ChipTracePlugin({ projectId: 'project-test', root: path.join(root, 'platform'),
      captureRoot: data.captureRoot, objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace' }), token });
    await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
    const client = new ChipTraceClient({ baseUrl: `http://127.0.0.1:${app.server.address().port}`, token });
    await client.submit({ id: 'archive-tool-conflict', kind: 'archive', archive_id: 'raw-tool-conflict' });
    assert.equal((await client.wait('archive-tool-conflict')).status, 'completed');
    await client.submit({ id: 'inspect-tool-conflict', kind: 'inspect', archive_id: 'raw-tool-conflict', session_id: 'thread-self-test' });
    const inspected = await client.wait('inspect-tool-conflict');
    assert.equal(inspected.status, 'completed');
    assert.equal(inspected.result.delivery_ready, false);
    assert.equal(inspected.result.session.delivery_ready, true);
    assert.equal(inspected.result.integrity.runtime_complete, false);
    assert.ok(!JSON.stringify(inspected).includes(marker));
    const page = await client.getTurns('inspect-tool-conflict');
    assert.equal(page.delivery_ready, false);
    const response = await client.downloadProjection('inspect-tool-conflict', 'runtime');
    const spans = decodeProjectionJsonl(Buffer.from(await response.arrayBuffer()));
    const tool = spans.find(span => span.span_kind === 'tool_execution' && span.call_id === 'call-2');
    assert.equal(tool.extensions.state_conflict, true);
    assert.equal(tool.extensions.native_result_consistency.observations, 2);
    assert.equal(tool.extensions.native_result_consistency[`${field}_conflict`], true);
    assert.ok(tool.raw_capture_refs.includes(original.captureId));
    assert.ok(tool.raw_capture_refs.includes(changed.captureId));
    await client.putUsageLog('tool-conflict-usage', await fs.readFile(data.usage));
    await client.submit({ id: 'export-tool-conflict', kind: 'export', archive_id: 'raw-tool-conflict',
      session_id: 'thread-self-test', release_id: 'release-tool-conflict', usage_log_ids: ['tool-conflict-usage'] });
    const exported = await client.wait('export-tool-conflict');
    assert.equal(exported.status, 'failed');
    assert.equal(exported.error.exit_code, 1);
    assert.match(exported.error.message, /interaction projection is not delivery ready; failed gates: runtime_complete/);
    assert.ok(!JSON.stringify(exported).includes(marker));
    await assert.rejects(client.download('export-tool-conflict', 'buyer-package.tar.gz'), error => error.status === 409);
    assert.deepEqual(await fs.readFile(segment), bytes);
  });
});

test('native result incompleteness blocks delivery in either arrival order', { timeout: 180000 }, async t => {
  for (const completeness of ['truncated', 'unknown']) for (const order of ['incomplete-first', 'incomplete-last']) {
    await t.test(`${completeness}/${order}`, async t => {
      const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-native-completeness-'));
      let app;
      t.after(async () => { if (app) await app.close(); await fs.rm(root, { recursive: true, force: true }); });
      const data = await fixture(root);
      const segmentsRoot = path.join(data.captureRoot, 'segments');
      const segments = (await fs.readdir(segmentsRoot)).filter(name => name.endsWith('.sealed.ndjson')).sort();
      const records = [];
      for (const name of segments) records.push(...(await fs.readFile(path.join(segmentsRoot, name), 'utf8'))
        .trim().split('\n').filter(Boolean).map(line => JSON.parse(line)));
      const original = records.find(record => record.toolExecution?.source_event_name === 'codex.tool_result'
        && record.toolExecution.call_id === 'call-2');
      assert.ok(original, 'the fixture must include a native OTLP result');
      const complete = structuredClone(original);
      complete.captureId = 'cap-native-completeness-complete';
      const incomplete = structuredClone(original);
      incomplete.captureId = 'cap-native-completeness-incomplete';
      incomplete.toolExecution.output_truncated = completeness === 'truncated' ? true : null;
      incomplete.toolExecution.result_content_captured = false;
      const extra = order === 'incomplete-first' ? [incomplete, complete] : [complete, incomplete];
      const segment = path.join(segmentsRoot, segments.at(-1));
      await fs.appendFile(segment, extra.map(record => JSON.stringify(record)).join('\n') + '\n');
      const bytes = await fs.readFile(segment);
      const token = 'platform-test-token-with-at-least-32-bytes';
      app = await createPlatformServer({ plugin: new ChipTracePlugin({ projectId: 'project-test', root: path.join(root, 'platform'),
        captureRoot: data.captureRoot, objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace' }), token });
      await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
      const client = new ChipTraceClient({ baseUrl: `http://127.0.0.1:${app.server.address().port}`, token });
      await client.submit({ id: 'archive-incomplete', kind: 'archive', archive_id: 'raw-incomplete' });
      assert.equal((await client.wait('archive-incomplete')).status, 'completed');
      await client.submit({ id: 'inspect-incomplete', kind: 'inspect', archive_id: 'raw-incomplete', session_id: 'thread-self-test' });
      const inspected = await client.wait('inspect-incomplete');
      assert.equal(inspected.status, 'completed');
      assert.equal(inspected.result.delivery_ready, false);
      assert.equal(inspected.result.session.delivery_ready, true);
      assert.equal(inspected.result.integrity.runtime_complete, false);
      assert.equal((await client.getTurns('inspect-incomplete')).delivery_ready, false);
      const response = await client.downloadProjection('inspect-incomplete', 'runtime');
      const spans = decodeProjectionJsonl(Buffer.from(await response.arrayBuffer()));
      const tool = spans.find(span => span.span_kind === 'tool_execution' && span.call_id === 'call-2');
      assert.equal(tool.extensions.state_conflict, false);
      assert.equal(tool.extensions.result_content_captured, false);
      assert.equal(tool.extensions.output_truncated, completeness === 'truncated' ? true : null);
      assert.equal(tool.extensions.native_result_consistency.observations, 3);
      assert.equal(tool.extensions.native_result_consistency.incomplete_observations, 1);
      for (const capture of [original, complete, incomplete]) assert.ok(tool.raw_capture_refs.includes(capture.captureId));
      await client.putUsageLog('incomplete-usage', await fs.readFile(data.usage));
      await client.submit({ id: 'export-incomplete', kind: 'export', archive_id: 'raw-incomplete',
        session_id: 'thread-self-test', release_id: 'release-incomplete', usage_log_ids: ['incomplete-usage'] });
      const exported = await client.wait('export-incomplete');
      assert.equal(exported.status, 'failed');
      assert.equal(exported.error.exit_code, 1);
      assert.match(exported.error.message, /interaction projection is not delivery ready; failed gates: runtime_complete/);
      await assert.rejects(client.download('export-incomplete', 'buyer-package.tar.gz'), error => error.status === 409);
      assert.deepEqual(await fs.readFile(segment), bytes);
    });
  }
});

test('HTTP service and SDK run the real CLI archive/restore/inspect/export path', { timeout: 60000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-'));
  let app;
  t.after(async () => { if (app) await app.close(); await fs.rm(root, { recursive: true, force: true }); });
  const data = await fixture(root);
  const plugin = new ChipTracePlugin({ projectId: 'project-test', root: path.join(root, 'platform'), captureRoot: data.captureRoot, objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace', concurrency: 2 });
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
  const scenarios = inspectedJob.result.scenario_evidence;
  assert.equal(scenarios.schema_version, 'chiptrace.native-canary-scenarios.v1');
  assert.equal(scenarios.session_id, 'thread-self-test');
  assert.equal(scenarios.source, 'exact_capture_snapshot');
  // A complete ordinary Session need not execute the Canary's resume scenario.
  assert.equal(scenarios.complete, false);
  assert.ok(scenarios.missing_scenarios.includes('resume'));
  assert.equal(scenarios.resume, null);
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
  plugin = new ChipTracePlugin({ projectId: 'project-test', root: platformRoot, captureRoot: data.captureRoot, objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace', concurrency: 1 });
  await plugin.start();
  const failed = await plugin.submit({ id: 'missing-archive', kind: 'restore', archive_id: 'definitely-missing' });
  const failedJob = await waitFor(plugin, failed.request.id);
  assert.equal(failedJob.status, 'failed');
  assert.equal(failedJob.error.exit_code, 1);
  await plugin.submit({ id: 'recovered-archive', kind: 'archive', archive_id: 'self-test-raw' });
  await plugin.close();
  assert.equal(plugin.getJob('recovered-archive').status, 'queued');

  recovered = new ChipTracePlugin({ projectId: 'project-test', root: platformRoot, captureRoot: data.captureRoot, objectRoot: data.objectRoot, binary, prefix: 'datasets/chiptrace', concurrency: 1 });
  await recovered.start();
  assert.equal((await waitFor(recovered, 'recovered-archive')).status, 'completed');
  assert.equal(recovered.getJob('recovered-archive').attempt, 2);
  assert.equal(recovered.getJob('missing-archive').status, 'failed');
});

test('restart rejects a different storage namespace before exposing cached jobs or Raw', { timeout: 60000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-namespace-'));
  const plugins = [];
  t.after(async () => {
    for (const plugin of plugins) await plugin.close();
    await fs.rm(root, { recursive: true, force: true });
  });
  const data = await fixture(root);
  const options = { projectId: 'project-a', root: path.join(root, 'platform'), captureRoot: data.captureRoot,
    objectRoot: data.objectRoot, binary, prefix: 'project-a', concurrency: 1 };
  const first = new ChipTracePlugin(options);
  plugins.push(first);
  await first.submit({ id: 'archive-before', kind: 'archive', archive_id: 'shared-id' });
  assert.equal((await waitFor(first, 'archive-before')).status, 'completed');
  await first.submit({ id: 'restore-before', kind: 'restore', archive_id: 'shared-id' });
  assert.equal((await waitFor(first, 'restore-before')).status, 'completed');
  await first.close();
  const snapshot = path.join(options.root, 'snapshots/shared-id/RAW_SOURCE.json');
  const original = await fs.readFile(snapshot);
  const missing = await run(binary, ['verify-raw-archive', '--backend', 'fs', '--root', data.objectRoot,
    '--prefix', 'project-b', '--archive-id', 'shared-id']).then(() => 0, error => error.code);
  assert.equal(missing, 1, 'the new namespace has no matching remote archive');
  const second = new ChipTracePlugin({ ...options, prefix: 'project-b' });
  plugins.push(second);
  const outcome = await second.start().then(() => ({ status: 'fulfilled' }),
    error => ({ status: 'rejected', error }));
  if (outcome.status === 'fulfilled') {
    const oldJob = second.getJob('restore-before');
    await second.submit({ id: 'restore-after', kind: 'restore', archive_id: 'shared-id' });
    const reused = await waitFor(second, 'restore-after');
    t.diagnostic(JSON.stringify({ startup: outcome.status, old_job: oldJob.status,
      new_namespace_archive_exit: missing, cached_restore: reused.status,
      snapshot_unchanged: (await fs.readFile(snapshot)).equals(original) }));
  }
  assert.equal(outcome.status, 'rejected');
  assert.equal(outcome.error.code, 'NAMESPACE_CONFLICT');
  assert.equal(second.health().ok, false);
  assert.equal(second.health().jobs, 0);
  assert.deepEqual(await fs.readFile(snapshot), original);
});

test('platform requires an explicit host-controlled project identity', () => {
  assert.throws(() => new ChipTracePlugin({ root: '/unused', binary }), /project_id/);
  assert.throws(() => new ChipTracePlugin({ root: '/unused', binary, projectId: '../outside' }), /project_id/);
});

test('namespace binding survives credential rotation and rejects changes to project or data sources', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-binding-'));
  const plugins = [];
  t.after(async () => {
    for (const plugin of plugins) await plugin.close();
    await fs.rm(root, { recursive: true, force: true });
  });
  for (const backend of ['fs', 'oss', 's3']) await t.test(backend, async t => {
    const options = { root: path.join(root, backend), binary, backend,
      projectId: 'private-project-a', captureRoot: path.join(root, 'private-captures-a'),
      objectRoot: path.join(root, 'private-objects-a'), prefix: 'private-prefix-a',
      endpoint: 'https://private-endpoint-a.invalid', bucket: 'private-bucket-a', region: 'region-a',
      engineEnv: { OSS_ACCESS_KEY_SECRET: 'synthetic-private-secret-before' } };
    const first = new ChipTracePlugin(options);
    plugins.push(first);
    await first.start();
    assert.throws(() => { first.prefix = 'changed'; }, TypeError);
    await first.close();
    const bindingFile = path.join(options.root, 'NAMESPACE.json');
    const binding = await fs.readFile(bindingFile);
    assert.equal(JSON.parse(binding).schema_version, 'chiptrace.platform-namespace.v1');
    assert.equal((await fs.stat(bindingFile)).mode & 0o777, 0o600);
    assert.ok(!binding.toString().includes('private-'));
    const rotated = new ChipTracePlugin({ ...options, prefix: '/private-prefix-a/', concurrency: 3,
      engineEnv: { OSS_ACCESS_KEY_SECRET: 'synthetic-private-secret-after' } });
    plugins.push(rotated);
    await rotated.start();
    assert.equal(rotated.health().ok, true);
    await rotated.close();
    assert.deepEqual(await fs.readFile(bindingFile), binding);
    const changes = [
      ['projectId', 'private-project-b'], ['captureRoot', path.join(root, 'private-captures-b')],
      ['prefix', 'private-prefix-b'],
      ...(backend === 'fs' ? [['objectRoot', path.join(root, 'private-objects-b')], ['backend', 'oss']]
        : [['endpoint', 'https://private-endpoint-b.invalid'], ['bucket', 'private-bucket-b'], ['backend', 'fs']]),
      ...(backend === 's3' ? [['region', 'region-b']] : []),
    ];
    for (const [field, value] of changes) await t.test(field, async () => {
      const changed = new ChipTracePlugin({ ...options, [field]: value });
      plugins.push(changed);
      await assert.rejects(changed.start(), error => error.code === 'NAMESPACE_CONFLICT'
        && !error.message.includes('private-'));
      assert.equal(changed.health().ok, false);
      assert.equal(changed.health().jobs, 0);
      assert.equal(changed.health().failure.code, 'NAMESPACE_CONFLICT');
      assert.deepEqual(await fs.readFile(bindingFile), binding);
      await changed.close();
    });
  });
});

test('legacy platform state cannot acquire an invented namespace binding', async t => {
  for (const directory of ['jobs', 'work', 'usage', 'snapshots']) await t.test(directory, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-unbound-'));
    const plugin = new ChipTracePlugin({ projectId: 'project-test', root, binary });
    t.after(async () => { await plugin.close(); await fs.rm(root, { recursive: true, force: true }); });
    await fs.mkdir(path.join(root, directory), { recursive: true });
    const file = path.join(root, directory, 'legacy-private.json');
    const original = Buffer.from('{"private":"synthetic-legacy-evidence"}\n');
    await fs.writeFile(file, original);
    await assert.rejects(plugin.start(), error => error.code === 'NAMESPACE_UNBOUND'
      && !error.message.includes('synthetic-legacy-evidence'));
    assert.equal(plugin.health().ok, false);
    assert.equal(plugin.health().jobs, 0);
    await assert.rejects(fs.stat(path.join(root, 'NAMESPACE.json')), { code: 'ENOENT' });
    assert.deepEqual(await fs.readFile(file), original);
  });
});

test('invalid namespace bindings stop recovery without exposing private stored state', async t => {
  const cases = [
    ['invalid JSON', async file => fs.writeFile(file, '{"private":"synthetic-private-state",')],
    ['invalid schema', async file => fs.writeFile(file, JSON.stringify({ schema_version: 'unknown', configuration_sha256: 'a'.repeat(64) }))],
    ['invalid digest', async file => fs.writeFile(file, JSON.stringify({ schema_version: 'chiptrace.platform-namespace.v1', configuration_sha256: 'invalid' }))],
    ['oversized binding', async file => fs.writeFile(file, 'x'.repeat(4097))],
    ['symbolic link', async file => { await fs.rename(file, `${file}.original`); await fs.symlink(`${file}.original`, file); }],
    ['directory', async file => { await fs.rename(file, `${file}.original`); await fs.mkdir(file); }],
  ];
  for (const [name, corrupt] of cases) await t.test(name, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-corrupt-binding-'));
    const first = new ChipTracePlugin({ projectId: 'project-test', root, binary });
    const second = new ChipTracePlugin({ projectId: 'project-test', root, binary });
    t.after(async () => { await first.close(); await second.close(); await fs.rm(root, { recursive: true, force: true }); });
    await first.start();
    await first.close();
    const bindingFile = path.join(root, 'NAMESPACE.json');
    await corrupt(bindingFile);
    const original = await fs.lstat(bindingFile);
    const jobFile = path.join(root, 'jobs', 'legacy-private.json');
    const jobBytes = Buffer.from('{"private":"synthetic-private-state",');
    await fs.writeFile(jobFile, jobBytes);
    await assert.rejects(second.start(), error => error.code === 'CORRUPT_STATE'
      && !error.message.includes('synthetic-private-state'));
    assert.equal(second.health().ok, false);
    assert.equal(second.health().jobs, 0);
    assert.deepEqual(await fs.readFile(jobFile), jobBytes);
    const after = await fs.lstat(bindingFile);
    assert.equal(after.ino, original.ino);
    assert.equal(after.size, original.size);
  });
});

test('namespace directory sync failure prevents readiness and allows evidence-preserving retry', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-binding-sync-'));
  const first = new ChipTracePlugin({ projectId: 'project-test', root, binary });
  const second = new ChipTracePlugin({ projectId: 'project-test', root, binary });
  t.after(async () => { await first.close(); await second.close(); await fs.rm(root, { recursive: true, force: true }); });
  const originalOpen = fs.open;
  const mocked = t.mock.method(fs, 'open', async (file, ...args) => {
    if (file === root) throw Object.assign(new Error('synthetic-private-sync-failure'), { code: 'EIO' });
    return originalOpen(file, ...args);
  });
  await assert.rejects(first.start(), error => error.code === 'STORAGE_FAILURE'
    && !error.message.includes('synthetic-private-sync-failure'));
  assert.equal(first.health().ok, false);
  assert.equal(first.health().jobs, 0);
  await first.close();
  mocked.mock.restore();
  const bindingFile = path.join(root, 'NAMESPACE.json');
  const binding = await fs.readFile(bindingFile);
  await second.start();
  assert.equal(second.health().ok, true);
  assert.deepEqual(await fs.readFile(bindingFile), binding);
});

test('independent project services do not share jobs, usage or cached archives', { timeout: 60000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-projects-'));
  const apps = [];
  t.after(async () => {
    for (const app of apps) await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });
  const data = await fixture(root);
  const clients = [];
  for (const projectId of ['project-a', 'project-b']) {
    const app = await createPlatformServer({ root: path.join(root, projectId), projectId, binary,
      captureRoot: data.captureRoot, objectRoot: data.objectRoot, prefix: projectId,
      token: `${projectId}-synthetic-service-token-at-least-32-bytes` });
    apps.push(app);
    await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
    clients.push(new ChipTraceClient({ baseUrl: `http://127.0.0.1:${app.server.address().port}`,
      token: `${projectId}-synthetic-service-token-at-least-32-bytes` }));
  }
  const [first, second] = clients;
  await first.submit({ id: 'archive-a', kind: 'archive', archive_id: 'shared-id' });
  assert.equal((await first.wait('archive-a')).status, 'completed');
  await first.submit({ id: 'restore-a', kind: 'restore', archive_id: 'shared-id' });
  assert.equal((await first.wait('restore-a')).status, 'completed');
  await first.putUsageLog('usage-a', await fs.readFile(data.usage));
  await assert.rejects(second.getJob('restore-a'), error => error.status === 404);
  await assert.rejects(second.submit({ id: 'export-b', kind: 'export', archive_id: 'shared-id',
    session_id: 'thread-self-test', release_id: 'release-b', usage_log_ids: ['usage-a'] }), error => error.status === 400);
  await second.submit({ id: 'restore-b', kind: 'restore', archive_id: 'shared-id' });
  const missing = await second.wait('restore-b');
  assert.equal(missing.status, 'failed');
  assert.equal(missing.error.exit_code, 1);
  await assert.rejects(fs.stat(path.join(root, 'project-b/snapshots/shared-id')), { code: 'ENOENT' });
  await second.submit({ id: 'archive-b', kind: 'archive', archive_id: 'shared-id' });
  assert.equal((await second.wait('archive-b')).status, 'completed');
  await second.submit({ id: 'restore-b-new', kind: 'restore', archive_id: 'shared-id' });
  assert.equal((await second.wait('restore-b-new')).status, 'completed');
  assert.equal(apps.every(app => app.plugin.health().ok), true);
});

test('writer lock excludes a second plugin and lock loss gates new jobs', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-platform-lock-'));
  const first = new ChipTracePlugin({ projectId: 'project-test', root, binary });
  const second = new ChipTracePlugin({ projectId: 'project-test', root, binary });
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
  const plugin = new ChipTracePlugin({ projectId: 'project-test', root, binary });
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
  const plugin = new ChipTracePlugin({ projectId: 'project-test', root, binary, maxJobs: 1, maxQueuedJobs: 1 });
  t.after(async () => { await plugin.close(); await fs.rm(root, { recursive: true, force: true }); });
  const request = { id: 'first', kind: 'restore', archive_id: 'missing' };
  await plugin.submit(request);
  assert.equal((await waitFor(plugin, 'first')).status, 'failed');
  await assert.rejects(plugin.submit({ id: 'next', kind: 'restore', archive_id: 'missing' }), error => error.status === 503 && error.code === 'CAPACITY');
  assert.equal((await plugin.submit(request)).duplicate, true);
  assert.equal(plugin.health().ok, true);
  assert.equal((await fs.readdir(path.join(root, 'jobs'))).filter(file => file.endsWith('.json')).length, 1);
});
