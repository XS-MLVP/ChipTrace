'use strict';

// Consume newly collected native evidence through the normal HTTP/SDK path.
// Run in an isolated child environment; this filesystem backend is not OSS
// account acceptance, and the service token is not end-user tenant identity.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { createReadStream } = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { execFile } = require('node:child_process');
const { promisify, isDeepStrictEqual } = require('node:util');
const { ChipTracePlugin } = require('../cloud-platform/plugin');
const { createPlatformServer } = require('../cloud-platform/server');
const { ChipTraceClient } = require('../cloud-platform/client');

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const run = promisify(execFile);

async function fileEvidence(file) {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(file)) { hash.update(chunk); bytes += chunk.length; }
  return { bytes, sha256: hash.digest('hex') };
}

async function segments(root) {
  const files = [];
  for (const entry of await fs.readdir(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name);
    if (entry.isDirectory()) files.push(...await segments(file));
    else if (entry.name.endsWith('.sealed.ndjson')) {
      assert.equal(entry.isFile(), true);
      files.push({ file, name: entry.name, ...await fileEvidence(file) });
    }
  }
  return files.sort((a, b) => a.name.localeCompare(b.name) || a.sha256.localeCompare(b.sha256));
}

async function verifyPlatform(root, binary, mode = 'partial') {
  assert.ok(['partial', 'model-switch', 'complete'].includes(mode), 'expected explicit native platform regression mode');
  const complete = mode !== 'partial';
  const accepted = mode === 'complete';
  const baseline = JSON.parse(await fs.readFile(path.join(root, 'inspection.json'), 'utf8'));
  const sessionId = baseline.session.session_id;
  assert.equal(baseline.delivery_ready, complete);
  assert.equal(baseline.integrity.protocol_complete, complete);
  assert.equal(baseline.source_coverage.complete, true);
  const captureRoot = path.join(root, 'collector');
  const input = await segments(path.join(captureRoot, 'segments'));
  assert.ok(input.length > 0);
  const wire = [];
  let records = 0;
  for (const segment of input) {
    for await (const line of readline.createInterface({ input: createReadStream(segment.file) })) {
      const record = JSON.parse(line);
      records += 1;
      if (record.recordType === 'api_snapshot') wire.push(record);
    }
  }
  assert.equal(wire.length, baseline.session.model_interactions);
  if (!complete) assert.equal(wire.length, 4);
  const usage = complete
    ? (await fs.readFile(path.join(root, 'synthetic-usage.jsonl'), 'utf8')).trim().split('\n').map(line => JSON.parse(line))
    : wire.map(record => {
    const requestId = record.responseHeaders['x-request-id'];
    assert.equal(typeof requestId, 'string', 'usage must join actual per-attempt response IDs');
    const model = JSON.parse(record.requestBody.raw).model;
    return { request_id: requestId, requested_model: model, upstream_model: model,
      provider: 'OpenAI', input_tokens: 0, output_tokens: 0 };
  });
  assert.equal(usage.length, wire.length);
  assert.equal(new Set(usage.map(item => item.request_id)).size, wire.length);
  for (const record of wire) {
    const matched = usage.find(item => item.request_id === record.responseHeaders['x-request-id']);
    assert.ok(matched, 'each independent endpoint observation must join an actual Wire attempt');
    assert.equal(matched.requested_model, JSON.parse(record.requestBody.raw).model);
  }
  const requestedModels = new Set(usage.map(item => item.requested_model));
  if (complete) assert.equal(requestedModels.size, accepted ? 1 : 2);
  const options = { projectId: 'synthetic-native-protocol', root: path.join(root, 'platform'),
    captureRoot, objectRoot: path.join(root, 'platform-objects'), binary,
    prefix: 'datasets/native-protocol-ci', concurrency: 1 };
  const token = crypto.randomBytes(32).toString('hex');
  let app;
  const open = async () => {
    app = await createPlatformServer({ plugin: new ChipTracePlugin(options), token });
    await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
    return new ChipTraceClient({ baseUrl: `http://127.0.0.1:${app.server.address().port}`, token });
  };
  const submit = async (client, request) => {
    await client.submit(request);
    return client.wait(request.id, { timeoutMs: 60000, intervalMs: 25 });
  };
  const inspectId = 'native-inspect';
  const archiveId = complete ? 'native-protocol-raw' : 'native-interruption-raw';
  const expectedTurns = baseline.session.turns;
  const expectedTurnBytes = Buffer.from(expectedTurns.map(turn => JSON.stringify(turn)).join('\n') + '\n');
  const expectedSession = { ...baseline.session };
  delete expectedSession.turns;
  const idleReads = async () => {
    const deadline = Date.now() + 5000;
    while (app.plugin.activeReads > 0 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.equal(app.plugin.activeReads, 0, 'consumed HTTP responses must release their actual read slots');
  };
  const verifyView = async client => {
    await idleReads();
    const job = await client.getJob(inspectId);
    assert.equal(job.status, 'completed');
    assert.equal(job.result.delivery_ready, complete, 'job readiness must respect the original protocol evidence');
    assert.deepEqual(job.result.session, expectedSession);
    assert.deepEqual(job.result.integrity, baseline.integrity);
    assert.deepEqual(job.result.source_context_audit, baseline.source_context_audit);
    const duplicate = await client.submit(job.request);
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.result.delivery_ready, complete, 'idempotent submission must preserve the conservative job view');
    const page = await client.getTurns(inspectId, { offset: 0, limit: 100 });
    assert.equal(page.delivery_ready, complete, 'streamed HTTP pages must preserve original protocol readiness');
    assert.deepEqual(page.turns, expectedTurns);
    await idleReads();
    const direct = await app.plugin.getTurns(inspectId, { offset: 0, limit: 100 });
    assert.equal(direct.delivery_ready, complete, 'embedded object pages must preserve the same overall readiness');
    const full = await client.downloadTurns(inspectId);
    const bytes = Buffer.from(await full.arrayBuffer());
    assert.equal(bytes.length, expectedTurnBytes.length);
    assert.equal(sha256(bytes), sha256(expectedTurnBytes));
    assert.equal(full.headers.get('x-content-sha256'), job.turns.sha256);
    assert.equal(job.turns.sha256, sha256(expectedTurnBytes));
    await idleReads();
    const manifestResponse = await client.downloadProjection(inspectId, 'manifest');
    const manifest = await manifestResponse.json();
    assert.deepEqual(manifest.integrity, baseline.integrity);
    assert.deepEqual(manifest.parts, baseline.projection.parts);
    await idleReads();
    for (const [part, file] of Object.entries({ interactions: 'interactions/model-interactions.jsonl.zst',
      runtime: 'runtime/runtime-spans.jsonl.zst', links: 'links/interaction-links.jsonl.zst' })) {
      const response = await client.downloadProjection(inspectId, part);
      const bytes = Buffer.from(await response.arrayBuffer());
      const expected = baseline.projection.parts.find(item => item.file === file);
      assert.equal(bytes.length, expected.bytes);
      assert.equal(sha256(bytes), expected.sha256, 'platform projection must retain every original interaction byte');
      assert.equal(response.headers.get('x-content-sha256'), expected.sha256);
      await idleReads();
    }
    return job;
  };
  let downloadRound = 0;
  const verifyAcceptedExport = async client => {
    await idleReads();
    const job = await client.getJob('native-export');
    assert.equal(job.status, 'completed', JSON.stringify(job.error));
    assert.equal(job.result.delivery_ready, true);
    assert.equal(job.result.schema_version, 'chiptrace.cloud-acceptance.v2');
    assert.equal(job.result.session_id, sessionId);
    assert.equal(job.result.hard_gate_pass, true);
    assert.equal(job.result.validation_status, 'pass');
    assert.ok(job.result.score >= 90);
    assert.ok(job.result.effective_turns >= 10);
    assert.ok(job.result.distinct_tool_names >= 5);
    assert.ok(job.result.complete_tool_definitions >= 5);
    assert.equal(job.result.pairing_rate_after_open_tail, 1);
    assert.deepEqual(job.result.session_view, expectedSession);
    assert.deepEqual(job.result.source_context_audit, baseline.source_context_audit);
    const page = await client.getTurns('native-export', { limit: 100 });
    assert.equal(page.delivery_ready, true);
    assert.deepEqual(page.turns, expectedTurns);
    await idleReads();
    assert.ok(job.artifacts.length > 0);
    const downloaded = path.join(root, `verified-buyer-download-${++downloadRound}`);
    await fs.mkdir(downloaded);
    const deliveredSessions = [];
    for (const artifact of job.artifacts) {
      const denied = await fetch(`${client.baseUrl}/v1/jobs/native-export/packages/${encodeURIComponent(artifact.file)}`);
      assert.equal(denied.status, 401);
      await denied.body.cancel();
      const response = await client.download('native-export', artifact.file, { signal: AbortSignal.timeout(60000) });
      const bytes = Buffer.from(await response.arrayBuffer());
      assert.equal(bytes.length, artifact.bytes);
      assert.equal(sha256(bytes), artifact.sha256);
      assert.equal(response.headers.get('x-content-sha256'), artifact.sha256);
      await idleReads();
      assert.equal(path.basename(artifact.file), artifact.file);
      const file = path.join(downloaded, artifact.file);
      await fs.writeFile(file, bytes, { flag: 'wx', mode: 0o600 });
      const entries = (await run('tar', ['-tzf', file])).stdout.trim().split('\n');
      assert.deepEqual(entries.sort(), ['PACKAGE.json', 'SHA256SUMS', 'sessions.jsonl']);
      // Read entries to stdout: never extract archive paths onto the filesystem.
      const read = async entry => (await run('tar', ['-xOf', file, entry],
        { encoding: 'buffer', maxBuffer: 16 * 1024 * 1024 })).stdout;
      const jsonl = await read('sessions.jsonl');
      const packageBytes = await read('PACKAGE.json');
      const metadata = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(packageBytes));
      const sums = (await read('SHA256SUMS')).toString('utf8');
      assert.equal(sums, `${sha256(jsonl)}  sessions.jsonl\n${sha256(packageBytes)}  PACKAGE.json\n`);
      assert.equal(metadata.validation_status, 'pass');
      assert.equal(metadata.buyer_profile, 'buyer-v7');
      assert.ok(metadata.minimum_score >= 90);
      assert.equal(metadata.encoding, 'UTF-8');
      assert.equal(metadata.session_atomic, true);
      assert.equal(metadata.jsonl_bytes, jsonl.length);
      assert.equal(metadata.jsonl_sha256, sha256(jsonl));
      const lines = new TextDecoder('utf-8', { fatal: true }).decode(jsonl).trim().split('\n');
      assert.equal(lines.length, metadata.records);
      deliveredSessions.push(...lines.map(line => JSON.parse(line)));
    }
    assert.equal(deliveredSessions.length, 1, 'the actual download must contain the complete selected Session');
    const session = deliveredSessions[0];
    assert.equal(session.session_id, sessionId);
    assert.equal(session.source_request_count, wire.length, 'Buyer metadata must retain every HTTP attempt, including retry');
    assert.deepEqual(new Set(session.meta.turn_ids), new Set(expectedTurns.map(turn => turn.turn_id)));
    assert.equal(session.meta.model_evidence.consistent, true);
    assert.equal(session.meta.model_evidence.provider_identity_attested, true);
    assert.equal(session.quality.buyer_acceptance.eligible, true);
    for (const record of wire) {
      assert.ok(session.meta.source_capture_ids.includes(record.captureId));
      for (const item of JSON.parse(record.requestBody.raw).input) {
        if (item.type !== 'function_call_output') continue;
        const delivered = session.messages.find(message => message.role === 'tool' && message.tool_call_id === item.call_id);
        assert.ok(delivered, `download must retain the actual tool result ${item.call_id}`);
        assert.ok(isDeepStrictEqual(delivered.content, item.output),
          `download must retain complete tool result content for ${item.call_id} (payload omitted)`);
      }
    }
    return job;
  };
  const verifyRejectedExport = async client => {
    const job = await client.getJob('native-export');
    assert.equal(job.status, 'failed');
    assert.equal(job.error.exit_code, 1);
    assert.match(job.error.message, complete
      ? /Release failed closed:.*failure_reasons=\{"model":1\}/
      : /not delivery ready; failed gates: protocol_complete/);
    await assert.rejects(client.download('native-export', 'buyer-package.tar.gz'), error => error.status === 409);
    return job;
  };
  try {
    let client = await open();
    const archive = await submit(client, { id: 'native-archive', kind: 'archive', archive_id: archiveId });
    assert.equal(archive.status, 'completed', archive.error?.message);
    assert.equal(archive.result.completeness, 'complete', 'Raw byte completeness is distinct from model protocol completeness');
    assert.equal(archive.result.total_records, records);
    assert.equal(archive.result.total_bytes, input.reduce((total, item) => total + item.bytes, 0));
    const restored = await submit(client, { id: 'native-restore', kind: 'restore', archive_id: archiveId });
    assert.equal(restored.status, 'completed', restored.error?.message);
    assert.equal(restored.result.total_records, records);
    const recovered = await segments(path.join(options.root, 'snapshots', archiveId, 'segments'));
    const stable = items => items.map(({ name, bytes, sha256 }) => ({ name, bytes, sha256 }));
    assert.deepEqual(stable(recovered), stable(input));
    const inspected = await submit(client, { id: inspectId, kind: 'inspect', archive_id: archiveId, session_id: sessionId });
    assert.equal(inspected.status, 'completed', inspected.error?.message);
    for (const route of [`/v1/jobs/${inspectId}`, `/v1/jobs/${inspectId}/turns.jsonl`,
      `/v1/jobs/${inspectId}/projection/interactions`]) {
      const response = await fetch(client.baseUrl + route);
      assert.equal(response.status, 401);
      await response.body.cancel();
    }
    await verifyView(client);
    await client.putUsageLog('native-usage', Buffer.from(usage.map(item => JSON.stringify(item)).join('\n') + '\n'));
    const exported = await submit(client, { id: 'native-export', kind: 'export', archive_id: archiveId,
      session_id: sessionId, release_id: `native-${mode}-${accepted ? 'accepted' : 'rejected'}`,
      usage_log_ids: ['native-usage'] });
    if (accepted) await verifyAcceptedExport(client);
    else await verifyRejectedExport(client);
    const exportFile = path.join(options.root, 'jobs/native-export.json');
    const exportBytes = await fs.readFile(exportFile);
    await app.close(); app = null;
    client = await open();
    await verifyView(client);
    assert.deepEqual(await fs.readFile(exportFile), exportBytes);
    if (accepted) await verifyAcceptedExport(client);
    else await verifyRejectedExport(client);
    await app.close(); app = null;
    // Only this newly generated derived job is changed. Raw and the recorded
    // integrity/source evidence stay intact; historical bytes must be preserved.
    if (!complete) {
      const jobFile = path.join(options.root, 'jobs', inspectId + '.json');
      const contradictory = JSON.parse(await fs.readFile(jobFile, 'utf8'));
      contradictory.result.delivery_ready = true;
      const contradictoryBytes = Buffer.from(JSON.stringify(contradictory) + '\n');
      await fs.writeFile(jobFile, contradictoryBytes);
      client = await open();
      await verifyView(client);
      assert.deepEqual(await fs.readFile(jobFile), contradictoryBytes, 'read-time normalization must not rewrite historical jobs');
    }
    assert.deepEqual(await fs.readFile(exportFile), exportBytes);
    assert.deepEqual(stable(await segments(path.join(captureRoot, 'segments'))), stable(input));
    assert.deepEqual(stable(await segments(path.join(options.root, 'snapshots', archiveId, 'segments'))), stable(input));
    return { backend: 'fs', real_oss_account: false, production_acceptance_claimed: false,
      usage_source: complete ? 'synthetic_endpoint_observations' : 'synthetic_raw_fixture',
      archive_restore_verified: true, raw_bytes: archive.result.total_bytes, raw_records: records,
      native_turns: expectedTurns.length, model_interactions: wire.length,
      all_projection_parts_verified: true, authenticated_downloads_verified: true,
      ...(accepted ? { accepted_export_verified: true, buyer_score: exported.result.score,
        effective_turns: exported.result.effective_turns, buyer_packages: exported.artifacts.length,
        downloaded_session_content_verified: true }
        : complete ? { mixed_model_export_exit_code: exported.error.exit_code, mixed_model_export_rejected: true,
          failure_reason_counts: { model: 1 } }
        : { partial_export_exit_code: exported.error.exit_code, partial_export_rejected: true,
          contradictory_historical_flags_rejected: true }),
      restart_verified: true,
      idempotent_responses_verified: true, historical_bytes_preserved: true };
  } finally { if (app) await app.close(); }
}

if (require.main === module) {
  const [root, binary, mode] = process.argv.slice(2);
  if (!root || !path.isAbsolute(root) || !binary || !path.isAbsolute(binary)) {
    throw new Error('expected absolute isolated fixture root and ChipTrace binary');
  }
  verifyPlatform(root, binary, mode).then(value => console.log(JSON.stringify(value))).catch(error => {
    console.error(error.stack);
    process.exitCode = 1;
  });
}

module.exports = { verifyPlatform };
