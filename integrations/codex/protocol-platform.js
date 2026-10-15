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
const { ChipTracePlugin } = require('../cloud-platform/plugin');
const { createPlatformServer } = require('../cloud-platform/server');
const { ChipTraceClient } = require('../cloud-platform/client');

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

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

async function verifyPlatform(root, binary) {
  const baseline = JSON.parse(await fs.readFile(path.join(root, 'inspection.json'), 'utf8'));
  const sessionId = baseline.session.session_id;
  assert.equal(baseline.delivery_ready, false);
  assert.equal(baseline.integrity.protocol_complete, false);
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
  assert.equal(wire.length, 4);
  const usage = wire.map(record => {
    const requestId = record.responseHeaders['x-request-id'];
    assert.equal(typeof requestId, 'string', 'usage must join actual per-attempt response IDs');
    const model = JSON.parse(record.requestBody.raw).model;
    return { request_id: requestId, requested_model: model, upstream_model: model,
      provider: 'OpenAI', input_tokens: 0, output_tokens: 0 };
  });
  assert.equal(new Set(usage.map(item => item.request_id)).size, wire.length);
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
  const archiveId = 'native-interruption-raw';
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
    assert.equal(job.result.delivery_ready, false, 'historical task flags cannot override incomplete protocol evidence');
    assert.deepEqual(job.result.session, expectedSession);
    assert.deepEqual(job.result.integrity, baseline.integrity);
    assert.deepEqual(job.result.source_context_audit, baseline.source_context_audit);
    const duplicate = await client.submit(job.request);
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.result.delivery_ready, false, 'idempotent submission must preserve the conservative job view');
    const page = await client.getTurns(inspectId, { offset: 0, limit: 100 });
    assert.equal(page.delivery_ready, false, 'partial protocol evidence must remain incomplete in streamed HTTP pages');
    assert.deepEqual(page.turns, expectedTurns);
    await idleReads();
    const direct = await app.plugin.getTurns(inspectId, { offset: 0, limit: 100 });
    assert.equal(direct.delivery_ready, false, 'embedded object pages must preserve the same overall readiness');
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
      session_id: sessionId, release_id: 'native-partial-rejected', usage_log_ids: ['native-usage'] });
    assert.equal(exported.status, 'failed');
    assert.equal(exported.error.exit_code, 1);
    assert.match(exported.error.message, /not delivery ready; failed gates: protocol_complete/);
    await assert.rejects(client.download('native-export', 'buyer-package.tar.gz'), error => error.status === 409);
    const failedFile = path.join(options.root, 'jobs/native-export.json');
    const failedBytes = await fs.readFile(failedFile);
    await app.close(); app = null;
    client = await open();
    await verifyView(client);
    assert.deepEqual(await fs.readFile(failedFile), failedBytes);
    assert.equal((await client.getJob('native-export')).error.exit_code, 1);
    await app.close(); app = null;
    // Only this newly generated derived job is changed. Raw and the recorded
    // integrity/source evidence stay intact; historical bytes must be preserved.
    const jobFile = path.join(options.root, 'jobs', inspectId + '.json');
    const contradictory = JSON.parse(await fs.readFile(jobFile, 'utf8'));
    contradictory.result.delivery_ready = true;
    const contradictoryBytes = Buffer.from(JSON.stringify(contradictory) + '\n');
    await fs.writeFile(jobFile, contradictoryBytes);
    client = await open();
    await verifyView(client);
    assert.deepEqual(await fs.readFile(jobFile), contradictoryBytes, 'read-time normalization must not rewrite historical jobs');
    assert.deepEqual(await fs.readFile(failedFile), failedBytes);
    assert.deepEqual(stable(await segments(path.join(captureRoot, 'segments'))), stable(input));
    assert.deepEqual(stable(await segments(path.join(options.root, 'snapshots', archiveId, 'segments'))), stable(input));
    return { backend: 'fs', real_oss_account: false, production_acceptance_claimed: false,
      archive_restore_verified: true, raw_bytes: archive.result.total_bytes, raw_records: records,
      native_turns: expectedTurns.length, model_interactions: wire.length,
      all_projection_parts_verified: true, authenticated_downloads_verified: true,
      partial_export_exit_code: exported.error.exit_code, partial_export_rejected: true,
      restart_verified: true, contradictory_historical_flags_rejected: true,
      idempotent_responses_verified: true, historical_bytes_preserved: true };
  } finally { if (app) await app.close(); }
}

if (require.main === module) {
  const [root, binary] = process.argv.slice(2);
  if (!root || !path.isAbsolute(root) || !binary || !path.isAbsolute(binary)) {
    throw new Error('expected absolute isolated fixture root and ChipTrace binary');
  }
  verifyPlatform(root, binary).then(value => console.log(JSON.stringify(value))).catch(error => {
    console.error(error.stack);
    process.exitCode = 1;
  });
}

module.exports = { verifyPlatform };
