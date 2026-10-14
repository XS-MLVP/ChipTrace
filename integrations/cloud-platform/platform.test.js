'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
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
  const page = await client.getTurns('inspect-job', { offset: 0, limit: 1 });
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

  const usage = await fs.readFile(data.usage);
  assert.equal((await client.putUsageLog('usage-1', usage)).duplicate, false);
  assert.equal((await client.putUsageLog('usage-1', usage)).duplicate, true);
  await assert.rejects(client.putUsageLog('usage-1', Buffer.from('{"different":true}\n')), error => error.status === 409);
  const exported = await client.submit({ id: 'export-job', kind: 'export', archive_id: 'self-test-raw', session_id: 'thread-self-test', release_id: 'platform-release', usage_log_ids: ['usage-1'] });
  const exportJob = await client.wait(exported.request.id);
  assert.equal(exportJob.status, 'completed', JSON.stringify(exportJob.error));
  assert.equal(exportJob.result.score, 100);
  assert.equal(exportJob.result.session_view.native_turns, 5);
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
