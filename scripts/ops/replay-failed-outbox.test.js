'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { replayFailedOutbox, RECOVERY_SCHEMA_VERSION } = require('./replay-failed-outbox');

function digest(text) {
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

async function fixtureRoot() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-failed-outbox-'));
  await fs.mkdir(path.join(root, 'failed'), { mode: 0o700 });
  return root;
}

function legacyRecord(captureId = 'cap-legacy-replay') {
  const request = '{"model":"gpt-5.6-sol","input":"hello"}';
  const response = 'event: response.completed\ndata: {"type":"response.completed"}\n\n';
  return {
    recordType: 'api_snapshot',
    captureId,
    sourceNamespace: 'router-v2-18084',
    requestHeaders: {
      'x-codex-turn-metadata': JSON.stringify({
        session_id: 'session-replay',
        thread_id: 'thread-replay',
        turn_id: 'turn-replay',
        agent_name: '/root',
      }),
    },
    responseHeaders: {},
    requestBodyText: request,
    requestBytesCaptured: Buffer.byteLength(request) + 13,
    requestBodyOriginalSha256: digest(`${request} with a secret`),
    responseBodyText: response,
    responseBytesCaptured: Buffer.byteLength(response) + 7,
    responseStatus: 200,
    traceContext: {},
    captureSanitization: {
      version: 'chiptrace.capture-sanitization.v1',
      bodyRedacted: true,
      fields: ['body.token_like'],
    },
  };
}

test('dry-run plans a normalized, turn-scoped copy and leaves failed evidence unchanged', async t => {
  const root = await fixtureRoot();
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'failed', 'cap-legacy-replay.json');
  const original = Buffer.from(`${JSON.stringify(legacyRecord())}\n`);
  await fs.writeFile(file, original, { mode: 0o600 });
  await fs.writeFile(`${file}.error.json`, `${JSON.stringify({ captureId: 'cap-legacy-replay', reason: 'http_400' })}\n`, { mode: 0o600 });

  const report = await replayFailedOutbox({ root });
  assert.equal(report.mode, 'dry_run');
  assert.equal(report.selected, 1);
  assert.equal(report.planned, 1);
  assert.equal(report.copied, 0);
  assert.equal(report.blocked, 0);
  assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), JSON.parse(original.toString('utf8')));
  await assert.rejects(fs.access(path.join(root, 'pending', 'cap-legacy-replay.json')));
  assert.equal(report.records[0].trace_context_fields_added.includes('session_id'), true);
});

test('apply is atomic and idempotent while preserving failed and error marker files', async t => {
  const root = await fixtureRoot();
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'failed', 'cap-legacy-replay.json');
  const original = Buffer.from(`${JSON.stringify(legacyRecord())}\n`);
  await fs.writeFile(file, original, { mode: 0o600 });
  await fs.writeFile(`${file}.error.json`, `${JSON.stringify({ captureId: 'cap-legacy-replay', reason: 'http_400' })}\n`, { mode: 0o600 });

  const first = await replayFailedOutbox({ root, apply: true });
  assert.equal(first.copied, 1);
  assert.equal(first.blocked, 0);
  const pendingNames = await fs.readdir(path.join(root, 'pending'));
  assert.equal(pendingNames.length, 1);
  const pending = JSON.parse(await fs.readFile(path.join(root, 'pending', pendingNames[0]), 'utf8'));
  assert.equal(pending.outboxRecovery.schema_version, RECOVERY_SCHEMA_VERSION);
  assert.equal(pending.outboxRecovery.original_failed_file_name, 'cap-legacy-replay.json');
  assert.equal(pending.outboxRecovery.original_capture_id, 'cap-legacy-replay');
  assert.equal(pending.outboxRecovery.replay_capture_id, pending.captureId);
  assert.match(pending.captureId, /^cap-replay-[a-f0-9]{64}$/);
  assert.equal(pending.traceContext.session_id, 'session-replay');
  assert.equal(pending.traceContext.turn_id, 'turn-replay');
  assert.equal(pending.requestBytesCaptured, Buffer.byteLength(pending.requestBodyText));
  assert.equal(pending.responseBytesCaptured, Buffer.byteLength(pending.responseBodyText));
  assert.equal(pending.requestBodySha256, digest(pending.requestBodyText));
  assert.equal(await fs.readFile(file, 'utf8'), original.toString('utf8'));
  assert.match(await fs.readFile(`${file}.error.json`, 'utf8'), /http_400/);

  const second = await replayFailedOutbox({ root, apply: true });
  assert.equal(second.copied, 0);
  assert.equal(second.already_present, 1);
  assert.equal(second.blocked, 0);
});

test('identity conflicts are blocked without creating a pending copy', async t => {
  const root = await fixtureRoot();
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const record = legacyRecord('cap-conflict');
  record.traceContext = { session_id: 'different-session' };
  const file = path.join(root, 'failed', 'cap-conflict.json');
  await fs.writeFile(file, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  const report = await replayFailedOutbox({ root, apply: true });
  assert.equal(report.blocked, 1);
  assert.match(report.records[0].reason, /identity conflict/);
  assert.deepEqual(await fs.readdir(path.join(root, 'pending')), []);
});
