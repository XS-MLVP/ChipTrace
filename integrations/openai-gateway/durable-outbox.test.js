'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = fs.promises;
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  DurableCaptureOutbox,
  codexTraceContextFromHeaders,
  validateProviderCredential,
} = require('./durable-outbox');

test('Stock Codex headers provide exact Session and Turn identity', () => {
  const metadata = JSON.stringify({
    session_id: 'session-1',
    thread_id: 'thread-1',
    turn_id: 'turn-1',
    root_turn_id: 'turn-root',
    parent_thread_id: 'thread-parent',
    agent_name: '/root/review',
  });
  const result = codexTraceContextFromHeaders({
    'session-id': 'session-1',
    'thread-id': 'thread-1',
    'x-codex-turn-metadata': metadata,
    traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
  });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.conflicts, []);
  assert.equal(result.trace.session_id, 'session-1');
  assert.equal(result.trace.conversation_id, 'session-1');
  assert.equal(result.trace.thread_id, 'thread-1');
  assert.equal(result.trace.turn_id, 'turn-1');
  assert.equal(result.trace.root_turn_id, 'turn-root');
  assert.equal(result.trace.parent_thread_id, 'thread-parent');
  assert.equal(result.trace.agent_path, '/root/review');
});

test('malformed or conflicting Stock Codex metadata is explicit', () => {
  const malformed = codexTraceContextFromHeaders({
    'session-id': 'session-1',
    'x-codex-turn-metadata': '{not-json',
  });
  assert.equal(malformed.errors.length, 1);
  const conflict = codexTraceContextFromHeaders({
    'session-id': 'session-1',
    'x-codex-turn-metadata': JSON.stringify({ session_id: 'session-other' }),
  });
  assert.equal(conflict.trace.session_id, 'session-1');
  assert.equal(conflict.conflicts.length, 1);
});

test('managed model access validates the Provider credential upstream', async () => {
  const observed = [];
  const fetchImpl = async (url, options) => {
    observed.push({ url, authorization: options.headers.authorization });
    const valid = options.headers.authorization === 'Bearer provider-valid';
    return { ok: valid, status: valid ? 200 : 401 };
  };
  const missing = await validateProviderCredential({
    authorization: '',
    modelsUrl: 'http://provider.test/v1/models',
    fetchImpl,
  });
  const rejected = await validateProviderCredential({
    authorization: 'Bearer provider-invalid',
    modelsUrl: 'http://provider.test/v1/models',
    fetchImpl,
  });
  const accepted = await validateProviderCredential({
    authorization: 'Bearer provider-valid',
    modelsUrl: 'http://provider.test/v1/models',
    fetchImpl,
  });
  assert.deepEqual(missing, { ok: false, status: 401, reason: 'model_auth_required' });
  assert.deepEqual(rejected, { ok: false, status: 401, reason: 'model_auth_rejected' });
  assert.deepEqual(accepted, { ok: true, status: 200 });
  assert.deepEqual(observed, [
    {
      url: 'http://provider.test/v1/models',
      authorization: 'Bearer provider-invalid',
    },
    {
      url: 'http://provider.test/v1/models',
      authorization: 'Bearer provider-valid',
    },
  ]);
});

function temporaryRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-outbox-test-'));
}

function capture(id = 'cap-test-1') {
  return {
    captureId: id,
    recordType: 'api_snapshot',
    requestHeaders: { authorization: 'Bearer should-not-be-written' },
    responseHeaders: { 'x-request-id': 'req-1' },
    requestBodyText: JSON.stringify({ api_key: 'sk_secret_123456789012345', prompt: 'keep this' }),
    responseBodyText: JSON.stringify({ output: 'ok' }),
  };
}

async function fakeRelay(handler) {
  const server = http.createServer((req, res) => {
    res.setHeader('connection', 'close');
    handler(req, res);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

test('outbox preserves Wire bodies, strips credentials, retries, and removes after durable ACK', async () => {
  let attempts = 0;
  const ingestToken = 'test-ingest-token-at-least-32-bytes';
  const relay = await fakeRelay((req, res) => {
    attempts += 1;
    assert.equal(req.headers.authorization, `Bearer ${ingestToken}`);
    req.resume();
    req.once('end', () => {
      res.setHeader('content-type', 'application/json');
      if (attempts < 3) {
        res.statusCode = 503;
        res.end(JSON.stringify({ ok: false, reason: 'temporary' }));
      } else {
        res.statusCode = 202;
        res.end(JSON.stringify({ ok: true, durable: true, duplicate: false }));
      }
    });
  });
  const root = temporaryRoot();
  const outbox = new DurableCaptureOutbox({
    root,
    relayUrl: relay.url,
    bearerToken: ingestToken,
    retryBaseMs: 1,
    retryMaxMs: 2,
    retryJitterPercent: 0,
    maxAttempts: 20,
  });
  try {
    const ack = await outbox.enqueue(capture());
    assert.equal(ack.durable, true);
    const stored = JSON.parse(await fsp.readFile(path.join(root, 'pending', 'cap-test-1.json'), 'utf8'));
    assert.equal(stored.requestHeaders.authorization, undefined);
    assert.equal(stored.requestBodyText, capture().requestBodyText);
    assert.equal(stored.captureSanitization.bodyRedacted, false);
    assert.equal(await outbox.flush(3000), true);
    assert.equal(attempts, 3);
    assert.equal(outbox.snapshot().pending, 0);
    assert.equal(outbox.snapshot().processing, 0);
    assert.equal(outbox.snapshot().queueBytes, 0);
    assert.equal(outbox.snapshot().activeQueueBytes, 0);
    assert.equal(outbox.snapshot().oldestPendingAt, null);
    assert.equal(fs.readdirSync(path.join(root, 'pending')).length, 0);
  } finally {
    await outbox.close();
    await relay.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('processing files are recovered and replayed after a restart', async () => {
  const root = temporaryRoot();
  const first = new DurableCaptureOutbox({ root, relayUrl: '', maxAttempts: 20 });
  await first.start();
  await first.enqueue(capture('cap-restart'));
  await fsp.rename(
    path.join(root, 'pending', 'cap-restart.json'),
    path.join(root, 'processing', 'cap-restart.json'),
  );
  await first.close();

  let received = 0;
  const relay = await fakeRelay((req, res) => {
    received += 1;
    req.resume();
    req.once('end', () => {
      res.statusCode = 202;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true, durable: true, duplicate: false }));
    });
  });
  const second = new DurableCaptureOutbox({
    root,
    relayUrl: relay.url,
    retryBaseMs: 1,
    retryMaxMs: 1,
    retryJitterPercent: 0,
    maxAttempts: 20,
  });
  try {
    await second.start();
    assert.equal(await second.flush(2000), true);
    assert.equal(received, 1);
    assert.equal(second.snapshot().pending, 0);
    assert.equal(second.snapshot().processing, 0);
  } finally {
    await second.close();
    await relay.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('complete temporary writes are recovered while corrupt tails are quarantined', async () => {
  const root = temporaryRoot();
  const bootstrap = new DurableCaptureOutbox({ root, relayUrl: '', maxAttempts: 20 });
  await bootstrap.start();
  await bootstrap.close();
  fs.writeFileSync(
    path.join(root, 'pending', 'cap-temp.json.1.tmp'),
    `${JSON.stringify(capture('cap-temp-recovery'))}\n`,
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(root, 'pending', 'cap-corrupt.json.2.tmp'),
    '{"captureId":"cap-corrupt"',
    { mode: 0o600 },
  );
  let received = 0;
  const relay = await fakeRelay((req, res) => {
    received += 1;
    req.resume();
    req.once('end', () => {
      res.statusCode = 202;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true, durable: true, duplicate: false }));
    });
  });
  const outbox = new DurableCaptureOutbox({
    root,
    relayUrl: relay.url,
    retryBaseMs: 1,
    retryMaxMs: 1,
    retryJitterPercent: 0,
    maxAttempts: 20,
  });
  try {
    await outbox.start();
    assert.equal(await outbox.flush(2000), true);
    assert.equal(received, 1);
    assert.equal(fs.readdirSync(path.join(root, 'pending')).length, 0);
    assert.equal(
      fs.readdirSync(path.join(root, 'failed')).some((name) => name.includes('cap-invalid-')),
      true,
    );
  } finally {
    await outbox.close();
    await relay.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('same capture bytes are idempotent and changed bytes are a conflict', async () => {
  const root = temporaryRoot();
  const outbox = new DurableCaptureOutbox({ root, relayUrl: '', maxAttempts: 20 });
  try {
    await outbox.start();
    const results = await Promise.all(Array.from(
      { length: 20 },
      () => outbox.enqueue(capture('cap-idempotent')),
    ));
    assert.equal(results.filter((result) => result.duplicate === false).length, 1);
    assert.equal(results.filter((result) => result.duplicate === true).length, 19);
    await assert.rejects(
      outbox.enqueue({ ...capture('cap-idempotent'), responseBodyText: 'changed' }),
      (error) => error.code === 'CAPTURE_ID_CONFLICT',
    );
    assert.equal(outbox.snapshot().pending, 1);
  } finally {
    await outbox.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('concurrent different bytes for one capture ID cannot overwrite each other', async () => {
  const root = temporaryRoot();
  const outbox = new DurableCaptureOutbox({ root, relayUrl: '', maxAttempts: 20 });
  try {
    await outbox.start();
    const outcomes = await Promise.allSettled([
      outbox.enqueue({ ...capture('cap-race'), responseBodyText: 'first' }),
      outbox.enqueue({ ...capture('cap-race'), responseBodyText: 'second' }),
    ]);
    assert.equal(outcomes.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(outcomes.filter((result) => result.status === 'rejected').length, 1);
    const rejected = outcomes.find((result) => result.status === 'rejected');
    assert.equal(rejected.reason.code, 'CAPTURE_ID_CONFLICT');
    const files = fs.readdirSync(path.join(root, 'pending'));
    assert.equal(files.length, 1);
    const stored = JSON.parse(fs.readFileSync(path.join(root, 'pending', files[0]), 'utf8'));
    assert.ok(['first', 'second'].includes(stored.responseBodyText));
  } finally {
    await outbox.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('file and free-space cutoffs reject new captures without deleting queued evidence', async () => {
  const fileRoot = temporaryRoot();
  const fileLimited = new DurableCaptureOutbox({
    root: fileRoot,
    relayUrl: '',
    maxFiles: 1,
    minFreeBytes: 0,
    minFreeFiles: 0,
    maxAttempts: 20,
  });
  try {
    await fileLimited.start();
    await fileLimited.enqueue(capture('cap-limit-1'));
    await assert.rejects(
      fileLimited.enqueue(capture('cap-limit-2')),
      (error) => error.code === 'OUTBOX_FULL',
    );
    assert.equal(fs.readdirSync(path.join(fileRoot, 'pending')).length, 1);
  } finally {
    await fileLimited.close();
    fs.rmSync(fileRoot, { recursive: true, force: true });
  }

  const diskRoot = temporaryRoot();
  const diskLimited = new DurableCaptureOutbox({
    root: diskRoot,
    relayUrl: '',
    minFreeBytes: Number.MAX_SAFE_INTEGER,
    minFreeFiles: 0,
    maxAttempts: 20,
  });
  try {
    await diskLimited.start();
    await assert.rejects(
      diskLimited.enqueue(capture('cap-disk-pressure')),
      (error) => error.code === 'OUTBOX_DISK_PRESSURE',
    );
    assert.equal(fs.readdirSync(path.join(diskRoot, 'pending')).length, 0);
  } finally {
    await diskLimited.close();
    fs.rmSync(diskRoot, { recursive: true, force: true });
  }
});

test('permanent relay conflict is retained in failed for audit', async () => {
  const relay = await fakeRelay((req, res) => {
    req.resume();
    req.once('end', () => {
      res.statusCode = 409;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: false, reason: 'capture_id_conflict' }));
    });
  });
  const root = temporaryRoot();
  const outbox = new DurableCaptureOutbox({ root, relayUrl: relay.url, maxAttempts: 20 });
  try {
    await outbox.enqueue(capture('cap-conflict'));
    assert.equal(await outbox.flush(2000), true);
    assert.equal(outbox.snapshot().conflicts, 1);
    assert.equal(fs.existsSync(path.join(root, 'failed', 'cap-conflict.json')), true);
    assert.equal(fs.existsSync(path.join(root, 'failed', 'cap-conflict.json.error.json')), true);
  } finally {
    await outbox.close();
    await relay.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('permanent validation error is retained once and never retried', async () => {
  let attempts = 0;
  const relay = await fakeRelay((req, res) => {
    attempts += 1;
    req.resume();
    req.once('end', () => {
      res.statusCode = 400;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: false, reason: 'invalid_capture' }));
    });
  });
  const root = temporaryRoot();
  const outbox = new DurableCaptureOutbox({ root, relayUrl: relay.url, maxAttempts: 20 });
  try {
    await outbox.enqueue(capture('cap-invalid'));
    assert.equal(await outbox.flush(2000), true);
    assert.equal(attempts, 1);
    assert.equal(outbox.snapshot().pending, 0);
    assert.equal(outbox.snapshot().failedFiles, 1);
    assert.equal(outbox.snapshot().activeQueueBytes, 0);
    assert.ok(outbox.snapshot().failedBytes > 0);
    assert.equal(fs.existsSync(path.join(root, 'failed', 'cap-invalid.json')), true);
  } finally {
    await outbox.close();
    await relay.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('historical failed evidence is reported without poisoning fresh health', async () => {
  const root = temporaryRoot();
  await fsp.mkdir(path.join(root, 'failed'), { recursive: true });
  await fsp.writeFile(
    path.join(root, 'failed', 'cap-historical.json'),
    `${JSON.stringify(capture('cap-historical'))}\n`,
    { mode: 0o600 },
  );
  await fsp.writeFile(
    path.join(root, 'failed', 'cap-historical.json.error.json'),
    `${JSON.stringify({ captureId: 'cap-historical', reason: 'http_400' })}\n`,
    { mode: 0o600 },
  );
  const relay = await fakeRelay((req, res) => {
    req.resume();
    req.once('end', () => {
      res.statusCode = 202;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true, durable: true, duplicate: false }));
    });
  });
  const outbox = new DurableCaptureOutbox({
    root,
    relayUrl: relay.url,
    retryBaseMs: 1,
    retryMaxMs: 1,
    retryJitterPercent: 0,
    maxAttempts: 20,
  });
  try {
    await outbox.start();
    let snapshot = outbox.snapshot();
    assert.equal(snapshot.historicalFailedFiles, 1);
    assert.equal(snapshot.historicalAuxiliaryFiles, 1);
    assert.equal(snapshot.recentFailureCount, 0);
    assert.equal(snapshot.currentFailureCount, 0);
    await outbox.enqueue(capture('cap-fresh'));
    assert.equal(await outbox.flush(2000), true);
    snapshot = outbox.snapshot();
    assert.equal(snapshot.recentFailureCount, 0);
    assert.equal(snapshot.currentFailureCount, 0);
    assert.equal(snapshot.historicalFailureCount, 2);
  } finally {
    await outbox.close();
    await relay.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
