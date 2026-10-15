'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = fs.promises;
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const test = require('node:test');

const {
  DurableCaptureOutbox,
  ResponsesSseBoundaryTracker,
  codexTraceContextFromHeaders,
  reconcileCaptureBodyMetadata,
  sanitizeCaptureRecord,
  validateProviderCredential,
} = require('./durable-outbox');

function cryptoHash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// Contract fixtures only. The separate gateway receipt integration test uses
// the real Relay and Collector and verifies the committed WAL bytes.
function syntheticReceipt(bytes, duplicate = false) {
  const record = JSON.parse(bytes.toString('utf8'));
  return {
    ok: true, durable: true, local_durable: true, duplicate,
    input_receipt: { schema_version: 'chiptrace.capture-input-receipt.v1',
      bytes: bytes.length, sha256: cryptoHash(bytes) },
    capture: { capture_id: record.captureId, state: duplicate ? 'duplicate' : 'accepted',
      durable: true, duplicate, raw_sha256: cryptoHash(bytes), length: bytes.length,
      segment_id: 1, offset: 0 },
  };
}

test('Responses SSE boundary requires a complete terminal event', () => {
  const tracker = new ResponsesSseBoundaryTracker();
  let state = tracker.observe(Buffer.from(
    'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"response.completed"}\n\n',
  ));
  assert.equal(state.protocolTerminalObserved, false);
  assert.equal(state.responseBoundaryObserved, false);

  state = tracker.observe(Buffer.from('event: response.comp'));
  assert.equal(state.protocolTerminalObserved, false);
  state = tracker.observe(Buffer.from(
    `leted\ndata: {"type":"response.completed","response":{"output":"${'x'.repeat(4096)}"}}`,
  ));
  assert.equal(state.protocolTerminalObserved, false);
  state = tracker.observe(Buffer.from('\n\n: keep-alive\n\n'));
  assert.equal(state.protocolTerminalObserved, true);
  assert.equal(state.protocolTerminalEvent, 'response.completed');
  assert.equal(state.responseBoundaryObserved, true);
  assert.equal(state.responseBytesObserved > 0, true);
  assert.equal(typeof state.protocolTerminalByteOffset, 'number');
  assert.equal(state.framingDoneObserved, false);
});

test('Responses SSE framing closes transport without inventing protocol completion', () => {
  const tracker = new ResponsesSseBoundaryTracker();
  const state = tracker.observe(Buffer.from(
    'data: {"type":"response.created"}\n\ndata: [DONE]\n\n',
  ));
  assert.equal(state.protocolTerminalObserved, false);
  assert.equal(state.framingDoneObserved, true);
  assert.equal(typeof state.framingDoneByteOffset, 'number');
  assert.equal(state.responseBoundaryObserved, true);
});

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

async function interruptedFinalization(t, { partial = false, sanitize = false } = {}) {
  const root = temporaryRoot();
  const first = new DurableCaptureOutbox({ root, relayUrl: '', sanitize,
    minFreeBytes: 0, minFreeFiles: 0 });
  t.after(async () => {
    await first.close();
    fs.rmSync(root, { recursive: true, force: true });
  });
  const transaction = await first.beginCapture({ captureId: 'cap-interrupted-finalize',
    sourceNamespace: 'synthetic-recovery', traceContext: { session_id: 'session-a', turn_id: 'turn-a' } });
  const request = Buffer.from('{"input":"原文 🧪","api_key":"sk_synthetic_recovery_123456789012345"}');
  const response = Buffer.from('event: response.completed\ndata: {"type":"response.completed","output":"原样响应"}\n\n');
  const split = request.indexOf(Buffer.from('原')) + 1;
  await transaction.appendRequest(request.subarray(0, split));
  await transaction.appendRequest(request.subarray(split));
  await transaction.appendResponse(response);
  const originalRm = fsp.rm;
  const intercepted = t.mock.method(fsp, 'rm', async (file, ...args) => {
    if (Object.values(transaction.files).includes(file)
      && (!partial || file === transaction.files.metadata)) {
      throw Object.assign(new Error('synthetic interrupted spool cleanup'), { code: 'EIO' });
    }
    return originalRm(file, ...args);
  });
  try { await assert.rejects(transaction.finalize({ responseStatus: 200 }), { code: 'EIO' }); }
  finally { intercepted.mock.restore(); await first.close(); }
  const pending = path.join(root, 'pending', 'cap-interrupted-finalize.json');
  return { root, first, transaction, pending, request, response };
}

test('body sanitization reconciles bytes and hashes while retaining the original hash', () => {
  const original = capture('cap-sanitize-contract');
  const sanitized = sanitizeCaptureRecord(original, true);
  assert.notEqual(sanitized.requestBodyText, original.requestBodyText);
  assert.equal(
    sanitized.requestBytesCaptured,
    Buffer.byteLength(sanitized.requestBodyText, 'utf8'),
  );
  assert.equal(sanitized.requestBodySha256, cryptoHash(sanitized.requestBodyText));
  assert.equal(
    sanitized.requestBodyTextOriginalSha256,
    cryptoHash(original.requestBodyText),
  );
  assert.equal(
    reconcileCaptureBodyMetadata({
      ...sanitized,
      requestBytesCaptured: 1,
      requestBodySha256: '0'.repeat(64),
    }).record.requestBodySha256,
    cryptoHash(sanitized.requestBodyText),
  );
});

test('historical records with stale body metadata are repaired only in the replay copy', async () => {
  const root = temporaryRoot();
  const failedDir = path.join(root, 'failed');
  await fsp.mkdir(failedDir, { recursive: true });
  const historical = capture('cap-historical-replay');
  historical.requestBytesCaptured += 17;
  historical.requestBodySha256 = '1'.repeat(64);
  historical.responseBytesCaptured += 19;
  historical.responseBodySha256 = '2'.repeat(64);
  const historicalBytes = Buffer.from(`${JSON.stringify(historical)}\n`, 'utf8');
  const historicalFile = path.join(failedDir, 'cap-historical-replay.json');
  await fsp.writeFile(historicalFile, historicalBytes, { mode: 0o600 });
  await fsp.writeFile(
    `${historicalFile}.error.json`,
    `${JSON.stringify({ captureId: historical.captureId, reason: 'http_400' })}\n`,
    { mode: 0o600 },
  );

  let received = 0;
  const relay = await fakeRelay((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.once('end', () => {
      received += 1;
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      assert.equal(body.requestBytesCaptured, Buffer.byteLength(body.requestBodyText, 'utf8'));
      assert.equal(body.requestBodySha256, cryptoHash(body.requestBodyText));
      assert.equal(body.responseBytesCaptured, Buffer.byteLength(body.responseBodyText, 'utf8'));
      assert.equal(body.responseBodySha256, cryptoHash(body.responseBodyText));
      res.statusCode = 202;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(syntheticReceipt(req.rawTestBody)));
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
    await fsp.copyFile(historicalFile, path.join(root, 'pending', 'cap-historical-replay.json'));
    await outbox.refreshQueueStats();
    assert.equal(await outbox.flush(2000), true);
    assert.equal(received, 1);
    assert.deepEqual(await fsp.readFile(historicalFile), historicalBytes);
    assert.equal(fs.existsSync(path.join(root, 'pending', 'cap-historical-replay.json')), false);
    assert.equal(outbox.snapshot().recentFailureCount, 0);
  } finally {
    await outbox.close();
    await relay.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

async function fakeRelay(handler) {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.once('end', () => { req.rawTestBody = Buffer.concat(chunks); });
    res.setHeader('connection', 'close');
    handler(req, res);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

test('queue rescan cannot resurrect a Capture after its durable receipt', { timeout: 10000 }, async t => {
  const root = temporaryRoot();
  const relay = await fakeRelay((req, res) => {
    req.resume();
    req.once('end', () => res.end(JSON.stringify(syntheticReceipt(req.rawTestBody))));
  });
  const outbox = new DurableCaptureOutbox({ root, relayUrl: '' });
  let releaseScan;
  const scanReleased = new Promise(resolve => { releaseScan = resolve; });
  let notifyScanned;
  const scanned = new Promise(resolve => { notifyScanned = resolve; });
  let refresh;
  try {
    await outbox.enqueue(capture('cap-rescan-delivered'), { schedule: false });
    const pendingFile = path.join(root, 'pending', 'cap-rescan-delivered.json');
    const originalStat = fsp.stat;
    let paused = false;
    t.mock.method(fsp, 'stat', async (file, ...args) => {
      const stat = await originalStat(file, ...args);
      if (file === pendingFile && !paused) {
        paused = true;
        notifyScanned();
        await scanReleased;
      }
      return stat;
    });
    refresh = outbox.refreshQueueStats();
    await scanned;
    outbox.relayUrl = relay.url;
    assert.equal(await outbox.flush(1000), true);
    assert.equal(outbox.snapshot().durable, 1);
    assert.equal(fs.existsSync(pendingFile), false);
    releaseScan();
    await refresh;
    const snapshot = outbox.snapshot();
    assert.equal(snapshot.pending, 0);
    assert.equal(snapshot.processing, 0);
    assert.equal(snapshot.activeQueueBytes, 0);
    assert.equal(snapshot.queueBytes, 0);
    assert.equal(snapshot.oldestPendingAt, null);
    assert.equal(await outbox.flush(100), true);
  } finally {
    releaseScan();
    if (refresh) await refresh;
    await outbox.close();
    if (outbox.drainPromise) await outbox.drainPromise;
    await relay.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('queue rescan cannot hide a Capture accepted while its directory was scanned',
  { timeout: 10000 }, async t => {
    const root = temporaryRoot();
    const outbox = new DurableCaptureOutbox({ root, relayUrl: '', maxFiles: 1 });
    let releaseScan;
    const scanReleased = new Promise(resolve => { releaseScan = resolve; });
    let notifyScanned;
    const scanned = new Promise(resolve => { notifyScanned = resolve; });
    let refresh;
    try {
      await outbox.start();
      const originalReadDir = fsp.readdir;
      let paused = false;
      t.mock.method(fsp, 'readdir', async (directory, ...args) => {
        const entries = await originalReadDir(directory, ...args);
        if (directory === outbox.pendingDir && !paused) {
          paused = true;
          notifyScanned();
          await scanReleased;
        }
        return entries;
      });
      refresh = outbox.refreshQueueStats();
      await scanned;
      await outbox.enqueue(capture('cap-rescan-accepted'), { schedule: false });
      const file = path.join(root, 'pending', 'cap-rescan-accepted.json');
      const originalBytes = await fsp.readFile(file);
      releaseScan();
      await refresh;
      const snapshot = outbox.snapshot();
      assert.equal(snapshot.pending, 1);
      assert.equal(snapshot.processing, 0);
      assert.equal(snapshot.activeQueueBytes, originalBytes.length);
      assert.equal(snapshot.queueBytes, originalBytes.length);
      assert.equal(typeof snapshot.oldestPendingAt, 'string');
      assert.equal(await outbox.flush(50), false);
      await assert.rejects(outbox.enqueue(capture('cap-rescan-over-capacity')),
        error => error.code === 'OUTBOX_FULL');
      assert.deepEqual(await fsp.readFile(file), originalBytes);
    } finally {
      releaseScan();
      if (refresh) await refresh;
      await outbox.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

test('queue rescan preserves streamed bytes and finalized Capture state', { timeout: 10000 }, async t => {
  for (const phase of ['append', 'finalize']) await t.test(phase, async t => {
    const root = temporaryRoot();
    const outbox = new DurableCaptureOutbox({ root, relayUrl: '' });
    let releaseScan;
    const scanReleased = new Promise(resolve => { releaseScan = resolve; });
    let notifyScanned;
    const scanned = new Promise(resolve => { notifyScanned = resolve; });
    let refresh;
    try {
      const transaction = await outbox.beginCapture({ captureId: 'cap-stream-rescan', sourceNamespace: 'test' });
      await transaction.appendRequest(Buffer.from('原始请求 '));
      const requestFile = path.join(root, 'open', 'cap-stream-rescan.request.bin');
      const watchedFile = phase === 'finalize' ? transaction.files.metadata : requestFile;
      const originalStat = fsp.stat;
      let paused = false;
      t.mock.method(fsp, 'stat', async (file, ...args) => {
        const stat = await originalStat(file, ...args);
        if (file === watchedFile && !paused) {
          paused = true;
          notifyScanned();
          await scanReleased;
        }
        return stat;
      });
      refresh = outbox.refreshQueueStats();
      await scanned;
      await transaction.appendRequest(Buffer.from('🧪 不截断'));
      if (phase === 'finalize') await transaction.finalize({ responseStatus: 200 });
      releaseScan();
      await refresh;
      const snapshot = outbox.snapshot();
      assert.equal(snapshot.lastError, null);
      assert.equal(snapshot.pending, phase === 'finalize' ? 1 : 0);
      assert.equal(snapshot.openTransactions, phase === 'finalize' ? 0 : 1);
      assert.equal(snapshot.openCaptureHealthy, true);
      assert.equal(snapshot.openBytes, phase === 'finalize' ? 0 : transaction.persistedBytes);
      if (phase === 'append') {
        assert.equal(snapshot.queueBytes, transaction.persistedBytes);
        assert.deepEqual(await fsp.readFile(requestFile), Buffer.from('原始请求 🧪 不截断'));
      } else {
        assert.deepEqual(await fsp.readdir(outbox.openDir), []);
        const bytes = await fsp.readFile(path.join(root, 'pending', 'cap-stream-rescan.json'));
        assert.equal(snapshot.activeQueueBytes, bytes.length);
        assert.equal(snapshot.queueBytes, bytes.length);
        const record = JSON.parse(bytes);
        assert.equal(record.requestBodyText, '原始请求 🧪 不截断');
        assert.equal(record.requestBytesCaptured, Buffer.byteLength(record.requestBodyText));
        assert.equal(record.requestBodySha256, cryptoHash(record.requestBodyText));
      }
    } finally {
      releaseScan();
      if (refresh) await refresh;
      await outbox.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

test('queue rescan stays available while a Relay receipt is outstanding', { timeout: 10000 }, async () => {
  const root = temporaryRoot();
  let releaseReceipt;
  const receiptReleased = new Promise(resolve => { releaseReceipt = resolve; });
  let notifyReceived;
  const received = new Promise(resolve => { notifyReceived = resolve; });
  const relay = await fakeRelay((req, res) => {
    req.resume();
    req.once('end', async () => {
      notifyReceived();
      await receiptReleased;
      res.end(JSON.stringify(syntheticReceipt(req.rawTestBody)));
    });
  });
  const outbox = new DurableCaptureOutbox({ root, relayUrl: '' });
  let delivery;
  let refresh;
  let timer;
  try {
    await outbox.enqueue(capture('cap-slow-receipt'), { schedule: false });
    outbox.relayUrl = relay.url;
    delivery = outbox.flush(5000);
    await received;
    refresh = outbox.refreshQueueStats();
    assert.equal(await Promise.race([refresh.then(() => true),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), 2000); })]), true);
    const snapshot = outbox.snapshot();
    assert.equal(snapshot.processing, 1);
    assert.equal(snapshot.pending, 0);
    assert.equal(snapshot.durable, 0);
    assert.ok(snapshot.activeQueueBytes > 0);
    assert.ok(fs.existsSync(path.join(root, 'processing', 'cap-slow-receipt.json')));
    releaseReceipt();
    assert.equal(await delivery, true);
    assert.equal(outbox.snapshot().processing, 0);
    assert.equal(outbox.snapshot().queueBytes, 0);
  } finally {
    clearTimeout(timer);
    releaseReceipt();
    if (delivery) await delivery;
    if (refresh) await refresh;
    await outbox.close();
    await relay.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('outbox retains exact pending bytes when Relay returns an unproven durable ACK', async t => {
  const cases = [
    ['ACK-only', () => ({ ok: true, durable: true, duplicate: false })],
    ['missing input receipt', r => { delete r.input_receipt; return r; }],
    ['wrong input hash', r => { r.input_receipt.sha256 = '0'.repeat(64); return r; }],
    ['wrong input length', r => { r.input_receipt.bytes++; return r; }],
    ['wrong input schema', r => { r.input_receipt.schema_version = 'unknown'; return r; }],
    ['wrong Capture ID', r => { r.capture.capture_id = 'cap-unrelated'; return r; }],
    ['not locally durable', r => { r.local_durable = false; return r; }],
    ['not durably stored', r => { r.capture.durable = false; return r; }],
    ['conflicting duplicate state', r => { r.capture.duplicate = true; return r; }],
    ['pending Capture state', r => { r.capture.state = 'pending'; return r; }],
    ['invalid stored hash', r => { r.capture.raw_sha256 = 'not-a-sha256'; return r; }],
    ['invalid WAL locator', r => { r.capture.offset = -1; return r; }],
    ['invalid JSON', () => '{'],
  ];
  for (const [name, transform] of cases) await t.test(name, async () => {
    const relay = await fakeRelay((req, res) => {
      req.resume();
      req.once('end', () => {
        const response = transform(syntheticReceipt(req.rawTestBody));
        res.writeHead(202, { 'content-type': 'application/json' });
        res.end(typeof response === 'string' ? response : JSON.stringify(response));
      });
    });
    const root = temporaryRoot();
    const outbox = new DurableCaptureOutbox({
      root, relayUrl: '', maxAttempts: 1,
      retryBaseMs: 1, retryMaxMs: 1, retryJitterPercent: 0,
    });
    try {
      await outbox.enqueue(capture('cap-unproven-receipt'), { schedule: false });
      const file = path.join(root, 'pending', 'cap-unproven-receipt.json');
      const original = await fsp.readFile(file);
      outbox.relayUrl = relay.url;
      assert.equal(await outbox.flush(100), false);
      await outbox.close();
      if (outbox.drainPromise) await outbox.drainPromise;
      assert.deepEqual(await fsp.readFile(file), original);
      assert.equal(outbox.snapshot().durable, 0);
      assert.equal(outbox.snapshot().failedFiles, 0);
    } finally {
      await outbox.close();
      if (outbox.drainPromise) await outbox.drainPromise;
      await relay.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

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
        res.end(JSON.stringify(syntheticReceipt(req.rawTestBody)));
      }
    });
  });
  const root = temporaryRoot();
  const outbox = new DurableCaptureOutbox({
    root,
    relayUrl: '',
    bearerToken: ingestToken,
    retryBaseMs: 1,
    retryMaxMs: 2,
    retryJitterPercent: 0,
    maxAttempts: 20,
  });
  try {
    const ack = await outbox.enqueue(capture(), { schedule: false });
    assert.equal(ack.durable, true);
    const stored = JSON.parse(await fsp.readFile(path.join(root, 'pending', 'cap-test-1.json'), 'utf8'));
    assert.equal(stored.requestHeaders.authorization, undefined);
    assert.equal(stored.requestBodyText, capture().requestBodyText);
    assert.equal(stored.captureSanitization.bodyRedacted, false);
    outbox.relayUrl = relay.url;
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
      res.end(JSON.stringify(syntheticReceipt(req.rawTestBody)));
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

test('two-phase capture durably starts before streaming and finalizes exact Wire bytes', async () => {
  const root = temporaryRoot();
  const outbox = new DurableCaptureOutbox({ root, relayUrl: '', maxAttempts: 20 });
  try {
    const transaction = await outbox.beginCapture({
      captureId: 'cap-two-phase',
      sourceNamespace: 'gateway-test',
      method: 'POST',
      proxiedPath: '/v1/responses',
      startedAt: '2026-09-08T00:00:00Z',
    }, {
      maxRequestBytes: 1024,
      maxResponseBytes: 1024,
    });
    const openNames = fs.readdirSync(path.join(root, 'open'));
    assert.deepEqual(openNames, ['cap-two-phase.open.json']);
    const open = JSON.parse(fs.readFileSync(path.join(root, 'open', openNames[0]), 'utf8'));
    assert.equal(open.captureId, 'cap-two-phase');
    assert.equal(open.captureStage, 'ingress');
    assert.equal(open.captureTransaction.state, 'open');

    await Promise.all([
      transaction.appendRequest(Buffer.from('{"input":')),
      transaction.appendRequest(Buffer.from('"hello"}')),
      transaction.appendResponse(Buffer.from('data: {"type":"response.completed"}\n')),
      transaction.appendResponse(Buffer.from('data: [DONE]\n\n')),
    ]);
    const ack = await transaction.finalize({
      finishedAt: '2026-09-08T00:00:01Z',
      responseStatus: 200,
      stream: true,
      upstreamResponseCompleted: true,
      clientResponseFinished: true,
    });
    assert.equal(ack.durable, true);
    assert.equal(ack.duplicate, false);
    assert.deepEqual(fs.readdirSync(path.join(root, 'open')), []);
    const stored = JSON.parse(
      fs.readFileSync(path.join(root, 'pending', 'cap-two-phase.json'), 'utf8'),
    );
    assert.equal(stored.requestBodyText, '{"input":"hello"}');
    assert.equal(stored.requestBytesCaptured, Buffer.byteLength(stored.requestBodyText));
    assert.equal(stored.responseBodyText, 'data: {"type":"response.completed"}\ndata: [DONE]\n\n');
    assert.equal(stored.responseBytesCaptured, Buffer.byteLength(stored.responseBodyText));
    assert.equal(stored.requestBodySha256, cryptoHash(stored.requestBodyText));
    assert.equal(stored.responseBodySha256, cryptoHash(stored.responseBodyText));
    assert.equal(stored.captureTransaction.state, 'finalized');
    assert.equal(outbox.snapshot().openTransactions, 0);
    assert.equal(outbox.snapshot().pending, 1);
  } finally {
    await outbox.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('open streamed captures expose age and stale transaction count', async t => {
  const root = temporaryRoot();
  const outbox = new DurableCaptureOutbox({ root, relayUrl: '', maxOpenAgeMs: 1000 });
  try {
    await outbox.start();
    const transaction = await outbox.beginCapture({
      captureId: 'cap-stale-open',
      sourceNamespace: 'gateway-test',
      method: 'POST',
      proxiedPath: '/v1/responses',
    });
    // Age the observation without changing the immutable ingress metadata.
    const originalNow = Date.now;
    t.mock.method(Date, 'now', () => originalNow() + 5000);
    await outbox.refreshQueueStats();
    const snapshot = outbox.snapshot();
    assert.equal(snapshot.openTransactions, 1);
    assert.equal(snapshot.staleOpenTransactions, 1);
    assert.equal(snapshot.openCaptureHealthy, false);
    assert.ok(snapshot.oldestOpenAgeMs >= 5000);
    await transaction.finalize({
      finishedAt: new Date().toISOString(),
      responseStatus: 200,
      responseBodyText: '{}',
      upstreamResponseCompleted: true,
      clientResponseFinished: true,
    });
    assert.equal(outbox.snapshot().staleOpenTransactions, 0);
    assert.equal(outbox.snapshot().oldestOpenAt, null);
    assert.equal(outbox.snapshot().openCaptureHealthy, true);
  } finally {
    await outbox.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('restart preserves open Wire when the same Capture ID has conflicting stored evidence', async t => {
  for (const directory of ['pending', 'failed']) await t.test(directory, async t => {
    const root = temporaryRoot();
    const first = new DurableCaptureOutbox({ root, relayUrl: '', minFreeBytes: 0, minFreeFiles: 0 });
    let second;
    try {
      const transaction = await first.beginCapture({ captureId: 'cap-recovery-conflict',
        sourceNamespace: 'synthetic-original', traceContext: { session_id: 'session-a', turn_id: 'turn-a' } });
      await transaction.appendRequest(Buffer.from('原始请求 🧪'));
      await transaction.appendResponse(Buffer.from('原始响应 🧪'));
      await first.close();
      const existing = path.join(root, directory, 'cap-recovery-conflict.json');
      await fsp.writeFile(existing, `${JSON.stringify({ ...capture('cap-recovery-conflict'),
        sourceNamespace: 'synthetic-conflict', traceContext: { session_id: 'session-b', turn_id: 'turn-b' } })}\n`);
      const originals = new Map(await Promise.all([...Object.values(transaction.files), existing]
        .map(async file => [file, await fsp.readFile(file)])));
      second = new DurableCaptureOutbox({ root, relayUrl: '', minFreeBytes: 0, minFreeFiles: 0 });
      const outcome = await second.start().then(() => ({ status: 'fulfilled' }),
        error => ({ status: 'rejected', error }));
      const retained = await Promise.all([...originals.keys()].map(async file => {
        try { return (await fsp.readFile(file)).equals(originals.get(file)); }
        catch (error) { if (error.code === 'ENOENT') return false; throw error; }
      }));
      t.diagnostic(JSON.stringify({ startup: outcome.status, unchanged_files: retained }));
      assert.equal(outcome.status, 'rejected');
      assert.equal(outcome.error.code, 'CAPTURE_ID_CONFLICT');
      assert.ok(retained.every(Boolean), 'recovery must preserve both versions byte for byte');
      assert.equal(second.started, false);
      assert.equal(second.snapshot().conflicts, 1);
    } finally {
      await first.close();
      if (second) await second.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

test('restart verifies interrupted finalization before cleaning open spools', async t => {
  const cases = [
    ['complete spools', 'pending', false, false],
    ['partly removed spools', 'pending', true, false],
    ['explicit redaction', 'pending', true, true],
    ['retained failed record', 'failed', false, false],
    ['interrupted processing', 'processing', true, false],
  ];
  for (const [name, directory, partial, sanitize] of cases) await t.test(name, async t => {
    const { root, transaction, pending, request, response } = await interruptedFinalization(t, { partial, sanitize });
    const storedFile = path.join(root, directory, path.basename(pending));
    if (storedFile !== pending) await fsp.rename(pending, storedFile);
    const original = await fsp.readFile(storedFile);
    const record = JSON.parse(original);
    const receipt = record.captureTransaction.openReceipt;
    assert.equal(receipt.schema_version, 'chiptrace.open-capture-receipt.v1');
    const metadata = await fsp.readFile(transaction.files.metadata);
    assert.deepEqual(receipt.metadata, { bytes: metadata.length, sha256: cryptoHash(metadata) });
    assert.deepEqual(receipt.request, { bytes: request.length, sha256: cryptoHash(request) });
    assert.deepEqual(receipt.response, { bytes: response.length, sha256: cryptoHash(response) });
    if (partial) await assert.rejects(fsp.stat(transaction.files.request), { code: 'ENOENT' });
    else assert.deepEqual(await fsp.readFile(transaction.files.request), request);
    const second = new DurableCaptureOutbox({ root, relayUrl: '', minFreeBytes: 0, minFreeFiles: 0 });
    try {
      await second.start();
      const finalFile = directory === 'processing' ? pending : storedFile;
      assert.deepEqual(await fsp.readFile(finalFile), original);
      assert.deepEqual(await fsp.readdir(second.openDir), []);
      assert.equal(second.snapshot().openFiles, 0);
      assert.equal(second.snapshot().openTransactions, 0);
      assert.equal(second.snapshot().queueBytes, original.length);
      assert.equal(second.snapshot().accepted, 0);
      assert.equal(second.snapshot().conflicts, 0);
      assert.equal(second.snapshot().pending, directory === 'failed' ? 0 : 1);
      assert.equal(second.snapshot().failedFiles, directory === 'failed' ? 1 : 0);
      assert.equal(second.snapshot().openCaptureHealthy, true);
    } finally { await second.close(); }
  });
});

test('restart rejects altered receipts, bodies and identities without changing either version', async t => {
  const cases = [
    ['stored body', async ({ pending }) => {
      const record = JSON.parse(await fsp.readFile(pending));
      record.requestBodyText = 'different body';
      record.requestBytesCaptured = Buffer.byteLength(record.requestBodyText);
      record.requestBodySha256 = cryptoHash(record.requestBodyText);
      await fsp.writeFile(pending, `${JSON.stringify(record)}\n`);
    }],
    ['trace identity', async ({ pending }) => {
      const record = JSON.parse(await fsp.readFile(pending));
      record.traceContext.turn_id = 'conflicting-turn';
      await fsp.writeFile(pending, `${JSON.stringify(record)}\n`);
    }],
    ['metadata digest', async ({ transaction }) => { await fsp.appendFile(transaction.files.metadata, ' '); }],
    ['spool digest', async ({ transaction }) => { await fsp.appendFile(transaction.files.request, 'changed'); }],
    ['invalid JSON', async ({ pending }) => {
      await fsp.writeFile(pending, '{"private":"synthetic-private-marker",');
    }],
    ['invalid open JSON', async ({ transaction }) => {
      await fsp.writeFile(transaction.files.metadata, '{"private":"synthetic-private-marker",');
    }],
    ['a second stored version', async ({ root, pending }) => {
      const record = JSON.parse(await fsp.readFile(pending));
      record.traceContext.session_id = 'conflicting-session';
      await fsp.writeFile(path.join(root, 'failed', path.basename(pending)), `${JSON.stringify(record)}\n`);
    }],
  ];
  for (const [name, corrupt] of cases) await t.test(name, async t => {
    const scenario = await interruptedFinalization(t);
    await corrupt(scenario);
    const files = [...Object.values(scenario.transaction.files), scenario.pending];
    const failed = path.join(scenario.root, 'failed', path.basename(scenario.pending));
    if (fs.existsSync(failed)) files.push(failed);
    const originals = await Promise.all(files.map(file => fsp.readFile(file)));
    const second = new DurableCaptureOutbox({ root: scenario.root, relayUrl: '',
      minFreeBytes: 0, minFreeFiles: 0 });
    try {
      await assert.rejects(second.start(), { code: 'CAPTURE_ID_CONFLICT' });
      assert.equal(second.started, false);
      assert.equal(second.snapshot().conflicts, 1);
      assert.equal(second.snapshot().openCaptureHealthy, false);
      assert.ok(!second.snapshot().lastError.includes('synthetic-private-marker'));
      for (const [index, file] of files.entries()) {
        assert.deepEqual(await fsp.readFile(file), originals[index]);
      }
    } finally { await second.close(); }
  });
});

test('invalid UTF-8 spools remain intact through failed finalization and restart', async () => {
  const root = temporaryRoot();
  const first = new DurableCaptureOutbox({ root, relayUrl: '', minFreeBytes: 0, minFreeFiles: 0 });
  let second;
  try {
    const transaction = await first.beginCapture({ captureId: 'cap-incomplete-utf8' });
    const bytes = Buffer.from([0xe4, 0xb8]);
    await transaction.appendRequest(bytes);
    const metadata = await fsp.readFile(transaction.files.metadata);
    await assert.rejects(transaction.finalize(), { code: 'CAPTURE_BODY_ENCODING' });
    assert.equal(first.snapshot().openCaptureHealthy, false);
    assert.equal(first.snapshot().openWriteFailures, 1);
    await first.close();
    second = new DurableCaptureOutbox({ root, relayUrl: '', minFreeBytes: 0, minFreeFiles: 0 });
    await assert.rejects(second.start(), { code: 'CAPTURE_BODY_ENCODING' });
    assert.deepEqual(await fsp.readFile(transaction.files.metadata), metadata);
    assert.deepEqual(await fsp.readFile(transaction.files.request), bytes);
    assert.deepEqual(await fsp.readdir(second.pendingDir), []);
  } finally {
    await first.close();
    if (second) await second.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a redacted stored body cannot be replaced after its original spool was cleaned', async t => {
  const scenario = await interruptedFinalization(t, { partial: true, sanitize: true });
  const stored = JSON.parse(await fsp.readFile(scenario.pending));
  stored.requestBodyText = 'altered after redaction';
  stored.requestBytesCaptured = Buffer.byteLength(stored.requestBodyText);
  stored.requestBodySha256 = cryptoHash(stored.requestBodyText);
  const altered = Buffer.from(`${JSON.stringify(stored)}\n`);
  await fsp.writeFile(scenario.pending, altered);
  const metadata = await fsp.readFile(scenario.transaction.files.metadata);
  const second = new DurableCaptureOutbox({ root: scenario.root, relayUrl: '',
    minFreeBytes: 0, minFreeFiles: 0 });
  try {
    await assert.rejects(second.start(), { code: 'CAPTURE_ID_CONFLICT' });
    assert.deepEqual(await fsp.readFile(scenario.pending), altered);
    assert.deepEqual(await fsp.readFile(scenario.transaction.files.metadata), metadata);
    await assert.rejects(fsp.stat(scenario.transaction.files.request), { code: 'ENOENT' });
  } finally { await second.close(); }
});

test('finalization preserves externally changed open metadata as a conflict', async () => {
  const root = temporaryRoot();
  const outbox = new DurableCaptureOutbox({ root, relayUrl: '', minFreeBytes: 0, minFreeFiles: 0 });
  try {
    const transaction = await outbox.beginCapture({ captureId: 'cap-changed-open-metadata' });
    const bytes = Buffer.from('原样证据');
    await transaction.appendRequest(bytes);
    await fsp.appendFile(transaction.files.metadata, ' ');
    const metadata = await fsp.readFile(transaction.files.metadata);
    await assert.rejects(transaction.finalize(), { code: 'CAPTURE_ID_CONFLICT' });
    assert.deepEqual(await fsp.readFile(transaction.files.metadata), metadata);
    assert.deepEqual(await fsp.readFile(transaction.files.request), bytes);
    assert.deepEqual(await fsp.readdir(outbox.pendingDir), []);
    assert.equal(outbox.snapshot().openCaptureHealthy, false);
    assert.equal(outbox.snapshot().conflicts, 1);
  } finally {
    await outbox.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('delivery waits for spool cleanup while unrelated Captures remain deliverable',
  { timeout: 10000 }, async t => {
    const root = temporaryRoot();
    const received = [];
    const relay = await fakeRelay((req, res) => {
      req.resume();
      req.once('end', () => {
        received.push(JSON.parse(req.rawTestBody).captureId);
        res.end(JSON.stringify(syntheticReceipt(req.rawTestBody)));
      });
    });
    const first = new DurableCaptureOutbox({ root, relayUrl: '', concurrency: 1,
      minFreeBytes: 0, minFreeFiles: 0 });
    let second;
    let releaseCleanup;
    const released = new Promise(resolve => { releaseCleanup = resolve; });
    let enteredCleanup;
    const entered = new Promise(resolve => { enteredCleanup = resolve; });
    let finalization;
    try {
      const transaction = await first.beginCapture({ captureId: 'cap-blocked-cleanup' });
      await transaction.appendRequest(Buffer.from('原样请求'));
      const originalRm = fsp.rm;
      t.mock.method(fsp, 'rm', async (file, ...args) => {
        if (file === transaction.files.request || file === transaction.files.response) {
          enteredCleanup();
          await released;
        }
        return originalRm(file, ...args);
      });
      finalization = transaction.finalize({ responseStatus: 200 });
      await entered;
      await first.enqueue(capture('cap-unrelated-ready'), { schedule: false });
      first.relayUrl = relay.url;
      await first.drain();
      // Visit the remaining candidate too, independent of filesystem order.
      await first.drain();
      assert.deepEqual(received, ['cap-unrelated-ready']);
      assert.ok(fs.existsSync(path.join(first.pendingDir, 'cap-blocked-cleanup.json')));
      await first.close();
      releaseCleanup();
      assert.equal((await finalization).durable, true);
      second = new DurableCaptureOutbox({ root, relayUrl: relay.url, minFreeBytes: 0, minFreeFiles: 0 });
      await second.start();
      assert.equal(await second.flush(1000), true);
      assert.deepEqual(received, ['cap-unrelated-ready', 'cap-blocked-cleanup']);
    } finally {
      releaseCleanup();
      if (finalization) await finalization.catch(() => {});
      await first.close();
      if (first.drainPromise) await first.drainPromise;
      if (second) {
        await second.close();
        if (second.drainPromise) await second.drainPromise;
      }
      await relay.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

test('restart converts an open streamed capture into explicit incomplete evidence', async () => {
  const root = temporaryRoot();
  const first = new DurableCaptureOutbox({ root, relayUrl: '', maxAttempts: 20 });
  const transaction = await first.beginCapture({
    captureId: 'cap-open-crash',
    sourceNamespace: 'gateway-test',
    method: 'POST',
    proxiedPath: '/v1/responses',
    startedAt: '2026-09-08T00:00:00Z',
  });
  await transaction.appendRequest(Buffer.from('{"input":"kept"}'));
  await transaction.appendResponse(Buffer.from('data: {"type":"response.created"}\n\n'));
  await first.close();

  const second = new DurableCaptureOutbox({ root, relayUrl: '', maxAttempts: 20 });
  try {
    await second.start();
    assert.deepEqual(fs.readdirSync(path.join(root, 'open')), []);
    const stored = JSON.parse(
      fs.readFileSync(path.join(root, 'pending', 'cap-open-crash.json'), 'utf8'),
    );
    assert.equal(stored.requestBodyText, '{"input":"kept"}');
    assert.equal(stored.responseBodyText, 'data: {"type":"response.created"}\n\n');
    assert.equal(stored.requestTruncated, true);
    assert.equal(stored.responseTruncated, true);
    assert.equal(stored.upstreamResponseCompleted, false);
    assert.equal(stored.clientResponseFinished, false);
    assert.equal(stored.captureErrorCode, 'CHIPTRACE_GATEWAY_CRASH');
    assert.equal(stored.captureTransaction.state, 'recovered_incomplete');
    assert.equal(stored.requestBodySha256, cryptoHash(stored.requestBodyText));
    assert.equal(stored.responseBodySha256, cryptoHash(stored.responseBodyText));
    assert.equal(second.snapshot().openTransactions, 0);
    assert.equal(second.snapshot().pending, 1);
  } finally {
    await second.close();
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
      res.end(JSON.stringify(syntheticReceipt(req.rawTestBody)));
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

test('streaming admission reserves capacity before concurrent writes', { timeout: 10000 }, async t => {
  for (const quota of ['files', 'bytes']) {
    for (const follower of ['open', 'enqueue']) await t.test(`${quota}: open then ${follower}`, async t => {
      const root = temporaryRoot();
      const outbox = new DurableCaptureOutbox({ root, relayUrl: '', maxBytes: 1024 * 1024,
        maxFiles: quota === 'files' ? 1 : 100, minFreeBytes: 0, minFreeFiles: 0 });
      let releaseWrite;
      const released = new Promise(resolve => { releaseWrite = resolve; });
      let enteredWrite;
      const entered = new Promise(resolve => { enteredWrite = resolve; });
      let first;
      try {
        await outbox.start();
        const originalLink = fsp.link;
        const target = path.join(root, 'open', 'cap-reserved-open.open.json');
        t.mock.method(fsp, 'link', async (source, destination, ...args) => {
          if (destination === target) {
            enteredWrite();
            await released;
          }
          return originalLink(source, destination, ...args);
        });
        const record = id => ({ captureId: id, sourceNamespace: 'synthetic-capacity',
          padding: quota === 'bytes' ? 'x'.repeat(600 * 1024) : '' });
        first = outbox.beginCapture(record('cap-reserved-open'));
        await entered;
        const [second] = await Promise.allSettled([follower === 'open'
          ? outbox.beginCapture(record('cap-reserved-following'))
          : outbox.enqueue(record('cap-reserved-following'), { schedule: false })]);
        assert.equal(second.status, 'rejected', 'the in-progress metadata write must occupy capacity');
        assert.equal(second.reason.code, 'OUTBOX_FULL');
        releaseWrite();
        const transaction = await first;
        const original = await fsp.readFile(transaction.files.metadata);
        assert.deepEqual(await fsp.readdir(outbox.openDir), ['cap-reserved-open.open.json']);
        assert.deepEqual(await fsp.readdir(outbox.pendingDir), []);
        assert.equal(outbox.snapshot().openTransactions, 1);
        assert.equal(outbox.snapshot().queueBytes, original.length);
        assert.equal(outbox.reservedBytes, 0);
        assert.equal(outbox.reservedFiles, 0);
      } finally {
        releaseWrite();
        if (first) await first.catch(() => {});
        await outbox.close();
        fs.rmSync(root, { recursive: true, force: true });
      }
    });
  }
});

test('concurrent stream appends keep the byte cap and recover the accepted prefix',
  { timeout: 10000 }, async t => {
    const root = temporaryRoot();
    const outbox = new DurableCaptureOutbox({ root, relayUrl: '', maxBytes: 1024 * 1024,
      minFreeBytes: 0, minFreeFiles: 0 });
    let recovered;
    let releaseWrite;
    const released = new Promise(resolve => { releaseWrite = resolve; });
    let enteredWrite;
    const entered = new Promise(resolve => { enteredWrite = resolve; });
    let firstWrite;
    try {
      const first = await outbox.beginCapture({ captureId: 'cap-capacity-first' });
      const second = await outbox.beginCapture({ captureId: 'cap-capacity-second' });
      const prefix = Buffer.from('保留的前缀 🧪');
      const payload = Buffer.from('原样'.repeat(100000));
      await second.appendRequest(prefix);
      const originalAppend = fsp.appendFile;
      t.mock.method(fsp, 'appendFile', async (file, ...args) => {
        if (file === first.files.request) {
          enteredWrite();
          await released;
        }
        return originalAppend(file, ...args);
      });
      firstWrite = first.appendRequest(payload);
      await entered;
      await second.appendRequest(payload);
      assert.equal(second.writeError?.code, 'OUTBOX_FULL');
      assert.equal(outbox.snapshot().openCaptureHealthy, false);
      assert.equal(outbox.snapshot().openWriteFailures, 1);
      releaseWrite();
      await firstWrite;
      assert.equal(first.writeError, null);
      assert.deepEqual(await fsp.readFile(first.files.request), payload);
      assert.deepEqual(await fsp.readFile(second.files.request), prefix);
      assert.ok(outbox.snapshot().queueBytes <= outbox.maxBytes);
      assert.equal(outbox.reservedBytes, 0);
      assert.equal(outbox.reservedFiles, 0);
      await assert.rejects(second.finalize({ responseStatus: 200 }), { code: 'OUTBOX_FULL' });
      await outbox.close();

      recovered = new DurableCaptureOutbox({ root, relayUrl: '', maxBytes: 1024 * 1024,
        minFreeBytes: 0, minFreeFiles: 0 });
      await recovered.start();
      assert.equal(recovered.snapshot().openTransactions, 0);
      assert.equal(recovered.snapshot().pending, 2);
      assert.equal(recovered.snapshot().openWriteFailures, 0);
      for (const [id, bytes] of [['cap-capacity-first', payload], ['cap-capacity-second', prefix]]) {
        const stored = JSON.parse(await fsp.readFile(path.join(root, 'pending', `${id}.json`)));
        assert.equal(stored.requestBodyText, bytes.toString('utf8'));
        assert.equal(stored.requestBytesCaptured, bytes.length);
        assert.equal(stored.requestBodySha256, cryptoHash(bytes));
        assert.equal(stored.captureTransaction.state, 'recovered_incomplete');
        assert.equal(stored.requestTruncated, true);
        assert.equal(stored.upstreamResponseCompleted, false);
        assert.equal(stored.clientResponseFinished, false);
      }
    } finally {
      releaseWrite();
      if (firstWrite) await firstWrite;
      await outbox.close();
      if (recovered) await recovered.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

test('stream writes respect file and filesystem cutoffs while preserving earlier bytes', async t => {
  const cases = [
    ['file cap', outbox => { outbox.maxFiles = 2; }, 'OUTBOX_FULL'],
    ['free space', outbox => { outbox.minFreeBytes = Number.MAX_SAFE_INTEGER; }, 'OUTBOX_DISK_PRESSURE'],
    ['inodes', outbox => { outbox.minFreeFiles = Number.MAX_SAFE_INTEGER; }, 'OUTBOX_INODE_PRESSURE'],
  ];
  for (const [name, applyPressure, code] of cases) await t.test(name, async () => {
    const root = temporaryRoot();
    const outbox = new DurableCaptureOutbox({ root, relayUrl: '', minFreeBytes: 0, minFreeFiles: 0 });
    try {
      const transaction = await outbox.beginCapture({ captureId: 'cap-stream-pressure' });
      const prefix = Buffer.from('已收集的请求 🧪');
      await transaction.appendRequest(prefix);
      const metadata = await fsp.readFile(transaction.files.metadata);
      // Raising the configured watermarks safely exercises pressure without
      // filling the host disk or allocating millions of real inodes.
      applyPressure(outbox);
      await transaction.appendResponse(Buffer.from('must not enter the spool'));
      assert.equal(transaction.writeError?.code, code);
      assert.equal(outbox.snapshot().openWriteFailures, 1);
      assert.equal(outbox.snapshot().openCaptureHealthy, false);
      await assert.rejects(transaction.finalize({ responseStatus: 200 }), { code });
      assert.deepEqual(await fsp.readFile(transaction.files.metadata), metadata);
      assert.deepEqual(await fsp.readFile(transaction.files.request), prefix);
      await assert.rejects(fsp.stat(transaction.files.response), { code: 'ENOENT' });
      assert.equal(outbox.snapshot().pending, 0);
      assert.equal(outbox.reservedBytes, 0);
      assert.equal(outbox.reservedFiles, 0);
    } finally {
      await outbox.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

test('failed stream writes release capacity for other Captures', async t => {
  await t.test('metadata publication failure', async t => {
    const root = temporaryRoot();
    const outbox = new DurableCaptureOutbox({ root, relayUrl: '', maxFiles: 1,
      minFreeBytes: 0, minFreeFiles: 0 });
    try {
      await outbox.start();
      const originalLink = fsp.link;
      let injectFailure = true;
      t.mock.method(fsp, 'link', async (...args) => {
        if (injectFailure && args[1] === path.join(root, 'open', 'cap-metadata-eio.open.json')) {
          injectFailure = false;
          throw Object.assign(new Error('synthetic metadata I/O failure'), { code: 'EIO' });
        }
        return originalLink(...args);
      });
      await assert.rejects(outbox.beginCapture({ captureId: 'cap-metadata-eio' }), { code: 'EIO' });
      assert.equal(outbox.reservedBytes, 0);
      assert.equal(outbox.reservedFiles, 0);
      await outbox.beginCapture({ captureId: 'cap-metadata-after-eio' });
      assert.deepEqual(await fsp.readdir(outbox.openDir), ['cap-metadata-after-eio.open.json']);
      assert.equal(outbox.snapshot().openTransactions, 1);
    } finally {
      await outbox.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
  await t.test('spool append failure', async t => {
    const root = temporaryRoot();
    const outbox = new DurableCaptureOutbox({ root, relayUrl: '', maxFiles: 3, maxBytes: 1024 * 1024,
      minFreeBytes: 0, minFreeFiles: 0 });
    try {
      const first = await outbox.beginCapture({ captureId: 'cap-append-eio' });
      const second = await outbox.beginCapture({ captureId: 'cap-append-after-eio' });
      const originalAppend = fsp.appendFile;
      t.mock.method(fsp, 'appendFile', async (file, ...args) => {
        if (file === first.files.request) {
          throw Object.assign(new Error('synthetic spool I/O failure'), { code: 'EIO' });
        }
        return originalAppend(file, ...args);
      });
      const payload = Buffer.from('x'.repeat(600 * 1024));
      await first.appendRequest(payload);
      assert.equal(first.writeError?.code, 'EIO');
      assert.equal(outbox.reservedBytes, 0);
      assert.equal(outbox.reservedFiles, 0);
      await second.appendRequest(payload);
      assert.equal(second.writeError, null);
      assert.deepEqual(await fsp.readFile(second.files.request), payload);
      assert.equal(outbox.snapshot().openWriteFailures, 1);
      assert.equal(outbox.snapshot().openCaptureHealthy, false);
    } finally {
      await outbox.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

test('stream finalization needs physical headroom while the open spools still exist', async t => {
  for (const quota of ['bytes', 'inodes']) await t.test(quota, async t => {
    const root = temporaryRoot();
    const outbox = new DurableCaptureOutbox({ root, relayUrl: '', minFreeBytes: 0, minFreeFiles: 0 });
    try {
      const transaction = await outbox.beginCapture({ captureId: 'cap-finalize-headroom' });
      const request = Buffer.from('x'.repeat(16 * 1024));
      await transaction.appendRequest(request);
      const original = await fsp.readFile(transaction.files.metadata);
      // Freeze the actual cached observation while configuring a waterline
      // that permits logical replacement but cannot fit the new physical file.
      t.mock.method(outbox, 'refreshFilesystemStats', async () => {});
      if (quota === 'bytes') outbox.minFreeBytes = outbox.metrics.filesystemFreeBytes - 1024;
      else outbox.minFreeFiles = outbox.metrics.filesystemFreeFiles;
      const code = quota === 'bytes' ? 'OUTBOX_DISK_PRESSURE' : 'OUTBOX_INODE_PRESSURE';
      await assert.rejects(transaction.finalize({ responseStatus: 200 }), { code });
      assert.equal(outbox.snapshot().openWriteFailures, 1);
      assert.equal(outbox.snapshot().openCaptureHealthy, false);
      assert.deepEqual(await fsp.readFile(transaction.files.metadata), original);
      assert.deepEqual(await fsp.readFile(transaction.files.request), request);
      assert.deepEqual(await fsp.readdir(outbox.pendingDir), []);
      assert.equal(outbox.reservedBytes, 0);
      assert.equal(outbox.reservedFiles, 0);
    } finally {
      await outbox.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

test('restart recovery releases each converted open Capture from the file quota', async () => {
  const root = temporaryRoot();
  const options = { root, relayUrl: '', maxFiles: 2, minFreeBytes: 0, minFreeFiles: 0 };
  const first = new DurableCaptureOutbox(options);
  let second;
  try {
    await first.beginCapture({ captureId: 'cap-recovery-capacity-a' });
    await first.beginCapture({ captureId: 'cap-recovery-capacity-b' });
    await first.close();
    second = new DurableCaptureOutbox(options);
    await second.start();
    assert.deepEqual(await fsp.readdir(second.openDir), []);
    assert.equal(second.snapshot().openFiles, 0);
    assert.equal(second.snapshot().openTransactions, 0);
    assert.equal(second.snapshot().pending, 2);
    let bytes = 0;
    for (const name of await fsp.readdir(second.pendingDir)) {
      const stored = await fsp.readFile(path.join(second.pendingDir, name));
      bytes += stored.length;
      const record = JSON.parse(stored);
      assert.equal(record.captureTransaction.state, 'recovered_incomplete');
      assert.equal(record.upstreamResponseCompleted, false);
      assert.equal(record.clientResponseFinished, false);
    }
    assert.equal(second.snapshot().queueBytes, bytes);
    await assert.rejects(second.beginCapture({ captureId: 'cap-recovery-capacity-full' }),
      { code: 'OUTBOX_FULL' });
  } finally {
    await first.close();
    if (second) await second.close();
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
      res.end(JSON.stringify(syntheticReceipt(req.rawTestBody)));
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
