'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { DurableCaptureOutbox } = require('./durable-outbox');

const binary = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/debug/chiptrace');
const token = 'synthetic-wire-receipt-credential-at-least-32-bytes';
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function reservePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function start(args) {
  const child = spawn(binary, args, { env: { ...process.env, CHIPTRACE_INGEST_TOKEN: token,
    TOKIO_WORKER_THREADS: '2', RAYON_NUM_THREADS: '2' }, stdio: ['ignore', 'ignore', 'pipe'] });
  const handle = { child, stderr: '', ended: false };
  child.stderr.on('data', chunk => { handle.stderr = `${handle.stderr}${chunk}`.slice(-4096); });
  handle.closed = new Promise(resolve => {
    child.once('error', error => { handle.ended = true; handle.stderr = error.message; resolve({ error }); });
    child.once('close', (code, signal) => { handle.ended = true; resolve({ code, signal }); });
  });
  return handle;
}

async function stop(handle) {
  if (handle.ended) return handle.closed;
  handle.child.kill('SIGINT');
  const timer = setTimeout(() => handle.child.kill('SIGKILL'), 5000);
  try { return await handle.closed; } finally { clearTimeout(timer); }
}

async function health(url, handle, predicate = () => true) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline && !handle.ended) {
    try {
      const response = await fetch(`${url}/health`, { signal: AbortSignal.timeout(500) });
      if (response.ok) {
        const value = await response.json();
        if (predicate(value)) return value;
      }
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.fail(`isolated receipt service did not reach the expected state: ${handle.stderr}`);
}

async function sealedRecords(root) {
  const records = new Map();
  const segments = path.join(root, 'segments');
  for (const name of await fs.readdir(segments)) {
    if (!name.endsWith('.ndjson') || name.endsWith('.open.ndjson')) continue;
    for (const line of (await fs.readFile(path.join(segments, name), 'utf8')).split('\n').filter(Boolean)) {
      const record = JSON.parse(line);
      assert.equal(records.has(record.captureId), false);
      records.set(record.captureId, { record, line, sha256: digest(Buffer.from(line, 'utf8')) });
    }
  }
  return records;
}

test('gateway requires a real Relay byte receipt before removal and Collector preserves the exact WAL',
  { timeout: 30000 }, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-wire-receipt-'));
    const outboxes = [];
    let collector;
    let relay;
    let proxy;
    t.after(async () => {
      for (const outbox of outboxes) {
        await outbox.close();
        if (outbox.drainPromise) await outbox.drainPromise;
      }
      if (proxy) {
        proxy.closeAllConnections();
        await new Promise(resolve => proxy.close(resolve));
      }
      if (relay) await stop(relay);
      if (collector) await stop(collector);
      await fs.rm(root, { recursive: true, force: true });
    });
    const collectorPort = await reservePort();
    const collectorUrl = `http://127.0.0.1:${collectorPort}`;
    const collectorArgs = ['collector', '--host', '127.0.0.1', '--port', String(collectorPort),
      '--root', path.join(root, 'collector'), '--state-root', path.join(root, 'collector-state')];
    collector = start(collectorArgs);
    await health(collectorUrl, collector);
    const relayPort = await reservePort();
    const relayUrl = `http://127.0.0.1:${relayPort}`;
    const relayArgs = ['relay', '--host', '127.0.0.1', '--port', String(relayPort),
      '--root', path.join(root, 'relay'), '--state-root', path.join(root, 'relay-state'),
      '--delivery-state-root', path.join(root, 'delivery'), '--collector-url', collectorUrl];
    relay = start(relayArgs);
    await health(relayUrl, relay);

    let loseReceipt = true;
    let proxyError;
    const inputs = new Map();
    const receipts = new Map();
    proxy = http.createServer((req, res) => {
      (async () => {
        const chunks = [];
        for await (const bytes of req) chunks.push(bytes);
        const bytes = Buffer.concat(chunks);
        const id = JSON.parse(bytes.toString('utf8')).captureId;
        const previous = inputs.get(id);
        if (previous) assert.deepEqual(bytes, previous, 'every retry must keep the exact sent bytes');
        else inputs.set(id, bytes);
        const response = await fetch(`${relayUrl}/capture`, { method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: bytes, signal: AbortSignal.timeout(5000) });
        const receipt = await response.json();
        assert.equal(response.ok, true);
        assert.deepEqual(receipt.input_receipt, { schema_version: 'chiptrace.capture-input-receipt.v1',
          bytes: bytes.length, sha256: digest(bytes) });
        receipts.set(id, receipt);
        res.writeHead(response.status, { 'content-type': 'application/json', connection: 'close' });
        // The real Relay has committed; losing its receipt must retain the
        // gateway copy until a later valid, idempotent acknowledgement.
        res.end(JSON.stringify(loseReceipt ? { ok: true, durable: true } : receipt));
      })().catch(error => {
        proxyError = error;
        res.writeHead(500, { connection: 'close' });
        res.end();
      });
    });
    await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
    const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
    const makeOutbox = () => {
      const outbox = new DurableCaptureOutbox({ root: path.join(root, 'gateway'), relayUrl: proxyUrl,
        bearerToken: token, maxAttempts: 1, retryBaseMs: 1, retryMaxMs: 1, retryJitterPercent: 0 });
      outboxes.push(outbox);
      return outbox;
    };
    const wire = id => ({ captureId: id, recordType: 'api_snapshot', sourceNamespace: 'synthetic-wire-receipt',
      traceContext: { session_id: 'synthetic-wire-session', turn_id: id }, responseStatus: 200,
      requestBodyText: JSON.stringify({ input: '中文 input 🧪' }),
      responseBodyText: id.endsWith('current-v2')
        ? 'event: response.completed\ndata: {"type":"response.completed","response":{"status":"completed","output":"原样保留 SSE"}}\n\n'
        : JSON.stringify({ output: '原样保留 response' }) });
    const first = makeOutbox();
    await first.enqueue(wire('cap-receipt-unversioned'), { schedule: false });
    const pending = path.join(root, 'gateway', 'pending', 'cap-receipt-unversioned.json');
    const original = await fs.readFile(pending);
    assert.equal(await first.flush(150), false);
    await first.close();
    if (first.drainPromise) await first.drainPromise;
    assert.ifError(proxyError);
    assert.deepEqual(await fs.readFile(pending), original);
    assert.equal(first.snapshot().durable, 0);
    assert.equal(first.snapshot().failedFiles, 0);
    assert.ok(receipts.has('cap-receipt-unversioned'));

    loseReceipt = false;
    const duplicateEvents = [];
    const second = makeOutbox();
    second.onDurable = value => duplicateEvents.push(value);
    await second.start();
    assert.equal(await second.flush(5000), true);
    assert.deepEqual(duplicateEvents, [{ captureId: 'cap-receipt-unversioned', duplicate: true }]);
    await second.enqueue({ ...wire('cap-receipt-current-v2'), version: 'chiptrace.capture.v2' });
    assert.equal(await second.flush(5000), true);
    assert.equal(second.snapshot().durable, 2);
    assert.equal(second.snapshot().activeQueueBytes, 0);
    await assert.rejects(fs.stat(pending), { code: 'ENOENT' });
    assert.ifError(proxyError);

    const delivered = await health(relayUrl, relay,
      h => h.delivered === 2 && h.pending === 0 && h.inflight === 0);
    assert.equal(delivered.conservation_ok, true);
    assert.equal(delivered.failed, 0);
    await health(collectorUrl, collector, h => h.collector.captures === 2);
    for (const url of [relayUrl, collectorUrl]) {
      const response = await fetch(`${url}/flush`, { method: 'POST',
        headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
      assert.equal(response.ok, true);
    }
    const relayRaw = await sealedRecords(path.join(root, 'relay'));
    const collectorRaw = await sealedRecords(path.join(root, 'collector'));
    assert.equal(collectorRaw.size, 2);
    assert.equal(relayRaw.size, 2);
    for (const [id, value] of collectorRaw) {
      assert.equal(value.line, relayRaw.get(id).line);
      assert.equal(value.sha256, receipts.get(id).capture.raw_sha256);
      assert.equal(Buffer.byteLength(value.line, 'utf8') + 1, receipts.get(id).capture.length);
      assert.equal(value.record.requestBody.kind, 'json');
      assert.equal(value.record.requestBody.raw, wire(id).requestBodyText);
      assert.equal(value.record.requestBytesCaptured, Buffer.byteLength(wire(id).requestBodyText, 'utf8'));
      assert.equal(value.record.requestBodySha256, digest(Buffer.from(wire(id).requestBodyText, 'utf8')));
      if (id.endsWith('current-v2')) {
        assert.equal(value.record.responseBody.kind, 'text');
        assert.equal(value.record.responseBody.value, wire(id).responseBodyText);
      } else {
        assert.equal(value.record.responseBody.kind, 'json');
        assert.equal(value.record.responseBody.raw, wire(id).responseBodyText);
      }
      assert.equal(value.record.responseBytesCaptured, Buffer.byteLength(wire(id).responseBodyText, 'utf8'));
      assert.equal(value.record.responseBodySha256, digest(Buffer.from(wire(id).responseBodyText, 'utf8')));
      assert.equal(value.record.traceContext.turn_id, id);
    }
    await second.close();
    if (second.drainPromise) await second.drainPromise;
    assert.equal((await stop(relay)).code, 0);
    assert.equal((await stop(collector)).code, 0);
    collector = start(collectorArgs);
    await health(collectorUrl, collector, h => h.collector.captures === 2);
    relay = start(relayArgs);
    await health(relayUrl, relay,
      h => h.delivered === 2 && h.pending === 0 && h.inflight === 0 && h.conservation_ok);
    assert.deepEqual(await sealedRecords(path.join(root, 'collector')), collectorRaw);
  });
