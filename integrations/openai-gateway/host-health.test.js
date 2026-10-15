'use strict';

// Deployment smoke against the actual host gateway, not a mock health handler.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return server.address().port;
}

async function verifyHostHealth(mode) {
  const script = process.env.CHIPTRACE_GATEWAY_SCRIPT;
  assert.ok(script && fs.statSync(script).isFile(), 'set CHIPTRACE_GATEWAY_SCRIPT to the real gateway server.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-host-health-'));
  let stream;
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      stream = res;
      res.writeHead(200, { 'content-type': 'text/event-stream', connection: 'close' });
      res.write('data: {"type":"response.created"}\n\n');
    });
  });
  const relay = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
      res.end(JSON.stringify({ ok: true, durable: true, conservation_ok: true,
        pending: 0, inflight: 0, delivered: 0, delivery_records: 0 }));
    });
  });
  const upstreamPort = await listen(upstream);
  const relayPort = await listen(relay);
  const reservation = http.createServer();
  const port = await listen(reservation);
  await new Promise(resolve => reservation.close(resolve));
  const child = spawn(process.execPath, [script], {
    cwd: path.dirname(script), stdio: ['ignore', 'ignore', 'pipe'],
    env: { ...process.env, PORT: String(port), SUB2API_BASE: `http://127.0.0.1:${upstreamPort}`,
      FULL_TRACE_CAPTURE_ENABLED: 'true', FULL_TRACE_CAPTURE_BODY_ENABLED: 'true',
      FULL_TRACE_CAPTURE_ALL_AUTHENTICATED_KEYS: 'true',
      FULL_TRACE_CAPTURE_HEALTH_MAX_OPEN_MS: mode === 'stale' ? '1000' : '60000',
      FULL_TRACE_CAPTURE_OUTBOX_MAX_FILES: mode === 'capacity' ? '1' : '100000',
      FULL_TRACE_CAPTURE_RELAY_URL: `http://127.0.0.1:${relayPort}`, FULL_TRACE_CAPTURE_OUTBOX_DIR: root,
      FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_BYTES: '0', FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_FILES: '0',
      FULL_TRACE_CAPTURE_SHUTDOWN_GRACE_MS: '100', WATCHDOG_ENABLED: 'false', TRACE_EXPORT_ENABLED: 'false',
      WATCHDOG_STATE_DIR: path.join(root, 'monitor'), CHIPTRACE_INGEST_TOKEN: 'synthetic-ingest-token-at-least-32-bytes',
      FULL_TRACE_OUTBOX_MODULE: path.join(__dirname, 'durable-outbox.js') },
  });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr = `${stderr}${chunk}`.slice(-4096); });
  let request;
  const health = async () => (await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1000) })).json();
  try {
    let initial;
    for (let i = 0; i < 100; i++) {
      try { initial = await health(); break; } catch { await new Promise(resolve => setTimeout(resolve, 10)); }
    }
    assert.equal(initial?.status, 'healthy', stderr);
    request = http.request(`http://127.0.0.1:${port}/responses`, {
      method: 'POST', headers: { authorization: 'Bearer cr_synthetic_host_health_123456789012', 'content-type': 'application/json' },
    }, res => res.resume());
    request.on('error', () => {});
    request.end('{"model":"gpt-5.6","input":"synthetic health probe"}');
    let active;
    for (let i = 0; i < 100; i++) {
      active = await health();
      if (active.fullTraceCapture.outbox.openTransactions === 1
        && (mode === 'stale' || active.fullTraceCapture.outbox.openWriteFailures === 1)) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(active.fullTraceCapture.outbox.openTransactions, 1, stderr);
    if (mode === 'stale') await new Promise(resolve => setTimeout(resolve, 1100));
    const unhealthy = await health();
    assert.equal(unhealthy.fullTraceCapture.outbox.staleOpenTransactions, mode === 'stale' ? 1 : 0);
    assert.equal(unhealthy.fullTraceCapture.outbox.openWriteFailures, mode === 'capacity' ? 1 : 0);
    assert.equal(unhealthy.fullTraceCapture.outbox.openCaptureHealthy, false);
    assert.equal(unhealthy.fullTraceCapture.currentDeliveryHealthy, false);
    assert.equal(unhealthy.status, 'degraded');
  } finally {
    stream?.end();
    request?.destroy();
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise(resolve => child.once('exit', resolve));
      child.kill('SIGTERM');
      const timer = setTimeout(() => child.kill('SIGKILL'), 2000);
      await exited;
      clearTimeout(timer);
    }
    upstream.closeAllConnections();
    relay.closeAllConnections();
    await Promise.all([new Promise(resolve => upstream.close(resolve)), new Promise(resolve => relay.close(resolve))]);
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('host gateway rejects healthy delivery while a streamed Capture is stale',
  () => verifyHostHealth('stale'));
test('host gateway rejects healthy delivery immediately after a streaming capacity failure',
  () => verifyHostHealth('capacity'));
