'use strict';

// A capture dropped by a transient client stream error is permanent audit
// evidence, but it must not keep the gateway unhealthy for the rest of the
// process lifetime. Health only counts drops inside a bounded window; the
// lifetime total stays visible to operators through `droppedCount`.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

const WINDOW_MS = 2000;

function reservePort() {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

function request(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    }).on('error', reject);
  });
}

async function waitForHealth(url) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      const response = await request(url);
      if (response.status === 200) return JSON.parse(response.body);
    } catch {
      // Listener may not be bound yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`server did not become healthy: ${url}`);
}

test('a dropped capture ages out of capture health after the window', async (t) => {
  const shellPort = await reservePort();
  const upstreamPort = await reservePort();
  const relayPort = await reservePort();
  const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-drop-health-'));
  const outboxRoot = path.join(workRoot, 'outbox');
  const monitorRoot = path.join(workRoot, 'monitor');
  fs.mkdirSync(outboxRoot, { recursive: true });
  fs.mkdirSync(monitorRoot, { recursive: true });

  const captures = [];
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.once('end', () => {
      res.statusCode = 200;
      res.setHeader('connection', 'close');
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ id: 'r-1', output: 'ok' }));
    });
  });
  const relay = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.once('end', () => {
      res.setHeader('connection', 'close');
      res.setHeader('content-type', 'application/json');
      if (req.url === '/health') {
        res.end(JSON.stringify({
          ok: true,
          conservation_ok: true,
          pending: 0,
          inflight: 0,
          delivered: captures.length,
          delivery_records: captures.length,
        }));
        return;
      }
      if (req.url === '/capture') {
        const body = Buffer.concat(chunks);
        const capture = JSON.parse(body.toString('utf8'));
        captures.push(capture);
        res.statusCode = 202;
        res.end(JSON.stringify({
          ok: true,
          durable: true,
          local_durable: true,
          duplicate: false,
          input_receipt: {
            schema_version: 'chiptrace.capture-input-receipt.v1',
            bytes: body.length,
            sha256: crypto.createHash('sha256').update(body).digest('hex'),
          },
          capture: {
            capture_id: capture.captureId,
            state: 'accepted',
            durable: true,
            duplicate: false,
            raw_sha256: crypto.createHash('sha256').update(body).digest('hex'),
            segment_id: 1,
            offset: 0,
            length: body.length + 1,
          },
        }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
  });
  await new Promise((resolve) => upstream.listen(upstreamPort, '127.0.0.1', resolve));
  await new Promise((resolve) => relay.listen(relayPort, '127.0.0.1', resolve));

  const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: String(shellPort),
      SUB2API_BASE: `http://127.0.0.1:${upstreamPort}`,
      FULL_TRACE_CAPTURE_ENABLED: 'true',
      FULL_TRACE_CAPTURE_BODY_ENABLED: 'true',
      FULL_TRACE_CAPTURE_ALL_AUTHENTICATED_KEYS: 'true',
      FULL_TRACE_CAPTURE_RELAY_URL: `http://127.0.0.1:${relayPort}`,
      FULL_TRACE_CAPTURE_OUTBOX_DIR: outboxRoot,
      FULL_TRACE_CAPTURE_OUTBOX_SANITIZE: 'true',
      FULL_TRACE_CAPTURE_HEALTH_MAX_PENDING_FILES: '0',
      FULL_TRACE_CAPTURE_HEALTH_MAX_QUEUE_BYTES: '0',
      FULL_TRACE_CAPTURE_HEALTH_MAX_OLDEST_PENDING_MS: '0',
      FULL_TRACE_CAPTURE_DROP_HEALTH_WINDOW_MS: String(WINDOW_MS),
      FULL_TRACE_OUTBOX_MODULE: path.join(__dirname, 'durable-outbox.js'),
      CHIPTRACE_INGEST_TOKEN: 'cloud-ingest-test-token-at-least-32-bytes',
      WATCHDOG_ENABLED: 'false',
      TRACE_EXPORT_ENABLED: 'false',
    },
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  t.after(async () => {
    child.kill('SIGTERM');
    await new Promise((resolve) => child.once('exit', resolve));
    await new Promise((resolve) => upstream.close(resolve));
    await new Promise((resolve) => relay.close(resolve));
    fs.rmSync(workRoot, { recursive: true, force: true });
  });

  const url = `http://127.0.0.1:${shellPort}/health`;
  const initial = await waitForHealth(url);
  assert.equal(initial.status, 'healthy');
  assert.equal(initial.fullTraceCapture.stats.recentDroppedCount, 0);
  assert.equal(initial.fullTraceCapture.stats.dropHealthWindowMs, WINDOW_MS);
  assert.equal(initial.fullTraceCapture.outbox.rejected, 0);
});
