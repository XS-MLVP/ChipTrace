'use strict';

// Claude Code's /v1/messages requests can exceed 1 MiB, and the native Session
// id lives in `metadata.user_id` at the end of the JSON body. The gateway must
// still attribute those Wire captures; a head-only identity sample loses them.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

const SESSION_ID = '0f1e2d3c-4b5a-4968-8776-655443322110';
const TURN_ID = '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d';

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

function awaitListen(server, port) {
  return new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
}

function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: options.method || 'GET',
      headers: options.headers || {},
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.end(options.body || '');
  });
}

async function waitForHealth(url) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      if ((await request(url)).status === 200) return;
    } catch {
      // Listener may not be bound yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`server did not become healthy: ${url}`);
}

test('large Anthropic Wire keeps its native Session and Hook Turn identity', async (t) => {
  const upstreamPort = await reservePort();
  const relayPort = await reservePort();
  const shellPort = await reservePort();
  const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-identity-'));
  const outboxRoot = path.join(workRoot, 'outbox');
  const monitorRoot = path.join(workRoot, 'monitor');
  const stateRoot = path.join(monitorRoot, 'claude-turns');
  fs.mkdirSync(outboxRoot, { recursive: true });
  fs.mkdirSync(stateRoot, { recursive: true });
  fs.writeFileSync(
    path.join(stateRoot, `${SESSION_ID}.json`),
    JSON.stringify({ session_id: SESSION_ID, turn_id: TURN_ID, turn_index: 1 }),
    { mode: 0o600 },
  );

  const captures = [];
  const ingestToken = 'cloud-ingest-test-token-at-least-32-bytes';
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.once('end', () => {
      res.statusCode = 200;
      res.setHeader('connection', 'close');
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ id: 'msg-1', type: 'message', content: [] }));
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
  await awaitListen(upstream, upstreamPort);
  await awaitListen(relay, relayPort);

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
      FULL_TRACE_OUTBOX_MODULE: path.join(__dirname, 'durable-outbox.js'),
      CHIPTRACE_CLAUDE_TURN_STATE_DIR: stateRoot,
      CHIPTRACE_INGEST_TOKEN: ingestToken,
      WATCHDOG_ENABLED: 'false',
      TRACE_EXPORT_ENABLED: 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(async () => {
    child.kill('SIGTERM');
    await new Promise((resolve) => child.once('exit', resolve));
    await new Promise((resolve) => upstream.close(resolve));
    await new Promise((resolve) => relay.close(resolve));
    fs.rmSync(workRoot, { recursive: true, force: true });
  });

  await waitForHealth(`http://127.0.0.1:${shellPort}/health`);

  // 1.75 MiB of padding puts metadata.user_id well past the 1 MiB head sample.
  const padding = 'x'.repeat(1835008);
  const body = JSON.stringify({
    model: 'deepseek-flash',
    max_tokens: 32,
    stream: true,
    messages: [{ role: 'user', content: [{ type: 'text', text: padding }] }],
    metadata: {
      user_id: JSON.stringify({ device_id: 'device', account_uuid: '', session_id: SESSION_ID }),
    },
  });
  const response = await request(`http://127.0.0.1:${shellPort}/v1/messages`, {
    method: 'POST',
    headers: {
      authorization: 'Bearer cr_gateway_test_secret_1234567890',
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(body)),
    },
    body,
  });
  assert.equal(response.status, 200);

  for (let attempt = 0; attempt < 200 && captures.length === 0; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(captures.length, 1, 'one Wire capture expected');
  const capture = captures[0];
  assert.equal(capture.recordType, 'api_snapshot');
  assert.equal(capture.traceContext.session_id, SESSION_ID);
  assert.equal(capture.traceContext.conversation_id, SESSION_ID);
  assert.equal(capture.traceContext.session_identity_source, 'anthropic_metadata_user_id');
  assert.equal(capture.traceContext.turn_id, TURN_ID);
  assert.equal(capture.traceContext.root_turn_id, TURN_ID);
  assert.equal(capture.traceContext.turn_identity_source, 'claude_hook_prompt_boundary');
});
