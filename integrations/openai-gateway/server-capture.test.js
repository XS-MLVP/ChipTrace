'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

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

function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const headers = { ...(options.headers || {}) };
    if (options.body !== undefined && headers['content-length'] === undefined) {
      headers['content-length'] = Buffer.byteLength(options.body);
    }
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: options.method || 'GET',
      headers,
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('aborted', () => reject(new Error(
        `response aborted before end: ${parsed.pathname}${parsed.search}`,
      )));
      response.on('error', (error) => reject(new Error(
        `response failed: ${parsed.pathname}${parsed.search}: ${error.message}`,
      )));
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.end(options.body || '');
  });
}

function abortAfterFirstChunk(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: options.method || 'GET',
      headers: options.headers || {},
    }, (response) => {
      response.once('data', () => {
        response.destroy();
        resolve(response.statusCode);
      });
    });
    req.on('error', reject);
    req.end(options.body || '');
  });
}

async function waitForHealth(url) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await request(url);
      if (response.status === 200) return;
    } catch {
      // The child may still be binding its listener.
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`server did not become healthy: ${url}`);
}

async function terminateChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  const graceful = await Promise.race([
    exited.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 2000)),
  ]);
  if (!graceful) {
    child.kill('SIGKILL');
    await exited;
  }
}

test('18084 proxy keeps observed task context and uses the durable outbox', async () => {
  const upstreamPort = await reservePort();
  const relayPort = await reservePort();
  const shellPort = await reservePort();
  const outboxRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-shell-capture-'));
  const monitorRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-shell-monitor-'));
  fs.mkdirSync(path.join(outboxRoot, 'failed'), { recursive: true });
  fs.writeFileSync(
    path.join(outboxRoot, 'failed', 'cap-historical.json'),
    `${JSON.stringify({ captureId: 'cap-historical', recordType: 'api_snapshot' })}\n`,
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(outboxRoot, 'failed', 'cap-historical.json.error.json'),
    `${JSON.stringify({ captureId: 'cap-historical', reason: 'http_400' })}\n`,
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(monitorRoot, 'gpt-watchdog-key.json'),
    `${JSON.stringify({ apiKey: 'cr_watchdog_secret_123456789012' })}\n`,
    { mode: 0o600 },
  );
  let captures = [];
  const ingestToken = 'cloud-ingest-test-token-at-least-32-bytes';
  const cloudRequests = [];
  const upstream = http.createServer((req, response) => {
    req.resume();
    req.once('end', () => {
      if (req.url === '/v1/models') {
        const valid = req.headers.authorization === 'Bearer cr_test_secret_123456789012';
        response.statusCode = valid ? 200 : 401;
        response.setHeader('connection', 'close');
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify(valid ? { data: [{ id: 'gpt-5.6-sol' }] } : {
          error: { message: 'invalid business credential' },
        }));
        return;
      }
      if (req.headers['x-test-complete-response'] === '1') {
        response.statusCode = 200;
        response.setHeader('connection', 'close');
        response.setHeader('content-type', 'text/event-stream');
        response.setHeader('content-length', Buffer.byteLength('event: response.created\ndata: {"type":"response.created","response":{"status":"in_progress"}}\n\nevent: response.completed\ndata: {"type":"response.completed","response":{"status":"completed","output":[]}}\n\n'));
        response.end('event: response.created\ndata: {"type":"response.created","response":{"status":"in_progress"}}\n\nevent: response.completed\ndata: {"type":"response.completed","response":{"status":"completed","output":[]}}\n\n');
        return;
      }
      response.statusCode = 200;
      response.setHeader('connection', 'close');
      if (req.headers['x-test-slow-response'] === '1') {
        response.setHeader('content-type', 'text/event-stream');
        response.write('data: {"type":"response.output_text.delta","delta":"first"}\n\n');
        setTimeout(() => response.end('data: [DONE]\n\n'), 50);
        return;
      }
      response.setHeader('content-type', 'application/json');
      response.setHeader('x-request-id', 'upstream-request-1');
      response.setHeader('x-client-request-id', 'gateway-request-1');
      response.end(JSON.stringify({ id: 'response-1', output: 'ok' }));
    });
  });
  const relay = http.createServer((req, response) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.once('end', () => {
      if (req.url === '/health') {
        response.setHeader('connection', 'close');
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({
          ok: true,
          conservation_ok: true,
          pending: 0,
          inflight: 0,
          delivered: captures.length,
          delivery_records: captures.length,
        }));
        return;
      }
      if (req.url === '/models' || req.url === '/v1/models') {
        assert.equal(req.headers.authorization, `Bearer ${ingestToken}`);
        response.statusCode = 200;
        response.setHeader('connection', 'close');
        response.setHeader('content-type', 'application/json');
        response.setHeader('etag', '"managed-models-test"');
        response.end(JSON.stringify({ models: [{ slug: 'gpt-5.6-sol', tool_mode: 'direct' }] }));
        return;
      }
      if (req.url === '/capture') {
        assert.equal(req.headers.authorization, `Bearer ${ingestToken}`);
        const body = Buffer.concat(chunks);
        const capture = JSON.parse(body.toString('utf8'));
        const duplicate = captures.some((item) => item.captureId === capture.captureId);
        captures.push(capture);
        response.statusCode = 202;
        response.setHeader('connection', 'close');
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({
          ok: true,
          durable: true,
          local_durable: true,
          duplicate,
          input_receipt: {
            schema_version: 'chiptrace.capture-input-receipt.v1',
            bytes: body.length,
            sha256: crypto.createHash('sha256').update(body).digest('hex'),
          },
          capture: {
            capture_id: capture.captureId,
            state: duplicate ? 'duplicate' : 'accepted',
            durable: true,
            duplicate,
            raw_sha256: crypto.createHash('sha256').update(body).digest('hex'),
            segment_id: 1,
            offset: 0,
            length: body.length + 1,
          },
        }));
        return;
      }
      if (req.url === '/otel/v1/logs' || req.url === '/otel/v1/traces' || req.url === '/hooks/codex') {
        const body = Buffer.concat(chunks).toString('utf8');
        cloudRequests.push({
          path: req.url,
          authorization: req.headers.authorization,
          body,
        });
        response.statusCode = body.includes('invalid-cloud-event') ? 400 : 202;
        response.setHeader('connection', 'close');
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify(body.includes('invalid-cloud-event')
          ? { ok: false, reason: 'cloud_ingest_quality_error' }
          : { ok: true, durable: true, duplicate: false }));
        return;
      }
      response.statusCode = 404;
      response.end();
    });
  });
  await new Promise((resolve) => upstream.listen(upstreamPort, '127.0.0.1', resolve));
  await new Promise((resolve) => relay.listen(relayPort, '127.0.0.1', resolve));
  let relayOpen = true;
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
      FULL_TRACE_CAPTURE_RETRY_BASE_MS: '1',
      FULL_TRACE_CAPTURE_RETRY_MAX_MS: '2',
      FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS: '50',
      FULL_TRACE_CAPTURE_OUTBOX_SANITIZE: 'false',
      // The gateway and its durable outbox live in the same directory, whether
      // the test runs from this repository or from the host relay_shell mount.
      FULL_TRACE_OUTBOX_MODULE: path.join(__dirname, 'durable-outbox.js'),
      FULL_TRACE_CAPTURE_HEALTH_MAX_PENDING_FILES: '0',
      FULL_TRACE_CAPTURE_HEALTH_MAX_QUEUE_BYTES: '0',
      FULL_TRACE_CAPTURE_HEALTH_MAX_OLDEST_PENDING_MS: '0',
      CHIPTRACE_INGEST_TOKEN: ingestToken,
      WATCHDOG_STATE_DIR: monitorRoot,
      WATCHDOG_ENABLED: 'false',
      TRACE_EXPORT_ENABLED: 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const childStderr = [];
  child.stderr.on('data', (chunk) => childStderr.push(chunk.toString('utf8')));
  let activeStep = 'startup';
  try {
    await waitForHealth(`http://127.0.0.1:${shellPort}/health`);
    activeStep = 'models';
    const unauthenticatedModels = await request(`http://127.0.0.1:${shellPort}/models`);
    assert.equal(unauthenticatedModels.status, 401);
    const rejectedModels = await request(`http://127.0.0.1:${shellPort}/models`, {
      headers: { authorization: 'Bearer cr_invalid_secret_123456789012' },
    });
    assert.equal(rejectedModels.status, 401);
    const managedModels = await request(`http://127.0.0.1:${shellPort}/models`, {
      headers: { authorization: 'Bearer cr_test_secret_123456789012' },
    });
    assert.equal(managedModels.status, 200);
    assert.deepEqual(JSON.parse(managedModels.body).models, [
      { slug: 'gpt-5.6-sol', tool_mode: 'direct' },
    ]);
    activeStep = 'normal response';
    const response = await request(`http://127.0.0.1:${shellPort}/v1/responses`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer cr_test_secret_123456789012',
        'session-id': 'session-1',
        'thread-id': 'thread-1',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
        'x-codex-turn-metadata': JSON.stringify({
          session_id: 'session-1',
          thread_id: 'thread-1',
          turn_id: 'turn-1',
          root_turn_id: 'turn-root',
          agent_name: '/root',
        }),
      },
      body: JSON.stringify({
        model: 'gpt-5.6',
        api_key: 'cr_test_secret_123456789012',
        messages: [{ role: 'user', content: 'hello' }],
      }),
    });
    assert.equal(response.status, 200);
    assert.match(response.body, /response-1/);
    for (let attempt = 0; attempt < 100 && captures.length === 0; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(captures.length, 1);
    const capture = captures[0];
    assert.equal(capture.traceContext.session_id, 'session-1');
    assert.equal(capture.traceContext.conversation_id, 'session-1');
    assert.equal(capture.traceContext.thread_id, 'thread-1');
    assert.equal(capture.traceContext.turn_id, 'turn-1');
    assert.equal(capture.traceContext.root_turn_id, 'turn-root');
    assert.equal(capture.traceContext.agent_path, '/root');
    assert.equal(capture.traceContext.traceparent, '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01');
    assert.deepEqual(capture.fieldEvidenceConflicts, []);
    assert.deepEqual(capture.traceContextErrors, []);
    assert.equal(capture.requestHeaders.authorization, undefined);
    const expectedRequestBody = JSON.stringify({
      model: 'gpt-5.6',
      api_key: 'cr_test_secret_123456789012',
      messages: [{ role: 'user', content: 'hello' }],
    });
    assert.equal(capture.requestBodyText, expectedRequestBody);
    assert.equal(capture.requestBytesCaptured, Buffer.byteLength(expectedRequestBody));
    assert.equal(
      capture.requestBodySha256,
      crypto.createHash('sha256').update(expectedRequestBody).digest('hex'),
    );
    assert.equal(capture.responseHeaders['x-request-id'], 'upstream-request-1');
    assert.equal(capture.responseHeaders['x-client-request-id'], 'gateway-request-1');
    assert.equal(capture.clientResponseFinished, true);
    assert.equal(capture.clientResponseClosedBeforeFinish, false);
    let health;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      health = JSON.parse((await request(`http://127.0.0.1:${shellPort}/health`)).body);
      if (health.fullTraceCapture.outbox.durable === 1
        && health.fullTraceCapture.outbox.pending === 0
        && health.fullTraceCapture.outbox.processing === 0) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(health.fullTraceCapture.outbox.accepted, 1);
    assert.equal(health.fullTraceCapture.outbox.pending, 0);
    assert.equal(health.fullTraceCapture.outbox.sanitize, false);
    assert.equal(health.fullTraceCapture.cloudIngestEndpointConfigured, true);
    assert.equal(health.status, 'healthy');
    assert.equal(health.fullTraceCapture.currentDeliveryHealthy, true);
    assert.equal(health.fullTraceCapture.historicalFailures.records, 1);
    assert.equal(health.fullTraceCapture.historicalFailures.markers, 1);
    assert.equal(health.fullTraceCapture.recentFailures.records, 0);

    const missingCloudAuth = await request(`http://127.0.0.1:${shellPort}/hooks/codex`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-ndjson' },
      body: '{"event":"missing-auth"}\n',
    });
    assert.equal(missingCloudAuth.status, 401);
    assert.equal(cloudRequests.length, 0);

    const hookBody = '{"hook_event_name":"SessionStart","session_id":"session-1"}';
    const hookAck = await request(`http://127.0.0.1:${shellPort}/hooks/codex`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${ingestToken}`,
      },
      body: hookBody,
    });
    assert.equal(hookAck.status, 202);
    assert.equal(JSON.parse(hookAck.body).durable, true);
    assert.deepEqual(cloudRequests[0], {
      path: '/hooks/codex',
      authorization: `Bearer ${ingestToken}`,
      body: hookBody,
    });

    const invalidCloud = await request(`http://127.0.0.1:${shellPort}/hooks/codex`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${ingestToken}`,
      },
      body: '{"event":"invalid-cloud-event"}',
    });
    assert.equal(invalidCloud.status, 400);
    assert.equal(JSON.parse(invalidCloud.body).reason, 'cloud_ingest_quality_error');
    assert.equal(cloudRequests.length, 2);

    const removedProducerRoute = await request(`http://127.0.0.1:${shellPort}/producer/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    assert.equal(removedProducerRoute.status, 404);

    const monitorResponse = await request(`http://127.0.0.1:${shellPort}/v1/responses`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer cr_watchdog_secret_123456789012',
      },
      body: JSON.stringify({ model: 'gpt-5.6', input: 'watchdog' }),
    });
    assert.equal(monitorResponse.status, 200);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(captures.length, 1);

    activeStep = 'completed response';
    const completedResponse = await request(`http://127.0.0.1:${shellPort}/responses`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer cr_test_secret_123456789012',
        'session-id': 'session-completed',
        'thread-id': 'session-completed',
        'x-test-complete-response': '1',
      },
      body: JSON.stringify({ model: 'gpt-5.6', input: 'complete normally' }),
    });
    assert.equal(completedResponse.status, 200);
    assert.match(completedResponse.body, /"type":"response.completed"/);
    for (let attempt = 0; attempt < 100 && captures.length < 2; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const completed = captures.find(
      (item) => item.traceContext?.session_id === 'session-completed',
    );
    assert.equal(completed.clientResponseFinished, true);
    assert.equal(completed.clientResponseClosedBeforeFinish, false);
    assert.equal(completed.responseProtocolTerminalObserved, true);
    assert.equal(completed.responseProtocolTerminalEvent, 'response.completed');
    assert.equal(completed.responseFramingDoneObserved, false);
    assert.equal(completed.upstreamResponseCompleted, true);

    activeStep = 'cancelled response';
    const cancelledStatus = await abortAfterFirstChunk(`http://127.0.0.1:${shellPort}/v1/responses`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer cr_test_secret_123456789012',
        'session-id': 'session-cancelled',
        'thread-id': 'session-cancelled',
        'x-codex-turn-metadata': JSON.stringify({
          session_id: 'session-cancelled',
          thread_id: 'session-cancelled',
          turn_id: 'turn-cancelled',
          root_turn_id: 'turn-cancelled',
        }),
        'x-test-slow-response': '1',
      },
      body: JSON.stringify({ model: 'gpt-5.6', input: 'cancel after first chunk' }),
    });
    assert.equal(cancelledStatus, 200);
    for (let attempt = 0; attempt < 100 && captures.length < 3; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(captures.length, 3);
    const cancelled = captures.find((item) => item.traceContext?.session_id === 'session-cancelled');
    assert.equal(cancelled.clientResponseClosedBeforeFinish, true);
    assert.equal(cancelled.clientResponseFinished, false);
    assert.equal(cancelled.clientRequestAborted, false);
    assert.equal(cancelled.upstreamResponseCompleted, true);
    assert.equal(typeof cancelled.responseBytesForwarded, 'number');
    assert.equal(typeof cancelled.responseBytesForwardedAtClientClose, 'number');
    assert.equal(
      cancelled.responseBytesForwardedAtClientClose <= cancelled.responseBytesForwarded,
      true,
    );
    assert.equal(cancelled.responseProtocolTerminalObservedAtClientClose, false);

    // Collector/Relay outages are fail-open for the business response. The
    // final Capture remains durable locally and is available for restart or
    // reconnect replay.
    await new Promise((resolve) => relay.close(resolve));
    relayOpen = false;
    const outageResponse = await request(`http://127.0.0.1:${shellPort}/v1/responses`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer cr_test_secret_123456789012',
        'session-id': 'session-2',
        'thread-id': 'session-2',
        'x-codex-turn-metadata': JSON.stringify({
          session_id: 'session-2',
          thread_id: 'session-2',
          turn_id: 'turn-2',
          root_turn_id: 'turn-2',
        }),
      },
      body: JSON.stringify({ model: 'gpt-5.6', input: 'relay is unavailable' }),
    });
    assert.equal(outageResponse.status, 200);
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const pendingFiles = fs.readdirSync(path.join(outboxRoot, 'pending')).length;
      const processingFiles = fs.readdirSync(path.join(outboxRoot, 'processing')).length;
      if (pendingFiles + processingFiles === 1) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(
      fs.readdirSync(path.join(outboxRoot, 'pending')).length
        + fs.readdirSync(path.join(outboxRoot, 'processing')).length,
      1,
    );
    const degraded = JSON.parse((await request(`http://127.0.0.1:${shellPort}/health`)).body);
    assert.equal(degraded.status, 'degraded');
    assert.equal(degraded.fullTraceCapture.backlogHealthy, false);
    assert.equal(degraded.fullTraceCapture.outbox.pending
      + degraded.fullTraceCapture.outbox.processing, 1);
    assert.ok(degraded.fullTraceCapture.outbox.activeQueueBytes > 0);
    assert.ok(degraded.fullTraceCapture.outbox.oldestPendingAt);
  } catch (error) {
    error.message = `${activeStep}: ${error.message}\nrelay stderr:\n${childStderr.join('')}`;
    throw error;
  } finally {
    await terminateChild(child);
    await new Promise((resolve) => upstream.close(resolve));
    if (relayOpen) await new Promise((resolve) => relay.close(resolve));
    fs.rmSync(outboxRoot, { recursive: true, force: true });
    fs.rmSync(monitorRoot, { recursive: true, force: true });
  }
});
