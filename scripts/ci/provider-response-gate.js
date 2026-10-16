'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MODEL = 'gpt-5.6-sol';
const MAX_RESPONSE_BYTES = 256 * 1024;

function fail(message) {
  throw new Error(`provider response gate: ${message}`);
}

function nonEmptyString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') fail(`${label} must be a non-empty string`);
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) fail(`${label} must be a positive integer`);
  return value;
}

function safeErrorCode(body) {
  if (typeof body !== 'string' || body.length === 0) return null;
  try {
    const parsed = JSON.parse(body);
    const value = parsed?.error?.code ?? parsed?.code;
    return typeof value === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(value) ? value : null;
  } catch {
    return null;
  }
}

function verifyProviderResponse({ status, contentType = '', body = '' }) {
  positiveInteger(status, 'response status');
  if (status < 200 || status >= 300) {
    const code = safeErrorCode(body);
    fail(`Responses request returned HTTP ${status}${code ? ` (${code})` : ''}`);
  }
  if (typeof body !== 'string' || body.length === 0) fail('Responses request returned an empty body');
  const type = String(contentType).toLowerCase();
  if (type.includes('text/event-stream')) {
    const events = body.split(/\r?\n/).filter(line => line.startsWith('data:') && line.slice(5).trim() !== '[DONE]');
    if (events.length === 0) fail('streaming Responses request returned no data event');
    if (events.some(line => /"error"\s*:/.test(line))) fail('streaming Responses request returned an error event');
  } else {
    let parsed;
    try { parsed = JSON.parse(body); } catch { fail('Responses request returned invalid JSON'); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      fail('Responses request returned a non-object JSON value');
    }
    if (parsed.error) fail('Responses request returned an error object');
    if (typeof parsed.id !== 'string' || parsed.id.trim() === '') {
      fail('Responses request did not return a response id');
    }
  }
  return { status, content_type: String(contentType || ''), response_bytes: Buffer.byteLength(body) };
}

function traceparent() {
  return `00-${crypto.randomBytes(16).toString('hex')}-${crypto.randomBytes(8).toString('hex')}-01`;
}

function requestContext() {
  const sessionId = crypto.randomUUID();
  const turnId = crypto.randomUUID();
  const metadata = {
    session_id: sessionId,
    thread_id: sessionId,
    turn_id: turnId,
    root_turn_id: turnId,
    agent_name: 'chiptrace-provider-readiness',
    request_kind: 'turn',
  };
  return { sessionId, turnId, metadata, metadataJson: JSON.stringify(metadata) };
}

function responseUrl(value) {
  const url = new URL(nonEmptyString(value, 'responses URL'));
  if (!['http:', 'https:'].includes(url.protocol)) fail('responses URL must use HTTP or HTTPS');
  return url;
}

async function readBoundedBody(response) {
  if (!response.body || typeof response.body.getReader !== 'function') {
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength > MAX_RESPONSE_BYTES) fail('Responses response exceeded the bounded probe limit');
    return Buffer.from(bytes).toString('utf8');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = Buffer.from(next.value);
      total += chunk.length;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        fail('Responses response exceeded the bounded probe limit');
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

async function runProviderProbe({
  url,
  apiKey,
  model = DEFAULT_MODEL,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  fetchImpl = fetch,
}) {
  nonEmptyString(apiKey, 'API key');
  nonEmptyString(model, 'model');
  positiveInteger(timeoutMs, 'timeout');
  if (timeoutMs > 120000) fail('timeout must not exceed 120000ms');
  const endpoint = responseUrl(url);
  const context = requestContext();
  const body = JSON.stringify({
    model,
    input: 'Reply with exactly READY.',
    instructions: 'This is a bounded provider readiness probe. Reply with exactly READY.',
    stream: false,
    store: false,
    max_output_tokens: 16,
  });
  let response;
  try {
    response = await fetchImpl(endpoint, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${apiKey}`,
        'content-type': 'application/json',
        accept: 'application/json',
        'originator': 'codex_cli_rs',
        'session-id': context.sessionId,
        'thread-id': context.sessionId,
        'x-client-request-id': context.sessionId,
        'x-codex-turn-metadata': context.metadataJson,
        traceparent: traceparent(),
      },
      body,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    fail(`Responses request failed before a response was received: ${error.message}`);
  }
  const contentType = response.headers.get('content-type') || '';
  const responseBody = await readBoundedBody(response);
  const verified = verifyProviderResponse({ status: response.status, contentType, body: responseBody });
  return {
    schema_version: 'chiptrace.provider-response-gate.v1',
    ok: true,
    endpoint: `${endpoint.origin}${endpoint.pathname}`,
    model,
    session_id: context.sessionId,
    turn_id: context.turnId,
    response_status: verified.status,
    response_content_type: verified.content_type,
    response_bytes: verified.response_bytes,
  };
}

function writeReport(reportPath, value) {
  if (!reportPath) return;
  fs.writeFileSync(reportPath, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
}

function parseArgs(argv) {
  let url;
  let apiKeyEnv = 'CHIPTRACE_API_KEY';
  let model = DEFAULT_MODEL;
  let timeout = DEFAULT_TIMEOUT_MS;
  let report;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--responses-url' && value) { url = value; index += 1; }
    else if (flag === '--api-key-env' && value) { apiKeyEnv = value; index += 1; }
    else if (flag === '--model' && value) { model = value; index += 1; }
    else if (flag === '--timeout-ms' && value) { timeout = Number(value); index += 1; }
    else if (flag === '--report' && value) { report = value; index += 1; }
    else fail('usage: provider-response-gate.js --responses-url URL [--api-key-env ENV] [--model MODEL] [--timeout-ms N] [--report PATH]');
  }
  if (!url || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(apiKeyEnv)
    || !Number.isSafeInteger(timeout) || timeout < 100) {
    fail('usage: provider-response-gate.js --responses-url URL [--api-key-env ENV] [--model MODEL] [--timeout-ms N] [--report PATH]');
  }
  return { url, apiKeyEnv, model, timeout, report };
}

if (require.main === module) {
  let args;
  Promise.resolve().then(async () => {
    args = parseArgs(process.argv.slice(2));
    const apiKey = process.env[args.apiKeyEnv];
    const result = await runProviderProbe({
      url: args.url, apiKey, model: args.model, timeoutMs: args.timeout,
    });
    writeReport(args.report, result);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  }).catch(error => {
    const message = error.message || String(error);
    if (args?.report) {
      try {
        writeReport(args.report, {
          schema_version: 'chiptrace.provider-response-gate.v1',
          ok: false,
          observed_at: new Date().toISOString(),
          model: args.model,
          failure: message.slice(0, 300),
        });
      } catch {
        // Preserve the original provider failure when a report path is unavailable.
      }
    }
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  DEFAULT_MODEL,
  DEFAULT_TIMEOUT_MS,
  MAX_RESPONSE_BYTES,
  parseArgs,
  runProviderProbe,
  verifyProviderResponse,
};
