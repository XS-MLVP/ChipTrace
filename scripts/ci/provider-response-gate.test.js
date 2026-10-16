'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');
const {
  runProviderProbe,
  verifyProviderResponse,
} = require('./provider-response-gate');

test('provider response gate accepts a bounded JSON Responses result', async t => {
  let request;
  const server = http.createServer((req, res) => {
    request = req;
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      assert.equal(req.method, 'POST');
      assert.match(req.headers.authorization, /^Bearer test-provider-key$/);
      assert.match(req.headers['session-id'], /^[0-9a-f-]{36}$/);
      assert.equal(req.headers['thread-id'], req.headers['session-id']);
      const metadata = JSON.parse(req.headers['x-codex-turn-metadata']);
      assert.equal(metadata.session_id, req.headers['session-id']);
      assert.equal(metadata.thread_id, req.headers['session-id']);
      assert.match(metadata.turn_id, /^[0-9a-f-]{36}$/);
      const value = JSON.parse(body);
      assert.equal(value.model, 'test-model');
      assert.equal(value.stream, false);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 'resp_test', output: [] }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const result = await runProviderProbe({
    url: `http://127.0.0.1:${server.address().port}/responses`,
    apiKey: 'test-provider-key', model: 'test-model', timeoutMs: 5000,
  });
  assert.equal(result.ok, true);
  assert.equal(result.response_status, 200);
  assert.equal(result.model, 'test-model');
  assert.ok(request);
});

test('provider response gate reports upstream refusal without exposing response text', () => {
  assert.throws(
    () => verifyProviderResponse({
      status: 403,
      contentType: 'application/json',
      body: JSON.stringify({ code: 'INSUFFICIENT_BALANCE', message: 'private provider detail' }),
    }),
    error => error.message === 'provider response gate: Responses request returned HTTP 403 (INSUFFICIENT_BALANCE)'
      && !error.message.includes('private provider detail'),
  );
});

test('provider response gate rejects empty and malformed successful responses', () => {
  for (const value of [
    { status: 200, contentType: 'application/json', body: '' },
    { status: 200, contentType: 'application/json', body: '{}' },
    { status: 200, contentType: 'application/json', body: '{' },
  ]) {
    assert.throws(() => verifyProviderResponse(value), /provider response gate:/);
  }
});

test('provider response gate accepts a non-empty streaming event', () => {
  const result = verifyProviderResponse({
    status: 200,
    contentType: 'text/event-stream',
    body: 'data: {"type":"response.created"}\n\ndata: [DONE]\n',
  });
  assert.equal(result.status, 200);
});
