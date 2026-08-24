'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  CaptureConflictError,
  QueueFullError,
  ReliableCaptureSubmitter,
} = require('../integration/reliable_capture_submitter');

function response(status, payload = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    async json() { return payload; },
  };
}

test('retries retryable failures with byte-identical payload', async () => {
  const calls = [];
  const replies = [response(503), response(202, { ok: true, durable: true, duplicate: false })];
  const submitter = new ReliableCaptureSubmitter({
    url: 'http://collector',
    fetchImpl: async (_url, options) => {
      calls.push(options.body);
      return replies.shift();
    },
    baseDelayMs: 0,
    maxDelayMs: 0,
  });
  const result = await submitter.submit({ captureId: 'cap-retry', responseStatus: 503 });
  assert.equal(result.attempts, 2);
  assert.equal(calls.length, 2);
  assert.equal(calls[0], calls[1]);
  assert.deepEqual(submitter.snapshot(), {
    offered: 1,
    enqueued: 1,
    durable: 1,
    duplicates: 0,
    conflicts: 0,
    dropped: 0,
    retryAttempts: 1,
    queued: 0,
    inFlight: 0,
    retainedBytes: 0,
    conservationOk: true,
  });
});

test('treats durable duplicate as success', async () => {
  const submitter = new ReliableCaptureSubmitter({
    url: 'http://collector',
    fetchImpl: async () => response(202, { ok: true, durable: true, duplicate: true }),
  });
  const result = await submitter.submit({ captureId: 'cap-duplicate' });
  assert.equal(result.duplicate, true);
  assert.equal(submitter.snapshot().duplicates, 1);
  assert.equal(submitter.snapshot().conservationOk, true);
});

test('does not accept an ambiguous 2xx acknowledgement', async () => {
  const submitter = new ReliableCaptureSubmitter({
    url: 'http://collector',
    maxAttempts: 1,
    fetchImpl: async () => response(202, { ok: true }),
  });
  await assert.rejects(
    submitter.submit({ captureId: 'cap-ambiguous-ack' }),
    /HTTP 202/,
  );
  assert.equal(submitter.snapshot().dropped, 1);
  assert.equal(submitter.snapshot().conservationOk, true);
});

test('does not retry captureId conflicts', async () => {
  let calls = 0;
  const submitter = new ReliableCaptureSubmitter({
    url: 'http://collector',
    fetchImpl: async () => {
      calls += 1;
      return response(409, { detail: 'reused' });
    },
  });
  await assert.rejects(submitter.submit({ captureId: 'cap-conflict' }), CaptureConflictError);
  assert.equal(calls, 1);
  assert.equal(submitter.snapshot().conflicts, 1);
  assert.equal(submitter.snapshot().conservationOk, true);
});

test('enforces retained payload byte budget', async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const submitter = new ReliableCaptureSubmitter({
    url: 'http://collector',
    maxQueueBytes: 128,
    concurrency: 1,
    fetchImpl: async () => {
      await pending;
      return response(202, { ok: true, durable: true });
    },
  });
  const first = submitter.submit({ captureId: 'cap-held', body: 'x'.repeat(50) });
  await assert.rejects(
    submitter.submit({ captureId: 'cap-over-budget', body: 'x'.repeat(50) }),
    QueueFullError,
  );
  assert.equal(submitter.snapshot().conservationOk, true);
  release();
  await first;
  assert.equal(submitter.snapshot().conservationOk, true);
});

test('close rejects queued jobs while allowing the in-flight job to finish', async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const submitter = new ReliableCaptureSubmitter({
    url: 'http://collector',
    concurrency: 1,
    fetchImpl: async () => {
      await pending;
      return response(202, { ok: true, durable: true });
    },
  });
  const first = submitter.submit({ captureId: 'cap-in-flight' });
  const second = submitter.submit({ captureId: 'cap-queued' });
  submitter.close();
  await assert.rejects(second, QueueFullError);
  release();
  await first;
  assert.equal(submitter.snapshot().dropped, 1);
  assert.equal(submitter.snapshot().conservationOk, true);
});
