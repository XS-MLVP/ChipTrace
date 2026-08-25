'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  CaptureConflictError,
  DurableCaptureOutbox,
  OutboxFullError,
} = require('../integration/durable_capture_outbox');

function response(status, payload = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    async json() { return payload; },
  };
}

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trace-outbox-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('persists locally before remote delivery completes', async (t) => {
  const directory = temporaryDirectory(t);
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const outbox = new DurableCaptureOutbox({
    directory,
    url: 'http://collector',
    fetchImpl: async () => {
      await held;
      return response(202, { ok: true, durable: true });
    },
  });
  t.after(() => outbox.close());
  const result = await outbox.enqueue({ captureId: 'cap-local-first', value: 1 });
  assert.equal(result.localDurable, true);
  assert.equal(fs.readdirSync(path.join(directory, 'pending')).length, 1);
  assert.equal(outbox.snapshot().offerConservationOk, true);
  release();
  await outbox.waitForEmpty();
  assert.equal(outbox.snapshot().deliveryConservationOk, true);
});

test('recovers after restart and retries byte-identical payload', async (t) => {
  const directory = temporaryDirectory(t);
  const record = { captureId: 'cap-restart', body: 'payload' };
  const first = new DurableCaptureOutbox({
    directory,
    url: 'http://collector',
    autostart: false,
    fetchImpl: async () => response(503),
  });
  await first.enqueue(record);
  first.close();

  const delivered = [];
  const second = new DurableCaptureOutbox({
    directory,
    url: 'http://collector',
    fetchImpl: async (_url, options) => {
      delivered.push(Buffer.from(options.body).toString('utf8'));
      return response(202, { ok: true, durable: true });
    },
  });
  t.after(() => second.close());
  await second.waitForEmpty();
  assert.deepEqual(delivered, [JSON.stringify(record)]);
  assert.equal(second.snapshot().recovered, 1);
  assert.equal(second.snapshot().deliveryConservationOk, true);
});

test('retries transient errors without changing bytes', async (t) => {
  const directory = temporaryDirectory(t);
  const bodies = [];
  let attempt = 0;
  const outbox = new DurableCaptureOutbox({
    directory,
    url: 'http://collector',
    baseDelayMs: 0,
    maxDelayMs: 0,
    fetchImpl: async (_url, options) => {
      bodies.push(Buffer.from(options.body).toString('utf8'));
      attempt += 1;
      return attempt === 1
        ? response(503)
        : response(202, { ok: true, durable: true, duplicate: true });
    },
  });
  t.after(() => outbox.close());
  await outbox.enqueue({ captureId: 'cap-retry', responseStatus: 503 });
  await outbox.waitForEmpty();
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0], bodies[1]);
  assert.equal(outbox.snapshot().retryAttempts, 1);
  assert.equal(outbox.snapshot().remoteDuplicates, 1);
});

test('same captureId is locally idempotent and changed bytes conflict', async (t) => {
  const directory = temporaryDirectory(t);
  const outbox = new DurableCaptureOutbox({
    directory,
    url: 'http://collector',
    autostart: false,
    fetchImpl: async () => response(202, { ok: true, durable: true }),
  });
  t.after(() => outbox.close());
  const record = { captureId: 'cap-idempotent', value: 1 };
  await outbox.enqueue(record);
  const duplicate = await outbox.enqueue(record);
  assert.equal(duplicate.duplicate, true);
  await assert.rejects(outbox.enqueue({ ...record, value: 2 }), CaptureConflictError);
  assert.equal(fs.readdirSync(path.join(directory, 'pending')).length, 1);
  assert.equal(outbox.snapshot().offerConservationOk, true);
});

test('preserves non-retryable collector failures for inspection', async (t) => {
  const directory = temporaryDirectory(t);
  const outbox = new DurableCaptureOutbox({
    directory,
    url: 'http://collector',
    fetchImpl: async () => response(400, { reason: 'invalid_capture' }),
  });
  t.after(() => outbox.close());
  await outbox.enqueue({ captureId: 'cap-invalid-remote' });
  await outbox.waitForEmpty();
  assert.equal(fs.readdirSync(path.join(directory, 'failed')).length, 1);
  assert.equal(outbox.snapshot().quarantined, 1);
  assert.equal(outbox.snapshot().deliveryConservationOk, true);
});

test('preserves remote captureId conflicts separately', async (t) => {
  const directory = temporaryDirectory(t);
  const outbox = new DurableCaptureOutbox({
    directory,
    url: 'http://collector',
    fetchImpl: async () => response(409, { reason: 'capture_store' }),
  });
  t.after(() => outbox.close());
  await outbox.enqueue({ captureId: 'cap-conflict-remote' });
  await outbox.waitForEmpty();
  assert.equal(fs.readdirSync(path.join(directory, 'conflicts')).length, 1);
  assert.equal(outbox.snapshot().remoteConflicts, 1);
  assert.equal(outbox.snapshot().deliveryConservationOk, true);
});

test('enforces pending byte capacity before acknowledgement', async (t) => {
  const directory = temporaryDirectory(t);
  const outbox = new DurableCaptureOutbox({
    directory,
    url: 'http://collector',
    autostart: false,
    maxBytes: 80,
    fetchImpl: async () => response(202, { ok: true, durable: true }),
  });
  t.after(() => outbox.close());
  await outbox.enqueue({ captureId: 'cap-held', body: 'x'.repeat(20) });
  await assert.rejects(
    outbox.enqueue({ captureId: 'cap-over-capacity', body: 'x'.repeat(20) }),
    OutboxFullError,
  );
  assert.equal(outbox.snapshot().offerConservationOk, true);
});
