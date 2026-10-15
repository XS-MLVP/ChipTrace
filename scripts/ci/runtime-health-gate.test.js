'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { verifyRuntimeHealth } = require('./runtime-health-gate');

function gateway() {
  return {
    status: 'healthy',
    fullTraceCapture: {
      enabled: true,
      currentDeliveryHealthy: true,
      outbox: {
        pending: 0,
        processing: 0,
        recentFailureCount: 0,
        openCaptureHealthy: true,
        openTransactions: 0,
        failedFiles: 3,
      },
      rustRelay: {
        configured: true,
        healthy: true,
        conservationOk: true,
        pending: 0,
        inflight: 0,
        failed: 0,
        delivered: 32,
      },
    },
  };
}

function relay() {
  const route = source_records => ({
    requests: 1, source_records, durable_captures: source_records, last_at: '2026-10-15T00:00:00Z',
  });
  return {
    status: 'healthy',
    ok: true,
    build: {
      version: '0.6.0',
      revision: 'f'.repeat(40),
    },
    pending: 0,
    inflight: 0,
    failed: 0,
    delivered: 32,
    conservation_ok: true,
    ingest_coverage: {
      status: 'complete',
      required_sources_observed: true,
      required_sources_fresh: true,
      freshness_applicable: true,
      freshness_window_ms: 300000,
      wire_age_ms: 0,
      missing_sources: [],
      stale_sources: [],
      wire: route(8),
      wire_turn_coverage: {
        success_definition: 'http_2xx',
        freshness_definition: 'new_durable_capture',
        turn_scoped_captures: 6,
        successful_turn_scoped_captures: 5,
        unscoped_captures: 2,
        identity_conflict_captures: 1,
        last_successful_at: '2026-10-15T00:00:00Z',
        last_successful_age_ms: 0,
        successful_turn_scoped_fresh: true,
      },
      otlp_logs: route(15),
      otlp_traces: route(9),
      hooks: route(8),
    },
  };
}

test('runtime health gate requires fresh scoped HTTP success without claiming Session delivery', () => {
  const result = verifyRuntimeHealth(gateway(), relay());
  assert.equal(result.schema_version, 'chiptrace.runtime-health-gate.v2');
  assert.equal(result.session_delivery_claimed, false);
  assert.equal(result.gateway.open_capture_healthy, true);
  assert.equal(result.relay.freshness_applicable, true);
  assert.deepEqual(result.relay.sources, { wire: 8, otlp_logs: 15, otlp_traces: 9, hooks: 8 });
  assert.equal(result.relay.wire_turn_coverage.successful_turn_scoped_captures, 5);
});

test('older health with only global Wire traffic fails closed', () => {
  const value = relay();
  delete value.ingest_coverage.wire_turn_coverage;
  assert.throws(() => verifyRuntimeHealth(gateway(), value), /wire_turn_coverage must be an object/);
});

test('unscoped 403 traffic and scoped non-2xx responses cannot satisfy the runtime gate', () => {
  for (const scoped of [0, 8]) {
    const value = relay();
    Object.assign(value.ingest_coverage.wire_turn_coverage, {
      turn_scoped_captures: scoped,
      successful_turn_scoped_captures: 0,
      unscoped_captures: 8 - scoped,
      identity_conflict_captures: 0,
      last_successful_at: null,
      last_successful_age_ms: null,
      successful_turn_scoped_fresh: false,
    });
    assert.throws(() => verifyRuntimeHealth(gateway(), value),
      /successful_turn_scoped_captures must be positive/);
  }
});

test('fresh global Wire cannot hide stale successful Turn evidence or inconsistent counters', () => {
  for (const changes of [
    { last_successful_age_ms: 300001 },
    { successful_turn_scoped_fresh: false },
    { last_successful_age_ms: null },
    { successful_turn_scoped_captures: 7 },
    { unscoped_captures: 3 },
    { identity_conflict_captures: 3 },
    { success_definition: 'http_or_sse_success' },
    { freshness_definition: 'any_retry' },
  ]) {
    const value = relay();
    Object.assign(value.ingest_coverage.wire_turn_coverage, changes);
    assert.throws(() => verifyRuntimeHealth(gateway(), value), /wire_turn_coverage/);
  }
});

test('old gateway health without openCaptureHealthy fails closed', () => {
  const value = gateway();
  delete value.fullTraceCapture.outbox.openCaptureHealthy;
  assert.throws(() => verifyRuntimeHealth(value, relay()), /openCaptureHealthy must be true/);
});

test('a stale or non-applicable Wire source cannot pass', () => {
  const value = relay();
  value.ingest_coverage.freshness_applicable = false;
  assert.throws(() => verifyRuntimeHealth(gateway(), value), /freshness_applicable must be true/);
  value.ingest_coverage.freshness_applicable = true;
  value.ingest_coverage.required_sources_fresh = false;
  assert.throws(() => verifyRuntimeHealth(gateway(), value), /required_sources_fresh must be true/);
});

test('missing or stale source lists fail even when Relay status says complete', () => {
  const value = relay();
  value.ingest_coverage.stale_sources = ['wire'];
  assert.throws(() => verifyRuntimeHealth(gateway(), value), /stale_sources must be empty/);
});

test('queue failures and non-conservation fail closed', () => {
  const value = relay();
  value.pending = 1;
  assert.throws(() => verifyRuntimeHealth(gateway(), value), /relay.pending must be zero/);
  value.pending = 0;
  value.conservation_ok = false;
  assert.throws(() => verifyRuntimeHealth(gateway(), value), /conservation_ok must be true/);
});

test('gateway and Relay delivery totals must agree', () => {
  const value = relay();
  value.delivered -= 1;
  assert.throws(
    () => verifyRuntimeHealth(gateway(), value),
    /gateway and Relay delivered totals do not match/,
  );
});

test('deployment gate can require the running Relay revision', () => {
  const expectedRevision = 'f'.repeat(40);
  const result = verifyRuntimeHealth(gateway(), relay(), { expectedRevision });
  assert.equal(result.expected_revision, expectedRevision);
  assert.equal(result.build_revision, expectedRevision);
  assert.throws(
    () => verifyRuntimeHealth(gateway(), relay(), { expectedRevision: 'e'.repeat(40) }),
    /relay health\.build\.revision does not match expected revision/,
  );
  const old = relay();
  delete old.build;
  assert.throws(
    () => verifyRuntimeHealth(gateway(), old, { expectedRevision }),
    /relay health\.build must be an object/,
  );
});

test('runtime gate CLI preserves a real failure and diagnoses Wire missing from older health', async t => {
  const current = relay();
  current.ingest_coverage.status = 'degraded';
  current.ingest_coverage.required_sources_observed = false;
  current.ingest_coverage.required_sources_fresh = false;
  current.ingest_coverage.wire = { requests: 0, source_records: 0, last_at: null };
  current.ingest_coverage.stale_sources = ['wire', 'private-untrusted-source'];
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
    res.end(JSON.stringify(req.url === '/gateway' ? gateway() : current));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(promisify(execFile)(process.execPath, [require.resolve('./runtime-health-gate'),
    '--gateway-url', `${url}/gateway`, '--relay-url', `${url}/relay`,
    '--expected-revision', current.build.revision], { timeout: 10000 }), error => {
    assert.equal(error.code, 1);
    assert.equal(error.stdout, '');
    assert.match(error.stderr, /observed=degraded; missing_sources=wire; stale_sources=wire/);
    assert.doesNotMatch(error.stderr, /private-untrusted-source/);
    return true;
  });
});

test('runtime gate CLI returns nonzero for an unscoped 403 despite fresh four-source health', async t => {
  const current = relay();
  Object.assign(current.ingest_coverage.wire_turn_coverage, {
    turn_scoped_captures: 0,
    successful_turn_scoped_captures: 0,
    unscoped_captures: 8,
    identity_conflict_captures: 0,
    last_successful_at: null,
    last_successful_age_ms: null,
    successful_turn_scoped_fresh: false,
  });
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
    res.end(JSON.stringify(req.url === '/gateway' ? gateway() : current));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(promisify(execFile)(process.execPath, [require.resolve('./runtime-health-gate'),
    '--gateway-url', `${url}/gateway`, '--relay-url', `${url}/relay`], { timeout: 10000 }), error => {
    assert.equal(error.code, 1);
    assert.equal(error.stdout, '');
    assert.match(error.stderr, /successful_turn_scoped_captures must be positive/);
    return true;
  });
});
