'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
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

function collector() {
  return { ok: true, build: { version: '0.6.0', revision: 'f'.repeat(40) },
    collector: { ok: true, ready: true, captures: 33, queue_depth: 0, last_error: null } };
}

test('runtime gate rejects an unobserved or unhealthy Collector despite healthy gateway and Relay', () => {
  assert.throws(() => verifyRuntimeHealth(gateway(), relay()), /collector health/);
  const unavailable = collector(); unavailable.ok = false;
  assert.throws(() => verifyRuntimeHealth(gateway(), relay(), { collectorHealth: unavailable }), /collector health.ok/);
  for (const changes of [
    { ok: false }, { ready: false }, { captures: 31 }, { captures: -1 },
    { queue_depth: 1 }, { last_error: 'PRIVATE_COLLECTOR_ERROR_BODY' },
  ]) {
    const value = collector();
    Object.assign(value.collector, changes);
    assert.throws(() => verifyRuntimeHealth(gateway(), relay(), { collectorHealth: value }), error => {
      assert.match(error.message, /collector/);
      assert.doesNotMatch(error.message, /PRIVATE_COLLECTOR_ERROR_BODY/);
      return true;
    });
  }
});

test('runtime gate rejects a different Collector build and unknown deployment revisions', () => {
  const value = collector();
  value.build.revision = 'e'.repeat(40);
  assert.throws(() => verifyRuntimeHealth(gateway(), relay(), { collectorHealth: value,
    expectedRevision: 'f'.repeat(40) }), /collector health\.build\.revision/);
  assert.throws(() => verifyRuntimeHealth(gateway(), relay(), { collectorHealth: value }), /collector health\.build\.revision/);
  assert.throws(() => verifyRuntimeHealth(gateway(), relay(), { collectorHealth: collector(), expectedRevision: 'unknown' }), /full Git commit SHA/);
  const old = collector(); delete old.build;
  assert.throws(() => verifyRuntimeHealth(gateway(), relay(), { collectorHealth: old }), /collector health\.build must be an object/);
  for (const revision of ['unknown', 'b68412b', 'PRIVATE_REVISION_MUST_NOT_LEAK']) {
    const current = relay(); current.build.revision = revision;
    assert.throws(() => verifyRuntimeHealth(gateway(), current, { collectorHealth: collector() }), error => {
      assert.match(error.message, /full Git commit SHA/);
      assert.doesNotMatch(error.message, /PRIVATE_REVISION_MUST_NOT_LEAK/);
      return true;
    });
  }
});

test('runtime CLI observes all three endpoints and refuses Collector faults or missing probes', async t => {
  let mode = 'healthy';
  const requests = [];
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-runtime-gate-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const server = http.createServer((req, res) => {
    requests.push(req.url);
    const value = req.url === '/gateway' ? gateway() : req.url === '/relay' ? relay() : collector();
    const isCollector = req.url === '/collector';
    if (isCollector && mode === 'old') value.build.revision = 'e'.repeat(40);
    if (isCollector && mode === 'short') value.collector.captures = 31;
    res.writeHead(isCollector && mode === 'unavailable' ? 503 : 200,
      { 'content-type': 'application/json', connection: 'close' });
    res.end(JSON.stringify(value));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}`;
  const flags = ['--gateway-url', `${url}/gateway`, '--relay-url', `${url}/relay`];
  const invoke = args => promisify(execFile)(process.execPath, [require.resolve('./runtime-health-gate'), ...args], { timeout: 10000 });
  const report = path.join(root, 'healthy.json');
  const complete = [...flags, '--collector-url', `${url}/collector`, '--expected-revision', 'f'.repeat(40)];
  const result = JSON.parse((await invoke([...complete, '--report', report])).stdout);
  assert.equal(result.schema_version, 'chiptrace.runtime-health-gate.v3');
  assert.equal(result.session_delivery_claimed, false);
  assert.equal(result.collector.captures, 33);
  const healthyReport = JSON.parse(await fs.readFile(report, 'utf8'));
  assert.equal(healthyReport.ok, true);
  assert.equal(healthyReport.schema_version, 'chiptrace.runtime-health-gate.v3');
  assert.deepEqual(requests.sort(), ['/collector', '/gateway', '/relay']);
  for (const [fault, pattern] of [
    ['old', /collector health\.build\.revision does not match expected revision/],
    ['short', /collector durable capture total is below Relay delivered total/],
    ['unavailable', /HTTP 503/],
  ]) {
    mode = fault;
    await assert.rejects(invoke(complete), error => {
      assert.equal(error.code, 1); assert.equal(error.stdout, ''); assert.match(error.stderr, pattern);
      return true;
    });
  }
  const missing = await invoke(flags).then(() => null, error => error);
  assert.equal(missing.code, 1);
  assert.match(missing.stderr, /--collector-url URL/);
});

test('runtime gate report records bounded failure state without arbitrary health payloads', async t => {
  const current = relay();
  current.ingest_coverage.status = 'degraded';
  current.ingest_coverage.required_sources_observed = false;
  current.ingest_coverage.required_sources_fresh = false;
  current.ingest_coverage.wire = { requests: 0, source_records: 0, last_at: null };
  current.ingest_coverage.stale_sources = ['wire', 'PRIVATE_SOURCE_MUST_NOT_LEAK'];
  current.collector_private = 'PRIVATE_COLLECTOR_BODY_MUST_NOT_LEAK';
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
    res.end(JSON.stringify(req.url === '/gateway' ? gateway() : req.url === '/collector' ? collector() : current));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-runtime-report-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const report = path.join(root, 'failed.json');
  const url = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(promisify(execFile)(process.execPath, [require.resolve('./runtime-health-gate'),
    '--gateway-url', `${url}/gateway`, '--relay-url', `${url}/relay`, '--collector-url', `${url}/collector`,
    '--expected-revision', current.build.revision, '--report', report], { timeout: 10000 }), error => {
    assert.equal(error.code, 1);
    assert.equal(error.stdout, '');
    assert.match(error.stderr, /observed=degraded; missing_sources=wire; stale_sources=wire/);
    assert.doesNotMatch(error.stderr, /PRIVATE_SOURCE_MUST_NOT_LEAK/);
    return true;
  });
  const observed = JSON.parse(await fs.readFile(report, 'utf8'));
  assert.equal(observed.ok, false);
  assert.equal(observed.failure_kind, 'validation_failed');
  assert.equal(observed.schema_version, 'chiptrace.runtime-health-observation.v1');
  assert.deepEqual(observed.relay.coverage.missing_sources, ['wire']);
  assert.deepEqual(observed.relay.coverage.stale_sources, ['wire']);
  assert.equal(observed.relay.coverage.wire.requests, 0);
  assert.equal(Object.hasOwn(observed, 'collector_private'), false);
  assert.doesNotMatch(JSON.stringify(observed), /PRIVATE_/);
  assert.equal(Object.hasOwn(observed, 'gateway_url'), false);
});

test('runtime health gate requires fresh scoped HTTP success without claiming Session delivery', () => {
  const result = verifyRuntimeHealth(gateway(), relay(), { collectorHealth: collector() });
  assert.equal(result.schema_version, 'chiptrace.runtime-health-gate.v3');
  assert.equal(result.session_delivery_claimed, false);
  assert.equal(result.gateway.open_capture_healthy, true);
  assert.equal(result.relay.freshness_applicable, true);
  assert.deepEqual(result.relay.sources, { wire: 8, otlp_logs: 15, otlp_traces: 9, hooks: 8 });
  assert.equal(result.relay.wire_turn_coverage.successful_turn_scoped_captures, 5);
  assert.equal(result.collector.captures, 33);
  assert.equal(result.collector.build_revision, relay().build.revision);
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

test('deployment gate requires matching Collector and Relay revisions', () => {
  const expectedRevision = 'f'.repeat(40);
  const result = verifyRuntimeHealth(gateway(), relay(), { expectedRevision, collectorHealth: collector() });
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
    res.end(JSON.stringify(req.url === '/gateway' ? gateway() : req.url === '/collector' ? collector() : current));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(promisify(execFile)(process.execPath, [require.resolve('./runtime-health-gate'),
    '--gateway-url', `${url}/gateway`, '--relay-url', `${url}/relay`,
    '--collector-url', `${url}/collector`,
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
    res.end(JSON.stringify(req.url === '/gateway' ? gateway() : req.url === '/collector' ? collector() : current));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(promisify(execFile)(process.execPath, [require.resolve('./runtime-health-gate'),
    '--gateway-url', `${url}/gateway`, '--relay-url', `${url}/relay`,
    '--collector-url', `${url}/collector`], { timeout: 10000 }), error => {
    assert.equal(error.code, 1);
    assert.equal(error.stdout, '');
    assert.match(error.stderr, /successful_turn_scoped_captures must be positive/);
    return true;
  });
});
