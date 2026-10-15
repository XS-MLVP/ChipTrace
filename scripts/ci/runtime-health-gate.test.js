'use strict';

const assert = require('node:assert/strict');
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
  const route = source_records => ({ requests: 1, source_records, last_at: '2026-10-15T00:00:00Z' });
  return {
    status: 'healthy',
    ok: true,
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
      otlp_logs: route(15),
      otlp_traces: route(9),
      hooks: route(8),
    },
  };
}

test('runtime health gate accepts a fresh four-source delivery closure', () => {
  const result = verifyRuntimeHealth(gateway(), relay());
  assert.equal(result.schema_version, 'chiptrace.runtime-health-gate.v1');
  assert.equal(result.gateway.open_capture_healthy, true);
  assert.equal(result.relay.freshness_applicable, true);
  assert.deepEqual(result.relay.sources, { wire: 8, otlp_logs: 15, otlp_traces: 9, hooks: 8 });
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
