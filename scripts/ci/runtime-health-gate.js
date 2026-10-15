'use strict';

const DEFAULT_TIMEOUT_MS = 5000;
const REQUIRED_SOURCES = ['wire', 'otlp_logs', 'otlp_traces', 'hooks'];

function fail(message) {
  throw new Error(`runtime health gate: ${message}`);
}

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function nonNegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${label} must be a non-negative integer`);
  }
  return value;
}

function requireTrue(value, label) {
  if (value !== true) fail(`${label} must be true`);
}

function requireZero(value, label) {
  if (value !== 0) fail(`${label} must be zero`);
}

function nonEmptyString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') {
    fail(`${label} must be a non-empty string`);
  }
  return value;
}

function verifyBuildRevision(health, expectedRevision, label) {
  if (expectedRevision === undefined) return null;
  const build = object(health.build, `${label}.build`);
  const revision = nonEmptyString(build.revision, `${label}.build.revision`);
  if (revision !== expectedRevision) {
    fail(`${label}.build.revision does not match expected revision `
      + `(expected=${expectedRevision}, observed=${revision})`);
  }
  return revision;
}

function verifyGatewayHealth(health) {
  object(health, 'gateway health');
  if (health.status !== 'healthy') fail('gateway status must be healthy');
  const capture = object(health.fullTraceCapture, 'gateway.fullTraceCapture');
  requireTrue(capture.enabled, 'gateway.fullTraceCapture.enabled');
  requireTrue(capture.currentDeliveryHealthy, 'gateway.fullTraceCapture.currentDeliveryHealthy');

  const outbox = object(capture.outbox, 'gateway.fullTraceCapture.outbox');
  requireZero(nonNegativeInteger(outbox.pending, 'gateway outbox.pending'), 'gateway outbox.pending');
  requireZero(nonNegativeInteger(outbox.processing, 'gateway outbox.processing'), 'gateway outbox.processing');
  requireZero(
    nonNegativeInteger(outbox.recentFailureCount, 'gateway outbox.recentFailureCount'),
    'gateway outbox.recentFailureCount',
  );
  // Older gateways omitted this field and cannot prove that a long-lived
  // streaming capture is safe to hand off.
  requireTrue(outbox.openCaptureHealthy, 'gateway outbox.openCaptureHealthy');
  nonNegativeInteger(outbox.openTransactions, 'gateway outbox.openTransactions');
  nonNegativeInteger(outbox.failedFiles, 'gateway outbox.failedFiles');

  const relay = object(capture.rustRelay, 'gateway.fullTraceCapture.rustRelay');
  requireTrue(relay.configured, 'gateway rustRelay.configured');
  requireTrue(relay.healthy, 'gateway rustRelay.healthy');
  requireTrue(relay.conservationOk, 'gateway rustRelay.conservationOk');
  requireZero(nonNegativeInteger(relay.pending, 'gateway rustRelay.pending'), 'gateway rustRelay.pending');
  requireZero(nonNegativeInteger(relay.inflight, 'gateway rustRelay.inflight'), 'gateway rustRelay.inflight');
  requireZero(nonNegativeInteger(relay.failed, 'gateway rustRelay.failed'), 'gateway rustRelay.failed');
  nonNegativeInteger(relay.delivered, 'gateway rustRelay.delivered');

  return {
    status: health.status,
    current_delivery_healthy: capture.currentDeliveryHealthy,
    open_capture_healthy: outbox.openCaptureHealthy,
    open_transactions: outbox.openTransactions,
    historical_failed_files: outbox.failedFiles,
    delivered: relay.delivered,
  };
}

function verifyCoverageRoute(route, source) {
  const value = object(route, `relay.ingest_coverage.${source}`);
  if (nonNegativeInteger(value.requests, `relay.ingest_coverage.${source}.requests`) === 0) {
    fail(`relay.ingest_coverage.${source}.requests must be positive`);
  }
  if (nonNegativeInteger(value.source_records, `relay.ingest_coverage.${source}.source_records`) === 0) {
    fail(`relay.ingest_coverage.${source}.source_records must be positive`);
  }
  nonEmptyString(value.last_at, `relay.ingest_coverage.${source}.last_at`);
}

function verifyRelayHealth(health) {
  object(health, 'relay health');
  if (health.status !== 'healthy') fail('relay status must be healthy');
  requireTrue(health.ok, 'relay.ok');
  requireTrue(health.conservation_ok, 'relay.conservation_ok');
  requireZero(nonNegativeInteger(health.pending, 'relay.pending'), 'relay.pending');
  requireZero(nonNegativeInteger(health.inflight, 'relay.inflight'), 'relay.inflight');
  requireZero(nonNegativeInteger(health.failed, 'relay.failed'), 'relay.failed');
  nonNegativeInteger(health.delivered, 'relay.delivered');

  const coverage = object(health.ingest_coverage, 'relay.ingest_coverage');
  if (coverage.status !== 'complete') {
    // Keep failure diagnostics bounded and free of arbitrary health response
    // text. Older Relays omitted Wire from missing_sources even at count zero.
    const status = ['warming', 'partial', 'degraded'].includes(coverage.status)
      ? coverage.status : 'unknown';
    const missing = REQUIRED_SOURCES.filter(source => (
      coverage[source]?.requests === 0 || coverage[source]?.source_records === 0
      || (Array.isArray(coverage.missing_sources) && coverage.missing_sources.includes(source))
    ));
    const stale = REQUIRED_SOURCES.filter(source => (
      Array.isArray(coverage.stale_sources) && coverage.stale_sources.includes(source)
    ));
    fail('relay.ingest_coverage.status must be complete '
      + `(observed=${status}; missing_sources=${missing.join(',') || 'none'}; `
      + `stale_sources=${stale.join(',') || 'none'})`);
  }
  requireTrue(coverage.required_sources_observed, 'relay.ingest_coverage.required_sources_observed');
  requireTrue(coverage.required_sources_fresh, 'relay.ingest_coverage.required_sources_fresh');
  // Runtime traffic without a recent Wire source must never pass as complete.
  requireTrue(coverage.freshness_applicable, 'relay.ingest_coverage.freshness_applicable');
  if (!Array.isArray(coverage.missing_sources) || coverage.missing_sources.length !== 0) {
    fail('relay.ingest_coverage.missing_sources must be empty');
  }
  if (!Array.isArray(coverage.stale_sources) || coverage.stale_sources.length !== 0) {
    fail('relay.ingest_coverage.stale_sources must be empty');
  }
  nonNegativeInteger(coverage.freshness_window_ms, 'relay.ingest_coverage.freshness_window_ms');
  nonNegativeInteger(coverage.wire_age_ms, 'relay.ingest_coverage.wire_age_ms');
  for (const source of REQUIRED_SOURCES) verifyCoverageRoute(coverage[source], source);

  return {
    status: health.status,
    delivered: health.delivered,
    conservation_ok: health.conservation_ok,
    coverage_status: coverage.status,
    freshness_applicable: coverage.freshness_applicable,
    required_sources_fresh: coverage.required_sources_fresh,
    sources: REQUIRED_SOURCES.reduce((result, source) => {
      result[source] = coverage[source].source_records;
      return result;
    }, {}),
  };
}

function verifyRuntimeHealth(gatewayHealth, relayHealth, { expectedRevision } = {}) {
  const gateway = verifyGatewayHealth(gatewayHealth);
  const relay = verifyRelayHealth(relayHealth);
  const buildRevision = verifyBuildRevision(relayHealth, expectedRevision, 'relay health');
  if (gateway.delivered !== relay.delivered) {
    fail(
      'gateway and Relay delivered totals do not match '
      + `(gateway=${gateway.delivered}, relay=${relay.delivered})`,
    );
  }
  return {
    schema_version: 'chiptrace.runtime-health-gate.v1',
    expected_revision: expectedRevision ?? null,
    build_revision: buildRevision,
    gateway,
    relay,
  };
}

async function fetchJson(url, timeoutMs = DEFAULT_TIMEOUT_MS) {
  let response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    fail(`cannot fetch ${url}: ${error.message}`);
  }
  if (!response.ok) fail(`${url} returned HTTP ${response.status}`);
  try {
    return await response.json();
  } catch (error) {
    fail(`${url} returned invalid JSON: ${error.message}`);
  }
}

async function runRemoteHealthGate(
  gatewayUrl,
  relayUrl,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  expectedRevision,
) {
  if (!gatewayUrl || !relayUrl) fail('gateway and relay health URLs are required');
  const [gateway, relay] = await Promise.all([
    fetchJson(gatewayUrl, timeoutMs),
    fetchJson(relayUrl, timeoutMs),
  ]);
  return verifyRuntimeHealth(gateway, relay, { expectedRevision });
}

function parseArgs(argv) {
  let gateway;
  let relay;
  let timeout = DEFAULT_TIMEOUT_MS;
  let expectedRevision;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--gateway-url' && value) { gateway = value; index += 1; }
    else if (flag === '--relay-url' && value) { relay = value; index += 1; }
    else if (flag === '--timeout-ms' && value) { timeout = Number(value); index += 1; }
    else if (flag === '--expected-revision' && value) { expectedRevision = value; index += 1; }
    else fail('usage: runtime-health-gate.js --gateway-url URL --relay-url URL [--timeout-ms N] [--expected-revision REVISION]');
  }
  if (!gateway || !relay || !Number.isSafeInteger(timeout) || timeout < 100) {
    fail('usage: runtime-health-gate.js --gateway-url URL --relay-url URL [--timeout-ms N] [--expected-revision REVISION]');
  }
  return { gateway, relay, timeout, expectedRevision };
}

if (require.main === module) {
  const args = parseArgs(process.argv.slice(2));
  runRemoteHealthGate(args.gateway, args.relay, args.timeout, args.expectedRevision)
    .then(result => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
    .catch(error => {
      process.stderr.write(`${error.message || String(error)}\n`);
      process.exitCode = 1;
    });
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  REQUIRED_SOURCES,
  verifyGatewayHealth,
  verifyRelayHealth,
  verifyRuntimeHealth,
  runRemoteHealthGate,
};
