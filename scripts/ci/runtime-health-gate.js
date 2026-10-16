'use strict';

const fs = require('node:fs');

const DEFAULT_TIMEOUT_MS = 5000;
const REQUIRED_SOURCES = ['wire', 'otlp_logs', 'otlp_traces', 'hooks'];
const REVISION_PATTERN = /^[a-f0-9]{40}$/;

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

function safeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function safeTimestamp(value) {
  return typeof value === 'string' && value.trim() !== '' ? value : null;
}

function safeSources(value) {
  return Array.isArray(value)
    ? value.filter(source => REQUIRED_SOURCES.includes(source))
    : [];
}

function observedMissingSources(coverage) {
  const listed = safeSources(coverage?.missing_sources);
  const derived = REQUIRED_SOURCES.filter(source => {
    const route = coverage?.[source];
    return route && (route.requests === 0 || route.source_records === 0);
  });
  return [...new Set([...listed, ...derived])];
}

function routeObservation(route) {
  if (!route || typeof route !== 'object' || Array.isArray(route)) return null;
  return {
    requests: safeInteger(route.requests),
    source_records: safeInteger(route.source_records),
    durable_captures: safeInteger(route.durable_captures),
    duplicates: safeInteger(route.duplicates),
    last_at: safeTimestamp(route.last_at),
  };
}

function healthObservation(gateway, relay, collector) {
  const capture = gateway?.fullTraceCapture;
  const gatewayRelay = capture?.rustRelay;
  const coverage = relay?.ingest_coverage;
  const turnCoverage = coverage?.wire_turn_coverage;
  const collectorStore = collector?.collector;
  return {
    schema_version: 'chiptrace.runtime-health-observation.v1',
    observed_at: new Date().toISOString(),
    session_delivery_claimed: false,
    gateway: {
      status: typeof gateway?.status === 'string' ? gateway.status : null,
      current_delivery_healthy: capture?.currentDeliveryHealthy === true,
      open_capture_healthy: capture?.outbox?.openCaptureHealthy === true,
      delivered: safeInteger(gatewayRelay?.delivered),
      pending: safeInteger(gatewayRelay?.pending),
      inflight: safeInteger(gatewayRelay?.inflight),
      failed: safeInteger(gatewayRelay?.failed),
    },
    relay: {
      status: typeof relay?.status === 'string' ? relay.status : null,
      revision: safeTimestamp(relay?.build?.revision),
      delivered: safeInteger(relay?.delivered),
      pending: safeInteger(relay?.pending),
      inflight: safeInteger(relay?.inflight),
      failed: safeInteger(relay?.failed),
      conservation_ok: relay?.conservation_ok === true,
      coverage: {
        status: typeof coverage?.status === 'string' ? coverage.status : null,
        required_sources_observed: coverage?.required_sources_observed === true,
        required_sources_fresh: coverage?.required_sources_fresh === true,
        freshness_applicable: coverage?.freshness_applicable === true,
        freshness_window_ms: safeInteger(coverage?.freshness_window_ms),
        wire_age_ms: safeInteger(coverage?.wire_age_ms),
        runtime_age_ms: safeInteger(coverage?.runtime_age_ms),
        missing_sources: observedMissingSources(coverage),
        stale_sources: safeSources(coverage?.stale_sources),
        source_lag_ms: {
          otlp_logs: safeInteger(coverage?.source_lag_ms?.otlp_logs),
          otlp_traces: safeInteger(coverage?.source_lag_ms?.otlp_traces),
          hooks: safeInteger(coverage?.source_lag_ms?.hooks),
        },
        wire: routeObservation(coverage?.wire),
        otlp_logs: routeObservation(coverage?.otlp_logs),
        otlp_traces: routeObservation(coverage?.otlp_traces),
        hooks: routeObservation(coverage?.hooks),
        wire_turn_coverage: {
          turn_scoped_captures: safeInteger(turnCoverage?.turn_scoped_captures),
          successful_turn_scoped_captures: safeInteger(turnCoverage?.successful_turn_scoped_captures),
          unscoped_captures: safeInteger(turnCoverage?.unscoped_captures),
          identity_conflict_captures: safeInteger(turnCoverage?.identity_conflict_captures),
          last_successful_at: safeTimestamp(turnCoverage?.last_successful_at),
          last_successful_age_ms: safeInteger(turnCoverage?.last_successful_age_ms),
          successful_turn_scoped_fresh: turnCoverage?.successful_turn_scoped_fresh === true,
        },
      },
    },
    collector: {
      ok: collector?.ok === true,
      revision: safeTimestamp(collector?.build?.revision),
      ready: collectorStore?.ready === true,
      captures: safeInteger(collectorStore?.captures),
      queue_depth: safeInteger(collectorStore?.queue_depth),
      last_error_present: collectorStore?.last_error !== null && collectorStore?.last_error !== undefined,
    },
  };
}

function writeReport(reportPath, value) {
  if (!reportPath) return;
  fs.writeFileSync(reportPath, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
}

function verifyBuildRevision(health, expectedRevision, label) {
  if (expectedRevision !== undefined && (typeof expectedRevision !== 'string' || !REVISION_PATTERN.test(expectedRevision))) {
    fail('expected revision must be a full Git commit SHA');
  }
  const build = object(health.build, `${label}.build`);
  const revision = nonEmptyString(build.revision, `${label}.build.revision`);
  if (!REVISION_PATTERN.test(revision)) fail(`${label}.build.revision must be a full Git commit SHA`);
  if (expectedRevision !== undefined && revision !== expectedRevision) {
    fail(`${label}.build.revision does not match expected revision `
      + `(expected=${expectedRevision}, observed=${revision})`);
  }
  return revision;
}

function verifyCollectorHealth(health) {
  object(health, 'collector health');
  requireTrue(health.ok, 'collector health.ok');
  const store = object(health.collector, 'collector health.collector');
  requireTrue(store.ok, 'collector health.collector.ok');
  requireTrue(store.ready, 'collector health.collector.ready');
  const captures = nonNegativeInteger(store.captures, 'collector health.collector.captures');
  requireZero(nonNegativeInteger(store.queue_depth, 'collector health.collector.queue_depth'), 'collector health.collector.queue_depth');
  if (store.last_error !== null) fail('collector health.collector.last_error must be null');
  return { ok: true, ready: true, captures, queue_depth: store.queue_depth };
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

function verifyWireTurnCoverage(coverage) {
  const label = 'relay.ingest_coverage.wire_turn_coverage';
  const turns = object(coverage.wire_turn_coverage, label);
  if (turns.success_definition !== 'http_2xx') fail(`${label}.success_definition must be http_2xx`);
  if (turns.freshness_definition !== 'new_durable_capture') {
    fail(`${label}.freshness_definition must be new_durable_capture`);
  }
  const scoped = nonNegativeInteger(turns.turn_scoped_captures, `${label}.turn_scoped_captures`);
  const successful = nonNegativeInteger(
    turns.successful_turn_scoped_captures, `${label}.successful_turn_scoped_captures`,
  );
  const unscoped = nonNegativeInteger(turns.unscoped_captures, `${label}.unscoped_captures`);
  const conflicts = nonNegativeInteger(
    turns.identity_conflict_captures, `${label}.identity_conflict_captures`,
  );
  const durable = nonNegativeInteger(
    coverage.wire.durable_captures, 'relay.ingest_coverage.wire.durable_captures',
  );
  if (scoped + unscoped !== durable || successful > scoped || conflicts > unscoped) {
    fail(`${label} counts are inconsistent with durable Wire captures`);
  }
  if (successful === 0) fail(`${label}.successful_turn_scoped_captures must be positive`);
  nonEmptyString(turns.last_successful_at, `${label}.last_successful_at`);
  const age = nonNegativeInteger(turns.last_successful_age_ms, `${label}.last_successful_age_ms`);
  if (coverage.freshness_window_ms === 0 || age > coverage.freshness_window_ms) {
    fail(`${label}.last_successful_age_ms exceeds the positive freshness window`);
  }
  requireTrue(turns.successful_turn_scoped_fresh, `${label}.successful_turn_scoped_fresh`);
  return {
    success_definition: turns.success_definition,
    freshness_definition: turns.freshness_definition,
    turn_scoped_captures: scoped,
    successful_turn_scoped_captures: successful,
    unscoped_captures: unscoped,
    identity_conflict_captures: conflicts,
    last_successful_at: turns.last_successful_at,
    last_successful_age_ms: age,
    successful_turn_scoped_fresh: turns.successful_turn_scoped_fresh,
  };
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
  const wireTurnCoverage = verifyWireTurnCoverage(coverage);

  return {
    status: health.status,
    delivered: health.delivered,
    conservation_ok: health.conservation_ok,
    coverage_status: coverage.status,
    freshness_applicable: coverage.freshness_applicable,
    required_sources_fresh: coverage.required_sources_fresh,
    wire_turn_coverage: wireTurnCoverage,
    sources: REQUIRED_SOURCES.reduce((result, source) => {
      result[source] = coverage[source].source_records;
      return result;
    }, {}),
  };
}

function verifyRuntimeHealth(gatewayHealth, relayHealth, { expectedRevision, collectorHealth } = {}) {
  const gateway = verifyGatewayHealth(gatewayHealth);
  const relay = verifyRelayHealth(relayHealth);
  const buildRevision = verifyBuildRevision(relayHealth, expectedRevision, 'relay health');
  if (gateway.delivered !== relay.delivered) {
    fail(
      'gateway and Relay delivered totals do not match '
      + `(gateway=${gateway.delivered}, relay=${relay.delivered})`,
    );
  }
  const collector = verifyCollectorHealth(collectorHealth);
  const collectorRevision = verifyBuildRevision(collectorHealth, expectedRevision ?? buildRevision, 'collector health');
  // The private Collector may also receive evaluator data or other Relays.
  // It must contain at least the Relay's durable delivery total, not exactly
  // that total. These counters do not prove any Session's Raw completeness.
  if (collector.captures < relay.delivered) {
    fail('collector durable capture total is below Relay delivered total '
      + `(collector=${collector.captures}, relay=${relay.delivered})`);
  }
  return {
    schema_version: 'chiptrace.runtime-health-gate.v3',
    // This process-wide health gate cannot prove any Session's full delivery.
    session_delivery_claimed: false,
    expected_revision: expectedRevision ?? null,
    build_revision: buildRevision,
    gateway,
    relay,
    collector: { ...collector, build_revision: collectorRevision },
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
  collectorUrl,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  expectedRevision,
  reportPath,
) {
  if (!gatewayUrl || !relayUrl || !collectorUrl) fail('gateway, relay and collector health URLs are required');
  let health;
  try {
    health = await Promise.all([
      fetchJson(gatewayUrl, timeoutMs),
      fetchJson(relayUrl, timeoutMs),
      fetchJson(collectorUrl, timeoutMs),
    ]);
  } catch (error) {
    writeReport(reportPath, {
      ok: false,
      schema_version: 'chiptrace.runtime-health-observation.v1',
      observed_at: new Date().toISOString(),
      session_delivery_claimed: false,
      failure_kind: 'fetch_failed',
    });
    throw error;
  }
  const [gateway, relay, collector] = health;
  let result;
  try {
    result = verifyRuntimeHealth(gateway, relay, { expectedRevision, collectorHealth: collector });
  } catch (error) {
    writeReport(reportPath, {
      ok: false,
      ...healthObservation(gateway, relay, collector),
      failure_kind: 'validation_failed',
    });
    throw error;
  }
  writeReport(reportPath, { ok: true, ...result });
  return result;
}

function parseArgs(argv) {
  let gateway;
  let relay;
  let collector;
  let timeout = DEFAULT_TIMEOUT_MS;
  let expectedRevision;
  let report;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--gateway-url' && value) { gateway = value; index += 1; }
    else if (flag === '--relay-url' && value) { relay = value; index += 1; }
    else if (flag === '--collector-url' && value) { collector = value; index += 1; }
    else if (flag === '--timeout-ms' && value) { timeout = Number(value); index += 1; }
    else if (flag === '--expected-revision' && value) { expectedRevision = value; index += 1; }
    else if (flag === '--report' && value) { report = value; index += 1; }
    else fail('usage: runtime-health-gate.js --gateway-url URL --relay-url URL --collector-url URL [--timeout-ms N] [--expected-revision REVISION] [--report PATH]');
  }
  if (!gateway || !relay || !collector || !Number.isSafeInteger(timeout) || timeout < 100) {
    fail('usage: runtime-health-gate.js --gateway-url URL --relay-url URL --collector-url URL [--timeout-ms N] [--expected-revision REVISION] [--report PATH]');
  }
  return { gateway, relay, collector, timeout, expectedRevision, report };
}

if (require.main === module) {
  const args = parseArgs(process.argv.slice(2));
  runRemoteHealthGate(args.gateway, args.relay, args.collector, args.timeout, args.expectedRevision, args.report)
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
  verifyCollectorHealth,
  verifyRuntimeHealth,
  healthObservation,
  runRemoteHealthGate,
};
