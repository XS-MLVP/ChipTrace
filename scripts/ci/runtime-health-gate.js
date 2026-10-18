'use strict';

const fs = require('node:fs');

const DEFAULT_TIMEOUT_MS = 5000;
const REQUIRED_SOURCES = ['wire', 'otlp_logs', 'otlp_traces', 'hooks'];
const QUALITY_ENDPOINTS = ['otlp_logs', 'otlp_traces', 'hooks'];
const QUALITY_REASON_CODES = [
  'unsupported_event',
  'invalid_structure',
  'invalid_attributes',
  'identity_conflict',
  'missing_identity',
  'invalid_tool',
  'invalid_lifecycle',
  'invalid_timestamp',
  'conversion_error',
  'legacy_unclassified',
];
const QUALITY_ERRORS_SCOPE = 'durable_relay_state';
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
    quality: {
      unknown_events: safeInteger(route.quality?.unknown_events),
      conversion_errors: safeInteger(route.quality?.conversion_errors),
      total: safeInteger(route.quality?.total),
    },
    last_at: safeTimestamp(route.last_at),
  };
}

function qualityErrorObservation(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const reasons = {};
  if (value.reasons && typeof value.reasons === 'object' && !Array.isArray(value.reasons)) {
    for (const code of QUALITY_REASON_CODES) {
      if (Number.isSafeInteger(value.reasons[code]) && value.reasons[code] >= 0) {
        reasons[code] = value.reasons[code];
      }
    }
  }
  return {
    unknown_events: safeInteger(value.unknown_events),
    conversion_errors: safeInteger(value.conversion_errors),
    total: safeInteger(value.total),
    reasons,
  };
}

function blockingReasons(
  observation,
  { expectedRevision, maxQualityErrors, maxHistoricalFailedFiles } = {},
) {
  const reasons = new Set();
  const add = reason => reasons.add(reason);
  const gateway = observation?.gateway || {};
  const relay = observation?.relay || {};
  const coverage = relay.coverage || {};
  const collector = observation?.collector || {};
  const turns = coverage.wire_turn_coverage || {};

  if (gateway.status !== 'healthy') add('gateway_not_healthy');
  if (gateway.current_delivery_healthy !== true) add('gateway_delivery_not_healthy');
  if (gateway.open_capture_healthy !== true) add('gateway_open_capture_not_healthy');
  if (gateway.pending !== 0) add('gateway_pending_records');
  if (gateway.inflight !== 0) add('gateway_inflight_records');
  if (gateway.failed !== 0) add('gateway_failed_records');
  if (maxHistoricalFailedFiles !== undefined
    && Number.isSafeInteger(
      gateway.unresolved_historical_failed_files ?? gateway.historical_failed_files,
    )
    && (gateway.unresolved_historical_failed_files ?? gateway.historical_failed_files)
      > maxHistoricalFailedFiles) {
    add('gateway_historical_failed_files_exceed_max');
  }

  if (relay.status !== 'healthy') add('relay_not_healthy');
  if (relay.pending !== 0) add('relay_pending_records');
  if (relay.inflight !== 0) add('relay_inflight_records');
  if (relay.failed !== 0) add('relay_failed_records');
  if (relay.conservation_ok !== true) add('relay_delivery_not_conserved');
  if (coverage.status !== 'complete') add('relay_coverage_not_complete');
  if (coverage.required_sources_observed !== true) add('relay_required_sources_not_observed');
  if (coverage.required_sources_fresh !== true) add('relay_required_sources_not_fresh');
  if (coverage.freshness_applicable !== true) add('relay_freshness_not_applicable');
  if (Array.isArray(coverage.missing_sources) && coverage.missing_sources.length > 0) {
    add('relay_sources_missing');
  }
  if (Array.isArray(coverage.stale_sources) && coverage.stale_sources.length > 0) {
    add('relay_sources_stale');
  }
  if (maxQualityErrors !== undefined
    && Number.isSafeInteger(coverage.quality_errors)
    && coverage.quality_errors > maxQualityErrors) {
    add('relay_quality_errors_exceed_max');
  }
  if (coverage.turn_capture_ready !== true) add('relay_turn_capture_not_ready');
  if (coverage.quality_errors_scope !== QUALITY_ERRORS_SCOPE) {
    add('relay_quality_history_not_durable');
  }
  if (coverage.quality_reason_breakdown_complete !== true) {
    add('relay_quality_reason_breakdown_missing');
  }
  if (Number.isSafeInteger(turns.successful_turn_scoped_captures)
    && turns.successful_turn_scoped_captures === 0) {
    add('relay_no_successful_turn_scoped_wire');
  }
  if (turns.successful_turn_scoped_fresh !== true) {
    add('relay_successful_turn_scoped_wire_not_fresh');
  }

  if (collector.ok !== true) add('collector_not_ok');
  if (collector.ready !== true) add('collector_not_ready');
  if (collector.queue_depth !== 0) add('collector_queue_not_empty');
  if (collector.last_error_present === true) add('collector_last_error_present');

  if (gateway.delivered !== null && relay.delivered !== null
    && gateway.delivered !== relay.delivered) {
    add('gateway_relay_delivery_totals_mismatch');
  }
  if (collector.captures !== null && relay.delivered !== null
    && collector.captures < relay.delivered) {
    add('collector_delivery_total_below_relay');
  }
  if (expectedRevision !== undefined) {
    if (relay.revision !== expectedRevision) add('relay_revision_mismatch');
    if (collector.revision !== expectedRevision) add('collector_revision_mismatch');
  } else if (relay.revision !== null && collector.revision !== null
    && relay.revision !== collector.revision) {
    add('relay_collector_revision_mismatch');
  }
  // Keep the report bounded even if a future health payload adds more checks.
  return [...reasons].slice(0, 32);
}

function healthObservation(
  gateway,
  relay,
  collector,
  { expectedRevision, maxQualityErrors, maxHistoricalFailedFiles } = {},
) {
  const capture = gateway?.fullTraceCapture;
  const gatewayRelay = capture?.rustRelay;
  const coverage = relay?.ingest_coverage;
  const turnCoverage = coverage?.wire_turn_coverage;
  const collectorStore = collector?.collector;
  const observation = {
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
      historical_failed_files: safeInteger(capture?.outbox?.failedFiles),
      unresolved_historical_failed_files: safeInteger(
        capture?.outbox?.unresolvedHistoricalFailedFiles,
      ),
      recovery_receipt_files: safeInteger(capture?.outbox?.recoveryReceiptFiles),
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
        quality_errors: safeInteger(coverage?.quality_errors),
        quality_errors_current_process: safeInteger(coverage?.quality_errors_current_process),
        quality_errors_scope: typeof coverage?.quality_errors_scope === 'string'
          ? coverage.quality_errors_scope : null,
        quality_errors_by_endpoint: {
          otlp_logs: qualityErrorObservation(coverage?.quality_errors_by_endpoint?.otlp_logs),
          otlp_traces: qualityErrorObservation(coverage?.quality_errors_by_endpoint?.otlp_traces),
          hooks: qualityErrorObservation(coverage?.quality_errors_by_endpoint?.hooks),
        },
        quality_reason_breakdown_complete: QUALITY_ENDPOINTS.every(endpoint => (
          coverage?.quality_errors_by_endpoint?.[endpoint]?.reasons
          && typeof coverage.quality_errors_by_endpoint[endpoint].reasons === 'object'
          && !Array.isArray(coverage.quality_errors_by_endpoint[endpoint].reasons)
        )),
        wire_turn_coverage: {
          turn_scoped_captures: safeInteger(turnCoverage?.turn_scoped_captures),
          successful_turn_scoped_captures: safeInteger(turnCoverage?.successful_turn_scoped_captures),
          unscoped_captures: safeInteger(turnCoverage?.unscoped_captures),
          identity_conflict_captures: safeInteger(turnCoverage?.identity_conflict_captures),
          last_successful_at: safeTimestamp(turnCoverage?.last_successful_at),
          last_successful_age_ms: safeInteger(turnCoverage?.last_successful_age_ms),
          successful_turn_scoped_fresh: turnCoverage?.successful_turn_scoped_fresh === true,
        },
        turn_capture_ready: coverage?.status === 'complete' && coverage?.turn_capture_ready === true,
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
  observation.blocking_reasons = blockingReasons(observation, {
    expectedRevision,
    maxQualityErrors,
    maxHistoricalFailedFiles,
  });
  return observation;
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

function verifyGatewayHealth(health, { maxHistoricalFailedFiles } = {}) {
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
  const historicalFailedFiles = nonNegativeInteger(outbox.failedFiles, 'gateway outbox.failedFiles');
  const unresolvedHistoricalFailedFiles = nonNegativeInteger(
    outbox.unresolvedHistoricalFailedFiles ?? historicalFailedFiles,
    'gateway outbox.unresolvedHistoricalFailedFiles',
  );
  if (maxHistoricalFailedFiles !== undefined) {
    if (!Number.isSafeInteger(maxHistoricalFailedFiles) || maxHistoricalFailedFiles < 0) {
      fail('max historical failed files must be a non-negative integer');
    }
    if (unresolvedHistoricalFailedFiles > maxHistoricalFailedFiles) {
      fail('gateway outbox unresolved historical failed files exceed the configured maximum '
        + `(observed=${unresolvedHistoricalFailedFiles}; maximum=${maxHistoricalFailedFiles})`);
    }
  }

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
    historical_failed_files: historicalFailedFiles,
    unresolved_historical_failed_files: unresolvedHistoricalFailedFiles,
    recovery_receipt_files: nonNegativeInteger(
      outbox.recoveryReceiptFiles ?? 0,
      'gateway outbox.recoveryReceiptFiles',
    ),
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

function verifyQualityBreakdown(coverage, qualityErrors) {
  if (coverage.quality_errors_by_endpoint === undefined) {
    fail('relay.ingest_coverage.quality_errors_by_endpoint is required');
  }
  const breakdown = object(
    coverage.quality_errors_by_endpoint,
    'relay.ingest_coverage.quality_errors_by_endpoint',
  );
  let total = 0;
  const result = {};
  for (const endpoint of QUALITY_ENDPOINTS) {
    const value = object(
      breakdown[endpoint],
      `relay.ingest_coverage.quality_errors_by_endpoint.${endpoint}`,
    );
    const unknown = nonNegativeInteger(
      value.unknown_events,
      `relay.ingest_coverage.quality_errors_by_endpoint.${endpoint}.unknown_events`,
    );
    const conversion = nonNegativeInteger(
      value.conversion_errors,
      `relay.ingest_coverage.quality_errors_by_endpoint.${endpoint}.conversion_errors`,
    );
    const endpointTotal = nonNegativeInteger(
      value.total,
      `relay.ingest_coverage.quality_errors_by_endpoint.${endpoint}.total`,
    );
    if (endpointTotal !== unknown + conversion) {
      fail(
        `relay.ingest_coverage.quality_errors_by_endpoint.${endpoint}.total `
        + `does not equal unknown_events + conversion_errors`,
      );
    }
    const reasons = object(
      value.reasons,
      `relay.ingest_coverage.quality_errors_by_endpoint.${endpoint}.reasons`,
    );
    let reasonTotal = 0;
    for (const [code, count] of Object.entries(reasons)) {
      if (!QUALITY_REASON_CODES.includes(code)) {
        fail(`relay.ingest_coverage.quality_errors_by_endpoint.${endpoint}.reasons contains an unsupported code`);
      }
      reasonTotal += nonNegativeInteger(
        count,
        `relay.ingest_coverage.quality_errors_by_endpoint.${endpoint}.reasons.${code}`,
      );
    }
    if (reasonTotal !== endpointTotal) {
      fail(
        `relay.ingest_coverage.quality_errors_by_endpoint.${endpoint}.reasons total `
        + `does not match endpoint total (observed=${reasonTotal}; expected=${endpointTotal})`,
      );
    }
    total += endpointTotal;
    result[endpoint] = {
      unknown_events: unknown,
      conversion_errors: conversion,
      total: endpointTotal,
      reasons: Object.fromEntries(QUALITY_REASON_CODES
        .filter(code => Object.hasOwn(reasons, code))
        .map(code => [code, reasons[code]])),
    };
  }
  if (total !== qualityErrors) {
    fail(
      'relay.ingest_coverage.quality_errors_by_endpoint total does not match '
      + `relay.ingest_coverage.quality_errors (observed=${total}; expected=${qualityErrors})`,
    );
  }
  return result;
}

function verifyRelayHealth(health, { maxQualityErrors } = {}) {
  object(health, 'relay health');
  if (health.status !== 'healthy') fail('relay status must be healthy');
  requireTrue(health.ok, 'relay.ok');
  requireTrue(health.conservation_ok, 'relay.conservation_ok');
  requireZero(nonNegativeInteger(health.pending, 'relay.pending'), 'relay.pending');
  requireZero(nonNegativeInteger(health.inflight, 'relay.inflight'), 'relay.inflight');
  requireZero(nonNegativeInteger(health.failed, 'relay.failed'), 'relay.failed');
  nonNegativeInteger(health.delivered, 'relay.delivered');

  const coverage = object(health.ingest_coverage, 'relay.ingest_coverage');
  if (coverage.quality_errors_scope !== QUALITY_ERRORS_SCOPE) {
    fail('relay.ingest_coverage.quality_errors_scope must be durable_relay_state');
  }
  nonNegativeInteger(
    coverage.quality_errors_current_process,
    'relay.ingest_coverage.quality_errors_current_process',
  );
  const qualityErrors = nonNegativeInteger(
    coverage.quality_errors ?? 0,
    'relay.ingest_coverage.quality_errors',
  );
  if (maxQualityErrors !== undefined) {
    if (!Number.isSafeInteger(maxQualityErrors) || maxQualityErrors < 0) {
      fail('max quality errors must be a non-negative integer');
    }
    if (qualityErrors > maxQualityErrors) {
      fail('relay.ingest_coverage.quality_errors exceeds the configured maximum '
        + `(observed=${qualityErrors}; maximum=${maxQualityErrors})`);
    }
  }
  const qualityBreakdown = verifyQualityBreakdown(coverage, qualityErrors);
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
  requireTrue(coverage.turn_capture_ready, 'relay.ingest_coverage.turn_capture_ready');
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
    turn_capture_ready: coverage.turn_capture_ready,
    quality_errors: qualityErrors,
    quality_errors_current_process: coverage.quality_errors_current_process,
    quality_errors_scope: coverage.quality_errors_scope,
    quality_errors_by_endpoint: qualityBreakdown,
    wire_turn_coverage: wireTurnCoverage,
    sources: REQUIRED_SOURCES.reduce((result, source) => {
      result[source] = coverage[source].source_records;
      return result;
    }, {}),
  };
}

function verifyRuntimeHealth(
  gatewayHealth,
  relayHealth,
  { expectedRevision, collectorHealth, maxQualityErrors, maxHistoricalFailedFiles } = {},
) {
  const gateway = verifyGatewayHealth(gatewayHealth, { maxHistoricalFailedFiles });
  const relay = verifyRelayHealth(relayHealth, { maxQualityErrors });
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
    blocking_reasons: [],
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
  maxQualityErrors,
  maxHistoricalFailedFiles,
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
      blocking_reasons: ['health_fetch_failed'],
      failure_kind: 'fetch_failed',
    });
    throw error;
  }
  const [gateway, relay, collector] = health;
  let result;
  try {
    result = verifyRuntimeHealth(gateway, relay, {
      expectedRevision,
      collectorHealth: collector,
      maxQualityErrors,
      maxHistoricalFailedFiles,
    });
  } catch (error) {
    writeReport(reportPath, {
      ok: false,
      ...healthObservation(gateway, relay, collector, {
        expectedRevision,
        maxQualityErrors,
        maxHistoricalFailedFiles,
      }),
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
  let maxQualityErrors;
  let maxHistoricalFailedFiles;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--gateway-url' && value) { gateway = value; index += 1; }
    else if (flag === '--relay-url' && value) { relay = value; index += 1; }
    else if (flag === '--collector-url' && value) { collector = value; index += 1; }
    else if (flag === '--timeout-ms' && value) { timeout = Number(value); index += 1; }
    else if (flag === '--expected-revision' && value) { expectedRevision = value; index += 1; }
    else if (flag === '--max-quality-errors' && value) { maxQualityErrors = Number(value); index += 1; }
    else if (flag === '--max-historical-failed-files' && value) {
      maxHistoricalFailedFiles = Number(value);
      index += 1;
    }
    else if (flag === '--report' && value) { report = value; index += 1; }
    else fail('usage: runtime-health-gate.js --gateway-url URL --relay-url URL --collector-url URL [--timeout-ms N] [--expected-revision REVISION] [--max-quality-errors N] [--max-historical-failed-files N] [--report PATH]');
  }
  if (!gateway || !relay || !collector || !Number.isSafeInteger(timeout) || timeout < 100
    || (maxQualityErrors !== undefined
      && (!Number.isSafeInteger(maxQualityErrors) || maxQualityErrors < 0))) {
    fail('usage: runtime-health-gate.js --gateway-url URL --relay-url URL --collector-url URL [--timeout-ms N] [--expected-revision REVISION] [--max-quality-errors N] [--max-historical-failed-files N] [--report PATH]');
  }
  if (maxHistoricalFailedFiles !== undefined
    && (!Number.isSafeInteger(maxHistoricalFailedFiles) || maxHistoricalFailedFiles < 0)) {
    fail('usage: runtime-health-gate.js --max-historical-failed-files N requires a non-negative integer');
  }
  return {
    gateway,
    relay,
    collector,
    timeout,
    expectedRevision,
    maxQualityErrors,
    maxHistoricalFailedFiles,
    report,
  };
}

if (require.main === module) {
  const args = parseArgs(process.argv.slice(2));
  runRemoteHealthGate(args.gateway, args.relay, args.collector, args.timeout,
    args.expectedRevision,
    args.report,
    args.maxQualityErrors,
    args.maxHistoricalFailedFiles)
    .then(result => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
    .catch(error => {
      process.stderr.write(`${error.message || String(error)}\n`);
      process.exitCode = 1;
    });
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  REQUIRED_SOURCES,
  QUALITY_REASON_CODES,
  verifyGatewayHealth,
  verifyRelayHealth,
  verifyCollectorHealth,
  verifyRuntimeHealth,
  healthObservation,
  blockingReasons,
  runRemoteHealthGate,
};
