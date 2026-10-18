'use strict';

const fs = require('node:fs');
const {
  QUALITY_REASON_CODES,
  compareQualityBaseline,
  readQualityBaseline,
} = require('./quality-baseline');

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_TRANSIENT_RETRIES = 0;
const DEFAULT_TRANSIENT_RETRY_DELAY_MS = 250;
const REQUIRED_SOURCES = ['wire', 'otlp_logs', 'otlp_traces', 'hooks'];
const QUALITY_ENDPOINTS = ['otlp_logs', 'otlp_traces', 'hooks'];
const QUALITY_ERRORS_SCOPE = 'durable_relay_state';
const REVISION_PATTERN = /^[a-f0-9]{40}$/;
const TRANSIENT_BLOCKING_REASONS = new Set([
  'gateway_pending_records',
  'gateway_inflight_records',
  'relay_pending_records',
  'relay_inflight_records',
  'collector_queue_not_empty',
]);

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

function routeObservation(route, qualityErrors) {
  if (!route || typeof route !== 'object' || Array.isArray(route)) return null;
  const quality = qualityErrorObservation(qualityErrors) || qualityErrorObservation(route.quality);
  return {
    requests: safeInteger(route.requests),
    source_records: safeInteger(route.source_records),
    durable_captures: safeInteger(route.durable_captures),
    duplicates: safeInteger(route.duplicates),
    quality: {
      unknown_events: quality?.unknown_events ?? null,
      conversion_errors: quality?.conversion_errors ?? null,
      total: quality?.total ?? null,
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

function hasCompleteQualityBreakdown(coverage, qualityErrors) {
  if (!Number.isSafeInteger(qualityErrors) || qualityErrors < 0) return false;
  const breakdown = coverage?.quality_errors_by_endpoint;
  if (!breakdown || typeof breakdown !== 'object' || Array.isArray(breakdown)) return false;
  let total = 0;
  for (const endpoint of QUALITY_ENDPOINTS) {
    const value = breakdown[endpoint];
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const unknown = value.unknown_events;
    const conversion = value.conversion_errors;
    const endpointTotal = value.total;
    if (![unknown, conversion, endpointTotal].every(number => (
      Number.isSafeInteger(number) && number >= 0
    ))) return false;
    if (unknown > Number.MAX_SAFE_INTEGER - conversion || endpointTotal !== unknown + conversion) {
      return false;
    }
    const reasons = value.reasons;
    if (!reasons || typeof reasons !== 'object' || Array.isArray(reasons)) return false;
    let reasonTotal = 0;
    for (const [code, count] of Object.entries(reasons)) {
      if (!QUALITY_REASON_CODES.includes(code)
        || !Number.isSafeInteger(count) || count < 0
        || reasonTotal > Number.MAX_SAFE_INTEGER - count) {
        return false;
      }
      reasonTotal += count;
    }
    if (reasonTotal !== endpointTotal || total > Number.MAX_SAFE_INTEGER - endpointTotal) {
      return false;
    }
    total += endpointTotal;
  }
  return total === qualityErrors;
}

function blockingReasons(
  observation,
  {
    expectedRevision,
    maxQualityErrors,
    maxNewQualityErrors,
    qualityBaseline,
    maxHistoricalFailedFiles,
    minGatewayFreeBytes,
    minGatewayFreeFiles,
  } = {},
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
  if (minGatewayFreeBytes !== undefined
    && (!Number.isSafeInteger(gateway.filesystem_free_bytes)
      || gateway.filesystem_free_bytes < minGatewayFreeBytes)) {
    add('gateway_free_bytes_below_minimum');
  }
  if (minGatewayFreeFiles !== undefined
    && (!Number.isSafeInteger(gateway.filesystem_free_files)
      || gateway.filesystem_free_files < minGatewayFreeFiles)) {
    add('gateway_free_files_below_minimum');
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
  if (qualityBaseline && coverage.quality_baseline?.invalid === true) {
    add('relay_quality_baseline_invalid');
  }
  if (maxNewQualityErrors !== undefined
    && Number.isSafeInteger(coverage.quality_baseline?.new_quality_errors)
    && coverage.quality_baseline.new_quality_errors > maxNewQualityErrors) {
    add('relay_new_quality_errors_exceed_max');
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

function onlyTransientBlockingReasons(reasons) {
  return reasons.length > 0 && reasons.every(reason => TRANSIENT_BLOCKING_REASONS.has(reason));
}

function healthObservation(
  gateway,
  relay,
  collector,
  {
    expectedRevision,
    maxQualityErrors,
    maxNewQualityErrors,
    qualityBaseline,
    maxHistoricalFailedFiles,
    minGatewayFreeBytes,
    minGatewayFreeFiles,
  } = {},
) {
  const capture = gateway?.fullTraceCapture;
  const gatewayRelay = capture?.rustRelay;
  const coverage = relay?.ingest_coverage;
  const turnCoverage = coverage?.wire_turn_coverage;
  const collectorStore = collector?.collector;
  let qualityBaselineObservation = null;
  if (qualityBaseline) {
    try {
      qualityBaselineObservation = compareQualityBaseline(coverage, qualityBaseline);
    } catch {
      qualityBaselineObservation = {
        baseline_id: qualityBaseline.baseline_id || null,
        invalid: true,
      };
    }
  }
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
      filesystem_free_bytes: safeInteger(capture?.outbox?.filesystemFreeBytes),
      filesystem_free_files: safeInteger(capture?.outbox?.filesystemFreeFiles),
    },
    relay: {
      status: typeof relay?.status === 'string' ? relay.status : null,
      revision: safeTimestamp(relay?.build?.revision),
      delivered: safeInteger(relay?.delivered),
      pending: safeInteger(relay?.pending),
      inflight: safeInteger(relay?.inflight),
      failed: safeInteger(relay?.failed),
      delivery_attempts: safeInteger(relay?.delivery_attempts),
      delivery_retries: safeInteger(relay?.delivery_retries),
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
        otlp_logs: routeObservation(
          coverage?.otlp_logs,
          coverage?.quality_errors_by_endpoint?.otlp_logs,
        ),
        otlp_traces: routeObservation(
          coverage?.otlp_traces,
          coverage?.quality_errors_by_endpoint?.otlp_traces,
        ),
        hooks: routeObservation(coverage?.hooks, coverage?.quality_errors_by_endpoint?.hooks),
        quality_errors: safeInteger(coverage?.quality_errors),
        quality_errors_current_process: safeInteger(coverage?.quality_errors_current_process),
        quality_errors_scope: typeof coverage?.quality_errors_scope === 'string'
          ? coverage.quality_errors_scope : null,
        quality_errors_by_endpoint: {
          otlp_logs: qualityErrorObservation(coverage?.quality_errors_by_endpoint?.otlp_logs),
          otlp_traces: qualityErrorObservation(coverage?.quality_errors_by_endpoint?.otlp_traces),
          hooks: qualityErrorObservation(coverage?.quality_errors_by_endpoint?.hooks),
        },
        quality_reason_breakdown_complete: hasCompleteQualityBreakdown(
          coverage,
          safeInteger(coverage?.quality_errors),
        ),
        quality_baseline: qualityBaselineObservation,
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
    maxNewQualityErrors,
    qualityBaseline,
    maxHistoricalFailedFiles,
    minGatewayFreeBytes,
    minGatewayFreeFiles,
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

function verifyGatewayHealth(
  health,
  { maxHistoricalFailedFiles, minGatewayFreeBytes, minGatewayFreeFiles } = {},
) {
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
  const filesystemFreeBytes = outbox.filesystemFreeBytes === undefined
    ? null
    : nonNegativeInteger(outbox.filesystemFreeBytes, 'gateway outbox.filesystemFreeBytes');
  const filesystemFreeFiles = outbox.filesystemFreeFiles === undefined
    ? null
    : nonNegativeInteger(outbox.filesystemFreeFiles, 'gateway outbox.filesystemFreeFiles');
  if (maxHistoricalFailedFiles !== undefined) {
    if (!Number.isSafeInteger(maxHistoricalFailedFiles) || maxHistoricalFailedFiles < 0) {
      fail('max historical failed files must be a non-negative integer');
    }
    if (unresolvedHistoricalFailedFiles > maxHistoricalFailedFiles) {
      fail('gateway outbox unresolved historical failed files exceed the configured maximum '
        + `(observed=${unresolvedHistoricalFailedFiles}; maximum=${maxHistoricalFailedFiles})`);
    }
  }
  if (minGatewayFreeBytes !== undefined) {
    if (!Number.isSafeInteger(minGatewayFreeBytes) || minGatewayFreeBytes < 0) {
      fail('minimum gateway free bytes must be a non-negative integer');
    }
    if (filesystemFreeBytes === null || filesystemFreeBytes < minGatewayFreeBytes) {
      fail('gateway outbox filesystem free bytes are below the configured minimum '
        + `(observed=${filesystemFreeBytes ?? 'unreported'}; minimum=${minGatewayFreeBytes})`);
    }
  }
  if (minGatewayFreeFiles !== undefined) {
    if (!Number.isSafeInteger(minGatewayFreeFiles) || minGatewayFreeFiles < 0) {
      fail('minimum gateway free files must be a non-negative integer');
    }
    if (filesystemFreeFiles === null || filesystemFreeFiles < minGatewayFreeFiles) {
      fail('gateway outbox filesystem free files are below the configured minimum '
        + `(observed=${filesystemFreeFiles ?? 'unreported'}; minimum=${minGatewayFreeFiles})`);
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
    filesystem_free_bytes: filesystemFreeBytes,
    filesystem_free_files: filesystemFreeFiles,
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

function verifyRelayHealth(
  health,
  { maxQualityErrors, maxNewQualityErrors, qualityBaseline } = {},
) {
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
  requireTrue(
    coverage.quality_reason_breakdown_complete,
    'relay.ingest_coverage.quality_reason_breakdown_complete',
  );
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
  let qualityBaselineObservation = null;
  if (maxNewQualityErrors !== undefined && !qualityBaseline) {
    fail('max new quality errors requires an approved quality baseline');
  }
  if (qualityBaseline) {
    qualityBaselineObservation = compareQualityBaseline(coverage, qualityBaseline);
  }
  if (maxNewQualityErrors !== undefined) {
    if (!Number.isSafeInteger(maxNewQualityErrors) || maxNewQualityErrors < 0) {
      fail('max new quality errors must be a non-negative integer');
    }
    if (qualityBaselineObservation.new_quality_errors > maxNewQualityErrors) {
      fail('new quality errors exceed the configured maximum '
        + `(observed=${qualityBaselineObservation.new_quality_errors}; maximum=${maxNewQualityErrors})`);
    }
  }
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
    delivery_attempts: safeInteger(health.delivery_attempts),
    delivery_retries: safeInteger(health.delivery_retries),
    conservation_ok: health.conservation_ok,
    coverage_status: coverage.status,
    freshness_applicable: coverage.freshness_applicable,
    required_sources_fresh: coverage.required_sources_fresh,
    turn_capture_ready: coverage.turn_capture_ready,
    quality_errors: qualityErrors,
    quality_errors_current_process: coverage.quality_errors_current_process,
    quality_errors_scope: coverage.quality_errors_scope,
    quality_errors_by_endpoint: qualityBreakdown,
    quality_baseline: qualityBaselineObservation,
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
  {
    expectedRevision,
    collectorHealth,
    maxQualityErrors,
    maxNewQualityErrors,
    qualityBaseline,
    maxHistoricalFailedFiles,
    minGatewayFreeBytes,
    minGatewayFreeFiles,
  } = {},
) {
  const gateway = verifyGatewayHealth(gatewayHealth, {
    maxHistoricalFailedFiles,
    minGatewayFreeBytes,
    minGatewayFreeFiles,
  });
  const relay = verifyRelayHealth(relayHealth, {
    maxQualityErrors,
    maxNewQualityErrors,
    qualityBaseline,
  });
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
  minGatewayFreeBytes,
  minGatewayFreeFiles,
  transientRetries = DEFAULT_TRANSIENT_RETRIES,
  transientRetryDelayMs = DEFAULT_TRANSIENT_RETRY_DELAY_MS,
  qualityBaseline,
  maxNewQualityErrors,
) {
  if (!gatewayUrl || !relayUrl || !collectorUrl) fail('gateway, relay and collector health URLs are required');
  if (!Number.isSafeInteger(transientRetries) || transientRetries < 0) {
    fail('transient retries must be a non-negative integer');
  }
  if (!Number.isSafeInteger(transientRetryDelayMs) || transientRetryDelayMs < 0) {
    fail('transient retry delay must be a non-negative integer');
  }

  for (let attempt = 0; ; attempt += 1) {
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
        maxNewQualityErrors,
        qualityBaseline,
        maxHistoricalFailedFiles,
        minGatewayFreeBytes,
        minGatewayFreeFiles,
      });
    } catch (error) {
      const observed = healthObservation(gateway, relay, collector, {
        expectedRevision,
        maxQualityErrors,
        maxNewQualityErrors,
        qualityBaseline,
        maxHistoricalFailedFiles,
        minGatewayFreeBytes,
        minGatewayFreeFiles,
      });
      const reasons = observed.blocking_reasons;
      if (attempt < transientRetries && onlyTransientBlockingReasons(reasons)) {
        if (transientRetryDelayMs > 0) {
          await new Promise(resolve => setTimeout(resolve, transientRetryDelayMs));
        }
        continue;
      }
      writeReport(reportPath, {
        ok: false,
        ...observed,
        failure_kind: 'validation_failed',
      });
      const reasonText = reasons.join(',');
      if (reasonText) {
        throw new Error(`${error.message}; blocking_reasons=${reasonText}`);
      }
      throw error;
    }
    writeReport(reportPath, { ok: true, ...result });
    return result;
  }
}

function parseArgs(argv) {
  let gateway;
  let relay;
  let collector;
  let timeout = DEFAULT_TIMEOUT_MS;
  let expectedRevision;
  let report;
  let maxQualityErrors;
  let maxNewQualityErrors;
  let qualityBaselinePath;
  let maxHistoricalFailedFiles;
  let minGatewayFreeBytes;
  let minGatewayFreeFiles;
  let transientRetries = DEFAULT_TRANSIENT_RETRIES;
  let transientRetryDelayMs = DEFAULT_TRANSIENT_RETRY_DELAY_MS;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--gateway-url' && value) { gateway = value; index += 1; }
    else if (flag === '--relay-url' && value) { relay = value; index += 1; }
    else if (flag === '--collector-url' && value) { collector = value; index += 1; }
    else if (flag === '--timeout-ms' && value) { timeout = Number(value); index += 1; }
    else if (flag === '--expected-revision' && value) { expectedRevision = value; index += 1; }
    else if (flag === '--max-quality-errors' && value) { maxQualityErrors = Number(value); index += 1; }
    else if (flag === '--max-new-quality-errors' && value) {
      maxNewQualityErrors = Number(value);
      index += 1;
    }
    else if (flag === '--quality-baseline' && value) {
      qualityBaselinePath = value;
      index += 1;
    }
    else if (flag === '--max-historical-failed-files' && value) {
      maxHistoricalFailedFiles = Number(value);
      index += 1;
    }
    else if (flag === '--min-gateway-free-bytes' && value) {
      minGatewayFreeBytes = Number(value);
      index += 1;
    }
    else if (flag === '--min-gateway-free-files' && value) {
      minGatewayFreeFiles = Number(value);
      index += 1;
    }
    else if (flag === '--transient-retries' && value) {
      transientRetries = Number(value);
      index += 1;
    }
    else if (flag === '--transient-retry-delay-ms' && value) {
      transientRetryDelayMs = Number(value);
      index += 1;
    }
    else if (flag === '--report' && value) { report = value; index += 1; }
    else fail('usage: runtime-health-gate.js --gateway-url URL --relay-url URL --collector-url URL [--timeout-ms N] [--expected-revision REVISION] [--max-quality-errors N] [--quality-baseline PATH --max-new-quality-errors N] [--max-historical-failed-files N] [--min-gateway-free-bytes N] [--min-gateway-free-files N] [--transient-retries N] [--transient-retry-delay-ms N] [--report PATH]');
  }
  if (!gateway || !relay || !collector || !Number.isSafeInteger(timeout) || timeout < 100
    || (maxQualityErrors !== undefined
      && (!Number.isSafeInteger(maxQualityErrors) || maxQualityErrors < 0))
    || (maxNewQualityErrors !== undefined
      && (!Number.isSafeInteger(maxNewQualityErrors) || maxNewQualityErrors < 0))
    || (minGatewayFreeBytes !== undefined
      && (!Number.isSafeInteger(minGatewayFreeBytes) || minGatewayFreeBytes < 0))
    || (minGatewayFreeFiles !== undefined
      && (!Number.isSafeInteger(minGatewayFreeFiles) || minGatewayFreeFiles < 0))
    || !Number.isSafeInteger(transientRetries) || transientRetries < 0
    || !Number.isSafeInteger(transientRetryDelayMs) || transientRetryDelayMs < 0) {
    fail('usage: runtime-health-gate.js --gateway-url URL --relay-url URL --collector-url URL [--timeout-ms N] [--expected-revision REVISION] [--max-quality-errors N] [--quality-baseline PATH --max-new-quality-errors N] [--max-historical-failed-files N] [--min-gateway-free-bytes N] [--min-gateway-free-files N] [--transient-retries N] [--transient-retry-delay-ms N] [--report PATH]');
  }
  if (maxHistoricalFailedFiles !== undefined
    && (!Number.isSafeInteger(maxHistoricalFailedFiles) || maxHistoricalFailedFiles < 0)) {
    fail('usage: runtime-health-gate.js --max-historical-failed-files N requires a non-negative integer');
  }
  if (maxNewQualityErrors !== undefined && !qualityBaselinePath) {
    fail('usage: --max-new-quality-errors N requires --quality-baseline PATH');
  }
  if (qualityBaselinePath && maxNewQualityErrors === undefined) {
    fail('usage: --quality-baseline PATH requires --max-new-quality-errors N');
  }
  const qualityBaseline = qualityBaselinePath ? readQualityBaseline(qualityBaselinePath) : undefined;
  return {
    gateway,
    relay,
    collector,
    timeout,
    expectedRevision,
    maxQualityErrors,
    maxNewQualityErrors,
    qualityBaseline,
    maxHistoricalFailedFiles,
    minGatewayFreeBytes,
    minGatewayFreeFiles,
    transientRetries,
    transientRetryDelayMs,
    report,
  };
}

if (require.main === module) {
  const args = parseArgs(process.argv.slice(2));
  runRemoteHealthGate(args.gateway, args.relay, args.collector, args.timeout,
    args.expectedRevision,
    args.report,
    args.maxQualityErrors,
    args.maxHistoricalFailedFiles,
    args.minGatewayFreeBytes,
    args.minGatewayFreeFiles,
    args.transientRetries,
    args.transientRetryDelayMs,
    args.qualityBaseline,
    args.maxNewQualityErrors)
    .then(result => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
    .catch(error => {
      process.stderr.write(`${error.message || String(error)}\n`);
      process.exitCode = 1;
    });
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  DEFAULT_TRANSIENT_RETRIES,
  DEFAULT_TRANSIENT_RETRY_DELAY_MS,
  REQUIRED_SOURCES,
  QUALITY_REASON_CODES,
  verifyGatewayHealth,
  verifyRelayHealth,
  verifyCollectorHealth,
  verifyRuntimeHealth,
  healthObservation,
  blockingReasons,
  onlyTransientBlockingReasons,
  runRemoteHealthGate,
};
