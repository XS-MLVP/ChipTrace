'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

const BASELINE_SCHEMA_VERSION = 'chiptrace.quality-baseline.v1';
const MAX_BASELINE_BYTES = 64 * 1024;
const ENDPOINTS = ['otlp_logs', 'otlp_traces', 'hooks'];
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
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

function fail(message) {
  throw new Error(`quality baseline: ${message}`);
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

function nonEmptyString(value, label, maxLength = 1024) {
  if (typeof value !== 'string' || value.trim() === '' || value.length > maxLength) {
    fail(`${label} must be a non-empty string of at most ${maxLength} characters`);
  }
  return value;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sourceCoverage(report) {
  const value = object(report, 'report');
  if (value.relay?.coverage) return object(value.relay.coverage, 'report.relay.coverage');
  if (value.ingest_coverage) return object(value.ingest_coverage, 'report.ingest_coverage');
  fail('report must contain relay.coverage or ingest_coverage');
}

function normalizeQualitySnapshot(coverage, label = 'coverage') {
  const value = object(coverage, label);
  if (value.quality_errors_scope !== 'durable_relay_state') {
    fail(`${label}.quality_errors_scope must be durable_relay_state`);
  }
  if (value.quality_reason_breakdown_complete !== true) {
    fail(`${label}.quality_reason_breakdown_complete must be true`);
  }
  const qualityErrors = nonNegativeInteger(value.quality_errors, `${label}.quality_errors`);
  const breakdown = object(value.quality_errors_by_endpoint, `${label}.quality_errors_by_endpoint`);
  let total = 0;
  const normalized = {};
  for (const endpoint of ENDPOINTS) {
    const route = object(breakdown[endpoint], `${label}.quality_errors_by_endpoint.${endpoint}`);
    const unknown = nonNegativeInteger(route.unknown_events, `${endpoint}.unknown_events`);
    const conversion = nonNegativeInteger(route.conversion_errors, `${endpoint}.conversion_errors`);
    if (unknown > Number.MAX_SAFE_INTEGER - conversion) {
      fail(`${endpoint}.unknown_events + conversion_errors exceeds the safe integer limit`);
    }
    const endpointTotal = nonNegativeInteger(route.total, `${endpoint}.total`);
    if (endpointTotal !== unknown + conversion) {
      fail(`${endpoint}.total must equal unknown_events + conversion_errors`);
    }
    const reasons = object(route.reasons, `${endpoint}.reasons`);
    let reasonTotal = 0;
    const normalizedReasons = {};
    for (const [reason, countValue] of Object.entries(reasons)) {
      if (!QUALITY_REASON_CODES.includes(reason)) {
        fail(`${endpoint}.reasons contains an unsupported code`);
      }
      const count = nonNegativeInteger(countValue, `${endpoint}.reasons.${reason}`);
      if (reasonTotal > Number.MAX_SAFE_INTEGER - count) {
        fail(`${endpoint}.reasons exceeds the safe integer limit`);
      }
      reasonTotal += count;
      if (count > 0) normalizedReasons[reason] = count;
    }
    if (reasonTotal !== endpointTotal) {
      fail(`${endpoint}.reasons total must equal endpoint total`);
    }
    if (total > Number.MAX_SAFE_INTEGER - endpointTotal) {
      fail(`${label}.quality_errors_by_endpoint exceeds the safe integer limit`);
    }
    total += endpointTotal;
    normalized[endpoint] = {
      unknown_events: unknown,
      conversion_errors: conversion,
      total: endpointTotal,
      reasons: normalizedReasons,
    };
  }
  if (total !== qualityErrors) {
    fail(`${label}.quality_errors does not equal endpoint totals`);
  }
  return {
    quality_errors_scope: 'durable_relay_state',
    quality_errors: qualityErrors,
    quality_reason_breakdown_complete: true,
    quality_errors_by_endpoint: normalized,
  };
}

// An operator quality archive moves historical counts out of the live ledger
// without deleting them. Comparison must stay monotonic across that boundary,
// so the effective total is live + archived per endpoint and per reason. A
// payload without archive fields is treated as archived = 0.
function combineArchivedQuality(coverage) {
  const live = normalizeQualitySnapshot(coverage);
  const archived = coverage.quality_errors_archived_by_endpoint;
  if (archived === undefined || archived === null) return live;
  const archivedSnapshot = normalizeQualitySnapshot(
    {
      quality_errors_scope: 'durable_relay_state',
      quality_reason_breakdown_complete: true,
      quality_errors: Object.values(archived).reduce(
        (sum, route) => sum + nonNegativeInteger(route?.total, 'archived.total'),
        0,
      ),
      quality_errors_by_endpoint: archived,
    },
    'coverage.quality_errors_archived_by_endpoint',
  );
  const combined = {
    quality_errors_scope: 'durable_relay_state',
    quality_errors: 0,
    quality_reason_breakdown_complete: true,
    quality_errors_by_endpoint: {},
  };
  for (const endpoint of ENDPOINTS) {
    const liveRoute = live.quality_errors_by_endpoint[endpoint];
    const archivedRoute = archivedSnapshot.quality_errors_by_endpoint[endpoint];
    const reasons = {};
    for (const reason of new Set([
      ...Object.keys(liveRoute.reasons),
      ...Object.keys(archivedRoute.reasons),
    ])) {
      reasons[reason] = (liveRoute.reasons[reason] || 0) + (archivedRoute.reasons[reason] || 0);
    }
    const unknownEvents = liveRoute.unknown_events + archivedRoute.unknown_events;
    const conversionErrors = liveRoute.conversion_errors + archivedRoute.conversion_errors;
    combined.quality_errors_by_endpoint[endpoint] = {
      unknown_events: unknownEvents,
      conversion_errors: conversionErrors,
      total: unknownEvents + conversionErrors,
      reasons,
    };
    combined.quality_errors += unknownEvents + conversionErrors;
  }
  return combined;
}

function validateApproval(approvedBy, approvedAt, approvalNote) {
  nonEmptyString(approvedBy, 'approved_by', 256);
  nonEmptyString(approvedAt, 'approved_at', 128);
  if (!Number.isFinite(Date.parse(approvedAt))) fail('approved_at must be an ISO timestamp');
  nonEmptyString(approvalNote, 'approval_note', 2048);
}

function baselineCore(value) {
  const baseline = object(value, 'baseline');
  const snapshot = normalizeQualitySnapshot(baseline, 'baseline');
  validateApproval(baseline.approved_by, baseline.approved_at, baseline.approval_note);
  if (typeof baseline.source_report_sha256 !== 'string'
    || !SHA256_PATTERN.test(baseline.source_report_sha256)) {
    fail('source_report_sha256 must be a lowercase SHA-256');
  }
  const core = {
    schema_version: BASELINE_SCHEMA_VERSION,
    approved_by: baseline.approved_by,
    approved_at: baseline.approved_at,
    approval_note: baseline.approval_note,
    source_report_sha256: baseline.source_report_sha256,
    ...snapshot,
  };
  return { core, snapshot };
}

function verifyQualityBaseline(value) {
  const baseline = object(value, 'baseline');
  if (baseline.schema_version !== BASELINE_SCHEMA_VERSION) {
    fail(`unsupported schema_version: ${baseline.schema_version}`);
  }
  const { core, snapshot } = baselineCore(baseline);
  if (typeof baseline.baseline_id !== 'string' || !SHA256_PATTERN.test(baseline.baseline_id)) {
    fail('baseline_id must be a lowercase SHA-256');
  }
  if (sha256Hex(canonicalJson(core)) !== baseline.baseline_id) {
    fail('baseline_id does not match the content');
  }
  const allowed = new Set([...Object.keys(core), 'baseline_id']);
  for (const key of Object.keys(baseline)) {
    if (!allowed.has(key)) fail(`unknown field: ${key}`);
  }
  return {
    schema_version: BASELINE_SCHEMA_VERSION,
    ...snapshot,
    baseline_id: baseline.baseline_id,
    approved_by: baseline.approved_by,
    approved_at: baseline.approved_at,
    approval_note: baseline.approval_note,
    source_report_sha256: baseline.source_report_sha256,
  };
}

function buildBaseline(report, { sourceReportSha256, approvedBy, approvedAt, approvalNote } = {}) {
  const coverage = sourceCoverage(report);
  const snapshot = normalizeQualitySnapshot(coverage, 'report.ingest_coverage');
  if (typeof sourceReportSha256 !== 'string' || !SHA256_PATTERN.test(sourceReportSha256)) {
    fail('source_report_sha256 must be a lowercase SHA-256');
  }
  validateApproval(approvedBy, approvedAt, approvalNote);
  const core = {
    schema_version: BASELINE_SCHEMA_VERSION,
    approved_by: approvedBy,
    approved_at: approvedAt,
    approval_note: approvalNote,
    source_report_sha256: sourceReportSha256,
    ...snapshot,
  };
  return { ...core, baseline_id: sha256Hex(canonicalJson(core)) };
}

function compareQualityBaseline(coverage, baselineValue) {
  const current = combineArchivedQuality(object(coverage, 'coverage'));
  const baseline = verifyQualityBaseline(baselineValue);
  let newQualityErrors = 0;
  for (const endpoint of ENDPOINTS) {
    const currentRoute = current.quality_errors_by_endpoint[endpoint];
    const baselineRoute = baseline.quality_errors_by_endpoint[endpoint];
    for (const field of ['unknown_events', 'conversion_errors', 'total']) {
      if (currentRoute[field] < baselineRoute[field]) {
        fail(`quality counter regressed for ${endpoint}.${field}`);
      }
    }
    const reasons = new Set([
      ...Object.keys(currentRoute.reasons),
      ...Object.keys(baselineRoute.reasons),
    ]);
    for (const reason of reasons) {
      const currentCount = currentRoute.reasons[reason] || 0;
      const baselineCount = baselineRoute.reasons[reason] || 0;
      if (currentCount < baselineCount) {
        fail(`quality reason counter regressed for ${endpoint}.${reason}`);
      }
      const increment = currentCount - baselineCount;
      if (newQualityErrors > Number.MAX_SAFE_INTEGER - increment) {
        fail('new quality error count exceeds the safe integer limit');
      }
      newQualityErrors += increment;
    }
  }
  if (current.quality_errors < baseline.quality_errors) {
    fail('quality_errors regressed below the approved baseline');
  }
  const liveQualityErrors = safeLiveTotal(coverage);
  return {
    baseline_id: baseline.baseline_id,
    approved_by: baseline.approved_by,
    approved_at: baseline.approved_at,
    source_report_sha256: baseline.source_report_sha256,
    baseline_quality_errors: baseline.quality_errors,
    // Effective total: live ledger plus any operator archive. This is the
    // number that must never regress; the live-only total legitimately drops
    // to zero when a historical archive is approved.
    current_quality_errors: current.quality_errors,
    current_live_quality_errors: liveQualityErrors,
    archived_quality_errors: current.quality_errors - liveQualityErrors,
    new_quality_errors: newQualityErrors,
  };
}

function safeLiveTotal(coverage) {
  const value = coverage?.quality_errors;
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function readJson(inputPath, label = 'input') {
  let metadata;
  try {
    metadata = fs.lstatSync(inputPath);
  } catch (error) {
    fail(`cannot stat ${label}: ${error.message}`);
  }
  if (!metadata.isFile()) fail(`${label} must be a regular file`);
  if (metadata.size > MAX_BASELINE_BYTES) fail(`${label} exceeds ${MAX_BASELINE_BYTES} bytes`);
  try {
    return JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}

function readQualityBaseline(inputPath) {
  return verifyQualityBaseline(readJson(inputPath, 'baseline'));
}

function readInputBytes(inputPath) {
  let metadata;
  try {
    metadata = fs.lstatSync(inputPath);
  } catch (error) {
    fail(`cannot stat input: ${error.message}`);
  }
  if (!metadata.isFile()) fail('input must be a regular file');
  if (metadata.size > MAX_BASELINE_BYTES) fail(`input exceeds ${MAX_BASELINE_BYTES} bytes`);
  try {
    return fs.readFileSync(inputPath);
  } catch (error) {
    fail(`cannot read input: ${error.message}`);
  }
}

function writeBaseline(outputPath, baseline) {
  const verified = verifyQualityBaseline(baseline);
  const value = {
    schema_version: BASELINE_SCHEMA_VERSION,
    approved_by: verified.approved_by,
    approved_at: verified.approved_at,
    approval_note: verified.approval_note,
    source_report_sha256: verified.source_report_sha256,
    quality_errors_scope: verified.quality_errors_scope,
    quality_errors: verified.quality_errors,
    quality_reason_breakdown_complete: verified.quality_reason_breakdown_complete,
    quality_errors_by_endpoint: verified.quality_errors_by_endpoint,
    baseline_id: verified.baseline_id,
  };
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  try {
    fs.writeFileSync(outputPath, bytes, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  } catch (error) {
    fail(`cannot create output: ${error.message}`);
  }
  return { path: outputPath, bytes: bytes.length, baseline_id: verified.baseline_id };
}

function parseArgs(argv) {
  let input;
  let output;
  let approvedBy;
  let approvedAt;
  let approvalNote;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--input' && value) { input = value; index += 1; }
    else if (flag === '--output' && value) { output = value; index += 1; }
    else if (flag === '--approved-by' && value) { approvedBy = value; index += 1; }
    else if (flag === '--approved-at' && value) { approvedAt = value; index += 1; }
    else if (flag === '--approval-note' && value) { approvalNote = value; index += 1; }
    else fail('usage: quality-baseline.js --input REPORT.json --output BASELINE.json --approved-by NAME --approved-at ISO --approval-note NOTE');
  }
  if (!input || !output || !approvedBy || !approvedAt || !approvalNote) {
    fail('usage: quality-baseline.js --input REPORT.json --output BASELINE.json --approved-by NAME --approved-at ISO --approval-note NOTE');
  }
  return { input, output, approvedBy, approvedAt, approvalNote };
}

if (require.main === module) {
  try {
    const args = parseArgs(process.argv.slice(2));
    const inputBytes = readInputBytes(args.input);
    let report;
    try {
      report = JSON.parse(inputBytes.toString('utf8'));
    } catch (error) {
      fail(`input is not valid JSON: ${error.message}`);
    }
    const baseline = buildBaseline(report, {
      sourceReportSha256: sha256Hex(inputBytes),
      approvedBy: args.approvedBy,
      approvedAt: args.approvedAt,
      approvalNote: args.approvalNote,
    });
    process.stdout.write(`${JSON.stringify(writeBaseline(args.output, baseline), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  BASELINE_SCHEMA_VERSION,
  MAX_BASELINE_BYTES,
  ENDPOINTS,
  QUALITY_REASON_CODES,
  canonicalJson,
  sha256Hex,
  buildBaseline,
  compareQualityBaseline,
  normalizeQualitySnapshot,
  verifyQualityBaseline,
  readQualityBaseline,
  readInputBytes,
  writeBaseline,
  parseArgs,
};
