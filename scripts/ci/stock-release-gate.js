'use strict';

// A known broken release must reproduce its context rejection in new native
// collection. This is a diagnostic regression, never a production green light.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const stock = require('../../integrations/codex/stock-release.json');
const digest = /^[a-f0-9]{64}$/;
const categories = ['turn_assigned_records', 'session_level_records', 'process_level_records',
  'unscoped_turn_records', 'unknown_session_records', 'other_session_records'];
const integer = (value, label) => assert.ok(Number.isSafeInteger(value) && value >= 0, `${label} must be a non-negative safe integer`);

function verifyStockRejection(report, collectionExit) {
  assert.equal(collectionExit, 1, 'native collection must retain its actual assertion-failure exit 1');
  assert.equal(report.schema_version, 'chiptrace.stock-release-qualification.v1');
  assert.equal(report.real_upstream, false);
  assert.equal(report.production_acceptance_claimed, false);
  assert.equal(report.unmodified_stock, true);
  assert.equal(report.producer.mode, 'unmodified_stock');
  assert.equal(report.producer.version, stock.version);
  assert.deepEqual(report.producer.patch_set, []);
  assert.equal(report.producer.binary_sha256, stock.linux_x64_binary_sha256);
  assert.equal(report.producer.source.upstream_commit, stock.upstream_commit);
  assert.equal(report.producer.source.source_sha256, stock.source_sha256);
  assert.ok(typeof report.session_id === 'string' && report.session_id.length > 0);
  assert.equal(report.native_turns, 2);
  assert.equal(report.closed_turns, 2);
  assert.equal(report.session_epochs, 2);
  assert.equal(report.closed_session_epochs, 2);
  integer(report.model_interactions, 'model_interactions');
  assert.ok(report.model_interactions >= 10, 'actual multi-tool HTTP attempts required');
  assert.equal(report.observed_http_attempts, report.model_interactions);
  integer(report.tool_execution_records, 'tool_execution_records');
  assert.ok(report.tool_execution_records >= 10, 'actual native tool results required');
  assert.equal(report.scenario_evidence_complete, true);
  for (const key of ['artifact_valid', 'delivery_ready', 'protocol_complete', 'raw_bytes_complete', 'root_complete', 'runtime_complete']) {
    assert.equal(report.integrity[key], true, `integrity.${key} must be true before classifying a source-context rejection`);
  }
  assert.equal(report.delivery_ready, false);
  assert.equal(report.validation_status, 'not_ready');
  assert.equal(report.source_coverage.complete, true);
  assert.deepEqual(report.source_coverage.missing_sources, []);
  for (const key of ['wire', 'otlp_logs', 'otlp_traces', 'hooks']) {
    integer(report.source_coverage[key], `source_coverage.${key}`);
    assert.ok(report.source_coverage[key] > 0, `missing ${key} collection`);
  }
  assert.equal(report.source_coverage.wire, report.model_interactions);
  assert.equal(report.source_audit.schema_version, 'chiptrace.source-context-audit.v2');
  assert.equal(report.source_audit.session_id, report.session_id);
  let unscoped = 0;
  let unknown = 0;
  for (const key of ['otlp_logs', 'otlp_traces']) {
    const counts = report.source_audit.sources[key];
    for (const category of ['total_records', ...categories]) integer(counts[category], `${key}.${category}`);
    assert.ok(counts.total_records > 0);
    assert.equal(counts.total_records, categories.reduce((total, category) => total + counts[category], 0), `${key} source counts must conserve`);
    unscoped += counts.unscoped_turn_records;
    unknown += counts.unknown_session_records;
  }
  assert.equal(report.source_audit.unscoped_otlp_records, unscoped);
  integer(report.source_audit.unscoped_otlp_records, 'source_audit.unscoped_otlp_records');
  integer(unknown, 'unknown_session_records');
  assert.ok(unscoped + unknown > 0, 'actual unresolved source records required');
  assert.match(report.inspection_sha256, digest);
  assert.match(report.audit_sha256, digest);
  assert.ok(Array.isArray(report.raw_segments) && report.raw_segments.length > 0, 'sealed Raw evidence required');
  const files = new Set();
  for (const segment of report.raw_segments) {
    assert.match(segment.file, /^segment-[0-9]+\.sealed\.ndjson$/);
    assert.ok(!files.has(segment.file), 'duplicate sealed Segment');
    files.add(segment.file);
    integer(segment.bytes, 'segment.bytes');
    assert.ok(segment.bytes > 0);
    assert.match(segment.sha256, digest);
  }
  return { schema_version: 'chiptrace.stock-release-gate.v1',
    observed_source_context_rejection: true, collection_exit_code: collectionExit,
    client_version: stock.version, producer_binary_sha256: report.producer.binary_sha256,
    real_upstream: false, unmodified_stock: true, production_ready: false,
    production_acceptance_claimed: false, delivery_ready: false,
    native_turns: report.native_turns, model_interactions: report.model_interactions,
    unscoped_turn_records: unscoped, unknown_session_records: unknown };
}

function main(args) {
  assert.ok(args.length === 2 && /^[0-9]+$/.test(args[1]), 'usage: stock-release-gate.js <report.json> <actual-collection-exit>');
  const fd = fs.openSync(args[0], fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    assert.ok(stat.isFile() && stat.size > 0 && stat.size <= 16384, 'qualification metadata must be a regular file of at most 16 KiB');
    const bytes = Buffer.alloc(16385);
    let length = 0;
    while (length < bytes.length) {
      const read = fs.readSync(fd, bytes, length, bytes.length - length, null);
      if (read === 0) break;
      length += read;
    }
    assert.ok(length === stat.size && length <= 16384, 'qualification metadata changed size or exceeds 16 KiB');
    const report = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)));
    console.log(JSON.stringify(verifyStockRejection(report, Number(args[1])), null, 2));
  } finally { fs.closeSync(fd); }
}

if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch { console.error('stock release gate: expected new native source-context rejection evidence was not verified'); process.exitCode = 1; }
}
module.exports = { verifyStockRejection };
