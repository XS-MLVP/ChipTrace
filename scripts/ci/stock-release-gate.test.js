'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { spawnSync } = require('node:child_process');
const { verifyStockRejection } = require('./stock-release-gate');
const stock = require('../../integrations/codex/stock-release.json');

// Synthetic verifier input only. Fresh real collection is a separate CI step.
function report() {
  const counts = { total_records: 3, turn_assigned_records: 1, session_level_records: 0,
    process_level_records: 0, unscoped_turn_records: 1, unknown_session_records: 1, other_session_records: 0 };
  return {
    schema_version: 'chiptrace.stock-release-qualification.v1', real_upstream: false,
    production_acceptance_claimed: false, unmodified_stock: true,
    producer: { mode: 'unmodified_stock', version: stock.version, patch_set: [],
      binary_sha256: stock.linux_x64_binary_sha256,
      source: { upstream_commit: stock.upstream_commit, source_sha256: stock.source_sha256 } },
    session_id: 'synthetic-verifier-session', native_turns: 2, closed_turns: 2,
    session_epochs: 2, closed_session_epochs: 2, model_interactions: 12,
    observed_http_attempts: 12, tool_execution_records: 10, scenario_evidence_complete: true,
    delivery_ready: false, validation_status: 'not_ready',
    integrity: { artifact_valid: true, delivery_ready: true, protocol_complete: true,
      raw_bytes_complete: true, root_complete: true, runtime_complete: true },
    source_coverage: { complete: true, missing_sources: [], wire: 12, otlp_logs: 5, otlp_traces: 5, hooks: 8 },
    source_audit: { schema_version: 'chiptrace.source-context-audit.v2', session_id: 'synthetic-verifier-session',
      sources: { otlp_logs: { ...counts }, otlp_traces: { ...counts } }, unscoped_otlp_records: 2 },
    inspection_sha256: 'a'.repeat(64), audit_sha256: 'b'.repeat(64),
    raw_segments: [{ file: 'segment-00000000000000000001.sealed.ndjson', bytes: 100, sha256: 'c'.repeat(64) }],
  };
}

test('source-context diagnostic success retains collection failure and never certifies production', () => {
  const result = verifyStockRejection(report(), 1);
  assert.equal(result.collection_exit_code, 1);
  assert.equal(result.observed_source_context_rejection, true);
  assert.equal(result.production_ready, false);
  assert.equal(result.delivery_ready, false);
  assert.equal(result.real_upstream, false);
  assert.equal(result.unscoped_turn_records, 2);
  assert.equal(result.unknown_session_records, 2);
  for (const exit of [0, 2, 124, 137, null, '1']) assert.throws(() => verifyStockRejection(report(), exit));
});

test('startup, tools, identity, protocol, missing Raw and changed readiness cannot masquerade as context rejection', () => {
  const changes = [
    r => { r.native_turns = 0; }, r => { r.closed_turns = 1; },
    r => { r.closed_session_epochs = 1; }, r => { r.tool_execution_records = 0; },
    r => { r.model_interactions = 1; }, r => { r.observed_http_attempts = 11; },
    r => { r.scenario_evidence_complete = false; }, r => { r.integrity.protocol_complete = false; },
    r => { r.integrity.runtime_complete = false; }, r => { r.delivery_ready = true; },
    r => { r.source_coverage.complete = false; }, r => { r.source_coverage.hooks = 0; },
    r => { r.producer.binary_sha256 = '0'.repeat(64); }, r => { r.producer.source.upstream_commit = '0'.repeat(40); },
    r => { r.producer.source.source_sha256 = '0'.repeat(64); }, r => { r.producer.patch_set = ['patch']; },
    r => { r.unmodified_stock = false; }, r => { r.real_upstream = true; },
    r => { r.production_acceptance_claimed = true; }, r => { r.source_audit.session_id = 'other'; },
    r => { r.source_audit.sources.otlp_logs.total_records += 1; },
    r => { r.source_audit.sources.otlp_logs.turn_assigned_records = -1; },
    r => { r.source_audit.unscoped_otlp_records = 0; },
    r => { for (const c of Object.values(r.source_audit.sources)) {
      c.turn_assigned_records = c.total_records; c.unscoped_turn_records = 0; c.unknown_session_records = 0;
    } r.source_audit.unscoped_otlp_records = 0; },
    r => { r.raw_segments = []; }, r => { r.raw_segments[0].sha256 = 'invalid'; },
    r => { r.raw_segments[0].file = '../raw'; }, r => { r.raw_segments[0].bytes = 0; },
    r => { r.raw_segments.push({ ...r.raw_segments[0] }); },
  ];
  for (const change of changes) { const value = report(); change(value); assert.throws(() => verifyStockRejection(value, 1)); }
});

test('CLI refuses missing, oversized, symlink and failed reports with bounded content-free diagnostics', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-stock-gate-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, 'report.json');
  const run = (name, exit) => spawnSync(process.execPath, [path.join(__dirname, 'stock-release-gate.js'), name, String(exit)],
    { encoding: 'utf8', maxBuffer: 65536 });
  const marker = 'PRIVATE_QUALIFICATION_CONTENT';
  const value = { ...report(), unrelated: marker };
  fs.writeFileSync(file, JSON.stringify(value));
  const success = run(file, 1);
  assert.equal(success.status, 0, success.stderr);
  assert.equal(JSON.parse(success.stdout).production_ready, false);
  assert.equal(success.stdout.includes(marker), false);
  const link = path.join(root, 'link.json');
  fs.symlinkSync(file, link);
  const failures = [run(file, 124), run(link, 1), run(path.join(root, 'missing.json'), 1)];
  const before = fs.readFileSync(file);
  const stale = spawnSync('bash', [path.join(__dirname, 'qualify-stock-release.sh'), root], { encoding: 'utf8' });
  assert.equal(stale.status, 1, 'qualification runner must refuse an existing evidence directory');
  assert.equal(stale.stdout, '');
  assert.deepEqual(fs.readFileSync(file), before);
  assert.deepEqual(fs.readdirSync(root).sort(), ['link.json', 'report.json']);
  fs.writeFileSync(file, JSON.stringify({ payload: marker.repeat(2000) }));
  failures.push(run(file, 1));
  fs.writeFileSync(file, marker);
  failures.push(run(file, 1));
  for (const failure of failures) {
    assert.equal(failure.status, 1);
    assert.equal(failure.stdout, '');
    assert.ok(failure.stderr.length < 256);
    assert.equal(failure.stderr.includes(marker), false);
  }
  assert.equal(fs.readFileSync(file, 'utf8'), marker);
});
