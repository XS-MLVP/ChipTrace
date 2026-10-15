'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { verifyNativeCanaryReport } = require('./native-canary-gate');

const fixtureRoot = path.resolve(__dirname, '../../fixtures');

function read(name) {
  return JSON.parse(fs.readFileSync(path.join(fixtureRoot, name), 'utf8'));
}

test('redacted real multi-turn evidence remains rejected while unknown Session records exist', () => {
  const report = read('native-canary-multiturn-0163-report.json');
  const audit = read('native-canary-multiturn-0163-audit.json');
  assert.equal(report.real_upstream, true);
  assert.equal(report.provenance.producer_mode, 'patched_stock');
  assert.equal(report.provenance.patch_set.length, 5);
  assert.equal(report.session_view.native_turns, 2);
  assert.equal(audit.sources.otlp_logs.unknown_session_records, 2);
  assert.equal(audit.sources.otlp_traces.unknown_session_records, 84);
  assert.throws(
    () => verifyNativeCanaryReport(report, audit),
    /source_context_audit\.sources\.otlp_logs\.unknown_session_records must be zero/,
  );
});

test('redacted real evidence keeps audit and Session identities aligned', () => {
  const report = read('native-canary-multiturn-0163-report.json');
  const audit = read('native-canary-multiturn-0163-audit.json');
  assert.equal(audit.session_id, report.session_view.session_id);
  for (const turn of report.session_view.turns) assert.equal(turn.session_id, report.session_view.session_id);
});

test('redacted real patched Canary passes the complete delivery gate', () => {
  const report = read('native-canary-multiturn-0163-success-report.json');
  const audit = read('native-canary-multiturn-0163-success-audit.json');
  const result = verifyNativeCanaryReport(report, audit);
  assert.equal(result.schema_version, 'chiptrace.native-canary-gate.v2');
  assert.equal(result.scenario_evidence_verified, true);
  assert.equal(result.native_turns, 2);
  assert.equal(result.producer_mode, 'patched_stock');
  assert.equal(result.unmodified_stock, false);
  assert.equal(result.production_ready, false);
  assert.equal(result.selected_audit_records, 3621);
  assert.equal(result.delivery_ready, true);
  assert.deepEqual(result.scenario_coverage, [
    'delayed_write_stdin',
    'failed_tool_process',
    'resume',
    'second_turn',
  ]);
  assert.deepEqual(result.source_coverage, report.source_coverage);
});

test('historical declaration-only success needs fresh engine witnesses', () => {
  const report = read('native-canary-multiturn-0163-success-report.json');
  const audit = read('native-canary-multiturn-0163-success-audit.json');
  delete report.scenario_evidence;
  assert.throws(() => verifyNativeCanaryReport(report, audit), /scenario evidence/);
});
