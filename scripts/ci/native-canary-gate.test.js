'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { verifyNativeCanaryReport } = require('./native-canary-gate');

const coverage = () => ({ wire: 1, otlp_logs: 2, otlp_traces: 3, hooks: 1, missing_sources: [], complete: true });

function report() {
  return {
    real_upstream: true,
    stock_version: '0.163.0-alpha.11',
    scenario_coverage: ['second_turn', 'resume', 'failed_tool_process', 'delayed_write_stdin'],
    source_coverage: { wire: 2, otlp_logs: 2, otlp_traces: 2, hooks: 2, missing_sources: [], complete: true },
    native_exit: { code: 0, signal: null },
    delivery_ready: true,
    integrity: { delivery_ready: true },
    session_view: {
      schema_version: 'chiptrace.session-view.v2',
      session_id: 'session-1',
      session_epochs: 2,
      closed_session_epochs: 2,
      invalid_session_boundaries: 0,
      delivery_ready: true,
      latest_epoch_closed: true,
      turn_source_coverage_complete: true,
      open_turns: 0,
      conflicted_turns: 0,
      incomplete_turns: 0,
      unscoped_turn_records: 0,
      unscoped_source_records: {},
      native_turns: 2,
      closed_turns: 2,
      model_interactions: 2,
      tool_execution_records: 2,
      turns: [
        {
          session_id: 'session-1', turn_id: 'turn-1', status: 'closed', state_conflict: false,
          started_at: 'redacted', finished_at: 'redacted', terminal_events: 1,
          raw_capture_refs: ['capture-1'],
          model_interactions: 1, tool_execution_records: 1, source_coverage: coverage(),
        },
        {
          session_id: 'session-1', turn_id: 'turn-2', status: 'cancelled', state_conflict: false,
          started_at: 'redacted', finished_at: 'redacted', terminal_events: 1,
          raw_capture_refs: ['capture-2'],
          model_interactions: 1, tool_execution_records: 1, source_coverage: coverage(),
        },
      ],
    },
  };
}

function audit() {
  const counts = total => ({
    total_records: total,
    turn_assigned_records: total,
    session_level_records: 0,
    process_level_records: 0,
    unscoped_turn_records: 0,
    other_session_records: 0,
    unknown_session_records: 0,
  });
  return {
    schema_version: 'chiptrace.source-context-audit.v2',
    session_id: 'session-1',
    selected_captures: 8,
    duplicate_captures_removed: 0,
    unscoped_otlp_records: 0,
    sources: { otlp_logs: counts(4), otlp_traces: counts(6) },
  };
}

test('native canary gate requires a complete multi-turn four-source bundle', () => {
  assert.deepEqual(verifyNativeCanaryReport(report(), audit()), {
    schema_version: 'chiptrace.native-canary-gate.v1',
    real_upstream: true,
    stock_version: '0.163.0-alpha.11',
    scenario_coverage: ['delayed_write_stdin', 'failed_tool_process', 'resume', 'second_turn'],
    source_coverage: { wire: 2, otlp_logs: 2, otlp_traces: 2, hooks: 2, missing_sources: [], complete: true },
    native_turns: 2,
    model_interactions: 2,
    tool_execution_records: 2,
    selected_audit_records: 10,
    delivery_ready: true,
  });
});

test('integrity.ready cannot bypass an unscoped Turn record', () => {
  const broken = report();
  broken.session_view.unscoped_turn_records = 1;
  assert.throws(() => verifyNativeCanaryReport(broken, audit()), /unscoped_turn_records must be zero/);
});

test('unknown Session records are retained as a hard evidence gap', () => {
  const broken = audit();
  broken.sources.otlp_traces.unknown_session_records = 1;
  broken.sources.otlp_traces.total_records += 1;
  assert.throws(() => verifyNativeCanaryReport(report(), broken), /unknown_session_records must be zero/);
});

test('the source audit must belong to the inspected native Session', () => {
  const broken = audit();
  broken.session_id = 'another-session';
  assert.throws(
    () => verifyNativeCanaryReport(report(), broken),
    /does not match report\.session_view\.session_id/,
  );
});

test('native Turn identities must be present, session-scoped and unique', () => {
  const missing = report();
  delete missing.session_view.turns[0].turn_id;
  assert.throws(() => verifyNativeCanaryReport(missing, audit()), /turn_id must be a non-empty string/);
  const duplicate = report();
  duplicate.session_view.turns[1].turn_id = 'turn-1';
  assert.throws(() => verifyNativeCanaryReport(duplicate, audit()), /duplicates a native identity/);
  const foreign = report();
  foreign.session_view.turns[1].session_id = 'another-session';
  assert.throws(() => verifyNativeCanaryReport(foreign, audit()), /does not match session_view\.session_id/);
});

test('short or non-upstream reports cannot pass the production gate', () => {
  const broken = report();
  broken.real_upstream = false;
  broken.session_view.native_turns = 1;
  assert.throws(() => verifyNativeCanaryReport(broken, audit()), /real_upstream must be true/);
  const short = report();
  short.session_view.native_turns = 1;
  short.session_view.turns.pop();
  assert.throws(() => verifyNativeCanaryReport(short, audit()), /at least 2/);
});

test('a canary must declare every required interaction scenario and source aggregate', () => {
  const scenarios = report();
  scenarios.scenario_coverage = ['second_turn', 'resume'];
  assert.throws(() => verifyNativeCanaryReport(scenarios, audit()), /missing failed_tool_process/);
  const sources = report();
  delete sources.source_coverage;
  assert.throws(() => verifyNativeCanaryReport(sources, audit()), /report\.source_coverage must be an object/);
});

test('a missing native exit result cannot be treated as a successful canary', () => {
  const broken = report();
  delete broken.native_exit;
  assert.throws(() => verifyNativeCanaryReport(broken, audit()), /report\.native_exit must be an object/);
});

test('source audit counts must conserve every record', () => {
  const broken = audit();
  broken.sources.otlp_logs.turn_assigned_records = 3;
  assert.throws(() => verifyNativeCanaryReport(report(), broken), /counts do not conserve records/);
});

test('per-Turn OTLP totals must match the source audit', () => {
  const broken = audit();
  broken.sources.otlp_logs.turn_assigned_records += 1;
  broken.sources.otlp_logs.total_records += 1;
  assert.throws(
    () => verifyNativeCanaryReport(report(), broken),
    /turn otlp_logs records do not match source_context_audit/,
  );
});

test('Session interaction totals must equal the native Turn totals', () => {
  const broken = report();
  broken.session_view.model_interactions += 1;
  assert.throws(
    () => verifyNativeCanaryReport(broken, audit()),
    /session_view\.model_interactions does not equal the sum of native Turn/,
  );
  const missing = report();
  delete missing.session_view.turns[0].tool_execution_records;
  assert.throws(
    () => verifyNativeCanaryReport(missing, audit()),
    /session_view\.turns\[0\]\.tool_execution_records must be a non-negative integer/,
  );
});

test('closed Turns must retain terminal boundaries and Raw references', () => {
  const missingTerminal = report();
  missingTerminal.session_view.turns[0].terminal_events = 0;
  assert.throws(() => verifyNativeCanaryReport(missingTerminal, audit()), /has no terminal event/);
  const missingRaw = report();
  missingRaw.session_view.turns[0].raw_capture_refs = [];
  assert.throws(() => verifyNativeCanaryReport(missingRaw, audit()), /raw_capture_refs must be non-empty/);
  const mismatchedEpochs = report();
  mismatchedEpochs.session_view.closed_session_epochs = 1;
  assert.throws(() => verifyNativeCanaryReport(mismatchedEpochs, audit()), /session epochs are not fully closed/);
});

test('explicit process-level records are conserved without becoming Session evidence', () => {
  const process = audit();
  process.sources.otlp_logs.total_records += 2;
  process.sources.otlp_logs.process_level_records = 2;
  assert.equal(verifyNativeCanaryReport(report(), process).selected_audit_records, 12);
});
