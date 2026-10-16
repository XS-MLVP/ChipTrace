'use strict';

const fs = require('node:fs');

const SOURCES = ['wire', 'otlp_logs', 'otlp_traces', 'hooks'];
const AUDIT_SOURCES = ['otlp_logs', 'otlp_traces'];
const DEFAULT_MINIMUM_TURNS = 2;
const REQUIRED_SCENARIOS = [
  'second_turn',
  'resume',
  'failed_tool_process',
  'delayed_write_stdin',
];
const PRODUCER_MODES = new Set(['patched_stock', 'unmodified_stock']);
const UPSTREAM_COMMIT_PATTERN = /^[0-9a-f]{40}$/;

function fail(message) {
  throw new Error(`native canary gate: ${message}`);
}

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

function nonNegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) fail(`${label} must be a non-negative integer`);
  return value;
}

function requireTrue(value, label) {
  if (value !== true) fail(`${label} must be true`);
}

function requireZero(value, label) {
  if (value !== 0) fail(`${label} must be zero`);
}

function nonEmptyString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') fail(`${label} must be a non-empty string`);
  return value;
}

function verifyProducerProvenance(report, { requireUnmodifiedStock = false } = {}) {
  if (report.provenance === undefined || report.provenance === null) {
    if (requireUnmodifiedStock) {
      fail('production canary requires producer provenance for an unmodified Stock Codex producer');
    }
    return {
      kind: 'unknown',
      client_version: report.stock_version,
      upstream_commit: null,
      producer_mode: 'unknown',
      patch_set: [],
      unmodified_stock: false,
    };
  }
  const provenance = object(report.provenance, 'report.provenance');
  const kind = nonEmptyString(provenance.kind, 'report.provenance.kind');
  const clientVersion = nonEmptyString(provenance.client_version, 'report.provenance.client_version');
  const upstreamCommit = nonEmptyString(provenance.upstream_commit, 'report.provenance.upstream_commit');
  if (!UPSTREAM_COMMIT_PATTERN.test(upstreamCommit)) {
    fail('report.provenance.upstream_commit must be a lowercase 40-character SHA-1');
  }
  const producerMode = nonEmptyString(provenance.producer_mode, 'report.provenance.producer_mode');
  if (!PRODUCER_MODES.has(producerMode)) {
    fail(`report.provenance.producer_mode must be one of ${[...PRODUCER_MODES].join(', ')}`);
  }
  const patchSet = provenance.patch_set;
  if (!Array.isArray(patchSet)) fail('report.provenance.patch_set must be an array');
  patchSet.forEach((patch, index) => nonEmptyString(patch, `report.provenance.patch_set[${index}]`));
  if (clientVersion !== report.stock_version) {
    fail('report.provenance.client_version must match report.stock_version');
  }
  if (producerMode === 'unmodified_stock' && patchSet.length !== 0) {
    fail('unmodified Stock Codex provenance cannot declare patches');
  }
  if (producerMode === 'patched_stock' && patchSet.length === 0) {
    fail('patched Stock Codex provenance must declare patch_set');
  }
  if (requireUnmodifiedStock && producerMode !== 'unmodified_stock') {
    fail('production canary requires an unmodified Stock Codex producer');
  }
  return {
    kind,
    client_version: clientVersion,
    upstream_commit: upstreamCommit,
    producer_mode: producerMode,
    patch_set: [...patchSet],
    unmodified_stock: producerMode === 'unmodified_stock',
  };
}

function verifySourceCoverage(coverage) {
  object(coverage, 'report.source_coverage');
  requireTrue(coverage.complete, 'report.source_coverage.complete');
  if (!Array.isArray(coverage.missing_sources) || coverage.missing_sources.length !== 0) {
    fail('report.source_coverage.missing_sources must be empty');
  }
  for (const source of SOURCES) {
    if (nonNegativeInteger(coverage[source], `report.source_coverage.${source}`) === 0) {
      fail(`report.source_coverage has no ${source} evidence`);
    }
  }
  return coverage;
}

function verifyScenarioCoverage(scenarios) {
  if (!Array.isArray(scenarios) || scenarios.length === 0) {
    fail('report.scenario_coverage must be a non-empty array');
  }
  const observed = new Set(scenarios.map((scenario, index) => (
    nonEmptyString(scenario, `report.scenario_coverage[${index}]`)
  )));
  for (const required of REQUIRED_SCENARIOS) {
    if (!observed.has(required)) fail(`report.scenario_coverage is missing ${required}`);
  }
  return [...observed].sort();
}

function verifyScenarioEvidence(evidence, session) {
  if (!evidence) fail('scenario evidence from the exact Capture snapshot is required');
  object(evidence, 'scenario_evidence');
  if (evidence.schema_version !== 'chiptrace.native-canary-scenarios.v1'
    || evidence.source !== 'exact_capture_snapshot') fail('unsupported scenario evidence source or schema');
  if (evidence.session_id !== session.session_id) fail('scenario evidence belongs to another Session');
  requireTrue(evidence.complete, 'scenario_evidence.complete');
  if (!Array.isArray(evidence.missing_scenarios) || evidence.missing_scenarios.length !== 0) {
    fail('scenario evidence has missing scenarios');
  }
  const turns = new Map(session.turns.map(turn => [turn.turn_id, turn]));
  const second = object(evidence.second_turn, 'scenario_evidence.second_turn');
  if (!Array.isArray(second.turn_ids) || second.turn_ids.length < 2
    || new Set(second.turn_ids).size !== second.turn_ids.length
    || second.turn_ids.some(id => !turns.has(id) || turns.get(id).model_interactions === 0)) {
    fail('second_turn needs two distinct native Turns with model interactions');
  }
  const resume = object(evidence.resume, 'scenario_evidence.resume');
  nonEmptyString(resume.capture_id, 'scenario_evidence.resume.capture_id');
  if (session.session_epochs < 2 || resume.source_event_name !== 'SessionStart' || resume.source !== 'resume') {
    fail('resume needs an observed SessionStart(source=resume) and multiple Session epochs');
  }
  const observations = new Map();
  const witnesses = new Map();
  const captureOwners = new Map();
  function witness(value, label, expectedTool) {
    object(value, label);
    const turn = turns.get(value.turn_id);
    if (value.session_id !== session.session_id || !turn
      || !turn.raw_capture_refs.includes(value.capture_id)
      || session.turns.filter(t => t.raw_capture_refs.includes(value.capture_id)).length !== 1) {
      fail(`${label} lacks unambiguous native Turn Raw membership`);
    }
    nonEmptyString(value.capture_id, `${label}.capture_id`);
    const callId = nonEmptyString(value.call_id, `${label}.call_id`);
    if (!['exec_command', 'write_stdin'].includes(value.tool)
      || (expectedTool && value.tool !== expectedTool)
      || !['', 'functions'].includes(value.runtime_namespace)
      || value.source_event_name !== 'codex.tool_result'
      || value.output_truncated !== false) fail(`${label} needs an untruncated builtin tool observation`);
    if (!Number.isSafeInteger(value.tool_result_seq) || value.tool_result_seq <= 0) {
      fail(`${label} needs an observed positive tool_result_seq`);
    }
    const outcome = object(value.process_outcome, `${label}.process_outcome`);
    if (outcome.kind !== 'process'
      || outcome.provenance !== 'stock_codex.unified_exec.log_output.header') {
      fail(`${label} needs Stock process provenance`);
    }
    if (outcome.state === 'exited') {
      if (!Number.isInteger(outcome.exit_code) || outcome.exit_code < -2147483648
        || outcome.exit_code > 2147483647 || outcome.success !== (outcome.exit_code === 0)
        || Object.hasOwn(outcome, 'session_id')) fail(`${label} has inconsistent exited process evidence`);
    } else if (outcome.state === 'running') {
      if (!Number.isInteger(outcome.session_id) || outcome.session_id <= 0 || outcome.session_id > 2147483647
        || outcome.success !== null || Object.hasOwn(outcome, 'exit_code')) {
        fail(`${label} has inconsistent running process evidence`);
      }
    } else fail(`${label} has no process result`);
    const identity = `${value.turn_id}\u0000${callId}`;
    const sequence = `${value.turn_id}\u0000${value.tool_result_seq}`;
    const metadata = JSON.stringify([value.capture_id, value.tool, value.tool_result_seq,
      outcome.state, outcome.exit_code, outcome.session_id, outcome.success, value.requested_session_id]);
    if ((witnesses.has(identity) && witnesses.get(identity) !== metadata)
      || (observations.has(sequence) && observations.get(sequence) !== identity)
      || (captureOwners.has(value.capture_id) && captureOwners.get(value.capture_id) !== identity)) {
      fail('scenario evidence contains contradictory call or sequence observations');
    }
    witnesses.set(identity, metadata);
    observations.set(sequence, identity);
    captureOwners.set(value.capture_id, identity);
    return value;
  }
  const failed = witness(evidence.failed_tool_process, 'scenario_evidence.failed_tool_process');
  if (failed.process_outcome.state !== 'exited' || failed.process_outcome.exit_code === 0) {
    fail('failed_tool_process needs an observed nonzero process exit');
  }
  const delayed = object(evidence.delayed_write_stdin, 'scenario_evidence.delayed_write_stdin');
  const launch = witness(delayed.launch, 'scenario_evidence.delayed_write_stdin.launch', 'exec_command');
  const terminal = witness(delayed.terminal, 'scenario_evidence.delayed_write_stdin.terminal', 'write_stdin');
  if (launch.process_outcome.state !== 'running' || terminal.process_outcome.state !== 'exited'
    || launch.turn_id !== terminal.turn_id || launch.call_id === terminal.call_id
    || launch.capture_id === terminal.capture_id
    || terminal.requested_session_id !== launch.process_outcome.session_id
    || terminal.tool_result_seq <= launch.tool_result_seq) {
    fail('delayed_write_stdin needs the actual running Session ID and a later terminal poll in the same Turn');
  }
  const perTurn = new Map();
  for (const identity of witnesses.keys()) {
    const turnId = identity.split('\u0000')[0];
    perTurn.set(turnId, (perTurn.get(turnId) || 0) + 1);
  }
  for (const [turnId, count] of perTurn) {
    if (count > turns.get(turnId).tool_execution_records) fail('scenario witnesses exceed native Turn tool records');
  }
}

function verifyAudit(audit, expectedSessionId) {
  object(audit, 'source_context_audit');
  if (audit.schema_version !== 'chiptrace.source-context-audit.v2') {
    fail('source_context_audit has an unsupported schema_version');
  }
  const auditSessionId = nonEmptyString(audit.session_id, 'source_context_audit.session_id');
  if (expectedSessionId !== undefined && auditSessionId !== expectedSessionId) {
    fail('source_context_audit.session_id does not match report.session_view.session_id');
  }
  const sources = object(audit.sources, 'source_context_audit.sources');
  let unscoped = 0;
  let selectedRecords = 0;
  for (const source of AUDIT_SOURCES) {
    const counts = object(sources[source], `source_context_audit.sources.${source}`);
    const fields = [
      'total_records',
      'turn_assigned_records',
      'session_level_records',
      'process_level_records',
      'unscoped_turn_records',
      'other_session_records',
      'unknown_session_records',
    ];
    const values = Object.fromEntries(fields.map(field => [
      field,
      nonNegativeInteger(counts[field], `source_context_audit.sources.${source}.${field}`),
    ]));
    const classified = fields.slice(1).reduce((sum, field) => sum + values[field], 0);
    if (classified !== values.total_records) {
      fail(`source_context_audit ${source} counts do not conserve records`);
    }
    requireZero(values.unscoped_turn_records, `source_context_audit.sources.${source}.unscoped_turn_records`);
    requireZero(values.unknown_session_records, `source_context_audit.sources.${source}.unknown_session_records`);
    unscoped += values.unscoped_turn_records;
    selectedRecords += values.turn_assigned_records
      + values.session_level_records + values.process_level_records;
  }
  requireZero(audit.unscoped_otlp_records, 'source_context_audit.unscoped_otlp_records');
  if (audit.unscoped_otlp_records !== unscoped) {
    fail('source_context_audit.unscoped_otlp_records does not match source counts');
  }
  nonNegativeInteger(audit.selected_captures, 'source_context_audit.selected_captures');
  nonNegativeInteger(audit.duplicate_captures_removed, 'source_context_audit.duplicate_captures_removed');
  return {
    selected_records: selectedRecords,
    turn_assigned_records: Object.fromEntries(AUDIT_SOURCES.map(source => [
      source,
      nonNegativeInteger(sources[source].turn_assigned_records,
        `source_context_audit.sources.${source}.turn_assigned_records`),
    ])),
  };
}

function verifyNativeCanaryReport(
  report,
  audit,
  { minimumTurns = DEFAULT_MINIMUM_TURNS, requireUnmodifiedStock = false } = {},
) {
  object(report, 'report');
  object(audit, 'source_context_audit');
  if (!Number.isInteger(minimumTurns) || minimumTurns < 1) fail('minimumTurns must be a positive integer');
  if (report.real_upstream !== true) fail('real_upstream must be true');
  nonEmptyString(report.stock_version, 'report.stock_version');
  const producer = verifyProducerProvenance(report, { requireUnmodifiedStock });
  const nativeExit = object(report.native_exit, 'report.native_exit');
  if (nativeExit.code !== 0 || nativeExit.signal !== null) fail('native client exited nonzero');
  const sourceCoverage = verifySourceCoverage(report.source_coverage);
  const scenarios = verifyScenarioCoverage(report.scenario_coverage);
  requireTrue(report.delivery_ready, 'report.delivery_ready');
  const integrityReady = report.integrity?.delivery_ready ?? report.integrity_ready;
  requireTrue(integrityReady, 'report.integrity.delivery_ready');

  const session = object(report.session_view || report.session, 'report.session_view');
  if (session.schema_version !== 'chiptrace.session-view.v2') {
    fail('session_view has an unsupported schema_version');
  }
  const sessionId = nonEmptyString(session.session_id, 'session_view.session_id');
  requireTrue(session.delivery_ready, 'session_view.delivery_ready');
  requireTrue(session.latest_epoch_closed, 'session_view.latest_epoch_closed');
  const sessionEpochs = nonNegativeInteger(session.session_epochs, 'session_view.session_epochs');
  const closedSessionEpochs = nonNegativeInteger(
    session.closed_session_epochs,
    'session_view.closed_session_epochs',
  );
  requireZero(
    nonNegativeInteger(session.invalid_session_boundaries, 'session_view.invalid_session_boundaries'),
    'session_view.invalid_session_boundaries',
  );
  if (sessionEpochs === 0 || closedSessionEpochs !== sessionEpochs) {
    fail(
      'session_view session epochs are not fully closed '
      + `(epochs=${sessionEpochs}, closed=${closedSessionEpochs})`,
    );
  }
  requireTrue(session.turn_source_coverage_complete, 'session_view.turn_source_coverage_complete');
  requireZero(session.open_turns, 'session_view.open_turns');
  requireZero(session.conflicted_turns, 'session_view.conflicted_turns');
  requireZero(session.incomplete_turns, 'session_view.incomplete_turns');
  requireZero(session.unscoped_turn_records, 'session_view.unscoped_turn_records');
  object(session.unscoped_source_records, 'session_view.unscoped_source_records');
  if (Object.keys(session.unscoped_source_records).length !== 0) {
    fail('session_view.unscoped_source_records must be empty');
  }
  nonNegativeInteger(session.native_turns, 'session_view.native_turns');
  if (session.native_turns < minimumTurns) {
    fail(`session_view.native_turns must be at least ${minimumTurns}`);
  }
  if (!Array.isArray(session.turns) || session.turns.length !== session.native_turns) {
    fail('session_view.turns does not match native_turns');
  }
  const closedTurns = nonNegativeInteger(session.closed_turns, 'session_view.closed_turns');
  if (closedTurns !== session.native_turns) {
    fail(`session_view.closed_turns must equal native_turns (closed=${closedTurns}, turns=${session.native_turns})`);
  }
  const turnIdentities = new Set();
  const turnAssignedRecords = Object.fromEntries(AUDIT_SOURCES.map(source => [source, 0]));
  const turnInteractionTotals = {
    model_interactions: 0,
    tool_execution_records: 0,
  };
  for (const [index, turn] of session.turns.entries()) {
    object(turn, `session_view.turns[${index}]`);
    if (nonEmptyString(turn.session_id, `session_view.turns[${index}].session_id`) !== sessionId) {
      fail(`session_view.turns[${index}].session_id does not match session_view.session_id`);
    }
    const turnId = nonEmptyString(turn.turn_id, `session_view.turns[${index}].turn_id`);
    const identity = `${sessionId}\u0000${turnId}`;
    if (turnIdentities.has(identity)) fail(`session_view.turns[${index}] duplicates a native identity`);
    turnIdentities.add(identity);
    if (!['closed', 'cancelled'].includes(turn.status)) {
      fail(`session_view.turns[${index}].status must be closed or cancelled`);
    }
    requireTrue(turn.state_conflict === false, `session_view.turns[${index}].state_conflict`);
    if (nonNegativeInteger(turn.terminal_events, `session_view.turns[${index}].terminal_events`) === 0) {
      fail(`session_view.turns[${index}] has no terminal event`);
    }
    nonEmptyString(turn.started_at, `session_view.turns[${index}].started_at`);
    nonEmptyString(turn.finished_at, `session_view.turns[${index}].finished_at`);
    if (!Array.isArray(turn.raw_capture_refs) || turn.raw_capture_refs.length === 0) {
      fail(`session_view.turns[${index}].raw_capture_refs must be non-empty`);
    }
    const captureRefs = new Set(turn.raw_capture_refs.map((captureId, refIndex) => (
      nonEmptyString(captureId, `session_view.turns[${index}].raw_capture_refs[${refIndex}]`)
    )));
    if (captureRefs.size !== turn.raw_capture_refs.length) {
      fail(`session_view.turns[${index}].raw_capture_refs must be unique`);
    }
    const turnModelInteractions = nonNegativeInteger(
      turn.model_interactions,
      `session_view.turns[${index}].model_interactions`,
    );
    turnInteractionTotals.model_interactions += turnModelInteractions;
    turnInteractionTotals.tool_execution_records += nonNegativeInteger(
      turn.tool_execution_records,
      `session_view.turns[${index}].tool_execution_records`,
    );
    const coverage = object(turn.source_coverage, `session_view.turns[${index}].source_coverage`);
    requireTrue(coverage.complete, `session_view.turns[${index}].source_coverage.complete`);
    if (!Array.isArray(coverage.missing_sources) || coverage.missing_sources.length !== 0) {
      fail(`session_view.turns[${index}].source_coverage.missing_sources must be empty`);
    }
    for (const source of SOURCES) {
      const count = nonNegativeInteger(
        coverage[source], `session_view.turns[${index}].source_coverage.${source}`,
      );
      if (count === 0) {
        fail(`session_view.turns[${index}] has no ${source} evidence`);
      }
      if (source === 'wire' && count !== turnModelInteractions) {
        fail(
          `session_view.turns[${index}].source_coverage.wire must equal `
          + `model_interactions (wire=${count}, model_interactions=${turnModelInteractions})`,
        );
      }
      if (AUDIT_SOURCES.includes(source)) turnAssignedRecords[source] += count;
    }
  }
  const sessionModelInteractions = nonNegativeInteger(
    session.model_interactions,
    'session_view.model_interactions',
  );
  const sessionToolExecutionRecords = nonNegativeInteger(
    session.tool_execution_records,
    'session_view.tool_execution_records',
  );
  if (sourceCoverage.wire !== sessionModelInteractions) {
    fail(
      'report.source_coverage.wire must equal session_view.model_interactions '
      + `(wire=${sourceCoverage.wire}, model_interactions=${sessionModelInteractions})`,
    );
  }
  if (sessionModelInteractions !== turnInteractionTotals.model_interactions) {
    fail(
      'session_view.model_interactions does not equal the sum of native Turn model_interactions '
      + `(session=${sessionModelInteractions}, turns=${turnInteractionTotals.model_interactions})`,
    );
  }
  if (sessionToolExecutionRecords !== turnInteractionTotals.tool_execution_records) {
    fail(
      'session_view.tool_execution_records does not equal the sum of native Turn '
      + `tool_execution_records (session=${sessionToolExecutionRecords}, turns=${turnInteractionTotals.tool_execution_records})`,
    );
  }
  const auditSummary = verifyAudit(audit, sessionId);
  for (const source of AUDIT_SOURCES) {
    if (turnAssignedRecords[source] !== auditSummary.turn_assigned_records[source]) {
      fail(
        `session_view turn ${source} records do not match source_context_audit `
        + `(turns=${turnAssignedRecords[source]}, audit=${auditSummary.turn_assigned_records[source]})`,
      );
    }
  }
  verifyScenarioEvidence(report.scenario_evidence, session);
  return {
    schema_version: 'chiptrace.native-canary-gate.v2',
    real_upstream: true,
    stock_version: report.stock_version,
    producer_mode: producer.producer_mode,
    upstream_commit: producer.upstream_commit,
    patch_set: producer.patch_set,
    unmodified_stock: producer.unmodified_stock,
    production_ready: producer.unmodified_stock,
    scenario_coverage: scenarios,
    scenario_evidence_verified: true,
    source_coverage: sourceCoverage,
    native_turns: session.native_turns,
    model_interactions: sessionModelInteractions,
    tool_execution_records: sessionToolExecutionRecords,
    selected_audit_records: auditSummary.selected_records,
    delivery_ready: true,
  };
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error(`cannot read JSON ${file}: ${error.message}`);
  }
}

function parseArgs(argv) {
  let report;
  let audit;
  let minimumTurns = DEFAULT_MINIMUM_TURNS;
  let requireUnmodifiedStock = false;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--report' && value) { report = value; index += 1; }
    else if (flag === '--audit' && value) { audit = value; index += 1; }
    else if (flag === '--minimum-turns' && value) { minimumTurns = Number(value); index += 1; }
    else if (flag === '--require-unmodified-stock') { requireUnmodifiedStock = true; }
    else fail('usage: native-canary-gate.js --report REPORT.json --audit AUDIT.json [--minimum-turns N] [--require-unmodified-stock]');
  }
  if (!report || !audit) fail('usage: native-canary-gate.js --report REPORT.json --audit AUDIT.json [--minimum-turns N] [--require-unmodified-stock]');
  return { report, audit, minimumTurns, requireUnmodifiedStock };
}

if (require.main === module) {
  try {
    const args = parseArgs(process.argv.slice(2));
    console.log(JSON.stringify(verifyNativeCanaryReport(
      readJson(args.report),
      readJson(args.audit),
      {
        minimumTurns: args.minimumTurns,
        requireUnmodifiedStock: args.requireUnmodifiedStock,
      },
    ), null, 2));
  } catch (error) {
    console.error(error.message || String(error));
    process.exitCode = 1;
  }
}

module.exports = { DEFAULT_MINIMUM_TURNS, REQUIRED_SCENARIOS, verifyNativeCanaryReport };
