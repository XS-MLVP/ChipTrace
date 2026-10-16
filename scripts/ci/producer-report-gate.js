'use strict';

// Bind newly executed native protocol evidence to the exact producer policy.
// This report is a CI/data-governance check, not a production acceptance claim.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { verifyProducerSupport } = require('./producer-support-gate');

const ROOT = path.resolve(__dirname, '../..');
const SUPPORT_PATH = path.join(ROOT, 'integrations/codex/producer-support.json');
const STOCK_RELEASE_PATH = path.join(ROOT, 'integrations/codex/stock-release.json');
const SHA256 = /^[a-f0-9]{64}$/;

function object(value, label) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  return value;
}

function nonEmptyString(value, label) {
  assert.equal(typeof value, 'string', `${label} must be a string`);
  assert.notEqual(value.trim(), '', `${label} must not be empty`);
  return value;
}

function nonNegativeInteger(value, label) {
  assert.equal(Number.isSafeInteger(value) && value >= 0, true, `${label} must be a non-negative integer`);
  return value;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function verifySourceCoverage(coverage, modelInteractions) {
  const value = object(coverage, 'report.source_coverage');
  assert.equal(value.complete, true, 'report.source_coverage.complete must be true');
  assert.deepEqual(value.missing_sources, [], 'report.source_coverage.missing_sources must be empty');
  for (const source of ['wire', 'otlp_logs', 'otlp_traces', 'hooks']) {
    assert.ok(nonNegativeInteger(value[source], `report.source_coverage.${source}`) > 0,
      `report.source_coverage.${source} must be positive`);
  }
  assert.equal(value.wire, modelInteractions,
    'report.source_coverage.wire must equal report.model_interactions');
  return value;
}

function verifyTurnCoverage(platform, sourceCoverage, nativeTurns, modelInteractions, toolExecutionRecords) {
  assert.ok(Array.isArray(platform.turn_coverage), 'platform.turn_coverage must be an array');
  assert.equal(platform.turn_coverage.length, nativeTurns,
    'platform.turn_coverage must contain one entry per native Turn');
  const identities = new Set();
  let modelTotal = 0;
  let wireTotal = 0;
  let toolTotal = 0;
  let expectedSessionId;
  const turns = platform.turn_coverage.map((turn, index) => {
    const value = object(turn, `platform.turn_coverage[${index}]`);
    const sessionId = nonEmptyString(value.session_id, `platform.turn_coverage[${index}].session_id`);
    const turnId = nonEmptyString(value.turn_id, `platform.turn_coverage[${index}].turn_id`);
    if (expectedSessionId === undefined) expectedSessionId = sessionId;
    else assert.equal(sessionId, expectedSessionId, 'platform.turn_coverage must contain one Session');
    const identity = `${sessionId}\u0000${turnId}`;
    assert.equal(identities.has(identity), false, `platform.turn_coverage[${index}] duplicates a native Turn`);
    identities.add(identity);
    const status = nonEmptyString(value.status, `platform.turn_coverage[${index}].status`);
    assert.ok(['closed', 'cancelled'].includes(status),
      `platform.turn_coverage[${index}].status must be closed or cancelled`);
    const interactions = nonNegativeInteger(value.model_interactions,
      `platform.turn_coverage[${index}].model_interactions`);
    assert.ok(interactions > 0,
      `platform.turn_coverage[${index}].model_interactions must be positive`);
    const tools = nonNegativeInteger(value.tool_execution_records,
      `platform.turn_coverage[${index}].tool_execution_records`);
    const coverage = object(value.source_coverage, `platform.turn_coverage[${index}].source_coverage`);
    assert.equal(coverage.complete, true,
      `platform.turn_coverage[${index}].source_coverage.complete must be true`);
    assert.deepEqual(coverage.missing_sources, [],
      `platform.turn_coverage[${index}].source_coverage.missing_sources must be empty`);
    const counts = {};
    for (const source of ['wire', 'otlp_logs', 'otlp_traces', 'hooks']) {
      counts[source] = nonNegativeInteger(coverage[source],
        `platform.turn_coverage[${index}].source_coverage.${source}`);
      assert.ok(counts[source] > 0,
        `platform.turn_coverage[${index}].source_coverage.${source} must be positive`);
    }
    assert.equal(counts.wire, interactions,
      `platform.turn_coverage[${index}].source_coverage.wire must equal model_interactions`);
    modelTotal += interactions;
    wireTotal += counts.wire;
    toolTotal += tools;
    return { session_id: sessionId, turn_id: turnId, status,
      model_interactions: interactions, tool_execution_records: tools,
      source_coverage: { complete: coverage.complete, missing_sources: [...coverage.missing_sources], ...counts } };
  });
  assert.equal(modelTotal, modelInteractions, 'per-Turn model interactions must conserve the Session total');
  assert.equal(wireTotal, sourceCoverage.wire, 'per-Turn Wire evidence must conserve the Session total');
  if (toolExecutionRecords !== undefined) {
    assert.equal(toolTotal, nonNegativeInteger(toolExecutionRecords, 'report.tool_execution_records'),
      'per-Turn tool execution records must conserve the Session total');
  }
  return turns;
}

function verifyPatchSet(report, policy) {
  assert.ok(Array.isArray(report.patch_set), 'report.patch_set must be an array');
  const patches = report.patch_set.map((patch, index) => {
    const value = object(patch, `report.patch_set[${index}]`);
    const file = nonEmptyString(value.file, `report.patch_set[${index}].file`);
    assert.match(value.sha256, SHA256, `report.patch_set[${index}].sha256 must be a SHA-256`);
    return { file, sha256: value.sha256 };
  });
  assert.deepEqual(patches, policy.producer.patches,
    'report.patch_set must match the content-addressed producer support policy');
  return patches;
}

function verifyProducerReport(report, policy, support = verifyProducerSupport(
  policy,
  readJson(STOCK_RELEASE_PATH),
)) {
  object(report, 'producer report');
  assert.equal(report.ok, true, 'producer report must be successful');
  assert.equal(report.real_upstream, false,
    'synthetic protocol reports must not claim a real upstream or production canary');
  assert.equal(report.production_acceptance_claimed, false,
    'synthetic protocol reports must not claim production acceptance');
  assert.equal(report.producer_mode, support.production_mode,
    'report.producer_mode must match the supported production mode');
  assert.equal(report.client_version, support.client_version,
    'report.client_version must match the supported producer version');

  const source = object(report.producer_source, 'report.producer_source');
  assert.equal(source.upstream_commit, support.upstream_commit,
    'report.producer_source.upstream_commit must match the supported producer');
  assert.match(source.source_sha256, SHA256, 'report.producer_source.source_sha256 must be a SHA-256');
  const patchSet = verifyPatchSet(report, policy);

  const modelInteractions = nonNegativeInteger(report.model_interactions, 'report.model_interactions');
  assert.ok(modelInteractions > 0, 'report.model_interactions must be positive');
  const toolExecutionRecords = nonNegativeInteger(
    report.tool_execution_records, 'report.tool_execution_records',
  );
  const nativeTurns = nonNegativeInteger(report.native_turns, 'report.native_turns');
  assert.ok(nativeTurns >= support.minimum_native_turns,
    `report.native_turns must be at least ${support.minimum_native_turns}`);
  const sourceCoverage = verifySourceCoverage(report.source_coverage, modelInteractions);

  const platform = object(report.platform_evidence, 'report.platform_evidence');
  assert.equal(platform.backend, 'fs', 'primary protocol evidence must use the verified FS backend');
  assert.equal(platform.production_acceptance_claimed, false);
  assert.equal(platform.native_turns, nativeTurns);
  assert.equal(platform.model_interactions, modelInteractions);
  const turnCoverage = verifyTurnCoverage(
    platform, sourceCoverage, nativeTurns, modelInteractions, toolExecutionRecords,
  );
  assert.equal(platform.remote_checkpoint_verified, undefined,
    'primary FS evidence must not masquerade as remote object evidence');
  assert.ok(Array.isArray(platform.additional_storage_backends),
    'protocol evidence must include the additional private object-storage result');
  assert.equal(platform.additional_storage_backends.length, 1);
  const remote = object(platform.additional_storage_backends[0], 'platform.additional_storage_backends[0]');
  assert.equal(remote.backend, 's3');
  assert.equal(remote.real_oss_account, false);
  assert.equal(remote.production_acceptance_claimed, false);
  assert.equal(remote.remote_checkpoint_verified, true);
  assert.ok(nonNegativeInteger(remote.remote_segment_objects_verified,
    'platform.additional_storage_backends[0].remote_segment_objects_verified') > 0);
  assert.equal(remote.native_turns, nativeTurns);
  assert.equal(remote.model_interactions, modelInteractions);
  assert.deepEqual(
    verifyTurnCoverage(remote, sourceCoverage, nativeTurns, modelInteractions, toolExecutionRecords),
    turnCoverage,
    'FS and private S3 Turn summaries must match',
  );

  return {
    schema_version: 'chiptrace.producer-report-gate.v1',
    producer_mode: report.producer_mode,
    client_version: report.client_version,
    upstream_commit: source.upstream_commit,
    patch_set: patchSet,
    source_sha256: source.source_sha256,
    native_turns: nativeTurns,
    model_interactions: modelInteractions,
    tool_execution_records: toolExecutionRecords,
    source_coverage: sourceCoverage,
    turn_coverage: turnCoverage,
    storage_backends: ['fs', 's3'],
    production_acceptance_claimed: false,
  };
}

function parseArgs(argv) {
  const reports = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] !== '--report' || !argv[index + 1]) {
      throw new Error('usage: producer-report-gate.js --report REPORT.json [--report REPORT.json ...]');
    }
    reports.push(argv[++index]);
  }
  if (reports.length === 0) {
    throw new Error('usage: producer-report-gate.js --report REPORT.json [--report REPORT.json ...]');
  }
  return reports;
}

function main(argv = process.argv.slice(2)) {
  const policy = readJson(SUPPORT_PATH);
  const stock = readJson(STOCK_RELEASE_PATH);
  const support = verifyProducerSupport(policy, stock);
  const reports = parseArgs(argv).map(file => ({
    file: path.basename(file),
    ...verifyProducerReport(readJson(file), policy, support),
  }));
  const result = { schema_version: 'chiptrace.producer-report-gate.v1', reports };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`producer report gate: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { verifyProducerReport, verifySourceCoverage, main };
