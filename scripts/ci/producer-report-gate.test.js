'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { verifyProducerReport } = require('./producer-report-gate');

const root = path.resolve(__dirname, '../..');
const policy = JSON.parse(fs.readFileSync(path.join(root, 'integrations/codex/producer-support.json')));

function report() {
  return {
    ok: true,
    real_upstream: false,
    production_acceptance_claimed: false,
    producer_mode: 'patched_stock_cli',
    client_version: policy.producer.version,
    producer_source: { upstream_commit: policy.producer.upstream_commit, source_sha256: 'a'.repeat(64) },
    patch_set: policy.producer.patches.map(patch => ({ ...patch })),
    native_turns: 2,
    model_interactions: 4,
    tool_execution_records: 2,
    source_coverage: { complete: true, missing_sources: [], wire: 4, otlp_logs: 8, otlp_traces: 8, hooks: 4 },
    source_audit: {
      schema_version: 'chiptrace.source-context-audit.v2', session_id: 'session', unscoped_otlp_records: 0,
      sources: {
        otlp_logs: { total_records: 6, turn_assigned_records: 6, session_level_records: 0,
          process_level_records: 0, unscoped_turn_records: 0, other_session_records: 0, unknown_session_records: 0 },
        otlp_traces: { total_records: 8, turn_assigned_records: 8, session_level_records: 0,
          process_level_records: 0, unscoped_turn_records: 0, other_session_records: 0, unknown_session_records: 0 },
      },
    },
    platform_evidence: {
      backend: 'fs', production_acceptance_claimed: false, session_id: 'session', native_turns: 2, model_interactions: 4,
      turn_coverage: [1, 2].map(index => ({ session_id: 'session', turn_id: `turn-${index}`, status: 'closed',
        model_interactions: 2, tool_execution_records: 1,
        source_coverage: { complete: true, missing_sources: [], wire: 2, otlp_logs: 3, otlp_traces: 4, hooks: 2 } })),
      additional_storage_backends: [{ backend: 's3', real_oss_account: false,
        production_acceptance_claimed: false, remote_checkpoint_verified: true,
        remote_segment_objects_verified: 3, session_id: 'session', native_turns: 2, model_interactions: 4,
        turn_coverage: [1, 2].map(index => ({ session_id: 'session', turn_id: `turn-${index}`, status: 'closed',
          model_interactions: 2, tool_execution_records: 1,
          source_coverage: { complete: true, missing_sources: [], wire: 2, otlp_logs: 3, otlp_traces: 4, hooks: 2 } })),
      }],
    },
  };
}

test('producer report gate binds protocol evidence to the supported producer and storage checks', () => {
  const result = verifyProducerReport(report(), policy);
  assert.equal(result.schema_version, 'chiptrace.producer-report-gate.v1');
  assert.equal(result.native_turns, 2);
  assert.deepEqual(result.storage_backends, ['fs', 's3']);
  assert.equal(result.production_acceptance_claimed, false);
});

test('producer report gate rejects a report from another producer or patch set', () => {
  const changedProducer = report();
  changedProducer.producer_source.upstream_commit = 'b'.repeat(40);
  assert.throws(() => verifyProducerReport(changedProducer, policy), /upstream_commit/);

  const changedPatch = report();
  changedPatch.patch_set[0].sha256 = 'b'.repeat(64);
  assert.throws(() => verifyProducerReport(changedPatch, policy), /patch_set/);
});

test('producer report gate rejects incomplete Turn source coverage and production claims', () => {
  const missingWire = report();
  missingWire.source_coverage.wire = 3;
  assert.throws(() => verifyProducerReport(missingWire, policy), /source_coverage\.wire/);

  const claimed = report();
  claimed.production_acceptance_claimed = true;
  assert.throws(() => verifyProducerReport(claimed, policy), /production acceptance/);
});

test('producer report gate rejects per-Turn Wire gaps and FS/S3 summary drift', () => {
  const missingTurnWire = report();
  missingTurnWire.platform_evidence.turn_coverage[0].source_coverage.wire = 1;
  assert.throws(() => verifyProducerReport(missingTurnWire, policy), /source_coverage\.wire/);

  const driftedRemote = report();
  driftedRemote.platform_evidence.additional_storage_backends[0].turn_coverage[1].turn_id = 'different-turn';
  assert.throws(() => verifyProducerReport(driftedRemote, policy), /FS and private S3 Turn summaries/);
});

test('producer report gate rejects a Turn with missing source evidence or interaction totals', () => {
  const incomplete = report();
  incomplete.platform_evidence.turn_coverage[0].source_coverage.complete = false;
  incomplete.platform_evidence.turn_coverage[0].source_coverage.missing_sources = ['hooks'];
  assert.throws(() => verifyProducerReport(incomplete, policy), /source_coverage\.complete/);

  const missingTools = report();
  delete missingTools.tool_execution_records;
  assert.throws(() => verifyProducerReport(missingTools, policy), /report\.tool_execution_records/);

  const openTurn = report();
  openTurn.platform_evidence.turn_coverage[0].status = 'open';
  assert.throws(() => verifyProducerReport(openTurn, policy), /status must be closed or cancelled/);

  const inflatedLogs = report();
  inflatedLogs.source_audit.sources.otlp_logs.turn_assigned_records = 10;
  inflatedLogs.source_audit.sources.otlp_logs.total_records = 10;
  assert.throws(() => verifyProducerReport(inflatedLogs, policy), /otlp_logs evidence must equal source_audit/);
});

test('producer report gate rejects source audit identity and conservation errors', () => {
  const wrongSession = report();
  wrongSession.source_audit.session_id = 'other-session';
  assert.throws(() => verifyProducerReport(wrongSession, policy), /session_id must match/);

  const brokenConservation = report();
  brokenConservation.source_audit.sources.otlp_traces.total_records += 1;
  assert.throws(() => verifyProducerReport(brokenConservation, policy), /counts do not conserve/);

  const unscoped = report();
  unscoped.source_audit.sources.otlp_logs.unscoped_turn_records = 1;
  unscoped.source_audit.sources.otlp_logs.total_records += 1;
  assert.throws(() => verifyProducerReport(unscoped, policy), /unscoped_turn_records must be zero/);
});
