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
    source_coverage: { complete: true, missing_sources: [], wire: 4, otlp_logs: 8, otlp_traces: 8, hooks: 4 },
    platform_evidence: {
      backend: 'fs', production_acceptance_claimed: false, native_turns: 2, model_interactions: 4,
      additional_storage_backends: [{ backend: 's3', real_oss_account: false,
        production_acceptance_claimed: false, remote_checkpoint_verified: true,
        remote_segment_objects_verified: 3, native_turns: 2, model_interactions: 4 }],
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
