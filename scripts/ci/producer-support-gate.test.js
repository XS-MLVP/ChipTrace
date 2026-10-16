'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { verifyProducerSupport } = require('./producer-support-gate');

const root = path.resolve(__dirname, '../..');
const support = JSON.parse(fs.readFileSync(path.join(root, 'integrations/codex/producer-support.json')));
const stock = JSON.parse(fs.readFileSync(path.join(root, 'integrations/codex/stock-release.json')));

function copy() {
  return JSON.parse(JSON.stringify(support));
}

test('producer support policy is content-addressed and matches the pinned release', () => {
  const result = verifyProducerSupport(support, stock);
  assert.equal(result.production_mode, 'patched_stock_cli');
  assert.deepEqual(result.ci_modes, ['patched_stock_cli', 'patched_stock_debug_app_server']);
  assert.equal(result.patch_digests_verified, true);
  assert.equal(result.unmodified_stock_production_acceptance, false);
  assert.deepEqual(result.required_sources, ['wire', 'otlp_logs', 'otlp_traces', 'hooks']);
});

test('a changed patch cannot silently remain production-supported', () => {
  const changed = copy();
  changed.producer.patches[0].sha256 = '0'.repeat(64);
  assert.throws(() => verifyProducerSupport(changed, stock), /patch digest changed/);
});

test('the policy rejects accidental unmodified-producer approval', () => {
  const changed = copy();
  changed.policy.unmodified_stock_production_acceptance = true;
  assert.throws(() => verifyProducerSupport(changed, stock));
});

test('the policy cannot drop a required source or lower the native Turn floor', () => {
  const changed = copy();
  changed.policy.required_sources = ['wire', 'hooks'];
  assert.throws(() => verifyProducerSupport(changed, stock));
  changed.policy.required_sources = ['wire', 'otlp_logs', 'otlp_traces', 'hooks'];
  changed.policy.minimum_native_turns = 1;
  assert.throws(() => verifyProducerSupport(changed, stock));
});
