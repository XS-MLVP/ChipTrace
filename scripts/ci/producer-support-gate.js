'use strict';

// Keep the producer that CI qualifies and the producer that operations may
// deploy in one reviewable, content-addressed policy.  This gate deliberately
// does not turn an unmodified Stock Codex failure into a release success.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '../..');
const STOCK_RELEASE_PATH = path.join(ROOT, 'integrations/codex/stock-release.json');
const SUPPORT_PATH = path.join(ROOT, 'integrations/codex/producer-support.json');
const PATCH_ROOT = path.join(ROOT, 'docs');
const SHA256 = /^[a-f0-9]{64}$/;
const SHA1 = /^[a-f0-9]{40}$/;

function nonEmptyString(value, label) {
  assert.equal(typeof value, 'string', `${label} must be a string`);
  assert.notEqual(value.trim(), '', `${label} must not be empty`);
  return value;
}

function readJson(file) {
  const bytes = fs.readFileSync(file);
  return JSON.parse(bytes.toString('utf8'));
}

function digest(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function verifyProducerSupport(policy, stock, { patchRoot = PATCH_ROOT } = {}) {
  assert.deepEqual(policy.schema_version, 'chiptrace.producer-support.v1');
  const contract = policy.policy;
  assert.ok(contract && typeof contract === 'object' && !Array.isArray(contract), 'policy.policy must be an object');
  assert.equal(contract.production_mode, 'patched_stock_cli');
  assert.deepEqual(contract.ci_modes, ['patched_stock_cli', 'patched_stock_debug_app_server']);
  assert.equal(contract.unmodified_stock_production_acceptance, false);
  assert.equal(contract.unmodified_stock_status, 'diagnostic_rejection_only');
  nonEmptyString(contract.unmodified_stock_reason, 'policy.unmodified_stock_reason');
  assert.deepEqual(contract.required_sources, ['wire', 'otlp_logs', 'otlp_traces', 'hooks']);
  assert.equal(contract.minimum_native_turns, 2);
  assert.equal(contract.require_delivery_ready, true);

  const producer = policy.producer;
  assert.ok(producer && typeof producer === 'object' && !Array.isArray(producer), 'policy.producer must be an object');
  assert.equal(producer.version, stock.version);
  assert.equal(producer.upstream_commit, stock.upstream_commit);
  assert.equal(producer.source_sha256, stock.source_sha256);
  assert.equal(producer.official_binary_sha256, stock.linux_x64_binary_sha256);
  assert.match(producer.upstream_commit, SHA1, 'producer.upstream_commit must be a full lowercase SHA-1');
  assert.match(producer.source_sha256, SHA256, 'producer.source_sha256 must be a SHA-256');
  assert.match(producer.official_binary_sha256, SHA256, 'producer.official_binary_sha256 must be a SHA-256');
  assert.ok(Array.isArray(producer.patches) && producer.patches.length === 7, 'exactly seven producer patches are required');

  const files = producer.patches.map((patch, index) => {
    assert.ok(patch && typeof patch === 'object' && !Array.isArray(patch), `producer.patches[${index}] must be an object`);
    const file = nonEmptyString(patch.file, `producer.patches[${index}].file`);
    assert.match(file, /^[A-Za-z0-9._-]+\.patch$/, `producer.patches[${index}].file must be a patch filename`);
    assert.match(patch.sha256, SHA256, `producer.patches[${index}].sha256 must be a SHA-256`);
    const absolute = path.resolve(patchRoot, file);
    assert.equal(absolute.startsWith(`${path.resolve(patchRoot)}${path.sep}`), true, 'patch path escapes patch root');
    assert.equal(digest(absolute), patch.sha256, `patch digest changed: ${file}`);
    assert.ok(fs.statSync(absolute).isFile(), `patch is not a regular file: ${file}`);
    return file;
  });
  assert.deepEqual(files, [
    'upstream-sse-context.patch',
    'upstream-sse-context-test.patch',
    'upstream-session-scope.patch',
    'upstream-session-scope-extension.patch',
    'upstream-session-scope-process.patch',
    'upstream-config-read-scope.patch',
    'upstream-otlp-outcome.patch',
  ]);

  return {
    schema_version: 'chiptrace.producer-support-gate.v1',
    production_mode: contract.production_mode,
    ci_modes: contract.ci_modes,
    client_version: producer.version,
    upstream_commit: producer.upstream_commit,
    patch_set: files,
    patch_digests_verified: true,
    required_sources: contract.required_sources,
    minimum_native_turns: contract.minimum_native_turns,
    unmodified_stock_production_acceptance: false,
    unmodified_stock_status: contract.unmodified_stock_status,
  };
}

function main(args = process.argv.slice(2)) {
  assert.equal(args.length, 0, 'usage: producer-support-gate.js');
  const result = verifyProducerSupport(readJson(SUPPORT_PATH), readJson(STOCK_RELEASE_PATH));
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`producer support gate: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { verifyProducerSupport };
