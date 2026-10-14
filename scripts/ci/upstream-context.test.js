'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { verifyProducerLock } = require('./check-producer-lock');
const { verifyProducerRegressions, callbackTests, parallelTests } = require('./check-producer-regressions');

const version = '0.163.0-alpha.11';
const metadata = {
  workspace_members: ['path+file:///source/core#codex-core@0.163.0-alpha.11'],
  packages: [{ id: 'path+file:///source/core#codex-core@0.163.0-alpha.11',
    name: 'codex-core', version, source: null }],
};
const original = `version = 4

[[package]]
name = "codex-core"
version = "0.0.0"
dependencies = ["external"]

[[package]]
name = "external"
version = "0.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "original-checksum"
`;
const resolved = original.replace('version = "0.0.0"', `version = "${version}"`);

test('release reconciliation retains the complete pinned external dependency graph', () => {
  const report = verifyProducerLock(original, resolved, metadata, version);
  assert.equal(report.reconciled_workspace_packages, 1);
  assert.equal(report.external_dependencies_unchanged, true);
  assert.notEqual(report.original_lock_sha256, report.resolved_lock_sha256);
  assert.equal(verifyProducerLock(resolved, resolved, metadata, version).reconciled_workspace_packages, 0);
});

test('dependency versions, checksums, edges and extra lock bytes cannot be normalized away', () => {
  for (const changed of [
    resolved.replace('version = "0.0.0"', 'version = "0.0.1"'),
    resolved.replace('original-checksum', 'changed-checksum'),
    resolved.replace('["external"]', '["different"]'),
    resolved + '\n',
  ]) {
    assert.throws(() => verifyProducerLock(original, changed, metadata, version), /changed beyond/);
  }
});

test('package names alone do not authorize changing a sourced or non-workspace dependency', () => {
  const sourced = { ...metadata, packages: [{ ...metadata.packages[0], source: 'git+https://example.invalid' }] };
  assert.throws(() => verifyProducerLock(original, resolved, sourced, version), /changed beyond/);
  assert.throws(() => verifyProducerLock(original, resolved, { ...metadata, workspace_members: [] }, version), /changed beyond/);
  const wrongVersion = { ...metadata, packages: [{ ...metadata.packages[0], version: '0.164.0' }] };
  assert.throws(() => verifyProducerLock(original, resolved, wrongVersion, version), /unexpected manifest version/);
});

const cargoReport = names => names.map(name => `test ${name} ... ok\n`).join('')
  + `test result: ok. ${names.length} passed; 0 failed; 0 ignored; 0 measured; 2757 filtered out; finished in 0.00s\n`;

test('producer report requires the four actual named tests, not just a successful cargo exit', () => {
  assert.equal(verifyProducerRegressions(cargoReport(callbackTests), cargoReport(parallelTests)).passed_tests, 4);
  for (const callbacks of [
    cargoReport([]),
    cargoReport(callbackTests.slice(1)),
    cargoReport([...callbackTests, callbackTests[0]]),
    cargoReport(callbackTests).replace('... ok', '... FAILED'),
    cargoReport(callbackTests).replace('3 passed; 0 failed', '2 passed; 1 failed'),
  ]) {
    assert.throws(() => verifyProducerRegressions(callbacks, cargoReport(parallelTests)));
  }
  assert.throws(() => verifyProducerRegressions(cargoReport(callbackTests), cargoReport([])));
});
