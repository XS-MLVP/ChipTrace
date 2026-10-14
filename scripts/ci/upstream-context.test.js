'use strict';

const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { prepareProducerLock, verifyProducerLock } = require('./check-producer-lock');
const {
  verifyProducerRegressions,
  verifyProducerSessionRegressions,
  callbackTests,
  parallelTests,
  sessionTests,
} = require('./check-producer-regressions');

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
    assert.throws(() => prepareProducerLock(original, changed, metadata, version), /changed beyond/);
  }
});

function lockCheckout(t, lock = original) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-producer-lock-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'codex-rs'));
  const file = path.join(root, 'codex-rs', 'Cargo.lock');
  fs.writeFileSync(file, lock);
  const metadataFile = path.join(root, 'metadata.json');
  fs.writeFileSync(metadataFile, JSON.stringify(metadata));
  execFileSync('git', ['init', '-q', root]);
  execFileSync('git', ['-C', root, 'add', 'codex-rs/Cargo.lock']);
  execFileSync('git', ['-C', root, '-c', 'user.name=ChipTrace CI',
    '-c', 'user.email=chiptrace-ci@example.invalid', '-c', 'commit.gpgsign=false',
    'commit', '-qm', 'pinned lock fixture']);
  const run = (...flags) => spawnSync(process.execPath,
    [path.join(__dirname, 'check-producer-lock.js'), ...flags, root, metadataFile, version],
    { encoding: 'utf8', maxBuffer: 1024 * 1024 });
  return { file, run };
}

test('CLI prepares a pristine committed lock and is idempotent before locked builds', t => {
  const { file, run } = lockCheckout(t);
  const unprepared = run();
  assert.notEqual(unprepared.status, 0);
  assert.equal(fs.readFileSync(file, 'utf8'), original);
  const prepared = run('--prepare');
  assert.equal(prepared.status, 0, prepared.stderr);
  assert.equal(fs.readFileSync(file, 'utf8'), resolved);
  assert.equal(JSON.parse(prepared.stdout).reconciled_workspace_packages, 1);
  const repeated = run('--prepare');
  assert.equal(repeated.status, 0, repeated.stderr);
  assert.equal(repeated.stdout, prepared.stdout);
  const verified = run();
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(verified.stdout, prepared.stdout);
});

test('CLI refuses dependency tampering without overwriting it or expanding large lock diagnostics', t => {
  const privateText = 'private-lock-context'.repeat(30000);
  const { file, run } = lockCheckout(t, original + `\n# ${privateText}\n`);
  const changed = fs.readFileSync(file, 'utf8').replace('original-checksum', 'changed-checksum');
  fs.writeFileSync(file, changed);
  const result = run('--prepare');
  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(file, 'utf8'), changed);
  assert.match(result.stderr, /changed beyond workspace release versions/);
  assert.match(result.stderr, /expected_sha256=[a-f0-9]{64}; actual_sha256=[a-f0-9]{64}/);
  assert.ok(result.stderr.length < 3000, 'lock diagnostics must remain bounded');
  assert.ok(!result.stderr.includes('private-lock-context'));
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

test('producer session report requires both scope propagation tests exactly once', () => {
  assert.equal(
    verifyProducerSessionRegressions(cargoReport(sessionTests)).passed_tests,
    sessionTests.length,
  );
  for (const sessionLog of [
    cargoReport([]),
    cargoReport(sessionTests.slice(1)),
    cargoReport([...sessionTests, sessionTests[0]]),
    cargoReport(sessionTests).replace('... ok', '... FAILED'),
    cargoReport(sessionTests).replace('2 passed; 0 failed', '1 passed; 1 failed'),
  ]) {
    assert.throws(() => verifyProducerSessionRegressions(sessionLog));
  }
});
