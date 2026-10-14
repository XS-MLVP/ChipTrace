'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// The pinned release tag updates workspace manifests but retains 0.0.0 in its
// lock. Allow only the corresponding local package version substitutions;
// every external dependency and every other lock byte must stay unchanged.
function expectedProducerLock(original, metadata, version) {
  assert.match(version, /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/);
  assert.ok(Array.isArray(metadata.workspace_members));
  assert.ok(Array.isArray(metadata.packages));
  const members = new Set(metadata.workspace_members);
  const packages = new Map(metadata.packages
    .filter(pkg => pkg.source === null && members.has(pkg.id))
    .map(pkg => [pkg.name, pkg]));
  let reconciled = 0;
  const expected = original.split(/(?=^\[\[package\]\]$)/m).map(block => {
    if (!block.startsWith('[[package]]') || /^source = /m.test(block)) return block;
    const name = /^name = "([^"]+)"$/m.exec(block)?.[1];
    const pkg = packages.get(name);
    if (!pkg || !/^version = "0\.0\.0"$/m.test(block)) return block;
    assert.equal(pkg.version, version, `unexpected manifest version for ${name}`);
    reconciled++;
    return block.replace(/^version = "0\.0\.0"$/m, `version = "${version}"`);
  }).join('');
  return { expected, reconciled };
}

const digest = value => createHash('sha256').update(value, 'utf8').digest('hex');

function assertLockMatches(resolved, expected) {
  // Never attach the whole lock to an assertion: Cargo.lock is hundreds of KB.
  assert.ok(resolved === expected,
    `producer lock changed beyond workspace release versions; expected_sha256=${digest(expected)}; actual_sha256=${digest(resolved)}`);
}

function prepareProducerLock(original, current, metadata, version) {
  const { expected } = expectedProducerLock(original, metadata, version);
  // A pristine checkout and an already prepared checkout are the only inputs
  // we may write. In particular, do not repair an altered dependency graph.
  if (current !== original) assertLockMatches(current, expected);
  return expected;
}

function verifyProducerLock(original, resolved, metadata, version) {
  const { expected, reconciled } = expectedProducerLock(original, metadata, version);
  assertLockMatches(resolved, expected);
  return {
    schema_version: 'chiptrace.producer-lock-check.v1',
    workspace_version: version,
    reconciled_workspace_packages: reconciled,
    original_lock_sha256: digest(original),
    resolved_lock_sha256: digest(resolved),
    external_dependencies_unchanged: true,
  };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const prepare = args[0] === '--prepare';
  if (prepare) args.shift();
  const [sourceRoot, metadataFile, version] = args;
  assert.ok(args.length === 3 && sourceRoot && metadataFile && version,
    'usage: check-producer-lock.js [--prepare] <source-root> <metadata.json> <version>');
  const original = execFileSync('git', ['-C', sourceRoot, 'show', 'HEAD:codex-rs/Cargo.lock'], {
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
  const lockFile = path.join(sourceRoot, 'codex-rs', 'Cargo.lock');
  const current = fs.readFileSync(lockFile, 'utf8');
  const metadata = JSON.parse(fs.readFileSync(metadataFile, 'utf8'));
  if (prepare) {
    const expected = prepareProducerLock(original, current, metadata, version);
    if (current !== expected) fs.writeFileSync(lockFile, expected, 'utf8');
  }
  const resolved = fs.readFileSync(lockFile, 'utf8');
  console.log(JSON.stringify(verifyProducerLock(original, resolved, metadata, version), null, 2));
}

module.exports = { prepareProducerLock, verifyProducerLock };
