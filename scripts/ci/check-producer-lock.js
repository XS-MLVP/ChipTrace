'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// The pinned release tag updates workspace manifests but retains 0.0.0 in its
// lock. Allow only the corresponding local package version substitutions;
// every external dependency and every other lock byte must stay unchanged.
function verifyProducerLock(original, resolved, metadata, version) {
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
  assert.equal(resolved, expected, 'producer lock changed beyond workspace release versions');
  const digest = value => createHash('sha256').update(value, 'utf8').digest('hex');
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
  const [sourceRoot, metadataFile, version] = process.argv.slice(2);
  assert.ok(sourceRoot && metadataFile && version, 'usage: check-producer-lock.js <source-root> <metadata.json> <version>');
  const original = execFileSync('git', ['-C', sourceRoot, 'show', 'HEAD:codex-rs/Cargo.lock'], {
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
  const resolved = fs.readFileSync(path.join(sourceRoot, 'codex-rs', 'Cargo.lock'), 'utf8');
  const metadata = JSON.parse(fs.readFileSync(metadataFile, 'utf8'));
  console.log(JSON.stringify(verifyProducerLock(original, resolved, metadata, version), null, 2));
}

module.exports = { verifyProducerLock };
