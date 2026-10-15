'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA = 'chiptrace.producer-source-cache.v1';
const SOURCE_TIME = 946684800; // 2000-01-01 UTC; always older than compiled artifacts.
const sha256 = value => createHash('sha256').update(value).digest('hex');

function prepareProducerSourceCache(sourceRoot, expectedDigest) {
  const root = fs.realpathSync(sourceRoot);
  const git = args => execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  });
  assert.equal(fs.realpathSync(git(['rev-parse', '--show-toplevel']).trim()), root,
    'producer source must be a Git checkout root');
  const upstreamCommit = git(['rev-parse', 'HEAD']).trim();
  assert.match(upstreamCommit, /^[a-f0-9]{40}$/);
  // In CI this is a clean, pinned checkout with only the declared patches and
  // reconciled lock applied. Include untracked patch additions as well as every
  // tracked input, not just Cargo manifests or the patch filenames.
  const files = [...new Set(git(['ls-files', '-z', '--cached', '--others',
    '--exclude-standard']).split('\0').filter(Boolean))].sort();
  assert.ok(files.length > 0, 'producer source snapshot is empty');
  const included = new Set(files);
  const hash = createHash('sha256');
  hash.update(JSON.stringify([SCHEMA, upstreamCommit, sha256(fs.readFileSync(__filename))]));
  const entries = [];
  const directories = new Set([root]);
  const buffer = Buffer.alloc(64 * 1024);
  let sourceBytes = 0;
  for (const relative of files) {
    const file = path.resolve(root, relative);
    assert.ok(file.startsWith(`${root}${path.sep}`), 'source path escapes checkout');
    let stat;
    try {
      stat = fs.lstatSync(file);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      hash.update(JSON.stringify([relative, 'deleted']));
      continue;
    }
    const content = createHash('sha256');
    let bytes = 0;
    if (stat.isSymbolicLink()) {
      const target = fs.realpathSync(file);
      assert.ok(target.startsWith(`${root}${path.sep}`)
        && included.has(path.relative(root, target)) && fs.lstatSync(target).isFile(),
      'producer symlink target must be an included source file');
      const link = Buffer.from(fs.readlinkSync(file));
      content.update(link);
      bytes = link.length;
    } else {
      assert.ok(stat.isFile(), 'producer snapshot contains an unsupported entry');
      const fd = fs.openSync(file, 'r');
      try {
        let count;
        while ((count = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) {
          content.update(buffer.subarray(0, count));
          bytes += count;
        }
      } finally {
        fs.closeSync(fd);
      }
    }
    hash.update(JSON.stringify([relative, stat.isSymbolicLink() ? 'symlink' : 'file',
      Boolean(stat.mode & 0o111), bytes, content.digest('hex')]));
    sourceBytes += bytes;
    entries.push({ file, symlink: stat.isSymbolicLink() });
    for (let dir = path.dirname(file); dir !== root; dir = path.dirname(dir)) {
      directories.add(dir);
    }
  }
  const digest = hash.digest('hex');
  if (expectedDigest !== undefined) {
    assert.match(expectedDigest, /^[a-f0-9]{64}$/);
    // Never normalize changed inputs under an old cache identity. The workflow
    // also places this digest in rust-cache's restore prefix, so even fallback
    // restores are confined to the exact same patched source bytes and modes.
    assert.ok(digest === expectedDigest,
      `producer source changed after cache identity; expected_sha256=${expectedDigest}; actual_sha256=${digest}`);
    for (const entry of entries) {
      if (entry.symlink) fs.lutimesSync(entry.file, SOURCE_TIME, SOURCE_TIME);
      else fs.utimesSync(entry.file, SOURCE_TIME, SOURCE_TIME);
    }
    for (const dir of [...directories].sort((a, b) => b.length - a.length)) {
      fs.utimesSync(dir, SOURCE_TIME, SOURCE_TIME);
    }
  }
  return {
    schema_version: SCHEMA,
    upstream_commit: upstreamCommit,
    source_sha256: digest,
    source_files: entries.length,
    source_bytes: sourceBytes,
    source_mtime_epoch_seconds: SOURCE_TIME,
    normalized: expectedDigest !== undefined,
  };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const normalize = args[0] === '--normalize';
  if (normalize) args.shift();
  assert.equal(args.length, normalize ? 2 : 1,
    'usage: producer-source-cache.js [--normalize] <source-root> [expected-sha256]');
  console.log(JSON.stringify(prepareProducerSourceCache(args[0], normalize ? args[1] : undefined), null, 2));
}

module.exports = { prepareProducerSourceCache };
