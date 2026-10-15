'use strict';

const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { prepareProducerSourceCache } = require('./producer-source-cache');

function checkout(t) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-producer-cache-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const root = path.join(temporary, 'source');
  fs.mkdirSync(root);
  const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
  git('init', '-q');
  const commit = () => {
    git('add', '.');
    git('-c', 'user.name=ChipTrace CI', '-c', 'user.email=chiptrace-ci@example.invalid',
      '-c', 'commit.gpgsign=false', 'commit', '-qm', 'source snapshot');
  };
  const write = (name, body) => fs.writeFileSync(path.join(root, name), body);
  write('.gitignore', '/target/\n');
  write('source.rs', 'const VALUE: u8 = 1;\n');
  write('Cargo.lock', 'version = 4\n');
  commit();
  return { root, temporary, write, git, commit };
}

test('cache identity covers actual source, lock, new files, modes, deletions and upstream identity', t => {
  const { root, write, commit } = checkout(t);
  const original = prepareProducerSourceCache(root);
  const file = path.join(root, 'source.rs');
  const oldTime = fs.statSync(file).mtimeMs;
  assert.equal(original.normalized, false);
  assert.equal(fs.statSync(file).mtimeMs, oldTime);
  fs.utimesSync(file, 1700000000, 1700000000);
  assert.equal(prepareProducerSourceCache(root).source_sha256, original.source_sha256);
  write('source.rs', 'const VALUE: u8 = 2;\n');
  assert.notEqual(prepareProducerSourceCache(root).source_sha256, original.source_sha256);
  const changedTime = fs.statSync(file).mtimeMs;
  assert.throws(() => prepareProducerSourceCache(root, original.source_sha256), /source changed/);
  assert.equal(fs.statSync(file).mtimeMs, changedTime);
  write('source.rs', 'const VALUE: u8 = 1;\n');
  for (const [name, body] of [['Cargo.lock', 'version = 3\n'], ['new.rs', '// patch addition\n']]) {
    write(name, body);
    assert.notEqual(prepareProducerSourceCache(root).source_sha256, original.source_sha256);
    if (name === 'Cargo.lock') write(name, 'version = 4\n');
    else fs.unlinkSync(path.join(root, name));
  }
  fs.chmodSync(file, 0o755);
  assert.notEqual(prepareProducerSourceCache(root).source_sha256, original.source_sha256);
  fs.chmodSync(file, 0o644);
  fs.unlinkSync(file);
  assert.notEqual(prepareProducerSourceCache(root).source_sha256, original.source_sha256);
  write('source.rs', 'const VALUE: u8 = 1;\n');
  write('new.rs', '// new upstream revision\n');
  commit();
  fs.unlinkSync(path.join(root, 'new.rs'));
  assert.notEqual(prepareProducerSourceCache(root).source_sha256, original.source_sha256);
});

test('normalization keeps bytes and symlink targets intact and excludes ignored artifacts', t => {
  const { root, temporary, git, commit } = checkout(t);
  const outside = path.join(temporary, 'outside');
  fs.writeFileSync(outside, 'unchanged symlink target');
  const outsideTime = fs.statSync(outside).mtimeMs;
  fs.symlinkSync('../outside', path.join(root, 'link'));
  assert.throws(() => prepareProducerSourceCache(root), /symlink target must be an included source file/);
  assert.equal(fs.statSync(outside).mtimeMs, outsideTime);
  fs.unlinkSync(path.join(root, 'link'));
  fs.symlinkSync('source.rs', path.join(root, 'link'));
  commit();
  const report = prepareProducerSourceCache(root);
  fs.mkdirSync(path.join(root, 'target'));
  fs.writeFileSync(path.join(root, 'target', 'ignored'), 'build output');
  const result = prepareProducerSourceCache(root, report.source_sha256);
  assert.equal(result.normalized, true);
  assert.equal(result.source_sha256, report.source_sha256);
  assert.equal(fs.statSync(outside).mtimeMs, outsideTime);
  assert.equal(fs.readlinkSync(path.join(root, 'link')), 'source.rs');
  assert.equal(fs.statSync(path.join(root, 'source.rs')).mtimeMs, 946684800000);
  assert.equal(git('diff', '--exit-code'), '');
});

test('real Cargo reuses identical source and executes tests again; changed source gets a new build and failure', t => {
  const { root, temporary, write, commit } = checkout(t);
  write('Cargo.toml', '[package]\nname = "producer-cache-regression"\nversion = "0.1.0"\nedition = "2021"\n');
  fs.mkdirSync(path.join(root, 'src'));
  write('src/lib.rs', 'pub const VALUE: u8 = 1;\n#[test] fn value_is_current() { assert_eq!(VALUE, 1); }\n');
  execFileSync('cargo', ['generate-lockfile', '--offline'], { cwd: root, stdio: 'pipe' });
  commit();
  const run = digest => spawnSync('cargo', ['test', '--locked', '--offline', '--lib', '-v'], {
    cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024,
    env: { ...process.env, CARGO_INCREMENTAL: '0', RUSTC_WRAPPER: '',
      RUSTC_WORKSPACE_WRAPPER: '', CARGO_TARGET_DIR: path.join(temporary, 'targets', digest) },
  });
  const first = prepareProducerSourceCache(root);
  prepareProducerSourceCache(root, first.source_sha256);
  const cold = run(first.source_sha256);
  assert.equal(cold.status, 0, cold.stderr);
  assert.match(cold.stderr, /Compiling producer-cache-regression/);
  assert.match(cold.stdout, /test value_is_current \.\.\. ok/);
  // Reproduce fresh-checkout timestamps without changing source bytes.
  fs.utimesSync(path.join(root, 'src', 'lib.rs'), 1800000000, 1800000000);
  assert.equal(prepareProducerSourceCache(root).source_sha256, first.source_sha256);
  prepareProducerSourceCache(root, first.source_sha256);
  const warm = run(first.source_sha256);
  assert.equal(warm.status, 0, warm.stderr);
  assert.match(warm.stderr, /Fresh producer-cache-regression/);
  assert.doesNotMatch(warm.stderr, /Compiling producer-cache-regression/);
  assert.match(warm.stdout, /test value_is_current \.\.\. ok/);
  write('src/lib.rs', 'pub const VALUE: u8 = 2;\n#[test] fn value_is_current() { assert_eq!(VALUE, 1); }\n');
  const changed = prepareProducerSourceCache(root);
  assert.notEqual(changed.source_sha256, first.source_sha256);
  assert.throws(() => prepareProducerSourceCache(root, first.source_sha256), /source changed/);
  prepareProducerSourceCache(root, changed.source_sha256);
  const failed = run(changed.source_sha256);
  assert.equal(failed.status, 101, failed.stderr);
  assert.match(failed.stderr, /Compiling producer-cache-regression/);
  assert.match(failed.stdout, /test value_is_current \.\.\. FAILED/);
});
