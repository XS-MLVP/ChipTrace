'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

function command(t, source, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-producer-command-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const log = path.join(root, 'producer.log');
  if (options.existing) fs.writeFileSync(log, options.existing);
  const env = { ...process.env, GITHUB_ACTIONS: 'true' };
  if (options.brokenLogger) {
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'tee'), '#!/bin/sh\n/bin/cat >/dev/null\nexit 91\n', { mode: 0o700 });
    env.PATH = bin + path.delimiter + env.PATH;
  }
  const args = options.missing ? [path.join(root, 'missing-producer-command')]
    : [process.execPath, '-e', source];
  const result = spawnSync('bash', [path.join(__dirname, 'run-producer-check.sh'), 'callbacks', log, ...args],
    { encoding: 'utf8', env, timeout: 10000, maxBuffer: 1024 * 1024 });
  assert.equal(result.error, undefined);
  return { result, log, bytes: fs.readFileSync(log, 'utf8') };
}

test('producer command retains the actual combined output and successful exit without an annotation', t => {
  const { result, bytes, log } = command(t, 'require("node:fs").writeSync(1,"stdout 中文\\n");require("node:fs").writeSync(2,"stderr\\n")');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(bytes, 'stdout 中文\nstderr\n');
  assert.equal(result.stdout, bytes);
  assert.equal(fs.statSync(log).mode & 0o077, 0);
  assert.doesNotMatch(result.stdout, /::error/);
});

test('producer command preserves real exit 77 and full logs while annotating a bounded escaped tail', t => {
  const output = 'early detail\n'.repeat(4000) + '\x1b[31mLAST_FAILURE 中文 50%\x1b[0m\nBearer synthetic-fixture-token\n';
  const { result, bytes } = command(t, 'process.stdout.write(' + JSON.stringify(output) + ');process.exitCode=77');
  assert.equal(result.status, 77, result.stderr);
  assert.equal(bytes, output);
  const annotation = result.stdout.split('\n').find(line => line.startsWith('::error title=Producer callbacks::'));
  assert.ok(annotation);
  assert.ok(annotation.length < 10000);
  assert.match(annotation, /actual exit=77; command_exit=77; log_exit=0%0A/);
  assert.match(annotation, /LAST_FAILURE 中文 50%25/);
  assert.match(annotation, /Bearer \[redacted\]/);
  assert.ok(!annotation.includes('synthetic-fixture-token'));
  assert.ok(!annotation.includes('\x1b'));
});

test('missing producer executable has a real 127 exit and actionable retained diagnostics', t => {
  const { result, bytes } = command(t, '', { missing: true });
  assert.equal(result.status, 127, result.stderr);
  assert.match(bytes, /missing-producer-command/);
  assert.match(result.stdout, /::error title=Producer callbacks::phase=callbacks; actual exit=127/);
});

test('producer termination retains the actual signal exit and its phase', t => {
  const { result } = command(t, 'process.kill(process.pid,"SIGTERM")');
  assert.equal(result.status, 143, result.stderr);
  assert.match(result.stdout, /::error title=Producer callbacks::phase=callbacks; actual exit=143/);
});

test('producer command refuses to overwrite earlier evidence before executing the child', t => {
  const { result, bytes } = command(t, 'process.stdout.write("CHILD_MUST_NOT_RUN")', { existing: 'historical failure\n' });
  assert.equal(result.status, 2);
  assert.equal(bytes, 'historical failure\n');
  assert.ok(!result.stdout.includes('CHILD_MUST_NOT_RUN'));
});

test('failed log writes cannot hide a producer failure or turn a successful child into a passing check', t => {
  for (const exit of [0, 77]) {
    const { result } = command(t, 'process.stdout.write("not retained by failed logger");process.exitCode=' + exit,
      { brokenLogger: true });
    assert.equal(result.status, exit || 91, result.stderr);
    assert.match(result.stderr, /producer log write failed/);
    assert.ok(result.stdout.includes('actual exit=' + (exit || 91)));
    assert.ok(result.stdout.includes('; command_exit=' + exit + '; log_exit=91'));
  }
});
