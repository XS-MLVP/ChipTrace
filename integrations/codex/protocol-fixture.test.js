'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { buildProducerSandboxArgs } = require('./protocol-fixture');

test('released producer sandbox gives the private daemon socket a writable /tmp', () => {
  const args = buildProducerSandboxArgs({
    producer: '/runner/codex',
    root: '/runner/work',
    sandboxTmp: '/runner/sandbox-tmp',
    home: '/runner/work/home',
    managed: '/runner/work/managed',
  });
  assert.deepEqual(args.slice(0, 6), [
    '--unshare-user', '--unshare-pid', '--die-with-parent',
    '--ro-bind', '/', '/',
  ]);
  assert.deepEqual(args.slice(6, 10), ['--proc', '/proc', '--dev', '/dev']);
  const privateTmp = args.findIndex(value => value === '/runner/sandbox-tmp');
  assert.ok(privateTmp > 0, 'sandbox must bind the private temporary directory');
  assert.deepEqual(args.slice(privateTmp - 1, privateTmp + 2), ['--bind', '/runner/sandbox-tmp', '/tmp']);
  assert.equal(args.includes('/host/tmp'), false);
  assert.ok(args.includes('--tmpfs') && args.includes('/etc'), 'sandbox must use a private /etc');
  assert.ok(args.includes('--remount-ro') && args.includes('/etc'), 'private /etc must be remounted read-only');
  assert.deepEqual(args.slice(-8), [
    '--remount-ro', '/etc', '--chdir', '/runner/work', '--', '/runner/codex',
    '--strict-config', 'app-server',
  ]);
});

test('sandbox arguments do not expose the host daemon directory', () => {
  const args = buildProducerSandboxArgs({
    producer: '/p', root: '/r', sandboxTmp: '/private/tmp', home: '/r/home', managed: '/r/managed',
  });
  assert.equal(args.includes('/tmp/codex-daemon'), false);
  assert.equal(args.filter(value => value === '/tmp').length, 1);
  assert.equal(args.includes('--bind-try'), false);
});
