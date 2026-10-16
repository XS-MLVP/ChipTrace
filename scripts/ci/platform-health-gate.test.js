'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { PLATFORM_VERSION, verifyPlatformHealth } = require('./platform-health-gate');

function health() {
  return {
    ok: true,
    version: PLATFORM_VERSION,
    queued: 0,
    running: 0,
    active_reads: 0,
    jobs: 0,
    failure: null,
  };
}

test('platform health gate accepts a ready export service', () => {
  const result = verifyPlatformHealth(health());
  assert.deepEqual(result, {
    schema_version: 'chiptrace.platform-health-gate.v1',
    ok: true,
    version: PLATFORM_VERSION,
    build_revision: null,
    expected_revision: null,
    queued: 0,
    running: 0,
    active_reads: 0,
    jobs: 0,
  });
});

test('platform health gate binds the running service to the release revision', () => {
  const revision = 'f'.repeat(40);
  const value = { ...health(), build: { revision } };
  const result = verifyPlatformHealth(value, { expectedRevision: revision });
  assert.equal(result.build_revision, revision);
  assert.equal(result.expected_revision, revision);
  assert.throws(
    () => verifyPlatformHealth(value, { expectedRevision: 'e'.repeat(40) }),
    /platform health\.build\.revision must equal/,
  );
  assert.throws(
    () => verifyPlatformHealth(health(), { expectedRevision: revision }),
    /platform health\.build\.revision must equal/,
  );
});

test('platform health gate rejects stale, failed, or malformed service state', () => {
  for (const change of [
    value => { value.ok = false; },
    value => { value.version = 'chiptrace.platform.v0'; },
    value => { value.failure = { code: 'SHUTDOWN' }; },
    value => { value.queued = -1; },
    value => { delete value.running; },
    value => { value.jobs = 1.5; },
    value => { value.build = { revision: 'short' }; },
  ]) {
    const value = health();
    change(value);
    assert.throws(() => verifyPlatformHealth(value), /platform health gate:/);
  }
});
