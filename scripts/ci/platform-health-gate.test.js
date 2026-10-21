'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { PLATFORM_VERSION, verifyPlatformHealth } = require('./platform-health-gate');

function health() {
  return {
    ok: true,
    version: PLATFORM_VERSION,
    backend: 'oss',
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
    backend: 'oss',
    build_revision: null,
    expected_revision: null,
    expected_backend: null,
    queued: 0,
    running: 0,
    active_reads: 0,
    jobs: 0,
  });
});

test('platform health gate binds the running service to the release revision', () => {
  const revision = 'f'.repeat(40);
  const value = { ...health(), build: { revision } };
  const result = verifyPlatformHealth(value, { expectedRevision: revision, expectedBackend: 'oss' });
  assert.equal(result.build_revision, revision);
  assert.equal(result.expected_revision, revision);
  assert.equal(result.backend, 'oss');
  assert.equal(result.expected_backend, 'oss');
  assert.throws(
    () => verifyPlatformHealth(value, { expectedRevision: 'e'.repeat(40) }),
    /platform health\.build\.revision must equal/,
  );
  assert.throws(
    () => verifyPlatformHealth(health(), { expectedRevision: revision }),
    /platform health\.build\.revision must equal/,
  );
});

test('platform health gate rejects backend drift from the production contract', () => {
  const value = { ...health(), backend: 'fs' };
  assert.throws(
    () => verifyPlatformHealth(value, { expectedBackend: 'oss' }),
    /platform health\.backend must equal oss/,
  );
  for (const backend of [undefined, '', 'minio', 'OSS']) {
    const candidate = { ...health(), backend };
    assert.throws(() => verifyPlatformHealth(candidate), /platform health\.backend/);
  }
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
    value => { value.backend = 'disk'; },
  ]) {
    const value = health();
    change(value);
    assert.throws(() => verifyPlatformHealth(value), /platform health gate:/);
  }
});
