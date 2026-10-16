'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { docker, validateConfig } = require('./preflight');

const revision = '1'.repeat(40);
const repository = path.resolve(__dirname, '../..');
const variables = {
  CHIPTRACE_REVISION: revision,
  CHIPTRACE_IMAGE: `sha256:${'2'.repeat(64)}`,
  CHIPTRACE_PLATFORM_IMAGE: `registry.example/chiptrace@sha256:${'3'.repeat(64)}`,
  CHIPTRACE_NETWORK: 'synthetic-preflight-network',
  CHIPTRACE_CAPTURE_ROOT: '/synthetic-preflight/capture',
  CHIPTRACE_COLLECTOR_STATE_ROOT: '/synthetic-preflight/collector-state',
  CHIPTRACE_RELAY_ROOT: '/synthetic-preflight/relay',
  CHIPTRACE_PLATFORM_ROOT: '/synthetic-preflight/platform',
  CHIPTRACE_OBJECT_ROOT: '/synthetic-preflight/objects',
  CHIPTRACE_BACKEND: 'oss',
  CHIPTRACE_PROJECT_ID: 'synthetic-preflight',
  CHIPTRACE_INGEST_TOKEN: 'synthetic-preflight-ingest-token-32-bytes',
  CHIPTRACE_PLATFORM_TOKEN: 'synthetic-preflight-platform-token-32-bytes',
};
const files = ['deploy/collector-relay.yml', 'deploy/cloud-platform.yml'];
const baseEnvironment = Object.fromEntries(Object.entries(process.env)
  .filter(([key]) => !/^(CHIPTRACE_|AWS_|OSS_|ALIBABA_)/.test(key)));

async function render(env) {
  return JSON.parse(await docker(['compose', '--env-file', '/dev/null',
    ...files.flatMap(file => ['-f', path.join(repository, file)]),
    'config', '--format', 'json'], env));
}

test('real deployment templates require pinned images and enforce runtime isolation', async () => {
  const config = await render({ ...baseEnvironment, ...variables });
  assert.deepEqual(validateConfig(config, revision).map(item => item.name).sort(), ['collector', 'platform', 'relay']);
  for (const name of ['CHIPTRACE_IMAGE', 'CHIPTRACE_PLATFORM_IMAGE', 'CHIPTRACE_REVISION']) {
    const env = { ...baseEnvironment, ...variables };
    delete env[name];
    await assert.rejects(render(env), error => error.code !== 0 && error.stderr.includes(name));
  }
});

test('deployment preflight rejects mutable images, unknown revisions and missing isolation', async () => {
  const config = await render({ ...baseEnvironment, ...variables });
  for (const revisionValue of ['unknown', '1916836', '', 'A'.repeat(40)]) {
    assert.throws(() => validateConfig(config, revisionValue));
  }
  for (const image of ['chiptrace:latest', `chiptrace:${revision}`, 'chiptrace-platform:local', 'sha256:bad']) {
    const candidate = structuredClone(config);
    candidate.services.platform.image = image;
    assert.throws(() => validateConfig(candidate, revision), /image must be pinned/);
  }
  for (const field of ['mem_limit', 'cpus', 'pids_limit', 'read_only', 'init', 'healthcheck', 'cap_drop', 'security_opt']) {
    const candidate = structuredClone(config);
    delete candidate.services.relay[field];
    assert.throws(() => validateConfig(candidate, revision), field);
  }
  for (const user of ['root', '0:0', '10001:0', '']) {
    const candidate = structuredClone(config);
    candidate.services.collector.user = user;
    assert.throws(() => validateConfig(candidate, revision), /non-root/);
  }
  const namespaceCollision = structuredClone(config);
  const collectorCapture = namespaceCollision.services.collector.volumes
    .find(volume => volume.target === '/data/capture');
  const relayData = namespaceCollision.services.relay.volumes
    .find(volume => volume.target === '/data');
  relayData.source = collectorCapture.source;
  assert.throws(() => validateConfig(namespaceCollision, revision), /writable bind source/);
  const invalidBackend = structuredClone(config);
  invalidBackend.services.platform.environment.CHIPTRACE_BACKEND = 'local';
  assert.throws(() => validateConfig(invalidBackend, revision), /backend/);
});
