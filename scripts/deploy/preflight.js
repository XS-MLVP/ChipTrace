'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const run = promisify(execFile);
const repository = path.resolve(__dirname, '../..');
const revisionPattern = /^[a-f0-9]{40}$/;
const imagePattern = /^(?:sha256:[a-f0-9]{64}|[^\s@]+@sha256:[a-f0-9]{64})$/;

async function docker(args, env = process.env, timeout = 60000) {
  const { stdout } = await run('docker', args, {
    cwd: repository, env, timeout, maxBuffer: 4 * 1024 * 1024,
  });
  return stdout;
}

function validateConfig(config, revision, { requirePlatform = true } = {}) {
  assert.match(revision || '', revisionPattern, 'expected revision must be a full Git commit SHA');
  const services = Object.entries(config.services || {});
  assert.ok(services.length, 'deployment must contain services');
  const platform = config.services.platform;
  if (requirePlatform) {
    assert.ok(platform, 'deployment must contain a platform service');
  }
  if (platform) {
    const backend = platform.environment?.CHIPTRACE_BACKEND;
    assert.ok(['fs', 'oss', 's3'].includes(backend), 'platform storage backend must be explicitly fs, oss, or s3');
    const platformRevision = platform.environment?.CHIPTRACE_BUILD_REVISION;
    assert.equal(platformRevision, revision,
      'platform health revision must be bound to the expected Git commit');
  }
  const writableBindSources = new Map();
  for (const [name, service] of services) {
    assert.ok(['collector', 'relay', 'platform'].includes(name), 'unexpected deployment service');
    assert.equal(service.build, undefined, `${name}: build images separately before deployment`);
    assert.match(service.image || '', imagePattern, `${name}: image must be pinned by SHA-256 digest or local image ID`);
    assert.equal(service.labels?.['io.chiptrace.expected-revision'], revision, `${name}: expected revision label mismatch`);
    assert.equal(service.read_only, true, `${name}: root filesystem must be read-only`);
    assert.match(service.user || '', /^[1-9][0-9]*:[1-9][0-9]*$/, `${name}: a non-root numeric uid:gid is required`);
    assert.equal(service.init, true, `${name}: init is required`);
    assert.equal(service.restart, 'unless-stopped', `${name}: restart policy is required`);
    assert.ok(service.mem_limit > 0, `${name}: a memory limit is required`);
    assert.ok(Number(service.cpus) > 0, `${name}: a CPU limit is required`);
    assert.ok(service.pids_limit > 0, `${name}: a PID limit is required`);
    assert.ok(service.cap_drop?.includes('ALL'), `${name}: capabilities must be dropped`);
    assert.ok(service.security_opt?.some(value => /^no-new-privileges(?::true)?$/.test(value)), `${name}: no-new-privileges is required`);
    assert.ok(service.healthcheck?.test?.length, `${name}: a healthcheck is required`);
    assert.ok(Array.isArray(service.volumes) && service.volumes.length > 0,
      `${name}: explicit data volumes are required`);
    if (name === 'collector' || name === 'relay') {
      const command = Array.isArray(service.command) ? service.command : [];
      const optionIndex = command.indexOf('--store-shards');
      assert.ok(optionIndex >= 0 && optionIndex + 1 < command.length,
        `${name}: --store-shards is required`);
      const shardCount = Number(command[optionIndex + 1]);
      assert.ok(Number.isInteger(shardCount) && shardCount >= 1 && shardCount <= 1024,
        `${name}: --store-shards must be an integer between 1 and 1024`);
      if (name === 'relay') {
        const deliveryIndex = command.indexOf('--delivery-concurrency');
        assert.ok(deliveryIndex >= 0 && deliveryIndex + 1 < command.length,
          'relay: --delivery-concurrency is required');
        const deliveryConcurrency = Number(command[deliveryIndex + 1]);
        assert.ok(Number.isInteger(deliveryConcurrency) && deliveryConcurrency >= 1 && deliveryConcurrency <= 128,
          'relay: --delivery-concurrency must be an integer between 1 and 128');
      }
    }
    for (const volume of service.volumes) {
      if (volume?.type !== 'bind' || volume.read_only === true) continue;
      assert.ok(typeof volume.source === 'string' && volume.source.trim() !== '',
        `${name}: writable data volume must have a host source`);
      const source = path.resolve(volume.source);
      const previous = writableBindSources.get(source);
      assert.equal(previous, undefined,
        `${name}: writable bind source ${source} is already used by ${previous?.service}`);
      writableBindSources.set(source, { service: name, target: volume.target });
    }
  }
  return services.map(([name, service]) => ({ name, image: service.image }));
}

function requiresPlatform(files, config) {
  const configuredPlatform = Object.hasOwn(config.services || {}, 'platform');
  const explicitPlatformFile = files.some(file => path.basename(file) === 'cloud-platform.yml');
  return configuredPlatform || explicitPlatformFile || files.length !== 1;
}

async function preflight({ files, revision, project, env = process.env }) {
  const compose = ['compose', '--env-file', '/dev/null'];
  for (const file of files) compose.push('-f', file);
  if (project) compose.push('--project-name', project);
  const config = JSON.parse(await docker([...compose, 'config', '--format', 'json'], env));
  const services = validateConfig(config, revision, { requirePlatform: requiresPlatform(files, config) });
  const images = new Map();
  for (const { image } of services) {
    if (images.has(image)) continue;
    const [info] = JSON.parse(await docker(['image', 'inspect', image], env));
    assert.match(info?.Id || '', /^sha256:[a-f0-9]{64}$/, 'invalid image identity');
    assert.equal(info.Config?.Labels?.['org.opencontainers.image.revision'], revision,
      'image OCI revision does not match the expected Git commit');
    images.set(image, info.Id);
  }
  return { schema_version: 'chiptrace.deployment-preflight.v1', ok: true, revision,
    services: services.map(({ name, image }) => ({ name, image_id: images.get(image),
      user: config.services[name].user, memory_bytes: Number(config.services[name].mem_limit),
      nano_cpus: Math.round(Number(config.services[name].cpus) * 1e9),
      pids_limit: Number(config.services[name].pids_limit) })) };
}

if (require.main === module) {
  const files = [];
  let project;
  let revision = process.env.CHIPTRACE_REVISION;
  for (let index = 2; index < process.argv.length; index += 2) {
    const flag = process.argv[index];
    const value = process.argv[index + 1];
    if (!value || !['--file', '--revision', '--project'].includes(flag)) throw new Error('usage: preflight.js --file COMPOSE [--file COMPOSE] [--revision SHA] [--project NAME]');
    if (flag === '--file') files.push(value);
    else if (flag === '--revision') revision = value;
    else project = value;
  }
  if (!files.length) files.push('deploy/collector-relay.yml', 'deploy/cloud-platform.yml');
  preflight({ files, revision, project }).then(result => console.log(JSON.stringify(result)))
    .catch(error => { console.error(`deployment preflight failed: ${error.message}`); process.exitCode = 1; });
}

module.exports = { docker, preflight, requiresPlatform, validateConfig };
