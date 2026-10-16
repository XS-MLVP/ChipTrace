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

function validateConfig(config, revision) {
  assert.match(revision || '', revisionPattern, 'expected revision must be a full Git commit SHA');
  const services = Object.entries(config.services || {});
  assert.ok(services.length, 'deployment must contain services');
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
  }
  return services.map(([name, service]) => ({ name, image: service.image }));
}

async function preflight({ files, revision, project, env = process.env }) {
  const compose = ['compose', '--env-file', '/dev/null'];
  for (const file of files) compose.push('-f', file);
  if (project) compose.push('--project-name', project);
  const config = JSON.parse(await docker([...compose, 'config', '--format', 'json'], env));
  const services = validateConfig(config, revision);
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

module.exports = { docker, preflight, validateConfig };
