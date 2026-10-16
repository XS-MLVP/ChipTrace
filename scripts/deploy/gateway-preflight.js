'use strict';

// Validate the host-side 18084 Gateway container without reading its payloads
// or printing any environment value. The Gateway owns the durable Wire outbox,
// so it must have the same immutable-image and isolation boundary as the Rust
// Collector/Relay services.
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const run = promisify(execFile);
const IMAGE_PATTERN = /^(?:sha256:[a-f0-9]{64}|[^\s@]+@sha256:[a-f0-9]{64})$/;
const IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/;
const REVISION_PATTERN = /^[a-f0-9]{40}$/;
const USER_PATTERN = /^[1-9][0-9]*:[1-9][0-9]*$/;

function environment(config) {
  const values = new Map();
  for (const value of config?.Env || []) {
    if (typeof value !== 'string') continue;
    const separator = value.indexOf('=');
    if (separator > 0) values.set(value.slice(0, separator), value.slice(separator + 1));
  }
  return values;
}

function requireEnvironment(values, name, expected) {
  const value = values.get(name);
  assert.equal(typeof value, 'string', `${name} must be configured`);
  assert.notEqual(value, '', `${name} must not be empty`);
  if (expected !== undefined) assert.equal(value, expected, `${name} must equal ${expected}`);
}

function validateGatewayInspect(info) {
  assert.ok(info && typeof info === 'object' && !Array.isArray(info), 'docker inspect result must be an object');
  const config = info.Config;
  const host = info.HostConfig;
  assert.ok(config && typeof config === 'object', 'Config must be an object');
  assert.ok(host && typeof host === 'object', 'HostConfig must be an object');
  assert.match(config.Image || '', IMAGE_PATTERN, 'Gateway image must be pinned by SHA-256');
  assert.match(info.Image || '', IMAGE_ID_PATTERN, 'Gateway image identity must be a SHA-256');
  assert.match(config.User || '', USER_PATTERN, 'Gateway must run as a numeric non-root uid:gid');
  assert.equal(host.ReadonlyRootfs, true, 'Gateway root filesystem must be read-only');
  assert.ok(Number.isSafeInteger(host.NanoCpus) && host.NanoCpus > 0, 'Gateway CPU limit is required');
  assert.ok(Number.isSafeInteger(host.Memory) && host.Memory > 0, 'Gateway memory limit is required');
  assert.ok(Number.isSafeInteger(host.PidsLimit) && host.PidsLimit > 0, 'Gateway PID limit is required');
  assert.ok(Array.isArray(host.CapDrop) && host.CapDrop.includes('ALL'), 'Gateway capabilities must be dropped');
  assert.ok(
    Array.isArray(host.SecurityOpt)
      && host.SecurityOpt.some(value => /^no-new-privileges(?::true)?$/.test(value)),
    'Gateway no-new-privileges is required',
  );
  assert.equal(host.RestartPolicy?.Name, 'unless-stopped', 'Gateway restart policy is required');
  assert.ok(Array.isArray(config.Healthcheck?.Test) && config.Healthcheck.Test.length > 0,
    'Gateway healthcheck is required');
  assert.equal(host.LogConfig?.Type, 'json-file', 'Gateway JSON log driver is required');
  assert.ok(host.LogConfig?.Config?.['max-size'], 'Gateway log max-size is required');
  assert.ok(host.LogConfig?.Config?.['max-file'], 'Gateway log max-file is required');

  const mounts = Array.isArray(info.Mounts) ? info.Mounts : [];
  const outbox = mounts.find(mount => mount?.Destination === '/capture-outbox');
  assert.ok(outbox && outbox.RW === true, 'Gateway durable outbox must be a writable mount');
  const monitorState = mounts.find(mount => mount?.Destination === '/monitor-state');
  assert.ok(monitorState && monitorState.RW === true, 'Gateway watchdog state must be a writable mount');

  const values = environment(config);
  requireEnvironment(values, 'FULL_TRACE_CAPTURE_ENABLED', 'true');
  requireEnvironment(values, 'FULL_TRACE_CAPTURE_BODY_ENABLED', 'true');
  requireEnvironment(values, 'FULL_TRACE_CAPTURE_RELAY_URL');
  requireEnvironment(values, 'FULL_TRACE_CAPTURE_OUTBOX_DIR', '/capture-outbox');
  requireEnvironment(values, 'FULL_TRACE_CAPTURE_OUTBOX_SANITIZE', 'false');
  requireEnvironment(values, 'CHIPTRACE_INGEST_TOKEN');

  const revision = config.Labels?.['org.opencontainers.image.revision'];
  assert.match(revision || '', REVISION_PATTERN, 'Gateway OCI revision must be a full Git SHA');
  return {
    schema_version: 'chiptrace.gateway-preflight.v1',
    ok: true,
    image: config.Image,
    image_id: info.Image,
    revision,
    user: config.User,
    read_only: host.ReadonlyRootfs,
    nano_cpus: host.NanoCpus,
    memory_bytes: host.Memory,
    pids_limit: host.PidsLimit,
    durable_outbox_mount: true,
    watchdog_state_mount: true,
    full_trace_capture_enabled: true,
    body_capture_enabled: true,
  };
}

async function inspectContainer(name) {
  assert.match(name || '', /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/, 'container name is invalid');
  const { stdout } = await run('docker', ['inspect', name], {
    maxBuffer: 4 * 1024 * 1024,
  });
  const values = JSON.parse(stdout);
  assert.ok(Array.isArray(values) && values.length === 1, 'docker inspect must return one container');
  return validateGatewayInspect(values[0]);
}

async function main(argv = process.argv.slice(2)) {
  if (argv.length !== 2 || argv[0] !== '--container') {
    throw new Error('usage: gateway-preflight.js --container CONTAINER');
  }
  const result = await inspectContainer(argv[1]);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (require.main === module) {
  main().catch(error => {
    process.stderr.write(`gateway preflight failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { validateGatewayInspect, inspectContainer, main };
