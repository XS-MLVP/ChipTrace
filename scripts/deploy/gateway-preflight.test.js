'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { validateGatewayInspect } = require('./gateway-preflight');

function inspect() {
  return {
    Image: `sha256:${'1'.repeat(64)}`,
    Config: {
      Image: `registry.example/chiptrace-gateway@sha256:${'2'.repeat(64)}`,
      User: '1267:1001',
      Env: [
        'FULL_TRACE_CAPTURE_ENABLED=true',
        'FULL_TRACE_CAPTURE_BODY_ENABLED=true',
        'FULL_TRACE_CAPTURE_RELAY_URL=http://chiptrace-relay:3012',
        'FULL_TRACE_CAPTURE_OUTBOX_DIR=/capture-outbox',
        'FULL_TRACE_CAPTURE_OUTBOX_SANITIZE=false',
        'CHIPTRACE_INGEST_TOKEN=private-test-token',
      ],
      Labels: { 'org.opencontainers.image.revision': 'f'.repeat(40) },
      Healthcheck: { Test: ['CMD', 'node', '-e', 'process.exit(0)'] },
    },
    HostConfig: {
      ReadonlyRootfs: true,
      NanoCpus: 1_000_000_000,
      Memory: 512 * 1024 * 1024,
      PidsLimit: 128,
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges:true'],
      RestartPolicy: { Name: 'unless-stopped' },
      LogConfig: { Type: 'json-file', Config: { 'max-size': '100m', 'max-file': '3' } },
    },
    Mounts: [
      { Destination: '/capture-outbox', RW: true },
      { Destination: '/monitor-state', RW: true },
    ],
  };
}

test('Gateway preflight accepts immutable isolated full-trace configuration', () => {
  const result = validateGatewayInspect(inspect(), { expectedRevision: 'f'.repeat(40) });
  assert.equal(result.schema_version, 'chiptrace.gateway-preflight.v1');
  assert.equal(result.ok, true);
  assert.equal(result.expected_revision, 'f'.repeat(40));
  assert.equal(result.full_trace_capture_enabled, true);
  assert.equal(result.body_capture_enabled, true);
  assert.equal(Object.hasOwn(result, 'ingest_token'), false);
});

test('Gateway preflight rejects a revision that is not the release revision', () => {
  assert.throws(
    () => validateGatewayInspect(inspect(), { expectedRevision: 'e'.repeat(40) }),
    /Gateway OCI revision must equal/,
  );
  assert.throws(
    () => validateGatewayInspect(inspect(), { expectedRevision: 'short' }),
    /expected Gateway revision must be a full Git SHA/,
  );
});

test('Gateway preflight rejects mutable images and missing isolation', () => {
  for (const change of [
    value => { value.Config.Image = 'weishaw/claude-relay-service:latest'; },
    value => { value.HostConfig.ReadonlyRootfs = false; },
    value => { value.HostConfig.NanoCpus = 0; },
    value => { value.HostConfig.Memory = 0; },
    value => { value.HostConfig.PidsLimit = 0; },
    value => { value.HostConfig.CapDrop = []; },
    value => { value.HostConfig.SecurityOpt = []; },
    value => { value.Config.Env = value.Config.Env.map(item => item === 'FULL_TRACE_CAPTURE_OUTBOX_SANITIZE=false' ? 'FULL_TRACE_CAPTURE_OUTBOX_SANITIZE=true' : item); },
    value => { value.Config.Env = value.Config.Env.filter(item => !item.startsWith('CHIPTRACE_INGEST_TOKEN=')); },
    value => { value.Mounts = value.Mounts.filter(item => item.Destination !== '/capture-outbox'); },
  ]) {
    const value = inspect();
    change(value);
    assert.throws(() => validateGatewayInspect(value));
  }
});

test('Gateway preflight never includes private environment values in its summary', () => {
  const result = validateGatewayInspect(inspect());
  assert.doesNotMatch(JSON.stringify(result), /private-test-token/);
});
