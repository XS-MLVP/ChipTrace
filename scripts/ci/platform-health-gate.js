'use strict';

const fs = require('node:fs');

const DEFAULT_TIMEOUT_MS = 5000;
const PLATFORM_VERSION = 'chiptrace.platform.v1';
const REVISION_PATTERN = /^[a-f0-9]{40}$/;
const STORAGE_BACKENDS = Object.freeze(['fs', 'oss', 's3']);

function fail(message) {
  throw new Error(`platform health gate: ${message}`);
}

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function nonNegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${label} must be a non-negative integer`);
  }
  return value;
}

function verifyPlatformHealth(health, { expectedRevision, expectedBackend } = {}) {
  object(health, 'platform health');
  if (health.ok !== true) fail('platform health.ok must be true');
  if (health.version !== PLATFORM_VERSION) {
    fail(`platform health.version must be ${PLATFORM_VERSION}`);
  }
  if (typeof health.backend !== 'string' || !STORAGE_BACKENDS.includes(health.backend)) {
    fail('platform health.backend must be one of fs, oss, or s3');
  }
  if (expectedBackend !== undefined && !STORAGE_BACKENDS.includes(expectedBackend)) {
    fail('expected platform backend must be one of fs, oss, or s3');
  }
  if (expectedBackend !== undefined && health.backend !== expectedBackend) {
    fail(`platform health.backend must equal ${expectedBackend}`);
  }
  if (expectedRevision !== undefined && !REVISION_PATTERN.test(expectedRevision)) {
    fail('expected platform revision must be a full Git SHA');
  }
  let buildRevision = null;
  if (health.build !== undefined) {
    const build = object(health.build, 'platform health.build');
    if (build.revision !== null && build.revision !== undefined) {
      if (typeof build.revision !== 'string' || !REVISION_PATTERN.test(build.revision)) {
        fail('platform health.build.revision must be a full Git SHA');
      }
      buildRevision = build.revision;
    }
  }
  if (expectedRevision !== undefined && buildRevision !== expectedRevision) {
    fail(`platform health.build.revision must equal ${expectedRevision}`);
  }
  const counters = {};
  for (const name of ['queued', 'running', 'active_reads', 'jobs']) {
    counters[name] = nonNegativeInteger(health[name], `platform health.${name}`);
  }
  if (health.failure !== null) fail('platform health.failure must be null');
  return {
    schema_version: 'chiptrace.platform-health-gate.v1',
    ok: true,
    version: health.version,
    backend: health.backend,
    build_revision: buildRevision,
    expected_revision: expectedRevision ?? null,
    expected_backend: expectedBackend ?? null,
    ...counters,
  };
}

function writeReport(reportPath, value) {
  if (!reportPath) return;
  fs.writeFileSync(reportPath, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: 'utf8', mode: 0o600, flag: 'wx',
  });
}

async function runPlatformHealthGate({
  url,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  reportPath,
  expectedRevision,
  expectedBackend,
  fetchImpl = fetch,
} = {}) {
  if (typeof url !== 'string' || url.trim() === '') fail('platform health URL is required');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) {
    fail('timeout must be an integer between 100ms and 120000ms');
  }
  let health;
  try {
    const response = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) fail(`platform health returned HTTP ${response.status}`);
    health = await response.json();
  } catch (error) {
    writeReport(reportPath, {
      schema_version: 'chiptrace.platform-health-gate.v1',
      ok: false,
      failure_kind: 'fetch_failed',
    });
    if (error?.message?.startsWith('platform health gate:')) throw error;
    fail(`cannot fetch platform health: ${error.message}`);
  }
  try {
    const result = verifyPlatformHealth(health, { expectedRevision, expectedBackend });
    writeReport(reportPath, result);
    return result;
  } catch (error) {
    writeReport(reportPath, {
      schema_version: 'chiptrace.platform-health-gate.v1',
      ok: false,
      failure_kind: 'validation_failed',
    });
    throw error;
  }
}

function parseArgs(argv) {
  let url;
  let timeout = DEFAULT_TIMEOUT_MS;
  let report;
  let expectedRevision;
  let expectedBackend;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--platform-url' && value) { url = value; index += 1; }
    else if (flag === '--timeout-ms' && value) { timeout = Number(value); index += 1; }
    else if (flag === '--expected-revision' && value) { expectedRevision = value; index += 1; }
    else if (flag === '--expected-backend' && value) { expectedBackend = value; index += 1; }
    else if (flag === '--report' && value) { report = value; index += 1; }
    else fail('usage: platform-health-gate.js --platform-url URL [--expected-revision SHA] [--expected-backend fs|oss|s3] [--timeout-ms N] [--report PATH]');
  }
  if (!url || !Number.isSafeInteger(timeout) || timeout < 100 || timeout > 120000) {
    fail('usage: platform-health-gate.js --platform-url URL [--expected-revision SHA] [--expected-backend fs|oss|s3] [--timeout-ms N] [--report PATH]');
  }
  return { url, timeout, report, expectedRevision, expectedBackend };
}

if (require.main === module) {
  let args;
  Promise.resolve().then(async () => {
    args = parseArgs(process.argv.slice(2));
    const result = await runPlatformHealthGate({
      url: args.url, timeoutMs: args.timeout, reportPath: args.report,
      expectedRevision: args.expectedRevision, expectedBackend: args.expectedBackend,
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  }).catch(error => {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  PLATFORM_VERSION,
  STORAGE_BACKENDS,
  parseArgs,
  runPlatformHealthGate,
  verifyPlatformHealth,
};
