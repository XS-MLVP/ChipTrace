'use strict';

const fs = require('node:fs');

const DEFAULT_TIMEOUT_MS = 5000;
const PLATFORM_VERSION = 'chiptrace.platform.v1';
const REVISION_PATTERN = /^[a-f0-9]{40}$/;

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

function verifyPlatformHealth(health, { expectedRevision } = {}) {
  object(health, 'platform health');
  if (health.ok !== true) fail('platform health.ok must be true');
  if (health.version !== PLATFORM_VERSION) {
    fail(`platform health.version must be ${PLATFORM_VERSION}`);
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
    build_revision: buildRevision,
    expected_revision: expectedRevision ?? null,
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
    const result = verifyPlatformHealth(health, { expectedRevision });
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
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--platform-url' && value) { url = value; index += 1; }
    else if (flag === '--timeout-ms' && value) { timeout = Number(value); index += 1; }
    else if (flag === '--expected-revision' && value) { expectedRevision = value; index += 1; }
    else if (flag === '--report' && value) { report = value; index += 1; }
    else fail('usage: platform-health-gate.js --platform-url URL [--expected-revision SHA] [--timeout-ms N] [--report PATH]');
  }
  if (!url || !Number.isSafeInteger(timeout) || timeout < 100 || timeout > 120000) {
    fail('usage: platform-health-gate.js --platform-url URL [--expected-revision SHA] [--timeout-ms N] [--report PATH]');
  }
  return { url, timeout, report, expectedRevision };
}

if (require.main === module) {
  let args;
  Promise.resolve().then(async () => {
    args = parseArgs(process.argv.slice(2));
    const result = await runPlatformHealthGate({
      url: args.url, timeoutMs: args.timeout, reportPath: args.report,
      expectedRevision: args.expectedRevision,
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
  parseArgs,
  runPlatformHealthGate,
  verifyPlatformHealth,
};
