'use strict';

const fs = require('node:fs');

const SEED_SCHEMA_VERSION = 'chiptrace.ingest-quality-seed.v1';
const MAX_INPUT_BYTES = 256 * 1024;
const ENDPOINTS = ['otlp_logs', 'otlp_traces', 'hooks'];
const QUALITY_REASON_CODES = [
  'unsupported_event',
  'invalid_structure',
  'invalid_attributes',
  'identity_conflict',
  'missing_identity',
  'invalid_tool',
  'invalid_lifecycle',
  'invalid_timestamp',
  'conversion_error',
  'legacy_unclassified',
];

function fail(message) {
  throw new Error(`relay quality seed: ${message}`);
}

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

function nonNegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${label} must be a non-negative integer`);
  return value;
}

function coverageFromReport(report) {
  const value = object(report, 'report');
  if (value.relay?.coverage) return object(value.relay.coverage, 'report.relay.coverage');
  if (value.ingest_coverage) return object(value.ingest_coverage, 'report.ingest_coverage');
  fail('report must contain relay.coverage or ingest_coverage');
}

function qualityCountersFromReport(report) {
  const coverage = coverageFromReport(report);
  const qualityErrors = nonNegativeInteger(coverage.quality_errors, 'quality_errors');
  const breakdown = object(coverage.quality_errors_by_endpoint, 'quality_errors_by_endpoint');
  const counters = {};
  let total = 0;
  for (const endpoint of ENDPOINTS) {
    const route = object(breakdown[endpoint], `quality_errors_by_endpoint.${endpoint}`);
    const unknown = nonNegativeInteger(route.unknown_events, `${endpoint}.unknown_events`);
    const conversion = nonNegativeInteger(route.conversion_errors, `${endpoint}.conversion_errors`);
    const endpointTotal = nonNegativeInteger(route.total, `${endpoint}.total`);
    if (endpointTotal !== unknown + conversion) {
      fail(`${endpoint}.total must equal unknown_events + conversion_errors`);
    }
    total += endpointTotal;
    const prefix = endpoint === 'hooks' ? 'codex_hook' : endpoint;
    counters[`${prefix}_unknown_events`] = unknown;
    counters[`${prefix}_conversion_errors`] = conversion;
    if (Object.hasOwn(route, 'reasons')) {
      const reasons = object(route.reasons, `${endpoint}.reasons`);
      let reasonTotal = 0;
      const normalizedReasons = {};
      for (const [reason, count] of Object.entries(reasons)) {
        if (!QUALITY_REASON_CODES.includes(reason)) fail(`${endpoint}.reasons contains an unsupported code`);
        normalizedReasons[reason] = nonNegativeInteger(count, `${endpoint}.reasons.${reason}`);
        reasonTotal += normalizedReasons[reason];
      }
      if (reasonTotal !== endpointTotal) {
        fail(`${endpoint}.reasons total must equal endpoint total`);
      }
      counters[`${prefix}_quality_reasons`] = normalizedReasons;
    }
  }
  if (total !== qualityErrors) {
    fail(`quality error total mismatch: breakdown=${total}, quality_errors=${qualityErrors}`);
  }
  return { source_quality_errors: qualityErrors, counters };
}

function buildSeed(report) {
  const { source_quality_errors, counters } = qualityCountersFromReport(report);
  return {
    schema_version: SEED_SCHEMA_VERSION,
    source_quality_errors,
    counters,
  };
}

function readJson(inputPath) {
  let metadata;
  try {
    metadata = fs.lstatSync(inputPath);
  } catch (error) {
    fail(`cannot stat input: ${error.message}`);
  }
  if (!metadata.isFile()) fail('input must be a regular file');
  if (metadata.size > MAX_INPUT_BYTES) fail(`input exceeds ${MAX_INPUT_BYTES} bytes`);
  let bytes;
  try {
    bytes = fs.readFileSync(inputPath);
  } catch (error) {
    fail(`cannot read input: ${error.message}`);
  }
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail(`input is not valid JSON: ${error.message}`);
  }
}

function writeSeed(outputPath, seed) {
  const bytes = Buffer.from(`${JSON.stringify(seed, null, 2)}\n`, 'utf8');
  try {
    fs.writeFileSync(outputPath, bytes, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  } catch (error) {
    fail(`cannot create output: ${error.message}`);
  }
  return { path: outputPath, bytes: bytes.length, source_quality_errors: seed.source_quality_errors };
}

function parseArgs(argv) {
  let input;
  let output;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--input' && value) { input = value; index += 1; }
    else if (flag === '--output' && value) { output = value; index += 1; }
    else fail('usage: relay-quality-seed.js --input REPORT.json --output ingest-quality-seed.json');
  }
  if (!input || !output) fail('usage: relay-quality-seed.js --input REPORT.json --output ingest-quality-seed.json');
  return { input, output };
}

if (require.main === module) {
  try {
    const args = parseArgs(process.argv.slice(2));
    const result = writeSeed(args.output, buildSeed(readJson(args.input)));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  ENDPOINTS,
  QUALITY_REASON_CODES,
  MAX_INPUT_BYTES,
  SEED_SCHEMA_VERSION,
  buildSeed,
  parseArgs,
  qualityCountersFromReport,
  readJson,
  writeSeed,
};
