'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  SEED_SCHEMA_VERSION,
  buildSeed,
  writeSeed,
} = require('./relay-quality-seed');

function coverage() {
  return {
    quality_errors: 7,
    quality_errors_by_endpoint: {
      otlp_logs: { unknown_events: 1, conversion_errors: 2, total: 3 },
      otlp_traces: { unknown_events: 0, conversion_errors: 4, total: 4 },
      hooks: { unknown_events: 0, conversion_errors: 0, total: 0 },
    },
  };
}

test('quality seed converts runtime observations without retaining health payloads', () => {
  const seed = buildSeed({ relay: { coverage: coverage() } });
  assert.deepEqual(seed, {
    schema_version: SEED_SCHEMA_VERSION,
    source_quality_errors: 7,
    counters: {
      otlp_logs_unknown_events: 1,
      otlp_logs_conversion_errors: 2,
      otlp_traces_unknown_events: 0,
      otlp_traces_conversion_errors: 4,
      codex_hook_unknown_events: 0,
      codex_hook_conversion_errors: 0,
    },
  });
  assert.equal(JSON.stringify(seed).includes('requestBody'), false);
});

test('quality seed accepts raw Relay health and rejects inconsistent evidence', () => {
  assert.equal(buildSeed({ ingest_coverage: coverage() }).source_quality_errors, 7);
  for (const invalid of [
    { ...coverage(), quality_errors: 8 },
    { ...coverage(), quality_errors_by_endpoint: { ...coverage().quality_errors_by_endpoint,
      otlp_logs: { unknown_events: 1, conversion_errors: 2, total: 4 } } },
  ]) {
    assert.throws(() => buildSeed({ ingest_coverage: invalid }), /relay quality seed:/);
  }
});

test('quality seed output is exclusive and bounded to counters', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chiptrace-quality-seed-'));
  const output = path.join(root, 'ingest-quality-seed.json');
  const result = writeSeed(output, buildSeed({ ingest_coverage: coverage() }));
  assert.equal(result.source_quality_errors, 7);
  const parsed = JSON.parse(fs.readFileSync(output, 'utf8'));
  assert.equal(parsed.source_quality_errors, 7);
  assert.deepEqual(Object.keys(parsed), ['schema_version', 'source_quality_errors', 'counters']);
  assert.throws(
    () => writeSeed(output, buildSeed({ ingest_coverage: coverage() })),
    /cannot create output/,
  );
});
