'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..', '..');
const {
  QUALITY_REASON_CODES: baselineCodes,
} = require('./quality-baseline');
const {
  QUALITY_REASON_CODES: seedCodes,
} = require('./relay-quality-seed');

function unique(values, label) {
  assert.equal(new Set(values).size, values.length, `${label} contains duplicate reason codes`);
  return values;
}

function rustReasonCodes() {
  const source = fs.readFileSync(path.join(root, 'crates', 'chiptrace', 'src', 'cloud_ingest.rs'), 'utf8');
  const match = source.match(/pub const QUALITY_REASON_CODES: &[^=]+ = &\[(.*?)];/s);
  assert.ok(match, 'Rust quality reason taxonomy is missing');
  return [...match[1].matchAll(/^\s*"([^"\n]+)",?\s*$/gm)].map(value => value[1]);
}

test('quality reason taxonomy is consistent across runtime, migration and Rust ingest paths', () => {
  const expected = unique(baselineCodes, 'quality baseline');
  assert.deepEqual(unique(seedCodes, 'relay quality seed'), expected,
    'relay quality seed taxonomy must match quality baseline taxonomy');

  const runtimeSource = fs.readFileSync(path.join(__dirname, 'runtime-health-gate.js'), 'utf8');
  assert.match(runtimeSource, /QUALITY_REASON_CODES/,
    'runtime health gate must consume the shared quality baseline taxonomy');

  const rust = unique(rustReasonCodes(), 'Rust ingest');
  assert.deepEqual(rust, expected.filter(code => code !== 'legacy_unclassified'),
    'Rust ingest must classify producer errors while legacy_unclassified remains migration-only');
});

test('legacy_unclassified is accepted only as historical migration evidence', () => {
  assert.ok(baselineCodes.includes('legacy_unclassified'));
  const rust = rustReasonCodes();
  assert.equal(rust.includes('legacy_unclassified'), false);
  const operations = fs.readFileSync(path.join(root, 'docs', 'operations.md'), 'utf8');
  assert.match(operations, /历史迁移专用的 `legacy_unclassified`/);
});

