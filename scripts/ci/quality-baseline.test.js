'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const {
  buildBaseline,
  compareQualityBaseline,
  sha256Hex,
  verifyQualityBaseline,
  writeBaseline,
} = require('./quality-baseline');

function coverage() {
  return {
    quality_errors_scope: 'durable_relay_state',
    quality_reason_breakdown_complete: true,
    quality_errors: 3,
    quality_errors_by_endpoint: {
      otlp_logs: {
        unknown_events: 1,
        conversion_errors: 0,
        total: 1,
        reasons: { unsupported_event: 1 },
      },
      otlp_traces: {
        unknown_events: 0,
        conversion_errors: 2,
        total: 2,
        reasons: { invalid_lifecycle: 2 },
      },
      hooks: { unknown_events: 0, conversion_errors: 0, total: 0, reasons: {} },
    },
  };
}

function baseline() {
  return buildBaseline({ ingest_coverage: coverage() }, {
    sourceReportSha256: sha256Hex(Buffer.from('audited-report', 'utf8')),
    approvedBy: 'release-owner',
    approvedAt: '2026-10-19T00:00:00Z',
    approvalNote: 'Audited historical ledger before producer repair.',
  });
}

test('quality baseline is content addressed and preserves the complete reason ledger', () => {
  const value = baseline();
  assert.equal(value.schema_version, 'chiptrace.quality-baseline.v1');
  assert.equal(value.quality_errors, 3);
  assert.equal(value.baseline_id.length, 64);
  assert.deepEqual(verifyQualityBaseline(value), {
    ...value,
  });
});

test('baseline comparison accepts the same ledger and counts only post-baseline errors', () => {
  const value = baseline();
  const current = coverage();
  current.quality_errors = 5;
  current.quality_errors_by_endpoint.otlp_traces.conversion_errors = 4;
  current.quality_errors_by_endpoint.otlp_traces.total = 4;
  current.quality_errors_by_endpoint.otlp_traces.reasons = { invalid_lifecycle: 4 };
  const result = compareQualityBaseline(current, value);
  assert.equal(result.baseline_id, value.baseline_id);
  assert.equal(result.baseline_quality_errors, 3);
  assert.equal(result.current_quality_errors, 5);
  assert.equal(result.new_quality_errors, 2);
});

test('comparison rejects a reset or replaced ledger even when total quality errors is lower', () => {
  const value = baseline();
  const current = coverage();
  current.quality_errors = 0;
  current.quality_errors_by_endpoint = {
    otlp_logs: { unknown_events: 0, conversion_errors: 0, total: 0, reasons: {} },
    otlp_traces: { unknown_events: 0, conversion_errors: 0, total: 0, reasons: {} },
    hooks: { unknown_events: 0, conversion_errors: 0, total: 0, reasons: {} },
  };
  assert.throws(() => compareQualityBaseline(current, value), /quality counter regressed/);
});

test('an approved quality archive keeps the comparison monotonic', () => {
  const value = baseline();
  const archived = coverage();
  const live = coverage();
  live.quality_errors = 1;
  live.quality_errors_by_endpoint = {
    otlp_logs: { unknown_events: 0, conversion_errors: 0, total: 0, reasons: {} },
    otlp_traces: { unknown_events: 0, conversion_errors: 0, total: 0, reasons: {} },
    hooks: { unknown_events: 0, conversion_errors: 1, total: 1, reasons: { invalid_tool: 1 } },
  };
  live.quality_errors_archived_total = archived.quality_errors;
  live.quality_errors_archived_by_endpoint = archived.quality_errors_by_endpoint;

  const result = compareQualityBaseline(live, value);
  // The live ledger is zero for the historical reasons, yet the effective
  // total still carries them, so only the genuinely new hook error is new.
  assert.equal(result.current_live_quality_errors, 1);
  assert.equal(result.archived_quality_errors, 3);
  assert.equal(result.current_quality_errors, 4);
  assert.equal(result.new_quality_errors, 1);

  // A live ledger that loses an archived reason is still a regression.
  const lossy = { ...live, quality_errors_archived_by_endpoint: {
    otlp_logs: { unknown_events: 1, conversion_errors: 0, total: 1, reasons: { unsupported_event: 1 } },
    otlp_traces: { unknown_events: 0, conversion_errors: 0, total: 0, reasons: {} },
    hooks: { unknown_events: 0, conversion_errors: 0, total: 0, reasons: {} },
  } };
  assert.throws(() => compareQualityBaseline(lossy, value), /regressed/);
});

test('tampering with approval or counts invalidates the baseline hash', () => {
  const value = baseline();
  value.approval_note = 'changed';
  assert.throws(() => verifyQualityBaseline(value), /baseline_id does not match the content/);
});

test('baseline output is exclusive and cannot be overwritten', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-quality-baseline-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const output = path.join(root, 'baseline.json');
  const result = writeBaseline(output, baseline());
  assert.equal(result.baseline_id.length, 64);
  assert.throws(() => writeBaseline(output, baseline()), /EEXIST/);
});

test('CLI requires explicit approval metadata and creates a verified artifact', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-quality-baseline-cli-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const input = path.join(root, 'report.json');
  const output = path.join(root, 'baseline.json');
  const report = { ingest_coverage: coverage() };
  await fs.writeFile(input, JSON.stringify(report));
  const command = require.resolve('./quality-baseline');
  const result = await promisify(execFile)(process.execPath, [command,
    '--input', input, '--output', output,
    '--approved-by', 'release-owner',
    '--approved-at', '2026-10-19T00:00:00Z',
    '--approval-note', 'Audited historical ledger.',
  ]);
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.path, output);
  const written = JSON.parse(await fs.readFile(output, 'utf8'));
  assert.equal(verifyQualityBaseline(written).baseline_id, summary.baseline_id);
  await assert.rejects(promisify(execFile)(process.execPath, [command,
    '--input', input, '--output', path.join(root, 'missing-approval.json'),
  ]), error => error.code === 1 && /approved-by/.test(error.stderr));
});
