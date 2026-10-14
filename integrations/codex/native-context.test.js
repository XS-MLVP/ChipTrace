'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const run = promisify(execFile);
const binary = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/debug/chiptrace');
const fixtureFile = path.resolve(__dirname, '../../fixtures/native-context-0163.json');

function batch(endpoint, raw, records) {
  const rawJson = JSON.stringify(raw);
  return { captureId: `cap-context-${endpoint}`, recordType: 'telemetry_batch', telemetryBatch: {
    schema_version: 'chiptrace.telemetry-batch.v1', endpoint, raw_json: rawJson,
    raw_bytes: Buffer.byteLength(rawJson), raw_sha256: crypto.createHash('sha256').update(rawJson).digest('hex'),
    source_records: records, derived_captures: 0, unknown_events: 0, conversion_errors: [],
  } };
}

async function input(t, captures) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-context-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'input.ndjson');
  const bytes = Buffer.from(captures.map(c => JSON.stringify(c)).join('\n') + '\n');
  await fs.writeFile(file, bytes, { mode: 0o400 });
  return { root, file, bytes };
}

test('real native metadata gaps stay visible without printing payloads or writing input', { timeout: 30000 }, async t => {
  const fixture = JSON.parse(await fs.readFile(fixtureFile, 'utf8'));
  assert.equal(fixture.provenance.kind, 'redacted_metadata_subset');
  const marker = 'private-content-must-not-appear-in-context-diagnostics';
  fixture.logs[1].body = { stringValue: marker };
  fixture.logs[1].attributes.push({ key: 'tool.output', value: { stringValue: marker } });
  const data = await input(t, [
    { captureId: 'cap-context-wire', recordType: 'api_snapshot', traceContext: fixture.wire_context },
    batch('otlp_logs', { resourceLogs: [{ scopeLogs: [{ logRecords: fixture.logs }] }] }, fixture.logs.length),
    batch('otlp_traces', { resourceSpans: [{ scopeSpans: [{ spans: fixture.spans }] }] }, fixture.spans.length),
  ]);
  const result = await run(binary, ['audit-session-context', '--input', data.file, '--session-id', fixture.session_id, '--sample-limit', '3']);
  const audit = JSON.parse(result.stdout);
  assert.equal(audit.schema_version, 'chiptrace.source-context-audit.v1');
  assert.equal(audit.unscoped_otlp_records, 16);
  assert.equal(audit.sources.otlp_logs.unscoped_turn_records, 1);
  assert.equal(audit.sources.otlp_traces.unscoped_turn_records, 15);
  assert.equal(audit.sources.otlp_traces.unknown_session_records, 1);
  assert.equal(audit.samples.length, 3);
  assert.equal(audit.omitted_samples, 14);
  for (const counts of Object.values(audit.sources)) {
    assert.equal(counts.total_records, counts.turn_assigned_records + counts.session_level_records
      + counts.unscoped_turn_records + counts.other_session_records + counts.unknown_session_records);
  }
  assert.equal(audit.gap_groups.find(g => g.record_name === 'codex.sse_event').reason, 'missing_trace_context');
  assert.equal(audit.gap_groups.find(g => g.record_name === 'fs.get_metadata').records, 2);
  assert.equal(result.stdout.includes(marker), false);
  assert.equal(Object.hasOwn(audit, 'delivery_ready'), false);
  assert.deepEqual(await fs.readFile(data.file), data.bytes);
  assert.deepEqual(await fs.readdir(data.root), ['input.ndjson']);
});

test('selecting one Session preserves whole-corpus native identity ambiguity', { timeout: 30000 }, async t => {
  const raw = { resourceSpans: [{ scopeSpans: [{ spans: [{ name: 'session_task.turn',
    traceId: 'cccccccccccccccccccccccccccccccc', spanId: '2222222222222222',
    attributes: [{ key: 'turn.id', value: { stringValue: 'shared-turn' } }],
  }] }] }] };
  const data = await input(t, [
    { captureId: 'cap-context-selected', traceContext: { session_id: 'selected', turn_id: 'shared-turn' } },
    { captureId: 'cap-context-other', traceContext: { session_id: 'other', turn_id: 'shared-turn' } },
    batch('otlp_traces', raw, 1),
  ]);
  const result = await run(binary, ['audit-session-context', '--input', data.file, '--session-id', 'selected']);
  const audit = JSON.parse(result.stdout);
  assert.equal(audit.unscoped_otlp_records, 1);
  assert.equal(audit.sources.otlp_traces.turn_assigned_records, 0);
  assert.equal(audit.samples[0].reason, 'ambiguous_session_context');
  assert.deepEqual(await fs.readFile(data.file), data.bytes);
});

test('corrupt Raw, conflicting captures and oversized diagnostic limits retain real nonzero exits', { timeout: 30000 }, async t => {
  const raw = { resourceLogs: [] };
  const bad = batch('otlp_logs', raw, 0);
  bad.telemetryBatch.raw_sha256 = '0'.repeat(64);
  const data = await input(t, [{ captureId: 'cap-context-wire', traceContext: { session_id: 'selected' } }, bad]);
  await assert.rejects(run(binary, ['audit-session-context', '--input', data.file, '--session-id', 'selected']), error => {
    assert.equal(error.code, 1);
    assert.match(error.stderr, /raw_sha256 does not match/);
    assert.equal(error.stdout, '');
    return true;
  });
  const conflicts = await input(t, [
    { captureId: 'cap-context-conflict', traceContext: { session_id: 'selected' } },
    { captureId: 'cap-context-conflict', traceContext: { session_id: 'other' } },
  ]);
  await assert.rejects(run(binary, ['audit-session-context', '--input', conflicts.file, '--session-id', 'selected']), error => {
    assert.equal(error.code, 1);
    assert.match(error.stderr, /conflicting bytes/);
    return true;
  });
  await assert.rejects(run(binary, ['audit-session-context', '--input', data.file, '--session-id', 'selected', '--sample-limit', '1001']), error => {
    assert.equal(error.code, 2);
    assert.match(error.stderr, /1001/);
    return true;
  });
  assert.deepEqual(await fs.readFile(data.file), data.bytes);
});
