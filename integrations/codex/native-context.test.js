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
  assert.equal(audit.schema_version, 'chiptrace.source-context-audit.v2');
  assert.equal(audit.unscoped_otlp_records, 16);
  assert.equal(audit.sources.otlp_logs.unscoped_turn_records, 1);
  assert.equal(audit.sources.otlp_traces.unscoped_turn_records, 15);
  assert.equal(audit.sources.otlp_traces.unknown_session_records, 1);
  assert.equal(audit.samples.length, 3);
  assert.equal(audit.omitted_samples, 14);
  for (const counts of Object.values(audit.sources)) {
    assert.equal(counts.total_records, counts.turn_assigned_records + counts.session_level_records
      + counts.process_level_records + counts.unscoped_turn_records
      + counts.other_session_records + counts.unknown_session_records);
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

test('source-declared Session scopes preserve exact Turn coverage and unresolved business evidence', async t => {
  const traceId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const session = 'scoped-session';
  const root = '1111111111111111';
  const init = '2222222222222222';
  const turn = '3333333333333333';
  const attr = (key, value) => ({ key, value: { stringValue: value } });
  const spans = [
    { traceId, spanId: root, attributes: [attr('codex.context_scope', 'session'), attr('conversation.id', session)] },
    { traceId, spanId: init, parentSpanId: root, name: 'fs.get_metadata' },
    { traceId, spanId: turn, parentSpanId: root },
    { traceId, spanId: '4444444444444444', parentSpanId: turn, name: 'fs.get_metadata' },
  ];
  const logs = [
    { traceId, spanId: init, attributes: [attr('event.name', 'codex.api_request')] },
    { traceId, spanId: init, attributes: [attr('event.name', 'codex.sse_event')] },
    { traceId, spanId: turn, attributes: [attr('event.name', 'codex.sse_event')] },
  ];
  const data = await input(t, [
    { captureId: 'cap-scoped-wire', recordType: 'api_snapshot', traceContext: {
      session_id: session, turn_id: 'native-turn', trace_id: traceId, parent_span_id: turn,
    } },
    batch('otlp_traces', { resourceSpans: [{ scopeSpans: [{ spans }] }] }, spans.length),
    batch('otlp_logs', { resourceLogs: [{ scopeLogs: [{ logRecords: logs }] }] }, logs.length),
  ]);
  const result = await run(binary, ['audit-session-context', '--input', data.file, '--session-id', session]);
  const audit = JSON.parse(result.stdout);
  assert.equal(audit.sources.otlp_traces.session_level_records, 2);
  assert.equal(audit.sources.otlp_traces.turn_assigned_records, 2);
  assert.equal(audit.sources.otlp_logs.session_level_records, 1);
  assert.equal(audit.sources.otlp_logs.turn_assigned_records, 1);
  assert.equal(audit.unscoped_otlp_records, 1);
  assert.equal(audit.samples[0].record_name, 'codex.sse_event');
  for (const counts of Object.values(audit.sources)) {
    assert.equal(counts.total_records, counts.turn_assigned_records + counts.session_level_records
      + counts.process_level_records + counts.unscoped_turn_records
      + counts.other_session_records + counts.unknown_session_records);
  }
  assert.deepEqual(await fs.readFile(data.file), data.bytes);
  assert.deepEqual(await fs.readdir(data.root), ['input.ndjson']);
});

test('source-declared Process scopes remain outside selected Session accounting', async t => {
  const traceId = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const root = '5555555555555555';
  const child = '6666666666666666';
  const attr = (key, value) => ({ key, value: { stringValue: value } });
  const spans = [
    { traceId, spanId: root, name: 'process.bootstrap', attributes: [attr('codex.context_scope', 'process')] },
    { traceId, spanId: child, parentSpanId: root, name: 'auth' },
  ];
  const logs = [{ traceId, spanId: child, attributes: [attr('event.name', 'auth')] }];
  const data = await input(t, [
    { captureId: 'cap-process-wire', recordType: 'api_snapshot', traceContext: {
      session_id: 'selected-session', turn_id: 'native-turn',
    } },
    batch('otlp_traces', { resourceSpans: [{ scopeSpans: [{ spans }] }] }, spans.length),
    batch('otlp_logs', { resourceLogs: [{ scopeLogs: [{ logRecords: logs }] }] }, logs.length),
  ]);
  const result = await run(binary, [
    'audit-session-context', '--input', data.file, '--session-id', 'selected-session', '--sample-limit', '0',
  ]);
  const audit = JSON.parse(result.stdout);
  assert.ok(audit.sources, JSON.stringify(audit));
  assert.equal(audit.unscoped_otlp_records, 0);
  assert.equal(audit.sources.otlp_traces.process_level_records, 2);
  assert.equal(audit.sources.otlp_logs.process_level_records, 1);
  assert.equal(audit.sources.otlp_traces.unknown_session_records, 0);
  assert.equal(audit.sources.otlp_logs.unknown_session_records, 0);
  assert.deepEqual(await fs.readFile(data.file), data.bytes);
});

test('unowned batches remain in the audit while exact Process ancestry crosses batches', async t => {
  const attr = (key, value) => ({ key, value: { stringValue: value } });
  const processTrace = 'ffffffffffffffffffffffffffffffff';
  const root = '1111111111111111';
  const child = '2222222222222222';
  const unknownLog = batch('otlp_logs', { resourceLogs: [{ scopeLogs: [{ logRecords: [{
    body: { stringValue: 'private-unowned-batch-payload' },
  }] }] }] }, 1);
  unknownLog.captureId = 'cap-unowned-logs';
  const traces = spans => ({ resourceSpans: [{ scopeSpans: [{ spans }] }] });
  const captures = [
    { captureId: 'cap-unowned-wire', recordType: 'api_snapshot', traceContext: { session_id: 'selected', turn_id: 'native-turn' } },
    unknownLog,
    batch('otlp_traces', traces([{ name: 'unowned', traceId: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', spanId: root }]), 1),
    batch('otlp_traces', traces([{ name: 'process.bootstrap', traceId: processTrace, spanId: root,
      attributes: [attr('codex.context_scope', 'process')] }]), 1),
    batch('otlp_traces', traces([{ name: 'auth', traceId: processTrace, spanId: child, parentSpanId: root }]), 1),
    batch('otlp_logs', { resourceLogs: [{ scopeLogs: [{ logRecords: [{ traceId: processTrace,
      spanId: child, attributes: [attr('event.name', 'auth')] }] }] }] }, 1),
    batch('otlp_logs', { resourceLogs: [{ scopeLogs: [{ logRecords: [{
      attributes: [attr('conversation.id', 'other-session'), attr('event.name', 'codex.sse_event')],
    }] }] }] }, 1),
  ].map((capture, index) => index < 2 ? capture : { ...capture, captureId: `cap-unowned-extra-${index}` });
  captures.push(unknownLog);
  const data = await input(t, captures);
  const result = await run(binary, ['audit-session-context', '--input', data.file, '--session-id', 'selected', '--sample-limit', '0']);
  const audit = JSON.parse(result.stdout);
  assert.equal(audit.selected_captures, 6);
  assert.equal(audit.duplicate_captures_removed, 1);
  assert.equal(audit.sources.otlp_logs.total_records, 2);
  assert.equal(audit.sources.otlp_logs.unknown_session_records, 1);
  assert.equal(audit.sources.otlp_logs.process_level_records, 1);
  assert.equal(audit.sources.otlp_logs.other_session_records, 0);
  assert.equal(audit.sources.otlp_traces.total_records, 3);
  assert.equal(audit.sources.otlp_traces.unknown_session_records, 1);
  assert.equal(audit.sources.otlp_traces.process_level_records, 2);
  assert.equal(audit.unscoped_otlp_records, 0);
  assert.ok(!result.stdout.includes('private-unowned-batch-payload'));
  assert.deepEqual(await fs.readFile(data.file), data.bytes);
  assert.deepEqual(await fs.readdir(data.root), ['input.ndjson']);
});

test('Turn business logs cannot be exempted by explicit or inherited Process scope', async t => {
  const attr = (key, value) => ({ key, value: { stringValue: value } });
  const traceId = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const spanId = '5555555555555555';
  const marker = 'private-process-scope-business-payload';
  for (const name of ['codex.sse_event', 'codex.tool_result', 'codex.tool_decision',
    'codex.sandbox_outcome', 'codex.user_prompt', 'codex.turn_ttft', 'codex.turn_cost']) {
    for (const inherited of [false, true]) {
      const log = { body: { stringValue: marker }, attributes: [attr('event.name', name)] };
      if (inherited) Object.assign(log, { traceId, spanId });
      else log.attributes.push(attr('codex.context_scope', 'process'));
      const spans = [{ traceId, spanId, name: 'process.bootstrap',
        attributes: [attr('codex.context_scope', 'process')] }];
      const data = await input(t, [
        { captureId: 'cap-business-process-wire', recordType: 'api_snapshot', traceContext: {
          session_id: 'selected-session', turn_id: 'native-turn',
        } },
        batch('otlp_traces', { resourceSpans: [{ scopeSpans: [{ spans }] }] }, 1),
        batch('otlp_logs', { resourceLogs: [{ scopeLogs: [{ logRecords: [log] }] }] }, 1),
      ]);
      await assert.rejects(run(binary, ['audit-session-context', '--input', data.file,
        '--session-id', 'selected-session']), error => {
        assert.equal(error.code, 1);
        assert.equal(error.stdout, '');
        assert.match(error.stderr, /Turn-level business event conflicts with Process scope/);
        assert.ok(!error.stderr.includes(marker));
        return true;
      }, `${name}, inherited=${inherited}`);
      assert.deepEqual(await fs.readFile(data.file), data.bytes);
      assert.deepEqual(await fs.readdir(data.root), ['input.ndjson']);
    }
  }
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
