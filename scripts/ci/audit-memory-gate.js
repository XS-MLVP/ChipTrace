#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);

const MEMORY_BUDGET_KIB = 96 * 1024;
const MINIMUM_INPUT_BYTES = 128 * 1024 * 1024;
const WIRE_CAPTURES = 512;
const SESSION = 'synthetic-audit-memory-session';

function batch(endpoint, raw) {
  const rawJson = JSON.stringify(raw);
  return { captureId: `cap-memory-${endpoint}`, recordType: 'telemetry_batch', telemetryBatch: {
    schema_version: 'chiptrace.telemetry-batch.v1', endpoint, raw_json: rawJson,
    raw_bytes: Buffer.byteLength(rawJson), raw_sha256: crypto.createHash('sha256').update(rawJson).digest('hex'),
    source_records: 1, derived_captures: 0, unknown_events: 0, conversion_errors: [],
  } };
}

async function sha256(file) {
  const digest = crypto.createHash('sha256');
  for await (const bytes of fs.createReadStream(file)) digest.update(bytes);
  return digest.digest('hex');
}

async function generate(file) {
  const handle = await fsp.open(file, 'wx', 0o600);
  const digest = crypto.createHash('sha256');
  const append = async value => {
    const line = Buffer.from(`${JSON.stringify(value)}\n`);
    await handle.writeFile(line);
    digest.update(line);
  };
  try {
    const request = JSON.stringify({ input: [{ role: 'user', content: 'synthetic '.repeat(26215) }] });
    for (let index = 0; index < WIRE_CAPTURES; index++) {
      await append({ captureId: `cap-memory-wire-${index}`, recordType: 'api_snapshot',
        traceContext: { session_id: SESSION, turn_id: 'synthetic-turn' }, requestBodyText: request });
    }
    const attributes = [
      { key: 'conversation.id', value: { stringValue: SESSION } },
      { key: 'turn.id', value: { stringValue: 'synthetic-turn' } },
    ];
    await append(batch('otlp_logs', { resourceLogs: [{ scopeLogs: [{ logRecords: [{
      attributes: [...attributes, { key: 'event.name', value: { stringValue: 'codex.sse_event' } }],
    }] }] }] }));
    await append(batch('otlp_traces', { resourceSpans: [{ scopeSpans: [{ spans: [{
      name: 'synthetic.turn', traceId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', spanId: '1111111111111111', attributes,
    }] }] }] }));
    await handle.sync();
  } finally { await handle.close(); }
  await fsp.chmod(file, 0o400);
  return digest.digest('hex');
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== '--report')) throw new Error('usage: audit-memory-gate.js [--report FILE]');
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'chiptrace-audit-memory-'));
  const result = { schema_version: 'chiptrace.audit-memory-gate.v1', synthetic: true,
    session_delivery_claimed: false, memory_budget_kib: MEMORY_BUDGET_KIB, ok: false };
  try {
    const input = path.join(root, 'synthetic.ndjson');
    result.input_sha256 = await generate(input);
    result.input_bytes = (await fsp.stat(input)).size;
    assert.ok(result.input_bytes >= MINIMUM_INPUT_BYTES, 'synthetic input must contain at least 128 MiB');
    const metrics = path.join(root, 'metrics.json');
    const binary = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/release/chiptrace');
    const { stdout } = await run('/usr/bin/time', ['-f', '{"max_rss_kib":%M,"elapsed_seconds":%e}', '-o', metrics,
      binary, 'audit-session-context', '--input', input, '--session-id', SESSION, '--sample-limit', '0'],
    { maxBuffer: 4 * 1024 * 1024, timeout: 120000,
      env: { ...process.env, TOKIO_WORKER_THREADS: '2', RAYON_NUM_THREADS: '2' } });
    const audit = JSON.parse(stdout);
    Object.assign(result, JSON.parse(await fsp.readFile(metrics, 'utf8')));
    assert.equal(audit.schema_version, 'chiptrace.source-context-audit.v2');
    assert.equal(audit.session_id, SESSION);
    assert.equal(audit.selected_captures, WIRE_CAPTURES + 2);
    assert.equal(audit.duplicate_captures_removed, 0);
    assert.equal(audit.unscoped_otlp_records, 0);
    assert.equal(audit.sample_limit, 0);
    assert.deepEqual(audit.samples, []);
    for (const source of ['otlp_logs', 'otlp_traces']) {
      assert.deepEqual(audit.sources[source], { total_records: 1, turn_assigned_records: 1,
        session_level_records: 0, process_level_records: 0, unscoped_turn_records: 0,
        other_session_records: 0, unknown_session_records: 0 });
    }
    assert.equal(await sha256(input), result.input_sha256);
    result.audited_captures = audit.selected_captures;
    result.input_unchanged = true;
    assert.ok(Number.isSafeInteger(result.max_rss_kib) && result.max_rss_kib > 0);
    assert.ok(result.max_rss_kib <= MEMORY_BUDGET_KIB,
      `audit peak RSS ${result.max_rss_kib} KiB exceeds ${MEMORY_BUDGET_KIB} KiB`);
    result.ok = true;
  } catch (error) {
    result.error = String(error.message).slice(0, 1000);
    process.exitCode = 1;
  } finally {
    if (args.length) await fsp.writeFile(args[1], `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    await fsp.rm(root, { recursive: true, force: true });
  }
}

main().catch(error => { process.stderr.write(`${String(error.message).slice(0,1000)}\n`); process.exitCode = 1; });
