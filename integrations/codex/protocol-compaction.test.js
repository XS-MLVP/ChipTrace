'use strict';

// New native compaction and process-resume evidence from the pinned patched
// producer. Synthetic model bytes and isolated credentials only.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { createReadStream } = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const zlib = require('node:zlib');
const { isDeepStrictEqual } = require('node:util');
const test = require('node:test');
const { codexTraceContextFromHeaders } = require('../openai-gateway/durable-outbox');
const { verifyNativeCanaryReport } = require('../../scripts/ci/native-canary-gate');
const { run, version, chiptrace, sha256, delay, fileDigest, stop, health, protocolFixture } = require('./protocol-fixture');

async function collectCompaction(t) {
  const fixture = await protocolFixture(t, 'chiptrace-compaction-');
  const { root, token, capture, collectorUrl, relayUrl, collectorArgs, relayArgs, launch, outbox } = fixture;
  let { collector, relay } = fixture;
  const catalog = JSON.parse(await fs.readFile(path.join(__dirname, 'managed-models.json'), 'utf8'));
  catalog.models.find(model => model.slug === 'gpt-6-astra').use_responses_lite = false;
  const summary = 'SYNTHETIC_COMPACTION_SUMMARY 中文 🧪: keep the failed tool result and continue.';
  const tool = { type: 'function_call', call_id: 'compact-before-tool', name: 'exec_command',
    arguments: JSON.stringify({ cmd: 'printf CHIPTRACE_BEFORE_COMPACT; exit 7', shell: '/bin/sh',
      login: false, yield_time_ms: 250, max_output_tokens: 2000 }) };
  const observations = [];
  const wire = [];
  let mode = 'before';
  const endpoint = await fixture.serve(async (req, res) => {
    const chunks = [];
    let bytes = 0;
    for await (const chunk of req) {
      assert.ok((bytes += chunk.length) <= 8 * 1024 * 1024, 'synthetic request exceeded 8 MiB');
      chunks.push(chunk);
    }
    const route = new URL(req.url, 'http://127.0.0.1').pathname;
    if (route === '/analytics/codex/turn-costs') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
      return;
    }
    assert.equal(req.headers.authorization, 'Bearer synthetic-protocol-provider');
    if (route === '/models') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(catalog));
      return;
    }
    assert.equal(req.method, 'POST');
    assert.equal(route, '/responses');
    const context = codexTraceContextFromHeaders(req.headers);
    assert.deepEqual(context.errors, []);
    assert.deepEqual(context.conflicts, []);
    assert.ok(context.trace.session_id && context.trace.turn_id);
    const request = Buffer.concat(chunks);
    const body = JSON.parse(request);
    assert.equal(body.model, 'gpt-6-astra');
    assert.equal(body.stream, true);
    assert.ok(observations.length < 5, 'unexpected additional HTTP attempt');
    let item;
    if (mode === 'before' && observations.length === 0) {
      assert.ok(body.tools.some(definition => (definition.function ?? definition).name === tool.name));
      item = tool;
    } else {
      if (mode === 'before' || mode === 'compact') {
        const result = body.input.find(item => item.type === 'function_call_output' && item.call_id === tool.call_id);
        assert.equal(typeof result?.output, 'string');
        assert.match(result.output, /CHIPTRACE_BEFORE_COMPACT/);
        assert.match(result.output, /exited with code 7/);
      } else {
        assert.ok(JSON.stringify(body.input).includes(summary), 'continuation must use the actual installed compaction summary');
      }
      item = { type: 'message', id: `compact-${mode}`, role: 'assistant', phase: 'final_answer',
        content: [{ type: 'output_text', text: mode === 'compact' ? summary : `SYNTHETIC_${mode.toUpperCase()}_REPLY 中文 🧪` }] };
    }
    const responseId = `compact-response-${observations.length + 1}`;
    const response = Buffer.from([
      { type: 'response.created', response: { id: responseId } },
      { type: 'response.output_item.done', output_index: 0, item },
      { type: 'response.completed', response: { id: responseId, output: [item],
        usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 } } },
    ].map(value => `event: ${value.type}\ndata: ${JSON.stringify(value)}\n\n`).join(''));
    const captureId = `cap-compaction-${crypto.randomUUID()}`;
    const requestHeaders = Object.fromEntries(Object.entries(req.headers)
      .filter(([key]) => ['session-id', 'thread-id', 'x-codex-turn-metadata', 'traceparent', 'tracestate'].includes(key)));
    const observation = { mode, capture_id: captureId, turn_id: context.trace.turn_id,
      response_id: responseId, output_items: [item], request_headers: requestHeaders,
      request_sha256: sha256(request), response_sha256: sha256(response) };
    observations.push(observation);
    const transaction = await outbox.beginCapture({ captureId,
      version: 'chiptrace.capture.v2', recordType: 'api_snapshot', sourceNamespace: 'synthetic-compaction-ci',
      method: req.method, proxiedPath: req.url, requestHeaders, startedAt: new Date().toISOString(),
      traceContext: context.trace, fieldEvidence: context.evidence,
      fieldEvidenceConflicts: context.conflicts, traceContextErrors: context.errors });
    await transaction.appendRequest(request);
    const responseHeaders = { 'content-type': 'text/event-stream', 'x-request-id': `request-${crypto.randomUUID()}` };
    const finished = new Promise((resolve, reject) => {
      res.once('finish', resolve);
      res.once('close', () => { if (!res.writableFinished) reject(new Error('synthetic compaction response closed early')); });
    });
    res.writeHead(200, responseHeaders);
    for (let offset = 0; offset < response.length; offset += 37) {
      const chunk = response.subarray(offset, offset + 37);
      await transaction.appendResponse(chunk);
      res.write(chunk);
    }
    res.end();
    await finished;
    await transaction.finalize({ responseStatus: 200, stream: true, responseHeaders,
      finishedAt: new Date().toISOString(), upstreamResponseCompleted: true,
      clientRequestAborted: req.aborted, clientResponseClosedBeforeFinish: false,
      clientResponseFinished: res.writableFinished, responseBytesForwarded: response.length });
    wire.push(observation);
  });
  const connect = await fixture.configure(endpoint, catalog);
  const first = await connect();
  const started = await first.client.request('thread/start', {
    model: 'gpt-6-astra', cwd: root, approvalPolicy: 'never', sandbox: 'read-only', ephemeral: false });
  const session = started.thread.id;
  const turns = [];
  const begin = async client => {
    const result = await client.request('turn/start', { threadId: session,
      input: [{ type: 'text', text: `SYNTHETIC_${mode.toUpperCase()}_REQUEST`, text_elements: [] }], model: 'gpt-6-astra' });
    await client.completed(session, result.turn.id);
    turns.push(result.turn.id);
    fixture.assertHealthy();
  };
  await begin(first.client);
  mode = 'compact';
  await first.client.request('thread/compact/start', { threadId: session });
  const compact = await first.client.notification('turn/started',
    params => params.threadId === session && !turns.includes(params.turn.id));
  await first.client.completed(session, compact.turn.id);
  turns.push(compact.turn.id);
  fixture.assertHealthy();
  mode = 'after';
  await begin(first.client);
  assert.deepEqual(await stop(first.handle, true), { code: 0, signal: null }, first.handle.stderr);
  const second = await connect();
  const resumed = await second.client.request('thread/resume', { threadId: session,
    cwd: root, approvalPolicy: 'never', sandbox: 'read-only' });
  assert.equal(resumed.thread.id, session);
  mode = 'resumed';
  await begin(second.client);
  assert.deepEqual(await stop(second.handle, true), { code: 0, signal: null }, second.handle.stderr);
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    await outbox.refreshQueueStats();
    const state = outbox.snapshot();
    if (state.pending + state.processing + state.openTransactions === 0 && wire.length === 5) break;
    await delay(25);
  }
  const state = outbox.snapshot();
  assert.equal(state.pending + state.processing + state.openTransactions + state.failed, 0);
  assert.equal(state.durable, 5);
  assert.equal(wire.length, 5);
  const delivered = await health(relayUrl, relay, value => value.pending === 0 && value.inflight === 0);
  assert.equal(delivered.conservation_ok, true);
  for (const url of [relayUrl, collectorUrl]) {
    const response = await fetch(`${url}/flush`, { method: 'POST', headers: { authorization: `Bearer ${token}` } });
    assert.equal(response.status, 200);
  }
  const projectionRoot = path.join(root, 'projection');
  const inspect = async () => JSON.parse((await run(chiptrace,
    ['inspect-session', '--input', capture, '--session-id', session, '--projection-output', projectionRoot],
    { maxBuffer: 32 * 1024 * 1024 })).stdout);
  const inspection = await inspect();
  await fs.writeFile(path.join(root, 'inspection.json'), JSON.stringify(inspection, null, 2));
  const audit = JSON.parse((await run(chiptrace,
    ['audit-session-context', '--input', capture, '--session-id', session, '--sample-limit', '0'],
    { maxBuffer: 1024 * 1024 })).stdout);
  await fs.writeFile(path.join(root, 'audit.json'), JSON.stringify(audit, null, 2));
  t.diagnostic(JSON.stringify({ phase: 'compacted_collection', native_turns: inspection.session.native_turns,
    session_epochs: inspection.session.session_epochs, integrity: inspection.integrity, source_counts: audit.sources }));
  assert.equal(inspection.delivery_ready, true, JSON.stringify({ integrity: inspection.integrity,
    open_turns: inspection.session.open_turns, incomplete_turns: inspection.session.incomplete_turns }));
  assert.equal(inspection.session.native_turns, 4);
  assert.equal(inspection.session.closed_turns, 4);
  assert.equal(inspection.session.closed_session_epochs, 2);
  assert.equal(inspection.session.model_interactions, 5);
  assert.deepEqual(new Set(inspection.session.turns.map(turn => turn.turn_id)), new Set(turns));
  for (const counts of Object.values(audit.sources)) {
    assert.equal(counts.unknown_session_records, 0);
    assert.equal(counts.unscoped_turn_records, 0);
  }
  const rawDigests = [];
  const records = [];
  for (const name of (await fs.readdir(path.join(capture, 'segments'))).filter(name => name.endsWith('.sealed.ndjson'))) {
    const file = path.join(capture, 'segments', name);
    rawDigests.push({ file: name, sha256: await fileDigest(file), bytes: (await fs.stat(file)).size });
    for await (const line of readline.createInterface({ input: createReadStream(file) })) records.push(JSON.parse(line));
  }
  const compactWire = observations.find(item => item.mode === 'compact');
  assert.equal(compactWire.turn_id, compact.turn.id);
  assert.equal(JSON.parse(compactWire.request_headers['x-codex-turn-metadata']).request_kind, 'compaction');
  const compactHooks = records.filter(record => record.lifecycleEvent?.source_event?.turn_id === compact.turn.id);
  for (const name of ['PreCompact', 'PostCompact']) {
    assert.equal(compactHooks.filter(record => record.lifecycleEvent.source_event_name === name).length, 1);
  }
  assert.equal(records.filter(record => record.lifecycleEvent?.source_event_name === 'SessionStart'
    && record.lifecycleEvent.source_event?.source === 'compact').length, 1);
  assert.equal(compactHooks.some(record => record.lifecycleEvent.source_event_name === 'Stop'), false,
    'standalone compaction must be verified with its actual Pre/Post hooks, without inventing Stop');
  for (const mutation of ['inline', 'missing-pre', 'missing-post']) {
    const file = path.join(root, `derived-${mutation}.ndjson`);
    const derived = [];
    for (const record of records) {
      const event = record.lifecycleEvent?.source_event_name;
      const batch = record.telemetryBatch?.endpoint === 'codex_hook'
        ? JSON.parse(record.telemetryBatch.raw_json).hook_event_name : undefined;
      const omitted = mutation === 'missing-pre' ? 'PreCompact' : mutation === 'missing-post' ? 'PostCompact' : null;
      if (omitted && (event === omitted || batch === omitted)) continue;
      if (mutation === 'inline' && record.captureId === compactWire.capture_id) {
        const changed = structuredClone(record);
        const metadata = JSON.parse(changed.requestHeaders['x-codex-turn-metadata']);
        metadata.compaction.phase = 'pre_turn';
        changed.requestHeaders['x-codex-turn-metadata'] = JSON.stringify(metadata);
        derived.push(changed);
      } else derived.push(record);
    }
    await fs.writeFile(file, derived.map(record => JSON.stringify(record)).join('\n') + '\n', { flag: 'wx' });
    const refused = JSON.parse((await run(chiptrace,
      ['inspect-session', '--input', file, '--session-id', session,
        '--projection-output', path.join(root, `refused-${mutation}`)], { maxBuffer: 32 * 1024 * 1024 })).stdout);
    assert.equal(refused.integrity.protocol_complete, true);
    assert.equal(refused.integrity.root_complete, false, mutation);
    assert.equal(refused.integrity.runtime_complete, false, mutation);
    assert.equal(refused.delivery_ready, false, mutation);
    assert.equal(refused.session.open_turns, 1, mutation);
  }
  const decode = async file => zlib.zstdDecompressSync(await fs.readFile(path.join(projectionRoot, file)))
    .toString('utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  const interactions = await decode('interactions/model-interactions.jsonl.zst');
  assert.equal(interactions.length, 5);
  for (const observed of observations) {
    const saved = records.find(record => record.captureId === observed.capture_id);
    assert.equal(sha256(saved.requestBody.raw), observed.request_sha256);
    assert.equal(sha256(saved.responseBody.raw ?? saved.responseBody.value), observed.response_sha256);
    const interaction = interactions.find(item => item.raw_capture_refs.some(ref => ref.capture_id === observed.capture_id));
    assert.equal(interaction.trace_context.turn_id ?? interaction.trace_context.root_turn_id, observed.turn_id);
    assert.equal(interaction.response.id, observed.response_id);
    assert.ok(isDeepStrictEqual(interaction.request.raw, JSON.parse(saved.requestBody.raw)), 'complete compaction input must survive (payload omitted)');
    assert.ok(isDeepStrictEqual(interaction.response.output_items.map(item => item.raw), observed.output_items),
      'complete compaction output must survive (payload omitted)');
  }
  const runtime = await decode('runtime/runtime-spans.jsonl.zst');
  const execution = runtime.find(span => span.span_kind === 'tool_execution' && span.call_id === tool.call_id);
  assert.equal(execution.extensions.process_outcome.exit_code, 7);
  assert.equal(execution.extensions.semantic_status, 'error');
  const compactSpan = runtime.find(span => span.span_kind === 'turn' && span.trace_context.turn_id === compact.turn.id);
  assert.equal(compactSpan.result.type, 'compaction_end');
  assert.equal(compactSpan.extensions.root_complete, true);
  for (const hook of compactHooks) assert.ok(compactSpan.raw_capture_refs.includes(hook.captureId));
  assert.deepEqual(await stop(relay), { code: 0, signal: null });
  assert.deepEqual(await stop(collector), { code: 0, signal: null });
  collector = launch(chiptrace, collectorArgs, { CHIPTRACE_INGEST_TOKEN: token });
  await health(collectorUrl, collector, value => value.collector.captures === delivered.delivered);
  relay = launch(chiptrace, relayArgs, { CHIPTRACE_INGEST_TOKEN: token });
  await health(relayUrl, relay, value => value.delivered === delivered.delivered && value.conservation_ok);
  const stable = value => ({ ...value, projection: { ...value.projection, created_at_utc: null } });
  assert.deepEqual(stable(await inspect()), stable(inspection));
  for (const digest of rawDigests) assert.equal(await fileDigest(path.join(capture, 'segments', digest.file)), digest.sha256);
  const platformEvidence = await fixture.verifyPlatform('compaction');
  const report = { schema_version: 'chiptrace.native-compaction-ci.v1', ok: true,
    checked_at: new Date().toISOString(), real_upstream: false, unmodified_stock: fixture.unmodifiedStock,
    production_acceptance_claimed: false, model_mode: 'local_deterministic_responses',
    producer_mode: fixture.producerMode, client_version: version,
    producer_source: fixture.source, patch_set: fixture.patchSet, producer_binary_sha256: await fileDigest(fixture.producer),
    native_turns: 4, session_epochs: 2, model_interactions: 5,
    tool_execution_records: inspection.session.tool_execution_records, compaction_turns: 1,
    compaction_input_output_verified: true, pre_post_hooks_verified: true,
    compact_session_start_does_not_open_epoch: true, summary_continuation_verified: true,
    summary_process_resume_verified: true, failed_tool_preserved: true,
    inline_and_missing_hook_boundaries_refused: true,
    source_coverage: inspection.source_coverage, source_audit: audit, collector_raw: rawDigests,
    platform_evidence: platformEvidence, restart_verified: true };
  assert.throws(() => verifyNativeCanaryReport(report, audit), /real_upstream/);
  if (process.env.CHIPTRACE_COMPACTION_REPORT) {
    await fs.writeFile(process.env.CHIPTRACE_COMPACTION_REPORT, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  }
  fixture.passed();
}

test('native compaction preserves every interaction, Hook boundary and summary through continuation and process resume',
  { timeout: 180000 }, async t => {
    try { await collectCompaction(t); }
    catch (error) {
      if (process.env.GITHUB_ACTIONS === 'true') {
        const message = String(error.message).replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').slice(0, 4000)
          .replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
        console.log(`::error title=Native protocol collection::${message}`);
      }
      throw error;
    }
  });
