'use strict';

// Exercise actual automatic compaction in the pinned producer. Token usage and
// model responses are synthetic; no operator credentials or production state.
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

async function collectAutomaticCompaction(t) {
  const fixture = await protocolFixture(t, 'chiptrace-auto-compaction-');
  const { root, token, capture, collectorUrl, relayUrl, collectorArgs, relayArgs, launch, outbox } = fixture;
  let { collector, relay } = fixture;
  const catalog = JSON.parse(await fs.readFile(path.join(__dirname, 'managed-models.json'), 'utf8'));
  catalog.models.find(model => model.slug === 'gpt-6-astra').use_responses_lite = false;
  const summaries = { pre_turn: 'SYNTHETIC_PRE_TURN_SUMMARY 中文 🧪',
    mid_turn: 'SYNTHETIC_MID_TURN_SUMMARY: preserve the real exit 7 中文 🧪',
    post_turn: 'SYNTHETIC_POST_TURN_SUMMARY 中文 🧪' };
  const tool = { type: 'function_call', call_id: 'automatic-compact-tool', name: 'exec_command',
    arguments: JSON.stringify({ cmd: 'printf CHIPTRACE_AUTO_COMPACT; exit 7', shell: '/bin/sh',
      login: false, yield_time_ms: 250, max_output_tokens: 2000 }) };
  const steps = [
    { name: 'first', text: 'SYNTHETIC_AUTO_FIRST_REPLY', tokens: 330000 },
    { name: 'pre', phase: 'pre_turn', text: summaries.pre_turn, tokens: 100,
      includes: 'SYNTHETIC_AUTO_FIRST_REPLY' },
    { name: 'tool', tool: true, tokens: 330000, includes: summaries.pre_turn },
    { name: 'mid', phase: 'mid_turn', text: summaries.mid_turn, tokens: 100, toolResult: true },
    { name: 'second-final', text: 'SYNTHETIC_AUTO_SECOND_REPLY', tokens: 100, includes: summaries.mid_turn },
    { name: 'resumed', text: 'SYNTHETIC_AUTO_RESUMED_REPLY', tokens: 330000, includes: summaries.mid_turn },
    { name: 'post', phase: 'post_turn', text: summaries.post_turn, tokens: 100,
      includes: 'SYNTHETIC_AUTO_RESUMED_REPLY' },
    { name: 'after-post', text: 'SYNTHETIC_AUTO_FINAL_REPLY', tokens: 100, includes: summaries.post_turn },
  ];
  const observations = [];
  let finalized = 0;
  const endpoint = await fixture.serve(async (req, res) => {
    const chunks = []; let bytes = 0;
    for await (const chunk of req) {
      assert.ok((bytes += chunk.length) <= 8 * 1024 * 1024, 'synthetic request exceeded 8 MiB');
      chunks.push(chunk);
    }
    const route = new URL(req.url, 'http://127.0.0.1').pathname;
    if (route === '/analytics/codex/turn-costs') {
      res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}'); return;
    }
    assert.equal(req.headers.authorization, 'Bearer synthetic-protocol-provider');
    if (route === '/models') {
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(catalog)); return;
    }
    assert.equal(req.method, 'POST'); assert.equal(route, '/responses');
    const context = codexTraceContextFromHeaders(req.headers);
    assert.deepEqual(context.errors, []); assert.deepEqual(context.conflicts, []);
    assert.ok(context.trace.session_id && context.trace.turn_id);
    const request = Buffer.concat(chunks); const body = JSON.parse(request);
    assert.equal(body.model, 'gpt-6-astra'); assert.equal(body.stream, true);
    const step = steps[observations.length];
    assert.ok(step, 'unexpected additional HTTP request');
    const metadata = JSON.parse(req.headers['x-codex-turn-metadata']);
    if (step.phase) {
      assert.equal(metadata.request_kind, 'compaction');
      assert.equal(metadata.compaction.trigger, 'auto');
      assert.equal(metadata.compaction.phase, step.phase);
    } else assert.notEqual(metadata.request_kind, 'compaction', step.name);
    if (step.includes) assert.ok(JSON.stringify(body.input).includes(step.includes),
      `${step.name} must retain its actual preceding summary/reply (payload omitted)`);
    if (step.toolResult) {
      const result = body.input.find(item => item.type === 'function_call_output' && item.call_id === tool.call_id);
      assert.equal(typeof result?.output, 'string');
      assert.match(result.output, /CHIPTRACE_AUTO_COMPACT/); assert.match(result.output, /exited with code 7/);
    }
    if (step.tool) assert.ok(body.tools.some(definition => (definition.function ?? definition).name === tool.name));
    const item = step.tool ? tool : { type: 'message', id: `auto-${step.name}`, role: 'assistant',
      phase: 'final_answer', content: [{ type: 'output_text', text: step.text }] };
    const responseId = `auto-response-${observations.length + 1}`;
    const response = Buffer.from([
      { type: 'response.created', response: { id: responseId } },
      { type: 'response.output_item.done', output_index: 0, item },
      { type: 'response.completed', response: { id: responseId, output: [item],
        usage: { input_tokens: step.tokens, output_tokens: 0, total_tokens: step.tokens } } },
    ].map(value => `event: ${value.type}\ndata: ${JSON.stringify(value)}\n\n`).join(''));
    const captureId = `cap-auto-compaction-${crypto.randomUUID()}`;
    const requestHeaders = Object.fromEntries(Object.entries(req.headers)
      .filter(([key]) => ['session-id', 'thread-id', 'x-codex-turn-metadata', 'traceparent', 'tracestate'].includes(key)));
    observations.push({ name: step.name, phase: step.phase, capture_id: captureId,
      turn_id: context.trace.turn_id, response_id: responseId, output_items: [item],
      request_sha256: sha256(request), response_sha256: sha256(response) });
    const transaction = await outbox.beginCapture({ captureId,
      version: 'chiptrace.capture.v2', recordType: 'api_snapshot', sourceNamespace: 'synthetic-auto-compaction-ci',
      method: req.method, proxiedPath: req.url, requestHeaders, startedAt: new Date().toISOString(),
      traceContext: context.trace, fieldEvidence: context.evidence,
      fieldEvidenceConflicts: context.conflicts, traceContextErrors: context.errors });
    await transaction.appendRequest(request);
    const responseHeaders = { 'content-type': 'text/event-stream', 'x-request-id': `request-${crypto.randomUUID()}` };
    const finished = new Promise((resolve, reject) => {
      res.once('finish', resolve);
      res.once('close', () => { if (!res.writableFinished) reject(new Error('synthetic auto-compaction response closed early')); });
    });
    res.writeHead(200, responseHeaders);
    for (let offset = 0; offset < response.length; offset += 37) {
      const chunk = response.subarray(offset, offset + 37);
      await transaction.appendResponse(chunk); res.write(chunk);
    }
    res.end(); await finished;
    await transaction.finalize({ responseStatus: 200, stream: true, responseHeaders,
      finishedAt: new Date().toISOString(), upstreamResponseCompleted: true,
      clientRequestAborted: req.aborted, clientResponseClosedBeforeFinish: false,
      clientResponseFinished: res.writableFinished, responseBytesForwarded: response.length });
    finalized += 1;
  });
  const connect = await fixture.configure(endpoint, catalog);
  const configFile = path.join(root, 'home', 'config.toml');
  const baseConfig = await fs.readFile(configFile, 'utf8');
  const configure = async postTurnPercent => fs.writeFile(configFile,
    'model_auto_compact_token_limit = 200000\nmodel_auto_compact_token_limit_scope = "total"\n'
    + `model_post_turn_compact_threshold_percent = ${postTurnPercent}\n`
    + 'compact_prompt = "SYNTHETIC_AUTO_COMPACTION_PROMPT"\n' + baseConfig, { mode: 0o600 });
  await configure(0);
  const first = await connect();
  const started = await first.client.request('thread/start', { model: 'gpt-6-astra', cwd: root,
    approvalPolicy: 'never', sandbox: 'read-only', ephemeral: false });
  const session = started.thread.id; const turns = [];
  const begin = async (client, text) => {
    const result = await client.request('turn/start', { threadId: session,
      input: [{ type: 'text', text, text_elements: [] }], model: 'gpt-6-astra' });
    await client.completed(session, result.turn.id); turns.push(result.turn.id); fixture.assertHealthy();
  };
  await begin(first.client, 'SYNTHETIC_AUTO_FIRST_REQUEST');
  assert.equal(observations.length, 1, 'post-turn compaction is disabled in the initial isolated configuration');
  await begin(first.client, 'SYNTHETIC_AUTO_SECOND_REQUEST');
  assert.equal(observations.length, 5);
  assert.deepEqual(await stop(first.handle, true), { code: 0, signal: null }, first.handle.stderr);
  await configure(50);
  const second = await connect();
  const resumed = await second.client.request('thread/resume', { threadId: session,
    cwd: root, approvalPolicy: 'never', sandbox: 'read-only' });
  assert.equal(resumed.thread.id, session);
  await begin(second.client, 'SYNTHETIC_AUTO_RESUMED_REQUEST');
  assert.equal(observations.length, 7);
  await begin(second.client, 'SYNTHETIC_AUTO_AFTER_POST_REQUEST');
  assert.deepEqual(await stop(second.handle, true), { code: 0, signal: null }, second.handle.stderr);
  assert.equal(observations.length, 8);
  for (const [name, turn] of [['pre', turns[1]], ['mid', turns[1]], ['post', turns[2]]]) {
    assert.equal(observations.find(item => item.name === name).turn_id, turn, 'automatic compaction belongs to its business Turn');
  }
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    await outbox.refreshQueueStats(); const state = outbox.snapshot();
    if (state.pending + state.processing + state.openTransactions === 0 && finalized === 8) break;
    await delay(25);
  }
  const state = outbox.snapshot();
  assert.equal(state.pending + state.processing + state.openTransactions + state.failed, 0);
  assert.equal(state.durable, 8); assert.equal(finalized, 8);
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
  t.diagnostic(JSON.stringify({ phase: 'automatic_compaction', native_turns: inspection.session.native_turns,
    session_epochs: inspection.session.session_epochs, integrity: inspection.integrity, source_counts: audit.sources }));
  assert.equal(inspection.delivery_ready, true);
  assert.equal(inspection.session.native_turns, 4); assert.equal(inspection.session.closed_turns, 4);
  assert.equal(inspection.session.closed_session_epochs, 2);
  assert.equal(inspection.session.model_interactions, 8); assert.equal(inspection.session.tool_execution_records, 1);
  assert.deepEqual(new Set(inspection.session.turns.map(turn => turn.turn_id)), new Set(turns));
  for (const counts of Object.values(audit.sources)) {
    assert.equal(counts.unknown_session_records, 0); assert.equal(counts.unscoped_turn_records, 0);
  }
  const rawDigests = []; const records = [];
  for (const name of (await fs.readdir(path.join(capture, 'segments'))).filter(name => name.endsWith('.sealed.ndjson'))) {
    const file = path.join(capture, 'segments', name);
    rawDigests.push({ file: name, sha256: await fileDigest(file), bytes: (await fs.stat(file)).size });
    for await (const line of readline.createInterface({ input: createReadStream(file) })) records.push(JSON.parse(line));
  }
  for (const name of ['PreCompact', 'PostCompact']) {
    const hooks = records.filter(record => record.lifecycleEvent?.source_event_name === name);
    assert.equal(hooks.length, 3);
    for (const hook of hooks) assert.equal(hook.lifecycleEvent.source_event.trigger, 'auto');
  }
  const decode = async file => zlib.zstdDecompressSync(await fs.readFile(path.join(projectionRoot, file)))
    .toString('utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  const interactions = await decode('interactions/model-interactions.jsonl.zst');
  assert.equal(interactions.length, 8);
  for (const observed of observations) {
    const saved = records.find(record => record.captureId === observed.capture_id);
    assert.equal(sha256(saved.requestBody.raw), observed.request_sha256);
    assert.equal(sha256(saved.responseBody.raw ?? saved.responseBody.value), observed.response_sha256);
    const interaction = interactions.find(item => item.raw_capture_refs.some(ref => ref.capture_id === observed.capture_id));
    assert.equal(interaction.trace_context.turn_id ?? interaction.trace_context.root_turn_id, observed.turn_id);
    assert.equal(interaction.response.id, observed.response_id);
    assert.ok(isDeepStrictEqual(interaction.request.raw, JSON.parse(saved.requestBody.raw)), 'complete automatic compaction input must survive (payload omitted)');
    assert.ok(isDeepStrictEqual(interaction.response.output_items.map(item => item.raw), observed.output_items),
      'complete automatic compaction output must survive (payload omitted)');
  }
  const runtime = await decode('runtime/runtime-spans.jsonl.zst');
  const execution = runtime.find(span => span.span_kind === 'tool_execution' && span.call_id === tool.call_id);
  assert.equal(execution.extensions.process_outcome.exit_code, 7);
  for (const turn of turns) {
    const span = runtime.find(span => span.span_kind === 'turn' && span.trace_context.turn_id === turn);
    assert.equal(span.extensions.root_complete, true);
    assert.notEqual(span.result.type, 'compaction_end', 'automatic PostCompact must not replace the business terminal');
    const hooks = records.filter(record => ['PreCompact', 'PostCompact'].includes(record.lifecycleEvent?.source_event_name)
      && record.lifecycleEvent.source_event.turn_id === turn);
    if (hooks.length) {
      assert.equal(span.extensions.compaction.complete, true);
      assert.equal(span.extensions.compaction.operations, turn === turns[1] ? 2 : 1);
      for (const hook of hooks) assert.ok(span.raw_capture_refs.includes(hook.captureId));
    }
  }
  const negativeCases = [];
  for (const mutation of ['missing-stop-mid', 'missing-stop-post', 'missing-auto-pre', 'missing-auto-post']) {
    const turn = mutation === 'missing-stop-post' ? turns[2] : turns[1];
    const compactionHook = mutation.startsWith('missing-auto-');
    const omitted = compactionHook ? mutation.endsWith('post') ? 'PostCompact' : 'PreCompact' : 'Stop';
    const eventId = compactionHook ? records.findLast(record => record.lifecycleEvent?.source_event_name === omitted
      && record.lifecycleEvent.source_event.turn_id === turn).lifecycleEvent.source_event.event_id : null;
    if (compactionHook) assert.equal(typeof eventId, 'string', 'remove exactly one real native Hook invocation');
    const derived = records.filter(record => {
      const source = record.lifecycleEvent?.source_event ?? (record.telemetryBatch?.endpoint === 'codex_hook'
        ? JSON.parse(record.telemetryBatch.raw_json) : null);
      return source?.hook_event_name !== omitted || source.turn_id !== turn
        || (compactionHook && source.event_id !== eventId);
    });
    assert.ok(derived.length < records.length, 'negative copy must remove actual native Hook evidence');
    const file = path.join(root, `derived-${mutation}.ndjson`);
    await fs.writeFile(file, derived.map(record => JSON.stringify(record)).join('\n') + '\n', { flag: 'wx' });
    const refused = JSON.parse((await run(chiptrace, ['inspect-session', '--input', file,
      '--session-id', session, '--projection-output', path.join(root, `refused-${mutation}`)],
    { maxBuffer: 32 * 1024 * 1024 })).stdout);
    await fs.writeFile(path.join(root, `${mutation}-inspection.json`), JSON.stringify(refused, null, 2));
    assert.equal(refused.integrity.protocol_complete, true);
    assert.equal(refused.delivery_ready, false, mutation);
    assert.equal(refused.session.delivery_ready, false, mutation);
    assert.equal(refused.integrity.root_complete, false, mutation);
    assert.equal(refused.integrity.runtime_complete, false, mutation);
    if (!compactionHook) {
      assert.equal(refused.session.open_turns, 1, mutation);
    } else {
      assert.equal(refused.session.conflicted_turns, 1);
      assert.equal(refused.session.turns.find(item => item.turn_id === turn).terminal_events,
        inspection.session.turns.find(item => item.turn_id === turn).terminal_events);
    }
    negativeCases.push({ mutation, removed_records: records.length - derived.length,
      integrity: refused.integrity, session_delivery_ready: refused.session.delivery_ready,
      open_turns: refused.session.open_turns, conflicted_turns: refused.session.conflicted_turns,
      observed_business_terminals: refused.session.turns.find(item => item.turn_id === turn).terminal_events });
  }
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
  const report = { schema_version: 'chiptrace.native-auto-compaction-ci.v1', ok: true,
    checked_at: new Date().toISOString(), real_upstream: false, unmodified_stock: false,
    production_acceptance_claimed: false, model_mode: 'local_deterministic_responses',
    producer_mode: 'patched_stock_debug_app_server', client_version: version,
    producer_source: fixture.source, patch_set: fixture.patchSet, producer_binary_sha256: await fileDigest(fixture.producer),
    native_turns: 4, session_epochs: 2, model_interactions: 8, tool_execution_records: 1,
    automatic_compaction_phases: ['pre_turn', 'mid_turn', 'post_turn'],
    compaction_input_output_verified: true, pre_post_hooks_verified: true,
    summary_process_resume_verified: true, failed_tool_preserved: true,
    missing_business_terminal_and_compaction_hook_refused: true,
    negative_cases: negativeCases,
    source_coverage: inspection.source_coverage, source_audit: audit, collector_raw: rawDigests,
    platform_evidence: platformEvidence, restart_verified: true };
  assert.throws(() => verifyNativeCanaryReport(report, audit), /real_upstream/);
  if (process.env.CHIPTRACE_AUTO_COMPACTION_REPORT) {
    await fs.writeFile(process.env.CHIPTRACE_AUTO_COMPACTION_REPORT, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  }
  fixture.passed();
}

test('native automatic pre/mid/post compaction preserves every interaction and requires business and compaction boundaries',
  { timeout: 240000 }, async t => {
    try { await collectAutomaticCompaction(t); }
    catch (error) {
      if (process.env.GITHUB_ACTIONS === 'true') {
        const message = String(error.message).replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').slice(0, 4000)
          .replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
        console.log(`::error title=Native protocol collection::${message}`);
      }
      throw error;
    }
  });
