'use strict';

// Real native interrupt/retry RPC and HTTP socket closure, with synthetic model
// bytes and an isolated patched producer. Never a production acceptance claim.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { createReadStream } = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const zlib = require('node:zlib');
const test = require('node:test');
const { codexTraceContextFromHeaders } = require('../openai-gateway/durable-outbox');
const { verifyNativeCanaryReport } = require('../../scripts/ci/native-canary-gate');
const { run, version, chiptrace, sha256, delay, fileDigest, stop, health, protocolFixture } = require('./protocol-fixture');

const events = values => values.map(value => `event: ${value.type}\ndata: ${JSON.stringify(value)}\n\n`).join('');

async function collectInterruption(t) {
  const fixture = await protocolFixture(t, 'chiptrace-interruption-');
  const { root, token, capture, collectorUrl, relayUrl, collectorArgs, relayArgs, launch, outbox } = fixture;
  let { collector, relay } = fixture;
  const catalog = JSON.parse(await fs.readFile(path.join(__dirname, 'managed-models.json'), 'utf8'));
  catalog.models.find(model => model.slug === 'gpt-6-astra').use_responses_lite = false;
  const observations = [];
  const wire = [];
  const modes = ['interrupt', 'disconnect', 'recovery', 'continuation'];
  const endpoint = await fixture.serve(async (req, res) => {
    const chunks = [];
    let bytes = 0;
    for await (const chunk of req) {
      assert.ok((bytes += chunk.length) <= 8 * 1024 * 1024, 'synthetic request exceeded 8 MiB');
      chunks.push(chunk);
    }
    const route = new URL(req.url, 'http://127.0.0.1').pathname;
    if (route === '/analytics/codex/turn-costs') {
      assert.equal(req.method, 'POST');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
      return;
    }
    assert.equal(req.headers.authorization, 'Bearer synthetic-protocol-provider');
    if (route === '/models') {
      assert.equal(req.method, 'GET');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(catalog));
      return;
    }
    assert.equal(req.method, 'POST');
    assert.equal(route, '/responses');
    const context = codexTraceContextFromHeaders(req.headers);
    assert.deepEqual(context.errors, []);
    assert.deepEqual(context.conflicts, []);
    assert.ok(context.trace.session_id && context.trace.turn_id, 'actual Wire native identities required');
    const request = Buffer.concat(chunks);
    const body = JSON.parse(request);
    assert.equal(body.model, 'gpt-6-astra');
    assert.equal(body.stream, true);
    assert.ok(observations.length < modes.length, 'unexpected additional HTTP attempt');
    const mode = modes[observations.length];
    const responseId = `resp-${mode}`;
    const text = `SYNTHETIC_${mode.toUpperCase()}_TEXT 中文 🧪`;
    const item = { type: 'message', id: `msg-${mode}`, role: 'assistant', phase: 'final_answer',
      content: [{ type: 'output_text', text }] };
    const prefix = [
      { type: 'response.created', response: { id: responseId, output: [] } },
      { type: 'response.output_item.added', output_index: 0, item: { ...item, content: [] } },
      { type: 'response.content_part.added', item_id: item.id, output_index: 0, content_index: 0,
        part: { type: 'output_text', text: '' } },
      { type: 'response.output_text.delta', item_id: item.id, output_index: 0, content_index: 0, delta: text },
    ];
    const partial = mode === 'interrupt' || mode === 'disconnect';
    const emitted = partial ? prefix : [...prefix,
      { type: 'response.output_item.done', output_index: 0, item },
      { type: 'response.completed', response: { id: responseId, output: [item],
        usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 } } },
    ];
    const response = Buffer.from(events(emitted));
    const captureId = `cap-interruption-${crypto.randomUUID()}`;
    const requestId = `request-${crypto.randomUUID()}`;
    const observation = { mode, capture_id: captureId, session_id: context.trace.session_id,
      turn_id: context.trace.turn_id, response_id: responseId, text, partial,
      request_sha256: sha256(request), response_sha256: sha256(response),
      response_bytes: response.length, input: body.input, response: response.toString('utf8') };
    observations.push(observation);
    const transaction = await outbox.beginCapture({ captureId,
      version: 'chiptrace.capture.v2', recordType: 'api_snapshot', sourceNamespace: 'synthetic-interruption-ci',
      method: req.method, proxiedPath: req.url, startedAt: new Date().toISOString(),
      traceContext: context.trace, fieldEvidence: context.evidence,
      fieldEvidenceConflicts: context.conflicts, traceContextErrors: context.errors });
    await transaction.appendRequest(request);
    let forwarded = 0;
    let finished = false;
    let closedBeforeFinish = false;
    let bytesAtClose;
    let terminalAtClose;
    let terminalWritten = false;
    const completion = new Promise(resolve => {
      res.once('finish', () => { finished = true; resolve(); });
      res.once('close', () => {
        closedBeforeFinish = !res.writableFinished;
        bytesAtClose = forwarded;
        terminalAtClose = terminalWritten;
        resolve();
      });
    });
    const responseHeaders = { 'content-type': 'text/event-stream', 'x-request-id': requestId };
    res.writeHead(200, responseHeaders);
    // The final delta must actually reach the App Server before either fault.
    await transaction.appendResponse(response);
    res.write(response);
    forwarded += response.length;
    terminalWritten = emitted.some(event => event.type === 'response.completed');
    if (mode === 'disconnect') observation.disconnect = () => res.destroy();
    if (!partial) res.end();
    await completion;
    const status = { upstreamResponseCompleted: finished && terminalWritten,
      clientRequestAborted: req.aborted, clientResponseClosedBeforeFinish: closedBeforeFinish,
      clientResponseFinished: finished, responseBytesForwarded: forwarded,
      responseProtocolTerminalObserved: terminalWritten,
      ...(closedBeforeFinish ? { responseBytesForwardedAtClientClose: bytesAtClose,
        responseProtocolTerminalObservedAtClientClose: terminalAtClose } : {}) };
    await transaction.finalize({ responseStatus: 200, stream: true, responseHeaders,
      finishedAt: new Date().toISOString(), ...status });
    wire.push({ ...observation, status });
  });
  const connect = await fixture.configure(endpoint, catalog);
  const { client, handle } = await connect();
  const started = await client.request('thread/start', {
    model: 'gpt-6-astra', cwd: root, approvalPolicy: 'never', sandbox: 'read-only', ephemeral: false });
  const session = started.thread.id;
  const begin = async text => (await client.request('turn/start', { threadId: session,
    input: [{ type: 'text', text, text_elements: [] }], model: 'gpt-6-astra' })).turn.id;
  const delta = turn => client.notification('item/agentMessage/delta',
    params => params.threadId === session && params.turnId === turn);
  const interrupted = await begin('INTERRUPT_REQUEST');
  assert.equal((await delta(interrupted)).delta, observations[0].text);
  await client.request('turn/interrupt', { threadId: session, turnId: interrupted });
  const interruptedResult = await client.completed(session, interrupted, 'interrupted');
  const disconnected = await begin('DISCONNECT_REQUEST');
  assert.equal((await delta(disconnected)).delta, observations[1].text);
  assert.equal(typeof observations[1].disconnect, 'function');
  observations[1].disconnect();
  await client.completed(session, disconnected);
  const continuation = await begin('CONTINUE_REQUEST');
  await client.completed(session, continuation);
  assert.equal(new Set([interrupted, disconnected, continuation]).size, 3);
  assert.deepEqual(await stop(handle, true), { code: 0, signal: null }, handle.stderr);
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    fixture.assertHealthy();
    await outbox.refreshQueueStats();
    const state = outbox.snapshot();
    if (state.pending + state.processing + state.openTransactions === 0 && wire.length === modes.length) break;
    await delay(25);
  }
  fixture.assertHealthy();
  const state = outbox.snapshot();
  assert.equal(state.pending + state.processing + state.openTransactions + state.failed, 0);
  assert.equal(state.durable, 4);
  assert.equal(wire.length, 4);
  assert.deepEqual(observations.map(item => item.mode), modes);
  assert.ok(wire.every(record => record.session_id === session));
  assert.equal(observations[0].turn_id, interrupted);
  assert.equal(observations[1].turn_id, disconnected);
  assert.equal(observations[2].turn_id, disconnected, 'a real retry must retain the native Turn');
  assert.equal(observations[3].turn_id, continuation);
  for (const attempt of observations.slice(1, 3)) {
    assert.ok(JSON.stringify(attempt.input).includes('DISCONNECT_REQUEST'), 'retry must retain the actual user input');
  }
  const delivered = await health(relayUrl, relay, value => value.pending === 0 && value.inflight === 0);
  assert.equal(delivered.conservation_ok, true);
  assert.equal(delivered.failed, 0);
  assert.equal(delivered.ingest_coverage.quality_errors, 0);
  for (const url of [relayUrl, collectorUrl]) {
    const response = await fetch(`${url}/flush`, { method: 'POST',
      headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
    assert.equal(response.status, 200);
  }
  const projectionRoot = path.join(root, 'projection');
  const inspect = async () => JSON.parse((await run(chiptrace,
    ['inspect-session', '--input', capture, '--session-id', session, '--projection-output', projectionRoot],
    { maxBuffer: 32 * 1024 * 1024 })).stdout);
  const inspection = await inspect();
  const audit = JSON.parse((await run(chiptrace,
    ['audit-session-context', '--input', capture, '--session-id', session, '--sample-limit', '0'],
    { maxBuffer: 1024 * 1024 })).stdout);
  await fs.writeFile(path.join(root, 'inspection.json'), JSON.stringify(inspection, null, 2));
  await fs.writeFile(path.join(root, 'audit.json'), JSON.stringify(audit, null, 2));
  t.diagnostic(JSON.stringify({ phase: 'interrupted_collection', native_turns: inspection.session.native_turns,
    closed_turns: inspection.session.closed_turns, model_interactions: inspection.session.model_interactions,
    integrity: inspection.integrity, source_counts: audit.sources }));
  assert.equal(inspection.session.native_turns, 3);
  assert.equal(inspection.session.closed_turns, 3);
  assert.equal(inspection.session.open_turns, 0);
  assert.equal(inspection.session.conflicted_turns, 0);
  assert.equal(inspection.session.unscoped_turn_records, 0);
  assert.equal(inspection.session.closed_session_epochs, 1);
  assert.equal(inspection.session.turns.find(turn => turn.turn_id === interrupted).status, 'cancelled');
  for (const turn of [disconnected, continuation]) {
    assert.equal(inspection.session.turns.find(item => item.turn_id === turn).status, 'closed');
  }
  for (const counts of Object.values(audit.sources)) {
    assert.equal(counts.unknown_session_records, 0);
    assert.equal(counts.unscoped_turn_records, 0);
    assert.equal(counts.total_records, counts.turn_assigned_records + counts.session_level_records
      + counts.process_level_records + counts.other_session_records);
  }
  assert.equal(inspection.source_coverage.complete, true);
  assert.equal(inspection.session.turn_source_coverage_complete, true);
  assert.equal(inspection.session.model_interactions, 4);
  assert.equal(inspection.delivery_ready, false, 'real partial responses must fail complete delivery');
  assert.equal(inspection.integrity.protocol_complete, false);
  assert.equal(inspection.integrity.raw_bytes_complete, true, 'all actually observed bytes remain intact');
  const rawDigests = [];
  const savedWire = [];
  const lifecycle = [];
  for (const name of (await fs.readdir(path.join(capture, 'segments'))).filter(name => name.endsWith('.sealed.ndjson'))) {
    const file = path.join(capture, 'segments', name);
    rawDigests.push({ file: name, sha256: await fileDigest(file), bytes: (await fs.stat(file)).size });
    for await (const line of readline.createInterface({ input: createReadStream(file) })) {
      const record = JSON.parse(line);
      if (record.recordType === 'api_snapshot') savedWire.push(record);
      if (record.recordType === 'lifecycle_event') lifecycle.push(record);
    }
  }
  assert.equal(savedWire.length, 4);
  const interactions = zlib.zstdDecompressSync(await fs.readFile(path.join(projectionRoot,
    'interactions/model-interactions.jsonl.zst'))).toString('utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.equal(interactions.length, 4);
  const interactionIds = new Set();
  for (const observed of wire) {
    const saved = savedWire.find(record => record.captureId === observed.capture_id);
    assert.ok(saved, 'every actual HTTP attempt must reach the Collector');
    const response = saved.responseBody.raw ?? saved.responseBody.value;
    assert.equal(sha256(saved.requestBody.raw), observed.request_sha256);
    assert.equal(sha256(response), observed.response_sha256);
    assert.equal(saved.responseBytesCaptured, observed.response_bytes);
    assert.equal(saved.traceContext.session_id, session);
    assert.equal(saved.traceContext.turn_id, observed.turn_id);
    for (const [key, value] of Object.entries(observed.status)) assert.equal(saved[key], value, key);
    const matches = interactions.filter(item => item.raw_capture_refs.some(ref => ref.capture_id === observed.capture_id));
    assert.equal(matches.length, 1, 'a successful retry must not overwrite the partial attempt');
    const interaction = matches[0];
    interactionIds.add(interaction.interaction_id);
    assert.equal(interaction.trace_context.session_id, session);
    assert.equal(interaction.trace_context.turn_id ?? interaction.trace_context.root_turn_id, observed.turn_id);
    assert.ok(interaction.extensions.wire.response.raw_utf8 === observed.response,
      'Canonical must preserve the exact observed SSE prefix (payload omitted)');
    assert.equal(interaction.integrity.raw_bytes_complete, true);
    assert.equal(interaction.integrity.status_dimensions_complete, true);
    assert.equal(interaction.integrity.client_delivery_evidence_consistent, true);
    assert.equal(interaction.integrity.trace_identity_complete, true);
    assert.equal(interaction.integrity.malformed_sse_events, 0);
    assert.equal(interaction.integrity.protocol_complete, !observed.partial);
    assert.equal(interaction.extensions.wire.stream_state.protocol_terminal_observed, !observed.partial);
    if (observed.partial) {
      assert.equal(saved.clientResponseClosedBeforeFinish, true);
      assert.equal(saved.clientResponseFinished, false);
      assert.equal(saved.responseBytesForwardedAtClientClose, observed.response_bytes);
      assert.equal(saved.responseProtocolTerminalObservedAtClientClose, false);
      assert.equal(interaction.response.client_delivery_status, 'cancelled');
      assert.equal(interaction.integrity.stream_outcome, 'transport_error');
    } else {
      assert.equal(interaction.integrity.stream_outcome, 'completed');
      assert.equal(interaction.response.output_items[0].raw.content[0].text, observed.text);
    }
  }
  assert.equal(interactionIds.size, 4);
  assert.ok(lifecycle.some(record => record.lifecycleEvent.type === 'turn_interrupt'
    && record.lifecycleEvent.source_event_name === 'Interrupt'
    && record.traceContext.session_id === session && record.traceContext.turn_id === interrupted),
  'actual Interrupt Hook must retain its native Turn');
  assert.deepEqual(await stop(relay), { code: 0, signal: null });
  assert.deepEqual(await stop(collector), { code: 0, signal: null });
  collector = launch(chiptrace, collectorArgs, { CHIPTRACE_INGEST_TOKEN: token });
  await health(collectorUrl, collector, value => value.collector.captures === delivered.delivered);
  relay = launch(chiptrace, relayArgs, { CHIPTRACE_INGEST_TOKEN: token });
  await health(relayUrl, relay, value => value.delivered === delivered.delivered && value.conservation_ok);
  const stable = value => ({ ...value, projection: { ...value.projection, created_at_utc: null } });
  assert.deepEqual(stable(await inspect()), stable(inspection));
  for (const record of rawDigests) assert.equal(await fileDigest(path.join(capture, 'segments', record.file)), record.sha256);
  const platformEvidence = await fixture.verifyPlatform();
  const report = { schema_version: 'chiptrace.native-interruption-ci.v1', ok: true,
    checked_at: new Date().toISOString(), real_upstream: false, unmodified_stock: false,
    production_acceptance_claimed: false, model_mode: 'local_deterministic_responses',
    producer_mode: 'patched_stock_debug_app_server', client_version: version,
    producer_source: fixture.source, patch_set: fixture.patchSet,
    producer_binary_sha256: await fileDigest(fixture.producer),
    native_turns: 3, model_interactions: 4, interrupted_status: interruptedResult.status,
    real_partial_deltas_received: 2, same_turn_retry_verified: true, continuation_verified: true,
    partial_attempts_preserved: true, partial_delivery_rejected: !inspection.delivery_ready,
    native_boundaries_verified: true, restart_verified: true,
    attempts: wire.map(({ mode, capture_id, turn_id, request_sha256, response_sha256, response_bytes, status }) =>
      ({ mode, capture_id, turn_id, request_sha256, response_sha256, response_bytes, status })),
    source_coverage: inspection.source_coverage, source_audit: audit, collector_raw: rawDigests,
    platform_evidence: platformEvidence };
  assert.throws(() => verifyNativeCanaryReport(report, audit), /real_upstream/);
  if (process.env.CHIPTRACE_INTERRUPTION_REPORT) {
    await fs.writeFile(process.env.CHIPTRACE_INTERRUPTION_REPORT, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  }
  t.diagnostic(JSON.stringify({ native_turns: 3, model_interactions: 4, interrupted_status: interruptedResult.status,
    partial_delivery_rejected: true, restart_verified: true, production_acceptance_claimed: false }));
  fixture.passed();
}

test('native collection preserves real interruption, disconnected retry and continuation without claiming complete partial delivery',
  { timeout: 180000 }, async t => {
    try {
      await collectInterruption(t);
    } catch (error) {
      if (process.env.GITHUB_ACTIONS === 'true') {
        const message = String(error.message).replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').slice(0, 4000)
          .replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
        console.log(`::error title=Native protocol collection::${message}`);
      }
      throw error;
    }
  });
