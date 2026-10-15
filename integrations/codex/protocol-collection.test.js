'use strict';

// Execute a real, pinned, patched debug App Server against a local deterministic
// Responses endpoint. These newly collected bytes are protocol regression
// evidence, never real-model or unmodified-producer production acceptance.
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

function sse(id, items, streamedItems = items) {
  return [{ type: 'response.created', response: { id } },
    ...streamedItems.map((item, output_index) => ({ type: 'response.output_item.done', output_index, item })),
    { type: 'response.completed', response: { id, output: items,
      usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 } } }]
    .map(value => `event: ${value.type}\ndata: ${JSON.stringify(value)}\n\n`).join('');
}

function deterministicModel(image, switchModel) {
  let phase = 'plan-start';
  let polls = 0;
  let processId;
  let retried = false;
  const observations = [];
  // Synthetic protocol content only; this is never a real model's reasoning.
  const reasoning = { type: 'reasoning', id: 'protocol-reasoning',
    summary: [{ type: 'summary_text', text: 'SYNTHETIC_PROTOCOL_SUMMARY 中文 🧪' }],
    encrypted_content: 'SYNTHETIC_OPAQUE_REASONING_CONTEXT' };
  const tool = (callId, name, args) => ({ type: 'function_call', call_id: callId,
    name, arguments: JSON.stringify(args) });
  const result = (body, callId) => {
    const value = body.input.find(item => item.type === 'function_call_output' && item.call_id === callId)?.output;
    assert.notEqual(value, undefined, `missing actual tool result for ${callId}`);
    return value;
  };
  const output = (body, callId) => {
    const value = result(body, callId);
    assert.equal(typeof value, 'string', `missing actual tool output for ${callId}`);
    return value;
  };
  const verifyImage = content => {
    assert.ok(Array.isArray(content), 'view_image must return structured content');
    const images = content.filter(item => item.type === 'input_image');
    assert.equal(images.length, 1, 'the actual tool must return one image');
    const encoded = /^data:image\/png;base64,([A-Za-z0-9+/=]+)$/.exec(images[0].image_url);
    assert.ok(encoded, 'view_image must return the actual inline PNG');
    const bytes = Buffer.from(encoded[1], 'base64');
    assert.equal(bytes.length, image.bytes);
    assert.equal(sha256(bytes), image.sha256, 'view_image must retain the fixture image bytes');
  };
  const verifyReasoning = input => {
    const item = input.find(item => item.type === 'reasoning'
      && item.encrypted_content === reasoning.encrypted_content);
    assert.ok(item, 'the real producer must replay its actual opaque reasoning context');
    assert.ok(isDeepStrictEqual(item.summary, reasoning.summary),
      'the real producer must retain the synthetic reasoning summary (payload omitted)');
  };
  return {
    observations,
    verifyImage,
    get finished() { return phase === 'done'; },
    respond(body, turnId) {
      const secondTurn = ['resumed', 'plan-complete', 'final'].includes(phase);
      const upstreamModel = !switchModel || secondTurn ? 'gpt-6-astra' : 'gpt-5.6-sol';
      assert.equal(body.model, upstreamModel);
      assert.equal(body.parallel_tool_calls, !switchModel || secondTurn,
        'actual requests must retain the selected Lite or parallel Responses profile');
      assert.equal(body.stream, true);
      if (phase === 'resumed' && !retried) {
        retried = true;
        const error = { error: { type: 'server_error', code: 'protocol_expected_retry',
          message: 'SYNTHETIC_EXPECTED_RETRY_503' } };
        observations.push({ turn_id: turnId, model: body.model, parallel_tool_calls: body.parallel_tool_calls,
          response_id: null, http_status: 503, error_response: error, output_items: [], tool_calls: [],
          input_sha256: sha256(JSON.stringify(body.input)), input_items: body.input.length });
        return { status: 503, content_type: 'application/json', upstream_model: upstreamModel, body: JSON.stringify(error) };
      }
      let item;
      const exec = (callId, cmd, yieldTime = 250) => tool(callId, 'exec_command',
        { cmd, shell: '/bin/sh', login: false, yield_time_ms: yieldTime, max_output_tokens: 2000 });
      if (phase === 'plan-start') {
        item = tool('protocol-plan-start', 'update_plan', {
          plan: [{ step: 'Verify native multimodal collection and resume', status: 'in_progress' }],
        });
        phase = 'goal';
      } else if (phase === 'goal') {
        verifyReasoning(body.input);
        assert.equal(output(body, 'protocol-plan-start'), 'Plan updated');
        item = tool('protocol-goal', 'get_goal', {});
        phase = 'image';
      } else if (phase === 'image') {
        assert.equal(JSON.parse(output(body, 'protocol-goal')).goal, null,
          'the isolated thread must read its actual empty goal');
        item = tool('protocol-image', 'view_image', { path: image.path, detail: 'original' });
        phase = 'read';
      } else if (phase === 'read') {
        verifyImage(result(body, 'protocol-image'));
        item = exec('protocol-read', 'head -n 12 README.md');
        phase = 'fail';
      } else if (phase === 'fail') {
        const actual = output(body, 'protocol-read');
        assert.match(actual, /CHIPTRACE_READ_OK/, `first real shell read failed: ${actual}`);
        item = exec('protocol-fail', 'printf CHIPTRACE_EXPECTED_EXIT_7 >&2; exit 7');
        phase = 'launch';
      } else if (phase === 'launch') {
        assert.match(output(body, 'protocol-fail'), /Process exited with code 7/);
        item = exec('protocol-launch', 'sleep 2; printf CHIPTRACE_CANARY_DONE');
        phase = 'poll';
      } else if (phase === 'poll') {
        const actual = output(body, polls === 0 ? 'protocol-launch' : `protocol-poll-${polls}`);
        const running = /Process running with session ID (\d+)/.exec(actual);
        if (polls === 0) {
          assert.ok(running, 'the actual delayed process must return a running session');
          processId = Number(running[1]);
        }
        if (running) {
          assert.equal(Number(running[1]), processId);
          assert.ok(++polls <= 8, 'delayed process did not finish');
          item = tool(`protocol-poll-${polls}`, 'write_stdin',
            { session_id: processId, chars: '', yield_time_ms: 1000, max_output_tokens: 2000 });
        } else {
          assert.match(actual, /Process exited with code 0/);
          assert.match(actual, /CHIPTRACE_CANARY_DONE/);
          item = { type: 'message', role: 'assistant', id: 'protocol-first-final',
            content: [{ type: 'output_text', text: 'FIRST_TURN_COMPLETE 中文 🧪' }] };
          phase = 'resumed';
        }
      } else if (phase === 'resumed') {
        assert.ok(JSON.stringify(body.input).includes('SECOND_TURN_REQUEST'));
        assert.match(output(body, 'protocol-fail'), /Process exited with code 7/,
          'resume must retain the failed first-turn tool output');
        assert.equal(output(body, 'protocol-plan-start'), 'Plan updated');
        assert.equal(JSON.parse(output(body, 'protocol-goal')).goal, null);
        verifyImage(result(body, 'protocol-image'));
        verifyReasoning(body.input);
        const commentary = body.input.find(item => item.type === 'message' && item.role === 'assistant'
          && item.content?.some(content => content.text === 'FIRST_TURN_COMMENTARY'));
        assert.equal(commentary?.phase, 'commentary', 'resume must retain the actual assistant message phase');
        item = exec('protocol-resumed', 'sleep 1; printf RESUMED_TURN_OK; printf CHIPTRACE_EXPECTED_EXIT_9 >&2; exit 9', 10000);
        phase = 'plan-complete';
      } else if (phase === 'plan-complete') {
        const actual = output(body, 'protocol-resumed');
        assert.match(actual, /Process exited with code 9/);
        assert.match(actual, /RESUMED_TURN_OK/);
        assert.match(output(body, 'protocol-count'), /16 README.md/,
          'the second real tool in the same model response must execute');
        item = tool('protocol-plan-complete', 'update_plan', {
          plan: [{ step: 'Verify native multimodal collection and resume', status: 'completed' }],
        });
        phase = 'final';
      } else if (phase === 'final') {
        assert.equal(output(body, 'protocol-plan-complete'), 'Plan updated');
        item = { type: 'message', role: 'assistant', id: 'protocol-second-final',
          content: [{ type: 'output_text', text: 'SECOND_TURN_COMPLETE' }] };
        phase = 'done';
      } else assert.fail('unexpected model request after terminal response');
      let items = [item];
      if (item.call_id === 'protocol-plan-start') items.unshift(reasoning);
      if (item.call_id === 'protocol-resumed') {
        assert.equal(body.parallel_tool_calls, true, 'the real request must enable parallel tool calls');
        items.push(exec('protocol-count', 'sleep 1; wc -l README.md', 10000));
      }
      if (item.id === 'protocol-first-final') items.unshift({ type: 'message', role: 'assistant',
        id: 'protocol-first-commentary', phase: 'commentary',
        content: [{ type: 'output_text', text: 'FIRST_TURN_COMMENTARY' }] });
      const streamedItems = [...items];
      if (item.id === 'protocol-second-final') items.push({ type: 'message', role: 'assistant',
        id: 'protocol-terminal-only-commentary', phase: 'commentary',
        content: [{ type: 'output_text', text: 'SYNTHETIC_TERMINAL_ONLY_OUTPUT 中文 🧪' }] });
      const definitions = specs => specs.flatMap(spec => spec.type === 'namespace'
        ? definitions(spec.tools) : [spec]);
      const declarations = definitions([...(body.tools || []), ...body.input
        .filter(input => input.type === 'additional_tools').flatMap(input => input.tools)]);
      const tools = items.filter(item => item.type === 'function_call').map(call => {
        const definition = declarations.find(spec => (spec.name ?? spec.function?.name) === call.name);
        assert.ok(definition, `the real producer must advertise ${call.name}`);
        return { call_id: call.call_id, name: call.name, turn_id: turnId,
          output_item: call, tool_definition: definition };
      });
      const responseId = `protocol-response-${observations.length + 1}`;
      observations.push({ turn_id: turnId, model: body.model, parallel_tool_calls: body.parallel_tool_calls,
        response_id: responseId, http_status: 200,
        output_items: items, streamed_output_items: streamedItems.length, tool_calls: tools,
        input_sha256: sha256(JSON.stringify(body.input)), input_items: body.input.length });
      return { status: 200, content_type: 'text/event-stream', upstream_model: upstreamModel,
        body: sse(responseId, items, streamedItems) };
    },
  };
}

async function collectProtocol(t, switchModel) {
    const fixture = await protocolFixture(t, 'chiptrace-protocol-');
    const { root, token, source, producer, patchSet, capture, collectorUrl, relayUrl,
      collectorArgs, relayArgs, outbox, launch } = fixture;
    let { collector, relay } = fixture;
    const imagePath = 'docs/assets/xs-mlvp-avatar.png';
    const imageSource = path.resolve(__dirname, '../../', imagePath);
    const image = { path: imagePath, bytes: (await fs.stat(imageSource)).size,
      sha256: await fileDigest(imageSource) };
    const model = deterministicModel(image, switchModel);
    const wire = [];
    const syntheticUsage = [];
    const catalog = JSON.parse(await fs.readFile(path.join(__dirname, 'managed-models.json'), 'utf8'));
    // Keep the default Lite profile for the switch regression. The single-model
    // Buyer regression uses ordinary Responses in both Turns, with real tools.
    catalog.models.find(model => model.slug === 'gpt-6-astra').use_responses_lite = false;
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
        if (route === '/models') {
          assert.equal(req.headers.authorization, 'Bearer synthetic-protocol-provider');
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify(catalog));
          return;
        }
        assert.equal(req.method, 'POST');
        assert.equal(route, '/responses');
        assert.equal(req.headers.authorization, 'Bearer synthetic-protocol-provider');
        const context = codexTraceContextFromHeaders(req.headers);
        assert.deepEqual(context.errors, []);
        assert.deepEqual(context.conflicts, []);
        assert.ok(context.trace.session_id && context.trace.turn_id, 'actual Wire native identities required');
        const request = Buffer.concat(chunks);
        const reply = model.respond(JSON.parse(request), context.trace.turn_id);
        const response = Buffer.from(reply.body);
        const captureId = `cap-protocol-${crypto.randomUUID()}`;
        model.observations.at(-1).capture_id = captureId;
        const transaction = await outbox.beginCapture({ captureId,
          version: 'chiptrace.capture.v2', recordType: 'api_snapshot', sourceNamespace: 'synthetic-protocol-ci',
          method: req.method, proxiedPath: req.url, startedAt: new Date().toISOString(),
          traceContext: context.trace, fieldEvidence: context.evidence,
          fieldEvidenceConflicts: context.conflicts, traceContextErrors: context.errors });
        await transaction.appendRequest(request);
        // Split in the middle of UTF-8 and SSE tokens as well as normal lines.
        const responseHeaders = { 'content-type': reply.content_type, 'x-request-id': `request-${crypto.randomUUID()}`,
          ...(reply.status === 503 ? { 'retry-after-ms': '1' } : {}) };
        res.writeHead(reply.status, responseHeaders);
        for (let offset = 0; offset < response.length; offset += 37) {
          const chunk = response.subarray(offset, offset + 37);
          await transaction.appendResponse(chunk);
          res.write(chunk);
        }
        const completion = new Promise((resolve, reject) => {
          res.once('finish', resolve);
          res.once('close', () => {
            if (!res.writableFinished) reject(new Error('synthetic response closed before finish'));
          });
        });
        res.end();
        await completion;
        await transaction.finalize({ responseStatus: reply.status, stream: reply.status === 200, responseHeaders,
          finishedAt: new Date().toISOString(), upstreamResponseCompleted: true,
          clientRequestAborted: req.aborted, clientResponseClosedBeforeFinish: res.destroyed && !res.writableFinished,
          clientResponseFinished: res.writableFinished, responseBytesForwarded: response.length });
        // Independent endpoint observations, not identities reconstructed from
        // Collector Raw. OpenAI is a synthetic route label, never a real claim.
        syntheticUsage.push({ request_id: responseHeaders['x-request-id'],
          requested_model: JSON.parse(request).model, upstream_model: reply.upstream_model,
          provider: 'OpenAI', input_tokens: 0, output_tokens: 0 });
        wire.push({ capture_id: captureId, session_id: context.trace.session_id, turn_id: context.trace.turn_id,
          request_sha256: sha256(request), response_sha256: sha256(response) });
    });
    await fs.writeFile(path.join(root, 'README.md'), 'CHIPTRACE_READ_OK 中文 🧪\n' + 'bounded fixture line\n'.repeat(15));
    await fs.mkdir(path.dirname(path.join(root, image.path)), { recursive: true });
    await fs.copyFile(imageSource, path.join(root, image.path));
    const connect = await fixture.configure(endpoint, catalog, true);
    const first = await connect();
    const firstModel = switchModel ? 'gpt-5.6-sol' : 'gpt-6-astra';
    const started = await first.client.request('thread/start', {
      model: firstModel, cwd: root, approvalPolicy: 'never', sandbox: 'read-only', ephemeral: false });
    const session = started.thread.id;
    const begin = async (client, prompt, model) => {
      const result = await client.request('turn/start', { threadId: session,
        input: [{ type: 'text', text: prompt, text_elements: [] }], model });
      await client.completed(session, result.turn.id);
      fixture.assertHealthy();
      return result.turn.id;
    };
    const turns = [await begin(first.client, 'FIRST_TURN_REQUEST', firstModel)];
    assert.deepEqual(await stop(first.handle, true), { code: 0, signal: null }, first.handle.stderr);
    const second = await connect();
    const resumed = await second.client.request('thread/resume', { threadId: session,
      cwd: root, approvalPolicy: 'never', sandbox: 'read-only' });
    assert.equal(resumed.thread.id, session);
    turns.push(await begin(second.client, 'SECOND_TURN_REQUEST', 'gpt-6-astra'));
    assert.notEqual(turns[0], turns[1]);
    assert.deepEqual(await stop(second.handle, true), { code: 0, signal: null }, second.handle.stderr);
    assert.equal(model.finished, true);
    fixture.assertHealthy();
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      await outbox.refreshQueueStats();
      const state = outbox.snapshot();
      if (state.pending === 0 && state.processing === 0 && state.openTransactions === 0 && wire.length === model.observations.length) break;
      await delay(25);
    }
    const state = outbox.snapshot();
    assert.equal(state.pending + state.processing + state.openTransactions + state.failed, 0);
    assert.equal(state.durable, model.observations.length);
    assert.equal(wire.length, model.observations.length);
    assert.equal(syntheticUsage.length, wire.length);
    await fs.writeFile(path.join(root, 'synthetic-usage.jsonl'),
      syntheticUsage.map(item => JSON.stringify(item)).join('\n') + '\n', { flag: 'wx', mode: 0o600 });
    assert.ok(wire.every(record => record.session_id === session && turns.includes(record.turn_id)));
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
    await fs.writeFile(path.join(root, 'inspection.json'), JSON.stringify(inspection, null, 2));
    const audit = JSON.parse((await run(chiptrace,
      ['audit-session-context', '--input', capture, '--session-id', session, '--sample-limit', '0'],
      { maxBuffer: 1024 * 1024 })).stdout);
    await fs.writeFile(path.join(root, 'audit.json'), JSON.stringify(audit, null, 2));
    t.diagnostic(JSON.stringify({ phase: 'new_collection', delivery_ready: inspection.delivery_ready,
      integrity: inspection.integrity, source_coverage: inspection.source_coverage, source_counts: audit.sources }));
    assert.equal(inspection.delivery_ready, true);
    assert.equal(inspection.integrity.delivery_ready, true);
    assert.equal(inspection.session.native_turns, 2);
    assert.equal(inspection.session.closed_turns, 2);
    assert.equal(inspection.session.closed_session_epochs, 2);
    assert.equal(inspection.session.model_interactions, wire.length);
    assert.deepEqual(new Set(inspection.session.turns.map(turn => turn.turn_id)), new Set(turns));
    assert.equal(inspection.scenario_evidence.complete, true);
    assert.equal(inspection.scenario_evidence.failed_tool_process.process_outcome.exit_code, 7);
    for (const counts of Object.values(audit.sources)) {
      assert.equal(counts.unknown_session_records, 0);
      assert.equal(counts.unscoped_turn_records, 0);
      assert.equal(counts.total_records, counts.turn_assigned_records + counts.session_level_records
        + counts.process_level_records + counts.other_session_records);
    }
    // Re-read the actual saved captures, rather than trusting gateway counters.
    const sealed = await fs.readdir(path.join(capture, 'segments'));
    const rawDigests = [];
    const savedWire = [];
    const nativeTools = [];
    for (const name of sealed.filter(name => name.endsWith('.sealed.ndjson'))) {
      const file = path.join(capture, 'segments', name);
      rawDigests.push({ file: name, sha256: await fileDigest(file), bytes: (await fs.stat(file)).size });
      for await (const line of readline.createInterface({ input: createReadStream(file) })) {
        const record = JSON.parse(line);
        if (record.recordType === 'api_snapshot') savedWire.push(record);
        if (record.toolExecution?.source_event_name === 'codex.tool_result') nativeTools.push(record);
      }
    }
    assert.equal(savedWire.length, wire.length);
    for (const expected of wire) {
      const saved = savedWire.find(record => record.captureId === expected.capture_id);
      assert.ok(saved, 'actual request bytes must reach Collector WAL');
      assert.equal(typeof saved.requestBody.raw, 'string');
      const responseRaw = saved.responseBody.raw ?? saved.responseBody.value;
      assert.equal(typeof responseRaw, 'string');
      assert.equal(sha256(saved.requestBody.raw), expected.request_sha256);
      assert.equal(sha256(responseRaw), expected.response_sha256);
      assert.equal(saved.requestBytesCaptured, Buffer.byteLength(saved.requestBody.raw));
      assert.equal(saved.responseBytesCaptured, Buffer.byteLength(responseRaw));
    }
    const issuedTools = model.observations.flatMap(item => item.tool_calls);
    assert.equal(nativeTools.length, issuedTools.length, 'every real tool result must reach Collector WAL');
    for (const issued of issuedTools) {
      const observed = nativeTools.filter(record => record.toolExecution.call_id === issued.call_id);
      assert.equal(observed.length, 1, `exactly one native result required for ${issued.call_id}`);
      assert.equal(observed[0].toolExecution.runtime_tool, issued.name);
      assert.equal(observed[0].traceContext.session_id, session);
    }
    const projectionRecords = async file => {
      const text = zlib.zstdDecompressSync(await fs.readFile(path.join(projectionRoot, file))).toString('utf8');
      return text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    };
    const interactions = await projectionRecords('interactions/model-interactions.jsonl.zst');
    const runtime = await projectionRecords('runtime/runtime-spans.jsonl.zst');
    assert.equal(interactions.length, model.observations.length);
    for (const observed of model.observations) {
      const matches = interactions.filter(item => item.raw_capture_refs
        .some(reference => reference.capture_id === observed.capture_id));
      assert.equal(matches.length, 1, 'every actual HTTP attempt must have a unique Canonical interaction');
      const interaction = matches[0];
      assert.equal(interaction.response.id, observed.response_id);
      assert.ok(isDeepStrictEqual(interaction.response.output_items.map(item => item.raw), observed.output_items),
        'Canonical model output must preserve every actual response item in order (payload omitted)');
      const captured = savedWire.find(record => interaction.raw_capture_refs
        .some(reference => reference.capture_id === record.captureId));
      assert.ok(captured, 'every Canonical interaction must reference its actual Collector Wire');
      assert.equal(captured.responseStatus, observed.http_status);
      if (observed.http_status === 200) {
        const terminal = interaction.extensions.wire.sse_events.find(event => event.data?.type === 'response.completed');
        assert.ok(isDeepStrictEqual(terminal?.data.response.output, observed.output_items),
          'the actual terminal response must retain its complete output array (payload omitted)');
      }
      if (observed.http_status === 503) {
        assert.ok(isDeepStrictEqual(interaction.response.raw, observed.error_response),
          'Canonical retry must preserve the actual HTTP error body (payload omitted)');
        assert.equal(interaction.response.model_status, 'failed');
        assert.equal(interaction.response.upstream_transport_status, 'completed');
        assert.equal(interaction.response.client_delivery_status, 'delivered');
        assert.ok(isDeepStrictEqual(interaction.error.response_error, observed.error_response.error),
          'Canonical retry diagnostics must preserve the actual HTTP error (payload omitted)');
        assert.equal(interaction.error.http_status, 503);
        assert.equal(interaction.error.stream_error, null, 'an HTTP error must not invent a stream error event');
        const stream = interaction.extensions.wire.stream_state;
        assert.equal(stream.http_error_response_complete, true);
        assert.equal(stream.protocol_terminal_observed, false);
        assert.equal(stream.framing_done_observed, false);
        assert.equal(interaction.extensions.wire.sse_events.length, 0);
        assert.equal(interaction.integrity.protocol_complete, true);
      }
      assert.ok(isDeepStrictEqual(interaction.request.raw, JSON.parse(captured.requestBody.raw)),
        'Canonical model input must preserve complete text, tools and multimodal history (payload omitted)');
      assert.equal(interaction.request.model, observed.model);
      assert.equal(interaction.trace_context.turn_id ?? interaction.trace_context.root_turn_id, observed.turn_id);
    }
    const retryIndex = model.observations.findIndex(item => item.http_status === 503);
    assert.ok(retryIndex >= 0, 'the real client must observe the injected HTTP failure');
    const retry = model.observations[retryIndex];
    const recovery = model.observations[retryIndex + 1];
    assert.equal(recovery.http_status, 200);
    assert.equal(recovery.turn_id, retry.turn_id, 'retry must keep its actual native Turn identity');
    assert.equal(recovery.input_sha256, retry.input_sha256, 'retry must preserve the actual model input history');
    assert.equal(model.observations.filter(item => item.http_status === 503).length, 1);
    const terminalOnlyItems = model.observations.filter(item => item.http_status === 200)
      .reduce((count, item) => count + item.output_items.length - item.streamed_output_items, 0);
    assert.equal(terminalOnlyItems, 1, 'collection must preserve an actual terminal-only output item');
    for (const turn of inspection.session.turns) {
      assert.equal(turn.model_interactions, wire.filter(item => item.turn_id === turn.turn_id).length,
        'each native Turn must include all actual HTTP attempts');
    }
    const imageResults = interactions.flatMap(item => item.tool_results_submitted)
      .filter(item => item.call_id === 'protocol-image');
    assert.ok(imageResults.length > 0, 'Canonical interactions must preserve the actual image result');
    for (const result of imageResults) model.verifyImage(result.content);
    for (const issued of issuedTools) {
      const spans = runtime.filter(span => span.span_kind === 'tool_execution' && span.call_id === issued.call_id);
      assert.equal(spans.length, 1, `Canonical runtime must preserve ${issued.call_id}`);
      const observed = nativeTools.find(record => record.toolExecution.call_id === issued.call_id);
      const execution = observed.toolExecution;
      const span = spans[0];
      assert.ok(isDeepStrictEqual(execution.arguments, JSON.parse(issued.output_item.arguments)),
        `native tool arguments must match the actual issued call ${issued.call_id} (payload omitted)`);
      assert.ok(isDeepStrictEqual(span.arguments, execution.arguments),
        `Canonical tool arguments must match native Raw for ${issued.call_id} (payload omitted)`);
      assert.ok(isDeepStrictEqual(span.result, execution.result),
        `Canonical tool result must match native Raw for ${issued.call_id} (payload omitted)`);
      assert.ok(isDeepStrictEqual(span.error, execution.error ?? null),
        `Canonical tool error must match native Raw for ${issued.call_id} (payload omitted)`);
      assert.ok(isDeepStrictEqual(span.extensions.process_outcome, execution.process_outcome ?? null),
        `Canonical process outcome must match native Raw for ${issued.call_id} (payload omitted)`);
      assert.equal(span.extensions.dispatch_status, execution.status);
      assert.equal(span.extensions.dispatch_status_provenance, execution.status_provenance);
      assert.equal(span.extensions.output_truncated, execution.output_truncated);
      assert.equal(span.extensions.result_content_captured, execution.result_content_captured);
      assert.ok(isDeepStrictEqual(span.tool_schema?.raw, issued.tool_definition),
        `Canonical tool schema must match its actual request declaration for ${issued.call_id} (payload omitted)`);
      const definition = issued.tool_definition.function ?? issued.tool_definition;
      assert.ok(isDeepStrictEqual(span.tool_schema.parameters, definition.parameters ?? definition.input_schema),
        `Canonical tool parameters must match the complete declaration for ${issued.call_id} (payload omitted)`);
      assert.ok(span.tool_schema.description === definition.description,
        `Canonical tool description must match the complete declaration for ${issued.call_id} (payload omitted)`);
      assert.ok(turns.includes(issued.turn_id), `tool ${issued.call_id} must be issued in an actual native Turn`);
      // Native tool logs can inherit their Turn through exact trace ancestry.
      // Compare the final assignment with the actual issuing Wire identity.
      assert.equal(spans[0].trace_context.turn_id ?? spans[0].trace_context.root_turn_id, issued.turn_id);
      assert.ok(spans[0].raw_capture_refs.includes(observed.captureId));
      assert.ok(spans[0].tool_schema?.description, `Canonical runtime must retain the schema for ${issued.name}`);
      assert.equal(spans[0].tool_schema.parameters?.type, 'object');
    }
    for (const [callId, turnId, status] of [
      ['protocol-plan-start', turns[0], 'in_progress'],
      ['protocol-plan-complete', turns[1], 'completed'],
    ]) {
      const span = runtime.find(span => span.span_kind === 'tool_execution' && span.call_id === callId);
      assert.equal(span.trace_context.turn_id ?? span.trace_context.root_turn_id, turnId);
      assert.equal(span.arguments.plan[0].status, status);
      assert.equal(span.result, 'Plan updated');
    }
    for (const [callId, exitCode] of [['protocol-fail', 7], ['protocol-resumed', 9]]) {
      const span = runtime.find(span => span.span_kind === 'tool_execution' && span.call_id === callId);
      assert.equal(span.extensions.process_outcome.exit_code, exitCode);
      assert.equal(span.extensions.semantic_status, 'error', 'a failed process must retain its failure semantics');
    }
    const parallelIntervals = ['protocol-resumed', 'protocol-count'].map(callId => {
      const execution = nativeTools.find(record => record.toolExecution.call_id === callId).toolExecution;
      const interval = { call_id: callId, start: Date.parse(execution.started_at), end: Date.parse(execution.finished_at) };
      assert.ok(Number.isFinite(interval.start) && interval.end > interval.start,
        'parallel execution evidence requires actual native start and finish times');
      return interval;
    });
    const parallelOverlapMs = Math.min(...parallelIntervals.map(item => item.end))
      - Math.max(...parallelIntervals.map(item => item.start));
    assert.ok(parallelOverlapMs > 0, 'the two actual read-only shell executions must overlap');
    assert.deepEqual(await stop(relay), { code: 0, signal: null });
    assert.deepEqual(await stop(collector), { code: 0, signal: null });
    collector = launch(chiptrace, collectorArgs, { CHIPTRACE_INGEST_TOKEN: token });
    await health(collectorUrl, collector, value => value.collector.captures === delivered.delivered);
    relay = launch(chiptrace, relayArgs, { CHIPTRACE_INGEST_TOKEN: token });
    await health(relayUrl, relay, value => value.delivered === delivered.delivered && value.conservation_ok);
    // Each inspect command creates a new projection manifest timestamp; all
    // evidence, Session fields, part bytes/hashes and integrity must be equal.
    const stable = value => ({ ...value, projection: { ...value.projection, created_at_utc: null } });
    assert.deepEqual(stable(await inspect()), stable(inspection), 'restart must preserve the complete Session view');
    for (const record of rawDigests) assert.equal(await fileDigest(path.join(capture, 'segments', record.file)), record.sha256);
    const platformEvidence = await fixture.verifyPlatform(switchModel ? 'model-switch' : 'complete');
    const report = { schema_version: 'chiptrace.native-protocol-ci.v1', ok: true,
      checked_at: new Date().toISOString(), real_upstream: false, unmodified_stock: false,
      production_acceptance_claimed: false, model_mode: 'local_deterministic_responses',
      model_switch: switchModel,
      producer_mode: 'patched_stock_debug_app_server', client_version: version,
      producer_source: source, patch_set: patchSet, producer_binary_sha256: await fileDigest(producer),
      native_turns: 2, session_epochs: 2, model_interactions: wire.length,
      tool_execution_records: inspection.session.tool_execution_records,
      tool_types: [...new Set(issuedTools.map(item => item.name))].sort(),
      image_evidence: { ...image, wire_and_canonical_verified: true, resume_verified: true },
      all_tool_results_in_raw_and_runtime: true, plan_turns_verified: true,
      tool_payloads_verified: true, tool_schemas_verified: true, process_outcomes_verified: true,
      all_model_items_in_canonical: true,
      terminal_output_evidence: { complete_arrays_verified: true, terminal_only_items: terminalOnlyItems },
      model_output_items: model.observations.reduce((count, item) => count + item.output_items.length, 0),
      reasoning_evidence: { canonical_verified: true, resume_verified: true },
      model_profiles: [...new Map(model.observations.map(item => [item.model,
        { model: item.model, parallel_tool_calls: item.parallel_tool_calls }])).values()],
      parallel_tool_evidence: { issued_in_one_response: true, native_overlap_ms: parallelOverlapMs },
      retry_evidence: { failed_http_status: retry.http_status, successful_http_status: recovery.http_status,
        same_native_turn: true, input_history_preserved: true, both_attempts_preserved: true },
      source_coverage: inspection.source_coverage, scenario_evidence: inspection.scenario_evidence,
      source_audit: audit, collector_raw: rawDigests, restart_verified: true,
      platform_evidence: platformEvidence };
    // The synthetic report must never satisfy the real-upstream production gate.
    assert.throws(() => verifyNativeCanaryReport(report, audit), /real_upstream/);
    const reportFile = process.env[switchModel ? 'CHIPTRACE_PROTOCOL_REPORT' : 'CHIPTRACE_BUYER_PROTOCOL_REPORT'];
    if (reportFile) {
      await fs.writeFile(reportFile, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    }
    t.diagnostic(JSON.stringify({ native_turns: 2, model_interactions: wire.length,
      tool_execution_records: report.tool_execution_records, restart_verified: true,
      real_upstream: false, production_acceptance_claimed: false }));
    fixture.passed();
}

for (const switchModel of [true, false]) {
  test(switchModel
    ? 'native collection preserves model switching and rejects mixed-model Buyer export'
    : 'native collection delivers a single-model multi-output Session through Buyer download and restart',
  { timeout: 240000 }, async t => {
    try {
      await collectProtocol(t, switchModel);
    } catch (error) {
      if (process.env.GITHUB_ACTIONS === 'true') {
        // Only the isolated synthetic experiment runs here. Keep actionable
        // errors in check annotations when anonymous job-log access is denied.
        const message = String(error.message).replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').slice(0, 4000)
          .replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
        console.log(`::error title=Native protocol collection::${message}`);
      }
      throw error;
    }
  });
}
