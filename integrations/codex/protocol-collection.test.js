'use strict';

// Execute a real, pinned, patched debug App Server against a local deterministic
// Responses endpoint. These newly collected bytes are protocol regression
// evidence, never real-model or unmodified-producer production acceptance.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { createReadStream } = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { DurableCaptureOutbox, codexTraceContextFromHeaders } = require('../openai-gateway/durable-outbox');
const { prepareProducerSourceCache } = require('../../scripts/ci/producer-source-cache');
const { verifyNativeCanaryReport } = require('../../scripts/ci/native-canary-gate');

const run = promisify(execFile);
const version = '0.163.0-alpha.11';
const upstream = '5425d3e625daa58eea3ad1de27c087eb3b2ffbd3';
const patches = ['upstream-sse-context.patch', 'upstream-sse-context-test.patch',
  'upstream-session-scope.patch', 'upstream-session-scope-extension.patch',
  'upstream-session-scope-process.patch', 'upstream-config-read-scope.patch'];
const chiptrace = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/debug/chiptrace');
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function fileDigest(file) {
  const hash = crypto.createHash('sha256');
  for await (const bytes of createReadStream(file)) hash.update(bytes);
  return hash.digest('hex');
}

async function verifyPatchSet(sourceRoot, root) {
  // Reverse only copies of the changed files, then compare them with the
  // pinned Git originals. Filenames or version strings alone cannot prove the
  // experiment has all the patches used in CI. Never mutate the source here.
  const copy = path.join(root, 'patch-validation');
  const touched = new Set();
  const reports = [];
  for (const name of patches) {
    const file = path.resolve(__dirname, '../../docs', name);
    const bytes = await fs.readFile(file);
    reports.push({ file: name, sha256: sha256(bytes) });
    for (const match of bytes.toString('utf8').matchAll(/^\+\+\+ b\/(.+)$/gm)) touched.add(match[1]);
  }
  for (const relative of touched) {
    const destination = path.join(copy, relative);
    assert.ok(destination.startsWith(copy + path.sep));
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.copyFile(path.join(sourceRoot, relative), destination);
  }
  for (const name of [...patches].reverse()) {
    await run('git', ['apply', '--reverse', path.resolve(__dirname, '../../docs', name)],
      { cwd: copy, maxBuffer: 1024 * 1024 });
  }
  for (const relative of touched) {
    const original = (await run('git', ['-C', sourceRoot, 'show', `HEAD:${relative}`],
      { encoding: 'buffer', maxBuffer: 8 * 1024 * 1024 })).stdout;
    assert.equal(await fileDigest(path.join(copy, relative)), sha256(original),
      `producer source differs beyond declared patches: ${relative}`);
  }
  const changed = (await run('git', ['-C', sourceRoot, 'diff', '--name-only', 'HEAD'])).stdout.trim().split('\n').filter(Boolean);
  for (const file of changed) assert.ok(touched.has(file) || file === 'codex-rs/Cargo.lock', `undeclared producer change: ${file}`);
  await fs.rm(copy, { recursive: true, force: true });
  return reports;
}

async function port() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const value = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return value;
}

function start(executable, args, cwd, env) {
  // Deliberately exclude the invoking user's credentials, proxy, config and
  // telemetry environment. All endpoint/auth configuration below is synthetic.
  const child = spawn(executable, args, { cwd, env: { PATH: process.env.PATH,
    HOME: cwd, TMPDIR: cwd, LANG: 'C.UTF-8', TOKIO_WORKER_THREADS: '2',
    RAYON_NUM_THREADS: '2', ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  const handle = { child, stderr: '', ended: false };
  child.stderr.on('data', bytes => { handle.stderr = `${handle.stderr}${bytes}`.slice(-8192); });
  child.stdin.on('error', () => {});
  handle.closed = new Promise(resolve => {
    child.once('error', error => { handle.ended = true; handle.stderr = error.message; resolve({ error: error.message }); });
    child.once('close', (code, signal) => { handle.ended = true; resolve({ code, signal }); });
  });
  return handle;
}

async function stop(handle, graceful = false) {
  if (!handle.ended) {
    if (graceful) handle.child.stdin.end();
    else handle.child.kill('SIGINT');
  }
  const kill = setTimeout(() => handle.child.kill('SIGKILL'), 10000);
  try { return await handle.closed; } finally { clearTimeout(kill); }
}

async function health(url, handle, predicate = () => true) {
  const deadline = Date.now() + 15000;
  while (!handle.ended && Date.now() < deadline) {
    try {
      const response = await fetch(`${url}/health`, { signal: AbortSignal.timeout(500) });
      if (response.ok) {
        const value = await response.json();
        if (predicate(value)) return value;
      }
    } catch {}
    await delay(25);
  }
  assert.fail(`isolated service did not reach its expected state: ${handle.stderr}`);
}

function rpc(handle, externalFailure) {
  let nextId = 0;
  let failure;
  let bytes = 0;
  const pending = new Map();
  const notifications = [];
  const reject = error => {
    failure ||= error;
    for (const request of pending.values()) request.reject(error);
    pending.clear();
  };
  const lines = readline.createInterface({ input: handle.child.stdout });
  lines.on('line', line => {
    bytes += Buffer.byteLength(line);
    if (bytes > 16 * 1024 * 1024) return reject(new Error('App Server RPC exceeded 16 MiB'));
    try {
      const message = JSON.parse(line);
      if (message.method && message.id !== undefined) {
        return reject(new Error(`unexpected server request: ${message.method}`));
      }
      if (message.method) notifications.push(message);
      const request = pending.get(message.id);
      if (!request) return;
      pending.delete(message.id);
      if (message.error) request.reject(new Error(`RPC error: ${JSON.stringify(message.error)}`));
      else request.resolve(message.result);
    } catch (error) { reject(error); }
  });
  handle.closed.then(result => reject(new Error(`App Server exited: ${JSON.stringify(result)} ${handle.stderr}`)));
  return {
    request(method, params) {
      return new Promise((resolve, rejectRequest) => {
        if (failure) return rejectRequest(failure);
        const id = ++nextId;
        const timer = setTimeout(() => {
          pending.delete(id);
          rejectRequest(new Error(`RPC timeout: ${method}; ${handle.stderr}`));
        }, 30000);
        pending.set(id, { resolve: value => { clearTimeout(timer); resolve(value); },
          reject: error => { clearTimeout(timer); rejectRequest(error); } });
        handle.child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
      });
    },
    notify(method) { handle.child.stdin.write(`${JSON.stringify({ method })}\n`); },
    async completed(threadId, turnId) {
      const deadline = Date.now() + 30000;
      while (Date.now() < deadline) {
        if (failure) throw failure;
        const cause = externalFailure();
        if (cause) throw cause;
        const completed = notifications.find(message => message.method === 'turn/completed'
          && message.params.threadId === threadId && message.params.turn.id === turnId);
        if (completed) {
          assert.equal(completed.params.turn.status, 'completed', JSON.stringify(completed.params.turn.error));
          return completed.params.turn;
        }
        await delay(25);
      }
      assert.fail(`turn/completed timed out: ${handle.stderr}`);
    },
  };
}

function sse(id, item) {
  return [{ type: 'response.created', response: { id } },
    { type: 'response.output_item.done', item },
    { type: 'response.completed', response: { id,
      usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 } } }]
    .map(value => `event: ${value.type}\ndata: ${JSON.stringify(value)}\n\n`).join('');
}

function deterministicModel() {
  let phase = 'read';
  let polls = 0;
  let processId;
  const observations = [];
  const tool = (callId, name, args) => ({ type: 'function_call', call_id: callId,
    name, arguments: JSON.stringify(args) });
  const output = (body, callId) => {
    const value = body.input.find(item => item.type === 'function_call_output' && item.call_id === callId)?.output;
    assert.equal(typeof value, 'string', `missing actual tool output for ${callId}`);
    return value;
  };
  return {
    observations,
    get finished() { return phase === 'done'; },
    respond(body) {
      assert.equal(body.model, 'gpt-5.6-sol');
      assert.equal(body.stream, true);
      let item;
      const exec = (callId, cmd, yieldTime = 250) => tool(callId, 'exec_command',
        { cmd, shell: '/bin/sh', login: false, yield_time_ms: yieldTime, max_output_tokens: 2000 });
      if (phase === 'read') {
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
        item = exec('protocol-resumed', 'printf RESUMED_TURN_OK; printf CHIPTRACE_EXPECTED_EXIT_9 >&2; exit 9');
        phase = 'final';
      } else if (phase === 'final') {
        const actual = output(body, 'protocol-resumed');
        assert.match(actual, /Process exited with code 9/);
        assert.match(actual, /RESUMED_TURN_OK/);
        item = { type: 'message', role: 'assistant', id: 'protocol-second-final',
          content: [{ type: 'output_text', text: 'SECOND_TURN_COMPLETE' }] };
        phase = 'done';
      } else assert.fail('unexpected model request after terminal response');
      observations.push({ call_id: item.call_id || null, name: item.name || 'assistant',
        input_sha256: sha256(JSON.stringify(body.input)), input_items: body.input.length });
      return sse(`protocol-response-${observations.length}`, item);
    },
  };
}

async function collectProtocol(t) {
    assert.ok(process.env.CHIPTRACE_PROTOCOL_PRODUCER, 'set CHIPTRACE_PROTOCOL_PRODUCER to the pinned patched debug App Server');
    assert.ok(process.env.CHIPTRACE_PROTOCOL_SOURCE, 'set CHIPTRACE_PROTOCOL_SOURCE to its pinned patched checkout');
    const producer = await fs.realpath(process.env.CHIPTRACE_PROTOCOL_PRODUCER);
    const sourceRoot = await fs.realpath(process.env.CHIPTRACE_PROTOCOL_SOURCE);
    const source = prepareProducerSourceCache(sourceRoot);
    assert.equal(source.upstream_commit, upstream);
    if (process.env.CHIPTRACE_PROTOCOL_EXPECTED_SOURCE_DIGEST) {
      assert.equal(source.source_sha256, process.env.CHIPTRACE_PROTOCOL_EXPECTED_SOURCE_DIGEST,
        'producer source must still match the cache/build identity');
    }
    const producerVersion = (await run(producer, ['--version'])).stdout.trim();
    assert.ok(producerVersion.endsWith(version), `unexpected producer version: ${producerVersion}`);
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-protocol-'));
    const token = crypto.randomBytes(32).toString('hex');
    const processes = [];
    let server;
    let outbox;
    let failure;
    let passed = false;
    t.after(async () => {
      for (const process of [...processes].reverse()) await stop(process);
      if (server) await new Promise(resolve => server.close(resolve));
      if (outbox) await outbox.close();
      if (passed && process.env.CHIPTRACE_PROTOCOL_KEEP !== '1') await fs.rm(root, { recursive: true, force: true });
      else t.diagnostic(`isolated protocol evidence retained: ${root}`);
    });
    const launch = (executable, args, env = {}) => {
      const process = start(executable, args, root, env);
      processes.push(process);
      return process;
    };
    const patchSet = await verifyPatchSet(sourceRoot, root);
    const capture = path.join(root, 'collector');
    const collectorUrl = `http://127.0.0.1:${await port()}`;
    const relayUrl = `http://127.0.0.1:${await port()}`;
    const collectorArgs = ['collector', '--host', '127.0.0.1', '--port', new URL(collectorUrl).port,
      '--root', capture, '--state-root', path.join(root, 'collector-state')];
    const relayArgs = ['relay', '--host', '127.0.0.1', '--port', new URL(relayUrl).port,
      '--root', path.join(root, 'relay'), '--state-root', path.join(root, 'relay-state'),
      '--delivery-state-root', path.join(root, 'delivery'), '--collector-url', collectorUrl];
    let collector = launch(chiptrace, collectorArgs, { CHIPTRACE_INGEST_TOKEN: token });
    await health(collectorUrl, collector);
    let relay = launch(chiptrace, relayArgs, { CHIPTRACE_INGEST_TOKEN: token });
    await health(relayUrl, relay);
    outbox = new DurableCaptureOutbox({ root: path.join(root, 'outbox'), relayUrl,
      bearerToken: token, minFreeBytes: 0, minFreeFiles: 0, sanitize: false });
    await outbox.start();
    const model = deterministicModel();
    const wire = [];
    const catalog = JSON.parse(await fs.readFile(path.join(__dirname, 'managed-models.json'), 'utf8'));
    server = http.createServer((req, res) => {
      (async () => {
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
        const response = Buffer.from(model.respond(JSON.parse(request)));
        const transaction = await outbox.beginCapture({ captureId: `cap-protocol-${crypto.randomUUID()}`,
          version: 'chiptrace.capture.v2', recordType: 'api_snapshot', sourceNamespace: 'synthetic-protocol-ci',
          method: req.method, proxiedPath: req.url, startedAt: new Date().toISOString(),
          traceContext: context.trace, fieldEvidence: context.evidence,
          fieldEvidenceConflicts: context.conflicts, traceContextErrors: context.errors });
        await transaction.appendRequest(request);
        // Split in the middle of UTF-8 and SSE tokens as well as normal lines.
        res.writeHead(200, { 'content-type': 'text/event-stream' });
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
        await transaction.finalize({ responseStatus: 200, stream: true,
          finishedAt: new Date().toISOString(), upstreamResponseCompleted: true,
          clientRequestAborted: req.aborted, clientResponseClosedBeforeFinish: res.destroyed && !res.writableFinished,
          clientResponseFinished: res.writableFinished, responseBytesForwarded: response.length });
        wire.push({ session_id: context.trace.session_id, turn_id: context.trace.turn_id,
          request_sha256: sha256(request), response_sha256: sha256(response) });
      })().catch(error => {
        failure ||= error;
        res.destroy(error);
      });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const home = path.join(root, 'home');
    const managed = path.join(root, 'managed');
    await fs.mkdir(home, { mode: 0o700 });
    await fs.mkdir(managed, { mode: 0o700 });
    await fs.writeFile(path.join(root, 'README.md'), 'CHIPTRACE_READ_OK 中文 🧪\n' + 'bounded fixture line\n'.repeat(15));
    const substitute = value => value.replaceAll('http://172.28.11.121:18084', endpoint)
      .replaceAll('CHIPTRACE_API_KEY', 'CHIPTRACE_PROTOCOL_API_KEY');
    const config = substitute(await fs.readFile(path.join(__dirname, 'config.toml.example'), 'utf8'))
      .replaceAll(`${endpoint}/otel/`, `${relayUrl}/otel/`);
    const requirements = substitute(await fs.readFile(path.join(__dirname, 'requirements.toml.example'), 'utf8'))
      .replaceAll(`${endpoint}/hooks/codex`, `${relayUrl}/hooks/codex`);
    await fs.writeFile(path.join(home, 'config.toml'), config, { mode: 0o600 });
    await fs.writeFile(path.join(managed, 'requirements.toml'), requirements, { mode: 0o600 });
    const producerEnv = { CODEX_HOME: home, CHIPTRACE_PROTOCOL_API_KEY: 'synthetic-protocol-provider',
      CHIPTRACE_INGEST_TOKEN: token, OTEL_EXPORTER_OTLP_HEADERS: `Authorization=Bearer%20${token}`,
      CODEX_APP_SERVER_MANAGED_CONFIG_PATH: path.join(managed, 'managed_config.toml') };
    const connect = async () => {
      const handle = launch(producer, ['--strict-config', '--disable-plugin-startup-tasks-for-tests'], producerEnv);
      const client = rpc(handle, () => failure);
      const initialized = await client.request('initialize', {
        clientInfo: { name: 'chiptrace-protocol-ci', version: '1.0.0' }, capabilities: { experimentalApi: true } });
      assert.ok(initialized.userAgent.includes(version));
      client.notify('initialized');
      const effective = await client.request('config/read', { includeLayers: false });
      assert.equal(effective.config.model_providers.OpenAI.base_url, `${endpoint}/`);
      assert.equal(effective.config.otel.exporter['otlp-http'].endpoint, `${relayUrl}/otel/v1/logs`);
      const required = await client.request('configRequirements/read', null);
      assert.equal(required.requirements.modelProvider, 'OpenAI');
      return { handle, client };
    };
    const first = await connect();
    const started = await first.client.request('thread/start', {
      model: 'gpt-5.6-sol', cwd: root, approvalPolicy: 'never', sandbox: 'read-only', ephemeral: false });
    const session = started.thread.id;
    const begin = async (client, prompt) => {
      const result = await client.request('turn/start', { threadId: session,
        input: [{ type: 'text', text: prompt, text_elements: [] }] });
      await client.completed(session, result.turn.id);
      if (failure) throw failure;
      return result.turn.id;
    };
    const turns = [await begin(first.client, 'FIRST_TURN_REQUEST')];
    assert.deepEqual(await stop(first.handle, true), { code: 0, signal: null }, first.handle.stderr);
    const second = await connect();
    const resumed = await second.client.request('thread/resume', { threadId: session,
      cwd: root, approvalPolicy: 'never', sandbox: 'read-only' });
    assert.equal(resumed.thread.id, session);
    turns.push(await begin(second.client, 'SECOND_TURN_REQUEST'));
    assert.notEqual(turns[0], turns[1]);
    assert.deepEqual(await stop(second.handle, true), { code: 0, signal: null }, second.handle.stderr);
    assert.equal(model.finished, true);
    if (failure) throw failure;
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
    const inspect = async () => JSON.parse((await run(chiptrace,
      ['inspect-session', '--input', capture, '--session-id', session], { maxBuffer: 32 * 1024 * 1024 })).stdout);
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
    for (const name of sealed.filter(name => name.endsWith('.sealed.ndjson'))) {
      const file = path.join(capture, 'segments', name);
      rawDigests.push({ file: name, sha256: await fileDigest(file), bytes: (await fs.stat(file)).size });
      for await (const line of readline.createInterface({ input: createReadStream(file) })) {
        const record = JSON.parse(line);
        if (record.recordType === 'api_snapshot') savedWire.push(record);
      }
    }
    assert.equal(savedWire.length, wire.length);
    for (const expected of wire) {
      const saved = savedWire.find(record => record.requestBodySha256 === expected.request_sha256);
      assert.ok(saved, 'actual request bytes must reach Collector WAL');
      assert.equal(typeof saved.requestBody.raw, 'string');
      assert.equal(typeof saved.responseBody.value, 'string');
      assert.equal(sha256(saved.requestBody.raw), expected.request_sha256);
      assert.equal(sha256(saved.responseBody.value), expected.response_sha256);
      assert.equal(saved.requestBytesCaptured, Buffer.byteLength(saved.requestBody.raw));
      assert.equal(saved.responseBytesCaptured, Buffer.byteLength(saved.responseBody.value));
    }
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
    const report = { schema_version: 'chiptrace.native-protocol-ci.v1', ok: true,
      checked_at: new Date().toISOString(), real_upstream: false, unmodified_stock: false,
      production_acceptance_claimed: false, model_mode: 'local_deterministic_responses',
      producer_mode: 'patched_stock_debug_app_server', client_version: version,
      producer_source: source, patch_set: patchSet, producer_binary_sha256: await fileDigest(producer),
      native_turns: 2, session_epochs: 2, model_interactions: wire.length,
      tool_execution_records: inspection.session.tool_execution_records,
      source_coverage: inspection.source_coverage, scenario_evidence: inspection.scenario_evidence,
      source_audit: audit, collector_raw: rawDigests, restart_verified: true };
    // The synthetic report must never satisfy the real-upstream production gate.
    assert.throws(() => verifyNativeCanaryReport(report, audit), /real_upstream/);
    if (process.env.CHIPTRACE_PROTOCOL_REPORT) {
      await fs.writeFile(process.env.CHIPTRACE_PROTOCOL_REPORT, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    }
    t.diagnostic(JSON.stringify({ native_turns: 2, model_interactions: wire.length,
      tool_execution_records: report.tool_execution_records, restart_verified: true,
      real_upstream: false, production_acceptance_claimed: false }));
    passed = true;
}

test('newly executed producer preserves two Turns, resume, failed exits and real async polling in four sources',
  { timeout: 180000 }, async t => {
    try {
      await collectProtocol(t);
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
