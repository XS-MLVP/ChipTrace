'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

const binary = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/debug/chiptrace');
const token = 'synthetic-hook-ack-credential-at-least-32-bytes';
const hookBinary = path.join(__dirname, 'chiptrace-codex-hook.sh');

async function commands() {
  const text = await fs.readFile(path.join(__dirname, 'requirements.toml.example'), 'utf8');
  return new Map([...text.matchAll(/^\[\[hooks\.([A-Za-z]+)\]\]([\s\S]*?)(?=^\[\[hooks\.[A-Za-z]+\]\]|$(?![\s\S]))/gm)]
    .map(match => [match[1], JSON.parse(match[2].match(/^command = (.*)$/m)[1])]));
}

function event(name) {
  return { hook_event_name: name, session_id: 'synthetic-hook-ack-session', turn_id: 'synthetic-turn',
    model: 'synthetic-model', permission_mode: 'default', source: 'startup', reason: 'other',
    trigger: 'manual', prompt: 'synthetic hook acknowledgement test', agent_id: 'synthetic-agent', agent_type: 'worker',
    event_id: `synthetic-hook-${name}`, occurred_at: '2026-10-15T00:00:00Z' };
}

async function invoke(command, endpoint, input, overrides = {}) {
  const child = spawn('/bin/sh', ['-c', command], {
    env: { ...process.env, CHIPTRACE_HOOK_BIN: hookBinary, CHIPTRACE_GATEWAY_URL: endpoint,
      CHIPTRACE_API_KEY: 'synthetic-provider-credential', CHIPTRACE_INGEST_TOKEN: token,
      OTEL_EXPORTER_OTLP_HEADERS: `Authorization=Bearer%20${token}`, ...overrides },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr = `${stderr}${chunk}`.slice(-4096); });
  child.stdin.on('error', () => {});
  const finished = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  child.stdin.end(JSON.stringify(input));
  return finished;
}

function receipt() {
  return { partialSuccess: { rejectedLogRecords: 0, rejectedSpans: 0, errorMessage: null }, chiptrace: {
    ok: true, durable: true, captures: 2, duplicates: 0, summary: { endpoint: 'codex_hook',
      source_records: 1, derived_captures: 1, unknown_events: 0, attributed_quality_errors: 0, conversion_errors: [] },
  } };
}

async function endpoint(t, respond) {
  const server = http.createServer((req, res) => {
    req.resume();
    req.once('end', () => respond(req, res));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

// These cases deliberately launch the native shell/curl/python Hook command
// for every retry.  On the shared NFS runner, process startup can be much
// slower than the local endpoint; keep the contract strict while allowing
// bounded runner variance.
test('SessionStart rejects HTTP success without a valid durable Hook receipt', { timeout: 120000 }, async t => {
  const hook = (await commands()).get('SessionStart');
  const cases = [
    ['ACK-only stand-in', () => ({}), 200],
    ['plain text response', () => 'not JSON', 200],
    ['oversized receipt', r => ' '.repeat(65536) + JSON.stringify(r), 200],
    ['OTLP endpoint', r => { r.chiptrace.summary.endpoint = 'otlp_logs'; return r; }, 200],
    ['not durable', r => { r.chiptrace.durable = false; return r; }, 200],
    ['unsuccessful ingest', r => { r.chiptrace.ok = false; return r; }, 200],
    ['Raw without lifecycle evidence', r => { r.chiptrace.captures = 1; r.chiptrace.summary.derived_captures = 0; return r; }, 200],
    ['unknown event', r => { r.chiptrace.summary.unknown_events = 1; return r; }, 200],
    ['conversion failure', r => { r.chiptrace.summary.conversion_errors = ['synthetic error']; return r; }, 200],
    ['invalid duplicate count', r => { r.chiptrace.duplicates = 3; return r; }, 200],
    ['boolean record count', r => { r.chiptrace.summary.source_records = true; return r; }, 200],
    ['partial rejection', r => { r.partialSuccess.rejectedLogRecords = 1; return r; }, 200],
    ['redirect carrying a receipt', r => r, 307],
    ['HTTP failure carrying a receipt', r => r, 503],
  ];
  for (const [label, transform, status] of cases) {
    await t.test(label, async scenario => {
      const response = transform(receipt());
      let requests = 0;
      const url = await endpoint(scenario, (_req, res) => {
        requests++;
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(typeof response === 'string' ? response : JSON.stringify(response));
      });
      const result = await invoke(hook, url, event('SessionStart'));
      assert.equal(result.code, 0, result.stderr);
      assert.equal(result.signal, null);
      assert.equal(JSON.parse(result.stdout).continue, false, label);
      assert.ok(requests >= 1 && requests <= 2, `${label}: unexpected retry count ${requests}`);
      if (status === 503) assert.equal(requests, 2);
    });
  }
});

test('SessionStart accepts a protected token file without provider or OTLP environment variables', { timeout: 30000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-hook-token-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const tokenFile = path.join(root, 'ingest-token');
  await fs.writeFile(tokenFile, `${token}\n`, { mode: 0o600 });
  const hook = (await commands()).get('SessionStart');
  const url = await endpoint(t, (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(receipt()));
  });
  const result = await invoke(hook, url, event('SessionStart'), {
    CHIPTRACE_API_KEY: '', CHIPTRACE_INGEST_TOKEN: '', OTEL_EXPORTER_OTLP_HEADERS: '',
    CHIPTRACE_INGEST_TOKEN_FILE: tokenFile,
  });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout, '', result.stderr);
});

test('all required lifecycle Hooks reject an empty ACK and accept conserved duplicate receipts', { timeout: 240000 }, async t => {
  let response = {};
  const url = await endpoint(t, (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(response));
  });
  const hooks = await commands();
  assert.equal(hooks.size, 9);
  for (const [name, command] of hooks) {
    response = {};
    const rejected = await invoke(command, url, event(name));
    if (name === 'SessionStart') {
      assert.equal(rejected.code, 0, rejected.stderr);
      assert.equal(JSON.parse(rejected.stdout).continue, false);
    } else assert.notEqual(rejected.code, 0, name);
    for (const duplicates of [0, 1, 2]) {
      response = receipt();
      response.chiptrace.duplicates = duplicates;
      const accepted = await invoke(command, url, event(name));
      assert.equal(accepted.code, 0, `${name}: ${accepted.stderr}`);
      assert.equal(accepted.stdout, '');
    }
  }
});

test('a truncated ACK retries the same event and validates only the completed response', { timeout: 10000 }, async t => {
  const bodies = [];
  const response = JSON.stringify(receipt());
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.once('end', () => {
      bodies.push(Buffer.concat(chunks).toString('utf8'));
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(response) });
      if (bodies.length === 1) res.write(response.slice(0, 32), () => res.destroy());
      else res.end(response);
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const hook = (await commands()).get('SessionStart');
  const result = await invoke(hook, `http://127.0.0.1:${server.address().port}`, event('SessionStart'));
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout, '', result.stderr);
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0], bodies[1], 'the retry must preserve the serialized native occurrence');
});

async function port() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const value = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return value;
}

function start(args) {
  const child = spawn(binary, args, { env: { ...process.env, CHIPTRACE_INGEST_TOKEN: token,
    TOKIO_WORKER_THREADS: '2', RAYON_NUM_THREADS: '2' }, stdio: ['ignore', 'ignore', 'pipe'] });
  const handle = { child, stderr: '', ended: false };
  child.stderr.on('data', chunk => { handle.stderr = `${handle.stderr}${chunk}`.slice(-4096); });
  handle.closed = new Promise(resolve => {
    child.once('error', error => { handle.ended = true; handle.stderr = error.message; resolve({ error }); });
    child.once('close', (code, signal) => { handle.ended = true; resolve({ code, signal }); });
  });
  return handle;
}

async function stop(process) {
  if (process.ended) return process.closed;
  process.child.kill('SIGINT');
  const kill = setTimeout(() => process.child.kill('SIGKILL'), 5000);
  try { return await process.closed; } finally { clearTimeout(kill); }
}

async function waitForHealth(url, process, predicate = () => true) {
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline && !process.ended) {
    try {
      const response = await fetch(`${url}/health`, { signal: AbortSignal.timeout(500) });
      if (response.ok) {
        const health = await response.json();
        if (predicate(health)) return health;
      }
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.fail(`isolated service did not reach the expected state: ${process.stderr}`);
}

test('native Hook commands accept real Relay WAL receipts through Collector delivery', { timeout: 120000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-hook-ack-'));
  let collector;
  let relay;
  t.after(async () => {
    if (relay) await stop(relay);
    if (collector) await stop(collector);
    await fs.rm(root, { recursive: true, force: true });
  });
  const collectorPort = await port();
  const collectorUrl = `http://127.0.0.1:${collectorPort}`;
  collector = start(['collector', '--host', '127.0.0.1', '--port', String(collectorPort),
    '--root', path.join(root, 'collector'), '--state-root', path.join(root, 'collector-state')]);
  await waitForHealth(collectorUrl, collector);
  const relayPort = await port();
  const relayUrl = `http://127.0.0.1:${relayPort}`;
  relay = start(['relay', '--host', '127.0.0.1', '--port', String(relayPort),
    '--root', path.join(root, 'relay'), '--state-root', path.join(root, 'relay-state'),
    '--delivery-state-root', path.join(root, 'delivery'), '--collector-url', collectorUrl]);
  await waitForHealth(relayUrl, relay);
  const hooks = await commands();
  for (const [name, command] of hooks) {
    const result = await invoke(command, relayUrl, event(name));
    assert.equal(result.code, 0, `${name}: ${result.stderr}`);
    assert.equal(result.stdout, '', name);
  }
  const duplicate = await invoke(hooks.get('SessionEnd'), relayUrl, event('SessionEnd'));
  assert.equal(duplicate.code, 0, duplicate.stderr);
  assert.equal(duplicate.stdout, '');
  const health = await waitForHealth(relayUrl, relay, h => h.delivered === 18 && h.pending === 0 && h.inflight === 0);
  assert.equal(health.conservation_ok, true);
  assert.equal(health.ingest_coverage.hooks.requests, 10);
  assert.equal(health.ingest_coverage.hooks.duplicates, 2);
  const stored = await waitForHealth(collectorUrl, collector, h => h.collector.captures === 18);
  assert.equal(stored.collector.rejected_attempts, 0);
  assert.equal(stored.collector.conflict_attempts, 0);
});
