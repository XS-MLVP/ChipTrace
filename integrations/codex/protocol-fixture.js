'use strict';

// Shared isolation and producer-identity checks for newly executed protocol CI.
// Never inherit the operator's credentials or edit the pinned producer checkout.
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
const { DurableCaptureOutbox } = require('../openai-gateway/durable-outbox');
const { prepareProducerSourceCache } = require('../../scripts/ci/producer-source-cache');
const stockRelease = require('./stock-release.json');
const producerPolicy = require('./producer-support.json').producer;
const { describePlatformProcessFailure } = require('./protocol-process-error');

const run = promisify(execFile);
const producerMode = process.env.CHIPTRACE_PROTOCOL_MODE || 'patched_stock_debug_app_server';
assert.ok(['patched_stock_debug_app_server', 'patched_stock_cli', 'unmodified_stock'].includes(producerMode), 'unsupported protocol producer mode');
const unmodifiedStock = producerMode === 'unmodified_stock';
const cliProducer = producerMode !== 'patched_stock_debug_app_server';
// Compare the official release and its context repair on the same upstream
// source. Patch provenance still distinguishes the repaired producer.
const version = stockRelease.version;
const upstream = stockRelease.upstream_commit;
const expectedBuildRevision = process.env.CHIPTRACE_EXPECTED_BUILD_REVISION;
if (expectedBuildRevision !== undefined) {
  assert.match(expectedBuildRevision, /^[a-f0-9]{40}$/, 'expected ChipTrace build revision must be a full Git SHA');
}
const patches = unmodifiedStock ? [] : producerPolicy.patches.map(patch => patch.file);
const patchDigests = new Map(producerPolicy.patches.map(patch => [patch.file, patch.sha256]));
const chiptrace = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/debug/chiptrace');
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function fileDigest(file) {
  const hash = crypto.createHash('sha256');
  for await (const bytes of createReadStream(file)) hash.update(bytes);
  return hash.digest('hex');
}

async function verifyPatchSet(sourceRoot, root) {
  const copy = path.join(root, 'patch-validation');
  const touched = new Set();
  const reports = [];
  for (const name of patches) {
    const file = path.resolve(__dirname, '../../docs', name);
    const bytes = await fs.readFile(file);
    const digest = sha256(bytes);
    assert.equal(digest, patchDigests.get(name), `producer patch digest changed: ${name}`);
    reports.push({ file: name, sha256: digest });
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
  const notification = async (method, matches) => {
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      if (failure) throw failure;
      const cause = externalFailure();
      if (cause) throw cause;
      const found = notifications.find(message => message.method === method && matches(message.params));
      if (found) return found.params;
      await delay(25);
    }
    assert.fail(`${method} timed out: ${handle.stderr}`);
  };
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
    notification,
    async completed(threadId, turnId, expectedStatus = 'completed') {
      const completed = await notification('turn/completed',
        params => params.threadId === threadId && params.turn.id === turnId);
      assert.equal(completed.turn.status, expectedStatus, JSON.stringify(completed.turn.error));
      return completed.turn;
    },
  };
}

async function protocolFixture(t, prefix) {
  assert.ok(process.env.CHIPTRACE_PROTOCOL_PRODUCER, 'set CHIPTRACE_PROTOCOL_PRODUCER to the selected pinned producer');
  assert.ok(process.env.CHIPTRACE_PROTOCOL_SOURCE, 'set CHIPTRACE_PROTOCOL_SOURCE to its pinned checkout');
  const producer = await fs.realpath(process.env.CHIPTRACE_PROTOCOL_PRODUCER);
  const sourceRoot = await fs.realpath(process.env.CHIPTRACE_PROTOCOL_SOURCE);
  const source = prepareProducerSourceCache(sourceRoot);
  assert.equal(source.upstream_commit, upstream);
  if (unmodifiedStock) {
    assert.equal(process.platform, 'linux');
    assert.equal(process.arch, 'x64');
    assert.equal((await run('git', ['-C', sourceRoot, 'status', '--porcelain'])).stdout, '', 'stock source must be clean');
    assert.equal(source.source_sha256, stockRelease.source_sha256, 'stock source must match the complete pinned tree');
    assert.equal(await fileDigest(producer), stockRelease.linux_x64_binary_sha256, 'stock binary must be the pinned official ELF');
  }
  if (process.env.CHIPTRACE_PROTOCOL_EXPECTED_SOURCE_DIGEST) {
    assert.equal(source.source_sha256, process.env.CHIPTRACE_PROTOCOL_EXPECTED_SOURCE_DIGEST,
      'producer source must still match the cache/build identity');
  }
  const producerVersion = (await run(producer, ['--version'])).stdout.trim();
  assert.ok(producerVersion.endsWith(version), `unexpected producer version: ${producerVersion}`);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  const token = crypto.randomBytes(32).toString('hex');
  const processes = [];
  let server;
  let outbox;
  let failure;
  let passed = false;
  t.after(async () => {
    for (const process of [...processes].reverse()) await stop(process);
    if (server) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
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
  const collector = launch(chiptrace, collectorArgs, { CHIPTRACE_INGEST_TOKEN: token });
  const collectorHealth = await health(collectorUrl, collector);
  if (expectedBuildRevision !== undefined) {
    assert.equal(collectorHealth.build?.revision, expectedBuildRevision,
      'native collector must run the ChipTrace revision under test');
  }
  const relay = launch(chiptrace, relayArgs, { CHIPTRACE_INGEST_TOKEN: token });
  const relayHealth = await health(relayUrl, relay);
  if (expectedBuildRevision !== undefined) {
    assert.equal(relayHealth.build?.revision, expectedBuildRevision,
      'native relay must run the ChipTrace revision under test');
  }
  outbox = new DurableCaptureOutbox({ root: path.join(root, 'outbox'), relayUrl,
    bearerToken: token, minFreeBytes: 0, minFreeFiles: 0, sanitize: false });
  await outbox.start();
  return { root, token, source, producer, producerMode, unmodifiedStock, patchSet, capture, collectorUrl, relayUrl,
    collectorArgs, relayArgs, collector, relay, outbox, launch,
    assertHealthy() { if (failure) throw failure; },
    passed() { passed = true; },
    async verifyPlatform(mode = 'partial') {
      const started = performance.now();
      const timeoutMs = 120000;
      let result;
      try {
        result = await run(process.execPath, [path.join(__dirname, 'protocol-platform.js'), root, path.resolve(chiptrace), mode],
          { env: { PATH: process.env.PATH, HOME: root, TMPDIR: root, LANG: 'C.UTF-8',
            ...(process.env.CHIPTRACE_PROTOCOL_MINIO_BINARY
              ? { CHIPTRACE_PROTOCOL_MINIO_BINARY: path.resolve(process.env.CHIPTRACE_PROTOCOL_MINIO_BINARY) } : {}),
            TOKIO_WORKER_THREADS: '2', RAYON_NUM_THREADS: '2' }, timeout: timeoutMs, maxBuffer: 1024 * 1024 });
      } catch (error) {
        const details = describePlatformProcessFailure(error,
          { mode, elapsedMs: performance.now() - started, timeoutMs });
        await fs.writeFile(path.join(root, `platform-child-${mode}-failure.json`),
          JSON.stringify(details, null, 2) + '\n', { mode: 0o600 });
        throw new Error(`Native platform child failed: ${JSON.stringify(details)}`);
      }
      t.diagnostic(JSON.stringify({ phase: 'native_platform_child', mode,
        elapsed_ms: Math.round(performance.now() - started), timeout_ms: timeoutMs }));
      return JSON.parse(result.stdout);
    },
    async serve(handler) {
      assert.equal(server, undefined, 'only one synthetic endpoint per fixture');
      server = http.createServer((req, res) => {
        Promise.resolve().then(() => handler(req, res)).catch(error => {
          failure ||= error;
          res.destroy(error);
        });
      });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      return `http://127.0.0.1:${server.address().port}`;
    },
    async configure(endpoint, catalog, plan = false) {
      const home = path.join(root, 'home');
      const managed = path.join(root, 'managed');
      await fs.mkdir(home, { mode: 0o700 });
      await fs.mkdir(managed, { mode: 0o700 });
      const sandboxTmp = path.join(root, 'sandbox-tmp');
      if (cliProducer) await fs.mkdir(sandboxTmp, { mode: 0o700 });
      const substitute = value => value.replaceAll('http://172.28.11.121:18084', endpoint)
        .replaceAll('CHIPTRACE_API_KEY', 'CHIPTRACE_PROTOCOL_API_KEY');
      const config = substitute(await fs.readFile(path.join(__dirname, 'config.toml.example'), 'utf8'))
        .replaceAll(`${endpoint}/otel/`, `${relayUrl}/otel/`);
      const requirements = substitute(await fs.readFile(path.join(__dirname, 'requirements.toml.example'), 'utf8'))
        .replaceAll(`${endpoint}/hooks/codex`, `${relayUrl}/hooks/codex`);
      const catalogPath = path.join(home, 'models.json');
      await fs.writeFile(catalogPath, JSON.stringify(catalog), { mode: 0o600 });
      await fs.writeFile(path.join(home, 'config.toml'), `model_catalog_json = ${JSON.stringify(catalogPath)}\n`
        + config + (plan ? '\n[tools.update_plan]\nenabled = true\n' : ''), { mode: 0o600 });
      await fs.writeFile(path.join(managed, 'requirements.toml'), requirements, { mode: 0o600 });
      const producerEnv = { CODEX_HOME: home, CHIPTRACE_PROTOCOL_API_KEY: 'synthetic-protocol-provider',
        CHIPTRACE_INGEST_TOKEN: token, OTEL_EXPORTER_OTLP_HEADERS: `Authorization=Bearer%20${token}`,
        CODEX_APP_SERVER_MANAGED_CONFIG_PATH: path.join(managed, 'managed_config.toml') };
      return async () => {
        // The release CLI has no debug managed-config/startup-task switches.
        // Build a private /etc even when the host has no /etc/codex. Only known
        // public OS files and this fixture's config are visible in that mount.
        const publicEtc = ['passwd', 'group', 'hosts', 'resolv.conf', 'nsswitch.conf', 'os-release', 'ssl/certs'];
        const args = cliProducer ? [
          '--unshare-user', '--unshare-pid', '--die-with-parent',
          '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
          // The released sandbox prepares /tmp/codex-daemon-<uid> even for
          // read-only tools. Do not depend on or expose a host's existing socket
          // directory. This writable /tmp maps only to the private fixture.
          '--bind', sandboxTmp, '/tmp', '--bind', root, root,
          '--ro-bind', producer, producer, '--tmpfs', '/etc',
          ...publicEtc.flatMap(name => ['--ro-bind-try', `/etc/${name}`, `/etc/${name}`]),
          '--ro-bind', path.join(home, 'config.toml'), '/etc/codex/config.toml',
          '--ro-bind', path.join(managed, 'requirements.toml'), '/etc/codex/requirements.toml',
          '--remount-ro', '/etc', '--chdir', root, '--', producer, '--strict-config', 'app-server',
        ] : ['--strict-config', '--disable-plugin-startup-tasks-for-tests'];
        const handle = launch(cliProducer ? 'bwrap' : producer, args, producerEnv);
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
    },
  };
}

module.exports = { run, version, chiptrace, sha256, delay, fileDigest, stop, health, protocolFixture };
