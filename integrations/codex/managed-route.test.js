'use strict';

// Exercise the unmodified client with the actual system templates. No model
// request, credential, host Codex configuration, or production volume is used.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { createReadStream } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');

const run = promisify(execFile);
const stockRelease = require('./stock-release.json');
const stockVersion = stockRelease.version;
const stockBinary = '@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex';
const image = process.env.CHIPTRACE_CONFIG_TEST_IMAGE || 'node:22-bookworm-slim';
const gatewayUrl = 'http://172.28.11.121:18084/';
const userConfig = `model_provider = "Bypass"
[model_providers.OpenAI]
name = "User override"
base_url = "https://user-bypass.invalid/v1"
wire_api = "responses"
auth = { command = "printenv", args = ["USER_BYPASS_KEY"] }
supports_websockets = true
http_headers = { X-User-Override = "synthetic" }
[model_providers.Bypass]
name = "Alternate user provider"
base_url = "https://alternate-bypass.invalid/v1"
wire_api = "responses"
[otel]
exporter = "none"
trace_exporter = "none"
metrics_exporter = "none"
`;

async function readConfiguration(t, root, modules, requirements, flags = []) {
  const work = await fs.mkdtemp(path.join(root, 'scenario-'));
  const home = path.join(work, 'home');
  await fs.mkdir(home, { mode: 0o700 });
  await fs.writeFile(path.join(home, 'config.toml'), userConfig, { mode: 0o600 });
  const requirementsPath = path.join(work, 'requirements.toml');
  await fs.writeFile(requirementsPath, requirements, { mode: 0o600 });
  const container = `chiptrace-managed-route-${crypto.randomUUID()}`;
  const child = spawn('docker', ['run', '--rm', '-i', '--name', container,
    '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true', '--user', `${process.getuid()}:${process.getgid()}`,
    '--tmpfs', '/tmp:size=128m,mode=1777', '--workdir', '/work',
    '-e', 'HOME=/work', '-e', 'CODEX_HOME=/work/home',
    '-v', `${modules}:/stock/node_modules:ro`, '-v', `${work}:/work`,
    '-v', `${path.join(__dirname, 'config.toml.example')}:/etc/codex/config.toml:ro`,
    '-v', `${requirementsPath}:/etc/codex/requirements.toml:ro`,
    '--entrypoint', `/stock/node_modules/${stockBinary}`, image,
    '--strict-config', ...flags, 'app-server'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map();
  let nextId = 0;
  let stderr = '';
  let outputBytes = 0;
  let failure;
  const rejectAll = error => {
    failure ||= error;
    for (const { reject } of pending.values()) reject(error);
    pending.clear();
  };
  child.stdin.on('error', rejectAll);
  child.once('error', rejectAll);
  child.stderr.on('data', bytes => { stderr = `${stderr}${bytes}`.slice(-4096); });
  child.stdout.on('data', bytes => {
    outputBytes += bytes.length;
    if (outputBytes > 1024 * 1024) rejectAll(new Error('config RPC output exceeded 1 MiB'));
  });
  const lines = readline.createInterface({ input: child.stdout });
  lines.on('line', line => {
    if (failure) return;
    try {
      const value = JSON.parse(line);
      const request = pending.get(value.id);
      if (!request) return;
      pending.delete(value.id);
      if (value.error) request.reject(new Error(`config RPC failed: ${JSON.stringify(value.error)}`));
      else request.resolve(value.result);
    } catch (error) { rejectAll(error); }
  });
  const exited = new Promise(resolve => child.once('close', (code, signal) => {
    rejectAll(new Error(`Stock config process exited (${code}, ${signal}): ${stderr}`));
    resolve({ code, signal });
  }));
  const timeout = setTimeout(() => rejectAll(new Error(`Stock config RPC timed out: ${stderr}`)), 15000);
  t.after(async () => {
    clearTimeout(timeout);
    child.stdin.end();
    const kill = setTimeout(() => {
      run('docker', ['stop', '--time', '1', container]).catch(() => {});
    }, 2000);
    await exited;
    clearTimeout(kill);
    lines.close();
  });
  const request = (method, params) => new Promise((resolve, reject) => {
    if (failure) return reject(failure);
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
  });
  const initialized = await request('initialize', {
    clientInfo: { name: 'chiptrace-managed-route-test', version: '1.0.0' },
    capabilities: { experimentalApi: true },
  });
  assert.ok(initialized.userAgent.includes(stockVersion), 'the config regression must use the pinned Stock client');
  child.stdin.write(`${JSON.stringify({ method: 'initialized' })}\n`);
  const effective = await request('config/read', { includeLayers: false });
  const required = await request('configRequirements/read', null);
  return { effective: effective.config, required: required.requirements };
}

test('Stock Codex cannot bypass the managed Wire route through local configuration', { timeout: 90000 }, async t => {
  const configuredModules = process.env.CHIPTRACE_STOCK_CODEX_MODULES;
  assert.ok(configuredModules, 'set CHIPTRACE_STOCK_CODEX_MODULES to the pinned npm node_modules directory');
  const modules = await fs.realpath(configuredModules);
  const metadata = JSON.parse(await fs.readFile(path.join(modules, '@openai/codex/package.json'), 'utf8'));
  assert.equal(metadata.version, stockVersion);
  const digest = crypto.createHash('sha256');
  for await (const bytes of createReadStream(path.join(modules, stockBinary))) digest.update(bytes);
  assert.equal(digest.digest('hex'), stockRelease.linux_x64_binary_sha256,
    'managed routing must use the same official ELF as source-context qualification');
  const requirements = await fs.readFile(path.join(__dirname, 'requirements.toml.example'), 'utf8');
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-managed-route-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));

  // A negative control proves the client reads the conflicting user settings.
  // System config.toml alone is a default, not a route requirement.
  await t.test('the former Hook-only requirements allow Wire to bypass the gateway', async scenario => {
    const oldRequirements = requirements.slice(requirements.indexOf('[features]'));
    const { effective, required } = await readConfiguration(scenario, root, modules, oldRequirements);
    assert.equal(effective.model_provider, 'Bypass');
    assert.equal(effective.model_providers.OpenAI.base_url, 'https://user-bypass.invalid/v1');
    assert.equal(required.modelProvider, null);
  });

  for (const [label, flags] of [
    ['conflicting user selection and same-name provider definition', []],
    ['session flags changing provider selection and endpoint', [
      '-c', 'model_provider="Bypass"',
      '-c', 'model_providers.OpenAI.base_url="https://flag-bypass.invalid/v1"',
    ]],
  ]) {
    await t.test(label, async scenario => {
      const { effective, required } = await readConfiguration(scenario, root, modules, requirements, flags);
      assert.equal(required.modelProvider, 'OpenAI');
      assert.equal(effective.model_provider, 'OpenAI');
      for (const provider of [effective.model_providers.OpenAI, required.modelProviders.OpenAI]) {
        assert.equal(provider.base_url, gatewayUrl);
        assert.equal(provider.wire_api, 'responses');
        assert.equal(provider.requires_openai_auth, false);
        assert.equal(provider.supports_websockets, false);
        assert.equal(provider.request_max_retries, 25);
        assert.equal(provider.stream_max_retries, 25);
        assert.equal(provider.env_key ?? null, null);
        assert.equal(provider.http_headers?.['X-User-Override'], undefined);
        assert.equal(provider.auth.command, 'printenv');
        assert.deepEqual(provider.auth.args, ['CHIPTRACE_API_KEY']);
      }
    });
  }
});
