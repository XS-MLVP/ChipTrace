'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const http = require('node:http');
const { spawn } = require('node:child_process');

const integrationRoot = __dirname;
const configPath = path.join(integrationRoot, 'config.toml.example');
const requirementsPath = path.join(integrationRoot, 'requirements.toml.example');
const readmePath = path.join(integrationRoot, 'README.md');
const config = fs.readFileSync(configPath, 'utf8');
const requirements = fs.readFileSync(requirementsPath, 'utf8');
const readme = fs.readFileSync(readmePath, 'utf8');

test('Stock Codex uses the current system configuration contract', () => {
  assert.equal(
    fs.existsSync(path.join(integrationRoot, 'managed_config.toml.example')),
    false,
  );
  assert.match(config, /^# Install as \/etc\/codex\/config\.toml\.$/m);
  assert.match(config, /^model_provider = "OpenAI"$/m);
  assert.match(config, /^\[model_providers\.OpenAI\]$/m);
  assert.doesNotMatch(config, /^model_provider = "ChipTrace"$/m);
  assert.match(requirements, /^# Install as \/etc\/codex\/requirements\.toml\.$/m);
  assert.match(readme, /`\/etc\/codex\/config\.toml`/);
  assert.doesNotMatch(readme, /managed_config\.toml/);
});

test('Responses and OTLP routes are complete without embedded credentials', () => {
  assert.match(config, /^wire_api = "responses"$/m);
  assert.match(config, /^request_max_retries = 25$/m);
  assert.match(config, /^stream_max_retries = 25$/m);
  assert.match(config, /^requires_openai_auth = false$/m);
  assert.match(config, /^auth\s*=.*CHIPTRACE_API_KEY/m);
  assert.match(config, /18084\/otel\/v1\/logs/);
  assert.match(config, /18084\/otel\/v1\/traces/);
  assert.match(config, /^log_user_prompt = true$/m);
  assert.match(config, /^\[otel\.tool_result\]$/m);
  assert.match(config, /^max_bytes = 268435456$/m);
  assert.doesNotMatch(config, /Authorization|CHIPTRACE_INGEST_TOKEN/);
  assert.match(readme, /OTEL_EXPORTER_OTLP_HEADERS/);
  assert.match(readme, /Authorization=Bearer%20\$\{CHIPTRACE_INGEST_TOKEN\}/);
});

test('model catalog keeps fields required by legacy and current Stock Codex', () => {
  const catalog = JSON.parse(
    fs.readFileSync(path.join(integrationRoot, 'managed-models.json'), 'utf8'),
  );
  assert.deepEqual(catalog.models.map((model) => model.slug), ['gpt-5.6-sol', 'gpt-6-astra']);
  for (const model of catalog.models) {
    assert.equal(model.tool_mode, 'direct');
    assert.equal(model.supports_reasoning_summaries, true);
    assert.equal(model.supports_parallel_tool_calls, true);
    assert.equal(Object.hasOwn(model, 'include_apps_usage_instructions'), true);
    assert.equal(Object.hasOwn(model, 'apply_patch_tool_type'), false);
  }
});

test('required Hooks contain lifecycle only and fail closed at SessionStart', () => {
  assert.doesNotMatch(requirements, /^allow_managed_hooks_only\s*=\s*true$/m);
  const events = [...requirements.matchAll(/^\[\[hooks\.([A-Za-z]+)\]\]$/gm)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(events, [
    'Interrupt',
    'PostCompact',
    'PreCompact',
    'SessionEnd',
    'SessionStart',
    'Stop',
    'SubagentStart',
    'SubagentStop',
    'UserPromptSubmit',
  ]);
  assert.doesNotMatch(requirements, /PreToolUse|PostToolUse|PermissionRequest/);
  assert.doesNotMatch(requirements, /<CHIPTRACE_INGEST_TOKEN>/);

  const commands = requirements.match(/^command = .*$/gm) ?? [];
  assert.equal(commands.length, events.length);
  assert.equal(commands.every((command) => command.includes('$CHIPTRACE_INGEST_TOKEN')), true);

  const sessionStart = requirements.split('[[hooks.SessionEnd]]', 1)[0];
  const sessionStartCommandLine = sessionStart.match(/^command = (.*)$/m);
  assert.notEqual(sessionStartCommandLine, null);
  const sessionStartCommand = JSON.parse(sessionStartCommandLine[1]);
  assert.match(sessionStart, /\$CHIPTRACE_API_KEY/);
  assert.match(sessionStart, /\$OTEL_EXPORTER_OTLP_HEADERS/);
  assert.match(sessionStartCommand, /\\"continue\\":false/);
  assert.match(sessionStartCommand, /cloud ingest unavailable or configuration incomplete/);

  const timeouts = [...requirements.matchAll(/^timeout = (\d+)$/gm)]
    .map((match) => Number(match[1]));
  assert.equal(timeouts.length, events.length);
  assert.equal(timeouts.every((timeout) => timeout <= 3), true);
  assert.equal(commands.every((command) => command.includes('--max-time 1')), true);
  assert.equal(commands.every((command) => command.includes('--retry-max-time 2')), true);
  assert.doesNotMatch(requirements, /--max-time 8|timeout = 10/);
});

test('configuration has no ChipTrace client or plugin dependency', () => {
  const repositoryRoot = path.resolve(integrationRoot, '..', '..');
  assert.equal(fs.existsSync(path.join(repositoryRoot, 'examples', 'tool-registry.json')), false);
  const publicContractPaths = [
    'README.md',
    'deploy/collector-relay.yml',
    'deploy/docker-compose.yml',
    'docs/acceptance-matrix.md',
    'docs/architecture.md',
    'docs/data-contract.md',
    'docs/delivery.md',
    'docs/object-storage.md',
    'docs/operations.md',
    'integrations/codex/README.md',
    'integrations/codex/config.toml.example',
    'integrations/codex/requirements.toml.example',
  ];
  const forbiddenPatterns = [
    /\bcodex-run\b/i,
    /\/producer\/events\b/i,
    /\brollout exporter\b/i,
    /\/usr\/local\/bin\/chiptrace/i,
    /\bchiptrace-codex-agent\b/i,
    /install.*plugin/i,
    /\bchiptrace plugin\b/i,
    /managed_config\.toml/i,
    /patched codex/i,
    /修改版 codex/i,
  ];
  for (const relativePath of publicContractPaths) {
    const content = fs.readFileSync(path.join(repositoryRoot, relativePath), 'utf8');
    for (const pattern of forbiddenPatterns) {
      assert.doesNotMatch(content, pattern, `${relativePath} contains ${pattern}`);
    }
  }
});

test('separate native hook invocations survive while HTTP retries deduplicate', async () => {
  const bodies = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      bodies.push(Buffer.concat(chunks).toString('utf8'));
      res.writeHead(bodies.length === 1 ? 503 : 200);
      res.end('{}');
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const block = requirements.split('[[hooks.SessionEnd]]')[1].split('[[hooks.Interrupt]]')[0];
    const native = JSON.parse(block.match(/^command = (.*)$/m)[1]);
    const command = native.replace('http://172.28.11.121:18084', `http://127.0.0.1:${server.address().port}`);
    const event = { hook_event_name: 'SessionEnd', session_id: 'resume-contract-session', reason: 'other' };
    async function invoke(input) {
      const child = spawn('/bin/sh', ['-c', command], {
        env: { ...process.env, CHIPTRACE_INGEST_TOKEN: 'synthetic-hook-test-credential' },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const stderr = [];
      child.stderr.on('data', block => stderr.push(block));
      child.stdout.resume();
      const finished = new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('close', (code, signal) => code === 0 ? resolve() : reject(new Error(`Hook failed (${code}, ${signal}): ${Buffer.concat(stderr)}`)));
      });
      child.stdin.end(JSON.stringify(input));
      await finished;
    }
    await invoke(event);
    await invoke(event);
    assert.equal(bodies.length, 3);
    assert.equal(bodies[0], bodies[1], 'curl must retry the same serialized invocation');
    const first = JSON.parse(bodies[0]);
    const second = JSON.parse(bodies[2]);
    assert.notEqual(first.event_id, second.event_id, 'equal native payloads are separate occurrences');
    for (const body of [first, second]) {
      assert.match(body.event_id, /^[0-9a-f-]{36}$/);
      assert.ok(Number.isFinite(Date.parse(body.occurred_at)));
      const { event_id, occurred_at, ...nativeFields } = body;
      assert.deepEqual(nativeFields, event);
    }
    const identified = { ...event, event_id: 'stock-event-id', occurred_at: '2026-09-05T10:00:00Z' };
    await invoke(identified);
    assert.deepEqual(JSON.parse(bodies[3]), identified, 'existing native identity must be preserved');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('SessionStart stops before forwarding when credentials or hook JSON are invalid', async () => {
  const block = requirements.split('[[hooks.SessionEnd]]', 1)[0];
  const command = JSON.parse(block.match(/^command = (.*)$/m)[1]);
  for (const scenario of [
    { input: '{}', token: '' },
    { input: '{invalid', token: 'synthetic-hook-test-credential' },
  ]) {
    const child = spawn('/bin/sh', ['-c', command], {
      env: { ...process.env, CHIPTRACE_API_KEY: 'synthetic-provider-credential',
        CHIPTRACE_INGEST_TOKEN: scenario.token,
        OTEL_EXPORTER_OTLP_HEADERS: `Authorization=Bearer%20${scenario.token}` },
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    let stdout = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    const finished = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', code => code === 0 ? resolve() : reject(new Error(`Unexpected hook exit ${code}`)));
    });
    child.stdin.end(scenario.input);
    await finished;
    const response = JSON.parse(stdout);
    assert.equal(response.continue, false);
    assert.match(response.stopReason, /cloud ingest unavailable or configuration incomplete/);
  }
});
