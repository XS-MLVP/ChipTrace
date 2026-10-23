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
const hookPath = path.join(integrationRoot, 'chiptrace-codex-hook.sh');
const readmePath = path.join(integrationRoot, 'README.md');
const collectorComposePath = path.join(integrationRoot, '..', '..', 'deploy', 'collector-relay.yml');
const platformComposePath = path.join(integrationRoot, '..', '..', 'deploy', 'cloud-platform.yml');
const dockerfilePath = path.join(integrationRoot, '..', '..', 'Dockerfile');
const platformServerPath = path.join(integrationRoot, '..', 'cloud-platform', 'server.js');
const config = fs.readFileSync(configPath, 'utf8');
const requirements = fs.readFileSync(requirementsPath, 'utf8');
const readme = fs.readFileSync(readmePath, 'utf8');
const collectorCompose = fs.readFileSync(collectorComposePath, 'utf8');
const platformCompose = fs.readFileSync(platformComposePath, 'utf8');
const dockerfile = fs.readFileSync(dockerfilePath, 'utf8');
const platformServer = fs.readFileSync(platformServerPath, 'utf8');

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
  assert.match(config, /^base_url = "http:\/\/127\.0\.0\.1:18084\/"$/m);
  assert.match(config, /^request_max_retries = 25$/m);
  assert.match(config, /^stream_max_retries = 25$/m);
  assert.match(config, /^requires_openai_auth = false$/m);
  assert.match(config, /^auth\s*=.*CHIPTRACE_API_KEY/m);
  assert.match(config, /18084\/otel\/v1\/logs/);
  assert.match(config, /18084\/otel\/v1\/traces/);
  assert.doesNotMatch(config, /172\.28\.11\.121/);
  assert.match(requirements, /^base_url = "http:\/\/127\.0\.0\.1:18084\/"$/m);
  assert.doesNotMatch(requirements, /172\.28\.11\.121/);
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
  assert.equal(fs.existsSync(hookPath), true);
  assert.notEqual(fs.statSync(hookPath).mode & 0o111, 0);
  const hook = fs.readFileSync(hookPath, 'utf8');
  assert.match(hook, /CHIPTRACE_INGEST_TOKEN_FILE/);
  assert.match(hook, /127\.0\.0\.1:18084/);
  assert.match(hook, /\/etc\/chiptrace\/ingest-token/);
  assert.match(hook, /invalid_durable_receipt/);
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
  assert.equal(commands.every((command) => command.includes('CHIPTRACE_HOOK_EVENT=')), true);
  assert.equal(commands.every((command) => command.includes('CHIPTRACE_HOOK_BIN')), true);

  const sessionStart = requirements.split('[[hooks.SessionEnd]]', 1)[0];
  const sessionStartCommandLine = sessionStart.match(/^command = (.*)$/m);
  assert.notEqual(sessionStartCommandLine, null);
  const sessionStartCommand = JSON.parse(sessionStartCommandLine[1]);
  assert.doesNotMatch(sessionStartCommand, /CHIPTRACE_API_KEY|OTEL_EXPORTER_OTLP_HEADERS/);
  assert.match(sessionStart, /CHIPTRACE_GATEWAY_URL/);
  assert.match(sessionStart, /CHIPTRACE_INGEST_TOKEN_FILE/);
  assert.match(sessionStartCommand, /CHIPTRACE_HOOK_EVENT=SessionStart/);

  const timeouts = [...requirements.matchAll(/^timeout = (\d+)$/gm)]
    .map((match) => Number(match[1]));
  assert.equal(timeouts.length, events.length);
  assert.equal(timeouts.every((timeout) => timeout <= 3), true);
  assert.doesNotMatch(requirements, /--max-time 8|timeout = 10/);
});

test('README SessionStart preflight includes the native fields required by the converter', () => {
  assert.match(readme, /"hook_event_name":"SessionStart","session_id":"preflight"/);
  assert.match(readme, /"model":"preflight"/);
  assert.match(readme, /"permission_mode":"default"/);
  assert.match(readme, /"source":"startup"/);
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

test('production deployment templates require an immutable image revision', () => {
  assert.match(
    collectorCompose,
    /image: \$\{CHIPTRACE_IMAGE:\?set CHIPTRACE_IMAGE to an immutable ChipTrace image\}/,
  );
  assert.doesNotMatch(collectorCompose, /chiptrace:(?:latest|local)\b/);
  assert.match(platformCompose, /image: \$\{CHIPTRACE_PLATFORM_IMAGE:\?set CHIPTRACE_PLATFORM_IMAGE to an immutable ChipTrace platform image\}/);
  assert.match(platformCompose, /CHIPTRACE_BACKEND: \$\{CHIPTRACE_BACKEND:\?set CHIPTRACE_BACKEND to fs, oss, or s3\}/);
  assert.match(platformCompose, /CHIPTRACE_BUILD_REVISION: \$\{CHIPTRACE_REVISION:\?set CHIPTRACE_REVISION to the full Git commit SHA\}/);
  assert.doesNotMatch(platformCompose, /CHIPTRACE_BACKEND: \$\{CHIPTRACE_BACKEND:-fs\}/);
  assert.match(platformServer, /CHIPTRACE_BACKEND must be explicitly set to fs, oss, or s3/);
  assert.doesNotMatch(platformServer, /process\.env\.CHIPTRACE_BACKEND \|\| 'fs'/);
  for (const compose of [collectorCompose, platformCompose]) {
    assert.match(compose, /CHIPTRACE_REVISION:\?set CHIPTRACE_REVISION to the full Git commit SHA/);
    assert.doesNotMatch(compose, /^\s+build:/m);
    assert.doesNotMatch(compose, /chiptrace(?:-platform)?:(?:latest|local)\b/);
  }
  assert.match(dockerfile, /org\.opencontainers\.image\.revision="\$\{CHIPTRACE_REVISION\}"/);
  assert.match(dockerfile, /ENV CHIPTRACE_BUILD_REVISION=\$\{CHIPTRACE_REVISION\}/);
});

test('standalone platform server refuses an implicit or invalid storage backend', async () => {
  for (const backend of [undefined, 'local']) {
    const env = { ...process.env, CHIPTRACE_BUILD_REVISION: 'f'.repeat(40) };
    if (backend === undefined) delete env.CHIPTRACE_BACKEND;
    else env.CHIPTRACE_BACKEND = backend;
    const child = spawn(process.execPath, [platformServerPath], {
      cwd: path.resolve(integrationRoot, '..', '..'),
      env,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    const stderr = [];
    child.stderr.on('data', chunk => stderr.push(chunk));
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error(`platform server did not reject backend=${backend ?? '<missing>'}`));
      }, 5000);
      child.once('error', reject);
      child.once('close', (code, signal) => {
        clearTimeout(timer);
        resolve({ code, signal });
      });
    });
    assert.equal(result.code, 1, `backend=${backend ?? '<missing>'} signal=${result.signal}`);
    assert.match(Buffer.concat(stderr).toString('utf8'), /CHIPTRACE_BACKEND must be explicitly set to fs, oss, or s3/);
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
      res.end(JSON.stringify({ partialSuccess: { rejectedLogRecords: 0, rejectedSpans: 0, errorMessage: null },
        chiptrace: { ok: true, durable: true, captures: 2, duplicates: 0,
          summary: { endpoint: 'codex_hook', source_records: 1, derived_captures: 1, unknown_events: 0,
            attributed_quality_errors: 0, conversion_errors: [] } } }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const block = requirements.split('[[hooks.SessionEnd]]')[1].split('[[hooks.Interrupt]]')[0];
    const native = JSON.parse(block.match(/^command = (.*)$/m)[1]);
    const command = native;
    const event = { hook_event_name: 'SessionEnd', session_id: 'resume-contract-session', reason: 'other' };
    async function invoke(input) {
      const child = spawn('/bin/sh', ['-c', command], {
        env: { ...process.env, CHIPTRACE_HOOK_BIN: hookPath,
          CHIPTRACE_GATEWAY_URL: `http://127.0.0.1:${server.address().port}`,
          CHIPTRACE_INGEST_TOKEN: 'synthetic-hook-test-credential' },
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
  // Point the token lookup at a path that cannot exist so the test never reads
  // a real host credential from the default location.
  const missingTokenFile = path.join(integrationRoot, 'does-not-exist-ingest-token');
  for (const scenario of [
    { input: '{}', token: '' },
    { input: '{invalid', token: 'synthetic-hook-test-credential' },
  ]) {
    const child = spawn('/bin/sh', ['-c', command], {
      env: { ...process.env, CHIPTRACE_HOOK_BIN: hookPath,
        CHIPTRACE_INGEST_TOKEN_FILE: missingTokenFile,
        CHIPTRACE_INGEST_TOKEN: scenario.token },
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
    assert.match(response.stopReason, /ChipTrace cloud ingest unavailable:/);
  }
});

test('an empty Hook probe is acknowledged locally without posting a bad event', async () => {
  const block = requirements.split('[[hooks.SessionEnd]]', 1)[0];
  const command = JSON.parse(block.match(/^command = (.*)$/m)[1]);
  let requested = 0;
  const server = http.createServer((request, response) => {
    requested += 1;
    response.end(JSON.stringify({ ok: true, durable: true }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    const child = spawn('/bin/sh', ['-c', command], {
      env: { ...process.env, CHIPTRACE_HOOK_BIN: hookPath,
        CHIPTRACE_GATEWAY_URL: `http://127.0.0.1:${port}`,
        CHIPTRACE_INGEST_TOKEN: 'synthetic-hook-test-credential' },
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    let stdout = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    const finished = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', code => code === 0 ? resolve() : reject(new Error(`Unexpected hook exit ${code}`)));
    });
    child.stdin.end('{}');
    await finished;
    assert.equal(stdout, '', 'an empty probe must not emit a stop reason');
    assert.equal(requested, 0, 'an empty probe must not reach the gateway');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
