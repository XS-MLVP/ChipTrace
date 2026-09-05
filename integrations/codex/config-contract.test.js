'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

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
  assert.equal(catalog.models.length, 1);
  const model = catalog.models[0];
  assert.equal(model.tool_mode, 'direct');
  assert.equal(model.supports_reasoning_summaries, true);
  assert.equal(model.supports_parallel_tool_calls, true);
  assert.equal(Object.hasOwn(model, 'include_apps_usage_instructions'), true);
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
