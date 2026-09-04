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
  assert.match(config, /^max_bytes = 268435456$/m);
  assert.doesNotMatch(config, /Authorization|CHIPTRACE_INGEST_TOKEN/);
  assert.match(readme, /OTEL_EXPORTER_OTLP_HEADERS/);
  assert.match(readme, /Authorization=Bearer%20\$\{CHIPTRACE_INGEST_TOKEN\}/);
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
  const contract = `${config}\n${requirements}\n${readme}`;
  assert.doesNotMatch(contract, /codex-run|producer\/events|rollout exporter/i);
  assert.doesNotMatch(contract, /\/usr\/local\/bin\/chiptrace|chiptrace-codex-agent/i);
  assert.doesNotMatch(contract, /install.*plugin|chiptrace plugin/i);
});
