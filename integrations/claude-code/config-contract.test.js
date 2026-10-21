'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const directory = __dirname;
const settingsPath = path.join(directory, 'settings.hooks.example.json');
const helperPath = path.join(directory, 'chiptrace-claude-hook.sh');
const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));

const REQUIRED_EVENTS = [
  'SessionStart',
  'UserPromptSubmit',
  'PreToolUse',
  'PostToolUse',
  'Stop',
  'SessionEnd',
];

test('Claude Code settings covers every lifecycle and tool boundary', () => {
  for (const event of REQUIRED_EVENTS) {
    const matchers = settings.hooks?.[event];
    assert.ok(Array.isArray(matchers) && matchers.length > 0, `missing ${event} hook`);
    const command = matchers[0]?.hooks?.[0]?.command;
    assert.ok(typeof command === 'string' && command.includes('chiptrace-claude-hook'),
      `${event} must invoke the ChipTrace helper`);
    assert.ok(command.includes(`CHIPTRACE_HOOK_EVENT=${event}`),
      `${event} must declare its Hook event name`);
    assert.ok(command.includes('CHIPTRACE_INGEST_TOKEN_FILE='),
      `${event} must read the ingest token from a protected file`);
  }
});

test('Claude Code settings never embeds the ingest token or provider key', () => {
  const text = fs.readFileSync(settingsPath, 'utf8');
  assert.ok(!/CHIPTRACE_INGEST_TOKEN=[^F\s]/.test(text), 'inline ingest token is forbidden');
  assert.ok(!/sk-[A-Za-z0-9]{20,}/.test(text), 'provider keys must not be committed');
});

test('helper fails closed on a payload without an event or session', () => {
  const result = spawnSync(helperPath, [], {
    input: '{}',
    encoding: 'utf8',
    env: {
      ...process.env,
      CHIPTRACE_HOOK_EVENT: 'Stop',
      CHIPTRACE_INGEST_TOKEN: 'x'.repeat(64),
      CHIPTRACE_CLAUDE_STATE_DIR: '/tmp/chiptrace-claude-hook-test',
    },
    timeout: 5000,
  });
  assert.notEqual(result.status, 0, 'malformed Hook payload must not be acknowledged');
});

test('helper binds a Turn from prompt_id without inventing a UUID', () => {
  const script = fs.readFileSync(helperPath, 'utf8');
  assert.ok(script.includes('claude_prompt_id'), 'native prompt_id provenance is required');
  assert.ok(script.includes('value["turn_id"] = turn_id'), 'turn_id must be injected');
  assert.ok(script.includes('"PostToolUse"'), 'tool result status handling is required');
});
