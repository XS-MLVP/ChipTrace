'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_WORKFLOW = path.join(ROOT, '.github', 'workflows', 'ci.yml');
const DEFAULT_MANIFEST = path.join(__dirname, 'action-pins.json');
const SHA_PATTERN = /^[a-f0-9]{40}$/;

function extractActionRefs(workflow) {
  assert.equal(typeof workflow, 'string', 'workflow must be a string');
  return [...workflow.matchAll(/^\s*(?:-\s+)?uses:\s+([^\s#]+)/gm)].map((match, index) => {
    const reference = match[1];
    const separator = reference.lastIndexOf('@');
    assert.ok(separator > 0, `workflow action ${index + 1} is missing @SHA: ${reference}`);
    const action = reference.slice(0, separator);
    const sha = reference.slice(separator + 1);
    assert.match(action, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, `invalid action name: ${action}`);
    assert.match(sha, SHA_PATTERN, `workflow action ${action} must use a 40-character lowercase commit SHA`);
    return { action, sha, reference };
  });
}

function validateManifest(manifest) {
  assert.ok(manifest && typeof manifest === 'object' && !Array.isArray(manifest),
    'action pin manifest must be an object');
  assert.equal(manifest.schema_version, 'chiptrace.github-action-pins.v1');
  assert.equal(manifest.workflow, '.github/workflows/ci.yml');
  assert.ok(manifest.actions && typeof manifest.actions === 'object' && !Array.isArray(manifest.actions),
    'action pin manifest must contain an actions object');

  const entries = Object.entries(manifest.actions);
  assert.ok(entries.length > 0, 'action pin manifest must contain at least one action');
  for (const [action, pin] of entries) {
    assert.match(action, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, `invalid manifest action name: ${action}`);
    assert.ok(pin && typeof pin === 'object' && !Array.isArray(pin),
      `manifest pin for ${action} must be an object`);
    assert.match(pin.sha || '', SHA_PATTERN, `manifest pin for ${action} must contain a 40-character lowercase SHA`);
    assert.match(pin.version || '', /^\S+$/, `manifest pin for ${action} must contain a version label`);
  }
  return manifest;
}

function validateActionPins(workflow, manifest) {
  const pins = validateManifest(manifest);
  const actual = extractActionRefs(workflow);
  assert.ok(actual.length > 0, 'workflow must contain at least one action');

  const observed = new Map();
  for (const reference of actual) {
    const pin = pins.actions[reference.action];
    assert.ok(pin, `workflow action is missing from the pin manifest: ${reference.action}`);
    assert.equal(reference.sha, pin.sha,
      `workflow action ${reference.action} does not match the pinned SHA in action-pins.json`);
    const previous = observed.get(reference.action);
    if (previous !== undefined) assert.equal(reference.sha, previous,
      `workflow uses multiple revisions for ${reference.action}`);
    observed.set(reference.action, reference.sha);
  }

  for (const action of Object.keys(pins.actions)) {
    assert.ok(observed.has(action), `action pin manifest contains an unused action: ${action}`);
  }

  return {
    schema_version: pins.schema_version,
    workflow: pins.workflow,
    action_references: actual.length,
    unique_actions: observed.size,
    actions: [...observed].map(([action, sha]) => ({ action, sha, version: pins.actions[action].version })),
  };
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function parseArgs(argv) {
  let workflow = DEFAULT_WORKFLOW;
  let manifest = DEFAULT_MANIFEST;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!value || (flag !== '--workflow' && flag !== '--manifest')) {
      throw new Error('usage: action-pin-gate.js [--workflow FILE] [--manifest FILE]');
    }
    if (flag === '--workflow') workflow = path.resolve(value);
    else manifest = path.resolve(value);
    index += 1;
  }
  return { workflow, manifest };
}

function main(argv = process.argv.slice(2)) {
  const { workflow, manifest } = parseArgs(argv);
  const result = validateActionPins(fs.readFileSync(workflow, 'utf8'), readJson(manifest));
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { extractActionRefs, validateManifest, validateActionPins, parseArgs };
