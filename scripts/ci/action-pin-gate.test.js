'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { extractActionRefs, validateActionPins } = require('./action-pin-gate');

const root = path.resolve(__dirname, '..', '..');
const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'action-pins.json'), 'utf8'));

test('all workflow action references match the checked-in immutable pin manifest', () => {
  const result = validateActionPins(workflow, manifest);
  assert.equal(result.schema_version, 'chiptrace.github-action-pins.v1');
  assert.ok(result.action_references >= 10);
  assert.equal(result.unique_actions, Object.keys(manifest.actions).length);
  assert.deepEqual(new Set(extractActionRefs(workflow).map(reference => reference.action)),
    new Set(Object.keys(manifest.actions)));
});

test('action pin gate rejects a tag, an unknown action and a SHA drift', () => {
  assert.throws(() => validateActionPins(workflow.replace(
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    'actions/checkout@v7',
  ), manifest), /40-character lowercase commit SHA/);
  assert.throws(() => validateActionPins(`${workflow}\n      - uses: example/unknown@${'a'.repeat(40)}\n`, manifest),
  /missing from the pin manifest/);
  assert.throws(() => validateActionPins(workflow.replace(
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    `actions/checkout@${'b'.repeat(40)}`,
  ), manifest), /does not match the pinned SHA/);
});

test('action pin gate rejects stale manifest entries and malformed pin metadata', () => {
  const stale = JSON.parse(JSON.stringify(manifest));
  stale.actions['example/stale'] = { sha: 'c'.repeat(40), version: 'v1' };
  assert.throws(() => validateActionPins(workflow, stale), /unused action/);

  const malformed = JSON.parse(JSON.stringify(manifest));
  malformed.actions['actions/checkout'].sha = '49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c';
  assert.throws(() => validateActionPins(workflow, malformed), /does not match the pinned SHA/);
});
