'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { requireSuccessfulTurnWireCoverage } = require('./deployment-smoke');

function gateWith(coverage) {
  return { relay: {
    turn_capture_ready: coverage.turn_capture_ready ?? true,
    wire_turn_coverage: {
      success_definition: 'http_2xx',
      freshness_definition: 'new_durable_capture',
      turn_scoped_captures: 2,
      successful_turn_scoped_captures: 1,
      unscoped_captures: 0,
      identity_conflict_captures: 0,
      last_successful_at: '2026-10-16T10:00:00.000Z',
      last_successful_age_ms: 100,
      successful_turn_scoped_fresh: true,
      turn_capture_ready: true,
      ...coverage,
    },
  } };
}

test('deployment smoke report requires fresh successful Turn Wire evidence', () => {
  const summary = requireSuccessfulTurnWireCoverage(gateWith({}));
  assert.equal(summary.successful_turn_scoped_captures, 1);
  assert.equal(summary.successful_turn_scoped_fresh, true);
  assert.equal(summary.turn_capture_ready, true);
  assert.deepEqual(Object.keys(summary).sort(), [
    'freshness_definition',
    'identity_conflict_captures',
    'last_successful_age_ms',
    'last_successful_at',
    'success_definition',
    'successful_turn_scoped_captures',
    'successful_turn_scoped_fresh',
    'turn_capture_ready',
    'turn_scoped_captures',
    'unscoped_captures',
  ]);
});

test('deployment smoke fails closed when Turn Wire evidence is missing or stale', () => {
  for (const coverage of [
    { successful_turn_scoped_captures: 0 },
    { successful_turn_scoped_captures: null },
    { successful_turn_scoped_fresh: false },
    { turn_capture_ready: false },
  ]) {
    assert.throws(() => requireSuccessfulTurnWireCoverage(gateWith(coverage)),
      /successful Turn-scoped Wire|fresh successful Turn-scoped Wire|turn_capture_ready/);
  }
  assert.throws(() => requireSuccessfulTurnWireCoverage({ relay: {} }),
    /relay\.wire_turn_coverage/);
});
