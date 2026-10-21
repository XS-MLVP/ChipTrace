'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { BUILD_REVISION_PATTERN, validateBuildRevision } = require('./server');

test('standalone platform startup requires a complete Git revision', () => {
  assert.equal(BUILD_REVISION_PATTERN.test('b'.repeat(40)), true);
  assert.equal(validateBuildRevision('b'.repeat(40)), 'b'.repeat(40));
  for (const value of [undefined, '', 'b'.repeat(39), 'b'.repeat(41), 'B'.repeat(40), 'unknown']) {
    assert.throws(() => validateBuildRevision(value), /full 40-character Git SHA/);
  }
});
