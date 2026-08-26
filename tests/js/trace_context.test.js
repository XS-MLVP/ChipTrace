'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { extractTraceMetadata } = require('../../integration/trace_context');

test('extracts explicit session DAG identifiers without inference', () => {
  const request = JSON.stringify({
    previous_response_id: 'response-parent',
    client_metadata: {
      session_id: 'session-child',
      thread_id: 'thread-one',
      root_session_id: 'session-root',
      parent_session_id: 'session-parent',
      goal_id: 'goal-one',
      turn_id: 'turn-one',
      agent_id: 'agent-one',
      branch_id: 'branch-one',
    },
    input: [{ type: 'compaction' }, { type: 'message', role: 'user' }],
  });
  const response = [
    'data: {"type":"response.created"}',
    'data: {"type":"response.completed"}',
  ].join('\n');
  assert.deepEqual(extractTraceMetadata(request, response), {
    traceContext: {
      session_id: 'session-child',
      thread_id: 'thread-one',
      root_session_id: 'session-root',
      parent_session_id: 'session-parent',
      goal_id: 'goal-one',
      turn_id: 'turn-one',
      agent_id: 'agent-one',
      branch_id: 'branch-one',
      previous_response_id: 'response-parent',
    },
    observedLifecycleEvents: ['compaction', 'response.completed', 'response.created'],
  });
});

test('does not fabricate identifiers or lifecycle events from malformed bodies', () => {
  assert.deepEqual(extractTraceMetadata('{bad', '<html>failure</html>'), {
    traceContext: {},
    observedLifecycleEvents: [],
  });
});
