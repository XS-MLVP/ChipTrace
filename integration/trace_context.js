'use strict';

const LIFECYCLE_ITEM_TYPES = new Set([
  'cancel',
  'compaction',
  'compaction_trigger',
  'retry',
  'session_end',
  'session_start',
  'subagent_join',
  'subagent_spawn',
]);

const RESPONSE_LIFECYCLE_TYPES = new Set([
  'response.cancelled',
  'response.completed',
  'response.created',
  'response.failed',
  'response.incomplete',
  'response.in_progress',
]);

function extractTraceMetadata(requestBodyText, responseBodyText) {
  const request = parseJsonObject(requestBodyText);
  const metadata = objectValue(request.client_metadata);
  const traceContext = {};
  for (const [target, names] of Object.entries({
    session_id: ['session_id', 'sessionId'],
    thread_id: ['thread_id', 'threadId'],
    root_session_id: ['root_session_id', 'rootSessionId'],
    parent_session_id: ['parent_session_id', 'parentSessionId'],
    goal_id: ['goal_id', 'goalId'],
    turn_id: ['turn_id', 'turnId'],
    agent_id: ['agent_id', 'agentId'],
    branch_id: ['branch_id', 'branchId'],
    previous_response_id: ['previous_response_id', 'previousResponseId'],
  })) {
    const value = firstString(metadata, request, names);
    if (value !== null) traceContext[target] = value;
  }

  const events = new Set();
  const input = Array.isArray(request.input) ? request.input : [];
  for (const item of input) {
    if (!item || typeof item !== 'object') continue;
    const type = stringValue(item.type);
    if (type && LIFECYCLE_ITEM_TYPES.has(type)) events.add(type);
  }
  for (const type of responseEventTypes(responseBodyText)) {
    if (RESPONSE_LIFECYCLE_TYPES.has(type) || LIFECYCLE_ITEM_TYPES.has(type)) events.add(type);
  }
  return { traceContext, observedLifecycleEvents: [...events].sort() };
}

function responseEventTypes(value) {
  const text = typeof value === 'string' ? value : '';
  const direct = parseJsonObject(text);
  const directType = stringValue(direct.type);
  const directStatus = stringValue(direct.status);
  const types = [];
  if (directType) types.push(directType);
  if (directStatus) types.push(`response.${directStatus}`);
  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith('data:')) continue;
    const payload = line.slice(5).trim();
    if (!payload || payload === '[DONE]') continue;
    const event = parseJsonObject(payload);
    const type = stringValue(event.type);
    if (type) types.push(type);
  }
  return types;
}

function parseJsonObject(value) {
  if (typeof value !== 'string' || !value) return {};
  try {
    const parsed = JSON.parse(value);
    return objectValue(parsed);
  } catch {
    return {};
  }
}

function objectValue(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function stringValue(value) {
  if (typeof value === 'string' && value) return value;
  if (Number.isSafeInteger(value)) return String(value);
  return null;
}

function firstString(primary, secondary, names) {
  for (const source of [primary, secondary]) {
    for (const name of names) {
      const value = stringValue(source[name]);
      if (value !== null) return value;
    }
  }
  return null;
}

module.exports = { extractTraceMetadata, responseEventTypes };
