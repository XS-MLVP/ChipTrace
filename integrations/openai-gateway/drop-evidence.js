'use strict';

// A dropped capture is data loss, so it must leave a durable record. In-memory
// counters cannot answer "which request was lost" once the health window has
// slid past it, and a lifecycle counter is not an audit trail.
//
// This module is deliberately small and dependency-free so the gateway can
// call it from any failure path and tests can exercise it directly.

const fs = require('node:fs');
const path = require('node:path');

const EVIDENCE_FILE = 'drops.ndjson';
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_ERROR_CHARS = 300;

function evidenceDirectory(outboxDir) {
  return path.join(outboxDir, 'dropped');
}

function evidenceSize(outboxDir) {
  try {
    return fs.statSync(path.join(evidenceDirectory(outboxDir), EVIDENCE_FILE)).size;
  } catch {
    return 0;
  }
}

function withinBudget(outboxDir, maxBytes = MAX_BYTES) {
  return evidenceSize(outboxDir) <= maxBytes;
}

function bounded(value, limit = MAX_ERROR_CHARS) {
  return typeof value === 'string' ? value.slice(0, limit) : null;
}

function boundedInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/**
 * Append one durable line describing a dropped capture.
 *
 * The returned record is exactly what was written (or would have been), so a
 * caller can surface it in health without re-reading the file.
 */
function recordDrop(outboxDir, { reason, error = null, context = {}, at = new Date() } = {}) {
  const droppedAt = at instanceof Date ? at.toISOString() : new Date(at).toISOString();
  const entry = {
    droppedAt,
    reason: bounded(reason) || 'unknown',
    captureId: bounded(context.captureId),
    clientRequestId: bounded(context.clientRequestId),
    proxiedPath: bounded(context.proxiedPath),
    method: bounded(context.method),
    requestBytesCaptured: boundedInteger(context.requestBytesCaptured),
    responseBytesCaptured: boundedInteger(context.responseBytesCaptured),
    errorCode: error && typeof error.code === 'string' ? bounded(error.code) : null,
    errorMessage: error ? bounded(error.message || String(error)) : null,
  };
  let persisted = false;
  let persistError = null;
  try {
    const directory = evidenceDirectory(outboxDir);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    fs.appendFileSync(path.join(directory, EVIDENCE_FILE), `${JSON.stringify(entry)}\n`, {
      mode: 0o600,
    });
    persisted = true;
  } catch (failure) {
    // The drop still counts; failing to persist evidence must not mask it.
    persistError = bounded(failure.message || String(failure));
  }
  return { entry, persisted, persistError, withinBudget: withinBudget(outboxDir) };
}

function readDrops(outboxDir, limit = 100) {
  try {
    const lines = fs
      .readFileSync(path.join(evidenceDirectory(outboxDir), EVIDENCE_FILE), 'utf8')
      .split('\n')
      .filter(Boolean);
    return lines.slice(-limit).map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

module.exports = {
  EVIDENCE_FILE,
  MAX_BYTES,
  evidenceDirectory,
  evidenceSize,
  withinBudget,
  recordDrop,
  readDrops,
};
