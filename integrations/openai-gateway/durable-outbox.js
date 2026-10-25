'use strict';

// The relay shell is a long-lived proxy process.  This small outbox keeps the
// capture hand-off durable without making the request forwarding path wait for
// the Rust Relay.  Files are written to a temporary name, fsynced, and then
// linked into `pending`; a file is only removed after a conserved durable ACK.

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { isUtf8 } = require('node:buffer');
const { isDeepStrictEqual } = require('node:util');

const CAPTURE_ID_RE = /^cap-[A-Za-z0-9._:-]+$/;
const SENSITIVE_KEY_RE = /(^|[_-])(authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|password|passwd|secret|cookie|set-cookie)([_-]|$)/i;
const BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const SECRET_PREFIX_RE = /\b(?:sk|cr|rk|key)_[A-Za-z0-9_-]{12,}\b/gi;
const SENSITIVE_BODY_CANDIDATE_RE = /"(?:authorization|api[_-]?key|apiKey|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|id[_-]?token|idToken|client[_-]?secret|clientSecret|password|passwd|secret|cookie|set-cookie)"\s*:|\bBearer\s+[A-Za-z0-9._~+/=-]+|\b(?:sk|cr|rk|key)_[A-Za-z0-9_-]{12,}\b/i;
const SENSITIVE_NORMALIZED_KEYS = new Set([
  'authorization',
  'apikey',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'clientsecret',
  'password',
  'passwd',
  'secret',
  'cookie',
  'setcookie',
]);
const RESPONSES_TERMINAL_EVENTS = new Set([
  'error',
  'response.cancelled',
  'response.canceled',
  'response.completed',
  'response.failed',
  'response.incomplete',
]);
const SSE_LINE_PREFIX_LIMIT = 1024;
const FAILED_OUTBOX_RECOVERY_SCHEMA = 'chiptrace.failed-outbox-recovery.v1';
const OUTBOX_RECOVERY_RECEIPT_SCHEMA = 'chiptrace.outbox-recovery-receipt.v1';
const SHA256_RE = /^[a-f0-9]{64}$/;

class ResponsesSseBoundaryTracker {
  constructor() {
    this.eventType = '';
    this.linePrefix = Buffer.alloc(0);
    this.lineTruncated = false;
    this.totalBytes = 0;
    this.lineStartOffset = 0;
    this.lineEndOffset = 0;
    this.protocolTerminalEvent = null;
    this.protocolTerminalByteOffset = null;
    this.framingDoneObserved = false;
    this.framingDoneByteOffset = null;
  }

  observe(chunk) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const chunkStart = this.totalBytes;
    this.totalBytes += bytes.length;
    let offset = 0;
    while (offset < bytes.length) {
      const newline = bytes.indexOf(0x0a, offset);
      const end = newline === -1 ? bytes.length : newline;
      const lineStart = chunkStart + offset;
      const lineEnd = chunkStart + (newline === -1 ? bytes.length : newline + 1);
      if (this.linePrefix.length === 0) this.lineStartOffset = lineStart;
      this.#appendLinePrefix(bytes.subarray(offset, end));
      this.lineEndOffset = lineEnd;
      if (newline === -1) break;
      this.#finishLine(lineEnd);
      offset = newline + 1;
    }
    if (bytes.length === 0 && this.linePrefix.length === 0) {
      this.lineStartOffset = chunkStart;
      this.lineEndOffset = chunkStart;
    }
    return this.snapshot();
  }

  #appendLinePrefix(bytes) {
    const remaining = SSE_LINE_PREFIX_LIMIT - this.linePrefix.length;
    if (remaining > 0) {
      this.linePrefix = Buffer.concat([
        this.linePrefix,
        bytes.subarray(0, remaining),
      ]);
    }
    if (bytes.length > remaining) this.lineTruncated = true;
  }

  #finishLine(lineEndOffset) {
    const line = this.linePrefix.toString('utf8').replace(/\r$/, '');
    if (line === '') {
      this.eventType = '';
    } else if (line.startsWith('event:')) {
      this.eventType = line.slice('event:'.length).trim();
    } else if (line.startsWith('data:')) {
      const data = line.slice('data:'.length).trimStart();
      if (data.trim() === '[DONE]') {
        this.framingDoneObserved = true;
        this.framingDoneByteOffset = lineEndOffset;
      }
      const dataType = /^\{\s*"type"\s*:\s*"([^"]+)"/.exec(data)?.[1] || '';
      const eventType = this.eventType || dataType;
      if (RESPONSES_TERMINAL_EVENTS.has(eventType)) {
        this.protocolTerminalEvent = eventType;
        this.protocolTerminalByteOffset = lineEndOffset;
      }
    }
    this.linePrefix = Buffer.alloc(0);
    this.lineTruncated = false;
  }

  snapshot() {
    return {
      protocolTerminalObserved: this.protocolTerminalEvent !== null,
      protocolTerminalEvent: this.protocolTerminalEvent,
      protocolTerminalByteOffset: this.protocolTerminalByteOffset,
      framingDoneObserved: this.framingDoneObserved,
      framingDoneByteOffset: this.framingDoneByteOffset,
      responseBytesObserved: this.totalBytes,
      responseBoundaryObserved:
        this.protocolTerminalEvent !== null || this.framingDoneObserved,
    };
  }
}

function positiveInteger(value, fallback, min = 1, max = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(Math.floor(parsed), min), max);
}

function asBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function validCaptureId(value) {
  return CAPTURE_ID_RE.test(value) && Buffer.byteLength(value, 'utf8') <= 256;
}

function firstHeaderValue(headers, name) {
  const value = headers?.[String(name).toLowerCase()];
  if (Array.isArray(value)) return value[0] || '';
  return value === undefined || value === null ? '' : String(value);
}

async function validateProviderCredential(options = {}) {
  const authorization = String(options.authorization || '').trim();
  if (!/^Bearer\s+\S+$/i.test(authorization)) {
    return { ok: false, status: 401, reason: 'model_auth_required' };
  }
  const modelsUrl = String(options.modelsUrl || '').trim();
  if (!modelsUrl) {
    return { ok: false, status: 503, reason: 'model_auth_not_configured' };
  }
  const timeoutMs = positiveInteger(options.timeoutMs, 30000, 1, 300000);
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    return { ok: false, status: 503, reason: 'model_auth_not_configured' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(modelsUrl, {
      method: 'GET',
      headers: { authorization, accept: 'application/json' },
      signal: controller.signal,
    });
    if (response.ok) return { ok: true, status: response.status };
    if (response.status === 401 || response.status === 403) {
      return { ok: false, status: response.status, reason: 'model_auth_rejected' };
    }
    return { ok: false, status: 503, reason: 'model_auth_unavailable' };
  } catch (error) {
    return {
      ok: false,
      status: 503,
      reason: error?.name === 'AbortError' ? 'model_auth_timeout' : 'model_auth_unavailable',
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Extract the task identity Stock Codex already sends with every Responses
 * request. Values are copied only from observed protocol headers; this helper
 * never invents a task/session boundary.
 */
function codexTraceContextFromHeaders(requestHeaders, responseHeaders = {}) {
  const candidates = new Map();
  const errors = [];
  const add = (field, value, source, priority) => {
    const normalized = typeof value === 'string' ? value.trim() : '';
    if (!normalized) return;
    const entries = candidates.get(field) || [];
    entries.push({
      field: `traceContext.${field}`,
      value: normalized,
      source,
      producer: 'stock_codex',
      authority: 'protocol_observed',
      priority,
    });
    candidates.set(field, entries);
  };

  add('session_id', firstHeaderValue(requestHeaders, 'session-id'), 'requestHeaders.session-id', 0);
  add('thread_id', firstHeaderValue(requestHeaders, 'thread-id'), 'requestHeaders.thread-id', 0);
  add('session_id', firstHeaderValue(requestHeaders, 'session_id'), 'requestHeaders.session_id', 1);
  add('thread_id', firstHeaderValue(requestHeaders, 'thread_id'), 'requestHeaders.thread_id', 1);

  const rawMetadata = firstHeaderValue(requestHeaders, 'x-codex-turn-metadata');
  if (rawMetadata) {
    try {
      const metadata = JSON.parse(rawMetadata);
      if (!metadata || Array.isArray(metadata) || typeof metadata !== 'object') {
        throw new Error('must be a JSON object');
      }
      for (const [sourceField, targetField] of [
        ['session_id', 'session_id'],
        ['thread_id', 'thread_id'],
        ['turn_id', 'turn_id'],
        ['root_turn_id', 'root_turn_id'],
        ['parent_thread_id', 'parent_thread_id'],
        ['agent_name', 'agent_path'],
        ['window_id', 'window_id'],
        ['context_window_id', 'context_window_id'],
      ]) {
        add(
          targetField,
          metadata[sourceField],
          `requestHeaders.x-codex-turn-metadata.${sourceField}`,
          2,
        );
      }
    } catch (error) {
      errors.push(`invalid x-codex-turn-metadata: ${error.message || String(error)}`);
    }
  }

  for (const field of ['traceparent', 'tracestate']) {
    const requestValue = firstHeaderValue(requestHeaders, field);
    const responseValue = firstHeaderValue(responseHeaders, field);
    add(field, requestValue || responseValue, `${requestValue ? 'requestHeaders' : 'responseHeaders'}.${field}`, 0);
  }

  const trace = {};
  const evidence = [];
  const conflicts = [];
  for (const [field, entries] of candidates) {
    entries.sort((left, right) => left.priority - right.priority || left.source.localeCompare(right.source));
    const selected = entries[0];
    trace[field] = selected.value;
    const publicEntries = entries.map(({ priority: _priority, ...entry }) => ({
      ...entry,
      selected: entry.source === selected.source && entry.value === selected.value,
    }));
    evidence.push(...publicEntries);
    const distinct = new Set(entries.map((entry) => entry.value));
    if (distinct.size > 1) conflicts.push({ field: `traceContext.${field}`, evidence: publicEntries });
  }
  if (trace.session_id && !trace.conversation_id) trace.conversation_id = trace.session_id;
  return { trace, evidence, conflicts, errors };
}

function captureFileName(captureId) {
  if (Buffer.byteLength(`${captureId}.json`, 'utf8') <= 240) return `${captureId}.json`;
  return `${captureId.slice(0, 80)}-${sha256(Buffer.from(captureId, 'utf8'))}.json`;
}

function recoveryReceiptFileName(captureId, originalFailedFileSha256) {
  const stem = captureFileName(captureId).replace(/\.json$/, '');
  const suffix = `.${originalFailedFileSha256}.receipt.json`;
  if (Buffer.byteLength(`${stem}${suffix}`, 'utf8') <= 240) return `${stem}${suffix}`;
  return `${captureId.slice(0, 64)}-${sha256(Buffer.from(captureId, 'utf8')).slice(0, 16)}${suffix}`;
}

function recoveryReceiptKey(fileName, originalFailedFileSha256) {
  return `${fileName}\u0000${originalFailedFileSha256}`;
}

function validRecoveryReceipt(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (value.schema_version !== OUTBOX_RECOVERY_RECEIPT_SCHEMA
    || !validCaptureId(value.capture_id)
    || typeof value.original_failed_file_name !== 'string'
    || value.original_failed_file_name.length === 0
    || value.original_failed_file_name.includes('/')
    || (value.original_capture_id !== undefined && !validCaptureId(value.original_capture_id))
    || !SHA256_RE.test(String(value.original_failed_file_sha256 || ''))
    || !SHA256_RE.test(String(value.replay_record_sha256 || ''))
    || !Number.isSafeInteger(value.replay_record_bytes)
    || value.replay_record_bytes <= 0
    || typeof value.recorded_at !== 'string'
    || !value.relay || value.relay.durable !== true
    || value.relay.capture_id !== value.capture_id
    || !SHA256_RE.test(String(value.relay.raw_sha256 || ''))
    || !Number.isSafeInteger(value.relay.length)
    || value.relay.length <= 0
    || !Number.isSafeInteger(value.relay.segment_id)
    || value.relay.segment_id <= 0
    || !Number.isSafeInteger(value.relay.offset)
    || value.relay.offset < 0) {
    return false;
  }
  return true;
}

function openCapturePaths(directory, captureId) {
  const name = captureFileName(captureId).replace(/\.json$/, '');
  return {
    metadata: path.join(directory, `${name}.open.json`),
    request: path.join(directory, `${name}.request.bin`),
    response: path.join(directory, `${name}.response.bin`),
  };
}

async function readOptionalFile(file, missing = Buffer.alloc(0)) {
  try {
    return await fsp.readFile(file);
  } catch (error) {
    if (error.code === 'ENOENT') return missing;
    throw error;
  }
}

async function syncOptionalFile(file) {
  let handle;
  try {
    handle = await fsp.open(file, 'r');
    await handle.sync();
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  } finally {
    await handle?.close();
  }
}

async function removeCaptureFiles(files) {
  // Metadata remains the recovery anchor until both body removals are durable.
  await Promise.all([files.request, files.response].map(file => fsp.rm(file, { force: true })));
  await fsyncDirectory(path.dirname(files.metadata));
  await fsp.rm(files.metadata, { force: true });
  await fsyncDirectory(path.dirname(files.metadata));
}

function recoveryConflict(reason) {
  const error = new Error(`open Capture recovery conflict: ${reason}`);
  error.code = 'CAPTURE_ID_CONFLICT';
  return error;
}

function openCaptureReceipt(metadata, request, response) {
  for (const [side, bytes] of [['request', request], ['response', response]]) {
    if (!isUtf8(bytes)) {
      const error = new Error(`open Capture ${side} spool is not valid UTF-8; bytes retained`);
      error.code = 'CAPTURE_BODY_ENCODING';
      throw error;
    }
  }
  const proof = bytes => ({ bytes: bytes.length, sha256: sha256(bytes) });
  return { schema_version: 'chiptrace.open-capture-receipt.v1',
    metadata: proof(metadata), request: proof(request), response: proof(response) };
}

function prepareOpenCaptureRecord(record, sanitize) {
  const prepared = sanitizeCaptureRecord(record, sanitize);
  prepared.captureTransaction = { ...prepared.captureTransaction, openReceipt: {
    ...prepared.captureTransaction.openReceipt,
    stored: Object.fromEntries(['request', 'response'].map(side => [side, {
      bytes: prepared[`${side}BytesCaptured`], sha256: prepared[`${side}BodySha256`],
    }])),
  } };
  return prepared;
}

function verifyOpenCaptureReceipt(record, base, metadata, request, response) {
  const transaction = record?.captureTransaction;
  const receipt = transaction?.openReceipt;
  if (record?.captureId !== base.captureId || record.captureStage !== 'combined'
    || !['finalized', 'recovered_incomplete'].includes(transaction?.state)
    || !base.captureTransaction?.openedAt || transaction.openedAt !== base.captureTransaction.openedAt
    || receipt?.schema_version !== 'chiptrace.open-capture-receipt.v1') {
    throw recoveryConflict('stored record lacks a matching open receipt');
  }
  for (const field of ['recordType', 'sourceNamespace', 'method', 'inboundPath', 'proxiedPath', 'startedAt']) {
    if (base[field] !== undefined && !isDeepStrictEqual(base[field], record[field])) {
      throw recoveryConflict('stored ingress identity differs');
    }
  }
  for (const [field, value] of Object.entries(base.traceContext || {})) {
    if (!isDeepStrictEqual(value, record.traceContext?.[field])) {
      throw recoveryConflict('stored trace identity differs');
    }
  }
  const validProof = proof => proof && Number.isSafeInteger(proof.bytes) && proof.bytes >= 0
    && typeof proof.sha256 === 'string' && /^[a-f0-9]{64}$/.test(proof.sha256);
  if (!validProof(receipt.metadata) || receipt.metadata.bytes !== metadata.length
    || receipt.metadata.sha256 !== sha256(metadata)) {
    throw recoveryConflict('open metadata does not match the receipt');
  }
  for (const [side, bytes] of [['request', request], ['response', response]]) {
    const proof = receipt[side];
    if (!validProof(proof) || (bytes !== null
      && (proof.bytes !== bytes.length || proof.sha256 !== sha256(bytes)))) {
      throw recoveryConflict(`${side} spool does not match the receipt`);
    }
    const text = record[`${side}BodyText`];
    const stored = receipt.stored?.[side];
    if (typeof text !== 'string' || record[`${side}BytesCaptured`] !== Buffer.byteLength(text, 'utf8')
      || record[`${side}BodySha256`] !== sha256(text) || !validProof(stored)
      || stored.bytes !== record[`${side}BytesCaptured`] || stored.sha256 !== record[`${side}BodySha256`]) {
      throw recoveryConflict(`stored ${side} body metadata is inconsistent`);
    }
    if (proof.bytes !== record[`${side}BytesCaptured`] || proof.sha256 !== record[`${side}BodySha256`]) {
      // Explicit body redaction keeps the original hash. It cannot silently
      // authorize arbitrary changed bytes under a matching Capture ID.
      if (record.captureSanitization?.version !== 'chiptrace.capture-sanitization.v1'
        || record.captureSanitization.bodyRedacted !== true
        || record[`${side}BodyTextOriginalSha256`] !== proof.sha256) {
        throw recoveryConflict(`stored ${side} body does not match the receipt`);
      }
      if (bytes !== null && sanitizeBodyText(bytes.toString('utf8'), new Set()).value !== text) {
        throw recoveryConflict(`stored ${side} redaction does not match the spool`);
      }
    }
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function retryDelayMs(attempt, baseMs, maxMs, jitterPercent) {
  const exponent = Math.min(Math.max(attempt - 1, 0), 20);
  const base = Math.min(maxMs, baseMs * (2 ** exponent));
  const jitter = base * jitterPercent / 100;
  return Math.max(0, Math.round(base + ((Math.random() * 2 - 1) * jitter)));
}

function isRetryableStatus(status) {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

function relayReceiptError(payload, captureId, inputBytes, inputSha256) {
  if (payload?.ok !== true || payload.durable !== true || payload.local_durable !== true) {
    return 'Relay did not confirm local durability';
  }
  const input = payload.input_receipt;
  if (input?.schema_version !== 'chiptrace.capture-input-receipt.v1'
    || input.bytes !== inputBytes || input.sha256 !== inputSha256) {
    return 'Relay receipt does not match the transmitted bytes';
  }
  const capture = payload.capture;
  if (capture?.capture_id !== captureId || capture.durable !== true
    || typeof payload.duplicate !== 'boolean' || capture.duplicate !== payload.duplicate
    || capture.state !== (payload.duplicate ? 'duplicate' : 'accepted')) {
    return 'Relay Capture receipt identity or state is inconsistent';
  }
  if (typeof capture.raw_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(capture.raw_sha256)
    || !Number.isSafeInteger(capture.length) || capture.length <= 0
    || !Number.isSafeInteger(capture.segment_id) || capture.segment_id <= 0
    || !Number.isSafeInteger(capture.offset) || capture.offset < 0
    || !Number.isSafeInteger(capture.offset + capture.length)) {
    return 'Relay Capture receipt hash or WAL locator is invalid';
  }
  return null;
}

function redactText(text, redactedFields) {
  let value = String(text ?? '');
  const before = value;
  value = value.replace(BEARER_RE, (match) => {
    redactedFields.add('body.bearer');
    return 'Bearer [REDACTED]';
  });
  value = value.replace(SECRET_PREFIX_RE, () => {
    redactedFields.add('body.token_like');
    return '[REDACTED]';
  });
  return { value, changed: value !== before };
}

function redactJson(value, redactedFields, fieldPath = 'body') {
  if (Array.isArray(value)) {
    return value.map((item, index) => redactJson(item, redactedFields, `${fieldPath}[${index}]`));
  }
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string') return redactText(value, redactedFields).value;
    return value;
  }
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    const currentPath = `${fieldPath}.${key}`;
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (SENSITIVE_KEY_RE.test(key) || SENSITIVE_NORMALIZED_KEYS.has(normalizedKey)) {
      redactedFields.add(currentPath);
      output[key] = '[REDACTED]';
    } else {
      output[key] = redactJson(item, redactedFields, currentPath);
    }
  }
  return output;
}

function sanitizeBodyText(text, redactedFields) {
  const source = String(text ?? '');
  if (!source) return { value: source, changed: false };
  if (!SENSITIVE_BODY_CANDIDATE_RE.test(source)) return { value: source, changed: false };
  try {
    const parsed = JSON.parse(source);
    const sanitized = redactJson(parsed, redactedFields);
    const value = JSON.stringify(sanitized);
    return { value, changed: value !== source };
  } catch {
    return redactText(source, redactedFields);
  }
}

/**
 * Keep the capture contract tied to the bytes that are actually sent.  Body
 * redaction (and older outbox versions) can leave the declared byte count or
 * digest referring to a pre-redaction string.  Rust Relay intentionally
 * rejects that ambiguity, so normalize the metadata at the last safe point
 * before enqueue/delivery.  The original pre-redaction digest, when known,
 * is never replaced.
 */
function reconcileCaptureBodyMetadata(record) {
  const copy = { ...record };
  let changed = false;
  for (const [textField, bytesField, shaField] of [
    ['requestBodyText', 'requestBytesCaptured', 'requestBodySha256'],
    ['responseBodyText', 'responseBytesCaptured', 'responseBodySha256'],
  ]) {
    if (typeof copy[textField] !== 'string') continue;
    const text = copy[textField];
    const bytes = Buffer.from(text, 'utf8');
    const byteCount = bytes.length;
    const digest = sha256(bytes);
    if (copy[bytesField] !== byteCount) {
      copy[bytesField] = byteCount;
      changed = true;
    }
    if (copy[shaField] !== digest) {
      copy[shaField] = digest;
      changed = true;
    }
  }
  return { record: copy, changed };
}

function sanitizeHeaders(headers, redactedFields, prefix) {
  const output = {};
  for (const [key, value] of Object.entries(headers && typeof headers === 'object' ? headers : {})) {
    if (SENSITIVE_KEY_RE.test(key) || key.toLowerCase() === 'authorization') {
      redactedFields.add(`${prefix}.${key}`);
      continue;
    }
    output[key] = value;
  }
  return output;
}

/**
 * Redaction is deliberately limited to credentials and token-like values. It
 * never creates tool calls, statuses, IDs, schemas, or lifecycle events.
 */
function sanitizeCaptureRecord(record, sanitizeBodies = true) {
  const copy = {
    ...record,
    requestHeaders: { ...(record?.requestHeaders || {}) },
    responseHeaders: { ...(record?.responseHeaders || {}) },
  };
  const redactedFields = new Set();
  copy.requestHeaders = sanitizeHeaders(copy.requestHeaders, redactedFields, 'requestHeaders');
  copy.responseHeaders = sanitizeHeaders(copy.responseHeaders, redactedFields, 'responseHeaders');
  if (sanitizeBodies) {
    for (const field of ['requestBodyText', 'responseBodyText']) {
      if (copy[field] === undefined || copy[field] === null) continue;
      const original = String(copy[field]);
      const originalHash = sha256(Buffer.from(original, 'utf8'));
      const sanitized = sanitizeBodyText(original, redactedFields);
      copy[field] = sanitized.value;
      if (sanitized.changed && !copy[`${field}OriginalSha256`]) {
        copy[`${field}OriginalSha256`] = originalHash;
      }
    }
  }
  if (redactedFields.size) {
    copy.redactedBodyFields = [...redactedFields].sort();
    copy.captureSanitization = {
      version: 'chiptrace.capture-sanitization.v1',
      bodyRedacted: sanitizeBodies,
      fields: copy.redactedBodyFields,
    };
  }
  return reconcileCaptureBodyMetadata(copy).record;
}

async function fsyncDirectory(directory) {
  try {
    const handle = await fsp.open(directory, 'r');
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    // Some filesystems (and Windows) do not permit opening a directory. The
    // file itself has already been fsynced, so keep the portable behavior for
    // unsupported directory sync only; real I/O failures must reject the ACK.
    if (!['EINVAL', 'EISDIR', 'ENOTSUP', 'EPERM'].includes(error.code)) throw error;
  }
}

async function atomicWrite(file, bytes) {
  const temporary = `${file}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  const handle = await fsp.open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    // POSIX rename replaces an existing target, which would make concurrent
    // conflicting writes invisible. link() is an atomic create-if-absent on
    // the same filesystem and preserves the already-fsynced inode.
    await fsp.link(temporary, file);
    await fsp.rm(temporary, { force: false });
  } catch (error) {
    await fsp.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
  await fsyncDirectory(path.dirname(file));
}

async function moveNoReplace(source, target) {
  await fsp.link(source, target);
  await fsp.rm(source, { force: false });
  await fsyncDirectory(path.dirname(target));
  if (path.dirname(source) !== path.dirname(target)) await fsyncDirectory(path.dirname(source));
}

async function moveOrDeduplicate(source, target) {
  try {
    await moveNoReplace(source, target);
    return { duplicate: false };
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const [sourceBytes, targetBytes] = await Promise.all([
      fsp.readFile(source),
      fsp.readFile(target),
    ]);
    if (sha256(sourceBytes) !== sha256(targetBytes)) {
      const conflict = new Error(`outbox move conflict for ${path.basename(source)}`);
      conflict.code = 'CAPTURE_ID_CONFLICT';
      throw conflict;
    }
    await fsp.rm(source, { force: false });
    await fsyncDirectory(path.dirname(source));
    return { duplicate: true };
  }
}

async function listRegularFiles(directory, suffix = '.json', includeErrorMarkers = false) {
  let entries = [];
  try {
    entries = await fsp.readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  return entries
    .filter((entry) => entry.isFile()
      && (includeErrorMarkers || !entry.name.endsWith('.error.json'))
      && (!suffix || entry.name.endsWith(suffix)))
    .map((entry) => path.join(directory, entry.name))
    .sort();
}

async function listRegularFilesLimited(directory, suffix, limit, skip = () => false) {
  const files = [];
  let handle;
  try {
    handle = await fsp.opendir(directory);
    for await (const entry of handle) {
      if (!entry.isFile() || entry.name.endsWith('.error.json') || !entry.name.endsWith(suffix)
        || skip(entry.name)) continue;
      files.push(path.join(directory, entry.name));
      if (files.length >= limit) break;
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  } finally {
    await handle?.close().catch((error) => {
      if (error.code !== 'ERR_DIR_CLOSED') throw error;
    });
  }
  return files.sort();
}

class DurableCaptureTransaction {
  constructor(outbox, baseRecord, files, options, metadataBytes) {
    this.outbox = outbox;
    this.baseRecord = baseRecord;
    this.captureId = baseRecord.captureId;
    this.files = files;
    this.maxRequestBytes = positiveInteger(
      options.maxRequestBytes,
      256 * 1024 * 1024,
      1,
      Number.MAX_SAFE_INTEGER,
    );
    this.maxResponseBytes = positiveInteger(
      options.maxResponseBytes,
      384 * 1024 * 1024,
      1,
      Number.MAX_SAFE_INTEGER,
    );
    this.requestBytes = 0;
    this.responseBytes = 0;
    this.requestTruncated = false;
    this.responseTruncated = false;
    this.metadataReceipt = { bytes: metadataBytes.length, sha256: sha256(metadataBytes) };
    this.persistedBytes = metadataBytes.length;
    this.persistedFiles = 1;
    this.createdSpools = new Set();
    this.writeChain = Promise.resolve();
    this.writeError = null;
    this.closed = false;
  }

  appendRequest(chunk) {
    return this.#append('request', chunk, this.maxRequestBytes);
  }

  appendResponse(chunk) {
    return this.#append('response', chunk, this.maxResponseBytes);
  }

  #append(side, chunk, limit) {
    if (this.closed) return Promise.reject(new Error('capture transaction is closed'));
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const countField = `${side}Bytes`;
    const truncatedField = `${side}Truncated`;
    const remaining = Math.max(0, limit - this[countField]);
    const retained = bytes.subarray(0, remaining);
    this[countField] += retained.length;
    if (retained.length < bytes.length) this[truncatedField] = true;
    if (retained.length === 0) return this.writeChain;
    const file = this.files[side];
    this.writeChain = this.writeChain.then(() => this.outbox.withQueueMutation(async () => {
      if (this.writeError) return;
      await this.outbox.refreshFilesystemStats(false);
      const firstWrite = !this.createdSpools.has(side);
      const releaseCapacity = this.outbox.reserveQueueCapacity(retained.length, Number(firstWrite));
      try {
        await fsp.appendFile(file, retained, { mode: 0o600, flag: 'a' });
        if (firstWrite) {
          this.createdSpools.add(side);
          this.persistedFiles += 1;
          this.outbox.metrics.openFiles += 1;
        }
        this.persistedBytes += retained.length;
        this.outbox.metrics.openBytes += retained.length;
        this.outbox.metrics.queueBytes += retained.length;
        this.outbox.accountFilesystemAllocation(retained.length, Number(firstWrite));
      } finally {
        releaseCapacity();
      }
    })).catch((error) => {
      this.writeError ||= error;
      this.outbox.recordError(error);
    });
    return this.writeChain;
  }

  async finalize(fields = {}) {
    if (this.closed) throw new Error('capture transaction is closed');
    this.closed = true;
    try {
      await this.writeChain;
      if (this.writeError) throw this.writeError;
      return await this.outbox.withQueueMutation(() => this.finalizeRecord(fields));
    } catch (error) {
      this.writeError ||= error;
      this.outbox.recordError(error);
      throw error;
    }
  }

  async finalizeRecord(fields) {
    await Promise.all([
      syncOptionalFile(this.files.request),
      syncOptionalFile(this.files.response),
    ]);
    const [metadataBytes, requestBytes, responseBytes] = await Promise.all([
      fsp.readFile(this.files.metadata),
      readOptionalFile(this.files.request),
      readOptionalFile(this.files.response),
    ]);
    if (metadataBytes.length !== this.metadataReceipt.bytes
      || sha256(metadataBytes) !== this.metadataReceipt.sha256) {
      this.outbox.metrics.conflicts += 1;
      throw recoveryConflict('open metadata changed before finalization');
    }
    const openReceipt = openCaptureReceipt(metadataBytes, requestBytes, responseBytes);
    const record = {
      ...this.baseRecord,
      ...fields,
      captureId: this.captureId,
      captureStage: 'combined',
      requestBodyText: requestBytes.toString('utf8'),
      requestBytesCaptured: requestBytes.length,
      requestBodySha256: sha256(requestBytes),
      requestTruncated: this.requestTruncated || fields.requestTruncated === true,
      responseBodyText: responseBytes.toString('utf8'),
      responseBytesCaptured: responseBytes.length,
      responseBodySha256: sha256(responseBytes),
      responseTruncated: this.responseTruncated || fields.responseTruncated === true,
      captureTransaction: {
        state: 'finalized',
        openedAt: this.baseRecord.captureTransaction.openedAt,
        finalizedAt: new Date().toISOString(),
        openReceipt,
      },
    };
    const prepared = prepareOpenCaptureRecord(record, this.outbox.sanitize);
    try {
      verifyOpenCaptureReceipt(prepared,
        this.baseRecord, metadataBytes, requestBytes, responseBytes);
    } catch (error) {
      this.outbox.metrics.conflicts += 1;
      throw error;
    }
    const ack = await this.outbox.enqueue(prepared, {
      creditBytes: this.persistedBytes,
      creditFiles: this.persistedFiles,
      schedule: false,
    });
    await removeCaptureFiles(this.files);
    this.outbox.releaseOpenCapture(this, this.persistedBytes, this.persistedFiles);
    this.outbox.scheduleDrain(0);
    return ack;
  }
}

class DurableCaptureOutbox {
  constructor(options = {}) {
    this.root = path.resolve(String(options.root || '/var/lib/chiptrace/relay-shell-outbox'));
    this.pendingDir = path.join(this.root, 'pending');
    this.processingDir = path.join(this.root, 'processing');
    this.failedDir = path.join(this.root, 'failed');
    this.openDir = path.join(this.root, 'open');
    this.recoveryReceiptDir = path.join(this.root, 'recovery-receipts');
    this.relayUrl = String(options.relayUrl || '').replace(/\/$/, '');
    this.bearerToken = String(options.bearerToken || '').trim();
    this.maxBytes = positiveInteger(options.maxBytes, 10 * 1024 * 1024 * 1024, 1024 * 1024);
    this.maxFiles = positiveInteger(options.maxFiles, 100000, 1);
    this.minFreeBytes = positiveInteger(options.minFreeBytes, 5 * 1024 * 1024 * 1024, 0);
    this.minFreeFiles = positiveInteger(options.minFreeFiles, 10000, 0);
    this.concurrency = positiveInteger(options.concurrency, 8, 1, 128);
    this.maxInflightBytes = positiveInteger(
      options.maxInflightBytes,
      1024 * 1024 * 1024,
      1024 * 1024,
      Number.MAX_SAFE_INTEGER,
    );
    this.maxAttempts = positiveInteger(options.maxAttempts, 25, 20, 128);
    this.timeoutMs = positiveInteger(options.timeoutMs, 30000, 1, 300000);
    this.maxOpenAgeMs = positiveInteger(options.maxOpenAgeMs, 30 * 60 * 1000, 1000, 7 * 24 * 60 * 60 * 1000);
    this.retryBaseMs = positiveInteger(options.retryBaseMs, 250, 10, 60000);
    this.retryMaxMs = positiveInteger(options.retryMaxMs, 5000, this.retryBaseMs, 300000);
    this.retryJitterPercent = positiveInteger(options.retryJitterPercent, 20, 0, 50);
    // Wire bodies are training evidence. Mutating them breaks the declared
    // byte length and SHA-256, so body sanitization is disabled by default.
    this.sanitize = options.sanitize === undefined ? false : asBoolean(options.sanitize, false);
    this.onDurable = typeof options.onDurable === 'function' ? options.onDurable : null;
    this.onAttempt = typeof options.onAttempt === 'function' ? options.onAttempt : null;
    this.onRetry = typeof options.onRetry === 'function' ? options.onRetry : null;
    this.onFailure = typeof options.onFailure === 'function' ? options.onFailure : null;
    this.metrics = {
      startedAt: null,
      accepted: 0,
      duplicate: 0,
      durable: 0,
      retries: 0,
      attempts: 0,
      failed: 0,
      conflicts: 0,
      rejected: 0,
      pending: 0,
      processing: 0,
      openTransactions: 0,
      openFiles: 0,
      openBytes: 0,
      oldestOpenAt: null,
      oldestOpenAgeMs: 0,
      staleOpenTransactions: 0,
      failedFiles: 0,
      auxiliaryFiles: 0,
      // Files already present when the process starts are retained audit
      // evidence. They must not make a healthy, newly started submitter look
      // broken. Failures observed during this process are tracked separately.
      historicalFailedFiles: 0,
      historicalAuxiliaryFiles: 0,
      historicalFailedBytes: 0,
      unresolvedHistoricalFailedFiles: 0,
      recoveryReceiptFiles: 0,
      recoveryReceiptBytes: 0,
      recentFailedFiles: 0,
      recentAuxiliaryFiles: 0,
      recentFailureBytes: 0,
      stalledFiles: 0,
      queueBytes: 0,
      activeQueueBytes: 0,
      failedBytes: 0,
      inflightBytes: 0,
      filesystemFreeBytes: null,
      filesystemFreeFiles: null,
      lastAcceptedAt: null,
      lastDurableAt: null,
      lastRetryAt: null,
      lastError: null,
    };
    this.started = false;
    this.startPromise = null;
    this.closed = false;
    this.draining = false;
    this.drainPromise = null;
    this.wakeTimer = null;
    this.activeBytes = 0;
    this.reservedBytes = 0;
    this.reservedFiles = 0;
    this.filesystemCheckedAtMs = 0;
    this.attemptsByFile = new Map();
    this.queuedAtByName = new Map();
    this.openAtByName = new Map();
    this.openCaptures = new Map();
    this.failedEvidenceCache = new Map();
    this.historicalFailedEvidence = null;
    this.recoveryReceiptKeys = new Set();
    this.queueMutationVersion = 0;
    this.queueMutations = 0;
    this.queueIdlePromise = null;
    this.resolveQueueIdle = null;
  }

  beginQueueMutation() {
    if (this.queueMutations === 0) {
      this.queueIdlePromise = new Promise(resolve => { this.resolveQueueIdle = resolve; });
    }
    this.queueMutations += 1;
    this.queueMutationVersion += 1;
    return () => {
      this.queueMutationVersion += 1;
      this.queueMutations -= 1;
      if (this.queueMutations === 0) {
        this.resolveQueueIdle();
        this.queueIdlePromise = null;
        this.resolveQueueIdle = null;
      }
    };
  }

  async withQueueMutation(action) {
    const finish = this.beginQueueMutation();
    try { return await action(); } finally { finish(); }
  }

  async start() {
    if (this.started) return this.snapshot();
    if (this.startPromise) return this.startPromise;
    this.startPromise = this.startInternal();
    try {
      return await this.startPromise;
    } finally {
      this.startPromise = null;
    }
  }

  async startInternal() {
    this.closed = false;
    await Promise.all([
      fsp.mkdir(this.pendingDir, { recursive: true, mode: 0o700 }),
      fsp.mkdir(this.processingDir, { recursive: true, mode: 0o700 }),
      fsp.mkdir(this.failedDir, { recursive: true, mode: 0o700 }),
      fsp.mkdir(this.openDir, { recursive: true, mode: 0o700 }),
      fsp.mkdir(this.recoveryReceiptDir, { recursive: true, mode: 0o700 }),
    ]);
    await this.recoverPendingTemporaries();
    // A crash between claim and remote ACK leaves the file in processing.
    // Move it back before accepting new work; the no-replace link is atomic on
    // one filesystem.
    await this.withQueueMutation(async () => {
      for (const file of await listRegularFiles(this.processingDir)) {
        const target = path.join(this.pendingDir, path.basename(file));
        try {
          await moveOrDeduplicate(file, target);
        } catch (error) {
          this.recordError(error);
        }
      }
    });
    await this.refreshQueueStats();
    // Capture the immutable failed-file set before this process begins doing
    // new work. A retained file is resolved only by a matching persisted
    // recovery receipt; the source evidence itself is never removed.
    this.historicalFailedEvidence = new Map(this.failedEvidenceCache);
    this.metrics.historicalFailedFiles = this.metrics.failedFiles;
    this.metrics.historicalAuxiliaryFiles = this.metrics.auxiliaryFiles;
    this.metrics.historicalFailedBytes = this.metrics.failedBytes;
    // Mark the outbox started before recovery so recovered transactions can
    // reuse the same immutable enqueue path without recursively starting it.
    this.started = true;
    try {
      await this.recoverOpenCaptures();
    } catch (error) {
      this.started = false;
      this.recordError(error);
      throw error;
    }
    await this.refreshQueueStats();
    this.metrics.startedAt = new Date().toISOString();
    // A client killed mid-request leaves an open transaction behind.  Without
    // periodic recovery the gateway stays degraded until the next restart.
    const recoveryIntervalMs = Math.min(
      Math.max(Math.floor(this.maxOpenAgeMs / 2), 60_000),
      5 * 60_000,
    );
    this.recoveryTimer = setInterval(() => {
      if (this.closed) return;
      this.recoverOpenCaptures({ staleOnly: true }).catch(error => this.recordError(error));
    }, recoveryIntervalMs);
    if (typeof this.recoveryTimer.unref === 'function') this.recoveryTimer.unref();
    this.scheduleDrain(0);
    return this.snapshot();
  }

  async recoverPendingTemporaries() {
    return this.withQueueMutation(() => this.recoverPendingTemporariesInternal());
  }

  async recoverPendingTemporariesInternal() {
    for (const temporary of await listRegularFiles(this.pendingDir, '.tmp')) {
      let captureId = null;
      try {
        const bytes = await fsp.readFile(temporary);
        const record = JSON.parse(bytes.toString('utf8'));
        captureId = String(record.captureId || '');
        if (!validCaptureId(captureId)) throw new Error('temporary outbox file has invalid captureId');
        await moveOrDeduplicate(temporary, path.join(this.pendingDir, captureFileName(captureId)));
      } catch (error) {
        this.recordError(error);
        const digest = sha256(Buffer.from(path.basename(temporary))).slice(0, 16);
        const safeId = captureId && validCaptureId(captureId) ? captureId : `cap-invalid-${digest}`;
        const target = path.join(this.failedDir, `${captureFileName(safeId)}.recovery-${digest}.json`);
        try {
          await moveOrDeduplicate(temporary, target);
        } catch (moveError) {
          this.recordError(moveError);
        }
      }
    }
  }


  /**
   * Most recent evidence that an open Capture is still making progress.
   * The metadata start time alone is a poor liveness signal for long streams,
   * so the request/response spool mtimes and an explicit heartbeat win.
   */
  async openCaptureLastActivityMs(metadataFile, requestFile, responseFile, baseRecord) {
    const candidates = [];
    const heartbeat = Number(baseRecord?.captureTransaction?.heartbeatAtMs);
    if (Number.isFinite(heartbeat)) candidates.push(heartbeat);
    const startedAtMs = Date.parse(baseRecord?.startedAt || '');
    if (Number.isFinite(startedAtMs)) candidates.push(startedAtMs);
    for (const file of [metadataFile, requestFile, responseFile]) {
      try {
        candidates.push((await fsp.stat(file)).mtimeMs);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
    return candidates.length ? Math.max(...candidates) : 0;
  }

  async recoverOpenCaptures({ staleOnly = false } = {}) {
    return this.withQueueMutation(() => this.recoverOpenCapturesInternal({ staleOnly }));
  }

  async recoverOpenCapturesInternal({ staleOnly = false } = {}) {
    const metadataFiles = await listRegularFiles(this.openDir, '.open.json');
    for (const metadataFile of metadataFiles) {
      const stem = path.basename(metadataFile, '.open.json');
      const files = {
        metadata: metadataFile,
        request: path.join(this.openDir, `${stem}.request.bin`),
        response: path.join(this.openDir, `${stem}.response.bin`),
      };
      const metadataBytes = await fsp.readFile(metadataFile);
      let baseRecord;
      try { baseRecord = JSON.parse(metadataBytes.toString('utf8')); }
      catch {
        this.metrics.conflicts += 1;
        throw recoveryConflict('open metadata is not valid JSON');
      }
      const captureId = String(baseRecord.captureId || '');
      if (!validCaptureId(captureId)) throw new Error('open Capture has invalid captureId');
      if (staleOnly) {
        // Periodic recovery must never race an in-flight capture.  Startup
        // recovery (staleOnly=false) still finalizes every orphan because the
        // previous process cannot own any live transaction.
        //
        // Age alone is not enough: a long streaming request can legitimately
        // exceed maxOpenAgeMs. A transaction this process still owns is live by
        // definition, so it is never recovered. For orphaned files, use the
        // most recent evidence of progress (start, spool mtime, heartbeat)
        // instead of only the start time.
        if (this.openCaptures.has(captureId)) continue;
        const observedAtMs = await this.openCaptureLastActivityMs(
          metadataFile,
          files.request,
          files.response,
          baseRecord,
        );
        if (Date.now() - observedAtMs <= this.maxOpenAgeMs) continue;
      }
      const spoolStats = await Promise.all([files.request, files.response].map(async file => {
        try { return await fsp.stat(file); } catch (error) {
          if (error.code === 'ENOENT') return null;
          throw error;
        }
      }));
      const openBytes = metadataBytes.length + spoolStats.reduce((sum, stat) => sum + (stat?.size || 0), 0);
      const openFiles = 1 + spoolStats.filter(Boolean).length;
      const [request, response] = await Promise.all([
        readOptionalFile(files.request, null), readOptionalFile(files.response, null),
      ]);
      let existing = false;
      let existingHash;
      for (const file of await this.filesForCapture(captureId)) {
        let bytes;
        try { bytes = await fsp.readFile(file); } catch (error) {
          if (error.code === 'ENOENT') continue;
          throw error;
        }
        try {
          let record;
          try { record = JSON.parse(bytes.toString('utf8')); }
          catch { throw recoveryConflict('stored record is not valid JSON'); }
          verifyOpenCaptureReceipt(record, baseRecord, metadataBytes, request, response);
          const digest = sha256(bytes);
          if (existingHash && digest !== existingHash) {
            throw recoveryConflict('stored queue versions differ');
          }
          existingHash = digest;
          existing = true;
        } catch (error) {
          this.metrics.conflicts += 1;
          throw error;
        }
      }
      if (existing) {
        await removeCaptureFiles(files);
        this.releaseOpenFiles(files, openBytes, openFiles);
        continue;
      }
      const requestBytes = request || Buffer.alloc(0);
      const responseBytes = response || Buffer.alloc(0);
      const openReceipt = openCaptureReceipt(metadataBytes, requestBytes, responseBytes);
      const recoveredAt = new Date().toISOString();
      const record = {
        ...baseRecord,
        captureStage: 'combined',
        finishedAt: recoveredAt,
        requestBodyText: requestBytes.toString('utf8'),
        requestBytesCaptured: requestBytes.length,
        requestBodySha256: sha256(requestBytes),
        requestTruncated: true,
        responseBodyText: responseBytes.toString('utf8'),
        responseBytesCaptured: responseBytes.length,
        responseBodySha256: sha256(responseBytes),
        responseTruncated: true,
        upstreamResponseCompleted: false,
        clientResponseFinished: false,
        captureError: 'gateway process ended before Capture finalization',
        captureErrorCode: 'CHIPTRACE_GATEWAY_CRASH',
        captureTransaction: {
          state: 'recovered_incomplete',
          openedAt: baseRecord.captureTransaction?.openedAt || null,
          recoveredAt,
          openReceipt,
        },
      };
      await this.enqueue(prepareOpenCaptureRecord(record, this.sanitize), {
        creditBytes: openBytes,
        creditFiles: openFiles,
        schedule: false,
      });
      await removeCaptureFiles(files);
      this.releaseOpenFiles(files, openBytes, openFiles);
    }
  }

  async beginCapture(record, options = {}) {
    if (!this.started) await this.start();
    if (this.closed) throw new Error('capture outbox is closed');
    return this.withQueueMutation(() => this.beginCaptureRecord(record, options));
  }

  async beginCaptureRecord(record, options) {
    const captureId = String(record?.captureId || '');
    if (!validCaptureId(captureId)) {
      this.metrics.rejected += 1;
      throw new Error('captureId is invalid for outbox');
    }
    if (this.openCaptures.has(captureId) || await this.findExisting(captureId)) {
      this.metrics.conflicts += 1;
      const error = new Error(`captureId ${captureId} already exists`);
      error.code = 'CAPTURE_ID_CONFLICT';
      throw error;
    }
    const files = openCapturePaths(this.openDir, captureId);
    const openedAt = new Date().toISOString();
    const baseRecord = sanitizeCaptureRecord({
      ...record,
      captureId,
      recordType: 'api_snapshot',
      captureStage: 'ingress',
      captureTransaction: { state: 'open', openedAt },
    }, false);
    delete baseRecord.requestBodyText;
    delete baseRecord.responseBodyText;
    const bytes = Buffer.from(`${JSON.stringify(baseRecord)}\n`, 'utf8');
    await this.refreshFilesystemStats(false);
    const releaseCapacity = this.reserveQueueCapacity(bytes.length, 1);
    try {
      await atomicWrite(files.metadata, bytes);
      const transaction = new DurableCaptureTransaction(this, baseRecord, files, options, bytes);
      this.openCaptures.set(captureId, transaction);
      this.openAtByName.set(path.basename(files.metadata), Date.parse(openedAt));
      this.metrics.openTransactions += 1;
      this.metrics.openFiles += 1;
      this.metrics.openBytes += bytes.length;
      this.metrics.queueBytes += bytes.length;
      this.accountFilesystemAllocation(bytes.length, 1);
      return transaction;
    } catch (error) {
      this.metrics.rejected += 1;
      this.recordError(error);
      throw error;
    } finally {
      releaseCapacity();
    }
  }

  releaseOpenCapture(transaction, bytes, files) {
    if (this.openCaptures.get(transaction.captureId) === transaction) {
      this.openCaptures.delete(transaction.captureId);
    }
    this.releaseOpenFiles(transaction.files, bytes, files);
  }

  releaseOpenFiles(paths, bytes, files) {
    this.openAtByName.delete(path.basename(paths.metadata));
    this.metrics.openTransactions = Math.max(0, this.metrics.openTransactions - 1);
    this.metrics.openFiles = Math.max(0, this.metrics.openFiles - files);
    this.metrics.openBytes = Math.max(0, this.metrics.openBytes - bytes);
    this.metrics.queueBytes = Math.max(0, this.metrics.queueBytes - bytes);
    if (this.metrics.filesystemFreeBytes !== null) this.metrics.filesystemFreeBytes += bytes;
    if (this.metrics.filesystemFreeFiles !== null) this.metrics.filesystemFreeFiles += files;
  }

  async close() {
    this.closed = true;
    if (this.wakeTimer) clearTimeout(this.wakeTimer);
    this.wakeTimer = null;
    if (this.recoveryTimer) clearInterval(this.recoveryTimer);
    this.recoveryTimer = null;
  }

  recordError(error) {
    this.metrics.lastError = (error?.message || String(error)).slice(0, 500);
  }

  async filesForCapture(captureId) {
    const name = captureFileName(captureId);
    return [
      path.join(this.pendingDir, name),
      path.join(this.processingDir, name),
      path.join(this.failedDir, name),
    ];
  }

  async findExisting(captureId) {
    for (const file of await this.filesForCapture(captureId)) {
      try {
        const bytes = await fsp.readFile(file);
        return { file, bytes, hash: sha256(bytes) };
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
    return null;
  }

  async refreshQueueStats() {
    for (;;) {
      if (this.queueIdlePromise) await this.queueIdlePromise;
      const version = this.queueMutationVersion;
      const { metrics, queuedAtByName, openAtByName, errors } = await this.readQueueStats();
      // A directory scan is not an atomic filesystem snapshot. Publishing a
      // scan that overlaps enqueue, delivery or streaming can erase a live
      // counter update, miss a new file, or resurrect an acknowledged file.
      // Retry after mutations settle; never overwrite their current metrics.
      if (this.queueMutations !== 0 || version !== this.queueMutationVersion) continue;
      Object.assign(this.metrics, metrics);
      for (const error of errors) this.recordError(error);
      this.queuedAtByName = queuedAtByName;
      this.openAtByName = openAtByName;
      this.refreshOpenAgeMetrics();
      await this.refreshFilesystemStats(true);
      return this.metrics;
    }
  }

  async readQueueStats() {
    let bytes = 0;
    let activeQueueBytes = 0;
    let failedBytes = 0;
    let pending = 0;
    let processing = 0;
    let failedFiles = 0;
    let auxiliaryFiles = 0;
    let openFiles = 0;
    let openBytes = 0;
    let openTransactions = 0;
    const openAtByName = new Map();
    const queuedAtByName = new Map();
    const errors = [];
    for (const [directory, kind] of [
      [this.pendingDir, 'pending'],
      [this.processingDir, 'processing'],
      [this.failedDir, 'failed'],
    ]) {
      const files = await listRegularFiles(directory, '.json', kind === 'failed');
      for (const file of files) {
        try {
          const stat = await fsp.stat(file);
          bytes += stat.size;
          if (kind === 'pending') {
            pending += 1;
            activeQueueBytes += stat.size;
            queuedAtByName.set(path.basename(file), stat.mtimeMs);
          } else if (kind === 'processing') {
            processing += 1;
            activeQueueBytes += stat.size;
            queuedAtByName.set(path.basename(file), stat.mtimeMs);
          } else {
            failedBytes += stat.size;
            if (file.endsWith('.error.json')) {
              auxiliaryFiles += 1;
            } else {
              failedFiles += 1;
              const name = path.basename(file);
              const cached = this.failedEvidenceCache.get(name);
              if (cached && cached.size === stat.size && cached.mtimeMs === stat.mtimeMs) {
                continue;
              }
              try {
                const bytes = await fsp.readFile(file);
                this.failedEvidenceCache.set(name, {
                  fileName: name,
                  size: stat.size,
                  mtimeMs: stat.mtimeMs,
                  sha256: sha256(bytes),
                });
              } catch (readError) {
                if (readError.code !== 'ENOENT') errors.push(readError);
                this.failedEvidenceCache.set(name, {
                  fileName: name,
                  size: stat.size,
                  mtimeMs: stat.mtimeMs,
                  sha256: null,
                });
              }
            }
          }
        } catch (error) {
          if (error.code !== 'ENOENT') errors.push(error);
        }
      }
    }
    const recoveryReceiptFiles = await listRegularFiles(this.recoveryReceiptDir);
    let recoveryReceiptBytes = 0;
    const recoveryReceiptKeys = new Set();
    for (const file of recoveryReceiptFiles) {
      try {
        const bytes = await fsp.readFile(file);
        recoveryReceiptBytes += bytes.length;
        const receipt = JSON.parse(bytes.toString('utf8'));
        if (validRecoveryReceipt(receipt)) {
          recoveryReceiptKeys.add(recoveryReceiptKey(
            receipt.original_failed_file_name,
            receipt.original_failed_file_sha256,
          ));
        } else {
          errors.push(new Error('invalid recovery receipt'));
        }
      } catch (error) {
        errors.push(error);
      }
    }
    bytes += recoveryReceiptBytes;
    this.recoveryReceiptKeys = recoveryReceiptKeys;
    let unresolvedHistoricalFailedFiles = 0;
    if (this.historicalFailedEvidence) {
      for (const evidence of this.historicalFailedEvidence.values()) {
        if (!recoveryReceiptKeys.has(recoveryReceiptKey(evidence.fileName, evidence.sha256))) {
          unresolvedHistoricalFailedFiles += 1;
        }
      }
    }
    for (const file of await listRegularFiles(this.openDir, null, true)) {
      try {
        const stat = await fsp.stat(file);
        bytes += stat.size;
        openBytes += stat.size;
        openFiles += 1;
        if (file.endsWith('.open.json')) {
          openTransactions += 1;
          try {
            const metadata = JSON.parse(await fsp.readFile(file, 'utf8'));
            const openedAt = Date.parse(
              metadata.captureTransaction?.openedAt || metadata.startedAt || '',
            );
            if (Number.isFinite(openedAt)) openAtByName.set(path.basename(file), openedAt);
          } catch (error) {
            errors.push(error);
          }
        }
      } catch (error) {
        if (error.code !== 'ENOENT') errors.push(error);
      }
    }
    return {
      metrics: { queueBytes: bytes, activeQueueBytes, failedBytes, pending, processing,
        openTransactions, openFiles, openBytes, failedFiles, auxiliaryFiles,
        recoveryReceiptFiles: recoveryReceiptFiles.length,
        recoveryReceiptBytes,
        unresolvedHistoricalFailedFiles },
      queuedAtByName,
      openAtByName,
      errors,
    };
  }

  refreshOpenAgeMetrics() {
    let oldestOpenAtMs = null;
    let staleOpenTransactions = 0;
    const now = Date.now();
    for (const openedAtMs of this.openAtByName.values()) {
      if (oldestOpenAtMs === null || openedAtMs < oldestOpenAtMs) oldestOpenAtMs = openedAtMs;
      if (now - openedAtMs > this.maxOpenAgeMs) staleOpenTransactions += 1;
    }
    this.metrics.oldestOpenAt = oldestOpenAtMs === null
      ? null
      : new Date(oldestOpenAtMs).toISOString();
    this.metrics.oldestOpenAgeMs = oldestOpenAtMs === null
      ? 0
      : Math.max(0, now - oldestOpenAtMs);
    this.metrics.staleOpenTransactions = staleOpenTransactions;
  }

  async refreshFilesystemStats(force = false) {
    if (!force && Date.now() - this.filesystemCheckedAtMs < 1000) return;
    if (typeof fsp.statfs === 'function') {
      try {
        const stats = await fsp.statfs(this.root, { bigint: true });
        this.metrics.filesystemFreeBytes = Number(stats.bavail * stats.bsize);
        this.metrics.filesystemFreeFiles = Number(stats.ffree);
        this.filesystemCheckedAtMs = Date.now();
      } catch (error) {
        this.recordError(error);
      }
    }
  }

  async enqueue(record, options = {}) {
    if (!this.started) await this.start();
    if (this.closed) throw new Error('capture outbox is closed');
    return this.withQueueMutation(() => this.enqueueRecord(record, options));
  }

  reserveQueueCapacity(bytes, files, { creditBytes = 0, creditFiles = 0 } = {}) {
    const reject = (message, code) => {
      this.metrics.rejected += 1;
      const error = new Error(message);
      error.code = code;
      this.recordError(error);
      throw error;
    };
    // Finalization's logical queue credit does not free physical space yet:
    // the old spools must survive until the combined record is durable.
    if (this.metrics.filesystemFreeBytes !== null
      && this.metrics.filesystemFreeBytes - this.reservedBytes - bytes < this.minFreeBytes) {
      reject('capture outbox filesystem free-space cutoff reached', 'OUTBOX_DISK_PRESSURE');
    }
    if (this.metrics.filesystemFreeFiles !== null
      && this.metrics.filesystemFreeFiles - this.reservedFiles - files < this.minFreeFiles) {
      reject('capture outbox filesystem inode cutoff reached', 'OUTBOX_INODE_PRESSURE');
    }
    if (Math.max(0, this.metrics.queueBytes - creditBytes)
      + this.reservedBytes + bytes > this.maxBytes) {
      reject('capture outbox byte cap is full', 'OUTBOX_FULL');
    }
    if (this.metrics.pending + this.metrics.processing + this.metrics.failedFiles
      + this.metrics.auxiliaryFiles + this.metrics.openFiles + this.metrics.stalledFiles
      + this.metrics.recoveryReceiptFiles
      + this.reservedFiles - creditFiles + files > this.maxFiles) {
      reject('capture outbox file cap is full', 'OUTBOX_FULL');
    }
    // There must be no await between checking the shared limits and reserving
    // them. Opens, appends and regular enqueue all use this same accounting.
    this.reservedBytes += bytes;
    this.reservedFiles += files;
    return () => {
      this.reservedBytes -= bytes;
      this.reservedFiles -= files;
    };
  }

  accountFilesystemAllocation(bytes, files) {
    if (this.metrics.filesystemFreeBytes !== null) {
      this.metrics.filesystemFreeBytes = Math.max(0, this.metrics.filesystemFreeBytes - bytes);
    }
    if (this.metrics.filesystemFreeFiles !== null) {
      this.metrics.filesystemFreeFiles = Math.max(0, this.metrics.filesystemFreeFiles - files);
    }
  }

  async enqueueRecord(record, options) {
    const captureId = String(record?.captureId || '');
    if (!validCaptureId(captureId)) {
      this.metrics.rejected += 1;
      throw new Error('captureId is invalid for outbox');
    }
    // Authentication material is never persisted. Body bytes remain unchanged
    // unless body sanitization was explicitly enabled.
    const prepared = sanitizeCaptureRecord(record, this.sanitize);
    const bytes = Buffer.from(`${JSON.stringify(prepared)}\n`, 'utf8');
    const digest = sha256(bytes);
    const creditBytes = Math.max(0, Number(options.creditBytes) || 0);
    const creditFiles = Math.max(0, Number(options.creditFiles) || 0);
    const existing = await this.findExisting(captureId);
    if (existing) {
      if (existing.hash !== digest) {
        this.metrics.conflicts += 1;
        const error = new Error(`captureId ${captureId} already exists with different bytes`);
        error.code = 'CAPTURE_ID_CONFLICT';
        throw error;
      }
      this.metrics.duplicate += 1;
      return { durable: true, duplicate: true, captureId, bytes: existing.bytes.length };
    }
    await this.refreshFilesystemStats(false);
    if (bytes.length > this.maxInflightBytes) {
      this.metrics.rejected += 1;
      const error = new Error('capture exceeds outbox in-flight byte budget');
      error.code = 'OUTBOX_RECORD_TOO_LARGE';
      throw error;
    }
    const target = path.join(this.pendingDir, captureFileName(captureId));
    const releaseCapacity = this.reserveQueueCapacity(bytes.length, 1, { creditBytes, creditFiles });
    try {
      await atomicWrite(target, bytes);
    } catch (error) {
      if (error.code === 'EEXIST') {
        const raced = await this.findExisting(captureId);
        if (raced?.hash === digest) {
          this.metrics.duplicate += 1;
          return { durable: true, duplicate: true, captureId, bytes: raced.bytes.length };
        }
        this.metrics.conflicts += 1;
        const conflict = new Error(`captureId ${captureId} raced with different bytes`);
        conflict.code = 'CAPTURE_ID_CONFLICT';
        throw conflict;
      }
      this.metrics.rejected += 1;
      this.recordError(error);
      throw error;
    } finally {
      releaseCapacity();
    }
    this.metrics.accepted += 1;
    this.metrics.pending += 1;
    this.metrics.queueBytes += bytes.length;
    this.metrics.activeQueueBytes += bytes.length;
    this.queuedAtByName.set(path.basename(target), Date.now());
    this.accountFilesystemAllocation(bytes.length, 1);
    this.metrics.lastAcceptedAt = new Date().toISOString();
    if (options.schedule !== false) this.scheduleDrain(0);
    return { durable: true, duplicate: false, captureId, bytes: bytes.length };
  }

  scheduleDrain(delayMs = 0) {
    if (this.closed || !this.relayUrl || this.wakeTimer) return;
    this.wakeTimer = setTimeout(() => {
      this.wakeTimer = null;
      this.drain().catch((error) => this.recordError(error));
    }, Math.max(0, delayMs));
    this.wakeTimer.unref?.();
  }

  async drain() {
    if (this.closed || this.draining || !this.relayUrl) return;
    this.drainPromise = (async () => {
      this.draining = true;
      let idle = true;
      try {
        const cleanupPending = name => this.openAtByName.has(name.replace(/\.json$/, '.open.json'));
        const files = await listRegularFilesLimited(this.pendingDir, '.json', this.concurrency, cleanupPending);
        const jobs = [];
        for (const file of files) {
          if (cleanupPending(path.basename(file))) continue;
          if (jobs.length >= this.concurrency) break;
          let reservedBytes;
          try {
            reservedBytes = (await fsp.stat(file)).size;
          } catch (error) {
            if (error.code !== 'ENOENT') this.recordError(error);
            continue;
          }
          if (this.activeBytes > 0 && this.activeBytes + reservedBytes > this.maxInflightBytes) break;
          const claimed = path.join(this.processingDir, path.basename(file));
          const finishClaim = this.beginQueueMutation();
          try {
            await moveOrDeduplicate(file, claimed);
            this.metrics.pending = Math.max(0, this.metrics.pending - 1);
            this.metrics.processing += 1;
            this.activeBytes += reservedBytes;
            this.metrics.inflightBytes = this.activeBytes;
          } catch (error) {
            if (error.code !== 'ENOENT') this.recordError(error);
            continue;
          } finally {
            finishClaim();
          }
          let finishTransition;
          const beforeQueueChange = () => {
            finishTransition ||= this.beginQueueMutation();
          };
          const job = this.deliverFile(claimed, beforeQueueChange)
            .catch(async (error) => {
              this.recordError(error);
              beforeQueueChange();
              await this.restoreClaimAfterError(claimed);
            })
            .finally(() => {
              beforeQueueChange();
              this.activeBytes = Math.max(0, this.activeBytes - reservedBytes);
              this.metrics.inflightBytes = this.activeBytes;
              this.metrics.processing = Math.max(0, this.metrics.processing - 1);
              finishTransition();
            });
          jobs.push(job);
        }
        if (jobs.length) {
          idle = false;
          await Promise.all(jobs);
        }
      } finally {
        this.draining = false;
        if (!this.closed && this.metrics.pending > 0) {
          this.scheduleDrain(this.metrics.lastError || idle ? this.retryBaseMs : 0);
        }
      }
    })();
    try {
      await this.drainPromise;
    } finally {
      this.drainPromise = null;
    }
  }

  async restoreClaimAfterError(file) {
    try {
      await fsp.access(file, fs.constants.F_OK);
    } catch (error) {
      if (error.code !== 'ENOENT') this.recordError(error);
      return;
    }
    try {
      await moveOrDeduplicate(file, path.join(this.pendingDir, path.basename(file)));
      this.metrics.pending += 1;
    } catch (error) {
      this.metrics.stalledFiles += 1;
      this.recordError(error);
    }
  }

  async writeRecoveryReceipt(record, inputSha256, inputBytes, payload) {
    const recovery = record?.outboxRecovery;
    if (!recovery || recovery.schema_version !== FAILED_OUTBOX_RECOVERY_SCHEMA) return null;
    const originalFailedFileSha256 = String(recovery.original_failed_file_sha256 || '');
    if (!SHA256_RE.test(originalFailedFileSha256)) {
      const error = new Error('outbox recovery record has an invalid original failed-file hash');
      error.code = 'CAPTURE_RECOVERY_RECEIPT_INVALID';
      throw error;
    }
    const captureId = String(record.captureId || '');
    const capture = payload?.capture;
    if (recovery.replay_capture_id !== undefined
      && recovery.replay_capture_id !== captureId) {
      const error = new Error('outbox recovery replay Capture ID does not match record');
      error.code = 'CAPTURE_RECOVERY_RECEIPT_INVALID';
      throw error;
    }
    if (recovery.original_capture_id !== undefined
      && !validCaptureId(recovery.original_capture_id)) {
      const error = new Error('outbox recovery original Capture ID is invalid');
      error.code = 'CAPTURE_RECOVERY_RECEIPT_INVALID';
      throw error;
    }
    const originalFailedFileName = String(
      recovery.original_failed_file_name || captureFileName(captureId),
    );
    if (!originalFailedFileName || originalFailedFileName.includes('/')) {
      const error = new Error('outbox recovery record has an invalid original failed-file name');
      error.code = 'CAPTURE_RECOVERY_RECEIPT_INVALID';
      throw error;
    }
    const receipt = {
      schema_version: OUTBOX_RECOVERY_RECEIPT_SCHEMA,
      capture_id: captureId,
      original_capture_id: validCaptureId(recovery.original_capture_id)
        ? recovery.original_capture_id : captureId,
      original_failed_file_name: originalFailedFileName,
      original_failed_file_sha256: originalFailedFileSha256,
      replay_record_sha256: inputSha256,
      replay_record_bytes: inputBytes.length,
      original_failure_reason: typeof recovery.original_failure_reason === 'string'
        ? recovery.original_failure_reason.slice(0, 200) : null,
      normalized_at: typeof recovery.normalized_at === 'string' ? recovery.normalized_at : null,
      recorded_at: new Date().toISOString(),
      relay: {
        durable: true,
        duplicate: payload.duplicate === true,
        capture_id: capture.capture_id,
        raw_sha256: capture.raw_sha256,
        length: capture.length,
        segment_id: capture.segment_id,
        offset: capture.offset,
      },
    };
    if (!validRecoveryReceipt(receipt)) {
      const error = new Error('Relay recovery receipt fields are invalid');
      error.code = 'CAPTURE_RECOVERY_RECEIPT_INVALID';
      throw error;
    }
    const bytes = Buffer.from(`${JSON.stringify(receipt)}\n`, 'utf8');
    const target = path.join(
      this.recoveryReceiptDir,
      recoveryReceiptFileName(captureId, originalFailedFileSha256),
    );
    let created = false;
    try {
      await atomicWrite(target, bytes);
      created = true;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const existing = await fsp.readFile(target);
      let sameReceipt = isDeepStrictEqual(existing, bytes);
      if (!sameReceipt) {
        try {
          const existingReceipt = JSON.parse(existing.toString('utf8'));
          const comparable = { ...receipt, recorded_at: existingReceipt.recorded_at };
          sameReceipt = isDeepStrictEqual(existingReceipt, comparable);
        } catch {
          sameReceipt = false;
        }
      }
      if (!sameReceipt) {
        const conflict = new Error('recovery receipt already exists with different bytes');
        conflict.code = 'CAPTURE_RECOVERY_RECEIPT_CONFLICT';
        throw conflict;
      }
    }
    if (created) {
      this.metrics.recoveryReceiptFiles += 1;
      this.metrics.recoveryReceiptBytes += bytes.length;
      this.metrics.queueBytes += bytes.length;
      this.accountFilesystemAllocation(bytes.length, 1);
    }
    this.recoveryReceiptKeys.add(recoveryReceiptKey(
      originalFailedFileName,
      originalFailedFileSha256,
    ));
    if (this.historicalFailedEvidence) {
      let unresolved = 0;
      for (const evidence of this.historicalFailedEvidence.values()) {
        if (!this.recoveryReceiptKeys.has(recoveryReceiptKey(evidence.fileName, evidence.sha256))) {
          unresolved += 1;
        }
      }
      this.metrics.unresolvedHistoricalFailedFiles = unresolved;
    }
    return receipt;
  }

  async deliverFile(file, beforeQueueChange) {
    let bytes;
    let record;
    let storedBytesLength = 0;
    let captureId = path.basename(file, '.json');
    try {
      bytes = await fsp.readFile(file);
      storedBytesLength = bytes.length;
      record = JSON.parse(bytes.toString('utf8'));
      captureId = String(record.captureId || captureId);
      if (!validCaptureId(captureId)) throw new Error('outbox file has invalid captureId');
      const reconciled = reconcileCaptureBodyMetadata(record);
      if (reconciled.changed) {
        // Repair in memory so the original failed file remains untouched as
        // audit evidence. A successful ACK removes only the replay copy.
        bytes = Buffer.from(`${JSON.stringify(reconciled.record)}\n`, 'utf8');
      }
    } catch (error) {
      beforeQueueChange();
      this.metrics.failed += 1;
      this.recordError(error);
      await this.moveFailed(file, 'invalid_record', storedBytesLength || bytes?.length);
      return;
    }

    const inputSha256 = sha256(bytes);
    let lastError = null;
    const currentAttempt = this.attemptsByFile.get(file) || 0;
    for (let offset = 1; offset <= this.maxAttempts; offset += 1) {
      const attempt = currentAttempt + offset;
      this.metrics.attempts += 1;
      this.onAttempt?.({ captureId, attempt });
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const response = await fetch(`${this.relayUrl}/capture`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...(this.bearerToken ? { authorization: `Bearer ${this.bearerToken}` } : {}),
          },
          body: bytes,
          signal: controller.signal,
        });
        const text = await response.text();
        let payload = {};
        try {
          payload = text ? JSON.parse(text) : {};
        } catch {
          payload = {};
        }
        const receiptError = relayReceiptError(payload, captureId, bytes.length, inputSha256);
        if (response.ok && receiptError === null) {
          beforeQueueChange();
          await this.writeRecoveryReceipt(record, inputSha256, bytes, payload);
          await fsp.rm(file, { force: false });
          await fsyncDirectory(this.processingDir);
          this.metrics.durable += 1;
          this.metrics.queueBytes = Math.max(0, this.metrics.queueBytes - storedBytesLength);
          this.metrics.activeQueueBytes = Math.max(0, this.metrics.activeQueueBytes - storedBytesLength);
          this.queuedAtByName.delete(path.basename(file));
          if (this.metrics.filesystemFreeBytes !== null) {
            this.metrics.filesystemFreeBytes += storedBytesLength;
          }
          if (this.metrics.filesystemFreeFiles !== null) {
            this.metrics.filesystemFreeFiles += 1;
          }
          this.metrics.lastDurableAt = new Date().toISOString();
          this.metrics.lastError = null;
          this.attemptsByFile.delete(file);
          this.onDurable?.({ captureId, duplicate: payload.duplicate === true });
          return;
        }
        const error = new Error(response.ok
          ? `Invalid Rust Relay acknowledgement: ${receiptError}`
          : `Rust Relay returned HTTP ${response.status} without durable acknowledgement`);
        error.status = response.status;
        error.retryable = response.ok || isRetryableStatus(response.status);
        lastError = error;
        if (!error.retryable) {
          beforeQueueChange();
          if (response.status === 409 || payload?.reason === 'capture_id_conflict') {
            this.metrics.conflicts += 1;
            this.onFailure?.({ captureId, reason: 'capture_id_conflict', error });
            await this.moveFailed(file, 'capture_id_conflict', storedBytesLength);
          } else {
            this.metrics.failed += 1;
            this.onFailure?.({ captureId, reason: `http_${response.status}`, error });
            await this.moveFailed(file, `http_${response.status}`, storedBytesLength);
          }
          this.recordError(error);
          this.attemptsByFile.delete(file);
          return;
        }
      } catch (error) {
        lastError = error;
      } finally {
        clearTimeout(timer);
      }
      if (attempt < currentAttempt + this.maxAttempts) {
        this.metrics.retries += 1;
        this.metrics.lastRetryAt = new Date().toISOString();
        this.onRetry?.({ captureId, attempt, error: lastError });
        this.attemptsByFile.set(file, attempt);
        await sleep(retryDelayMs(attempt, this.retryBaseMs, this.retryMaxMs, this.retryJitterPercent));
      }
    }

    // Keep the record for a future process restart or scheduled retry. It is
    // never silently discarded after transient failures.
    this.recordError(lastError || new Error(`delivery failed for ${captureId}`));
    this.attemptsByFile.set(file, currentAttempt + this.maxAttempts);
    beforeQueueChange();
    try {
      await moveOrDeduplicate(file, path.join(this.pendingDir, path.basename(file)));
      // The common `finally` block accounts for the processing decrement.
      this.metrics.pending += 1;
    } catch (error) {
      throw new Error(`failed to return Capture to pending: ${error.message || String(error)}`, {
        cause: error,
      });
    }
  }

  async moveFailed(file, reason, sourceBytes = null) {
    const target = path.join(this.failedDir, `${path.basename(file, '.json')}.json`);
    try {
      const retainedBytes = Number.isFinite(sourceBytes)
        ? Number(sourceBytes)
        : (await fsp.stat(file)).size;
      const move = await moveOrDeduplicate(file, target);
      this.metrics.activeQueueBytes = Math.max(0, this.metrics.activeQueueBytes - retainedBytes);
      this.queuedAtByName.delete(path.basename(file));
      if (!move.duplicate) {
        this.metrics.failedFiles += 1;
        this.metrics.failedBytes += retainedBytes;
        this.metrics.recentFailedFiles += 1;
        this.metrics.recentFailureBytes += retainedBytes;
      } else {
        this.metrics.queueBytes = Math.max(0, this.metrics.queueBytes - retainedBytes);
      }
      const marker = `${target}.error.json`;
      const markerBytes = Buffer.from(`${JSON.stringify({
        captureId: path.basename(file, '.json'),
        reason,
        recordedAt: new Date().toISOString(),
      })}\n`, 'utf8');
      await atomicWrite(marker, markerBytes)
        .then(() => {
          this.metrics.auxiliaryFiles += 1;
          this.metrics.queueBytes += markerBytes.length;
          this.metrics.failedBytes += markerBytes.length;
          this.metrics.recentAuxiliaryFiles += 1;
          this.metrics.recentFailureBytes += markerBytes.length;
          if (this.metrics.filesystemFreeBytes !== null) {
            this.metrics.filesystemFreeBytes = Math.max(0, this.metrics.filesystemFreeBytes - markerBytes.length);
          }
          if (this.metrics.filesystemFreeFiles !== null) {
            this.metrics.filesystemFreeFiles = Math.max(0, this.metrics.filesystemFreeFiles - 1);
          }
        })
        .catch((error) => this.recordError(error));
    } catch (error) {
      throw new Error(`failed to retain permanent Capture error: ${error.message || String(error)}`, {
        cause: error,
      });
    }
  }

  async flush(timeoutMs = 5000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.drainPromise) await this.drainPromise.catch(() => {});
      else await this.drain();
      if (this.metrics.pending === 0 && this.metrics.processing === 0) return true;
      await sleep(10);
    }
    return false;
  }

  snapshot() {
    this.refreshOpenAgeMetrics();
    let openWriteFailures = 0;
    for (const transaction of this.openCaptures.values()) {
      if (transaction.writeError) openWriteFailures += 1;
    }
    let oldestQueuedAtMs = null;
    for (const queuedAtMs of this.queuedAtByName.values()) {
      if (oldestQueuedAtMs === null || queuedAtMs < oldestQueuedAtMs) {
        oldestQueuedAtMs = queuedAtMs;
      }
    }
    return {
      root: this.root,
      relayUrlConfigured: Boolean(this.relayUrl),
      maxBytes: this.maxBytes,
      maxFiles: this.maxFiles,
      minFreeBytes: this.minFreeBytes,
      minFreeFiles: this.minFreeFiles,
      concurrency: this.concurrency,
      maxInflightBytes: this.maxInflightBytes,
      maxAttempts: this.maxAttempts,
      maxOpenAgeMs: this.maxOpenAgeMs,
      openWriteFailures,
      openCaptureHealthy: this.started && openWriteFailures === 0 && this.metrics.staleOpenTransactions === 0
        && this.openAtByName.size === this.metrics.openTransactions,
      timeoutMs: this.timeoutMs,
      sanitize: this.sanitize,
      ...this.metrics,
      historicalFailureCount: this.metrics.historicalFailedFiles
        + this.metrics.historicalAuxiliaryFiles,
      unresolvedHistoricalFailureCount: this.metrics.unresolvedHistoricalFailedFiles,
      recoveryReceiptCount: this.metrics.recoveryReceiptFiles,
      recentFailureCount: this.metrics.recentFailedFiles
        + this.metrics.recentAuxiliaryFiles,
      currentFailureCount: this.metrics.recentFailedFiles
        + this.metrics.recentAuxiliaryFiles,
      oldestPendingAt: oldestQueuedAtMs === null
        ? null
        : new Date(oldestQueuedAtMs).toISOString(),
      oldestPendingAgeMs: oldestQueuedAtMs === null
        ? 0
        : Math.max(0, Date.now() - oldestQueuedAtMs),
    };
  }
}

module.exports = {
  DurableCaptureOutbox,
  ResponsesSseBoundaryTracker,
  codexTraceContextFromHeaders,
  reconcileCaptureBodyMetadata,
  sanitizeCaptureRecord,
  retryDelayMs,
  validateProviderCredential,
};
