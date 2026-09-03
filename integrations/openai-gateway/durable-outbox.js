'use strict';

// The relay shell is a long-lived proxy process.  This small outbox keeps the
// capture hand-off durable without making the request forwarding path wait for
// the Rust Relay.  Files are written to a temporary name, fsynced, and then
// linked into `pending`; a file is only removed after a conserved durable ACK.

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

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
      if (sanitized.changed) copy[`${field}OriginalSha256`] = originalHash;
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
  return copy;
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

async function listRegularFilesLimited(directory, suffix, limit) {
  const files = [];
  let handle;
  try {
    handle = await fsp.opendir(directory);
    for await (const entry of handle) {
      if (!entry.isFile() || entry.name.endsWith('.error.json') || !entry.name.endsWith(suffix)) continue;
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

class DurableCaptureOutbox {
  constructor(options = {}) {
    this.root = path.resolve(String(options.root || '/var/lib/chiptrace/relay-shell-outbox'));
    this.pendingDir = path.join(this.root, 'pending');
    this.processingDir = path.join(this.root, 'processing');
    this.failedDir = path.join(this.root, 'failed');
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
      failedFiles: 0,
      auxiliaryFiles: 0,
      // Files already present when the process starts are retained audit
      // evidence. They must not make a healthy, newly started submitter look
      // broken. Failures observed during this process are tracked separately.
      historicalFailedFiles: 0,
      historicalAuxiliaryFiles: 0,
      historicalFailedBytes: 0,
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
    ]);
    await this.recoverPendingTemporaries();
    // A crash between claim and remote ACK leaves the file in processing.
    // Move it back before accepting new work; the no-replace link is atomic on
    // one filesystem.
    for (const file of await listRegularFiles(this.processingDir)) {
      const target = path.join(this.pendingDir, path.basename(file));
      try {
        await moveOrDeduplicate(file, target);
      } catch (error) {
        this.recordError(error);
      }
    }
    await this.refreshQueueStats();
    this.metrics.historicalFailedFiles = this.metrics.failedFiles;
    this.metrics.historicalAuxiliaryFiles = this.metrics.auxiliaryFiles;
    this.metrics.historicalFailedBytes = this.metrics.failedBytes;
    this.metrics.startedAt = new Date().toISOString();
    this.started = true;
    this.scheduleDrain(0);
    return this.snapshot();
  }

  async recoverPendingTemporaries() {
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

  async close() {
    this.closed = true;
    if (this.wakeTimer) clearTimeout(this.wakeTimer);
    this.wakeTimer = null;
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
    let bytes = 0;
    let activeQueueBytes = 0;
    let failedBytes = 0;
    let pending = 0;
    let processing = 0;
    let failedFiles = 0;
    let auxiliaryFiles = 0;
    const queuedAtByName = new Map();
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
            if (file.endsWith('.error.json')) auxiliaryFiles += 1;
            else failedFiles += 1;
          }
        } catch (error) {
          if (error.code !== 'ENOENT') this.recordError(error);
        }
      }
    }
    this.metrics.queueBytes = bytes;
    this.metrics.activeQueueBytes = activeQueueBytes;
    this.metrics.failedBytes = failedBytes;
    this.metrics.pending = pending;
    this.metrics.processing = processing;
    this.metrics.failedFiles = failedFiles;
    this.metrics.auxiliaryFiles = auxiliaryFiles;
    this.queuedAtByName = queuedAtByName;
    await this.refreshFilesystemStats(true);
    return this.metrics;
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

  async enqueue(record) {
    if (!this.started) await this.start();
    if (this.closed) throw new Error('capture outbox is closed');
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
    if (this.metrics.filesystemFreeBytes !== null
      && this.metrics.filesystemFreeBytes - this.reservedBytes - bytes.length < this.minFreeBytes) {
      this.metrics.rejected += 1;
      const error = new Error('capture outbox filesystem free-space cutoff reached');
      error.code = 'OUTBOX_DISK_PRESSURE';
      throw error;
    }
    if (this.metrics.filesystemFreeFiles !== null
      && this.metrics.filesystemFreeFiles - this.reservedFiles - 1 < this.minFreeFiles) {
      this.metrics.rejected += 1;
      const error = new Error('capture outbox filesystem inode cutoff reached');
      error.code = 'OUTBOX_INODE_PRESSURE';
      throw error;
    }
    if (this.metrics.queueBytes + this.reservedBytes + bytes.length > this.maxBytes) {
      this.metrics.rejected += 1;
      const error = new Error('capture outbox byte cap is full');
      error.code = 'OUTBOX_FULL';
      throw error;
    }
    if (this.metrics.pending
      + this.metrics.processing
      + this.metrics.failedFiles
      + this.metrics.auxiliaryFiles
      + this.metrics.stalledFiles
      + this.reservedFiles >= this.maxFiles) {
      this.metrics.rejected += 1;
      const error = new Error('capture outbox file cap is full');
      error.code = 'OUTBOX_FULL';
      throw error;
    }
    if (bytes.length > this.maxInflightBytes) {
      this.metrics.rejected += 1;
      const error = new Error('capture exceeds outbox in-flight byte budget');
      error.code = 'OUTBOX_RECORD_TOO_LARGE';
      throw error;
    }
    const target = path.join(this.pendingDir, captureFileName(captureId));
    this.reservedBytes += bytes.length;
    this.reservedFiles += 1;
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
      this.reservedBytes = Math.max(0, this.reservedBytes - bytes.length);
      this.reservedFiles = Math.max(0, this.reservedFiles - 1);
    }
    this.metrics.accepted += 1;
    this.metrics.pending += 1;
    this.metrics.queueBytes += bytes.length;
    this.metrics.activeQueueBytes += bytes.length;
    this.queuedAtByName.set(path.basename(target), Date.now());
    if (this.metrics.filesystemFreeBytes !== null) {
      this.metrics.filesystemFreeBytes = Math.max(0, this.metrics.filesystemFreeBytes - bytes.length);
    }
    if (this.metrics.filesystemFreeFiles !== null) {
      this.metrics.filesystemFreeFiles = Math.max(0, this.metrics.filesystemFreeFiles - 1);
    }
    this.metrics.lastAcceptedAt = new Date().toISOString();
    this.scheduleDrain(0);
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
      try {
        const files = await listRegularFilesLimited(this.pendingDir, '.json', this.concurrency);
        const jobs = [];
        for (const file of files) {
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
          try {
            await moveOrDeduplicate(file, claimed);
          } catch (error) {
            if (error.code !== 'ENOENT') this.recordError(error);
            continue;
          }
          this.metrics.pending = Math.max(0, this.metrics.pending - 1);
          this.metrics.processing += 1;
          this.activeBytes += reservedBytes;
          this.metrics.inflightBytes = this.activeBytes;
          const job = this.deliverFile(claimed)
            .catch(async (error) => {
              this.recordError(error);
              await this.restoreClaimAfterError(claimed);
            })
            .finally(() => {
              this.activeBytes = Math.max(0, this.activeBytes - reservedBytes);
              this.metrics.inflightBytes = this.activeBytes;
              this.metrics.processing = Math.max(0, this.metrics.processing - 1);
            });
          jobs.push(job);
        }
        if (jobs.length) await Promise.all(jobs);
      } finally {
        this.draining = false;
        if (!this.closed && this.metrics.pending > 0) {
          this.scheduleDrain(this.metrics.lastError ? this.retryBaseMs : 0);
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

  async deliverFile(file) {
    let bytes;
    let captureId = path.basename(file, '.json');
    try {
      bytes = await fsp.readFile(file);
      const record = JSON.parse(bytes.toString('utf8'));
      captureId = String(record.captureId || captureId);
      if (!validCaptureId(captureId)) throw new Error('outbox file has invalid captureId');
    } catch (error) {
      this.metrics.failed += 1;
      this.recordError(error);
      await this.moveFailed(file, 'invalid_record', bytes?.length);
      return;
    }

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
        if (response.ok && payload.ok === true && payload.durable === true) {
          await fsp.rm(file, { force: false });
          await fsyncDirectory(this.processingDir);
          this.metrics.durable += 1;
          this.metrics.queueBytes = Math.max(0, this.metrics.queueBytes - bytes.length);
          this.metrics.activeQueueBytes = Math.max(0, this.metrics.activeQueueBytes - bytes.length);
          this.queuedAtByName.delete(path.basename(file));
          if (this.metrics.filesystemFreeBytes !== null) {
            this.metrics.filesystemFreeBytes += bytes.length;
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
        const error = new Error(`Rust Relay returned HTTP ${response.status} without durable acknowledgement`);
        error.status = response.status;
        error.retryable = isRetryableStatus(response.status);
        lastError = error;
        if (!error.retryable) {
          if (response.status === 409 || payload.reason === 'capture_id_conflict') {
            this.metrics.conflicts += 1;
            this.onFailure?.({ captureId, reason: 'capture_id_conflict', error });
            await this.moveFailed(file, 'capture_id_conflict', bytes.length);
          } else {
            this.metrics.failed += 1;
            this.onFailure?.({ captureId, reason: `http_${response.status}`, error });
            await this.moveFailed(file, `http_${response.status}`, bytes.length);
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
      timeoutMs: this.timeoutMs,
      sanitize: this.sanitize,
      ...this.metrics,
      historicalFailureCount: this.metrics.historicalFailedFiles
        + this.metrics.historicalAuxiliaryFiles,
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
  codexTraceContextFromHeaders,
  sanitizeCaptureRecord,
  retryDelayMs,
  validateProviderCredential,
};
