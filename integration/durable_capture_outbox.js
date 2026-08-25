'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

class OutboxFullError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OutboxFullError';
    this.code = 'CAPTURE_OUTBOX_FULL';
  }
}

class CaptureConflictError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CaptureConflictError';
    this.code = 'CAPTURE_ID_CONFLICT';
  }
}

class DurableCaptureOutbox {
  constructor(options = {}) {
    if (!options.directory) throw new TypeError('directory is required');
    if (!options.url) throw new TypeError('url is required');
    this.directory = path.resolve(String(options.directory));
    this.pendingDirectory = path.join(this.directory, 'pending');
    this.failedDirectory = path.join(this.directory, 'failed');
    this.conflictDirectory = path.join(this.directory, 'conflicts');
    this.url = String(options.url).replace(/\/$/, '');
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') throw new TypeError('fetch implementation is required');
    this.maxItems = positiveInteger(options.maxItems, 8192);
    this.maxBytes = positiveInteger(options.maxBytes, 1024 * 1024 * 1024);
    this.concurrency = positiveInteger(options.concurrency, 4);
    this.requestTimeoutMs = positiveInteger(options.requestTimeoutMs, 30000);
    this.baseDelayMs = nonnegativeInteger(options.baseDelayMs, 250);
    this.maxDelayMs = nonnegativeInteger(options.maxDelayMs, 30000);
    this.fsync = options.fsync !== false;
    this.entries = new Map();
    this.queue = [];
    this.queued = new Set();
    this.inFlight = new Map();
    this.scheduled = new Map();
    this.pendingBytes = 0;
    this.closed = false;
    this.running = false;
    this.counters = {
      offered: 0,
      locallyPersisted: 0,
      localDuplicates: 0,
      localConflicts: 0,
      rejected: 0,
      recovered: 0,
      recoveryQuarantined: 0,
      deliveryAttempts: 0,
      retryAttempts: 0,
      remoteDurable: 0,
      remoteDuplicates: 0,
      remoteConflicts: 0,
      quarantined: 0,
    };
    this.lastError = null;
    this.lastPersistedAt = null;
    this.lastDeliveredAt = null;
    this.lastRetryAt = null;
    this._ensureDirectories();
    this._recover();
    if (options.autostart !== false) this.start();
  }

  start() {
    if (this.closed) throw new Error('capture outbox is closed');
    if (this.running) return;
    this.running = true;
    for (const entry of this.entries.values()) this._queueEntry(entry);
    this._pump();
  }

  enqueue(record) {
    this.counters.offered += 1;
    if (this.closed) return this._rejectOffer(new OutboxFullError('capture outbox is closed'));
    let captureId;
    let body;
    try {
      captureId = captureIdentity(record);
      body = Buffer.from(JSON.stringify(record));
    } catch (error) {
      return this._rejectOffer(error);
    }
    const bodySha256 = sha256(body);
    const existing = this.entries.get(captureId);
    if (existing) {
      if (existing.bodySha256 === bodySha256 && existing.bytes === body.length) {
        this.counters.localDuplicates += 1;
        return Promise.resolve({ captureId, localDurable: true, duplicate: true, bytes: body.length });
      }
      this.counters.localConflicts += 1;
      return Promise.reject(new CaptureConflictError(`captureId ${captureId} was reused with different bytes`));
    }
    if (this.entries.size >= this.maxItems || this.pendingBytes + body.length > this.maxBytes) {
      return this._rejectOffer(new OutboxFullError('capture outbox capacity is exhausted'));
    }

    const fileName = `${sha256(Buffer.from(captureId))}.json`;
    const target = path.join(this.pendingDirectory, fileName);
    const entry = { captureId, fileName, path: target, bytes: body.length, bodySha256, attempts: 0 };
    try {
      this._publishBody(entry, body);
    } catch (error) {
      if (error.code === 'EEXIST') {
        try {
          const onDisk = this._readEntry(target);
          if (onDisk.captureId === captureId && onDisk.bodySha256 === bodySha256) {
            this.entries.set(captureId, onDisk);
            this.pendingBytes += onDisk.bytes;
            this.counters.recovered += 1;
            this.counters.localDuplicates += 1;
            this._queueEntry(onDisk);
            this._pump();
            return Promise.resolve({ captureId, localDurable: true, duplicate: true, bytes: body.length });
          }
          this.counters.localConflicts += 1;
          return Promise.reject(new CaptureConflictError(`captureId ${captureId} conflicts with outbox bytes`));
        } catch (readError) {
          this.lastError = errorText(readError);
          return this._rejectOffer(readError);
        }
      }
      this.lastError = errorText(error);
      return this._rejectOffer(error);
    }
    this.entries.set(captureId, entry);
    this.pendingBytes += body.length;
    this.counters.locallyPersisted += 1;
    this.lastPersistedAt = new Date().toISOString();
    this._queueEntry(entry);
    this._pump();
    return Promise.resolve({ captureId, localDurable: true, duplicate: false, bytes: body.length });
  }

  snapshot() {
    const pendingItems = this.entries.size;
    const deliveryTerminal = (
      this.counters.remoteDurable + this.counters.remoteConflicts + this.counters.quarantined
    );
    return {
      ...this.counters,
      pendingItems,
      pendingBytes: this.pendingBytes,
      queued: this.queue.length,
      inFlight: this.inFlight.size,
      waitingRetry: this.scheduled.size,
      running: this.running && !this.closed,
      closed: this.closed,
      maxItems: this.maxItems,
      maxBytes: this.maxBytes,
      concurrency: this.concurrency,
      lastPersistedAt: this.lastPersistedAt,
      lastDeliveredAt: this.lastDeliveredAt,
      lastRetryAt: this.lastRetryAt,
      lastError: this.lastError,
      offerConservationOk: this.counters.offered === (
        this.counters.locallyPersisted
        + this.counters.localDuplicates
        + this.counters.localConflicts
        + this.counters.rejected
      ),
      deliveryConservationOk: (
        this.counters.recovered + this.counters.locallyPersisted
      ) === deliveryTerminal + pendingItems,
    };
  }

  async waitForEmpty(timeoutMs = 5000) {
    const deadline = Date.now() + Math.max(Number(timeoutMs), 0);
    while (this.entries.size || this.inFlight.size) {
      if (Date.now() >= deadline) throw new Error('capture outbox did not drain before timeout');
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }

  close() {
    this.closed = true;
    this.running = false;
    for (const timer of this.scheduled.values()) clearTimeout(timer);
    this.scheduled.clear();
    this.queue.length = 0;
    this.queued.clear();
  }

  _rejectOffer(error) {
    this.counters.rejected += 1;
    this.lastError = errorText(error);
    return Promise.reject(error);
  }

  _ensureDirectories() {
    for (const directory of [this.directory, this.pendingDirectory, this.failedDirectory, this.conflictDirectory]) {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      fs.chmodSync(directory, 0o700);
    }
  }

  _recover() {
    const names = fs.readdirSync(this.pendingDirectory).sort();
    const published = names.filter((name) => name.endsWith('.json'));
    const temporary = names.filter((name) => name.includes('.tmp'));
    for (const name of [...published, ...temporary]) {
      const source = path.join(this.pendingDirectory, name);
      try {
        const entry = this._readEntry(source);
        const targetName = `${sha256(Buffer.from(entry.captureId))}.json`;
        const target = path.join(this.pendingDirectory, targetName);
        if (source !== target) {
          if (fs.existsSync(target)) {
            const existing = this._readEntry(target);
            if (existing.bodySha256 !== entry.bodySha256 || existing.captureId !== entry.captureId) {
              this._moveFile(source, this.conflictDirectory, 'recovery-conflict');
              this.counters.recoveryQuarantined += 1;
              continue;
            }
            fs.unlinkSync(source);
          } else {
            fs.linkSync(source, target);
            if (this.fsync) fsyncDirectory(this.pendingDirectory);
            fs.unlinkSync(source);
          }
          entry.fileName = targetName;
          entry.path = target;
        }
        const prior = this.entries.get(entry.captureId);
        if (prior) {
          if (prior.bodySha256 !== entry.bodySha256) {
            this._moveFile(entry.path, this.conflictDirectory, 'recovery-conflict');
            this.counters.recoveryQuarantined += 1;
          }
          continue;
        }
        this.entries.set(entry.captureId, entry);
        this.pendingBytes += entry.bytes;
        this.counters.recovered += 1;
      } catch (error) {
        this.lastError = errorText(error);
        try {
          this._moveFile(source, this.failedDirectory, 'recovery-invalid');
        } catch (moveError) {
          this.lastError = errorText(moveError);
        }
        this.counters.recoveryQuarantined += 1;
      }
    }
  }

  _publishBody(entry, body) {
    const temporary = path.join(
      this.pendingDirectory,
      `${entry.fileName}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
    );
    let descriptor;
    try {
      descriptor = fs.openSync(temporary, 'wx', 0o600);
      let offset = 0;
      while (offset < body.length) offset += fs.writeSync(descriptor, body, offset, body.length - offset);
      if (this.fsync) fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      fs.linkSync(temporary, entry.path);
      if (this.fsync) fsyncDirectory(this.pendingDirectory);
      fs.unlinkSync(temporary);
    } catch (error) {
      if (descriptor !== undefined) fs.closeSync(descriptor);
      try { fs.unlinkSync(temporary); } catch {}
      throw error;
    }
  }

  _readEntry(filePath) {
    const body = fs.readFileSync(filePath);
    const value = JSON.parse(body.toString('utf8'));
    const captureId = captureIdentity(value);
    return {
      captureId,
      fileName: path.basename(filePath),
      path: filePath,
      bytes: body.length,
      bodySha256: sha256(body),
      attempts: 0,
    };
  }

  _queueEntry(entry) {
    if (!this.running || this.closed || this.queued.has(entry.captureId)
      || this.inFlight.has(entry.captureId) || this.scheduled.has(entry.captureId)) return;
    this.queue.push(entry);
    this.queued.add(entry.captureId);
  }

  _pump() {
    if (!this.running || this.closed) return;
    while (this.inFlight.size < this.concurrency && this.queue.length) {
      const entry = this.queue.shift();
      this.queued.delete(entry.captureId);
      if (!this.entries.has(entry.captureId)) continue;
      this.inFlight.set(entry.captureId, entry);
      this._deliver(entry).catch((error) => {
        this.lastError = errorText(error);
        this._retry(entry);
      }).finally(() => {
        this.inFlight.delete(entry.captureId);
        this._pump();
      });
    }
  }

  async _deliver(entry) {
    const body = fs.readFileSync(entry.path);
    if (body.length !== entry.bytes || sha256(body) !== entry.bodySha256) {
      this._quarantine(entry, this.failedDirectory, 'payload-changed');
      return;
    }
    this.counters.deliveryAttempts += 1;
    entry.attempts += 1;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    let response;
    try {
      response = await this.fetchImpl(`${this.url}/capture`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    const payload = await responseJson(response);
    if (response.status === 409) {
      this._quarantine(entry, this.conflictDirectory, 'remote-conflict', 'remoteConflicts');
      return;
    }
    if (response.ok && payload.ok === true && payload.durable === true) {
      this._remove(entry);
      this.counters.remoteDurable += 1;
      if (payload.duplicate) this.counters.remoteDuplicates += 1;
      this.lastDeliveredAt = new Date().toISOString();
      this.lastError = null;
      return;
    }
    const error = new Error(`capture collector returned HTTP ${response.status} without durable acknowledgement`);
    error.status = response.status;
    if (!isRetryableStatus(response.status)) {
      this.lastError = error.message;
      this._quarantine(entry, this.failedDirectory, `remote-http-${response.status}`);
      return;
    }
    throw error;
  }

  _retry(entry) {
    if (!this.entries.has(entry.captureId) || this.closed) return;
    this.counters.retryAttempts += 1;
    this.lastRetryAt = new Date().toISOString();
    const delay = backoffDelay(this.baseDelayMs, this.maxDelayMs, entry.attempts);
    const timer = setTimeout(() => {
      this.scheduled.delete(entry.captureId);
      this._queueEntry(entry);
      this._pump();
    }, delay);
    timer.unref?.();
    this.scheduled.set(entry.captureId, timer);
  }

  _remove(entry) {
    fs.unlinkSync(entry.path);
    if (this.fsync) fsyncDirectory(this.pendingDirectory);
    this.entries.delete(entry.captureId);
    this.pendingBytes -= entry.bytes;
  }

  _quarantine(entry, destination, reason, counter = 'quarantined') {
    this._moveFile(entry.path, destination, reason);
    this.entries.delete(entry.captureId);
    this.pendingBytes -= entry.bytes;
    this.counters[counter] += 1;
  }

  _moveFile(source, destination, reason) {
    const base = path.basename(source).replace(/\.tmp.*$/, '');
    let target = path.join(destination, `${base}.${reason}`);
    if (fs.existsSync(target)) target = `${target}.${Date.now()}.${crypto.randomBytes(3).toString('hex')}`;
    fs.renameSync(source, target);
    if (this.fsync) {
      fsyncDirectory(path.dirname(source));
      fsyncDirectory(destination);
    }
    return target;
  }
}

function captureIdentity(record) {
  const captureId = record && record.captureId;
  if (typeof captureId !== 'string' || !/^cap-[A-Za-z0-9._:-]+$/.test(captureId)) {
    throw new TypeError('captureId must match cap-[A-Za-z0-9._:-]+');
  }
  return captureId;
}

async function responseJson(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

function isRetryableStatus(status) {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

function backoffDelay(base, maximum, attempt) {
  return Math.min(maximum, base * (2 ** Math.max(attempt - 1, 0)));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, 'r');
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function errorText(error) {
  return String(error && (error.message || error)).slice(0, 500);
}

function positiveInteger(value, fallback) {
  const number = Number(value ?? fallback);
  if (!Number.isSafeInteger(number) || number <= 0) throw new TypeError('expected a positive integer');
  return number;
}

function nonnegativeInteger(value, fallback) {
  const number = Number(value ?? fallback);
  if (!Number.isSafeInteger(number) || number < 0) throw new TypeError('expected a nonnegative integer');
  return number;
}

module.exports = {
  CaptureConflictError,
  DurableCaptureOutbox,
  OutboxFullError,
  isRetryableStatus,
};
