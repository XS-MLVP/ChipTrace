'use strict';

class QueueFullError extends Error {
  constructor(message) {
    super(message);
    this.name = 'QueueFullError';
    this.code = 'CAPTURE_QUEUE_FULL';
  }
}

class CaptureConflictError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CaptureConflictError';
    this.code = 'CAPTURE_ID_CONFLICT';
  }
}

class ReliableCaptureSubmitter {
  constructor(options = {}) {
    if (!options.url) throw new TypeError('url is required');
    this.url = String(options.url).replace(/\/$/, '');
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') throw new TypeError('fetch implementation is required');
    this.maxQueueItems = positiveInteger(options.maxQueueItems, 2048);
    this.maxQueueBytes = positiveInteger(options.maxQueueBytes, 1024 * 1024 * 1024);
    this.concurrency = positiveInteger(options.concurrency, 4);
    this.requestTimeoutMs = positiveInteger(options.requestTimeoutMs, 30000);
    this.maxAttempts = positiveInteger(options.maxAttempts, 5);
    this.baseDelayMs = nonnegativeInteger(options.baseDelayMs, 100);
    this.maxDelayMs = nonnegativeInteger(options.maxDelayMs, 5000);
    this.sleep = options.sleep || ((delay) => new Promise((resolve) => setTimeout(resolve, delay)));
    this.queue = [];
    this.inFlight = 0;
    this.retainedBytes = 0;
    this.closed = false;
    this.counters = {
      offered: 0,
      enqueued: 0,
      durable: 0,
      duplicates: 0,
      conflicts: 0,
      dropped: 0,
      retryAttempts: 0,
    };
  }

  submit(record) {
    this.counters.offered += 1;
    if (this.closed) {
      this.counters.dropped += 1;
      return Promise.reject(new QueueFullError('capture submitter is closed'));
    }
    let body;
    try {
      body = JSON.stringify(record);
    } catch (error) {
      this.counters.dropped += 1;
      return Promise.reject(error);
    }
    const bytes = Buffer.byteLength(body);
    if (
      this.queue.length + this.inFlight >= this.maxQueueItems
      || this.retainedBytes + bytes > this.maxQueueBytes
    ) {
      this.counters.dropped += 1;
      return Promise.reject(new QueueFullError('capture retry queue is full'));
    }
    this.counters.enqueued += 1;
    this.retainedBytes += bytes;
    return new Promise((resolve, reject) => {
      this.queue.push({ captureId: record && record.captureId, body, bytes, resolve, reject });
      this._pump();
    });
  }

  snapshot() {
    const terminal = this.counters.durable + this.counters.conflicts + this.counters.dropped;
    return {
      ...this.counters,
      queued: this.queue.length,
      inFlight: this.inFlight,
      retainedBytes: this.retainedBytes,
      conservationOk: this.counters.offered === terminal + this.queue.length + this.inFlight,
    };
  }

  close() {
    this.closed = true;
    while (this.queue.length) {
      const job = this.queue.shift();
      this.retainedBytes -= job.bytes;
      this.counters.dropped += 1;
      job.reject(new QueueFullError('capture submitter is closed'));
    }
  }

  _pump() {
    while (this.inFlight < this.concurrency && this.queue.length) {
      const job = this.queue.shift();
      this.inFlight += 1;
      this._run(job);
    }
  }

  async _run(job) {
    let result = null;
    let failure = null;
    try {
      result = await this._sendWithRetry(job);
    } catch (error) {
      failure = error;
    }
    this.inFlight -= 1;
    this.retainedBytes -= job.bytes;
    if (failure === null) {
      this.counters.durable += 1;
      if (result.duplicate) this.counters.duplicates += 1;
    } else if (failure instanceof CaptureConflictError) {
      this.counters.conflicts += 1;
    } else {
      this.counters.dropped += 1;
    }
    this._pump();
    if (failure === null) {
      job.resolve(result);
    } else {
      job.reject(failure);
    }
  }

  async _sendWithRetry(job) {
    let lastError = null;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
      try {
        const response = await this.fetchImpl(`${this.url}/capture`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: job.body,
          signal: controller.signal,
        });
        const payload = await responseJson(response);
        if (response.status === 409) {
          throw new CaptureConflictError(payload.detail || 'captureId conflict');
        }
        if (response.ok && payload.ok === true && payload.durable === true) {
          return {
            captureId: job.captureId,
            duplicate: Boolean(payload.duplicate),
            attempts: attempt,
          };
        }
        const error = new Error(`capture collector returned HTTP ${response.status}`);
        error.status = response.status;
        error.retryable = isRetryableStatus(response.status);
        throw error;
      } catch (error) {
        lastError = error;
        if (error instanceof CaptureConflictError) throw error;
        if (error.retryable === false || (error.status && !isRetryableStatus(error.status))) throw error;
      } finally {
        clearTimeout(timer);
      }
      if (attempt < this.maxAttempts) {
        this.counters.retryAttempts += 1;
        await this.sleep(backoffDelay(this.baseDelayMs, this.maxDelayMs, attempt));
      }
    }
    throw lastError || new Error('capture submission failed');
  }
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
  QueueFullError,
  ReliableCaptureSubmitter,
  isRetryableStatus,
};
