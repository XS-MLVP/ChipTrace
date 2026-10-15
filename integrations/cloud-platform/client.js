'use strict';

const { setTimeout: delay } = require('node:timers/promises');

class ChipTraceClient {
  constructor({ baseUrl, token, fetchImpl = fetch }) {
    const url = new URL(baseUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('invalid platform URL');
    this.baseUrl = url.toString().replace(/\/$/, '');
    this.token = token;
    this.fetch = fetchImpl;
  }

  async request(route, { method = 'GET', body, signal, contentType = 'application/json' } = {}) {
    const response = await this.fetch(`${this.baseUrl}${route}`, {
      method, body, signal: signal || AbortSignal.timeout(30000), redirect: 'error',
      headers: { authorization: `Bearer ${this.token}`, 'content-type': contentType },
    });
    if (!response.ok) {
      const result = await response.json().catch(() => null);
      const error = new Error(result?.error?.message || `ChipTrace HTTP ${response.status}`);
      error.status = response.status;
      error.code = result?.error?.code;
      throw error;
    }
    return response;
  }

  async submit(job, options) { return (await this.request('/v1/jobs', { ...options, method: 'POST', body: JSON.stringify(job) })).json(); }
  async getJob(id, options) { return (await this.request(`/v1/jobs/${encodeURIComponent(id)}`, options)).json(); }
  async listJobs({ offset = 0, limit = 50, ...options } = {}) { return (await this.request(`/v1/jobs?offset=${offset}&limit=${limit}`, options)).json(); }
  async getTurns(id, options) { return (await this.streamTurns(id, options)).json(); }
  streamTurns(id, { offset = 0, limit = 50, ...options } = {}) { return this.request(`/v1/jobs/${encodeURIComponent(id)}/turns?offset=${offset}&limit=${limit}`, options); }
  downloadTurns(id, options) { return this.request(`/v1/jobs/${encodeURIComponent(id)}/turns.jsonl`, options); }
  downloadProjection(id, part, options) { return this.request(`/v1/jobs/${encodeURIComponent(id)}/projection/${encodeURIComponent(part)}`, options); }
  async putUsageLog(id, bytes, options) { return (await this.request(`/v1/usage/${encodeURIComponent(id)}`, { ...options, method: 'PUT', body: bytes, contentType: 'application/x-ndjson' })).json(); }
  download(id, file, options) { return this.request(`/v1/jobs/${encodeURIComponent(id)}/packages/${encodeURIComponent(file)}`, options); }

  async wait(id, { timeoutMs = 60 * 60 * 1000, intervalMs = 250, signal } = {}) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 24 * 60 * 60 * 1000
        || !Number.isSafeInteger(intervalMs) || intervalMs < 1 || intervalMs > timeoutMs) throw new Error('invalid wait limits');
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      signal?.throwIfAborted();
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error(`ChipTrace job ${id} did not finish within timeout`);
      const timeout = AbortSignal.timeout(Math.min(remaining, 30000));
      const job = await this.getJob(id, { signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
      if (['completed', 'failed'].includes(job.status)) return job;
      if (Date.now() >= deadline) throw new Error(`ChipTrace job ${id} did not finish within timeout`);
      await delay(Math.min(intervalMs, Math.max(1, deadline - Date.now())), undefined, { signal });
    }
  }
}

module.exports = { ChipTraceClient };
