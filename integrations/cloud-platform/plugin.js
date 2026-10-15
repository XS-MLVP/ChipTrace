'use strict';

const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { isDeepStrictEqual } = require('node:util');
const readline = require('node:readline');

const PROJECTION_PARTS = Object.freeze({
  manifest: { file: 'manifest.json', contentType: 'application/json; charset=utf-8' },
  interactions: { file: 'interactions/model-interactions.jsonl.zst', contentType: 'application/zstd' },
  runtime: { file: 'runtime/runtime-spans.jsonl.zst', contentType: 'application/zstd' },
  links: { file: 'links/interaction-links.jsonl.zst', contentType: 'application/zstd' },
});

class PlatformError extends Error {
  constructor(message, status = 400, code = 'INVALID_REQUEST') {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function component(value, field) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/.test(value)) {
    throw new PlatformError(`${field} must be a nonempty ASCII identifier`);
  }
  return value;
}

function integer(value, fallback, minimum, maximum) {
  const number = value ?? fallback;
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw new PlatformError('invalid platform resource limit');
  }
  return number;
}

function sourceContextReady(audit, sessionId) {
  if (audit?.schema_version !== 'chiptrace.source-context-audit.v2'
      || audit.session_id !== sessionId || audit.unscoped_otlp_records !== 0) return false;
  const fields = ['turn_assigned_records', 'session_level_records', 'process_level_records',
    'unscoped_turn_records', 'other_session_records', 'unknown_session_records'];
  return ['otlp_logs', 'otlp_traces'].every(source => {
    const counts = audit.sources?.[source];
    if (!counts || !['total_records', ...fields].every(field => Number.isSafeInteger(counts[field]) && counts[field] >= 0)) return false;
    const total = fields.reduce((sum, field) => sum + counts[field], 0);
    return Number.isSafeInteger(total) && total === counts.total_records
      && counts.unscoped_turn_records === 0 && counts.unknown_session_records === 0;
  });
}

async function syncDirectory(directory) {
  const handle = await fsp.open(directory, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}

async function durableWrite(file, value, createOnly = false) {
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(`${JSON.stringify(value)}\n`);
  try {
    const handle = await fsp.open(temporary, 'wx', 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
    if (createOnly) await fsp.link(temporary, file);
    else await fsp.rename(temporary, file);
    await syncDirectory(path.dirname(file));
  } finally {
    await fsp.unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}

async function safeDirectory(directory) {
  await fsp.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await fsp.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new PlatformError('platform directory must not be a symbolic link', 503, 'CORRUPT_STATE');
}

function decodeUtf8(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new PlatformError('body must be valid UTF-8'); }
}

function projectionMetadata(value, manifest = null) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.parts)) return null;
  const parts = value.parts.map(part => ({
    file: part.file,
    bytes: part.bytes,
    records: part.records ?? null,
    sha256: part.sha256,
    uncompressed_bytes: part.uncompressed_bytes ?? null,
  }));
  if (parts.some(part => typeof part.file !== 'string' || !Number.isSafeInteger(part.bytes)
      || typeof part.sha256 !== 'string')) return null;
  const metadata = {
    schema_version: value.schema_version,
    session_id: value.session_id ?? null,
    interactions: value.interactions,
    runtime_spans: value.runtime_spans,
    links: value.links,
    parts,
  };
  if (manifest) metadata.manifest = manifest;
  return metadata;
}

async function fileDigest(file) {
  const handle = await fsp.open(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new PlatformError('engine artifact is not a regular file', 502, 'ENGINE_PROTOCOL');
    const digest = crypto.createHash('sha256');
    const buffer = Buffer.alloc(64 * 1024);
    let bytes = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, bytes);
      if (!bytesRead) break;
      digest.update(buffer.subarray(0, bytesRead));
      bytes += bytesRead;
    }
    return { bytes, sha256: digest.digest('hex') };
  } finally { await handle.close(); }
}

function engineTurnEvidence(session, evidence) {
  if (session?.turns !== undefined || !evidence
      || !Number.isSafeInteger(evidence.records) || evidence.records < 0 || evidence.records !== session?.native_turns
      || !Number.isSafeInteger(evidence.bytes) || evidence.bytes < 0
      || typeof evidence.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(evidence.sha256)) {
    throw new PlatformError('invalid engine Turn evidence descriptor', 502, 'ENGINE_PROTOCOL');
  }
  return { records: evidence.records, bytes: evidence.bytes, sha256: evidence.sha256 };
}

function normalizeRequest(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PlatformError('job must be an object');
  const allowed = new Set(['id', 'kind', 'archive_id', 'session_id', 'release_id', 'usage_log_ids']);
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new PlatformError(`unsupported job field: ${key}`);
  const request = {
    id: component(input.id, 'id'),
    kind: input.kind,
    archive_id: component(input.archive_id, 'archive_id'),
  };
  if (!['archive', 'restore', 'inspect', 'export'].includes(input.kind)) throw new PlatformError('unknown job kind');
  if (['inspect', 'export'].includes(input.kind)) {
    request.session_id = component(input.session_id, 'session_id');
  } else if (input.session_id !== undefined) throw new PlatformError('session_id is only valid for inspect/export');
  if (input.kind === 'export') {
    request.release_id = component(input.release_id, 'release_id');
    if (!Array.isArray(input.usage_log_ids) || !input.usage_log_ids.length || input.usage_log_ids.length > 32) {
      throw new PlatformError('export requires 1..32 usage_log_ids');
    }
    request.usage_log_ids = [...new Set(input.usage_log_ids.map(id => component(id, 'usage_log_id')))];
  } else if (input.release_id !== undefined || input.usage_log_ids !== undefined) {
    throw new PlatformError('release and usage logs are only valid for export');
  }
  return request;
}

/** One instance is one platform-controlled project/storage namespace. */
class ChipTracePlugin {
  constructor(options = {}) {
    if (!options.root) throw new PlatformError('platform root is required');
    this.root = path.resolve(options.root);
    this.projectId = component(options.projectId, 'project_id');
    this.captureRoot = path.resolve(options.captureRoot || path.join(this.root, 'captures'));
    this.binary = options.binary || 'chiptrace';
    this.backend = options.backend || 'fs';
    if (!['fs', 'oss', 's3'].includes(this.backend)) throw new PlatformError('unknown storage backend');
    this.objectRoot = path.resolve(options.objectRoot || path.join(this.root, 'objects'));
    this.prefix = options.prefix ?? 'chiptrace';
    if (typeof this.prefix !== 'string') throw new PlatformError('object prefix must be a string');
    this.endpoint = options.endpoint;
    this.bucket = options.bucket;
    this.region = options.region;
    if (this.backend !== 'fs' && !this.bucket) throw new PlatformError('cloud backend requires a bucket');
    if (this.backend === 'oss' && !this.endpoint) throw new PlatformError('OSS backend requires an endpoint');
    this.concurrency = integer(options.concurrency, 2, 1, 16);
    this.maxQueuedJobs = integer(options.maxQueuedJobs, 128, 1, 10000);
    this.maxJobs = integer(options.maxJobs, 10000, 1, 1000000);
    this.maxOutputBytes = integer(options.maxOutputBytes, 64 * 1024 * 1024, 1024, 1024 * 1024 * 1024);
    this.maxTurnBytes = integer(options.maxTurnBytes, 64 * 1024 * 1024, 1024, 16 * 1024 * 1024 * 1024);
    this.maxUsageBytes = integer(options.maxUsageBytes, 64 * 1024 * 1024, 1024, 1024 * 1024 * 1024);
    this.jobTimeoutMs = integer(options.jobTimeoutMs, 60 * 60 * 1000, 100, 24 * 60 * 60 * 1000);
    this.engineEnv = { ...process.env, RAYON_NUM_THREADS: '2', ...options.engineEnv };
    // A running instance cannot switch the source of already cached evidence.
    // Credentials and resource limits may change between instances independently.
    for (const key of ['root', 'projectId', 'captureRoot', 'backend', 'objectRoot', 'prefix', 'endpoint', 'bucket', 'region']) {
      Object.defineProperty(this, key, { writable: false, configurable: false });
    }
    this.jobs = new Map();
    this.queue = [];
    this.running = new Set();
    this.activeReads = 0;
    this.activeArchives = new Set();
    this.children = new Set();
    this.submissions = Promise.resolve();
    this.started = false;
    this.closing = false;
  }

  async start() {
    if (!this.starting) this.starting = this.#start().catch(error => { this.starting = null; throw error; });
    return this.starting;
  }

  async #start() {
    this.closing = false;
    this.failure = null;
    this.jobs.clear();
    this.queue = [];
    this.activeArchives.clear();
    await safeDirectory(this.root);
    for (const name of ['jobs', 'work', 'usage', 'snapshots']) await safeDirectory(path.join(this.root, name));
    try {
      await this.#acquireLock();
      await this.#bindNamespace();
      const names = (await fsp.readdir(path.join(this.root, 'jobs'))).filter(name => name.endsWith('.json')).sort();
      if (names.length > this.maxJobs) throw new PlatformError('stored job capacity exceeded', 503, 'CAPACITY');
      for (const name of names) {
        const file = path.join(this.root, 'jobs', name);
        const stat = await fsp.lstat(file);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) {
          throw new PlatformError('invalid persisted job file', 503, 'CORRUPT_STATE');
        }
        const job = JSON.parse(decodeUtf8(await fsp.readFile(file)));
        const request = normalizeRequest(job.request);
        if (name !== `${request.id}.json` || job.schema_version !== 'chiptrace.platform-job.v1'
            || !['queued', 'running', 'completed', 'failed'].includes(job.status)
            || !Number.isSafeInteger(job.attempt) || job.attempt < 0
            || typeof job.created_at !== 'string') {
          throw new PlatformError('invalid persisted job', 503, 'CORRUPT_STATE');
        }
        job.request = request;
        if (['queued', 'running'].includes(job.status)) {
          job.status = 'queued';
          job.phase = 'recovered';
          await this.#save(job);
          this.queue.push(request.id);
        }
        this.jobs.set(request.id, job);
      }
      if (this.failure) throw new PlatformError('platform writer lock was lost', 503, 'WRITER_LOCK');
      this.started = true;
      this.#pump();
      return this.health();
    } catch (error) {
      this.started = false;
      await this.#releaseLock();
      throw error;
    }
  }

  async #bindNamespace() {
    const identity = {
      project_id: this.projectId,
      capture_root: this.captureRoot,
      backend: this.backend,
      object_root: this.backend === 'fs' ? this.objectRoot : null,
      endpoint: this.backend === 'fs' ? null : this.endpoint || null,
      bucket: this.backend === 'fs' ? null : this.bucket || null,
      region: this.backend === 's3' ? this.region || null : null,
      prefix: this.prefix.replace(/^\/+|\/+$/g, ''),
    };
    // Persist only a digest: paths, project names, URLs and credentials do not
    // belong in bootstrap diagnostics or the public health response.
    const expected = { schema_version: 'chiptrace.platform-namespace.v1',
      configuration_sha256: crypto.createHash('sha256').update(JSON.stringify(identity)).digest('hex') };
    const file = path.join(this.root, 'NAMESPACE.json');
    try {
      const stat = await fsp.lstat(file).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
      if (stat) {
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) {
          throw new PlatformError('platform namespace binding is invalid', 503, 'CORRUPT_STATE');
        }
        let stored;
        try { stored = JSON.parse(decodeUtf8(await fsp.readFile(file))); }
        catch { throw new PlatformError('platform namespace binding is invalid', 503, 'CORRUPT_STATE'); }
        if (stored?.schema_version !== expected.schema_version
            || typeof stored.configuration_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(stored.configuration_sha256)
            || Object.keys(stored).length !== 2) {
          throw new PlatformError('platform namespace binding is invalid', 503, 'CORRUPT_STATE');
        }
        if (stored.configuration_sha256 !== expected.configuration_sha256) {
          throw new PlatformError('platform root belongs to a different project or storage namespace', 503, 'NAMESPACE_CONFLICT');
        }
        await syncDirectory(this.root);
        return;
      }
      for (const name of ['jobs', 'work', 'usage', 'snapshots']) {
        const directory = await fsp.opendir(path.join(this.root, name));
        try {
          if (await directory.read()) {
            throw new PlatformError('existing platform state has no namespace binding; use a new root and verify Raw before migration', 503, 'NAMESPACE_UNBOUND');
          }
        } finally { await directory.close(); }
      }
      await durableWrite(file, expected, true);
    } catch (error) {
      const failure = error instanceof PlatformError ? error
        : new PlatformError('platform namespace persistence failed', 503, 'STORAGE_FAILURE');
      this.#degrade(failure.code, failure.message);
      throw failure;
    }
  }

  async #acquireLock() {
    const child = spawn(this.binary, ['platform-lock', '--root', this.root], { env: this.engineEnv, stdio: ['pipe', 'pipe', 'pipe'] });
    this.lockProcess = child;
    child.stdin.on('error', () => {}); // EOF/early engine exit also closes the pipe.
    this.lockClosed = new Promise(resolve => child.once('close', resolve));
    let acknowledged = false;
    child.once('close', () => {
      if (acknowledged && !this.closing && !this.releasingLock) this.#degrade('WRITER_LOCK', 'platform writer lock was lost');
    });
    await new Promise((resolve, reject) => {
      let output = '';
      let errorText = '';
      const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new PlatformError('platform writer lock timed out', 503, 'WRITER_LOCK')); }, 10000);
      timeout.unref();
      const finish = (error) => { clearTimeout(timeout); if (error) reject(error); else resolve(); };
      child.stdout.on('data', bytes => {
        if (acknowledged) return;
        output += bytes.toString('utf8');
        if (output.length > 2048) { child.kill('SIGKILL'); return finish(new PlatformError('invalid engine lock ACK', 503, 'ENGINE_PROTOCOL')); }
        if (output.includes('\n')) {
          try {
            if (JSON.parse(output.split('\n')[0]).locked !== true) throw new Error('missing lock ACK');
            acknowledged = true;
            finish();
          } catch { child.kill('SIGKILL'); finish(new PlatformError('invalid engine lock ACK', 503, 'ENGINE_PROTOCOL')); }
        }
      });
      child.stderr.on('data', bytes => { errorText = `${errorText}${bytes}`.slice(-2048); });
      child.once('error', finish);
      child.once('close', code => finish(new PlatformError(`platform writer lock failed (${code}): ${this.#redact(errorText)}`, 503, 'WRITER_LOCK')));
    });
  }

  async #releaseLock() {
    this.releasingLock = true;
    const child = this.lockProcess;
    const timeout = setTimeout(() => { if (child?.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }, 2000);
    timeout.unref();
    this.lockProcess?.stdin.end();
    if (this.lockClosed) await this.lockClosed;
    clearTimeout(timeout);
    this.lockProcess = null;
    this.releasingLock = false;
  }

  #degrade(code, message) {
    this.failure ||= { code, message };
    for (const child of this.children) this.#stopChild(child);
  }

  #assertReady() {
    if (!this.health().ok) throw new PlatformError('platform is shutting down or storage is unavailable', 503, this.failure?.code || 'SHUTDOWN');
  }

  #acquireRead() {
    this.#assertReady();
    if (this.activeReads >= this.concurrency) throw new PlatformError('platform read capacity is full', 503, 'CAPACITY');
    this.activeReads += 1;
    let released = false;
    return () => { if (!released) { this.activeReads -= 1; released = true; } };
  }

  #stopChild(child) {
    child.kill('SIGTERM');
    const timer = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }, 2000);
    timer.unref();
  }

  storageArgs() {
    const args = ['--backend', this.backend, '--prefix', this.prefix];
    if (this.backend === 'fs') args.push('--root', this.objectRoot);
    if (this.endpoint) args.push('--endpoint', this.endpoint);
    if (this.bucket) args.push('--bucket', this.bucket);
    if (this.region) args.push('--region', this.region);
    return args;
  }

  async putUsageLog(id, bytes) {
    await this.start();
    this.#assertReady();
    component(id, 'usage_log_id');
    const body = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    if (!body.length || body.length > this.maxUsageBytes) throw new PlatformError('usage log size exceeds limit', 413, 'BODY_LIMIT');
    let rows = 0;
    for (const line of decodeUtf8(body).split('\n')) {
      if (!line.trim()) continue;
      let row;
      try { row = JSON.parse(line); } catch { throw new PlatformError('usage log must be valid UTF-8 JSONL'); }
      if (!row || typeof row !== 'object' || Array.isArray(row)) throw new PlatformError('usage log rows must be objects');
      rows += 1;
    }
    if (!rows) throw new PlatformError('usage log must contain at least one object');
    const file = path.join(this.root, 'usage', `${id}.jsonl`);
    try {
      await durableWrite(file, body, true);
      return { id, bytes: body.length, duplicate: false };
    } catch (error) {
      if (error.code !== 'EEXIST') { this.#degrade('STORAGE_FAILURE', 'usage log persistence failed'); throw new PlatformError('usage log persistence failed', 503, 'STORAGE_FAILURE'); }
      const stat = await fsp.lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > this.maxUsageBytes) throw new PlatformError('invalid stored usage log', 503, 'CORRUPT_STATE');
      const existing = await fsp.readFile(file);
      if (!existing.equals(body)) throw new PlatformError('usage log ID conflicts with existing bytes', 409, 'ID_CONFLICT');
      return { id, bytes: body.length, duplicate: true };
    }
  }

  async submit(input) {
    await this.start();
    const request = normalizeRequest(input);
    const submitted = this.submissions.then(async () => {
      this.#assertReady();
      const existing = this.jobs.get(request.id);
      if (existing) {
        if (JSON.stringify(existing.request) !== JSON.stringify(request)) throw new PlatformError('job ID conflicts with existing request', 409, 'ID_CONFLICT');
        return { ...structuredClone(existing), duplicate: true };
      }
      if (this.queue.length + this.running.size >= this.maxQueuedJobs || this.jobs.size >= this.maxJobs) {
        throw new PlatformError('platform job capacity is full', 503, 'CAPACITY');
      }
      if (request.kind === 'export') {
        for (const id of request.usage_log_ids) {
          const stat = await fsp.lstat(path.join(this.root, 'usage', `${id}.jsonl`)).catch(() => null);
          if (!stat?.isFile() || stat.isSymbolicLink()) throw new PlatformError(`usage log is not registered: ${id}`);
        }
      }
      const job = { schema_version: 'chiptrace.platform-job.v1', request,
        status: 'queued', phase: 'queued', created_at: new Date().toISOString(), attempt: 0 };
      await this.#save(job, true);
      this.jobs.set(request.id, job);
      this.queue.push(request.id);
      this.#pump();
      return { ...structuredClone(job), duplicate: false };
    });
    this.submissions = submitted.catch(() => {});
    return submitted;
  }

  #jobFile(id) { return path.join(this.root, 'jobs', `${component(id, 'job_id')}.json`); }
  async #save(job, createOnly = false) {
    try {
      if (Buffer.byteLength(JSON.stringify(job)) > 1024 * 1024) throw new Error('job metadata limit exceeded');
      await durableWrite(this.#jobFile(job.request.id), job, createOnly);
    } catch {
      this.#degrade('STORAGE_FAILURE', 'job state persistence failed');
      throw new PlatformError('job state persistence failed', 503, 'STORAGE_FAILURE');
    }
  }

  #pump() {
    while (!this.closing && !this.failure && this.running.size < this.concurrency && this.queue.length) {
      const index = this.queue.findIndex(id => !this.activeArchives.has(this.jobs.get(id).request.archive_id));
      if (index < 0) break;
      const job = structuredClone(this.jobs.get(this.queue.splice(index, 1)[0]));
      this.activeArchives.add(job.request.archive_id);
      job.status = 'running';
      const work = this.#execute(job).catch(() => this.#degrade('STORAGE_FAILURE', 'job state persistence failed'))
        .finally(() => { this.running.delete(work); this.activeArchives.delete(job.request.archive_id); this.#pump(); });
      this.running.add(work);
    }
  }

  async #phase(job, phase) {
    job.phase = phase;
    job.updated_at = new Date().toISOString();
    await this.#save(job);
    this.jobs.set(job.request.id, structuredClone(job));
  }

  async #execute(job) {
    job.attempt += 1;
    try {
      await this.#phase(job, 'starting');
      job.result = await this.#runJob(job);
      await this.#persistTurns(job);
      this.#assertReady();
      job.status = 'completed';
      job.phase = 'completed';
      delete job.error;
    } catch (error) {
      job.status = this.closing || this.failure ? 'queued' : 'failed';
      job.phase = this.closing || this.failure ? 'interrupted' : 'failed';
      delete job.result;
      delete job.artifacts;
      delete job.turns;
      job.error = { code: error.code || 'ENGINE_FAILURE', message: this.#redact(error.message),
        exit_code: error.exitCode ?? null, signal: error.signal ?? null };
    }
    job.updated_at = new Date().toISOString();
    await this.#save(job);
    this.jobs.set(job.request.id, structuredClone(job));
  }

  async #persistTurns(job) {
    const session = job.result?.session || job.result?.session_view;
    if (!session) return;
    if (job.result.schema_version === 'chiptrace.platform-inspection.v1'
        || (job.request.kind === 'export' && job.result.schema_version === 'chiptrace.cloud-acceptance.v2')) {
      job.turns = engineTurnEvidence(session, job.result.turns);
      delete job.result.turns;
      await this.#readTurnEvidence(job, 0, 0);
      return;
    }
    if (!Array.isArray(session.turns) || session.turns.length !== session.native_turns) {
      throw new PlatformError('invalid engine Session/Turn view', 502, 'ENGINE_PROTOCOL');
    }
    const file = path.join(this.root, 'work', job.request.id, 'turns.jsonl');
    const temporary = `${file}.${crypto.randomUUID()}.tmp`;
    const digest = crypto.createHash('sha256');
    let bytes = 0;
    let handle;
    try {
      handle = await fsp.open(temporary, 'wx', 0o600);
      for (const turn of session.turns) {
        const line = Buffer.from(`${JSON.stringify(turn)}\n`);
        bytes += line.length;
        if (bytes > this.maxTurnBytes) throw new Error('turn metadata limit exceeded');
        await handle.writeFile(line);
        digest.update(line);
      }
      await handle.sync();
      await handle.close();
      handle = null;
      await fsp.rename(temporary, file);
      await syncDirectory(path.dirname(file));
      job.turns = { records: session.turns.length, bytes, sha256: digest.digest('hex') };
      delete session.turns;
    } catch {
      this.#degrade('STORAGE_FAILURE', 'turn state persistence failed');
      throw new PlatformError('turn state persistence failed', 503, 'STORAGE_FAILURE');
    } finally {
      if (handle) await handle.close();
      await fsp.unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
    }
  }

  #redact(text) {
    let message = String(text).slice(-8192);
    for (const [key, value] of Object.entries(this.engineEnv)) {
      if (/token|secret|password|api.?key/i.test(key) && typeof value === 'string' && value.length >= 8) message = message.replaceAll(value, '[REDACTED]');
    }
    return message;
  }

  async #acceptanceSummary(report, request, output) {
    const result = report?.acceptance;
    if (report?.schema_version !== 'chiptrace.platform-acceptance.v1'
        || result?.schema_version !== 'chiptrace.cloud-acceptance.v2'
        || result.session_view?.schema_version !== 'chiptrace.session-view.v2'
        || result.session_view.delivery_ready !== true
        || !sourceContextReady(result.source_context_audit, request.session_id)
        || result.delivery_ready !== true || result.hard_gate_pass !== true
        || typeof result.score !== 'number' || !Number.isFinite(result.score) || result.score < 90
        || result.archive_id !== request.archive_id || result.session_id !== request.session_id || result.release_id !== request.release_id) {
      throw new PlatformError('export does not match the requested accepted Session', 422, 'ACCEPTANCE_FAILED');
    }
    engineTurnEvidence(result.session_view, report.turns);
    const manifest = await fileDigest(path.join(output, 'manifest.json'));
    if (report.manifest?.file !== 'manifest.json'
        || report.manifest.bytes !== manifest.bytes || report.manifest.sha256 !== manifest.sha256) {
      throw new PlatformError('acceptance manifest does not match engine report', 502, 'ENGINE_PROTOCOL');
    }
    return result;
  }

  async #runJob(job) {
    const request = job.request;
    const work = path.join(this.root, 'work', request.id);
    await safeDirectory(work);
    if (request.kind === 'archive') {
      await this.#phase(job, 'archiving');
      const result = await this.#engine(['archive-raw', '--input', this.captureRoot, '--archive-id', request.archive_id, ...this.storageArgs()]);
      if (result.ok !== true || result.archive_id !== request.archive_id || result.completeness !== 'complete') {
        throw new PlatformError('archive does not match the requested complete Raw', 422, 'RAW_INCOMPLETE');
      }
      return result;
    }
    if (request.kind === 'export') {
      const output = path.join(work, 'acceptance');
      await this.#phase(job, 'acceptance');
      let report;
      const existingOutput = await fsp.lstat(output).catch(() => null);
      if (existingOutput && (!existingOutput.isDirectory() || existingOutput.isSymbolicLink())) {
        throw new PlatformError('stored acceptance output is not a directory', 503, 'CORRUPT_STATE');
      }
      if (existingOutput) {
        report = await this.#engine(['verify-cloud-acceptance', '--acceptance', output,
          '--platform-report', '--max-turn-bytes', String(this.maxTurnBytes)]);
      } else {
        const usage = request.usage_log_ids.flatMap(id => ['--usage-log', path.join(this.root, 'usage', `${id}.jsonl`)]);
        report = await this.#engine(['cloud-acceptance', '--archive-id', request.archive_id, ...this.storageArgs(),
          '--session-id', request.session_id, '--release-id', request.release_id, '--output', output,
          '--minimum-score', '90', '--workers', '1', '--partitions', '16',
          '--platform-report', '--max-turn-bytes', String(this.maxTurnBytes), ...usage]);
      }
      const result = await this.#acceptanceSummary(report, request, output);
      const buyerPath = path.join(output, 'buyer-package', 'manifest.json');
      const buyerStat = await fsp.lstat(buyerPath);
      if (!buyerStat.isFile() || buyerStat.isSymbolicLink()) throw new PlatformError('stored buyer manifest is invalid', 503, 'CORRUPT_STATE');
      const buyer = JSON.parse(decodeUtf8(await fsp.readFile(buyerPath)));
      job.artifacts = buyer.packages.map(part => ({ file: path.basename(part.file), bytes: part.bytes, sha256: part.sha256 }));
      // #persistTurns verifies this descriptor and removes it before the job
      // is saved; the public result retains its existing v2 summary shape.
      result.turns = report.turns;
      return result;
    }
    const output = path.join(this.root, 'snapshots', request.archive_id);
    await this.#phase(job, 'restoring');
    const existingOutput = await fsp.lstat(output).catch(() => null);
    if (existingOutput && (!existingOutput.isDirectory() || existingOutput.isSymbolicLink())) {
      throw new PlatformError('stored Raw output is not a directory', 503, 'CORRUPT_STATE');
    }
    const result = existingOutput
      ? await this.#engine(['verify-restored-raw', '--input', output])
      : await this.#engine(['restore-raw-archive', '--archive-id', request.archive_id, '--output', output,
        '--verify-records', ...this.storageArgs()]);
    if (result.archive_id !== request.archive_id || result.completeness !== 'complete' || result.ok !== true) {
      throw new PlatformError('restored Raw is incomplete or belongs to another archive', 422, 'RAW_INCOMPLETE');
    }
    if (request.kind === 'restore') return result;
    await this.#phase(job, 'inspecting');
    const projectionRoot = path.join(work, 'projection');
    const projectionStat = await fsp.lstat(projectionRoot).catch(() => null);
    if (projectionStat && (!projectionStat.isDirectory() || projectionStat.isSymbolicLink())) {
      throw new PlatformError('stored interaction projection is invalid', 503, 'CORRUPT_STATE');
    }
    const inspected = await this.#engine([
      'inspect-session', '--input', output, '--session-id', request.session_id,
      '--projection-output', projectionRoot, '--platform-report', '--max-turn-bytes', String(this.maxTurnBytes),
    ]);
    if (inspected.schema_version !== 'chiptrace.platform-inspection.v1'
        || inspected.session?.session_id !== request.session_id || inspected.session.schema_version !== 'chiptrace.session-view.v2'
        || inspected.source_context_audit?.schema_version !== 'chiptrace.source-context-audit.v2'
        || inspected.source_context_audit?.session_id !== request.session_id
        || typeof inspected.delivery_ready !== 'boolean'
        || (inspected.delivery_ready && !sourceContextReady(inspected.source_context_audit, request.session_id))) {
      throw new PlatformError('inspection does not match requested Session', 502, 'ENGINE_PROTOCOL');
    }
    const projection = inspected.interaction_projection;
    const manifestPath = path.join(projectionRoot, 'manifest.json');
    const manifest = await fileDigest(manifestPath);
    const metadata = projectionMetadata(projection, { file: 'manifest.json', ...manifest });
    if (!metadata || metadata.schema_version !== 'chiptrace.interaction-projection.v1'
        || metadata.session_id !== request.session_id
        || projection.manifest?.file !== 'manifest.json'
        || projection.manifest?.bytes !== manifest.bytes || projection.manifest?.sha256 !== manifest.sha256) {
      throw new PlatformError('interaction projection does not match inspected Session', 502, 'ENGINE_PROTOCOL');
    }
    inspected.interaction_projection = metadata;
    return inspected;
  }

  async #engine(args) {
    this.#assertReady();
    return new Promise((resolve, reject) => {
      const child = spawn(this.binary, args, { env: this.engineEnv, stdio: ['ignore', 'pipe', 'pipe'] });
      this.children.add(child);
      const chunks = [];
      let bytes = 0;
      let stderr = '';
      let limitError;
      const stop = () => this.#stopChild(child);
      const timer = setTimeout(() => { limitError = new PlatformError('engine job timed out', 504, 'JOB_TIMEOUT'); stop(); }, this.jobTimeoutMs);
      timer.unref();
      child.stdout.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > this.maxOutputBytes) { if (!limitError) { limitError = new PlatformError('engine JSON output exceeds limit', 503, 'OUTPUT_LIMIT'); stop(); } }
        else chunks.push(chunk);
      });
      child.stderr.on('data', chunk => { stderr = `${stderr}${chunk}`.slice(-8192); });
      child.once('error', error => { clearTimeout(timer); this.children.delete(child); reject(error); });
      child.once('close', (code, signal) => {
        clearTimeout(timer);
        this.children.delete(child);
        if (limitError || code !== 0 || signal) {
          const error = limitError || new PlatformError(`engine exited (${code}, ${signal}): ${stderr}`, 422, 'ENGINE_FAILURE');
          error.exitCode = code;
          error.signal = signal;
          return reject(error);
        }
        try { resolve(JSON.parse(decodeUtf8(Buffer.concat(chunks)))); }
        catch { reject(new PlatformError('engine did not return valid JSON', 502, 'ENGINE_PROTOCOL')); }
      });
    });
  }

  getJob(id) {
    const job = this.jobs.get(component(id, 'job_id'));
    if (!job) throw new PlatformError('job not found', 404, 'NOT_FOUND');
    return structuredClone(job);
  }

  listJobs({ offset = 0, limit = 50 } = {}) {
    offset = integer(offset, 0, 0, this.maxJobs);
    limit = integer(limit, 50, 1, 100);
    return { total: this.jobs.size, offset, jobs: [...this.jobs.values()].slice(offset, offset + limit)
      .map(job => ({ id: job.request.id, kind: job.request.kind, status: job.status, phase: job.phase, created_at: job.created_at })) };
  }

  async getTurns(id, { offset = 0, limit = 50 } = {}) {
    const release = this.#acquireRead();
    try { return await this.#readTurns(id, { offset, limit }); }
    finally { release(); }
  }

  async #readTurns(id, { offset, limit }) {
    const job = this.getJob(id);
    if (job.status !== 'completed') throw new PlatformError('job has no completed inspection', 409, 'JOB_NOT_READY');
    const session = job.result?.session || job.result?.session_view;
    if (!session || !job.turns) throw new PlatformError('job has no Session/Turn view', 404, 'NOT_FOUND');
    offset = integer(offset, 0, 0, Number.MAX_SAFE_INTEGER);
    limit = integer(limit, 50, 1, 100);
    const { turns, records } = await this.#readTurnEvidence(job, offset, limit);
    const deliveryReady = job.result.delivery_ready === true
      && sourceContextReady(job.result.source_context_audit, job.request.session_id);
    return { delivery_ready: deliveryReady, summary: session, total: records, offset, turns };
  }

  async #readTurnEvidence(job, offset, limit) {
    const file = path.join(this.root, 'work', job.request.id, 'turns.jsonl');
    const stat = await fsp.lstat(file);
    if (stat.size > this.maxTurnBytes) {
      throw new PlatformError('Turn evidence exceeds disk limit', 503, 'OUTPUT_LIMIT');
    }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== job.turns.bytes) {
      throw new PlatformError('Turn evidence changed', 422, 'ARTIFACT_CHANGED');
    }
    const digest = crypto.createHash('sha256');
    const input = fs.createReadStream(file);
    input.on('data', chunk => digest.update(chunk));
    const lines = readline.createInterface({ input, crlfDelay: Infinity });
    const turns = [];
    let records = 0;
    try {
      for await (const line of lines) {
        if (records >= offset && records < offset + limit) turns.push(JSON.parse(line));
        records += 1;
      }
    } catch {
      throw new PlatformError('Turn evidence changed or cannot be read', 422, 'ARTIFACT_CHANGED');
    } finally { lines.close(); input.destroy(); }
    if (records !== job.turns.records || digest.digest('hex') !== job.turns.sha256) {
      throw new PlatformError('Turn evidence changed', 422, 'ARTIFACT_CHANGED');
    }
    return { turns, records };
  }

  async openArtifact(id, file) {
    const release = this.#acquireRead();
    try {
      const artifact = await this.#openArtifact(id, file);
      artifact.stream.once('close', release);
      return artifact;
    } catch (error) { release(); throw error; }
  }

  async #openArtifact(id, file) {
    const job = this.getJob(id);
    if (job.request.kind !== 'export' || job.status !== 'completed') throw new PlatformError('export is not ready', 409, 'JOB_NOT_READY');
    component(file, 'package file');
    const artifact = job.artifacts?.find(item => item.file === file);
    if (!artifact) throw new PlatformError('package not found', 404, 'NOT_FOUND');
    const output = path.join(this.root, 'work', job.request.id, 'acceptance');
    const report = await this.#engine(['verify-cloud-acceptance', '--acceptance', output,
      '--platform-report', '--max-turn-bytes', String(this.maxTurnBytes)]);
    const summary = await this.#acceptanceSummary(report, job.request, output);
    if (!isDeepStrictEqual(summary, job.result)
        || !isDeepStrictEqual(engineTurnEvidence(summary.session_view, report.turns), job.turns)) {
      throw new PlatformError('accepted Session evidence changed', 422, 'ARTIFACT_CHANGED');
    }
    const artifactPath = path.join(output, 'buyer-package', 'packages', file);
    const artifactStat = await fsp.lstat(artifactPath);
    if (!artifactStat.isFile() || artifactStat.isSymbolicLink()) throw new PlatformError('package file is invalid', 422, 'ARTIFACT_CHANGED');
    const handle = await fsp.open(artifactPath, 'r');
    try {
      const stat = await handle.stat();
      const digest = crypto.createHash('sha256');
      const buffer = Buffer.alloc(1024 * 1024);
      let position = 0;
      for (;;) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
        if (!bytesRead) break;
        digest.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
      }
      if (!stat.isFile() || position !== artifact.bytes || digest.digest('hex') !== artifact.sha256) {
        throw new PlatformError('package checksum mismatch', 422, 'ARTIFACT_CHANGED');
      }
      return { ...artifact, stream: handle.createReadStream({ start: 0, autoClose: true }) };
    } catch (error) { await handle.close(); throw error; }
  }

  async openProjection(id, part) {
    const release = this.#acquireRead();
    try {
      const artifact = await this.#openProjection(id, part);
      artifact.stream.once('close', release);
      return artifact;
    } catch (error) { release(); throw error; }
  }

  async #openProjection(id, part) {
    const job = this.getJob(id);
    if (job.status !== 'completed' || !job.result?.interaction_projection) {
      throw new PlatformError('interaction projection is not ready', 409, 'JOB_NOT_READY');
    }
    const descriptor = PROJECTION_PARTS[part];
    if (!descriptor) throw new PlatformError('projection part not found', 404, 'NOT_FOUND');
    const expected = job.result.interaction_projection;
    if (!expected || !Array.isArray(expected.parts)) {
      throw new PlatformError('interaction projection metadata is invalid', 503, 'CORRUPT_STATE');
    }
    const expectedManifest = expected.manifest;
    if (!expectedManifest || expectedManifest.file !== 'manifest.json'
        || !Number.isSafeInteger(expectedManifest.bytes) || typeof expectedManifest.sha256 !== 'string') {
      throw new PlatformError('interaction projection metadata is invalid', 503, 'CORRUPT_STATE');
    }
    const root = path.join(this.root, 'work', component(id, 'job_id'), 'projection');
    const rootStat = await fsp.lstat(root).catch(() => null);
    if (!rootStat?.isDirectory() || rootStat.isSymbolicLink()) {
      throw new PlatformError('interaction projection is missing', 422, 'ARTIFACT_CHANGED');
    }
    const manifestPath = path.join(root, 'manifest.json');
    const manifestStat = await fsp.lstat(manifestPath).catch(() => null);
    if (!manifestStat?.isFile() || manifestStat.isSymbolicLink() || manifestStat.size !== expectedManifest.bytes) {
      throw new PlatformError('interaction projection manifest changed', 422, 'ARTIFACT_CHANGED');
    }
    const manifestBytes = await fsp.readFile(manifestPath);
    if (crypto.createHash('sha256').update(manifestBytes).digest('hex') !== expectedManifest.sha256) {
      throw new PlatformError('interaction projection manifest changed', 422, 'ARTIFACT_CHANGED');
    }
    let manifest;
    try { manifest = JSON.parse(decodeUtf8(manifestBytes)); }
    catch { throw new PlatformError('interaction projection manifest is invalid', 422, 'ARTIFACT_CHANGED'); }
    if (JSON.stringify(projectionMetadata(manifest, expected.manifest)) !== JSON.stringify(expected)) {
      throw new PlatformError('interaction projection metadata changed', 422, 'ARTIFACT_CHANGED');
    }
    const expectedPart = descriptor.file === 'manifest.json'
      ? expectedManifest
      : expected.parts.find(item => item.file === descriptor.file);
    if (!expectedPart) throw new PlatformError('projection part is not recorded', 422, 'ARTIFACT_CHANGED');
    const file = path.join(root, descriptor.file);
    const stat = await fsp.lstat(file).catch(() => null);
    if (!stat?.isFile() || stat.isSymbolicLink() || stat.size !== expectedPart.bytes) {
      throw new PlatformError('interaction projection part changed', 422, 'ARTIFACT_CHANGED');
    }
    const handle = await fsp.open(file, 'r');
    try {
      const digest = crypto.createHash('sha256');
      const buffer = Buffer.alloc(1024 * 1024);
      let position = 0;
      for (;;) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
        if (!bytesRead) break;
        digest.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
      }
      if (position !== expectedPart.bytes || digest.digest('hex') !== expectedPart.sha256) {
        throw new PlatformError('interaction projection part checksum mismatch', 422, 'ARTIFACT_CHANGED');
      }
      return { file: descriptor.file, bytes: expectedPart.bytes, sha256: expectedPart.sha256,
        contentType: descriptor.contentType, stream: handle.createReadStream({ start: 0, autoClose: true }) };
    } catch (error) { await handle.close(); throw error; }
  }

  health() { return { ok: this.started && !this.closing && !this.failure, version: 'chiptrace.platform.v1',
    queued: this.queue.length, running: this.running.size, active_reads: this.activeReads,
    jobs: this.jobs.size, failure: this.failure || null }; }

  async close() {
    this.closing = true;
    await this.submissions;
    for (const child of this.children) this.#stopChild(child);
    await Promise.allSettled([...this.running]);
    await this.#releaseLock();
    this.started = false;
    this.starting = null;
  }
}

module.exports = { ChipTracePlugin, PlatformError, component, decodeUtf8 };
