'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { pipeline } = require('node:stream/promises');
const { ChipTracePlugin, PlatformError, decodeUtf8 } = require('./plugin');

function json(res, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': body.length });
  res.end(body);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let bytes = 0;
    let oversized = false;
    const chunks = [];
    req.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > limit) { oversized = true; chunks.length = 0; }
      else if (!oversized) chunks.push(chunk);
    });
    req.once('end', () => oversized ? reject(new PlatformError('request body exceeds limit', 413, 'BODY_LIMIT')) : resolve(Buffer.concat(chunks)));
    req.once('error', reject);
  });
}

function publicJob(job) {
  for (const key of ['session', 'session_view']) {
    if (job.result?.[key]) delete job.result[key].turns;
  }
  return job;
}

/** Mount this handler behind the cloud platform's own user authentication. */
function createPlatformHandler(plugin, token) {
  if (typeof token !== 'string' || Buffer.byteLength(token) < 32) throw new PlatformError('platform service token must contain at least 32 bytes');
  const expected = Buffer.from(`Bearer ${token}`);
  return async (req, res) => {
    try {
      const url = new URL(req.url, 'http://chiptrace-platform.local');
      if (url.pathname === '/health' && req.method === 'GET') return json(res, plugin.health().ok ? 200 : 503, plugin.health());
      const supplied = Buffer.from(req.headers.authorization || '');
      if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
        return json(res, 401, { ok: false, error: { code: 'AUTH_REQUIRED', message: 'platform service authentication required' } });
      }
      if (!plugin.health().ok) throw new PlatformError('platform is not ready', 503, 'NOT_READY');
      const page = () => ({ offset: url.searchParams.has('offset') ? Number(url.searchParams.get('offset')) : 0,
        limit: url.searchParams.has('limit') ? Number(url.searchParams.get('limit')) : 50 });
      if (url.pathname === '/v1/jobs') {
        if (req.method === 'GET') return json(res, 200, plugin.listJobs(page()));
        if (req.method === 'POST') {
          let request;
          try { request = JSON.parse(decodeUtf8(await readBody(req, 32 * 1024))); }
          catch (error) { if (error instanceof PlatformError) throw error; throw new PlatformError('job body must be valid JSON'); }
          const job = await plugin.submit(request);
          return json(res, job.duplicate ? 200 : 202, publicJob(job));
        }
      }
      const usage = url.pathname.match(/^\/v1\/usage\/([^/]+)$/);
      if (usage && req.method === 'PUT') {
        const result = await plugin.putUsageLog(decodeURIComponent(usage[1]), await readBody(req, plugin.maxUsageBytes));
        return json(res, result.duplicate ? 200 : 201, result);
      }
      const projection = url.pathname.match(/^\/v1\/jobs\/([^/]+)\/projection\/([^/]+)$/);
      if (projection && req.method === 'GET') {
        const artifact = await plugin.openProjection(decodeURIComponent(projection[1]), decodeURIComponent(projection[2]));
        res.writeHead(200, { 'content-type': artifact.contentType, 'content-length': artifact.bytes,
          'content-disposition': `attachment; filename="${artifact.file.split('/').pop()}"`, etag: `"${artifact.sha256}"`,
          'x-content-sha256': artifact.sha256 });
        await pipeline(artifact.stream, res);
        return;
      }
      const jobPath = url.pathname.match(/^\/v1\/jobs\/([^/]+)(?:\/(turns|turns\.jsonl|packages\/([^/]+)))?$/);
      if (jobPath && req.method === 'GET') {
        const id = decodeURIComponent(jobPath[1]);
        if (jobPath[2] === 'turns') {
          const artifact = await plugin.openTurnPage(id, page());
          res.writeHead(200, { 'content-type': artifact.contentType, 'content-length': artifact.bytes });
          await pipeline(artifact.stream, res);
          return;
        }
        if (jobPath[2] === 'turns.jsonl') {
          const artifact = await plugin.openTurns(id);
          res.writeHead(200, { 'content-type': artifact.contentType, 'content-length': artifact.bytes,
            'content-disposition': 'attachment; filename="turns.jsonl"', etag: `"${artifact.sha256}"`,
            'x-content-sha256': artifact.sha256 });
          await pipeline(artifact.stream, res);
          return;
        }
        if (jobPath[3]) {
          const artifact = await plugin.openArtifact(id, decodeURIComponent(jobPath[3]));
          res.writeHead(200, { 'content-type': 'application/gzip', 'content-length': artifact.bytes,
            'content-disposition': `attachment; filename="${artifact.file}"`, etag: `"${artifact.sha256}"`,
            'x-content-sha256': artifact.sha256 });
          await pipeline(artifact.stream, res);
          return;
        }
        return json(res, 200, publicJob(plugin.getJob(id)));
      }
      json(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: 'route not found' } });
    } catch (error) {
      if (res.headersSent) { res.destroy(); return; }
      const known = error instanceof PlatformError;
      json(res, known ? error.status : error instanceof URIError ? 400 : 500,
        { ok: false, error: { code: known ? error.code : 'INTERNAL_ERROR', message: known ? error.message : 'platform request failed' } });
    }
  };
}

async function createPlatformServer(options) {
  const plugin = options.plugin || new ChipTracePlugin(options);
  const handler = createPlatformHandler(plugin, options.token);
  await plugin.start();
  const server = http.createServer(handler);
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  return { server, plugin, handler, async close() {
    // Stop accepting new requests, interrupt only this plugin's engine jobs,
    // and leave their durable queue records for the next process.
    const closed = new Promise(resolve => server.close(resolve));
    await plugin.close();
    server.closeIdleConnections();
    await closed;
  } };
}

if (require.main === module) {
  const backend = process.env.CHIPTRACE_BACKEND;
  if (!['fs', 'oss', 's3'].includes(backend)) {
    process.stderr.write('CHIPTRACE_BACKEND must be explicitly set to fs, oss, or s3\n');
    process.exitCode = 1;
  } else {
    createPlatformServer({
      root: process.env.CHIPTRACE_PLATFORM_ROOT || '/data/platform',
      projectId: process.env.CHIPTRACE_PROJECT_ID,
      captureRoot: process.env.CHIPTRACE_CAPTURE_ROOT,
      binary: process.env.CHIPTRACE_BIN || 'chiptrace',
      backend,
      objectRoot: process.env.CHIPTRACE_OBJECT_ROOT,
      prefix: process.env.CHIPTRACE_OBJECT_PREFIX || 'chiptrace',
      endpoint: process.env.CHIPTRACE_OBJECT_ENDPOINT,
      bucket: process.env.CHIPTRACE_OBJECT_BUCKET,
      region: process.env.CHIPTRACE_OBJECT_REGION,
      token: process.env.CHIPTRACE_PLATFORM_TOKEN,
      concurrency: Number(process.env.CHIPTRACE_JOB_CONCURRENCY || '2'),
      maxQueuedJobs: Number(process.env.CHIPTRACE_MAX_QUEUED_JOBS || '128'),
      maxJobs: Number(process.env.CHIPTRACE_MAX_JOBS || '10000'),
      maxUsageBytes: Number(process.env.CHIPTRACE_MAX_USAGE_BYTES || String(64 * 1024 * 1024)),
      maxOutputBytes: Number(process.env.CHIPTRACE_MAX_OUTPUT_BYTES || String(64 * 1024 * 1024)),
      maxTurnBytes: Number(process.env.CHIPTRACE_MAX_TURN_BYTES || String(64 * 1024 * 1024)),
      jobTimeoutMs: Number(process.env.CHIPTRACE_JOB_TIMEOUT_MS || String(60 * 60 * 1000)),
    }).then(app => {
      app.server.listen(Number(process.env.CHIPTRACE_PLATFORM_PORT || '18086'), process.env.CHIPTRACE_PLATFORM_HOST || '127.0.0.1', () => {
        process.stdout.write(`${JSON.stringify({ event: 'platform_ready', port: app.server.address().port })}\n`);
      });
      for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => app.close().then(() => process.exit(0)));
    }).catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
  }
}

module.exports = { createPlatformHandler, createPlatformServer };
