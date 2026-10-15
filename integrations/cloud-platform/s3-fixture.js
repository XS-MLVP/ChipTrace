'use strict';

// Fixture-only S3 signing and a private MinIO process. Never use host storage
// services or inherit the operator's cloud credentials for native protocol CI.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { createReadStream } = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { execFile, spawn } = require('node:child_process');
const run = require('node:util').promisify(execFile);

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hmac = (key, text) => crypto.createHmac('sha256', key).update(text).digest();

async function signedS3Request(endpoint, resource, { accessKeyId, secretAccessKey,
  region = 'us-east-1', method = 'GET', body } = {}) {
  assert.ok(accessKeyId && secretAccessKey, 'explicit fixture credentials are required');
  const url = new URL(resource, endpoint);
  assert.equal(url.search, '', 'fixture requests do not use query parameters');
  const timestamp = new Date().toISOString().replace(/[-:]|\.\d{3}/g, '');
  const day = timestamp.slice(0, 8);
  const digest = sha(body || Buffer.alloc(0));
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const headers = `host:${url.host}\nx-amz-content-sha256:${digest}\nx-amz-date:${timestamp}\n`;
  const canonical = `${method}\n${url.pathname}\n\n${headers}\n${signedHeaders}\n${digest}`;
  const scope = `${day}/${region}/s3/aws4_request`;
  const key = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, day), region), 's3'), 'aws4_request');
  const signature = hmac(key, `AWS4-HMAC-SHA256\n${timestamp}\n${scope}\n${sha(canonical)}`).toString('hex');
  return fetch(url, { method, body, signal: AbortSignal.timeout(10000), headers: {
    'x-amz-content-sha256': digest, 'x-amz-date': timestamp,
    authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  } });
}

async function startS3Fixture(binary, root) {
  assert.ok(path.isAbsolute(binary) && path.isAbsolute(root), 'absolute fixture binary and root are required');
  binary = await fs.realpath(binary);
  const hash = crypto.createHash('sha256');
  for await (const bytes of createReadStream(binary)) hash.update(bytes);
  const binarySha256 = hash.digest('hex');
  await fs.mkdir(root, { mode: 0o700 });
  const env = { PATH: process.env.PATH, HOME: root, TMPDIR: root, LANG: 'C.UTF-8',
    GOMAXPROCS: '2', MINIO_BROWSER: 'off', MINIO_ROOT_USER: 'chiptrace-native-ci',
    MINIO_ROOT_PASSWORD: crypto.randomBytes(32).toString('hex') };
  const version = (await run(binary, ['--version'], { env, timeout: 10000 })).stdout.split('\n')[0];
  const reservation = net.createServer();
  await new Promise((resolve, reject) => {
    reservation.once('error', reject);
    reservation.listen(0, '127.0.0.1', resolve);
  });
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const endpoint = `http://127.0.0.1:${port}`;
  const log = await fs.open(path.join(root, 'minio.log'), 'wx', 0o600);
  let child;
  let spawnError;
  let closed;
  try {
    child = spawn(binary, ['server', path.join(root, 'data'), '--address', `127.0.0.1:${port}`,
      '--console-address', '127.0.0.1:0'], { env, stdio: ['ignore', log.fd, log.fd] });
    closed = new Promise(resolve => {
      child.once('error', error => { spawnError = error; resolve(); });
      child.once('close', resolve);
    });
  } finally { await log.close(); }
  const close = async () => {
    if (!spawnError && child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    timer.unref();
    try { await closed; } finally { clearTimeout(timer); }
  };
  try {
    let ready = false;
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline && !ready) {
      if (spawnError) throw spawnError;
      assert.ok(child.exitCode === null && child.signalCode === null, 'private MinIO exited before readiness; inspect its fixture log');
      try {
        const response = await fetch(`${endpoint}/minio/health/live`, { signal: AbortSignal.timeout(500) });
        ready = response.ok;
        await response.body?.cancel();
      } catch { /* The owned process may still be starting. */ }
      if (!ready) await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(ready, 'private MinIO did not become ready; inspect its fixture log');
    const bucket = 'chiptrace-native-ci';
    const credentials = { accessKeyId: env.MINIO_ROOT_USER, secretAccessKey: env.MINIO_ROOT_PASSWORD };
    const request = (resource, options) => signedS3Request(endpoint, `/${bucket}/${resource}`, { ...credentials, ...options });
    const created = await signedS3Request(endpoint, `/${bucket}`, { ...credentials, method: 'PUT' });
    assert.ok(created.ok, 'the owned MinIO must accept creation of its fresh fixture bucket');
    await created.body?.cancel();
    return { endpoint, bucket, region: 'us-east-1', request, close,
      engineEnv: { AWS_ACCESS_KEY_ID: credentials.accessKeyId, AWS_SECRET_ACCESS_KEY: credentials.secretAccessKey,
        AWS_EC2_METADATA_DISABLED: 'true' },
      evidence: { service: 'isolated_minio', endpoint_scope: 'loopback', fixture_credentials: true,
        binary_sha256: binarySha256, version } };
  } catch (error) { await close(); throw error; }
}

module.exports = { signedS3Request, startS3Fixture };
