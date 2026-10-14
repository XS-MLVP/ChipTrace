'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const run = promisify(execFile);
const binary = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/debug/chiptrace');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hmac = (key, text) => crypto.createHmac('sha256', key).update(text).digest();

// Sign fixture setup/corruption requests without installing another S3 SDK.
async function put(endpoint, resource, bytes = Buffer.alloc(0)) {
  const url = new URL(resource, endpoint);
  const timestamp = new Date().toISOString().replace(/[-:]|\.\d{3}/g, '');
  const day = timestamp.slice(0, 8);
  const digest = sha(bytes);
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const headers = `host:${url.host}\nx-amz-content-sha256:${digest}\nx-amz-date:${timestamp}\n`;
  const canonical = `PUT\n${url.pathname}\n\n${headers}\n${signedHeaders}\n${digest}`;
  const scope = `${day}/us-east-1/s3/aws4_request`;
  const key = hmac(hmac(hmac(hmac(`AWS4${process.env.AWS_SECRET_ACCESS_KEY}`, day), 'us-east-1'), 's3'), 'aws4_request');
  const signature = hmac(key, `AWS4-HMAC-SHA256\n${timestamp}\n${scope}\n${sha(canonical)}`).toString('hex');
  return fetch(url, { method: 'PUT', body: bytes, signal: AbortSignal.timeout(10000), headers: {
    'x-amz-content-sha256': digest, 'x-amz-date': timestamp,
    authorization: `AWS4-HMAC-SHA256 Credential=${process.env.AWS_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  } });
}

test('MinIO S3 multipart archive, idempotency, disk restore and corruption rejection', { timeout: 60000 }, async t => {
  const endpoint = process.env.CHIPTRACE_S3_ENDPOINT;
  assert.ok(endpoint && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY, 'run with an isolated S3 endpoint and fixture credentials');
  const bucket = process.env.CHIPTRACE_S3_BUCKET || 'chiptrace-ci';
  const created = await put(endpoint, `/${bucket}`);
  assert.ok(created.ok || (created.status === 409 && (await created.text()).includes('BucketAlreadyOwnedByYou')));
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'chiptrace-s3-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const input = path.join(root, 'segments');
  await fsp.mkdir(input);
  const largeRecord = `${JSON.stringify({ recordType: 'api_snapshot', captureId: 's3-large', requestBody: { kind: 'text', text: 'x'.repeat(6 * 1024 * 1024) } })}\n`;
  await fsp.writeFile(path.join(input, 'segment-00000000000000000001.sealed.ndjson'), largeRecord);
  await fsp.writeFile(path.join(input, 'segment-00000000000000000002.sealed.ndjson'), '\n');
  const prefix = `ci/${crypto.randomUUID()}`;
  const args = ['--backend', 's3', '--endpoint', endpoint, '--bucket', bucket, '--region', 'us-east-1', '--prefix', prefix];
  const invoke = async args => JSON.parse((await run(binary, args, { env: { ...process.env, AWS_EC2_METADATA_DISABLED: 'true' }, timeout: 45000 })).stdout);
  assert.equal((await invoke(['archive-raw', '--input', input, '--archive-id', 's3-raw', '--multipart-chunk-mib', '5', ...args])).ok, true);
  assert.equal((await invoke(['archive-raw', '--input', input, '--archive-id', 's3-raw', ...args])).idempotent, true);
  assert.equal((await invoke(['verify-raw-archive', '--archive-id', 's3-raw', '--verify-records', ...args])).ok, true);
  const output = path.join(root, 'restored');
  const restoreArgs = ['restore-raw-archive', '--archive-id', 's3-raw', '--output', output, '--verify-records', ...args];
  assert.equal((await invoke(restoreArgs)).ok, true);
  assert.equal((await invoke(['verify-restored-raw', '--input', output])).ok, true);
  assert.equal((await invoke([...restoreArgs, '--replace'])).ok, true);
  const manifest = JSON.parse(await fsp.readFile(path.join(output, 'RAW_MANIFEST.json'), 'utf8'));
  const changed = Buffer.from(largeRecord);
  changed[0] ^= 1;
  assert.equal((await put(endpoint, `/${bucket}/${manifest.segments[0].object_key}`, changed)).ok, true);
  await assert.rejects(invoke([...restoreArgs, '--replace']), error => error.code === 1 && /SHA-256 mismatch/.test(error.stderr));
  assert.equal((await invoke(['verify-restored-raw', '--input', output])).ok, true);
});
