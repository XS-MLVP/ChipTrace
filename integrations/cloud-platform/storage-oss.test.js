'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const run = promisify(execFile);
const binary = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/debug/chiptrace');

// A deliberately small OSS protocol fixture. It validates V1 signatures and
// conditional writes; it does not stand in for an Alibaba Cloud account test.
test('OSS adapter signs immutable writes and restores verified bytes to disk', { timeout: 30000 }, async t => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'chiptrace-oss-protocol-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const objects = new Map();
  const requests = [];
  const bucket = 'chiptrace-test';
  const keyId = 'oss-protocol-test';
  const secret = 'oss-protocol-test-secret';
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const key = decodeURIComponent(url.pathname.slice(1));
    const ossHeaders = Object.keys(req.headers).filter(k => k.startsWith('x-oss-')).sort()
      .map(k => `${k}:${req.headers[k]}\n`).join('');
    const signed = `${req.method}\n${req.headers['content-md5'] || ''}\n${req.headers['content-type'] || ''}\n${req.headers.date}\n${ossHeaders}/${bucket}${url.pathname}`;
    const auth = `OSS ${keyId}:${crypto.createHmac('sha1', secret).update(signed).digest('base64')}`;
    if (req.headers.authorization !== auth || url.hostname !== `${bucket}.oss-test.invalid` || url.search) {
      res.writeHead(403); return res.end('<Error><Code>SignatureDoesNotMatch</Code></Error>');
    }
    requests.push({ method: req.method, key, immutable: req.headers['x-oss-forbid-overwrite'] });
    if (req.method === 'PUT') {
      if (objects.has(key) && req.headers['x-oss-forbid-overwrite'] === 'true') {
        res.writeHead(409); return res.end('<Error><Code>FileAlreadyExists</Code></Error>');
      }
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      objects.set(key, bytes);
      res.writeHead(200, { etag: `"${crypto.createHash('md5').update(bytes).digest('hex')}"` });
      return res.end();
    }
    const bytes = objects.get(key);
    if (!bytes) { res.writeHead(404); return res.end('<Error><Code>NoSuchKey</Code></Error>'); }
    const headers = { 'content-length': bytes.length, 'last-modified': 'Wed, 14 Oct 2026 00:00:00 GMT', etag: `"${crypto.createHash('md5').update(bytes).digest('hex')}"` };
    if (req.method === 'HEAD') { res.writeHead(200, headers); return res.end(); }
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    const range = req.headers.range?.match(/^bytes=(\d+)-(\d*)$/);
    if (range) {
      const start = Number(range[1]);
      const end = Math.min(range[2] ? Number(range[2]) : bytes.length - 1, bytes.length - 1);
      const part = bytes.subarray(start, end + 1);
      res.writeHead(206, { ...headers, 'content-length': part.length, 'content-range': `bytes ${start}-${end}/${bytes.length}` });
      return res.end(part);
    }
    res.writeHead(200, headers); res.end(bytes);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const env = { ...process.env, OSS_ACCESS_KEY_ID: keyId, OSS_ACCESS_KEY_SECRET: secret,
    ALIBABA_CLOUD_ACCESS_KEY_ID: keyId, ALIBABA_CLOUD_ACCESS_KEY_SECRET: secret,
    ALIBABA_CLOUD_SECURITY_TOKEN: '', OSS_SECURITY_TOKEN: '',
    HTTP_PROXY: `http://127.0.0.1:${server.address().port}`, http_proxy: '', NO_PROXY: '', no_proxy: '', ALL_PROXY: '', all_proxy: '' };
  const input = path.join(root, 'segments');
  await fsp.mkdir(input);
  const record = `${JSON.stringify({ recordType: 'api_snapshot', captureId: 'oss-wire', requestBody: { kind: 'json', value: { model: 'synthetic', input: [] } } })}\n`;
  await fsp.writeFile(path.join(input, 'segment-00000000000000000001.sealed.ndjson'), record);
  await fsp.writeFile(path.join(input, 'segment-00000000000000000002.sealed.ndjson'), '\n');
  const args = ['--backend', 'oss', '--endpoint', 'http://oss-test.invalid', '--bucket', bucket, '--prefix', 'ci/chiptrace'];
  const invoke = async args => JSON.parse((await run(binary, args, { env, timeout: 20000 })).stdout);
  const first = await invoke(['archive-raw', '--input', input, '--archive-id', 'oss-raw', ...args]);
  assert.equal(first.ok, true);
  assert.equal(requests.filter(r => r.method === 'PUT').at(-1).key, 'ci/chiptrace/raw/oss-raw/CHECKPOINT.json');
  assert.ok(requests.filter(r => r.method === 'PUT').every(r => r.immutable === 'true'));
  assert.equal((await invoke(['archive-raw', '--input', input, '--archive-id', 'oss-raw', ...args])).idempotent, true);
  const output = path.join(root, 'restored');
  const beforeRestore = requests.length;
  const restored = await invoke(['restore-raw-archive', '--archive-id', 'oss-raw', '--output', output, '--verify-records', ...args]);
  assert.equal(restored.ok, true);
  const payloadReads = requests.slice(beforeRestore).filter(r => r.method === 'GET' && r.key.includes('/objects/'));
  assert.equal(payloadReads.length, 2, 'download each data/empty object once');
  assert.equal((await invoke(['verify-restored-raw', '--input', output])).ok, true);
  assert.equal(await fsp.readFile(path.join(output, 'segments/shard-00000/segment-00000000000000000001.sealed.ndjson'), 'utf8'), record);
  const manifest = JSON.parse(await fsp.readFile(path.join(output, 'RAW_MANIFEST.json'), 'utf8'));
  const payloadKey = manifest.segments[0].object_key;
  const tampered = Buffer.from(objects.get(payloadKey));
  tampered[0] ^= 1;
  objects.set(payloadKey, tampered);
  await assert.rejects(run(binary, ['restore-raw-archive', '--archive-id', 'oss-raw', '--output', output, '--replace', ...args], { env }), error => error.code === 1 && /SHA-256 mismatch/.test(error.stderr));
  assert.equal((await invoke(['verify-restored-raw', '--input', output])).ok, true);
});
