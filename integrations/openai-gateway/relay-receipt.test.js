'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { DurableCaptureOutbox } = require('./durable-outbox');

const binary = process.env.CHIPTRACE_BIN || path.resolve(__dirname, '../../target/debug/chiptrace');
const token = 'synthetic-wire-receipt-credential-at-least-32-bytes';
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const run = promisify(execFile);

async function reservePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function start(args) {
  const child = spawn(binary, args, { env: { ...process.env, CHIPTRACE_INGEST_TOKEN: token,
    TOKIO_WORKER_THREADS: '2', RAYON_NUM_THREADS: '2' }, stdio: ['ignore', 'ignore', 'pipe'] });
  const handle = { child, stderr: '', ended: false };
  child.stderr.on('data', chunk => { handle.stderr = `${handle.stderr}${chunk}`.slice(-4096); });
  handle.closed = new Promise(resolve => {
    child.once('error', error => { handle.ended = true; handle.stderr = error.message; resolve({ error }); });
    child.once('close', (code, signal) => { handle.ended = true; resolve({ code, signal }); });
  });
  return handle;
}

test('identity aliases fail cloud quality ACKs while exact Raw and equal aliases survive restart',
  { timeout: 60000 }, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-identity-alias-'));
    let collector;
    let relay;
    let passed = false;
    t.after(async () => {
      if (relay) await stop(relay);
      if (collector) await stop(collector);
      if (passed && process.env.CHIPTRACE_RECEIPT_KEEP !== '1') await fs.rm(root, { recursive: true, force: true });
      else t.diagnostic(`isolated identity alias evidence retained: ${root}`);
    });
    const collectorUrl = `http://127.0.0.1:${await reservePort()}`;
    const collectorArgs = ['collector', '--host', '127.0.0.1', '--port', new URL(collectorUrl).port,
      '--root', path.join(root, 'collector'), '--state-root', path.join(root, 'collector-state')];
    collector = start(collectorArgs);
    await health(collectorUrl, collector);
    const relayUrl = `http://127.0.0.1:${await reservePort()}`;
    const relayArgs = ['relay', '--host', '127.0.0.1', '--port', new URL(relayUrl).port,
      '--root', path.join(root, 'relay'), '--state-root', path.join(root, 'relay-state'),
      '--delivery-state-root', path.join(root, 'delivery'), '--collector-url', collectorUrl];
    relay = start(relayArgs);
    await health(relayUrl, relay);
    const expected = new Map();
    const marker = 'PRIVATE_ALIAS_BODY_MUST_NOT_APPEAR';
    const session = '11111111-1111-1111-1111-111111111111';
    const attr = (key, value) => ({ key, value: { stringValue: value } });
    let first;
    for (const endpoint of ['logs', 'traces']) {
      for (const [key, equal, conflict] of [
        ['session.id', session, marker], ['thread_id', session, '22222222-2222-2222-2222-222222222222'],
        ['turn_id', 'native-turn', marker], ['root_turn_id', 'root-turn', marker],
        ['codex.root_turn_id', 'root-turn', marker],
      ]) {
        for (const [candidate, invalid] of [[conflict, true], [equal, false]]) {
          const attributes = [attr('event.name', 'codex.user_prompt'), attr('test.utf8', '中文 🧪'),
            attr('private.body', marker)];
          const envelope = { [endpoint === 'logs' ? 'resourceLogs' : 'resourceSpans']: [{
            resource: { attributes: [attr('conversation.id', session)] },
            [endpoint === 'logs' ? 'scopeLogs' : 'scopeSpans']: [{
              scope: { attributes: [attr('turn.id', 'native-turn'), attr('root_turn.id', 'root-turn')] },
              [endpoint === 'logs' ? 'logRecords' : 'spans']: [
                { name: 'codex.turn', attributes },
                { name: 'codex.turn', attributes: [...attributes, attr(key, candidate)] },
              ],
            }],
          }] };
          const body = JSON.stringify(envelope, null, 2) + '\n';
          expected.set(digest(Buffer.from(body)), body);
          first ||= { endpoint, body };
          for (let attempt = 0; attempt < (invalid ? 2 : 1); attempt++) {
            const response = await fetch(`${relayUrl}/otel/v1/${endpoint}`, { method: 'POST',
              headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
              body, signal: AbortSignal.timeout(5000) });
            const receipt = await response.json();
            const detail = invalid ? receipt : receipt.chiptrace;
            assert.equal(response.status, invalid ? 400 : 200, `${endpoint} ${key}: identity aliases must agree`);
            assert.equal(detail.durable, true);
            assert.equal(detail.captures, 1);
            assert.equal(detail.duplicates, attempt);
            assert.equal(detail.summary.source_records, 2);
            assert.equal(detail.summary.derived_captures, 0);
            assert.equal(detail.summary.conversion_errors.length, invalid ? 1 : 0);
            if (invalid) {
              assert.equal(receipt.ok, false);
              assert.equal(receipt.local_durable, true);
              assert.equal(receipt.reason, 'cloud_ingest_quality_error');
              assert.equal(receipt.unattributed_quality_errors, 1);
              assert.match(receipt.detail, /conflict/);
              assert.ok(!JSON.stringify(receipt).includes(candidate), 'quality errors must omit conflicting identity values');
            }
            assert.ok(!JSON.stringify(receipt).includes(marker), 'ACK diagnostics must omit identities and bodies');
          }
        }
      }
    }
    const delivered = await health(relayUrl, relay,
      h => h.delivered === expected.size && h.pending === 0 && h.inflight === 0);
    assert.equal(delivered.conservation_ok, true);
    assert.equal(delivered.ingest_coverage.quality_errors, 20);
    await health(collectorUrl, collector, h => h.collector.captures === expected.size);
    for (const url of [relayUrl, collectorUrl]) {
      const response = await fetch(`${url}/flush`, { method: 'POST',
        headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
      assert.equal(response.ok, true);
    }
    const collectorRaw = await sealedRecords(path.join(root, 'collector'));
    assert.equal(collectorRaw.size, expected.size);
    assert.deepEqual(await sealedRecords(path.join(root, 'relay')), collectorRaw);
    for (const { record } of collectorRaw.values()) {
      const batch = record.telemetryBatch;
      assert.equal(batch.raw_json, expected.get(batch.raw_sha256));
      assert.equal(batch.raw_bytes, Buffer.byteLength(batch.raw_json));
      assert.equal(batch.raw_sha256, digest(Buffer.from(batch.raw_json)));
    }
    const audit = () => run(binary, ['audit-session-context', '--input', path.join(root, 'collector'),
      '--session-id', session, '--sample-limit', '0'], { maxBuffer: 1024 * 1024 });
    await assert.rejects(audit, error => error.code === 1 && /conflict/.test(error.stderr)
      && error.stdout === '' && !error.stderr.includes(marker));
    assert.equal((await stop(relay)).code, 0);
    assert.equal((await stop(collector)).code, 0);
    collector = start(collectorArgs);
    await health(collectorUrl, collector, h => h.collector.captures === expected.size);
    relay = start(relayArgs);
    await health(relayUrl, relay, h => h.delivered === expected.size && h.conservation_ok);
    const replay = await fetch(`${relayUrl}/otel/v1/${first.endpoint}`, { method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: first.body, signal: AbortSignal.timeout(5000) });
    const receipt = await replay.json();
    assert.equal(replay.status, 400);
    assert.equal(receipt.durable, true);
    assert.equal(receipt.duplicates, 1);
    await assert.rejects(audit, { code: 1 });
    assert.deepEqual(await sealedRecords(path.join(root, 'collector')), collectorRaw);
    passed = true;
  });

test('malformed OTLP containers and metadata fail HTTP and source auditing without losing either WAL',
  { timeout: 30000 }, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-otlp-shape-'));
    let collector;
    let relay;
    let passed = false;
    t.after(async () => {
      if (relay) await stop(relay);
      if (collector) await stop(collector);
      if (passed && process.env.CHIPTRACE_RECEIPT_KEEP !== '1') await fs.rm(root, { recursive: true, force: true });
      else t.diagnostic(`isolated OTLP shape evidence retained: ${root}`);
    });
    const collectorUrl = `http://127.0.0.1:${await reservePort()}`;
    const collectorArgs = ['collector', '--host', '127.0.0.1', '--port', new URL(collectorUrl).port,
      '--root', path.join(root, 'collector'), '--state-root', path.join(root, 'collector-state')];
    collector = start(collectorArgs);
    await health(collectorUrl, collector);
    const relayUrl = `http://127.0.0.1:${await reservePort()}`;
    const relayArgs = ['relay', '--host', '127.0.0.1', '--port', new URL(relayUrl).port,
      '--root', path.join(root, 'relay'), '--state-root', path.join(root, 'relay-state'),
      '--delivery-state-root', path.join(root, 'delivery'), '--collector-url', collectorUrl];
    relay = start(relayArgs);
    await health(relayUrl, relay);
    const expected = new Map();
    const marker = 'PRIVATE_MALFORMED_BODY_MUST_NOT_APPEAR_IN_DIAGNOSTICS';
    let metadataReplay;
    const attr = (key, value) => ({ key, value: { stringValue: value } });
    for (const endpoint of ['logs', 'traces']) {
      const resources = endpoint === 'logs' ? 'resourceLogs' : 'resourceSpans';
      const scopes = endpoint === 'logs' ? 'scopeLogs' : 'scopeSpans';
      const records = endpoint === 'logs' ? 'logRecords' : 'spans';
      const valid = { [scopes]: [{ [records]: [{ name: 'codex.turn', attributes: [
        attr('event.name', 'codex.user_prompt'), attr('conversation.id', 'native-session'),
        attr('turn.id', 'native-turn'), attr('test.utf8', '中文 🧪'),
      ] }] }] };
      for (const layer of ['container', 'resource', 'scope', 'record', 'resource-entry',
        'scope-entry', 'record-entry', 'resource-message', 'scope-message']) {
        const malformed = structuredClone(valid);
        if (layer === 'container') malformed[scopes][0][records] = { private: marker };
        if (layer === 'resource') malformed.resource = { attributes: { private: marker } };
        if (layer === 'scope') malformed[scopes][0].scope = { attributes: { private: marker } };
        if (layer === 'record') malformed[scopes][0][records][0].attributes = { private: marker };
        if (layer === 'resource-entry') malformed.resource = { attributes: [null] };
        if (layer === 'scope-entry') malformed[scopes][0].scope = { attributes: [null] };
        if (layer === 'record-entry') malformed[scopes][0][records][0].attributes.push(null);
        if (layer === 'resource-message') malformed.resource = [marker];
        if (layer === 'scope-message') malformed[scopes][0].scope = [marker];
        const envelope = { [resources]: [valid, malformed] };
        const body = JSON.stringify(envelope, null, 2) + '\n';
        if (layer === 'resource') metadataReplay ||= { endpoint, body };
        expected.set(digest(Buffer.from(body)), body);
        for (let attempt = 0; attempt < 2; attempt++) {
          const response = await fetch(`${relayUrl}/otel/v1/${endpoint}`, { method: 'POST',
            headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
            body, signal: AbortSignal.timeout(5000) });
          const receipt = await response.json();
          assert.equal(response.status, 400, `${endpoint} ${layer}: a valid record must not hide malformed metadata`);
          assert.equal(receipt.ok, false);
          assert.equal(receipt.durable, true);
          assert.equal(receipt.local_durable, true);
          assert.equal(receipt.reason, 'cloud_ingest_quality_error');
          assert.equal(receipt.captures, 1);
          assert.equal(receipt.duplicates, attempt);
          assert.equal(receipt.summary.source_records, layer === 'container' ? 1 : 2);
          assert.equal(receipt.summary.derived_captures, 0);
          assert.equal(receipt.summary.conversion_errors.length, 1);
          assert.equal(receipt.unattributed_quality_errors, 1);
          assert.ok(!JSON.stringify(receipt).includes(marker));
        }
      }
    }
    assert.equal(expected.size, 18);
    const delivered = await health(relayUrl, relay,
      h => h.delivered === expected.size && h.pending === 0 && h.inflight === 0);
    assert.equal(delivered.conservation_ok, true);
    assert.equal(delivered.ingest_coverage.quality_errors, 2 * expected.size);
    await health(collectorUrl, collector, h => h.collector.captures === expected.size);
    for (const url of [relayUrl, collectorUrl]) {
      const response = await fetch(`${url}/flush`, { method: 'POST',
        headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
      assert.equal(response.ok, true);
    }
    const relayRaw = await sealedRecords(path.join(root, 'relay'));
    const collectorRaw = await sealedRecords(path.join(root, 'collector'));
    assert.equal(collectorRaw.size, expected.size);
    assert.deepEqual(collectorRaw, relayRaw);
    for (const { record } of collectorRaw.values()) {
      const batch = record.telemetryBatch;
      assert.equal(batch.raw_json, expected.get(batch.raw_sha256));
      assert.equal(batch.raw_bytes, Buffer.byteLength(batch.raw_json));
      assert.equal(batch.raw_sha256, digest(Buffer.from(batch.raw_json)));
    }
    const audit = () => run(binary, ['audit-session-context', '--input', path.join(root, 'collector'),
      '--session-id', 'native-session', '--sample-limit', '0'], { maxBuffer: 1024 * 1024 });
    await assert.rejects(audit, error => error.code === 1
      && /OTLP.*must be an? (array|object)/.test(error.stderr) && !error.stderr.includes(marker));
    assert.equal((await stop(relay)).code, 0);
    assert.equal((await stop(collector)).code, 0);
    collector = start(collectorArgs);
    await health(collectorUrl, collector, h => h.collector.captures === expected.size);
    relay = start(relayArgs);
    await health(relayUrl, relay, h => h.delivered === expected.size && h.conservation_ok);
    await assert.rejects(audit, { code: 1 });
    const replay = await fetch(`${relayUrl}/otel/v1/${metadataReplay.endpoint}`, { method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: metadataReplay.body, signal: AbortSignal.timeout(5000) });
    const replayReceipt = await replay.json();
    assert.equal(replay.status, 400);
    assert.equal(replayReceipt.durable, true);
    assert.equal(replayReceipt.duplicates, 1);
    assert.equal(replayReceipt.summary.conversion_errors.length, 1);
    assert.ok(!JSON.stringify(replayReceipt).includes(marker));
    assert.deepEqual(await sealedRecords(path.join(root, 'collector')), collectorRaw);
    passed = true;
  });

test('conflicting tool attributes fail quality ACKs while valid neighbors and exact Raw survive restart',
  { timeout: 60000 }, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-tool-attributes-'));
    let collector;
    let relay;
    let passed = false;
    t.after(async () => {
      if (relay) await stop(relay);
      if (collector) await stop(collector);
      if (passed && process.env.CHIPTRACE_RECEIPT_KEEP !== '1') await fs.rm(root, { recursive: true, force: true });
      else t.diagnostic(`isolated tool attribute evidence retained: ${root}`);
    });
    const collectorUrl = `http://127.0.0.1:${await reservePort()}`;
    const collectorArgs = ['collector', '--host', '127.0.0.1', '--port', new URL(collectorUrl).port,
      '--root', path.join(root, 'collector'), '--state-root', path.join(root, 'collector-state')];
    collector = start(collectorArgs);
    await health(collectorUrl, collector);
    const relayUrl = `http://127.0.0.1:${await reservePort()}`;
    const relayArgs = ['relay', '--host', '127.0.0.1', '--port', new URL(relayUrl).port,
      '--root', path.join(root, 'relay'), '--state-root', path.join(root, 'relay-state'),
      '--delivery-state-root', path.join(root, 'delivery'), '--collector-url', collectorUrl];
    relay = start(relayArgs);
    await health(relayUrl, relay);
    const marker = 'PRIVATE_TOOL_OUTPUT_中文_🧪';
    const attr = (key, value) => value === undefined ? { key }
      : { key, value: { [typeof value === 'boolean' ? 'boolValue' : 'stringValue']: value } };
    const expected = new Map();
    const toolIds = new Set();
    let first;
    for (const endpoint of ['logs', 'traces']) {
      const resources = endpoint === 'logs' ? 'resourceLogs' : 'resourceSpans';
      const scopes = endpoint === 'logs' ? 'scopeLogs' : 'scopeSpans';
      const records = endpoint === 'logs' ? 'logRecords' : 'spans';
      for (const layer of ['resource', 'scope', 'record']) {
        for (const [name, values, invalid] of [
          ['truncated-first', [true, false], true], ['truncated-last', [false, true], true],
          ['missing-first', [undefined, false], true], ['missing-last', [false, undefined], true],
          ['equal', [false, false], false],
        ]) {
          const id = `${endpoint}-${layer}-${name}`;
          const record = callId => ({ name: 'codex.tool_result', attributes: [
            attr('event.name', 'codex.tool_result'), attr('conversation.id', 'native-session'),
            attr('turn.id', 'native-turn'), attr('call_id', callId), attr('tool_name', 'exec_command'),
            attr('tool_namespace', 'functions'), attr('arguments', '{}'), attr('success', true),
            attr('output_truncated', false), attr('output', marker),
          ] });
          const good = { [scopes]: [{ [records]: [record(`good-${id}`)] }] };
          const candidate = record(`candidate-${id}`);
          const scope = { [records]: [candidate] };
          const resource = { [scopes]: [scope] };
          const duplicate = values.map(value => attr('output_truncated', value));
          if (layer === 'resource') resource.resource = { attributes: duplicate };
          if (layer === 'scope') scope.scope = { attributes: duplicate };
          if (layer === 'record') candidate.attributes = [
            ...candidate.attributes.filter(a => a.key !== 'output_truncated'), ...duplicate,
          ];
          const body = JSON.stringify({ [resources]: [good, resource] }, null, 2) + '\n';
          expected.set(digest(Buffer.from(body)), body);
          if (endpoint === 'logs') {
            toolIds.add(`good-${id}`);
            if (!invalid) toolIds.add(`candidate-${id}`);
          }
          first ||= { endpoint, body };
          const derived = endpoint === 'logs' ? (invalid ? 1 : 2) : 0;
          for (let attempt = 0; attempt < (invalid ? 2 : 1); attempt++) {
            const response = await fetch(`${relayUrl}/otel/v1/${endpoint}`, { method: 'POST',
              headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
              body, signal: AbortSignal.timeout(5000) });
            const receipt = await response.json();
            const detail = invalid ? receipt : receipt.chiptrace;
            assert.equal(response.status, invalid ? 400 : 200, id);
            assert.equal(detail.durable, true);
            assert.equal(detail.captures, 1 + derived);
            assert.equal(detail.duplicates, attempt * (1 + derived));
            assert.equal(detail.summary.source_records, 2);
            assert.equal(detail.summary.derived_captures, derived);
            assert.equal(detail.summary.conversion_errors.length, invalid ? 1 : 0);
            if (invalid) {
              assert.equal(receipt.ok, false);
              assert.equal(receipt.local_durable, true);
              assert.equal(receipt.reason, 'cloud_ingest_quality_error');
              assert.equal(receipt.unattributed_quality_errors, 1);
              assert.match(receipt.detail, /conflicting duplicate OTLP attribute/);
            }
            assert.ok(!JSON.stringify(receipt).includes(marker));
          }
        }
      }
    }
    assert.equal(expected.size, 30);
    assert.equal(toolIds.size, 18);
    const captures = expected.size + toolIds.size;
    const delivered = await health(relayUrl, relay,
      h => h.delivered === captures && h.pending === 0 && h.inflight === 0);
    assert.equal(delivered.conservation_ok, true);
    assert.equal(delivered.ingest_coverage.quality_errors, 48);
    await health(collectorUrl, collector, h => h.collector.captures === captures);
    for (const url of [relayUrl, collectorUrl]) {
      const response = await fetch(`${url}/flush`, { method: 'POST',
        headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
      assert.equal(response.ok, true);
    }
    const collectorRaw = await sealedRecords(path.join(root, 'collector'));
    assert.equal(collectorRaw.size, captures);
    assert.deepEqual(await sealedRecords(path.join(root, 'relay')), collectorRaw);
    const foundTools = new Set();
    for (const { record } of collectorRaw.values()) {
      if (record.telemetryBatch) {
        const batch = record.telemetryBatch;
        assert.equal(batch.raw_json, expected.get(batch.raw_sha256));
        assert.equal(batch.raw_bytes, Buffer.byteLength(batch.raw_json));
        assert.equal(batch.raw_sha256, digest(Buffer.from(batch.raw_json)));
      } else {
        assert.ok(record.toolExecution);
        foundTools.add(record.toolExecution.call_id);
        assert.equal(record.toolExecution.result, marker);
        assert.equal(record.toolExecution.output_truncated, false);
      }
    }
    assert.deepEqual(foundTools, toolIds);
    const audit = () => run(binary, ['audit-session-context', '--input', path.join(root, 'collector'),
      '--session-id', 'native-session', '--sample-limit', '0'], { maxBuffer: 1024 * 1024 });
    const refused = error => error.code === 1 && error.stdout === ''
      && /conflicting duplicate OTLP attribute/.test(error.stderr) && !error.stderr.includes(marker);
    await assert.rejects(audit, refused);
    assert.equal((await stop(relay)).code, 0);
    assert.equal((await stop(collector)).code, 0);
    collector = start(collectorArgs);
    await health(collectorUrl, collector, h => h.collector.captures === captures);
    relay = start(relayArgs);
    await health(relayUrl, relay, h => h.delivered === captures && h.conservation_ok);
    const replay = await fetch(`${relayUrl}/otel/v1/${first.endpoint}`, { method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: first.body, signal: AbortSignal.timeout(5000) });
    const receipt = await replay.json();
    assert.equal(replay.status, 400);
    assert.equal(receipt.durable, true);
    assert.equal(receipt.duplicates, 2);
    assert.equal(receipt.summary.derived_captures, 1);
    assert.ok(!JSON.stringify(receipt).includes(marker));
    await assert.rejects(audit, refused);
    assert.deepEqual(await sealedRecords(path.join(root, 'collector')), collectorRaw);
    assert.deepEqual(await sealedRecords(path.join(root, 'relay')), collectorRaw);
    passed = true;
  });

test('cloud ingest reports duplicate context conflicts after preserving exact Raw in both WALs',
  { timeout: 30000 }, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-cloud-context-'));
    let collector;
    let relay;
    t.after(async () => {
      if (relay) await stop(relay);
      if (collector) await stop(collector);
      await fs.rm(root, { recursive: true, force: true });
    });
    const collectorPort = await reservePort();
    const collectorUrl = `http://127.0.0.1:${collectorPort}`;
    const collectorArgs = ['collector', '--host', '127.0.0.1', '--port', String(collectorPort),
      '--root', path.join(root, 'collector'), '--state-root', path.join(root, 'collector-state')];
    collector = start(collectorArgs);
    await health(collectorUrl, collector);
    const relayPort = await reservePort();
    const relayUrl = `http://127.0.0.1:${relayPort}`;
    const relayArgs = ['relay', '--host', '127.0.0.1', '--port', String(relayPort),
      '--root', path.join(root, 'relay'), '--state-root', path.join(root, 'relay-state'),
      '--delivery-state-root', path.join(root, 'delivery'), '--collector-url', collectorUrl];
    relay = start(relayArgs);
    await health(relayUrl, relay);
    const marker = 'private-conflicting-context-value';
    const attr = (key, value) => ({ key, value: { stringValue: value } });
    const expected = new Map();
    for (const endpoint of ['logs', 'traces']) {
      for (const layer of ['resource', 'scope', 'record', 'equal']) {
        await t.test(`${endpoint}: ${layer}`, async () => {
          const duplicate = [attr('conversation.id', layer === 'equal' ? 'native-session' : marker),
            attr('conversation.id', 'native-session')];
          const attributes = [attr('event.name', 'codex.user_prompt'), attr('turn.id', 'native-turn'),
            attr('test.utf8', '中文 🧪 原样保存')];
          const record = endpoint === 'logs' ? { body: { stringValue: '原始日志' } } : { name: 'codex.turn' };
          const records = [{ ...record, attributes },
            { ...record, attributes: [...attributes,
              ...(layer === 'record' || layer === 'equal' ? duplicate : [])] }];
          const scope = { scope: { attributes: layer === 'scope' ? duplicate : [] },
            [endpoint === 'logs' ? 'logRecords' : 'spans']: records };
          const envelope = { [endpoint === 'logs' ? 'resourceLogs' : 'resourceSpans']: [{
            resource: { attributes: layer === 'resource' ? duplicate : [] },
            [endpoint === 'logs' ? 'scopeLogs' : 'scopeSpans']: [scope],
          }] };
          const body = JSON.stringify(envelope, null, 2) + '\n';
          expected.set(digest(Buffer.from(body)), body);
          for (let attempt = 0; attempt < (layer === 'equal' ? 1 : 2); attempt++) {
            const response = await fetch(`${relayUrl}/otel/v1/${endpoint}`, { method: 'POST',
              headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
              body, signal: AbortSignal.timeout(5000) });
            const receipt = await response.json();
            const detail = layer === 'equal' ? receipt.chiptrace : receipt;
            assert.equal(response.status, layer === 'equal' ? 200 : 400);
            assert.equal(detail.ok, layer === 'equal');
            assert.equal(detail.durable, true);
            assert.equal(detail.captures, 1);
            assert.equal(detail.duplicates, attempt);
            assert.equal(detail.summary.source_records, 2);
            assert.equal(detail.summary.derived_captures, 0);
            if (layer === 'equal') assert.deepEqual(detail.summary.conversion_errors, []);
            else {
              assert.equal(receipt.local_durable, true);
              assert.equal(receipt.reason, 'cloud_ingest_quality_error');
              assert.equal(detail.summary.conversion_errors.length, 1);
              assert.match(receipt.detail, /conflicting duplicate context attribute/);
            }
            assert.ok(!JSON.stringify(receipt).includes(marker));
          }
        });
      }
    }
    const delivered = await health(relayUrl, relay,
      h => h.delivered === 8 && h.pending === 0 && h.inflight === 0);
    assert.equal(delivered.conservation_ok, true);
    assert.equal(delivered.ingest_coverage.quality_errors, 12);
    await health(collectorUrl, collector, h => h.collector.captures === 8);
    for (const url of [relayUrl, collectorUrl]) {
      const response = await fetch(`${url}/flush`, { method: 'POST',
        headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
      assert.equal(response.ok, true);
    }
    const relayRaw = await sealedRecords(path.join(root, 'relay'));
    const collectorRaw = await sealedRecords(path.join(root, 'collector'));
    assert.equal(relayRaw.size, 8);
    assert.deepEqual(collectorRaw, relayRaw);
    for (const { record } of collectorRaw.values()) {
      assert.equal(record.recordType, 'telemetry_batch');
      const batch = record.telemetryBatch;
      const body = expected.get(batch.raw_sha256);
      assert.equal(typeof body, 'string');
      assert.equal(batch.raw_json, body);
      assert.equal(batch.raw_bytes, Buffer.byteLength(body));
    }
    assert.equal((await stop(relay)).code, 0);
    assert.equal((await stop(collector)).code, 0);
    collector = start(collectorArgs);
    await health(collectorUrl, collector, h => h.collector.captures === 8);
    relay = start(relayArgs);
    await health(relayUrl, relay, h => h.delivered === 8 && h.conservation_ok);
    assert.deepEqual(await sealedRecords(path.join(root, 'collector')), collectorRaw);
  });

test('cloud ingest distinguishes Stock process outcomes from external namespaced tool text',
  { timeout: 30000 }, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-process-namespace-'));
    let collector;
    let relay;
    t.after(async () => {
      if (relay) await stop(relay);
      if (collector) await stop(collector);
      await fs.rm(root, { recursive: true, force: true });
    });
    const collectorUrl = `http://127.0.0.1:${await reservePort()}`;
    collector = start(['collector', '--host', '127.0.0.1', '--port', new URL(collectorUrl).port,
      '--root', path.join(root, 'collector'), '--state-root', path.join(root, 'collector-state')]);
    await health(collectorUrl, collector);
    const relayUrl = `http://127.0.0.1:${await reservePort()}`;
    relay = start(['relay', '--host', '127.0.0.1', '--port', new URL(relayUrl).port,
      '--root', path.join(root, 'relay'), '--state-root', path.join(root, 'relay-state'),
      '--delivery-state-root', path.join(root, 'delivery'), '--collector-url', collectorUrl]);
    await health(relayUrl, relay);

    const cases = [
      { id: 'builtin-failed', namespace: 'functions', tool: 'exec_command', success: true,
        line: 'Process exited with code 7', outcome: { state: 'exited', exit_code: 7, success: false } },
      { id: 'builtin-running', namespace: 'functions', tool: 'exec_command', success: true,
        line: 'Process running with session ID 4242', outcome: { state: 'running', session_id: 4242, success: null } },
      { id: 'builtin-finished', namespace: 'functions', tool: 'write_stdin', success: true,
        line: 'Process exited with code 0', outcome: { state: 'exited', exit_code: 0, success: true } },
      { id: 'external-failed-text', namespace: 'client', tool: 'exec_command', success: true,
        line: 'Process exited with code 7', outcome: null },
      { id: 'external-running-text', namespace: 'client', tool: 'write_stdin', success: true,
        line: 'Process running with session ID 4242', outcome: null },
      { id: 'external-success-text', namespace: 'client', tool: 'exec_command', success: false,
        line: 'Process exited with code 0', outcome: null },
    ];
    const attr = (key, value) => ({ key, value: { [typeof value === 'boolean' ? 'boolValue' : 'stringValue']: value } });
    const output = value => `Chunk ID: abc123\nWall time: 0.0100 seconds\n${value.line}\nOutput:\n中文 🧪\nProcess exited with code 99\n`;
    const body = JSON.stringify({ resourceLogs: [{ scopeLogs: [{ logRecords: cases.map(value => ({
      timeUnixNano: '1788307201000000000',
      attributes: [attr('event.name', 'codex.tool_result'), attr('conversation.id', 'synthetic-session'),
        attr('turn.id', 'synthetic-turn'), attr('call_id', value.id), attr('tool_name', value.tool),
        attr('tool_namespace', value.namespace), attr('arguments', '{}'), attr('success', value.success),
        attr('output_truncated', false), attr('output', output(value))],
    })) }] }] }, null, 2) + '\n';
    const response = await fetch(`${relayUrl}/otel/v1/logs`, { method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body, signal: AbortSignal.timeout(5000) });
    const receipt = await response.json();
    assert.equal(response.status, 200);
    assert.equal(receipt.chiptrace.durable, true);
    assert.equal(receipt.chiptrace.summary.derived_captures, cases.length);
    assert.deepEqual(receipt.chiptrace.summary.conversion_errors, []);
    const delivered = await health(relayUrl, relay,
      h => h.delivered === cases.length + 1 && h.pending === 0 && h.inflight === 0);
    assert.equal(delivered.conservation_ok, true);
    await health(collectorUrl, collector, h => h.collector.captures === cases.length + 1);
    for (const url of [relayUrl, collectorUrl]) {
      const flushed = await fetch(`${url}/flush`, { method: 'POST',
        headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
      assert.equal(flushed.ok, true);
    }
    const relayRaw = await sealedRecords(path.join(root, 'relay'));
    const collectorRaw = await sealedRecords(path.join(root, 'collector'));
    assert.deepEqual(collectorRaw, relayRaw);
    const records = [...collectorRaw.values()].map(value => value.record);
    const batch = records.find(value => value.recordType === 'telemetry_batch').telemetryBatch;
    assert.equal(batch.raw_json, body);
    assert.equal(batch.raw_bytes, Buffer.byteLength(body));
    assert.equal(batch.raw_sha256, digest(Buffer.from(body)));
    for (const value of cases) {
      const execution = records.find(record => record.toolExecution?.call_id === value.id).toolExecution;
      assert.equal(execution.name, value.namespace === 'functions' ? value.tool : `${value.namespace}.${value.tool}`);
      assert.equal(execution.status, value.success ? 'success' : 'error');
      assert.equal(execution.result, output(value));
      assert.equal(execution.result_content_captured, true);
      assert.equal(execution.output_truncated, false);
      assert.deepEqual(execution.process_outcome, value.outcome && { kind: 'process', ...value.outcome,
        provenance: 'stock_codex.unified_exec.log_output.header' }, value.id);
    }
  });

async function stop(handle) {
  if (handle.ended) return handle.closed;
  handle.child.kill('SIGINT');
  const timer = setTimeout(() => handle.child.kill('SIGKILL'), 5000);
  try { return await handle.closed; } finally { clearTimeout(timer); }
}

async function health(url, handle, predicate = () => true) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline && !handle.ended) {
    try {
      const response = await fetch(`${url}/health`, { signal: AbortSignal.timeout(500) });
      if (response.ok) {
        const value = await response.json();
        if (predicate(value)) return value;
      }
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.fail(`isolated receipt service did not reach the expected state: ${handle.stderr}`);
}

async function sealedRecords(root) {
  const records = new Map();
  const segments = path.join(root, 'segments');
  for (const name of await fs.readdir(segments)) {
    if (!name.endsWith('.ndjson') || name.endsWith('.open.ndjson')) continue;
    for (const line of (await fs.readFile(path.join(segments, name), 'utf8')).split('\n').filter(Boolean)) {
      const record = JSON.parse(line);
      assert.equal(records.has(record.captureId), false);
      records.set(record.captureId, { record, line, sha256: digest(Buffer.from(line, 'utf8')) });
    }
  }
  return records;
}

test('gateway requires a real Relay byte receipt before removal and Collector preserves the exact WAL',
  { timeout: 30000 }, async t => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-wire-receipt-'));
    const outboxes = [];
    let collector;
    let relay;
    let proxy;
    t.after(async () => {
      for (const outbox of outboxes) {
        await outbox.close();
        if (outbox.drainPromise) await outbox.drainPromise;
      }
      if (proxy) {
        proxy.closeAllConnections();
        await new Promise(resolve => proxy.close(resolve));
      }
      if (relay) await stop(relay);
      if (collector) await stop(collector);
      await fs.rm(root, { recursive: true, force: true });
    });
    const collectorPort = await reservePort();
    const collectorUrl = `http://127.0.0.1:${collectorPort}`;
    const collectorArgs = ['collector', '--host', '127.0.0.1', '--port', String(collectorPort),
      '--root', path.join(root, 'collector'), '--state-root', path.join(root, 'collector-state')];
    collector = start(collectorArgs);
    await health(collectorUrl, collector);
    const relayPort = await reservePort();
    const relayUrl = `http://127.0.0.1:${relayPort}`;
    const relayArgs = ['relay', '--host', '127.0.0.1', '--port', String(relayPort),
      '--root', path.join(root, 'relay'), '--state-root', path.join(root, 'relay-state'),
      '--delivery-state-root', path.join(root, 'delivery'), '--collector-url', collectorUrl];
    relay = start(relayArgs);
    await health(relayUrl, relay);

    let loseReceipt = true;
    let proxyError;
    const inputs = new Map();
    const receipts = new Map();
    proxy = http.createServer((req, res) => {
      (async () => {
        const chunks = [];
        for await (const bytes of req) chunks.push(bytes);
        const bytes = Buffer.concat(chunks);
        const id = JSON.parse(bytes.toString('utf8')).captureId;
        const previous = inputs.get(id);
        if (previous) assert.deepEqual(bytes, previous, 'every retry must keep the exact sent bytes');
        else inputs.set(id, bytes);
        const response = await fetch(`${relayUrl}/capture`, { method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: bytes, signal: AbortSignal.timeout(5000) });
        const receipt = await response.json();
        assert.equal(response.ok, true);
        assert.deepEqual(receipt.input_receipt, { schema_version: 'chiptrace.capture-input-receipt.v1',
          bytes: bytes.length, sha256: digest(bytes) });
        receipts.set(id, receipt);
        res.writeHead(response.status, { 'content-type': 'application/json', connection: 'close' });
        // The real Relay has committed; losing its receipt must retain the
        // gateway copy until a later valid, idempotent acknowledgement.
        res.end(JSON.stringify(loseReceipt ? { ok: true, durable: true } : receipt));
      })().catch(error => {
        proxyError = error;
        res.writeHead(500, { connection: 'close' });
        res.end();
      });
    });
    await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
    const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
    const makeOutbox = () => {
      const outbox = new DurableCaptureOutbox({ root: path.join(root, 'gateway'), relayUrl: proxyUrl,
        bearerToken: token, maxAttempts: 1, retryBaseMs: 1, retryMaxMs: 1, retryJitterPercent: 0 });
      outboxes.push(outbox);
      return outbox;
    };
    const wire = id => ({ captureId: id, recordType: 'api_snapshot', sourceNamespace: 'synthetic-wire-receipt',
      traceContext: { session_id: 'synthetic-wire-session', turn_id: id }, responseStatus: 200,
      requestBodyText: JSON.stringify({ input: '中文 input 🧪' }),
      responseBodyText: id.endsWith('current-v2')
        ? 'event: response.completed\ndata: {"type":"response.completed","response":{"status":"completed","output":"原样保留 SSE"}}\n\n'
        : JSON.stringify({ output: '原样保留 response' }) });
    const first = makeOutbox();
    await first.enqueue(wire('cap-receipt-unversioned'), { schedule: false });
    const pending = path.join(root, 'gateway', 'pending', 'cap-receipt-unversioned.json');
    const original = await fs.readFile(pending);
    assert.equal(await first.flush(150), false);
    await first.close();
    if (first.drainPromise) await first.drainPromise;
    assert.ifError(proxyError);
    assert.deepEqual(await fs.readFile(pending), original);
    assert.equal(first.snapshot().durable, 0);
    assert.equal(first.snapshot().failedFiles, 0);
    assert.ok(receipts.has('cap-receipt-unversioned'));

    loseReceipt = false;
    const duplicateEvents = [];
    const second = makeOutbox();
    second.onDurable = value => duplicateEvents.push(value);
    await second.start();
    assert.equal(await second.flush(5000), true);
    assert.deepEqual(duplicateEvents, [{ captureId: 'cap-receipt-unversioned', duplicate: true }]);
    const streamingWire = { ...wire('cap-receipt-current-v2'), version: 'chiptrace.capture.v2' };
    const transaction = await second.beginCapture(streamingWire);
    await transaction.appendRequest(Buffer.from(streamingWire.requestBodyText));
    await transaction.appendResponse(Buffer.from(streamingWire.responseBodyText));
    await transaction.finalize({ responseStatus: streamingWire.responseStatus });
    assert.equal(await second.flush(5000), true);
    assert.equal(second.snapshot().durable, 2);
    assert.equal(second.snapshot().activeQueueBytes, 0);
    await assert.rejects(fs.stat(pending), { code: 'ENOENT' });
    assert.ifError(proxyError);

    const delivered = await health(relayUrl, relay,
      h => h.delivered === 2 && h.pending === 0 && h.inflight === 0);
    assert.equal(delivered.conservation_ok, true);
    assert.equal(delivered.failed, 0);
    await health(collectorUrl, collector, h => h.collector.captures === 2);
    for (const url of [relayUrl, collectorUrl]) {
      const response = await fetch(`${url}/flush`, { method: 'POST',
        headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
      assert.equal(response.ok, true);
    }
    const relayRaw = await sealedRecords(path.join(root, 'relay'));
    const collectorRaw = await sealedRecords(path.join(root, 'collector'));
    assert.equal(collectorRaw.size, 2);
    assert.equal(relayRaw.size, 2);
    for (const [id, value] of collectorRaw) {
      assert.equal(value.line, relayRaw.get(id).line);
      assert.equal(value.sha256, receipts.get(id).capture.raw_sha256);
      assert.equal(Buffer.byteLength(value.line, 'utf8') + 1, receipts.get(id).capture.length);
      assert.equal(value.record.requestBody.kind, 'json');
      assert.equal(value.record.requestBody.raw, wire(id).requestBodyText);
      assert.equal(value.record.requestBytesCaptured, Buffer.byteLength(wire(id).requestBodyText, 'utf8'));
      assert.equal(value.record.requestBodySha256, digest(Buffer.from(wire(id).requestBodyText, 'utf8')));
      if (id.endsWith('current-v2')) {
        assert.equal(value.record.responseBody.kind, 'text');
        assert.equal(value.record.responseBody.value, wire(id).responseBodyText);
      } else {
        assert.equal(value.record.responseBody.kind, 'json');
        assert.equal(value.record.responseBody.raw, wire(id).responseBodyText);
      }
      assert.equal(value.record.responseBytesCaptured, Buffer.byteLength(wire(id).responseBodyText, 'utf8'));
      assert.equal(value.record.responseBodySha256, digest(Buffer.from(wire(id).responseBodyText, 'utf8')));
      assert.equal(value.record.traceContext.turn_id, id);
    }
    await second.close();
    if (second.drainPromise) await second.drainPromise;
    assert.equal((await stop(relay)).code, 0);
    assert.equal((await stop(collector)).code, 0);
    collector = start(collectorArgs);
    await health(collectorUrl, collector, h => h.collector.captures === 2);
    relay = start(relayArgs);
    await health(relayUrl, relay,
      h => h.delivered === 2 && h.pending === 0 && h.inflight === 0 && h.conservation_ok);
    assert.deepEqual(await sealedRecords(path.join(root, 'collector')), collectorRaw);
  });
