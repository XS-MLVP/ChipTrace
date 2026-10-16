'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { setTimeout: delay } = require('node:timers/promises');
const { docker, preflight } = require('../deploy/preflight');
const { ChipTraceClient } = require('../../integrations/cloud-platform/client');

const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const files = ['deploy/collector-relay.yml', 'deploy/cloud-platform.yml'];
const token = 'synthetic-deployment-smoke-credential-at-least-32-bytes';
const run = promisify(execFile);

async function eventually(action, timeout = 60000) {
  const deadline = Date.now() + timeout;
  let last;
  do {
    try { return await action(); } catch (error) { last = error; }
    await delay(200);
  } while (Date.now() < deadline);
  throw last;
}

async function json(url, { auth = false, method = 'GET', body } = {}) {
  const response = await fetch(url, { method, body, redirect: 'error',
    headers: { 'content-type': 'application/json', ...(auth ? { authorization: `Bearer ${token}` } : {}) },
    signal: AbortSignal.timeout(5000) });
  assert.ok([200, 202].includes(response.status), `unexpected HTTP ${response.status} at ${new URL(url).pathname}`);
  return response.json();
}

// Keep the deployment report honest about the evidence that matters for a
// real conversation. Container health and delivery conservation can both be
// green while no successful Session/Turn-scoped Wire has arrived. The runtime
// gate already validates the full shape; this explicit assertion makes the
// deployment smoke contract visible at its call site and preserves a bounded
// summary in the CI artifact.
function requireSuccessfulTurnWireCoverage(liveGate) {
  const coverage = liveGate?.relay?.wire_turn_coverage;
  assert.ok(coverage && typeof coverage === 'object' && !Array.isArray(coverage),
    'runtime gate must return relay.wire_turn_coverage');
  assert.ok(Number.isSafeInteger(coverage.successful_turn_scoped_captures)
    && coverage.successful_turn_scoped_captures > 0,
  'deployment smoke requires a successful Turn-scoped Wire capture');
  assert.equal(coverage.successful_turn_scoped_fresh, true,
    'deployment smoke requires fresh successful Turn-scoped Wire evidence');
  assert.equal(liveGate.relay.turn_capture_ready, true,
    'deployment smoke requires Relay turn_capture_ready');
  return {
    success_definition: coverage.success_definition,
    freshness_definition: coverage.freshness_definition,
    turn_scoped_captures: coverage.turn_scoped_captures,
    successful_turn_scoped_captures: coverage.successful_turn_scoped_captures,
    unscoped_captures: coverage.unscoped_captures,
    identity_conflict_captures: coverage.identity_conflict_captures,
    last_successful_at: coverage.last_successful_at,
    last_successful_age_ms: coverage.last_successful_age_ms,
    successful_turn_scoped_fresh: coverage.successful_turn_scoped_fresh,
    turn_capture_ready: liveGate.relay.turn_capture_ready,
  };
}

async function sealed(root) {
  const records = new Map();
  const directory = path.join(root, 'segments');
  for (const name of (await fs.readdir(directory)).filter(name => name.endsWith('.sealed.ndjson')).sort()) {
    const bytes = await fs.readFile(path.join(directory, name), 'utf8');
    assert.ok(bytes.length === 0 || bytes.endsWith('\n'), 'sealed Raw must end at a complete JSONL record');
    for (const line of bytes.trimEnd().split('\n').filter(Boolean)) {
      const record = JSON.parse(line);
      assert.ok(!records.has(record.captureId), 'duplicate Raw identity');
      records.set(record.captureId, line);
    }
  }
  return records;
}

function sameRaw(actual, expected) {
  assert.equal(actual.size, expected.size, 'Raw record count changed');
  for (const [id, bytes] of expected) assert.ok(actual.get(id) === bytes, 'Raw record identity or bytes changed');
}

async function main({ runtimeImage, platformImage, revision, reportPath }) {
  assert.ok(process.getuid() > 0 && process.getgid() > 0, 'run the deployment smoke as a non-root host user');
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'chiptrace-deployment-'));
  const project = `chiptrace-deploy-${path.basename(root).split('-').at(-1).toLowerCase()}`;
  const network = `${project}-network`;
  const environment = Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => !/^(CHIPTRACE_|AWS_|OSS_|ALIBABA_)/.test(key)));
  Object.assign(environment, {
    CHIPTRACE_REVISION: revision, CHIPTRACE_IMAGE: runtimeImage, CHIPTRACE_PLATFORM_IMAGE: platformImage,
    CHIPTRACE_PROJECT_NAME: project, CHIPTRACE_PLATFORM_PROJECT: project, CHIPTRACE_PROJECT_ID: project,
    CHIPTRACE_RUN_AS: `${process.getuid()}:${process.getgid()}`,
    CHIPTRACE_NETWORK: network, CHIPTRACE_COLLECTOR_CONTAINER: `${project}-collector`,
    CHIPTRACE_RELAY_CONTAINER: `${project}-relay`, CHIPTRACE_COLLECTOR_BIND: '127.0.0.1:0',
    CHIPTRACE_RELAY_BIND: '127.0.0.1:0', CHIPTRACE_PLATFORM_BIND: '127.0.0.1:0',
    CHIPTRACE_CAPTURE_ROOT: path.join(root, 'capture'),
    CHIPTRACE_COLLECTOR_STATE_ROOT: path.join(root, 'collector-state'),
    CHIPTRACE_RELAY_ROOT: path.join(root, 'relay'),
    CHIPTRACE_PLATFORM_ROOT: path.join(root, 'platform'), CHIPTRACE_OBJECT_ROOT: path.join(root, 'objects'),
    CHIPTRACE_INGEST_TOKEN: token, CHIPTRACE_PLATFORM_TOKEN: token, CHIPTRACE_BACKEND: 'fs',
  });
  const compose = ['compose', '--env-file', '/dev/null', ...files.flatMap(file => ['-f', file]), '--project-name', project];
  const command = args => docker([...compose, ...args], environment, 180000);
  const report = { schema_version: 'chiptrace.deployment-smoke.v1', synthetic: true,
    real_upstream: false, real_oss_account: false, production_acceptance_claimed: false,
    revision, ok: false, checks: {} };
  let networkCreated = false;
  let started = false;
  let passed = false;
  let healthFixture;
  const check = name => { report.checks[name] = true; console.log(`deployment smoke: ${name}`); };
  try {
    const proof = await preflight({ files, revision, project, env: environment });
    report.services = proof.services;
    check('rendered_templates_and_pinned_images');
    const otherRevision = revision === 'f'.repeat(40) ? 'e'.repeat(40) : 'f'.repeat(40);
    await assert.rejects(preflight({ files, revision: otherRevision, project,
      env: { ...environment, CHIPTRACE_REVISION: otherRevision } }), /OCI revision/);
    check('mismatched_image_revision_refused');

    for (const name of ['capture', 'collector-state', 'relay', 'platform', 'objects']) await fs.mkdir(path.join(root, name));
    const seeded = JSON.parse(await docker(['run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
      '--user', environment.CHIPTRACE_RUN_AS, '--memory', '1g', '--cpus', '2', '--pids-limit', '256',
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:size=256m,mode=1777',
      '-e', 'TOKIO_WORKER_THREADS=2', '-e', 'RAYON_NUM_THREADS=2',
      '--mount', `type=bind,source=${root},target=/canary`, '--entrypoint', 'chiptrace',
      platformImage, 'self-test', '--fixture-output', '/canary/fixture'], environment));
    assert.equal(seeded.ok, true);
    assert.equal(seeded.collection.build.revision, revision, 'platform CLI must match the expected revision');
    const sourceRecords = await sealed(path.join(root, 'fixture/capture'));
    assert.equal(sourceRecords.size, seeded.collection_submission.records);
    const expectedRelayRaw = new Map([...sourceRecords].filter(([, line]) => JSON.parse(line).recordType !== 'evaluation'));
    check('platform_cli_compiled_revision');

    await docker(['network', 'create', '--label', `io.chiptrace.canary=${project}`, network], environment);
    networkCreated = true;
    // Set before up so even a partially failed start is cleaned up.
    started = true;
    await command(['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '120']);
    const ids = (await command(['ps', '--all', '--quiet'])).trim().split(/\s+/).filter(Boolean);
    assert.equal(ids.length, 3);
    const containers = JSON.parse(await docker(['inspect', ...ids], environment));
    const urls = {};
    const actualIds = new Set();
    for (const container of containers) {
      assert.equal(container.Config.Labels['com.docker.compose.project'], project);
      const service = container.Config.Labels['com.docker.compose.service'];
      const expected = proof.services.find(item => item.name === service);
      assert.ok(expected, 'only owned deployment services may be inspected');
      assert.equal(container.Image, expected.image_id);
      assert.equal(container.HostConfig.ReadonlyRootfs, true);
      assert.equal(container.HostConfig.Memory, expected.memory_bytes);
      assert.equal(container.HostConfig.NanoCpus, expected.nano_cpus);
      assert.equal(container.HostConfig.PidsLimit, expected.pids_limit);
      assert.equal(container.Config.User, expected.user);
      assert.equal(container.HostConfig.Init, true);
      assert.ok(container.HostConfig.CapDrop.includes('ALL'));
      assert.ok(container.HostConfig.SecurityOpt.some(value => /^no-new-privileges(?::true)?$/.test(value)));
      assert.equal(container.State.OOMKilled, false);
      assert.equal(container.State.Health.Status, 'healthy');
      const port = { collector: '3010/tcp', relay: '3012/tcp', platform: '18086/tcp' }[service];
      const binding = container.NetworkSettings.Ports[port];
      assert.ok(binding, `${service}: loopback port was not published`);
      assert.equal(binding.length, 1);
      assert.equal(binding[0].HostIp, '127.0.0.1');
      urls[service] = `http://127.0.0.1:${binding[0].HostPort}`;
      actualIds.add(container.Id);
    }
    check('actual_container_identity_health_and_limits');
    for (const service of ['collector', 'relay']) assert.equal((await json(`${urls[service]}/health`)).build.revision, revision);
    const unauthorized = await fetch(`${urls.relay}/capture`, { method: 'POST', body: '{}', signal: AbortSignal.timeout(5000) });
    assert.equal(unauthorized.status, 401);
    await unauthorized.body.cancel();
    for (const [id, line] of sourceRecords) {
      const record = JSON.parse(line);
      if (['lifecycle_event', 'tool_execution'].includes(record.recordType)) continue;
      if (record.recordType === 'telemetry_batch') {
        const batch = record.telemetryBatch;
        const route = { otlp_logs: '/otel/v1/logs', otlp_traces: '/otel/v1/traces', codex_hook: '/hooks/codex' }[batch.endpoint];
        assert.ok(route, 'unknown telemetry endpoint');
        const receipt = await json(`${urls.relay}${route}`, { auth: true, method: 'POST', body: batch.raw_json });
        assert.equal(receipt.chiptrace.durable, true);
        assert.equal(receipt.chiptrace.summary.source_records, batch.source_records);
        assert.equal(receipt.chiptrace.summary.derived_captures, batch.derived_captures);
        assert.deepEqual(receipt.chiptrace.summary.conversion_errors, []);
        continue;
      }
      assert.ok(['api_snapshot', 'evaluation'].includes(record.recordType), 'unknown fixture record type');
      // Evaluator evidence belongs only on the private Collector. Replay
      // original OTLP/Hook envelopes above to recreate their derived records.
      const target = record.recordType === 'evaluation' ? urls.collector : urls.relay;
      const receipt = await json(`${target}/capture`, { auth: true, method: 'POST', body: line });
      assert.equal(receipt.ok, true);
      assert.equal(receipt.durable, true);
      assert.equal(receipt.capture.capture_id, id);
      assert.equal(receipt.capture.raw_sha256, digest(Buffer.from(line)));
    }
    const first = [...sourceRecords.values()].find(line => JSON.parse(line).recordType === 'api_snapshot');
    assert.ok(first);
    const duplicate = await json(`${urls.relay}/capture`, { auth: true, method: 'POST', body: first });
    assert.equal(duplicate.duplicate, true);
    await eventually(async () => {
      const relay = await json(`${urls.relay}/health`);
      assert.equal(relay.delivered, expectedRelayRaw.size);
      assert.equal(relay.pending, 0); assert.equal(relay.inflight, 0); assert.equal(relay.failed, 0);
      assert.equal(relay.conservation_ok, true);
      assert.equal((await json(`${urls.collector}/health`)).collector.captures, sourceRecords.size);
    });
    for (const service of ['collector', 'relay']) assert.equal((await json(`${urls[service]}/flush`, { auth: true, method: 'POST' })).ok, true);
    const collectorRaw = await sealed(environment.CHIPTRACE_CAPTURE_ROOT);
    const relayRaw = await sealed(path.join(environment.CHIPTRACE_RELAY_ROOT, 'outbox'));
    sameRaw(collectorRaw, sourceRecords);
    sameRaw(relayRaw, expectedRelayRaw);
    report.raw_records = sourceRecords.size;
    check('authenticated_relay_collector_exact_raw_and_duplicates');

    // The public repository does not ship the host's 18084 server. This
    // explicitly synthetic gateway health fixture reads the real Relay count;
    // positive Collector/Relay probes below go directly to the real services.
    // Fault routes are controlled health responses, not claims about a second
    // actual Collector deployment.
    healthFixture = http.createServer(async (req, res) => {
      try {
        let value;
        let status = 200;
        if (req.url === '/gateway') {
          const relay = await json(`${urls.relay}/health`);
          value = { status: 'healthy', fullTraceCapture: { enabled: true, currentDeliveryHealthy: true,
            outbox: { pending: 0, processing: 0, recentFailureCount: 0, openCaptureHealthy: true,
              openTransactions: 0, failedFiles: 0, unresolvedHistoricalFailedFiles: 0,
              recoveryReceiptFiles: 0 },
            rustRelay: { configured: true, healthy: true, conservationOk: relay.conservation_ok,
              pending: relay.pending, inflight: relay.inflight, failed: relay.failed, delivered: relay.delivered } } };
        } else if (req.url === '/collector-other-revision') {
          value = await json(`${urls.collector}/health`);
          value.build.revision = otherRevision;
        } else { status = 503; value = { ok: false }; }
        res.writeHead(status, { 'content-type': 'application/json', connection: 'close' });
        res.end(JSON.stringify(value));
      } catch {
        res.writeHead(503, { 'content-type': 'application/json', connection: 'close' });
        res.end('{"ok":false}');
      }
    });
    await new Promise(resolve => healthFixture.listen(0, '127.0.0.1', resolve));
    const fixtureUrl = `http://127.0.0.1:${healthFixture.address().port}`;
    const runtimeGate = async (collectorUrl = `${urls.collector}/health`) => {
      const result = await run(process.execPath, [require.resolve('./runtime-health-gate'),
        '--gateway-url', `${fixtureUrl}/gateway`, '--relay-url', `${urls.relay}/health`,
        '--collector-url', collectorUrl, '--expected-revision', revision,
        '--max-historical-failed-files', '0'],
      { env: environment, timeout: 10000, maxBuffer: 128 * 1024 });
      return JSON.parse(result.stdout);
    };
    const liveGate = await runtimeGate();
    assert.equal(liveGate.schema_version, 'chiptrace.runtime-health-gate.v3');
    assert.equal(liveGate.session_delivery_claimed, false);
    assert.equal(liveGate.build_revision, revision);
    assert.equal(liveGate.collector.build_revision, revision);
    assert.equal(liveGate.collector.captures, sourceRecords.size);
    assert.equal(liveGate.relay.delivered, expectedRelayRaw.size);
    const wireTurnCoverage = requireSuccessfulTurnWireCoverage(liveGate);
    report.runtime_gate = { schema_version: liveGate.schema_version, gateway_health_source: 'synthetic_fixture',
      collector_health_source: 'actual_service', relay_health_source: 'actual_service',
      session_delivery_claimed: false, build_revision: liveGate.build_revision,
      collector_captures: liveGate.collector.captures, relay_delivered: liveGate.relay.delivered,
      wire_turn_coverage: wireTurnCoverage };
    check('runtime_cli_probes_actual_collector_and_relay');
    check('runtime_cli_requires_fresh_successful_turn_wire');
    for (const [route, pattern] of [
      ['/collector-unavailable', /HTTP 503/],
      ['/collector-other-revision', /collector health\.build\.revision does not match expected revision/],
    ]) {
      await assert.rejects(runtimeGate(`${fixtureUrl}${route}`), error => {
        assert.equal(error.code, 1); assert.equal(error.stdout, '');
        assert.match(error.stderr, pattern);
        return true;
      });
    }
    check('runtime_cli_refuses_collector_probe_and_revision_faults');

    let client = new ChipTraceClient({ baseUrl: urls.platform, token });
    const unauthenticated = await fetch(`${urls.platform}/v1/jobs`, { signal: AbortSignal.timeout(5000) });
    assert.equal(unauthenticated.status, 401);
    await unauthenticated.body.cancel();
    const submit = async request => {
      await client.submit(request);
      const job = await client.wait(request.id, { timeoutMs: 60000, intervalMs: 100 });
      assert.equal(job.status, 'completed', `platform ${request.kind} must complete: ${job.error?.code || job.error?.exit_code || ''}`);
      return job;
    };
    await submit({ id: 'archive', kind: 'archive', archive_id: 'deployment-raw' });
    await submit({ id: 'restore', kind: 'restore', archive_id: 'deployment-raw' });
    const inspection = await submit({ id: 'inspect', kind: 'inspect', archive_id: 'deployment-raw', session_id: 'thread-self-test' });
    assert.equal(inspection.result.delivery_ready, true);
    assert.equal(inspection.result.source_context_audit.unscoped_otlp_records, 0);
    const page = await client.getTurns('inspect', { limit: 100 });
    assert.equal(page.delivery_ready, true);
    assert.equal(page.total, 5);
    const turns = Buffer.from(await (await client.downloadTurns('inspect')).arrayBuffer());
    assert.equal(digest(turns), inspection.turns.sha256);
    assert.equal(turns.length, inspection.turns.bytes);
    await client.putUsageLog('synthetic-usage', await fs.readFile(path.join(root, 'fixture/sub2api-usage.jsonl')));
    const exported = await submit({ id: 'export', kind: 'export', archive_id: 'deployment-raw', session_id: 'thread-self-test',
      release_id: 'deployment-release', usage_log_ids: ['synthetic-usage'] });
    assert.equal(exported.result.delivery_ready, true);
    assert.equal(exported.result.score, 100);
    assert.equal(exported.result.session_view.native_turns, page.total);
    assert.ok(exported.artifacts.length > 0);
    const artifact = exported.artifacts[0];
    const packageBytes = Buffer.from(await (await client.download('export', artifact.file)).arrayBuffer());
    assert.equal(digest(packageBytes), artifact.sha256);
    assert.equal(packageBytes.length, artifact.bytes);
    report.native_turns = page.total;
    report.turns = { bytes: turns.length, sha256: digest(turns) };
    report.package = { bytes: packageBytes.length, sha256: digest(packageBytes) };
    check('platform_archive_restore_turns_and_verified_export');

    await command(['restart', '--timeout', '30']);
    await eventually(async () => {
      const current = JSON.parse(await docker(['inspect', ...ids], environment));
      assert.deepEqual(new Set(current.map(item => item.Id)), actualIds);
      for (const item of current) {
        assert.equal(item.State.Health.Status, 'healthy'); assert.equal(item.State.OOMKilled, false);
        const service = item.Config.Labels['com.docker.compose.service'];
        const port = { collector: '3010/tcp', relay: '3012/tcp', platform: '18086/tcp' }[service];
        const binding = item.NetworkSettings.Ports[port];
        assert.ok(binding, `${service}: restarted loopback port was not published`);
        assert.equal(binding.length, 1); assert.equal(binding[0].HostIp, '127.0.0.1');
        // Docker can assign a new port on restart when published=0.
        urls[service] = `http://127.0.0.1:${binding[0].HostPort}`;
      }
      client = new ChipTraceClient({ baseUrl: urls.platform, token });
      for (const service of ['collector', 'relay']) assert.equal((await json(`${urls[service]}/health`)).build.revision, revision);
      assert.equal((await json(`${urls.collector}/health`)).collector.captures, sourceRecords.size);
      const relay = await json(`${urls.relay}/health`);
      assert.equal(relay.delivered, expectedRelayRaw.size); assert.equal(relay.pending, 0); assert.equal(relay.inflight, 0);
      assert.equal(relay.failed, 0); assert.equal(relay.conservation_ok, true);
      assert.equal((await client.getJob('export')).status, 'completed');
    });
    sameRaw(await sealed(environment.CHIPTRACE_CAPTURE_ROOT), collectorRaw);
    sameRaw(await sealed(path.join(environment.CHIPTRACE_RELAY_ROOT, 'outbox')), relayRaw);
    assert.equal((await client.submit({ id: 'archive', kind: 'archive', archive_id: 'deployment-raw' })).duplicate, true);
    assert.ok(Buffer.from(await (await client.downloadTurns('inspect')).arrayBuffer()).equals(turns), 'Turn download bytes changed after restart');
    assert.ok(Buffer.from(await (await client.download('export', artifact.file)).arrayBuffer()).equals(packageBytes), 'package download bytes changed after restart');
    check('restart_preserves_raw_jobs_turns_and_package_bytes');
    // Persisted Raw does not refresh process-scoped source evidence. Require
    // a new real canary after restart; duplicates cannot manufacture freshness.
    await assert.rejects(runtimeGate(), error => {
      assert.equal(error.code, 1); assert.equal(error.stdout, '');
      assert.match(error.stderr, /ingest_coverage.status must be complete/);
      return true;
    });
    check('restarted_runtime_requires_new_source_evidence');
    passed = true;
  } finally {
    let cleanupError;
    if (healthFixture) {
      try { healthFixture.closeAllConnections(); await new Promise((resolve, reject) => healthFixture.close(error => error ? reject(error) : resolve())); }
      catch (error) { cleanupError = error; }
    }
    if (started) {
      if (!passed) {
        try { console.error((await command(['logs', '--no-color', '--tail', '20'])).slice(-12000)); }
        catch { console.error('deployment smoke: service diagnostics unavailable'); }
      }
      try {
        await command(['down', '--timeout', '30']);
        assert.equal((await command(['ps', '--all', '--quiet'])).trim(), '');
      } catch (error) { cleanupError = error; }
    }
    if (networkCreated) {
      try {
        const [owned] = JSON.parse(await docker(['network', 'inspect', network], environment));
        assert.equal(owned.Labels['io.chiptrace.canary'], project);
        await docker(['network', 'rm', network], environment);
      } catch (error) { cleanupError ||= error; }
    }
    if (!cleanupError) check('owned_services_and_network_removed');
    report.ok = passed && !cleanupError;
    if (reportPath) await fs.writeFile(path.resolve(reportPath), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    if (report.ok && process.env.CHIPTRACE_DEPLOYMENT_KEEP !== '1') await fs.rm(root, { recursive: true, force: true });
    else console.error(`deployment smoke evidence retained: ${root}`);
    if (cleanupError) throw cleanupError;
  }
  assert.equal(report.ok, true);
  return report;
}

if (require.main === module) {
  const options = {};
  for (let index = 2; index < process.argv.length; index += 2) {
    const key = { '--runtime-image': 'runtimeImage', '--platform-image': 'platformImage', '--revision': 'revision', '--report': 'reportPath' }[process.argv[index]];
    if (!key || !process.argv[index + 1]) throw new Error('usage: deployment-smoke.js --runtime-image DIGEST --platform-image DIGEST --revision SHA [--report FILE]');
    options[key] = process.argv[index + 1];
  }
  main(options).then(result => console.log(JSON.stringify(result)))
    .catch(error => { console.error(`deployment smoke failed: ${error.message}`); process.exitCode = 1; });
}

module.exports = { main, requireSuccessfulTurnWireCoverage };
