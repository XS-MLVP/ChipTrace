'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

const workflow = fs.readFileSync('.github/workflows/ci.yml', 'utf8');

test('live provider preflight is manual, protected and isolated from ordinary CI', () => {
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /live_preflight:[\s\S]*?type: boolean/);
  assert.match(workflow, /live-provider-runtime-preflight:/);
  assert.match(workflow, /if: \$\{\{ github\.event_name == 'workflow_dispatch' && inputs\.live_preflight == true && github\.ref_protected == true \}\}/);
  assert.match(workflow, /runs-on: \[self-hosted, linux, chiptrace-canary\]/);
  assert.match(workflow, /environment: production-canary/);
  assert.match(workflow, /expected_revision:[\s\S]*?required: false[\s\S]*?default: ""/);
  assert.match(workflow, /gateway_revision:[\s\S]*?description: Full OCI revision of the independently released Gateway image[\s\S]*?required: false[\s\S]*?default: ""/);
});

test('live provider preflight requires protected endpoints and runs both gates', () => {
  for (const name of [
    'CHIPTRACE_API_KEY',
    'CHIPTRACE_CODEX_CONFIG',
    'CHIPTRACE_CODEX_USER_CONFIG',
    'CHIPTRACE_CODEX_BASE_URL',
    'CHIPTRACE_RESPONSES_URL',
    'CHIPTRACE_GATEWAY_HEALTH_URL',
    'CHIPTRACE_RELAY_HEALTH_URL',
    'CHIPTRACE_COLLECTOR_HEALTH_URL',
    'CHIPTRACE_PLATFORM_HEALTH_URL',
    'CHIPTRACE_PLATFORM_BACKEND',
    'CHIPTRACE_GATEWAY_CONTAINER',
    'CHIPTRACE_EXPECTED_REVISION',
    'CHIPTRACE_GATEWAY_EXPECTED_REVISION',
  ]) {
    assert.match(workflow, new RegExp(name));
  }
  assert.match(workflow, /node scripts\/deploy\/codex-route-preflight\.js/);
  assert.match(workflow, /- name: Verify the actual Codex configuration targets the managed Gateway\n        env:\n          CHIPTRACE_CODEX_CONFIG: \$\{\{ vars\.CHIPTRACE_CODEX_CONFIG \}\}\n          CHIPTRACE_CODEX_USER_CONFIG: \$\{\{ vars\.CHIPTRACE_CODEX_USER_CONFIG \}\}\n          CHIPTRACE_CODEX_BASE_URL: \$\{\{ vars\.CHIPTRACE_CODEX_BASE_URL \}\}/);
  assert.match(workflow, /--config "\$CHIPTRACE_CODEX_CONFIG"/);
  assert.match(workflow, /--user-config "\$CHIPTRACE_CODEX_USER_CONFIG"/);
  assert.match(workflow, /--expected-base-url "\$CHIPTRACE_CODEX_BASE_URL"/);
  assert.match(workflow, /codex-route-preflight\.json/);
  assert.match(workflow, /node scripts\/ci\/provider-response-gate\.js/);
  assert.match(workflow, /node scripts\/ci\/runtime-health-gate\.js/);
  assert.match(workflow, /name: Verify live Collector, Relay and Gateway readiness\n        if: \$\{\{ always\(\) \}\}/);
  assert.match(workflow, /--expected-revision "\$CHIPTRACE_EXPECTED_REVISION"/);
  assert.match(workflow, /node scripts\/ci\/platform-health-gate\.js/);
  assert.match(workflow, /--platform-url "\$CHIPTRACE_PLATFORM_HEALTH_URL"/);
  assert.match(workflow, /--expected-revision "\$CHIPTRACE_EXPECTED_REVISION"/);
  assert.match(workflow, /--expected-backend "\$CHIPTRACE_PLATFORM_BACKEND"/);
  assert.match(workflow, /CHIPTRACE_PLATFORM_BACKEND must be oss or s3 for protected live preflight/);
  assert.match(workflow, /node --test scripts\/ci\/platform-health-gate\.test\.js/);
  assert.match(workflow, /--max-quality-errors 0/);
  assert.match(workflow, /--max-historical-failed-files 0/);
  assert.match(workflow, /--min-gateway-free-bytes 10737418240/);
  assert.match(workflow, /--min-gateway-free-files 10000/);
  assert.match(workflow, /--transient-retries 4/);
  assert.match(workflow, /--transient-retry-delay-ms 250/);
  assert.match(workflow, /node scripts\/deploy\/gateway-preflight\.js/);
  assert.match(workflow, /--container "\$CHIPTRACE_GATEWAY_CONTAINER"/);
  assert.match(workflow, /--expected-gateway-revision "\$CHIPTRACE_GATEWAY_EXPECTED_REVISION"/);
  assert.match(workflow, /name: live-provider-runtime-preflight/);
});

test('CI actions are immutable and the MinIO job verifies its Go toolchain before compiling', () => {
  // Match both the compact `- uses:` form and a named step's indented
  // `uses:` field. The latter is easy to miss when checking only list items.
  const actions = [...workflow.matchAll(/^\s*(?:-\s+)?uses:\s+([^\s#]+)/gm)].map(match => match[1]);
  assert.ok(actions.length >= 10);
  assert.ok(actions.every(action => /@[a-f0-9]{40}$/.test(action)),
    `all third-party Actions must be pinned by commit: ${actions.filter(action => !/@[a-f0-9]{40}$/.test(action)).join(', ')}`);
  assert.match(workflow, /GOTOOLCHAIN: go1\.24\.2/);
  assert.match(workflow, /test "\$\(go env GOVERSION\)" = "go1\.24\.2"/);
  assert.doesNotMatch(workflow, /actions\/setup-go@/,
    'the S3 job must use the runner Go bootstrap because setup-go v6 archives are unavailable');
  assert.match(workflow, /name: Select and verify the pinned Go toolchain/);
  // v2 is an annotated tag. Pin the dereferenced commit so the Actions
  // runner can load action.yml instead of trying to execute the tag object.
  assert.doesNotMatch(workflow, /Swatinem\/rust-cache@49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c/);
  assert.match(workflow, /Swatinem\/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6/);
});

test('managed route uses a digest-pinned container image for deterministic startup', () => {
  const image = 'node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392';
  assert.ok(workflow.includes(`docker pull ${image}`));
  assert.ok(workflow.includes(`CHIPTRACE_CONFIG_TEST_IMAGE: ${image}`));
  assert.doesNotMatch(workflow, /docker pull node:22-bookworm-slim\s*$/m);
});

test('hosted sandbox startup tolerates optional sysctl writes but requires a real namespace probe', () => {
  assert.match(workflow, /Could not enable kernel\.unprivileged_userns_clone; continuing to the real namespace probe/);
  assert.match(workflow, /Could not disable AppArmor unprivileged-userns restriction; continuing to the real namespace probe/);
  assert.match(workflow, /if ! unshare --user --map-root-user \/bin\/true; then/);
  assert.match(workflow, /native producer sandbox namespace is unavailable on this runner/);
});

test('container fixture mounts are readable by the fixed non-root image user', () => {
  assert.match(workflow,
    /- name: Prepare read-only test mounts for the non-root container[\s\S]*?chmod -R a\+rX integrations\/openai-gateway integrations\/cloud-platform integrations\/codex fixtures/);
  assert.match(workflow,
    /- name: Verify non-root container mounts before test runners[\s\S]*?--user 10001:10001[\s\S]*?--entrypoint node[\s\S]*?NON_ROOT_TEST_MOUNTS_READABLE/);
});

test('Relay CI benchmark fails on hidden delivery retries', () => {
  assert.match(workflow,
    /name: Verify Relay cloud delivery benchmark path[\s\S]*?--relay --max-delivery-retries 0[\s\S]*?assert result\["delivery_retries"\] == 0/);
});
