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
});

test('live provider preflight requires protected endpoints and runs both gates', () => {
  for (const name of [
    'CHIPTRACE_API_KEY',
    'CHIPTRACE_RESPONSES_URL',
    'CHIPTRACE_GATEWAY_HEALTH_URL',
    'CHIPTRACE_RELAY_HEALTH_URL',
    'CHIPTRACE_COLLECTOR_HEALTH_URL',
    'CHIPTRACE_PLATFORM_HEALTH_URL',
    'CHIPTRACE_GATEWAY_CONTAINER',
    'CHIPTRACE_EXPECTED_REVISION',
  ]) {
    assert.match(workflow, new RegExp(name));
  }
  assert.match(workflow, /node scripts\/ci\/provider-response-gate\.js/);
  assert.match(workflow, /node scripts\/ci\/runtime-health-gate\.js/);
  assert.match(workflow, /name: Verify live Collector, Relay and Gateway readiness\n        if: \$\{\{ always\(\) \}\}/);
  assert.match(workflow, /--expected-revision "\$CHIPTRACE_EXPECTED_REVISION"/);
  assert.match(workflow, /node scripts\/ci\/platform-health-gate\.js/);
  assert.match(workflow, /--platform-url "\$CHIPTRACE_PLATFORM_HEALTH_URL"/);
  assert.match(workflow, /--expected-revision "\$CHIPTRACE_EXPECTED_REVISION"/);
  assert.match(workflow, /node --test scripts\/ci\/platform-health-gate\.test\.js/);
  assert.match(workflow, /--max-quality-errors 0/);
  assert.match(workflow, /--max-historical-failed-files 0/);
  assert.match(workflow, /node scripts\/deploy\/gateway-preflight\.js/);
  assert.match(workflow, /--container "\$CHIPTRACE_GATEWAY_CONTAINER"/);
  assert.match(workflow, /--expected-revision "\$CHIPTRACE_EXPECTED_REVISION"/);
  assert.match(workflow, /name: live-provider-runtime-preflight/);
});

test('CI actions are immutable and the MinIO job verifies its Go toolchain before compiling', () => {
  const actions = [...workflow.matchAll(/^\s*- uses:\s+([^\s#]+)/gm)].map(match => match[1]);
  assert.ok(actions.length > 0);
  assert.ok(actions.every(action => /@[a-f0-9]{40}$/.test(action)),
    `all third-party Actions must be pinned by commit: ${actions.filter(action => !/@[a-f0-9]{40}$/.test(action)).join(', ')}`);
  assert.match(workflow, /GOTOOLCHAIN: go1\.24\.2/);
  assert.match(workflow, /test "\$\(go env GOVERSION\)" = "go1\.24\.2"/);
  assert.match(workflow, /name: Select and verify the pinned Go toolchain using the runner's Go bootstrap/);
});
