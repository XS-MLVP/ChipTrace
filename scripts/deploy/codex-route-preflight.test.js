'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { validateCodexRoute } = require('./codex-route-preflight');

const config = fs.readFileSync(path.join(__dirname, '../../integrations/codex/config.toml.example'), 'utf8');
const gateway = 'http://172.28.11.121:18084/';

test('managed Stock Codex configuration binds Responses and both OTLP routes to 18084', () => {
  assert.deepEqual(validateCodexRoute(config, gateway), {
    schema_version: 'chiptrace.codex-route-preflight.v1',
    ok: true,
    base_url: 'http://172.28.11.121:18084/',
    wire_api: 'responses',
    otlp_logs_endpoint: 'http://172.28.11.121:18084/otel/v1/logs',
    otlp_traces_endpoint: 'http://172.28.11.121:18084/otel/v1/traces',
  });
});

test('an external Provider route is refused before any model request', () => {
  const bypass = config.replace('http://172.28.11.121:18084/', 'https://provider.example/v1/');
  assert.throws(() => validateCodexRoute(bypass, gateway), /base_url must target the managed Gateway/);
});

test('missing or redirected OTLP routes are refused', () => {
  const missingLogs = config.replace(/exporter = \{ otlp-http = \{[^\n]+\n/, 'exporter = { otlp-http = { endpoint = "https://collector.example/logs", protocol = "json" } }\n');
  assert.throws(() => validateCodexRoute(missingLogs, gateway), /OTLP logs endpoint/);
  const missingTraces = config.replace(/trace_exporter = \{ otlp-http = \{[^\n]+\n/, 'trace_exporter = { otlp-http = { endpoint = "https://collector.example/traces", protocol = "json" } }\n');
  assert.throws(() => validateCodexRoute(missingTraces, gateway), /OTLP traces endpoint/);
});

test('preflight diagnostics never include configuration body or credentials', () => {
  const privateConfig = `${config}\napi_key = "do-not-print"\n`;
  try {
    validateCodexRoute(privateConfig, gateway);
  } catch (error) {
    assert.doesNotMatch(String(error), /do-not-print|api_key/);
  }
});
