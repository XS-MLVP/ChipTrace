'use strict';

// Validate the managed Stock Codex route without reading or printing secrets.
// This is a configuration contract check, not a model request.
const fs = require('node:fs');

const SCHEMA_VERSION = 'chiptrace.codex-route-preflight.v1';

function fail(message) {
  throw new Error(`Codex route preflight failed: ${message}`);
}

function tomlSection(text, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = text.match(new RegExp(`(?:^|\\n)\\[${escaped}\\]\\s*\\n([\\s\\S]*?)(?=\\n\\[|$)`));
  return match?.[1] || null;
}

function tomlString(text, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = text.match(new RegExp(`^${escaped}\\s*=\\s*"([^"]*)"\\s*$`, 'm'));
  return match?.[1] ?? null;
}

function normalizeUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${label} must be an absolute URL`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    fail(`${label} must use HTTP or HTTPS`);
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    fail(`${label} must not contain credentials, query, or fragment`);
  }
  parsed.pathname = parsed.pathname.replace(/\/+$/, '') || '/';
  return parsed;
}

function routeIdentity(value, label) {
  const parsed = normalizeUrl(value, label);
  return `${parsed.protocol}//${parsed.host}${parsed.pathname === '/' ? '/' : parsed.pathname}`;
}

function endpointFromLine(text, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = text.match(new RegExp(`${escaped}\\s*=\\s*\\{[\\s\\S]*?endpoint\\s*=\\s*"([^"]+)"`));
  return match?.[1] ?? null;
}

function validateCodexRoute(configText, expectedBaseUrl) {
  if (typeof configText !== 'string' || configText.length === 0) fail('configuration is empty');
  const provider = tomlString(configText, 'model_provider');
  if (provider !== 'OpenAI') fail('model_provider must be OpenAI');
  const providerSection = tomlSection(configText, 'model_providers.OpenAI');
  if (!providerSection) fail('model_providers.OpenAI section is missing');
  const observedBaseUrl = tomlString(providerSection, 'base_url');
  if (!observedBaseUrl) fail('OpenAI base_url is missing');
  const expectedRoute = routeIdentity(expectedBaseUrl, 'expected base URL');
  const observedRoute = routeIdentity(observedBaseUrl, 'OpenAI base_url');
  if (observedRoute !== expectedRoute) {
    fail(`OpenAI base_url must target the managed Gateway (${expectedRoute})`);
  }
  if (tomlString(providerSection, 'wire_api') !== 'responses') {
    fail('OpenAI wire_api must be responses');
  }
  const logs = endpointFromLine(configText, 'exporter');
  const traces = endpointFromLine(configText, 'trace_exporter');
  const expectedLogs = `${expectedRoute.replace(/\/$/, '')}/otel/v1/logs`;
  const expectedTraces = `${expectedRoute.replace(/\/$/, '')}/otel/v1/traces`;
  if (logs !== expectedLogs) fail('OTLP logs endpoint must target the managed Gateway');
  if (traces !== expectedTraces) fail('OTLP traces endpoint must target the managed Gateway');
  return {
    schema_version: SCHEMA_VERSION,
    ok: true,
    base_url: observedRoute,
    wire_api: 'responses',
    otlp_logs_endpoint: logs,
    otlp_traces_endpoint: traces,
  };
}

function parseArgs(argv) {
  let config;
  let expectedBaseUrl;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!value || (flag !== '--config' && flag !== '--expected-base-url')) {
      fail('usage: codex-route-preflight.js --config PATH --expected-base-url URL');
    }
    if (flag === '--config') {
      if (config !== undefined) fail('duplicate --config');
      config = value;
    } else {
      if (expectedBaseUrl !== undefined) fail('duplicate --expected-base-url');
      expectedBaseUrl = value;
    }
    index += 1;
  }
  if (!config || !expectedBaseUrl) {
    fail('usage: codex-route-preflight.js --config PATH --expected-base-url URL');
  }
  return { config, expectedBaseUrl };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  let text;
  try {
    text = fs.readFileSync(args.config, 'utf8');
  } catch (error) {
    fail(`cannot read configuration: ${error.code || 'read_error'}`);
  }
  const result = validateCodexRoute(text, args.expectedBaseUrl);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  }
}

module.exports = { SCHEMA_VERSION, validateCodexRoute, parseArgs, main };
