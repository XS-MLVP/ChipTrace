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

function assertManagedRoute(value, expectedRoute, label) {
  if (!value) return;
  if (routeIdentity(value, label) !== expectedRoute) {
    fail(`${label} must target the managed Gateway (${expectedRoute})`);
  }
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

// A user/node config is layered over the managed system config by Stock Codex.
// It may omit inherited fields, but it must not replace the selected Provider,
// disable OTLP, or install a second route. This check is intentionally static:
// it never reads credentials or starts a model request.
function validateCodexUserOverrides(configText, expectedBaseUrl) {
  if (typeof configText !== 'string' || configText.length === 0) fail('user configuration is empty');
  const expectedRoute = routeIdentity(expectedBaseUrl, 'expected base URL');
  const selectedProvider = tomlString(configText, 'model_provider');
  if (selectedProvider && selectedProvider !== 'OpenAI') {
    fail('user configuration must not select a different model_provider');
  }
  const providerSection = tomlSection(configText, 'model_providers.OpenAI');
  if (providerSection) {
    assertManagedRoute(tomlString(providerSection, 'base_url'), expectedRoute, 'user OpenAI base_url');
    const wireApi = tomlString(providerSection, 'wire_api');
    if (wireApi && wireApi !== 'responses') fail('user OpenAI wire_api must be responses');
    if (/^\s*(?:http_headers|env_key)\s*=/m.test(providerSection)) {
      fail('user OpenAI provider must not override managed HTTP authentication');
    }
  }
  const otel = tomlSection(configText, 'otel');
  if (otel) {
    for (const [key, suffix] of [['exporter', '/otel/v1/logs'], ['trace_exporter', '/otel/v1/traces']]) {
      const scalar = tomlString(otel, key);
      if (scalar === 'none') fail(`user ${key} must not disable managed OTLP`);
      if (scalar && scalar !== 'otlp-http') fail(`user ${key} must use managed OTLP`);
      const endpoint = endpointFromLine(otel, key);
      if (endpoint) assertManagedRoute(endpoint, `${expectedRoute.replace(/\/$/, '')}${suffix}`, `user ${key} endpoint`);
      if (!scalar && /^(?:exporter|trace_exporter)\s*=\s*\{/m.test(otel) && !endpoint) {
        fail(`user ${key} must include a managed OTLP endpoint`);
      }
    }
  }
  return {
    schema_version: SCHEMA_VERSION,
    ok: true,
    checked: true,
    inherited_system_route: true,
  };
}

function parseArgs(argv) {
  let config;
  let userConfig;
  let expectedBaseUrl;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!value || (flag !== '--config' && flag !== '--user-config' && flag !== '--expected-base-url')) {
      fail('usage: codex-route-preflight.js --config PATH [--user-config PATH] --expected-base-url URL');
    }
    if (flag === '--config') {
      if (config !== undefined) fail('duplicate --config');
      config = value;
    } else if (flag === '--user-config') {
      if (userConfig !== undefined) fail('duplicate --user-config');
      userConfig = value;
    } else {
      if (expectedBaseUrl !== undefined) fail('duplicate --expected-base-url');
      expectedBaseUrl = value;
    }
    index += 1;
  }
  if (!config || !expectedBaseUrl) {
    fail('usage: codex-route-preflight.js --config PATH [--user-config PATH] --expected-base-url URL');
  }
  return { config, userConfig, expectedBaseUrl };
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
  if (args.userConfig) {
    let userText;
    try {
      userText = fs.readFileSync(args.userConfig, 'utf8');
    } catch (error) {
      fail(`cannot read user configuration: ${error.code || 'read_error'}`);
    }
    result.user_config = validateCodexUserOverrides(userText, args.expectedBaseUrl);
  }
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

module.exports = {
  SCHEMA_VERSION, validateCodexRoute, validateCodexUserOverrides, parseArgs, main,
};
