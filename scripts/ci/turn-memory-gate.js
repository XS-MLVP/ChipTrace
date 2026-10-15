#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);
const CASES = [
  { test: 'platform_inspection::tests::large_turn_sidecar_memory', field: 'measurement',
    schema: 'chiptrace.turn-writer-memory.v1', references: 200000,
    bytesField: 'turn_bytes', minimumBytes: 32 * 1024 * 1024, budgetKiB: 128 * 1024 },
  { test: 'platform_projection::tests::large_manifest_metadata_memory', field: 'projection_manifest_measurement',
    schema: 'chiptrace.projection-reader-memory.v1', references: 400000,
    bytesField: 'manifest_bytes', minimumBytes: 64 * 1024 * 1024, budgetKiB: 48 * 1024 },
  { test: 'platform_turns::tests::large_turn_page_metadata_memory', field: 'turn_page_measurement',
    schema: 'chiptrace.turn-page-reader-memory.v1', references: 400000,
    bytesField: 'turn_bytes', minimumBytes: 64 * 1024 * 1024, budgetKiB: 48 * 1024 },
];

async function main() {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== '--report')) throw new Error('usage: turn-memory-gate.js [--report FILE]');
  const report = { schema_version: 'chiptrace.turn-memory-gate.v1', synthetic: true,
    session_delivery_claimed: false, tests_executed: 0, ok: false };
  try {
    // Measure the test process alone, never Cargo or compiler peak memory.
    const build = await run('cargo', ['test', '-p', 'chiptrace', '--lib', '--no-run', '--locked', '--message-format=json'],
      { maxBuffer: 16 * 1024 * 1024, timeout: 10 * 60 * 1000 });
    const artifacts = build.stdout.trim().split('\n').map(line => JSON.parse(line))
      .filter(value => value.reason === 'compiler-artifact' && value.target.name === 'chiptrace'
        && value.profile.test === true && value.executable);
    assert.equal(artifacts.length, 1, 'exactly one chiptrace library test executable is required');
    for (const specification of CASES) {
      let output;
      try {
        output = await run(artifacts[0].executable, ['--exact', specification.test, '--ignored', '--nocapture'],
          { maxBuffer: 1024 * 1024, timeout: 120000 });
      } catch (error) {
        process.stdout.write(error.stdout || '');
        process.stderr.write(error.stderr || '');
        throw error;
      }
      process.stdout.write(output.stdout);
      assert.match(output.stdout, /^test result: ok\. 1 passed; 0 failed; 0 ignored;/m,
        'each RSS regression must actually execute exactly one test in its own process');
      const measurements = output.stdout.split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line));
      assert.equal(measurements.length, 1, 'exactly one memory measurement is required per test');
      const measurement = measurements[0];
      assert.equal(measurement.schema_version, specification.schema);
      assert.equal(measurement.synthetic, true);
      assert.equal(measurement.session_delivery_claimed, false);
      assert.equal(measurement.references, specification.references);
      assert.ok(Number.isSafeInteger(measurement[specification.bytesField])
        && measurement[specification.bytesField] > specification.minimumBytes);
      assert.equal(measurement.memory_budget_kib, specification.budgetKiB);
      assert.ok(Number.isSafeInteger(measurement.max_rss_kib) && measurement.max_rss_kib > 0);
      assert.ok(measurement.max_rss_kib <= measurement.memory_budget_kib);
      report[specification.field] = measurement;
      report.tests_executed += 1;
    }
    assert.equal(report.tests_executed, CASES.length);
    report.ok = true;
  } catch (error) {
    report.error = String(error.message).slice(0, 2000);
    process.exitCode = 1;
  } finally {
    if (args.length) await fs.writeFile(args[1], `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    process.stdout.write(`${JSON.stringify(report)}\n`);
  }
}

main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
