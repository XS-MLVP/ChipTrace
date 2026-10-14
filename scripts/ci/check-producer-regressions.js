'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');

const callbackTests = [
  'client::tests::sse_callback_reenters_the_request_span_after_creation_scope_ends',
  'client::tests::response_completed_reenters_the_request_span_after_creation_scope_ends',
  'client::tests::response_failure_reenters_the_request_span_after_creation_scope_ends',
];
const parallelTests = ['client::tests::parallel_response_terminals_keep_their_creation_spans'];
const sessionTests = [
  'message_processor::message_processor_tracing_tests::thread_start_jsonrpc_span_exports_server_span_and_parents_children',
  'message_processor::message_processor_tracing_tests::turn_start_jsonrpc_span_parents_core_turn_spans',
];

function verifyNamedTests(log, expected) {
  const tests = [...log.matchAll(/^test (\S+) \.\.\. (ok|FAILED)$/gm)];
  assert.deepEqual(tests.map(match => match[1]).sort(), [...expected].sort(), 'producer regressions were not all executed exactly once');
  assert.ok(tests.every(match => match[2] === 'ok'), 'producer regression failed');
  const summaries = [...log.matchAll(/^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;/gm)];
  assert.equal(summaries.length, 1, 'missing or ambiguous producer test summary');
  assert.equal(summaries[0][1], 'ok');
  assert.equal(Number(summaries[0][2]), expected.length);
  assert.equal(Number(summaries[0][3]), 0);
}

function verifyProducerRegressions(callbackLog, parallelLog) {
  verifyNamedTests(callbackLog, callbackTests);
  verifyNamedTests(parallelLog, parallelTests);
  return {
    schema_version: 'chiptrace.producer-regression-check.v1',
    passed_tests: callbackTests.length + parallelTests.length,
    regression_names: [...callbackTests, ...parallelTests],
  };
}

function verifyProducerSessionRegressions(sessionLog) {
  verifyNamedTests(sessionLog, sessionTests);
  return {
    schema_version: 'chiptrace.producer-session-regression-check.v1',
    passed_tests: sessionTests.length,
    regression_names: sessionTests,
  };
}

if (require.main === module) {
  const [callbackFile, parallelFile, sessionFile] = process.argv.slice(2);
  assert.ok(callbackFile && parallelFile, 'usage: check-producer-regressions.js <callbacks.log> <parallel.log> [session.log]');
  const sessionReport = sessionFile
    ? verifyProducerSessionRegressions(fs.readFileSync(sessionFile, 'utf8'))
    : null;
  const report = verifyProducerRegressions(
    fs.readFileSync(callbackFile, 'utf8'), fs.readFileSync(parallelFile, 'utf8'),
  );
  if (sessionReport) report.session = sessionReport;
  console.log(JSON.stringify(report, null, 2));
}

module.exports = {
  verifyProducerRegressions,
  verifyProducerSessionRegressions,
  callbackTests,
  parallelTests,
  sessionTests,
};
