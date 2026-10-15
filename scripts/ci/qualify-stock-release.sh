#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
  printf '%s\n' 'usage: qualify-stock-release.sh <new-private-output-directory>' >&2
  exit 2
fi
# Refuse stale metadata/logs from a previous invocation, including symlinks.
mkdir -m 700 -- "$1"
trace_qualification_output=$(cd -- "$1" && pwd -P)
mkdir -m 700 -- "$trace_qualification_output/runs"
export TMPDIR="$trace_qualification_output/runs"
export CHIPTRACE_PROTOCOL_MODE=unmodified_stock
export CHIPTRACE_PROTOCOL_QUALIFICATION_REPORT="$trace_qualification_output/qualification.json"
export CHIPTRACE_PROTOCOL_KEEP=1

# Preserve the real failed positive test. A timeout, signal, missing report,
# failed tool/configuration or unexpected readiness must fail the outer gate.
if timeout --signal=TERM --kill-after=30s 5m \
  node --test --test-concurrency=1 \
    --test-name-pattern='native collection delivers a single-model' \
    integrations/codex/protocol-collection.test.js \
    2>&1 | tee "$trace_qualification_output/collection.tap"; then
  trace_qualification_exit=0
else
  trace_qualification_exit=$?
fi
node scripts/ci/stock-release-gate.js \
  "$trace_qualification_output/qualification.json" "$trace_qualification_exit" \
  | tee "$trace_qualification_output/gate.json"
