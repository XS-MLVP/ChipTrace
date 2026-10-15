#!/usr/bin/env bash
set -uo pipefail
umask 077

if test "$#" -lt 3; then
  printf '%s\n' 'usage: run-producer-check.sh <phase> <new-log-file> <command> [arguments...]' >&2
  exit 2
fi
trace_phase=$1
trace_log=$2
shift 2
if ! [[ "$trace_phase" =~ ^[a-z][a-z0-9-]{0,63}$ ]]; then
  printf '%s\n' 'invalid producer check phase' >&2
  exit 2
fi
# Each invocation owns a new log; never overwrite an earlier failure.
if ! (set -o noclobber; : > "$trace_log"); then
  printf '%s\n' 'producer check requires a new writable log file' >&2
  exit 2
fi
trace_interval=${CHIPTRACE_PRODUCER_RESOURCE_INTERVAL_SECONDS:-}
trace_monitor_pid=
if test -n "$trace_interval"; then
  if ! [[ "$trace_interval" =~ ^[1-9][0-9]{0,3}$ ]] || test "$trace_interval" -gt 3600; then
    printf '%s\n' 'invalid producer resource interval' >&2
    exit 2
  fi
  node "$(dirname "$0")/producer-resources.js" "$trace_phase" "$trace_interval" &
  trace_monitor_pid=$!
fi
trace_cleanup() {
  if test -n "$trace_monitor_pid"; then
    kill "$trace_monitor_pid" 2>/dev/null || true
    wait "$trace_monitor_pid" 2>/dev/null || true
  fi
}
trap trace_cleanup EXIT
if "$@" 2>&1 | tee -a "$trace_log"; then
  trace_pipeline_status=("${PIPESTATUS[@]}")
else
  trace_pipeline_status=("${PIPESTATUS[@]}")
fi
trace_status=${trace_pipeline_status[0]}
if test "${trace_pipeline_status[1]}" -ne 0; then
  printf '%s\n' 'producer log write failed' >&2
  if test "$trace_status" -eq 0; then trace_status=${trace_pipeline_status[1]}; fi
fi
if test "$trace_status" -eq 0; then exit 0; fi
node "$(dirname "$0")/report-producer-failure.js" "$trace_phase" "$trace_log" "$trace_status" \
  "${trace_pipeline_status[0]}" "${trace_pipeline_status[1]}"
exit "$trace_status"
