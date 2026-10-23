#!/bin/sh
# Deliver one native Stock Codex lifecycle event and require the durable Relay
# receipt.  The requirements.toml template invokes this helper for every
# required lifecycle Hook.  Keep all diagnostics bounded and free of payloads
# or credentials because SessionStart output is shown directly to users.

set -u

hook_event=${CHIPTRACE_HOOK_EVENT:-}
# Keep the default local so a standard single-host deployment does not send
# lifecycle data to a private example address.  Remote/sidecar deployments
# must set CHIPTRACE_GATEWAY_URL explicitly in the service environment.
gateway=${CHIPTRACE_GATEWAY_URL:-http://127.0.0.1:18084}
gateway=${gateway%/}

fail() {
  reason=$1
  if [ "$hook_event" = "SessionStart" ]; then
    /usr/bin/printf '%s\n' "{\"continue\":false,\"stopReason\":\"ChipTrace cloud ingest unavailable: ${reason}\"}"
    exit 0
  fi
  /usr/bin/printf 'ChipTrace Hook failed: %s\n' "$reason" >&2
  exit 1
}

case "$gateway" in
  http://*|https://*) ;;
  *) fail gateway_url_invalid ;;
esac

token=${CHIPTRACE_INGEST_TOKEN:-}
if [ -z "$token" ]; then
  token_file=${CHIPTRACE_INGEST_TOKEN_FILE:-/etc/chiptrace/ingest-token}
  if [ ! -f "$token_file" ] || [ ! -r "$token_file" ]; then
    # A missing default file is reported as a missing credential, while an
    # explicitly supplied path remains distinguishable as a deployment error.
    if [ -n "${CHIPTRACE_INGEST_TOKEN_FILE:-}" ]; then
      fail ingest_token_file_unreadable
    fi
    fail ingest_token_missing
  fi
  token=$(/usr/bin/head -c 4097 -- "$token_file" 2>/dev/null | /usr/bin/tr -d '\r\n') || fail ingest_token_file_unreadable
fi
[ -n "$token" ] || fail ingest_token_missing
case "$token" in
  *[![:print:]]*) fail ingest_token_invalid ;;
esac

event=$(CHIPTRACE_EVENT_HINT="${CHIPTRACE_HOOK_EVENT:-}" /usr/bin/python3 -c '
import datetime
import json
import os
import sys
import uuid

try:
    raw = sys.stdin.buffer.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("oversized")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("object required")
    # An empty invocation carries no Session, Turn or payload. Codex emits a
    # bare "{}" when it probes the Hook; posting it only creates an
    # unattributable quality error, so acknowledge locally and send nothing.
    if not value:
        raise SystemExit(0)
    value.setdefault("event_id", str(uuid.uuid4()))
    value.setdefault("occurred_at", datetime.datetime.now(datetime.timezone.utc).isoformat())
    # Codex can invoke a required Hook with an event name but no payload. The
    # managed requirements.toml already names the event in
    # CHIPTRACE_HOOK_EVENT, so carry it explicitly instead of letting ingest
    # reject a valid boundary.
    if not str(value.get("hook_event_name") or "").strip():
        hint = str(os.environ.get("CHIPTRACE_EVENT_HINT") or "").strip()
        if hint:
            value["hook_event_name"] = hint
            value["hook_event_name_source"] = "requirements_env"
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(2)
' 2>/dev/null)
status=$?
# An empty payload exits 0 with no output: local acknowledgement only.
[ "$status" -eq 0 ] && [ -z "$event" ] && exit 0
[ "$status" -eq 0 ] || fail invalid_hook_json

for attempt in 1 2; do
  if wire=$(
    /usr/bin/printf '%s' "$event" |
      /usr/bin/curl --disable --fail --silent --show-error \
        --connect-timeout 0.5 --max-time 1 --max-filesize 65536 \
        --write-out '\n%{http_code}' \
        -H "Authorization: Bearer $token" \
        -H 'Content-Type: application/json' \
        --data-binary @- "$gateway/hooks/codex"
  ); then
    if /usr/bin/printf '%s' "$wire" | /usr/bin/python3 -c '
import json
import sys

try:
    wire = sys.stdin.read(65537)
    body, status = wire.rsplit("\n", 1)
    value = json.loads(body)
    receipt = value["chiptrace"]
    summary = receipt["summary"]
    partial = value["partialSuccess"]
    expected = {"source_records": 1, "derived_captures": 1, "unknown_events": 0,
                "attributed_quality_errors": 0}
    valid = (
        len(wire) <= 65536 and status == "200"
        and receipt["ok"] is True and receipt["durable"] is True
        and type(receipt["captures"]) is int and receipt["captures"] == 2
        and type(receipt["duplicates"]) is int and 0 <= receipt["duplicates"] <= 2
        and summary["endpoint"] == "codex_hook"
        and all(type(summary[key]) is int and summary[key] == count
                for key, count in expected.items())
        and summary["conversion_errors"] == []
        and all(type(partial[key]) is int and partial[key] == 0
                for key in ("rejectedLogRecords", "rejectedSpans"))
        and partial["errorMessage"] is None
    )
except (ValueError, TypeError, KeyError, AttributeError):
    valid = False
sys.exit(0 if valid else 1)
'; then
      exit 0
    fi
    fail invalid_durable_receipt
  fi
done

fail gateway_unavailable
