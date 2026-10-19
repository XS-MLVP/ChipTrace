#!/bin/sh
# Deliver one native Stock Codex lifecycle event and require the durable Relay
# receipt.  The requirements.toml template invokes this helper for every
# required lifecycle Hook.  Keep all diagnostics bounded and free of payloads
# or credentials because SessionStart output is shown directly to users.

set -u

hook_event=${CHIPTRACE_HOOK_EVENT:-}
gateway=${CHIPTRACE_GATEWAY_URL:-http://172.28.11.121:18084}
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
if [ -z "$token" ] && [ -n "${CHIPTRACE_INGEST_TOKEN_FILE:-}" ]; then
  token_file=$CHIPTRACE_INGEST_TOKEN_FILE
  if [ ! -f "$token_file" ] || [ ! -r "$token_file" ]; then
    fail ingest_token_file_unreadable
  fi
  token=$(/usr/bin/head -c 4097 -- "$token_file" 2>/dev/null | /usr/bin/tr -d '\r\n') || fail ingest_token_file_unreadable
fi
[ -n "$token" ] || fail ingest_token_missing
case "$token" in
  *[![:print:]]*) fail ingest_token_invalid ;;
esac

event=$(/usr/bin/python3 -c '
import datetime
import json
import sys
import uuid

try:
    raw = sys.stdin.buffer.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("oversized")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("object required")
    value.setdefault("event_id", str(uuid.uuid4()))
    value.setdefault("occurred_at", datetime.datetime.now(datetime.timezone.utc).isoformat())
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(2)
' 2>/dev/null) || fail invalid_hook_json

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
