#!/bin/sh
# Deliver one Claude Code lifecycle event to ChipTrace and require the durable
# Relay receipt.
#
# Claude Code has no native Turn ID. A UserPromptSubmit hook creates one per
# prompt and the remaining turn-scoped hooks reuse it, so Wire, Hook and the
# canonical projection share one explicit derived identity. The derivation is
# recorded in the payload as turn_identity_source=claude_hook_prompt_boundary.
#
# Required environment (the installer/settings supply them):
#   CHIPTRACE_GATEWAY_URL          default http://127.0.0.1:18084
#   CHIPTRACE_INGEST_TOKEN_FILE    default /etc/chiptrace/ingest-token
#   CHIPTRACE_CLAUDE_STATE_DIR     default /var/lib/chiptrace/claude-turn-state

set -u

gateway=${CHIPTRACE_GATEWAY_URL:-http://127.0.0.1:18084}
gateway=${gateway%/}
state_dir=${CHIPTRACE_CLAUDE_STATE_DIR:-/var/lib/chiptrace/claude-turn-state}
event_name=${CHIPTRACE_HOOK_EVENT:-}

fail() {
  reason=$1
  if [ "$event_name" = "SessionStart" ]; then
    /usr/bin/printf '%s\n' "{\"continue\":false,\"stopReason\":\"ChipTrace cloud ingest unavailable: ${reason}\"}"
    exit 0
  fi
  /usr/bin/printf 'ChipTrace Claude Hook failed: %s\n' "$reason" >&2
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

mkdir -p "$state_dir" 2>/dev/null || fail state_dir_unavailable

# Read the hook payload and inject a deterministic Turn identity.  Only fixed
# metadata and a prompt digest are persisted; no prompt or tool body is stored
# in the state file.
event=$(CHIPTRACE_EVENT_HINT="$event_name" CHIPTRACE_STATE_DIR="$state_dir" \
  /usr/bin/python3 -c '
import datetime
import hashlib
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
except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(2)

hook = str(value.get("hook_event_name") or os.environ.get("CHIPTRACE_EVENT_HINT") or "")
session = str(value.get("session_id") or "").strip()
if not hook or not session:
    raise SystemExit(3)
value.setdefault("event_id", str(uuid.uuid4()))
value.setdefault("occurred_at", datetime.datetime.now(datetime.timezone.utc).isoformat())
model = os.environ.get("CHIPTRACE_MODEL") or os.environ.get("ANTHROPIC_MODEL")
if model and not value.get("model"):
    # Session-level alias from the Claude Code configuration; per-request
    # Wire remains the source of truth for the executed model.
    value["model"] = model
    value["model_source"] = "claude_hook_env"

state_dir = os.environ["CHIPTRACE_STATE_DIR"]
state_path = os.path.join(state_dir, session + ".json")
state = {}
try:
    with open(state_path, "r", encoding="utf-8") as handle:
        state = json.load(handle)
except (OSError, ValueError):
    state = {}

def write_state(next_state):
    temporary = state_path + ".tmp." + str(os.getpid())
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(next_state, handle, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, state_path)

# Claude Code supplies a native prompt_id on every turn-scoped Hook. It is the
# Turn identity used by Wire correlation, Hooks and the canonical projection;
# no synthetic Turn UUID is invented here.
turn_scoped = hook in {
    "UserPromptSubmit", "PreToolUse", "PostToolUse", "PermissionRequest",
    "Stop", "PreCompact", "PostCompact", "SubagentStop",
}
if not value.get("permission_mode"):
    value["permission_mode"] = (
        os.environ.get("CHIPTRACE_PERMISSION_MODE")
        or os.environ.get("CLAUDE_PERMISSION_MODE")
        or "unknown"
    )
    value["permission_mode_source"] = "hook_env_or_unknown"
if hook == "SessionStart":
    state = {"session_id": session, "turn_index": 0}
    write_state(state)
elif hook == "SessionEnd":
    value["turn_identity_source"] = "claude_session_boundary"
else:
    turn_index = int(state.get("turn_index") or 0)
    if hook == "UserPromptSubmit":
        turn_index += 1
    elif turn_index < 1:
        turn_index = 1
    turn_id = str(value.get("prompt_id") or "").strip()
    if turn_scoped and not turn_id:
        raise SystemExit(4)
    if hook == "UserPromptSubmit":
        prompt = value.get("prompt")
        prompt_sha256 = (
            hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            if isinstance(prompt, str) else None
        )
        state = {
            "session_id": session,
            "turn_id": turn_id,
            "turn_index": turn_index,
            "prompt_sha256": prompt_sha256,
            "started_at": value["occurred_at"],
        }
        write_state(state)
    open_tools = dict(state.get("open_tools") or {})
    if hook == "PreToolUse":
        tool_call = str(value.get("tool_use_id") or "").strip()
        if tool_call:
            open_tools[tool_call] = str(value.get("tool_name") or "")
    elif hook == "PostToolUse":
        open_tools.pop(str(value.get("tool_use_id") or "").strip(), None)
    if turn_scoped:
        value["turn_id"] = turn_id
        value["root_turn_id"] = turn_id
        value["turn_identity_source"] = "claude_prompt_id"
        value["turn_index"] = turn_index
    if open_tools != dict(state.get("open_tools") or {}):
        state = dict(state)
        state["open_tools"] = open_tools
        write_state(state)
    if hook == "PostToolUse" and not value.get("status"):
        response = value.get("tool_response")
        if isinstance(response, dict):
            if response.get("interrupted") is True:
                value["status"] = "cancelled"
            elif response.get("is_error") is True or response.get("error"):
                value["status"] = "error"
            else:
                value["status"] = "success"
    # Claude Code emits SubagentStop with an empty agent_type for generic
    # subagents. The ingest contract requires a non-empty type, so label the
    # producer gap explicitly instead of inventing a concrete agent type.
    if hook == "SubagentStop" and not str(value.get("agent_type") or "").strip():
        value["agent_type"] = "unspecified"
        value["agent_type_source"] = "claude_payload_empty"
extra = []
if hook == "SessionEnd":
    # A PreToolUse with no PostToolUse when the Session closes means the tool
    # never reported a result. Record that explicitly as cancelled so the
    # runtime span is terminal; the evidence is the closed Session boundary.
    background = {
        str(task.get("id"))
        for task in (state.get("open_tools_background") or [])
        if isinstance(task, dict)
    }
    last_turn = str(state.get("turn_id") or "").strip()
    for tool_call, tool_name in (state.get("open_tools") or {}).items():
        if tool_call in background:
            continue
        extra.append({
            "hook_event_name": "PostToolUse",
            "session_id": session,
            "turn_id": last_turn or None,
            "root_turn_id": last_turn or None,
            "turn_identity_source": "claude_prompt_id",
            "tool_use_id": tool_call,
            "tool_name": tool_name or "unknown",
            # The tool never returned, so there is no argument echo to carry;
            # an empty object keeps the record structurally valid while the
            # explicit evidence field records why it is cancelled.
            "tool_input": {},
            "tool_response": {"interrupted": True},
            "status": "cancelled",
            "cancel_evidence": "session_ended_without_post_tool_use",
            "event_id": str(uuid.uuid4()),
            "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "model": value.get("model"),
            "permission_mode": value.get("permission_mode"),
        })
print(json.dumps({"event": value, "extra": extra}, ensure_ascii=False, separators=(",", ":")))
' 2>/dev/null) || fail invalid_hook_json

# One HTTP request per event keeps the durable receipt contract exact: every
# payload yields source_records=1 and captures=2. SessionEnd may carry extra
# derived cancellations, so fan them out instead of merging.
payloads=$(/usr/bin/printf '%s' "$event" | /usr/bin/python3 -c '
import json, sys
value = json.load(sys.stdin)
items = [value["event"]] + list(value.get("extra") or [])
for item in items:
    print(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
' 2>/dev/null) || fail invalid_hook_json
[ -n "$payloads" ] || fail invalid_hook_json

session_id=$(/usr/bin/printf '%s' "$event" | /usr/bin/python3 -c '
import json,sys
try: print(json.load(sys.stdin)["event"].get("session_id") or "")
except Exception: print("")' 2>/dev/null)

# A here-document keeps the loop in this shell, so `exit 0` and `fail` keep
# their fail-closed meaning instead of only ending a pipeline subshell.
while IFS= read -r payload; do
  [ -n "$payload" ] || continue
  sent=0
  for attempt in 1 2; do
    if wire=$(
      /usr/bin/printf '%s' "$payload" |
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
        sent=1
        break
      fi
      fail invalid_durable_receipt
    fi
  done
  [ "$sent" = "1" ] || fail gateway_unavailable
done <<EOF
$payloads
EOF

if [ "$event_name" = "SessionEnd" ] && [ -n "$session_id" ]; then
  # Session end is terminal for this Hook; drop stale turn state.
  /usr/bin/rm -f -- "$state_dir/$session_id.json"
fi
exit 0
