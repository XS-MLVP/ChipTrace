from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from .compression import CompressionError, decompress_chunk
from .model import utc_now

try:
    import orjson
except ImportError:  # pragma: no cover - optional performance dependency
    orjson = None


CATALOG_FORMAT = "agent-session-sqlite-delivery-v4"
CATALOG_SCHEMA_VERSION = "session-catalog-v4"
QUALITY_POLICY_VERSION = "session-trace-completeness-v1"
SESSION_DEFINITION = (
    "sha256(source_namespace + NUL + (client_metadata.session_id or client_metadata.thread_id)); "
    "one orphan session per capture when both are absent"
)
TRAJECTORY_DEFINITION = SESSION_DEFINITION
TURN_DEFINITION = "sha256(traj_id + NUL + client_metadata.turn_id)"
TERMINAL_TYPES = {
    "response.completed",
    "response.failed",
    "response.incomplete",
    "response.cancelled",
}
HISTORY_ITEM_TYPES = {
    "reasoning",
    "agent_message",
    "function_call",
    "function_call_output",
    "custom_tool_call",
    "custom_tool_call_output",
    "computer_call",
    "computer_call_output",
    "compaction",
    "compaction_trigger",
}
COMPACTION_ITEM_TYPES = {"compaction", "compaction_trigger"}
RELEVANT_SSE_MARKERS = (
    "response.completed",
    "response.failed",
    "response.incomplete",
    "response.cancelled",
    "response.output_item.done",
    "response.function_call_arguments.done",
    "response.custom_tool_call_input.done",
    "response.output_text.done",
)


CATALOG_SCHEMA = """
PRAGMA foreign_keys=OFF;
CREATE TABLE dataset_meta(
  key TEXT PRIMARY KEY,value TEXT NOT NULL,value_type TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE shards(
  shard_id INTEGER PRIMARY KEY,file_name TEXT NOT NULL UNIQUE,
  file_size_bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,records INTEGER NOT NULL,
  trajectories INTEGER NOT NULL,turns INTEGER NOT NULL,raw_bytes INTEGER NOT NULL,
  stored_bytes INTEGER NOT NULL,first_event_utc TEXT,last_event_utc TEXT,
  input_tokens INTEGER NOT NULL,cached_input_tokens INTEGER NOT NULL,
  cache_write_tokens INTEGER NOT NULL,uncached_input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,reasoning_tokens INTEGER NOT NULL,
  total_tokens INTEGER NOT NULL,payload_table TEXT NOT NULL,payload_codec TEXT NOT NULL
);
CREATE TABLE trajectories(
  traj_id TEXT PRIMARY KEY,source_namespace TEXT NOT NULL,
  shard_id INTEGER NOT NULL,turns INTEGER NOT NULL,
  steps INTEGER NOT NULL,first_event_utc TEXT,last_event_utc TEXT,
  first_step_id TEXT NOT NULL,last_step_id TEXT NOT NULL,raw_bytes INTEGER NOT NULL,
  stored_bytes INTEGER NOT NULL,parse_ok_steps INTEGER NOT NULL,
  truncated_steps INTEGER NOT NULL,thread_id_present_steps INTEGER NOT NULL,
  turn_id_present_steps INTEGER NOT NULL,terminal_present_steps INTEGER NOT NULL,
  terminal_completed_steps INTEGER NOT NULL,terminal_failed_steps INTEGER NOT NULL,
  usage_present_steps INTEGER NOT NULL,compaction_steps INTEGER NOT NULL,
  subagent_steps INTEGER NOT NULL,final_message_steps INTEGER NOT NULL,
  tool_calls INTEGER NOT NULL,tool_results INTEGER NOT NULL,
  matched_tool_calls INTEGER NOT NULL,orphan_tool_results INTEGER NOT NULL,
  input_tokens INTEGER NOT NULL,cached_input_tokens INTEGER NOT NULL,
  cache_write_tokens INTEGER NOT NULL,uncached_input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,reasoning_tokens INTEGER NOT NULL,
  total_tokens INTEGER NOT NULL,left_censored INTEGER NOT NULL,
  right_censored INTEGER NOT NULL,closed INTEGER NOT NULL,
  projection_mode TEXT NOT NULL,projection_gap_status TEXT NOT NULL,
  reward REAL,reward_source TEXT,
  FOREIGN KEY(shard_id) REFERENCES shards(shard_id)
) WITHOUT ROWID;
CREATE TABLE turns(
  turn_key TEXT PRIMARY KEY,traj_id TEXT NOT NULL,turn_index INTEGER NOT NULL,
  first_event_utc TEXT,last_event_utc TEXT,steps INTEGER NOT NULL,
  terminal_completed_steps INTEGER NOT NULL,terminal_failed_steps INTEGER NOT NULL,
  usage_present_steps INTEGER NOT NULL,compaction_steps INTEGER NOT NULL,
  subagent_steps INTEGER NOT NULL,final_message_steps INTEGER NOT NULL,
  tool_calls INTEGER NOT NULL,tool_results INTEGER NOT NULL,input_tokens INTEGER NOT NULL,
  cached_input_tokens INTEGER NOT NULL,cache_write_tokens INTEGER NOT NULL,
  uncached_input_tokens INTEGER NOT NULL,output_tokens INTEGER NOT NULL,
  reasoning_tokens INTEGER NOT NULL,total_tokens INTEGER NOT NULL,
  UNIQUE(traj_id,turn_index),FOREIGN KEY(traj_id) REFERENCES trajectories(traj_id)
) WITHOUT ROWID;
CREATE TABLE steps(
  step_id TEXT PRIMARY KEY,shard_id INTEGER NOT NULL,record_id INTEGER NOT NULL,
  raw_bytes INTEGER NOT NULL,stored_bytes INTEGER NOT NULL,raw_sha256 TEXT NOT NULL,
  traj_id TEXT NOT NULL,turn_key TEXT,turn_index INTEGER,step_index INTEGER NOT NULL,
  step_index_in_turn INTEGER,event_ts TEXT,received_at TEXT,started_at TEXT,
  finished_at TEXT,model TEXT,response_http_status INTEGER,response_api_status TEXT,
  terminal_event_type TEXT NOT NULL,terminal_present INTEGER NOT NULL,
  terminal_completed INTEGER NOT NULL,terminal_matches_source_index INTEGER NOT NULL,
  payload_parse_ok INTEGER NOT NULL,sse_parse_errors INTEGER NOT NULL,
  request_truncated INTEGER NOT NULL,response_truncated INTEGER NOT NULL,
  capture_error_present INTEGER NOT NULL,source_namespace TEXT NOT NULL,
  response_id TEXT,previous_response_id TEXT,session_id TEXT,thread_id TEXT,
  root_session_id TEXT,parent_session_id TEXT,goal_id TEXT,agent_id TEXT,branch_id TEXT,
  thread_id_present INTEGER NOT NULL,
  turn_id_present INTEGER NOT NULL,subagent_present INTEGER NOT NULL,
  request_input_items INTEGER NOT NULL,prior_history_items INTEGER NOT NULL,
  compaction_items INTEGER NOT NULL,output_items INTEGER NOT NULL,
  output_tool_calls INTEGER NOT NULL,output_messages INTEGER NOT NULL,
  final_message_present INTEGER NOT NULL,final_message_bytes INTEGER NOT NULL,
  final_message_sha256 TEXT,history_tool_results INTEGER NOT NULL,
  new_tool_results INTEGER NOT NULL,stream INTEGER NOT NULL,
  UNIQUE(shard_id,record_id),UNIQUE(traj_id,step_index),
  FOREIGN KEY(shard_id) REFERENCES shards(shard_id),
  FOREIGN KEY(traj_id) REFERENCES trajectories(traj_id),
  FOREIGN KEY(turn_key) REFERENCES turns(turn_key)
) WITHOUT ROWID;
CREATE TABLE step_usage(
  step_id TEXT PRIMARY KEY,usage_present INTEGER NOT NULL,input_tokens INTEGER NOT NULL,
  cached_input_tokens INTEGER NOT NULL,cache_write_tokens INTEGER NOT NULL,
  uncached_input_tokens INTEGER NOT NULL,output_tokens INTEGER NOT NULL,
  reasoning_tokens INTEGER NOT NULL,total_tokens INTEGER NOT NULL,
  parsed_usage_present INTEGER NOT NULL,parsed_matches_source_index INTEGER NOT NULL,
  usage_source TEXT NOT NULL,FOREIGN KEY(step_id) REFERENCES steps(step_id)
) WITHOUT ROWID;
CREATE TABLE step_item_counts(
  step_id TEXT NOT NULL,direction TEXT NOT NULL,item_type TEXT NOT NULL,
  item_count INTEGER NOT NULL,PRIMARY KEY(step_id,direction,item_type),
  FOREIGN KEY(step_id) REFERENCES steps(step_id)
) WITHOUT ROWID;
CREATE TABLE tool_calls(
  call_key TEXT PRIMARY KEY,traj_id TEXT NOT NULL,turn_key TEXT,
  source_step_id TEXT NOT NULL,shard_id INTEGER NOT NULL,record_id INTEGER NOT NULL,
  output_index INTEGER NOT NULL,call_type TEXT NOT NULL,tool_name TEXT,
  call_id_present INTEGER NOT NULL,call_status TEXT,
  argument_bytes INTEGER NOT NULL,argument_sha256 TEXT,
  argument_json TEXT,arguments_complete INTEGER NOT NULL,
  result_present INTEGER NOT NULL DEFAULT 0,
  definition_present INTEGER NOT NULL DEFAULT 0,
  linkage_status TEXT NOT NULL DEFAULT 'open_tail'
    CHECK(linkage_status IN ('executed','abandoned_concurrent','abandoned_retry','open_tail','capture_gap')),
  FOREIGN KEY(shard_id) REFERENCES shards(shard_id),
  FOREIGN KEY(traj_id) REFERENCES trajectories(traj_id),
  FOREIGN KEY(turn_key) REFERENCES turns(turn_key),
  FOREIGN KEY(source_step_id) REFERENCES steps(step_id)
) WITHOUT ROWID;
CREATE TABLE tool_definitions(
  definition_key TEXT PRIMARY KEY,traj_id TEXT NOT NULL,tool_name TEXT NOT NULL,
  tool_type TEXT,schema_version TEXT,description_present INTEGER NOT NULL,
  parameters_present INTEGER NOT NULL,
  definition_bytes INTEGER NOT NULL,definition_sha256 TEXT NOT NULL,
  schema_json TEXT NOT NULL,
  first_seen_step_id TEXT NOT NULL,
  FOREIGN KEY(traj_id) REFERENCES trajectories(traj_id),
  FOREIGN KEY(first_seen_step_id) REFERENCES steps(step_id)
) WITHOUT ROWID;
CREATE TABLE tool_results(
  call_key TEXT PRIMARY KEY,traj_id TEXT NOT NULL,turn_key TEXT,
  first_seen_step_id TEXT NOT NULL,shard_id INTEGER NOT NULL,record_id INTEGER NOT NULL,
  result_type TEXT NOT NULL,call_id_present INTEGER NOT NULL,
  result_status TEXT,result_error INTEGER NOT NULL DEFAULT 0,
  result_bytes INTEGER NOT NULL,result_sha256 TEXT,result_json TEXT,
  matched_call INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(shard_id) REFERENCES shards(shard_id),
  FOREIGN KEY(traj_id) REFERENCES trajectories(traj_id),
  FOREIGN KEY(turn_key) REFERENCES turns(turn_key),
  FOREIGN KEY(first_seen_step_id) REFERENCES steps(step_id)
) WITHOUT ROWID;
CREATE TABLE trajectory_edges(
  parent_step_id TEXT NOT NULL,child_step_id TEXT NOT NULL,
  edge_type TEXT NOT NULL,edge_identity TEXT,
  PRIMARY KEY(parent_step_id,child_step_id,edge_type),
  FOREIGN KEY(parent_step_id) REFERENCES steps(step_id),
  FOREIGN KEY(child_step_id) REFERENCES steps(step_id)
) WITHOUT ROWID;
CREATE TABLE session_relations(
  parent_traj_id TEXT NOT NULL,child_traj_id TEXT NOT NULL,
  relation_type TEXT NOT NULL CHECK(relation_type IN ('root_session','parent_session')),
  relation_identity TEXT NOT NULL,observed_step_id TEXT NOT NULL,
  parent_present INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(parent_traj_id,child_traj_id,relation_type),
  FOREIGN KEY(child_traj_id) REFERENCES trajectories(traj_id),
  FOREIGN KEY(observed_step_id) REFERENCES steps(step_id)
) WITHOUT ROWID;
CREATE TABLE lifecycle_events(
  event_key TEXT PRIMARY KEY,traj_id TEXT NOT NULL,step_id TEXT NOT NULL,
  event_index INTEGER NOT NULL,event_type TEXT NOT NULL,event_source TEXT NOT NULL,
  UNIQUE(step_id,event_index,event_type),
  FOREIGN KEY(traj_id) REFERENCES trajectories(traj_id),
  FOREIGN KEY(step_id) REFERENCES steps(step_id)
) WITHOUT ROWID;
CREATE TABLE trajectory_quality(
  traj_id TEXT PRIMARY KEY,policy_version TEXT NOT NULL,structural_score REAL NOT NULL,
  quality_grade TEXT NOT NULL,payload_component REAL NOT NULL,
  identity_component REAL NOT NULL,terminal_component REAL NOT NULL,
  usage_component REAL NOT NULL,tool_linkage_component REAL NOT NULL,
  boundary_component REAL NOT NULL,semantic_reward_available INTEGER NOT NULL,
  score_scope TEXT NOT NULL,FOREIGN KEY(traj_id) REFERENCES trajectories(traj_id)
) WITHOUT ROWID;
CREATE VIEW session_quality AS
SELECT traj_id AS session_id,policy_version,
       structural_score AS session_completeness_score,
       quality_grade AS completeness_grade,payload_component,
       identity_component,terminal_component,usage_component,
       tool_linkage_component,boundary_component,
       semantic_reward_available,score_scope,t.steps,t.turns,t.closed,
       t.left_censored,t.right_censored,t.truncated_steps,
       t.parse_ok_steps,t.thread_id_present_steps,t.turn_id_present_steps,
       t.terminal_present_steps,t.usage_present_steps,t.tool_calls,t.tool_results,
       t.matched_tool_calls,t.orphan_tool_results
  FROM trajectory_quality q JOIN trajectories t USING(traj_id);
CREATE TABLE item_type_summary(
  direction TEXT NOT NULL,item_type TEXT NOT NULL,steps INTEGER NOT NULL,
  items INTEGER NOT NULL,PRIMARY KEY(direction,item_type)
) WITHOUT ROWID;
CREATE TABLE validation_results(
  check_name TEXT PRIMARY KEY,status TEXT NOT NULL,observed TEXT NOT NULL,
  expected TEXT,details TEXT
) WITHOUT ROWID;
"""


@dataclass(frozen=True)
class RawRecord:
    shard_id: int
    record_id: int
    capture_id: str
    event_ts: str | None
    received_at: str | None
    started_at: str | None
    finished_at: str | None
    model: str | None
    api_key_fingerprint: str | None
    response_status: int | None
    raw_bytes: int
    stored_bytes: int
    raw_sha256: str
    raw: bytes


def read_only_connection(path: Path) -> sqlite3.Connection:
    encoded = urllib.parse.quote(str(Path(path).resolve()), safe="/")
    conn = sqlite3.connect(f"file:{encoded}?mode=ro&immutable=1", uri=True, timeout=60)
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA cache_size=-65536")
    return conn


def json_loads(value: bytes | str) -> Any:
    if orjson is not None:
        return orjson.loads(value)
    return json.loads(value)


def canonical_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    if orjson is not None:
        return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def canonical_text(value: Any) -> str:
    """Return a stable UTF-8 JSON/text representation for catalog evidence."""
    return canonical_bytes(value).decode("utf-8", errors="replace")


def digest_parts(*values: str) -> str:
    digest = hashlib.sha256()
    for index, value in enumerate(values):
        if index:
            digest.update(b"\0")
        digest.update(str(value).encode("utf-8", errors="replace"))
    return digest.hexdigest()


def value_fingerprint(value: Any) -> tuple[int, str | None]:
    raw = canonical_bytes(value)
    return len(raw), hashlib.sha256(raw).hexdigest() if raw else None


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def body_value(value: Any) -> Any:
    body = as_dict(value)
    return body.get("value") if "value" in body else None


def nonempty_string(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (str, int)):
        return str(value)
    return None


def item_type(item: Any) -> str:
    if not isinstance(item, dict):
        return type(item).__name__
    return str(item.get("type") or item.get("role") or "unknown")


def is_tool_result_type(value: str) -> bool:
    return value.endswith("_call_output") or value in {"tool_result", "tool_output"}


def is_tool_call_type(value: str) -> bool:
    return not value.endswith("_call_output") and (
        value.endswith("_call") or value in {"tool_call", "function_call"}
    )


def usage_from_response(response: dict[str, Any]) -> dict[str, int]:
    usage = as_dict(response.get("usage") or response.get("usage_details"))
    input_details = as_dict(usage.get("input_tokens_details") or usage.get("input_details"))
    output_details = as_dict(usage.get("output_tokens_details") or usage.get("output_details"))

    def integer(*values: Any) -> int:
        for value in values:
            try:
                if value is not None:
                    return max(int(value), 0)
            except (TypeError, ValueError):
                pass
        return 0

    input_tokens = integer(usage.get("input_tokens"), usage.get("prompt_tokens"), usage.get("input"))
    cached = integer(input_details.get("cached_tokens"), input_details.get("cache_read_tokens"))
    cache_write = integer(
        input_details.get("cache_write_tokens"),
        input_details.get("cache_creation_tokens"),
        usage.get("cache_write_tokens"),
    )
    output_tokens = integer(usage.get("output_tokens"), usage.get("completion_tokens"), usage.get("output"))
    reasoning = integer(output_details.get("reasoning_tokens"), usage.get("reasoning_tokens"))
    total = integer(usage.get("total_tokens"), usage.get("total"), input_tokens + output_tokens)
    return {
        "present": int(bool(usage)),
        "input_tokens": input_tokens,
        "cached_input_tokens": cached,
        "cache_write_tokens": cache_write,
        "uncached_input_tokens": max(input_tokens - cached - cache_write, 0),
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning,
        "total_tokens": total,
    }


def parse_sse_response(text: str) -> dict[str, Any]:
    terminal_type = "missing"
    terminal_response: dict[str, Any] = {}
    output_done: dict[int, dict[str, Any]] = {}
    payload_done: dict[int, tuple[str, Any]] = {}
    output_text_done: dict[int, Any] = {}
    parse_errors = 0
    for line in text.splitlines():
        if not line.startswith("data:") or not any(marker in line for marker in RELEVANT_SSE_MARKERS):
            continue
        data = line[5:].lstrip()
        if not data or data == "[DONE]":
            continue
        try:
            event = json_loads(data)
        except (ValueError, TypeError):
            parse_errors += 1
            continue
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or "")
        try:
            output_index = int(event.get("output_index", -1))
        except (TypeError, ValueError):
            output_index = -1
        if event_type in TERMINAL_TYPES:
            terminal_type = event_type
            terminal_response = as_dict(event.get("response"))
        elif event_type == "response.output_item.done" and output_index >= 0:
            output_done[output_index] = as_dict(event.get("item"))
        elif event_type == "response.function_call_arguments.done" and output_index >= 0:
            payload_done[output_index] = ("arguments", event.get("arguments"))
        elif event_type == "response.custom_tool_call_input.done" and output_index >= 0:
            payload_done[output_index] = ("input", event.get("input"))
        elif event_type == "response.output_text.done" and output_index >= 0:
            output_text_done[output_index] = event.get("text")

    for index, item in output_done.items():
        payload = payload_done.get(index)
        if payload and item.get(payload[0]) in (None, ""):
            item[payload[0]] = payload[1]
        if item_type(item) == "message" and not item.get("content") and index in output_text_done:
            item["content"] = [{"type": "output_text", "text": output_text_done[index]}]
    terminal_output = terminal_response.get("output")
    if output_done:
        indexes = sorted(output_done)
        output = [output_done[index] for index in indexes]
    elif isinstance(terminal_output, list):
        output = [dict(item) if isinstance(item, dict) else item for item in terminal_output]
        indexes = list(range(len(output)))
        for index, item in enumerate(output):
            if not isinstance(item, dict):
                continue
            payload = payload_done.get(index)
            if payload and item.get(payload[0]) in (None, ""):
                item[payload[0]] = payload[1]
            if item_type(item) == "message" and not item.get("content") and index in output_text_done:
                item["content"] = [{"type": "output_text", "text": output_text_done[index]}]
    else:
        output = []
        indexes = []
    return {
        "terminal_type": terminal_type,
        "response": terminal_response,
        "output": output,
        "output_indexes": indexes,
        "parse_errors": parse_errors,
    }


def parse_response_body(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        return parse_sse_response(value)
    if isinstance(value, dict):
        status = str(value.get("status") or "")
        output = value.get("output") if isinstance(value.get("output"), list) else []
        return {
            "terminal_type": f"response.{status}" if status else "missing",
            "response": value,
            "output": output,
            "output_indexes": list(range(len(output))),
            "parse_errors": 0,
        }
    return {"terminal_type": "missing", "response": {}, "output": [], "output_indexes": [], "parse_errors": 0}


def tool_definition_summary(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    nested = value.get("function") if isinstance(value.get("function"), dict) else value
    name = nonempty_string(nested.get("name") or value.get("name"))
    if name is None:
        return None
    description = nonempty_string(nested.get("description") or value.get("description"))
    parameters = nested.get("parameters") if "parameters" in nested else value.get("parameters")
    raw = canonical_bytes(value)
    return {
        "name": name,
        "type": nonempty_string(value.get("type")),
        "schema_version": nonempty_string(
            value.get("schema_version")
            or value.get("schemaVersion")
            or value.get("version")
            or nested.get("schema_version")
            or nested.get("schemaVersion")
            or nested.get("version")
        ),
        "description_present": int(description is not None),
        "parameters_present": int(isinstance(parameters, dict)),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "schema_json": raw.decode("utf-8", errors="replace"),
    }


def request_context(request: Any) -> dict[str, Any]:
    request_obj = as_dict(request)
    metadata = as_dict(request_obj.get("client_metadata"))
    raw_input = request_obj.get("input")
    items = raw_input if isinstance(raw_input, list) else ([raw_input] if raw_input is not None else [])
    counts = Counter(item_type(item) for item in items)
    raw_tools: list[Any] = []
    for field in ("tools", "additional_tools"):
        candidate = request_obj.get(field)
        if isinstance(candidate, list):
            raw_tools.extend(candidate)
    tool_definitions = [
        definition
        for item in raw_tools
        if (definition := tool_definition_summary(item)) is not None
    ]
    prior = sum(
        count
        for kind, count in counts.items()
        if kind in HISTORY_ITEM_TYPES or is_tool_call_type(kind) or is_tool_result_type(kind)
    )
    session_id = nonempty_string(metadata.get("session_id") or metadata.get("sessionId"))
    thread_id = nonempty_string(metadata.get("thread_id") or metadata.get("threadId"))

    def metadata_identity(name: str, camel_name: str) -> str | None:
        return nonempty_string(
            metadata.get(name)
            or metadata.get(camel_name)
            or request_obj.get(name)
            or request_obj.get(camel_name)
        )

    return {
        "items": items,
        "item_counts": counts,
        "prior_history_items": prior,
        "compaction_items": sum(counts.get(kind, 0) for kind in COMPACTION_ITEM_TYPES),
        "session_id": session_id,
        "thread_id": thread_id,
        "session_identity": session_id or thread_id,
        "root_session_id": metadata_identity("root_session_id", "rootSessionId"),
        "parent_session_id": metadata_identity("parent_session_id", "parentSessionId"),
        "goal_id": metadata_identity("goal_id", "goalId"),
        "agent_id": metadata_identity("agent_id", "agentId"),
        "branch_id": metadata_identity("branch_id", "branchId"),
        "turn_id": nonempty_string(metadata.get("turn_id") or metadata.get("turnId")),
        "previous_response_id": nonempty_string(
            request_obj.get("previous_response_id")
            or request_obj.get("previousResponseId")
            or metadata.get("previous_response_id")
            or metadata.get("previousResponseId")
        ),
        "tool_definitions": tool_definitions,
        "subagent_present": int(
            metadata.get("x-openai-subagent") not in (None, "", False, "false", "0")
        ),
    }


def message_payload(item: dict[str, Any]) -> Any:
    return item.get("content") if "content" in item else item.get("text")


def tool_call_payload(item: dict[str, Any]) -> tuple[Any, bool]:
    for key in ("arguments", "input", "action", "parameters"):
        if key in item and item[key] is not None:
            return item[key], True
    return None, False


def tool_result_payload(item: dict[str, Any]) -> Any:
    for key in ("output", "result", "content"):
        if key in item:
            return item[key]
    return None


def response_summary(parsed: dict[str, Any]) -> dict[str, Any]:
    output = parsed["output"]
    indexes = parsed.get("output_indexes") or list(range(len(output)))
    counts = Counter(item_type(item) for item in output)
    calls: list[tuple[int, dict[str, Any]]] = []
    messages: list[dict[str, Any]] = []
    final_messages: list[dict[str, Any]] = []
    for ordinal, item in enumerate(output):
        if not isinstance(item, dict):
            continue
        kind = item_type(item)
        if is_tool_call_type(kind):
            calls.append((int(indexes[ordinal]), item))
        elif kind in {"message", "agent_message"} or item.get("role") == "assistant":
            messages.append(item)
            phase = nonempty_string(item.get("phase"))
            if phase is None or phase in {"final", "final_answer"}:
                final_messages.append(item)
    final_raw = b"".join(canonical_bytes(message_payload(item)) for item in final_messages)
    return {
        "item_counts": counts,
        "calls": calls,
        "messages": messages,
        "final_messages": final_messages,
        "final_message_bytes": len(final_raw),
        "final_message_sha256": hashlib.sha256(final_raw).hexdigest() if final_raw else None,
    }


def iter_raw_records(
    path: Path,
    shard_id: int,
    *,
    model_exact: str | None = None,
) -> Iterator[RawRecord]:
    conn = read_only_connection(path)
    where = "WHERE i.model=?" if model_exact is not None else ""
    parameters: tuple[Any, ...] = (model_exact,) if model_exact is not None else ()
    try:
        cursor = conn.execute(
            f"""
            SELECT i.record_id,i.capture_id,i.event_ts,i.received_at,i.started_at,i.finished_at,
                   i.model,i.api_key_fingerprint,i.response_status,i.raw_bytes,i.stored_bytes,
                   i.raw_sha256,c.chunk_index,c.codec,c.raw_bytes,c.stored_bytes,c.payload
              FROM interactions i
              JOIN interaction_chunks c ON c.record_id=i.record_id
              {where}
             ORDER BY i.event_ts,i.record_id,c.chunk_index
            """,
            parameters,
        )
        current: tuple[Any, ...] | None = None
        raw = bytearray()
        expected_chunk = 0
        actual_stored = 0
        for row in cursor:
            metadata = tuple(row[:12])
            if current is not None and metadata[0] != current[0]:
                yield _finish_raw_record(shard_id, current, raw, actual_stored)
                raw = bytearray()
                expected_chunk = 0
                actual_stored = 0
            if current is None or metadata[0] != current[0]:
                current = metadata
            elif metadata != current:
                raise RuntimeError(f"interaction metadata changed between chunks in {path}: record {metadata[0]}")
            chunk_index = int(row[12])
            codec = str(row[13])
            chunk_raw_bytes = int(row[14])
            chunk_stored_bytes = int(row[15])
            payload = bytes(row[16])
            if chunk_index != expected_chunk:
                raise RuntimeError(f"invalid chunk sequence or codec in {path}: record {metadata[0]}")
            if len(payload) != chunk_stored_bytes:
                raise RuntimeError(f"compressed chunk length mismatch in {path}: record {metadata[0]}")
            try:
                decoded = decompress_chunk(
                    payload,
                    codec,
                    expected_raw_bytes=chunk_raw_bytes,
                )
            except CompressionError as exc:
                raise RuntimeError(
                    f"invalid compressed payload in {path}: record {metadata[0]}"
                ) from exc
            if len(decoded) != chunk_raw_bytes:
                raise RuntimeError(f"raw chunk length mismatch in {path}: record {metadata[0]}")
            raw.extend(decoded)
            actual_stored += len(payload)
            expected_chunk += 1
        if current is not None:
            yield _finish_raw_record(shard_id, current, raw, actual_stored)
    finally:
        conn.close()


def _finish_raw_record(
    shard_id: int,
    metadata: tuple[Any, ...],
    raw: bytearray,
    actual_stored: int,
) -> RawRecord:
    (
        record_id,
        capture_id,
        event_ts,
        received_at,
        started_at,
        finished_at,
        model,
        api_key_fingerprint,
        response_status,
        expected_raw,
        expected_stored,
        expected_sha256,
    ) = metadata
    raw_bytes = bytes(raw)
    if len(raw_bytes) != int(expected_raw):
        raise RuntimeError(f"raw record length mismatch: {capture_id}")
    if actual_stored != int(expected_stored):
        raise RuntimeError(f"stored record length mismatch: {capture_id}")
    actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if actual_sha256 != str(expected_sha256):
        raise RuntimeError(f"raw record hash mismatch: {capture_id}")
    try:
        status = int(response_status) if response_status is not None else None
    except (TypeError, ValueError):
        status = None
    return RawRecord(
        shard_id=shard_id,
        record_id=int(record_id),
        capture_id=str(capture_id),
        event_ts=nonempty_string(event_ts),
        received_at=nonempty_string(received_at),
        started_at=nonempty_string(started_at),
        finished_at=nonempty_string(finished_at),
        model=nonempty_string(model),
        api_key_fingerprint=nonempty_string(api_key_fingerprint),
        response_status=status,
        raw_bytes=len(raw_bytes),
        stored_bytes=actual_stored,
        raw_sha256=actual_sha256,
        raw=raw_bytes,
    )


def record_and_context(raw_record: RawRecord) -> tuple[dict[str, Any], dict[str, Any], str, str | None]:
    try:
        value = json_loads(raw_record.raw)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"invalid JSON payload: {raw_record.capture_id}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"raw payload is not an object: {raw_record.capture_id}")
    if value.get("captureId") != raw_record.capture_id:
        raise RuntimeError(f"capture identity mismatch: {raw_record.capture_id}")
    context = request_context(body_value(value.get("requestBody")))
    captured_context = as_dict(value.get("traceContext"))
    for field in (
        "session_id",
        "thread_id",
        "root_session_id",
        "parent_session_id",
        "goal_id",
        "turn_id",
        "agent_id",
        "branch_id",
        "previous_response_id",
    ):
        if context.get(field) is None:
            context[field] = nonempty_string(captured_context.get(field))
    context["session_identity"] = context.get("session_id") or context.get("thread_id")
    source_namespace = nonempty_string(value.get("sourceNamespace")) or raw_record.api_key_fingerprint or "default"
    context["source_namespace"] = source_namespace
    session_identity = context["session_identity"]
    if session_identity is not None:
        traj_id = f"session-{digest_parts(source_namespace, session_identity)}"
    else:
        # The prefix is an explicit quality flag, not a fabricated thread ID.
        traj_id = f"orphan-{digest_parts(raw_record.capture_id)}"
    turn_id = context["turn_id"]
    turn_key = digest_parts(traj_id, turn_id) if turn_id is not None else None
    return value, context, traj_id, turn_key


def selected_complete_threads(inputs: Sequence[Path], model_exact: str) -> set[str]:
    selected: set[str] = set()
    for shard_id, path in enumerate(inputs, start=1):
        for raw_record in iter_raw_records(path, shard_id, model_exact=model_exact):
            _record, _context, traj_id, _turn_key = record_and_context(raw_record)
            selected.add(traj_id)
    return selected


def validate_raw_shard(path: Path) -> None:
    conn = read_only_connection(path)
    try:
        tables = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        missing_tables = {"interactions", "interaction_chunks"} - tables
        if missing_tables:
            raise RuntimeError(f"raw SQLite is missing tables {sorted(missing_tables)}: {path}")
        missing_chunks = int(
            conn.execute(
                "SELECT count(*) FROM interactions i WHERE NOT EXISTS "
                "(SELECT 1 FROM interaction_chunks c WHERE c.record_id=i.record_id)"
            ).fetchone()[0]
        )
        orphan_chunks = int(
            conn.execute(
                "SELECT count(*) FROM interaction_chunks c WHERE NOT EXISTS "
                "(SELECT 1 FROM interactions i WHERE i.record_id=c.record_id)"
            ).fetchone()[0]
        )
        if missing_chunks or orphan_chunks:
            raise RuntimeError(
                f"raw SQLite chunk coverage failed for {path}: "
                f"missing={missing_chunks}, orphan={orphan_chunks}"
            )
        if "validation_results" in tables:
            failures = int(
                conn.execute("SELECT count(*) FROM validation_results WHERE status='fail'").fetchone()[0]
            )
            if failures:
                raise RuntimeError(f"raw SQLite reports {failures} failed validation rows: {path}")
    finally:
        conn.close()


def _insert_tool_result(
    conn: sqlite3.Connection,
    *,
    call_key: str,
    traj_id: str,
    turn_key: str | None,
    step_id: str,
    raw_record: RawRecord,
    result_type: str,
    call_id_present: bool,
    result_status: str | None,
    result_error: bool,
    result_bytes: int,
    result_sha256: str | None,
    result_json: str,
) -> bool:
    existing = conn.execute(
        "SELECT result_type,result_status,result_error,result_bytes,result_sha256,result_json "
        "FROM tool_results WHERE call_key=?",
        (call_key,),
    ).fetchone()
    expected = (
        result_type,
        result_status,
        int(result_error),
        result_bytes,
        result_sha256,
        result_json,
    )
    if existing is not None:
        if tuple(existing) != expected:
            raise RuntimeError(f"tool result changed for call key {call_key}")
        return False
    conn.execute(
        "INSERT INTO tool_results("
        "call_key,traj_id,turn_key,first_seen_step_id,shard_id,record_id,result_type,"
        "call_id_present,result_status,result_error,result_bytes,result_sha256,result_json,matched_call"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
        (
            call_key,
            traj_id,
            turn_key,
            step_id,
            raw_record.shard_id,
            raw_record.record_id,
            result_type,
            int(call_id_present),
            result_status,
            int(result_error),
            result_bytes,
            result_sha256,
            result_json,
        ),
    )
    return True


def _insert_tool_call(
    conn: sqlite3.Connection,
    *,
    call_key: str,
    traj_id: str,
    turn_key: str | None,
    step_id: str,
    raw_record: RawRecord,
    output_index: int,
    call_type: str,
    tool_name: str | None,
    call_id_present: bool,
    call_status: str | None,
    argument_bytes: int,
    argument_sha256: str | None,
    argument_json: str,
    arguments_complete: bool,
) -> None:
    existing = conn.execute(
        "SELECT call_type,tool_name,call_status,argument_bytes,argument_sha256,argument_json,arguments_complete "
        "FROM tool_calls WHERE call_key=?",
        (call_key,),
    ).fetchone()
    expected = (
        call_type,
        tool_name,
        call_status,
        argument_bytes,
        argument_sha256,
        argument_json,
        int(arguments_complete),
    )
    if existing is not None:
        if tuple(existing) != expected:
            raise RuntimeError(f"tool call changed for call key {call_key}")
        return
    conn.execute(
        "INSERT INTO tool_calls("
        "call_key,traj_id,turn_key,source_step_id,shard_id,record_id,output_index,"
        "call_type,tool_name,call_id_present,call_status,argument_bytes,argument_sha256,"
        "argument_json,arguments_complete"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            call_key,
            traj_id,
            turn_key,
            step_id,
            raw_record.shard_id,
            raw_record.record_id,
            output_index,
            call_type,
            tool_name,
            int(call_id_present),
            call_status,
            argument_bytes,
            argument_sha256,
            argument_json,
            int(arguments_complete),
        ),
    )


def _insert_tool_definition(
    conn: sqlite3.Connection,
    *,
    traj_id: str,
    step_id: str,
    definition: dict[str, Any],
) -> None:
    definition_key = digest_parts(traj_id, definition["name"], definition["sha256"])
    existing = conn.execute(
        "SELECT tool_name,tool_type,schema_version,description_present,parameters_present,"
        "definition_bytes,definition_sha256,schema_json FROM tool_definitions WHERE definition_key=?",
        (definition_key,),
    ).fetchone()
    expected = (
        definition["name"],
        definition["type"],
        definition["schema_version"],
        definition["description_present"],
        definition["parameters_present"],
        definition["bytes"],
        definition["sha256"],
        definition["schema_json"],
    )
    if existing is not None:
        if tuple(existing) != expected:
            raise RuntimeError(f"tool definition changed for key {definition_key}")
        return
    conn.execute(
        "INSERT INTO tool_definitions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (definition_key, traj_id, *expected, step_id),
    )


def _insert_session_relation(
    conn: sqlite3.Connection,
    *,
    source_namespace: str,
    child_traj_id: str,
    relation_type: str,
    relation_identity: str | None,
    step_id: str,
) -> None:
    if relation_identity is None:
        return
    parent_traj_id = f"session-{digest_parts(source_namespace, relation_identity)}"
    if parent_traj_id == child_traj_id:
        return
    conn.execute(
        "INSERT OR IGNORE INTO session_relations("
        "parent_traj_id,child_traj_id,relation_type,relation_identity,observed_step_id"
        ") VALUES(?,?,?,?,?)",
        (parent_traj_id, child_traj_id, relation_type, relation_identity, step_id),
    )


def process_record(
    conn: sqlite3.Connection,
    raw_record: RawRecord,
    *,
    value: dict[str, Any],
    context: dict[str, Any],
    traj_id: str,
    turn_key: str | None,
    turn_index: int | None,
    step_index: int,
    step_index_in_turn: int | None,
) -> None:
    parsed_response = parse_response_body(body_value(value.get("responseBody")))
    response = as_dict(parsed_response["response"])
    output = response_summary(parsed_response)
    usage = usage_from_response(response)
    terminal_type = str(parsed_response["terminal_type"])
    step_id = raw_record.capture_id

    lifecycle_events = value.get("observedLifecycleEvents")
    if isinstance(lifecycle_events, list):
        for event_index, raw_event_type in enumerate(lifecycle_events):
            event_type = nonempty_string(raw_event_type)
            if event_type is None:
                continue
            conn.execute(
                "INSERT INTO lifecycle_events VALUES(?,?,?,?,?,?)",
                (
                    digest_parts(step_id, str(event_index), event_type),
                    traj_id,
                    step_id,
                    event_index,
                    event_type,
                    "capture_envelope_observation",
                ),
            )

    _insert_session_relation(
        conn,
        source_namespace=context["source_namespace"],
        child_traj_id=traj_id,
        relation_type="root_session",
        relation_identity=context["root_session_id"],
        step_id=step_id,
    )
    _insert_session_relation(
        conn,
        source_namespace=context["source_namespace"],
        child_traj_id=traj_id,
        relation_type="parent_session",
        relation_identity=context["parent_session_id"],
        step_id=step_id,
    )

    for definition in context["tool_definitions"]:
        _insert_tool_definition(
            conn,
            traj_id=traj_id,
            step_id=step_id,
            definition=definition,
        )

    history_results = 0
    new_results = 0
    for item in context["items"]:
        if not isinstance(item, dict):
            continue
        kind = item_type(item)
        if not is_tool_result_type(kind):
            continue
        history_results += 1
        call_id = nonempty_string(item.get("call_id") or item.get("tool_call_id") or item.get("id"))
        identity = call_id or f"missing-result:{step_id}:{history_results}"
        call_key = digest_parts(traj_id, identity)
        result_payload = tool_result_payload(item)
        result_bytes, result_sha256 = value_fingerprint(result_payload)
        new_results += int(
            _insert_tool_result(
                conn,
                call_key=call_key,
                traj_id=traj_id,
                turn_key=turn_key,
                step_id=step_id,
                raw_record=raw_record,
                result_type=kind,
                call_id_present=call_id is not None,
                result_status=nonempty_string(item.get("status")),
                result_error=bool(item.get("is_error") or item.get("isError")),
                result_bytes=result_bytes,
                result_sha256=result_sha256,
                result_json=canonical_text(result_payload),
            )
        )

    for output_index, item in output["calls"]:
        kind = item_type(item)
        call_id = nonempty_string(item.get("call_id") or item.get("tool_call_id") or item.get("id"))
        identity = call_id or f"missing-call:{step_id}:{output_index}"
        call_key = digest_parts(traj_id, identity)
        argument, complete = tool_call_payload(item)
        argument_bytes, argument_sha256 = value_fingerprint(argument)
        _insert_tool_call(
            conn,
            call_key=call_key,
            traj_id=traj_id,
            turn_key=turn_key,
            step_id=step_id,
            raw_record=raw_record,
            output_index=output_index,
            call_type=kind,
            tool_name=nonempty_string(item.get("name") or item.get("tool_name")),
            call_id_present=call_id is not None,
            call_status=nonempty_string(item.get("status")),
            argument_bytes=argument_bytes,
            argument_sha256=argument_sha256,
            argument_json=canonical_text(argument),
            arguments_complete=complete,
        )

    for kind, count in context["item_counts"].items():
        conn.execute(
            "INSERT INTO step_item_counts VALUES(?,?,?,?)",
            (step_id, "request_history", kind, count),
        )
    for kind, count in output["item_counts"].items():
        conn.execute(
            "INSERT INTO step_item_counts VALUES(?,?,?,?)",
            (step_id, "response_output", kind, count),
        )

    step_values = (
            step_id,
            raw_record.shard_id,
            raw_record.record_id,
            raw_record.raw_bytes,
            raw_record.stored_bytes,
            raw_record.raw_sha256,
            traj_id,
            turn_key,
            turn_index,
            step_index,
            step_index_in_turn,
            raw_record.event_ts,
            raw_record.received_at,
            raw_record.started_at,
            raw_record.finished_at,
            raw_record.model,
            raw_record.response_status,
            nonempty_string(response.get("status")),
            terminal_type,
            int(terminal_type != "missing"),
            int(terminal_type == "response.completed"),
            1,
            1,
            int(parsed_response["parse_errors"]),
            int(bool(value.get("requestTruncated"))),
            int(bool(value.get("responseTruncated"))),
            int(bool(value.get("captureError"))),
            context["source_namespace"],
            nonempty_string(response.get("id")),
            context["previous_response_id"],
            context["session_id"],
            context["thread_id"],
            context["root_session_id"],
            context["parent_session_id"],
            context["goal_id"],
            context["agent_id"],
            context["branch_id"],
            int(context["session_identity"] is not None),
            int(context["turn_id"] is not None),
            int(context["subagent_present"]),
            len(context["items"]),
            int(context["prior_history_items"]),
            int(context["compaction_items"]),
            len(parsed_response["output"]),
            len(output["calls"]),
            len(output["messages"]),
            int(bool(output["final_messages"])),
            int(output["final_message_bytes"]),
            output["final_message_sha256"],
            history_results,
            new_results,
            int(bool(value.get("stream"))),
        )
    conn.execute(
        f"INSERT INTO steps VALUES({','.join('?' for _ in step_values)})",
        step_values,
    )
    conn.execute(
        "INSERT INTO step_usage VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            step_id,
            usage["present"],
            usage["input_tokens"],
            usage["cached_input_tokens"],
            usage["cache_write_tokens"],
            usage["uncached_input_tokens"],
            usage["output_tokens"],
            usage["reasoning_tokens"],
            usage["total_tokens"],
            usage["present"],
            1,
            "native_terminal_response",
        ),
    )


def aggregate_catalog(conn: sqlite3.Connection, projection_mode: str) -> None:
    conn.execute(
        "UPDATE tool_calls SET result_present=EXISTS(SELECT 1 FROM tool_results r WHERE r.call_key=tool_calls.call_key)"
    )
    conn.execute(
        "UPDATE tool_results SET matched_call=EXISTS(SELECT 1 FROM tool_calls c WHERE c.call_key=tool_results.call_key)"
    )
    conn.execute(
        """
        UPDATE tool_calls SET definition_present=EXISTS(
          SELECT 1
            FROM tool_definitions d
            JOIN steps definition_step ON definition_step.step_id=d.first_seen_step_id
            JOIN steps call_step ON call_step.step_id=tool_calls.source_step_id
           WHERE d.traj_id=tool_calls.traj_id
             AND d.tool_name=tool_calls.tool_name
             AND definition_step.step_index<=call_step.step_index
        )
        """
    )
    conn.execute(
        """
        INSERT INTO trajectory_edges(parent_step_id,child_step_id,edge_type,edge_identity)
        SELECT parent.step_id,child.step_id,'previous_response',child.previous_response_id
          FROM steps child
          JOIN steps parent
            ON parent.traj_id=child.traj_id
           AND parent.response_id=child.previous_response_id
         WHERE child.previous_response_id IS NOT NULL
        """
    )
    if projection_mode == "exact-model-projection":
        conn.execute(
            "UPDATE tool_calls SET linkage_status=CASE WHEN result_present=1 "
            "THEN 'executed' ELSE 'capture_gap' END"
        )
    else:
        conn.execute(
            """
            UPDATE tool_calls SET linkage_status=CASE
              WHEN result_present=1 THEN 'executed'
              WHEN EXISTS(
                SELECT 1 FROM steps source
                JOIN steps child
                  ON child.traj_id=source.traj_id
                 AND child.previous_response_id=source.response_id
                WHERE source.step_id=tool_calls.source_step_id
                GROUP BY source.step_id HAVING count(*)>1
              ) THEN 'abandoned_concurrent'
              WHEN EXISTS(
                SELECT 1 FROM steps source
                JOIN steps sibling
                  ON sibling.traj_id=source.traj_id
                 AND sibling.previous_response_id=source.previous_response_id
                 AND sibling.step_index>source.step_index
                WHERE source.step_id=tool_calls.source_step_id
                  AND source.previous_response_id IS NOT NULL
              ) THEN 'abandoned_retry'
              WHEN (SELECT source.step_index=(SELECT max(last_step.step_index)
                                               FROM steps last_step
                                              WHERE last_step.traj_id=source.traj_id)
                      FROM steps source
                     WHERE source.step_id=tool_calls.source_step_id)
              THEN 'open_tail'
              ELSE 'capture_gap'
            END
            """
        )
    conn.execute(
        "UPDATE session_relations SET parent_present=EXISTS("
        "SELECT 1 FROM steps parent WHERE parent.traj_id=session_relations.parent_traj_id)"
    )
    conn.execute(
        """
        INSERT INTO turns(
          turn_key,traj_id,turn_index,first_event_utc,last_event_utc,steps,
          terminal_completed_steps,terminal_failed_steps,usage_present_steps,
          compaction_steps,subagent_steps,final_message_steps,tool_calls,tool_results,
          input_tokens,cached_input_tokens,cache_write_tokens,uncached_input_tokens,
          output_tokens,reasoning_tokens,total_tokens
        )
        SELECT s.turn_key,s.traj_id,min(s.turn_index),min(s.event_ts),max(s.event_ts),count(*),
               sum(s.terminal_completed),sum(s.terminal_event_type='response.failed'),
               sum(u.usage_present),sum(s.compaction_items>0),sum(s.subagent_present),
               sum(s.final_message_present),0,0,sum(u.input_tokens),sum(u.cached_input_tokens),
               sum(u.cache_write_tokens),sum(u.uncached_input_tokens),sum(u.output_tokens),
               sum(u.reasoning_tokens),sum(u.total_tokens)
          FROM steps s JOIN step_usage u ON u.step_id=s.step_id
         WHERE s.turn_key IS NOT NULL
         GROUP BY s.turn_key,s.traj_id
        """
    )
    conn.execute(
        "UPDATE turns SET tool_calls=(SELECT count(*) FROM tool_calls c WHERE c.turn_key=turns.turn_key),"
        "tool_results=(SELECT count(*) FROM tool_results r WHERE r.turn_key=turns.turn_key)"
    )
    gap_status = (
        "not_evaluable_from_exact_model_projection"
        if projection_mode == "exact-model-projection"
        else "complete_thread"
    )
    conn.execute(
        """
        INSERT INTO trajectories(
          traj_id,source_namespace,shard_id,turns,steps,first_event_utc,last_event_utc,first_step_id,last_step_id,
          raw_bytes,stored_bytes,parse_ok_steps,truncated_steps,thread_id_present_steps,
          turn_id_present_steps,terminal_present_steps,terminal_completed_steps,terminal_failed_steps,
          usage_present_steps,compaction_steps,subagent_steps,final_message_steps,tool_calls,
          tool_results,matched_tool_calls,orphan_tool_results,input_tokens,cached_input_tokens,
          cache_write_tokens,uncached_input_tokens,output_tokens,reasoning_tokens,total_tokens,
          left_censored,right_censored,closed,projection_mode,projection_gap_status,reward,reward_source
        )
        SELECT s.traj_id,min(s.source_namespace),min(s.shard_id),count(DISTINCT s.turn_key),count(*),min(s.event_ts),max(s.event_ts),
               '', '',sum(s.raw_bytes),sum(s.stored_bytes),sum(s.payload_parse_ok),
               sum(s.request_truncated OR s.response_truncated),sum(s.thread_id_present),
               sum(s.turn_id_present),sum(s.terminal_present),sum(s.terminal_completed),
               sum(s.terminal_event_type='response.failed'),sum(u.usage_present),
               sum(s.compaction_items>0),sum(s.subagent_present),sum(s.final_message_present),
               0,0,0,0,sum(u.input_tokens),sum(u.cached_input_tokens),sum(u.cache_write_tokens),
               sum(u.uncached_input_tokens),sum(u.output_tokens),sum(u.reasoning_tokens),
               sum(u.total_tokens),0,0,0,?,?,NULL,NULL
          FROM steps s JOIN step_usage u ON u.step_id=s.step_id
         GROUP BY s.traj_id
        """,
        (projection_mode, gap_status),
    )
    conn.execute(
        """
        UPDATE trajectories SET
          first_step_id=(SELECT step_id FROM steps s WHERE s.traj_id=trajectories.traj_id ORDER BY step_index LIMIT 1),
          last_step_id=(SELECT step_id FROM steps s WHERE s.traj_id=trajectories.traj_id ORDER BY step_index DESC LIMIT 1),
          tool_calls=(SELECT count(*) FROM tool_calls c WHERE c.traj_id=trajectories.traj_id),
          tool_results=(SELECT count(*) FROM tool_results r WHERE r.traj_id=trajectories.traj_id),
          matched_tool_calls=(SELECT count(*) FROM tool_calls c WHERE c.traj_id=trajectories.traj_id AND c.result_present=1),
          orphan_tool_results=(SELECT count(*) FROM tool_results r WHERE r.traj_id=trajectories.traj_id AND r.matched_call=0)
        """
    )
    conn.execute(
        """
        UPDATE trajectories SET
          left_censored=(SELECT prior_history_items>0 FROM steps s WHERE s.step_id=trajectories.first_step_id),
          right_censored=NOT (SELECT terminal_present=1 AND (
                                      terminal_event_type IN (
                                        'response.failed','response.incomplete','response.cancelled'
                                      ) OR (
                                        terminal_event_type='response.completed'
                                        AND final_message_present=1 AND output_tool_calls=0
                                      )
                                    )
                                 FROM steps s WHERE s.step_id=trajectories.last_step_id)
        """
    )
    conn.execute("UPDATE trajectories SET closed=NOT right_censored")
    conn.execute(
        """
        INSERT INTO item_type_summary(direction,item_type,steps,items)
        SELECT direction,item_type,count(*),sum(item_count)
          FROM step_item_counts GROUP BY direction,item_type
        """
    )
    conn.execute(
        """
        UPDATE shards SET
          records=(SELECT count(*) FROM steps s WHERE s.shard_id=shards.shard_id),
          trajectories=(SELECT count(DISTINCT traj_id) FROM steps s WHERE s.shard_id=shards.shard_id),
          turns=(SELECT count(DISTINCT turn_key) FROM steps s WHERE s.shard_id=shards.shard_id),
          raw_bytes=coalesce((SELECT sum(raw_bytes) FROM steps s WHERE s.shard_id=shards.shard_id),0),
          stored_bytes=coalesce((SELECT sum(stored_bytes) FROM steps s WHERE s.shard_id=shards.shard_id),0),
          first_event_utc=(SELECT min(event_ts) FROM steps s WHERE s.shard_id=shards.shard_id),
          last_event_utc=(SELECT max(event_ts) FROM steps s WHERE s.shard_id=shards.shard_id),
          input_tokens=coalesce((SELECT sum(u.input_tokens) FROM step_usage u JOIN steps s ON s.step_id=u.step_id WHERE s.shard_id=shards.shard_id),0),
          cached_input_tokens=coalesce((SELECT sum(u.cached_input_tokens) FROM step_usage u JOIN steps s ON s.step_id=u.step_id WHERE s.shard_id=shards.shard_id),0),
          cache_write_tokens=coalesce((SELECT sum(u.cache_write_tokens) FROM step_usage u JOIN steps s ON s.step_id=u.step_id WHERE s.shard_id=shards.shard_id),0),
          uncached_input_tokens=coalesce((SELECT sum(u.uncached_input_tokens) FROM step_usage u JOIN steps s ON s.step_id=u.step_id WHERE s.shard_id=shards.shard_id),0),
          output_tokens=coalesce((SELECT sum(u.output_tokens) FROM step_usage u JOIN steps s ON s.step_id=u.step_id WHERE s.shard_id=shards.shard_id),0),
          reasoning_tokens=coalesce((SELECT sum(u.reasoning_tokens) FROM step_usage u JOIN steps s ON s.step_id=u.step_id WHERE s.shard_id=shards.shard_id),0),
          total_tokens=coalesce((SELECT sum(u.total_tokens) FROM step_usage u JOIN steps s ON s.step_id=u.step_id WHERE s.shard_id=shards.shard_id),0)
        """
    )


def quality_grade(score: float) -> str:
    if score >= 99.999:
        return "A_complete"
    if score >= 85:
        return "B_mostly_complete"
    if score >= 60:
        return "C_partial"
    return "D_fragment"


def calculate_quality(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT traj_id,steps,parse_ok_steps,truncated_steps,thread_id_present_steps,
               turn_id_present_steps,terminal_present_steps,usage_present_steps,
               tool_calls,tool_results,matched_tool_calls,
               left_censored,right_censored FROM trajectories
        """
    )
    for row in rows:
        (
            traj_id,
            steps,
            parse_ok,
            truncated,
            thread_present,
            turn_present,
            terminal_present,
            usage_present,
            calls,
            results,
            matched,
            left_censored,
            right_censored,
        ) = row
        steps = max(int(steps), 1)
        payload = 10 * int(parse_ok) / steps + 10 * (steps - int(truncated)) / steps
        identity = 10 * int(thread_present) / steps + 10 * int(turn_present) / steps
        # A captured failure/cancellation is a complete trace outcome. Task
        # success belongs in semantic reward, not session completeness.
        terminal = 20 * int(terminal_present) / steps
        usage = 5 * int(usage_present) / steps
        denominator = max(int(calls), int(results))
        linkage = 20.0 if denominator == 0 else 20 * int(matched) / denominator
        boundary = 5 * (not bool(left_censored)) + 10 * (not bool(right_censored))
        score = round(payload + identity + terminal + usage + linkage + boundary, 3)
        conn.execute(
            "INSERT INTO trajectory_quality VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                traj_id,
                QUALITY_POLICY_VERSION,
                score,
                quality_grade(score),
                round(payload, 3),
                round(identity, 3),
                round(terminal, 3),
                round(usage, 3),
                round(linkage, 3),
                round(boundary, 3),
                0,
                "observed session trace completeness only; not task correctness or semantic reward",
            ),
        )


def create_indexes(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE INDEX steps_traj_order_idx ON steps(traj_id,step_index);
        CREATE INDEX steps_turn_order_idx ON steps(turn_key,step_index_in_turn);
        CREATE INDEX steps_shard_record_idx ON steps(shard_id,record_id);
        CREATE INDEX steps_event_idx ON steps(event_ts,step_id);
        CREATE INDEX usage_present_idx ON step_usage(usage_present,step_id);
        CREATE INDEX item_counts_type_idx ON step_item_counts(direction,item_type,step_id);
        CREATE INDEX tool_calls_traj_idx ON tool_calls(traj_id,source_step_id);
        CREATE INDEX tool_calls_linkage_idx ON tool_calls(linkage_status,traj_id);
        CREATE INDEX tool_definitions_name_idx ON tool_definitions(traj_id,tool_name);
        CREATE INDEX tool_results_traj_idx ON tool_results(traj_id,first_seen_step_id);
        CREATE INDEX steps_response_id_idx ON steps(traj_id,response_id);
        CREATE INDEX steps_previous_response_idx ON steps(traj_id,previous_response_id);
        CREATE INDEX trajectory_edges_child_idx ON trajectory_edges(child_step_id,edge_type);
        CREATE INDEX session_relations_child_idx ON session_relations(child_traj_id,relation_type);
        CREATE INDEX lifecycle_events_type_idx ON lifecycle_events(event_type,traj_id,step_id);
        """
    )


def meta_value(value: Any) -> tuple[str, str]:
    if isinstance(value, bool):
        return ("true" if value else "false", "boolean")
    if isinstance(value, (int, float)):
        return (str(value), "number")
    if value is None:
        return ("null", "null")
    if isinstance(value, (dict, list, tuple)):
        return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")), "json")
    return (str(value), "string")


def put_meta(conn: sqlite3.Connection, key: str, value: Any) -> None:
    encoded, value_type = meta_value(value)
    conn.execute("INSERT OR REPLACE INTO dataset_meta VALUES(?,?,?)", (key, encoded, value_type))


def validation_row(
    conn: sqlite3.Connection,
    name: str,
    observed: Any,
    expected: Any | None = None,
    *,
    warning: bool = False,
    details: str | None = None,
) -> str:
    if expected is None:
        status = "warn" if warning else "pass"
    else:
        status = "pass" if observed == expected else ("warn" if warning else "fail")
    observed_text, _kind = meta_value(observed)
    expected_text = None if expected is None else meta_value(expected)[0]
    conn.execute(
        "INSERT INTO validation_results VALUES(?,?,?,?,?)",
        (name, status, observed_text, expected_text, details),
    )
    return status


def validate_catalog(
    conn: sqlite3.Connection,
    selected_records: int,
    *,
    projection_mode: str,
    model_exact: str | None,
) -> str:
    statuses = [
        validation_row(conn, "step_count", conn.execute("SELECT count(*) FROM steps").fetchone()[0], selected_records),
        validation_row(
            conn,
            "trajectory_shard_preservation",
            conn.execute(
                "SELECT count(*) FROM (SELECT traj_id FROM steps GROUP BY traj_id HAVING count(DISTINCT shard_id)>1)"
            ).fetchone()[0],
            0,
        ),
        validation_row(
            conn,
            "trajectory_source_namespace_consistency",
            conn.execute(
                "SELECT count(*) FROM (SELECT traj_id FROM steps GROUP BY traj_id "
                "HAVING count(DISTINCT source_namespace)>1)"
            ).fetchone()[0],
            0,
        ),
        validation_row(
            conn,
            "duplicate_capture_ids",
            conn.execute(
                "SELECT count(*) FROM (SELECT step_id FROM steps GROUP BY step_id HAVING count(*)>1)"
            ).fetchone()[0],
            0,
        ),
        validation_row(
            conn,
            "sse_parse_errors",
            conn.execute("SELECT coalesce(sum(sse_parse_errors),0) FROM steps").fetchone()[0],
            0,
        ),
        validation_row(
            conn,
            "semantic_rewards_are_null",
            conn.execute("SELECT count(*) FROM trajectories WHERE reward IS NULL AND reward_source IS NULL").fetchone()[0],
            conn.execute("SELECT count(*) FROM trajectories").fetchone()[0],
        ),
        validation_row(
            conn,
            "session_quality_rows",
            conn.execute("SELECT count(*) FROM session_quality").fetchone()[0],
            conn.execute("SELECT count(*) FROM trajectories").fetchone()[0],
        ),
        validation_row(
            conn,
            "session_completeness_score_bounds",
            conn.execute(
                "SELECT count(*) FROM session_quality "
                "WHERE session_completeness_score < 0 OR session_completeness_score > 100"
            ).fetchone()[0],
            0,
        ),
        validation_row(
            conn,
            "trajectory_step_aggregate",
            conn.execute("SELECT coalesce(sum(steps),0) FROM trajectories").fetchone()[0],
            selected_records,
        ),
        validation_row(
            conn,
            "shard_record_aggregate",
            conn.execute("SELECT coalesce(sum(records),0) FROM shards").fetchone()[0],
            selected_records,
        ),
        validation_row(
            conn,
            "tool_linkage_status_aggregate",
            conn.execute("SELECT count(*) FROM tool_calls WHERE linkage_status IS NOT NULL").fetchone()[0],
            conn.execute("SELECT count(*) FROM tool_calls").fetchone()[0],
        ),
        validation_row(
            conn,
            "trajectory_edges_cross_session",
            conn.execute(
                "SELECT count(*) FROM trajectory_edges e "
                "JOIN steps p ON p.step_id=e.parent_step_id "
                "JOIN steps c ON c.step_id=e.child_step_id WHERE p.traj_id<>c.traj_id"
            ).fetchone()[0],
            0,
        ),
        validation_row(
            conn,
            "lifecycle_events_step_coverage",
            conn.execute(
                "SELECT count(*) FROM lifecycle_events e WHERE NOT EXISTS("
                "SELECT 1 FROM steps s WHERE s.step_id=e.step_id AND s.traj_id=e.traj_id)"
            ).fetchone()[0],
            0,
        ),
    ]
    if projection_mode == "exact-model-projection":
        statuses.append(
            validation_row(
                conn,
                "exact_model_projection",
                conn.execute("SELECT count(*) FROM steps WHERE model IS NOT ?", (model_exact,)).fetchone()[0],
                0,
            )
        )
    usage_columns = (
        "input_tokens",
        "cached_input_tokens",
        "cache_write_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
    )
    step_totals = conn.execute(
        f"SELECT {','.join(f'coalesce(sum({column}),0)' for column in usage_columns)} FROM step_usage"
    ).fetchone()
    trajectory_totals = conn.execute(
        f"SELECT {','.join(f'coalesce(sum({column}),0)' for column in usage_columns)} FROM trajectories"
    ).fetchone()
    shard_totals = conn.execute(
        f"SELECT {','.join(f'coalesce(sum({column}),0)' for column in usage_columns)} FROM shards"
    ).fetchone()
    for index, column in enumerate(usage_columns):
        statuses.append(
            validation_row(
                conn,
                f"trajectory_usage_{column}",
                int(trajectory_totals[index]),
                int(step_totals[index]),
            )
        )
        statuses.append(
            validation_row(
                conn,
                f"shard_usage_{column}",
                int(shard_totals[index]),
                int(step_totals[index]),
            )
        )
    missing_call_ids = conn.execute("SELECT count(*) FROM tool_calls WHERE call_id_present=0").fetchone()[0]
    statuses.append(
        validation_row(
            conn,
            "tool_calls_missing_native_id",
            missing_call_ids,
            0,
            warning=True,
            details="synthetic per-step call keys are retained but lower identity quality",
        )
    )
    statuses.append(
        validation_row(
            conn,
            "tool_calls_without_prior_definition",
            conn.execute("SELECT count(*) FROM tool_calls WHERE definition_present=0").fetchone()[0],
            0,
            warning=True,
            details="the source request did not contain a matching tool schema before the call",
        )
    )
    statuses.append(
        validation_row(
            conn,
            "tool_definitions_without_full_schema",
            conn.execute(
                "SELECT count(*) FROM tool_definitions WHERE schema_json IS NULL OR schema_json=''"
            ).fetchone()[0],
            0,
        )
    )
    statuses.append(
        validation_row(
            conn,
            "tool_calls_without_argument_evidence",
            conn.execute(
                "SELECT count(*) FROM tool_calls WHERE arguments_complete=1 "
                "AND (argument_json IS NULL OR argument_json='')"
            ).fetchone()[0],
            0,
            warning=True,
        )
    )
    statuses.append(
        validation_row(
            conn,
            "tool_results_without_result_evidence",
            conn.execute(
                "SELECT count(*) FROM tool_results WHERE result_bytes>0 "
                "AND (result_json IS NULL OR result_json='')"
            ).fetchone()[0],
            0,
            warning=True,
        )
    )
    statuses.append(
        validation_row(
            conn,
            "duplicate_response_ids",
            conn.execute(
                "SELECT count(*) FROM (SELECT traj_id,response_id FROM steps "
                "WHERE response_id IS NOT NULL GROUP BY traj_id,response_id HAVING count(*)>1)"
            ).fetchone()[0],
            0,
            warning=True,
            details="duplicate response IDs make previous-response DAG linkage ambiguous",
        )
    )
    statuses.append(
        validation_row(
            conn,
            "unresolved_previous_response_ids",
            conn.execute(
                "SELECT count(*) FROM steps child WHERE child.previous_response_id IS NOT NULL "
                "AND NOT EXISTS(SELECT 1 FROM steps parent WHERE parent.traj_id=child.traj_id "
                "AND parent.response_id=child.previous_response_id)"
            ).fetchone()[0],
            0,
            warning=True,
            details="the parent response may be outside the selected projection or capture boundary",
        )
    )
    statuses.append(
        validation_row(
            conn,
            "tool_calls_incomplete_arguments",
            conn.execute("SELECT count(*) FROM tool_calls WHERE arguments_complete=0").fetchone()[0],
            0,
            warning=True,
        )
    )
    statuses.append(
        validation_row(
            conn,
            "tool_calls_without_result_in_projection",
            conn.execute("SELECT count(*) FROM tool_calls WHERE result_present=0").fetchone()[0],
            details="boundary/quality count; not a semantic failure",
        )
    )
    statuses.append(
        validation_row(
            conn,
            "orphan_tool_results_in_projection",
            conn.execute("SELECT count(*) FROM tool_results WHERE matched_call=0").fetchone()[0],
            details="the call may predate the selected projection",
        )
    )
    conn.commit()
    conn.execute("PRAGMA foreign_keys=ON")
    statuses.append(
        validation_row(
            conn,
            "foreign_key_check_rows",
            len(conn.execute("PRAGMA foreign_key_check").fetchall()),
            0,
        )
    )
    integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
    statuses.append(validation_row(conn, "sqlite_integrity_check", integrity, "ok"))
    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    return "pass"


def build_trajectory_catalog(
    inputs: Sequence[Path],
    output: Path,
    *,
    model_exact: str | None = None,
    projection_mode: str = "exact-model-projection",
    replace: bool = False,
) -> dict[str, Any]:
    if projection_mode not in {"exact-model-projection", "complete-thread"}:
        raise ValueError("projection_mode must be exact-model-projection or complete-thread")
    if not model_exact:
        raise ValueError("model_exact is required")
    paths = [Path(path).resolve() for path in inputs]
    if not paths:
        raise ValueError("at least one raw SQLite input is required")
    if len({path.name for path in paths}) != len(paths):
        raise ValueError("raw SQLite input file names must be unique")
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(path)
        validate_raw_shard(path)
    output = Path(output).resolve()
    if output in paths:
        raise ValueError("trajectory catalog output cannot overwrite a raw SQLite input")
    if output.exists() and not replace:
        raise FileExistsError(f"output exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    staging.unlink(missing_ok=True)

    selected = (
        selected_complete_threads(paths, str(model_exact))
        if projection_mode == "complete-thread" and model_exact
        else None
    )
    conn = sqlite3.connect(staging)
    os.chmod(staging, 0o600)
    published = False
    selected_records = 0
    traj_steps: defaultdict[str, int] = defaultdict(int)
    turn_steps: defaultdict[str, int] = defaultdict(int)
    turn_order: defaultdict[str, dict[str, int]] = defaultdict(dict)
    traj_shards: dict[str, int] = {}
    try:
        conn.execute("PRAGMA page_size=4096")
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.executescript(CATALOG_SCHEMA)
        file_rows = []
        for shard_id, path in enumerate(paths, start=1):
            stat = path.stat()
            file_rows.append(
                {
                    "shard_id": shard_id,
                    "file": path.name,
                    "bytes": stat.st_size,
                    "inode": stat.st_ino,
                    "mtime_ns": stat.st_mtime_ns,
                    "sha256": None,
                }
            )
            conn.execute(
                "INSERT INTO shards VALUES(?,?,?,?,0,0,0,0,0,NULL,NULL,0,0,0,0,0,0,0,?,?)",
                (
                    shard_id,
                    path.name,
                    stat.st_size,
                    "pending",
                    "interactions + interaction_chunks",
                    "codec-tagged-independent-chunks",
                ),
            )

        for shard_id, path in enumerate(paths, start=1):
            filter_model = model_exact if projection_mode == "exact-model-projection" else None
            for raw_record in iter_raw_records(path, shard_id, model_exact=filter_model):
                value, context, traj_id, turn_key = record_and_context(raw_record)
                if selected is not None and traj_id not in selected:
                    continue
                prior_shard = traj_shards.setdefault(traj_id, shard_id)
                if prior_shard != shard_id:
                    raise RuntimeError(
                        f"trajectory {traj_id} spans raw shards {prior_shard} and {shard_id}; repartition before delivery"
                    )
                if turn_key is not None and turn_key not in turn_order[traj_id]:
                    turn_order[traj_id][turn_key] = len(turn_order[traj_id]) + 1
                traj_steps[traj_id] += 1
                if turn_key is not None:
                    turn_steps[turn_key] += 1
                process_record(
                    conn,
                    raw_record,
                    value=value,
                    context=context,
                    traj_id=traj_id,
                    turn_key=turn_key,
                    turn_index=turn_order[traj_id].get(turn_key),
                    step_index=traj_steps[traj_id],
                    step_index_in_turn=turn_steps.get(turn_key),
                )
                selected_records += 1
                if selected_records % 500 == 0:
                    conn.commit()
        if selected_records == 0:
            raise RuntimeError("the projection selected zero records")

        for row in file_rows:
            path = paths[int(row["shard_id"]) - 1]
            before_hash = path.stat()
            if (
                before_hash.st_size != int(row["bytes"])
                or before_hash.st_ino != int(row["inode"])
                or before_hash.st_mtime_ns != int(row["mtime_ns"])
            ):
                raise RuntimeError(f"raw SQLite input changed during catalog build: {path}")
            checksum = _file_sha256(path)
            after_hash = path.stat()
            if (
                after_hash.st_size != before_hash.st_size
                or after_hash.st_ino != before_hash.st_ino
                or after_hash.st_mtime_ns != before_hash.st_mtime_ns
            ):
                raise RuntimeError(f"raw SQLite input changed while hashing: {path}")
            row["sha256"] = checksum
            conn.execute(
                "UPDATE shards SET sha256=? WHERE shard_id=?",
                (checksum, row["shard_id"]),
            )

        aggregate_catalog(conn, projection_mode)
        calculate_quality(conn)
        create_indexes(conn)
        put_meta(conn, "format", CATALOG_FORMAT)
        put_meta(conn, "schema_version", CATALOG_SCHEMA_VERSION)
        put_meta(conn, "created_at_utc", utc_now())
        put_meta(conn, "projection_mode", projection_mode)
        put_meta(conn, "model_exact", model_exact)
        put_meta(conn, "trajectory_id_definition", TRAJECTORY_DEFINITION)
        put_meta(conn, "session_id_definition", SESSION_DEFINITION)
        put_meta(conn, "turn_id_definition", TURN_DEFINITION)
        put_meta(conn, "source_namespace_definition", "explicit envelope sourceNamespace, then source fingerprint, then default")
        put_meta(conn, "response_dag_definition", "trajectory_edges links observed previous_response_id to an observed response_id in one session")
        put_meta(conn, "session_relation_definition", "root/parent session identifiers are namespaced and may reference a session outside the projection")
        put_meta(conn, "lifecycle_event_definition", "only event types directly observed in captured request or response payloads")
        put_meta(conn, "tool_linkage_statuses", ["executed", "abandoned_concurrent", "abandoned_retry", "open_tail", "capture_gap"])
        put_meta(
            conn,
            "tool_evidence_storage",
            "tool_definitions.schema_json, tool_calls.argument_json and tool_results.result_json "
            "store canonical observed payloads; hashes remain available for integrity checks",
        )
        put_meta(conn, "quality_policy_version", QUALITY_POLICY_VERSION)
        put_meta(conn, "semantic_reward_available", False)
        put_meta(conn, "reasoning_plaintext_claimed", False)
        put_meta(conn, "sensitive_unsanitized_raw_shards", True)
        put_meta(conn, "raw_payload_location", "join steps(shard_id,record_id) to shards(file_name), then interaction_chunks")
        put_meta(conn, "input_files", file_rows)
        event_range = conn.execute("SELECT min(event_ts),max(event_ts) FROM steps").fetchone()
        put_meta(conn, "actual_event_start_utc", event_range[0])
        put_meta(conn, "actual_event_end_utc", event_range[1])
        validation_status = validate_catalog(
            conn,
            selected_records,
            projection_mode=projection_mode,
            model_exact=model_exact,
        )
        put_meta(conn, "validation_status", validation_status)
        if validation_status == "fail":
            raise RuntimeError("trajectory catalog validation failed")
        for row in file_rows:
            path = paths[int(row["shard_id"]) - 1]
            stat = path.stat()
            if (
                stat.st_size != int(row["bytes"])
                or stat.st_ino != int(row["inode"])
                or stat.st_mtime_ns != int(row["mtime_ns"])
            ):
                raise RuntimeError(f"raw SQLite input changed before catalog publication: {path}")
        conn.execute("ANALYZE")
        conn.commit()
        conn.close()
        _fsync_file(staging)
        _publish_file(staging, output, replace=replace)
        _fsync_directory(output.parent)
        published = True
    finally:
        conn.close()
        if not published:
            staging.unlink(missing_ok=True)

    with sqlite3.connect(f"file:{output}?mode=ro", uri=True) as check:
        trajectories = int(check.execute("SELECT count(*) FROM trajectories").fetchone()[0])
        turns = int(check.execute("SELECT count(*) FROM turns").fetchone()[0])
        quality = check.execute(
            "SELECT round(avg(structural_score),3),min(structural_score),max(structural_score) FROM trajectory_quality"
        ).fetchone()
    return {
        "output": str(output),
        "output_bytes": output.stat().st_size,
        "sha256": _file_sha256(output),
        "records": selected_records,
        "trajectories": trajectories,
        "turns": turns,
        "projection_mode": projection_mode,
        "model_exact": model_exact,
        "validation_status": validation_status,
        "session_completeness_score_average": quality[0],
        "session_completeness_score_minimum": quality[1],
        "session_completeness_score_maximum": quality[2],
        "structural_score_average": quality[0],
        "structural_score_minimum": quality[1],
        "structural_score_maximum": quality[2],
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_file(staging: Path, output: Path, *, replace: bool) -> None:
    if replace:
        os.replace(staging, output)
        return
    os.link(staging, output)
    staging.unlink()
