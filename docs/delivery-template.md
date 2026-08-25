# Standard delivery template

## Directory

Deliver one immutable directory per dataset version:

```text
<dataset-id>/
  <model>-part-001.sqlite
  <model>-part-002.sqlite
  ...
  session-catalog.sqlite
  manifest.json
  SHA256SUMS
```

Raw parts target about 10 GiB. Never split one session across parts; a session
larger than the target is delivered as one explicitly oversized part. The
builder copies verified compressed BLOBs directly and does not decompress and
recompress unchanged payloads.

Build the directory atomically with:

```bash
trace-pipeline release \
  --input raw-001.sqlite --input raw-002.sqlite \
  --output target-model-YYYYMMDD-v1 \
  --model target-model-v1 --target-part-gib 10
```

## Manifest

`manifest.json` should contain:

```json
{
  "release_id": "target-model-YYYYMMDD-v1",
  "schema_version": "complete-session-release-v1",
  "selection": {"model": "target-model-v1", "mode": "complete-session"},
  "session_atomic": true,
  "session_split_count": 0,
  "actual_window": {"start": "...", "end": "..."},
  "models_present": ["target-model-v1", "helper-model-v1"],
  "sensitive_raw_data": true,
  "semantic_reward_available": false,
  "score_semantics": "observed session trace completeness; not task correctness",
  "session_quality": {
    "policy_version": "session-trace-completeness-v1",
    "average": 0,
    "minimum": 0,
    "maximum": 0,
    "grades": {},
    "incomplete_reasons": {}
  },
  "records": 0,
  "sessions": 0,
  "token_totals": {},
  "parts": [
    {"file": "target-model-v1-part-001.sqlite", "bytes": 0, "sha256": "..."}
  ],
  "catalog": {
    "file": "session-catalog.sqlite",
    "schema_version": "session-catalog-v3",
    "bytes": 0,
    "sha256": "..."
  },
  "validation_status": "pass"
}
```

`actual_window` must come from retained event timestamps. Do not extend it to
the requested end date when collection stopped earlier.

## Catalog minimum

The catalog contains no duplicate captures. It points to raw records by
`(shard_id, record_id)` and includes these normalized tables:

- `trajectories` (compatibility name for sessions), `turns`, `steps`;
- `step_usage`, including input/cache/output/reasoning/total dimensions;
- `step_item_counts`;
- `tool_calls`, `tool_results` and linkage status;
- `session_quality` and the compatible `trajectory_quality` table;
- `validation_results` and dataset metadata.

Identity is versioned:

```text
session_id = sha256(source_namespace + NUL + (client_metadata.session_id or thread_id))
turn_key   = sha256(session_id + NUL + stable_turn_id)
step_id  = captureId
call_key = sha256(session_id + NUL + native_call_id)
```

Missing native identity creates an explicit orphan session and lowers
completeness. Do not invent a successful task, turn, tool result, or reward.

## Acceptance gates

Publication fails unless:

- capture IDs are unique and source/export counts match;
- every payload chunk decompresses, lengths match, and raw hashes reproduce;
- every session containing the selected model includes all its observed steps;
- a session belongs to exactly one raw part;
- aggregate turns, usage dimensions, and terminal counts reproduce source
  indices;
- truncation, left/right censoring, and missing linkage remain explicit;
- `PRAGMA foreign_key_check` returns no rows;
- `PRAGMA integrity_check` returns `ok` for every SQLite file;
- every delivered file has a SHA-256 in both manifest and `SHA256SUMS`.

After upload, verify remote size and SHA-256 before declaring delivery complete.
