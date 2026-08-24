# Standard delivery template

## Directory

Deliver one immutable directory per dataset version:

```text
<dataset-id>/
  <model>-part-001.sqlite
  <model>-part-002.sqlite
  ...
  trajectory-catalog.sqlite
  manifest.json
  SHA256SUMS
```

Raw parts should target about 10 GB and stay below the receiver's hard limit.
Never split one trajectory across parts. Reuse verified SQLite files or hard
links when repackaging; do not decompress and recompress unchanged BLOBs.

## Manifest

`manifest.json` should contain:

```json
{
  "dataset_id": "router-v2-gpt-next-YYYYMMDD-v1",
  "schema_version": "trajectory-catalog-v1",
  "projection_mode": "complete-thread",
  "requested_window": {"start": "...", "end": "..."},
  "actual_window": {"start": "...", "end": "..."},
  "models": ["gpt-next-sol"],
  "sensitive_raw_data": true,
  "semantic_reward_available": false,
  "structural_score_policy": "structural-deliverability-v1",
  "records": 0,
  "trajectories": 0,
  "turns": 0,
  "token_totals": {},
  "parts": [
    {"file": "gpt-next-sol-part-001.sqlite", "bytes": 0, "sha256": "..."}
  ],
  "catalog": {"file": "trajectory-catalog.sqlite", "bytes": 0, "sha256": "..."},
  "validation_status": "pass"
}
```

`actual_window` must come from retained event timestamps. Do not extend it to
the requested end date when collection stopped earlier.

## Catalog minimum

The catalog should contain no duplicate raw bodies. It points to raw records by
`(shard_id, record_id)` and includes these normalized tables:

- `trajectories`, `turns`, `steps`;
- `step_usage`, including input/cache/output/reasoning/total dimensions;
- `step_item_counts`;
- `tool_calls`, `tool_results` and linkage status;
- `trajectory_quality` with policy components;
- `validation_results` and dataset metadata.

Identity is versioned:

```text
traj_id  = sha256(scope + NUL + stable_thread_id)
turn_key = sha256(traj_id + NUL + stable_turn_id)
step_id  = captureId
call_key = sha256(traj_id + NUL + native_call_id)
```

Missing native identity stays null and lowers structural quality. Do not invent
a successful thread, turn, tool result, or reward.

## Acceptance gates

Publication fails unless:

- capture IDs are unique and source/export counts match;
- every payload chunk decompresses, lengths match, and raw hashes reproduce;
- all selected steps match the declared projection;
- a trajectory belongs to exactly one raw part;
- aggregate turns, usage dimensions, and terminal counts reproduce source
  indices;
- truncation, left/right censoring, and missing linkage remain explicit;
- `PRAGMA foreign_key_check` returns no rows;
- `PRAGMA integrity_check` returns `ok` for every SQLite file;
- every delivered file has a SHA-256 in both manifest and `SHA256SUMS`.

After upload, verify remote size and SHA-256 before declaring delivery complete.
