# Trace Training Pipeline

This repository is the isolated capture and training-data boundary for the
Router V2 full interaction path. It is intentionally independent from the
online relay deployment: the current relay is not modified by this repository.
The direct `18080` entrypoint and capture-enabled `18084` entrypoint remain
independent by design.

The service accepts the existing Relay `POST /capture` envelope, normalizes it
to the historical spool shape, keeps every valid response (including errors),
and durably records it before returning `202`.
Retries with the same `captureId` are acknowledged as duplicates instead of
creating a second physical record.

## What this fixes

- no status-code filtering at the capture boundary;
- bounded backpressure instead of fire-and-forget HTTP submission;
- a durable attempt ledger with explicit terminal states;
- one global `capture_id` uniqueness boundary across all segments;
- explicit `open -> sealed` segment lifecycle rather than mtime-based closure;
- crash recovery of complete lines and safe truncation of an incomplete tail;
- SQLite integrity and source/hash/byte accounting suitable for later session
  assembly and evaluation;
- bounded HTTP body memory, writer queue, and Relay retry queue;
- independently compressed SQLite chunks for bounded-memory training reads;
- complete-session release parts with automatic completeness scoring.

## Quick start

```bash
cd trace-training-pipeline
PYTHONPATH=src python3 -m trace_pipeline self-test
mkdir -p /var/tmp/trace-pipeline-dev/capture /var/tmp/trace-pipeline-dev/state
PYTHONPATH=src python3 -m trace_pipeline serve \
  --root /var/tmp/trace-pipeline-dev/capture \
  --state-root /var/tmp/trace-pipeline-dev/state \
  --port 3010
```

The service is compatible with the current relay submission shape:

```bash
curl -X POST http://127.0.0.1:3010/capture \
  -H 'content-type: application/json' \
  --data-binary @capture.json
```

`/health` is read-only and reports queue, ledger, segment, and recovery state.
`/audit` runs a bounded read-only audit and does not alter captured bodies.

Export sealed data, then build the preferred complete-session release with:

```bash
PYTHONPATH=src python3 -m trace_pipeline export \
  --root /data/capture --ledger /data/state/capture-ledger.sqlite \
  --output /delivery/gpt-next-part-001.sqlite \
  --compression-codec zstd --compression-level 1 \
  --compression-workers 8 --compression-batch-mib 256
PYTHONPATH=src python3 -m trace_pipeline export-sharded \
  --root /data/capture --ledger /data/state/capture-ledger.sqlite \
  --output /delivery/raw-shards \
  --shards 8 --max-writers 4 \
  --compression-codec zstd --compression-level 1 \
  --compression-workers-per-writer 2 --compression-batch-mib 256
PYTHONPATH=src python3 -m trace_pipeline release \
  --input /delivery/gpt-next-part-001.sqlite \
  --output /release/router-v2-gpt-next-YYYYMMDD-v1 \
  --model gpt-next-sol --target-part-gib 10
```

`release` selects every session containing the requested model, includes all
other-model interactions from those sessions, and never splits one session
across SQLite parts. It creates `session-catalog.sqlite`, `manifest.json`, and
`SHA256SUMS`. The automatic score measures observed trace completeness only;
semantic reward remains null.

`export-sharded` partitions immutable source segments across independent SQLite
writers. Its raw parts are deliberately not session-atomic; pass every raw part
to `release` to produce the final complete-session directory.

Run the full Python, Node, crash-recovery, export, and performance suite with:

```bash
make self-test
make benchmark-pack
```

Install the optional native codecs before using zstd:

```bash
python3 -m pip install -e '.[performance]'
```

## Repository boundary

The raw envelope is treated as sensitive even when the expected cohort has no
sensitive body text. This repository does not publish or copy the existing
production spool. Use separate data/state roots for tests and deployment.
Training exports must come from sealed segments after policy, consent,
de-duplication, and evaluation checks.

Read `docs/optimization-plan.md`, `docs/high-throughput-plan.md`,
`docs/data-contract.md`, and `docs/rollout.md` before connecting the service to
`18084`. The deployment examples are canary-only and are not enabled by this
repository.
