# Optimization plan

## Evidence from the existing pipeline

This snapshot was measured read-only on 2026-08-24. It is the baseline for the
new design, not a claim that the new collector is already deployed.

| Observation | Measured value | Consequence |
| --- | ---: | --- |
| Relay accepted / submitted | 226,144 / 222,627 | Lifetime counters do not form a closed state machine |
| Relay filtered / dropped | 2,619 / 687 | Failure and timeout examples are missing from raw training data |
| Spooler rejected | 11 | Rejections exist but are not joined to a durable attempt ledger |
| Existing physical / unique captures | 210,483 / 208,794 | 1,689 cross-pack duplicate rows |
| Duplicate raw bytes | about 1.536 GB | Three source segments were packaged into adjacent packs twice |
| Submission deadline | 250 ms | NFS or spooler stalls become permanent drops; no durable retry |
| Existing write path | synchronous stringify + append on Node | Large bodies block the spooler event loop and create memory copies |
| Last capture | 2026-08-12 00:55 +08:00 | No later source record exists in this capture path as of the snapshot |

The measured target-model projection contains 104,759 unique steps and 975 trajectories.
It has 104,643 completed terminals, 115 failed terminals, one missing terminal,
100,685 tool calls, and 97,592 paired call/results. Its average structural
score under the earlier `structural-deliverability-v1` policy is 92.951. It
must be recomputed with the session completeness policy when building a new
release. Semantic reward is absent, so these figures measure delivery
structure, not answer correctness. API usage is a lower bound of
16,966,625,642 tokens; it is repeated processing usage, not deduplicated corpus
tokens.

## Implemented in this repository

### P0: durable identity and accounting

- one global `capture_id` primary key across every segment and export;
- same-body retry returns duplicate; different-body reuse returns 409;
- explicit `capture_attempts` states for accepted, duplicate, conflict,
  recovered, and rejected requests;
- failure responses and capture errors are retained without status filtering;
- segment `fsync` then SQLite `synchronous=FULL` commit before HTTP 202;
- crash recovery truncates only an incomplete open tail;
- missing files and physical duplicate IDs prevent a false-ready startup.

This directly addresses the 1,689 duplicate rows and the unaccounted relay
drops. Accounting target:

```text
offered = durable + conflict + rejected/dropped + queued + in_flight
```

### P0: bounded high-throughput path

- one writer owns both the append file and SQLite connection;
- small requests are group-committed by record count/time;
- HTTP connections, writer queue items, and in-flight body bytes are bounded;
- the Relay adapter serializes once, retries the exact body with exponential
  backoff, and reports a conservation check;
- the durable Relay outbox persists each body locally, recovers it after a
  restart, and deletes it only after an explicit remote durable acknowledgement;
- raw SQLite export streams source bytes into independent 4 MiB zlib or zstd
  chunks through a bounded parallel compression window;
- sharded raw export balances immutable segments across independent SQLite
  writer processes and validates aggregate segment/record/byte conservation;
- export reads a consistent ledger snapshot and publishes only after checks.

### P0: session-atomic release

- source-namespaced `session_id/thread_id` is the release identity, independent of model;
- selecting a target model includes helper/subagent model steps in that session;
- a two-pass planner keeps every session in exactly one target-size SQLite part;
- source compressed chunks are copied without recompressing payloads;
- `session-catalog.sqlite`, manifest, and SHA-256 files publish atomically;
- session completeness is scored automatically with explicit component and
  censoring fields; semantic reward remains null.

The synthetic local benchmark with 500 records, 4 KiB payloads, 16 workers,
and `fsync` enabled measured about 1.25k records/s and 4.9 MiB/s. This is only
a regression baseline. Large-body and NFS throughput must be measured on the
canary storage path before sizing production.

The separate packing target is 500 MB/s sustained with a 1 GB/s stretch goal.
It requires sharded readers and SQLite part writers on 25GbE and multi-NVMe
storage. The current 1GbE host cannot demonstrate that end-to-end rate. See
`docs/high-throughput-plan.md` for metric definitions and acceptance gates.

### P0: NFS boundary

The current raw path is NFSv3 with `local_lock=none`. SQLite WAL on that mount
is rejected. Raw immutable segments may remain on NFS; the live ledger must be
on a local persistent ext4/xfs volume. This removes shared-memory locking from
NFS while retaining one auditable global identity boundary.

## Required before production cutover

1. Integrate the durable outbox in the relay and remove response-status quality
   filtering from the capture admission path. Preserve any explicit mechanical
   traffic exclusion as a separately counted source-policy state.
2. Canary the collector on a new data/state root. Do not reuse or mutate the
   existing spool directory during validation.
3. Measure 64 KiB, 4 MiB, 64 MiB, and maximum expected bodies. Set the HTTP byte
   budget from measured peak RSS, not merely host RAM.
4. Run periodic sealed-segment payload audit. Startup intentionally skips
   rehashing already-known sealed history for fast recovery.
5. Back up and restore-test the local ledger; rebuilding it from multi-terabyte
   raw history is correct but slow.

## Next protocol for very large bodies

The compatibility endpoint must parse one JSON envelope and therefore still
creates several copies of large strings. The byte budget prevents unbounded
concurrency but does not remove this cost. Before raising a single response cap
to 512 MiB or more, introduce a versioned streaming protocol:

1. send fixed-size metadata first, including `captureId`, lengths, and hashes;
2. stream request and response bodies as separate framed parts or file
   descriptors over a local Unix socket;
3. hash and append each part incrementally;
4. commit one ledger row only after every declared part is durable;
5. retain `/capture` as a compatibility path during migration.

Do not base64 bodies or place very large bodies in span attributes. Keep
searchable metadata separate and link it to the immutable raw payload by
locator and hash. Observability storage is not the canonical raw-body store.
