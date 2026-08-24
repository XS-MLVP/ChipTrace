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

The `gpt-5.6-sol` projection contains 104,759 unique steps and 975 trajectories.
It has 104,643 completed terminals, 115 failed terminals, one missing terminal,
100,685 tool calls, and 97,592 paired call/results. Its average structural
score is 92.951. Semantic reward is absent, so these figures measure delivery
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
- raw SQLite export streams source bytes into independent 4 MiB zlib chunks;
- export reads a consistent ledger snapshot and publishes only after checks.

The synthetic local benchmark with 500 records, 4 KiB payloads, 16 workers,
and `fsync` enabled measured about 1.25k records/s and 4.9 MiB/s. This is only
a regression baseline. Large-body and NFS throughput must be measured on the
canary storage path before sizing production.

### P0: NFS boundary

The current raw path is NFSv3 with `local_lock=none`. SQLite WAL on that mount
is rejected. Raw immutable segments may remain on NFS; the live ledger must be
on a local persistent ext4/xfs volume. This removes shared-memory locking from
NFS while retaining one auditable global identity boundary.

## Required before production cutover

1. Integrate the reliable submitter in Relay and remove response-status quality
   filtering from the capture admission path. Preserve any explicit mechanical
   traffic exclusion as a separately counted source-policy state.
2. Add a disk-backed Relay outbox or local sidecar handoff. The included
   adapter survives transient failures but its queue is in memory; a Relay
   process crash can still lose jobs that have not reached the collector.
3. Canary the collector on a new data/state root. Do not reuse or mutate the
   existing spool directory during validation.
4. Measure 64 KiB, 4 MiB, 64 MiB, and maximum expected bodies. Set the HTTP byte
   budget from measured peak RSS, not merely host RAM.
5. Run periodic sealed-segment payload audit. Startup intentionally skips
   rehashing already-known sealed history for fast recovery.
6. Back up and restore-test the local ledger; rebuilding it from multi-terabyte
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

Do not base64 bodies or place very large bodies in OpenTelemetry attributes.
Use OTel spans for searchable metadata and link them to the raw payload
locator/hash.

## Open-source components to borrow from

| Project | Useful part | Do not use it as |
| --- | --- | --- |
| [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector) | receivers, batching, retry/backoff, persistent sending queues, metrics | the canonical multi-hundred-MiB raw body store |
| [OpenInference](https://github.com/Arize-ai/openinference) | GenAI span attributes and tool/message conventions | a guarantee of vendor-native payload completeness |
| [Langfuse](https://github.com/langfuse/langfuse) | trace UI, datasets, scoring, prompt/eval workflows | forwarding-critical storage or the only raw copy |
| [Phoenix](https://github.com/Arize-ai/phoenix) | OTel ingestion and evaluation/annotation workflows | a replacement for durable capture identity |
| [OpenLLMetry](https://github.com/traceloop/openllmetry) | framework instrumentation coverage | a lossless proxy-body recorder |

The useful architecture is hybrid: OTel/OpenInference metadata for observability,
an immutable raw store for replayable bodies, and a normalized trajectory
catalog for training and evaluation.
