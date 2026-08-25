# Canary and rollout

This repository has not replaced the live collector. The following sequence is
designed to preserve forwarding availability and existing raw data.

The direct entrypoint remains independent and is outside this rollout. Only
clients that deliberately select the capture entrypoint are in scope.

## 1. Offline gate

```bash
make self-test
```

Record the current read-only baseline from Relay `/health` and the existing
spooler `/health`: accepted, submitted, filtered, dropped, rejected, queue
bytes, last event time, and current segment. Do not infer closure from log lines
alone.

## 2. Start an isolated collector

Use a new NFS data directory, a new local state directory, and canary port 3011.
The example Compose file has profile `canary` and does nothing until explicitly
started:

```bash
export TRACE_CAPTURE_DATA_ROOT=/srv/trace-data/capture-canary
export TRACE_CAPTURE_STATE_ROOT=/var/lib/trace-pipeline-canary
export TRACE_COLLECTOR_NETWORK=trace-pipeline-net
export TRACE_PIPELINE_UID="$(id -u)"
export TRACE_PIPELINE_GID="$(id -g)"
install -d -m 0700 "$TRACE_CAPTURE_DATA_ROOT" "$TRACE_CAPTURE_STATE_ROOT"
docker compose -f deploy/collector-canary.compose.yml --profile canary up -d --build
curl -fsS http://127.0.0.1:3011/health
```

Do not mount `records/full-trace-capture` into the canary. That directory
belongs to the existing spool/archive pipeline.

## 3. Synthetic compatibility gate

Submit fixtures containing:

- HTTP 200 JSON response;
- SSE response;
- HTTP 408, 429, and 503;
- upstream `captureError` without a terminal event;
- same-ID same-body retry;
- same-ID changed-body conflict;
- body near the configured maximum;
- forced collector timeout followed by retry.

Required results: failures remain present, retry produces one physical row,
conflict is 409, byte-budget overload is explicit, `/audit` is healthy, and a
sealed SQLite export passes all validation rows. A synthetic multi-file
release must also report `session_split_count=0`, reproduce all selected
records, and distinguish a closed session from an open tool session in its
completeness score.

## 4. Shadow or bounded cohort

Integrate `integration/durable_capture_outbox.js` behind a disabled feature
flag. Remove status-code filtering only for the canary route. Start with a
bounded internal cohort and keep the existing collector path unchanged as
rollback.

Gate for at least one complete rotation interval:

- accounting conservation is true and unknown drops are zero;
- 408/429/5xx samples appear in the collector;
- queue and body-budget saturation remain zero at normal load;
- relay forwarding error rate and latency do not regress;
- collector restart recovers the open tail and preserves ID uniqueness;
- sealed audit and SQLite export pass;
- process RSS and NFS write latency stay below agreed host limits.

The included outbox is persistent. Before cutover, crash-test restart recovery,
byte-identical retry, explicit conflict quarantine, and accounting conservation
on the actual local filesystem.

## 5. Cutover and rollback

Any production relay change needs a separate approved window. Recreate only
the capture relay; do not restart the direct path, databases, caches, or
unrelated observability services for a collector-only change.

Before cutover, record the old spooler URL/config and the exact command to
restore it. Rollback means restoring that URL/config and recreating only Relay.
Keep both collectors and their roots intact until all acknowledged canary rows
are audited and exported. Never delete or merge production roots during the
rollback window.

## 6. Operating checks

Automate these alerts:

- `health.ok != true` or writer fatal error;
- nonzero conflicts;
- body-budget or queue rejections;
- attempt accounting mismatch;
- no recent accepted row while Relay has eligible traffic;
- open segment exceeds size/age policy;
- sealed checksum or locator audit failure;
- local state filesystem free space below threshold;
- NFS latency or free space below threshold;
- export validation failure.

Run payload audit on sealed segments outside peak hours. Export from sealed
segments only. Back up the local ledger and test restore quarterly.
