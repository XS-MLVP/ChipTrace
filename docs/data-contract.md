# Data contract

## Boundary

The collector is a raw, durable boundary. It does not decide whether an
interaction is useful, correct, or eligible for training. In particular, it
does not discard HTTP 408, 429, or 5xx responses, upstream errors, incomplete
responses, or records without usage. Policy and quality decisions happen in a
versioned downstream projection.

The operator must authorize the source before enabling capture. The service
does no body redaction and treats every stored envelope as sensitive raw data,
even when the expected traffic contains no sensitive text.

## Relay input

`POST /capture` accepts `application/json` and requires a `captureId` matching
`cap-[A-Za-z0-9._:-]+`. The current Router V2 relay shape is supported:

```json
{
  "captureId": "cap-...",
  "startedAt": "2026-08-24T00:00:00Z",
  "finishedAt": "2026-08-24T00:00:01Z",
  "requestBodyText": "{\"model\":\"gpt-5.6-sol\",\"input\":[]}",
  "responseStatus": 503,
  "responseBodyText": "data: {...}\n\n",
  "requestTruncated": false,
  "responseTruncated": false,
  "stream": true,
  "captureError": null
}
```

The collector normalizes the two text bodies to the historical
`full-trace-spool-v3` shape:

- valid JSON text becomes `{ "kind": "json", "value": ... }`;
- SSE, plain text, and invalid JSON become `{ "kind": "text", "value": ... }`;
- `requestBodySha256` and `responseBodySha256` cover the original UTF-8 text;
- all response statuses and `captureError` fields are retained;
- the persisted `receivedAt` is derived only from stable event timestamps;
- the collector's actual arrival time is stored separately as `imported_at`.

The stable timestamp rule makes a byte-identical retry with the same
`captureId` idempotent, including compatibility clients that omit timestamps.
Already-normalized spool records are accepted without rewriting their body
shape.

## ACK and identity

The collector returns HTTP 202 only after the segment bytes have crossed the
configured `fsync` boundary and the SQLite ledger transaction has committed.
The response includes `durable: true` and one of these states:

- `accepted`: the ID and payload were committed for the first time;
- `duplicate`: the same ID and payload hash were already committed;
- HTTP 409 `conflict`: the ID was reused with different payload bytes.

HTTP 400/411/413/415, body-budget overload, duplicate, conflict, accepted, and
startup-recovered attempts are recorded in `capture_attempts`. The durable
ledger, rather than process-lifetime counters, is the accounting authority.
Timeout is ambiguous by design: the sender retries the exact serialized body
and ID; the ledger resolves it to accepted or duplicate.

## Storage

Raw records are one JSON object per line in:

```text
<data-root>/segments/segment-NNNNNNNN.open.ndjson
<data-root>/segments/segment-NNNNNNNN.sealed.ndjson
```

Only the writer appends to the one open segment. Rotation atomically renames it
to `sealed`; sealed files have a SHA-256 in the ledger. Startup truncates only
an incomplete tail of an open segment. Missing segments, conflicting IDs, or a
second physical copy of an ID fail startup rather than being hidden.

SQLite state defaults to `<data-root>/state/capture-ledger.sqlite`, but WAL is
rejected on NFS/CIFS. The production layout must use separate roots:

```text
NFS or data volume:  --root /data/capture
local persistent FS: --state-root /data/state
```

The local state directory must be backed up. If it is lost, it can be rebuilt
by scanning all retained segments, but startup will take proportional time.

## Raw SQLite export

`trace-pipeline export` takes a read-only SQLite snapshot and selects sealed or
archived segments only. It builds a private staging database, validates it,
then publishes it atomically: the default no-overwrite path uses a hard link,
while `--replace` uses an atomic rename. The schema is:

- `dataset_meta`: format, creation time, compression, sensitivity claims;
- `source_segments`: segment path, byte/record count, and SHA-256;
- `interactions`: one unique capture and its metadata/source locator;
- `interaction_chunks`: ordered independent zlib or zstd chunks, 4 MiB raw by
  default;
- `validation_results`: record, chunk, foreign-key, and integrity checks.

The independent chunks bound decompression memory and match the existing
trajectory reader's `interactions + interaction_chunks` input contract. Raw
prompt, answer, tool arguments, and tool results stay in this raw database.
The codec and level are recorded on every chunk. Readers must reject unknown
codecs, length mismatches, decompression failures, and raw hash mismatches.

`export-sharded` takes one explicit snapshot of all sealed segment IDs, assigns
each segment to exactly one raw SQLite writer, and publishes a directory with
`manifest.json` and `SHA256SUMS`. Raw shards are a throughput boundary and may
split a session. Only the downstream `release` command may claim session-atomic
delivery.

## Session release and score boundary

`trace-pipeline release` treats a session as the delivery atom. Session identity
comes from `client_metadata.session_id`, falling back to `thread_id`; a missing
identity becomes a one-capture orphan and is scored accordingly. Selecting a
model includes every other-model interaction belonging to the same session.
One session is never split across release parts, even when that session alone
exceeds the configured target size.

The raw export has enough information to calculate session, turn, step, usage,
terminal status, native tool call/result linkage, and truncation flags. The
release automatically keeps:

- `session_completeness_score`: deterministic observed trace completeness;
- component scores for payload, identity, terminal, usage, tool linkage, and
  session boundaries;
- `reward`: nullable correctness or preference result;
- `reward_source`: evaluator, judge version, benchmark, or ground truth.

The 100-point completeness policy is payload 20, session/turn identity 20,
terminal observation 20, usage 5, tool call/result linkage 20, and observed
session boundaries 15. `A_complete` requires all 100 points. Every component
and the underlying flags remain queryable in `session_quality`.

Captured `response.failed`, `response.incomplete`, and `response.cancelled`
events are complete terminal observations and do not imply incomplete capture.
Likewise, HTTP success, `response.completed`, final text, and tool closure are
not semantic reward. Encrypted reasoning may be retained as opaque source data;
the delivery must not claim plaintext chain-of-thought availability.

`left_censored`, `right_censored`, truncation, missing identity, and unmatched
tools remain explicit. Completeness is limited to the supplied raw-input
universe; the builder cannot prove that an omitted source file contains no
earlier or later session step. See `docs/delivery-template.md`.
