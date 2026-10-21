# Cloud platform embedding

`ChipTracePlugin` is a server side adapter for a platform that needs durable
Trace collection and export. One plugin instance owns one configured project
namespace: its root, capture directory, object-store namespace, and backend
credentials are fixed by the host. Requests can choose an archive/session
identifier, but cannot choose paths, credentials, storage options, or release
quality gates.

The host must supply `projectId` to `ChipTracePlugin`/`createPlatformServer`,
or `CHIPTRACE_PROJECT_ID` to the standalone service. This is a stable ASCII
project identifier assigned by the host, not a field accepted from API callers.
Each root persists a private `NAMESPACE.json` before accepting jobs. Its SHA-256
binds the project, capture path and effective storage namespace (backend,
filesystem object root or endpoint/bucket/region, and prefix); it contains no
credentials or conversation data. Source settings are fixed for the instance.
Credential rotation and resource-limit changes do not change the binding.

Startup rejects mismatched configuration with `NAMESPACE_CONFLICT` before
loading jobs or reusing snapshots. Invalid bindings fail as `CORRUPT_STATE`.
Existing jobs, work, usage or snapshots without a binding fail as
`NAMESPACE_UNBOUND`; their bytes remain intact. For such historical state, keep
the old root for evidence and start a new bound project root, verify the
authoritative Raw in the intended storage namespace, then submit new restore,
inspection and export jobs. Do not invent a binding or copy old cache/job files
into a new namespace. Switching storage backends, project IDs or capture paths
also requires a new root and verified migration. The binding guards accidental
state reuse; host authentication and tenant authorization remain required.

`GET /health` reports the selected `backend` as `fs`, `oss`, or `s3` without
exposing endpoint, bucket, prefix, or credentials. A production deployment gate
should pass `--expected-backend oss` (or an approved `s3`) to
`scripts/ci/platform-health-gate.js`; this makes a local FS scratch service fail
closed before it is presented as a remote durable export service.

The plugin persists job acknowledgements before returning, uses the Rust
engine's OS lock for a single writer, resumes queued/running jobs after a
restart, and stores native Session/Turn records in a checksummed JSONL sidecar.
Inspection uses `inspect-session --platform-report --projection-output DIR`:
the engine durably writes the full `turns.jsonl` beside the projection and
returns a `chiptrace.platform-inspection.v1` summary with its byte count,
SHA-256 and record count. The platform verifies the sidecar before completing
the job. Full Turn arrays are absent from engine stdout and job JSON; the
default CLI inspection output retains its existing full format. The projection
manifest is hashed in chunks during job setup. Use a matching plugin/CLI build;
an older CLI that lacks this report fails explicitly.

Export creation, restart recovery and every package download use
`cloud-acceptance` / `verify-cloud-acceptance --platform-report`. These run the
full acceptance verifier before returning `chiptrace.platform-acceptance.v1`:
an `acceptance` summary, manifest checksum and the same durable Turn sidecar
descriptor. The full `chiptrace.cloud-acceptance.v2` manifest and its complete
Session view stay on disk. Public export jobs keep their existing v2 summary
fields without the Turn array. The summary is not a standalone full acceptance
Schema document. Downloads recheck the accepted summary, Turn descriptor and
package bytes against the completed job. The default CLI commands retain their
full output; default `verify-cloud-acceptance` is still read-only. Explicit
`--platform-report` can create its derived sidecar beside the acceptance root.

The engine JSON limit (`maxOutputBytes` / `CHIPTRACE_MAX_OUTPUT_BYTES`) and Turn
disk limit (`maxTurnBytes` / `CHIPTRACE_MAX_TURN_BYTES`) are independent; both
default to 64 MiB. A host can provision more Turn disk capacity without raising
the engine stdout/heap guard. The engine refuses to publish a sidecar above
the configured disk limit. Restarts can reuse an existing sidecar only when
its exact canonical bytes match the inspected snapshot, including sidecars
written by the previous platform. Changed evidence and symlinks are preserved
and refused. Completed legacy jobs remain readable through their recorded
hashes.

The `turns` endpoint reads that sidecar by page; completed inspection and export jobs keep
only the summary in their long-lived state. Inspection jobs also retain the verified canonical
interaction projection; its manifest, ModelInteraction, RuntimeSpan and Link
parts are available through the projection endpoint and are rechecked against
their recorded SHA-256 before every download. This keeps the paged Turn summary
small without dropping the full interaction evidence.

The writer serializes borrowed Turn fields directly into a buffered, hashing,
quota-checked file; it does not clone a Turn or allocate its whole JSON line.
Completion verification scans chunks, hashing all bytes and counting records.
HTTP Turn pages keep the existing JSON object format but stream selected rows
without materializing them in Node. `read-turn-page` validates every JSONL
record and all UTF-8 bytes in Rust, returning only the recorded digest, count
and at most 100 selected byte ranges. Node opens one `O_NOFOLLOW` descriptor
before that scan, verifies its identity against the path and recorded size
afterward, then streams from the same descriptor. Invalid records, including
those outside the page, fail before response headers; a missing, replaced or
unreadable sidecar is reported as `ARTIFACT_CHANGED`.
Use `client.streamTurns(id, { offset, limit })` to consume a page's Response
body as a stream. `client.getTurns` still parses that Response into an object
on the client. The embedding-only `plugin.getTurns` object API also retains
selected rows in its caller's memory; use `plugin.openTurnPage` for streaming.
For the full file, use `client.downloadTurns(id)`
(`GET /v1/jobs/{id}/turns.jsonl`). The server checks the complete byte count, record
count and SHA-256 before responding, and streams from the same open file with
`Content-Length`, `ETag` and `X-Content-SHA256`. Clients should hash downloaded
bytes; this validates the recorded artifact and does not certify an incomplete
Session as delivery-ready. Host storage must prevent in-place evidence writes.

Restores and inspections reuse one verified disk snapshot per archive ID.
Jobs for the same archive are serialized; distinct archives can run up to the
configured concurrency. Queue length, job history, usage bodies, engine output
and execution time all have limits. Export directories retain their own Raw
and verification evidence; provision storage for these directories and set a
host-managed retention policy after downloads are acknowledged.

The HTTP wrapper is intentionally a small internal service. Put the platform's
user authentication and tenant authorization in front of it; its bearer token
is a backend service credential, not an end-user credential. The service
exposes:

```text
GET  /health
POST /v1/jobs
GET  /v1/jobs?offset=0&limit=50
GET  /v1/jobs/{id}
GET  /v1/jobs/{id}/turns?offset=0&limit=50
GET  /v1/jobs/{id}/turns.jsonl
GET  /v1/jobs/{id}/projection/{part}
PUT  /v1/usage/{id}
GET  /v1/jobs/{id}/packages/{file}
```

The [OpenAPI contract](../../schemas/platform-openapi.yaml) describes the job
requests, service authentication, pagination and responses.

Use the Node SDK when embedding in another Node service:

```js
const { ChipTraceClient } = require('./client');
const client = new ChipTraceClient({
  baseUrl: 'http://127.0.0.1:18086',
  token: process.env.CHIPTRACE_PLATFORM_TOKEN,
});
const job = await client.submit({
  id: 'export-2026-10-14', kind: 'export', archive_id: 'raw-2026-10-14',
  session_id: 'stock-codex-session', release_id: 'release-2026-10-14',
  usage_log_ids: ['usage-2026-10-14'],
});
const completed = await client.wait(job.request.id);
```

The supported storage backends are `fs`, `oss`, and `s3`. Production Compose
requires the host to choose the backend explicitly; use `oss` or `s3` when the
local object directory is only scratch space. `fs` is useful for a
single-node deployment and keeps the committed Raw archive on a mounted disk;
`oss` and `s3` keep the immutable archive in object storage while the plugin
still restores it to its private work directory before inspection. Credentials
come from the service environment and are never accepted in a job request.
The repository CI exercises the S3 protocol against an isolated MinIO service;
real Alibaba Cloud OSS credentials and regional endpoint behavior must be
verified in the deployment account before production enablement.

The native producer CI also sends each of its five newly collected Raw samples
through both the FS and private MinIO S3 platform paths. It independently reads
the remote checkpoint, manifest and every Segment object, verifies their hashes,
then checks disk restore, complete Turn/projection downloads, restart recovery
and the same Buyer acceptance or refusal. The reports retain both backend
results and the actual private MinIO binary hash. Model data is synthetic, the
producer is patched, and this does not qualify a real OSS account or tenant.

CI also exercises the actual OpenDAL OSS adapter against a signed HTTP
protocol fixture, including checksum failures and single-pass disk downloads.
That fixture is a protocol regression test, not Alibaba Cloud acceptance.

The CLI has two direct diagnostic entry points:

```bash
chiptrace restore-raw-archive --backend oss --endpoint "$OSS_ENDPOINT" \
  --bucket "$OSS_BUCKET" --prefix chiptrace --archive-id raw-001 \
  --output /srv/chiptrace/restored/raw-001 --verify-records
chiptrace verify-restored-raw --input /srv/chiptrace/restored/raw-001
chiptrace inspect-session --input /srv/chiptrace/restored/raw-001 \
  --session-id <stock-codex-session-id>
```

Disk verification needs no credentials. It checks the exact committed file
set, lengths, SHA-256 and record counts, and rejects symlinks and extra files.
Restoration stages bytes in a separate directory and publishes only verified
content. On Linux `--replace` uses an atomic directory exchange; filesystems
that do not support that operation keep the previous output and require a new
destination. Every restored directory retains `RAW_SOURCE.json`,
`RAW_MANIFEST.json` and `RAW_CHECKPOINT.json`.

`chiptrace.session-view.v2` reports native turns by explicit source Session and
Turn IDs, model interactions, evidence record counts, open/closed/conflicted
boundaries, and per-Turn Wire/OTLP logs/OTLP traces/Hook coverage. A Session is
delivery-ready only when every Turn has all four sources, no Turn is open or
conflicted, and no business evidence is unscoped. Retry requests and tool
captures cannot inflate native turns, `SessionStart(source=compact)` cannot
start another epoch, and resumed Sessions need a new `SessionEnd`. Missing IDs
remain unscoped. Buyer v7's
`effective_turns` is a separate procurement metric (user pairs plus paired
required calls) and keeps its existing gate.

`delivery_ready` on the Session view and inspection result combines source
coverage, closed Session/Turn boundaries and zero unscoped records.
`unscoped_source_records` identifies which sources still lack an exact Turn
join. Native logs can join through the Wire's W3C context and observed span
ancestry; blank IDs and ambiguous shared traces never join by time or order.

The inspection result's top-level `delivery_ready` and `validation_status`
combine the scoped Session view, canonical protocol/runtime integrity and
`source_context_audit`. Entire OTLP batches without an exact Session owner
remain in the audit, even when their payloads are excluded from the selected
canonical projection. They cannot be presumed unrelated. Inspection reuses one
read snapshot for both projection and auditing; its audit disables ID samples.
The full identity/parent index still grows with corpus size and is not yet a
disk index.
The Rust projection still holds the selected Session and Turn metadata in
memory; these compact reports do not bound Rust projection or acceptance RSS.
Projection downloads use `read-projection-manifest --input FILE` to extract
only the recorded schema/session/counts/parts metadata in Rust. The command
streams the complete file with UTF-8, JSON syntax, length and SHA-256 checks,
skipping large Session/Turn/metrics values. Its
`chiptrace.projection-manifest-metadata.v1` report explicitly sets
`session_delivery_claimed=false`; it does not run full projection or Session
acceptance. The plugin compares both the complete Manifest descriptor and
metadata to the recorded job, with strict values and order-independent object
keys. It then hashes the requested regular file and streams from that same
open handle. Original Manifest bytes and part hashes remain unchanged.
Each download uses a CLI process under the existing timeout/output limits and
holds a read slot until its stream closes. Plugin and CLI builds must match.
Turn pages still validate and count the whole
sidecar, including records outside the requested page. The page path reuses
the Rust-produced digest and the descriptor opened before validation, so it
does not perform a second Node full-file digest; the object API and full-file
download retain their complete Node-side checksum pass. These paths need
separate scale measurements and a persistent index before capacity claims.
One selected Turn can itself contain a large set of Raw references; a page's
Turn count does not impose a byte limit on its streamed response. HTTP pages
perform one full Rust validation pass before sending bytes and reuse its
verified descriptor; they do not use a persistent index, so each page remains
O(file size). Both page and full-file streams consume a read slot until their file handle closes,
including cancellation before the first byte. Page JSON framing is generated
by the server; selected row bytes, including any legal whitespace, come from
the verified sidecar. No Raw reference is truncated or dropped.

CI explicitly runs `make turn-memory-test`'s ignored Rust RSS regressions in
separate processes and requires exactly one measured test per case: Turn
serialization has a 128 MiB fixture budget; streaming Manifest and Turn page
reading each have a 48 MiB fixture budget. The platform suite also reads an
80 MB synthetic Turn sidecar in a Node child with a 32 MiB V8 heap, skipping
a giant row, streaming the giant selected page and the full file with exact
byte/hash checks, and rejecting corruption outside the selected page.
Another limited-heap test downloads an expanded Manifest and canonical part,
rejects metadata conflicts and skipped Turn corruption, and rejects invalid
UTF-8 even when the recorded digest is changed to match those synthetic bytes.
These synthetic metadata checks do not establish production capture capacity
or bound the Rust projection/acceptance paths described above.

The Turns endpoint also returns this overall `delivery_ready` alongside the
scoped `summary`. A true `summary.delivery_ready` or
`integrity.delivery_ready` alone does not certify the complete inspection.
Job queries, idempotent submission responses and both embedded and HTTP Turn
pages conservatively recheck the recorded native Session identity, closed
boundaries, four-source coverage and source audit. Inspections also require
every recorded integrity gate; exports
require the v2 acceptance schema, passing hard gate/status, Buyer v7 counts and
pairing, single-root/resolved-parent counts, positive Raw counts and score at
least the recorded minimum (90–100).
Missing or contradictory evidence overrides a historical `delivery_ready=true`:
the returned job has `delivery_ready=false` and `not_ready` (inspection) or `fail`
(export). Historical job files, nested evidence and Turn sidecars are not
rewritten. Submit a new job ID to recheck the original archive. This read-time
check does not rerun acceptance or prove current artifact integrity; Buyer
downloads still run the complete Rust acceptance verifier.

Exports require `chiptrace.cloud-acceptance.v2`. Historical v1 manifests retain
their original contract and must be reprocessed from original Raw to qualify
for the current release.

`projection/{part}` is available for completed inspection jobs with `part` set
to `manifest`, `interactions`, `runtime`, or `links`. The compressed JSONL
parts retain every canonical ModelInteraction, RuntimeSpan and InteractionLink;
the manifest records their counts and checksums. The Turn sidecar remains the
bounded index containing each Turn's explicit identity, source coverage and Raw
capture references. Consumers should use those identities and the projection
parts together rather than treating Session-level counts as Turn evidence.

For a container image, build from the repository root:

```bash
docker build --target platform \
  --build-arg CHIPTRACE_REVISION=<git-revision> \
  -t chiptrace-platform:<git-revision> .
```

The minimal Compose example is [deploy/cloud-platform.yml](../../deploy/cloud-platform.yml).
Set its required `CHIPTRACE_PROJECT_ID` alongside the service token and root.
Mount `/data/platform` on durable local storage. In `fs` mode also mount the
object root; in `oss`/`s3` mode it can be an empty scratch directory.

The platform API accepts the following jobs:

```json
{"id":"archive-001","kind":"archive","archive_id":"raw-001"}
{"id":"restore-001","kind":"restore","archive_id":"raw-001"}
{"id":"inspect-001","kind":"inspect","archive_id":"raw-001","session_id":"session-001"}
{"id":"export-001","kind":"export","archive_id":"raw-001","session_id":"session-001","release_id":"release-001","usage_log_ids":["usage-001"]}
```

Before `archive`, the host must seal and freeze the configured capture inputs.
A live directory with a nonempty open WAL is refused. Upload authoritative
Sub2API JSONL using `PUT /v1/usage/usage-001` before `export`; that ID is immutable
and conflicting bytes return 409. An inspection may complete with incomplete
evidence and reports its integrity; an export still requires all four sources,
Buyer v7 hard gates and a score of at least 90. A nonzero engine exit is retained
as a failed job with its actual exit code.

For direct in-process embedding, construct `ChipTracePlugin` with the same
server-controlled settings and call `await plugin.start()`, `submit`, `getJob`,
`getTurns` and `close`. `createPlatformHandler` can be mounted under a host HTTP
server. Use a separate root/storage namespace per authorized project. This
adapter does not implement cross-tenant authorization, billing or raw ingress;
collection remains the existing gateway/Relay/Collector path.
