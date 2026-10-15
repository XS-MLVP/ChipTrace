# Cloud platform embedding

`ChipTracePlugin` is a server side adapter for a platform that needs durable
Trace collection and export. One plugin instance owns one configured project
namespace: its root, capture directory, object-store namespace, and backend
credentials are fixed by the host. Requests can choose an archive/session
identifier, but cannot choose paths, credentials, storage options, or release
quality gates.

The plugin persists job acknowledgements before returning, uses the Rust
engine's OS lock for a single writer, resumes queued/running jobs after a
restart, and stores native Session/Turn records in a checksummed JSONL sidecar.
The `turns` endpoint reads that sidecar by page, so a large Session does not
remain in the service's heap. Inspection jobs also retain the verified canonical
interaction projection; its manifest, ModelInteraction, RuntimeSpan and Link
parts are available through the projection endpoint and are rechecked against
their recorded SHA-256 before every download. This keeps the paged Turn summary
small without dropping the full interaction evidence.

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

The supported storage backends are `fs`, `oss`, and `s3`. `fs` is useful for a
single-node deployment and keeps the committed Raw archive on a mounted disk;
`oss` and `s3` keep the immutable archive in object storage while the plugin
still restores it to its private work directory before inspection. Credentials
come from the service environment and are never accepted in a job request.
The repository CI exercises the S3 protocol against an isolated MinIO service;
real Alibaba Cloud OSS credentials and regional endpoint behavior must be
verified in the deployment account before production enablement.

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
