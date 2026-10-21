# Auxiliary source-scope producer patch

The seven maintained patches in `docs/upstream-*.patch` close native Session, Turn,
SSE and process scope for business records, but a real 0.163 session still leaves
startup/auxiliary OTLP spans unattributed. The source-context audit correctly
refuses to assign them to the Session. This note records the additional producer
changes applied to the local pinned source tree at
`/nfs/home/zhangyuxin/router_v2/codex-producer-0.163.0/src` (HEAD `8308618`).

## Gap baseline

Session `01a15846` before the changes: 17 gap groups / 1,051 unresolved records
(`fs.*`, `config/read`, `auth`, `plugin/list`, `skills/list`, `account/read`,
app-server RPC, `thread/name/set`, `rmcp` transport). After the changes, Session
`01a15887` reports 0 gap groups and `inspect-session delivery_ready=true`.

## Changes

| Location | Change |
| --- | --- |
| `app-server/src/app_server_tracing.rs` | `record_process_scope_for_method` marks account/auth/collaboration/hooks/plugin/skills/fs-catalog/model-catalog methods `process` |
| `app-server/src/config_manager.rs` | `load_with_cli_overrides` records `codex.context_scope="process"` so `fs.*` children inherit |
| `app-server/src/request_processors/thread_processor.rs` | `thread/name/set` records `conversation.id` and `session` from its params |
| `app-server/src/request_processors/thread_attachments.rs` | `thread/attachment/list` records `conversation.id` and `session` |
| `exec-server/src/local_file_system.rs` | `fs.read_file` / `fs.get_metadata` record `process` |
| `exec-server/src/client/route_aware_http_client.rs` | `codex.exec_server.http_request` records `process` |
| `model-provider/src/models_endpoint.rs` | `codex.api_request` for the model catalog records `process` |
| `otel/src/events/session_telemetry.rs` | `with_conversation_id` rebinds telemetry to the native Session |
| `core/src/client.rs` | API/SSE/WebSocket telemetry uses `responses_metadata.session_id` (the Wire `session-id`) instead of the turn thread placeholder |
| `otel/src/provider.rs` | `SessionSplittingExporter` splits trace/log SDK batches per native Session before OTLP export |
| `rmcp` git checkout (`rust-sdk` rev `4048ac40`) | `transport_worker`, `serve_inner`, `streamable_http_session` record `process` |

The rmcp change lives in the Cargo git checkout because those spans are created
inside the dependency. The checkout's `rust-toolchain.toml` requests 1.96; build
with `RUSTUP_TOOLCHAIN=1.95.0-x86_64-unknown-linux-gnu` to avoid a network
toolchain sync:

```bash
cd /nfs/home/zhangyuxin/router_v2/codex-producer-0.163.0/src/codex-rs
RUSTUP_TOOLCHAIN=1.95.0-x86_64-unknown-linux-gnu \
  cargo build -p codex-cli --bin codex --locked
```

## Per-Session export split

The app-server/exec-server process can batch spans and logs from several native
Sessions (for example the startup `thread/attachment/list` for another thread),
and `assemble` rejects a telemetry batch that mixes the selected Session with an
unrelated one. `otel/src/provider.rs` now wraps both the trace and log OTLP
exporters in `SessionSplittingExporter`, which groups every SDK export batch by
`conversation.id`/`session.id`/`turn.id` and sends one batch per Session;
records without a native identity stay together as one process batch. This is a
producer-side split, not an audit exemption: each exported batch has one Session
identity, and a session-less auxiliary record still fails the audit unless the
producer marked it `process`.

The Session view also treats duplicate Hook boundaries as duplicates when the
two deliveries arrive out of order (absolute timestamp distance within two
seconds), because the managed requirements and user `hooks.json` run
concurrently.
