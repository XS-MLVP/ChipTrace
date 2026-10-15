# Draft: OTLP SSE logs lack request/Turn context in 0.163.0

This is a draft for upstream review. It has not been posted as an issue or PR.

## Current stable release reproduction

The official unmodified Linux x64 `0.163.0` binary (release commit
`83086188ae0614bd882818ff1aa23f3194962012`) reproduces the context gap in new
native collection. The maintained `stock-release-context` CI job installs that
exact release and verifies its complete source digest and ELF SHA-256 before
executing two Turns with resume, real tools, HTTP retry and asynchronous
process polling against a local deterministic Responses endpoint. Model bytes
and usage in this reproduction are synthetic; native tools and telemetry are
actually executed.

A local execution retained 2 closed Turns, 2 closed Session epochs, 12 HTTP
attempts and 10 actual native tool results. Its 82 logs included 47 unresolved
Turn records; 1,992 spans included 375 unresolved Turn records and 153 records
without an exact Session owner. All source categories conserved their totals;
these counts vary with initialization and are not pinned as universal values.
The full collection assertion returned actual exit 1. CI accepts the known-gap
diagnostic only after complete protocol/Raw/Runtime witnesses and the missing
source context are verified; it always reports production readiness false.

In the stable source, `ApiTelemetry` still has no captured request Span, and
[`on_sse_poll`](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/core/src/client.rs#L3020)
directly calls `log_sse_event`. The creation-scope and response-terminal patch
and its regression patch apply to this stable commit. The separate Session,
process and configuration scope repairs also apply. Current maintained CI now
builds those repairs from the stable commit; passing the earlier alpha
experiment does not by itself qualify this new source or the official ELF.

## Earlier real-provider reproduction

An unmodified Codex `0.163.0-alpha.11` CLI completed a real Responses-provider
session with native OTLP HTTP JSON logs, traces and lifecycle hooks enabled.
The session ran three shell commands and a subsequent `write_stdin`, including
an intentional exit 7 and a yielded process. The CLI exited 0, and the native
Session and Turn boundaries closed.

The collector durably received five Wire captures, sixteen OTLP log batches,
ten OTLP trace batches and four original lifecycle hooks. All 296
`codex.sse_event` log records have `conversation.id` but lack a valid Trace ID,
Span ID, native Turn ID or request/response ID. Their remaining fields include
`event.kind`, `duration_ms`, `event.timestamp`, model and application metadata.
Other log types, including `codex.tool_result`, did carry usable Span context.

This prevents an exact join of the SSE telemetry to native Turns when sessions
have multiple Turns, retries or concurrent requests. A timestamp or the last
active Turn cannot establish ownership. The same missing SSE context was also
observed with `0.153.4`.

In tag `rust-v0.163.0-alpha.11`, commit
`5425d3e625daa58eea3ad1de27c087eb3b2ffbd3`,
[ApiTelemetry::on_sse_poll](https://github.com/openai/codex/blob/5425d3e625daa58eea3ad1de27c087eb3b2ffbd3/codex-rs/core/src/client.rs#L3019)
calls `SessionTelemetry::log_sse_event` without storing or re-entering the
request's creation Span. The
[SSE emission path](https://github.com/openai/codex/blob/5425d3e625daa58eea3ad1de27c087eb3b2ffbd3/codex-rs/otel/src/events/session_telemetry.rs#L1057)
does not explicitly include native Turn or response identity either.

The attached [patch draft](upstream-sse-context.patch) retains the creation
`tracing::Span` for synchronous SSE callbacks and passes the original request
Span into the detached HTTP/WebSocket response mapper. Both successful and
failed terminal telemetry re-enter that Span only during synchronous emission.
The [regressions](upstream-sse-context-test.patch) cover callbacks after leaving
the creation scope, successful/failed terminals, and parallel requests completing
in reverse order. All four passed on the pinned `0.163.0-alpha.11` source, and
the exact patched CLI built successfully. Removing successful-terminal context
restoration made its test fail with exit 101 and an observed `None` Span.
The release tag's lock reconciliation was verified to change only 160 local
workspace package versions; external dependency lock entries were unchanged.
Tests and the CLI build then used `--locked`.

A real-provider isolated run of the modified CLI retained native boundaries and
tool outcomes, but still rejected Session delivery: one log and 159 spans lacked
an exact Turn join. Another log and 35 spans had no exact Session owner. This is
evidence for the patch mechanism, not an unmodified-release acceptance claim.

Suggested regression coverage:

- Emit callbacks after leaving the creation Span and while another Turn is
  active; assert OTLP identity belongs to the original request.
- Exercise retry, parallel requests, resumed sessions, cancellation and SSE
  failures; avoid a process-global mutable current-Turn label.
- Verify original Wire W3C context and exported Span ancestry still establish
  an unambiguous native Session/Turn join.

The 159 remaining spans belong to startup (139) and Session-loop/shutdown (20)
Traces. These are a separate [scope-audit item](session-scope-audit.md), not
evidence that this draft fixes all native telemetry. Raw records remain
preserved and strict delivery remains rejected.
No provider credential, conversation body or complete Raw archive is attached.
