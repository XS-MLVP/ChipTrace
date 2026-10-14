# Draft: OTLP SSE logs lack request/Turn context in 0.163.0-alpha.11

This is a draft for upstream review. It has not been posted as an issue or PR.

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

The proposed investigation is to retain immutable request/Turn context when
the telemetry adapter is constructed and restore it inside synchronous SSE
callbacks. The attached [patch draft](upstream-sse-context.patch) preserves a
`tracing::Span` and enters it for `on_sse_poll`. It applies cleanly to the
pinned `0.163.0-alpha.11` source and to the current inspected upstream source.
The patch plus [regression test](upstream-sse-context-test.patch) compiled and
passed on a complete `0.150.0-alpha.9` source worktree. It has not yet been
compiled against the pinned `0.163.0-alpha.11` tree or validated by a new
unmodified-client canary. In particular, the adapter's construction sites must
be checked to ensure the captured Span is request or Turn scoped.

Suggested regression coverage:

- Emit callbacks after leaving the creation Span and while another Turn is
  active; assert OTLP identity belongs to the original request.
- Exercise retry, parallel requests, resumed sessions, cancellation and SSE
  failures; avoid a process-global mutable current-Turn label.
- Verify original Wire W3C context and exported Span ancestry still establish
  an unambiguous native Session/Turn join.

The collector also observed 159 other spans without an exact Turn join. That
is a separate scope-audit item, not evidence that this draft fixes all native
telemetry. Raw records remain preserved and strict delivery remains rejected.
No provider credential, conversation body or complete Raw archive is attached.
