# Native OTLP context regression

`native-context-0163.json` is a small metadata subset derived from the isolated,
real `0.163.0-alpha.11` canary described in `docs/native-turn-context.md`. The
provenance names the upstream commit and original sealed Segment SHA-256.

Selected records retain their identity fields and observed span ancestry.
Session/Turn UUIDs and Trace/Span IDs use consistent aliases; absent and empty
IDs stay absent or empty. OS `thread.id` values are preserved separately from
native `thread_id`. Bodies, timestamps, file paths, tools, auth and unrelated
attributes are omitted. This is a transformed regression fixture, not original
Raw, a complete canary, or a qualified delivery package.

The subset has 3 logs and 26 spans: 1 log and 15 spans remain unscoped, while 1
additional span has no exact Session owner. The `model_client.stream_responses_api`
ancestry reaches native Turn attributes; the SSE record still has no Trace/Span.
CI must preserve both observations. Supplying a Span in a positive protocol
test validates the join only; it does not demonstrate that Stock Codex emits it.

Rust checks the join, unchanged Session gates, bounded diagnostics and schema.
Node runs the real CLI with reconstructed Capture envelopes, verifies input
bytes remain unchanged and asserts actual nonzero exits for corrupt/conflicting
inputs. CI also runs the CLI path in a container with a read-only root filesystem.

Separate synthetic negative cases cover seven Turn business event names with
explicit or exact-parent-inherited Process scope (14 combinations). The Rust
audit and Session checks reject this conflict; the real CLI must exit 1 with
empty stdout, bounded diagnostics without body content, unchanged input bytes
and no new files. These cases prevent Process declarations from hiding missing
Turn identities; they are not observations of a real producer emitting them.

Another CLI regression keeps wholly unowned batches in source accounting,
resolves exact Process ancestry across separate batches, excludes an explicitly
unrelated Session, and counts duplicate Captures once. The HTTP/SDK regression
in `integrations/cloud-platform/platform.test.js` verifies that an otherwise
complete synthetic Session with unowned logs/traces cannot claim overall
delivery through inspection, paged Turns, or export.
