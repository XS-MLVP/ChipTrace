# 网关 Anthropic 身份回填

Claude Code 的 `/v1/messages` 请求没有 `session-id` header，Turn 也没有 header。
`relay_shell/server.js` 需要在 Wire 捕获记录中回填两个身份：

1. `session_id`：解析请求体 `metadata.user_id`（JSON 字符串）中的 `session_id`。
2. `turn_id`/`root_turn_id`：从 Hook helper 写入的
   `<CHIPTRACE_CLAUDE_TURN_STATE_DIR>/<session>.json` 读取 `turn_id`（即 Claude 的
   `prompt_id`）。

配置：

```text
CHIPTRACE_CLAUDE_TURN_STATE_DIR=/monitor-state/claude-turns
```

该目录与 Hook helper 的 `CHIPTRACE_CLAUDE_STATE_DIR` 必须是同一个共享目录。

核心函数：

```js
const SESSION_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function sessionFromUserId(userId) {
  if (typeof userId !== 'string') return null;
  try {
    const session = JSON.parse(userId)?.session_id;
    return typeof session === 'string' && SESSION_UUID_RE.test(session) ? session : null;
  } catch {
    return null;
  }
}

function anthropicSessionFromBody(requestBodyText) {
  if (typeof requestBodyText !== 'string' || requestBodyText.trim() === '') return null;
  try {
    const session = sessionFromUserId(JSON.parse(requestBodyText)?.metadata?.user_id);
    if (session) return session;
  } catch {
    // Large interactive requests are sampled at head and tail; fall through.
  }
  const match = requestBodyText.match(/"user_id"\s*:\s*("(?:\\.|[^"\\])*")/);
  if (!match) return null;
  try {
    return sessionFromUserId(JSON.parse(match[1]));
  } catch {
    return null;
  }
}

function claudeTurnFromHookState(sessionId) {
  const stateDir = process.env.CHIPTRACE_CLAUDE_TURN_STATE_DIR || '/monitor-state/claude-turns';
  try {
    const value = JSON.parse(fs.readFileSync(path.join(stateDir, `${sessionId}.json`), 'utf8'));
    return typeof value?.turn_id === 'string' && value.turn_id.trim() !== ''
      ? value.turn_id
      : null;
  } catch {
    return null;
  }
}
```

在 `scheduleFullTraceSubmit` 中，使用**有界身份副本**（最多 1 MiB）而不是事务 spool，
因为事务存在时请求正文只写入 spool：

```js
const anthropicSession = anthropicSessionFromBody(requestIdentityText || requestBodyText);
if (anthropicSession) {
  const trace = traceContext.trace || (traceContext.trace = {});
  trace.session_id ||= anthropicSession;
  trace.thread_id ||= anthropicSession;
  trace.conversation_id ||= anthropicSession;
  trace.session_identity_source ||= 'anthropic_metadata_user_id';
  const turn = claudeTurnFromHookState(anthropicSession);
  if (turn) {
    trace.turn_id ||= turn;
    trace.root_turn_id ||= turn;
    trace.turn_identity_source ||= 'claude_hook_prompt_boundary';
  }
}
```

`requestIdentityCapture` 在 `appendCaptureChunk` 中对 request 侧始终追加
（上限 1 MiB），并随 `scheduleFullTraceSubmit` 传入；不要使用未填充的
`requestCapture`，它在事务模式下为空。

## 大请求体：头部 + 尾部

交互式 Claude Code 的 `/v1/messages` 请求在真实会话中会超过 1 MiB（实测
1.67–2.60 MB），而 `metadata.user_id` 位于 JSON 末尾。只缓存前 1 MiB 会让这类
Wire 没有 session 标签，`inspect-session` 也无法归属。

网关因此同时保留：

- `requestIdentityCapture`：前 1 MiB；
- `requestIdentityTail`：最后 256 KiB（滚动窗口）。

`scheduleFullTraceSubmit` 用 `head + "\n" + tail` 组成
`requestIdentityText`，先尝试完整 `JSON.parse`，失败时用
`"user_id"\s*:\s*("(?:\\.|[^"\\])*")` 取出转义字符串，再解析两次。这样既覆盖
小请求，也能从大请求尾部取到身份，且不会为每个请求复制整个正文。

实测：重启后本机会话 `f4302b69-…`（1.72 MB）和另一会话 `839b4b0d-…`
（2.62 MB）的 Wire 都带上了 `session_id`；未重启前的同类记录仍保持为空，Raw
不重写。
