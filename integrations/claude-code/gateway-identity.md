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
function anthropicSessionFromBody(requestBodyText) {
  if (typeof requestBodyText !== 'string' || requestBodyText.trim() === '') return null;
  try {
    const body = JSON.parse(requestBodyText);
    const userId = body?.metadata?.user_id;
    if (typeof userId !== 'string') return null;
    const parsed = JSON.parse(userId);
    const session = parsed?.session_id;
    if (typeof session !== 'string') return null;
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(session)
      ? session
      : null;
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
