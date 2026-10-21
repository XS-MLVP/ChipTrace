# Claude Code + DeepSeek 接入

本目录提供 Claude Code（Anthropic Messages/`/v1/messages`）经 ChipTrace 采集所需
的 Hook helper 和配置样例。Claude Code 通过 `ANTHROPIC_BASE_URL` 指向 18084，模型可用
DeepSeek 的 Anthropic 兼容端点或上游聚合网关。

## 数据源与标签

| 数据 | 来源 | 关键标签 |
| --- | --- | --- |
| Wire | 18084 `/v1/messages` 原字节捕获 | `session_id`（`metadata.user_id.session_id`）、`turn_id`（prompt_id，网关从 Hook 状态回填） |
| Hook | SessionStart / UserPromptSubmit / PreToolUse / PostToolUse / Stop / SessionEnd | `session_id`、`prompt_id`、`tool_use_id`、`tool_name`、`tool_input`、`tool_response`、`permission_mode` |
| Tool | PostToolUse 派生的 `tool_execution` | `call_id=tool_use_id`、`status=success/error/cancelled`、`turn_id=prompt_id` |
| OTLP | 当前 Claude Code 2.1.304 + DeepSeek 仅导出 metrics | 不作为 Turn 级必需来源；不伪造 logs/traces |

Claude Code 没有原生 Turn ID。它的 **`prompt_id`** 是每个用户 Prompt 的稳定标识，
helper 用它作为 `turn_id`/`root_turn_id`，并写入
`turn_identity_source=claude_prompt_id`。Wire 侧由网关读取 Hook 状态文件回填同一
`turn_id`，因此 Wire、Hook、Tool 三方共享一个显式身份，不做时间或“最后一个 Turn”猜测。

## 安装 Hook helper

```bash
install -d -m 0755 ~/.local/libexec
install -m 0755 chiptrace-claude-hook.sh ~/.local/libexec/chiptrace-claude-hook
install -d -m 0755 /var/lib/chiptrace/claude-turn-state
```

在 Claude Code 的 `settings.json` 中把 [settings.hooks.example.json](settings.hooks.example.json)
的 `hooks` 合并进去，并按实际路径修改：

- `CHIPTRACE_GATEWAY_URL`：默认 `http://127.0.0.1:18084`
- `CHIPTRACE_INGEST_TOKEN_FILE`：默认 `/etc/chiptrace/ingest-token`
- `CHIPTRACE_CLAUDE_STATE_DIR`：默认 `/var/lib/chiptrace/claude-turn-state`；网关默认读取
  `/monitor-state/claude-turns`，部署时把两者指向同一个共享目录
- `CHIPTRACE_MODEL`：会话模型别名（例如 `deepseek-flash`）
- `CHIPTRACE_PERMISSION_MODE`：Claude 的 permission mode（例如 `bypassPermissions`）

Hook 是同步的；采集入口不可用或 Relay 没有 durable receipt 时会 fail-closed。`SessionStart`
还会要求 `model` 和 `permission_mode`，因此样例显式注入这两个会话级标签。

## 网关要求

18084 需要：

1. 捕获 `/v1/messages`（`server.js` 的 full-trace 路径已包含）。
2. 从请求体 `metadata.user_id` 解析 native session UUID，并写入 Wire `traceContext.session_id`。
3. 读取 Hook 状态目录中的 `turn_id`，写入 Wire `traceContext.turn_id/root_turn_id`，
   来源标记 `claude_hook_prompt_boundary`。

这些逻辑在 `relay_shell/server.js`；变更后重启 `router-v2-relay-shell`。

## 采集参数

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:18084
export ANTHROPIC_AUTH_TOKEN='<sub2api-key>'
export ANTHROPIC_MODEL=deepseek-flash
export CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT=1
claude --session-id <uuid> --dangerously-skip-permissions -p '<task>'
```

服务端要求 Sub2API 的 group 能路由 `deepseek-flash`；本机由 kxyai 账户提供该模型的
Anthropic 兼容入口。

## 验收

```bash
chiptrace inspect-session --input <sealed-segment-or-capture-dir> \
  --session-id <session-id> --projection-output /tmp/inspect-claude
chiptrace export-maas --input <sealed-segment> \
  --output <sample-root> --provider-code <provider> --platform anthropic \
  --session-id <session-id> --skip-incomplete
chiptrace verify-maas --input <sample-root>
```

`inspect-session` 对 Claude profile 要求 `wire + hooks`（Tool 由 PostToolUse 派生），
不再把 OTLP logs/traces 计为缺失来源；Codex 仍保持四源契约。
