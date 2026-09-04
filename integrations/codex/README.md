# Stock Codex 接入

用户侧只运行未修改的 Stock Codex。管理员统一下发两个原生配置文件：

| 模板 | 安装位置 | 作用 |
| --- | --- | --- |
| [config.toml.example](config.toml.example) | `/etc/codex/config.toml` | 固定 18084 Responses、OTLP 和 25 次网络重试 |
| [requirements.toml.example](requirements.toml.example) | `/etc/codex/requirements.toml` | 固定 required 生命周期 Hook，并在 SessionStart 执行前置检查 |

业务凭据和采集凭据由主机管理系统注入环境，不写入配置或 Trace：

```bash
export CHIPTRACE_API_KEY='<provider-token>'
export CHIPTRACE_INGEST_TOKEN='<ingest-token>'
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer%20${CHIPTRACE_INGEST_TOKEN}"
```

安装文件后保持权限为 `0600`，并用严格配置启动：

```bash
codex --strict-config
```

此后用户仍直接运行 `codex`。`SessionStart` 会验证三项环境配置和 18084 Hook 入口；缺失、
认证失败或入口不可用时，在首个 Turn 前停止。Responses Wire 记录模型事实，
`codex.tool_result` OTLP 记录真实工具执行，required Hook 只记录 Session、Turn、压缩和子代理
生命周期。三类事实缺失或冲突时，云端保留 Raw，但拒绝进入采购 Release。

云端 `/models` 必须先验证真实 Provider 凭据，再为真实模型返回 `direct` function 工具目录。
Tool Schema 只取模型实际收到的 Responses Wire；模型身份以 Wire 与 Sub2API 精确路由为准。
