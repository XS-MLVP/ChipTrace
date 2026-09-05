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
生命周期，且不覆盖用户已有 Hook。三类事实缺失或冲突时，云端保留 Raw，但拒绝进入采购
Release。

云端 `/models` 必须先验证真实 Provider 凭据，再为真实模型返回 `direct` function 工具目录。
Provider 使用 command auth，确保 Stock Codex 会刷新该目录。Tool Schema 只取模型实际收到的
Responses Wire；模型身份以 Wire 与 Sub2API 精确路由为准。

受管主机要求 Stock Codex 0.150 或更高版本，并使用 `--strict-config`。`otel.tool_result.max_bytes`
固定为 256 MiB；低版本不识别该字段时必须在首个 Turn 前失败，不能以默认 2 KiB 截断结果后
继续产生不可交付的 Session。云端仍以每条事件实际报告的 `output_truncated=false` 为准。

## 无管理员权限的测试

临时测试可以在独立 `CODEX_HOME` 中使用原生 `config.toml` 和 `hooks.json`，但这不是
`/etc/codex/requirements.toml` 的强制受管安装。通过 app-server `hooks/list` 检查九类
生命周期 Hook，必须同时满足 `enabled=true` 和 `trustStatus=trusted`。管理员审核具体
命令后，应在最终路径记录对应的 `hooks.state.<key>.trusted_hash`，并重新读取验证。

Hook 的 key 包含文件路径，hash 对应实际命令。移动配置目录或修改采集端口后必须重新
校验，不能复制旧的信任状态。`--strict-config` 只检查配置字段是否合法；用户级 Hook
即使显示 enabled，也可能因未受信任而跳过。真实测试必须在 Collector 中检查同一个
Session 的四源和 start/end 闭合，不能以 CLI 正常退出代替采集验收。

Stock Codex 0.153.4 的 `exec --json` 被 SessionStart Hook 前置拦截时，仍可能返回
退出码 0 和零 Token 的 `turn.completed`。前置拦截测试应验证零模型请求；正常采集测试
则应验证真实模型交互、工具结果以及 Collector 的会话完整性。
