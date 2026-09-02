# Stock Codex 接入

用户侧只运行未修改的 Stock Codex。管理员下发一个原生配置包：

| 文件 | 作用 |
| --- | --- |
| [managed_config.toml.example](managed_config.toml.example) | 安装为 `/etc/codex/managed_config.toml`，固定 18084 Provider、Responses、OTLP 和 25 次网络重试 |
| [requirements.toml.example](requirements.toml.example) | 安装为 `/etc/codex/requirements.toml`，固定 required lifecycle Hooks，并在 SessionStart 检查云端入口 |

将 `<CHIPTRACE_INGEST_TOKEN>` 替换为云端采集 Token，并由主机管理系统写入 Stock Codex 的
系统配置位置。业务凭据只通过 `CHIPTRACE_API_KEY` 环境变量提供，不写入配置或 Trace。
用户侧不部署任何 ChipTrace 程序或服务。

`managed_config.toml` 只固定模型网络与 OTLP 路由，`requirements.toml` 固定 required
Hook 并启用 `allow_managed_hooks_only`，避免用户或项目配置重复采集。下发后用
`codex --strict-config` 启动，字段不受当前 Stock Codex 支持时直接失败。

云端 `/models` 使用真实模型名 `gpt-5.6-sol` 返回版本化能力元数据，只将 `tool_mode` 固定为
`direct`。Stock Codex 使用 Provider 业务凭据访问 18084；网关完成业务鉴权后，以内部采集
凭据读取 Relay 目录。Stock Codex 因而能自动刷新目录，并在真实 Wire 中提供 JSON function
Tool Schema。模型身份仍以 Wire 与 Sub2API 路由事实为准，不能由目录内容代替。

配置完成后，用户的操作不变：

```bash
codex
```

一次可交付 Session 必须同时收到完整 Wire、OTLP tool result 和 start/end Hook。缺少任一
来源、字段冲突、工具输出截断或云端验收失败时，只保留 Raw，不进入采购 Release。
