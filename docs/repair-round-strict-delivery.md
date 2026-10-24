# 严格交付修复轮（local repair round）

目标：让本机 Codex 采集的数据达到 `delivery_ready=true`。
原则：只在**有证据**的层补标签；不按时间、名称或“最后一个 Turn”猜测归属，不改写历史 Raw。

## 本轮改动

### 生产者（codex-producer-0.163.0 源码树）

| 文件 | 改动 | 解决 |
| --- | --- | --- |
| `core/src/session/turn.rs` | `receiving_stream`、`stream_request` 增加 `codex.context_scope=turn` + `conversation.id` + `turn.id` | SSE 日志及其父 Span 可落到 Turn |
| `codex-api/src/endpoint/session.rs` | `execute_with` 增加 `process` | 共享 HTTP 客户端不能声明 Turn |
| `app-server/src/model_catalog.rs` | `model_catalog.list_models` 增加 `process` | 模型目录刷新 |
| `core-plugins/src/manager.rs` | `plugins_for_config`、`recommended_plugins_mode_for_config` 增加 `process` | 插件加载 |
| `core-plugins/src/loader.rs` | `load_plugins_from_layer_stack` 增加 `process` | 插件层加载 |
| `core/src/environment_selection.rs` | `environments.snapshot` 增加 `process` | 启动环境快照 |
| `ext/skills/src/host_service.rs` | `skills_for_config` 增加 `process` | 技能目录 |
| `thread-store/src/local/live_writer.rs` | `append_items` 增加 `process` | Rollout 持久化无 Turn 归属 |

SSE 的关键是 `ApiTelemetry` 在构造时捕获请求 Span，`on_sse_poll` 用
`sse_span.in_scope(...)` 重新进入；请求 Span 带上 Turn 后，日志自然获得可回溯身份。

### 采集器（ChipTrace）

| 改动 | 原因 |
| --- | --- |
| 新增 `ambient_records` 与 `ambient_producers` | 同机其他用户/旧版本 Codex 进程的遥测既不能算进本会话，也不能静默丢弃 |
| ambient 判定要求**具名生产者** | 没有 `service.name` 的记录仍然计入 gap，不能被豁免 |
| 生产者对所选 Session 有证据时，其未归属记录仍计入 gap | 防止用 ambient 掩盖真实缺口 |
| `encrypted_content` 按“存在性”比较 | 上游会对同一 reasoning item 重新加密，密文不是语义内容；其余字段仍须完全一致 |
| 净化正文允许 forwarded > stored | 仅当 `captureSanitization.bodyRedacted=true` 且保留 `responseBodyTextOriginalSha256` 时放宽 |

## 验证

真实两轮 Codex 会话 `01a16df9-e32c-7222-a5ed-8779f1da5d7b`（实现 CLI + 跑测试 + 执行命令）：

| 项 | 结果 |
| --- | --- |
| `delivery_ready` | **true** |
| source-context gap groups | **0** |
| `protocol_complete` / `runtime_complete` / `raw_bytes_complete` | 全部 true |
| Session/Turn | 1 epoch、2 Turn 闭合、0 incomplete |
| 工具配对 | 6/6 |
| ambient 记录 | `codex-app-server@0.162.1` 77、`codex-app-server@0.163.0-alpha.11` 88、`codex_cli_rs@0.154.0` 24 |
| MaaS 包 | 8 请求、454,664 bytes、SHA-256 `c9fc6522…`、`verify-maas` 退出 0 |
| `make cloud-test` | 退出 0（Rust 368 passed） |

样本目录：`records/chiptrace-samples/maas-codex-repair-01a16df9/`。

## 边界

- ambient 只统计**具名且从未引用本会话**的生产者；属主不明仍 fail-closed。
- 修复未放宽生命周期、工具、身份冲突等严格规则。
- 运行中的旧 `codex-app-server` 守护进程仍会持续上报 ambient 记录，不影响本会话交付，
  但若要彻底消除，需把守护进程刷新到同一构建。
- 本地安装的 `chiptrace` 已更新到本轮修复版本。
