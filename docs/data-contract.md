# 数据契约

## Raw Capture

云端新写入统一使用 `chiptrace.capture.v2`。权威记录只有以下类型：

| `recordType` | 来源 | 内容 |
| --- | --- | --- |
| `api_snapshot` | 18084 | Responses 请求/响应原字节、状态、SSE、传输结果 |
| `telemetry_batch` | OTLP/Hook 入口 | 原始 JSON envelope、字节数、SHA-256、转换统计 |
| `lifecycle_event` | Stock Codex | Session、Turn、中断、压缩和子代理生命周期 |
| `tool_execution` | Stock Codex OTLP | 真实工具参数、输出、状态、截断和耗时 |
| `evaluation` | 云端 evaluator | 测试、构建、搜索证据和最终验收 |

每条记录必须有稳定 `captureId`。同 ID 同字节为幂等重放，同 ID 不同字节为冲突。入口
不记录认证头、Cookie 或 API Key，也不在保存后重建正文。请求和响应正文必须满足：

```text
captured UTF-8 byte length == declared length
SHA-256(captured UTF-8 bytes) == declared SHA-256
truncated == false
```

OTLP/Hook 的原始 envelope 始终先保存。已知事件严格转换为 Capture；未知事件或字段错误
能归属 Session 时生成 `telemetry_incomplete`，无法归属时返回 400。两者都不能进入合格
Release。

Relay 的 `/capture` 和 `/captures` 只接收 `recordType=api_snapshot` 且来源非空的 Wire 记录。
显式 `version` 必须为 `chiptrace.capture.v2`；未携带版本的当前网关记录由 Wire adapter
规范化，并保留规范化前的字节哈希。Runtime、生命周期、评价、Telemetry 及历史生产者字段
出现在这两个入口时整条或整批返回 400，不能绕过对应的权威来源。历史字段仅由离线读取器
验证原始字节和哈希，不属于在线采集契约。

## 身份与关联

Stock Codex 已在 Responses 请求中提供：

- `session-id` 和 `thread-id`；
- `x-codex-turn-metadata` 中的 `session_id`、`thread_id`、`turn_id`、
  `root_turn_id`、`parent_thread_id` 和 `agent_name`；
- `traceparent` / `tracestate`；
- Responses、工具调用和结果中的 request ID、response ID 与 `call_id`。

网关将这些观察值写入 `traceContext` 和 `fieldEvidence`。同一字段出现不同值时写入
`fieldEvidenceConflicts`，不选择一个值掩盖冲突。Assembly 只执行以下精确 Join：

```text
Wire <-> OTLP/Hook       by session_id + turn_id / W3C context
model call <-> result    by call_id within the same runtime scope
Wire <-> Sub2API         by exact request ID
root <-> subagent        by parent_thread_id and observed lifecycle
response chain           by response_id / previous_response_id
```

不按时间邻近、模型名、正文相似度或 thread ID 猜测跨 Session 关系。

## 状态

以下事实分别保存：

| 状态 | 权威来源 |
| --- | --- |
| 模型完成、失败或取消 | Responses 协议终态 |
| 上游传输完成或错误 | 18084 转发器 |
| 客户端完整接收或提前关闭 | 18084 客户连接 |
| 工具调度是否返回结果 | `codex.tool_result.success` |
| `exec_command` / `write_stdin` 子进程状态 | Stock Codex 固定结果头中的退出码或运行中 Session ID |
| Session/Turn 闭合 | required lifecycle Hook |

SSE `[DONE]` 只是 framing，不代表模型成功。返回文本不能用于推断工具状态。
`output_truncated != false` 表示工具结果不完整。`codex.tool_result.success=true` 只证明工具
调度器成功返回结果，不代表子进程退出码为 0。ChipTrace 仅解析 Stock Codex 在 `Output:`
之前生成的固定进程结果头，并将其独立保存为 `process_outcome`；`Output:` 后的业务正文不能
改变任何状态。OTLP Span 状态使用有证据的语义结果，同时以独立属性保留 lifecycle、
dispatch 和 process 三类事实。

## Canonical

`project-interactions` 将一条显式 Stock Codex Session 投影为：

```text
interactions/
├── interactions/model-interactions.jsonl.zst
├── runtime/runtime-spans.jsonl.zst
├── links/interaction-links.jsonl.zst
└── manifest.json
```

- `ModelInteraction` 以一次 Responses 请求/响应为原子。
- `RuntimeSpan` 保存 task root、turn、agent 和真实工具执行。
- `InteractionLink` 保存精确父子与 call/result/execution 关系。

写出和复验时逐条执行 Draft 2020-12 JSON Schema。完整性分为
`artifact_valid`、`raw_bytes_complete`、`protocol_complete`、`runtime_complete`、
`root_complete` 和 `delivery_ready`；最后一项只在前五项全部通过时为 true。
`source_coverage` 另行证明所选 Session 同时存在 Wire、OTLP logs、OTLP traces 和 required
Hook；它不把 OTLP trace 重写成第二套 Runtime 真相，缺一路时云端采购验收直接失败。

## Tool Schema

采购工具定义只取自模型实际收到的 Responses Wire。每个被调用工具必须包含明确
`name`、`description` 和 JSON `parameters`。OTLP 结果可以通过相同 `call_id` 关联这份
定义，但不能生成、补写或改名。

三类事实必须保持分离：

```text
model_tool_call          模型真实发出的调用
tool_result_submitted    客户端后续回传给模型的结果
runtime_tool_execution   工具执行器真实执行及状态
```

外层 Code Mode 调用和内层执行都保留，通过父子 Link 表达；内层执行不会替换模型调用。

## Buyer v7

采购评分由 `chiptrace.assessment.v2` 表示，包含独立的 Capture 完整性、训练 readiness、
Buyer acceptance、语义证据和 Token。正式准入至少要求：

- 首条消息 role 合法，System Prompt 存在；
- 有效轮次不少于 10；
- 不同实际工具不少于 5，至少 2 个有效结果；
- 去掉 open tail 后 tool call/result 配对率 100%；
- 每个被调用工具有完整真实 Schema；
- 机器轮占比小于 25%；
- Session 明确闭合，模型/Provider 路由一致；
- `delivery_ready=true`、score 不低于 90、全部 hard gate 通过。

结构分数不证明任务语义正确。测试、构建、搜索引用、用户修正和最终验收作为独立
semantic reward 证据保留。

## Token

去重后分别统计：

- API input、cached input、cache write、output、reasoning 和 total Token；
- Tool definitions + 全部消息的规范化语料 Token；
- 监督输出 Token；
- 被排除的 base64 字节数。

缓存 Token 是 API 用量的一部分，不等于数据集规范化语料 Token。结算口径写入每条
Assessment 和 Release Manifest。

## 交付

`cloud-acceptance` 只处理指定 `session_id`，并要求来源为已提交的 complete Raw Archive。
输出包含内部 zstd Release、逐 Session Assessment、OTLP 树和采购 `tar.gz`。采购归档内
每行一个完整 UTF-8 JSON Session，Session 不跨包；Manifest 和 `SHA256SUMS` 绑定 Raw、
Release 和最终归档。

当前公开 Schema：

- `capture-v2.schema.json`
- `model-interaction-v1.schema.json`
- `runtime-span-v1.schema.json`
- `interaction-link-v1.schema.json`
- `assessment-v2.schema.json`
- `release-manifest-v1.schema.json`
- `buyer-package-v1.schema.json`
- `cloud-acceptance-v1.schema.json`
