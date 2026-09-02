# 架构

ChipTrace 只维护一条生产数据路径：

```text
Stock Codex
  ├─ OpenAI Responses ───────────────┐
  ├─ OTLP JSON logs/traces ─────────┼─> 18084 Cloud Gateway
  └─ required lifecycle Hooks ──────┘          │
                                                v
                                    Rust Relay -> WAL -> OSS Raw
                                                │
                                                v
                                       cloud-acceptance
                                                │
                         ┌──────────────────────┴───────────────────┐
                         v                                          v
              Buyer JSONL tar.gz                           OTLP / Langfuse
```

用户主机只运行未修改的 Stock Codex 和系统下发的原生配置。采集、可靠存储、
轨迹组装和采购验收全部在云端完成。Langfuse 是可选展示层，不是 Raw 事实源或采购准入器。

## 权威事实

| 事实 | 来源 |
| --- | --- |
| 请求、响应、SSE、工具定义、模型调用、结果回传 | 18084 Responses Wire |
| 工具真实参数、输出、成功失败、截断和耗时 | Stock Codex `codex.tool_result` OTLP log |
| Session、Turn、中断、压缩和子代理生命周期 | Stock Codex required Hook |
| 模型路由、Provider 和 API Token | Sub2API usage log |

入口保留每个 HTTP envelope 的原始 UTF-8 字节、长度和 SHA-256。Canonical 只通过
`session-id`、`thread-id`、`x-codex-turn-metadata`、`call_id`、request ID 和
`traceparent` 精确关联。不同来源冲突、未来事件无法解析、工具输出截断或任务未闭合时，
Raw 继续保留，但 Session 为 incomplete。

## 工具定义

云端 `/models` 为真实模型名 `gpt-5.6-sol` 返回版本化模型能力，并将 `tool_mode` 固定为
`direct`。18084 网关验证 Provider 业务凭据，再用内部采集凭据读取 Relay 目录；业务凭据
不会传给 Relay。Stock Codex 因而在真实 Responses 请求中发送 JSON function tools 和完整
`parameters`；这份 Wire 是 Tool Schema 的唯一依据。运行时结果只能关联已有模型调用，
不能把内层执行改写为另一个模型调用。

## 完整性

以下条件相互独立，任何分数都不能补偿硬失败：

```text
Raw committed
  AND raw bytes complete
  AND Responses protocol complete
  AND runtime complete
  AND Session root complete
  AND exact parent/call links complete
  AND Buyer v7 hard gates pass
  AND score >= 90
  = delivery ready
```

成功、失败、取消、重试和 open tail 都保留。Responses `[DONE]` 只表示传输 framing 结束；
模型终态、上游传输状态和客户端交付状态分别记录。

## 可靠性

18084 的 Wire Capture 先写云端网关磁盘 outbox，再异步送入 Rust Relay。OTLP 和 Hook 在
Relay durable ACK 后返回。Relay 和 Collector 使用确定性 Capture ID、WAL、ledger、重启
恢复、批量投递和有界背压；OSS 只接收 sealed Segment，并以 Manifest + Checkpoint 提交。

纯云端模式不能保证客户端断网后补发尚未到达云端的事件。因此 required `SessionStart`
在采集入口不可达时阻止任务开始；运行中缺失的 Session 保留作取证，但不会进入 Release。
