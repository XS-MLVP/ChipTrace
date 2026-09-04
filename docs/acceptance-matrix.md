# 验收矩阵

本文只记录当前云端主线。需要在用户主机部署 ChipTrace 程序的入口不属于产品能力，
也不作为验收证据。

## 产品门槛

| 验收项 | 实现 | 通过条件 |
| --- | --- | --- |
| Raw 完整性 | WAL、sealed Segment、OSS Manifest/Checkpoint | complete；逐对象和逐行 SHA-256 通过 |
| Wire 完整性 | 18084 原字节 Capture | 请求/响应长度与 SHA 一致；Responses 有协议终态 |
| Session 身份 | Stock Codex headers、OTLP、required Hook | 显式 `session_id`；start/end 闭合；无冲突 |
| Runtime | `codex.tool_result` + lifecycle | 输出未截断；调度状态明确；Shell 进程结果独立；无 open/conflict span |
| 调用关联 | ModelInteraction、RuntimeSpan、InteractionLink | call/result/execution 精确配对；内部父引用 100% |
| Tool Schema | Responses Wire direct function tools | 每个被调用工具有 name、description、parameters |
| 模型路由 | Wire + Sub2API usage | request ID 精确匹配；模型和 Provider 一致 |
| Buyer v7 | `assessment.v2` | 有效轮次 >=10；工具 >=5；配对率 100%；机器轮 <25% |
| Release | `cloud-acceptance` | `delivery_ready=true`；score >=90；全部 hard gate 通过 |
| 采购包 | `verify-buyer-package` | 1 Session/JSONL line；UTF-8；tar.gz；SHA/Token 守恒 |

## 隔离闭环

`chiptrace self-test` 使用确定性 Responses、OTLP、Hook 和 Sub2API fixture，验证实现逻辑，
不冒充真实用户数据。当前预期结果：

| 指标 | 预期 |
| --- | --- |
| Relay/Collector | attempt 守恒，pending/inflight 为 0 |
| Raw | Archive、Verify、Restore 全通过 |
| Canonical | Schema 全通过，`delivery_ready=true` |
| OTLP | 1 个 root，内部父引用解析率 100% |
| Buyer v7 | 10 个有效轮次、5 个不同工具、5 份完整 Schema、配对率 100% |
| Release | score 100、hard gate 全通过、1/1 eligible |
| Buyer package | UTF-8 JSONL tar.gz 与 SHA-256 复验通过 |
| Cloud acceptance | 七个阶段 Manifest 均有 SHA-256，复验通过 |

负例必须 fail-closed：created + `[DONE]`、SSE error + `[DONE]`、模型 completed + 客户端
关闭、缺 lifecycle root、缺内部 parent、未知 OTLP、工具结果截断、身份元数据冲突、混合
Session 输入以及缺 Tool Schema。

## 真实 Canary

生产部署前必须使用未修改的 Stock Codex 和普通 `codex` 命令完成一条自然长任务。该任务
必须经隔离 18084、Relay、Collector、OSS Raw 和 `cloud-acceptance`，且满足上表全部条件。
Stock Codex Session 以 Hook 顺序为边界；最新 `SessionStart` 必须有后续 `SessionEnd`，历史终态、
`response.completed`、`Stop` 和 OTLP `conversation_starts` 均不能代替该终态。

2026-09-04 已使用未修改的 Stock Codex `0.152.0-alpha.7.2` 完成隔离云端 canary，并用当前
源码从已提交 Raw Archive 重新验收：

| 指标 | 结果 |
| --- | --- |
| Session | `01a06b4d-d092-7511-8179-9505e97c137a` |
| Raw | 266 条；60,236,267 bytes；9 个 sealed Segment |
| Wire / usage | 30 条精确关联的 Sub2API usage evidence |
| 工具 | 9 个不同工具；9 份完整定义；result/execution 配对率 100% |
| Runtime / OTLP | `delivery_ready=true`；1 个 root；60/60 内部父引用解析 |
| Buyer v7 | 29 个有效轮次；score 100；hard gate 全通过；1/1 eligible |
| 交付 | UTF-8 JSONL `tar.gz`、Manifest 和 SHA-256 复验通过 |

该结果证明当前源码的云端主线可生成合格产物。隔离结果不能代替线上状态；生产可用性必须
另外满足 18084、Relay、Collector 健康、attempt 守恒和真实 Stock Codex smoke 通过。

## 历史数据

历史数据可以重放现有真实字段。只有原始 Wire、Stock Codex OTLP/Hook 或其他同源运行时
证据仍存在时，才能通过精确 Join 补齐。缺少原始请求字节、生命周期、真实工具结果或
Schema 的历史 Session 保持 partial；不能通过清洗推断成合格数据。
