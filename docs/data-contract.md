# 数据与评分契约

## Capture

Collector 接收 `schemas/capture-v1.schema.json`。必需字段为稳定
`captureId`；完整采集应同时提供：

- 原始 request/response body、HTTP 状态、错误与截断标志；
- `sourceNamespace` 和实际 provider/model；
- `session_id`、`root_session_id`、`parent_session_id`、`goal_id`、
  `turn_id`、`agent_id`、`branch_id`、`previous_response_id`；
- Session start/end、cancel、retry、compaction、subagent spawn/join 等事件；
- 流式 SSE 原文或完整聚合响应；
- 原生 usage 与缓存 Token；
- 测试、构建、搜索、用户修正、最终验收和 evaluator 的真实证据。

Collector 保存所有响应状态。认证头、Cookie 和 API Key 在进入 WAL 前删除；
正文按敏感原始数据管理，不自动改写。

## Canonical Session

Assembly 输出 `schemas/session-v1.schema.json`，一行一个完整 Session。主要
字段如下：

| 字段 | 说明 |
| --- | --- |
| `trajectory_id` / `session_id` | 稳定轨迹与任务 Session 标识 |
| `provider` / `model` | 捕获到的模型字段及推断 provider |
| `system_prompt` | Agent 角色与行为约束 |
| `tools` | name、description、parameters、schema hash/version |
| `messages` | system/user/assistant/tool 的真实时序 |
| `usage` | 实际 API Token 与缓存 Token 聚合 |
| `meta.capture_dag` | response 链、状态、根、尾、环和缺失父节点 |
| `meta.task_dag` | root/subagent 关系和可拆分子轨迹 |
| `meta.trace` | root/parent/goal/turn/agent/branch 标识 |
| `meta.model_evidence` | 请求与响应模型一致性及证明范围 |
| `meta.evaluation_evidence` | 测试、构建、搜索、验收和 evaluator 证据 |

每个工具定义包含 `schema_hash` 和 `schema_version`。来源没有版本时，Assembly
使用 `sha256:<schema_hash>` 作为内容寻址版本。每次工具调用包含
`execution_status`，工具返回保留 `status`、`is_error` 与原始内容。

模型字段一致性不等于供应商身份认证。若采集入口不能提供可信 provider
证明，评分会输出 `model_attestation_missing`，不得宣称已证明模型来源。

## 三类质量结果

每条 Session 同时保留三类独立结果：

1. `capture_completeness`：身份、时间、usage、层级和闭环是否被采到。
2. `buyer_acceptance`：采购标准的确定性硬门槛、分数和失败原因。
3. `semantic_quality`：测试、搜索证据、用户修正和 evaluator reward。

采集完整性不能替代采购验收，结构分不能替代任务正确性。
`semantic_quality` 只接受带来源的 0–1 reward，或对已采集证据中的明确
pass/fail、0–1 score 求平均；未知状态不参与计算。

## 版本化验收

| 规则 | buyer-v6 | buyer-v7 |
| --- | ---: | ---: |
| 有效轮次 | ≥2 | ≥10 |
| 结构化工具调用 | ≥1 | ≥5 |
| 不同工具名 | ≥1 | ≥5 |
| 有效工具返回 | ≥1 | ≥2 |
| 去尾配对率 | 100% | 100% |
| 机器轮 / user 轮 | <25% | <25% |
| System Prompt | 必需 | 必需 |
| 完整 Tool Schema | 必需 | 必需 |
| 首消息 role | system/user | system/user |

`buyer-v6` 对应仓库外采购文档 v6.0。`buyer-v7` 对应用户提供的 v7.0：
GPT-5.5+、合格 Claude、DeepSeek v4+、GLM 5.2+、K3+，排除 Gemini 和 Haiku。
规则以 profile 固化，不能用同一个硬编码版本覆盖不同采购合同。

有效轮次由实质 user→assistant 交互与已配对 assistant→tool→result 相加。
`heartbeat`、`cron`、`no_reply` 优先读取显式 `meta.turn_kind`，缺失时使用
确定性文本规则。最终 assistant 消息中的未返回调用可标记 open tail，但完整
Release 仍要求 Session 有明确终态且不悬停在工具调用。

## 分数与准入

100 分结构权重：

| 项目 | 分值 |
| --- | ---: |
| 必填字段、role、首 role、System Prompt | 20 |
| 有效轮次 | 15 |
| 结构化工具调用与有效返回 | 15 |
| 完整 Tool Schema | 15 |
| 工具配对 | 15 |
| 机器轮比例 | 10 |
| 模型范围 | 5 |
| Session 闭环 | 5 |

`eligible = all_required_gates_pass && score >= minimum_score`。分数不能补偿任何
硬门槛失败；默认准入阈值为 90。消息合并分歧、工具 Schema 冲突、Trace
冲突、response DAG 环/缺失父节点以及 task DAG 不完整统一进入
`assembly_integrity` hard gate。

`chiptrace score` 的输出文件和 Release 的 `reports/assessments-part-*.jsonl.zst` 使用
`schemas/assessment-v1.schema.json`，逐条给出 Gate、观测值、期望值、失败原因、
三类质量结果和 Token。`release_decision=eligible` 仅在全部 hard gate 通过且
分数达到阈值时产生。

## 去重

- 精确去重指纹覆盖 System Prompt、Tool Definitions 和全部 Messages。
- 同一 trajectory_id 的连续消息子序列只保留最长版本。
- 同一 trajectory_id 出现无法互为连续子序列的候选时整组拒绝，并写入
  `reports/divergent-sessions.jsonl.zst`。
- Manifest 记录输入、解析失败、精确重复、子集、冲突、已评分和准入数量，
  并校验守恒。

## Token

Manifest 同时报告：

- `api_input_tokens`；
- `api_cached_input_tokens`；
- `api_cache_write_tokens`；
- `api_output_tokens` 与 `api_reasoning_tokens`；
- `api_total_tokens`；
- `normalized_corpus_tokens`；
- `supervised_output_tokens`。

规范化语料 Token 使用 `o200k_base`，范围为实际调用工具的 Definition 与全部
Messages。显式 base64 字段和 `data:*;base64,...` 载荷替换为占位符并记录
排除字节数。API Token 表示真实调用消耗；规范化语料 Token 表示去重后数据量，
两者不可互换。
