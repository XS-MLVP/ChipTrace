# 交付验收矩阵

ChipTrace 将原始采集、轨迹组装、质量评分和采购交付拆成四个可独立复验的层。
每层只声明自己能证明的事实，不用传输完整性替代轨迹语义，也不用结构分替代任务
正确性。

## 分层结果

| 层 | 输入 | 输出 | 能证明 | 不能证明 |
| --- | --- | --- | --- | --- |
| Raw OSS | Collector sealed WAL | Segment、Manifest、Checkpoint | 字节、记录数、SHA-256、快照完整性 | Session 边界、工具语义、任务正确性 |
| Assembly | `complete` Raw 恢复目录 | 一行一个 canonical Session | 时间顺序、Response/Task DAG、去重来源、工具状态 | 模型供应商的密码学身份、用户任务是否正确 |
| Score | canonical Session | 三套质量结果和 buyer-v7 Gate | 结构门槛、失败原因、Token 分类、准入决定 | 真实感和业务正确性（需 evaluator evidence） |
| Release/Buyer | 通过评分的 Session | JSONL.zst、tar.gz、Manifest、SHA256SUMS | Session 原子分包、数量/Token/校验守恒 | 缺失原始事件的事后补造 |

## 采购 v6/v7 映射

仓库同时保留两个版本化 Profile，不能把不同合同的阈值混用：

| 规则 | buyer-v6 | buyer-v7 |
| --- | ---: | ---: |
| 有效交互轮次 | >=2 | >=10 |
| 真实 User -> Assistant 轮 | 至少 2（Session 定义） | 至少 2 |
| 结构化工具调用 | >=1 | >=5 |
| 不同工具名 | >=1 | >=5（严格执行 v7 文档“工具不重复”） |
| 有效工具返回 | >=1 | >=2 |
| 去尾配对率 | 100% | 100% |
| 机器轮 / user 轮 | <25% | <25% |
| System Prompt、首条 role、工具 schema | 必需 | 必需 |
| 模型 | GPT-5+、Claude-4.5+、Gemini-3+ | GPT-5.5+、合格 Claude、DeepSeek-v4+、GLM-5.2+、K3+；排除 Gemini/Haiku |
| 准入阈值 | 由命令指定 | 默认 score >=90 且全部 hard gate 通过 |

“不同工具名”是对用户提供 v7 文档中“调用的工具不重复”的保守解释。若采购方
确认只要求五个不同 call ID，应新增独立 Profile，不修改既有 v7 结果。

## 评分输出

每条 Assessment 同时保存：

- `capture_completeness`：身份、时间、usage、层级和终态采集情况；
- `buyer_acceptance`：结构分、全部 Gate、失败原因和 release decision；
- `semantic_quality`：测试、构建、搜索、用户修正、最终验收和 evaluator evidence。

`eligible` 的唯一判定为：

```text
all_required_gates_pass && score >= minimum_score
```

任何 Assembly 冲突、producer sequence 缺口/重复、工具状态机不闭合、DAG 环、
未解析父节点、工具 schema 缺失、非法工具参数或未配对结果都不能由高分抵消。工具
执行状态只从真实事件或返回字段读取；缺失状态为 `unknown`，不会被清洗为成功。
存在原生 runtime 时，`runtime_dag_integrity` 和 `inference_api_conservation` 也是独立
hard gate：前者拒绝 open/unresolved 节点，后者拒绝任一完成推理没有精确 API Capture。

## 当前线上样本复核

2026-08-28 的内部只读复核固定了 11 个 sealed Segment，共 699 条 Capture、
523,568,134 字节（约 499 MiB）。临时 FS 对象后端生成 `complete` Raw Checkpoint，
逐行校验 699/699，对象长度和 SHA-256 全部通过；归档恢复与 Assembly 成功。

Assembly 生成 18 条候选 Session，精确去重移除 5 条，最终评估 13 条；buyer-v7
`score >=90` 与 hard gate 通过数均为 0，平均分 48.46。评估集包含 85,549,669
API 总 Token，其中缓存输入 80,844,288；规范化语料 Token 为 1,594,776，准入
Token 为 0。13/13 未达到结构化工具门槛且缺少合格的真实结果状态，11/13 没有明确
任务终态，8/13 缺必填字段或 System Prompt。12/13 的去尾配对率已经是 100%，
因此主要缺口不是 WAL/OSS 拼接。完整证据见仓库外同级报告
`reports/oss-raw-archive-and-online-quality-20260828.md`。

这说明当前主要缺口在 Agent harness 和工具执行器事件，而不是 OSS 传输：

1. 任务开始时创建并贯穿 `task_session_id`，结束时发送 task/session end、cancel 或
   terminate；
2. 每次工具执行发送 call ID、完整 schema、参数、开始/结束、真实 success/error/
   cancelled/timeout 状态和返回；
3. 发送 compaction、retry、subagent spawn/join、用户修正和 evaluator evidence；生命周期
   事件必须保留 type、status、reason、occurred_at 和 event_id 等原始字段；
4. 用同一 reliable submitter 投递这些事件，和 18084 API snapshot 共享
   `sourceNamespace` 与 `task_session_id`。

隔离 v2 闭环使用 21 条 Capture 生成 1 条完整 Session，其中 15 条 Harness/
dispatcher 事件通过 Relay producer 入口提交并幂等重放。两条 producer stream
连续，5 个工具的 started/terminal 状态机全部闭合，包含 1 次真实失败结果；buyer-v7
得分 100，Raw lineage、采购包校验、发布幂等和逐对象 SHA-256 复验均通过。该结果
证明本地实现能力，不代表 18084 热服务已经接入 Agent harness 事件。

入口适配器另在隔离链路验证了本地 outbox 原子写入、重启恢复、20 次以上断连重试、
并发同 ID 幂等/冲突、永久错误留证和 Relay 不可用时业务响应 fail-open。一次真实
Sub2API 401 请求通过该适配器进入 Rust Relay/Collector 后，Capture v2 校验通过，
`task_session_id/root_session_id/goal_id/turn_id/agent_id` 和响应 request ID 均按来源
保留，`fieldEvidenceConflicts=[]`，Relay/Collector 记录数增加 1 且 pending 回到 0。

补齐事件后，现有 Raw/Assembly/Score/Release 链路可以直接复用；不需要重导出或把
历史字节拼成一个无限增长的 OSS 对象。

Codex 0.150+ 的生产者接入优先读取原生 `codex-rollout-trace` bundle。该入口能
直接保存模型 inference、dispatcher 工具、Code Mode、Terminal、compaction 和
子代理关系，避免从普通 rollout 的外层 `exec/wait` 反推内层工具。bundle 仍不能
替代 harness 的业务任务 start/end，也不能替代 18084/Sub2API 的 provider 路由证明；
三类证据共享 `task_session_id` 后才构成 `runtime-full` 采购候选。

固定版本 producer 补丁已在 Codex `rust-v0.150.0-alpha.9` 的精确 commit 上通过
应用校验。真实 `ToolRouter` 调用点测试证明 Registry 在 turn bundle 中落盘，
`codex-rollout-trace` 的 62 项测试全部通过。该验证证明 producer 代码路径可用，
不表示补丁已经部署到 18084 热服务。

## Codex 0.150 原生 canary

真实原生 bundle 包含 30 个连续事件、23 个 payload 和 281,959 字节镜像 Raw；
Runtime DAG 完整，open/unresolved 节点均为 0，包含 3 次 inference、2 个 Code Mode
cell 和 2 次真实 `exec_command`。原生单源基线为 buyer-v7 45 分：5 个有效轮次、
1 个真实 User -> Assistant 轮、4 次调用但只有 2 种工具，缺实际 Runtime Tool
Registry、可信 provider 证明和 harness task start/end。

另用一条同 request ID 的隔离 API fixture 和一条 Sub2API usage fact 验证多源 Join；
fixture 不是线上采集内容，不计入真实语料质量结论。该链路中
`provider_identity_attested` 与 `proxy_route_verified` 均为 true，Trace/模型/Token
冲突均为 0，buyer-v7 为 55 分。三次调用只结算一次，API 总 Token 为 49,470，
其中输入 48,989、缓存输入 41,216、输出 481、reasoning 239。工具去尾配对率和
Runtime DAG 通过，但缺 Registry、5 种工具和任务终态，仍被严格拒绝。这证明
API/rollout/Sub2API 精确关联工作正常，也证明生产者语义不完整时不会被清洗成
合格数据。

## 统一 Raw lineage 端到端 canary（2026-08-30）

使用当前 Rust 二进制重新生成的 21 条 Harness/API 事实与 7 条 Codex 原生
`codex-rollout-trace` 事实，通过同一个隔离 Collector 写入同一 sealed WAL；该样本
只用于契约和链路验证，不代表线上真实任务质量。

| 阶段 | 结果 |
| --- | --- |
| Collector durable ingest | 28/28 accepted，`attempts=28`、`captures=28`、`conflicts=0`、`rejected=0` |
| WAL payload audit | 1 个 sealed Segment，28 条，177,508 bytes；ledger、payload SHA-256 和 attempt 守恒通过 |
| Raw OSS archive/restore | `completeness=complete`；归档、逐条校验和恢复均为 28/28 |
| Gateway enrichment | 6 条 Sub2API usage 按精确 request ID 命中；其余 22 条因没有 request ID 保留为 `request_id_missing`，未补造账单事实 |
| Assembly | 1 条 canonical Session，`orphan_sessions=0`、`merge_divergences=0`，携带同一 Raw lineage |
| buyer-v7 Score | `score=100`、`hard_gate_pass=true`、`eligible=true`；10 个有效轮次、5 个真实 User -> Assistant 轮次、5 个不同工具、5 个有显式状态的结果，含 1 次真实错误 |
| Runtime/Task DAG | 原生事件 7 条，open/unresolved/unknown/unmapped/conflict 均为 0；Task start/end 均有事实 |
| Release/Buyer package | `verify-release --require-pass` 与 `verify-buyer-package` 均通过；Session 原子、UTF-8 JSONL、tar.gz、Token 和 SHA-256 守恒通过 |

该 canary 同时覆盖了 lineage 守恒回归：Assembly、Enrich、Release 各自拒绝将
lineaged 输入与 legacy 无 lineage 输入混入同一产物；全 lineaged 或全 legacy 的
既有路径保持兼容。三条混合输入测试与全工作区 185 条测试均通过，Clippy 在
`-D warnings` 下无告警。

失败尝试遵循同一证据边界：没有模型响应、provider 报告或精确 usage 的纯拒绝请求仍
进入 Session 的原始消息和 Capture 计数，但在
`model_evidence.non_attestable_api_snapshots` 中显式标记，不以缺失账单行伪造 Token
或 provider 证明；同一 Session 中其他成功请求的精确证明不会被这类失败尝试错误阻断。

## 多 rollout 真实闭环 canary v5（2026-08-30）

隔离环境使用新的入口 outbox、Relay 和 Collector，通过 `codex-run begin/finish` 在
同一显式任务下执行两个真实 Codex rollout。未修改或重启线上 `18084` 及生产
Relay/Collector。原始证据目录为
`/var/tmp/chiptrace-full-proof-v5-20260830-eMWhHz`。

| 阶段 | 结果 |
| --- | --- |
| Producer Capture | 139 条：14 API snapshot、3 lifecycle、98 rollout、24 tool execution |
| 任务边界 | 一个 `task_session_id`、两个 rollout 根；Harness 只生成一次 task start/end |
| Runtime DAG | `task_scoped_rollout_forest`；unknown/unmapped/open/unresolved/conflict 均为 0 |
| inference/API 守恒 | 14 个 completed inference 与 14 个 API Capture 通过精确 ID 全部配对 |
| buyer-v7 | 14 个有效轮次、2 个真实 User -> Assistant 轮、12 次调用、5 个不同工具、12/12 结果配对、1 次真实失败；100 分、全部 hard gate 通过 |
| 模型证据 | `provider=openai`、`model=gpt-5.6-sol`，Sub2API 路由证明完整 |
| Token | API input 225,400，其中 cached input 211,712；output 3,054；reasoning 1,435；normalized corpus 17,369；supervised output 2,634 |
| Raw lineage | sealed WAL 139 条、6,697,716 bytes；Archive/Verify/Restore、记录数与 SHA-256 全部通过 |
| Buyer package | UTF-8 JSONL + tar.gz，`lineage_status=complete`，Release 与采购包验证通过 |

当前二进制已从 v5 的 `raw-restored` 重新执行 Enrich、Assembly、Score、Release 和
Buyer Package，结果仍为 100 分、14/14 守恒和 1/1 eligible。直接跳过 Enrich 的
对照组为 95 分并仅失败于 `model` Gate，证明缺少 Sub2API provider 路由证据时不会
被模型名称字符串误放行。

前一轮隔离验证曾出现 11 个 completed inference 只有 10 个 API Capture，buyer-v7
因此被新守恒 Gate 拒绝。根因是入口容器仍运行旧 direct-to-Relay 进程，没有加载已
落盘的入口 outbox 代码。v5 使用新隔离入口后 `accepted/localDurable/durable=14/14/14`，
pending/processing/failed/conflict/rejected 全为 0。这一对照证明守恒 Gate 能暴露真实
漏采，也证明 Assembly、Score 和 Release 无需通过伪造或近似关联修补数据。

## 正式交付门槛

正式 buyer 包必须满足：

- Raw Checkpoint `completeness=complete`，并在 Release/Buyer Manifest 中携带
  `lineage_status=complete`；
- `verify-release --require-pass` 成功，所有 Session 的 buyer-v7 score >=90；
- `verify-buyer-package` 成功，UTF-8 JSONL、Session 原子、Token/记录数/SHA-256
  守恒；
- 正式采购包发布到 `deliveries/<release_id>/COMMIT.json`，`verify-published` 通过，
  消费端不通过 LIST 推断完整性。

没有 Raw lineage 的历史 Release 可以用 `--allow-legacy-lineage` 迁移，但会标记
`legacy_unbound`，默认验证器和正式交付流程拒绝该包。
