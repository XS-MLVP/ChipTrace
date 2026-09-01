# 交付验收矩阵

> 本文中 `codex-run`、patched Codex、Harness 与 bundle canary 仅记录历史兼容验证，
> 不代表当前生产接入。当前唯一生产验收路径是 Stock Codex + Plugin + Wire；历史 100 分
> 不能替代真实 Stock Codex canary。

ChipTrace 将原始采集、轨迹组装、质量评分和采购交付拆成四个可独立复验的层。
每层只声明自己能证明的事实，不用传输完整性替代轨迹语义，也不用结构分替代任务
正确性。

## 分层结果

| 层 | 输入 | 输出 | 能证明 | 不能证明 |
| --- | --- | --- | --- | --- |
| Raw OSS | Collector sealed WAL | Segment、Manifest、Checkpoint | 字节、记录数、SHA-256、快照完整性 | Session 边界、工具语义、任务正确性 |
| Assembly | `complete` Raw 恢复目录 | 一行一个 canonical Session | 时间顺序、Response/Task DAG、去重来源、工具状态 | 模型供应商的密码学身份、用户任务是否正确 |
| Score | canonical Session | 三套质量结果和 expanded Profile Gate | 结构门槛、失败原因、Token 分类、准入决定 | 真实感和业务正确性（需 evaluator evidence） |
| Release/Buyer | 通过评分的 Session | JSONL.zst、tar.gz、Manifest、SHA256SUMS | Session 原子分包、数量/Token/校验守恒 | 缺失原始事件的事后补造 |

本文 2026-08-30 及更早历史结果中写作 `buyer-v7` 的口径，现冻结并正式命名为
`buyer-v7-codex-runtime-expanded`。这些分数只表示 expanded Session 采购结构验收，
不表示 OpenAI wire 字节完整性；新产物统一写正式名称。

## 采购 v6/v7 映射

仓库同时保留两个版本化 Profile，不能把不同合同的阈值混用：

| 规则 | buyer-v6 | buyer-v7-codex-runtime-expanded |
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
- `readiness`：独立的 `delivery_ready`、`training_ready` 与训练交互证据；
- `buyer_acceptance`：结构分、全部 Gate、失败原因和 release decision；
- `semantic_quality`：测试、构建、搜索、用户修正、最终验收和 evaluator evidence。

`eligible` 的唯一判定为：

```text
all_required_gates_pass && score >= minimum_score
```

任何 Assembly 冲突、producer sequence 缺口/重复、工具状态机不闭合、DAG 环、
未解析父节点、工具 schema 缺失、非法工具参数或未配对结果都不能由高分抵消。工具
执行状态只从真实事件或返回字段读取；缺失状态为 `unknown`，不会被清洗为成功。
存在 Stock rollout 时启用 `runtime_dag_integrity`；来源另有显式 inference ID 时再启用
`inference_api_conservation`。前者拒绝 open/unresolved 节点，后者拒绝任一完成推理没有
精确 API Capture。

## Stock Codex 主链 canary（2026-09-01）

使用未修改的 Stock Codex、普通 `codex` 命令、Plugin 本地 outbox 和隔离 Wire 入口完成
真实代码任务。该结果验证当前源码，不表示生产 `18084` 已升级：

| 项目 | 结果 |
| --- | --- |
| Raw | 194 条 Capture，18 次 Responses 交互；原始字节、协议终态和 SHA-256 完整 |
| Canonical | 18 个 ModelInteraction、43 个 RuntimeSpan、182 个 Link；16/16 模型调用有结果且有真实执行 |
| Runtime Gate | 171 个 Stock rollout 源事件；1 个 Root，open/unresolved/conflict 均为 0 |
| OTLP | 61 个节点，60/60 内部父引用解析，单根树验证通过 |
| Assembly | 1 个 Session，`merge_divergences=0`，去尾工具配对率 100% |
| Buyer v7 | 65 分，`eligible=false` |

Buyer 只剩三项真实失败：只有 1 次人类 User -> Assistant 交互；expanded 内层 Runtime
工具没有采购级完整 Schema；网关没有提供可验证的上游 provider evidence。模型可见工具
只有 4 种，也不满足采购方 5 种工具要求。这些缺口不能通过清洗或改名补造。

Stock rollout 的 Buyer Runtime Gate 直接读取 Canonical ModelInteraction/RuntimeSpan/Link
完整性结果，评分器同时校验摘要来源；旧 bundle DAG 不能冒充 Stock Canonical 结果。

## 历史线上样本复核（2026-08-28）

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

该批数据形成于 Stock Plugin 主链上线前，只包含代理可见的模型 Wire。若原生产主机仍
保留 rollout，可以用当前 importer 精确回填；否则只能保留为 API-only 历史数据，不能
补造 Session、工具执行、Schema 或 provider 身份。

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

现有 Raw/Assembly/Score/Release 链路可以直接复用，不需要重新导出 Wire 或把历史字节
拼成一个无限增长的对象。patched bundle 只用于历史兼容回放，不是当前生产依赖。

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
既有路径保持兼容。三条混合输入测试与全工作区 186 条测试均通过，Clippy 在
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

## 18084 在线 runtime-full v2（2026-08-30）

真实任务通过 18084 产生 API 快照，patched Codex producer 提供原生 rollout，Harness
提供显式任务边界。生产服务未切换；producer 事件经隔离兼容 Relay durable 投递，随后
从生产 Collector sealed Segment 提取同一 `task_session_id`，在临时 Collector 中重新
校验封存并完成 Raw Archive/Restore。

| 阶段 | 结果 |
| --- | --- |
| Capture | 249 条：24 API snapshot、3 lifecycle、166 rollout、56 tool execution |
| Sub2API 精确关联 | 24/24 命中 `client:<response x-client-request-id>`；provider 为 OpenAI，upstream model 为 `gpt-5.6-sol` |
| Runtime/Task DAG | 222 个原生事件；24/24 completed inference 与 API snapshot 守恒；open/unresolved/unknown/unmapped/conflict 均为 0 |
| buyer-v7-codex-runtime-expanded | 30 个有效轮次、2 个真实 User -> Assistant 轮、28 次调用、5 个不同工具、28/28 配对、1 次真实失败；100 分，全部 hard gate 通过 |
| Token | API 总量 522,626，其中缓存输入 452,864；规范化语料 37,342；监督输出 6,663 |
| Raw lineage | 1 个 sealed Segment、249 条、14,209,890 bytes；Archive/Verify/Restore 后 SHA-256 逐字节一致 |
| Release | 1/1 eligible；`verify-release --require-pass` 与 `verify-buyer-package` 通过，Buyer tar.gz 为 1,796,555 bytes |

该结果证明生产者补齐后，现有 Relay、Collector、Raw、Assembly、Score 和 Release 可以
形成符合 expanded Profile 结构门槛的在线闭环。Assessment 仍保留
`model_attestation_missing` 警告：Sub2API 路由和 provider 观察足以通过当前结构规则，
但不等同于供应商密码学身份签名。该 Session 也没有带分值的 evaluator evidence，
因此 100 分只表示确定性结构验收通过，不证明任务语义正确性。

## ModelInteraction 双轨回放（2026-08-30）

当前实现从上述在线 v2 和多 rollout v5 的已提交 Raw lineage 重新生成
ModelInteraction、RuntimeSpan、精确 Link、Session、Release 和 Buyer Package：

| 样本 | Wire | Runtime | expanded Session |
| --- | --- | --- | --- |
| v5 | 14 个 Responses 交互；12 个模型 `exec`；模型工具名只有 1 个 | 45 个 span，含 1 个 Task Root；44/44 内部父节点已解析 | 外层 12 个 `exec` 全部保留，采购投影统计 12 个内层执行；14 个有效轮次、100 分 |
| 在线 v2 | 24 个 Responses 交互；22 个模型 `exec`；模型工具名只有 1 个 | 81 个 span，含 1 个 Task Root；80/80 内部父节点已解析 | 外层 22 个 `exec` 全部保留，采购投影统计 28 个内层执行；30 个有效轮次、100 分 |

两批历史 Capture 都没有保存请求 body 的原始 UTF-8 字节，因此
`raw_bytes_complete=false`、`delivery_ready=false`；响应原始流、协议终态、未知 item
和 runtime 证据仍可恢复。该失败是历史采集事实，不通过重新序列化修补。M0 正向
canary 保存请求/响应字节、长度、SHA-256、三个独立状态、Task Root、精确 Link 和
runtime 结果，并通过六项完整性硬门槛。

两批新 Release 和 Buyer Package 均使用正式 Profile 名、1/1 eligible 并通过复验；
旧 `buyer-v7` Release/Buyer Package 也能以只读别名复验。Rust 全量测试、Clippy
`-D warnings` 和闭环 self-test 通过。

## Responses M0 真实闭环（2026-08-31）

独立端口 `18088/3131/3130` 使用统一 Codex producer 完成一个两阶段真实任务。生产
`18084` 未修改或重启。Raw Archive ID 为
`chiptrace-m0-function-v1-r2-20260831`。

| 阶段 | 结果 |
| --- | --- |
| Raw | 6 个 sealed Segment、785 条、36,237,461 bytes；Archive/Verify/Restore 逐对象、逐行通过，重放为幂等成功 |
| Wire | 21 个 Responses streaming 交互；原始请求/响应字节、长度、SHA-256 和协议终态 21/21 完整，`delivery_ready=true` |
| Runtime | 78 个 span、1 个 Task Root、77/77 内部父引用解析；19/19 模型调用有结果和真实执行 |
| 路由 | 21/21 Sub2API usage 按响应 client ID 精确关联；`provider=openai`、`model=gpt-5.6-sol` |
| Buyer | 33 个有效轮次、2 个真实 User -> Assistant 轮、31 次调用、5 个不同工具、31/31 配对、21 个有效返回、1 次真实失败；100 分且全部 hard gate 通过 |
| OTLP | 99 个 span、1 个根、98/98 内部父引用解析，缺失父节点为 0 |
| Token | API 总量 365,307，其中缓存输入 319,232；规范化语料 23,254；监督输出 6,261 |
| Buyer package | 1/1 eligible；UTF-8 JSONL + tar.gz 为 1,231,411 bytes，SHA-256 为 `8c46174efb698e87385004ba0ccf38076e3ddd9f4b27c02e4434f6be8f57b755` |
| 回归 | Rust 210/210、Clippy、格式、self-test 和入口 outbox 8/8 通过；25 次网络尝试在第 25 次 durable ACK 后清空队列 |

首次 Archive 在一个长流结束前约 51 秒提交，因此只含 20 个 API Snapshot；该流结束后
7 ms 进入本地 outbox、18 ms 获得 Relay durable ACK、26 ms 提交到 Collector。根因是
封存时仍有请求在途，不是 outbox 重试延迟。纳入第 6 个 sealed Segment 后，21/21 守恒
恢复。该 Session 没有带分值的 evaluator evidence，因此 Buyer 100 分仍只代表结构
验收通过，不代表语义奖励可用。

验收后，生产 Collector/Relay 滚动到 revision `209d2a5`，入口 `18084` 未重启。
升级后一个真实 API-only Responses 流得到 `raw_bytes_complete=true` 和
`protocol_complete=true`；由于该探针没有 lifecycle/runtime 生产者，验证器按预期以
`root_complete=false`、`runtime_complete=false` 拒绝交付，未将 Wire 完整性冒充为
完整任务 Session。

## Stock Codex 生产闭环（2026-09-01）

生产 `18084`、Relay 和 Collector 保持 revision `68ab122`，使用未修改的
`codex-cli 0.152.0-alpha.7.2`、普通 `codex exec`、`0.6.0` Plugin 和常驻
`codex-agent` 完成真实只读 canary。未使用 Harness、Registry、patched Codex、bundle
或自定义启动器。Session ID 为 `01a05b3e-71bf-7d30-9df7-8b06441d21b1`，Langfuse
Trace ID 为 `073f59de062830b6bebfbb14d4b1e0c9`。

| 阶段 | 结果 |
| --- | --- |
| Raw | 57 条 Capture：6 条 Wire、48 条 rollout 原行、3 条生命周期事件；Hook 与入口 outbox 均清空，Relay/Collector 守恒，重试、冲突和永久失败增量均为 0 |
| Wire | 6/6 Responses streaming 交互保留原始请求/响应字节、长度和 SHA-256；Raw 与协议终态均完整 |
| Runtime | 11 个 span、1 个 Turn Root；5/5 模型 `exec` 同时有回传结果和真实执行；5 个 CommandExecution 中 1 个真实失败、4 个成功 |
| 完整性 | `artifact_valid`、`raw_bytes_complete`、`protocol_complete`、`runtime_complete`、`root_complete`、`delivery_ready` 全部为 true |
| OTLP | 17 个 span、1 个根、16/16 内部父引用解析；1 个 AGENT、6 个 GENERATION、10 个 TOOL 已落入 Langfuse，失败命令保持 `failed` |
| Token | 输入 97,388、缓存输入 56,832、输出 776、reasoning 344、API 总计 98,164；Langfuse 与 rollout 逐项一致 |
| 训练口径 | Session 闭合并包含真实 User -> Assistant 交互，`delivery_ready=true`、`training_ready=true` |
| Buyer | 50 分，`eligible=false`；6 个有效轮、1 种模型工具、Stock `exec` custom grammar 缺 JSON parameters schema，且该样本未做 Sub2API provider 富化 |

入口升级时关闭正文脱敏，并将历史队列分为 1,790 条可持久化记录和 287 条永久失败证据；
永久失败记录保留在 `failed`，没有重新序列化或伪造 Raw。该 canary 同时验证
`codex-agent` 同一 state root 单写和 rollout 追加期间 checkpoint 推进：运行日志没有
`Database already open`、越界或截断误报。普通 Stock Codex 已经自动形成可训练完整
Trace；Buyer 准入仍由真实长任务自身的轮次、工具多样性、provider 证据和采购 schema
要求决定。

## Stock Codex 多轮真实审计（2026-09-01）

使用当前 `0.6.0` 源码只读回放生产 sealed Raw 中 Session
`01a05a92-c0ef-7422-b152-afb145d12cd8`。审计没有修改或重启 `18084`、Relay、Collector
和运行中的 `codex-agent`。

| 阶段 | 结果 |
| --- | --- |
| Raw/Wire | 657 条唯一 Capture；55/55 Responses streaming 原始字节、长度、SHA-256 和协议终态完整 |
| Runtime | 227 个 RuntimeSpan；52/52 模型工具调用均有回传结果和真实执行；173 个内层执行中 162 成功、11 失败 |
| Session/Turn | 1 个 Stock Session、2 个 Turn Root；`delivery_ready=true`、`training_ready=true` |
| OTLP | 282 个 span、2 条 Turn Trace、280/280 内部父引用解析；相同上游 trace ID 不会合并两个 Turn |
| OTLP 体积 | 20 KiB 预览 policy 下未压缩体积从 31,949,674 降至 4,140,098 bytes，减少 87.0%；完整值仍在 Canonical/Raw |
| Buyer v7 | 85 分，52 次真实模型调用、5 个真实模型工具名、52/52 配对；唯一失败为 `tool_definitions` |

`exec` 是 Stock Codex 原生 custom grammar，不是采购合同要求的 JSON function
`parameters` schema；其余 4 个被调用工具具有完整定义。内层 `CommandExecution` 仅保留在
Runtime DAG/OTLP，不改写成新的模型 tool call。该样本不能通过清洗、改名或静态 Schema
补造升到 90 分；采购方需接受 custom-tool Profile，或 Stock Codex 必须真实暴露并调用
5 个符合合同的 JSON function 工具。

## 正式交付门槛

正式 buyer 包必须满足：

- Raw Checkpoint `completeness=complete`，并在 Release/Buyer Manifest 中携带
  `lineage_status=complete`；
- `verify-release --require-pass` 成功，所有 Session 的
  `buyer-v7-codex-runtime-expanded` score >=90；
- `verify-buyer-package` 成功，UTF-8 JSONL、Session 原子、Token/记录数/SHA-256
  守恒；
- 正式采购包发布到 `deliveries/<release_id>/COMMIT.json`，`verify-published` 通过，
  消费端不通过 LIST 推断完整性。

没有 Raw lineage 的历史 Release 可以用 `--allow-legacy-lineage` 迁移，但会标记
`legacy_unbound`，默认验证器和正式交付流程拒绝该包。
