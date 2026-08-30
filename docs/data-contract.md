# 数据与评分契约

## Capture

Collector 新写入的数据遵循 `schemas/capture-v2.schema.json`。每条记录使用稳定
`captureId` 和以下 `recordType` 之一：

| `recordType` | 必要证据 |
| --- | --- |
| `api_snapshot` | 完整 request/response、HTTP 状态、截断/错误标记 |
| `lifecycle_event` | `sourceNamespace`、`task_session_id`、事件类型、终态事件的真实状态 |
| `tool_execution` | `sourceNamespace`、`task_session_id`、call ID、initiator、参数、完整 schema、真实状态/结果 |
| `evaluation` | `sourceNamespace`、`task_session_id`、带来源的测试/构建/搜索/验收结果 |
| `rollout_event` | Codex 源 Session/ordinal、原始 JSONL、源行 SHA-256、事件分类与投影结果；原生 bundle 另含 manifest/payload SHA-256 和镜像引用 |

完整采集还应提供：

- 原始 request/response body、HTTP 状态、错误与截断标志；
- `clientRequestAborted`、`clientResponseClosedBeforeFinish` 和
  `upstreamResponseCompleted` 传输事实，取消不能由正文或状态码推断；
- `sourceNamespace` 和实际 provider/model；
- `task_session_id`、`session_id/thread_id`、`root_session_id`、
  `parent_session_id`、`goal_id`、`turn_id`、`agent_id`、`branch_id`、
  `previous_response_id` 和 span parent；
- Session start/end、cancel、retry、compaction、subagent spawn/join 等事件；
- 流式 SSE 原文或完整聚合响应；
- 原生 usage 与缓存 Token；
- 测试、构建、搜索、用户修正、最终验收和 evaluator 的真实证据。

Collector 保存所有响应状态。认证头和 Cookie 在进入 WAL 前删除；18084 入口 outbox
在首次落盘前只替换明确的凭据字段、Bearer/token-like 值，并保存脱敏字段列表、版本和
脱敏前正文 SHA-256。普通交互正文保持原样，Collector 不做语义改写。actor 查询不阻塞
Capture 落盘，`actorMetadataStatus` 显式区分 resolved、missing、pending 和 error。
缺失工具状态记录为 unknown；不得默认 success。只有 Agent/工具执行器能提供任务 lifecycle 与内部工具 span，API
网关不得根据响应文本补造。

同一任务的 API snapshot、lifecycle、tool 和 evaluation Capture 必须使用相同的
`sourceNamespace` 与 `task_session_id`。命名空间参与隔离键；不同命名空间即使
任务 ID 相同也不会被拼成一个 Session。

Relay producer 入口和 `chiptrace produce` 要求 `producerEvent` 包含版本、稳定
event ID、生产者、生产者版本、`stream_id` 和单调 `sequence`，所有事件携带
RFC3339 证据时间。确定性 `captureId` 覆盖这些身份字段；同一 stream 的重复 sequence
或内部缺口进入 `meta.producer_event_conflicts`。工具状态不得为 unknown，在线
dispatcher 必须分别发送 started 与 terminal；Assembly 将它们归并为一个审计 span，
状态漂移进入 `meta.tool_execution_conflicts`。任务开始 Capture 可携带完整
`toolRegistry`；其规范化内容 SHA-256、生产者版本和工具数量进入 Session
`meta.tool_registry_evidence`。

### Harness 生产者

`chiptrace harness` 是生产者侧的参考实现，状态文件和 `events.ndjson` 位于同一
任务目录，格式由 `schemas/harness-session-v1.schema.json` 固定。启动命令原子创建
任务身份并先写入 `task_start`；之后只能由 dispatcher 写入真实的工具 started/
terminal，任务结束必须显式写入 `task_end`、`cancel` 或其他终态。Harness 同时
导出以下可直接注入 HTTP 请求的关联头：

- `x-chiptrace-task-session-id`
- `x-chiptrace-root-session-id`
- `x-chiptrace-parent-session-id`
- `x-chiptrace-goal-id`
- `x-chiptrace-agent-id`
- `x-chiptrace-branch-id`
- `x-chiptrace-session-id`
- `x-chiptrace-thread-id`
- `x-chiptrace-previous-response-id`
- W3C `traceparent`

每次事件先以规范化 JSONL 原子追加并 `fsync`，再由 `harness flush` 投递到
`/producer/events`。checkpoint 只有在整批收到 Relay 的逐条 durable ACK 后推进；
Relay 重试返回的 duplicate 不会增加唯一事件计数。恢复时会校验每个 producer stream
从序号 0 连续、checkpoint 落在换行边界，并截去未完成的最后一行；状态、序列或终态
不一致会显式失败。Harness 不会从 thread、response `completed`、工具名或返回文本
推断任务边界、工具 Schema 或成功状态。

Harness/dispatcher 使用 `identity_scheme=chiptrace.deterministic-capture.v1`。Codex
原生 bundle 使用 `identity_scheme=source-native`，保留源 Capture 身份；两种方案显式
区分，不能根据 producer 名称猜测。

升级后的在线入口只接受当前 producer 契约。历史 WAL 仍按原字节恢复，不重写 hash；
缺少 `stream_id`、identity scheme 或状态机事件的历史记录会在 Assembly 中保持
partial 并拒绝严格 Release，不会阻止 Collector 启动。

`traceContext` 的字段按来源保留在 `fieldEvidence`：显式 Capture、
`x-chiptrace-*`、W3C `traceparent`、Codex `client_metadata`/
`x-codex-turn-metadata` 和请求正文不会被混成无来源字段。值不一致时写入
`fieldEvidenceConflicts` 并使严格 Assembly Gate 失败。`thread_id`、
`session_id` 和 `prompt_cache_key` 只用于关联，不会提升为 `task_session_id`。
Codex `agent_name` 规范化为 `agent_path`；只有 harness/dispatcher 分配的稳定实例
标识写入 `agent_id`，两者不作为同一字段比较。

原生 `codex-rollout-trace` bundle 的 `trace.jsonl` 是运行时权威事件源；导出器
校验 manifest、连续 seq、payload ref 和原始字节 SHA-256，并在 durable ACK 后推进
checkpoint。缺失或改写的 bundle 前缀直接失败。`rollout_ended/thread_ended` 只表示
运行时生命周期。Codex `task_started/task_complete` 只表示 turn start/end。rollout exporter 不把
`turn_id` 或 thread/session ID 提升为采购任务边界。只有 harness 明确创建并注入
`task_session_id`，再发送任务 start/end/cancel，`task_boundary_attested` 才能通过。
每条 rollout Capture 保存源 JSONL 原文及 SHA-256；解析器未知类型和无法用真实
Tool Registry、模型调用 ID、工具名三者精确映射的 runtime 工具不会丢弃，分别进入
`rollout_unknown_events` 和 `rollout_unmapped_tools`。Codex 0.150 的 `WebSearch`
可识别，但源文件没有搜索结果正文时不生成有效工具返回。

新 Codex producer 必须把 dispatcher 在任务开始时导出的实际 Registry 快照内联到
原生 bundle；`--tool-registry` 只作为旧 bundle 的显式兼容输入。缺 Registry 时仍保存
真实工具参数、结果和状态，工具 Schema 为 null、provenance 为
`missing_runtime_registry`，并由 `rollout_unmapped_tools` 阻止严格 Release；不得从
`source_js`、输出文本或工具名列表重建 Schema。

## Sub2API 精确关联

Sub2API usage log 与 Capture 使用离线命令关联：

```bash
chiptrace enrich \
  --input /srv/chiptrace/raw/segments \
  --usage-log /srv/sub2api/usage-logs.jsonl \
  --output /srv/chiptrace/enriched

chiptrace verify-enrichment --enrichment /srv/chiptrace/enriched
```

Sub2API 原生 `usage_logs` 表不保存 provider；其仓库以
`COALESCE(NULLIF(groups.platform,''), accounts.platform)` 计算有效平台。生产导出必须
显式联表，且只输出 Trace 对账所需字段，例如：

```sql
SELECT jsonb_build_object(
  'id', ul.id,
  'request_id', ul.request_id,
  'requested_model', COALESCE(NULLIF(ul.requested_model, ''), ul.model),
  'upstream_model', COALESCE(NULLIF(ul.upstream_model, ''), ul.model),
  'effective_platform', COALESCE(NULLIF(g.platform, ''), a.platform),
  'model_mapping_chain', ul.model_mapping_chain,
  'user_id', ul.user_id,
  'api_key_id', ul.api_key_id,
  'account_id', ul.account_id,
  'group_id', ul.group_id,
  'channel_id', ul.channel_id,
  'input_tokens', ul.input_tokens,
  'cache_read_tokens', ul.cache_read_tokens,
  'cache_creation_tokens', ul.cache_creation_tokens,
  'output_tokens', ul.output_tokens,
  'created_at', ul.created_at
)::text
FROM usage_logs ul
LEFT JOIN groups g ON g.id = ul.group_id
JOIN accounts a ON a.id = ul.account_id
WHERE ul.created_at >= $1 AND ul.created_at < $2
ORDER BY ul.id;
```

查询结果每行就是一个 JSONL 对象，不包含账号凭据。普通/管理员 Usage API 当前不稳定
提供 platform，不能用账号名称或模型名替代。缺 provider/platform 的行计入
`invalid_usage_rows`，不会产生模型身份证明。

关联键只接受两类有协议依据的精确映射：上游 `x-request-id` 原值，或 Sub2API
`resolveUsageBillingRequestID` 生成的 `client:<X-Client-Request-ID>`。当前 Sub2API
中间件会为请求生成新的 Client Request ID 并写回响应，因此响应
`X-Client-Request-ID` 是账单关联的权威值；若入口转发的同名请求头与响应不同，
不得使用请求头覆盖响应证据。入口仍应生成并复用稳定 ID，以兼容尊重入站 ID 的
网关版本。输出的
`gatewayEvidenceJoin` 保存 Capture 字段、变换规则、usage fact SHA-256 和版本。
缺 ID、未命中、一对多、多个候选指向不同事实或已有证据冲突都会保留在汇总中，
不使用时间、模型、thread、正文相似度做回退。Sub2API 的 `local:` 和 `generated:`
ID 没有可由 18084 独立复验的对应字段，因此保持 unmatched。
产物目录包含 `captures/enriched-captures.jsonl.zst`、`manifest.json` 和继承的
`RAW_SOURCES.json`，Manifest 绑定 Capture/usage 输入与输出 SHA-256。
Manifest 遵循 `schemas/gateway-enrichment-v1.schema.json`；
`verify-enrichment` 会重新解析全部 Capture 并复核记录数、输出 SHA-256 和 Raw lineage。

精确命中后才写入 `gatewayEvidence`：requested/upstream model、provider、
mapping chain、账号/渠道标识和缓存 Token。Assembly 对每个可证明的 API 尝试要求一致
的路由证据，才把 `proxy_route_verified` 和 `provider_identity_attested` 置为 true。
纯 4xx/认证拒绝且没有模型响应、精确 usage 或 provider 报告的尝试仍完整保留在
Raw/Session，但记录在 `model_evidence.non_attestable_api_snapshots`，不进入证明分母；
如果 Session 中没有任何可证明的模型调用，模型门槛仍失败。按路径或模型字符串推断
的 provider 只保存在 `provider_evidence`，authority 为 `derived`，不能通过 buyer-v7
模型门槛。

Sub2API `usage_logs.input_tokens` 是扣除 `cache_read_tokens` 后的非缓存输入。Enrich
显式写入 `input_tokens_semantics=sub2api_non_cached_input`，并以
`api_input_tokens=input_tokens+cache_read_tokens` 重建 API 总输入。Assembly 以响应
usage 为首选，只有响应字段缺失时才用精确 Join 的网关事实补齐。Assembly 再按同一
`sourceNamespace` 中的 upstream/client/response/gateway ID 构造调用组件，同一调用
同时出现在 API snapshot 和 rollout 时只结算一次；没有显式 ID 时不跨 Capture
猜测去重。逐 Capture 选择保存在 `usage_evidence`，调用级结算保存在
`usage_settlement_evidence`；同一组件出现不同 usage 或相互矛盾的 ID 时写入
`usage_conflicts`，严格 Gate 失败。

## OSS Raw Zone

`schemas/raw-archive-v1.schema.json` 和 `schemas/raw-checkpoint-v1.schema.json`
定义原始对象层。Segment 内容按原字节保存为 NDJSON，不做质量筛选或 Session
合并；Manifest 记录 Segment 序号、记录数、字节数和 SHA-256，Checkpoint 只在
Manifest 与全部对象校验完成后写入。`completeness=complete` 才能进入 Release，
`partial` 仅用于取证。原始层只检查 JSONL framing 和 `captureId`，历史字段的
语义校验在 Assembly/Score 执行，以免清洗阶段丢失证据。

恢复目录中的 `RAW_SOURCE.json` 使用 `schemas/raw-lineage-v1.schema.json`。Assembly
和 Release Manifest 继承其 Checkpoint/Manifest 键与 SHA-256；`partial` 来源在
标准 Assembly 阶段拒绝。

新生产者必须显式发送 `recordType`。`capture-v1` 固定为历史只读契约；为读取旧
WAL，Assembly 仅把缺失类型的 v1 记录解释为 `api_snapshot`。Collector 写入的
规范化记录始终包含 `recordType` 并标记为 `chiptrace.capture.v2`。

滚动升级期间，旧 Relay 可能重放已存在于 Collector ledger 的 v1 原始字节。入口
仍生成 v2 规范化记录，但同时计算旧输入的原字节 SHA-256；该摘要只用于与既有
locator 做精确幂等匹配，不写入新 WAL，也不参与语义等价判断。原字节摘要相同返回
`duplicate`，同一 `captureId` 的不同旧字节仍返回 `conflict`。

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
| `source_request_count` | API snapshot 数量，不包含 lifecycle/tool/evaluation/rollout Capture |
| `source_capture_count` | 组成 Session 的全部不可变 Capture 数量 |
| `meta.capture_dag` | response 链、状态、根、尾、环和缺失父节点 |
| `meta.runtime_dag` | 原生 rollout/turn/inference/tool DAG；多进程任务可形成 task-scoped rollout forest |
| `meta.inference_api_conservation` | 原生完成推理与 API snapshot 的精确 ID 守恒证明 |
| `meta.task_dag` | root/subagent 关系和可拆分子轨迹 |
| `meta.trace` | root/parent/goal/turn/agent/branch 标识 |
| `meta.trace_contexts` | 每条 Capture 的完整 trace context 快照，保留 turn、span 和 response 链字段 |
| `meta.lifecycle_event_records` | 生命周期事件的完整对象（type、status、reason、occurred_at 及 capture_id） |
| `meta.tool_executions` | 按 call ID 归并的工具 span、started/terminal Capture 及证据模式 |
| `meta.tool_execution_conflicts` | 重复/缺失状态、参数或 Schema 漂移；非空即拒绝严格 Release |
| `meta.producer_streams` | producer/stream 的 sequence 范围、缺口、重复和连续性 |
| `meta.producer_event_conflicts` | producer 版本漂移、sequence 缺口或重复；非空即拒绝严格 Release |
| `meta.tool_registry_evidence` | 任务开始时实际 Registry 的内容 hash、生产者版本和工具数量 |
| `meta.system_prompt_evidence` | request/developer/response Prompt 的来源证据 |
| `meta.model_evidence` | 请求与响应模型一致性及证明范围 |
| `meta.evaluation_evidence` | 测试、构建、搜索、验收和 evaluator 证据 |
| `meta.usage_evidence` | 响应与 Sub2API usage 的逐 Capture 选择来源、口径和冲突 |
| `meta.usage_settlement_evidence` | 按精确调用 ID 组件执行一次结算的 Capture 集合、选择值和来源 |
| `meta.rollout_events` | Codex 原始事件 lineage 与投影分类 |
| `meta.rollout_unknown_events` | 当前解析器不认识的源事件，非空即拒绝严格 Release |
| `meta.rollout_unmapped_tools` | 缺 Registry 或模型调用精确关联的 runtime 工具，非空即拒绝严格 Release |

每个工具定义包含 `schema_hash` 和 `schema_version`。`parameters` 中的
`required` 名称必须引用已定义属性；每个结构化调用的 `arguments` 必须是可解析
JSON。来源没有版本时，Assembly
使用 `sha256:<schema_hash>` 作为内容寻址版本。每次工具调用包含
`execution_status`，工具返回保留 `status`、`is_error` 与原始内容。
原生 grammar 会无损保存在 `native_format`，生成的 JSON 包装仅供分析；
buyer-v7 不把 `generated_adapter=true` 当成采购方要求的原生完整 JSON Schema。
Tool Registry 遵循 `schemas/tool-registry-v1.schema.json`，必须绑定实际 Codex CLI
版本；静态工具名列表或由命令文本生成的 Schema 不接受。

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
| 真实 User → Assistant 轮 | ≥2 | ≥2 |
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
ChipTrace 对 v7 的“调用工具不重复”采用严格解释：至少 5 个不同工具名，并且
每个调用 ID 唯一。若合同只要求 5 个不同调用 ID，应建立独立 profile，不修改
既有 v7 结果。

有效轮次由实质 user→assistant 交互与已配对 assistant→tool→result 相加；两个
Profile 都要求至少 2 次真实 user→assistant 交互，buyer-v7 另外要求总有效轮次达到 10。
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
硬门槛失败；默认准入阈值为 90。消息合并分歧、工具 Schema/状态机冲突、producer
sequence 缺口或重复、Trace/usage 冲突、未知/unmapped rollout、response DAG 环或
缺失父节点、task DAG 不完整统一进入 `assembly_integrity` hard gate。

原生 Codex runtime 还启用两个独立硬门槛：`runtime_dag_integrity` 要求所有原生节点
闭合且没有 open/unresolved/terminal-status-conflict 节点；dispatcher 与 runtime
终态分别保留。Codex dispatcher 的 `completed` 仅表示调用包装结束，结果以 runtime
terminal 为准；显式 success/error/cancelled 声明矛盾时列入
`runtime_dag.status_conflict_node_ids`。
`inference_api_conservation` 要求每个
`inference_completed` 都通过精确 `upstream_request_id` 或 `response_id` 命中真实
`api_snapshot`。该对象包含 runtime/API 数量、覆盖率、缺失键、无关联 Capture、重复
runtime key 和额外 API 键。匹配不使用 task、时间、模型、thread 或正文相似度；原生
runtime 已存在但该对象缺失的旧 Assembly 直接失败。

`chiptrace score` 的输出文件和 Release 的 `reports/assessments-part-*.jsonl.zst` 使用
`schemas/assessment-v1.schema.json`，逐条给出 Gate、观测值、期望值、失败原因、
三类质量结果和 Token。`release_decision=eligible` 仅在全部 hard gate 通过且
分数达到阈值时产生。

正式 buyer 包还必须携带 `lineage_status=complete`，将 Release 绑定到完整 OSS Raw
Checkpoint；历史迁移包明确标记为 `legacy_unbound`，不得进入对外交付目录。

OSS Raw 的首次提交将每个 Segment 的 SHA-256、字节数和 JSONL 记录数合并为一次
流式读取；Checkpoint 写入后不再重复下载整个快照。独立的
`verify-raw-archive --verify-records` 仍会执行完整远端复验。

## 去重

- 精确去重指纹覆盖 System Prompt、Tool Definitions 和全部 Messages。
- 同一 trajectory_id 的连续消息子序列只保留最长版本。
- 同一 trajectory_id 出现无法互为连续子序列的候选时整组拒绝，并写入
  `reports/divergent-sessions.jsonl.zst`。
- Manifest 记录输入、解析失败、精确重复、子集、冲突、已评分和准入数量，
  并校验守恒。

## Token

Codex rollout 的累计 `token_count` 快照可能连续重复，原始对象逐条保存在
`meta.rollout_usage_evidence`，不直接叠加到 Session `usage`。原生 bundle 的逐调用
inference usage 可参与结算，但会与 18084 API snapshot 按精确 request/response ID
组成同一组件，只计算一次；Sub2API 事实只用于响应字段缺失时补齐。无法完成调用级
关联的累计快照保持独立证据，不补造为 API Token。

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
