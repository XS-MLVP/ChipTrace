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

## 网关输入与持久化确认

Relay 的 Wire `/capture` 成功响应包含 `input_receipt`，使用
`chiptrace.capture-input-receipt.v1` 确认当前 HTTP 请求的完整字节数和 SHA-256，包括请求
实际携带的尾部换行。`capture` 则确认规范化后的 WAL 记录；两种字节口径必须分开：

| 字段 | 字节口径 |
| --- | --- |
| `input_receipt.bytes` | 当前 HTTP 请求正文 |
| `input_receipt.sha256` | 当前 HTTP 请求正文的 SHA-256 |
| `capture.raw_sha256` | 规范化后的 WAL JSON，不包含行尾换行 |
| `capture.length` | 规范化后的 WAL JSON 加一个行尾换行 |

网关 outbox 删除待投递文件前，必须核对 input receipt 与本次实际发送的字节完全一致，
并检查 Capture ID、两层 durable、local_durable、幂等状态和有效 WAL locator。历史正文
元数据修复仍只作用于发送副本，确认应绑定修复后的发送字节，不能使用审计原件的哈希。
无效成功响应按退避重试，耗尽本轮尝试后仍保留 pending，不能删除文件或伪造 durable 计数。
幂等重试的 input receipt 绑定本次请求，规范化后的 Capture 身份与哈希保持不变。

## Collector 持久化确认

Relay 只有在下游 HTTP 成功且收到绑定当前 Capture 的持久化确认后，才能把投递账本
记为 `delivered`。确认中的 `capture.capture_id`、`capture.raw_sha256` 和
`capture.length` 必须分别等于本地账本的原始身份、SHA-256 和包含行尾换行的 WAL 字节
长度。外层与 Capture 内的 `durable` 都必须为 true，`duplicate` 必须一致，状态只能是
`accepted`/false 或 `duplicate`/true。远端 Segment 与 offset 独立于 Relay，只检查其
有效性；不能要求两台服务使用相同磁盘位置。

批量响应按 Capture ID 对应，每个已投递项必须有且只有一个有效确认。响应顺序不影响
归属；缺项、重复 ID、缺失明细、身份或哈希不符、矛盾状态和无效 JSON 都保留为
`pending`，由原有退避重试继续发送同一份 WAL 字节。部分响应中已经证明的成功、明确
冲突与待重试项分别记账；HTTP 失败不能被响应正文中的成功标志覆盖。

Relay 本地 durable ACK 只确认其自身 WAL 已提交，下游 Collector 确认和 OSS 归档仍是
后续独立阶段。升级确认校验不会重新认证历史 `delivered` 记录；历史数据的交付结论仍需
从保留的 Raw 和目标存储逐项验收。

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

来源端可在 OTLP 记录或 Span 边界声明 `codex.context_scope=session|turn`。
Session 边界必须提供实际原生 Session 身份；初始化、关闭及其派生操作仅通过精确
Trace/Span 父链继承这一作用域，不能借用同一 Trace 的唯一 Turn。业务 Turn 分支的
显式作用域或原生 Turn 身份优先，缺少 Turn 身份的新边界不能借用祖先 Turn。
缺少 Session 身份的边界保留为未解析记录，未知作用域、矛盾声明、父关系冲突和环均拒绝。

Session 级记录不参与逐 Turn 四源计数。SSE、工具结果/决策、用户输入及 Turn 指标
始终需要 Turn 身份；声明 Session 作用域不能豁免这些业务记录。未提供这一协议的
历史 Raw 保持现有严格分类；添加来源补丁不改变历史字节或历史交付结论。

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
调度器成功返回结果，不代表子进程退出码为 0。ChipTrace 仅对默认 `functions` 命名空间中的
`exec_command` / `write_stdin` 解析 Stock Codex 在 `Output:` 之前生成的固定进程结果头，
并将其独立保存为 `process_outcome`；旧遥测缺省或空命名空间按上游默认空间兼容。
`client.exec_command` 等外部同名工具的全部返回文本均为正文，不能声明 Stock 进程结果；
`Output:` 后的业务正文也不能改变任何状态。OTLP Span 状态使用有证据的语义结果，
同时以独立属性保留 lifecycle、dispatch 和 process 三类事实。

历史 Capture 如果把 Stock 进程来源标记附在外部工具上，新版投影会拒绝生成产物，
保留原始 Capture。此类 Session 需要从原始 OTLP 重新验证与迁移，不能原地改写 Raw
或将旧导出作为新版通过的证明。

同一精确执行作用域与 `call_id` 下，多个原生 `codex.tool_result` 的参数和输出必须一致。
参数按采集时解析的 JSON 值比较，键顺序及空白差异不构成冲突；输出保留原始值，不按
业务含义归一化。任一参数或输出冲突使 RuntimeSpan 的 `state_conflict=true`，进而使
Runtime/Session 检查不可交付并阻止 Buyer 导出。所有原始 Capture 和 Raw 引用继续保留；
不能按最后到达的结果消除冲突。`extensions.native_result_consistency` 只记录原生结果
观察数及两类冲突标志，不复制正文。Hook 的参数/输出是独立视图，不参加这项原生结果
一致性比较；其来源及其他生命周期、状态冲突检查继续保留。

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

## 原生 Session/Turn 统计

`inspect-session` 和投影/验收 Manifest 中的 `session_view` 使用
`chiptrace.session-view.v2`。其口径与采购评分分开；每个 Native Turn 都必须单独记录
四路来源覆盖，不能用 Session 级别的全局计数替代：

| 字段 | 统计口径 |
| --- | --- |
| `native_turns` | 去重的 `(source_session_id, turn_id)`；只允许显式 root Turn ID 回退 |
| `model_interactions` | 模型请求/响应记录；同一 Turn 的 retry 仍是独立交互 |
| `tool_execution_records` | 去重后的工具证据记录，pre/post Hook、OTLP 仍分别保留 |
| `session_epochs` | SessionStart 事件，排除 `source=compact` |
| `unscoped_turn_records` | 缺少显式 Turn 身份的交互、工具或 Turn 边界记录 |
| `unscoped_source_records` | 上述未归属记录按 Wire、工具、生命周期、OTLP logs/traces 和 Hook 的计数；总和必须守恒 |
| `turn.source_coverage` | 当前 Turn 的 Wire、OTLP logs、OTLP traces、required Hook 证据计数及缺失来源 |
| `incomplete_turns` | 至少缺一路 Turn 来源、未闭合、冲突或缺少明确身份的 Turn 数 |
| `delivery_ready` | 最新 Session epoch 已闭合；无 open/conflict/incomplete Turn、无未归属记录且四源完整 |
| `effective_turns` | Buyer v7 的有效用户配对数加必需工具配对数 |

新一轮 resume 需要自己的 SessionEnd；Stop 只闭合 Turn。冲突终态标记为 `conflict`，
不能用模型响应的 `completed` 推断 Session 完成。平台 API 将 Turn 明细作为磁盘 JSONL
保存并分页读取；采购验收会从已验证 Raw 重新计算并比对此统计。`turn_source_coverage_complete=true`
且 `incomplete_turns=0` 才能进入云端交付门禁。SessionStart/SessionEnd 本身没有 Turn ID
时只作为 Session 边界，不会被错误分配到某个 Turn；缺少 Turn ID 的业务证据继续计入
`unscoped_turn_records`。

原生 OTLP 不要求重复附带所有身份属性。Turn 可通过原始 Wire 中的 W3C Trace Context、
精确 Span/parentSpan 和原生 Turn ID 关联；同一 Trace 包含多个 Turn 时，必须有足够的
Span 或显式身份消歧。全量快照中发现的身份歧义在 Session 选择后仍保留，不能因为其他
Session 被移出载荷而宣称唯一。`thread.id` 是 OS 线程号，不是 Session 身份。
空值、全零 Trace/Span ID、冲突别名和环形父关系不能成为关联证据；不按时间或记录顺序匹配。

同一 OTLP resource、scope 或 record 的属性列表内，原生 Session/Turn 身份、
`codex.context_scope` 和 `event.name` 的重复键若值冲突，检查、投影和交付均拒绝；
不能按最后一个值选择归属或把业务事件改分为后台记录。冲突在原始 AnyValue 转为属性映射
之前检测，诊断只输出已知属性名，不输出冲突值或正文。完全相同的重复值不增加记录数，
原始 Raw 保持不变。

在线 OTLP logs/traces 入口使用同一重复属性校验。冲突 Raw 先写入 Relay WAL，再返回
`HTTP 400`、`reason=cloud_ingest_quality_error` 和 `durable/local_durable=true`；持久化确认
不代表质量合格。源记录数仍按实际输入统计，重试同一正文不新增 Capture。logs 只从上下文
有效的记录派生事实，按 resource → scope → record 合并属性，保留合法 scope 中的原生身份。

Turn 覆盖中的 Wire 是 Capture 数，OTLP logs/traces 是原始记录数，Hook 是原始批次中的
事件数。派生生命周期和工具事件不重复计为 Hook。Session 级 `source_coverage` 的 OTLP
数仍是批次数，两种统计不能直接相加或比较。

Canonical interaction 投影还必须通过 `metrics.turn_interaction` 门禁。每条
`ModelInteraction` 和 `span_kind=tool_execution` 的 `RuntimeSpan` 都要带明确的
`trace_context.session_id` 与 `turn_id`（缺少时才回退到 `root_turn_id`），并至少引用一条
属于对应 Native Turn 的 Raw Capture。对每个 Turn，Canonical ModelInteraction 数必须等于
`turn.model_interactions`；所有 Turn 的总和必须等于 `session_view.model_interactions`。
当 `tool_execution_records` 大于零时，该 Turn 至少要有一个 Canonical
`tool_execution` RuntimeSpan。RuntimeSpan 可以因为 pre/post 证据去重而少于原始工具记录，
所以不要求两者逐条相等。任一身份、Raw 引用或双向计数不一致都会使投影失败，不能只依赖
Runtime integrity 或 Session 级计数宣称交付完整。

当前交付契约为 `chiptrace.cloud-acceptance.v2`，必须包含完整的 `session-view.v2`。
v1 Schema 保持历史定义；旧产物只能按其冻结的旧验证器进行历史复验。升级必须从同一份
原始 Raw 重新运行全部验收，不能仅改版本字段、补写 Session 统计或沿用旧的通过标志。

`inspect-session.scenario_evidence` 使用 `chiptrace.native-canary-scenarios.v1`，从同一
精确身份快照提取第二轮、resume、非零进程退出和异步 `write_stdin` 的有界元数据证据。
该字段用于 Canary 门禁 v2；普通 Session 不需要执行所有 Canary 场景。
它不进入投影 metrics 或代替 Manifest 校验，缺失场景以 null 和 `missing_scenarios` 保留。
只有场景标签的旧 Canary 报告须从 Raw 重生成；具体字段来源与组装命令见
[原生 Turn 验收记录](native-turn-context.md#下一轮验收)。

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
- `cloud-acceptance-v1.schema.json`（历史格式）
- `cloud-acceptance-v2.schema.json`
- `session-view-v1.schema.json`（历史格式）
- `session-view-v2.schema.json`
