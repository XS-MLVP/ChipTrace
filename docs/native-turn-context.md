# 原生 Turn 上下文缺口与修复验收

当前 v2 交付要求完整的原生 Turn 身份、四路来源、闭合边界和零未归属业务记录。
目前已实现精确关联和拒绝不完整交付，但真实 Stock Codex 仍有来源上下文缺口。
上线、完整交付或新客户端版本支持均需重新完成真实验收。

## 2026-10-14 的真实新版客户端检查

使用当前唯一终端安装的 Stock Codex `0.163.0-alpha.11`，在只读容器中执行一次短采集任务。
容器没有宿主 `/etc/codex` 配置，原生配置和九类 lifecycle Hook 只发送到临时网关、Relay 和
Collector；未重启线上 18084。模型使用真实上游的 `gpt-5.6-sol/low`，没有构造模型响应。
Hook 命令经过检查后仅在这次隔离调用中使用原生 trust bypass；这不证明管理员 required
Hook 部署或正常用户 Hook 信任状态已经通过验收。

| 指标 | 实际结果 |
| --- | --- |
| Session | `01a13a92-86d3-7a51-875a-79903750d55f` |
| Native Turn | 1 个；Session 和 Turn 均闭合 |
| Wire / 原始 OTLP batch / Hook | 5 / logs 16 / traces 10 / Hook 4 |
| Turn 精确归属记录 | Wire 5；logs 15；spans 1082；不同 Turn Hook 2 |
| 未归属记录 | logs 296；spans 159；总计 455 |
| Runtime 检查 / Session 交付 | `integrity.delivery_ready=true` / `delivery_ready=false` |
| 真实工具结果 | README 读取成功；故意 exit 7 保留；sleep 2 和后续 write_stdin 完成 |
| sealed Raw | 5,386,965 bytes；SHA-256 `e7c8d59423d494f1006fe341d7dbe010312a6edd075d43215b7aa70d2d20ad48` |

这是短采集 Canary，未满足 Buyer 采购规模，也未测试 resume、子 Session 或真实阿里 OSS。
缺失上下文的原始记录保留作取证，不能通过删除、改写或时间窗口关联使其变成合格数据。
完整原始证据保存在运维侧，不将对话正文、鉴权值或完整 Raw 提交到 Git。

## 元数据审计与全量计数

`audit-session-context` 复用 Canonical 的完整快照歧义检测和精确 Session 选择，直接只读
扫描 Capture，不创建投影或临时副本。输出遵循
[source-context-audit.v2](../schemas/source-context-audit-v2.schema.json)，只含计数、事件/span
名称、Capture/Trace/Span ID 和 envelope 内记录序号，不打印对话、工具输出或其他属性值。
v2 额外要求来源端用 `codex.context_scope=process` 明确标记进程级后台记录；没有该声明的
记录仍属于未知 Session，不能通过门禁。
分组最多 128 个，定位样本默认 20 个、最多 1000 个；超限仍保留遗漏记录数。
这些标识和名称仍属于运维元数据，报告应按项目权限保存。

```bash
chiptrace audit-session-context --input <sealed-raw-or-restored-directory> \
  --session-id <native-session-id> --sample-limit 5
```

2026-10-14 对上述 44 条原始 Capture 实际执行并保持 Segment SHA-256 不变：

| 来源 | envelope 内记录总数 | Turn 精确归属 | 已知 Session 级事件 | 未归属 Turn | Session 身份未知 |
| --- | --- | --- | --- | --- | --- |
| OTLP logs | 314 | 15 | 3 | 296 | 0 |
| OTLP spans | 1276 | 1082 | 0 | 159 | 35 |

每一来源的分类计数与总数守恒。455 条未归属 Turn 与当前 Session 检查一致；另有 35 个
span 无法精确确定 Session 身份，以前的 Session 未归属计数没有涵盖它们。报告显式保留
这一范围，不能把这些 span 自动归属给当前 Session，也不能宣称其必然不相关。
未归属的 159 个 span 中，`fs.get_metadata` 70、`fs.read_file` 20、
`persist_rollout_items` 6；其 Trace 没有已观察到的原生 Turn 身份。初始化/会话循环作用域
仍须凭来源端代码和原生身份审计，诊断名称本身不是豁免依据。命令不会给出交付通过标志。

进程级记录单独计入 `process_level_records`，不参与 Session/Turn 的四源覆盖，也不计入
`unknown_session_records`；只有来源端显式声明 `codex.context_scope=process` 时才能使用
这一分类。旧 v1 报告没有该字段，不能作为当前 v2 门禁证据。

`process` 声明也不能豁免 Turn 业务事件。`codex.sse_event`、`codex.tool_result`、
`codex.tool_decision`、`codex.sandbox_outcome`、`codex.user_prompt`、`codex.turn_ttft`
和 `codex.turn_cost` 若直接声明或沿精确父链继承 Process scope，审计和 Session 检查均拒绝，
诊断为 `OTLP Turn-level business event conflicts with Process scope`。合法进程后台记录
仍按原始声明分类；冲突输入和 Raw 保留，不改写 scope 或删除业务记录。

[精简回归 fixture](../fixtures/native-context-README.md) 只保留实际字段和父链，用一致
别名替换身份。CI 验证缺口、跨 Session 歧义、正文不输出、计数守恒和真实非零退出；
它不替代完整 Raw 或新的真实客户端 Canary。

## 已定位的生产者路径

296 条未归属日志均为 `codex.sse_event`，有 `conversation.id`，没有有效 Trace/Span ID、
原生 Turn ID 或响应 ID。它们只有事件种类、耗时和时间戳，无法在多 Turn、重试和并行任务中
精确确定所属 Turn。这一字段缺口在旧 `0.153.4` 和本次 `0.163.0-alpha.11` 均被真实观察到。
159 个未归属 span 仍需要逐项审计，不能假定与 SSE 日志具有同一原因。

版本 tag `rust-v0.163.0-alpha.11` 对应 upstream commit
`5425d3e625daa58eea3ad1de27c087eb3b2ffbd3`。该版本的
[ApiTelemetry](https://github.com/openai/codex/blob/5425d3e625daa58eea3ad1de27c087eb3b2ffbd3/codex-rs/core/src/client.rs#L2937)
保存 Session telemetry、鉴权环境和路由信息；`on_sse_poll` 直接调用 `log_sse_event`，没有在
该结构中保存并重新进入原始请求 Span。
[SSE 日志发射路径](https://github.com/openai/codex/blob/5425d3e625daa58eea3ad1de27c087eb3b2ffbd3/codex-rs/otel/src/events/session_telemetry.rs#L1057)
也未显式带入原生 Turn 或响应 ID。代码与实际缺失字段相符，具体修复仍需回调级测试和新
客户端真实 Canary 证明。

固定版本的 HTTP 工厂在 `#[instrument(name = "model_client.stream_responses_api")]`
函数内构建 SSE 适配器。真实 Raw 中同名 span 的父链经过 `try_run_sampling_request`、
`session_task.turn` 和 `codex.turn_input`，含原生 Turn 身份。这为保留创建时上下文提供
具体证据；仍需要验证实际异步回调发射及 OTLP 导出，不能仅以 join 的正例宣布修复。

[来源端补丁草案](upstream-sse-context.patch) 在 `ApiTelemetry` 创建时捕获请求 Span，
并在同步 SSE 回调期间重新进入它。HTTP 和 WebSocket 工厂还将创建时的请求 Span
传给异步 stream mapper，成功和失败终态日志只在同步发射期间进入这个 Span，不把
entered guard 保持到 `.await` 之后。补丁不修改业务正文、原生身份或完成状态。

2026-10-15 在固定的 `5425d3e625daa58eea3ad1de27c087eb3b2ffbd3` 源码上完成
[回调和终态回归](upstream-sse-context-test.patch)：SSE 回调、成功终态、失败终态和
并行请求交错完成共 4 项通过。测试在退出创建作用域后触发事件，并保留没有 Span 的
日志事件，避免把缺失上下文误当成没有发射日志。临时移除成功终态的上下文恢复时，
该测试实际退出 101，观察结果为 `None`；恢复补丁后再次通过。
同一源码的 `client::tests` 全部 37 项通过，包含 HTTP/WebSocket 请求、鉴权恢复、
interceptor、丢弃流和背压取消；CI 也执行这组回归。
`cargo build -p codex-cli --bin codex --locked --offline` 也通过。
两个补丁又在另一个干净的同 commit 工作树中顺序 apply/check，通过；未纳入临时锁文件
或其他源码修改。

该 tag 的 Cargo.toml 已使用 `0.163.0-alpha.11`，Cargo.lock 中 160 个本地 workspace
包仍为 `0.0.0`。本次临时解析后的差异仅为这些本地包版本；外部依赖版本、来源、校验和、
依赖边及其余锁文件字节保持不变。[锁文件检查](../scripts/ci/check-producer-lock.js)
复验了这个限制，之后的测试和 CLI 构建均使用 `--locked`。原始锁文件 SHA-256 为
`0da7b7298c7e50d05f0d59b2b801afbaf3c3cf74c36d4e66ac6b51c21f60a4df`，临时协调后的
SHA-256 为 `0b2af1620da0832300973f59c3f0ff9de1547fd18098bce9ef8f9daa6505416c`。
这不是上游官方发行构建证明。

首次新增作业的远端 run `38610333057` 在干净 checkout 的锁文件协调步骤失败：
`cargo metadata --no-deps` 只读取 manifest，不会更新原始 Cargo.lock。本地已构建源码的
锁文件此前被 Cargo 协调，因此未覆盖这一启动路径。CI 现在显式执行 `--prepare`，
仅接受原始锁文件或严格计算出的本地包版本替换结果；其他依赖或字节变化直接拒绝，
不会覆盖。后续构建仍使用 `--locked`。CLI 回归从原始 Git 锁文件验证协调、重试幂等和
依赖篡改拒绝；失败诊断只打印 SHA-256，避免展开完整锁文件。

GitHub CI 的 `upstream-context` job 现在固定同一 commit，顺序应用两个补丁、复验上述
锁文件限制、编译并执行 4 项回归，再构建 CLI。CI 另检查每个指定测试确实执行且通过，
零项匹配、重复测试或依赖变化均不能获得通过报告。日志、锁文件摘要和测试摘要作为
Artifact 保存。工作流定义和本地检查不能代替该提交的远端 Actions 结果。
[上游问题草稿](upstream-turn-context-issue.md)
仅作为可审查材料保存在本仓库，尚未向其他项目发消息、创建 Issue 或提交 PR。

## 2026-10-15 的补丁实验与剩余作用域

隔离真实 Provider Canary 使用上述修改后的 CLI；版本基线为 `0.163.0-alpha.11`，
不是未修改的 Stock Codex。Session `01a13b67-bcff-79d0-b131-cb28e1e8b4d6` 退出 0，
1 个原生 Turn 和 Session epoch 均闭合；Wire 5、OTLP logs 12 批、traces 4 批、Hook 4。
真实工具读取、故意 exit 7 和 sleep/write_stdin 结果均保留。每个 Turn 四源齐全，
但 Session `delivery_ready=false`；这是短采集实验，不满足采购规模。

| 来源 | 记录总数 | Turn 精确归属 | 已知 Session 级 | 未归属 Turn | Session 未知 |
| --- | --- | --- | --- | --- | --- |
| OTLP logs | 326 | 321 | 3 | 1 | 1 |
| OTLP spans | 1265 | 1071 | 0 | 159 | 35 |

未归属 Turn 总计 160，另有 36 条记录没有精确 Session 身份；不能把后者包含在前者中
或默认为无关。原始 sealed Segment SHA-256 为
`5285f05e1813795d22cd291d92d726dab4faba3393fe2fa3fe4535a4c2d27721`，证据保留在
运维目录 `/var/tmp/chiptrace-native-patched-a62a74`，不将完整 Raw、日志正文或鉴权数据提交到 Git。

只读定位样本确认 159 个 span 分布于两个没有原生 Turn 的 Trace：启动链 139 个、
Session 循环/关闭链 20 个。启动链包括 `thread/start -> thread_spawn -> session_init`，
Session 循环根有真实 UUID `thread_id`；两者都没有 Turn 边界，不能用同名文件操作或
最近 Turn 把它们关联到业务 Turn。具体来源路径与下一轮修复约束见
[Session 作用域审计](session-scope-audit.md)。当前分类和门禁保持严格，未将它们自动豁免。

下一步应在生产者的请求/Turn 上下文创建时保存不可变关联信息，并在异步 SSE 回调和派生
span 中继续传递；同时核实 Session 级 span 的原始作用域。补丁原型应在独立环境验证，
不能替换当前唯一终端安装或改写历史 Raw。只有后续未修改的发行版本通过验收，才能宣称
Stock Codex 的完整 v2 交付已经可用。

## 2026-10-15 的 patched Canary 门禁结果

在固定 upstream commit `5425d3e625daa58eea3ad1de27c087eb3b2ffbd3` 上顺序应用
SSE 上下文、Session 作用域、扩展作用域和 process 作用域补丁，再使用真实
`0.163.0-alpha.11` 客户端在隔离环境采集。该客户端不是未修改 Stock Codex；线上 18084
也没有加载这组补丁。

本轮 Canary 有 2 个 Native Turn 和 2 个 Session epoch，覆盖第二轮、实际 resume、失败
工具进程和延迟 `write_stdin`。两个 Turn 均闭合，Session/Turn 没有冲突、未归属或未知
Session 记录，Wire、OTLP logs、OTLP traces、Hook 四路来源均有正数证据。脱敏后的门禁
输入保存在 [success report](../fixtures/native-canary-multiturn-0163-success-report.json)
和 [success audit](../fixtures/native-canary-multiturn-0163-success-audit.json)，只包含
计数和元数据。

```json
{
  "schema_version": "chiptrace.native-canary-gate.v1",
  "real_upstream": true,
  "stock_version": "0.163.0-alpha.11",
  "producer_mode": "patched_stock",
  "unmodified_stock": false,
  "production_ready": false,
  "native_turns": 2,
  "selected_audit_records": 3621,
  "delivery_ready": true
}
```

审计总计为 OTLP logs 580 条（Turn 573、Session 5、process 2）和 OTLP traces 3041 条
（Turn 2190、Session 737、process 114），`unscoped_otlp_records=0`，每项分类与总数
守恒。`process` 记录只有在来源端显式写入 `codex.context_scope=process` 时才可以这样
分类。该结果证明补丁后的隔离生产者路径可以满足数据完整性门禁，不证明未修改发行版、
线上镜像或真实 Alibaba OSS 账户已经验收。门禁输出 `producer_mode=patched_stock`，生产
交接命令还必须添加 `--require-unmodified-stock`；正向 fixture 也不替代 Raw、鉴权审计或
采购包。

2026-10-15 加入上述 Process 冲突保护后，再次只读回放这份真实两轮 patched Canary：
`audit-session-context --sample-limit 0` 和 `inspect-session` 均退出 0，仍为 2 个原生 Turn、
`delivery_ready=true` 和 3621 条分类守恒的 OTLP 记录。合法的 2 条 process 日志和 114 个
process span 均保留。sealed Raw 在回放前后的 SHA-256 相同：
`fb39af7a9bae56dd17455f7840b51248a57e4fe64725705339de04d43f6fd3ef`。
Rust 和真实 CLI 的独立负例覆盖七类业务事件的直接/父链 Process 声明，共 14 种组合；
CLI 均真实退出 1、stdout 为空、诊断不含正文、输入字节和目录不变。这些负例是协议回归，
不表示 Stock Codex 在真实任务中已经发射了错误 Process 声明。

门禁还要求 `session_view.model_interactions` 和
`session_view.tool_execution_records` 分别等于所有 Native Turn 对应字段的总和。聚合值
缺失、被篡改或存在未归属交互时，Canary 会失败；这两个字段不能用 Runtime integrity
结果代替。

CI 现在在固定源码 clean clone 中复验五个补丁的 `apply --check`、顺序应用和
`git diff --check`，其中进程级后台任务的补丁单独保存为
[`upstream-session-scope-process.patch`](upstream-session-scope-process.patch)。

## 下一轮验收

真实 Canary 的报告和 `audit-session-context` 必须经过仓库内的同一门禁，不能只看
`integrity.delivery_ready` 或 CLI 退出码。门禁要求真实上游客户端至少两个 Native Turn，
每个 Turn 的 Wire、OTLP logs、OTLP traces、required Hook 均有记录，Session/Turn 均闭合，
没有未归属或未知 Session 记录；进程级后台记录必须有显式 `process` scope，并且来源计数守恒：

```bash
chiptrace inspect-session --input <sealed-raw-or-restored-directory> \
  --session-id <stock-codex-session-id> > report.json
chiptrace audit-session-context --input <sealed-raw-or-restored-directory> \
  --session-id <stock-codex-session-id> --sample-limit 0 > source-context-audit.json
node scripts/ci/native-canary-gate.js \
  --report report.json --audit source-context-audit.json --minimum-turns 2
```

生产交接还必须声明生产者未修改：

```bash
node scripts/ci/native-canary-gate.js \
  --report report.json --audit source-context-audit.json \
  --minimum-turns 2 --require-unmodified-stock
```

报告的 `provenance` 必须包含 `client_version`、固定的 `upstream_commit`、
`producer_mode` 和守恒的 `patch_set`。`patched_stock` 只用于隔离数据治理回归，不能作为
未修改 Stock Codex 的生产证明。

该门禁只输出计数和状态摘要，不读取或打印对话正文、工具参数、鉴权值或文件路径。
失败结果必须保留 Raw 和审计报告，不能通过删除未归属记录、改写状态或降低轮次门槛来
获得通过。

1. 保留业务请求的原生 Session、Turn、request/response 和 W3C 上下文，验证 SSE 回调离开
   原始异步任务后仍能精确关联；同 Trace 多 Turn 不允许依赖全局“当前 Turn”。
2. 使用至少两个真实 Turn、并行请求、重试、实际 resume、取消和失败复现；检查所有来源
   的归属计数和未归属计数守恒，保留确实属于 Session 作用域的原始证据。
3. 在目标 OSS 账户复验提交对象、恢复、逐 Turn 检查和完整 Buyer 导出下载；保存提交 SHA、
   镜像 ID、原始对象哈希及对应 CI run。
4. 更新宿主网关健康门禁，保留并恢复长期 open 的 Capture；健康检查必须能反映未最终化
   或不可验证的事务。完成隔离 Canary 后再灰度部署，验证重启及回滚保持原始证据。

ChipTrace 修复提交 `b5352addce361edac78a08ffd08638aa36b22476` 的
[GitHub CI](https://github.com/XS-MLVP/ChipTrace/actions/runs/38570741233) 三个作业均已通过。
这证明该提交的工程回归通过；上面的真实客户端结果仍未满足完整交付门槛。
