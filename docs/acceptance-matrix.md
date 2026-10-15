# 验收矩阵

本文只记录当前云端主线。需要在用户主机部署 ChipTrace 程序的入口不属于产品能力，
也不作为验收证据。

## 产品门槛

| 验收项 | 实现 | 通过条件 |
| --- | --- | --- |
| Raw 完整性 | WAL、sealed Segment、OSS Manifest/Checkpoint | complete；逐对象和逐行 SHA-256 通过 |
| 云端来源 | Wire、OTLP logs、OTLP traces、required Hook | Session 与每个 Native Turn 均精确归属四路来源；缺一路即拒绝 |
| Wire 完整性 | 18084 原字节 Capture | 请求/响应长度与 SHA 一致；Responses 有协议终态 |
| Session/Turn 身份 | Stock Codex headers、OTLP、required Hook | 显式 `session_id`/`turn_id`；Session start/end 闭合；每个 Turn 无 open/conflict/unscoped |
| Runtime | `codex.tool_result` + lifecycle | 输出未截断；调度状态明确；Shell 进程结果独立；无 open/conflict span |
| 调用关联 | ModelInteraction、RuntimeSpan、InteractionLink | call/result/execution 精确配对；内部父引用 100% |
| Tool Schema | Responses Wire direct function tools | 每个被调用工具有 name、description、parameters |
| 模型路由 | Wire + Sub2API usage | request ID 精确匹配；模型和 Provider 一致 |
| Buyer v7 | `assessment.v2` | 有效轮次 >=10；真人交互轮 >=2；工具 >=5；配对率 100%；机器轮 <25% |
| Release | `cloud-acceptance` | `delivery_ready=true`；score >=90；全部 hard gate 通过 |
| 采购包 | `verify-buyer-package` | 1 Session/JSONL line；UTF-8；tar.gz；SHA/Token 守恒 |

## 隔离闭环

`chiptrace self-test` 使用确定性 Responses、OTLP、Hook 和 Sub2API fixture，验证实现逻辑，
不冒充真实用户数据。当前预期结果：

| 指标 | 预期 |
| --- | --- |
| Relay/Collector | attempt 守恒，pending/inflight 为 0 |
| Raw | Archive、Verify、Restore 全通过 |
| Canonical | Schema 全通过，四源齐全，每个 Turn 四源齐全，`delivery_ready=true` |
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
Canary 报告还必须记录 `provenance.upstream_commit`、`producer_mode=unmodified_stock` 和
空的 `patch_set`，并通过 `native-canary-gate --require-unmodified-stock`；带补丁的隔离
Canary 只能证明数据治理链路，不得作为生产者发布证据。
Stock Codex Session 以 Hook 顺序为边界；最新 `SessionStart` 必须有后续 `SessionEnd`，历史终态、
`response.completed`、`Stop` 和 OTLP `conversation_starts` 均不能代替该终态。

2026-09-05 已使用未修改的 Stock Codex `0.152.0-alpha.7.2` 完成真实长任务，并从生产
Collector 的连续 sealed Segment 建立 `complete` Raw Checkpoint，再通过唯一
`cloud-acceptance` 主线验收：

| 指标 | 结果 |
| --- | --- |
| Session | `01a06d0f-a725-7e11-bcb3-cec3bbe00945` |
| Raw lineage | 142,798 条；33,452,748,417 bytes；Checkpoint `complete` |
| 云端来源 | Wire 51；OTLP logs 190；OTLP traces 62；Hook 6；缺失 0 |
| Wire / usage | 51 次 streaming 尝试；42 次完成并精确关联 Sub2API；9 次响应前传输失败完整保留 |
| 工具 | 38 个必需调用；8 个不同工具；8 份完整定义；result/execution 配对率 100% |
| 分支 | 2 个调用由客户端关闭字节边界证明为 abandoned，未改写为成功或执行 |
| Runtime / OTLP | `delivery_ready=true`；1 个 root；91/91 内部父引用解析 |
| Buyer v7 | 41 个有效轮次；3 个真人交互轮；score 100；hard gate 全通过；1/1 eligible |
| Token | API 929,396；缓存输入 819,200；规范化语料 53,297；监督输出 11,820 |
| 交付 | UTF-8 JSONL `tar.gz`、七阶段 Manifest 和 SHA-256 复验通过 |

该结果证明当时的镜像和 v1 验收契约能从 18084 的真实线上采集生成合格产物。当前 v2
新增逐 Turn 来源和未归属记录门禁；这些历史通过结果必须从原始 Raw 重验，不能作为 v2
已经通过的证明。持续生产可用性仍要求 18084、
Relay、Collector 健康、attempt 守恒，并对每条 Session 独立执行相同的 fail-closed 验收。

同日接入复查发现旧产物缺少当前 Schema 的 `source_coverage`，旧采购包还使用历史
`buyer-v7-codex-runtime-expanded` 标记，均不能直接作为当前验收证据。已用部署镜像
`chiptrace:0.6.0-5085f91` 从原始完整归档重新执行全部 `cloud-acceptance` 阶段，退出码 0，
上表结果在当前 `buyer-v7` 下复现。新产物位于
`router_v2/records/chiptrace-readiness-20260905/acceptance/historical-01a06d0f/`；
采购包又经最终离线镜像独立复验并放入同一证据根的 `delivery/`。旧产物保留为历史记录，
未修改字段或降低门槛。

同日 node42 的 Stock Codex `0.153.4` 完成新的长任务和实际 resume，修复原生 Hook
相同 `SessionEnd` 被去重的问题后，从连续 sealed Raw 全量归档通过 `cloud-acceptance`
并以退出码 0 结束：

| 指标 | node42 结果 |
| --- | --- |
| Session | `01a07125-8b55-79f2-abf0-6f272e244db1` |
| Raw lineage | 154,819 条；40,181,343,078 bytes；Checkpoint `complete` |
| 四源 | Wire 36；OTLP logs 338；OTLP traces 58；Hook 8 |
| 生命周期 | 实际 start/resume 两次；SessionStart 2、SessionEnd 2；最新 epoch 闭合 |
| 工具与结构 | 34/34 call/result/execution；5 种工具及完整定义；OTLP 父引用 72/72 |
| Buyer v7 | 36 个有效轮次；2 个实质用户交互轮；score 100；1/1 eligible |
| 镜像 | `chiptrace:0.6.0-readiness-20260905`，8 GiB 隔离离线容器 |

该长任务显式使用 `gpt-5.6-sol`；默认 `gpt-6-astra`/`max` 未改动，另有四源完整的短
smoke，通过采集验收但不满足采购轮次/工具数门槛。两个任务都是操作员运行的 canary，
不是甲方来源数据或负载测试。Raw 使用本地 FS 对象后端，CI 另用隔离 MinIO 验证 S3
协议；甲方 OSS 上传与远端校验
仍需真实目标。该长任务验收时，线上 Collector/Relay 镜像为
`chiptrace:0.6.0-5085f91`。

node42 完整目录迁入 NFS 后，最终离线镜像 `chiptrace:0.6.0-readiness-r2-20260905`
再次执行 `verify-cloud-acceptance` 并退出 0；采购包复制后独立复验及所有 SHA-256 通过，
已放入同一证据根的 `delivery/01a07125-8b55-79f2-abf0-6f272e244db1/`。

2026-09-05 22:56（Asia/Shanghai），线上 Collector/Relay 已更新为上述 r2 镜像。
隔离候选服务先通过原生 Canary，再以 node42 默认用户配置向生产 18084 发起新会话
`01a07215-719c-7c72-a402-f3574bdbe939`：Wire 4、OTLP logs 14、OTLP traces 8、Hook 4，
3/3 调用、执行、结果精确配对，SessionEnd 闭合。工具实际正文 13,400 bytes 中的
512 行逐一校验通过，故意 exit 7 的错误保留；短会话只证明采集完整性，不满足采购规模。
两份长采购包又经实际解包检查，保留失败、图片及 resume 证据。两包均有
`model_attestation_missing` 告警：路由事实已验证，外部密码学模型身份未认证。
当前用户配置与凭据通过 20 项控制端检查；报告及正文节选见
[热更新证据](../../records/chiptrace-hot-r2-20260905/REPORT.md)。

## v2 当前门禁状态

2026-10-15 的隔离 patched Canary 使用真实 `0.163.0-alpha.11` 上游客户端完成 2 个
Native Turn 和 2 个 Session epoch，覆盖第二轮、resume、失败工具进程和延迟
`write_stdin`。四路来源均有证据，`unscoped_turn_records=0`、`unknown_session_records=0`、
`unscoped_otlp_records=0`；仓库门禁输出 `selected_audit_records=3621`、
`delivery_ready=true`。该结果只证明 producer 补丁链路在隔离环境满足 v2 门禁。

Collector/Relay 已部署 revision `fe9fcf924b226099202cb770b7cf0da29e0c2310`。新进程只有
1 条没有原生 Session/Turn 的 HTTP 403 Wire；全局四源门禁曾短暂通过，随后因 Wire 过期
真实退出 1。这个通过窗口不构成 Native Turn 的业务采集证据。runtime gate v2 新增成功
Turn Wire 与独立新鲜度要求，并保留 `session_delivery_claimed=false`；该修复尚未部署。
未修改 Stock Codex 的同等两轮证据、真实 Alibaba OSS 账户和
18086 平台服务仍未完成验收。18084/Collector/Relay 的传输健康和 `pending=0` 不能替代逐 Session 的
Turn 来源覆盖；历史通过的 v1 长任务也必须从原始 Raw 按当前 v2 门槛重验。GitHub CI 会把
门禁摘要作为 `native-canary-gate-report` artifact 保存，方便审查者核对这一区分。

## 历史数据

历史数据可以重放现有真实字段。只有原始 Wire、Stock Codex OTLP/Hook 或其他同源运行时
证据仍存在时，才能通过精确 Join 补齐。缺少原始请求字节、生命周期、真实工具结果或
Schema 的历史 Session 保持 partial；不能通过清洗推断成合格数据。
