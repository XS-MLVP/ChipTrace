# 生产就绪评估

评估日期：2026-10-15。首次线上读取窗口为 10:53–10:59（Asia/Shanghai），11:26 再次只读复查。
结论：具备可靠采集与离线验收的基础，可开展受控试用；当前部署尚未达到向他人承诺
原生 Turn 全量采集、远端持久保存和在线导出的发布条件。

## 当前部署证据

| 项目 | 实际观察 | 能证明的范围 |
| --- | --- | --- |
| 18084、3011、3012 | HTTP 200 | 入口与采集进程存活 |
| Collector/Relay | revision `fe9fcf924b226099202cb770b7cf0da29e0c2310` | 运行版本已固定；仓库新增修复尚未部署 |
| 投递 | 同一快照已投递 1,034,159 条，pending/inflight/failed 为 0，计数守恒 | 累计传输闭环；不能当作并发压测结果 |
| Collector 磁盘 | 724 个 sealed Segment，79,568,736,213 bytes；活动段仍在增长 | 云端本地 WAL 持续保存；不能证明 OSS 已提交 |
| Wire | 新进程内仅 1 条；活动 WAL 中为无原生 Session/Turn 的 HTTP 403 | 无真实成功 Turn Wire 的证据 |
| 来源新鲜度 | OTLP/Hook 有流量，Wire 超过五分钟未更新；runtime gate 实际退出 1 | 当前采集覆盖降级 |
| 历史失败 | 293 个文件，267,219,223 bytes | 保留失败取证，不能删除换取健康状态 |
| 平台 18086 | 无法连接 | 当前无法交接在线管理、导出入口 |
| 部署隔离 | Relay 要求 ingest token；Collector/Relay 绑定 loopback；两容器有重启策略 | 有内部入口保护；两容器尚无内存/CPU 上限或只读根文件系统 |
| GitHub CI | `9510758` 的 [run 38676531074](https://github.com/XS-MLVP/ChipTrace/actions/runs/38676531074) 已确认 5/5 作业成功 | 覆盖 Process 冲突修复这一 SHA；不能代替后续提交或线上验收 |

11:26 复查时三个既有服务仍返回 HTTP 200，Relay 已投递 1,036,522 条，pending 为 1、
inflight/failed 为 0、计数守恒。持续流量下瞬时 pending 不能单独判定积压故障。
OTLP logs/traces 与 Hook 仍更新，Wire 仍只有 1 条，约 43 分钟未更新，覆盖仍为
`degraded`；18086 连接被拒绝。同一轮 runtime gate 真实退出 1，首个失败项为网关
`rustRelay.inflight must be zero`，该瞬时门禁结果不取代来源新鲜度或逐 Session 审计。

Wire 诊断只读取活动段打开时的固定长度快照：439,333,206 bytes、2,826 条完整记录、
1 条 Wire，没有复制或输出对话正文。它是故障定位证据，不是从 Segment 1 开始的完整
sealed Archive 验收。全局四源门禁在该 403 到达后曾短暂通过；该结果不构成业务采集
成功。runtime gate v2 已在仓库加入独立 Turn Wire 证据要求，线上旧镜像尚无该统计。

本轮 Process scope 冲突修复的 `make cloud-test` 实际退出 0，覆盖 fmt/Clippy、275 个 Rust 库测试、CLI、
网关、原生上下文、Canary/runtime 门禁及平台 HTTP/SDK 的归档、恢复、导出和 OSS 协议
回归。Rust 和 CLI 新增用例拒绝七类 Turn 业务事件直接或沿父链声明 Process scope 的
14 种组合；合法 Process 记录仍在真实 patched Raw 回放中保留，原始 SHA-256 不变。
此前的 runtime gate 回归覆盖单条、批量部分 ACK、重复、冲突、不可用和成功证据过期。
`make m0-test` 也实际退出 0：独立镜像 `chiptrace:m0-process-scope-canary` 在断网、只读
根文件系统及非 root 用户下完成自测；构建标记为 `working-tree-process-scope-guard`，未替换线上镜像。
这些隔离实现回归不改变上述线上、未修改生产者或真实 OSS 账号的验收状态。

后续只读回放又确认检查入口的误报：历史样本存在 2 条日志和 84 个 span 的未知 Session
身份，旧 `inspect-session` 顶层仍返回可交付。修复后检查入口复用同快照的来源审计，
完整状态为 false；完全没有身份的独立 OTLP batch 也逐批计入审计，正文不因此留在
Canonical 投影内存集合中。平台分页增加总交付状态，完整性不足的导出继续真实失败。
原始 Raw 与合格 patched Canary 均保留，回放前后哈希不变。线上尚未加载这些修复。
该检查修复的本地 `cloud-test` 已通过，包含 275 个 Rust 库测试、1 个 CLI 测试、
7 个原生上下文 CLI 测试和 7 个平台/OSS 协议测试。独立镜像
`chiptrace:m0-source-audit-canary` 的 `m0-test` 实际退出 0，构建标记为
`working-tree-source-audit-inspection`。历史任务重启后的缺少审计和状态与审计冲突用例也通过，
历史任务文件保持原样；这些实现回归不证明线上或真实 OSS 已验收。
本地复跑还记录过一次 outbox 测试 18/19 通过、`make` 退出 2；随后独立 outbox 回归
19/19 和完整 `cloud-test` 均通过，测试条件未放宽。原失败的断言细节未被当时的摘要
保留，原因尚未定位，需继续跟踪；后续摘要已保留失败测试名称和完整断言块。

## 已有优势

- Wire、OTLP logs、OTLP traces 和 Hook 按原生身份精确关联，覆盖请求、工具定义、
  工具真实输出、进程失败、异步工具与 Session/Turn 生命周期；不按时间猜轮次。
- 网关磁盘 outbox、Relay/Collector WAL、幂等和计数守恒提供可追溯的 ACK；失败与未完成
  事实继续保存。用户主机不需要运行 ChipTrace 服务。
- sealed Segment、SHA-256、Manifest 和最后提交的 Checkpoint 支持可校验归档与磁盘恢复。
  FS、S3 和 OSS 走统一适配层；真实目标账号仍需独立验收。
- `cloud-acceptance` 将字节完整性、协议终态、工具配对、逐 Turn 来源与 Buyer 门槛分别
  检查；旧产物和带补丁的 Canary 不能自动成为当前生产验收证据。
- 云平台插件已有任务落盘、重启重排队、Session/Turn 分页、交互投影及校验后下载接口。
  它适合作为主平台后端组件，终端用户鉴权与租户授权由主平台负责。

## 迭代顺序与发布条件

| 优先级 | 工作 | 完成证据 |
| --- | --- | --- |
| P0 | 应用受管 Provider 路由约束，恢复真实 Wire | 新客户端普通任务经 18084；Wire 含原生 Session/Turn；新 runtime gate 通过 |
| P0 | 获得符合 v2 上下文契约的未修改生产者版本 | 真实第二轮、resume、失败工具及延迟 `write_stdin`；`unscoped=0`；`--require-unmodified-stock` 通过 |
| P0 | 在目标 OSS 账号验收存储、恢复与交付 | 连续 sealed Archive 上传、Checkpoint、逐对象校验、恢复、损坏拒绝、Buyer 包下载复验 |
| P0 | 发布平台服务 | 18086/API 可访问；通过主平台身份鉴权完成一次真实采集到导出下载 |
| P1 | 固定发布与回滚流程 | 对应 SHA 的远端 CI 全绿；同 revision 镜像；隔离 Canary、升级、重启与回滚复验 |
| P1 | 容量、告警与恢复演练 | 明确峰值、保留周期、云端临时磁盘配额、积压告警与恢复时间/数据损失目标，并实测故障恢复 |
| P1 | 企业数据治理 | 项目命名空间、主平台租户授权、访问审计、脱敏策略与下载确认后的保留/删除规则验收 |
| P2 | 大数据量处理 | 为 Session/Turn 建持久索引；减少两遍 Raw 扫描及分页 sidecar 重扫，记录大归档内存/时间/磁盘指标 |

未修改 Stock Codex 的当前多轮生产验收仍缺证据；已有五个 producer 补丁的隔离 Canary
证明修复方向可行，但不能替代该条件。受管路由模板也尚未应用到系统配置。
纯云端采集无法恢复客户端未发送成功的事件：运行中断网造成缺失时，应保留 partial 状态，
按原生重试能力恢复，不能补造记录或承诺任意网络条件下绝不丢失。

发布必须同时通过运行状态、原生生产者、真实存储账号、逐 Session 验收和平台交付验证。
新 runtime gate 的 HTTP 2xx 只证明有归属的请求获得 HTTP 成功状态，仍输出
`session_delivery_claimed=false`。完整规范与命令见[验收矩阵](acceptance-matrix.md)、
[运维说明](operations.md)和[平台维护流程](platform-maintenance.md)。
