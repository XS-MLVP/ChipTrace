# 芯迹（ChipTrace）

<p align="center">
  <a href="https://github.com/XS-MLVP">
    <img src="docs/assets/xs-mlvp-avatar.png" alt="万众一芯团队" width="96">
  </a>
</p>

<p align="center">
  <a href="https://github.com/XS-MLVP"><strong>万众一芯团队</strong></a>
  ·
  <a href="https://open-verify.cc/">官方网站</a>
</p>

面向芯片行业代码 Agent 的 Trace 采集与训练数据验收框架。ChipTrace 在云端保存 Stock
Codex 的 Responses Wire、原生 OTLP 和生命周期 Hook，组装完整 Session，并只交付通过
Buyer v7 硬门槛的 UTF-8 JSONL `tar.gz`。

最新维护状态（2026-10-20 03:21，Asia/Shanghai）的代码基线为 [`bde52f4`](https://github.com/XS-MLVP/ChipTrace/commit/bde52f454d19a386e56d2288132587ef937e750d)。
维护分支与 `origin/fix/oss-disk-session-platform` 的 SHA 一致；工作区只保留三份外部 DOCX
作为未跟踪的需求原件，没有改写或纳入仓库。`make check`、`make test`、Codex 配置契约和
质量/部署门禁契约均在本机通过。GitHub CLI 未认证且 Actions API 当前超时，远端运行结果仍
不可观测，不能用本地通过替代 GitHub 证据。

最新线上只读采样中 18084、3011、3012、18086 的 `/health` 均返回 HTTP 200；Collector
队列为 0 且 ready，Relay `delivered=1,338,902`、`pending=0`、`inflight=0`、`failed=0`、
`conservation_ok=true`。这些证据说明 Raw/WAL 接收、恢复和投递守恒正常，不能据此宣称业务
Session/Turn 已就绪。

业务门禁仍未通过：Relay `/ready` 返回 HTTP 503，持久 `quality_errors=8,684`
（`otlp_traces.identity_conflict=184`、`invalid_lifecycle=6,529`、
`legacy_unclassified=1,965`，另有 Hook `conversion_error=6`），`missing_sources=["wire"]`、
`wire.requests=0`、`successful_turn_scoped_captures=0`、`turn_capture_ready=false`。
当前 `/etc/codex/config.toml` 与实际 `CODEX_HOME/config.toml` 的静态路由预检已对同一网关退出 0，
但尚未由真实新进程产生可验收的 Wire。18084 的 payload 脱敏仍关闭并保留 293 个历史失败文件；Platform 健康虽为 200，实际后端仍是
`fs`。真实 OSS 上传/恢复/远端哈希、未修改 Stock Codex 多轮四源 Canary 和同 SHA 远端 CI
尚未验收，当前只能用于内部 Raw/恢复验证，不能作为外部 MaaS 交付服务。

历史线上只读快照（2026-10-19 09:01:42，Asia/Shanghai）确认 18084、3011、3012、18086 的
`/health` 均返回 HTTP 200，但 Relay `/ready` 返回 HTTP 503。Collector/Relay
revision 为 `db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，Collector Capture 与 Relay Delivered
均为 `1,291,300`，`pending=0`、`inflight=0`、`failed=0` 且计数守恒；Collector 队列为 0 且 ready。
Gateway full-trace outbox 的 pending/processing/最近失败均为 0，293 个历史失败原件仍有恢复凭据且
未解决数为 0。Relay delivery retries 累计为 83，持久质量账本为 `6,506`（182 个身份冲突、4,359
个生命周期冲突、1,965 个旧账本未分类），本进程新增 984；Wire 请求和成功的逐 Turn Wire 均为 0，
缺失且过期来源为 `wire`，`turn_capture_ready=false`。Platform 运行 revision 仍为旧版本，健康响应
没有 `backend` 字段，容器环境实际为本地 `fs`；要求 `oss` 的 platform health gate 真实退出 1。
随后 runtime gate 采样到质量计数 `6,515` 并真实退出 1。当前适合内部 Raw/恢复验证，尚未达到对外
承诺完整 Session/Turn 采集、真实 OSS 和在线导出的生产标准。

历史线上只读快照（2026-10-19 06:07:26，Asia/Shanghai）确认 18084、3011、3012、18086 的 `/health` 均返回
HTTP 200，但 Relay `/ready` 返回 HTTP 503；Collector、Relay 和平台实际已运行维护提交
`db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，使用内容寻址镜像、非 root、只读根和持久目录。
该时刻 Collector 与 Relay 均为 `1,278,543` 条，`pending=0`、`failed=0`、`conservation_ok=true`，
Collector 队列深度为 0、ready；`inflight` 随持续流量瞬时变化。Gateway outbox 当前 pending/processing/recent
failure 均为 0，历史失败原件和 recovery receipt 仍保留且未解决数为 0。

业务门禁仍未通过：Relay `/ready` 返回 HTTP 503，`ingest_coverage.status=degraded`，持久
`quality_errors=5525`，全部来自 `otlp_traces`，其中 `identity_conflict=182`、`invalid_lifecycle=3378`、
旧账本无法回溯的 `legacy_unclassified=1965`；本次进程质量错误为 3，Raw 仍保留。当前仍未观察到 Wire，
`missing_sources=["wire","hooks"]`、`stale_sources=["wire"]`、`successful_turn_scoped_captures=0`、
`turn_capture_ready=false`，带质量、新鲜度和来源门禁的 runtime gate 真实退出 1。Platform health gate
以该 revision 真实通过，但平台后端仍是本地 FS；18084 trace exporter 关闭，Gateway full-trace outbox 已接受 2 条。
真实 Alibaba OSS 提交/恢复/远端对象哈希及未修改 Stock Codex 多轮 Canary 尚未完成。因此当前可用于内部传输与恢复验证，
不能对外承诺完整 Session/Turn 采集或生产 OSS 导出。详见[生产就绪评估](docs/production-readiness.md)。

维护分支的原生启动护栏已在 `266bded` 加强：CI 在长时 Producer Canary 前会实际进入 Bubblewrap
namespace，并验证只读根、私有 `/etc` 与私有可写 `/tmp`。本机探针和 21 项原生上下文/沙箱测试已通过；
远端 Actions 仍需用对应提交的真实 run 复核，不能把本地通过当作远端发布证据。

## 主线

```mermaid
flowchart LR
    A[Stock Codex] -->|Responses / OTLP / Hooks| B[18084]
    B --> C[Relay / WAL]
    C --> D[OSS Raw]
    D --> E[Cloud Acceptance]
    E -->|score >= 90| F[Buyer JSONL tar.gz]
    E --> G[OTLP / Langfuse]
```

用户主机不运行 ChipTrace 程序。管理员下发 Stock Codex 原生
[配置与 required Hooks](integrations/codex/README.md)，用户继续直接运行 `codex`。
Wire、OTLP 和 Hook 使用 Stock Codex 自带的 Session、Turn、call ID 和 W3C Trace Context
精确关联；缺失或冲突时拒绝交付，不补造 Schema、状态、模型身份或任务边界。

当前真实客户端仍有未归属的 SSE 日志和 span，完整 v2 交付尚未通过真实验收。
已验证的能力与剩余来源上下文缺口见[原生 Turn 验收记录](docs/native-turn-context.md)。
`audit-session-context` 提供只读的上下文缺口统计和有界定位样本；CI 使用精简的真实
客户端元数据回归，完整对话和原始取证档保留在运维侧。

2026-10-16 18:42（Asia/Shanghai）的线上快照已将 Collector、Relay 和平台服务升级到维护
提交 `30f6d243d527732acbfae4970a740ec88c8451cf`：三个容器均使用内容摘要镜像、非 root、只读根、
资源限额和持久 NFS 挂载，18084、3011、3012、18086 均返回 200。Collector/Relay 队列为空且
计数守恒，平台已通过鉴权健康检查；平台当前实际后端是本地 FS，尚未接入真实 OSS。
同一窗口的 runtime gate 真实退出 1：Relay/Collector revision 均为该提交，Collector 与 Relay
均为 `1,164,002` 条且 pending/inflight/failed 为 0，但 Relay 的 Wire 只有 4 条、成功的
逐 Turn HTTP 2xx 为 0，Wire 已落后约 31.5 分钟，覆盖为 `degraded`。因此当前部署不能声称
已完成任意 Session 的逐 Turn 全量交付。

截至 2026-10-15，最新隔离的 patched Canary 已用真实 `0.163.0-alpha.11` 上游客户端完成
两个 Native Turn、resume、失败工具进程和延迟 `write_stdin` 场景；四路来源齐全，审计
计数守恒，仓库门禁输出 `native_turns=2`、`selected_audit_records=3621`、
`delivery_ready=true`。这是带生产者上下文补丁的隔离证据，不是未修改 Stock Codex 的发布
证明；脱敏 fixture 只保存元数据，不包含 Raw 或对话正文。

此前复查确认 Collector/Relay 曾运行 revision
`fe9fcf924b226099202cb770b7cf0da29e0c2310`，18084、3011、3012 返回 200；传输队列排空且
`conservation_ok=true`。新 Relay 进程内仅有 1 条 Wire；只读活动 WAL 快照确认它是没有
原生 Session/Turn 的 HTTP 403，不能作为真实 Turn 的采集证据。OTLP/Hook 仍有流量，
随后 Wire 超过 5 分钟未更新，runtime gate 真实退出 1。18084 保留 293 个历史失败文件
（约 267 MB），trace exporter 未启用，
watchdog 仍有错误；18086 当时没有监听。已核验基线 `08cadf5` 的远端 CI 已确认 5/5 作业通过，覆盖
原生 Hook 持久化确认、生产者缓存、流式下载及图片/计划/五类真实工具的双轮 resume 采集；
新增原生协议采集使用带补丁生产者和合成模型，不替代线上验收。
2026-10-16 新执行的同模型双轮协议联测已贯通 FS 归档、恢复和 Buyer 下载，实际解包
复核两轮、12 次请求引用与全部工具结果；模型切换、取消和断流保留独立拒绝回归。
正向数据 score=100，仍是合成模型与带补丁生产者的实现证据，详见生产就绪评估。
独立手动压缩的新采集已验证摘要跨后续轮次和新进程恢复，归档、恢复、投影下载和重启
检查通过；内联压缩和缺少边界 Hook 仍拒绝交付。该修复尚未部署，详见同一评估。
自动压缩新联测还覆盖轮前、轮中、轮后和跨进程恢复；缺失压缩生命周期时，即使业务
Stop 和四源存在也拒绝完整交付，原始失败证据保留。验证范围与限制见同一评估。
真实 OSS 账号及未修改客户端的 v2 多轮验收仍未完成，因此尚不能按生产就绪对外交付。
2026-10-16 另用官方未修改 `0.163.0` 新执行双轮采集，四源和协议完整，但来源上下文
仍有缺口，交付检查实际失败。CI 新增固定官方二进制的独立诊断；诊断成功仅表示复现
了拒绝，报告始终不声明生产就绪，详见同一评估及[验证命令](docs/native-turn-context.md)。

接入排查还复现了系统默认 Provider 被用户配置覆盖、使 Wire 绕过采集的风险。
受管 requirements 模板现已强制 Provider 选择和完整网关定义，并增加固定版本未修改
客户端的断网配置回归；部署方式和能力边界见 [Stock Codex 接入](integrations/codex/README.md)。
线上主机的实际用户级配置仍存在 Provider 覆盖风险，不能视为线上 Wire 已恢复；当前 runtime
gate 的 Wire/Hook 缺失正是该风险的可观测结果。
仓库 runtime gate v3 另要求近期有明确 Session/Turn、无上下文冲突的 HTTP 2xx Wire，
并拒绝缺少该统计的旧 Relay；重复投递不能刷新这类证据。完整评估和发布条件见
[生产就绪评估](docs/production-readiness.md)。维护分支包含该门禁；线上是否生效必须用实际
部署 revision 运行 runtime gate 核对，不能按分支或历史提交号推断。当前真实失败仍须在受管
Provider 和完整 Hook 生效后重新验收。

## 构建

要求 Rust 1.91+。

```bash
cargo build --release --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
make m0-test
```

## 验收

`cloud-acceptance` 是唯一采购验收入口。它从已提交 Raw Archive 开始，依次复验原始对象、
Sub2API 精确路由、Canonical Schema、OTLP 树、Session、Buyer v7、Release 和采购包；任一
步骤失败即返回非零状态。

```bash
chiptrace cloud-acceptance \
  --archive-id raw-20260902-01 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket trace-dataset \
  --prefix chiptrace \
  --usage-log /srv/sub2api/usage.jsonl \
  --session-id <stock-codex-session-id> \
  --release-id release-20260902-01 \
  --output /srv/chiptrace/acceptance/release-20260902-01
```

通过结果必须同时满足：`delivery_ready=true`、有效轮次不少于 10、不同工具不少于 5、
完整工具定义不少于 5、去尾配对率 100%、Buyer v7 分数不低于 90、全部 hard gate 通过、
OTLP 单根且内部父引用全部可解析。

## 文档

- [架构](docs/architecture.md)
- [部署与运维](docs/operations.md)
- [数据契约](docs/data-contract.md)
- [验收矩阵](docs/acceptance-matrix.md)
- [生产就绪评估](docs/production-readiness.md)
- [业务采集数据符合性评估](docs/business-data-assessment.md)
- [交付格式](docs/delivery.md)
- [外部 MaaS request 级交付](docs/maas-delivery.md)
- [OpenAPI](schemas/openapi.yaml)
- [云平台嵌入插件](integrations/cloud-platform/README.md)
- [生产者支持策略](integrations/codex/producer-support.json)
- [Provider Responses 前置门禁](docs/operations.md#provider-responses-前置门禁)

## 磁盘恢复与平台嵌入

原始 sealed WAL 以 Manifest + Checkpoint 提交到 FS、OSS 或 S3。平台插件在服务端固定对象
存储配置，先将提交的 Raw 恢复到受保护的本地工作目录，再按页提供原生 Session/Turn，
并只下载经过完整校验的 Buyer 包。插件的 ACK、任务状态、Turn sidecar 和输出校验均落到
磁盘；服务重启会重新排队未完成任务。平台 API、Node SDK、容器镜像和 Compose 示例见
[cloud-platform](integrations/cloud-platform/README.md)。
Turn 分页保持原 JSON 格式，校验后流式返回完整选中记录；`streamTurns` 可流式读取分页，
`downloadTurns` 可下载全量 JSONL。对象形式的 `getTurns` 仍需由调用者容纳所选数据。

## 许可证

本项目使用 [Apache License 2.0](LICENSE)。
