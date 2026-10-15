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

截至 2026-10-15，最新隔离的 patched Canary 已用真实 `0.163.0-alpha.11` 上游客户端完成
两个 Native Turn、resume、失败工具进程和延迟 `write_stdin` 场景；四路来源齐全，审计
计数守恒，仓库门禁输出 `native_turns=2`、`selected_audit_records=3621`、
`delivery_ready=true`。这是带生产者上下文补丁的隔离证据，不是未修改 Stock Codex 的发布
证明；脱敏 fixture 只保存元数据，不包含 Raw 或对话正文。

同日复查确认 Collector/Relay 已运行 revision
`fe9fcf924b226099202cb770b7cf0da29e0c2310`，18084、3011、3012 返回 200；传输队列排空且
`conservation_ok=true`。新 Relay 进程内仅有 1 条 Wire；只读活动 WAL 快照确认它是没有
原生 Session/Turn 的 HTTP 403，不能作为真实 Turn 的采集证据。OTLP/Hook 仍有流量，
随后 Wire 超过 5 分钟未更新，runtime gate 真实退出 1。18084 保留 293 个历史失败文件
（约 267 MB），trace exporter 未启用，
watchdog 仍有错误；18086 没有监听。已核验基线 `3ebb0c4` 的远端 CI 已确认 5/5 作业通过，覆盖
原生 Hook 持久化确认、生产者缓存、流式下载及图片/计划/五类真实工具的双轮 resume 采集；
新增原生协议采集使用带补丁生产者和合成模型，不替代线上验收。
2026-10-16 新执行的同模型双轮协议联测已贯通 FS 归档、恢复和 Buyer 下载，实际解包
复核两轮、12 次请求引用与全部工具结果；模型切换、取消和断流保留独立拒绝回归。
正向数据 score=100，仍是合成模型与带补丁生产者的实现证据，详见生产就绪评估。
真实 OSS 账号及未修改客户端的 v2 多轮验收仍未完成，因此尚不能按生产就绪对外交付。

接入排查还复现了系统默认 Provider 被用户配置覆盖、使 Wire 绕过采集的风险。
受管 requirements 模板现已强制 Provider 选择和完整网关定义，并增加固定版本未修改
客户端的断网配置回归；部署方式和能力边界见 [Stock Codex 接入](integrations/codex/README.md)。
这项模板修复尚未应用到线上主机，不能视为线上 Wire 已恢复。
仓库 runtime gate v2 另要求近期有明确 Session/Turn、无上下文冲突的 HTTP 2xx Wire，
并拒绝缺少该统计的旧 Relay；重复投递不能刷新这类证据。完整评估和发布条件见
[生产就绪评估](docs/production-readiness.md)。该门禁修复尚未部署到上述线上 revision。

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
- [交付格式](docs/delivery.md)
- [OpenAPI](schemas/openapi.yaml)
- [云平台嵌入插件](integrations/cloud-platform/README.md)

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
