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

同日线上只读检查显示 18084、3011、3012 返回 200，Relay 已投递 1,021,950 条且
`pending=0`、`failed=0`、`conservation_ok=true`，但 Collector/Relay 仍运行旧镜像
`chiptrace:0.6.0-readiness-r2-20260905`。18084 报告有 3 个 open transaction、293 个
历史失败文件（约 267 MB），旧 Relay 的 freshness 检查仍显示 `freshness_applicable=false`；
18086 当前没有监听。因而传输闭环可用不等于每个 Session 已达到可交付标准，最新分支修复
仍需先完成远端 CI、真实 OSS 账号验收和隔离 Canary 后再部署。

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
- [交付格式](docs/delivery.md)
- [OpenAPI](schemas/openapi.yaml)
- [云平台嵌入插件](integrations/cloud-platform/README.md)

## 磁盘恢复与平台嵌入

原始 sealed WAL 以 Manifest + Checkpoint 提交到 FS、OSS 或 S3。平台插件在服务端固定对象
存储配置，先将提交的 Raw 恢复到受保护的本地工作目录，再按页提供原生 Session/Turn，
并只下载经过完整校验的 Buyer 包。插件的 ACK、任务状态、Turn sidecar 和输出校验均落到
磁盘；服务重启会重新排队未完成任务。平台 API、Node SDK、容器镜像和 Compose 示例见
[cloud-platform](integrations/cloud-platform/README.md)。

## 许可证

本项目使用 [Apache License 2.0](LICENSE)。
