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

面向芯片行业 Agent 的 Trace 采集与训练数据治理框架。项目由单一 Rust
二进制提供可靠采集、Session DAG 组装、版本化验收、JSONL 分包和 OSS/S3
发布能力。

## 功能

- Collector：JSON/NDJSON 接收、分片 WAL、redb ledger、幂等与崩溃恢复。
- Relay：本地 durable outbox、批量续投、背压、取消/失败/重试完整保留。
- Trajectory：Session 边界、response DAG、root/subagent DAG 和工具执行状态。
- Quality：`buyer-v6` / `buyer-v7` 硬门槛、90 分准入、语义证据与 Token 分类。
- Delivery：Session 原子 `JSONL.zst`、去重、Manifest、SHA-256 和 OSS/S3 提交。

## 构建

要求 Rust 1.91+。

```bash
cargo build --release --locked
cargo test --workspace --all-targets --locked
target/release/chiptrace self-test
```

## 采集

启动 Collector：

```bash
target/release/chiptrace collector \
  --root /srv/chiptrace/capture \
  --state-root /var/lib/chiptrace/state \
  --host 127.0.0.1 \
  --port 3010
```

单条入口为 `POST /capture`；高吞吐入口为 `POST /captures`，请求体使用
`application/x-ndjson`，每行一个 Capture：

```bash
curl --fail-with-body http://127.0.0.1:3010/captures \
  -H 'content-type: application/x-ndjson' \
  --data-binary @captures.jsonl
```

需要跨进程可靠投递时启动 Relay：

```bash
target/release/chiptrace relay \
  --root /var/lib/chiptrace/outbox \
  --state-root /var/lib/chiptrace/outbox-state \
  --delivery-state-root /var/lib/chiptrace/delivery \
  --collector-url http://127.0.0.1:3010 \
  --host 127.0.0.1 \
  --port 3011
```

## 交付

```bash
target/release/chiptrace assemble \
  --input /srv/chiptrace/capture \
  --output /srv/chiptrace/assembly

target/release/chiptrace release \
  --input /srv/chiptrace/assembly \
  --output /srv/chiptrace/release-v1 \
  --release-id chiptrace-20260827-v1 \
  --profile buyer-v7 \
  --minimum-score 90 \
  --target-part-gib 10 \
  --workers 16

target/release/chiptrace verify-release \
  --release /srv/chiptrace/release-v1 \
  --require-pass

target/release/chiptrace publish \
  --release /srv/chiptrace/release-v1 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace
```

OSS 凭据从 `ALIBABA_CLOUD_ACCESS_KEY_ID`、
`ALIBABA_CLOUD_ACCESS_KEY_SECRET` 和可选的
`ALIBABA_CLOUD_SECURITY_TOKEN` 读取。

```text
release-v1/
├── data/sessions-part-*.jsonl.zst
├── reports/assessments-part-*.jsonl.zst
├── manifest.json
└── SHA256SUMS
```

## 文档

- [架构与性能](docs/architecture.md)
- [数据与评分契约](docs/data-contract.md)
- [JSONL 与对象存储交付](docs/delivery.md)
- [部署与运维](docs/operations.md)
- [OpenAPI](schemas/openapi.yaml)

## 许可证

本项目使用 [Apache License 2.0](LICENSE)。
