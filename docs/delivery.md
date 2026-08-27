# JSONL 与对象存储交付

## 本地 Release

`chiptrace release` 只输出 UTF-8 JSONL 数据、逐 Session 验收报告和校验文件：

```text
release/
├── data/
│   └── sessions-part-00001.jsonl.zst
├── reports/
│   ├── assessments-part-*.jsonl.zst
│   └── divergent-sessions.jsonl.zst
├── manifest.json
└── SHA256SUMS
```

每条数据行为一个完整 Session。Session 不跨 Part；单条 Session 大于目标分片
时生成独立超限 Part，并在 Manifest 标记。`.jsonl.zst` 是 zstd 压缩的标准
UTF-8 JSONL，解压后每行均可独立解析。

生成 buyer-v7、90 分准入集：

```bash
chiptrace assemble \
  --input /srv/chiptrace/capture/segments \
  --output /srv/chiptrace/assembly \
  --partitions 256

chiptrace release \
  --input /srv/chiptrace/assembly \
  --output /srv/chiptrace/release-v1 \
  --release-id chiptrace-20260827-v1 \
  --profile buyer-v7 \
  --minimum-score 90 \
  --target-part-gib 10 \
  --dedup-partitions 256 \
  --workers 16

chiptrace verify-release \
  --release /srv/chiptrace/release-v1 \
  --require-pass
```

目录输入只读取已封存的 `.sealed.ndjson`；仍在写入的 `.open.ndjson` 会被跳过。
需要纳入当前段时先调用 Collector 的 `POST /flush`，再启动 Assembly。

`reports/assessments-part-*.jsonl.zst` 包含每条去重 Session 的完整 Gate、失败原因、
三类质量结果和 Token，字段遵循 `schemas/assessment-v1.schema.json`。`data/`
只包含 `eligible=true` 的 Session。

## 发布协议

对象键布局：

```text
<prefix>/
├── .staging/<release_id>/<manifest_sha256>/
│   ├── data/*.jsonl.zst
│   ├── reports/*.jsonl.zst
│   ├── manifest.json
│   └── SHA256SUMS
└── releases/<release_id>/COMMIT.json
```

`COMMIT.json` 最后创建，列出每个对象的 key、字节和 SHA-256。重复执行相同
Release 为幂等成功；同一 release_id 的不同 Manifest 会被拒绝。消费端先读取
COMMIT，再按其引用读取对象，不通过 OSS LIST 推断 Release 是否完整。

OSS 凭据使用标准环境变量：

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID='...'
export ALIBABA_CLOUD_ACCESS_KEY_SECRET='...'

chiptrace publish \
  --release /srv/chiptrace/release-v1 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace \
  --file-concurrency 8 \
  --multipart-concurrency 8 \
  --multipart-chunk-mib 16
```

S3 使用 `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、可选
`AWS_SESSION_TOKEN`：

```bash
chiptrace publish \
  --release /srv/chiptrace/release-v1 \
  --backend s3 \
  --bucket example-bucket \
  --region us-east-1 \
  --prefix datasets/chiptrace
```

本地对象目录可用于离线验收：

```bash
chiptrace publish \
  --release /srv/chiptrace/release-v1 \
  --backend fs \
  --root /srv/object-store \
  --prefix datasets/chiptrace \
  --verify-remote-sha256
```

默认上传后校验远端对象长度，Manifest 保存本地 SHA-256。使用
`--verify-remote-sha256` 会完整回读远端对象，获得更强校验但使网络流量接近
两倍。
