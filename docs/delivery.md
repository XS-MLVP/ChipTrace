# JSONL 与对象存储交付

原始证据先在 Collector 本地 WAL 中完成 durable ACK，再封存进入 OSS Raw Zone，随后由 Release 投影为采购数据。Raw Zone 的 Segment、
Manifest 和 Checkpoint 协议见 [OSS 原始层与提交协议](object-storage.md)。Release
只读取 Checkpoint 已提交的 `complete` 快照；`partial` 取证快照不能作为全量交付。

## 内部 Release

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

生成 `buyer-v7-codex-runtime-expanded`、90 分准入集：

```bash
chiptrace restore-raw-archive \
  --archive-id chiptrace-20260827-1800 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace \
  --output /srv/chiptrace/restored/capture

chiptrace enrich \
  --input /srv/chiptrace/restored/capture \
  --usage-log /srv/sub2api/usage-logs.jsonl \
  --output /srv/chiptrace/enriched

chiptrace verify-enrichment \
  --enrichment /srv/chiptrace/enriched

chiptrace assemble \
  --input /srv/chiptrace/enriched \
  --output /srv/chiptrace/assembly \
  --partitions 256

chiptrace release \
  --input /srv/chiptrace/assembly \
  --output /srv/chiptrace/release-v1 \
  --release-id chiptrace-20260827-v1 \
  --profile buyer-v7-codex-runtime-expanded \
  --minimum-score 90 \
  --target-part-gib 10 \
  --dedup-partitions 256 \
  --workers 16

chiptrace verify-release \
  --release /srv/chiptrace/release-v1 \
  --require-pass
```

Sub2API PostgreSQL 的最小 JSONL 导出使用
[`integrations/sub2api/export-usage.sql`](../integrations/sub2api/export-usage.sql)，不应把数据库
全表、凭据或请求正文复制进 Release 工作目录。

`enrich` 不修改 Raw 恢复目录；它只按上游 request ID 或 Sub2API 的
`client:<X-Client-Request-ID>` 规则生成版本化投影。未命中和歧义记录仍原样输出，
但没有 `proxy_route_verified`，不能靠模型名推断通过 expanded Profile 的模型门槛。

目录输入只读取已封存的 `.sealed.ndjson`；如果发现非空的仍在写入
`.open.ndjson`，`archive-raw` 会直接失败而不会静默跳过活动尾段。`POST /flush`
后产生的零字节 open 占位文件会被忽略。需要纳入当前段时先调用 Collector 的
`POST /flush`，再启动归档和 Assembly；对明确的历史文件集可以将 sealed 文件
逐个作为 `--input` 传入。

`reports/assessments-part-*.jsonl.zst` 包含每条去重 Session 的完整 Gate、失败原因、
采购 Gate、附加完整性/语义观测和 Token，字段遵循
`schemas/assessment-v2.schema.json`。每条 Assessment 分别保存 `delivery_ready`、
`training_ready` 与 `buyer_eligible`；`data/` 只包含三者均通过且
`buyer_acceptance.eligible=true` 的 Session。

若输入来自 OSS Raw Zone，Release Manifest 的 `raw_sources` 保存原始 Checkpoint、
Manifest 的对象键和 SHA-256，采购包的 `source_release_manifest_sha256` 继续绑定
该来源链。

生产交付必须从 `completeness=complete` 的 Raw Checkpoint 恢复并生成
`raw_sources`。`package-buyer` 默认拒绝没有 lineage 的 Release；旧本地 Assembly
只能显式使用 `--allow-legacy-lineage` 做迁移或内部回归，不应作为对外采购包。
发布到 OSS 时默认回读并校验远端 SHA-256；正式验收不得使用
`--skip-remote-sha256`。

内部 Release 使用 zstd 提供高速去重、复验和对象发布，不直接作为采购方传输包。

## 采购方交付包

采购交付统一为 `tar.gz`，归档内为未二次压缩的 UTF-8 JSONL：

```bash
chiptrace package-buyer \
  --release /srv/chiptrace/release-v1 \
  --output /srv/chiptrace/buyer-v1 \
  --gzip-level 1 \
  --workers 16

chiptrace verify-buyer-package \
  --package /srv/chiptrace/buyer-v1
```

```text
buyer-v1/
├── packages/
│   └── sessions-part-00001.tar.gz
├── manifest.json
└── SHA256SUMS

sessions-part-00001.tar.gz
├── sessions.jsonl
├── PACKAGE.json
└── SHA256SUMS
```

`package-buyer` 只接受 `buyer-v7-codex-runtime-expanded`（或历史只读别名
`buyer-v7`）、`minimum_score >= 90`、Release 校验状态为
`pass` 且至少含一条准入 Session 的输入。它在临时目录并行流式转换，不生成
巨型中间 JSONL；完整解包、逐行 JSON 解析、Gate 一致性、记录数、Token 汇总和
SHA-256 全部通过后才原子发布目标目录。`verify-buyer-package` 执行相同的只读复验。
正式包的外层 Manifest 和归档内 `PACKAGE.json` 均标记
`lineage_status=complete`；历史迁移开关生成的 `legacy_unbound` 包只能内部使用，
默认校验命令会拒绝。
外层 Manifest 和归档内 `PACKAGE.json` 分别遵循
`schemas/buyer-package-v1.schema.json` 与 `schemas/buyer-archive-v1.schema.json`。

`--target-part-gib` 控制内部 Part 的未压缩 JSONL 目标大小，因此每个 Session
保持原子且不会跨包；最终 gzip 大小随语料压缩率变化。单条 Session 超过目标时
独占一个包。

## 统一对象发布协议

对象键布局：

```text
<prefix>/
├── raw/
│   ├── objects/<sha256>.ndjson
│   └── <archive_id>/{manifest.json,CHECKPOINT.json}
├── .staging/
│   ├── releases/<release_id>/<manifest_sha256>/...
│   └── deliveries/<release_id>/<manifest_sha256>/...
├── releases/<release_id>/COMMIT.json
└── deliveries/<release_id>/COMMIT.json
```

`COMMIT.json` 最后创建，列出每个对象的 key、字节和 SHA-256。重复执行相同
制品为幂等成功；同一命名空间和 release_id 的不同 Manifest 会被拒绝。内部
Release 与采购包分别位于 `releases` 和 `deliveries`，共享同一上传、重试、校验和
提交实现。消费端先读取 COMMIT，再按其引用读取对象，不通过 OSS LIST 推断完整性。
COMMIT 字段遵循 `schemas/object-commit-v1.schema.json`。

OSS 凭据使用标准环境变量：

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID='...'
export ALIBABA_CLOUD_ACCESS_KEY_SECRET='...'

chiptrace publish \
  --buyer-package /srv/chiptrace/buyer-v1 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace \
  --file-concurrency 8 \
  --multipart-concurrency 8 \
  --multipart-chunk-mib 16

chiptrace verify-published \
  --artifact-kind buyer-package \
  --artifact-id chiptrace-20260827-v1 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace
```

S3 使用 `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、可选
`AWS_SESSION_TOKEN`：

```bash
chiptrace publish \
  --buyer-package /srv/chiptrace/buyer-v1 \
  --backend s3 \
  --bucket example-bucket \
  --region us-east-1 \
  --prefix datasets/chiptrace
```

本地对象目录可用于离线验收：

```bash
chiptrace publish \
  --buyer-package /srv/chiptrace/buyer-v1 \
  --backend fs \
  --root /srv/object-store \
  --prefix datasets/chiptrace
```

`publish --release` 可归档内部 zstd Release；采购方只消费
`publish --buyer-package` 产生的 `deliveries/.../COMMIT.json`。`verify-published`
只读检查 COMMIT、Manifest 类型、对象集合、长度和完整 SHA-256；采购内容语义仍由
下载后的 `verify-buyer-package` 复验。

默认上传后校验远端对象长度和完整 SHA-256。受控 staging 若需要降低回读流量，
内部 Release 可显式使用 `--skip-remote-sha256`；采购包发布会拒绝该选项。
