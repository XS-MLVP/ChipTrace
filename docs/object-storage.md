# OSS 原始层与提交协议

本协议是 ChipTrace Raw Zone 的唯一对象存储实现；FS 后端只用于离线复现和自测。

ChipTrace 将原始 Trace 保存为一条逻辑连续日志，物理上由多个不可变 OSS/S3
对象组成。采集确认点仍是本地 durable WAL；对象存储只接收已封存的 Segment，
不参与在线请求的同步路径。

Collector 的 `redb` ledger 只是幂等、定位和恢复所需的本地运行状态，不是
交付数据源；Raw Segment、Release 和 Buyer 包均以 OSS 对象及其 Manifest/Checkpoint
为准。这样清理或迁移本地 ledger 不会改变已提交的交付内容。

## 方案选型

| 参考方案 | 已验证能力 | ChipTrace 采用方式 |
| --- | --- | --- |
| [OpenTelemetry Collector exporterhelper](https://github.com/open-telemetry/opentelemetry-collector/tree/main/exporter/exporterhelper) | 持久化 sending queue、批量、背压和失败重试 | Relay 本地 outbox、批量投递和有界资源 |
| [Vector disk buffer](https://vector.dev/docs/architecture/buffering-model/) | WAL、事件校验和重启恢复、容量上限 | Collector/Relay 的封存段、校验和、恢复语义 |
| [OpenTelemetry](https://opentelemetry.io/docs/specs/otel/trace/) / [OpenInference](https://github.com/Arize-ai/openinference) | trace/span/parent、Session、Agent/Tool 语义 | `task_session_id`、DAG、工具 schema 和生命周期事件 |
| [Apache Iceberg](https://iceberg.apache.org/spec/) | 不可变数据文件、Manifest、快照和原子元数据提交 | Segment Manifest + 最后写入 Checkpoint |
| [Apache OpenDAL](https://opendal.apache.org/) | 统一 OSS/S3/本地后端、multipart writer、重试层 | `chiptrace` 的唯一对象存储适配层 |
| [Alibaba OSS Multipart Upload](https://www.alibabacloud.com/help/en/oss/user-guide/multipart-upload) | 分片并行传输、失败分片重传、完成时合并 | Segment 和 Release 文件的并行上传 |

没有复制这些项目的源文件。OpenDAL 通过 Cargo 依赖使用，其余项目作为协议和
故障语义的参考。

OSS 的 `AppendObject` 不作为主路径：官方限制 Appendable 对象最大 5 GB，且下载
性能低于普通或 Multipart 对象。单个无限增长对象还会把校验、重传和故障域扩大到
整个对象。Segment 对象保留相同的逻辑连续性，同时支持局部重试和增量发布。

## 对象布局

```text
<prefix>/
├── raw/
│   ├── objects/<sha256>.ndjson
│   └── <archive_id>/
│       ├── manifest.json
│       └── CHECKPOINT.json
├── releases/<release_id>/COMMIT.json
└── deliveries/<release_id>/COMMIT.json
```

`raw/objects/<sha256>.ndjson` 是内容寻址的不可变数据 Segment。Manifest 记录每个
数据 Segment 的 shard、序号、对象键、字节数、记录数和 SHA-256。零记录的 sealed
旋转文件放在 `empty_segments` 中，保留序号、来源路径、字节数和 SHA-256 作为审计
证据；空段字节也使用内容寻址对象保存并可原样恢复，但不计入 `segment_count`、
记录数或交付 Token。`total_bytes` 覆盖数据段和空段的全部 sealed WAL 字节。
Checkpoint 记录 Manifest 的 SHA-256、统计值和 `completeness`：

- `complete`：每个 shard 从 Segment 1 开始且序号连续，可作为 Release 输入。
- `partial`：使用了 `--allow-segment-gaps`，仅用于故障取证或局部检查，不得作为
  全量交付声明。

消费者只读取 Checkpoint 引用的 Manifest，再读取 Manifest 列出的对象；不使用
OSS LIST 推断数据是否完整。Manifest 和 Segment 可在 Checkpoint 前可见，但在
Checkpoint 出现前都不是可消费快照。

Manifest 是确定性的：时间范围来自 Segment 内 Capture 时间字段，缺失时使用
`unknown`，不使用本地文件 ctime/mtime。相同 Segment 字节、shard 和序号在不同
机器上会得到相同 Manifest SHA-256。

`archive-raw` 只读取 `.sealed.ndjson`。目录输入发现非空 `.open.ndjson` 就直接
失败，不会静默跳过活动尾段；Collector `/flush` 产生的零字节 open 占位文件可以
安全忽略。归档前先调用 `/flush`，或显式传入已经封存的文件集合。

## 提交状态机

```text
sealed WAL
   │ 逐行 JSONL framing、字节数、SHA-256
   ▼
objects uploaded (multipart + retry)
   │ 远端长度与 SHA-256 校验
   ▼
manifest immutable write
   │ if-not-exists；同内容重试幂等，冲突拒绝
   ▼
CHECKPOINT immutable write  ← 唯一可见提交点
   │
   ▼
restore / Assembly / Score / Release
```

进程在任意步骤退出时可以重试同一 `archive_id`。对象键和 Manifest 内容是确定性
的；相同输入会得到相同摘要。未完成的 OSS Multipart Upload 不会被消费者看到，
生产 Bucket 必须配置生命周期规则自动清理超时 UploadId。

## 命令

先让 Collector 封存当前段，再执行原始归档：

```bash
chiptrace archive-raw \
  --input /srv/chiptrace/capture \
  --archive-id chiptrace-20260828-1800 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace \
  --file-concurrency 8 \
  --multipart-concurrency 8 \
  --multipart-chunk-mib 16 \
  --retry-max-times 25

chiptrace verify-raw-archive \
  --archive-id chiptrace-20260828-1800 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace \
  --verify-records

chiptrace restore-raw-archive \
  --archive-id chiptrace-20260828-1800 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace \
  --output /srv/chiptrace/restored/capture

chiptrace assemble \
  --input /srv/chiptrace/restored/capture \
  --output /srv/chiptrace/assembly \
  --partitions 256
```

恢复目录包含 `RAW_SOURCE.json`，记录 Checkpoint/Manifest 对象键、SHA-256、统计值
和完整性。Assembly 会校验并继承该来源，Release Manifest 继续携带同一份
`raw_sources`；最终采购包通过 Release Manifest SHA-256 关联到完整来源链。

本地验收可以把 `--backend oss` 换为 `--backend fs --root /srv/object-store`。
`restore-raw-archive` 默认拒绝覆盖已有目录，确认替换时显式添加 `--replace`。
对于 `completeness=partial` 的取证快照，还必须显式添加 `--allow-partial`；这类
恢复结果不得进入标准 buyer Release。

## 与交付标准的关系

| 验收层 | 原始 OSS 层保证 | Release 层保证 |
| --- | --- | --- |
| 字节完整 | Segment 长度、记录数、SHA-256、Checkpoint | Release Manifest、SHA256SUMS |
| JSON 合法 | 每行 JSON 对象和 `captureId` | UTF-8 JSONL 逐行解析 |
| Session 边界 | 保存所有原始 API/事件，不猜测任务结束 | 依据 Stock Codex `session_id`、Response DAG 和生命周期组装 |
| Tool 配对 | 原始事件不删改 | Call/Result 配对率、schema 和状态硬门槛 |
| 质量准入 | 不做过滤 | buyer-v7、分数阈值和 hard gate |
| 分包 | 不切断 Segment | Session 原子 `tar.gz + JSONL`，目标约 10 GiB |

完整 Trajectory 由 Stock Codex Wire、OTLP 和 required Hook 三源共同提供。OSS 只能证明
原始证据没有丢失，不能从 API 快照生成生命周期、工具状态或 Schema。
