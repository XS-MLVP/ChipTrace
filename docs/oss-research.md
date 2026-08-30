# OSS 方案选型

本文记录 ChipTrace 的对象存储方向、开源方案调研结果和可验收边界。调研日期为
2026-08-29。引用项目只作为架构和契约参考，仓库没有复制其源代码。

## 结论

ChipTrace 采用一条对象存储数据面：

```text
18084 / Agent harness
    -> Relay durable outbox
    -> Collector WAL
    -> sealed Segment
    -> OSS Raw objects
    -> Manifest
    -> CHECKPOINT
    -> Assembly / DAG
    -> buyer-v7-codex-runtime-expanded Score
    -> JSONL Release
    -> buyer tar.gz
    -> OSS COMMIT
```

本地 WAL 只承担入口确认和断点恢复；OSS 是原始证据、Release 和提交索引的统一
归档面。Raw 使用内容寻址的不可变 Segment，Manifest 描述 Segment 集合，最后写入
Checkpoint 作为唯一可消费提交点。逻辑上它是一条连续日志，物理上是可并行上传、
可校验和可重试的对象集合。

## 参考方案

| 项目 | 许可证 | 借鉴能力 | 在 ChipTrace 中的落点 |
| --- | --- | --- | --- |
| [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector) | Apache-2.0 | Receiver/Processor/Exporter 分层、持久队列、重试和背压 | Relay、Collector 的边界和流量控制 |
| [OpenInference](https://github.com/Arize-ai/openinference) | Apache-2.0 | LLM、Agent、Tool、Session、父子关系语义 | `traceContext`、任务 DAG、工具执行事件 |
| [Vector](https://github.com/vectordotdev/vector) | MPL-2.0 | 磁盘缓冲、批处理、重启恢复和 at-least-once 投递 | durable outbox、delivery ledger、批量 NDJSON |
| [Apache OpenDAL](https://github.com/apache/opendal) | Apache-2.0 | 统一 FS/OSS/S3 API、multipart writer、重试层 | `object_store.rs`，Raw 和 Release 共用 |
| [Apache Iceberg](https://github.com/apache/iceberg) | Apache-2.0 | 不可变数据文件、Manifest、快照和最后提交元数据 | Raw Manifest/Checkpoint、Release COMMIT |
| [Langfuse](https://github.com/langfuse/langfuse) / [Phoenix](https://github.com/Arize-ai/phoenix) | 各自上游许可证 | Trace 查询、人工反馈、评测投影 | 只借鉴评测闭环；不作为生产 Raw 存储 |

许可证信息用于依赖审查，不表示 ChipTrace 链接或重新分发这些项目。Rust 依赖由
Cargo 锁定版本，发布前应使用组织的许可证扫描流程复核完整依赖树。

## 为什么不使用单一无限增长对象

OSS 更适合不可变对象和 multipart 上传，不适合让每个请求竞争同一个追加对象。单一
对象会带来四个问题：

1. 追加确认和业务响应耦合，网络重试容易重复或覆盖尾部。
2. 进程在中途退出时，消费者无法可靠区分完整对象和未完成尾部。
3. 单对象锁住并发写入，无法把磁盘分片、网络连接和 multipart 并行化。
4. Alibaba OSS `AppendObject` 文档对 Appendable 对象有 5 GB 上限，且下载性能
   不如普通或 multipart 对象，不能作为长期 Raw 主路径。

因此 ChipTrace 使用“不可变 Segment + 内容寻址 + 最后 Checkpoint”。Segment 可以
持续封存，重复归档只上传新对象；Checkpoint 之前的半成品永远不会被恢复或组装。
若业务需要一个逻辑对象，Manifest 和 Checkpoint 就是这个逻辑对象的稳定索引。

## 统一对象布局

```text
<prefix>/
├── raw/
│   ├── objects/<sha256>.ndjson
│   └── <archive_id>/
│       ├── manifest.json
│       └── CHECKPOINT.json
├── .staging/
│   ├── releases/<release_id>/<manifest_sha256>/...
│   └── deliveries/<release_id>/<manifest_sha256>/...
├── releases/<release_id>/COMMIT.json
└── deliveries/<release_id>/COMMIT.json
```

提交顺序固定为：

```text
Segment -> Manifest -> 校验对象长度/SHA-256 -> CHECKPOINT
内部 Release files -> releases COMMIT
buyer tar.gz files -> deliveries COMMIT
```

消费者只读取 Checkpoint 或 COMMIT 引用的对象，不通过 OSS LIST 推断完整性。相同
`archive_id` 或同一命名空间内的 `release_id` 和相同内容重复执行为幂等；同一 ID
的不同 Manifest 会被拒绝。未完成的 multipart upload 必须由 Bucket 生命周期规则
自动 Abort。`verify-published` 从 COMMIT 读取对象集合并逐对象回验 SHA-256。

## 交付标准映射

| 采购要求 | 产生位置 | 验收方式 |
| --- | --- | --- |
| 完整原始证据 | Raw Segment | `verify-raw-archive --verify-records` |
| 唯一 Session 和 DAG | Assembly | `verify-assembly`、`RAW_SOURCE.json` |
| 工具 schema、call、result、状态 | Agent/tool event + Assembly | buyer-v7-codex-runtime-expanded `tool_definitions`、`tool_pairing_after_open_tail` |
| 10 个有效轮次、5 个工具、2 个有效返回 | canonical Session | buyer-v7-codex-runtime-expanded hard gate |
| 首条 role、机器轮比例、模型限制 | canonical Session | buyer-v7-codex-runtime-expanded hard gate |
| 去重和 Token 守恒 | Release | `verify-release --require-pass` |
| UTF-8 JSONL、Session 原子分包 | Buyer package | `verify-buyer-package` |
| 传输完整性和来源追溯 | OSS COMMIT + `raw_sources` | `verify-published`、SHA-256 和 lineage 对账 |

OSS 只能证明原始字节没有丢失，不能从 HTTP 快照推断任务结束、工具真实状态或
用户验收。没有 Agent harness/tool executor 事件的 Session 会保留在 Raw，但在
buyer-v7-codex-runtime-expanded Release 中拒绝，这个边界是数据真实性要求的一部分。

## 上线验收

1. 在 FS 后端跑 `chiptrace self-test`，覆盖 outbox、Raw、恢复、DAG、评分、Release、
   buyer tar.gz 和篡改检测。
2. 使用真实 OSS 凭据执行一次 `archive-raw`、`verify-raw-archive --verify-records`、
   `restore-raw-archive`、两类 `publish` 和 `verify-published`，记录吞吐、P99、重试
   次数、错误率和对象校验结果。
3. 注入断网、进程重启、重复提交、缺失对象和非法 Manifest，确认不会出现可见的
   半快照，恢复后 attempt/record/Token 计数守恒。
4. 配置 Raw/Release 分离权限、版本保护或 WORM、multipart 清理和容量告警；再把
   archiver 纳入定时任务，按封存 Segment 生成新的 `archive_id`。

## 性能边界

对象存储路径的吞吐取决于 Segment 大小、multipart 并发、OSS 限流、NVMe 和网络，
不能用单机自测结果直接宣称 500 MiB/s–1 GiB/s 的生产能力。上线报告必须分别给出
采集 durable ACK、Raw 上传、恢复、Assembly、压缩和发布的吞吐与 p50/p95/p99；
通过增加 Collector 分片、独立 NVMe 和并发 multipart 扩展，而不是增大单一对象。
