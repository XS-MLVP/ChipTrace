# 芯迹数据契约

## 采集边界

Collector 是原始数据的持久化边界，不判断交互是否有效、正确或符合
训练准入条件。HTTP 408、429、5xx、上游错误、不完整响应和缺少 usage
的记录均进入原始存储。质量策略在版本化的下游投影中执行。

部署方必须在启用采集前取得数据源授权。服务不对正文执行脱敏，每个 envelope 均按敏感原始数据处理。

## Relay 输入

`POST /capture` 接受 `application/json`，并要求 `captureId` 匹配 `cap-[A-Za-z0-9._:-]+`。请求格式如下：

```json
{
  "captureId": "cap-example-001",
  "sourceNamespace": "relay-a",
  "startedAt": "2026-08-26T00:00:00Z",
  "finishedAt": "2026-08-26T00:00:01Z",
  "requestBodyText": "{\"model\":\"target-model-v1\",\"input\":[]}",
  "responseStatus": 503,
  "responseBodyText": "data: {...}\n\n",
  "requestTruncated": false,
  "responseTruncated": false,
  "stream": true,
  "captureError": null,
  "traceContext": {
    "session_id": "session-1",
    "turn_id": "turn-1",
    "previous_response_id": "response-0"
  },
  "observedLifecycleEvents": ["response.failed"]
}
```

Collector 将两个文本正文规范化为 `full-trace-spool-v3`：

- 合法 JSON 文本保存为 `{"kind": "json", "value": ...}`。
- SSE、纯文本和非法 JSON 保存为 `{"kind": "text", "value": ...}`。
- `requestBodySha256` 和 `responseBodySha256` 覆盖原始 UTF-8 字节。
- 所有响应状态和 `captureError` 字段完整保留。
- `receivedAt` 只由稳定事件时间生成。
- Collector 实际接收时间单独保存在 `imported_at`。

稳定时间规则确保客户端省略时间戳时，同一 `captureId` 和相同字节仍可幂等重试。已经规范化的 spool 记录保持正文结构不变。

完整字段由
[Capture Envelope JSON Schema](../src/chiptrace/specs/capture-envelope-v3.schema.json)
定义。

## 持久化确认与身份

Collector 在段文件跨过配置的 `fsync` 边界并提交 SQLite ledger 事务后
返回 HTTP 202。响应包含 `durable: true` 和以下状态之一：

- `accepted`：ID 和 payload 首次提交。
- `duplicate`：相同 ID 和 payload hash 已提交。
- HTTP 409 `conflict`：相同 ID 对应不同 payload 字节。

HTTP 400、411、413、415、在途字节超限、duplicate、conflict、accepted
和启动恢复状态均记录到 `capture_attempts`。ledger 是 attempt 记账
依据，进程内计数只用于运行监控。

请求超时不代表写入失败。发送端必须重试完全相同的序列化字节和 ID，ledger 将结果归并为 accepted 或 duplicate。

## Open 段封存

离线 `export` 只读取 `sealed`/`archived` 段。在线服务继续运行时，先调用
受信任的本地 `POST /flush`；该接口按写入顺序等待队列完成、封存当前段并
创建新的 `open` 段。也可以先优雅停止 Collector，`close()` 会封存最后一段。

## 原始存储

每条原始记录占一行 JSON：

```text
<data-root>/segments/segment-NNNNNNNN.open.ndjson
<data-root>/segments/segment-NNNNNNNN.sealed.ndjson
```

只有当前写者追加 open 段。轮转通过原子重命名生成 sealed 段，并将
SHA-256 写入 ledger。启动恢复只截断 open 段末尾的不完整行；
段文件缺失、ID 冲突或同一 ID 存在第二份物理记录会阻止服务进入
ready 状态。

SQLite 状态默认位于 `<data-root>/state/capture-ledger.sqlite`。生产部署使用独立目录：

```text
数据卷或 NFS:   --root /data/capture
本地持久化磁盘: --state-root /var/lib/chiptrace/state
```

live ledger 不在 NFS/CIFS 上使用 WAL。状态目录纳入备份；从 retained segments 重建 ledger 的耗时与原始数据规模成正比。

## Raw SQLite 导出

`chiptrace export` 固定一个只读 SQLite 快照，只选择 sealed 或
archived 段。命令在私有 staging 数据库中构建并校验结果，再原子发布。
默认无覆盖路径使用 hard link，`--replace` 使用原子 rename。

Raw SQLite 包含以下表：

- `dataset_meta`：格式、创建时间、压缩方式和敏感数据声明。
- `source_segments`：段路径、字节数、记录数和 SHA-256。
- `interactions`：唯一 capture、元数据和源定位信息。
- `interaction_chunks`：有序、独立的 zlib 或 zstd 压缩块，默认原始块大小为 4 MiB。
- `validation_results`：记录、压缩块、外键和完整性校验结果。

独立压缩块限制解压内存，并与 trajectory reader 的
`interactions + interaction_chunks` 输入契约一致。原始 Prompt、
回答、工具参数和工具结果保留在 raw 数据库中。读取端必须拒绝未知
codec、长度不符、解压失败和原始哈希不符。

`export-sharded` 固定所有 sealed segment ID 的同一快照，将每个段
分配给唯一 raw SQLite writer，并发布包含 `manifest.json` 和
`SHA256SUMS` 的目录。Raw shard 可以拆分 Session，只有下游
`release` 可以声明 Session 原子交付。

## Session 交付与评分边界

`chiptrace release` 将 Session 作为最小交付单元。Session 身份
优先取 `client_metadata.session_id`，其次取 `thread_id`，并与
`sourceNamespace` 一起计算哈希。缺少身份的记录生成单 capture
orphan Session，并在完整性评分中体现。

选择目标模型时，同一 Session 中其他模型的交互也会保留。一个 Session
不跨 release part；单个 Session 超过目标大小时，独立生成超限 part。

Raw export 支持计算以下字段：

- Session、Turn 和 Step 身份。
- input、cache、output、reasoning 和 total Token 用量。
- Terminal 状态和生命周期事件。
- 工具 schema、调用、结果和关联状态。
- payload 截断和 Session 左右边界。
- root、parent、goal、agent、branch 和 Response DAG 关系。

Release 保存以下质量字段：

- `session_completeness_score`：确定性的已观测 Trace 完整性。
- Payload、Identity、Terminal、Usage、Tool Linkage 和 Boundary 分项得分。
- `reward`：可空的正确性或偏好结果。
- `reward_source`：evaluator、judge 版本、benchmark 或 ground truth。

100 分完整性策略如下：

| 分项 | 分值 |
| --- | ---: |
| Payload | 20 |
| Session / Turn Identity | 20 |
| Terminal | 20 |
| Usage | 5 |
| Tool Linkage | 20 |
| Boundary | 15 |

`A_complete` 要求 100 分。所有分项和底层 flags 保存在 `session_quality` 中。

`response.failed`、`response.incomplete` 和 `response.cancelled`
是完整的终态观测，不代表采集不完整。HTTP 成功、
`response.completed`、最终文本和工具闭合也不代表语义奖励。
加密 reasoning 作为不透明原始数据保存，交付结果不声明具备明文思维链。

`left_censored`、`right_censored`、正文截断、身份缺失和工具未配对均保持显式。完整性结论仅覆盖本次输入的原始数据集合。交付约束见[交付规范](delivery.md)。

## 版本

| 对象 | 当前格式 |
| --- | --- |
| Capture envelope | `capture-envelope-v3` |
| Raw spool | `full-trace-spool-v3` |
| Session catalog | `session-catalog-v4` |
| Release manifest | `complete-session-release-v1` |
| Completeness policy | `session-trace-completeness-v1` |

持久化格式变更必须新增版本和迁移测试，不覆盖既有格式语义。
