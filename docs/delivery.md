# 芯迹交付规范

## 目录结构

每个数据集版本使用一个不可变目录：

```text
<dataset-id>/
├── manifest.json
├── SHA256SUMS
├── session-catalog.sqlite
├── <model>-part-001.sqlite
├── <model>-part-002.sqlite
└── ...
```

Part 目标大小为 10 GiB。一个 Session 不跨 Part；单个 Session 大于目标值
时生成一个明确标记的超限 Part。构建器直接复制经过校验的压缩 BLOB，
不对未变化 payload 重复解压和压缩。

生成交付目录：

```bash
chiptrace release \
  --input raw-001.sqlite \
  --input raw-002.sqlite \
  --output target-model-YYYYMMDD-v1 \
  --model target-model-v1 \
  --target-part-gib 10
```

发布过程先在临时目录完成构建、SQLite 校验、文件同步和哈希计算，再原子生成目标目录。

## Manifest

`manifest.json` 使用以下结构：

```json
{
  "release_id": "target-model-YYYYMMDD-v1",
  "schema_version": "complete-session-release-v1",
  "selection": {
    "model": "target-model-v1",
    "mode": "complete-session"
  },
  "session_atomic": true,
  "session_split_count": 0,
  "actual_window": {
    "start": "2026-08-01T00:00:00Z",
    "end": "2026-08-26T00:00:00Z"
  },
  "models_present": ["target-model-v1", "helper-model-v1"],
  "sensitive_raw_data": true,
  "semantic_reward_available": false,
  "score_semantics": "observed session trace completeness; not task correctness",
  "session_quality": {
    "policy_version": "session-trace-completeness-v1",
    "average": 0,
    "minimum": 0,
    "maximum": 0,
    "grades": {},
    "incomplete_reasons": {}
  },
  "records": 0,
  "sessions": 0,
  "token_totals": {
    "input": 0,
    "cached_input": 0,
    "cache_write": 0,
    "uncached_input": 0,
    "output": 0,
    "reasoning": 0,
    "total": 0
  },
  "parts": [
    {
      "file": "target-model-v1-part-001.sqlite",
      "bytes": 0,
      "sha256": "..."
    }
  ],
  "catalog": {
    "file": "session-catalog.sqlite",
    "schema_version": "session-catalog-v3",
    "bytes": 0,
    "sha256": "..."
  },
  "validation_status": "pass"
}
```

`actual_window` 来自实际保留记录的事件时间。采集提前停止时，结束时间保持为最后一条已观测记录的时间。

## Catalog

`session-catalog.sqlite` 不包含重复 capture，并通过 `(shard_id, record_id)` 定位原始记录。核心表如下：

- `trajectories`：Session 主表，保留兼容命名。
- `turns` 和 `steps`：Turn 与交互步骤。
- `step_usage`：input、cache、output、reasoning 和 total Token。
- `step_item_counts`：消息和响应 item 计数。
- `tool_definitions`：工具 schema、hash 和版本。
- `tool_calls` 与 `tool_results`：工具调用、真实结果和关联状态。
- `session_quality` 与 `trajectory_quality`：完整性分项、总分和原因。
- `validation_results`：构建和验收校验。

身份计算规则：

```text
session_id = sha256(source_namespace + NUL + (native_session_id or thread_id))
turn_key   = sha256(session_id + NUL + stable_turn_id)
step_id    = captureId
call_key   = sha256(session_id + NUL + native_call_id)
```

缺少原生身份时生成 orphan Session 并降低完整性得分。系统不补造任务成功、Turn、工具结果或 reward。

## Token 统计

Release Manifest 自动汇总上游 API 返回的 usage：

| 口径 | 含义 |
| --- | --- |
| `input` | API 输入 Token |
| `cached_input` | 命中缓存的输入 Token |
| `cache_write` | 写入缓存的输入 Token |
| `uncached_input` | 未命中缓存的输入 Token |
| `output` | API 输出 Token |
| `reasoning` | API 返回的 reasoning Token |
| `total` | API 返回或按各 usage 维度汇总的总 Token |

API usage 表示实际调用成本，包含同一上下文被重复处理的 Token。规范化语料 Token 和监督
输出 Token 依赖明确的 tokenizer、消息规范化规则和监督字段选择，基础 release 命令不生成
这两项估算值。按 Token 结算时，验收报告必须记录 tokenizer 名称、版本、去重规则、Base64
排除规则和监督字段范围，并将统计结果与 `release_id`、Manifest SHA-256 绑定。

## 验收门槛

发布必须通过以下校验：

- Capture ID 唯一，源段、导出和发布记录数守恒。
- 每个 payload chunk 可以解压，长度与原始哈希一致。
- 包含目标模型的 Session 保留全部已观测 Step。
- 每个 Session 只属于一个 Part。
- Turn、usage 维度和 Terminal 计数可以从源索引复现。
- Truncation、左右截断和缺失工具关联保持显式。
- 每个 SQLite 的 `PRAGMA foreign_key_check` 返回空结果。
- 每个 SQLite 的 `PRAGMA integrity_check` 返回 `ok`。
- Manifest 与 `SHA256SUMS` 包含全部交付文件的 SHA-256。
- `validation_status` 为 `pass`。

上传完成后，使用远端文件大小和 SHA-256 复核传输完整性。

## 压缩交付

传输包使用 UTF-8 文件名和 `tar.gz`：

```bash
tar --sort=name \
  --owner=0 --group=0 --numeric-owner \
  -czf target-model-YYYYMMDD-v1.tar.gz \
  target-model-YYYYMMDD-v1/
```

压缩包不修改目录内 SQLite、Manifest 和校验文件。数据授权、访问控制、静态加密和保留周期由交付双方在传输前确认。
