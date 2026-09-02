# 交付格式

## 唯一入口

正式交付只由 `cloud-acceptance` 生成：

```bash
chiptrace cloud-acceptance \
  --archive-id <archive-id> \
  --backend oss \
  --endpoint <oss-endpoint> \
  --bucket <bucket> \
  --prefix chiptrace \
  --usage-log <sub2api-usage.jsonl> \
  --session-id <stock-codex-session-id> \
  --release-id <release-id> \
  --minimum-score 90 \
  --target-part-gib 10 \
  --output <acceptance-directory>
```

该命令只接受已提交且 `completeness=complete` 的 Raw Archive，并只组装显式
`session-id`。它不从混合 WAL 中猜测任务边界。任一阶段失败时返回非零状态，不覆盖已有
通过目录。

## 目录

```text
acceptance-directory/
├── raw/                 # 从 Raw Checkpoint 恢复的 sealed Segment
├── enriched/            # Sub2API request ID 精确关联
├── interactions/        # ModelInteraction / RuntimeSpan / Link
├── otlp/                # 单根 OTLP 树
├── assembly/            # 唯一 canonical Session
├── release/             # 内部 JSONL.zst 与 Assessment
├── buyer-package/       # 可上传采购包
└── manifest.json        # 整体验收结论与各阶段 SHA-256
```

`verify-cloud-acceptance` 只读复验总 Manifest 和所有阶段摘要：

```bash
chiptrace verify-cloud-acceptance --acceptance <acceptance-directory>
```

## 采购包

```text
buyer-package/
├── packages/
│   └── sessions-part-00001.tar.gz
├── manifest.json
└── SHA256SUMS

sessions-part-00001.tar.gz
├── sessions.jsonl
├── PACKAGE.json
└── SHA256SUMS
```

`sessions.jsonl` 使用 UTF-8，每行一条完整 Session。Session 不跨包；单条 Session 超过
目标大小时独占一个包。`--target-part-gib` 控制内部未压缩 JSONL 的目标大小，gzip 后大小
由内容压缩率决定。

采购包只包含：

- `delivery_ready=true`；
- Buyer v7 score >=90；
- 全部 hard gate 通过；
- Raw lineage 完整；
- 去重后唯一且不是其他记录连续子序列的 Session。

Manifest 分别统计 API、缓存、规范化语料和监督输出 Token。base64 正文按采购规则排除，
排除字节数单独记录。

## OSS 发布

验收通过后才允许发布 `buyer-package/`：

```bash
chiptrace publish \
  --buyer-package <acceptance-directory>/buyer-package \
  --backend oss \
  --endpoint <oss-endpoint> \
  --bucket <bucket> \
  --prefix chiptrace

chiptrace verify-published \
  --artifact-kind buyer-package \
  --artifact-id <release-id> \
  --backend oss \
  --endpoint <oss-endpoint> \
  --bucket <bucket> \
  --prefix chiptrace
```

`COMMIT.json` 最后写入。消费者只读取 COMMIT 引用的对象，不使用 OSS LIST 推断交付是否
完整。相同 release ID 和相同 Manifest 为幂等；相同 ID 的不同内容被拒绝。
