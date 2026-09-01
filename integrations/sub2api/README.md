# Sub2API 路由证据

该适配器从 Sub2API PostgreSQL 只读导出模型路由、有效平台和 Token 事实。有效平台优先
使用请求所属分组，缺失时回退到账号平台。产物不包含请求正文、响应正文、API Key、
用户信息或账号凭据。

```bash
usage_tmp="$(mktemp /srv/chiptrace/sub2api-usage.XXXXXX.jsonl)"
psql "$SUB2API_DATABASE_URL" -X -qAt \
  --set=ON_ERROR_STOP=1 \
  --set=after_id=0 \
  --set=batch_size=100000 \
  --file=integrations/sub2api/export-usage.sql > "$usage_tmp"
mv "$usage_tmp" /srv/chiptrace/sub2api-usage.jsonl

chiptrace enrich \
  --input /srv/chiptrace/raw \
  --usage-log /srv/chiptrace/sub2api-usage.jsonl \
  --output /srv/chiptrace/enriched
chiptrace verify-enrichment --enrichment /srv/chiptrace/enriched
```

`after_id` 使用上一个已确认批次的最大 `usage_log_id`。批次可以重叠；相同 request ID
和相同事实会按内容指纹去重。相同 request ID 出现不同事实时，关联保持 ambiguous 并拒绝
进入严格交付，不能使用时间、模型名或正文相似度回退。
