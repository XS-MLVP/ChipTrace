\if :{?after_id}
\else
\set after_id 0
\endif
\if :{?batch_size}
\else
\set batch_size 100000
\endif

SELECT jsonb_strip_nulls(jsonb_build_object(
    'usage_log_id', ul.id,
    'request_id', ul.request_id,
    'requested_model', COALESCE(NULLIF(ul.requested_model, ''), ul.model),
    'upstream_model', COALESCE(NULLIF(ul.upstream_model, ''), ul.model),
    'effective_platform', COALESCE(NULLIF(g.platform, ''), NULLIF(a.platform, '')),
    'model_mapping_chain', ul.model_mapping_chain,
    'input_tokens', ul.input_tokens,
    'output_tokens', ul.output_tokens,
    'cache_creation_tokens', COALESCE(ul.cache_creation_tokens, 0)
        + COALESCE(ul.cache_creation_5m_tokens, 0)
        + COALESCE(ul.cache_creation_1h_tokens, 0),
    'cache_read_tokens', ul.cache_read_tokens,
    'created_at', ul.created_at
))::text
FROM usage_logs AS ul
LEFT JOIN groups AS g ON g.id = ul.group_id
LEFT JOIN accounts AS a ON a.id = ul.account_id
WHERE ul.id > :'after_id'::bigint
  AND ul.request_id IS NOT NULL
  AND btrim(ul.request_id) <> ''
ORDER BY ul.id
LIMIT :'batch_size'::integer;
