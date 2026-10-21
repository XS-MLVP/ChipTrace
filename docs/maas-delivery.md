# 外部 MaaS request 级交付

`export-maas` 面向外部 MaaS 的 SFTP/FTP 拉取目录生成 request 级 `tar.gz`。它只读取已封存
的 Capture JSONL/NDJSON，拒绝 `.open.ndjson`，只处理 `recordType=api_snapshot`，并且要求每条
Wire 同时具备 `requestId`、Session/Turn 身份、RFC3339 请求时间、HTTP 状态、模型和完整输入/输出
Token 用量。缺少或冲突的身份、协议、用量和正文会使命令失败，避免把未归属数据发布出去。

## 目录和文件

输出根目录按外部约定使用 `/maasData/archive`：

```text
/maasData/archive/{providerCode}/{yyyy-MM-dd}/
└── batch_00001.tar.gz       # 压缩后严格小于等于 100 MB（十进制）
```

每个压缩包内按 `requestId` 分目录。每个目录包含 `metadata.json`、`biz_request.json`，以及二选一
的响应文件：流式请求为 `biz_stream_response.jsonl`（每行一个 JSON SSE 事件），同步请求为
`biz_response.json`。一个 request 的三个文件始终位于同一个压缩包。发布目录只保留压缩包，导出
阶段使用的临时 request 目录不会被发布。

`metadata.json` 固定包含：`requestId`、`sessionId`、`requestTime`、`httpStatus`、`protocol`、
`requestMode`、`modelName`、`platform`、`inputTokens`、`outputTokens`、`providerCode`。
`requestTime` 默认按外部约定使用北京时间（UTC+08:00）的 `yyyy-MM-dd HH:mm:ss`；日期目录取
同一北京时间日期。导出 CLI 支持用固定分钟偏移覆盖该默认值，禁止依赖主机本地时区。协议、模式、
平台和供应商编码均做枚举/路径校验。

正文导出前会拦截已识别的恶意 Prompt 注入，并把高置信度邮箱、手机号、身份证号、Bearer/API
凭据、姓名/地址上下文以及敏感字段统一替换为 `<|mask_privacy|>`。结构化字段按大小写、下划线、
短横线和 camelCase 归一化后匹配，验证器会拒绝仍含未掩码敏感字段的 JSON。导出器不会伪造缺失
事实，也不会把 OTLP、Hook 或旧的未分类记录当作 Wire 请求。

从共享 Raw 生成“指定进程”的样本时，用可重复的 `--session-id` 只导出给定 native
Session，其他会话的请求计入 `skipped_other_session_requests`；`--skip-incomplete`
把没有完整用量的失败/中断 Wire 计入 `skipped_incomplete_requests`，默认仍整体失败。
两个过滤条件都不改写 Raw。

```bash
chiptrace export-maas \
  --input /var/lib/chiptrace/capture/segments/segment-*.sealed.ndjson \
  --output /maasData/archive \
  --provider-code providerX --platform openai \
  --session-id <native-session-id> --skip-incomplete
```

## 命令

```bash
chiptrace export-maas \
  --input /var/lib/chiptrace/capture/segments \
  --output /maasData/archive \
  --provider-code providerX \
  --platform openai \
  --timezone-offset-minutes 480 \
  --replace

chiptrace verify-maas \
  --input /maasData/archive
```

`verify-maas` 会重新读取每个压缩包，校验路径、大小、请求目录、11 个元数据字段、响应文件
二选一、JSON/JSONL 结构、脱敏和跨包重复 `requestId`。通过验证后再由供应商按约定在 T+1
02:00 前通过自建 SFTP/FTP 提供给接收方拉取；ChipTrace 不保存或管理外部 SFTP 凭据。
