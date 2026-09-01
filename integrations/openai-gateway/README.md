# OpenAI 网关接入

该目录只提供 OpenAI-compatible 网关旁路采集所需的本地可靠投递模块，不包含业务代理、
查询界面或评测服务。

网关在业务响应结束后构造 Capture，并调用 `DurableCaptureOutbox.enqueue()`。该调用只等待
本地原子落盘；后台获得 Rust Relay 的 durable ACK 后才删除文件。进程重启时会恢复
`pending` 和 `processing`，相同 `captureId` 保持幂等，不同内容使用相同 ID 时直接冲突。

```js
const { DurableCaptureOutbox } = require('./durable-outbox');

const outbox = new DurableCaptureOutbox({
  root: process.env.CHIPTRACE_OUTBOX_DIR,
  relayUrl: process.env.CHIPTRACE_RELAY_URL,
  sanitize: false,
  maxAttempts: 25,
});

await outbox.start();
await outbox.enqueue(capture);
```

接入约束：

- 请求和响应正文必须使用实际观察到的原始 UTF-8 字节计算长度与 SHA-256。
- `sanitize: false` 保留 Wire 正文；认证头、Cookie 和 API Key 不得写入 Capture headers。
- `408`、`425`、`429` 和 `5xx` 重试；其他 `4xx` 作为永久错误移入 `failed`。
- `/producer/event` 与 `/producer/events` 原样流式转发到 Rust Relay，并透传 Bearer Token
  和下游状态码；网关不能解析后重建 rollout。
- 业务响应不等待远端 Relay。磁盘写入失败、队列上限或 inode/空间水位必须出现在健康指标。

运行测试：

```bash
node --test integrations/openai-gateway/durable-outbox.test.js
```
