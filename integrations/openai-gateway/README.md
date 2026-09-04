# OpenAI 网关接入

该目录只提供 OpenAI-compatible 网关旁路采集所需的本地可靠投递模块，不包含业务代理、
查询界面或评测服务。生产语义由云端 OTLP/Hook 主线提供；网关只保存它真实看到的 Wire。

网关在业务响应结束后构造 Capture，并调用 `DurableCaptureOutbox.enqueue()`。该调用只等待
本地原子落盘；后台获得 Rust Relay 的 durable ACK 后才删除文件。进程重启时会恢复
`pending` 和 `processing`，相同 `captureId` 保持幂等，不同内容使用相同 ID 时直接冲突。

```js
const {
  DurableCaptureOutbox,
  validateProviderCredential,
} = require('./durable-outbox');

const outbox = new DurableCaptureOutbox({
  root: process.env.CHIPTRACE_OUTBOX_DIR,
  relayUrl: process.env.CHIPTRACE_RELAY_URL,
  sanitize: false,
  maxAttempts: 25,
});

await outbox.start();
await outbox.enqueue(capture);
```

网关返回 ChipTrace 受管 `/models` 前，必须先用原业务 Bearer 请求 Provider 的
`/v1/models`，并要求 `validateProviderCredential()` 返回 `ok=true`；随后才以内部采集
凭据读取 Relay 目录。业务凭据不得转发到 Relay。

接入约束：

- 每条记录必须使用 `recordType=api_snapshot` 和非空 `sourceNamespace`；显式 `version` 必须为
  `chiptrace.capture.v2`，缺省时由 Relay 规范化并保留原始字节哈希。该入口不接受 Runtime、
  生命周期或评价记录。
- 请求和响应正文必须使用实际观察到的原始 UTF-8 字节计算长度与 SHA-256。
- `/models` 必须验证真实 Provider 业务凭据；只检查 Bearer 非空不算鉴权。
- `sanitize: false` 保留 Wire 正文；认证头、Cookie 和 API Key 不得写入 Capture headers。
- `408`、`425`、`429` 和 `5xx` 重试；其他 `4xx` 作为永久错误移入 `failed`。
- 网关不生成 Session、工具执行或模型身份字段；这些事实只能由 Stock Codex 的云端
  OTLP/Hook 证据提供。无法关联的记录保留为 Wire-only，不能进入合格 Release。
- 业务响应不等待远端 Relay。磁盘写入失败、队列上限或 inode/空间水位必须出现在健康指标。

运行测试：

```bash
node --test integrations/openai-gateway/durable-outbox.test.js
```
