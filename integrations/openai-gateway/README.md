# OpenAI 网关接入

该目录只提供 OpenAI-compatible 网关旁路采集所需的本地可靠投递模块，不包含业务代理、
查询界面或评测服务。生产语义由云端 OTLP/Hook 主线提供；网关只保存它真实看到的 Wire。

流式网关在转发前调用 `beginCapture()`，持续用 `appendRequest()`/`appendResponse()` 保存
观察到的字节，再在响应结束后 `finalize()`。非流式记录可用 `enqueue()`；确认只等待本地
原子落盘，后台获得 Rust Relay 的 durable ACK 后才删除待投递文件。进程重启时会恢复
`pending` 和 `processing`，相同 `captureId` 保持幂等，不同内容使用相同 ID 时直接冲突。

远端确认必须包含 `chiptrace.capture-input-receipt.v1`，其字节数和 SHA-256 精确匹配本次
实际发送的请求正文，同时返回当前 Capture 的有效 WAL 明细。仅有 `ok/durable`、错误
身份、矛盾状态或无效 JSON 都继续重试，文件保留在 pending。Relay 会规范化输入 JSON，
因此输入哈希和规范化 WAL 哈希分别确认，不能互相替代。
发布时先更新 Relay，再更新网关模块；旧 Relay 缺少 input receipt 时，新模块会保留积压。
必须用同一发布候选的真实进程验证确认链路，并检查积压和完整性门禁。

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
- 健康检查必须要求 `outbox.snapshot().openCaptureHealthy === true`，并结合 Relay、积压、
  当前失败与截断指标。open 事务超过 `maxOpenAgeMs`（默认 30 分钟）或缺少可验证打开时间
  时，该值为 false；pending/processing 为零不能掩盖未最终化的 Capture。

历史失败 Capture 的正文如果曾经被脱敏，旧记录可能把脱敏前的 `requestBytesCaptured`/
`responseBytesCaptured` 或 SHA-256 留在元数据中。发送前 outbox 会按当前 UTF-8 正文修复这
两个字段，并保留 `*BodyTextOriginalSha256`；修复只作用于内存中的发送副本，不改写
`failed/` 审计原件。人工恢复时将原件复制（`cp -p`）到 `pending/`，等待 durable ACK，
并同时确认 `pending=0`、`processing=0` 和 `recentFailureCount=0`。

运行测试：

```bash
node --test integrations/openai-gateway/durable-outbox.test.js
# 隔离启动真实 Relay/Collector，验证确认链、OTLP 质量错误、重试与重启后的 Raw：
make gateway-receipt-test
# 部署前对实际宿主网关执行，脚本必须加载本版本 outbox 并接入上述健康门禁：
CHIPTRACE_GATEWAY_SCRIPT=/absolute/path/to/server.js make gateway-host-test
```
