# 网关源码

`server.js` 是 18084 业务网关的正式源码，与主机 `/nfs/home/zhangyuxin/router_v2/relay_shell`
运行的是同一份文件（Compose 用 bind mount 覆盖）。`durable-outbox.js` 是它唯一的本地依赖。

变更网关必须：

1. 修改本目录的 `server.js`；
2. 运行 `make gateway-source-test`（`server-capture.test.js` + `server-identity.test.js`）；
3. 重建 `router-v2-relay-shell` 容器并确认 `/health` 的 `status=healthy`。

`server-identity.test.js` 覆盖大于 1 MiB 的 Anthropic 请求体：`metadata.user_id` 位于 JSON
末尾，网关需要头部 + 尾部采样才能回填 native Session 和 Hook 派生的 Turn。

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

`refreshQueueStats()` 只发布未与本进程队列变更重叠的磁盘扫描；入队、流式写入、
最终化、投递和恢复发生在扫描期间时会重读，避免漏计新文件或把已确认记录重新计为
pending。等待远端确认时仍可重扫并观察 processing；扫描不修改 Capture 正文或历史失败。

`beginCapture()`、流式追加和 `enqueue()` 共用字节与文件数预留；预留在磁盘操作前完成，
一直保留到计数更新或写入失败，避免并发请求同时通过容量检查。流式追加也检查文件数、
剩余空间和 inode 水位。最终化可抵扣旧 spool 的逻辑队列用量，但物理空间和 inode 必须
足够容纳新的完整 JSON，旧 spool 在新记录持久化后才释放；重启恢复逐条释放已转换用量。

写入或最终化失败会立即令 `openCaptureHealthy=false`，`openWriteFailures` 返回本进程中
受影响的 open Capture 数。已写入的字节继续保留；`finalize()` 返回真实错误，重启后按
`recovered_incomplete` 恢复，不能当作完整交付。追加方法仍通过写入链保存错误并在
`finalize()` 拒绝，调用方还应持续检查健康状态。磁盘水位基于缓存的文件系统观察，不能
阻止其他进程占满共享磁盘；实际 I/O 错误仍须保留和告警。

流式最终化与 incomplete 恢复会生成 `chiptrace.open-capture-receipt.v1`，绑定 ingress
元数据、原始 spool 和实际保存正文的长度与 SHA-256。重启时如果已有同 ID 记录，必须
核对 pending/processing/failed 中的全部版本、原始身份和 receipt 后才能清理 open 原件；
同 ID 本身不证明内容相同。旧记录缺少 receipt 或任一内容冲突时，启动返回
`CAPTURE_ID_CONFLICT`，两份证据均保留，需按原始证据处理，不能直接删除或补造确认。

清理先删除正文 spool 并同步目录，最后删除 ingress 元数据；若中途停止，匹配的
receipt 支持继续清理已移除部分正文的事务。清理完成前该记录不进入远端投递，其他
Capture 仍可投递。拆分在多个 chunk 中的 UTF-8 会按完整 spool 验证；最终 spool
包含无效 UTF-8 时返回 `CAPTURE_BODY_ENCODING` 并保留原始字节，避免用替换字符改写 Wire。
这份本地恢复确认与 Relay 的 input receipt 分别验证，均不代表 Session/Turn 已完整交付。

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
  当前失败与截断指标。open 事务写入/最终化失败、超过 `maxOpenAgeMs`（默认 30 分钟）或
  缺少可验证打开时间时，该值为 false；pending/processing 为零不能掩盖未最终化的 Capture。

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
