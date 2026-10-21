# 业务采集数据符合性评估

本页保留 2026-10-20 03:21（Asia/Shanghai）的历史复核，并在“最新在线只读刷新”中记录当前事实。它区分
“传输层已经持久化”与“业务 Session/Turn 可以对外交付”，后者必须由真实来源覆盖和质量门禁证明。

## 结论

当前业务采集数据不满足对外生产交付要求。Collector 的 Raw/WAL 接收和恢复链路正常，但 Relay
没有观察到 Wire 来源，四源 Session/Turn 门禁未通过，且线上平台仍使用 `fs` 而非生产 OSS/S3。
因此不能把当前服务或历史采集直接交给外部方作为合格 MaaS 数据。

仓库的 MaaS 导出器已经可以处理合格的真实 Wire Capture：它拒绝 open WAL 和缺失事实，生成固定
11 字段 metadata、request 级 `tar.gz`、流式/同步响应文件，并在 `verify-maas` 阶段复验包大小、路径、
字段、JSON/JSONL、重复 requestId、Prompt 注入和敏感信息。导出合同通过不等于线上采集已经就绪。

## 与外部需求逐项对照

| 要求 | 真实证据 | 结论 |
| --- | --- | --- |
| `/maasData/archive/{providerCode}/{yyyy-MM-dd}/batch_*.tar.gz`（北京时间日期） | 导出器和 `verify-maas` 已实现并测试；线上尚未发布受验收的 MaaS 目录 | 代码通过，线上未证明 |
| 单包压缩后不超过十进制 100 MB | 真实封存段样本生成包为 10,582,450 字节；验证器强制 `<=100,000,000` | 通过（样本） |
| 每个 request 目录含 metadata、请求和响应三件文件 | 样本 56/56 请求均为三件文件，流式响应为 `biz_stream_response.jsonl` | 通过（样本） |
| metadata 固定 11 字段且身份/时间/状态/模型/usage 真实 | 样本 56/56 通过；缺字段或冲突会拒绝导出 | 通过（样本） |
| 数据必须是真实请求 | 导出器只读 sealed `api_snapshot`，不读取 open WAL、不伪造缺失字段；仓库 Rollout/Canary 产物不冒充 Wire | 规则通过，线上业务来源仍缺失 |
| 拦截恶意 Prompt 注入 | 导出和验证均 fail-closed，覆盖中英文常见模式 | 通过代码合同 |
| 邮箱、手机号、身份证、人名、地址等统一为 `<|mask_privacy|>` | 结构化敏感字段按字段别名统一掩码，邮箱/手机号/身份证/凭据和高置信姓名/地址上下文有规则；验证器拒绝未掩码字段和高置信模式 | 代码通过；低置信自由文本实体仍需来源端实体识别证据 |
| T+1 发布和 SFTP/FTP 拉取 | 仓库只生成北京时间日期目录和发布包，凭据和外部 SFTP 由供应商运维 | 交付流程待真实账号验收 |

三份外部需求原件当前仍以未跟踪文件保存在工作区：`外部 MaaS 数据交付规范.docx` 定义目录、
`batch_*.tar.gz`、100 MB 上限和三文件 request 目录；`数据要求说明(1).docx` 增加真实数据、
内容安全、禁止作假、账号/技术资产/双向保密和 `<|mask_privacy|>` 统一脱敏要求；
`Metarouters_SFTP连接与样例映射说明示例.docx` 给出 11 字段映射、T+1 02:00 和 SFTP 样例。
其中供应商编码、主机、账号、密码、指纹和具体 UTC 偏移在原件中是 `****`/`UTC+**` 占位符，
因此本机没有足够事实证明真实 SFTP 连接或最终时区已经验收。仓库当前默认 UTC+08:00 是实现选择，
需要接收方确认后才能作为外部合同事实。

## 最新在线只读刷新

2026-10-20 05:02:17（Asia/Shanghai）对同一组本机端口只读采样得到：

- `3011 /health` 返回 200，Collector `ready=true`，`captures=1,343,679`，`queue_depth=0`，
  `sealed_bytes=127,364,327,921`，`sealed_segments=873`；`3012` 的 `delivered` 与该数量一致，
  `pending=0`、`inflight=0`、`failed=0`、`conservation_ok=true`。这只证明接收、封存和投递守恒。
- `3012 /health` 返回 200、`/ready` 返回 503：`wire.requests=0`、`wire.durable_captures=0`、
  `successful_turn_scoped_captures=0`，`missing_sources=["wire"]`、`stale_sources=["wire"]`、
  `turn_capture_ready=false`。持久 `quality_errors=8,766`，其中 `otlp_traces` 为
  `identity_conflict=184`、`invalid_lifecycle=6,611`、`legacy_unclassified=1,965`，Hooks 另有
  `conversion_error=6`；本进程新增值为 1，历史账本没有被清零。
- 最新已封存的 Relay Segment `00873` 含 `1,104` 个 `telemetry_batch` 和 `157` 个
  `tool_execution`，没有 `api_snapshot`；157 条工具记录都有 Session/Thread 和 call ID，但
  `turn_id` 为 0/157，因此只能保留为未归属证据，不能按时间或 Thread 猜成某一 Turn。
- `18084 /health` 返回 200，`fullTraceCapture.bodyEnabled=true`、脱敏开关为 true，历史失败原件
  293 个（267,219,223 字节），未解决历史失败为 0；`traceExporter` 仍未配置。`18086 /health`
  返回 200，但 `backend=fs`，不是已验收的 OSS/S3。

因此本次刷新仍不满足真实 Session/Turn MaaS 交付门禁；当前可证明的是 Raw/WAL 接收、持久化、
恢复和投递守恒。上述标签保持 fail-closed：缺失 Turn 或身份冲突的记录不被重分类为成功。

## 05:15 真实客户端 Canary 结果

在上述刷新后，用未修改的 Stock Codex 二进制发起最小只读请求。18084 和 Relay 实际封存了
`20` 条带 Session/Turn 的 `api_snapshot`，响应状态全部为 `401`，因此
`successful_turn_scoped_captures=0`、`turn_capture_ready=false`；客户端在重试后超时退出。
这证明 Wire 入口、原始字节封存和 Turn 标签链路工作，但当前注入的业务凭据不被 18084 上游接受，
不能把这些失败请求当作可交付业务交互。随后用仓库 Hook helper 发出一个 SessionStart 预检，
真实返回码为 0 且没有错误输出；Hook 的传输确认正常，仍不替代成功的模型 Turn。

## 03:21 历史在线实测

只读请求观察到：

- `3011 /health` 返回 200，Collector ready，`captures=1,338,902`，`queue_depth=0`，已封存约
  `126,835,243,904` 字节。这证明 Raw/WAL 接收，不证明业务关联完整。
- `3012 /health` 返回 200，但 `ingest_coverage.wire.requests=0`、
  `wire.durable_captures=0`、`successful_turn_scoped_captures=0`，`missing_sources=["wire"]`，
  `turn_capture_ready=false`。
- `3012 /ready` 返回 503。Relay 的 `quality_errors=8,684`，包括 `identity_conflict=184`、
  `invalid_lifecycle=6,529`、`legacy_unclassified=1,965`，另有 Hook `conversion_error=6`。
  因此四源覆盖、来源新鲜度和零质量错误门禁均失败。
- `18084 /health` 返回 200，但 `traceExporter.enabled=false`、`configured=false`，
  `fullTraceCapture.adapterDoesPayloadSanitization=false`，且保留 293 个历史失败文件（约 267 MB）。
- `18086 /health` 返回 200，但 `backend=fs`。生产门禁要求明确配置并实测 `oss` 或 `s3`，所以该结果
  不能作为真实 OSS 证据。

这些计数会随服务运行变化；再次验收必须重新采集同一组健康、覆盖、质量和后端字段，不能用本页旧
数字替代当前证据。

## 真实封存样本验证

从 Relay 的 sealed Segment 读取一段真实 Capture（不修改源文件）后，导出器观察到 56 条
`api_snapshot`，跳过 2,211 条非 Wire 记录，生成：

```text
providerX/2026-09-15/batch_00001.tar.gz
compressed bytes: 10,582,450
requests: 56
protocol: OPENAI_RESPONSES
requestMode: STREAM
httpStatus: 200
```

`verify-maas` 对该包返回成功。仓库中的 `target/rollout-smoke.../captures.jsonl` 和
`target/codex-0150-shadow.../captures.jsonl` 当前分别只有 `rollout_event`，
`target/native-canary-state/events.ndjson` 只有生命周期/评价记录；它们不能直接导出为外部
request 级 MaaS 数据。

## 交付前必须补齐

1. 虽然当前系统和实际 `CODEX_HOME` 路由预检已对同一 18084 网关退出 0，仍需从新进程产生带
   真实 Session/Turn 身份的请求，并确认 Wire 成功到达 Relay。
2. 修复 OTLP traces 的身份冲突、重复 lifecycle 终态和历史未分类来源；保留历史 Raw，重新验收
   新增数据，直到质量门禁为零且四源覆盖、新鲜度完整。
3. 在 18084 启用并验证 payload 采集/脱敏和失败 outbox 清理策略，保留可审计失败记录。
4. 将平台切换到真实 OSS/S3，使用独立生产 root、固定镜像 revision 和小数据上传/下载 SHA-256
   验收；`/health` 必须与目标后端一致。
5. 对目标 Session 执行真实多轮 Canary，封存后只导出通过 `verify-maas` 的包，并由接收方确认
   SFTP/FTP 目录、时间窗口和下载结果。
