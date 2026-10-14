# 部署与运维

## 隔离环境

`deploy/docker-compose.yml` 提供隔离引擎自测，`deploy/cloud-platform.yml` 提供平台插件部署。
提交前执行：

```bash
make cloud-test
make m0-test
```

其中 `cloud-test` 检查格式、Clippy、Rust/网关测试、平台 HTTP/SDK 和完整云端验收自测；`m0-test` 在 Docker
中复现。热服务只在真实 Stock Codex canary 通过后升级。

## 云端服务

```bash
export CHIPTRACE_IMAGE='chiptrace:<git-revision>'
export CHIPTRACE_NETWORK='router-v2-net'
export CHIPTRACE_CAPTURE_ROOT='/srv/chiptrace/capture'
export CHIPTRACE_COLLECTOR_STATE_ROOT='/srv/chiptrace/collector-state'
export CHIPTRACE_RELAY_ROOT='/srv/chiptrace/relay'
export CHIPTRACE_INGEST_TOKEN='<at-least-32-bytes>'
docker compose -f deploy/collector-relay.yml up -d
```

18084 对外提供 Responses、`/models`、`/otel/v1/logs`、`/otel/v1/traces` 和
`/hooks/codex`。Responses 与 `/models` 使用 Provider 业务鉴权，网关使用内部采集凭据读取
Relay 目录；OTLP 与 Hook 使用独立采集凭据。Wire Capture 使用网关磁盘 outbox，其余采集
请求获得 Rust Relay 的 durable ACK。格式错误返回 400，认证失败返回 401，ID 冲突返回
409，只有暂时故障返回可重试 5xx。

2026-10-15 的只读检查显示，18084、3011、3012 均返回 HTTP 200；Collector/Relay 已
投递 1,021,950 条，`pending=0`、`failed=0`、`conservation_ok=true`。当前运行镜像仍是
`chiptrace:0.6.0-readiness-r2-20260905`，不是本分支最新修复。18084 还有 3 个 open
transaction、293 个历史失败文件（约 267 MB），watchdog 配置存在但
`watchdog.running=false`；3012 的旧 Relay 报告 `wire_age_ms=162514459` 且
`freshness_applicable=false`，所以其 `status=complete` 不能作为最新 freshness 门禁已
部署的证据。18086 当前没有监听，平台插件尚未作为在线服务运行。

隔离 patched Canary 已通过当前仓库门禁，但线上镜像尚未切换。生产发布仍需先完成远端
CI、目标 OSS 账号验收和未修改 Stock Codex 的真实 Canary，再灰度升级并复查重启/回滚。
历史失败文件和 open transaction 是审计证据，不能为了让健康计数变绿而删除。

## Stock Codex

管理员按 [Stock Codex 接入](../integrations/codex/README.md) 下发原生配置。用户主机没有
ChipTrace 程序或服务，用户仍直接运行：

```bash
codex
```

`SessionStart` 会同步检查采集入口；配置无效、认证失败或入口不可用时，在首个 Turn 前
停止。任务期间发生缺失时不阻断业务，但该 Session 不能交付。

## 云端验收

先确认目标 Session 的 `SessionEnd` 已到达 Collector，且该 Session 的 Wire、OTLP 和
Hook 均已持久化。网关 outbox 和 Relay 的待投递队列需要排空；持续业务流量下，全局
计数器不能代替目标 Session 的完整性校验。

Collector 支持在线封存，不需要停止热服务。在本机管理地址调用：

```bash
curl -fsS -X POST http://127.0.0.1:3011/flush
```

`3011` 是 router_v2 部署的 Collector 映射端口，其他部署按实际映射调整。返回
`ok=true`、`sealed=true` 后，当前段已成为不可变文件，服务继续向新 open 段写入。
归档应固定此次封存边界内、每个 shard 从 Segment 1 开始的连续 sealed 文件集合，
通过重复的 `--input <sealed-file>` 传入。不要把持续写入的目录直接作为完整快照：新
open 段一旦非空，`archive-raw` 会拒绝该目录；未封存尾段也不会被离线投影读取。

提交 Raw Archive 后，再导出同一时间窗的 Sub2API usage log。随后只运行：

```bash
chiptrace cloud-acceptance \
  --archive-id <archive-id> \
  --backend oss \
  --endpoint <oss-endpoint> \
  --bucket <bucket> \
  --prefix chiptrace \
  --usage-log <usage.jsonl> \
  --session-id <stock-codex-session-id> \
  --release-id <release-id> \
  --output <acceptance-directory>

chiptrace verify-cloud-acceptance \
  --acceptance <acceptance-directory>
```

通过目录中的 `buyer-package/` 是可上传交付物；`manifest.json` 汇总分数、轮次、工具、
配对率、Token、OTLP 父子关系以及每一阶段 Manifest 的 SHA-256。失败命令返回非零状态，
且不会覆盖已有通过目录。

## 云平台插件

需要把收集与验收能力嵌入已有云平台时，使用
[integrations/cloud-platform](../integrations/cloud-platform/README.md) 的服务端插件。
它把每个实例绑定到一个项目命名空间，任务确认、队列、Raw 恢复目录、Session/Turn 分页
sidecar 和交付包都落在 `CHIPTRACE_PLATFORM_ROOT`；客户端只能提交已授权的 ID，不能传入
路径、OSS 凭据或降低 Buyer v7 门槛。服务令牌只用于平台后端之间的调用，外层仍应接入
平台自己的用户鉴权和租户授权。

本地磁盘模式可直接运行：

```bash
export CHIPTRACE_PLATFORM_TOKEN='<at-least-32-bytes>'
export CHIPTRACE_PLATFORM_ROOT=/srv/chiptrace/platform
export CHIPTRACE_CAPTURE_ROOT=/srv/chiptrace/capture
export CHIPTRACE_OBJECT_ROOT=/srv/chiptrace/objects
export CHIPTRACE_BACKEND=fs
sudo install -d -o 10001 -g 10001 -m 0700 \
  /srv/chiptrace/platform /srv/chiptrace/objects
docker compose -f deploy/cloud-platform.yml up -d --build
```

OSS/S3 模式只替换后端环境变量，归档仍会在工作目录恢复后才进入验收：

```bash
export CHIPTRACE_BACKEND=oss                 # or s3
export CHIPTRACE_OBJECT_ENDPOINT='<endpoint>'
export CHIPTRACE_OBJECT_BUCKET='<bucket>'
export CHIPTRACE_OBJECT_PREFIX='datasets/chiptrace'
export OSS_ACCESS_KEY_ID='<service-key>'
export OSS_ACCESS_KEY_SECRET='<service-secret>'
```

CI 使用隔离 MinIO 验证 S3 协议、对象长度和 SHA-256；真实 Alibaba OSS 账号、区域 endpoint
和 IAM 权限仍需在目标部署账户做一次小数据验收，不能用本地 FS 结果代替。

显式 `--session-id` 投影会顺序扫描两遍全部输入：先建立身份与子会话关系索引，再只保留
选中 Session 的载荷。跨 Session 的 captureId 冲突、精确请求关联冲突和来源校验仍会拒绝
输入。内存需求取决于身份索引和选中 Session 的大小；未指定 Session 的取证投影仍可能
载入全量。完整验收还会恢复 Raw、生成富化副本并多次验证 SHA，应使用独立离线资源和
足够磁盘空间，不要在在线请求处理进程内执行。

## 监控

- 业务 Responses 增长时，Wire、OTLP logs、OTLP traces 和 Hook 四源是否同时增长。
- Relay `ingest_coverage.status` 必须保持 `complete`。`partial` 表示启动预热或来源尚未出现；
  `degraded` 表示 Wire 活跃时 Runtime 来源缺失或落后超过 5 分钟，也表示 OTLP/Hook 仍在
  近 5 分钟持续流入而 Wire 停止或落后超过 5 分钟。后者会把 `wire` 列入 `stale_sources`，
  应按 `missing_sources`、`stale_sources`、`source_lag_ms`、`runtime_age_ms` 和 `wire_lag_ms`
  检查 Stock Codex 受管配置；不能用 Runtime 来源的增长把 Wire 断流解释为 complete。
- Relay `pending`、`inflight`、最老队列时间、磁盘空间和 attempt 守恒。
- `output_truncated=true`、未知 OTLP 事件、转换错误和身份冲突。
- Session start/end、模型调用/结果/执行、内部父引用的完整率；以及每个 Turn 的 Wire、
  OTLP logs、OTLP traces、required Hook 覆盖和 `incomplete_turns`。
- Buyer v7 失败原因、合格 Session 数和四种 Token 口径。

网关 `/health` 的 `fullTraceCapture.currentDeliveryHealthy=true`、`outbox.pending=0`、
`outbox.processing=0`、`outbox.recentFailureCount=0` 且 `rustRelay.conservationOk=true`
才表示当前 Wire 投递闭环可交接。`historicalFailures` 是启动前保留的审计证据，不应因
数量非零而清理或把服务标成故障。旧版本在正文脱敏后可能留下过期的 body 长度/哈希；当前
outbox 会在新写入和发送历史副本前按实际 UTF-8 正文幂等重算元数据，并保留已有的原文哈希。
`outbox.openTransactions`、`outbox.oldestOpenAgeMs` 和 `outbox.staleOpenTransactions` 也必须
纳入告警；长期 open 的流式 Capture 不是已交付证据，必须保留为未完成证据或完成最终化后
再交付。
宿主网关健康门禁必须要求 `outbox.openCaptureHealthy === true`；该值在超龄或缺少可验证
open 时间的事务存在时为 false。router_v2 宿主使用 `FULL_TRACE_CAPTURE_HEALTH_MAX_OPEN_MS`
配置期限，默认 30 分钟。新增模块和宿主检查只在进程重新加载后生效，修改挂载文件不等于部署。
重放失败证据时只能复制到 `pending`（不要移动或删除 `failed` 原件），确认 Relay durable
ACK 后再以 pending/processing 清零作为完成条件。

生命周期 Hook 不是心跳。单个 Turn 超过 5 分钟且没有新的生命周期边界时，可能出现
`stale_sources=["hooks"]`；这是需要核对的来源新鲜度告警，不单独证明数据丢失。
应检查目标 Session 的起始 Hook、持续 OTLP，以及结束后的 `SessionEnd` 和投影完整性。
Session 检查以 `session.delivery_ready`（及 inspect 顶层同名字段）作为完整 Turn 门禁，
用 `unscoped_source_records` 定位无法归属的来源。Runtime `integrity.delivery_ready` 只证明
Canonical Runtime/协议检查通过，不能覆盖原生 Turn 的缺失、未归属或未闭合状态。

进一步定位时使用只读 `audit-session-context --input <sealed-raw> --session-id <id>`。
该入口不生成投影，复用全快照身份歧义与子 Session 选择，并对所选 envelope 内全部 OTLP
记录保留分类总数；`unknown_session_records` 不会被默认为当前 Session。
来源端显式声明 `codex.context_scope=process` 的后台记录计入 `process_level_records`，
不会参与 Turn 覆盖；缺少该声明的进程级记录仍按未知 Session 处理。
`--sample-limit 0` 可关闭定位样本，分组和样本上限不会截断总计数。
诊断报告保留 ID/名称元数据，按项目控制访问；完整交付结论仍来自云端验收。

## 回滚

发布和回滚时同时更新部署环境文件中的 `CHIPTRACE_IMAGE`，使后续 Compose 重建使用
已验收的不可变镜像；仅在单次命令中设置环境变量不会更新持久部署配置。

回滚只恢复上一个不可变云端镜像和 18084 路由。WAL、OSS Checkpoint、Release 和失败证据
不删除、不回退；旧版本不理解的新事件继续保持 Raw-only。
