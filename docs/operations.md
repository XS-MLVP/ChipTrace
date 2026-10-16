# 部署与运维

## 隔离环境

`deploy/docker-compose.yml` 提供隔离引擎自测，`deploy/cloud-platform.yml` 提供平台插件部署。
平台模板要求显式设置 `CHIPTRACE_BACKEND`；生产环境应选择 `oss` 或 `s3`，未配置对象存储
时预检会拒绝启动，独立启动 `server.js` 也会拒绝缺失或非法后端，避免把完整 Raw
误落到本地对象目录。
提交前执行：

```bash
make cloud-test
make m0-test
```

其中 `cloud-test` 检查格式、Clippy、Rust/网关测试、平台 HTTP/SDK 和完整云端验收自测；`m0-test` 在 Docker
中复现。热服务只在真实 Stock Codex canary 通过后升级。

## 云端服务

```bash
export CHIPTRACE_REVISION="$(git rev-parse HEAD)"
docker build --build-arg CHIPTRACE_REVISION="$CHIPTRACE_REVISION" \
  -t "chiptrace:$CHIPTRACE_REVISION" .
export CHIPTRACE_IMAGE="$(docker image inspect --format '{{.Id}}' "chiptrace:$CHIPTRACE_REVISION")"
export CHIPTRACE_NETWORK='router-v2-net'
export CHIPTRACE_CAPTURE_ROOT='/srv/chiptrace/capture'
export CHIPTRACE_COLLECTOR_STATE_ROOT='/srv/chiptrace/collector-state'
export CHIPTRACE_RELAY_ROOT='/srv/chiptrace/relay'
export CHIPTRACE_INGEST_TOKEN='<at-least-32-bytes>'
sudo install -d -o 10001 -g 10001 -m 0700 \
  /srv/chiptrace/capture /srv/chiptrace/collector-state /srv/chiptrace/relay
node scripts/deploy/preflight.js --file deploy/collector-relay.yml
docker compose -f deploy/collector-relay.yml up -d --no-build --pull never
```

镜像须固定为本机完整 `sha256:<image-id>` 或仓库 `repository@sha256:<digest>`，不能只用
版本 tag。预检只读解析实际 Compose 配置，拒绝可变 tag、缺失隔离/资源限制及与目标
完整 Git SHA 不一致的 OCI revision；不会启动或更新服务。跨主机发布时使用仓库 digest。
构建参数写入 Collector/Relay 的健康响应；启动后还需核对实际编译 revision 和业务门禁。
预检通过不替代真实 Stock Codex、OSS 账号或目标 Session 验收。

模板默认 Collector 8 GiB、Relay 12 GiB、平台 4 GiB 内存上限，均为 2 CPU、256 PID。
可通过 `CHIPTRACE_COLLECTOR_MEMORY_LIMIT`、`CHIPTRACE_RELAY_MEMORY_LIMIT`、
`CHIPTRACE_PLATFORM_MEMORY_LIMIT`、`CHIPTRACE_CPU_LIMIT`、`CHIPTRACE_PID_LIMIT` 调整。
这些是隔离上限，不是实测容量承诺或预留：Collector/Relay 的正文预算为 4 GiB，Relay
另有 4 GiB 投递预算，解析、队列及索引仍消耗内存。须根据最大正文、并发与任务规模实测
峰值后配置，监控 OOM 和磁盘余量；不能直接把小样本 CI 的成功当作生产负载验收。
三个服务均以非 root 用户、只读根运行，仅显式数据挂载和平台 tmpfs 可写。

18084 网关也必须通过容器级隔离预检。它拥有原始 Wire 的 durable outbox，不能继续使用
可变镜像 tag、可写根文件系统或无资源上限的容器：

```bash
node scripts/deploy/gateway-preflight.js --container <gateway-container>
```

预检只输出镜像摘要、OCI revision、资源限额和挂载/采集开关，不输出环境变量或凭据；失败时
不得以重启或清理 outbox 绕过。生产 Gateway 还必须通过同一 runtime gate 的历史失败文件、
质量错误和新鲜 Turn Wire 门禁。当前 router_v2 的 `router-v2-relay-shell` 仍使用
`weishaw/claude-relay-service:latest`，根可写且没有 CPU/内存/PID 限额，因此该容器级门禁
在现状下应退出非零；这与 HTTP `/health` 返回 200 是两条独立证据。

18084 对外提供 Responses、`/models`、`/otel/v1/logs`、`/otel/v1/traces` 和
`/hooks/codex`。Responses 与 `/models` 使用 Provider 业务鉴权，网关使用内部采集凭据读取
Relay 目录；OTLP 与 Hook 使用独立采集凭据。Wire Capture 使用网关磁盘 outbox，其余采集
请求获得 Rust Relay 的 durable ACK。格式错误返回 400，认证失败返回 401，ID 冲突返回
409，只有暂时故障返回可重试 5xx。

OTLP 上下文重复属性或有效身份别名冲突会先保留 Raw，再返回 `HTTP 400` 和
`reason=cloud_ingest_quality_error`，即使响应包含 `durable/local_durable=true` 也不是质量
成功。应修复来源端冲突，保留原失败及质量计数。旧版本已落盘 Capture 的派生元数据可能
与新版不同，同一 ID 重投可能返回 409；升级不能自动重新认证历史 delivered 账本或改写 Raw。
入口与离线审计共用 Session/Turn 身份规则，包括 UUID 形式的原生 `thread_id`；冲突记录
不能派生出工具所有者或带归属的不完整事件。同批正常记录继续保留。相同别名合法，
resource/scope/record 的既定覆盖顺序不变；原生 Turn 与 root Turn 是不同身份，不要求相等。

2026-10-15 复查确认，18084、3011、3012 均返回 HTTP 200；Collector/Relay 已运行
revision `fe9fcf924b226099202cb770b7cf0da29e0c2310`，`pending=0`、`failed=0`、
`conservation_ok=true`。18084 的 open transaction 已为 0，293 个历史失败文件
（267,219,223 bytes）仍保留。新 Relay 进程收到 OTLP logs/traces 和 Hook，Wire 只有 1 条；
活动 WAL 的固定长度只读快照确认它是没有原生 Session/Turn 的 HTTP 403。全局四源门禁
曾短暂通过，但这不证明业务 Turn 采集成功。随后 Wire 超过 5 分钟未更新，
`required_sources_fresh=false`，带预期 revision 的 runtime gate 真实退出 1。
trace exporter 未启用，watchdog 最近报告重试失败；18086 没有监听。

读取到的系统和用户配置存在同名 Provider 的不同 `base_url`。离线原生客户端回归确认，
系统 `config.toml` 的默认路由可以被用户配置覆盖；仅有 OTLP/Hook 流量不能证明 Wire
经过 18084。新 requirements 模板通过原生 exact Provider 约束修复这个接入风险，但本次
没有改动线上 `/etc/codex` 或用户配置。更新受管配置后必须从新客户端进程获取真实 Wire，
再复验 runtime gate 和目标 Session 的四源关联；不能用合成 Capture 把线上计数补成通过。

隔离 patched Canary 已通过仓库门禁，但不证明线上未修改客户端已经通过。提交
`13164883972a33634e4c420d532e612c666edfad` 的
[远端 CI](https://github.com/XS-MLVP/ChipTrace/actions/runs/38674424831)
已确认 5/5 作业成功；该结果只覆盖这一 SHA。生产交接仍需待发布 SHA 的远端 CI、
目标 OSS 账号验收、未修改 Stock Codex 的真实 Canary，以及重启/回滚复验。
历史失败文件和 open transaction 是审计证据，不能为了让健康计数变绿而删除。

## Stock Codex

管理员按 [Stock Codex 接入](../integrations/codex/README.md) 下发原生配置。用户主机没有
ChipTrace 程序或服务，用户仍直接运行：

```bash
codex
```

`SessionStart` 会同步检查采集入口和 Relay 持久化确认；配置无效、认证失败、入口不可用，
或仅返回 HTTP 200 而没有合法确认时，在首个 Turn 前停止。它不检查有效 Provider 或 OTLP
路由，不能替代 requirements 的 Provider 约束和真实来源验收。其他版本部署前须通过
`make managed-route-test`，确认 exact 约束确实生效。
任务期间发生缺失时不阻断业务，但该 Session 不能交付。

ACK-only 备用服务不保存 Trace，不能作为采集健康或交付证据。open21 若曾启用
`codex-open21-chiptrace-ack-sink.service`，真实网关恢复后应先确认 `/health` 的
`fullTraceCapture.enabled=true` 且传输健康，再停用其开机启动并将 unit 归档，随后执行
用户级 `daemon-reload`；历史日志保留。不能让备用 ACK 代替 required Hook 的持久化确认。
更新原生命令后须重新部署 requirements；用户级 Hook 还需在最终路径重新审核 trust hash。

## 云端验收

### Provider Responses 前置门禁

`/models` 返回 200 只证明业务 Key 能读取模型目录，不能证明实际 Responses 请求能被上游执行。
发布或真实 Canary 前，使用受管的业务 Key 对同一网关发送一次有界、带 Session/Turn 身份的
Responses 探针；探针不会把 Key、请求正文或响应正文写入报告：

```bash
export CHIPTRACE_API_KEY='<provider-key-from-secret-manager>'
node scripts/ci/provider-response-gate.js \
  --responses-url http://127.0.0.1:18084/responses \
  --model gpt-5.6-sol \
  --report /srv/chiptrace/acceptance/provider-response.json
```

该命令必须返回 2xx 和有效 Responses `id`。401/403、网关 502、超时或空/错误响应都阻止
真实 Canary；网关可能把上游余额、权限或路由故障归一化为 502，因此还要同时检查 Sub2API
日志中的上游错误码。探针通过后仍必须完成真实 Stock Codex 的多轮四源验收，探针本身不构成
Session 交付证据。

GitHub CI 的 `live-provider-runtime-preflight` 只在手工 `workflow_dispatch`、
`live_preflight=true`、受保护分支/规则集、受保护的 `production-canary` Environment 和标签为
`self-hosted, linux, chiptrace-canary` 的内网 Runner 上执行。Environment Secret 必须提供
`CHIPTRACE_API_KEY`；Environment Variables 必须提供
`CHIPTRACE_RESPONSES_URL`、`CHIPTRACE_GATEWAY_HEALTH_URL`、`CHIPTRACE_RELAY_HEALTH_URL`
和 `CHIPTRACE_COLLECTOR_HEALTH_URL`。手工输入的 `expected_revision` 必须是 Collector/Relay
实际构建的完整 Git SHA。普通 push/PR 不接触这些 Secret，也不会因为缺少 Runner 或变量而
跳过真实预检。该作业只确认 Provider 请求和当前进程 readiness，随后仍须用同一 Session
执行未修改 Stock Codex 的多轮四源 Canary、OSS 验收和 `cloud-acceptance`。
Live preflight 还要求 Relay 的 `ingest_coverage.quality_errors` 为 0；该计数从持久
Delivery ledger 恢复，`quality_errors_scope` 必须为 `durable_relay_state`，而
`quality_errors_current_process` 仅用于区分本次进程新增错误。重启不能把历史错误静默归零；
若历史错误已存在，应先保留其报告并修复生产者或采集配置，再开始新的 Canary。

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
sidecar、canonical interaction projection 和交付包都落在 `CHIPTRACE_PLATFORM_ROOT`；
客户端只能提交已授权的 ID，不能传入路径、OSS 凭据或降低 Buyer v7 门槛。服务令牌只用于
平台后端之间的调用，外层仍应接入平台自己的用户鉴权和租户授权。检查任务的 `/turns`
接口提供有界的 Turn 索引，`/projection/{part}` 提供经过 SHA-256 复核的完整
ModelInteraction、RuntimeSpan 和 InteractionLink 证据。

本地磁盘模式可直接运行：

```bash
export CHIPTRACE_PLATFORM_TOKEN='<at-least-32-bytes>'
export CHIPTRACE_PROJECT_ID='project-001'
export CHIPTRACE_PLATFORM_ROOT=/srv/chiptrace/platform
export CHIPTRACE_CAPTURE_ROOT=/srv/chiptrace/capture
export CHIPTRACE_OBJECT_ROOT=/srv/chiptrace/objects
export CHIPTRACE_BACKEND=fs
export CHIPTRACE_REVISION="$(git rev-parse HEAD)"
docker build --target platform --build-arg CHIPTRACE_REVISION="$CHIPTRACE_REVISION" \
  -t "chiptrace-platform:$CHIPTRACE_REVISION" .
export CHIPTRACE_PLATFORM_IMAGE="$(docker image inspect --format '{{.Id}}' "chiptrace-platform:$CHIPTRACE_REVISION")"
sudo install -d -o 10001 -g 10001 -m 0700 \
  /srv/chiptrace/platform /srv/chiptrace/objects
node scripts/deploy/preflight.js --file deploy/cloud-platform.yml
docker compose -f deploy/cloud-platform.yml up -d --no-build --pull never
```

项目 ID、采集路径和存储命名空间由 root 下的 `NAMESPACE.json` 在首次启动时绑定。
源配置变化会在加载任务和复用缓存前返回 `NAMESPACE_CONFLICT`；没有绑定的历史非空
root 返回 `NAMESPACE_UNBOUND`，原数据保留。新版本需要显式项目 ID；历史状态或存储
迁移须使用新的项目 root，先校验目标命名空间的权威 Raw，再重新提交恢复、检查和导出。
不要补造绑定或复制旧任务/缓存来绕过检查。凭据轮换和资源限额变化可继续使用同一绑定。

首次配置 OSS/S3 项目时，设置独立 root 和后端环境变量；归档仍会在工作目录恢复后才进入验收：

```bash
export CHIPTRACE_BACKEND=oss                 # or s3
export CHIPTRACE_PLATFORM_ROOT=/srv/chiptrace/platform-oss-project-001
export CHIPTRACE_OBJECT_ENDPOINT='<endpoint>'
export CHIPTRACE_OBJECT_BUCKET='<bucket>'
export CHIPTRACE_OBJECT_PREFIX='datasets/chiptrace'
export OSS_ACCESS_KEY_ID='<service-key>'
export OSS_ACCESS_KEY_SECRET='<service-secret>'
sudo install -d -o 10001 -g 10001 -m 0700 \
  /srv/chiptrace/platform-oss-project-001
```

CI 使用隔离 MinIO 验证 S3 协议、对象长度和 SHA-256；真实 Alibaba OSS 账号、区域 endpoint
和 IAM 权限仍需在目标部署账户做一次小数据验收，不能用本地 FS 结果代替。

`make deployment-config-test` 通过真实 `docker compose config` 验证模板及负例。
容器 CI 另运行 `scripts/ci/deployment-smoke.js`，在随机项目、临时挂载和独立网络中实际
启动这两个模板的三个服务，核对镜像 ID、OCI/CLI revision、资源限制和健康状态，再验证
Relay/Collector 的精确 Raw、重复确认、平台归档/恢复、Turn 和采购包下载及重启后字节
一致性。它只使用合成数据和 FS 后端，精简报告明确不宣称真实上游、OSS 或生产验收；
失败证据留在临时目录，不上传 Raw。通过后删除本次临时数据及自建容器/网络，不触及热服务。

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
- `ingest_coverage.wire_turn_coverage` 的成功 Turn Wire 数及新鲜度。无身份、上下文冲突、
  非 2xx 请求和重复投递均不能刷新 `last_successful_at`；它们仍计入各自真实 ACK 统计。
- `ingest_coverage.turn_capture_ready` 必须为 `true` 才能把进程交给新的真实 Canary；
  `false` 只表示当前进程缺少就绪证据，不代表已有 Raw 可以补造为完整 Session。
- `output_truncated=true`、未知 OTLP 事件、转换错误和身份冲突。
- `ingest_coverage.quality_errors_by_endpoint` 用于区分 `otlp_logs`、`otlp_traces` 和 `hooks`
  的 `unknown_events`、`conversion_errors` 与总数；总数必须和持久化的 `quality_errors` 对账，
  `quality_errors_current_process` 仅表示本次进程增量。`quality_errors_scope` 缺失或不是
  `durable_relay_state` 时门禁必须失败。先保留失败快照，再修正生产者或采集配置。
- Session start/end、模型调用/结果/执行、内部父引用的完整率；以及每个 Turn 的 Wire、
  OTLP logs、OTLP traces、required Hook 覆盖和 `incomplete_turns`。
- Buyer v7 失败原因、合格 Session 数和四种 Token 口径。

网关 `/health` 的 `fullTraceCapture.currentDeliveryHealthy=true`、`outbox.pending=0`、
`outbox.processing=0`、`outbox.recentFailureCount=0` 且 `rustRelay.conservationOk=true`
才表示当前传输闭环健康；它们不证明收到过有归属的成功 Turn Wire。
`historicalFailures` 是启动前保留的审计证据，不应因
数量非零而清理或把服务标成故障。旧版本在正文脱敏后可能留下过期的 body 长度/哈希；当前
outbox 会在新写入和发送历史副本前按实际 UTF-8 正文幂等重算元数据，并保留已有的原文哈希。
生产发布门禁可以用 `--max-historical-failed-files 0` 把仍未成功 ACK 的历史文件列为阻断条件；
这不会删除或覆盖 `failed/` 原件。若需要先恢复证据，应按下文的只复制到 `pending/` 流程处理，
直到文件重新得到 durable ACK，再重新运行门禁。
`outbox.openTransactions`、`outbox.oldestOpenAgeMs` 和 `outbox.staleOpenTransactions` 也必须
纳入告警；长期 open 的流式 Capture 不是已交付证据，必须保留为未完成证据或完成最终化后
再交付。
宿主网关健康门禁必须要求 `outbox.openCaptureHealthy === true`；该值在超龄或缺少可验证
open 时间的事务存在时为 false。router_v2 宿主使用 `FULL_TRACE_CAPTURE_HEALTH_MAX_OPEN_MS`
配置期限，默认 30 分钟。新增模块和宿主检查只在进程重新加载后生效，修改挂载文件不等于部署。
升级后应在同一窗口执行仓库提供的 runtime health gate：

```bash
node scripts/ci/runtime-health-gate.js \
  --gateway-url http://127.0.0.1:18084/health \
  --relay-url http://127.0.0.1:3012/health \
  --collector-url http://127.0.0.1:3011/health \
  --expected-revision <git-revision> \
  --max-quality-errors 0 \
  --max-historical-failed-files 0 \
  --report /var/tmp/chiptrace-runtime-health.json
```

三个参数都须传完整 `/health` URL；Collector 端口按实际映射调整。v3 要求同时观察
网关、Relay 和 Collector，缺少探测参数、Collector 不可达、不 ready、有队列或错误时
均真实退出非零。Relay/Collector 的构建 revision 必须是完整 Git SHA 且相同；提供
`--expected-revision` 时两者均须匹配待发布版本。Collector 持久 Capture 总数不得低于
Relay delivered；额外的私有评估或其他 Relay 数据不要求计数相等。计数下界不证明 Raw
逐对象完整性，仍须对目标 Session 独立验收。预检的 OCI label 不能替代运行版本探测。

门禁继续要求网关 `openCaptureHealthy`、Relay `freshness_applicable`、四路来源新鲜、
队列排空和 attempt 守恒。保留 v2 的 `wire_turn_coverage` 要求：明确原生 Session/Turn、无
上下文冲突的 HTTP 2xx Capture，且最近一次新 durable Capture 在五分钟窗口内；旧 Relay
缺少新统计时失败。统计按真实 durable ACK 逐条累加，包含 duplicate，批量冲突或失败项
不计入；duplicate 不刷新成功证据的时间。HTTP 2xx 仅指 HTTP 状态，不证明 SSE 模型终态、
客户端交付或整个 Session 完整。输出固定 `session_delivery_claimed=false`，逐 Session
交付仍必须通过 `cloud-acceptance`。
Relay 重启后进程级来源证据重新开始；旧 Raw 和导出仍可验证，但必须让新真实 Canary
重新产生四源和成功 Wire，才能通过运行门禁。重复回放不能刷新成功 Wire 的新鲜度。
旧网关缺少 `openCaptureHealthy`，或旧 Relay 在 Runtime 有流量而
Wire 停止时返回 `freshness_applicable=false`，都会失败；历史失败文件仍保留为审计证据，
不会被当作当前失败清理。
传入 `--report` 时，成功结果写入完整门禁摘要；失败结果写入一次性、0600 的
`chiptrace.runtime-health-observation.v1` 快照。快照只包含版本、计数、队列、来源新鲜度、
按端点质量错误分解、Turn Wire 统计和有界的 `blocking_reasons` 代码（一次列出所有已知阻断类别），
不包含健康 URL、Raw、对话正文、工具参数、凭据或任意错误字段；
目标路径必须事先不存在，避免覆盖事故证据。即使 Collector/Relay 探测失败，也会留下
`failure_kind=fetch_failed` 的最小快照。
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
Turn 业务事件不能以直接声明或精确父链继承的 Process scope 获得豁免；出现冲突时，
审计和 Session 检查真实失败，Raw 保留。七类事件名单及回归证据见
[原生上下文约束](native-turn-context.md)。
`--sample-limit 0` 可关闭定位样本，分组和样本上限不会截断总计数。
诊断报告保留 ID/名称元数据，按项目控制访问；完整交付结论仍来自云端验收。

`inspect-session` 顶层 `delivery_ready` 还要求同快照的 `source_context_audit` 没有未知
Session 或未归属业务记录，并通过 Canonical Runtime/协议与逐 Turn 来源检查。
嵌套 Session 视图或 Runtime integrity 单项通过不代表顶层通过。完全无身份的独立 OTLP
batch 逐批进入审计计数，不能在 Session 选择时静默遗漏；它们不会被猜测归属到当前 Turn。
审计用的精确身份/父链索引仍占用随记录数增长的内存，大归档应测量峰值并安排磁盘索引。

独立 `audit-session-context` 在计数后释放每条 Capture 的正文，不再保留整个选中 Session。
`inspect-session` 和交互投影仍需保留选中载荷，不能套用独立审计的内存测量。
可运行 `make audit-memory-test` 检查审计的载荷保留回归：release CLI 读取至少 128 MiB
的合成输入，校验 514 条 Capture、来源计数和输入 SHA 不变，峰值 RSS 不超过 96 MiB。
GitHub CI 保存 `audit-memory-report` 元数据产物；它不是大记录数压力测试或真实 Session
交付证明，身份索引的磁盘化仍需单独迭代。

平台 `/v1/jobs/{id}/turns` 的顶层 `delivery_ready` 表示检查/验收总状态；`summary` 继续
保留已精确归属的 Session 视图。历史检查结果若没有 `source_context_audit`，分页总状态
为 false，需使用新 job ID 重新检查原始 Archive；不要改写历史任务结果。

## 回滚

发布和回滚时同时更新部署环境文件中的 `CHIPTRACE_IMAGE`，使后续 Compose 重建使用
已验收的不可变镜像；仅在单次命令中设置环境变量不会更新持久部署配置。

回滚只恢复上一个不可变云端镜像和 18084 路由。WAL、OSS Checkpoint、Release 和失败证据
不删除、不回退；旧版本不理解的新事件继续保持 Raw-only。
