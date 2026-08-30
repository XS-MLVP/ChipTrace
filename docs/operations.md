# 部署与运维

## 目录

Collector：

```text
/srv/chiptrace/capture/segments/       # open/sealed NDJSON WAL
/var/lib/chiptrace/state/              # capture-ledger.redb
```

`--store-shards N` 大于 1 时，两个根目录下均创建 `shard-00000` 等固定子目录，
`state/sharding.json` 保存拓扑。分片数不能直接变更；扩容时建立新 Collector
实例并切换流量。需要跨设备并行时，将各 shard 子目录分别挂载到独立磁盘。

Relay：

```text
/var/lib/chiptrace/outbox/segments/    # 本地 outbox WAL
/var/lib/chiptrace/outbox-state/       # 本地 capture ledger
/var/lib/chiptrace/delivery/           # delivery-ledger.redb
```

18084 入口适配器的独立缓冲目录（挂载到 relay-shell 容器的 `/capture-outbox`）：

```text
/local/zhangyuxin/router_v2-data/relay-shell-outbox/pending/     # 已 fsync、待投递
/local/zhangyuxin/router_v2-data/relay-shell-outbox/processing/  # 已 claim，崩溃后恢复
/local/zhangyuxin/router_v2-data/relay-shell-outbox/failed/      # 冲突/永久错误，保留审计
```

该目录必须使用独立的配额和服务账号权限；入口 outbox 有字节、文件数和在途字节
上限，达到上限时只丢弃旁路 Capture，不返回业务错误。

Relay 的 `--max-delivery-inflight-mib` 是跨全部投递 Worker 的 Payload 内存上限，
必须不小于单条 Capture 上限。默认 4096 MiB；内存较小的机器应同时下调
`--max-envelope-mib` 与该值。

State、Capture 与 outbox 使用本地持久化 ext4/XFS；生产数据目录使用服务专属账号和
`0700` 权限。对象存储凭据通过环境或运行时密钥服务注入。

## Docker

```bash
export CHIPTRACE_CAPTURE_DATA_ROOT=/srv/chiptrace/capture
export CHIPTRACE_CAPTURE_STATE_ROOT=/var/lib/chiptrace/state
export CHIPTRACE_RELAY_DATA_ROOT=/var/lib/chiptrace/relay/outbox
export CHIPTRACE_RELAY_STATE_ROOT=/var/lib/chiptrace/relay/outbox-state
export CHIPTRACE_RELAY_DELIVERY_ROOT=/var/lib/chiptrace/relay/delivery
export CHIPTRACE_UID="$(id -u)"
export CHIPTRACE_GID="$(id -g)"

install -d -m 0700 \
  "$CHIPTRACE_CAPTURE_DATA_ROOT" \
  "$CHIPTRACE_CAPTURE_STATE_ROOT" \
  "$CHIPTRACE_RELAY_DATA_ROOT" \
  "$CHIPTRACE_RELAY_STATE_ROOT" \
  "$CHIPTRACE_RELAY_DELIVERY_ROOT"

docker compose -f deploy/docker-compose.yml up -d --build
curl --fail http://127.0.0.1:3010/health
curl --fail http://127.0.0.1:3011/health
```

隔离的端到端验收不需要业务数据目录：

```bash
docker build -t chiptrace:self-test .
docker run --rm chiptrace:self-test self-test
```

自测生成累计 API snapshot、任务 start/end、真实工具成功/失败和 evaluator
事件，通过 Relay 的真实 HTTP NDJSON 批量入口进入 outbox，再经 Collector WAL、
Assembly、buyer-v7 评分、Release 与本地对象提交完成闭环；输出必须为
`ok=true`、100 分且 hard gate 通过。自测还会生成最终 `tar.gz + JSONL` 采购包，
逐行复验后破坏副本并确认 SHA-256 校验能够拒绝篡改。

Compose 可通过 `CHIPTRACE_STORE_SHARDS` 设置分片数。默认值为 1，适用于单盘和
既有数据目录。

## 18084 入口适配器

机房 `18084` 只负责业务请求/响应的有界旁路复制。业务响应结束后，Capture 先以
临时文件写入入口 outbox，执行文件 `fsync` 后以 create-if-absent hard-link 原子发布到
`pending/`，再异步
提交到 Rust Relay。当前生产配置为：

```text
FULL_TRACE_CAPTURE_SUBMIT_ATTEMPTS=25   # 1 次初始提交 + 24 次重连
FULL_TRACE_CAPTURE_RETRY_BASE_MS=250
FULL_TRACE_CAPTURE_RETRY_MAX_MS=5000
FULL_TRACE_CAPTURE_RETRY_JITTER_PERCENT=20
FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS=30000
FULL_TRACE_CAPTURE_SHUTDOWN_GRACE_MS=20000
FULL_TRACE_CAPTURE_SUBMIT_CONCURRENCY=8
FULL_TRACE_CAPTURE_SUBMIT_MAX_INFLIGHT_BYTES=1073741824
FULL_TRACE_CAPTURE_OUTBOX_DIR=/capture-outbox
FULL_TRACE_CAPTURE_OUTBOX_MAX_BYTES=10737418240
FULL_TRACE_CAPTURE_OUTBOX_MAX_FILES=100000
FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_BYTES=5368709120
FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_FILES=10000
FULL_TRACE_CAPTURE_OUTBOX_SANITIZE=true
```

重试采用指数退避、上限和抖动，默认 25 次尝试；失败、取消、重试及非成功 HTTP
响应均会进入 Capture，不按状态码过滤。入口 outbox 的本地 `durable` 只表示文件已
落盘；Rust Relay 返回 `durable=true` 后才计入远端交接，随后由 Rust Relay outbox
续投 Collector。进程在远端 ACK 前重启时，`processing/` 文件会恢复到 `pending/`，
同一 `captureId` 重放由 Rust ledger 幂等处理；永久冲突保留在 `failed/`，不静默删除。
磁盘写入、正文脱敏和重试均发生在业务响应完成之后，旁路故障不会返回 5xx。
API snapshot 显式保存 `recordType`、`captureStage`、响应 `x-request-id`、
`x-client-request-id` 和允许列表中的响应关联头；`traceContext` 只复制请求中真实
出现的 `x-chiptrace-*` 字段，不从 thread、模型或 response `completed` 推断任务边界。
认证头、Cookie 和 API Key 不进入 Capture，正文脱敏只替换凭据字段，不补造工具、状态
或 Schema。封存后可用
`chiptrace enrich` 与 Sub2API usage log 精确关联，命令和证据规则见
[数据与评分契约](data-contract.md#sub2api-精确关联)。
入口为缺少 `x-client-request-id` 的请求生成一次稳定值，并在同一上游请求的所有
尝试中复用。当前 Sub2API 会重新生成该值并通过响应头返回，Capture 的显式
`requestId` 必须优先采用响应值；只有账单行 `client:<response id>` 精确命中后才
形成 provider 和缓存 Token 证明。
Sub2API 导出必须按该契约联表生成 `effective_platform`；其原生 Usage API 没有稳定的
provider 字段，不能根据模型名补齐。

18084 能产生 `api_snapshot`，但无法观察 Agent 内部工具或任务结束。Agent harness
和工具执行器必须复用同一可靠 submitter，向 Relay 追加：

- 任务开始时创建稳定 `task_session_id`；
- 每个工具真实 start/finish 状态、参数、schema 和结果；
- task end/cancel/retry、compaction、subagent spawn/join；
- 测试、构建和最终验收 evidence。

同一任务的各类事件使用不同 `captureId`，但共享 `sourceNamespace` 和
`task_session_id`。API snapshot 仍保留原始 `thread_id/turn_id`。不能在 18084
根据响应 `completed` 推断 task end，也不能从工具输出文本推断 success。

Harness 和 dispatcher 将版本化 producer event 直接批量提交到本机 Relay；该入口
负责生成 Capture ID、原子写入 outbox 并返回 durable ACK：

```bash
curl --fail-with-body http://127.0.0.1:3011/producer/events \
  -H 'content-type: application/x-ndjson' \
  --data-binary @/var/lib/chiptrace/events/task-001.jsonl
```

每条记录必须包含 `producerEvent` 的 `schema_version`、`event_id`、`producer`、
`producer_version`、`stream_id`、`sequence`，以及 RFC3339 证据时间和
`traceContext.task_session_id`；Harness/dispatcher 的 `identity_scheme` 固定为
`chiptrace.deterministic-capture.v1`。Capture ID
由 namespace、任务 ID、producer、stream、sequence 和 event ID 共同确定；同一事件
重试幂等，内容变化会在 Relay 产生冲突。Assembly 对每条 stream 检查重复 sequence
和内部缺口，并要求 producer 工具调用各有一个 started 与 terminal 事件。工具事件
拒绝 `status=unknown`，started 事件不能携带伪终态。任务开始记录可携带实际
`toolRegistry` 与内容 SHA-256。

`POST /producer/event` 接收单条 JSON，`POST /producer/events` 接收 NDJSON 批次。
`chiptrace produce` 用于已落盘 JSONL 的补投或恢复，不是在线 Harness 的额外队列层。

生产者也可直接使用内置 Harness，避免在业务代码中重复实现身份、序列和恢复逻辑：

```bash
chiptrace harness start \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --source-namespace router-v2-18084 \
  --relay-url http://127.0.0.1:3011 \
  --task-session-id task-001 \
  --tool-registry examples/tool-registry.json

chiptrace harness tool-start \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --relay-url http://127.0.0.1:3011 \
  --call-id call-001 --name exec_command \
  --arguments '{"cmd":"cargo test"}'

chiptrace harness tool-end \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --relay-url http://127.0.0.1:3011 \
  --call-id call-001 --status error --error '@tool-error.json'

chiptrace harness end \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --relay-url http://127.0.0.1:3011 --status failed

chiptrace harness inspect \
  --state-root /var/lib/chiptrace/tasks/task-001
```

Harness 状态契约见 `schemas/harness-session-v1.schema.json`。每个任务目录只能由一个
生产者进程持有；进程异常退出后下一次 `harness flush` 会重放未确认的完整行。只有
Relay 的完整 durable ACK 会推进 checkpoint；业务层可以在投递失败时继续执行，但该
任务必须在待投递队列清空前标记为未交付。工具没有完整 Registry Schema 时仍保存
原始事件，`schema_provenance.source_complete=false`，严格 buyer-v7 评分会拒绝。

## Codex rollout 生产者

### `codex-run` 任务监督器

生产接入优先使用 `codex-run`。它在 Codex 进程启动前落盘 Harness task start，将
`task_session_id`、root/parent、goal、agent、branch、session/thread、
`previous_response_id` 和 W3C `traceparent` 作为 provider 环境请求头注入，同时强制
启用 Runtime Tool Registry producer、至少 20 次采集投递尝试和至少 20 次 provider
请求/流重试。运行期间每 250 ms 增量导出原生 bundle，只有 Relay durable ACK 后推进
checkpoint；退出时完成严格 bundle 扫描和 spool flush。

单进程任务使用默认的 `--task-phase single`：

```bash
chiptrace codex-run \
  --codex-bin /usr/local/bin/codex \
  --working-directory /workspace/project \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --source-namespace router-v2-18084 \
  --relay-url http://127.0.0.1:3011 \
  --model-base-url http://172.28.11.121:18084/ \
  --task-session-id task-001 \
  -- exec --json "执行并验证任务"
```

一个采购任务需要多个真实 User -> Assistant 交互时，使用同一 `state-root` 和 sink，
为每个进程分配新的空 `trace-root`：

```bash
chiptrace codex-run --codex-bin /usr/local/bin/codex \
  --working-directory /workspace/project \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --trace-root /var/lib/chiptrace/tasks/task-001/trace-01 \
  --source-namespace router-v2-18084 --relay-url http://127.0.0.1:3011 \
  --model-base-url http://172.28.11.121:18084/ --task-phase begin \
  --task-session-id task-001 -- exec --json "执行第一阶段"

chiptrace codex-run --codex-bin /usr/local/bin/codex \
  --working-directory /workspace/project \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --trace-root /var/lib/chiptrace/tasks/task-001/trace-02 \
  --source-namespace router-v2-18084 --relay-url http://127.0.0.1:3011 \
  --model-base-url http://172.28.11.121:18084/ --task-phase continue \
  -- exec --json "依据上一阶段继续修正"

chiptrace codex-run --codex-bin /usr/local/bin/codex \
  --working-directory /workspace/project \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --trace-root /var/lib/chiptrace/tasks/task-001/trace-03 \
  --source-namespace router-v2-18084 --relay-url http://127.0.0.1:3011 \
  --model-base-url http://172.28.11.121:18084/ --task-phase finish \
  -- exec --json "执行最终验收"
```

`begin` 创建唯一 task start，`continue` 只追加 rollout，`finish` 根据最后一个 Codex
进程与采集结果写入 completed/failed/incomplete 终态。SIGINT/SIGTERM 在任一阶段都会
产生 cancelled/terminated 任务终态。恢复阶段会校验持久身份、namespace 和任务仍为
open；不同 sink、已关闭任务、复用非空 trace 目录或通过 Codex `-c` 覆盖关联头、重试
和 Runtime Tool Registry 设置都会失败。每阶段摘要必须满足 `ok=true`、
`capture_complete=true`、`pending_records=0`；`finish` 还必须满足
`task_terminal_emitted=true` 和 `task_status=closed`。

入口部署必须包含业务进程的持久 `/capture-outbox` 挂载。只升级 `codex-run` 而入口仍
运行旧的 direct-to-Relay 代码，会出现原生 `inference_completed` 多于 API Capture；
Assembly 的 `inference_api_conservation` Gate 会拒绝该 Session，不能用 rollout 或
Sub2API usage 补造缺失快照。

### 原生 trace bundle（优先）

Codex 0.150+ 可通过 `CODEX_ROLLOUT_TRACE_ROOT` 写出原生 bundle：
`manifest.json`、`trace.jsonl` 和 `payloads/`。使用以下命令导出：

```bash
chiptrace export-codex-trace-bundle \
  --input /var/lib/codex/trace-bundles/trace-<id> \
  --state-root /var/lib/chiptrace/codex-bundle-exporter \
  --relay-url http://127.0.0.1:3011 \
  --source-namespace router-v2-18084 \
  --task-session-id "$TASK_SESSION_ID" \
  --root-session-id "$ROOT_SESSION_ID" \
  --goal-id "$GOAL_ID" \
  --tool-registry /etc/chiptrace/codex-tool-registry.json \
  --retry-max-times 25
```

导出器验证 manifest schema、bundle `rollout_id`、事件 `schema_version`、从 1
开始的连续 `seq`、UTF-8 JSON、payload ref 的相对路径和文件存在性。每个 event
和 payload 以内容 SHA-256 镜像到 `state_root/raw-bundles/<trace_id>/`，Capture
中保存已校验的来源、hash 和镜像引用。配置指纹绑定 namespace、任务身份、sink
和镜像目录；更换配置不会复用旧 checkpoint。

原生 bundle 的 `ToolCallStarted/ToolCallEnded` 使用 runtime 明确的参数、结果、状态
和 requester。真实 call/result 即使缺少 Registry 也保存为 `toolExecution`，此时
`schema=null`、provenance 为 `missing_runtime_registry`，同时标记 `unmapped_tool`；
不得从 `source_js` 或工具名补造 Schema。只有实际 dispatcher 导出的 Registry 与
runtime 工具精确匹配时才成为 buyer-v7 合格定义。`rollout_ended` 只表示 bundle
运行结束，任务终态仍需 harness 的 `task_end/session_end/cancel` 事件。
`--require-complete` 只检查原生 bundle 的 rollout 终止和无 open tail，不会把它
提升为任务终态。

### 兼容 rollout JSONL

实时生产由 Agent supervisor 启动常驻 sidecar。命令只
读取完整换行记录，Relay durable ACK 后提交本地 byte offset/ordinal checkpoint：

```bash
chiptrace watch-codex-rollout \
  --input /var/lib/codex/sessions/2026/08/29/rollout.jsonl \
  --state-root /var/lib/chiptrace/codex-exporter \
  --relay-url http://127.0.0.1:3011 \
  --source-namespace router-v2-18084 \
  --task-session-id "$TASK_SESSION_ID" \
  --root-session-id "$ROOT_SESSION_ID" \
  --goal-id "$GOAL_ID" \
  --tool-registry /etc/chiptrace/codex-tool-registry.json \
  --poll-ms 250 \
  --retry-max-times 25
```

`TASK_SESSION_ID`、root/parent 和 goal 必须由 harness 生成；不能用 Codex thread 或
turn 猜测。API snapshot、harness lifecycle、dispatcher tool 和 rollout exporter
应收到同一组 ID；某一侧缺失 `task_session_id` 时，Assembly 仅按同一
`sourceNamespace` 内的 upstream/client/response/gateway request ID 精确关联，歧义
直接失败。Tool Registry 遵循
`schemas/tool-registry-v1.schema.json`，由实际 dispatcher 导出并绑定精确 CLI
版本；`code_mode_tool_names` 或静态名字列表不能替代 Schema。

Stop hook 是结束时补采和对账入口，不是实时完整性的唯一保证。`codex-hook` 从
stdin 读取 hook JSON，只接受配置 session 根目录内、首行 session 身份一致的
rollout。已有 hook 配置应追加命令而不是覆盖其他 Stop hook，例如：

```json
{
  "hooks": {
    "Stop": [{
      "hooks": [{
        "type": "command",
        "command": "/usr/local/bin/chiptrace codex-hook --session-root /var/lib/codex/sessions --state-root /var/lib/chiptrace/codex-exporter --relay-url http://127.0.0.1:3011 --source-namespace router-v2-18084 --retry-max-times 25 >>/var/log/chiptrace/codex-hook.log 2>&1 || true"
      }]
    }]
  }
}
```

hook fail-open 不会推进 checkpoint，下一次 sidecar/hook 会用相同 Capture ID 重试。
生产必须同时运行实时 sidecar，确保进程崩溃前的完整记录已进入 Relay；`--output`
只用于隔离测试，生产使用 `--relay-url`。监控以下 exporter 指标：

- `unknown_events` 必须为 0，否则当前 Codex 版本存在未支持事件；
- `unmapped_tool_events` 必须为 0，且 Tool Registry 版本与 CLI 一致；
- `incomplete_tail_bytes` 在活动文件中允许短暂非零，封存后必须为 0；
- `committed_offset` 必须持续追上源文件长度；源文件在 checkpoint 前改写或截断会失败。

Codex 原生 structured call 会保存为 Assistant tool call；输出未报告状态时保持
`unknown`。只有模型调用和 runtime item 的 `call_id` 及 Registry 工具名都一致，
`CommandExecution/FileChange/ImageView/CollabAgentToolCall` 的真实状态才投影回该调用。
Code Mode 内层执行无法关联外层调用时仍被拒绝。`WebSearch` 缺结果正文时只保存调用
与完成观察，不计为有效返回。Codex `agent_name/agent_path` 记录代理路径，harness
`agent_id` 记录稳定实例身份，两者不互相覆盖。任务 start/end/cancel 仍由 harness
另行提交。

## open21 复现环境

`open21` 是由独立 Docker Compose 管理的复现 fixture，不是 ChipTrace 生产
服务。其容器网络与生产数据平面隔离；复现场景通过业务入口进入唯一的 Rust
Trace 链路。open21 的容器、数据库和目录均不作为 Collector/Relay 实现。

## OSS 原始归档

原始归档器只读取 Collector 已封存的 `.sealed.ndjson`。先执行 Collector 的
`POST /flush`，再使用 `chiptrace archive-raw` 写入 OSS Raw Zone；归档完成后用
`verify-raw-archive --verify-records` 校验 Checkpoint、对象 SHA-256 和逐行记录。
归档对象采用内容寻址，重复执行同一 `archive_id` 是幂等操作。恢复到本地后再
执行 Assembly、Score 和 Release，完整命令见 [OSS 原始层与提交协议](object-storage.md)。
`partial` Checkpoint 默认不能恢复到标准处理目录；取证时需显式使用
`restore-raw-archive --allow-partial`。

`archive-raw` 是显式的离线封存步骤，不会在 Collector 进程内后台扫描或上传。生产
环境应由受监管的 systemd timer、Kubernetes CronJob 或外部编排器在 `/flush` 成功后
按时间窗口生成新的 `archive_id`；同一 ID 一旦提交不可追加。编排器必须保存命令
输出和 Checkpoint，失败时重试同一 ID，不能通过 OSS LIST 猜测是否完成。

生产 Bucket 需要配置以下治理规则：

- 未完成 Multipart Upload 超过保留窗口后自动 Abort；
- Raw 对象启用版本保护或 WORM 策略，禁止覆盖已提交对象；
- 仅允许发布服务账号写入 `raw/`，消费账号只读 Checkpoint 引用的对象；
- 保留 Raw Zone 和 Release Zone 的独立生命周期、容量和校验告警。

## systemd

```bash
cargo build --release --locked
install -m 0755 target/release/chiptrace "$HOME/.local/bin/chiptrace"
install -d "$HOME/.config/systemd/user"
cp deploy/chiptrace.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now chiptrace.service
systemctl --user status chiptrace.service
```

服务默认监听 loopback，采集接口不实现应用层认证。跨主机部署时放在受控内网
或服务网格中，并由网络策略限制 `/flush` 与 `/audit`。认证头在写入 WAL 前
移除，Trace 正文不做内容改写。

## 上线验收

在独立临时目录和非业务端口执行：

```bash
cargo test --workspace --all-targets --locked
chiptrace self-test

chiptrace benchmark-store \
  --records 5000 \
  --payload-kib 256 \
  --concurrency 256 \
  --store-shards 4 \
  --work-root /mnt/local-nvme/chiptrace-benchmark

chiptrace benchmark-http \
  --records 5000 \
  --payload-kib 256 \
  --batch-records 16 \
  --concurrency 16 \
  --store-shards 4

chiptrace benchmark-http \
  --records 1024 \
  --payload-kib 256 \
  --batch-records 16 \
  --concurrency 16 \
  --store-shards 4 \
  --relay \
  --producer-events

chiptrace benchmark-compression \
  --records 10000 \
  --payload-kib 64 \
  --level 1 \
  --streams 16 \
  --workers-per-stream 1
```

验收样本覆盖 200、408、429、503、取消、CaptureError、SSE、重复、冲突、
截断、累计快照、任务生命周期、工具 unknown/error/retry、并发工具和 subagent。
必须验证：

- 已 ACK Capture 在 kill -9 后仍可恢复；
- Relay 在 Collector 停止期间积压，重启后回落；
- accepted + duplicate + conflict + rejected attempt 守恒；
- WAL locator 覆盖连续且 SHA-256 一致；
- Session 不跨 Release Part；
- 去重与评分数量守恒；
- 采购包逐行可解析，全部 Session 为 buyer-v7、得分不低于 90 且硬门槛通过；
- 采购包记录数、有效 Token、归档内外 SHA-256 守恒；
- OSS/S3 在 COMMIT 出现前不可见为完整制品，且 `verify-published` 逐对象复验通过。

## 热服务升级门槛

本地自测通过后仍不直接替换 18084。升级按以下顺序进行：

1. 在新端口和新数据目录启动候选 Relay/Collector，不读取或改写生产 WAL。
2. 为入口创建独立 `0700` outbox 目录并挂载；先运行 adapter 单元/隔离测试，再让
   入口与 Agent harness 向候选链路影子提交，同一业务响应不等待 Trace ACK。
3. 连续验证入口 outbox 与 Rust Relay 的 Capture 数守恒、pending 回落、P99 业务
   延迟差异和磁盘增长，并执行一次进程退出后的 processing 恢复。
4. 从候选封存段构建 Release，要求 parse failure、merge divergence、trace/schema
   conflict 均为 0，且符合业务条件的 fixture 达到 buyer-v7 100 分。
5. 对旧 Collector 故障、Relay 重启、重复投递和断网恢复做注入测试。
6. 达标后再切换采集目标；旧链路只读保留至新链路完成一个 Release 周期。

滚动升级测试必须包含一条生产 v1 WAL 的精确重放：新 Collector 应返回
`duplicate`，修改同一 `captureId` 的任一原始字段应返回 `409 conflict`。该用例用于
防止 v1 到 v2 规范化改变幂等摘要，不能以关闭冲突检查规避。

任何 hard-gate 下降、业务延迟回归、attempt 不守恒或事件缺失都会终止切换。

## 监控

告警至少覆盖：

- 业务请求增长但 Capture 不增长；
- 入口 outbox `pending/processing` 不回落、`failedFiles/conflicts/rejected` 非零，或
  `filesystemFreeBytes/filesystemFreeFiles` 触及保留线；
- Relay pending/inflight 持续增长；
- Collector queue 或在途字节预算耗尽；
- attempt 或 Release 计数不守恒；
- open WAL 超过大小或时间阈值；
- `/audit` 失败、磁盘空间不足、fsync 延迟升高；
- Assembly orphan、merge divergence、模型证明缺失增加；
- 有 API snapshot 但没有 task end/tool execution 的 Session 比例升高；
- buyer hard-gate 通过率或有效 Token 异常下降；
- multipart 重试、staging 残留和 COMMIT 冲突；
- Raw Zone Checkpoint 缺失、Segment 序号断档、对象长度/SHA-256 不一致和未完成
  Multipart Upload 持续增长。

在线 `/audit` 只检查持久化增量计数的守恒关系，不扫描历史 WAL。完整 locator、
段哈希和 Payload 校验使用离线命令，避免审计流量阻塞采集写线程：

```bash
chiptrace audit \
  --root /srv/chiptrace/capture \
  --state-root /var/lib/chiptrace/state \
  --verify-payloads
```
