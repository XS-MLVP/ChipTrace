# 芯迹（ChipTrace）

<p align="center">
  <a href="https://github.com/XS-MLVP">
    <img src="docs/assets/xs-mlvp-avatar.png" alt="万众一芯团队" width="96">
  </a>
</p>

<p align="center">
  <a href="https://github.com/XS-MLVP"><strong>万众一芯团队</strong></a>
  ·
  <a href="https://open-verify.cc/">官方网站</a>
</p>

面向芯片行业 Agent 的 Trace 采集与训练数据治理框架。核心数据平面由单一
Rust 二进制提供可靠采集、Session DAG 组装、版本化验收、JSONL 分包和
OSS/S3 发布能力。

## 架构边界

生产 Trace 链路只有一套：`18084` 业务入口适配器完成有界旁路复制后，先写入本地
durable outbox，再由 ChipTrace Rust Relay 续投 Rust Collector；随后由同一 Rust
二进制的 Enrich、Assembly、Score 和 Release 命令完成关联、组装、验收与交付。
18084 的 outbox 只是入口故障缓冲，canonical 数据源仍是 Rust Collector 的 WAL。

`open21`（`open21-agor`、`open21-gitlab`）是独立的 Docker 复现与验收环境，
只用于生成可重复的业务场景；它不属于生产采集链路，也不承担 Trace 存储。

## 功能

- Collector：JSON/NDJSON 接收、分片 WAL、redb ledger、幂等与崩溃恢复。
- Relay：入口 outbox 与 Rust durable outbox、批量续投、背压、取消/失败/重试完整保留。
- Producer：显式生命周期/工具事件、实时 rollout sidecar、确定性 Capture ID 与 Stop hook 补采。
- Enrich：按 `request_id` 精确关联 Sub2API usage log，保留模型路由和缓存 Token 证据。
- Trajectory：API 快照与任务/工具事件组装、Session DAG 和真实执行状态。
- Quality：`buyer-v6` / `buyer-v7` 硬门槛、90 分准入、语义证据与 Token 分类。
- Delivery：OSS 原始 Segment/Checkpoint、内部 `JSONL.zst` Release、采购方
  `tar.gz + JSONL` 包和 OSS/S3 提交。

## 构建

要求 Rust 1.91+。

```bash
cargo build --release --locked
cargo test --workspace --all-targets --locked
target/release/chiptrace self-test
```

上线前可运行隔离 runtime canary。它执行五个真实工具（包含一次预期的真实文件错误），
写入完整 Registry、生命周期和评估证据，并等待 Relay durable ACK；输出只用于链路验收，
不作为采购训练语料：

```bash
target/release/chiptrace runtime-canary \
  --state-root /var/lib/chiptrace/canary/task-001 \
  --source-namespace router-v2-canary \
  --relay-url http://127.0.0.1:3011 \
  --task-session-id canary-task-001 \
  --collector-health-url http://127.0.0.1:3010/health \
  --evidence-jsonl /srv/chiptrace/capture/segments/latest.sealed.ndjson \
  --expected-missing-path /var/lib/chiptrace/canary/does-not-exist \
  --retry-max-times 25
```

## 采集

启动 Collector：

```bash
target/release/chiptrace collector \
  --root /srv/chiptrace/capture \
  --state-root /var/lib/chiptrace/state \
  --host 127.0.0.1 \
  --port 3010
```

单条入口为 `POST /capture`；高吞吐入口为 `POST /captures`，请求体使用
`application/x-ndjson`，每行一个 `api_snapshot`、`lifecycle_event`、
`tool_execution`、`evaluation` 或 `rollout_event` Capture：

```bash
curl --fail-with-body http://127.0.0.1:3010/captures \
  -H 'content-type: application/x-ndjson' \
  --data-binary @captures.jsonl
```

需要跨进程可靠投递时启动 Relay：

```bash
target/release/chiptrace relay \
  --root /var/lib/chiptrace/outbox \
  --state-root /var/lib/chiptrace/outbox-state \
  --delivery-state-root /var/lib/chiptrace/delivery \
  --collector-url http://127.0.0.1:3010 \
  --host 127.0.0.1 \
  --port 3011
```

Agent harness 创建 `task_session_id` 后，将生命周期、工具和评测事件直接提交到
本机 Relay。Relay 生成确定性 Capture ID，并在本地 durable ACK 后返回：

```bash
curl --fail-with-body http://127.0.0.1:3011/producer/events \
  -H 'content-type: application/x-ndjson' \
  --data-binary @harness-events.jsonl
```

每条 producer event 使用任务内稳定的 `stream_id + sequence`；文件补投使用
`chiptrace produce --input harness-events.jsonl --relay-url http://127.0.0.1:3011`。

也可以由 Rust Harness 管理任务边界和本地 durable spool。启动时只生成一次任务身份，
工具状态必须由 dispatcher 以真实结果结束，断网或重启后用同一 state 目录续投：

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
  --call-id call-001 --status success --result '@tool-result.json'

chiptrace harness end \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --relay-url http://127.0.0.1:3011 --status completed
```

`harness inspect` 可查看 pending、checkpoint、活动工具和应注入 API 的
`x-chiptrace-*`/`traceparent` 关联头。没有实际 Schema 或真实 terminal 结果的事件仍
会保留在 Raw，但不能进入 buyer-v7 Release；不得从 `exec`、返回文本或 response
`completed` 补造工具和任务状态。

实时 sidecar 将 Codex rollout 增量投递到同一 Relay：

```bash
target/release/chiptrace watch-codex-rollout \
  --input /var/lib/codex/sessions/rollout.jsonl \
  --state-root /var/lib/chiptrace/codex-exporter \
  --relay-url http://127.0.0.1:3011 \
  --source-namespace router-v2-18084 \
  --task-session-id "$TASK_SESSION_ID" \
  --tool-registry /etc/chiptrace/codex-tool-registry.json
```

exporter 按源 byte offset/ordinal 续读，每条事件保存原始 JSONL 与 SHA-256。Codex
turn 不会自动提升为完整任务 Session；工具 Schema 只接受与 CLI 版本一致的实际
runtime registry。Producer JSONL、Stop hook 和字段边界见[部署与运维](docs/operations.md)。

Codex 0.150 及以上优先使用原生 `codex-rollout-trace` bundle。它保留运行时
工具、Code Mode、Terminal、推理、compaction 和子代理的真实事件及 payload 引用：

固定版本的 producer 补丁见
[Codex 0.150 Runtime Tool Registry](integrations/codex/0.150.0-alpha.9/README.md)。

生产任务优先由 `codex-run` 同时管理 Harness 边界、关联头、断线重试和原生 bundle
增量导出。单个 Codex 进程使用默认的 `single` 阶段；一个任务跨多个 Codex 进程时，
复用同一 `state-root`，并依次使用 `begin`、`continue`、`finish`：

```bash
TASK_PHASE=begin
TRACE_PHASE=01
chiptrace codex-run --codex-bin /usr/local/bin/codex \
  --working-directory /workspace/project \
  --state-root /var/lib/chiptrace/tasks/task-001 \
  --trace-root "/var/lib/chiptrace/tasks/task-001/trace-${TRACE_PHASE}" \
  --source-namespace router-v2-18084 --relay-url http://127.0.0.1:3011 \
  --model-base-url http://172.28.11.121:18084/ --task-phase "$TASK_PHASE" \
  --task-session-id task-001 -- exec --json "执行第一阶段"
```

后续以新的 `TRACE_PHASE` 依次执行 `continue` 和 `finish`。每个阶段的 `trace-root`
必须独占且为空；`begin` 只创建一次任务开始事件，只有 `finish` 产生正常任务终态。
身份不一致、未知 bundle 事件、未映射工具、open tail 或未清空的 durable spool 都会
使本次运行标记为不完整。完整命令与运维约束见
[部署与运维](docs/operations.md#codex-run-任务监督器)。

```bash
target/release/chiptrace export-codex-trace-bundle \
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

导出器校验 `manifest.json`、连续 `seq`、bundle 身份和 payload 安全路径，
并将 event/payload 原始字节镜像到 `state_root/raw-bundles`。只有 Relay durable
ACK 完成后才推进 checkpoint；活动 bundle 可保留 open tail，正式封存验证使用
`--require-complete`。

API snapshot 与 runtime Capture 缺少一侧 `task_session_id` 时，Assembly 仅按同一
`sourceNamespace` 内的 upstream/client/response/gateway request ID 精确关联；歧义
立即失败，不使用时间、模型或 thread 猜测。缺少真实 Tool Registry 不丢弃工具
调用和结果，但会标记 `unmapped_tool`，不能进入 buyer-v7 Release。

生产流程先封存并归档原始证据，再从已提交的 OSS Checkpoint 恢复后组装：

```bash
target/release/chiptrace archive-raw \
  --input /srv/chiptrace/capture \
  --archive-id chiptrace-20260828-1800 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace \
  --retry-max-times 25

target/release/chiptrace verify-raw-archive \
  --archive-id chiptrace-20260828-1800 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace \
  --verify-records

target/release/chiptrace restore-raw-archive \
  --archive-id chiptrace-20260828-1800 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace \
  --output /srv/chiptrace/restored/capture
```

原始层采用不可变 Segment、内容寻址和最后提交 Checkpoint，不使用无限增长的
单一对象。对象协议、开源方案对照和故障恢复见
[OSS 原始层与提交协议](docs/object-storage.md)。
本地 `redb` 仅保存幂等与恢复状态，正式原始数据和交付索引以 OSS 为准。

## 交付

```bash
target/release/chiptrace enrich \
  --input /srv/chiptrace/restored/capture \
  --usage-log /srv/sub2api/usage-logs.jsonl \
  --output /srv/chiptrace/enriched

target/release/chiptrace verify-enrichment \
  --enrichment /srv/chiptrace/enriched

target/release/chiptrace assemble \
  --input /srv/chiptrace/enriched \
  --output /srv/chiptrace/assembly

target/release/chiptrace release \
  --input /srv/chiptrace/assembly \
  --output /srv/chiptrace/release-v1 \
  --release-id chiptrace-20260827-v1 \
  --profile buyer-v7 \
  --minimum-score 90 \
  --target-part-gib 10 \
  --workers 16

target/release/chiptrace verify-release \
  --release /srv/chiptrace/release-v1 \
  --require-pass

target/release/chiptrace package-buyer \
  --release /srv/chiptrace/release-v1 \
  --output /srv/chiptrace/buyer-v1 \
  --gzip-level 1 \
  --workers 16

target/release/chiptrace verify-buyer-package \
  --package /srv/chiptrace/buyer-v1

target/release/chiptrace publish \
  --buyer-package /srv/chiptrace/buyer-v1 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace

target/release/chiptrace verify-published \
  --artifact-kind buyer-package \
  --artifact-id chiptrace-20260827-v1 \
  --backend oss \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --bucket example-bucket \
  --prefix datasets/chiptrace
```

OSS 凭据由 OpenDAL 从 `ALIBABA_CLOUD_ACCESS_KEY_ID`、
`ALIBABA_CLOUD_ACCESS_KEY_SECRET` 和可选的
`ALIBABA_CLOUD_SECURITY_TOKEN` 读取；S3 兼容后端使用其标准凭据环境变量。

```text
release-v1/
├── data/sessions-part-*.jsonl.zst
├── reports/assessments-part-*.jsonl.zst
├── manifest.json
└── SHA256SUMS

buyer-v1/
├── packages/sessions-part-*.tar.gz
├── manifest.json
└── SHA256SUMS
```

每个采购归档只包含 `sessions.jsonl`、`PACKAGE.json` 和 `SHA256SUMS`；打包命令
默认还要求 Release 带完整 OSS Raw lineage。旧数据迁移可显式使用
`--allow-legacy-lineage`，该模式会在 Manifest/PACKAGE.json 标记为
`legacy_unbound`，且不作为对外交付声明。正式包标记为 `lineage_status=complete`。
`publish --release` 用于内部 Release，`publish --buyer-package` 是正式采购交付入口；
两者都以最后写入的不可变 `COMMIT.json` 作为唯一可消费边界。

## 文档

- [架构与性能](docs/architecture.md)
- [数据与评分契约](docs/data-contract.md)
- [JSONL 与对象存储交付](docs/delivery.md)
- [OSS 原始层与提交协议](docs/object-storage.md)
- [OSS 方案选型](docs/oss-research.md)
- [交付验收矩阵](docs/acceptance-matrix.md)
- [部署与运维](docs/operations.md)
- [OpenAPI](schemas/openapi.yaml)

## 许可证

本项目使用 [Apache License 2.0](LICENSE)。
