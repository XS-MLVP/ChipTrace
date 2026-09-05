# 部署与运维

## 隔离环境

仓库只维护 `deploy/docker-compose.yml` 这一套测试部署。提交前执行：

```bash
make cloud-test
make m0-test
```

其中 `cloud-test` 检查格式、Clippy、Rust/网关测试和完整云端验收自测；`m0-test` 在 Docker
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

## Stock Codex

管理员按 [Stock Codex 接入](../integrations/codex/README.md) 下发原生配置。用户主机没有
ChipTrace 程序或服务，用户仍直接运行：

```bash
codex
```

`SessionStart` 会同步检查采集入口；配置无效、认证失败或入口不可用时，在首个 Turn 前
停止。任务期间发生缺失时不阻断业务，但该 Session 不能交付。

## 云端验收

先封存 WAL 并提交 Raw Archive，再导出同一时间窗的 Sub2API usage log。随后只运行：

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

## 监控

- 业务 Responses 增长时，Wire、OTLP 和 Hook 三源是否同时增长。
- Relay `ingest_coverage.status` 必须保持 `complete`。`partial` 表示启动预热或来源尚未出现；
  `degraded` 表示 Wire 活跃时 Runtime 来源缺失或落后超过 5 分钟，应按 `missing_sources`、
  `stale_sources` 和 `source_lag_ms` 检查 Stock Codex 受管配置。
- Relay `pending`、`inflight`、最老队列时间、磁盘空间和 attempt 守恒。
- `output_truncated=true`、未知 OTLP 事件、转换错误和身份冲突。
- Session start/end、模型调用/结果/执行、内部父引用的完整率。
- Buyer v7 失败原因、合格 Session 数和四种 Token 口径。

## 回滚

回滚只恢复上一个不可变云端镜像和 18084 路由。WAL、OSS Checkpoint、Release 和失败证据
不删除、不回退；旧版本不理解的新事件继续保持 Raw-only。
