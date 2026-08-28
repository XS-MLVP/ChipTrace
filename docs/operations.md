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

Compose 可通过 `CHIPTRACE_STORE_SHARDS` 设置分片数。默认值为 1，适用于单盘和
既有数据目录。

## 18084 入口适配器

机房 `18084` 只负责业务请求/响应的有界旁路复制，并在业务响应结束后异步提交
到 Rust Relay。当前生产配置为：

```text
FULL_TRACE_CAPTURE_SUBMIT_ATTEMPTS=25   # 1 次初始提交 + 24 次重连
FULL_TRACE_CAPTURE_RETRY_BASE_MS=250
FULL_TRACE_CAPTURE_RETRY_MAX_MS=5000
FULL_TRACE_CAPTURE_RETRY_JITTER_PERCENT=20
FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS=30000
FULL_TRACE_CAPTURE_SUBMIT_CONCURRENCY=8
FULL_TRACE_CAPTURE_SUBMIT_MAX_INFLIGHT_BYTES=1073741824
```

重试采用指数退避、上限和抖动；失败、取消、重试及非成功 HTTP 响应均会进入
Capture，不按状态码过滤。18084 不写 Trace 磁盘，Rust Relay 返回 `durable=true`
才是持久化交接点；交接后由 Relay outbox 持续续投 Collector。若 18084 进程在
取得 durable ACK 前重启，当前 Capture 仍可能丢失，这是旁路适配器的明确边界。

## open21 复现环境

`open21` 是由独立 Docker Compose 管理的复现 fixture，不是 ChipTrace 生产
服务。其容器网络与生产数据平面隔离；复现场景通过业务入口进入唯一的 Rust
Trace 链路。open21 的容器、数据库和目录均不作为 Collector/Relay 实现。

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

chiptrace benchmark-compression \
  --records 10000 \
  --payload-kib 64 \
  --level 1 \
  --streams 16 \
  --workers-per-stream 1
```

验收样本覆盖 200、408、429、503、取消、CaptureError、SSE、重复、冲突、
截断、Session 生命周期、并发工具和 subagent。必须验证：

- 已 ACK Capture 在 kill -9 后仍可恢复；
- Relay 在 Collector 停止期间积压，重启后回落；
- accepted + duplicate + conflict + rejected attempt 守恒；
- WAL locator 覆盖连续且 SHA-256 一致；
- Session 不跨 Release Part；
- 去重与评分数量守恒；
- OSS/S3 在 COMMIT 出现前不可见为完整 Release。

## 监控

告警至少覆盖：

- 业务请求增长但 Capture 不增长；
- Relay pending/inflight 持续增长；
- Collector queue 或在途字节预算耗尽；
- attempt 或 Release 计数不守恒；
- open WAL 超过大小或时间阈值；
- `/audit` 失败、磁盘空间不足、fsync 延迟升高；
- Assembly orphan、merge divergence、模型证明缺失增加；
- buyer hard-gate 通过率或有效 Token 异常下降；
- multipart 重试、staging 残留和 COMMIT 冲突。

在线 `/audit` 只检查持久化增量计数的守恒关系，不扫描历史 WAL。完整 locator、
段哈希和 Payload 校验使用离线命令，避免审计流量阻塞采集写线程：

```bash
chiptrace audit \
  --root /srv/chiptrace/capture \
  --state-root /var/lib/chiptrace/state \
  --verify-payloads
```
