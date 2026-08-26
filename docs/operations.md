# 部署与运维

## 存储布局

数据链路使用三个独立持久化目录：

```text
/srv/trace-data/capture/             # sealed 与 open NDJSON 段
/var/lib/chiptrace/state/            # live SQLite ledger
/var/lib/trace-relay/outbox/         # Relay 待投递文件
```

Capture 数据目录可以位于 NFS 或数据卷。Collector 使用 Capture 和 State
目录，Relay 使用 outbox 目录。State 和 outbox 位于本地持久化 ext4/XFS。
三个目录均使用服务专属账号和 `0700` 权限。

## Docker Compose

创建目录并启动服务：

```bash
export CHIPTRACE_CAPTURE_DATA_ROOT=/srv/trace-data/capture
export CHIPTRACE_CAPTURE_STATE_ROOT=/var/lib/chiptrace/state
export CHIPTRACE_UID="$(id -u)"
export CHIPTRACE_GID="$(id -g)"

install -d -m 0700 \
  "$CHIPTRACE_CAPTURE_DATA_ROOT" \
  "$CHIPTRACE_CAPTURE_STATE_ROOT"

docker compose -f deploy/docker-compose.yml up -d --build
curl --fail http://127.0.0.1:3010/health
```

默认只监听宿主机 `127.0.0.1:3010`。通过 `CHIPTRACE_COLLECTOR_BIND` 和
`CHIPTRACE_COLLECTOR_PORT` 调整绑定地址与端口。

停止服务：

```bash
docker compose -f deploy/docker-compose.yml down
```

`down` 不删除宿主机数据目录。

## systemd 用户服务

仓库放置于 `$HOME/chiptrace` 并完成虚拟环境安装后，启用用户服务：

```bash
install -d "$HOME/.config/systemd/user"
install -d -m 0700 \
  "$HOME/.local/share/chiptrace/capture" \
  "$HOME/.local/state/chiptrace"

cp deploy/chiptrace.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now chiptrace.service
systemctl --user status chiptrace.service
```

服务日志通过以下命令查看：

```bash
journalctl --user -u chiptrace.service -f
```

服务单元提供 `trace-pipeline.service` 兼容别名；已有调用方可平滑迁移到
`chiptrace.service`。

## Relay 配置

Relay 初始化一个长期存活的 `DurableCaptureOutbox`：

```javascript
const { DurableCaptureOutbox } = require('./integration/durable_capture_outbox');

const outbox = new DurableCaptureOutbox({
  directory: '/var/lib/trace-relay/outbox',
  url: 'http://127.0.0.1:3010',
  concurrency: 8,
  maxBytes: 64 * 1024 * 1024 * 1024,
});
```

每条真实请求生成一个稳定 `captureId`。请求、响应、错误、取消和重试
状态全部写入 envelope，不按 HTTP 状态过滤。Relay 退出前调用
`close()`；尚未送达的文件保留在 outbox，下次启动自动恢复。

## 上线校验

新部署使用独立 data root 和 state root 执行校验，不复用现有采集目录。校验样本覆盖：

- HTTP 200 JSON 响应
- SSE 响应
- HTTP 408、429 和 503
- 只有 `captureError`、没有 Terminal 事件的上游错误
- 同 ID 同正文重试
- 同 ID 不同正文字节冲突
- 接近配置上限的正文
- Collector 超时后的同字节重试
- Session start/end、cancel、retry、compaction 和 subagent 生命周期事件

验收结果必须满足：

- 失败和取消记录存在于原始段。
- 同字节重试只产生一条物理记录。
- 不同字节复用 ID 返回 HTTP 409。
- 字节预算和队列拒绝状态进入 attempt ledger。
- `/audit` 返回 `ok: true`。
- sealed SQLite export 的全部 validation rows 通过。
- 多文件 release 的 `session_split_count` 为 0。
- 完整 Session 与 open-tail Session 获得不同的完整性结果。

## 运行检查

健康检查：

```bash
curl --fail http://127.0.0.1:3010/health | python3 -m json.tool
curl --fail http://127.0.0.1:3010/audit | python3 -m json.tool
```

离线导出前封存当前 open 段，服务可以继续运行：

```bash
curl --fail -X POST http://127.0.0.1:3010/flush | python3 -m json.tool
```

`/flush` 按写入顺序等待队列完成，封存当前段后立即创建新的 open 段。
它是受信任的本地运维接口；对外绑定端口时必须由网络策略限制访问。

定时告警覆盖以下状态：

- `health.ok != true` 或 writer fatal error
- Capture ID conflict 非零
- body budget 或 queue rejection 非零
- attempt accounting 不守恒
- Relay 存在符合采集条件的业务流量，但 accepted 记录不增长
- open segment 超过配置的大小或时间阈值
- sealed checksum 或 payload locator 校验失败
- 本地 state 文件系统空间低于阈值
- NFS 延迟或剩余空间超过阈值
- outbox 积压持续增长
- export 或 release validation 失败

sealed segment 的 payload audit 在业务低峰期执行。导出只读取 sealed segment。
在线服务继续写入时先调用 `/flush`；停机导出时先执行优雅停止，再运行导出命令。

## 备份与恢复

备份对象包括：

- Capture data root 中的全部 open 和 sealed 段
- State root 中的 ledger 及其 SQLite 辅助文件
- Relay outbox 的 pending、failed 和 conflicts 目录
- 已发布目录中的 Manifest、Catalog、Part 和 SHA256SUMS

每季度执行一次 ledger 恢复验证。恢复后先运行只读 `audit`，通过后再启动写入服务。

## 升级与回滚

升级前记录镜像版本、命令行参数、数据目录、状态目录和 Relay Collector URL。停止 Collector 会完成当前批次提交并封存 open 段。

升级过程只替换 Collector 进程或容器，不修改已有段和 ledger。新版本启动后依次检查 `/health`、`/audit`、重复提交幂等性和新段轮转。

回滚时恢复上一版本镜像或可执行文件，并继续使用同一数据契约兼容的目录。涉及持久化 schema 变更的版本必须提供迁移和回滚测试；不直接改写历史 sealed 段。
