# 部署与运维

## 目录

```text
/srv/chiptrace/capture/                 Collector sealed/open WAL
/var/lib/chiptrace/collector-state/     Collector ledger
/var/lib/chiptrace/relay/               Relay outbox WAL 与 ledger
~/.local/state/chiptrace/outbox/        Codex Hook 本地 pending 事件
~/.local/state/chiptrace/agent/         rollout checkpoint
~/.codex/sessions/                      Stock Codex rollout
```

所有状态目录使用持久化 ext4/XFS、服务专属权限和独立磁盘配额。Token 放在权限为 `0600`
的环境文件或密钥服务中，不写入仓库和 Capture。

## 隔离验收

仓库只有一个 Docker Compose 测试环境。它不访问生产网关或生产数据：

```bash
make m0-test
```

验收必须包含 `delivery_ready=true`、单根 OTLP 树、内部父引用 100% 解析和五个 fail-closed
负例。`cargo test`、Clippy 与 `self-test` 同时通过后，才进入真实 canary。

## Collector 与 Relay

构建不可变镜像后配置部署变量：

```bash
export CHIPTRACE_IMAGE=registry.example.com/chiptrace@sha256:REPLACE_ME
export CHIPTRACE_NETWORK=chiptrace-data-plane
export CHIPTRACE_CAPTURE_ROOT=/srv/chiptrace/capture
export CHIPTRACE_COLLECTOR_STATE_ROOT=/var/lib/chiptrace/collector-state
export CHIPTRACE_RELAY_ROOT=/var/lib/chiptrace/relay
export CHIPTRACE_PRODUCER_TOKEN="$(openssl rand -hex 32)"
docker network inspect "$CHIPTRACE_NETWORK" >/dev/null
docker compose -f deploy/collector-relay.yml up -d
```

默认只发布到 loopback：Collector `3010`，Relay `3011`。需要跨主机接入时，由现有网关
将带认证的 `/producer/events` 暴露到私网或 TLS 入口，不直接公开 Collector。

```bash
chiptrace probe --url http://127.0.0.1:3010/health
chiptrace probe --url http://127.0.0.1:3011/health
```

Relay 健康状态同时检查 ledger 守恒、冲突、永久失败和积压比例。`degraded` 不能作为发布
canary 的健康状态。

## 18084 Wire 入口

18084 在业务响应结束后旁路复制 OpenAI-compatible 请求和响应，并先写入口本地 outbox。
业务请求不等待远端 Trace ACK。入口必须满足：

- 保存原始请求/响应字节、长度、SHA-256、HTTP 状态、SSE 错误和客户端关闭。
- 成功、失败、取消、重试和非 2xx 响应全部采集，不按状态过滤。
- 关闭会改变正文长度的脱敏；认证头、Cookie 和 API Key 在规范化时移除。
- Capture schema 或正文校验失败返回 400 并隔离，不投入无限 5xx 重试。
- 同一 `captureId` 重试幂等，Relay durable ACK 后才删除入口 pending 文件。
- `/producer/events` 使用 Bearer Token；Wire Capture 与 Producer 路由权限分离。

网关侧的最小可靠投递实现和接入约束见
[OpenAI 网关接入](../integrations/openai-gateway/README.md)。业务代理本体不属于 ChipTrace。

入口只能证明模型 Wire，不能单独证明本地工具已经执行。完整 Trace 必须同时收到 Stock
Codex rollout 与 Hook 生命周期。

## Stock Codex 配置

构建并安装二进制：

```bash
cargo build --release --locked
install -Dm755 target/release/chiptrace /usr/local/bin/chiptrace
```

从当前 Stock Codex 导出模型目录，并在模型交互前启用 direct JSON function 工具：

```bash
codex debug models --bundled > codex-models.json
chiptrace prepare-codex-catalog \
  --input codex-models.json \
  --output /etc/chiptrace/codex-models-direct.json \
  --model gpt-5.6-sol
install -Dm644 integrations/codex/managed_config.toml.example \
  /etc/codex/managed_config.toml
install -Dm644 integrations/codex/requirements.toml.example \
  /etc/codex/requirements.toml
```

将 [受管配置模板](../integrations/codex/managed_config.toml.example) 安装到
`/etc/codex/managed_config.toml`，将
[required Hook 模板](../integrations/codex/requirements.toml.example) 安装到
`/etc/codex/requirements.toml`。Hook 订阅 `SessionStart`、`SessionEnd`、`Stop`、
`Interrupt`、`SubagentStart` 和 `SubagentStop`，不使用自定义启动命令。用户级未确认
hash 的 Hook 会被 Stock Codex 标记为 `Untrusted` 并跳过，因此不作为生产部署方式。

SessionStart 同步验证当前模型的 direct 目录、`codex-agent` 独占锁、本地积压和磁盘预算，
再原子写入 outbox。结构配置错误返回 Codex 原生 `continue:false`，首个 Turn 不执行。
远端暂时不可用不属于启动失败；只要本地闭环健康，后续由 outbox 续投。

## codex-agent 用户服务

```bash
install -Dm644 deploy/chiptrace-codex-agent.service \
  "$HOME/.config/systemd/user/chiptrace-codex-agent.service"
install -Dm600 deploy/codex-agent.env.example \
  "$HOME/.config/chiptrace/codex-agent.env"
```

环境文件必须设置：

```text
CHIPTRACE_RELAY_URL=https://trace.example.com
CHIPTRACE_SOURCE_NAMESPACE=production-codex
CHIPTRACE_PRODUCER_TOKEN=<至少 32 字节的随机值>
```

启动并检查：

```bash
systemctl --user daemon-reload
systemctl --user enable --now chiptrace-codex-agent.service
systemctl --user status chiptrace-codex-agent.service
journalctl --user -u chiptrace-codex-agent.service -n 100 --no-pager
```

主机需要无人登录持续采集时，由系统管理员为该账号启用 user manager linger。自定义
`XDG_STATE_HOME` 时，同步修改 unit 和 managed Hook 中的 `queue-root`、`state-root`，
两者必须指向同一目录。`codex-agent` 对同一 `state-root` 持有
进程级独占锁，第二个实例直接失败，禁止两个 writer 同时推进 rollout checkpoint。
每批 Capture 获得 Relay durable ACK 后，Agent 以源文件当前长度和最后一行 SHA-256
重新校验再提交 checkpoint；Codex 正常追加 rollout 不会被误判为越界或截断。

手动诊断只处理当前 pending 集合：

```bash
CHIPTRACE_PRODUCER_TOKEN="$CHIPTRACE_PRODUCER_TOKEN" \
chiptrace codex-agent \
  --queue-root "$HOME/.local/state/chiptrace/outbox" \
  --session-root "$HOME/.codex/sessions" \
  --state-root "$HOME/.local/state/chiptrace/agent" \
  --relay-url "$CHIPTRACE_RELAY_URL" \
  --source-namespace "$CHIPTRACE_SOURCE_NAMESPACE" \
  --retry-max-times 25 --once
```

## 投影与发布

Collector 封存后的 Raw 先通过 Canonical 校验：

```bash
chiptrace project-interactions \
  --input /srv/chiptrace/capture \
  --output /srv/chiptrace/interactions
chiptrace verify-interactions --projection /srv/chiptrace/interactions
chiptrace export-otlp \
  --projection /srv/chiptrace/interactions \
  --output /srv/chiptrace/otlp
chiptrace verify-otlp --projection /srv/chiptrace/otlp
export LANGFUSE_PUBLIC_KEY='<public-key>'
export LANGFUSE_SECRET_KEY='<secret-key>'
export LANGFUSE_BASE_URL='<langfuse-base-url>'
chiptrace send-otlp \
  --projection /srv/chiptrace/otlp \
  --endpoint "$LANGFUSE_BASE_URL/api/public/otel/v1/traces"
```

`send-otlp` 在发送前重复验证文件、SHA-256 和单根树，默认拒绝
`delivery_ready=false`。瞬时网络错误、408、429 与 5xx 至少重试 20 次；其他 4xx
立即失败。同一投影重放保持确定性的 Trace ID 和 Span ID。

`delivery_ready=true` 的 Trace 可以进入训练候选；`training_ready` 还要求闭合 Session 和
真实训练交互。只有 `buyer_eligible=true` 才进入采购 Release。Release 继续执行精确去重、
连续子序列去重、Buyer Profile 评分、Session 原子分包和全对象 SHA-256。具体命令见
[数据交付](delivery.md)。

## 真实 canary

canary 必须使用未修改的 Stock Codex 和普通 `codex` 命令：

1. provider `base_url` 指向 18084。
2. managed Hook 与 `codex-agent` 自动产生生命周期、rollout 和 durable ACK。
3. Wire 与 rollout 通过 request/response/call ID 精确关联。
4. Session start/end、每个 Turn、工具参数/结果/错误、子代理和 Token 均可见。
5. Raw 重放不重复，原始长度与 SHA-256 守恒。
6. OTLP 每个 Turn 一个 AGENT 根，内部父引用解析率 100%。
7. Langfuse 正确显示 AGENT、LLM、TOOL 树与 `session.id`。
8. 长任务自然满足采购轮次和工具数量后，Buyer 得分不低于 90 且 hard gate 全过。

缺少 Wire 的 rollout-only 样本可以投影 OTLP，但必须保持 `delivery_ready=false`；缺少完整
工具 schema 的执行保留为 RuntimeSpan，不得进入 Buyer 合格集。

## 监控与升级

持续监控：

- Hook pending 文件数、最老文件年龄和失败次数。
- Relay pending/inflight/delivered/conflict/failed 守恒。
- Collector accepted、sealed segment、磁盘剩余空间和 fsync 延迟。
- Wire 有业务但 Capture 零增长、Producer 有事件但 rollout 零增长。
- unknown rollout event、未关联 runtime span、原始字节缺失和 OTLP 缺父节点。
- `wire_ready`、`runtime_ready`、`delivery_ready`、`training_ready`、`buyer_eligible`
  五个 cohort，禁止混报。

热服务升级前必须完成隔离测试和真实 canary，并准备旧镜像与配置回滚。只升级旁路采集，
不改变业务路由、模型选择或响应语义；出现业务延迟、Capture 冲突、积压持续增长或 Raw
hash 不守恒时立即回滚。

历史 Harness、bundle 与启动器代码只用于旧数据重放，已从公开 CLI 帮助和生产接入移除。
