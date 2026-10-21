# Stock Codex 接入

用户侧只运行未修改的 Stock Codex。管理员统一下发两个原生配置文件和一个 Hook helper：

| 模板 | 安装位置 | 作用 |
| --- | --- | --- |
| [config.toml.example](config.toml.example) | `/etc/codex/config.toml` | 默认 18084 Responses、OTLP 和 25 次网络重试 |
| [requirements.toml.example](requirements.toml.example) | `/etc/codex/requirements.toml` | 强制 Provider 选择及完整定义、required 生命周期 Hook，并在 SessionStart 执行前置检查 |
| [chiptrace-codex-hook.sh](chiptrace-codex-hook.sh) | `/usr/local/libexec/chiptrace-codex-hook` | 发送生命周期事件并校验 Relay durable receipt |
| [install-host.sh](install-host.sh) | root 安装脚本 | 原子备份并安装两个配置、helper 和采集 token |

系统 `config.toml` 提供默认值，用户配置和会话参数可以覆盖它。仅安装该文件不能证明
Responses 经过 18084：OTLP/Hook 可以仍发往云端，而同名 Provider 已被用户改到另一个入口。
`requirements.toml` 因此显式设置 `model_provider` 和完整的 `model_providers.OpenAI`，
使原生客户端强制使用采集网关和 command auth；修改目标网关时必须同时更新两个文件。
目前原生 requirements 没有对应的 OTLP 强制字段；OTLP 仍是默认配置，必须在真实 Canary
中逐 Turn 验证，不能把 Provider 约束当作四路来源已经完整。

业务凭据和采集凭据由主机管理系统注入环境，不写入配置或 Trace。生命周期 Hook 只需要
Gateway 地址和采集凭据；它不依赖 Provider 业务 Key 或 OTLP header 才能启动：

```bash
export CHIPTRACE_API_KEY='<provider-token>'
export CHIPTRACE_INGEST_TOKEN_FILE=/etc/chiptrace/ingest-token
# The launcher reads the protected token file and sets the OTLP header for
# Codex. If an external secret manager supplies the header, its value is
# Authorization=Bearer%20${CHIPTRACE_INGEST_TOKEN}; do not put the token in a
# shell command. Same-host installs may omit CHIPTRACE_GATEWAY_URL; the helper
# uses 127.0.0.1:18084. Remote/sidecar deployments must set the exact Hook
# gateway.
export CHIPTRACE_GATEWAY_URL='http://127.0.0.1:18084'
```

推荐把采集凭据放在 root-owned、仅 Codex 运行组可读的文件中，避免把内部 token 放进用户
shell 历史或进程启动参数。Hook 与 Codex 由同一普通用户运行，因此 token 文件必须对该
用户所属的受管组可读：

```bash
sudo ./install-host.sh /path/to/chiptrace-ingest-token
# If /etc/codex is owned by root:root, select the group used to run Codex:
sudo CHIPTRACE_CODEX_GROUP=codex ./install-host.sh /path/to/chiptrace-ingest-token
```

脚本会原子替换 `/etc/codex/config.toml`、`/etc/codex/requirements.toml`、
`/usr/local/libexec/chiptrace-codex-hook` 和 `/etc/chiptrace/ingest-token`，先在
`/var/lib/chiptrace-codex/backups` 留存旧文件（备份为 `0600 root:root`）；配置为
`0640 root:<CodexGroup>`，token 目录为 `0750 root:<CodexGroup>`，并拒绝旧内嵌 token、旧
私网 Hook 地址和 `configuration incomplete` 文案。

`CHIPTRACE_GATEWAY_URL` 必须指向承载 `/hooks/codex` 的 Hook Relay；同机部署使用
`http://127.0.0.1:18084`，远程或 sidecar 部署必须显式设置该变量。Provider 的
`base_url` 由路由预检单独核对。安装后先执行一次无业务请求的 Hook 预检：

```bash
printf '%s' '{"hook_event_name":"SessionStart","session_id":"preflight","model":"preflight","permission_mode":"default","source":"startup"}' \
  | CHIPTRACE_HOOK_EVENT=SessionStart \
    CHIPTRACE_HOOK_BIN=/usr/local/libexec/chiptrace-codex-hook \
    /bin/sh -c 'exec "$CHIPTRACE_HOOK_BIN"'
```

预检必须输出空成功流（收到有效 durable receipt 时）或包含固定原因码的
`continue:false`；看到 `ingest_token_missing`、`gateway_unavailable` 或
`invalid_durable_receipt` 时不要启动 Codex，先修复配置。Hook 不会把 token、请求正文或
响应正文写入诊断。

`CHIPTRACE_API_KEY` 必须是目标 18084 上游业务系统授权的凭据。当前 router_v2 部署由
Sub2API 验证业务鉴权；另一个 Provider 接受的凭据不能据此视为可在 18084 使用。
2026-10-20 的 `codex doctor --network` 已用现有 Codex 凭据完成只读目录检查并返回 HTTP 200；
该检查没有发送模型请求，也没有输出凭据或响应正文。管理员仍应在目标新客户端进程中用该部署
授权的业务凭据验证目录访问，再下发受管配置和运行真实 Canary。目录访问成功只证明该次目录请求被接受，
模型生成、逐 Turn 四源和远端持久化仍需分别验收。

受管配置和采集 token 保持 `0640 root:<CodexGroup>`，token 目录保持 `0750`，Hook helper 保持 `0755 root:root`；回滚备份保持 `0600 root:root`。启动时使用严格配置：

```bash
codex --strict-config
```

此后用户仍直接运行 `codex`。`SessionStart` 会验证采集凭据和 18084 Hook 入口的真实
持久化确认；缺失、认证失败、入口不可用或确认无效时，在首个 Turn 前停止。
`CHIPTRACE_API_KEY` 和 `OTEL_EXPORTER_OTLP_HEADERS` 只分别用于 Provider Responses 与
OTLP 路由，缺失它们不会误报为 Hook 配置错误。
Responses Wire 记录模型事实，
`codex.tool_result` OTLP 记录真实工具执行，required Hook 只记录 Session、Turn、压缩和子代理
生命周期，且不覆盖用户已有 Hook。三类事实缺失或冲突时，云端保留 Raw，但拒绝进入采购
Release。

九类 Hook 都要求 HTTP 200，以及 `chiptrace.ok=true`、`durable=true`、正确的
`codex_hook` 来源和零质量错误。单次生命周期事件应确认一个原始批次和一个派生事件，
共两条 Capture；重复数可以是 0、1 或 2，同一次重试的事件字节保持不变。
`HTTP 200 {}`、ACK-only 备用入口、重定向和部分拒绝均不能作为持久化证据。
其他 Hook 的确认失败返回非零退出码，云端继续保留收到的事实并拒绝不完整 Session。
单次 Hook 确认只证明 Relay WAL 接收，逐 Turn 的四源完整性和 OSS 交付仍需独立验收。
开发回归 `make codex-config-test` 会构建 CLI，执行错误确认负例和隔离 Relay/Collector
实测；CI 保存精简的 `native-hook-ack-report`，不采集真实业务正文。

云端 `/models` 必须先验证真实 Provider 凭据，再为真实模型返回 `direct` function 工具目录。
Provider 使用 command auth，确保 Stock Codex 会刷新该目录。Tool Schema 只取模型实际收到的
Responses Wire；模型身份以 Wire 与 Sub2API 精确路由为准。

当前 Provider 约束已使用未修改的 Stock Codex `0.163.0` 在断网、只读根文件系统的
容器中验证。其他版本需要重新运行配置回归和真实 Canary，不能仅凭版本号较新或
`--strict-config` 未报错认定约束生效。`otel.tool_result.max_bytes` 固定为 256 MiB；
受管主机要求 Stock Codex `0.150` 或更高版本，并使用 `--strict-config`；客户端必须支持该字段，
低版本不识别时必须在首个 Turn 前失败，不能以默认 2 KiB 截断结果后继续产生不可交付的 Session。
云端仍以每条事件实际报告的 `output_truncated=false` 为准。

正式版 `0.163.0` 已独立执行合成模型双轮采集，仍因来源上下文缺口拒绝交付。
`stock-release-context` CI 保存该已知拒绝的精简诊断，不声明生产版本支持；命令、固定
身份和验收边界见[原生 Turn 记录](../../docs/native-turn-context.md)。
修复生产者的五项协议联测已迁移到同一正式版源码及完整七补丁；其来源仍为
`patched_stock_cli`，从正常 CLI 入口启动并保留插件启动任务；不表示官方二进制已包含修复。

生产准入只接受仓库内[生产者支持策略](producer-support.json)声明的固定版本和补丁摘要。
该策略明确未修改 Stock Codex 只能走 `diagnostic_rejection_only`，不得因为 Wire、OTLP 或
Hook 的全局计数正常而进入交付。每次 CI 都重新计算七个补丁的 SHA-256，并核对上游提交、
官方二进制摘要和四路来源要求；部署或升级生产者时必须保留同一份策略报告，不能仅凭
客户端版本号或“CI 通过”放行。

配置回归不需要 Provider 凭据，不启动 Turn，不调用模型，也不读取宿主用户配置：

```bash
CHIPTRACE_STOCK_CODEX_MODULES=/path/to/pinned-install/node_modules make managed-route-test
```

部署前还应检查实际下发的 `config.toml`：Responses、OTLP logs 和 OTLP traces 必须同时指向
同一个 `18084` Gateway。该检查只读取路由字段，不读取或输出凭据，也不会调用模型：

```bash
node scripts/deploy/codex-route-preflight.js \
  --config /etc/codex/config.toml \
  --user-config /path/to/actual/CODEX_HOME/config.toml \
  --expected-base-url http://127.0.0.1:18084/
```

`--user-config` 必须指向实际运行 Stock Codex 的 `CODEX_HOME/config.toml`，而不是另一个
用户或系统目录。预检会拒绝用户 Provider 指向外部入口、选择其他 Provider、覆盖鉴权或关闭
OTLP；省略的字段可以继承系统配置。用户级配置仍可能覆盖系统默认 Provider；如果检查发现
外部入口，不能把 Collector/Relay 的健康解释为 Wire 已采集，必须先修正受管配置并重新执行
真实 Session/Turn Canary。受保护的 GitHub live-preflight 将该路径作为
`CHIPTRACE_CODEX_USER_CONFIG` 强制提供。

它先验证旧的 Hook-only requirements 会让用户 Provider 绕过系统默认路由，再通过实际
`config/read` 和 `configRequirements/read` 验证新模板能抵御用户选择、同名 Provider 定义和
命令行覆盖，并移除用户注入的鉴权/HTTP header 设置。GitHub CI 单独安装固定版本客户端，
保留 `stock-managed-route-report`；这项离线检查不替代未修改客户端的真实多轮数据验收。

## 无管理员权限的测试

临时测试可以在独立 `CODEX_HOME` 中使用原生 `config.toml` 和 `hooks.json`，但这不是
`/etc/codex/requirements.toml` 的强制受管安装。通过 app-server `hooks/list` 检查九类
生命周期 Hook，必须同时满足 `enabled=true` 和 `trustStatus=trusted`。管理员审核具体
命令后，应在最终路径记录对应的 `hooks.state.<key>.trusted_hash`，并重新读取验证。

Hook 的 key 包含文件路径，hash 对应实际命令。移动配置目录或修改采集端口后必须重新
校验，不能复制旧的信任状态。`--strict-config` 只检查配置字段是否合法；用户级 Hook
即使显示 enabled，也可能因未受信任而跳过。真实测试必须在 Collector 中检查同一个
Session 的四源和 start/end 闭合，不能以 CLI 正常退出代替采集验收。

Stock Codex 0.153.4 的 `exec --json` 被 SessionStart Hook 前置拦截时，仍可能返回
退出码 0 和零 Token 的 `turn.completed`。前置拦截测试应验证零模型请求；正常采集测试
则应验证真实模型交互、工具结果以及 Collector 的会话完整性。

原生 Hook helper 依赖 `/usr/bin/python3`、`/usr/bin/curl`、`/usr/bin/head` 和 `/usr/bin/tr`。
命令在每次 Hook 调用时保留原生
JSON 字段，并为缺少身份的事件补充独立 `event_id` 与 `occurred_at`，然后把同一份 JSON
交给 curl，最多执行两次、每次不超过一秒。每次响应独立读取，传输中断时丢弃该次确认
残片，再验证下一次完整响应；不会把多次响应拼接成 JSON。Stock Codex 恢复会话后可能
再次发送内容完全相同的 `SessionEnd`；单纯按请求体哈希去重会丢掉第二次闭合。
独立调用必须有不同 ID，同一次 HTTP 重试必须保持 ID
不变。更新用户级命令后，需要在最终路径重新审核并记录 Hook trust hash。
