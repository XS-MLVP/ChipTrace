# Stock Codex 接入

用户侧只运行未修改的 Stock Codex。管理员统一下发两个原生配置文件：

| 模板 | 安装位置 | 作用 |
| --- | --- | --- |
| [config.toml.example](config.toml.example) | `/etc/codex/config.toml` | 默认 18084 Responses、OTLP 和 25 次网络重试 |
| [requirements.toml.example](requirements.toml.example) | `/etc/codex/requirements.toml` | 强制 Provider 选择及完整定义、required 生命周期 Hook，并在 SessionStart 执行前置检查 |

系统 `config.toml` 提供默认值，用户配置和会话参数可以覆盖它。仅安装该文件不能证明
Responses 经过 18084：OTLP/Hook 可以仍发往云端，而同名 Provider 已被用户改到另一个入口。
`requirements.toml` 因此显式设置 `model_provider` 和完整的 `model_providers.OpenAI`，
使原生客户端强制使用采集网关和 command auth；修改目标网关时必须同时更新两个文件。
目前原生 requirements 没有对应的 OTLP 强制字段；OTLP 仍是默认配置，必须在真实 Canary
中逐 Turn 验证，不能把 Provider 约束当作四路来源已经完整。

业务凭据和采集凭据由主机管理系统注入环境，不写入配置或 Trace：

```bash
export CHIPTRACE_API_KEY='<provider-token>'
export CHIPTRACE_INGEST_TOKEN='<ingest-token>'
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer%20${CHIPTRACE_INGEST_TOKEN}"
```

`CHIPTRACE_API_KEY` 必须是目标 18084 上游业务系统授权的凭据。当前 router_v2 部署由
Sub2API 验证业务鉴权；另一个 Provider 接受的凭据不能据此视为可在 18084 使用。
2026-10-15 使用同一份现有 Codex 凭据做只读目录检查，共享 Provider 返回 HTTP 200，
18084 `/models` 返回 HTTP 401；没有发送模型请求，也没有输出凭据或响应正文。
管理员应先在目标新客户端进程注入三项环境变量，并用该部署授权的业务凭据验证目录
访问，再下发受管配置和运行真实 Canary。目录访问成功只证明该次目录请求被接受，
模型生成、逐 Turn 四源和远端持久化仍需分别验收。

安装文件后保持权限为 `0600`，并用严格配置启动：

```bash
codex --strict-config
```

此后用户仍直接运行 `codex`。`SessionStart` 会验证三项环境配置和 18084 Hook 入口的
真实持久化确认；缺失、认证失败、入口不可用或确认无效时，在首个 Turn 前停止。
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
  --expected-base-url http://172.28.11.121:18084/
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

原生 Hook 命令依赖 `/usr/bin/python3` 和 `/usr/bin/curl`。命令在每次 Hook 调用时保留原生
JSON 字段，并为缺少身份的事件补充独立 `event_id` 与 `occurred_at`，然后把同一份 JSON
交给 curl，最多执行两次、每次不超过一秒。每次响应独立读取，传输中断时丢弃该次确认
残片，再验证下一次完整响应；不会把多次响应拼接成 JSON。Stock Codex 恢复会话后可能
再次发送内容完全相同的 `SessionEnd`；单纯按请求体哈希去重会丢掉第二次闭合。
独立调用必须有不同 ID，同一次 HTTP 重试必须保持 ID
不变。更新用户级命令后，需要在最终路径重新审核并记录 Hook trust hash。
