# 平台接入维护与验收

本轮维护补齐 FS/OSS/S3 的磁盘恢复、逐 Turn 四源覆盖校验、原生 Session/Turn 统计和服务端平台插件。
一次请求只确认磁盘中已保存的任务，随后由独立 CLI 子进程执行归档、恢复、检查或采购验收。
业务采集入口仍是网关、Relay 和 Collector；平台插件提供异步管理与交付 API。

已发现并修复的具体故障是 OpenDAL 0.58 在显式 `rustls-no-provider` feature 下未注册
HTTP transport：原先 FS 自测可通过，而 OSS/S3 在发送前返回 ConfigInvalid。网络存储
现在显式注册传输与 TLS provider，并有真实适配器回归。

## 本地验证

2026-10-14 在隔离环境执行，未修改线上 18084 或生产 WAL/OSS：

- Rust 1.91：264 个 workspace 测试和 1 个 CLI 测试通过；fmt、Clippy `-D warnings` 通过。
- Stock Codex 配置、网关 durable outbox：26 个 Node 测试通过。
- 平台 HTTP/SDK：真实 CLI 四源采集 fixture，归档、恢复、分页 Turn、逐 Turn 四源覆盖、
  canonical interaction projection 下载与篡改拒绝、usage 注册、Buyer 导出与下载哈希通过。
  fixture 中 5 个原生 Turn、10 个采购有效轮次、分数 100。
- 故障测试覆盖非零引擎退出、重启重排队、ID 冲突、UTF-8、请求上限、单写者锁、
  锁丢失、任务 ACK 写盘失败、历史容量限制和 Turn 文件篡改。
- OSS 使用带 V1 签名检查的 HTTP 协议 fixture，校验不可覆盖写入、Checkpoint 最后提交、
  单遍恢复和损坏对象拒绝。它不证明真实阿里 OSS 账户的 IAM/区域能力。
- 隔离 MinIO S3 覆盖 6 MiB multipart、幂等、逐记录校验、磁盘恢复、原子替换及损坏拒绝。
- Rust 1.91 + Node 22 平台容器在只读根文件系统和 `--network none` 下执行 HTTP/SDK
  与 OSS 协议测试，通过；Compose 配置解析通过。

GitHub CI 当前包括 Rust/Node、引擎/平台容器、MinIO S3、未修改客户端受管路由和
固定生产者上下文五个作业。
测试报告作为 Artifact 保留，所有管道启用 `pipefail`。远端状态必须读取对应提交的
Actions run，不能用本地通过或旧 main 的绿色结果代替。
MinIO 公共容器标签的远端拉取已返回 access denied；CI 因此从固定的公开源码提交
`07c3a429bfed433e49018cb0f78a52145d4bedeb` 构建隔离服务，避免依赖本机镜像缓存。

## 迭代与发布流程

1. 在修复分支提交源码、Schema 和 API 契约；完成 `make cloud-test`，以及隔离 S3 回归。
2. 等待该提交的 GitHub CI 全部作业（包含固定 Stock Codex 上下文补丁检查）通过，再做 review/合并；镜像记录 Git revision。
3. 用目标云平台自己的身份授权和项目隔离，配置一个项目一套 plugin root/storage prefix。
   服务令牌只在后端使用；不要把 OSS 密钥下发给插件调用者。
4. 在目标 OSS/S3 账号先验收小 Archive：上传、verify、恢复、离线 verify、Session 检查和
   Buyer 导出下载，保存真实 endpoint、IAM 结果和镜像 ID。
5. 先隔离 Stock Codex canary，再升级线上镜像。验收目标 Session 的每个 Turn 都有四源和
   显式结束边界，同时检查 outbox/Relay 排空；全局 health 不能证明每个 Session 可交付。

升级完成后还要运行 `node scripts/ci/runtime-health-gate.js` 检查网关和 Relay 的实时门禁。
它会拒绝旧版本缺少 `openCaptureHealthy` 的响应，以及 `freshness_applicable=false` 的
Relay 快照，避免把“Runtime 仍在增长、Wire 已断流”误判为完整采集。runtime gate v2
还独立校验 `wire_turn_coverage`：明确 Session/Turn、无上下文冲突的 HTTP 2xx Capture
必须近期获得新的 durable ACK；403、无身份请求和 duplicate 不刷新该证据。统计只包含
真实成功 ACK，批量冲突和失败项被排除；CI 保存 `runtime-health-gate-report` TAP artifact。
HTTP 2xx 不证明协议终态，门禁始终输出 `session_delivery_claimed=false`。
门禁还会比较网关和 Relay 的 `delivered` 总数；两端计数不一致时必须先定位投递账本或
健康快照延迟，不能继续交接数据。

后续优先迭代：基于 Session/Turn 索引减少两遍全量扫描；按项目设置磁盘配额和确认后的保留周期；
在主平台完成多租户授权、计费与审计；扩大到真实并发与较大 Archive 的压力测试。
HTTP Turn 分页现先流式验证全部 JSONL/UTF-8，再复核下载句柄的全文件哈希，保持原
JSON 格式并分段返回完整选中记录。`streamTurns` 返回 Response；`getTurns` 对象 API
仍由调用者容纳选中数据。每页仍扫描整份 sidecar，尚无持久索引；任务历史有上限，
导出目录独立保留 Raw，因此上线前仍需安排磁盘容量和保留策略。

2026-10-15 的接入复查发现系统配置和用户配置的同名 Provider 指向不同入口。现有 required
Hook 只验证采集凭据和 Hook ACK，无法阻止 Responses 绕过采集网关。requirements 模板现已
使用固定 Stock Codex 版本支持的 `model_provider` 和完整 `model_providers.OpenAI` exact
约束；`stock-managed-route` CI 作业以未修改客户端、断网容器验证用户配置和命令行覆盖被
约束，并保留旧模板确实可绕过的负对照。该配置回归不使用模型或业务凭据，不代表真实
Turn 上下文、线上配置或 OSS 已验收。当前线上 Collector/Relay revision 为 `fe9fcf9`，
新进程唯一 Wire 是没有原生 Session/Turn 的 HTTP 403，随后 runtime gate 因 Wire 过期
失败；受管配置模板和新的 Turn Wire 统计还未应用到线上主机。

## 真实字段回归与当前缺口

2026-10-14 从保留的 2026-09-05 Stock Codex 原始 sealed Canary 只读重放：
1 个原生 Turn 闭合；Wire 4、精确归属的 OTLP logs 12、OTLP spans 823、不同 Hook 2。
原生日志没有直接的 Turn 属性，Trace/Span 精确关联恢复了这部分证据；没有人为补写原始 ID。
仍有 294 条日志、66 个 span 无法精确归属，`unscoped_turn_records=360`，因此 Session 和
inspect 顶层 `delivery_ready=false`。四源存在和 Runtime 投影通过不能替代完整 Turn 交付。
这些无 ID 记录继续保留在 Raw；后续需要补齐来源端上下文或取得同源精确关联证据。

CI 的原生字段回归涵盖缺少 Turn 属性、无 Session 属性的 traces、共享 Trace、子 Session、
全局身份歧义、全零 ID、冲突别名、父关系环和未归属记录，均不采用时间窗口推断。
同一精确 Span 的不同 Session/Turn 身份必须拒绝，单条日志的显式属性不能覆盖该冲突；
没有事件名的原始日志和 span 仍参与未归属计数，不能因名字缺失而隐式豁免。
自测的 Turn Hook 数严格为 1；真实 Canary 的 UserPromptSubmit/Stop 则是两个不同事件。
新版云验收使用 `cloud-acceptance.v2`，v1 Schema 保留原定义，旧通过产物不会自动升级。

同日使用 `0.163.0-alpha.11` 和真实上游在隔离环境完成新 Canary，仍有 455 条未归属记录。
采集、失败和流式工具证据已保存，但 Session 不可交付；具体字段和下一轮生产者修复验收
见[原生 Turn 上下文记录](native-turn-context.md)。代码修复 `b5352ad` 的远端三个 CI 作业
均已通过，CI 通过不改变真实 Canary 的失败结论。

2026-10-15 又在固定 upstream commit `5425d3e625daa58eea3ad1de27c087eb3b2ffbd3` 上
验证了带生产者上下文补丁的隔离 Canary：真实 `0.163.0-alpha.11` 完成 2 个 Native Turn、
2 个 Session epoch、resume、失败工具进程和延迟 `write_stdin`；四路来源均有证据，
`unscoped_turn_records=0`、`unknown_session_records=0`、`unscoped_otlp_records=0`。
同一仓库门禁输出 `native_turns=2`、`selected_audit_records=3621`、`delivery_ready=true`。
这证明隔离补丁链路可通过当前数据治理门禁，但不是未修改 Stock Codex 或线上部署的通过
证明；正向 fixture 是脱敏元数据，真实 Alibaba OSS 账户验收仍未完成。

本轮同时修正了扩展 producer patch 的 hunk 计数与上下文截断，并在 clean clone 中完成五个
patch 的顺序 `apply --check`、应用和 `git diff --check`。GitHub CI 会继续固定 upstream
commit，先应用已有补丁，再应用 Session 扩展和独立的 process 作用域补丁；任何 patch 漂移
或锁文件依赖变化都应使 job 失败。

生产者编译缓存保存工作区 crate，但缓存身份必须覆盖固定 upstream commit、补丁应用后
全部已跟踪文件、未跟踪的补丁新增文件、协调后的锁文件、执行位和缓存脚本自身。完整
SHA-256 放入 `rust-cache` 的 key，因而 fallback prefix 也限制在同一份源码；Rust 版本、
构建环境与依赖键仍由该 Action 校验。只有恢复缓存后再次核对源码身份，才把源码时间戳
归一化，以避免新 checkout 导致重复编译。源码变化会使用新缓存，身份不符直接失败。
缓存命中也继续执行全部回调、并行、Session 和客户端测试，以及 CLI 构建。
`producer-context-report` 另保留身份、归一化复验和实际 cache-hit 观察；真实 Cargo 回归
覆盖相同源码复用、测试重新执行及源码变化后重新编译并保留真实失败。首次远端缓存填充
和后续命中的耗时需要分别观测，不能从本地回归宣称 GitHub 已获得加速。

新增缓存回归首次在远端 Rust 作业失败；本地使用同一 Rust 1.91 和
`CARGO_TERM_COLOR=always` 真实复现了 9/10：Cargo 已编译成功，但 ANSI 颜色打断了
测试读取的 `Compiling` 文本。子进程现在显式使用 `--color never`，并保留强制彩色环境的
负载来覆盖该差异，仍要求真实编译、复用、测试执行和源码变化后的 exit 101。
CI 另将完整 TAP 上传为 `producer-ci-regressions-report`。收到 runner 的 Ubuntu 26
迁移通知后，五个作业均固定 `ubuntu-24.04`，避免操作系统别名变化使构建环境漂移。
同一轮真实注释还报告三个 v4 Action 的 Node 20 已弃用、正被强制以 Node 24 运行。
已核对上游稳定 release、完整 `action.yml` 和 tag 对应的提交，将 checkout 7.0.1、
setup-node 7.1.0、upload-artifact 7.0.2 固定到 SHA；三者原生使用 Node 24。测试运行时
继续显式选择 Node 22，关闭 setup-node 新的自动包管理器缓存，保留原来的安装和报告路径。

生产者作业的真实远端观测如下。每轮均执行补丁检查、锁文件检查、全部生产者回归和 CLI
构建；表中成功仅指该作业，整轮 CI 仍需按对应 SHA 独立检查。

| 配置 | 提交 / Actions run | 生产者作业耗时 |
| --- | --- | --- |
| 原先仅缓存依赖 | `eb70405` / [38683383719](https://github.com/XS-MLVP/ChipTrace/actions/runs/38683383719) | 9 分 51 秒 |
| 工作区缓存首次填充 | `fd5fd0f` / [38684659151](https://github.com/XS-MLVP/ChipTrace/actions/runs/38684659151) | 19 分 44 秒 |
| 工作区缓存实际命中 | `dd3de61` / [38686561355](https://github.com/XS-MLVP/ChipTrace/actions/runs/38686561355) | 2 分 04 秒 |
| 固定 Go 工具链后的再次命中 | `91bcd79` / [38687168540](https://github.com/XS-MLVP/ChipTrace/actions/runs/38687168540) | 1 分 55 秒 |

命中轮的步骤实际返回 `exact cache hit: true`，随后生产者测试和 CLI 构建分别执行 7 秒和
13 秒，均成功。新缓存为 2,562,094,057 bytes，源码身份与隔离 clean checkout 的完整
哈希一致。源码变化仍需重新填充缓存，耗时会随 runner 负载变化。

`dd3de61` 的 S3 作业在初始化阶段下载 `actions/setup-go@v6` 归档失败，尚未执行协议
测试。只读 HEAD 复查确认 tag API 可用，但 v6 对应提交与稳定 v7.0.0 的 codeload
归档均返回 HTTP 404。工作流改由 runner 预装 Go 的原生 `GOTOOLCHAIN=go1.24.2`
机制选择工具链，构建前检查真实 `go env GOVERSION`；MinIO 源码仍固定同一 commit。
工具链日志和完整构建日志另随 S3 报告保留。`91bcd79` 的上述 Actions run 已真实完成
工具链检查、MinIO 编译和 S3 测试，五个作业均成功；生产者作业再次实际命中缓存，仍执行
全部测试及 CLI 构建。该结果不替代后续提交的 CI，也不证明线上部署或真实 Alibaba OSS
账号已验收。

宿主网关还须使用 `openCaptureHealthy` 门禁。独立部署 smoke：

```bash
CHIPTRACE_GATEWAY_SCRIPT=/absolute/path/to/server.js make gateway-host-test
```

该测试启动临时网关、Provider 和 Relay，保留超过配置期限的流式请求，验证真实 `/health`
变为 `degraded`，不接触生产队列。宿主源码不随 ChipTrace 发布，公共 CI 覆盖 outbox 模块，
目标网关部署前必须运行上述宿主测试；不能用模块通过代替宿主已部署。
