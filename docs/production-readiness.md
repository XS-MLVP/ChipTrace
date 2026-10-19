# 生产就绪评估

## 2026-10-19 09:28（Asia/Shanghai）线上只读复核（维护分支 `6db26f8`）

本轮只读取健康端点、容器元数据和 Git 状态，未重启服务、修改配置或清理 Raw。18084 Gateway、
3011 Collector、3012 Relay 和 18086 Platform 的 `/health` 均返回 HTTP 200；Relay `/ready` 返回
HTTP 503。Collector 与 Relay 实际运行 revision `db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，
Collector `captures=1,293,154`，Relay `delivered=1,293,154`、`delivery_records=1,293,155`、
`pending=0`、`failed=0`、`conservation_ok=true`，但仍有 1 条 inflight 和 83 次 delivery retry。

业务交付门禁仍真实失败：Relay 持久质量账本为 `6,668`，全部来自 `otlp_traces`，其中
`identity_conflict=182`、`invalid_lifecycle=4,521`、`legacy_unclassified=1,965`；本进程新增
`1,146`。Wire `requests=0`、`successful_turn_scoped_captures=0`、`turn_capture_ready=false`，
缺失且过期来源为 `wire`。同一时刻运行 runtime gate 观察到质量计数 `6,670`，退出码为 1，阻断
原因包含质量、新鲜度、来源覆盖、Turn 就绪和部署 revision 不匹配；OTLP/Hook 流量不能替代
缺失的 Wire。

Platform `/health` 返回 HTTP 200，但没有 `backend` 字段；只读容器环境为
`CHIPTRACE_BUILD_REVISION=db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`、`CHIPTRACE_BACKEND=fs`。
以维护分支 revision 和 `--expected-backend oss` 执行 Platform 健康门禁实际退出 1。因此当前运行
只证明 Raw/WAL、投递守恒和恢复基础仍在工作，尚未达到对外提供完整 Session/Turn 与真实 OSS 导出的
生产标准。

本轮维护分支已推送 `6db26f8`；本地 `make cloud-test` 以退出码 0 完成，覆盖 343 个 Rust 通过、
OSS 签名/恢复、受限堆内存平台路径、质量标签和 GitHub Actions 合同门禁。GitHub Actions 新提交
Run 仍因本环境未认证 `gh` CLI 无法取得真实运行证据，不能把本地绿色替代远端同 SHA 检查。

## 2026-10-19 09:35（Asia/Shanghai）CI 启动输入收敛

维护分支提交 `881f6aa` 将 `stock-managed-route` 作业使用的 `node:22-bookworm-slim` 固定为
`node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392`，
并把同一 digest 通过 `CHIPTRACE_CONFIG_TEST_IMAGE` 传给实际 Docker 测试；合同测试会拒绝退回可变标签。
当前节点用非 root、只读根、无网络参数启动该 digest，实际输出 Node `v22.23.3` 并退出 0。该修复
降低远程 CI 因基础镜像漂移产生的启动差异，但仍需要 GitHub Actions 对同一 SHA 的真实 Run 作为最终证据。

## 2026-10-19 09:01:42（Asia/Shanghai）线上只读复核

本次复核只读取健康端点、Docker 容器元数据和 Git 状态，未重启服务、修改配置或清理 Raw。18084
Gateway、3011 Collector、3012 Relay 和 18086 Platform 的 `/health` 均返回 HTTP 200；Relay `/ready`
返回 HTTP 503。Collector/Relay 实际运行 revision
`db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，Collector 与 Relay 的 Capture/Delivered 均为
`1,291,300`，`pending=0`、`inflight=0`、`failed=0`、`conservation_ok=true`，Collector 队列为 0
且 ready。Relay delivery attempts 为 `1,291,383`，其中 `83` 次为重试；Gateway outbox 的
pending/processing/最近失败均为 0，293 个历史失败原件均有 recovery receipt，未解决数为 0。

业务交付门禁仍失败：Relay 持久质量账本在本次健康采样为 `6,506`，全部来自 `otlp_traces`，其中
`identity_conflict=182`、`invalid_lifecycle=4,359`、`legacy_unclassified=1,965`；本进程新增 984，
Raw 未被改写。Wire `requests=0`、`successful_turn_scoped_captures=0`、`turn_capture_ready=false`，
`wire` 同时缺失且过期。随后以同一 revision 运行 runtime gate，实际观察到质量计数 `6,515`，退出码为
1，阻断原因包含质量、新鲜度、Wire 覆盖和 Turn 就绪；持续增长的 OTLP 不能替代缺失的 Wire。

Platform `/health` 返回 HTTP 200 且无排队任务，但响应没有 `backend` 字段；只读容器元数据显示
`CHIPTRACE_BACKEND=fs`，运行 revision 仍为 `db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`。对同一
端点执行 `platform-health-gate --expected-backend oss` 实际退出 1。维护分支当前已推送提交
`59790ac`，线上尚未部署它，因此真实 OSS 提交、恢复、远端 SHA-256、同 SHA GitHub Actions 和
新鲜多轮 Wire Canary 仍未验收。服务目前只适合内部 Raw/恢复验证，不能向外部使用者承诺完整
Session/Turn 和远端持久导出。

## 2026-10-19 09:13（Asia/Shanghai）当前 release 性能复测

在当前工作树的 release binary 上使用 4 shard、16 并发、64 KiB、批量 64、`fsync` 和
`--max-delivery-retries 0` 连续复测两次。入口确认吞吐为 `3,969–4,071 records/s`，端到端
吞吐为 `1,230–1,235 records/s`，P95 批请求延迟约 `319–335 ms`，两次均为 `10,000/10,000`
delivered、`failed=0`、`delivery_retries=0`、`conservation_ok=true`；排空耗时约 `5.58–5.68 s`。
复测主机 load average 约 `27`，根文件系统使用率约 `91%`，因此不能把历史的 `1,384 records/s`
直接判定为代码回退。下一轮容量结论必须在隔离主机或明确的目标 NFS/OSS 上重复相同参数，并同时记录
P95/P99、磁盘余量、`pending/inflight/retries/failed` 和对象上传耗时；当前结果只证明本版本在受限
环境下仍保持零重试和投递守恒。

## 2026-10-19 08:30（Asia/Shanghai）线上只读复核

本次复核仅读取健康端点和容器元数据，未重启服务、修改配置或清理 Raw。18084 Gateway、3011
Collector、3012 Relay 和 18086 Platform 的 `/health` 均返回 HTTP 200；Relay `/ready` 仍返回
HTTP 503。Collector 与 Relay 实际运行 revision `db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，
Collector `captures=1,289,122`、队列深度为 0 且 ready，单 shard 已封存 849 个 Segment、
`119,280,003,319` bytes；Relay `delivered=1,289,122`、`pending=0`、`failed=0`、
`conservation_ok=true`。Gateway outbox pending、processing 和最近失败均为 0，未解决历史失败为
0；该瞬间 Rust relay 有 1 条 inflight，故不能把单次快照写成完全排空。

业务交付门禁仍真实失败：Relay 持久质量账本为 `6,325`，全部来自 `otlp_traces`，其中
`identity_conflict=182`、`invalid_lifecycle=4,178`、`legacy_unclassified=1,965`；原因分解完整，
Raw 未被改写。Wire `requests=0`、`successful_turn_scoped_captures=0`、`turn_capture_ready=false`，
`wire` 同时缺失且过期。使用同一 revision 的 runtime gate 实际退出 1，阻断原因包括质量错误、
缺少/过期 Wire 和未准备好 Turn 交付；这不是传输进程健康就绪的误报。

Platform 健康响应为 HTTP 200 且当前无排队任务，但未提供新版 `backend` 字段；只读容器环境为
`CHIPTRACE_BACKEND=fs`，运行 revision 仍为 `db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`。对该
端点执行 `platform-health-gate --expected-backend oss` 实际退出 1。因此真实 OSS 提交、恢复、
远端 SHA-256、同 SHA GitHub Actions 和新鲜多轮 Wire Canary 仍未验收，服务目前只适合内部
Raw/恢复验证，不能向外部使用者承诺完整 Session/Turn 和远端持久导出。

## 2026-10-19 08:17:11（Asia/Shanghai）线上只读复核

本次复核未重启容器、未修改配置或清理 Raw。18084 Gateway、3011 Collector、3012 Relay 和
18086 Platform 的 `/health` 均返回 HTTP 200；Relay `/ready` 返回 HTTP 503。Collector 与
Relay 实际运行 revision `db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，Capture/Delivered
均为 `1,287,967`，`pending=0`、`inflight=0`、`failed=0`、`conservation_ok=true`；Collector
队列深度为 0 且 ready，单 shard 已封存 849 个 Segment、`119,280,003,319` bytes。Gateway
outbox 当前 pending、processing 和最近失败均为 0，293 个历史失败原件仍有恢复凭据，未解决数
为 0；独立 trace exporter 关闭。

业务交付门禁仍失败：Relay 持久质量账本为 `6,243`，其中 `identity_conflict=182`、
`invalid_lifecycle=4,096`、`legacy_unclassified=1,965`；当前进程新增 721。错误全部来自
OTLP traces，原因分解完整且 Raw 未被改写。Wire `requests=0`、
`successful_turn_scoped_captures=0`、`turn_capture_ready=false`，`wire` 同时缺失且过期；
runtime gate 在质量、新鲜度和来源覆盖门禁下真实退出 1。新增 `invalid_lifecycle` 仍对应上游
重复 `outcome` 属性，必须修复 Producer 或采用已验收的补丁版本，不能在 Relay 中择一终态来掩盖冲突。

Platform 健康响应仍没有新版 `backend` 字段，实际容器环境为 `CHIPTRACE_BACKEND=fs`，运行 revision
为 `db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`；维护分支最新提交尚未部署，真实 OSS 提交、恢复、
远端 SHA-256、同 SHA GitHub Actions 和新鲜多轮 Wire Canary 仍未验收。因此当前只能用于内部
Raw/恢复验证，不能向外部使用者承诺完整 Session/Turn 和远端持久导出。

## 2026-10-19 07:52（Asia/Shanghai）线上只读复核

本次复核未重启容器、未改动配置或清理 Raw。18084 Gateway、3011 Collector、3012 Relay 和
18086 Platform 的 `/health` 均返回 HTTP 200；Relay `/ready` 返回 HTTP 503。Collector 与
Relay 实际运行 revision `db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，Capture/Delivered
均为 `1,286,211`，`pending=0`、`inflight=0`、`failed=0`、`conservation_ok=true`；Collector
队列深度为 0、ready，单 shard 已封存 `848` 个 Segment、`118,743,161,277` bytes。Gateway
outbox 当前 pending/processing/recent failure 均为 0，293 个历史失败原件及 293 个恢复凭据
仍保留，未解决数为 0。

业务交付门禁仍失败：Relay 持久质量账本为 `6,105`，其中 `identity_conflict=182`、
`invalid_lifecycle=3,958`、`legacy_unclassified=1,965`；当前进程新增 583。错误全部来自
OTLP traces，原因分解完整且 Raw 未被改写。Wire `requests=0`、
`successful_turn_scoped_captures=0`、`turn_capture_ready=false`，缺失且过期来源为 `wire`；
runtime gate 因质量、新鲜度和四源覆盖硬门禁真实退出 1。新增 `invalid_lifecycle` 仍对应
上游重复 `outcome` 生命周期属性，必须修复 Producer 或采用已验收的补丁版本，不能在 Relay
中择一终态来掩盖冲突。

Platform 进程仍运行旧 revision，HTTP 健康响应尚未包含新版 `backend` 字段；只读容器环境明确
为 `CHIPTRACE_BACKEND=fs`，对象目录挂载在本地磁盘。维护分支已把后端字段加入健康契约，并让
受保护 live preflight 只接受 `oss` 或 `s3`，但提交 `d55e26f` 尚未部署。真实 OSS 提交、恢复、
远端 SHA-256、同 SHA GitHub Actions 和新鲜多轮 Wire Canary 仍未验收，因此当前服务只能用于
内部 Raw/恢复验证，不能向外部使用者承诺完整 Session/Turn 和远端持久导出。

## 2026-10-19 07:23（Asia/Shanghai）线上只读复核与生产结论

本次只读复核没有重启容器、修改配置或清理证据。18084 Gateway、3011 Collector、3012 Relay 和
18086 Platform 的 `/health` 均返回 HTTP 200；Collector/Relay 实际运行 revision
`db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，Collector Capture 与 Relay Delivered 均为
`1,284,184`，`pending=0`、`inflight=0`、`failed=0`、`conservation_ok=true`，Collector
ready 且队列深度为 0。Gateway full-trace outbox 当前 `pending=0`、`processing=0`、最近失败为 0，
293 个历史失败文件和 293 个 recovery receipt 仍保留，未解决数为 0。上述证据证明 Raw/WAL、
durable receipt、重试和守恒链路在运行。

业务交付门禁仍真实失败：runtime gate 退出 1，Relay `/ready` 返回 503。该快照的持久质量账本为
`quality_errors=5,944`（`identity_conflict=182`、`invalid_lifecycle=3,797`、
`legacy_unclassified=1,965`），本进程新增 422；Wire `requests=0`、
`successful_turn_scoped_captures=0`，因此 `turn_capture_ready=false`，缺失且过期来源为 `wire`。
对最新 3.76 GB WAL 片段的流式只读复核发现新增错误均为固定的
`conflicting duplicate lifecycle attribute "outcome"`；这与
`docs/upstream-otlp-outcome.patch` 描述的生产者修复一致。Relay 正确保留 Raw 并标记
`invalid_lifecycle`，不能通过选择一个终态或重启清零。

当前实际运行的 Stock Codex 用户配置把 Provider 指向外部地址，受管 `/etc/codex` 虽指向
18084；这解释了 OTLP/Hook 持续增长而 Wire 为零。没有把该配置静默改写，因为它属于用户级运行时
授权。要达到发布标准，必须先用受管配置和已应用生产者补丁的新进程产生至少两个新鲜、带 Session/Turn
身份的 HTTP 2xx Wire，再通过四源 runtime gate、真实 Alibaba OSS 提交/恢复/哈希校验、目标租户
Platform 导出和同一发布 SHA 的 GitHub Actions。

本仓库的优势已经由本地 `make cloud-test` 的真实退出码 0 覆盖：磁盘 Raw/WAL 和 redb 账本可恢复，
质量原因码有界且守恒，Session/Turn 分页不把大正文装入内存，FS/私有 S3/OSS 协议有重启与哈希回归，
容器和 CI 使用不可变 revision、只读根、非 root 及资源上限。它们是可靠性基础，不等同于当前线上
生产就绪。

后续迭代按以下顺序执行：

1. **P0 来源与交付**：修正实际用户 Provider/OTLP 路由，部署包含 outcome/context 补丁的受管
   Producer，观察新错误增量为零并完成真实多轮四源 Canary；任何质量错误、缺 Wire 或 stale Wire
   都继续阻断发布。
2. **P0 远端与对象存储**：用待发布 SHA 核验 GitHub Actions；将 Platform 从 FS 切到目标 OSS，
   完成提交、恢复、远端 SHA-256 和鉴权导出，保留 FS 作为回滚验证而不是生产后端。
3. **P1 性能与容量**：在目标 NFS/OSS 上按现有目录拓扑做迁移前压测，比较 1/4 shard、16/32
   delivery concurrency、批量和 P95/P99；用 `pending/inflight/retries/failed`、磁盘余量和
   `conservation_ok` 建立持续 SLO，再决定是否新建四 shard 数据目录。
4. **P1 GitHub 维护**：合并维护分支前完成同 SHA 远端 run、保护分支和必需检查；本地绿色测试、
   公开 ref 或历史 run 均不能替代新提交的远端证据。

## 2026-10-19 质量账本基线机制（代码变更）

维护分支新增 `chiptrace.quality-baseline.v1`：基线保存完整端点/原因计数、源报告 SHA-256、
审批元数据和自身内容摘要；runtime gate 只有显式传入基线与 `--max-new-quality-errors` 时才按
基线后的增量门禁。计数回退、未知原因、篡改或缺少审批信息均失败，原始质量账本和 Raw 不会被
清零。默认 live preflight 仍使用 `--max-quality-errors 0`，因此本机制没有放宽当前线上门槛。
新增质量基线测试已纳入本地 Makefile 和 GitHub CI；它解决的是历史账本治理，不能替代实际
Producer 路由、四源 Turn、真实 OSS 或目标租户验收。

## 2026-10-19 06:41（Asia/Shanghai）最新只读复核

本次复核未重启服务、未改动主机配置。18084 Gateway、3011 Collector、3012 Relay 和 18086
Platform 的 `/health` 均返回 HTTP 200；Collector 与 Relay 使用 revision
`db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，两者的累计 Capture/Delivered 均为
`1,281,084`，队列、pending、inflight 和 failed 均为 0，Collector ready 且无错误。Collector
当前 sealed Segment 为 846 个、`117,669,720,704` bytes，仍落在 NFS，不能当作远端归档证据。

业务门禁仍未通过：runtime gate 真实退出 1；Relay 持久 `quality_errors=5,714`，全部来自
`otlp_traces`，原因分解为 `identity_conflict=182`、`invalid_lifecycle=3,567`、
`legacy_unclassified=1,965`。`wire` 同时缺失且过期，`successful_turn_scoped_captures=0`、
`turn_capture_ready=false`。其中 `invalid_lifecycle` 继续对应上游同一 Span 重复声明终态；
Raw 和质量账本均保留，不能通过选择某一个终态来清零。Gateway outbox 当前 pending、processing
和 recent failure 均为 0，293 个历史失败文件均有 recovery receipt 且未解决数为 0；独立 trace
exporter 仍关闭。Platform health gate 以同一 revision 退出 0，但当前后端仍为本地 FS。

路由预检以实际运行 Codex 的 user 配置执行时真实退出 1：受管 `/etc/codex` 指向 18084，user
配置覆盖为外部 Provider，因此只能观察到 OTLP/Hook 流量，不能把当前线上状态解释为完整 Wire
采集。真实 Alibaba OSS、未修改 Stock Codex 新鲜多轮 Canary、主平台鉴权导出和远端 Actions
结论仍未验收。

本轮还修复了 GitHub live preflight 的启动阻断：工作流的“Verify the actual Codex configuration”
步骤现在显式注入 `CHIPTRACE_CODEX_USER_CONFIG`，并由契约测试锁定同一步的变量作用域；此前该变量
只存在于前一步，在 `set -u` 下会在路由检查前直接失败。当前工作树的 `make cloud-test` 已真实
退出 0；该本地结果仍不替代对应提交的远端 Actions 证据。

同轮还为 runtime gate 增加了受限排空重试：受控 live preflight 使用 4 次、每次 250 ms，
只对 Gateway/Relay 的 pending/inflight 和 Collector 短暂队列进行重采样；质量错误、缺失或过期
Wire、版本不一致和存储失败不会被重试掩盖。新增回归实际验证了首个快照 inflight 后第二次稳定
快照可以通过，持续业务质量缺口仍保持真实非零退出。

## 2026-10-19 06:53（Asia/Shanghai）当前 release 性能复核

在当前工作树的 release binary 上串行执行了相同 10,000 条、64 KiB、`fsync` 对照，避免并行
构建竞争。Collector WAL 单 shard 为 `3,282.2 records/s`、`205.1 MiB/s`，四 shard 为
`4,676.4 records/s`、`292.3 MiB/s`；loopback HTTP 入口单 shard 为 `3,640.9 records/s`
（P95 `287.6 ms`、P99 `360.6 ms`），四 shard 为 `5,083.7 records/s`（P95 `251.3 ms`、
P99 `275.1 ms`）。

Relay 四 shard、批量 64、并发 16 的端到端吞吐为 `1,384.0 records/s`，入口确认吞吐为
`3,923.4 records/s`，10,000/10,000 delivered、零重试，排空耗时 `4.68 s`；排空期间有
`265/347` 次健康轮询处于背压 503。结果再次说明 Relay 交付和背压是热路径瓶颈，四 shard
有明显收益，但不包含真实 Session/Turn、OSS 上传、多租户竞争或长期 NFS 负载，因此没有把
Compose 默认从单 shard 直接改成四 shard。已初始化的数据目录拓扑不能在线修改，生产切换仍需
独立归档、恢复和目标 OSS 压测证据。

评估日期：2026-10-19。最新线上只读快照为 06:07:26（Asia/Shanghai）；文内较早实验保留各自时间与验证范围。
结论：具备可靠 Raw 采集、持久账本和离线验收的基础，可开展受控试用；当前部署尚未达到向他人承诺
原生 Turn 全量采集、远端持久保存和在线导出的发布条件。

最新快照中 Collector 与 Relay 的传输计数仍守恒：06:07:26 健康观测到两者均为
`1,278,543`，`pending=0`、`failed=0`、`inflight=0`，Collector ready；18084、3011、3012、
18086 的 `/health` 均返回 HTTP 200，但 Relay `/ready` 为 HTTP 503。Collector/Relay/Platform
实际 build revision 均为 `db0294ecb4e5bb9e4d5877ebf659e53926c3a13d`，已完成受控滚动更新。
业务覆盖仍拒绝：`ingest_coverage.status=degraded`，持久 `quality_errors=5525`
（全部来自 `otlp_traces`，其中 `identity_conflict=182`、`invalid_lifecycle=3378`、
`legacy_unclassified=1965`），本次进程质量错误为 3。原因标签按固定分类计数并保留 Raw；
当前缺少且过期的来源为 `wire`（同一时刻 Hook 也尚未观察到），`successful_turn_scoped_captures=0`、
`turn_capture_ready=false`，runtime gate 仍以质量、新鲜度、来源和 revision 门禁真实退出 1。
18086 的平台后端仍为 `fs`；Gateway outbox 当前 pending/processing/recent failure 均为 0，
历史失败原件和 recovery receipt 保留且未解决数为 0，但 trace exporter 仍关闭。
真实 Alibaba OSS 提交、恢复、远端对象哈希、未修改 Stock Codex 新鲜多轮 Canary 和目标租户导出
仍未完成。GitHub API/CLI 当前无法核验远端 Actions 结论；维护分支与 `main` 的远端 ref 已更新，
当前仅以 `git ls-remote` 证明远端 ref 存在。

较早的 03:50 快照显示 Gateway/Collector/Relay 的传输闭环健康：Gateway outbox 的 pending/processing/recent
failure 均为 0，293 个历史失败原件与 293 个 recovery receipt 保留，Collector/Relay 队列为空且
`conservation_ok=true`。Collector/Relay/Platform 实际 revision 均为本次部署的代码基线
`bd2bf5cb54fe5fab4161f37bff5294eff0ebcffb`；Gateway 入口仍是独立发布组件，需在 live preflight
中使用 `gateway_revision` 单独核对。

本轮还将 Gateway outbox 的可用余量接入 runtime gate：受保护 live preflight 要求
`filesystemFreeBytes >= 10 GiB`、`filesystemFreeFiles >= 10,000`，缺失或低于阈值会以固定阻断原因失败。
该门禁只保护 Gateway outbox；Collector sealed WAL 的 NFS 容量、归档和保留周期仍需独立验收。

03:44（Asia/Shanghai）又复跑了 4-shard 与 1-shard 的可重复性能对照（release binary，10,000 条、
64 KiB、批量 64、并发 16、`fsync`、Relay 模式）。4 shard 的入口确认吞吐为 `4,242.2 records/s`、
端到端吞吐为 `1,232.8 records/s`、排空 `5.75 s`；1 shard 分别为 `3,211.4 records/s`、
`1,085.1 records/s`、`6.10 s`。两次均为 10,000/10,000 delivered、零重试、计数守恒；4 shard
使端到端吞吐提升约 13.6%，说明交付链路仍是主要瓶颈。该基准不含真实 Session/Turn、OSS 上传或
多租户竞争，不能替代目标硬件上的容量和 SLO 验收。

04:59（Asia/Shanghai）在同一 10,000 条、64 KiB、`fsync`、Relay 回环条件下补测了配置敏感性：
`batch=128`、并发 16、1 shard 的端到端吞吐为 `1,572.3 records/s`，4 shard 为
`1,893.1 records/s`（约提升 20.4%），两次均为 10,000/10,000 delivered、零交付重试；
并发 32、4 shard 可达到 `2,530.6 records/s`，但 P99 批延迟升至约 `1.29 s`，并发 16 的
P99 约为 `0.52 s`。这支持在真实 NFS/OSS 压测后优先评估四 shard，不能据此直接把并发 32
作为生产默认值；测试仍不包含对象上传、跨租户竞争和长期负载。

较早快照的 Relay `ingest_coverage.status=degraded`，`quality_errors=848`（全部来自 `otlp_traces`），
Wire 已约 96 分钟未刷新，`required_sources_fresh=false`、`turn_capture_ready=false`，
`successful_turn_scoped_captures=279/293`。runtime gate 使用质量错误、新鲜度、历史失败和 revision
门禁真实退出 1；不能将传输进程健康解释为逐 Session/Turn 交付。

18084 trace exporter 当前关闭；平台 18086 `/health` 返回 200 且无排队任务，但响应没有 `build.revision`，
这只证明平台进程存活。
Gateway 容器 OCI revision 为 `e57480eca4fe11769c5fcb8787266ab6b77ce4d5`，新的 Gateway preflight
在传入待发布 SHA 后会拒绝该版本。真实 Alibaba OSS、未修改 Stock Codex 的新鲜多轮 Canary 和
目标 Session 的 `cloud-acceptance` 仍未完成，因此当前服务不满足真实生产发布标准。

本轮维护新增独立 Gateway revision 护栏和 Platform health gate；本地 `make cloud-test` 已真实退出 0，
但本地绿色测试不能替代待发布 SHA 的 GitHub Actions、真实 OSS 和生产 Canary 证据。

提交 `d794700` 修复了维护分支远端 CI 的一个启动阻断：工作流原先把
`Swatinem/rust-cache` 指向 annotated tag 对象 `49a0bdc...`，GitHub Actions 无法从该对象加载
`action.yml`。现在固定到 `v2` 解引用后的可执行 commit
`6323deb102c322ba6fcbdcafc7e3dddab59af2b6`，并由契约测试锁定旧对象不得回归。SSH ref 与工作流
内容已推送并核对；由于当前 Actions API/CLI 仍不可用，尚不能声称该 SHA 的远端作业已经通过。

## 2026-10-18 23:49 维护分支 CI 启动护栏

提交 `b6d7635` 将正式版 Producer 的 Bubblewrap 参数集中到可测试的构造函数，固定只读根、私有
`/etc` 和私有可写 `/tmp`；提交 `266bded` 又让 `scripts/ci/check-native-sandbox.sh` 在长时 Canary
前实际进入 user/PID namespace，写入并校验私有 `/tmp` 探针。两次本机执行均真实退出 0，输出
`BWRAP_READ_ONLY_OK` 和 `BWRAP_PRIVATE_TMP_OK`；协议契约测试 2/2 通过。该检查覆盖了上游
`codex-daemon-*` socket 的启动前置条件，但仍需对应提交的 GitHub Actions run 作为远端证据。
维护分支 `fix/oss-disk-session-platform` 的远端 ref 已更新到 `266bded4e71df227f7940ee628ed6c7520d6347b`；
Actions API 当前不可达，不能声称远端作业已通过。

21:22 的热服务只读复核显示：18084、3011、3012、18086 均返回 HTTP 200；Gateway
health 为 `healthy`，outbox 的 pending/processing/open 均为 0，最近失败为 0。Collector
与 Relay 均报告 revision `ec8a6b2f687e8454f96366abd5efa8542761a98e`、version `0.6.0`；
Collector ready、队列深度 0、Capture `1,173,531` 且守恒通过，Relay delivered 同为
`1,173,531`，pending/inflight/failed 为 0 且守恒通过。传输进程健康不等于业务完整：Relay
`ingest_coverage.status=degraded`，`stale_sources=["wire"]`，Wire age 约 43 分钟，
`successful_turn_scoped_captures=0`、`turn_capture_ready=false`，并报告 163 个质量错误。
使用同一 revision 的 runtime gate 实际退出 1，原因是 `status` 仍为 `degraded`。当前热服务
尚未部署维护分支 `84686f4` 的 CI/文档提交；该提交只改善门禁和审计，不会凭空恢复 Wire。

本次 shell 未设置 Provider/采集凭据，因此没有发送真实 Responses 请求；对应 Provider gate
和未修改 Stock Codex 多轮验收仍为未观测状态。GitHub CLI 未认证且公开 Actions API 请求
超时，`84686f4` 的远端 CI 结果仍不能声明为通过。

18:42 的实际部署复核已将 Collector、Relay 和平台服务升级到维护提交
`30f6d243d527732acbfae4970a740ec88c8451cf`。Collector/Relay 使用同一内容摘要镜像
`sha256:e0c8433fa589627f10386f68f6a8a1d453549ee33d6ecd261c3e655a65af632b`，平台使用
`sha256:da2d19047b47ea4e3dfc4df7a5b6b5cbd5fbab7178b05ad5e092396ff3dcc4e2`；三者的 OCI
revision、预期 revision、非 root 用户、只读根、CPU/内存/PID 限额和持久挂载均已通过预检与
容器 inspect。18084、3011、3012、18086 均返回 200，平台鉴权列表请求返回 200；平台当前
配置为本地 FS 后端，线上真实 OSS 账号和远端对象校验仍未完成。

同一快照中 Collector capture 与 Relay delivered 均为 `1,164,002`，pending/inflight/failed
为 0，`conservation_ok=true`，但 runtime gate 实际退出 1：OTLP logs/traces 仍在增长，Wire
只有 4 条且最后一条约 31.5 分钟前，`wire_turn_coverage.successful_turn_scoped_captures=0`，
覆盖为 `degraded`。这次升级证明了镜像、持久 WAL 和运行隔离已生效，不证明任何新的真实
Session 已通过四源逐 Turn 验收。

16:16 的本机回环只读快照中，18084、3011（Collector）、3012（Relay）均返回 200，
Collector/Relay 仍为 `fe9fcf9`；Collector Capture 与 Relay 累计投递均为 1,154,949，
pending/inflight/failed 均为 0，计数守恒。该 revision 没有本维护分支的新逐 Turn 门禁。
这只是瞬时队列状态，不构成持续 SLO 或完整 Session 的证明。Wire 仍只有 1 条且已约
29.5 小时未更新，覆盖为 `degraded`；Relay health 没有 `wire_turn_coverage`，同轮
18086 连接拒绝。使用三个 `/health` URL 的 runtime gate v3 真实退出 1，明确
报告 `stale_sources=wire`。
网关独立 trace exporter 的 `enabled=false`；Full Trace Raw Capture 仍为启用状态。
网关 health 仍报告模型探针最后可用时间为 10 月 8 日，最近错误为连续失败；未主动调用模型。
Collector health 报告 755 个 sealed Segment 共 94,069,563,151 bytes，保存在共享 NFS；
此观测不证明已提交目标 OSS。当前状态应区分为传输进程存活、完整
业务链路未验收和在线交付入口不可用。

维护分支基线 `a02a1d3` 的 [CI run 38844306105](https://github.com/XS-MLVP/ChipTrace/actions/runs/38844306105)
已独立确认 6/6 作业成功，138 个步骤逐项核对，18 个 artifact 元数据有效。
另独立下载并匹配生产者报告 ZIP 的 GitHub SHA-256，核对五份报告与实际 TAP：5/5、
无跳过；每份均有同一 Raw 的 FS/私有 S3、下载和重启证据，正向 Buyer 分数为 100。
固定正式版的生产者回归、五场景完整 CLI 采集、官方原版拒绝诊断、受管路由、容器
及存储作业均实际执行；五项新采集的同一 Raw 已分别走 FS 和私有 MinIO S3，报告检查也
实际执行。它不证明线上已升级，也不能替代后续修复对应提交的远端 CI。

本轮维护提交 `3e7e5f2`（包含 `2af2ae0`）已推送到 `fix/oss-disk-session-platform`。本地 `make cloud-test`
实际退出 0；新增报告门禁要求每个 Turn 的唯一身份、闭合/取消终态、模型交互数、工具数和
四源完整覆盖，并要求 FS/私有 S3 摘要一致；逐 Turn OTLP/Hook 计数不得超过 Session 总量。
GitHub Actions API 在本次复核中未认证且连接
超时，故该提交的远端作业状态仍为未核验；本地验证不能替代同 SHA 的远端 CI。

17:05 的 runtime gate 复核再次真实退出 1：网关、Relay、Collector 的 delivered/capture
均为 1,157,373 且队列为零，但 Relay 覆盖仍为 `degraded`，Wire 年龄约 30.4 小时；
报告中的 `wire_turn_coverage` 四项计数为空，不能证明任何近期成功的 Turn。该报告只保留
有限健康摘要，不含对话正文。

## 当前发布门槛与迭代顺序

生产者准入现在由 `integrations/codex/producer-support.json` 和
`scripts/ci/producer-support-gate.js` 固定。当前策略只支持带七个内容寻址补丁的
`patched_stock_cli` 作为生产候选；官方未修改 `0.163.0` 的结果必须保持
`diagnostic_rejection_only`。这条门禁解决了“维护分支 CI 运行修复版、线上却运行官方版”
的治理错位，但它本身不会升级线上客户端，也不会替代目标环境的真实 Canary。

| 优先级 | 当前证据与缺口 | 进入下一阶段的验收条件 |
| --- | --- | --- |
| P0 业务采集 | Runtime 持续增长，但 Wire 陈旧；官方原版仍有未归属记录 | 真实业务走采集入口，固定生产者版本；新 Session、resume、失败与异步工具的逐 Turn 四源、身份、正文及终态全部独立通过 |
| P0 在线交付 | 平台端口连接拒绝；隔离 HTTP/SDK 导出已通过 | 匹配 revision 的目标环境内，以平台租户身份完成检查、鉴权下载和完整包哈希核对 |
| P0 远端持久化 | FS/私有 MinIO S3 通过；线上观测仅为 NFS | 目标 OSS 账号完成提交、远端对象核验、磁盘恢复、重启后逐字节验证，并留存权限与恢复证据 |
| P1 运维与治理 | 实际容器可写且没有 CPU/内存/PID 限额；生产容量未验收 | 应用已验证的部署边界，完成负载/SLO、告警、容量与保留周期、脱敏视图、租户隔离和恢复/回滚演练 |
| P1 GitHub 交付 | `main` 仍为 `514d4cf`，公开 API 显示未保护且无 Release | 经 review 合并已核验提交，设置必需检查与发布审批，固定镜像摘要、revision 和回滚版本；单次 CI 绿色不替代生产验收 |

优势在于精确 Raw 留存、四源原生身份关联、严格的完整性拒绝，以及从采集到存储、
恢复、导出的可复验链路。主要短板是这些隔离实现证据尚未在真实业务环境中闭环。
本表是验收顺序；未修改线上部署、分支保护、Release 或历史 Raw。

## 实际部署模板的隔离验证

只读配置负对照确认：旧平台模板在未固定镜像和 revision 时，仍生成
`chiptrace-platform:local` / `unknown`，静态的版本约束测试也通过。新模板要求显式
镜像及完整 revision，部署前预检进一步拒绝可变 tag，核对本地 image ID/仓库摘要、
OCI revision、只读根、非 root 和资源限额；平台构建从生产 Compose 中移出。

新的实际配置回归修复前 0/2，修复后 2/2；与现有配置契约一起执行为 10/10、无跳过。
隔离镜像的 Rust/平台源码与 `1916836` 相同，使用修复中的工作树模板实际启动三个服务，
核对镜像身份和 CLI 编译 revision，并按原有 Wire/OTLP/Hook 来源边界回放合成数据。
Collector 的 29 条 Raw 与原始 fixture 字节相同，Relay 保存其应有的 28 条；独立评估
记录仅进入私有 Collector。归档、恢复、5 原生 Turn 和 score=100 的采购下载通过。
实际重启三个服务后，Raw、任务、Turn JSONL 与采购包字节均不变，临时容器和网络已清理。

联测最初因混用 Canonical/Raw 计数失败，之后又复现了当前 Docker 的 internal 网络
不发布回环端口，以及动态端口重启后重新分配的行为；失败证据保留，脚本使用独立临时
bridge，并从实际容器读取重启后的端口。Compose 内存值的字符串表示也按数值规范化，
随后实际完整联测退出 0。CI 新增相同模板联测和精简 `deployment-smoke-report`，不上传
Raw 或对话正文；发布仍须核验本修复对应提交的远端作业。

默认限额为 Collector 8 GiB、Relay 12 GiB、平台 4 GiB，均为 2 CPU 和 256 PID，可显式
调整。这些是运行边界，不是容量验收。该测试使用合成数据和 FS，未修改线上部署，
也不证明未修改客户端、真实模型、目标 OSS 或租户授权已验收。

## Collector 运行门禁

运行门禁此前只检查网关与 Relay，没有观察 Collector。新增的两项负对照在修复前
实际 0/2、退出 1：健康的上游快照仍可能掩盖未探测、不可用或版本不一致的 Collector。
v3 现在强制传入三个健康 URL，核对 Relay/Collector 的完整 Git SHA、Collector 的
ready、空队列、无错误，以及持久 Capture 数不少于 Relay delivered。私有评估或其他
Relay 可以贡献额外 Capture；计数下界不证明任何 Session 的逐对象完整性。

定向回归实际 15/15、无跳过，包含真实 HTTP CLI 探测、缺参数、503、错误版本、
未知 SHA 和计数不足。扩展模板联测实际退出 0，11 项检查全部通过；正向探测直接访问
临时 Collector/Relay，网关健康明确使用合成 fixture。受控 Collector 503 和版本错误
均真实退出 1。三个服务重启后旧 Raw、Turn 和采购包字节不变，但运行门禁因缺少新的
进程级来源证据正确拒绝，不能用重复数据刷新成功 Wire 的新鲜度。

该门禁修复未改 Rust 或平台源码，本地沿用与 `1916836` 相同源码构建的隔离镜像；
对应 `88894c4` 的远端 CI 已实际按新 SHA 重建，6/6 作业成功。报告明确
`session_delivery_claimed=false`、合成网关、非真实上游、非真实 OSS 账号、非生产验收。
该门禁修复尚未部署，后续 Rust 修改仍须核验各自提交的远端 CI。

## 官方正式版 0.163.0 的新采集

官方 npm 的未修改 Linux x64 二进制在私有 user/PID/mount namespace 中新执行同模型
双轮、resume、真实失败工具和异步轮询。来源为官方 commit
`83086188ae0614bd882818ff1aa23f3194962012`，完整源码树和实际 ELF 均有固定 SHA-256；
生产者没有补丁，模型和 usage 仍为本地合成，不能称为真实上游验收。

首次隔离结果为 2 个闭合 Native Turn、2 个闭合 epoch、12 次 HTTP 尝试、10 条工具记录；
四源、协议、Raw 和 Runtime 完整性均为 true，但有 399 条未归属 Turn 记录及另 151 条
未知 Session span，整体 `delivery_ready=false`。重复只读审计得到相同结果，原始
7,072,139-byte sealed Segment 的 SHA-256 保持
`5875479a061ad89d8e359520f4d2e3536629eaceda0b4def8ecbc71332d7aec6`。

仓库新增 `stock-release-context` CI 作业直接使用官方二进制和同一正向测试，不再需要
修改临时 harness。新执行本地复验又保留 2 Turn / 12 请求 / 10 工具记录，实际未归属
Turn 为 422、未知 Session 为 153；初始化 span 数量会变化，不能写成固定生产统计。
正向测试仍真实退出 1；独立诊断门禁只在完整采集和计数守恒成立、且确有来源缺口时
接受这一拒绝结果。启动/配置/工具失败、超时、缺少报告、身份不符或意外可交付都会
使该诊断作业失败。其通过仅表示已复现已知缺口，报告始终为
`production_ready=false`、`real_upstream=false`，不是生产门禁通过。

报告上限 16 KiB，仅保存计数、版本/源码/二进制和 Raw 哈希，不保存对话、工具正文或
完整 Turn 数组；GitHub artifact 只选择精简报告和测试日志，失败 Raw 保留在临时 runner。
具体运行命令和身份约束见[原生 Turn 验收记录](native-turn-context.md)。

## 同一正式版的完整修复 CLI

在同一 `0.163.0` 源码应用完整七补丁后，正常 CLI 的 `app-server` 入口完成五项新采集
联测，实际 5/5 通过、无跳过，保留插件启动任务。`patched_stock_cli` 与官方原版使用
相同的私有 user/PID/mount namespace、只读根及私有 `/etc`、`/tmp`；报告核对完整源码、
七补丁和实际 CLI ELF 的 SHA-256。五份报告的 OTLP 分类均守恒，未归属 Turn 和未知
Session 记录均为 0；不能用旧 debug App Server 的结果替代这次启动边界验证。

同模型正向样本保留 2 Native Turn、2 个 epoch、12 次 HTTP 尝试及 10 条工具结果，
通过 FS 归档/恢复、全部投影和 Turn 鉴权下载、Buyer 下载包内容核对、重启与幂等复验，
score=100、采购有效轮次=12、生成 1 个包。模型切换、取消/断流及缺少压缩 Hook 或业务
Stop 的负例仍被拒绝；手动/自动压缩的一工具样本仍明确未执行 Buyer 准入。

这些是带补丁生产者、合成模型和 FS 后端的隔离证据，五份报告均声明
`production_acceptance_claimed=false`、`real_upstream=false`、`real_oss_account=false`。
它们不改变官方未修改二进制的来源缺口，也不证明线上已升级或目标 OSS、租户授权和
容量达到生产条件。线上容器本次仍未设置 CPU、内存、PID 限额，根文件系统可写。

## 同一原生 Raw 的网络存储路径

五项新采集已在隔离本地分别通过 FS 和私有 MinIO S3 平台路径，5/5、无跳过。
S3 端独立下载远端 Checkpoint、Manifest 和每个 Segment，核对提交状态、原始字节/
哈希及规范化分片身份，再完成磁盘恢复、完整 Turn/投影鉴权下载和重启复验。正向
2 Native Turn / 12 次请求 / 10 条工具结果在两后端均通过 Buyer，score=100；混合模型
和取消/断流仍真实退出 1，一工具压缩样本仍不宣称 Buyer 准入。

FS/S3 重启前后四次下载的完整 Buyer Session JSONL 已独立核对字节与 SHA-256 相同；
回归报告保留该摘要并要求跨后端一致，不将对话正文加入报告。首轮新增路径断言曾因
忽略归档的分片路径规范化而失败；失败 Raw 保留，修正对照后重新采集通过。
完整 `cloud-test` 实际退出 0：fmt/Clippy、312 个 Rust 库测试、1 个 CLI 测试和 284 个
Node 测试通过；三项 RSS 默认忽略，仍须由独立 CI 门禁执行。MinIO multipart/损坏
拒绝回归另行通过。这仍是带补丁生产者、合成模型和隔离 S3，不证明目标阿里 OSS、
未修改生产者或线上授权交付已验收。

## 同批 OTLP 结构错误的拒绝

隔离 HTTP 回归实际复现：同批一个正常日志旁的 `logRecords` 被写成对象时，旧 Relay
返回 200、`source_records=1`、`conversion_errors=[]`，来源审计也跳过异常同批结构。
两个新增 Rust 回归先真实失败；失败请求的 Relay/Collector 原始 WAL 均保留。

共享遍历器现在先检查资源、Scope 和记录数组及其元素，结构错误使来源审计拒绝。
入口保留精确 Raw 和仍可读取的派生工具结果，记录不可归属的结构错误，再由现有持久
确认逻辑返回 HTTP 400。可选数组缺省、null 或为空时仍表示零条记录；诊断只含字段路径，
不展开错误字段正文。两端日志/Trace 的重复请求、WAL 字节、重启恢复和实际 CLI 拒绝
均已通过；此前误接受的同一份 Raw 只读重放现真实退出 1，原始 SHA-256 不变。

本轮完整 `cloud-test` 实际退出 0：fmt/Clippy、316 个 Rust 库测试、1 个 CLI 测试和
285 个 Node 测试通过；三项 RSS 默认忽略，继续由独立 CI 门禁执行。受限容器作业也
纳入相同 HTTP/WAL 回归；其远端结果仍须核对本修复对应的提交。这是未部署的结构完整性
修复，不证明真实上游、目标 OSS 或线上逐 Turn 采集已验收。

修复后的引擎另完成五项新的完整 CLI 采集，实际 5/5、无跳过；同一 Raw 的 FS/S3
报告检查通过，全部来源分类守恒且未知 Session/未归属 Turn 均为 0。正向 Buyer 下载
仍为 score=100，FS/S3 与重启后完整 Session JSONL 的字节/SHA 一致；混合模型和取消/
断流继续拒绝采购，压缩样本不冒称满足采购准入。生产者补丁和合成模型身份均未改变。

## OTLP 身份别名的采集确认

隔离服务实际复现：日志的 `conversation.id` 与 `session.id` 矛盾时仍返回 HTTP 200；
新增 HTTP 回归真实退出 1，两项 Rust 回归也分别退出 101。离线来源审计原本会拒绝
这些别名冲突，但入口没有执行相同规则，不能把其持久化确认视为质量成功。

现在 logs 在派生所有者前、traces 在确认质量前复用原生身份规则；矛盾的 Session、
UUID `thread_id`、Turn 和 root Turn 别名在完整原文落盘后返回 HTTP 400。正常同批
记录保留，存在身份歧义的工具日志不派生所有者。只读取身份标量进行新增检查，不复制
工具输出或日志正文；诊断不含身份值和正文。相同别名、层级覆盖和不同的 Turn/root Turn
仍正常接收。

定向 Rust 转换回归实际 21/21、无跳过。真实临时 Relay/Collector 的 HTTP 联测通过：
20 份 batch 在两份 WAL 的原始 UTF-8 字节和哈希一致，重复投递及实际重启通过，冲突
Raw 的来源审计继续真实退出 1。这是合成协议回归，未改线上服务；对应提交的远端 CI、
未修改生产者、真实 OSS 账号和租户授权交付仍需独立验证。

复核还发现转换器支持 `codex.root_turn_id`，审计的 root Turn 别名表却遗漏它。新增
Rust/真实 CLI 回归先实际失败，分别退出 101/1。补齐后，只有该字段的记录可精确归属，
与其他 root Turn 别名冲突时拒绝；普通 Turn 与 root Turn 的值仍可不同。同一份失败
输入只读回放从 0 条恢复为 1 条归属，原始 SHA-256 不变，未冒称完整 Session 可交付。
最终源码的完整 `cloud-test` 实际退出 0：fmt/Clippy、319 个 Rust 库测试、1 个 CLI
测试和 290 个 Node 测试通过；三项 RSS 默认忽略，继续由独立 CI 门禁实际执行。

该身份修复提交 `7b48ae6` 的 [CI run 38838161789](https://github.com/XS-MLVP/ChipTrace/actions/runs/38838161789)
已独立核对 6/6 作业成功、138 个步骤与 18 项产物元数据；没有下载产物正文重新哈希。
这不替代后续提交的 CI 或线上验收。

## OTLP 元数据结构的拒绝

新增隔离回归实际复现：resource 的 `attributes` 是对象时，Relay 返回 200，离线 CLI
仍将该日志计为 1 条 Turn 归属、未归属为 0。两项 Node 回归先真实退出 1，三项 Rust
负对照真实失败、测试命令退出 101；错误属性还可能被当作空列表，借用继承字段派生工具所有者。

共享检查现拒绝非对象的 resource/scope 元数据、非数组的属性和非对象的属性元素。
logs 在派生前检查，traces 和离线审计使用相同规则；省略/null 元数据及省略/null/空
属性列表保持原义。错误 Raw 继续保留，同批正常记录继续处理，诊断不展开错误正文。
定向 Rust 回归 9/9，另有可选元数据正向回归通过。真实临时服务的 18 份 logs/traces
批次在 Relay/Collector WAL 中逐字节与哈希一致，重复确认和实际重启通过；错误输入
返回 HTTP 400。同一份旧失败 CLI 输入现在真实退出 1，原始 SHA-256 不变。

完整 `cloud-test` 实际退出 0：fmt/Clippy、323 个 Rust 库测试、1 个 CLI 测试和
291 个 Node 测试通过；三项默认忽略的 RSS 仍须由独立 CI 门禁实际执行。
这些是合成结构回归；对应新提交的远端 CI 仍须核验，不证明线上、未修改生产者、
目标 OSS 或租户授权交付已经通过，也不宣称实现全部 OTLP 字段语义验证。

该提交 `f40bdbf` 的 [CI run 38840675811](https://github.com/XS-MLVP/ChipTrace/actions/runs/38840675811)
实际为 5/6 作业通过，`upstream-context` 的正常双轮 Buyer 平台子进程失败。采集检查已
通过，但平台报告没有生成；现有日志缺少真实退出码、信号和 watchdog 状态，不能据
总耗时推定超时。失败产物的 ZIP 已独立匹配 GitHub SHA-256，失败证据保留。
同源码本地新采集通过仅证明该隔离路径可用，不能抵消远端失败。后续诊断只输出进程
元数据、有界源码位置和耗时，不公开子进程正文，仍保留原有 120 秒预算及全部验收门禁。
诊断补丁的真实进程回归 9/9 通过，新增完整五场景联测也实际 5/5、无跳过；正常双轮的
平台子进程耗时 104.4 秒，同一 Raw 的 FS/S3 与 Buyer 下载摘要一致。该本地结果仍不
解释旧远端失败；对应新提交的远端结果须独立核验。

诊断提交 `ee05efe` 的 [CI run 38843352287](https://github.com/XS-MLVP/ChipTrace/actions/runs/38843352287)
已独立核对 6/6 作业成功、138 个步骤与 18 项产物元数据；未下载正文重新哈希。
该成功没有复现或解释上一提交的失败。另以同一 Rust 1.91、同源码和同一隔离产物做
只读完整验收对照：debug 9.15 秒，release 0.68 秒，8,073 字节输出的 SHA-256 完全相同。
release 的五项新采集实际 5/5、无跳过；正常平台子进程耗时 9.9 秒，FS/S3、Buyer 下载
和原有负例均保留。原生协议 CI 因此改用与部署镜像相同的 release 构建，仍固定当前
revision、原有 120 秒预算和全部门禁；该工作流改动对应的新提交仍须独立远端核验。

## 工具属性冲突与原生线程元数据

隔离负对照实际复现：同一 OTLP 列表先声明 `output_truncated=true`，再声明 false，
旧 HTTP 入口返回 200、无转换错误，并派生该工具结果；离线审计也接受该 Raw。
两项 Rust 回归先真实失败。修复在属性解析/覆盖前比较原始可选 AnyValue，工具参数、
输出、调用身份、成功和截断标志等发生矛盾时，先保留完整 Raw，再拒绝质量 ACK 和
离线来源审计；同批正常工具仍保留。未知属性名及其值不进入错误文本，只报告位置。
相等重复值、可选空值和不同层级间的正常覆盖仍保持原义。

全键检查的首轮完整回归同时发现，历史真实元数据和当前带补丁生产者均混用
`thread.id` 的 OS 线程号与旧 Session UUID；后者一次双轮样本有 12 处。该字段按既有
数据契约不是原生 Session 身份，现仅留在 Raw，不进入两种解释属性表。保留原 fixture
与原来的来源缺口计数，不删除历史冲突，也不将其猜成会话或轮次；其他属性继续检查。

修复后的真实临时 HTTP 测试覆盖 logs/traces、三层属性、两种冲突顺序、缺值冲突、
相等重复、正常同批工具、重复投递与实际重启；30 份 batch 和 18 条合法工具结果在
Relay/Collector 的两份 WAL 中逐字节一致。36 份离线 CLI 冲突输入均拒绝且文件不变。
之前误接受的同一 HTTP/CLI 失败输入只读重放现真实退出 1，原始文件 SHA-256 不变。
该修复提交 `5369416de1b27b61e71a98c485d25323b3aba5d0` 的
[CI run 38847565004](https://github.com/XS-MLVP/ChipTrace/actions/runs/38847565004)
已实际完成并独立核对为 6/6 作业、138 个步骤、18 个 artifact 元数据成功。
生产者报告 ZIP 为 27,248 bytes，SHA-256
`6f134fbe84a4d0bbd95f2ec473748d42c25d32bd865a138656f7db03869ff45b`，与 GitHub 元数据匹配。
五个场景 TAP 为 5/5、无跳过；正向 Buyer 场景为 2 Native Turn、12 次模型交互、10 条
工具结果、score=100，FS/私有 S3/重启后的下载摘要一致。所有报告仍明确
`real_upstream=false`、`real_oss_account=false`、`production_acceptance_claimed=false`；
这是未部署的协议修复和 CI 证据，不是线上验收。

## 平台状态验收

本轮分支修复了历史平台状态误报：旧任务即使独立完整性证据不通过，只凭顶层 ready
标记和来源审计也可能在查询、分页中被误报可交付；重复提交还会直接返回旧记录。
现对记录中的 Session、四源、来源审计和完整性/验收门禁作保守复核，覆盖查询、重复
提交和两类分页；导出还检查 Buyer 轮次/工具/配对、单根/父引用、Raw 数量和分数门槛。
只调整返回副本，历史文件及嵌套证据保持不变。
相同取消 Raw 已通过正常 HTTP/SDK 的 FS 归档、恢复、全部投影下载与重启检查；
Buyer 导出因协议不完整真实退出 1，未鉴权下载为 401。这是合成模型、带补丁生产者和
FS 后端的隔离回归，尚未部署，不能代替真实 OSS、终端租户授权或在线交付验收。
38 类缺失或矛盾历史状态负例修复后通过；最终 `cloud-test` 实际退出 0，包含 306 个
Rust 库测试、1 个 CLI 测试和 280 个 Node 测试。正常与取消平台联测另行新执行，
2/2 通过；三项默认忽略的 RSS 回归仍由独立 CI 门禁执行。

## 原生采集到采购下载的联测

新增正向平台联测首先真实失败：同一份正常采集 Raw 的 Session 完整性检查通过、评分
95，但 Buyer 拒绝，唯一失败项为 `model`。该 Session 在 resume 后从 `gpt-5.6-sol`
切换到 `gpt-6-astra`，不符合当前单个 Buyer Session 的有效模型一致要求。原始数据和
失败记录保留；没有放宽门禁、重写模型身份或切分原始 Session。严格 Release 现在返回
不含正文的失败门禁计数，同份派生数据重放仍真实退出 1，Raw SHA-256 不变。

新执行三项原生协议回归实际全部通过：模型切换保留并按 `model` 拒绝导出；同模型双轮
采集完成真实 HTTP/SDK 的 FS 归档、恢复、检查、投影下载、Buyer 导出与重启复验；取消/
断流仍保留部分证据并拒绝采购交付。正向 Session 有 2 Native Turn、2 个 epoch、12 次
HTTP 尝试、10 条真实工具结果、5 类工具，score=100、采购有效轮次=12，生成 1 个包。
下载端独立读取 tar 条目，复核 UTF-8、包内字节/SHA、完整 Session、每次请求引用、两轮
身份和全部实际工具结果正文；未鉴权下载返回 401。usage 来自隔离合成 endpoint 的逐次
独立观察，以真实响应 request ID 关联，不能视为真实 OpenAI 身份或模型执行证据。

这些测试使用固定的带补丁 App Server、合成模型与 FS 后端，CI 新增独立正向报告。
它们补上从新采集到实际下载内容的实现证据；线上升级、未修改客户端、真实 OSS 账号、
租户授权及生产容量仍未验收。
本轮完整 `cloud-test` 实际退出 0：307 个 Rust 库测试、1 个 CLI 测试、280 个 Node
测试通过，fmt/Clippy 通过；上述三项新采集联测另行全部通过。三项默认忽略的 RSS
测试继续由独立 CI 门禁负责，不能用默认套件的成功代替其实际执行。

## 独立手动压缩与 Turn 边界

新执行真实 `thread/compact/start` 首先复现了独立压缩 Turn 一直 open：生产者只有
PreCompact/PostCompact，没有 Stop。四个原生 Turn 中仅三个闭合，虽协议和四源完整，
`root_complete`、`runtime_complete` 和整体交付状态仍为 false；失败 Raw 已保留。

SessionView 和 Canonical Runtime 现共享严格边界规则：精确相同原生 Session/Turn 的
全部 Wire 必须声明手动独立压缩，且恰有一对身份一致、顺序合法的 PreCompact/成功
PostCompact；存在普通请求、业务开始或实际工具执行时不得使用此规则。只引用真实
Hook，不补造 Stop，不以网关/生产者时钟相等推断关联，不修改 Raw。

同一失败 Raw 只读回放后 4/4 Turn 闭合，5 次交互的投影字节、来源计数和审计不变，
原始 SHA-256 不变。新采集另完成 4 Turn、2 个 epoch、5 次 HTTP 请求、真实 exit 7
工具结果，压缩摘要跨后续轮次和新进程 resume 保留；FS 归档恢复、全部投影下载和
平台重启均通过。内联阶段、缺 PreCompact、缺 PostCompact 三份派生负例协议仍完整，
但根边界、Runtime 和整体交付均被拒绝，原始 Segment 不变。

新增场景与正常 Buyer、混合模型拒绝、取消/断流一起执行，四项原生联测实际 4/4 通过。
完整 `cloud-test` 实际退出 0：fmt/Clippy、309 个 Rust 库测试、1 个 CLI 测试和 280 个
Node 测试通过；三项 RSS 默认忽略，仍由独立 CI 门禁验证。
压缩样本只有一种工具，明确报告 `buyer_export_checked=false`；采购准入仍由独立多工具
正向用例验证，未放宽门槛。所有场景仍使用固定带补丁生产者、合成模型和 FS 后端，
不证明未修改客户端、真实 OSS 或线上已完成验收。

## 自动压缩的完整生命周期

新执行的隔离 App Server 实际触发轮前、轮中、轮后三个自动压缩，保留 4 个业务
Native Turn、2 个 epoch、8 次 HTTP 请求和实际 exit 7 工具结果；摘要跨新进程 resume
继续使用。首轮故障注入移除同一业务 Turn 的自动 PostCompact 后，协议、四源和业务
Stop 均存在，旧检查仍返回可交付。失败采集、派生副本和原始结果均已保留。

修复后 SessionView 与 Runtime 共享压缩完整性检查：以原生窗口/阶段识别操作并合并
HTTP 重试，核对同 Session/Turn/trigger 的全部 Pre/Post 数量、身份、状态和来源端顺序。
Runtime 保留真实 Hook 引用与压缩计数；业务终态计数不变，自动 PostCompact 不能
替代业务 Stop。缺少压缩证据的已闭合业务 Turn 标为冲突，拒绝 Session、根和 Runtime
的完整交付；不按网关时间猜关联，不补写 Hook，也不改 Raw。
子 Session 投影到父 Session 后继续按 `source_session_id` 校验，父子复用相同 Turn ID
也不会混合压缩证据；相关身份隔离回归已通过。

同一缺 PostCompact 副本只读回放已从可交付改为拒绝，未删改的完整原样本仍通过。
两份输入回放前后的模型交互投影、来源审计和真实业务终态计数均不变，原始 Segment
SHA-256 不变。独立新采集已通过 FS 归档、恢复、全部投影下载及重启复验；一工具样本
仍报告 `buyer_export_checked=false`。新增回归还要求分别移除同一 Turn 多个压缩中的
一个实际 Pre/Post 事件，或移除轮中/轮后业务 Stop，均不得交付。所有模型字节与 usage
仍为合成，固定带补丁生产者没有变化；该修复尚未部署，也不证明真实 OSS 或未修改
客户端达到生产条件。历史产物需从 Raw 重新检查。
完整五项原生采集联测实际 5/5 通过；最终自动压缩源码另行新采集复验通过，四个负例
各移除一个真实 Hook 调用的原始 batch 和派生事件，业务终态与压缩终态没有互相替代。
最终源码的完整 `cloud-test` 实际退出 0：fmt/Clippy、312 个 Rust 库测试、1 个 CLI
测试和 280 个 Node 测试通过；三项 RSS 默认忽略，继续由独立 CI 门禁实际执行。

## HTTP 重试与全量交互回归

新的隔离采集实际复现并修复了 HTTP 503 JSON 错误在 Canonical 中变空、随后重试成功
仍因前次缺少 SSE 终态而被误判不完整的问题。现在只在 HTTP 400–599、非空合法错误、
原始字节与 SHA-256、转发长度、未截断及上游/客户端完成证据全部成立时，将前次记为
完整的失败尝试；不补造 SSE 终态。错误与后续成功按实际 Capture ID 独立保留。

最终新执行回归保留 2 Native Turn、12 次 HTTP 尝试、10 条实际工具结果和 14 个输出项目，
覆盖模型切换、HTTP 重试、实际重叠的并行工具、图片、合成 reasoning/commentary 及进程
resume。四种派生工具数据篡改均被门禁以真实退出 1 拒绝，诊断不展开正文。这些仍是带
补丁生产者和合成模型的 CI 协议证据；线上旧镜像、未修改客户端和真实 OSS 的缺口不变。
代码复核后的完整 `cloud-test` 实际退出 0：303 个 Rust 库测试、1 个 CLI 测试和
241 个 Node 测试通过；默认套件忽略的三项 RSS 用例仍须由独立 CI 门禁实际执行。

## 终态完整输出保真

进一步的新采集实际复现：Raw 终态有完整 `output`，Canonical 却被逐项事件的子集覆盖，
遗漏一个项目时旧检查仍返回 `delivery_ready=true`。修复后终态数组完整保留；没有数组的
Lite 终态沿用逐项事件重建。已完成正文冲突和缺失项目拒绝完整交付，added 占位补全
允许，工具调用的完成字节边界随实际完整内容到达的位置计算。

同一原始合成 Raw 只读回放从 14 个恢复为 15 个模型输出项目，其余 11 个模型交互、
10 条工具执行、Session 计数和来源审计完全不变，Raw SHA-256 不变。新双轮采集也实际
通过，三个新增定向 Rust 测试从修复前全部失败变为通过。这些是未部署的实现回归，
不证明线上、未修改生产者或真实 OSS 已达到交付标准。
本轮完整 `cloud-test` 实际退出 0：306 个 Rust 库测试、1 个 CLI 测试和 241 个 Node
测试通过；默认套件忽略的三项 RSS 用例继续由独立 CI 门禁执行。

## 新执行的取消与断连回归

隔离 patched App Server 实际完成三轮：收到文本 delta 后原生 `turn/interrupt`，下一轮
收到 delta 后实际断开 HTTP socket 并自动重试，再正常继续一轮。4 次 HTTP 尝试逐条保留，
3 个原生 Turn 均闭合，首轮为 `cancelled`；Interrupt Hook、四路来源、Raw 字节/哈希、
Canonical 引用和重启恢复均通过。两条部分响应没有被后续成功覆盖，整体完整交付检查
仍为 false。首轮测试曾因使用错误的 Hook 字段名退出 1；按实际 WAL 契约修正后退出 0，
原失败证据保留。这补充了原生取消/断流的协议 CI，模型仍为合成且生产者带补丁，不能
代替未修改客户端和线上真实任务验收，也没有改变线上部署。

## 既有隔离验证记录

20:16 后的资源回归复现了两个独立分配问题：Rust 先复制整个 Turn 再分配完整 JSON 行，
Node 即使跳过某个 Turn 也会拼接整行。旧 Rust 写入对同一份 200,000 条引用、
40,200,429 bytes 的合成 Turn 实测峰值 RSS 154,880 KiB，退出 101；流式修复后为
78,080 KiB，独立进程的 128 MiB 门禁实际执行一个测试并退出 0。规范字节、转义、
Unicode、空值、末尾换行配额和失败临时文件清理均有兼容回归。
旧 Node 在 32 MiB 堆限制下因页外巨大 Turn 耗尽堆而 SIGABRT；修复后同一份
80,400,833 bytes 合成文件可分页跳过首行，并经鉴权接口完整流式下载、校验 SHA-256，
页外损坏仍被拒绝。新接口为 `/v1/jobs/{id}/turns.jsonl`，SDK 为 `downloadTurns`。
这些是隔离元数据资源验证，不证明线上已升级、Rust 全 Session 投影内存有界，或生产
容量已验收。完整发布条件仍见文末；线上 runtime gate 本轮仍因 `stale_sources=wire`
实际退出 1。

本轮完整 `cloud-test` 实际退出 0：297 个 Rust 库测试通过，独立 RSS 测试在默认套件中
跳过、由专用门禁另行实际执行通过，另有 1 个 CLI 测试及平台/OSS 协议 59/59 通过。
M0 镜像自测退出 0；平台镜像在断网、只读、非 root、1 GiB 内存、2 CPU、256 PID、
禁用 capabilities 和 no-new-privileges 下也实际 59/59 通过。两镜像均为
`working-tree-turn-streaming` 的隔离构建。真实 patched Canary 的只读回放仍保留
2 Turn、8 次模型交互、6 条工具记录，同快照 Session、审计、场景及 Canonical parts
均未变，原始 SHA-256 不变；它仍不能代替未修改生产者或线上验收。

后续投影下载负对照又复现了整份 Manifest 在 Node 中解析造成的 OOM：规范形状的
80,407,694 bytes 合成文件在 32 MiB 堆限制下令旧实现 SIGABRT。新实现调用只读
`read-projection-manifest` 流式读取元数据，逐块校验全部 UTF-8、JSON 和 SHA-256，
再比对已记录的 Manifest 和投影元数据，最后从同一已校验文件句柄下载原字节。
相同用例现在实际通过，元数据冲突、页外 Turn 损坏以及匹配哈希的非法 UTF-8 均被拒绝。
Rust 独立合成读取实测峰值 25,600 KiB，低于 48 MiB 预算；CI 在两个独立进程中分别
执行 Turn writer 和 Manifest reader RSS 用例，要求每个用例确实执行一个测试。
本轮完整 `cloud-test` 实际退出 0：300 个 Rust 库测试、1 个 CLI 测试、平台/OSS 协议
60/60；两项 RSS 测试另行执行通过。M0 自测退出 0，受限平台容器也实际 60/60 通过。
镜像为 `working-tree-projection-manifest` 的隔离构建。真实 patched Raw 还通过正常
平台任务完成 FS 归档、恢复、检查、完整 Turn 与全部四个投影文件下载，以及重启复验；
2 Turn、8 次模型交互、6 条工具记录、审计、场景和 Canonical parts 保持不变，
11,974,944 bytes 原始 Raw 的 SHA-256 不变，临时回放副本已清理。这不代替真实 OSS、
未修改生产者或 Buyer 导出验收，也不证明 Rust 全 Session 投影内存已受限。

后续受限堆负对照还复现选中巨大 Turn 时的分页分配问题：约 80 MB 的单个选中 Turn
令旧 HTTP 服务在 32 MiB Node 堆限制下 SIGABRT，测试实际退出 1。分页现在保持原 JSON
字段，先用只读 `read-turn-page` 流式验证全部 JSONL/UTF-8 和哈希，再由 Node 在实际
下载句柄上复核全文件，将选中记录原字节分段写入响应。相同用例实际退出 0，分页
80,400,534 bytes 的字节数与 SHA-256 完整一致；CRLF、末尾无换行、空页、文件替换、
取消读取和匹配记录哈希的非法 UTF-8/JSON 均有拒绝或兼容回归。独立 Rust 合成读取
峰值 RSS 24,576 KiB，低于 48 MiB 预算；CI 在三个独立进程中执行 writer、Manifest
reader 和 Turn page reader。SDK 新增 `streamTurns`；`getTurns` 对象 API 仍由调用者
容纳完整选中数据。每页仍有全文件语法校验和哈希扫描，Rust 全 Session 投影与验收的
内存、持久索引和真实生产容量尚未解决；本修复也未部署到线上。
本轮完整 `cloud-test` 实际退出 0：301 个 Rust 库测试、1 个 CLI 测试、平台/OSS 协议
60/60；三项 RSS 用例另行执行通过。M0 自测与受限平台容器 60/60 也实际退出 0，
镜像标记为 `working-tree-turn-pages`。真实 patched Raw 经正常 HTTP/SDK 任务重放后仍
保留 2 Turn、8 模型交互、6 工具记录及原 Session/审计/场景/Canonical parts；原始
11,974,944 bytes Raw SHA-256 不变。该回放使用临时 FS 对象后端，未修改线上数据。

代码侧本轮复现并修正 Canary 的声明式误通过：旧门禁仅凭四个场景标签，即使只有一个
Session epoch、零工具执行也接受。新门禁要求同快照引擎生成的具体事件证据，真实
patched Raw 回放保留 2 Turn、8 模型交互、6 工具记录、3621 审计记录和不变的 Raw 哈希。
这些改进强化验收，尚未部署到线上；未修改客户端与真实 OSS 的发布条件继续保留。

后续合成故障回归还复现了同一原生工具调用的矛盾载荷被折叠后误报可交付：参数和输出
分别变更时，旧平台检查都返回 `delivery_ready=true`。新版投影对同作用域/call_id 的多个
`codex.tool_result` 比较参数与输出，冲突保留 Raw 引用并阻止交付。检查只借用已有载荷，
不保留第二份序列化正文；相同 JSON 参数的格式差异和独立 Hook 视图不误判为冲突。
该负对照是隔离合成故障，不说明线上已经出现此类矛盾；历史 Raw 需重新检查，旧的通过
产物不能自动视为已覆盖新校验。CI 保留宿主和容器平台回归的完整 TAP。

进一步的隔离负对照还确认，原生结果的截断或未知完整性标记可被同调用后到的完整标记
掩盖：参数与正文完全一致时，旧平台仍会误报 `delivery_ready=true`。新版 Runtime 汇总
每条原生结果的质量证据，任一不完整观察都阻止交付，不受到达顺序影响；Hook 视图保持
独立。CI 的真实 CLI/平台回归覆盖两类质量缺口的两种顺序、分页状态、Raw 引用及 Buyer
导出拒绝。这是合成故障回归，不能据此断言线上存在相同损坏或已加载修复。
该修复的本地 `cloud-test` 已实际退出 0：295 个 Rust 库测试、1 个 CLI 测试，平台与 OSS
协议回归 54/54；真实 patched Canary 只读重放仍保留 2 Turn、8 模型交互和 6 工具记录，
Session、审计、场景证据和完整性结果均未变，Raw SHA-256 前后一致。CI 的平台容器回归
增加 1 GiB 内存、2 CPU、256 PID、禁用 capabilities 和 no-new-privileges 约束；这是小
fixture 的资源限制回归，不是生产容量证明。

平台规模负对照还复现了“分页前先传输完整 Turn”的问题：合法元数据在较小 stdout 配额
下使旧检查任务以 `OUTPUT_LIMIT` 失败。新的平台检查格式直接写入校验后的 Turn JSONL，
stdout 与任务只保留摘要。隔离回归在 65,536 bytes JSON 上限下保留 447,426 bytes 的
5 Turn 文件，任务 JSON 为 3,108 bytes；页外损坏仍拒绝，旧规范文件可原样复用。
这是受控合成元数据回归，尚不是大归档容量测试或线上部署证明。Rust 的全 Session 投影、
投影 Manifest 下载解析和逐页全文件扫描仍需单独优化，不能据此宣称整体内存已受限。
本地完整 `cloud-test` 实际退出 0，包含 296 个 Rust 库测试、1 个 CLI 测试和平台/OSS 协议
56/56。真实 patched Canary 的同快照 Turn、审计、场景证据与 Canonical parts 均未变，
原始 SHA-256 不变；精简报告为 6,118 bytes，完整 2 Turn 文件为 3,975 bytes。该证据仍
不能代替未修改生产者、目标 OSS 或线上服务验收。
同一工作树的平台镜像在断网、只读、非 root、1 GiB 内存、2 CPU、256 PID、禁用
capabilities 和 no-new-privileges 下执行平台/OSS 协议测试，实际退出 0、56/56 通过。
镜像 revision 标记为 `working-tree-platform-turn-report`，未作为生产镜像发布。

后续导出负对照又复现相同的 stdout 瓶颈：合法合成 Session 在完整验收后因报告超过
65,536 bytes 被平台终止，测试实际退出 1。新的 `chiptrace.platform-acceptance.v1` 在
首次导出、重启恢复和每次下载前仍执行完整复验，将同一份完整 Turn 元数据持久化到
sidecar，stdout 只返回验收摘要与校验描述。定向 HTTP/SDK 回归实际退出 0，保留
5 Native Turn、10 个采购有效轮次、分数 100；完整验收 Manifest 为 474,462 bytes，
Turn 文件为 447,426 bytes，报告为 4,099 bytes，任务 JSON 为 3,413 bytes。
恢复复用原 Manifest 和 Turn inode，采购包下载的字节/哈希一致，损坏后真实拒绝。
默认 CLI 输出和完整 v2 Manifest 保持原格式，精简报告不代替未修改生产者、真实 OSS
账号或线上验收，也不证明 Rust 验收内存已受限。
完整 `cloud-test` 随后实际退出 0：296 个 Rust 库测试、1 个 CLI 测试，平台/OSS 协议
57/57；隔离 M0 镜像 `working-tree-platform-export-report` 的断网、只读、非 root 自测
也实际退出 0。真实 patched Canary 只读回放仍保留原 Session、审计、场景和 Canonical
parts，2 Turn、8 模型交互、6 工具记录不变，Raw SHA-256 一致。
同一工作树的平台容器在前述 1 GiB/2 CPU/256 PID 限制下也实际退出 0，57/57 通过；
这是隔离协议和故障回归，不能据此确认生产容量或线上已完成升级。

## 当前部署证据

| 项目 | 实际观察 | 能证明的范围 |
| --- | --- | --- |
| 18084、3011、3012、18086 | HTTP 200 | 入口、采集进程和平台进程存活 |
| Collector/Relay/平台 | revision `30f6d243d527732acbfae4970a740ec88c8451cf`；镜像摘要已固定 | 当前服务运行维护提交；不替代真实 Turn 验收 |
| 投递 | 18:42 Collector Capture/Relay delivered 均为 1,164,002，pending/inflight/failed 均为 0，计数守恒 | 瞬时传输状态；不是持续 SLO 或完整 Session 数 |
| Collector 磁盘 | 约 72 GiB sealed Raw，挂载在共享 NFS；重启后继续增长 | WAL 持久保存；不能证明 OSS 已提交 |
| Wire | 当前进程内 4 条，成功逐 Turn HTTP 2xx 为 0，最后一条约 31.5 分钟前 | 没有近期真实成功 Turn Wire 的证据 |
| 来源新鲜度 | OTLP logs/traces 仍有新记录，Hook 最后记录约 5.5 分钟前，Wire 已过期约 31.5 分钟；覆盖 `degraded`；runtime gate 真实退出 1 | 当前采集覆盖降级 |
| 历史失败 | 293 个文件，267,219,223 bytes | 保留失败取证，不能删除换取健康状态 |
| 平台 18086 | FS 后端、鉴权列表请求 HTTP 200，当前无任务 | 在线入口可用；没有真实 OSS 导出证据 |
| 部署隔离 | 三个容器均为非 root、只读根、2 CPU、256 PID；Collector/Relay 8/12 GiB，平台 4 GiB | 运行边界已生效；尚缺容量、保留周期和告警验收 |
| GitHub CI | 已核验基线 `4e6c177`：[run 38826013418](https://github.com/XS-MLVP/ChipTrace/actions/runs/38826013418) 已确认成功；6/6 作业、17 份有效报告元数据 | 包括五场景新采集的 FS/S3 贯通、独立 RSS 门禁和官方原版拒绝诊断；使用带补丁生产者和合成模型，未下载报告正文；后续修复仍需对应提交的 CI |
| GitHub 集成 | 远端 main 仍为 `514d4cf`，公共分支 API 返回 `protected=false`；维护分支修复尚未合并 | 需设置评审和必需检查约束、完成同 SHA 验证及受控发布；分支 CI 不等于部署 |

11:26 复查时三个既有服务仍返回 HTTP 200，Relay 已投递 1,036,522 条，pending 为 1、
inflight/failed 为 0、计数守恒。持续流量下瞬时 pending 不能单独判定积压故障。
OTLP logs/traces 与 Hook 仍更新，Wire 仍只有 1 条，约 43 分钟未更新，覆盖仍为
`degraded`；18086 连接被拒绝。同一轮 runtime gate 真实退出 1，首个失败项为网关
`rustRelay.inflight must be zero`，该瞬时门禁结果不取代来源新鲜度或逐 Session 审计。

12:17 复查中入口与采集服务仍返回 HTTP 200，OTLP/Hook 继续流入，Wire 仍只有 1 条，
约 94 分钟未更新。runtime gate 实际退出 1，原因为
`relay.ingest_coverage.status must be complete (observed=degraded; missing_sources=none; stale_sources=wire)`；
18086 仍返回连接拒绝。Collector/Relay 仍是 `fe9fcf9`，未设置容器 CPU/内存上限，
根文件系统可写。WAL 所在共享 NFS 使用率为 57%，当时可用约 2.33 TB；可用空间
不替代项目配额、保留周期和恢复演练。

Wire 诊断只读取活动段打开时的固定长度快照：439,333,206 bytes、2,826 条完整记录、
1 条 Wire，没有复制或输出对话正文。它是故障定位证据，不是从 Segment 1 开始的完整
sealed Archive 验收。全局四源门禁在该 403 到达后曾短暂通过；该结果不构成业务采集
成功。runtime gate v2 已在仓库加入独立 Turn Wire 证据要求，线上旧镜像尚无该统计。

本轮 Process scope 冲突修复的 `make cloud-test` 实际退出 0，覆盖 fmt/Clippy、275 个 Rust 库测试、CLI、
网关、原生上下文、Canary/runtime 门禁及平台 HTTP/SDK 的归档、恢复、导出和 OSS 协议
回归。Rust 和 CLI 新增用例拒绝七类 Turn 业务事件直接或沿父链声明 Process scope 的
14 种组合；合法 Process 记录仍在真实 patched Raw 回放中保留，原始 SHA-256 不变。
此前的 runtime gate 回归覆盖单条、批量部分 ACK、重复、冲突、不可用和成功证据过期。
`make m0-test` 也实际退出 0：独立镜像 `chiptrace:m0-process-scope-canary` 在断网、只读
根文件系统及非 root 用户下完成自测；构建标记为 `working-tree-process-scope-guard`，未替换线上镜像。
这些隔离实现回归不改变上述线上、未修改生产者或真实 OSS 账号的验收状态。

后续只读回放又确认检查入口的误报：历史样本存在 2 条日志和 84 个 span 的未知 Session
身份，旧 `inspect-session` 顶层仍返回可交付。修复后检查入口复用同快照的来源审计，
完整状态为 false；完全没有身份的独立 OTLP batch 也逐批计入审计，正文不因此留在
Canonical 投影内存集合中。平台分页增加总交付状态，完整性不足的导出继续真实失败。
原始 Raw 与合格 patched Canary 均保留，回放前后哈希不变。线上尚未加载这些修复。
该检查修复的本地 `cloud-test` 已通过，包含 275 个 Rust 库测试、1 个 CLI 测试、
7 个原生上下文 CLI 测试和 7 个平台/OSS 协议测试。独立镜像
`chiptrace:m0-source-audit-canary` 的 `m0-test` 实际退出 0，构建标记为
`working-tree-source-audit-inspection`。历史任务重启后的缺少审计和状态与审计冲突用例也通过，
历史任务文件保持原样；这些实现回归不证明线上或真实 OSS 已验收。
本地复跑还记录过一次 outbox 测试 18/19 通过、`make` 退出 2；随后独立 outbox 回归
19/19 和完整 `cloud-test` 均通过，测试条件未放宽。原失败的断言细节未被当时的摘要
保留，原因尚未定位，需继续跟踪；后续摘要已保留失败测试名称和完整断言块。

后续内存回归发现，独立来源审计仍把选中 Session 的全部 Capture 正文留在内存，尽管
返回值只需要审计结果。修复后独立审计按条释放正文，投影和检查入口的行为保持原有要求。
同一份 134,337,249 bytes、514 条 Capture 的纯合成输入，在相同 debug CLI 两线程设置下：

| 测量 | 修复前 | 修复后 |
| --- | --- | --- |
| 峰值 RSS | 179,000 KiB | 42,212 KiB |
| 耗时 | 59.17 秒 | 59.94 秒 |

两次完整审计 JSON 完全一致，输入 SHA-256 均为
`0b1d367141031f1656fbac02718b5da35881c97af3cb536ee23054509e04cb91`，原始合成输入未变。
独立 release 门禁实测 22,508 KiB、1.90 秒，低于 96 MiB 预算；不能把该 release 结果
与 debug 基线混作直接对比。门禁已加入 GitHub CI，校验来源计数和输入哈希，只保存精简
合成元数据。该修复的本地 `cloud-test` 实际退出 0；精确身份索引仍随 Capture/Span
数量增长，这项测量不证明全量数据处理内存恒定或线上已完成大归档验收。
隔离镜像 `chiptrace:m0-audit-memory-canary` 的 `m0-test` 也实际退出 0，构建标记为
`working-tree-audit-payload-retention`；它在断网、只读根文件系统和非 root 用户下运行，
没有替换线上 Collector/Relay。

后续运维复查发现 ACK-only 备用用户服务仍被启用，累计重启 810,067 次，最近退出码 1，
日志为 723,461,901 bytes，末尾仍有 `Address already in use`。真实 18084 网关当时返回
200、`fullTraceCapture.enabled=true` 且传输健康。已停用备用服务、归档 unit 并重新加载
用户 systemd，复查为 `LoadState=not-found`、`ActiveState=inactive`、`MainPID=0`。
归档 unit 的 SHA-256 与原件相同，历史日志未删除；完整采集门禁仍因 Wire 过期退出 1。

同一轮真实执行模板负对照：`SessionStart` 收到 ACK-only 的 `HTTP 200 {}` 后退出 0，
没有返回停止结果。模板现已为九类 Hook 增加持久化确认校验，拒绝无效 JSON、非持久化、
错误来源、质量错误、计数冲突、超大响应、重定向和 HTTP 失败。定向配置与 Hook 回归
26/26 通过；隔离真实 Relay/Collector 保存九个生命周期事件的 18 条记录，重复的
SessionEnd 获得幂等确认且没有增加记录。未修改 Stock Codex 的断网受管配置回归也通过。
中断确认测试还复现过 curl 内部重试拼接残片、使后续有效确认误失败的问题；命令现已
按次独立读取确认，最多执行两次，同一原生事件字节不变。新的网络中断回归和最终
`make cloud-test` 均实际退出 0；完整测试日志保留，失败细节不会仅由摘要替代。
主机 `/etc/codex` 两个文件仍为 root 所有、当前用户不可写，新的 Hook 和 Provider 约束
尚需管理员部署。该回归不证明未修改客户端的真实多轮、线上 Wire 或目标 OSS 已验收。

12:55 的 runtime gate 再次实际退出 1，诊断为 `stale_sources=wire`。13:49 只读复查时，
18084、3011、3012 仍返回 HTTP 200，Collector/Relay 仍是 `fe9fcf9`；同一窗口已投递
1,045,024 条，pending/inflight/failed 为 0，计数守恒。Wire 仍只有 1 条，约 186 分钟
未更新，runtime gate 真实退出 1；18086 仍为 `ECONNREFUSED`。
同一轮容器瞬时内存为 Relay 1.726 GiB、Collector 113.5 MiB；容器未设置内存或 CPU
上限。该瞬时观测不是峰值容量或泄漏诊断。共享 NFS 使用率为 57%，没有因此证明项目
配额、保留策略或真实 OSS 归档已生效。两个 root 所有的受管配置文件仍为九月的修改时间；
已退役的 ACK-only unit 仍为 not-found/inactive。维护分支已有后续修复，但远端 main
仍为 `514d4cf`。这些结果表明代码、线上部署和可交付能力尚未闭合。

## 业务鉴权与客户端环境

同日后续接入排查进一步核对了业务鉴权边界：同一份已配置的 Codex 凭据用于共享
Provider 目录时返回 HTTP 200，用于 18084 `/models` 时返回 HTTP 401。18084 源码将
业务鉴权交给当前 Sub2API 上游验证；仅有另一个 Provider 的可用凭据，无法据此完成
这个入口的真实 Wire Canary。该检查只读取模型目录，未调用模型、未输出密钥或正文。
维护进程未设置 `CHIPTRACE_API_KEY`、`CHIPTRACE_INGEST_TOKEN` 和
`OTEL_EXPORTER_OTLP_HEADERS`；其他已运行进程的 OTLP/Hook 流量不能证明新进程已有
这些环境变量。当前唯一安装和 npm alpha 均仍是 `0.163.0-alpha.11`，状态与更新检查
均退出 0；没有已发现的新发行版本可以替代当前原生上下文缺口的验收。

管理员部署受管配置前，还需向目标新进程注入 18084 对应的授权业务凭据及采集凭据。
业务和采集凭据从本项目授权 Secret 或主机管理系统注入；共享 Provider 按主机策略
维护。真实 Alibaba OSS 和主平台身份接入的验收条件继续保留。

## 确认链路的隔离回归

后续检查定位到两层错误确认风险：Relay 对 Collector 的部分确认只检查 `ok/durable`，
网关也会仅凭这两个标志删除待投递文件。隔离负对照真实复现前者将无 Capture 明细的
确认记为 delivered（两项 Rust 测试失败、退出 101），后者错误排空队列（Node 退出 1）。
修复后 Collector 确认绑定 Capture ID、SHA-256、字节长度和状态；网关另验证当前请求的
input receipt，避免混淆输入 JSON 与规范化 WAL 的字节口径。无效确认保留 pending。

Rust 1.91 与 Node 22 的最终 `cloud-test` 实际退出 0，包含 281 个 Rust 库测试、33 个
网关测试及真实网关 outbox → Relay → Collector 联测。联测覆盖确认丢失、网关重启、
幂等重放、JSON/SSE 的 UTF-8 正文、两份 WAL 的字节与哈希一致及服务重启后恢复。
独立宿主网关健康检查也通过。联测首轮因断言使用网关字段名而失败，按实际 WAL 的
`requestBody.raw` 等字段修正后通过，失败日志与最终日志均保留。CI 新增
`rust-tests-report`、`gateway-receipt-report`，包括失败时的完整测试输出。
这些隔离回归没有升级线上进程、重新认证历史 delivered 账本或替代未修改客户端及真实
OSS 账号的生产验收；新版网关须在支持 input receipt 的 Relay 部署后启用。

## 2026-10-17 维护分支复查

提交 `1d3c492` 为历史失败 outbox 增加了内容绑定的 recovery receipt，并让重放副本使用
确定性的 `cap-replay-*` Capture ID；随后提交 `fbc09b5` 让部署预检拒绝跨服务重复的可写
bind source。两次提交均已推送到 `fix/oss-disk-session-platform`，工作区干净。

在线 18084、3011、3012 和 18086 的进程级健康检查均成功。18084 的历史 293 个失败原件
仍保留，293 个 receipt 均能按原文件 SHA-256 复核，`pending=0`、`processing=0`、
`unresolvedHistoricalFailedFiles=0`；这一结果证明传输恢复闭环，不证明新 Session/Turn 已
完成交付。

同一窗口的 runtime gate 仍真实退出 1：Relay 持久质量错误为 565（全部在 OTLP traces），
`stale_sources` 包含 `hooks` 和 `wire`，`turn_capture_ready=false`，最新 Wire 证据中只有
279/293 条具备 Turn 身份且已过新鲜度窗口。trace exporter 仍未配置，watchdog 的上游请求
仍返回 403；真实 Alibaba OSS、未修改生产者和远端 Actions 结果仍未验收。当前服务可用于
内部传输和恢复验证，不能据此签发生产交付结论。

## 2026-10-18 质量标签与 CI 启动修复

提交 `f3b5459531683e72046f5f4a07965ceaf0059af8` 已推送到
`fix/oss-disk-session-platform`，工作区保持干净。它为 OTLP/Hook 质量错误增加固定、脱敏的
原因码（`unsupported_event`、`invalid_structure`、`invalid_attributes`、`identity_conflict`、
`missing_identity`、`invalid_tool`、`invalid_lifecycle`、`invalid_timestamp`、`conversion_error`），
并把端点原因计数持久化到 Relay 账本；旧账本无法回溯时只归入
`legacy_unclassified`。原始 telemetry 重验会重新计算原因码，原因总数必须与端点和全局质量错误
守恒，运行门禁会拒绝缺失、未知或不一致的原因分解。GitHub Actions 的普通手工启动不再要求
生产 `expected_revision`；启用受保护 live preflight 时仍强制完整 SHA。该提交的本地
`make cloud-test` 真实退出 0，Rust 格式、检查和 Clippy 也通过。随后对线上 sealed Raw 的有界抽样
确认样本中的 traces 质量错误全部来自重复 `code.file.path` / `code.line.number` 源码定位元数据；维护提交
`f3b5459531683e72046f5f4a07965ceaf0059af8` 仅放行这类不参与身份解释的 trace 属性，身份、工具和未知
字段仍 fail-closed，并增加 Rust 回归覆盖。

同日 17:48（Asia/Shanghai）对热服务的只读门禁仍真实退出 1：18084、3011、3012、18086 均返回
HTTP 200，但 Relay/Collector 仍为旧 revision `e5237065ff3a48623179c5846ff1916040030c9a`，
`quality_errors=1581`、`quality_errors_by_endpoint.*.reasons` 缺失，Wire `279/293` 条具备 Turn
身份但已约 38.4 小时未刷新，`turn_capture_ready=false`；平台 `/health` 没有
`build.revision`。因此本提交尚未在线生效，服务仍未达到真实生产发布标准。远端 Actions API
本次连接超时、CLI 未认证，不能把本地绿色结果当作同 SHA 的远端 CI 结论。

随后提交 `73f75b9c6d4d615c524970560310f5a58b9746a7` 将实际 Codex 路由检查加入受保护的
`live-provider-runtime-preflight`：作业现在必须读取指定 Canary 配置文件，并在 Provider 探针前
确认 Responses、OTLP logs 和 OTLP traces 同时指向受管 Gateway；路由诊断不输出配置正文或凭据。
相关契约测试通过并已推送，但尚未替代管理员对现有用户级配置的切换，也没有改变当前线上 Wire 缺失的事实。

提交 `785e582` 进一步让 Runtime gate 在保持真实非零退出的同时，把所有固定、脱敏的
`blocking_reasons` 追加到标准错误；当前线上复核因此可以一次看到质量、来源新鲜度和 Turn 证据的全部阻断项，
而不是只看到第一个失败检查。24 个 Runtime gate 回归通过；真实线上 gate 仍按预期非零退出并输出完整诊断。

提交 `ba0600a` 修正 hosted Runner 的原生沙箱启动流程：内核 sysctl 写入失败只产生明确警告，
真正的 user namespace 探针仍是硬门禁，避免平台权限差异把 CI 误报为启动失败，也不会把不可用沙箱放行。

## 2026-10-18 22:14 线上只读复核

最新只读快照中 18084、3011、3012 和 18086 均返回 HTTP 200。Collector 与 Relay 使用同一
revision `7f5abad42fff171fd80f024bb0f03c2ae6de52b6`，捕获/投递计数均为 `1,239,955`，队列为 0，
`conservation_ok=true`；Platform 也报告同一 revision，队列和运行任务均为 0。18084 的完整正文捕获
仍启用，Gateway outbox 当前 pending/processing/recent failure 均为 0，293 个历史失败原件和
293 个恢复回执仍保留，未解决历史失败为 0；这证明传输与恢复闭环，不证明业务 Turn 已采集。

业务覆盖仍为 `degraded`：Relay 持久 `quality_errors=2905`（当前进程新增 659），全部来自
`otlp_traces`，原因是 `identity_conflict=182`、`invalid_lifecycle=758`、
`legacy_unclassified=1965`；`wire` 同时列入 `missing_sources` 和 `stale_sources`，
`successful_turn_scoped_captures=0`，`turn_capture_ready=false`。Gateway 的
`fullTraceCapture.stats.acceptedCount=0`，其 OCI revision `e57480eca4fe11769c5fcb8787266ab6b77ce4d5`
也未与维护分支 revision 对齐。带 `--max-quality-errors 0` 和历史失败门槛运行的 runtime gate
真实退出 1，阻断项包含质量错误、来源缺失/过期、Turn 未就绪和无成功逐 Turn Wire。

当前工作树上的完整 `make cloud-test` 已真实退出 0，包含 Rust/Node、Raw/WAL、确认回执、Session/Turn、
标签质量、平台 FS/OSS 适配、大对象内存和部署配置回归。该结果证明代码和离线契约稳定，不能替代
受管 Provider 路由、未修改 Stock Codex 多轮 Canary、真实 OSS 账号和远端 Actions 结果。

同日 release 构建的本地性能基线为：Collector WAL 在 `fsync=true`、64 KiB 记录下约
`3,629 records/s`（`226.8 MiB/s`）；loopback HTTP 批量入口（并发 16、每批 64 条）约
`3,690 records/s`（`230.6 MiB/s`），批延迟 p95 `297.8 ms`；四路 zstd level 1 输出约
`477.3 MiB/s` 未压缩输入、`363.9 MiB/s` 压缩输出。以上基准明确排除 Relay、Session 组装、OSS
上传和对象存储，不能直接换算成生产容量；后续容量门禁应在目标硬件、真实 Relay 和对象存储路径上重测。

当前提交 `5038dd7` 还按 CI 的容器路径完成了本机启动烟测：runtime 镜像构建后在隔离网络中运行
`self-test`，返回 `ok=true`、`delivery_ready=true`、Buyer 分数 `100` 且所有检查通过；platform
镜像在只读根文件系统、非 root `10001:10001`、独立 tmpfs 数据目录下启动，`/health` 返回 200，
并报告同一 revision。该证据覆盖镜像入口和启动契约，不代表现有线上 Gateway 已升级。

同一组镜像运行 `scripts/ci/deployment-smoke.js` 也通过：三容器 Compose 的镜像/资源/隔离约束、
鉴权、Raw/WAL 精确字节与重复投递、实际 Collector/Relay runtime gate、Session/Turn 分页与导出、
重启后的任务和包哈希恢复，以及重启后要求新的来源证据均通过，临时服务和网络已清理。报告的
`synthetic=true`、`real_upstream=false`、`real_oss_account=false` 和
`production_acceptance_claimed=false` 保留了证据边界。

## 2026-10-19 00:06 性能与容量复核

同一 release 构建在本机重新执行了带 `fsync` 的 64 KiB 基准：单 shard Collector WAL 为
`3,283 records/s`（`205.2 MiB/s`，100,000 条）；loopback HTTP 入口（并发 16、每批 64 条）为
`3,747 records/s`（`234.2 MiB/s`），批延迟 p95 `279.0 ms`、p99 `329.1 ms`；四路 zstd level 1
为 `442.1 MiB/s` 未压缩输入、`337.1 MiB/s` 压缩输出，压缩比 `1.312`。这些数字只覆盖本地
WAL、HTTP 和压缩路径。

带 Relay 的同一 HTTP 压测入口为 `895 records/s`（`55.9 MiB/s`）端到端，入口确认仍为
`3,508 records/s`，异步排空耗时 `8.32 s`，重试 `0`；排空期间有 `613/695` 次健康轮询处于
背压 `503`，最终 `delivered=10,000`、`pending/inflight/failed=0` 且计数守恒。压测载荷没有原生
Session/Turn 身份，不能用于业务就绪或生产 SLO；它说明 Relay 背压会保留 Raw 并最终排空，但
真实对象存储上传和多租户并发仍需单独测量。

随后针对 Relay 交付热路径做了一个受内存预算约束的并行度修复：正文读取不再固定为每个 worker
四路，而是随 `delivery_concurrency` 在 4 到 16 之间调整；原有字节信号量继续限制所有 worker
的总驻留正文，不改变 Capture、回执、重试或计数语义。相同参数（release、10,000 条、64 KiB、
批量 64、并发 16、4 shard、`fsync`）的本机配对基准，修改前端到端为 `1,108.7 records/s`、
排空 `6.88 s`，修改后两次为 `1,238.0` 和 `1,240.4 records/s`、排空约 `5.72 s`；两次均
10,000/10,000 delivered、零重试、计数守恒。该结果是本机 Relay/WAL 对照，不代表真实 OSS
容量或生产 SLO；仍需在目标硬件和对象存储路径重测。

线上 Collector 在同一只读窗口报告 `sealed_bytes=109,736,469,031`（约 102.2 GiB）、827 个
sealed Segment；宿主根分区约 91% 使用率，NFS 约 58%。当前没有达到可长期运行的容量证明，必须
先建立保留/归档策略、磁盘余量告警和对象存储提交，再增加采集流量。

## 2026-10-18 22:14 质量标签根因抽样

对最新活动 Segment 尾部最多 200 条记录做了有界脱敏摘要：共看到 162 个 telemetry batch，
其中 77 个来自 `otlp_traces`；12 条转换错误具有相同的固定诊断，均为同一 OTLP span 重复声明
冲突的 `outcome` 属性。该批次的取样值类别为 `completed`、`exited` 和 `interrupted`。这与
`invalid_lifecycle` 的 758 条线上计数相符，且与仓库第七个生产者补丁
`docs/upstream-otlp-outcome.patch` 的修复目标一致：声明字段先为空，终态只记录一次，取消路径
才补写 `interrupted`。因此当前解析器保持冲突即拒绝是数据正确性要求；放宽重复属性校验会把
不确定的终态伪装成有效标签。生产修复应部署包含该补丁的受管 Producer，并重新通过逐 Turn 四源门禁。

## 已有优势

- Wire、OTLP logs、OTLP traces 和 Hook 按原生身份精确关联，覆盖请求、工具定义、
  工具真实输出、进程失败、异步工具与 Session/Turn 生命周期；不按时间猜轮次。
- 网关磁盘 outbox、Relay/Collector WAL、幂等和计数守恒提供可追溯的 ACK；失败与未完成
  事实继续保存。用户主机不需要运行 ChipTrace 服务。
- sealed Segment、SHA-256、Manifest 和最后提交的 Checkpoint 支持可校验归档与磁盘恢复。
  FS、S3 和 OSS 走统一适配层；真实目标账号仍需独立验收。
- `cloud-acceptance` 将字节完整性、协议终态、工具配对、逐 Turn 来源与 Buyer 门槛分别
  检查；旧产物和带补丁的 Canary 不能自动成为当前生产验收证据。
- 云平台插件已有任务落盘、重启重排队、Session/Turn 分页、交互投影及校验后下载接口。
  它适合作为主平台后端组件，终端用户鉴权与租户授权由主平台负责。

## 迭代顺序与发布条件

| 优先级 | 工作 | 完成证据 |
| --- | --- | --- |
| P0 | 注入目标业务与采集凭据，应用受管 Provider 路由约束，恢复真实 Wire | 新客户端普通任务经 18084；Wire 含原生 Session/Turn；新 runtime gate 通过 |
| P0 | 获得符合 v2 上下文契约的未修改生产者版本 | 真实第二轮、resume、失败工具及延迟 `write_stdin`；`unscoped=0`；`--require-unmodified-stock` 通过 |
| P0 | 在目标 OSS 账号验收存储、恢复与交付 | 连续 sealed Archive 上传、Checkpoint、逐对象校验、恢复、损坏拒绝、Buyer 包下载复验 |
| P0 | 发布平台服务 | 18086/API 可访问；通过主平台身份鉴权完成一次真实采集到导出下载 |
| P1 | 固定发布与回滚流程 | 对应 SHA 的远端 CI 全绿；同 revision 镜像；隔离 Canary、升级、重启与回滚复验 |
| P1 | 容量、告警与恢复演练 | 明确峰值、保留周期、云端临时磁盘配额、积压告警与恢复时间/数据损失目标，并实测故障恢复 |
| P1 | 企业数据治理 | 项目命名空间、主平台租户授权、访问审计、脱敏策略与下载确认后的保留/删除规则验收 |
| P2 | 大数据量处理 | 为 Session/Turn 建持久索引；消除每页仍需的全 sidecar 扫描，记录大归档内存/时间/磁盘指标 |

未修改 Stock Codex 的当前多轮生产验收仍缺证据；已有来源上下文补丁的隔离 Canary
证明修复方向可行，但不能替代该条件。受管路由模板也尚未应用到系统配置。
纯云端采集无法恢复客户端未发送成功的事件：运行中断网造成缺失时，应保留 partial 状态，
按原生重试能力恢复，不能补造记录或承诺任意网络条件下绝不丢失。

发布必须同时通过运行状态、原生生产者、真实存储账号、逐 Session 验收和平台交付验证。
新 runtime gate 的 HTTP 2xx 只证明有归属的请求获得 HTTP 成功状态，仍输出
`session_delivery_claimed=false`。完整规范与命令见[验收矩阵](acceptance-matrix.md)、
[运维说明](operations.md)和[平台维护流程](platform-maintenance.md)。
