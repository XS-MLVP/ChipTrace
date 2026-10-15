# 生产就绪评估

评估日期：2026-10-16。最新线上只读快照为 03:15（Asia/Shanghai）；文内较早实验保留各自时间与验证范围。
结论：具备可靠采集与离线验收的基础，可开展受控试用；当前部署尚未达到向他人承诺
原生 Turn 全量采集、远端持久保存和在线导出的发布条件。

03:14 的本机回环只读快照中，18084、3011、3012 均返回 200，Collector/Relay 仍为 `fe9fcf9`；
Relay 累计投递 1,100,490，pending/inflight/failed 均为 0，计数守恒。
这只是瞬时队列状态，不构成持续 SLO 或完整 Session 的证明。Wire 仍只有 1 条且已约
16.5 小时未更新，覆盖为
`degraded`；18086 连接拒绝，runtime gate 实际因 `stale_sources=wire` 退出 1。
模型探针最后可用时间仍为 10 月 8 日，网关 trace exporter 未启用。
03:15 Collector 累计保存 1,100,521 条 Capture；741 个 sealed Segment 共 87,431,090,167 bytes
保存在共享 NFS；此观测不证明已提交目标 OSS。当前状态应区分为传输进程存活、完整
业务链路未验收和在线交付入口不可用。

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
| 18084、3011、3012 | HTTP 200 | 入口与采集进程存活 |
| Collector/Relay | revision `fe9fcf924b226099202cb770b7cf0da29e0c2310` | 运行版本已固定；仓库新增修复尚未部署 |
| 投递 | 03:14 已投递 1,100,490 条，pending/inflight/failed 均为 0，计数守恒 | 该快照队列排空；不是持续 SLO 或完整 Session 数 |
| Collector 磁盘 | 03:15 有 741 个 sealed Segment，87,431,090,167 bytes | 云端共享 NFS 上的 WAL 持续保存；不能证明 OSS 已提交 |
| Wire | 新进程内仅 1 条；活动 WAL 中为无原生 Session/Turn 的 HTTP 403 | 无真实成功 Turn Wire 的证据 |
| 来源新鲜度 | 03:14 OTLP/Hook 有流量，Wire 约 16.5 小时未更新；runtime gate 仍实际因 Wire 过期退出 1 | 当前采集覆盖降级 |
| 历史失败 | 293 个文件，267,219,223 bytes | 保留失败取证，不能删除换取健康状态 |
| 平台 18086 | 无法连接 | 当前无法交接在线管理、导出入口 |
| 部署隔离 | Relay 要求 ingest token；Collector/Relay 绑定 loopback；两容器有重启策略 | 有内部入口保护；两容器尚无内存/CPU 上限或只读根文件系统 |
| GitHub CI | 已核验基线 `06086cd`：[run 38788773961](https://github.com/XS-MLVP/ChipTrace/actions/runs/38788773961) 已确认成功；5/5 作业、16 份正大小报告元数据均未过期、带 SHA-256 | 包含完整终态输出保真、图片、五类真实工具、双轮 resume、HTTP 重试、模型切换、实际并行、原生取消与断连继续；使用带补丁生产者和合成模型，未下载报告正文；本轮平台修复仍需独立提交后核验 CI |
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
| P2 | 大数据量处理 | 为 Session/Turn 建持久索引；减少两遍 Raw 扫描及分页 sidecar 重扫，记录大归档内存/时间/磁盘指标 |

未修改 Stock Codex 的当前多轮生产验收仍缺证据；已有来源上下文补丁的隔离 Canary
证明修复方向可行，但不能替代该条件。受管路由模板也尚未应用到系统配置。
纯云端采集无法恢复客户端未发送成功的事件：运行中断网造成缺失时，应保留 partial 状态，
按原生重试能力恢复，不能补造记录或承诺任意网络条件下绝不丢失。

发布必须同时通过运行状态、原生生产者、真实存储账号、逐 Session 验收和平台交付验证。
新 runtime gate 的 HTTP 2xx 只证明有归属的请求获得 HTTP 成功状态，仍输出
`session_delivery_claimed=false`。完整规范与命令见[验收矩阵](acceptance-matrix.md)、
[运维说明](operations.md)和[平台维护流程](platform-maintenance.md)。
