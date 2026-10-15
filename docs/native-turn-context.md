# 原生 Turn 上下文缺口与修复验收

当前 v2 交付要求完整的原生 Turn 身份、四路来源、闭合边界和零未归属业务记录。
目前已实现精确关联和拒绝不完整交付，但真实 Stock Codex 仍有来源上下文缺口。
上线、完整交付或新客户端版本支持均需重新完成真实验收。

## 官方正式版的独立上下文诊断

`stock-release-context` CI 作业安装
[stock-release.json](../integrations/codex/stock-release.json) 固定的官方 npm Linux x64 二进制，
另检出对应 commit 并核对完整源码摘要、干净 Git 状态和 ELF SHA-256。它不会更换
原有六补丁生产者、终端 CLI 或正向交付门槛。源码 tag 与 npm 包身份分别核验；这不是
下载二进制的可复现构建证明。

`CHIPTRACE_PROTOCOL_MODE=unmodified_stock` 使共享 fixture 通过系统 Bubblewrap 启动
普通 `codex --strict-config app-server`，不传 debug-only 启动参数。根文件系统只读，
本次临时目录可写，私有 `/tmp` 仅映射到该目录下新建的沙箱工作目录；私有 `/etc`
仅绑定必要的公开 OS 文件和本次 config/requirements，
最后重新挂为只读；宿主没有 `/etc/codex` 也能运行，不读取或改写宿主 Provider 配置。

远端首次运行在第一个 shell 工具失败，实际错误为构建 Bubblewrap 命令时遇到只读
文件系统。上游 `codex-uds` 在 `/tmp/codex-daemon-<uid>` 准备受保护的 socket 目录，
不使用 TMPDIR；本机此前已有目录，空白 CI 主机没有。将 `/tmp` 隔离为空白只读目录后
本地也复现同一失败；fixture 现提供私有可写 `/tmp`，保留原生工具沙箱和所有断言，
也不再暴露宿主已有 daemon 目录。失败运行和诊断保留，不以预创建宿主目录或关闭沙箱
换取通过。

```bash
CHIPTRACE_PROTOCOL_PRODUCER=/absolute/path/to/official/codex \
CHIPTRACE_PROTOCOL_SOURCE=/absolute/path/to/clean/stable-checkout \
  bash scripts/ci/qualify-stock-release.sh /private/new-qualification-directory
```

输出目录必须不存在，脚本以 0700 创建，避免复用上次报告。它运行同模型双轮正向
测试；保留真实测试退出码，在原有 `delivery_ready=true` 断言之前排他写入
`chiptrace.stock-release-qualification.v1` 元数据。模型响应仍是本地合成；未修改客户端
不能把合成模型实验变为生产验收。后面的 Buyer 下载和重启检查在该断言失败后不执行。

正式版 0.163.0 两次本地新采集均完成 2 个 Native Turn、12 次 HTTP 尝试、10 条真实工具
结果，整体交付均被拒绝。首次为 399 条未归属 Turn、151 条未知 Session span；仓库
新入口复验为 422 和 153。全部分类计数守恒；缺口包括没有 Trace/Span 的 SSE 日志和
缺少来源端 Session/Process scope 的初始化、配置、文件与生命周期 span。完整协议和
四源存在不足以证明所有业务记录均能精确归属。

外层 `stock-release-gate.js` 只验证这一明确的已知拒绝：实际子测试必须退出 1，完整
双轮/epoch、HTTP/工具、四源和协议/Runtime 证据均须成立，来源计数守恒且确有缺口。
启动/工具失败、超时、缺少或超过 16 KiB 的报告、错误二进制/源码以及意外交付成功
都不能让作业通过。诊断输出固定声明 `delivery_ready=false`、`production_ready=false`、
`real_upstream=false`，并保留 `collection_exit_code=1`。未来候选版本须重新固定身份、
执行资格验证，再通过真实上游生产 Canary；不能以诊断作业绿色替代生产准入。

GitHub 只上传精简计数/身份/哈希报告和本次测试日志；Raw、模型正文、工具正文及完整
Session/Turn 不上传。正向的 patched 五场景仍独立执行，原有所有验收断言保持不变。

## 每次 CI 新执行的协议采集

当前修复生产者与官方原版诊断统一固定
[`stock-release.json`](../integrations/codex/stock-release.json) 的正式版 `0.163.0`，
upstream commit 为 `83086188ae0614bd882818ff1aa23f3194962012`。
`upstream-context` 在该源码应用完整六补丁并构建 CLI；`stock-release-context` 使用同一
源码对应的官方未修改 ELF。修复版的来源报告仍明确保留补丁列表和源码摘要，不能通过
未修改客户端门禁。受管路由配置回归也使用同一正式版；下文 alpha Canary 是历史证据。
源码、外部依赖和 API 行为均须重新验证，不能从旧 alpha 的通过结果推导正式版通过。

`upstream-context` 除生产者单元测试和 CLI 构建外，还以 `patched_stock_cli` 模式运行
[protocol-collection.test.js](../integrations/codex/protocol-collection.test.js)。完整 CLI 通过
正常 `app-server` 入口启动，保留插件启动任务；私有 user/PID/mount namespace 提供只读根、
私有 `/etc` 和 `/tmp`，与官方原版诊断使用同一隔离路径。它使用临时
受管配置、本地确定性 Responses 服务、真实工具、当前 Relay/Collector 和原生 OTLP/Hook；
不读取宿主客户端配置或模型凭据。先更新计划、读取隔离线程的实际空 Goal，用
`view_image` 打开仓库 PNG，再执行 README 读取、故意 exit 7 和 sleep/write_stdin。
关闭客户端并启动新进程实际 resume 后，必须仍能读取第一轮的图片和工具结果；第二轮
保留 exit 9 并完成计划。异步轮询只能使用第一次工具输出中的真实 process session ID。
第一轮保留仓库默认 Responses Lite 模式；第二轮通过本次临时模型目录将另一模型切到
普通 Responses 模式。先返回真实 HTTP 503，再由客户端自行重试，随后在一个响应中
发出两个只读 shell 调用。两个原生执行区间必须实际重叠。模型名称和轮次均与实际
Wire 比对，不能在 Lite 请求明确禁用并行时发送并行调用来宣称验证成功。
计划工具只在临时测试配置显式启用；每次调用还检查真实请求的 `tools` 或
`input[].additional_tools` 声明，不能靠模型服务返回一个未注册的工具调用制造成功。

检查直接来自本次 Collector Raw：原生 Session/Turn 身份、四源覆盖、来源计数守恒、闭合
边界、失败/异步场景见证及 Wire 请求/响应正文哈希。Relay/Collector 重启后还须得到完全
相同的 Session 检查结果和原始 Segment 哈希。工作流保留 `native-protocol-ci.tap` 和
`chiptrace.native-protocol-ci.v1` 元数据报告，不上传 Raw 或对话正文。

五场景还将各自的同一份 sealed Raw 分别经过 FS 和私有 MinIO S3 的平台 HTTP/SDK。
S3 路径独立读取远端 Checkpoint、Manifest 和每个 Segment 对象，校验提交状态、原始
字节/哈希及规范化分片路径，再完成磁盘恢复、完整 Turn/投影下载、重启和相同的导出
准入。归档路径按协议规范化，不能直接与 Collector 的扁平目录路径比较。
每份报告在 `platform_evidence.additional_storage_backends` 中保存 S3 结果及实际 MinIO
二进制摘要；正向导出还保存实际下载的完整 Session JSONL 字节数/哈希，要求两后端及
重启前后相同。CI 要求五份均有 S3 证据。服务仅监听私有回环端口，使用本次临时凭据和
目录，不读取宿主云凭据。真实模型、真实 OSS 账号及租户授权仍需独立生产验收。

图片验证比较实际 inline PNG 的完整字节数和 SHA-256，包括新进程 resume 后的请求以及
Canonical 交互投影；不能只检查图片占位文字。五类工具的每次实际调用都须有唯一原生
`codex.tool_result`、精确 Raw 引用、完整 Tool Schema 和 Canonical RuntimeSpan；其 Turn
归属与发出调用时实际 Wire 的原生 ID 比较。原生日志可通过精确 Trace 父链继承 Turn，
不要求每条日志重复相同字段。报告只保存工具类型、完整性结论、图片长度与哈希。
全部模型输入须与实际保存的 Wire JSON 相等，全部输出项目（包含两轮最终文本）须与
本次 Responses 返回的项目相等；交互和工具的条数均以实际执行为准。完整正文仍参与
严格比较，但失败断言只报告不一致的输入或输出类别，不展开正文或 inline 图片。
每个 RuntimeSpan 的参数、结果、错误和进程状态还须与对应原生 Raw 逐项相等；参数再与
实际发出的模型调用比较，完整 Schema 与本次请求中的工具声明比较。exit 7 和 exit 9
都必须保留进程失败语义，不能用工具调度成功替代实际进程结果。
一个响应可含多个项目，包括合成 reasoning、多个工具调用和带 commentary 阶段的
助手消息。Canonical 必须保留全部实际项目及顺序；新进程 resume 后还须保留合成的
opaque reasoning、summary、commentary 阶段及图片。报告只记录元数据和完整性结论。
503 与后续 200 必须各有独立 Capture/交互，保持同一原生 Turn 和输入历史；相同请求
正文不能使失败尝试被折叠。完整 JSON 错误正文须保留，失败不能被后续成功覆盖。
服务还在实际终态 `output` 中返回一个没有独立 `output_item.done` 的项目，必须从
Collector Raw 的终态复核其完整数组，并与 Canonical 全部项目逐项、按顺序比较。
报告的 `terminal_output_evidence` 只保存验证结论及这类项目的数量，不包含正文。
四类终态、added 占位补全、矛盾已完成项目和工具调用字节边界另有 Rust 回归。

同一 CI 步骤还顺序执行
[protocol-interruption.test.js](../integrations/codex/protocol-interruption.test.js)。它新建隔离
Session：首轮等待 App Server 实际收到文本 delta 后，用真实 threadId/turnId 调用
`turn/interrupt`，必须观察到 `turn/completed.status=interrupted`、实际响应连接关闭和
带原生 Turn 的 Interrupt Hook；第二轮也先确认 delta 到达，再实际断开服务端 socket，
由客户端自行重试，两个 HTTP 尝试保持同一原生 Turn；第三轮正常继续。
四次请求各有独立 Capture 和 Canonical 交互，逐次校验实际前缀的字节、SHA-256、关闭
位置和未出现协议终态的事实。所有来源按原生身份归属且计数守恒；两条部分响应不得因
后续成功而变完整，整体 `delivery_ready=false`。Relay/Collector 重启后复验投影和 Raw。
工作流在既有 artifact 中另保存 `chiptrace.native-interruption-ci.v1` 元数据报告；该测试
与正常完整 Session 的正向门禁分开断言，不放宽交付条件。两组测试共享隔离配置与固定
生产者身份检查，不共享原生 Session 或采集目录。

取消回归还把本次新采集的同一份 Raw 经正常平台 HTTP/SDK 完成 FS 归档、磁盘恢复、
检查、Turn 与全部交互投影下载及重启复验。原始 Segment、Turn 和全部投影 part 的
字节/哈希必须一致，未鉴权下载返回 401。usage 使用这次实际返回的独立请求 ID；
Buyer 导出必须真实退出 1，明确拒绝 `protocol_complete=false`。仅将新生成的派生任务
顶层 ready 标记改为 true 后，任务查询、重复提交、嵌入式分页和 HTTP 分页仍须返回
不可交付，历史任务文件和失败记录原字节保持不变。报告的 `platform_evidence` 声明后端为 FS、
`real_oss_account=false`、`production_acceptance_claimed=false`；这不代表目标 OSS 或
主平台终端用户鉴权验收。

同一作业新增 [protocol-compaction.test.js](../integrations/codex/protocol-compaction.test.js)，
通过真实 `thread/compact/start` 新执行独立手动压缩：实际失败工具输出进入压缩请求，
生成的摘要必须出现在后续请求和新进程 resume 的历史中。共 4 Native Turn、2 个 epoch、
5 次模型请求；压缩为其中一个独立 Turn，真实生产者只发 PreCompact/PostCompact，
不会发 Stop。严格检查明确的 Wire 独立阶段、Hook 身份、配对、成功状态和来源端顺序，
再将原有 Hook 作为边界证据；Raw 事件类型保持原样。

回归还对本次派生副本分别改为内联压缩、移除 PreCompact、移除 PostCompact；三者
协议仍完整，但根边界、Runtime 和 Session 交付必须拒绝。原始 Segment 保持不变。
`native-compaction-ci.json` 报告只记录元数据与校验结论，声明合成模型、带补丁生产者，
不能作为未修改客户端或生产验收证据。

[protocol-auto-compaction.test.js](../integrations/codex/protocol-auto-compaction.test.js) 另通过
合成 usage 触发真实轮前、轮中和轮后自动压缩，包含实际 exit 7 工具和新进程 resume。
4 个业务 Native Turn、2 个 epoch、8 次模型请求保持独立；三个压缩均使用其业务 Turn
的原生身份，不新增虚构 Turn。完整输入、输出、摘要延续和 Hook 均保留，并经过 FS
归档恢复、投影下载和重启复验。派生副本移除轮中/轮后业务 Stop，或从同一 Turn 的
多个压缩中移除一个实际 Pre/Post 事件，均须拒绝完整交付。报告为
`native-auto-compaction-ci.json`；生产者源码与补丁保持固定，测试仍声明非生产验收。

这项回归使用已打补丁生产者和合成模型响应，报告固定声明 `real_upstream=false`、
`production_acceptance_claimed=false`，并验证真实上游 Canary 门禁拒绝它。它能发现协议、
生产者和采集链路一起运行时的回归，不能替代未修改客户端、真实模型、阿里 OSS 或
生产环境的交付验收。原有脱敏真实 Canary fixture 仍用于验证门禁本身。

回归执行前，在源码副本上逆序撤销完整六补丁集，并逐文件核对固定 upstream 原文；
GitHub 还核对构建前的源码摘要。仅同版本号、补丁文件名或编译成功不能证明实验基线一致。

本地复验需先构建 ChipTrace，以及固定源码、六个补丁和协调锁文件对应的 CLI：

```bash
CHIPTRACE_PROTOCOL_MODE=patched_stock_cli \
CHIPTRACE_PROTOCOL_SOURCE=/absolute/path/to/pinned-codex-checkout \
CHIPTRACE_PROTOCOL_PRODUCER=/absolute/path/to/codex \
CHIPTRACE_PROTOCOL_MINIO_BINARY=/absolute/path/to/minio \
CHIPTRACE_PROTOCOL_REPORT=/private/path/native-protocol-ci.json \
CHIPTRACE_BUYER_PROTOCOL_REPORT=/private/path/native-buyer-protocol-ci.json \
CHIPTRACE_INTERRUPTION_REPORT=/private/path/native-interruption-ci.json \
CHIPTRACE_COMPACTION_REPORT=/private/path/native-compaction-ci.json \
CHIPTRACE_AUTO_COMPACTION_REPORT=/private/path/native-auto-compaction-ci.json \
  make protocol-collection-test
```

`CHIPTRACE_PROTOCOL_MINIO_BINARY` 缺省时只执行 FS 平台联测；CI 必须设置它，并核对
五份报告的实际 S3 证据。CI 从固定 MinIO commit
`07c3a429bfed433e49018cb0f78a52145d4bedeb` 以 Go 1.24.2 构建该私有服务。

本地仍可显式选择 `patched_stock_debug_app_server` 并传入 `codex-app-server` 进行调试；
该路径关闭插件启动任务，不能用它的通过代替完整 CLI 的启动边界验证。
取消、手动和自动压缩报告的 `producer_mode`、`unmodified_stock` 均取实际 fixture 模式，
不再写死为 debug App Server。所有合成模型报告仍明确声明非真实上游和非生产验收。

运行只创建新的临时采集目录。通过后清理本次临时数据；失败时保留证据目录并返回非零。
`CHIPTRACE_PROTOCOL_KEEP=1` 可保留通过的本地实验数据，须按运维数据权限管理。
GitHub 的临时 runner 按同一 pinned producer 的 CI 配置启用非特权 user namespace，并先
用 `unshare --user --map-root-user true` 验证。实际工具仍使用 `read-only` sandbox。
失败同时生成有长度限制的 check annotation，避免匿名日志访问受限时只能看到退出码；
模型服务的断言错误会立即结束当前等待，不等待生产者耗尽网络重试。

namespace 可用仍不等于原生工具可执行：一次远端新采集实际因缺少 Bubblewrap 而使
第一个 shell 工具退出 101。debug producer 没有 release 包内的 bundled bwrap，因此 CI
显式安装系统 bubblewrap，并在编译前执行只读
[sandbox 检查](../scripts/ci/check-native-sandbox.sh)：检查 producer 要求的 --perms 能力，
实际进入 user/PID namespace，绑定只读根并检查系统文件可读。缺少 bwrap 时真实退出
127；不改用无沙箱工具或伪造成功。

生产者 core/App Server 测试程序编译、回调、并行终态、完整客户端、Session 作用域和
二进制构建各有独立 CI 步骤，便于从公开 job 状态区分编译与测试执行。上述命令要求新
的私有日志文件并保留原始输出；失败注释同时记录命令、日志写入和最终退出码，
只读最后 8 KiB，限制正文长度、转义工作流控制字符并遮蔽 Bearer 字符串，命令真实非零
退出码保持不变。完整编译日志随同生产者报告保留；注释不能代替完整日志的根因分析。

一次实际 runner 失联使整个生产者作业失败、后续采集未执行。原因尚不能归结为内存或
网络；构建并发降为 2，每 120 秒在该阶段发布有界资源 notice，记录实际可用内存、磁盘、
CPU 数和 load average，不采集生产者环境值、命令行或对话。监控进程随命令退出回收。

本轮新执行的实验在完整五补丁基线上发现 `config/read` 及其文件读取子 span 没有作用域，
导致 62 个 span 的 Session 身份未知，交付检查实际退出为不通过。此请求读取进程配置，
没有原生 Session/Turn 参数。[第六个补丁](upstream-config-read-scope.patch) 在来源端为
`config/read` 和同类 `configRequirements/read` 明确声明 process scope；两种请求均在
新回归每次连接时实际执行。子文件操作只沿其精确父链继承 scope，不按 span 名称豁免。
原始五补丁真实 Canary 的历史证据和生产门禁保持原样；新实验仍须使用独立的合成报告。

## 2026-10-14 的真实新版客户端检查

使用当前唯一终端安装的 Stock Codex `0.163.0-alpha.11`，在只读容器中执行一次短采集任务。
容器没有宿主 `/etc/codex` 配置，原生配置和九类 lifecycle Hook 只发送到临时网关、Relay 和
Collector；未重启线上 18084。模型使用真实上游的 `gpt-5.6-sol/low`，没有构造模型响应。
Hook 命令经过检查后仅在这次隔离调用中使用原生 trust bypass；这不证明管理员 required
Hook 部署或正常用户 Hook 信任状态已经通过验收。

| 指标 | 实际结果 |
| --- | --- |
| Session | `01a13a92-86d3-7a51-875a-79903750d55f` |
| Native Turn | 1 个；Session 和 Turn 均闭合 |
| Wire / 原始 OTLP batch / Hook | 5 / logs 16 / traces 10 / Hook 4 |
| Turn 精确归属记录 | Wire 5；logs 15；spans 1082；不同 Turn Hook 2 |
| 未归属记录 | logs 296；spans 159；总计 455 |
| Runtime 检查 / Session 交付 | `integrity.delivery_ready=true` / `delivery_ready=false` |
| 真实工具结果 | README 读取成功；故意 exit 7 保留；sleep 2 和后续 write_stdin 完成 |
| sealed Raw | 5,386,965 bytes；SHA-256 `e7c8d59423d494f1006fe341d7dbe010312a6edd075d43215b7aa70d2d20ad48` |

这是短采集 Canary，未满足 Buyer 采购规模，也未测试 resume、子 Session 或真实阿里 OSS。
缺失上下文的原始记录保留作取证，不能通过删除、改写或时间窗口关联使其变成合格数据。
完整原始证据保存在运维侧，不将对话正文、鉴权值或完整 Raw 提交到 Git。

## 元数据审计与全量计数

`audit-session-context` 复用 Canonical 的完整快照歧义检测和精确 Session 选择，直接只读
扫描 Capture，不创建投影或临时副本。输出遵循
[source-context-audit.v2](../schemas/source-context-audit-v2.schema.json)，只含计数、事件/span
名称、Capture/Trace/Span ID 和 envelope 内记录序号，不打印对话、工具输出或其他属性值。
v2 额外要求来源端用 `codex.context_scope=process` 明确标记进程级后台记录；没有该声明的
记录仍属于未知 Session，不能通过门禁。
分组最多 128 个，定位样本默认 20 个、最多 1000 个；超限仍保留遗漏记录数。
这些标识和名称仍属于运维元数据，报告应按项目权限保存。

```bash
chiptrace audit-session-context --input <sealed-raw-or-restored-directory> \
  --session-id <native-session-id> --sample-limit 5
```

2026-10-14 对上述 44 条原始 Capture 实际执行并保持 Segment SHA-256 不变：

| 来源 | envelope 内记录总数 | Turn 精确归属 | 已知 Session 级事件 | 未归属 Turn | Session 身份未知 |
| --- | --- | --- | --- | --- | --- |
| OTLP logs | 314 | 15 | 3 | 296 | 0 |
| OTLP spans | 1276 | 1082 | 0 | 159 | 35 |

每一来源的分类计数与总数守恒。455 条未归属 Turn 与当前 Session 检查一致；另有 35 个
span 无法精确确定 Session 身份，以前的 Session 未归属计数没有涵盖它们。报告显式保留
这一范围，不能把这些 span 自动归属给当前 Session，也不能宣称其必然不相关。
未归属的 159 个 span 中，`fs.get_metadata` 70、`fs.read_file` 20、
`persist_rollout_items` 6；其 Trace 没有已观察到的原生 Turn 身份。初始化/会话循环作用域
仍须凭来源端代码和原生身份审计，诊断名称本身不是豁免依据。命令不会给出交付通过标志。

进程级记录单独计入 `process_level_records`，不参与 Session/Turn 的四源覆盖，也不计入
`unknown_session_records`；只有来源端显式声明 `codex.context_scope=process` 时才能使用
这一分类。旧 v1 报告没有该字段，不能作为当前 v2 门禁证据。

审计也覆盖完全没有 Session 身份的独立 OTLP batch。全快照第一遍保留精确 Span 父链
元数据，第二遍逐 Capture 累计计数；没有身份的 batch 正文不会因此加入 Canonical 投影
或长期保留在投影的内存集合中。`selected_captures` 表示审计涉及的 Capture 数，包含已选
Session、显式 Process 和身份未知的 batch，可能大于投影的 `input_records`。未知身份
仍不归属当前 Session，但不能被假定为无关而从交付检查消失。明确属于其他 Session 且
没有未知记录的 batch 继续排除，重复 Capture 只计一次。诊断分组和样本有上限，精确
身份/父链索引仍随快照规模增长，尚未实现磁盘索引。

`process` 声明也不能豁免 Turn 业务事件。`codex.sse_event`、`codex.tool_result`、
`codex.tool_decision`、`codex.sandbox_outcome`、`codex.user_prompt`、`codex.turn_ttft`
和 `codex.turn_cost` 若直接声明或沿精确父链继承 Process scope，审计和 Session 检查均拒绝，
诊断为 `OTLP Turn-level business event conflicts with Process scope`。合法进程后台记录
仍按原始声明分类；冲突输入和 Raw 保留，不改写 scope 或删除业务记录。

同一属性列表的重复键也必须在合并前检查。原先属性映射会静默采用最后一个值，导致
冲突的 Session/Turn、scope 或事件名绕过后续别名校验。现在 resource、scope 和 record
各层都会拒绝这些冲突；相同重复值仍只对应一条原始记录。真实 CLI 的合成负例覆盖 logs
和 traces 的四类冲突，要求退出 1、stdout 为空、诊断不含正文且 Raw 字节不变。
平台 HTTP/SDK 还验证冲突 Raw 可归档取证，但检查和导出任务失败、分页和下载不可用。
在线 logs/traces 的三层冲突也须在 Raw 持久化后返回质量错误，不能以 `durable=true`
报告采集质量成功。真实 Relay/Collector 回归验证重试幂等、两份 WAL 的原始 UTF-8 字节及
哈希一致、重启后恢复。logs 派生路径同时保留 scope 身份，record 属性仍有覆盖优先级。
这些协议负例不表示实际生产者已经发射了同类冲突，也不替代未修改客户端的真实验收。

[精简回归 fixture](../fixtures/native-context-README.md) 只保留实际字段和父链，用一致
别名替换身份。CI 验证缺口、跨 Session 歧义、正文不输出、计数守恒和真实非零退出；
它不替代完整 Raw 或新的真实客户端 Canary。

## 已定位的生产者路径

296 条未归属日志均为 `codex.sse_event`，有 `conversation.id`，没有有效 Trace/Span ID、
原生 Turn ID 或响应 ID。它们只有事件种类、耗时和时间戳，无法在多 Turn、重试和并行任务中
精确确定所属 Turn。这一字段缺口在旧 `0.153.4` 和本次 `0.163.0-alpha.11` 均被真实观察到。
159 个未归属 span 仍需要逐项审计，不能假定与 SSE 日志具有同一原因。

版本 tag `rust-v0.163.0-alpha.11` 对应 upstream commit
`5425d3e625daa58eea3ad1de27c087eb3b2ffbd3`。该版本的
[ApiTelemetry](https://github.com/openai/codex/blob/5425d3e625daa58eea3ad1de27c087eb3b2ffbd3/codex-rs/core/src/client.rs#L2937)
保存 Session telemetry、鉴权环境和路由信息；`on_sse_poll` 直接调用 `log_sse_event`，没有在
该结构中保存并重新进入原始请求 Span。
[SSE 日志发射路径](https://github.com/openai/codex/blob/5425d3e625daa58eea3ad1de27c087eb3b2ffbd3/codex-rs/otel/src/events/session_telemetry.rs#L1057)
也未显式带入原生 Turn 或响应 ID。代码与实际缺失字段相符，具体修复仍需回调级测试和新
客户端真实 Canary 证明。

固定版本的 HTTP 工厂在 `#[instrument(name = "model_client.stream_responses_api")]`
函数内构建 SSE 适配器。真实 Raw 中同名 span 的父链经过 `try_run_sampling_request`、
`session_task.turn` 和 `codex.turn_input`，含原生 Turn 身份。这为保留创建时上下文提供
具体证据；仍需要验证实际异步回调发射及 OTLP 导出，不能仅以 join 的正例宣布修复。

[来源端补丁草案](upstream-sse-context.patch) 在 `ApiTelemetry` 创建时捕获请求 Span，
并在同步 SSE 回调期间重新进入它。HTTP 和 WebSocket 工厂还将创建时的请求 Span
传给异步 stream mapper，成功和失败终态日志只在同步发射期间进入这个 Span，不把
entered guard 保持到 `.await` 之后。补丁不修改业务正文、原生身份或完成状态。

2026-10-15 在固定的 `5425d3e625daa58eea3ad1de27c087eb3b2ffbd3` 源码上完成
[回调和终态回归](upstream-sse-context-test.patch)：SSE 回调、成功终态、失败终态和
并行请求交错完成共 4 项通过。测试在退出创建作用域后触发事件，并保留没有 Span 的
日志事件，避免把缺失上下文误当成没有发射日志。临时移除成功终态的上下文恢复时，
该测试实际退出 101，观察结果为 `None`；恢复补丁后再次通过。
同一源码的 `client::tests` 全部 37 项通过，包含 HTTP/WebSocket 请求、鉴权恢复、
interceptor、丢弃流和背压取消；CI 也执行这组回归。
`cargo build -p codex-cli --bin codex --locked --offline` 也通过。
两个补丁又在另一个干净的同 commit 工作树中顺序 apply/check，通过；未纳入临时锁文件
或其他源码修改。

该 tag 的 Cargo.toml 已使用 `0.163.0-alpha.11`，Cargo.lock 中 160 个本地 workspace
包仍为 `0.0.0`。本次临时解析后的差异仅为这些本地包版本；外部依赖版本、来源、校验和、
依赖边及其余锁文件字节保持不变。[锁文件检查](../scripts/ci/check-producer-lock.js)
复验了这个限制，之后的测试和 CLI 构建均使用 `--locked`。原始锁文件 SHA-256 为
`0da7b7298c7e50d05f0d59b2b801afbaf3c3cf74c36d4e66ac6b51c21f60a4df`，临时协调后的
SHA-256 为 `0b2af1620da0832300973f59c3f0ff9de1547fd18098bce9ef8f9daa6505416c`。
这不是上游官方发行构建证明。

首次新增作业的远端 run `38610333057` 在干净 checkout 的锁文件协调步骤失败：
`cargo metadata --no-deps` 只读取 manifest，不会更新原始 Cargo.lock。本地已构建源码的
锁文件此前被 Cargo 协调，因此未覆盖这一启动路径。CI 现在显式执行 `--prepare`，
仅接受原始锁文件或严格计算出的本地包版本替换结果；其他依赖或字节变化直接拒绝，
不会覆盖。后续构建仍使用 `--locked`。CLI 回归从原始 Git 锁文件验证协调、重试幂等和
依赖篡改拒绝；失败诊断只打印 SHA-256，避免展开完整锁文件。

GitHub CI 的 `upstream-context` job 现在固定同一 commit，顺序应用两个补丁、复验上述
锁文件限制、编译并执行 4 项回归，再构建 CLI。CI 另检查每个指定测试确实执行且通过，
零项匹配、重复测试或依赖变化均不能获得通过报告。日志、锁文件摘要和测试摘要作为
Artifact 保存。工作流定义和本地检查不能代替该提交的远端 Actions 结果。
[上游问题草稿](upstream-turn-context-issue.md)
仅作为可审查材料保存在本仓库，尚未向其他项目发消息、创建 Issue 或提交 PR。

## 2026-10-15 的补丁实验与剩余作用域

隔离真实 Provider Canary 使用上述修改后的 CLI；版本基线为 `0.163.0-alpha.11`，
不是未修改的 Stock Codex。Session `01a13b67-bcff-79d0-b131-cb28e1e8b4d6` 退出 0，
1 个原生 Turn 和 Session epoch 均闭合；Wire 5、OTLP logs 12 批、traces 4 批、Hook 4。
真实工具读取、故意 exit 7 和 sleep/write_stdin 结果均保留。每个 Turn 四源齐全，
但 Session `delivery_ready=false`；这是短采集实验，不满足采购规模。

| 来源 | 记录总数 | Turn 精确归属 | 已知 Session 级 | 未归属 Turn | Session 未知 |
| --- | --- | --- | --- | --- | --- |
| OTLP logs | 326 | 321 | 3 | 1 | 1 |
| OTLP spans | 1265 | 1071 | 0 | 159 | 35 |

未归属 Turn 总计 160，另有 36 条记录没有精确 Session 身份；不能把后者包含在前者中
或默认为无关。原始 sealed Segment SHA-256 为
`5285f05e1813795d22cd291d92d726dab4faba3393fe2fa3fe4535a4c2d27721`，证据保留在
运维目录 `/var/tmp/chiptrace-native-patched-a62a74`，不将完整 Raw、日志正文或鉴权数据提交到 Git。

只读定位样本确认 159 个 span 分布于两个没有原生 Turn 的 Trace：启动链 139 个、
Session 循环/关闭链 20 个。启动链包括 `thread/start -> thread_spawn -> session_init`，
Session 循环根有真实 UUID `thread_id`；两者都没有 Turn 边界，不能用同名文件操作或
最近 Turn 把它们关联到业务 Turn。具体来源路径与下一轮修复约束见
[Session 作用域审计](session-scope-audit.md)。当前分类和门禁保持严格，未将它们自动豁免。

下一步应在生产者的请求/Turn 上下文创建时保存不可变关联信息，并在异步 SSE 回调和派生
span 中继续传递；同时核实 Session 级 span 的原始作用域。补丁原型应在独立环境验证，
不能替换当前唯一终端安装或改写历史 Raw。只有后续未修改的发行版本通过验收，才能宣称
Stock Codex 的完整 v2 交付已经可用。

## 2026-10-15 的 patched Canary 门禁结果

在固定 upstream commit `5425d3e625daa58eea3ad1de27c087eb3b2ffbd3` 上顺序应用
SSE 上下文、Session 作用域、扩展作用域和 process 作用域补丁，再使用真实
`0.163.0-alpha.11` 客户端在隔离环境采集。该客户端不是未修改 Stock Codex；线上 18084
也没有加载这组补丁。

本轮 Canary 有 2 个 Native Turn 和 2 个 Session epoch，覆盖第二轮、实际 resume、失败
工具进程和延迟 `write_stdin`。两个 Turn 均闭合，Session/Turn 没有冲突、未归属或未知
Session 记录，Wire、OTLP logs、OTLP traces、Hook 四路来源均有正数证据。脱敏后的门禁
输入保存在 [success report](../fixtures/native-canary-multiturn-0163-success-report.json)
和 [success audit](../fixtures/native-canary-multiturn-0163-success-audit.json)，只包含
计数和元数据。

```json
{
  "schema_version": "chiptrace.native-canary-gate.v2",
  "real_upstream": true,
  "stock_version": "0.163.0-alpha.11",
  "producer_mode": "patched_stock",
  "unmodified_stock": false,
  "production_ready": false,
  "scenario_evidence_verified": true,
  "native_turns": 2,
  "selected_audit_records": 3621,
  "delivery_ready": true
}
```

审计总计为 OTLP logs 580 条（Turn 573、Session 5、process 2）和 OTLP traces 3041 条
（Turn 2190、Session 737、process 114），`unscoped_otlp_records=0`，每项分类与总数
守恒。`process` 记录只有在来源端显式写入 `codex.context_scope=process` 时才可以这样
分类。该结果证明补丁后的隔离生产者路径可以满足数据完整性门禁，不证明未修改发行版、
线上镜像或真实 Alibaba OSS 账户已经验收。门禁输出 `producer_mode=patched_stock`，生产
交接命令还必须添加 `--require-unmodified-stock`；正向 fixture 也不替代 Raw、鉴权审计或
采购包。

2026-10-15 加入上述 Process 冲突保护后，再次只读回放这份真实两轮 patched Canary：
`audit-session-context --sample-limit 0` 和 `inspect-session` 均退出 0，仍为 2 个原生 Turn、
`delivery_ready=true` 和 3621 条分类守恒的 OTLP 记录。合法的 2 条 process 日志和 114 个
process span 均保留。sealed Raw 在回放前后的 SHA-256 相同：
`fb39af7a9bae56dd17455f7840b51248a57e4fe64725705339de04d43f6fd3ef`。
Rust 和真实 CLI 的独立负例覆盖七类业务事件的直接/父链 Process 声明，共 14 种组合；
CLI 均真实退出 1、stdout 为空、诊断不含正文、输入字节和目录不变。这些负例是协议回归，
不表示 Stock Codex 在真实任务中已经发射了错误 Process 声明。

## 检查入口的完整交付状态

`inspect-session` 的顶层 `delivery_ready` 和 `validation_status` 现在合并逐 Turn 来源、
原生边界、Canonical 协议/Runtime 完整性和来源身份审计。返回的 `source_context_audit`
使用 `sample_limit=0`，与投影复用同一份读取快照；不额外重扫 Raw。来源审计和
`cloud-acceptance` 复用同一计数守恒、未知 Session 和未归属 Turn 检查。
嵌套 `session.delivery_ready` 是已精确选择的 Session/Turn 视图，
`integrity.delivery_ready` 是 Canonical Runtime/协议视图，均不能单独替代顶层结果。

2026-10-15 只读重放历史 Session `01a13bd7-c500-76c1-94c1-74370b1da588`：
已归属的 Session 和 Runtime 检查均通过，但仍有 2 条日志、84 个 span 没有 Session
身份。旧检查错误返回可交付；修复后顶层为 `delivery_ready=false`、
`validation_status=not_ready`。原始 sealed Segment 的 SHA-256 保持
`4682d03226ba984e8bd1cc1593026c215a2997a926f6d0999c1ed93d49b21039`。
该失败样本和前述合格 patched 样本均保留，没有删除记录或改写原始身份。

平台 HTTP/SDK 回归另向合成采集样本加入完全无身份的独立 logs/traces batch：检查任务
成功返回诊断，总交付状态为 false；Turn 分页同样返回顶层 `delivery_ready=false`；
导出任务保留引擎真实退出 1。CLI 回归覆盖跨 batch 的精确 Process 父链、重复 Capture、
未知记录计数和正文不输出。这些合成负例不代替真实客户端验收。

门禁还要求 `session_view.model_interactions` 和
`session_view.tool_execution_records` 分别等于所有 Native Turn 对应字段的总和。聚合值
缺失、被篡改或存在未归属交互时，Canary 会失败；这两个字段不能用 Runtime integrity
结果代替。

CI 现在在固定源码 clean clone 中复验五个补丁的 `apply --check`、顺序应用和
`git diff --check`，其中进程级后台任务的补丁单独保存为
[`upstream-session-scope-process.patch`](upstream-session-scope-process.patch)。

## 下一轮验收

Canary 门禁 v2 不再把 `scenario_coverage` 标签视为场景已执行的证明。
`inspect-session` 顶层新增 `scenario_evidence`，与 Session 视图及来源审计来自同一次
Capture 快照，不写入 Canonical 投影 metrics，也不放宽投影 Manifest 的重算校验。
其中只保留有模型交互的两个原生 Turn、真实 `SessionStart(source=resume)`、非零进程退出，
以及同一 Turn 内 running exec 与较晚 terminal `write_stdin` 的调用、序号和进程 ID。
工具证据必须来自未截断的 builtin `codex.tool_result`；进程 ID 重用或调用证据冲突不能
用来拼接异步过程。摘要不含对话正文、完整工具参数或输出。

2026-10-15 以新的检查入口只读回放前述合格 patched Raw，仍得到 2 个 Turn、8 个模型
交互、6 条工具记录、3621 条审计记录；真实失败退出为 7，异步 launch/poll 序号为 3/4。
脱敏 fixture 保留这些实际状态及序号，并一致替换身份。Raw SHA-256 保持上文值不变。
只有标签、没有 `scenario_evidence` 的历史报告现在会拒绝，须从保留的 Raw 重新检查。
普通完整 Session 不要求执行 Canary 的四项特殊场景，因此场景缺失本身不降低
`inspect-session.delivery_ready`；Canary 门禁单独要求它们齐全。

真实 Canary 的报告和 `audit-session-context` 必须经过仓库内的同一门禁，不能只看
`integrity.delivery_ready` 或 CLI 退出码。门禁要求真实上游客户端至少两个 Native Turn，
每个 Turn 的 Wire、OTLP logs、OTLP traces、required Hook 均有记录，Session/Turn 均闭合，
没有未归属或未知 Session 记录；进程级后台记录必须有显式 `process` scope，并且来源计数守恒：

```bash
chiptrace inspect-session --input <sealed-raw-or-restored-directory> \
  --session-id <stock-codex-session-id> > inspection.json
```

Canary 启动器另保留真实上游观察、客户端版本/源码/补丁来源和进程退出结果，写入
`producer-run.json` 的 `real_upstream`、`stock_version`、`provenance`、`native_exit`；
这些运行事实不能从检查结果或场景标签推断。将它与同快照的引擎结果组装后执行门禁：

```bash
node - <<'NODE'
const fs = require('node:fs');
const inspection = JSON.parse(fs.readFileSync('inspection.json', 'utf8'));
const run = JSON.parse(fs.readFileSync('producer-run.json', 'utf8'));
const report = {
  real_upstream: run.real_upstream, stock_version: run.stock_version,
  provenance: run.provenance, native_exit: run.native_exit,
  delivery_ready: inspection.delivery_ready, integrity: inspection.integrity,
  session: inspection.session, source_coverage: inspection.source_coverage,
  scenario_coverage: ['second_turn', 'resume', 'failed_tool_process', 'delayed_write_stdin'],
  scenario_evidence: inspection.scenario_evidence,
};
fs.writeFileSync('report.json', JSON.stringify(report, null, 2));
fs.writeFileSync('source-context-audit.json', JSON.stringify(inspection.source_context_audit, null, 2));
NODE
node scripts/ci/native-canary-gate.js \
  --report report.json --audit source-context-audit.json --minimum-turns 2
```

生产交接还必须声明生产者未修改：

```bash
node scripts/ci/native-canary-gate.js \
  --report report.json --audit source-context-audit.json \
  --minimum-turns 2 --require-unmodified-stock
```

报告的 `provenance` 必须包含 `client_version`、固定的 `upstream_commit`、
`producer_mode` 和守恒的 `patch_set`。`patched_stock` 只用于隔离数据治理回归，不能作为
未修改 Stock Codex 的生产证明。

该门禁只输出计数和状态摘要，不读取或打印对话正文、工具参数、鉴权值或文件路径。
失败结果必须保留 Raw 和审计报告，不能通过删除未归属记录、改写状态或降低轮次门槛来
获得通过。
门禁校验这些摘要之间的一致性，不认证任意手写 JSON 的真实性，也不替代 Raw/Manifest
哈希复验、生产者来源确认、真实 OSS 或线上交付验收；发布时应从已验证 Raw 新生成检查结果。

1. 保留业务请求的原生 Session、Turn、request/response 和 W3C 上下文，验证 SSE 回调离开
   原始异步任务后仍能精确关联；同 Trace 多 Turn 不允许依赖全局“当前 Turn”。
2. 使用至少两个真实 Turn、并行请求、重试、实际 resume、取消和失败复现；检查所有来源
   的归属计数和未归属计数守恒，保留确实属于 Session 作用域的原始证据。
3. 在目标 OSS 账户复验提交对象、恢复、逐 Turn 检查和完整 Buyer 导出下载；保存提交 SHA、
   镜像 ID、原始对象哈希及对应 CI run。
4. 更新宿主网关健康门禁，保留并恢复长期 open 的 Capture；健康检查必须能反映未最终化
   或不可验证的事务。完成隔离 Canary 后再灰度部署，验证重启及回滚保持原始证据。

ChipTrace 修复提交 `b5352addce361edac78a08ffd08638aa36b22476` 的
[GitHub CI](https://github.com/XS-MLVP/ChipTrace/actions/runs/38570741233) 三个作业均已通过。
这证明该提交的工程回归通过；上面的真实客户端结果仍未满足完整交付门槛。
