# 原生 Turn 上下文缺口与修复验收

当前 v2 交付要求完整的原生 Turn 身份、四路来源、闭合边界和零未归属业务记录。
目前已实现精确关联和拒绝不完整交付，但真实 Stock Codex 仍有来源上下文缺口。
上线、完整交付或新客户端版本支持均需重新完成真实验收。

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

[来源端补丁草案](upstream-sse-context.patch) 在 `ApiTelemetry` 创建时捕获请求 Span，
仅在同步 SSE 日志回调期间重新进入它。该草案尚未经过 upstream 编译、回调隔离测试或
真实客户端验证，不能作为已修复证明；它也没有解决其余未归属 span 的作用域问题。
已在上述固定版本源码上通过 `git apply --check`；[上游问题草稿](upstream-turn-context-issue.md)
仅作为可审查材料保存在本仓库，尚未向其他项目发消息、创建 Issue 或提交 PR。

下一步应在生产者的请求/Turn 上下文创建时保存不可变关联信息，并在异步 SSE 回调和派生
span 中继续传递；同时核实 Session 级 span 的原始作用域。补丁原型应在独立环境验证，
不能替换当前唯一终端安装或改写历史 Raw。只有后续未修改的发行版本通过验收，才能宣称
Stock Codex 的完整 v2 交付已经可用。

## 下一轮验收

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
