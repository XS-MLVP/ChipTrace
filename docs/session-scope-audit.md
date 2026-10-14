# 原生 Session 作用域审计

本记录来自固定 Codex commit `5425d3e625daa58eea3ad1de27c087eb3b2ffbd3` 的源码和
2026-10-15 隔离补丁 Canary。它定位下一步生产者修复，不修改 Raw 或交付门槛。
完整结果和 Segment SHA-256 见 [native-turn-context](native-turn-context.md)。

只读 `audit-session-context --sample-limit 1000` 实际列出全部缺口。159 个未归属 span
恰好属于以下两条链；另有 35 个 span 和 1 条日志 Session 未知，单独保留。

| 来源链 | 实际数量 | 固定源码证据 | 下一步所需证据 |
| --- | --- | --- | --- |
| `thread/start -> thread_spawn -> session_init` 与启动辅助操作 | 139 spans；1 条未归属 `codex.api_request` | `core/src/session/mod.rs` 的 `Session::spawn` 在创建线程时建立 `thread_spawn`；`core/src/session/session.rs` 的 `Session::new` 在 `session_init` 内按 new/fork/resume 确定真实 thread ID；模型目录请求发生在初始化流程 | 来源端明确标记 Session 作用域并记录实际线程 ID；父链必须可复验，不能通过 Trace 名称猜测 |
| `session_loop -> op.dispatch.shutdown` 与关闭辅助操作 | 20 spans | `core/src/session/mod.rs` 在取得 `session.thread_id` 后启动独立 submission loop；`core/src/session/handlers.rs` 处理 Shutdown；本次根 span 的 UUID `thread_id` 是已观察事实 | 来源端标记 Session 作用域；Turn 分支仍必须携带自身原生 Turn ID，关闭操作不能借用最后一个 Turn |

`fs.get_metadata`、`fs.read_file`、`persist_rollout_items` 等名字同时出现在业务 Turn 和
初始化/关闭链中，因此不能对这些名称统一豁免。`turn_context.build` 同样既有正常 Turn
调用，也有关闭链调用；作用域应由创建路径和显式身份决定。

Session 未知的记录包含独立鉴权、模型目录、文件访问、持久化和订阅操作。部分名称看起来
像进程辅助活动，但名称不是不相关证明。需要继续检查产生这些独立 root span 的异步任务，
保留真实 Session 或明确的进程作用域；未知记录不能默认为本次 Session，也不能删除。

下一轮实现应遵守以下约束：

1. 在来源端作用域创建处记录不可变的 Session/Turn 身份及作用域类别；new、fork、resume
   使用实际分配的线程 ID，不生成另一套关联 ID。
2. Session 级上下文通过精确父链传递；只要子分支进入 Turn，其自己的 Turn 上下文优先。
   Session 级记录不能参与逐 Turn 四源计数。
3. 工具结果、SSE 和 Turn 边界缺少 Turn 身份时继续拒绝交付。Session 根的存在不能掩盖
   这些业务记录丢失上下文，也不能通过单个 Trace 恰好只有一个 Turn 来补造归属。
4. 来源声明、原生身份或父关系冲突时拒绝；跨 Session 共享 Trace、父关系环、取消、重试、
   resume 和子 Session 都需独立验证。
5. 真实多 Turn Canary 必须证明分类总数守恒、零未归属业务记录、所有 Turn 四源齐全且
   Session/Turn 边界闭合；仍无法确定 Session 的记录继续在审计中显式报告。

当前来源端补丁草案 `upstream-session-scope.patch` 为固定 upstream commit 增加
`codex.context_scope=session|turn`、实际 `conversation.id` 和精确父链测试；CI 会在
SSE 上下文补丁之后应用它，并使用 16 MiB 测试栈运行 thread-start、session-init、
session-loop 和 turn-start 作用域回归。该补丁仍需进入上游发行版本并通过未修改客户端
的多 Turn、并行、resume、取消和子 Session Canary；它不改变历史 Raw 的分类结论。
