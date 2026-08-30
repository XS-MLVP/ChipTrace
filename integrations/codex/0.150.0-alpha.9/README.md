# Codex 0.150 Runtime Tool Registry

本目录提供固定版本的 Codex producer 补丁。补丁从每个 turn 实际构建完成的
`ToolRouter` 导出可执行 Tool Registry，并在任何后续工具执行事件前写入原生
rollout-trace bundle。

## 上游基线

- Tag：`rust-v0.150.0-alpha.9`
- Commit：`a1a7e0b1d11436a3c33d14b2f019004bdf453777`
- Patch：`runtime-tool-registry.patch`
- SHA-256：`a392999dfc70bc03b99b18ef57ab5c793f25d89e34f77f88682b76e72aec09f3`

## 应用

```bash
git clone https://github.com/openai/codex.git
cd codex
git checkout a1a7e0b1d11436a3c33d14b2f019004bdf453777
git apply --check /path/to/runtime-tool-registry.patch
git apply /path/to/runtime-tool-registry.patch
```

启用原生 bundle 后运行 Codex，再由 ChipTrace 增量导出：

```bash
export CODEX_ROLLOUT_TRACE_ROOT=/var/lib/codex/trace-bundles
codex

chiptrace export-codex-trace-bundle \
  --input /var/lib/codex/trace-bundles/trace-<id> \
  --state-root /var/lib/chiptrace/codex-bundle-exporter \
  --relay-url http://127.0.0.1:3011 \
  --source-namespace router-v2-18084 \
  --task-session-id "$TASK_SESSION_ID" \
  --root-session-id "$ROOT_SESSION_ID" \
  --goal-id "$GOAL_ID" \
  --retry-max-times 25
```

## 证据边界

补丁保存 function、custom、namespace 和 tool-search 的原始运行时定义；custom
grammar 原样保存，不生成虚假的 JSON parameters。连续相同快照会去重，真实
`A -> B -> A` Registry 切换仍完整记录。

Registry 只证明该 turn 可执行的工具定义。任务 Session 起止仍由 Harness 提供，
模型与 provider 仍由 API 和网关证据证明，工具结果状态仍由 dispatcher 真实事件
提供。任何一侧缺失时，ChipTrace 保留 Raw 并将 Session 标为 incomplete。
