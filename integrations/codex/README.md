# Stock Codex 接入

ChipTrace 使用 Stock Codex 的受管配置采集 Trace，不修改 Codex 二进制，也不依赖启动器。
主机完成一次部署后，普通用户直接运行 `codex`。

## 管理员准备

从当前 Codex 生成同版本模型目录，并将采购模型切换为原生 direct function 工具模式：

```bash
codex debug models --bundled > codex-models.json
chiptrace prepare-codex-catalog \
  --input codex-models.json \
  --output /etc/chiptrace/codex-models-direct.json \
  --model gpt-5.6-sol
```

该命令保留原模型目录的全部字段，只将指定模型的 `tool_mode` 设为 `direct`，并移除
freeform `apply_patch`。当前 Stock Codex 没有 `apply_patch` 的 JSON function 形态，因此该
工具不会出现在 direct 请求中，也不会被 ChipTrace 改名或补造 Schema；文件操作由请求中
真实存在的 direct function 工具完成。变更发生在模型请求构造前，Assembly 只保留事实。

将 `chiptrace` 安装到 `/usr/local/bin`，安装
[managed_config.toml.example](managed_config.toml.example) 到
`/etc/codex/managed_config.toml`，安装
[requirements.toml.example](requirements.toml.example) 到
`/etc/codex/requirements.toml`，再启用 `chiptrace-codex-agent.service`。服务持有
`codex-agent.lock`，断网时继续依赖本地 outbox，不要求远端健康才能启动 Codex。

受管配置同时固定以下事实：

- OpenAI-compatible provider 指向 `18084`；
- 当前采购模型读取 direct 模型目录；
- required 生命周期 Hook 不需要用户确认 Hook hash，也不能被用户配置静默替换。

两份系统文件各有一个职责：`managed_config.toml` 固定 provider、模型和 Wire 路由；
`requirements.toml` 固定 direct catalog 与 required Hook。不要把 Hook 同时写进两份文件，
否则 Stock Codex 的兼容加载路径可能重复注册同一个处理器。

不要把生产 Hook 仅写入用户级 `config.toml`。Stock Codex 会将未确认 hash 的用户 Hook
标记为 `Untrusted` 并跳过执行，无法提供严格采集保证。

## 启动门禁

`SessionStart` 在首个 Turn 前同步验证：

- 模型目录中当前模型为 `tool_mode=direct`，且未暴露 freeform `apply_patch`；
- `codex-agent` 正在持有指定状态目录的独占锁；
- outbox 可原子写入，积压未超过上限，磁盘空间满足预算。

任一条件失败时，Hook 返回 Codex 原生 `continue:false`，首个 Turn 不会执行。检查通过后
SessionStart 先持久化到本地 outbox。Hook 命令缺失或异常退出时，受管命令中的固定兜底
同样返回 `continue:false`。

远端短时断网不阻止启动：已经落盘的事件由 `codex-agent` 幂等续投。主机部署完成后，
用户侧没有额外命令或标签。
