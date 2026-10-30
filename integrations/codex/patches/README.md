# 本地 Codex 启动器补丁

本机 Codex 是本地安装（`~/.local/openai-codex`），launcher 为
`~/.local/bin/codex`。它原先在 open21 上依赖 root 所有的两处资产，导致本地采集
在没有 root 时无法加载最新契约：

1. 用户 helper 从 `/usr/local/libexec/chiptrace-codex-hook` 同步；
2. 受管 Hook 的 `CHIPTRACE_HOOK_BIN`、`CHIPTRACE_INGEST_TOKEN_FILE` 和
   requirements 都指向 `/etc/**` 的 root 文件。

`local-helper-loading.patch` 把本地 Codex 的采集路径改成**完全用户所有**：

| 资产 | 改为 |
| --- | --- |
| Hook helper | 仓库 `integrations/codex/chiptrace-codex-hook.sh` → `~/.local/libexec/chiptrace-codex-hook` |
| requirements | 仓库 `requirements.toml.example` → `~/.codex/requirements.chiptrace-managed.toml`，在私有 mount namespace 内 bind 覆盖 `/etc/codex/requirements.toml` |
| ingest token | `~/.config/chiptrace/ingest-token`（不再从 `/etc` 覆盖） |
| OTLP/API key 判定 | 读取生效的 overlay，而不是 `/etc/codex/requirements.toml` |
| daemon 新旧判定 | 使用 overlay 时跳过 `/etc` 检查 |

overlay 使用 `unshare --user --map-root-user --mount`，不需要真实 root；挂载目标不存在时会在
命名空间内创建，挂载失败则 **fail-closed**（exit 126），不会静默丢掉必需 Hook。

验证（本机实测）：

- 正常启动：使用 overlay，Session 采集到 Wire + 4 个生命周期 Hook；
- `mount -t tmpfs none /etc/codex` 把 `/etc/codex` 完全屏蔽后再启动：Codex 正常回复，
  overlay 自建目标并生效，仍采集到完整 8 个 Hook，质量账本零新增。

应用：

```bash
cd /nfs/home/zhangyuxin
cp -a .local/bin/codex .local/bin/codex.bak-$(date +%Y%m%dT%H%M%S)
patch -p0 .local/bin/codex < /nfs/home/zhangyuxin/router_v2/ChipTrace/integrations/codex/patches/local-helper-loading.patch
bash -n .local/bin/codex
install -m 0755 /nfs/home/zhangyuxin/router_v2/ChipTrace/integrations/codex/chiptrace-codex-hook.sh \
  /nfs/home/zhangyuxin/.local/libexec/chiptrace-codex-hook
```

`codex-single-install-maintainer` 的更新脚本可能重写 launcher，升级后需重新应用本目录下的两个补丁。

## 统一使用 patched Codex（严格交付）

`patched-upstream.patch` 让 launcher 在
`/nfs/home/zhangyuxin/.local/openai-codex/patched/0.163.0-alpha.11-chiptrace`
存在时优先使用 `bin/codex`，否则回退到官方 package。

该二进制是 `codex-producer-0.163.0` 的 **release** 构建（已 strip debug 信息），
包含 Turn 级 SSE 标签与辅助 Span 的 process 作用域，因此日常会话可直接达到
`delivery_ready=true`，无需在“日常版/采集版”之间切换。

### 必须是完整 package，不能只有一个二进制

Codex 会从**二进制所在的 package layout** 解析运行时依赖：命令执行器
`bin/codex-code-mode-host`、`codex-path/rg`、`codex-resources/bwrap`（以及
voice 资源）。把 `codex` 单独丢进一个目录时，CLI 仍能对话，但**每一次 exec
工具调用都会失败**：

```
failed to spawn code-mode host .../codex-code-mode-host: No such file or directory
```

搜索（`runtime.search`）同样降级。故障只在使用工具时才暴露 —— 2026-10-30 有一个
会话就是这样全程无法执行命令。

因此安装一律走脚本，它会把 CLI 摆成官方同款 layout、从同版本官方 release 包补齐
helper/rg/bwrap、跑一次真实的"执行一条命令"冒烟测试，失败则回滚：

```bash
cd /nfs/home/zhangyuxin/router_v2/ChipTrace
integrations/codex/install-patched-codex.sh            # 用 producer 现有 release 构建安装
integrations/codex/install-patched-codex.sh --build    # 先重建 producer（codex + helper）
integrations/codex/install-patched-codex.sh --verify   # 只校验现有安装
```

冒烟测试走 launcher + 一次性 `CODEX_NODE_HOME`，不会在真实会话列表里留下探针会话；
`CODEX_PATCHED_SKIP_SMOKE=1` 可跳过。

七个 producer 补丁一行都不碰 `code-mode-host` 及其依赖（`code-mode-protocol` /
`code-mode-runtime`），所以同 commit 的官方 helper 与此构建等价，脚本直接取用：

```
<CODEX_CANONICAL_INSTALL_ROOT>/releases/<version>-*/node_modules/@openai/codex-linux-*/vendor/*/bin/
```

launcher 也会校验 package 完整性：缺任何一块时打印缺失项并回退官方 package，
不再进入"能对话但工具全废"的状态。

回退：删除 package 目录，launcher 自动使用官方版本；或用
`CODEX_PATCHED_ROOT=<path>` 覆盖。

