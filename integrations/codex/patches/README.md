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

`codex-single-install-maintainer` 的更新脚本可能重写 launcher，升级后需重新应用。
