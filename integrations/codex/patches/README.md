# 本地 Codex 启动器补丁

本机 Codex 是本地安装（`~/.local/openai-codex`），launcher 为
`~/.local/bin/codex`。它原本在 open21 上把用户 helper 同步自 root 所有的
`/usr/local/libexec/chiptrace-codex-hook`，并把受管 Hook 的 `CHIPTRACE_HOOK_BIN`
固定到同一路径。root 文件无法在无 sudo 密码时更新，于是本机一直在跑旧 helper，
空 `{}` 探针会持续产生 `Codex hook requires hook_event_name` 质量错误。

`local-helper-loading.patch` 做两件事：

1. 用户 helper 同步源改为仓库里的
   `integrations/codex/chiptrace-codex-hook.sh`（不存在时回退到 root 副本）；
2. 受管 Hook 的 `CHIPTRACE_HOOK_BIN` 优先指向
   `~/.local/libexec/chiptrace-codex-hook`。

应用：

```bash
cd /nfs/home/zhangyuxin
cp -a .local/bin/codex .local/bin/codex.bak-$(date +%Y%m%dT%H%M%S)
patch -p0 .local/bin/codex < /nfs/home/zhangyuxin/router_v2/ChipTrace/integrations/codex/patches/local-helper-loading.patch
bash -n .local/bin/codex
install -m 0755 /nfs/home/zhangyuxin/router_v2/ChipTrace/integrations/codex/chiptrace-codex-hook.sh \
  /nfs/home/zhangyuxin/.local/libexec/chiptrace-codex-hook
```

注意：`codex-single-install-maintainer` 的更新脚本可能重写 launcher，升级后需要重新应用本补丁。
