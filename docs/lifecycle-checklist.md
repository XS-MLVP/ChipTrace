# 软件生命周期检查清单

本清单由每日 09:07 的定时任务执行，也可手工运行。原则：只报警**已到期或临近**的项，
正常项合并成一行，不重复已完成事项。

## 1. Codex 版本与 patched 构建

```bash
readlink ~/.local/openai-codex/current
integrations/codex/install-patched-codex.sh --verify        # 期望 "package ok"
```

- `current` 指向的官方版本若发生变化，需重建/重装 patched 包：
  `integrations/codex/install-patched-codex.sh`（见 `patches/README.md`）。
- patched 二进制的 mtime 应不早于 `codex-producer-0.163.0` 源码最后一次修改。
- `--verify` 只在文件齐全时通过；它不是冒烟测试。定期跑一次完整安装
  （或手工 `codex exec "run 'echo ok'"`）确认工具真的能执行 —— 缺 helper 时
  CLI 仍能对话，只有执行工具才暴露。

## 2. 启动器补丁漂移

```bash
grep -c 'PATCHED_CODEX_ROOT' ~/.local/bin/codex               # 期望 >= 1
grep -c 'repo_helper='       ~/.local/bin/codex               # 期望 >= 1
```

- 结果不足说明 `codex-single-install-maintainer` 重写了 launcher，需要重新应用
  `integrations/codex/patches/local-helper-loading.patch` 与 `patched-upstream.patch`。

## 3. Hook helper 一致性

```bash
sha256sum ~/.local/libexec/chiptrace-codex-hook \
          integrations/codex/chiptrace-codex-hook.sh
sha256sum ~/.local/libexec/chiptrace-claude-hook \
          integrations/claude-code/chiptrace-claude-hook.sh
```

- 两侧哈希必须相同；不同说明本地安装落后于仓库。

## 4. 质量基线时效

```bash
ls -lt /nfs/home/zhangyuxin/router_v2-data/chiptrace-relay/delivery/quality-baseline-*.json | head -3
```

- 最新基线超过 7 天，或历史质量计数发生变化，需要重新审计并生成新基线（附审批说明）。

## 5. 容量与段数

```bash
du -sh /nfs/home/zhangyuxin/router_v2/records/chiptrace-capture \
       /nfs/home/zhangyuxin/router_v2-data/chiptrace-relay
curl -s http://127.0.0.1:3011/health | jq '.collector | {captures, sealed_segments, queue_depth}'
```

- 阈值建议：本地 Raw 超过 200 GiB 或 segment 超过 2,000 时启动归档评估。
- 归档**只移动已封存 segment**，不得改动 `.open.ndjson`，不得改写 Raw 内容。

## 6. 镜像与仓库 revision 一致性

```bash
cd /nfs/home/zhangyuxin/router_v2/ChipTrace
git log --oneline -1
for c in router-v2-chiptrace-collector router-v2-chiptrace-relay \
         router-v2-platform-platform-1; do
  docker inspect "$c" --format '{{.Name}} {{index .Config.Labels "io.chiptrace.expected-revision"}}'
done
git diff --name-only <deployed-sha>..HEAD | grep -E '^crates/|^schemas/|^Dockerfile'
```

- 若 HEAD 与镜像 revision 不同，且差异含 `crates/`、`schemas/` 或 `Dockerfile`，
  必须重建并滚动镜像；仅文档/脚本差异可以暂缓。

## 7. 网关源码一致性

```bash
sha256sum integrations/openai-gateway/server.js
docker exec router-v2-relay-shell sha256sum /shell/server.js
```

- 两值必须相等。不等说明运行的是未入库的版本，需立即核对。

## 8. 服务健康与守恒

```bash
curl -s http://127.0.0.1:18084/health | jq '{status, openTransactions: .fullTraceCapture.outbox.openTransactions}'
curl -s http://127.0.0.1:3012/health | jq '. | {status, pending, inflight, failed, conservation_ok}'
curl -s http://127.0.0.1:3011/health | jq '.collector | {ready, queue_depth, rejected_attempts}'
```

- 任一非 healthy、`conservation_ok=false`、`failed>0` 或 `openTransactions` 持续增长，立即处置。

## 9. 依赖与安全

```bash
cargo audit --file Cargo.lock 2>/dev/null || echo "cargo-audit 未安装"
npm audit --omit=dev 2>/dev/null || true
```

- 记录高危项与可升级路径；升级后必须重跑 `make cloud-test`。

## 10. 未闭环能力跟踪

当前仍未闭环（每次检查确认状态是否变化）：

| 项 | 判定命令 |
| --- | --- |
| 真实 OSS/S3 | `curl -s http://127.0.0.1:18086/health \| jq -r .backend`（`fs` = 未接） |
| SFTP/T+1 对外发布 | 是否已有真实供应商参数与发布记录 |
| 官方 Codex 历史会话严格交付 | `chiptrace inspect-session` 对官方会话的 `delivery_ready` |
