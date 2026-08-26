# 贡献指南

## 开发环境

项目要求 Python 3.10 或更高版本，以及 Node.js 20 或更高版本。

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e '.[performance]'
make test
make self-test
```

## 代码规范

- 保留原始证据，质量筛选只在版本化投影中执行。
- 保持持久化确认、全局身份、哈希校验和原子发布约束。
- 持久化 schema 变更必须包含新版本、迁移逻辑和兼容性测试。
- 每种请求、响应和生命周期格式必须包含对应测试样例。
- 不提交真实 Prompt、响应正文、凭据、私有地址和生产标识。
- 性能结果必须标明硬件、存储、缓存状态、持续时间和校验范围。
- 公共字段、状态、评分或命令发生变化时，同步更新数据契约和变更记录。

## 提交流程

1. 从最新主分支创建主题分支。
2. 保持提交范围单一，并为行为变化补充测试。
3. 运行 `make test` 和 `make self-test`。
4. 检查 `git diff --check`，确保没有格式错误。
5. 在 Pull Request 中说明数据契约影响、兼容性边界和验证结果。

## Commit 信息

提交标题使用命令式短句，并采用以下类型：

- `feat`：新增能力
- `fix`：修复缺陷
- `docs`：文档变更
- `test`：测试变更
- `refactor`：不改变行为的结构调整
- `perf`：性能优化
- `build`：构建或依赖变更
