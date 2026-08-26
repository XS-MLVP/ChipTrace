# 变更记录

本文件记录项目各版本的重要变更。版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## 未发布

暂无。

## 0.4.0 - 2026-08-26

### 版本内容

- 增加本地持久化 Relay outbox，支持重启恢复、幂等重试和冲突隔离。
- 增加 source-namespaced Session 身份、Response DAG 和父子 Agent 索引。
- 增加工具 schema、schema hash、调用结果和生命周期事件索引。
- 增加 Session 完整性评分、Session 原子分包和标准交付 Manifest。
- 增加 OpenAPI、JSON Schema、持续集成、安全策略和通用部署文件。

### 优化

- 使用有界并行压缩和多进程 sharded export 提高离线处理吞吐。
- 统一 Collector、ledger、catalog、release 和质量策略的版本边界。
- 收敛仓库目录和文档结构，统一中文项目说明。

## 0.3.0 - 2026-08-25

### 新增

- 增加有界并行压缩和 sharded raw export。
- 增加完整 Session release 构建和完整性评分。
- 增加持久化幂等采集、崩溃恢复、审计和校验导出。
