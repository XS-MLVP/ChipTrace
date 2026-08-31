use anyhow::{Context, Result, bail};
use chiptrace::assemble::{AssembleConfig, assemble, verify_assembly};
use chiptrace::buyer::{
    BuyerPackageConfig, package_buyer_release, package_buyer_release_legacy, verify_buyer_package,
    verify_buyer_package_legacy,
};
use chiptrace::capture::{CAPTURE_SCHEMA_VERSION, normalize_capture};
use chiptrace::codex_hook::{CodexAgentConfig, HookSpoolConfig, run_codex_agent, spool_hook_event};
use chiptrace::codex_rollout::{
    ExportConfig as CodexRolloutExportConfig, ExportTarget as CodexRolloutTarget,
    export_codex_rollout, resolve_hook_rollout, watch_codex_rollout,
};
use chiptrace::codex_run::{CodexRunConfig, CodexRunTarget, CodexTaskPhase, run_codex};
use chiptrace::codex_trace_bundle::{
    BundleExportConfig as CodexTraceBundleExportConfig,
    BundleExportTarget as CodexTraceBundleTarget, export_codex_trace_bundle,
};
use chiptrace::collector::{CollectorConfig, serve};
use chiptrace::delivery::producer_relay_target;
use chiptrace::enrich::{EnrichConfig, enrich_captures, verify_enrichment};
use chiptrace::harness::{
    EvaluationInput, Harness, HarnessConfig, HarnessTarget, LifecycleEventInput, ToolEndInput,
    ToolStartInput,
};
use chiptrace::model_interaction::{
    InteractionProjectConfig, project_interactions, verify_interaction_projection,
};
use chiptrace::producer::{ProducerConfig, ProducerTarget, submit_producer_events};
use chiptrace::publish::{
    ArtifactKind, Backend, PublishConfig, PublishSource, VerifyPublishedConfig, publish,
    verify_published,
};
use chiptrace::raw_archive::{
    RawArchiveConfig, RawArchiveRestoreConfig, RawArchiveVerifyConfig, archive_raw,
    restore_raw_archive, verify_raw_archive,
};
use chiptrace::relay::{RelayConfig, serve_relay};
use chiptrace::release::{ReleaseConfig, build_release, verify_release};
use chiptrace::runtime_canary::{RuntimeCanaryConfig, run_runtime_canary};
use chiptrace::score::{Profile, score_jsonl};
use chiptrace::sharded::{ShardedCaptureStore, audit_sharded_store};
use chiptrace::store::StoreConfig;
use chiptrace::telemetry::{OtlpExportConfig, export_otlp, verify_otlp_export};
use clap::{Args, Parser, Subcommand};
use rayon::prelude::*;
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufWriter, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "chiptrace",
    version,
    about = "芯迹：高性能 Agent Trace 采集、Session 组装、验收与对象存储交付"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// 启动持久化 Collector。
    Collector(CollectorArgs),
    /// 启动带本地 durable outbox 的 Relay。
    Relay(RelayArgs),
    /// 只读审计 WAL 与 ledger。
    Audit(AuditArgs),
    /// 将 Capture NDJSON 组装为 canonical Session JSONL。
    Assemble(AssembleArgs),
    /// 将 Capture 投影为 vendor-neutral ModelInteraction 与 RuntimeSpan。
    ProjectInteractions(ProjectInteractionsArgs),
    /// 只读验证 ModelInteraction 双轨投影。
    VerifyInteractions(VerifyInteractionsArgs),
    /// 从 delivery-ready canonical Trace 生成单一 OTLP 树。
    ExportOtlp(ExportOtlpArgs),
    /// 只读验证 OTLP 文件、SHA-256 和内部父子关系。
    VerifyOtlp(VerifyOtlpArgs),
    /// 对 canonical Session JSONL 输出逐条验收结果。
    Score(ScoreArgs),
    /// 按显式 request_id 将 Sub2API usage log 精确关联到 Capture。
    Enrich(EnrichArgs),
    /// 从 Codex rollout JSONL 可靠导出任务、工具和生命周期事实。
    #[command(hide = true)]
    ExportCodexRollout(ExportCodexRolloutArgs),
    /// 持续增量导出活动 Codex rollout；用于实时 sidecar。
    #[command(hide = true)]
    WatchCodexRollout(WatchCodexRolloutArgs),
    /// 从 Codex Stop hook stdin 定位 rollout 并可靠导出。
    #[command(hide = true)]
    CodexHook(CodexHookArgs),
    /// 将 Stock Codex Hook 原子写入本地 durable outbox；不访问网络。
    #[command(hide = true)]
    CodexHookSpool(CodexHookSpoolArgs),
    /// 恢复 Hook outbox 和 rollout，获得 durable ACK 后推进本地队列。
    CodexAgent(CodexAgentArgs),
    /// 从 Codex 原生 rollout-trace bundle 校验并导出完整运行时事实。
    #[command(
        name = "export-codex-trace-bundle",
        hide = true,
        visible_alias = "import-codex-trace-bundle",
        visible_alias = "export-codex-bundle"
    )]
    ExportCodexTraceBundle(ExportCodexTraceBundleArgs),
    /// 在明确任务边界内运行 Codex 并持续导出原生 runtime Trace。
    #[command(hide = true)]
    CodexRun(CodexRunArgs),
    /// 校验版本化 Agent Producer 事件并等待 Relay durable ACK。
    Produce(ProduceArgs),
    /// 由真实任务运行器创建边界并记录生命周期、工具和评估证据。
    #[command(hide = true)]
    Harness(HarnessArgs),
    /// 只读验证 Enrich 产物、记录数、SHA-256 和 Raw lineage。
    VerifyEnrichment(VerifyEnrichmentArgs),
    /// 去重、评分并生成仅含准入 Session 的 JSONL.zst Release。
    Release(ReleaseArgs),
    /// 只读验证 Assembly。
    VerifyAssembly(VerifyAssemblyArgs),
    /// 只读验证 Release。
    VerifyRelease(VerifyReleaseArgs),
    /// 将内部 Release 转换为采购方 tar.gz + UTF-8 JSONL 交付包。
    PackageBuyer(PackageBuyerArgs),
    /// 只读验证采购方交付包、归档内容与全部 SHA-256。
    VerifyBuyerPackage(VerifyBuyerPackageArgs),
    /// 将已验收的内部 Release 或采购包原子发布到对象存储。
    Publish(PublishArgs),
    /// 从远端 COMMIT 只读复验已发布对象及完整 SHA-256。
    VerifyPublished(VerifyPublishedArgs),
    /// 将已封存的原始 WAL Segment 发布到统一 OSS 原始层。
    ArchiveRaw(RawArchiveArgs),
    /// 校验 OSS 原始层 Checkpoint、Manifest、Segment 和记录。
    VerifyRawArchive(VerifyRawArchiveArgs),
    /// 从 OSS 原始层恢复已提交的 sealed WAL Segment。
    RestoreRawArchive(RestoreRawArchiveArgs),
    /// 检查 Collector 或 Relay HTTP 健康接口。
    Probe(ProbeArgs),
    /// 运行隔离的采集到交付闭环自测。
    SelfTest,
    /// 执行五个真实工具并验证 runtime-full 生产者通路。
    #[command(hide = true)]
    RuntimeCanary(RuntimeCanaryArgs),
    /// 测量本地 WAL/ledger 持久化吞吐。
    BenchmarkStore(BenchmarkStoreArgs),
    /// 测量环回 HTTP、可选 Relay 双 WAL 与 producer 入口吞吐。
    BenchmarkHttp(BenchmarkHttpArgs),
    /// 测量 JSONL zstd 压缩吞吐。
    BenchmarkCompression(BenchmarkCompressionArgs),
}

#[derive(Debug, Args)]
struct CollectorArgs {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,
    #[arg(long, default_value_t = 3010)]
    port: u16,
    #[arg(long, default_value_t = 512)]
    segment_max_mib: u64,
    #[arg(long, default_value_t = 3600)]
    segment_max_age_seconds: u64,
    #[arg(long, default_value_t = 8192)]
    queue_items: usize,
    #[arg(long, default_value_t = 256)]
    batch_records: usize,
    #[arg(long, default_value_t = 64)]
    batch_mib: usize,
    #[arg(long, default_value_t = 10)]
    batch_wait_ms: u64,
    #[arg(long, default_value_t = 1024)]
    max_envelope_mib: usize,
    #[arg(long, default_value_t = 4096)]
    max_inflight_body_mib: usize,
    #[arg(long, default_value_t = 1024)]
    max_connections: usize,
    #[arg(long, default_value_t = 1)]
    store_shards: usize,
    #[arg(long, default_value_t = 4096)]
    max_batch_records: usize,
    #[arg(long, hide = true)]
    no_fsync: bool,
}

#[derive(Debug, Args)]
struct RelayArgs {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long)]
    delivery_state_root: PathBuf,
    #[arg(long)]
    collector_url: String,
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,
    #[arg(long, default_value_t = 3011)]
    port: u16,
    #[arg(long, default_value_t = 512)]
    segment_max_mib: u64,
    #[arg(long, default_value_t = 3600)]
    segment_max_age_seconds: u64,
    #[arg(long, default_value_t = 8192)]
    queue_items: usize,
    #[arg(long, default_value_t = 256)]
    batch_records: usize,
    #[arg(long, default_value_t = 64)]
    batch_mib: usize,
    #[arg(long, default_value_t = 10)]
    batch_wait_ms: u64,
    #[arg(long, default_value_t = 1024)]
    max_envelope_mib: usize,
    #[arg(long, default_value_t = 4096)]
    max_inflight_body_mib: usize,
    #[arg(long, default_value_t = 1024)]
    max_connections: usize,
    #[arg(long, default_value_t = 1)]
    store_shards: usize,
    #[arg(long, default_value_t = 4096)]
    max_batch_records: usize,
    #[arg(long, default_value_t = 16)]
    delivery_concurrency: usize,
    #[arg(long, default_value_t = 16384)]
    delivery_queue_items: usize,
    #[arg(long, default_value_t = 128)]
    delivery_batch_records: usize,
    #[arg(long, default_value_t = 16)]
    delivery_batch_mib: usize,
    #[arg(long, default_value_t = 2)]
    delivery_batch_wait_ms: u64,
    #[arg(long, default_value_t = 4096)]
    max_delivery_inflight_mib: usize,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
    /// 仅用于隔离开发；生产 producer 路由默认要求 CHIPTRACE_PRODUCER_TOKEN。
    #[arg(long)]
    allow_unauthenticated_producer: bool,
}

#[derive(Debug, Args)]
struct AuditArgs {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long)]
    verify_payloads: bool,
    #[arg(long, default_value_t = 1)]
    store_shards: usize,
}

#[derive(Debug, Args)]
struct AssembleArgs {
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    #[arg(long, required = true)]
    output: PathBuf,
    #[arg(long, default_value_t = 256)]
    partitions: usize,
    #[arg(long, default_value_t = 1)]
    zstd_level: i32,
    #[arg(long)]
    replace: bool,
}

#[derive(Debug, Args)]
struct ProjectInteractionsArgs {
    /// Capture JSONL、sealed NDJSON 或包含这些文件的目录，可重复指定。
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    #[arg(long, required = true)]
    output: PathBuf,
    /// 仅投影这一完整任务；混合输入中存在多个任务时必须指定。
    #[arg(long)]
    task_session_id: Option<String>,
    /// 仅投影这一 Stock Codex Session；与 --task-session-id 互斥。
    #[arg(long, conflicts_with = "task_session_id")]
    session_id: Option<String>,
    #[arg(long, default_value_t = 1)]
    zstd_level: i32,
    #[arg(long)]
    replace: bool,
}

#[derive(Debug, Args)]
struct VerifyInteractionsArgs {
    #[arg(long, required = true)]
    projection: PathBuf,
}

#[derive(Debug, Args)]
struct ExportOtlpArgs {
    #[arg(long, required = true)]
    projection: PathBuf,
    #[arg(long, required = true)]
    output: PathBuf,
    #[arg(long, default_value_t = 1)]
    zstd_level: i32,
    #[arg(long)]
    replace: bool,
}

#[derive(Debug, Args)]
struct VerifyOtlpArgs {
    #[arg(long, required = true)]
    projection: PathBuf,
}

#[derive(Debug, Args)]
struct ScoreArgs {
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum, default_value = "buyer-v7-codex-runtime-expanded")]
    profile: Profile,
    #[arg(long, default_value_t = 90.0)]
    minimum_score: f64,
    #[arg(long, default_value_t = 1)]
    zstd_level: i32,
}

#[derive(Debug, Args)]
struct EnrichArgs {
    /// Capture JSONL、sealed NDJSON 或包含这些文件的目录，可重复指定。
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    /// Sub2API usage log JSON/JSONL 文件或目录，可重复指定。
    #[arg(long = "usage-log", required = true)]
    usage_log: Vec<PathBuf>,
    #[arg(long, required = true)]
    output: PathBuf,
    #[arg(long, default_value_t = 1)]
    zstd_level: i32,
    #[arg(long)]
    replace: bool,
}

#[derive(Debug, Args)]
struct ExportCodexRolloutArgs {
    /// Codex rollout JSONL 文件。
    #[arg(long)]
    input: PathBuf,
    /// exporter 的持久化 byte offset/ordinal checkpoint 目录。
    #[arg(long)]
    state_root: PathBuf,
    /// Rust Relay 地址；与 --output 二选一。
    #[arg(long, conflicts_with = "output")]
    relay_url: Option<String>,
    /// 本地验证用 NDJSON；与 --relay-url 二选一。
    #[arg(long, conflicts_with = "relay_url")]
    output: Option<PathBuf>,
    /// 必须与 18084 Capture 使用相同 namespace 才能组装为同一任务。
    #[arg(long)]
    source_namespace: String,
    /// 由实际 Agent runtime 导出的版本化 Tool Registry 快照。
    #[arg(long)]
    tool_registry: Option<PathBuf>,
    #[arg(long, default_value_t = 128)]
    batch_records: usize,
    #[arg(long, default_value_t = 1024)]
    max_envelope_mib: usize,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    /// 由 harness 显式创建的完整任务 Session ID；不从 Codex thread/turn 推断。
    #[arg(long)]
    task_session_id: Option<String>,
    /// 由 harness 显式提供的根任务 Session；未提供时不推断。
    #[arg(long)]
    root_session_id: Option<String>,
    /// 由 harness 显式提供的父任务 Session；不从 thread ID 推断。
    #[arg(long)]
    parent_session_id: Option<String>,
    #[arg(long)]
    goal_id: Option<String>,
}

#[derive(Debug, Args)]
struct WatchCodexRolloutArgs {
    #[command(flatten)]
    export: ExportCodexRolloutArgs,
    #[arg(long, default_value_t = 250)]
    poll_ms: u64,
    /// 非零时，在无新增完整行达到该秒数后退出；生产 sidecar 保持 0。
    #[arg(long, default_value_t = 0)]
    idle_exit_seconds: u64,
}

#[derive(Debug, Args)]
struct CodexHookArgs {
    /// 只允许读取该目录下的 rollout 文件。
    #[arg(long)]
    session_root: PathBuf,
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long, conflicts_with = "output")]
    relay_url: Option<String>,
    #[arg(long, conflicts_with = "relay_url")]
    output: Option<PathBuf>,
    #[arg(long)]
    source_namespace: String,
    #[arg(long)]
    tool_registry: Option<PathBuf>,
    #[arg(long, default_value_t = 128)]
    batch_records: usize,
    #[arg(long, default_value_t = 1024)]
    max_envelope_mib: usize,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    #[arg(long)]
    task_session_id: Option<String>,
    #[arg(long)]
    root_session_id: Option<String>,
    #[arg(long)]
    parent_session_id: Option<String>,
    #[arg(long)]
    goal_id: Option<String>,
}

#[derive(Debug, Args)]
struct CodexHookSpoolArgs {
    /// 插件私有数据目录中的本地 outbox 根目录。
    #[arg(long)]
    queue_root: PathBuf,
    #[arg(long, default_value_t = 4)]
    max_input_mib: usize,
}

#[derive(Debug, Args)]
struct CodexAgentArgs {
    /// Hook 写入的本地 outbox 根目录。
    #[arg(long)]
    queue_root: PathBuf,
    /// Stock Codex rollout sessions 根目录；所有 transcript 必须位于其中。
    #[arg(long)]
    session_root: PathBuf,
    /// rollout byte checkpoint 状态目录。
    #[arg(long)]
    state_root: PathBuf,
    /// 提供 `/producer/events` 的 Relay 基础 URL。
    #[arg(long, default_value = "http://127.0.0.1:3011")]
    relay_url: String,
    #[arg(long)]
    source_namespace: String,
    #[arg(long, default_value_t = 128)]
    batch_records: usize,
    #[arg(long, default_value_t = 1024)]
    max_envelope_mib: usize,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    #[arg(long, default_value_t = 1000)]
    poll_ms: u64,
    /// 处理一次当前 pending 集合后退出，用于自测和定时任务。
    #[arg(long)]
    once: bool,
}

#[derive(Debug, Args)]
struct ProduceArgs {
    /// Capture v2 producer-event JSONL；使用 - 从 stdin 读取。
    #[arg(long)]
    input: PathBuf,
    /// 本机 Rust Relay 地址；与 --output 二选一。
    #[arg(long, conflicts_with = "output")]
    relay_url: Option<String>,
    /// 隔离验证用 NDJSON；与 --relay-url 二选一。
    #[arg(long, conflicts_with = "relay_url")]
    output: Option<PathBuf>,
    #[arg(long, default_value_t = 128)]
    batch_records: usize,
    #[arg(long, default_value_t = 1024)]
    max_envelope_mib: usize,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
}

#[derive(Debug, Args)]
struct HarnessArgs {
    #[command(subcommand)]
    command: HarnessCommand,
}

#[derive(Debug, Subcommand)]
enum HarnessCommand {
    /// 创建任务身份并立即写入 task_start 事件。
    Start(HarnessStartArgs),
    /// 写入任意生命周期事实（task/session 边界除外的事件也在此记录）。
    Lifecycle(HarnessLifecycleArgs),
    /// 写入工具 dispatcher 的 started 事实。
    ToolStart(HarnessToolStartArgs),
    /// 写入工具 dispatcher 的真实终态和返回。
    ToolEnd(HarnessToolEndArgs),
    /// 写入测试、构建、搜索、修正或验收证据。
    Evaluate(HarnessEvaluateArgs),
    /// 写入 task_end 终态。
    End(HarnessEndArgs),
    /// 将本地 spool 中尚未收到 durable ACK 的事件续投。
    Flush(HarnessFlushArgs),
    /// 查看身份、队列和活动工具。
    Inspect(HarnessInspectArgs),
    /// 更新后续事件使用的 previous_response_id。
    SetPreviousResponse(HarnessSetPreviousResponseArgs),
}

#[derive(Debug, Args)]
struct HarnessStartArgs {
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long)]
    source_namespace: String,
    #[arg(long, conflicts_with = "output")]
    relay_url: Option<String>,
    #[arg(long, conflicts_with = "relay_url")]
    output: Option<PathBuf>,
    #[arg(long)]
    task_session_id: Option<String>,
    #[arg(long)]
    root_session_id: Option<String>,
    #[arg(long)]
    parent_session_id: Option<String>,
    #[arg(long)]
    goal_id: Option<String>,
    #[arg(long)]
    agent_id: Option<String>,
    #[arg(long)]
    branch_id: Option<String>,
    #[arg(long)]
    session_id: Option<String>,
    #[arg(long)]
    thread_id: Option<String>,
    #[arg(long)]
    previous_response_id: Option<String>,
    #[arg(long)]
    traceparent: Option<String>,
    /// Harness 启动时由实际 dispatcher 导出的 Tool Registry JSON。
    #[arg(long)]
    tool_registry: Option<PathBuf>,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
    #[arg(long, default_value_t = 1024)]
    max_envelope_mib: usize,
    #[arg(long, default_value_t = 128)]
    batch_records: usize,
}

#[derive(Debug, Args)]
struct HarnessStateArgs {
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long, conflicts_with = "output")]
    relay_url: Option<String>,
    #[arg(long, conflicts_with = "relay_url")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct HarnessLifecycleArgs {
    #[command(flatten)]
    state: HarnessStateArgs,
    #[arg(long = "type")]
    event_type: String,
    #[arg(long)]
    status: String,
    #[arg(long)]
    reason: Option<String>,
    #[arg(long)]
    turn_id: Option<String>,
    /// JSON 对象或普通文本；作为生命周期 details 保存。
    #[arg(long)]
    details: Option<String>,
    #[arg(long)]
    occurred_at: Option<String>,
}

#[derive(Debug, Args)]
struct HarnessToolStartArgs {
    #[command(flatten)]
    state: HarnessStateArgs,
    #[arg(long)]
    call_id: String,
    #[arg(long)]
    name: String,
    /// Optional dispatcher namespace. Canonical Session identity is
    /// `namespace.name` while the raw components are retained.
    #[arg(long)]
    runtime_namespace: Option<String>,
    /// Optional raw dispatcher tool name when `name` is already canonical.
    #[arg(long)]
    runtime_tool: Option<String>,
    /// JSON 参数；无法解析为 JSON 时按字符串保存，不会改变工具状态。
    #[arg(long)]
    arguments: String,
    /// 完整工具 Schema JSON 文件。缺省时只允许从启动时 Registry 精确查找。
    #[arg(long)]
    schema: Option<PathBuf>,
    #[arg(long, default_value = "assistant")]
    initiator: String,
    #[arg(long)]
    parent_call_id: Option<String>,
    #[arg(long)]
    turn_id: Option<String>,
    #[arg(long)]
    started_at: Option<String>,
}

#[derive(Debug, Args)]
struct HarnessToolEndArgs {
    #[command(flatten)]
    state: HarnessStateArgs,
    #[arg(long)]
    call_id: String,
    #[arg(long)]
    status: String,
    /// JSON 结果；无法解析时按字符串保存。
    #[arg(long)]
    result: Option<String>,
    /// JSON 错误；无法解析时按字符串保存。
    #[arg(long)]
    error: Option<String>,
    #[arg(long)]
    finished_at: Option<String>,
}

#[derive(Debug, Args)]
struct HarnessEvaluateArgs {
    #[command(flatten)]
    state: HarnessStateArgs,
    #[arg(long)]
    kind: String,
    #[arg(long)]
    source: String,
    #[arg(long)]
    status: Option<String>,
    #[arg(long)]
    passed: Option<bool>,
    #[arg(long)]
    reward: Option<f64>,
    #[arg(long)]
    score: Option<f64>,
    #[arg(long)]
    artifact: Option<String>,
    #[arg(long)]
    observed_at: Option<String>,
}

#[derive(Debug, Args)]
struct HarnessEndArgs {
    #[command(flatten)]
    state: HarnessStateArgs,
    #[arg(long, default_value = "completed")]
    status: String,
    #[arg(long)]
    reason: Option<String>,
}

#[derive(Debug, Args)]
struct HarnessFlushArgs {
    #[command(flatten)]
    state: HarnessStateArgs,
}

#[derive(Debug, Args)]
struct HarnessInspectArgs {
    #[arg(long)]
    state_root: PathBuf,
}

#[derive(Debug, Args)]
struct HarnessSetPreviousResponseArgs {
    #[command(flatten)]
    state: HarnessStateArgs,
    #[arg(long)]
    value: Option<String>,
}

#[derive(Debug, Args)]
struct ExportCodexTraceBundleArgs {
    /// 原生 Codex trace bundle 目录（manifest.json、trace.jsonl、payloads/）。
    #[arg(long)]
    input: PathBuf,
    /// exporter checkpoint 目录。
    #[arg(long)]
    state_root: PathBuf,
    /// Rust Relay 地址；与 --output 二选一。
    #[arg(long, conflicts_with = "output")]
    relay_url: Option<String>,
    /// 本地验证用 Capture JSONL；与 --relay-url 二选一。
    #[arg(long, conflicts_with = "relay_url")]
    output: Option<PathBuf>,
    #[arg(long)]
    source_namespace: String,
    /// Harness 在任务开始时导出的实际运行时 Tool Registry 快照。
    #[arg(long)]
    tool_registry: Option<PathBuf>,
    #[arg(long, default_value_t = 128)]
    batch_records: usize,
    #[arg(long, default_value_t = 1024)]
    max_envelope_mib: usize,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    /// Harness 显式创建的完整任务 Session ID；不会从 Codex thread 推断。
    #[arg(long)]
    task_session_id: Option<String>,
    #[arg(long)]
    root_session_id: Option<String>,
    #[arg(long)]
    parent_session_id: Option<String>,
    #[arg(long)]
    goal_id: Option<String>,
    #[arg(long)]
    agent_id: Option<String>,
    #[arg(long)]
    branch_id: Option<String>,
    /// Harness 生成并注入 API 的同一 W3C traceparent。
    #[arg(long)]
    traceparent: Option<String>,
    /// 原始 event/payload 字节镜像目录；默认位于 state_root/raw-bundles。
    #[arg(long)]
    mirror_root: Option<PathBuf>,
    /// 要求 bundle 已观察到 rollout_ended 且没有活动尾部。
    #[arg(long)]
    require_complete: bool,
}

#[derive(Debug, Args)]
struct CodexRunArgs {
    /// 启用了 Runtime Tool Registry producer 补丁的 Codex ELF；不能传通用 launcher。
    #[arg(long)]
    codex_bin: PathBuf,
    /// Codex 任务工作目录。
    #[arg(long, default_value = ".")]
    working_directory: PathBuf,
    /// 本任务的 Harness、checkpoint 和 Raw mirror 根目录。
    #[arg(long)]
    state_root: PathBuf,
    /// 本任务独占且启动前必须为空的原生 bundle 目录。
    #[arg(long)]
    trace_root: Option<PathBuf>,
    #[arg(long)]
    source_namespace: String,
    /// 单进程任务，或同一显式任务的开始、继续、结束阶段。
    #[arg(long, value_enum, default_value = "single")]
    task_phase: CodexTaskPhase,
    #[arg(long, conflicts_with = "output")]
    relay_url: Option<String>,
    #[arg(long, conflicts_with = "relay_url")]
    output: Option<PathBuf>,
    /// 共享 Codex 配置中的 provider key。
    #[arg(long, default_value = "OpenAI")]
    model_provider_id: String,
    /// 可选的任务级 API 入口覆盖，例如 http://gateway.internal:18084/。
    #[arg(long)]
    model_base_url: Option<String>,
    #[arg(long)]
    task_session_id: Option<String>,
    #[arg(long)]
    root_session_id: Option<String>,
    #[arg(long)]
    parent_session_id: Option<String>,
    #[arg(long)]
    goal_id: Option<String>,
    #[arg(long)]
    agent_id: Option<String>,
    #[arg(long)]
    branch_id: Option<String>,
    #[arg(long)]
    session_id: Option<String>,
    #[arg(long)]
    thread_id: Option<String>,
    #[arg(long)]
    previous_response_id: Option<String>,
    #[arg(long)]
    traceparent: Option<String>,
    /// 外部 Tool Registry 只用于旧 bundle 兼容；新 Codex 应内联实际快照。
    #[arg(long)]
    tool_registry: Option<PathBuf>,
    #[arg(long, default_value_t = 250)]
    poll_ms: u64,
    #[arg(long, default_value_t = 30)]
    shutdown_grace_seconds: u64,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    #[arg(long, default_value_t = 25)]
    provider_request_max_retries: u64,
    #[arg(long, default_value_t = 25)]
    provider_stream_max_retries: u64,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
    #[arg(long, default_value_t = 1024)]
    max_envelope_mib: usize,
    #[arg(long, default_value_t = 128)]
    batch_records: usize,
    /// `--` 后原样传给 Codex，例如 `exec --json "任务"`。
    #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
    codex_args: Vec<String>,
}

#[derive(Debug, Args)]
struct VerifyEnrichmentArgs {
    #[arg(long)]
    enrichment: PathBuf,
}

#[derive(Debug, Args)]
struct ReleaseArgs {
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    release_id: String,
    #[arg(long, value_enum, default_value = "buyer-v7-codex-runtime-expanded")]
    profile: Profile,
    #[arg(long, default_value_t = 90.0)]
    minimum_score: f64,
    #[arg(long, default_value_t = 10.0)]
    target_part_gib: f64,
    #[arg(long, default_value_t = 256)]
    dedup_partitions: usize,
    #[arg(long, default_value_t = 1)]
    zstd_level: i32,
    #[arg(long, default_value_t = 0)]
    workers: usize,
    #[arg(long)]
    replace: bool,
}

#[derive(Debug, Args)]
struct VerifyAssemblyArgs {
    #[arg(long)]
    assembly: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyReleaseArgs {
    #[arg(long)]
    release: PathBuf,
    #[arg(long)]
    require_pass: bool,
}

#[derive(Debug, Args)]
struct PackageBuyerArgs {
    #[arg(long)]
    release: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 1)]
    gzip_level: u32,
    #[arg(long, default_value_t = 0)]
    workers: usize,
    #[arg(long)]
    replace: bool,
    /// 仅迁移没有 OSS Raw lineage 的历史 Release；不适用于对外交付。
    #[arg(long)]
    allow_legacy_lineage: bool,
}

#[derive(Debug, Args)]
struct VerifyBuyerPackageArgs {
    #[arg(long)]
    package: PathBuf,
    /// 允许验证仅供历史迁移使用的 legacy_unbound 包。
    #[arg(long)]
    allow_legacy_lineage: bool,
}

#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("artifact")
        .required(true)
        .args(["release", "buyer_package"])
))]
struct PublishArgs {
    #[arg(long)]
    release: Option<PathBuf>,
    #[arg(long)]
    buyer_package: Option<PathBuf>,
    #[arg(long, value_enum)]
    backend: Backend,
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    bucket: Option<String>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long, default_value = "chiptrace")]
    prefix: String,
    #[arg(long, default_value_t = 8)]
    file_concurrency: usize,
    #[arg(long, default_value_t = 8)]
    multipart_concurrency: usize,
    #[arg(long, default_value_t = 16)]
    multipart_chunk_mib: usize,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    /// 仅用于受控 staging；跳过远端对象的完整 SHA-256 回读。
    #[arg(long)]
    skip_remote_sha256: bool,
}

#[derive(Debug, Args)]
struct VerifyPublishedArgs {
    #[arg(long, value_enum)]
    artifact_kind: ArtifactKind,
    #[arg(long)]
    artifact_id: String,
    #[arg(long, value_enum)]
    backend: Backend,
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    bucket: Option<String>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long, default_value = "chiptrace")]
    prefix: String,
    #[arg(long, default_value_t = 8)]
    file_concurrency: usize,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
}

#[derive(Debug, Args)]
struct RawArchiveArgs {
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    #[arg(long)]
    archive_id: String,
    #[arg(long, value_enum)]
    backend: Backend,
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    bucket: Option<String>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long, default_value = "chiptrace")]
    prefix: String,
    #[arg(long, default_value_t = 8)]
    file_concurrency: usize,
    #[arg(long, default_value_t = 8)]
    multipart_concurrency: usize,
    #[arg(long, default_value_t = 16)]
    multipart_chunk_mib: usize,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    #[arg(long)]
    allow_segment_gaps: bool,
}

#[derive(Debug, Args)]
struct VerifyRawArchiveArgs {
    #[arg(long)]
    archive_id: String,
    #[arg(long, value_enum)]
    backend: Backend,
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    bucket: Option<String>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long, default_value = "chiptrace")]
    prefix: String,
    #[arg(long)]
    verify_records: bool,
    /// 仅允许校验取证用的 partial 快照；默认拒绝。
    #[arg(long)]
    allow_partial: bool,
}

#[derive(Debug, Args)]
struct RestoreRawArchiveArgs {
    #[arg(long)]
    archive_id: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum)]
    backend: Backend,
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    bucket: Option<String>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long, default_value = "chiptrace")]
    prefix: String,
    #[arg(long)]
    verify_records: bool,
    #[arg(long)]
    replace: bool,
    #[arg(long)]
    allow_partial: bool,
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[arg(long, default_value = "http://127.0.0.1:3010/health")]
    url: String,
    #[arg(long, default_value_t = 5)]
    timeout_seconds: u64,
}

#[derive(Debug, Args)]
struct RuntimeCanaryArgs {
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long)]
    source_namespace: String,
    #[arg(long)]
    relay_url: String,
    #[arg(long)]
    task_session_id: String,
    #[arg(long)]
    root_session_id: Option<String>,
    #[arg(long)]
    goal_id: Option<String>,
    #[arg(long, default_value = "runtime-canary")]
    agent_id: String,
    #[arg(long, default_value = "main")]
    branch_id: String,
    #[arg(long)]
    collector_health_url: String,
    #[arg(long)]
    evidence_jsonl: PathBuf,
    #[arg(long)]
    expected_missing_path: PathBuf,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
}

#[derive(Debug, Args)]
struct BenchmarkStoreArgs {
    #[arg(long, default_value_t = 100_000)]
    records: u64,
    #[arg(long, default_value_t = 64)]
    payload_kib: usize,
    #[arg(long, default_value_t = 256)]
    concurrency: usize,
    #[arg(long, default_value_t = 1)]
    store_shards: usize,
    #[arg(long)]
    work_root: Option<PathBuf>,
    #[arg(long)]
    no_fsync: bool,
}

#[derive(Debug, Args)]
struct BenchmarkHttpArgs {
    #[arg(long, default_value_t = 10_000)]
    records: u64,
    #[arg(long, default_value_t = 64)]
    payload_kib: usize,
    #[arg(long, default_value_t = 64)]
    batch_records: usize,
    #[arg(long, default_value_t = 16)]
    concurrency: usize,
    #[arg(long, default_value_t = 1)]
    store_shards: usize,
    #[arg(long)]
    work_root: Option<PathBuf>,
    #[arg(long)]
    no_fsync: bool,
    /// 经 Relay 本地 outbox 续投 Collector，并等待最终守恒。
    #[arg(long)]
    relay: bool,
    /// 使用 Harness/dispatcher producer 事件入口；必须同时启用 --relay。
    #[arg(long, requires = "relay")]
    producer_events: bool,
}

#[derive(Debug, Args)]
struct BenchmarkCompressionArgs {
    #[arg(long, default_value_t = 10_000)]
    records: u64,
    #[arg(long, default_value_t = 64)]
    payload_kib: usize,
    #[arg(long, default_value_t = 1)]
    level: i32,
    #[arg(long, default_value_t = 4)]
    streams: usize,
    #[arg(long, default_value_t = 1)]
    workers_per_stream: u32,
    #[arg(long)]
    work_root: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let output = match cli.command {
        Command::Collector(args) => {
            let bind = SocketAddr::new(args.host, args.port);
            serve(
                CollectorConfig {
                    bind,
                    store: store_config(&args),
                    store_shards: args.store_shards,
                    max_connections: args.max_connections,
                    max_envelope_bytes: checked_mib(args.max_envelope_mib)?,
                    max_inflight_body_bytes: checked_mib(args.max_inflight_body_mib)?,
                    max_batch_records: args.max_batch_records,
                },
                shutdown_signal(),
            )
            .await?;
            return Ok(());
        }
        Command::Relay(args) => {
            let producer_bearer_token = std::env::var("CHIPTRACE_PRODUCER_TOKEN")
                .ok()
                .filter(|value| !value.trim().is_empty());
            if producer_bearer_token.is_none() && !args.allow_unauthenticated_producer {
                bail!(
                    "CHIPTRACE_PRODUCER_TOKEN is required; use --allow-unauthenticated-producer only in isolated development"
                );
            }
            if producer_bearer_token
                .as_deref()
                .is_some_and(|value| value.trim().len() < 32)
            {
                bail!("CHIPTRACE_PRODUCER_TOKEN must contain at least 32 bytes after trimming");
            }
            serve_relay(
                RelayConfig {
                    bind: SocketAddr::new(args.host, args.port),
                    store: StoreConfig {
                        root: args.root,
                        state_root: args.state_root,
                        segment_max_bytes: args.segment_max_mib.saturating_mul(1024 * 1024),
                        segment_max_age: Duration::from_secs(args.segment_max_age_seconds),
                        queue_items: args.queue_items,
                        batch_records: args.batch_records,
                        batch_bytes: args.batch_mib.saturating_mul(1024 * 1024),
                        batch_wait: Duration::from_millis(args.batch_wait_ms),
                        fsync: true,
                    },
                    store_shards: args.store_shards,
                    delivery_state_root: args.delivery_state_root,
                    collector_url: args.collector_url,
                    delivery_concurrency: args.delivery_concurrency,
                    delivery_queue_items: args.delivery_queue_items,
                    delivery_batch_records: args.delivery_batch_records,
                    delivery_batch_bytes: checked_mib(args.delivery_batch_mib)?,
                    delivery_batch_wait: Duration::from_millis(args.delivery_batch_wait_ms),
                    max_delivery_inflight_bytes: checked_mib(args.max_delivery_inflight_mib)?,
                    request_timeout: Duration::from_secs(args.request_timeout_seconds),
                    base_retry_delay: Duration::from_millis(250),
                    max_retry_delay: Duration::from_secs(30),
                    max_connections: args.max_connections,
                    max_envelope_bytes: checked_mib(args.max_envelope_mib)?,
                    max_inflight_body_bytes: checked_mib(args.max_inflight_body_mib)?,
                    max_batch_records: args.max_batch_records,
                    producer_bearer_token,
                },
                shutdown_signal(),
            )
            .await?;
            return Ok(());
        }
        Command::Audit(args) => audit_sharded_store(
            &args.root,
            &args.state_root,
            args.store_shards,
            args.verify_payloads,
        )?,
        Command::Assemble(args) => serde_json::to_value(assemble(AssembleConfig {
            inputs: args.input,
            output: args.output,
            partitions: args.partitions,
            zstd_level: args.zstd_level,
            replace: args.replace,
        })?)?,
        Command::ProjectInteractions(args) => {
            serde_json::to_value(project_interactions(InteractionProjectConfig {
                inputs: args.input,
                output: args.output,
                task_session_id: args.task_session_id,
                session_id: args.session_id,
                zstd_level: args.zstd_level,
                replace: args.replace,
            })?)?
        }
        Command::VerifyInteractions(args) => {
            serde_json::to_value(verify_interaction_projection(&args.projection)?)?
        }
        Command::ExportOtlp(args) => serde_json::to_value(export_otlp(OtlpExportConfig {
            projection: args.projection,
            output: args.output,
            zstd_level: args.zstd_level,
            replace: args.replace,
        })?)?,
        Command::VerifyOtlp(args) => serde_json::to_value(verify_otlp_export(&args.projection)?)?,
        Command::Score(args) => serde_json::to_value(score_jsonl(
            &args.input,
            &args.output,
            args.profile,
            args.minimum_score,
            args.zstd_level,
        )?)?,
        Command::Enrich(args) => serde_json::to_value(enrich_captures(EnrichConfig {
            inputs: args.input,
            usage_logs: args.usage_log,
            output: args.output,
            zstd_level: args.zstd_level,
            replace: args.replace,
        })?)?,
        Command::ExportCodexRollout(args) => {
            let target = match (args.relay_url, args.output) {
                (Some(url), None) => CodexRolloutTarget::Relay(url),
                (None, Some(path)) => CodexRolloutTarget::Jsonl(path),
                _ => bail!("exactly one of --relay-url or --output is required"),
            };
            serde_json::to_value(
                export_codex_rollout(CodexRolloutExportConfig {
                    input: args.input,
                    state_root: args.state_root,
                    target,
                    source_namespace: args.source_namespace,
                    tool_registry: args.tool_registry,
                    batch_records: args.batch_records,
                    max_envelope_bytes: checked_mib(args.max_envelope_mib)?,
                    request_timeout: Duration::from_secs(args.request_timeout_seconds),
                    retry_max_times: args.retry_max_times,
                    task_session_id: args.task_session_id,
                    root_session_id: args.root_session_id,
                    parent_session_id: args.parent_session_id,
                    goal_id: args.goal_id,
                })
                .await?,
            )?
        }
        Command::WatchCodexRollout(args) => {
            let export = args.export;
            let target = match (export.relay_url, export.output) {
                (Some(url), None) => CodexRolloutTarget::Relay(url),
                (None, Some(path)) => CodexRolloutTarget::Jsonl(path),
                _ => bail!("exactly one of --relay-url or --output is required"),
            };
            let idle_exit =
                (args.idle_exit_seconds > 0).then(|| Duration::from_secs(args.idle_exit_seconds));
            serde_json::to_value(
                watch_codex_rollout(
                    CodexRolloutExportConfig {
                        input: export.input,
                        state_root: export.state_root,
                        target,
                        source_namespace: export.source_namespace,
                        tool_registry: export.tool_registry,
                        batch_records: export.batch_records,
                        max_envelope_bytes: checked_mib(export.max_envelope_mib)?,
                        request_timeout: Duration::from_secs(export.request_timeout_seconds),
                        retry_max_times: export.retry_max_times,
                        task_session_id: export.task_session_id,
                        root_session_id: export.root_session_id,
                        parent_session_id: export.parent_session_id,
                        goal_id: export.goal_id,
                    },
                    Duration::from_millis(args.poll_ms),
                    idle_exit,
                    shutdown_signal(),
                )
                .await?,
            )?
        }
        Command::CodexHook(args) => {
            let target = match (args.relay_url, args.output) {
                (Some(url), None) => CodexRolloutTarget::Relay(url),
                (None, Some(path)) => CodexRolloutTarget::Jsonl(path),
                _ => bail!("exactly one of --relay-url or --output is required"),
            };
            let mut hook_input = Vec::new();
            std::io::stdin().read_to_end(&mut hook_input)?;
            let input = resolve_hook_rollout(&hook_input, &args.session_root)?;
            serde_json::to_value(
                export_codex_rollout(CodexRolloutExportConfig {
                    input,
                    state_root: args.state_root,
                    target,
                    source_namespace: args.source_namespace,
                    tool_registry: args.tool_registry,
                    batch_records: args.batch_records,
                    max_envelope_bytes: checked_mib(args.max_envelope_mib)?,
                    request_timeout: Duration::from_secs(args.request_timeout_seconds),
                    retry_max_times: args.retry_max_times,
                    task_session_id: args.task_session_id,
                    root_session_id: args.root_session_id,
                    parent_session_id: args.parent_session_id,
                    goal_id: args.goal_id,
                })
                .await?,
            )?
        }
        Command::CodexHookSpool(args) => {
            let max_input_bytes = checked_mib(args.max_input_mib)?;
            let mut hook_input = Vec::new();
            std::io::stdin()
                .take(max_input_bytes.saturating_add(1) as u64)
                .read_to_end(&mut hook_input)?;
            spool_hook_event(
                &hook_input,
                &HookSpoolConfig {
                    queue_root: args.queue_root,
                    max_input_bytes,
                },
            )?;
            // Command hooks must not print the regular CLI JSON summary to stdout.
            return Ok(());
        }
        Command::CodexAgent(args) => serde_json::to_value(
            run_codex_agent(
                CodexAgentConfig {
                    queue_root: args.queue_root,
                    session_root: args.session_root,
                    state_root: args.state_root,
                    target: producer_relay_target(args.relay_url)?,
                    source_namespace: args.source_namespace,
                    batch_records: args.batch_records,
                    max_envelope_bytes: checked_mib(args.max_envelope_mib)?,
                    request_timeout: Duration::from_secs(args.request_timeout_seconds),
                    retry_max_times: args.retry_max_times,
                    poll_interval: Duration::from_millis(args.poll_ms),
                    once: args.once,
                },
                shutdown_signal(),
            )
            .await?,
        )?,
        Command::ExportCodexTraceBundle(args) => {
            let target = match (args.relay_url, args.output) {
                (Some(url), None) => CodexTraceBundleTarget::Relay(url),
                (None, Some(path)) => CodexTraceBundleTarget::Jsonl(path),
                _ => bail!("exactly one of --relay-url or --output is required"),
            };
            serde_json::to_value(
                export_codex_trace_bundle(CodexTraceBundleExportConfig {
                    input: args.input,
                    state_root: args.state_root,
                    target,
                    source_namespace: args.source_namespace,
                    tool_registry: args.tool_registry,
                    batch_records: args.batch_records,
                    max_envelope_bytes: checked_mib(args.max_envelope_mib)?,
                    request_timeout: Duration::from_secs(args.request_timeout_seconds),
                    retry_max_times: args.retry_max_times,
                    task_session_id: args.task_session_id,
                    root_session_id: args.root_session_id,
                    parent_session_id: args.parent_session_id,
                    goal_id: args.goal_id,
                    agent_id: args.agent_id,
                    branch_id: args.branch_id,
                    traceparent: args.traceparent,
                    mirror_root: args.mirror_root,
                    require_complete: args.require_complete,
                })
                .await?,
            )?
        }
        Command::CodexRun(args) => {
            let target = match (args.relay_url, args.output) {
                (Some(url), None) => CodexRunTarget::Relay(url),
                (None, Some(path)) => CodexRunTarget::Jsonl(path),
                _ => bail!("exactly one of --relay-url or --output is required"),
            };
            serde_json::to_value(
                run_codex(CodexRunConfig {
                    codex_bin: args.codex_bin,
                    codex_args: args.codex_args,
                    working_directory: args.working_directory,
                    state_root: args.state_root,
                    trace_root: args.trace_root,
                    source_namespace: args.source_namespace,
                    target,
                    task_phase: args.task_phase,
                    model_provider_id: args.model_provider_id,
                    model_base_url: args.model_base_url,
                    task_session_id: args.task_session_id,
                    root_session_id: args.root_session_id,
                    parent_session_id: args.parent_session_id,
                    goal_id: args.goal_id,
                    agent_id: args.agent_id,
                    branch_id: args.branch_id,
                    session_id: args.session_id,
                    thread_id: args.thread_id,
                    previous_response_id: args.previous_response_id,
                    traceparent: args.traceparent,
                    tool_registry: args.tool_registry,
                    poll_interval: Duration::from_millis(args.poll_ms),
                    shutdown_grace: Duration::from_secs(args.shutdown_grace_seconds),
                    retry_max_times: args.retry_max_times,
                    provider_request_max_retries: args.provider_request_max_retries,
                    provider_stream_max_retries: args.provider_stream_max_retries,
                    request_timeout: Duration::from_secs(args.request_timeout_seconds),
                    max_envelope_bytes: checked_mib(args.max_envelope_mib)?,
                    batch_records: args.batch_records,
                })
                .await?,
            )?
        }
        Command::Produce(args) => {
            let target = match (args.relay_url, args.output) {
                (Some(url), None) => producer_relay_target(url)?,
                (None, Some(path)) => ProducerTarget::Jsonl(path),
                _ => bail!("exactly one of --relay-url or --output is required"),
            };
            serde_json::to_value(
                submit_producer_events(ProducerConfig {
                    input: args.input,
                    target,
                    batch_records: args.batch_records,
                    max_envelope_bytes: checked_mib(args.max_envelope_mib)?,
                    request_timeout: Duration::from_secs(args.request_timeout_seconds),
                    retry_max_times: args.retry_max_times,
                })
                .await?,
            )?
        }
        Command::Harness(args) => match args.command {
            HarnessCommand::Start(args) => harness_start(args).await?,
            HarnessCommand::Lifecycle(args) => harness_lifecycle(args).await?,
            HarnessCommand::ToolStart(args) => harness_tool_start(args).await?,
            HarnessCommand::ToolEnd(args) => harness_tool_end(args).await?,
            HarnessCommand::Evaluate(args) => harness_evaluate(args).await?,
            HarnessCommand::End(args) => harness_end(args).await?,
            HarnessCommand::Flush(args) => harness_flush(args).await?,
            HarnessCommand::Inspect(args) => {
                serde_json::to_value(Harness::open(args.state_root)?.inspect()?)?
            }
            HarnessCommand::SetPreviousResponse(args) => {
                let target = harness_target(args.state.relay_url, args.state.output)?;
                let mut harness =
                    chiptrace::harness::Harness::open_with_target(args.state.state_root, target)?;
                harness.set_previous_response_id(args.value)?;
                serde_json::to_value(harness.inspect()?)?
            }
        },
        Command::VerifyEnrichment(args) => {
            serde_json::to_value(verify_enrichment(&args.enrichment)?)?
        }
        Command::Release(args) => {
            if !args.target_part_gib.is_finite() || args.target_part_gib <= 0.0 {
                bail!("target_part_gib must be positive");
            }
            serde_json::to_value(build_release(ReleaseConfig {
                inputs: args.input,
                output: args.output,
                release_id: args.release_id,
                profile: args.profile,
                minimum_score: args.minimum_score,
                target_part_bytes: (args.target_part_gib * 1024.0 * 1024.0 * 1024.0) as u64,
                dedup_partitions: args.dedup_partitions,
                zstd_level: args.zstd_level,
                workers: args.workers,
                replace: args.replace,
            })?)?
        }
        Command::VerifyAssembly(args) => serde_json::to_value(verify_assembly(&args.assembly)?)?,
        Command::VerifyRelease(args) => {
            serde_json::to_value(verify_release(&args.release, args.require_pass)?)?
        }
        Command::PackageBuyer(args) => {
            let config = BuyerPackageConfig {
                release: args.release,
                output: args.output,
                gzip_level: args.gzip_level,
                workers: args.workers,
                replace: args.replace,
            };
            serde_json::to_value(if args.allow_legacy_lineage {
                package_buyer_release_legacy(config)?
            } else {
                package_buyer_release(config)?
            })?
        }
        Command::VerifyBuyerPackage(args) => serde_json::to_value(if args.allow_legacy_lineage {
            verify_buyer_package_legacy(&args.package)?
        } else {
            verify_buyer_package(&args.package)?
        })?,
        Command::Publish(args) => {
            let source = match (args.release, args.buyer_package) {
                (Some(path), None) => PublishSource::Release(path),
                (None, Some(path)) => PublishSource::BuyerPackage(path),
                _ => bail!("exactly one of --release or --buyer-package is required"),
            };
            serde_json::to_value(
                publish(PublishConfig {
                    source,
                    backend: args.backend,
                    root: args.root,
                    endpoint: args.endpoint,
                    bucket: args.bucket,
                    region: args.region,
                    prefix: args.prefix,
                    file_concurrency: args.file_concurrency,
                    multipart_concurrency: args.multipart_concurrency,
                    multipart_chunk_bytes: checked_mib(args.multipart_chunk_mib)?,
                    retry_max_times: args.retry_max_times,
                    verify_remote_sha256: !args.skip_remote_sha256,
                })
                .await?,
            )?
        }
        Command::VerifyPublished(args) => serde_json::to_value(
            verify_published(VerifyPublishedConfig {
                artifact_kind: args.artifact_kind,
                artifact_id: args.artifact_id,
                backend: args.backend,
                root: args.root,
                endpoint: args.endpoint,
                bucket: args.bucket,
                region: args.region,
                prefix: args.prefix,
                file_concurrency: args.file_concurrency,
                retry_max_times: args.retry_max_times,
            })
            .await?,
        )?,
        Command::ArchiveRaw(args) => serde_json::to_value(
            archive_raw(RawArchiveConfig {
                inputs: args.input,
                archive_id: args.archive_id,
                backend: args.backend,
                root: args.root,
                endpoint: args.endpoint,
                bucket: args.bucket,
                region: args.region,
                prefix: args.prefix,
                file_concurrency: args.file_concurrency,
                multipart_concurrency: args.multipart_concurrency,
                multipart_chunk_bytes: checked_mib(args.multipart_chunk_mib)?,
                retry_max_times: args.retry_max_times,
                allow_segment_gaps: args.allow_segment_gaps,
            })
            .await?,
        )?,
        Command::VerifyRawArchive(args) => serde_json::to_value(
            verify_raw_archive(RawArchiveVerifyConfig {
                archive_id: args.archive_id,
                backend: args.backend,
                root: args.root,
                endpoint: args.endpoint,
                bucket: args.bucket,
                region: args.region,
                prefix: args.prefix,
                verify_records: args.verify_records,
                allow_partial: args.allow_partial,
            })
            .await?,
        )?,
        Command::RestoreRawArchive(args) => serde_json::to_value(
            restore_raw_archive(RawArchiveRestoreConfig {
                archive_id: args.archive_id,
                output: args.output,
                backend: args.backend,
                root: args.root,
                endpoint: args.endpoint,
                bucket: args.bucket,
                region: args.region,
                prefix: args.prefix,
                verify_records: args.verify_records,
                replace: args.replace,
                allow_partial: args.allow_partial,
            })
            .await?,
        )?,
        Command::Probe(args) => probe(args).await?,
        Command::SelfTest => self_test().await?,
        Command::RuntimeCanary(args) => serde_json::to_value(
            run_runtime_canary(RuntimeCanaryConfig {
                state_root: args.state_root,
                source_namespace: args.source_namespace,
                relay_url: args.relay_url,
                task_session_id: args.task_session_id,
                root_session_id: args.root_session_id,
                goal_id: args.goal_id,
                agent_id: Some(args.agent_id),
                branch_id: Some(args.branch_id),
                collector_health_url: args.collector_health_url,
                evidence_jsonl: args.evidence_jsonl,
                expected_missing_path: args.expected_missing_path,
                retry_max_times: args.retry_max_times,
                request_timeout: Duration::from_secs(args.request_timeout_seconds),
            })
            .await?,
        )?,
        Command::BenchmarkStore(args) => benchmark_store(args).await?,
        Command::BenchmarkHttp(args) => benchmark_http(args).await?,
        Command::BenchmarkCompression(args) => benchmark_compression(args)?,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn probe(args: ProbeArgs) -> Result<Value> {
    if args.timeout_seconds == 0 {
        bail!("timeout_seconds must be positive");
    }
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout_seconds))
        .build()?
        .get(&args.url)
        .send()
        .await
        .with_context(|| format!("probe {}", args.url))?;
    let status = response.status();
    let value: Value = response
        .json()
        .await
        .with_context(|| format!("parse health response from {}", args.url))?;
    let healthy = value.get("ok").and_then(Value::as_bool) == Some(true)
        || value.get("status").and_then(Value::as_str) == Some("healthy");
    if !status.is_success() || !healthy {
        bail!("health probe failed: HTTP {status}: {value}");
    }
    Ok(json!({
        "ok": true,
        "url": args.url,
        "http_status": status.as_u16(),
    }))
}

fn store_config(args: &CollectorArgs) -> StoreConfig {
    StoreConfig {
        root: args.root.clone(),
        state_root: args.state_root.clone(),
        segment_max_bytes: args.segment_max_mib.saturating_mul(1024 * 1024),
        segment_max_age: Duration::from_secs(args.segment_max_age_seconds),
        queue_items: args.queue_items,
        batch_records: args.batch_records,
        batch_bytes: args.batch_mib.saturating_mul(1024 * 1024),
        batch_wait: Duration::from_millis(args.batch_wait_ms),
        fsync: !args.no_fsync,
    }
}

fn checked_mib(value: usize) -> Result<usize> {
    value
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("MiB value overflows usize"))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn self_test() -> Result<Value> {
    let temporary = tempfile::tempdir()?;
    let capture_root = temporary.path().join("capture");
    let collector_bind = reserve_local_address()?;
    let (collector_shutdown_tx, collector_shutdown_rx) = tokio::sync::oneshot::channel();
    let collector = tokio::spawn(serve(
        CollectorConfig {
            bind: collector_bind,
            store: StoreConfig {
                root: capture_root.clone(),
                state_root: temporary.path().join("collector-state"),
                segment_max_bytes: 1024 * 1024,
                segment_max_age: Duration::from_secs(60),
                queue_items: 64,
                batch_records: 16,
                batch_bytes: 2 * 1024 * 1024,
                batch_wait: Duration::from_millis(1),
                fsync: true,
            },
            store_shards: 1,
            max_connections: 32,
            max_envelope_bytes: 4 * 1024 * 1024,
            max_inflight_body_bytes: 16 * 1024 * 1024,
            max_batch_records: 64,
        },
        async move {
            let _ = collector_shutdown_rx.await;
        },
    ));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    wait_for_health(&client, &format!("http://{collector_bind}/health")).await?;
    let relay_bind = reserve_local_address()?;
    let (relay_shutdown_tx, relay_shutdown_rx) = tokio::sync::oneshot::channel();
    let relay = tokio::spawn(serve_relay(
        RelayConfig {
            bind: relay_bind,
            store: StoreConfig {
                root: temporary.path().join("outbox"),
                state_root: temporary.path().join("outbox-state"),
                segment_max_bytes: 1024 * 1024,
                segment_max_age: Duration::from_secs(60),
                queue_items: 64,
                batch_records: 16,
                batch_bytes: 2 * 1024 * 1024,
                batch_wait: Duration::from_millis(1),
                fsync: true,
            },
            store_shards: 1,
            delivery_state_root: temporary.path().join("delivery-state"),
            collector_url: format!("http://{collector_bind}"),
            delivery_concurrency: 2,
            delivery_queue_items: 64,
            delivery_batch_records: 16,
            delivery_batch_bytes: 2 * 1024 * 1024,
            delivery_batch_wait: Duration::from_millis(1),
            max_delivery_inflight_bytes: 16 * 1024 * 1024,
            request_timeout: Duration::from_secs(5),
            base_retry_delay: Duration::from_millis(5),
            max_retry_delay: Duration::from_millis(50),
            max_connections: 32,
            max_envelope_bytes: 4 * 1024 * 1024,
            max_inflight_body_bytes: 16 * 1024 * 1024,
            max_batch_records: 64,
            producer_bearer_token: None,
        },
        async move {
            let _ = relay_shutdown_rx.await;
        },
    ));
    wait_for_health(&client, &format!("http://{relay_bind}/health")).await?;
    // Generate lifecycle, dispatcher and evaluator records through the same
    // public Harness API used by production producers.  API snapshots remain
    // a deterministic fixture, while producer semantics are exercised as a
    // real durable spool and resume path.
    let harness_events = self_test_harness_events(temporary.path()).await?;
    let mut captures = self_test_captures();
    captures.retain(|capture| capture["recordType"] == "api_snapshot");
    captures.extend(harness_events);
    let api_snapshots: Vec<&Value> = captures
        .iter()
        .filter(|capture| capture["recordType"] == "api_snapshot")
        .collect();
    let producer_events: Vec<&Value> = captures
        .iter()
        .filter(|capture| capture["recordType"] != "api_snapshot")
        .collect();
    let mut submission_routes = Vec::new();
    for (route, records) in [
        ("captures", api_snapshots.as_slice()),
        ("producer/events", producer_events.as_slice()),
    ] {
        let mut body = Vec::new();
        for record in records {
            body.extend_from_slice(&serde_json::to_vec(record)?);
            body.push(b'\n');
        }
        let response = client
            .post(format!("http://{relay_bind}/{route}"))
            .header("content-type", "application/x-ndjson")
            .body(body)
            .send()
            .await?;
        let status = response.status();
        let result: Value = response.json().await?;
        if !status.is_success()
            || result.get("durable").and_then(Value::as_bool) != Some(true)
            || result.pointer("/counts/total").and_then(Value::as_u64) != Some(records.len() as u64)
        {
            bail!("self-test Relay {route} batch was not durably accepted: {result}");
        }
        submission_routes.push(json!({
            "route":format!("/{route}"),
            "http_status":status.as_u16(),
            "counts":result.get("counts"),
        }));
    }
    let mut producer_replay = Vec::new();
    for record in &producer_events {
        producer_replay.extend_from_slice(&serde_json::to_vec(record)?);
        producer_replay.push(b'\n');
    }
    let replay_response = client
        .post(format!("http://{relay_bind}/producer/events"))
        .header("content-type", "application/x-ndjson")
        .body(producer_replay)
        .send()
        .await?;
    let replay_status = replay_response.status();
    let replay_result: Value = replay_response.json().await?;
    if !replay_status.is_success()
        || replay_result
            .pointer("/counts/duplicates")
            .and_then(Value::as_u64)
            != Some(producer_events.len() as u64)
    {
        bail!("self-test producer replay was not idempotent: {replay_result}");
    }
    let submit_summary = json!({
        "durable":true,
        "records":captures.len(),
        "routes":submission_routes,
        "producer_replay_duplicates":replay_result.pointer("/counts/duplicates"),
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let relay_health = loop {
        let health: Value = client
            .get(format!("http://{relay_bind}/health"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if health.get("delivered").and_then(Value::as_u64) == Some(captures.len() as u64) {
            break health;
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("self-test Relay did not drain its outbox: {health:?}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    client
        .post(format!("http://{relay_bind}/flush"))
        .send()
        .await?
        .error_for_status()?;
    let _ = relay_shutdown_tx.send(());
    relay.await??;
    client
        .post(format!("http://{collector_bind}/flush"))
        .send()
        .await?
        .error_for_status()?;
    let _ = collector_shutdown_tx.send(());
    collector.await??;
    let raw_object_root = temporary.path().join("raw-object-store");
    let raw_archive = archive_raw(RawArchiveConfig {
        inputs: vec![capture_root.clone()],
        archive_id: "self-test-raw".to_owned(),
        backend: Backend::Fs,
        root: Some(raw_object_root.clone()),
        endpoint: None,
        bucket: None,
        region: None,
        prefix: "datasets/chiptrace".to_owned(),
        file_concurrency: 2,
        multipart_concurrency: 1,
        multipart_chunk_bytes: 5 * 1024 * 1024,
        retry_max_times: 3,
        allow_segment_gaps: false,
    })
    .await?;
    let raw_verify = verify_raw_archive(RawArchiveVerifyConfig {
        archive_id: "self-test-raw".to_owned(),
        backend: Backend::Fs,
        root: Some(raw_object_root.clone()),
        endpoint: None,
        bucket: None,
        region: None,
        prefix: "datasets/chiptrace".to_owned(),
        verify_records: true,
        allow_partial: false,
    })
    .await?;
    let raw_restore_root = temporary.path().join("raw-restored");
    let raw_restore = restore_raw_archive(RawArchiveRestoreConfig {
        archive_id: "self-test-raw".to_owned(),
        output: raw_restore_root.clone(),
        backend: Backend::Fs,
        root: Some(raw_object_root),
        endpoint: None,
        bucket: None,
        region: None,
        prefix: "datasets/chiptrace".to_owned(),
        verify_records: true,
        replace: false,
        allow_partial: false,
    })
    .await?;
    let usage_log_path = temporary.path().join("sub2api-usage.jsonl");
    let mut usage_log = Vec::new();
    for ordinal in 1..=5 {
        usage_log.extend_from_slice(&serde_json::to_vec(&json!({
            "id": ordinal,
            "request_id": format!("request-{ordinal}"),
            "requested_model": "gpt-5.6-sol",
            "upstream_model": "gpt-5.6-sol",
            "provider": "OpenAI",
            "input_tokens": 200,
            "output_tokens": 80,
            "cache_read_tokens": 800 + ordinal * 100,
        }))?);
        usage_log.push(b'\n');
    }
    usage_log.extend_from_slice(&serde_json::to_vec(&json!({
        "id": 6,
        "request_id": "request-final",
        "requested_model": "gpt-5.6-sol",
        "upstream_model": "gpt-5.6-sol",
        "provider": "OpenAI",
        "input_tokens": 200,
        "output_tokens": 100,
        "cache_read_tokens": 1800,
    }))?);
    usage_log.push(b'\n');
    fs::write(&usage_log_path, usage_log)?;
    let enriched_root = temporary.path().join("enriched");
    let enrichment = enrich_captures(EnrichConfig {
        inputs: vec![raw_restore_root],
        usage_logs: vec![usage_log_path],
        output: enriched_root.clone(),
        zstd_level: 1,
        replace: false,
    })?;
    let enrichment_verified = verify_enrichment(&enriched_root)?;
    let interaction_root = temporary.path().join("interactions");
    let interaction = project_interactions(InteractionProjectConfig {
        inputs: vec![enriched_root.clone()],
        output: interaction_root.clone(),
        task_session_id: Some("task-self-test-v7".to_owned()),
        session_id: None,
        zstd_level: 1,
        replace: false,
    })?;
    let interaction_verified = verify_interaction_projection(&interaction_root)?;
    let otlp_root = temporary.path().join("otlp");
    let otlp = export_otlp(OtlpExportConfig {
        projection: interaction_root,
        output: otlp_root.clone(),
        zstd_level: 1,
        replace: false,
    })?;
    let otlp_verified = verify_otlp_export(&otlp_root)?;
    let assembly_root = temporary.path().join("assembly");
    let assembly = assemble(AssembleConfig {
        inputs: vec![enriched_root],
        output: assembly_root.clone(),
        partitions: 4,
        zstd_level: 1,
        replace: false,
    })?;
    let release_root = temporary.path().join("release");
    let release = build_release(ReleaseConfig {
        inputs: vec![assembly_root],
        output: release_root.clone(),
        release_id: "self-test-release".to_owned(),
        profile: Profile::BuyerV7,
        minimum_score: 90.0,
        target_part_bytes: 1024 * 1024,
        dedup_partitions: 4,
        zstd_level: 1,
        workers: 4,
        replace: false,
    })?;
    let rejection_diagnostic = if release.validation_status == "pass" {
        None
    } else {
        let report = release
            .reports
            .iter()
            .find(|report| report.file.starts_with("reports/assessments-part-"))
            .context("self-test Release has no assessment report")?;
        let mut reader = chiptrace::jsonl::open_jsonl_reader(&release_root.join(&report.file))?;
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line)?;
        Some(serde_json::from_slice::<Value>(&line)?)
    };
    let verified = verify_release(&release_root, true).with_context(|| {
        format!(
            "self-test release verification failed: counts={:?} failure_reasons={:?} assessment={}",
            release.counts,
            release.failure_reason_counts,
            rejection_diagnostic
                .as_ref()
                .map(Value::to_string)
                .unwrap_or_else(|| "null".to_owned()),
        )
    })?;
    let buyer_root = temporary.path().join("buyer-package");
    let buyer = package_buyer_release(BuyerPackageConfig {
        release: release_root.clone(),
        output: buyer_root.clone(),
        gzip_level: 1,
        workers: 4,
        replace: false,
    })?;
    let verified_buyer = verify_buyer_package(&buyer_root)?;
    let tampered_buyer_root = temporary.path().join("tampered-buyer-package");
    fs::create_dir_all(tampered_buyer_root.join("packages"))?;
    fs::copy(
        buyer_root.join("manifest.json"),
        tampered_buyer_root.join("manifest.json"),
    )?;
    fs::copy(
        buyer_root.join("SHA256SUMS"),
        tampered_buyer_root.join("SHA256SUMS"),
    )?;
    let buyer_archive = buyer
        .packages
        .first()
        .context("self-test buyer package has no archive")?;
    let tampered_archive = tampered_buyer_root.join(&buyer_archive.file);
    fs::copy(buyer_root.join(&buyer_archive.file), &tampered_archive)?;
    OpenOptions::new()
        .append(true)
        .open(&tampered_archive)?
        .write_all(b"tamper")?;
    let buyer_tamper_detected = verify_buyer_package(&tampered_buyer_root).is_err();
    let delivered_part = release
        .parts
        .first()
        .ok_or_else(|| anyhow::anyhow!("self-test Release has no data part"))?;
    let mut reader = chiptrace::jsonl::open_jsonl_reader(&release_root.join(&delivered_part.file))?;
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line)?;
    let delivered: Value = serde_json::from_slice(&line)?;
    let score = delivered
        .pointer("/quality/buyer_acceptance/score")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let hard_gate_pass = delivered
        .pointer("/quality/buyer_acceptance/hard_gate_pass")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let task_dag_complete = delivered
        .pointer("/meta/task_dag/complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let proxy_route_verified = delivered
        .pointer("/meta/model_evidence/proxy_route_verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let provider_identity_attested = delivered
        .pointer("/meta/model_evidence/provider_identity_attested")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let tool_call_statuses: Vec<&str> = delivered
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|message| {
            message
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|call| call.get("execution_status").and_then(Value::as_str))
        .collect();
    let completed_tool_calls = tool_call_statuses
        .iter()
        .filter(|status| matches!(**status, "executed" | "failed"))
        .count();
    let failed_tool_calls = tool_call_statuses
        .iter()
        .filter(|status| **status == "failed")
        .count();
    let semantic_reward_available = delivered
        .pointer("/quality/semantic_quality/reward_available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let tool_execution_audit_pass = delivered
        .pointer("/meta/tool_execution_conflicts")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
        && delivered
            .pointer("/meta/tool_executions")
            .and_then(Value::as_array)
            .is_some_and(|executions| {
                executions.len() == 5
                    && executions.iter().all(|execution| {
                        execution["evidence_mode"] == "producer_state_machine"
                            && execution["state"] == "closed"
                            && execution["started_capture_ids"]
                                .as_array()
                                .is_some_and(|captures| captures.len() == 1)
                            && execution["terminal_capture_ids"]
                                .as_array()
                                .is_some_and(|captures| captures.len() == 1)
                    })
            });
    let producer_stream_audit_pass = delivered
        .pointer("/meta/producer_event_conflicts")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
        && delivered
            .pointer("/meta/producer_streams")
            .and_then(Value::as_array)
            .is_some_and(|streams| {
                streams.len() == 3 && streams.iter().all(|stream| stream["contiguous"] == true)
            });
    let published_object_root = temporary.path().join("object-store");
    let publish_config = PublishConfig {
        source: PublishSource::Release(release_root),
        backend: Backend::Fs,
        root: Some(published_object_root.clone()),
        endpoint: None,
        bucket: None,
        region: None,
        prefix: "self-test".to_owned(),
        file_concurrency: 4,
        multipart_concurrency: 2,
        multipart_chunk_bytes: 5 * 1024 * 1024,
        retry_max_times: 25,
        verify_remote_sha256: true,
    };
    let first_publish = publish(publish_config.clone()).await?;
    let second_publish = publish(publish_config).await?;
    let published_release = verify_published(VerifyPublishedConfig {
        artifact_kind: ArtifactKind::Release,
        artifact_id: "self-test-release".to_owned(),
        backend: Backend::Fs,
        root: Some(published_object_root.clone()),
        endpoint: None,
        bucket: None,
        region: None,
        prefix: "self-test".to_owned(),
        file_concurrency: 4,
        retry_max_times: 25,
    })
    .await?;
    let buyer_publish_config = PublishConfig {
        source: PublishSource::BuyerPackage(buyer_root),
        backend: Backend::Fs,
        root: Some(published_object_root.clone()),
        endpoint: None,
        bucket: None,
        region: None,
        prefix: "self-test".to_owned(),
        file_concurrency: 4,
        multipart_concurrency: 2,
        multipart_chunk_bytes: 5 * 1024 * 1024,
        retry_max_times: 25,
        verify_remote_sha256: true,
    };
    let first_buyer_publish = publish(buyer_publish_config.clone()).await?;
    let second_buyer_publish = publish(buyer_publish_config).await?;
    let published_buyer = verify_published(VerifyPublishedConfig {
        artifact_kind: ArtifactKind::BuyerPackage,
        artifact_id: "self-test-release".to_owned(),
        backend: Backend::Fs,
        root: Some(published_object_root),
        endpoint: None,
        bucket: None,
        region: None,
        prefix: "self-test".to_owned(),
        file_concurrency: 4,
        retry_max_times: 25,
    })
    .await?;
    let self_test_checks = json!({
        "buyer_v7_session_eligible":release.counts.eligible_sessions == 1
            && release.buyer_profile == "buyer-v7-codex-runtime-expanded"
            && score == 100.0
            && hard_gate_pass,
        "task_and_provider_evidence":task_dag_complete
            && proxy_route_verified
            && provider_identity_attested
            && delivered.pointer("/meta/capture_dag").is_some(),
        "tool_projection":completed_tool_calls == 5 && failed_tool_calls == 1,
        "tool_execution_state_machine":tool_execution_audit_pass,
        "producer_stream_conservation":producer_stream_audit_pass,
        "capture_counts":delivered["source_request_count"] == 6
            && delivered["source_capture_count"] == captures.len(),
        "assembly_integrity":assembly.merge_divergences == 0
            && assembly.capture_schema_versions.len() == 1
            && assembly.capture_schema_versions.contains(CAPTURE_SCHEMA_VERSION),
        "relay_delivery_conservation":relay_health.get("delivered").and_then(Value::as_u64)
                == Some(captures.len() as u64)
            && relay_health.get("pending").and_then(Value::as_u64) == Some(0)
            && relay_health.get("inflight").and_then(Value::as_u64) == Some(0)
            && relay_health.get("conservation_ok").and_then(Value::as_bool) == Some(true),
        "raw_archive_lineage":raw_archive.segment_count == raw_verify.segment_count
            && raw_archive.completeness == "complete"
            && raw_verify.completeness == "complete"
            && raw_restore.completeness == "complete"
            && raw_verify.total_records == raw_archive.total_records
            && raw_restore.segment_count == raw_archive.segment_count
            && assembly.raw_sources.len() == 1
            && assembly.raw_sources[0].archive_id == "self-test-raw"
            && release.raw_sources == assembly.raw_sources,
        "gateway_enrichment":enrichment.matched == 6
            && enrichment.unmatched == producer_events.len() as u64
            && enrichment.ambiguous == 0
            && enrichment == enrichment_verified,
        "semantic_reward":semantic_reward_available,
        "m0_interaction_delivery":interaction.integrity.delivery_ready
            && interaction.validation_status == "delivery_ready"
            && interaction_verified == interaction,
        "m0_otlp_tree":otlp.root_spans == 1
            && otlp.internal_parent_references == otlp.resolved_internal_parents
            && otlp.resolved_internal_parent_rate == 1.0
            && otlp.missing_parent_nodes.is_empty()
            && otlp_verified == otlp,
        "release_verification":verified.validation_status == "pass",
        "buyer_package_verification":buyer.eligible_sessions == 1
            && buyer.packages.len() == 1
            && verified_buyer == buyer
            && buyer_tamper_detected,
        "release_publish_idempotency":!first_publish.idempotent
            && second_publish.idempotent
            && published_release.ok,
        "buyer_publish_idempotency":!first_buyer_publish.idempotent
            && second_buyer_publish.idempotent
            && published_buyer.ok,
    });
    let self_test_ok = self_test_checks
        .as_object()
        .is_some_and(|checks| checks.values().all(|check| check == &Value::Bool(true)));
    Ok(json!({
        "ok": self_test_ok,
        "checks":self_test_checks,
        "assembly": assembly,
        "collection": relay_health,
        "collection_submission": submit_summary,
        "raw_archive": raw_archive,
        "raw_archive_verify": raw_verify,
        "raw_archive_restore": raw_restore,
        "enrichment": enrichment,
        "enrichment_verify": enrichment_verified,
        "interaction":interaction,
        "interaction_verify":interaction_verified,
        "otlp":otlp,
        "otlp_verify":otlp_verified,
        "release": release,
        "buyer_package": buyer,
        "buyer_tamper_detected": buyer_tamper_detected,
        "publish": first_publish,
        "publish_retry": second_publish,
        "published_release_verify": published_release,
        "buyer_publish": first_buyer_publish,
        "buyer_publish_retry": second_buyer_publish,
        "published_buyer_verify": published_buyer,
        "acceptance": {
            "profile": release.buyer_profile,
            "minimum_score": release.minimum_score,
            "score": score,
            "hard_gate_pass": hard_gate_pass,
            "capture_dag_present": delivered.pointer("/meta/capture_dag").is_some(),
            "task_dag_complete": task_dag_complete,
            "proxy_route_verified": proxy_route_verified,
            "provider_identity_attested": provider_identity_attested,
            "completed_tool_calls": completed_tool_calls,
            "failed_tool_calls": failed_tool_calls,
            "tool_execution_audit_pass":tool_execution_audit_pass,
            "producer_stream_audit_pass":producer_stream_audit_pass,
            "source_request_count": delivered["source_request_count"],
            "source_capture_count": delivered["source_capture_count"],
            "semantic_reward_available": semantic_reward_available,
        },
    }))
}

fn reserve_local_address() -> Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?)
}

async fn wait_for_health(client: &reqwest::Client, url: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("service did not become healthy: {url}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn harness_target(
    relay_url: Option<String>,
    output: Option<PathBuf>,
) -> Result<Option<HarnessTarget>> {
    match (relay_url, output) {
        (Some(url), None) => {
            if url.trim().is_empty() {
                bail!("--relay-url must not be empty");
            }
            Ok(Some(HarnessTarget::Relay(url)))
        }
        (None, Some(path)) => Ok(Some(HarnessTarget::Jsonl(path))),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => bail!("--relay-url and --output are mutually exclusive"),
    }
}

fn parse_harness_value(raw: &str, field: &str) -> Result<Value> {
    if let Some(path) = raw.strip_prefix('@') {
        let bytes = fs::read(path).with_context(|| format!("read {field} file {path}"))?;
        return serde_json::from_slice(&bytes)
            .with_context(|| format!("parse {field} JSON file {path}"));
    }
    match serde_json::from_str(raw) {
        Ok(value) => Ok(value),
        Err(_) => Ok(Value::String(raw.to_owned())),
    }
}

fn parse_harness_json_file(path: Option<PathBuf>, field: &str) -> Result<Option<Value>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = fs::read(&path).with_context(|| format!("read {field} {}", path.display()))?;
    Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
        format!("parse {field} {}", path.display())
    })?))
}

fn open_harness_state(
    state_root: PathBuf,
    relay_url: Option<String>,
    output: Option<PathBuf>,
) -> Result<Harness> {
    let target = harness_target(relay_url, output)?;
    Harness::open_with_target(state_root, target)
}

async fn harness_start(args: HarnessStartArgs) -> Result<Value> {
    let target = harness_target(args.relay_url, args.output)?;
    let registry = parse_harness_json_file(args.tool_registry, "tool registry")?;
    let mut config = HarnessConfig::new(args.state_root, args.source_namespace);
    config.task_session_id = args.task_session_id;
    config.root_session_id = args.root_session_id;
    config.parent_session_id = args.parent_session_id;
    config.goal_id = args.goal_id;
    config.agent_id = args.agent_id;
    config.branch_id = args.branch_id;
    config.session_id = args.session_id;
    config.thread_id = args.thread_id;
    config.previous_response_id = args.previous_response_id;
    config.traceparent = args.traceparent;
    config.target = target;
    config.tool_registry = registry;
    config.retry_max_times = args.retry_max_times;
    config.request_timeout = Duration::from_secs(args.request_timeout_seconds);
    config.max_envelope_bytes = checked_mib(args.max_envelope_mib)?;
    config.batch_records = args.batch_records;
    let mut harness = Harness::start(config)?;
    let delivery = match harness.flush().await {
        Ok(summary) => json!({"ok":true,"summary":summary}),
        Err(error) => json!({"ok":false,"error":error.to_string(),"durable_spool":true}),
    };
    Ok(json!({
        "ok":true,
        "identity":harness.identity(),
        "delivery":delivery,
        "inspection":harness.inspect()?,
    }))
}

async fn harness_lifecycle(args: HarnessLifecycleArgs) -> Result<Value> {
    let target = harness_target(args.state.relay_url, args.state.output)?;
    let mut harness = Harness::open_with_target(args.state.state_root, target)?;
    let details = args
        .details
        .as_deref()
        .map(|raw| parse_harness_value(raw, "details"))
        .transpose()?;
    let receipt = harness.emit_lifecycle(LifecycleEventInput {
        event_type: args.event_type,
        status: args.status,
        reason: args.reason,
        turn_id: args.turn_id,
        details,
        occurred_at: args.occurred_at,
    })?;
    let delivery = match harness.flush().await {
        Ok(summary) => json!({"ok":true,"summary":summary}),
        Err(error) => json!({"ok":false,"error":error.to_string(),"durable_spool":true}),
    };
    Ok(json!({"ok":true,"receipt":receipt,"delivery":delivery,"inspection":harness.inspect()?}))
}

async fn harness_tool_start(args: HarnessToolStartArgs) -> Result<Value> {
    let target = harness_target(args.state.relay_url, args.state.output)?;
    let mut harness = Harness::open_with_target(args.state.state_root, target)?;
    let schema = parse_harness_json_file(args.schema, "tool schema")?;
    let arguments = parse_harness_value(&args.arguments, "arguments")?;
    let receipt = harness.tool_start(ToolStartInput {
        call_id: args.call_id,
        name: args.name,
        runtime_namespace: args.runtime_namespace,
        runtime_tool: args.runtime_tool,
        arguments,
        schema,
        parent_call_id: args.parent_call_id,
        initiator: args.initiator,
        turn_id: args.turn_id,
        started_at: args.started_at,
    })?;
    let delivery = match harness.flush().await {
        Ok(summary) => json!({"ok":true,"summary":summary}),
        Err(error) => json!({"ok":false,"error":error.to_string(),"durable_spool":true}),
    };
    Ok(json!({"ok":true,"receipt":receipt,"delivery":delivery,"inspection":harness.inspect()?}))
}

async fn harness_tool_end(args: HarnessToolEndArgs) -> Result<Value> {
    let target = harness_target(args.state.relay_url, args.state.output)?;
    let mut harness = Harness::open_with_target(args.state.state_root, target)?;
    let result = args
        .result
        .as_deref()
        .map(|raw| parse_harness_value(raw, "result"))
        .transpose()?;
    let error = args
        .error
        .as_deref()
        .map(|raw| parse_harness_value(raw, "error"))
        .transpose()?;
    let receipt = harness.tool_end(ToolEndInput {
        call_id: args.call_id,
        status: args.status,
        result,
        error,
        finished_at: args.finished_at,
    })?;
    let delivery = match harness.flush().await {
        Ok(summary) => json!({"ok":true,"summary":summary}),
        Err(error) => json!({"ok":false,"error":error.to_string(),"durable_spool":true}),
    };
    Ok(json!({"ok":true,"receipt":receipt,"delivery":delivery,"inspection":harness.inspect()?}))
}

async fn harness_evaluate(args: HarnessEvaluateArgs) -> Result<Value> {
    let target = harness_target(args.state.relay_url, args.state.output)?;
    let mut harness = Harness::open_with_target(args.state.state_root, target)?;
    let artifact = args
        .artifact
        .as_deref()
        .map(|raw| parse_harness_value(raw, "artifact"))
        .transpose()?;
    let receipt = harness.evaluate(EvaluationInput {
        kind: args.kind,
        source: args.source,
        status: args.status,
        passed: args.passed,
        reward: args.reward,
        score: args.score,
        artifact,
        observed_at: args.observed_at,
    })?;
    let delivery = match harness.flush().await {
        Ok(summary) => json!({"ok":true,"summary":summary}),
        Err(error) => json!({"ok":false,"error":error.to_string(),"durable_spool":true}),
    };
    Ok(json!({"ok":true,"receipt":receipt,"delivery":delivery,"inspection":harness.inspect()?}))
}

async fn harness_end(args: HarnessEndArgs) -> Result<Value> {
    let target = harness_target(args.state.relay_url, args.state.output)?;
    let mut harness = Harness::open_with_target(args.state.state_root, target)?;
    let receipt = harness.task_end(args.status, args.reason)?;
    let delivery = match harness.flush().await {
        Ok(summary) => json!({"ok":true,"summary":summary}),
        Err(error) => json!({"ok":false,"error":error.to_string(),"durable_spool":true}),
    };
    Ok(json!({"ok":true,"receipt":receipt,"delivery":delivery,"inspection":harness.inspect()?}))
}

async fn harness_flush(args: HarnessFlushArgs) -> Result<Value> {
    let mut harness = open_harness_state(
        args.state.state_root,
        args.state.relay_url,
        args.state.output,
    )?;
    let summary = harness.flush().await?;
    Ok(json!({"ok":true,"summary":summary,"inspection":harness.inspect()?}))
}

fn self_test_tool_schema(name: &str) -> Value {
    json!({
        "type":"function",
        "name":name,
        "description":format!("Execute the {name} verification step."),
        "parameters":{
            "type":"object",
            "properties":{
                "target":{"type":"string","description":"Workspace target to inspect."}
            },
            "required":["target"]
        }
    })
}

fn self_test_trace(turn_id: Option<&str>) -> Value {
    let mut trace = json!({
        "task_session_id":"task-self-test-v7",
        "session_id":"thread-self-test",
        "thread_id":"thread-self-test",
        "root_session_id":"task-self-test-v7",
        "goal_id":"goal-self-test",
        "agent_id":"agent-root",
        "branch_id":"main",
        "trace_id":"0123456789abcdef0123456789abcdef",
        "parent_span_id":"1111111111111111",
        "trace_flags":"01",
        "traceparent":"00-0123456789abcdef0123456789abcdef-1111111111111111-01"
    });
    if let Some(turn_id) = turn_id {
        trace["root_turn_id"] = json!(turn_id);
        trace["turn_id"] = json!(turn_id);
    }
    trace
}

fn self_test_producer_event(
    producer: &str,
    stream_id: &str,
    event_id: &str,
    sequence: u64,
) -> Value {
    json!({
        "schema_version":"chiptrace.producer-event.v1",
        "event_id":event_id,
        "producer":producer,
        "producer_version":"0.5.1",
        "identity_scheme":"chiptrace.deterministic-capture.v1",
        "stream_id":stream_id,
        "sequence":sequence,
    })
}

async fn self_test_harness_events(root: &std::path::Path) -> Result<Vec<Value>> {
    let state_root = root.join("harness-state");
    let delivery_path = root.join("harness-delivery.ndjson");
    let names = [
        "read_workspace",
        "search_source",
        "run_tests",
        "check_format",
        "verify_release",
    ];
    let registry = json!({
        "schema_version":"chiptrace.tool-registry.v1",
        "producer":"codex-cli",
        "producer_version":"0.150.0-alpha.9",
        "captured_at":"2026-08-27T00:00:00Z",
        "tools":names.iter().map(|name| json!({
            "runtime_item_type":"CodeModeTool",
            "tool":self_test_tool_schema(name)
        })).collect::<Vec<_>>()
    });
    let mut config = HarnessConfig::new(state_root, "self-test");
    config.task_session_id = Some("task-self-test-v7".to_owned());
    config.root_session_id = Some("task-self-test-v7".to_owned());
    config.goal_id = Some("goal-self-test".to_owned());
    config.agent_id = Some("agent-root".to_owned());
    config.branch_id = Some("main".to_owned());
    config.session_id = Some("thread-self-test".to_owned());
    config.thread_id = Some("thread-self-test".to_owned());
    config.traceparent = Some("00-0123456789abcdef0123456789abcdef-1111111111111111-01".to_owned());
    config.target = Some(HarnessTarget::Jsonl(delivery_path));
    config.tool_registry = Some(registry);
    config.retry_max_times = 25;
    config.batch_records = 32;
    let mut harness = Harness::start(config)?;
    for (index, name) in names.iter().enumerate() {
        let turn_id = format!("turn-{}", index + 1);
        harness.tool_start(ToolStartInput {
            call_id: format!("call-{}", index + 1),
            name: (*name).to_owned(),
            runtime_namespace: None,
            runtime_tool: None,
            arguments: json!({"target":"/workspace/chip"}),
            schema: None,
            parent_call_id: None,
            initiator: "assistant".to_owned(),
            turn_id: Some(turn_id),
            started_at: Some(format!("2026-08-27T00:00:{:02}Z", index * 3 + 2)),
        })?;
        let end = if index == 0 {
            ToolEndInput {
                call_id: format!("call-{}", index + 1),
                status: "error".to_owned(),
                result: Some(json!("permission denied while reading workspace")),
                error: None,
                finished_at: Some(format!("2026-08-27T00:00:{:02}Z", index * 3 + 3)),
            }
        } else {
            ToolEndInput {
                call_id: format!("call-{}", index + 1),
                status: "success".to_owned(),
                result: Some(json!("completed with recorded workspace evidence")),
                error: None,
                finished_at: Some(format!("2026-08-27T00:00:{:02}Z", index * 3 + 3)),
            }
        };
        harness.tool_end(end)?;
    }
    harness.evaluate(EvaluationInput {
        kind: "test".to_owned(),
        source: "cargo test --workspace".to_owned(),
        status: Some("passed".to_owned()),
        passed: Some(true),
        reward: None,
        score: None,
        artifact: Some(json!({"all_tests_passed":true})),
        observed_at: Some("2026-08-27T00:00:17Z".to_owned()),
    })?;
    harness.evaluate(EvaluationInput {
        kind: "build".to_owned(),
        source: "cargo build --release".to_owned(),
        status: Some("passed".to_owned()),
        passed: Some(true),
        reward: None,
        score: None,
        artifact: Some(json!({"binary":"target/release/chiptrace"})),
        observed_at: Some("2026-08-27T00:00:17Z".to_owned()),
    })?;
    harness.evaluate(EvaluationInput {
        kind: "final_acceptance".to_owned(),
        source: "self-test evaluator".to_owned(),
        status: Some("accepted".to_owned()),
        passed: Some(true),
        reward: Some(1.0),
        score: None,
        artifact: Some(json!({"profile":"buyer-v7-codex-runtime-expanded"})),
        observed_at: Some("2026-08-27T00:00:17Z".to_owned()),
    })?;
    harness.task_end("completed", Some("self-test complete".to_owned()))?;
    let flushed = harness.flush().await?;
    if flushed.pending_records != 0 {
        bail!(
            "harness self-test left pending records: {}",
            flushed.pending_records
        );
    }
    let mut events = Vec::new();
    let reader = std::io::BufReader::new(File::open(harness.spool_path())?);
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            events.push(serde_json::from_str(&line)?);
        }
    }
    if events.len() != 15 {
        bail!(
            "harness self-test expected 15 producer events, got {}",
            events.len()
        );
    }
    Ok(events)
}

fn self_test_captures() -> Vec<Value> {
    let names = [
        "read_workspace",
        "search_source",
        "run_tests",
        "check_format",
        "verify_release",
    ];
    let schemas: Vec<Value> = names
        .iter()
        .map(|name| self_test_tool_schema(name))
        .collect();
    let tool_namespace = json!({
        "type":"additional_tools",
        "role":"developer",
        "tools":[{
            "type":"namespace",
            "name":"functions",
            "description":"Workspace verification tools.",
            "tools":schemas
        }]
    });
    let system_prompt =
        "You are a coding agent. Preserve real tool evidence and verify the final result.";
    let user_prompts = [
        "Inspect the workspace before changing anything.",
        "The first read failed; search the source using another path.",
        "Run the focused tests against the recovered source.",
        "Check formatting after the tests pass.",
        "Verify the release artifact and report the evidence.",
    ];
    let mut captures = vec![json!({
        "recordType":"lifecycle_event",
        "sourceNamespace":"self-test",
        "traceContext":self_test_trace(None),
        "producerEvent":self_test_producer_event(
            "chiptrace-harness", "harness-self-test", "life-start", 0
        ),
        "lifecycleEvent":{
            "event_id":"life-start",
            "type":"task_start",
            "status":"started",
            "occurred_at":"2026-08-27T00:00:00Z"
        }
    })];
    let mut history = Vec::new();
    let mut previous_response_id: Option<String> = None;
    for (index, name) in names.iter().enumerate() {
        let ordinal = index + 1;
        let turn_id = format!("turn-{ordinal}");
        let call_id = format!("call-{ordinal}");
        let response_id = format!("response-{ordinal}");
        let user = json!({
            "type":"message",
            "id":format!("user-{ordinal}"),
            "role":"user",
            "content":user_prompts[index]
        });
        history.push(user);
        let mut request_input = vec![
            tool_namespace.clone(),
            json!({"type":"message","role":"developer","content":system_prompt}),
        ];
        request_input.extend(history.clone());
        let assistant_text = format!("I will execute {name} and retain its real result.");
        let arguments = json!({"target":"/workspace/chip"});
        let request_value = json!({
            "model":"gpt-5.6-sol",
            "stream":true,
            "previous_response_id":previous_response_id,
            "input":request_input
        });
        let response_value = json!({
            "id":response_id,
            "model":"gpt-5.6-sol",
            "provider":"OpenAI",
            "status":"completed",
            "instructions":system_prompt,
            "output":[
                {"type":"message","id":format!("assistant-{ordinal}"),"role":"assistant","content":assistant_text},
                {"type":"function_call","id":format!("tool-item-{ordinal}"),"call_id":call_id,"name":name,
                 "arguments":serde_json::to_string(&arguments).unwrap()}
            ],
            "usage":{
                "input_tokens":1000 + ordinal * 100,
                "input_tokens_details":{"cached_tokens":800 + ordinal * 100},
                "output_tokens":80,
                "output_tokens_details":{"reasoning_tokens":20},
                "total_tokens":1080 + ordinal * 100
            }
        });
        let request_raw = serde_json::to_string(&request_value).unwrap();
        let response_raw = format!(
            "event: response.created\ndata: {}\n\nevent: response.completed\ndata: {}\n\ndata: [DONE]\n\n",
            json!({"type":"response.created","response":{"id":format!("response-{ordinal}"),"status":"in_progress","model":"gpt-5.6-sol","output":[]}}),
            json!({"type":"response.completed","response":response_value})
        );
        captures.push(json!({
            "recordType":"api_snapshot",
            "captureId":format!("cap-self-api-{ordinal}"),
            "upstreamRequestId":format!("request-{ordinal}"),
            "sourceNamespace":"self-test",
            "startedAt":format!("2026-08-27T00:00:{:02}Z", index * 3 + 1),
            "finishedAt":format!("2026-08-27T00:00:{:02}Z", index * 3 + 1),
            "proxiedPath":"/v1/responses",
            "stream":true,
            "upstreamResponseCompleted":true,
            "clientRequestAborted":false,
            "clientResponseClosedBeforeFinish":false,
            "traceContext":self_test_trace(Some(&turn_id)),
            "requestBodyText":request_raw,
            "responseStatus":200,
            "responseHeaders":{"x-request-id":format!("request-{ordinal}")},
            "responseBodyText":response_raw
        }));
        let (status, result_field, result) = if index == 0 {
            (
                "error",
                "error",
                "permission denied while reading workspace",
            )
        } else {
            (
                "success",
                "result",
                "completed with recorded workspace evidence",
            )
        };
        let started_at = format!("2026-08-27T00:00:{:02}Z", index * 3 + 2);
        captures.push(json!({
            "recordType":"tool_execution",
            "sourceNamespace":"self-test",
            "traceContext":self_test_trace(Some(&turn_id)),
            "producerEvent":self_test_producer_event(
                "tool-dispatcher",
                "dispatcher-self-test",
                &format!("tool-{ordinal}-start"),
                (index * 2) as u64,
            ),
            "toolExecution":{
                "call_id":call_id,
                "name":name,
                "initiator":"assistant",
                "status":"started",
                "arguments":arguments,
                "schema":schemas[index],
                "started_at":started_at,
            }
        }));
        let mut execution = json!({
            "call_id":call_id,
            "name":name,
            "initiator":"assistant",
            "status":status,
            "arguments":arguments,
            "schema":schemas[index],
            "started_at":started_at,
            "finished_at":format!("2026-08-27T00:00:{:02}Z", index * 3 + 3)
        });
        execution[result_field] = json!(result);
        captures.push(json!({
            "recordType":"tool_execution",
            "sourceNamespace":"self-test",
            "traceContext":self_test_trace(Some(&turn_id)),
            "producerEvent":self_test_producer_event(
                "tool-dispatcher",
                "dispatcher-self-test",
                &format!("tool-{ordinal}-finish"),
                (index * 2 + 1) as u64,
            ),
            "toolExecution":execution
        }));
        history.push(json!({
            "type":"message","id":format!("assistant-{ordinal}"),"role":"assistant","content":assistant_text
        }));
        history.push(json!({
            "type":"function_call","id":format!("tool-item-{ordinal}"),"call_id":call_id,
            "name":name,"arguments":serde_json::to_string(&arguments).unwrap()
        }));
        history.push(json!({
            "type":"function_call_output","id":format!("result-item-{ordinal}"),
            "call_id":call_id,"output":result
        }));
        previous_response_id = Some(format!("response-{ordinal}"));
    }
    let mut final_input = vec![
        tool_namespace,
        json!({"type":"message","role":"developer","content":system_prompt}),
    ];
    final_input.extend(history);
    let final_request_value = json!({
        "model":"gpt-5.6-sol",
        "stream":true,
        "previous_response_id":previous_response_id,
        "input":final_input
    });
    let final_response_value = json!({
        "id":"response-final","model":"gpt-5.6-sol","provider":"OpenAI","status":"completed",
        "instructions":system_prompt,
        "output":[{"type":"message","id":"assistant-final","role":"assistant",
                   "content":"The release passed tests, formatting, and final verification."}],
        "usage":{"input_tokens":2000,"input_tokens_details":{"cached_tokens":1800},
                 "output_tokens":100,"output_tokens_details":{"reasoning_tokens":20},"total_tokens":2100}
    });
    let final_request_raw = serde_json::to_string(&final_request_value).unwrap();
    let final_response_raw = format!(
        "event: response.created\ndata: {}\n\nevent: response.completed\ndata: {}\n\ndata: [DONE]\n\n",
        json!({"type":"response.created","response":{"id":"response-final","status":"in_progress","model":"gpt-5.6-sol","output":[]}}),
        json!({"type":"response.completed","response":final_response_value})
    );
    captures.push(json!({
        "recordType":"api_snapshot",
        "captureId":"cap-self-api-final",
        "upstreamRequestId":"request-final",
        "sourceNamespace":"self-test",
        "startedAt":"2026-08-27T00:00:16Z",
        "finishedAt":"2026-08-27T00:00:16Z",
        "proxiedPath":"/v1/responses",
        "stream":true,
        "upstreamResponseCompleted":true,
        "clientRequestAborted":false,
        "clientResponseClosedBeforeFinish":false,
        "traceContext":self_test_trace(Some("turn-5")),
        "requestBodyText":final_request_raw,
        "responseStatus":200,
        "responseHeaders":{"x-request-id":"request-final"},
        "responseBodyText":final_response_raw
    }));
    captures.push(json!({
        "recordType":"evaluation",
        "sourceNamespace":"self-test",
        "traceContext":self_test_trace(Some("turn-5")),
        "producerEvent":self_test_producer_event(
            "chiptrace-harness", "harness-self-test", "evaluation-final", 1
        ),
        "receivedAt":"2026-08-27T00:00:17Z",
        "evaluationEvidence":[
            {"kind":"test","source":"cargo test --workspace","status":"passed","artifact":"all tests passed",
             "observed_at":"2026-08-27T00:00:17Z"},
            {"kind":"build","source":"cargo build --release","status":"passed","artifact":"release binary",
             "observed_at":"2026-08-27T00:00:17Z"},
            {"kind":"final_acceptance","source":"self-test evaluator","status":"accepted","reward":1.0,
             "observed_at":"2026-08-27T00:00:17Z"}
        ]
    }));
    captures.push(json!({
        "recordType":"lifecycle_event",
        "sourceNamespace":"self-test",
        "traceContext":self_test_trace(None),
        "producerEvent":self_test_producer_event(
            "chiptrace-harness", "harness-self-test", "life-end", 2
        ),
        "lifecycleEvent":{
            "event_id":"life-end",
            "type":"task_end",
            "status":"completed",
            "occurred_at":"2026-08-27T00:00:18Z"
        }
    }));
    captures
}

async fn benchmark_store(args: BenchmarkStoreArgs) -> Result<Value> {
    if args.records == 0 || args.payload_kib == 0 || args.concurrency == 0 {
        bail!("benchmark records, payload and concurrency must be positive");
    }
    let owned_temporary = if args.work_root.is_none() {
        Some(tempfile::tempdir()?)
    } else {
        None
    };
    let root = args
        .work_root
        .unwrap_or_else(|| owned_temporary.as_ref().unwrap().path().to_path_buf());
    let store = ShardedCaptureStore::open(
        StoreConfig {
            root: root.join("capture"),
            state_root: root.join("state"),
            segment_max_bytes: 1024 * 1024 * 1024,
            segment_max_age: Duration::from_secs(3600),
            queue_items: args.concurrency.saturating_mul(4),
            batch_records: 512,
            batch_bytes: 256 * 1024 * 1024,
            batch_wait: Duration::from_millis(5),
            fsync: !args.no_fsync,
        },
        args.store_shards,
    )
    .await?;
    let payload = "x".repeat(args.payload_kib * 1024);
    let started = Instant::now();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(args.concurrency));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..args.records {
        let permit = std::sync::Arc::clone(&semaphore).acquire_owned().await?;
        let store = store.clone();
        let payload = payload.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let max_bytes = payload.len() + 1024 * 1024;
            let value = json!({
                "captureId": format!("cap-benchmark-{index:020}"),
                "startedAt": "2026-08-27T00:00:00Z",
                "requestBody": {"kind":"json","value":{"model":"gpt-5.6-sol","input":payload}},
                "responseStatus": 200,
                "responseBody": {"kind":"json","value":{"status":"completed"}}
            });
            let record = normalize_capture(&serde_json::to_vec(&value).unwrap(), max_bytes)?;
            store.submit(record).await.map_err(anyhow::Error::from)
        });
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    store.close().await?;
    let elapsed = started.elapsed().as_secs_f64();
    let bytes = args.records as f64 * args.payload_kib as f64 * 1024.0;
    Ok(json!({
        "records": args.records,
        "payload_kib": args.payload_kib,
        "fsync": !args.no_fsync,
        "store_shards": args.store_shards,
        "elapsed_seconds": elapsed,
        "records_per_second": args.records as f64 / elapsed,
        "payload_mib_per_second": bytes / elapsed / 1024.0 / 1024.0,
        "scope": "local Collector WAL + redb durable acknowledgements; excludes HTTP and object upload",
    }))
}

async fn benchmark_http(args: BenchmarkHttpArgs) -> Result<Value> {
    if args.records == 0
        || args.payload_kib == 0
        || args.batch_records == 0
        || args.concurrency == 0
        || args.store_shards == 0
    {
        bail!("HTTP benchmark records, payload, batch, concurrency, and shards must be positive");
    }
    let owned_temporary = if args.work_root.is_none() {
        Some(tempfile::tempdir()?)
    } else {
        None
    };
    let root = args
        .work_root
        .unwrap_or_else(|| owned_temporary.as_ref().unwrap().path().to_path_buf());
    let reserved = std::net::TcpListener::bind("127.0.0.1:0")?;
    let collector_bind = reserved.local_addr()?;
    drop(reserved);
    let estimated_batch_bytes = args
        .payload_kib
        .checked_mul(1024)
        .and_then(|bytes| bytes.checked_add(4096))
        .and_then(|bytes| bytes.checked_mul(args.batch_records))
        .ok_or_else(|| anyhow::anyhow!("HTTP benchmark batch size overflows usize"))?;
    let max_body_bytes = estimated_batch_bytes.max(1024 * 1024);
    if max_body_bytes > u32::MAX as usize {
        bail!("HTTP benchmark batch exceeds the 4 GiB request limit");
    }
    let max_inflight_body_bytes = max_body_bytes
        .checked_mul(args.concurrency)
        .ok_or_else(|| anyhow::anyhow!("HTTP benchmark inflight budget overflows usize"))?;
    let (collector_shutdown_tx, collector_shutdown_rx) = tokio::sync::oneshot::channel();
    let collector = tokio::spawn(serve(
        CollectorConfig {
            bind: collector_bind,
            store: StoreConfig {
                root: root.join("capture"),
                state_root: root.join("state"),
                segment_max_bytes: 1024 * 1024 * 1024,
                segment_max_age: Duration::from_secs(3600),
                queue_items: args
                    .concurrency
                    .saturating_mul(args.batch_records)
                    .max(1024),
                batch_records: 512,
                batch_bytes: 256 * 1024 * 1024,
                batch_wait: Duration::from_millis(5),
                fsync: !args.no_fsync,
            },
            store_shards: args.store_shards,
            max_connections: args.concurrency.saturating_mul(2),
            max_envelope_bytes: max_body_bytes,
            max_inflight_body_bytes,
            max_batch_records: args.batch_records,
        },
        async move {
            let _ = collector_shutdown_rx.await;
        },
    ));
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.concurrency)
        .timeout(Duration::from_secs(120))
        .build()?;
    wait_for_health(&client, &format!("http://{collector_bind}/health")).await?;
    let mut relay_shutdown_tx = None;
    let mut relay_server = None;
    let ingest_bind = if args.relay {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0")?;
        let relay_bind = reserved.local_addr()?;
        drop(reserved);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        relay_server = Some(tokio::spawn(serve_relay(
            RelayConfig {
                bind: relay_bind,
                store: StoreConfig {
                    root: root.join("outbox"),
                    state_root: root.join("outbox-state"),
                    segment_max_bytes: 1024 * 1024 * 1024,
                    segment_max_age: Duration::from_secs(3600),
                    queue_items: args
                        .concurrency
                        .saturating_mul(args.batch_records)
                        .max(1024),
                    batch_records: 512,
                    batch_bytes: 256 * 1024 * 1024,
                    batch_wait: Duration::from_millis(5),
                    fsync: !args.no_fsync,
                },
                store_shards: args.store_shards,
                delivery_state_root: root.join("delivery-state"),
                collector_url: format!("http://{collector_bind}"),
                delivery_concurrency: args.concurrency,
                delivery_queue_items: args
                    .concurrency
                    .saturating_mul(args.batch_records)
                    .max(1024),
                delivery_batch_records: args.batch_records,
                delivery_batch_bytes: max_body_bytes,
                delivery_batch_wait: Duration::from_millis(2),
                max_delivery_inflight_bytes: max_inflight_body_bytes,
                request_timeout: Duration::from_secs(120),
                base_retry_delay: Duration::from_millis(5),
                max_retry_delay: Duration::from_millis(100),
                max_connections: args.concurrency.saturating_mul(2),
                max_envelope_bytes: max_body_bytes,
                max_inflight_body_bytes,
                max_batch_records: args.batch_records,
                producer_bearer_token: None,
            },
            async move {
                let _ = shutdown_rx.await;
            },
        )));
        relay_shutdown_tx = Some(shutdown_tx);
        wait_for_health(&client, &format!("http://{relay_bind}/health")).await?;
        relay_bind
    } else {
        collector_bind
    };
    let capture_url = format!(
        "http://{ingest_bind}/{}",
        if args.producer_events {
            "producer/events"
        } else {
            "captures"
        }
    );
    let payload = Arc::new("x".repeat(args.payload_kib * 1024));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(args.concurrency));
    let mut tasks = tokio::task::JoinSet::new();
    let started = Instant::now();
    let mut first = 0_u64;
    while first < args.records {
        let count = (args.records - first).min(args.batch_records as u64);
        let permit = Arc::clone(&semaphore).acquire_owned().await?;
        let client = client.clone();
        let capture_url = capture_url.clone();
        let payload = Arc::clone(&payload);
        let producer_events = args.producer_events;
        tasks.spawn(async move {
            let _permit = permit;
            let mut body = Vec::with_capacity(
                (payload.len().saturating_add(1024)).saturating_mul(count as usize),
            );
            for index in first..first + count {
                let record = if producer_events {
                    json!({
                        "recordType":"evaluation",
                        "sourceNamespace":"benchmark",
                        "traceContext":{"task_session_id":"task-http-benchmark"},
                        "producerEvent":{
                            "schema_version":"chiptrace.producer-event.v1",
                            "event_id":format!("evaluation-{index:020}"),
                            "producer":"benchmark-evaluator",
                            "producer_version":"0.5.1",
                            "identity_scheme":"chiptrace.deterministic-capture.v1",
                            "stream_id":"benchmark-evaluator-stream",
                            "sequence":index,
                        },
                        "receivedAt":"2026-08-29T00:00:00Z",
                        "evaluationEvidence":[{
                            "kind":"evaluator",
                            "source":"benchmark-http",
                            "passed":true,
                            "observed_at":"2026-08-29T00:00:00Z",
                            "artifact":payload.as_str(),
                        }],
                    })
                } else {
                    json!({
                        "captureId": format!("cap-http-benchmark-{index:020}"),
                        "startedAt": "2026-08-27T00:00:00Z",
                        "requestBody": {"kind":"json","value":{"model":"gpt-5.6-sol","input":payload.as_str()}},
                        "responseStatus": 200,
                        "responseBody": {"kind":"json","value":{"status":"completed"}}
                    })
                };
                serde_json::to_writer(&mut body, &record)?;
                body.push(b'\n');
            }
            let wire_bytes = body.len() as u64;
            let request_started = Instant::now();
            let response = client
                .post(capture_url)
                .header("content-type", "application/x-ndjson")
                .body(body)
                .send()
                .await?;
            let status = response.status();
            let value: Value = response.json().await?;
            if !status.is_success()
                || value.get("durable").and_then(Value::as_bool) != Some(true)
            {
                bail!("HTTP benchmark batch failed: HTTP {status}: {value}");
            }
            Ok::<(u64, u64, f64), anyhow::Error>((
                count,
                wire_bytes,
                request_started.elapsed().as_secs_f64() * 1000.0,
            ))
        });
        first += count;
    }
    let mut observed_records = 0_u64;
    let mut wire_bytes = 0_u64;
    let mut latency_ms = Vec::new();
    let mut benchmark_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok((records, bytes, latency))) => {
                observed_records = observed_records.saturating_add(records);
                wire_bytes = wire_bytes.saturating_add(bytes);
                latency_ms.push(latency);
            }
            Ok(Err(error)) => {
                benchmark_error = Some(error);
                tasks.abort_all();
                break;
            }
            Err(error) => {
                benchmark_error = Some(error.into());
                tasks.abort_all();
                break;
            }
        }
    }
    let ingress_elapsed = started.elapsed().as_secs_f64();
    let mut relay_health = Value::Null;
    if benchmark_error.is_none() && args.relay {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let health = match client
                .get(format!("http://{ingest_bind}/health"))
                .send()
                .await
            {
                Ok(response) => match response.json::<Value>().await {
                    Ok(health) => health,
                    Err(error) => {
                        benchmark_error = Some(error.into());
                        break;
                    }
                },
                Err(error) => {
                    benchmark_error = Some(error.into());
                    break;
                }
            };
            if health.get("delivered").and_then(Value::as_u64) == Some(observed_records)
                && health.get("pending").and_then(Value::as_u64) == Some(0)
                && health.get("inflight").and_then(Value::as_u64) == Some(0)
            {
                relay_health = health;
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                benchmark_error = Some(anyhow::anyhow!(
                    "HTTP benchmark Relay did not drain: {health}"
                ));
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let end_to_end_elapsed = started.elapsed().as_secs_f64();
    if let Some(shutdown_tx) = relay_shutdown_tx {
        let _ = shutdown_tx.send(());
    }
    if let Some(server) = relay_server {
        server.await.context("join HTTP benchmark Relay")??;
    }
    let _ = collector_shutdown_tx.send(());
    collector.await.context("join HTTP benchmark Collector")??;
    if let Some(error) = benchmark_error {
        return Err(error);
    }
    latency_ms.sort_by(f64::total_cmp);
    let payload_bytes = observed_records as f64 * args.payload_kib as f64 * 1024.0;
    Ok(json!({
        "records": observed_records,
        "payload_kib": args.payload_kib,
        "batch_records": args.batch_records,
        "batch_requests": latency_ms.len(),
        "concurrency": args.concurrency,
        "store_shards": args.store_shards,
        "fsync": !args.no_fsync,
        "relay":args.relay,
        "producer_events":args.producer_events,
        "ingress_ack_elapsed_seconds": ingress_elapsed,
        "end_to_end_elapsed_seconds":end_to_end_elapsed,
        "delivery_drain_seconds":end_to_end_elapsed - ingress_elapsed,
        "ingress_records_per_second": observed_records as f64 / ingress_elapsed,
        "end_to_end_records_per_second":observed_records as f64 / end_to_end_elapsed,
        "ingress_payload_mib_per_second": payload_bytes / ingress_elapsed / 1024.0 / 1024.0,
        "end_to_end_payload_mib_per_second":payload_bytes / end_to_end_elapsed / 1024.0 / 1024.0,
        "ingress_wire_mib_per_second": wire_bytes as f64 / ingress_elapsed / 1024.0 / 1024.0,
        "relay_health":relay_health,
        "batch_latency_ms": {
            "p50": percentile(&latency_ms, 0.50),
            "p95": percentile(&latency_ms, 0.95),
            "p99": percentile(&latency_ms, 0.99),
            "max": latency_ms.last().copied().unwrap_or(0.0),
        },
        "scope": if args.relay {
            "loopback HTTP NDJSON + Relay durable outbox + async Collector delivery + two sharded WAL/redb durable acknowledgements; excludes object upload"
        } else {
            "loopback HTTP NDJSON batching + normalization + sharded Collector WAL/redb durable acknowledgements; excludes Relay and object upload"
        },
    }))
}

fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * quantile).ceil() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn benchmark_compression(args: BenchmarkCompressionArgs) -> Result<Value> {
    if args.records == 0
        || args.payload_kib == 0
        || args.streams == 0
        || args.workers_per_stream == 0
    {
        bail!("compression benchmark records, payload, streams, and workers must be positive");
    }
    let owned_temporary = if args.work_root.is_none() {
        Some(tempfile::tempdir()?)
    } else {
        None
    };
    let root = args
        .work_root
        .unwrap_or_else(|| owned_temporary.as_ref().unwrap().path().to_path_buf());
    fs::create_dir_all(&root)?;
    let run_root = tempfile::Builder::new()
        .prefix("chiptrace-compression-")
        .tempdir_in(&root)?;
    let variants = args.records.min(256) as usize;
    let records: Arc<Vec<Vec<u8>>> = Arc::new(
        (0..variants)
            .map(|index| {
                serde_json::to_vec(&json!({
                    "schema_version": "chiptrace.session.v1",
                    "trajectory_id": format!("traj-benchmark-{index:08}"),
                    "session_id": format!("session-benchmark-{index:08}"),
                    "messages": [{
                        "role": "tool",
                        "tool_call_id": format!("call-{index:08}"),
                        "status": "success",
                        "content": deterministic_text(args.payload_kib * 1024, index as u64 + 1)
                    }]
                }))
            })
            .collect::<std::result::Result<_, _>>()?,
    );
    let started = Instant::now();
    let stream_results: Vec<(u64, u64)> = (0..args.streams)
        .into_par_iter()
        .map(|stream| {
            let output_path = run_root
                .path()
                .join(format!("stream-{stream:05}.jsonl.zst"));
            let file = File::create(&output_path)?;
            let writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
            let mut encoder = zstd::stream::write::Encoder::new(writer, args.level)?;
            if args.workers_per_stream > 1 {
                encoder.multithread(args.workers_per_stream)?;
            }
            let mut uncompressed = 0_u64;
            let mut index = stream as u64;
            while index < args.records {
                let record = &records[index as usize % records.len()];
                encoder.write_all(record)?;
                encoder.write_all(b"\n")?;
                uncompressed = uncompressed.saturating_add(record.len() as u64 + 1);
                index = index.saturating_add(args.streams as u64);
            }
            let mut writer = encoder.finish()?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            Ok::<(u64, u64), anyhow::Error>((uncompressed, output_path.metadata()?.len()))
        })
        .collect::<Result<Vec<_>>>()?;
    let elapsed = started.elapsed().as_secs_f64();
    let uncompressed_bytes = stream_results.iter().map(|result| result.0).sum::<u64>();
    let compressed_bytes = stream_results.iter().map(|result| result.1).sum::<u64>();
    Ok(json!({
        "records": args.records,
        "payload_kib": args.payload_kib,
        "level": args.level,
        "streams": args.streams,
        "workers_per_stream": args.workers_per_stream,
        "elapsed_seconds": elapsed,
        "uncompressed_bytes": uncompressed_bytes,
        "compressed_bytes": compressed_bytes,
        "compression_ratio": uncompressed_bytes as f64 / compressed_bytes.max(1) as f64,
        "uncompressed_mib_per_second": uncompressed_bytes as f64 / elapsed / 1024.0 / 1024.0,
        "compressed_mib_per_second": compressed_bytes as f64 / elapsed / 1024.0 / 1024.0,
        "scope": "Rust zstd JSONL encoding and output fsync; excludes Session assembly, scoring, and object upload",
    }))
}

fn deterministic_text(bytes: usize, seed: u64) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /._-";
    let mut state = seed.max(1);
    let mut output = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        output.push(ALPHABET[state as usize % ALPHABET.len()]);
    }
    String::from_utf8(output).expect("benchmark alphabet is UTF-8")
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn public_help_exposes_only_the_stock_codex_ingest_path() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("codex-agent"));
        for hidden in [
            "codex-hook-spool",
            "codex-run",
            "export-codex-rollout",
            "watch-codex-rollout",
            "export-codex-trace-bundle",
            "harness",
            "runtime-canary",
        ] {
            assert!(
                !help
                    .lines()
                    .any(|line| line.trim_start().starts_with(&format!("{hidden} "))),
                "public help exposed {hidden}"
            );
        }
    }
}
