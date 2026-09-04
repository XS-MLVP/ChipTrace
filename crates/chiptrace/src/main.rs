use anyhow::{Context, Result, bail};
use chiptrace::assemble::{AssembleConfig, assemble, verify_assembly};
use chiptrace::buyer::{BuyerPackageConfig, package_buyer_release, verify_buyer_package};
use chiptrace::capture::{CAPTURE_SCHEMA_VERSION, normalize_capture};
use chiptrace::cloud_acceptance::{
    CloudAcceptanceConfig, run_cloud_acceptance, verify_cloud_acceptance,
};
use chiptrace::collector::{CollectorConfig, serve};
use chiptrace::enrich::{EnrichConfig, enrich_captures, verify_enrichment};
use chiptrace::model_interaction::{
    InteractionProjectConfig, project_interactions, verify_interaction_projection,
};
use chiptrace::otlp_delivery::{OtlpDeliveryConfig, send_otlp};
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
use chiptrace::score::{Profile, score_jsonl};
use chiptrace::sharded::{ShardedCaptureStore, audit_sharded_store};
use chiptrace::store::StoreConfig;
use chiptrace::telemetry::{OtlpExportConfig, export_otlp, verify_otlp_export};
use clap::{Args, Parser, Subcommand};
use rayon::prelude::*;
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufWriter, Write};
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
    /// 从已提交 Raw Archive 对一条 Stock Codex Session 执行完整云端采购验收。
    CloudAcceptance(CloudAcceptanceArgs),
    /// 只读复验云端验收产物及全部阶段 Manifest。
    VerifyCloudAcceptance(VerifyCloudAcceptanceArgs),
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
    /// 将已验证的 OTLP 树可靠发送到 Langfuse。
    SendOtlp(SendOtlpArgs),
    /// 对 canonical Session JSONL 输出逐条验收结果。
    Score(ScoreArgs),
    /// 按显式 request_id 将 Sub2API usage log 精确关联到 Capture。
    Enrich(EnrichArgs),
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
    /// 测量本地 WAL/ledger 持久化吞吐。
    BenchmarkStore(BenchmarkStoreArgs),
    /// 测量环回 HTTP、可选 Relay 双 WAL 吞吐。
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
    /// 仅用于隔离开发；生产 OTLP/Hook 路由默认要求 CHIPTRACE_INGEST_TOKEN。
    #[arg(long)]
    allow_unauthenticated_cloud_ingest: bool,
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
    /// 只组装这一显式任务 Session；与 --session-id 互斥。
    #[arg(long)]
    task_session_id: Option<String>,
    /// 只组装这一 Stock Codex Session；与 --task-session-id 互斥。
    #[arg(long, conflicts_with = "task_session_id")]
    session_id: Option<String>,
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
struct SendOtlpArgs {
    #[arg(long, required = true)]
    projection: PathBuf,
    /// Langfuse OTLP traces API，例如 http://127.0.0.1:8990/api/public/otel/v1/traces。
    #[arg(long, required = true)]
    endpoint: String,
    #[arg(long, default_value_t = 30)]
    request_timeout_seconds: u64,
    #[arg(long, default_value_t = 25)]
    retry_max_times: usize,
    #[arg(long, default_value_t = 256)]
    batch_spans: usize,
    #[arg(long, default_value_t = 4)]
    max_batch_mib: usize,
    /// 仅用于观测：显式允许发送 delivery_ready=false 的投影。
    #[arg(long)]
    allow_incomplete: bool,
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
}

#[derive(Debug, Args)]
struct VerifyBuyerPackageArgs {
    #[arg(long)]
    package: PathBuf,
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
struct CloudAcceptanceArgs {
    /// 已提交 Raw Archive 的唯一标识。
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
    /// Sub2API usage log JSON/JSONL，可重复指定。
    #[arg(long = "usage-log", required = true)]
    usage_log: Vec<PathBuf>,
    /// Stock Codex 原生 session-id；不接受推断值。
    #[arg(long)]
    session_id: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    release_id: String,
    #[arg(long, default_value_t = 90.0)]
    minimum_score: f64,
    #[arg(long, default_value_t = 10.0)]
    target_part_gib: f64,
    #[arg(long, default_value_t = 256)]
    partitions: usize,
    #[arg(long, default_value_t = 1)]
    zstd_level: i32,
    #[arg(long, default_value_t = 1)]
    gzip_level: u32,
    #[arg(long, default_value_t = 0)]
    workers: usize,
    #[arg(long)]
    replace: bool,
}

#[derive(Debug, Args)]
struct VerifyCloudAcceptanceArgs {
    #[arg(long)]
    acceptance: PathBuf,
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[arg(long, default_value = "http://127.0.0.1:3010/health")]
    url: String,
    #[arg(long, default_value_t = 5)]
    timeout_seconds: u64,
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
            let ingest_bearer_token = std::env::var("CHIPTRACE_INGEST_TOKEN")
                .ok()
                .filter(|value| !value.trim().is_empty());
            if ingest_bearer_token.is_none() && !args.allow_unauthenticated_cloud_ingest {
                bail!(
                    "CHIPTRACE_INGEST_TOKEN is required; use --allow-unauthenticated-cloud-ingest only in isolated development"
                );
            }
            if ingest_bearer_token
                .as_deref()
                .is_some_and(|value| value.trim().len() < 32)
            {
                bail!("CHIPTRACE_INGEST_TOKEN must contain at least 32 bytes after trimming");
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
                    ingest_bearer_token,
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
        Command::CloudAcceptance(args) => {
            if !args.target_part_gib.is_finite() || args.target_part_gib <= 0.0 {
                bail!("target_part_gib must be positive");
            }
            serde_json::to_value(
                run_cloud_acceptance(CloudAcceptanceConfig {
                    archive_id: args.archive_id,
                    backend: args.backend,
                    root: args.root,
                    endpoint: args.endpoint,
                    bucket: args.bucket,
                    region: args.region,
                    prefix: args.prefix,
                    usage_logs: args.usage_log,
                    session_id: args.session_id,
                    output: args.output,
                    release_id: args.release_id,
                    minimum_score: args.minimum_score,
                    target_part_bytes: (args.target_part_gib * 1024.0 * 1024.0 * 1024.0) as u64,
                    partitions: args.partitions,
                    zstd_level: args.zstd_level,
                    gzip_level: args.gzip_level,
                    workers: args.workers,
                    replace: args.replace,
                })
                .await?,
            )?
        }
        Command::VerifyCloudAcceptance(args) => {
            serde_json::to_value(verify_cloud_acceptance(&args.acceptance)?)?
        }
        Command::Assemble(args) => serde_json::to_value(assemble(AssembleConfig {
            inputs: args.input,
            output: args.output,
            task_session_id: args.task_session_id,
            session_id: args.session_id,
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
        Command::SendOtlp(args) => {
            let public_key = std::env::var("LANGFUSE_PUBLIC_KEY")
                .context("LANGFUSE_PUBLIC_KEY is required for send-otlp")?;
            let secret_key = std::env::var("LANGFUSE_SECRET_KEY")
                .context("LANGFUSE_SECRET_KEY is required for send-otlp")?;
            serde_json::to_value(
                send_otlp(OtlpDeliveryConfig {
                    projection: args.projection,
                    endpoint: args.endpoint,
                    public_key,
                    secret_key,
                    request_timeout: Duration::from_secs(args.request_timeout_seconds),
                    retry_max_times: args.retry_max_times,
                    batch_spans: args.batch_spans,
                    max_batch_bytes: checked_mib(args.max_batch_mib)?,
                    allow_incomplete: args.allow_incomplete,
                })
                .await?,
            )?
        }
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
                require_pass: true,
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
            serde_json::to_value(package_buyer_release(config)?)?
        }
        Command::VerifyBuyerPackage(args) => {
            serde_json::to_value(verify_buyer_package(&args.package)?)?
        }
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
            ingest_bearer_token: None,
        },
        async move {
            let _ = relay_shutdown_rx.await;
        },
    ));
    wait_for_health(&client, &format!("http://{relay_bind}/health")).await?;
    let self_test_captures = self_test_captures();
    let captures: Vec<Value> = self_test_captures
        .iter()
        .filter(|capture| capture["recordType"] == "api_snapshot")
        .cloned()
        .collect();
    let evaluator_capture = self_test_captures
        .iter()
        .find(|capture| capture["recordType"] == "evaluation")
        .context("self-test evaluator Capture is missing")?;
    let api_snapshot_count = captures
        .iter()
        .filter(|capture| capture["recordType"] == "api_snapshot")
        .count();
    let mut submission_routes = Vec::new();
    let mut gateway_body = Vec::new();
    for record in &captures {
        gateway_body.extend_from_slice(&serde_json::to_vec(record)?);
        gateway_body.push(b'\n');
    }
    let gateway_response = client
        .post(format!("http://{relay_bind}/captures"))
        .header("content-type", "application/x-ndjson")
        .body(gateway_body)
        .send()
        .await?;
    let gateway_status = gateway_response.status();
    let gateway_result: Value = gateway_response.json().await?;
    if !gateway_status.is_success()
        || gateway_result.get("durable").and_then(Value::as_bool) != Some(true)
        || gateway_result
            .pointer("/counts/total")
            .and_then(Value::as_u64)
            != Some(captures.len() as u64)
    {
        bail!("self-test Wire captures were not durable: {gateway_result}");
    }
    submission_routes.push(json!({
        "route":"/captures",
        "http_status":gateway_status.as_u16(),
        "counts":gateway_result.get("counts"),
    }));

    let rejected_evaluator_response = client
        .post(format!("http://{relay_bind}/capture"))
        .json(evaluator_capture)
        .send()
        .await?;
    let rejected_evaluator_status = rejected_evaluator_response.status();
    let rejected_evaluator_result: Value = rejected_evaluator_response.json().await?;
    let relay_source_isolation = rejected_evaluator_status == reqwest::StatusCode::BAD_REQUEST
        && rejected_evaluator_result
            .get("reason")
            .and_then(Value::as_str)
            == Some("invalid_capture");
    if !relay_source_isolation {
        bail!("self-test Relay accepted evaluator evidence as Wire: {rejected_evaluator_result}");
    }
    submission_routes.push(json!({
        "route":"/capture",
        "source":"cloud_evaluator",
        "http_status":rejected_evaluator_status.as_u16(),
        "durable":false,
        "expected_rejection":true,
    }));

    // Evaluation evidence is produced by a cloud evaluator, not by the Wire
    // gateway. Submit it to the private Collector path so the public Relay
    // ingress remains a single-source record of observed model traffic.
    let evaluator_response = client
        .post(format!("http://{collector_bind}/capture"))
        .json(evaluator_capture)
        .send()
        .await?;
    let evaluator_status = evaluator_response.status();
    let evaluator_result: Value = evaluator_response.json().await?;
    if !evaluator_status.is_success()
        || evaluator_result.get("durable").and_then(Value::as_bool) != Some(true)
    {
        bail!("self-test evaluator Capture was not durable: {evaluator_result}");
    }
    submission_routes.push(json!({
        "route":"collector:/capture",
        "source":"cloud_evaluator",
        "http_status":evaluator_status.as_u16(),
        "durable":true,
    }));

    let otlp_logs = serde_json::to_vec(&self_test_otlp_logs())?;
    let otlp_result =
        submit_self_test_cloud_json(&client, relay_bind, "/otel/v1/logs", otlp_logs.clone())
            .await?;
    let otlp_capture_count = otlp_result
        .pointer("/chiptrace/captures")
        .and_then(Value::as_u64)
        .context("self-test OTLP response omitted capture count")?;
    submission_routes.push(json!({
        "route":"/otel/v1/logs",
        "captures":otlp_capture_count,
    }));

    let mut hook_payloads = vec![json!({
        "hook_event_name":"SessionStart","session_id":"thread-self-test",
        "transcript_path":Value::Null,"cwd":"/workspace","model":"gpt-5.6-sol",
        "permission_mode":"default","source":"startup"
    })];
    hook_payloads.extend((1..=5).map(|ordinal| {
        json!({
            "hook_event_name":"Stop",
            "session_id":"thread-self-test",
            "turn_id":format!("turn-{ordinal}"),
            "cwd":"/workspace",
            "reason":"completed"
        })
    }));
    hook_payloads.push(json!({
        "hook_event_name":"SessionEnd","session_id":"thread-self-test",
        "transcript_path":Value::Null,"cwd":"/workspace","reason":"other"
    }));
    let mut hook_capture_count = 0_u64;
    for payload in hook_payloads {
        let result = submit_self_test_cloud_json(
            &client,
            relay_bind,
            "/hooks/codex",
            serde_json::to_vec(&payload)?,
        )
        .await?;
        hook_capture_count = hook_capture_count.saturating_add(
            result
                .pointer("/chiptrace/captures")
                .and_then(Value::as_u64)
                .context("self-test Hook response omitted capture count")?,
        );
    }
    submission_routes.push(json!({
        "route":"/hooks/codex",
        "captures":hook_capture_count,
    }));

    let replay_result =
        submit_self_test_cloud_json(&client, relay_bind, "/otel/v1/logs", otlp_logs).await?;
    if replay_result
        .pointer("/chiptrace/duplicates")
        .and_then(Value::as_u64)
        != Some(otlp_capture_count)
    {
        bail!("self-test OTLP replay was not idempotent: {replay_result}");
    }
    let expected_relay_records = captures.len() as u64 + otlp_capture_count + hook_capture_count;
    let expected_collector_records = expected_relay_records.saturating_add(1);
    let raw_batch_count = 8_u64;
    let canonical_capture_count = expected_collector_records.saturating_sub(raw_batch_count);
    let non_api_capture_count =
        expected_collector_records.saturating_sub(api_snapshot_count as u64);
    let submit_summary = json!({
        "durable":true,
        "records":expected_collector_records,
        "routes":submission_routes,
        "otlp_replay_duplicates":replay_result.pointer("/chiptrace/duplicates"),
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
        if health.get("delivered").and_then(Value::as_u64) == Some(expected_relay_records) {
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
        root: Some(raw_object_root.clone()),
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
    let cloud_acceptance_root = temporary.path().join("cloud-acceptance");
    let cloud_acceptance = run_cloud_acceptance(CloudAcceptanceConfig {
        archive_id: "self-test-raw".to_owned(),
        backend: Backend::Fs,
        root: Some(raw_object_root.clone()),
        endpoint: None,
        bucket: None,
        region: None,
        prefix: "datasets/chiptrace".to_owned(),
        usage_logs: vec![usage_log_path.clone()],
        session_id: "thread-self-test".to_owned(),
        output: cloud_acceptance_root.clone(),
        release_id: "self-test-cloud-release".to_owned(),
        minimum_score: 90.0,
        target_part_bytes: 1024 * 1024,
        partitions: 4,
        zstd_level: 1,
        gzip_level: 1,
        workers: 4,
        replace: false,
    })
    .await?;
    let cloud_acceptance_verified = verify_cloud_acceptance(&cloud_acceptance_root)?;
    let cloud_buyer_manifest: Value = serde_json::from_slice(&fs::read(
        cloud_acceptance_root.join("buyer-package/manifest.json"),
    )?)?;
    let cloud_archive_relative = cloud_buyer_manifest
        .pointer("/packages/0/file")
        .and_then(Value::as_str)
        .context("cloud acceptance buyer package has no archive")?;
    let cloud_archive_path = cloud_acceptance_root
        .join("buyer-package")
        .join(cloud_archive_relative);
    let cloud_archive_bytes = fs::read(&cloud_archive_path)?;
    OpenOptions::new()
        .append(true)
        .open(&cloud_archive_path)?
        .write_all(b"tamper")?;
    let cloud_acceptance_tamper_detected = verify_cloud_acceptance(&cloud_acceptance_root).is_err();
    fs::write(&cloud_archive_path, cloud_archive_bytes)?;
    let cloud_acceptance_restored = verify_cloud_acceptance(&cloud_acceptance_root)?;
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
        task_session_id: None,
        session_id: Some("thread-self-test".to_owned()),
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
        task_session_id: None,
        session_id: Some("thread-self-test".to_owned()),
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
        require_pass: true,
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
                        execution["evidence_mode"] == "composite_runtime_span"
                            && execution["state"] == "closed"
                            && execution["started_capture_ids"]
                                .as_array()
                                .is_some_and(Vec::is_empty)
                            && execution["terminal_capture_ids"]
                                .as_array()
                                .is_some_and(|captures| captures.len() == 1)
                    })
            });
    let cloud_runtime_audit_pass = delivered
        .pointer("/meta/producer_event_conflicts")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
        && delivered
            .pointer("/meta/producer_streams")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
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
        "cloud_tool_execution_evidence":tool_execution_audit_pass,
        "cloud_runtime_evidence":cloud_runtime_audit_pass,
        "cloud_source_isolation":relay_source_isolation
            && relay_health.pointer("/ingest_coverage/wire/durable_captures")
                .and_then(Value::as_u64) == Some(api_snapshot_count as u64),
        "capture_counts":delivered["source_request_count"] == 6
            && delivered["source_capture_count"] == canonical_capture_count,
        "assembly_integrity":assembly.merge_divergences == 0
            && assembly.capture_schema_versions.len() == 1
            && assembly.capture_schema_versions.contains(CAPTURE_SCHEMA_VERSION),
        "relay_delivery_conservation":relay_health.get("delivered").and_then(Value::as_u64)
                == Some(expected_relay_records)
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
            && enrichment.unmatched == non_api_capture_count
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
        "cloud_acceptance":cloud_acceptance == cloud_acceptance_verified
            && cloud_acceptance == cloud_acceptance_restored
            && cloud_acceptance_tamper_detected
            && cloud_acceptance.validation_status == "pass"
            && cloud_acceptance.delivery_ready
            && cloud_acceptance.hard_gate_pass
            && cloud_acceptance.score >= 90.0
            && cloud_acceptance.eligible_sessions == 1,
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
        "cloud_acceptance":cloud_acceptance,
        "enrichment": enrichment,
        "enrichment_verify": enrichment_verified,
        "interaction":interaction,
        "interaction_verify":interaction_verified,
        "otlp":otlp,
        "otlp_verify":otlp_verified,
        "release": release,
        "buyer_package": buyer,
        "buyer_tamper_detected": buyer_tamper_detected,
        "cloud_acceptance_tamper_detected": cloud_acceptance_tamper_detected,
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
            "cloud_runtime_audit_pass":cloud_runtime_audit_pass,
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

async fn submit_self_test_cloud_json(
    client: &reqwest::Client,
    relay_bind: SocketAddr,
    path: &str,
    body: Vec<u8>,
) -> Result<Value> {
    let response = client
        .post(format!("http://{relay_bind}{path}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let result: Value = response.json().await?;
    if !status.is_success()
        || result
            .pointer("/chiptrace/durable")
            .and_then(Value::as_bool)
            != Some(true)
    {
        bail!("self-test cloud route {path} was not durable: HTTP {status}: {result}");
    }
    Ok(result)
}

fn self_test_otlp_attribute(key: &str, value: Value) -> Value {
    json!({"key":key,"value":value})
}

fn self_test_otlp_logs() -> Value {
    let names = [
        "read_workspace",
        "search_source",
        "run_tests",
        "check_format",
        "verify_release",
    ];
    let mut records = vec![json!({
        "timeUnixNano":"1787788800000000000",
        "traceId":"0123456789abcdef0123456789abcdef",
        "spanId":"1111111111111111",
        "attributes":[
            self_test_otlp_attribute("event.name", json!({"stringValue":"codex.conversation_starts"})),
            self_test_otlp_attribute("conversation.id", json!({"stringValue":"thread-self-test"})),
            self_test_otlp_attribute("model", json!({"stringValue":"gpt-5.6-sol"}))
        ]
    })];
    for (index, name) in names.iter().enumerate() {
        let ordinal = index + 1;
        let success = index != 0;
        let output = if success {
            "completed with recorded workspace evidence"
        } else {
            "permission denied while reading workspace"
        };
        records.push(json!({
            "timeUnixNano":format!("17877888{:02}000000000", ordinal * 3 + 3),
            "traceId":"0123456789abcdef0123456789abcdef",
            "spanId":format!("{:016x}", ordinal + 1),
            "attributes":[
                self_test_otlp_attribute("event.name", json!({"stringValue":"codex.tool_result"})),
                self_test_otlp_attribute("event.timestamp", json!({"stringValue":format!("2026-08-27T00:00:{:02}Z", index * 3 + 3)})),
                self_test_otlp_attribute("conversation.id", json!({"stringValue":"thread-self-test"})),
                self_test_otlp_attribute("model", json!({"stringValue":"gpt-5.6-sol"})),
                self_test_otlp_attribute("tool_name", json!({"stringValue":name})),
                self_test_otlp_attribute("tool_namespace", json!({"stringValue":"functions"})),
                self_test_otlp_attribute("call_id", json!({"stringValue":format!("call-{ordinal}")})),
                self_test_otlp_attribute("arguments", json!({"stringValue":"{\"target\":\"/workspace/chip\"}"})),
                self_test_otlp_attribute("output", json!({"stringValue":output})),
                self_test_otlp_attribute("duration_ms", json!({"intValue":"1000"})),
                self_test_otlp_attribute("success", json!({"boolValue":success})),
                self_test_otlp_attribute("output_truncated", json!({"boolValue":false}))
            ]
        }));
    }
    json!({
        "resourceLogs":[{
            "resource":{"attributes":[
                self_test_otlp_attribute("service.name", json!({"stringValue":"codex"}))
            ]},
            "scopeLogs":[{"scope":{"name":"codex_otel"},"logRecords":records}]
        }]
    })
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
        "session_id":"thread-self-test",
        "thread_id":"thread-self-test",
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
            "version":CAPTURE_SCHEMA_VERSION,
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
        "version":CAPTURE_SCHEMA_VERSION,
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
        "captureId":"cap-self-evaluation-final",
        "sourceNamespace":"self-test",
        "traceContext":self_test_trace(Some("turn-5")),
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
                ingest_bearer_token: None,
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
    let capture_url = format!("http://{ingest_bind}/captures");
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
        tasks.spawn(async move {
            let _permit = permit;
            let mut body = Vec::with_capacity(
                (payload.len().saturating_add(1024)).saturating_mul(count as usize),
            );
            for index in first..first + count {
                let record = json!({
                    "version": CAPTURE_SCHEMA_VERSION,
                    "recordType": "api_snapshot",
                    "captureId": format!("cap-http-benchmark-{index:020}"),
                    "sourceNamespace": "chiptrace-http-benchmark",
                    "startedAt": "2026-08-27T00:00:00Z",
                    "requestBody": {"kind":"json","value":{"model":"gpt-5.6-sol","input":payload.as_str()}},
                    "responseStatus": 200,
                    "responseBody": {"kind":"json","value":{"status":"completed"}}
                });
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
    fn public_commands_are_the_cloud_mainline() {
        let mut observed = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect::<Vec<_>>();
        observed.sort();
        let mut expected = vec![
            "archive-raw",
            "assemble",
            "audit",
            "benchmark-compression",
            "benchmark-http",
            "benchmark-store",
            "cloud-acceptance",
            "collector",
            "enrich",
            "export-otlp",
            "package-buyer",
            "probe",
            "project-interactions",
            "publish",
            "relay",
            "release",
            "restore-raw-archive",
            "score",
            "self-test",
            "send-otlp",
            "verify-assembly",
            "verify-buyer-package",
            "verify-cloud-acceptance",
            "verify-enrichment",
            "verify-interactions",
            "verify-otlp",
            "verify-published",
            "verify-raw-archive",
            "verify-release",
        ];
        expected.sort();
        assert_eq!(observed, expected);
    }
}
