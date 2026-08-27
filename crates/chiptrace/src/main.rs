use anyhow::{Context, Result, bail};
use chiptrace::assemble::{AssembleConfig, assemble, verify_assembly};
use chiptrace::capture::normalize_capture;
use chiptrace::collector::{CollectorConfig, serve};
use chiptrace::publish::{Backend, PublishConfig, publish};
use chiptrace::relay::{RelayConfig, serve_relay};
use chiptrace::release::{ReleaseConfig, build_release, verify_release};
use chiptrace::score::{Profile, score_jsonl};
use chiptrace::sharded::{ShardedCaptureStore, audit_sharded_store};
use chiptrace::store::{CaptureStore, StoreConfig};
use clap::{Args, Parser, Subcommand};
use rayon::prelude::*;
use serde_json::{Value, json};
use std::fs::{self, File};
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
    /// 将 Capture NDJSON 组装为 canonical Session JSONL。
    Assemble(AssembleArgs),
    /// 对 canonical Session JSONL 输出逐条验收结果。
    Score(ScoreArgs),
    /// 去重、评分并生成仅含准入 Session 的 JSONL.zst Release。
    Release(ReleaseArgs),
    /// 只读验证 Assembly。
    VerifyAssembly(VerifyAssemblyArgs),
    /// 只读验证 Release。
    VerifyRelease(VerifyReleaseArgs),
    /// 将 Release 通过 staging + commit manifest 发布到 OSS/S3/本地对象目录。
    Publish(PublishArgs),
    /// 检查 Collector 或 Relay HTTP 健康接口。
    Probe(ProbeArgs),
    /// 运行隔离的采集到交付闭环自测。
    SelfTest,
    /// 测量本地 WAL/ledger 持久化吞吐。
    BenchmarkStore(BenchmarkStoreArgs),
    /// 测量环回 HTTP 批量接收与持久化确认吞吐。
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
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 256)]
    partitions: usize,
    #[arg(long, default_value_t = 1)]
    zstd_level: i32,
    #[arg(long)]
    replace: bool,
}

#[derive(Debug, Args)]
struct ScoreArgs {
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum, default_value = "buyer-v7")]
    profile: Profile,
    #[arg(long, default_value_t = 90.0)]
    minimum_score: f64,
    #[arg(long, default_value_t = 1)]
    zstd_level: i32,
}

#[derive(Debug, Args)]
struct ReleaseArgs {
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    release_id: String,
    #[arg(long, value_enum, default_value = "buyer-v7")]
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
struct PublishArgs {
    #[arg(long)]
    release: PathBuf,
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
    #[arg(long)]
    verify_remote_sha256: bool,
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
        Command::Score(args) => serde_json::to_value(score_jsonl(
            &args.input,
            &args.output,
            args.profile,
            args.minimum_score,
            args.zstd_level,
        )?)?,
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
        Command::Publish(args) => serde_json::to_value(
            publish(PublishConfig {
                release: args.release,
                backend: args.backend,
                root: args.root,
                endpoint: args.endpoint,
                bucket: args.bucket,
                region: args.region,
                prefix: args.prefix,
                file_concurrency: args.file_concurrency,
                multipart_concurrency: args.multipart_concurrency,
                multipart_chunk_bytes: checked_mib(args.multipart_chunk_mib)?,
                verify_remote_sha256: args.verify_remote_sha256,
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
    let state_root = temporary.path().join("state");
    let store = CaptureStore::open(StoreConfig {
        root: capture_root.clone(),
        state_root,
        segment_max_bytes: 1024 * 1024,
        segment_max_age: Duration::from_secs(60),
        queue_items: 32,
        batch_records: 8,
        batch_bytes: 1024 * 1024,
        batch_wait: Duration::from_millis(1),
        fsync: true,
    })
    .await?;
    let tool_names = [
        "read_workspace",
        "search_source",
        "run_tests",
        "check_format",
        "verify_release",
    ];
    let tools: Vec<Value> = tool_names
        .iter()
        .map(|name| {
            json!({
                "name": name,
                "description": format!("Execute the {name} verification step."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Workspace target to inspect."}
                    },
                    "required": ["target"]
                }
            })
        })
        .collect();
    let mut input = Vec::new();
    for index in 1..=5 {
        input.push(json!({
            "type": "message",
            "role": "user",
            "content": format!("Inspect verification stage {index} in /workspace/chip.")
        }));
        input.push(json!({
            "type": "message",
            "role": "assistant",
            "content": format!("I will verify stage {index} against the workspace evidence.")
        }));
    }
    for (index, name) in tool_names.iter().enumerate() {
        input.push(json!({
            "type": "function_call",
            "call_id": format!("call-{}", index + 1),
            "name": name,
            "arguments": "{\"target\":\"/workspace/chip\"}"
        }));
        input.push(json!({
            "type": "function_call_output",
            "call_id": format!("call-{}", index + 1),
            "output": format!("{name} completed with recorded evidence"),
            "status": "completed"
        }));
    }
    let captures = vec![json!({
        "captureId": "cap-self-test-v7",
        "sourceNamespace": "self-test",
        "startedAt": "2026-08-27T00:00:00Z",
        "finishedAt": "2026-08-27T00:00:03Z",
        "proxiedPath": "/v1/responses",
        "traceContext": {
            "session_id": "session-self-test-v7",
            "root_session_id": "session-self-test-v7",
            "goal_id": "goal-self-test",
            "turn_id": "turn-5",
            "agent_id": "agent-root",
            "branch_id": "main"
        },
        "requestBody": {"kind": "json", "value": {
            "model": "gpt-5.6-sol",
            "instructions": "You are a coding agent. Preserve real tool evidence.",
            "tools": tools,
            "input": input
        }},
        "responseStatus": 200,
        "responseBody": {"kind": "json", "value": {
            "id": "response-self-test-v7",
            "model": "gpt-5.6-sol",
            "status": "completed",
            "output": [{
                "type":"message",
                "role":"assistant",
                "content":[{"type":"output_text","text":"All five verification stages passed."}]
            }],
            "usage": {
                "input_tokens": 1200,
                "input_tokens_details": {"cached_tokens": 900},
                "output_tokens": 180,
                "output_tokens_details": {"reasoning_tokens": 40},
                "total_tokens": 1380
            }
        }},
        "evaluationEvidence": [
            {"kind":"test","source":"cargo test","status":"passed","artifact":"25 tests"},
            {"kind":"build","source":"cargo build --release","status":"passed"},
            {"kind":"final_acceptance","source":"self-test","status":"accepted"}
        ],
        "observedLifecycleEvents": ["session_start", "session_end"]
    })];
    for capture in captures {
        let raw = serde_json::to_vec(&capture)?;
        store
            .submit(normalize_capture(&raw, 1024 * 1024)?)
            .await
            .map_err(anyhow::Error::from)?;
    }
    store.close().await?;
    let assembly_root = temporary.path().join("assembly");
    let assembly = assemble(AssembleConfig {
        inputs: vec![capture_root],
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
    let verified = verify_release(&release_root, true)?;
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
    let executed_tool_calls = delivered
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
        .filter(|call| call.get("execution_status").and_then(Value::as_str) == Some("executed"))
        .count();
    let semantic_reward_available = delivered
        .pointer("/quality/semantic_quality/reward_available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let publish_config = PublishConfig {
        release: release_root,
        backend: Backend::Fs,
        root: Some(temporary.path().join("object-store")),
        endpoint: None,
        bucket: None,
        region: None,
        prefix: "self-test".to_owned(),
        file_concurrency: 4,
        multipart_concurrency: 2,
        multipart_chunk_bytes: 5 * 1024 * 1024,
        verify_remote_sha256: true,
    };
    let first_publish = publish(publish_config.clone()).await?;
    let second_publish = publish(publish_config).await?;
    Ok(json!({
        "ok": release.counts.eligible_sessions == 1
            && release.buyer_profile == "buyer-v7"
            && score == 100.0
            && hard_gate_pass
            && task_dag_complete
            && delivered.pointer("/meta/capture_dag").is_some()
            && executed_tool_calls == 5
            && semantic_reward_available
            && verified.validation_status == "pass"
            && !first_publish.idempotent
            && second_publish.idempotent,
        "assembly": assembly,
        "release": release,
        "publish": first_publish,
        "publish_retry": second_publish,
        "acceptance": {
            "profile": release.buyer_profile,
            "minimum_score": release.minimum_score,
            "score": score,
            "hard_gate_pass": hard_gate_pass,
            "capture_dag_present": delivered.pointer("/meta/capture_dag").is_some(),
            "task_dag_complete": task_dag_complete,
            "executed_tool_calls": executed_tool_calls,
            "semantic_reward_available": semantic_reward_available,
        },
    }))
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
    let bind = reserved.local_addr()?;
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
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(
        CollectorConfig {
            bind,
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
            let _ = shutdown_rx.await;
        },
    ));
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.concurrency)
        .timeout(Duration::from_secs(120))
        .build()?;
    let health_url = format!("http://{bind}/health");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if client
            .get(&health_url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = shutdown_tx.send(());
            bail!("HTTP benchmark Collector did not become ready");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let capture_url = format!("http://{bind}/captures");
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
                serde_json::to_writer(
                    &mut body,
                    &json!({
                        "captureId": format!("cap-http-benchmark-{index:020}"),
                        "startedAt": "2026-08-27T00:00:00Z",
                        "requestBody": {"kind":"json","value":{"model":"gpt-5.6-sol","input":payload.as_str()}},
                        "responseStatus": 200,
                        "responseBody": {"kind":"json","value":{"status":"completed"}}
                    }),
                )?;
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
    let elapsed = started.elapsed().as_secs_f64();
    let _ = shutdown_tx.send(());
    server.await.context("join HTTP benchmark Collector")??;
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
        "elapsed_seconds": elapsed,
        "records_per_second": observed_records as f64 / elapsed,
        "payload_mib_per_second": payload_bytes / elapsed / 1024.0 / 1024.0,
        "wire_mib_per_second": wire_bytes as f64 / elapsed / 1024.0 / 1024.0,
        "batch_latency_ms": {
            "p50": percentile(&latency_ms, 0.50),
            "p95": percentile(&latency_ms, 0.95),
            "p99": percentile(&latency_ms, 0.99),
            "max": latency_ms.last().copied().unwrap_or(0.0),
        },
        "scope": "loopback HTTP NDJSON batching + normalization + sharded WAL/redb durable acknowledgements; excludes Relay and object upload",
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
