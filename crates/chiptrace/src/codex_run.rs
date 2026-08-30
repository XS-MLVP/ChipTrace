//! Task-scoped Codex producer orchestration.
//!
//! This module binds one explicit Harness task to one Codex process, injects
//! the same correlation context into model API requests, and incrementally
//! exports every native rollout-trace bundle written by that process. The
//! Codex thread and response lifecycle remain runtime facts; only the Harness
//! owns the task boundary.

use crate::codex_trace_bundle::{
    BundleExportConfig, BundleExportSummary, BundleExportTarget, export_codex_trace_bundle,
};
use crate::harness::{
    FlushSummary, Harness, HarnessConfig, HarnessIdentity, HarnessInspection, HarnessTarget,
    LifecycleEventInput,
};
use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::time::{Instant, MissedTickBehavior};

const CODEX_ROLLOUT_TRACE_ROOT_ENV: &str = "CODEX_ROLLOUT_TRACE_ROOT";
const CODE_MODE_HOST_CONFIG: &str = "features.code_mode_host=true";
const MIN_RETRY_ATTEMPTS: usize = 20;
const MAX_PROVIDER_RETRY_ATTEMPTS: u64 = 100;

const CORRELATION_HEADER_ENV: &[(&str, &str)] = &[
    ("x-chiptrace-task-session-id", "CHIPTRACE_TASK_SESSION_ID"),
    ("x-chiptrace-root-session-id", "CHIPTRACE_ROOT_SESSION_ID"),
    (
        "x-chiptrace-parent-session-id",
        "CHIPTRACE_PARENT_SESSION_ID",
    ),
    ("x-chiptrace-goal-id", "CHIPTRACE_GOAL_ID"),
    ("x-chiptrace-agent-id", "CHIPTRACE_AGENT_ID"),
    ("x-chiptrace-branch-id", "CHIPTRACE_BRANCH_ID"),
    ("x-chiptrace-session-id", "CHIPTRACE_SESSION_ID"),
    ("x-chiptrace-thread-id", "CHIPTRACE_THREAD_ID"),
    (
        "x-chiptrace-previous-response-id",
        "CHIPTRACE_PREVIOUS_RESPONSE_ID",
    ),
    ("traceparent", "CHIPTRACE_TRACEPARENT"),
];

#[derive(Debug, Clone)]
pub enum CodexRunTarget {
    Relay(String),
    Jsonl(PathBuf),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum CodexTaskPhase {
    /// Create and close one task around this Codex process.
    #[default]
    Single,
    /// Create the task, run one Codex process, and leave the task open.
    Begin,
    /// Attach another Codex process to an existing open task.
    Continue,
    /// Attach the final Codex process and emit the task terminal event.
    Finish,
}

impl CodexTaskPhase {
    fn starts_task(self) -> bool {
        matches!(self, Self::Single | Self::Begin)
    }

    fn closes_task(self) -> bool {
        matches!(self, Self::Single | Self::Finish)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Begin => "begin",
            Self::Continue => "continue",
            Self::Finish => "finish",
        }
    }
}

impl CodexRunTarget {
    fn harness_target(&self) -> HarnessTarget {
        match self {
            Self::Relay(url) => HarnessTarget::Relay(url.clone()),
            Self::Jsonl(path) => HarnessTarget::Jsonl(path.clone()),
        }
    }

    fn bundle_target(&self) -> BundleExportTarget {
        match self {
            Self::Relay(url) => BundleExportTarget::Relay(url.clone()),
            Self::Jsonl(path) => BundleExportTarget::Jsonl(path.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CodexRunConfig {
    pub codex_bin: PathBuf,
    pub codex_args: Vec<String>,
    pub working_directory: PathBuf,
    pub state_root: PathBuf,
    pub trace_root: Option<PathBuf>,
    pub source_namespace: String,
    pub target: CodexRunTarget,
    pub task_phase: CodexTaskPhase,
    pub model_provider_id: String,
    pub model_base_url: Option<String>,
    pub task_session_id: Option<String>,
    pub root_session_id: Option<String>,
    pub parent_session_id: Option<String>,
    pub goal_id: Option<String>,
    pub agent_id: Option<String>,
    pub branch_id: Option<String>,
    pub session_id: Option<String>,
    pub thread_id: Option<String>,
    pub previous_response_id: Option<String>,
    pub traceparent: Option<String>,
    pub tool_registry: Option<PathBuf>,
    pub poll_interval: Duration,
    pub shutdown_grace: Duration,
    pub retry_max_times: usize,
    pub provider_request_max_retries: u64,
    pub provider_stream_max_retries: u64,
    pub request_timeout: Duration,
    pub max_envelope_bytes: usize,
    pub batch_records: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexProcessOutcome {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub supervisor_signal: Option<String>,
    pub forced_kill: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexBundleTotals {
    pub scans: u64,
    pub transient_scan_errors: u64,
    pub captures_emitted: u64,
    pub duplicate_captures: u64,
    pub lines_read: u64,
    pub payloads_verified: u64,
    pub raw_mirrored_bytes: u64,
    pub lifecycle_events: u64,
    pub message_events: u64,
    pub inference_events: u64,
    pub tool_executions: u64,
    pub tool_registry_snapshots: u64,
    pub unknown_events: u64,
    pub unmapped_tool_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexRunSummary {
    pub ok: bool,
    pub capture_complete: bool,
    pub task_phase: String,
    pub run_status: String,
    pub task_status: String,
    pub task_terminal_emitted: bool,
    pub state_root: String,
    pub trace_root: String,
    pub task_session_id: String,
    pub root_session_id: String,
    pub traceparent: String,
    pub process: CodexProcessOutcome,
    pub bundle_totals: CodexBundleTotals,
    pub bundles: Vec<BundleExportSummary>,
    pub start_delivery_error: Option<String>,
    pub final_delivery_error: Option<String>,
    pub last_transient_scan_error: Option<String>,
    pub final_flush: Option<FlushSummary>,
    pub harness: HarnessInspection,
}

#[derive(Debug, Default)]
struct ExportAccumulator {
    totals: CodexBundleTotals,
    transient_scan_errors: u64,
    last_transient_scan_error: Option<String>,
}

impl ExportAccumulator {
    fn observe(&mut self, summary: &BundleExportSummary) {
        self.totals.scans = self.totals.scans.saturating_add(1);
        self.totals.captures_emitted = self
            .totals
            .captures_emitted
            .saturating_add(summary.captures_emitted);
        self.totals.duplicate_captures = self
            .totals
            .duplicate_captures
            .saturating_add(summary.duplicate_captures);
        self.totals.lines_read = self.totals.lines_read.saturating_add(summary.lines_read);
        self.totals.payloads_verified = self
            .totals
            .payloads_verified
            .saturating_add(summary.payloads_verified);
        self.totals.raw_mirrored_bytes = self
            .totals
            .raw_mirrored_bytes
            .saturating_add(summary.raw_mirrored_bytes);
        self.totals.lifecycle_events = self
            .totals
            .lifecycle_events
            .saturating_add(summary.lifecycle_events);
        self.totals.message_events = self
            .totals
            .message_events
            .saturating_add(summary.message_events);
        self.totals.inference_events = self
            .totals
            .inference_events
            .saturating_add(summary.inference_events);
        self.totals.tool_executions = self
            .totals
            .tool_executions
            .saturating_add(summary.tool_executions);
        self.totals.tool_registry_snapshots = self
            .totals
            .tool_registry_snapshots
            .saturating_add(summary.tool_registry_snapshots);
        self.totals.unknown_events = self
            .totals
            .unknown_events
            .saturating_add(summary.unknown_events);
        self.totals.unmapped_tool_events = self
            .totals
            .unmapped_tool_events
            .saturating_add(summary.unmapped_tool_events);
    }

    fn observe_transient_error(&mut self, error: &anyhow::Error) {
        self.transient_scan_errors = self.transient_scan_errors.saturating_add(1);
        self.last_transient_scan_error = Some(error.to_string());
    }

    fn finish(mut self) -> (CodexBundleTotals, Option<String>) {
        self.totals.transient_scan_errors = self.transient_scan_errors;
        (self.totals, self.last_transient_scan_error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupervisorSignal {
    Interrupt,
    Terminate,
}

fn open_task_harness(config: &CodexRunConfig, registry: Option<Value>) -> Result<Harness> {
    if config.task_phase.starts_task() {
        let mut harness_config =
            HarnessConfig::new(config.state_root.clone(), &config.source_namespace);
        harness_config.task_session_id = config.task_session_id.clone();
        harness_config.root_session_id = config.root_session_id.clone();
        harness_config.parent_session_id = config.parent_session_id.clone();
        harness_config.goal_id = config.goal_id.clone();
        harness_config.agent_id = config.agent_id.clone();
        harness_config.branch_id = config.branch_id.clone();
        harness_config.session_id = config.session_id.clone();
        harness_config.thread_id = config.thread_id.clone();
        harness_config.previous_response_id = config.previous_response_id.clone();
        harness_config.traceparent = config.traceparent.clone();
        harness_config.target = Some(config.target.harness_target());
        harness_config.tool_registry = registry;
        harness_config.retry_max_times = config.retry_max_times;
        harness_config.request_timeout = config.request_timeout;
        harness_config.max_envelope_bytes = config.max_envelope_bytes;
        harness_config.batch_records = config.batch_records;
        return Harness::start(harness_config);
    }

    let harness = Harness::open_with_target(
        config.state_root.clone(),
        Some(config.target.harness_target()),
    )?;
    let identity = harness.identity();
    validate_resumed_identity(
        "task_session_id",
        config.task_session_id.as_deref(),
        Some(identity.task_session_id.as_str()),
    )?;
    validate_resumed_identity(
        "root_session_id",
        config.root_session_id.as_deref(),
        Some(identity.root_session_id.as_str()),
    )?;
    validate_resumed_identity(
        "parent_session_id",
        config.parent_session_id.as_deref(),
        identity.parent_session_id.as_deref(),
    )?;
    validate_resumed_identity(
        "goal_id",
        config.goal_id.as_deref(),
        identity.goal_id.as_deref(),
    )?;
    validate_resumed_identity(
        "agent_id",
        config.agent_id.as_deref(),
        identity.agent_id.as_deref(),
    )?;
    validate_resumed_identity(
        "branch_id",
        config.branch_id.as_deref(),
        identity.branch_id.as_deref(),
    )?;
    validate_resumed_identity(
        "traceparent",
        config.traceparent.as_deref(),
        Some(identity.traceparent.as_str()),
    )?;
    if harness.source_namespace() != config.source_namespace {
        bail!(
            "resumed task source_namespace mismatch: expected={} observed={}",
            harness.source_namespace(),
            config.source_namespace
        );
    }
    if harness.inspect()?.status != "open" {
        bail!("resumed Codex task is already closed");
    }
    Ok(harness)
}

fn validate_resumed_identity(
    field: &str,
    requested: Option<&str>,
    persisted: Option<&str>,
) -> Result<()> {
    if let Some(requested) = requested
        && Some(requested) != persisted
    {
        bail!(
            "resumed task {field} mismatch: requested={requested} persisted={}",
            persisted.unwrap_or("<missing>")
        );
    }
    Ok(())
}

impl SupervisorSignal {
    fn name(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Terminate => "terminate",
        }
    }

    #[cfg(unix)]
    fn raw(self) -> i32 {
        match self {
            Self::Interrupt => libc::SIGINT,
            Self::Terminate => libc::SIGTERM,
        }
    }
}

/// Run one task-scoped Codex process and persist every observed producer fact.
pub async fn run_codex(config: CodexRunConfig) -> Result<CodexRunSummary> {
    validate_config(&config)?;
    let codex_bin = config
        .codex_bin
        .canonicalize()
        .with_context(|| format!("resolve Codex binary {}", config.codex_bin.display()))?;
    let working_directory = config.working_directory.canonicalize().with_context(|| {
        format!(
            "resolve Codex working directory {}",
            config.working_directory.display()
        )
    })?;

    let trace_root = config
        .trace_root
        .clone()
        .unwrap_or_else(|| config.state_root.join("trace-bundles"));
    prepare_empty_trace_root(&trace_root)?;
    let trace_root = trace_root
        .canonicalize()
        .with_context(|| format!("resolve trace root {}", trace_root.display()))?;

    let registry = config
        .tool_registry
        .as_ref()
        .map(|path| {
            let bytes = fs::read(path)
                .with_context(|| format!("read runtime Tool Registry {}", path.display()))?;
            serde_json::from_slice::<Value>(&bytes)
                .with_context(|| format!("parse runtime Tool Registry {}", path.display()))
        })
        .transpose()?;

    let mut harness = open_task_harness(&config, registry)?;
    let identity = harness.identity().clone();

    let start_delivery_error = harness.flush().await.err().map(|error| error.to_string());
    let mut child = match spawn_codex(
        &config,
        &codex_bin,
        &working_directory,
        &trace_root,
        &identity,
    ) {
        Ok(child) => child,
        Err(error) => {
            let reason = format!("Codex process failed to start: {error}");
            if config.task_phase.closes_task() {
                let _ = harness.task_end("failed", Some(reason));
            } else {
                let _ = harness.emit_lifecycle(LifecycleEventInput {
                    event_type: "codex_run_end".to_owned(),
                    status: "failed".to_owned(),
                    reason: Some(reason),
                    turn_id: None,
                    details: None,
                    occurred_at: None,
                });
            }
            let _ = harness.flush().await;
            return Err(error);
        }
    };

    let mut accumulator = ExportAccumulator::default();
    let (status, supervisor_signal, forced_kill) = supervise_child(
        &mut child,
        &config,
        &trace_root,
        &identity,
        &mut accumulator,
    )
    .await?;
    let process = process_outcome(status, supervisor_signal, forced_kill);

    let final_scan = scan_bundles(&config, &trace_root, &identity, true, &mut accumulator).await;
    let (bundles, final_scan_error) = match final_scan {
        Ok(summaries) => (summaries, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let bundles_complete = !bundles.is_empty()
        && bundles.iter().all(|summary| {
            summary.bundle_complete
                && summary.open_tail_bytes == 0
                && summary.open_runtime_objects == 0
        });
    let runtime_fields_complete = accumulator.totals.unknown_events == 0
        && accumulator.totals.unmapped_tool_events == 0
        && accumulator.totals.tool_registry_snapshots > 0;
    let capture_complete =
        final_scan_error.is_none() && bundles_complete && runtime_fields_complete;

    let run_status = terminal_status(&process, capture_complete);
    let terminal_reason = terminal_reason(&process, capture_complete, final_scan_error.as_deref());
    let task_terminal_emitted = config.task_phase.closes_task()
        || matches!(run_status.as_str(), "cancelled" | "terminated");
    if task_terminal_emitted {
        match run_status.as_str() {
            "cancelled" => {
                harness.cancel(Some(terminal_reason))?;
            }
            "terminated" => {
                harness.emit_lifecycle(LifecycleEventInput {
                    event_type: "terminated".to_owned(),
                    status: "terminated".to_owned(),
                    reason: Some(terminal_reason),
                    turn_id: None,
                    details: None,
                    occurred_at: None,
                })?;
            }
            _ => {
                harness.task_end(run_status.clone(), Some(terminal_reason))?;
            }
        }
    } else {
        harness.emit_lifecycle(LifecycleEventInput {
            event_type: "codex_run_end".to_owned(),
            status: run_status.clone(),
            reason: Some(terminal_reason),
            turn_id: None,
            details: Some(json!({
                "capture_complete":capture_complete,
                "process_success":process.success,
            })),
            occurred_at: None,
        })?;
    }
    let (final_flush, final_delivery_error) = match harness.flush().await {
        Ok(summary) => (Some(summary), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let inspection = harness.inspect()?;
    let delivery_complete = final_delivery_error.is_none() && inspection.pending_records == 0;
    let ok = process.success && capture_complete && delivery_complete;
    let (bundle_totals, last_transient_scan_error) = accumulator.finish();

    Ok(CodexRunSummary {
        ok,
        capture_complete,
        task_phase: config.task_phase.as_str().to_owned(),
        run_status,
        task_status: inspection.status.clone(),
        task_terminal_emitted,
        state_root: config.state_root.to_string_lossy().into_owned(),
        trace_root: trace_root.to_string_lossy().into_owned(),
        task_session_id: identity.task_session_id,
        root_session_id: identity.root_session_id,
        traceparent: identity.traceparent,
        process,
        bundle_totals,
        bundles,
        start_delivery_error,
        final_delivery_error,
        last_transient_scan_error,
        final_flush,
        harness: inspection,
    })
}

async fn supervise_child(
    child: &mut Child,
    config: &CodexRunConfig,
    trace_root: &Path,
    identity: &HarnessIdentity,
    accumulator: &mut ExportAccumulator,
) -> Result<(ExitStatus, Option<SupervisorSignal>, bool)> {
    let mut interval = tokio::time::interval(config.poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut supervisor_signal = None;
    let mut signal_sent_at = None;
    let mut forced_kill = false;
    let interrupt = tokio::signal::ctrl_c();
    let terminate = wait_for_terminate();
    tokio::pin!(interrupt);
    tokio::pin!(terminate);

    loop {
        tokio::select! {
            status = child.wait() => return Ok((status?, supervisor_signal, forced_kill)),
            _ = interval.tick() => {
                if let Err(error) = scan_bundles(
                    config,
                    trace_root,
                    identity,
                    false,
                    accumulator,
                ).await {
                    accumulator.observe_transient_error(&error);
                }
                if signal_sent_at.is_some_and(|started: Instant| started.elapsed() >= config.shutdown_grace)
                    && !forced_kill
                {
                    child.start_kill().context("force-stop Codex after shutdown grace")?;
                    forced_kill = true;
                }
            }
            result = &mut interrupt, if supervisor_signal.is_none() => {
                result?;
                supervisor_signal = Some(SupervisorSignal::Interrupt);
                signal_sent_at = Some(Instant::now());
                forward_signal(child, SupervisorSignal::Interrupt)?;
            }
            result = &mut terminate, if supervisor_signal.is_none() => {
                result?;
                supervisor_signal = Some(SupervisorSignal::Terminate);
                signal_sent_at = Some(Instant::now());
                forward_signal(child, SupervisorSignal::Terminate)?;
            }
        }
    }
}

fn spawn_codex(
    config: &CodexRunConfig,
    codex_bin: &Path,
    working_directory: &Path,
    trace_root: &Path,
    identity: &HarnessIdentity,
) -> Result<Child> {
    let headers = correlation_headers(identity);
    let mut command = Command::new(codex_bin);
    command
        .current_dir(working_directory)
        .env(CODEX_ROLLOUT_TRACE_ROOT_ENV, trace_root)
        .kill_on_drop(true)
        .arg("-c")
        .arg(CODE_MODE_HOST_CONFIG);

    for (header, value) in &headers {
        let environment = header_environment(header)
            .ok_or_else(|| anyhow::anyhow!("unsupported correlation header {header}"))?;
        command.env(environment, value);
        command.arg("-c").arg(provider_header_override(
            &config.model_provider_id,
            header,
            environment,
        ));
    }
    command
        .arg("-c")
        .arg(format!(
            "model_providers.{}.request_max_retries={}",
            config.model_provider_id, config.provider_request_max_retries
        ))
        .arg("-c")
        .arg(format!(
            "model_providers.{}.stream_max_retries={}",
            config.model_provider_id, config.provider_stream_max_retries
        ));
    if let Some(base_url) = config.model_base_url.as_deref() {
        command.arg("-c").arg(format!(
            "model_providers.{}.base_url={}",
            config.model_provider_id,
            serde_json::to_string(base_url).expect("serializing a string cannot fail")
        ));
    }
    command.args(&config.codex_args);
    command
        .spawn()
        .with_context(|| format!("start Codex process {}", codex_bin.display()))
}

async fn scan_bundles(
    config: &CodexRunConfig,
    trace_root: &Path,
    identity: &HarnessIdentity,
    require_complete: bool,
    accumulator: &mut ExportAccumulator,
) -> Result<Vec<BundleExportSummary>> {
    let bundles = discover_bundles(trace_root, require_complete)?;
    if require_complete && bundles.is_empty() {
        bail!("Codex process produced no native trace bundle");
    }
    let mut summaries = Vec::with_capacity(bundles.len());
    for bundle in bundles {
        let key = path_digest(&bundle)?;
        let summary = export_codex_trace_bundle(BundleExportConfig {
            input: bundle,
            state_root: config.state_root.join("bundle-exporter").join(key),
            target: config.target.bundle_target(),
            source_namespace: config.source_namespace.clone(),
            tool_registry: config.tool_registry.clone(),
            batch_records: config.batch_records,
            max_envelope_bytes: config.max_envelope_bytes,
            request_timeout: config.request_timeout,
            retry_max_times: config.retry_max_times,
            task_session_id: Some(identity.task_session_id.clone()),
            root_session_id: Some(identity.root_session_id.clone()),
            parent_session_id: identity.parent_session_id.clone(),
            goal_id: identity.goal_id.clone(),
            agent_id: identity.agent_id.clone(),
            branch_id: identity.branch_id.clone(),
            traceparent: Some(identity.traceparent.clone()),
            mirror_root: Some(config.state_root.join("raw-bundles")),
            require_complete,
        })
        .await?;
        accumulator.observe(&summary);
        summaries.push(summary);
    }
    Ok(summaries)
}

fn discover_bundles(trace_root: &Path, strict: bool) -> Result<Vec<PathBuf>> {
    let mut bundles = Vec::new();
    for entry in fs::read_dir(trace_root)
        .with_context(|| format!("read Codex trace root {}", trace_root.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() && path.join("manifest.json").is_file() {
            bundles.push(path);
        } else if strict {
            bail!(
                "unexpected incomplete entry in Codex trace root: {}",
                path.display()
            );
        }
    }
    bundles.sort();
    Ok(bundles)
}

fn prepare_empty_trace_root(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("create Codex trace root {}", path.display()))?;
    if fs::read_dir(path)?.next().transpose()?.is_some() {
        bail!(
            "Codex trace root must be empty for one task: {}",
            path.display()
        );
    }
    Ok(())
}

fn correlation_headers(identity: &HarnessIdentity) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::from([
        (
            "x-chiptrace-task-session-id".to_owned(),
            identity.task_session_id.clone(),
        ),
        (
            "x-chiptrace-root-session-id".to_owned(),
            identity.root_session_id.clone(),
        ),
        ("traceparent".to_owned(), identity.traceparent.clone()),
    ]);
    for (header, value) in [
        (
            "x-chiptrace-parent-session-id",
            identity.parent_session_id.as_deref(),
        ),
        ("x-chiptrace-goal-id", identity.goal_id.as_deref()),
        ("x-chiptrace-agent-id", identity.agent_id.as_deref()),
        ("x-chiptrace-branch-id", identity.branch_id.as_deref()),
        ("x-chiptrace-session-id", identity.session_id.as_deref()),
        ("x-chiptrace-thread-id", identity.thread_id.as_deref()),
        (
            "x-chiptrace-previous-response-id",
            identity.previous_response_id.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            headers.insert(header.to_owned(), value.to_owned());
        }
    }
    headers
}

fn header_environment(header: &str) -> Option<&'static str> {
    CORRELATION_HEADER_ENV
        .iter()
        .find_map(|(candidate, environment)| (*candidate == header).then_some(*environment))
}

fn provider_header_override(provider: &str, header: &str, environment: &str) -> String {
    format!("model_providers.{provider}.env_http_headers.{header}=\"{environment}\"")
}

fn validate_config(config: &CodexRunConfig) -> Result<()> {
    if !config.codex_bin.is_file() {
        bail!(
            "Codex binary is not a regular file: {}",
            config.codex_bin.display()
        );
    }
    if !config.working_directory.is_dir() {
        bail!(
            "Codex working directory is not a directory: {}",
            config.working_directory.display()
        );
    }
    if config.source_namespace.trim().is_empty() {
        bail!("source namespace must not be empty");
    }
    if config.task_phase != CodexTaskPhase::Single && config.trace_root.is_none() {
        bail!("multi-phase Codex tasks require an explicit empty --trace-root for each phase");
    }
    if config.model_provider_id.is_empty()
        || !config
            .model_provider_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("model provider ID must be a TOML bare key");
    }
    if config.retry_max_times < MIN_RETRY_ATTEMPTS {
        bail!("Codex producer delivery requires at least 20 retry attempts");
    }
    for (name, value) in [
        (
            "provider_request_max_retries",
            config.provider_request_max_retries,
        ),
        (
            "provider_stream_max_retries",
            config.provider_stream_max_retries,
        ),
    ] {
        if !(MIN_RETRY_ATTEMPTS as u64..=MAX_PROVIDER_RETRY_ATTEMPTS).contains(&value) {
            bail!("{name} must be between 20 and 100");
        }
    }
    if config.poll_interval.is_zero() {
        bail!("Codex bundle poll interval must be positive");
    }
    if config.shutdown_grace.is_zero() {
        bail!("Codex shutdown grace must be positive");
    }
    if config.batch_records == 0 || config.max_envelope_bytes == 0 {
        bail!("Codex producer batch and envelope limits must be positive");
    }
    if let Some(url) = config.model_base_url.as_deref() {
        let parsed = reqwest::Url::parse(url).context("parse model base URL")?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            bail!("model base URL must be an http(s) URL without credentials or fragment");
        }
    }
    reject_conflicting_codex_args(config)?;
    Ok(())
}

fn reject_conflicting_codex_args(config: &CodexRunConfig) -> Result<()> {
    let provider_prefix = format!("model_providers.{}.", config.model_provider_id);
    for argument in &config.codex_args {
        if argument.contains("features.code_mode_host") {
            bail!("Codex arguments cannot override the required Runtime Tool Registry producer");
        }
        let conflicts_with_headers = argument.contains("env_http_headers")
            || CORRELATION_HEADER_ENV
                .iter()
                .any(|(header, _)| argument.contains(header));
        let conflicts_with_retries =
            argument.contains("request_max_retries") || argument.contains("stream_max_retries");
        let conflicts_with_base = config.model_base_url.is_some() && argument.contains("base_url");
        if argument.contains(&provider_prefix)
            && (conflicts_with_headers || conflicts_with_retries || conflicts_with_base)
        {
            bail!("Codex arguments cannot override ChipTrace provider correlation settings");
        }
    }
    Ok(())
}

fn terminal_status(process: &CodexProcessOutcome, capture_complete: bool) -> String {
    match process.supervisor_signal.as_deref() {
        Some("interrupt") => "cancelled".to_owned(),
        Some("terminate") => "terminated".to_owned(),
        _ if !capture_complete => "incomplete".to_owned(),
        _ if process.success => "completed".to_owned(),
        _ => "failed".to_owned(),
    }
}

fn terminal_reason(
    process: &CodexProcessOutcome,
    capture_complete: bool,
    final_scan_error: Option<&str>,
) -> String {
    if let Some(signal) = process.supervisor_signal.as_deref() {
        return format!("Codex task stopped after supervisor {signal} signal");
    }
    if !capture_complete {
        return final_scan_error
            .map(|error| format!("Codex runtime trace incomplete: {error}"))
            .unwrap_or_else(|| {
                "Codex runtime trace contains unknown, unmapped, or open events".to_owned()
            });
    }
    if process.success {
        "Codex process exited successfully and native runtime trace closed".to_owned()
    } else {
        format!(
            "Codex process failed with exit_code={:?}, signal={:?}",
            process.exit_code, process.signal
        )
    }
}

fn process_outcome(
    status: ExitStatus,
    supervisor_signal: Option<SupervisorSignal>,
    forced_kill: bool,
) -> CodexProcessOutcome {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;

    CodexProcessOutcome {
        success: status.success(),
        exit_code: status.code(),
        #[cfg(unix)]
        signal: status.signal(),
        #[cfg(not(unix))]
        signal: None,
        supervisor_signal: supervisor_signal.map(|signal| signal.name().to_owned()),
        forced_kill,
    }
}

#[cfg(unix)]
fn forward_signal(child: &Child, signal: SupervisorSignal) -> Result<()> {
    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("Codex process has no active PID"))?;
    // SAFETY: libc::kill does not retain pointers; pid and signal are scalar values.
    let result = unsafe { libc::kill(pid as i32, signal.raw()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("forward signal to Codex process");
    }
    Ok(())
}

#[cfg(not(unix))]
fn forward_signal(child: &Child, _signal: SupervisorSignal) -> Result<()> {
    child.start_kill().context("stop Codex process")
}

#[cfg(unix)]
async fn wait_for_terminate() -> Result<()> {
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    signal.recv().await;
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_terminate() -> Result<()> {
    std::future::pending::<()>().await;
    Ok(())
}

fn path_digest(path: &Path) -> Result<String> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolve Codex bundle {}", path.display()))?;
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> HarnessIdentity {
        HarnessIdentity {
            task_session_id: "task-1".to_owned(),
            root_session_id: "root-1".to_owned(),
            parent_session_id: Some("parent-1".to_owned()),
            goal_id: Some("goal-1".to_owned()),
            agent_id: Some("agent-1".to_owned()),
            branch_id: Some("branch-1".to_owned()),
            session_id: None,
            thread_id: None,
            previous_response_id: None,
            traceparent: "00-11111111111111111111111111111111-2222222222222222-01".to_owned(),
        }
    }

    #[test]
    fn correlation_headers_use_environment_backed_provider_overrides() {
        let headers = correlation_headers(&identity());
        assert_eq!(headers.len(), 7);
        for (header, value) in headers {
            let environment = header_environment(&header).unwrap();
            assert!(!value.is_empty());
            assert_eq!(
                provider_header_override("OpenAI", &header, environment),
                format!("model_providers.OpenAI.env_http_headers.{header}=\"{environment}\"")
            );
        }
    }

    #[test]
    fn strict_bundle_discovery_rejects_silent_partial_entries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("trace-partial")).unwrap();
        assert!(discover_bundles(temp.path(), false).unwrap().is_empty());
        let error = discover_bundles(temp.path(), true).unwrap_err();
        assert!(error.to_string().contains("unexpected incomplete entry"));
    }

    #[test]
    fn terminal_status_keeps_task_failure_separate_from_capture_failure() {
        let failed_task = CodexProcessOutcome {
            success: false,
            exit_code: Some(7),
            ..CodexProcessOutcome::default()
        };
        assert_eq!(terminal_status(&failed_task, true), "failed");
        assert_eq!(terminal_status(&failed_task, false), "incomplete");
        let interrupted = CodexProcessOutcome {
            supervisor_signal: Some("interrupt".to_owned()),
            ..CodexProcessOutcome::default()
        };
        assert_eq!(terminal_status(&interrupted, true), "cancelled");
    }

    #[test]
    fn task_phases_have_explicit_boundary_ownership() {
        assert!(CodexTaskPhase::Single.starts_task());
        assert!(CodexTaskPhase::Single.closes_task());
        assert!(CodexTaskPhase::Begin.starts_task());
        assert!(!CodexTaskPhase::Begin.closes_task());
        assert!(!CodexTaskPhase::Continue.starts_task());
        assert!(!CodexTaskPhase::Continue.closes_task());
        assert!(!CodexTaskPhase::Finish.starts_task());
        assert!(CodexTaskPhase::Finish.closes_task());
    }

    #[test]
    fn codex_args_cannot_disable_the_runtime_tool_registry_producer() {
        let temporary = tempfile::tempdir().unwrap();
        let config = CodexRunConfig {
            codex_bin: std::env::current_exe().unwrap(),
            codex_args: vec!["-c".to_owned(), "features.code_mode_host=false".to_owned()],
            working_directory: temporary.path().to_path_buf(),
            state_root: temporary.path().join("state"),
            trace_root: None,
            source_namespace: "fixture".to_owned(),
            target: CodexRunTarget::Jsonl(temporary.path().join("captures.jsonl")),
            task_phase: CodexTaskPhase::Single,
            model_provider_id: "OpenAI".to_owned(),
            model_base_url: None,
            task_session_id: None,
            root_session_id: None,
            parent_session_id: None,
            goal_id: None,
            agent_id: None,
            branch_id: None,
            session_id: None,
            thread_id: None,
            previous_response_id: None,
            traceparent: None,
            tool_registry: None,
            poll_interval: Duration::from_millis(250),
            shutdown_grace: Duration::from_secs(30),
            retry_max_times: 25,
            provider_request_max_retries: 25,
            provider_stream_max_retries: 25,
            request_timeout: Duration::from_secs(30),
            max_envelope_bytes: 1024,
            batch_records: 1,
        };
        assert!(
            validate_config(&config)
                .unwrap_err()
                .to_string()
                .contains("Runtime Tool Registry producer")
        );
    }
}
