use crate::capture::normalize_capture;
use crate::delivery::{DeliveryConfig, DeliveryTarget, deliver_batch};
use crate::tool_registry::{
    LoadedToolRegistry, ToolRegistryEntry, canonical_runtime_tool_name, load_tool_registry,
    registry_entry_identity,
};
use anyhow::{Context, Result, bail};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::future::Future;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use walkdir::WalkDir;

pub const CODEX_ROLLOUT_SCHEMA_VERSION: &str = "chiptrace.codex-rollout.v1";
pub use crate::tool_registry::TOOL_REGISTRY_SCHEMA_VERSION;
const CHECKPOINT_SCHEMA_VERSION: &str = "chiptrace.codex-rollout-checkpoint.v1";
const CHECKPOINTS: TableDefinition<&str, &[u8]> = TableDefinition::new("codex_rollout_checkpoints");
const MAX_TRACKED_MODEL_TOOL_CALLS: usize = 16_384;

pub type ExportTarget = DeliveryTarget;

#[derive(Debug, Clone)]
pub struct ExportConfig {
    pub input: PathBuf,
    pub state_root: PathBuf,
    pub target: ExportTarget,
    pub source_namespace: String,
    pub tool_registry: Option<PathBuf>,
    pub batch_records: usize,
    pub max_envelope_bytes: usize,
    pub request_timeout: Duration,
    pub retry_max_times: usize,
    pub task_session_id: Option<String>,
    pub root_session_id: Option<String>,
    pub parent_session_id: Option<String>,
    pub goal_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportSummary {
    pub input: String,
    pub source_session_id: Option<String>,
    pub source_cli_version: Option<String>,
    pub start_offset: u64,
    pub committed_offset: u64,
    pub lines_read: u64,
    pub metadata_lines: u64,
    pub captures_emitted: u64,
    pub duplicate_captures: u64,
    pub lifecycle_events: u64,
    pub message_events: u64,
    pub token_events: u64,
    pub tool_executions: u64,
    pub unmapped_tool_events: u64,
    pub unknown_events: u64,
    pub incomplete_tail_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchSummary {
    pub cycles: u64,
    pub stop_reason: String,
    pub export: ExportSummary,
}

pub fn resolve_hook_rollout(raw: &[u8], session_root: &Path) -> Result<PathBuf> {
    let input: Value = serde_json::from_slice(raw).context("parse Codex hook input")?;
    if let Some(event) = string(&input, "hook_event_name")
        && !event.eq_ignore_ascii_case("stop")
    {
        bail!("Codex rollout hook only accepts Stop events");
    }
    let root = session_root
        .canonicalize()
        .with_context(|| format!("resolve Codex session root {}", session_root.display()))?;
    if let Some(path) = string(&input, "transcript_path").or_else(|| string(&input, "rollout_path"))
    {
        let path = PathBuf::from(path)
            .canonicalize()
            .with_context(|| format!("resolve hook rollout path {path}"))?;
        if !path.starts_with(&root) || !path.is_file() {
            bail!("hook rollout path is outside the configured Codex session root");
        }
        if let Some(session_id) = string(&input, "session_id") {
            verify_rollout_session_id(&path, session_id)?;
        }
        return Ok(path);
    }
    let session_id = string(&input, "session_id")
        .filter(|value| {
            value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .ok_or_else(|| anyhow::anyhow!("Codex hook input is missing a safe session_id"))?;
    let mut candidates = Vec::new();
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if name.ends_with(".jsonl") && name.contains(session_id) {
            let path = entry.path().canonicalize()?;
            if verify_rollout_session_id(&path, session_id).is_ok() {
                candidates.push(path);
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [path] => Ok(path.clone()),
        [] => bail!("no Codex rollout matches hook session_id {session_id}"),
        _ => bail!("multiple Codex rollouts match hook session_id {session_id}"),
    }
}

fn verify_rollout_session_id(path: &Path, expected: &str) -> Result<()> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let value: Value = serde_json::from_str(line.trim_end())?;
    let observed = value
        .get("payload")
        .and_then(|payload| string(payload, "session_id").or_else(|| string(payload, "id")))
        .ok_or_else(|| anyhow::anyhow!("Codex rollout first line has no session identity"))?;
    if observed != expected {
        bail!("Codex rollout session identity does not match hook input");
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct RolloutContext {
    source_session_id: Option<String>,
    source_cli_version: Option<String>,
    model_provider: Option<String>,
    system_prompt: Option<String>,
    active_turn_id: Option<String>,
    producer_model: Option<String>,
    producer_effort: Option<String>,
    parent_agent_thread_id: Option<String>,
    agent_path: Option<String>,
    thread_source: Option<String>,
    model_tool_calls: BTreeMap<String, ObservedModelToolCall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObservedModelToolCall {
    name: String,
    event_type: String,
    source_ordinal: u64,
    turn_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    schema_version: String,
    source_path: String,
    committed_offset: u64,
    last_line_start: u64,
    last_line_bytes: u64,
    last_line_sha256: String,
    last_ordinal: Option<u64>,
    context: RolloutContext,
}

impl Checkpoint {
    fn new(source_path: String) -> Self {
        Self {
            schema_version: CHECKPOINT_SCHEMA_VERSION.to_owned(),
            source_path,
            committed_offset: 0,
            last_line_start: 0,
            last_line_bytes: 0,
            last_line_sha256: String::new(),
            last_ordinal: None,
            context: RolloutContext::default(),
        }
    }
}

struct CheckpointStore {
    database: Database,
}

impl CheckpointStore {
    fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        let database = Database::create(root.join("codex-rollout-checkpoints.redb"))?;
        let transaction = database.begin_write()?;
        transaction.open_table(CHECKPOINTS)?;
        transaction.commit()?;
        Ok(Self { database })
    }

    fn load(&self, key: &str, source_path: String) -> Result<Checkpoint> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(CHECKPOINTS)?;
        let checkpoint = table
            .get(key)?
            .map(|value| serde_json::from_slice::<Checkpoint>(value.value()))
            .transpose()?
            .unwrap_or_else(|| Checkpoint::new(source_path.clone()));
        if checkpoint.schema_version != CHECKPOINT_SCHEMA_VERSION {
            bail!("unsupported Codex rollout checkpoint schema");
        }
        if checkpoint.source_path != source_path {
            bail!("Codex rollout checkpoint source path changed");
        }
        Ok(checkpoint)
    }

    fn save(&self, key: &str, checkpoint: &Checkpoint) -> Result<()> {
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(CHECKPOINTS)?;
            if let Some(current) = table.get(key)? {
                let current: Checkpoint = serde_json::from_slice(current.value())?;
                if current.committed_offset > checkpoint.committed_offset {
                    return Ok(());
                }
            }
            table.insert(key, serde_json::to_vec(checkpoint)?.as_slice())?;
        }
        transaction.commit()?;
        Ok(())
    }
}

type LoadedRegistry = LoadedToolRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionKind {
    Metadata,
    Lifecycle,
    Message,
    Token,
    Tool,
    Raw,
}

#[derive(Debug)]
struct ProjectedLine {
    capture: Option<Value>,
    kind: ProjectionKind,
    unknown: bool,
    unmapped_tool: bool,
    clear_active_turn: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeCallCorrelation {
    Matched,
    MissingRegistry,
    MissingModelCall,
    ToolNameMismatch,
}

impl RuntimeCallCorrelation {
    fn label(self) -> &'static str {
        match self {
            Self::Matched => "matched_model_call",
            Self::MissingRegistry => "missing_registry",
            Self::MissingModelCall => "missing_model_call",
            Self::ToolNameMismatch => "tool_name_mismatch",
        }
    }

    fn is_matched(self) -> bool {
        self == Self::Matched
    }
}

pub async fn export_codex_rollout(config: ExportConfig) -> Result<ExportSummary> {
    if config.batch_records == 0 {
        bail!("Codex rollout batch size must be positive");
    }
    if config.retry_max_times < 20 {
        bail!("Codex rollout delivery requires at least 20 retry attempts");
    }
    if config.source_namespace.trim().is_empty() {
        bail!("Codex rollout source namespace must not be empty");
    }
    let input = config
        .input
        .canonicalize()
        .with_context(|| format!("resolve Codex rollout {}", config.input.display()))?;
    if !input.is_file() {
        bail!("Codex rollout input is not a file: {}", input.display());
    }
    let source_path = input.to_string_lossy().into_owned();
    let source_key = hex::encode(Sha256::digest(source_path.as_bytes()));
    let checkpoint_store = CheckpointStore::open(&config.state_root)?;
    let mut checkpoint = checkpoint_store.load(&source_key, source_path.clone())?;
    verify_checkpoint(&input, &checkpoint)?;
    let registry = load_tool_registry(config.tool_registry.as_deref())?;
    if registry
        .as_ref()
        .is_some_and(|registry| registry.registry.producer != "codex-cli")
    {
        bail!("Codex rollout requires a codex-cli Tool Registry snapshot");
    }
    let mut summary = ExportSummary {
        input: source_path,
        start_offset: checkpoint.committed_offset,
        committed_offset: checkpoint.committed_offset,
        ..ExportSummary::default()
    };
    let mut file = File::open(&input)?;
    let file_len = file.metadata()?.len();
    file.seek(SeekFrom::Start(checkpoint.committed_offset))?;
    let mut reader = BufReader::with_capacity(4 * 1024 * 1024, file);
    let mut batch = Vec::with_capacity(config.batch_records);
    let mut batch_checkpoint = checkpoint.clone();
    loop {
        let line_start = checkpoint.committed_offset;
        let mut bytes = Vec::new();
        let read = reader.read_until(b'\n', &mut bytes)?;
        if read == 0 {
            break;
        }
        if !bytes.ends_with(b"\n") {
            summary.incomplete_tail_bytes = read as u64;
            break;
        }
        let source_record_sha256 = sha256(&bytes);
        checkpoint.committed_offset = checkpoint.committed_offset.saturating_add(read as u64);
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            checkpoint.last_line_start = line_start;
            checkpoint.last_line_bytes = read as u64;
            checkpoint.last_line_sha256 = source_record_sha256;
            continue;
        }
        let source_line = std::str::from_utf8(&bytes).context("Codex rollout must be UTF-8")?;
        let event: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse Codex rollout at byte {line_start}"))?;
        let ordinal = event
            .get("ordinal")
            .and_then(Value::as_u64)
            .or_else(|| checkpoint.last_ordinal.map(|value| value.saturating_add(1)))
            .unwrap_or(0);
        if checkpoint
            .last_ordinal
            .is_some_and(|previous| ordinal <= previous)
        {
            bail!("Codex rollout ordinal is not strictly increasing at byte {line_start}");
        }
        summary.lines_read = summary.lines_read.saturating_add(1);
        let projected = project_event(
            &event,
            source_line,
            ordinal,
            &mut checkpoint.context,
            registry.as_ref(),
            &config,
        )?;
        checkpoint.last_ordinal = Some(ordinal);
        checkpoint.last_line_start = line_start;
        checkpoint.last_line_bytes = read as u64;
        checkpoint.last_line_sha256 = source_record_sha256;
        if projected.clear_active_turn {
            checkpoint.context.active_turn_id = None;
        }
        update_summary(&mut summary, &projected);
        if let Some(capture) = projected.capture {
            let raw = serde_json::to_vec(&capture)?;
            let normalized = normalize_capture(&raw, config.max_envelope_bytes)?;
            batch.push(normalized.canonical);
            summary.captures_emitted = summary.captures_emitted.saturating_add(1);
        }
        batch_checkpoint = checkpoint.clone();
        if batch.len() >= config.batch_records {
            summary.duplicate_captures = summary
                .duplicate_captures
                .saturating_add(deliver_rollout_batch(&config, &batch).await?);
            checkpoint_store.save(&source_key, &batch_checkpoint)?;
            summary.committed_offset = batch_checkpoint.committed_offset;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        summary.duplicate_captures = summary
            .duplicate_captures
            .saturating_add(deliver_rollout_batch(&config, &batch).await?);
    }
    checkpoint_store.save(&source_key, &batch_checkpoint)?;
    summary.committed_offset = batch_checkpoint.committed_offset;
    summary.source_session_id = batch_checkpoint.context.source_session_id.clone();
    summary.source_cli_version = batch_checkpoint.context.source_cli_version.clone();
    if summary.committed_offset > file_len {
        bail!("Codex rollout checkpoint advanced beyond the source file");
    }
    Ok(summary)
}

pub async fn watch_codex_rollout<S>(
    config: ExportConfig,
    poll_interval: Duration,
    idle_exit: Option<Duration>,
    shutdown: S,
) -> Result<WatchSummary>
where
    S: Future<Output = ()>,
{
    if poll_interval < Duration::from_millis(10) {
        bail!("Codex rollout sidecar poll interval must be at least 10ms");
    }
    if idle_exit.is_some_and(|duration| duration.is_zero()) {
        bail!("Codex rollout sidecar idle exit must be positive");
    }
    tokio::pin!(shutdown);
    let mut cycles = 0_u64;
    let mut aggregate: Option<ExportSummary> = None;
    let mut idle_since = tokio::time::Instant::now();
    loop {
        let cycle = export_codex_rollout(config.clone()).await?;
        cycles = cycles.saturating_add(1);
        if cycle.lines_read > 0 {
            idle_since = tokio::time::Instant::now();
        }
        merge_export_summary(&mut aggregate, cycle);
        if idle_exit.is_some_and(|duration| idle_since.elapsed() >= duration) {
            return Ok(WatchSummary {
                cycles,
                stop_reason: "idle_exit".to_owned(),
                export: aggregate.unwrap_or_default(),
            });
        }
        tokio::select! {
            _ = &mut shutdown => {
                return Ok(WatchSummary {
                    cycles,
                    stop_reason: "shutdown_signal".to_owned(),
                    export: aggregate.unwrap_or_default(),
                });
            }
            _ = tokio::time::sleep(poll_interval) => {}
        }
    }
}

fn merge_export_summary(aggregate: &mut Option<ExportSummary>, cycle: ExportSummary) {
    let Some(output) = aggregate.as_mut() else {
        *aggregate = Some(cycle);
        return;
    };
    output.input = cycle.input;
    output.source_session_id = cycle.source_session_id;
    output.source_cli_version = cycle.source_cli_version;
    output.committed_offset = cycle.committed_offset;
    output.lines_read = output.lines_read.saturating_add(cycle.lines_read);
    output.metadata_lines = output.metadata_lines.saturating_add(cycle.metadata_lines);
    output.captures_emitted = output
        .captures_emitted
        .saturating_add(cycle.captures_emitted);
    output.duplicate_captures = output
        .duplicate_captures
        .saturating_add(cycle.duplicate_captures);
    output.lifecycle_events = output
        .lifecycle_events
        .saturating_add(cycle.lifecycle_events);
    output.message_events = output.message_events.saturating_add(cycle.message_events);
    output.token_events = output.token_events.saturating_add(cycle.token_events);
    output.tool_executions = output.tool_executions.saturating_add(cycle.tool_executions);
    output.unmapped_tool_events = output
        .unmapped_tool_events
        .saturating_add(cycle.unmapped_tool_events);
    output.unknown_events = output.unknown_events.saturating_add(cycle.unknown_events);
    output.incomplete_tail_bytes = cycle.incomplete_tail_bytes;
}

fn verify_checkpoint(path: &Path, checkpoint: &Checkpoint) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if checkpoint.committed_offset > metadata.len() {
        bail!("Codex rollout was truncated after the last checkpoint");
    }
    if checkpoint.last_line_bytes == 0 || checkpoint.last_line_sha256.is_empty() {
        return Ok(());
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(checkpoint.last_line_start))?;
    let mut bytes = vec![0_u8; checkpoint.last_line_bytes as usize];
    file.read_exact(&mut bytes)?;
    if sha256(&bytes) != checkpoint.last_line_sha256 {
        bail!("Codex rollout bytes before the checkpoint changed");
    }
    Ok(())
}

fn project_event(
    event: &Value,
    source_line: &str,
    ordinal: u64,
    context: &mut RolloutContext,
    registry: Option<&LoadedRegistry>,
    config: &ExportConfig,
) -> Result<ProjectedLine> {
    let top_type = string(event, "type").unwrap_or("");
    let payload = event.get("payload").unwrap_or(&Value::Null);
    let event_type = string(payload, "type").unwrap_or("");
    if top_type == "session_meta" {
        context.source_session_id = string(payload, "session_id")
            .or_else(|| string(payload, "id"))
            .map(str::to_owned);
        context.source_cli_version = string(payload, "cli_version").map(str::to_owned);
        context.model_provider = string(payload, "model_provider").map(str::to_owned);
        context.system_prompt = string(payload, "base_instructions").map(str::to_owned);
        context.parent_agent_thread_id = string(payload, "parent_thread_id").map(str::to_owned);
        context.agent_path = string(payload, "agent_path").map(str::to_owned);
        context.thread_source = string(payload, "thread_source").map(str::to_owned);
        return Ok(metadata_projection());
    }
    if top_type == "turn_context" {
        context.producer_model = string(payload, "model").map(str::to_owned);
        context.producer_effort = string(payload, "effort").map(str::to_owned);
        if let Some(turn_id) = string(payload, "turn_id") {
            context.active_turn_id = Some(turn_id.to_owned());
        }
    }
    if top_type == "event_msg" && event_type == "task_started" {
        context.active_turn_id = string(payload, "turn_id").map(str::to_owned);
    }
    let explicit_turn = string(payload, "turn_id")
        .or_else(|| payload.pointer("/item/turn_id").and_then(Value::as_str));
    let turn_id = explicit_turn
        .map(str::to_owned)
        .or_else(|| context.active_turn_id.clone());
    let item_type = payload
        .pointer("/item/type")
        .and_then(Value::as_str)
        .unwrap_or("");
    let completed_runtime_tool = top_type == "event_msg"
        && event_type == "item_completed"
        && matches!(
            item_type,
            "CommandExecution" | "FileChange" | "ImageView" | "CollabAgentToolCall" | "WebSearch"
        );
    let legacy_web_tool =
        top_type == "event_msg" && matches!(event_type, "web_search_begin" | "web_search_end");
    let tool_like = completed_runtime_tool || legacy_web_tool;
    let known = known_event(top_type, event_type, item_type);
    if turn_id.is_none() && known && !tool_like {
        return Ok(metadata_projection());
    }
    let session_id = context
        .source_session_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Codex rollout event precedes session_meta"))?;
    if top_type == "response_item" {
        remember_model_tool_call(context, payload, event_type, ordinal, turn_id.as_deref());
    }
    let registry_match = completed_runtime_tool
        .then(|| matching_registry_entry(payload, context, registry))
        .flatten();
    let runtime_correlation =
        completed_runtime_tool.then(|| runtime_call_correlation(payload, context, registry_match));
    let unmapped_tool = tool_like
        && (registry_match.is_none()
            || runtime_correlation.is_some_and(|correlation| !correlation.is_matched()));
    let source_digest = sha256(source_line.as_bytes());
    let capture_id = deterministic_capture_id(&session_id, ordinal);
    let timestamp = string(event, "timestamp").unwrap_or("").to_owned();
    let mut field_evidence = Vec::new();
    if let Some(turn_id) = turn_id.as_deref() {
        field_evidence.push(json!({
            "field":"traceContext.turn_id",
            "value":turn_id,
            "source":if explicit_turn.is_some() {
                "codex_rollout.payload.turn_id"
            } else {
                "codex_rollout.context.active_turn_id"
            },
            "producer":"codex_cli",
            "authority":"runtime_attested",
            "selected":true
        }));
    }
    if let Some(task_session_id) = config.task_session_id.as_deref() {
        field_evidence.push(json!({
            "field":"traceContext.task_session_id",
            "value":task_session_id,
            "source":"chiptrace_harness.task_session_id",
            "producer":"chiptrace_harness",
            "authority":"producer_asserted",
            "selected":true
        }));
    }
    let mut capture = json!({
        "recordType":"rollout_event",
        "captureId":capture_id,
        "captureStage":"event",
        "sourceNamespace":config.source_namespace,
        "receivedAt":timestamp,
        "producerModel":context.producer_model,
        "runtimeProvider":context.model_provider,
        "systemPrompt":context.system_prompt,
        "traceContext":trace_context(&session_id, turn_id.as_deref(), config),
        "fieldEvidence":field_evidence,
        "rolloutEvent":{
            "schema_version":CODEX_ROLLOUT_SCHEMA_VERSION,
            "source":"codex_rollout_jsonl",
            "source_session_id":session_id,
            "source_ordinal":ordinal,
            "source_cli_version":context.source_cli_version,
            "source_line":source_line,
            "source_line_sha256":source_digest,
            "top_level_type":top_type,
            "event_type":if event_type.is_empty() {Value::Null} else {json!(event_type)},
            "item_type":if item_type.is_empty() {Value::Null} else {json!(item_type)},
            "classification":if known {"known"} else {"unknown"},
            "projection":"raw",
            "unmapped_tool":unmapped_tool,
            "runtime_call_correlation":runtime_correlation.map(RuntimeCallCorrelation::label),
            "tool_registry_sha256":registry.map(|registry| registry.sha256.clone()),
            "parent_agent_thread_id":context.parent_agent_thread_id,
            "agent_path":context.agent_path,
            "thread_source":context.thread_source,
        }
    });
    let mut kind = ProjectionKind::Raw;
    let mut clear_active_turn = false;
    if top_type == "event_msg" {
        match event_type {
            "task_started" => {
                set_lifecycle(
                    &mut capture,
                    "turn_start",
                    "started",
                    payload,
                    &timestamp,
                    ordinal,
                );
                kind = ProjectionKind::Lifecycle;
            }
            "task_complete" => {
                set_lifecycle(
                    &mut capture,
                    "turn_end",
                    "completed",
                    payload,
                    &timestamp,
                    ordinal,
                );
                kind = ProjectionKind::Lifecycle;
                clear_active_turn = true;
            }
            "turn_aborted" => {
                set_lifecycle(
                    &mut capture,
                    "turn_aborted",
                    "cancelled",
                    payload,
                    &timestamp,
                    ordinal,
                );
                kind = ProjectionKind::Lifecycle;
                clear_active_turn = true;
            }
            "context_compacted" => {
                set_lifecycle(
                    &mut capture,
                    "compaction",
                    "completed",
                    payload,
                    &timestamp,
                    ordinal,
                );
                kind = ProjectionKind::Lifecycle;
            }
            "token_count" => {
                capture["rolloutUsage"] = payload.get("info").cloned().unwrap_or(Value::Null);
                capture["rolloutEvent"]["projection"] = json!("token_usage");
                kind = ProjectionKind::Token;
            }
            "item_completed" => {
                kind = project_completed_item(
                    &mut capture,
                    payload,
                    item_type,
                    registry_match,
                    runtime_correlation,
                    &timestamp,
                    ordinal,
                )?;
            }
            "web_search_begin" | "web_search_end" => {
                capture["runtimeToolObservation"] = payload.clone();
                capture["rolloutEvent"]["projection"] = json!("legacy_web_search_observation");
            }
            _ => {}
        }
    } else if top_type == "response_item" {
        match event_type {
            "message" => {
                if let Some(message) = canonical_response_message(payload) {
                    capture["rolloutMessages"] = json!([message]);
                    capture["rolloutEvent"]["projection"] = json!("message");
                    kind = ProjectionKind::Message;
                }
            }
            "custom_tool_call" | "function_call" => {
                if let Some(message) = canonical_tool_call_message(payload) {
                    capture["rolloutMessages"] = json!([message]);
                    capture["rolloutEvent"]["projection"] = json!("assistant_tool_call");
                    kind = ProjectionKind::Message;
                }
            }
            "web_search_call" => {
                if let Some(message) = canonical_web_search_call_message(payload) {
                    capture["rolloutMessages"] = json!([message]);
                    capture["rolloutEvent"]["projection"] = json!("assistant_tool_call");
                    kind = ProjectionKind::Message;
                }
            }
            "custom_tool_call_output" | "function_call_output" => {
                if let Some(message) = canonical_tool_result_message(payload) {
                    capture["rolloutMessages"] = json!([message]);
                    capture["rolloutEvent"]["projection"] = json!("tool_result_unknown_status");
                    kind = ProjectionKind::Message;
                }
            }
            _ => {}
        }
    } else if top_type == "compacted" {
        set_lifecycle(
            &mut capture,
            "compaction",
            "completed",
            payload,
            &timestamp,
            ordinal,
        );
        kind = ProjectionKind::Lifecycle;
    }
    Ok(ProjectedLine {
        capture: Some(capture),
        kind,
        unknown: !known,
        unmapped_tool,
        clear_active_turn,
    })
}

fn metadata_projection() -> ProjectedLine {
    ProjectedLine {
        capture: None,
        kind: ProjectionKind::Metadata,
        unknown: false,
        unmapped_tool: false,
        clear_active_turn: false,
    }
}

fn trace_context(session_id: &str, turn_id: Option<&str>, config: &ExportConfig) -> Value {
    json!({
        "task_session_id":config.task_session_id,
        "session_id":session_id,
        "thread_id":session_id,
        "root_session_id":config.root_session_id,
        "parent_session_id":config.parent_session_id,
        "goal_id":config.goal_id,
        "root_turn_id":Value::Null,
        "turn_id":turn_id,
        "agent_id":Value::Null,
        "branch_id":Value::Null,
    })
}

fn set_lifecycle(
    capture: &mut Value,
    event_type: &str,
    status: &str,
    source: &Value,
    timestamp: &str,
    ordinal: u64,
) {
    capture["lifecycleEvent"] = json!({
        "event_id":format!("codex-rollout-{ordinal}"),
        "type":event_type,
        "status":status,
        "reason":source.get("reason").and_then(Value::as_str),
        "occurred_at":timestamp,
        "source_event":source,
    });
    capture["rolloutEvent"]["projection"] = json!("lifecycle");
}

fn project_completed_item(
    capture: &mut Value,
    payload: &Value,
    item_type: &str,
    registry_entry: Option<(&LoadedRegistry, &ToolRegistryEntry)>,
    runtime_correlation: Option<RuntimeCallCorrelation>,
    timestamp: &str,
    ordinal: u64,
) -> Result<ProjectionKind> {
    let item = payload.get("item").unwrap_or(&Value::Null);
    match item_type {
        "UserMessage" | "AgentMessage" => {
            let role = if item_type == "UserMessage" {
                "user"
            } else {
                "assistant"
            };
            capture["rolloutMessages"] = json!([{
                "role":role,
                "content":item.get("content").cloned().unwrap_or(Value::Null),
                "message_id":string(item, "id"),
                "source":"codex_rollout.item_completed"
            }]);
            capture["rolloutEvent"]["projection"] = json!("message");
            Ok(ProjectionKind::Message)
        }
        "ContextCompaction" => {
            set_lifecycle(capture, "compaction", "completed", item, timestamp, ordinal);
            Ok(ProjectionKind::Lifecycle)
        }
        "SubAgentActivity" => {
            let kind = string(item, "kind").unwrap_or("unknown");
            let (event_type, status) = match kind {
                "started" => ("subagent_spawn", "started"),
                "completed" => ("subagent_join", "completed"),
                "interacted" => ("subagent_interaction", "completed"),
                _ => ("subagent_activity", "unknown"),
            };
            set_lifecycle(capture, event_type, status, item, timestamp, ordinal);
            Ok(ProjectionKind::Lifecycle)
        }
        "CommandExecution" | "FileChange" | "ImageView" | "CollabAgentToolCall" | "WebSearch" => {
            capture["runtimeToolObservation"] = item.clone();
            let Some((registry, entry)) = registry_entry else {
                capture["rolloutEvent"]["projection"] = json!("runtime_tool_unmapped");
                return Ok(ProjectionKind::Raw);
            };
            if capture
                .pointer("/traceContext/task_session_id")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
            {
                capture["recordType"] = json!("tool_execution");
            }
            capture["toolExecution"] = tool_execution(
                payload,
                item_type,
                registry,
                entry,
                runtime_correlation.is_some_and(RuntimeCallCorrelation::is_matched),
            )?;
            capture["rolloutEvent"]["projection"] = json!("tool_execution");
            Ok(ProjectionKind::Tool)
        }
        _ => Ok(ProjectionKind::Raw),
    }
}

fn matching_registry_entry<'a>(
    payload: &Value,
    context: &RolloutContext,
    registry: Option<&'a LoadedRegistry>,
) -> Option<(&'a LoadedRegistry, &'a ToolRegistryEntry)> {
    let registry = registry?;
    if context.source_cli_version.as_deref() != Some(&registry.registry.producer_version) {
        return None;
    }
    let item = payload.get("item")?;
    let item_type = string(item, "type")?;
    let observed_name = string(item, "tool")
        .map(|name| canonical_runtime_tool_name(string(item, "namespace"), name))
        .or_else(|| {
            item.get("id")
                .and_then(Value::as_str)
                .and_then(|id| context.model_tool_calls.get(id))
                .map(|call| call.name.clone())
        });
    let candidates: Vec<&ToolRegistryEntry> = registry
        .registry
        .tools
        .iter()
        .filter(|entry| entry.runtime_item_type == item_type)
        .filter(|entry| {
            observed_name.as_deref().is_none_or(|observed| {
                registry_entry_identity(entry)
                    .ok()
                    .is_some_and(|identity| identity == observed)
            })
        })
        .collect();
    if candidates.len() == 1 {
        candidates.into_iter().next().map(|entry| (registry, entry))
    } else {
        None
    }
}

fn remember_model_tool_call(
    context: &mut RolloutContext,
    payload: &Value,
    event_type: &str,
    ordinal: u64,
    turn_id: Option<&str>,
) {
    let observed = match event_type {
        "custom_tool_call" | "function_call" => {
            let (Some(call_id), Some(name)) = (string(payload, "call_id"), string(payload, "name"))
            else {
                return;
            };
            (
                call_id,
                canonical_runtime_tool_name(string(payload, "namespace"), name),
            )
        }
        "web_search_call" => {
            let Some(call_id) = string(payload, "id") else {
                return;
            };
            (call_id, "web_search".to_owned())
        }
        _ => return,
    };
    context
        .model_tool_calls
        .entry(observed.0.to_owned())
        .or_insert_with(|| ObservedModelToolCall {
            name: observed.1,
            event_type: event_type.to_owned(),
            source_ordinal: ordinal,
            turn_id: turn_id.map(str::to_owned),
        });
    while context.model_tool_calls.len() > MAX_TRACKED_MODEL_TOOL_CALLS {
        let oldest = context
            .model_tool_calls
            .iter()
            .min_by_key(|(_, call)| call.source_ordinal)
            .map(|(call_id, _)| call_id.clone());
        let Some(oldest) = oldest else {
            break;
        };
        context.model_tool_calls.remove(&oldest);
    }
}

fn runtime_call_correlation(
    payload: &Value,
    context: &RolloutContext,
    registry_entry: Option<(&LoadedRegistry, &ToolRegistryEntry)>,
) -> RuntimeCallCorrelation {
    let Some((_, registry_entry)) = registry_entry else {
        return RuntimeCallCorrelation::MissingRegistry;
    };
    let Some(call_id) = payload.pointer("/item/id").and_then(Value::as_str) else {
        return RuntimeCallCorrelation::MissingModelCall;
    };
    let Some(model_call) = context.model_tool_calls.get(call_id) else {
        return RuntimeCallCorrelation::MissingModelCall;
    };
    let registry_name = registry_entry_identity(registry_entry).unwrap_or_default();
    if model_call.name == registry_name {
        RuntimeCallCorrelation::Matched
    } else {
        RuntimeCallCorrelation::ToolNameMismatch
    }
}

fn tool_execution(
    payload: &Value,
    item_type: &str,
    registry: &LoadedRegistry,
    entry: &ToolRegistryEntry,
    model_call_matched: bool,
) -> Result<Value> {
    let item = payload
        .get("item")
        .ok_or_else(|| anyhow::anyhow!("item_completed is missing item"))?;
    let mut schema = entry.tool.clone();
    let runtime_tool = entry
        .runtime_tool
        .as_deref()
        .or_else(|| string(&schema, "name"))
        .unwrap_or("")
        .to_owned();
    let runtime_namespace = entry.runtime_namespace.as_deref();
    let name = registry_entry_identity(entry)
        .unwrap_or_else(|_| canonical_runtime_tool_name(runtime_namespace, &runtime_tool));
    schema["name"] = json!(name);
    schema["runtime_tool"] = json!(runtime_tool);
    if let Some(namespace) = runtime_namespace {
        schema["runtime_namespace"] = json!(namespace);
    }
    let schema_hash = sha256(&serde_json::to_vec(&schema)?);
    schema["schema_hash"] = json!(schema_hash);
    schema["schema_version"] = json!(format!("sha256:{schema_hash}"));
    schema["schema_provenance"] = json!({
        "source":"captured_runtime_registry",
        "registry_sha256":registry.sha256,
        "producer":registry.registry.producer,
        "producer_version":registry.registry.producer_version,
        "generated_adapter":false,
    });
    let status = normalize_runtime_status(string(item, "status"));
    let arguments = match item_type {
        "CommandExecution" => json!({
            "command":item.get("command"),
            "cwd":item.get("cwd"),
            "parsed_cmd":item.get("parsed_cmd"),
            "source":item.get("source"),
        }),
        "FileChange" => json!({"changes":item.get("changes")}),
        "ImageView" => json!({"path":item.get("path")}),
        "CollabAgentToolCall" => json!({
            "tool":item.get("tool"),
            "sender_thread_id":item.get("sender_thread_id"),
            "receiver_thread_ids":item.get("receiver_thread_ids"),
            "receiver_agents":item.get("receiver_agents"),
        }),
        "WebSearch" => json!({
            "query":item.get("query"),
            "action":item.get("action"),
        }),
        _ => Value::Null,
    };
    let result = match item_type {
        "CommandExecution" => json!({
            "stdout":item.get("stdout"),
            "stderr":item.get("stderr"),
            "aggregated_output":item.get("aggregated_output"),
            "formatted_output":item.get("formatted_output"),
            "exit_code":item.get("exit_code"),
            "process_id":item.get("process_id"),
            "duration":item.get("duration"),
        }),
        "FileChange" => json!({"stdout":item.get("stdout"),"stderr":item.get("stderr")}),
        "ImageView" => json!({"path":item.get("path")}),
        "CollabAgentToolCall" => json!({"agents_states":item.get("agents_states")}),
        // Codex records the hosted search action and completion, but not the
        // provider's search result body. Preserve that absence explicitly.
        "WebSearch" => Value::Null,
        _ => Value::Null,
    };
    let started_at = milliseconds_timestamp(payload.get("started_at_ms")).or_else(|| {
        payload
            .get("started_at")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let finished_at = milliseconds_timestamp(payload.get("completed_at_ms")).or_else(|| {
        payload
            .get("completed_at")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let mut execution = json!({
        "call_id":string(item, "id").unwrap_or(""),
        "name":name,
        "status":status,
        "initiator":if model_call_matched {"assistant"} else {"runtime"},
        "arguments":arguments,
        "schema":schema,
        "started_at":started_at,
        "finished_at":finished_at,
        "runtime_item_type":item_type,
        "runtime_tool":runtime_tool,
        "runtime_namespace":runtime_namespace,
        "runtime_status":item.get("status"),
        "model_call_matched":model_call_matched,
        "result_content_captured":item_type != "WebSearch",
        "result":result,
    });
    if matches!(status, "error" | "cancelled" | "timeout") {
        execution["error"] = json!({
            "stderr":item.get("stderr"),
            "exit_code":item.get("exit_code"),
            "runtime_status":item.get("status"),
        });
    }
    Ok(execution)
}

fn normalize_runtime_status(status: Option<&str>) -> &'static str {
    match status.map(|value| value.to_ascii_lowercase()) {
        Some(value) if matches!(value.as_str(), "completed" | "success" | "succeeded") => "success",
        Some(value) if matches!(value.as_str(), "failed" | "error") => "error",
        Some(value) if matches!(value.as_str(), "cancelled" | "canceled" | "aborted") => {
            "cancelled"
        }
        Some(value) if matches!(value.as_str(), "timeout" | "timed_out") => "timeout",
        Some(value) if value == "started" => "started",
        _ => "unknown",
    }
}

fn canonical_response_message(payload: &Value) -> Option<Value> {
    let role = string(payload, "role")?;
    if !matches!(role, "system" | "user" | "assistant" | "tool") {
        return None;
    }
    Some(json!({
        "role":role,
        "content":payload.get("content").cloned().unwrap_or(Value::Null),
        "message_id":string(payload, "id"),
        "source":"codex_rollout.response_item",
    }))
}

fn canonical_tool_call_message(payload: &Value) -> Option<Value> {
    let call_id = string(payload, "call_id")?;
    let raw_name = string(payload, "name")?;
    let name = canonical_runtime_tool_name(string(payload, "namespace"), raw_name);
    let arguments = payload
        .get("arguments")
        .or_else(|| payload.get("input"))
        .cloned()
        .unwrap_or(Value::Null);
    Some(json!({
        "role":"assistant",
        "content":"",
        "tool_calls":[{
            "id":call_id,
            "type":"function",
            "function":{
                "name":name,
                "arguments":arguments.as_str().map(str::to_owned)
                    .unwrap_or_else(|| serde_json::to_string(&arguments).unwrap_or_default()),
            },
            "source":"codex_rollout.response_item",
            "provider_item_status":payload.get("status"),
        }],
    }))
}

fn canonical_web_search_call_message(payload: &Value) -> Option<Value> {
    let call_id = string(payload, "id")?;
    let action = payload.get("action").cloned().unwrap_or(Value::Null);
    Some(json!({
        "role":"assistant",
        "content":"",
        "tool_calls":[{
            "id":call_id,
            "type":"function",
            "function":{
                "name":"web_search",
                "arguments":serde_json::to_string(&action).unwrap_or_default(),
            },
            "source":"codex_rollout.response_item",
            "provider_item_status":payload.get("status"),
        }],
    }))
}

fn canonical_tool_result_message(payload: &Value) -> Option<Value> {
    let call_id = string(payload, "call_id")?;
    Some(json!({
        "role":"tool",
        "tool_call_id":call_id,
        "content":payload.get("output").cloned().unwrap_or(Value::Null),
        "source":"codex_rollout.response_item",
        "status":"unknown",
        "status_provenance":"not_reported_by_codex_rollout_response_item",
    }))
}

fn known_event(top: &str, event: &str, item: &str) -> bool {
    match top {
        "session_meta"
        | "turn_context"
        | "world_state"
        | "compacted"
        | "inter_agent_communication_metadata" => true,
        "response_item" => matches!(
            event,
            "reasoning"
                | "custom_tool_call"
                | "custom_tool_call_output"
                | "function_call"
                | "function_call_output"
                | "web_search_call"
                | "message"
                | "agent_message"
        ),
        "event_msg" => {
            if event == "item_completed" {
                matches!(
                    item,
                    "CommandExecution"
                        | "FileChange"
                        | "ImageView"
                        | "CollabAgentToolCall"
                        | "WebSearch"
                        | "SubAgentActivity"
                        | "ContextCompaction"
                        | "UserMessage"
                        | "AgentMessage"
                        | "Reasoning"
                        | "EnteredReviewMode"
                        | "ExitedReviewMode"
                )
            } else {
                matches!(
                    event,
                    "token_count"
                        | "task_started"
                        | "task_complete"
                        | "thread_settings_applied"
                        | "agent_message"
                        | "patch_apply_end"
                        | "user_message"
                        | "context_compacted"
                        | "sub_agent_activity"
                        | "agent_reasoning"
                        | "turn_aborted"
                        | "thread_goal_updated"
                        | "web_search_begin"
                        | "web_search_end"
                )
            }
        }
        _ => false,
    }
}

fn milliseconds_timestamp(value: Option<&Value>) -> Option<String> {
    let milliseconds = value.and_then(Value::as_i64)?;
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(milliseconds) * 1_000_000)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn deterministic_capture_id(session_id: &str, ordinal: u64) -> String {
    let digest = hex::encode(Sha256::digest(session_id.as_bytes()));
    format!("cap-rollout-{}-{ordinal:020}", &digest[..24])
}

fn string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

fn update_summary(summary: &mut ExportSummary, projected: &ProjectedLine) {
    match projected.kind {
        ProjectionKind::Metadata => {
            summary.metadata_lines = summary.metadata_lines.saturating_add(1)
        }
        ProjectionKind::Lifecycle => {
            summary.lifecycle_events = summary.lifecycle_events.saturating_add(1)
        }
        ProjectionKind::Message => {
            summary.message_events = summary.message_events.saturating_add(1)
        }
        ProjectionKind::Token => summary.token_events = summary.token_events.saturating_add(1),
        ProjectionKind::Tool => summary.tool_executions = summary.tool_executions.saturating_add(1),
        ProjectionKind::Raw => {}
    }
    summary.unknown_events = summary
        .unknown_events
        .saturating_add(u64::from(projected.unknown));
    summary.unmapped_tool_events = summary
        .unmapped_tool_events
        .saturating_add(u64::from(projected.unmapped_tool));
}

async fn deliver_rollout_batch(config: &ExportConfig, records: &[Vec<u8>]) -> Result<u64> {
    Ok(deliver_batch(
        &DeliveryConfig {
            target: config.target.clone(),
            request_timeout: config.request_timeout,
            retry_max_times: config.retry_max_times,
        },
        records,
    )
    .await?
    .duplicates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path, output: &Path) -> ExportConfig {
        ExportConfig {
            input: root.join("rollout.jsonl"),
            state_root: root.join("state"),
            target: ExportTarget::Jsonl(output.to_owned()),
            source_namespace: "relay-18084".to_owned(),
            tool_registry: None,
            batch_records: 2,
            max_envelope_bytes: 4 * 1024 * 1024,
            request_timeout: Duration::from_secs(1),
            retry_max_times: 20,
            task_session_id: None,
            root_session_id: None,
            parent_session_id: None,
            goal_id: None,
        }
    }

    fn line(ordinal: u64, event: Value) -> String {
        serde_json::to_string(&json!({
            "ordinal":ordinal,
            "timestamp":format!("2026-08-29T00:00:{ordinal:02}Z"),
            "type":event["type"],
            "payload":event["payload"],
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn turn_lifecycle_does_not_fabricate_task_boundary_and_resume_is_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("captures.jsonl");
        let lines = [
            line(
                0,
                json!({"type":"session_meta","payload":{
                    "session_id":"thread-1","cli_version":"0.150.0-alpha.9",
                    "model_provider":"OpenAI","base_instructions":"system"
                }}),
            ),
            line(
                1,
                json!({"type":"event_msg","payload":{
                    "type":"task_started","turn_id":"turn-1","started_at":"2026-08-29T00:00:01Z"
                }}),
            ),
            line(
                2,
                json!({"type":"event_msg","payload":{
                    "type":"item_completed","thread_id":"thread-1","turn_id":"turn-1",
                    "item":{"type":"UserMessage","id":"user-1","content":"hello"}
                }}),
            ),
            line(
                3,
                json!({"type":"event_msg","payload":{
                    "type":"task_complete","turn_id":"turn-1","completed_at":"2026-08-29T00:00:03Z"
                }}),
            ),
        ]
        .join("\n")
            + "\n";
        fs::write(temporary.path().join("rollout.jsonl"), lines).unwrap();
        let first = export_codex_rollout(config(temporary.path(), &output))
            .await
            .unwrap();
        assert_eq!(first.captures_emitted, 3);
        assert_eq!(first.lifecycle_events, 2);
        assert_eq!(first.message_events, 1);
        let bytes = fs::read(&output).unwrap();
        let records: Vec<Value> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert!(records.iter().all(|record| {
            record
                .pointer("/traceContext/task_session_id")
                .is_some_and(Value::is_null)
        }));
        assert!(records.iter().all(|record| {
            record
                .pointer("/traceContext/turn_id")
                .and_then(Value::as_str)
                == Some("turn-1")
        }));
        assert_eq!(
            records.last().unwrap()["lifecycleEvent"]["type"],
            "turn_end"
        );
        let second = export_codex_rollout(config(temporary.path(), &output))
            .await
            .unwrap();
        assert_eq!(second.captures_emitted, 0);
        assert_eq!(fs::read(&output).unwrap(), bytes);
    }

    #[tokio::test]
    async fn sidecar_incrementally_exports_and_idle_exit_is_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("captures.jsonl");
        let lines = [
            line(
                0,
                json!({"type":"session_meta","payload":{
                    "session_id":"thread-sidecar","cli_version":"0.150.0-alpha.9"
                }}),
            ),
            line(
                1,
                json!({"type":"event_msg","payload":{
                    "type":"task_started","turn_id":"turn-sidecar"
                }}),
            ),
        ]
        .join("\n")
            + "\n";
        fs::write(temporary.path().join("rollout.jsonl"), lines).unwrap();
        let summary = watch_codex_rollout(
            config(temporary.path(), &output),
            Duration::from_millis(10),
            Some(Duration::from_millis(30)),
            std::future::pending(),
        )
        .await
        .unwrap();
        assert_eq!(summary.stop_reason, "idle_exit");
        assert!(summary.cycles >= 2);
        assert_eq!(summary.export.lines_read, 2);
        assert_eq!(summary.export.captures_emitted, 1);
        assert_eq!(fs::read_to_string(output).unwrap().lines().count(), 1);
    }

    #[tokio::test]
    async fn tool_event_without_real_registry_is_preserved_but_not_promoted() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("captures.jsonl");
        let lines = [
            line(
                0,
                json!({"type":"session_meta","payload":{
                    "session_id":"thread-1","cli_version":"0.150.0-alpha.9"
                }}),
            ),
            line(
                1,
                json!({"type":"event_msg","payload":{
                    "type":"task_started","turn_id":"turn-1"
                }}),
            ),
            line(
                2,
                json!({"type":"event_msg","payload":{
                    "type":"item_completed","thread_id":"thread-1","turn_id":"turn-1",
                    "started_at_ms":1787961602000_i64,"completed_at_ms":1787961602001_i64,
                    "item":{"type":"CommandExecution","id":"call-1","status":"failed",
                        "command":["false"],"cwd":"/workspace","parsed_cmd":[],"source":"runtime",
                        "exit_code":1,"stdout":"","stderr":"failed"}
                }}),
            ),
        ]
        .join("\n")
            + "\n";
        fs::write(temporary.path().join("rollout.jsonl"), lines).unwrap();
        let summary = export_codex_rollout(config(temporary.path(), &output))
            .await
            .unwrap();
        assert_eq!(summary.unmapped_tool_events, 1);
        assert_eq!(summary.tool_executions, 0);
        let last = fs::read_to_string(output)
            .unwrap()
            .lines()
            .last()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .unwrap();
        assert_eq!(last["recordType"], "rollout_event");
        assert_eq!(last["rolloutEvent"]["unmapped_tool"], true);
        assert!(last.get("toolExecution").is_none());
    }

    #[tokio::test]
    async fn registry_without_model_call_keeps_runtime_execution_unmapped() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("captures.jsonl");
        let registry = temporary.path().join("registry.json");
        fs::write(
            &registry,
            serde_json::to_vec(&json!({
                "schema_version":TOOL_REGISTRY_SCHEMA_VERSION,
                "producer":"codex-cli",
                "producer_version":"0.150.0-alpha.9",
                "tools":[{
                    "runtime_item_type":"CommandExecution",
                    "tool":{
                        "name":"exec_command",
                        "description":"Execute a command through the Codex runtime.",
                        "parameters":{"type":"object","properties":{
                            "command":{"type":"array","description":"Executed argv."},
                            "cwd":{"type":["string","null"],"description":"Runtime working directory."}
                        }}
                    }
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let lines = [
            line(
                0,
                json!({"type":"session_meta","payload":{
                    "session_id":"thread-1","cli_version":"0.150.0-alpha.9"
                }}),
            ),
            line(
                1,
                json!({"type":"event_msg","payload":{
                    "type":"task_started","turn_id":"turn-1"
                }}),
            ),
            line(
                2,
                json!({"type":"event_msg","payload":{
                    "type":"item_completed","thread_id":"thread-1","turn_id":"turn-1",
                    "started_at_ms":1787961602000_i64,"completed_at_ms":1787961602001_i64,
                    "item":{"type":"CommandExecution","id":"call-1","status":"failed",
                        "command":["false"],"cwd":"/workspace","parsed_cmd":[],"source":"runtime",
                        "exit_code":1,"stdout":"","stderr":"failed"}
                }}),
            ),
        ]
        .join("\n")
            + "\n";
        fs::write(temporary.path().join("rollout.jsonl"), lines).unwrap();
        let mut export_config = config(temporary.path(), &output);
        export_config.tool_registry = Some(registry);
        export_config.task_session_id = Some("task-from-harness".to_owned());
        let summary = export_codex_rollout(export_config).await.unwrap();
        assert_eq!(summary.tool_executions, 1);
        assert_eq!(summary.unmapped_tool_events, 1);
        let last = fs::read_to_string(output)
            .unwrap()
            .lines()
            .last()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .unwrap();
        assert_eq!(last["recordType"], "tool_execution");
        assert_eq!(last["traceContext"]["task_session_id"], "task-from-harness");
        assert_eq!(last["toolExecution"]["status"], "error");
        assert_eq!(last["toolExecution"]["initiator"], "runtime");
        assert_eq!(last["toolExecution"]["model_call_matched"], false);
        assert_eq!(last["rolloutEvent"]["unmapped_tool"], true);
        assert_eq!(
            last["rolloutEvent"]["runtime_call_correlation"],
            "missing_model_call"
        );
        assert_eq!(
            last["toolExecution"]["schema"]["schema_provenance"]["generated_adapter"],
            false
        );
    }

    #[tokio::test]
    async fn exact_model_call_and_runtime_id_promote_real_status() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("captures.jsonl");
        let registry = temporary.path().join("registry.json");
        fs::write(
            &registry,
            serde_json::to_vec(&json!({
                "schema_version":TOOL_REGISTRY_SCHEMA_VERSION,
                "producer":"codex-cli",
                "producer_version":"0.150.0-alpha.9",
                "tools":[{
                    "runtime_item_type":"CommandExecution",
                    "tool":{
                        "name":"exec_command",
                        "description":"Execute a command through the Codex runtime.",
                        "parameters":{"type":"object","properties":{
                            "cmd":{"type":"string","description":"Shell command."},
                            "cwd":{"type":["string","null"],"description":"Working directory."}
                        },"required":["cmd"]}
                    }
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let lines = [
            line(
                0,
                json!({"type":"session_meta","payload":{
                    "session_id":"thread-1","cli_version":"0.150.0-alpha.9"
                }}),
            ),
            line(
                1,
                json!({"type":"event_msg","payload":{
                    "type":"task_started","turn_id":"turn-1"
                }}),
            ),
            line(
                2,
                json!({"type":"response_item","payload":{
                    "type":"function_call","call_id":"call-1","name":"exec_command",
                    "arguments":"{\"cmd\":\"false\",\"cwd\":\"/workspace\"}"
                }}),
            ),
            line(
                3,
                json!({"type":"event_msg","payload":{
                    "type":"item_completed","turn_id":"turn-1",
                    "started_at_ms":1787961602000_i64,"completed_at_ms":1787961602001_i64,
                    "item":{"type":"CommandExecution","id":"call-1","status":"failed",
                        "command":["false"],"cwd":"/workspace","exit_code":1,
                        "aggregated_output":"permission denied"}
                }}),
            ),
        ]
        .join("\n")
            + "\n";
        fs::write(temporary.path().join("rollout.jsonl"), lines).unwrap();
        let mut export_config = config(temporary.path(), &output);
        export_config.tool_registry = Some(registry);
        export_config.task_session_id = Some("task-from-harness".to_owned());
        let summary = export_codex_rollout(export_config).await.unwrap();
        assert_eq!(summary.tool_executions, 1);
        assert_eq!(summary.unmapped_tool_events, 0);
        let execution = fs::read_to_string(output)
            .unwrap()
            .lines()
            .last()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .unwrap();
        assert_eq!(execution["toolExecution"]["initiator"], "assistant");
        assert_eq!(execution["toolExecution"]["status"], "error");
        assert_eq!(execution["toolExecution"]["model_call_matched"], true);
        assert_eq!(
            execution["rolloutEvent"]["runtime_call_correlation"],
            "matched_model_call"
        );
    }

    #[tokio::test]
    async fn web_search_is_known_but_missing_result_is_not_fabricated() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("captures.jsonl");
        let lines = [
            line(
                0,
                json!({"type":"session_meta","payload":{
                    "session_id":"thread-1","cli_version":"0.150.0-alpha.9"
                }}),
            ),
            line(
                1,
                json!({"type":"event_msg","payload":{
                    "type":"task_started","turn_id":"turn-1"
                }}),
            ),
            line(
                2,
                json!({"type":"event_msg","payload":{
                    "type":"item_completed","turn_id":"turn-1",
                    "item":{"type":"WebSearch","id":"ws-1","query":"ChipTrace",
                        "action":{"type":"search","query":"ChipTrace"}}
                }}),
            ),
            line(
                3,
                json!({"type":"response_item","payload":{
                    "type":"web_search_call","id":"ws-1","status":"completed",
                    "action":{"type":"search","query":"ChipTrace"}
                }}),
            ),
        ]
        .join("\n")
            + "\n";
        fs::write(temporary.path().join("rollout.jsonl"), lines).unwrap();
        let summary = export_codex_rollout(config(temporary.path(), &output))
            .await
            .unwrap();
        assert_eq!(summary.unknown_events, 0);
        assert_eq!(summary.unmapped_tool_events, 1);
        assert_eq!(summary.message_events, 1);
        let records: Vec<Value> = fs::read_to_string(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let search_call = records
            .iter()
            .find(|record| record["rolloutEvent"]["event_type"] == "web_search_call")
            .unwrap();
        assert_eq!(
            search_call["rolloutMessages"][0]["tool_calls"][0]["function"]["name"],
            "web_search"
        );
        assert!(records.iter().all(|record| {
            record
                .get("rolloutMessages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .all(|message| message["role"] != "tool")
        }));
    }

    #[test]
    fn unknown_item_is_not_silently_accepted() {
        let event = json!({
            "ordinal":2,
            "timestamp":"2026-08-29T00:00:02Z",
            "type":"event_msg",
            "payload":{"type":"item_completed","turn_id":"turn-1","item":{"type":"FutureItem"}}
        });
        let mut context = RolloutContext {
            source_session_id: Some("thread-1".to_owned()),
            active_turn_id: Some("turn-1".to_owned()),
            ..RolloutContext::default()
        };
        let temporary = tempfile::tempdir().unwrap();
        let projected = project_event(
            &event,
            &serde_json::to_string(&event).unwrap(),
            2,
            &mut context,
            None,
            &config(temporary.path(), &temporary.path().join("out.jsonl")),
        )
        .unwrap();
        assert!(projected.unknown);
        let capture = projected.capture.unwrap();
        assert_eq!(capture["rolloutEvent"]["classification"], "unknown");
        assert_eq!(capture["fieldEvidence"][0]["field"], "traceContext.turn_id");
        assert!(
            capture["fieldEvidence"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| { item["field"] != "traceContext.task_session_id" })
        );
    }

    #[tokio::test]
    async fn unknown_event_without_turn_is_preserved_and_counted() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("captures.jsonl");
        let unknown = line(
            1,
            json!({"type":"future_envelope","payload":{"type":"future_event"}}),
        );
        let lines = [
            line(
                0,
                json!({"type":"session_meta","payload":{
                    "session_id":"thread-1","cli_version":"0.150.0-alpha.9"
                }}),
            ),
            unknown.clone(),
        ]
        .join("\n")
            + "\n";
        fs::write(temporary.path().join("rollout.jsonl"), lines).unwrap();

        let summary = export_codex_rollout(config(temporary.path(), &output))
            .await
            .unwrap();
        assert_eq!(summary.lines_read, 2);
        assert_eq!(summary.metadata_lines, 1);
        assert_eq!(summary.captures_emitted, 1);
        assert_eq!(summary.unknown_events, 1);

        let capture: Value =
            serde_json::from_str(fs::read_to_string(output).unwrap().trim_end()).unwrap();
        assert_eq!(capture["rolloutEvent"]["classification"], "unknown");
        assert_eq!(capture["rolloutEvent"]["source_line"], unknown);
        assert_eq!(capture["rolloutEvent"]["source_session_id"], "thread-1");
        assert!(capture["traceContext"]["turn_id"].is_null());
        assert!(capture["traceContext"]["root_turn_id"].is_null());
        assert!(capture["traceContext"]["branch_id"].is_null());
        assert!(capture["traceContext"]["task_session_id"].is_null());
        assert!(
            capture["fieldEvidence"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| {
                    item["field"] != "traceContext.turn_id"
                        && item["field"] != "traceContext.task_session_id"
                })
        );
    }

    #[test]
    fn native_response_tool_call_is_structured_but_result_status_is_not_invented() {
        let temporary = tempfile::tempdir().unwrap();
        let mut context = RolloutContext {
            source_session_id: Some("thread-1".to_owned()),
            active_turn_id: Some("turn-1".to_owned()),
            ..RolloutContext::default()
        };
        let call = json!({
            "ordinal":2,"timestamp":"2026-08-29T00:00:02Z","type":"response_item",
            "payload":{"type":"custom_tool_call","call_id":"call-1","name":"exec",
                "input":"await tools.read({path:\"a\"})","status":"completed"}
        });
        let result = json!({
            "ordinal":3,"timestamp":"2026-08-29T00:00:03Z","type":"response_item",
            "payload":{"type":"custom_tool_call_output","call_id":"call-1",
                "output":[{"type":"input_text","text":"observed output"}]}
        });
        let export_config = config(temporary.path(), &temporary.path().join("out.jsonl"));
        let projected_call = project_event(
            &call,
            &serde_json::to_string(&call).unwrap(),
            2,
            &mut context,
            None,
            &export_config,
        )
        .unwrap()
        .capture
        .unwrap();
        let projected_result = project_event(
            &result,
            &serde_json::to_string(&result).unwrap(),
            3,
            &mut context,
            None,
            &export_config,
        )
        .unwrap()
        .capture
        .unwrap();
        assert_eq!(
            projected_call["rolloutMessages"][0]["tool_calls"][0]["function"]["name"],
            "exec"
        );
        assert_eq!(projected_result["rolloutMessages"][0]["role"], "tool");
        assert_eq!(projected_result["rolloutMessages"][0]["status"], "unknown");
        assert!(
            projected_result["rolloutMessages"][0]
                .get("is_error")
                .is_none()
        );
    }

    #[test]
    fn hook_resolution_is_confined_and_session_verified() {
        let temporary = tempfile::tempdir().unwrap();
        let sessions = temporary.path().join("sessions/2026/08/29");
        fs::create_dir_all(&sessions).unwrap();
        let rollout = sessions.join("rollout-thread-1.jsonl");
        fs::write(
            &rollout,
            format!(
                "{}\n",
                line(
                    0,
                    json!({"type":"session_meta","payload":{"session_id":"thread-1"}})
                )
            ),
        )
        .unwrap();
        let hook = serde_json::to_vec(&json!({
            "hook_event_name":"Stop",
            "session_id":"thread-1",
            "transcript_path":rollout
        }))
        .unwrap();
        assert_eq!(
            resolve_hook_rollout(&hook, &temporary.path().join("sessions")).unwrap(),
            rollout.canonicalize().unwrap()
        );
        let wrong = serde_json::to_vec(&json!({
            "hook_event_name":"Stop",
            "session_id":"different",
            "transcript_path":rollout
        }))
        .unwrap();
        assert!(resolve_hook_rollout(&wrong, &temporary.path().join("sessions")).is_err());
    }
}
