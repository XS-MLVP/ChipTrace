//! Importer for the native Codex `codex-rollout-trace` bundle.
//!
//! A native bundle is the authoritative producer-side record for a Codex
//! rollout.  It contains `manifest.json`, an append-only `trace.jsonl`, and
//! JSON payload files below `payloads/`.  This module deliberately validates
//! the bundle before projecting it to Capture v2: a missing payload, sequence
//! gap, changed prefix, or path escape is a producer error, not an invitation
//! to reconstruct a plausible event.

use crate::capture::normalize_capture;
use crate::delivery::{DeliveryConfig, DeliveryTarget, deliver_batch};
use crate::tool_registry::{
    LoadedToolRegistry, ToolRegistryEntry, canonical_runtime_tool_name, load_tool_registry,
    load_tool_registry_value, registry_entry_identity, tool_definition_source_complete,
};
use anyhow::{Context, Result, bail};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Native Codex trace-bundle manifest schema version.
pub const CODEX_TRACE_BUNDLE_MANIFEST_VERSION: u32 = 1;
/// Capture-side source marker for native bundles.
pub const CODEX_TRACE_BUNDLE_SOURCE: &str = "codex_rollout_trace_bundle";
/// Checkpoint schema used by the bundle exporter.
pub const CODEX_TRACE_BUNDLE_CHECKPOINT_VERSION: &str =
    "chiptrace.codex-trace-bundle-checkpoint.v2";
const LEGACY_CODEX_TRACE_BUNDLE_CHECKPOINT_VERSION: &str =
    "chiptrace.codex-trace-bundle-checkpoint.v1";

const CHECKPOINTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("codex_trace_bundle_checkpoints");
const MAX_CONTEXT_ENTRIES: usize = 65_536;

pub type BundleExportTarget = DeliveryTarget;

/// Configuration for one native Codex bundle exporter.
#[derive(Debug, Clone)]
pub struct BundleExportConfig {
    pub input: PathBuf,
    pub state_root: PathBuf,
    pub target: BundleExportTarget,
    pub source_namespace: String,
    /// Harness-captured runtime Tool Registry snapshot. This is the only
    /// accepted source for Code Mode inner-tool schemas absent from the bundle.
    pub tool_registry: Option<PathBuf>,
    pub batch_records: usize,
    pub max_envelope_bytes: usize,
    pub request_timeout: Duration,
    pub retry_max_times: usize,
    /// Harness-owned task identity.  It is never inferred from a Codex thread.
    pub task_session_id: Option<String>,
    pub root_session_id: Option<String>,
    pub parent_session_id: Option<String>,
    pub goal_id: Option<String>,
    pub agent_id: Option<String>,
    pub branch_id: Option<String>,
    /// Harness-owned W3C trace context. The bundle's native trace UUID remains
    /// in rolloutEvent.bundle_trace_id and is never substituted for this ID.
    pub traceparent: Option<String>,
    /// Optional location for the exact event/payload byte mirror.  Defaults to
    /// `<state_root>/raw-bundles`.
    pub mirror_root: Option<PathBuf>,
    /// Require an explicit native `rollout_ended` event and no open tail.
    pub require_complete: bool,
}

/// Export counters and integrity facts.  Counters describe only lines read in
/// this invocation; checkpoint offsets make retries idempotent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleExportSummary {
    pub input: String,
    pub trace_id: Option<String>,
    pub rollout_id: Option<String>,
    pub manifest_sha256: Option<String>,
    pub start_offset: u64,
    pub committed_offset: u64,
    pub start_seq: u64,
    pub committed_seq: u64,
    pub lines_read: u64,
    pub captures_emitted: u64,
    pub duplicate_captures: u64,
    pub lifecycle_events: u64,
    pub message_events: u64,
    pub inference_events: u64,
    pub tool_executions: u64,
    pub tool_registry_snapshots: u64,
    pub unmapped_tool_events: u64,
    pub unknown_events: u64,
    pub payloads_verified: u64,
    pub raw_mirrored_bytes: u64,
    pub open_tail_bytes: u64,
    pub bundle_complete: bool,
    pub open_runtime_objects: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct TraceBundleManifest {
    schema_version: u32,
    trace_id: String,
    rollout_id: String,
    root_thread_id: String,
    started_at_unix_ms: i64,
    raw_event_log: String,
    payloads_dir: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct BundleContext {
    threads: BTreeMap<String, ThreadContext>,
    model_calls: BTreeMap<String, ModelCallContext>,
    tool_schemas: BTreeMap<String, Value>,
    pending_tools: BTreeMap<String, PendingToolContext>,
    deferred_runtime_tools: BTreeSet<String>,
    code_cells: BTreeMap<String, CodeCellContext>,
    active_threads: BTreeSet<String>,
    active_turns: BTreeSet<String>,
    active_inferences: BTreeSet<String>,
    active_code_cells: BTreeSet<String>,
    active_compactions: BTreeSet<String>,
    seen_threads: BTreeSet<String>,
    seen_turns: BTreeSet<String>,
    seen_inferences: BTreeSet<String>,
    seen_tools: BTreeSet<String>,
    seen_code_cells: BTreeSet<String>,
    seen_compactions: BTreeSet<String>,
    seen_agent_edges: BTreeSet<String>,
    tool_registry_sha256: Option<String>,
    tool_registry_snapshot: Option<Value>,
    current_model: Option<String>,
    current_provider: Option<String>,
    system_prompt: Option<String>,
    rollout_started: bool,
    rollout_ended: bool,
    rollout_terminal: bool,
    root_thread_started: bool,
    root_thread_ended: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct ThreadContext {
    parent_thread_id: Option<String>,
    agent_path: Option<String>,
    thread_source: Option<Value>,
    model: Option<String>,
    provider: Option<String>,
    system_prompt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModelCallContext {
    name: String,
    source_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodeCellContext {
    model_visible_call_id: String,
    started_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingToolContext {
    name: Option<String>,
    #[serde(default)]
    runtime_tool: Option<String>,
    #[serde(default)]
    runtime_namespace: Option<String>,
    initiator: String,
    model_visible_call_id: Option<String>,
    code_mode_runtime_tool_id: Option<String>,
    parent_call_id: Option<String>,
    lineage_matched: bool,
    schema: Option<Value>,
    invocation: Option<Value>,
    started_seq: u64,
    started_at: Option<String>,
    runtime_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundleCheckpoint {
    schema_version: String,
    source_path: String,
    manifest_sha256: String,
    config_fingerprint: String,
    committed_offset: u64,
    #[serde(default)]
    committed_prefix_sha256: String,
    last_line_start: u64,
    last_line_bytes: u64,
    last_line_sha256: String,
    last_seq: u64,
    context: BundleContext,
}

impl BundleCheckpoint {
    fn new(source_path: String, manifest_sha256: String, config_fingerprint: String) -> Self {
        Self {
            schema_version: CODEX_TRACE_BUNDLE_CHECKPOINT_VERSION.to_owned(),
            source_path,
            manifest_sha256,
            config_fingerprint,
            committed_offset: 0,
            committed_prefix_sha256: sha256([]),
            last_line_start: 0,
            last_line_bytes: 0,
            last_line_sha256: String::new(),
            last_seq: 0,
            context: BundleContext::default(),
        }
    }
}

struct CheckpointStore {
    database: Database,
}

impl CheckpointStore {
    fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        let database = Database::create(root.join("codex-trace-bundle-checkpoints.redb"))?;
        let transaction = database.begin_write()?;
        transaction.open_table(CHECKPOINTS)?;
        transaction.commit()?;
        Ok(Self { database })
    }

    fn load(
        &self,
        key: &str,
        source_path: String,
        manifest_sha256: String,
        config_fingerprint: String,
    ) -> Result<BundleCheckpoint> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(CHECKPOINTS)?;
        let mut checkpoint = table
            .get(key)?
            .map(|value| serde_json::from_slice::<BundleCheckpoint>(value.value()))
            .transpose()?
            .unwrap_or_else(|| {
                BundleCheckpoint::new(
                    source_path.clone(),
                    manifest_sha256.clone(),
                    config_fingerprint.clone(),
                )
            });
        if checkpoint.schema_version == LEGACY_CODEX_TRACE_BUNDLE_CHECKPOINT_VERSION {
            checkpoint.schema_version = CODEX_TRACE_BUNDLE_CHECKPOINT_VERSION.to_owned();
        } else if checkpoint.schema_version != CODEX_TRACE_BUNDLE_CHECKPOINT_VERSION {
            bail!("unsupported Codex trace-bundle checkpoint schema");
        }
        if checkpoint.source_path != source_path {
            bail!("Codex trace-bundle checkpoint source path changed");
        }
        if checkpoint.manifest_sha256 != manifest_sha256 {
            bail!("Codex trace-bundle manifest bytes changed");
        }
        if checkpoint.config_fingerprint != config_fingerprint {
            bail!("Codex trace-bundle exporter configuration changed for this source");
        }
        Ok(checkpoint)
    }

    fn save(&self, key: &str, checkpoint: &BundleCheckpoint) -> Result<()> {
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(CHECKPOINTS)?;
            if let Some(current) = table.get(key)? {
                let current: BundleCheckpoint = serde_json::from_slice(current.value())?;
                if current.committed_offset > checkpoint.committed_offset {
                    return Ok(());
                }
            }
            let encoded = serde_json::to_vec(checkpoint)?;
            table.insert(key, encoded.as_slice())?;
        }
        transaction.commit()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct PayloadEvidence {
    raw_payload_id: String,
    path: String,
    kind: Value,
    bytes: Vec<u8>,
    content: Option<Value>,
    sha256: String,
    mirror_path: String,
    raw_json: String,
}

struct BundleLoadPaths<'a> {
    bundle_root: &'a Path,
    payload_root: &'a Path,
    mirror_root: &'a Path,
}

struct BaseCaptureProjection<'a> {
    timestamp: Option<&'a str>,
    known: bool,
    payloads: Value,
}

#[derive(Debug)]
struct BundleEvent {
    raw_line: Vec<u8>,
    raw_record_bytes: u64,
    event_mirror_path: String,
    seq: u64,
    rollout_id: String,
    thread_id: Option<String>,
    turn_id: Option<String>,
    wall_time_unix_ms: Option<i64>,
    payload: Map<String, Value>,
    payloads: Vec<PayloadEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionKind {
    Lifecycle,
    Inference,
    Tool,
    Raw,
}

#[derive(Debug)]
struct ProjectedBundleEvent {
    capture: Value,
    kind: ProjectionKind,
    unknown: bool,
    unmapped_tool: bool,
    bundle_complete: bool,
}

/// Export a native Codex trace bundle to Capture v2 JSONL or a Rust Relay.
pub async fn export_codex_trace_bundle(config: BundleExportConfig) -> Result<BundleExportSummary> {
    if config.batch_records == 0 {
        bail!("Codex trace-bundle batch size must be positive");
    }
    if config.retry_max_times < 20 {
        bail!("Codex trace-bundle delivery requires at least 20 retry attempts");
    }
    if config.source_namespace.trim().is_empty() {
        bail!("Codex trace-bundle source namespace must not be empty");
    }
    validate_optional_id(config.task_session_id.as_deref(), "task_session_id")?;
    validate_optional_id(config.root_session_id.as_deref(), "root_session_id")?;
    validate_optional_id(config.parent_session_id.as_deref(), "parent_session_id")?;
    validate_optional_id(config.goal_id.as_deref(), "goal_id")?;
    validate_optional_id(config.agent_id.as_deref(), "agent_id")?;
    validate_optional_id(config.branch_id.as_deref(), "branch_id")?;
    if let Some(traceparent) = config.traceparent.as_deref() {
        validate_traceparent(traceparent)?;
    }

    let bundle_root = config
        .input
        .canonicalize()
        .with_context(|| format!("resolve Codex trace bundle {}", config.input.display()))?;
    if !bundle_root.is_dir() {
        bail!(
            "Codex trace-bundle input is not a directory: {}",
            bundle_root.display()
        );
    }
    let manifest_path = safe_existing_path(&bundle_root, Path::new("manifest.json"), None)?;
    let manifest_bytes = fs::read(&manifest_path).with_context(|| {
        format!(
            "read Codex trace-bundle manifest {}",
            manifest_path.display()
        )
    })?;
    let manifest_sha256 = sha256(&manifest_bytes);
    let manifest: TraceBundleManifest =
        serde_json::from_slice(&manifest_bytes).context("parse Codex trace-bundle manifest")?;
    validate_manifest(&manifest)?;
    let raw_event_path =
        safe_existing_path(&bundle_root, Path::new(&manifest.raw_event_log), None)?;
    let payload_root = safe_existing_path(&bundle_root, Path::new(&manifest.payloads_dir), None)?;
    if !payload_root.is_dir() {
        bail!("Codex trace-bundle payloads_dir is not a directory");
    }

    let source_path = raw_event_path.to_string_lossy().into_owned();
    let tool_registry = load_tool_registry(config.tool_registry.as_deref())?;
    if tool_registry
        .as_ref()
        .is_some_and(|registry| registry.registry.producer != "codex-cli")
    {
        bail!("Codex trace bundle requires a codex-cli Tool Registry snapshot");
    }
    let config_fingerprint = config_fingerprint(&config, tool_registry.as_ref());
    let checkpoint_key = sha256(source_path.as_bytes());
    let checkpoint_store = CheckpointStore::open(&config.state_root)?;
    let mut checkpoint = checkpoint_store.load(
        &checkpoint_key,
        source_path.clone(),
        manifest_sha256.clone(),
        config_fingerprint.clone(),
    )?;
    reconcile_checkpoint_context(&mut checkpoint.context, &manifest);
    install_tool_registry(&mut checkpoint.context, tool_registry.as_ref())?;
    let mut prefix_hasher = verify_checkpoint(&raw_event_path, &checkpoint)?;
    checkpoint.committed_prefix_sha256 = hex::encode(prefix_hasher.clone().finalize());

    let mirror_root = config
        .mirror_root
        .clone()
        .unwrap_or_else(|| config.state_root.join("raw-bundles"));
    let mirror_root = mirror_root.canonicalize().unwrap_or(mirror_root);
    fs::create_dir_all(&mirror_root)?;
    let manifest_mirror_path = mirror_bytes(
        &mirror_root,
        &manifest.trace_id,
        "manifest",
        "manifest.json",
        &manifest_bytes,
    )?;
    let manifest_raw = std::str::from_utf8(&manifest_bytes)
        .context("Codex trace-bundle manifest must be UTF-8")?
        .to_owned();

    let mut summary = BundleExportSummary {
        input: source_path.clone(),
        trace_id: Some(manifest.trace_id.clone()),
        rollout_id: Some(manifest.rollout_id.clone()),
        manifest_sha256: Some(manifest_sha256.clone()),
        start_offset: checkpoint.committed_offset,
        committed_offset: checkpoint.committed_offset,
        start_seq: checkpoint.last_seq,
        committed_seq: checkpoint.last_seq,
        bundle_complete: runtime_complete(&checkpoint.context),
        open_runtime_objects: open_runtime_objects(&checkpoint.context),
        ..BundleExportSummary::default()
    };

    let mut file = File::open(&raw_event_path)?;
    file.seek(SeekFrom::Start(checkpoint.committed_offset))?;
    let mut reader = BufReader::with_capacity(4 * 1024 * 1024, file);
    let mut batch = Vec::with_capacity(config.batch_records);
    let mut batch_checkpoint = checkpoint.clone();
    let mut expected_seq = checkpoint.last_seq.saturating_add(1);

    loop {
        let line_start = checkpoint.committed_offset;
        let mut line_with_newline = Vec::new();
        let read = reader.read_until(b'\n', &mut line_with_newline)?;
        if read == 0 {
            break;
        }
        if !line_with_newline.ends_with(b"\n") {
            summary.open_tail_bytes = read as u64;
            break;
        }
        let source_line_sha256 = sha256(&line_with_newline);
        let raw_record = line_with_newline.clone();
        prefix_hasher.update(&raw_record);
        let mut raw_line = line_with_newline;
        raw_line.pop();
        if raw_line.ends_with(b"\r") {
            raw_line.pop();
        }
        checkpoint.committed_offset = checkpoint.committed_offset.saturating_add(read as u64);
        checkpoint.committed_prefix_sha256 = hex::encode(prefix_hasher.clone().finalize());
        if raw_line.iter().all(u8::is_ascii_whitespace) {
            checkpoint.last_line_start = line_start;
            checkpoint.last_line_bytes = read as u64;
            checkpoint.last_line_sha256 = source_line_sha256;
            batch_checkpoint = checkpoint.clone();
            continue;
        }
        let source_line = std::str::from_utf8(&raw_line)
            .context("Codex trace-bundle trace.jsonl must be UTF-8")?;
        let value: Value = serde_json::from_slice(&raw_line)
            .with_context(|| format!("parse trace.jsonl at byte {line_start}"))?;
        let event = load_event(
            value,
            raw_line.clone(),
            raw_record,
            expected_seq,
            &manifest,
            &BundleLoadPaths {
                bundle_root: &bundle_root,
                payload_root: &payload_root,
                mirror_root: &mirror_root,
            },
        )?;
        if checkpoint.context.rollout_ended {
            bail!("Codex trace-bundle contains events after rollout_ended");
        }
        expected_seq = expected_seq.saturating_add(1);
        summary.lines_read = summary.lines_read.saturating_add(1);
        summary.payloads_verified = summary
            .payloads_verified
            .saturating_add(event.payloads.len() as u64);
        summary.raw_mirrored_bytes = summary.raw_mirrored_bytes.saturating_add(
            event.raw_record_bytes
                + event
                    .payloads
                    .iter()
                    .map(|payload| payload.bytes.len() as u64)
                    .sum::<u64>(),
        );

        let mut projected = project_event(
            &event,
            source_line,
            &manifest,
            &mut checkpoint.context,
            &config,
        )?;
        projected.capture["rolloutEvent"]["bundle_manifest_sha256"] =
            json!(manifest_sha256.clone());
        projected.capture["rolloutEvent"]["bundle_manifest_raw"] = json!(manifest_raw.clone());
        projected.capture["rolloutEvent"]["bundle_manifest_mirror_path"] =
            json!(manifest_mirror_path.clone());
        update_summary(&mut summary, &projected);
        checkpoint.last_seq = event.seq;
        checkpoint.last_line_start = line_start;
        checkpoint.last_line_bytes = read as u64;
        checkpoint.last_line_sha256 = source_line_sha256;
        summary.bundle_complete = projected.bundle_complete;

        let normalized = normalize_capture(
            &serde_json::to_vec(&projected.capture)?,
            config.max_envelope_bytes,
        )?;
        batch.push(normalized.canonical);
        summary.captures_emitted = summary.captures_emitted.saturating_add(1);
        batch_checkpoint = checkpoint.clone();
        if batch.len() >= config.batch_records {
            summary.duplicate_captures = summary
                .duplicate_captures
                .saturating_add(deliver_bundle_batch(&config, &batch).await?);
            checkpoint_store.save(&checkpoint_key, &batch_checkpoint)?;
            summary.committed_offset = batch_checkpoint.committed_offset;
            summary.committed_seq = batch_checkpoint.last_seq;
            batch.clear();
        }
    }

    if !batch.is_empty() {
        summary.duplicate_captures = summary
            .duplicate_captures
            .saturating_add(deliver_bundle_batch(&config, &batch).await?);
    }
    checkpoint_store.save(&checkpoint_key, &batch_checkpoint)?;
    summary.committed_offset = batch_checkpoint.committed_offset;
    summary.committed_seq = batch_checkpoint.last_seq;
    summary.bundle_complete = runtime_complete(&batch_checkpoint.context);
    summary.open_runtime_objects = open_runtime_objects(&batch_checkpoint.context);
    let final_file_len = fs::metadata(&raw_event_path)?.len();
    if summary.committed_offset > final_file_len {
        bail!("Codex trace-bundle checkpoint advanced beyond trace.jsonl");
    }
    if config.require_complete && (summary.open_tail_bytes != 0 || !summary.bundle_complete) {
        bail!(
            "Codex trace bundle is not complete: open_tail_bytes={}, open_runtime_objects={}, rollout_ended={}",
            summary.open_tail_bytes,
            summary.open_runtime_objects,
            summary.bundle_complete
        );
    }
    Ok(summary)
}

/// Compatibility alias with a shorter name for integrations.
pub async fn export_codex_bundle(config: BundleExportConfig) -> Result<BundleExportSummary> {
    export_codex_trace_bundle(config).await
}

async fn deliver_bundle_batch(config: &BundleExportConfig, batch: &[Vec<u8>]) -> Result<u64> {
    let receipt = deliver_batch(
        &DeliveryConfig {
            target: config.target.clone(),
            request_timeout: config.request_timeout,
            retry_max_times: config.retry_max_times,
        },
        batch,
    )
    .await?;
    Ok(receipt.duplicates)
}

fn validate_manifest(manifest: &TraceBundleManifest) -> Result<()> {
    if manifest.schema_version != CODEX_TRACE_BUNDLE_MANIFEST_VERSION {
        bail!("unsupported Codex trace-bundle manifest schema_version");
    }
    for (field, value) in [
        ("trace_id", manifest.trace_id.as_str()),
        ("rollout_id", manifest.rollout_id.as_str()),
        ("root_thread_id", manifest.root_thread_id.as_str()),
        ("raw_event_log", manifest.raw_event_log.as_str()),
        ("payloads_dir", manifest.payloads_dir.as_str()),
    ] {
        if value.trim().is_empty() {
            bail!("Codex trace-bundle manifest {field} is empty");
        }
    }
    safe_component(&manifest.trace_id)
        .with_context(|| "Codex trace-bundle manifest trace_id is not a safe identifier")?;
    safe_component(&manifest.rollout_id)
        .with_context(|| "Codex trace-bundle manifest rollout_id is not a safe identifier")?;
    safe_component(&manifest.root_thread_id)
        .with_context(|| "Codex trace-bundle manifest root_thread_id is not a safe identifier")?;
    if manifest.started_at_unix_ms < 0 {
        bail!("Codex trace-bundle manifest started_at_unix_ms is negative");
    }
    validate_relative_path(Path::new(&manifest.raw_event_log))?;
    validate_relative_path(Path::new(&manifest.payloads_dir))?;
    if manifest.raw_event_log == manifest.payloads_dir
        || Path::new(&manifest.raw_event_log).starts_with(Path::new(&manifest.payloads_dir))
    {
        bail!("Codex trace-bundle raw_event_log overlaps payloads_dir");
    }
    Ok(())
}

fn load_event(
    value: Value,
    raw_line: Vec<u8>,
    raw_record: Vec<u8>,
    expected_seq: u64,
    manifest: &TraceBundleManifest,
    paths: &BundleLoadPaths<'_>,
) -> Result<BundleEvent> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Codex trace-bundle event must be a JSON object"))?;
    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("Codex trace-bundle event schema_version is required"))?;
    if schema_version != CODEX_TRACE_BUNDLE_MANIFEST_VERSION as u64 {
        bail!("unsupported Codex trace-bundle raw event schema_version");
    }
    let seq = object
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("Codex trace-bundle event seq is required"))?;
    if seq != expected_seq {
        bail!("Codex trace-bundle seq gap or duplicate: expected {expected_seq}, got {seq}");
    }
    let rollout_id = object
        .get("rollout_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Codex trace-bundle event rollout_id is required"))?;
    if rollout_id != manifest.rollout_id {
        bail!("Codex trace-bundle event rollout_id does not match manifest");
    }
    let rollout_id = rollout_id.to_owned();
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("Codex trace-bundle event payload is required"))?
        .clone();
    let payload_type = payload
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("Codex trace-bundle event payload.type is required"))?;
    if seq == 1 && payload_type != "rollout_started" {
        bail!("Codex trace-bundle first event must be rollout_started");
    }
    let thread_id = object
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let turn_id = object
        .get("codex_turn_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    validate_event_shape(
        payload_type,
        &payload,
        thread_id.as_deref(),
        turn_id.as_deref(),
    )?;
    let wall_time_unix_ms = object
        .get("wall_time_unix_ms")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("Codex trace-bundle event wall_time_unix_ms is required"))?;
    if wall_time_unix_ms < 0 {
        bail!("Codex trace-bundle event wall_time_unix_ms is negative");
    }
    let mut refs = Vec::new();
    collect_payload_refs(&Value::Object(payload.clone()), &mut refs)?;
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut payloads = Vec::with_capacity(refs.len());
    for (raw_payload_id, path, kind) in refs {
        if let Some(previous_path) = seen.insert(raw_payload_id.clone(), path.clone()) {
            if previous_path != path {
                bail!("payload ref {raw_payload_id} points to multiple paths");
            }
            continue;
        }
        let payload_path = safe_existing_path(
            paths.bundle_root,
            Path::new(&path),
            Some(paths.payload_root),
        )?;
        let bytes = fs::read(&payload_path)
            .with_context(|| format!("read Codex trace payload {raw_payload_id}"))?;
        let digest = sha256(&bytes);
        let content = serde_json::from_slice::<Value>(&bytes).ok();
        let raw_json = std::str::from_utf8(&bytes)
            .with_context(|| format!("Codex trace payload {raw_payload_id} must be UTF-8"))?
            .to_owned();
        let mirror_path = mirror_bytes(
            paths.mirror_root,
            &manifest.trace_id,
            "payloads",
            &digest,
            &bytes,
        )?;
        payloads.push(PayloadEvidence {
            raw_payload_id,
            path,
            kind,
            bytes,
            content,
            sha256: digest,
            mirror_path,
            raw_json,
        });
    }
    let event_mirror_path = mirror_bytes(
        paths.mirror_root,
        &manifest.trace_id,
        "events",
        &format!("{:020}-{}", seq, sha256(&raw_record)),
        &raw_record,
    )?;
    Ok(BundleEvent {
        raw_line,
        raw_record_bytes: raw_record.len() as u64,
        event_mirror_path,
        seq,
        rollout_id,
        thread_id,
        turn_id,
        wall_time_unix_ms: Some(wall_time_unix_ms),
        payload,
        payloads,
    })
}

fn validate_event_shape(
    event_type: &str,
    payload: &Map<String, Value>,
    envelope_thread_id: Option<&str>,
    envelope_turn_id: Option<&str>,
) -> Result<()> {
    let require_strings = |fields: &[&str]| -> Result<()> {
        for field in fields {
            require_event_string(payload, event_type, field)?;
        }
        Ok(())
    };
    let require_objects = |fields: &[&str]| -> Result<()> {
        for field in fields {
            if !payload.get(*field).is_some_and(Value::is_object) {
                bail!("Codex trace-bundle {event_type}.{field} must be an object");
            }
        }
        Ok(())
    };
    match event_type {
        "rollout_started" => require_strings(&["trace_id", "root_thread_id"]),
        "rollout_ended" => require_strings(&["status"]),
        "thread_started" => require_strings(&["thread_id", "agent_path"]),
        "thread_ended" => require_strings(&["thread_id", "status"]),
        "codex_turn_started" => require_strings(&["codex_turn_id", "thread_id"]),
        "codex_turn_ended" => require_strings(&["codex_turn_id", "status"]),
        "inference_started" => {
            require_strings(&[
                "inference_call_id",
                "thread_id",
                "codex_turn_id",
                "model",
                "provider_name",
            ])?;
            require_objects(&["request_payload"])
        }
        "inference_completed" => {
            require_strings(&["inference_call_id"])?;
            require_objects(&["response_payload"])
        }
        "inference_failed" => require_strings(&["inference_call_id", "error"]),
        "inference_cancelled" => require_strings(&["inference_call_id", "reason"]),
        "tool_call_started" => {
            require_strings(&["tool_call_id"])?;
            require_objects(&["requester", "kind", "summary"])
        }
        "mcp_tool_call_correlation_assigned" => require_strings(&["tool_call_id", "mcp_call_id"]),
        "tool_call_runtime_started" => {
            require_strings(&["tool_call_id"])?;
            require_objects(&["runtime_payload"])
        }
        "tool_call_runtime_ended" => {
            require_strings(&["tool_call_id", "status"])?;
            require_objects(&["runtime_payload"])
        }
        "tool_call_ended" => require_strings(&["tool_call_id", "status"]),
        "code_cell_started" => {
            require_strings(&["runtime_cell_id", "model_visible_call_id"])?;
            if !payload.get("source_js").is_some_and(Value::is_string) {
                bail!("Codex trace-bundle code_cell_started.source_js must be a string");
            }
            Ok(())
        }
        "code_cell_initial_response" | "code_cell_ended" => {
            require_strings(&["runtime_cell_id", "status"])
        }
        "compaction_request_started" => {
            require_strings(&[
                "compaction_id",
                "compaction_request_id",
                "thread_id",
                "codex_turn_id",
                "model",
                "provider_name",
            ])?;
            require_objects(&["request_payload"])
        }
        "compaction_request_completed" => {
            require_strings(&["compaction_id", "compaction_request_id"])?;
            require_objects(&["response_payload"])
        }
        "compaction_request_failed" => {
            require_strings(&["compaction_id", "compaction_request_id", "error"])
        }
        "compaction_installed" => {
            require_strings(&["compaction_id"])?;
            require_objects(&["checkpoint_payload"])
        }
        "agent_result_observed" => require_strings(&[
            "edge_id",
            "child_thread_id",
            "child_codex_turn_id",
            "parent_thread_id",
            "message",
        ]),
        "protocol_event_observed" => {
            require_strings(&["event_type"])?;
            require_objects(&["event_payload"])
        }
        "other" => {
            require_strings(&["kind", "summary"])?;
            if !payload.get("payloads").is_some_and(Value::is_array)
                || payload.get("metadata").is_none()
            {
                bail!("Codex trace-bundle other event requires payloads and metadata");
            }
            Ok(())
        }
        _ => Ok(()),
    }?;

    if let (Some(payload_thread_id), Some(envelope_thread_id)) = (
        payload.get("thread_id").and_then(Value::as_str),
        envelope_thread_id,
    ) && payload_thread_id != envelope_thread_id
    {
        bail!("Codex trace-bundle payload thread_id conflicts with its event envelope");
    }
    if let (Some(payload_turn_id), Some(envelope_turn_id)) = (
        payload.get("codex_turn_id").and_then(Value::as_str),
        envelope_turn_id,
    ) && payload_turn_id != envelope_turn_id
    {
        bail!("Codex trace-bundle payload codex_turn_id conflicts with its event envelope");
    }
    Ok(())
}

fn require_event_string<'a>(
    payload: &'a Map<String, Value>,
    event_type: &str,
    field: &str,
) -> Result<&'a str> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Codex trace-bundle {event_type}.{field} is required"))
}

fn collect_payload_refs(value: &Value, output: &mut Vec<(String, String, Value)>) -> Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_payload_refs(value, output)?;
            }
        }
        Value::Object(object) => {
            if object.get("raw_payload_id").is_some() {
                let id = object
                    .get("raw_payload_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("payload ref raw_payload_id is required"))?;
                let path = object
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("payload ref path is required"))?;
                if id.trim().is_empty() || path.trim().is_empty() {
                    bail!("payload ref ID and path must not be empty");
                }
                output.push((
                    id.to_owned(),
                    path.to_owned(),
                    object.get("kind").cloned().unwrap_or(Value::Null),
                ));
                return Ok(());
            }
            for value in object.values() {
                collect_payload_refs(value, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn project_event(
    event: &BundleEvent,
    source_line: &str,
    manifest: &TraceBundleManifest,
    context: &mut BundleContext,
    config: &BundleExportConfig,
) -> Result<ProjectedBundleEvent> {
    let event_type = event
        .payload
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("");
    let known = known_event_type(event_type);
    let timestamp = event.wall_time_unix_ms.and_then(format_timestamp);
    let payload_json = payload_evidence_json(&event.payloads);
    let mut capture = base_capture(
        event,
        source_line,
        manifest,
        context,
        config,
        BaseCaptureProjection {
            timestamp: timestamp.as_deref(),
            known,
            payloads: payload_json,
        },
    );
    let mut kind = ProjectionKind::Raw;
    let mut unmapped_tool = false;

    match event_type {
        "rollout_started" => {
            if context.rollout_started
                || event.payload.get("trace_id").and_then(Value::as_str)
                    != Some(manifest.trace_id.as_str())
                || event.payload.get("root_thread_id").and_then(Value::as_str)
                    != Some(manifest.root_thread_id.as_str())
            {
                bail!("Codex trace-bundle rollout_started conflicts with manifest");
            }
            context.rollout_started = true;
            set_lifecycle(
                &mut capture,
                "rollout_start",
                "started",
                &event.payload,
                timestamp.as_deref(),
            );
            kind = ProjectionKind::Lifecycle;
        }
        "rollout_ended" => {
            let status = execution_status(event.payload.get("status").and_then(Value::as_str));
            set_lifecycle(
                &mut capture,
                "rollout_end",
                status,
                &event.payload,
                timestamp.as_deref(),
            );
            context.rollout_ended = true;
            context.rollout_terminal = status != "incomplete";
            kind = ProjectionKind::Lifecycle;
        }
        "thread_started" => {
            if let Some(thread_id) = event
                .payload
                .get("thread_id")
                .and_then(Value::as_str)
                .or(event.thread_id.as_deref())
            {
                if !context.seen_threads.insert(thread_id.to_owned())
                    || !context.active_threads.insert(thread_id.to_owned())
                {
                    bail!("duplicate Codex trace-bundle thread start for {thread_id}");
                }
                if thread_id == manifest.root_thread_id {
                    context.root_thread_started = true;
                }
            }
            update_thread_context(event, context)?;
            if let Some(parent_thread_id) = event
                .payload
                .get("thread_id")
                .and_then(Value::as_str)
                .and_then(|thread_id| context.threads.get(thread_id))
                .and_then(|thread| thread.parent_thread_id.as_deref())
                && !context.seen_threads.contains(parent_thread_id)
            {
                bail!("Codex trace-bundle child thread started before its parent");
            }
            set_lifecycle(
                &mut capture,
                "thread_start",
                "started",
                &event.payload,
                timestamp.as_deref(),
            );
            kind = ProjectionKind::Lifecycle;
        }
        "thread_ended" => {
            if let Some(thread_id) = event
                .payload
                .get("thread_id")
                .and_then(Value::as_str)
                .or(event.thread_id.as_deref())
            {
                if !context.active_threads.remove(thread_id) {
                    bail!("Codex trace-bundle thread end has no matching start for {thread_id}");
                }
                if thread_id == manifest.root_thread_id {
                    context.root_thread_ended = true;
                }
            }
            let status = execution_status(event.payload.get("status").and_then(Value::as_str));
            set_lifecycle(
                &mut capture,
                "thread_end",
                status,
                &event.payload,
                timestamp.as_deref(),
            );
            kind = ProjectionKind::Lifecycle;
        }
        "codex_turn_started" => {
            if let Some(turn_id) = native_turn_id(event)
                && (!context.seen_turns.insert(turn_id.to_owned())
                    || !context.active_turns.insert(turn_id.to_owned()))
            {
                bail!("duplicate Codex trace-bundle turn start for {turn_id}");
            }
            set_lifecycle(
                &mut capture,
                "turn_start",
                "started",
                &event.payload,
                timestamp.as_deref(),
            );
            kind = ProjectionKind::Lifecycle;
        }
        "codex_turn_ended" => {
            if let Some(turn_id) = native_turn_id(event)
                && !context.active_turns.remove(turn_id)
            {
                bail!("Codex trace-bundle turn end has no matching start for {turn_id}");
            }
            let status = execution_status(event.payload.get("status").and_then(Value::as_str));
            set_lifecycle(
                &mut capture,
                "turn_end",
                status,
                &event.payload,
                timestamp.as_deref(),
            );
            kind = ProjectionKind::Lifecycle;
        }
        "inference_started" => {
            if let Some(inference_id) = event
                .payload
                .get("inference_call_id")
                .and_then(Value::as_str)
                && (!context.seen_inferences.insert(inference_id.to_owned())
                    || !context.active_inferences.insert(inference_id.to_owned()))
            {
                bail!("duplicate Codex trace-bundle inference start for {inference_id}");
            }
            update_inference_context(event, context)?;
            if let Some(request) = referenced_content(event, "request_payload") {
                capture["requestBody"] = json!({"kind":"json","value":request});
                if let Some(previous) = request
                    .get("previous_response_id")
                    .or_else(|| request.get("previousResponseId"))
                    .and_then(Value::as_str)
                {
                    capture["traceContext"]["previous_response_id"] = json!(previous);
                    append_field_evidence(
                        &mut capture,
                        "traceContext.previous_response_id",
                        previous,
                        "codex_rollout_trace.inference_request",
                        "runtime_attested",
                    );
                }
            }
            capture["producerModel"] = event
                .payload
                .get("model")
                .cloned()
                .or_else(|| context.current_model.clone().map(Value::String))
                .unwrap_or(Value::Null);
            capture["runtimeProvider"] = event
                .payload
                .get("provider_name")
                .cloned()
                .or_else(|| context.current_provider.clone().map(Value::String))
                .unwrap_or(Value::Null);
            capture["rolloutEvent"]["projection"] = json!("inference_request");
            kind = ProjectionKind::Inference;
        }
        "inference_completed" | "inference_failed" | "inference_cancelled" => {
            if let Some(inference_id) = event
                .payload
                .get("inference_call_id")
                .and_then(Value::as_str)
                && !context.active_inferences.remove(inference_id)
            {
                bail!("Codex trace-bundle inference end has no matching start for {inference_id}");
            }
            update_inference_context(event, context)?;
            if let Some(response) = referenced_content(event, response_payload_field(event_type)) {
                capture["responseBody"] = json!({
                    "kind":"json",
                    "value":response_body(response, &event.payload),
                });
                if let Some(usage) = response
                    .get("token_usage")
                    .or_else(|| response.get("usage"))
                {
                    capture["rolloutUsage"] = usage.clone();
                }
            }
            if let Some(response_id) = event.payload.get("response_id") {
                capture["responseId"] = response_id.clone();
            }
            if let Some(request_id) = event.payload.get("upstream_request_id") {
                capture["upstreamRequestId"] = request_id.clone();
            }
            let status = match event_type {
                "inference_completed" => "completed",
                "inference_failed" => "failed",
                _ => "cancelled",
            };
            set_lifecycle(
                &mut capture,
                "inference_end",
                status,
                &event.payload,
                timestamp.as_deref(),
            );
            capture["rolloutEvent"]["projection"] = json!("inference_response");
            kind = ProjectionKind::Inference;
        }
        "tool_call_started" => {
            if let Some(call_id) = event.payload.get("tool_call_id").and_then(Value::as_str)
                && !context.seen_tools.insert(call_id.to_owned())
            {
                bail!("duplicate Codex trace-bundle tool start for {call_id}");
            }
            let (pending, correlation) = start_tool_context(event, context, timestamp.as_deref())?;
            unmapped_tool = correlation != RuntimeCorrelation::Matched;
            if let Some(pending) = pending {
                capture["runtimeToolObservation"] = json!({
                    "tool_call_id":event.payload.get("tool_call_id"),
                    "requester":event.payload.get("requester"),
                    "name":pending.name,
                    "runtime_tool":pending.runtime_tool,
                    "runtime_namespace":pending.runtime_namespace,
                    "invocation":pending.invocation,
                    "status":"started",
                });
                if let Some(name) = pending.name.as_deref()
                    && (pending.initiator != "assistant" || pending.lineage_matched)
                {
                    let (schema, schema_provenance) = projected_tool_schema(&pending, name);
                    capture["toolExecution"] = json!({
                        "call_id":event.payload.get("tool_call_id"),
                        "parent_call_id":pending.parent_call_id,
                        "name":name,
                        "runtime_tool":pending.runtime_tool,
                        "runtime_namespace":pending.runtime_namespace,
                        "status":"started",
                        "initiator":pending.initiator,
                        "arguments":invocation_arguments(pending.invocation.as_ref()),
                        "result":Value::Null,
                        "started_at":pending.started_at,
                        "finished_at":Value::Null,
                        "model_call_matched":pending.lineage_matched,
                        "result_content_captured":false,
                        "schema":schema,
                        "schema_provenance":schema_provenance,
                    });
                    if config.task_session_id.is_some() {
                        capture["recordType"] = json!("tool_execution");
                    }
                }
            }
            capture["rolloutEvent"]["runtime_call_correlation"] = json!(correlation.label());
            capture["rolloutEvent"]["projection"] = json!("tool_started");
            kind = ProjectionKind::Tool;
        }
        "tool_call_runtime_started" | "tool_call_runtime_ended" => {
            let call_id = event
                .payload
                .get("tool_call_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            if let Some(pending) = context.pending_tools.get_mut(call_id) {
                if event_type == "tool_call_runtime_started" {
                    pending.runtime_status = Some("started".to_owned());
                } else {
                    pending.runtime_status = event
                        .payload
                        .get("status")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
                capture["runtimeToolObservation"] = json!({
                    "tool_call_id":call_id,
                    "runtime_payload":event.payload.get("runtime_payload"),
                    "status":event.payload.get("status"),
                });
            } else if event_type == "tool_call_runtime_ended"
                && context.deferred_runtime_tools.remove(call_id)
            {
                capture["runtimeToolObservation"] = json!({
                    "tool_call_id":call_id,
                    "runtime_payload":event.payload.get("runtime_payload"),
                    "status":event.payload.get("status"),
                    "deferred_completion":true,
                });
            } else {
                unmapped_tool = true;
            }
            capture["rolloutEvent"]["runtime_call_correlation"] = json!(if unmapped_tool {
                "missing_tool_start"
            } else if event_type == "tool_call_runtime_ended"
                && !context.pending_tools.contains_key(call_id)
            {
                "deferred_runtime_completion"
            } else {
                "runtime_tool_call"
            });
            capture["rolloutEvent"]["projection"] = json!("tool_runtime");
            kind = ProjectionKind::Tool;
        }
        "tool_call_ended" => {
            let call_id = event
                .payload
                .get("tool_call_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let pending = context.pending_tools.remove(call_id);
            if pending
                .as_ref()
                .is_some_and(|pending| pending.runtime_status.as_deref() == Some("started"))
            {
                context.deferred_runtime_tools.insert(call_id.to_owned());
            }
            let dispatch_status = event
                .payload
                .get("status")
                .and_then(Value::as_str)
                .map(normalize_tool_status)
                .unwrap_or("unknown");
            let status = pending
                .as_ref()
                .and_then(|pending| pending.runtime_status.as_deref())
                .map(normalize_tool_status)
                .filter(|status| *status != "unknown")
                .unwrap_or(dispatch_status);
            let result = referenced_content(event, "result_payload").map(tool_result_content);
            if let Some(pending) = pending {
                let matched = pending.lineage_matched;
                unmapped_tool =
                    pending.schema.is_none() || !matched && pending.initiator == "assistant";
                capture["rolloutEvent"]["runtime_call_correlation"] = json!(if matched {
                    "matched_model_call"
                } else if pending.schema.is_none() {
                    "missing_registry"
                } else {
                    "missing_model_call"
                });
                if let (Some(name), Some(result)) = (pending.name.clone(), result.as_ref())
                    && !result.is_null()
                    && status != "unknown"
                    && (pending.initiator != "assistant" || matched)
                {
                    let (schema, schema_provenance) = projected_tool_schema(&pending, &name);
                    let execution = json!({
                        "call_id":call_id,
                        "parent_call_id":pending.parent_call_id,
                        "name":name,
                        "runtime_tool":pending.runtime_tool,
                        "runtime_namespace":pending.runtime_namespace,
                        "status":status,
                        "initiator":pending.initiator,
                        "arguments":invocation_arguments(pending.invocation.as_ref()),
                        "result":result,
                        "started_at":pending.started_at,
                        "finished_at":timestamp,
                        "model_call_matched":matched,
                        "result_content_captured":true,
                        "schema":schema,
                        "schema_provenance":schema_provenance,
                    });
                    capture["toolExecution"] = execution;
                    if config.task_session_id.is_some() {
                        capture["recordType"] = json!("tool_execution");
                    }
                    kind = ProjectionKind::Tool;
                } else {
                    unmapped_tool = true;
                    capture["rolloutEvent"]["projection"] = json!("tool_end_unmapped");
                    kind = ProjectionKind::Tool;
                }
            } else {
                unmapped_tool = true;
                capture["rolloutEvent"]["runtime_call_correlation"] = json!("missing_tool_start");
                capture["rolloutEvent"]["projection"] = json!("tool_end_unmapped");
                kind = ProjectionKind::Tool;
            }
            set_lifecycle(
                &mut capture,
                "tool_end",
                status,
                &event.payload,
                timestamp.as_deref(),
            );
        }
        "code_cell_started" | "code_cell_initial_response" | "code_cell_ended" => {
            if event_type == "code_cell_started"
                && let (Some(runtime_cell_id), Some(model_visible_call_id)) = (
                    event.payload.get("runtime_cell_id").and_then(Value::as_str),
                    event
                        .payload
                        .get("model_visible_call_id")
                        .and_then(Value::as_str),
                )
            {
                if !context.seen_code_cells.insert(runtime_cell_id.to_owned()) {
                    bail!("duplicate Codex trace-bundle code cell start for {runtime_cell_id}");
                }
                context.code_cells.insert(
                    runtime_cell_id.to_owned(),
                    CodeCellContext {
                        model_visible_call_id: model_visible_call_id.to_owned(),
                        started_seq: event.seq,
                    },
                );
                if !context.active_code_cells.insert(runtime_cell_id.to_owned()) {
                    bail!("duplicate Codex trace-bundle code cell start for {runtime_cell_id}");
                }
                trim_context(context);
            }
            if event_type == "code_cell_ended"
                && let Some(runtime_cell_id) =
                    event.payload.get("runtime_cell_id").and_then(Value::as_str)
                && !context.active_code_cells.remove(runtime_cell_id)
            {
                bail!(
                    "Codex trace-bundle code cell end has no matching start for {runtime_cell_id}"
                );
            }
            if event_type == "code_cell_initial_response"
                && let Some(runtime_cell_id) =
                    event.payload.get("runtime_cell_id").and_then(Value::as_str)
                && !context.active_code_cells.contains(runtime_cell_id)
            {
                bail!(
                    "Codex trace-bundle code cell response has no matching start for {runtime_cell_id}"
                );
            }
            let lifecycle = match event_type {
                "code_cell_started" => ("code_cell_start", "started"),
                "code_cell_initial_response" => ("code_cell_initial_response", "completed"),
                _ => ("code_cell_end", "completed"),
            };
            let status = event
                .payload
                .get("status")
                .and_then(Value::as_str)
                .map(normalize_tool_status)
                .unwrap_or(lifecycle.1);
            set_lifecycle(
                &mut capture,
                lifecycle.0,
                status,
                &event.payload,
                timestamp.as_deref(),
            );
            capture["runtimeToolObservation"] = event.payload.clone().into();
            kind = ProjectionKind::Lifecycle;
        }
        "compaction_request_started"
        | "compaction_request_completed"
        | "compaction_request_failed"
        | "compaction_installed" => {
            if let Some(request_id) = event
                .payload
                .get("compaction_request_id")
                .and_then(Value::as_str)
            {
                if event_type == "compaction_request_started" {
                    if !context.seen_compactions.insert(request_id.to_owned())
                        || !context.active_compactions.insert(request_id.to_owned())
                    {
                        bail!("duplicate Codex compaction request start for {request_id}");
                    }
                } else if !context.active_compactions.remove(request_id) {
                    bail!(
                        "Codex trace-bundle compaction end has no matching start for {request_id}"
                    );
                }
            }
            let status = if event_type.ends_with("failed") {
                "failed"
            } else if event_type.ends_with("started") {
                "started"
            } else {
                "completed"
            };
            set_lifecycle(
                &mut capture,
                "compaction",
                status,
                &event.payload,
                timestamp.as_deref(),
            );
            kind = ProjectionKind::Lifecycle;
        }
        "agent_result_observed" => {
            let edge_id = event
                .payload
                .get("edge_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !context.seen_agent_edges.insert(edge_id.to_owned()) {
                bail!("duplicate Codex trace-bundle agent result edge {edge_id}");
            }
            for field in ["child_thread_id", "parent_thread_id"] {
                let thread_id = event
                    .payload
                    .get(field)
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !context.seen_threads.contains(thread_id) {
                    bail!("Codex trace-bundle agent result references an unknown {field}");
                }
            }
            set_lifecycle(
                &mut capture,
                "subagent_join",
                "completed",
                &event.payload,
                timestamp.as_deref(),
            );
            capture["traceContext"]["parent_thread_id"] = event
                .payload
                .get("parent_thread_id")
                .cloned()
                .unwrap_or(Value::Null);
            kind = ProjectionKind::Lifecycle;
        }
        "protocol_event_observed" => {
            capture["rolloutEvent"]["projection"] = json!("protocol_event");
            kind = ProjectionKind::Raw;
        }
        "mcp_tool_call_correlation_assigned" => {
            capture["rolloutEvent"]["projection"] = json!("tool_correlation");
            kind = ProjectionKind::Tool;
        }
        "other" => {
            if event.payload.get("kind").and_then(Value::as_str) == Some("tool_registry_snapshot") {
                let registry = inline_runtime_tool_registry(event)?;
                install_tool_registry(context, Some(&registry))?;
                capture["toolRegistry"] = serde_json::to_value(&registry.registry)?;
                capture["toolRegistrySha256"] = json!(registry.sha256);
                capture["rolloutEvent"]["tool_registry_sha256"] =
                    json!(context.tool_registry_sha256);
                capture["rolloutEvent"]["projection"] = json!("tool_registry_snapshot");
            } else {
                capture["rolloutEvent"]["projection"] = json!("other");
            }
        }
        _ => {
            capture["rolloutEvent"]["projection"] = json!("unknown");
        }
    }
    capture["rolloutEvent"]["unmapped_tool"] = json!(unmapped_tool);
    capture["rolloutEvent"]["classification"] = json!(if known { "known" } else { "unknown" });
    if event_type == "rollout_started"
        && let (Some(registry), Some(digest)) = (
            context.tool_registry_snapshot.as_ref(),
            context.tool_registry_sha256.as_deref(),
        )
    {
        capture["toolRegistry"] = registry.clone();
        capture["toolRegistrySha256"] = json!(digest);
    }
    apply_runtime_lineage(&mut capture, event, manifest, context);
    Ok(ProjectedBundleEvent {
        capture,
        kind,
        unknown: !known,
        unmapped_tool,
        bundle_complete: runtime_complete(context),
    })
}

fn projected_tool_schema(pending: &PendingToolContext, name: &str) -> (Option<Value>, Value) {
    let captured = pending.schema.clone();
    let schema = captured
        .clone()
        .filter(|schema| complete_tool_contract(schema, name));
    let provenance = captured
        .as_ref()
        .and_then(|schema| schema.get("schema_provenance"))
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "source":"missing_runtime_registry",
                "source_complete":false,
                "generated_adapter":false,
            })
        });
    (schema, provenance)
}

fn inline_runtime_tool_registry(event: &BundleEvent) -> Result<LoadedToolRegistry> {
    if event.payloads.len() != 1 {
        bail!("tool_registry_snapshot requires exactly one payload");
    }
    let source = event.payloads[0]
        .content
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("tool_registry_snapshot payload must be a JSON object"))?;
    if source.get("schema_version").and_then(Value::as_str)
        != Some("codex.runtime-tool-registry.v1")
        || source.get("producer").and_then(Value::as_str) != Some("codex-cli")
    {
        bail!("unsupported Codex runtime Tool Registry payload");
    }
    let producer_version = source
        .get("producer_version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("runtime Tool Registry producer_version is required"))?;
    let tools = source
        .get("tools")
        .and_then(Value::as_array)
        .filter(|tools| !tools.is_empty())
        .ok_or_else(|| anyhow::anyhow!("runtime Tool Registry tools are required"))?;
    let mut registry = json!({
        "schema_version":"chiptrace.tool-registry.v1",
        "producer":"codex-cli",
        "producer_version":producer_version,
        "tools":tools,
    });
    if let Some(captured_at) = event.wall_time_unix_ms.and_then(format_timestamp) {
        registry["captured_at"] = json!(captured_at);
    }
    load_tool_registry_value(&registry)
}

fn base_capture(
    event: &BundleEvent,
    source_line: &str,
    manifest: &TraceBundleManifest,
    context: &BundleContext,
    config: &BundleExportConfig,
    projection: BaseCaptureProjection<'_>,
) -> Value {
    let capture_id = format!(
        "cap-codex-trace-{}-{:020}",
        &sha256(manifest.trace_id.as_bytes())[..24],
        event.seq
    );
    let native_thread_id = event
        .thread_id
        .as_deref()
        .or_else(|| event.payload.get("thread_id").and_then(Value::as_str));
    let native_turn_id = native_turn_id(event);
    let traceparent = config.traceparent.as_deref();
    let (w3c_trace_id, parent_span_id, trace_flags) = traceparent
        .and_then(traceparent_parts)
        .map(|(_, trace_id, parent_span_id, flags)| {
            (Some(trace_id), Some(parent_span_id), Some(flags))
        })
        .unwrap_or((None, None, None));
    let trace_context = json!({
        "task_session_id":config.task_session_id,
        "session_id":manifest.rollout_id,
        "thread_id":native_thread_id,
        "trace_id":w3c_trace_id,
        "parent_span_id":parent_span_id,
        "trace_flags":trace_flags,
        "traceparent":traceparent,
        "root_session_id":config.root_session_id,
        "parent_session_id":config.parent_session_id,
        "goal_id":config.goal_id,
        "agent_id":config.agent_id,
        "branch_id":config.branch_id,
        "turn_id":native_turn_id,
        "previous_response_id":Value::Null,
        "session_final":false,
    });
    let mut evidence = vec![json!({
        "field":"traceContext.session_id",
        "value":manifest.rollout_id,
        "source":"codex_rollout_trace.manifest.rollout_id",
        "producer":"codex-cli",
        "authority":"runtime_attested",
        "selected":true,
    })];
    if let Some(thread_id) = native_thread_id {
        evidence.push(json!({
            "field":"traceContext.thread_id",
            "value":thread_id,
            "source":"codex_rollout_trace.raw_event.thread_id",
            "producer":"codex-cli",
            "authority":"runtime_attested",
            "selected":true,
        }));
    }
    if let Some(turn_id) = native_turn_id {
        evidence.push(json!({
            "field":"traceContext.turn_id",
            "value":turn_id,
            "source":"codex_rollout_trace.raw_event.codex_turn_id",
            "producer":"codex-cli",
            "authority":"runtime_attested",
            "selected":true,
        }));
    }
    if let Some(task) = config.task_session_id.as_deref() {
        evidence.push(json!({
            "field":"traceContext.task_session_id",
            "value":task,
            "source":"chiptrace_harness.task_session_id",
            "producer":"chiptrace_harness",
            "authority":"producer_asserted",
            "selected":true,
        }));
    }
    if let Some(traceparent) = traceparent {
        evidence.extend([
            json!({
                "field":"traceContext.traceparent",
                "value":traceparent,
                "source":"chiptrace_harness.traceparent",
                "producer":"chiptrace_harness",
                "authority":"producer_asserted",
                "selected":true,
            }),
            json!({
                "field":"traceContext.trace_id",
                "value":w3c_trace_id,
                "source":"chiptrace_harness.traceparent",
                "producer":"chiptrace_harness",
                "authority":"producer_asserted",
                "selected":true,
            }),
        ]);
    }
    let timestamp_value = projection
        .timestamp
        .map(|value| Value::String(value.to_owned()))
        .unwrap_or(Value::Null);
    json!({
        "version":"chiptrace.capture.v2",
        "recordType":"rollout_event",
        "captureId":capture_id,
        "captureStage":"event",
        "sourceNamespace":config.source_namespace,
        "receivedAt":timestamp_value,
        "producerModel":context.current_model,
        "runtimeProvider":context.current_provider,
        "systemPrompt":context.system_prompt,
        "traceContext":trace_context,
        "fieldEvidence":evidence,
        "producerEvent":{
            "schema_version":"chiptrace.producer-event.v1",
            "event_id":format!("codex-trace:{}:{}", manifest.trace_id, event.seq),
            "producer":"codex-rollout-trace",
            "producer_version":"native-bundle-v1",
            "identity_scheme":"source-native",
            "stream_id":format!("codex-trace:{}", manifest.trace_id),
            "sequence":event.seq,
        },
        "rolloutEvent":{
            "schema_version":"chiptrace.codex-rollout.v1",
            "source":CODEX_TRACE_BUNDLE_SOURCE,
            "source_session_id":event.rollout_id,
            "source_ordinal":event.seq,
            "source_cli_version":Value::Null,
            "source_line":source_line,
            "source_line_sha256":sha256(source_line.as_bytes()),
            "raw_event_sha256":sha256(&event.raw_line),
            "raw_event_mirror_path":event.event_mirror_path,
            "bundle_trace_id":manifest.trace_id,
            "bundle_manifest_sha256":Value::Null,
            "bundle_root_thread_id":manifest.root_thread_id,
            "event_type":event.payload.get("type"),
            "thread_id":event.thread_id,
            "codex_turn_id":event.turn_id,
            "classification":if projection.known {"known"} else {"unknown"},
            "projection":"raw",
            "unmapped_tool":false,
            "tool_registry_sha256":context.tool_registry_sha256,
            "payloads":projection.payloads,
        }
    })
}

fn payload_evidence_json(payloads: &[PayloadEvidence]) -> Value {
    Value::Array(
        payloads
            .iter()
            .map(|payload| {
                json!({
                    "raw_payload_id":payload.raw_payload_id,
                    "path":payload.path,
                    "kind":payload.kind,
                    "sha256":payload.sha256,
                    "bytes":payload.bytes.len(),
                    "mirror_path":payload.mirror_path,
                    "raw_json":payload.raw_json,
                })
            })
            .collect(),
    )
}

fn referenced_content<'a>(event: &'a BundleEvent, field: &str) -> Option<&'a Value> {
    let reference = event.payload.get(field)?.as_object()?;
    let id = reference.get("raw_payload_id")?.as_str()?;
    event
        .payloads
        .iter()
        .find(|payload| payload.raw_payload_id == id)
        .and_then(|payload| payload.content.as_ref())
}

fn response_payload_field(event_type: &str) -> &'static str {
    if event_type == "inference_started" {
        "request_payload"
    } else if event_type == "inference_completed" {
        "response_payload"
    } else {
        "partial_response_payload"
    }
}

fn response_body(response: &Value, event: &Map<String, Value>) -> Value {
    let Some(object) = response.as_object() else {
        return response.clone();
    };
    if !object.contains_key("output_items") {
        return response.clone();
    }
    let mut body = object.clone();
    if let Some(items) = object.get("output_items") {
        body.insert("output".to_owned(), items.clone());
    }
    if let Some(id) = event.get("response_id") {
        body.entry("id".to_owned()).or_insert_with(|| id.clone());
    }
    if let Some(usage) = object.get("token_usage") {
        body.entry("usage".to_owned())
            .or_insert_with(|| usage.clone());
    }
    Value::Object(body)
}

fn update_thread_context(event: &BundleEvent, context: &mut BundleContext) -> Result<()> {
    let Some(thread_id) = event
        .payload
        .get("thread_id")
        .and_then(Value::as_str)
        .or(event.thread_id.as_deref())
    else {
        return Ok(());
    };
    let mut thread = ThreadContext::default();
    if let Some(metadata) = referenced_content(event, "metadata_payload") {
        thread.parent_thread_id = metadata
            .pointer("/session_source/subagent/thread_spawn/parent_thread_id")
            .or_else(|| metadata.get("parent_thread_id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        thread.agent_path = metadata
            .get("agent_path")
            .and_then(Value::as_str)
            .map(str::to_owned);
        thread.thread_source = metadata
            .get("session_source")
            .or_else(|| metadata.get("thread_source"))
            .cloned();
        thread.model = metadata
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_owned);
        thread.provider = metadata
            .get("provider_name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        thread.system_prompt = metadata
            .get("base_instructions")
            .or_else(|| metadata.get("system_prompt"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned);
    }
    if thread.agent_path.is_none() {
        thread.agent_path = event
            .payload
            .get("agent_path")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    if thread.model.is_some() {
        context.current_model = thread.model.clone();
    }
    if thread.provider.is_some() {
        context.current_provider = thread.provider.clone();
    }
    if thread.system_prompt.is_some() {
        context.system_prompt = thread.system_prompt.clone();
    }
    context.threads.insert(thread_id.to_owned(), thread);
    trim_context(context);
    Ok(())
}

fn apply_runtime_lineage(
    capture: &mut Value,
    event: &BundleEvent,
    manifest: &TraceBundleManifest,
    context: &BundleContext,
) {
    capture["rolloutEvent"]["bundle_root_thread_id"] = json!(manifest.root_thread_id);
    capture["rolloutEvent"]["bundle_complete"] = json!(runtime_complete(context));
    capture["rolloutEvent"]["open_runtime_objects"] = json!(open_runtime_objects(context));
    let thread_id = event
        .thread_id
        .as_deref()
        .or_else(|| event.payload.get("thread_id").and_then(Value::as_str));
    let Some(thread_id) = thread_id else {
        return;
    };
    let Some(thread) = context.threads.get(thread_id) else {
        return;
    };
    capture["rolloutEvent"]["parent_agent_thread_id"] = json!(thread.parent_thread_id);
    capture["rolloutEvent"]["agent_path"] = json!(thread.agent_path);
    capture["rolloutEvent"]["thread_source"] = thread.thread_source.clone().unwrap_or(Value::Null);
    capture["traceContext"]["parent_thread_id"] = json!(thread.parent_thread_id);
    capture["traceContext"]["agent_path"] = json!(thread.agent_path);
    if let Some(agent_path) = thread.agent_path.as_deref() {
        append_field_evidence(
            capture,
            "traceContext.agent_path",
            agent_path,
            "codex_rollout_trace.thread_metadata.agent_path",
            "runtime_attested",
        );
    }
    if capture.get("producerModel").is_none_or(Value::is_null)
        && let Some(model) = thread.model.as_deref().or(context.current_model.as_deref())
    {
        capture["producerModel"] = json!(model);
    }
    if capture.get("runtimeProvider").is_none_or(Value::is_null)
        && let Some(provider) = thread
            .provider
            .as_deref()
            .or(context.current_provider.as_deref())
    {
        capture["runtimeProvider"] = json!(provider);
    }
    if capture.get("systemPrompt").is_none_or(Value::is_null)
        && let Some(prompt) = thread
            .system_prompt
            .as_deref()
            .or(context.system_prompt.as_deref())
    {
        capture["systemPrompt"] = json!(prompt);
    }
}

fn update_inference_context(event: &BundleEvent, context: &mut BundleContext) -> Result<()> {
    if let Some(model) = event.payload.get("model").and_then(Value::as_str) {
        context.current_model = Some(model.to_owned());
    }
    if let Some(provider) = event.payload.get("provider_name").and_then(Value::as_str) {
        context.current_provider = Some(provider.to_owned());
    }
    if let Some(request) = referenced_content(event, "request_payload") {
        collect_request_tool_schemas(request, context)?;
        if let Some(prompt) = request
            .get("instructions")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            context.system_prompt = Some(prompt.to_owned());
        }
        observe_model_calls(request.get("input"), event.seq, context);
    }
    if let Some(response) = referenced_content(event, "response_payload")
        .or_else(|| referenced_content(event, "partial_response_payload"))
    {
        observe_model_calls(response.get("output_items"), event.seq, context);
    }
    trim_context(context);
    Ok(())
}

fn observe_model_calls(value: Option<&Value>, source_seq: u64, context: &mut BundleContext) {
    let Some(items) = value.and_then(Value::as_array) else {
        return;
    };
    for (index, item) in items.iter().enumerate() {
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
        let observed = if matches!(kind, "function_call" | "custom_tool_call") {
            item.get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .zip(item.get("name").and_then(Value::as_str))
                .map(|(id, name)| {
                    (
                        id,
                        canonical_runtime_tool_name(
                            item.get("namespace").and_then(Value::as_str),
                            name,
                        ),
                    )
                })
        } else if kind == "web_search_call" {
            item.get("id")
                .and_then(Value::as_str)
                .map(|id| (id, "web_search".to_owned()))
        } else {
            None
        };
        if let Some((id, name)) = observed {
            context.model_calls.insert(
                id.to_owned(),
                ModelCallContext {
                    name,
                    source_seq: source_seq.saturating_add(index as u64),
                },
            );
        }
    }
}

fn collect_request_tool_schemas(request: &Value, context: &mut BundleContext) -> Result<()> {
    let mut definitions = Vec::new();
    for field in ["tools", "additional_tools"] {
        if let Some(values) = request.get(field).and_then(Value::as_array) {
            for value in values {
                collect_tool_definitions(value, &mut definitions);
            }
        }
    }
    if let Some(input) = request.get("input").and_then(Value::as_array) {
        for item in input {
            if item.get("type").and_then(Value::as_str) == Some("additional_tools") {
                for field in ["tools", "additional_tools", "definitions"] {
                    if let Some(values) = item.get(field).and_then(Value::as_array) {
                        for value in values {
                            collect_tool_definitions(value, &mut definitions);
                        }
                    }
                }
            }
        }
    }
    for definition in definitions {
        insert_tool_schema(context, definition)?;
    }
    trim_context(context);
    Ok(())
}

fn collect_tool_definitions(value: &Value, output: &mut Vec<Value>) {
    collect_tool_definitions_with_namespace(value, None, output);
}

fn collect_tool_definitions_with_namespace(
    value: &Value,
    inherited_namespace: Option<&str>,
    output: &mut Vec<Value>,
) {
    if let Some(children) = value.get("tools").and_then(Value::as_array)
        && (value.get("parameters").is_none() && value.get("format").is_none())
    {
        let namespace = if value.get("type").and_then(Value::as_str) == Some("namespace") {
            value
                .get("name")
                .and_then(Value::as_str)
                .or(inherited_namespace)
        } else {
            value
                .get("namespace")
                .and_then(Value::as_str)
                .or(inherited_namespace)
        };
        for child in children {
            collect_tool_definitions_with_namespace(child, namespace, output);
        }
        return;
    }
    let nested = value.get("function").unwrap_or(value);
    let Some(runtime_tool) = nested.get("name").and_then(Value::as_str) else {
        return;
    };
    let runtime_namespace = nested
        .get("namespace")
        .or_else(|| value.get("namespace"))
        .and_then(Value::as_str)
        .or(inherited_namespace);
    let name = canonical_runtime_tool_name(runtime_namespace, runtime_tool);
    let description = nested
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let captured_parameters = nested
        .get("parameters")
        .or_else(|| nested.get("input_schema"))
        .cloned();
    let native_format = nested.get("format").cloned();
    let mut captured = json!({
        "name":name.as_str(),
        "description":description,
        "type":value.get("type").and_then(Value::as_str).unwrap_or("function"),
    });
    if let Some(parameters) = captured_parameters.as_ref() {
        captured["parameters"] = parameters.clone();
    }
    if let Some(format) = native_format.as_ref() {
        captured["format"] = format.clone();
    }
    if runtime_tool != name {
        captured["runtime_tool"] = json!(runtime_tool);
    }
    if let Some(namespace) = runtime_namespace {
        captured["runtime_namespace"] = json!(namespace);
    }
    let hash = sha256(serde_json::to_vec(&captured).unwrap_or_default());
    let mut normalized = captured;
    normalized["schema_hash"] = json!(hash);
    normalized["schema_version"] = json!(format!("sha256:{hash}"));
    let generated_adapter = captured_parameters.is_none() && native_format.is_none();
    let source_complete = complete_tool_contract(&normalized, &name);
    normalized["schema_provenance"] = json!({
        "source":if captured_parameters.is_some() {
            "captured_json_schema"
        } else if native_format.is_some() {
            "captured_native_format"
        } else {
            "missing"
        },
        "source_complete":source_complete,
        "generated_adapter":generated_adapter,
    });
    output.push(normalized);
}

fn install_tool_registry(
    context: &mut BundleContext,
    registry: Option<&LoadedToolRegistry>,
) -> Result<()> {
    let Some(registry) = registry else {
        return Ok(());
    };
    let registry_changed = context.tool_registry_sha256.as_deref() != Some(&registry.sha256);
    if registry_changed
        && (!context.pending_tools.is_empty() || !context.deferred_runtime_tools.is_empty())
    {
        bail!("Codex trace-bundle Tool Registry changed while tool calls were pending");
    }
    let snapshot = serde_json::to_value(&registry.registry)?;
    if registry_changed {
        context.tool_schemas.clear();
    }
    context.tool_registry_sha256 = Some(registry.sha256.clone());
    context.tool_registry_snapshot = Some(snapshot);
    for entry in &registry.registry.tools {
        let (name, schema) = projected_registry_schema(registry, entry)?;
        insert_tool_schema(context, schema)?;
        if !context.tool_schemas.contains_key(&name) {
            bail!("failed to install runtime Tool Registry schema {name}");
        }
    }
    Ok(())
}

fn projected_registry_schema(
    registry: &LoadedToolRegistry,
    entry: &ToolRegistryEntry,
) -> Result<(String, Value)> {
    let mut schema = entry.tool.clone();
    let name = registry_entry_identity(entry)?;
    let runtime_tool = entry
        .runtime_tool
        .as_deref()
        .or_else(|| schema.get("name").and_then(Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("Tool Registry entry has no runtime tool name"))?
        .to_owned();
    schema["name"] = json!(name);
    schema["runtime_tool"] = json!(runtime_tool);
    if let Some(namespace) = entry.runtime_namespace.as_deref() {
        schema["runtime_namespace"] = json!(namespace);
    }
    let schema_hash = sha256(serde_json::to_vec(&schema)?);
    let source_complete = complete_tool_contract(&schema, &name);
    schema["schema_hash"] = json!(schema_hash);
    schema["schema_version"] = json!(format!("sha256:{schema_hash}"));
    schema["schema_provenance"] = json!({
        "source":if schema.get("parameters").is_some() {
            "captured_runtime_registry"
        } else if schema.get("format").is_some() {
            "captured_runtime_registry_native_format"
        } else {
            "missing"
        },
        "source_complete":source_complete,
        "registry_sha256":registry.sha256,
        "producer":registry.registry.producer,
        "producer_version":registry.registry.producer_version,
        "runtime_item_type":entry.runtime_item_type,
            "runtime_tool":runtime_tool,
        "runtime_namespace":entry.runtime_namespace,
        "generated_adapter":false,
    });
    Ok((name, schema))
}

fn insert_tool_schema(context: &mut BundleContext, schema: Value) -> Result<()> {
    let name = schema
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("observed tool schema has no name"))?
        .to_owned();
    if let Some(existing) = context.tool_schemas.get(&name) {
        let contract = |value: &Value| {
            json!({
                "name":value.get("name"),
                "description":value.get("description"),
                "parameters":value.get("parameters"),
                "format":value.get("format"),
            })
        };
        if contract(existing) != contract(&schema) {
            bail!("conflicting observed tool schemas for {name}");
        }
        if existing
            .pointer("/schema_provenance/source")
            .and_then(Value::as_str)
            .is_some_and(|source| source.starts_with("captured_runtime_registry"))
        {
            return Ok(());
        }
    }
    context.tool_schemas.insert(name, schema);
    Ok(())
}

fn start_tool_context(
    event: &BundleEvent,
    context: &mut BundleContext,
    timestamp: Option<&str>,
) -> Result<(Option<PendingToolContext>, RuntimeCorrelation)> {
    let call_id = event
        .payload
        .get("tool_call_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if call_id.is_empty() {
        return Ok((None, RuntimeCorrelation::MissingCallId));
    }
    if context.pending_tools.contains_key(call_id) {
        bail!("duplicate Codex trace-bundle tool start for {call_id}");
    }
    let invocation = referenced_content(event, "invocation_payload").cloned();
    let runtime_tool = invocation
        .as_ref()
        .and_then(|value| value.get("tool_name"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            event
                .payload
                .get("kind")
                .and_then(kind_tool_name)
                .map(str::to_owned)
        });
    let runtime_namespace = invocation
        .as_ref()
        .and_then(|value| value.get("tool_namespace"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    let name = runtime_tool.as_deref().map(|runtime_tool| {
        canonical_runtime_tool_name(runtime_namespace.as_deref(), runtime_tool)
    });
    let expected_kind_name = event.payload.get("kind").and_then(kind_tool_name);
    let requester = event.payload.get("requester");
    let requester_type = requester.and_then(|value| {
        value
            .as_str()
            .or_else(|| value.get("type").and_then(Value::as_str))
    });
    let initiator = if matches!(requester_type, Some("model" | "code_cell")) {
        "assistant"
    } else {
        "runtime"
    };
    let model_visible_call_id = event
        .payload
        .get("model_visible_call_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let code_mode_runtime_tool_id = event
        .payload
        .get("code_mode_runtime_tool_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let parent_call_id = requester
        .and_then(|value| value.get("runtime_cell_id"))
        .and_then(Value::as_str)
        .and_then(|cell_id| context.code_cells.get(cell_id))
        .map(|cell| cell.model_visible_call_id.clone());
    let schema = name
        .as_deref()
        .and_then(|name| context.tool_schemas.get(name).cloned());
    let kind_matches = expected_kind_name
        .zip(runtime_tool.as_deref())
        .is_none_or(|(expected, observed)| tool_kind_matches(expected, observed));
    let mut lineage_matched = match requester_type {
        Some("model") => model_visible_call_id.is_some(),
        Some("code_cell") => code_mode_runtime_tool_id.is_some() && parent_call_id.is_some(),
        _ => true,
    };
    let correlation = if name.is_none() || !kind_matches {
        RuntimeCorrelation::ToolNameMismatch
    } else if schema.is_none() {
        RuntimeCorrelation::MissingRegistry
    } else if !lineage_matched {
        RuntimeCorrelation::MissingModelCall
    } else if requester_type == Some("model") {
        match model_visible_call_id
            .as_deref()
            .and_then(|id| context.model_calls.get(id))
        {
            None => {
                lineage_matched = false;
                RuntimeCorrelation::MissingModelCall
            }
            Some(call) if name.as_deref() != Some(call.name.as_str()) => {
                lineage_matched = false;
                RuntimeCorrelation::ToolNameMismatch
            }
            Some(_) => RuntimeCorrelation::Matched,
        }
    } else {
        RuntimeCorrelation::Matched
    };
    let pending = PendingToolContext {
        name,
        runtime_tool,
        runtime_namespace,
        initiator: initiator.to_owned(),
        model_visible_call_id,
        code_mode_runtime_tool_id,
        parent_call_id,
        lineage_matched,
        schema,
        invocation,
        started_seq: event.seq,
        started_at: timestamp.map(str::to_owned),
        runtime_status: None,
    };
    context
        .pending_tools
        .insert(call_id.to_owned(), pending.clone());
    trim_context(context);
    Ok((Some(pending), correlation))
}

fn kind_tool_name(value: &Value) -> Option<&str> {
    let object = value.as_object()?;
    match object.get("type").and_then(Value::as_str) {
        Some("mcp") => object.get("tool").and_then(Value::as_str),
        Some("other") => object.get("name").and_then(Value::as_str),
        Some(name) => Some(name),
        None => None,
    }
}

fn tool_kind_matches(expected: &str, observed: &str) -> bool {
    match expected {
        "web" => matches!(observed, "web_search" | "web_search_preview"),
        "image_generation" => matches!(observed, "image_generation" | "image_query" | "imagegen"),
        "assign_agent_task" => matches!(observed, "followup_task" | "assign_task"),
        "close_agent" => matches!(observed, "close_agent" | "interrupt_agent"),
        other => other == observed,
    }
}

fn invocation_arguments(invocation: Option<&Value>) -> Value {
    let Some(invocation) = invocation else {
        return Value::Null;
    };
    let payload = invocation.get("payload").unwrap_or(invocation);
    match payload.get("type").and_then(Value::as_str) {
        Some("function") => payload.get("arguments").cloned().unwrap_or(Value::Null),
        Some("custom") => json!({
            "input":payload.get("input").cloned().unwrap_or(Value::Null)
        }),
        Some("tool_search") => payload.get("arguments").cloned().unwrap_or(Value::Null),
        Some("local_shell") => payload.clone(),
        _ => payload.clone(),
    }
}

fn tool_result_content(result: &Value) -> Value {
    match result.get("type").and_then(Value::as_str) {
        Some("direct_response") => result
            .get("response_item")
            .and_then(|item| item.get("output").or_else(|| item.get("content")))
            .cloned()
            .unwrap_or_else(|| result.get("response_item").cloned().unwrap_or(Value::Null)),
        Some("code_mode_response") => result.get("value").cloned().unwrap_or(Value::Null),
        Some("error") => result
            .get("error")
            .cloned()
            .unwrap_or_else(|| result.clone()),
        _ => result.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeCorrelation {
    Matched,
    MissingRegistry,
    MissingModelCall,
    ToolNameMismatch,
    MissingCallId,
}

impl RuntimeCorrelation {
    fn label(self) -> &'static str {
        match self {
            Self::Matched => "matched_model_call",
            Self::MissingRegistry => "missing_registry",
            Self::MissingModelCall => "missing_model_call",
            Self::ToolNameMismatch => "tool_name_mismatch",
            Self::MissingCallId => "missing_call_id",
        }
    }
}

fn set_lifecycle(
    capture: &mut Value,
    event_type: &str,
    status: &str,
    source: &Map<String, Value>,
    timestamp: Option<&str>,
) {
    capture["lifecycleEvent"] = json!({
        "event_id":capture["producerEvent"]["event_id"],
        "type":event_type,
        "status":status,
        "reason":source.get("reason"),
        "occurred_at":timestamp,
        "source_event":source,
    });
    capture["observedLifecycleEvents"] = json!([event_type]);
    capture["rolloutEvent"]["projection"] = json!("lifecycle");
}

fn append_field_evidence(
    capture: &mut Value,
    field: &str,
    value: &str,
    source: &str,
    authority: &str,
) {
    let item = json!({
        "field":field,
        "value":value,
        "source":source,
        "producer":"codex-cli",
        "authority":authority,
        "selected":true,
    });
    if let Some(items) = capture["fieldEvidence"].as_array_mut() {
        items.push(item);
    }
}

fn update_summary(summary: &mut BundleExportSummary, event: &ProjectedBundleEvent) {
    if event
        .capture
        .pointer("/rolloutEvent/projection")
        .and_then(Value::as_str)
        == Some("tool_registry_snapshot")
    {
        summary.tool_registry_snapshots += 1;
    }
    match event.kind {
        ProjectionKind::Lifecycle => summary.lifecycle_events += 1,
        ProjectionKind::Inference => summary.inference_events += 1,
        ProjectionKind::Tool => {
            if event
                .capture
                .pointer("/toolExecution/status")
                .and_then(Value::as_str)
                .is_some_and(|status| status != "started")
            {
                summary.tool_executions += 1;
            }
        }
        ProjectionKind::Raw => {}
    }
    summary.unknown_events += u64::from(event.unknown);
    summary.unmapped_tool_events += u64::from(event.unmapped_tool);
}

fn known_event_type(value: &str) -> bool {
    matches!(
        value,
        "rollout_started"
            | "rollout_ended"
            | "thread_started"
            | "thread_ended"
            | "codex_turn_started"
            | "codex_turn_ended"
            | "inference_started"
            | "inference_completed"
            | "inference_failed"
            | "inference_cancelled"
            | "tool_call_started"
            | "mcp_tool_call_correlation_assigned"
            | "tool_call_runtime_started"
            | "tool_call_runtime_ended"
            | "tool_call_ended"
            | "code_cell_started"
            | "code_cell_initial_response"
            | "code_cell_ended"
            | "compaction_request_started"
            | "compaction_request_completed"
            | "compaction_request_failed"
            | "compaction_installed"
            | "agent_result_observed"
            | "protocol_event_observed"
            | "other"
    )
}

fn execution_status(value: Option<&str>) -> &'static str {
    match value.map(|value| value.trim().to_ascii_lowercase()) {
        Some(value) if matches!(value.as_str(), "completed" | "complete" | "success" | "ok") => {
            "completed"
        }
        Some(value) if matches!(value.as_str(), "failed" | "failure" | "error") => "failed",
        Some(value) if matches!(value.as_str(), "cancelled" | "canceled" | "aborted") => {
            "cancelled"
        }
        Some(value) if value == "terminated" => "terminated",
        _ => "incomplete",
    }
}

fn normalize_tool_status(value: &str) -> &'static str {
    match value.trim().to_ascii_lowercase().as_str() {
        "completed" | "complete" | "success" | "succeeded" | "ok" => "success",
        "failed" | "failure" | "error" | "errored" => "error",
        "cancelled" | "canceled" | "aborted" => "cancelled",
        "timeout" | "timed_out" => "timeout",
        _ => "unknown",
    }
}

fn complete_tool_contract(schema: &Value, expected_name: &str) -> bool {
    tool_definition_source_complete(schema, expected_name)
}

fn native_turn_id(event: &BundleEvent) -> Option<&str> {
    event
        .payload
        .get("codex_turn_id")
        .and_then(Value::as_str)
        .or(event.turn_id.as_deref())
}

fn open_runtime_objects(context: &BundleContext) -> u64 {
    (context.active_threads.len()
        + context.active_turns.len()
        + context.active_inferences.len()
        + context.pending_tools.len()
        + context.deferred_runtime_tools.len()
        + context.active_code_cells.len()
        + context.active_compactions.len()) as u64
}

fn runtime_complete(context: &BundleContext) -> bool {
    context.rollout_started
        && context.rollout_ended
        && context.rollout_terminal
        && context.root_thread_started
        && context.root_thread_ended
        && open_runtime_objects(context) == 0
}

fn reconcile_checkpoint_context(context: &mut BundleContext, manifest: &TraceBundleManifest) {
    context.seen_threads.extend(context.threads.keys().cloned());
    context
        .seen_turns
        .extend(context.active_turns.iter().cloned());
    context
        .seen_inferences
        .extend(context.active_inferences.iter().cloned());
    context
        .seen_tools
        .extend(context.pending_tools.keys().cloned());
    context
        .seen_tools
        .extend(context.deferred_runtime_tools.iter().cloned());
    context
        .seen_code_cells
        .extend(context.code_cells.keys().cloned());
    context
        .seen_compactions
        .extend(context.active_compactions.iter().cloned());
    if context.threads.contains_key(&manifest.root_thread_id) {
        context.root_thread_started = true;
        if !context.active_threads.contains(&manifest.root_thread_id) {
            context.root_thread_ended = true;
        }
    }
}

fn trim_context(context: &mut BundleContext) {
    while context.threads.len()
        + context.model_calls.len()
        + context.tool_schemas.len()
        + context.pending_tools.len()
        + context.deferred_runtime_tools.len()
        + context.code_cells.len()
        > MAX_CONTEXT_ENTRIES
    {
        if let Some(key) = context
            .model_calls
            .iter()
            .min_by_key(|(_, value)| value.source_seq)
            .map(|(key, _)| key.clone())
        {
            context.model_calls.remove(&key);
            continue;
        }
        if let Some(key) = context
            .pending_tools
            .iter()
            .min_by_key(|(_, value)| value.started_seq)
            .map(|(key, _)| key.clone())
        {
            context.pending_tools.remove(&key);
            continue;
        }
        if let Some(key) = context
            .code_cells
            .iter()
            .filter(|(key, _)| !context.active_code_cells.contains(*key))
            .min_by_key(|(_, value)| value.started_seq)
            .map(|(key, _)| key.clone())
        {
            context.code_cells.remove(&key);
            continue;
        }
        break;
    }
}

fn config_fingerprint(
    config: &BundleExportConfig,
    tool_registry: Option<&LoadedToolRegistry>,
) -> String {
    let target = match &config.target {
        DeliveryTarget::Relay(url) => json!({"kind":"relay","value":url}),
        DeliveryTarget::ProducerRelay { base, .. } => {
            json!({"kind":"producer-relay","value":base})
        }
        DeliveryTarget::Jsonl(path) => {
            json!({"kind":"jsonl","value":path.to_string_lossy()})
        }
    };
    let value = json!({
        "source_namespace":config.source_namespace,
        "task_session_id":config.task_session_id,
        "root_session_id":config.root_session_id,
        "parent_session_id":config.parent_session_id,
        "goal_id":config.goal_id,
        "agent_id":config.agent_id,
        "branch_id":config.branch_id,
        "traceparent":config.traceparent,
        "tool_registry_sha256":tool_registry.map(|registry| registry.sha256.as_str()),
        "target":target,
        "mirror_root":config.mirror_root,
    });
    sha256(serde_json::to_vec(&value).unwrap_or_default())
}

fn validate_traceparent(value: &str) -> Result<()> {
    let Some((version, trace_id, parent_span_id, flags)) = traceparent_parts(value) else {
        bail!("traceparent must follow W3C version-trace-parent-flags format");
    };
    if version != "00"
        || trace_id.bytes().all(|byte| byte == b'0')
        || parent_span_id.bytes().all(|byte| byte == b'0')
        || flags.len() != 2
    {
        bail!("traceparent contains an unsupported version or zero identifier");
    }
    Ok(())
}

fn traceparent_parts(value: &str) -> Option<(&str, &str, &str, &str)> {
    let mut parts = value.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let parent_span_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some()
        || version.len() != 2
        || trace_id.len() != 32
        || parent_span_id.len() != 16
        || flags.len() != 2
        || ![version, trace_id, parent_span_id, flags]
            .into_iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return None;
    }
    Some((version, trace_id, parent_span_id, flags))
}

fn verify_checkpoint(path: &Path, checkpoint: &BundleCheckpoint) -> Result<Sha256> {
    let metadata = fs::metadata(path)?;
    if checkpoint.committed_offset > metadata.len() {
        bail!("Codex trace bundle was truncated after the last checkpoint");
    }
    let mut prefix_hasher = Sha256::new();
    let mut prefix = File::open(path)?;
    let mut remaining = checkpoint.committed_offset;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = prefix.read(&mut buffer[..limit])?;
        if read == 0 {
            bail!("Codex trace bundle ended before the committed checkpoint");
        }
        prefix_hasher.update(&buffer[..read]);
        remaining = remaining.saturating_sub(read as u64);
    }
    let observed_prefix = hex::encode(prefix_hasher.clone().finalize());
    if !checkpoint.committed_prefix_sha256.is_empty()
        && observed_prefix != checkpoint.committed_prefix_sha256
    {
        bail!("Codex trace bundle committed prefix changed");
    }
    if checkpoint.last_line_bytes == 0 || checkpoint.last_line_sha256.is_empty() {
        return Ok(prefix_hasher);
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(checkpoint.last_line_start))?;
    let mut bytes = vec![0_u8; checkpoint.last_line_bytes as usize];
    file.read_exact(&mut bytes)?;
    if sha256(&bytes) != checkpoint.last_line_sha256 {
        bail!("Codex trace bundle bytes before the checkpoint changed");
    }
    Ok(prefix_hasher)
}

fn safe_existing_path(
    root: &Path,
    relative: &Path,
    expected_parent: Option<&Path>,
) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    let root = root
        .canonicalize()
        .with_context(|| format!("resolve bundle root {}", root.display()))?;
    let path = root.join(relative);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolve bundle path {}", relative.display()))?;
    if !canonical.starts_with(&root) {
        bail!(
            "Codex trace-bundle path escapes bundle root: {}",
            relative.display()
        );
    }
    if let Some(expected_parent) = expected_parent {
        let parent = expected_parent
            .canonicalize()
            .with_context(|| format!("resolve payload root {}", expected_parent.display()))?;
        if !canonical.starts_with(&parent) {
            bail!("Codex trace-bundle payload path escapes payloads_dir");
        }
    }
    if !canonical.is_file() && expected_parent.is_none() && relative.extension().is_some() {
        bail!(
            "Codex trace-bundle path is not a regular file: {}",
            relative.display()
        );
    }
    Ok(canonical)
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.is_absolute() {
        bail!("Codex trace-bundle path must be relative");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("Codex trace-bundle path contains an unsafe component")
            }
        }
    }
    Ok(())
}

fn mirror_bytes(
    mirror_root: &Path,
    trace_id: &str,
    category: &str,
    name: &str,
    bytes: &[u8],
) -> Result<String> {
    let trace_component = safe_component(trace_id)?;
    let category_component = safe_component(category)?;
    let name_component = safe_component(name)?;
    let mirror_reference = format!("{trace_component}/{category_component}/{name_component}");
    let directory = mirror_root.join(trace_component).join(category_component);
    fs::create_dir_all(&directory)?;
    let destination = directory.join(&name_component);
    if destination.exists() {
        let existing = fs::read(&destination)?;
        if existing != bytes {
            bail!(
                "raw trace mirror digest collision at {}",
                destination.display()
            );
        }
        return Ok(mirror_reference);
    }
    let temporary = directory.join(format!(
        ".{}.tmp-{}-{}",
        name_component,
        std::process::id(),
        unique_suffix(bytes)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &destination)?;
    Ok(mirror_reference)
}

fn safe_component(value: &str) -> Result<String> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("unsafe trace mirror path component");
    }
    Ok(value.to_owned())
}

fn unique_suffix(bytes: &[u8]) -> String {
    sha256(bytes)[..16].to_owned()
}

fn validate_optional_id(value: Option<&str>, field: &str) -> Result<()> {
    if let Some(value) = value
        && (value.trim().is_empty()
            || value.len() > 256
            || value.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
            }))
    {
        bail!("{field} must be a safe non-empty identifier");
    }
    Ok(())
}

fn format_timestamp(milliseconds: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(milliseconds) * 1_000_000)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path, output: &Path) -> BundleExportConfig {
        BundleExportConfig {
            input: root.join("bundle"),
            state_root: root.join("state"),
            target: BundleExportTarget::Jsonl(output.to_owned()),
            source_namespace: "relay-18084".to_owned(),
            tool_registry: None,
            batch_records: 2,
            max_envelope_bytes: 8 * 1024 * 1024,
            request_timeout: Duration::from_secs(1),
            retry_max_times: 20,
            task_session_id: Some("task-1".to_owned()),
            root_session_id: Some("root-task-1".to_owned()),
            parent_session_id: None,
            goal_id: Some("goal-1".to_owned()),
            agent_id: Some("agent-root".to_owned()),
            branch_id: Some("branch-1".to_owned()),
            traceparent: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_owned()),
            mirror_root: None,
            require_complete: true,
        }
    }

    fn write_payload(root: &Path, ordinal: u64, value: Value) -> String {
        let path = root.join("bundle/payloads").join(format!("{ordinal}.json"));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        format!("payloads/{ordinal}.json")
    }

    fn event(seq: u64, payload: Value, thread: Option<&str>, turn: Option<&str>) -> Value {
        json!({
            "schema_version":1,
            "seq":seq,
            "wall_time_unix_ms":1787961600000_i64 + seq as i64,
            "rollout_id":"rollout-1",
            "thread_id":thread,
            "codex_turn_id":turn,
            "payload":payload,
        })
    }

    fn write_minimal_complete_bundle(root: &Path) {
        fs::create_dir_all(root.join("bundle/payloads")).unwrap();
        let manifest = json!({
            "schema_version":1,
            "trace_id":"trace-1",
            "rollout_id":"rollout-1",
            "root_thread_id":"thread-1",
            "started_at_unix_ms":1787961600000_i64,
            "raw_event_log":"trace.jsonl",
            "payloads_dir":"payloads"
        });
        fs::write(
            root.join("bundle/manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let events = [
            event(
                1,
                json!({"type":"rollout_started","trace_id":"trace-1","root_thread_id":"thread-1"}),
                None,
                None,
            ),
            event(
                2,
                json!({"type":"thread_started","thread_id":"thread-1","agent_path":"/root"}),
                None,
                None,
            ),
            event(
                3,
                json!({"type":"thread_ended","thread_id":"thread-1","status":"completed"}),
                None,
                None,
            ),
            event(
                4,
                json!({"type":"rollout_ended","status":"completed"}),
                None,
                None,
            ),
        ];
        let trace = events
            .iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(root.join("bundle/trace.jsonl"), trace).unwrap();
    }

    fn write_bundle_events(root: &Path, events: &[Value]) {
        fs::create_dir_all(root.join("bundle/payloads")).unwrap();
        let manifest = json!({
            "schema_version":1,
            "trace_id":"trace-1",
            "rollout_id":"rollout-1",
            "root_thread_id":"thread-1",
            "started_at_unix_ms":1787961600000_i64,
            "raw_event_log":"trace.jsonl",
            "payloads_dir":"payloads"
        });
        fs::write(
            root.join("bundle/manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let trace = events
            .iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(root.join("bundle/trace.jsonl"), trace).unwrap();
    }

    #[tokio::test]
    async fn capture_bytes_do_not_depend_on_mirror_storage_root() {
        let temp = tempfile::tempdir().unwrap();
        write_minimal_complete_bundle(temp.path());
        let first_output = temp.path().join("first.jsonl");
        let second_output = temp.path().join("second.jsonl");

        export_codex_trace_bundle(config(temp.path(), &first_output))
            .await
            .unwrap();
        let mut second = config(temp.path(), &second_output);
        second.state_root = temp.path().join("second-state");
        second.mirror_root = Some(temp.path().join("second-mirror"));
        export_codex_trace_bundle(second).await.unwrap();

        assert_eq!(
            fs::read_to_string(first_output).unwrap(),
            fs::read_to_string(second_output).unwrap()
        );
        let first: Value = serde_json::from_str(
            fs::read_to_string(temp.path().join("first.jsonl"))
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            first["rolloutEvent"]["bundle_manifest_mirror_path"],
            "trace-1/manifest/manifest.json"
        );
        assert!(
            !first["rolloutEvent"]["raw_event_mirror_path"]
                .as_str()
                .unwrap()
                .starts_with('/')
        );
    }

    #[tokio::test]
    async fn imports_native_bundle_and_preserves_payload_hashes_and_status() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("bundle/payloads")).unwrap();
        let request_path = write_payload(
            temp.path(),
            1,
            json!({
                "model":"gpt-5.6-sol",
                "instructions":"system prompt",
                "input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"run"}]}],
                "tools":[{"type":"function","name":"lookup","description":"Look up a value.","parameters":{"type":"object","properties":{"key":{"type":"string","description":"Lookup key."}},"required":["key"]}}]
            }),
        );
        let invocation_path = write_payload(
            temp.path(),
            2,
            json!({"tool_name":"lookup","payload":{"type":"function","arguments":"{\"key\":\"a\"}"}}),
        );
        let result_path = write_payload(temp.path(), 3, json!({"value":"found"}));
        let response_path = write_payload(
            temp.path(),
            4,
            json!({"response_id":"resp-1","token_usage":{"input_tokens":10,"output_tokens":3},"output_items":[{"type":"function_call","call_id":"call-1","name":"lookup","arguments":"{\"key\":\"a\"}"}]}),
        );
        let events = vec![
            event(
                1,
                json!({"type":"rollout_started","trace_id":"trace-1","root_thread_id":"thread-1"}),
                None,
                None,
            ),
            event(
                2,
                json!({"type":"thread_started","thread_id":"thread-1","agent_path":"/root","metadata_payload":{"raw_payload_id":"meta-1","kind":{"type":"session_metadata"},"path":"payloads/1.json"}}),
                Some("thread-1"),
                None,
            ),
            event(
                3,
                json!({"type":"codex_turn_started","codex_turn_id":"turn-1","thread_id":"thread-1"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                4,
                json!({"type":"inference_started","inference_call_id":"inf-1","thread_id":"thread-1","codex_turn_id":"turn-1","model":"gpt-5.6-sol","provider_name":"openai","request_payload":{"raw_payload_id":"req-1","kind":{"type":"inference_request"},"path":request_path}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                5,
                json!({"type":"inference_completed","inference_call_id":"inf-1","response_id":"resp-1","response_payload":{"raw_payload_id":"resp-1","kind":{"type":"inference_response"},"path":response_path}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                6,
                json!({"type":"tool_call_started","tool_call_id":"tool-1","model_visible_call_id":"call-1","requester":{"type":"model"},"kind":{"type":"mcp","server":"x","tool":"lookup"},"summary":{"type":"generic","label":"lookup"},"invocation_payload":{"raw_payload_id":"inv-1","kind":{"type":"tool_invocation"},"path":invocation_path}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                7,
                json!({"type":"tool_call_ended","tool_call_id":"tool-1","status":"completed","result_payload":{"raw_payload_id":"res-1","kind":{"type":"tool_result"},"path":result_path}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                8,
                json!({"type":"codex_turn_ended","codex_turn_id":"turn-1","status":"completed"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                9,
                json!({"type":"thread_ended","thread_id":"thread-1","status":"completed"}),
                Some("thread-1"),
                None,
            ),
            event(
                10,
                json!({"type":"rollout_ended","status":"completed"}),
                None,
                None,
            ),
        ];
        let manifest = json!({"schema_version":1,"trace_id":"trace-1","rollout_id":"rollout-1","root_thread_id":"thread-1","started_at_unix_ms":1787961600000_i64,"raw_event_log":"trace.jsonl","payloads_dir":"payloads"});
        fs::write(
            temp.path().join("bundle/manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let mut trace = String::new();
        for value in events {
            trace.push_str(&serde_json::to_string(&value).unwrap());
            trace.push('\n');
        }
        fs::write(temp.path().join("bundle/trace.jsonl"), trace).unwrap();
        let output = temp.path().join("captures.jsonl");
        let summary = export_codex_trace_bundle(config(temp.path(), &output))
            .await
            .unwrap();
        assert_eq!(summary.lines_read, 10);
        assert_eq!(summary.tool_executions, 1);
        assert!(summary.bundle_complete);
        assert_eq!(summary.open_tail_bytes, 0);
        let records: Vec<Value> = fs::read_to_string(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let tool = records
            .iter()
            .find(|record| {
                record
                    .pointer("/toolExecution/status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| status != "started")
            })
            .unwrap();
        assert_eq!(tool["toolExecution"]["status"], "success");
        assert_eq!(tool["toolExecution"]["model_call_matched"], true);
        assert_eq!(tool["traceContext"]["task_session_id"], "task-1");
        assert_eq!(tool["traceContext"]["session_id"], "rollout-1");
        assert_eq!(tool["traceContext"]["thread_id"], "thread-1");
        assert_eq!(
            tool["traceContext"]["trace_id"],
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(tool["rolloutEvent"]["bundle_trace_id"], "trace-1");
        assert_eq!(tool["rolloutEvent"]["source"], CODEX_TRACE_BUNDLE_SOURCE);
        assert!(
            tool["rolloutEvent"]["payloads"][0]["sha256"]
                .as_str()
                .unwrap()
                .len()
                == 64
        );
        assert!(
            temp.path()
                .join("state/raw-bundles/trace-1/events")
                .is_dir()
        );
        assert!(
            temp.path()
                .join("state/raw-bundles/trace-1/payloads")
                .is_dir()
        );
        let second = export_codex_trace_bundle(config(temp.path(), &output))
            .await
            .unwrap();
        assert_eq!(second.captures_emitted, 0);
    }

    #[tokio::test]
    async fn imports_code_mode_subagent_compaction_failure_and_cancel() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("bundle/payloads")).unwrap();
        let root_metadata = write_payload(
            temp.path(),
            1,
            json!({
                "thread_id":"thread-1",
                "agent_path":"/root",
                "session_source":"cli",
                "model":"gpt-5.6-sol",
                "provider_name":"openai"
            }),
        );
        let child_metadata = write_payload(
            temp.path(),
            2,
            json!({
                "thread_id":"thread-2",
                "agent_path":"/root/worker",
                "session_source":{"subagent":{"thread_spawn":{
                    "parent_thread_id":"thread-1",
                    "agent_path":"/root/worker",
                    "agent_role":"worker"
                }}},
                "model":"gpt-5.6-sol",
                "provider_name":"openai"
            }),
        );
        let inference_request = write_payload(
            temp.path(),
            3,
            json!({
                "model":"gpt-5.6-sol",
                "instructions":"system prompt",
                "input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"inspect"}]}],
                "tools":[
                    {"type":"custom","name":"exec","description":"Execute tool code.","format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}},
                    {"type":"function","name":"lookup","description":"Look up a value.","parameters":{"type":"object","properties":{"key":{"type":"string","description":"Lookup key."}},"required":["key"]}}
                ]
            }),
        );
        let inference_response = write_payload(
            temp.path(),
            4,
            json!({
                "response_id":"response-1",
                "token_usage":{"input_tokens":100,"cached_input_tokens":80,"output_tokens":20},
                "output_items":[{"type":"custom_tool_call","call_id":"exec-1","name":"exec","input":"tools.lookup({key:'x'})"}]
            }),
        );
        let invocation = write_payload(
            temp.path(),
            5,
            json!({"tool_name":"lookup","payload":{"type":"function","arguments":"{\"key\":\"x\"}"}}),
        );
        let runtime_started = write_payload(temp.path(), 6, json!({"phase":"started"}));
        let runtime_ended = write_payload(temp.path(), 7, json!({"phase":"ended","exit_code":1}));
        let tool_result = write_payload(
            temp.path(),
            8,
            json!({"type":"error","error":"backend unavailable"}),
        );
        let compaction_request = write_payload(
            temp.path(),
            9,
            json!({"input":[{"role":"user","content":"history"}]}),
        );
        let partial_response =
            write_payload(temp.path(), 10, json!({"output_items":[],"partial":true}));
        let agent_result = write_payload(
            temp.path(),
            11,
            json!({"status":"completed","message":"done"}),
        );

        let events = vec![
            event(
                1,
                json!({"type":"rollout_started","trace_id":"trace-1","root_thread_id":"thread-1"}),
                None,
                None,
            ),
            event(
                2,
                json!({"type":"thread_started","thread_id":"thread-1","agent_path":"/root","metadata_payload":{"raw_payload_id":"meta-root","kind":{"type":"session_metadata"},"path":root_metadata}}),
                None,
                None,
            ),
            event(
                3,
                json!({"type":"codex_turn_started","codex_turn_id":"turn-1","thread_id":"thread-1"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                4,
                json!({"type":"inference_started","inference_call_id":"inference-1","thread_id":"thread-1","codex_turn_id":"turn-1","model":"gpt-5.6-sol","provider_name":"openai","request_payload":{"raw_payload_id":"request-1","kind":{"type":"inference_request"},"path":inference_request}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                5,
                json!({"type":"inference_completed","inference_call_id":"inference-1","response_id":"response-1","response_payload":{"raw_payload_id":"response-1","kind":{"type":"inference_response"},"path":inference_response}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                6,
                json!({"type":"code_cell_started","runtime_cell_id":"cell-1","model_visible_call_id":"exec-1","source_js":"tools.lookup({key:'x'})"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                7,
                json!({"type":"code_cell_initial_response","runtime_cell_id":"cell-1","status":"yielded"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                8,
                json!({"type":"tool_call_started","tool_call_id":"tool-1","model_visible_call_id":null,"code_mode_runtime_tool_id":"runtime-tool-1","requester":{"type":"code_cell","runtime_cell_id":"cell-1"},"kind":{"type":"other","name":"lookup"},"summary":{"type":"generic","label":"lookup"},"invocation_payload":{"raw_payload_id":"tool-request-1","kind":{"type":"tool_invocation"},"path":invocation}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                9,
                json!({"type":"tool_call_runtime_started","tool_call_id":"tool-1","runtime_payload":{"raw_payload_id":"runtime-start-1","kind":{"type":"tool_runtime"},"path":runtime_started}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                10,
                json!({"type":"tool_call_runtime_ended","tool_call_id":"tool-1","status":"failed","runtime_payload":{"raw_payload_id":"runtime-end-1","kind":{"type":"tool_runtime"},"path":runtime_ended}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                11,
                // The wrapper completed, but the dispatcher runtime reported
                // the real tool failure at seq 10.
                json!({"type":"tool_call_ended","tool_call_id":"tool-1","status":"completed","result_payload":{"raw_payload_id":"tool-result-1","kind":{"type":"tool_result"},"path":tool_result}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                12,
                json!({"type":"code_cell_ended","runtime_cell_id":"cell-1","status":"failed"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                13,
                json!({"type":"compaction_request_started","compaction_id":"compaction-1","compaction_request_id":"compaction-request-1","thread_id":"thread-1","codex_turn_id":"turn-1","model":"gpt-5.6-sol","provider_name":"openai","request_payload":{"raw_payload_id":"compaction-request-1","kind":{"type":"compaction_request"},"path":compaction_request}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                14,
                json!({"type":"compaction_request_failed","compaction_id":"compaction-1","compaction_request_id":"compaction-request-1","error":"compaction failed"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                15,
                json!({"type":"inference_started","inference_call_id":"inference-2","thread_id":"thread-1","codex_turn_id":"turn-1","model":"gpt-5.6-sol","provider_name":"openai","request_payload":{"raw_payload_id":"request-2","kind":{"type":"inference_request"},"path":inference_request}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                16,
                json!({"type":"inference_cancelled","inference_call_id":"inference-2","reason":"user_cancelled","partial_response_payload":{"raw_payload_id":"partial-2","kind":{"type":"inference_response"},"path":partial_response}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                17,
                json!({"type":"thread_started","thread_id":"thread-2","agent_path":"/root/worker","metadata_payload":{"raw_payload_id":"meta-child","kind":{"type":"session_metadata"},"path":child_metadata}}),
                None,
                None,
            ),
            event(
                18,
                json!({"type":"codex_turn_started","codex_turn_id":"turn-2","thread_id":"thread-2"}),
                Some("thread-2"),
                Some("turn-2"),
            ),
            event(
                19,
                json!({"type":"codex_turn_ended","codex_turn_id":"turn-2","status":"completed"}),
                Some("thread-2"),
                Some("turn-2"),
            ),
            event(
                20,
                json!({"type":"thread_ended","thread_id":"thread-2","status":"completed"}),
                None,
                None,
            ),
            event(
                21,
                json!({"type":"agent_result_observed","edge_id":"edge-1","child_thread_id":"thread-2","child_codex_turn_id":"turn-2","parent_thread_id":"thread-1","message":"done","carried_payload":{"raw_payload_id":"agent-result-1","kind":{"type":"agent_result"},"path":agent_result}}),
                Some("thread-2"),
                Some("turn-2"),
            ),
            event(
                22,
                json!({"type":"codex_turn_ended","codex_turn_id":"turn-1","status":"completed"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                23,
                json!({"type":"thread_ended","thread_id":"thread-1","status":"completed"}),
                None,
                None,
            ),
            event(
                24,
                json!({"type":"rollout_ended","status":"completed"}),
                None,
                None,
            ),
        ];
        write_bundle_events(temp.path(), &events);
        let output = temp.path().join("captures.jsonl");
        let summary = export_codex_trace_bundle(config(temp.path(), &output))
            .await
            .unwrap();
        assert!(summary.bundle_complete);
        assert_eq!(summary.open_runtime_objects, 0);
        assert_eq!(summary.tool_executions, 1);
        assert_eq!(summary.unmapped_tool_events, 0);
        assert_eq!(summary.unknown_events, 0);
        let records: Vec<Value> = fs::read_to_string(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let tool = records
            .iter()
            .find(|record| {
                record
                    .pointer("/toolExecution/status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| status != "started")
            })
            .unwrap();
        assert_eq!(tool["toolExecution"]["name"], "lookup");
        assert_eq!(tool["toolExecution"]["status"], "error");
        assert_eq!(tool["toolExecution"]["parent_call_id"], "exec-1");
        assert_eq!(tool["toolExecution"]["initiator"], "assistant");
        let child = records
            .iter()
            .find(|record| record["rolloutEvent"]["agent_path"] == "/root/worker")
            .unwrap();
        assert_eq!(child["rolloutEvent"]["parent_agent_thread_id"], "thread-1");
        assert!(records.iter().any(|record| {
            record.pointer("/lifecycleEvent/type") == Some(&json!("inference_end"))
                && record.pointer("/lifecycleEvent/status") == Some(&json!("cancelled"))
        }));
        assert!(records.iter().any(|record| {
            record.pointer("/lifecycleEvent/type") == Some(&json!("compaction"))
                && record.pointer("/lifecycleEvent/status") == Some(&json!("failed"))
        }));
        assert!(records.iter().all(|record| {
            record.pointer("/traceContext/session_id") == Some(&json!("rollout-1"))
        }));
    }

    #[tokio::test]
    async fn runtime_registry_promotes_inner_tool_schema_without_fabrication() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("bundle/payloads")).unwrap();
        let request = write_payload(
            temp.path(),
            1,
            json!({
                "model":"gpt-5.6-sol",
                "input":[{"type":"message","role":"user","content":"run"}],
                "tools":[{"type":"custom","name":"exec","description":"Execute tool code.","format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}}]
            }),
        );
        let response = write_payload(
            temp.path(),
            2,
            json!({
                "response_id":"response-1",
                "output_items":[{"type":"custom_tool_call","call_id":"exec-1","name":"exec","input":"tools.exec_command({cmd:'true'})"}]
            }),
        );
        let invocation = write_payload(
            temp.path(),
            3,
            json!({"tool_name":"exec_command","payload":{"type":"function","arguments":"{\"cmd\":\"true\"}"}}),
        );
        let result = write_payload(
            temp.path(),
            4,
            json!({"type":"code_mode_response","value":{"exit_code":0,"output":""}}),
        );
        let runtime_started = write_payload(
            temp.path(),
            5,
            json!({"process_id":"42","status":"running"}),
        );
        let runtime_ended = write_payload(
            temp.path(),
            6,
            json!({"process_id":"42","status":"completed","exit_code":0}),
        );
        let events = vec![
            event(
                1,
                json!({"type":"rollout_started","trace_id":"trace-1","root_thread_id":"thread-1"}),
                None,
                None,
            ),
            event(
                2,
                json!({"type":"thread_started","thread_id":"thread-1","agent_path":"/root"}),
                None,
                None,
            ),
            event(
                3,
                json!({"type":"codex_turn_started","codex_turn_id":"turn-1","thread_id":"thread-1"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                4,
                json!({"type":"inference_started","inference_call_id":"inference-1","thread_id":"thread-1","codex_turn_id":"turn-1","model":"gpt-5.6-sol","provider_name":"openai","request_payload":{"raw_payload_id":"request-1","kind":{"type":"inference_request"},"path":request}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                5,
                json!({"type":"inference_completed","inference_call_id":"inference-1","response_payload":{"raw_payload_id":"response-1","kind":{"type":"inference_response"},"path":response}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                6,
                json!({"type":"code_cell_started","runtime_cell_id":"cell-1","model_visible_call_id":"exec-1","source_js":"tools.exec_command({cmd:'true'})"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                7,
                json!({"type":"tool_call_started","tool_call_id":"tool-1","model_visible_call_id":null,"code_mode_runtime_tool_id":"runtime-tool-1","requester":{"type":"code_cell","runtime_cell_id":"cell-1"},"kind":{"type":"exec_command"},"summary":{"type":"generic","label":"exec_command"},"invocation_payload":{"raw_payload_id":"invocation-1","kind":{"type":"tool_invocation"},"path":invocation}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                8,
                json!({"type":"tool_call_runtime_started","tool_call_id":"tool-1","runtime_payload":{"raw_payload_id":"runtime-start-1","kind":{"type":"tool_runtime_event"},"path":runtime_started}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                9,
                json!({"type":"tool_call_ended","tool_call_id":"tool-1","status":"completed","result_payload":{"raw_payload_id":"result-1","kind":{"type":"tool_result"},"path":result}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                10,
                json!({"type":"tool_call_runtime_ended","tool_call_id":"tool-1","status":"completed","runtime_payload":{"raw_payload_id":"runtime-end-1","kind":{"type":"tool_runtime_event"},"path":runtime_ended}}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                11,
                json!({"type":"code_cell_ended","runtime_cell_id":"cell-1","status":"completed"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                12,
                json!({"type":"codex_turn_ended","codex_turn_id":"turn-1","status":"completed"}),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                13,
                json!({"type":"thread_ended","thread_id":"thread-1","status":"completed"}),
                None,
                None,
            ),
            event(
                14,
                json!({"type":"rollout_ended","status":"completed"}),
                None,
                None,
            ),
        ];
        write_bundle_events(temp.path(), &events);

        let output_without = temp.path().join("without-registry.jsonl");
        let without = export_codex_trace_bundle(config(temp.path(), &output_without))
            .await
            .unwrap();
        assert_eq!(without.tool_executions, 1);
        assert_eq!(without.unmapped_tool_events, 2);
        let tool_without: Value = fs::read_to_string(&output_without)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .find(|record: &Value| {
                record
                    .pointer("/toolExecution/status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| status != "started")
            })
            .unwrap();
        assert!(tool_without["toolExecution"]["schema"].is_null());
        assert_eq!(
            tool_without["toolExecution"]["schema_provenance"]["source"],
            "missing_runtime_registry"
        );

        let registry_path = temp.path().join("tool-registry.json");
        let registry = json!({
            "schema_version":"chiptrace.tool-registry.v1",
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "captured_at":"2026-08-29T00:00:00Z",
            "tools":[{"runtime_item_type":"CommandExecution","runtime_tool":"exec_command","tool":{
                "name":"exec_command",
                "description":"Execute a shell command.",
                "parameters":{"type":"object","properties":{"cmd":{"type":"string","description":"Command to execute."}},"required":["cmd"]}
            }}]
        });
        fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
        let output_with = temp.path().join("with-registry.jsonl");
        let mut with_config = config(temp.path(), &output_with);
        with_config.state_root = temp.path().join("registry-state");
        with_config.tool_registry = Some(registry_path);
        let with = export_codex_trace_bundle(with_config).await.unwrap();
        assert_eq!(with.tool_executions, 1);
        assert_eq!(with.unmapped_tool_events, 0);
        let records: Vec<Value> = fs::read_to_string(&output_with)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let tool = records
            .iter()
            .find(|record| {
                record
                    .pointer("/toolExecution/status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| status != "started")
            })
            .unwrap();
        assert_eq!(tool["toolExecution"]["schema"]["name"], "exec_command");
        assert_eq!(
            tool["toolExecution"]["schema"]["schema_provenance"]["source"],
            "captured_runtime_registry"
        );
        assert!(records.iter().any(|record| {
            record["rolloutEvent"]["runtime_call_correlation"] == "deferred_runtime_completion"
                && record["runtimeToolObservation"]["deferred_completion"] == true
        }));
        let start = records
            .iter()
            .find(|record| record["rolloutEvent"]["event_type"] == "rollout_started")
            .unwrap();
        assert_eq!(start["toolRegistry"], registry);
        assert_eq!(
            start["toolRegistrySha256"],
            start["rolloutEvent"]["tool_registry_sha256"]
        );
    }

    #[tokio::test]
    async fn native_bundle_installs_inline_runtime_registry_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("bundle/payloads")).unwrap();
        let registry_payload = write_payload(
            temp.path(),
            1,
            json!({
                "schema_version":"codex.runtime-tool-registry.v1",
                "producer":"codex-cli",
                "producer_version":"0.150.0-alpha.9",
                "tools":[
                    {"runtime_item_type":"function","runtime_tool":"exec_command","tool":{
                        "name":"exec_command","description":"Execute a command.",
                        "parameters":{"type":"object","properties":{
                            "cmd":{"type":"string","description":"Command to execute."},
                            "cwd":{"type":"string"}
                        },"required":["cmd"]}
                    }},
                    {"runtime_item_type":"custom","runtime_tool":"apply_patch","tool":{
                        "name":"apply_patch","description":"Apply a patch.",
                        "format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}
                    }}
                ]
            }),
        );
        let events = vec![
            event(
                1,
                json!({"type":"rollout_started","trace_id":"trace-1","root_thread_id":"thread-1"}),
                None,
                None,
            ),
            event(
                2,
                json!({"type":"thread_started","thread_id":"thread-1","agent_path":"/root"}),
                None,
                None,
            ),
            event(
                3,
                json!({
                    "type":"other",
                    "kind":"tool_registry_snapshot",
                    "summary":"Runtime tool registry snapshot",
                    "payloads":[{"raw_payload_id":"registry-1","kind":{"type":"protocol_event"},"path":registry_payload}],
                    "metadata":{"scope":"dispatcher"}
                }),
                Some("thread-1"),
                Some("turn-1"),
            ),
            event(
                4,
                json!({"type":"thread_ended","thread_id":"thread-1","status":"completed"}),
                None,
                None,
            ),
            event(
                5,
                json!({"type":"rollout_ended","status":"completed"}),
                None,
                None,
            ),
        ];
        write_bundle_events(temp.path(), &events);
        let output = temp.path().join("captures.jsonl");
        let summary = export_codex_trace_bundle(config(temp.path(), &output))
            .await
            .unwrap();
        assert_eq!(summary.tool_registry_snapshots, 1);
        let snapshot: Value = fs::read_to_string(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .find(|record: &Value| {
                record.pointer("/rolloutEvent/projection") == Some(&json!("tool_registry_snapshot"))
            })
            .unwrap();
        assert_eq!(
            snapshot["toolRegistry"]["tools"].as_array().unwrap().len(),
            2
        );
        assert!(
            snapshot["toolRegistry"]["tools"][1]["tool"]
                .get("parameters")
                .is_none()
        );
        assert_eq!(
            snapshot["toolRegistrySha256"],
            snapshot["rolloutEvent"]["tool_registry_sha256"]
        );
        assert_eq!(
            snapshot["toolRegistry"]["captured_at"],
            format_timestamp(1787961600003_i64).unwrap()
        );
    }

    #[test]
    fn request_native_format_matches_runtime_registry_without_fabrication() {
        let format = json!({
            "type":"grammar",
            "syntax":"lark",
            "definition":"start: /.+/"
        });
        let registry = load_tool_registry_value(&json!({
            "schema_version":"chiptrace.tool-registry.v1",
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[{"runtime_item_type":"custom","runtime_tool":"exec",
                "runtime_namespace":"functions","tool":{
                    "type":"custom",
                    "name":"exec",
                    "description":"Execute tool code.",
                    "format":format
                }
            }]
        }))
        .unwrap();
        let mut context = BundleContext::default();
        install_tool_registry(&mut context, Some(&registry)).unwrap();

        collect_request_tool_schemas(
            &json!({
                "input":[{"type":"additional_tools","role":"developer","tools":[{
                    "type":"namespace",
                    "name":"functions",
                    "description":"",
                    "tools":[{
                        "type":"custom",
                        "name":"exec",
                        "description":"Execute tool code.",
                        "format":format
                    }]
                }]}]
            }),
            &mut context,
        )
        .unwrap();

        assert_eq!(context.tool_schemas.len(), 1);
        let schema = &context.tool_schemas["exec"];
        assert!(schema.get("parameters").is_none());
        assert_eq!(schema["format"], format);
        assert_eq!(
            schema["schema_provenance"]["source"],
            "captured_runtime_registry_native_format"
        );
        assert_eq!(schema["schema_provenance"]["source_complete"], true);
        assert_eq!(schema["schema_provenance"]["generated_adapter"], false);
        assert!(complete_tool_contract(schema, "exec"));
        assert!(schema.get("parameters").is_none());
    }

    #[test]
    fn runtime_registry_switches_atomically_and_preserves_namespaces() {
        let definition = || {
            json!({
                "name":"lookup",
                "description":"Look up one value.",
                "parameters":{"type":"object","properties":{}}
            })
        };
        let first = load_tool_registry_value(&json!({
            "schema_version":"chiptrace.tool-registry.v1",
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[
                {"runtime_item_type":"function","runtime_tool":"lookup",
                 "runtime_namespace":"catalog","tool":definition()},
                {"runtime_item_type":"function","runtime_tool":"lookup",
                 "runtime_namespace":"symbols","tool":definition()}
            ]
        }))
        .unwrap();
        let second = load_tool_registry_value(&json!({
            "schema_version":"chiptrace.tool-registry.v1",
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[{"runtime_item_type":"function","runtime_tool":"compile","tool":{
                "name":"compile","description":"Compile one target.",
                "parameters":{"type":"object","properties":{}}
            }}]
        }))
        .unwrap();
        let mut context = BundleContext::default();
        install_tool_registry(&mut context, Some(&first)).unwrap();
        assert_eq!(
            context.tool_schemas.keys().cloned().collect::<Vec<_>>(),
            vec!["catalog.lookup", "symbols.lookup"]
        );
        assert_eq!(
            context.tool_schemas["catalog.lookup"]["runtime_namespace"],
            "catalog"
        );

        install_tool_registry(&mut context, Some(&second)).unwrap();
        assert_eq!(
            context.tool_schemas.keys().cloned().collect::<Vec<_>>(),
            vec!["compile"]
        );

        context.pending_tools.insert(
            "call-open".to_owned(),
            PendingToolContext {
                name: Some("compile".to_owned()),
                runtime_tool: Some("compile".to_owned()),
                runtime_namespace: None,
                initiator: "assistant".to_owned(),
                model_visible_call_id: Some("call-open".to_owned()),
                code_mode_runtime_tool_id: None,
                parent_call_id: None,
                lineage_matched: true,
                schema: context.tool_schemas.get("compile").cloned(),
                invocation: Some(json!({})),
                started_seq: 1,
                started_at: None,
                runtime_status: None,
            },
        );
        let error = install_tool_registry(&mut context, Some(&first)).unwrap_err();
        assert!(error.to_string().contains("while tool calls were pending"));
        assert_eq!(
            context.tool_registry_sha256.as_deref(),
            Some(second.sha256.as_str())
        );
    }

    #[tokio::test]
    async fn rejects_sequence_gaps_and_payload_traversal_without_advancing_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("bundle/payloads")).unwrap();
        let manifest = json!({"schema_version":1,"trace_id":"trace-1","rollout_id":"rollout-1","root_thread_id":"thread-1","started_at_unix_ms":1,"raw_event_log":"trace.jsonl","payloads_dir":"payloads"});
        fs::write(
            temp.path().join("bundle/manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let bad = event(2, json!({"type":"rollout_started"}), None, None);
        fs::write(
            temp.path().join("bundle/trace.jsonl"),
            format!("{}\n", serde_json::to_string(&bad).unwrap()),
        )
        .unwrap();
        let output = temp.path().join("captures.jsonl");
        let error = export_codex_trace_bundle(config(temp.path(), &output))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("seq gap"));
        let started = event(
            1,
            json!({"type":"rollout_started","trace_id":"trace-1","root_thread_id":"thread-1"}),
            None,
            None,
        );
        let traversal = event(
            2,
            json!({"type":"protocol_event_observed","event_type":"item_completed","event_payload":{"raw_payload_id":"x","kind":null,"path":"../secret"}}),
            None,
            None,
        );
        fs::write(
            temp.path().join("bundle/trace.jsonl"),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&started).unwrap(),
                serde_json::to_string(&traversal).unwrap()
            ),
        )
        .unwrap();
        let error = export_codex_trace_bundle(config(temp.path(), &output))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unsafe") || error.to_string().contains("escapes"));
    }

    #[tokio::test]
    async fn checkpoint_rejects_configuration_drift() {
        let temp = tempfile::tempdir().unwrap();
        write_minimal_complete_bundle(temp.path());
        let output = temp.path().join("captures.jsonl");
        export_codex_trace_bundle(config(temp.path(), &output))
            .await
            .unwrap();

        let mut changed = config(temp.path(), &output);
        changed.source_namespace = "different-namespace".to_owned();
        let error = export_codex_trace_bundle(changed).await.unwrap_err();
        assert!(error.to_string().contains("configuration changed"));
    }

    #[tokio::test]
    async fn checkpoint_rejects_rewritten_committed_prefix() {
        let temp = tempfile::tempdir().unwrap();
        write_minimal_complete_bundle(temp.path());
        let output = temp.path().join("captures.jsonl");
        export_codex_trace_bundle(config(temp.path(), &output))
            .await
            .unwrap();

        let trace_path = temp.path().join("bundle/trace.jsonl");
        let trace = fs::read_to_string(&trace_path).unwrap();
        let rewritten = trace.replacen("\"trace_id\":\"trace-1\"", "\"trace_id\":\"trace-2\"", 1);
        assert_eq!(trace.len(), rewritten.len());
        fs::write(trace_path, rewritten).unwrap();

        let error = export_codex_trace_bundle(config(temp.path(), &output))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("committed prefix changed"));
    }

    #[tokio::test]
    async fn rejects_known_events_with_missing_fields_or_unpaired_lifecycle() {
        let malformed = tempfile::tempdir().unwrap();
        write_bundle_events(
            malformed.path(),
            &[
                event(
                    1,
                    json!({"type":"rollout_started","trace_id":"trace-1","root_thread_id":"thread-1"}),
                    None,
                    None,
                ),
                event(
                    2,
                    json!({"type":"inference_started","inference_call_id":"inference-1"}),
                    None,
                    None,
                ),
            ],
        );
        let output = malformed.path().join("captures.jsonl");
        let error = export_codex_trace_bundle(config(malformed.path(), &output))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("inference_started.thread_id"));

        let unpaired = tempfile::tempdir().unwrap();
        write_bundle_events(
            unpaired.path(),
            &[
                event(
                    1,
                    json!({"type":"rollout_started","trace_id":"trace-1","root_thread_id":"thread-1"}),
                    None,
                    None,
                ),
                event(
                    2,
                    json!({"type":"thread_ended","thread_id":"thread-1","status":"completed"}),
                    None,
                    None,
                ),
            ],
        );
        let output = unpaired.path().join("captures.jsonl");
        let error = export_codex_trace_bundle(config(unpaired.path(), &output))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no matching start"));
    }

    #[test]
    fn safe_path_rejects_parent_and_absolute_components() {
        assert!(validate_relative_path(Path::new("../payloads/1.json")).is_err());
        assert!(validate_relative_path(Path::new("/tmp/payloads/1.json")).is_err());
        assert!(validate_relative_path(Path::new("payloads/1.json")).is_ok());
    }
}
