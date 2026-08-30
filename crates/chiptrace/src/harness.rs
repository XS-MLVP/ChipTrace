//! Producer-side task harness for complete, evidence-backed traces.
//!
//! The HTTP gateway can only observe model network traffic.  This module is
//! intentionally used by the task runner and the tool dispatcher so task
//! boundaries, real tool state transitions, and evaluator evidence are
//! recorded at their source.  Events are appended to a local durable spool
//! before any network delivery is attempted.  A byte checkpoint advances only
//! after a complete Relay acknowledgement, so a crash or a lost response is
//! recovered by replaying the same deterministic Capture IDs.

use crate::delivery::{DeliveryConfig, DeliveryTarget, deliver_batch};
use crate::producer::{
    DETERMINISTIC_CAPTURE_IDENTITY, PRODUCER_EVENT_SCHEMA_VERSION, prepare_producer_capture,
};
use crate::tool_registry::{
    canonical_runtime_tool_name, canonical_tool_registry_sha256, canonical_tool_schema_sha256,
    tool_definition_source_complete, validate_tool_registry_value,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const HARNESS_SCHEMA_VERSION: &str = "chiptrace.harness-session.v1";
pub const DEFAULT_PRODUCER: &str = "chiptrace-harness";
pub const DEFAULT_PRODUCER_VERSION: &str = env!("CARGO_PKG_VERSION");
const STATE_FILE: &str = "session.json";
const SPOOL_FILE: &str = "events.ndjson";
const LOCK_FILE: &str = ".session.lock";
const DEFAULT_MAX_ENVELOPE_BYTES: usize = 1024 * 1024 * 1024;
const DEFAULT_RETRY_MAX_TIMES: usize = 25;
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A delivery target persisted with the harness session.  `Relay` always
/// means the producer endpoint (`/producer/events`), never the raw API route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value")]
pub enum HarnessTarget {
    Relay(String),
    Jsonl(PathBuf),
}

#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub state_root: PathBuf,
    pub source_namespace: String,
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
    pub target: Option<HarnessTarget>,
    pub tool_registry: Option<Value>,
    pub producer: String,
    pub producer_version: String,
    pub retry_max_times: usize,
    pub request_timeout: Duration,
    pub max_envelope_bytes: usize,
    pub batch_records: usize,
}

impl HarnessConfig {
    pub fn new(state_root: PathBuf, source_namespace: impl Into<String>) -> Self {
        Self {
            state_root,
            source_namespace: source_namespace.into(),
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
            target: None,
            tool_registry: None,
            producer: DEFAULT_PRODUCER.to_owned(),
            producer_version: DEFAULT_PRODUCER_VERSION.to_owned(),
            retry_max_times: DEFAULT_RETRY_MAX_TIMES,
            request_timeout: Duration::from_secs(30),
            max_envelope_bytes: DEFAULT_MAX_ENVELOPE_BYTES,
            batch_records: 128,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HarnessIdentity {
    pub task_session_id: String,
    pub root_session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    pub traceparent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecycleEventInput {
    pub event_type: String,
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub details: Option<Value>,
    #[serde(default)]
    pub occurred_at: Option<String>,
}

impl LifecycleEventInput {
    pub fn new(event_type: impl Into<String>, status: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            status: status.into(),
            reason: None,
            turn_id: None,
            details: None,
            occurred_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolStartInput {
    pub call_id: String,
    /// Runtime name as registered by the dispatcher. When a namespace is
    /// present, the canonical Session name becomes `namespace.name`.
    pub name: String,
    #[serde(default)]
    pub runtime_namespace: Option<String>,
    #[serde(default)]
    pub runtime_tool: Option<String>,
    pub arguments: Value,
    #[serde(default)]
    pub schema: Option<Value>,
    #[serde(default)]
    pub parent_call_id: Option<String>,
    #[serde(default = "default_initiator")]
    pub initiator: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
}

fn default_initiator() -> String {
    "assistant".to_owned()
}

impl ToolStartInput {
    pub fn assistant(
        call_id: impl Into<String>,
        name: impl Into<String>,
        arguments: Value,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            name: name.into(),
            runtime_namespace: None,
            runtime_tool: None,
            arguments,
            schema: None,
            parent_call_id: None,
            initiator: "assistant".to_owned(),
            turn_id: None,
            started_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolEndInput {
    pub call_id: String,
    pub status: String,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<Value>,
    #[serde(default)]
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationInput {
    pub kind: String,
    pub source: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub passed: Option<bool>,
    #[serde(default)]
    pub reward: Option<f64>,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub artifact: Option<Value>,
    #[serde(default)]
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventReceipt {
    pub capture_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub local_durable: bool,
    pub pending_records: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlushSummary {
    pub records_attempted: u64,
    pub records_durable: u64,
    pub duplicates: u64,
    pub pending_records: u64,
    pub spool_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HarnessInspection {
    pub schema_version: String,
    pub state_root: String,
    pub source_namespace: String,
    pub task_session_id: String,
    pub root_session_id: String,
    pub status: String,
    pub target: Option<HarnessTarget>,
    pub emitted_events: u64,
    pub delivered_events: u64,
    pub pending_records: u64,
    pub spool_bytes: u64,
    pub checkpoint_offset: u64,
    pub recovered_tail_bytes: u64,
    pub next_sequences: BTreeMap<String, u64>,
    pub active_tool_calls: Vec<String>,
    pub correlation_headers: BTreeMap<String, String>,
    pub last_delivery_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveTool {
    call_id: String,
    name: String,
    #[serde(default)]
    runtime_namespace: Option<String>,
    #[serde(default)]
    runtime_tool: Option<String>,
    arguments: Value,
    schema: Option<Value>,
    schema_provenance: Option<Value>,
    parent_call_id: Option<String>,
    initiator: String,
    turn_id: Option<String>,
    started_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HarnessState {
    schema_version: String,
    source_namespace: String,
    identity: HarnessIdentity,
    target: Option<HarnessTarget>,
    producer: String,
    producer_version: String,
    retry_max_times: usize,
    request_timeout_ms: u64,
    max_envelope_bytes: usize,
    batch_records: usize,
    spool_file: String,
    spool_offset: u64,
    emitted_events: u64,
    delivered_events: u64,
    streams: BTreeMap<String, u64>,
    status: String,
    started_at: String,
    ended_at: Option<String>,
    last_delivery_error: Option<String>,
    #[serde(default)]
    recovered_tail_bytes: u64,
    tool_registry: Option<Value>,
    tool_registry_sha256: Option<String>,
    active_tools: BTreeMap<String, ActiveTool>,
}

/// A live producer harness.  One process owns the session lock at a time;
/// the lock is released on drop and stale locks from crashed processes are
/// recoverable on Linux.
pub struct Harness {
    root: PathBuf,
    state: HarnessState,
    lock: Option<SessionLock>,
}

struct SessionLock {
    _file: File,
    path: PathBuf,
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Harness {
    pub fn start(mut config: HarnessConfig) -> Result<Self> {
        validate_config(&config)?;
        fs::create_dir_all(&config.state_root)?;
        config.state_root = config.state_root.canonicalize().with_context(|| {
            format!("resolve harness state root {}", config.state_root.display())
        })?;
        let lock = acquire_lock(&config.state_root)?;
        let state_path = config.state_root.join(STATE_FILE);
        if state_path.exists() {
            drop(lock);
            bail!("harness session already exists: {}", state_path.display());
        }
        let task_session_id = config
            .task_session_id
            .take()
            .unwrap_or_else(|| generated_id("task"));
        validate_identifier(&task_session_id, "task_session_id")?;
        let root_session_id = config
            .root_session_id
            .take()
            .unwrap_or_else(|| task_session_id.clone());
        validate_identifier(&root_session_id, "root_session_id")?;
        let traceparent = config
            .traceparent
            .take()
            .unwrap_or_else(generated_traceparent);
        validate_traceparent(&traceparent)?;
        let registry_hash = if let Some(registry) = config.tool_registry.as_ref() {
            validate_tool_registry_value(registry)?;
            Some(canonical_tool_registry_sha256(registry)?)
        } else {
            None
        };
        let started_at = now_rfc3339()?;
        let identity = HarnessIdentity {
            task_session_id: task_session_id.clone(),
            root_session_id,
            parent_session_id: config.parent_session_id.take(),
            goal_id: config.goal_id.take(),
            agent_id: config.agent_id.take(),
            branch_id: config.branch_id.take(),
            session_id: config.session_id.take(),
            thread_id: config.thread_id.take(),
            previous_response_id: config.previous_response_id.take(),
            traceparent,
        };
        validate_identity(&identity)?;
        for (field, value) in [
            ("source_namespace", config.source_namespace.as_str()),
            ("producer", config.producer.as_str()),
            ("producer_version", config.producer_version.as_str()),
        ] {
            validate_identifier(value, field)?;
        }
        let mut streams = BTreeMap::new();
        streams.insert(harness_stream(&task_session_id), 0);
        streams.insert(dispatcher_stream(&task_session_id), 0);
        streams.insert(evaluator_stream(&task_session_id), 0);
        let target = normalize_target(config.target)?;
        validate_target(&target, &config.state_root.join(SPOOL_FILE))?;
        let state = HarnessState {
            schema_version: HARNESS_SCHEMA_VERSION.to_owned(),
            source_namespace: config.source_namespace,
            identity,
            target,
            producer: config.producer,
            producer_version: config.producer_version,
            retry_max_times: config.retry_max_times,
            request_timeout_ms: config.request_timeout.as_millis().min(u64::MAX as u128) as u64,
            max_envelope_bytes: config.max_envelope_bytes,
            batch_records: config.batch_records,
            spool_file: SPOOL_FILE.to_owned(),
            spool_offset: 0,
            emitted_events: 0,
            delivered_events: 0,
            streams,
            status: "open".to_owned(),
            started_at,
            ended_at: None,
            last_delivery_error: None,
            recovered_tail_bytes: 0,
            tool_registry: config.tool_registry,
            tool_registry_sha256: registry_hash,
            active_tools: BTreeMap::new(),
        };
        let mut harness = Self {
            root: config.state_root,
            state,
            lock: Some(lock),
        };
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(harness.spool_path())?
            .sync_all()?;
        harness.persist_state()?;
        // A task boundary is a producer fact and is emitted before the
        // caller can make a model request.  Delivery is intentionally left to
        // `flush`; local durability is the business-safe acknowledgement.
        harness.emit_lifecycle(LifecycleEventInput::new("task_start", "started"))?;
        Ok(harness)
    }

    pub fn open(state_root: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_target(state_root.into(), None)
    }

    pub fn open_with_target(
        state_root: impl Into<PathBuf>,
        target: Option<HarnessTarget>,
    ) -> Result<Self> {
        let requested_root = state_root.into();
        let root = requested_root
            .canonicalize()
            .with_context(|| format!("resolve harness state root {}", requested_root.display()))?;
        let lock = acquire_lock(&root)?;
        let state_path = root.join(STATE_FILE);
        let mut state: HarnessState = match fs::read(&state_path)
            .with_context(|| format!("read harness state {}", state_path.display()))
            .and_then(|bytes| serde_json::from_slice(&bytes).context("parse harness state"))
        {
            Ok(state) => state,
            Err(error) => {
                drop(lock);
                return Err(error);
            }
        };
        state.target = normalize_target(state.target)?;
        let mut harness = Self {
            root,
            state,
            lock: Some(lock),
        };
        validate_state(&harness.state)?;
        if let Some(target) = target {
            let requested =
                normalize_target(Some(target))?.expect("target normalization preserved target");
            if let Some(persisted) = harness.state.target.as_ref() {
                if persisted != &requested {
                    bail!(
                        "harness delivery target does not match persisted task target; use an explicit migration instead of splitting one task across sinks"
                    );
                }
            } else {
                harness.state.target = Some(requested);
            }
        }
        validate_target(&harness.state.target, &harness.spool_path())?;
        harness.reconcile_spool()?;
        harness.persist_state()?;
        Ok(harness)
    }

    pub fn identity(&self) -> &HarnessIdentity {
        &self.state.identity
    }

    pub fn task_session_id(&self) -> &str {
        &self.state.identity.task_session_id
    }

    pub fn source_namespace(&self) -> &str {
        &self.state.source_namespace
    }

    pub fn set_previous_response_id(&mut self, value: Option<String>) -> Result<()> {
        if let Some(value) = value.as_deref() {
            validate_identifier(value, "previous_response_id")?;
        }
        self.state.identity.previous_response_id = value;
        self.persist_state()
    }

    pub fn emit_lifecycle(&mut self, input: LifecycleEventInput) -> Result<EventReceipt> {
        validate_nonempty(&input.event_type, "lifecycle event type")?;
        validate_nonempty(&input.status, "lifecycle event status")?;
        if input.event_type.len() > 128 {
            bail!("lifecycle event type is too long");
        }
        if let Some(turn_id) = input.turn_id.as_deref() {
            validate_identifier(turn_id, "lifecycle turn_id")?;
        }
        self.ensure_open_for_event(&input.event_type)?;
        let occurred_at = input.occurred_at.clone().unwrap_or(now_rfc3339()?);
        validate_rfc3339(&occurred_at, "lifecycle occurred_at")?;
        let is_task_start = input.event_type_is_task_start();
        let event_id_hint = self.next_event_id("harness")?;
        let mut event = json!({
            "recordType":"lifecycle_event",
            "sourceNamespace":self.state.source_namespace,
            "traceContext":self.trace_context(input.turn_id.as_deref()),
            "receivedAt":occurred_at,
            "producerEvent":self.producer_event(
                event_id_hint.event_id.clone(),
                harness_stream(self.task_session_id()),
                event_id_hint.sequence,
            ),
            "lifecycleEvent":{
                "event_id":event_id_hint.event_id.clone(),
                "type":input.event_type.clone(),
                "status":input.status.clone(),
                "occurred_at":occurred_at,
            }
        });
        if let Some(reason) = input.reason {
            event["lifecycleEvent"]["reason"] = json!(reason);
        }
        if let Some(details) = input.details {
            event["lifecycleEvent"]["details"] = details;
        }
        if is_task_start && let Some(registry) = self.state.tool_registry.clone() {
            event["toolRegistry"] = registry;
            event["toolRegistrySha256"] = json!(self.state.tool_registry_sha256);
        }
        let receipt = self.append_event(event, "harness", event_id_hint.sequence)?;
        if is_terminal_lifecycle(&input.event_type) {
            self.state.status = "closed".to_owned();
            self.state.ended_at = Some(occurred_at);
            self.persist_state()?;
        }
        Ok(receipt)
    }

    pub fn task_end(
        &mut self,
        status: impl Into<String>,
        reason: Option<String>,
    ) -> Result<EventReceipt> {
        self.emit_lifecycle(LifecycleEventInput {
            event_type: "task_end".to_owned(),
            status: status.into(),
            reason,
            turn_id: None,
            details: None,
            occurred_at: None,
        })
    }

    pub fn cancel(&mut self, reason: Option<String>) -> Result<EventReceipt> {
        self.emit_lifecycle(LifecycleEventInput {
            event_type: "cancel".to_owned(),
            status: "cancelled".to_owned(),
            reason,
            turn_id: None,
            details: None,
            occurred_at: None,
        })
    }

    pub fn retry(
        &mut self,
        reason: Option<String>,
        turn_id: Option<String>,
    ) -> Result<EventReceipt> {
        self.emit_lifecycle(LifecycleEventInput {
            event_type: "retry".to_owned(),
            status: "retrying".to_owned(),
            reason,
            turn_id,
            details: None,
            occurred_at: None,
        })
    }

    pub fn compaction(
        &mut self,
        details: Option<Value>,
        turn_id: Option<String>,
    ) -> Result<EventReceipt> {
        self.emit_lifecycle(LifecycleEventInput {
            event_type: "compaction".to_owned(),
            status: "completed".to_owned(),
            reason: None,
            turn_id,
            details,
            occurred_at: None,
        })
    }

    pub fn subagent_spawn(
        &mut self,
        child_task_session_id: impl Into<String>,
        child_agent_id: Option<String>,
        child_branch_id: Option<String>,
    ) -> Result<EventReceipt> {
        let child_task_session_id = child_task_session_id.into();
        validate_identifier(&child_task_session_id, "child_task_session_id")?;
        if let Some(value) = child_agent_id.as_deref() {
            validate_identifier(value, "child_agent_id")?;
        }
        if let Some(value) = child_branch_id.as_deref() {
            validate_identifier(value, "child_branch_id")?;
        }
        self.emit_lifecycle(LifecycleEventInput {
            event_type: "subagent_spawn".to_owned(),
            status: "started".to_owned(),
            reason: None,
            turn_id: None,
            details: Some(json!({
                "child_task_session_id":child_task_session_id,
                "child_agent_id":child_agent_id,
                "child_branch_id":child_branch_id,
                "parent_task_session_id":self.task_session_id(),
            })),
            occurred_at: None,
        })
    }

    pub fn subagent_join(
        &mut self,
        child_task_session_id: impl Into<String>,
        status: impl Into<String>,
    ) -> Result<EventReceipt> {
        let child_task_session_id = child_task_session_id.into();
        validate_identifier(&child_task_session_id, "child_task_session_id")?;
        let status = status.into();
        validate_nonempty(&status, "subagent join status")?;
        self.emit_lifecycle(LifecycleEventInput {
            event_type: "subagent_join".to_owned(),
            status,
            reason: None,
            turn_id: None,
            details: Some(json!({"child_task_session_id":child_task_session_id})),
            occurred_at: None,
        })
    }

    pub fn tool_start(&mut self, mut input: ToolStartInput) -> Result<EventReceipt> {
        validate_identifier(&input.call_id, "tool call_id")?;
        validate_identifier(&input.name, "tool name")?;
        if let Some(namespace) = input.runtime_namespace.as_deref() {
            validate_identifier(namespace, "tool runtime_namespace")?;
        }
        if let Some(runtime_tool) = input.runtime_tool.as_deref() {
            validate_identifier(runtime_tool, "tool runtime_tool")?;
        }
        validate_nonempty(&input.initiator, "tool initiator")?;
        if !matches!(input.initiator.as_str(), "assistant" | "runtime" | "user") {
            bail!("tool initiator must be assistant, runtime, or user");
        }
        if let Some(parent_call_id) = input.parent_call_id.as_deref() {
            validate_identifier(parent_call_id, "tool parent_call_id")?;
        }
        if let Some(turn_id) = input.turn_id.as_deref() {
            validate_identifier(turn_id, "tool turn_id")?;
        }
        if self.state.active_tools.contains_key(&input.call_id) {
            bail!("tool call is already active: {}", input.call_id);
        }
        self.ensure_open_for_event("tool_execution")?;
        let runtime_tool = input
            .runtime_tool
            .take()
            .unwrap_or_else(|| input.name.clone());
        let runtime_namespace = input.runtime_namespace.take();
        let canonical_name =
            canonical_runtime_tool_name(runtime_namespace.as_deref(), &runtime_tool);
        let schema = input
            .schema
            .take()
            .or_else(|| self.registry_schema(runtime_namespace.as_deref(), &runtime_tool));
        let (schema, schema_provenance) = match schema {
            Some(schema) => {
                let mut schema = schema;
                schema["name"] = json!(canonical_name);
                schema["runtime_tool"] = json!(runtime_tool);
                if let Some(namespace) = runtime_namespace.as_deref() {
                    schema["runtime_namespace"] = json!(namespace);
                }
                let schema = enrich_tool_schema(schema, &canonical_name)?;
                let digest = schema
                    .get("schema_hash")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let provenance = json!({
                    "source": if self.state.tool_registry.is_some() { "runtime_tool_registry" } else { "dispatcher_schema" },
                    "source_complete": tool_definition_source_complete(&schema, &canonical_name),
                    "schema_sha256": digest,
                    "registry_sha256": self.state.tool_registry_sha256,
                });
                (Some(schema), Some(provenance))
            }
            None => (
                None,
                Some(json!({
                    "source":"missing_runtime_registry",
                    "source_complete":false,
                    "reason":"dispatcher did not provide a complete schema"
                })),
            ),
        };
        let started_at = input.started_at.take().unwrap_or(now_rfc3339()?);
        validate_rfc3339(&started_at, "tool started_at")?;
        let event_id_hint = self.next_event_id("dispatcher")?;
        let mut execution = json!({
            "call_id":input.call_id,
            "name":canonical_name,
            "runtime_tool":runtime_tool,
            "runtime_namespace":runtime_namespace,
            "initiator":input.initiator,
            "status":"started",
            "arguments":input.arguments,
            "started_at":started_at,
        });
        if let Some(parent) = input.parent_call_id.clone() {
            execution["parent_call_id"] = json!(parent);
        }
        if let Some(turn_id) = input.turn_id.as_deref() {
            execution["turn_id"] = json!(turn_id);
        }
        execution["schema"] = schema.clone().unwrap_or(Value::Null);
        execution["schema_provenance"] = schema_provenance.clone().unwrap_or(Value::Null);
        let event =
            self.tool_event_envelope(event_id_hint.clone(), input.turn_id.as_deref(), execution)?;
        let receipt = self.append_event(event, "dispatcher", event_id_hint.sequence)?;
        self.state.active_tools.insert(
            input.call_id.clone(),
            ActiveTool {
                call_id: input.call_id,
                name: canonical_name,
                runtime_namespace,
                runtime_tool: Some(runtime_tool),
                arguments: input.arguments,
                schema,
                schema_provenance,
                parent_call_id: input.parent_call_id,
                initiator: input.initiator,
                turn_id: input.turn_id,
                started_at,
            },
        );
        self.persist_state()?;
        Ok(receipt)
    }

    pub fn tool_end(&mut self, input: ToolEndInput) -> Result<EventReceipt> {
        let active = self
            .state
            .active_tools
            .get(&input.call_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("tool call has no recorded start: {}", input.call_id))?;
        if !matches!(
            input.status.as_str(),
            "success" | "error" | "cancelled" | "timeout"
        ) {
            bail!("tool terminal status must be success, error, cancelled, or timeout");
        }
        if input.status == "success" && input.result.is_none() {
            bail!("successful tool call requires an explicit result");
        }
        if matches!(input.status.as_str(), "error" | "cancelled" | "timeout")
            && input.result.is_none()
            && input.error.is_none()
        {
            bail!("failed/cancelled tool call requires an explicit result or error");
        }
        let finished_at = input.finished_at.unwrap_or(now_rfc3339()?);
        let finished_timestamp = parse_rfc3339(&finished_at, "tool finished_at")?;
        let started_timestamp = parse_rfc3339(&active.started_at, "tool started_at")?;
        if finished_timestamp < started_timestamp {
            bail!("tool finished_at precedes started_at");
        }
        let event_id_hint = self.next_event_id("dispatcher")?;
        let mut execution = json!({
            "call_id":active.call_id,
            "name":active.name,
            "runtime_tool":active.runtime_tool,
            "runtime_namespace":active.runtime_namespace,
            "initiator":active.initiator,
            "status":input.status,
            "arguments":active.arguments,
            "started_at":active.started_at,
            "finished_at":finished_at,
            "schema":active.schema.clone().unwrap_or(Value::Null),
            "schema_provenance":active.schema_provenance.clone().unwrap_or(Value::Null),
        });
        if let Some(parent) = active.parent_call_id {
            execution["parent_call_id"] = json!(parent);
        }
        if let Some(turn_id) = active.turn_id.as_deref() {
            execution["turn_id"] = json!(turn_id);
        }
        if let Some(result) = input.result {
            execution["result"] = result;
        }
        if let Some(error) = input.error {
            execution["error"] = error;
        }
        let event =
            self.tool_event_envelope(event_id_hint.clone(), active.turn_id.as_deref(), execution)?;
        let receipt = self.append_event(event, "dispatcher", event_id_hint.sequence)?;
        self.state.active_tools.remove(&input.call_id);
        self.persist_state()?;
        Ok(receipt)
    }

    pub fn evaluate(&mut self, input: EvaluationInput) -> Result<EventReceipt> {
        const KINDS: &[&str] = &[
            "test",
            "build",
            "search",
            "user_correction",
            "final_acceptance",
            "evaluator",
        ];
        if !KINDS.contains(&input.kind.as_str()) {
            bail!("unsupported evaluation kind: {}", input.kind);
        }
        validate_nonempty(&input.source, "evaluation source")?;
        if input.status.is_none()
            && input.passed.is_none()
            && input.reward.is_none()
            && input.score.is_none()
        {
            bail!("evaluation needs status, passed, reward, or score");
        }
        for (field, value) in [("reward", input.reward), ("score", input.score)] {
            if let Some(value) = value
                && !(0.0..=1.0).contains(&value)
            {
                bail!("evaluation {field} must be between 0 and 1");
            }
        }
        let observed_at = input.observed_at.unwrap_or(now_rfc3339()?);
        validate_rfc3339(&observed_at, "evaluation observed_at")?;
        let event_id_hint = self.next_event_id("evaluator")?;
        let mut evidence = json!({
            "kind":input.kind,
            "source":input.source,
            "observed_at":observed_at,
        });
        for (name, value) in [
            ("status", input.status.map(Value::String)),
            ("passed", input.passed.map(Value::Bool)),
            ("reward", input.reward.map(Value::from)),
            ("score", input.score.map(Value::from)),
            ("artifact", input.artifact),
        ] {
            if let Some(value) = value {
                evidence[name] = value;
            }
        }
        let event = json!({
            "recordType":"evaluation",
            "sourceNamespace":self.state.source_namespace,
            "traceContext":self.trace_context(None),
            "receivedAt":observed_at,
            "producerEvent":self.producer_event(event_id_hint.event_id, evaluator_stream(self.task_session_id()), event_id_hint.sequence),
            "evaluationEvidence":[evidence],
        });
        let receipt = self.append_event(event, "evaluator", event_id_hint.sequence)?;
        Ok(receipt)
    }

    /// Set a new target for a resumed session.  The target is persisted before
    /// any network request is made.
    pub fn set_target(&mut self, target: Option<HarnessTarget>) -> Result<()> {
        let target = normalize_target(target)?;
        validate_target(&target, &self.spool_path())?;
        self.state.target = target;
        self.persist_state()
    }

    pub async fn flush(&mut self) -> Result<FlushSummary> {
        let target = self.state.target.clone().ok_or_else(|| {
            anyhow::anyhow!("harness has no delivery target; use --relay-url or --output")
        })?;
        if self.state.retry_max_times < 20 {
            bail!("harness delivery requires at least 20 retry attempts");
        }
        let delivery_target = match target {
            HarnessTarget::Relay(url) => DeliveryTarget::ProducerRelay(url),
            HarnessTarget::Jsonl(path) => DeliveryTarget::Jsonl(path),
        };
        let mut summary = FlushSummary::default();
        loop {
            let (batch, consumed_bytes) = self.read_pending_batch()?;
            if batch.is_empty() {
                break;
            }
            summary.records_attempted =
                summary.records_attempted.saturating_add(batch.len() as u64);
            let receipt = match deliver_batch(
                &DeliveryConfig {
                    target: delivery_target.clone(),
                    request_timeout: Duration::from_millis(self.state.request_timeout_ms),
                    retry_max_times: self.state.retry_max_times,
                },
                &batch,
            )
            .await
            {
                Ok(receipt) => receipt,
                Err(error) => {
                    self.state.last_delivery_error = Some(error.to_string());
                    self.persist_state()?;
                    return Err(error);
                }
            };
            self.state.spool_offset = self.state.spool_offset.saturating_add(consumed_bytes);
            // Relay `durable` includes idempotent duplicates on replay. The
            // harness checkpoint counts unique spool records, so advance it
            // by the batch length and expose duplicates separately.
            self.state.delivered_events = self
                .state
                .delivered_events
                .saturating_add(batch.len() as u64);
            self.state.last_delivery_error = None;
            summary.records_durable = summary.records_durable.saturating_add(receipt.durable);
            summary.duplicates = summary.duplicates.saturating_add(receipt.duplicates);
            self.persist_state()?;
        }
        summary.spool_offset = self.state.spool_offset;
        summary.pending_records = self.pending_record_count()?;
        Ok(summary)
    }

    pub fn inspect(&self) -> Result<HarnessInspection> {
        let metadata = fs::metadata(self.spool_path())?;
        Ok(HarnessInspection {
            schema_version: self.state.schema_version.clone(),
            state_root: self.root.to_string_lossy().into_owned(),
            source_namespace: self.state.source_namespace.clone(),
            task_session_id: self.task_session_id().to_owned(),
            root_session_id: self.state.identity.root_session_id.clone(),
            status: self.state.status.clone(),
            target: self.state.target.clone(),
            emitted_events: self.state.emitted_events,
            delivered_events: self.state.delivered_events,
            pending_records: self.pending_record_count()?,
            spool_bytes: metadata.len(),
            checkpoint_offset: self.state.spool_offset,
            recovered_tail_bytes: self.state.recovered_tail_bytes,
            next_sequences: self.state.streams.clone(),
            active_tool_calls: self.state.active_tools.keys().cloned().collect(),
            correlation_headers: self.correlation_headers(),
            last_delivery_error: self.state.last_delivery_error.clone(),
        })
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.join(STATE_FILE)
    }

    pub fn spool_path(&self) -> PathBuf {
        self.root.join(&self.state.spool_file)
    }

    fn tool_event_envelope(
        &self,
        event_id_hint: EventId,
        turn_id: Option<&str>,
        execution: Value,
    ) -> Result<Value> {
        let stream_id = dispatcher_stream(self.task_session_id());
        let event_id = event_id_hint.event_id;
        let mut envelope = json!({
            "recordType":"tool_execution",
            "sourceNamespace":self.state.source_namespace,
            "traceContext":self.trace_context(turn_id),
            "receivedAt":execution.get("finished_at").or_else(|| execution.get("started_at")),
            "producerEvent":self.producer_event(event_id.clone(), stream_id, event_id_hint.sequence),
            "toolExecution":execution,
        });
        // Keep the event ID in the evidence as well as the producer envelope;
        // the producer validator rejects a mismatch.
        envelope["toolExecution"]["event_id"] = json!(event_id);
        Ok(envelope)
    }

    fn append_event(
        &mut self,
        value: Value,
        stream_kind: &str,
        sequence: u64,
    ) -> Result<EventReceipt> {
        let raw = serde_json::to_vec(&value)?;
        let record = prepare_producer_capture(&raw, self.state.max_envelope_bytes)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.spool_path())?;
        file.write_all(&record.canonical)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        let stream_id = stream_for_kind(stream_kind, self.task_session_id());
        let next = sequence.saturating_add(1);
        self.state.streams.insert(stream_id.clone(), next);
        self.state.emitted_events = self.state.emitted_events.saturating_add(1);
        self.persist_state()?;
        Ok(EventReceipt {
            capture_id: record.capture_id,
            stream_id,
            sequence,
            local_durable: true,
            pending_records: self.pending_record_count()?,
        })
    }

    fn producer_event(&self, event_id: String, stream_id: String, sequence: u64) -> Value {
        json!({
            "schema_version":PRODUCER_EVENT_SCHEMA_VERSION,
            "event_id":event_id,
            "producer":self.state.producer,
            "producer_version":self.state.producer_version,
            "identity_scheme":DETERMINISTIC_CAPTURE_IDENTITY,
            "stream_id":stream_id,
            "sequence":sequence,
        })
    }

    fn trace_context(&self, turn_id: Option<&str>) -> Value {
        let identity = &self.state.identity;
        let (_, trace_id, span_id, trace_flags) = traceparent_parts(&identity.traceparent)
            .expect("Harness identity contains a validated traceparent");
        let mut trace = Map::new();
        for (name, value) in [
            ("task_session_id", Some(identity.task_session_id.as_str())),
            ("root_session_id", Some(identity.root_session_id.as_str())),
            ("parent_session_id", identity.parent_session_id.as_deref()),
            ("goal_id", identity.goal_id.as_deref()),
            ("agent_id", identity.agent_id.as_deref()),
            ("branch_id", identity.branch_id.as_deref()),
            ("session_id", identity.session_id.as_deref()),
            ("thread_id", identity.thread_id.as_deref()),
            (
                "previous_response_id",
                identity.previous_response_id.as_deref(),
            ),
            ("traceparent", Some(identity.traceparent.as_str())),
        ] {
            if let Some(value) = value {
                trace.insert(name.to_owned(), Value::String(value.to_owned()));
            }
        }
        trace.insert("trace_id".to_owned(), json!(trace_id.to_ascii_lowercase()));
        trace.insert("span_id".to_owned(), json!(span_id.to_ascii_lowercase()));
        trace.insert(
            "trace_flags".to_owned(),
            json!(trace_flags.to_ascii_lowercase()),
        );
        if let Some(turn_id) = turn_id {
            trace.insert("turn_id".to_owned(), json!(turn_id));
            trace.insert("root_turn_id".to_owned(), json!(turn_id));
        }
        Value::Object(trace)
    }

    fn correlation_headers(&self) -> BTreeMap<String, String> {
        let identity = &self.state.identity;
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
        for (name, value) in [
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
                headers.insert(name.to_owned(), value.to_owned());
            }
        }
        headers
    }

    fn next_event_id(&self, stream_kind: &str) -> Result<EventId> {
        let stream_id = stream_for_kind(stream_kind, self.task_session_id());
        let sequence = *self.state.streams.get(&stream_id).unwrap_or(&0);
        validate_identifier(&stream_id, "stream_id")?;
        let mut digest = Sha256::new();
        for field in [self.state.producer.as_str(), stream_id.as_str()] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        digest.update(sequence.to_be_bytes());
        let event_id = format!("evt-{}", hex::encode(digest.finalize()));
        Ok(EventId { event_id, sequence })
    }

    fn registry_schema(&self, namespace: Option<&str>, name: &str) -> Option<Value> {
        self.state
            .tool_registry
            .as_ref()?
            .get("tools")
            .and_then(Value::as_array)?
            .iter()
            .find(|entry| {
                let tool = entry.get("tool").and_then(Value::as_object);
                let runtime_tool = entry
                    .get("runtime_tool")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        tool.and_then(|tool| tool.get("runtime_tool"))
                            .and_then(Value::as_str)
                    })
                    .or_else(|| {
                        tool.and_then(|tool| tool.get("name"))
                            .and_then(Value::as_str)
                    });
                let runtime_namespace = entry
                    .get("runtime_namespace")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        tool.and_then(|tool| tool.get("runtime_namespace"))
                            .and_then(Value::as_str)
                    })
                    .or_else(|| {
                        tool.and_then(|tool| tool.get("namespace"))
                            .and_then(Value::as_str)
                    });
                runtime_tool == Some(name) && runtime_namespace == namespace
            })
            .and_then(|entry| entry.get("tool"))
            .cloned()
    }

    fn ensure_open_for_event(&self, event_type: &str) -> Result<()> {
        if self.state.status == "closed" {
            bail!("harness task is already closed; cannot append {event_type}");
        }
        Ok(())
    }

    fn read_pending_batch(&self) -> Result<(Vec<Vec<u8>>, u64)> {
        let mut file = File::open(self.spool_path())?;
        file.seek(SeekFrom::Start(self.state.spool_offset))?;
        let mut reader = BufReader::new(file);
        let mut consumed = 0_u64;
        let mut batch = Vec::with_capacity(self.state.batch_records.max(1));
        let mut line = Vec::new();
        while batch.len() < self.state.batch_records.max(1) {
            line.clear();
            let bytes = reader.read_until(b'\n', &mut line)?;
            if bytes == 0 {
                break;
            }
            if !line.ends_with(b"\n") {
                // An active writer may have left an incomplete tail.  It is
                // retained for a later invocation rather than acknowledged.
                break;
            }
            consumed = consumed.saturating_add(bytes as u64);
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let record = prepare_producer_capture(&line, self.state.max_envelope_bytes)
                .context("invalid event in durable harness spool")?;
            batch.push(record.canonical);
        }
        Ok((batch, consumed))
    }

    fn reconcile_spool(&mut self) -> Result<()> {
        let path = self.spool_path();
        if !path.exists() {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?
                .sync_all()?;
        }
        let mut bytes = fs::read(&path)?;
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            let complete_len = bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |index| index + 1);
            if self.state.spool_offset > complete_len as u64 {
                bail!("harness checkpoint references an incomplete spool tail");
            }
            let truncated = bytes.len().saturating_sub(complete_len) as u64;
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(complete_len as u64)?;
            file.sync_all()?;
            bytes.truncate(complete_len);
            self.state.recovered_tail_bytes =
                self.state.recovered_tail_bytes.saturating_add(truncated);
        }
        if self.state.spool_offset > bytes.len() as u64 {
            bail!("harness spool checkpoint is beyond spool length");
        }
        if self.state.spool_offset > 0
            && bytes.get(self.state.spool_offset as usize - 1).copied() != Some(b'\n')
        {
            bail!("harness spool checkpoint does not end on a record boundary");
        }
        let mut next_sequences = BTreeMap::from([
            (harness_stream(self.task_session_id()), 0_u64),
            (dispatcher_stream(self.task_session_id()), 0_u64),
            (evaluator_stream(self.task_session_id()), 0_u64),
        ]);
        let mut emitted = 0_u64;
        let mut delivered = 0_u64;
        let mut consumed = 0_u64;
        let mut active = BTreeMap::new();
        let mut terminal_at = None;
        for framed in bytes.split_inclusive(|byte| *byte == b'\n') {
            consumed = consumed.saturating_add(framed.len() as u64);
            let line = framed.strip_suffix(b"\n").unwrap_or(framed);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let record = prepare_producer_capture(line, self.state.max_envelope_bytes)
                .context("invalid event in durable harness spool")?;
            emitted = emitted.saturating_add(1);
            let value: Value = serde_json::from_slice(&record.canonical)?;
            validate_spool_identity(&value, &self.state)?;
            if let Some(event) = value.get("producerEvent")
                && let (Some(stream), Some(sequence)) = (
                    event.get("stream_id").and_then(Value::as_str),
                    event.get("sequence").and_then(Value::as_u64),
                )
            {
                let expected = next_sequences.entry(stream.to_owned()).or_insert(0);
                if sequence != *expected {
                    bail!(
                        "harness spool producer sequence is not contiguous: stream={stream} expected={} observed={sequence}",
                        *expected
                    );
                }
                *expected = expected.saturating_add(1);
            }
            if consumed <= self.state.spool_offset {
                delivered = delivered.saturating_add(1);
            }
            if value.get("recordType").and_then(Value::as_str) == Some("tool_execution")
                && let Some(execution) = value.get("toolExecution").and_then(Value::as_object)
            {
                if execution.get("status").and_then(Value::as_str) == Some("started") {
                    if let Some(call_id) = execution.get("call_id").and_then(Value::as_str) {
                        active.insert(call_id.to_owned(), active_tool_from_execution(execution)?);
                    }
                } else if let Some(call_id) = execution.get("call_id").and_then(Value::as_str) {
                    active.remove(call_id);
                }
            }
            if value.get("recordType").and_then(Value::as_str) == Some("lifecycle_event")
                && let Some(kind) = value
                    .pointer("/lifecycleEvent/type")
                    .and_then(Value::as_str)
                && is_terminal_lifecycle(kind)
            {
                if terminal_at.is_some() {
                    bail!("harness spool contains multiple task terminal events");
                }
                terminal_at = value
                    .pointer("/lifecycleEvent/occurred_at")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            } else if terminal_at.is_some() {
                bail!("harness spool contains an event after the task terminal event");
            }
        }
        if self.state.emitted_events > emitted {
            bail!(
                "harness state claims {} emitted events but spool contains {emitted}",
                self.state.emitted_events
            );
        }
        if self.state.delivered_events != delivered {
            bail!(
                "harness delivery checkpoint is inconsistent: state={} framed={delivered}",
                self.state.delivered_events
            );
        }
        self.state.streams = next_sequences;
        self.state.emitted_events = emitted;
        self.state.active_tools = active;
        if let Some(ended_at) = terminal_at {
            self.state.status = "closed".to_owned();
            self.state.ended_at = Some(ended_at);
        } else if self.state.status == "closed" {
            bail!("harness state is closed but spool has no terminal lifecycle event");
        }
        Ok(())
    }

    fn pending_record_count(&self) -> Result<u64> {
        let bytes = fs::read(self.spool_path())?;
        if self.state.spool_offset >= bytes.len() as u64 {
            return Ok(0);
        }
        Ok(bytes[self.state.spool_offset as usize..]
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            .count() as u64)
    }

    fn persist_state(&self) -> Result<()> {
        atomic_write(&self.state_path(), &serde_json::to_vec_pretty(&self.state)?)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Dropping SessionLock removes the ownership marker.
        self.lock.take();
    }
}

#[derive(Debug, Clone)]
struct EventId {
    event_id: String,
    sequence: u64,
}

fn active_tool_from_execution(execution: &Map<String, Value>) -> Result<ActiveTool> {
    Ok(ActiveTool {
        call_id: execution
            .get("call_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("tool execution call_id is missing"))?
            .to_owned(),
        name: execution
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("tool execution name is missing"))?
            .to_owned(),
        runtime_namespace: execution
            .get("runtime_namespace")
            .and_then(Value::as_str)
            .map(str::to_owned),
        runtime_tool: execution
            .get("runtime_tool")
            .and_then(Value::as_str)
            .map(str::to_owned),
        arguments: execution.get("arguments").cloned().unwrap_or(Value::Null),
        schema: execution
            .get("schema")
            .filter(|value| !value.is_null())
            .cloned(),
        schema_provenance: execution
            .get("schema_provenance")
            .filter(|value| !value.is_null())
            .cloned(),
        parent_call_id: execution
            .get("parent_call_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        initiator: execution
            .get("initiator")
            .and_then(Value::as_str)
            .unwrap_or("assistant")
            .to_owned(),
        turn_id: execution
            .get("turn_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        started_at: execution
            .get("started_at")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("tool execution started_at is missing"))?
            .to_owned(),
    })
}

fn validate_config(config: &HarnessConfig) -> Result<()> {
    validate_nonempty(&config.source_namespace, "source_namespace")?;
    validate_nonempty(&config.producer, "producer")?;
    validate_nonempty(&config.producer_version, "producer_version")?;
    if config.source_namespace.len() > 256 {
        bail!("source_namespace must be <= 256 bytes");
    }
    if config.retry_max_times < 20 {
        bail!("harness delivery requires at least 20 retry attempts");
    }
    if config.max_envelope_bytes == 0 || config.batch_records == 0 {
        bail!("harness envelope and batch limits must be positive");
    }
    if let Some(registry) = config.tool_registry.as_ref() {
        validate_tool_registry_value(registry)?;
    }
    Ok(())
}

fn validate_state(state: &HarnessState) -> Result<()> {
    if state.schema_version != HARNESS_SCHEMA_VERSION {
        bail!("unsupported harness state schema {}", state.schema_version);
    }
    for (field, value) in [
        ("source_namespace", state.source_namespace.as_str()),
        ("producer", state.producer.as_str()),
        ("producer_version", state.producer_version.as_str()),
    ] {
        validate_identifier(value, field)?;
    }
    validate_identity(&state.identity)?;
    if state.retry_max_times < 20
        || state.request_timeout_ms == 0
        || state.max_envelope_bytes == 0
        || state.batch_records == 0
    {
        bail!("harness state contains invalid delivery limits");
    }
    if state.spool_file != SPOOL_FILE {
        bail!("harness state references an unsupported spool file");
    }
    if state.delivered_events > state.emitted_events {
        bail!("harness state delivered event count exceeds emitted events");
    }
    if !matches!(state.status.as_str(), "open" | "closed") {
        bail!("harness state status must be open or closed");
    }
    if (state.status == "closed") != state.ended_at.is_some() {
        bail!("harness state status and ended_at are inconsistent");
    }
    validate_rfc3339(&state.started_at, "harness started_at")?;
    if let Some(ended_at) = state.ended_at.as_deref() {
        validate_rfc3339(ended_at, "harness ended_at")?;
    }
    match (&state.tool_registry, &state.tool_registry_sha256) {
        (Some(registry), Some(observed)) => {
            let expected = canonical_tool_registry_sha256(registry)?;
            if observed != &expected {
                bail!("harness Tool Registry hash does not match its contents");
            }
        }
        (None, None) => {}
        _ => bail!("harness Tool Registry and hash must be present together"),
    }
    Ok(())
}

fn validate_identity(identity: &HarnessIdentity) -> Result<()> {
    for (field, value) in [
        ("task_session_id", Some(identity.task_session_id.as_str())),
        ("root_session_id", Some(identity.root_session_id.as_str())),
        ("parent_session_id", identity.parent_session_id.as_deref()),
        ("goal_id", identity.goal_id.as_deref()),
        ("agent_id", identity.agent_id.as_deref()),
        ("branch_id", identity.branch_id.as_deref()),
        ("session_id", identity.session_id.as_deref()),
        ("thread_id", identity.thread_id.as_deref()),
        (
            "previous_response_id",
            identity.previous_response_id.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            validate_identifier(value, field)?;
        }
    }
    validate_traceparent(&identity.traceparent)
}

fn validate_schema_name(schema: &Value, expected: &str) -> Result<()> {
    let object = schema
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("tool schema must be an object"))?;
    if object.get("name").and_then(Value::as_str) != Some(expected) {
        bail!("tool schema name does not match tool call name");
    }
    let has_parameters = object.get("parameters").is_some_and(Value::is_object);
    let has_native_format = object.get("format").is_some_and(Value::is_object);
    if !has_parameters && !has_native_format {
        bail!("tool schema requires captured parameters or a native format");
    }
    Ok(())
}

fn enrich_tool_schema(mut schema: Value, expected: &str) -> Result<Value> {
    validate_schema_name(&schema, expected)?;
    let digest = canonical_tool_schema_sha256(&schema)?;
    let object = schema
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("tool schema must be an object"))?;
    if let Some(observed) = object.get("schema_hash").and_then(Value::as_str)
        && observed != digest
    {
        bail!("tool schema schema_hash does not match its contents");
    }
    if let Some(version) = object.get("schema_version").and_then(Value::as_str)
        && version.trim().is_empty()
    {
        bail!("tool schema schema_version must not be empty");
    }
    object.insert("schema_hash".to_owned(), json!(digest));
    object
        .entry("schema_version".to_owned())
        .or_insert_with(|| json!(format!("sha256:{digest}")));
    Ok(schema)
}

fn normalize_target(target: Option<HarnessTarget>) -> Result<Option<HarnessTarget>> {
    let Some(target) = target else {
        return Ok(None);
    };
    match target {
        HarnessTarget::Relay(url) => {
            let parsed = reqwest::Url::parse(&url).context("parse Harness Relay URL")?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                bail!("Harness Relay URL must be an absolute HTTP(S) URL");
            }
            Ok(Some(HarnessTarget::Relay(
                url.trim_end_matches('/').to_owned(),
            )))
        }
        HarnessTarget::Jsonl(path) => {
            let requested = if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            };
            let file_name = requested
                .file_name()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| anyhow::anyhow!("Harness output path must name a file"))?;
            let parent = requested
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Harness output path has no parent"))?;
            fs::create_dir_all(parent)?;
            let absolute = parent.canonicalize()?.join(file_name);
            if absolute.is_dir() {
                bail!("Harness output path must not be a directory");
            }
            Ok(Some(HarnessTarget::Jsonl(absolute)))
        }
    }
}

fn validate_target(target: &Option<HarnessTarget>, spool: &Path) -> Result<()> {
    let Some(HarnessTarget::Jsonl(path)) = target else {
        return Ok(());
    };
    let spool = if spool.exists() {
        spool.canonicalize()?
    } else {
        let parent = spool
            .parent()
            .ok_or_else(|| anyhow::anyhow!("harness spool path has no parent"))?;
        parent.canonicalize()?.join(
            spool
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("harness spool path has no file name"))?,
        )
    };
    if path == &spool {
        bail!("harness delivery target cannot be the event spool itself");
    }
    Ok(())
}

fn validate_spool_identity(value: &Value, state: &HarnessState) -> Result<()> {
    if value.get("sourceNamespace").and_then(Value::as_str) != Some(state.source_namespace.as_str())
    {
        bail!("harness spool event sourceNamespace does not match session state");
    }
    for (field, expected) in [
        (
            "task_session_id",
            Some(state.identity.task_session_id.as_str()),
        ),
        (
            "root_session_id",
            Some(state.identity.root_session_id.as_str()),
        ),
        (
            "parent_session_id",
            state.identity.parent_session_id.as_deref(),
        ),
        ("goal_id", state.identity.goal_id.as_deref()),
        ("agent_id", state.identity.agent_id.as_deref()),
        ("branch_id", state.identity.branch_id.as_deref()),
        ("session_id", state.identity.session_id.as_deref()),
        ("thread_id", state.identity.thread_id.as_deref()),
        ("traceparent", Some(state.identity.traceparent.as_str())),
    ] {
        let observed = value
            .pointer(&format!("/traceContext/{field}"))
            .and_then(Value::as_str);
        if observed != expected {
            bail!("harness spool event {field} does not match session state");
        }
    }
    let producer = value
        .pointer("/producerEvent/producer")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("harness spool event producer is missing"))?;
    if producer != state.producer {
        bail!("harness spool event producer does not match session state");
    }
    if value
        .pointer("/producerEvent/producer_version")
        .and_then(Value::as_str)
        != Some(state.producer_version.as_str())
    {
        bail!("harness spool event producer_version does not match session state");
    }
    let stream = value
        .pointer("/producerEvent/stream_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("harness spool event stream_id is missing"))?;
    let expected_streams = [
        harness_stream(&state.identity.task_session_id),
        dispatcher_stream(&state.identity.task_session_id),
        evaluator_stream(&state.identity.task_session_id),
    ];
    if !expected_streams.iter().any(|expected| expected == stream) {
        bail!("harness spool event stream_id does not belong to this task");
    }
    Ok(())
}

fn event_type_is_task_start(input: &LifecycleEventInput) -> bool {
    matches!(
        input.event_type.trim().to_ascii_lowercase().as_str(),
        "task_start" | "session_start"
    )
}

trait LifecycleInputExt {
    fn event_type_is_task_start(&self) -> bool;
}

impl LifecycleInputExt for LifecycleEventInput {
    fn event_type_is_task_start(&self) -> bool {
        event_type_is_task_start(self)
    }
}

fn is_terminal_lifecycle(event_type: &str) -> bool {
    let event = event_type
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', ':'], "_");
    matches!(
        event.as_str(),
        "session_end"
            | "session_ended"
            | "task_end"
            | "task_ended"
            | "task_completed"
            | "cancel"
            | "cancelled"
            | "canceled"
            | "terminated"
            | "abort"
            | "aborted"
            | "abandoned"
    ) || event.starts_with("task_fail")
        || event.starts_with("session_fail")
        || event.starts_with("task_cancel")
        || event.starts_with("session_cancel")
}

fn stream_for_kind(kind: &str, task_session_id: &str) -> String {
    match kind {
        "dispatcher" => dispatcher_stream(task_session_id),
        "evaluator" => evaluator_stream(task_session_id),
        _ => harness_stream(task_session_id),
    }
}

fn harness_stream(task_session_id: &str) -> String {
    format!("harness-{task_session_id}")
}

fn dispatcher_stream(task_session_id: &str) -> String {
    format!("dispatcher-{task_session_id}")
}

fn evaluator_stream(task_session_id: &str) -> String {
    format!("evaluator-{task_session_id}")
}

fn generated_id(prefix: &str) -> String {
    let counter = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut digest = Sha256::new();
    digest.update(prefix.as_bytes());
    digest.update(now.to_be_bytes());
    digest.update(std::process::id().to_be_bytes());
    digest.update(counter.to_be_bytes());
    format!("{prefix}-{}", hex::encode(digest.finalize()))
}

fn generated_traceparent() -> String {
    let mut digest = Sha256::new();
    digest.update(generated_id("trace").as_bytes());
    let bytes = digest.finalize();
    format!(
        "00-{}-{}-01",
        hex::encode(&bytes[..16]),
        hex::encode(&bytes[16..24])
    )
}

fn now_rfc3339() -> Result<String> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

fn validate_rfc3339(value: &str, field: &str) -> Result<()> {
    parse_rfc3339(value, field)?;
    Ok(())
}

fn parse_rfc3339(value: &str, field: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).with_context(|| format!("{field} must be RFC3339"))
}

fn validate_traceparent(value: &str) -> Result<()> {
    let Some((version, trace_id, span_id, _)) = traceparent_parts(value) else {
        bail!("traceparent must follow W3C version-trace-parent-flags format");
    };
    if version.eq_ignore_ascii_case("ff")
        || trace_id.bytes().all(|byte| byte == b'0')
        || span_id.bytes().all(|byte| byte == b'0')
    {
        bail!("traceparent version and trace/span identifiers are invalid");
    }
    Ok(())
}

fn traceparent_parts(value: &str) -> Option<(&str, &str, &str, &str)> {
    let mut parts = value.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let span_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some()
        || version.len() != 2
        || trace_id.len() != 32
        || span_id.len() != 16
        || flags.len() != 2
        || [version, trace_id, span_id, flags]
            .into_iter()
            .any(|part| !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return None;
    }
    Some((version, trace_id, span_id, flags))
}

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{field} must be a non-empty safe identifier <= 256 bytes");
    }
    Ok(())
}

fn validate_nonempty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(())
}

fn acquire_lock(root: &Path) -> Result<SessionLock> {
    fs::create_dir_all(root)?;
    let path = root.join(LOCK_FILE);
    for _ in 0..2 {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())?;
                file.sync_all()?;
                return Ok(SessionLock { _file: file, path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let pid = fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| text.trim().parse::<u32>().ok());
                let alive =
                    pid.is_some_and(|pid| Path::new("/proc").join(pid.to_string()).exists());
                if alive {
                    bail!(
                        "harness session is locked by process {}",
                        pid.unwrap_or_default()
                    );
                }
                fs::remove_file(&path)
                    .with_context(|| format!("remove stale harness lock {}", path.display()))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    bail!("could not acquire harness session lock")
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("atomic state path has no parent"))?;
    fs::create_dir_all(parent)?;
    let nonce = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        nonce
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        let directory = File::open(parent)?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn registry() -> Value {
        json!({
            "schema_version":"chiptrace.tool-registry.v1",
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[
                {"runtime_item_type":"CommandExecution","tool":{"name":"read_workspace","description":"Read workspace files.","parameters":{"type":"object","properties":{"target":{"type":"string","description":"Workspace path."}},"required":["target"]}}},
                {"runtime_item_type":"WebSearch","tool":{"name":"search_source","description":"Search source code.","parameters":{"type":"object","properties":{"query":{"type":"string","description":"Search query."}},"required":["query"]}}}
            ]
        })
    }

    #[test]
    fn start_persists_identity_and_real_lifecycle_event() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = HarnessConfig::new(temp.path().to_path_buf(), "test-harness");
        config.task_session_id = Some("task-test".to_owned());
        config.traceparent =
            Some("00-11111111111111111111111111111111-2222222222222222-03".to_owned());
        config.tool_registry = Some(registry());
        let harness = Harness::start(config).unwrap();
        assert_eq!(harness.task_session_id(), "task-test");
        let state: Value =
            serde_json::from_slice(&fs::read(harness.state_path()).unwrap()).unwrap();
        assert_eq!(state["schema_version"], HARNESS_SCHEMA_VERSION);
        assert_eq!(state["identity"]["root_session_id"], "task-test");
        let lines = fs::read_to_string(harness.spool_path()).unwrap();
        let event: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
        assert_eq!(event["recordType"], "lifecycle_event");
        assert_eq!(event["lifecycleEvent"]["type"], "task_start");
        assert_eq!(
            event["traceContext"]["trace_id"],
            "11111111111111111111111111111111"
        );
        assert_eq!(event["traceContext"]["span_id"], "2222222222222222");
        assert_eq!(event["traceContext"]["trace_flags"], "03");
        assert!(event["traceContext"].get("parent_span_id").is_none());
        assert!(event["toolRegistrySha256"].as_str().is_some());
    }

    #[test]
    fn start_rejects_unsafe_optional_identity_fields() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = HarnessConfig::new(temp.path().join("session"), "test-harness");
        config.agent_id = Some("agent id with spaces".to_owned());
        assert!(Harness::start(config).is_err());
    }

    #[test]
    fn tool_schema_hash_matches_the_assembly_semantic_projection() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = HarnessConfig::new(temp.path().join("session"), "test-harness");
        config.tool_registry = Some(registry());
        let mut harness = Harness::start(config).unwrap();
        harness
            .tool_start(ToolStartInput::assistant(
                "call-schema",
                "read_workspace",
                json!({"target":"/workspace"}),
            ))
            .unwrap();
        let lines = fs::read_to_string(harness.spool_path()).unwrap();
        let event: Value = serde_json::from_str(lines.lines().nth(1).unwrap()).unwrap();
        let schema = &event["toolExecution"]["schema"];
        let semantic = json!({
            "name":schema.get("name"),
            "description":schema.get("description"),
            "parameters":schema.get("parameters"),
            "format":schema.get("format"),
            "type":schema.get("type").and_then(Value::as_str).unwrap_or("function"),
        });
        let expected = hex::encode(Sha256::digest(serde_json::to_vec(&semantic).unwrap()));
        assert_eq!(schema["schema_hash"], expected);
        assert_eq!(schema["schema_version"], format!("sha256:{expected}"));
    }

    #[tokio::test]
    async fn dispatcher_state_machine_replays_after_resume() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = HarnessConfig::new(temp.path().to_path_buf(), "test-harness");
        config.task_session_id = Some("task-replay".to_owned());
        config.target = Some(HarnessTarget::Jsonl(temp.path().join("delivered.ndjson")));
        config.tool_registry = Some(registry());
        let mut harness = Harness::start(config).unwrap();
        let start = harness
            .tool_start(ToolStartInput::assistant(
                "call-1",
                "read_workspace",
                json!({"target":"/workspace"}),
            ))
            .unwrap();
        assert!(start.local_durable);
        harness
            .tool_end(ToolEndInput {
                call_id: "call-1".to_owned(),
                status: "error".to_owned(),
                result: None,
                error: Some(json!({"message":"permission denied"})),
                finished_at: None,
            })
            .unwrap();
        harness.task_end("failed", None).unwrap();
        let first = harness.flush().await.unwrap();
        assert_eq!(first.records_durable, 4);
        drop(harness);
        let mut resumed = Harness::open(temp.path()).unwrap();
        let inspection = resumed.inspect().unwrap();
        assert_eq!(inspection.pending_records, 0);
        assert!(inspection.active_tool_calls.is_empty());
        let second = resumed.flush().await.unwrap();
        assert_eq!(second.records_durable, 0);
    }

    #[test]
    fn missing_schema_is_explicit_and_never_success_by_inference() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = HarnessConfig::new(temp.path().to_path_buf(), "test-harness");
        config.task_session_id = Some("task-schema".to_owned());
        let mut harness = Harness::start(config).unwrap();
        harness
            .tool_start(ToolStartInput::assistant(
                "call-1",
                "unknown_tool",
                json!({}),
            ))
            .unwrap();
        let line = fs::read_to_string(harness.spool_path()).unwrap();
        let event: Value = serde_json::from_str(line.lines().nth(1).unwrap()).unwrap();
        assert!(event["toolExecution"]["schema"].is_null());
        assert_eq!(
            event["toolExecution"]["schema_provenance"]["source_complete"],
            false
        );
        assert!(
            harness
                .tool_end(ToolEndInput {
                    call_id: "call-1".to_owned(),
                    status: "unknown".to_owned(),
                    result: Some(json!("unknown")),
                    error: None,
                    finished_at: None,
                })
                .is_err()
        );
    }

    #[test]
    fn lifecycle_input_keeps_explicit_cancel_and_retry() {
        let temp = tempfile::tempdir().unwrap();
        let mut harness = Harness::start(HarnessConfig::new(
            temp.path().to_path_buf(),
            "test-harness",
        ))
        .unwrap();
        harness
            .retry(Some("network reset".to_owned()), Some("turn-1".to_owned()))
            .unwrap();
        harness.cancel(Some("user cancelled".to_owned())).unwrap();
        let lines = fs::read_to_string(harness.spool_path()).unwrap();
        assert!(lines.contains("network reset"));
        assert!(lines.contains("user cancelled"));
    }

    #[test]
    fn schema_validator_preserves_incomplete_property_for_quality_gating() {
        let bad = json!({"name":"x","description":"x","parameters":{"type":"object","properties":{"p":{}}}});
        validate_schema_name(&bad, "x").unwrap();
        assert!(!tool_definition_source_complete(&bad, "x"));
    }

    #[test]
    fn generated_traceparent_is_w3c_shape() {
        validate_traceparent(&generated_traceparent()).unwrap();
        assert!(
            validate_traceparent("00-00000000000000000000000000000000-0000000000000000-01")
                .is_err()
        );
    }

    #[test]
    fn resume_truncates_only_an_incomplete_tail() {
        let temp = tempfile::tempdir().unwrap();
        let harness = Harness::start(HarnessConfig::new(
            temp.path().to_path_buf(),
            "test-harness",
        ))
        .unwrap();
        let spool = harness.spool_path();
        drop(harness);
        let before = fs::metadata(&spool).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&spool).unwrap();
        file.write_all(br#"{"recordType":"lifecycle_event""#)
            .unwrap();
        file.sync_all().unwrap();
        drop(file);

        let resumed = Harness::open(temp.path()).unwrap();
        let inspection = resumed.inspect().unwrap();
        assert_eq!(inspection.emitted_events, 1);
        assert_eq!(inspection.pending_records, 1);
        assert!(inspection.recovered_tail_bytes > 0);
        assert_eq!(fs::metadata(spool).unwrap().len(), before);
    }

    #[test]
    fn resume_rejects_an_event_from_another_task_spool() {
        let temp = tempfile::tempdir().unwrap();
        let first_root = temp.path().join("first");
        let second_root = temp.path().join("second");
        let mut first_config = HarnessConfig::new(first_root.clone(), "test-harness");
        first_config.task_session_id = Some("task-first".to_owned());
        let first = Harness::start(first_config).unwrap();
        let first_spool = first.spool_path();
        drop(first);

        let mut second_config = HarnessConfig::new(second_root, "test-harness");
        second_config.task_session_id = Some("task-second".to_owned());
        let second = Harness::start(second_config).unwrap();
        let foreign = fs::read_to_string(second.spool_path()).unwrap();
        drop(second);
        let mut spool = OpenOptions::new().append(true).open(first_spool).unwrap();
        spool.write_all(foreign.as_bytes()).unwrap();
        spool.sync_all().unwrap();
        drop(spool);

        let error = Harness::open(first_root).err().unwrap();
        assert!(error.to_string().contains("does not match session state"));
    }

    #[test]
    fn start_rejects_the_spool_as_its_delivery_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("session");
        let mut config = HarnessConfig::new(root.clone(), "test-harness");
        config.target = Some(HarnessTarget::Jsonl(root.join(SPOOL_FILE)));
        assert!(Harness::start(config).is_err());
    }

    #[test]
    fn resumed_task_rejects_delivery_target_drift() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = HarnessConfig::new(temp.path().to_path_buf(), "test-harness");
        config.target = Some(HarnessTarget::Relay("http://127.0.0.1:3011".to_owned()));
        drop(Harness::start(config).unwrap());

        let error = Harness::open_with_target(
            temp.path(),
            Some(HarnessTarget::Relay("http://127.0.0.1:4011".to_owned())),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("does not match persisted"));

        let resumed = Harness::open_with_target(
            temp.path(),
            Some(HarnessTarget::Relay("http://127.0.0.1:3011".to_owned())),
        )
        .unwrap();
        assert_eq!(
            resumed.inspect().unwrap().target,
            Some(HarnessTarget::Relay("http://127.0.0.1:3011".to_owned()))
        );
    }

    #[test]
    fn resume_recovers_terminal_state_from_the_spool() {
        let temp = tempfile::tempdir().unwrap();
        let mut harness = Harness::start(HarnessConfig::new(
            temp.path().to_path_buf(),
            "test-harness",
        ))
        .unwrap();
        harness.task_end("completed", None).unwrap();
        let state_path = harness.state_path();
        drop(harness);

        let mut state: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        state["status"] = json!("open");
        state["ended_at"] = Value::Null;
        fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

        let mut resumed = Harness::open(temp.path()).unwrap();
        assert_eq!(resumed.inspect().unwrap().status, "closed");
        assert!(
            resumed
                .emit_lifecycle(LifecycleEventInput::new("retry", "retrying"))
                .is_err()
        );
    }

    #[test]
    fn tool_timestamp_order_uses_instants_not_text_order() {
        let temp = tempfile::tempdir().unwrap();
        let mut harness = Harness::start(HarnessConfig::new(
            temp.path().to_path_buf(),
            "test-harness",
        ))
        .unwrap();
        let mut input = ToolStartInput::assistant("call-offset", "offset_tool", json!({}));
        input.started_at = Some("2026-08-29T10:00:00+08:00".to_owned());
        harness.tool_start(input).unwrap();
        harness
            .tool_end(ToolEndInput {
                call_id: "call-offset".to_owned(),
                status: "success".to_owned(),
                result: Some(json!("done")),
                error: None,
                finished_at: Some("2026-08-29T03:00:00Z".to_owned()),
            })
            .unwrap();
    }

    #[test]
    fn inspection_exports_the_exact_gateway_correlation_headers() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = HarnessConfig::new(temp.path().to_path_buf(), "test-harness");
        config.task_session_id = Some("task-headers".to_owned());
        config.root_session_id = Some("task-root".to_owned());
        config.previous_response_id = Some("response-1".to_owned());
        let harness = Harness::start(config).unwrap();
        let headers = harness.inspect().unwrap().correlation_headers;
        assert_eq!(
            headers
                .get("x-chiptrace-task-session-id")
                .map(String::as_str),
            Some("task-headers")
        );
        assert_eq!(
            headers
                .get("x-chiptrace-previous-response-id")
                .map(String::as_str),
            Some("response-1")
        );
    }
}
