use crate::capture::{CaptureRecord, normalize_capture};
use crate::tool_registry::canonical_runtime_tool_name;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const TELEMETRY_BATCH_SCHEMA_VERSION: &str = "chiptrace.telemetry-batch.v1";
pub const CLOUD_SOURCE_NAMESPACE: &str = "stock-codex-cloud";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudEndpoint {
    OtlpLogs,
    OtlpTraces,
    CodexHook,
}

impl CloudEndpoint {
    fn as_str(self) -> &'static str {
        match self {
            Self::OtlpLogs => "otlp_logs",
            Self::OtlpTraces => "otlp_traces",
            Self::CodexHook => "codex_hook",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "otlp_logs" => Ok(Self::OtlpLogs),
            "otlp_traces" => Ok(Self::OtlpTraces),
            "codex_hook" => Ok(Self::CodexHook),
            _ => bail!("unsupported cloud ingest endpoint {value:?}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudIngestSummary {
    pub endpoint: String,
    pub source_records: u64,
    pub derived_captures: u64,
    pub unknown_events: u64,
    pub attributed_quality_errors: u64,
    pub conversion_errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CloudIngestBatch {
    pub records: Vec<CaptureRecord>,
    pub summary: CloudIngestSummary,
}

pub fn prepare_cloud_ingest(
    endpoint: CloudEndpoint,
    raw: &[u8],
    max_bytes: usize,
) -> Result<CloudIngestBatch> {
    if raw.is_empty() {
        bail!("cloud ingest body must not be empty");
    }
    if raw.len() > max_bytes {
        bail!("cloud ingest body exceeds {max_bytes} bytes");
    }
    let raw_json = std::str::from_utf8(raw).context("cloud ingest body must be UTF-8 JSON")?;
    let envelope: Value = serde_json::from_slice(raw).context("parse cloud ingest JSON")?;
    if !envelope.is_object() {
        bail!("cloud ingest body must be a JSON object");
    }

    let raw_sha256 = sha256(raw);
    // Keep the original envelope durable even when a known event is malformed
    // or a future event is not understood. The HTTP layer turns these quality
    // signals into a non-success response after the raw batch is queued.
    let (derived, source_records, unknown_events, conversion_errors) = match endpoint {
        CloudEndpoint::OtlpLogs => match derive_otlp_logs(&envelope, &raw_sha256, max_bytes) {
            Ok(batch) => batch,
            Err(error) => (Vec::new(), 0, 0, vec![format!("{error:#}")]),
        },
        CloudEndpoint::OtlpTraces => match validate_otlp_traces(&envelope) {
            Ok(source_records) => (Vec::new(), source_records, 0, Vec::new()),
            Err(error) => (Vec::new(), 0, 0, vec![format!("{error:#}")]),
        },
        CloudEndpoint::CodexHook => match derive_codex_hook(&envelope, &raw_sha256, max_bytes) {
            Ok(batch) => batch,
            Err(error) => (Vec::new(), 1, 0, vec![format!("{error:#}")]),
        },
    };
    let quality_error_count = unknown_events.saturating_add(conversion_errors.len() as u64);
    let attributed_quality_errors = derived
        .iter()
        .filter(|record| {
            serde_json::from_slice::<Value>(&record.canonical)
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/lifecycleEvent/type")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .as_deref()
                == Some("telemetry_incomplete")
        })
        .count() as u64;
    let summary = CloudIngestSummary {
        endpoint: endpoint.as_str().to_owned(),
        source_records,
        derived_captures: derived.len() as u64,
        unknown_events,
        attributed_quality_errors: attributed_quality_errors.min(quality_error_count),
        conversion_errors,
    };
    let batch_id = capture_id("batch", &[endpoint.as_str(), &raw_sha256]);
    let batch = json!({
        "recordType":"telemetry_batch",
        "captureId":batch_id,
        "captureStage":"event",
        "sourceNamespace":CLOUD_SOURCE_NAMESPACE,
        "telemetryBatch":{
            "schema_version":TELEMETRY_BATCH_SCHEMA_VERSION,
            "endpoint":endpoint.as_str(),
            "raw_json":raw_json,
            "raw_bytes":raw.len(),
            "raw_sha256":raw_sha256,
            "source_records":summary.source_records,
            "derived_captures":summary.derived_captures,
            "unknown_events":summary.unknown_events,
            "attributed_quality_errors":summary.attributed_quality_errors,
            "conversion_errors":summary.conversion_errors,
        }
    });
    let mut records = Vec::with_capacity(derived.len() + 1);
    records.push(normalize_value(batch, max_bytes)?);
    records.extend(derived);
    Ok(CloudIngestBatch { records, summary })
}

pub(crate) fn revalidate_telemetry_batch(capture: &Value) -> Result<CloudIngestSummary> {
    let batch = capture
        .get("telemetryBatch")
        .and_then(Value::as_object)
        .context("telemetry_batch requires telemetryBatch")?;
    let endpoint = batch
        .get("endpoint")
        .and_then(Value::as_str)
        .context("telemetryBatch.endpoint is required")?;
    let raw = batch
        .get("raw_json")
        .and_then(Value::as_str)
        .context("telemetryBatch.raw_json is required")?;
    Ok(prepare_cloud_ingest(CloudEndpoint::parse(endpoint)?, raw.as_bytes(), usize::MAX)?.summary)
}

type DerivedBatch = (Vec<CaptureRecord>, u64, u64, Vec<String>);

fn derive_otlp_logs(envelope: &Value, raw_sha256: &str, max_bytes: usize) -> Result<DerivedBatch> {
    let mut records = Vec::new();
    let mut source_records = 0_u64;
    let mut unknown_events = 0_u64;
    let mut errors = Vec::new();
    for resource_log in envelope
        .get("resourceLogs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let resource_attributes = attributes_map(
            resource_log
                .pointer("/resource/attributes")
                .and_then(Value::as_array),
        );
        for scope_log in resource_log
            .get("scopeLogs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for log_record in scope_log
                .get("logRecords")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let ordinal = source_records;
                source_records = source_records.saturating_add(1);
                let mut attributes = resource_attributes.clone();
                attributes.extend(attributes_map(
                    log_record.get("attributes").and_then(Value::as_array),
                ));
                let event_name = attribute_string(&attributes, "event.name").unwrap_or("");
                let derived = match event_name {
                    "codex.conversation_starts" => derive_conversation_start(
                        log_record,
                        &attributes,
                        raw_sha256,
                        ordinal,
                        max_bytes,
                    ),
                    "codex.tool_result" => {
                        derive_tool_result(log_record, &attributes, raw_sha256, ordinal, max_bytes)
                    }
                    "codex.user_prompt"
                    | "codex.api_request"
                    | "codex.sse_event"
                    | "codex.tool_decision"
                    | "codex.sandbox_outcome"
                    | "codex.startup_phase"
                    | "codex.turn_ttft"
                    | "codex.turn_cost"
                    | "codex.plugin_install_elicitation_sent"
                    | "codex.plugin_install_suggestion"
                    | "codex.websocket_connect"
                    | "codex.websocket_request"
                    | "codex.auth_recovery" => Ok(None),
                    // Agent communication is supplementary transport evidence.
                    // Required SubagentStart/SubagentStop hooks remain the
                    // authoritative lifecycle boundary for buyer delivery.
                    "codex.agent_communication" => Ok(None),
                    _ => {
                        unknown_events = unknown_events.saturating_add(1);
                        derive_telemetry_incomplete(
                            log_record,
                            &attributes,
                            raw_sha256,
                            ordinal,
                            format!("unsupported OTLP log event {event_name:?}"),
                            max_bytes,
                        )
                    }
                };
                match derived {
                    Ok(Some(record)) => records.push(record),
                    Ok(None) => {}
                    Err(error) => {
                        let error = format!("logRecords[{ordinal}] {event_name}: {error:#}");
                        if let Ok(Some(record)) = derive_telemetry_incomplete(
                            log_record,
                            &attributes,
                            raw_sha256,
                            ordinal,
                            error.clone(),
                            max_bytes,
                        ) {
                            records.push(record);
                        }
                        errors.push(error);
                    }
                }
            }
        }
    }
    if envelope.get("resourceLogs").is_none() {
        bail!("OTLP logs body requires resourceLogs");
    }
    Ok((records, source_records, unknown_events, errors))
}

fn derive_telemetry_incomplete(
    record: &Value,
    attributes: &BTreeMap<String, Value>,
    raw_sha256: &str,
    ordinal: u64,
    reason: String,
    max_bytes: usize,
) -> Result<Option<CaptureRecord>> {
    let Some(session_id) = attribute_string(attributes, "conversation.id") else {
        return Ok(None);
    };
    let occurred_at = record_timestamp(record, attributes);
    let event_id = stable_digest(&[raw_sha256, &ordinal.to_string(), "telemetry_incomplete"]);
    let capture = json!({
        "recordType":"lifecycle_event",
        "captureId":format!("cap-cloud-{event_id}"),
        "captureStage":"event",
        "sourceNamespace":CLOUD_SOURCE_NAMESPACE,
        "receivedAt":occurred_at,
        "traceContext":trace_context(record, attributes, session_id),
        "observedLifecycleEvents":["telemetry_incomplete"],
        "lifecycleEvent":{
            "event_id":format!("otel-{event_id}"),
            "type":"telemetry_incomplete",
            "status":"incomplete",
            "reason":reason,
            "occurred_at":occurred_at,
            "source_event_name":attribute_string(attributes, "event.name")
        }
    });
    normalize_value(capture, max_bytes).map(Some)
}

fn derive_conversation_start(
    record: &Value,
    attributes: &BTreeMap<String, Value>,
    raw_sha256: &str,
    ordinal: u64,
    max_bytes: usize,
) -> Result<Option<CaptureRecord>> {
    let session_id = required_attribute(attributes, "conversation.id")?;
    let occurred_at = record_timestamp(record, attributes);
    let event_id = stable_digest(&[raw_sha256, &ordinal.to_string(), "session_start"]);
    let capture = json!({
        "recordType":"lifecycle_event",
        "captureId":format!("cap-cloud-{event_id}"),
        "captureStage":"event",
        "sourceNamespace":CLOUD_SOURCE_NAMESPACE,
        "requestedModelAlias":attribute_string(attributes, "model"),
        "receivedAt":occurred_at,
        "traceContext":trace_context(record, attributes, session_id),
        "observedLifecycleEvents":["session_start"],
        "lifecycleEvent":{
            "event_id":format!("otel-{event_id}"),
            "type":"session_start",
            "status":"started",
            "occurred_at":occurred_at,
            "source_event_name":"codex.conversation_starts"
        }
    });
    normalize_value(capture, max_bytes).map(Some)
}

fn derive_tool_result(
    record: &Value,
    attributes: &BTreeMap<String, Value>,
    raw_sha256: &str,
    ordinal: u64,
    max_bytes: usize,
) -> Result<Option<CaptureRecord>> {
    let session_id = required_attribute(attributes, "conversation.id")?;
    let call_id = required_attribute(attributes, "call_id")?;
    let runtime_tool = required_attribute(attributes, "tool_name")?;
    let runtime_namespace = attribute_string(attributes, "tool_namespace");
    let name = canonical_runtime_tool_name(runtime_namespace, runtime_tool);
    let arguments = attributes
        .get("arguments")
        .context("arguments is required")
        .map(parse_json_string_or_clone)?;
    let output = attributes
        .get("output")
        .context("output is required")?
        .clone();
    let success = attribute_bool(attributes, "success").context("success is required")?;
    let output_truncated = attribute_bool(attributes, "output_truncated");
    let finished_at = record_timestamp(record, attributes);
    let started_at = started_at(attributes, finished_at.as_deref());
    let digest = stable_digest(&[raw_sha256, &ordinal.to_string(), "tool_result"]);
    let status = if success { "success" } else { "error" };
    let result_content_captured = output_truncated == Some(false);
    let capture = json!({
        "recordType":"tool_execution",
        "captureId":format!("cap-cloud-{digest}"),
        "captureStage":"event",
        "sourceNamespace":CLOUD_SOURCE_NAMESPACE,
        "requestedModelAlias":attribute_string(attributes, "model"),
        "receivedAt":finished_at,
        "startedAt":started_at,
        "finishedAt":finished_at,
        "traceContext":trace_context(record, attributes, session_id),
        "toolExecution":{
            "call_id":call_id,
            "parent_call_id":attribute_string(attributes, "parent_call_id"),
            "name":name,
            "runtime_tool":runtime_tool,
            "runtime_namespace":runtime_namespace,
            "status":status,
            "initiator":"assistant",
            "arguments":arguments,
            "result":output,
            "error":if success { Value::Null } else { output.clone() },
            "schema_provenance":{
                "source":"openai_wire_tool_definition",
                "source_complete":false,
                "reason":"OTLP tool results do not contain Tool Schema; Assembly must join the observed Wire definition"
            },
            "started_at":started_at,
            "finished_at":finished_at,
            "model_call_matched":false,
            "result_content_captured":result_content_captured,
            "output_truncated":output_truncated,
            "duration_ms":attributes.get("duration_ms"),
            "tool_result_seq":attributes.get("tool_result_seq"),
            "source_event_name":"codex.tool_result"
        }
    });
    normalize_value(capture, max_bytes).map(Some)
}

fn derive_codex_hook(envelope: &Value, raw_sha256: &str, max_bytes: usize) -> Result<DerivedBatch> {
    let event_name = envelope
        .get("hook_event_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("Codex hook requires hook_event_name")?;
    let session_id = envelope
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("Codex hook requires session_id")?;
    let Some(event_kind) = known_hook_event(event_name) else {
        return Ok((Vec::new(), 1, 1, Vec::new()));
    };
    validate_hook_fields(envelope, event_name)?;
    let turn_id = optional_alias_string(envelope, &["turn_id", "turnId"]);
    if event_kind.requires_turn && turn_id.is_none() {
        bail!("{event_name} requires turn_id");
    }
    let agent_id = optional_alias_string(envelope, &["agent_id", "agentId"]);
    if event_kind.requires_agent && agent_id.is_none() {
        bail!("{event_name} requires agent_id");
    }
    let event_id = optional_alias_string(envelope, &["event_id", "eventId", "hook_event_id"])
        .unwrap_or_else(|| stable_digest(&[raw_sha256, event_name]));
    let trace = hook_trace_context(
        envelope,
        session_id,
        turn_id.as_deref(),
        agent_id.as_deref(),
    );

    if event_kind.tool_event {
        return derive_hook_tool_event(envelope, event_name, event_id.as_str(), trace, max_bytes);
    }

    // A lifecycle hook attests that a boundary was observed, not that the
    // user's task succeeded. Tool success comes from codex.tool_result and
    // model completion comes from the captured Responses protocol.
    let status = event_kind.default_status.unwrap_or("unknown");
    let occurred_at = optional_alias_string(envelope, &["occurred_at", "occurredAt", "timestamp"]);
    let capture = json!({
        "recordType":"lifecycle_event",
        "captureId":format!("cap-cloud-{event_id}"),
        "captureStage":"event",
        "sourceNamespace":CLOUD_SOURCE_NAMESPACE,
        "requestedModelAlias":optional_alias_string(envelope, &["model", "model_name", "modelName"]),
        "isFinalSnapshot":event_kind.terminal,
        "traceContext":trace,
        "observedLifecycleEvents":[event_kind.lifecycle_type],
        "lifecycleEvent":{
            "event_id":format!("hook-{event_id}"),
            "type":event_kind.lifecycle_type,
            "status":status,
            "reason":value_alias(envelope, &["reason"]),
            "occurred_at":occurred_at,
            "source_event":envelope,
            "source_event_name":event_name
        }
    });
    Ok((vec![normalize_value(capture, max_bytes)?], 1, 0, Vec::new()))
}

#[derive(Debug, Clone, Copy)]
struct HookEventKind {
    lifecycle_type: &'static str,
    default_status: Option<&'static str>,
    terminal: bool,
    requires_turn: bool,
    requires_agent: bool,
    tool_event: bool,
}

fn known_hook_event(event_name: &str) -> Option<HookEventKind> {
    Some(match event_name {
        "SessionStart" => HookEventKind {
            lifecycle_type: "session_start",
            default_status: Some("started"),
            terminal: false,
            requires_turn: false,
            requires_agent: false,
            tool_event: false,
        },
        "SessionEnd" => HookEventKind {
            lifecycle_type: "session_end",
            // Stock Codex only reports that the Session closed. It does not
            // attest that the user's task succeeded.
            default_status: Some("closed"),
            terminal: true,
            requires_turn: false,
            requires_agent: false,
            tool_event: false,
        },
        "Stop" => HookEventKind {
            lifecycle_type: "turn_end",
            default_status: Some("closed"),
            terminal: false,
            requires_turn: true,
            requires_agent: false,
            tool_event: false,
        },
        "Interrupt" => HookEventKind {
            lifecycle_type: "turn_interrupt",
            default_status: Some("cancelled"),
            terminal: false,
            requires_turn: true,
            requires_agent: false,
            tool_event: false,
        },
        "SubagentStart" => HookEventKind {
            lifecycle_type: "subagent_spawn",
            default_status: Some("started"),
            terminal: false,
            requires_turn: true,
            requires_agent: true,
            tool_event: false,
        },
        "SubagentStop" => HookEventKind {
            lifecycle_type: "subagent_join",
            default_status: Some("closed"),
            terminal: false,
            requires_turn: true,
            requires_agent: true,
            tool_event: false,
        },
        "PreCompact" => HookEventKind {
            lifecycle_type: "compaction_start",
            default_status: Some("started"),
            terminal: false,
            requires_turn: true,
            requires_agent: false,
            tool_event: false,
        },
        "PostCompact" => HookEventKind {
            lifecycle_type: "compaction_end",
            default_status: Some("completed"),
            terminal: false,
            requires_turn: true,
            requires_agent: false,
            tool_event: false,
        },
        "UserPromptSubmit" => HookEventKind {
            lifecycle_type: "user_prompt_submit",
            default_status: Some("completed"),
            terminal: false,
            requires_turn: true,
            requires_agent: false,
            tool_event: false,
        },
        "PermissionRequest" => HookEventKind {
            lifecycle_type: "permission_request",
            default_status: Some("unknown"),
            terminal: false,
            requires_turn: true,
            requires_agent: false,
            tool_event: false,
        },
        "PreToolUse" => HookEventKind {
            lifecycle_type: "tool_start",
            default_status: Some("started"),
            terminal: false,
            requires_turn: true,
            requires_agent: false,
            tool_event: true,
        },
        "PostToolUse" => HookEventKind {
            lifecycle_type: "tool_end",
            default_status: Some("unknown"),
            terminal: false,
            requires_turn: true,
            requires_agent: false,
            tool_event: true,
        },
        _ => return None,
    })
}

fn validate_hook_fields(envelope: &Value, event_name: &str) -> Result<()> {
    let require_string = |field: &str| -> Result<()> {
        envelope
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .with_context(|| format!("{event_name} requires {field}"))?;
        Ok(())
    };
    match event_name {
        "SessionStart" => {
            require_string("model")?;
            require_string("permission_mode")?;
            require_string("source")?;
        }
        "SessionEnd" => require_string("reason")?,
        "UserPromptSubmit" => require_string("prompt")?,
        "PreCompact" | "PostCompact" => require_string("trigger")?,
        "SubagentStart" | "SubagentStop" => require_string("agent_type")?,
        "PermissionRequest" => {
            require_string("tool_name")?;
            if envelope.get("tool_input").is_none() {
                bail!("PermissionRequest requires tool_input");
            }
        }
        _ => {}
    }
    Ok(())
}

fn derive_hook_tool_event(
    envelope: &Value,
    event_name: &str,
    event_id: &str,
    trace: Value,
    max_bytes: usize,
) -> Result<DerivedBatch> {
    let tool_name = optional_alias_string(envelope, &["tool_name", "toolName", "name"])
        .context("tool event requires tool_name")?;
    let call_id = optional_alias_string(
        envelope,
        &[
            "tool_use_id",
            "toolUseId",
            "tool_call_id",
            "toolCallId",
            "call_id",
        ],
    )
    .context("tool event requires tool_use_id")?;
    let arguments = value_alias(envelope, &["tool_input", "toolInput", "arguments", "input"])
        .context("tool event requires tool_input")?;
    let is_post = event_name == "PostToolUse";
    let result = value_alias(
        envelope,
        &["tool_response", "toolResponse", "tool_output", "output"],
    );
    if is_post && result.is_none() {
        bail!("PostToolUse requires tool_response");
    }
    let status = if is_post {
        explicit_hook_status(envelope).unwrap_or("unknown")
    } else {
        "started"
    };
    if !matches!(
        status,
        "started" | "success" | "error" | "cancelled" | "timeout" | "unknown"
    ) {
        bail!("unsupported tool event status {status:?}");
    }
    let runtime_namespace =
        optional_alias_string(envelope, &["tool_namespace", "toolNamespace", "namespace"]);
    let name = canonical_runtime_tool_name(runtime_namespace.as_deref(), &tool_name);
    let capture = json!({
        "recordType":"tool_execution",
        "captureId":format!("cap-cloud-{event_id}"),
        "captureStage":"event",
        "sourceNamespace":CLOUD_SOURCE_NAMESPACE,
        "requestedModelAlias":optional_alias_string(envelope, &["model", "model_name", "modelName"]),
        "traceContext":trace,
        "toolExecution":{
            "call_id":call_id,
            "parent_call_id":optional_alias_string(envelope, &["parent_call_id", "parentCallId"]),
            "name":name,
            "runtime_tool":tool_name,
            "runtime_namespace":runtime_namespace,
            "status":status,
            "initiator":"runtime",
            "arguments":arguments,
            "result":result,
            "error":if matches!(status, "error" | "cancelled" | "timeout") { result.clone().unwrap_or(Value::Null) } else { Value::Null },
            "schema_provenance":{
                "source":"hook_tool_event",
                "source_complete":false,
                "reason":"Hook payload has no authoritative JSON Tool Schema; Assembly must join the observed Wire definition"
            },
            "started_at":optional_alias_string(envelope, &["started_at", "startedAt"]),
            "finished_at":optional_alias_string(envelope, &["finished_at", "finishedAt", "timestamp"]),
            "model_call_matched":false,
            "result_content_captured":is_post,
            "output_truncated":optional_alias_bool(envelope, &["output_truncated", "outputTruncated"]),
            "source_event_name":event_name,
            "source_event":envelope
        }
    });
    Ok((vec![normalize_value(capture, max_bytes)?], 1, 0, Vec::new()))
}

fn hook_trace_context(
    envelope: &Value,
    session_id: &str,
    turn_id: Option<&str>,
    agent_id: Option<&str>,
) -> Value {
    let mut trace = json!({
        "session_id":session_id,
        "thread_id":session_id,
        "conversation_id":session_id,
        "task_session_id":optional_alias_string(envelope, &["task_session_id", "taskSessionId"]),
        "root_session_id":optional_alias_string(envelope, &["root_session_id", "rootSessionId"]),
        "parent_session_id":optional_alias_string(envelope, &["parent_session_id", "parentSessionId"]),
        "goal_id":optional_alias_string(envelope, &["goal_id", "goalId"]),
        "turn_id":turn_id,
        "root_turn_id":optional_alias_string(envelope, &["root_turn_id", "rootTurnId"]).or_else(|| turn_id.map(str::to_owned)),
        "agent_id":agent_id,
        "branch_id":optional_alias_string(envelope, &["branch_id", "branchId"]),
        "previous_response_id":optional_alias_string(envelope, &["previous_response_id", "previousResponseId"]),
    });
    remove_null_fields(trace.as_object_mut().expect("trace object"));
    trace
}

fn explicit_hook_status(envelope: &Value) -> Option<&'static str> {
    if let Some(status) = optional_alias_string(envelope, &["status", "tool_status", "toolStatus"])
    {
        return match status.trim().to_ascii_lowercase().as_str() {
            "started" | "running" => Some("started"),
            "success" | "succeeded" | "completed" | "complete" => Some("success"),
            "error" | "failed" | "failure" => Some("error"),
            "cancelled" | "canceled" => Some("cancelled"),
            "timeout" | "timed_out" => Some("timeout"),
            "unknown" => Some("unknown"),
            _ => None,
        };
    }
    if optional_alias_bool(envelope, &["is_error", "isError"]) == Some(true) {
        return Some("error");
    }
    if optional_alias_bool(envelope, &["success"]) == Some(true) {
        return Some("success");
    }
    if optional_alias_bool(envelope, &["success"]) == Some(false) {
        return Some("error");
    }
    None
}

fn optional_alias_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .filter(|item| !item.trim().is_empty())
            .map(str::to_owned)
    })
}

fn optional_alias_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|item| {
            item.as_bool().or_else(|| {
                item.as_str().and_then(|text| match text {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                })
            })
        })
    })
}

fn value_alias(value: &Value, keys: &[&str]) -> Option<Value> {
    keys.iter().find_map(|key| value.get(*key).cloned())
}

fn validate_otlp_traces(envelope: &Value) -> Result<u64> {
    if !envelope.get("resourceSpans").is_some_and(Value::is_array) {
        bail!("OTLP traces body requires resourceSpans");
    }
    Ok(count_nested_records(
        envelope,
        "resourceSpans",
        "scopeSpans",
        "spans",
    ))
}

fn trace_context(record: &Value, attributes: &BTreeMap<String, Value>, session_id: &str) -> Value {
    let mut trace = json!({
        "session_id":session_id,
        "thread_id":session_id,
        "conversation_id":session_id,
        "trace_id":optional_nonempty_string(record, "traceId"),
        "span_id":optional_nonempty_string(record, "spanId"),
        "parent_span_id":attribute_string(attributes, "parent.span_id")
            .or_else(|| attribute_string(attributes, "parent_span_id")),
        "turn_id":first_attribute_string(attributes, &["turn.id", "turn_id", "codex.turn_id"]),
        "root_turn_id":first_attribute_string(attributes, &["root_turn.id", "root_turn_id", "codex.root_turn_id"]),
        "agent_id":first_attribute_string(attributes, &["agent.id", "agent_id", "codex.agent_id"]),
        "branch_id":first_attribute_string(attributes, &["branch.id", "branch_id"]),
    });
    remove_null_fields(trace.as_object_mut().expect("trace object"));
    trace
}

fn attributes_map(attributes: Option<&Vec<Value>>) -> BTreeMap<String, Value> {
    let mut output = BTreeMap::new();
    for attribute in attributes.into_iter().flatten() {
        let Some(key) = attribute.get("key").and_then(Value::as_str) else {
            continue;
        };
        let Some(value) = attribute.get("value").map(otlp_any_value) else {
            continue;
        };
        output.insert(key.to_owned(), value);
    }
    output
}

fn otlp_any_value(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    if let Some(value) = object.get("stringValue") {
        return value.clone();
    }
    if let Some(value) = object.get("boolValue") {
        return value.clone();
    }
    if let Some(value) = object.get("intValue") {
        if let Some(integer) = value.as_i64() {
            return json!(integer);
        }
        if let Some(integer) = value.as_str().and_then(|value| value.parse::<i64>().ok()) {
            return json!(integer);
        }
        return value.clone();
    }
    if let Some(value) = object.get("doubleValue") {
        return value.clone();
    }
    if let Some(value) = object.get("bytesValue") {
        return value.clone();
    }
    if let Some(values) = object
        .get("arrayValue")
        .and_then(|value| value.get("values"))
        .and_then(Value::as_array)
    {
        return Value::Array(values.iter().map(otlp_any_value).collect());
    }
    if let Some(values) = object
        .get("kvlistValue")
        .and_then(|value| value.get("values"))
        .and_then(Value::as_array)
    {
        let mut map = Map::new();
        for item in values {
            if let (Some(key), Some(value)) =
                (item.get("key").and_then(Value::as_str), item.get("value"))
            {
                map.insert(key.to_owned(), otlp_any_value(value));
            }
        }
        return Value::Object(map);
    }
    value.clone()
}

fn record_timestamp(record: &Value, attributes: &BTreeMap<String, Value>) -> Option<String> {
    attribute_string(attributes, "event.timestamp")
        .map(str::to_owned)
        .or_else(|| {
            optional_nonempty_string(record, "timeUnixNano")
                .or_else(|| optional_nonempty_string(record, "observedTimeUnixNano"))
                .and_then(|value| value.parse::<i128>().ok())
                .and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
                .and_then(|timestamp| timestamp.format(&Rfc3339).ok())
        })
}

fn started_at(attributes: &BTreeMap<String, Value>, finished_at: Option<&str>) -> Option<String> {
    let duration_ms = attributes.get("duration_ms").and_then(value_u64)?;
    let finished = OffsetDateTime::parse(finished_at?, &Rfc3339).ok()?;
    let millis = i64::try_from(duration_ms).ok()?;
    finished
        .checked_sub(time::Duration::milliseconds(millis))?
        .format(&Rfc3339)
        .ok()
}

fn count_nested_records(value: &Value, outer: &str, middle: &str, inner: &str) -> u64 {
    value
        .get(outer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|outer| {
            outer
                .get(middle)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .map(|middle| {
            middle
                .get(inner)
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or_default() as u64
        })
        .sum()
}

fn normalize_value(value: Value, max_bytes: usize) -> Result<CaptureRecord> {
    normalize_capture(&serde_json::to_vec(&value)?, max_bytes)
}

fn required_attribute<'a>(attributes: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a str> {
    attribute_string(attributes, key).with_context(|| format!("{key} is required"))
}

fn attribute_string<'a>(attributes: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    attributes
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn first_attribute_string<'a>(
    attributes: &'a BTreeMap<String, Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| attribute_string(attributes, key))
}

fn attribute_bool(attributes: &BTreeMap<String, Value>, key: &str) -> Option<bool> {
    attributes.get(key).and_then(|value| {
        value.as_bool().or_else(|| {
            value.as_str().and_then(|value| match value {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            })
        })
    })
}

fn value_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn optional_nonempty_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn parse_json_string_or_clone(value: &Value) -> Value {
    value
        .as_str()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_else(|| value.clone())
}

fn remove_null_fields(object: &mut Map<String, Value>) {
    object.retain(|_, value| !value.is_null());
}

fn capture_id(kind: &str, components: &[&str]) -> String {
    format!(
        "cap-cloud-{}",
        stable_digest(&[&[kind], components].concat())
    )
}

fn stable_digest(components: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for component in components {
        hasher.update(component.len().to_be_bytes());
        hasher.update(component.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(key: &str, value: Value) -> Value {
        json!({"key":key,"value":value})
    }

    fn stock_logs(truncated: bool, success: bool) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "resourceLogs":[{
                "resource":{"attributes":[attr("service.name", json!({"stringValue":"codex"}))]},
                "scopeLogs":[{"scope":{"name":"codex_otel"},"logRecords":[
                    {
                        "timeUnixNano":"1788307200000000000",
                        "traceId":"0123456789abcdef0123456789abcdef",
                        "spanId":"1111111111111111",
                        "attributes":[
                            attr("event.name", json!({"stringValue":"codex.conversation_starts"})),
                            attr("conversation.id", json!({"stringValue":"session-1"})),
                            attr("model", json!({"stringValue":"gpt-5.6-sol"}))
                        ]
                    },
                    {
                        "timeUnixNano":"1788307201000000000",
                        "traceId":"0123456789abcdef0123456789abcdef",
                        "spanId":"2222222222222222",
                        "attributes":[
                            attr("event.name", json!({"stringValue":"codex.tool_result"})),
                            attr("conversation.id", json!({"stringValue":"session-1"})),
                            attr("model", json!({"stringValue":"gpt-5.6-sol"})),
                            attr("tool_name", json!({"stringValue":"exec_command"})),
                            attr("tool_namespace", json!({"stringValue":"functions"})),
                            attr("call_id", json!({"stringValue":"call-1"})),
                            attr("arguments", json!({"stringValue":"{\"cmd\":\"printf ok\"}"})),
                            attr("output", json!({"stringValue":"ok"})),
                            attr("duration_ms", json!({"intValue":"25"})),
                            attr("success", json!({"boolValue":success})),
                            attr("output_truncated", json!({"boolValue":truncated}))
                        ]
                    }
                ]}]
            }]
        }))
        .unwrap()
    }

    fn values(batch: &CloudIngestBatch) -> Vec<Value> {
        batch
            .records
            .iter()
            .map(|record| serde_json::from_slice(&record.canonical).unwrap())
            .collect()
    }

    #[test]
    fn stock_otlp_logs_preserve_raw_and_derive_strict_facts() {
        let raw = stock_logs(false, true);
        let batch = prepare_cloud_ingest(CloudEndpoint::OtlpLogs, &raw, 1024 * 1024).unwrap();
        let values = values(&batch);
        assert_eq!(batch.summary.source_records, 2);
        assert_eq!(batch.summary.derived_captures, 2);
        assert!(batch.summary.conversion_errors.is_empty());
        assert_eq!(values[0]["recordType"], "telemetry_batch");
        assert_eq!(
            values[0]["telemetryBatch"]["raw_json"],
            String::from_utf8(raw.clone()).unwrap()
        );
        assert_eq!(values[0]["telemetryBatch"]["raw_sha256"], sha256(&raw));
        assert_eq!(values[1]["lifecycleEvent"]["type"], "session_start");
        assert_eq!(values[2]["toolExecution"]["name"], "exec_command");
        assert_eq!(values[2]["toolExecution"]["arguments"]["cmd"], "printf ok");
        assert_eq!(values[2]["toolExecution"]["status"], "success");
        assert_eq!(values[2]["toolExecution"]["result_content_captured"], true);
        assert_eq!(
            values[2]["toolExecution"]["schema_provenance"]["source_complete"],
            false
        );

        let replay = prepare_cloud_ingest(CloudEndpoint::OtlpLogs, &raw, 1024 * 1024).unwrap();
        assert_eq!(
            batch
                .records
                .iter()
                .map(|record| (&record.capture_id, &record.sha256))
                .collect::<Vec<_>>(),
            replay
                .records
                .iter()
                .map(|record| (&record.capture_id, &record.sha256))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn tool_failure_uses_reported_boolean_and_truncation_fails_closed() {
        let batch = prepare_cloud_ingest(
            CloudEndpoint::OtlpLogs,
            &stock_logs(true, false),
            1024 * 1024,
        )
        .unwrap();
        let values = values(&batch);
        assert_eq!(values[2]["toolExecution"]["status"], "error");
        assert_eq!(values[2]["toolExecution"]["result_content_captured"], false);
        assert_eq!(values[2]["toolExecution"]["output_truncated"], true);
    }

    #[test]
    fn unknown_log_event_is_preserved_without_fabricated_projection() {
        let raw = serde_json::to_vec(&json!({
            "resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[
                attr("event.name", json!({"stringValue":"codex.future_event"})),
                attr("conversation.id", json!({"stringValue":"session-future"}))
            ]}]}]}]
        }))
        .unwrap();
        let batch = prepare_cloud_ingest(CloudEndpoint::OtlpLogs, &raw, 1024 * 1024).unwrap();
        assert_eq!(batch.records.len(), 2);
        assert_eq!(batch.summary.unknown_events, 1);
        let records = values(&batch);
        assert_eq!(records[1]["lifecycleEvent"]["type"], "telemetry_incomplete");
        assert_eq!(records[1]["lifecycleEvent"]["status"], "incomplete");
        assert_eq!(records[1]["traceContext"]["session_id"], "session-future");
    }

    #[test]
    fn current_stock_codex_observability_events_do_not_poison_a_session() {
        for event_name in [
            "codex.startup_phase",
            "codex.turn_ttft",
            "codex.turn_cost",
            "codex.plugin_install_elicitation_sent",
            "codex.plugin_install_suggestion",
            "codex.websocket_connect",
            "codex.websocket_request",
            "codex.auth_recovery",
            "codex.agent_communication",
        ] {
            let raw = serde_json::to_vec(&json!({
                "resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[
                    attr("event.name", json!({"stringValue":event_name})),
                    attr("conversation.id", json!({"stringValue":"session-current"}))
                ]}]}]}]
            }))
            .unwrap();
            let batch = prepare_cloud_ingest(CloudEndpoint::OtlpLogs, &raw, 1024 * 1024).unwrap();
            assert_eq!(batch.summary.source_records, 1, "{event_name}");
            assert_eq!(batch.summary.unknown_events, 0, "{event_name}");
            assert!(batch.summary.conversion_errors.is_empty(), "{event_name}");
            assert_eq!(batch.records.len(), 1, "{event_name}");
        }
    }

    #[test]
    fn codex_hooks_create_session_and_turn_lifecycle() {
        for (event, expected_type, expected_status) in [
            ("SessionStart", "session_start", "started"),
            ("SessionEnd", "session_end", "closed"),
            ("Stop", "turn_end", "closed"),
            ("Interrupt", "turn_interrupt", "cancelled"),
            ("SubagentStart", "subagent_spawn", "started"),
            ("SubagentStop", "subagent_join", "closed"),
        ] {
            let mut hook = json!({
                "hook_event_name":event,
                "session_id":"session-1",
                "turn_id":"turn-1",
                "agent_id":"agent-1",
                "agent_type":"worker",
                "model":"gpt-5.6-sol",
                "cwd":"/workspace",
                "permission_mode":"default",
                "source":"startup",
                "reason":"other",
                "stop_hook_active":false
            });
            if event == "SessionEnd" {
                hook.as_object_mut().unwrap().remove("model");
            }
            let raw = serde_json::to_vec(&hook).unwrap();
            let batch = prepare_cloud_ingest(CloudEndpoint::CodexHook, &raw, 1024 * 1024).unwrap();
            let values = values(&batch);
            assert_eq!(values.len(), 2);
            assert_eq!(values[1]["lifecycleEvent"]["type"], expected_type);
            assert_eq!(values[1]["lifecycleEvent"]["status"], expected_status);
        }
    }

    #[test]
    fn permission_hook_does_not_require_a_tool_call_id() {
        let raw = serde_json::to_vec(&json!({
            "hook_event_name":"PermissionRequest",
            "session_id":"session-1",
            "turn_id":"turn-1",
            "tool_name":"exec_command",
            "tool_input":{"cmd":"true"}
        }))
        .unwrap();
        let batch = prepare_cloud_ingest(CloudEndpoint::CodexHook, &raw, 1024 * 1024).unwrap();
        let records = values(&batch);
        assert_eq!(records[1]["lifecycleEvent"]["type"], "permission_request");
    }

    #[test]
    fn prompt_and_compaction_hooks_require_stock_codex_fields() {
        for raw in [
            br#"{"hook_event_name":"UserPromptSubmit","session_id":"s","turn_id":"t"}"#.as_slice(),
            br#"{"hook_event_name":"PreCompact","session_id":"s","turn_id":"t"}"#.as_slice(),
            br#"{"hook_event_name":"PostCompact","session_id":"s","turn_id":"t"}"#.as_slice(),
        ] {
            let batch = prepare_cloud_ingest(CloudEndpoint::CodexHook, raw, 1024 * 1024).unwrap();
            assert_eq!(batch.records.len(), 1);
            assert_eq!(batch.summary.conversion_errors.len(), 1);
        }
    }

    #[test]
    fn malformed_known_hook_is_raw_only_and_cannot_qualify() {
        let raw = br#"{"hook_event_name":"Stop","session_id":"session-1"}"#;
        let batch = prepare_cloud_ingest(CloudEndpoint::CodexHook, raw, 1024 * 1024).unwrap();
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.summary.conversion_errors, ["Stop requires turn_id"]);
    }

    #[test]
    fn otlp_traces_are_authoritative_raw_not_a_second_runtime_truth() {
        let raw = br#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"01"}]}]}]}"#;
        let batch = prepare_cloud_ingest(CloudEndpoint::OtlpTraces, raw, 1024 * 1024).unwrap();
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.summary.source_records, 1);
        let values = values(&batch);
        assert_eq!(values[0]["telemetryBatch"]["endpoint"], "otlp_traces");
    }
}
