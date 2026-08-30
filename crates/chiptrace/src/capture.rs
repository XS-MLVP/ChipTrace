use crate::tool_registry::{
    canonical_runtime_tool_name, canonical_tool_registry_sha256, validate_tool_registry_value,
};
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

pub const CAPTURE_SCHEMA_VERSION: &str = "chiptrace.capture.v2";

static CAPTURE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^cap-[A-Za-z0-9._:-]+$").unwrap());
static TRACEPARENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<version>[0-9a-fA-F]{2})-(?P<trace>[0-9a-fA-F]{32})-(?P<parent>[0-9a-fA-F]{16})-(?P<flags>[0-9a-fA-F]{2})(?:-.+)?$")
        .unwrap()
});

static SENSITIVE_HEADERS: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    BTreeSet::from([
        "api-key",
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    ])
});

#[derive(Debug, Clone)]
pub struct CaptureRecord {
    pub capture_id: String,
    pub canonical: Vec<u8>,
    pub sha256: String,
    pub legacy_raw_sha256: Option<String>,
    pub received_at: Option<String>,
    pub model: Option<String>,
}

impl CaptureRecord {
    pub fn matches_persisted_sha256(&self, persisted: &str) -> bool {
        self.sha256 == persisted || self.legacy_raw_sha256.as_deref() == Some(persisted)
    }
}

pub fn normalize_capture(raw: &[u8], max_bytes: usize) -> Result<CaptureRecord> {
    normalize_capture_with_policy(raw, max_bytes, true)
}

fn normalize_capture_with_policy(
    raw: &[u8],
    max_bytes: usize,
    enforce_current_producer_contract: bool,
) -> Result<CaptureRecord> {
    if raw.len() > max_bytes {
        bail!("capture envelope exceeds {max_bytes} bytes");
    }
    let mut value: Value = serde_json::from_slice(raw)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("capture envelope must be a JSON object"))?;
    let legacy_raw_sha256 = (object.get("version").and_then(Value::as_str)
        != Some(CAPTURE_SCHEMA_VERSION))
    .then(|| hex::encode(Sha256::digest(raw)));
    let capture_id = object
        .get("captureId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("captureId is required"))?;
    if capture_id.len() > 256 || !CAPTURE_ID.is_match(capture_id) {
        bail!("captureId must match cap-[A-Za-z0-9._:-]+ and be <= 256 bytes");
    }
    let capture_id = capture_id.to_owned();
    object
        .entry("recordType".to_owned())
        .or_insert_with(|| Value::String("api_snapshot".to_owned()));
    if enforce_current_producer_contract && let Some(producer_event) = object.get("producerEvent") {
        crate::producer::validate_producer_event_value(producer_event)?;
        if producer_event
            .get("identity_scheme")
            .and_then(Value::as_str)
            == Some(crate::producer::DETERMINISTIC_CAPTURE_IDENTITY)
        {
            crate::producer::validate_stored_producer_capture(object, &capture_id)?;
        }
    }
    validate_optional_string(object, "sourceNamespace")?;
    validate_optional_string(object, "receivedAt")?;
    validate_optional_string(object, "startedAt")?;
    validate_optional_string(object, "finishedAt")?;
    for field in ["requestHeaders", "responseHeaders"] {
        if object
            .get(field)
            .is_some_and(|value| !value.is_null() && !value.is_object())
        {
            bail!("{field} must be an object or null");
        }
    }
    validate_response_status(object.get("responseStatus"))?;
    if object
        .get("traceContext")
        .is_some_and(|value| !value.is_null() && !value.is_object())
    {
        bail!("traceContext must be an object or null");
    }
    if object.get("observedLifecycleEvents").is_some_and(|value| {
        !value.is_null()
            && value.as_array().is_none_or(|events| {
                events
                    .iter()
                    .any(|event| event.as_str().is_none_or(str::is_empty))
            })
    }) {
        bail!("observedLifecycleEvents must contain non-empty strings");
    }
    if object
        .get("evaluationEvidence")
        .or_else(|| object.get("evaluation_evidence"))
        .is_some_and(|value| {
            !value.is_null()
                && value
                    .as_array()
                    .is_none_or(|items| items.iter().any(|item| !item.is_object()))
        })
    {
        bail!("evaluationEvidence must contain JSON objects");
    }
    validate_lifecycle_event(object)?;
    validate_tool_execution(object)?;
    validate_tool_registry_snapshot(object)?;
    validate_evaluation_evidence(object)?;
    validate_rollout_event(object)?;

    normalize_body_fields(object)?;
    promote_protocol_fields(object)?;
    // Protocol promotion may obtain task_session_id from Codex metadata or an
    // explicit correlation header. Validate the record-specific contract only
    // after that promotion so valid event envelopes are not rejected merely
    // because the field was not duplicated at the top level.
    validate_record_type(object)?;
    validate_trace_context(object)?;
    validate_field_evidence(object)?;
    validate_gateway_evidence(object)?;
    let redacted = sanitize_headers(object);
    object.insert(
        "version".to_owned(),
        Value::String(CAPTURE_SCHEMA_VERSION.to_owned()),
    );
    object.insert(
        "redactedHeaders".to_owned(),
        Value::Array(redacted.into_iter().map(Value::String).collect()),
    );
    object
        .entry("traceContext".to_owned())
        .or_insert_with(|| json!({}));
    object
        .entry("observedLifecycleEvents".to_owned())
        .or_insert_with(|| json!([]));
    object
        .entry("requestTruncated".to_owned())
        .or_insert(Value::Bool(false));
    object
        .entry("responseTruncated".to_owned())
        .or_insert(Value::Bool(false));
    object
        .entry("stream".to_owned())
        .or_insert(Value::Bool(false));
    object
        .entry("captureError".to_owned())
        .or_insert(Value::Null);

    let received_at = ["receivedAt", "finishedAt", "startedAt"]
        .into_iter()
        .find_map(|field| {
            object
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        });
    if object.get("receivedAt").is_none_or(Value::is_null) {
        object.insert(
            "receivedAt".to_owned(),
            received_at
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
    }
    let model = extract_body(object.get("requestBody"))
        .and_then(Value::as_object)
        .and_then(|body| body.get("model"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let canonical = serde_json::to_vec(&value)?;
    if canonical.len() > max_bytes {
        bail!("normalized capture envelope exceeds {max_bytes} bytes");
    }
    let sha256 = hex::encode(Sha256::digest(&canonical));
    Ok(CaptureRecord {
        capture_id,
        canonical,
        sha256,
        legacy_raw_sha256,
        received_at,
        model,
    })
}

pub fn normalize_capture_batch(
    raw: &[u8],
    max_envelope_bytes: usize,
    max_records: usize,
) -> Result<Vec<CaptureRecord>> {
    if max_records == 0 {
        bail!("batch record limit must be positive");
    }
    let mut records = Vec::new();
    for (index, line) in raw.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records.len() >= max_records {
            bail!("batch contains more than {max_records} records");
        }
        records.push(
            normalize_capture(line, max_envelope_bytes)
                .with_context(|| format!("invalid capture at NDJSON line {}", index + 1))?,
        );
    }
    if records.is_empty() {
        bail!("capture batch is empty");
    }
    Ok(records)
}

pub fn validate_stored_capture(raw: &[u8]) -> Result<CaptureRecord> {
    let value: Value = serde_json::from_slice(raw)?;
    // Run the current structural validator, but retain the exact historical
    // bytes. WAL locators and hashes must never change during migration.
    let _ = normalize_capture_with_policy(raw, raw.len().saturating_add(1024 * 1024), false)?;
    let capture_id = value
        .get("captureId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("captureId is required"))?
        .to_owned();
    let received_at = ["receivedAt", "finishedAt", "startedAt"]
        .into_iter()
        .find_map(|field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
                .map(str::to_owned)
        });
    let model = extract_body(value.get("requestBody"))
        .and_then(Value::as_object)
        .and_then(|body| body.get("model"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(CaptureRecord {
        capture_id,
        canonical: raw.to_vec(),
        sha256: hex::encode(Sha256::digest(raw)),
        legacy_raw_sha256: None,
        received_at,
        model,
    })
}

pub fn extract_body(value: Option<&Value>) -> Option<&Value> {
    let value = value?;
    match value.get("kind").and_then(Value::as_str) {
        Some("json" | "text" | "binary" | "sse") => value.get("value"),
        _ => Some(value),
    }
}

fn normalize_body_fields(object: &mut Map<String, Value>) -> Result<()> {
    for (text_field, body_field, bytes_field, sha_field) in [
        (
            "requestBodyText",
            "requestBody",
            "requestBytesCaptured",
            "requestBodySha256",
        ),
        (
            "responseBodyText",
            "responseBody",
            "responseBytesCaptured",
            "responseBodySha256",
        ),
    ] {
        if !object.contains_key(text_field) {
            continue;
        }
        let text = match object.remove(text_field).unwrap_or(Value::Null) {
            Value::Null => String::new(),
            Value::String(text) => text,
            _ => bail!("{text_field} must be a string or null"),
        };
        let body = match serde_json::from_str::<Value>(&text) {
            Ok(value) => json!({"kind": "json", "value": value, "raw": text}),
            Err(_) => json!({"kind": "text", "value": text}),
        };
        let bytes = text.len() as u64;
        let digest = hex::encode(Sha256::digest(text.as_bytes()));
        object.insert(body_field.to_owned(), body);
        object
            .entry(bytes_field.to_owned())
            .or_insert_with(|| Value::from(bytes));
        object.insert(sha_field.to_owned(), Value::String(digest));
    }
    for (body_field, bytes_field, sha_field) in [
        ("requestBody", "requestBytesCaptured", "requestBodySha256"),
        (
            "responseBody",
            "responseBytesCaptured",
            "responseBodySha256",
        ),
    ] {
        validate_embedded_raw_body(object, body_field, bytes_field, sha_field)?;
    }
    Ok(())
}

fn validate_embedded_raw_body(
    object: &mut Map<String, Value>,
    body_field: &str,
    bytes_field: &str,
    sha_field: &str,
) -> Result<()> {
    let Some(body) = object.get(body_field).and_then(Value::as_object) else {
        return Ok(());
    };
    let Some(raw) = body.get("raw").and_then(Value::as_str) else {
        return Ok(());
    };
    if body.get("kind").and_then(Value::as_str) == Some("json") {
        let parsed: Value = serde_json::from_str(raw)
            .with_context(|| format!("{body_field}.raw must contain valid JSON"))?;
        if body.get("value") != Some(&parsed) {
            bail!("{body_field}.raw does not match parsed value");
        }
    }
    let raw_len = raw.len() as u64;
    if object
        .get(bytes_field)
        .and_then(Value::as_u64)
        .is_some_and(|declared| declared != raw_len)
    {
        bail!("{bytes_field} does not match {body_field}.raw");
    }
    let digest = hex::encode(Sha256::digest(raw.as_bytes()));
    if object
        .get(sha_field)
        .and_then(Value::as_str)
        .is_some_and(|declared| declared != digest)
    {
        bail!("{sha_field} does not match {body_field}.raw");
    }
    object
        .entry(bytes_field.to_owned())
        .or_insert_with(|| Value::from(raw_len));
    object
        .entry(sha_field.to_owned())
        .or_insert_with(|| Value::String(digest));
    Ok(())
}

#[derive(Debug, Clone)]
struct FieldCandidate {
    value: Value,
    source: String,
    producer: &'static str,
    authority: &'static str,
}

fn promote_protocol_fields(object: &mut Map<String, Value>) -> Result<()> {
    let existing_evidence_fields: BTreeSet<String> = object
        .get("fieldEvidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("field").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    let request = extract_body(object.get("requestBody"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let metadata = request
        .get("client_metadata")
        .or_else(|| request.get("metadata"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let turn_metadata = metadata
        .get("x-codex-turn-metadata")
        .and_then(Value::as_str)
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    let top_level = object.clone();
    let captured = object
        .get("traceContext")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let request_headers = object
        .get("requestHeaders")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut by_field: BTreeMap<String, Vec<FieldCandidate>> = BTreeMap::new();
    for (field, aliases) in trace_aliases() {
        if !existing_evidence_fields.contains(&format!("traceContext.{field}")) {
            append_object_candidates(
                &mut by_field,
                field,
                &captured,
                aliases,
                "capture.traceContext",
                "capture_producer",
                "producer_asserted",
            );
        }
        if let Some(header) = chiptrace_header(field)
            && let Some(value) = header_value(&request_headers, header)
        {
            append_candidate(
                &mut by_field,
                field,
                Value::String(value.to_owned()),
                format!("requestHeaders.{header}"),
                "agent_harness",
                "client_asserted",
            );
        }
        append_object_candidates(
            &mut by_field,
            field,
            &top_level,
            aliases,
            "capture",
            "capture_producer",
            "producer_asserted",
        );
        append_object_candidates(
            &mut by_field,
            field,
            &metadata,
            aliases,
            "requestBody.client_metadata",
            "codex_client",
            "client_asserted",
        );
        append_object_candidates(
            &mut by_field,
            field,
            &turn_metadata,
            aliases,
            "requestBody.client_metadata.x-codex-turn-metadata",
            "codex_client",
            "client_asserted",
        );
        append_object_candidates(
            &mut by_field,
            field,
            &request,
            aliases,
            "requestBody",
            "codex_client",
            "client_asserted",
        );
    }
    append_w3c_trace_context(&mut by_field, &request_headers);

    let mut trace = captured;
    let mut generated_evidence = Vec::new();
    let mut generated_conflicts = Vec::new();
    for (field, candidates) in by_field {
        let selected = trace
            .get(&field)
            .filter(|value| protocol_value_present(value))
            .cloned()
            .or_else(|| candidates.first().map(|candidate| candidate.value.clone()));
        if let Some(value) = &selected {
            trace.entry(field.clone()).or_insert_with(|| value.clone());
        }
        let distinct: BTreeSet<Vec<u8>> = candidates
            .iter()
            .filter_map(|candidate| serde_json::to_vec(&candidate.value).ok())
            .collect();
        if distinct.len() > 1 {
            generated_conflicts.push(json!({
                "field": format!("traceContext.{field}"),
                "evidence": candidates.iter().map(field_candidate_json).collect::<Vec<_>>(),
            }));
        }
        for candidate in &candidates {
            let mut evidence = field_candidate_json(candidate);
            evidence["field"] = json!(format!("traceContext.{field}"));
            evidence["selected"] = json!(selected.as_ref() == Some(&candidate.value));
            generated_evidence.push(evidence);
        }
    }
    object.insert("traceContext".to_owned(), Value::Object(trace));

    promote_request_id(
        object,
        "requestId",
        "x-client-request-id",
        "sub2api",
        &existing_evidence_fields,
        &mut generated_evidence,
    );
    promote_request_id(
        object,
        "upstreamRequestId",
        "x-request-id",
        "upstream_provider",
        &existing_evidence_fields,
        &mut generated_evidence,
    );
    merge_array_field(object, "fieldEvidence", generated_evidence);
    merge_array_field(object, "fieldEvidenceConflicts", generated_conflicts);

    if !object.contains_key("captureStage") {
        let request_present = object
            .get("requestBody")
            .is_some_and(|value| !value.is_null());
        let response_present = object
            .get("responseBody")
            .is_some_and(|value| !value.is_null());
        object.insert(
            "captureStage".to_owned(),
            Value::String(
                match (request_present, response_present) {
                    (true, true) => "combined",
                    (true, false) => "ingress",
                    (false, true) => "egress",
                    (false, false) => "event",
                }
                .to_owned(),
            ),
        );
    }
    Ok(())
}

fn trace_aliases() -> [(&'static str, &'static [&'static str]); 21] {
    [
        ("task_session_id", &["task_session_id", "taskSessionId"]),
        ("session_id", &["session_id", "sessionId"]),
        ("thread_id", &["thread_id", "threadId"]),
        ("conversation_id", &["conversation_id", "conversationId"]),
        ("trace_id", &["trace_id", "traceId"]),
        ("span_id", &["span_id", "spanId"]),
        ("parent_span_id", &["parent_span_id", "parentSpanId"]),
        ("task_id", &["task_id", "taskId"]),
        ("root_session_id", &["root_session_id", "rootSessionId"]),
        (
            "parent_session_id",
            &["parent_session_id", "parentSessionId"],
        ),
        ("goal_id", &["goal_id", "goalId"]),
        ("root_turn_id", &["root_turn_id", "rootTurnId"]),
        ("turn_id", &["turn_id", "turnId"]),
        ("agent_id", &["agent_id", "agentId"]),
        ("agent_path", &["agent_path", "agentPath", "agent_name"]),
        ("branch_id", &["branch_id", "branchId"]),
        (
            "previous_response_id",
            &["previous_response_id", "previousResponseId"],
        ),
        ("session_final", &["session_final", "sessionFinal"]),
        ("traceparent", &["traceparent"]),
        ("trace_flags", &["trace_flags", "traceFlags"]),
        ("tracestate", &["tracestate"]),
    ]
}

fn chiptrace_header(field: &str) -> Option<&'static str> {
    match field {
        "task_session_id" => Some("x-chiptrace-task-session-id"),
        "session_id" => Some("x-chiptrace-session-id"),
        "thread_id" => Some("x-chiptrace-thread-id"),
        "root_session_id" => Some("x-chiptrace-root-session-id"),
        "parent_session_id" => Some("x-chiptrace-parent-session-id"),
        "goal_id" => Some("x-chiptrace-goal-id"),
        "root_turn_id" => Some("x-chiptrace-root-turn-id"),
        "turn_id" => Some("x-chiptrace-turn-id"),
        "agent_id" => Some("x-chiptrace-agent-id"),
        "branch_id" => Some("x-chiptrace-branch-id"),
        "previous_response_id" => Some("x-chiptrace-previous-response-id"),
        _ => None,
    }
}

fn append_object_candidates(
    output: &mut BTreeMap<String, Vec<FieldCandidate>>,
    field: &str,
    object: &Map<String, Value>,
    aliases: &[&str],
    source_prefix: &str,
    producer: &'static str,
    authority: &'static str,
) {
    for alias in aliases {
        let Some(value) = object
            .get(*alias)
            .filter(|value| protocol_value_present(value))
        else {
            continue;
        };
        append_candidate(
            output,
            field,
            value.clone(),
            format!("{source_prefix}.{alias}"),
            producer,
            authority,
        );
    }
}

fn append_candidate(
    output: &mut BTreeMap<String, Vec<FieldCandidate>>,
    field: &str,
    value: Value,
    source: String,
    producer: &'static str,
    authority: &'static str,
) {
    output
        .entry(field.to_owned())
        .or_default()
        .push(FieldCandidate {
            value,
            source,
            producer,
            authority,
        });
}

fn protocol_value_present(value: &Value) -> bool {
    value.as_str().is_some_and(|value| !value.trim().is_empty()) || value.is_boolean()
}

fn append_w3c_trace_context(
    output: &mut BTreeMap<String, Vec<FieldCandidate>>,
    headers: &Map<String, Value>,
) {
    let Some(raw) = header_value(headers, "traceparent") else {
        return;
    };
    let Some(captures) = TRACEPARENT.captures(raw.trim()) else {
        return;
    };
    let version = captures.name("version").map(|value| value.as_str());
    let trace = captures.name("trace").map(|value| value.as_str());
    let parent = captures.name("parent").map(|value| value.as_str());
    if version == Some("ff")
        || trace.is_none_or(|value| value.chars().all(|character| character == '0'))
        || parent.is_none_or(|value| value.chars().all(|character| character == '0'))
    {
        return;
    }
    for (field, value) in [
        ("traceparent", Some(raw)),
        ("trace_id", trace),
        ("parent_span_id", parent),
        (
            "trace_flags",
            captures.name("flags").map(|value| value.as_str()),
        ),
    ] {
        if let Some(value) = value {
            append_candidate(
                output,
                field,
                Value::String(value.to_ascii_lowercase()),
                "requestHeaders.traceparent".to_owned(),
                "w3c_trace_context",
                "protocol_observed",
            );
        }
    }
    if let Some(value) = header_value(headers, "tracestate") {
        append_candidate(
            output,
            "tracestate",
            Value::String(value.to_owned()),
            "requestHeaders.tracestate".to_owned(),
            "w3c_trace_context",
            "protocol_observed",
        );
    }
}

fn field_candidate_json(candidate: &FieldCandidate) -> Value {
    json!({
        "value": candidate.value,
        "source": candidate.source,
        "producer": candidate.producer,
        "authority": candidate.authority,
    })
}

fn promote_request_id(
    object: &mut Map<String, Value>,
    field: &str,
    header: &str,
    producer: &str,
    existing_evidence_fields: &BTreeSet<String>,
    evidence: &mut Vec<Value>,
) {
    let existing = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    let request_observed = object
        .get("requestHeaders")
        .and_then(Value::as_object)
        .and_then(|headers| header_value(headers, header))
        .map(str::to_owned);
    let response_observed = object
        .get("responseHeaders")
        .and_then(Value::as_object)
        .and_then(|headers| header_value(headers, header))
        .map(str::to_owned);
    // The gateway may replace a client-supplied identifier and uses the
    // response value for billing. Preserve an explicit producer field first,
    // then prefer the value actually attested by the response.
    let observed = response_observed
        .clone()
        .or_else(|| request_observed.clone());
    let selected = existing.clone().or_else(|| observed.clone());
    if existing.is_none()
        && let Some(value) = &observed
    {
        object.insert(field.to_owned(), Value::String(value.clone()));
    }
    let producer_assertion = (!existing_evidence_fields.contains(field))
        .then_some(existing.clone())
        .flatten();
    for (value, source, authority) in [
        (
            producer_assertion,
            format!("capture.{field}"),
            "producer_asserted",
        ),
        (
            request_observed,
            format!("requestHeaders.{header}"),
            "protocol_observed",
        ),
        (
            response_observed,
            format!("responseHeaders.{header}"),
            "protocol_observed",
        ),
    ] {
        if let Some(value) = value {
            evidence.push(json!({
                "field": field,
                "value": value,
                "source": source,
                "producer": producer,
                "authority": authority,
                "selected": selected.as_deref() == Some(value.as_str()),
            }));
        }
    }
}

fn merge_array_field(object: &mut Map<String, Value>, field: &str, additions: Vec<Value>) {
    let mut values = object
        .remove(field)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    values.extend(additions);
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(serde_json::to_vec(value).unwrap_or_default()));
    object.insert(field.to_owned(), Value::Array(values));
}

fn header_value<'a>(headers: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name)
            .then(|| value.as_str())
            .flatten()
    })
}

fn sanitize_headers(object: &mut Map<String, Value>) -> BTreeSet<String> {
    let mut redacted = BTreeSet::new();
    for field in ["requestHeaders", "responseHeaders"] {
        let Some(headers) = object.get_mut(field).and_then(Value::as_object_mut) else {
            object.insert(field.to_owned(), json!({}));
            continue;
        };
        let names: Vec<String> = headers
            .keys()
            .filter(|name| SENSITIVE_HEADERS.contains(name.to_ascii_lowercase().as_str()))
            .cloned()
            .collect();
        for name in names {
            headers.remove(&name);
            redacted.insert(name.to_ascii_lowercase());
        }
    }
    if let Some(existing) = object.get("redactedHeaders").and_then(Value::as_array) {
        redacted.extend(existing.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    redacted
}

fn validate_optional_string(object: &Map<String, Value>, field: &str) -> Result<()> {
    if object
        .get(field)
        .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        bail!("{field} must be a string or null");
    }
    Ok(())
}

fn validate_response_status(value: Option<&Value>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let status = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .ok_or_else(|| anyhow::anyhow!("responseStatus must be an integer or null"))?;
    if !(100..=599).contains(&status) {
        bail!("responseStatus must be between 100 and 599");
    }
    Ok(())
}

fn validate_record_type(object: &Map<String, Value>) -> Result<()> {
    let Some(record_type) = object.get("recordType") else {
        return Ok(());
    };
    let Some(record_type) = record_type.as_str() else {
        bail!("recordType must be a string");
    };
    if !matches!(
        record_type,
        "api_snapshot" | "lifecycle_event" | "tool_execution" | "evaluation" | "rollout_event"
    ) {
        bail!("unsupported recordType {record_type:?}");
    }
    if matches!(
        record_type,
        "lifecycle_event" | "tool_execution" | "evaluation"
    ) {
        let source_namespace = object
            .get("sourceNamespace")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty());
        if source_namespace.is_none() {
            bail!("{record_type} requires a non-empty sourceNamespace");
        }
        let task_session_id = object
            .get("traceContext")
            .and_then(|trace| trace.get("task_session_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty());
        if task_session_id.is_none() {
            bail!("{record_type} requires traceContext.task_session_id");
        }
    }
    match record_type {
        "lifecycle_event" if !object.get("lifecycleEvent").is_some_and(Value::is_object) => {
            bail!("lifecycle_event requires lifecycleEvent")
        }
        "tool_execution" if !object.get("toolExecution").is_some_and(Value::is_object) => {
            bail!("tool_execution requires toolExecution")
        }
        "evaluation"
            if object
                .get("evaluationEvidence")
                .or_else(|| object.get("evaluation_evidence"))
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty) =>
        {
            bail!("evaluation requires at least one evaluationEvidence item")
        }
        "rollout_event" if !object.get("rolloutEvent").is_some_and(Value::is_object) => {
            bail!("rollout_event requires rolloutEvent")
        }
        _ => {}
    }
    Ok(())
}

fn validate_rollout_event(object: &Map<String, Value>) -> Result<()> {
    let Some(event) = object.get("rolloutEvent") else {
        return Ok(());
    };
    let event = event
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("rolloutEvent must be an object"))?;
    for field in [
        "schema_version",
        "source",
        "source_session_id",
        "source_line",
        "source_line_sha256",
        "classification",
    ] {
        event
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("rolloutEvent.{field} is required"))?;
    }
    if event.get("schema_version").and_then(Value::as_str) != Some("chiptrace.codex-rollout.v1") {
        bail!("rolloutEvent.schema_version is unsupported");
    }
    if !matches!(
        event.get("source").and_then(Value::as_str),
        Some("codex_rollout_jsonl" | "codex_rollout_trace_bundle")
    ) {
        bail!("rolloutEvent.source is unsupported");
    }
    if !matches!(
        event.get("classification").and_then(Value::as_str),
        Some("known" | "unknown")
    ) {
        bail!("rolloutEvent.classification must be known or unknown");
    }
    event
        .get("source_ordinal")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("rolloutEvent.source_ordinal is required"))?;
    let source_line = event["source_line"].as_str().unwrap();
    let digest = event["source_line_sha256"].as_str().unwrap();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("rolloutEvent.source_line_sha256 must be a SHA-256 hex digest");
    }
    if digest != hex::encode(Sha256::digest(source_line.as_bytes())) {
        bail!("rolloutEvent.source_line_sha256 does not match source_line");
    }
    if event.get("source").and_then(Value::as_str) == Some("codex_rollout_trace_bundle") {
        validate_native_bundle_evidence(event, source_line)?;
    }
    if object.get("rolloutMessages").is_some_and(|messages| {
        messages.as_array().is_none_or(|messages| {
            messages.iter().any(|message| {
                !message.is_object()
                    || !matches!(
                        message.get("role").and_then(Value::as_str),
                        Some("system" | "user" | "assistant" | "tool")
                    )
                    || message.get("content").is_none()
            })
        })
    }) {
        bail!("rolloutMessages must contain canonical messages");
    }
    if object
        .get("rolloutUsage")
        .is_some_and(|usage| !usage.is_object())
    {
        bail!("rolloutUsage must be an object");
    }
    Ok(())
}

fn validate_native_bundle_evidence(event: &Map<String, Value>, source_line: &str) -> Result<()> {
    let raw_event_sha256 = event
        .get("raw_event_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("native rolloutEvent.raw_event_sha256 is required"))?;
    if raw_event_sha256 != hex::encode(Sha256::digest(source_line.as_bytes())) {
        bail!("native rolloutEvent.raw_event_sha256 does not match source_line");
    }
    let manifest_raw = event
        .get("bundle_manifest_raw")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("native rolloutEvent.bundle_manifest_raw is required"))?;
    let manifest_sha256 = event
        .get("bundle_manifest_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("native rolloutEvent.bundle_manifest_sha256 is required"))?;
    if manifest_sha256 != hex::encode(Sha256::digest(manifest_raw.as_bytes())) {
        bail!("native rolloutEvent manifest SHA-256 does not match raw bytes");
    }
    serde_json::from_str::<Value>(manifest_raw)
        .context("native rolloutEvent.bundle_manifest_raw must be JSON")?;
    for (index, payload) in event
        .get("payloads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let payload = payload.as_object().ok_or_else(|| {
            anyhow::anyhow!("native rolloutEvent.payloads[{index}] must be an object")
        })?;
        for field in [
            "raw_payload_id",
            "path",
            "mirror_path",
            "raw_json",
            "sha256",
        ] {
            payload
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty() || field == "raw_json")
                .ok_or_else(|| {
                    anyhow::anyhow!("native rolloutEvent.payloads[{index}].{field} is required")
                })?;
        }
        let raw_json = payload["raw_json"].as_str().unwrap();
        serde_json::from_str::<Value>(raw_json).with_context(|| {
            format!("native rolloutEvent.payloads[{index}].raw_json must be JSON")
        })?;
        if payload["sha256"].as_str().unwrap() != hex::encode(Sha256::digest(raw_json.as_bytes())) {
            bail!("native rolloutEvent payload SHA-256 does not match raw bytes");
        }
        if payload.get("bytes").and_then(Value::as_u64) != Some(raw_json.len() as u64) {
            bail!("native rolloutEvent payload length does not match raw bytes");
        }
    }
    Ok(())
}

fn validate_lifecycle_event(object: &Map<String, Value>) -> Result<()> {
    let Some(event) = object.get("lifecycleEvent") else {
        return Ok(());
    };
    let event = event
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("lifecycleEvent must be an object"))?;
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("lifecycleEvent.type is required"))?;
    if event_type.len() > 128 {
        bail!("lifecycleEvent.type must be <= 128 bytes");
    }
    for field in ["event_id", "status", "reason", "occurred_at"] {
        validate_optional_string(event, field)?;
    }
    let normalized_type = event_type
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', ':'], "_");
    let terminal = matches!(
        normalized_type.as_str(),
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
    ) || normalized_type.starts_with("session_cancel")
        || normalized_type.starts_with("task_cancel")
        || normalized_type.starts_with("session_fail")
        || normalized_type.starts_with("task_fail");
    if terminal {
        let status = event
            .get("status")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("terminal lifecycleEvent requires status"))?;
        if !matches!(
            status.trim().to_ascii_lowercase().as_str(),
            "success"
                | "succeeded"
                | "completed"
                | "failed"
                | "error"
                | "cancelled"
                | "canceled"
                | "terminated"
                | "aborted"
                | "abandoned"
                | "incomplete"
        ) {
            bail!("unsupported terminal lifecycleEvent.status {status:?}");
        }
    }
    Ok(())
}

fn validate_tool_execution(object: &Map<String, Value>) -> Result<()> {
    let Some(execution) = object.get("toolExecution") else {
        return Ok(());
    };
    let execution = execution
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("toolExecution must be an object"))?;
    for field in ["call_id", "name", "status", "initiator"] {
        execution
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("toolExecution.{field} is required"))?;
    }
    let status = execution["status"].as_str().unwrap_or_default();
    if !matches!(
        status,
        "started" | "success" | "error" | "cancelled" | "timeout" | "unknown"
    ) {
        bail!("unsupported toolExecution.status {status:?}");
    }
    for field in ["parent_call_id", "started_at", "finished_at", "initiator"] {
        validate_optional_string(execution, field)?;
    }
    for field in ["runtime_tool", "runtime_namespace"] {
        validate_optional_string(execution, field)?;
    }
    if execution.get("arguments").is_none() {
        bail!("toolExecution.arguments is required");
    }
    if !matches!(
        execution["initiator"].as_str(),
        Some("assistant" | "runtime" | "user")
    ) {
        bail!("toolExecution.initiator must be assistant, runtime, or user");
    }
    let Some(schema) = execution.get("schema").and_then(Value::as_object) else {
        let provenance = execution
            .get("schema_provenance")
            .and_then(Value::as_object);
        if provenance
            .and_then(|value| value.get("source_complete"))
            .and_then(Value::as_bool)
            != Some(false)
            || provenance
                .and_then(|value| value.get("source"))
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty())
        {
            bail!(
                "toolExecution without a captured schema requires explicit incomplete schema_provenance"
            );
        }
        return validate_tool_execution_result(execution, status);
    };
    let runtime_tool = execution
        .get("runtime_tool")
        .and_then(Value::as_str)
        .or_else(|| schema.get("runtime_tool").and_then(Value::as_str));
    let runtime_namespace = execution
        .get("runtime_namespace")
        .and_then(Value::as_str)
        .or_else(|| schema.get("runtime_namespace").and_then(Value::as_str));
    if let Some(runtime_tool) = runtime_tool {
        let expected = canonical_runtime_tool_name(runtime_namespace, runtime_tool);
        if expected != execution["name"].as_str().unwrap_or_default() {
            bail!("toolExecution runtime identity does not match toolExecution.name");
        }
    }
    if schema.get("name").and_then(Value::as_str) != Some(execution["name"].as_str().unwrap()) {
        bail!("toolExecution.schema.name must equal toolExecution.name");
    }
    if schema
        .get("description")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        bail!("toolExecution.schema.description is required");
    }
    match (schema.get("parameters"), schema.get("format")) {
        (None, None) => {
            bail!("toolExecution.schema requires parameters or a native format");
        }
        (Some(parameters), _) => validate_tool_parameters(parameters)?,
        (None, Some(format)) => validate_tool_format(format)?,
    }
    validate_tool_execution_result(execution, status)
}

fn validate_tool_parameters(parameters: &Value) -> Result<()> {
    let parameters = parameters
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("toolExecution.schema.parameters must be an object"))?;
    if parameters.get("type").and_then(Value::as_str) != Some("object")
        || !parameters.get("properties").is_some_and(Value::is_object)
    {
        bail!("toolExecution.schema.parameters must be an object JSON Schema");
    }
    if parameters["properties"]
        .as_object()
        .unwrap()
        .values()
        .any(|property| {
            property.as_object().is_none_or(|definition| {
                let typed = definition.get("type").is_some()
                    || definition.get("oneOf").is_some()
                    || definition.get("anyOf").is_some()
                    || definition.get("$ref").is_some();
                let described = definition
                    .get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty());
                !typed || !described
            })
        })
    {
        bail!("toolExecution.schema parameter properties require type and description");
    }
    if parameters.get("required").is_some_and(|required| {
        required.as_array().is_none_or(|names| {
            names.iter().any(|name| {
                name.as_str().is_none_or(|name| {
                    !parameters["properties"]
                        .as_object()
                        .unwrap()
                        .contains_key(name)
                })
            })
        })
    }) {
        bail!("toolExecution.schema.parameters.required must reference defined properties");
    }
    Ok(())
}

fn validate_tool_format(format: &Value) -> Result<()> {
    let format = format
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("toolExecution.schema.format must be an object"))?;
    for field in ["type", "syntax", "definition"] {
        if format
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            bail!("toolExecution.schema.format.{field} is required");
        }
    }
    Ok(())
}

fn validate_tool_execution_result(execution: &Map<String, Value>, status: &str) -> Result<()> {
    if status == "success" && execution.get("result").is_none_or(Value::is_null) {
        bail!("successful toolExecution requires result");
    }
    if matches!(status, "error" | "cancelled" | "timeout")
        && execution.get("result").is_none_or(Value::is_null)
        && execution.get("error").is_none_or(Value::is_null)
    {
        bail!("failed toolExecution requires result or error");
    }
    Ok(())
}

fn validate_tool_registry_snapshot(object: &Map<String, Value>) -> Result<()> {
    let Some(registry) = object.get("toolRegistry") else {
        return Ok(());
    };
    validate_tool_registry_value(registry)?;
    let digest = canonical_tool_registry_sha256(registry)?;
    if let Some(observed) = object.get("toolRegistrySha256") {
        let observed = observed
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("toolRegistrySha256 must be a string"))?;
        if observed != digest {
            bail!("toolRegistrySha256 does not match toolRegistry");
        }
    }
    Ok(())
}

fn validate_evaluation_evidence(object: &Map<String, Value>) -> Result<()> {
    let Some(items) = object
        .get("evaluationEvidence")
        .or_else(|| object.get("evaluation_evidence"))
    else {
        return Ok(());
    };
    let items = items
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("evaluationEvidence must be an array"))?;
    for (index, item) in items.iter().enumerate() {
        let item = item
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("evaluationEvidence[{index}] must be an object"))?;
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("evaluationEvidence[{index}].kind is required"))?;
        if !matches!(
            kind,
            "test" | "build" | "search" | "user_correction" | "final_acceptance" | "evaluator"
        ) {
            bail!("unsupported evaluationEvidence[{index}].kind {kind:?}");
        }
        item.get("source")
            .and_then(Value::as_str)
            .filter(|source| !source.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("evaluationEvidence[{index}].source is required"))?;
        validate_optional_string(item, "status")?;
        validate_optional_string(item, "observed_at")?;
        if item.get("passed").is_some_and(|value| !value.is_boolean()) {
            bail!("evaluationEvidence[{index}].passed must be a boolean");
        }
        for field in ["reward", "score"] {
            if let Some(value) = item.get(field) {
                let value = value.as_f64().ok_or_else(|| {
                    anyhow::anyhow!("evaluationEvidence[{index}].{field} must be a number")
                })?;
                if !(0.0..=1.0).contains(&value) {
                    bail!("evaluationEvidence[{index}].{field} must be between 0 and 1");
                }
            }
        }
        if !["status", "passed", "reward", "score"]
            .iter()
            .any(|field| item.contains_key(*field))
        {
            bail!("evaluationEvidence[{index}] requires status, passed, reward, or score");
        }
    }
    Ok(())
}

fn validate_field_evidence(object: &Map<String, Value>) -> Result<()> {
    for field in ["fieldEvidence", "fieldEvidenceConflicts"] {
        let Some(items) = object.get(field) else {
            continue;
        };
        let items = items
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("{field} must be an array"))?;
        for (index, item) in items.iter().enumerate() {
            let item = item
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("{field}[{index}] must be an object"))?;
            item.get("field")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("{field}[{index}].field is required"))?;
            if field == "fieldEvidence" {
                for required in ["value", "source", "producer", "authority"] {
                    if !item.contains_key(required) {
                        bail!("{field}[{index}].{required} is required");
                    }
                }
                for required in ["source", "producer", "authority"] {
                    item.get(required)
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .ok_or_else(|| {
                            anyhow::anyhow!("{field}[{index}].{required} must be non-empty")
                        })?;
                }
                if item
                    .get("selected")
                    .is_some_and(|value| !value.is_boolean())
                {
                    bail!("{field}[{index}].selected must be a boolean");
                }
            } else if item
                .get("evidence")
                .and_then(Value::as_array)
                .is_none_or(|evidence| evidence.len() < 2)
            {
                bail!("{field}[{index}].evidence must contain conflicting candidates");
            }
        }
    }
    Ok(())
}

fn validate_gateway_evidence(object: &Map<String, Value>) -> Result<()> {
    for field in ["requestId", "upstreamRequestId", "captureStage"] {
        validate_optional_string(object, field)?;
    }
    if let Some(stage) = object.get("captureStage").and_then(Value::as_str)
        && !matches!(
            stage,
            "ingress" | "upstream_request" | "upstream_response" | "egress" | "combined" | "event"
        )
    {
        bail!("unsupported captureStage {stage:?}");
    }
    let Some(evidence) = object.get("gatewayEvidence") else {
        if object.contains_key("gatewayEvidenceJoin") {
            bail!("gatewayEvidenceJoin requires gatewayEvidence");
        }
        return Ok(());
    };
    let evidence = evidence
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("gatewayEvidence must be an object"))?;
    for field in ["source", "request_id", "requested_model", "provider"] {
        evidence
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("gatewayEvidence.{field} is required"))?;
    }
    if !matches!(
        evidence.get("source").and_then(Value::as_str),
        Some("sub2api_usage_log" | "sub2api.usage_logs")
    ) {
        bail!("gatewayEvidence.source must identify sub2api usage logs");
    }
    for field in [
        "upstream_model",
        "response_model",
        "model_mapping_chain",
        "provider_source",
        "observed_at",
    ] {
        validate_optional_string(evidence, field)?;
    }
    for field in [
        "user_id",
        "api_key_id",
        "account_id",
        "group_id",
        "channel_id",
        "usage_log_id",
    ] {
        if evidence.get(field).is_some_and(|value| {
            !value.is_null() && !value.is_string() && !value.is_i64() && !value.is_u64()
        }) {
            bail!("gatewayEvidence.{field} must be a string, integer, or null");
        }
    }
    for field in [
        "input_tokens",
        "api_input_tokens",
        "output_tokens",
        "cache_creation_tokens",
        "cache_read_tokens",
    ] {
        if evidence
            .get(field)
            .is_some_and(|value| value.as_u64().is_none())
        {
            bail!("gatewayEvidence.{field} must be a non-negative integer");
        }
    }
    if let Some(semantics) = evidence
        .get("input_tokens_semantics")
        .and_then(Value::as_str)
        && semantics != "sub2api_non_cached_input"
    {
        bail!("gatewayEvidence.input_tokens_semantics is unsupported");
    }
    if let (Some(input), Some(cached), Some(api_input)) = (
        evidence.get("input_tokens").and_then(Value::as_u64),
        evidence.get("cache_read_tokens").and_then(Value::as_u64),
        evidence.get("api_input_tokens").and_then(Value::as_u64),
    ) && api_input != input.saturating_add(cached)
    {
        bail!("gatewayEvidence.api_input_tokens is inconsistent");
    }
    if let Some(join) = object.get("gatewayEvidenceJoin") {
        validate_gateway_evidence_join(object, evidence, join)?;
    }
    Ok(())
}

fn validate_gateway_evidence_join(
    capture: &Map<String, Value>,
    evidence: &Map<String, Value>,
    join: &Value,
) -> Result<()> {
    let join = join
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("gatewayEvidenceJoin must be an object"))?;
    if join.get("schema_version").and_then(Value::as_str) != Some("chiptrace.gateway-enrichment.v1")
    {
        bail!("gatewayEvidenceJoin.schema_version is unsupported");
    }
    if join.get("mode").and_then(Value::as_str) != Some("exact_request_id") {
        bail!("gatewayEvidenceJoin.mode must be exact_request_id");
    }
    for field in [
        "request_id",
        "capture_request_id",
        "capture_field",
        "transform",
        "usage_fact_sha256",
    ] {
        join.get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("gatewayEvidenceJoin.{field} is required"))?;
    }
    let request_id = join["request_id"].as_str().unwrap();
    if evidence.get("request_id").and_then(Value::as_str) != Some(request_id) {
        bail!("gatewayEvidenceJoin.request_id must equal gatewayEvidence.request_id");
    }
    let captured = join["capture_request_id"].as_str().unwrap();
    let transformed = match join["transform"].as_str().unwrap() {
        "exact" => captured.to_owned(),
        "sub2api_client_prefix" => format!("client:{captured}"),
        value => bail!("unsupported gatewayEvidenceJoin.transform {value:?}"),
    };
    if transformed != request_id {
        bail!("gatewayEvidenceJoin request-id transformation does not match usage evidence");
    }
    let capture_field = join["capture_field"].as_str().unwrap();
    let observed = match capture_field {
        "upstreamRequestId" | "requestId" => capture.get(capture_field).and_then(Value::as_str),
        "requestHeaders.x-client-request-id" => capture
            .get("requestHeaders")
            .and_then(Value::as_object)
            .and_then(|headers| header_value(headers, "x-client-request-id")),
        "responseHeaders.x-client-request-id" => capture
            .get("responseHeaders")
            .and_then(Value::as_object)
            .and_then(|headers| header_value(headers, "x-client-request-id")),
        "responseHeaders.x-request-id" => capture
            .get("responseHeaders")
            .and_then(Value::as_object)
            .and_then(|headers| header_value(headers, "x-request-id")),
        value => bail!("unsupported gatewayEvidenceJoin.capture_field {value:?}"),
    };
    if observed != Some(captured) {
        bail!("gatewayEvidenceJoin.capture_request_id does not match the captured field");
    }
    let digest = join["usage_fact_sha256"].as_str().unwrap();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("gatewayEvidenceJoin.usage_fact_sha256 must be a SHA-256 hex digest");
    }
    if digest != gateway_evidence_fingerprint(&Value::Object(evidence.clone())) {
        bail!("gatewayEvidenceJoin.usage_fact_sha256 does not match gatewayEvidence");
    }
    Ok(())
}

pub(crate) fn gateway_evidence_fingerprint(value: &Value) -> String {
    let mut selected = Map::new();
    if let Some(object) = value.as_object() {
        for key in [
            "source",
            "request_id",
            "requested_model",
            "upstream_model",
            "response_model",
            "provider",
            "provider_source",
            "model_mapping_chain",
            "user_id",
            "api_key_id",
            "account_id",
            "group_id",
            "channel_id",
            "input_tokens",
            "api_input_tokens",
            "input_tokens_semantics",
            "output_tokens",
            "cache_creation_tokens",
            "cache_read_tokens",
            "observed_at",
            "usage_log_id",
        ] {
            if let Some(value) = object.get(key) {
                selected.insert(key.to_owned(), value.clone());
            }
        }
    }
    hex::encode(Sha256::digest(
        serde_json::to_vec(&Value::Object(selected)).unwrap_or_default(),
    ))
}

fn validate_trace_context(object: &Map<String, Value>) -> Result<()> {
    let Some(trace) = object.get("traceContext").and_then(Value::as_object) else {
        return Ok(());
    };
    for field in [
        "task_session_id",
        "session_id",
        "thread_id",
        "conversation_id",
        "trace_id",
        "span_id",
        "parent_span_id",
        "task_id",
        "root_session_id",
        "parent_session_id",
        "goal_id",
        "root_turn_id",
        "turn_id",
        "agent_id",
        "agent_path",
        "branch_id",
        "previous_response_id",
        "traceparent",
        "tracestate",
        "trace_flags",
    ] {
        validate_optional_string(trace, field)?;
    }
    if trace
        .get("session_final")
        .is_some_and(|value| !value.is_boolean())
    {
        bail!("traceContext.session_final must be a boolean");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_legacy_text_body_and_redacts_credentials() {
        let raw = br#"{
          "captureId":"cap-1",
          "requestHeaders":{"Authorization":"secret","x-id":"keep"},
          "requestBodyText":"{\"model\":\"gpt-5.6-sol\"}",
          "responseBodyText":"data: done",
          "responseStatus":500
        }"#;
        let record = normalize_capture(raw, 1024 * 1024).unwrap();
        let value: Value = serde_json::from_slice(&record.canonical).unwrap();
        assert_eq!(record.model.as_deref(), Some("gpt-5.6-sol"));
        assert_eq!(value["version"], CAPTURE_SCHEMA_VERSION);
        assert_eq!(value["recordType"], "api_snapshot");
        assert!(value["requestHeaders"].get("Authorization").is_none());
        assert_eq!(value["requestHeaders"]["x-id"], "keep");
        assert_eq!(value["responseStatus"], 500);
    }

    #[test]
    fn accepts_failure_cancel_and_retry_evidence_without_filtering() {
        let value = json!({
            "captureId":"cap-failed",
            "responseStatus":503,
            "captureError":"upstream cancelled",
            "observedLifecycleEvents":["retry","cancel"]
        });
        let record = normalize_capture(&serde_json::to_vec(&value).unwrap(), 1024).unwrap();
        let normalized: Value = serde_json::from_slice(&record.canonical).unwrap();
        assert_eq!(normalized["captureError"], "upstream cancelled");
        assert_eq!(
            normalized["observedLifecycleEvents"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn validates_structured_lifecycle_and_tool_execution_events() {
        let lifecycle = json!({
            "recordType":"lifecycle_event",
            "captureId":"cap-life-1",
            "sourceNamespace":"test",
            "traceContext":{"task_session_id":"task-1"},
            "lifecycleEvent":{"type":"task_end","status":"completed"}
        });
        normalize_capture(&serde_json::to_vec(&lifecycle).unwrap(), 4096).unwrap();

        let tool = json!({
            "recordType":"tool_execution",
            "captureId":"cap-tool-1",
            "sourceNamespace":"test",
            "traceContext":{"task_session_id":"task-1"},
            "toolExecution":{
                "call_id":"call-1",
                "name":"run_tests",
                "status":"success",
                "initiator":"assistant",
                "arguments":{"target":"workspace"},
                "schema":{
                    "name":"run_tests",
                    "description":"Run workspace tests.",
                    "parameters":{"type":"object","properties":{
                        "target":{"type":"string","description":"Workspace target."}
                    }}
                },
                "result":"2 tests passed"
            }
        });
        normalize_capture(&serde_json::to_vec(&tool).unwrap(), 4096).unwrap();

        let native_tool = json!({
            "recordType":"tool_execution",
            "captureId":"cap-tool-native-1",
            "sourceNamespace":"test",
            "traceContext":{"task_session_id":"task-1"},
            "toolExecution":{
                "call_id":"call-native-1",
                "name":"apply_patch",
                "status":"success",
                "initiator":"assistant",
                "arguments":"*** Begin Patch\n*** End Patch",
                "schema":{
                    "name":"apply_patch",
                    "description":"Apply a patch.",
                    "format":{
                        "type":"grammar",
                        "syntax":"lark",
                        "definition":"start: /.+/"
                    }
                },
                "result":"Done!"
            }
        });
        let native = normalize_capture(&serde_json::to_vec(&native_tool).unwrap(), 4096).unwrap();
        let native: Value = serde_json::from_slice(&native.canonical).unwrap();
        assert!(
            native["toolExecution"]["schema"]
                .get("parameters")
                .is_none()
        );
        assert_eq!(
            native["toolExecution"]["schema"]["format"]["syntax"],
            "lark"
        );

        let mut invalid_native = native_tool;
        invalid_native["captureId"] = json!("cap-tool-native-invalid");
        invalid_native["toolExecution"]["schema"]["format"]["definition"] = json!("");
        assert!(normalize_capture(&serde_json::to_vec(&invalid_native).unwrap(), 4096).is_err());

        let evaluation = json!({
            "recordType":"evaluation",
            "captureId":"cap-eval-valid",
            "sourceNamespace":"test",
            "traceContext":{"task_session_id":"task-1"},
            "evaluationEvidence":[{
                "kind":"test","source":"cargo test","status":"passed"
            }]
        });
        normalize_capture(&serde_json::to_vec(&evaluation).unwrap(), 4096).unwrap();

        let invalid = json!({
            "recordType":"tool_execution",
            "captureId":"cap-tool-2",
            "toolExecution":{"call_id":"call-2","name":"run_tests","status":"success","initiator":"assistant"}
        });
        assert!(normalize_capture(&serde_json::to_vec(&invalid).unwrap(), 4096).is_err());

        let invalid_evaluation = json!({
            "recordType":"evaluation",
            "captureId":"cap-eval-invalid",
            "sourceNamespace":"test",
            "traceContext":{"task_session_id":"task-1"},
            "evaluationEvidence":[{"kind":"test","source":"cargo test"}]
        });
        assert!(
            normalize_capture(&serde_json::to_vec(&invalid_evaluation).unwrap(), 4096).is_err()
        );

        let incomplete_end = json!({
            "recordType":"lifecycle_event",
            "captureId":"cap-life-2",
            "sourceNamespace":"test",
            "traceContext":{"task_session_id":"task-1"},
            "lifecycleEvent":{"type":"task_completed"}
        });
        assert!(normalize_capture(&serde_json::to_vec(&incomplete_end).unwrap(), 4096).is_err());
    }

    #[test]
    fn event_task_identity_may_arrive_in_a_protocol_header() {
        let event = json!({
            "version":CAPTURE_SCHEMA_VERSION,
            "recordType":"lifecycle_event",
            "captureId":"cap-life-header",
            "sourceNamespace":"test",
            "requestHeaders":{"X-ChipTrace-Task-Session-Id":"task-from-header"},
            "lifecycleEvent":{"type":"session_start","status":"started"}
        });
        let record = normalize_capture(&serde_json::to_vec(&event).unwrap(), 4096).unwrap();
        let normalized: Value = serde_json::from_slice(&record.canonical).unwrap();
        assert_eq!(
            normalized["traceContext"]["task_session_id"],
            "task-from-header"
        );
    }

    #[test]
    fn historical_wal_bytes_keep_their_original_hash() {
        let raw =
            br#"{"version":"full-trace-spool-v3","captureId":"cap-old","responseStatus":200}"#;
        let record = validate_stored_capture(raw).unwrap();
        assert_eq!(record.canonical, raw);
        assert_eq!(record.sha256, hex::encode(Sha256::digest(raw)));
    }

    #[test]
    fn captured_body_wrappers_are_unwrapped_for_assembly() {
        for kind in ["json", "text", "binary", "sse"] {
            let value = json!({"kind": kind, "value": "payload"});
            assert_eq!(extract_body(Some(&value)), Some(&json!("payload")));
        }
        let native = json!({"model": "gpt-5.6-sol"});
        assert_eq!(extract_body(Some(&native)), Some(&native));
    }

    #[test]
    fn promotes_codex_and_w3c_protocol_fields_with_provenance() {
        let turn_metadata = json!({
            "request_kind":"turn",
            "root_turn_id":"root-turn-1",
            "agent_name":"/root"
        })
        .to_string();
        let request = json!({
            "model":"gpt-5.6-sol",
            "previous_response_id":"resp-previous",
            "client_metadata":{
                "session_id":"codex-session",
                "thread_id":"codex-thread",
                "turn_id":"turn-1",
                "x-codex-turn-metadata":turn_metadata
            }
        });
        let value = json!({
            "captureId":"cap-protocol-fields",
            "requestHeaders":{
                "x-chiptrace-task-session-id":"task-1",
                "x-chiptrace-agent-id":"agent-root-id",
                "x-chiptrace-previous-response-id":"resp-previous",
                "traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                "tracestate":"vendor=value"
            },
            "responseHeaders":{
                "x-request-id":"upstream-request-1",
                "x-client-request-id":"client-request-1"
            },
            "requestBodyText":request.to_string(),
            "responseBodyText":"{}"
        });
        let normalized = normalize_capture(&serde_json::to_vec(&value).unwrap(), 1024 * 1024)
            .map(|record| serde_json::from_slice::<Value>(&record.canonical).unwrap())
            .unwrap();
        assert_eq!(normalized["traceContext"]["task_session_id"], "task-1");
        assert_eq!(normalized["traceContext"]["session_id"], "codex-session");
        assert_eq!(normalized["traceContext"]["thread_id"], "codex-thread");
        assert_eq!(normalized["traceContext"]["turn_id"], "turn-1");
        assert_eq!(normalized["traceContext"]["root_turn_id"], "root-turn-1");
        assert_eq!(normalized["traceContext"]["agent_id"], "agent-root-id");
        assert_eq!(normalized["traceContext"]["agent_path"], "/root");
        assert_eq!(
            normalized["traceContext"]["previous_response_id"],
            "resp-previous"
        );
        assert!(
            normalized["fieldEvidenceConflicts"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
        assert_eq!(
            normalized["traceContext"]["trace_id"],
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(
            normalized["traceContext"]["parent_span_id"],
            "00f067aa0ba902b7"
        );
        assert_eq!(normalized["requestId"], "client-request-1");
        assert_eq!(normalized["upstreamRequestId"], "upstream-request-1");
        assert_eq!(normalized["captureStage"], "combined");
        let evidence = normalized["fieldEvidence"].as_array().unwrap();
        assert!(evidence.iter().any(|item| {
            item["field"] == "traceContext.session_id"
                && item["source"] == "requestBody.client_metadata.session_id"
                && item["authority"] == "client_asserted"
        }));
        assert!(evidence.iter().any(|item| {
            item["field"] == "traceContext.trace_id"
                && item["source"] == "requestHeaders.traceparent"
                && item["authority"] == "protocol_observed"
        }));
    }

    #[test]
    fn response_request_identity_wins_when_gateway_rekeys_request() {
        let value = json!({
            "captureId":"cap-gateway-rekey",
            "requestHeaders":{
                "x-client-request-id":"forwarded-client-id",
                "x-request-id":"forwarded-request-id"
            },
            "responseHeaders":{
                "x-client-request-id":"gateway-client-id",
                "x-request-id":"upstream-request-id"
            },
            "requestBodyText":"{}",
            "responseBodyText":"{}"
        });
        let normalized = normalize_capture(&serde_json::to_vec(&value).unwrap(), 1024 * 1024)
            .map(|record| serde_json::from_slice::<Value>(&record.canonical).unwrap())
            .unwrap();

        assert_eq!(normalized["requestId"], "gateway-client-id");
        assert_eq!(normalized["upstreamRequestId"], "upstream-request-id");
        let evidence = normalized["fieldEvidence"].as_array().unwrap();
        assert!(evidence.iter().any(|item| {
            item["field"] == "requestId"
                && item["source"] == "requestHeaders.x-client-request-id"
                && item["value"] == "forwarded-client-id"
        }));
        assert!(evidence.iter().any(|item| {
            item["field"] == "requestId"
                && item["source"] == "responseHeaders.x-client-request-id"
                && item["value"] == "gateway-client-id"
        }));
    }

    #[test]
    fn canonical_v2_normalization_is_idempotent_across_relay_and_collector() {
        let value = json!({
            "captureId":"cap-normalize-idempotent",
            "requestHeaders":{
                "authorization":"Bearer must-not-survive",
                "x-chiptrace-task-session-id":"task-1",
                "x-chiptrace-turn-id":"turn-1",
                "traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            },
            "requestBodyText":"{\"model\":\"gpt-5.6-sol\"}",
            "responseBodyText":"{\"status\":\"completed\"}",
            "responseStatus":200
        });
        let first = normalize_capture(&serde_json::to_vec(&value).unwrap(), 1024 * 1024).unwrap();
        let second = normalize_capture(&first.canonical, 1024 * 1024).unwrap();

        assert_eq!(second.canonical, first.canonical);
        assert_eq!(second.sha256, first.sha256);
        let normalized: Value = serde_json::from_slice(&second.canonical).unwrap();
        assert!(normalized["requestHeaders"].get("authorization").is_none());
        assert_eq!(normalized["redactedHeaders"], json!(["authorization"]));
        assert_eq!(normalized["traceContext"]["task_session_id"], "task-1");
        assert_eq!(normalized["traceContext"]["turn_id"], "turn-1");
        let evidence = normalized["fieldEvidence"].as_array().unwrap();
        let unique = evidence
            .iter()
            .map(|value| serde_json::to_vec(value).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), evidence.len());
    }

    #[test]
    fn native_rollout_unicode_payload_keeps_raw_bytes_and_digest() {
        let source_line = r#"{"schema_version":1,"seq":1,"payload":{"type":"item_completed"}}"#;
        let manifest_raw = r#"{"schema_version":1,"trace_id":"trace-unicode"}"#;
        let payload_raw = "{\n  \"message\": \"后续继续执行，不改写原始字节。\"\n}";
        let source_digest = hex::encode(Sha256::digest(source_line.as_bytes()));
        let manifest_digest = hex::encode(Sha256::digest(manifest_raw.as_bytes()));
        let payload_digest = hex::encode(Sha256::digest(payload_raw.as_bytes()));
        let value = json!({
            "version":CAPTURE_SCHEMA_VERSION,
            "recordType":"rollout_event",
            "captureId":"cap-native-unicode",
            "sourceNamespace":"test",
            "traceContext":{"task_session_id":"task-unicode"},
            "rolloutEvent":{
                "schema_version":"chiptrace.codex-rollout.v1",
                "source":"codex_rollout_trace_bundle",
                "source_session_id":"rollout-unicode",
                "source_ordinal":1,
                "source_line":source_line,
                "source_line_sha256":source_digest,
                "raw_event_sha256":source_digest,
                "classification":"known",
                "bundle_manifest_raw":manifest_raw,
                "bundle_manifest_sha256":manifest_digest,
                "payloads":[{
                    "raw_payload_id":"raw-payload:1",
                    "path":"payloads/1.json",
                    "mirror_path":"trace-unicode/payloads/1.json",
                    "raw_json":payload_raw,
                    "sha256":payload_digest,
                    "bytes":payload_raw.len()
                }]
            }
        });

        let first = normalize_capture(&serde_json::to_vec(&value).unwrap(), 1024 * 1024).unwrap();
        let normalized: Value = serde_json::from_slice(&first.canonical).unwrap();
        let stored = normalized["rolloutEvent"]["payloads"][0]["raw_json"]
            .as_str()
            .unwrap();
        assert_eq!(stored.as_bytes(), payload_raw.as_bytes());
        assert_eq!(
            normalized["rolloutEvent"]["payloads"][0]["sha256"],
            payload_digest
        );
        assert_eq!(
            normalized["rolloutEvent"]["payloads"][0]["bytes"],
            payload_raw.len()
        );

        let second = normalize_capture(&first.canonical, 1024 * 1024).unwrap();
        assert_eq!(second.canonical, first.canonical);
        assert_eq!(second.sha256, first.sha256);
    }

    #[test]
    fn codex_thread_is_never_promoted_to_task_session() {
        let value = json!({
            "captureId":"cap-thread-only",
            "requestBody":{"kind":"json","value":{
                "model":"gpt-5.6-sol",
                "client_metadata":{
                    "session_id":"codex-session",
                    "thread_id":"codex-thread",
                    "turn_id":"turn-1"
                }
            }}
        });
        let normalized = normalize_capture(&serde_json::to_vec(&value).unwrap(), 4096)
            .map(|record| serde_json::from_slice::<Value>(&record.canonical).unwrap())
            .unwrap();
        assert_eq!(normalized["traceContext"]["session_id"], "codex-session");
        assert_eq!(normalized["traceContext"]["thread_id"], "codex-thread");
        assert!(normalized["traceContext"].get("task_session_id").is_none());
    }

    #[test]
    fn conflicting_protocol_ids_are_preserved_instead_of_overwritten() {
        let value = json!({
            "captureId":"cap-protocol-conflict",
            "traceContext":{"session_id":"producer-session"},
            "requestBody":{"kind":"json","value":{
                "client_metadata":{"session_id":"client-session"}
            }}
        });
        let normalized = normalize_capture(&serde_json::to_vec(&value).unwrap(), 4096)
            .map(|record| serde_json::from_slice::<Value>(&record.canonical).unwrap())
            .unwrap();
        assert_eq!(normalized["traceContext"]["session_id"], "producer-session");
        let conflicts = normalized["fieldEvidenceConflicts"].as_array().unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0]["field"], "traceContext.session_id");
        assert_eq!(conflicts[0]["evidence"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn validates_sub2api_gateway_evidence_shape_without_claiming_provider_attestation() {
        let value = json!({
            "captureId":"cap-gateway-evidence",
            "upstreamRequestId":"request-1",
            "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol"}},
            "gatewayEvidence":{
                "source":"sub2api_usage_log",
                "request_id":"request-1",
                "requested_model":"gpt-5.6-sol",
                "upstream_model":"gpt-5.6-sol",
                "provider":"OpenAI",
                "account_id":7,
                "channel_id":2,
                "cache_read_tokens":100
            }
        });
        normalize_capture(&serde_json::to_vec(&value).unwrap(), 4096).unwrap();

        let mut invalid = value;
        invalid["gatewayEvidence"]["source"] = json!("invented_proxy");
        assert!(normalize_capture(&serde_json::to_vec(&invalid).unwrap(), 4096).is_err());
    }

    #[test]
    fn validates_exact_gateway_join_and_evidence_digest() {
        let evidence = json!({
            "source":"sub2api_usage_log",
            "request_id":"client:client-1",
            "requested_model":"gpt-5.6-sol",
            "upstream_model":"gpt-5.6-sol",
            "response_model":null,
            "provider":"OpenAI",
            "model_mapping_chain":null
        });
        let digest = gateway_evidence_fingerprint(&evidence);
        let value = json!({
            "captureId":"cap-gateway-join",
            "requestId":"client-1",
            "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol"}},
            "gatewayEvidence":evidence,
            "gatewayEvidenceJoin":{
                "schema_version":"chiptrace.gateway-enrichment.v1",
                "mode":"exact_request_id",
                "request_id":"client:client-1",
                "capture_request_id":"client-1",
                "capture_field":"requestId",
                "transform":"sub2api_client_prefix",
                "usage_fact_sha256":digest
            }
        });
        normalize_capture(&serde_json::to_vec(&value).unwrap(), 8192).unwrap();
        let mut tampered = value;
        tampered["gatewayEvidence"]["upstream_model"] = json!("gpt-5.5");
        assert!(normalize_capture(&serde_json::to_vec(&tampered).unwrap(), 8192).is_err());
    }
}
