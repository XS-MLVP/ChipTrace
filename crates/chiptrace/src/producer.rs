use crate::capture::{CaptureRecord, normalize_capture};
use crate::delivery::{DeliveryConfig, DeliveryTarget, deliver_batch};
use crate::tool_registry::{
    canonical_runtime_tool_name, canonical_tool_registry_sha256, validate_tool_registry_value,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const PRODUCER_EVENT_SCHEMA_VERSION: &str = "chiptrace.producer-event.v1";
pub const DETERMINISTIC_CAPTURE_IDENTITY: &str = "chiptrace.deterministic-capture.v1";
pub type ProducerTarget = DeliveryTarget;

#[derive(Debug, Clone)]
pub struct ProducerConfig {
    pub input: PathBuf,
    pub target: ProducerTarget,
    pub batch_records: usize,
    pub max_envelope_bytes: usize,
    pub request_timeout: Duration,
    pub retry_max_times: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProducerSummary {
    pub input: String,
    pub records_read: u64,
    pub durable: u64,
    pub duplicates: u64,
    pub lifecycle_events: u64,
    pub tool_executions: u64,
    pub evaluations: u64,
}

pub async fn submit_producer_events(config: ProducerConfig) -> Result<ProducerSummary> {
    if config.batch_records == 0 {
        bail!("producer batch size must be positive");
    }
    if config.retry_max_times < 20 {
        bail!("producer delivery requires at least 20 retry attempts");
    }
    let mut summary = ProducerSummary {
        input: config.input.to_string_lossy().into_owned(),
        ..ProducerSummary::default()
    };
    if config.input == Path::new("-") {
        let stdin = std::io::stdin();
        submit_reader(BufReader::new(stdin), &config, &mut summary).await?;
    } else {
        let input = config
            .input
            .canonicalize()
            .with_context(|| format!("resolve producer input {}", config.input.display()))?;
        if !input.is_file() {
            bail!("producer input is not a file: {}", input.display());
        }
        summary.input = input.to_string_lossy().into_owned();
        submit_reader(BufReader::new(File::open(input)?), &config, &mut summary).await?;
    }
    Ok(summary)
}

async fn submit_reader<R: BufRead>(
    mut reader: R,
    config: &ProducerConfig,
    summary: &mut ProducerSummary,
) -> Result<()> {
    let mut line = Vec::new();
    let mut batch = Vec::with_capacity(config.batch_records);
    let mut line_number = 0_u64;
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        line_number = line_number.saturating_add(1);
        if line.len() > config.max_envelope_bytes {
            bail!("producer input line {line_number} exceeds the envelope limit");
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record = prepare_producer_capture(&line, config.max_envelope_bytes)
            .with_context(|| format!("invalid producer event at line {line_number}"))?;
        update_summary_for_record(summary, &record)?;
        batch.push(record.canonical);
        summary.records_read = summary.records_read.saturating_add(1);
        if batch.len() >= config.batch_records {
            deliver_producer_batch(config, &batch, summary).await?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        deliver_producer_batch(config, &batch, summary).await?;
    }
    if summary.records_read == 0 {
        bail!("producer input contains no events");
    }
    Ok(())
}

async fn deliver_producer_batch(
    config: &ProducerConfig,
    batch: &[Vec<u8>],
    summary: &mut ProducerSummary,
) -> Result<()> {
    let receipt = deliver_batch(
        &DeliveryConfig {
            target: config.target.clone(),
            request_timeout: config.request_timeout,
            retry_max_times: config.retry_max_times,
        },
        batch,
    )
    .await?;
    summary.durable = summary.durable.saturating_add(receipt.durable);
    summary.duplicates = summary.duplicates.saturating_add(receipt.duplicates);
    Ok(())
}

pub fn prepare_producer_capture(raw: &[u8], max_envelope_bytes: usize) -> Result<CaptureRecord> {
    let mut value: Value = serde_json::from_slice(raw)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("producer event must be a JSON object"))?;
    let (record_type, expected_capture_id) = producer_capture_identity(object)?;
    if let Some(observed) = object.get("captureId").and_then(Value::as_str)
        && observed != expected_capture_id
    {
        bail!("captureId does not match the deterministic producer event identity");
    }
    object.insert("captureId".to_owned(), json!(expected_capture_id));
    object
        .entry("captureStage".to_owned())
        .or_insert_with(|| json!("event"));
    validate_stored_producer_capture(object, &expected_capture_id)?;
    if let Some(registry) = object.get("toolRegistry") {
        validate_tool_registry_value(registry)?;
        let registry_hash = canonical_tool_registry_sha256(registry)?;
        if let Some(observed) = object.get("toolRegistrySha256").and_then(Value::as_str)
            && observed != registry_hash
        {
            bail!("toolRegistrySha256 does not match toolRegistry");
        }
        object.insert("toolRegistrySha256".to_owned(), json!(registry_hash));
    }
    let timestamp = evidence_timestamp(object, &record_type)
        .ok_or_else(|| anyhow::anyhow!("producer event requires a real evidence timestamp"))?
        .to_owned();
    validate_timestamp(&timestamp, "producer event evidence timestamp")?;
    object
        .entry("receivedAt".to_owned())
        .or_insert_with(|| json!(timestamp));
    normalize_capture(&serde_json::to_vec(&value)?, max_envelope_bytes)
}

pub(crate) fn validate_stored_producer_capture(
    object: &Map<String, Value>,
    capture_id: &str,
) -> Result<()> {
    let (record_type, expected_capture_id) = producer_capture_identity(object)?;
    if capture_id != expected_capture_id {
        bail!("captureId does not match the deterministic producer event identity");
    }
    validate_event_evidence(object, &record_type)?;
    let timestamp = evidence_timestamp(object, &record_type)
        .ok_or_else(|| anyhow::anyhow!("producer event requires a real evidence timestamp"))?;
    validate_timestamp(timestamp, "producer event evidence timestamp")?;
    Ok(())
}

fn producer_capture_identity(object: &Map<String, Value>) -> Result<(String, String)> {
    let record_type = required_string(object, "recordType")?.to_owned();
    if !matches!(
        record_type.as_str(),
        "lifecycle_event" | "tool_execution" | "evaluation"
    ) {
        bail!("producer only accepts lifecycle_event, tool_execution, or evaluation");
    }
    let source_namespace = required_string(object, "sourceNamespace")?;
    let task_session_id = object
        .get("traceContext")
        .and_then(Value::as_object)
        .and_then(|trace| trace.get("task_session_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("producer event requires traceContext.task_session_id"))?;
    let producer_event = object
        .get("producerEvent")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("producerEvent is required"))?;
    validate_producer_event(producer_event)?;
    if required_string(producer_event, "identity_scheme")? != DETERMINISTIC_CAPTURE_IDENTITY {
        bail!("producer endpoint requires deterministic Capture identity");
    }
    let event_id = required_string(producer_event, "event_id")?;
    let producer = required_string(producer_event, "producer")?;
    let stream_id = required_string(producer_event, "stream_id")?;
    let sequence = producer_event["sequence"].as_u64().unwrap();
    Ok((
        record_type,
        deterministic_producer_capture_id(
            source_namespace,
            task_session_id,
            producer,
            stream_id,
            sequence,
            event_id,
        ),
    ))
}

pub fn prepare_producer_capture_batch(
    raw: &[u8],
    max_envelope_bytes: usize,
    max_records: usize,
) -> Result<Vec<CaptureRecord>> {
    if max_records == 0 {
        bail!("producer batch record limit must be positive");
    }
    let mut records = Vec::new();
    for (index, line) in raw.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records.len() >= max_records {
            bail!("producer batch contains more than {max_records} records");
        }
        records.push(
            prepare_producer_capture(line, max_envelope_bytes)
                .with_context(|| format!("invalid producer event at NDJSON line {}", index + 1))?,
        );
    }
    if records.is_empty() {
        bail!("producer event batch is empty");
    }
    Ok(records)
}

pub(crate) fn validate_producer_event_value(value: &Value) -> Result<()> {
    let event = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("producerEvent must be an object"))?;
    validate_producer_event(event)
}

fn validate_producer_event(event: &Map<String, Value>) -> Result<()> {
    if required_string(event, "schema_version")? != PRODUCER_EVENT_SCHEMA_VERSION {
        bail!("unsupported producerEvent.schema_version");
    }
    validate_safe_identifier(required_string(event, "event_id")?, "event_id")?;
    required_string(event, "producer")?;
    required_string(event, "producer_version")?;
    if !matches!(
        required_string(event, "identity_scheme")?,
        DETERMINISTIC_CAPTURE_IDENTITY | "source-native"
    ) {
        bail!("unsupported producerEvent.identity_scheme");
    }
    validate_safe_identifier(required_string(event, "stream_id")?, "stream_id")?;
    event
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("producerEvent.sequence is required"))?;
    Ok(())
}

fn validate_safe_identifier(value: &str, field: &str) -> Result<()> {
    if value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("producerEvent.{field} must be a safe identifier <= 256 bytes");
    }
    Ok(())
}

fn validate_event_evidence(object: &Map<String, Value>, record_type: &str) -> Result<()> {
    match record_type {
        "lifecycle_event" => {
            let event = object
                .get("lifecycleEvent")
                .and_then(Value::as_object)
                .ok_or_else(|| anyhow::anyhow!("lifecycleEvent is required"))?;
            let event_id = required_string(event, "event_id")?;
            if event_id
                != object
                    .get("producerEvent")
                    .and_then(|event| event.get("event_id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            {
                bail!("lifecycleEvent.event_id must equal producerEvent.event_id");
            }
            required_string(event, "type")?;
            required_string(event, "status")?;
            validate_timestamp(
                required_string(event, "occurred_at")?,
                "lifecycleEvent.occurred_at",
            )?;
        }
        "tool_execution" => {
            let execution = object
                .get("toolExecution")
                .and_then(Value::as_object)
                .ok_or_else(|| anyhow::anyhow!("toolExecution is required"))?;
            let status = required_string(execution, "status")?;
            for field in ["runtime_tool", "runtime_namespace"] {
                if let Some(value) = execution.get(field).filter(|value| !value.is_null()) {
                    required_string(execution, field)?;
                    if !value.is_string() {
                        bail!("toolExecution.{field} must be a string");
                    }
                }
            }
            if let Some(runtime_tool) = execution.get("runtime_tool").and_then(Value::as_str) {
                let runtime_namespace = execution.get("runtime_namespace").and_then(Value::as_str);
                let expected = canonical_runtime_tool_name(runtime_namespace, runtime_tool);
                if required_string(execution, "name")? != expected {
                    bail!("toolExecution runtime identity does not match name");
                }
            }
            if status == "unknown" {
                bail!("producer toolExecution.status must be observed, not unknown");
            }
            let started_at = required_string(execution, "started_at")?;
            let started_at = validate_timestamp(started_at, "toolExecution.started_at")?;
            if status != "started" {
                let finished_at = required_string(execution, "finished_at")?;
                let finished_at = validate_timestamp(finished_at, "toolExecution.finished_at")?;
                if finished_at < started_at {
                    bail!("toolExecution.finished_at precedes started_at");
                }
            } else if execution
                .get("finished_at")
                .is_some_and(|value| !value.is_null())
                || execution
                    .get("result")
                    .is_some_and(|value| !value.is_null())
                || execution.get("error").is_some_and(|value| !value.is_null())
            {
                bail!("started toolExecution cannot contain terminal evidence");
            }
        }
        "evaluation" => {
            let evidence = object
                .get("evaluationEvidence")
                .or_else(|| object.get("evaluation_evidence"))
                .and_then(Value::as_array)
                .filter(|items| !items.is_empty())
                .ok_or_else(|| anyhow::anyhow!("evaluationEvidence is required"))?;
            for item in evidence {
                let item = item
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("evaluationEvidence entries must be objects"))?;
                validate_timestamp(
                    required_string(item, "observed_at")?,
                    "evaluationEvidence.observed_at",
                )?;
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_timestamp(value: &str, field: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .with_context(|| format!("{field} must be an RFC3339 timestamp"))
}

fn evidence_timestamp<'a>(object: &'a Map<String, Value>, record_type: &str) -> Option<&'a str> {
    object
        .get("receivedAt")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| match record_type {
            "lifecycle_event" => object
                .get("lifecycleEvent")
                .and_then(|event| event.get("occurred_at"))
                .and_then(Value::as_str),
            "tool_execution" => object.get("toolExecution").and_then(|execution| {
                execution
                    .get("finished_at")
                    .or_else(|| execution.get("started_at"))
                    .and_then(Value::as_str)
            }),
            "evaluation" => object
                .get("evaluationEvidence")
                .or_else(|| object.get("evaluation_evidence"))
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(|item| item.get("observed_at"))
                .and_then(Value::as_str),
            _ => None,
        })
        .filter(|value| !value.trim().is_empty())
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{field} is required"))
}

fn deterministic_producer_capture_id(
    source_namespace: &str,
    task_session_id: &str,
    producer: &str,
    stream_id: &str,
    sequence: u64,
    event_id: &str,
) -> String {
    let mut digest = Sha256::new();
    for field in [source_namespace, task_session_id, producer, stream_id] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest.update(sequence.to_be_bytes());
    digest.update((event_id.len() as u64).to_be_bytes());
    digest.update(event_id.as_bytes());
    format!("cap-producer-{}", hex::encode(digest.finalize()))
}

fn update_summary_for_record(summary: &mut ProducerSummary, record: &CaptureRecord) -> Result<()> {
    let value: Value = serde_json::from_slice(&record.canonical)?;
    match value.get("recordType").and_then(Value::as_str) {
        Some("lifecycle_event") => {
            summary.lifecycle_events = summary.lifecycle_events.saturating_add(1)
        }
        Some("tool_execution") => {
            summary.tool_executions = summary.tool_executions.saturating_add(1)
        }
        Some("evaluation") => summary.evaluations = summary.evaluations.saturating_add(1),
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle(event_id: &str, status: &str) -> Value {
        json!({
            "recordType":"lifecycle_event",
            "sourceNamespace":"shadow-canary",
            "traceContext":{"task_session_id":"task-1","root_session_id":"task-1"},
            "producerEvent":{
                "schema_version":PRODUCER_EVENT_SCHEMA_VERSION,
                "event_id":event_id,
                "producer":"chiptrace-harness",
                "producer_version":"0.5.1",
                "identity_scheme":DETERMINISTIC_CAPTURE_IDENTITY,
                "stream_id":"harness-task-1",
                "sequence":1
            },
            "lifecycleEvent":{
                "event_id":event_id,"type":"task_start","status":status,
                "occurred_at":"2026-08-29T00:00:00Z"
            }
        })
    }

    #[test]
    fn deterministic_identity_is_stable_and_conflicting_override_is_rejected() {
        let raw = serde_json::to_vec(&lifecycle("start-1", "started")).unwrap();
        let first = prepare_producer_capture(&raw, 1024 * 1024).unwrap();
        let second = prepare_producer_capture(&raw, 1024 * 1024).unwrap();
        assert_eq!(first.capture_id, second.capture_id);
        assert_eq!(first.canonical, second.canonical);
        let mut conflicting = lifecycle("start-1", "started");
        conflicting["captureId"] = json!("cap-wrong");
        assert!(
            prepare_producer_capture(&serde_json::to_vec(&conflicting).unwrap(), 1024 * 1024)
                .is_err()
        );
        let mut altered: Value = serde_json::from_slice(&first.canonical).unwrap();
        altered["producerEvent"]["sequence"] = json!(2);
        assert!(normalize_capture(&serde_json::to_vec(&altered).unwrap(), 1024 * 1024).is_err());
    }

    #[test]
    fn tool_status_and_real_timestamps_are_required() {
        let tool = json!({
            "recordType":"tool_execution","sourceNamespace":"shadow-canary",
            "traceContext":{"task_session_id":"task-1"},
            "producerEvent":{"schema_version":PRODUCER_EVENT_SCHEMA_VERSION,
                "event_id":"tool-1-finished","producer":"tool-dispatcher","producer_version":"1",
                "identity_scheme":DETERMINISTIC_CAPTURE_IDENTITY,
                "stream_id":"dispatcher-task-1","sequence":2},
            "toolExecution":{
                "call_id":"call-1","name":"run_tests","status":"unknown","initiator":"assistant",
                "arguments":{"target":"workspace"},"started_at":"2026-08-29T00:00:01Z",
                "finished_at":"2026-08-29T00:00:02Z","result":"passed",
                "schema":{"name":"run_tests","description":"Run workspace tests.","parameters":{
                    "type":"object","properties":{"target":{"type":"string","description":"Target."}},
                    "required":["target"]
                }}
            }
        });
        assert!(
            prepare_producer_capture(&serde_json::to_vec(&tool).unwrap(), 1024 * 1024).is_err()
        );
        let mut observed = tool;
        observed["toolExecution"]["status"] = json!("success");
        prepare_producer_capture(&serde_json::to_vec(&observed).unwrap(), 1024 * 1024).unwrap();
    }

    #[tokio::test]
    async fn jsonl_submission_validates_and_reports_durable_records() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("events.jsonl");
        let output = temporary.path().join("captures.jsonl");
        let lines = format!(
            "{}\n{}\n",
            serde_json::to_string(&lifecycle("start-1", "started")).unwrap(),
            serde_json::to_string(&lifecycle("retry-1", "started")).unwrap()
        );
        std::fs::write(&input, lines).unwrap();
        let summary = submit_producer_events(ProducerConfig {
            input,
            target: ProducerTarget::Jsonl(output.clone()),
            batch_records: 1,
            max_envelope_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(1),
            retry_max_times: 20,
        })
        .await
        .unwrap();
        assert_eq!(summary.records_read, 2);
        assert_eq!(summary.durable, 2);
        assert_eq!(summary.lifecycle_events, 2);
        assert_eq!(std::fs::read_to_string(output).unwrap().lines().count(), 2);
    }

    #[test]
    fn producer_batch_assigns_ids_and_rejects_partial_or_empty_input() {
        let first = lifecycle("start-1", "started");
        let mut second = lifecycle("retry-1", "started");
        second["producerEvent"]["sequence"] = json!(2);
        let raw = format!(
            "{}\n{}\n",
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        let records = prepare_producer_capture_batch(raw.as_bytes(), 1024 * 1024, 2).unwrap();
        assert_eq!(records.len(), 2);
        assert_ne!(records[0].capture_id, records[1].capture_id);
        assert!(prepare_producer_capture_batch(raw.as_bytes(), 1024 * 1024, 1).is_err());
        assert!(prepare_producer_capture_batch(b"\n", 1024 * 1024, 1).is_err());
    }

    #[test]
    fn legacy_producer_wal_is_readable_but_not_accepted_as_new_input() {
        let legacy = json!({
            "version":"chiptrace.capture.v2",
            "recordType":"lifecycle_event",
            "captureId":"cap-legacy-producer",
            "sourceNamespace":"legacy",
            "traceContext":{"task_session_id":"task-legacy"},
            "producerEvent":{
                "schema_version":PRODUCER_EVENT_SCHEMA_VERSION,
                "event_id":"legacy-start",
                "producer":"legacy-harness",
                "producer_version":"0.4.0",
                "sequence":0
            },
            "lifecycleEvent":{
                "event_id":"legacy-start",
                "type":"task_start",
                "status":"started",
                "occurred_at":"2026-08-01T00:00:00Z"
            }
        });
        let raw = serde_json::to_vec(&legacy).unwrap();
        let recovered = crate::capture::validate_stored_capture(&raw).unwrap();
        assert_eq!(recovered.canonical, raw);
        assert!(prepare_producer_capture(&raw, 1024 * 1024).is_err());
        assert!(normalize_capture(&raw, 1024 * 1024).is_err());
    }
}
