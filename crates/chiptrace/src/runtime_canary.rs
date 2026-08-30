//! Runtime canary backed by concrete tool executions.
//!
//! This is an operational acceptance probe, not training data. The canary is
//! itself the dispatcher for five versioned tools and records the results at
//! the same point where each operation actually completes.

use crate::harness::{
    EvaluationInput, Harness, HarnessConfig, HarnessInspection, HarnessTarget, ToolEndInput,
    ToolStartInput,
};
use crate::jsonl::{open_jsonl_reader, sha256_file, utc_now};
use crate::tool_registry::canonical_tool_registry_sha256;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::BufRead;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RuntimeCanaryConfig {
    pub state_root: PathBuf,
    pub source_namespace: String,
    pub relay_url: String,
    pub task_session_id: String,
    pub root_session_id: Option<String>,
    pub goal_id: Option<String>,
    pub agent_id: Option<String>,
    pub branch_id: Option<String>,
    pub collector_health_url: String,
    pub evidence_jsonl: PathBuf,
    pub expected_missing_path: PathBuf,
    pub retry_max_times: usize,
    pub request_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeCanaryToolOutcome {
    pub call_id: String,
    pub name: String,
    pub status: String,
    pub expectation_met: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeCanarySummary {
    pub ok: bool,
    pub task_session_id: String,
    pub tool_registry_sha256: String,
    pub tools: Vec<RuntimeCanaryToolOutcome>,
    pub flush: crate::harness::FlushSummary,
    pub inspection: HarnessInspection,
}

pub async fn run_runtime_canary(config: RuntimeCanaryConfig) -> Result<RuntimeCanarySummary> {
    if config.retry_max_times < 20 {
        bail!("runtime canary requires at least 20 delivery attempts");
    }
    if config.expected_missing_path.exists() {
        bail!(
            "expected missing path already exists: {}",
            config.expected_missing_path.display()
        );
    }
    let registry = runtime_canary_registry();
    let registry_sha256 = canonical_tool_registry_sha256(&registry)?;
    let mut harness_config = HarnessConfig::new(config.state_root, &config.source_namespace);
    harness_config.task_session_id = Some(config.task_session_id.clone());
    harness_config.root_session_id = Some(
        config
            .root_session_id
            .clone()
            .unwrap_or_else(|| config.task_session_id.clone()),
    );
    harness_config.goal_id = config.goal_id;
    harness_config.agent_id = config.agent_id;
    harness_config.branch_id = config.branch_id;
    harness_config.session_id = Some(config.task_session_id.clone());
    harness_config.target = Some(HarnessTarget::Relay(config.relay_url));
    harness_config.tool_registry = Some(registry);
    harness_config.retry_max_times = config.retry_max_times;
    harness_config.request_timeout = config.request_timeout;
    let mut harness = Harness::start(harness_config)?;
    let mut outcomes = Vec::with_capacity(5);

    let http_arguments = json!({"url":config.collector_health_url});
    start_tool(&mut harness, 1, "http_get_json", http_arguments)?;
    let http_outcome =
        match fetch_health_json(&config.collector_health_url, config.request_timeout).await {
            Ok(result) => finish_success(&mut harness, 1, "http_get_json", result, true)?,
            Err(error) => finish_error(&mut harness, 1, "http_get_json", &error, false)?,
        };
    outcomes.push(http_outcome);

    let metadata_arguments = json!({"path":config.evidence_jsonl});
    start_tool(&mut harness, 2, "read_file_metadata", metadata_arguments)?;
    let metadata_outcome = match fs::metadata(&config.evidence_jsonl) {
        Ok(metadata) if metadata.is_file() => finish_success(
            &mut harness,
            2,
            "read_file_metadata",
            json!({"bytes":metadata.len(),"is_file":true,"readonly":metadata.permissions().readonly()}),
            true,
        )?,
        Ok(metadata) => finish_success(
            &mut harness,
            2,
            "read_file_metadata",
            json!({"bytes":metadata.len(),"is_file":false,"readonly":metadata.permissions().readonly()}),
            false,
        )?,
        Err(error) => finish_io_error(&mut harness, 2, "read_file_metadata", &error, false)?,
    };
    outcomes.push(metadata_outcome);

    let validate_arguments = json!({"path":config.evidence_jsonl});
    start_tool(&mut harness, 3, "validate_jsonl", validate_arguments)?;
    let validate_outcome = match validate_jsonl(&config.evidence_jsonl) {
        Ok(result) => finish_success(&mut harness, 3, "validate_jsonl", result, true)?,
        Err(error) => finish_error(&mut harness, 3, "validate_jsonl", &error, false)?,
    };
    outcomes.push(validate_outcome);

    let sha_arguments = json!({"path":config.evidence_jsonl});
    start_tool(&mut harness, 4, "sha256_file", sha_arguments)?;
    let sha_outcome = match sha256_file(&config.evidence_jsonl) {
        Ok(sha256) => finish_success(
            &mut harness,
            4,
            "sha256_file",
            json!({"sha256":sha256}),
            true,
        )?,
        Err(error) => finish_error(&mut harness, 4, "sha256_file", &error, false)?,
    };
    outcomes.push(sha_outcome);

    let missing_arguments = json!({"path":config.expected_missing_path});
    start_tool(&mut harness, 5, "probe_missing_path", missing_arguments)?;
    let missing_outcome = match fs::metadata(&config.expected_missing_path) {
        Ok(metadata) => finish_success(
            &mut harness,
            5,
            "probe_missing_path",
            json!({"exists":true,"bytes":metadata.len()}),
            false,
        )?,
        Err(error) => {
            let expected = error.kind() == std::io::ErrorKind::NotFound;
            finish_io_error(&mut harness, 5, "probe_missing_path", &error, expected)?
        }
    };
    outcomes.push(missing_outcome);

    let ok = outcomes.iter().all(|outcome| outcome.expectation_met);
    harness.evaluate(EvaluationInput {
        kind: "test".to_owned(),
        source: "chiptrace runtime-canary concrete tool execution".to_owned(),
        status: Some(if ok { "passed" } else { "failed" }.to_owned()),
        passed: Some(ok),
        reward: None,
        score: None,
        artifact: Some(json!({"tools":outcomes,"observed_at":utc_now()})),
        observed_at: None,
    })?;
    harness.evaluate(EvaluationInput {
        kind: "final_acceptance".to_owned(),
        source: "chiptrace runtime-canary evaluator".to_owned(),
        status: Some(if ok { "accepted" } else { "rejected" }.to_owned()),
        passed: Some(ok),
        reward: Some(if ok { 1.0 } else { 0.0 }),
        score: Some(if ok { 1.0 } else { 0.0 }),
        artifact: Some(json!({
            "profile":"runtime-full-canary",
            "not_training_data":true,
            "tool_registry_sha256":registry_sha256,
        })),
        observed_at: None,
    })?;
    harness.task_end(
        if ok { "completed" } else { "failed" },
        Some("runtime canary concrete tool execution finished".to_owned()),
    )?;
    let flush = harness.flush().await?;
    let inspection = harness.inspect()?;
    if flush.pending_records != 0 {
        bail!(
            "runtime canary has {} events without durable Relay acknowledgement",
            flush.pending_records
        );
    }
    if !ok {
        bail!("runtime canary tool expectations failed: {outcomes:?}");
    }
    Ok(RuntimeCanarySummary {
        ok,
        task_session_id: config.task_session_id,
        tool_registry_sha256: registry_sha256,
        tools: outcomes,
        flush,
        inspection,
    })
}

fn start_tool(harness: &mut Harness, ordinal: u64, name: &str, arguments: Value) -> Result<()> {
    harness.tool_start(ToolStartInput {
        call_id: format!("runtime-canary-call-{ordinal}"),
        name: name.to_owned(),
        runtime_namespace: None,
        runtime_tool: None,
        arguments,
        schema: None,
        parent_call_id: None,
        initiator: "assistant".to_owned(),
        turn_id: Some(format!("runtime-canary-turn-{ordinal}")),
        started_at: None,
    })?;
    Ok(())
}

fn finish_success(
    harness: &mut Harness,
    ordinal: u64,
    name: &str,
    result: Value,
    expectation_met: bool,
) -> Result<RuntimeCanaryToolOutcome> {
    harness.tool_end(ToolEndInput {
        call_id: format!("runtime-canary-call-{ordinal}"),
        status: "success".to_owned(),
        result: Some(result.clone()),
        error: None,
        finished_at: None,
    })?;
    Ok(RuntimeCanaryToolOutcome {
        call_id: format!("runtime-canary-call-{ordinal}"),
        name: name.to_owned(),
        status: "success".to_owned(),
        expectation_met,
        result: Some(result),
        error: None,
    })
}

fn finish_error(
    harness: &mut Harness,
    ordinal: u64,
    name: &str,
    error: &anyhow::Error,
    expectation_met: bool,
) -> Result<RuntimeCanaryToolOutcome> {
    let evidence = json!({"kind":"runtime_error","message":error.to_string()});
    finish_error_value(harness, ordinal, name, evidence, expectation_met)
}

fn finish_io_error(
    harness: &mut Harness,
    ordinal: u64,
    name: &str,
    error: &std::io::Error,
    expectation_met: bool,
) -> Result<RuntimeCanaryToolOutcome> {
    let evidence = json!({
        "kind":"io_error",
        "message":error.to_string(),
        "io_error_kind":format!("{:?}", error.kind()),
        "raw_os_error":error.raw_os_error(),
    });
    finish_error_value(harness, ordinal, name, evidence, expectation_met)
}

fn finish_error_value(
    harness: &mut Harness,
    ordinal: u64,
    name: &str,
    error: Value,
    expectation_met: bool,
) -> Result<RuntimeCanaryToolOutcome> {
    harness.tool_end(ToolEndInput {
        call_id: format!("runtime-canary-call-{ordinal}"),
        status: "error".to_owned(),
        result: None,
        error: Some(error.clone()),
        finished_at: None,
    })?;
    Ok(RuntimeCanaryToolOutcome {
        call_id: format!("runtime-canary-call-{ordinal}"),
        name: name.to_owned(),
        status: "error".to_owned(),
        expectation_met,
        result: None,
        error: Some(error),
    })
}

async fn fetch_health_json(url: &str, timeout: Duration) -> Result<Value> {
    let response = reqwest::Client::builder()
        .timeout(timeout)
        .build()?
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if bytes.len() > 1024 * 1024 {
        bail!("health response exceeds 1 MiB");
    }
    let body: Value = serde_json::from_slice(&bytes).context("health response is not JSON")?;
    if !status.is_success() {
        bail!("health endpoint returned HTTP {status}: {body}");
    }
    if body.get("ok").and_then(Value::as_bool) != Some(true) {
        bail!("health endpoint did not attest ok=true: {body}");
    }
    Ok(json!({"http_status":status.as_u16(),"body":body}))
}

fn validate_jsonl(path: &std::path::Path) -> Result<Value> {
    let mut reader = open_jsonl_reader(path)?;
    let mut line = String::new();
    let mut records = 0_u64;
    let mut bytes = 0_u64;
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        if line.trim().is_empty() {
            continue;
        }
        serde_json::from_str::<Value>(&line)
            .with_context(|| format!("invalid JSONL record {}", records + 1))?;
        records = records.saturating_add(1);
    }
    if records == 0 {
        bail!("JSONL evidence has no records");
    }
    Ok(json!({"records":records,"bytes_read":bytes,"valid":true}))
}

fn runtime_canary_registry() -> Value {
    let tools = [
        (
            "http_get_json",
            "Fetch a health endpoint and require a JSON response with ok=true.",
            "url",
            "HTTP URL of the health endpoint.",
        ),
        (
            "read_file_metadata",
            "Read metadata for an evidence file from the local filesystem.",
            "path",
            "Absolute path of the evidence file.",
        ),
        (
            "validate_jsonl",
            "Parse every non-empty line in an evidence JSONL file.",
            "path",
            "Absolute path of the JSONL evidence file.",
        ),
        (
            "sha256_file",
            "Compute the SHA-256 digest of an evidence file.",
            "path",
            "Absolute path of the evidence file.",
        ),
        (
            "probe_missing_path",
            "Probe a path that the canary expects to be absent and retain the real IO error.",
            "path",
            "Absolute path expected to be absent.",
        ),
    ];
    json!({
        "schema_version":"chiptrace.tool-registry.v1",
        "producer":"chiptrace-runtime-canary",
        "producer_version":env!("CARGO_PKG_VERSION"),
        "captured_at":utc_now(),
        "tools":tools.into_iter().map(|(name, description, parameter, parameter_description)| json!({
            "runtime_item_type":"ChipTraceRuntimeCanaryTool",
            "runtime_tool":name,
            "tool":{
                "type":"function",
                "name":name,
                "description":description,
                "parameters":{
                    "type":"object",
                    "properties":{
                        parameter:{"type":"string","description":parameter_description}
                    },
                    "required":[parameter],
                    "additionalProperties":false
                }
            }
        })).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_registry::validate_tool_registry_value;

    #[test]
    fn runtime_canary_registry_is_complete_and_versioned() {
        let registry = runtime_canary_registry();
        validate_tool_registry_value(&registry).unwrap();
        let tools = registry["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 5);
        assert_eq!(
            tools
                .iter()
                .filter_map(|tool| tool.pointer("/tool/name").and_then(Value::as_str))
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            5
        );
        for tool in tools {
            let required = tool["tool"]["parameters"]["required"][0].as_str().unwrap();
            assert!(
                tool["tool"]["parameters"]["properties"]
                    .get(required)
                    .is_some()
            );
        }
    }

    #[test]
    fn jsonl_validator_reports_real_records() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        fs::write(&path, b"{\"one\":1}\n\n{\"two\":2}\n").unwrap();
        let result = validate_jsonl(&path).unwrap();
        assert_eq!(result["records"], 2);
        assert_eq!(result["valid"], true);
    }
}
