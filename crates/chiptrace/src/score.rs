use crate::jsonl::{canonical_bytes, string_field, u64_field};
use crate::schema::{
    ASSESSMENT_SCHEMA_VERSION, AcceptanceMetrics, BuyerAssessment, CaptureCompleteness, GateResult,
    QualityEnvelope, SemanticQuality, TokenCounts,
};
use clap::ValueEnum;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tiktoken_rs::o200k_base_singleton;

static GPT_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)gpt[-_ ]?(\d+)(?:[._-](\d+))?").unwrap());
static CLAUDE_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:claude|sonnet|opus)[-_ ]?(\d+)(?:[._-](\d+))?").unwrap());
static GEMINI_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)gemini[-_ ]?(\d+)(?:[._-](\d+))?").unwrap());
static DEEPSEEK_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)deepseek[-_ ]?(?:v)?(\d+)(?:[._-](\d+))?").unwrap());
static GLM_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)glm[-_ ]?(\d+)(?:[._-](\d+))?").unwrap());
static KIMI_K_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:kimi[-_ ]?)?k[-_ ]?(\d+)(?:[._-](\d+))?").unwrap());
static PUNCTUATION_ONLY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\p{P}\p{S}\s]+$").unwrap());
static ENVIRONMENT_SIGNAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:/[a-z0-9_.-]+/|[a-z]:\\|localhost|127\.0\.0\.1|:[0-9]{2,5}\b|\.[a-z0-9]{1,8}\b)",
    )
    .unwrap()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    #[value(name = "buyer-v6")]
    BuyerV6,
    #[value(name = "buyer-v7")]
    BuyerV7,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreSummary {
    pub profile: String,
    pub minimum_score: f64,
    pub records: u64,
    pub parse_failures: u64,
    pub eligible: u64,
    pub rejected: u64,
    pub average_score: f64,
    pub failure_reason_counts: BTreeMap<String, u64>,
    pub tokens: TokenCounts,
    pub eligible_tokens: TokenCounts,
}

pub fn score_jsonl(
    inputs: &[PathBuf],
    output: &Path,
    profile: Profile,
    minimum_score: f64,
    zstd_level: i32,
) -> anyhow::Result<ScoreSummary> {
    if !minimum_score.is_finite() || !(0.0..=100.0).contains(&minimum_score) {
        anyhow::bail!("minimum_score must be between 0 and 100");
    }
    let inputs = discover_score_inputs(inputs)?;
    if inputs.is_empty() {
        anyhow::bail!("no Session JSONL inputs found");
    }
    let mut writer = crate::jsonl::JsonlWriter::create(output, zstd_level)?;
    let mut summary = ScoreSummary {
        profile: profile.as_str().to_owned(),
        minimum_score,
        records: 0,
        parse_failures: 0,
        eligible: 0,
        rejected: 0,
        average_score: 0.0,
        failure_reason_counts: BTreeMap::new(),
        tokens: TokenCounts::default(),
        eligible_tokens: TokenCounts::default(),
    };
    let mut score_total = 0.0;
    for input in inputs {
        let mut reader = crate::jsonl::open_jsonl_reader(&input)?;
        let mut line = Vec::new();
        loop {
            line.clear();
            if std::io::BufRead::read_until(&mut reader, b'\n', &mut line)? == 0 {
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let session: Value = match serde_json::from_slice(&line) {
                Ok(value) => value,
                Err(_) => {
                    summary.parse_failures += 1;
                    continue;
                }
            };
            let quality = assess_session(&session, profile, minimum_score);
            summary.records += 1;
            score_total += quality.buyer_acceptance.score;
            summary.tokens.add_assign(&quality.buyer_acceptance.tokens);
            if quality.buyer_acceptance.eligible {
                summary.eligible += 1;
                summary
                    .eligible_tokens
                    .add_assign(&quality.buyer_acceptance.tokens);
            } else {
                summary.rejected += 1;
            }
            for reason in &quality.buyer_acceptance.failure_reasons {
                *summary
                    .failure_reason_counts
                    .entry(reason.clone())
                    .or_insert(0) += 1;
            }
            let release_decision = if quality.buyer_acceptance.eligible {
                "eligible"
            } else {
                "rejected"
            };
            writer.write_value(&json!({
                "trajectory_id": session.get("trajectory_id"),
                "session_id": session.get("session_id"),
                "provider": session.get("provider"),
                "model": session.get("model"),
                "quality": quality,
                "release_decision": release_decision,
                "content_fingerprint": exact_content_fingerprint(&session),
            }))?;
        }
    }
    writer.finish()?;
    if summary.records > 0 {
        summary.average_score = round(score_total / summary.records as f64, 3);
    }
    Ok(summary)
}

fn discover_score_inputs(inputs: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    let mut output = Vec::new();
    for input in inputs {
        if input.is_file() {
            output.push(input.canonicalize()?);
        } else if input.is_dir() {
            for entry in walkdir::WalkDir::new(input).follow_links(false) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    let name = entry.file_name().to_string_lossy();
                    if (name.ends_with(".jsonl") || name.ends_with(".jsonl.zst"))
                        && !entry.path().to_string_lossy().contains("/reports/")
                    {
                        output.push(entry.path().canonicalize()?);
                    }
                }
            }
        } else {
            anyhow::bail!("score input does not exist: {}", input.display());
        }
    }
    output.sort();
    output.dedup();
    Ok(output)
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuyerV6 => "buyer-v6",
            Self::BuyerV7 => "buyer-v7",
        }
    }

    pub fn version(self) -> &'static str {
        match self {
            Self::BuyerV6 => "buyer-v6.0-2026-05",
            Self::BuyerV7 => "buyer-v7.0-user-supplied",
        }
    }

    fn minimum_effective_turns(self) -> u64 {
        match self {
            Self::BuyerV6 => 2,
            Self::BuyerV7 => 10,
        }
    }

    fn minimum_tool_calls(self) -> u64 {
        match self {
            Self::BuyerV6 => 1,
            Self::BuyerV7 => 5,
        }
    }

    fn minimum_valid_results(self) -> u64 {
        match self {
            Self::BuyerV6 => 1,
            Self::BuyerV7 => 2,
        }
    }
}

#[derive(Debug, Clone)]
struct ToolCall {
    id: Option<String>,
    name: Option<String>,
    arguments_valid: bool,
    message_index: usize,
}

#[derive(Debug, Clone)]
struct ToolResult {
    id: Option<String>,
    valid: bool,
    failed: bool,
    explicit_status: bool,
    conflict: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserTurnKind {
    Human,
    Machine,
    Harness,
}

pub fn assess_session(session: &Value, profile: Profile, minimum_score: f64) -> QualityEnvelope {
    let messages = session
        .get("messages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let tools = session
        .get("tools")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let calls = collect_tool_calls(messages);
    let results = collect_tool_results(messages, profile);
    let result_by_id = results_by_id(&results);
    let last_message_index = messages.len().saturating_sub(1);
    let required_calls: Vec<&ToolCall> = calls
        .iter()
        .filter(|call| call.message_index != last_message_index)
        .collect();

    let mut paired_required = 0_u64;
    let mut required_call_ids = HashSet::new();
    let mut duplicate_call_ids = false;
    for call in &required_calls {
        if let Some(id) = call.id.as_deref() {
            duplicate_call_ids |= !required_call_ids.insert(id.to_owned());
            if result_by_id
                .get(id)
                .is_some_and(|matches| matches.len() == 1)
            {
                paired_required += 1;
            }
        }
    }
    let all_call_ids: HashSet<&str> = calls.iter().filter_map(|call| call.id.as_deref()).collect();
    let orphan_results = results
        .iter()
        .filter(|result| {
            result
                .id
                .as_deref()
                .is_none_or(|id| !all_call_ids.contains(id))
        })
        .count() as u64;
    let duplicate_result_ids = result_by_id.values().any(|matches| matches.len() > 1);
    let pairing_rate = if required_calls.is_empty() {
        1.0
    } else {
        paired_required as f64 / required_calls.len() as f64
    };

    let definition_map = tool_definition_map(tools);
    let called_names: BTreeSet<String> =
        calls.iter().filter_map(|call| call.name.clone()).collect();
    let complete_called_definitions = called_names
        .iter()
        .filter(|name| {
            definition_map
                .get(*name)
                .is_some_and(|value| tool_definition_complete(value, profile))
        })
        .count() as u64;
    let generic_called_names = called_names.iter().any(|name| generic_tool_name(name));
    let invalid_tool_arguments = calls.iter().filter(|call| !call.arguments_valid).count() as u64;

    let (user_turns, machine_turns, effective_user_pairs, corrections) = classify_turns(messages);
    let machine_ratio = if user_turns == 0 {
        1.0
    } else {
        machine_turns as f64 / user_turns as f64
    };
    let valid_results = results.iter().filter(|result| result.valid).count() as u64;
    let failed_results = results.iter().filter(|result| result.failed).count() as u64;
    let explicit_status_results = results
        .iter()
        .filter(|result| result.explicit_status)
        .count() as u64;
    let conflicting_tool_results = results.iter().filter(|result| result.conflict).count() as u64;
    let unknown_tool_results = results
        .len()
        .saturating_sub(explicit_status_results as usize) as u64;
    let effective_turns = effective_user_pairs.saturating_add(paired_required);
    let lifecycle_retries = lifecycle_retry_count(session);
    let unique_call_ids = all_call_ids.len() as u64;
    let assembly_merge_divergences = session
        .pointer("/meta/merge_divergences")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let assembly_schema_conflicts = session
        .pointer("/meta/schema_conflicts")
        .and_then(Value::as_array)
        .map_or(0, |conflicts| conflicts.len() as u64);
    let assembly_trace_conflicts = session
        .pointer("/meta/trace_conflicts")
        .and_then(Value::as_array)
        .map_or(0, |conflicts| conflicts.len() as u64);
    let assembly_system_prompt_conflicts = session
        .pointer("/meta/system_prompt_conflicts")
        .and_then(Value::as_array)
        .map_or(0, |conflicts| conflicts.len() as u64);
    let assembly_usage_conflicts = session
        .pointer("/meta/usage_conflicts")
        .and_then(Value::as_array)
        .map_or(0, |conflicts| conflicts.len() as u64);
    let assembly_tool_execution_conflicts = session
        .pointer("/meta/tool_execution_conflicts")
        .and_then(Value::as_array)
        .map_or(0, |conflicts| conflicts.len() as u64);
    let assembly_producer_event_conflicts = session
        .pointer("/meta/producer_event_conflicts")
        .and_then(Value::as_array)
        .map_or(0, |conflicts| conflicts.len() as u64);
    let rollout_unknown_events = session
        .pointer("/meta/rollout_unknown_events")
        .and_then(Value::as_array)
        .map_or(0, |events| events.len() as u64);
    let rollout_unmapped_tools = session
        .pointer("/meta/rollout_unmapped_tools")
        .and_then(Value::as_array)
        .map_or(0, |events| events.len() as u64);
    let capture_dag_present = session
        .pointer("/meta/capture_dag")
        .is_some_and(Value::is_object);
    let runtime_dag_present = session
        .pointer("/meta/runtime_dag")
        .is_some_and(Value::is_object);
    let native_runtime_events_present = session
        .pointer("/meta/rollout_events")
        .and_then(Value::as_array)
        .is_some_and(|events| {
            events
                .iter()
                .any(|event| string_field(event, "source") == Some("codex_rollout_trace_bundle"))
        });
    let runtime_dag_applicable = session
        .pointer("/meta/runtime_dag/applicable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || native_runtime_events_present;
    let runtime_dag_complete = session
        .pointer("/meta/runtime_dag/complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let runtime_dag_native_events = session
        .pointer("/meta/runtime_dag/native_event_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let runtime_dag_open_nodes = session
        .pointer("/meta/runtime_dag/open_node_ids")
        .and_then(Value::as_array)
        .map_or(0, |nodes| nodes.len() as u64);
    let runtime_dag_unresolved_nodes = session
        .pointer("/meta/runtime_dag/unresolved_node_ids")
        .and_then(Value::as_array)
        .map_or(0, |nodes| nodes.len() as u64);
    let task_dag_present = session
        .pointer("/meta/task_dag")
        .is_some_and(Value::is_object);
    let response_dag_cycle = session
        .pointer("/meta/capture_dag/has_cycle")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let response_dag_unresolved_parents = session
        .pointer("/meta/capture_dag/unresolved_parent_response_ids")
        .and_then(Value::as_array)
        .map_or(0, |parents| parents.len() as u64)
        .saturating_add(
            session
                .pointer("/meta/capture_dag/unresolved_parent_span_ids")
                .and_then(Value::as_array)
                .map_or(0, |parents| parents.len() as u64),
        );
    let task_dag_complete = session
        .pointer("/meta/task_dag/complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let task_start_event_present = session_has_start_event(session);
    let task_terminal_event_present = session_has_terminal_event(session);
    let task_session_id_present = session
        .pointer("/meta/trace/task_session_id")
        .or_else(|| session.pointer("/trace/task_session_id"))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty());
    let task_boundary_attested =
        task_session_id_present && task_start_event_present && task_terminal_event_present;
    let model_evidence_consistent = session
        .pointer("/meta/model_evidence/consistent")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            model_evidence_consistent(
                session,
                string_field(session, "model").unwrap_or(""),
                string_field(session, "provider").unwrap_or(""),
            )
        });
    let proxy_route_verified = session
        .pointer("/meta/model_evidence/proxy_route_verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let provider_identity_attested = session
        .pointer("/meta/model_evidence/provider_identity_attested")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let model_attestation_candidate_count = session
        .pointer("/meta/model_evidence/attestation_candidate_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let non_attestable_api_snapshot_count = session
        .pointer("/meta/model_evidence/non_attestable_api_snapshots")
        .and_then(Value::as_array)
        .map_or(0, |items| items.len() as u64);

    let metrics = AcceptanceMetrics {
        messages: messages.len() as u64,
        user_turns,
        machine_turns,
        machine_turn_ratio: round(machine_ratio, 6),
        human_user_assistant_turns: effective_user_pairs,
        effective_turns,
        tool_calls: calls.len() as u64,
        unique_tool_call_ids: unique_call_ids,
        distinct_tool_names: called_names.len() as u64,
        invalid_tool_arguments,
        tool_results: results.len() as u64,
        valid_tool_results: valid_results,
        tool_results_with_explicit_status: explicit_status_results,
        unknown_tool_results,
        conflicting_tool_results,
        paired_required_tool_calls: required_calls.len() as u64,
        paired_required_tool_results: paired_required,
        orphan_tool_results: orphan_results,
        pairing_rate_after_open_tail: round(pairing_rate, 6),
        tool_definitions: definition_map.len() as u64,
        complete_tool_definitions: complete_called_definitions,
        user_corrections: corrections,
        failed_tool_results: failed_results,
        lifecycle_retries,
        assembly_merge_divergences,
        assembly_schema_conflicts,
        assembly_trace_conflicts,
        assembly_system_prompt_conflicts,
        assembly_usage_conflicts,
        assembly_tool_execution_conflicts,
        assembly_producer_event_conflicts,
        rollout_unknown_events,
        rollout_unmapped_tools,
        response_dag_cycle,
        response_dag_unresolved_parents,
        capture_dag_present,
        runtime_dag_present,
        runtime_dag_applicable,
        runtime_dag_complete,
        runtime_dag_native_events,
        runtime_dag_open_nodes,
        runtime_dag_unresolved_nodes,
        task_dag_present,
        task_dag_complete,
        task_start_event_present,
        task_terminal_event_present,
        task_boundary_attested,
        model_evidence_consistent,
        provider_identity_attested,
        model_attestation_candidate_count,
        non_attestable_api_snapshot_count,
        proxy_route_verified,
    };

    let mut gates = Vec::new();
    let required_fields = required_fields_present(session);
    push_gate(
        &mut gates,
        "required_fields",
        required_fields,
        true,
        json!(required_fields),
        "canonical required fields are present and non-empty",
        None,
    );
    let roles_valid = !messages.is_empty()
        && messages.iter().all(|message| {
            matches!(
                string_field(message, "role"),
                Some("system" | "user" | "assistant" | "tool")
            ) && message.get("content").is_some()
        });
    push_gate(
        &mut gates,
        "message_roles",
        roles_valid,
        true,
        json!(roles_valid),
        "every message has role=system|user|assistant|tool and a content field",
        None,
    );
    let first_role = messages
        .first()
        .and_then(|message| string_field(message, "role"));
    let first_role_valid = matches!(first_role, Some("system" | "user"));
    push_gate(
        &mut gates,
        "first_message_role",
        first_role_valid,
        true,
        json!(first_role),
        "system or user",
        None,
    );
    let system_prompt_present = has_system_prompt(session, messages);
    push_gate(
        &mut gates,
        "system_prompt",
        system_prompt_present,
        true,
        json!(system_prompt_present),
        "non-empty system_prompt or system message",
        None,
    );
    let effective_turns_pass =
        effective_turns >= profile.minimum_effective_turns() && effective_user_pairs >= 2;
    push_gate(
        &mut gates,
        "effective_turns",
        effective_turns_pass,
        true,
        json!({
            "effective_turns": effective_turns,
            "human_user_assistant_turns": effective_user_pairs,
        }),
        &format!(
            ">= {} effective turns{}",
            profile.minimum_effective_turns(),
            " and >= 2 human User -> Assistant turns"
        ),
        Some(
            "counted as substantive user-to-assistant pairs plus paired assistant-tool-result calls",
        ),
    );
    let tool_count_pass = calls.len() as u64 >= profile.minimum_tool_calls()
        && unique_call_ids == calls.len() as u64
        && calls
            .iter()
            .all(|call| call.id.is_some() && call.name.is_some())
        && invalid_tool_arguments == 0
        && !duplicate_call_ids
        && (profile != Profile::BuyerV7
            || called_names.len() as u64 >= profile.minimum_tool_calls());
    push_gate(
        &mut gates,
        "structured_tool_calls",
        tool_count_pass,
        true,
        json!({
            "calls": calls.len(),
            "unique_call_ids": unique_call_ids,
            "distinct_tool_names": called_names.len(),
            "invalid_arguments": invalid_tool_arguments,
        }),
        &format!(
            ">= {} calls with unique IDs{}",
            profile.minimum_tool_calls(),
            if profile == Profile::BuyerV7 {
                " and distinct tool names"
            } else {
                ""
            }
        ),
        None,
    );
    push_gate(
        &mut gates,
        "valid_tool_results",
        valid_results >= profile.minimum_valid_results(),
        true,
        json!(valid_results),
        &format!(">= {} non-empty results", profile.minimum_valid_results()),
        Some(if profile == Profile::BuyerV7 {
            "buyer-v7 also requires an explicit status or is_error flag"
        } else {
            "buyer-v6 accepts a non-empty result because its published example omits status"
        }),
    );
    let definitions_pass = !called_names.is_empty()
        && complete_called_definitions == called_names.len() as u64
        && !generic_called_names;
    push_gate(
        &mut gates,
        "tool_definitions",
        definitions_pass,
        true,
        json!({
            "called_names": called_names,
            "complete_called_definitions": complete_called_definitions,
            "generic_called_name": generic_called_names,
        }),
        "every called tool has a semantic name and complete name/description/parameters schema",
        None,
    );
    let pairing_pass = (pairing_rate - 1.0).abs() < f64::EPSILON
        && orphan_results == 0
        && !duplicate_call_ids
        && !duplicate_result_ids;
    push_gate(
        &mut gates,
        "tool_pairing_after_open_tail",
        pairing_pass,
        true,
        json!({
            "rate": pairing_rate,
            "required_calls": required_calls.len(),
            "matched": paired_required,
            "orphan_results": orphan_results,
            "duplicate_call_ids": duplicate_call_ids,
            "duplicate_result_ids": duplicate_result_ids,
        }),
        "100%; only calls in a terminal assistant message may be excluded as open_tail",
        None,
    );
    push_gate(
        &mut gates,
        "machine_turn_ratio",
        user_turns > 0 && machine_ratio < 0.25,
        true,
        json!(machine_ratio),
        "< 0.25",
        Some(
            "explicit metadata labels take precedence over deterministic heartbeat/cron/no_reply rules",
        ),
    );
    push_gate(
        &mut gates,
        "assembly_integrity",
        assembly_merge_divergences == 0
            && assembly_schema_conflicts == 0
            && assembly_trace_conflicts == 0
            && assembly_system_prompt_conflicts == 0
            && assembly_usage_conflicts == 0
            && assembly_tool_execution_conflicts == 0
            && assembly_producer_event_conflicts == 0
            && rollout_unknown_events == 0
            && rollout_unmapped_tools == 0
            && capture_dag_present
            && task_dag_present
            && !response_dag_cycle
            && response_dag_unresolved_parents == 0
            && task_dag_complete
            && conflicting_tool_results == 0
            && (profile != Profile::BuyerV7 || task_boundary_attested),
        true,
        json!({
            "merge_divergences": assembly_merge_divergences,
            "schema_conflicts": assembly_schema_conflicts,
            "trace_conflicts": assembly_trace_conflicts,
            "system_prompt_conflicts": assembly_system_prompt_conflicts,
            "usage_conflicts": assembly_usage_conflicts,
            "tool_execution_conflicts": assembly_tool_execution_conflicts,
            "producer_event_conflicts": assembly_producer_event_conflicts,
            "rollout_unknown_events": rollout_unknown_events,
            "rollout_unmapped_tools": rollout_unmapped_tools,
            "response_dag_cycle": response_dag_cycle,
            "response_dag_unresolved_parents": response_dag_unresolved_parents,
            "capture_dag_present": capture_dag_present,
            "task_dag_present": task_dag_present,
            "task_dag_complete": task_dag_complete,
            "conflicting_tool_results": conflicting_tool_results,
            "task_start_event_present": task_start_event_present,
            "task_terminal_event_present": task_terminal_event_present,
            "task_boundary_attested": task_boundary_attested,
        }),
        "no message, tool schema, status, trace, system prompt, usage, unknown rollout, or unmapped runtime-tool conflicts; buyer-v7 also requires an explicitly bounded task Session",
        Some(
            "an assembly conflict or inferred-only task boundary is never compensated by the numeric score",
        ),
    );
    let runtime_dag_pass = !runtime_dag_applicable
        || (runtime_dag_present
            && runtime_dag_complete
            && runtime_dag_native_events > 0
            && runtime_dag_open_nodes == 0
            && runtime_dag_unresolved_nodes == 0);
    push_gate(
        &mut gates,
        "runtime_dag_integrity",
        runtime_dag_pass,
        true,
        json!({
            "present": runtime_dag_present,
            "applicable": runtime_dag_applicable,
            "native_events": runtime_dag_native_events,
            "complete": runtime_dag_complete,
            "open_nodes": runtime_dag_open_nodes,
            "unresolved_nodes": runtime_dag_unresolved_nodes,
        }),
        "when native Codex bundle evidence is present, runtime DAG complete=true with at least one native event and zero open or unresolved nodes",
        Some(
            "API-only Sessions are not reclassified as runtime-complete; native runtime evidence cannot be omitted to bypass this gate",
        ),
    );
    let model_result = model_eligible(session, profile);
    push_gate(
        &mut gates,
        "model",
        model_result.0,
        true,
        json!({
            "provider": string_field(session, "provider"),
            "model": string_field(session, "model"),
            "provider_identity_attested": provider_identity_attested,
            "api_snapshot_count": session
                .pointer("/meta/model_evidence/api_snapshot_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            "attestation_candidate_count": model_attestation_candidate_count,
            "non_attestable_api_snapshot_count": non_attestable_api_snapshot_count,
        }),
        model_result.1,
        Some(
            "model/provider evidence must be internally consistent; buyer-v7 also requires an explicit provider or gateway observation, while cryptographic identity remains outside JSONL scoring",
        ),
    );
    let closed = session_closed(session, messages);
    push_gate(
        &mut gates,
        "session_closed",
        closed,
        true,
        json!({
            "status": string_field(session, "status"),
            "is_final_snapshot": session.get("is_final_snapshot"),
        }),
        "final snapshot with completed/terminated/failed/cancelled/incomplete terminal state and no unresolved tail",
        None,
    );
    let domain = session
        .pointer("/meta/task_type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let domain_pass = !matches!(
        domain.as_str(),
        "roleplay"
            | "gui"
            | "gui_only"
            | "embedding"
            | "embeddings"
            | "translation"
            | "pure_translation"
            | "ordinary_qa"
            | "general_qa"
            | "error_request"
            | "error_only"
            | "no_tool"
            | "no_tools"
    );
    push_gate(
        &mut gates,
        "content_domain",
        domain_pass,
        true,
        if domain.is_empty() {
            Value::Null
        } else {
            json!(domain)
        },
        "code/search/data task; not roleplay, GUI-only, embedding, pure translation, ordinary QA, or error-only",
        Some(
            "unknown task_type is retained as unknown and is not fabricated; explicit labels take precedence",
        ),
    );

    let score = round(
        gates
            .iter()
            .filter(|gate| gate.pass)
            .map(|gate| gate_weight(&gate.name))
            .sum(),
        3,
    );
    let hard_gate_pass = gates
        .iter()
        .filter(|gate| gate.required)
        .all(|gate| gate.pass);
    let eligible = hard_gate_pass && score >= minimum_score;
    let failure_reasons: Vec<String> = gates
        .iter()
        .filter(|gate| gate.required && !gate.pass)
        .map(|gate| gate.name.clone())
        .collect();
    let mut warnings = Vec::new();
    if session
        .pointer("/meta/model_evidence/attested")
        .and_then(Value::as_bool)
        != Some(true)
    {
        warnings.push("model_attestation_missing".to_owned());
    }
    if session
        .pointer("/meta/model_evidence/proxy_route_verified")
        .and_then(Value::as_bool)
        != Some(true)
    {
        warnings.push("proxy_route_evidence_missing".to_owned());
    }
    if string_field(session, "trajectory_id").is_none() {
        warnings.push("trajectory_id_missing".to_owned());
    }
    if session.pointer("/meta/merge_divergences").is_none()
        || session.pointer("/meta/schema_conflicts").is_none()
        || session.pointer("/meta/trace_conflicts").is_none()
        || session.pointer("/meta/system_prompt_conflicts").is_none()
        || session.pointer("/meta/usage_conflicts").is_none()
        || session.pointer("/meta/tool_execution_conflicts").is_none()
        || session.pointer("/meta/producer_streams").is_none()
        || session.pointer("/meta/producer_event_conflicts").is_none()
        || session.pointer("/meta/usage_evidence").is_none()
        || session.pointer("/meta/rollout_unknown_events").is_none()
        || session.pointer("/meta/rollout_unmapped_tools").is_none()
        || session.pointer("/meta/capture_dag").is_none()
        || session.pointer("/meta/task_dag").is_none()
    {
        warnings.push("assembly_integrity_evidence_missing".to_owned());
    }
    if session.pointer("/meta/runtime_dag").is_none() {
        warnings.push("runtime_dag_evidence_missing".to_owned());
    }
    if lifecycle_retries == 0 && failed_results == 0 && corrections == 0 {
        warnings.push("no_realism_recovery_signal".to_owned());
    }

    let tokens = count_tokens(session, &called_names);
    let buyer = BuyerAssessment {
        schema_version: ASSESSMENT_SCHEMA_VERSION.to_owned(),
        profile: profile.as_str().to_owned(),
        profile_version: profile.version().to_owned(),
        score,
        hard_gate_pass,
        eligible,
        minimum_score,
        metrics,
        tokens,
        gates,
        failure_reasons,
        warnings,
        scoring_scope: "deterministic structural acceptance projection; authenticity, task correctness, and provider identity require external evidence".to_owned(),
    };
    let completeness = capture_completeness(session, closed, messages);
    let semantic = semantic_quality(
        session,
        failed_results,
        lifecycle_retries,
        corrections,
        messages,
    );
    QualityEnvelope {
        capture_completeness: completeness,
        buyer_acceptance: buyer,
        semantic_quality: semantic,
    }
}

fn push_gate(
    gates: &mut Vec<GateResult>,
    name: &str,
    pass: bool,
    required: bool,
    observed: Value,
    expected: &str,
    detail: Option<&str>,
) {
    gates.push(GateResult {
        name: name.to_owned(),
        pass,
        required,
        observed,
        expected: expected.to_owned(),
        detail: detail.map(str::to_owned),
    });
}

fn collect_tool_calls(messages: &[Value]) -> Vec<ToolCall> {
    let mut calls = Vec::new();
    for (message_index, message) in messages.iter().enumerate() {
        if string_field(message, "role") != Some("assistant") {
            continue;
        }
        let Some(raw_calls) = message.get("tool_calls").and_then(Value::as_array) else {
            continue;
        };
        for call in raw_calls {
            let function = call.get("function").unwrap_or(call);
            calls.push(ToolCall {
                id: string_field(call, "id")
                    .or_else(|| string_field(call, "call_id"))
                    .map(str::to_owned),
                name: string_field(function, "name").map(str::to_owned),
                arguments_valid: tool_arguments_valid(function.get("arguments")),
                message_index,
            });
        }
    }
    calls
}

fn collect_tool_results(messages: &[Value], profile: Profile) -> Vec<ToolResult> {
    messages
        .iter()
        .filter(|message| string_field(message, "role") == Some("tool"))
        .map(|message| {
            let content_valid = message.get("content").is_some_and(nonempty_value)
                || message.get("error_message").is_some_and(nonempty_value)
                || message.get("error").is_some_and(nonempty_value);
            let explicit_status = string_field(message, "status").is_some_and(|status| {
                matches!(
                    status.to_ascii_lowercase().as_str(),
                    "success"
                        | "completed"
                        | "error"
                        | "failed"
                        | "cancelled"
                        | "canceled"
                        | "timeout"
                )
            }) || message.get("is_error").is_some_and(Value::is_boolean);
            let status_conflict = message
                .get("status_conflict")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let failed = message
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || string_field(message, "status").is_some_and(|status| {
                    matches!(
                        status.to_ascii_lowercase().as_str(),
                        "failed" | "error" | "cancelled" | "canceled" | "timeout"
                    )
                });
            ToolResult {
                id: string_field(message, "tool_call_id")
                    .or_else(|| string_field(message, "call_id"))
                    .or_else(|| string_field(message, "tool_use_id"))
                    .map(str::to_owned),
                valid: content_valid
                    && !status_conflict
                    && (profile == Profile::BuyerV6 || explicit_status),
                failed,
                explicit_status,
                conflict: status_conflict,
            }
        })
        .collect()
}

fn results_by_id(results: &[ToolResult]) -> HashMap<&str, Vec<&ToolResult>> {
    let mut output: HashMap<&str, Vec<&ToolResult>> = HashMap::new();
    for result in results {
        if let Some(id) = result.id.as_deref() {
            output.entry(id).or_default().push(result);
        }
    }
    output
}

fn tool_definition_map(tools: &[Value]) -> HashMap<String, &Value> {
    let mut definitions = HashMap::new();
    for tool in tools {
        let nested = tool.get("function").unwrap_or(tool);
        if let Some(name) = string_field(nested, "name") {
            definitions.insert(name.to_owned(), tool);
        }
    }
    definitions
}

fn tool_definition_complete(tool: &Value, profile: Profile) -> bool {
    let nested = tool.get("function").unwrap_or(tool);
    if nested
        .pointer("/schema_provenance/source_complete")
        .and_then(Value::as_bool)
        == Some(false)
    {
        return false;
    }
    // A generated adapter is useful for lossless inspection, but it is not an
    // original tool schema. Buyer-v7 requires the schema supplied by the
    // producer (or a native schema that has not been rewritten).
    if profile == Profile::BuyerV7
        && nested
            .pointer("/schema_provenance/generated_adapter")
            .and_then(Value::as_bool)
            == Some(true)
    {
        return false;
    }
    if string_field(nested, "name").is_none() || string_field(nested, "description").is_none() {
        return false;
    }
    let Some(parameters) = nested.get("parameters").and_then(Value::as_object) else {
        return false;
    };
    if parameters.get("type").and_then(Value::as_str) != Some("object") {
        return false;
    }
    let Some(properties) = parameters.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let properties_valid = properties.values().all(|property| {
        property.as_object().is_some_and(|definition| {
            let has_type = definition.get("type").is_some()
                || definition.get("oneOf").is_some()
                || definition.get("anyOf").is_some()
                || definition.get("$ref").is_some();
            let has_description = definition
                .get("description")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.trim().is_empty());
            has_type && has_description
        })
    });
    let required_valid = parameters
        .get("required")
        .map(|required| {
            required.as_array().is_some_and(|names| {
                names.iter().all(|name| {
                    name.as_str()
                        .is_some_and(|name| properties.contains_key(name))
                })
            })
        })
        .unwrap_or(true);
    properties_valid && required_valid
}

fn tool_arguments_valid(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(text)) => serde_json::from_str::<Value>(text).is_ok(),
        Some(Value::Object(_)) | Some(Value::Array(_)) => true,
        Some(Value::Bool(_)) | Some(Value::Number(_)) => true,
        _ => false,
    }
}

fn generic_tool_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "tool1" | "tool_1" | "helper" | "action"
    )
}

fn classify_turns(messages: &[Value]) -> (u64, u64, u64, u64) {
    let mut user_turns = 0_u64;
    let mut machine_turns = 0_u64;
    let mut effective_pairs = 0_u64;
    let mut corrections = 0_u64;
    let mut previous_user: Option<String> = None;
    for (index, message) in messages.iter().enumerate() {
        if string_field(message, "role") != Some("user") {
            continue;
        }
        let text = content_text(message.get("content"));
        let kind = classify_user_message(message, &text, previous_user.as_deref());
        previous_user = Some(text.clone());
        if kind == UserTurnKind::Harness {
            continue;
        }
        user_turns += 1;
        if kind == UserTurnKind::Machine {
            machine_turns += 1;
            continue;
        }
        if is_correction(&text) {
            corrections += 1;
        }
        let assistant_seen = messages[index + 1..]
            .iter()
            .take_while(|candidate| string_field(candidate, "role") != Some("user"))
            .any(|candidate| {
                string_field(candidate, "role") == Some("assistant")
                    && (assistant_substantive(candidate)
                        || candidate
                            .get("tool_calls")
                            .and_then(Value::as_array)
                            .is_some_and(|calls| !calls.is_empty()))
            });
        effective_pairs += u64::from(assistant_seen);
    }
    (user_turns, machine_turns, effective_pairs, corrections)
}

fn classify_user_message(message: &Value, text: &str, previous: Option<&str>) -> UserTurnKind {
    let kind = message
        .pointer("/meta/turn_kind")
        .or_else(|| message.pointer("/metadata/turn_kind"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        kind.as_str(),
        "harness" | "meta_injection" | "tool_result_carrier"
    ) {
        return UserTurnKind::Harness;
    }
    if matches!(kind.as_str(), "heartbeat" | "cron" | "no_reply") {
        return UserTurnKind::Machine;
    }
    let normalized = text.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || PUNCTUATION_ONLY.is_match(&normalized)
        || matches!(
            normalized.as_str(),
            "ok" | "okay" | "yes" | "y" | "好的" | "收到" | "确认" | "继续" | "嗯" | "是"
        )
        || previous.is_some_and(|value| value.trim() == text.trim())
        || normalized.contains("heartbeat")
        || normalized.starts_with("cron:")
        || normalized.starts_with("[cron]")
    {
        UserTurnKind::Machine
    } else {
        UserTurnKind::Human
    }
}

fn is_correction(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "不对",
        "不是",
        "改成",
        "重新",
        "等等",
        "补充",
        "actually",
        "instead",
        "wrong",
        "not what",
        "change it",
        "correction",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn required_fields_present(session: &Value) -> bool {
    let string_fields = [
        "session_id",
        "trajectory_id",
        "provider",
        "model",
        "created_at",
        "status",
    ];
    string_fields
        .iter()
        .all(|field| string_field(session, field).is_some())
        && session
            .get("is_final_snapshot")
            .is_some_and(Value::is_boolean)
        && session
            .get("source_request_count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
        && session.get("tools").is_some_and(Value::is_array)
        && session.get("messages").is_some_and(Value::is_array)
        && session
            .get("usage")
            .is_some_and(|value| value.is_object() || value.is_null())
        && session
            .get("messages")
            .and_then(Value::as_array)
            .is_some_and(|messages| has_system_prompt(session, messages))
}

fn has_system_prompt(session: &Value, messages: &[Value]) -> bool {
    string_field(session, "system_prompt").is_some()
        || messages.iter().any(|message| {
            string_field(message, "role") == Some("system") && content_nonempty(message)
        })
}

fn model_eligible(session: &Value, profile: Profile) -> (bool, &'static str) {
    let model = string_field(session, "model")
        .unwrap_or("")
        .to_ascii_lowercase();
    let provider = string_field(session, "provider")
        .unwrap_or("")
        .to_ascii_lowercase();
    let evidence_consistent = model_evidence_consistent(session, &model, &provider);
    let provider_identity_attested = session
        .pointer("/meta/model_evidence/provider_identity_attested")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (eligible, expected_provider) = match profile {
        Profile::BuyerV6 => {
            if version_at_least(&GPT_VERSION, &model, 5, 0) {
                (true, "openai")
            } else if version_at_least(&CLAUDE_VERSION, &model, 4, 5) {
                (true, "anthropic")
            } else if version_at_least(&GEMINI_VERSION, &model, 3, 0) {
                (true, "google")
            } else {
                (false, "")
            }
        }
        Profile::BuyerV7 => {
            if version_at_least(&GPT_VERSION, &model, 5, 5) {
                (true, "openai")
            } else if version_at_least(&CLAUDE_VERSION, &model, 4, 6)
                && !model.contains("haiku")
                && (!model.contains("sonnet") || version_at_least(&CLAUDE_VERSION, &model, 5, 0))
            {
                (true, "anthropic")
            } else if version_at_least(&DEEPSEEK_VERSION, &model, 4, 0) {
                (true, "deepseek")
            } else if version_at_least(&GLM_VERSION, &model, 5, 2) {
                (true, "zhipu")
            } else if version_at_least(&KIMI_K_VERSION, &model, 3, 0) {
                (true, "moonshot")
            } else {
                (false, "")
            }
        }
    };
    let provider_consistent = eligible
        && (provider.contains(expected_provider)
            || (expected_provider == "google" && provider.contains("gemini"))
            || (expected_provider == "zhipu" && provider.contains("glm"))
            || (expected_provider == "moonshot"
                && (provider.contains("kimi") || provider.contains("moonshot"))));
    let expectation = match profile {
        Profile::BuyerV6 => {
            "GPT-5+, Gemini-3+, or Claude-4.5+ with consistent provider/model evidence"
        }
        Profile::BuyerV7 => {
            "GPT-5.5+, eligible Claude, DeepSeek-v4+, GLM-5.2+, or K3+; no Gemini/Haiku"
        }
    };
    (
        eligible
            && provider_consistent
            && evidence_consistent
            && (profile != Profile::BuyerV7 || provider_identity_attested),
        expectation,
    )
}

fn version_at_least(
    pattern: &Regex,
    model: &str,
    required_major: u64,
    required_minor: u64,
) -> bool {
    let Some(captures) = pattern.captures(model) else {
        return false;
    };
    let major = captures
        .get(1)
        .and_then(|value| value.as_str().parse::<u64>().ok())
        .unwrap_or(0);
    let minor = captures
        .get(2)
        .and_then(|value| value.as_str().parse::<u64>().ok())
        .unwrap_or(0);
    (major, minor) >= (required_major, required_minor)
}

fn model_evidence_consistent(session: &Value, declared: &str, provider: &str) -> bool {
    let Some(evidence) = session
        .pointer("/meta/model_evidence")
        .and_then(Value::as_object)
    else {
        return false;
    };
    if evidence.get("consistent").and_then(Value::as_bool) == Some(false) {
        return false;
    }
    let request_models: Vec<&str> = evidence
        .get("request_models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let effective_models: Vec<&str> = evidence
        .get("effective_models")
        .or_else(|| evidence.get("gateway_upstream_models"))
        .or_else(|| evidence.get("response_models"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let response_models: Vec<&str> = evidence
        .get("response_models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let legacy_models_match = ["request_models", "response_models"]
        .iter()
        .filter_map(|field| evidence.get(*field).and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .all(|value| value.eq_ignore_ascii_case(declared));
    let models_match = if effective_models.is_empty() {
        !request_models.is_empty() && !response_models.is_empty() && legacy_models_match
    } else {
        !request_models.is_empty()
            && effective_models
                .iter()
                .all(|value| value.eq_ignore_ascii_case(declared))
            && response_models.iter().all(|value| {
                effective_models
                    .iter()
                    .any(|effective| effective.eq_ignore_ascii_case(value))
            })
    };
    let providers_match = evidence
        .get("providers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .all(|value| value.eq_ignore_ascii_case(provider));
    models_match && providers_match
}

fn session_closed(session: &Value, messages: &[Value]) -> bool {
    let status = string_field(session, "status")
        .map(|status| status.to_ascii_lowercase())
        .unwrap_or_default();
    let terminal_status = matches!(
        status.as_str(),
        "completed" | "terminated" | "failed" | "cancelled" | "canceled" | "incomplete"
    );
    let final_snapshot = session
        .get("is_final_snapshot")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let unresolved_calls = !unresolved_tool_call_ids_for_closure(messages).is_empty();
    let final_assistant = messages.last().is_some_and(|message| {
        string_field(message, "role") == Some("assistant")
            && message
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            && assistant_substantive(message)
    });
    let explicit_termination = session_has_terminal_event(session);
    let terminal_without_assistant = matches!(
        status.as_str(),
        "completed" | "terminated" | "failed" | "cancelled" | "canceled" | "incomplete"
    ) && explicit_termination;
    terminal_status
        && final_snapshot
        && !unresolved_calls
        && (final_assistant || terminal_without_assistant)
}

fn session_has_terminal_event(session: &Value) -> bool {
    let string_events = session
        .pointer("/meta/lifecycle_events")
        .or_else(|| session.pointer("/trace/lifecycle_events"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(is_terminal_lifecycle_event);
    let object_events = session
        .pointer("/meta/lifecycle_event_records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|event| event.get("type").and_then(Value::as_str))
        .any(is_terminal_lifecycle_event);
    string_events || object_events
}

fn session_has_start_event(session: &Value) -> bool {
    let string_events = session
        .pointer("/meta/lifecycle_events")
        .or_else(|| session.pointer("/trace/lifecycle_events"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(is_start_lifecycle_event);
    let object_events = session
        .pointer("/meta/lifecycle_event_records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|event| event.get("type").and_then(Value::as_str))
        .any(is_start_lifecycle_event);
    string_events || object_events
}

fn unresolved_tool_call_ids_for_closure(messages: &[Value]) -> Vec<String> {
    let calls: HashSet<String> = messages
        .iter()
        .filter(|message| string_field(message, "role") == Some("assistant"))
        .filter_map(|message| message.get("tool_calls").and_then(Value::as_array))
        .flatten()
        .filter_map(|call| {
            string_field(call, "id")
                .or_else(|| string_field(call, "call_id"))
                .map(str::to_owned)
        })
        .collect();
    let results: HashSet<String> = messages
        .iter()
        .filter(|message| string_field(message, "role") == Some("tool"))
        .filter_map(|message| {
            string_field(message, "tool_call_id")
                .or_else(|| string_field(message, "call_id"))
                .or_else(|| string_field(message, "tool_use_id"))
                .map(str::to_owned)
        })
        .collect();
    calls.difference(&results).cloned().collect()
}

fn is_terminal_lifecycle_event(event: &str) -> bool {
    let normalized = event
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', ':'], "_");
    matches!(
        normalized.as_str(),
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
    ) || normalized.starts_with("session_cancel")
        || normalized.starts_with("task_cancel")
        || normalized.starts_with("session_fail")
        || normalized.starts_with("task_fail")
}

fn is_start_lifecycle_event(event: &str) -> bool {
    matches!(
        event
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '.', ' ', ':'], "_")
            .as_str(),
        "session_start" | "session_started" | "task_start" | "task_started"
    )
}

fn lifecycle_retry_count(session: &Value) -> u64 {
    let string_count = session
        .pointer("/meta/lifecycle_events")
        .or_else(|| session.pointer("/trace/lifecycle_events"))
        .and_then(Value::as_array)
        .map(|events| {
            events
                .iter()
                .filter(|event| {
                    event.as_str().is_some_and(|text| {
                        let text = text.to_ascii_lowercase();
                        text.contains("retry")
                            || text.contains("cancel")
                            || text.contains("compaction")
                    })
                })
                .count() as u64
        })
        .unwrap_or(0);
    let object_count = session
        .pointer("/meta/lifecycle_event_records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|event| event.get("type").and_then(Value::as_str))
        .filter(|event| {
            let event = event.to_ascii_lowercase();
            event.contains("retry") || event.contains("cancel") || event.contains("compaction")
        })
        .count() as u64;
    string_count.max(object_count)
}

fn capture_completeness(session: &Value, closed: bool, messages: &[Value]) -> CaptureCompleteness {
    let stable_identity = string_field(session, "session_id").is_some();
    let timestamps = string_field(session, "created_at").is_some()
        && (string_field(session, "ended_at").is_some() || !closed);
    let source_count = u64_field(session, &["source_request_count"]);
    let usage = session.get("usage").is_some_and(Value::is_object);
    let hierarchy = session.get("trace").is_some_and(Value::is_object)
        || session.pointer("/meta/trace").is_some_and(Value::is_object)
        || ["root_session_id", "goal_id", "agent_id", "branch_id"]
            .iter()
            .any(|field| session.pointer(&format!("/meta/{field}")).is_some());
    let score = 20.0 * f64::from(stable_identity)
        + 15.0 * f64::from(timestamps)
        + 10.0 * f64::from(source_count > 0)
        + 20.0 * f64::from(!messages.is_empty())
        + 15.0 * f64::from(closed)
        + 10.0 * f64::from(usage)
        + 10.0 * f64::from(hierarchy);
    CaptureCompleteness {
        policy_version: "capture-completeness-v2".to_owned(),
        score,
        closed,
        source_request_count: source_count,
        has_stable_session_identity: stable_identity,
        has_timestamps: timestamps,
        has_usage: usage,
        has_trace_hierarchy: hierarchy,
        scope: "capture observability only; not buyer acceptance or task correctness".to_owned(),
    }
}

fn semantic_quality(
    session: &Value,
    failed_results: u64,
    retries: u64,
    corrections: u64,
    messages: &[Value],
) -> SemanticQuality {
    let explicit_reward = session
        .pointer("/meta/reward/value")
        .or_else(|| session.pointer("/reward/value"))
        .and_then(Value::as_f64)
        .filter(|reward| (0.0..=1.0).contains(reward));
    let explicit_source = session
        .pointer("/meta/reward/source")
        .or_else(|| session.pointer("/reward/source"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let evidence = session
        .pointer("/meta/evaluation_evidence")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let evidence_rewards: Vec<f64> = evidence.iter().filter_map(evidence_reward).collect();
    let evidence_reward = (!evidence_rewards.is_empty()).then(|| {
        round(
            evidence_rewards.iter().sum::<f64>() / evidence_rewards.len() as f64,
            6,
        )
    });
    let explicit_available = explicit_reward.is_some() && explicit_source.is_some();
    let reward = if explicit_available {
        explicit_reward
    } else {
        evidence_reward
    };
    let reward_source = if explicit_available {
        explicit_source
    } else {
        evidence_reward.map(|_| "chiptrace.semantic-evidence-v1".to_owned())
    };
    let environment_context = messages
        .iter()
        .any(|message| ENVIRONMENT_SIGNAL.is_match(&content_text(message.get("content"))));
    let user_messages = messages
        .iter()
        .filter(|message| string_field(message, "role") == Some("user"))
        .count() as u64;
    let multi_turn = user_messages >= 2;
    let signal_score = 20.0 * f64::from(failed_results > 0)
        + 20.0 * f64::from(retries > 0)
        + 20.0 * f64::from(corrections > 0)
        + 20.0 * f64::from(environment_context)
        + 20.0 * f64::from(multi_turn);
    let mut evidence_kinds = BTreeMap::new();
    for item in evidence {
        let kind = string_field(item, "kind").unwrap_or("unknown");
        *evidence_kinds.entry(kind.to_owned()).or_insert(0_u64) += 1;
    }
    let mut signals = BTreeMap::from([
        ("failed_tool_result".to_owned(), json!(failed_results > 0)),
        ("retry_or_recovery".to_owned(), json!(retries > 0)),
        ("user_correction".to_owned(), json!(corrections > 0)),
        ("environment_context".to_owned(), json!(environment_context)),
        ("multi_user_turn".to_owned(), json!(multi_turn)),
    ]);
    signals.insert(
        "evaluation_evidence_by_kind".to_owned(),
        json!(evidence_kinds),
    );
    signals.insert(
        "scored_evaluation_evidence".to_owned(),
        json!(evidence_rewards.len()),
    );
    SemanticQuality {
        policy_version: "semantic-evidence-v1".to_owned(),
        reward_available: reward.is_some() && reward_source.is_some(),
        reward,
        reward_source,
        realism_signal_score: signal_score,
        evidence_count: evidence.len() as u64,
        signals,
        scope: "reward is copied from an attributed 0-1 evaluator or averaged from captured test/build/search/acceptance evidence; realism signals remain non-reward metadata".to_owned(),
    }
}

fn evidence_reward(evidence: &Value) -> Option<f64> {
    if let Some(reward) = evidence
        .get("reward")
        .or_else(|| evidence.get("score"))
        .and_then(Value::as_f64)
        .filter(|reward| (0.0..=1.0).contains(reward))
    {
        return Some(reward);
    }
    if let Some(passed) = evidence.get("passed").and_then(Value::as_bool) {
        return Some(f64::from(passed));
    }
    match string_field(evidence, "status")?
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "success" | "succeeded" | "accepted" | "completed" => Some(1.0),
        "fail" | "failed" | "error" | "rejected" | "cancelled" | "canceled" => Some(0.0),
        _ => None,
    }
}

fn count_tokens(session: &Value, called_names: &BTreeSet<String>) -> TokenCounts {
    let usage = session.get("usage").unwrap_or(&Value::Null);
    let api_input = u64_field(usage, &["input_tokens", "prompt_tokens"]);
    let cached = u64_field(
        usage,
        &[
            "cached_input_tokens",
            "cache_read_input_tokens",
            "cached_tokens",
        ],
    )
    .max(
        usage
            .pointer("/input_tokens_details/cached_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    );
    let cache_write = u64_field(
        usage,
        &["cache_write_tokens", "cache_creation_input_tokens"],
    );
    let output = u64_field(usage, &["output_tokens", "completion_tokens"]);
    let reasoning = u64_field(usage, &["reasoning_tokens"]).max(
        usage
            .pointer("/output_tokens_details/reasoning_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    );
    let total = u64_field(usage, &["total_tokens"]).max(api_input.saturating_add(output));

    let called_tools: Vec<Value> = session
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|tool| {
            let nested = tool.get("function").unwrap_or(tool);
            string_field(nested, "name").is_some_and(|name| called_names.contains(name))
        })
        .cloned()
        .collect();
    let corpus = json!({
        "tools": called_tools,
        "messages": session.get("messages").cloned().unwrap_or_else(|| json!([])),
    });
    let mut excluded = 0_u64;
    let scrubbed = scrub_base64(&corpus, None, &mut excluded);
    let corpus_text = serde_json::to_string(&scrubbed).unwrap_or_default();
    let normalized = o200k_base_singleton().encode_ordinary(&corpus_text).len() as u64;

    let assistant_outputs: Vec<Value> = session
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|message| string_field(message, "role") == Some("assistant"))
        .map(|message| {
            json!({
                "content": message.get("content").cloned().unwrap_or(Value::Null),
                "reasoning": message.get("reasoning").cloned().unwrap_or(Value::Null),
                "thinking": message.get("thinking").cloned().unwrap_or(Value::Null),
                "tool_calls": message.get("tool_calls").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let mut supervised_excluded = 0_u64;
    let supervised = scrub_base64(&json!(assistant_outputs), None, &mut supervised_excluded);
    let supervised_text = serde_json::to_string(&supervised).unwrap_or_default();
    let supervised_tokens = o200k_base_singleton()
        .encode_ordinary(&supervised_text)
        .len() as u64;

    TokenCounts {
        api_input_tokens: api_input,
        api_cached_input_tokens: cached,
        api_cache_write_tokens: cache_write,
        api_output_tokens: output,
        api_reasoning_tokens: reasoning,
        api_total_tokens: total,
        normalized_corpus_tokens: normalized,
        supervised_output_tokens: supervised_tokens,
        excluded_base64_bytes: excluded,
        tokenizer: "o200k_base; canonical called-tool definitions + messages; explicit base64 fields excluded"
            .to_owned(),
    }
}

fn scrub_base64(value: &Value, key: Option<&str>, excluded: &mut u64) -> Value {
    match value {
        Value::String(text) => {
            let explicit_key = key.is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "b64_json" | "base64" | "image_base64" | "audio_base64"
                )
            });
            let data_base64 = text
                .get(..text.len().min(128))
                .is_some_and(|prefix| prefix.to_ascii_lowercase().contains(";base64,"));
            if explicit_key || data_base64 {
                let payload_bytes = text
                    .split_once(";base64,")
                    .map(|(_, payload)| payload.len())
                    .unwrap_or(text.len());
                *excluded = excluded.saturating_add(payload_bytes as u64);
                Value::String("<base64-excluded>".to_owned())
            } else {
                value.clone()
            }
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| scrub_base64(item, key, excluded))
                .collect(),
        ),
        Value::Object(map) => {
            let mut output = Map::new();
            for (field, nested) in map {
                output.insert(field.clone(), scrub_base64(nested, Some(field), excluded));
            }
            Value::Object(output)
        }
        _ => value.clone(),
    }
}

fn nonempty_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        _ => true,
    }
}

fn content_nonempty(message: &Value) -> bool {
    message.get("content").is_some_and(nonempty_value)
}

fn assistant_substantive(message: &Value) -> bool {
    content_nonempty(message)
        || message.get("reasoning").is_some_and(nonempty_value)
        || message.get("thinking").is_some_and(nonempty_value)
}

fn content_text(value: Option<&Value>) -> String {
    fn collect(value: &Value, output: &mut String) {
        match value {
            Value::String(text) => {
                if !output.is_empty() {
                    output.push(' ');
                }
                output.push_str(text);
            }
            Value::Array(items) => {
                for item in items {
                    collect(item, output);
                }
            }
            Value::Object(map) => {
                for key in ["text", "content", "output_text", "input_text"] {
                    if let Some(nested) = map.get(key) {
                        collect(nested, output);
                    }
                }
            }
            _ => {}
        }
    }
    let mut output = String::new();
    if let Some(value) = value {
        collect(value, &mut output);
    }
    output
}

pub fn message_fingerprints(session: &Value) -> Vec<String> {
    session
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|message| {
            let bytes = canonical_bytes(message).unwrap_or_default();
            crate::jsonl::sha256_bytes(&bytes)
        })
        .collect()
}

pub fn exact_content_fingerprint(session: &Value) -> String {
    let content = json!({
        "system_prompt": session.get("system_prompt").cloned().unwrap_or(Value::Null),
        "tools": session.get("tools").cloned().unwrap_or_else(|| json!([])),
        "messages": session.get("messages").cloned().unwrap_or_else(|| json!([])),
    });
    crate::jsonl::sha256_bytes(&canonical_bytes(&content).unwrap_or_default())
}

pub fn eligible_assessment_contract_valid(
    assessment: &BuyerAssessment,
    profile: Profile,
    minimum_score: f64,
) -> bool {
    assessment_contract_valid(assessment, profile, minimum_score) && assessment.eligible
}

pub fn assessment_contract_valid(
    assessment: &BuyerAssessment,
    profile: Profile,
    minimum_score: f64,
) -> bool {
    const REQUIRED_GATES: [&str; 15] = [
        "required_fields",
        "message_roles",
        "first_message_role",
        "system_prompt",
        "effective_turns",
        "structured_tool_calls",
        "valid_tool_results",
        "tool_definitions",
        "tool_pairing_after_open_tail",
        "machine_turn_ratio",
        "assembly_integrity",
        "runtime_dag_integrity",
        "model",
        "session_closed",
        "content_domain",
    ];
    let observed: BTreeSet<&str> = assessment
        .gates
        .iter()
        .map(|gate| gate.name.as_str())
        .collect();
    let expected: BTreeSet<&str> = REQUIRED_GATES.into_iter().collect();
    let gate_contract_valid = assessment.gates.len() == REQUIRED_GATES.len()
        && observed == expected
        && assessment.gates.iter().all(|gate| gate.required);
    let required_gates_pass = assessment
        .gates
        .iter()
        .filter(|gate| gate.required)
        .all(|gate| gate.pass);
    let expected_eligible = required_gates_pass && assessment.score >= minimum_score;
    let expected_score = round(
        assessment
            .gates
            .iter()
            .filter(|gate| gate.pass)
            .map(|gate| gate_weight(&gate.name))
            .sum(),
        3,
    );
    let expected_failures: Vec<String> = assessment
        .gates
        .iter()
        .filter(|gate| gate.required && !gate.pass)
        .map(|gate| gate.name.clone())
        .collect();
    assessment.schema_version == ASSESSMENT_SCHEMA_VERSION
        && assessment.profile == profile.as_str()
        && assessment.profile_version == profile.version()
        && minimum_score.is_finite()
        && (0.0..=100.0).contains(&minimum_score)
        && assessment.minimum_score == minimum_score
        && assessment.score.is_finite()
        && (0.0..=100.0).contains(&assessment.score)
        && assessment.score == expected_score
        && gate_contract_valid
        && assessment.hard_gate_pass == required_gates_pass
        && assessment.eligible == expected_eligible
        && assessment.failure_reasons == expected_failures
}

fn gate_weight(name: &str) -> f64 {
    match name {
        "required_fields" | "message_roles" | "first_message_role" | "system_prompt"
        | "valid_tool_results" | "model" | "session_closed" => 5.0,
        "structured_tool_calls" | "machine_turn_ratio" => 10.0,
        "effective_turns" | "tool_definitions" | "tool_pairing_after_open_tail" => 15.0,
        _ => 0.0,
    }
}

pub fn is_contiguous_subsequence(needle: &[String], haystack: &[String]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn round(value: f64, places: u32) -> f64 {
    let factor = 10_f64.powi(places as i32);
    (value * factor).round() / factor
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> Value {
        json!({
            "name": name,
            "description": format!("Run {name}."),
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {"type": "string", "description": "Input value."}
                }
            }
        })
    }

    #[test]
    fn native_runtime_evidence_requires_a_complete_runtime_dag() {
        let mut session = json!({
            "trajectory_id":"runtime-gate",
            "session_id":"runtime-gate",
            "provider":"OpenAI",
            "model":"gpt-5.6-sol",
            "created_at":"2026-08-29T00:00:00Z",
            "status":"incomplete",
            "is_final_snapshot":false,
            "source_request_count":0,
            "system_prompt":"system",
            "tools":[],
            "messages":[{"role":"system","content":"system"}],
            "usage":{},
            "meta":{
                "rollout_events":[{"source":"codex_rollout_trace_bundle"}],
                "runtime_dag":{
                    "applicable":true,
                    "native_event_count":4,
                    "complete":false,
                    "open_node_ids":["trace:tool:open"],
                    "unresolved_node_ids":[]
                }
            }
        });
        let quality = assess_session(&session, Profile::BuyerV7, 90.0);
        let gate = quality
            .buyer_acceptance
            .gates
            .iter()
            .find(|gate| gate.name == "runtime_dag_integrity")
            .unwrap();
        assert!(!gate.pass);
        assert_eq!(quality.buyer_acceptance.metrics.runtime_dag_open_nodes, 1);

        session["meta"]["runtime_dag"]["complete"] = json!(true);
        session["meta"]["runtime_dag"]["open_node_ids"] = json!([]);
        let quality = assess_session(&session, Profile::BuyerV7, 90.0);
        let gate = quality
            .buyer_acceptance
            .gates
            .iter()
            .find(|gate| gate.name == "runtime_dag_integrity")
            .unwrap();
        assert!(gate.pass);

        session["meta"]
            .as_object_mut()
            .unwrap()
            .remove("runtime_dag");
        let quality = assess_session(&session, Profile::BuyerV7, 90.0);
        let gate = quality
            .buyer_acceptance
            .gates
            .iter()
            .find(|gate| gate.name == "runtime_dag_integrity")
            .unwrap();
        assert!(!gate.pass);
    }

    #[test]
    fn buyer_v7_requires_hard_gates_not_only_numeric_score() {
        let session = json!({
            "schema_version": "chiptrace.session.v1",
            "trajectory_id": "traj-1",
            "session_id": "session-1",
            "provider": "OpenAI",
            "model": "gpt-5.6-sol",
            "created_at": "2026-08-27T00:00:00Z",
            "ended_at": "2026-08-27T00:01:00Z",
            "status": "completed",
            "is_final_snapshot": true,
            "source_request_count": 1,
            "system_prompt": "You are a coding agent.",
            "tools": [tool("exec_command")],
            "messages": [
                {"role": "system", "content": "You are a coding agent."},
                {"role": "user", "content": "Run the tests in /work/repo."},
                {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "name": "exec_command", "arguments": {"cmd": "test"}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "ok", "status": "success", "is_error": false},
                {"role": "assistant", "content": "Done."}
            ],
            "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
            "meta": {"model_evidence": {"request_models": ["gpt-5.6-sol"], "response_models": ["gpt-5.6-sol"]}}
        });
        let assessment = assess_session(&session, Profile::BuyerV7, 90.0);
        assert!(!assessment.buyer_acceptance.eligible);
        assert!(
            assessment
                .buyer_acceptance
                .failure_reasons
                .contains(&"effective_turns".to_owned())
        );
        assert!(
            assessment
                .buyer_acceptance
                .failure_reasons
                .contains(&"structured_tool_calls".to_owned())
        );
    }

    #[test]
    fn system_message_can_supply_the_required_system_prompt() {
        let session = json!({
            "trajectory_id": "traj-system-message",
            "session_id": "session-system-message",
            "provider": "OpenAI",
            "model": "gpt-5.6-sol",
            "created_at": "2026-08-27T00:00:00Z",
            "status": "incomplete",
            "is_final_snapshot": false,
            "source_request_count": 1,
            "system_prompt": null,
            "tools": [],
            "messages": [
                {"role": "system", "content": "You are a coding agent."},
                {"role": "user", "content": "Inspect the repository."}
            ],
            "usage": null
        });
        let quality = assess_session(&session, Profile::BuyerV7, 90.0);
        let gate = quality
            .buyer_acceptance
            .gates
            .iter()
            .find(|gate| gate.name == "required_fields")
            .unwrap();
        assert!(gate.pass);
    }

    #[test]
    fn malformed_tool_arguments_fail_the_structured_call_gate() {
        let session = json!({
            "trajectory_id": "traj-invalid-args",
            "session_id": "session-invalid-args",
            "provider": "OpenAI",
            "model": "gpt-5.6-sol",
            "created_at": "2026-08-27T00:00:00Z",
            "status": "completed",
            "is_final_snapshot": true,
            "source_request_count": 1,
            "system_prompt": "system",
            "tools": [tool("read_workspace")],
            "messages": [
                {"role": "system", "content": "system"},
                {"role": "user", "content": "Inspect the workspace."},
                {"role": "assistant", "content": "", "tool_calls": [{
                    "id": "call-invalid", "name": "read_workspace", "arguments": "{not-json}"
                }]},
                {"role": "tool", "tool_call_id": "call-invalid", "content": "done", "status": "success"},
                {"role": "assistant", "content": "Done."}
            ],
            "usage": {}
        });
        let quality = assess_session(&session, Profile::BuyerV6, 0.0);
        assert_eq!(quality.buyer_acceptance.metrics.invalid_tool_arguments, 1);
        assert!(
            quality
                .buyer_acceptance
                .failure_reasons
                .contains(&"structured_tool_calls".to_owned())
        );
    }

    #[test]
    fn buyer_v6_requires_two_human_user_assistant_turns() {
        let session = json!({
            "trajectory_id": "traj-v6-turns",
            "session_id": "session-v6-turns",
            "provider": "OpenAI",
            "model": "gpt-5",
            "created_at": "2026-08-27T00:00:00Z",
            "status": "completed",
            "is_final_snapshot": true,
            "source_request_count": 1,
            "system_prompt": "system",
            "tools": [tool("run_tests")],
            "messages": [
                {"role": "system", "content": "system"},
                {"role": "user", "content": "Run the tests."},
                {"role": "assistant", "content": "", "tool_calls": [{
                    "id": "call-1", "name": "run_tests", "arguments": {}
                }]},
                {"role": "tool", "tool_call_id": "call-1", "content": "passed"},
                {"role": "assistant", "content": "The tests passed."}
            ],
            "usage": {}
        });
        let quality = assess_session(&session, Profile::BuyerV6, 0.0);
        assert_eq!(
            quality.buyer_acceptance.metrics.human_user_assistant_turns,
            1
        );
        assert!(
            quality
                .buyer_acceptance
                .failure_reasons
                .contains(&"effective_turns".to_owned())
        );
    }

    #[test]
    fn buyer_v7_requires_two_human_user_assistant_turns() {
        let calls: Vec<Value> = (0..9)
            .map(|index| {
                json!({
                    "id": format!("call-{index}"),
                    "name": format!("tool-{index}"),
                    "arguments": {}
                })
            })
            .collect();
        let mut messages = vec![
            json!({"role":"system","content":"system"}),
            json!({"role":"user","content":"Complete the task in /workspace/repo."}),
            json!({"role":"assistant","content":"Running tools.","tool_calls":calls}),
        ];
        messages.extend((0..9).map(|index| {
            json!({
                "role":"tool",
                "tool_call_id":format!("call-{index}"),
                "content":"result",
                "status":"success"
            })
        }));
        messages.push(json!({"role":"assistant","content":"Done."}));
        let session = json!({
            "trajectory_id":"trajectory-one-human-turn",
            "session_id":"session-one-human-turn",
            "provider":"OpenAI",
            "model":"gpt-5.6-sol",
            "created_at":"2026-08-27T00:00:00Z",
            "status":"completed",
            "is_final_snapshot":true,
            "source_request_count":1,
            "system_prompt":"system",
            "tools":[],
            "messages":messages,
            "usage":{}
        });
        let quality = assess_session(&session, Profile::BuyerV7, 90.0);
        assert_eq!(quality.buyer_acceptance.metrics.effective_turns, 10);
        assert_eq!(
            quality.buyer_acceptance.metrics.human_user_assistant_turns,
            1
        );
        assert!(
            !quality
                .buyer_acceptance
                .gates
                .iter()
                .find(|gate| gate.name == "effective_turns")
                .unwrap()
                .pass
        );
    }

    #[test]
    fn embedded_assessment_contract_rejects_missing_gate() {
        let session = json!({
            "trajectory_id":"trajectory-contract",
            "session_id":"session-contract",
            "provider":"OpenAI",
            "model":"gpt-5.6-sol",
            "created_at":"2026-08-27T00:00:00Z",
            "status":"completed",
            "is_final_snapshot":true,
            "source_request_count":1,
            "system_prompt":"system",
            "tools":[],
            "messages":[{"role":"user","content":"work"}],
            "usage":{}
        });
        let mut assessment = assess_session(&session, Profile::BuyerV7, 90.0).buyer_acceptance;
        assessment.gates.pop();
        for gate in &mut assessment.gates {
            gate.required = true;
            gate.pass = true;
        }
        assessment.score = 100.0;
        assessment.hard_gate_pass = true;
        assessment.eligible = true;
        assessment.failure_reasons.clear();
        assert!(!eligible_assessment_contract_valid(
            &assessment,
            Profile::BuyerV7,
            90.0
        ));
    }

    #[test]
    fn only_terminal_open_tail_is_excluded_from_pairing() {
        let session = json!({
            "trajectory_id":"t", "session_id":"s", "provider":"OpenAI", "model":"gpt-5.6-sol",
            "created_at":"2026-08-27T00:00:00Z", "status":"completed", "is_final_snapshot":true,
            "source_request_count":1, "system_prompt":"system", "tools":[tool("exec_command")], "usage":{},
            "messages":[
                {"role":"system","content":"system"},
                {"role":"user","content":"do work"},
                {"role":"assistant","content":"","tool_calls":[{"id":"missing","name":"exec_command","arguments":{}}]},
                {"role":"assistant","content":"done"}
            ]
        });
        let assessment = assess_session(&session, Profile::BuyerV6, 90.0);
        let gate = assessment
            .buyer_acceptance
            .gates
            .iter()
            .find(|gate| gate.name == "tool_pairing_after_open_tail")
            .unwrap();
        assert!(!gate.pass);
    }

    #[test]
    fn contiguous_subsequence_is_order_sensitive() {
        let full = vec!["a".into(), "b".into(), "c".into()];
        assert!(is_contiguous_subsequence(&["a".into(), "b".into()], &full));
        assert!(!is_contiguous_subsequence(&["a".into(), "c".into()], &full));
    }

    #[test]
    fn captured_evaluator_evidence_produces_attributed_reward() {
        let session = json!({
            "trajectory_id":"t", "session_id":"s", "provider":"OpenAI", "model":"gpt-5.6-sol",
            "created_at":"2026-08-27T00:00:00Z", "status":"completed", "is_final_snapshot":true,
            "source_request_count":1, "system_prompt":"system", "tools":[], "usage":{},
            "messages":[{"role":"system","content":"system"}],
            "meta": {
                "evaluation_evidence": [
                    {"kind":"test","source":"cargo test","status":"passed"},
                    {"kind":"build","source":"cargo build","status":"failed"},
                    {"kind":"evaluator","source":"quality-eval-v1","reward":0.8}
                ]
            }
        });
        let quality = assess_session(&session, Profile::BuyerV7, 90.0);
        assert!(quality.semantic_quality.reward_available);
        assert_eq!(quality.semantic_quality.evidence_count, 3);
        assert_eq!(quality.semantic_quality.reward, Some(0.6));
        assert_eq!(
            quality.semantic_quality.reward_source.as_deref(),
            Some("chiptrace.semantic-evidence-v1")
        );
    }

    #[test]
    fn assembly_divergence_is_a_hard_failure() {
        let session = json!({
            "trajectory_id":"t", "session_id":"s", "provider":"OpenAI", "model":"gpt-5.6-sol",
            "created_at":"2026-08-27T00:00:00Z", "status":"completed", "is_final_snapshot":true,
            "source_request_count":1, "system_prompt":"system", "tools":[tool("exec_command")], "usage":{},
            "messages":[{"role":"system","content":"system"}],
            "meta": {"merge_divergences": 1, "schema_conflicts": []}
        });
        let assessment = assess_session(&session, Profile::BuyerV7, 90.0);
        assert!(
            assessment
                .buyer_acceptance
                .failure_reasons
                .contains(&"assembly_integrity".to_owned())
        );
    }

    #[test]
    fn producer_or_tool_state_conflicts_are_hard_failures() {
        let session = json!({
            "trajectory_id":"t", "session_id":"s", "provider":"OpenAI", "model":"gpt-5.6-sol",
            "created_at":"2026-08-29T00:00:00Z", "status":"completed", "is_final_snapshot":true,
            "source_request_count":1, "system_prompt":"system", "tools":[], "usage":{},
            "messages":[{"role":"system","content":"system"}],
            "meta": {
                "merge_divergences":0,
                "schema_conflicts":[],
                "trace_conflicts":[],
                "system_prompt_conflicts":[],
                "usage_conflicts":[],
                "tool_execution_conflicts":["call-1:missing_started_event"],
                "producer_event_conflicts":["dispatcher:stream-1:sequence_gap"],
                "capture_dag":{},
                "task_dag":{}
            }
        });
        let assessment = assess_session(&session, Profile::BuyerV7, 90.0);
        let gate = assessment
            .buyer_acceptance
            .gates
            .iter()
            .find(|gate| gate.name == "assembly_integrity")
            .unwrap();
        assert!(!gate.pass);
        assert_eq!(
            assessment
                .buyer_acceptance
                .metrics
                .assembly_tool_execution_conflicts,
            1
        );
        assert_eq!(
            assessment
                .buyer_acceptance
                .metrics
                .assembly_producer_event_conflicts,
            1
        );
    }

    #[test]
    fn usage_evidence_conflict_is_a_hard_failure() {
        let session = json!({
            "trajectory_id":"t", "session_id":"s", "provider":"OpenAI", "model":"gpt-5.6-sol",
            "created_at":"2026-08-27T00:00:00Z", "status":"completed", "is_final_snapshot":true,
            "source_request_count":1, "system_prompt":"system", "tools":[tool("exec_command")], "usage":{},
            "messages":[{"role":"system","content":"system"}],
            "meta": {
                "merge_divergences":0,
                "schema_conflicts":[],
                "trace_conflicts":[],
                "system_prompt_conflicts":[],
                "usage_conflicts":["cap-1:input_tokens:response=100:sub2api=110"],
                "capture_dag":{},
                "task_dag":{}
            }
        });
        let assessment = assess_session(&session, Profile::BuyerV7, 90.0);
        let gate = assessment
            .buyer_acceptance
            .gates
            .iter()
            .find(|gate| gate.name == "assembly_integrity")
            .unwrap();
        assert!(!gate.pass);
        assert_eq!(
            assessment.buyer_acceptance.metrics.assembly_usage_conflicts,
            1
        );
    }

    #[test]
    fn base64_exclusion_is_not_counted_twice_for_supervised_output() {
        let session = json!({
            "messages": [
                {"role":"assistant", "content":{"image_base64":"YWJj"}}
            ],
            "tools": [],
            "usage": {}
        });
        assert_eq!(
            count_tokens(&session, &BTreeSet::new()).excluded_base64_bytes,
            4
        );
    }

    #[test]
    fn buyer_v7_parses_claude_family_version_names() {
        fn session(model: &str) -> Value {
            json!({
                "provider":"Anthropic",
                "model":model,
                "meta":{"model_evidence":{
                    "request_models":[model],
                    "response_models":[model],
                    "provider_identity_attested":true
                }}
            })
        }
        assert!(model_eligible(&session("claude-opus-4-6"), Profile::BuyerV7).0);
        assert!(model_eligible(&session("claude-sonnet-5"), Profile::BuyerV7).0);
        assert!(!model_eligible(&session("claude-sonnet-4-6"), Profile::BuyerV7).0);
        assert!(!model_eligible(&session("claude-haiku-5"), Profile::BuyerV7).0);
    }

    #[test]
    fn buyer_v7_rejects_heuristic_provider_identity() {
        let mut session = json!({
            "provider":"OpenAI",
            "model":"gpt-5.6-sol",
            "meta":{"model_evidence":{
                "request_models":["gpt-5.6-sol"],
                "response_models":["gpt-5.6-sol"],
                "provider_identity_attested":false
            }}
        });
        assert!(!model_eligible(&session, Profile::BuyerV7).0);
        session["meta"]["model_evidence"]["provider_identity_attested"] = json!(true);
        assert!(model_eligible(&session, Profile::BuyerV7).0);
    }

    #[test]
    fn generated_native_schema_adapter_is_not_a_buyer_v7_definition() {
        let mut definition = tool("exec");
        definition["schema_provenance"] = json!({
            "source":"captured_native_format",
            "source_complete":true,
            "generated_adapter":true
        });
        assert!(tool_definition_complete(&definition, Profile::BuyerV6));
        assert!(!tool_definition_complete(&definition, Profile::BuyerV7));
    }

    #[test]
    fn tool_call_and_error_message_aliases_are_counted() {
        let session = json!({
            "trajectory_id":"alias",
            "session_id":"alias",
            "provider":"OpenAI",
            "model":"gpt-5.6-sol",
            "created_at":"2026-08-28T00:00:00Z",
            "status":"failed",
            "is_final_snapshot":true,
            "source_request_count":1,
            "system_prompt":"system",
            "tools":[tool("run_tests")],
            "messages":[
                {"role":"system","content":"system"},
                {"role":"user","content":"run tests"},
                {"role":"assistant","content":"running","tool_calls":[
                    {"call_id":"alias-call","name":"run_tests","arguments":"{}"}
                ]},
                {"role":"tool","call_id":"alias-call","error_message":"permission denied","status":"error"},
                {"role":"assistant","content":"The command failed."}
            ],
            "usage":{}
        });
        let quality = assess_session(&session, Profile::BuyerV6, 0.0);
        assert_eq!(quality.buyer_acceptance.metrics.tool_calls, 1);
        assert_eq!(quality.buyer_acceptance.metrics.valid_tool_results, 1);
        assert_eq!(
            quality
                .buyer_acceptance
                .metrics
                .paired_required_tool_results,
            1
        );
    }

    #[test]
    fn a_completed_session_cannot_end_on_tool_result_without_assistant() {
        let session = json!({
            "trajectory_id":"tail-result",
            "session_id":"tail-result",
            "provider":"OpenAI",
            "model":"gpt-5.6-sol",
            "created_at":"2026-08-28T00:00:00Z",
            "status":"completed",
            "is_final_snapshot":true,
            "source_request_count":1,
            "system_prompt":"system",
            "tools":[tool("run_tests")],
            "messages":[
                {"role":"system","content":"system"},
                {"role":"user","content":"run tests"},
                {"role":"assistant","content":"running","tool_calls":[
                    {"id":"tail-call","name":"run_tests","arguments":"{}"}
                ]},
                {"role":"tool","tool_call_id":"tail-call","content":"passed","status":"success"}
            ],
            "usage":{}
        });
        let quality = assess_session(&session, Profile::BuyerV6, 0.0);
        assert!(
            !quality
                .buyer_acceptance
                .gates
                .iter()
                .find(|gate| gate.name == "session_closed")
                .unwrap()
                .pass
        );
    }

    #[test]
    fn terminal_lifecycle_allows_explicit_failed_tail_without_assistant() {
        let session = json!({
            "trajectory_id":"failed-tail",
            "session_id":"failed-tail",
            "provider":"OpenAI",
            "model":"gpt-5.6-sol",
            "created_at":"2026-08-28T00:00:00Z",
            "status":"failed",
            "is_final_snapshot":true,
            "source_request_count":1,
            "system_prompt":"system",
            "tools":[tool("run_tests")],
            "messages":[
                {"role":"system","content":"system"},
                {"role":"user","content":"run tests"},
                {"role":"assistant","content":"running","tool_calls":[
                    {"id":"failed-call","name":"run_tests","arguments":"{}"}
                ]},
                {"role":"tool","tool_call_id":"failed-call","content":"permission denied","status":"error"}
            ],
            "meta":{"lifecycle_events":["task_end"]},
            "usage":{}
        });
        let quality = assess_session(&session, Profile::BuyerV6, 0.0);
        assert!(
            quality
                .buyer_acceptance
                .gates
                .iter()
                .find(|gate| gate.name == "session_closed")
                .unwrap()
                .pass
        );
    }
}
