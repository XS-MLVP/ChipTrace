use crate::jsonl::{JsonlWriter, absolute_path, ensure_safe_relative_path, sha256_file, utc_now};
use crate::model_interaction::{
    INTERACTION_PROJECTION_SCHEMA_VERSION, verify_interaction_artifacts,
};
use crate::schema::FileManifest;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use walkdir::WalkDir;

pub const OTLP_EXPORT_SCHEMA_VERSION: &str = "chiptrace.otlp-export.v1";

#[derive(Debug, Clone)]
pub struct OtlpExportConfig {
    pub projection: PathBuf,
    pub output: PathBuf,
    pub zstd_level: i32,
    pub replace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OtlpExportManifest {
    pub schema_version: String,
    pub created_at_utc: String,
    pub source_projection_schema_version: String,
    pub source_projection_manifest_sha256: String,
    #[serde(default)]
    pub source_delivery_ready: bool,
    pub interactions: u64,
    pub runtime_spans: u64,
    pub links: u64,
    pub root_spans: u64,
    pub internal_parent_references: u64,
    pub resolved_internal_parents: u64,
    pub resolved_internal_parent_rate: f64,
    pub missing_parent_nodes: Vec<String>,
    pub body_policy: String,
    pub parts: Vec<FileManifest>,
    pub validation_status: String,
}

pub fn export_otlp(config: OtlpExportConfig) -> Result<OtlpExportManifest> {
    let projection = config.projection.canonicalize()?;
    let source = verify_interaction_artifacts(&projection)?;
    let interactions =
        read_projection_part(&projection.join("interactions/model-interactions.jsonl.zst"))?;
    let runtime_spans = read_projection_part(&projection.join("runtime/runtime-spans.jsonl.zst"))?;
    let links = read_projection_part(&projection.join("links/interaction-links.jsonl.zst"))?;

    let output = absolute_path(&config.output)?;
    if output.exists() && !config.replace {
        bail!("OTLP output already exists: {}", output.display());
    }
    let parent = output.parent().context("OTLP output has no parent")?;
    fs::create_dir_all(parent)?;
    let work = TempDir::new_in(parent)?;
    let staging = work.path().join("otlp-export");
    fs::create_dir_all(staging.join("otlp"))?;

    let (otlp, hierarchy) = project_otlp_tree(&interactions, &runtime_spans, &links)?;
    let parts = vec![write_part(
        &staging,
        "otlp/otlp.jsonl.zst",
        &otlp,
        config.zstd_level,
    )?];
    let manifest = OtlpExportManifest {
        schema_version: OTLP_EXPORT_SCHEMA_VERSION.to_owned(),
        created_at_utc: utc_now(),
        source_projection_schema_version: source.schema_version,
        source_projection_manifest_sha256: sha256_file(&projection.join("manifest.json"))?,
        source_delivery_ready: source.integrity.delivery_ready,
        interactions: interactions.len() as u64,
        runtime_spans: runtime_spans.len() as u64,
        links: links.len() as u64,
        root_spans: hierarchy.root_spans,
        internal_parent_references: hierarchy.internal_parent_references,
        resolved_internal_parents: hierarchy.resolved_internal_parents,
        resolved_internal_parent_rate: hierarchy.resolved_internal_parent_rate,
        missing_parent_nodes: hierarchy.missing_parent_nodes,
        body_policy:
            "normalized_io_and_raw_references; raw wire request and response bodies are not copied"
                .to_owned(),
        parts,
        validation_status: "verified".to_owned(),
    };
    fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    sync_tree(&staging)?;
    verify_otlp_export(&staging)?;
    if output.exists() {
        fs::remove_dir_all(&output)?;
    }
    fs::rename(&staging, &output)?;
    File::open(parent)?.sync_all()?;
    Ok(manifest)
}

pub fn verify_otlp_export(root: &Path) -> Result<OtlpExportManifest> {
    let manifest: OtlpExportManifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json"))?)?;
    if manifest.schema_version != OTLP_EXPORT_SCHEMA_VERSION
        || manifest.source_projection_schema_version != INTERACTION_PROJECTION_SCHEMA_VERSION
        || manifest.validation_status != "verified"
        || manifest.body_policy
            != "normalized_io_and_raw_references; raw wire request and response bodies are not copied"
    {
        bail!("unsupported or unsafe OTLP export manifest");
    }
    let expected_records = manifest.interactions.saturating_add(manifest.runtime_spans);
    let mut expected_files = HashSet::from(["manifest.json".to_owned()]);
    if manifest.parts.len() != 1 || manifest.parts[0].file != "otlp/otlp.jsonl.zst" {
        bail!("OTLP export must contain exactly one OTLP JSONL part");
    }
    let mut otlp_records = Vec::new();
    for part in &manifest.parts {
        ensure_safe_relative_path(&part.file)?;
        expected_files.insert(part.file.clone());
        let path = root.join(&part.file);
        if path.metadata()?.len() != part.bytes || sha256_file(&path)? != part.sha256 {
            bail!("OTLP export checksum mismatch: {}", part.file);
        }
        let values = read_projection_part(&path)?;
        if values.len() as u64 != expected_records || part.records != Some(expected_records) {
            bail!("OTLP export record count mismatch: {}", part.file);
        }
        if values.iter().any(contains_large_body_field) {
            bail!("OTLP export copied a forbidden large body field");
        }
        otlp_records.extend(values);
    }
    let hierarchy = verify_otlp_tree(&otlp_records)?;
    if manifest.root_spans != hierarchy.root_spans
        || manifest.internal_parent_references != hierarchy.internal_parent_references
        || manifest.resolved_internal_parents != hierarchy.resolved_internal_parents
        || manifest.resolved_internal_parent_rate != hierarchy.resolved_internal_parent_rate
        || manifest.missing_parent_nodes != hierarchy.missing_parent_nodes
    {
        bail!("OTLP hierarchy metrics do not match exported spans");
    }
    let actual_files: HashSet<String> = WalkDir::new(root)
        .min_depth(1)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .expect("OTLP export file outside root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    if actual_files != expected_files {
        bail!("OTLP export file set does not match manifest");
    }
    Ok(manifest)
}

fn read_projection_part(path: &Path) -> Result<Vec<Value>> {
    let mut reader = crate::jsonl::open_jsonl_reader(path)?;
    let mut line = Vec::new();
    let mut values = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        values.push(serde_json::from_slice(&line)?);
    }
    Ok(values)
}

fn write_part(root: &Path, relative: &str, values: &[Value], level: i32) -> Result<FileManifest> {
    let path = root.join(relative);
    let mut writer = JsonlWriter::create(&path, level)?;
    let mut uncompressed = 0_u64;
    for value in values {
        uncompressed = uncompressed.saturating_add(writer.write_value(value)?);
    }
    writer.finish()?;
    Ok(FileManifest {
        file: relative.to_owned(),
        sha256: sha256_file(&path)?,
        bytes: path.metadata()?.len(),
        records: Some(values.len() as u64),
        uncompressed_bytes: Some(uncompressed),
        oversized_session: None,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OtlpHierarchy {
    pub(crate) root_spans: u64,
    pub(crate) internal_parent_references: u64,
    pub(crate) resolved_internal_parents: u64,
    pub(crate) resolved_internal_parent_rate: f64,
    pub(crate) missing_parent_nodes: Vec<String>,
}

pub(crate) fn project_otlp_tree(
    interactions: &[Value],
    runtime_spans: &[Value],
    links: &[Value],
) -> Result<(Vec<Value>, OtlpHierarchy)> {
    let mut node_ids = BTreeMap::new();
    let mut emitted_ids = HashSet::new();
    for interaction in interactions {
        if session_id(interaction).is_none() {
            bail!("ModelInteraction is missing session.id context");
        }
        let id = string_field(interaction, "interaction_id")
            .context("ModelInteraction missing interaction_id")?;
        insert_otlp_node(
            &mut node_ids,
            &mut emitted_ids,
            format!("interaction:{id}"),
            projection_ids(interaction, "interaction_id"),
        )?;
    }
    for span in runtime_spans {
        if session_id(span).is_none() {
            bail!("RuntimeSpan is missing session.id context");
        }
        let id = string_field(span, "span_id").context("RuntimeSpan missing span_id")?;
        insert_otlp_node(
            &mut node_ids,
            &mut emitted_ids,
            format!("runtime-span:{id}"),
            projection_ids(span, "span_id"),
        )?;
    }

    let mut parent_nodes: BTreeMap<String, (u8, String)> = BTreeMap::new();
    for link in links {
        let relation = string_field(link, "relation").unwrap_or("");
        let from = string_field(link, "from").unwrap_or("");
        let to = string_field(link, "to").unwrap_or("");
        let (parent, child, priority) = match relation {
            "runtime_parent_to_child" => (from, to, 20),
            "interaction_to_runtime_span" => (from, to, 25),
            "runtime_parent_to_interaction" => (from, to, 10),
            "model_call_to_runtime_execution" => {
                let Some(interaction_id) = from
                    .strip_prefix("model-call:")
                    .and_then(|value| value.split_once(':').map(|(interaction, _)| interaction))
                else {
                    continue;
                };
                let interaction = format!("interaction:{interaction_id}");
                if !node_ids.contains_key(&interaction) {
                    continue;
                }
                let parent_id = node_ids.get(&interaction).unwrap();
                let child_id = node_ids
                    .get(to)
                    .with_context(|| format!("InteractionLink child node is absent: {to}"))?;
                if parent_id.0 != child_id.0 {
                    bail!("InteractionLink crosses OTLP traces: {interaction} -> {to}");
                }
                match parent_nodes.get(to) {
                    Some((existing_priority, _)) if *existing_priority > 30 => {}
                    Some((existing_priority, existing))
                        if *existing_priority == 30 && existing != &interaction =>
                    {
                        bail!("OTLP node {to} has multiple internal parents");
                    }
                    _ => {
                        parent_nodes.insert(to.to_owned(), (30, interaction));
                    }
                }
                continue;
            }
            _ => continue,
        };
        let parent_id = node_ids
            .get(parent)
            .with_context(|| format!("InteractionLink parent node is absent: {parent}"))?;
        let child_id = node_ids
            .get(child)
            .with_context(|| format!("InteractionLink child node is absent: {child}"))?;
        if parent_id.0 != child_id.0 {
            bail!("InteractionLink crosses OTLP traces: {parent} -> {child}");
        }
        match parent_nodes.get(child) {
            Some((existing_priority, _)) if *existing_priority > priority => {}
            Some((existing_priority, existing))
                if *existing_priority == priority && existing != parent =>
            {
                bail!("OTLP node {child} has multiple internal parents");
            }
            _ => {
                parent_nodes.insert(child.to_owned(), (priority, parent.to_owned()));
            }
        }
    }

    let root_nodes: BTreeSet<String> = runtime_spans
        .iter()
        .filter(|span| string_field(span, "span_kind") == Some("task_root"))
        .filter_map(|span| string_field(span, "span_id"))
        .map(|id| format!("runtime-span:{id}"))
        .collect();
    if root_nodes.is_empty() {
        bail!("OTLP export requires at least one canonical root");
    }
    let missing_parent_nodes: Vec<String> = node_ids
        .keys()
        .filter(|node| !root_nodes.contains(*node) && !parent_nodes.contains_key(*node))
        .cloned()
        .collect();
    if !missing_parent_nodes.is_empty() {
        bail!(
            "OTLP internal parent is missing for: {}",
            missing_parent_nodes.join(", ")
        );
    }

    let mut otlp = Vec::with_capacity(node_ids.len());
    for span in runtime_spans
        .iter()
        .filter(|span| string_field(span, "span_kind") == Some("task_root"))
        .chain(
            runtime_spans
                .iter()
                .filter(|span| string_field(span, "span_kind") != Some("task_root")),
        )
    {
        let id = string_field(span, "span_id").unwrap_or("missing");
        let node = format!("runtime-span:{id}");
        let parent_span_id = parent_nodes
            .get(&node)
            .and_then(|(_, parent)| node_ids.get(parent))
            .map(|identity| identity.1.as_str());
        otlp.push(runtime_otlp(span, parent_span_id));
    }
    for interaction in interactions {
        let id = string_field(interaction, "interaction_id").unwrap_or("missing");
        let node = format!("interaction:{id}");
        let parent_span_id = parent_nodes
            .get(&node)
            .and_then(|(_, parent)| node_ids.get(parent))
            .map(|identity| identity.1.as_str());
        otlp.push(interaction_otlp(interaction, parent_span_id));
    }
    let hierarchy = verify_otlp_tree(&otlp)?;
    Ok((otlp, hierarchy))
}

fn insert_otlp_node(
    nodes: &mut BTreeMap<String, (String, String)>,
    emitted_ids: &mut HashSet<(String, String)>,
    node: String,
    identity: (String, String),
) -> Result<()> {
    if !emitted_ids.insert(identity.clone()) {
        bail!(
            "multiple canonical nodes map to OTLP identity {}:{}",
            identity.0,
            identity.1
        );
    }
    nodes.insert(node, identity);
    Ok(())
}

fn verify_otlp_tree(records: &[Value]) -> Result<OtlpHierarchy> {
    let mut spans = Vec::new();
    for record in records {
        let record_spans = record
            .pointer("/resourceSpans/0/scopeSpans/0/spans")
            .and_then(Value::as_array)
            .context("OTLP record has no spans")?;
        if record_spans.len() != 1 {
            bail!("each OTLP JSONL record must contain exactly one span");
        }
        spans.push(&record_spans[0]);
    }
    let mut identities = HashSet::new();
    for span in &spans {
        let trace_id = string_field(span, "traceId").context("OTLP span missing traceId")?;
        let span_id = string_field(span, "spanId").context("OTLP span missing spanId")?;
        if !valid_otel_hex(trace_id, 32) || !valid_otel_hex(span_id, 16) {
            bail!("OTLP span has an invalid traceId or spanId");
        }
        if !identities.insert((trace_id.to_owned(), span_id.to_owned())) {
            bail!("OTLP export contains a duplicate span identity");
        }
    }
    let mut root_spans = 0_u64;
    let mut roots_by_trace: BTreeMap<String, u64> = BTreeMap::new();
    let mut internal_parent_references = 0_u64;
    let mut resolved_internal_parents = 0_u64;
    let mut missing_parent_nodes = Vec::new();
    for span in &spans {
        let trace_id = string_field(span, "traceId").unwrap_or("");
        let span_id = string_field(span, "spanId").unwrap_or("");
        let Some(parent_span_id) = string_field(span, "parentSpanId") else {
            root_spans = root_spans.saturating_add(1);
            *roots_by_trace.entry(trace_id.to_owned()).or_default() += 1;
            continue;
        };
        internal_parent_references = internal_parent_references.saturating_add(1);
        if identities.contains(&(trace_id.to_owned(), parent_span_id.to_owned())) {
            resolved_internal_parents = resolved_internal_parents.saturating_add(1);
        } else {
            missing_parent_nodes.push(format!("{trace_id}:{span_id}"));
        }
    }
    missing_parent_nodes.sort();
    let resolved_internal_parent_rate = if internal_parent_references == 0 {
        if root_spans > 0 { 1.0 } else { 0.0 }
    } else {
        resolved_internal_parents as f64 / internal_parent_references as f64
    };
    if root_spans == 0
        || roots_by_trace.values().any(|roots| *roots != 1)
        || !missing_parent_nodes.is_empty()
        || resolved_internal_parents != internal_parent_references
        || resolved_internal_parent_rate != 1.0
    {
        bail!("OTLP export does not contain exactly one root per trace");
    }
    Ok(OtlpHierarchy {
        root_spans,
        internal_parent_references,
        resolved_internal_parents,
        resolved_internal_parent_rate,
        missing_parent_nodes,
    })
}

fn interaction_otlp(interaction: &Value, parent_span_id: Option<&str>) -> Value {
    let (trace_id, span_id) = projection_ids(interaction, "interaction_id");
    let endpoint = interaction
        .pointer("/protocol/endpoint")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let attributes = vec![
        otlp_attr("openinference.span.kind", json!("LLM")),
        otlp_attr("session.id", json!(session_id(interaction))),
        otlp_attr("gen_ai.conversation.id", json!(session_id(interaction))),
        otlp_attr("gen_ai.operation.name", json!("chat")),
        otlp_attr("chiptrace.protocol.endpoint", json!(endpoint)),
        otlp_attr(
            "gen_ai.provider.name",
            interaction
                .pointer("/extensions/routing/provider_observation")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr(
            "gen_ai.request.model",
            interaction
                .pointer("/request/model")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr(
            "gen_ai.response.model",
            interaction
                .pointer("/response/model")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr(
            "gen_ai.response.id",
            interaction
                .pointer("/response/id")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr(
            "gen_ai.response.tool_calls.count",
            json!(array_len(interaction, "/model_tool_calls")),
        ),
        otlp_attr(
            "gen_ai.usage.input_tokens",
            interaction
                .pointer("/usage/input_tokens")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr(
            "gen_ai.usage.output_tokens",
            interaction
                .pointer("/usage/output_tokens")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr(
            "gen_ai.usage.cached_input_tokens",
            interaction
                .pointer("/usage/cached_input_tokens")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr(
            "gen_ai.usage.reasoning_tokens",
            interaction
                .pointer("/usage/reasoning_tokens")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr(
            "gen_ai.usage.total_tokens",
            interaction
                .pointer("/usage/total_tokens")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr("input.mime_type", json!("application/json")),
        otlp_attr(
            "input.value",
            interaction
                .pointer("/request/input_items")
                .cloned()
                .unwrap_or_else(|| json!([])),
        ),
        otlp_attr("output.mime_type", json!("application/json")),
        otlp_attr(
            "output.value",
            interaction
                .pointer("/response/output_items")
                .cloned()
                .unwrap_or_else(|| json!([])),
        ),
        otlp_attr(
            "chiptrace.raw_capture_refs",
            json!(compact_refs(interaction)),
        ),
    ];
    otlp_record(
        &trace_id,
        &span_id,
        parent_span_id,
        "openai.model_interaction",
        (
            interaction
                .pointer("/timing/started_at")
                .and_then(Value::as_str),
            interaction
                .pointer("/timing/finished_at")
                .and_then(Value::as_str),
        ),
        string_field(
            interaction.pointer("/response").unwrap_or(&Value::Null),
            "status",
        )
        .unwrap_or("incomplete"),
        attributes,
    )
}

fn runtime_otlp(span: &Value, parent_span_id: Option<&str>) -> Value {
    let (trace_id, span_id) = projection_ids(span, "span_id");
    let span_kind = string_field(span, "span_kind").unwrap_or("runtime");
    let openinference_kind = match span_kind {
        "task_root" | "agent" | "turn" | "rollout" => "AGENT",
        "inference" => "LLM",
        _ => "TOOL",
    };
    let operation = match openinference_kind {
        "AGENT" => "invoke_agent",
        "LLM" => "chat",
        _ => "execute_tool",
    };
    let mut attributes = vec![
        otlp_attr("openinference.span.kind", json!(openinference_kind)),
        otlp_attr("session.id", json!(session_id(span))),
        otlp_attr("gen_ai.conversation.id", json!(session_id(span))),
        otlp_attr("gen_ai.operation.name", json!(operation)),
        otlp_attr(
            "gen_ai.tool.name",
            span.get("name").cloned().unwrap_or(Value::Null),
        ),
        otlp_attr(
            "gen_ai.tool.call.id",
            span.get("call_id").cloned().unwrap_or(Value::Null),
        ),
        otlp_attr(
            "tool.name",
            span.get("name").cloned().unwrap_or(Value::Null),
        ),
        otlp_attr(
            "tool.id",
            span.get("call_id").cloned().unwrap_or(Value::Null),
        ),
        otlp_attr(
            "tool.parameters",
            span.get("arguments").cloned().unwrap_or(Value::Null),
        ),
        otlp_attr(
            "tool.json_schema",
            span.get("tool_schema").cloned().unwrap_or(Value::Null),
        ),
        otlp_attr("input.mime_type", json!("application/json")),
        otlp_attr(
            "input.value",
            span.get("arguments").cloned().unwrap_or(Value::Null),
        ),
        otlp_attr("output.mime_type", json!("application/json")),
        otlp_attr(
            "output.value",
            span.get("result")
                .or_else(|| span.get("error"))
                .cloned()
                .unwrap_or(Value::Null),
        ),
        otlp_attr(
            "chiptrace.parent_span_id",
            span.get("parent_span_id").cloned().unwrap_or(Value::Null),
        ),
        otlp_attr(
            "chiptrace.raw_capture_refs",
            span.get("raw_capture_refs")
                .cloned()
                .unwrap_or_else(|| json!([])),
        ),
    ];
    if openinference_kind != "TOOL" {
        attributes.retain(|attribute| {
            attribute["key"]
                .as_str()
                .is_none_or(|key| !key.starts_with("tool.") && !key.starts_with("gen_ai.tool."))
        });
    }
    otlp_record(
        &trace_id,
        &span_id,
        parent_span_id,
        string_field(span, "name").unwrap_or("runtime"),
        (
            string_field(span, "started_at"),
            string_field(span, "finished_at"),
        ),
        string_field(span, "status").unwrap_or("unknown"),
        attributes,
    )
}

fn otlp_record(
    trace_id: &str,
    span_id: &str,
    parent_span_id: Option<&str>,
    name: &str,
    timing: (Option<&str>, Option<&str>),
    status: &str,
    attributes: Vec<Value>,
) -> Value {
    let mut span = json!({
        "traceId":trace_id,
        "spanId":span_id,
        "name":name,
        "kind":"SPAN_KIND_INTERNAL",
        "startTimeUnixNano":rfc3339_nanos(timing.0),
        "endTimeUnixNano":rfc3339_nanos(timing.1),
        "attributes":attributes,
        "status":{
            "code":match status {
                "failed" => "STATUS_CODE_ERROR",
                "completed" => "STATUS_CODE_OK",
                _ => "STATUS_CODE_UNSET",
            },
            "message":status,
        },
    });
    if let Some(parent_span_id) = parent_span_id
        .filter(|value| valid_otel_hex(value, 16))
        .filter(|value| *value != span_id)
    {
        span["parentSpanId"] = json!(parent_span_id.to_ascii_lowercase());
    }
    json!({
        "resourceSpans":[{
            "resource":{"attributes":[otlp_attr("service.name", json!("chiptrace"))]},
            "scopeSpans":[{
                "scope":{"name":"chiptrace.otlp-export","version":env!("CARGO_PKG_VERSION")},
                "spans":[span]
            }]
        }]
    })
}

fn projection_ids(value: &Value, identity_field: &str) -> (String, String) {
    let traceparent = value
        .pointer("/trace_context/traceparent")
        .and_then(Value::as_str);
    let trace_id = traceparent
        .and_then(|value| value.split('-').nth(1))
        .filter(|value| valid_otel_hex(value, 32))
        .or_else(|| {
            value
                .pointer("/trace_context/trace_id")
                .and_then(Value::as_str)
                .filter(|value| valid_otel_hex(value, 32))
        })
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| {
            let seed = value
                .pointer("/trace_context/task_session_id")
                .and_then(Value::as_str)
                .or_else(|| {
                    value
                        .pointer("/trace_context/root_turn_id")
                        .and_then(Value::as_str)
                })
                .or_else(|| {
                    value
                        .pointer("/trace_context/turn_id")
                        .and_then(Value::as_str)
                })
                .or_else(|| string_field(value, identity_field))
                .unwrap_or("missing");
            sha256(seed.as_bytes())[..32].to_owned()
        });
    let span_seed = string_field(value, identity_field).unwrap_or("missing");
    let span_id = sha256(span_seed.as_bytes())[..16].to_owned();
    (trace_id, span_id)
}

fn session_id(value: &Value) -> Option<&str> {
    value
        .pointer("/trace_context/session_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            value
                .pointer("/trace_context/task_session_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
}

fn valid_otel_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

fn otlp_attr(key: &str, value: Value) -> Value {
    let value = match value {
        Value::Bool(value) => json!({"boolValue":value}),
        Value::Number(value) => json!({"intValue":value.to_string()}),
        Value::Null => json!({"stringValue":""}),
        Value::String(value) => json!({"stringValue":value}),
        value => json!({"stringValue":serde_json::to_string(&value).unwrap_or_default()}),
    };
    json!({"key":key,"value":value})
}

fn compact_refs(value: &Value) -> Value {
    Value::Array(
        value
            .get("raw_capture_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|reference| {
                json!({
                    "capture_id":reference.get("capture_id"),
                    "request_body_sha256":reference.get("request_body_sha256"),
                    "response_body_sha256":reference.get("response_body_sha256"),
                })
            })
            .collect(),
    )
}

fn contains_large_body_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "request" | "response" | "arguments" | "result" | "input_body" | "output_body"
            ) || contains_large_body_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_large_body_field),
        _ => false,
    }
}

fn array_len(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map_or(0, |items| items.len() as u64)
}

fn rfc3339_nanos(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "0".to_owned();
    };
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.to_owned();
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .and_then(|value| u128::try_from(value.unix_timestamp_nanos()).ok())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "0".to_owned())
}

fn string_field<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value.get(name).and_then(Value::as_str)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sync_tree(root: &Path) -> Result<()> {
    for entry in WalkDir::new(root).contents_first(true) {
        let entry = entry?;
        if entry.file_type().is_file() || entry.file_type().is_dir() {
            File::open(entry.path())?.sync_all()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_projections_do_not_copy_raw_bodies_or_tool_payloads() {
        let interaction = json!({
            "interaction_id":"interaction-1",
            "protocol":{"endpoint":"responses"},
            "trace_context":{"task_session_id":"task-1"},
            "request":{"model":"model","input_items":[{},{}],"raw":{"secret":"large"}},
            "response":{"id":"resp-1","model":"model","status":"completed","output_items":[{}],"raw":{"secret":"large"}},
            "model_tool_calls":[{"arguments":{"secret":"large"}}],
            "usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5},
            "timing":{"started_at":"2026-08-30T00:00:00Z","finished_at":"2026-08-30T00:00:01Z"},
            "raw_capture_refs":[{"capture_id":"cap-1","request_body_sha256":"aa","response_body_sha256":"bb"}]
        });
        let value = interaction_otlp(&interaction, Some("1111111111111111"));
        assert!(!value.to_string().contains("large"));
        assert!(!contains_large_body_field(&value));
        assert!(value.to_string().contains("cap-1"));
    }

    #[test]
    fn otlp_summary_uses_canonical_identity_parent_and_nanosecond_time() {
        let span = json!({
            "span_id":"runtime-imported",
            "trace_context":{
                "trace_id":"0123456789abcdef0123456789abcdef",
                "span_id":"2222222222222222",
                "parent_span_id":"1111111111111111"
            },
            "span_kind":"tool_execution",
            "name":"run_tests",
            "parent_span_id":"1111111111111111",
            "status":"completed",
            "started_at":"100",
            "finished_at":"200",
            "raw_capture_refs":["otlp-source-test"],
        });
        let projected = runtime_otlp(&span, Some("1111111111111111"));
        let output = &projected["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(output["traceId"], "0123456789abcdef0123456789abcdef");
        assert_eq!(output["spanId"], &sha256(b"runtime-imported")[..16]);
        assert_eq!(output["parentSpanId"], "1111111111111111");
        assert_eq!(output["startTimeUnixNano"], "100");
        assert_eq!(output["endTimeUnixNano"], "200");
        assert_eq!(output["status"]["code"], "STATUS_CODE_OK");
    }

    #[test]
    fn otlp_tree_uses_interaction_links_and_resolves_every_parent() {
        let trace_id = "0123456789abcdef0123456789abcdef";
        let root = json!({
            "span_id":"runtime-root",
            "trace_context":{"trace_id":trace_id,"span_id":"1111111111111111","session_id":"session-1","task_session_id":"task-1"},
            "span_kind":"task_root","name":"task","status":"completed",
            "started_at":"100","finished_at":"400","raw_capture_refs":["root"]
        });
        let child = json!({
            "span_id":"runtime-inference",
            "trace_context":{"trace_id":trace_id,"span_id":"2222222222222222","session_id":"session-1","task_session_id":"task-1"},
            "span_kind":"inference","name":"model_inference","status":"completed",
            "started_at":"200","finished_at":"300","raw_capture_refs":["inference"]
        });
        let interaction = json!({
            "interaction_id":"interaction-1",
            "protocol":{"endpoint":"responses"},
            "trace_context":{"trace_id":trace_id,"session_id":"session-1","task_session_id":"task-1"},
            "request":{"model":"model","input_items":[]},
            "response":{"id":"resp-1","model":"model","status":"completed","output_items":[]},
            "model_tool_calls":[],
            "usage":null,
            "timing":{"started_at":"200","finished_at":"300"},
            "raw_capture_refs":[{"capture_id":"capture-1"}]
        });
        let links = vec![
            json!({
                "relation":"runtime_parent_to_interaction",
                "from":"runtime-span:runtime-root",
                "to":"interaction:interaction-1"
            }),
            json!({
                "relation":"interaction_to_runtime_span",
                "from":"interaction:interaction-1",
                "to":"runtime-span:runtime-inference"
            }),
        ];
        let (records, hierarchy) =
            project_otlp_tree(&[interaction], &[root, child], &links).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(hierarchy.root_spans, 1);
        assert_eq!(hierarchy.internal_parent_references, 2);
        assert_eq!(hierarchy.resolved_internal_parents, 2);
        assert_eq!(hierarchy.resolved_internal_parent_rate, 1.0);
        assert!(hierarchy.missing_parent_nodes.is_empty());
        for record in &records {
            let attributes = record["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
                .as_array()
                .unwrap();
            let keys: BTreeSet<&str> = attributes
                .iter()
                .filter_map(|attribute| attribute["key"].as_str())
                .collect();
            assert!(keys.contains("openinference.span.kind"));
            assert!(keys.contains("session.id"));
        }
    }

    #[test]
    fn otlp_export_accepts_multiple_turn_traces_with_one_root_each() {
        let roots = ["turn-a", "turn-b"].map(|turn| {
            json!({
                "span_id":format!("root-{turn}"),
                "trace_context":{"session_id":"session-1","root_turn_id":turn},
                "span_kind":"task_root","name":"turn","status":"completed",
                "started_at":"100","finished_at":"200","raw_capture_refs":[turn]
            })
        });
        let (records, hierarchy) = project_otlp_tree(&[], &roots, &[]).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(hierarchy.root_spans, 2);
        assert_eq!(hierarchy.resolved_internal_parent_rate, 1.0);
        assert!(verify_otlp_tree(&records).is_ok());
    }

    #[test]
    fn otlp_verifier_rejects_missing_internal_parent() {
        let root = runtime_otlp(
            &json!({
                "span_id":"runtime-root",
                "trace_context":{
                    "trace_id":"0123456789abcdef0123456789abcdef",
                    "span_id":"1111111111111111"
                },
                "span_kind":"task_root","name":"task","status":"completed",
                "raw_capture_refs":["root"]
            }),
            None,
        );
        let child = runtime_otlp(
            &json!({
                "span_id":"runtime-child",
                "trace_context":{
                    "trace_id":"0123456789abcdef0123456789abcdef",
                    "span_id":"2222222222222222"
                },
                "span_kind":"tool_execution","name":"tool","status":"completed",
                "raw_capture_refs":["child"]
            }),
            Some("3333333333333333"),
        );
        assert!(verify_otlp_tree(&[root, child]).is_err());
    }
}
