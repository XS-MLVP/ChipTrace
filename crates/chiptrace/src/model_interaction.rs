use crate::capture::{extract_body, validate_stored_capture};
use crate::jsonl::{JsonlWriter, absolute_path, ensure_safe_relative_path, sha256_file, utc_now};
use crate::schema::{FileManifest, RAW_LINEAGE_SCHEMA_VERSION, RawSourceLineage};
use crate::session_lineage::StockSessionLineage;
use crate::tool_registry::canonical_runtime_tool_name;
use crate::wire_tools::request_tool_definitions as captured_request_tool_definitions;
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use walkdir::WalkDir;

pub const MODEL_INTERACTION_SCHEMA_VERSION: &str = "chiptrace.model-interaction.v1";
pub const RUNTIME_SPAN_SCHEMA_VERSION: &str = "chiptrace.runtime-span.v1";
pub const INTERACTION_LINK_SCHEMA_VERSION: &str = "chiptrace.interaction-link.v1";
pub const INTERACTION_PROJECTION_SCHEMA_VERSION: &str = "chiptrace.interaction-projection.v1";
const ADAPTER_VERSION: &str = "chiptrace.openai-shape-adapter.v1";

#[derive(Debug, Clone)]
pub struct InteractionProjectConfig {
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
    pub task_session_id: Option<String>,
    pub session_id: Option<String>,
    pub zstd_level: i32,
    pub replace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InteractionProjectionManifest {
    pub schema_version: String,
    pub created_at_utc: String,
    pub task_session_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    pub input_records: u64,
    pub duplicate_captures_removed: u64,
    pub api_snapshots: u64,
    pub interactions: u64,
    pub runtime_spans: u64,
    pub links: u64,
    pub protocol_counts: BTreeMap<String, u64>,
    pub transport_counts: BTreeMap<String, u64>,
    pub distinct_model_tool_names: BTreeSet<String>,
    pub integrity: DeliveryIntegrity,
    pub metrics: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_sources: Vec<RawSourceLineage>,
    pub parts: Vec<FileManifest>,
    pub validation_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryIntegrity {
    pub artifact_valid: bool,
    pub raw_bytes_complete: bool,
    pub protocol_complete: bool,
    pub runtime_complete: bool,
    pub root_complete: bool,
    pub delivery_ready: bool,
}

#[derive(Debug)]
struct RuntimeIntegrity {
    runtime_complete: bool,
    root_complete: bool,
    metrics: Value,
}

struct CanonicalRecords {
    interactions: Vec<Value>,
    runtime_spans: Vec<Value>,
    links: Vec<Value>,
}

pub(crate) struct CanonicalTraceSummary {
    pub runtime_dag: Value,
    pub readiness: Value,
}

#[derive(Debug, Clone)]
struct WireBody {
    captured: Value,
    parsed: Value,
    raw_utf8: Option<String>,
    declared_sha256: Option<String>,
    declared_bytes: Option<u64>,
    raw_sha256_matches: Option<bool>,
    raw_bytes_match: Option<bool>,
    truncated: bool,
}

#[derive(Debug, Clone)]
struct SseEvent {
    index: usize,
    event: Option<String>,
    data_raw: String,
    data: Option<Value>,
    byte_start: usize,
    byte_end: usize,
}

#[derive(Debug, Clone, Copy)]
struct SseByteRange {
    event_index: usize,
    byte_start: usize,
    byte_end: usize,
}

#[derive(Debug, Clone)]
struct ProtocolShape {
    family: &'static str,
    endpoint: &'static str,
    transport: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamOutcome {
    Completed,
    Failed,
    Incomplete,
    Cancelled,
    EofWithoutTerminal,
    TransportError,
}

impl StreamOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Incomplete => "incomplete",
            Self::Cancelled => "cancelled",
            Self::EofWithoutTerminal => "eof_without_terminal",
            Self::TransportError => "transport_error",
        }
    }
}

#[derive(Debug, Clone)]
struct StreamState {
    outcome: StreamOutcome,
    model_status: &'static str,
    upstream_transport_status: &'static str,
    client_delivery_status: &'static str,
    protocol_terminal_observed: bool,
    framing_done_observed: bool,
    error_event: Option<Value>,
}

#[derive(Debug, Clone)]
struct ResponsesStreamView {
    response: Value,
    events: Value,
    tool_call_event_ranges: BTreeMap<String, SseByteRange>,
    terminal_outcome: Option<StreamOutcome>,
    protocol_terminal_observed: bool,
    framing_done_observed: bool,
    malformed_events: u64,
    framing_recovered_events: u64,
    error_event: Option<Value>,
}

struct CanonicalValidators {
    model_interaction: jsonschema::Validator,
    runtime_span: jsonschema::Validator,
    interaction_link: jsonschema::Validator,
}

impl CanonicalValidators {
    fn new() -> Result<Self> {
        Ok(Self {
            model_interaction: compile_schema(
                "model-interaction-v1.schema.json",
                include_str!("../../../schemas/model-interaction-v1.schema.json"),
            )?,
            runtime_span: compile_schema(
                "runtime-span-v1.schema.json",
                include_str!("../../../schemas/runtime-span-v1.schema.json"),
            )?,
            interaction_link: compile_schema(
                "interaction-link-v1.schema.json",
                include_str!("../../../schemas/interaction-link-v1.schema.json"),
            )?,
        })
    }

    fn for_version(&self, schema_version: &str) -> Result<&jsonschema::Validator> {
        match schema_version {
            MODEL_INTERACTION_SCHEMA_VERSION => Ok(&self.model_interaction),
            RUNTIME_SPAN_SCHEMA_VERSION => Ok(&self.runtime_span),
            INTERACTION_LINK_SCHEMA_VERSION => Ok(&self.interaction_link),
            _ => bail!("no canonical validator for schema {schema_version}"),
        }
    }
}

fn compile_schema(name: &str, source: &str) -> Result<jsonschema::Validator> {
    let schema: Value =
        serde_json::from_str(source).with_context(|| format!("parse JSON Schema {name}"))?;
    jsonschema::draft202012::new(&schema)
        .map_err(|error| anyhow::anyhow!("compile JSON Schema {name}: {error}"))
}

fn validate_canonical_records(
    validator: &jsonschema::Validator,
    schema_version: &str,
    records: &[Value],
    source: &str,
) -> Result<()> {
    for (index, record) in records.iter().enumerate() {
        if let Err(error) = validator.validate(record) {
            bail!(
                "{schema_version} validation failed in {source} record {} at {}: {error}",
                index + 1,
                error.instance_path()
            );
        }
    }
    Ok(())
}

pub fn project_interactions(
    config: InteractionProjectConfig,
) -> Result<InteractionProjectionManifest> {
    if config.inputs.is_empty() {
        bail!("at least one Capture input is required");
    }
    let inputs = discover_inputs(&config.inputs)?;
    if inputs.is_empty() {
        bail!("no Capture JSONL inputs found");
    }
    let raw_sources = discover_raw_sources(&config.inputs, &inputs)?;
    let output = absolute_path(&config.output)?;
    if output.exists() && !config.replace {
        bail!("interaction output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("interaction output has no parent"))?;
    fs::create_dir_all(parent)?;

    let (mut captures, duplicate_captures_removed) = read_captures(&inputs)?;
    apply_exact_task_links(&mut captures)?;
    let (mut captures, task_session_id, session_id) = select_projection_captures(
        captures,
        config.task_session_id.as_deref(),
        config.session_id.as_deref(),
    )?;
    captures.sort_by_key(capture_order_key);
    let capture_records = captures.len() as u64;

    let CanonicalRecords {
        interactions,
        runtime_spans,
        links,
    } = build_canonical_records(&captures)?;
    let (raw_bytes_complete, protocol_complete, interaction_metrics) =
        aggregate_interaction_integrity(&interactions);
    let runtime = runtime_integrity(&interactions, &runtime_spans, &links);
    let integrity = DeliveryIntegrity {
        artifact_valid: true,
        raw_bytes_complete,
        protocol_complete,
        runtime_complete: runtime.runtime_complete,
        root_complete: runtime.root_complete,
        delivery_ready: raw_bytes_complete
            && protocol_complete
            && runtime.runtime_complete
            && runtime.root_complete,
    };
    let metrics = json!({
        "interactions":interaction_metrics,
        "runtime":runtime.metrics,
    });

    let mut protocol_counts = BTreeMap::new();
    let mut transport_counts = BTreeMap::new();
    let mut distinct_model_tool_names = BTreeSet::new();
    for interaction in &interactions {
        if let Some(endpoint) = interaction
            .pointer("/protocol/endpoint")
            .and_then(Value::as_str)
        {
            *protocol_counts.entry(endpoint.to_owned()).or_insert(0) += 1;
        }
        if let Some(transport) = interaction
            .pointer("/protocol/transport")
            .and_then(Value::as_str)
        {
            *transport_counts.entry(transport.to_owned()).or_insert(0) += 1;
        }
        for name in interaction
            .get("model_tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|call| call.get("name").and_then(Value::as_str))
            .filter(|name| !name.trim().is_empty())
        {
            distinct_model_tool_names.insert(name.to_owned());
        }
    }

    let work = TempDir::new_in(parent)?;
    let staging = work.path().join("interactions");
    fs::create_dir_all(staging.join("interactions"))?;
    fs::create_dir_all(staging.join("runtime"))?;
    fs::create_dir_all(staging.join("links"))?;
    let parts = vec![
        write_part(
            &staging,
            "interactions/model-interactions.jsonl.zst",
            &interactions,
            config.zstd_level,
        )?,
        write_part(
            &staging,
            "runtime/runtime-spans.jsonl.zst",
            &runtime_spans,
            config.zstd_level,
        )?,
        write_part(
            &staging,
            "links/interaction-links.jsonl.zst",
            &links,
            config.zstd_level,
        )?,
    ];
    let manifest = InteractionProjectionManifest {
        schema_version: INTERACTION_PROJECTION_SCHEMA_VERSION.to_owned(),
        created_at_utc: utc_now(),
        task_session_id,
        session_id,
        input_records: capture_records,
        duplicate_captures_removed,
        api_snapshots: interactions.len() as u64,
        interactions: interactions.len() as u64,
        runtime_spans: runtime_spans.len() as u64,
        links: links.len() as u64,
        protocol_counts,
        transport_counts,
        distinct_model_tool_names,
        validation_status: if integrity.delivery_ready {
            "delivery_ready".to_owned()
        } else {
            "not_ready".to_owned()
        },
        integrity,
        metrics,
        raw_sources,
        parts,
    };
    fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    sync_tree(&staging)?;
    if output.exists() {
        fs::remove_dir_all(&output)?;
    }
    fs::rename(&staging, &output)?;
    File::open(parent)?.sync_all()?;
    verify_interaction_artifacts(&output)?;
    Ok(manifest)
}

fn build_canonical_records(captures: &[Value]) -> Result<CanonicalRecords> {
    let api_captures: Vec<&Value> = captures
        .iter()
        .filter(|capture| record_type(capture) == "api_snapshot")
        .collect();
    let mut interactions: Vec<Value> = api_captures
        .par_iter()
        .map(|capture| model_interaction_from_capture(capture))
        .collect::<Result<Vec<_>>>()?;
    interactions.sort_by(|left, right| {
        string_field(left, "interaction_id").cmp(&string_field(right, "interaction_id"))
    });

    let mut runtime_spans = build_runtime_spans(captures, &interactions)?;
    deduplicate_runtime_spans(&mut runtime_spans)?;
    runtime_spans
        .sort_by(|left, right| string_field(left, "span_id").cmp(&string_field(right, "span_id")));
    let mut links = build_interaction_links(&interactions, &runtime_spans, captures)?;
    links.sort_by(|left, right| string_field(left, "link_id").cmp(&string_field(right, "link_id")));
    attach_captured_tool_schemas(&mut runtime_spans, &interactions, &links)?;
    attach_runtime_link_refs(&mut interactions, &links);

    let validators = CanonicalValidators::new()?;
    validate_canonical_records(
        &validators.model_interaction,
        MODEL_INTERACTION_SCHEMA_VERSION,
        &interactions,
        "generated interactions",
    )?;
    validate_canonical_records(
        &validators.runtime_span,
        RUNTIME_SPAN_SCHEMA_VERSION,
        &runtime_spans,
        "generated runtime spans",
    )?;
    validate_canonical_records(
        &validators.interaction_link,
        INTERACTION_LINK_SCHEMA_VERSION,
        &links,
        "generated interaction links",
    )?;
    Ok(CanonicalRecords {
        interactions,
        runtime_spans,
        links,
    })
}

pub(crate) fn canonical_trace_summary(captures: &[Value]) -> Result<Option<CanonicalTraceSummary>> {
    let stock_event_count = captures
        .iter()
        .filter(|capture| {
            capture
                .pointer("/rolloutEvent/source")
                .and_then(Value::as_str)
                == Some("codex_rollout_jsonl")
        })
        .count();
    let legacy_event_count = captures
        .iter()
        .filter(|capture| {
            capture
                .pointer("/rolloutEvent/source")
                .and_then(Value::as_str)
                == Some("codex_rollout_trace_bundle")
        })
        .count();
    let producer_runtime_event_count = captures
        .iter()
        .filter(|capture| {
            capture.get("lifecycleEvent").is_some() || capture.get("toolExecution").is_some()
        })
        .count();
    let (runtime_source, source_event_count) = match (stock_event_count, legacy_event_count) {
        (stock, 0) if stock > 0 => ("canonical_model_interaction:codex_rollout_jsonl", stock),
        (0, legacy) if legacy > 0 => ("codex_rollout_trace_bundle", legacy),
        (stock, legacy) if stock > 0 && legacy > 0 => (
            "canonical_model_interaction:mixed_runtime_sources",
            stock.saturating_add(legacy),
        ),
        _ if producer_runtime_event_count > 0 => (
            "canonical_model_interaction:producer_events",
            producer_runtime_event_count,
        ),
        _ => ("", 0),
    };
    if source_event_count == 0 {
        return Ok(None);
    }

    let CanonicalRecords {
        interactions,
        runtime_spans,
        links,
    } = build_canonical_records(captures)?;
    let (raw_bytes_complete, protocol_complete, interaction_metrics) =
        aggregate_interaction_integrity(&interactions);
    let integrity = runtime_integrity(&interactions, &runtime_spans, &links);
    let metrics = &integrity.metrics;
    let roots: BTreeSet<String> = runtime_spans
        .iter()
        .filter(|span| string_field(span, "span_kind") == Some("task_root"))
        .filter_map(|span| string_field(span, "span_id").map(str::to_owned))
        .collect();
    let terminal_roots: BTreeSet<String> = runtime_spans
        .iter()
        .filter(|span| string_field(span, "span_kind") == Some("task_root"))
        .filter(|span| runtime_span_is_terminal(span))
        .filter_map(|span| string_field(span, "span_id").map(str::to_owned))
        .collect();
    let open_nodes = metric_string_set(metrics, "/open_span_ids");
    let status_conflicts = metric_string_set(metrics, "/conflicting_span_ids");
    let mut unresolved = BTreeSet::new();
    for path in [
        "/unscoped_span_ids",
        "/unresolved_parent_call_span_ids",
        "/unresolved_parent_span_ids",
        "/calls_without_results",
        "/calls_without_execution",
        "/unlinked_interaction_ids",
        "/invalid_link_ids",
    ] {
        unresolved.extend(metric_string_set(metrics, path));
    }
    let task_session_ids = canonical_task_session_ids(&interactions, &runtime_spans);
    let session_ids = canonical_session_ids(&interactions, &runtime_spans);
    let complete = integrity.runtime_complete && integrity.root_complete;
    let runtime_dag = json!({
        "schema_version":"chiptrace.runtime-dag.v1",
        "source":runtime_source,
        "native_event_count":source_event_count,
        "roots":roots,
        "root_mode":if roots.len() > 1 { "session_scoped_turn_forest" } else { "single_turn" },
        "task_session_ids":task_session_ids,
        "session_ids":session_ids,
        "open_node_ids":open_nodes,
        "unresolved_node_ids":unresolved,
        "status_conflict_node_ids":status_conflicts,
        "terminal_rollout_ids":terminal_roots,
        "canonical_metrics":metrics,
        "root_complete":integrity.root_complete,
        "complete":complete,
        "applicable":true,
    });
    let wire_ready = raw_bytes_complete && protocol_complete;
    let runtime_ready = integrity.runtime_complete && integrity.root_complete;
    let delivery_ready = wire_ready && runtime_ready;
    let readiness = json!({
        "schema_version":"chiptrace.trace-readiness.v1",
        "artifact_valid":true,
        "raw_bytes_complete":raw_bytes_complete,
        "protocol_complete":protocol_complete,
        "runtime_complete":integrity.runtime_complete,
        "root_complete":integrity.root_complete,
        "wire_ready":wire_ready,
        "runtime_ready":runtime_ready,
        "delivery_ready":delivery_ready,
        "interaction_metrics":interaction_metrics,
        "runtime_metrics":integrity.metrics,
    });
    Ok(Some(CanonicalTraceSummary {
        runtime_dag,
        readiness,
    }))
}

fn metric_string_set(metrics: &Value, path: &str) -> BTreeSet<String> {
    metrics
        .pointer(path)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

pub fn verify_interaction_projection(root: &Path) -> Result<InteractionProjectionManifest> {
    let manifest = verify_interaction_artifacts(root)?;
    if !manifest.integrity.delivery_ready {
        let failed = failed_integrity_gates(&manifest.integrity).join(", ");
        bail!("interaction projection is not delivery ready; failed gates: {failed}");
    }
    Ok(manifest)
}

pub(crate) fn verify_interaction_artifacts(root: &Path) -> Result<InteractionProjectionManifest> {
    let manifest_path = root.join("manifest.json");
    let manifest: InteractionProjectionManifest =
        serde_json::from_slice(&fs::read(&manifest_path)?)?;
    if manifest.schema_version != INTERACTION_PROJECTION_SCHEMA_VERSION {
        bail!("unsupported interaction projection manifest");
    }
    for source in &manifest.raw_sources {
        validate_raw_source(source)?;
    }
    let validators = CanonicalValidators::new()?;
    let expected_versions = [
        (
            "interactions/model-interactions.jsonl.zst",
            MODEL_INTERACTION_SCHEMA_VERSION,
            manifest.interactions,
        ),
        (
            "runtime/runtime-spans.jsonl.zst",
            RUNTIME_SPAN_SCHEMA_VERSION,
            manifest.runtime_spans,
        ),
        (
            "links/interaction-links.jsonl.zst",
            INTERACTION_LINK_SCHEMA_VERSION,
            manifest.links,
        ),
    ];
    let mut expected_files = HashSet::from(["manifest.json".to_owned()]);
    let mut records_by_file = HashMap::new();
    for (relative, schema_version, expected_records) in expected_versions {
        let part = manifest
            .parts
            .iter()
            .find(|part| part.file == relative)
            .ok_or_else(|| anyhow::anyhow!("missing interaction part {relative}"))?;
        ensure_safe_relative_path(&part.file)?;
        expected_files.insert(part.file.clone());
        let path = root.join(&part.file);
        if path.metadata()?.len() != part.bytes || sha256_file(&path)? != part.sha256 {
            bail!("interaction part checksum mismatch: {}", path.display());
        }
        let mut reader = crate::jsonl::open_jsonl_reader(&path)?;
        let mut line = Vec::new();
        let mut records = Vec::new();
        let validator = validators.for_version(schema_version)?;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let value: Value = serde_json::from_slice(&line)?;
            if string_field(&value, "schema_version") != Some(schema_version) {
                bail!("unexpected record schema in {}", path.display());
            }
            records.push(value);
        }
        validate_canonical_records(
            validator,
            schema_version,
            &records,
            &path.display().to_string(),
        )?;
        if records.len() as u64 != expected_records || part.records != Some(records.len() as u64) {
            bail!("interaction part record count mismatch: {}", part.file);
        }
        records_by_file.insert(relative, records);
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
                .expect("interaction file outside output root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    if actual_files != expected_files {
        bail!("interaction projection file set does not match manifest");
    }

    let interactions = records_by_file
        .remove("interactions/model-interactions.jsonl.zst")
        .unwrap_or_default();
    let runtime_spans = records_by_file
        .remove("runtime/runtime-spans.jsonl.zst")
        .unwrap_or_default();
    let links = records_by_file
        .remove("links/interaction-links.jsonl.zst")
        .unwrap_or_default();
    let projected_task_ids = canonical_task_session_ids(&interactions, &runtime_spans);
    if projected_task_ids.len() > 1 {
        bail!("interaction projection contains multiple task_session_id values");
    }
    let projected_task_session_id = projected_task_ids.into_iter().next();
    if manifest.task_session_id != projected_task_session_id {
        bail!("interaction projection task_session_id does not match its records");
    }
    if let Some(expected_session_id) = manifest.session_id.as_deref() {
        let projected_session_ids = canonical_session_ids(&interactions, &runtime_spans);
        if projected_session_ids.len() != 1 || !projected_session_ids.contains(expected_session_id)
        {
            bail!("interaction projection session_id does not match its records");
        }
    }
    let (raw_bytes_complete, protocol_complete, interaction_metrics) =
        aggregate_interaction_integrity(&interactions);
    let runtime = runtime_integrity(&interactions, &runtime_spans, &links);
    let expected_integrity = DeliveryIntegrity {
        artifact_valid: true,
        raw_bytes_complete,
        protocol_complete,
        runtime_complete: runtime.runtime_complete,
        root_complete: runtime.root_complete,
        delivery_ready: raw_bytes_complete
            && protocol_complete
            && runtime.runtime_complete
            && runtime.root_complete,
    };
    let expected_metrics = json!({
        "interactions":interaction_metrics,
        "runtime":runtime.metrics,
    });
    let expected_status = if expected_integrity.delivery_ready {
        "delivery_ready"
    } else {
        "not_ready"
    };
    if manifest.integrity != expected_integrity
        || manifest.metrics != expected_metrics
        || manifest.validation_status != expected_status
    {
        bail!("interaction projection integrity does not match its records");
    }
    Ok(manifest)
}

fn failed_integrity_gates(integrity: &DeliveryIntegrity) -> Vec<&'static str> {
    [
        ("artifact_valid", integrity.artifact_valid),
        ("raw_bytes_complete", integrity.raw_bytes_complete),
        ("protocol_complete", integrity.protocol_complete),
        ("runtime_complete", integrity.runtime_complete),
        ("root_complete", integrity.root_complete),
    ]
    .into_iter()
    .filter_map(|(name, passed)| (!passed).then_some(name))
    .collect()
}

fn canonical_task_session_ids(interactions: &[Value], runtime_spans: &[Value]) -> BTreeSet<String> {
    interactions
        .iter()
        .chain(runtime_spans)
        .filter_map(|record| {
            record
                .pointer("/trace_context/task_session_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        })
        .collect()
}

fn canonical_session_ids(interactions: &[Value], runtime_spans: &[Value]) -> BTreeSet<String> {
    interactions
        .iter()
        .chain(runtime_spans)
        .filter_map(|record| {
            record
                .pointer("/trace_context/session_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        })
        .collect()
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

fn read_captures(inputs: &[PathBuf]) -> Result<(Vec<Value>, u64)> {
    let mut captures = Vec::new();
    let mut seen = HashMap::new();
    let mut duplicates = 0_u64;
    for path in inputs {
        let mut reader = crate::jsonl::open_jsonl_reader(path)?;
        let mut line = Vec::new();
        let mut index = 0_u64;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            index = index.saturating_add(1);
            while line
                .last()
                .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
            {
                line.pop();
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            validate_stored_capture(&line)
                .with_context(|| format!("validate {} line {index}", path.display()))?;
            let value: Value = serde_json::from_slice(&line)
                .with_context(|| format!("parse {} line {index}", path.display()))?;
            let capture_id = string_field(&value, "captureId")
                .ok_or_else(|| anyhow::anyhow!("Capture missing captureId"))?;
            let digest = sha256(&line);
            if let Some(existing) = seen.get(capture_id) {
                if existing != &digest {
                    bail!("captureId {capture_id:?} has conflicting bytes");
                }
                duplicates = duplicates.saturating_add(1);
                continue;
            }
            seen.insert(capture_id.to_owned(), digest);
            captures.push(value);
        }
    }
    Ok((captures, duplicates))
}

fn select_projection_captures(
    mut captures: Vec<Value>,
    requested_task: Option<&str>,
    requested_session: Option<&str>,
) -> Result<(Vec<Value>, Option<String>, Option<String>)> {
    if requested_task.is_some() && requested_session.is_some() {
        bail!("--task-session-id and --session-id cannot be used together");
    }
    let available_tasks: BTreeSet<String> = captures
        .iter()
        .filter_map(|capture| {
            capture
                .pointer("/traceContext/task_session_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        })
        .collect();
    let available_sessions: BTreeSet<String> = captures
        .iter()
        .filter_map(|capture| {
            capture
                .pointer("/traceContext/session_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        })
        .collect();
    let mut session_lineage = StockSessionLineage::default();
    for capture in &captures {
        session_lineage.observe(capture)?;
    }

    if let Some(requested) = requested_task {
        let requested = requested.trim();
        if requested.is_empty() {
            bail!("--task-session-id cannot be empty");
        }
        if !available_tasks.contains(requested) {
            bail!("task_session_id {requested:?} was not found in Capture inputs");
        }
        captures.retain(|capture| {
            capture
                .pointer("/traceContext/task_session_id")
                .and_then(Value::as_str)
                == Some(requested)
        });
        return Ok((captures, Some(requested.to_owned()), None));
    }

    if let Some(requested) = requested_session {
        let requested = requested.trim();
        if requested.is_empty() {
            bail!("--session-id cannot be empty");
        }
        if !available_sessions.contains(requested) {
            bail!("session_id {requested:?} was not found in Capture inputs");
        }
        let selection = session_lineage.selection(requested)?;
        captures.retain(|capture| selection.contains(capture));
        for capture in &mut captures {
            selection.canonicalize(capture)?;
        }
        return Ok((captures, None, Some(requested.to_owned())));
    }

    match available_tasks.len() {
        0 => {}
        1 => {
            let selected = available_tasks.into_iter().next().unwrap_or_default();
            captures.retain(|capture| {
                capture
                    .pointer("/traceContext/task_session_id")
                    .and_then(Value::as_str)
                    == Some(selected.as_str())
            });
            return Ok((captures, Some(selected), None));
        }
        count => {
            bail!("Capture inputs contain {count} task Sessions; select one with --task-session-id")
        }
    }

    let top_level_sessions = session_lineage.top_level_sessions(&available_sessions);
    match top_level_sessions.len() {
        0 => Ok((captures, None, None)),
        1 => {
            let selected = top_level_sessions.into_iter().next().unwrap_or_default();
            let selection = session_lineage.selection(&selected)?;
            captures.retain(|capture| selection.contains(capture));
            for capture in &mut captures {
                selection.canonicalize(capture)?;
            }
            Ok((captures, None, Some(selected)))
        }
        count => bail!(
            "Capture inputs contain {count} Stock Codex Sessions; select one with --session-id"
        ),
    }
}

fn model_interaction_from_capture(capture: &Value) -> Result<Value> {
    let capture_id = string_field(capture, "captureId")
        .ok_or_else(|| anyhow::anyhow!("Capture missing captureId"))?;
    let request_body = wire_body(capture, "request");
    let response_body = wire_body(capture, "response");
    let shape = detect_protocol_shape(capture, &request_body, &response_body);
    match shape.endpoint {
        "responses" => adapt_responses(capture, request_body, response_body, shape),
        "chat_completions" => adapt_chat_completions(capture, request_body, response_body, shape),
        _ => adapt_opaque(capture, request_body, response_body, shape),
    }
    .with_context(|| format!("adapt Capture {capture_id}"))
}

fn record_type(value: &Value) -> &str {
    string_field(value, "recordType").unwrap_or("api_snapshot")
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn stable_id(prefix: &str, values: &[&str]) -> String {
    let mut digest = Sha256::new();
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("{prefix}-{}", hex::encode(digest.finalize()))
}

fn capture_order_key(value: &Value) -> (String, String) {
    let timestamp = ["startedAt", "receivedAt", "finishedAt"]
        .into_iter()
        .find_map(|field| string_field(value, field))
        .unwrap_or("")
        .to_owned();
    let capture_id = string_field(value, "captureId").unwrap_or("").to_owned();
    (timestamp, capture_id)
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

fn discover_inputs(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut output = Vec::new();
    for input in inputs {
        if input.is_file() {
            let name = input
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if name.ends_with(".open.ndjson") {
                bail!(
                    "refusing unstable open WAL segment {}; flush the Collector first",
                    input.display()
                );
            }
            if !capture_input_name(name) {
                bail!("unsupported Capture input: {}", input.display());
            }
            output.push(input.canonicalize()?);
        } else if input.is_dir() {
            for entry in WalkDir::new(input).follow_links(false) {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy();
                if capture_input_name(&name) && !name.ends_with(".open.ndjson") {
                    output.push(entry.path().canonicalize()?);
                }
            }
        } else {
            bail!("Capture input does not exist: {}", input.display());
        }
    }
    output.sort();
    output.dedup();
    Ok(output)
}

fn capture_input_name(name: &str) -> bool {
    name.ends_with(".ndjson") || name.ends_with(".jsonl") || name.ends_with(".jsonl.zst")
}

fn discover_raw_sources(
    inputs: &[PathBuf],
    capture_inputs: &[PathBuf],
) -> Result<Vec<RawSourceLineage>> {
    let mut sources = BTreeMap::new();
    let mut lineaged = Vec::new();
    let mut unlineaged = Vec::new();
    for input in inputs {
        let canonical = input.canonicalize()?;
        let contributes = if canonical.is_file() {
            capture_inputs.contains(&canonical)
        } else {
            capture_inputs
                .iter()
                .any(|path| path.starts_with(&canonical))
        };
        if !contributes {
            continue;
        }
        if !canonical.is_dir() {
            unlineaged.push(canonical);
            continue;
        }
        let mut has_lineage = false;
        for name in ["RAW_SOURCE.json", "RAW_SOURCES.json"] {
            let path = canonical.join(name);
            if !path.is_file() {
                continue;
            }
            has_lineage = true;
            let value: Value = serde_json::from_slice(&fs::read(&path)?)
                .with_context(|| format!("parse Raw lineage {}", path.display()))?;
            let values: Vec<Value> = match value {
                Value::Array(values) => values,
                value => vec![value],
            };
            for value in values {
                let source: RawSourceLineage = serde_json::from_value(value)?;
                validate_raw_source(&source)?;
                if let Some(existing) = sources.get(&source.archive_id)
                    && existing != &source
                {
                    bail!("conflicting Raw lineage for archive {}", source.archive_id);
                }
                sources.insert(source.archive_id.clone(), source);
            }
        }
        if has_lineage {
            lineaged.push(canonical);
        } else {
            unlineaged.push(canonical);
        }
    }
    if !lineaged.is_empty() && !unlineaged.is_empty() {
        bail!("cannot mix Raw-lineaged and unlineaged Capture inputs");
    }
    Ok(sources.into_values().collect())
}

fn validate_raw_source(source: &RawSourceLineage) -> Result<()> {
    let valid_digest =
        |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if source.schema_version != RAW_LINEAGE_SCHEMA_VERSION
        || source.archive_id.trim().is_empty()
        || source.completeness != "complete"
        || source.segment_count == 0
        || source.checkpoint_key.trim().is_empty()
        || source.manifest_key.trim().is_empty()
        || !valid_digest(&source.checkpoint_sha256)
        || !valid_digest(&source.manifest_sha256)
    {
        bail!("Raw source archive {} is incomplete", source.archive_id);
    }
    Ok(())
}

fn apply_exact_task_links(captures: &mut [Value]) -> Result<()> {
    let mut links: HashMap<String, String> = HashMap::new();
    for capture in captures.iter() {
        let Some(task_session_id) = capture
            .pointer("/traceContext/task_session_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        for key in correlation_keys(capture) {
            if let Some(existing) = links.get(&key)
                && existing != task_session_id
            {
                bail!("one exact request identity maps to multiple task Sessions");
            }
            links.insert(key, task_session_id.to_owned());
        }
    }
    for capture in captures {
        if capture
            .pointer("/traceContext/task_session_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            continue;
        }
        let matched: BTreeSet<String> = correlation_keys(capture)
            .into_iter()
            .filter_map(|key| links.get(&key).cloned())
            .collect();
        if matched.len() > 1 {
            bail!("Capture exact IDs link to multiple task Sessions");
        }
        let Some(task_session_id) = matched.into_iter().next() else {
            continue;
        };
        let object = capture
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("Capture must be an object"))?;
        object
            .entry("traceContext".to_owned())
            .or_insert_with(|| json!({}))["task_session_id"] = json!(task_session_id);
    }
    Ok(())
}

fn scoped_correlation_key(capture: &Value, key: &str) -> String {
    let scope = canonical_identity_scope(capture)
        .unwrap_or_else(|| format!("source:{}", source_namespace(capture)));
    format!("{scope}\0{key}")
}

fn correlation_keys(capture: &Value) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for value in [
        string_field(capture, "upstreamRequestId"),
        header(capture, "responseHeaders", "x-request-id"),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.trim().is_empty())
    {
        keys.insert(format!("upstream:{value}"));
    }
    for value in [
        string_field(capture, "requestId"),
        header(capture, "requestHeaders", "x-client-request-id"),
        header(capture, "responseHeaders", "x-client-request-id"),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.trim().is_empty())
    {
        keys.insert(format!("client:{value}"));
    }
    let response = extract_body(capture.get("responseBody"));
    for value in [
        string_field(capture, "responseId"),
        response.and_then(|response| string_field(response, "id")),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.trim().is_empty())
    {
        keys.insert(format!("response:{value}"));
    }
    if let Some(value) = capture
        .pointer("/gatewayEvidence/request_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        keys.insert(format!("gateway:{value}"));
    }
    keys
}

fn header<'a>(capture: &'a Value, object: &str, name: &str) -> Option<&'a str> {
    let headers = capture.get(object)?.as_object()?;
    headers.iter().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name)
            .then(|| value.as_str())
            .flatten()
    })
}

fn wire_body(capture: &Value, side: &str) -> WireBody {
    let body_field = if side == "request" {
        "requestBody"
    } else {
        "responseBody"
    };
    let text_field = if side == "request" {
        "requestBodyText"
    } else {
        "responseBodyText"
    };
    let bytes_field = if side == "request" {
        "requestBytesCaptured"
    } else {
        "responseBytesCaptured"
    };
    let sha_field = if side == "request" {
        "requestBodySha256"
    } else {
        "responseBodySha256"
    };
    let truncated_field = if side == "request" {
        "requestTruncated"
    } else {
        "responseTruncated"
    };
    let captured = capture.get(body_field).cloned().unwrap_or(Value::Null);
    let parsed = extract_body(Some(&captured))
        .cloned()
        .unwrap_or(Value::Null);
    let raw_utf8 = captured
        .get("raw")
        .and_then(Value::as_str)
        .or_else(|| {
            captured
                .get("kind")
                .and_then(Value::as_str)
                .filter(|kind| matches!(*kind, "text" | "sse"))
                .and_then(|_| captured.get("value"))
                .and_then(Value::as_str)
        })
        .or_else(|| capture.get(text_field).and_then(Value::as_str))
        .or_else(|| captured.as_str())
        .map(str::to_owned);
    let declared_sha256 = string_field(capture, sha_field).map(str::to_owned);
    let declared_bytes = capture.get(bytes_field).and_then(Value::as_u64);
    let raw_sha256_matches = raw_utf8.as_ref().map(|raw| {
        declared_sha256
            .as_deref()
            .is_none_or(|declared| declared == sha256(raw.as_bytes()))
    });
    let raw_bytes_match = raw_utf8
        .as_ref()
        .map(|raw| declared_bytes.is_none_or(|declared| declared == raw.len() as u64));
    WireBody {
        captured,
        parsed,
        raw_utf8,
        declared_sha256,
        declared_bytes,
        raw_sha256_matches,
        raw_bytes_match,
        truncated: capture
            .get(truncated_field)
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn detect_protocol_shape(
    capture: &Value,
    request: &WireBody,
    response: &WireBody,
) -> ProtocolShape {
    let path = string_field(capture, "proxiedPath")
        .or_else(|| string_field(capture, "inboundPath"))
        .unwrap_or("")
        .to_ascii_lowercase();
    let request_object = request.parsed.as_object();
    let response_object = response.parsed.as_object();
    let stream = capture.get("stream").and_then(Value::as_bool) == Some(true)
        || response.raw_utf8.as_deref().is_some_and(|raw| {
            raw.lines()
                .any(|line| line.trim_start().starts_with("data:"))
        })
        || response.captured.get("kind").and_then(Value::as_str) == Some("sse");
    let endpoint = if path.contains("chat/completions")
        || request_object.is_some_and(|object| object.contains_key("messages"))
            && response_object.is_some_and(|object| object.contains_key("choices"))
        || response_object.is_some_and(|object| object.contains_key("choices"))
    {
        "chat_completions"
    } else if path.ends_with("/responses")
        || request_object.is_some_and(|object| object.contains_key("input"))
        || response_object.is_some_and(|object| object.contains_key("output"))
        || response.raw_utf8.as_deref().is_some_and(|raw| {
            raw.contains("response.created") || raw.contains("response.completed")
        })
    {
        "responses"
    } else {
        "unknown"
    };
    ProtocolShape {
        family: "openai",
        endpoint,
        transport: if stream { "stream" } else { "non_stream" },
    }
}

#[derive(Debug, Default)]
struct SseParseResult {
    events: Vec<SseEvent>,
    done: bool,
    malformed: u64,
    recovered_boundaries: u64,
}

fn parse_sse(raw: &str) -> SseParseResult {
    let mut events = Vec::new();
    let mut event_name: Option<String> = None;
    let mut data_lines = Vec::new();
    let mut event_start = None;
    let mut event_end = 0_usize;
    let mut done = false;
    let mut malformed = 0_u64;
    let mut recovered_boundaries = 0_u64;
    // A conforming SSE frame ends with a blank line. Some upstream gateways
    // omit that separator between the first event/data pairs while keeping
    // each JSON payload and its event name intact. An event: line is an
    // unambiguous boundary in that case; recover it only when the pending
    // payload is independently valid JSON (or [DONE]). Other malformed data
    // remains visible and fail-closed through `malformed`.
    let flush = |event_name: &mut Option<String>,
                 data_lines: &mut Vec<String>,
                 event_start: &mut Option<usize>,
                 event_end: &mut usize,
                 events: &mut Vec<SseEvent>,
                 done: &mut bool,
                 malformed: &mut u64| {
        if data_lines.is_empty() {
            *event_name = None;
            *event_start = None;
            *event_end = 0;
            return false;
        }
        let data_raw = data_lines.join("\n");
        let valid = if data_raw.trim() == "[DONE]" {
            *done = true;
            true
        } else {
            let data = serde_json::from_str::<Value>(&data_raw).ok();
            let valid = data.is_some();
            if !valid {
                *malformed = malformed.saturating_add(1);
            }
            events.push(SseEvent {
                index: events.len(),
                event: event_name.take(),
                data_raw,
                data,
                byte_start: event_start.take().unwrap_or(0),
                byte_end: *event_end,
            });
            valid
        };
        data_lines.clear();
        *event_name = None;
        *event_start = None;
        *event_end = 0;
        valid
    };
    let mut byte_offset = 0_usize;
    for raw_line in raw.split_inclusive('\n') {
        let line_start = byte_offset;
        byte_offset = byte_offset.saturating_add(raw_line.len());
        let line_end = byte_offset;
        let line = raw_line
            .strip_suffix('\n')
            .unwrap_or(raw_line)
            .trim_end_matches('\r');
        if line.is_empty() {
            event_end = line_end;
            let _ = flush(
                &mut event_name,
                &mut data_lines,
                &mut event_start,
                &mut event_end,
                &mut events,
                &mut done,
                &mut malformed,
            );
        } else if let Some(value) = line.strip_prefix("event:") {
            if !data_lines.is_empty()
                && flush(
                    &mut event_name,
                    &mut data_lines,
                    &mut event_start,
                    &mut event_end,
                    &mut events,
                    &mut done,
                    &mut malformed,
                )
            {
                recovered_boundaries = recovered_boundaries.saturating_add(1);
            }
            event_start = Some(line_start);
            event_end = line_end;
            event_name = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("data:") {
            // A few OpenAI-compatible gateways omit the blank separator even
            // when they emit data-only frames. Split only when both the
            // pending payload and the new payload are complete JSON objects
            // or arrays; partial/multiline JSON remains one frame and fails
            // closed if it cannot be decoded.
            let pending_is_complete = (!data_lines.is_empty()).then(|| {
                serde_json::from_str::<Value>(&data_lines.join("\n"))
                    .ok()
                    .is_some_and(|json| json.is_object() || json.is_array())
            }) == Some(true);
            let next = value.trim_start();
            let next_is_complete = next == "[DONE]"
                || serde_json::from_str::<Value>(next)
                    .ok()
                    .is_some_and(|json| json.is_object() || json.is_array());
            if pending_is_complete
                && next_is_complete
                && flush(
                    &mut event_name,
                    &mut data_lines,
                    &mut event_start,
                    &mut event_end,
                    &mut events,
                    &mut done,
                    &mut malformed,
                )
            {
                recovered_boundaries = recovered_boundaries.saturating_add(1);
            }
            event_start.get_or_insert(line_start);
            event_end = line_end;
            data_lines.push(value.trim_start().to_owned());
        } else if event_start.is_some() {
            event_end = line_end;
        }
    }
    let _ = flush(
        &mut event_name,
        &mut data_lines,
        &mut event_start,
        &mut event_end,
        &mut events,
        &mut done,
        &mut malformed,
    );
    SseParseResult {
        events,
        done,
        malformed,
        recovered_boundaries,
    }
}

fn sse_events_value(events: &[SseEvent]) -> Value {
    Value::Array(
        events
            .iter()
            .map(|event| {
                json!({
                    "index":event.index,
                    "event":event.event,
                    "data_raw":event.data_raw,
                    "data":event.data,
                    "byte_start":event.byte_start,
                    "byte_end":event.byte_end,
                })
            })
            .collect(),
    )
}

fn wire_body_value(body: &WireBody) -> Value {
    json!({
        "raw_utf8":body.raw_utf8,
        "declared_sha256":body.declared_sha256,
        "declared_bytes":body.declared_bytes,
        "raw_sha256_matches":body.raw_sha256_matches,
        "raw_bytes_match":body.raw_bytes_match,
        "truncated":body.truncated,
    })
}

fn client_delivery_boundary(capture: &Value) -> Value {
    json!({
        "response_bytes_forwarded":capture.get("responseBytesForwarded"),
        "response_bytes_forwarded_at_client_close":capture.get("responseBytesForwardedAtClientClose"),
        "client_response_closed_before_finish":capture.get("clientResponseClosedBeforeFinish"),
        "protocol_terminal_observed_at_client_close":capture.get("responseProtocolTerminalObservedAtClientClose"),
        "framing_done_observed_at_client_close":capture.get("responseFramingDoneObservedAtClientClose"),
        "protocol_terminal_byte_offset":capture.get("responseProtocolTerminalByteOffset"),
        "framing_done_byte_offset":capture.get("responseFramingDoneByteOffset"),
    })
}

fn trace_context(capture: &Value) -> Value {
    let mut context = capture
        .get("traceContext")
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    if context.get("source_namespace").is_none() {
        context["source_namespace"] =
            json!(string_field(capture, "sourceNamespace").unwrap_or("default"));
    }
    context
}

fn trace_string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .pointer(&format!("/traceContext/{field}"))
        .or_else(|| value.pointer(&format!("/trace_context/{field}")))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn source_namespace(value: &Value) -> &str {
    string_field(value, "sourceNamespace")
        .or_else(|| {
            value
                .pointer("/trace_context/source_namespace")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            value
                .pointer("/provenance/source_namespace")
                .and_then(Value::as_str)
        })
        .unwrap_or("default")
}

fn runtime_thread_key(value: &Value, thread_id: &str) -> String {
    trace_string(value, "session_id").map_or_else(
        || format!("source:{}\0thread:{thread_id}", source_namespace(value)),
        |session_id| format!("session:{session_id}\0thread:{thread_id}"),
    )
}

fn raw_capture_ref(capture: &Value) -> Value {
    json!({
        "capture_id":string_field(capture, "captureId"),
        "record_type":record_type(capture),
        "request_body_sha256":string_field(capture, "requestBodySha256"),
        "response_body_sha256":string_field(capture, "responseBodySha256"),
        "request_id":string_field(capture, "requestId"),
        "upstream_request_id":string_field(capture, "upstreamRequestId"),
    })
}

fn interaction_id(capture: &Value) -> String {
    stable_id(
        "interaction",
        &[
            string_field(capture, "sourceNamespace").unwrap_or("default"),
            string_field(capture, "captureId").unwrap_or("missing"),
            string_field(capture, "upstreamRequestId").unwrap_or(""),
        ],
    )
}

fn observed_parent_span_id(value: &Value) -> Option<&str> {
    value
        .pointer("/traceContext/parent_span_id")
        .or_else(|| value.pointer("/trace_context/parent_span_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            value
                .pointer("/traceContext/traceparent")
                .or_else(|| value.pointer("/trace_context/traceparent"))
                .and_then(Value::as_str)
                .and_then(|traceparent| traceparent.split('-').nth(2))
                .filter(|value| !value.trim().is_empty())
        })
}

fn child_trace_context(capture: &Value) -> Value {
    let mut context = trace_context(capture);
    if let Some(parent_span_id) = observed_parent_span_id(capture) {
        if context.get("span_id").and_then(Value::as_str) == Some(parent_span_id) {
            context
                .as_object_mut()
                .map(|object| object.remove("span_id"));
        }
        context["parent_span_id"] = json!(parent_span_id);
    }
    context
}

fn client_delivery_status(capture: &Value) -> &'static str {
    let request_aborted = capture.get("clientRequestAborted").and_then(Value::as_bool);
    let response_closed = capture
        .get("clientResponseClosedBeforeFinish")
        .and_then(Value::as_bool);
    let response_finished = capture
        .get("clientResponseFinished")
        .and_then(Value::as_bool);
    if request_aborted == Some(true) {
        "cancelled"
    } else {
        match (response_finished, response_closed) {
            (Some(true), Some(false)) => "delivered",
            (Some(false), Some(true)) => "cancelled",
            (Some(_), Some(_)) => "unknown",
            (None, Some(true)) => "cancelled",
            (None, Some(false)) if request_aborted == Some(false) => "delivered",
            _ => "unknown",
        }
    }
}

fn explicit_transport_error(capture: &Value) -> bool {
    string_field(capture, "captureError").is_some()
        || capture
            .get("upstreamResponseCompleted")
            .and_then(Value::as_bool)
            == Some(false)
}

fn http_failed(capture: &Value) -> bool {
    capture
        .get("responseStatus")
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
        .is_some_and(|status| status >= 400)
}

fn model_outcome(status: Option<&str>) -> Option<StreamOutcome> {
    match status.map(|value| value.to_ascii_lowercase()) {
        Some(value)
            if matches!(
                value.as_str(),
                "completed" | "complete" | "succeeded" | "success"
            ) =>
        {
            Some(StreamOutcome::Completed)
        }
        Some(value) if matches!(value.as_str(), "failed" | "failure" | "error") => {
            Some(StreamOutcome::Failed)
        }
        Some(value) if matches!(value.as_str(), "cancelled" | "canceled") => {
            Some(StreamOutcome::Cancelled)
        }
        Some(value) if value == "incomplete" => Some(StreamOutcome::Incomplete),
        _ => None,
    }
}

fn non_stream_state(capture: &Value, response: &Value) -> StreamState {
    let transport_error = explicit_transport_error(capture);
    let model_outcome =
        model_outcome(response.get("status").and_then(Value::as_str)).or_else(|| {
            if http_failed(capture) {
                Some(StreamOutcome::Failed)
            } else if !response.is_null() {
                Some(StreamOutcome::Completed)
            } else {
                None
            }
        });
    let outcome = if transport_error && model_outcome.is_none() {
        StreamOutcome::TransportError
    } else {
        model_outcome.unwrap_or(StreamOutcome::Incomplete)
    };
    StreamState {
        outcome,
        model_status: match model_outcome {
            Some(StreamOutcome::Completed) => "completed",
            Some(StreamOutcome::Failed) => "failed",
            Some(StreamOutcome::Cancelled) => "cancelled",
            Some(StreamOutcome::Incomplete) => "incomplete",
            _ => "incomplete",
        },
        upstream_transport_status: if transport_error {
            "transport_error"
        } else if !response.is_null() {
            "completed"
        } else {
            "eof_without_terminal"
        },
        client_delivery_status: client_delivery_status(capture),
        protocol_terminal_observed: model_outcome.is_some(),
        framing_done_observed: true,
        error_event: None,
    }
}

fn responses_stream_state(capture: &Value, view: &ResponsesStreamView) -> StreamState {
    let transport_error = explicit_transport_error(capture);
    let outcome = view.terminal_outcome.unwrap_or({
        if transport_error {
            StreamOutcome::TransportError
        } else {
            StreamOutcome::EofWithoutTerminal
        }
    });
    StreamState {
        outcome,
        model_status: match view.terminal_outcome {
            Some(StreamOutcome::Completed) => "completed",
            Some(StreamOutcome::Failed) => "failed",
            Some(StreamOutcome::Cancelled) => "cancelled",
            Some(StreamOutcome::Incomplete) => "incomplete",
            _ => "incomplete",
        },
        upstream_transport_status: if transport_error {
            "transport_error"
        } else if view.protocol_terminal_observed {
            "completed"
        } else {
            "eof_without_terminal"
        },
        client_delivery_status: client_delivery_status(capture),
        protocol_terminal_observed: view.protocol_terminal_observed,
        framing_done_observed: view.framing_done_observed,
        error_event: view.error_event.clone(),
    }
}

fn chat_stream_state(capture: &Value, response: &Value, framing_done: bool) -> StreamState {
    let protocol_terminal_observed = response
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            !choices.is_empty()
                && choices.iter().all(|choice| {
                    choice
                        .get("finish_reason")
                        .is_some_and(|value| !value.is_null())
                })
        });
    let transport_error = explicit_transport_error(capture);
    let outcome = if protocol_terminal_observed {
        StreamOutcome::Completed
    } else if transport_error {
        StreamOutcome::TransportError
    } else {
        StreamOutcome::EofWithoutTerminal
    };
    StreamState {
        outcome,
        model_status: if protocol_terminal_observed {
            "completed"
        } else {
            "incomplete"
        },
        upstream_transport_status: if transport_error {
            "transport_error"
        } else if protocol_terminal_observed {
            "completed"
        } else {
            "eof_without_terminal"
        },
        client_delivery_status: client_delivery_status(capture),
        protocol_terminal_observed,
        framing_done_observed: framing_done,
        error_event: None,
    }
}

fn stream_state_value(state: &StreamState) -> Value {
    json!({
        "outcome":state.outcome.as_str(),
        "model_status":state.model_status,
        "upstream_transport_status":state.upstream_transport_status,
        "client_delivery_status":state.client_delivery_status,
        "protocol_terminal_observed":state.protocol_terminal_observed,
        "framing_done_observed":state.framing_done_observed,
    })
}

fn capture_error(capture: &Value, response: &Value, stream_error: Option<&Value>) -> Value {
    let capture_message = string_field(capture, "captureError");
    let response_error = response.get("error").cloned();
    if capture_message.is_none() && response_error.is_none() && stream_error.is_none() {
        return Value::Null;
    }
    json!({
        "capture_message":capture_message,
        "capture_code":string_field(capture, "captureErrorCode"),
        "response_error":response_error,
        "stream_error":stream_error,
        "http_status":capture.get("responseStatus"),
        "client_request_aborted":capture.get("clientRequestAborted"),
        "client_response_closed_before_finish":capture.get("clientResponseClosedBeforeFinish"),
        "client_response_finished":capture.get("clientResponseFinished"),
        "response_protocol_terminal_observed":capture.get("responseProtocolTerminalObserved"),
        "response_protocol_terminal_event":capture.get("responseProtocolTerminalEvent"),
        "response_framing_done_observed":capture.get("responseFramingDoneObserved"),
    })
}

fn normalized_usage(response: &Value, capture: &Value) -> Value {
    let usage = response
        .get("usage")
        .or_else(|| capture.get("rolloutUsage"));
    let Some(usage) = usage else {
        return Value::Null;
    };
    let number = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| usage.get(*name).and_then(Value::as_u64))
    };
    let input = number(&["input_tokens", "prompt_tokens"]);
    let cached = number(&["cached_input_tokens", "cache_read_input_tokens"]).or_else(|| {
        usage
            .pointer("/input_tokens_details/cached_tokens")
            .and_then(Value::as_u64)
            .or_else(|| {
                usage
                    .pointer("/prompt_tokens_details/cached_tokens")
                    .and_then(Value::as_u64)
            })
    });
    let output = number(&["output_tokens", "completion_tokens"]);
    let reasoning = number(&["reasoning_tokens", "reasoning_output_tokens"]).or_else(|| {
        usage
            .pointer("/output_tokens_details/reasoning_tokens")
            .and_then(Value::as_u64)
            .or_else(|| {
                usage
                    .pointer("/completion_tokens_details/reasoning_tokens")
                    .and_then(Value::as_u64)
            })
    });
    let total = number(&["total_tokens"]).or_else(|| {
        input
            .zip(output)
            .map(|(input, output)| input.saturating_add(output))
    });
    json!({
        "input_tokens":input,
        "cached_input_tokens":cached,
        "output_tokens":output,
        "reasoning_tokens":reasoning,
        "total_tokens":total,
        "raw":usage,
    })
}

fn interaction_integrity(
    capture: &Value,
    request: &WireBody,
    response: &WireBody,
    shape: &ProtocolShape,
    state: &StreamState,
    malformed_events: u64,
    unknown_items: u64,
) -> Value {
    let artifact_valid = string_field(capture, "captureId")
        .is_some_and(|value| !value.trim().is_empty())
        && record_type(capture) == "api_snapshot";
    let raw_bytes_complete = raw_body_complete(request) && raw_body_complete(response);
    let response_finished = capture
        .get("clientResponseFinished")
        .and_then(Value::as_bool);
    let response_closed = capture
        .get("clientResponseClosedBeforeFinish")
        .and_then(Value::as_bool);
    let response_bytes_captured = capture.get("responseBytesCaptured").and_then(Value::as_u64);
    let response_bytes_forwarded = capture
        .get("responseBytesForwarded")
        .and_then(Value::as_u64);
    let response_bytes_at_close = capture
        .get("responseBytesForwardedAtClientClose")
        .and_then(Value::as_u64);
    let boundary_offsets_consistent = response_bytes_forwarded
        .zip(response_bytes_captured)
        .is_none_or(|(forwarded, captured)| forwarded <= captured)
        && response_bytes_at_close
            .zip(response_bytes_forwarded)
            .is_none_or(|(at_close, forwarded)| at_close <= forwarded)
        && (!matches!(response_closed, Some(true))
            || (response_bytes_at_close.is_some()
                && capture
                    .get("responseProtocolTerminalObservedAtClientClose")
                    .is_some_and(Value::is_boolean)));
    let client_delivery_evidence_consistent = !matches!(
        (response_finished, response_closed),
        (Some(true), Some(true))
    ) && boundary_offsets_consistent;
    let status_dimensions_complete = capture
        .get("upstreamResponseCompleted")
        .is_some_and(Value::is_boolean)
        && capture
            .get("clientRequestAborted")
            .is_some_and(Value::is_boolean)
        && capture
            .get("clientResponseClosedBeforeFinish")
            .is_some_and(Value::is_boolean);
    let status_dimensions_complete =
        status_dimensions_complete && client_delivery_evidence_consistent;
    let trace_identity_complete = capture
        .get("fieldEvidenceConflicts")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
        && capture
            .get("traceContextErrors")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty);
    let protocol_complete = shape.family == "openai"
        && shape.endpoint == "responses"
        && shape.transport == "stream"
        && state.protocol_terminal_observed
        && matches!(
            state.outcome,
            StreamOutcome::Completed
                | StreamOutcome::Failed
                | StreamOutcome::Incomplete
                | StreamOutcome::Cancelled
        )
        && malformed_events == 0
        && status_dimensions_complete
        && trace_identity_complete;
    json!({
        "artifact_valid":artifact_valid,
        "raw_bytes_complete":raw_bytes_complete,
        "protocol_complete":protocol_complete,
        "stream_outcome":state.outcome.as_str(),
        "status_dimensions_complete":status_dimensions_complete,
        "client_delivery_evidence_consistent":client_delivery_evidence_consistent,
        "trace_identity_complete":trace_identity_complete,
        "malformed_sse_events":malformed_events,
        "unknown_item_count":unknown_items,
    })
}

fn raw_body_complete(body: &WireBody) -> bool {
    body.raw_utf8.is_some()
        && body.declared_sha256.is_some()
        && body.declared_bytes.is_some()
        && body.raw_sha256_matches == Some(true)
        && body.raw_bytes_match == Some(true)
        && !body.truncated
}

fn aggregate_interaction_integrity(interactions: &[Value]) -> (bool, bool, Value) {
    let raw_complete = interactions
        .iter()
        .filter(|interaction| {
            interaction
                .pointer("/integrity/raw_bytes_complete")
                .and_then(Value::as_bool)
                == Some(true)
        })
        .count();
    let protocol_complete = interactions
        .iter()
        .filter(|interaction| {
            interaction
                .pointer("/integrity/protocol_complete")
                .and_then(Value::as_bool)
                == Some(true)
        })
        .count();
    let artifact_valid = interactions
        .iter()
        .filter(|interaction| {
            interaction
                .pointer("/integrity/artifact_valid")
                .and_then(Value::as_bool)
                == Some(true)
        })
        .count();
    let mut outcomes = BTreeMap::new();
    for outcome in interactions.iter().filter_map(|interaction| {
        interaction
            .pointer("/integrity/stream_outcome")
            .and_then(Value::as_str)
    }) {
        *outcomes.entry(outcome.to_owned()).or_insert(0_u64) += 1;
    }
    let total = interactions.len();
    (
        total > 0 && raw_complete == total,
        total > 0 && protocol_complete == total,
        json!({
            "total":total,
            "artifact_valid":artifact_valid,
            "raw_bytes_complete":raw_complete,
            "protocol_complete":protocol_complete,
            "stream_outcomes":outcomes,
        }),
    )
}

fn runtime_integrity(
    interactions: &[Value],
    runtime_spans: &[Value],
    links: &[Value],
) -> RuntimeIntegrity {
    let applicable = !runtime_spans.is_empty();
    let root_spans: Vec<&Value> = runtime_spans
        .iter()
        .filter(|span| string_field(span, "span_kind") == Some("task_root"))
        .collect();
    let scope_root_spans: Vec<&Value> = runtime_spans
        .iter()
        .filter(|span| {
            string_field(span, "span_kind") == Some("task_root")
                || span
                    .pointer("/extensions/scope_root")
                    .and_then(Value::as_bool)
                    == Some(true)
        })
        .collect();
    let task_scopes: BTreeSet<String> = runtime_spans
        .iter()
        .filter_map(runtime_task_scope)
        .collect();
    let root_task_scopes: BTreeSet<String> = scope_root_spans
        .iter()
        .filter_map(|span| runtime_task_scope(span))
        .collect();
    let unscoped_span_ids: BTreeSet<&str> = runtime_spans
        .iter()
        .filter(|span| runtime_task_scope(span).is_none())
        .filter_map(|span| string_field(span, "span_id"))
        .collect();
    let root_complete = applicable
        && unscoped_span_ids.is_empty()
        && !task_scopes.is_empty()
        && root_spans.len() == 1
        && scope_root_spans.len() == task_scopes.len()
        && root_task_scopes == task_scopes
        && scope_root_spans.iter().all(|span| {
            span.pointer("/extensions/root_complete")
                .and_then(Value::as_bool)
                == Some(true)
                && runtime_span_is_terminal(span)
        });
    let open_span_ids: BTreeSet<&str> = runtime_spans
        .iter()
        .filter(|span| !runtime_span_is_terminal(span))
        .filter_map(|span| string_field(span, "span_id"))
        .collect();
    let conflicting_span_ids: BTreeSet<&str> = runtime_spans
        .iter()
        .filter(|span| {
            span.pointer("/extensions/state_conflict")
                .and_then(Value::as_bool)
                == Some(true)
        })
        .filter_map(|span| string_field(span, "span_id"))
        .collect();
    let incomplete_result_span_ids: BTreeSet<&str> = runtime_spans
        .iter()
        .filter(|span| {
            span.pointer("/extensions/result_content_captured")
                .and_then(Value::as_bool)
                == Some(false)
        })
        .filter_map(|span| string_field(span, "span_id"))
        .collect();
    let quality_failure_span_ids: BTreeSet<&str> = runtime_spans
        .iter()
        .filter(|span| {
            span.pointer("/extensions/quality_gate_failed")
                .and_then(Value::as_bool)
                == Some(true)
        })
        .filter_map(|span| string_field(span, "span_id"))
        .collect();
    let linked_parent_call_spans: HashSet<&str> = links
        .iter()
        .filter(|link| string_field(link, "relation") == Some("model_call_to_runtime_execution"))
        .filter_map(|link| string_field(link, "to"))
        .filter_map(|target| target.strip_prefix("runtime-span:"))
        .collect();
    let linked_parent_span_children: HashSet<&str> = links
        .iter()
        .filter(|link| string_field(link, "relation") == Some("runtime_parent_to_child"))
        .filter_map(|link| string_field(link, "to"))
        .filter_map(|target| target.strip_prefix("runtime-span:"))
        .collect();
    let unresolved_parent_call_span_ids: BTreeSet<&str> = runtime_spans
        .iter()
        .filter(|span| {
            string_field(span, "parent_call_id").is_some_and(|value| !value.trim().is_empty())
        })
        .filter_map(|span| string_field(span, "span_id"))
        .filter(|span_id| !linked_parent_call_spans.contains(span_id))
        .collect();
    let unlinked_parent_spans: Vec<&Value> = runtime_spans
        .iter()
        .filter(|span| {
            string_field(span, "parent_span_id").is_some_and(|value| !value.trim().is_empty())
        })
        .filter(|span| {
            string_field(span, "span_id")
                .is_none_or(|span_id| !linked_parent_span_children.contains(span_id))
        })
        .collect();
    let unresolved_parent_span_ids: BTreeSet<&str> = unlinked_parent_spans
        .iter()
        .copied()
        .filter(|span| {
            span.pointer("/extensions/parent_span_required")
                .and_then(Value::as_bool)
                == Some(true)
                || span
                    .pointer("/trace_context/task_session_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
        })
        .filter_map(|span| string_field(span, "span_id"))
        .collect();
    let unobserved_external_parent_spans = unlinked_parent_spans
        .len()
        .saturating_sub(unresolved_parent_span_ids.len());
    let internal_parent_references = runtime_spans
        .iter()
        .filter(|span| {
            string_field(span, "parent_span_id").is_some_and(|value| !value.trim().is_empty())
                && (span
                    .pointer("/extensions/parent_span_required")
                    .and_then(Value::as_bool)
                    == Some(true)
                    || span
                        .pointer("/trace_context/task_session_id")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()))
        })
        .count();
    let resolved_internal_parents =
        internal_parent_references.saturating_sub(unresolved_parent_span_ids.len());
    let resolved_internal_parent_rate = if internal_parent_references == 0 {
        if root_complete { 1.0 } else { 0.0 }
    } else {
        resolved_internal_parents as f64 / internal_parent_references as f64
    };
    let model_call_nodes: BTreeSet<String> = interactions
        .iter()
        .flat_map(|interaction| {
            let interaction_id = string_field(interaction, "interaction_id").unwrap_or("missing");
            interaction
                .get("model_tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(move |call| {
                    call.get("call_id")
                        .and_then(Value::as_str)
                        .filter(|call_id| !call_id.trim().is_empty())
                        .map(|call_id| format!("model-call:{interaction_id}:{call_id}"))
                })
        })
        .collect();
    let calls_with_results: BTreeSet<String> = links
        .iter()
        .filter(|link| string_field(link, "relation") == Some("model_call_to_submitted_result"))
        .filter_map(|link| string_field(link, "from"))
        .map(str::to_owned)
        .collect();
    let calls_with_execution: BTreeSet<String> = links
        .iter()
        .filter(|link| string_field(link, "relation") == Some("model_call_to_runtime_execution"))
        .filter_map(|link| string_field(link, "from"))
        .map(str::to_owned)
        .collect();
    let cancelled_delivery_call_candidates: BTreeSet<String> = interactions
        .iter()
        .flat_map(|interaction| {
            interaction
                .get("model_tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|call| explicitly_abandoned_model_call_node(interaction, call))
        })
        .collect();
    let abandoned_model_call_nodes: BTreeSet<String> = cancelled_delivery_call_candidates
        .difference(&calls_with_results)
        .filter(|node| !calls_with_execution.contains(node.as_str()))
        .cloned()
        .collect();
    let abandoned_model_call_ids: BTreeSet<String> = abandoned_model_call_nodes
        .iter()
        .filter_map(|node| node.rsplit_once(':').map(|(_, call_id)| call_id.to_owned()))
        .collect();
    let required_model_call_nodes: BTreeSet<String> = model_call_nodes
        .difference(&abandoned_model_call_nodes)
        .cloned()
        .collect();
    let calls_without_results: BTreeSet<&String> = required_model_call_nodes
        .difference(&calls_with_results)
        .collect();
    let calls_without_execution: BTreeSet<&String> = required_model_call_nodes
        .difference(&calls_with_execution)
        .collect();
    let linked_interactions: BTreeSet<&str> = links
        .iter()
        .filter_map(|link| match string_field(link, "relation") {
            Some("interaction_to_runtime_span") => string_field(link, "from"),
            Some("runtime_parent_to_interaction") => string_field(link, "to"),
            _ => None,
        })
        .filter_map(|node| node.strip_prefix("interaction:"))
        .collect();
    let unlinked_interaction_ids: BTreeSet<&str> = interactions
        .iter()
        .filter_map(|interaction| string_field(interaction, "interaction_id"))
        .filter(|interaction_id| !linked_interactions.contains(interaction_id))
        .collect();
    let known_nodes = projection_nodes(interactions, runtime_spans);
    let invalid_link_ids: BTreeSet<&str> = links
        .iter()
        .filter(|link| {
            string_field(link, "from").is_none_or(|node| !known_nodes.contains(node))
                || string_field(link, "to").is_none_or(|node| !known_nodes.contains(node))
        })
        .filter_map(|link| string_field(link, "link_id"))
        .collect();
    let runtime_complete = applicable
        && unscoped_span_ids.is_empty()
        && open_span_ids.is_empty()
        && conflicting_span_ids.is_empty()
        && incomplete_result_span_ids.is_empty()
        && quality_failure_span_ids.is_empty()
        && unresolved_parent_call_span_ids.is_empty()
        && unresolved_parent_span_ids.is_empty()
        && calls_without_results.is_empty()
        && calls_without_execution.is_empty()
        && unlinked_interaction_ids.is_empty()
        && invalid_link_ids.is_empty();
    RuntimeIntegrity {
        runtime_complete,
        root_complete,
        metrics: json!({
            "runtime_spans":runtime_spans.len(),
            "task_scopes":task_scopes.len(),
            "root_span_count":root_spans.len(),
            "scope_root_span_count":scope_root_spans.len(),
            "unscoped_span_ids":unscoped_span_ids,
            "open_span_ids":open_span_ids,
            "conflicting_span_ids":conflicting_span_ids,
            "incomplete_result_span_ids":incomplete_result_span_ids,
            "quality_failure_span_ids":quality_failure_span_ids,
            "unresolved_parent_call_span_ids":unresolved_parent_call_span_ids,
            "unresolved_parent_span_ids":unresolved_parent_span_ids,
            "unobserved_external_parent_spans":unobserved_external_parent_spans,
            "internal_parent_references":internal_parent_references,
            "resolved_internal_parents":resolved_internal_parents,
            "resolved_internal_parent_rate":resolved_internal_parent_rate,
            "model_tool_calls":model_call_nodes.len(),
            "required_model_tool_calls":required_model_call_nodes.len(),
            "abandoned_model_tool_calls":abandoned_model_call_nodes.len(),
            "abandoned_model_call_nodes":abandoned_model_call_nodes,
            "abandoned_model_call_ids":abandoned_model_call_ids,
            "model_tool_calls_with_results":model_call_nodes.intersection(&calls_with_results).count(),
            "model_tool_calls_with_execution":model_call_nodes.intersection(&calls_with_execution).count(),
            "calls_without_results":calls_without_results,
            "calls_without_execution":calls_without_execution,
            "unlinked_interaction_ids":unlinked_interaction_ids,
            "invalid_link_ids":invalid_link_ids,
        }),
    }
}

fn runtime_span_is_terminal(span: &Value) -> bool {
    matches!(
        string_field(span, "status"),
        Some("completed" | "failed" | "cancelled" | "timeout" | "incomplete" | "closed")
    )
}

fn projection_nodes(interactions: &[Value], runtime_spans: &[Value]) -> HashSet<String> {
    let mut nodes = HashSet::new();
    for interaction in interactions {
        let interaction_id = string_field(interaction, "interaction_id").unwrap_or("missing");
        nodes.insert(format!("interaction:{interaction_id}"));
        for (index, result) in interaction
            .get("tool_results_submitted")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            nodes.insert(format!("submitted-result:{interaction_id}:{index}"));
            if let Some(call_id) = result.get("call_id").and_then(Value::as_str) {
                nodes.insert(format!("model-call:{interaction_id}:{call_id}"));
            }
        }
        for call_id in interaction
            .get("model_tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|call| call.get("call_id").and_then(Value::as_str))
        {
            nodes.insert(format!("model-call:{interaction_id}:{call_id}"));
        }
    }
    for span_id in runtime_spans
        .iter()
        .filter_map(|span| string_field(span, "span_id"))
    {
        nodes.insert(format!("runtime-span:{span_id}"));
    }
    nodes
}

/// Return a model-call node only when the wire contains explicit byte-offset
/// evidence that the call was generated after the client connection closed.
/// Missing offsets are intentionally not interpreted as abandonment: a call
/// that was visible before the close must remain a hard pairing failure.
fn explicitly_abandoned_model_call_node(interaction: &Value, call: &Value) -> Option<String> {
    let response = interaction.get("response")?;
    if response.get("model_status").and_then(Value::as_str) != Some("completed")
        || response
            .get("upstream_transport_status")
            .and_then(Value::as_str)
            != Some("completed")
        || response
            .get("client_delivery_status")
            .and_then(Value::as_str)
            != Some("cancelled")
        || interaction
            .pointer("/integrity/protocol_complete")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return None;
    }
    let boundary = interaction.pointer("/extensions/wire/client_delivery_boundary")?;
    if boundary
        .get("client_response_closed_before_finish")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return None;
    }
    if boundary
        .get("protocol_terminal_observed_at_client_close")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return None;
    }
    let close_offset = boundary
        .get("response_bytes_forwarded_at_client_close")
        .and_then(Value::as_u64)?;
    let start = call.get("source_byte_start").and_then(Value::as_u64)?;
    let end = call.get("source_byte_end").and_then(Value::as_u64)?;
    if start < close_offset || end < start {
        return None;
    }
    let interaction_id = string_field(interaction, "interaction_id")?;
    let call_id = call
        .get("call_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())?;
    Some(format!("model-call:{interaction_id}:{call_id}"))
}

fn annotate_model_tool_call_delivery_evidence(
    calls: &mut [Value],
    capture: &Value,
    state: &StreamState,
    event_ranges: &BTreeMap<String, SseByteRange>,
) {
    let boundary = client_delivery_boundary(capture);
    let close_offset = boundary
        .get("response_bytes_forwarded_at_client_close")
        .and_then(Value::as_u64);
    let closed = boundary
        .get("client_response_closed_before_finish")
        .and_then(Value::as_bool)
        == Some(true);
    let terminal_at_close = boundary
        .get("protocol_terminal_observed_at_client_close")
        .and_then(Value::as_bool);
    for call in calls {
        let call_id = call
            .get("call_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty());
        let range = call_id.and_then(|id| event_ranges.get(id));
        let Some(range) = range else {
            call["delivery_evidence"] = json!({
                "source":"gateway_response_byte_boundary",
                "available":false,
                "abandoned":false,
            });
            continue;
        };
        let abandoned = state.client_delivery_status == "cancelled"
            && state.protocol_terminal_observed
            && state.outcome == StreamOutcome::Completed
            && closed
            && close_offset.is_some()
            && terminal_at_close == Some(false)
            && close_offset.is_some_and(|offset| {
                u64::try_from(range.byte_start).is_ok_and(|start| start >= offset)
            });
        call["delivery_evidence"] = json!({
            "source":"gateway_response_byte_boundary",
            "available":true,
            "event_index":range.event_index,
            "response_byte_start":range.byte_start,
            "response_byte_end":range.byte_end,
            "client_close_byte_offset":close_offset,
            "protocol_terminal_observed_at_client_close":terminal_at_close,
            "abandoned":abandoned,
        });
    }
}

/// Compute deterministic Buyer exclusions from observed post-close byte
/// evidence. A call is returned only when exactly one interaction proves it;
/// ambiguous IDs are retained as strict pairing failures.
pub(crate) fn abandoned_model_call_ids_from_captures(
    captures: &[Value],
) -> Result<BTreeSet<String>> {
    let mut by_call: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for capture in captures
        .iter()
        .filter(|capture| record_type(capture) == "api_snapshot")
    {
        let interaction = model_interaction_from_capture(capture)?;
        let Some(interaction_id) = string_field(&interaction, "interaction_id") else {
            continue;
        };
        for call in interaction
            .get("model_tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if explicitly_abandoned_model_call_node(&interaction, call).is_some()
                && let Some(call_id) = call
                    .get("call_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
            {
                by_call
                    .entry(call_id.to_owned())
                    .or_default()
                    .insert(interaction_id.to_owned());
            }
        }
    }
    Ok(by_call
        .into_iter()
        .filter_map(|(call_id, interactions)| (interactions.len() == 1).then_some(call_id))
        .collect())
}

fn adapt_responses(
    capture: &Value,
    request_body: WireBody,
    response_body: WireBody,
    shape: ProtocolShape,
) -> Result<Value> {
    let request = request_body.parsed.as_object().cloned().unwrap_or_default();
    let stream_view = responses_response_view(&response_body, &shape);
    let state = if shape.transport == "stream" {
        responses_stream_state(capture, &stream_view)
    } else {
        non_stream_state(capture, &stream_view.response)
    };
    let response = stream_view.response;
    let input_items = responses_input_items(request.get("input"));
    let output_items = response
        .get("output")
        .and_then(Value::as_array)
        .map(|items| normalized_wire_items(items))
        .unwrap_or_default();
    let tool_definitions = request_tool_definitions(&request);
    let mut model_tool_calls = responses_model_tool_calls(
        response
            .get("output")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        &stream_view.tool_call_event_ranges,
    );
    annotate_model_tool_call_delivery_evidence(
        &mut model_tool_calls,
        capture,
        &state,
        &stream_view.tool_call_event_ranges,
    );
    let tool_results_submitted = responses_submitted_results(request.get("input"));
    let unknown_items = input_items
        .iter()
        .chain(output_items.iter())
        .filter(|item| {
            item.get("item_type")
                .and_then(Value::as_str)
                .is_some_and(|kind| !known_responses_item(kind))
        })
        .count() as u64;
    let features = interaction_features(
        &request,
        &response,
        &input_items,
        &output_items,
        &model_tool_calls,
        shape.endpoint,
    );
    let integrity = interaction_integrity(
        capture,
        &request_body,
        &response_body,
        &shape,
        &state,
        stream_view.malformed_events,
        unknown_items,
    );
    Ok(json!({
        "schema_version":MODEL_INTERACTION_SCHEMA_VERSION,
        "interaction_id":interaction_id(capture),
        "protocol":{
            "family":shape.family,
            "endpoint":shape.endpoint,
            "transport":shape.transport,
            "features":features,
            "adapter_version":ADAPTER_VERSION,
        },
        "provenance":producer_provenance(capture),
        "trace_context":trace_context(capture),
        "request":{
            "model":request.get("model"),
            "input_items":input_items,
            "raw":request_body.parsed,
        },
        "response":{
            "id":response.get("id"),
            "model":response.get("model"),
            "status":state.model_status,
            "model_status":state.model_status,
            "upstream_transport_status":state.upstream_transport_status,
            "client_delivery_status":state.client_delivery_status,
            "output_items":output_items,
            "choices":[],
            "raw":response,
        },
        "tool_definitions":tool_definitions,
        "model_tool_calls":model_tool_calls,
        "tool_results_submitted":tool_results_submitted,
        "usage":normalized_usage(&response, capture),
        "timing":interaction_timing(capture),
        "error":capture_error(capture, &response, state.error_event.as_ref()),
        "raw_capture_refs":[raw_capture_ref(capture)],
        "integrity":integrity,
        "extensions":{
            "wire":{
                "request":wire_body_value(&request_body),
                "response":wire_body_value(&response_body),
                "sse_events":stream_view.events,
                "client_delivery_boundary":client_delivery_boundary(capture),
                "malformed_sse_events":stream_view.malformed_events,
                "framing_recovered_events":stream_view.framing_recovered_events,
                "stream_state":stream_state_value(&state),
            },
            "routing":routing_extension(capture),
        },
    }))
}

fn adapt_chat_completions(
    capture: &Value,
    request_body: WireBody,
    response_body: WireBody,
    shape: ProtocolShape,
) -> Result<Value> {
    let request = request_body.parsed.as_object().cloned().unwrap_or_default();
    let (response, stream_events, stream_terminal, malformed_events, framing_recovered_events) =
        chat_response_view(&response_body, &shape);
    let request_messages = request
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let input_items = normalized_wire_items(&request_messages);
    let choices = response
        .get("choices")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let output_items = chat_output_items(&choices);
    let model_tool_calls = chat_model_tool_calls(&choices);
    let tool_results_submitted = chat_submitted_results(&request_messages);
    let tool_definitions = request_tool_definitions(&request);
    let unknown_items = input_items
        .iter()
        .filter(|item| {
            item.get("role")
                .and_then(Value::as_str)
                .is_some_and(|role| {
                    !matches!(
                        role,
                        "system" | "developer" | "user" | "assistant" | "tool" | "function"
                    )
                })
        })
        .count() as u64;
    let features = interaction_features(
        &request,
        &response,
        &input_items,
        &output_items,
        &model_tool_calls,
        shape.endpoint,
    );
    let state = if shape.transport == "stream" {
        chat_stream_state(capture, &response, stream_terminal)
    } else {
        non_stream_state(capture, &response)
    };
    let integrity = interaction_integrity(
        capture,
        &request_body,
        &response_body,
        &shape,
        &state,
        malformed_events,
        unknown_items,
    );
    Ok(json!({
        "schema_version":MODEL_INTERACTION_SCHEMA_VERSION,
        "interaction_id":interaction_id(capture),
        "protocol":{
            "family":shape.family,
            "endpoint":shape.endpoint,
            "transport":shape.transport,
            "features":features,
            "adapter_version":ADAPTER_VERSION,
        },
        "provenance":producer_provenance(capture),
        "trace_context":trace_context(capture),
        "request":{
            "model":request.get("model"),
            "input_items":input_items,
            "raw":request_body.parsed,
        },
        "response":{
            "id":response.get("id"),
            "model":response.get("model"),
            "status":state.model_status,
            "model_status":state.model_status,
            "upstream_transport_status":state.upstream_transport_status,
            "client_delivery_status":state.client_delivery_status,
            "output_items":output_items,
            "choices":choices,
            "raw":response,
        },
        "tool_definitions":tool_definitions,
        "model_tool_calls":model_tool_calls,
        "tool_results_submitted":tool_results_submitted,
        "usage":normalized_usage(&response, capture),
        "timing":interaction_timing(capture),
        "error":capture_error(capture, &response, state.error_event.as_ref()),
        "raw_capture_refs":[raw_capture_ref(capture)],
        "integrity":integrity,
        "extensions":{
            "wire":{
                "request":wire_body_value(&request_body),
                "response":wire_body_value(&response_body),
                "sse_events":stream_events,
                "malformed_sse_events":malformed_events,
                "framing_recovered_events":framing_recovered_events,
                "stream_state":stream_state_value(&state),
            },
            "routing":routing_extension(capture),
        },
    }))
}

fn adapt_opaque(
    capture: &Value,
    request_body: WireBody,
    response_body: WireBody,
    shape: ProtocolShape,
) -> Result<Value> {
    let response = response_body.parsed.clone();
    let state = if shape.transport == "stream" {
        StreamState {
            outcome: if explicit_transport_error(capture) {
                StreamOutcome::TransportError
            } else {
                StreamOutcome::EofWithoutTerminal
            },
            model_status: "incomplete",
            upstream_transport_status: if explicit_transport_error(capture) {
                "transport_error"
            } else {
                "eof_without_terminal"
            },
            client_delivery_status: client_delivery_status(capture),
            protocol_terminal_observed: false,
            framing_done_observed: false,
            error_event: None,
        }
    } else {
        non_stream_state(capture, &response)
    };
    let integrity =
        interaction_integrity(capture, &request_body, &response_body, &shape, &state, 0, 1);
    Ok(json!({
        "schema_version":MODEL_INTERACTION_SCHEMA_VERSION,
        "interaction_id":interaction_id(capture),
        "protocol":{
            "family":shape.family,
            "endpoint":shape.endpoint,
            "transport":shape.transport,
            "features":["opaque_payload"],
            "adapter_version":ADAPTER_VERSION,
        },
        "provenance":producer_provenance(capture),
        "trace_context":trace_context(capture),
        "request":{"model":Value::Null,"input_items":[],"raw":request_body.parsed},
        "response":{
            "id":Value::Null,
            "model":Value::Null,
            "status":state.model_status,
            "model_status":state.model_status,
            "upstream_transport_status":state.upstream_transport_status,
            "client_delivery_status":state.client_delivery_status,
            "output_items":[],
            "choices":[],
            "raw":response,
        },
        "tool_definitions":[],
        "model_tool_calls":[],
        "tool_results_submitted":[],
        "usage":normalized_usage(&response, capture),
        "timing":interaction_timing(capture),
        "error":capture_error(capture, &response, state.error_event.as_ref()),
        "raw_capture_refs":[raw_capture_ref(capture)],
        "integrity":integrity,
        "extensions":{
            "wire":{
                "request":wire_body_value(&request_body),
                "response":wire_body_value(&response_body),
                "stream_state":stream_state_value(&state),
            },
            "routing":routing_extension(capture),
        },
    }))
}

fn producer_provenance(capture: &Value) -> Value {
    json!({
        "producer":capture.pointer("/producerEvent/producer"),
        "producer_version":capture.pointer("/producerEvent/producer_version"),
        "source_namespace":string_field(capture, "sourceNamespace"),
    })
}

fn routing_extension(capture: &Value) -> Value {
    json!({
        "evidence":capture.get("gatewayEvidence"),
        "join":capture.get("gatewayEvidenceJoin"),
        "provider_observation":capture.get("actualProvider").or_else(|| capture.get("provider")),
    })
}

fn interaction_timing(capture: &Value) -> Value {
    json!({
        "started_at":string_field(capture, "startedAt"),
        "finished_at":string_field(capture, "finishedAt"),
        "received_at":string_field(capture, "receivedAt"),
        "http_status":capture.get("responseStatus"),
        "stream":capture.get("stream"),
        "upstream_response_completed":capture.get("upstreamResponseCompleted"),
    })
}

fn normalized_wire_items(items: &[Value]) -> Vec<Value> {
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            json!({
                "index":index,
                "item_type":item.get("type").and_then(Value::as_str).unwrap_or_else(|| {
                    if item.get("role").is_some() { "message" } else { "unknown" }
                }),
                "item_id":item.get("id"),
                "role":item.get("role"),
                "raw":item,
            })
        })
        .collect()
}

fn responses_input_items(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => normalized_wire_items(items),
        Some(Value::String(text)) => vec![json!({
            "index":0,"item_type":"input_text","item_id":Value::Null,
            "role":"user","raw":text
        })],
        Some(value) if !value.is_null() => vec![json!({
            "index":0,"item_type":"unknown","item_id":Value::Null,
            "role":Value::Null,"raw":value
        })],
        _ => Vec::new(),
    }
}

fn request_tool_definitions(request: &Map<String, Value>) -> Vec<Value> {
    captured_request_tool_definitions(&Value::Object(request.clone()))
        .into_iter()
        .enumerate()
        .map(|(index, captured)| {
            let nested = captured.nested();
            json!({
                "index":index,
                "name":captured.canonical_name(),
                "definition_key":captured.definition_key(),
                "description":nested.get("description"),
                "parameters":nested.get("parameters").or_else(|| nested.get("input_schema")),
                "format":nested.get("format"),
                "namespace":captured.namespace(),
                "namespace_path":captured.namespace_path,
                "tool_type":captured.raw.get("type"),
                "raw":captured.raw,
            })
        })
        .collect()
}

fn responses_model_tool_calls(
    items: &[Value],
    event_ranges: &BTreeMap<String, SseByteRange>,
) -> Vec<Value> {
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            matches!(
                item.get("type").and_then(Value::as_str),
                Some("function_call" | "custom_tool_call")
            )
        })
        .map(|(index, item)| {
            let call_id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str);
            let name = item.get("name").and_then(Value::as_str).map(|name| {
                canonical_runtime_tool_name(item.get("namespace").and_then(Value::as_str), name)
            });
            let range = call_id.and_then(|id| event_ranges.get(id));
            json!({
                "call_id":item.get("call_id").or_else(|| item.get("id")),
                "item_id":item.get("id"),
                "name":name,
                "arguments":item.get("arguments").or_else(|| item.get("input")),
                "choice_index":Value::Null,
                "output_index":index,
                "source_event_index":range.map(|value| value.event_index),
                "source_byte_start":range.map(|value| value.byte_start),
                "source_byte_end":range.map(|value| value.byte_end),
                "raw":item,
            })
        })
        .collect()
}

fn responses_submitted_results(input: Option<&Value>) -> Vec<Value> {
    input
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            matches!(
                item.get("type").and_then(Value::as_str),
                Some("function_call_output" | "custom_tool_call_output" | "tool_result")
            )
        })
        .map(|item| {
            json!({
                "call_id":item.get("call_id").or_else(|| item.get("tool_call_id")).or_else(|| item.get("tool_use_id")),
                "content":item.get("output").or_else(|| item.get("content")),
                "status":item.get("status"),
                "raw":item,
            })
        })
        .collect()
}

fn chat_output_items(choices: &[Value]) -> Vec<Value> {
    choices
        .iter()
        .enumerate()
        .map(|(index, choice)| {
            let message = choice
                .get("message")
                .or_else(|| choice.get("delta"))
                .cloned()
                .unwrap_or(Value::Null);
            json!({
                "index":index,
                "item_type":"message",
                "item_id":message.get("id"),
                "role":message.get("role"),
                "choice_index":choice.get("index").cloned().unwrap_or_else(|| json!(index)),
                "finish_reason":choice.get("finish_reason"),
                "raw":message,
            })
        })
        .collect()
}

fn chat_model_tool_calls(choices: &[Value]) -> Vec<Value> {
    let mut calls = Vec::new();
    for (fallback_index, choice) in choices.iter().enumerate() {
        let choice_index = choice
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or(fallback_index as u64);
        let message = choice.get("message").or_else(|| choice.get("delta"));
        for call in message
            .and_then(|message| message.get("tool_calls"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let function = call.get("function").unwrap_or(call);
            calls.push(json!({
                "call_id":call.get("id"),
                "item_id":Value::Null,
                "name":function.get("name"),
                "arguments":function.get("arguments"),
                "choice_index":choice_index,
                "output_index":Value::Null,
                "raw":call,
            }));
        }
        if let Some(function) = message.and_then(|message| message.get("function_call")) {
            calls.push(json!({
                "call_id":Value::Null,
                "item_id":Value::Null,
                "name":function.get("name"),
                "arguments":function.get("arguments"),
                "choice_index":choice_index,
                "output_index":Value::Null,
                "raw":function,
            }));
        }
    }
    calls
}

fn chat_submitted_results(messages: &[Value]) -> Vec<Value> {
    messages
        .iter()
        .filter(|message| {
            matches!(
                message.get("role").and_then(Value::as_str),
                Some("tool" | "function")
            )
        })
        .map(|message| {
            json!({
                "call_id":message.get("tool_call_id"),
                "content":message.get("content"),
                "status":message.get("status"),
                "raw":message,
            })
        })
        .collect()
}

fn known_responses_item(kind: &str) -> bool {
    matches!(
        kind,
        "message"
            | "reasoning"
            | "function_call"
            | "function_call_output"
            | "custom_tool_call"
            | "custom_tool_call_output"
            | "web_search_call"
            | "file_search_call"
            | "computer_call"
            | "computer_call_output"
            | "image_generation_call"
            | "code_interpreter_call"
            | "local_shell_call"
            | "local_shell_call_output"
            | "mcp_call"
            | "mcp_list_tools"
            | "mcp_approval_request"
            | "input_text"
    )
}

fn interaction_features(
    request: &Map<String, Value>,
    response: &Value,
    input_items: &[Value],
    output_items: &[Value],
    model_tool_calls: &[Value],
    endpoint: &str,
) -> BTreeSet<String> {
    let mut features = BTreeSet::new();
    if !model_tool_calls.is_empty() || request.get("tools").is_some() {
        features.insert("function_call".to_owned());
    }
    if model_tool_calls.iter().any(|call| {
        call.get("raw")
            .and_then(|raw| raw.get("type"))
            .and_then(Value::as_str)
            == Some("custom_tool_call")
    }) {
        features.insert("custom_tool_call".to_owned());
    }
    if request.get("reasoning").is_some()
        || input_items
            .iter()
            .chain(output_items.iter())
            .any(|item| item.get("item_type").and_then(Value::as_str) == Some("reasoning"))
        || contains_object_key(response, "reasoning_content")
    {
        features.insert("reasoning".to_owned());
    }
    if request.get("parallel_tool_calls").and_then(Value::as_bool) == Some(true)
        || model_tool_calls.len() > 1
    {
        features.insert("parallel_calls".to_owned());
    }
    if response
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| choices.len() > 1)
    {
        features.insert("multi_choice".to_owned());
    }
    if input_items.iter().any(|item| {
        item.get("role").and_then(Value::as_str) == Some("developer")
            || item
                .get("raw")
                .and_then(|raw| raw.get("role"))
                .and_then(Value::as_str)
                == Some("developer")
    }) {
        features.insert("developer_role".to_owned());
    }
    if endpoint == "responses" {
        features.insert("typed_items".to_owned());
    }
    features
}

fn contains_object_key(value: &Value, expected: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(expected)
                || object
                    .values()
                    .any(|value| contains_object_key(value, expected))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| contains_object_key(value, expected)),
        _ => false,
    }
}

fn responses_response_view(body: &WireBody, shape: &ProtocolShape) -> ResponsesStreamView {
    if shape.transport != "stream" {
        return ResponsesStreamView {
            response: body.parsed.clone(),
            events: json!([]),
            tool_call_event_ranges: BTreeMap::new(),
            terminal_outcome: None,
            protocol_terminal_observed: true,
            framing_done_observed: true,
            malformed_events: 0,
            framing_recovered_events: 0,
            error_event: None,
        };
    }
    let Some(raw) = body.raw_utf8.as_deref() else {
        return ResponsesStreamView {
            response: body.parsed.clone(),
            events: json!([]),
            tool_call_event_ranges: BTreeMap::new(),
            terminal_outcome: None,
            protocol_terminal_observed: false,
            framing_done_observed: false,
            malformed_events: 0,
            framing_recovered_events: 0,
            error_event: None,
        };
    };
    let parsed_sse = parse_sse(raw);
    let events = parsed_sse.events;
    let done = parsed_sse.done;
    let mut malformed = parsed_sse.malformed;
    let framing_recovered_events = parsed_sse.recovered_boundaries;
    let mut created = None;
    let mut terminal = None;
    let mut output = BTreeMap::new();
    let mut tool_call_event_ranges: BTreeMap<String, SseByteRange> = BTreeMap::new();
    let mut item_call_ids: BTreeMap<String, String> = BTreeMap::new();
    let mut terminal_outcome = None;
    let mut error_event = None;
    for event in &events {
        let Some(value) = event.data.as_ref() else {
            continue;
        };
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .or(event.event.as_deref())
            .unwrap_or("");
        let mut observed_call_id = value
            .get("call_id")
            .or_else(|| value.get("callId"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned);
        let observed_item_id = value
            .get("item_id")
            .or_else(|| value.get("itemId"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty());
        if observed_call_id.is_none() {
            observed_call_id =
                observed_item_id.and_then(|item_id| item_call_ids.get(item_id).cloned());
        }
        if let Some(item) = value.get("item")
            && matches!(
                item.get("type").and_then(Value::as_str),
                Some("function_call" | "custom_tool_call")
            )
            && let Some(item_id) = item
                .get("id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            && let Some(call_id) = item
                .get("call_id")
                .or_else(|| item.get("callId"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        {
            item_call_ids.insert(item_id.to_owned(), call_id.to_owned());
            observed_call_id = Some(call_id.to_owned());
        }
        if let Some(call_id) = observed_call_id.as_deref() {
            let range = SseByteRange {
                event_index: event.index,
                byte_start: event.byte_start,
                byte_end: event.byte_end,
            };
            tool_call_event_ranges
                .entry(call_id.to_owned())
                .and_modify(|existing| {
                    existing.byte_start = existing.byte_start.min(range.byte_start);
                    existing.byte_end = existing.byte_end.max(range.byte_end);
                    existing.event_index = existing.event_index.min(range.event_index);
                })
                .or_insert(range);
        }
        if kind == "response.created" {
            created = value.get("response").cloned();
        }
        if matches!(
            kind,
            "response.output_item.done" | "response.output_item.added"
        ) && let Some(item) = value.get("item")
        {
            let index = value
                .get("output_index")
                .and_then(Value::as_u64)
                .unwrap_or(output.len() as u64);
            if kind.ends_with("done") || !output.contains_key(&index) {
                output.insert(index, item.clone());
            }
            if matches!(
                item.get("type").and_then(Value::as_str),
                Some("function_call" | "custom_tool_call")
            ) && let Some(call_id) = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                let range = SseByteRange {
                    event_index: event.index,
                    byte_start: event.byte_start,
                    byte_end: event.byte_end,
                };
                tool_call_event_ranges
                    .entry(call_id.to_owned())
                    .and_modify(|existing| {
                        existing.byte_start = existing.byte_start.min(range.byte_start);
                        existing.byte_end = existing.byte_end.max(range.byte_end);
                        existing.event_index = existing.event_index.min(range.event_index);
                    })
                    .or_insert(range);
            }
        }
        if matches!(
            kind,
            "response.completed" | "response.failed" | "response.incomplete" | "response.cancelled"
        ) {
            if terminal_outcome.is_some() {
                malformed = malformed.saturating_add(1);
            } else {
                terminal = value.get("response").cloned();
                if let Some(items) = value.pointer("/response/output").and_then(Value::as_array) {
                    for item in items.iter().filter(|item| {
                        matches!(
                            item.get("type").and_then(Value::as_str),
                            Some("function_call" | "custom_tool_call")
                        )
                    }) {
                        if let Some(call_id) = item
                            .get("call_id")
                            .or_else(|| item.get("id"))
                            .and_then(Value::as_str)
                            .filter(|value| !value.trim().is_empty())
                        {
                            tool_call_event_ranges.entry(call_id.to_owned()).or_insert(
                                SseByteRange {
                                    event_index: event.index,
                                    byte_start: event.byte_start,
                                    byte_end: event.byte_end,
                                },
                            );
                        }
                    }
                }
                terminal_outcome = Some(match kind {
                    "response.completed" => StreamOutcome::Completed,
                    "response.failed" => StreamOutcome::Failed,
                    "response.incomplete" => StreamOutcome::Incomplete,
                    _ => StreamOutcome::Cancelled,
                });
                if kind == "response.failed" {
                    error_event = Some(value.clone());
                }
            }
        } else if matches!(kind, "error" | "response.error") {
            if terminal_outcome.is_some() {
                malformed = malformed.saturating_add(1);
            } else {
                terminal_outcome = Some(StreamOutcome::Failed);
                error_event = Some(value.clone());
            }
        }
    }
    let mut response = terminal.or(created).unwrap_or_else(|| json!({}));
    if !output.is_empty() {
        response["output"] = Value::Array(output.into_values().collect());
    }
    ResponsesStreamView {
        response,
        events: sse_events_value(&events),
        tool_call_event_ranges,
        terminal_outcome,
        protocol_terminal_observed: terminal_outcome.is_some(),
        framing_done_observed: done,
        malformed_events: malformed,
        framing_recovered_events,
        error_event,
    }
}

#[derive(Debug, Default)]
struct ChatChoiceAccumulator {
    role: Option<String>,
    content: String,
    reasoning_content: String,
    finish_reason: Option<Value>,
    tool_calls: BTreeMap<u64, ChatToolCallAccumulator>,
    legacy_function_call: Option<ChatToolCallAccumulator>,
    raw_chunks: Vec<Value>,
}

#[derive(Debug, Default)]
struct ChatToolCallAccumulator {
    id: Option<String>,
    call_type: Option<String>,
    name: String,
    arguments: String,
    raw_deltas: Vec<Value>,
}

fn chat_response_view(body: &WireBody, shape: &ProtocolShape) -> (Value, Value, bool, u64, u64) {
    if shape.transport != "stream" {
        return (body.parsed.clone(), json!([]), true, 0, 0);
    }
    let Some(raw) = body.raw_utf8.as_deref() else {
        return (body.parsed.clone(), json!([]), false, 0, 0);
    };
    let parsed_sse = parse_sse(raw);
    let events = parsed_sse.events;
    let done = parsed_sse.done;
    let malformed = parsed_sse.malformed;
    let framing_recovered_events = parsed_sse.recovered_boundaries;
    let mut response_id = None;
    let mut response_model = None;
    let mut response_created = None;
    let mut usage = None;
    let mut choices: BTreeMap<u64, ChatChoiceAccumulator> = BTreeMap::new();
    for event in &events {
        let Some(chunk) = event.data.as_ref() else {
            continue;
        };
        if response_id.is_none() {
            response_id = chunk.get("id").cloned();
        }
        if response_model.is_none() {
            response_model = chunk.get("model").cloned();
        }
        if response_created.is_none() {
            response_created = chunk.get("created").cloned();
        }
        if chunk.get("usage").is_some_and(|value| !value.is_null()) {
            usage = chunk.get("usage").cloned();
        }
        for choice in chunk
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
            let accumulator = choices.entry(index).or_default();
            accumulator.raw_chunks.push(choice.clone());
            if choice
                .get("finish_reason")
                .is_some_and(|value| !value.is_null())
            {
                accumulator.finish_reason = choice.get("finish_reason").cloned();
            }
            let delta = choice
                .get("delta")
                .or_else(|| choice.get("message"))
                .unwrap_or(&Value::Null);
            if let Some(role) = delta.get("role").and_then(Value::as_str) {
                accumulator.role = Some(role.to_owned());
            }
            append_delta(&mut accumulator.content, delta.get("content"));
            append_delta(
                &mut accumulator.reasoning_content,
                delta
                    .get("reasoning_content")
                    .or_else(|| delta.get("reasoning")),
            );
            for (fallback_tool_index, tool) in delta
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                let tool_index = tool
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(fallback_tool_index as u64);
                let target = accumulator.tool_calls.entry(tool_index).or_default();
                target.raw_deltas.push(tool.clone());
                if let Some(id) = tool.get("id").and_then(Value::as_str) {
                    target.id = Some(id.to_owned());
                }
                if let Some(call_type) = tool.get("type").and_then(Value::as_str) {
                    target.call_type = Some(call_type.to_owned());
                }
                let function = tool.get("function").unwrap_or(tool);
                append_delta(&mut target.name, function.get("name"));
                append_delta(&mut target.arguments, function.get("arguments"));
            }
            if let Some(function) = delta.get("function_call") {
                let target = accumulator
                    .legacy_function_call
                    .get_or_insert_with(ChatToolCallAccumulator::default);
                target.raw_deltas.push(function.clone());
                append_delta(&mut target.name, function.get("name"));
                append_delta(&mut target.arguments, function.get("arguments"));
            }
        }
    }
    let choices: Vec<Value> = choices
        .into_iter()
        .map(|(index, choice)| {
            let tool_calls: Vec<Value> = choice
                .tool_calls
                .into_iter()
                .map(|(tool_index, tool)| {
                    json!({
                        "index":tool_index,
                        "id":tool.id,
                        "type":tool.call_type.unwrap_or_else(|| "function".to_owned()),
                        "function":{"name":tool.name,"arguments":tool.arguments},
                        "raw_deltas":tool.raw_deltas,
                    })
                })
                .collect();
            let mut message = json!({
                "role":choice.role.unwrap_or_else(|| "assistant".to_owned()),
                "content":choice.content,
                "tool_calls":tool_calls,
            });
            if let Some(function) = choice.legacy_function_call {
                message["function_call"] = json!({
                    "name":function.name,
                    "arguments":function.arguments,
                    "raw_deltas":function.raw_deltas,
                });
            }
            if !choice.reasoning_content.is_empty() {
                message["reasoning_content"] = json!(choice.reasoning_content);
            }
            json!({
                "index":index,
                "message":message,
                "finish_reason":choice.finish_reason,
                "raw_chunks":choice.raw_chunks,
            })
        })
        .collect();
    (
        json!({
            "id":response_id,
            "model":response_model,
            "created":response_created,
            "choices":choices,
            "usage":usage,
        }),
        sse_events_value(&events),
        done,
        malformed,
        framing_recovered_events,
    )
}

fn append_delta(output: &mut String, value: Option<&Value>) {
    if let Some(text) = value.and_then(Value::as_str) {
        output.push_str(text);
    }
}

#[derive(Debug, Default)]
struct RuntimeScopeIndex {
    root_turns_by_thread: HashMap<String, BTreeSet<String>>,
    root_turns_by_session_call: HashMap<String, BTreeSet<String>>,
}

impl RuntimeScopeIndex {
    fn with_interactions(captures: &[Value], interactions: &[Value]) -> Self {
        let mut index = Self::default();
        for capture in captures {
            let Some(root_turn_id) = capture
                .pointer("/traceContext/root_turn_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            else {
                continue;
            };
            let Some(thread_id) = capture
                .pointer("/traceContext/thread_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            else {
                continue;
            };
            index
                .root_turns_by_thread
                .entry(runtime_thread_key(capture, thread_id))
                .or_default()
                .insert(root_turn_id.to_owned());
        }
        for interaction in interactions {
            let Some(session_id) = trace_string(interaction, "session_id") else {
                continue;
            };
            let Some(root_turn_id) = trace_string(interaction, "root_turn_id") else {
                continue;
            };
            for call_id in interaction
                .get("model_tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|call| call.get("call_id").and_then(Value::as_str))
                .filter(|call_id| !call_id.trim().is_empty())
            {
                index
                    .root_turns_by_session_call
                    .entry(session_call_key(session_id, call_id))
                    .or_default()
                    .insert(root_turn_id.to_owned());
            }
        }
        index
    }

    fn scope(&self, value: &Value) -> Option<(&'static str, String)> {
        if let Some(task_session_id) = trace_string(value, "task_session_id") {
            return Some(("task", task_session_id.to_owned()));
        }
        if let Some(root_turn_id) = trace_string(value, "root_turn_id") {
            return Some(("turn", root_turn_id.to_owned()));
        }
        if is_session_lifecycle(value)
            && let Some(session_id) = trace_string(value, "session_id")
        {
            return Some(("session", session_id.to_owned()));
        }
        if let (Some(session_id), Some(call_id)) = (
            trace_string(value, "session_id"),
            value
                .pointer("/toolExecution/call_id")
                .and_then(Value::as_str)
                .filter(|call_id| !call_id.trim().is_empty()),
        ) && let Some(root_turn_id) = self.unique_root_turn_for_call(session_id, call_id)
        {
            return Some(("turn", root_turn_id));
        }
        if let Some(thread_id) = trace_string(value, "thread_id")
            && let Some(root_turn_id) = self.unique_root_turn(value, thread_id)
        {
            return Some(("turn", root_turn_id));
        }
        if let Some(parent_thread_id) = trace_string(value, "parent_thread_id") {
            if let Some(root_turn_id) = self.unique_root_turn(value, parent_thread_id) {
                return Some(("turn", root_turn_id));
            }
            return None;
        }
        trace_string(value, "turn_id").map(|value| ("turn", value.to_owned()))
    }

    fn unique_root_turn(&self, value: &Value, thread_id: &str) -> Option<String> {
        let candidates = self
            .root_turns_by_thread
            .get(&runtime_thread_key(value, thread_id))?;
        (candidates.len() == 1)
            .then(|| candidates.iter().next().cloned())
            .flatten()
    }

    fn unique_root_turn_for_call(&self, session_id: &str, call_id: &str) -> Option<String> {
        let candidates = self
            .root_turns_by_session_call
            .get(&session_call_key(session_id, call_id))?;
        (candidates.len() == 1)
            .then(|| candidates.iter().next().cloned())
            .flatten()
    }

    fn key(&self, value: &Value) -> Option<String> {
        let (kind, identity) = self.scope(value)?;
        Some(runtime_scope_key(value, kind, &identity))
    }

    fn trace_context(&self, capture: &Value, child: bool) -> Value {
        let mut context = if child {
            child_trace_context(capture)
        } else {
            trace_context(capture)
        };
        if let Some(("turn", root_turn_id)) = self.scope(capture)
            && context
                .get("root_turn_id")
                .is_none_or(|value| value.is_null())
        {
            context["root_turn_id"] = json!(root_turn_id);
        }
        context
    }
}

fn session_call_key(session_id: &str, call_id: &str) -> String {
    format!("session:{session_id}\0call:{call_id}")
}

fn is_session_lifecycle(value: &Value) -> bool {
    value
        .pointer("/lifecycleEvent/type")
        .and_then(Value::as_str)
        .is_some_and(|event_type| {
            matches!(
                event_type,
                "session_start" | "session_end" | "session_ended" | "session_cancelled"
            ) || event_type.starts_with("session_cancel")
        })
}

fn build_runtime_spans(captures: &[Value], interactions: &[Value]) -> Result<Vec<Value>> {
    let scope_index = RuntimeScopeIndex::with_interactions(captures, interactions);
    let mut spans = build_task_root_spans(captures, &scope_index)?;
    spans.extend(build_dispatcher_runtime_spans(captures, &scope_index)?);
    spans.extend(build_tool_runtime_spans(
        captures,
        interactions,
        &scope_index,
    )?);
    spans.extend(build_subagent_runtime_spans(captures, &scope_index)?);
    spans.extend(build_quality_signal_spans(captures, &scope_index));
    spans.extend(build_native_runtime_spans(captures, &scope_index)?);
    Ok(spans)
}

fn build_quality_signal_spans(captures: &[Value], scope_index: &RuntimeScopeIndex) -> Vec<Value> {
    captures
        .iter()
        .filter(|capture| {
            capture
                .pointer("/lifecycleEvent/type")
                .and_then(Value::as_str)
                == Some("telemetry_incomplete")
        })
        .map(|capture| {
            let capture_id = string_field(capture, "captureId").unwrap_or("missing");
            let (scope_kind, scope_id) = scope_index
                .scope(capture)
                .unwrap_or(("unscoped", capture_id.to_owned()));
            let parent_span_id = (scope_kind != "unscoped")
                .then(|| canonical_scope_root_span_id(scope_kind, &scope_id));
            json!({
                "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
                "span_id":stable_id("runtime-span", &["quality", capture_id]),
                "trace_context":scope_index.trace_context(capture, true),
                "span_kind":"quality_signal",
                "name":"telemetry_incomplete",
                "call_id":Value::Null,
                "parent_call_id":Value::Null,
                "parent_span_id":parent_span_id,
                "status":"incomplete",
                "started_at":capture.pointer("/lifecycleEvent/occurred_at")
                    .or_else(|| capture.get("receivedAt")),
                "finished_at":capture.pointer("/lifecycleEvent/occurred_at")
                    .or_else(|| capture.get("receivedAt")),
                "arguments":capture.get("lifecycleEvent"),
                "result":Value::Null,
                "error":capture.get("lifecycleEvent"),
                "tool_schema":Value::Null,
                "raw_capture_refs":[capture_id],
                "extensions":{
                    "quality_gate_failed":true,
                    "parent_span_required":scope_kind != "unscoped",
                    "state_conflict":false
                }
            })
        })
        .collect()
}

fn build_task_root_spans(
    captures: &[Value],
    scope_index: &RuntimeScopeIndex,
) -> Result<Vec<Value>> {
    let mut groups: BTreeMap<String, (&'static str, String, Vec<&Value>)> = BTreeMap::new();
    for capture in captures {
        let event_type = capture
            .pointer("/lifecycleEvent/type")
            .and_then(Value::as_str);
        let wire_turn_start = record_type(capture) == "api_snapshot"
            && trace_string(capture, "root_turn_id").is_some();
        if !wire_turn_start
            && !event_type.is_some_and(|event_type| {
                is_task_root_start(event_type)
                    || is_task_root_terminal(event_type)
                    || is_subagent_root_event(event_type)
            })
        {
            continue;
        }
        let Some((scope_kind, scope_id)) = scope_index.scope(capture) else {
            continue;
        };
        let relevant = match scope_kind {
            "session" => event_type.is_some_and(is_session_root_event),
            "turn" => {
                wire_turn_start
                    || event_type.is_some_and(|event_type| {
                        is_turn_root_event(event_type) || is_subagent_root_event(event_type)
                    })
            }
            "task" => event_type.is_some_and(is_explicit_task_root_event),
            _ => false,
        };
        if !relevant {
            continue;
        }
        let scope = runtime_scope_key(capture, scope_kind, &scope_id);
        groups
            .entry(scope)
            .or_insert_with(|| (scope_kind, scope_id, Vec::new()))
            .2
            .push(capture);
    }

    let session_root_ids: HashMap<String, String> = groups
        .values()
        .filter(|(scope_kind, _, _)| *scope_kind == "session")
        .map(|(_, scope_id, _)| {
            (
                scope_id.clone(),
                canonical_scope_root_span_id("session", scope_id),
            )
        })
        .collect();
    let mut spans = Vec::new();
    for (scope_kind, scope_id, observations) in groups.into_values() {
        let starts: Vec<&Value> = observations
            .iter()
            .copied()
            .filter(|capture| root_observation_is_start(capture, scope_kind))
            .collect();
        let terminals: Vec<&Value> = observations
            .iter()
            .copied()
            .filter(|capture| root_observation_is_terminal(capture, scope_kind))
            .collect();
        let first = starts
            .first()
            .copied()
            .or_else(|| observations.first().copied())
            .context("task root group is empty")?;
        let selected = terminals.last().copied().unwrap_or(first);
        let trace_ids: BTreeSet<&str> = observations
            .iter()
            .filter_map(|capture| {
                capture
                    .pointer("/traceContext/trace_id")
                    .and_then(Value::as_str)
            })
            .collect();
        let native_span_ids: BTreeSet<&str> = observations
            .iter()
            .filter_map(|capture| {
                capture
                    .pointer("/traceContext/span_id")
                    .and_then(Value::as_str)
            })
            .collect();
        let terminal_statuses: BTreeSet<String> = terminals
            .iter()
            .map(|capture| {
                normalize_runtime_status(
                    capture
                        .pointer("/lifecycleEvent/status")
                        .and_then(Value::as_str),
                )
            })
            .collect();
        let root_complete =
            !starts.is_empty() && !terminals.is_empty() && terminal_statuses.len() == 1;
        let status = terminals
            .last()
            .and_then(|capture| {
                capture
                    .pointer("/lifecycleEvent/status")
                    .and_then(Value::as_str)
            })
            .map(|status| normalize_runtime_status(Some(status)))
            .unwrap_or_else(|| "running".to_owned());
        let capture_ids: Vec<&str> = observations
            .iter()
            .filter_map(|capture| string_field(capture, "captureId"))
            .collect();
        let parent_span_id = if scope_kind == "turn" {
            trace_string(selected, "session_id")
                .or_else(|| trace_string(first, "session_id"))
                .map(|session_id| {
                    session_root_ids
                        .get(session_id)
                        .cloned()
                        .unwrap_or_else(|| canonical_scope_root_span_id("session", session_id))
                })
        } else {
            None
        };
        spans.push(json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":canonical_scope_root_span_id(scope_kind, &scope_id),
            "trace_context":scope_index.trace_context(selected, false),
            "span_kind":if scope_kind == "turn" {"turn"} else {"task_root"},
            "name":scope_kind,
            "call_id":Value::Null,
            "parent_call_id":Value::Null,
            "parent_span_id":parent_span_id,
            "status":status,
            "started_at":starts.first().and_then(|capture| {
                capture.pointer("/lifecycleEvent/occurred_at").and_then(Value::as_str)
                    .or_else(|| string_field(capture, "receivedAt"))
            }),
            "finished_at":terminals.last().and_then(|capture| {
                capture.pointer("/lifecycleEvent/occurred_at").and_then(Value::as_str)
                    .or_else(|| string_field(capture, "receivedAt"))
            }),
            "arguments":starts.first().and_then(|capture| capture.get("lifecycleEvent")),
            "result":terminals.last().and_then(|capture| capture.get("lifecycleEvent")),
            "error":if matches!(status.as_str(), "failed" | "cancelled" | "timeout" | "incomplete") {
                terminals.last().and_then(|capture| capture.get("lifecycleEvent"))
            } else {
                None
            },
            "tool_schema":Value::Null,
            "raw_capture_refs":capture_ids,
            "extensions":{
                "state_conflict":terminal_statuses.len() > 1,
                "root_complete":root_complete,
                "scope_root":true,
                "parent_span_required":scope_kind == "turn",
                "start_observations":starts.len(),
                "terminal_observations":terminals.len(),
                "wire_start_observations":starts.iter()
                    .filter(|capture| record_type(capture) == "api_snapshot").count(),
                "scope_kind":scope_kind,
                "scope_id":scope_id,
                "observed_trace_ids":trace_ids,
                "observed_native_span_ids":native_span_ids,
                "lifecycle":observations.iter().filter_map(|capture| capture.get("lifecycleEvent")).cloned().collect::<Vec<_>>(),
            },
        }));
    }
    Ok(spans)
}

fn canonical_scope_root_span_id(scope_kind: &str, scope_id: &str) -> String {
    stable_id("runtime-span", &[scope_kind, scope_id, "scope_root"])
}

fn root_observation_is_start(capture: &Value, scope_kind: &str) -> bool {
    if scope_kind == "turn" && record_type(capture) == "api_snapshot" {
        return true;
    }
    capture
        .pointer("/lifecycleEvent/type")
        .and_then(Value::as_str)
        .is_some_and(|event_type| match scope_kind {
            "session" => event_type == "session_start",
            "turn" => matches!(event_type, "turn_start" | "subagent_spawn"),
            "task" => event_type == "task_start",
            _ => false,
        })
}

fn root_observation_is_terminal(capture: &Value, scope_kind: &str) -> bool {
    capture
        .pointer("/lifecycleEvent/type")
        .and_then(Value::as_str)
        .is_some_and(|event_type| match scope_kind {
            "session" => is_session_root_terminal(event_type),
            "turn" => is_turn_root_terminal(event_type) || event_type == "subagent_join",
            "task" => is_explicit_task_root_terminal(event_type),
            _ => false,
        })
}

fn is_session_root_event(event_type: &str) -> bool {
    event_type == "session_start" || is_session_root_terminal(event_type)
}

fn is_session_root_terminal(event_type: &str) -> bool {
    matches!(
        event_type,
        "session_end" | "session_ended" | "session_cancelled"
    ) || event_type.starts_with("session_cancel")
}

fn is_turn_root_event(event_type: &str) -> bool {
    event_type == "turn_start" || is_turn_root_terminal(event_type)
}

fn is_turn_root_terminal(event_type: &str) -> bool {
    matches!(
        event_type,
        "turn_end" | "turn_stop" | "turn_interrupt" | "turn_aborted"
    )
}

fn is_subagent_root_event(event_type: &str) -> bool {
    matches!(event_type, "subagent_spawn" | "subagent_join")
}

fn is_explicit_task_root_event(event_type: &str) -> bool {
    event_type == "task_start" || is_explicit_task_root_terminal(event_type)
}

fn is_explicit_task_root_terminal(event_type: &str) -> bool {
    matches!(
        event_type,
        "task_end" | "task_ended" | "cancel" | "cancelled" | "canceled" | "terminated" | "aborted"
    ) || event_type.starts_with("task_cancel")
}

fn is_task_root_start(event_type: &str) -> bool {
    matches!(event_type, "task_start" | "session_start" | "turn_start")
}

fn is_task_root_terminal(event_type: &str) -> bool {
    matches!(
        event_type,
        "task_end"
            | "task_ended"
            | "session_end"
            | "session_ended"
            | "cancel"
            | "cancelled"
            | "canceled"
            | "terminated"
            | "aborted"
            | "turn_end"
            | "turn_stop"
            | "turn_interrupt"
            | "turn_aborted"
    ) || event_type.starts_with("task_cancel")
        || event_type.starts_with("session_cancel")
}

fn deduplicate_runtime_spans(spans: &mut Vec<Value>) -> Result<()> {
    let mut seen = HashMap::new();
    spans.retain(|span| {
        let Some(span_id) = string_field(span, "span_id") else {
            return true;
        };
        let digest = serde_json::to_vec(span).map(|bytes| sha256(&bytes));
        match (seen.get(span_id), digest) {
            (None, Ok(digest)) => {
                seen.insert(span_id.to_owned(), digest);
                true
            }
            (Some(existing), Ok(digest)) if existing == &digest => false,
            _ => true,
        }
    });
    let mut identities = HashMap::new();
    for span in spans.iter() {
        let span_id = string_field(span, "span_id")
            .ok_or_else(|| anyhow::anyhow!("RuntimeSpan missing span_id"))?;
        let digest = sha256(&serde_json::to_vec(span)?);
        if let Some(existing) = identities.insert(span_id.to_owned(), digest.clone())
            && existing != digest
        {
            bail!("RuntimeSpan {span_id:?} has conflicting records");
        }
    }
    Ok(())
}

#[derive(Debug)]
struct DispatcherCall<'a> {
    capture: &'a Value,
    name: String,
    arguments: Value,
}

#[derive(Debug)]
struct DispatcherResult<'a> {
    capture: &'a Value,
    content: Value,
}

#[derive(Debug, Default)]
struct DispatcherObservations<'a> {
    calls: Vec<DispatcherCall<'a>>,
    results: Vec<DispatcherResult<'a>>,
}

fn build_dispatcher_runtime_spans(
    captures: &[Value],
    scope_index: &RuntimeScopeIndex,
) -> Result<Vec<Value>> {
    let exact_runtime_calls: HashSet<String> = captures
        .iter()
        .filter_map(|capture| {
            let call_id = capture
                .pointer("/toolExecution/call_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())?;
            Some(scoped_runtime_call(scope_index, capture, call_id))
        })
        .collect();
    let mut groups: BTreeMap<String, (String, DispatcherObservations<'_>)> = BTreeMap::new();

    for capture in captures {
        let Some(messages) = capture.get("rolloutMessages").and_then(Value::as_array) else {
            continue;
        };
        for message in messages {
            if string_field(message, "role") == Some("assistant") {
                for call in message
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let Some(call_id) =
                        string_field(call, "id").filter(|value| !value.trim().is_empty())
                    else {
                        continue;
                    };
                    let function = call.get("function").unwrap_or(call);
                    let Some(name) =
                        string_field(function, "name").filter(|value| !value.trim().is_empty())
                    else {
                        continue;
                    };
                    let key = scoped_runtime_call(scope_index, capture, call_id);
                    if exact_runtime_calls.contains(&key) {
                        continue;
                    }
                    let arguments = parse_json_string_or_clone(function.get("arguments"));
                    groups
                        .entry(key)
                        .or_insert_with(|| (call_id.to_owned(), DispatcherObservations::default()))
                        .1
                        .calls
                        .push(DispatcherCall {
                            capture,
                            name: name.to_owned(),
                            arguments,
                        });
                }
            } else if string_field(message, "role") == Some("tool") {
                let Some(call_id) =
                    string_field(message, "tool_call_id").filter(|value| !value.trim().is_empty())
                else {
                    continue;
                };
                let key = scoped_runtime_call(scope_index, capture, call_id);
                if exact_runtime_calls.contains(&key) {
                    continue;
                }
                groups
                    .entry(key)
                    .or_insert_with(|| (call_id.to_owned(), DispatcherObservations::default()))
                    .1
                    .results
                    .push(DispatcherResult {
                        capture,
                        content: message.get("content").cloned().unwrap_or(Value::Null),
                    });
            }
        }
    }

    let mut spans = Vec::new();
    for (scope, (call_id, observations)) in groups {
        let Some(first) = observations.calls.first() else {
            continue;
        };
        let selected = observations
            .results
            .last()
            .map(|result| result.capture)
            .unwrap_or(first.capture);
        let names: BTreeSet<&str> = observations
            .calls
            .iter()
            .map(|call| call.name.as_str())
            .collect();
        let arguments: BTreeSet<String> = observations
            .calls
            .iter()
            .map(|call| canonical_json(&call.arguments))
            .collect::<Result<_>>()?;
        let results: BTreeSet<String> = observations
            .results
            .iter()
            .map(|result| canonical_json(&result.content))
            .collect::<Result<_>>()?;
        let terminal = observations.results.len() == 1;
        let state_conflict = observations.calls.len() != 1
            || observations.results.len() > 1
            || names.len() != 1
            || arguments.len() != 1
            || results.len() > 1;
        let capture_ids: Vec<&str> = observations
            .calls
            .iter()
            .map(|call| call.capture)
            .chain(observations.results.iter().map(|result| result.capture))
            .filter_map(|capture| string_field(capture, "captureId"))
            .collect();
        let evidence: Vec<Value> = observations
            .calls
            .iter()
            .map(|call| native_event_evidence(call.capture))
            .chain(
                observations
                    .results
                    .iter()
                    .map(|result| native_event_evidence(result.capture)),
            )
            .collect();
        spans.push(json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":dispatcher_span_id(&scope),
            "trace_context":scope_index.trace_context(selected, true),
            "span_kind":"tool_execution",
            "name":first.name,
            "call_id":call_id,
            "parent_call_id":Value::Null,
            "parent_span_id":Value::Null,
            "status":if terminal {"completed"} else {"running"},
            "started_at":observations.calls.iter()
                .filter_map(|call| string_field(call.capture, "receivedAt")).min(),
            "finished_at":observations.results.iter()
                .filter_map(|result| string_field(result.capture, "receivedAt")).max(),
            "arguments":first.arguments,
            "result":observations.results.last().map(|result| &result.content),
            "error":Value::Null,
            "tool_schema":Value::Null,
            "raw_capture_refs":capture_ids,
            "extensions":{
                "state_observations":if terminal {json!(["started", "completed"])} else {json!(["started"])},
                "state_conflict":state_conflict,
                "lifecycle_terminal":terminal,
                "semantic_status":"unknown",
                "semantic_status_provenance":"not_reported_by_codex_rollout_response_item",
                "evidence_type":"codex_dispatcher_call_output_pair",
                "schema_provenance":{
                    "source":"codex_rollout_response_item",
                    "source_complete":false,
                    "reason":"rollout response items do not contain the registered tool schema"
                },
                "buyer_schema_eligible":false,
                "codex":evidence,
            },
        }));
    }
    Ok(spans)
}

fn scoped_runtime_call(scope_index: &RuntimeScopeIndex, capture: &Value, call_id: &str) -> String {
    let scope = scope_index.key(capture).unwrap_or_else(|| {
        format!(
            "source:{}\0unscoped:{}",
            source_namespace(capture),
            trace_string(capture, "thread_id")
                .or_else(|| trace_string(capture, "turn_id"))
                .unwrap_or_else(|| string_field(capture, "captureId").unwrap_or("missing"))
        )
    });
    format!("{scope}\0{call_id}")
}

fn dispatcher_span_id(scoped_call: &str) -> String {
    stable_id("runtime-span", &["dispatcher", scoped_call])
}

fn parse_json_string_or_clone(value: Option<&Value>) -> Value {
    match value {
        Some(Value::String(value)) => {
            serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.clone()))
        }
        Some(value) => value.clone(),
        None => Value::Null,
    }
}

fn canonical_json(value: &Value) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn build_tool_runtime_spans(
    captures: &[Value],
    interactions: &[Value],
    scope_index: &RuntimeScopeIndex,
) -> Result<Vec<Value>> {
    let model_call_names = interaction_model_call_names(interactions);
    let mut groups: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for capture in captures {
        let Some(execution) = capture.get("toolExecution") else {
            continue;
        };
        let Some(call_id) = execution.get("call_id").and_then(Value::as_str) else {
            continue;
        };
        let namespace = string_field(capture, "sourceNamespace").unwrap_or("default");
        let scope = scope_index.key(capture).unwrap_or_else(|| {
            format!(
                "{namespace}\0unscoped:{}",
                trace_string(capture, "thread_id")
                    .or_else(|| trace_string(capture, "turn_id"))
                    .unwrap_or_else(|| string_field(capture, "captureId").unwrap_or("missing"))
            )
        });
        groups
            .entry(format!("{scope}\0{call_id}"))
            .or_default()
            .push(capture);
    }
    let mut spans = Vec::new();
    for (_group_key, captures) in groups {
        let first = captures[0];
        let first_execution = &first["toolExecution"];
        let call_id = string_field(first_execution, "call_id").unwrap_or("missing");
        let runtime_name = string_field(first_execution, "name").unwrap_or("unknown");
        let session_id = trace_string(first, "session_id");
        let model_names = session_id
            .map(|session_id| session_call_key(session_id, call_id))
            .and_then(|key| model_call_names.get(&key));
        let name = if model_names.is_some_and(|names| names.len() == 1) {
            model_names
                .and_then(|names| names.iter().next())
                .map(String::as_str)
                .unwrap_or(runtime_name)
        } else {
            runtime_name
        };
        let terminal: Vec<&Value> = captures
            .iter()
            .copied()
            .filter(|capture| string_field(&capture["toolExecution"], "status") != Some("started"))
            .collect();
        // PostToolUse proves the hook ran but does not report an authoritative
        // result status. Prefer codex.tool_result when both observations share
        // the same call_id.
        let selected = terminal
            .iter()
            .rev()
            .copied()
            .find(|capture| string_field(&capture["toolExecution"], "status") != Some("unknown"))
            .or_else(|| terminal.last().copied())
            .unwrap_or(first);
        let execution = &selected["toolExecution"];
        let lifecycle_terminal = terminal.iter().any(|capture| {
            capture
                .pointer("/rolloutEvent/event_type")
                .and_then(Value::as_str)
                == Some("item_completed")
        });
        let dispatch_status = string_field(execution, "status").unwrap_or("unknown");
        let process_outcome = execution
            .get("process_outcome")
            .filter(|value| !value.is_null());
        let semantic_status = match (
            process_outcome.and_then(|value| string_field(value, "state")),
            process_outcome.and_then(|value| value.get("success").and_then(Value::as_bool)),
        ) {
            (Some("exited"), Some(true)) => "success",
            (Some("exited"), Some(false)) => "error",
            (Some("running"), _) => "running",
            _ => dispatch_status,
        };
        let dispatch_status_provenance = string_field(execution, "status_provenance").unwrap_or(
            if string_field(execution, "source_event_name") == Some("codex.tool_result") {
                "codex.tool_result.success"
            } else {
                "codex_rollout_runtime_item.status"
            },
        );
        let semantic_status_provenance = process_outcome
            .and_then(|value| string_field(value, "provenance"))
            .unwrap_or(if dispatch_status == "unknown" {
                "not_reported_by_runtime_item"
            } else {
                dispatch_status_provenance
            });
        let status = if terminal.is_empty() {
            "running".to_owned()
        } else if dispatch_status == "unknown" && lifecycle_terminal {
            "completed".to_owned()
        } else {
            normalize_runtime_status(Some(dispatch_status))
        };
        let parent_call_ids: BTreeSet<String> = captures
            .iter()
            .filter_map(|capture| {
                string_field(&capture["toolExecution"], "parent_call_id").map(str::to_owned)
            })
            .collect();
        let names: BTreeSet<String> = captures
            .iter()
            .filter_map(|capture| {
                string_field(&capture["toolExecution"], "name").map(str::to_owned)
            })
            .collect();
        let authoritative_names: BTreeSet<String> = captures
            .iter()
            .filter(|capture| runtime_observation_is_authoritative(capture))
            .filter_map(|capture| {
                string_field(&capture["toolExecution"], "name").map(str::to_owned)
            })
            .collect();
        let statuses: Vec<String> = captures
            .iter()
            .filter_map(|capture| {
                string_field(&capture["toolExecution"], "status").map(str::to_owned)
            })
            .collect();
        let authoritative_statuses: BTreeSet<&str> = captures
            .iter()
            .filter_map(|capture| string_field(&capture["toolExecution"], "status"))
            .filter(|status| !matches!(*status, "started" | "unknown"))
            .collect();
        let process_outcomes: BTreeSet<Vec<u8>> = captures
            .iter()
            .filter_map(|capture| capture["toolExecution"].get("process_outcome"))
            .filter(|value| !value.is_null())
            .filter_map(|value| serde_json::to_vec(value).ok())
            .collect();
        let capture_ids: Vec<String> = captures
            .iter()
            .filter_map(|capture| string_field(capture, "captureId").map(str::to_owned))
            .collect();
        let scope = scope_index
            .key(first)
            .unwrap_or_else(|| "unscoped".to_owned());
        let span_id = stable_id("runtime-span", &[&scope, call_id]);
        let observed_parent_call_id = (parent_call_ids.len() == 1)
            .then(|| parent_call_ids.iter().next().cloned())
            .flatten();
        // Stock Codex may repeat the execution call ID as parent_call_id for a
        // direct/unified-exec item. The call_id already carries that identity;
        // retaining it as a parent would create a self edge when no Wire call
        // exists. Only a distinct call can be a real parent.
        let parent_call_id = observed_parent_call_id
            .as_deref()
            .filter(|parent| *parent != call_id)
            .map(str::to_owned);
        let collapsed_self_parent = observed_parent_call_id.as_deref() == Some(call_id);
        let model_name_conflict = model_names.is_some_and(|model_names| {
            model_names.len() > 1
                || (!authoritative_names.is_empty()
                    && model_names.is_disjoint(&authoritative_names))
        });
        let conflict = authoritative_statuses.len() > 1
            || process_outcomes.len() > 1
            || authoritative_names.len() > 1
            || model_name_conflict
            || parent_call_ids.len() > 1;
        spans.push(json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":span_id,
            "trace_context":scope_index.trace_context(selected, true),
            "span_kind":"tool_execution",
            "name":name,
            "call_id":call_id,
            "parent_call_id":parent_call_id,
            "parent_span_id":observed_parent_span_id(selected),
            "status":status,
            "started_at":captures.iter().filter_map(|capture| {
                string_field(&capture["toolExecution"], "started_at")
                    .or_else(|| string_field(capture, "receivedAt"))
            }).min(),
            "finished_at":terminal.iter().filter_map(|capture| {
                string_field(&capture["toolExecution"], "finished_at")
                    .or_else(|| string_field(capture, "receivedAt"))
            }).max(),
            "arguments":execution.get("arguments"),
            "result":execution.get("result"),
            "error":execution.get("error"),
            "tool_schema":execution.get("schema"),
            "raw_capture_refs":capture_ids,
            "extensions":{
                "state_observations":statuses,
                "state_conflict":conflict,
                "producer":captures.iter().filter_map(|capture| capture.get("producerEvent")).cloned().collect::<Vec<_>>(),
                "codex":native_runtime_extension(&captures),
                "schema_provenance":execution.get("schema_provenance")
                    .or_else(|| execution.pointer("/schema/schema_provenance")),
                "buyer_schema_eligible":execution.get("schema").is_some_and(|schema| !schema.is_null())
                    && execution.pointer("/schema/schema_provenance/source_complete")
                        .and_then(Value::as_bool) != Some(false),
                "result_content_captured":execution.get("result_content_captured")
                    .and_then(Value::as_bool).unwrap_or(true),
                "output_truncated":execution.get("output_truncated"),
                "lifecycle_terminal":lifecycle_terminal,
                "semantic_status":semantic_status,
                "semantic_status_provenance":semantic_status_provenance,
                "dispatch_status":dispatch_status,
                "dispatch_status_provenance":dispatch_status_provenance,
                "process_outcome":process_outcome,
                "runtime_tool_name":runtime_name,
                "observed_tool_name_aliases":names,
                "authoritative_runtime_tool_names":authoritative_names,
                "observed_parent_call_ids":parent_call_ids,
                "collapsed_self_parent_call_id":collapsed_self_parent,
            },
        }));
    }
    Ok(spans)
}

fn runtime_observation_is_authoritative(capture: &Value) -> bool {
    let execution = &capture["toolExecution"];
    string_field(execution, "source_event_name") == Some("codex.tool_result")
        || string_field(execution, "status")
            .is_some_and(|status| !matches!(status, "started" | "unknown"))
}

fn interaction_model_call_names(interactions: &[Value]) -> HashMap<String, BTreeSet<String>> {
    let mut calls = HashMap::new();
    for interaction in interactions {
        let Some(session_id) = trace_string(interaction, "session_id") else {
            continue;
        };
        for call in interaction
            .get("model_tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(call_id) = call
                .get("call_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            else {
                continue;
            };
            let Some(name) = call
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            else {
                continue;
            };
            calls
                .entry(session_call_key(session_id, call_id))
                .or_insert_with(BTreeSet::new)
                .insert(name.to_owned());
        }
    }
    calls
}

fn build_subagent_runtime_spans(
    captures: &[Value],
    scope_index: &RuntimeScopeIndex,
) -> Result<Vec<Value>> {
    let model_calls = rollout_model_call_keys(captures, scope_index);
    let exact_runtime_calls: HashSet<String> = captures
        .iter()
        .filter_map(|capture| {
            let call_id = capture
                .pointer("/toolExecution/call_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())?;
            Some(scoped_runtime_call(scope_index, capture, call_id))
        })
        .collect();
    let mut groups: BTreeMap<String, (String, String, Vec<&Value>)> = BTreeMap::new();
    for capture in captures {
        let Some(event) = capture.get("lifecycleEvent") else {
            continue;
        };
        if !matches!(
            string_field(event, "type"),
            Some("subagent_spawn" | "subagent_join")
        ) {
            continue;
        }
        let Some(agent_thread_id) = event
            .pointer("/source_event/agent_thread_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        let scope = scope_index
            .key(capture)
            .unwrap_or_else(|| format!("source:{}\0unscoped", source_namespace(capture)));
        groups
            .entry(format!("{scope}\0{agent_thread_id}"))
            .or_insert_with(|| (scope, agent_thread_id.to_owned(), Vec::new()))
            .2
            .push(capture);
    }

    let mut spans = Vec::new();
    for (_, (scope, agent_thread_id, observations)) in groups {
        let starts: Vec<&Value> = observations
            .iter()
            .copied()
            .filter(|capture| {
                capture
                    .pointer("/lifecycleEvent/type")
                    .and_then(Value::as_str)
                    == Some("subagent_spawn")
            })
            .collect();
        let terminals: Vec<&Value> = observations
            .iter()
            .copied()
            .filter(|capture| {
                capture
                    .pointer("/lifecycleEvent/type")
                    .and_then(Value::as_str)
                    == Some("subagent_join")
            })
            .collect();
        let first = starts
            .first()
            .copied()
            .or_else(|| observations.first().copied())
            .context("subagent activity group is empty")?;
        let selected = terminals.last().copied().unwrap_or(first);
        let parent_calls: BTreeSet<String> = starts
            .iter()
            .filter_map(|capture| {
                capture
                    .pointer("/lifecycleEvent/source_event/id")
                    .and_then(Value::as_str)
            })
            .filter(|call_id| model_calls.contains(&format!("{scope}\0{call_id}")))
            .map(str::to_owned)
            .collect();
        let parent_span_id = (parent_calls.len() == 1)
            .then(|| parent_calls.iter().next())
            .flatten()
            .map(|call_id| {
                let scoped_call = format!("{scope}\0{call_id}");
                if exact_runtime_calls.contains(&scoped_call) {
                    stable_id("runtime-span", &[&scope, call_id])
                } else {
                    dispatcher_span_id(&scoped_call)
                }
            });
        let agent_paths: BTreeSet<&str> = observations
            .iter()
            .filter_map(|capture| {
                capture
                    .pointer("/lifecycleEvent/source_event/agent_path")
                    .and_then(Value::as_str)
            })
            .collect();
        let capture_ids: Vec<&str> = observations
            .iter()
            .filter_map(|capture| string_field(capture, "captureId"))
            .collect();
        spans.push(json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":stable_id("runtime-span", &[&scope, "subagent", &agent_thread_id]),
            "trace_context":scope_index.trace_context(selected, true),
            "span_kind":"agent",
            "name":agent_paths.iter().next().copied().unwrap_or("subagent"),
            "call_id":agent_thread_id,
            "parent_call_id":Value::Null,
            "parent_span_id":parent_span_id,
            "status":if terminals.is_empty() {"running"} else {"completed"},
            "started_at":starts.iter().filter_map(|capture| {
                capture.pointer("/lifecycleEvent/occurred_at").and_then(Value::as_str)
                    .or_else(|| string_field(capture, "receivedAt"))
            }).min(),
            "finished_at":terminals.iter().filter_map(|capture| {
                capture.pointer("/lifecycleEvent/occurred_at").and_then(Value::as_str)
                    .or_else(|| string_field(capture, "receivedAt"))
            }).max(),
            "arguments":starts.first().and_then(|capture| capture.get("lifecycleEvent")),
            "result":terminals.last().and_then(|capture| capture.get("lifecycleEvent")),
            "error":Value::Null,
            "tool_schema":Value::Null,
            "raw_capture_refs":capture_ids,
            "extensions":{
                "state_conflict":starts.len() != 1 || terminals.len() != 1
                    || parent_calls.len() > 1 || agent_paths.len() > 1,
                "parent_span_required":parent_span_id.is_some(),
                "agent_thread_id":agent_thread_id,
                "agent_path":agent_paths.iter().next(),
                "spawn_call_id":parent_calls.iter().next(),
                "start_observations":starts.len(),
                "terminal_observations":terminals.len(),
                "codex":observations.iter()
                    .map(|capture| native_event_evidence(capture)).collect::<Vec<_>>(),
            },
        }));
    }
    Ok(spans)
}

fn rollout_model_call_keys(captures: &[Value], scope_index: &RuntimeScopeIndex) -> HashSet<String> {
    rollout_model_call_names(captures, scope_index)
        .into_keys()
        .collect()
}

fn rollout_model_call_names(
    captures: &[Value],
    scope_index: &RuntimeScopeIndex,
) -> HashMap<String, BTreeSet<String>> {
    let mut calls = HashMap::new();
    for capture in captures {
        for call in capture
            .get("rolloutMessages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|message| string_field(message, "role") == Some("assistant"))
            .flat_map(|message| {
                message
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
        {
            let Some(call_id) = string_field(call, "id").filter(|value| !value.trim().is_empty())
            else {
                continue;
            };
            let Some(name) = call
                .get("function")
                .and_then(|function| string_field(function, "name"))
                .filter(|value| !value.trim().is_empty())
            else {
                continue;
            };
            calls
                .entry(scoped_runtime_call(scope_index, capture, call_id))
                .or_insert_with(BTreeSet::new)
                .insert(name.to_owned());
        }
    }
    calls
}

#[derive(Debug, Clone)]
struct NativeSpanEvent<'a> {
    capture: &'a Value,
    kind: String,
    name: String,
    source_id: String,
    phase: &'static str,
    status: String,
    payload: Value,
    parent_call_id: Option<String>,
    correlation_keys: BTreeSet<String>,
}

fn build_native_runtime_spans(
    captures: &[Value],
    scope_index: &RuntimeScopeIndex,
) -> Result<Vec<Value>> {
    let mut groups: BTreeMap<String, Vec<NativeSpanEvent<'_>>> = BTreeMap::new();
    for capture in captures {
        if capture.get("toolExecution").is_some() {
            continue;
        }
        let Some(event) = native_span_event(capture)? else {
            continue;
        };
        let namespace = string_field(capture, "sourceNamespace").unwrap_or("default");
        let trace = capture
            .pointer("/rolloutEvent/bundle_trace_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        groups
            .entry(format!(
                "{namespace}\0{trace}\0{}\0{}",
                event.kind, event.source_id
            ))
            .or_default()
            .push(event);
    }
    let mut spans = Vec::new();
    for events in groups.into_values() {
        let first = &events[0];
        let terminal: Vec<&NativeSpanEvent<'_>> = events
            .iter()
            .filter(|event| event.phase == "terminal")
            .collect();
        let selected = terminal.last().copied().unwrap_or(first);
        let statuses: BTreeSet<String> =
            terminal.iter().map(|event| event.status.clone()).collect();
        let parent_call_ids: BTreeSet<String> = events
            .iter()
            .filter_map(|event| event.parent_call_id.clone())
            .collect();
        let correlation_keys: BTreeSet<String> = events
            .iter()
            .flat_map(|event| event.correlation_keys.iter().cloned())
            .collect();
        let capture_ids: Vec<String> = events
            .iter()
            .filter_map(|event| string_field(event.capture, "captureId").map(str::to_owned))
            .collect();
        let span_id = stable_id(
            "runtime-span",
            &[
                string_field(first.capture, "sourceNamespace").unwrap_or("default"),
                first
                    .capture
                    .pointer("/rolloutEvent/bundle_trace_id")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                &first.kind,
                &first.source_id,
            ],
        );
        spans.push(json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":span_id,
            "trace_context":scope_index.trace_context(selected.capture, true),
            "span_kind":first.kind,
            "name":first.name,
            "call_id":if first.kind == "inference" { Some(first.source_id.as_str()) } else { None },
            "parent_call_id":if parent_call_ids.len() == 1 { parent_call_ids.iter().next() } else { None },
            "parent_span_id":observed_parent_span_id(selected.capture),
            "status":if terminal.is_empty() { "running" } else { selected.status.as_str() },
            "started_at":events.iter().filter_map(|event| string_field(event.capture, "receivedAt")).min(),
            "finished_at":terminal.iter().filter_map(|event| string_field(event.capture, "receivedAt")).max(),
            "arguments":first.payload,
            "result":if terminal.is_empty() { Value::Null } else { selected.payload.clone() },
            "error":if selected.status == "failed" { selected.payload.clone() } else { Value::Null },
            "tool_schema":Value::Null,
            "raw_capture_refs":capture_ids,
            "extensions":{
                "state_conflict":statuses.len() > 1 || parent_call_ids.len() > 1,
                "correlation_keys":correlation_keys,
                "codex":events.iter().map(|event| native_event_evidence(event.capture)).collect::<Vec<_>>(),
            },
        }));
    }
    Ok(spans)
}

fn native_span_event(capture: &Value) -> Result<Option<NativeSpanEvent<'_>>> {
    let Some(rollout) = capture.get("rolloutEvent") else {
        return Ok(None);
    };
    let Some(source_line) = rollout.get("source_line").and_then(Value::as_str) else {
        return Ok(None);
    };
    let source: Value = serde_json::from_str(source_line)?;
    let payload = source.get("payload").cloned().unwrap_or(Value::Null);
    let kind = payload.get("type").and_then(Value::as_str).unwrap_or("");
    let descriptor = match kind {
        "rollout_started" => Some(("rollout", "rollout", "rollout_id", "started", "running")),
        "rollout_ended" => Some(("rollout", "rollout", "rollout_id", "terminal", "completed")),
        "thread_started" => Some(("agent", "agent_thread", "thread_id", "started", "running")),
        "thread_ended" => Some((
            "agent",
            "agent_thread",
            "thread_id",
            "terminal",
            "completed",
        )),
        "codex_turn_started" => Some(("turn", "model_turn", "codex_turn_id", "started", "running")),
        "codex_turn_ended" => Some((
            "turn",
            "model_turn",
            "codex_turn_id",
            "terminal",
            "completed",
        )),
        "inference_started" => Some((
            "inference",
            "model_inference",
            "inference_call_id",
            "started",
            "running",
        )),
        "inference_completed" => Some((
            "inference",
            "model_inference",
            "inference_call_id",
            "terminal",
            "completed",
        )),
        "inference_failed" => Some((
            "inference",
            "model_inference",
            "inference_call_id",
            "terminal",
            "failed",
        )),
        "code_cell_started" => Some((
            "code_cell",
            "code_cell",
            "runtime_cell_id",
            "started",
            "running",
        )),
        "code_cell_ended" => Some((
            "code_cell",
            "code_cell",
            "runtime_cell_id",
            "terminal",
            "completed",
        )),
        "code_cell_failed" => Some((
            "code_cell",
            "code_cell",
            "runtime_cell_id",
            "terminal",
            "failed",
        )),
        "compaction_request_started" => Some((
            "compaction",
            "compaction",
            "compaction_request_id",
            "started",
            "running",
        )),
        "compaction_request_completed" => Some((
            "compaction",
            "compaction",
            "compaction_request_id",
            "terminal",
            "completed",
        )),
        "compaction_request_failed" => Some((
            "compaction",
            "compaction",
            "compaction_request_id",
            "terminal",
            "failed",
        )),
        _ => None,
    };
    let Some((span_kind, name, id_field, phase, default_status)) = descriptor else {
        return Ok(None);
    };
    let source_id = payload
        .get(id_field)
        .and_then(Value::as_str)
        .or_else(|| {
            (id_field == "rollout_id")
                .then(|| source.get("rollout_id").and_then(Value::as_str))
                .flatten()
        })
        .or_else(|| {
            (id_field == "codex_turn_id")
                .then(|| source.get("codex_turn_id").and_then(Value::as_str))
                .flatten()
        })
        .unwrap_or_else(|| string_field(capture, "captureId").unwrap_or("missing"))
        .to_owned();
    let status = normalize_runtime_status(
        payload
            .get("status")
            .and_then(Value::as_str)
            .or(Some(default_status)),
    );
    let parent_call_id = payload
        .get("model_visible_call_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut exact_keys = correlation_keys(capture);
    for (prefix, field) in [
        ("upstream", "upstream_request_id"),
        ("response", "response_id"),
    ] {
        if let Some(value) = payload
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            exact_keys.insert(format!("{prefix}:{value}"));
        }
    }
    Ok(Some(NativeSpanEvent {
        capture,
        kind: span_kind.to_owned(),
        name: name.to_owned(),
        source_id,
        phase,
        status,
        payload,
        parent_call_id,
        correlation_keys: exact_keys,
    }))
}

fn normalize_runtime_status(status: Option<&str>) -> String {
    match status.map(|value| value.trim().to_ascii_lowercase()) {
        Some(value)
            if matches!(
                value.as_str(),
                "success" | "succeeded" | "completed" | "complete" | "ok"
            ) =>
        {
            "completed"
        }
        Some(value) if matches!(value.as_str(), "failed" | "failure" | "error" | "errored") => {
            "failed"
        }
        Some(value) if matches!(value.as_str(), "cancel" | "cancelled" | "canceled") => "cancelled",
        Some(value) if matches!(value.as_str(), "abort" | "aborted" | "terminated") => "cancelled",
        Some(value) if matches!(value.as_str(), "timeout" | "timed_out") => "timeout",
        Some(value) if value == "incomplete" => "incomplete",
        Some(value) if value == "closed" => "closed",
        Some(value) if value == "started" || value == "running" => "running",
        _ => "unknown",
    }
    .to_owned()
}

fn native_runtime_extension(captures: &[&Value]) -> Value {
    Value::Array(
        captures
            .iter()
            .filter(|capture| capture.get("rolloutEvent").is_some())
            .map(|capture| native_event_evidence(capture))
            .collect(),
    )
}

fn native_event_evidence(capture: &Value) -> Value {
    json!({
        "capture_id":string_field(capture, "captureId"),
        "source":capture.pointer("/rolloutEvent/source"),
        "source_ordinal":capture.pointer("/rolloutEvent/source_ordinal"),
        "source_line_sha256":capture.pointer("/rolloutEvent/source_line_sha256"),
        "bundle_trace_id":capture.pointer("/rolloutEvent/bundle_trace_id"),
        "event_type":capture.pointer("/rolloutEvent/event_type"),
    })
}

fn build_interaction_links(
    interactions: &[Value],
    runtime_spans: &[Value],
    captures: &[Value],
) -> Result<Vec<Value>> {
    let mut calls: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut responses: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut exact_interactions: HashMap<String, BTreeSet<String>> = HashMap::new();
    let captures_by_id: HashMap<&str, &Value> = captures
        .iter()
        .filter_map(|capture| {
            string_field(capture, "captureId").map(|capture_id| (capture_id, capture))
        })
        .collect();
    for interaction in interactions {
        let interaction_id = string_field(interaction, "interaction_id").unwrap_or("missing");
        for call_id in interaction
            .get("model_tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|call| call.get("call_id").and_then(Value::as_str))
        {
            calls
                .entry(scoped_model_call_identity(interaction, call_id))
                .or_default()
                .insert(interaction_id.to_owned());
        }
        if let Some(response_id) = interaction
            .pointer("/response/id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            responses
                .entry(scoped_identity(interaction, response_id))
                .or_default()
                .insert(interaction_id.to_owned());
        }
        for reference in interaction
            .get("raw_capture_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(capture_id) = reference.get("capture_id").and_then(Value::as_str) else {
                continue;
            };
            if let Some(capture) = captures_by_id.get(capture_id) {
                for key in correlation_keys(capture) {
                    exact_interactions
                        .entry(scoped_correlation_key(capture, &key))
                        .or_default()
                        .insert(interaction_id.to_owned());
                }
            }
        }
    }
    let mut runtime_span_identities: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut runtime_call_spans: HashMap<String, BTreeSet<String>> = HashMap::new();
    for span in runtime_spans {
        let Some(span_id) = string_field(span, "span_id") else {
            continue;
        };
        if let Some(call_id) =
            string_field(span, "call_id").filter(|value| !value.trim().is_empty())
        {
            runtime_call_spans
                .entry(scoped_identity(span, call_id))
                .or_default()
                .insert(span_id.to_owned());
        }
        for identity in [
            Some(span_id),
            span.pointer("/trace_context/span_id")
                .and_then(Value::as_str),
        ]
        .into_iter()
        .flatten()
        .filter(|value| !value.trim().is_empty())
        {
            runtime_span_identities
                .entry(runtime_span_identity(span, identity))
                .or_default()
                .insert(span_id.to_owned());
        }
    }
    let mut links = Vec::new();
    for interaction in interactions {
        let interaction_id = string_field(interaction, "interaction_id").unwrap_or("missing");
        if let Some(parent_span_id) = observed_parent_span_id(interaction)
            && let Some(targets) =
                runtime_span_identities.get(&runtime_span_identity(interaction, parent_span_id))
            && targets.len() == 1
        {
            let parent = targets.iter().next().cloned().unwrap_or_default();
            links.push(interaction_link(
                &format!("runtime-span:{parent}"),
                &format!("interaction:{interaction_id}"),
                "runtime_parent_to_interaction",
                json!({
                    "match":"exact_parent_span_id",
                    "parent_span_id":parent_span_id,
                }),
            ));
        }
        for (index, result) in interaction
            .get("tool_results_submitted")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let Some(call_id) = result.get("call_id").and_then(Value::as_str) else {
                continue;
            };
            let Some(targets) = calls.get(&scoped_model_call_identity(interaction, call_id)) else {
                continue;
            };
            if targets.len() != 1 {
                continue;
            }
            let source_interaction = targets.iter().next().cloned().unwrap_or_default();
            links.push(interaction_link(
                &format!("model-call:{source_interaction}:{call_id}"),
                &format!("submitted-result:{interaction_id}:{index}"),
                "model_call_to_submitted_result",
                json!({
                    "match":"exact_call_id",
                    "interaction_id":source_interaction,
                    "submitted_in_interaction_id":interaction_id,
                    "call_id":call_id,
                }),
            ));
        }
        if let Some(previous_response_id) = interaction
            .pointer("/request/raw/previous_response_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            && let Some(targets) =
                responses.get(&scoped_identity(interaction, previous_response_id))
            && targets.len() == 1
        {
            let previous_interaction = targets.iter().next().cloned().unwrap_or_default();
            links.push(interaction_link(
                &format!("interaction:{previous_interaction}"),
                &format!("interaction:{interaction_id}"),
                "previous_response_to_interaction",
                json!({
                    "match":"exact_previous_response_id",
                    "response_id":previous_response_id,
                }),
            ));
        }
    }
    for span in runtime_spans {
        let span_id = string_field(span, "span_id").unwrap_or("missing");
        if let Some(parent_call_id) =
            string_field(span, "parent_call_id").filter(|value| !value.trim().is_empty())
            && let Some(targets) = runtime_call_spans.get(&scoped_identity(span, parent_call_id))
            && targets.len() == 1
        {
            let parent = targets.iter().next().cloned().unwrap_or_default();
            if parent != span_id {
                links.push(interaction_link(
                    &format!("runtime-span:{parent}"),
                    &format!("runtime-span:{span_id}"),
                    "runtime_parent_to_child",
                    json!({
                        "match":"exact_runtime_call_id",
                        "parent_call_id":parent_call_id,
                    }),
                ));
            }
        }
        if let Some(parent_span_id) =
            string_field(span, "parent_span_id").filter(|value| !value.trim().is_empty())
            && let Some(parent) = runtime_parent_span(
                span,
                parent_span_id,
                &runtime_span_identities,
                runtime_spans,
            )
            && parent != span_id
        {
            links.push(interaction_link(
                &format!("runtime-span:{parent}"),
                &format!("runtime-span:{span_id}"),
                "runtime_parent_to_child",
                json!({
                    "match":"exact_parent_span_id",
                    "parent_span_id":parent_span_id,
                }),
            ));
        }
        if let Some(parent_call_id) = string_field(span, "parent_call_id")
            && let Some(targets) = calls.get(&scoped_model_call_identity(span, parent_call_id))
            && targets.len() == 1
        {
            let interaction = targets.iter().next().cloned().unwrap_or_default();
            links.push(interaction_link(
                &format!("model-call:{interaction}:{parent_call_id}"),
                &format!("runtime-span:{span_id}"),
                "model_call_to_runtime_execution",
                json!({
                    "match":"exact_parent_call_id",
                    "interaction_id":interaction,
                    "call_id":parent_call_id,
                }),
            ));
        } else if let Some(call_id) = string_field(span, "call_id")
            && let Some(targets) = calls.get(&scoped_model_call_identity(span, call_id))
            && targets.len() == 1
        {
            let interaction = targets.iter().next().cloned().unwrap_or_default();
            links.push(interaction_link(
                &format!("model-call:{interaction}:{call_id}"),
                &format!("runtime-span:{span_id}"),
                "model_call_to_runtime_execution",
                json!({
                    "match":"exact_call_id",
                    "interaction_id":interaction,
                    "call_id":call_id,
                }),
            ));
        }
        for key in span
            .pointer("/extensions/correlation_keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let scoped = scoped_correlation_key(span, key);
            if let Some(targets) = exact_interactions.get(&scoped)
                && targets.len() == 1
            {
                let interaction = targets.iter().next().cloned().unwrap_or_default();
                links.push(interaction_link(
                    &format!("interaction:{interaction}"),
                    &format!("runtime-span:{span_id}"),
                    "interaction_to_runtime_span",
                    json!({"match":"exact_request_identity","key":key}),
                ));
            }
        }
    }

    let mut roots_by_scope: HashMap<String, BTreeSet<String>> = HashMap::new();
    for span in runtime_spans.iter().filter(|span| {
        string_field(span, "span_kind") == Some("task_root")
            || span
                .pointer("/extensions/scope_root")
                .and_then(Value::as_bool)
                == Some(true)
    }) {
        if let (Some(scope), Some(span_id)) =
            (runtime_task_scope(span), string_field(span, "span_id"))
        {
            roots_by_scope
                .entry(scope)
                .or_default()
                .insert(span_id.to_owned());
        }
    }
    let parented_interactions: HashSet<String> = links
        .iter()
        .filter(|link| string_field(link, "relation") == Some("runtime_parent_to_interaction"))
        .filter_map(|link| string_field(link, "to"))
        .map(str::to_owned)
        .collect();
    for interaction in interactions {
        let Some(interaction_id) = string_field(interaction, "interaction_id") else {
            continue;
        };
        let node = format!("interaction:{interaction_id}");
        if parented_interactions.contains(&node) {
            continue;
        }
        let Some(scope) = runtime_task_scope(interaction) else {
            continue;
        };
        let Some(roots) = roots_by_scope.get(&scope).filter(|roots| roots.len() == 1) else {
            continue;
        };
        let root = roots.iter().next().cloned().unwrap_or_default();
        links.push(interaction_link(
            &format!("runtime-span:{root}"),
            &node,
            "runtime_parent_to_interaction",
            json!({"match":"exact_runtime_scope","scope":scope}),
        ));
    }
    let parented_runtime_spans: HashSet<String> = links
        .iter()
        .filter(|link| {
            matches!(
                string_field(link, "relation"),
                Some(
                    "runtime_parent_to_child"
                        | "model_call_to_runtime_execution"
                        | "interaction_to_runtime_span"
                )
            )
        })
        .filter_map(|link| string_field(link, "to"))
        .map(str::to_owned)
        .collect();
    for span in runtime_spans
        .iter()
        .filter(|span| string_field(span, "span_kind") != Some("task_root"))
    {
        let Some(span_id) = string_field(span, "span_id") else {
            continue;
        };
        let node = format!("runtime-span:{span_id}");
        if parented_runtime_spans.contains(&node) {
            continue;
        }
        let Some(scope) = runtime_task_scope(span) else {
            continue;
        };
        let Some(roots) = roots_by_scope.get(&scope).filter(|roots| roots.len() == 1) else {
            continue;
        };
        let root = roots.iter().next().cloned().unwrap_or_default();
        if root != span_id {
            links.push(interaction_link(
                &format!("runtime-span:{root}"),
                &node,
                "runtime_parent_to_child",
                json!({"match":"exact_runtime_scope","scope":scope}),
            ));
        }
    }
    let mut seen = BTreeSet::new();
    links.retain(|link| string_field(link, "link_id").is_some_and(|id| seen.insert(id.to_owned())));
    Ok(links)
}

fn runtime_parent_span(
    child: &Value,
    parent_span_id: &str,
    runtime_span_identities: &HashMap<String, BTreeSet<String>>,
    runtime_spans: &[Value],
) -> Option<String> {
    let native = runtime_span_identities.get(&runtime_span_identity(child, parent_span_id));
    if let Some(targets) = native.filter(|targets| targets.len() == 1) {
        return targets.iter().next().cloned();
    }
    let targets: BTreeSet<String> = runtime_spans
        .iter()
        .filter(|span| string_field(span, "span_id") == Some(parent_span_id))
        .filter(|span| same_session_or_task_scope(child, span))
        .filter_map(|span| string_field(span, "span_id").map(str::to_owned))
        .collect();
    (targets.len() == 1)
        .then(|| targets.into_iter().next())
        .flatten()
}

fn same_session_or_task_scope(left: &Value, right: &Value) -> bool {
    match (
        trace_string(left, "task_session_id"),
        trace_string(right, "task_session_id"),
    ) {
        (Some(left), Some(right)) => return left == right,
        (Some(_), None) | (None, Some(_)) => return false,
        (None, None) => {}
    }
    matches!(
        (trace_string(left, "session_id"), trace_string(right, "session_id")),
        (Some(left), Some(right)) if left == right
    )
}

fn scoped_identity(value: &Value, identity: &str) -> String {
    let scope = canonical_identity_scope(value)
        .unwrap_or_else(|| format!("source:{}", source_namespace(value)));
    format!("{scope}\0{identity}")
}

fn scoped_model_call_identity(value: &Value, call_id: &str) -> String {
    let scope = trace_string(value, "task_session_id")
        .map(|task_session_id| format!("task:{task_session_id}"))
        .or_else(|| {
            trace_string(value, "session_id").map(|session_id| format!("session:{session_id}"))
        })
        .unwrap_or_else(|| format!("source:{}", source_namespace(value)));
    format!("{scope}\0{call_id}")
}

fn runtime_span_identity(value: &Value, identity: &str) -> String {
    let trace = value
        .pointer("/trace_context/trace_id")
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .pointer("/trace_context/traceparent")
                .and_then(Value::as_str)
                .and_then(|traceparent| traceparent.split('-').nth(1))
        })
        .map(|trace_id| format!("trace:{trace_id}"))
        .or_else(|| canonical_identity_scope(value))
        .unwrap_or_else(|| format!("source:{}", source_namespace(value)));
    format!("{trace}\0{identity}")
}

fn runtime_task_scope(value: &Value) -> Option<String> {
    let (kind, identity) = if let Some(identity) = trace_string(value, "task_session_id") {
        ("task", identity)
    } else if value
        .pointer("/extensions/scope_kind")
        .and_then(Value::as_str)
        == Some("session")
    {
        ("session", trace_string(value, "session_id")?)
    } else if let Some(identity) = trace_string(value, "root_turn_id") {
        ("turn", identity)
    } else if let Some(identity) = trace_string(value, "session_id") {
        ("session", identity)
    } else {
        return None;
    };
    Some(runtime_scope_key(value, kind, identity))
}

fn runtime_scope_key(value: &Value, kind: &str, identity: &str) -> String {
    if kind == "task" {
        return format!("task:{identity}");
    }
    if kind == "session" {
        return format!("session:{identity}");
    }
    trace_string(value, "session_id").map_or_else(
        || format!("turn:{identity}"),
        |session_id| format!("session:{session_id}\0turn:{identity}"),
    )
}

fn canonical_identity_scope(value: &Value) -> Option<String> {
    if let Some(task_session_id) = trace_string(value, "task_session_id") {
        return Some(format!("task:{task_session_id}"));
    }
    let session_id = trace_string(value, "session_id");
    let turn_id = trace_string(value, "root_turn_id").or_else(|| trace_string(value, "turn_id"));
    match (session_id, turn_id) {
        (Some(session_id), Some(turn_id)) => Some(format!("session:{session_id}\0turn:{turn_id}")),
        (Some(session_id), None) => Some(format!("session:{session_id}")),
        (None, Some(turn_id)) => Some(format!("turn:{turn_id}")),
        (None, None) => None,
    }
}

fn interaction_link(from: &str, to: &str, relation: &str, evidence: Value) -> Value {
    json!({
        "schema_version":INTERACTION_LINK_SCHEMA_VERSION,
        "link_id":stable_id("link", &[from, to, relation]),
        "from":from,
        "to":to,
        "relation":relation,
        "evidence":evidence,
    })
}

fn attach_captured_tool_schemas(
    runtime_spans: &mut [Value],
    interactions: &[Value],
    links: &[Value],
) -> Result<()> {
    let interactions_by_id: HashMap<&str, &Value> = interactions
        .iter()
        .filter_map(|interaction| {
            string_field(interaction, "interaction_id").map(|id| (id, interaction))
        })
        .collect();
    let spans_by_id: HashMap<&str, usize> = runtime_spans
        .iter()
        .enumerate()
        .filter_map(|(index, span)| string_field(span, "span_id").map(|id| (id, index)))
        .collect();
    let mut candidates: HashMap<usize, BTreeMap<String, (&Value, &str, &str)>> = HashMap::new();

    for link in links {
        if string_field(link, "relation") != Some("model_call_to_runtime_execution") {
            continue;
        }
        let Some(source) =
            string_field(link, "from").and_then(|value| value.strip_prefix("model-call:"))
        else {
            continue;
        };
        let Some((interaction_id, call_id)) = source.rsplit_once(':') else {
            continue;
        };
        let Some(span_id) =
            string_field(link, "to").and_then(|value| value.strip_prefix("runtime-span:"))
        else {
            continue;
        };
        let Some(&span_index) = spans_by_id.get(span_id) else {
            continue;
        };
        if string_field(&runtime_spans[span_index], "call_id") != Some(call_id) {
            continue;
        }
        let Some(interaction) = interactions_by_id.get(interaction_id).copied() else {
            continue;
        };
        let call_names: BTreeSet<&str> = interaction
            .get("model_tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|call| string_field(call, "call_id") == Some(call_id))
            .filter_map(|call| string_field(call, "name"))
            .collect();
        if call_names.len() != 1 {
            continue;
        }
        let name = call_names.iter().next().copied().unwrap_or_default();
        if string_field(&runtime_spans[span_index], "name") != Some(name) {
            continue;
        }
        for definition in interaction
            .get("tool_definitions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|definition| string_field(definition, "name") == Some(name))
        {
            let digest = sha256(&serde_json::to_vec(definition)?);
            candidates
                .entry(span_index)
                .or_default()
                .insert(digest, (definition, interaction_id, call_id));
        }
    }

    for (span_index, definitions) in candidates {
        if definitions.len() > 1 {
            bail!(
                "runtime execution has conflicting captured tool definitions: {}",
                string_field(&runtime_spans[span_index], "span_id").unwrap_or("missing")
            );
        }
        let Some((_, (definition, interaction_id, call_id))) = definitions.into_iter().next()
        else {
            continue;
        };
        if runtime_spans[span_index]
            .get("tool_schema")
            .is_none_or(Value::is_null)
        {
            runtime_spans[span_index]["tool_schema"] = definition.clone();
            runtime_spans[span_index]["extensions"]["schema_provenance"] = json!({
                "source":"openai_request.tools",
                "source_complete":true,
                "interaction_id":interaction_id,
                "call_id":call_id,
            });
            let eligible = definition
                .get("description")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
                && (definition.get("parameters").is_some_and(Value::is_object)
                    || definition.get("format").is_some_and(Value::is_object));
            runtime_spans[span_index]["extensions"]["buyer_schema_eligible"] = json!(eligible);
        }
    }
    Ok(())
}

fn attach_runtime_link_refs(interactions: &mut [Value], links: &[Value]) {
    let mut spans_by_interaction: HashMap<String, BTreeSet<String>> = HashMap::new();
    for link in links {
        let Some(span) =
            string_field(link, "to").and_then(|value| value.strip_prefix("runtime-span:"))
        else {
            continue;
        };
        if let Some(interaction) = link
            .pointer("/evidence/interaction_id")
            .and_then(Value::as_str)
            .or_else(|| {
                string_field(link, "from").and_then(|value| value.strip_prefix("interaction:"))
            })
        {
            spans_by_interaction
                .entry(interaction.to_owned())
                .or_default()
                .insert(span.to_owned());
        }
    }
    for interaction in interactions {
        let Some(interaction_id) = string_field(interaction, "interaction_id") else {
            continue;
        };
        interaction["extensions"]["linked_runtime_span_ids"] = json!(
            spans_by_interaction
                .get(interaction_id)
                .cloned()
                .unwrap_or_default()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CAPTURE_SCHEMA_VERSION, normalize_capture};

    const RESPONSES_NON_STREAM_REQUEST: &str =
        include_str!("../../../fixtures/openai/responses-non-stream-request.json");
    const RESPONSES_NON_STREAM_RESPONSE: &str =
        include_str!("../../../fixtures/openai/responses-non-stream-response.json");
    const RESPONSES_STREAM_REQUEST: &str =
        include_str!("../../../fixtures/openai/responses-stream-request.json");
    const RESPONSES_STREAM_RESPONSE: &str =
        include_str!("../../../fixtures/openai/responses-stream-response.sse");
    const CHAT_NON_STREAM_REQUEST: &str =
        include_str!("../../../fixtures/openai/chat-non-stream-request.json");
    const CHAT_NON_STREAM_RESPONSE: &str =
        include_str!("../../../fixtures/openai/chat-non-stream-response.json");
    const CHAT_STREAM_REQUEST: &str =
        include_str!("../../../fixtures/openai/chat-stream-request.json");
    const CHAT_STREAM_RESPONSE: &str =
        include_str!("../../../fixtures/openai/chat-stream-response.sse");
    const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";
    const ROOT_SPAN_ID: &str = "1111111111111111";

    #[test]
    fn stock_dispatcher_subagent_and_statusless_item_keep_separate_status_facts() {
        let context = json!({
            "session_id":"session-stock",
            "thread_id":"thread-root",
            "root_turn_id":"turn-root",
            "turn_id":"turn-root"
        });
        let rollout = |ordinal: u64, event_type: &str| {
            json!({
                "schema_version":"chiptrace.codex-rollout.v1",
                "source":"codex_rollout_jsonl",
                "source_session_id":"session-stock",
                "source_ordinal":ordinal,
                "classification":"known",
                "event_type":event_type,
                "source_line":"{}",
                "source_line_sha256":sha256(b"{}")
            })
        };
        let call = json!({
            "captureId":"cap-dispatch-call","sourceNamespace":"stock",
            "receivedAt":"2026-09-01T00:00:01Z","traceContext":context,
            "rolloutEvent":rollout(1, "function_call"),
            "rolloutMessages":[{
                "role":"assistant","content":"","tool_calls":[{
                    "id":"call-spawn","type":"function",
                    "function":{"name":"collaboration.spawn_agent","arguments":"{\"task_name\":\"review\"}"}
                }]
            }]
        });
        let result = json!({
            "captureId":"cap-dispatch-result","sourceNamespace":"stock",
            "receivedAt":"2026-09-01T00:00:02Z","traceContext":context,
            "rolloutEvent":rollout(2, "function_call_output"),
            "rolloutMessages":[{
                "role":"tool","content":"{\"task_name\":\"/root/review\"}",
                "tool_call_id":"call-spawn","status":"unknown"
            }]
        });
        let spawn = json!({
            "captureId":"cap-subagent-start","sourceNamespace":"stock",
            "receivedAt":"2026-09-01T00:00:02Z","traceContext":context,
            "rolloutEvent":rollout(3, "item_completed"),
            "lifecycleEvent":{
                "type":"subagent_spawn","status":"started",
                "occurred_at":"2026-09-01T00:00:02Z",
                "source_event":{
                    "type":"SubAgentActivity","id":"call-spawn","kind":"started",
                    "agent_thread_id":"thread-child","agent_path":"/root/review"
                }
            }
        });
        let join = json!({
            "captureId":"cap-subagent-end","sourceNamespace":"stock",
            "receivedAt":"2026-09-01T00:00:04Z","traceContext":context,
            "rolloutEvent":rollout(5, "item_completed"),
            "lifecycleEvent":{
                "type":"subagent_join","status":"completed",
                "occurred_at":"2026-09-01T00:00:04Z",
                "source_event":{
                    "type":"SubAgentActivity","id":"subagent-completed","kind":"completed",
                    "agent_thread_id":"thread-child","agent_path":"/root/review"
                }
            }
        });
        let interaction = json!({
            "captureId":"cap-subagent-interaction","sourceNamespace":"stock",
            "receivedAt":"2026-09-01T00:00:03Z","traceContext":context,
            "rolloutEvent":rollout(4, "item_completed"),
            "lifecycleEvent":{
                "type":"subagent_interaction","status":"completed",
                "occurred_at":"2026-09-01T00:00:03Z",
                "source_event":{
                    "type":"SubAgentActivity","id":"subagent-message", "kind":"interacted",
                    "agent_thread_id":"thread-child","agent_path":"/root/review"
                }
            }
        });
        let image = json!({
            "captureId":"cap-image","sourceNamespace":"stock",
            "receivedAt":"2026-09-01T00:00:03Z","traceContext":context,
            "rolloutEvent":rollout(6, "item_completed"),
            "toolExecution":{
                "call_id":"runtime-image","parent_call_id":"call-spawn",
                "name":"ImageView","status":"unknown","initiator":"runtime",
                "arguments":{"path":"file:///tmp/image.png"},
                "result":{"path":"file:///tmp/image.png"},
                "schema_provenance":{"source":"codex_rollout_item_completed","source_complete":false}
            }
        });
        let captures = vec![call, result, spawn, interaction, image, join];
        let spans = build_runtime_spans(&captures, &[]).unwrap();
        let dispatcher = spans
            .iter()
            .find(|span| span["call_id"] == "call-spawn")
            .unwrap();
        assert_eq!(dispatcher["status"], "completed");
        assert_eq!(dispatcher["extensions"]["semantic_status"], "unknown");
        let subagents: Vec<&Value> = spans
            .iter()
            .filter(|span| span["span_kind"] == "agent")
            .collect();
        assert_eq!(subagents.len(), 1);
        let subagent = subagents[0];
        assert_eq!(subagent["status"], "completed");
        assert_eq!(subagent["parent_span_id"], dispatcher["span_id"]);
        assert_eq!(subagent["extensions"]["state_conflict"], false);
        let image = spans
            .iter()
            .find(|span| span["call_id"] == "runtime-image")
            .unwrap();
        assert_eq!(image["status"], "completed");
        assert_eq!(image["extensions"]["semantic_status"], "unknown");
        assert_eq!(image["extensions"]["lifecycle_terminal"], true);

        let links = build_interaction_links(&[], &spans, &captures).unwrap();
        assert!(links.iter().any(|link| {
            link["relation"] == "runtime_parent_to_child"
                && link["from"]
                    == format!("runtime-span:{}", dispatcher["span_id"].as_str().unwrap())
                && link["to"] == format!("runtime-span:{}", subagent["span_id"].as_str().unwrap())
        }));
    }

    #[test]
    fn cancelled_delivery_is_abandoned_only_with_post_close_byte_evidence() {
        let interaction = |interaction_id: &str,
                           delivery: &str,
                           with_result: bool,
                           source_start: Option<u64>,
                           source_end: Option<u64>| {
            json!({
                "interaction_id":interaction_id,
                "trace_context":{
                    "task_session_id":"task-runtime-integrity"
                },
                "response":{
                    "model_status":"completed",
                    "upstream_transport_status":"completed",
                    "client_delivery_status":delivery
                },
                "integrity":{"protocol_complete":true},
                "model_tool_calls":[{
                    "call_id":"call-runtime-integrity",
                    "name":"exec",
                    "arguments":{},
                    "raw":{},
                    "source_byte_start":source_start,
                    "source_byte_end":source_end
                }],
                "tool_results_submitted":if with_result {
                    json!([{"call_id":"call-runtime-integrity","output":"observed"}])
                } else {
                    json!([])
                }
            })
        };
        let root = json!({
            "span_id":"runtime-root",
            "trace_context":{"task_session_id":"task-runtime-integrity"},
            "span_kind":"task_root",
            "status":"completed",
            "extensions":{"root_complete":true,"state_conflict":false}
        });
        let interaction_to_root = |interaction_id: &str| {
            interaction_link(
                &format!("interaction:{interaction_id}"),
                "runtime-span:runtime-root",
                "interaction_to_runtime_span",
                json!({"match":"test"}),
            )
        };

        // Without a client-close offset there is no admissible abandonment
        // fact, even though the response was cancelled and lacks a result.
        let no_evidence = interaction("interaction-no-evidence", "cancelled", false, None, None);
        let integrity = runtime_integrity(
            std::slice::from_ref(&no_evidence),
            std::slice::from_ref(&root),
            &[interaction_to_root("interaction-no-evidence")],
        );
        assert!(!integrity.runtime_complete);
        assert!(integrity.root_complete);
        assert_eq!(integrity.metrics["model_tool_calls"], 1);
        assert_eq!(integrity.metrics["required_model_tool_calls"], 1);
        assert_eq!(integrity.metrics["abandoned_model_tool_calls"], 0);

        let mut post_close = interaction(
            "interaction-post-close",
            "cancelled",
            false,
            Some(101),
            Some(140),
        );
        post_close["extensions"] = json!({
            "wire": {
                "client_delivery_boundary": {
                    "client_response_closed_before_finish": true,
                    "response_bytes_forwarded_at_client_close": 100,
                    "protocol_terminal_observed_at_client_close": false
                }
            }
        });
        let integrity = runtime_integrity(
            std::slice::from_ref(&post_close),
            std::slice::from_ref(&root),
            &[interaction_to_root("interaction-post-close")],
        );
        assert!(integrity.runtime_complete);
        assert_eq!(integrity.metrics["required_model_tool_calls"], 0);
        assert_eq!(integrity.metrics["abandoned_model_tool_calls"], 1);

        let delivered = interaction(
            "interaction-delivered",
            "completed",
            false,
            Some(101),
            Some(140),
        );
        let integrity = runtime_integrity(
            std::slice::from_ref(&delivered),
            std::slice::from_ref(&root),
            &[interaction_to_root("interaction-delivered")],
        );
        assert!(!integrity.runtime_complete);
        assert_eq!(integrity.metrics["required_model_tool_calls"], 1);
        assert_eq!(integrity.metrics["abandoned_model_tool_calls"], 0);

        let mut partial = interaction(
            "interaction-partial",
            "cancelled",
            true,
            Some(101),
            Some(140),
        );
        partial["extensions"] = json!({
            "wire": {
                "client_delivery_boundary": {
                    "client_response_closed_before_finish": true,
                    "response_bytes_forwarded_at_client_close": 100,
                    "protocol_terminal_observed_at_client_close": false
                }
            }
        });
        let links = [
            interaction_to_root("interaction-partial"),
            interaction_link(
                "model-call:interaction-partial:call-runtime-integrity",
                "submitted-result:interaction-partial:0",
                "model_call_to_submitted_result",
                json!({"match":"test"}),
            ),
        ];
        let integrity = runtime_integrity(
            std::slice::from_ref(&partial),
            std::slice::from_ref(&root),
            &links,
        );
        assert!(!integrity.runtime_complete);
        assert_eq!(integrity.metrics["required_model_tool_calls"], 1);
        assert_eq!(integrity.metrics["abandoned_model_tool_calls"], 0);
        assert_eq!(integrity.metrics["calls_without_results"], json!([]));
        assert_eq!(
            integrity.metrics["calls_without_execution"],
            json!(["model-call:interaction-partial:call-runtime-integrity"])
        );
    }

    #[test]
    fn dispatcher_without_output_remains_open() {
        let capture = json!({
            "captureId":"cap-dispatch-open","sourceNamespace":"stock",
            "receivedAt":"2026-09-01T00:00:01Z",
            "traceContext":{
                "session_id":"session-stock","thread_id":"thread-root",
                "root_turn_id":"turn-root","turn_id":"turn-root"
            },
            "rolloutMessages":[{
                "role":"assistant","content":"","tool_calls":[{
                    "id":"call-open","type":"function",
                    "function":{"name":"wait","arguments":"{}"}
                }]
            }]
        });
        let scope_index = RuntimeScopeIndex::with_interactions(std::slice::from_ref(&capture), &[]);
        let spans = build_dispatcher_runtime_spans(&[capture], &scope_index).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["status"], "running");
        assert_eq!(spans[0]["extensions"]["lifecycle_terminal"], false);
    }

    #[test]
    fn responses_tools_are_collected_recursively_with_reversible_namespaces() {
        let request = json!({
            "tools":[{
                "type":"function",
                "namespace":"functions",
                "name":"plain",
                "description":"Plain tool.",
                "parameters":{"type":"object","properties":{}}
            }],
            "input":[{
                "type":"additional_tools",
                "tools":[{
                    "type":"namespace",
                    "name":"catalog",
                    "tools":[
                        {"type":"function","name":"lookup","description":"Lookup.",
                         "parameters":{"type":"object","properties":{}}},
                        {"type":"custom","name":"query","description":"Query.",
                         "format":{"type":"grammar","syntax":"lark","definition":"start: WORD"}}
                    ]
                }]
            }]
        });
        let definitions = request_tool_definitions(request.as_object().unwrap());
        assert_eq!(definitions.len(), 3);
        assert_eq!(definitions[0]["name"], "plain");
        assert_eq!(definitions[1]["name"], "catalog.lookup");
        assert_eq!(definitions[2]["name"], "catalog.query");
        assert_eq!(definitions[2]["format"]["syntax"], "lark");
        assert_eq!(definitions[2]["raw"]["name"], "query");

        let calls = responses_model_tool_calls(
            &[json!({
                "type":"custom_tool_call",
                "id":"item-1",
                "call_id":"call-1",
                "namespace":"catalog",
                "name":"query",
                "input":"part-42"
            })],
            &BTreeMap::new(),
        );
        assert_eq!(calls[0]["name"], "catalog.query");
        assert_eq!(calls[0]["arguments"], "part-42");
    }

    #[test]
    fn interaction_tool_projection_keeps_exact_namespace_path() {
        let request = json!({"tools":[{
            "type":"namespace","name":"same","tools":[{
                "type":"namespace","name":"same","tools":[{
                    "type":"namespace","name":"segment.with.dot","tools":[{
                        "type":"function","name":"lookup","parameters":{"type":"object","properties":{}}
                    }]
                }]
            }]
        }]});
        let definitions = request_tool_definitions(request.as_object().unwrap());
        assert_eq!(
            definitions[0]["namespace_path"],
            json!(["same", "same", "segment.with.dot"])
        );
    }

    fn fixture_capture(
        capture_id: &str,
        path: &str,
        stream: bool,
        request: &str,
        response: &str,
    ) -> Value {
        let capture = json!({
            "version":CAPTURE_SCHEMA_VERSION,
            "recordType":"api_snapshot",
            "captureId":format!("cap-{capture_id}"),
            "sourceNamespace":"golden",
            "receivedAt":"2026-08-30T00:00:00Z",
            "startedAt":"2026-08-30T00:00:00Z",
            "finishedAt":"2026-08-30T00:00:01Z",
            "proxiedPath":path,
            "stream":stream,
            "responseStatus":200,
            "upstreamResponseCompleted":true,
            "clientRequestAborted":false,
            "clientResponseClosedBeforeFinish":false,
            "clientResponseFinished":true,
            "traceContext":{
                "task_session_id":"task-golden",
                "trace_id":TRACE_ID,
                "parent_span_id":ROOT_SPAN_ID,
                "traceparent":format!("00-{TRACE_ID}-{ROOT_SPAN_ID}-01")
            },
            "requestBodyText":request,
            "responseBodyText":response,
        });
        let normalized =
            normalize_capture(&serde_json::to_vec(&capture).unwrap(), 1024 * 1024).unwrap();
        serde_json::from_slice(&normalized.canonical).unwrap()
    }

    fn feature_set(interaction: &Value) -> BTreeSet<&str> {
        interaction
            .pointer("/protocol/features")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    }

    #[test]
    fn responses_non_stream_golden_preserves_all_items_and_unknown_shapes() {
        let capture = fixture_capture(
            "golden-responses-non-stream",
            "/v1/responses",
            false,
            RESPONSES_NON_STREAM_REQUEST,
            RESPONSES_NON_STREAM_RESPONSE,
        );
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(interaction["protocol"]["endpoint"], "responses");
        assert_eq!(interaction["protocol"]["transport"], "non_stream");
        assert_eq!(interaction["model_tool_calls"].as_array().unwrap().len(), 2);
        assert_eq!(
            interaction["tool_results_submitted"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            interaction["response"]["output_items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| {
                    item["item_type"] == "future_output_item"
                        && item["raw"]["payload"] == json!([1, 2, 3])
                })
        );
        let features = feature_set(&interaction);
        assert!(features.contains("developer_role"));
        assert!(features.contains("reasoning"));
        assert!(features.contains("parallel_calls"));
        assert_eq!(interaction["integrity"]["raw_bytes_complete"], true);
        assert_eq!(interaction["integrity"]["protocol_complete"], false);
        assert_eq!(
            interaction["extensions"]["wire"]["request"]["raw_utf8"],
            RESPONSES_NON_STREAM_REQUEST
        );
    }

    #[test]
    fn responses_stream_golden_rebuilds_terminal_output_and_keeps_sse() {
        let capture = fixture_capture(
            "golden-responses-stream",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            RESPONSES_STREAM_RESPONSE,
        );
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(interaction["protocol"]["transport"], "stream");
        assert_eq!(interaction["response"]["status"], "completed");
        assert_eq!(interaction["model_tool_calls"][0]["name"], "run_query");
        assert!(
            interaction["response"]["output_items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["item_type"] == "future_output_item")
        );
        assert!(
            interaction["extensions"]["wire"]["sse_events"]
                .as_array()
                .unwrap()
                .len()
                >= 5
        );
        assert_eq!(interaction["integrity"]["raw_bytes_complete"], true);
        assert_eq!(interaction["integrity"]["protocol_complete"], true);
        assert_eq!(
            interaction["extensions"]["wire"]["response"]["raw_utf8"],
            RESPONSES_STREAM_RESPONSE
        );
        let call = &interaction["model_tool_calls"][0];
        assert_eq!(call["delivery_evidence"]["available"], true);
        assert_eq!(call["delivery_evidence"]["abandoned"], false);
        assert!(
            call["source_byte_start"].as_u64().unwrap() < call["source_byte_end"].as_u64().unwrap()
        );
    }

    #[test]
    fn responses_stream_marks_only_post_close_calls_as_abandoned() {
        let mut capture = fixture_capture(
            "post-close-call",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            RESPONSES_STREAM_RESPONSE,
        );
        capture["clientResponseClosedBeforeFinish"] = json!(true);
        capture["clientResponseFinished"] = json!(false);
        capture["responseBytesForwarded"] = json!(0);
        capture["responseBytesForwardedAtClientClose"] = json!(0);
        capture["responseProtocolTerminalObservedAtClientClose"] = json!(false);
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(
            interaction["response"]["client_delivery_status"],
            "cancelled"
        );
        assert_eq!(
            interaction["model_tool_calls"][0]["delivery_evidence"]["abandoned"],
            true
        );

        let call_end = interaction["model_tool_calls"][0]["source_byte_end"]
            .as_u64()
            .unwrap();
        capture["responseBytesForwarded"] = json!(call_end + 1);
        capture["responseBytesForwardedAtClientClose"] = json!(call_end + 1);
        let before_close = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(
            before_close["model_tool_calls"][0]["delivery_evidence"]["abandoned"],
            false
        );
    }

    #[test]
    fn sse_missing_blank_boundaries_are_recovered_only_for_valid_json() {
        let response = concat!(
            "event: response.created\n",
            "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-recovered\",\"status\":\"in_progress\"}}\n",
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-recovered\",\"status\":\"completed\",\"output\":[]}}\n\n",
            "data: [DONE]\n\n",
        );
        let capture = fixture_capture(
            "sse-recovered",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            response,
        );
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(interaction["integrity"]["protocol_complete"], true);
        assert_eq!(interaction["extensions"]["wire"]["malformed_sse_events"], 0);
        assert_eq!(
            interaction["extensions"]["wire"]["framing_recovered_events"],
            1
        );
        assert_eq!(
            interaction["extensions"]["wire"]["stream_state"]["framing_done_observed"],
            true
        );

        let invalid = concat!(
            "event: response.created\n",
            "data: {not-json}\n",
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n",
            "data: [DONE]\n\n",
        );
        let invalid_capture = fixture_capture(
            "sse-invalid",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            invalid,
        );
        let invalid_interaction = model_interaction_from_capture(&invalid_capture).unwrap();
        assert_eq!(
            invalid_interaction["extensions"]["wire"]["malformed_sse_events"],
            1
        );
        assert_eq!(
            invalid_interaction["extensions"]["wire"]["framing_recovered_events"],
            0
        );
        assert_eq!(invalid_interaction["integrity"]["protocol_complete"], false);
    }

    #[test]
    fn chat_sse_missing_blank_boundary_is_reported_without_losing_raw_bytes() {
        let request = r#"{"model":"model-family-latest","stream":true,"messages":[{"role":"user","content":"hello"}]}"#;
        let response = concat!(
            "data: {\"id\":\"chat-recovered\",\"model\":\"model-family-latest\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n",
            "data: {\"id\":\"chat-recovered\",\"model\":\"model-family-latest\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n",
            "data: [DONE]\n\n",
        );
        let capture = fixture_capture(
            "chat-recovered",
            "/v1/chat/completions",
            true,
            request,
            response,
        );
        let interaction = model_interaction_from_capture(&capture).unwrap();
        // The KISS delivery gate currently admits Responses streaming only;
        // Chat Completions remains a forensic projection even when framing is
        // recovered correctly.
        assert_eq!(interaction["integrity"]["protocol_complete"], false);
        assert_eq!(interaction["extensions"]["wire"]["malformed_sse_events"], 0);
        assert_eq!(
            interaction["extensions"]["wire"]["framing_recovered_events"],
            2
        );
        assert_eq!(
            interaction["response"]["choices"][0]["message"]["content"],
            "ok"
        );
        assert_eq!(
            interaction["extensions"]["wire"]["response"]["raw_utf8"],
            response
        );
    }

    #[test]
    fn runtime_only_direct_call_collapses_redundant_self_parent() {
        let context = json!({
            "session_id":"session-stock",
            "thread_id":"session-stock",
            "root_turn_id":"turn-stock",
            "turn_id":"turn-stock"
        });
        let lifecycle = |capture_id: &str, event_type: &str, status: &str, at: &str| {
            json!({
                "recordType":"lifecycle_event",
                "captureId":capture_id,
                "sourceNamespace":"stock-codex",
                "receivedAt":at,
                "traceContext":context,
                "lifecycleEvent":{
                    "type":event_type,
                    "status":status,
                    "occurred_at":at
                }
            })
        };
        let tool = json!({
            "recordType":"tool_execution",
            "captureId":"cap-tool",
            "sourceNamespace":"stock-codex",
            "receivedAt":"2026-09-01T00:00:01Z",
            "traceContext":context,
            "toolExecution":{
                "call_id":"call-direct",
                "parent_call_id":"call-direct",
                "name":"exec_command",
                "status":"success",
                "started_at":"2026-09-01T00:00:01Z",
                "finished_at":"2026-09-01T00:00:01Z",
                "arguments":{"cmd":"git diff --check"},
                "result":{"exit_code":0}
            }
        });
        let captures = vec![
            lifecycle("cap-start", "turn_start", "started", "2026-09-01T00:00:00Z"),
            tool,
            lifecycle("cap-end", "turn_end", "completed", "2026-09-01T00:00:02Z"),
        ];

        let spans = build_runtime_spans(&captures, &[]).unwrap();
        let tool_span = spans
            .iter()
            .find(|span| span["call_id"] == "call-direct")
            .unwrap();
        assert_eq!(tool_span["parent_call_id"], Value::Null);
        assert_eq!(
            tool_span["extensions"]["observed_parent_call_ids"],
            json!(["call-direct"])
        );
        assert_eq!(
            tool_span["extensions"]["collapsed_self_parent_call_id"],
            true
        );

        let links = build_interaction_links(&[], &spans, &captures).unwrap();
        assert!(links.iter().any(|link| {
            link["relation"] == "runtime_parent_to_child"
                && link["to"] == format!("runtime-span:{}", tool_span["span_id"].as_str().unwrap())
        }));
        let integrity = runtime_integrity(&[], &spans, &links);
        assert!(!integrity.root_complete);
        assert!(!integrity.runtime_complete);
        assert_eq!(
            integrity.metrics["unresolved_parent_call_span_ids"],
            json!([])
        );
    }

    #[test]
    fn runtime_span_separates_dispatch_success_from_process_failure() {
        let capture = json!({
            "recordType":"tool_execution",
            "captureId":"cap-process-failed",
            "sourceNamespace":"stock-codex-cloud",
            "receivedAt":"2026-09-04T00:00:01Z",
            "traceContext":{
                "session_id":"session-process",
                "thread_id":"session-process",
                "root_turn_id":"turn-process",
                "turn_id":"turn-process"
            },
            "toolExecution":{
                "call_id":"call-process",
                "name":"exec_command",
                "status":"success",
                "status_scope":"tool_dispatch",
                "status_provenance":"codex.tool_result.success",
                "source_event_name":"codex.tool_result",
                "started_at":"2026-09-04T00:00:00Z",
                "finished_at":"2026-09-04T00:00:01Z",
                "arguments":{"cmd":"exit 101"},
                "result":"Process exited with code 101",
                "process_outcome":{
                    "kind":"process",
                    "state":"exited",
                    "exit_code":101,
                    "success":false,
                    "provenance":"stock_codex.unified_exec.log_output.header"
                }
            }
        });

        let spans = build_runtime_spans(&[capture], &[]).unwrap();
        let span = spans
            .iter()
            .find(|span| span["call_id"] == "call-process")
            .unwrap();
        assert_eq!(span["status"], "completed");
        assert_eq!(span["extensions"]["dispatch_status"], "success");
        assert_eq!(span["extensions"]["semantic_status"], "error");
        assert_eq!(
            span["extensions"]["semantic_status_provenance"],
            "stock_codex.unified_exec.log_output.header"
        );
        assert_eq!(span["extensions"]["process_outcome"]["exit_code"], 101);
    }

    #[test]
    fn responses_created_then_done_is_protocol_incomplete() {
        let response = concat!(
            "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-created-only\",\"status\":\"in_progress\",\"output\":[]}}\n\n",
            "data: [DONE]\n\n",
        );
        let capture = fixture_capture(
            "created-done",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            response,
        );
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(
            interaction["extensions"]["wire"]["stream_state"]["framing_done_observed"],
            true
        );
        assert_eq!(
            interaction["integrity"]["stream_outcome"],
            "eof_without_terminal"
        );
        assert_eq!(interaction["response"]["model_status"], "incomplete");
        assert_eq!(interaction["integrity"]["protocol_complete"], false);
    }

    #[test]
    fn responses_error_then_done_is_failed_and_preserves_error() {
        let response = concat!(
            "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-error\",\"status\":\"in_progress\",\"output\":[]}}\n\n",
            "data: {\"type\":\"error\",\"error\":{\"code\":\"upstream_failure\",\"message\":\"real upstream error\"}}\n\n",
            "data: [DONE]\n\n",
        );
        let capture = fixture_capture(
            "error-done",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            response,
        );
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(interaction["integrity"]["stream_outcome"], "failed");
        assert_eq!(interaction["response"]["model_status"], "failed");
        assert_eq!(interaction["integrity"]["protocol_complete"], true);
        assert_eq!(
            interaction["error"]["stream_error"]["error"]["message"],
            "real upstream error"
        );
    }

    #[test]
    fn responses_completed_with_client_close_keeps_both_statuses() {
        let mut capture = fixture_capture(
            "completed-client-close",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            RESPONSES_STREAM_RESPONSE,
        );
        capture["clientResponseClosedBeforeFinish"] = json!(true);
        capture["clientResponseFinished"] = json!(false);
        capture["responseBytesForwarded"] = json!(RESPONSES_STREAM_RESPONSE.len());
        capture["responseBytesForwardedAtClientClose"] = json!(RESPONSES_STREAM_RESPONSE.len());
        capture["responseProtocolTerminalObservedAtClientClose"] = json!(true);
        capture["responseFramingDoneObservedAtClientClose"] = json!(true);
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(interaction["response"]["model_status"], "completed");
        assert_eq!(
            interaction["response"]["upstream_transport_status"],
            "completed"
        );
        assert_eq!(
            interaction["response"]["client_delivery_status"],
            "cancelled"
        );
        assert_eq!(interaction["integrity"]["stream_outcome"], "completed");
        assert_eq!(interaction["integrity"]["protocol_complete"], true);
    }

    #[test]
    fn contradictory_client_delivery_evidence_fails_closed() {
        let mut capture = fixture_capture(
            "contradictory-client-delivery",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            RESPONSES_STREAM_RESPONSE,
        );
        capture["clientResponseClosedBeforeFinish"] = json!(true);
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(interaction["response"]["client_delivery_status"], "unknown");
        assert_eq!(
            interaction["integrity"]["client_delivery_evidence_consistent"],
            false
        );
        assert_eq!(interaction["integrity"]["protocol_complete"], false);
    }

    #[test]
    fn responses_stream_distinguishes_incomplete_cancelled_and_transport_error() {
        for (event_type, expected) in [
            ("response.incomplete", "incomplete"),
            ("response.cancelled", "cancelled"),
        ] {
            let response = format!(
                "data: {{\"type\":\"response.created\",\"response\":{{\"id\":\"resp-state\",\"status\":\"in_progress\",\"output\":[]}}}}\n\ndata: {{\"type\":\"{event_type}\",\"response\":{{\"id\":\"resp-state\",\"status\":\"{expected}\",\"output\":[]}}}}\n\ndata: [DONE]\n\n"
            );
            let capture = fixture_capture(
                expected,
                "/v1/responses",
                true,
                RESPONSES_STREAM_REQUEST,
                &response,
            );
            let interaction = model_interaction_from_capture(&capture).unwrap();
            assert_eq!(interaction["integrity"]["stream_outcome"], expected);
            assert_eq!(interaction["response"]["model_status"], expected);
            assert_eq!(interaction["integrity"]["protocol_complete"], true);
        }

        let response = concat!(
            "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-transport\",\"status\":\"in_progress\",\"output\":[]}}\n\n",
            "data: [DONE]\n\n",
        );
        let mut capture = fixture_capture(
            "transport-error",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            response,
        );
        capture["upstreamResponseCompleted"] = json!(false);
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(
            interaction["integrity"]["stream_outcome"],
            "transport_error"
        );
        assert_eq!(
            interaction["response"]["upstream_transport_status"],
            "transport_error"
        );
        assert_eq!(interaction["integrity"]["protocol_complete"], false);
    }

    #[test]
    fn m0_responses_task_trace_closes_the_core_integrity_gates() {
        let mut first_api = fixture_capture(
            "m0-api-1",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            RESPONSES_STREAM_RESPONSE,
        );
        first_api["upstreamRequestId"] = json!("upstream-1");
        let second_request = json!({
            "model":"model-family-latest",
            "stream":true,
            "input":[{
                "type":"function_call_output",
                "call_id":"call-query",
                "output":"42"
            }]
        })
        .to_string();
        let second_response = concat!(
            "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-m0-2\",\"status\":\"in_progress\",\"model\":\"model-family-latest\",\"output\":[]}}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-m0-2\",\"status\":\"completed\",\"model\":\"model-family-latest\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"42\"}]}]}}\n\n",
            "data: [DONE]\n\n",
        );
        let mut second_api = fixture_capture(
            "m0-api-2",
            "/v1/responses",
            true,
            &second_request,
            second_response,
        );
        second_api["upstreamRequestId"] = json!("upstream-2");

        let trace_context = json!({
            "task_session_id":"task-golden",
            "trace_id":TRACE_ID,
            "parent_span_id":ROOT_SPAN_ID,
            "traceparent":format!("00-{TRACE_ID}-{ROOT_SPAN_ID}-01")
        });
        let start = json!({
            "recordType":"lifecycle_event","captureId":"cap-m0-start",
            "sourceNamespace":"golden","receivedAt":"2026-08-30T00:00:00Z",
            "traceContext":{
                "task_session_id":"task-golden","trace_id":TRACE_ID,
                "span_id":ROOT_SPAN_ID,
                "traceparent":format!("00-{TRACE_ID}-{ROOT_SPAN_ID}-01")
            },
            "lifecycleEvent":{"type":"task_start","status":"started","occurred_at":"2026-08-30T00:00:00Z"}
        });
        let mut end = start.clone();
        end["captureId"] = json!("cap-m0-end");
        end["receivedAt"] = json!("2026-08-30T00:00:05Z");
        end["lifecycleEvent"] = json!({
            "type":"task_end","status":"completed","occurred_at":"2026-08-30T00:00:05Z"
        });
        let tool = json!({
            "recordType":"tool_execution","captureId":"cap-m0-tool",
            "sourceNamespace":"golden","receivedAt":"2026-08-30T00:00:02Z",
            "traceContext":trace_context,
            "toolExecution":{
                "call_id":"runtime-query","parent_call_id":"call-query",
                "name":"run_query","status":"success","initiator":"assistant",
                "started_at":"2026-08-30T00:00:01Z",
                "finished_at":"2026-08-30T00:00:02Z",
                "arguments":{"sql":"select count(*) from traces"},
                "result":{"rows":[{"count":42}]},
                "schema":{
                    "name":"run_query","description":"Run a structured query.",
                    "parameters":{"type":"object","properties":{"sql":{"type":"string","description":"SQL query."}},"required":["sql"]}
                }
            }
        });
        let raw_captures = [start, first_api.clone(), tool, second_api.clone(), end];
        let stored = raw_captures
            .iter()
            .map(|capture| {
                normalize_capture(&serde_json::to_vec(capture).unwrap(), 16 * 1024 * 1024).unwrap()
            })
            .collect::<Vec<_>>();
        let captures = stored
            .iter()
            .map(|record| serde_json::from_slice(&record.canonical).unwrap())
            .collect::<Vec<Value>>();
        let interactions = vec![
            model_interaction_from_capture(
                captures
                    .iter()
                    .find(|capture| string_field(capture, "captureId") == Some("cap-m0-api-1"))
                    .unwrap(),
            )
            .unwrap(),
            model_interaction_from_capture(
                captures
                    .iter()
                    .find(|capture| string_field(capture, "captureId") == Some("cap-m0-api-2"))
                    .unwrap(),
            )
            .unwrap(),
        ];
        let runtime_spans = build_runtime_spans(&captures, &interactions).unwrap();
        let links = build_interaction_links(&interactions, &runtime_spans, &captures).unwrap();
        let (raw_bytes_complete, protocol_complete, _) =
            aggregate_interaction_integrity(&interactions);
        let runtime = runtime_integrity(&interactions, &runtime_spans, &links);
        assert!(raw_bytes_complete);
        assert!(protocol_complete);
        assert!(runtime.runtime_complete);
        assert!(runtime.root_complete);
        assert_eq!(runtime.metrics["root_span_count"], 1);
        assert_eq!(runtime.metrics["model_tool_calls"], 1);
        assert_eq!(runtime.metrics["model_tool_calls_with_results"], 1);
        assert_eq!(runtime.metrics["model_tool_calls_with_execution"], 1);
        let (_, hierarchy) =
            crate::telemetry::project_otlp_tree(&interactions, &runtime_spans, &links).unwrap();
        assert_eq!(hierarchy.root_spans, 1);
        assert_eq!(hierarchy.resolved_internal_parent_rate, 1.0);
        assert!(hierarchy.missing_parent_nodes.is_empty());

        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("captures.jsonl");
        let mut bytes = Vec::new();
        for record in &stored {
            bytes.extend_from_slice(&record.canonical);
            bytes.push(b'\n');
        }
        fs::write(&input, bytes).unwrap();
        let projection = temp.path().join("projection");
        let manifest = project_interactions(InteractionProjectConfig {
            inputs: vec![input],
            output: projection.clone(),
            task_session_id: Some("task-golden".to_owned()),
            session_id: None,
            zstd_level: 1,
            replace: false,
        })
        .unwrap();
        assert_eq!(
            manifest.integrity,
            DeliveryIntegrity {
                artifact_valid: true,
                raw_bytes_complete: true,
                protocol_complete: true,
                runtime_complete: true,
                root_complete: true,
                delivery_ready: true,
            }
        );
        assert_eq!(manifest.validation_status, "delivery_ready");
        assert_eq!(
            verify_interaction_projection(&projection).unwrap(),
            manifest
        );
        let otlp = temp.path().join("otlp");
        let otlp_manifest = crate::telemetry::export_otlp(crate::telemetry::OtlpExportConfig {
            projection,
            output: otlp.clone(),
            zstd_level: 1,
            replace: false,
        })
        .unwrap();
        assert_eq!(otlp_manifest.root_spans, 1);
        assert_eq!(otlp_manifest.resolved_internal_parent_rate, 1.0);
        assert!(otlp_manifest.missing_parent_nodes.is_empty());
        assert_eq!(
            crate::telemetry::verify_otlp_export(&otlp).unwrap(),
            otlp_manifest
        );
    }

    #[test]
    fn chat_non_stream_golden_preserves_multi_choice_reasoning_and_parallel_calls() {
        let capture = fixture_capture(
            "golden-chat-non-stream",
            "/v1/chat/completions",
            false,
            CHAT_NON_STREAM_REQUEST,
            CHAT_NON_STREAM_RESPONSE,
        );
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(interaction["protocol"]["endpoint"], "chat_completions");
        assert_eq!(
            interaction["response"]["choices"].as_array().unwrap().len(),
            2
        );
        assert_eq!(interaction["model_tool_calls"].as_array().unwrap().len(), 2);
        assert_eq!(
            interaction["tool_results_submitted"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let features = feature_set(&interaction);
        assert!(features.contains("developer_role"));
        assert!(features.contains("reasoning"));
        assert!(features.contains("multi_choice"));
        assert!(features.contains("parallel_calls"));
        assert_eq!(interaction["integrity"]["protocol_complete"], false);
    }

    #[test]
    fn chat_stream_golden_reassembles_fragmented_arguments_and_all_choices() {
        let capture = fixture_capture(
            "golden-chat-stream",
            "/v1/chat/completions",
            true,
            CHAT_STREAM_REQUEST,
            CHAT_STREAM_RESPONSE,
        );
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(
            interaction["response"]["choices"].as_array().unwrap().len(),
            2
        );
        assert_eq!(interaction["model_tool_calls"][0]["name"], "search_docs");
        assert_eq!(
            interaction["model_tool_calls"][0]["arguments"],
            "{\"query\":\"adapter\"}"
        );
        assert_eq!(
            interaction["response"]["choices"][0]["message"]["reasoning_content"],
            "Need evidence."
        );
        assert_eq!(interaction["usage"]["total_tokens"], 56);
        assert_eq!(interaction["integrity"]["protocol_complete"], false);
    }

    #[test]
    fn chat_stream_preserves_legacy_fragmented_function_call() {
        let request = r#"{"model":"model-family-latest","stream":true,"messages":[{"role":"user","content":"lookup"}]}"#;
        let response = concat!(
            "data: {\"id\":\"chat-legacy\",\"model\":\"model-family-latest\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"function_call\":{\"name\":\"look\",\"arguments\":\"{\\\"q\\\":\"}},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chat-legacy\",\"model\":\"model-family-latest\",\"choices\":[{\"index\":0,\"delta\":{\"function_call\":{\"name\":\"up\",\"arguments\":\"\\\"trace\\\"}\"}},\"finish_reason\":\"function_call\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let capture = fixture_capture(
            "golden-chat-legacy-stream",
            "/v1/chat/completions",
            true,
            request,
            response,
        );
        let interaction = model_interaction_from_capture(&capture).unwrap();
        assert_eq!(interaction["model_tool_calls"][0]["name"], "lookup");
        assert_eq!(
            interaction["model_tool_calls"][0]["arguments"],
            "{\"q\":\"trace\"}"
        );
        assert_eq!(
            interaction["response"]["choices"][0]["message"]["function_call"]["raw_deltas"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn exact_parent_call_link_crosses_producers_but_not_sessions() {
        let mut wire_a = fixture_capture(
            "wire-a",
            "/v1/responses",
            false,
            RESPONSES_NON_STREAM_REQUEST,
            RESPONSES_NON_STREAM_RESPONSE,
        );
        wire_a["sourceNamespace"] = json!("wire-gateway");
        wire_a["traceContext"] = json!({
            "session_id":"session-golden",
            "root_turn_id":"turn-golden",
            "turn_id":"turn-golden"
        });
        let mut wire_b = wire_a.clone();
        wire_b["captureId"] = json!("cap-wire-b");
        wire_b["traceContext"]["session_id"] = json!("session-other");
        let mut interaction_a = model_interaction_from_capture(&wire_a).unwrap();
        let mut interaction_b = model_interaction_from_capture(&wire_b).unwrap();
        interaction_a["model_tool_calls"] = json!([{
            "call_id":"outer-call","name":"exec","arguments":{},"raw":{}
        }]);
        interaction_b["model_tool_calls"] = interaction_a["model_tool_calls"].clone();
        let span = json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":"runtime-inner",
            "trace_context":{
                "source_namespace":"stock-codex-rollout",
                "session_id":"session-golden",
                "root_turn_id":"turn-golden",
                "turn_id":"turn-golden"
            },
            "span_kind":"tool_execution",
            "name":"exec_command",
            "call_id":"inner-call",
            "parent_call_id":"outer-call",
            "status":"failed",
            "arguments":{"cmd":"false"},
            "result":Value::Null,
            "error":{"exit_code":1},
            "raw_capture_refs":["runtime-capture"],
            "extensions":{"state_conflict":false},
        });
        let links = build_interaction_links(
            &[interaction_a.clone(), interaction_b.clone()],
            std::slice::from_ref(&span),
            &[wire_a],
        )
        .unwrap();
        let parent_links: Vec<&Value> = links
            .iter()
            .filter(|link| link["relation"] == "model_call_to_runtime_execution")
            .collect();
        assert_eq!(parent_links.len(), 1);
        assert_eq!(
            parent_links[0]["evidence"]["interaction_id"],
            interaction_a["interaction_id"]
        );
        let integrity = runtime_integrity(
            &[interaction_a, interaction_b],
            std::slice::from_ref(&span),
            &links,
        );
        assert!(!integrity.runtime_complete);
        assert_eq!(integrity.metrics["model_tool_calls_with_execution"], 1);
        let api_only = runtime_integrity(&[], &[], &[]);
        assert!(!api_only.runtime_complete);
        assert!(!api_only.root_complete);
    }

    #[test]
    fn runtime_parent_span_must_resolve_within_the_same_trace() {
        let parent = json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":"runtime-parent",
            "trace_context":{
                "source_namespace":"otlp",
                "trace_id":"0123456789abcdef0123456789abcdef",
                "span_id":"1111111111111111"
            },
            "span_kind":"agent",
            "name":"parent",
            "status":"completed",
            "raw_capture_refs":["parent"],
            "extensions":{"state_conflict":false},
        });
        let child = json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":"runtime-child",
            "trace_context":{
                "source_namespace":"otlp",
                "trace_id":"0123456789abcdef0123456789abcdef",
                "span_id":"2222222222222222",
                "parent_span_id":"1111111111111111"
            },
            "span_kind":"tool_execution",
            "name":"child",
            "parent_span_id":"1111111111111111",
            "status":"completed",
            "raw_capture_refs":["child"],
            "extensions":{"state_conflict":false,"parent_span_required":true},
        });
        let spans = vec![parent, child.clone()];
        let links = build_interaction_links(&[], &spans, &[]).unwrap();
        assert_eq!(
            links
                .iter()
                .filter(|link| link["relation"] == "runtime_parent_to_child")
                .count(),
            1
        );
        let resolved = runtime_integrity(&[], &spans, &links);
        assert_eq!(resolved.metrics["resolved_internal_parents"], 1);

        let dangling = vec![child];
        let dangling_links = build_interaction_links(&[], &dangling, &[]).unwrap();
        let integrity = runtime_integrity(&[], &dangling, &dangling_links);
        assert!(!integrity.runtime_complete);
        assert_eq!(
            integrity.metrics["unresolved_parent_span_ids"][0],
            "runtime-child"
        );
    }

    #[test]
    fn lifecycle_task_root_resolves_all_internal_parents() {
        let start = json!({
            "recordType":"lifecycle_event",
            "captureId":"cap-task-start",
            "sourceNamespace":"golden",
            "receivedAt":"2026-08-30T00:00:00Z",
            "traceContext":{
                "task_session_id":"task-golden",
                "trace_id":TRACE_ID,
                "span_id":ROOT_SPAN_ID,
                "traceparent":format!("00-{TRACE_ID}-{ROOT_SPAN_ID}-01")
            },
            "lifecycleEvent":{
                "type":"task_start","status":"started",
                "occurred_at":"2026-08-30T00:00:00Z"
            }
        });
        let mut end = start.clone();
        end["captureId"] = json!("cap-task-end");
        end["receivedAt"] = json!("2026-08-30T00:00:02Z");
        end["lifecycleEvent"] = json!({
            "type":"task_end","status":"completed",
            "occurred_at":"2026-08-30T00:00:02Z"
        });
        let child = json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":"runtime-child",
            "trace_context":{
                "source_namespace":"golden",
                "task_session_id":"task-golden",
                "trace_id":TRACE_ID,
                "span_id":"2222222222222222",
                "parent_span_id":ROOT_SPAN_ID
            },
            "span_kind":"tool_execution",
            "name":"run_tests",
            "parent_span_id":ROOT_SPAN_ID,
            "status":"completed",
            "raw_capture_refs":["cap-tool"],
            "extensions":{"state_conflict":false}
        });
        let captures = [start, end];
        let scope_index = RuntimeScopeIndex::with_interactions(&captures, &[]);
        let mut spans = build_task_root_spans(&captures, &scope_index).unwrap();
        assert_eq!(spans.len(), 1);
        spans.push(child);
        let links = build_interaction_links(&[], &spans, &[]).unwrap();
        let integrity = runtime_integrity(&[], &spans, &links);
        assert!(integrity.root_complete);
        assert_eq!(integrity.metrics["internal_parent_references"], 1);
        assert_eq!(integrity.metrics["resolved_internal_parents"], 1);
        assert_eq!(integrity.metrics["resolved_internal_parent_rate"], 1.0);
    }

    #[test]
    fn stock_turn_root_merges_consistent_cancel_evidence_and_rejects_status_conflicts() {
        let lifecycle = |capture_id: &str, event_type: &str, status: &str, occurred_at: &str| {
            json!({
                "recordType":"lifecycle_event",
                "captureId":capture_id,
                "sourceNamespace":"stock",
                "receivedAt":occurred_at,
                "traceContext":{
                    "session_id":"session-interrupt",
                    "thread_id":"session-interrupt",
                    "root_turn_id":"turn-interrupt",
                    "turn_id":"turn-interrupt"
                },
                "lifecycleEvent":{
                    "type":event_type,
                    "status":status,
                    "occurred_at":occurred_at
                }
            })
        };
        let start = lifecycle(
            "cap-turn-start",
            "turn_start",
            "started",
            "2026-09-01T00:00:00Z",
        );
        let interrupt = lifecycle(
            "cap-turn-interrupt",
            "turn_interrupt",
            "cancelled",
            "2026-09-01T00:00:01Z",
        );
        let aborted = lifecycle(
            "cap-turn-aborted",
            "turn_aborted",
            "cancelled",
            "2026-09-01T00:00:02Z",
        );
        let captures = [start.clone(), interrupt, aborted];
        let scope_index = RuntimeScopeIndex::with_interactions(&captures, &[]);
        let spans = build_task_root_spans(&captures, &scope_index).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["status"], "cancelled");
        assert_eq!(spans[0]["extensions"]["root_complete"], true);
        assert_eq!(spans[0]["extensions"]["state_conflict"], false);
        assert_eq!(spans[0]["extensions"]["terminal_observations"], 2);
        let integrity = runtime_integrity(&[], &spans, &[]);
        assert!(!integrity.root_complete);
        assert!(!integrity.runtime_complete);

        let completed = lifecycle(
            "cap-turn-stop",
            "turn_stop",
            "completed",
            "2026-09-01T00:00:03Z",
        );
        let captures = [start, captures[1].clone(), captures[2].clone(), completed];
        let scope_index = RuntimeScopeIndex::with_interactions(&captures, &[]);
        let spans = build_task_root_spans(&captures, &scope_index).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["extensions"]["root_complete"], false);
        assert_eq!(spans[0]["extensions"]["state_conflict"], true);
        assert_eq!(spans[0]["extensions"]["terminal_observations"], 3);
        let integrity = runtime_integrity(&[], &spans, &[]);
        assert!(!integrity.root_complete);
        assert!(!integrity.runtime_complete);
    }

    #[test]
    fn missing_lifecycle_root_fails_complete_trace() {
        let child = json!({
            "schema_version":RUNTIME_SPAN_SCHEMA_VERSION,
            "span_id":"runtime-child",
            "trace_context":{
                "source_namespace":"golden",
                "task_session_id":"task-golden",
                "trace_id":TRACE_ID,
                "span_id":"2222222222222222",
                "parent_span_id":ROOT_SPAN_ID
            },
            "span_kind":"tool_execution",
            "name":"run_tests",
            "parent_span_id":ROOT_SPAN_ID,
            "status":"completed",
            "raw_capture_refs":["cap-tool"],
            "extensions":{"state_conflict":false}
        });
        let spans = vec![child];
        let links = build_interaction_links(&[], &spans, &[]).unwrap();
        let integrity = runtime_integrity(&[], &spans, &links);
        assert!(!integrity.root_complete);
        assert!(!integrity.runtime_complete);
        assert_eq!(
            integrity.metrics["unresolved_parent_span_ids"][0],
            "runtime-child"
        );
    }

    #[test]
    fn canonical_schemas_do_not_embed_vendor_or_buyer_policy_names() {
        for schema in [
            include_str!("../../../schemas/model-interaction-v1.schema.json"),
            include_str!("../../../schemas/runtime-span-v1.schema.json"),
            include_str!("../../../schemas/interaction-link-v1.schema.json"),
        ] {
            let lower = schema.to_ascii_lowercase();
            for forbidden in ["codex", "sub2api", "buyer-v7", "gpt-", "claude", "gemini"] {
                assert!(
                    !lower.contains(forbidden),
                    "forbidden core token {forbidden}"
                );
            }
        }
    }

    #[test]
    fn protocol_matrix_projects_for_forensics_but_is_not_m0_delivery() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("captures.jsonl");
        let captures = [
            fixture_capture(
                "matrix-responses-non-stream",
                "/v1/responses",
                false,
                RESPONSES_NON_STREAM_REQUEST,
                RESPONSES_NON_STREAM_RESPONSE,
            ),
            fixture_capture(
                "matrix-responses-stream",
                "/v1/responses",
                true,
                RESPONSES_STREAM_REQUEST,
                RESPONSES_STREAM_RESPONSE,
            ),
            fixture_capture(
                "matrix-chat-non-stream",
                "/v1/chat/completions",
                false,
                CHAT_NON_STREAM_REQUEST,
                CHAT_NON_STREAM_RESPONSE,
            ),
            fixture_capture(
                "matrix-chat-stream",
                "/v1/chat/completions",
                true,
                CHAT_STREAM_REQUEST,
                CHAT_STREAM_RESPONSE,
            ),
        ];
        let bytes = captures
            .iter()
            .map(|capture| serde_json::to_string(capture).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&input, bytes).unwrap();

        let projection = temp.path().join("projection");
        let manifest = project_interactions(InteractionProjectConfig {
            inputs: vec![input],
            output: projection.clone(),
            task_session_id: Some("task-golden".to_owned()),
            session_id: None,
            zstd_level: 1,
            replace: false,
        })
        .unwrap();
        assert_eq!(manifest.interactions, 4);
        assert_eq!(manifest.protocol_counts["responses"], 2);
        assert_eq!(manifest.protocol_counts["chat_completions"], 2);
        assert_eq!(manifest.transport_counts["stream"], 2);
        assert_eq!(manifest.transport_counts["non_stream"], 2);
        assert!(!manifest.integrity.protocol_complete);
        assert!(!manifest.integrity.runtime_complete);
        assert!(!manifest.integrity.root_complete);
        assert_eq!(manifest.validation_status, "not_ready");
        assert_eq!(verify_interaction_artifacts(&projection).unwrap(), manifest);
        assert!(verify_interaction_projection(&projection).is_err());
    }

    #[test]
    fn canonical_record_schemas_reject_invalid_records() {
        let validators = CanonicalValidators::new().unwrap();
        for (validator, version) in [
            (
                &validators.model_interaction,
                MODEL_INTERACTION_SCHEMA_VERSION,
            ),
            (&validators.runtime_span, RUNTIME_SPAN_SCHEMA_VERSION),
            (
                &validators.interaction_link,
                INTERACTION_LINK_SCHEMA_VERSION,
            ),
        ] {
            let invalid = json!({"schema_version":version});
            assert!(
                validate_canonical_records(validator, version, &[invalid], "negative fixture")
                    .is_err(),
                "{version} accepted a record missing required fields"
            );
        }
    }

    #[test]
    fn mixed_task_inputs_require_an_explicit_task_selection() {
        let first = fixture_capture(
            "task-selection-a",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            RESPONSES_STREAM_RESPONSE,
        );
        let mut second = fixture_capture(
            "task-selection-b",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            RESPONSES_STREAM_RESPONSE,
        );
        second["traceContext"]["task_session_id"] = json!("task-other");
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("mixed.jsonl");
        fs::write(
            &input,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&first).unwrap(),
                serde_json::to_string(&second).unwrap()
            ),
        )
        .unwrap();

        let error = project_interactions(InteractionProjectConfig {
            inputs: vec![input.clone()],
            output: temp.path().join("ambiguous"),
            task_session_id: None,
            session_id: None,
            zstd_level: 1,
            replace: false,
        })
        .unwrap_err();
        assert!(error.to_string().contains("--task-session-id"));

        let projection = temp.path().join("selected");
        let manifest = project_interactions(InteractionProjectConfig {
            inputs: vec![input],
            output: projection.clone(),
            task_session_id: Some("task-other".to_owned()),
            session_id: None,
            zstd_level: 1,
            replace: false,
        })
        .unwrap();
        assert_eq!(manifest.task_session_id.as_deref(), Some("task-other"));
        assert_eq!(manifest.input_records, 1);
        assert_eq!(manifest.interactions, 1);
        assert_eq!(verify_interaction_artifacts(&projection).unwrap(), manifest);
    }

    #[test]
    fn mixed_stock_sessions_require_session_selection_and_keep_task_null() {
        let mut first = fixture_capture(
            "stock-session-a",
            "/v1/responses",
            true,
            RESPONSES_STREAM_REQUEST,
            RESPONSES_STREAM_RESPONSE,
        );
        first["sourceNamespace"] = json!("wire-gateway");
        first["traceContext"] = json!({
            "session_id":"session-a",
            "thread_id":"thread-a",
            "root_turn_id":"turn-a",
            "turn_id":"turn-a"
        });
        let mut second = first.clone();
        second["captureId"] = json!("cap-stock-session-b");
        second["traceContext"] = json!({
            "session_id":"session-b",
            "thread_id":"thread-b",
            "root_turn_id":"turn-b",
            "turn_id":"turn-b"
        });
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("mixed-stock.jsonl");
        fs::write(
            &input,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&first).unwrap(),
                serde_json::to_string(&second).unwrap()
            ),
        )
        .unwrap();

        let error = project_interactions(InteractionProjectConfig {
            inputs: vec![input.clone()],
            output: temp.path().join("ambiguous-stock"),
            task_session_id: None,
            session_id: None,
            zstd_level: 1,
            replace: false,
        })
        .unwrap_err();
        assert!(error.to_string().contains("--session-id"));

        let projection = temp.path().join("selected-stock");
        let manifest = project_interactions(InteractionProjectConfig {
            inputs: vec![input],
            output: projection.clone(),
            task_session_id: None,
            session_id: Some("session-b".to_owned()),
            zstd_level: 1,
            replace: false,
        })
        .unwrap();
        assert_eq!(manifest.task_session_id, None);
        assert_eq!(manifest.session_id.as_deref(), Some("session-b"));
        assert_eq!(manifest.input_records, 1);
        assert_eq!(manifest.interactions, 1);
        assert_eq!(verify_interaction_artifacts(&projection).unwrap(), manifest);
    }

    #[test]
    fn child_thread_uses_its_observed_root_turn_in_a_multi_turn_session() {
        let root_a = json!({
            "sourceNamespace":"stock",
            "traceContext":{
                "session_id":"session-a","thread_id":"thread-root",
                "root_turn_id":"turn-a","turn_id":"turn-a"
            }
        });
        let root_b = json!({
            "sourceNamespace":"stock",
            "traceContext":{
                "session_id":"session-a","thread_id":"thread-root",
                "root_turn_id":"turn-b","turn_id":"turn-b"
            }
        });
        let child_wire = json!({
            "sourceNamespace":"stock",
            "traceContext":{
                "session_id":"session-a","thread_id":"thread-child",
                "parent_thread_id":"thread-root",
                "root_turn_id":"turn-a","turn_id":"turn-child"
            }
        });
        let child_rollout = json!({
            "sourceNamespace":"stock",
            "traceContext":{
                "session_id":"session-a","thread_id":"thread-child",
                "parent_thread_id":"thread-root","turn_id":"turn-child"
            }
        });
        let index = RuntimeScopeIndex::with_interactions(&[root_a, root_b, child_wire], &[]);

        assert_eq!(
            index.scope(&child_rollout),
            Some(("turn", "turn-a".to_owned()))
        );
        assert_eq!(
            index.trace_context(&child_rollout, true)["root_turn_id"],
            "turn-a"
        );
    }

    #[test]
    fn stock_session_selection_includes_only_explicitly_linked_subagent_evidence() {
        let lifecycle = |capture_id: &str, event_type: &str| {
            json!({
                "captureId":capture_id,"sourceNamespace":"stock-codex-cloud",
                "traceContext":{
                    "session_id":"session-root","root_turn_id":"turn-child",
                    "turn_id":"turn-child","agent_id":"session-child"
                },
                "lifecycleEvent":{
                    "type":event_type,
                    "source_event":{
                        "session_id":"session-root","agent_id":"session-child",
                        "turn_id":"turn-child"
                    }
                }
            })
        };
        let child = json!({
            "captureId":"cap-child-tool","sourceNamespace":"stock-codex-cloud",
            "traceContext":{
                "session_id":"session-child","conversation_id":"session-child",
                "thread_id":"session-child"
            },
            "toolExecution":{
                "call_id":"call-child","name":"exec_command","status":"success"
            }
        });
        let unrelated = json!({
            "captureId":"cap-unrelated","sourceNamespace":"stock-codex-cloud",
            "traceContext":{"session_id":"session-unrelated"}
        });

        let (selected, task_session_id, session_id) = select_projection_captures(
            vec![
                lifecycle("cap-child-start", "subagent_spawn"),
                child,
                lifecycle("cap-child-stop", "subagent_join"),
                unrelated,
            ],
            None,
            Some("session-root"),
        )
        .unwrap();
        assert_eq!(task_session_id, None);
        assert_eq!(session_id.as_deref(), Some("session-root"));
        assert_eq!(selected.len(), 3);
        let child = selected
            .iter()
            .find(|capture| string_field(capture, "captureId") == Some("cap-child-tool"))
            .unwrap();
        assert_eq!(child["traceContext"]["session_id"], "session-root");
        assert_eq!(child["traceContext"]["source_session_id"], "session-child");
        assert_eq!(child["traceContext"]["root_turn_id"], "turn-child");
    }
}
