use crate::capture::{extract_body, gateway_evidence_fingerprint};
use crate::jsonl::{
    JsonlWriter, absolute_path, ensure_safe_relative_path, sha256_file, string_field, utc_now,
};
use crate::schema::{
    FileManifest, RAW_LINEAGE_SCHEMA_VERSION, RawSourceLineage, SESSION_SCHEMA_VERSION,
};
use crate::tool_registry::{
    canonical_runtime_tool_name, canonical_tool_registry_sha256, canonical_tool_schema_sha256,
    tool_definition_source_complete,
};
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use walkdir::WalkDir;

pub const ASSEMBLY_SCHEMA_VERSION: &str = "chiptrace.assembly-manifest.v1";

#[derive(Debug, Clone)]
pub struct AssembleConfig {
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
    pub partitions: usize,
    pub zstd_level: i32,
    pub replace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyManifest {
    pub schema_version: String,
    pub created_at_utc: String,
    pub format: String,
    pub capture_schema_versions: BTreeSet<String>,
    pub inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_sources: Vec<RawSourceLineage>,
    pub input_records: u64,
    pub duplicate_captures_removed: u64,
    #[serde(default)]
    pub exact_task_links_applied: u64,
    pub sessions: u64,
    pub orphan_sessions: u64,
    pub merge_divergences: u64,
    pub parts: Vec<FileManifest>,
    pub validation_status: String,
}

#[derive(Debug, Clone, Default)]
struct PartitionResult {
    sessions: u64,
    orphan_sessions: u64,
    merge_divergences: u64,
    file: Option<FileManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskLinkTarget {
    task_session_id: String,
    source_capture_id: String,
}

#[derive(Debug, Clone, Default)]
struct ParsedCapture {
    capture_id: String,
    record_type: String,
    timestamp: String,
    timestamp_unix_nanos: Option<i128>,
    response: Value,
    request_id: Option<String>,
    upstream_request_id: Option<String>,
    response_id: Option<String>,
    previous_response_id: Option<String>,
    response_status: Option<u64>,
    terminal_status: Option<String>,
    provider: String,
    provider_evidence: Value,
    model: Option<String>,
    response_model: Option<String>,
    source_namespace: String,
    session_identity: String,
    session_identity_source: String,
    trace_context: Map<String, Value>,
    field_evidence: Vec<Value>,
    protocol_conflicts: Vec<Value>,
    gateway_evidence: Option<Value>,
    gateway_evidence_join: Option<Value>,
    lifecycle_events: Vec<String>,
    lifecycle_event_records: Vec<Value>,
    evaluation_evidence: Vec<Value>,
    tool_execution: Option<Value>,
    producer_event: Option<Value>,
    tool_registry_evidence: Option<Value>,
    final_snapshot: bool,
    messages: Vec<Value>,
    response_messages: Vec<Value>,
    tools: Vec<Value>,
    system_prompt: Option<String>,
    system_prompt_sources: Vec<Value>,
    usage: UsageObservation,
    rollout_event: Option<Value>,
    rollout_usage: Option<Value>,
    rollout_unknown: bool,
    rollout_unmapped_tool: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Usage {
    input_tokens: u64,
    cached_input_tokens: u64,
    cache_creation_input_tokens: u64,
    output_tokens: u64,
    reasoning_tokens: u64,
    total_tokens: u64,
}

impl Usage {
    fn add(&mut self, other: &Self) {
        self.input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        self.cached_input_tokens = self
            .cached_input_tokens
            .saturating_add(other.cached_input_tokens);
        self.cache_creation_input_tokens = self
            .cache_creation_input_tokens
            .saturating_add(other.cache_creation_input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(other.output_tokens);
        self.reasoning_tokens = self.reasoning_tokens.saturating_add(other.reasoning_tokens);
        self.total_tokens = self.total_tokens.saturating_add(other.total_tokens);
    }

    fn as_value(&self) -> Value {
        json!({
            "input_tokens": self.input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "total_tokens": self.total_tokens,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct UsagePresence {
    input_tokens: bool,
    cached_input_tokens: bool,
    cache_creation_input_tokens: bool,
    output_tokens: bool,
    reasoning_tokens: bool,
    total_tokens: bool,
}

#[derive(Debug, Clone)]
struct ReconciledCaptureUsage {
    values: Usage,
    present: UsagePresence,
    evidence: Value,
    conflicts: BTreeSet<String>,
}

impl UsagePresence {
    fn any(&self) -> bool {
        self.input_tokens
            || self.cached_input_tokens
            || self.cache_creation_input_tokens
            || self.output_tokens
            || self.reasoning_tokens
            || self.total_tokens
    }

    fn fields(&self) -> Vec<&'static str> {
        [
            ("input_tokens", self.input_tokens),
            ("cached_input_tokens", self.cached_input_tokens),
            (
                "cache_creation_input_tokens",
                self.cache_creation_input_tokens,
            ),
            ("output_tokens", self.output_tokens),
            ("reasoning_tokens", self.reasoning_tokens),
            ("total_tokens", self.total_tokens),
        ]
        .into_iter()
        .filter_map(|(field, present)| present.then_some(field))
        .collect()
    }
}

#[derive(Debug, Clone, Default)]
struct UsageObservation {
    values: Usage,
    present: UsagePresence,
}

pub fn assemble(config: AssembleConfig) -> Result<AssemblyManifest> {
    if config.inputs.is_empty() {
        bail!("at least one capture input is required");
    }
    if config.partitions == 0 {
        bail!("partitions must be positive");
    }
    let inputs = discover_inputs(&config.inputs)?;
    if inputs.is_empty() {
        bail!("no NDJSON capture files found");
    }
    let raw_sources = discover_raw_sources(&config.inputs, &inputs)?;
    let task_links = build_task_link_index(&inputs)?;
    let output = absolute_path(&config.output)?;
    if output.exists() && !config.replace {
        bail!("assembly output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("assembly output has no parent"))?;
    fs::create_dir_all(parent)?;
    let work = TempDir::new_in(parent)?;
    let partition_root = work.path().join("partitions");
    let staging = work.path().join("release");
    fs::create_dir_all(&partition_root)?;
    fs::create_dir_all(staging.join("sessions"))?;
    let mut partition_writers = Vec::with_capacity(config.partitions);
    for index in 0..config.partitions {
        partition_writers.push(BufWriter::with_capacity(
            4 * 1024 * 1024,
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(partition_root.join(format!("capture-{index:05}.ndjson")))?,
        ));
    }
    let mut seen_capture_ids: HashMap<String, String> = HashMap::new();
    let mut duplicate_captures = 0_u64;
    let mut exact_task_links_applied = 0_u64;
    let mut input_records = 0_u64;
    let mut versions = BTreeSet::new();
    for path in &inputs {
        let reader = crate::jsonl::open_jsonl_reader(path)?;
        for (line_index, line) in reader.split(b'\n').enumerate() {
            let line =
                line.with_context(|| format!("read {} line {}", path.display(), line_index + 1))?;
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let mut value: Value = serde_json::from_slice(&line)
                .with_context(|| format!("parse {} line {}", path.display(), line_index + 1))?;
            let capture_id = string_field(&value, "captureId")
                .ok_or_else(|| anyhow::anyhow!("captureId missing in {}", path.display()))?;
            let digest = hex::encode(Sha256::digest(&line));
            if let Some(existing) = seen_capture_ids.get(capture_id) {
                if existing != &digest {
                    bail!("captureId {capture_id:?} has conflicting bytes across inputs");
                }
                duplicate_captures += 1;
                continue;
            }
            seen_capture_ids.insert(capture_id.to_owned(), digest);
            let linked = apply_exact_task_link(&mut value, &task_links)?;
            exact_task_links_applied = exact_task_links_applied.saturating_add(u64::from(linked));
            if let Some(version) = string_field(&value, "version") {
                versions.insert(version.to_owned());
            }
            let key = task_partition_key(&value);
            let index = partition_index(&key, config.partitions);
            if linked {
                partition_writers[index].write_all(&serde_json::to_vec(&value)?)?;
            } else {
                partition_writers[index].write_all(&line)?;
            }
            partition_writers[index].write_all(b"\n")?;
            input_records += 1;
        }
    }
    for mut writer in partition_writers {
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }

    let partition_paths: Vec<PathBuf> = (0..config.partitions)
        .map(|index| partition_root.join(format!("capture-{index:05}.ndjson")))
        .collect();
    let results: Vec<PartitionResult> = partition_paths
        .par_iter()
        .enumerate()
        .map(|(index, path)| {
            process_partition(path, &staging.join("sessions"), index, config.zstd_level)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut parts: Vec<FileManifest> = results
        .iter()
        .filter_map(|result| result.file.clone())
        .collect();
    parts.sort_by(|left, right| left.file.cmp(&right.file));
    let manifest = AssemblyManifest {
        schema_version: ASSEMBLY_SCHEMA_VERSION.to_owned(),
        created_at_utc: utc_now(),
        format: "one complete canonical Session per JSONL line; zstd compression".to_owned(),
        capture_schema_versions: versions,
        inputs: inputs
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        raw_sources,
        input_records,
        duplicate_captures_removed: duplicate_captures,
        exact_task_links_applied,
        sessions: results.iter().map(|result| result.sessions).sum(),
        orphan_sessions: results.iter().map(|result| result.orphan_sessions).sum(),
        merge_divergences: results.iter().map(|result| result.merge_divergences).sum(),
        parts,
        validation_status: "pass".to_owned(),
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
    sync_directory(parent)?;
    verify_assembly(&output)?;
    Ok(manifest)
}

pub fn verify_assembly(root: &Path) -> Result<AssemblyManifest> {
    let manifest: AssemblyManifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json"))?)?;
    if manifest.schema_version != ASSEMBLY_SCHEMA_VERSION {
        bail!("unsupported assembly schema {}", manifest.schema_version);
    }
    if manifest.validation_status != "pass" {
        bail!(
            "assembly validation status is {}",
            manifest.validation_status
        );
    }
    for source in &manifest.raw_sources {
        validate_raw_source(source)?;
    }
    let mut sessions = 0_u64;
    let mut expected_files = HashSet::from(["manifest.json".to_owned()]);
    for part in &manifest.parts {
        ensure_safe_relative_path(&part.file)?;
        if !expected_files.insert(part.file.clone()) {
            bail!("duplicate assembly part path: {}", part.file);
        }
        let path = root.join(&part.file);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("assembly part is not a regular file: {}", path.display());
        }
        if path.metadata()?.len() != part.bytes || sha256_file(&path)? != part.sha256 {
            bail!("assembly part checksum mismatch: {}", path.display());
        }
        let mut reader = crate::jsonl::open_jsonl_reader(&path)?;
        let mut line = Vec::new();
        let mut part_records = 0_u64;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let session: Value = serde_json::from_slice(&line)?;
            if string_field(&session, "schema_version") != Some(SESSION_SCHEMA_VERSION)
                || string_field(&session, "session_id").is_none()
            {
                bail!("invalid canonical session in {}", path.display());
            }
            part_records += 1;
            sessions += 1;
        }
        if part.records != Some(part_records) {
            bail!("assembly part record count mismatch: {}", part.file);
        }
    }
    if sessions != manifest.sessions {
        bail!(
            "assembly session count mismatch: observed={sessions}, manifest={}",
            manifest.sessions
        );
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
                .expect("walked assembly entry outside root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    if actual_files != expected_files {
        bail!("assembly file set does not match manifest");
    }
    Ok(manifest)
}

fn process_partition(
    input: &Path,
    output_root: &Path,
    index: usize,
    zstd_level: i32,
) -> Result<PartitionResult> {
    let mut groups: HashMap<String, Vec<Value>> = HashMap::new();
    let reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
    for line in reader.split(b'\n') {
        let line = line?;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: Value = serde_json::from_slice(&line)?;
        groups
            .entry(session_group_key(&value))
            .or_default()
            .push(value);
    }
    if groups.is_empty() {
        return Ok(PartitionResult::default());
    }
    let relative = format!("sessions/session-part-{index:05}.jsonl.zst");
    let path = output_root.join(format!("session-part-{index:05}.jsonl.zst"));
    let mut writer = JsonlWriter::create(&path, zstd_level)?;
    let mut keys: Vec<String> = groups.keys().cloned().collect();
    keys.sort();
    let mut result = PartitionResult::default();
    let mut sessions = Vec::with_capacity(keys.len());
    for key in keys {
        let captures = groups.remove(&key).expect("partition key disappeared");
        let (session, orphan, divergence) = assemble_group(captures)?;
        result.sessions += 1;
        result.orphan_sessions += u64::from(orphan);
        result.merge_divergences += divergence;
        sessions.push(session);
    }
    attach_task_dags(&mut sessions)?;
    let mut uncompressed = 0_u64;
    for session in sessions {
        uncompressed = uncompressed.saturating_add(writer.write_value(&session)?);
    }
    writer.finish()?;
    result.file = Some(FileManifest {
        file: relative,
        sha256: sha256_file(&path)?,
        bytes: path.metadata()?.len(),
        records: Some(result.sessions),
        uncompressed_bytes: Some(uncompressed),
        oversized_session: None,
    });
    Ok(result)
}

fn assemble_group(captures: Vec<Value>) -> Result<(Value, bool, u64)> {
    let mut parsed: Vec<ParsedCapture> = captures
        .into_iter()
        .map(parse_capture)
        .collect::<Result<Vec<_>>>()?;
    parsed.sort_by(compare_capture_order);
    let first = parsed
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty capture group"))?;
    let code_mode_parent_call_ids = native_code_mode_parent_call_ids(&parsed);
    let source_namespace = first.source_namespace.clone();
    let session_identity = first.session_identity.clone();
    let identity_source = first.session_identity_source.clone();
    if parsed.iter().any(|capture| {
        capture.source_namespace != source_namespace || capture.session_identity != session_identity
    }) {
        bail!("capture partition mixed different session identities");
    }
    let orphan = identity_source == "capture_id_fallback";
    let mut messages = Vec::new();
    let mut tools_by_name: BTreeMap<String, Value> = BTreeMap::new();
    let mut schema_conflicts: BTreeSet<String> = BTreeSet::new();
    let mut rollout_events = Vec::new();
    let mut rollout_usage_evidence = Vec::new();
    let mut rollout_unknown_events = BTreeSet::new();
    let mut rollout_unmapped_tools = BTreeSet::new();
    let mut lifecycle = Vec::new();
    let mut lifecycle_event_records = Vec::new();
    let mut evaluation_evidence = Vec::new();
    let mut request_models = BTreeSet::new();
    let mut response_models = BTreeSet::new();
    let mut providers = BTreeSet::new();
    let mut provider_evidence = Vec::new();
    let mut provider_attested_api_snapshots = 0_u64;
    let mut response_ids = Vec::new();
    let mut trace = Map::new();
    let mut trace_conflicts = BTreeSet::new();
    let mut trace_session_ids = BTreeSet::new();
    let mut trace_thread_ids = BTreeSet::new();
    let mut turn_ids = BTreeSet::new();
    let mut previous_response_ids = BTreeSet::new();
    let mut span_ids = BTreeSet::new();
    let mut parent_span_ids = BTreeSet::new();
    let mut tool_registry_evidence = Vec::new();
    let mut field_evidence = Vec::new();
    let mut protocol_conflicts = Vec::new();
    let mut gateway_evidence_records = Vec::new();
    let mut gateway_requested_models = BTreeSet::new();
    let mut gateway_upstream_models = BTreeSet::new();
    let mut gateway_providers = BTreeSet::new();
    let mut model_mapping_chains = BTreeSet::new();
    let mut model_evidence_conflicts = BTreeSet::new();
    let mut proxy_route_evidence_count = 0_u64;
    let mut system_prompt_evidence = Vec::new();
    let mut system_prompt_conflicts = BTreeSet::new();
    let mut system_prompt_variants = BTreeSet::new();
    let mut task_scoped_system_prompts = BTreeSet::new();
    let mut system_prompt = None;
    let mut divergences = 0_u64;
    for capture in &parsed {
        let mut candidate = capture.messages.clone();
        candidate.retain(|message| string_field(message, "role") != Some("system"));
        candidate.extend(capture.response_messages.clone());
        divergences += merge_messages(&mut messages, &candidate);
        for tool in &capture.tools {
            let Some(name) = tool_name(tool) else {
                continue;
            };
            if let Some(existing) = tools_by_name.get(name)
                && !tool_schemas_semantically_equal(existing, tool)
            {
                schema_conflicts.insert(name.to_owned());
            }
            tools_by_name.insert(name.to_owned(), tool.clone());
        }
        if let Some(execution) = &capture.tool_execution {
            divergences += project_tool_execution(
                &mut messages,
                &mut tools_by_name,
                &mut schema_conflicts,
                execution,
            );
        }
        if let Some(registry) = &capture.tool_registry_evidence {
            tool_registry_evidence.push(registry.clone());
        }
        field_evidence.extend(capture.field_evidence.clone());
        for conflict in &capture.protocol_conflicts {
            protocol_conflicts.push(json!({
                "capture_id": capture.capture_id,
                "conflict": conflict,
            }));
            if let Some(field) = conflict.get("field").and_then(Value::as_str) {
                trace_conflicts.insert(format!("{}:{field}", capture.capture_id));
            }
        }
        if let Some(evidence) = &capture.gateway_evidence {
            let mut record = evidence.clone();
            record["capture_id"] = json!(capture.capture_id);
            gateway_evidence_records.push(record);
            let mut verified = 0_u64;
            collect_gateway_model_evidence(
                capture,
                evidence,
                &mut gateway_requested_models,
                &mut gateway_upstream_models,
                &mut gateway_providers,
                &mut model_mapping_chains,
                &mut model_evidence_conflicts,
                &mut verified,
            );
            if capture.record_type == "api_snapshot" {
                proxy_route_evidence_count = proxy_route_evidence_count.saturating_add(verified);
            }
        }
        if let Some(event) = &capture.rollout_event {
            rollout_events.push(event.clone());
            if capture.rollout_unknown {
                rollout_unknown_events.insert(capture.capture_id.clone());
            }
            if capture.rollout_unmapped_tool {
                rollout_unmapped_tools.insert(capture.capture_id.clone());
            }
        }
        if let Some(rollout_usage) = &capture.rollout_usage {
            rollout_usage_evidence.push(json!({
                "capture_id":capture.capture_id,
                "usage":rollout_usage,
            }));
        }
        lifecycle.extend(capture.lifecycle_events.clone());
        lifecycle_event_records.extend(capture.lifecycle_event_records.clone());
        evaluation_evidence.extend(capture.evaluation_evidence.clone());
        if capture.record_type == "api_snapshot" {
            providers.insert(capture.provider.clone());
            if capture
                .provider_evidence
                .get("attested")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                provider_attested_api_snapshots = provider_attested_api_snapshots.saturating_add(1);
            }
        }
        provider_evidence.push(capture.provider_evidence.clone());
        if let Some(model) = &capture.model {
            request_models.insert(model.clone());
        }
        if let Some(model) = &capture.response_model {
            response_models.insert(model.clone());
        }
        if let Some(response_id) = &capture.response_id {
            response_ids.push(response_id.clone());
        }
        for (key, value) in &capture.trace_context {
            if !value.is_null() {
                if matches!(key.as_str(), "session_id" | "thread_id") {
                    if let Some(value) = value.as_str().filter(|value| !value.trim().is_empty()) {
                        if key == "session_id" {
                            trace_session_ids.insert(value.to_owned());
                        } else {
                            trace_thread_ids.insert(value.to_owned());
                        }
                    }
                    continue;
                }
                if matches!(
                    key.as_str(),
                    "turn_id" | "root_turn_id" | "span_id" | "parent_span_id"
                ) {
                    if let Some(value) = value.as_str()
                        && (key == "turn_id" || key == "root_turn_id")
                    {
                        turn_ids.insert(value.to_owned());
                    } else if let Some(value) = value.as_str() {
                        if key == "span_id" {
                            span_ids.insert(value.to_owned());
                        } else {
                            parent_span_ids.insert(value.to_owned());
                        }
                    }
                    continue;
                }
                if key == "previous_response_id" {
                    if let Some(value) = value.as_str() {
                        previous_response_ids.insert(value.to_owned());
                    }
                    continue;
                }
                if trace.get(key).is_some_and(|existing| existing != value) {
                    trace_conflicts.insert(key.clone());
                } else {
                    trace.entry(key.clone()).or_insert_with(|| value.clone());
                }
            }
        }
        if capture.system_prompt.is_some() {
            system_prompt = capture.system_prompt.clone();
        }
        if let Some(prompt) = &capture.system_prompt {
            system_prompt_variants.insert(prompt.clone());
        }
        let mut capture_task_prompts = BTreeSet::new();
        for evidence in &capture.system_prompt_sources {
            if let Some(prompt) = evidence.get("content").and_then(Value::as_str) {
                system_prompt_variants.insert(prompt.to_owned());
                if system_prompt_source_is_task_scoped(evidence) {
                    capture_task_prompts.insert(prompt.to_owned());
                }
            }
        }
        if capture_task_prompts.len() > 1 {
            system_prompt_conflicts.insert(format!(
                "{}:multiple_task_scoped_prompts",
                capture.capture_id
            ));
        }
        task_scoped_system_prompts.extend(capture_task_prompts);
        if capture
            .system_prompt_sources
            .iter()
            .any(|evidence| evidence.get("conflict").and_then(Value::as_bool) == Some(true))
        {
            system_prompt_conflicts.insert(capture.capture_id.clone());
        }
        system_prompt_evidence.extend(capture.system_prompt_sources.clone());
    }
    let (tool_executions, tool_execution_conflicts) = reconcile_tool_executions(&parsed);
    let (producer_streams, producer_event_conflicts) = audit_producer_streams(&parsed);
    let (usage, usage_evidence, usage_settlement_evidence, usage_conflicts) =
        reconcile_session_usage(&parsed);
    if task_scoped_system_prompts.len() > 1 {
        system_prompt_conflicts.insert("across_task_scoped_captures".to_owned());
    }
    let mut prompt_evidence_fingerprints = BTreeSet::new();
    system_prompt_evidence.retain(|evidence| {
        prompt_evidence_fingerprints.insert(serde_json::to_vec(evidence).unwrap_or_default())
    });
    lifecycle.sort();
    lifecycle.dedup();
    let mut lifecycle_record_fingerprints = BTreeSet::new();
    lifecycle_event_records.retain(|event| {
        lifecycle_record_fingerprints.insert(serde_json::to_vec(event).unwrap_or_default())
    });
    let mut evidence_fingerprints = BTreeSet::new();
    evaluation_evidence.retain(|evidence| {
        evidence_fingerprints.insert(serde_json::to_vec(evidence).unwrap_or_default())
    });
    let mut field_evidence_fingerprints = BTreeSet::new();
    field_evidence.retain(|evidence| {
        field_evidence_fingerprints.insert(serde_json::to_vec(evidence).unwrap_or_default())
    });
    let mut gateway_evidence_fingerprints = BTreeSet::new();
    gateway_evidence_records.retain(|evidence| {
        gateway_evidence_fingerprints.insert(serde_json::to_vec(evidence).unwrap_or_default())
    });
    let mut provider_evidence_fingerprints = BTreeSet::new();
    provider_evidence.retain(|evidence| {
        provider_evidence_fingerprints.insert(serde_json::to_vec(evidence).unwrap_or_default())
    });
    let model = gateway_upstream_models
        .iter()
        .next()
        .cloned()
        .or_else(|| response_models.iter().next().cloned())
        .or_else(|| gateway_requested_models.iter().next().cloned())
        .or_else(|| request_models.iter().next().cloned())
        .unwrap_or_else(|| "unknown".to_owned());
    let provider = gateway_providers
        .iter()
        .next()
        .cloned()
        .or_else(|| providers.iter().next().cloned())
        .unwrap_or_else(|| "unknown".to_owned());
    let effective_models = if gateway_upstream_models.is_empty() {
        response_models.clone()
    } else {
        gateway_upstream_models.clone()
    };
    let api_snapshot_count = parsed
        .iter()
        .filter(|capture| capture.record_type == "api_snapshot")
        .count() as u64;
    let model_attestation_candidate_count = parsed
        .iter()
        .filter(|capture| model_attestation_applicable(capture))
        .count() as u64;
    let non_attestable_api_snapshots: Vec<Value> = parsed
        .iter()
        .filter(|capture| {
            capture.record_type == "api_snapshot" && !model_attestation_applicable(capture)
        })
        .map(|capture| {
            json!({
                "capture_id":capture.capture_id,
                "response_status":capture.response_status,
                "reason":"no successful/model-bearing response or exact gateway evidence",
            })
        })
        .collect();
    let request_response_consistent_without_gateway = !gateway_evidence_records.is_empty()
        || (request_models.len() <= 1
            && request_models.iter().all(|candidate| {
                effective_models.is_empty()
                    || effective_models
                        .iter()
                        .any(|effective| effective.eq_ignore_ascii_case(candidate))
            }));
    let model_evidence_consistent = model_evidence_conflicts.is_empty()
        && effective_models.len() <= 1
        && gateway_providers.len() <= 1
        && providers.len() <= 1
        && request_response_consistent_without_gateway
        && effective_models
            .iter()
            .all(|candidate| candidate.eq_ignore_ascii_case(&model))
        && response_models.iter().all(|candidate| {
            effective_models.is_empty()
                || effective_models
                    .iter()
                    .any(|effective| effective.eq_ignore_ascii_case(candidate))
        });
    // A model name and a provider family inferred from a path or model string
    // are useful diagnostics, but they are not an identity attestation. Only
    // an explicit proxy/upstream/runtime observation (or an exact gateway
    // usage-log join) can satisfy the strict buyer profile.
    let provider_identity_attested = model_attestation_candidate_count > 0
        && model_evidence_consistent
        && (provider_attested_api_snapshots == model_attestation_candidate_count
            || proxy_route_evidence_count == model_attestation_candidate_count);
    let proxy_route_verified = model_attestation_candidate_count > 0
        && proxy_route_evidence_count == model_attestation_candidate_count
        && model_evidence_consistent;
    let provider_candidates = providers.clone();
    let provider_observations = if gateway_providers.is_empty() {
        providers.clone()
    } else {
        gateway_providers.clone()
    };
    let final_snapshot = parsed.iter().any(|capture| capture.final_snapshot);
    let status = if final_snapshot {
        terminal_session_status(&parsed)
    } else {
        "incomplete".to_owned()
    };
    let system_prompt = system_prompt
        .or_else(|| {
            messages
                .iter()
                .find(|message| string_field(message, "role") == Some("system"))
                .and_then(|message| content_text(message.get("content")))
        })
        .unwrap_or_default();
    if !system_prompt.is_empty() {
        messages.insert(0, json!({"role": "system", "content": system_prompt}));
    }
    let trajectory_id = format!(
        "traj-{}",
        hex::encode(Sha256::digest(
            format!("{source_namespace}\0{session_identity}").as_bytes()
        ))
    );
    let created_at = parsed
        .first()
        .map(|capture| capture.timestamp.clone())
        .unwrap();
    let ended_at = final_snapshot
        .then(|| parsed.last().map(|capture| capture.timestamp.clone()))
        .flatten();
    let tools: Vec<Value> = tools_by_name.into_values().collect();
    let code_mode_message_projection =
        exclude_code_mode_parent_messages(&mut messages, &code_mode_parent_call_ids);
    let (schema_conflicts, uncalled_schema_conflicts) =
        partition_schema_conflicts(&messages, &schema_conflicts);
    annotate_tool_call_statuses(&mut messages);
    let capture_dag = build_capture_dag(&parsed, &messages);
    let runtime_dag = build_runtime_dag(&parsed);
    let inference_api_conservation = build_inference_api_conservation(&parsed);
    insert_scoped_trace_values(&mut trace, "session_id", "session_ids", &trace_session_ids);
    insert_scoped_trace_values(&mut trace, "thread_id", "thread_ids", &trace_thread_ids);
    if turn_ids.len() == 1 {
        trace.insert(
            "turn_id".to_owned(),
            Value::String(turn_ids.iter().next().cloned().unwrap_or_default()),
        );
    } else if !turn_ids.is_empty() {
        trace.insert("turn_ids".to_owned(), json!(turn_ids));
    }
    if previous_response_ids.len() == 1 {
        trace.insert(
            "previous_response_id".to_owned(),
            Value::String(
                previous_response_ids
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_default(),
            ),
        );
    } else if !previous_response_ids.is_empty() {
        trace.insert(
            "previous_response_ids".to_owned(),
            json!(previous_response_ids),
        );
    }
    if !span_ids.is_empty() {
        trace.insert("span_ids".to_owned(), json!(span_ids));
    }
    if !parent_span_ids.is_empty() {
        trace.insert("parent_span_ids".to_owned(), json!(parent_span_ids));
    }
    let trace_contexts: Vec<Value> = parsed
        .iter()
        .map(|capture| {
            json!({
                "capture_id": capture.capture_id.clone(),
                "record_type": capture.record_type.clone(),
                "context": capture.trace_context.clone(),
            })
        })
        .collect();
    let mut meta = Map::new();
    meta.insert(
        "source_capture_ids".to_owned(),
        Value::Array(
            parsed
                .iter()
                .map(|capture| Value::String(capture.capture_id.clone()))
                .collect(),
        ),
    );
    meta.insert(
        "source_request_ids".to_owned(),
        Value::Array(
            parsed
                .iter()
                .filter_map(|capture| capture.upstream_request_id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    meta.insert(
        "source_client_request_ids".to_owned(),
        Value::Array(
            parsed
                .iter()
                .filter_map(|capture| capture.request_id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    meta.insert("response_ids".to_owned(), json!(response_ids));
    meta.insert("session_identity_source".to_owned(), json!(identity_source));
    meta.insert("source_namespace".to_owned(), json!(source_namespace));
    meta.insert("trace_contexts".to_owned(), json!(trace_contexts));
    meta.insert("capture_dag".to_owned(), capture_dag);
    meta.insert("runtime_dag".to_owned(), runtime_dag);
    meta.insert(
        "inference_api_conservation".to_owned(),
        inference_api_conservation,
    );
    meta.insert("lifecycle_events".to_owned(), json!(lifecycle));
    meta.insert(
        "lifecycle_event_records".to_owned(),
        json!(lifecycle_event_records),
    );
    meta.insert("turn_ids".to_owned(), json!(turn_ids));
    meta.insert(
        "previous_response_ids".to_owned(),
        json!(previous_response_ids),
    );
    meta.insert("tool_executions".to_owned(), json!(tool_executions));
    meta.insert(
        "tool_execution_conflicts".to_owned(),
        json!(tool_execution_conflicts),
    );
    meta.insert("producer_streams".to_owned(), json!(producer_streams));
    meta.insert(
        "producer_event_conflicts".to_owned(),
        json!(producer_event_conflicts),
    );
    meta.insert(
        "tool_registry_evidence".to_owned(),
        json!(tool_registry_evidence),
    );
    meta.insert("field_evidence".to_owned(), json!(field_evidence));
    meta.insert("protocol_conflicts".to_owned(), json!(protocol_conflicts));
    meta.insert(
        "system_prompt_evidence".to_owned(),
        json!(system_prompt_evidence),
    );
    meta.insert(
        "system_prompt_conflicts".to_owned(),
        json!(system_prompt_conflicts),
    );
    meta.insert(
        "system_prompt_variants".to_owned(),
        json!(system_prompt_variants),
    );
    meta.insert(
        "evaluation_evidence".to_owned(),
        Value::Array(evaluation_evidence),
    );
    meta.insert("schema_conflicts".to_owned(), json!(schema_conflicts));
    meta.insert(
        "observed_schema_conflicts".to_owned(),
        json!(
            schema_conflicts
                .union(&uncalled_schema_conflicts)
                .cloned()
                .collect::<BTreeSet<_>>()
        ),
    );
    meta.insert(
        "uncalled_schema_conflicts".to_owned(),
        json!(uncalled_schema_conflicts),
    );
    meta.insert("trace_conflicts".to_owned(), json!(trace_conflicts));
    meta.insert("usage_evidence".to_owned(), json!(usage_evidence));
    meta.insert(
        "usage_settlement_evidence".to_owned(),
        json!(usage_settlement_evidence),
    );
    meta.insert("usage_conflicts".to_owned(), json!(usage_conflicts));
    meta.insert("rollout_events".to_owned(), json!(rollout_events));
    meta.insert(
        "rollout_usage_evidence".to_owned(),
        json!(rollout_usage_evidence),
    );
    meta.insert(
        "rollout_unknown_events".to_owned(),
        json!(rollout_unknown_events),
    );
    meta.insert(
        "rollout_unmapped_tools".to_owned(),
        json!(rollout_unmapped_tools),
    );
    meta.insert(
        "code_mode_message_projection".to_owned(),
        code_mode_message_projection,
    );
    meta.insert("merge_divergences".to_owned(), json!(divergences));
    meta.insert(
        "model_evidence".to_owned(),
        json!({
            "request_models": request_models,
            "response_models": response_models,
            "gateway_requested_models": gateway_requested_models,
            "gateway_upstream_models": gateway_upstream_models,
            "effective_models": effective_models,
            "providers": provider_observations,
            "provider_candidates": provider_candidates,
            "gateway_providers": gateway_providers,
            "model_mapping_chains": model_mapping_chains,
            "gateway_evidence": gateway_evidence_records,
            "provider_evidence": provider_evidence,
            "provider_identity_attested": provider_identity_attested,
            "conflicts": model_evidence_conflicts,
            "consistent": model_evidence_consistent,
            "proxy_route_verified": proxy_route_verified,
            "api_snapshot_count": api_snapshot_count,
            "attestation_candidate_count": model_attestation_candidate_count,
            "non_attestable_api_snapshots": non_attestable_api_snapshots,
            "attested": false,
            "scope": if proxy_route_verified {
                "sub2api route evidence linked by upstream request ID plus provider-reported response model; not cryptographic provider attestation"
            } else {
                "captured request/response consistency only; provider identity is not attested"
            },
        }),
    );
    meta.insert("trace".to_owned(), Value::Object(trace));
    let session = json!({
        "schema_version": SESSION_SCHEMA_VERSION,
        "trajectory_id": trajectory_id,
        "session_id": session_identity,
        "dataset": "chiptrace",
        "provider": provider,
        "model": model,
        "created_at": created_at,
        "ended_at": ended_at,
        "status": status,
        "is_final_snapshot": final_snapshot,
        "source_request_count": parsed.iter().filter(|capture| capture.record_type == "api_snapshot").count(),
        "source_capture_count": parsed.len(),
        "system_prompt": system_prompt,
        "tools": tools,
        "messages": messages,
        "usage": {
            "input_tokens": usage.input_tokens,
            "cached_input_tokens": usage.cached_input_tokens,
            "cache_creation_input_tokens": usage.cache_creation_input_tokens,
            "output_tokens": usage.output_tokens,
            "reasoning_tokens": usage.reasoning_tokens,
            "total_tokens": usage.total_tokens,
        },
        "meta": meta,
    });
    Ok((session, orphan, divergences))
}

fn compare_capture_order(left: &ParsedCapture, right: &ParsedCapture) -> std::cmp::Ordering {
    let time_order = match (left.timestamp_unix_nanos, right.timestamp_unix_nanos) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => left.timestamp.cmp(&right.timestamp),
    };
    if !time_order.is_eq() {
        return time_order;
    }

    match (
        native_source_order(left.rollout_event.as_ref()),
        native_source_order(right.rollout_event.as_ref()),
    ) {
        (Some((left_trace, left_ordinal)), Some((right_trace, right_ordinal)))
            if left_trace == right_trace =>
        {
            left_ordinal
                .cmp(&right_ordinal)
                .then(left.capture_id.cmp(&right.capture_id))
        }
        _ => left.capture_id.cmp(&right.capture_id),
    }
}

fn native_source_order(event: Option<&Value>) -> Option<(&str, u64)> {
    let event = event?;
    if string_field(event, "source") != Some("codex_rollout_trace_bundle") {
        return None;
    }
    Some((
        string_field(event, "bundle_trace_id")?,
        event.get("source_ordinal")?.as_u64()?,
    ))
}

fn native_code_mode_parent_call_ids(captures: &[ParsedCapture]) -> BTreeSet<String> {
    captures
        .iter()
        .filter_map(|capture| capture.rollout_event.as_ref())
        .filter(|event| string_field(event, "source") == Some("codex_rollout_trace_bundle"))
        .filter_map(|event| string_field(event, "source_line"))
        .filter_map(|source_line| serde_json::from_str::<Value>(source_line).ok())
        .filter_map(|event| {
            let payload = event.get("payload")?;
            (string_field(payload, "type") == Some("code_cell_started"))
                .then(|| string_field(payload, "model_visible_call_id"))
                .flatten()
                .map(str::to_owned)
        })
        .collect()
}

fn exclude_code_mode_parent_messages(
    messages: &mut Vec<Value>,
    parent_call_ids: &BTreeSet<String>,
) -> Value {
    let mut excluded_tool_calls = 0_u64;
    let mut excluded_tool_results = 0_u64;
    let mut excluded_empty_messages = 0_u64;
    let mut projected = Vec::with_capacity(messages.len());

    for mut message in messages.drain(..) {
        let role = string_field(&message, "role").unwrap_or("");
        if role == "tool"
            && string_field(&message, "tool_call_id")
                .is_some_and(|call_id| parent_call_ids.contains(call_id))
        {
            excluded_tool_results = excluded_tool_results.saturating_add(1);
            continue;
        }

        let mut removed_from_message = 0_u64;
        if role == "assistant"
            && let Some(object) = message.as_object_mut()
            && let Some(calls) = object.get_mut("tool_calls").and_then(Value::as_array_mut)
        {
            let before = calls.len();
            calls.retain(|call| {
                !string_field(call, "id").is_some_and(|call_id| parent_call_ids.contains(call_id))
            });
            removed_from_message = before.saturating_sub(calls.len()) as u64;
            excluded_tool_calls = excluded_tool_calls.saturating_add(removed_from_message);
            if calls.is_empty() {
                object.remove("tool_calls");
            }
        }

        let became_empty_parent_call = removed_from_message > 0
            && message.get("content").is_none_or(value_empty)
            && message.get("reasoning").is_none_or(value_empty)
            && message.get("thinking").is_none_or(value_empty)
            && message.get("tool_calls").is_none();
        if became_empty_parent_call {
            excluded_empty_messages = excluded_empty_messages.saturating_add(1);
        } else {
            projected.push(message);
        }
    }
    *messages = projected;

    json!({
        "schema_version":"chiptrace.code-mode-message-projection.v1",
        "evidence":"codex_rollout_trace_bundle.code_cell_started.model_visible_call_id",
        "excluded_parent_call_ids":parent_call_ids,
        "excluded_tool_calls":excluded_tool_calls,
        "excluded_tool_results":excluded_tool_results,
        "excluded_empty_messages":excluded_empty_messages,
        "raw_runtime_events_retained":true,
    })
}

fn partition_schema_conflicts(
    messages: &[Value],
    observed: &BTreeSet<String>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let called: BTreeSet<String> = messages
        .iter()
        .filter_map(|message| message.get("tool_calls").and_then(Value::as_array))
        .flatten()
        .filter_map(tool_name)
        .map(str::to_owned)
        .collect();
    observed
        .iter()
        .cloned()
        .partition(|name| called.contains(name))
}

fn insert_scoped_trace_values(
    trace: &mut Map<String, Value>,
    singular: &str,
    plural: &str,
    values: &BTreeSet<String>,
) {
    if values.is_empty() {
        return;
    }
    trace.insert(plural.to_owned(), json!(values));
    if values.len() == 1 {
        trace.insert(
            singular.to_owned(),
            Value::String(values.iter().next().cloned().unwrap_or_default()),
        );
    } else {
        trace.remove(singular);
    }
}

fn build_inference_api_conservation(captures: &[ParsedCapture]) -> Value {
    let runtime: Vec<(String, BTreeSet<String>)> = captures
        .iter()
        .filter_map(|capture| {
            let event = capture.rollout_event.as_ref()?;
            if string_field(event, "source") != Some("codex_rollout_trace_bundle") {
                return None;
            }
            let raw: Value = serde_json::from_str(string_field(event, "source_line")?).ok()?;
            let payload = raw.get("payload")?;
            if string_field(payload, "type") != Some("inference_completed") {
                return None;
            }
            Some((
                capture.capture_id.clone(),
                inference_correlation_keys(payload),
            ))
        })
        .collect();
    let api: Vec<(String, BTreeSet<String>)> = captures
        .iter()
        .filter(|capture| capture.record_type == "api_snapshot")
        .map(|capture| {
            let mut keys = BTreeSet::new();
            if let Some(value) = capture.upstream_request_id.as_deref() {
                keys.insert(format!("upstream_request_id:{value}"));
            }
            if let Some(value) = capture.response_id.as_deref() {
                keys.insert(format!("response_id:{value}"));
            }
            (capture.capture_id.clone(), keys)
        })
        .collect();
    let runtime_keys: BTreeSet<String> = runtime
        .iter()
        .flat_map(|(_, keys)| keys.iter().cloned())
        .collect();
    let api_keys: BTreeSet<String> = api
        .iter()
        .flat_map(|(_, keys)| keys.iter().cloned())
        .collect();
    let runtime_without_correlation: Vec<String> = runtime
        .iter()
        .filter(|(_, keys)| keys.is_empty())
        .map(|(capture_id, _)| capture_id.clone())
        .collect();
    let api_without_correlation: Vec<String> = api
        .iter()
        .filter(|(_, keys)| keys.is_empty())
        .map(|(capture_id, _)| capture_id.clone())
        .collect();
    let missing_api_capture_keys: BTreeSet<String> = runtime
        .iter()
        .filter(|(_, keys)| !keys.is_empty() && keys.is_disjoint(&api_keys))
        .filter_map(|(_, keys)| preferred_correlation_key(keys))
        .collect();
    let extra_api_capture_keys: BTreeSet<String> = api
        .iter()
        .filter(|(_, keys)| !keys.is_empty() && keys.is_disjoint(&runtime_keys))
        .filter_map(|(_, keys)| preferred_correlation_key(keys))
        .collect();
    let matched_runtime_inferences = runtime
        .iter()
        .filter(|(_, keys)| !keys.is_empty() && !keys.is_disjoint(&api_keys))
        .count() as u64;
    let mut runtime_key_counts = BTreeMap::new();
    for (_, keys) in &runtime {
        if let Some(key) = preferred_correlation_key(keys) {
            *runtime_key_counts.entry(key).or_insert(0_u64) += 1;
        }
    }
    let duplicate_runtime_keys: BTreeSet<String> = runtime_key_counts
        .into_iter()
        .filter_map(|(key, count)| (count > 1).then_some(key))
        .collect();
    let applicable = !runtime.is_empty();
    let complete = !applicable
        || (runtime_without_correlation.is_empty()
            && missing_api_capture_keys.is_empty()
            && duplicate_runtime_keys.is_empty());
    let coverage = if runtime.is_empty() {
        1.0
    } else {
        matched_runtime_inferences as f64 / runtime.len() as f64
    };
    json!({
        "schema_version":"chiptrace.inference-api-conservation.v1",
        "matching_policy":"exact upstream_request_id, then exact response_id; no time/model/thread inference",
        "applicable":applicable,
        "complete":complete,
        "runtime_completed_inferences":runtime.len(),
        "runtime_correlatable_inferences":runtime.iter().filter(|(_, keys)| !keys.is_empty()).count(),
        "api_snapshots":api.len(),
        "api_correlatable_snapshots":api.iter().filter(|(_, keys)| !keys.is_empty()).count(),
        "matched_runtime_inferences":matched_runtime_inferences,
        "coverage":coverage,
        "missing_api_capture_keys":missing_api_capture_keys,
        "runtime_without_correlation_capture_ids":runtime_without_correlation,
        "duplicate_runtime_keys":duplicate_runtime_keys,
        "extra_api_capture_keys":extra_api_capture_keys,
        "api_without_correlation_capture_ids":api_without_correlation,
    })
}

fn inference_correlation_keys(payload: &Value) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    if let Some(value) = string_field(payload, "upstream_request_id") {
        keys.insert(format!("upstream_request_id:{value}"));
    }
    if let Some(value) = string_field(payload, "response_id") {
        keys.insert(format!("response_id:{value}"));
    }
    keys
}

fn preferred_correlation_key(keys: &BTreeSet<String>) -> Option<String> {
    keys.iter()
        .find(|key| key.starts_with("upstream_request_id:"))
        .or_else(|| keys.iter().next())
        .cloned()
}

fn build_runtime_dag(captures: &[ParsedCapture]) -> Value {
    let mut nodes: BTreeMap<String, Value> = BTreeMap::new();
    let mut edges: BTreeMap<String, Value> = BTreeMap::new();
    let mut open_nodes = BTreeSet::new();
    let mut status_conflict_nodes = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut native_events = 0_u64;
    let mut terminal_rollouts = BTreeSet::new();
    let task_session_ids: BTreeSet<String> = captures
        .iter()
        .filter_map(|capture| {
            capture
                .trace_context
                .get("task_session_id")
                .and_then(Value::as_str)
        })
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .collect();
    let mut cells_by_runtime: HashMap<(String, String, String), String> = HashMap::new();

    for capture in captures {
        let Some(lineage) = capture.rollout_event.as_ref() else {
            continue;
        };
        if string_field(lineage, "source") != Some("codex_rollout_trace_bundle") {
            continue;
        }
        let Some(source_line) = string_field(lineage, "source_line") else {
            continue;
        };
        let Ok(raw) = serde_json::from_str::<Value>(source_line) else {
            continue;
        };
        let payload = raw.get("payload").unwrap_or(&Value::Null);
        let event_type = string_field(payload, "type").unwrap_or("");
        let trace_id = string_field(lineage, "bundle_trace_id").unwrap_or("missing-trace");
        let rollout_id = string_field(lineage, "source_session_id").unwrap_or("missing-rollout");
        let seq = lineage
            .get("source_ordinal")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let thread_id =
            string_field(&raw, "thread_id").or_else(|| string_field(payload, "thread_id"));
        let turn_id =
            string_field(&raw, "codex_turn_id").or_else(|| string_field(payload, "codex_turn_id"));
        let rollout_node = runtime_node_id(trace_id, "rollout", rollout_id);
        native_events = native_events.saturating_add(1);

        match event_type {
            "rollout_started" => {
                let node =
                    upsert_runtime_node(&mut nodes, &rollout_node, "rollout", rollout_id, trace_id);
                node["status"] = json!("running");
                node["started_seq"] = json!(seq);
                open_nodes.insert(rollout_node.clone());
                roots.insert(rollout_node.clone());
            }
            "rollout_ended" => {
                let node =
                    upsert_runtime_node(&mut nodes, &rollout_node, "rollout", rollout_id, trace_id);
                let status = runtime_status(payload.get("status").and_then(Value::as_str));
                node["status"] = json!(status);
                node["ended_seq"] = json!(seq);
                open_nodes.remove(&rollout_node);
                if status != "incomplete" {
                    terminal_rollouts.insert(rollout_node.clone());
                }
            }
            "thread_started" => {
                let Some(thread_id) = thread_id else { continue };
                let id = runtime_node_id(trace_id, "thread", thread_id);
                let node = upsert_runtime_node(&mut nodes, &id, "thread", thread_id, trace_id);
                node["status"] = json!("running");
                node["started_seq"] = json!(seq);
                node["agent_path"] = lineage.get("agent_path").cloned().unwrap_or(Value::Null);
                node["thread_source"] =
                    lineage.get("thread_source").cloned().unwrap_or(Value::Null);
                open_nodes.insert(id.clone());
                let parent = string_field(lineage, "parent_agent_thread_id")
                    .map(|parent| runtime_node_id(trace_id, "thread", parent))
                    .unwrap_or_else(|| rollout_node.clone());
                insert_runtime_edge(&mut edges, &parent, &id, "contains");
            }
            "thread_ended" => {
                let Some(thread_id) = thread_id else { continue };
                let id = runtime_node_id(trace_id, "thread", thread_id);
                let node = upsert_runtime_node(&mut nodes, &id, "thread", thread_id, trace_id);
                node["status"] = json!(runtime_status(
                    payload.get("status").and_then(Value::as_str)
                ));
                node["ended_seq"] = json!(seq);
                open_nodes.remove(&id);
            }
            "codex_turn_started" => {
                let Some(turn_id) = turn_id else { continue };
                let id = runtime_node_id(trace_id, "turn", turn_id);
                let node = upsert_runtime_node(&mut nodes, &id, "turn", turn_id, trace_id);
                node["status"] = json!("running");
                node["started_seq"] = json!(seq);
                open_nodes.insert(id.clone());
                if let Some(thread_id) = thread_id {
                    insert_runtime_edge(
                        &mut edges,
                        &runtime_node_id(trace_id, "thread", thread_id),
                        &id,
                        "activates",
                    );
                }
            }
            "codex_turn_ended" => {
                let Some(turn_id) = turn_id else { continue };
                let id = runtime_node_id(trace_id, "turn", turn_id);
                let node = upsert_runtime_node(&mut nodes, &id, "turn", turn_id, trace_id);
                node["status"] = json!(runtime_status(
                    payload.get("status").and_then(Value::as_str)
                ));
                node["ended_seq"] = json!(seq);
                open_nodes.remove(&id);
            }
            "inference_started" => {
                let Some(inference_id) = string_field(payload, "inference_call_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "inference", inference_id);
                let node =
                    upsert_runtime_node(&mut nodes, &id, "inference", inference_id, trace_id);
                node["status"] = json!("running");
                node["started_seq"] = json!(seq);
                node["model"] = payload.get("model").cloned().unwrap_or(Value::Null);
                node["provider"] = payload.get("provider_name").cloned().unwrap_or(Value::Null);
                open_nodes.insert(id.clone());
                if let Some(turn_id) = turn_id {
                    insert_runtime_edge(
                        &mut edges,
                        &runtime_node_id(trace_id, "turn", turn_id),
                        &id,
                        "samples",
                    );
                }
            }
            "inference_completed" | "inference_failed" | "inference_cancelled" => {
                let Some(inference_id) = string_field(payload, "inference_call_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "inference", inference_id);
                let node =
                    upsert_runtime_node(&mut nodes, &id, "inference", inference_id, trace_id);
                let status = match event_type {
                    "inference_completed" => "completed",
                    "inference_failed" => "failed",
                    _ => "cancelled",
                };
                node["status"] = json!(status);
                node["ended_seq"] = json!(seq);
                node["response_id"] = payload.get("response_id").cloned().unwrap_or(Value::Null);
                node["upstream_request_id"] = payload
                    .get("upstream_request_id")
                    .cloned()
                    .unwrap_or(Value::Null);
                open_nodes.remove(&id);
            }
            "code_cell_started" => {
                let Some(runtime_cell_id) = string_field(payload, "runtime_cell_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "code_cell", runtime_cell_id);
                let node =
                    upsert_runtime_node(&mut nodes, &id, "code_cell", runtime_cell_id, trace_id);
                node["status"] = json!("running");
                node["started_seq"] = json!(seq);
                node["model_visible_call_id"] = payload
                    .get("model_visible_call_id")
                    .cloned()
                    .unwrap_or(Value::Null);
                open_nodes.insert(id.clone());
                if let Some(thread_id) = thread_id {
                    cells_by_runtime.insert(
                        (
                            trace_id.to_owned(),
                            thread_id.to_owned(),
                            runtime_cell_id.to_owned(),
                        ),
                        id.clone(),
                    );
                }
                if let Some(turn_id) = turn_id {
                    insert_runtime_edge(
                        &mut edges,
                        &runtime_node_id(trace_id, "turn", turn_id),
                        &id,
                        "executes_code",
                    );
                }
            }
            "code_cell_initial_response" => {
                let Some(runtime_cell_id) = string_field(payload, "runtime_cell_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "code_cell", runtime_cell_id);
                let node =
                    upsert_runtime_node(&mut nodes, &id, "code_cell", runtime_cell_id, trace_id);
                node["initial_status"] = payload.get("status").cloned().unwrap_or(Value::Null);
                node["initial_response_seq"] = json!(seq);
            }
            "code_cell_ended" => {
                let Some(runtime_cell_id) = string_field(payload, "runtime_cell_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "code_cell", runtime_cell_id);
                let node =
                    upsert_runtime_node(&mut nodes, &id, "code_cell", runtime_cell_id, trace_id);
                node["status"] = payload
                    .get("status")
                    .cloned()
                    .unwrap_or_else(|| json!("incomplete"));
                node["ended_seq"] = json!(seq);
                open_nodes.remove(&id);
            }
            "tool_call_started" => {
                let Some(tool_id) = string_field(payload, "tool_call_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "tool", tool_id);
                let node = upsert_runtime_node(&mut nodes, &id, "tool", tool_id, trace_id);
                node["status"] = json!("running");
                node["started_seq"] = json!(seq);
                node["kind"] = payload.get("kind").cloned().unwrap_or(Value::Null);
                node["requester"] = payload.get("requester").cloned().unwrap_or(Value::Null);
                node["model_visible_call_id"] = payload
                    .get("model_visible_call_id")
                    .cloned()
                    .unwrap_or(Value::Null);
                node["code_mode_runtime_tool_id"] = payload
                    .get("code_mode_runtime_tool_id")
                    .cloned()
                    .unwrap_or(Value::Null);
                open_nodes.insert(id.clone());
                let code_cell_parent = payload
                    .pointer("/requester/runtime_cell_id")
                    .and_then(Value::as_str)
                    .and_then(|cell_id| {
                        thread_id.and_then(|thread_id| {
                            cells_by_runtime
                                .get(&(
                                    trace_id.to_owned(),
                                    thread_id.to_owned(),
                                    cell_id.to_owned(),
                                ))
                                .cloned()
                        })
                    });
                if let Some(parent) = code_cell_parent {
                    insert_runtime_edge(&mut edges, &parent, &id, "nested_tool");
                } else if let Some(turn_id) = turn_id {
                    insert_runtime_edge(
                        &mut edges,
                        &runtime_node_id(trace_id, "turn", turn_id),
                        &id,
                        "dispatches_tool",
                    );
                }
            }
            "tool_call_runtime_started" | "tool_call_runtime_ended" => {
                let Some(tool_id) = string_field(payload, "tool_call_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "tool", tool_id);
                let node = upsert_runtime_node(&mut nodes, &id, "tool", tool_id, trace_id);
                let observed = if event_type == "tool_call_runtime_started" {
                    "running"
                } else {
                    runtime_status(payload.get("status").and_then(Value::as_str))
                };
                if event_type == "tool_call_runtime_ended" {
                    let dispatch_claims_outcome = node
                        .get("dispatch_status_claims_outcome")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if observed == "incomplete"
                        || string_field(node, "dispatch_status").is_some_and(|dispatch| {
                            dispatch_claims_outcome
                                && runtime_status_is_terminal(dispatch)
                                && dispatch != observed
                        })
                    {
                        status_conflict_nodes.insert(id.clone());
                    }
                    node["runtime_ended_seq"] = json!(seq);
                    if runtime_status_is_terminal(observed) {
                        node["status"] = json!(observed);
                    }
                }
                node["runtime_status"] = json!(observed);
                node["last_runtime_seq"] = json!(seq);
            }
            "tool_call_ended" => {
                let Some(tool_id) = string_field(payload, "tool_call_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "tool", tool_id);
                let node = upsert_runtime_node(&mut nodes, &id, "tool", tool_id, trace_id);
                let dispatch_raw = payload.get("status").and_then(Value::as_str);
                let dispatch_status = runtime_status(dispatch_raw);
                let dispatch_claims_outcome = dispatch_raw.is_some_and(|status| {
                    !matches!(
                        status.trim().to_ascii_lowercase().as_str(),
                        "completed" | "complete"
                    )
                });
                if dispatch_status == "incomplete"
                    || string_field(node, "runtime_status").is_some_and(|runtime| {
                        dispatch_claims_outcome
                            && runtime_status_is_terminal(runtime)
                            && runtime != dispatch_status
                    })
                {
                    status_conflict_nodes.insert(id.clone());
                }
                node["dispatch_status"] = json!(dispatch_status);
                node["dispatch_status_claims_outcome"] = json!(dispatch_claims_outcome);
                node["status"] = json!(
                    string_field(node, "runtime_status")
                        .filter(|status| runtime_status_is_terminal(status))
                        .unwrap_or(dispatch_status)
                );
                node["ended_seq"] = json!(seq);
                open_nodes.remove(&id);
            }
            "compaction_request_started" => {
                let Some(request_id) = string_field(payload, "compaction_request_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "compaction", request_id);
                let node = upsert_runtime_node(&mut nodes, &id, "compaction", request_id, trace_id);
                node["status"] = json!("running");
                node["started_seq"] = json!(seq);
                open_nodes.insert(id.clone());
                if let Some(turn_id) = turn_id {
                    insert_runtime_edge(
                        &mut edges,
                        &runtime_node_id(trace_id, "turn", turn_id),
                        &id,
                        "compacts",
                    );
                }
            }
            "compaction_request_completed" | "compaction_request_failed" => {
                let Some(request_id) = string_field(payload, "compaction_request_id") else {
                    continue;
                };
                let id = runtime_node_id(trace_id, "compaction", request_id);
                let node = upsert_runtime_node(&mut nodes, &id, "compaction", request_id, trace_id);
                node["status"] = json!(if event_type.ends_with("failed") {
                    "failed"
                } else {
                    "completed"
                });
                node["ended_seq"] = json!(seq);
                open_nodes.remove(&id);
            }
            "agent_result_observed" => {
                if let (Some(child), Some(parent)) = (
                    string_field(payload, "child_thread_id"),
                    string_field(payload, "parent_thread_id"),
                ) {
                    insert_runtime_edge(
                        &mut edges,
                        &runtime_node_id(trace_id, "thread", child),
                        &runtime_node_id(trace_id, "thread", parent),
                        "agent_result",
                    );
                }
            }
            _ => {}
        }
    }

    let node_ids: BTreeSet<String> = nodes.keys().cloned().collect();
    let mut unresolved = BTreeSet::new();
    for edge in edges.values() {
        for field in ["from", "to"] {
            if let Some(node) = string_field(edge, field)
                && !node_ids.contains(node)
            {
                unresolved.insert(node.to_owned());
            }
        }
    }
    let mut disposition_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut kind_counts: BTreeMap<String, u64> = BTreeMap::new();
    for (id, node) in &mut nodes {
        let status = string_field(node, "status").unwrap_or("incomplete");
        let started_seq = node.get("started_seq").and_then(Value::as_u64);
        let ended_seq = node.get("ended_seq").and_then(Value::as_u64);
        if started_seq.is_none()
            || status == "incomplete"
            || (status != "running" && ended_seq.is_none())
            || started_seq
                .zip(ended_seq)
                .is_some_and(|(start, end)| end < start)
        {
            unresolved.insert(id.clone());
        }
        let disposition = if open_nodes.contains(id) || status == "running" {
            "open_tail"
        } else if matches!(status, "cancelled" | "aborted" | "terminated") {
            "abandoned"
        } else {
            "executed"
        };
        node["disposition"] = json!(disposition);
        *disposition_counts
            .entry(disposition.to_owned())
            .or_insert(0) += 1;
        let kind = string_field(node, "node_type").unwrap_or("unknown");
        *kind_counts.entry(kind.to_owned()).or_insert(0) += 1;
    }
    let task_binds_all_roots = roots.len() <= 1 || task_session_ids.len() == 1;
    let complete = native_events > 0
        && !roots.is_empty()
        && task_binds_all_roots
        && terminal_rollouts == roots
        && open_nodes.is_empty()
        && unresolved.is_empty()
        && status_conflict_nodes.is_empty();
    json!({
        "schema_version":"chiptrace.runtime-dag.v1",
        "source":"codex_rollout_trace_bundle",
        "native_event_count":native_events,
        "nodes":nodes.into_values().collect::<Vec<_>>(),
        "edges":edges.into_values().collect::<Vec<_>>(),
        "roots":roots,
        "root_mode":if roots.len() > 1 { "task_scoped_rollout_forest" } else { "single_rollout" },
        "task_session_ids":task_session_ids,
        "open_node_ids":open_nodes,
        "unresolved_node_ids":unresolved,
        "status_conflict_node_ids":status_conflict_nodes,
        "terminal_rollout_ids":terminal_rollouts,
        "kind_counts":kind_counts,
        "disposition_counts":disposition_counts,
        "complete":complete,
        "applicable":native_events > 0,
    })
}

fn runtime_node_id(trace_id: &str, kind: &str, id: &str) -> String {
    format!("{trace_id}:{kind}:{id}")
}

fn upsert_runtime_node<'a>(
    nodes: &'a mut BTreeMap<String, Value>,
    node_id: &str,
    kind: &str,
    source_id: &str,
    trace_id: &str,
) -> &'a mut Value {
    nodes.entry(node_id.to_owned()).or_insert_with(|| {
        json!({
            "node_id":node_id,
            "node_type":kind,
            "source_id":source_id,
            "trace_id":trace_id,
            "status":"incomplete",
            "disposition":"open_tail",
        })
    })
}

fn insert_runtime_edge(edges: &mut BTreeMap<String, Value>, from: &str, to: &str, kind: &str) {
    edges
        .entry(format!("{from}\0{to}\0{kind}"))
        .or_insert_with(|| {
            json!({
                "from":from,
                "to":to,
                "kind":kind,
            })
        });
}

fn runtime_status(value: Option<&str>) -> &'static str {
    match value.map(|value| value.trim().to_ascii_lowercase()) {
        Some(value) if matches!(value.as_str(), "completed" | "complete" | "success" | "ok") => {
            "completed"
        }
        Some(value) if matches!(value.as_str(), "failed" | "failure" | "error") => "failed",
        Some(value) if matches!(value.as_str(), "cancelled" | "canceled") => "cancelled",
        Some(value) if value == "aborted" => "aborted",
        Some(value) if value == "terminated" => "terminated",
        Some(value) if matches!(value.as_str(), "timeout" | "timed_out") => "timeout",
        Some(value) if value == "running" => "running",
        _ => "incomplete",
    }
}

fn runtime_status_is_terminal(value: &str) -> bool {
    matches!(
        value,
        "completed" | "failed" | "cancelled" | "aborted" | "terminated" | "timeout"
    )
}

fn build_capture_dag(captures: &[ParsedCapture], messages: &[Value]) -> Value {
    let open_tail_call_ids = unresolved_tool_call_ids(messages);
    let node_ids: BTreeSet<String> = captures.iter().map(capture_node_id).collect();
    let mut span_nodes: HashMap<String, String> = HashMap::new();
    for capture in captures {
        if let Some(span_id) = capture.trace_context.get("span_id").and_then(Value::as_str) {
            // Lifecycle start/end records can describe the same producer span.
            // The first ordered record is the stable parent anchor for children.
            span_nodes
                .entry(span_id.to_owned())
                .or_insert_with(|| capture_node_id(capture));
        }
    }
    let mut referenced_parents = BTreeSet::new();
    let mut unresolved_response_parents = BTreeSet::new();
    let mut unresolved_span_parents = BTreeSet::new();
    let mut edges = Vec::new();
    let mut parents_by_child: HashMap<String, Vec<String>> = HashMap::new();
    for capture in captures {
        let node_id = capture_node_id(capture);
        if let Some(parent) = &capture.previous_response_id {
            referenced_parents.insert(parent.clone());
            parents_by_child
                .entry(node_id.clone())
                .or_default()
                .push(parent.clone());
            edges.push(json!({
                "from": parent,
                "to": node_id,
                "kind": "previous_response",
            }));
            if !node_ids.contains(parent) {
                unresolved_response_parents.insert(parent.clone());
            }
        }
        if let Some(parent_span_id) = capture
            .trace_context
            .get("parent_span_id")
            .and_then(Value::as_str)
        {
            let parent_node = span_nodes
                .get(parent_span_id)
                .cloned()
                .unwrap_or_else(|| format!("span:{parent_span_id}"));
            referenced_parents.insert(parent_node.clone());
            parents_by_child
                .entry(node_id.clone())
                .or_default()
                .push(parent_node.clone());
            edges.push(json!({
                "from": parent_node,
                "to": node_id,
                "kind":"parent_span",
                "parent_span_id":parent_span_id,
            }));
            if !span_nodes.contains_key(parent_span_id) {
                unresolved_span_parents.insert(parent_span_id.to_owned());
            }
        }
    }
    let has_cycle = graph_has_cycle(&parents_by_child);
    let final_index = captures.len().saturating_sub(1);
    let mut disposition_counts: BTreeMap<String, u64> = BTreeMap::new();
    let nodes: Vec<Value> = captures
        .iter()
        .enumerate()
        .map(|(index, capture)| {
            let lifecycle: Vec<String> = capture
                .lifecycle_events
                .iter()
                .map(|event| normalize_event(event))
                .collect();
            let disposition = if lifecycle.iter().any(|event| event.contains("retry")) {
                "retry"
            } else if lifecycle.iter().any(|event| {
                event.contains("cancel") || event.contains("abandon") || event.contains("abort")
            }) {
                "abandoned"
            } else if index == final_index && !open_tail_call_ids.is_empty() {
                "open_tail"
            } else {
                "executed"
            };
            *disposition_counts
                .entry(disposition.to_owned())
                .or_insert(0) += 1;
            json!({
                "node_id": capture_node_id(capture),
                "capture_id": capture.capture_id,
                "record_type": capture.record_type,
                "response_id": capture.response_id,
                "previous_response_id": capture.previous_response_id,
                "timestamp": capture.timestamp,
                "terminal_status": capture.terminal_status,
                "http_status": capture.response_status,
                "disposition": disposition,
                "lifecycle_events": capture.lifecycle_events,
                "lifecycle_event_records": capture.lifecycle_event_records,
                "trace": capture.trace_context,
            })
        })
        .collect();
    let roots: Vec<String> = node_ids
        .iter()
        .filter(|node| !parents_by_child.contains_key(node.as_str()))
        .cloned()
        .collect();
    let tips: Vec<String> = node_ids.difference(&referenced_parents).cloned().collect();
    json!({
        "nodes": nodes,
        "edges": edges,
        "roots": roots,
        "tips": tips,
        "open_tail_call_ids": open_tail_call_ids,
        "unresolved_parent_response_ids": unresolved_response_parents,
        "unresolved_parent_span_ids": unresolved_span_parents,
        "has_cycle": has_cycle,
        "disposition_counts": disposition_counts,
    })
}

fn capture_node_id(capture: &ParsedCapture) -> String {
    capture
        .response_id
        .clone()
        .or_else(|| {
            capture
                .trace_context
                .get("span_id")
                .and_then(Value::as_str)
                .map(|span_id| format!("span:{span_id}"))
        })
        .unwrap_or_else(|| capture.capture_id.clone())
}

fn graph_has_cycle(parents_by_child: &HashMap<String, Vec<String>>) -> bool {
    fn visit(
        node: &str,
        parents_by_child: &HashMap<String, Vec<String>>,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> bool {
        if visited.contains(node) {
            return false;
        }
        if !visiting.insert(node.to_owned()) {
            return true;
        }
        if parents_by_child.get(node).is_some_and(|parents| {
            parents
                .iter()
                .any(|parent| visit(parent, parents_by_child, visiting, visited))
        }) {
            return true;
        }
        visiting.remove(node);
        visited.insert(node.to_owned());
        false
    }

    let mut visited = HashSet::new();
    parents_by_child
        .keys()
        .any(|node| visit(node, parents_by_child, &mut HashSet::new(), &mut visited))
}

fn attach_task_dags(sessions: &mut [Value]) -> Result<()> {
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, session) in sessions.iter().enumerate() {
        let namespace = session
            .pointer("/meta/source_namespace")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let session_id = string_field(session, "session_id").unwrap_or("missing");
        let trace = session.pointer("/meta/trace").and_then(Value::as_object);
        let root_session_id = trace
            .and_then(|trace| trace.get("root_session_id"))
            .or_else(|| trace.and_then(|trace| trace.get("parent_session_id")))
            .and_then(Value::as_str)
            .unwrap_or(session_id);
        groups
            .entry(format!("{namespace}\0{root_session_id}"))
            .or_default()
            .push(index);
    }
    for indices in groups.into_values() {
        let first = &sessions[indices[0]];
        let first_session_id = string_field(first, "session_id").unwrap_or("missing");
        let first_trace = first.pointer("/meta/trace").and_then(Value::as_object);
        let root_session_id = first_trace
            .and_then(|trace| trace.get("root_session_id"))
            .or_else(|| first_trace.and_then(|trace| trace.get("parent_session_id")))
            .and_then(Value::as_str)
            .unwrap_or(first_session_id)
            .to_owned();
        let session_ids: BTreeSet<String> = indices
            .iter()
            .filter_map(|index| string_field(&sessions[*index], "session_id").map(str::to_owned))
            .collect();
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut unresolved_parents = BTreeSet::new();
        for index in &indices {
            let session = &sessions[*index];
            let session_id = string_field(session, "session_id").unwrap_or("missing");
            let trace = session.pointer("/meta/trace").and_then(Value::as_object);
            let parent = trace
                .and_then(|trace| trace.get("parent_session_id"))
                .and_then(Value::as_str);
            let role = if session_id == root_session_id {
                "root"
            } else {
                "subagent"
            };
            nodes.push(json!({
                "session_id": session_id,
                "trajectory_id": session.get("trajectory_id"),
                "parent_session_id": parent,
                "agent_id": trace.and_then(|trace| trace.get("agent_id")),
                "branch_id": trace.and_then(|trace| trace.get("branch_id")),
                "role": role,
                "detachable": role == "subagent",
            }));
            if let Some(parent) = parent {
                edges.push(json!({
                    "from": parent,
                    "to": session_id,
                    "kind": "subagent",
                }));
                if !session_ids.contains(parent) {
                    unresolved_parents.insert(parent.to_owned());
                }
            }
        }
        let root_present = session_ids.contains(&root_session_id);
        let graph = json!({
            "root_session_id": root_session_id,
            "nodes": nodes,
            "edges": edges,
            "unresolved_parent_session_ids": unresolved_parents,
            "complete": root_present && unresolved_parents.is_empty(),
        });
        for index in indices {
            let session_id = string_field(&sessions[index], "session_id")
                .unwrap_or("missing")
                .to_owned();
            let object = sessions[index]
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("canonical Session must be an object"))?;
            let meta = object
                .get_mut("meta")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| anyhow::anyhow!("canonical Session meta must be an object"))?;
            meta.insert("task_dag".to_owned(), graph.clone());
            meta.insert(
                "task_role".to_owned(),
                json!(if session_id == root_session_id {
                    "root"
                } else {
                    "subagent"
                }),
            );
        }
    }
    Ok(())
}

fn parse_capture(value: Value) -> Result<ParsedCapture> {
    let capture_id = string_field(&value, "captureId")
        .ok_or_else(|| anyhow::anyhow!("captureId missing"))?
        .to_owned();
    let request = extract_body(value.get("requestBody"))
        .cloned()
        .unwrap_or(Value::Null);
    let raw_response = extract_body(value.get("responseBody"))
        .cloned()
        .unwrap_or(Value::Null);
    let (response, response_terminal_status) = parse_response(&raw_response);
    let request_object = request.as_object().cloned().unwrap_or_default();
    let response_object = response.as_object().cloned().unwrap_or_default();
    let trace_context = collect_trace_context(&value, &request_object);
    let source_namespace = string_field(&value, "sourceNamespace")
        .or_else(|| string_field(&value, "apiKeyFingerprint"))
        .unwrap_or("default")
        .to_owned();
    let (session_identity, identity_source) =
        session_identity(&capture_id, &request_object, &trace_context);
    let (provider, provider_evidence) = infer_provider(&value, &request_object, &response_object);
    let model = request_object
        .get("model")
        .and_then(Value::as_str)
        .or_else(|| string_field(&value, "producerModel"))
        .map(str::to_owned);
    let response_model = response_object
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let (mut messages, mut tools, request_system_prompt, mut system_prompt_sources) =
        parse_request(&request_object, &provider);
    let tool_registry_evidence = if let Some(registry) = value.get("toolRegistry") {
        for entry in registry
            .get("tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(tool) = normalize_registry_tool_entry(entry) {
                tools.push(tool);
            }
        }
        Some(json!({
            "capture_id":capture_id.clone(),
            "sha256":value.get("toolRegistrySha256").and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| canonical_tool_registry_sha256(registry).ok()),
            "schema_version":registry.get("schema_version"),
            "producer":registry.get("producer"),
            "producer_version":registry.get("producer_version"),
            "captured_at":registry.get("captured_at"),
            "tool_count":registry.get("tools").and_then(Value::as_array).map(Vec::len),
        }))
    } else {
        None
    };
    messages.extend(
        value
            .get("rolloutMessages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|message| message.is_object())
            .cloned(),
    );
    let response_system_prompt = response_object
        .get("instructions")
        .and_then(|value| content_text(Some(value)))
        .filter(|value| !value.trim().is_empty());
    if let Some(prompt) = &response_system_prompt {
        system_prompt_sources.push(json!({
            "source":"response.instructions",
            "producer":"upstream_provider",
            "authority":"provider_reported",
            "content":prompt,
            "selected":true,
        }));
    }
    let rollout_system_prompt = string_field(&value, "systemPrompt").map(str::to_owned);
    if let Some(prompt) = &rollout_system_prompt {
        system_prompt_sources.push(json!({
            "source":"codex_rollout.session_meta.base_instructions",
            "producer":"codex_cli",
            "authority":"runtime_attested",
            "content":prompt,
            "selected":true,
        }));
    }
    let system_prompt = merge_system_prompts(
        merge_system_prompts(response_system_prompt, request_system_prompt),
        rollout_system_prompt,
    );
    set_system_message(&mut messages, system_prompt.as_deref());
    let response_messages = parse_response_messages(&response, &provider);
    let usage = parse_usage(response_object.get("usage"));
    let response_id = response_object
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let previous_response_id = request_object
        .get("previous_response_id")
        .or_else(|| request_object.get("previousResponseId"))
        .or_else(|| trace_context.get("previous_response_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let timestamp = ["startedAt", "receivedAt", "finishedAt"]
        .into_iter()
        .find_map(|field| string_field(&value, field))
        .or_else(|| {
            value
                .pointer("/lifecycleEvent/occurred_at")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            value
                .pointer("/toolExecution/started_at")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            value
                .pointer("/toolExecution/finished_at")
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .to_owned();
    let timestamp_unix_nanos = OffsetDateTime::parse(&timestamp, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp_nanos);
    let response_status = value.get("responseStatus").and_then(|status| {
        status
            .as_u64()
            .or_else(|| status.as_str().and_then(|text| text.parse().ok()))
    });
    let upstream_request_id = string_field(&value, "upstreamRequestId")
        .or_else(|| header_string(&value, "responseHeaders", "x-request-id"))
        .map(str::to_owned);
    let request_id = string_field(&value, "requestId")
        .or_else(|| header_string(&value, "requestHeaders", "x-client-request-id"))
        .or_else(|| header_string(&value, "responseHeaders", "x-client-request-id"))
        .map(str::to_owned);
    let mut lifecycle_events = value
        .get("observedLifecycleEvents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut lifecycle_event_records = value
        .get("observedLifecycleEvents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|event| {
            json!({
                "capture_id": capture_id.clone(),
                "type": event,
                "source": "observed",
            })
        })
        .collect::<Vec<_>>();
    if let Some(event) = value
        .pointer("/lifecycleEvent/type")
        .and_then(Value::as_str)
    {
        lifecycle_events.push(event.to_owned());
    }
    if let Some(event) = value.get("lifecycleEvent").and_then(Value::as_object) {
        let mut record = event.clone();
        record
            .entry("capture_id".to_owned())
            .or_insert_with(|| Value::String(capture_id.clone()));
        record
            .entry("source".to_owned())
            .or_insert_with(|| Value::String("lifecycle_event".to_owned()));
        lifecycle_event_records.push(Value::Object(record));
    }
    lifecycle_events.extend(infer_lifecycle_events(&request_object, &raw_response));
    lifecycle_events.sort();
    lifecycle_events.dedup();
    let evaluation_evidence = value
        .get("evaluationEvidence")
        .or_else(|| value.get("evaluation_evidence"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let final_snapshot = value
        .get("isFinalSnapshot")
        .or_else(|| value.get("is_final_snapshot"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || trace_context
            .get("session_final")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || lifecycle_events
            .iter()
            .any(|event| terminal_lifecycle_event(event));
    let lifecycle_status = value
        .pointer("/lifecycleEvent/status")
        .and_then(Value::as_str)
        .map(normalize_terminal_status);
    let terminal_status = lifecycle_status.or(response_terminal_status);
    let record_type = string_field(&value, "recordType")
        .unwrap_or("api_snapshot")
        .to_owned();
    let tool_execution = value.get("toolExecution").cloned();
    let producer_event = value.get("producerEvent").cloned();
    let field_evidence = value
        .get("fieldEvidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let protocol_conflicts = value
        .get("fieldEvidenceConflicts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let gateway_evidence = value.get("gatewayEvidence").cloned();
    let gateway_evidence_join = value.get("gatewayEvidenceJoin").cloned();
    let rollout_event = value.get("rolloutEvent").cloned();
    let rollout_usage = value.get("rolloutUsage").cloned();
    let rollout_unknown = rollout_event
        .as_ref()
        .and_then(|event| event.get("classification"))
        .and_then(Value::as_str)
        == Some("unknown");
    let rollout_unmapped_tool = rollout_event
        .as_ref()
        .and_then(|event| event.get("unmapped_tool"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(ParsedCapture {
        capture_id,
        record_type,
        timestamp,
        timestamp_unix_nanos,
        response,
        request_id,
        upstream_request_id,
        response_id,
        previous_response_id,
        response_status,
        terminal_status,
        provider,
        provider_evidence,
        model,
        response_model,
        source_namespace,
        session_identity,
        session_identity_source: identity_source,
        trace_context,
        field_evidence,
        protocol_conflicts,
        gateway_evidence,
        gateway_evidence_join,
        lifecycle_events,
        lifecycle_event_records,
        evaluation_evidence,
        tool_execution,
        producer_event,
        tool_registry_evidence,
        final_snapshot,
        messages,
        response_messages,
        tools,
        system_prompt,
        system_prompt_sources,
        usage,
        rollout_event,
        rollout_usage,
        rollout_unknown,
        rollout_unmapped_tool,
    })
}

fn parse_request(
    request: &Map<String, Value>,
    provider: &str,
) -> (Vec<Value>, Vec<Value>, Option<String>, Vec<Value>) {
    let mut messages = Vec::new();
    let mut tools = Vec::new();
    let mut system_prompt = None;
    let mut prompt_evidence = Vec::new();
    for field in ["instructions", "system"] {
        if let Some(prompt) = request
            .get(field)
            .and_then(|value| content_text(Some(value)))
            .filter(|value| !value.trim().is_empty())
        {
            system_prompt = merge_system_prompts(system_prompt, Some(prompt.clone()));
            prompt_evidence.push(json!({
                "source":format!("request.{field}"),
                "producer":"codex_client",
                "authority":"client_asserted",
                "content":prompt,
                "selected":true,
            }));
        }
    }
    for field in ["tools", "additional_tools"] {
        if let Some(values) = request.get(field).and_then(Value::as_array) {
            for value in values {
                collect_tool_definitions(value, &mut tools);
            }
        }
    }
    let input = if provider == "Anthropic" {
        request.get("messages")
    } else {
        request.get("input").or_else(|| request.get("messages"))
    };
    match input {
        Some(Value::String(text)) => {
            messages.push(json!({"role": "user", "content": text}));
        }
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                if matches!(
                    item.get("role").and_then(Value::as_str),
                    Some("developer" | "system")
                ) && item
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("message")
                    == "message"
                {
                    if let Some(developer) =
                        content_text(item.get("content")).filter(|value| !value.trim().is_empty())
                    {
                        system_prompt =
                            merge_system_prompts(system_prompt, Some(developer.clone()));
                        prompt_evidence.push(json!({
                            "source":format!("request.input[{index}].content"),
                            "producer":"codex_client",
                            "authority":"client_asserted",
                            "role":item.get("role"),
                            "content":developer,
                            "selected":true,
                        }));
                    }
                    continue;
                }
                parse_input_item(item, &mut messages, &mut tools);
            }
        }
        _ => {}
    }
    set_system_message(&mut messages, system_prompt.as_deref());
    (messages, tools, system_prompt, prompt_evidence)
}

fn parse_input_item(item: &Value, messages: &mut Vec<Value>, tools: &mut Vec<Value>) {
    let Some(object) = item.as_object() else {
        return;
    };
    let kind = object.get("type").and_then(Value::as_str).unwrap_or("");
    if kind == "additional_tools" {
        for field in ["tools", "additional_tools", "definitions"] {
            if let Some(definitions) = object.get(field).and_then(Value::as_array) {
                for definition in definitions {
                    collect_tool_definitions(definition, tools);
                }
            }
        }
        return;
    }
    if matches!(kind, "function_call" | "custom_tool_call" | "tool_use") {
        let id = object
            .get("call_id")
            .or_else(|| object.get("id"))
            .and_then(Value::as_str);
        let name = object.get("name").and_then(Value::as_str).map(|name| {
            canonical_runtime_tool_name(object.get("namespace").and_then(Value::as_str), name)
        });
        let arguments = if kind == "custom_tool_call" {
            json!({
                "input": object
                    .get("input")
                    .or_else(|| object.get("arguments"))
                    .cloned()
                    .unwrap_or(Value::Null)
            })
        } else {
            object
                .get("arguments")
                .or_else(|| object.get("input"))
                .cloned()
                .unwrap_or_else(|| json!({}))
        };
        let mut message = json!({
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": id,
                "type": "function",
                "function": {"name": name, "arguments": argument_string(&arguments)}
            }]
        });
        if let Some(item_id) = object.get("id") {
            message["id"] = item_id.clone();
        }
        messages.push(message);
        return;
    }
    if matches!(
        kind,
        "function_call_output" | "custom_tool_call_output" | "tool_result"
    ) {
        let call_id = object
            .get("call_id")
            .or_else(|| object.get("tool_use_id"))
            .or_else(|| object.get("tool_call_id"))
            .and_then(Value::as_str);
        let content = object
            .get("output")
            .or_else(|| object.get("content"))
            .cloned()
            .unwrap_or(Value::Null);
        let result_status = explicit_tool_result_status(object, &content);
        let mut message = json!({
            "role": "tool",
            "tool_call_id": call_id,
            "content": content,
        });
        if let Some(item_id) = object.get("id") {
            message["id"] = item_id.clone();
        }
        if let Some(status) = result_status.status {
            message["status"] = json!(status);
        }
        if let Some(is_error) = result_status.is_error {
            message["is_error"] = json!(is_error);
        }
        if let Some(source) = result_status.source {
            message["status_source"] = json!(source);
        }
        if result_status.envelope_count > 0 {
            message["runtime_envelope_count"] = json!(result_status.envelope_count);
        }
        if result_status.conflict {
            message["status_conflict"] = json!(true);
        }
        messages.push(message);
        return;
    }
    let role = object
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or(if kind == "message" { "user" } else { "" });
    if matches!(role, "system" | "user" | "assistant" | "tool") {
        if let Some(content) = object.get("content") {
            let start = messages.len();
            parse_role_content(role, content, object, messages);
            if let Some(id) = object.get("id").and_then(Value::as_str) {
                for (offset, message) in messages[start..].iter_mut().enumerate() {
                    message["id"] = json!(if offset == 0 {
                        id.to_owned()
                    } else {
                        format!("{id}:{offset}")
                    });
                }
            }
        } else {
            let mut normalized = Map::new();
            normalized.insert("role".to_owned(), Value::String(role.to_owned()));
            normalized.insert("content".to_owned(), Value::String(String::new()));
            if let Some(calls) = object.get("tool_calls") {
                normalized.insert("tool_calls".to_owned(), normalize_tool_calls(calls));
            }
            if let Some(id) = object.get("id") {
                normalized.insert("id".to_owned(), id.clone());
            }
            messages.push(Value::Object(normalized));
        }
    }
}

#[derive(Debug, Default)]
struct ExplicitToolResultStatus {
    status: Option<&'static str>,
    is_error: Option<bool>,
    source: Option<&'static str>,
    envelope_count: usize,
    conflict: bool,
}

fn explicit_tool_result_status(
    object: &Map<String, Value>,
    content: &Value,
) -> ExplicitToolResultStatus {
    let direct_status = object
        .get("status")
        .and_then(Value::as_str)
        .map(normalize_tool_status);
    let direct_error = object
        .get("is_error")
        .or_else(|| object.get("isError"))
        .and_then(Value::as_bool);
    let envelope_errors = runtime_result_envelope_errors(content);
    let envelope_status = if envelope_errors.is_empty() {
        None
    } else if envelope_errors.iter().all(|is_error| *is_error) {
        Some(("error", true))
    } else if envelope_errors.iter().all(|is_error| !*is_error) {
        Some(("success", false))
    } else {
        None
    };

    let direct_conflict = matches!(
        (direct_status, direct_error),
        (Some("success"), Some(true)) | (Some("error" | "cancelled" | "timeout"), Some(false))
    );
    let envelope_conflict = !envelope_errors.is_empty() && envelope_status.is_none();
    let cross_conflict = match (direct_status, direct_error, envelope_status) {
        (Some(status), _, Some((envelope, _))) => status != envelope,
        (None, Some(error), Some((_, envelope_error))) => error != envelope_error,
        _ => false,
    };
    let conflict = direct_conflict || envelope_conflict || cross_conflict;
    if conflict {
        return ExplicitToolResultStatus {
            status: Some("unknown"),
            is_error: direct_error,
            source: Some("conflicting_explicit_status"),
            envelope_count: envelope_errors.len(),
            conflict: true,
        };
    }
    if let Some(status) = direct_status {
        return ExplicitToolResultStatus {
            status: Some(status),
            is_error: direct_error.or_else(|| status_to_error(status)),
            source: Some("tool_result.status"),
            envelope_count: envelope_errors.len(),
            conflict: false,
        };
    }
    if let Some(is_error) = direct_error {
        return ExplicitToolResultStatus {
            status: Some(if is_error { "error" } else { "success" }),
            is_error: Some(is_error),
            source: Some("tool_result.is_error"),
            envelope_count: envelope_errors.len(),
            conflict: false,
        };
    }
    if let Some((status, is_error)) = envelope_status {
        return ExplicitToolResultStatus {
            status: Some(status),
            is_error: Some(is_error),
            source: Some("codex_runtime_result_envelope"),
            envelope_count: envelope_errors.len(),
            conflict: false,
        };
    }
    ExplicitToolResultStatus::default()
}

fn status_to_error(status: &str) -> Option<bool> {
    match status {
        "success" => Some(false),
        "error" | "cancelled" | "timeout" => Some(true),
        _ => None,
    }
}

fn runtime_result_envelope_errors(content: &Value) -> Vec<bool> {
    let mut output = Vec::new();
    collect_runtime_result_envelopes(content, &mut output);
    output
}

fn collect_runtime_result_envelopes(value: &Value, output: &mut Vec<bool>) {
    match value {
        Value::String(text) => {
            if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                collect_runtime_result_envelopes(&parsed, output);
            }
        }
        Value::Array(items) => {
            for item in items {
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    if let Ok(parsed) = serde_json::from_str::<Value>(text)
                        && let Some(is_error) = runtime_result_envelope(&parsed)
                    {
                        output.push(is_error);
                    }
                } else if let Some(is_error) = runtime_result_envelope(item) {
                    output.push(is_error);
                }
            }
        }
        Value::Object(_) => {
            if let Some(is_error) = runtime_result_envelope(value) {
                output.push(is_error);
            }
        }
        _ => {}
    }
}

fn runtime_result_envelope(value: &Value) -> Option<bool> {
    let object = value.as_object()?;
    let allowed = ["content", "isError", "structuredContent", "_meta"];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return None;
    }
    let is_error = object.get("isError")?.as_bool()?;
    let content = object.get("content")?.as_array()?;
    if content.iter().any(|item| {
        item.as_object().is_none_or(|item| {
            item.get("type").and_then(Value::as_str).is_none_or(|kind| {
                !matches!(
                    kind,
                    "text" | "image" | "audio" | "resource" | "resource_link"
                )
            })
        })
    }) {
        return None;
    }
    Some(is_error)
}

fn parse_role_content(
    role: &str,
    content: &Value,
    source: &Map<String, Value>,
    messages: &mut Vec<Value>,
) {
    let Some(blocks) = content.as_array() else {
        let mut message = json!({"role": role, "content": content});
        if let Some(calls) = source.get("tool_calls") {
            message["tool_calls"] = calls.clone();
        }
        if let Some(call_id) = source.get("tool_call_id") {
            message["tool_call_id"] = call_id.clone();
        }
        if let Some(status) = source.get("status") {
            message["status"] = status.clone();
        }
        if let Some(is_error) = source.get("is_error") {
            message["is_error"] = is_error.clone();
        }
        if let Some(id) = source.get("id") {
            message["id"] = id.clone();
        }
        messages.push(message);
        return;
    };
    let mut text = Vec::new();
    let mut calls = Vec::new();
    for block in blocks {
        let kind = string_field(block, "type").unwrap_or("");
        match kind {
            "tool_use" => {
                calls.push(json!({
                    "id": block.get("id"),
                    "type": "function",
                    "function": {
                        "name": canonical_tool_identity(block),
                        "arguments": argument_string(block.get("input").unwrap_or(&Value::Null))
                    }
                }));
            }
            "tool_result" => {
                flush_role_blocks(role, &mut text, &mut calls, messages);
                let mut message = json!({
                    "role": "tool",
                    "tool_call_id": block.get("tool_use_id"),
                    "content": block.get("content").cloned().unwrap_or(Value::Null),
                });
                if let Some(is_error) = block.get("is_error").and_then(Value::as_bool) {
                    message["status"] = json!(if is_error { "error" } else { "success" });
                    message["is_error"] = json!(is_error);
                }
                messages.push(message);
            }
            _ => {
                if let Some(value) = content_text(Some(block))
                    && !value.is_empty()
                {
                    text.push(value);
                }
            }
        }
    }
    flush_role_blocks(role, &mut text, &mut calls, messages);
}

fn flush_role_blocks(
    role: &str,
    text: &mut Vec<String>,
    calls: &mut Vec<Value>,
    messages: &mut Vec<Value>,
) {
    if text.is_empty() && calls.is_empty() {
        return;
    }
    let mut message = json!({"role": role, "content": text.join("\n")});
    if !calls.is_empty() {
        message["tool_calls"] = Value::Array(std::mem::take(calls));
    }
    text.clear();
    messages.push(message);
}

fn parse_response(value: &Value) -> (Value, Option<String>) {
    let Some(text) = value.as_str() else {
        let status = value
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_owned);
        return (value.clone(), status);
    };
    let mut output: BTreeMap<u64, Value> = BTreeMap::new();
    let mut terminal = None;
    let mut status = None;
    let mut created_response = None;
    for line in text.lines() {
        let Some(payload) = line.trim().strip_prefix("data:") else {
            continue;
        };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        let kind = string_field(&event, "type").unwrap_or("");
        if kind == "response.created" {
            created_response = event.get("response").cloned();
        }
        if kind == "response.output_item.done"
            && let Some(item) = event.get("item")
        {
            let index = event
                .get("output_index")
                .and_then(Value::as_u64)
                .unwrap_or(output.len() as u64);
            output.insert(index, item.clone());
        }
        if matches!(
            kind,
            "response.completed" | "response.failed" | "response.incomplete" | "response.cancelled"
        ) {
            terminal = event.get("response").cloned();
            status = Some(kind.trim_start_matches("response.").to_owned());
        }
    }
    let mut response = terminal
        .or_else(|| created_response.clone())
        .unwrap_or_else(|| json!({}));
    if let (Some(created), Value::Object(response_object)) = (created_response, &mut response)
        && let Value::Object(created_object) = created
    {
        for (key, value) in created_object {
            response_object.entry(key).or_insert(value);
        }
    }
    if !output.is_empty() {
        response["output"] = Value::Array(output.into_values().collect());
    }
    (response, status)
}

fn parse_response_messages(response: &Value, provider: &str) -> Vec<Value> {
    if let Some(message) = response
        .pointer("/choices/0/message")
        .or_else(|| response.pointer("/choices/0/delta"))
    {
        let mut output = Vec::new();
        parse_input_item(message, &mut output, &mut Vec::new());
        return output;
    }
    if provider == "Anthropic" {
        let mut output = Vec::new();
        if let Some(content) = response.get("content") {
            parse_role_content(
                response
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("assistant"),
                content,
                &Map::new(),
                &mut output,
            );
        }
        return output;
    }
    let mut output = Vec::new();
    let items = response
        .get("output")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for item in items {
        let kind = string_field(item, "type").unwrap_or("");
        if matches!(kind, "function_call" | "custom_tool_call") {
            let arguments = if kind == "custom_tool_call" {
                json!({
                    "input": item
                        .get("input")
                        .or_else(|| item.get("arguments"))
                        .cloned()
                        .unwrap_or(Value::Null)
                })
            } else {
                item.get("arguments")
                    .or_else(|| item.get("input"))
                    .cloned()
                    .unwrap_or(Value::Null)
            };
            let mut message = json!({
                "role":"assistant",
                "content":"",
                "tool_calls":[{
                    "id": item.get("call_id").or_else(|| item.get("id")),
                    "type": "function",
                    "function": {
                        "name": canonical_tool_identity(item),
                        "arguments": argument_string(&arguments)
                    }
                }]
            });
            if let Some(id) = item.get("id") {
                message["id"] = id.clone();
            }
            output.push(message);
            continue;
        }
        if matches!(kind, "message" | "agent_message")
            || string_field(item, "role") == Some("assistant")
        {
            let content = item.get("content").cloned().unwrap_or(Value::Null);
            let mut message = json!({
                "role": "assistant",
                "content": content_text(Some(&content)).unwrap_or_default(),
            });
            if let Some(id) = item.get("id") {
                message["id"] = id.clone();
            }
            output.push(message);
        }
    }
    output
}

fn collect_tool_definitions(value: &Value, output: &mut Vec<Value>) {
    collect_tool_definitions_in_namespace(value, output, None);
}

fn collect_tool_definitions_in_namespace(
    value: &Value,
    output: &mut Vec<Value>,
    inherited_namespace: Option<&str>,
) {
    if let Some(children) = value.get("tools").and_then(Value::as_array)
        && (string_field(value, "type") == Some("namespace")
            || value.get("parameters").is_none() && value.get("format").is_none())
    {
        let namespace = if string_field(value, "type") == Some("namespace") {
            string_field(value, "name").or(inherited_namespace)
        } else {
            inherited_namespace
        };
        for child in children {
            collect_tool_definitions_in_namespace(child, output, namespace);
        }
        return;
    }
    if let Some(tool) = normalize_tool_definition_with_namespace(value, inherited_namespace) {
        output.push(tool);
    }
}

fn normalize_tool_definition(value: &Value) -> Option<Value> {
    normalize_tool_definition_with_namespace(value, None)
}

fn normalize_registry_tool_entry(entry: &Value) -> Option<Value> {
    let mut tool = entry.get("tool")?.clone();
    if let Some(runtime_tool) = string_field(entry, "runtime_tool") {
        tool["runtime_tool"] = json!(runtime_tool);
    }
    if let Some(runtime_namespace) = string_field(entry, "runtime_namespace") {
        tool["runtime_namespace"] = json!(runtime_namespace);
    }
    normalize_tool_definition(&tool)
}

fn normalize_tool_definition_with_namespace(
    value: &Value,
    inherited_namespace: Option<&str>,
) -> Option<Value> {
    let nested = value.get("function").unwrap_or(value);
    let definition_name = string_field(nested, "name")?;
    let runtime_tool = string_field(nested, "runtime_tool").unwrap_or(definition_name);
    let runtime_namespace = string_field(nested, "runtime_namespace")
        .or_else(|| string_field(nested, "namespace"))
        .or_else(|| string_field(value, "namespace"))
        .or(inherited_namespace);
    let name = canonical_runtime_tool_name(runtime_namespace, runtime_tool);
    let description = nested
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let native_format = nested.get("format").cloned();
    let captured_parameters = nested
        .get("parameters")
        .or_else(|| nested.get("input_schema"))
        .cloned();
    let source_complete = tool_definition_source_complete(nested, definition_name);
    let (parameters, adapter_version) = if let Some(parameters) = captured_parameters.clone() {
        (parameters, None)
    } else if let Some(format) = &native_format {
        (
            json!({
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "Raw custom-tool input governed by the captured native format."
                    }
                },
                "required": ["input"],
                "x-chiptrace-native-format": format,
            }),
            Some("chiptrace.custom-input-object.v1"),
        )
    } else {
        (json!({"type": "object", "properties": {}}), None)
    };
    let hash = canonical_tool_schema_sha256(&json!({
        "name":name,
        "description":description,
        "parameters":captured_parameters,
        "format":native_format,
        "type":value.get("type").and_then(Value::as_str).unwrap_or("function"),
    }))
    .ok()?;
    let schema_version = value
        .get("schema_version")
        .or_else(|| value.get("version"))
        .cloned()
        .unwrap_or_else(|| Value::String(format!("sha256:{hash}")));
    let mut output = json!({
        "name": name,
        "description": description,
        "parameters": parameters,
        "type": value.get("type").and_then(Value::as_str).unwrap_or("function"),
        "schema_hash": hash,
        "schema_version": schema_version,
        "schema_provenance": {
            "source": if native_format.is_some() { "captured_native_format" } else if captured_parameters.is_some() { "captured_json_schema" } else { "missing" },
            "source_complete": source_complete,
            "adapter_version": adapter_version,
            "generated_adapter": adapter_version.is_some(),
        },
    });
    if let Some(format) = native_format {
        output["native_format"] = format;
    }
    if runtime_tool != name {
        output["runtime_tool"] = json!(runtime_tool);
    }
    if let Some(namespace) = runtime_namespace {
        output["runtime_namespace"] = json!(namespace);
    }
    Some(output)
}

fn canonical_tool_identity(value: &Value) -> Option<String> {
    let nested = value.get("function").unwrap_or(value);
    let definition_name = string_field(nested, "name")?;
    let runtime_tool = string_field(nested, "runtime_tool").unwrap_or(definition_name);
    let namespace = string_field(nested, "runtime_namespace")
        .or_else(|| string_field(nested, "namespace"))
        .or_else(|| string_field(value, "namespace"));
    Some(canonical_runtime_tool_name(namespace, runtime_tool))
}

fn tool_schemas_semantically_equal(left: &Value, right: &Value) -> bool {
    let left_hash = string_field(left, "schema_hash");
    let right_hash = string_field(right, "schema_hash");
    left_hash.is_some() && left_hash == right_hash
}

fn normalize_tool_calls(value: &Value) -> Value {
    let Some(calls) = value.as_array() else {
        return value.clone();
    };
    Value::Array(
        calls
            .iter()
            .map(|call| {
                let mut call = call.clone();
                if let Some(name) = canonical_tool_identity(&call) {
                    if call.get("function").is_some() {
                        call["function"]["name"] = json!(name);
                    } else {
                        call["name"] = json!(name);
                    }
                }
                call
            })
            .collect(),
    )
}

fn merge_system_prompts(existing: Option<String>, additional: Option<String>) -> Option<String> {
    let mut parts = Vec::new();
    for value in [existing, additional].into_iter().flatten() {
        let value = value.trim();
        if !value.is_empty() && !parts.iter().any(|part| part == value) {
            parts.push(value.to_owned());
        }
    }
    (!parts.is_empty()).then(|| parts.join("\n\n"))
}

/// Request/response `instructions` are scoped to an individual model call and
/// may legitimately change between turns. Runtime/session base instructions
/// are task-scoped and conflicting values remain a hard integrity error.
fn system_prompt_source_is_task_scoped(evidence: &Value) -> bool {
    if evidence.get("scope").and_then(Value::as_str) == Some("request") {
        return false;
    }
    if evidence.get("scope").and_then(Value::as_str) == Some("task") {
        return true;
    }
    let source = evidence.get("source").and_then(Value::as_str).unwrap_or("");
    !source.starts_with("request.") && !source.starts_with("response.")
}

fn set_system_message(messages: &mut Vec<Value>, system_prompt: Option<&str>) {
    let Some(system_prompt) = system_prompt.filter(|value| !value.trim().is_empty()) else {
        return;
    };
    if let Some(message) = messages
        .iter_mut()
        .find(|message| string_field(message, "role") == Some("system"))
    {
        message["content"] = json!(system_prompt);
    } else {
        messages.insert(0, json!({"role":"system", "content":system_prompt}));
    }
}

fn reconcile_tool_executions(captures: &[ParsedCapture]) -> (Vec<Value>, Vec<String>) {
    let mut by_call: BTreeMap<String, Vec<&ParsedCapture>> = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for capture in captures {
        let Some(execution) = capture.tool_execution.as_ref() else {
            continue;
        };
        let Some(call_id) = string_field(execution, "call_id") else {
            conflicts.insert(format!("{}:missing_call_id", capture.capture_id));
            continue;
        };
        by_call.entry(call_id.to_owned()).or_default().push(capture);
    }

    let mut executions = Vec::with_capacity(by_call.len());
    for (call_id, events) in by_call {
        for field in ["name", "initiator", "arguments"] {
            if tool_event_field_variants(&events, field, false) > 1 {
                conflicts.insert(format!("{call_id}:field_mismatch:{field}"));
            }
        }
        for field in [
            "parent_call_id",
            "schema",
            "schema_provenance",
            "started_at",
        ] {
            if tool_event_field_variants(&events, field, true) > 1 {
                conflicts.insert(format!("{call_id}:field_mismatch:{field}"));
            }
        }

        let started: Vec<&ParsedCapture> = events
            .iter()
            .copied()
            .filter(|capture| {
                capture
                    .tool_execution
                    .as_ref()
                    .and_then(|execution| string_field(execution, "status"))
                    == Some("started")
            })
            .collect();
        let terminal: Vec<&ParsedCapture> = events
            .iter()
            .copied()
            .filter(|capture| {
                capture
                    .tool_execution
                    .as_ref()
                    .and_then(|execution| string_field(execution, "status"))
                    != Some("started")
            })
            .collect();
        let producer_event_count = events
            .iter()
            .filter(|capture| capture.producer_event.is_some())
            .count();
        let producer_state_machine = producer_event_count > 0;
        if producer_state_machine && producer_event_count != events.len() {
            conflicts.insert(format!("{call_id}:mixed_producer_and_composite_evidence"));
        }
        if started.len() > 1 {
            conflicts.insert(format!("{call_id}:duplicate_started_event"));
        }
        if terminal.len() > 1 {
            conflicts.insert(format!("{call_id}:duplicate_terminal_event"));
        }
        if terminal.is_empty() {
            conflicts.insert(format!("{call_id}:missing_terminal_event"));
        }
        if producer_state_machine && started.len() != 1 {
            conflicts.insert(format!("{call_id}:missing_started_event"));
        }

        if let Some(finished) = terminal.first() {
            let execution = finished.tool_execution.as_ref().unwrap();
            if string_field(execution, "status") == Some("unknown") {
                conflicts.insert(format!("{call_id}:unknown_terminal_status"));
            }
            if !producer_state_machine
                && (string_field(execution, "started_at").is_none()
                    || string_field(execution, "finished_at").is_none())
            {
                conflicts.insert(format!("{call_id}:incomplete_composite_span"));
            }
        }

        if let (Some(start), Some(finish)) = (started.first(), terminal.first()) {
            match (
                producer_event_identity(start.producer_event.as_ref()),
                producer_event_identity(finish.producer_event.as_ref()),
            ) {
                (
                    Some((start_producer, start_stream, start_sequence)),
                    Some((end_producer, end_stream, end_sequence)),
                ) if start_producer == end_producer && start_stream == end_stream => {
                    if end_sequence <= start_sequence {
                        conflicts.insert(format!("{call_id}:producer_sequence_not_increasing"));
                    }
                }
                (None, _) | (_, None) if producer_state_machine => {
                    conflicts.insert(format!("{call_id}:producer_identity_incomplete"));
                }
                _ => {}
            }
        }

        let selected = terminal
            .first()
            .or_else(|| started.first())
            .or_else(|| events.first())
            .and_then(|capture| capture.tool_execution.clone())
            .unwrap_or_else(|| json!({"call_id":call_id}));
        let mut selected = selected.as_object().cloned().unwrap_or_default();
        selected.insert(
            "event_capture_ids".to_owned(),
            json!(
                events
                    .iter()
                    .map(|capture| capture.capture_id.as_str())
                    .collect::<Vec<_>>()
            ),
        );
        selected.insert(
            "started_capture_ids".to_owned(),
            json!(
                started
                    .iter()
                    .map(|capture| capture.capture_id.as_str())
                    .collect::<Vec<_>>()
            ),
        );
        selected.insert(
            "terminal_capture_ids".to_owned(),
            json!(
                terminal
                    .iter()
                    .map(|capture| capture.capture_id.as_str())
                    .collect::<Vec<_>>()
            ),
        );
        selected.insert(
            "producer_event_ids".to_owned(),
            json!(
                events
                    .iter()
                    .filter_map(|capture| capture.producer_event.as_ref())
                    .filter_map(|event| string_field(event, "event_id"))
                    .collect::<Vec<_>>()
            ),
        );
        selected.insert(
            "evidence_mode".to_owned(),
            json!(if producer_state_machine {
                "producer_state_machine"
            } else {
                "composite_runtime_span"
            }),
        );
        selected.insert(
            "state".to_owned(),
            json!(if terminal.len() == 1 {
                "closed"
            } else {
                "open"
            }),
        );
        executions.push(Value::Object(selected));
    }
    (executions, conflicts.into_iter().collect())
}

fn tool_event_field_variants(events: &[&ParsedCapture], field: &str, ignore_null: bool) -> usize {
    events
        .iter()
        .filter_map(|capture| capture.tool_execution.as_ref())
        .filter_map(|execution| execution.get(field))
        .filter(|value| !ignore_null || !value.is_null())
        .filter_map(|value| serde_json::to_vec(value).ok())
        .collect::<BTreeSet<_>>()
        .len()
}

fn producer_event_identity(event: Option<&Value>) -> Option<(&str, &str, u64)> {
    let event = event?;
    Some((
        string_field(event, "producer")?,
        string_field(event, "stream_id")?,
        event.get("sequence")?.as_u64()?,
    ))
}

fn audit_producer_streams(captures: &[ParsedCapture]) -> (Vec<Value>, Vec<String>) {
    type StreamKey = (String, String);
    type StreamEvent = (u64, String, String, String);
    let mut streams: BTreeMap<StreamKey, Vec<StreamEvent>> = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for capture in captures {
        let Some(event) = capture.producer_event.as_ref() else {
            continue;
        };
        let Some(producer) = string_field(event, "producer") else {
            conflicts.insert(format!("{}:producer_missing_name", capture.capture_id));
            continue;
        };
        let Some(stream_id) = string_field(event, "stream_id") else {
            conflicts.insert(format!("{}:producer_missing_stream_id", capture.capture_id));
            continue;
        };
        let Some(sequence) = event.get("sequence").and_then(Value::as_u64) else {
            conflicts.insert(format!("{}:producer_missing_sequence", capture.capture_id));
            continue;
        };
        let Some(event_id) = string_field(event, "event_id") else {
            conflicts.insert(format!("{}:producer_missing_event_id", capture.capture_id));
            continue;
        };
        let Some(producer_version) = string_field(event, "producer_version") else {
            conflicts.insert(format!("{}:producer_missing_version", capture.capture_id));
            continue;
        };
        if string_field(event, "schema_version") != Some("chiptrace.producer-event.v1") {
            conflicts.insert(format!("{}:producer_schema_version", capture.capture_id));
        }
        streams
            .entry((producer.to_owned(), stream_id.to_owned()))
            .or_default()
            .push((
                sequence,
                event_id.to_owned(),
                capture.capture_id.clone(),
                producer_version.to_owned(),
            ));
    }

    let mut output = Vec::with_capacity(streams.len());
    for ((producer, stream_id), mut events) in streams {
        events.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let versions: BTreeSet<&str> = events.iter().map(|event| event.3.as_str()).collect();
        let event_ids: BTreeSet<&str> = events.iter().map(|event| event.1.as_str()).collect();
        let mut duplicate_sequences = BTreeSet::new();
        let mut gaps = Vec::new();
        for pair in events.windows(2) {
            if pair[0].0 == pair[1].0 {
                duplicate_sequences.insert(pair[0].0);
            } else if pair[1].0 > pair[0].0.saturating_add(1) {
                gaps.push(json!({
                    "after":pair[0].0,
                    "before":pair[1].0,
                    "missing":pair[1].0.saturating_sub(pair[0].0).saturating_sub(1),
                }));
            }
        }
        let duplicate_event_ids = event_ids.len() != events.len();
        if versions.len() != 1 {
            conflicts.insert(format!("{producer}:{stream_id}:producer_version_changed"));
        }
        if !duplicate_sequences.is_empty() {
            conflicts.insert(format!("{producer}:{stream_id}:duplicate_sequence"));
        }
        if !gaps.is_empty() {
            conflicts.insert(format!("{producer}:{stream_id}:sequence_gap"));
        }
        if duplicate_event_ids {
            conflicts.insert(format!("{producer}:{stream_id}:duplicate_event_id"));
        }
        let contiguous = duplicate_sequences.is_empty() && !duplicate_event_ids && gaps.is_empty();
        output.push(json!({
            "producer":producer,
            "stream_id":stream_id,
            "producer_versions":versions,
            "first_sequence":events.first().map(|event| event.0),
            "last_sequence":events.last().map(|event| event.0),
            "event_count":events.len(),
            "capture_ids":events.iter().map(|event| event.2.as_str()).collect::<Vec<_>>(),
            "duplicate_sequences":duplicate_sequences,
            "duplicate_event_ids":duplicate_event_ids,
            "gaps":gaps,
            "contiguous":contiguous,
        }));
    }
    (output, conflicts.into_iter().collect())
}

fn project_tool_execution(
    messages: &mut Vec<Value>,
    tools_by_name: &mut BTreeMap<String, Value>,
    schema_conflicts: &mut BTreeSet<String>,
    execution: &Value,
) -> u64 {
    let Some(name) = string_field(execution, "name") else {
        return 1;
    };
    let Some(call_id) = string_field(execution, "call_id") else {
        return 1;
    };
    if let Some(schema) = execution.get("schema").and_then(normalize_tool_definition) {
        if tool_name(&schema) != Some(name) {
            schema_conflicts.insert(name.to_owned());
        } else if let Some(existing) = tools_by_name.get(name)
            && !tool_schemas_semantically_equal(existing, &schema)
        {
            schema_conflicts.insert(name.to_owned());
        } else {
            tools_by_name.insert(name.to_owned(), schema);
        }
    }

    if string_field(execution, "initiator") != Some("assistant") {
        return 0;
    }
    let arguments = execution.get("arguments").cloned().unwrap_or(Value::Null);
    let mut call = json!({
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": argument_string(&arguments),
        },
        "source": "executor_span",
    });
    if let Some(parent) = execution.get("parent_call_id") {
        call["parent_call_id"] = parent.clone();
    }
    let mut candidate = vec![json!({
        "role":"assistant",
        "content":"",
        "tool_calls":[call],
    })];
    let status = string_field(execution, "status").unwrap_or("unknown");
    if status != "started" {
        let content = execution
            .get("result")
            .or_else(|| execution.get("error"))
            .cloned()
            .unwrap_or(Value::Null);
        let normalized_status = normalize_tool_status(status);
        let mut result = json!({
            "role":"tool",
            "tool_call_id":call_id,
            "content":content,
            "status":normalized_status,
            "source":"executor_span",
        });
        if normalized_status != "unknown" {
            result["is_error"] = json!(normalized_status != "success");
        }
        candidate.push(result);
    }
    merge_messages(messages, &candidate)
}

fn normalize_tool_status(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "success" | "succeeded" | "completed" | "complete" | "ok" => "success",
        "error" | "errored" | "failed" | "failure" => "error",
        "cancel" | "cancelled" | "canceled" => "cancelled",
        "timeout" | "timed_out" => "timeout",
        _ => "unknown",
    }
}

fn normalize_terminal_status(status: &str) -> String {
    match status.trim().to_ascii_lowercase().as_str() {
        "success" | "succeeded" | "completed" | "complete" | "ok" => "completed",
        "error" | "errored" | "failed" | "failure" => "failed",
        "cancel" | "cancelled" | "canceled" => "cancelled",
        "abort" | "aborted" | "abandoned" => "cancelled",
        "terminate" | "terminated" => "terminated",
        "incomplete" => "incomplete",
        _ => "incomplete",
    }
    .to_owned()
}

fn annotate_tool_call_statuses(messages: &mut [Value]) {
    let mut results = HashMap::new();
    for (index, message) in messages.iter().enumerate() {
        if string_field(message, "role") != Some("tool") {
            continue;
        }
        let Some(call_id) = string_field(message, "tool_call_id") else {
            continue;
        };
        let status = string_field(message, "status")
            .unwrap_or("unknown")
            .to_owned();
        let normalized = normalize_tool_status(&status);
        let is_error = message.get("is_error").and_then(Value::as_bool);
        results.insert(call_id.to_owned(), (index, normalized, is_error));
    }
    let last_index = messages.len().saturating_sub(1);
    for (message_index, message) in messages.iter_mut().enumerate() {
        if string_field(message, "role") != Some("assistant") {
            continue;
        }
        let Some(calls) = message.get_mut("tool_calls").and_then(Value::as_array_mut) else {
            continue;
        };
        for call in calls {
            let Some(object) = call.as_object_mut() else {
                continue;
            };
            let call_id = object.get("id").and_then(Value::as_str);
            if let Some((result_index, status, is_error)) =
                call_id.and_then(|call_id| results.get(call_id))
            {
                object.insert(
                    "execution_status".to_owned(),
                    Value::String(
                        if *status == "unknown" {
                            "unknown"
                        } else if is_error.unwrap_or(*status != "success") {
                            "failed"
                        } else {
                            "executed"
                        }
                        .to_owned(),
                    ),
                );
                object.insert("result_status".to_owned(), json!(status));
                object.insert("result_message_index".to_owned(), json!(result_index));
            } else {
                object.insert(
                    "execution_status".to_owned(),
                    Value::String(
                        if message_index == last_index {
                            "open_tail"
                        } else {
                            "unpaired"
                        }
                        .to_owned(),
                    ),
                );
            }
        }
    }
}

fn collect_trace_context(capture: &Value, request: &Map<String, Value>) -> Map<String, Value> {
    let mut output = Map::new();
    let top_level = capture.as_object().cloned().unwrap_or_default();
    let captured = capture
        .get("traceContext")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let metadata = request
        .get("client_metadata")
        .or_else(|| request.get("metadata"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let turn_metadata = codex_turn_metadata(request);
    for (field, aliases) in [
        ("task_session_id", &["task_session_id", "taskSessionId"][..]),
        ("session_id", &["session_id", "sessionId"][..]),
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
        ("traceparent", &["traceparent"]),
        ("tracestate", &["tracestate"]),
        ("trace_flags", &["trace_flags", "traceFlags"]),
        ("session_final", &["session_final", "sessionFinal"]),
    ] {
        if let Some(value) = [&captured, &top_level, &metadata, &turn_metadata, request]
            .into_iter()
            .find_map(|source| aliases.iter().find_map(|alias| source.get(*alias)))
        {
            output.insert(field.to_owned(), value.clone());
        }
    }
    output
}

fn infer_lifecycle_events(request: &Map<String, Value>, response: &Value) -> Vec<String> {
    fn add_event(events: &mut BTreeSet<String>, value: Option<&Value>) {
        let Some(event) = value.and_then(Value::as_str) else {
            return;
        };
        if lifecycle_event_type(event) {
            events.insert(event.to_owned());
        }
    }

    fn add_response(events: &mut BTreeSet<String>, response: &Value) {
        add_event(events, response.get("type"));
        if let Some(status) = response.get("status").and_then(Value::as_str) {
            add_event(events, Some(&Value::String(format!("response.{status}"))));
        }
    }

    let mut events = BTreeSet::new();
    let turn_metadata = codex_turn_metadata(request);
    if turn_metadata.get("request_kind").and_then(Value::as_str) == Some("compaction") {
        events.insert("compaction".to_owned());
    }
    if let Some(input) = request.get("input").and_then(Value::as_array) {
        for item in input {
            add_event(&mut events, item.get("type"));
        }
    }
    match response {
        Value::Object(_) => add_response(&mut events, response),
        Value::String(text) => {
            if let Ok(value) = serde_json::from_str::<Value>(text) {
                add_response(&mut events, &value);
            }
            for line in text.lines() {
                let Some(payload) = line.trim().strip_prefix("data:") else {
                    continue;
                };
                let payload = payload.trim();
                if payload.is_empty() || payload == "[DONE]" {
                    continue;
                }
                if let Ok(value) = serde_json::from_str::<Value>(payload) {
                    add_response(&mut events, &value);
                }
            }
        }
        _ => {}
    }
    events.into_iter().collect()
}

fn codex_turn_metadata(request: &Map<String, Value>) -> Map<String, Value> {
    request
        .get("client_metadata")
        .or_else(|| request.get("metadata"))
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("x-codex-turn-metadata"))
        .and_then(Value::as_str)
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

fn lifecycle_event_type(event: &str) -> bool {
    matches!(
        normalize_event(event).as_str(),
        "cancel"
            | "compaction"
            | "compaction_trigger"
            | "retry"
            | "session_end"
            | "session_start"
            | "subagent_join"
            | "subagent_spawn"
            | "response_cancelled"
            | "response_completed"
            | "response_created"
            | "response_failed"
            | "response_incomplete"
            | "response_in_progress"
    )
}

fn build_task_link_index(inputs: &[PathBuf]) -> Result<HashMap<String, TaskLinkTarget>> {
    let mut links = HashMap::new();
    for path in inputs {
        let mut reader = crate::jsonl::open_jsonl_reader(path)?;
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let capture: Value = serde_json::from_slice(&line)
                .with_context(|| format!("parse task-link source {}", path.display()))?;
            register_task_links(&capture, &mut links)?;
        }
    }
    Ok(links)
}

fn register_task_links(capture: &Value, links: &mut HashMap<String, TaskLinkTarget>) -> Result<()> {
    let Some(task_session_id) = explicit_task_session_id(capture) else {
        return Ok(());
    };
    let source_capture_id = string_field(capture, "captureId").unwrap_or("missing");
    for (key, display) in namespaced_task_correlation_keys(capture) {
        let target = TaskLinkTarget {
            task_session_id: task_session_id.to_owned(),
            source_capture_id: source_capture_id.to_owned(),
        };
        if let Some(existing) = links.get(&key)
            && existing.task_session_id != target.task_session_id
        {
            bail!(
                "exact request identity {display:?} in one source namespace maps to multiple task Sessions: {} and {}",
                existing.task_session_id,
                target.task_session_id
            );
        }
        links.entry(key).or_insert(target);
    }
    Ok(())
}

fn apply_exact_task_link(
    capture: &mut Value,
    links: &HashMap<String, TaskLinkTarget>,
) -> Result<bool> {
    if explicit_task_session_id(capture).is_some() {
        return Ok(false);
    }
    let matched: Vec<(String, TaskLinkTarget)> = namespaced_task_correlation_keys(capture)
        .into_iter()
        .filter_map(|(key, display)| links.get(&key).cloned().map(|target| (display, target)))
        .collect();
    if matched.is_empty() {
        return Ok(false);
    }
    let task_ids: BTreeSet<&str> = matched
        .iter()
        .map(|(_, target)| target.task_session_id.as_str())
        .collect();
    if task_ids.len() != 1 {
        bail!("Capture matches exact request identities from multiple task Sessions");
    }
    let task_session_id = task_ids
        .iter()
        .next()
        .copied()
        .unwrap_or_default()
        .to_owned();
    let object = capture
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Capture must be an object for task linking"))?;
    let trace = object
        .entry("traceContext".to_owned())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("traceContext must be an object for task linking"))?;
    trace.insert("task_session_id".to_owned(), json!(task_session_id));

    let evidence = object
        .entry("fieldEvidence".to_owned())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("fieldEvidence must be an array for task linking"))?;
    let matched_keys: Vec<String> = matched.iter().map(|(key, _)| key.clone()).collect();
    let source_captures: BTreeSet<String> = matched
        .iter()
        .map(|(_, target)| target.source_capture_id.clone())
        .collect();
    evidence.push(json!({
        "field":"traceContext.task_session_id",
        "value":task_session_id,
        "source":"chiptrace.assembly.exact_request_identity_join",
        "producer":"chiptrace-assembly",
        "authority":"derived",
        "selected":true,
        "correlation_keys":matched_keys,
        "source_capture_ids":source_captures,
    }));
    Ok(true)
}

fn explicit_task_session_id(capture: &Value) -> Option<&str> {
    capture
        .pointer("/traceContext/task_session_id")
        .or_else(|| capture.get("task_session_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn capture_correlation_keys(capture: &Value) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for value in [
        string_field(capture, "upstreamRequestId"),
        header_string(capture, "responseHeaders", "x-request-id"),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.trim().is_empty())
    {
        keys.insert(format!("upstream:{value}"));
    }
    for value in [
        string_field(capture, "requestId"),
        header_string(capture, "requestHeaders", "x-client-request-id"),
        header_string(capture, "responseHeaders", "x-client-request-id"),
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

fn namespaced_task_correlation_keys(capture: &Value) -> Vec<(String, String)> {
    let namespace = string_field(capture, "sourceNamespace")
        .or_else(|| string_field(capture, "apiKeyFingerprint"))
        .unwrap_or("default");
    capture_correlation_keys(capture)
        .into_iter()
        .map(|display| (format!("{namespace}\0{display}"), display))
        .collect()
}

fn session_identity(
    capture_id: &str,
    request: &Map<String, Value>,
    trace: &Map<String, Value>,
) -> (String, String) {
    for field in [
        "task_session_id",
        "task_id",
        "session_id",
        "conversation_id",
        "trace_id",
        "turn_id",
        "thread_id",
    ] {
        if let Some(value) = trace
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            return (value.to_owned(), field.to_owned());
        }
    }
    if let Some(value) = request
        .get("prompt_cache_key")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return (value.to_owned(), "prompt_cache_key".to_owned());
    }
    (capture_id.to_owned(), "capture_id_fallback".to_owned())
}

fn session_group_key(value: &Value) -> String {
    let request = extract_body(value.get("requestBody"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let trace = collect_trace_context(value, &request);
    let capture_id = string_field(value, "captureId").unwrap_or("missing");
    let (identity, _) = session_identity(capture_id, &request, &trace);
    let namespace = string_field(value, "sourceNamespace")
        .or_else(|| string_field(value, "apiKeyFingerprint"))
        .unwrap_or("default");
    format!("{namespace}\0{identity}")
}

fn task_partition_key(value: &Value) -> String {
    let request = extract_body(value.get("requestBody"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let trace = collect_trace_context(value, &request);
    let capture_id = string_field(value, "captureId").unwrap_or("missing");
    let (session_identity, _) = session_identity(capture_id, &request, &trace);
    let task_identity = trace
        .get("root_session_id")
        .or_else(|| trace.get("parent_session_id"))
        .and_then(Value::as_str)
        .filter(|identity| !identity.trim().is_empty())
        .unwrap_or(&session_identity);
    let namespace = string_field(value, "sourceNamespace")
        .or_else(|| string_field(value, "apiKeyFingerprint"))
        .unwrap_or("default");
    format!("{namespace}\0{task_identity}")
}

fn infer_provider(
    capture: &Value,
    request: &Map<String, Value>,
    response: &Map<String, Value>,
) -> (String, Value) {
    if let Some(provider) = string_field(capture, "actualProvider") {
        return (
            provider.to_owned(),
            json!({
                "value": provider,
                "source": "capture.actualProvider",
                "authority": "proxy_attested",
                "attested": true,
            }),
        );
    }
    if let Some(provider) = response
        .get("provider")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return (
            provider.to_owned(),
            json!({
                "value": provider,
                "source": "response.provider",
                "authority": "provider_reported",
                "attested": true,
            }),
        );
    }
    if let Some(provider) = string_field(capture, "runtimeProvider") {
        return (
            provider.to_owned(),
            json!({
                "value": provider,
                "source": "capture.runtimeProvider",
                "authority": "runtime_attested",
                "attested": false,
                "scope": "client_model_route",
            }),
        );
    }
    if let Some(provider) = string_field(capture, "provider") {
        return (
            provider.to_owned(),
            json!({
                "value": provider,
                "source": "capture.provider",
                "authority": "producer_asserted",
                "attested": false,
            }),
        );
    }
    if let Some(provider) = request
        .get("provider")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return (
            provider.to_owned(),
            json!({
                "value": provider,
                "source": "request.provider",
                "authority": "client_asserted",
                "attested": false,
            }),
        );
    }
    let path = string_field(capture, "proxiedPath")
        .or_else(|| string_field(capture, "inboundPath"))
        .unwrap_or("");
    let model = request
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if path.ends_with("/messages") || model.contains("claude") {
        (
            "Anthropic".to_owned(),
            json!({
                "value": "Anthropic",
                "source": "derived.proxiedPath_or_model",
                "authority": "derived",
                "attested": false,
            }),
        )
    } else if model.contains("gemini") {
        (
            "Google".to_owned(),
            json!({
                "value": "Google",
                "source": "derived.model",
                "authority": "derived",
                "attested": false,
            }),
        )
    } else if model.contains("deepseek") {
        (
            "DeepSeek".to_owned(),
            json!({
                "value": "DeepSeek",
                "source": "derived.model",
                "authority": "derived",
                "attested": false,
            }),
        )
    } else if model.contains("glm") {
        (
            "Zhipu".to_owned(),
            json!({
                "value": "Zhipu",
                "source": "derived.model",
                "authority": "derived",
                "attested": false,
            }),
        )
    } else if model.contains("kimi") || model.starts_with('k') {
        (
            "Moonshot".to_owned(),
            json!({
                "value": "Moonshot",
                "source": "derived.model",
                "authority": "derived",
                "attested": false,
            }),
        )
    } else {
        (
            "OpenAI".to_owned(),
            json!({
                "value": "OpenAI",
                "source": "derived.model_or_default",
                "authority": "derived",
                "attested": false,
            }),
        )
    }
}

/// A rejected/invalid API attempt can legitimately have no model response or
/// billing row. Keep it in Raw and Session evidence, but do not make it part of
/// the denominator for provider/model attestation. Any successful or
/// model-bearing attempt remains subject to exact evidence checks.
fn model_attestation_applicable(capture: &ParsedCapture) -> bool {
    if capture.record_type != "api_snapshot" {
        return false;
    }
    if capture.gateway_evidence.is_some() || capture.response_model.is_some() {
        return true;
    }
    capture.response_status.is_none_or(|status| status < 400)
}

#[allow(clippy::too_many_arguments)]
fn collect_gateway_model_evidence(
    capture: &ParsedCapture,
    evidence: &Value,
    requested_models: &mut BTreeSet<String>,
    upstream_models: &mut BTreeSet<String>,
    providers: &mut BTreeSet<String>,
    mapping_chains: &mut BTreeSet<String>,
    conflicts: &mut BTreeSet<String>,
    verified_count: &mut u64,
) {
    let source = string_field(evidence, "source").unwrap_or("");
    let before = conflicts.len();
    if !matches!(source, "sub2api_usage_log" | "sub2api.usage_logs") {
        conflicts.insert(format!(
            "{}:unsupported_gateway_evidence_source",
            capture.capture_id
        ));
    }
    let request_id = string_field(evidence, "request_id").unwrap_or("");
    if !gateway_request_id_linked(capture, evidence, request_id) {
        conflicts.insert(format!(
            "{}:gateway_request_id_unlinked",
            capture.capture_id
        ));
    }
    let requested = string_field(evidence, "requested_model").unwrap_or("");
    if !requested.is_empty() {
        requested_models.insert(requested.to_owned());
    }
    if let Some(captured) = capture.model.as_deref()
        && !captured.eq_ignore_ascii_case(requested)
    {
        conflicts.insert(format!(
            "{}:gateway_requested_model_mismatch",
            capture.capture_id
        ));
    }
    let upstream = string_field(evidence, "upstream_model")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(requested);
    if !upstream.is_empty() {
        upstream_models.insert(upstream.to_owned());
    }
    if let Some(response) = capture.response_model.as_deref()
        && !response.eq_ignore_ascii_case(upstream)
    {
        conflicts.insert(format!(
            "{}:gateway_response_model_mismatch",
            capture.capture_id
        ));
    }
    if let Some(reported) = string_field(evidence, "response_model")
        && !reported.eq_ignore_ascii_case(upstream)
    {
        conflicts.insert(format!(
            "{}:gateway_reported_model_mismatch",
            capture.capture_id
        ));
    }
    let provider = string_field(evidence, "provider").unwrap_or("");
    if !provider.is_empty() {
        providers.insert(provider.to_owned());
    }
    let capture_provider_is_not_upstream = capture
        .provider_evidence
        .get("authority")
        .and_then(Value::as_str)
        == Some("derived")
        || capture
            .provider_evidence
            .get("source")
            .and_then(Value::as_str)
            == Some("capture.runtimeProvider");
    if !capture_provider_is_not_upstream && !provider_equivalent(provider, &capture.provider) {
        conflicts.insert(format!("{}:gateway_provider_mismatch", capture.capture_id));
    }
    if let Some(chain) = string_field(evidence, "model_mapping_chain")
        && !chain.trim().is_empty()
    {
        mapping_chains.insert(chain.to_owned());
    }
    if conflicts.len() == before {
        *verified_count = verified_count.saturating_add(1);
    }
}

fn gateway_request_id_linked(capture: &ParsedCapture, evidence: &Value, request_id: &str) -> bool {
    if request_id.is_empty() {
        return false;
    }
    if let Some(join) = capture.gateway_evidence_join.as_ref() {
        let Some(object) = join.as_object() else {
            return false;
        };
        if string_field(join, "schema_version") != Some("chiptrace.gateway-enrichment.v1")
            || string_field(join, "mode") != Some("exact_request_id")
            || string_field(join, "request_id") != Some(request_id)
            || string_field(join, "usage_fact_sha256")
                != Some(gateway_evidence_fingerprint(evidence).as_str())
        {
            return false;
        }
        let Some(captured) = string_field(join, "capture_request_id") else {
            return false;
        };
        let transformed = match string_field(join, "transform") {
            Some("exact") => captured.to_owned(),
            Some("sub2api_client_prefix") => format!("client:{captured}"),
            _ => return false,
        };
        if transformed != request_id {
            return false;
        }
        return match object.get("capture_field").and_then(Value::as_str) {
            Some("upstreamRequestId" | "responseHeaders.x-request-id") => {
                capture.upstream_request_id.as_deref() == Some(captured)
            }
            Some(
                "requestId"
                | "requestHeaders.x-client-request-id"
                | "responseHeaders.x-client-request-id",
            ) => capture.request_id.as_deref() == Some(captured),
            _ => false,
        };
    }
    capture.upstream_request_id.as_deref() == Some(request_id)
        || capture
            .request_id
            .as_deref()
            .is_some_and(|captured| request_id == format!("client:{captured}"))
}

fn gateway_usage_observation(evidence: Option<&Value>) -> UsageObservation {
    let Some(evidence) = evidence else {
        return UsageObservation::default();
    };
    let number = |field: &str| evidence.get(field).and_then(Value::as_u64);
    let non_cached_input = number("input_tokens");
    let cached_input = number("cache_read_tokens");
    let api_input = number("api_input_tokens").or_else(|| {
        non_cached_input
            .zip(cached_input)
            .map(|(input, cached)| input.saturating_add(cached))
    });
    let cache_creation = number("cache_creation_tokens");
    let output = number("output_tokens");
    let total = api_input
        .zip(output)
        .map(|(input, output)| input.saturating_add(output));
    UsageObservation {
        values: Usage {
            input_tokens: api_input.unwrap_or(0),
            cached_input_tokens: cached_input.unwrap_or(0),
            cache_creation_input_tokens: cache_creation.unwrap_or(0),
            output_tokens: output.unwrap_or(0),
            reasoning_tokens: 0,
            total_tokens: total.unwrap_or(0),
        },
        present: UsagePresence {
            input_tokens: api_input.is_some(),
            cached_input_tokens: cached_input.is_some(),
            cache_creation_input_tokens: cache_creation.is_some(),
            output_tokens: output.is_some(),
            reasoning_tokens: false,
            total_tokens: total.is_some(),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn select_usage_field(
    capture_id: &str,
    field: &str,
    response_value: u64,
    response_present: bool,
    gateway_value: u64,
    gateway_present: bool,
    selected: &mut u64,
    selected_sources: &mut Map<String, Value>,
    conflicts: &mut BTreeSet<String>,
) {
    if response_present {
        *selected = response_value;
        selected_sources.insert(field.to_owned(), json!("response_usage"));
        if gateway_present && response_value != gateway_value {
            conflicts.insert(format!(
                "{capture_id}:{field}:response={response_value}:sub2api={gateway_value}"
            ));
        }
    } else if gateway_present {
        *selected = gateway_value;
        selected_sources.insert(field.to_owned(), json!("sub2api_fallback"));
    } else {
        selected_sources.insert(field.to_owned(), json!("absent"));
    }
}

fn reconcile_capture_usage_observation(capture: &ParsedCapture) -> ReconciledCaptureUsage {
    let response = &capture.usage;
    let gateway_linked = capture.gateway_evidence.as_ref().is_some_and(|evidence| {
        let request_id = string_field(evidence, "request_id").unwrap_or("");
        gateway_request_id_linked(capture, evidence, request_id)
    });
    let gateway = gateway_usage_observation(
        gateway_linked
            .then_some(capture.gateway_evidence.as_ref())
            .flatten(),
    );
    let mut selected = Usage::default();
    let mut selected_sources = Map::new();
    let mut conflicts = BTreeSet::new();
    select_usage_field(
        &capture.capture_id,
        "input_tokens",
        response.values.input_tokens,
        response.present.input_tokens,
        gateway.values.input_tokens,
        gateway.present.input_tokens,
        &mut selected.input_tokens,
        &mut selected_sources,
        &mut conflicts,
    );
    select_usage_field(
        &capture.capture_id,
        "cached_input_tokens",
        response.values.cached_input_tokens,
        response.present.cached_input_tokens,
        gateway.values.cached_input_tokens,
        gateway.present.cached_input_tokens,
        &mut selected.cached_input_tokens,
        &mut selected_sources,
        &mut conflicts,
    );
    select_usage_field(
        &capture.capture_id,
        "cache_creation_input_tokens",
        response.values.cache_creation_input_tokens,
        response.present.cache_creation_input_tokens,
        gateway.values.cache_creation_input_tokens,
        gateway.present.cache_creation_input_tokens,
        &mut selected.cache_creation_input_tokens,
        &mut selected_sources,
        &mut conflicts,
    );
    select_usage_field(
        &capture.capture_id,
        "output_tokens",
        response.values.output_tokens,
        response.present.output_tokens,
        gateway.values.output_tokens,
        gateway.present.output_tokens,
        &mut selected.output_tokens,
        &mut selected_sources,
        &mut conflicts,
    );
    select_usage_field(
        &capture.capture_id,
        "reasoning_tokens",
        response.values.reasoning_tokens,
        response.present.reasoning_tokens,
        gateway.values.reasoning_tokens,
        gateway.present.reasoning_tokens,
        &mut selected.reasoning_tokens,
        &mut selected_sources,
        &mut conflicts,
    );
    select_usage_field(
        &capture.capture_id,
        "total_tokens",
        response.values.total_tokens,
        response.present.total_tokens,
        gateway.values.total_tokens,
        gateway.present.total_tokens,
        &mut selected.total_tokens,
        &mut selected_sources,
        &mut conflicts,
    );
    let derived_total = selected.input_tokens.saturating_add(selected.output_tokens);
    if selected.total_tokens < derived_total {
        selected.total_tokens = derived_total;
        if !response.present.total_tokens && !gateway.present.total_tokens {
            selected_sources.insert(
                "total_tokens".to_owned(),
                json!("derived_selected_input_plus_output"),
            );
        }
    }
    let evidence = json!({
        "capture_id": capture.capture_id,
        "policy": "response_usage_then_exact_sub2api_fallback.v1",
        "response": {
            "present": response.present.any(),
            "present_fields": response.present.fields(),
            "normalized": response.values.as_value(),
            "input_tokens_semantics": "api_total_input_including_cache_read",
        },
        "gateway": {
            "present": gateway.present.any(),
            "request_id_linked": gateway_linked,
            "present_fields": gateway.present.fields(),
            "normalized": gateway.values.as_value(),
            "input_tokens_semantics": "sub2api_non_cached_input_plus_cache_read",
        },
        "selected": selected.as_value(),
        "selected_sources": selected_sources,
        "conflicts": conflicts,
    });
    ReconciledCaptureUsage {
        values: selected,
        present: UsagePresence {
            input_tokens: response.present.input_tokens || gateway.present.input_tokens,
            cached_input_tokens: response.present.cached_input_tokens
                || gateway.present.cached_input_tokens,
            cache_creation_input_tokens: response.present.cache_creation_input_tokens
                || gateway.present.cache_creation_input_tokens,
            output_tokens: response.present.output_tokens || gateway.present.output_tokens,
            reasoning_tokens: response.present.reasoning_tokens || gateway.present.reasoning_tokens,
            total_tokens: response.present.total_tokens || gateway.present.total_tokens,
        },
        evidence,
        conflicts,
    }
}

fn usage_correlation_keys(capture: &ParsedCapture) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    if let Some(value) = capture
        .upstream_request_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        keys.insert(format!("upstream:{value}"));
    }
    if let Some(value) = capture
        .request_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        keys.insert(format!("client:{value}"));
    }
    if let Some(value) = capture
        .response_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        keys.insert(format!("response:{value}"));
    }
    if let Some(value) = capture
        .gateway_evidence
        .as_ref()
        .and_then(|evidence| string_field(evidence, "request_id"))
        .filter(|value| !value.trim().is_empty())
    {
        if value.starts_with("client:") {
            keys.insert(value.to_owned());
        } else {
            keys.insert(format!("upstream:{value}"));
        }
    }
    keys
}

fn usage_component_root(parents: &mut [usize], index: usize) -> usize {
    let mut root = index;
    while parents[root] != root {
        root = parents[root];
    }
    let mut cursor = index;
    while parents[cursor] != cursor {
        let next = parents[cursor];
        parents[cursor] = root;
        cursor = next;
    }
    root
}

fn join_usage_components(parents: &mut [usize], left: usize, right: usize) {
    let left = usage_component_root(parents, left);
    let right = usage_component_root(parents, right);
    if left == right {
        return;
    }
    let (root, child) = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    parents[child] = root;
}

fn reconcile_session_usage(
    captures: &[ParsedCapture],
) -> (Usage, Vec<Value>, Vec<Value>, BTreeSet<String>) {
    let observations: Vec<ReconciledCaptureUsage> = captures
        .iter()
        .map(reconcile_capture_usage_observation)
        .collect();
    let keys_by_capture: Vec<BTreeSet<String>> =
        captures.iter().map(usage_correlation_keys).collect();
    let mut parents: Vec<usize> = (0..captures.len()).collect();
    let mut key_owner: HashMap<&str, usize> = HashMap::new();
    for (index, keys) in keys_by_capture.iter().enumerate() {
        for key in keys {
            if let Some(previous) = key_owner.insert(key, index) {
                join_usage_components(&mut parents, previous, index);
            }
        }
    }

    let mut components: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..captures.len() {
        let root = usage_component_root(&mut parents, index);
        components.entry(root).or_default().push(index);
    }

    let mut total = Usage::default();
    let mut capture_evidence = Vec::with_capacity(captures.len());
    let mut settlement_evidence = Vec::new();
    let mut conflicts = BTreeSet::new();
    for indices in components.values() {
        let capture_ids: Vec<String> = indices
            .iter()
            .map(|index| captures[*index].capture_id.clone())
            .collect();
        let correlation_keys: BTreeSet<String> = indices
            .iter()
            .flat_map(|index| keys_by_capture[*index].iter().cloned())
            .collect();
        let identity = if correlation_keys.is_empty() {
            capture_ids.join("\0")
        } else {
            correlation_keys
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\0")
        };
        let component_id = format!("usage-{}", hex::encode(Sha256::digest(identity.as_bytes())));

        let upstream_ids: BTreeSet<&str> = indices
            .iter()
            .filter_map(|index| captures[*index].upstream_request_id.as_deref())
            .collect();
        let response_ids: BTreeSet<&str> = indices
            .iter()
            .filter_map(|index| captures[*index].response_id.as_deref())
            .collect();
        if upstream_ids.len() > 1 {
            conflicts.insert(format!(
                "{component_id}:multiple_upstream_request_ids:{}",
                upstream_ids.into_iter().collect::<Vec<_>>().join(",")
            ));
        }
        if response_ids.len() > 1 {
            conflicts.insert(format!(
                "{component_id}:multiple_response_ids:{}",
                response_ids.into_iter().collect::<Vec<_>>().join(",")
            ));
        }

        let mut component = Usage::default();
        let mut present = UsagePresence::default();
        let mut selected_capture_ids = Map::new();
        macro_rules! settle_field {
            ($field:ident) => {
                for index in indices {
                    let observation = &observations[*index];
                    if !observation.present.$field {
                        continue;
                    }
                    let candidate = observation.values.$field;
                    if present.$field {
                        if component.$field != candidate {
                            conflicts.insert(format!(
                                "{component_id}:{}:{}={}:{}={}",
                                stringify!($field),
                                selected_capture_ids
                                    .get(stringify!($field))
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown"),
                                component.$field,
                                captures[*index].capture_id,
                                candidate,
                            ));
                        }
                    } else {
                        component.$field = candidate;
                        present.$field = true;
                        selected_capture_ids.insert(
                            stringify!($field).to_owned(),
                            json!(captures[*index].capture_id),
                        );
                    }
                }
            };
        }
        settle_field!(input_tokens);
        settle_field!(cached_input_tokens);
        settle_field!(cache_creation_input_tokens);
        settle_field!(output_tokens);
        settle_field!(reasoning_tokens);
        settle_field!(total_tokens);
        component.total_tokens = component.total_tokens.max(
            component
                .input_tokens
                .saturating_add(component.output_tokens),
        );

        for index in indices {
            conflicts.extend(observations[*index].conflicts.clone());
            let mut evidence = observations[*index].evidence.clone();
            evidence["settlement_component_id"] = json!(component_id);
            capture_evidence.push(evidence);
        }
        if present.any() {
            total.add(&component);
            settlement_evidence.push(json!({
                "policy":"exact_request_component_once.v1",
                "component_id":component_id,
                "correlation_keys":correlation_keys,
                "capture_ids":capture_ids,
                "selected":component.as_value(),
                "selected_capture_ids":selected_capture_ids,
                "present_fields":present.fields(),
            }));
        }
    }
    (total, capture_evidence, settlement_evidence, conflicts)
}

#[cfg(test)]
fn reconcile_capture_usage(capture: &ParsedCapture) -> (Usage, Value, BTreeSet<String>) {
    let observation = reconcile_capture_usage_observation(capture);
    (
        observation.values,
        observation.evidence,
        observation.conflicts,
    )
}

fn provider_equivalent(left: &str, right: &str) -> bool {
    fn family(value: &str) -> &str {
        let value = value.trim();
        if value.eq_ignore_ascii_case("openai") || value.eq_ignore_ascii_case("chatgpt") {
            "openai"
        } else if value.eq_ignore_ascii_case("anthropic") || value.eq_ignore_ascii_case("claude") {
            "anthropic"
        } else if value.eq_ignore_ascii_case("google") || value.eq_ignore_ascii_case("gemini") {
            "google"
        } else if value.eq_ignore_ascii_case("zhipu") || value.eq_ignore_ascii_case("glm") {
            "zhipu"
        } else if value.eq_ignore_ascii_case("moonshot") || value.eq_ignore_ascii_case("kimi") {
            "moonshot"
        } else if value.eq_ignore_ascii_case("deepseek") {
            "deepseek"
        } else {
            value
        }
    }
    family(left).eq_ignore_ascii_case(family(right))
}

fn header_string<'a>(capture: &'a Value, field: &str, name: &str) -> Option<&'a str> {
    capture
        .get(field)
        .and_then(Value::as_object)
        .and_then(|headers| {
            headers.iter().find_map(|(key, value)| {
                key.eq_ignore_ascii_case(name)
                    .then(|| value.as_str())
                    .flatten()
            })
        })
        .filter(|value| !value.trim().is_empty())
}

fn parse_usage(value: Option<&Value>) -> UsageObservation {
    let usage = value.unwrap_or(&Value::Null);
    fn number(usage: &Value, fields: &[&str]) -> Option<u64> {
        fields
            .iter()
            .find_map(|field| usage.get(*field).and_then(Value::as_u64))
    }
    let input = number(usage, &["input_tokens", "prompt_tokens"]);
    let output = number(usage, &["output_tokens", "completion_tokens"]);
    let cached = number(usage, &["cached_input_tokens", "cache_read_input_tokens"]).or_else(|| {
        usage
            .pointer("/input_tokens_details/cached_tokens")
            .and_then(Value::as_u64)
    });
    let cache_creation = number(
        usage,
        &[
            "cache_creation_input_tokens",
            "cache_write_input_tokens",
            "cache_write_tokens",
        ],
    );
    let reasoning = number(usage, &["reasoning_tokens", "reasoning_output_tokens"]).or_else(|| {
        usage
            .pointer("/output_tokens_details/reasoning_tokens")
            .and_then(Value::as_u64)
    });
    let total = number(usage, &["total_tokens"]);
    let values = Usage {
        input_tokens: input.unwrap_or(0),
        cached_input_tokens: cached.unwrap_or(0),
        cache_creation_input_tokens: cache_creation.unwrap_or(0),
        output_tokens: output.unwrap_or(0),
        reasoning_tokens: reasoning.unwrap_or(0),
        total_tokens: total
            .unwrap_or(0)
            .max(input.unwrap_or(0).saturating_add(output.unwrap_or(0))),
    };
    UsageObservation {
        values,
        present: UsagePresence {
            input_tokens: input.is_some(),
            cached_input_tokens: cached.is_some(),
            cache_creation_input_tokens: cache_creation.is_some(),
            output_tokens: output.is_some(),
            reasoning_tokens: reasoning.is_some(),
            total_tokens: total.is_some(),
        },
    }
}

fn merge_messages(current: &mut Vec<Value>, candidate: &[Value]) -> u64 {
    let mut by_identity: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, message) in current.iter().enumerate() {
        by_identity
            .entry(message_identity(message))
            .or_default()
            .push(index);
    }
    let mut candidate_occurrences: HashMap<String, usize> = HashMap::new();
    let mut divergences = 0;
    for message in candidate {
        let identity = message_identity(message);
        let occurrence = candidate_occurrences.entry(identity.clone()).or_default();
        if let Some(index) = by_identity
            .get(&identity)
            .and_then(|indices| indices.get(*occurrence))
            .copied()
        {
            divergences += u64::from(merge_message(&mut current[index], message));
        } else {
            by_identity.entry(identity).or_default().push(current.len());
            current.push(message.clone());
        }
        *occurrence += 1;
    }
    divergences
}

fn message_identity(message: &Value) -> String {
    let role = string_field(message, "role").unwrap_or("unknown");
    if role == "system" {
        return "role:system".to_owned();
    }
    if role == "tool"
        && let Some(call_id) = string_field(message, "tool_call_id")
    {
        return format!("tool-result:{call_id}");
    }
    if role == "assistant"
        && let Some(calls) = message.get("tool_calls").and_then(Value::as_array)
        && !calls.is_empty()
    {
        let mut ids: Vec<&str> = calls
            .iter()
            .filter_map(|call| string_field(call, "id"))
            .collect();
        ids.sort_unstable();
        if ids.len() == calls.len() {
            return format!("tool-call:{}", ids.join("\0"));
        }
    }
    if let Some(id) = string_field(message, "id") {
        return format!("message:{id}");
    }
    let bytes = serde_json::to_vec(message).unwrap_or_default();
    format!("content:{}", hex::encode(Sha256::digest(bytes)))
}

fn merge_message(existing: &mut Value, candidate: &Value) -> bool {
    merge_value(existing, candidate, None)
}

fn merge_value(existing: &mut Value, candidate: &Value, field: Option<&str>) -> bool {
    if existing == candidate {
        return false;
    }
    if value_empty(existing) && !value_empty(candidate) {
        *existing = candidate.clone();
        return false;
    }
    match (existing, candidate) {
        (Value::Object(left), Value::Object(right)) => {
            let mut conflict = false;
            for (key, value) in right {
                if let Some(current) = left.get_mut(key) {
                    conflict |= merge_value(current, value, Some(key));
                } else {
                    left.insert(key.clone(), value.clone());
                }
            }
            conflict
        }
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => left
            .iter_mut()
            .zip(right)
            .fold(false, |conflict, (current, value)| {
                merge_value(current, value, field) || conflict
            }),
        (Value::String(left), Value::String(right))
            if field == Some("status") && left == "unknown" && right != "unknown" =>
        {
            *left = right.clone();
            false
        }
        _ => true,
    }
}

fn value_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        _ => false,
    }
}

fn terminal_session_status(captures: &[ParsedCapture]) -> String {
    for event in captures
        .iter()
        .rev()
        .flat_map(|capture| capture.lifecycle_events.iter().rev())
    {
        let event = normalize_event(event);
        if event.contains("cancel") || event.contains("abandon") || event.contains("abort") {
            return "cancelled".to_owned();
        }
        if event.contains("fail") {
            return "failed".to_owned();
        }
        if event.contains("terminate") {
            return "terminated".to_owned();
        }
    }
    if let Some(status) = captures
        .iter()
        .rev()
        .find(|capture| capture.final_snapshot)
        .and_then(|capture| capture.terminal_status.clone())
    {
        return status;
    }
    let capture = captures.last().expect("parsed capture list is empty");
    if let Some(status) = &capture.terminal_status {
        return status.clone();
    }
    if capture.response_status.is_some_and(|status| status >= 400) {
        return "failed".to_owned();
    }
    capture
        .response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("incomplete")
        .to_owned()
}

fn normalize_event(event: &str) -> String {
    event
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', ':'], "_")
}

fn terminal_lifecycle_event(event: &str) -> bool {
    let event = normalize_event(event);
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
    ) || event.starts_with("session_cancel")
        || event.starts_with("task_cancel")
        || event.starts_with("session_fail")
        || event.starts_with("task_fail")
}

fn unresolved_tool_call_ids(messages: &[Value]) -> Vec<String> {
    let calls: BTreeSet<String> = messages
        .iter()
        .filter_map(|message| message.get("tool_calls").and_then(Value::as_array))
        .flatten()
        .filter_map(|call| {
            call.get("id")
                .or_else(|| call.get("call_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let results: BTreeSet<String> = messages
        .iter()
        .filter(|message| string_field(message, "role") == Some("tool"))
        .filter_map(|message| {
            message
                .get("tool_call_id")
                .or_else(|| message.get("call_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    calls.difference(&results).cloned().collect()
}

fn tool_name(tool: &Value) -> Option<&str> {
    tool.get("function")
        .unwrap_or(tool)
        .get("name")
        .and_then(Value::as_str)
}

fn argument_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| serde_json::to_string(value).unwrap_or_default())
}

fn content_text(value: Option<&Value>) -> Option<String> {
    fn collect(value: &Value, output: &mut Vec<String>) {
        match value {
            Value::String(text) => output.push(text.clone()),
            Value::Array(items) => {
                for item in items {
                    collect(item, output);
                }
            }
            Value::Object(object) => {
                for field in ["text", "content", "output_text", "input_text"] {
                    if let Some(value) = object.get(field) {
                        collect(value, output);
                    }
                }
            }
            _ => {}
        }
    }
    let mut values = Vec::new();
    collect(value?, &mut values);
    Some(values.join("\n"))
}

fn partition_index(key: &str, partitions: usize) -> usize {
    let digest = Sha256::digest(key.as_bytes());
    u64::from_le_bytes(digest[..8].try_into().unwrap()) as usize % partitions
}

fn discover_raw_sources(
    inputs: &[PathBuf],
    capture_inputs: &[PathBuf],
) -> Result<Vec<RawSourceLineage>> {
    let mut sources: BTreeMap<String, RawSourceLineage> = BTreeMap::new();
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
        let path = canonical.join("RAW_SOURCE.json");
        if path.is_file() {
            has_lineage = true;
            let source: RawSourceLineage = serde_json::from_slice(&fs::read(&path)?)
                .with_context(|| format!("parse raw source lineage {}", path.display()))?;
            insert_raw_source(&mut sources, source)?;
        }
        let set_path = canonical.join("RAW_SOURCES.json");
        if set_path.is_file() {
            has_lineage = true;
            let values: Vec<RawSourceLineage> = serde_json::from_slice(&fs::read(&set_path)?)
                .with_context(|| format!("parse raw source lineage {}", set_path.display()))?;
            for source in values {
                insert_raw_source(&mut sources, source)?;
            }
        }
        if has_lineage {
            lineaged.push(canonical);
        } else {
            unlineaged.push(canonical);
        }
    }
    if !lineaged.is_empty() && !unlineaged.is_empty() {
        bail!(
            "cannot mix Raw-lineaged and unlineaged capture inputs: lineaged={lineaged:?}, unlineaged={unlineaged:?}"
        );
    }
    Ok(sources.into_values().collect())
}

fn insert_raw_source(
    sources: &mut BTreeMap<String, RawSourceLineage>,
    source: RawSourceLineage,
) -> Result<()> {
    validate_raw_source(&source)?;
    if let Some(existing) = sources.get(&source.archive_id)
        && existing != &source
    {
        bail!(
            "conflicting raw source lineage for archive {}",
            source.archive_id
        );
    }
    sources.insert(source.archive_id.clone(), source);
    Ok(())
}

fn validate_raw_source(source: &RawSourceLineage) -> Result<()> {
    if source.schema_version != RAW_LINEAGE_SCHEMA_VERSION {
        bail!(
            "unsupported raw source lineage schema {}",
            source.schema_version
        );
    }
    if source.archive_id.trim().is_empty()
        || source.completeness != "complete"
        || source.segment_count == 0
        || source.checkpoint_key.trim().is_empty()
        || source.manifest_key.trim().is_empty()
        || !valid_sha256(&source.checkpoint_sha256)
        || !valid_sha256(&source.manifest_sha256)
    {
        bail!(
            "raw source archive {} is incomplete or invalid",
            source.archive_id
        );
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
                    "refusing unstable open WAL segment {}; run chiptrace collector flush first",
                    input.display()
                );
            }
            if !capture_input_name(name) {
                bail!("unsupported capture input: {}", input.display());
            }
            output.push(input.canonicalize()?);
            continue;
        }
        if input.is_dir() {
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
            continue;
        }
        bail!("capture input does not exist: {}", input.display());
    }
    output.sort();
    output.dedup();
    Ok(output)
}

fn capture_input_name(name: &str) -> bool {
    name.ends_with(".ndjson") || name.ends_with(".jsonl") || name.ends_with(".jsonl.zst")
}

fn sync_tree(root: &Path) -> Result<()> {
    for entry in WalkDir::new(root).contents_first(true) {
        let entry = entry?;
        if entry.file_type().is_file() {
            File::open(entry.path())?.sync_all()?;
        } else if entry.file_type().is_dir() {
            sync_directory(entry.path())?;
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_raw_lineage() -> RawSourceLineage {
        RawSourceLineage {
            schema_version: RAW_LINEAGE_SCHEMA_VERSION.to_owned(),
            archive_id: "archive-test".to_owned(),
            completeness: "complete".to_owned(),
            checkpoint_key: "raw/archive-test/CHECKPOINT.json".to_owned(),
            checkpoint_sha256: "a".repeat(64),
            manifest_key: "raw/archive-test/manifest.json".to_owned(),
            manifest_sha256: "b".repeat(64),
            segment_count: 1,
            total_records: 1,
            total_bytes: 1,
        }
    }

    fn native_runtime_capture(
        seq: u64,
        payload: Value,
        thread_id: Option<&str>,
        turn_id: Option<&str>,
        parent_thread_id: Option<&str>,
    ) -> Value {
        let raw = json!({
            "schema_version":1,
            "seq":seq,
            "wall_time_unix_ms":1787961600000_i64 + seq as i64,
            "rollout_id":"rollout-1",
            "thread_id":thread_id,
            "codex_turn_id":turn_id,
            "payload":payload,
        });
        json!({
            "version":"chiptrace.capture.v2",
            "recordType":"rollout_event",
            "captureId":format!("cap-native-{seq:020}"),
            "sourceNamespace":"fixture",
            "receivedAt":"2026-08-29T00:00:00Z",
            "traceContext":{"task_session_id":"task-native"},
            "rolloutEvent":{
                "source":"codex_rollout_trace_bundle",
                "source_session_id":"rollout-1",
                "source_ordinal":seq,
                "source_line":serde_json::to_string(&raw).unwrap(),
                "bundle_trace_id":"trace-1",
                "parent_agent_thread_id":parent_thread_id,
                "classification":"known",
                "unmapped_tool":false
            }
        })
    }

    fn retarget_native_runtime_capture(
        mut capture: Value,
        bundle_trace_id: &str,
        rollout_id: &str,
    ) -> Value {
        capture["captureId"] = json!(format!(
            "cap-native-{bundle_trace_id}-{rollout_id}-{}",
            capture["rolloutEvent"]["source_ordinal"]
                .as_u64()
                .unwrap_or_default()
        ));
        capture["rolloutEvent"]["bundle_trace_id"] = json!(bundle_trace_id);
        capture["rolloutEvent"]["source_session_id"] = json!(rollout_id);
        let mut source: Value =
            serde_json::from_str(capture["rolloutEvent"]["source_line"].as_str().unwrap()).unwrap();
        source["rollout_id"] = json!(rollout_id);
        capture["rolloutEvent"]["source_line"] = json!(serde_json::to_string(&source).unwrap());
        capture
    }

    #[test]
    fn codex_native_usage_aliases_preserve_reasoning_and_cache_write_tokens() {
        let usage = parse_usage(Some(&json!({
            "input_tokens":48989,
            "cached_input_tokens":41216,
            "cache_write_input_tokens":17,
            "output_tokens":481,
            "reasoning_output_tokens":239,
            "total_tokens":49470
        })));
        assert_eq!(usage.values.input_tokens, 48989);
        assert_eq!(usage.values.cached_input_tokens, 41216);
        assert_eq!(usage.values.cache_creation_input_tokens, 17);
        assert_eq!(usage.values.output_tokens, 481);
        assert_eq!(usage.values.reasoning_tokens, 239);
        assert_eq!(usage.values.total_tokens, 49470);
        assert!(usage.present.reasoning_tokens);
        assert!(usage.present.cache_creation_input_tokens);
    }

    #[test]
    fn multiple_terminal_rollouts_form_a_complete_task_scoped_runtime_forest() {
        let captures = vec![
            retarget_native_runtime_capture(
                native_runtime_capture(1, json!({"type":"rollout_started"}), None, None, None),
                "trace-a",
                "rollout-a",
            ),
            retarget_native_runtime_capture(
                native_runtime_capture(
                    2,
                    json!({"type":"rollout_ended","status":"completed"}),
                    None,
                    None,
                    None,
                ),
                "trace-a",
                "rollout-a",
            ),
            retarget_native_runtime_capture(
                native_runtime_capture(3, json!({"type":"rollout_started"}), None, None, None),
                "trace-b",
                "rollout-b",
            ),
            retarget_native_runtime_capture(
                native_runtime_capture(
                    4,
                    json!({"type":"rollout_ended","status":"completed"}),
                    None,
                    None,
                    None,
                ),
                "trace-b",
                "rollout-b",
            ),
        ];
        let (session, _, _) = assemble_group(captures).unwrap();
        assert_eq!(session["meta"]["runtime_dag"]["complete"], true);
        assert_eq!(
            session["meta"]["runtime_dag"]["root_mode"],
            "task_scoped_rollout_forest"
        );
        assert_eq!(
            session["meta"]["runtime_dag"]["task_session_ids"],
            json!(["task-native"])
        );
        assert_eq!(
            session["meta"]["runtime_dag"]["roots"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn native_runtime_dag_rejects_conflicting_tool_terminal_statuses() {
        let captures = vec![
            native_runtime_capture(1, json!({"type":"rollout_started"}), None, None, None),
            native_runtime_capture(
                2,
                json!({
                    "type":"tool_call_started",
                    "tool_call_id":"tool-1",
                    "requester":{"type":"model"}
                }),
                Some("thread-1"),
                Some("turn-1"),
                None,
            ),
            native_runtime_capture(
                3,
                json!({"type":"tool_call_runtime_started","tool_call_id":"tool-1"}),
                Some("thread-1"),
                Some("turn-1"),
                None,
            ),
            native_runtime_capture(
                4,
                json!({"type":"tool_call_ended","tool_call_id":"tool-1","status":"success"}),
                Some("thread-1"),
                Some("turn-1"),
                None,
            ),
            native_runtime_capture(
                5,
                json!({"type":"tool_call_runtime_ended","tool_call_id":"tool-1","status":"failed"}),
                Some("thread-1"),
                Some("turn-1"),
                None,
            ),
            native_runtime_capture(
                6,
                json!({"type":"rollout_ended","status":"completed"}),
                None,
                None,
                None,
            ),
        ];

        let (session, _, _) = assemble_group(captures).unwrap();
        let dag = &session["meta"]["runtime_dag"];
        assert_eq!(dag["complete"], false);
        assert_eq!(
            dag["status_conflict_node_ids"],
            json!(["trace-1:tool:tool-1"])
        );
    }

    #[test]
    fn native_dispatch_completion_keeps_real_failed_runtime_status() {
        let captures = vec![
            native_runtime_capture(1, json!({"type":"rollout_started"}), None, None, None),
            native_runtime_capture(
                2,
                json!({
                    "type":"tool_call_started",
                    "tool_call_id":"tool-1",
                    "requester":{"type":"runtime"}
                }),
                None,
                None,
                None,
            ),
            native_runtime_capture(
                3,
                json!({"type":"tool_call_runtime_started","tool_call_id":"tool-1"}),
                None,
                None,
                None,
            ),
            native_runtime_capture(
                4,
                json!({"type":"tool_call_runtime_ended","tool_call_id":"tool-1","status":"failed"}),
                None,
                None,
                None,
            ),
            native_runtime_capture(
                5,
                json!({"type":"tool_call_ended","tool_call_id":"tool-1","status":"completed"}),
                None,
                None,
                None,
            ),
            native_runtime_capture(
                6,
                json!({"type":"rollout_ended","status":"completed"}),
                None,
                None,
                None,
            ),
        ];

        let (session, _, _) = assemble_group(captures).unwrap();
        let dag = &session["meta"]["runtime_dag"];
        assert_eq!(dag["complete"], true);
        assert!(
            dag["status_conflict_node_ids"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(dag["nodes"].as_array().unwrap().iter().any(|node| {
            node["source_id"] == "tool-1"
                && node["status"] == "failed"
                && node["dispatch_status"] == "completed"
                && node["runtime_status"] == "failed"
        }));
    }

    #[test]
    fn native_inference_requires_an_exact_api_capture_correlation() {
        let runtime = native_runtime_capture(
            1,
            json!({
                "type":"inference_completed",
                "inference_call_id":"inference-1",
                "response_id":"response-1",
                "upstream_request_id":"upstream-1"
            }),
            Some("thread-1"),
            Some("turn-1"),
            None,
        );
        let api = json!({
            "version":"chiptrace.capture.v2",
            "recordType":"api_snapshot",
            "captureId":"cap-api-upstream-1",
            "sourceNamespace":"fixture",
            "receivedAt":"2026-08-29T00:00:01Z",
            "traceContext":{"task_session_id":"task-native"},
            "upstreamRequestId":"upstream-1",
            "responseBody":{"kind":"json","value":{"id":"response-1","status":"completed"}}
        });

        let (matched, _, _) = assemble_group(vec![runtime.clone(), api]).unwrap();
        assert_eq!(
            matched["meta"]["inference_api_conservation"]["complete"],
            true
        );
        assert_eq!(
            matched["meta"]["inference_api_conservation"]["matched_runtime_inferences"],
            1
        );

        let (missing, _, _) = assemble_group(vec![runtime]).unwrap();
        assert_eq!(
            missing["meta"]["inference_api_conservation"]["complete"],
            false
        );
        assert_eq!(
            missing["meta"]["inference_api_conservation"]["missing_api_capture_keys"],
            json!(["upstream_request_id:upstream-1"])
        );
    }

    #[test]
    fn rollout_session_and_thread_ids_are_scoped_sets_not_trace_conflicts() {
        let captures = vec![
            json!({
                "recordType":"lifecycle_event",
                "captureId":"cap-task-start",
                "sourceNamespace":"fixture",
                "receivedAt":"2026-08-29T00:00:00Z",
                "traceContext":{
                    "task_session_id":"task-scoped-ids",
                    "session_id":"rollout-a",
                    "thread_id":"thread-a"
                },
                "lifecycleEvent":{
                    "type":"task_start",
                    "status":"running",
                    "occurred_at":"2026-08-29T00:00:00Z"
                }
            }),
            json!({
                "recordType":"lifecycle_event",
                "captureId":"cap-task-end",
                "sourceNamespace":"fixture",
                "receivedAt":"2026-08-29T00:00:01Z",
                "traceContext":{
                    "task_session_id":"task-scoped-ids",
                    "session_id":"rollout-b",
                    "thread_id":"thread-b"
                },
                "lifecycleEvent":{
                    "type":"task_end",
                    "status":"completed",
                    "occurred_at":"2026-08-29T00:00:01Z"
                }
            }),
        ];
        let (session, _, _) = assemble_group(captures).unwrap();
        assert_eq!(
            session["meta"]["trace"]["session_ids"],
            json!(["rollout-a", "rollout-b"])
        );
        assert_eq!(
            session["meta"]["trace"]["thread_ids"],
            json!(["thread-a", "thread-b"])
        );
        assert!(session["meta"]["trace"].get("session_id").is_none());
        assert!(session["meta"]["trace"].get("thread_id").is_none());
        assert!(
            session["meta"]["trace_conflicts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn only_called_tool_schema_conflicts_block_delivery() {
        let messages = vec![json!({
            "role":"assistant",
            "content":"",
            "tool_calls":[{
                "id":"call-1",
                "type":"function",
                "function":{"name":"exec_command","arguments":"{}"}
            }]
        })];
        let observed = BTreeSet::from(["exec".to_owned(), "exec_command".to_owned()]);
        let (blocking, uncalled) = partition_schema_conflicts(&messages, &observed);
        assert_eq!(blocking, BTreeSet::from(["exec_command".to_owned()]));
        assert_eq!(uncalled, BTreeSet::from(["exec".to_owned()]));
    }

    #[test]
    fn exact_request_identity_links_api_capture_to_harness_task() {
        let source = json!({
            "captureId":"cap-runtime",
            "upstreamRequestId":"request-1",
            "traceContext":{"task_session_id":"task-1"}
        });
        let mut api = json!({
            "captureId":"cap-api",
            "recordType":"api_snapshot",
            "responseHeaders":{"x-request-id":"request-1"},
            "traceContext":{"thread_id":"codex-thread-1"}
        });
        let mut links = HashMap::new();
        register_task_links(&source, &mut links).unwrap();
        assert!(apply_exact_task_link(&mut api, &links).unwrap());
        assert_eq!(
            api.pointer("/traceContext/task_session_id"),
            Some(&json!("task-1"))
        );
        assert_eq!(session_group_key(&api), "default\0task-1");
        let evidence = api["fieldEvidence"].as_array().unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0]["authority"], "derived");
        assert_eq!(
            evidence[0]["correlation_keys"],
            json!(["upstream:request-1"])
        );
    }

    #[test]
    fn exact_request_identity_collision_is_rejected() {
        let mut links = HashMap::new();
        register_task_links(
            &json!({
                "captureId":"cap-one",
                "upstreamRequestId":"request-shared",
                "traceContext":{"task_session_id":"task-one"}
            }),
            &mut links,
        )
        .unwrap();
        let error = register_task_links(
            &json!({
                "captureId":"cap-two",
                "upstreamRequestId":"request-shared",
                "traceContext":{"task_session_id":"task-two"}
            }),
            &mut links,
        )
        .unwrap_err();
        assert!(error.to_string().contains("multiple task Sessions"));
    }

    #[test]
    fn exact_request_identity_is_isolated_by_source_namespace() {
        let mut links = HashMap::new();
        register_task_links(
            &json!({
                "captureId":"cap-one","sourceNamespace":"tenant-one",
                "upstreamRequestId":"request-shared",
                "traceContext":{"task_session_id":"task-one"}
            }),
            &mut links,
        )
        .unwrap();
        register_task_links(
            &json!({
                "captureId":"cap-two","sourceNamespace":"tenant-two",
                "upstreamRequestId":"request-shared",
                "traceContext":{"task_session_id":"task-two"}
            }),
            &mut links,
        )
        .unwrap();
        let mut api = json!({
            "captureId":"cap-api","sourceNamespace":"tenant-two",
            "upstreamRequestId":"request-shared","traceContext":{}
        });
        assert!(apply_exact_task_link(&mut api, &links).unwrap());
        assert_eq!(
            api.pointer("/traceContext/task_session_id"),
            Some(&json!("task-two"))
        );
    }

    #[test]
    fn native_runtime_dag_preserves_code_mode_subagent_and_terminal_states() {
        let events = vec![
            native_runtime_capture(1, json!({"type":"rollout_started"}), None, None, None),
            native_runtime_capture(
                2,
                json!({"type":"thread_started","thread_id":"root"}),
                Some("root"),
                None,
                None,
            ),
            native_runtime_capture(
                3,
                json!({"type":"codex_turn_started","codex_turn_id":"turn-root"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                4,
                json!({"type":"inference_started","inference_call_id":"inf-1","model":"gpt-5.6-sol","provider_name":"openai"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                5,
                json!({"type":"inference_failed","inference_call_id":"inf-1"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                6,
                json!({"type":"code_cell_started","runtime_cell_id":"cell-1","model_visible_call_id":"exec-1"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                7,
                json!({"type":"tool_call_started","tool_call_id":"tool-1","requester":{"type":"code_cell","runtime_cell_id":"cell-1"},"code_mode_runtime_tool_id":"runtime-tool-1"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                8,
                json!({"type":"tool_call_ended","tool_call_id":"tool-1","status":"failed"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                9,
                json!({"type":"code_cell_ended","runtime_cell_id":"cell-1","status":"cancelled"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                10,
                json!({"type":"compaction_request_started","compaction_request_id":"compact-1"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                11,
                json!({"type":"compaction_request_completed","compaction_request_id":"compact-1"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                12,
                json!({"type":"thread_started","thread_id":"child"}),
                Some("child"),
                None,
                Some("root"),
            ),
            native_runtime_capture(
                13,
                json!({"type":"codex_turn_started","codex_turn_id":"turn-child"}),
                Some("child"),
                Some("turn-child"),
                Some("root"),
            ),
            native_runtime_capture(
                14,
                json!({"type":"codex_turn_ended","codex_turn_id":"turn-child","status":"completed"}),
                Some("child"),
                Some("turn-child"),
                Some("root"),
            ),
            native_runtime_capture(
                15,
                json!({"type":"thread_ended","thread_id":"child","status":"completed"}),
                Some("child"),
                None,
                Some("root"),
            ),
            native_runtime_capture(
                16,
                json!({"type":"agent_result_observed","child_thread_id":"child","parent_thread_id":"root"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                17,
                json!({"type":"codex_turn_ended","codex_turn_id":"turn-root","status":"completed"}),
                Some("root"),
                Some("turn-root"),
                None,
            ),
            native_runtime_capture(
                18,
                json!({"type":"thread_ended","thread_id":"root","status":"completed"}),
                Some("root"),
                None,
                None,
            ),
            native_runtime_capture(
                19,
                json!({"type":"rollout_ended","status":"completed"}),
                None,
                None,
                None,
            ),
        ];
        let (session, _, _) = assemble_group(events).unwrap();
        let dag = &session["meta"]["runtime_dag"];
        assert_eq!(dag["applicable"], true);
        assert_eq!(dag["complete"], true);
        assert_eq!(dag["kind_counts"]["thread"], 2);
        assert_eq!(dag["kind_counts"]["tool"], 1);
        assert_eq!(dag["kind_counts"]["compaction"], 1);
        assert!(dag["open_node_ids"].as_array().unwrap().is_empty());
        assert!(dag["unresolved_node_ids"].as_array().unwrap().is_empty());
        let edges = dag["edges"].as_array().unwrap();
        assert!(edges.iter().any(|edge| edge["kind"] == "nested_tool"));
        assert!(edges.iter().any(|edge| edge["kind"] == "agent_result"));
        let nodes = dag["nodes"].as_array().unwrap();
        assert!(nodes.iter().any(|node| {
            node["node_type"] == "code_cell" && node["disposition"] == "abandoned"
        }));
        assert!(
            nodes
                .iter()
                .any(|node| { node["node_type"] == "tool" && node["status"] == "failed" })
        );
    }

    #[test]
    fn native_runtime_dag_marks_open_tail_incomplete() {
        let events = vec![
            native_runtime_capture(1, json!({"type":"rollout_started"}), None, None, None),
            native_runtime_capture(
                2,
                json!({"type":"thread_started","thread_id":"root"}),
                Some("root"),
                None,
                None,
            ),
            native_runtime_capture(
                3,
                json!({"type":"tool_call_started","tool_call_id":"tool-open","requester":{"type":"model"}}),
                Some("root"),
                Some("turn-open"),
                None,
            ),
        ];
        let (session, _, _) = assemble_group(events).unwrap();
        let dag = &session["meta"]["runtime_dag"];
        assert_eq!(dag["complete"], false);
        assert_eq!(dag["disposition_counts"]["open_tail"], 3);
        assert_eq!(dag["open_node_ids"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn native_runtime_order_parses_variable_rfc3339_fraction_widths() {
        let mut rollout_start =
            native_runtime_capture(1, json!({"type":"rollout_started"}), None, None, None);
        rollout_start["receivedAt"] = json!("2026-08-29T00:00:00.8Z");
        let mut cell_start = native_runtime_capture(
            2,
            json!({"type":"code_cell_started","runtime_cell_id":"cell-1","model_visible_call_id":"exec-1"}),
            Some("root"),
            Some("turn-1"),
            None,
        );
        cell_start["receivedAt"] = json!("2026-08-29T00:00:00.87Z");
        let mut cell_end = native_runtime_capture(
            3,
            json!({"type":"code_cell_ended","runtime_cell_id":"cell-1","status":"completed"}),
            Some("root"),
            Some("turn-1"),
            None,
        );
        cell_end["receivedAt"] = json!("2026-08-29T00:00:00.874Z");
        let mut rollout_end = native_runtime_capture(
            4,
            json!({"type":"rollout_ended","status":"completed"}),
            None,
            None,
            None,
        );
        rollout_end["receivedAt"] = json!("2026-08-29T00:00:00.9Z");

        let (session, _, _) =
            assemble_group(vec![cell_end, rollout_end, cell_start, rollout_start]).unwrap();
        let dag = &session["meta"]["runtime_dag"];
        assert!(dag["open_node_ids"].as_array().unwrap().is_empty());
        assert!(dag["nodes"].as_array().unwrap().iter().any(|node| {
            node["node_type"] == "code_cell"
                && node["status"] == "completed"
                && node["disposition"] == "executed"
        }));
    }

    #[test]
    fn code_mode_parent_call_is_excluded_only_with_native_cell_evidence() {
        let api = json!({
            "recordType":"api_snapshot",
            "captureId":"cap-code-mode-api",
            "sourceNamespace":"fixture",
            "receivedAt":"2026-08-29T00:00:00Z",
            "traceContext":{"task_session_id":"task-native"},
            "requestBody":{"kind":"json","value":{
                "model":"gpt-5.6-sol",
                "instructions":"system",
                "input":[
                    {"type":"message","id":"user-1","role":"user","content":"run checks"},
                    {"type":"custom_tool_call","id":"outer-item","call_id":"outer-exec","name":"exec","input":"tools.exec_command({cmd:'true'})"},
                    {"type":"custom_tool_call_output","id":"outer-result-1","call_id":"outer-exec","output":"first notification"},
                    {"type":"custom_tool_call_output","id":"outer-result-2","call_id":"outer-exec","output":"second notification"}
                ]
            }},
            "responseBody":{"kind":"json","value":{
                "id":"response-code-mode",
                "model":"gpt-5.6-sol",
                "status":"completed",
                "output":[
                    {"type":"custom_tool_call","id":"outer-item","call_id":"outer-exec","name":"exec","input":"tools.exec_command({cmd:'true'})"}
                ]
            }}
        });
        let cell = native_runtime_capture(
            1,
            json!({
                "type":"code_cell_started",
                "runtime_cell_id":"cell-1",
                "model_visible_call_id":"outer-exec"
            }),
            Some("root"),
            Some("turn-1"),
            None,
        );
        let inner = json!({
            "recordType":"tool_execution",
            "captureId":"cap-code-mode-inner",
            "sourceNamespace":"fixture",
            "receivedAt":"2026-08-29T00:00:01Z",
            "traceContext":{"task_session_id":"task-native"},
            "toolExecution":{
                "call_id":"inner-call",
                "name":"exec_command",
                "initiator":"assistant",
                "status":"success",
                "arguments":{"cmd":"true"},
                "result":{"exit_code":0},
                "schema":{
                    "name":"exec_command",
                    "description":"Run a command.",
                    "parameters":{
                        "type":"object",
                        "properties":{"cmd":{"type":"string","description":"Command."}},
                        "required":["cmd"]
                    }
                }
            }
        });

        let (session, _, _) = assemble_group(vec![api, cell, inner]).unwrap();
        let messages = session["messages"].as_array().unwrap();
        let calls: Vec<&Value> = messages
            .iter()
            .filter_map(|message| message.get("tool_calls").and_then(Value::as_array))
            .flatten()
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["id"], "inner-call");
        let results: Vec<&Value> = messages
            .iter()
            .filter(|message| message["role"] == "tool")
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["tool_call_id"], "inner-call");
        assert_eq!(
            session["meta"]["code_mode_message_projection"]["excluded_parent_call_ids"],
            json!(["outer-exec"])
        );
        assert_eq!(
            session["meta"]["code_mode_message_projection"]["excluded_tool_calls"],
            2
        );
        assert_eq!(
            session["meta"]["code_mode_message_projection"]["excluded_tool_results"],
            2
        );
        assert_eq!(
            session["meta"]["runtime_dag"]["kind_counts"]["code_cell"],
            1
        );
    }

    #[test]
    fn custom_tool_call_is_not_filtered_without_native_cell_evidence() {
        let mut messages = vec![
            json!({
                "role":"assistant",
                "content":"",
                "tool_calls":[{
                    "id":"custom-call",
                    "type":"function",
                    "function":{"name":"exec","arguments":"{}"}
                }]
            }),
            json!({
                "role":"tool",
                "tool_call_id":"custom-call",
                "content":"observed output"
            }),
        ];
        let audit = exclude_code_mode_parent_messages(&mut messages, &BTreeSet::new());
        assert_eq!(messages.len(), 2);
        assert_eq!(audit["excluded_tool_calls"], 0);
        assert_eq!(audit["excluded_tool_results"], 0);
    }

    #[test]
    fn additional_tools_in_responses_input_are_extracted() {
        let capture = json!({
            "captureId": "cap-assembly-1",
            "sourceNamespace": "fixture",
            "startedAt": "2026-08-27T00:00:00Z",
            "proxiedPath": "/v1/responses",
            "traceContext": {"session_id": "session-one"},
            "requestBody": {"kind": "json", "value": {
                "model": "gpt-5.6-sol",
                "instructions": "system",
                "input": [
                    {"type": "additional_tools", "tools": [{
                        "name": "exec_command",
                        "description": "Run a command.",
                        "parameters": {"type": "object", "properties": {
                            "cmd": {"type": "string", "description": "Command."}
                        }}
                    }]},
                    {"type": "message", "role": "user", "content": "run tests"}
                ]
            }},
            "responseStatus": 200,
            "responseBody": {"kind": "json", "value": {
                "id": "resp-1",
                "status": "completed",
                "output": [{"type": "function_call", "call_id": "c1", "name": "exec_command", "arguments": "{}"}],
                "usage": {"input_tokens": 10, "output_tokens": 2}
            }}
        });
        let (session, _, _) = assemble_group(vec![capture]).unwrap();
        assert_eq!(session["tools"][0]["name"], "exec_command");
        assert!(
            session["tools"][0]["schema_version"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            session["messages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|message| message.get("tool_calls").is_some())
                .count(),
            1
        );
        assert_eq!(
            session["messages"].as_array().unwrap().last().unwrap()["tool_calls"][0]["execution_status"],
            "open_tail"
        );
    }

    fn usage_capture(response_usage: Option<Value>, non_cached_input: u64) -> ParsedCapture {
        let mut response = json!({
            "id":"response-usage",
            "model":"gpt-5.6-sol",
            "status":"completed",
            "output":[]
        });
        if let Some(usage) = response_usage {
            response["usage"] = usage;
        }
        parse_capture(json!({
            "recordType":"api_snapshot",
            "captureId":"cap-usage",
            "sourceNamespace":"fixture",
            "upstreamRequestId":"request-usage",
            "traceContext":{"task_session_id":"task-usage"},
            "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol","input":[]}},
            "responseBody":{"kind":"json","value":response},
            "gatewayEvidence":{
                "source":"sub2api_usage_log",
                "request_id":"request-usage",
                "requested_model":"gpt-5.6-sol",
                "upstream_model":"gpt-5.6-sol",
                "provider":"OpenAI",
                "input_tokens":non_cached_input,
                "cache_read_tokens":80,
                "output_tokens":20,
                "input_tokens_semantics":"sub2api_non_cached_input",
                "api_input_tokens":non_cached_input + 80
            }
        }))
        .unwrap()
    }

    #[test]
    fn exact_sub2api_usage_fills_missing_response_usage_without_double_counting_cache() {
        let capture = usage_capture(None, 20);
        let (usage, evidence, conflicts) = reconcile_capture_usage(&capture);
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.cached_input_tokens, 80);
        assert_eq!(usage.output_tokens, 20);
        assert_eq!(usage.total_tokens, 120);
        assert!(conflicts.is_empty());
        assert_eq!(
            evidence["selected_sources"]["input_tokens"],
            "sub2api_fallback"
        );
    }

    #[test]
    fn response_usage_wins_when_sub2api_usage_matches() {
        let capture = usage_capture(
            Some(json!({
                "input_tokens":100,
                "input_tokens_details":{"cached_tokens":80},
                "output_tokens":20,
                "total_tokens":120
            })),
            20,
        );
        let (usage, evidence, conflicts) = reconcile_capture_usage(&capture);
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.cached_input_tokens, 80);
        assert!(conflicts.is_empty());
        assert_eq!(
            evidence["selected_sources"]["input_tokens"],
            "response_usage"
        );
    }

    #[test]
    fn conflicting_sub2api_usage_is_retained_for_the_hard_gate() {
        let capture = usage_capture(
            Some(json!({
                "input_tokens":100,
                "input_tokens_details":{"cached_tokens":80},
                "output_tokens":20,
                "total_tokens":120
            })),
            30,
        );
        let (usage, _, conflicts) = reconcile_capture_usage(&capture);
        assert_eq!(usage.input_tokens, 100);
        assert!(
            conflicts
                .iter()
                .any(|conflict| conflict.contains("input_tokens:response=100:sub2api=110"))
        );
    }

    fn multi_source_usage_capture(
        capture_id: &str,
        record_type: &str,
        request_id: &str,
        response_id: &str,
        input_tokens: u64,
    ) -> Value {
        json!({
            "version":"chiptrace.capture.v2",
            "recordType":record_type,
            "captureId":capture_id,
            "sourceNamespace":"fixture",
            "upstreamRequestId":request_id,
            "actualProvider":"OpenAI",
            "traceContext":{"task_session_id":"task-multi-source-usage"},
            "requestBody":{"kind":"json","value":{
                "model":"gpt-5.6-sol","instructions":"system","input":[]
            }},
            "responseBody":{"kind":"json","value":{
                "id":response_id,"model":"gpt-5.6-sol","status":"completed","output":[],
                "usage":{"input_tokens":input_tokens,"cached_input_tokens":80,
                         "output_tokens":20,"reasoning_output_tokens":5,
                         "total_tokens":input_tokens + 20}
            }}
        })
    }

    #[test]
    fn exact_request_component_settles_api_and_rollout_usage_once() {
        let api = multi_source_usage_capture(
            "cap-usage-api",
            "api_snapshot",
            "request-shared",
            "response-shared",
            100,
        );
        let rollout = multi_source_usage_capture(
            "cap-usage-rollout",
            "rollout_event",
            "request-shared",
            "response-shared",
            100,
        );
        let (session, _, _) = assemble_group(vec![api, rollout]).unwrap();
        assert_eq!(session["usage"]["input_tokens"], 100);
        assert_eq!(session["usage"]["cached_input_tokens"], 80);
        assert_eq!(session["usage"]["output_tokens"], 20);
        assert_eq!(session["usage"]["reasoning_tokens"], 5);
        assert_eq!(session["usage"]["total_tokens"], 120);
        assert_eq!(
            session["meta"]["usage_settlement_evidence"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            session["meta"]["usage_conflicts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rollout_gateway_evidence_does_not_distort_api_route_coverage() {
        let gateway = json!({
            "source":"sub2api_usage_log",
            "request_id":"request-shared",
            "requested_model":"gpt-5.6-sol",
            "upstream_model":"gpt-5.6-sol",
            "response_model":"gpt-5.6-sol",
            "provider":"OpenAI",
            "input_tokens":20,
            "cache_read_tokens":80,
            "api_input_tokens":100,
            "input_tokens_semantics":"sub2api_non_cached_input",
            "output_tokens":20
        });
        let mut api = multi_source_usage_capture(
            "cap-route-api",
            "api_snapshot",
            "request-shared",
            "response-shared",
            100,
        );
        api["gatewayEvidence"] = gateway.clone();
        let mut rollout = multi_source_usage_capture(
            "cap-route-rollout",
            "rollout_event",
            "request-shared",
            "response-shared",
            100,
        );
        rollout.as_object_mut().unwrap().remove("actualProvider");
        rollout["runtimeProvider"] = json!("TokensRouter");
        rollout["gatewayEvidence"] = gateway;
        let (session, _, _) = assemble_group(vec![api, rollout]).unwrap();
        assert_eq!(
            session["meta"]["model_evidence"]["proxy_route_verified"],
            true
        );
        assert_eq!(
            session["meta"]["model_evidence"]["provider_identity_attested"],
            true
        );
        assert_eq!(session["usage"]["total_tokens"], 120);
    }

    #[test]
    fn rejected_api_attempt_is_retained_but_excluded_from_attestation_denominator() {
        let success = multi_source_usage_capture(
            "cap-attested-success",
            "api_snapshot",
            "request-success",
            "response-success",
            100,
        );
        let mut rejected = multi_source_usage_capture(
            "cap-attestation-rejected",
            "api_snapshot",
            "request-rejected",
            "response-rejected",
            100,
        );
        rejected["responseStatus"] = json!(400);
        rejected["responseBody"] = json!({
            "kind":"json",
            "value":{"error":{"type":"invalid_request_error","message":"invalid request"}}
        });
        rejected.as_object_mut().unwrap().remove("actualProvider");

        let (session, _, _) = assemble_group(vec![success, rejected]).unwrap();
        assert_eq!(session["meta"]["model_evidence"]["api_snapshot_count"], 2);
        assert_eq!(
            session["meta"]["model_evidence"]["attestation_candidate_count"],
            1
        );
        assert_eq!(
            session["meta"]["model_evidence"]["non_attestable_api_snapshots"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            session["meta"]["model_evidence"]["provider_identity_attested"],
            true
        );
        assert_eq!(
            session["meta"]["model_evidence"]["proxy_route_verified"],
            false
        );
    }

    #[test]
    fn per_request_instruction_changes_are_not_task_prompt_conflicts() {
        let first = multi_source_usage_capture(
            "cap-prompt-first",
            "api_snapshot",
            "request-prompt-first",
            "response-prompt-first",
            100,
        );
        let mut second = multi_source_usage_capture(
            "cap-prompt-second",
            "api_snapshot",
            "request-prompt-second",
            "response-prompt-second",
            100,
        );
        second["requestBody"]["value"]["instructions"] =
            json!("a different per-request instruction");
        let (session, _, _) = assemble_group(vec![first, second]).unwrap();
        assert!(
            session["meta"]["system_prompt_conflicts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            session["meta"]["system_prompt_variants"]
                .as_array()
                .unwrap()
                .len()
                >= 2
        );
    }

    #[test]
    fn task_scoped_prompt_changes_remain_visible_as_conflicts() {
        let mut first = multi_source_usage_capture(
            "cap-task-prompt-first",
            "api_snapshot",
            "request-task-prompt-first",
            "response-task-prompt-first",
            100,
        );
        let mut second = multi_source_usage_capture(
            "cap-task-prompt-second",
            "api_snapshot",
            "request-task-prompt-second",
            "response-task-prompt-second",
            100,
        );
        first["systemPrompt"] = json!("task prompt one");
        second["systemPrompt"] = json!("task prompt two");
        let (session, _, _) = assemble_group(vec![first, second]).unwrap();
        assert!(
            session["meta"]["system_prompt_conflicts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "across_task_scoped_captures")
        );
    }

    #[test]
    fn different_request_components_keep_additive_usage() {
        let first = multi_source_usage_capture(
            "cap-usage-first",
            "api_snapshot",
            "request-first",
            "response-first",
            100,
        );
        let second = multi_source_usage_capture(
            "cap-usage-second",
            "api_snapshot",
            "request-second",
            "response-second",
            200,
        );
        let (session, _, _) = assemble_group(vec![first, second]).unwrap();
        assert_eq!(session["usage"]["input_tokens"], 300);
        assert_eq!(session["usage"]["output_tokens"], 40);
        assert_eq!(session["usage"]["total_tokens"], 340);
        assert_eq!(
            session["meta"]["usage_settlement_evidence"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn conflicting_usage_for_one_request_is_a_hard_gate_signal() {
        let api = multi_source_usage_capture(
            "cap-usage-api-conflict",
            "api_snapshot",
            "request-conflict",
            "response-conflict",
            100,
        );
        let rollout = multi_source_usage_capture(
            "cap-usage-rollout-conflict",
            "rollout_event",
            "request-conflict",
            "response-conflict",
            101,
        );
        let (session, _, _) = assemble_group(vec![api, rollout]).unwrap();
        assert!(
            session["meta"]["usage_conflicts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|conflict| conflict
                    .as_str()
                    .is_some_and(|value| value.contains("input_tokens")))
        );
    }

    #[test]
    fn codex_developer_prompt_and_nested_namespaces_are_normalized() {
        let capture = json!({
            "captureId":"cap-codex-shape",
            "sourceNamespace":"fixture",
            "traceContext":{"task_session_id":"task-codex"},
            "requestBody":{"kind":"json","value":{
                "model":"gpt-5.6-sol",
                "input":[
                    {"type":"additional_tools","role":"developer","tools":[{
                        "type":"namespace","name":"functions","description":"Runtime tools.","tools":[
                            {"type":"custom","name":"exec","description":"Execute a tool program.",
                             "format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}},
                            {"type":"function","name":"wait","description":"Wait for a running execution.",
                             "parameters":{"type":"object","properties":{
                                 "cell_id":{"type":"string","description":"Running execution ID."}
                             },"required":["cell_id"]}}
                        ]
                    }]},
                    {"type":"message","role":"developer","content":"fallback developer prompt"},
                    {"type":"message","id":"user-1","role":"user","content":"inspect workspace"}
                ]
            }},
            "responseBody":{"kind":"json","value":{
                "id":"response-1","model":"gpt-5.6-sol","status":"completed",
                "instructions":"authoritative response instructions",
                "output":[{"type":"message","id":"assistant-1","role":"assistant","content":"done"}]
            }}
        });
        let (session, _, divergence) = assemble_group(vec![capture]).unwrap();
        assert_eq!(divergence, 0);
        assert_eq!(
            session["system_prompt"],
            "authoritative response instructions\n\nfallback developer prompt"
        );
        assert_eq!(
            session["meta"]["system_prompt_evidence"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(
            session["meta"]["system_prompt_conflicts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(session["messages"][0]["role"], "system");
        let tools = session["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "exec");
        assert!(tools[0].get("native_format").is_some());
        assert_eq!(
            tools[0]["schema_provenance"]["source"],
            "captured_native_format"
        );
        assert_eq!(tools[0]["schema_provenance"]["generated_adapter"], true);
        assert_eq!(
            tools[0]["parameters"]["properties"]["input"]["type"],
            "string"
        );
        assert_eq!(tools[1]["name"], "wait");
    }

    #[test]
    fn sse_created_metadata_is_retained_when_terminal_event_is_sparse() {
        let capture = json!({
            "captureId":"cap-sse-created",
            "sourceNamespace":"fixture",
            "traceContext":{"task_session_id":"task-sse"},
            "requestBody":{"kind":"json","value":{
                "model":"gpt-5.6-sol",
                "input":[{"type":"message","role":"user","content":"hello"}]
            }},
            "responseBody":{"kind":"text","value":concat!(
                "event: response.created\n",
                "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-sse\",\"instructions\":\"created instructions\",\"model\":\"gpt-5.6-sol\",\"status\":\"in_progress\"}}\n\n",
                "event: response.completed\n",
                "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-sse\",\"status\":\"completed\"}}\n\n"
            )}
        });
        let parsed = parse_capture(capture).unwrap();
        assert_eq!(
            parsed.system_prompt.as_deref(),
            Some("created instructions")
        );
        assert_eq!(parsed.response["instructions"], "created instructions");
    }

    #[test]
    fn ordinary_json_tool_output_does_not_acquire_a_status() {
        let mut messages = Vec::new();
        let mut tools = Vec::new();
        parse_input_item(
            &json!({
                "type":"function_call_output",
                "call_id":"call-ordinary",
                "output":"{\"ok\":true,\"exit_code\":0}"
            }),
            &mut messages,
            &mut tools,
        );
        let result = &messages[0];
        assert_eq!(result["role"], "tool");
        assert!(result.get("status").is_none());
        assert!(result.get("is_error").is_none());
        assert!(result.get("status_source").is_none());
    }

    #[test]
    fn codex_runtime_result_envelope_supplies_only_its_explicit_status() {
        let mut messages = Vec::new();
        let mut tools = Vec::new();
        parse_input_item(
            &json!({
                "type":"custom_tool_call_output",
                "call_id":"call-runtime",
                "output":[{"type":"text","text":"{\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"isError\":false}"}]
            }),
            &mut messages,
            &mut tools,
        );
        let result = &messages[0];
        assert_eq!(result["status"], "success");
        assert_eq!(result["is_error"], false);
        assert_eq!(result["status_source"], "codex_runtime_result_envelope");
        assert_eq!(result["runtime_envelope_count"], 1);
    }

    #[test]
    fn conflicting_direct_and_runtime_tool_status_is_unknown() {
        let mut messages = Vec::new();
        let mut tools = Vec::new();
        parse_input_item(
            &json!({
                "type":"function_call_output",
                "call_id":"call-conflict",
                "status":"success",
                "output":"{\"content\":[{\"type\":\"text\",\"text\":\"failed\"}],\"isError\":true}"
            }),
            &mut messages,
            &mut tools,
        );
        let result = &messages[0];
        assert_eq!(result["status"], "unknown");
        assert_eq!(result["status_conflict"], true);
        assert_eq!(result["status_source"], "conflicting_explicit_status");
    }

    #[test]
    fn cumulative_snapshots_merge_by_identity_and_keep_turns_at_node_scope() {
        let trace_one = json!({
            "task_session_id":"task-merge",
            "session_id":"thread-merge",
            "root_session_id":"task-merge",
            "turn_id":"turn-1"
        });
        let trace_two = json!({
            "task_session_id":"task-merge",
            "session_id":"thread-merge",
            "root_session_id":"task-merge",
            "turn_id":"turn-2"
        });
        let first = json!({
            "recordType":"api_snapshot","captureId":"cap-merge-1","sourceNamespace":"fixture",
            "startedAt":"2026-08-28T00:00:01Z","upstreamRequestId":"request-1",
            "traceContext":trace_one,
            "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol","instructions":"system",
                "input":[{"type":"message","id":"user-1","role":"user","content":"first"}]}},
            "responseBody":{"kind":"json","value":{"id":"response-1","model":"gpt-5.6-sol",
                "status":"completed","output":[{"type":"message","id":"assistant-1","role":"assistant","content":"one"}]}}
        });
        let second = json!({
            "recordType":"api_snapshot","captureId":"cap-merge-2","sourceNamespace":"fixture",
            "startedAt":"2026-08-28T00:00:02Z","upstreamRequestId":"request-2",
            "traceContext":trace_two,
            "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol","instructions":"system",
                "input":[
                    {"type":"message","id":"user-1","role":"user","content":"first"},
                    {"type":"message","id":"assistant-1","role":"assistant","content":"one"},
                    {"type":"message","id":"user-2","role":"user","content":"second"}
                ]}},
            "responseBody":{"kind":"json","value":{"id":"response-2","model":"gpt-5.6-sol",
                "status":"completed","output":[{"type":"message","id":"assistant-2","role":"assistant","content":"two"}]}}
        });
        let end = json!({
            "recordType":"lifecycle_event","captureId":"cap-merge-end","sourceNamespace":"fixture",
            "traceContext":{"task_session_id":"task-merge","session_id":"thread-merge","root_session_id":"task-merge"},
            "lifecycleEvent":{"type":"task_end","status":"completed","occurred_at":"2026-08-28T00:00:03Z"}
        });
        let (session, _, divergence) = assemble_group(vec![second, end, first]).unwrap();
        assert_eq!(divergence, 0);
        assert_eq!(session["session_id"], "task-merge");
        assert_eq!(session["source_request_count"], 2);
        assert_eq!(session["source_capture_count"], 3);
        assert_eq!(session["status"], "completed");
        assert_eq!(session["is_final_snapshot"], true);
        assert_eq!(session["meta"]["turn_ids"].as_array().unwrap().len(), 2);
        assert!(
            session["meta"]["trace_conflicts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            session["meta"]["source_request_ids"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(session["messages"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn cumulative_snapshots_preserve_repeated_messages_without_ids() {
        let repeated = json!({"role":"user","content":"retry the same request"});
        let first = vec![repeated.clone(), repeated.clone()];
        let mut current = Vec::new();
        assert_eq!(merge_messages(&mut current, &first), 0);
        assert_eq!(current.len(), 2);

        let cumulative = vec![repeated.clone(), repeated.clone(), repeated];
        assert_eq!(merge_messages(&mut current, &cumulative), 0);
        assert_eq!(current.len(), 3);
    }

    #[test]
    fn executor_span_projects_real_status_and_schema() {
        let api = json!({
            "recordType":"api_snapshot","captureId":"cap-span-api","sourceNamespace":"fixture",
            "startedAt":"2026-08-28T00:00:01Z",
            "traceContext":{"task_session_id":"task-span","root_session_id":"task-span","span_id":"span-api"},
            "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol","instructions":"system",
                "input":[{"type":"message","id":"user-span","role":"user","content":"run tests"}]}},
            "responseBody":{"kind":"json","value":{"id":"response-span","model":"gpt-5.6-sol",
                "status":"completed","output":[{"type":"message","id":"assistant-span","role":"assistant","content":"checking"}]}}
        });
        let tool = json!({
            "recordType":"tool_execution","captureId":"cap-span-tool","sourceNamespace":"fixture",
            "traceContext":{"task_session_id":"task-span","root_session_id":"task-span",
                            "span_id":"span-tool","parent_span_id":"span-api"},
            "toolExecution":{
                "call_id":"call-tests","name":"run_tests","initiator":"assistant","status":"error",
                "arguments":{"target":"workspace"},"result":"test failed",
                "schema":{"name":"run_tests","description":"Run workspace tests.","parameters":{
                    "type":"object","properties":{"target":{"type":"string","description":"Workspace target."}},
                    "required":["target"]
                }},"started_at":"2026-08-28T00:00:02Z","finished_at":"2026-08-28T00:00:03Z"
            }
        });
        let (session, _, divergence) = assemble_group(vec![api, tool]).unwrap();
        assert_eq!(divergence, 0);
        assert_eq!(session["tools"][0]["name"], "run_tests");
        let result = session["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["role"] == "tool")
            .unwrap();
        assert_eq!(result["status"], "error");
        assert_eq!(result["is_error"], true);
        let call = session["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|message| {
                message
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .and_then(|calls| calls.first())
            })
            .unwrap();
        assert_eq!(call["execution_status"], "failed");
        assert_eq!(
            session["meta"]["capture_dag"]["edges"][0]["kind"],
            "parent_span"
        );
        assert!(
            session["meta"]["capture_dag"]["unresolved_parent_span_ids"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn producer_tool_state_and_stream_sequences_are_audited() {
        let producer = |event_id: &str, sequence: u64| {
            json!({
                "schema_version":"chiptrace.producer-event.v1",
                "event_id":event_id,
                "producer":"tool-dispatcher",
                "producer_version":"1.2.3",
                "identity_scheme":"chiptrace.deterministic-capture.v1",
                "stream_id":"dispatcher-task-a",
                "sequence":sequence,
            })
        };
        let schema = json!({
            "name":"run_tests","description":"Run workspace tests.","parameters":{
                "type":"object","properties":{
                    "target":{"type":"string","description":"Workspace target."}
                },"required":["target"]
            }
        });
        let start = json!({
            "recordType":"tool_execution","captureId":"cap-audit-start","sourceNamespace":"fixture",
            "traceContext":{"task_session_id":"task-audit"},
            "producerEvent":producer("call-1-start", 10),
            "toolExecution":{
                "call_id":"call-1","name":"run_tests","initiator":"assistant","status":"started",
                "arguments":{"target":"workspace"},"schema":schema,
                "started_at":"2026-08-29T00:00:00Z"
            }
        });
        let finish = json!({
            "recordType":"tool_execution","captureId":"cap-audit-finish","sourceNamespace":"fixture",
            "traceContext":{"task_session_id":"task-audit"},
            "producerEvent":producer("call-1-finish", 11),
            "toolExecution":{
                "call_id":"call-1","name":"run_tests","initiator":"assistant","status":"success",
                "arguments":{"target":"workspace"},"schema":schema,
                "started_at":"2026-08-29T00:00:00Z","finished_at":"2026-08-29T00:00:01Z",
                "result":"passed"
            }
        });
        let (session, _, divergence) = assemble_group(vec![start.clone(), finish.clone()]).unwrap();
        assert_eq!(divergence, 0);
        assert!(
            session["meta"]["tool_execution_conflicts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            session["meta"]["producer_event_conflicts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(session["meta"]["tool_executions"][0]["state"], "closed");
        assert_eq!(
            session["meta"]["tool_executions"][0]["evidence_mode"],
            "producer_state_machine"
        );
        assert_eq!(session["meta"]["producer_streams"][0]["contiguous"], true);

        let mut invalid_finish = finish;
        invalid_finish["producerEvent"]["sequence"] = json!(12);
        invalid_finish["toolExecution"]["arguments"] = json!({"target":"other"});
        let (invalid, _, _) = assemble_group(vec![start, invalid_finish]).unwrap();
        assert!(
            invalid["meta"]["producer_event_conflicts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|conflict| conflict.as_str().unwrap().ends_with(":sequence_gap"))
        );
        assert!(
            invalid["meta"]["tool_execution_conflicts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|conflict| conflict == "call-1:field_mismatch:arguments")
        );
    }

    #[test]
    fn task_registry_snapshot_supplies_versioned_tool_definitions() {
        let registry = json!({
            "recordType":"lifecycle_event","captureId":"cap-registry","sourceNamespace":"fixture",
            "receivedAt":"2026-08-28T00:00:00Z",
            "traceContext":{"task_session_id":"task-registry","root_session_id":"task-registry"},
            "lifecycleEvent":{"event_id":"start","type":"task_start","status":"started",
                "occurred_at":"2026-08-28T00:00:00Z"},
            "toolRegistry":{
                "schema_version":"chiptrace.tool-registry.v1","producer":"codex-cli",
                "producer_version":"0.150.0-alpha.9","captured_at":"2026-08-28T00:00:00Z",
                "tools":[{"runtime_item_type":"CommandExecution","tool":{
                    "name":"exec_command","description":"Execute a command.",
                    "parameters":{"type":"object","properties":{
                        "cmd":{"type":"string","description":"Command to execute."}
                    },"required":["cmd"]}
                }}]
            }
        });
        let api = json!({
            "recordType":"api_snapshot","captureId":"cap-registry-api","sourceNamespace":"fixture",
            "startedAt":"2026-08-28T00:00:01Z",
            "traceContext":{"task_session_id":"task-registry","root_session_id":"task-registry"},
            "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol","instructions":"system",
                "input":[{"type":"message","role":"user","content":"run command"}]}},
            "responseBody":{"kind":"json","value":{"id":"response-registry","model":"gpt-5.6-sol",
                "status":"completed","output":[{"type":"function_call","call_id":"call-registry",
                    "name":"exec_command","arguments":"{\"cmd\":\"true\"}"}]}}
        });
        let (session, _, _) = assemble_group(vec![registry, api]).unwrap();
        assert_eq!(session["tools"][0]["name"], "exec_command");
        assert_eq!(
            session["meta"]["tool_registry_evidence"][0]["producer_version"],
            "0.150.0-alpha.9"
        );
        assert_eq!(
            session["meta"]["tool_registry_evidence"][0]["tool_count"],
            1
        );
        assert!(
            session["meta"]["tool_registry_evidence"][0]["sha256"]
                .as_str()
                .is_some_and(|digest| digest.len() == 64)
        );
    }

    #[test]
    fn namespace_tool_calls_and_definitions_use_the_same_reversible_identity() {
        let namespace = json!({
            "type":"namespace",
            "name":"catalog",
            "description":"Catalog tools.",
            "tools":[{"type":"function","name":"lookup","description":"Look up one value.",
                "parameters":{"type":"object","properties":{}}}]
        });
        let mut definitions = Vec::new();
        collect_tool_definitions(&namespace, &mut definitions);
        assert_eq!(definitions[0]["name"], "catalog.lookup");
        assert_eq!(definitions[0]["runtime_tool"], "lookup");
        assert_eq!(definitions[0]["runtime_namespace"], "catalog");

        let mut messages = Vec::new();
        parse_input_item(
            &json!({
                "type":"function_call",
                "call_id":"call-namespace",
                "namespace":"catalog",
                "name":"lookup",
                "arguments":"{}"
            }),
            &mut messages,
            &mut Vec::new(),
        );
        assert_eq!(
            messages[0]["tool_calls"][0]["function"]["name"],
            "catalog.lookup"
        );

        let normalized = normalize_tool_calls(&json!([{
            "id":"call-chat",
            "type":"function",
            "namespace":"catalog",
            "function":{"name":"lookup","arguments":"{}"}
        }]));
        assert_eq!(normalized[0]["function"]["name"], "catalog.lookup");
    }

    #[test]
    fn default_namespace_and_plain_registry_schema_are_semantically_equal() {
        let source = json!({
            "type":"function",
            "name":"lookup",
            "description":"Look up one value.",
            "parameters":{"type":"object","properties":{},"required":[]}
        });
        let api = normalize_tool_definition_with_namespace(&source, Some("functions")).unwrap();
        let registry = normalize_tool_definition(&source).unwrap();
        assert_ne!(api, registry);
        assert_eq!(api["name"], registry["name"]);
        assert_eq!(api["schema_hash"], registry["schema_hash"]);
        assert!(tool_schemas_semantically_equal(&api, &registry));
    }

    #[test]
    fn missing_tool_result_status_is_not_fabricated() {
        let mut messages = Vec::new();
        parse_input_item(
            &json!({"type":"function_call_output","call_id":"call-unknown","output":"real output"}),
            &mut messages,
            &mut Vec::new(),
        );
        assert_eq!(messages[0]["role"], "tool");
        assert!(messages[0].get("status").is_none());
        assert!(messages[0].get("is_error").is_none());
    }

    #[test]
    fn parallel_response_calls_match_later_input_items_by_call_id() {
        let first = json!({
            "captureId":"cap-parallel-1","sourceNamespace":"fixture","startedAt":"2026-08-28T00:00:01Z",
            "traceContext":{"task_session_id":"task-parallel"},
            "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol","instructions":"system",
                "input":[{"type":"message","id":"user-p","role":"user","content":"run both"}]}},
            "responseBody":{"kind":"json","value":{"id":"response-p1","model":"gpt-5.6-sol","status":"completed","output":[
                {"type":"function_call","id":"item-p1","call_id":"call-p1","name":"tool_a","arguments":"{}"},
                {"type":"function_call","id":"item-p2","call_id":"call-p2","name":"tool_b","arguments":"{}"}
            ]}}
        });
        let second = json!({
            "captureId":"cap-parallel-2","sourceNamespace":"fixture","startedAt":"2026-08-28T00:00:02Z",
            "traceContext":{"task_session_id":"task-parallel"},
            "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol","instructions":"system","input":[
                {"type":"message","id":"user-p","role":"user","content":"run both"},
                {"type":"function_call","id":"item-p1","call_id":"call-p1","name":"tool_a","arguments":"{}"},
                {"type":"function_call","id":"item-p2","call_id":"call-p2","name":"tool_b","arguments":"{}"},
                {"type":"function_call_output","id":"result-p1","call_id":"call-p1","output":"a"},
                {"type":"function_call_output","id":"result-p2","call_id":"call-p2","output":"b"}
            ]}},
            "responseBody":{"kind":"json","value":{"id":"response-p2","model":"gpt-5.6-sol","status":"completed",
                "output":[{"type":"message","id":"assistant-p","role":"assistant","content":"done"}]}}
        });
        let (session, _, divergence) = assemble_group(vec![first, second]).unwrap();
        assert_eq!(divergence, 0);
        let calls = session["messages"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|message| {
                message
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .count();
        assert_eq!(calls, 2);
    }

    #[test]
    fn explicit_session_id_wins_over_thread_id() {
        let capture = json!({
            "captureId": "cap-identity",
            "sourceNamespace": "fixture",
            "traceContext": {"session_id": "codex-session", "thread_id": "thread"},
            "requestBody": {"kind": "json", "value": {}}
        });
        assert_eq!(session_group_key(&capture), "fixture\0codex-session");
        assert_eq!(task_partition_key(&capture), "fixture\0codex-session");
    }

    #[test]
    fn explicit_task_session_id_wins_over_codex_thread() {
        let capture = json!({
            "captureId":"cap-task-identity",
            "sourceNamespace":"fixture",
            "traceContext":{
                "task_session_id":"task-one",
                "session_id":"codex-thread",
                "thread_id":"codex-thread"
            },
            "requestBody":{"kind":"json","value":{}}
        });
        assert_eq!(session_group_key(&capture), "fixture\0task-one");
    }

    #[test]
    fn raw_capture_infers_trace_aliases_and_lifecycle_events_in_rust() {
        let capture = json!({
            "captureId": "cap-raw-metadata",
            "sourceNamespace": "fixture",
            "startedAt": "2026-08-28T00:00:00Z",
            "requestBody": {"kind": "json", "value": {
                "model": "gpt-5.6-sol",
                "client_metadata": {
                    "sessionId": "session-camel",
                    "rootSessionId": "root-camel",
                    "previousResponseId": "response-parent",
                    "x-codex-turn-metadata": "{\"request_kind\":\"compaction\",\"root_turn_id\":\"root-turn\",\"agent_name\":\"/root\"}"
                },
                "input": [
                    {"type": "session_start"},
                    {"type": "compaction"},
                    {"role": "user", "content": "continue"}
                ]
            }},
            "responseBody": {"kind": "text", "value":
                "data: {\"type\":\"response.in_progress\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"response-current\",\"status\":\"completed\"}}\n\n"
            }
        });
        assert_eq!(session_group_key(&capture), "fixture\0session-camel");
        let parsed = parse_capture(capture).unwrap();
        assert_eq!(parsed.trace_context["root_session_id"], "root-camel");
        assert_eq!(parsed.trace_context["root_turn_id"], "root-turn");
        assert_eq!(parsed.trace_context["agent_path"], "/root");
        assert!(!parsed.trace_context.contains_key("agent_id"));
        assert_eq!(
            parsed.previous_response_id.as_deref(),
            Some("response-parent")
        );
        assert_eq!(
            parsed.lifecycle_events,
            vec![
                "compaction",
                "response.completed",
                "response.in_progress",
                "session_start"
            ]
        );
        assert!(!parsed.final_snapshot);
    }

    #[test]
    fn preserves_structured_lifecycle_records_and_top_level_trace_aliases() {
        let capture = json!({
            "captureId":"cap-structured-lifecycle",
            "sourceNamespace":"fixture",
            "startedAt":"2026-08-28T00:00:00Z",
            "task_session_id":"task-top-level",
            "root_session_id":"root-top-level",
            "parent_session_id":"parent-top-level",
            "goal_id":"goal-top-level",
            "turn_id":"turn-top-level",
            "agent_id":"agent-top-level",
            "branch_id":"branch-top-level",
            "previous_response_id":"response-parent-top-level",
            "recordType":"lifecycle_event",
            "lifecycleEvent":{
                "event_id":"event-1",
                "type":"task_end",
                "status":"failed",
                "reason":"tool timeout",
                "occurred_at":"2026-08-28T00:00:01Z"
            }
        });
        let (session, _, _) = assemble_group(vec![capture]).unwrap();
        assert_eq!(
            session["meta"]["trace"]["root_session_id"],
            "root-top-level"
        );
        assert_eq!(session["meta"]["trace"]["goal_id"], "goal-top-level");
        assert_eq!(session["meta"]["trace"]["turn_id"], "turn-top-level");
        assert_eq!(
            session["meta"]["trace"]["previous_response_id"],
            "response-parent-top-level"
        );
        let records = session["meta"]["lifecycle_event_records"]
            .as_array()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["status"], "failed");
        assert_eq!(records[0]["reason"], "tool timeout");
        assert_eq!(
            session["meta"]["trace_contexts"].as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn anthropic_tool_results_keep_content_block_order() {
        let mut messages = Vec::new();
        parse_role_content(
            "user",
            &json!([
                {"type":"text","text":"before"},
                {"type":"tool_result","tool_use_id":"call-1","content":"result"},
                {"type":"text","text":"after"}
            ]),
            &Map::new(),
            &mut messages,
        );
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"], "before");
        assert_eq!(messages[1]["role"], "tool");
        assert_eq!(messages[1]["tool_call_id"], "call-1");
        assert_eq!(messages[2]["role"], "user");
        assert_eq!(messages[2]["content"], "after");
    }

    #[test]
    fn response_completion_does_not_fabricate_session_completion() {
        let capture = json!({
            "captureId": "cap-not-final",
            "sourceNamespace": "fixture",
            "startedAt": "2026-08-27T00:00:00Z",
            "traceContext": {"session_id": "session-open"},
            "requestBody": {"kind":"json", "value": {
                "model":"gpt-5.6-sol",
                "input":[{"role":"user","content":"continue later"}]
            }},
            "responseBody": {"kind":"json", "value": {
                "id":"response-open",
                "status":"completed",
                "output":[{"type":"message","role":"assistant","content":"partial"}]
            }}
        });
        let (session, _, _) = assemble_group(vec![capture]).unwrap();
        assert_eq!(session["is_final_snapshot"], false);
        assert_eq!(session["status"], "incomplete");
    }

    #[test]
    fn root_and_subagent_sessions_share_a_detachable_task_dag() {
        let root_capture = json!({
            "captureId":"cap-root",
            "sourceNamespace":"fixture",
            "traceContext":{"session_id":"root"},
            "requestBody":{"kind":"json","value":{}}
        });
        let child_capture = json!({
            "captureId":"cap-child",
            "sourceNamespace":"fixture",
            "traceContext":{
                "session_id":"child",
                "root_session_id":"root",
                "parent_session_id":"root",
                "agent_id":"agent-child"
            },
            "requestBody":{"kind":"json","value":{}}
        });
        assert_eq!(task_partition_key(&root_capture), "fixture\0root");
        assert_eq!(task_partition_key(&child_capture), "fixture\0root");
        let (root, _, _) = assemble_group(vec![root_capture]).unwrap();
        let (child, _, _) = assemble_group(vec![child_capture]).unwrap();
        let mut sessions = vec![root, child];
        attach_task_dags(&mut sessions).unwrap();
        assert_eq!(sessions[0].pointer("/meta/task_role"), Some(&json!("root")));
        assert_eq!(
            sessions[1].pointer("/meta/task_role"),
            Some(&json!("subagent"))
        );
        assert_eq!(
            sessions[0]
                .pointer("/meta/task_dag/nodes")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            sessions[0].pointer("/meta/task_dag/complete"),
            Some(&json!(true))
        );
    }

    #[test]
    fn directory_discovery_excludes_open_wal_segments() {
        let temporary = tempfile::tempdir().unwrap();
        let open = temporary.path().join("segment-00001.open.ndjson");
        let sealed = temporary.path().join("segment-00002.sealed.ndjson");
        fs::write(&open, b"{}\n").unwrap();
        fs::write(&sealed, b"{}\n").unwrap();
        let discovered = discover_inputs(&[temporary.path().to_path_buf()]).unwrap();
        assert_eq!(discovered, vec![sealed.canonicalize().unwrap()]);
        assert!(discover_inputs(&[open]).is_err());
    }

    #[test]
    fn assembly_rejects_mixed_raw_lineage_inputs() {
        let temporary = tempfile::tempdir().unwrap();
        let lineaged = temporary.path().join("lineaged");
        let legacy = temporary.path().join("legacy");
        fs::create_dir_all(&lineaged).unwrap();
        fs::create_dir_all(&legacy).unwrap();
        let lineaged_capture = lineaged.join("captures.ndjson");
        let legacy_capture = legacy.join("captures.ndjson");
        fs::write(&lineaged_capture, "{}\n").unwrap();
        fs::write(&legacy_capture, "{}\n").unwrap();
        fs::write(
            lineaged.join("RAW_SOURCE.json"),
            serde_json::to_vec(&complete_raw_lineage()).unwrap(),
        )
        .unwrap();

        let error = discover_raw_sources(
            &[lineaged, legacy],
            &[
                lineaged_capture.canonicalize().unwrap(),
                legacy_capture.canonicalize().unwrap(),
            ],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot mix Raw-lineaged and unlineaged capture inputs")
        );
    }
}
