use crate::capture::extract_body;
use crate::jsonl::{
    JsonlWriter, absolute_path, ensure_safe_relative_path, sha256_file, string_field, utc_now,
};
use crate::schema::{FileManifest, SESSION_SCHEMA_VERSION};
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
use walkdir::WalkDir;

const ASSEMBLY_SCHEMA_VERSION: &str = "chiptrace.assembly-manifest.v1";

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
    pub input_records: u64,
    pub duplicate_captures_removed: u64,
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

#[derive(Debug, Clone, Default)]
struct ParsedCapture {
    capture_id: String,
    timestamp: String,
    response: Value,
    response_id: Option<String>,
    previous_response_id: Option<String>,
    response_status: Option<u64>,
    terminal_status: Option<String>,
    provider: String,
    model: Option<String>,
    response_model: Option<String>,
    source_namespace: String,
    session_identity: String,
    session_identity_source: String,
    trace_context: Map<String, Value>,
    lifecycle_events: Vec<String>,
    evaluation_evidence: Vec<Value>,
    final_snapshot: bool,
    messages: Vec<Value>,
    response_messages: Vec<Value>,
    tools: Vec<Value>,
    system_prompt: Option<String>,
    usage: Usage,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
            let value: Value = serde_json::from_slice(&line)
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
            if let Some(version) = string_field(&value, "version") {
                versions.insert(version.to_owned());
            }
            let key = task_partition_key(&value);
            let index = partition_index(&key, config.partitions);
            partition_writers[index].write_all(&line)?;
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
        input_records,
        duplicate_captures_removed: duplicate_captures,
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
    parsed.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then(left.capture_id.cmp(&right.capture_id))
    });
    let first = parsed
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty capture group"))?;
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
    let mut usage = Usage::default();
    let mut lifecycle = Vec::new();
    let mut evaluation_evidence = Vec::new();
    let mut request_models = BTreeSet::new();
    let mut response_models = BTreeSet::new();
    let mut providers = BTreeSet::new();
    let mut response_ids = Vec::new();
    let mut trace = Map::new();
    let mut trace_conflicts = BTreeSet::new();
    let mut system_prompt = None;
    let mut divergences = 0_u64;
    for capture in &parsed {
        let mut candidate = capture.messages.clone();
        candidate.extend(capture.response_messages.clone());
        divergences += merge_messages(&mut messages, &candidate);
        for tool in &capture.tools {
            let Some(name) = tool_name(tool) else {
                continue;
            };
            if let Some(existing) = tools_by_name.get(name)
                && existing != tool
            {
                schema_conflicts.insert(name.to_owned());
            }
            tools_by_name.insert(name.to_owned(), tool.clone());
        }
        usage.add(&capture.usage);
        lifecycle.extend(capture.lifecycle_events.clone());
        evaluation_evidence.extend(capture.evaluation_evidence.clone());
        providers.insert(capture.provider.clone());
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
    }
    lifecycle.sort();
    lifecycle.dedup();
    let mut evidence_fingerprints = BTreeSet::new();
    evaluation_evidence.retain(|evidence| {
        evidence_fingerprints.insert(serde_json::to_vec(evidence).unwrap_or_default())
    });
    let model = request_models
        .iter()
        .next()
        .cloned()
        .or_else(|| response_models.iter().next().cloned())
        .unwrap_or_else(|| "unknown".to_owned());
    let provider = providers
        .iter()
        .next()
        .cloned()
        .unwrap_or_else(|| "unknown".to_owned());
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
    if !system_prompt.is_empty()
        && !messages
            .iter()
            .any(|message| string_field(message, "role") == Some("system"))
    {
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
    annotate_tool_call_statuses(&mut messages);
    let capture_dag = build_capture_dag(&parsed, &messages);
    let mut meta = Map::new();
    meta.insert(
        "source_request_ids".to_owned(),
        Value::Array(
            parsed
                .iter()
                .map(|capture| Value::String(capture.capture_id.clone()))
                .collect(),
        ),
    );
    meta.insert("response_ids".to_owned(), json!(response_ids));
    meta.insert("session_identity_source".to_owned(), json!(identity_source));
    meta.insert("source_namespace".to_owned(), json!(source_namespace));
    meta.insert("capture_dag".to_owned(), capture_dag);
    meta.insert("lifecycle_events".to_owned(), json!(lifecycle));
    meta.insert(
        "evaluation_evidence".to_owned(),
        Value::Array(evaluation_evidence),
    );
    meta.insert("schema_conflicts".to_owned(), json!(schema_conflicts));
    meta.insert("trace_conflicts".to_owned(), json!(trace_conflicts));
    meta.insert("merge_divergences".to_owned(), json!(divergences));
    meta.insert(
        "model_evidence".to_owned(),
        json!({
            "request_models": request_models,
            "response_models": response_models,
            "providers": providers,
            "attested": false,
            "scope": "request/response field consistency only; provider was inferred from captured API path and model",
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
        "source_request_count": parsed.len(),
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

fn build_capture_dag(captures: &[ParsedCapture], messages: &[Value]) -> Value {
    let open_tail_call_ids = unresolved_tool_call_ids(messages);
    let node_ids: BTreeSet<String> = captures
        .iter()
        .map(|capture| {
            capture
                .response_id
                .clone()
                .unwrap_or_else(|| capture.capture_id.clone())
        })
        .collect();
    let mut referenced_parents = BTreeSet::new();
    let mut unresolved_parents = BTreeSet::new();
    let mut edges = Vec::new();
    let mut parent_by_child = HashMap::new();
    for capture in captures {
        let node_id = capture
            .response_id
            .clone()
            .unwrap_or_else(|| capture.capture_id.clone());
        if let Some(parent) = &capture.previous_response_id {
            referenced_parents.insert(parent.clone());
            parent_by_child.insert(node_id.clone(), parent.clone());
            edges.push(json!({
                "from": parent,
                "to": node_id,
                "kind": "previous_response",
            }));
            if !node_ids.contains(parent) {
                unresolved_parents.insert(parent.clone());
            }
        }
    }
    let has_cycle = parent_by_child.keys().any(|start| {
        let mut current = start.as_str();
        let mut visited = HashSet::new();
        while let Some(parent) = parent_by_child.get(current) {
            if !visited.insert(current.to_owned()) {
                return true;
            }
            current = parent;
        }
        false
    });
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
                "node_id": capture.response_id.as_ref().unwrap_or(&capture.capture_id),
                "capture_id": capture.capture_id,
                "response_id": capture.response_id,
                "previous_response_id": capture.previous_response_id,
                "timestamp": capture.timestamp,
                "terminal_status": capture.terminal_status,
                "http_status": capture.response_status,
                "disposition": disposition,
                "lifecycle_events": capture.lifecycle_events,
                "trace": capture.trace_context,
            })
        })
        .collect();
    let roots: Vec<String> = node_ids
        .iter()
        .filter(|node| !parent_by_child.contains_key(node.as_str()))
        .cloned()
        .collect();
    let tips: Vec<String> = node_ids.difference(&referenced_parents).cloned().collect();
    json!({
        "nodes": nodes,
        "edges": edges,
        "roots": roots,
        "tips": tips,
        "open_tail_call_ids": open_tail_call_ids,
        "unresolved_parent_response_ids": unresolved_parents,
        "has_cycle": has_cycle,
        "disposition_counts": disposition_counts,
    })
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
    let (response, terminal_status) = parse_response(&raw_response);
    let request_object = request.as_object().cloned().unwrap_or_default();
    let response_object = response.as_object().cloned().unwrap_or_default();
    let trace_context = collect_trace_context(&value, &request_object);
    let source_namespace = string_field(&value, "sourceNamespace")
        .or_else(|| string_field(&value, "apiKeyFingerprint"))
        .unwrap_or("default")
        .to_owned();
    let (session_identity, identity_source) =
        session_identity(&capture_id, &request_object, &trace_context);
    let provider = infer_provider(&value, &request_object);
    let model = request_object
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let response_model = response_object
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let (messages, tools, system_prompt) = parse_request(&request_object, &provider);
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
        .unwrap_or("")
        .to_owned();
    let response_status = value.get("responseStatus").and_then(|status| {
        status
            .as_u64()
            .or_else(|| status.as_str().and_then(|text| text.parse().ok()))
    });
    let mut lifecycle_events = value
        .get("observedLifecycleEvents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
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
    Ok(ParsedCapture {
        capture_id,
        timestamp,
        response,
        response_id,
        previous_response_id,
        response_status,
        terminal_status,
        provider,
        model,
        response_model,
        source_namespace,
        session_identity,
        session_identity_source: identity_source,
        trace_context,
        lifecycle_events,
        evaluation_evidence,
        final_snapshot,
        messages,
        response_messages,
        tools,
        system_prompt,
        usage,
    })
}

fn parse_request(
    request: &Map<String, Value>,
    provider: &str,
) -> (Vec<Value>, Vec<Value>, Option<String>) {
    let mut messages = Vec::new();
    let mut tools = Vec::new();
    let system_prompt = request
        .get("instructions")
        .or_else(|| request.get("system"))
        .and_then(|value| content_text(Some(value)));
    if let Some(system) = &system_prompt {
        messages.push(json!({"role": "system", "content": system}));
    }
    for field in ["tools", "additional_tools"] {
        if let Some(values) = request.get(field).and_then(Value::as_array) {
            for value in values {
                if let Some(tool) = normalize_tool_definition(value) {
                    tools.push(tool);
                }
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
            for item in items {
                parse_input_item(item, &mut messages, &mut tools);
            }
        }
        _ => {}
    }
    (messages, tools, system_prompt)
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
                    if let Some(tool) = normalize_tool_definition(definition) {
                        tools.push(tool);
                    }
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
        let name = object.get("name").and_then(Value::as_str);
        let arguments = object
            .get("arguments")
            .or_else(|| object.get("input"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        messages.push(json!({
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": id,
                "type": "function",
                "function": {"name": name, "arguments": argument_string(&arguments)}
            }]
        }));
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
        let source_status = object.get("status").and_then(Value::as_str);
        let failed = object
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || source_status.is_some_and(|status| {
                matches!(
                    status.to_ascii_lowercase().as_str(),
                    "error" | "failed" | "cancelled" | "canceled"
                )
            });
        messages.push(json!({
            "role": "tool",
            "tool_call_id": call_id,
            "content": content,
            "status": source_status.unwrap_or(if failed {"error"} else {"success"}),
            "is_error": failed,
        }));
        return;
    }
    let role = object
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or(if kind == "message" { "user" } else { "" });
    if matches!(role, "system" | "user" | "assistant" | "tool") {
        if let Some(content) = object.get("content") {
            parse_role_content(role, content, object, messages);
        } else {
            let mut normalized = Map::new();
            normalized.insert("role".to_owned(), Value::String(role.to_owned()));
            normalized.insert("content".to_owned(), Value::String(String::new()));
            if let Some(calls) = object.get("tool_calls") {
                normalized.insert("tool_calls".to_owned(), calls.clone());
            }
            messages.push(Value::Object(normalized));
        }
    }
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
                        "name": block.get("name"),
                        "arguments": argument_string(block.get("input").unwrap_or(&Value::Null))
                    }
                }));
            }
            "tool_result" => {
                flush_role_blocks(role, &mut text, &mut calls, messages);
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": block.get("tool_use_id"),
                    "content": block.get("content").cloned().unwrap_or(Value::Null),
                    "status": if block.get("is_error").and_then(Value::as_bool).unwrap_or(false) {"error"} else {"success"},
                    "is_error": block.get("is_error").and_then(Value::as_bool).unwrap_or(false),
                }));
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
    let mut response = terminal.unwrap_or_else(|| json!({}));
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
    let mut pending_calls = Vec::new();
    for item in items {
        let kind = string_field(item, "type").unwrap_or("");
        if matches!(kind, "function_call" | "custom_tool_call") {
            pending_calls.push(json!({
                "id": item.get("call_id").or_else(|| item.get("id")),
                "type": "function",
                "function": {
                    "name": item.get("name"),
                    "arguments": argument_string(
                        item.get("arguments").or_else(|| item.get("input")).unwrap_or(&Value::Null)
                    )
                }
            }));
            continue;
        }
        if matches!(kind, "message" | "agent_message")
            || string_field(item, "role") == Some("assistant")
        {
            if !pending_calls.is_empty() {
                output.push(json!({
                    "role": "assistant",
                    "content": "",
                    "tool_calls": std::mem::take(&mut pending_calls),
                }));
            }
            let content = item.get("content").cloned().unwrap_or(Value::Null);
            output.push(json!({
                "role": "assistant",
                "content": content_text(Some(&content)).unwrap_or_default(),
            }));
        }
    }
    if !pending_calls.is_empty() {
        output.push(json!({
            "role": "assistant",
            "content": "",
            "tool_calls": pending_calls,
        }));
    }
    output
}

fn normalize_tool_definition(value: &Value) -> Option<Value> {
    let nested = value.get("function").unwrap_or(value);
    let name = string_field(nested, "name")?;
    let description = nested
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let parameters = nested
        .get("parameters")
        .or_else(|| nested.get("input_schema"))
        .cloned()
        .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
    let canonical = json!({
        "name": name,
        "description": description,
        "parameters": parameters,
        "type": value.get("type").and_then(Value::as_str).unwrap_or("function"),
    });
    let hash = hex::encode(Sha256::digest(serde_json::to_vec(&canonical).ok()?));
    let schema_version = value
        .get("schema_version")
        .or_else(|| value.get("version"))
        .cloned()
        .unwrap_or_else(|| Value::String(format!("sha256:{hash}")));
    Some(json!({
        "name": name,
        "description": description,
        "parameters": parameters,
        "type": value.get("type").and_then(Value::as_str).unwrap_or("function"),
        "schema_hash": hash,
        "schema_version": schema_version,
    }))
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
        let is_error = message
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| {
                matches!(
                    status.to_ascii_lowercase().as_str(),
                    "error" | "failed" | "cancelled" | "canceled"
                )
            });
        results.insert(call_id.to_owned(), (index, status, is_error));
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
                    Value::String(if *is_error { "failed" } else { "executed" }.to_owned()),
                );
                object.insert("result_status".to_owned(), Value::String(status.clone()));
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
    for (field, aliases) in [
        ("session_id", &["session_id", "sessionId"][..]),
        ("thread_id", &["thread_id", "threadId"]),
        ("conversation_id", &["conversation_id", "conversationId"]),
        ("trace_id", &["trace_id", "traceId"]),
        ("task_id", &["task_id", "taskId"]),
        ("root_session_id", &["root_session_id", "rootSessionId"]),
        (
            "parent_session_id",
            &["parent_session_id", "parentSessionId"],
        ),
        ("goal_id", &["goal_id", "goalId"]),
        ("turn_id", &["turn_id", "turnId"]),
        ("agent_id", &["agent_id", "agentId"]),
        ("branch_id", &["branch_id", "branchId"]),
        (
            "previous_response_id",
            &["previous_response_id", "previousResponseId"],
        ),
        ("session_final", &["session_final", "sessionFinal"]),
    ] {
        if let Some(value) = [&captured, &metadata, request]
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

fn session_identity(
    capture_id: &str,
    request: &Map<String, Value>,
    trace: &Map<String, Value>,
) -> (String, String) {
    for field in [
        "session_id",
        "conversation_id",
        "trace_id",
        "task_id",
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

fn infer_provider(capture: &Value, request: &Map<String, Value>) -> String {
    if let Some(provider) =
        string_field(capture, "actualProvider").or_else(|| string_field(capture, "provider"))
    {
        return provider.to_owned();
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
        "Anthropic".to_owned()
    } else if model.contains("gemini") {
        "Google".to_owned()
    } else if model.contains("deepseek") {
        "DeepSeek".to_owned()
    } else if model.contains("glm") {
        "Zhipu".to_owned()
    } else if model.contains("kimi") || model.starts_with('k') {
        "Moonshot".to_owned()
    } else {
        "OpenAI".to_owned()
    }
}

fn parse_usage(value: Option<&Value>) -> Usage {
    let usage = value.unwrap_or(&Value::Null);
    fn number(usage: &Value, fields: &[&str]) -> u64 {
        fields
            .iter()
            .find_map(|field| usage.get(*field).and_then(Value::as_u64))
            .unwrap_or(0)
    }
    let input = number(usage, &["input_tokens", "prompt_tokens"]);
    let output = number(usage, &["output_tokens", "completion_tokens"]);
    Usage {
        input_tokens: input,
        cached_input_tokens: number(usage, &["cached_input_tokens", "cache_read_input_tokens"])
            .max(
                usage
                    .pointer("/input_tokens_details/cached_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            ),
        cache_creation_input_tokens: number(
            usage,
            &["cache_creation_input_tokens", "cache_write_tokens"],
        ),
        output_tokens: output,
        reasoning_tokens: number(usage, &["reasoning_tokens"]).max(
            usage
                .pointer("/output_tokens_details/reasoning_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        ),
        total_tokens: number(usage, &["total_tokens"]).max(input.saturating_add(output)),
    }
}

fn merge_messages(current: &mut Vec<Value>, candidate: &[Value]) -> u64 {
    if current.is_empty() {
        current.extend(candidate.iter().cloned());
        return 0;
    }
    let current_fingerprints: Vec<Vec<u8>> = current
        .iter()
        .map(|message| serde_json::to_vec(message).unwrap_or_default())
        .collect();
    let candidate_fingerprints: Vec<Vec<u8>> = candidate
        .iter()
        .map(|message| serde_json::to_vec(message).unwrap_or_default())
        .collect();
    if is_subsequence(&current_fingerprints, &candidate_fingerprints) {
        *current = candidate.to_vec();
        return 0;
    }
    if is_subsequence(&candidate_fingerprints, &current_fingerprints) {
        return 0;
    }
    let overlap = (1..=current.len().min(candidate.len()))
        .rev()
        .find(|length| {
            current_fingerprints[current.len() - length..] == candidate_fingerprints[..*length]
        })
        .unwrap_or(0);
    current.extend(candidate[overlap..].iter().cloned());
    1
}

fn is_subsequence<T: PartialEq>(needle: &[T], haystack: &[T]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let mut position = 0;
    for value in haystack {
        if value == &needle[position] {
            position += 1;
            if position == needle.len() {
                return true;
            }
        }
    }
    false
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
                    "previousResponseId": "response-parent"
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
}
