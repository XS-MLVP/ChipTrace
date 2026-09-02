//! Offline enrichment of captures with gateway facts.
//!
//! The gateway (Sub2API) and the trace relay have different persistence
//! paths.  This module joins them only on an explicit request identifier.  It
//! deliberately does not use timestamps, thread IDs, model names, or body
//! similarity as a fallback: those values are useful diagnostics but cannot
//! prove that two records describe the same request.

use crate::capture::{gateway_evidence_fingerprint, normalize_capture};
use crate::jsonl::{
    JsonlWriter, absolute_path, open_jsonl_reader, sha256_file, utc_now, value_as_u64,
};
use crate::schema::{RAW_LINEAGE_SCHEMA_VERSION, RawSourceLineage};
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub const ENRICHMENT_SCHEMA_VERSION: &str = "chiptrace.gateway-enrichment.v1";

#[derive(Debug, Clone)]
pub struct EnrichConfig {
    pub inputs: Vec<PathBuf>,
    pub usage_logs: Vec<PathBuf>,
    pub output: PathBuf,
    pub zstd_level: i32,
    pub replace: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EnrichSummary {
    pub schema_version: String,
    pub created_at_utc: String,
    pub capture_inputs: Vec<EnrichmentSource>,
    pub usage_log_inputs: Vec<EnrichmentSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_sources: Vec<RawSourceLineage>,
    pub input_records: u64,
    pub output_records: u64,
    pub usage_rows: u64,
    pub usable_usage_rows: u64,
    pub invalid_usage_rows: u64,
    pub matched: u64,
    pub already_enriched: u64,
    pub unmatched: u64,
    pub ambiguous: u64,
    pub conflicting_existing_evidence: u64,
    pub output_sha256: String,
    pub output_bytes: u64,
    pub output_file: String,
    pub match_rule_counts: BTreeMap<String, u64>,
    pub unmatched_reason_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EnrichmentSource {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
struct UsageFact {
    request_id: String,
    evidence: Value,
    fingerprint: String,
}

#[derive(Debug, Clone)]
struct UsageIndexEntry {
    facts: Vec<UsageFact>,
}

/// Enrich Capture JSONL with exact Sub2API usage-log facts.
pub fn enrich_captures(config: EnrichConfig) -> Result<EnrichSummary> {
    if config.inputs.is_empty() {
        bail!("at least one capture input is required");
    }
    if config.usage_logs.is_empty() {
        bail!("at least one usage-log input is required");
    }
    let capture_inputs = discover_inputs(&config.inputs)?;
    if capture_inputs.is_empty() {
        bail!("no Capture JSONL inputs found");
    }
    let usage_inputs = discover_usage_inputs(&config.usage_logs)?;
    if usage_inputs.is_empty() {
        bail!("no usage-log inputs found");
    }
    let raw_sources = discover_raw_sources(&config.inputs, &capture_inputs)?;
    let output = absolute_path(&config.output)?;
    if output.exists() && !config.replace {
        bail!("enrichment output already exists: {}", output.display());
    }

    let parent = output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("enrichment output has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = TempDir::new_in(parent)?;
    let staging = temporary.path().join("enriched");
    let relative_output = "captures/enriched-captures.jsonl.zst";
    let output_file = staging.join(relative_output);
    fs::create_dir_all(output_file.parent().unwrap())?;

    let (index, usage_rows, usable_usage_rows, invalid_usage_rows) =
        build_usage_index_from_paths(&usage_inputs)?;
    let mut writer = JsonlWriter::create(&output_file, config.zstd_level)?;
    let mut summary = EnrichSummary {
        schema_version: ENRICHMENT_SCHEMA_VERSION.to_owned(),
        created_at_utc: utc_now(),
        capture_inputs: describe_sources(&capture_inputs)?,
        usage_log_inputs: describe_sources(&usage_inputs)?,
        raw_sources,
        usage_rows,
        usable_usage_rows,
        invalid_usage_rows,
        output_file: relative_output.to_owned(),
        ..EnrichSummary::default()
    };

    for input in capture_inputs {
        let mut reader = open_jsonl_reader(&input)?;
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader
                .read_until(b'\n', &mut line)
                .with_context(|| format!("read capture input {}", input.display()))?
                == 0
            {
                break;
            }
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let mut capture: Value = serde_json::from_slice(&line)
                .with_context(|| format!("parse capture input {}", input.display()))?;
            summary.input_records += 1;
            let outcome = enrich_one(&mut capture, &index);
            match outcome {
                JoinOutcome::Matched { rule, already } => {
                    summary.matched += 1;
                    if already {
                        summary.already_enriched += 1;
                    }
                    *summary.match_rule_counts.entry(rule).or_default() += 1;
                }
                JoinOutcome::Ambiguous { reason } => {
                    summary.ambiguous += 1;
                    *summary.unmatched_reason_counts.entry(reason).or_default() += 1;
                }
                JoinOutcome::ConflictingExisting => {
                    summary.conflicting_existing_evidence += 1;
                    *summary
                        .unmatched_reason_counts
                        .entry("conflicting_existing_evidence".to_owned())
                        .or_default() += 1;
                }
                JoinOutcome::Unmatched { reason } => {
                    summary.unmatched += 1;
                    *summary.unmatched_reason_counts.entry(reason).or_default() += 1;
                }
            }

            // Normalize the derived record with the same validator used by
            // the Collector.  The original input remains untouched; this
            // output is an explicitly versioned projection.
            let bytes = serde_json::to_vec(&capture)?;
            let normalized =
                normalize_capture(&bytes, bytes.len().saturating_add(4 * 1024 * 1024))?;
            let normalized_value: Value = serde_json::from_slice(&normalized.canonical)?;
            writer.write_value(&normalized_value)?;
            summary.output_records += 1;
        }
    }
    writer.finish()?;
    summary.output_sha256 = sha256_file(&output_file)?;
    summary.output_bytes = fs::metadata(&output_file)?.len();
    if summary.input_records != summary.output_records {
        bail!(
            "enrichment record conservation failed: input={} output={}",
            summary.input_records,
            summary.output_records
        );
    }
    fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    if !summary.raw_sources.is_empty() {
        fs::write(
            staging.join("RAW_SOURCES.json"),
            serde_json::to_vec_pretty(&summary.raw_sources)?,
        )?;
    }
    sync_enrichment_tree(&staging)?;
    let staged = verify_enrichment(&staging)?;
    if staged != summary {
        bail!("staged enrichment verification changed the manifest");
    }
    if output.exists() {
        if output.is_dir() {
            fs::remove_dir_all(&output)?;
        } else {
            fs::remove_file(&output)?;
        }
    }
    fs::rename(&staging, &output)?;
    fs::File::open(parent)?.sync_all()?;
    let verified = verify_enrichment(&output)?;
    if verified != summary {
        bail!("enrichment verification changed the manifest");
    }
    Ok(verified)
}

pub fn verify_enrichment(root: &Path) -> Result<EnrichSummary> {
    let manifest_path = root.join("manifest.json");
    let manifest: EnrichSummary = serde_json::from_slice(&fs::read(&manifest_path)?)
        .with_context(|| format!("parse {}", manifest_path.display()))?;
    let outcomes = manifest
        .matched
        .saturating_add(manifest.unmatched)
        .saturating_add(manifest.ambiguous)
        .saturating_add(manifest.conflicting_existing_evidence);
    let reason_total = manifest
        .unmatched_reason_counts
        .values()
        .copied()
        .fold(0_u64, u64::saturating_add);
    let rule_total = manifest
        .match_rule_counts
        .values()
        .copied()
        .fold(0_u64, u64::saturating_add);
    if manifest.schema_version != ENRICHMENT_SCHEMA_VERSION
        || manifest.input_records != manifest.output_records
        || outcomes != manifest.input_records
        || manifest
            .usable_usage_rows
            .saturating_add(manifest.invalid_usage_rows)
            != manifest.usage_rows
        || manifest.already_enriched > manifest.matched
        || rule_total != manifest.matched
        || reason_total
            != manifest
                .unmatched
                .saturating_add(manifest.ambiguous)
                .saturating_add(manifest.conflicting_existing_evidence)
        || manifest.capture_inputs.is_empty()
        || manifest.usage_log_inputs.is_empty()
        || !valid_sha256(&manifest.output_sha256)
        || manifest.output_file != "captures/enriched-captures.jsonl.zst"
    {
        bail!("invalid enrichment manifest contract");
    }
    let output = root.join(&manifest.output_file);
    if !output.is_file()
        || fs::metadata(&output)?.len() != manifest.output_bytes
        || sha256_file(&output)? != manifest.output_sha256
    {
        bail!("enrichment output checksum or length mismatch");
    }
    let mut reader = open_jsonl_reader(&output)?;
    let mut line = Vec::new();
    let mut records = 0_u64;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let _ = normalize_capture(&line, line.len().saturating_add(4 * 1024 * 1024))?;
        records += 1;
    }
    if records != manifest.output_records {
        bail!("enrichment output record count mismatch");
    }
    for source in &manifest.raw_sources {
        let mut values = BTreeMap::new();
        insert_raw_source(&mut values, source.clone())?;
    }
    let lineage_path = root.join("RAW_SOURCES.json");
    if manifest.raw_sources.is_empty() {
        if lineage_path.exists() {
            bail!("unexpected RAW_SOURCES.json without manifest lineage");
        }
    } else {
        let values: Vec<RawSourceLineage> = serde_json::from_slice(&fs::read(&lineage_path)?)?;
        if values != manifest.raw_sources {
            bail!("enrichment Raw lineage set differs from manifest");
        }
    }
    Ok(manifest)
}

fn sync_enrichment_tree(root: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(root).contents_first(true) {
        let entry = entry?;
        if entry.file_type().is_file() || entry.file_type().is_dir() {
            fs::File::open(entry.path())?.sync_all()?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum JoinOutcome {
    Matched { rule: String, already: bool },
    Ambiguous { reason: String },
    ConflictingExisting,
    Unmatched { reason: String },
}

fn enrich_one(capture: &mut Value, index: &HashMap<String, UsageIndexEntry>) -> JoinOutcome {
    let Some(object) = capture.as_object_mut() else {
        return JoinOutcome::Unmatched {
            reason: "capture_not_object".to_owned(),
        };
    };
    let candidates = capture_request_id_candidates(object);
    if candidates.is_empty() {
        return JoinOutcome::Unmatched {
            reason: "request_id_missing".to_owned(),
        };
    }

    let mut matches = Vec::new();
    for candidate in candidates {
        let key = &candidate.lookup_key;
        if let Some(entry) = index.get(key) {
            if entry.facts.len() != 1 {
                return JoinOutcome::Ambiguous {
                    reason: "usage_request_id_multiple_facts".to_owned(),
                };
            }
            matches.push((candidate, entry.facts[0].clone()));
        }
    }
    if matches.is_empty() {
        return JoinOutcome::Unmatched {
            reason: "request_id_not_in_usage_logs".to_owned(),
        };
    }
    let first_fingerprint = matches[0].1.fingerprint.clone();
    if matches
        .iter()
        .any(|(_, fact)| fact.fingerprint != first_fingerprint)
    {
        return JoinOutcome::Ambiguous {
            reason: "capture_has_conflicting_request_id_matches".to_owned(),
        };
    }
    let (candidate, fact) = matches.remove(0);
    let join = json!({
        "schema_version": ENRICHMENT_SCHEMA_VERSION,
        "mode": "exact_request_id",
        "request_id": fact.request_id,
        "capture_request_id": candidate.capture_value,
        "capture_field": candidate.source,
        "transform": candidate.transform,
        "usage_fact_sha256": fact.fingerprint,
    });

    if let Some(existing) = object.get("gatewayEvidence").cloned() {
        let existing_fingerprint = gateway_evidence_fingerprint(&existing);
        let fact_fingerprint = gateway_evidence_fingerprint(&fact.evidence);
        if existing_fingerprint != fact_fingerprint {
            let mut conflicts = object
                .remove("fieldEvidenceConflicts")
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default();
            conflicts.push(json!({
                "field":"gatewayEvidence",
                "evidence":[
                    {"value":existing,"source":"capture.gatewayEvidence","authority":"producer_asserted"},
                    {"value":fact.evidence,"source":"sub2api_usage_log","authority":"proxy_attested"}
                ]
            }));
            object.insert("fieldEvidenceConflicts".to_owned(), Value::Array(conflicts));
            return JoinOutcome::ConflictingExisting;
        }
        object.insert("gatewayEvidenceJoin".to_owned(), join);
        return JoinOutcome::Matched {
            rule: format!("{}:{}", candidate.transform, candidate.source),
            already: true,
        };
    }
    object.insert("gatewayEvidence".to_owned(), fact.evidence);
    object.insert("gatewayEvidenceJoin".to_owned(), join);
    JoinOutcome::Matched {
        rule: format!("{}:{}", candidate.transform, candidate.source),
        already: false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RequestIdCandidate {
    lookup_key: String,
    capture_value: String,
    source: String,
    transform: &'static str,
}

fn capture_request_id_candidates(object: &Map<String, Value>) -> Vec<RequestIdCandidate> {
    let mut candidates = Vec::new();
    if let Some(value) = object
        .get("upstreamRequestId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        candidates.push(RequestIdCandidate {
            lookup_key: value.to_owned(),
            capture_value: value.to_owned(),
            source: "upstreamRequestId".to_owned(),
            transform: "exact",
        });
    }
    if let Some(value) = object
        .get("requestId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        candidates.push(RequestIdCandidate {
            lookup_key: format!("client:{value}"),
            capture_value: value.to_owned(),
            source: "requestId".to_owned(),
            transform: "sub2api_client_prefix",
        });
    }
    if let Some(headers) = object.get("responseHeaders").and_then(Value::as_object) {
        if let Some(value) = header_value(headers, "x-request-id") {
            candidates.push(RequestIdCandidate {
                lookup_key: value.to_owned(),
                capture_value: value.to_owned(),
                source: "responseHeaders.x-request-id".to_owned(),
                transform: "exact",
            });
        }
        if let Some(value) = header_value(headers, "x-client-request-id") {
            candidates.push(RequestIdCandidate {
                lookup_key: format!("client:{value}"),
                capture_value: value.to_owned(),
                source: "responseHeaders.x-client-request-id".to_owned(),
                transform: "sub2api_client_prefix",
            });
        }
    }
    if let Some(headers) = object.get("requestHeaders").and_then(Value::as_object)
        && let Some(value) = header_value(headers, "x-client-request-id")
    {
        candidates.push(RequestIdCandidate {
            lookup_key: format!("client:{value}"),
            capture_value: value.to_owned(),
            source: "requestHeaders.x-client-request-id".to_owned(),
            transform: "sub2api_client_prefix",
        });
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

fn build_usage_index_from_paths(
    paths: &[PathBuf],
) -> Result<(HashMap<String, UsageIndexEntry>, u64, u64, u64)> {
    let mut index: HashMap<String, UsageIndexEntry> = HashMap::new();
    let mut usage_rows = 0_u64;
    let mut usable = 0_u64;
    let mut invalid = 0_u64;
    for path in paths {
        for value in read_usage_values(path)? {
            usage_rows += 1;
            let Some(fact) = usage_fact(&value)? else {
                invalid += 1;
                continue;
            };
            usable += 1;
            let entry = index
                .entry(fact.request_id.clone())
                .or_insert_with(|| UsageIndexEntry { facts: Vec::new() });
            if !entry
                .facts
                .iter()
                .any(|existing| existing.fingerprint == fact.fingerprint)
            {
                entry.facts.push(fact);
            }
        }
    }
    Ok((index, usage_rows, usable, invalid))
}

fn usage_fact(value: &Value) -> Result<Option<UsageFact>> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let request_id = first_string(object, &["request_id", "requestId", "upstream_request_id"]);
    let Some(request_id) = request_id else {
        return Ok(None);
    };
    let requested_model = first_string(object, &["requested_model", "requestedModel", "model"]);
    let provider = provider_fact(object);
    let (Some(requested_model), Some((provider, provider_source))) = (requested_model, provider)
    else {
        return Ok(None);
    };
    let upstream_model = first_string(object, &["upstream_model", "upstreamModel"]);
    let response_model = first_string(object, &["response_model", "responseModel"]);
    let mapping = first_string(object, &["model_mapping_chain", "modelMappingChain"]);
    let mut evidence = Map::new();
    evidence.insert("source".to_owned(), json!("sub2api_usage_log"));
    evidence.insert("request_id".to_owned(), json!(request_id));
    evidence.insert("requested_model".to_owned(), json!(requested_model));
    evidence.insert("provider".to_owned(), json!(provider));
    evidence.insert("provider_source".to_owned(), json!(provider_source));
    evidence.insert(
        "upstream_model".to_owned(),
        upstream_model.map(Value::String).unwrap_or(Value::Null),
    );
    evidence.insert(
        "response_model".to_owned(),
        response_model.map(Value::String).unwrap_or(Value::Null),
    );
    evidence.insert(
        "model_mapping_chain".to_owned(),
        mapping.map(Value::String).unwrap_or(Value::Null),
    );
    for (canonical, aliases) in [
        ("user_id", &["user_id", "userId"][..]),
        ("api_key_id", &["api_key_id", "apiKeyId"][..]),
        ("account_id", &["account_id", "accountId"][..]),
        ("group_id", &["group_id", "groupId"][..]),
        ("channel_id", &["channel_id", "channelId"][..]),
    ] {
        if let Some(value) = first_value(object, aliases) {
            evidence.insert(canonical.to_owned(), value.clone());
        }
    }
    for (canonical, aliases) in [
        ("input_tokens", &["input_tokens", "inputTokens"][..]),
        ("output_tokens", &["output_tokens", "outputTokens"][..]),
        (
            "cache_creation_tokens",
            &["cache_creation_tokens", "cacheCreationTokens"][..],
        ),
        (
            "cache_read_tokens",
            &["cache_read_tokens", "cacheReadTokens"][..],
        ),
    ] {
        if let Some(value) = first_value(object, aliases).and_then(value_as_u64) {
            evidence.insert(canonical.to_owned(), json!(value));
        }
    }
    let non_cached_input = evidence.get("input_tokens").and_then(Value::as_u64);
    let cache_read = evidence.get("cache_read_tokens").and_then(Value::as_u64);
    if non_cached_input.is_some() || cache_read.is_some() {
        evidence.insert(
            "input_tokens_semantics".to_owned(),
            json!("sub2api_non_cached_input"),
        );
    }
    if let Some((input, cached)) = non_cached_input.zip(cache_read) {
        evidence.insert(
            "api_input_tokens".to_owned(),
            json!(input.saturating_add(cached)),
        );
    }
    if let Some(value) = first_string(
        object,
        &["created_at", "createdAt", "observed_at", "observedAt"],
    ) {
        evidence.insert("observed_at".to_owned(), json!(value));
    }
    if let Some(value) = first_value(object, &["id", "usage_log_id", "usageLogId"]) {
        evidence.insert("usage_log_id".to_owned(), value.clone());
    }
    let evidence = Value::Object(evidence);
    let fingerprint = gateway_evidence_fingerprint(&evidence);
    Ok(Some(UsageFact {
        request_id,
        evidence,
        fingerprint,
    }))
}

fn first_string(object: &Map<String, Value>, aliases: &[&str]) -> Option<String> {
    aliases.iter().find_map(|field| {
        object
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
    })
}

fn provider_fact(object: &Map<String, Value>) -> Option<(String, &'static str)> {
    for (field, source) in [
        ("provider", "usage_log.provider"),
        ("platform", "usage_log.platform"),
        ("effective_platform", "usage_log.effective_platform"),
        ("provider_platform", "usage_log.provider_platform"),
        ("account_platform", "usage_log.account_platform"),
    ] {
        if let Some(value) = object
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            return Some((value.to_owned(), source));
        }
    }
    for (container, source_prefix) in [
        ("group", "usage_log.group"),
        ("account", "usage_log.account"),
        ("channel", "usage_log.channel"),
    ] {
        let Some(nested) = object.get(container).and_then(Value::as_object) else {
            continue;
        };
        for field in ["platform", "provider"] {
            if let Some(value) = nested
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                let source = match (source_prefix, field) {
                    ("usage_log.group", "platform") => "usage_log.group.platform",
                    ("usage_log.group", _) => "usage_log.group.provider",
                    ("usage_log.account", "platform") => "usage_log.account.platform",
                    ("usage_log.account", _) => "usage_log.account.provider",
                    ("usage_log.channel", "platform") => "usage_log.channel.platform",
                    _ => "usage_log.channel.provider",
                };
                return Some((value.to_owned(), source));
            }
        }
    }
    None
}

fn first_value<'a>(object: &'a Map<String, Value>, aliases: &[&str]) -> Option<&'a Value> {
    aliases.iter().find_map(|field| object.get(*field))
}

fn header_value<'a>(headers: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name)
            .then(|| value.as_str())
            .flatten()
            .filter(|value| !value.trim().is_empty())
    })
}

fn describe_sources(paths: &[PathBuf]) -> Result<Vec<EnrichmentSource>> {
    paths
        .iter()
        .map(|path| {
            Ok(EnrichmentSource {
                path: path.to_string_lossy().into_owned(),
                bytes: fs::metadata(path)?.len(),
                sha256: sha256_file(path)?,
            })
        })
        .collect()
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
        let single = canonical.join("RAW_SOURCE.json");
        if single.is_file() {
            has_lineage = true;
            insert_raw_source(
                &mut sources,
                serde_json::from_slice(&fs::read(&single)?)
                    .with_context(|| format!("parse {}", single.display()))?,
            )?;
        }
        let set = canonical.join("RAW_SOURCES.json");
        if set.is_file() {
            has_lineage = true;
            let values: Vec<RawSourceLineage> = serde_json::from_slice(&fs::read(&set)?)
                .with_context(|| format!("parse {}", set.display()))?;
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
            "cannot mix Raw-lineaged and unlineaged enrichment inputs: lineaged={lineaged:?}, unlineaged={unlineaged:?}"
        );
    }
    Ok(sources.into_values().collect())
}

fn insert_raw_source(
    sources: &mut BTreeMap<String, RawSourceLineage>,
    source: RawSourceLineage,
) -> Result<()> {
    if source.schema_version != RAW_LINEAGE_SCHEMA_VERSION
        || source.archive_id.trim().is_empty()
        || source.completeness != "complete"
        || source.segment_count == 0
        || source.checkpoint_key.trim().is_empty()
        || source.manifest_key.trim().is_empty()
        || !valid_sha256(&source.checkpoint_sha256)
        || !valid_sha256(&source.manifest_sha256)
    {
        bail!("invalid or incomplete Raw lineage {}", source.archive_id);
    }
    if let Some(existing) = sources.get(&source.archive_id)
        && existing != &source
    {
        bail!("conflicting Raw lineage for archive {}", source.archive_id);
    }
    sources.insert(source.archive_id.clone(), source);
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn discover_inputs(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let files = discover_files(inputs, |name| {
        (name.ends_with(".ndjson") || name.ends_with(".jsonl") || name.ends_with(".jsonl.zst"))
            && !name.ends_with(".open.ndjson")
    })?;
    for input in inputs.iter().filter(|input| input.is_file()) {
        if input
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".open.ndjson"))
        {
            bail!("refusing active open WAL input: {}", input.display());
        }
    }
    Ok(files)
}

fn discover_usage_inputs(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    discover_files(inputs, |name| {
        name.ends_with(".json")
            || name.ends_with(".ndjson")
            || name.ends_with(".jsonl")
            || name.ends_with(".zst")
    })
}

fn discover_files<F>(inputs: &[PathBuf], predicate: F) -> Result<Vec<PathBuf>>
where
    F: Fn(&str) -> bool + Copy,
{
    let mut files = Vec::new();
    for input in inputs {
        if input.is_file() {
            let name = input
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if !predicate(name) {
                bail!("unsupported input file: {}", input.display());
            }
            files.push(input.canonicalize()?);
        } else if input.is_dir() {
            for entry in walkdir::WalkDir::new(input).follow_links(false) {
                let entry = entry?;
                if entry.file_type().is_file() && predicate(&entry.file_name().to_string_lossy()) {
                    files.push(entry.path().canonicalize()?);
                }
            }
        } else {
            bail!("input does not exist: {}", input.display());
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn read_usage_values(path: &Path) -> Result<Vec<Value>> {
    let mut bytes = Vec::new();
    let mut reader = open_jsonl_reader(path)?;
    reader.read_to_end(&mut bytes)?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        return Ok(extract_usage_values(value));
    }
    let mut values = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        values.push(
            serde_json::from_slice(line).with_context(|| {
                format!("parse usage log {} line {}", path.display(), index + 1)
            })?,
        );
    }
    Ok(values)
}

fn extract_usage_values(value: Value) -> Vec<Value> {
    match value {
        Value::Array(values) => values,
        Value::Object(mut object) => {
            for key in ["items", "usage_logs", "usageLogs", "logs"] {
                if let Some(Value::Array(values)) = object.remove(key) {
                    return values;
                }
            }
            if let Some(data) = object.remove("data") {
                return extract_usage_values(data);
            }
            vec![Value::Object(object)]
        }
        _ => vec![value],
    }
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

    fn capture(id: &str) -> Value {
        json!({
            "captureId": format!("cap-{id}"),
            "requestBody": {"kind":"json","value":{"model":"gpt-5.6-sol"}},
            "responseBody": {"kind":"json","value":{}},
            "responseHeaders": {"x-request-id": id}
        })
    }

    fn usage(id: &str, model: &str) -> Value {
        json!({
            "request_id": id,
            "requested_model": model,
            "upstream_model": model,
            "provider": "OpenAI",
            "input_tokens": 10,
            "output_tokens": 2,
            "cache_read_tokens": 4
        })
    }

    #[test]
    fn joins_only_on_explicit_request_id() {
        let mut value = capture("req-1");
        let (index, ..) = build_usage_index_from_values(vec![usage("req-1", "gpt-5.6-sol")]);
        assert!(matches!(
            enrich_one(&mut value, &index),
            JoinOutcome::Matched { .. }
        ));
        assert_eq!(value["gatewayEvidence"]["request_id"], "req-1");
        assert_eq!(
            value["gatewayEvidence"]["input_tokens_semantics"],
            "sub2api_non_cached_input"
        );
        assert_eq!(value["gatewayEvidence"]["api_input_tokens"], 14);
    }

    #[test]
    fn applies_the_documented_sub2api_client_id_namespace() {
        let mut value = capture("unrelated-upstream");
        value["requestId"] = json!("client-request-1");
        let (index, ..) =
            build_usage_index_from_values(vec![usage("client:client-request-1", "gpt-5.6-sol")]);
        assert!(matches!(
            enrich_one(&mut value, &index),
            JoinOutcome::Matched { .. }
        ));
        assert_eq!(
            value["gatewayEvidenceJoin"]["transform"],
            "sub2api_client_prefix"
        );
        assert_eq!(
            value["gatewayEvidenceJoin"]["capture_request_id"],
            "client-request-1"
        );
    }

    #[test]
    fn joins_the_gateway_response_id_when_forwarded_id_was_replaced() {
        let mut value = capture("unrelated-upstream");
        value["requestHeaders"] = json!({"x-client-request-id":"forwarded-client-id"});
        value["responseHeaders"] = json!({
            "x-request-id":"unrelated-upstream",
            "x-client-request-id":"gateway-client-id"
        });
        value["requestId"] = json!("gateway-client-id");
        let (index, ..) =
            build_usage_index_from_values(vec![usage("client:gateway-client-id", "gpt-5.5")]);

        assert!(matches!(
            enrich_one(&mut value, &index),
            JoinOutcome::Matched { .. }
        ));
        assert_eq!(
            value["gatewayEvidenceJoin"]["capture_request_id"],
            "gateway-client-id"
        );
        assert_ne!(
            value["gatewayEvidenceJoin"]["capture_request_id"],
            "forwarded-client-id"
        );
    }

    #[test]
    fn accepts_sub2api_effective_platform_from_account_group_join() {
        let value = json!({
            "request_id":"req-platform",
            "requested_model":"gpt-5.6-sol",
            "upstream_model":"gpt-5.6-sol",
            "effective_platform":"openai",
            "input_tokens":10,
            "cache_read_tokens":4,
            "output_tokens":2
        });
        let fact = usage_fact(&value).unwrap().unwrap();
        assert_eq!(fact.evidence["provider"], "openai");
        assert_eq!(
            fact.evidence["provider_source"],
            "usage_log.effective_platform"
        );
        assert_eq!(fact.evidence["api_input_tokens"], 14);
    }

    #[test]
    fn conflicting_rows_are_ambiguous() {
        let mut value = capture("req-1");
        let (index, ..) = build_usage_index_from_values(vec![
            usage("req-1", "gpt-5.6-sol"),
            usage("req-1", "gpt-5.5"),
        ]);
        assert!(matches!(
            enrich_one(&mut value, &index),
            JoinOutcome::Ambiguous { .. }
        ));
        assert!(value.get("gatewayEvidence").is_none());
    }

    #[test]
    fn missing_id_does_not_fall_back_to_model_or_time() {
        let mut value = capture("req-1");
        value["responseHeaders"] = json!({});
        let (index, ..) = build_usage_index_from_values(vec![usage("req-1", "gpt-5.6-sol")]);
        assert!(matches!(
            enrich_one(&mut value, &index),
            JoinOutcome::Unmatched { reason } if reason == "request_id_missing"
        ));
    }

    fn build_usage_index_from_values(
        values: Vec<Value>,
    ) -> (HashMap<String, UsageIndexEntry>, u64, u64, u64) {
        let mut index = HashMap::new();
        let mut usable = 0;
        let mut invalid = 0;
        for value in values {
            if let Some(fact) = usage_fact(&value).unwrap() {
                usable += 1;
                index
                    .entry(fact.request_id.clone())
                    .or_insert_with(|| UsageIndexEntry { facts: Vec::new() })
                    .facts
                    .push(fact);
            } else {
                invalid += 1;
            }
        }
        (index, usable + invalid, usable, invalid)
    }

    #[test]
    fn wrapper_usage_documents_are_supported() {
        let values = extract_usage_values(json!({
            "code":0,
            "data":{"items":[usage("req-1", "gpt-5.6-sol")]}
        }));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["request_id"], "req-1");
    }

    #[test]
    fn artifact_round_trip_preserves_raw_lineage() {
        let directory = tempfile::tempdir().unwrap();
        let capture_root = directory.path().join("raw");
        fs::create_dir_all(capture_root.join("segments")).unwrap();
        fs::write(
            capture_root
                .join("segments")
                .join("segment-00000000000000000001.sealed.ndjson"),
            format!("{}\n", capture("req-1")),
        )
        .unwrap();
        let lineage = RawSourceLineage {
            schema_version: RAW_LINEAGE_SCHEMA_VERSION.to_owned(),
            archive_id: "archive-1".to_owned(),
            completeness: "complete".to_owned(),
            checkpoint_key: "raw/archive-1/CHECKPOINT.json".to_owned(),
            checkpoint_sha256: "a".repeat(64),
            manifest_key: "raw/archive-1/manifest.json".to_owned(),
            manifest_sha256: "b".repeat(64),
            segment_count: 1,
            total_records: 1,
            total_bytes: 1,
        };
        fs::write(
            capture_root.join("RAW_SOURCE.json"),
            serde_json::to_vec(&lineage).unwrap(),
        )
        .unwrap();
        let usage_path = directory.path().join("usage.jsonl");
        fs::write(&usage_path, format!("{}\n", usage("req-1", "gpt-5.6-sol"))).unwrap();
        let output = directory.path().join("enriched");
        let manifest = enrich_captures(EnrichConfig {
            inputs: vec![capture_root],
            usage_logs: vec![usage_path],
            output: output.clone(),
            zstd_level: 1,
            replace: false,
        })
        .unwrap();
        assert_eq!(manifest.matched, 1);
        assert_eq!(manifest.raw_sources, vec![lineage.clone()]);
        assert_eq!(verify_enrichment(&output).unwrap(), manifest);
        let mut reader = open_jsonl_reader(&output.join(&manifest.output_file)).unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["gatewayEvidence"]["request_id"], "req-1");
        assert_eq!(value["gatewayEvidenceJoin"]["mode"], "exact_request_id");
        let assembly = crate::assemble::assemble(crate::assemble::AssembleConfig {
            inputs: vec![output],
            output: directory.path().join("assembly"),
            task_session_id: None,
            session_id: None,
            partitions: 1,
            zstd_level: 1,
            replace: false,
        })
        .unwrap();
        assert_eq!(assembly.raw_sources, vec![lineage]);
    }

    #[test]
    fn enrichment_rejects_mixed_raw_lineage_inputs() {
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
                .contains("cannot mix Raw-lineaged and unlineaged enrichment inputs")
        );
    }
}
