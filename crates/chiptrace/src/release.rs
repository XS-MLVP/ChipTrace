use crate::jsonl::{absolute_path, ensure_safe_relative_path, sha256_file, string_field, utc_now};
use crate::schema::{
    BuyerAssessment, FileManifest, RAW_LINEAGE_SCHEMA_VERSION, RELEASE_SCHEMA_VERSION,
    RawSourceLineage, ReleaseCounts, ReleaseManifest, TokenCounts,
};
use crate::score::{
    AssessmentSchemaValidators, Profile, assess_session, assessment_contract_valid,
    assessment_record_from_session, eligible_assessment_contract_valid, exact_content_fingerprint,
    is_contiguous_subsequence, materialize_profile_session, message_fingerprints,
    recompute_assessment_for_version,
};
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;
use walkdir::WalkDir;

const PART_SIZE_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ReleaseConfig {
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
    pub release_id: String,
    pub profile: Profile,
    pub minimum_score: f64,
    pub target_part_bytes: u64,
    pub dedup_partitions: usize,
    pub zstd_level: i32,
    pub workers: usize,
    pub replace: bool,
    pub require_pass: bool,
}

#[derive(Debug, Clone)]
struct Candidate {
    session: Value,
    exact_removed: u64,
    subset_removed: u64,
}

#[derive(Debug, Clone, Default)]
struct DedupStats {
    exact_removed: u64,
    subset_removed: u64,
    conflicts: u64,
    conflict_records: u64,
}

#[derive(Debug, Default)]
struct ScorePartitionResult {
    index: usize,
    exact_removed: u64,
    assessed: u64,
    eligible: u64,
    rejected: u64,
    eligible_tokens: TokenCounts,
    assessed_tokens: TokenCounts,
    failure_reason_counts: BTreeMap<String, u64>,
    data_parts: Vec<FileManifest>,
    assessment: Option<FileManifest>,
}

#[derive(Debug, Default)]
struct ReportAudit {
    assessed: u64,
    eligible: u64,
    rejected: u64,
    divergent_conflicts: u64,
    divergent_records: u64,
    assessed_tokens: TokenCounts,
    eligible_tokens: TokenCounts,
    failure_reason_counts: BTreeMap<String, u64>,
    eligible_fingerprints: HashSet<String>,
    assessment_fingerprints: HashSet<String>,
}

pub fn build_release(config: ReleaseConfig) -> Result<ReleaseManifest> {
    if config.inputs.is_empty() {
        bail!("at least one Session JSONL input is required");
    }
    if config.release_id.trim().is_empty() {
        bail!("release_id is required");
    }
    if !(0.0..=100.0).contains(&config.minimum_score) {
        bail!("minimum_score must be between 0 and 100");
    }
    if config.require_pass && config.profile == Profile::BuyerV7 && config.minimum_score < 90.0 {
        bail!("buyer-v7 Release requires minimum_score >= 90");
    }
    if config.target_part_bytes == 0 || config.dedup_partitions == 0 {
        bail!("target part bytes and dedup partitions must be positive");
    }
    let release_workers = if config.workers == 0 {
        std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1)
    } else {
        config.workers
    }
    .clamp(1, config.dedup_partitions);
    let inputs = discover_session_inputs(&config.inputs)?;
    if inputs.is_empty() {
        bail!("no Session JSONL inputs found");
    }
    let raw_sources = discover_release_raw_sources(&config.inputs, &inputs)?;
    let output = absolute_path(&config.output)?;
    if output.exists() && !config.replace {
        bail!("release output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("release output has no parent"))?;
    fs::create_dir_all(parent)?;
    let work = TempDir::new_in(parent)?;
    let partition_root = work.path().join("dedup");
    let candidate_root = work.path().join("candidates");
    let score_root = work.path().join("score-partitions");
    let staging = work.path().join("release");
    fs::create_dir_all(&partition_root)?;
    fs::create_dir_all(&candidate_root)?;
    fs::create_dir_all(&score_root)?;
    fs::create_dir_all(staging.join("data"))?;
    fs::create_dir_all(staging.join("reports"))?;

    let mut partition_writers = Vec::with_capacity(config.dedup_partitions);
    for index in 0..config.dedup_partitions {
        partition_writers.push(BufWriter::with_capacity(
            4 * 1024 * 1024,
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(partition_root.join(format!("sessions-{index:05}.jsonl")))?,
        ));
    }
    let mut counts = ReleaseCounts::default();
    for path in &inputs {
        let mut reader = crate::jsonl::open_jsonl_reader(path)?;
        let mut line = Vec::new();
        let mut line_number = 0_u64;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            line_number += 1;
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            counts.input_records += 1;
            let session: Value = match serde_json::from_slice(&line) {
                Ok(value) => value,
                Err(_) => {
                    counts.parse_failures += 1;
                    continue;
                }
            };
            let Some(session_id) = string_field(&session, "session_id") else {
                counts.parse_failures += 1;
                continue;
            };
            let key = string_field(&session, "trajectory_id").unwrap_or(session_id);
            let index = partition_index(key, config.dedup_partitions);
            partition_writers[index]
                .write_all(&line)
                .with_context(|| format!("partition {} line {}", path.display(), line_number))?;
            partition_writers[index].write_all(b"\n")?;
        }
    }
    for mut writer in partition_writers {
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }

    let mut dedup = DedupStats::default();
    let mut candidate_paths = Vec::new();
    let mut conflict_writer = CompressedWriter::create(
        &staging.join("reports/divergent-sessions.jsonl.zst"),
        config.zstd_level,
        4,
    )?;
    let mut conflict_records = 0_u64;
    for index in 0..config.dedup_partitions {
        let input = partition_root.join(format!("sessions-{index:05}.jsonl"));
        let output = candidate_root.join(format!("candidate-{index:05}.jsonl"));
        let (stats, candidates, conflicts) =
            deduplicate_partition(&input, &output, &mut conflict_writer)?;
        dedup.exact_removed += stats.exact_removed;
        dedup.subset_removed += stats.subset_removed;
        dedup.conflicts += stats.conflicts;
        dedup.conflict_records += stats.conflict_records;
        conflict_records += conflicts;
        if candidates > 0 {
            candidate_paths.push(output);
        }
    }
    conflict_writer.finish()?;

    let mut score_writers = Vec::with_capacity(release_workers);
    for index in 0..release_workers {
        score_writers.push(BufWriter::with_capacity(
            8 * 1024 * 1024,
            File::create(score_root.join(format!("score-{index:05}.jsonl")))?,
        ));
    }
    for path in candidate_paths {
        let reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(&path)?);
        for line in reader.split(b'\n') {
            let line = line?;
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let candidate: Value = serde_json::from_slice(&line)?;
            let session = candidate
                .get("session")
                .ok_or_else(|| anyhow::anyhow!("candidate session missing"))?;
            let fingerprint = exact_content_fingerprint(session);
            let index = partition_index(&fingerprint, release_workers);
            score_writers[index].write_all(&line)?;
            score_writers[index].write_all(b"\n")?;
        }
    }
    for mut writer in score_writers {
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    let score_paths: Vec<PathBuf> = (0..release_workers)
        .map(|index| score_root.join(format!("score-{index:05}.jsonl")))
        .collect();
    let mut score_results: Vec<ScorePartitionResult> = score_paths
        .par_iter()
        .enumerate()
        .map(|(index, path)| score_partition(path, &staging, index, &config))
        .collect::<Result<Vec<_>>>()?;
    score_results.sort_by_key(|result| result.index);

    let mut eligible_tokens = TokenCounts::default();
    let mut assessed_tokens = TokenCounts::default();
    let mut failure_reason_counts = BTreeMap::new();
    let mut data_parts = Vec::new();
    let mut reports = Vec::new();
    for result in score_results {
        dedup.exact_removed = dedup.exact_removed.saturating_add(result.exact_removed);
        counts.assessed_sessions = counts.assessed_sessions.saturating_add(result.assessed);
        counts.eligible_sessions = counts.eligible_sessions.saturating_add(result.eligible);
        counts.rejected_sessions = counts.rejected_sessions.saturating_add(result.rejected);
        eligible_tokens.add_assign(&result.eligible_tokens);
        assessed_tokens.add_assign(&result.assessed_tokens);
        for (reason, count) in result.failure_reason_counts {
            *failure_reason_counts.entry(reason).or_insert(0) += count;
        }
        data_parts.extend(result.data_parts);
        reports.extend(result.assessment);
    }
    data_parts.sort_by(|left, right| left.file.cmp(&right.file));
    reports.sort_by(|left, right| left.file.cmp(&right.file));
    counts.exact_duplicates_removed = dedup.exact_removed;
    counts.subset_snapshots_removed = dedup.subset_removed;
    counts.divergent_session_conflicts = dedup.conflicts;
    counts.divergent_session_records = dedup.conflict_records;
    counts.rejected_sessions = counts
        .rejected_sessions
        .saturating_add(dedup.conflict_records);
    let conflict_path = staging.join("reports/divergent-sessions.jsonl.zst");
    if conflict_records > 0 {
        reports.push(file_manifest(
            &staging,
            &conflict_path,
            Some(conflict_records),
            None,
        )?);
    } else {
        fs::remove_file(&conflict_path)?;
    }
    let conserved = counts.input_records
        == counts
            .parse_failures
            .saturating_add(counts.exact_duplicates_removed)
            .saturating_add(counts.subset_snapshots_removed)
            .saturating_add(counts.divergent_session_records)
            .saturating_add(counts.assessed_sessions);
    let validation_status =
        if counts.parse_failures == 0 && counts.eligible_sessions > 0 && conserved {
            "pass".to_owned()
        } else {
            "fail".to_owned()
        };
    let manifest = ReleaseManifest {
        schema_version: RELEASE_SCHEMA_VERSION.to_owned(),
        release_id: config.release_id,
        created_at_utc: utc_now(),
        format: "one complete Session per UTF-8 JSONL line; zstd compressed".to_owned(),
        session_atomic: true,
        session_split_count: 0,
        buyer_profile: config.profile.as_str().to_owned(),
        minimum_score: config.minimum_score,
        tokenizer: eligible_tokens.tokenizer.clone(),
        compression: format!("zstd-{level}", level = config.zstd_level),
        processing_workers: release_workers,
        target_part_bytes: config.target_part_bytes,
        raw_sources,
        counts,
        eligible_tokens,
        assessed_tokens,
        failure_reason_counts,
        parts: data_parts,
        reports,
        validation_status,
    };
    let manifest_path = staging.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    write_checksums(&staging, &manifest)?;
    sync_tree(&staging)?;
    verify_release(&staging, false)?;
    if config.require_pass && manifest.validation_status != "pass" {
        bail!(
            "Release failed closed: eligible_sessions={}, parse_failures={}, conserved={conserved}",
            manifest.counts.eligible_sessions,
            manifest.counts.parse_failures
        );
    }
    if output.exists() {
        fs::remove_dir_all(&output)?;
    }
    fs::rename(&staging, &output)?;
    sync_directory(parent)?;
    Ok(manifest)
}

pub fn verify_release(root: &Path, require_pass: bool) -> Result<ReleaseManifest> {
    let manifest_path = root.join("manifest.json");
    let manifest: ReleaseManifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    if manifest.schema_version != RELEASE_SCHEMA_VERSION {
        bail!("unsupported release schema {}", manifest.schema_version);
    }
    if !manifest.session_atomic || manifest.session_split_count != 0 {
        bail!("release is not Session atomic");
    }
    for source in &manifest.raw_sources {
        validate_release_raw_source(source)?;
    }
    if !manifest.minimum_score.is_finite() || !(0.0..=100.0).contains(&manifest.minimum_score) {
        bail!("release minimum_score must be between 0 and 100");
    }
    if manifest.buyer_profile != Profile::BuyerV7.as_str() {
        bail!(
            "unsupported release buyer profile {:?}",
            manifest.buyer_profile
        );
    }
    let profile = Profile::BuyerV7;
    let assessment_schemas = AssessmentSchemaValidators::new()?;
    if require_pass && manifest.validation_status != "pass" {
        bail!(
            "release validation status is {}, not pass",
            manifest.validation_status
        );
    }
    let mut expected_files = HashSet::from(["manifest.json".to_owned(), "SHA256SUMS".to_owned()]);
    let mut eligible = 0_u64;
    let mut eligible_tokens = TokenCounts::default();
    let mut eligible_fingerprints = HashSet::new();
    for file in manifest.parts.iter().chain(manifest.reports.iter()) {
        ensure_safe_relative_path(&file.file)?;
        if !expected_files.insert(file.file.clone()) {
            bail!("duplicate release file path: {}", file.file);
        }
        let path = root.join(&file.file);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("release entry is not a regular file: {}", path.display());
        }
        if path.metadata()?.len() != file.bytes || sha256_file(&path)? != file.sha256 {
            bail!("release checksum mismatch: {}", path.display());
        }
    }
    for part in &manifest.parts {
        let path = root.join(&part.file);
        let mut reader = crate::jsonl::open_jsonl_reader(&path)?;
        let mut line = Vec::new();
        let mut part_records = 0_u64;
        let mut part_bytes = 0_u64;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                bail!("release part contains an empty JSONL line: {}", part.file);
            }
            part_bytes = part_bytes.saturating_add(line.len() as u64);
            let session: Value = serde_json::from_slice(&line)?;
            let assessment = validate_embedded_acceptance(
                &session,
                profile,
                manifest.minimum_score,
                &assessment_schemas,
            )?;
            if !eligible_fingerprints.insert(exact_content_fingerprint(&session)) {
                bail!("release contains duplicate eligible Session content");
            }
            eligible_tokens.add_assign(&assessment.tokens);
            part_records += 1;
            eligible += 1;
        }
        if part.records != Some(part_records) {
            bail!("release part record count mismatch: {}", part.file);
        }
        if part.uncompressed_bytes != Some(part_bytes) {
            bail!(
                "release part uncompressed byte count mismatch: {}",
                part.file
            );
        }
    }
    if eligible != manifest.counts.eligible_sessions {
        bail!("release eligible session count mismatch");
    }
    if eligible_tokens != manifest.eligible_tokens {
        bail!("release eligible Token totals mismatch");
    }
    let report_audit = verify_release_reports(root, &manifest, profile, &assessment_schemas)?;
    if report_audit.assessed != manifest.counts.assessed_sessions
        || report_audit.eligible != manifest.counts.eligible_sessions
        || report_audit
            .rejected
            .saturating_add(report_audit.divergent_records)
            != manifest.counts.rejected_sessions
        || report_audit.divergent_conflicts != manifest.counts.divergent_session_conflicts
        || report_audit.divergent_records != manifest.counts.divergent_session_records
        || report_audit.assessed_tokens != manifest.assessed_tokens
        || report_audit.eligible_tokens != manifest.eligible_tokens
        || report_audit.failure_reason_counts != manifest.failure_reason_counts
        || report_audit.eligible_fingerprints != eligible_fingerprints
    {
        bail!("release assessment, rejection, Token, or fingerprint totals are inconsistent");
    }
    let conserved = manifest.counts.input_records
        == manifest
            .counts
            .parse_failures
            .saturating_add(manifest.counts.exact_duplicates_removed)
            .saturating_add(manifest.counts.subset_snapshots_removed)
            .saturating_add(manifest.counts.divergent_session_records)
            .saturating_add(manifest.counts.assessed_sessions);
    let expected_status = if manifest.counts.parse_failures == 0
        && manifest.counts.eligible_sessions > 0
        && conserved
    {
        "pass"
    } else {
        "fail"
    };
    if !conserved || manifest.validation_status != expected_status {
        bail!("release conservation or validation status is inconsistent");
    }
    let mut actual_files = HashSet::new();
    for entry in WalkDir::new(root).min_depth(1).follow_links(false) {
        let entry = entry?;
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_str()
            .context("release path is not UTF-8")?
            .replace('\\', "/");
        if entry.file_type().is_file() {
            actual_files.insert(relative);
        } else if !entry.file_type().is_dir() || !matches!(relative.as_str(), "data" | "reports") {
            bail!("release contains an unexpected entry: {relative}");
        }
    }
    if actual_files != expected_files {
        bail!("release file set does not match manifest");
    }
    verify_checksum_file(root, &manifest)?;
    Ok(manifest)
}

fn verify_release_reports(
    root: &Path,
    manifest: &ReleaseManifest,
    profile: Profile,
    assessment_schemas: &AssessmentSchemaValidators,
) -> Result<ReportAudit> {
    let mut audit = ReportAudit::default();
    for report in &manifest.reports {
        let mut reader = crate::jsonl::open_jsonl_reader(&root.join(&report.file))?;
        let mut line = Vec::new();
        let mut records = 0_u64;
        let mut uncompressed_bytes = 0_u64;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                bail!(
                    "release report contains an empty JSONL line: {}",
                    report.file
                );
            }
            records = records.saturating_add(1);
            uncompressed_bytes = uncompressed_bytes.saturating_add(line.len() as u64);
            let value: Value = serde_json::from_slice(&line)?;
            if report.file.starts_with("reports/assessments-part-")
                && report.file.ends_with(".jsonl.zst")
            {
                audit_assessment_record(&value, manifest, profile, assessment_schemas, &mut audit)?;
            } else if report.file == "reports/divergent-sessions.jsonl.zst" {
                audit_divergent_record(&value, &mut audit)?;
            } else {
                bail!("release contains an unsupported report: {}", report.file);
            }
        }
        if report.records != Some(records)
            || report
                .uncompressed_bytes
                .is_some_and(|expected| expected != uncompressed_bytes)
        {
            bail!(
                "release report record or byte count mismatch: {}",
                report.file
            );
        }
    }
    if audit.assessment_fingerprints.len() as u64 != audit.assessed {
        bail!("release assessment report contains duplicate content fingerprints");
    }
    Ok(audit)
}

fn audit_assessment_record(
    value: &Value,
    manifest: &ReleaseManifest,
    profile: Profile,
    assessment_schemas: &AssessmentSchemaValidators,
    audit: &mut ReportAudit,
) -> Result<()> {
    assessment_schemas.validate(value)?;
    let assessment: BuyerAssessment = serde_json::from_value(
        value
            .pointer("/quality/buyer_acceptance")
            .cloned()
            .context("assessment report has no quality.buyer_acceptance")?,
    )?;
    if !assessment_contract_valid(&assessment, profile, manifest.minimum_score) {
        bail!("release report contains an inconsistent Session assessment");
    }
    let decision = string_field(value, "release_decision");
    if decision
        != Some(if assessment.eligible {
            "eligible"
        } else {
            "rejected"
        })
    {
        bail!("release report decision does not match its assessment");
    }
    let fingerprint = string_field(value, "content_fingerprint")
        .filter(|value| valid_sha256(value))
        .context("release assessment has an invalid content fingerprint")?
        .to_owned();
    if !audit.assessment_fingerprints.insert(fingerprint.clone()) {
        bail!("release assessment report contains duplicate content fingerprints");
    }
    audit.assessed = audit.assessed.saturating_add(1);
    audit.assessed_tokens.add_assign(&assessment.tokens);
    if assessment.eligible {
        audit.eligible = audit.eligible.saturating_add(1);
        audit.eligible_tokens.add_assign(&assessment.tokens);
        audit.eligible_fingerprints.insert(fingerprint);
    } else {
        audit.rejected = audit.rejected.saturating_add(1);
    }
    for reason in assessment.failure_reasons {
        *audit.failure_reason_counts.entry(reason).or_insert(0) += 1;
    }
    Ok(())
}

fn audit_divergent_record(value: &Value, audit: &mut ReportAudit) -> Result<()> {
    let candidate_count = value
        .get("candidate_count")
        .and_then(Value::as_u64)
        .filter(|count| *count >= 2)
        .context("divergent Session report has an invalid candidate_count")?;
    let fingerprints = value
        .get("content_fingerprints")
        .and_then(Value::as_array)
        .context("divergent Session report has no content_fingerprints")?;
    if string_field(value, "reason") != Some("divergent_session_snapshots")
        || fingerprints.len() as u64 != candidate_count
        || fingerprints.iter().any(|fingerprint| {
            fingerprint
                .as_str()
                .is_none_or(|value| !valid_sha256(value))
        })
    {
        bail!("divergent Session report is inconsistent");
    }
    audit.divergent_conflicts = audit.divergent_conflicts.saturating_add(1);
    audit.divergent_records = audit.divergent_records.saturating_add(candidate_count);
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_embedded_acceptance(
    session: &Value,
    profile: Profile,
    minimum_score: f64,
    assessment_schemas: &AssessmentSchemaValidators,
) -> Result<BuyerAssessment> {
    let assessment: BuyerAssessment = serde_json::from_value(
        session
            .pointer("/quality/buyer_acceptance")
            .cloned()
            .context("release Session has no quality.buyer_acceptance")?,
    )?;
    if !eligible_assessment_contract_valid(&assessment, profile, minimum_score) {
        bail!("release contains an inconsistent or ineligible Session assessment");
    }
    assessment_schemas.validate(&assessment_record_from_session(session, "eligible"))?;
    let recomputed = recompute_assessment_for_version(
        session,
        profile,
        minimum_score,
        &assessment.schema_version,
    )
    .context("release Session uses an unsupported assessment schema")?;
    if recomputed != assessment {
        bail!("release Session quality does not match its canonical content");
    }
    Ok(assessment)
}

fn deduplicate_partition(
    input: &Path,
    output: &Path,
    conflict_writer: &mut CompressedWriter,
) -> Result<(DedupStats, u64, u64)> {
    let mut groups: HashMap<String, Vec<Value>> = HashMap::new();
    let reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
    for line in reader.split(b'\n') {
        let line = line?;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let session: Value = serde_json::from_slice(&line)?;
        let session_id = string_field(&session, "session_id")
            .ok_or_else(|| anyhow::anyhow!("candidate session_id missing"))?;
        let key = string_field(&session, "trajectory_id").unwrap_or(session_id);
        groups.entry(key.to_owned()).or_default().push(session);
    }
    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, File::create(output)?);
    let mut stats = DedupStats::default();
    let mut candidate_count = 0_u64;
    let mut conflict_count = 0_u64;
    let mut keys: Vec<String> = groups.keys().cloned().collect();
    keys.sort();
    for dedup_key in keys {
        let candidates = groups.remove(&dedup_key).unwrap();
        let mut unique = Vec::new();
        let mut exact = HashSet::new();
        for session in candidates {
            if exact.insert(exact_content_fingerprint(&session)) {
                unique.push(session);
            } else {
                stats.exact_removed += 1;
            }
        }
        // Pick the most complete snapshot deterministically.  HashMap
        // iteration order must never decide which equal-length snapshot is
        // exported.
        unique.sort_by_key(|session| std::cmp::Reverse(snapshot_order_key(session)));
        let full = unique.first().expect("dedup group empty");
        let full_messages = message_fingerprints(full);
        let subset = unique.iter().skip(1).all(|session| {
            is_contiguous_subsequence(&message_fingerprints(session), &full_messages)
        });
        if !subset {
            stats.conflicts += 1;
            stats.conflict_records += unique.len() as u64;
            conflict_count += 1;
            conflict_writer.write_value(&json!({
                "trajectory_id": dedup_key,
                "session_id": full.get("session_id"),
                "reason": "divergent_session_snapshots",
                "candidate_count": unique.len(),
                "content_fingerprints": unique
                    .iter()
                    .map(exact_content_fingerprint)
                    .collect::<Vec<_>>(),
            }))?;
            continue;
        }
        stats.subset_removed += unique.len().saturating_sub(1) as u64;
        let candidate = Candidate {
            session: full.clone(),
            exact_removed: 0,
            subset_removed: unique.len().saturating_sub(1) as u64,
        };
        serde_json::to_writer(
            &mut writer,
            &json!({
                "session": candidate.session,
                "exact_removed": candidate.exact_removed,
                "subset_removed": candidate.subset_removed,
            }),
        )?;
        writer.write_all(b"\n")?;
        candidate_count += 1;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok((stats, candidate_count, conflict_count))
}

fn snapshot_order_key(session: &Value) -> (u8, u8, u64, u64, String) {
    let final_snapshot = session
        .get("is_final_snapshot")
        .and_then(Value::as_bool)
        .unwrap_or(false) as u8;
    let terminal_status = string_field(session, "status").is_some_and(|status| {
        matches!(
            status.to_ascii_lowercase().as_str(),
            "completed" | "terminated" | "failed" | "cancelled" | "canceled" | "incomplete"
        )
    }) as u8;
    let message_count = session
        .get("messages")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0) as u64;
    let capture_count = session
        .get("source_capture_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let fingerprint = exact_content_fingerprint(session);
    (
        final_snapshot,
        terminal_status,
        message_count,
        capture_count,
        fingerprint,
    )
}

fn score_partition(
    input: &Path,
    staging: &Path,
    index: usize,
    config: &ReleaseConfig,
) -> Result<ScorePartitionResult> {
    if input.metadata()?.len() == 0 {
        return Ok(ScorePartitionResult {
            index,
            ..ScorePartitionResult::default()
        });
    }
    let assessment_path = staging.join(format!("reports/assessments-part-{index:05}.jsonl.zst"));
    let mut assessments = CompressedWriter::create(&assessment_path, config.zstd_level, 1)?;
    let mut parts = PartSet::new(
        staging.join("data"),
        config.target_part_bytes,
        config.zstd_level,
        format!("sessions-part-{index:05}"),
        1,
    );
    let mut result = ScorePartitionResult {
        index,
        ..ScorePartitionResult::default()
    };
    let mut exact_fingerprints = HashSet::new();
    let reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
    for line in reader.split(b'\n') {
        let line = line?;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let candidate: Value = serde_json::from_slice(&line)?;
        let source_session = candidate
            .get("session")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("candidate session missing"))?;
        let session = materialize_profile_session(&source_session, config.profile);
        let fingerprint = exact_content_fingerprint(&session);
        if !exact_fingerprints.insert(fingerprint.clone()) {
            result.exact_removed += 1;
            continue;
        }
        let quality = assess_session(&source_session, config.profile, config.minimum_score);
        result.assessed += 1;
        result
            .assessed_tokens
            .add_assign(&quality.buyer_acceptance.tokens);
        for reason in &quality.buyer_acceptance.failure_reasons {
            *result
                .failure_reason_counts
                .entry(reason.clone())
                .or_insert(0) += 1;
        }
        let eligible = quality.buyer_acceptance.eligible;
        let assessment = json!({
            "trajectory_id": session.get("trajectory_id"),
            "session_id": session.get("session_id"),
            "provider": session.get("provider"),
            "model": session.get("model"),
            "quality": quality,
            "release_decision": if eligible {"eligible"} else {"rejected"},
            "content_fingerprint": fingerprint,
        });
        assessments.write_value(&assessment)?;
        if eligible {
            let mut delivered = session;
            let object = delivered
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("session must be an object"))?;
            object.insert("quality".to_owned(), serde_json::to_value(&quality)?);
            parts.write_session(&delivered)?;
            result
                .eligible_tokens
                .add_assign(&quality.buyer_acceptance.tokens);
            result.eligible += 1;
        } else {
            result.rejected += 1;
        }
    }
    let (assessment_records, assessment_uncompressed) = assessments.finish()?;
    result.assessment = Some(file_manifest(
        staging,
        &assessment_path,
        Some(assessment_records),
        Some(assessment_uncompressed),
    )?);
    result.data_parts = parts.finish()?;
    Ok(result)
}

struct CountingWriter {
    inner: BufWriter<File>,
    count: Arc<AtomicU64>,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.count.fetch_add(written as u64, Ordering::Relaxed);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct CompressedWriter {
    encoder: zstd::stream::write::Encoder<'static, CountingWriter>,
    count: Arc<AtomicU64>,
    records: u64,
    uncompressed_bytes: u64,
}

impl CompressedWriter {
    fn create(path: &Path, level: i32, workers: u32) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let count = Arc::new(AtomicU64::new(0));
        let inner = CountingWriter {
            inner: BufWriter::with_capacity(8 * 1024 * 1024, File::create(path)?),
            count: Arc::clone(&count),
        };
        let mut encoder = zstd::stream::write::Encoder::new(inner, level)?;
        if workers > 1 {
            encoder.multithread(workers)?;
        }
        Ok(Self {
            encoder,
            count,
            records: 0,
            uncompressed_bytes: 0,
        })
    }

    fn write_value(&mut self, value: &Value) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        self.encoder.write_all(&bytes)?;
        self.encoder.write_all(b"\n")?;
        self.records += 1;
        self.uncompressed_bytes = self
            .uncompressed_bytes
            .saturating_add(bytes.len() as u64 + 1);
        Ok(())
    }

    fn compressed_bytes(&mut self) -> Result<u64> {
        self.encoder.flush()?;
        Ok(self.count.load(Ordering::Relaxed))
    }

    fn finish(self) -> Result<(u64, u64)> {
        let mut inner = self.encoder.finish()?;
        inner.flush()?;
        inner.inner.get_ref().sync_all()?;
        Ok((self.records, self.uncompressed_bytes))
    }
}

struct PartSet {
    root: PathBuf,
    target_bytes: u64,
    level: i32,
    current: Option<(PathBuf, CompressedWriter)>,
    next_id: u64,
    prefix: String,
    compression_workers: u32,
    manifests: Vec<FileManifest>,
    last_checked_uncompressed: u64,
}

impl PartSet {
    fn new(
        root: PathBuf,
        target_bytes: u64,
        level: i32,
        prefix: String,
        compression_workers: u32,
    ) -> Self {
        Self {
            root,
            target_bytes,
            level,
            current: None,
            next_id: 1,
            prefix,
            compression_workers,
            manifests: Vec::new(),
            last_checked_uncompressed: 0,
        }
    }

    fn write_session(&mut self, session: &Value) -> Result<()> {
        if self.current.is_none() {
            self.open_part()?;
        }
        let checkpoint = self.target_bytes.clamp(1, PART_SIZE_CHECKPOINT_BYTES);
        let should_check = {
            let (_, writer) = self.current.as_mut().expect("part opened above");
            writer.write_value(session)?;
            writer.records == 1
                || writer
                    .uncompressed_bytes
                    .saturating_sub(self.last_checked_uncompressed)
                    >= checkpoint
        };
        if should_check {
            let (_, writer) = self.current.as_mut().expect("part opened above");
            self.last_checked_uncompressed = writer.uncompressed_bytes;
            if writer.compressed_bytes()? >= self.target_bytes {
                self.close_part()?;
            }
        }
        Ok(())
    }

    fn open_part(&mut self) -> Result<()> {
        let path = self
            .root
            .join(format!("{}-{:05}.jsonl.zst", self.prefix, self.next_id));
        self.next_id += 1;
        self.last_checked_uncompressed = 0;
        self.current = Some((
            path.clone(),
            CompressedWriter::create(&path, self.level, self.compression_workers)?,
        ));
        Ok(())
    }

    fn close_part(&mut self) -> Result<()> {
        let Some((path, writer)) = self.current.take() else {
            return Ok(());
        };
        self.last_checked_uncompressed = 0;
        let (records, uncompressed) = writer.finish()?;
        if records == 0 {
            fs::remove_file(path)?;
            return Ok(());
        }
        self.manifests.push(FileManifest {
            file: format!("data/{}", path.file_name().unwrap().to_string_lossy()),
            sha256: sha256_file(&path)?,
            bytes: path.metadata()?.len(),
            records: Some(records),
            uncompressed_bytes: Some(uncompressed),
            oversized_session: Some(records == 1 && path.metadata()?.len() > self.target_bytes),
        });
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<FileManifest>> {
        self.close_part()?;
        Ok(self.manifests)
    }
}

fn file_manifest(
    root: &Path,
    path: &Path,
    records: Option<u64>,
    uncompressed: Option<u64>,
) -> Result<FileManifest> {
    Ok(FileManifest {
        file: path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/"),
        sha256: sha256_file(path)?,
        bytes: path.metadata()?.len(),
        records,
        uncompressed_bytes: uncompressed,
        oversized_session: None,
    })
}

fn write_checksums(root: &Path, manifest: &ReleaseManifest) -> Result<()> {
    let mut files: Vec<&FileManifest> = manifest
        .parts
        .iter()
        .chain(manifest.reports.iter())
        .collect();
    files.sort_by(|left, right| left.file.cmp(&right.file));
    let mut writer = BufWriter::new(File::create(root.join("SHA256SUMS"))?);
    writeln!(
        writer,
        "{}  manifest.json",
        sha256_file(&root.join("manifest.json"))?
    )?;
    for file in files {
        writeln!(writer, "{}  {}", file.sha256, file.file)?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

fn verify_checksum_file(root: &Path, manifest: &ReleaseManifest) -> Result<()> {
    let expected: HashMap<String, String> = manifest
        .parts
        .iter()
        .chain(manifest.reports.iter())
        .map(|file| (file.file.clone(), file.sha256.clone()))
        .chain(std::iter::once((
            "manifest.json".to_owned(),
            sha256_file(&root.join("manifest.json")).unwrap_or_default(),
        )))
        .collect();
    let reader = BufReader::new(File::open(root.join("SHA256SUMS"))?);
    let mut observed = HashMap::new();
    for line in reader.lines() {
        let line = line?;
        let (digest, name) = line
            .split_once("  ")
            .ok_or_else(|| anyhow::anyhow!("invalid SHA256SUMS line"))?;
        observed.insert(name.to_owned(), digest.to_owned());
    }
    if observed != expected {
        bail!("SHA256SUMS does not match release manifest");
    }
    Ok(())
}

fn discover_release_raw_sources(
    inputs: &[PathBuf],
    session_inputs: &[PathBuf],
) -> Result<Vec<RawSourceLineage>> {
    let mut sources: BTreeMap<String, RawSourceLineage> = BTreeMap::new();
    let mut lineaged = Vec::new();
    let mut unlineaged = Vec::new();
    for input in inputs {
        let canonical = input.canonicalize()?;
        let contributes = if canonical.is_file() {
            session_inputs.contains(&canonical)
        } else {
            session_inputs
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
        let manifest_path = canonical.join("manifest.json");
        if !manifest_path.is_file() {
            unlineaged.push(canonical);
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(&manifest_path)?)
            .with_context(|| format!("parse input manifest {}", manifest_path.display()))?;
        if string_field(&value, "schema_version") != Some(crate::assemble::ASSEMBLY_SCHEMA_VERSION)
        {
            unlineaged.push(canonical);
            continue;
        }
        let assembly = crate::assemble::verify_assembly(&canonical)?;
        if assembly.raw_sources.is_empty() {
            unlineaged.push(canonical);
            continue;
        }
        for source in assembly.raw_sources {
            validate_release_raw_source(&source)?;
            if let Some(existing) = sources.get(&source.archive_id)
                && existing != &source
            {
                bail!(
                    "conflicting raw source lineage for archive {}",
                    source.archive_id
                );
            }
            sources.insert(source.archive_id.clone(), source);
        }
        lineaged.push(canonical);
    }
    if !lineaged.is_empty() && !unlineaged.is_empty() {
        bail!(
            "cannot mix Raw-lineaged and unlineaged Session inputs: lineaged={lineaged:?}, unlineaged={unlineaged:?}"
        );
    }
    Ok(sources.into_values().collect())
}

fn validate_release_raw_source(source: &RawSourceLineage) -> Result<()> {
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
        bail!(
            "invalid raw source lineage for archive {}",
            source.archive_id
        );
    }
    Ok(())
}

fn discover_session_inputs(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut output = Vec::new();
    for input in inputs {
        if input.is_file() {
            output.push(input.canonicalize()?);
        } else if input.is_dir() {
            for entry in WalkDir::new(input).follow_links(false) {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let relative = entry
                    .path()
                    .strip_prefix(input)
                    .unwrap_or(entry.path())
                    .to_string_lossy();
                let name = entry.file_name().to_string_lossy();
                if (name.ends_with(".jsonl") || name.ends_with(".jsonl.zst"))
                    && (relative.starts_with("sessions/")
                        || name.starts_with("session")
                        || name.starts_with("trajectory"))
                    && !relative.starts_with("reports/")
                {
                    output.push(entry.path().canonicalize()?);
                }
            }
        } else {
            bail!("Session input does not exist: {}", input.display());
        }
    }
    output.sort();
    output.dedup();
    Ok(output)
}

fn partition_index(key: &str, partitions: usize) -> usize {
    let digest = sha2::Sha256::digest(key.as_bytes());
    u64::from_le_bytes(digest[..8].try_into().unwrap()) as usize % partitions
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
    use serde_json::json;

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

    fn session(id: &str, messages: Vec<Value>) -> Value {
        json!({
            "schema_version":"chiptrace.session.v1",
            "trajectory_id": format!("traj-{id}"),
            "session_id":id,
            "provider":"OpenAI",
            "model":"gpt-5.6-sol",
            "created_at":"2026-08-27T00:00:00Z",
            "ended_at":"2026-08-27T00:01:00Z",
            "status":"completed",
            "is_final_snapshot":true,
            "source_request_count":1,
            "system_prompt":"system",
            "tools":[],
            "messages":messages,
            "usage":{}
        })
    }

    fn eligible_session(id: &str) -> Value {
        let tool_names = [
            "repository_search",
            "file_read",
            "shell_execute",
            "source_patch",
            "test_run",
        ];
        let tools: Vec<Value> = tool_names
            .iter()
            .map(|name| {
                json!({
                    "name":name,
                    "description":format!("Execute {name}."),
                    "parameters":{
                        "type":"object",
                        "properties":{
                            "value":{"type":"string","description":"Input value."}
                        }
                    }
                })
            })
            .collect();
        let mut messages = vec![
            json!({"role":"system","content":"system"}),
            json!({"role":"user","content":"inspect the repository"}),
            json!({"role":"assistant","content":"I will inspect it."}),
        ];
        for index in 0..8 {
            messages.push(json!({
                "role":"assistant","content":"",
                "tool_calls":[{
                    "id":format!("call-{index}"),"type":"function",
                    "function":{
                        "name":tool_names[index % tool_names.len()],
                        "arguments":format!("{{\"value\":\"{index}\"}}")
                    }
                }]
            }));
            messages.push(json!({
                "role":"tool","tool_call_id":format!("call-{index}"),
                "content":format!("result-{index}"),"status":"success","is_error":false
            }));
        }
        messages.extend([
            json!({"role":"user","content":"verify the result"}),
            json!({"role":"assistant","content":"Verification passed."}),
        ]);
        let runtime_dag = json!({
            "schema_version":"chiptrace.runtime-dag.v1",
            "source":"canonical_model_interaction:cloud_evidence",
            "evidence_event_count":1,
            "roots":["root"],
            "root_mode":"single_turn",
            "task_session_ids":[],
            "session_ids":[id],
            "open_node_ids":[],
            "unresolved_node_ids":[],
            "status_conflict_node_ids":[],
            "terminal_root_ids":["root"],
            "canonical_metrics":{},
            "root_complete":true,
            "complete":true,
            "applicable":true
        });
        json!({
            "schema_version":"chiptrace.session.v1",
            "trajectory_id":format!("traj-{id}"),
            "session_id":id,
            "provider":"OpenAI",
            "model":"gpt-5.6-sol",
            "created_at":"2026-09-01T00:00:00Z",
            "ended_at":"2026-09-01T00:01:00Z",
            "status":"completed",
            "is_final_snapshot":true,
            "source_request_count":1,
            "system_prompt":"system",
            "tools":tools,
            "messages":messages,
            "usage":{},
            "meta":{
                "trace":{"session_id":id},
                "lifecycle_events":["session_start","session_end"],
                "merge_divergences":0,
                "schema_conflicts":[],
                "trace_conflicts":[],
                "system_prompt_conflicts":[],
                "usage_conflicts":[],
                "tool_execution_conflicts":[],
                "runtime_evidence_conflicts":[],
                "runtime_unknown_events":[],
                "runtime_unmapped_tools":[],
                "capture_dag":{
                    "has_cycle":false,
                    "unresolved_parent_response_ids":[],
                    "unresolved_parent_span_ids":[]
                },
                "runtime_dag":runtime_dag,
                "task_dag":{"complete":true},
                "inference_api_conservation":{"applicable":false,"complete":true},
                "model_evidence":{
                    "provider_identity_attested":true,
                    "consistent":true,
                    "api_snapshot_count":1,
                    "attestation_candidate_count":1,
                    "request_models":["gpt-5.6-sol"],
                    "effective_models":["gpt-5.6-sol"],
                    "response_models":["gpt-5.6-sol"],
                    "providers":["OpenAI"],
                    "non_attestable_api_snapshots":[]
                },
                "trace_readiness":{
                    "schema_version":"chiptrace.trace-readiness.v1",
                    "artifact_valid":true,
                    "raw_bytes_complete":true,
                    "protocol_complete":true,
                    "runtime_complete":true,
                    "root_complete":true,
                    "wire_ready":true,
                    "runtime_ready":true,
                    "delivery_ready":true
                }
            }
        })
    }

    #[test]
    fn subset_dedup_keeps_complete_snapshot() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("input.jsonl");
        let output = temporary.path().join("candidate.jsonl");
        let mut file = File::create(&input).unwrap();
        let short = session(
            "s",
            vec![
                json!({"role":"system","content":"system"}),
                json!({"role":"user","content":"one"}),
                json!({"role":"assistant","content":"answer"}),
            ],
        );
        let full = session(
            "s",
            vec![
                json!({"role":"system","content":"system"}),
                json!({"role":"user","content":"one"}),
                json!({"role":"assistant","content":"answer"}),
                json!({"role":"user","content":"two"}),
                json!({"role":"assistant","content":"answer two"}),
            ],
        );
        writeln!(file, "{}", serde_json::to_string(&short).unwrap()).unwrap();
        writeln!(file, "{}", serde_json::to_string(&full).unwrap()).unwrap();
        drop(file);
        let conflict_path = temporary.path().join("conflicts.zst");
        let mut conflicts = CompressedWriter::create(&conflict_path, 1, 1).unwrap();
        let (stats, candidates, _) =
            deduplicate_partition(&input, &output, &mut conflicts).unwrap();
        conflicts.finish().unwrap();
        assert_eq!(stats.subset_removed, 1);
        assert_eq!(candidates, 1);
    }

    #[test]
    fn same_session_id_in_different_trajectories_is_not_merged() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("input.jsonl");
        let output = temporary.path().join("candidate.jsonl");
        let mut file = File::create(&input).unwrap();
        let mut left = session("shared", vec![json!({"role":"user","content":"left"})]);
        left["trajectory_id"] = json!("traj-namespace-left");
        let mut right = session("shared", vec![json!({"role":"user","content":"right"})]);
        right["trajectory_id"] = json!("traj-namespace-right");
        writeln!(file, "{}", serde_json::to_string(&left).unwrap()).unwrap();
        writeln!(file, "{}", serde_json::to_string(&right).unwrap()).unwrap();
        drop(file);
        let conflict_path = temporary.path().join("conflicts.zst");
        let mut conflicts = CompressedWriter::create(&conflict_path, 1, 1).unwrap();
        let (stats, candidates, conflict_groups) =
            deduplicate_partition(&input, &output, &mut conflicts).unwrap();
        conflicts.finish().unwrap();
        assert_eq!(candidates, 2);
        assert_eq!(conflict_groups, 0);
        assert_eq!(stats.conflicts, 0);
    }

    #[test]
    fn parallel_release_keeps_global_exact_dedup_conservation() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("sessions.jsonl");
        let output = temporary.path().join("release");
        let messages = vec![
            json!({"role":"system","content":"system"}),
            json!({"role":"user","content":"same content"}),
            json!({"role":"assistant","content":"same answer"}),
        ];
        let left = session("left", messages.clone());
        let right = session("right", messages);
        let mut file = File::create(&input).unwrap();
        writeln!(file, "{}", serde_json::to_string(&left).unwrap()).unwrap();
        writeln!(file, "{}", serde_json::to_string(&right).unwrap()).unwrap();
        drop(file);
        let manifest = build_release(ReleaseConfig {
            inputs: vec![input],
            output,
            release_id: "parallel-dedup".to_owned(),
            profile: Profile::BuyerV7,
            minimum_score: 90.0,
            target_part_bytes: 1024 * 1024,
            dedup_partitions: 8,
            zstd_level: 1,
            workers: 4,
            replace: false,
            require_pass: false,
        })
        .unwrap();
        assert_eq!(manifest.processing_workers, 4);
        assert_eq!(manifest.counts.input_records, 2);
        assert_eq!(manifest.counts.exact_duplicates_removed, 1);
        assert_eq!(manifest.counts.assessed_sessions, 1);
        assert_eq!(manifest.counts.rejected_sessions, 1);
    }

    #[test]
    fn strict_release_does_not_publish_a_failed_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("sessions.jsonl");
        let output = temporary.path().join("release");
        fs::write(
            &input,
            format!(
                "{}\n",
                session(
                    "too-short",
                    vec![
                        json!({"role":"user","content":"short"}),
                        json!({"role":"assistant","content":"answer"})
                    ]
                )
            ),
        )
        .unwrap();
        let error = build_release(ReleaseConfig {
            inputs: vec![input],
            output: output.clone(),
            release_id: "strict-failure".to_owned(),
            profile: Profile::BuyerV7,
            minimum_score: 90.0,
            target_part_bytes: 1024 * 1024,
            dedup_partitions: 1,
            zstd_level: 1,
            workers: 1,
            replace: false,
            require_pass: true,
        })
        .unwrap_err();
        assert!(error.to_string().contains("Release failed closed"));
        assert!(!output.exists());
    }

    #[test]
    fn strict_release_rejects_historical_client_metadata_before_projection() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("sessions.jsonl");
        let output = temporary.path().join("release");
        let mut session = eligible_session("historical-client");
        assert!(
            assess_session(&session, Profile::BuyerV7, 90.0)
                .buyer_acceptance
                .eligible
        );
        session["meta"]["producer_streams"] = json!({"old-client": {}});
        fs::write(&input, format!("{session}\n")).unwrap();

        let error = build_release(ReleaseConfig {
            inputs: vec![input],
            output: output.clone(),
            release_id: "historical-client".to_owned(),
            profile: Profile::BuyerV7,
            minimum_score: 90.0,
            target_part_bytes: 1024 * 1024,
            dedup_partitions: 1,
            zstd_level: 1,
            workers: 1,
            replace: false,
            require_pass: true,
        })
        .unwrap_err();
        assert!(error.to_string().contains("Release failed closed"));
        assert!(!output.exists());
    }

    #[test]
    fn release_rejects_mixed_raw_lineage_inputs() {
        let temporary = tempfile::tempdir().unwrap();
        let raw = temporary.path().join("raw");
        fs::create_dir_all(&raw).unwrap();
        fs::write(
            raw.join("captures.ndjson"),
            format!(
                "{}\n",
                json!({
                    "captureId":"cap-release-lineage",
                    "requestBody":{"kind":"json","value":{"model":"gpt-5.6-sol"}},
                    "responseBody":{"kind":"json","value":{}},
                    "responseHeaders":{"x-request-id":"request-release-lineage"}
                })
            ),
        )
        .unwrap();
        fs::write(
            raw.join("RAW_SOURCE.json"),
            serde_json::to_vec(&complete_raw_lineage()).unwrap(),
        )
        .unwrap();
        let assembly = temporary.path().join("assembly");
        crate::assemble::assemble(crate::assemble::AssembleConfig {
            inputs: vec![raw],
            output: assembly.clone(),
            task_session_id: None,
            session_id: None,
            partitions: 1,
            zstd_level: 1,
            replace: false,
        })
        .unwrap();
        let session_inputs = discover_session_inputs(std::slice::from_ref(&assembly)).unwrap();
        assert!(!session_inputs.is_empty());

        let error =
            discover_release_raw_sources(&[assembly, session_inputs[0].clone()], &session_inputs)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot mix Raw-lineaged and unlineaged Session inputs")
        );
    }

    #[test]
    fn release_rejects_current_assessment_with_missing_readiness_envelope() {
        let mut session = eligible_session("missing-readiness");
        let quality = assess_session(&session, Profile::BuyerV7, 90.0);
        assert!(quality.buyer_acceptance.eligible);
        session["quality"] = serde_json::to_value(quality).unwrap();
        session["quality"]
            .as_object_mut()
            .unwrap()
            .remove("readiness");

        let validators = AssessmentSchemaValidators::new().unwrap();
        let error = validate_embedded_acceptance(&session, Profile::BuyerV7, 90.0, &validators)
            .unwrap_err();
        assert!(error.to_string().contains("chiptrace.assessment.v2"));
    }
}
