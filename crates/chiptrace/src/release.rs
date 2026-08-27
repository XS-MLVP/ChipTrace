use crate::jsonl::{absolute_path, ensure_safe_relative_path, sha256_file, string_field, utc_now};
use crate::schema::{
    FileManifest, RELEASE_SCHEMA_VERSION, ReleaseCounts, ReleaseManifest, TokenCounts,
};
use crate::score::{
    Profile, assess_session, exact_content_fingerprint, is_contiguous_subsequence,
    message_fingerprints,
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
    if output.exists() {
        fs::remove_dir_all(&output)?;
    }
    fs::rename(&staging, &output)?;
    sync_directory(parent)?;
    verify_release(&output, false)?;
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
    if require_pass && manifest.validation_status != "pass" {
        bail!(
            "release validation status is {}, not pass",
            manifest.validation_status
        );
    }
    let mut expected_files = HashSet::from(["manifest.json".to_owned(), "SHA256SUMS".to_owned()]);
    let mut eligible = 0_u64;
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
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let session: Value = serde_json::from_slice(&line)?;
            if !session
                .pointer("/quality/buyer_acceptance/eligible")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                bail!("release part contains an ineligible session");
            }
            part_records += 1;
            eligible += 1;
        }
        if part.records != Some(part_records) {
            bail!("release part record count mismatch: {}", part.file);
        }
    }
    if eligible != manifest.counts.eligible_sessions {
        bail!("release eligible session count mismatch");
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
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    if actual_files != expected_files {
        bail!("release file set does not match manifest");
    }
    verify_checksum_file(root, &manifest)?;
    Ok(manifest)
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
        unique.sort_by_key(|session| {
            std::cmp::Reverse(
                session
                    .get("messages")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0),
            )
        });
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
        let session = candidate
            .get("session")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("candidate session missing"))?;
        let fingerprint = exact_content_fingerprint(&session);
        if !exact_fingerprints.insert(fingerprint.clone()) {
            result.exact_removed += 1;
            continue;
        }
        let quality = assess_session(&session, config.profile, config.minimum_score);
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
        })
        .unwrap();
        assert_eq!(manifest.processing_workers, 4);
        assert_eq!(manifest.counts.input_records, 2);
        assert_eq!(manifest.counts.exact_duplicates_removed, 1);
        assert_eq!(manifest.counts.assessed_sessions, 1);
        assert_eq!(manifest.counts.rejected_sessions, 1);
    }
}
