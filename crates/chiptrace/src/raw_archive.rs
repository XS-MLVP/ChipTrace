//! Raw sealed-WAL archiving for the single ChipTrace object-store path.
//!
//! The archive is an immutable set of segment objects.  A manifest describes
//! the set, and a checkpoint is written last.  Readers trust only a checkpoint,
//! which gives object storage a small, explicit commit protocol without
//! pretending that an object store offers a multi-object transaction.

use crate::jsonl::{sha256_file, utc_now};
use crate::object_store::{
    Backend, LocalObject, ObjectStoreConfig, build_operator, ensure_local_objects, join_key,
    normalize_prefix, read_optional, remote_sha256, validate_component, validate_key,
    write_immutable_bytes,
};
use crate::schema::{
    RAW_ARCHIVE_SCHEMA_VERSION, RAW_CHECKPOINT_SCHEMA_VERSION, RAW_LINEAGE_SCHEMA_VERSION,
    RawArchiveCheckpoint, RawArchiveManifest, RawEmptySegmentEntry, RawSegmentEntry,
    RawSourceLineage,
};
use anyhow::{Context, Result, bail};
use opendal::Operator;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RawArchiveConfig {
    pub inputs: Vec<PathBuf>,
    pub archive_id: String,
    pub backend: Backend,
    pub root: Option<PathBuf>,
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub prefix: String,
    pub file_concurrency: usize,
    pub multipart_concurrency: usize,
    pub multipart_chunk_bytes: usize,
    pub retry_max_times: usize,
    pub allow_segment_gaps: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawArchiveResult {
    pub ok: bool,
    pub idempotent: bool,
    pub archive_id: String,
    pub completeness: String,
    pub manifest_key: String,
    pub checkpoint_key: String,
    pub segment_count: u64,
    pub total_records: u64,
    pub total_bytes: u64,
    pub objects: u64,
}

#[derive(Debug, Clone)]
pub struct RawArchiveVerifyConfig {
    pub archive_id: String,
    pub backend: Backend,
    pub root: Option<PathBuf>,
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub prefix: String,
    pub verify_records: bool,
    /// Permit verification of a forensic partial snapshot.  A partial
    /// snapshot is never a valid input for the standard release path.
    pub allow_partial: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawArchiveVerifyResult {
    pub ok: bool,
    pub archive_id: String,
    pub completeness: String,
    pub segment_count: u64,
    pub total_records: u64,
    pub total_bytes: u64,
    pub verified_objects: u64,
    pub verified_records: u64,
}

#[derive(Debug, Clone)]
pub struct RawArchiveRestoreConfig {
    pub archive_id: String,
    pub output: PathBuf,
    pub backend: Backend,
    pub root: Option<PathBuf>,
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub prefix: String,
    pub verify_records: bool,
    pub replace: bool,
    pub allow_partial: bool,
}

impl RawArchiveConfig {
    fn object_store(&self) -> ObjectStoreConfig {
        ObjectStoreConfig {
            backend: self.backend,
            root: self.root.clone(),
            endpoint: self.endpoint.clone(),
            bucket: self.bucket.clone(),
            region: self.region.clone(),
            prefix: self.prefix.clone(),
            file_concurrency: self.file_concurrency,
            multipart_concurrency: self.multipart_concurrency,
            multipart_chunk_bytes: self.multipart_chunk_bytes,
            retry_max_times: self.retry_max_times,
            // Raw objects are fully verified once immediately before the
            // checkpoint commit; avoid duplicate readback during upload.
            verify_remote_sha256: false,
        }
    }
}

impl RawArchiveVerifyConfig {
    fn object_store(&self) -> ObjectStoreConfig {
        ObjectStoreConfig {
            backend: self.backend,
            root: self.root.clone(),
            endpoint: self.endpoint.clone(),
            bucket: self.bucket.clone(),
            region: self.region.clone(),
            prefix: self.prefix.clone(),
            file_concurrency: 1,
            multipart_concurrency: 1,
            multipart_chunk_bytes: 5 * 1024 * 1024,
            retry_max_times: 25,
            verify_remote_sha256: true,
        }
    }
}

impl RawArchiveRestoreConfig {
    fn object_store(&self) -> ObjectStoreConfig {
        ObjectStoreConfig {
            backend: self.backend,
            root: self.root.clone(),
            endpoint: self.endpoint.clone(),
            bucket: self.bucket.clone(),
            region: self.region.clone(),
            prefix: self.prefix.clone(),
            file_concurrency: 1,
            multipart_concurrency: 1,
            multipart_chunk_bytes: 5 * 1024 * 1024,
            retry_max_times: 25,
            verify_remote_sha256: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RawArchiveRestoreResult {
    pub ok: bool,
    pub archive_id: String,
    pub completeness: String,
    pub output: PathBuf,
    pub segment_count: u64,
    pub total_records: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
struct LocalSegment {
    source_path: PathBuf,
    shard: String,
    segment_id: u64,
    bytes: u64,
    records: u64,
    sha256: String,
    created_at: String,
    sealed_at: Option<String>,
}

#[derive(Debug, Clone)]
struct ArchivePaths {
    object_base: String,
    manifest: String,
    checkpoint: String,
}

pub async fn archive_raw(config: RawArchiveConfig) -> Result<RawArchiveResult> {
    validate_component("archive_id", &config.archive_id)?;
    let object_config = config.object_store();
    object_config.validate()?;
    let paths = archive_paths(&config.prefix, &config.archive_id)?;
    let segments = discover_segments(&config.inputs, config.allow_segment_gaps)?;
    if segments.is_empty() {
        bail!("no sealed WAL segments found in archive inputs");
    }
    let manifest = build_manifest(
        &config.archive_id,
        &paths,
        &segments,
        !config.allow_segment_gaps,
    )?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_sha256 = crate::jsonl::sha256_bytes(&manifest_bytes);
    let checkpoint = RawArchiveCheckpoint {
        schema_version: RAW_CHECKPOINT_SCHEMA_VERSION.to_owned(),
        archive_id: config.archive_id.clone(),
        state: "committed".to_owned(),
        completeness: manifest.completeness.clone(),
        committed_at_utc: utc_now(),
        manifest_key: paths.manifest.clone(),
        manifest_sha256: manifest_sha256.clone(),
        segment_count: manifest.segment_count,
        total_records: manifest.total_records,
        total_bytes: manifest.total_bytes,
    };
    let checkpoint_bytes = serde_json::to_vec_pretty(&checkpoint)?;
    let operator = Arc::new(build_operator(&object_config)?);

    let local_objects = segments
        .iter()
        .map(|segment| LocalObject {
            path: segment.source_path.clone(),
            key: join_key(&paths.object_base, &format!("{}.ndjson", segment.sha256)),
            sha256: segment.sha256.clone(),
            bytes: segment.bytes,
        })
        .collect::<Vec<_>>();
    let mut unique_objects = BTreeMap::new();
    for object in local_objects {
        unique_objects.entry(object.key.clone()).or_insert(object);
    }
    let object_count = unique_objects.len() as u64;

    if let Some(existing) = read_checkpoint(&operator, &paths.checkpoint).await? {
        validate_checkpoint(&existing, &checkpoint, &config.archive_id, &paths.manifest)?;
        // A committed checkpoint is the visibility marker, but an operator may
        // have removed an unprotected object after the commit.  Re-check the
        // local source set first so a retry can repair a missing object while
        // still rejecting a digest-changing (tampered) object.
        ensure_local_objects(
            &operator,
            unique_objects.into_values().collect(),
            &object_config,
        )
        .await?;
        if read_optional(&operator, &paths.manifest).await?.is_none() {
            write_immutable_bytes(&operator, &paths.manifest, manifest_bytes.clone()).await?;
        }
        verify_manifest_objects(&operator, &existing, &paths, true).await?;
        return Ok(result(&existing, &paths, true, object_count));
    }

    let _ = ensure_local_objects(
        &operator,
        unique_objects.into_values().collect(),
        &object_config,
    )
    .await?;
    let _ = write_immutable_bytes(&operator, &paths.manifest, manifest_bytes).await?;
    // Validate the immutable object set before publishing the visibility
    // marker.  A consumer can never observe a checkpoint whose objects have
    // not passed the full length, digest, and record-count checks.
    verify_manifest_objects(&operator, &checkpoint, &paths, true).await?;
    let checkpoint_created =
        write_checkpoint(&operator, &paths.checkpoint, checkpoint_bytes, &checkpoint).await?;
    let committed = read_checkpoint(&operator, &paths.checkpoint)
        .await?
        .context("checkpoint disappeared after commit")?;
    validate_checkpoint(&committed, &checkpoint, &config.archive_id, &paths.manifest)?;
    Ok(result(
        &committed,
        &paths,
        !checkpoint_created,
        object_count,
    ))
}

pub async fn verify_raw_archive(config: RawArchiveVerifyConfig) -> Result<RawArchiveVerifyResult> {
    validate_component("archive_id", &config.archive_id)?;
    let object_config = config.object_store();
    object_config.validate()?;
    let paths = archive_paths(&config.prefix, &config.archive_id)?;
    let operator = build_operator(&object_config)?;
    let checkpoint = read_checkpoint(&operator, &paths.checkpoint)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "raw archive checkpoint does not exist: {}",
                paths.checkpoint
            )
        })?;
    if checkpoint.archive_id != config.archive_id {
        bail!("raw archive checkpoint ID does not match requested archive");
    }
    if checkpoint.completeness == "partial" && !config.allow_partial {
        bail!(
            "raw archive {} is partial; pass --allow-partial only for forensic verification",
            config.archive_id
        );
    }
    let (manifest, verified_objects, verified_records) =
        verify_manifest_objects(&operator, &checkpoint, &paths, config.verify_records).await?;
    Ok(RawArchiveVerifyResult {
        ok: true,
        archive_id: config.archive_id,
        completeness: manifest.completeness.clone(),
        segment_count: manifest.segment_count,
        total_records: manifest.total_records,
        total_bytes: manifest.total_bytes,
        verified_objects,
        verified_records,
    })
}

pub async fn restore_raw_archive(
    config: RawArchiveRestoreConfig,
) -> Result<RawArchiveRestoreResult> {
    validate_component("archive_id", &config.archive_id)?;
    let object_config = config.object_store();
    object_config.validate()?;
    let paths = archive_paths(&config.prefix, &config.archive_id)?;
    let operator = build_operator(&object_config)?;
    let checkpoint = read_checkpoint(&operator, &paths.checkpoint)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "raw archive checkpoint does not exist: {}",
                paths.checkpoint
            )
        })?;
    if checkpoint.archive_id != config.archive_id {
        bail!("raw archive checkpoint ID does not match requested archive");
    }
    let (manifest, _, _verified_records) =
        verify_manifest_objects(&operator, &checkpoint, &paths, config.verify_records).await?;
    if manifest.completeness == "partial" && !config.allow_partial {
        bail!(
            "raw archive {} is partial; pass --allow-partial only for forensic restore",
            config.archive_id
        );
    }
    if config.output.exists() && !config.replace {
        bail!(
            "restore output already exists: {}; pass --replace to replace it",
            config.output.display()
        );
    }
    let output_parent = config.output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_parent)?;
    let output_name = config
        .output
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("restore");
    let staging = output_parent.join(format!(
        ".{output_name}.chiptrace-restore-{}",
        config.archive_id
    ));
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .with_context(|| format!("remove stale restore staging {}", staging.display()))?;
    }
    fs::create_dir_all(&staging)?;
    for segment in &manifest.segments {
        let relative = Path::new("segments")
            .join(&segment.shard)
            .join(format!("segment-{:020}.sealed.ndjson", segment.segment_id));
        let destination = staging.join(&relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = destination.with_extension("ndjson.partial");
        download_object(&operator, &segment.object_key, &temporary).await?;
        let bytes = fs::metadata(&temporary)?.len();
        if bytes != segment.bytes || sha256_file(&temporary)? != segment.sha256 {
            bail!(
                "restored segment integrity mismatch: {}",
                segment.object_key
            );
        }
        fs::rename(&temporary, &destination)?;
    }
    for segment in &manifest.empty_segments {
        let relative = Path::new("segments")
            .join(&segment.shard)
            .join(format!("segment-{:020}.sealed.ndjson", segment.segment_id));
        let destination = staging.join(&relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = destination.with_extension("ndjson.partial");
        download_object(&operator, &segment.object_key, &temporary).await?;
        let bytes = fs::metadata(&temporary)?.len();
        if bytes != segment.bytes || sha256_file(&temporary)? != segment.sha256 {
            bail!(
                "restored empty segment integrity mismatch: {}",
                segment.object_key
            );
        }
        fs::rename(&temporary, &destination)?;
    }
    let checkpoint_bytes = operator.read(&paths.checkpoint).await?.to_vec();
    let lineage = RawSourceLineage {
        schema_version: RAW_LINEAGE_SCHEMA_VERSION.to_owned(),
        archive_id: checkpoint.archive_id.clone(),
        completeness: checkpoint.completeness.clone(),
        checkpoint_key: paths.checkpoint.clone(),
        checkpoint_sha256: crate::jsonl::sha256_bytes(&checkpoint_bytes),
        manifest_key: checkpoint.manifest_key.clone(),
        manifest_sha256: checkpoint.manifest_sha256.clone(),
        segment_count: checkpoint.segment_count,
        total_records: checkpoint.total_records,
        total_bytes: checkpoint.total_bytes,
    };
    let lineage_path = staging.join("RAW_SOURCE.json");
    fs::write(&lineage_path, serde_json::to_vec_pretty(&lineage)?)?;
    File::open(&lineage_path)?.sync_all()?;
    if config.output.exists() {
        if config.output.is_dir() {
            fs::remove_dir_all(&config.output)?;
        } else {
            fs::remove_file(&config.output)?;
        }
    }
    fs::rename(&staging, &config.output)?;
    Ok(RawArchiveRestoreResult {
        ok: true,
        archive_id: config.archive_id,
        completeness: manifest.completeness.clone(),
        output: config.output,
        segment_count: manifest.segment_count,
        total_records: manifest.total_records,
        total_bytes: manifest.total_bytes,
    })
}

fn archive_paths(prefix: &str, archive_id: &str) -> Result<ArchivePaths> {
    let prefix = normalize_prefix(prefix)?;
    let raw_base = join_key(&prefix, "raw");
    let base = join_key(&raw_base, archive_id);
    Ok(ArchivePaths {
        object_base: join_key(&raw_base, "objects"),
        manifest: join_key(&base, "manifest.json"),
        checkpoint: join_key(&base, "CHECKPOINT.json"),
    })
}

fn result(
    checkpoint: &RawArchiveCheckpoint,
    paths: &ArchivePaths,
    idempotent: bool,
    objects: u64,
) -> RawArchiveResult {
    RawArchiveResult {
        ok: true,
        idempotent,
        archive_id: checkpoint.archive_id.clone(),
        completeness: checkpoint.completeness.clone(),
        manifest_key: paths.manifest.clone(),
        checkpoint_key: paths.checkpoint.clone(),
        segment_count: checkpoint.segment_count,
        total_records: checkpoint.total_records,
        total_bytes: checkpoint.total_bytes,
        objects: objects + 2,
    }
}

fn build_manifest(
    archive_id: &str,
    paths: &ArchivePaths,
    segments: &[LocalSegment],
    complete_source: bool,
) -> Result<RawArchiveManifest> {
    let entries = segments
        .iter()
        .filter(|segment| segment.records > 0)
        .map(|segment| RawSegmentEntry {
            shard: segment.shard.clone(),
            segment_id: segment.segment_id,
            object_key: join_key(&paths.object_base, &format!("{}.ndjson", segment.sha256)),
            source_path: format!(
                "segments/{}/segment-{:020}.sealed.ndjson",
                segment.shard, segment.segment_id
            ),
            bytes: segment.bytes,
            records: segment.records,
            sha256: segment.sha256.clone(),
            created_at: segment.created_at.clone(),
            sealed_at: segment.sealed_at.clone(),
        })
        .collect::<Vec<_>>();
    let empty_segments = segments
        .iter()
        .filter(|segment| segment.records == 0)
        .map(|segment| RawEmptySegmentEntry {
            shard: segment.shard.clone(),
            segment_id: segment.segment_id,
            object_key: join_key(&paths.object_base, &format!("{}.ndjson", segment.sha256)),
            source_path: format!(
                "segments/{}/segment-{:020}.sealed.ndjson",
                segment.shard, segment.segment_id
            ),
            bytes: segment.bytes,
            records: segment.records,
            sha256: segment.sha256.clone(),
            created_at: segment.created_at.clone(),
            sealed_at: segment.sealed_at.clone(),
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        bail!("raw archive cannot commit a snapshot without data segments");
    }
    Ok(RawArchiveManifest {
        schema_version: RAW_ARCHIVE_SCHEMA_VERSION.to_owned(),
        archive_id: archive_id.to_owned(),
        // Keep retries byte-for-byte deterministic after a crash before the
        // checkpoint is published.
        created_at_utc: segments
            .first()
            .map(|segment| segment.created_at.clone())
            .unwrap_or_else(utc_now),
        format: "UTF-8 NDJSON sealed WAL".to_owned(),
        completeness: if complete_source {
            "complete".to_owned()
        } else {
            "partial".to_owned()
        },
        segment_count: entries.len() as u64,
        empty_segments,
        total_records: entries.iter().map(|entry| entry.records).sum(),
        total_bytes: segments.iter().map(|segment| segment.bytes).sum(),
        segments: entries,
    })
}

fn discover_segments(inputs: &[PathBuf], allow_gaps: bool) -> Result<Vec<LocalSegment>> {
    let mut paths = BTreeSet::new();
    for input in inputs {
        if input.is_file() {
            validate_segment_path(input)?;
            paths.insert(input.canonicalize()?);
        } else if input.is_dir() {
            for entry in walkdir::WalkDir::new(input).follow_links(false) {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                if is_sealed_segment(entry.path()) {
                    paths.insert(entry.path().canonicalize()?);
                } else if is_open_segment(entry.path()) {
                    // `POST /flush` seals the active file and immediately
                    // creates a new zero-byte open placeholder. It carries no
                    // records and is safe to ignore; a non-empty open file is
                    // an unsealed tail and must never be called complete.
                    if fs::metadata(entry.path())?.len() != 0 {
                        bail!(
                            "raw archive found a non-empty open WAL segment {}; flush the Collector first or pass only explicit sealed segment files",
                            entry.path().display()
                        );
                    }
                }
            }
        } else {
            bail!("raw archive input does not exist: {}", input.display());
        }
    }
    let mut segments = paths
        .into_iter()
        .map(read_segment)
        .collect::<Result<Vec<_>>>()?;
    segments.sort_by(|left, right| {
        left.shard
            .cmp(&right.shard)
            .then(left.segment_id.cmp(&right.segment_id))
    });
    let mut seen = BTreeSet::new();
    if !allow_gaps {
        // Validate the complete source sequence over both data segments and
        // zero-record rotation markers. A marker is evidence for an ID that
        // exists in the WAL, so it legitimately fills a numeric interval.
        let mut previous: BTreeMap<String, u64> = BTreeMap::new();
        for segment in &segments {
            if let Some(previous_id) = previous.get(&segment.shard)
                && segment.segment_id != previous_id.saturating_add(1)
            {
                bail!(
                    "raw segment sequence gap in {}: previous={}, current={}",
                    segment.shard,
                    previous_id,
                    segment.segment_id
                );
            }
            if !previous.contains_key(&segment.shard) && segment.segment_id != 1 {
                bail!(
                    "raw archive for {} starts at segment {}; include data/empty segment 1..{} or pass --allow-segment-gaps for a partial snapshot",
                    segment.shard,
                    segment.segment_id,
                    segment.segment_id.saturating_sub(1)
                );
            }
            previous.insert(segment.shard.clone(), segment.segment_id);
        }
    }
    for segment in &segments {
        if !seen.insert((segment.shard.clone(), segment.segment_id)) {
            bail!(
                "duplicate raw segment {}:{}",
                segment.shard,
                segment.segment_id
            );
        }
        if segment.segment_id == 0 {
            bail!("raw segment IDs must be positive");
        }
    }
    Ok(segments)
}

fn validate_segment_path(path: &Path) -> Result<()> {
    if !is_sealed_segment(path) {
        if path.to_string_lossy().contains(".open.") {
            bail!(
                "refusing open WAL segment {}; flush before archiving",
                path.display()
            );
        }
        bail!(
            "raw archive input is not a sealed NDJSON segment: {}",
            path.display()
        );
    }
    Ok(())
}

fn is_sealed_segment(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".sealed.ndjson") && name.starts_with("segment-"))
}

fn is_open_segment(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".open.ndjson") && name.starts_with("segment-"))
}

fn read_segment(path: PathBuf) -> Result<LocalSegment> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid segment filename {}", path.display()))?;
    let segment_id = name
        .strip_prefix("segment-")
        .and_then(|value| value.strip_suffix(".sealed.ndjson"))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid sealed segment filename {name:?}"))?;
    let shard = path
        .ancestors()
        .find_map(|ancestor| {
            ancestor
                .file_name()
                .and_then(|value| value.to_str())
                .filter(|value| value.starts_with("shard-"))
        })
        .unwrap_or("shard-00000")
        .to_owned();
    validate_component("segment shard", &shard)?;
    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::with_capacity(8 * 1024 * 1024, file);
    let mut line = Vec::new();
    let mut records = 0_u64;
    let mut observed_times = BTreeSet::new();
    loop {
        line.clear();
        let count = reader.read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: Value = serde_json::from_slice(&line).with_context(|| {
            format!("invalid JSON in {} record {}", path.display(), records + 1)
        })?;
        // The raw layer is lossless: only JSONL framing and the stable capture
        // identity are checked here.  Current buyer/schema validation belongs
        // to Assembly and Release, so historical evidence is never filtered.
        if !value.is_object() || value.get("captureId").and_then(Value::as_str).is_none() {
            bail!(
                "raw segment record {} lacks an object captureId: {}",
                records + 1,
                path.display()
            );
        }
        for field in ["receivedAt", "startedAt", "finishedAt"] {
            if let Some(timestamp) = value.get(field).and_then(Value::as_str)
                && !timestamp.trim().is_empty()
            {
                observed_times.insert(timestamp.to_owned());
            }
        }
        if let Some(timestamp) = value
            .pointer("/lifecycleEvent/occurred_at")
            .and_then(Value::as_str)
            && !timestamp.trim().is_empty()
        {
            observed_times.insert(timestamp.to_owned());
        }
        records += 1;
    }
    let metadata = fs::metadata(&path)?;
    let created_at = observed_times
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_owned());
    let sealed_at = observed_times.iter().next_back().cloned();
    Ok(LocalSegment {
        source_path: path.clone(),
        shard,
        segment_id,
        bytes: metadata.len(),
        records,
        sha256: sha256_file(&path)?,
        created_at,
        sealed_at,
    })
}

async fn read_checkpoint(operator: &Operator, key: &str) -> Result<Option<RawArchiveCheckpoint>> {
    let Some(bytes) = read_optional(operator, key).await? else {
        return Ok(None);
    };
    let checkpoint = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse raw archive checkpoint {key}"))?;
    Ok(Some(checkpoint))
}

async fn write_checkpoint(
    operator: &Operator,
    key: &str,
    bytes: Vec<u8>,
    expected: &RawArchiveCheckpoint,
) -> Result<bool> {
    // `committed_at_utc` is intentionally the time of the winning writer and
    // therefore differs across concurrent attempts.  Compare the parsed
    // checkpoint contract on a conditional-write race instead of comparing
    // the serialized bytes byte-for-byte.
    match operator.write_with(key, bytes).if_not_exists(true).await {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                opendal::ErrorKind::AlreadyExists | opendal::ErrorKind::ConditionNotMatch
            ) =>
        {
            let existing = read_checkpoint(operator, key)
                .await?
                .context("checkpoint exists but cannot be read after conditional write")?;
            validate_checkpoint(
                &existing,
                expected,
                &expected.archive_id,
                &expected.manifest_key,
            )?;
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_checkpoint(
    actual: &RawArchiveCheckpoint,
    expected: &RawArchiveCheckpoint,
    archive_id: &str,
    manifest_key: &str,
) -> Result<()> {
    if actual.schema_version != RAW_CHECKPOINT_SCHEMA_VERSION
        || actual.state != "committed"
        || actual.committed_at_utc.trim().is_empty()
        || actual.completeness != expected.completeness
        || actual.archive_id != archive_id
        || actual.manifest_key != manifest_key
        || actual.manifest_sha256 != expected.manifest_sha256
        || actual.segment_count != expected.segment_count
        || actual.total_records != expected.total_records
        || actual.total_bytes != expected.total_bytes
    {
        bail!("raw archive checkpoint conflicts with requested archive {archive_id}");
    }
    Ok(())
}

async fn verify_manifest_objects(
    operator: &Operator,
    checkpoint: &RawArchiveCheckpoint,
    paths: &ArchivePaths,
    verify_records: bool,
) -> Result<(RawArchiveManifest, u64, u64)> {
    if checkpoint.schema_version != RAW_CHECKPOINT_SCHEMA_VERSION
        || checkpoint.state != "committed"
        || !matches!(checkpoint.completeness.as_str(), "complete" | "partial")
        || checkpoint.manifest_key != paths.manifest
    {
        bail!("invalid raw archive checkpoint at {}", paths.checkpoint);
    }
    validate_key(&checkpoint.manifest_key)?;
    let manifest_bytes = operator.read(&checkpoint.manifest_key).await?.to_vec();
    validate_sha256(&checkpoint.manifest_sha256)?;
    if crate::jsonl::sha256_bytes(&manifest_bytes) != checkpoint.manifest_sha256 {
        bail!(
            "raw archive manifest SHA-256 mismatch: {}",
            checkpoint.manifest_key
        );
    }
    let manifest: RawArchiveManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema_version != RAW_ARCHIVE_SCHEMA_VERSION
        || manifest.archive_id != checkpoint.archive_id
        || manifest.format != "UTF-8 NDJSON sealed WAL"
        || manifest.completeness != checkpoint.completeness
        || manifest.segment_count != checkpoint.segment_count
        || manifest.total_records != checkpoint.total_records
        || manifest.total_bytes != checkpoint.total_bytes
        || manifest.segments.len() as u64 != checkpoint.segment_count
    {
        bail!("raw archive manifest does not match checkpoint");
    }
    validate_manifest_sequence(&manifest)?;
    let manifest_records = manifest
        .segments
        .iter()
        .map(|segment| segment.records)
        .sum::<u64>();
    let manifest_bytes_total = manifest
        .segments
        .iter()
        .map(|segment| segment.bytes)
        .chain(manifest.empty_segments.iter().map(|segment| segment.bytes))
        .sum::<u64>();
    if manifest_records != manifest.total_records || manifest_bytes_total != manifest.total_bytes {
        bail!("raw archive manifest aggregate totals are inconsistent");
    }
    if manifest.total_records == 0 || manifest.total_bytes == 0 {
        bail!("raw archive cannot commit an empty snapshot");
    }
    let mut seen = BTreeSet::new();
    let mut records = 0_u64;
    let mut verified_object_keys = BTreeSet::new();
    let mut object_record_counts = BTreeMap::new();
    let mut object_byte_counts = BTreeMap::new();
    for segment in &manifest.segments {
        validate_component("segment.shard", &segment.shard)?;
        let expected_source_path = format!(
            "segments/{}/segment-{:020}.sealed.ndjson",
            segment.shard, segment.segment_id
        );
        if segment.source_path != expected_source_path {
            bail!("raw archive segment source_path is inconsistent");
        }
        validate_key(&segment.object_key)?;
        validate_sha256(&segment.sha256)?;
        let expected_object_key =
            join_key(&paths.object_base, &format!("{}.ndjson", segment.sha256));
        if segment.object_key != expected_object_key {
            bail!(
                "raw archive object key is not content addressed: {}",
                segment.object_key
            );
        }
        if !seen.insert((segment.shard.clone(), segment.segment_id)) {
            bail!("raw archive manifest contains duplicate segment");
        }
        if segment.bytes == 0 || segment.records == 0 {
            bail!("raw archive manifest contains an empty segment");
        }
        if verified_object_keys.insert(segment.object_key.clone()) {
            let metadata = operator.stat(&segment.object_key).await?;
            let remote_bytes = metadata.content_length();
            if remote_bytes != segment.bytes {
                bail!(
                    "raw archive object length mismatch: {} (expected={}, remote={})",
                    segment.object_key,
                    segment.bytes,
                    remote_bytes
                );
            }
            object_byte_counts.insert(segment.object_key.clone(), remote_bytes);
            if verify_records {
                let count = verify_remote_segment_records(
                    operator,
                    &segment.object_key,
                    segment.bytes,
                    &segment.sha256,
                )
                .await?;
                object_record_counts.insert(segment.object_key.clone(), count);
            } else if remote_sha256(operator, &segment.object_key).await? != segment.sha256 {
                bail!(
                    "raw archive object SHA-256 mismatch: {}",
                    segment.object_key
                );
            }
        }
        if object_byte_counts.get(&segment.object_key).copied() != Some(segment.bytes) {
            bail!("raw archive object length mismatch: {}", segment.object_key);
        }
        if verify_records {
            let count = object_record_counts
                .get(&segment.object_key)
                .copied()
                .unwrap_or_default();
            if count != segment.records {
                bail!("raw archive record count mismatch: {}", segment.object_key);
            }
            records = records.saturating_add(segment.records);
        }
    }
    for segment in &manifest.empty_segments {
        validate_component("empty_segment.shard", &segment.shard)?;
        validate_key(&segment.object_key)?;
        validate_sha256(&segment.sha256)?;
        let expected_object_key =
            join_key(&paths.object_base, &format!("{}.ndjson", segment.sha256));
        if segment.object_key != expected_object_key {
            bail!(
                "raw archive empty object key is not content addressed: {}",
                segment.object_key
            );
        }
        if !seen.insert((segment.shard.clone(), segment.segment_id)) {
            bail!("raw archive manifest contains duplicate data/empty segment");
        }
        if segment.records != 0 {
            bail!("raw archive empty segment has non-zero records");
        }
        if verified_object_keys.insert(segment.object_key.clone()) {
            let metadata = operator.stat(&segment.object_key).await?;
            let remote_bytes = metadata.content_length();
            if remote_bytes != segment.bytes {
                bail!(
                    "raw archive empty object length mismatch: {} (expected={}, remote={})",
                    segment.object_key,
                    segment.bytes,
                    remote_bytes
                );
            }
            object_byte_counts.insert(segment.object_key.clone(), remote_bytes);
            if verify_records {
                let count = verify_remote_segment_records(
                    operator,
                    &segment.object_key,
                    segment.bytes,
                    &segment.sha256,
                )
                .await?;
                object_record_counts.insert(segment.object_key.clone(), count);
            } else if remote_sha256(operator, &segment.object_key).await? != segment.sha256 {
                bail!(
                    "raw archive empty object SHA-256 mismatch: {}",
                    segment.object_key
                );
            }
        }
        if object_byte_counts.get(&segment.object_key).copied() != Some(segment.bytes) {
            bail!(
                "raw archive empty object length mismatch: {}",
                segment.object_key
            );
        }
        if verify_records
            && object_record_counts
                .get(&segment.object_key)
                .copied()
                .unwrap_or_default()
                != 0
        {
            bail!(
                "raw archive empty object contains records: {}",
                segment.object_key
            );
        }
    }
    if verify_records && records != manifest.total_records {
        bail!("raw archive total record count mismatch");
    }
    let verified_objects = verified_object_keys.len() as u64;
    Ok((manifest, verified_objects, records))
}

async fn verify_remote_segment_records(
    operator: &Operator,
    key: &str,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<u64> {
    use futures_util::io::AsyncBufReadExt;

    let remote = operator
        .reader(key)
        .await?
        .into_futures_async_read(..)
        .await?;
    let mut reader = futures_util::io::BufReader::with_capacity(8 * 1024 * 1024, remote);
    let mut hasher = sha2::Sha256::new();
    let mut line = Vec::new();
    let mut bytes = 0_u64;
    let mut records = 0_u64;
    loop {
        line.clear();
        let count = reader.read_until(b'\n', &mut line).await?;
        if count == 0 {
            break;
        }
        bytes = bytes.saturating_add(count as u64);
        hasher.update(&line);
        strip_line_ending(&mut line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: Value = serde_json::from_slice(&line)
            .with_context(|| format!("invalid JSON in remote raw object {key}"))?;
        if !value.is_object() || value.get("captureId").and_then(Value::as_str).is_none() {
            bail!("remote raw object contains a record without captureId: {key}");
        }
        records = records.saturating_add(1);
    }
    // JSONL permits the final line to omit a newline.  `read_until` already
    // returned that final fragment, so no extra tail handling is needed.
    let digest = hex::encode(hasher.finalize());
    if bytes != expected_bytes {
        bail!("raw archive object length mismatch: {key}");
    }
    if digest != expected_sha256 {
        bail!("raw archive object SHA-256 mismatch: {key}");
    }
    Ok(records)
}

fn strip_line_ending(line: &mut Vec<u8>) {
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
}

fn validate_manifest_sequence(manifest: &RawArchiveManifest) -> Result<()> {
    if !matches!(manifest.completeness.as_str(), "complete" | "partial") {
        bail!("raw archive manifest has an invalid completeness value");
    }

    let mut seen = BTreeSet::new();
    let mut previous_data: Option<(&str, u64)> = None;
    for segment in &manifest.segments {
        validate_component("segment.shard", &segment.shard)?;
        if segment.segment_id == 0 {
            bail!("raw archive segment IDs must be positive");
        }
        if let Some((previous_shard, previous_id)) = previous_data
            && (segment.shard.as_str(), segment.segment_id) < (previous_shard, previous_id)
        {
            bail!("raw archive manifest segments are not in deterministic order");
        }
        previous_data = Some((segment.shard.as_str(), segment.segment_id));
        if !seen.insert((segment.shard.clone(), segment.segment_id)) {
            bail!("raw archive manifest contains duplicate segment");
        }
    }

    let mut previous_empty: Option<(&str, u64)> = None;
    for segment in &manifest.empty_segments {
        validate_component("empty_segment.shard", &segment.shard)?;
        if segment.segment_id == 0 {
            bail!("raw archive empty segment IDs must be positive");
        }
        let expected_source_path = format!(
            "segments/{}/segment-{:020}.sealed.ndjson",
            segment.shard, segment.segment_id
        );
        if segment.source_path != expected_source_path {
            bail!("raw archive empty segment source_path is inconsistent");
        }
        if segment.records != 0 {
            bail!("raw archive empty segment has non-zero records");
        }
        validate_sha256(&segment.sha256)?;
        if segment.created_at.trim().is_empty() {
            bail!("raw archive empty segment created_at is empty");
        }
        if let Some((previous_shard, previous_id)) = previous_empty
            && (segment.shard.as_str(), segment.segment_id) < (previous_shard, previous_id)
        {
            bail!("raw archive empty segments are not in deterministic order");
        }
        previous_empty = Some((segment.shard.as_str(), segment.segment_id));
        if !seen.insert((segment.shard.clone(), segment.segment_id)) {
            bail!("raw archive manifest contains duplicate data/empty segment");
        }
    }

    if manifest.completeness == "complete" {
        let mut by_shard: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
        for (shard, segment_id) in &seen {
            by_shard
                .entry(shard.as_str())
                .or_default()
                .push(*segment_id);
        }
        for (shard, mut ids) in by_shard {
            ids.sort_unstable();
            if ids.first().copied() != Some(1) {
                bail!(
                    "complete raw archive for {shard} starts at segment {}",
                    ids.first().copied().unwrap_or_default()
                );
            }
            for pair in ids.windows(2) {
                if pair[1] != pair[0].saturating_add(1) {
                    bail!(
                        "raw archive manifest sequence gap in {}: previous={}, current={}",
                        shard,
                        pair[0],
                        pair[1]
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid SHA-256 digest in raw archive manifest");
    }
    Ok(())
}

async fn download_object(operator: &Operator, key: &str, destination: &Path) -> Result<()> {
    use futures_util::io::AsyncReadExt;
    use std::io::BufWriter;
    let mut reader = operator
        .reader(key)
        .await?
        .into_futures_async_read(..)
        .await?;
    let file = File::create(destination)?;
    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
    let mut buffer = vec![0_u8; 8 * 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        writer.write_all(&buffer[..count])?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_store::Backend;
    use serde_json::json;

    fn fixture_capture(id: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "recordType": "api_snapshot",
            "captureId": id,
            "requestBody": {"kind":"json","value":{"model":"gpt-5.6-sol","input":[]}},
            "responseBody": {"kind":"json","value":{"id":id,"status":"completed"}},
            "responseStatus": 200
        }))
        .unwrap()
    }

    fn config(root: &Path, input: PathBuf, archive_id: &str) -> RawArchiveConfig {
        RawArchiveConfig {
            inputs: vec![input],
            archive_id: archive_id.to_owned(),
            backend: Backend::Fs,
            root: Some(root.to_path_buf()),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            file_concurrency: 2,
            multipart_concurrency: 1,
            multipart_chunk_bytes: 5 * 1024 * 1024,
            retry_max_times: 3,
            allow_segment_gaps: false,
        }
    }

    #[tokio::test]
    async fn archive_checkpoint_is_last_and_round_trips() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("capture/segments");
        fs::create_dir_all(&input).unwrap();
        for id in 1..=2 {
            let path = input.join(format!("segment-{id:020}.sealed.ndjson"));
            fs::write(
                &path,
                [fixture_capture(&format!("cap-{id}")), vec![b'\n']].concat(),
            )
            .unwrap();
        }
        let object_root = temporary.path().join("objects");
        let result = archive_raw(config(&object_root, input.clone(), "batch-1"))
            .await
            .unwrap();
        assert!(!result.idempotent);
        assert_eq!(result.segment_count, 2);
        let verified = verify_raw_archive(RawArchiveVerifyConfig {
            archive_id: "batch-1".to_owned(),
            backend: Backend::Fs,
            root: Some(object_root.clone()),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            verify_records: true,
            allow_partial: false,
        })
        .await
        .unwrap();
        assert_eq!(verified.total_records, 2);
        assert_eq!(verified.verified_objects, 2);
        let restored = temporary.path().join("restored");
        let restored_result = restore_raw_archive(RawArchiveRestoreConfig {
            archive_id: "batch-1".to_owned(),
            output: restored.clone(),
            backend: Backend::Fs,
            root: Some(object_root.clone()),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            verify_records: true,
            replace: false,
            allow_partial: false,
        })
        .await
        .unwrap();
        assert_eq!(restored_result.segment_count, 2);
        assert!(
            restored
                .join("segments/shard-00000/segment-00000000000000000001.sealed.ndjson")
                .exists()
        );
        let manifest: crate::schema::RawArchiveManifest = serde_json::from_slice(
            &fs::read(object_root.join("datasets/chiptrace/raw/batch-1/manifest.json")).unwrap(),
        )
        .unwrap();
        let object_path = object_root.join(manifest.segments.first().unwrap().object_key.as_str());
        OpenOptions::new()
            .append(true)
            .open(object_path)
            .unwrap()
            .write_all(b"tamper")
            .unwrap();
        assert!(
            verify_raw_archive(RawArchiveVerifyConfig {
                archive_id: "batch-1".to_owned(),
                backend: Backend::Fs,
                root: Some(object_root.clone()),
                endpoint: None,
                bucket: None,
                region: None,
                prefix: "datasets/chiptrace".to_owned(),
                verify_records: false,
                allow_partial: false,
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn archive_is_idempotent_and_rejects_sequence_gaps() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("segments");
        fs::create_dir_all(&input).unwrap();
        for id in [1_u64, 3] {
            fs::write(
                input.join(format!("segment-{id:020}.sealed.ndjson")),
                [fixture_capture(&format!("cap-{id}")), vec![b'\n']].concat(),
            )
            .unwrap();
        }
        let object_root = temporary.path().join("objects");
        assert!(
            archive_raw(config(&object_root, input.clone(), "gap"))
                .await
                .is_err()
        );
        let mut allow = config(&object_root, input, "gap");
        allow.allow_segment_gaps = true;
        let first = archive_raw(allow.clone()).await.unwrap();
        let second = archive_raw(allow).await.unwrap();
        assert!(!first.idempotent);
        assert_eq!(first.completeness, "partial");
        assert!(second.idempotent);
        let partial_output = temporary.path().join("partial-restore");
        let partial_config = RawArchiveRestoreConfig {
            archive_id: "gap".to_owned(),
            output: partial_output.clone(),
            backend: Backend::Fs,
            root: Some(object_root.clone()),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            verify_records: false,
            replace: false,
            allow_partial: false,
        };
        assert!(restore_raw_archive(partial_config.clone()).await.is_err());
        let mut allowed = partial_config;
        allowed.allow_partial = true;
        assert!(restore_raw_archive(allowed).await.is_ok());
    }

    #[tokio::test]
    async fn sealed_rotation_marker_fills_a_complete_sequence_gap() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("segments");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("segment-00000000000000000001.sealed.ndjson"),
            [fixture_capture("cap-marker-1"), vec![b'\n']].concat(),
        )
        .unwrap();
        // Collector can seal an empty file while rotating. It is evidence for
        // the sequence number, but contributes no records to the data count.
        fs::write(
            input.join("segment-00000000000000000002.sealed.ndjson"),
            b"\n",
        )
        .unwrap();
        fs::write(
            input.join("segment-00000000000000000003.sealed.ndjson"),
            [fixture_capture("cap-marker-3"), vec![b'\n']].concat(),
        )
        .unwrap();
        let object_root = temporary.path().join("objects");
        let result = archive_raw(config(&object_root, input, "marker"))
            .await
            .unwrap();
        assert_eq!(result.completeness, "complete");
        assert_eq!(result.segment_count, 2);
        assert_eq!(result.total_records, 2);
        let manifest: RawArchiveManifest = serde_json::from_slice(
            &fs::read(object_root.join("datasets/chiptrace/raw/marker/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.empty_segments.len(), 1);
        assert_eq!(manifest.empty_segments[0].segment_id, 2);
        verify_raw_archive(RawArchiveVerifyConfig {
            archive_id: "marker".to_owned(),
            backend: Backend::Fs,
            root: Some(object_root.clone()),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            verify_records: true,
            allow_partial: false,
        })
        .await
        .unwrap();
        let restored = temporary.path().join("marker-restored");
        restore_raw_archive(RawArchiveRestoreConfig {
            archive_id: "marker".to_owned(),
            output: restored.clone(),
            backend: Backend::Fs,
            root: Some(object_root),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            verify_records: true,
            replace: false,
            allow_partial: false,
        })
        .await
        .unwrap();
        assert_eq!(
            fs::read(
                restored.join("segments/shard-00000/segment-00000000000000000002.sealed.ndjson")
            )
            .unwrap(),
            b"\n"
        );
    }

    #[tokio::test]
    async fn concurrent_same_archive_id_is_semantically_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("capture/segments");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("segment-00000000000000000001.sealed.ndjson"),
            [fixture_capture("cap-concurrent"), vec![b'\n']].concat(),
        )
        .unwrap();
        let object_root = temporary.path().join("objects");
        let first_config = config(&object_root, input.clone(), "concurrent");
        let second_config = first_config.clone();
        let (first, second) = tokio::join!(archive_raw(first_config), archive_raw(second_config));
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.manifest_key, second.manifest_key);
        assert_eq!(first.checkpoint_key, second.checkpoint_key);
        let retry = archive_raw(config(&object_root, input, "concurrent"))
            .await
            .unwrap();
        assert!(retry.idempotent);
        verify_raw_archive(RawArchiveVerifyConfig {
            archive_id: "concurrent".to_owned(),
            backend: Backend::Fs,
            root: Some(object_root),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            verify_records: true,
            allow_partial: false,
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn retry_repairs_a_missing_content_addressed_object() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("capture/segments");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("segment-00000000000000000001.sealed.ndjson"),
            [fixture_capture("cap-repair"), vec![b'\n']].concat(),
        )
        .unwrap();
        let object_root = temporary.path().join("objects");
        let config = config(&object_root, input.clone(), "repair");
        archive_raw(config.clone()).await.unwrap();
        let manifest: crate::schema::RawArchiveManifest = serde_json::from_slice(
            &fs::read(object_root.join("datasets/chiptrace/raw/repair/manifest.json")).unwrap(),
        )
        .unwrap();
        fs::remove_file(object_root.join(&manifest.segments[0].object_key)).unwrap();
        let retry = archive_raw(config).await.unwrap();
        assert!(retry.idempotent);
        verify_raw_archive(RawArchiveVerifyConfig {
            archive_id: "repair".to_owned(),
            backend: Backend::Fs,
            root: Some(object_root),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            verify_records: true,
            allow_partial: false,
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn retry_repairs_a_missing_manifest_but_rejects_changed_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("capture/segments");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("segment-00000000000000000001.sealed.ndjson"),
            [fixture_capture("cap-manifest-repair"), vec![b'\n']].concat(),
        )
        .unwrap();
        let object_root = temporary.path().join("objects");
        let config = config(&object_root, input.clone(), "manifest-repair");
        archive_raw(config.clone()).await.unwrap();
        let manifest_path =
            object_root.join("datasets/chiptrace/raw/manifest-repair/manifest.json");
        fs::remove_file(&manifest_path).unwrap();
        assert!(archive_raw(config.clone()).await.unwrap().idempotent);
        assert!(manifest_path.is_file());
        fs::write(&manifest_path, b"tampered").unwrap();
        assert!(archive_raw(config).await.is_err());
    }

    #[test]
    fn raw_manifest_rejects_unsafe_shards_and_empty_prefix_components() {
        let manifest = RawArchiveManifest {
            schema_version: RAW_ARCHIVE_SCHEMA_VERSION.to_owned(),
            archive_id: "unsafe".to_owned(),
            created_at_utc: "2026-08-28T00:00:00Z".to_owned(),
            format: "UTF-8 NDJSON sealed WAL".to_owned(),
            completeness: "partial".to_owned(),
            segment_count: 1,
            empty_segments: vec![],
            total_records: 1,
            total_bytes: 1,
            segments: vec![RawSegmentEntry {
                shard: "../escape".to_owned(),
                segment_id: 1,
                object_key: "raw/objects/abc.ndjson".to_owned(),
                source_path: "segments/../escape/segment-00000000000000000001.sealed.ndjson"
                    .to_owned(),
                bytes: 1,
                records: 1,
                sha256: "a".repeat(64),
                created_at: "2026-08-28T00:00:00Z".to_owned(),
                sealed_at: None,
            }],
        };
        assert!(validate_manifest_sequence(&manifest).is_err());
        assert!(normalize_prefix("datasets//chiptrace").is_err());
    }

    #[tokio::test]
    async fn empty_sealed_segment_is_not_a_committable_archive() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("capture/segments");
        fs::create_dir_all(&input).unwrap();
        fs::write(input.join("segment-00000000000000000001.sealed.ndjson"), []).unwrap();
        assert!(
            archive_raw(config(&temporary.path().join("objects"), input, "empty"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn directory_archive_refuses_an_open_segment_instead_of_claiming_complete() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("segments");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("segment-00000000000000000001.sealed.ndjson"),
            [fixture_capture("cap-open-boundary"), vec![b'\n']].concat(),
        )
        .unwrap();
        fs::write(
            input.join("segment-00000000000000000002.open.ndjson"),
            fixture_capture("cap-still-writing"),
        )
        .unwrap();
        let error = archive_raw(config(
            &temporary.path().join("objects"),
            input,
            "open-boundary",
        ))
        .await
        .expect_err("an open segment must never be silently omitted");
        assert!(error.to_string().contains("non-empty open WAL segment"));
    }

    #[tokio::test]
    async fn directory_archive_ignores_zero_byte_open_placeholder() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("segments");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("segment-00000000000000000001.sealed.ndjson"),
            [fixture_capture("cap-empty-open"), vec![b'\n']].concat(),
        )
        .unwrap();
        fs::write(input.join("segment-00000000000000000002.open.ndjson"), []).unwrap();
        let result = archive_raw(config(
            &temporary.path().join("objects"),
            input,
            "empty-open",
        ))
        .await
        .unwrap();
        assert_eq!(result.completeness, "complete");
        assert_eq!(result.total_records, 1);
    }

    #[tokio::test]
    async fn explicit_sealed_input_remains_available_for_forensic_snapshot() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("segments");
        fs::create_dir_all(&input).unwrap();
        let sealed = input.join("segment-00000000000000000001.sealed.ndjson");
        fs::write(
            &sealed,
            [fixture_capture("cap-explicit-sealed"), vec![b'\n']].concat(),
        )
        .unwrap();
        fs::write(
            input.join("segment-00000000000000000002.open.ndjson"),
            fixture_capture("cap-still-open"),
        )
        .unwrap();
        let result = archive_raw(config(
            &temporary.path().join("objects"),
            sealed,
            "explicit-sealed",
        ))
        .await
        .unwrap();
        assert_eq!(result.completeness, "complete");
        assert_eq!(result.total_records, 1);
    }
}
