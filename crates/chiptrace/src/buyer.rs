use crate::jsonl::{absolute_path, ensure_safe_relative_path, sha256_bytes, sha256_file, utc_now};
use crate::release::verify_release;
use crate::schema::{
    ASSESSMENT_SCHEMA_VERSION, BuyerAssessment, RawSourceLineage, ReleaseManifest, TokenCounts,
};
use crate::score::{
    AssessmentSchemaValidators, Profile, assessment_record_from_session,
    eligible_assessment_contract_valid, normalize_assessment_profile,
    recompute_assessment_for_version,
};
use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use walkdir::WalkDir;

pub const BUYER_PACKAGE_SCHEMA_VERSION: &str = "chiptrace.buyer-package.v1";
const BUYER_ARCHIVE_SCHEMA_VERSION: &str = "chiptrace.buyer-archive.v1";
const LINEAGE_COMPLETE: &str = "complete";

#[derive(Debug, Clone)]
pub struct BuyerPackageConfig {
    pub release: PathBuf,
    pub output: PathBuf,
    pub gzip_level: u32,
    pub workers: usize,
    pub replace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuyerArchiveManifest {
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
    pub records: u64,
    pub jsonl_bytes: u64,
    pub jsonl_sha256: String,
    pub source_part: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuyerPackageManifest {
    pub schema_version: String,
    pub release_id: String,
    pub created_at_utc: String,
    pub format: String,
    pub encoding: String,
    pub archive_format: String,
    pub buyer_profile: String,
    pub minimum_score: f64,
    pub source_release_manifest_sha256: String,
    pub lineage_status: String,
    pub raw_sources: Vec<RawSourceLineage>,
    pub eligible_sessions: u64,
    pub eligible_tokens: TokenCounts,
    pub packages: Vec<BuyerArchiveManifest>,
    pub validation_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArchiveMetadata {
    schema_version: String,
    release_id: String,
    buyer_profile: String,
    minimum_score: f64,
    format: String,
    encoding: String,
    session_atomic: bool,
    source_part: String,
    lineage_status: String,
    records: u64,
    jsonl_file: String,
    jsonl_bytes: u64,
    jsonl_sha256: String,
    validation_status: String,
}

struct PackagePartContext<'a> {
    release: &'a Path,
    package_root: &'a Path,
    release_id: &'a str,
    buyer_profile: &'a str,
    minimum_score: f64,
    lineage_status: &'a str,
    gzip_level: u32,
}

pub fn package_buyer_release(config: BuyerPackageConfig) -> Result<BuyerPackageManifest> {
    if config.gzip_level > 9 {
        bail!("gzip_level must be between 0 and 9");
    }
    let release = config.release.canonicalize()?;
    let source = verify_release(&release, true)?;
    require_current_assessments(&release, &source)?;
    if source.parts.is_empty() {
        bail!("verified Release has no eligible Session parts");
    }
    if !matches!(
        source.buyer_profile.as_str(),
        "buyer-v7" | "buyer-v7-codex-runtime-expanded"
    ) || source.minimum_score < 90.0
    {
        bail!("buyer package requires buyer-v7 with minimum_score >= 90");
    }
    if source.raw_sources.is_empty() {
        bail!("buyer package requires complete OSS Raw lineage");
    }
    let output = absolute_path(&config.output)?;
    if output.exists() && !config.replace {
        bail!("buyer package output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("buyer package output has no parent"))?;
    fs::create_dir_all(parent)?;
    let work = TempDir::new_in(parent)?;
    let staging = work.path().join("buyer-package");
    let package_root = staging.join("packages");
    fs::create_dir_all(&package_root)?;

    let workers = if config.workers == 0 {
        std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1)
    } else {
        config.workers
    }
    .clamp(1, source.parts.len());
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(|index| format!("chiptrace-buyer-{index}"))
        .build()?;
    let lineage_status = LINEAGE_COMPLETE;
    let part_context = PackagePartContext {
        release: &release,
        package_root: &package_root,
        release_id: &source.release_id,
        buyer_profile: &source.buyer_profile,
        minimum_score: source.minimum_score,
        lineage_status,
        gzip_level: config.gzip_level,
    };
    let mut packages = pool.install(|| {
        source
            .parts
            .par_iter()
            .enumerate()
            .map(|(index, part)| package_part(&part_context, index + 1, part))
            .collect::<Result<Vec<_>>>()
    })?;
    packages.sort_by(|left, right| left.file.cmp(&right.file));
    let packaged_records = packages.iter().map(|package| package.records).sum::<u64>();
    if packaged_records != source.counts.eligible_sessions {
        bail!(
            "buyer package record mismatch: packaged={packaged_records}, release={}",
            source.counts.eligible_sessions
        );
    }
    let manifest = BuyerPackageManifest {
        schema_version: BUYER_PACKAGE_SCHEMA_VERSION.to_owned(),
        release_id: source.release_id,
        created_at_utc: utc_now(),
        format: "one complete Session per UTF-8 JSONL line; one JSONL file per tar.gz".to_owned(),
        encoding: "UTF-8".to_owned(),
        archive_format: format!("tar.gz; gzip-{level}", level = config.gzip_level),
        buyer_profile: source.buyer_profile,
        minimum_score: source.minimum_score,
        source_release_manifest_sha256: sha256_file(&release.join("manifest.json"))?,
        lineage_status: lineage_status.to_owned(),
        raw_sources: source.raw_sources,
        eligible_sessions: source.counts.eligible_sessions,
        eligible_tokens: source.eligible_tokens,
        packages,
        validation_status: "pass".to_owned(),
    };
    fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    write_outer_checksums(&staging, &manifest)?;
    sync_tree(&staging)?;
    let verified = verify_buyer_package(&staging)?;
    if output.exists() {
        fs::remove_dir_all(&output)?;
    }
    fs::rename(&staging, &output)?;
    sync_directory(parent)?;
    Ok(verified)
}

fn require_current_assessments(release: &Path, manifest: &ReleaseManifest) -> Result<()> {
    for report in manifest.reports.iter().filter(|report| {
        report.file.starts_with("reports/assessments-part-") && report.file.ends_with(".jsonl.zst")
    }) {
        let mut reader = crate::jsonl::open_jsonl_reader(&release.join(&report.file))?;
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let record: Value = serde_json::from_slice(&line)?;
            if record
                .pointer("/quality/buyer_acceptance/schema_version")
                .and_then(Value::as_str)
                != Some(ASSESSMENT_SCHEMA_VERSION)
            {
                bail!(
                    "new buyer packages require {ASSESSMENT_SCHEMA_VERSION}; legacy assessments are read-only"
                );
            }
        }
    }
    Ok(())
}

pub fn verify_buyer_package(root: &Path) -> Result<BuyerPackageManifest> {
    let manifest_path = root.join("manifest.json");
    let manifest: BuyerPackageManifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    if manifest.schema_version != BUYER_PACKAGE_SCHEMA_VERSION {
        bail!(
            "unsupported buyer package schema {}",
            manifest.schema_version
        );
    }
    let gzip_level_valid = manifest
        .archive_format
        .strip_prefix("tar.gz; gzip-")
        .is_some_and(|level| level.len() == 1 && level.bytes().all(|byte| byte.is_ascii_digit()));
    if manifest.validation_status != "pass"
        || manifest.encoding != "UTF-8"
        || !gzip_level_valid
        || !matches!(
            manifest.buyer_profile.as_str(),
            "buyer-v7" | "buyer-v7-codex-runtime-expanded"
        )
        || !manifest.minimum_score.is_finite()
        || !(90.0..=100.0).contains(&manifest.minimum_score)
        || manifest.release_id.trim().is_empty()
        || manifest.eligible_sessions == 0
        || manifest.packages.is_empty()
        || !is_sha256(&manifest.source_release_manifest_sha256)
        || manifest.lineage_status != LINEAGE_COMPLETE
        || manifest.raw_sources.is_empty()
        || manifest
            .raw_sources
            .iter()
            .any(|source| !valid_raw_source(source))
    {
        bail!("buyer package manifest is not a passing buyer-v7 UTF-8 tar.gz delivery");
    }
    let mut expected_files = HashSet::from(["manifest.json".to_owned(), "SHA256SUMS".to_owned()]);
    let mut records = 0_u64;
    let mut tokens = TokenCounts::default();
    let assessment_schemas = AssessmentSchemaValidators::new()?;
    for (index, package) in manifest.packages.iter().enumerate() {
        ensure_safe_relative_path(&package.file)?;
        let expected_name = format!("packages/sessions-part-{:05}.tar.gz", index + 1);
        if package.file != expected_name
            || package.records == 0
            || package.bytes == 0
            || package.jsonl_bytes == 0
            || !is_sha256(&package.sha256)
            || !is_sha256(&package.jsonl_sha256)
            || !expected_files.insert(package.file.clone())
        {
            bail!("invalid or duplicate buyer archive path: {}", package.file);
        }
        let path = root.join(&package.file);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("buyer archive is not a regular file: {}", path.display());
        }
        if metadata.len() != package.bytes {
            bail!("buyer archive byte count mismatch: {}", path.display());
        }
        let archive_tokens = verify_archive(
            &path,
            &manifest.release_id,
            &manifest.buyer_profile,
            manifest.minimum_score,
            &manifest.lineage_status,
            package,
            &assessment_schemas,
        )?;
        tokens.add_assign(&archive_tokens);
        records = records.saturating_add(package.records);
    }
    if records != manifest.eligible_sessions {
        bail!("buyer package eligible Session count mismatch");
    }
    if tokens != manifest.eligible_tokens {
        bail!("buyer package eligible Token totals mismatch");
    }
    verify_outer_checksums(root, &manifest)?;
    let mut actual_files = HashSet::new();
    for entry in WalkDir::new(root).min_depth(1).follow_links(false) {
        let entry = entry?;
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_str()
            .context("buyer package path is not UTF-8")?
            .replace('\\', "/");
        if entry.file_type().is_file() {
            actual_files.insert(relative);
        } else if !entry.file_type().is_dir() || relative != "packages" {
            bail!("buyer package contains an unexpected entry: {relative}");
        }
    }
    if actual_files != expected_files {
        bail!("buyer package file set does not match manifest");
    }
    Ok(manifest)
}

fn package_part(
    context: &PackagePartContext<'_>,
    index: usize,
    part: &crate::schema::FileManifest,
) -> Result<BuyerArchiveManifest> {
    ensure_safe_relative_path(&part.file)?;
    let source = context.release.join(&part.file);
    if source.extension().and_then(|value| value.to_str()) != Some("zst") {
        bail!("source Release part is not JSONL.zst: {}", part.file);
    }
    let records = part
        .records
        .context("source Release part record count missing")?;
    let jsonl_bytes = part
        .uncompressed_bytes
        .context("source Release part uncompressed byte count missing")?;
    let relative = format!("packages/sessions-part-{index:05}.tar.gz");
    let output = context
        .package_root
        .join(format!("sessions-part-{index:05}.tar.gz"));
    let archive_metadata = ArchiveMetadata {
        schema_version: BUYER_ARCHIVE_SCHEMA_VERSION.to_owned(),
        release_id: context.release_id.to_owned(),
        buyer_profile: context.buyer_profile.to_owned(),
        minimum_score: context.minimum_score,
        format: "one complete Session per JSONL line".to_owned(),
        encoding: "UTF-8".to_owned(),
        session_atomic: true,
        source_part: part.file.clone(),
        lineage_status: context.lineage_status.to_owned(),
        records,
        jsonl_file: "sessions.jsonl".to_owned(),
        jsonl_bytes,
        jsonl_sha256: String::new(),
        validation_status: "pass".to_owned(),
    };

    let file = File::create(&output)?;
    let writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
    let writer = DigestWriter::new(writer);
    let encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(writer, Compression::new(context.gzip_level));
    let mut archive = tar::Builder::new(encoder);
    archive.mode(tar::HeaderMode::Deterministic);
    let compressed = DigestReader::new(File::open(&source)?);
    let decoder = zstd::stream::read::Decoder::new(compressed)?;
    let mut reader = DigestReader::new(decoder);
    append_tar_entry(&mut archive, "sessions.jsonl", jsonl_bytes, &mut reader)?;
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 || reader.bytes != jsonl_bytes {
        bail!(
            "source Release part uncompressed byte count changed: {}",
            part.file
        );
    }
    let (decoder, _, jsonl_sha256) = reader.into_parts();
    let mut compressed_reader = decoder.finish();
    std::io::copy(&mut compressed_reader, &mut std::io::sink())?;
    let (_, compressed_bytes, compressed_sha256) = compressed_reader.into_inner().into_parts();
    if compressed_bytes != part.bytes || compressed_sha256 != part.sha256 {
        bail!(
            "source Release part changed during buyer packaging: {}",
            part.file
        );
    }
    let archive_metadata = ArchiveMetadata {
        jsonl_sha256: jsonl_sha256.clone(),
        ..archive_metadata
    };
    let package_json = serde_json::to_vec_pretty(&archive_metadata)?;
    let package_sha256 = sha256_bytes(&package_json);
    let sums = format!("{jsonl_sha256}  sessions.jsonl\n{package_sha256}  PACKAGE.json\n");
    append_tar_entry(
        &mut archive,
        "PACKAGE.json",
        package_json.len() as u64,
        &mut Cursor::new(package_json),
    )?;
    append_tar_entry(
        &mut archive,
        "SHA256SUMS",
        sums.len() as u64,
        &mut Cursor::new(sums.into_bytes()),
    )?;
    let encoder = archive.into_inner()?;
    let writer = encoder.finish()?;
    let (mut writer, archive_bytes, archive_sha256) = writer.into_parts();
    writer.flush()?;
    writer.get_ref().sync_all()?;
    if output.metadata()?.len() != archive_bytes {
        bail!("buyer archive persisted byte count mismatch");
    }
    Ok(BuyerArchiveManifest {
        file: relative,
        sha256: archive_sha256,
        bytes: archive_bytes,
        records,
        jsonl_bytes,
        jsonl_sha256,
        source_part: part.file.clone(),
    })
}

struct DigestReader<R> {
    inner: R,
    digest: Sha256,
    bytes: u64,
}

impl<R> DigestReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes: 0,
        }
    }

    fn into_parts(self) -> (R, u64, String) {
        (self.inner, self.bytes, hex::encode(self.digest.finalize()))
    }
}

impl<R: Read> Read for DigestReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.digest.update(&buffer[..count]);
        self.bytes = self.bytes.saturating_add(count as u64);
        Ok(count)
    }
}

struct DigestWriter<W> {
    inner: W,
    digest: Sha256,
    bytes: u64,
}

impl<W> DigestWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes: 0,
        }
    }

    fn into_parts(self) -> (W, u64, String) {
        (self.inner, self.bytes, hex::encode(self.digest.finalize()))
    }
}

impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(buffer)?;
        self.digest.update(&buffer[..count]);
        self.bytes = self.bytes.saturating_add(count as u64);
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn append_tar_entry<W: Write, R: Read>(
    archive: &mut tar::Builder<W>,
    path: &str,
    size: u64,
    reader: &mut R,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, path, reader)?;
    Ok(())
}

fn verify_archive(
    path: &Path,
    release_id: &str,
    buyer_profile: &str,
    minimum_score: f64,
    lineage_status: &str,
    expected: &BuyerArchiveManifest,
    assessment_schemas: &AssessmentSchemaValidators,
) -> Result<TokenCounts> {
    let compressed = DigestReader::new(File::open(path)?);
    let decoder = GzDecoder::new(compressed);
    let mut archive = tar::Archive::new(decoder);
    let mut observed = HashSet::new();
    let mut metadata = None;
    let mut checksum_text = None;
    let mut records = 0_u64;
    let mut jsonl_bytes = 0_u64;
    let mut jsonl_digest = Sha256::new();
    let mut tokens = TokenCounts::default();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            bail!("buyer archive contains a non-file entry");
        }
        let entry_path = entry.path()?;
        let name = entry_path
            .to_str()
            .context("buyer archive entry path is not UTF-8")?
            .replace('\\', "/");
        ensure_safe_relative_path(&name)?;
        if !observed.insert(name.clone()) {
            bail!("buyer archive contains duplicate entry {name:?}");
        }
        let declared_size = entry.header().size()?;
        match name.as_str() {
            "sessions.jsonl" => {
                if declared_size != expected.jsonl_bytes {
                    bail!("buyer archive JSONL size does not match manifest");
                }
                let mut reader = BufReader::new(entry);
                let mut line = Vec::new();
                loop {
                    line.clear();
                    if reader.read_until(b'\n', &mut line)? == 0 {
                        break;
                    }
                    if line.iter().all(u8::is_ascii_whitespace) {
                        bail!("buyer archive JSONL contains an empty line");
                    }
                    jsonl_digest.update(&line);
                    jsonl_bytes = jsonl_bytes.saturating_add(line.len() as u64);
                    let value: Value = serde_json::from_slice(&line)?;
                    let assessment =
                        validate_buyer_record(&value, minimum_score, assessment_schemas)?;
                    tokens.add_assign(&assessment.tokens);
                    records += 1;
                    if records > expected.records {
                        bail!("buyer archive contains more Session records than declared");
                    }
                }
            }
            "PACKAGE.json" => {
                if declared_size > 1024 * 1024 {
                    bail!("buyer archive PACKAGE.json exceeds 1 MiB");
                }
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                metadata = Some((serde_json::from_slice::<ArchiveMetadata>(&bytes)?, bytes));
            }
            "SHA256SUMS" => {
                if declared_size > 1024 * 1024 {
                    bail!("buyer archive SHA256SUMS exceeds 1 MiB");
                }
                let mut text = String::new();
                entry.read_to_string(&mut text)?;
                checksum_text = Some(text);
            }
            _ => bail!("buyer archive contains unexpected entry {name:?}"),
        }
    }
    let mut decoder = archive.into_inner();
    std::io::copy(&mut decoder, &mut std::io::sink())?;
    let (_, compressed_bytes, compressed_sha256) = decoder.into_inner().into_parts();
    if compressed_bytes != expected.bytes || compressed_sha256 != expected.sha256 {
        bail!("buyer archive checksum mismatch: {}", path.display());
    }
    if observed
        != HashSet::from([
            "sessions.jsonl".to_owned(),
            "PACKAGE.json".to_owned(),
            "SHA256SUMS".to_owned(),
        ])
    {
        bail!("buyer archive entry set is incomplete");
    }
    let jsonl_sha256 = hex::encode(jsonl_digest.finalize());
    let (metadata, metadata_bytes) = metadata.context("buyer archive PACKAGE.json missing")?;
    if metadata.schema_version != BUYER_ARCHIVE_SCHEMA_VERSION
        || metadata.release_id != release_id
        || metadata.buyer_profile != buyer_profile
        || metadata.minimum_score != minimum_score
        || metadata.format != "one complete Session per JSONL line"
        || metadata.encoding != "UTF-8"
        || !metadata.session_atomic
        || metadata.source_part != expected.source_part
        || metadata.lineage_status != lineage_status
        || metadata.records != records
        || metadata.jsonl_file != "sessions.jsonl"
        || metadata.jsonl_bytes != jsonl_bytes
        || metadata.jsonl_sha256 != jsonl_sha256
        || metadata.validation_status != "pass"
        || records != expected.records
        || jsonl_bytes != expected.jsonl_bytes
        || jsonl_sha256 != expected.jsonl_sha256
    {
        bail!("buyer archive metadata does not match its JSONL payload");
    }
    let expected_sums = BTreeMap::from([
        ("sessions.jsonl".to_owned(), jsonl_sha256),
        ("PACKAGE.json".to_owned(), sha256_bytes(&metadata_bytes)),
    ]);
    if parse_checksums(&checksum_text.context("buyer archive SHA256SUMS missing")?)?
        != expected_sums
    {
        bail!("buyer archive SHA256SUMS mismatch");
    }
    Ok(tokens)
}

fn validate_buyer_record(
    session: &Value,
    minimum_score: f64,
    assessment_schemas: &AssessmentSchemaValidators,
) -> Result<BuyerAssessment> {
    validate_buyer_session_surface(session)?;
    let assessment: BuyerAssessment = serde_json::from_value(
        session
            .pointer("/quality/buyer_acceptance")
            .cloned()
            .context("buyer Session has no quality.buyer_acceptance")?,
    )?;
    if !eligible_assessment_contract_valid(&assessment, Profile::BuyerV7, minimum_score) {
        bail!("buyer archive contains an inconsistent or ineligible buyer-v7 Session");
    }
    assessment_schemas.validate(&assessment_record_from_session(session, "eligible"))?;
    let recomputed = recompute_assessment_for_version(
        session,
        Profile::BuyerV7,
        minimum_score,
        &assessment.schema_version,
    )
    .context("buyer Session uses an unsupported assessment schema")?;
    let mut comparable = assessment.clone();
    normalize_assessment_profile(&mut comparable, Profile::BuyerV7);
    if recomputed != comparable {
        bail!("buyer archive Session quality does not match its canonical content");
    }
    Ok(assessment)
}

fn validate_buyer_session_surface(session: &Value) -> Result<()> {
    let meta = session
        .get("meta")
        .and_then(Value::as_object)
        .context("buyer Session has no meta object")?;
    for field in [
        "active_quality_projection",
        "code_mode_message_projection",
        "producer_event_conflicts",
        "producer_streams",
        "quality_projections",
        "rollout_events",
        "rollout_unknown_events",
        "rollout_unmapped_tools",
        "rollout_usage_evidence",
        "tool_registry_evidence",
    ] {
        if meta.contains_key(field) {
            bail!("buyer Session contains internal metadata field {field}");
        }
    }
    if let Some(runtime) = meta.get("runtime_dag").and_then(Value::as_object) {
        for field in ["native_event_count", "terminal_rollout_ids"] {
            if runtime.contains_key(field) {
                bail!("buyer Session Runtime DAG contains historical field {field}");
            }
        }
        if runtime.get("source").and_then(Value::as_str)
            != Some("canonical_model_interaction:cloud_evidence")
        {
            bail!("buyer Session Runtime DAG does not use canonical cloud evidence");
        }
    }
    Ok(())
}

fn write_outer_checksums(root: &Path, manifest: &BuyerPackageManifest) -> Result<()> {
    let mut writer = BufWriter::new(File::create(root.join("SHA256SUMS"))?);
    writeln!(
        writer,
        "{}  manifest.json",
        sha256_file(&root.join("manifest.json"))?
    )?;
    for package in &manifest.packages {
        writeln!(writer, "{}  {}", package.sha256, package.file)?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

fn verify_outer_checksums(root: &Path, manifest: &BuyerPackageManifest) -> Result<()> {
    let mut expected = BTreeMap::from([(
        "manifest.json".to_owned(),
        sha256_file(&root.join("manifest.json"))?,
    )]);
    for package in &manifest.packages {
        expected.insert(package.file.clone(), package.sha256.clone());
    }
    let text = fs::read_to_string(root.join("SHA256SUMS"))?;
    if parse_checksums(&text)? != expected {
        bail!("buyer package SHA256SUMS does not match manifest");
    }
    Ok(())
}

fn parse_checksums(text: &str) -> Result<BTreeMap<String, String>> {
    let mut output = BTreeMap::new();
    for line in text.lines() {
        let (digest, name) = line
            .split_once("  ")
            .ok_or_else(|| anyhow::anyhow!("invalid SHA256SUMS line"))?;
        if !is_sha256(digest) {
            bail!("invalid SHA-256 digest in SHA256SUMS");
        }
        ensure_safe_relative_path(name)?;
        if output.insert(name.to_owned(), digest.to_owned()).is_some() {
            bail!("duplicate SHA256SUMS path {name:?}");
        }
    }
    Ok(output)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_raw_source(source: &RawSourceLineage) -> bool {
    source.schema_version == "chiptrace.raw-lineage.v1"
        && !source.archive_id.trim().is_empty()
        && source.completeness == "complete"
        && source.segment_count > 0
        && source.total_records > 0
        && source.total_bytes > 0
        && !source.checkpoint_key.trim().is_empty()
        && !source.manifest_key.trim().is_empty()
        && ensure_safe_relative_path(&source.checkpoint_key).is_ok()
        && ensure_safe_relative_path(&source.manifest_key).is_ok()
        && is_sha256(&source.checkpoint_sha256)
        && is_sha256(&source.manifest_sha256)
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
    use crate::jsonl::JsonlWriter;
    use crate::schema::{
        FileManifest, LEGACY_ASSESSMENT_SCHEMA_VERSION, RELEASE_SCHEMA_VERSION, ReleaseCounts,
    };
    use serde_json::json;

    #[test]
    fn buyer_surface_rejects_internal_collection_metadata() {
        let base = json!({"meta":{"runtime_dag":{
            "source":"canonical_model_interaction:cloud_evidence"
        }}});
        validate_buyer_session_surface(&base).unwrap();

        for field in [
            "active_quality_projection",
            "code_mode_message_projection",
            "producer_event_conflicts",
            "producer_streams",
            "quality_projections",
            "rollout_events",
            "rollout_unknown_events",
            "rollout_unmapped_tools",
            "rollout_usage_evidence",
            "tool_registry_evidence",
        ] {
            let mut invalid = base.clone();
            invalid["meta"][field] = json!({});
            assert!(
                validate_buyer_session_surface(&invalid).is_err(),
                "accepted internal field {field}"
            );
        }
    }

    #[test]
    fn new_buyer_package_rejects_legacy_v1_assessment_reports() {
        let temporary = tempfile::tempdir().unwrap();
        let report_path = temporary
            .path()
            .join("reports/assessments-part-00001.jsonl.zst");
        let mut writer = JsonlWriter::create(&report_path, 1).unwrap();
        writer
            .write_value(&json!({
                "quality":{"buyer_acceptance":{
                    "schema_version":LEGACY_ASSESSMENT_SCHEMA_VERSION
                }}
            }))
            .unwrap();
        writer.finish().unwrap();
        let report = FileManifest {
            file: "reports/assessments-part-00001.jsonl.zst".to_owned(),
            sha256: sha256_file(&report_path).unwrap(),
            bytes: report_path.metadata().unwrap().len(),
            records: Some(1),
            uncompressed_bytes: None,
            oversized_session: None,
        };
        let manifest = ReleaseManifest {
            schema_version: RELEASE_SCHEMA_VERSION.to_owned(),
            release_id: "legacy-assessment".to_owned(),
            created_at_utc: "2026-09-01T00:00:00Z".to_owned(),
            format: "jsonl".to_owned(),
            session_atomic: true,
            session_split_count: 0,
            buyer_profile: "buyer-v7-codex-runtime-expanded".to_owned(),
            minimum_score: 90.0,
            tokenizer: String::new(),
            compression: "zstd".to_owned(),
            processing_workers: 1,
            target_part_bytes: 1,
            raw_sources: Vec::new(),
            counts: ReleaseCounts::default(),
            eligible_tokens: TokenCounts::default(),
            assessed_tokens: TokenCounts::default(),
            failure_reason_counts: BTreeMap::new(),
            parts: Vec::new(),
            reports: vec![report],
            validation_status: "pass".to_owned(),
        };

        let error = require_current_assessments(temporary.path(), &manifest).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("legacy assessments are read-only")
        );
    }
}
