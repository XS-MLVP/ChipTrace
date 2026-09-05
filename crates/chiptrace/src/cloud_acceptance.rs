use crate::assemble::{AssembleConfig, assemble, verify_assembly};
use crate::buyer::{BuyerPackageConfig, package_buyer_release, verify_buyer_package};
use crate::enrich::{EnrichConfig, enrich_captures, verify_enrichment};
use crate::jsonl::{
    absolute_path, ensure_safe_relative_path, open_jsonl_reader, sha256_file, utc_now,
};
use crate::model_interaction::{
    CloudSourceCoverage, InteractionProjectConfig, project_interactions,
    verify_interaction_projection,
};
use crate::object_store::Backend;
use crate::raw_archive::{
    RawArchiveRestoreConfig, RawArchiveVerifyConfig, restore_raw_archive, verify_raw_archive,
};
use crate::release::{ReleaseConfig, build_release, verify_release};
use crate::schema::{RAW_LINEAGE_SCHEMA_VERSION, RawSourceLineage};
use crate::score::Profile;
use crate::telemetry::{OtlpExportConfig, export_otlp, verify_otlp_export};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub const CLOUD_ACCEPTANCE_SCHEMA_VERSION: &str = "chiptrace.cloud-acceptance.v1";

#[derive(Debug, Clone)]
pub struct CloudAcceptanceConfig {
    pub archive_id: String,
    pub backend: Backend,
    pub root: Option<PathBuf>,
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub prefix: String,
    pub usage_logs: Vec<PathBuf>,
    pub session_id: String,
    pub output: PathBuf,
    pub release_id: String,
    pub minimum_score: f64,
    pub target_part_bytes: u64,
    pub partitions: usize,
    pub zstd_level: i32,
    pub gzip_level: u32,
    pub workers: usize,
    pub replace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptanceArtifact {
    pub path: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudAcceptanceManifest {
    pub schema_version: String,
    pub created_at_utc: String,
    pub archive_id: String,
    pub session_id: String,
    pub release_id: String,
    pub quality_profile: String,
    pub minimum_score: f64,
    pub score: f64,
    pub hard_gate_pass: bool,
    pub delivery_ready: bool,
    pub effective_turns: u64,
    pub distinct_tool_names: u64,
    pub complete_tool_definitions: u64,
    pub pairing_rate_after_open_tail: f64,
    pub eligible_sessions: u64,
    pub api_total_tokens: u64,
    pub normalized_corpus_tokens: u64,
    pub source_coverage: CloudSourceCoverage,
    pub root_spans: u64,
    pub internal_parent_references: u64,
    pub resolved_internal_parents: u64,
    pub raw_records: u64,
    pub raw_bytes: u64,
    pub artifacts: BTreeMap<String, AcceptanceArtifact>,
    pub validation_status: String,
}

pub async fn run_cloud_acceptance(
    config: CloudAcceptanceConfig,
) -> Result<CloudAcceptanceManifest> {
    validate_config(&config)?;
    let output = absolute_path(&config.output)?;
    if output.exists() && !config.replace {
        bail!(
            "cloud acceptance output already exists: {}",
            output.display()
        );
    }
    let parent = output
        .parent()
        .context("cloud acceptance output has no parent")?;
    fs::create_dir_all(parent)?;
    let work = TempDir::new_in(parent)?;
    let staging = work.path().join("cloud-acceptance");
    fs::create_dir_all(&staging)?;

    let result = run_pipeline(&config, &staging).await;
    if let Err(error) = &result {
        let failure = json!({
            "schema_version":CLOUD_ACCEPTANCE_SCHEMA_VERSION,
            "created_at_utc":utc_now(),
            "archive_id":config.archive_id,
            "session_id":config.session_id,
            "release_id":config.release_id,
            "validation_status":"fail",
            "error":format!("{error:#}"),
        });
        let output_name = output
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("cloud-acceptance");
        let path = parent.join(format!("{output_name}.failed.json"));
        fs::write(&path, serde_json::to_vec_pretty(&failure)?)?;
        File::open(&path)?.sync_all()?;
        return result;
    }
    if output.exists() {
        if output.is_dir() {
            fs::remove_dir_all(&output)?;
        } else {
            fs::remove_file(&output)?;
        }
    }
    fs::rename(&staging, &output)?;
    File::open(parent)?.sync_all()?;
    verify_cloud_acceptance(&output)
}

async fn run_pipeline(
    config: &CloudAcceptanceConfig,
    output: &Path,
) -> Result<CloudAcceptanceManifest> {
    let raw_verify = verify_raw_archive(raw_verify_config(config)).await?;
    if !raw_verify.ok || raw_verify.completeness != "complete" {
        bail!("Raw archive is not complete");
    }
    let raw_root = output.join("raw");
    let raw_restore = restore_raw_archive(RawArchiveRestoreConfig {
        archive_id: config.archive_id.clone(),
        output: raw_root.clone(),
        backend: config.backend,
        root: config.root.clone(),
        endpoint: config.endpoint.clone(),
        bucket: config.bucket.clone(),
        region: config.region.clone(),
        prefix: config.prefix.clone(),
        verify_records: true,
        replace: false,
        allow_partial: false,
    })
    .await?;
    if !raw_restore.ok
        || raw_restore.completeness != "complete"
        || raw_restore.total_records != raw_verify.total_records
        || raw_restore.total_bytes != raw_verify.total_bytes
    {
        bail!("restored Raw archive does not match its committed checkpoint");
    }

    let enriched_root = output.join("enriched");
    let enrichment = enrich_captures(EnrichConfig {
        inputs: vec![raw_root],
        usage_logs: config.usage_logs.clone(),
        output: enriched_root.clone(),
        zstd_level: config.zstd_level,
        replace: false,
    })?;
    let enrichment_verified = verify_enrichment(&enriched_root)?;
    if enrichment != enrichment_verified
        || enrichment.invalid_usage_rows != 0
        || enrichment.ambiguous != 0
        || enrichment.conflicting_existing_evidence != 0
    {
        bail!("Sub2API enrichment is ambiguous, invalid, or inconsistent");
    }

    let interaction_root = output.join("interactions");
    let interaction = project_interactions(InteractionProjectConfig {
        inputs: vec![enriched_root.clone()],
        output: interaction_root.clone(),
        task_session_id: None,
        session_id: Some(config.session_id.clone()),
        zstd_level: config.zstd_level,
        replace: false,
    })?;
    let interaction_verified = verify_interaction_projection(&interaction_root)?;
    if interaction != interaction_verified
        || interaction.session_id.as_deref() != Some(config.session_id.as_str())
        || interaction.validation_status != "delivery_ready"
        || !interaction.integrity.delivery_ready
        || !interaction.source_coverage.complete
    {
        bail!(
            "selected Stock Codex Session is not delivery-ready; missing cloud sources: {:?}",
            interaction.source_coverage.missing_sources
        );
    }

    let otlp_root = output.join("otlp");
    let otlp = export_otlp(OtlpExportConfig {
        projection: interaction_root,
        output: otlp_root.clone(),
        zstd_level: config.zstd_level,
        replace: false,
    })?;
    let otlp_verified = verify_otlp_export(&otlp_root)?;
    if otlp != otlp_verified
        || !otlp.source_delivery_ready
        || otlp.root_spans != 1
        || otlp.internal_parent_references != otlp.resolved_internal_parents
        || otlp.resolved_internal_parent_rate != 1.0
        || !otlp.missing_parent_nodes.is_empty()
    {
        bail!("OTLP projection is not a single fully resolved Trace tree");
    }

    let assembly_root = output.join("assembly");
    let assembly = assemble(AssembleConfig {
        inputs: vec![enriched_root],
        output: assembly_root.clone(),
        task_session_id: None,
        session_id: Some(config.session_id.clone()),
        partitions: config.partitions,
        zstd_level: config.zstd_level,
        replace: false,
    })?;
    let assembly_verified = verify_assembly(&assembly_root)?;
    if assembly.sessions != 1
        || assembly.session_id.as_deref() != Some(config.session_id.as_str())
        || assembly.raw_sources.is_empty()
        || assembly_verified.sessions != 1
    {
        bail!("Assembly did not produce exactly the selected Stock Codex Session");
    }

    let release_root = output.join("release");
    let release = build_release(ReleaseConfig {
        inputs: vec![assembly_root],
        output: release_root.clone(),
        release_id: config.release_id.clone(),
        profile: Profile::BuyerV7,
        minimum_score: config.minimum_score,
        target_part_bytes: config.target_part_bytes,
        dedup_partitions: config.partitions,
        zstd_level: config.zstd_level,
        workers: config.workers,
        replace: false,
        require_pass: true,
    })?;
    let release_verified = verify_release(&release_root, true)?;
    if release != release_verified
        || release.counts.eligible_sessions != 1
        || release.counts.assessed_sessions != 1
        || release.counts.rejected_sessions != 0
        || release.raw_sources.is_empty()
    {
        bail!("Release did not contain exactly one eligible Session");
    }

    let delivered = read_single_release_session(&release_root, &release)?;
    let buyer_quality = delivered
        .pointer("/quality/buyer_acceptance")
        .context("eligible Session has no buyer_acceptance result")?;
    let score = buyer_quality
        .get("score")
        .and_then(Value::as_f64)
        .context("buyer_acceptance score is missing")?;
    let hard_gate_pass = buyer_quality
        .get("hard_gate_pass")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let effective_turns = quality_u64(buyer_quality, "effective_turns")?;
    let distinct_tool_names = quality_u64(buyer_quality, "distinct_tool_names")?;
    let complete_tool_definitions = quality_u64(buyer_quality, "complete_tool_definitions")?;
    let pairing_rate_after_open_tail = buyer_quality
        .pointer("/metrics/pairing_rate_after_open_tail")
        .or_else(|| buyer_quality.get("pairing_rate_after_open_tail"))
        .and_then(Value::as_f64)
        .context("buyer_acceptance pairing rate is missing")?;
    if score < config.minimum_score
        || !hard_gate_pass
        || effective_turns < 10
        || distinct_tool_names < 5
        || complete_tool_definitions < 5
        || pairing_rate_after_open_tail != 1.0
    {
        bail!("eligible Session does not satisfy the strict Buyer v7 thresholds");
    }

    let buyer_root = output.join("buyer-package");
    let buyer = package_buyer_release(BuyerPackageConfig {
        release: release_root.clone(),
        output: buyer_root.clone(),
        gzip_level: config.gzip_level,
        workers: config.workers,
        replace: false,
    })?;
    let buyer_verified = verify_buyer_package(&buyer_root)?;
    if buyer != buyer_verified || buyer.eligible_sessions != 1 || buyer.lineage_status != "complete"
    {
        bail!("Buyer package verification failed");
    }

    let artifacts = artifact_manifests(output)?;
    let manifest = CloudAcceptanceManifest {
        schema_version: CLOUD_ACCEPTANCE_SCHEMA_VERSION.to_owned(),
        created_at_utc: utc_now(),
        archive_id: config.archive_id.clone(),
        session_id: config.session_id.clone(),
        release_id: config.release_id.clone(),
        quality_profile: release.buyer_profile,
        minimum_score: config.minimum_score,
        score,
        hard_gate_pass,
        delivery_ready: true,
        effective_turns,
        distinct_tool_names,
        complete_tool_definitions,
        pairing_rate_after_open_tail,
        eligible_sessions: buyer.eligible_sessions,
        api_total_tokens: buyer.eligible_tokens.api_total_tokens,
        normalized_corpus_tokens: buyer.eligible_tokens.normalized_corpus_tokens,
        source_coverage: interaction.source_coverage,
        root_spans: otlp.root_spans,
        internal_parent_references: otlp.internal_parent_references,
        resolved_internal_parents: otlp.resolved_internal_parents,
        raw_records: raw_verify.total_records,
        raw_bytes: raw_verify.total_bytes,
        artifacts,
        validation_status: "pass".to_owned(),
    };
    let manifest_path = output.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    File::open(&manifest_path)?.sync_all()?;
    File::open(output)?.sync_all()?;
    verify_cloud_acceptance(output)
}

pub fn verify_cloud_acceptance(root: &Path) -> Result<CloudAcceptanceManifest> {
    let manifest_path = root.join("manifest.json");
    let value: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/cloud-acceptance-v1.schema.json"
    ))?;
    let validator = jsonschema::draft202012::new(&schema)
        .map_err(|error| anyhow::anyhow!("compile cloud acceptance schema: {error}"))?;
    if let Err(error) = validator.validate(&value) {
        bail!(
            "cloud acceptance manifest validation failed at {}: {error}",
            error.instance_path()
        );
    }
    let manifest: CloudAcceptanceManifest = serde_json::from_value(value)?;
    if manifest.validation_status != "pass"
        || !manifest.delivery_ready
        || !manifest.hard_gate_pass
        || manifest.score < manifest.minimum_score
        || manifest.minimum_score < 90.0
        || manifest.effective_turns < 10
        || manifest.distinct_tool_names < 5
        || manifest.complete_tool_definitions < 5
        || manifest.pairing_rate_after_open_tail != 1.0
        || manifest.eligible_sessions != 1
        || !manifest.source_coverage.complete
        || manifest.source_coverage.wire == 0
        || manifest.source_coverage.otlp_logs == 0
        || manifest.source_coverage.otlp_traces == 0
        || manifest.source_coverage.hooks == 0
        || !manifest.source_coverage.missing_sources.is_empty()
        || manifest.root_spans != 1
        || manifest.internal_parent_references != manifest.resolved_internal_parents
    {
        bail!("cloud acceptance manifest does not satisfy strict delivery gates");
    }
    let expected_artifacts = [
        ("raw", "raw/RAW_SOURCE.json"),
        ("enriched", "enriched/manifest.json"),
        ("interactions", "interactions/manifest.json"),
        ("otlp", "otlp/manifest.json"),
        ("assembly", "assembly/manifest.json"),
        ("release", "release/manifest.json"),
        ("buyer_package", "buyer-package/manifest.json"),
    ];
    if manifest.artifacts.len() != expected_artifacts.len()
        || expected_artifacts.iter().any(|(name, path)| {
            manifest.artifacts.get(*name).map(|item| item.path.as_str()) != Some(*path)
        })
    {
        bail!("cloud acceptance artifact set is not canonical");
    }
    for artifact in manifest.artifacts.values() {
        ensure_safe_relative_path(&artifact.path)?;
        let path = root.join(&artifact.path);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || sha256_file(&path)? != artifact.manifest_sha256
        {
            bail!(
                "cloud acceptance artifact checksum mismatch: {}",
                artifact.path
            );
        }
    }

    let raw_source: RawSourceLineage =
        serde_json::from_slice(&fs::read(root.join("raw/RAW_SOURCE.json"))?)?;
    if raw_source.schema_version != RAW_LINEAGE_SCHEMA_VERSION
        || raw_source.archive_id != manifest.archive_id
        || raw_source.completeness != "complete"
        || raw_source.total_records != manifest.raw_records
        || raw_source.total_bytes != manifest.raw_bytes
    {
        bail!("cloud acceptance Raw lineage does not match its manifest");
    }
    let lineage = vec![raw_source];
    let enriched = verify_enrichment(&root.join("enriched"))?;
    verify_restored_raw_snapshot(&root.join("raw"), &lineage[0], &enriched)?;
    let interactions = verify_interaction_projection(&root.join("interactions"))?;
    let otlp = verify_otlp_export(&root.join("otlp"))?;
    let assembly = verify_assembly(&root.join("assembly"))?;
    let release = verify_release(&root.join("release"), true)?;
    let buyer = verify_buyer_package(&root.join("buyer-package"))?;
    if enriched.raw_sources != lineage
        || interactions.raw_sources != lineage
        || assembly.raw_sources != lineage
        || release.raw_sources != lineage
        || buyer.raw_sources != lineage
    {
        bail!("cloud acceptance stages do not share one exact Raw lineage");
    }
    let release_manifest_sha256 = &manifest
        .artifacts
        .get("release")
        .context("cloud acceptance release artifact is missing")?
        .manifest_sha256;
    let interaction_manifest_sha256 = &manifest
        .artifacts
        .get("interactions")
        .context("cloud acceptance interaction artifact is missing")?
        .manifest_sha256;
    if interactions.session_id.as_deref() != Some(manifest.session_id.as_str())
        || interactions.validation_status != "delivery_ready"
        || !interactions.integrity.delivery_ready
        || assembly.session_id.as_deref() != Some(manifest.session_id.as_str())
        || assembly.sessions != 1
        || release.release_id != manifest.release_id
        || release.buyer_profile != manifest.quality_profile
        || release.minimum_score != manifest.minimum_score
        || release.counts.assessed_sessions != 1
        || release.counts.eligible_sessions != 1
        || release.counts.rejected_sessions != 0
        || buyer.release_id != manifest.release_id
        || buyer.buyer_profile != manifest.quality_profile
        || buyer.minimum_score != manifest.minimum_score
        || buyer.eligible_sessions != manifest.eligible_sessions
        || buyer.source_release_manifest_sha256 != *release_manifest_sha256
        || buyer.eligible_tokens.api_total_tokens != manifest.api_total_tokens
        || buyer.eligible_tokens.normalized_corpus_tokens != manifest.normalized_corpus_tokens
        || otlp.source_projection_manifest_sha256 != *interaction_manifest_sha256
        || otlp.root_spans != manifest.root_spans
        || otlp.internal_parent_references != manifest.internal_parent_references
        || otlp.resolved_internal_parents != manifest.resolved_internal_parents
    {
        bail!("cloud acceptance stage manifests disagree with the top-level result");
    }

    let delivered = read_single_release_session(&root.join("release"), &release)?;
    let quality = delivered
        .pointer("/quality/buyer_acceptance")
        .context("eligible Session has no buyer_acceptance result")?;
    let delivered_score = quality
        .get("score")
        .and_then(Value::as_f64)
        .context("buyer_acceptance score is missing")?;
    let delivered_pairing = quality
        .pointer("/metrics/pairing_rate_after_open_tail")
        .or_else(|| quality.get("pairing_rate_after_open_tail"))
        .and_then(Value::as_f64)
        .context("buyer_acceptance pairing rate is missing")?;
    if delivered_score != manifest.score
        || quality.get("hard_gate_pass").and_then(Value::as_bool) != Some(manifest.hard_gate_pass)
        || quality_u64(quality, "effective_turns")? != manifest.effective_turns
        || quality_u64(quality, "distinct_tool_names")? != manifest.distinct_tool_names
        || quality_u64(quality, "complete_tool_definitions")? != manifest.complete_tool_definitions
        || delivered_pairing != manifest.pairing_rate_after_open_tail
    {
        bail!("cloud acceptance quality summary differs from the delivered Session");
    }
    Ok(manifest)
}

fn verify_restored_raw_snapshot(
    raw_root: &Path,
    lineage: &RawSourceLineage,
    enrichment: &crate::enrich::EnrichSummary,
) -> Result<()> {
    // Raw lineage counts data segments; the restored directory may also hold
    // zero-record rotation markers that still contribute bytes and sequence evidence.
    if enrichment.capture_inputs.len() < lineage.segment_count as usize
        || enrichment.input_records != lineage.total_records
    {
        bail!("restored Raw snapshot counts do not match lineage");
    }
    let mut total_bytes = 0_u64;
    let mut expected_files = std::collections::BTreeSet::new();
    for source in &enrichment.capture_inputs {
        let relative = source
            .path
            .rsplit_once("/raw/")
            .map(|(_, relative)| relative)
            .filter(|path| path.starts_with("segments/"))
            .context("enrichment Raw input has no canonical segments path")?;
        ensure_safe_relative_path(relative)?;
        if !expected_files.insert(relative.to_owned()) {
            bail!("enrichment Raw inputs contain a duplicate segment path");
        }
        let path = raw_root.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != source.bytes
            || sha256_file(&path)? != source.sha256
        {
            bail!("restored Raw segment does not match enrichment input: {relative}");
        }
        total_bytes = total_bytes.saturating_add(source.bytes);
    }
    let actual_files = walkdir::WalkDir::new(raw_root.join("segments"))
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| {
            entry
                .path()
                .strip_prefix(raw_root)
                .expect("walked Raw entry outside root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<std::collections::BTreeSet<_>>();
    if actual_files != expected_files || total_bytes != lineage.total_bytes {
        bail!("restored Raw snapshot files or bytes do not match lineage");
    }
    Ok(())
}

fn validate_config(config: &CloudAcceptanceConfig) -> Result<()> {
    if config.archive_id.trim().is_empty()
        || config.session_id.trim().is_empty()
        || config.release_id.trim().is_empty()
        || config.usage_logs.is_empty()
        || config.partitions == 0
        || config.target_part_bytes == 0
        || !(90.0..=100.0).contains(&config.minimum_score)
        || config.gzip_level > 9
    {
        bail!(
            "cloud acceptance requires a complete archive, explicit Session, usage evidence, and Buyer v7 thresholds"
        );
    }
    Ok(())
}

fn raw_verify_config(config: &CloudAcceptanceConfig) -> RawArchiveVerifyConfig {
    RawArchiveVerifyConfig {
        archive_id: config.archive_id.clone(),
        backend: config.backend,
        root: config.root.clone(),
        endpoint: config.endpoint.clone(),
        bucket: config.bucket.clone(),
        region: config.region.clone(),
        prefix: config.prefix.clone(),
        verify_records: true,
        allow_partial: false,
    }
}

fn quality_u64(quality: &Value, field: &str) -> Result<u64> {
    quality
        .pointer(&format!("/metrics/{field}"))
        .or_else(|| quality.get(field))
        .and_then(Value::as_u64)
        .with_context(|| format!("buyer_acceptance metric {field} is missing"))
}

fn read_single_release_session(
    root: &Path,
    release: &crate::schema::ReleaseManifest,
) -> Result<Value> {
    let mut sessions = Vec::new();
    for part in &release.parts {
        let mut reader = open_jsonl_reader(&root.join(&part.file))?;
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if !line.iter().all(u8::is_ascii_whitespace) {
                sessions.push(serde_json::from_slice(&line)?);
            }
        }
    }
    if sessions.len() != 1 {
        bail!("expected one eligible Session, observed {}", sessions.len());
    }
    Ok(sessions.remove(0))
}

fn artifact_manifests(root: &Path) -> Result<BTreeMap<String, AcceptanceArtifact>> {
    let definitions = [
        ("raw", "raw/RAW_SOURCE.json"),
        ("enriched", "enriched/manifest.json"),
        ("interactions", "interactions/manifest.json"),
        ("otlp", "otlp/manifest.json"),
        ("assembly", "assembly/manifest.json"),
        ("release", "release/manifest.json"),
        ("buyer_package", "buyer-package/manifest.json"),
    ];
    definitions
        .into_iter()
        .map(|(name, path)| {
            let manifest = root.join(path);
            Ok((
                name.to_owned(),
                AcceptanceArtifact {
                    path: path.to_owned(),
                    manifest_sha256: sha256_file(&manifest)?,
                },
            ))
        })
        .collect()
}
