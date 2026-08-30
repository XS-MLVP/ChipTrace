use crate::buyer::{BUYER_PACKAGE_SCHEMA_VERSION, BuyerPackageManifest, verify_buyer_package};
use crate::jsonl::{sha256_bytes, sha256_file, utc_now};
#[cfg(test)]
use crate::object_store::write_immutable_bytes;
use crate::object_store::{
    LocalObject, ObjectStoreConfig, build_operator, ensure_local_objects, join_key,
    normalize_prefix, object_entries, remote_sha256, validate_component, validate_key,
};
use crate::release::verify_release;
use crate::schema::{
    OBJECT_COMMIT_SCHEMA_VERSION, ObjectCommit, ObjectEntry, RELEASE_SCHEMA_VERSION,
    ReleaseManifest,
};
use anyhow::{Context, Result, bail};
use futures_util::stream::{self, StreamExt, TryStreamExt};
use opendal::{ErrorKind, Operator};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use crate::object_store::Backend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Release,
    BuyerPackage,
}

impl ArtifactKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::BuyerPackage => "buyer_package",
        }
    }

    fn object_namespace(self) -> &'static str {
        match self {
            Self::Release => "releases",
            Self::BuyerPackage => "deliveries",
        }
    }
}

#[derive(Debug, Clone)]
pub enum PublishSource {
    Release(PathBuf),
    BuyerPackage(PathBuf),
}

impl PublishSource {
    fn kind(&self) -> ArtifactKind {
        match self {
            Self::Release(_) => ArtifactKind::Release,
            Self::BuyerPackage(_) => ArtifactKind::BuyerPackage,
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::Release(path) | Self::BuyerPackage(path) => path,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PublishConfig {
    pub source: PublishSource,
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
    pub verify_remote_sha256: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyPublishedConfig {
    pub artifact_kind: ArtifactKind,
    pub artifact_id: String,
    pub backend: Backend,
    pub root: Option<PathBuf>,
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub prefix: String,
    pub file_concurrency: usize,
    pub retry_max_times: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResult {
    pub ok: bool,
    pub idempotent: bool,
    pub backend: String,
    pub artifact_kind: String,
    pub artifact_id: String,
    pub manifest_sha256: String,
    pub commit_key: String,
    pub objects: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyPublishedResult {
    pub ok: bool,
    pub backend: String,
    pub artifact_kind: String,
    pub artifact_id: String,
    pub manifest_sha256: String,
    pub commit_key: String,
    pub objects: u64,
    pub bytes: u64,
}

struct VerifiedArtifact {
    kind: ArtifactKind,
    id: String,
    root: PathBuf,
    manifest_sha256: String,
    source_release_manifest_sha256: Option<String>,
    files: Vec<String>,
}

fn object_store_config(config: &PublishConfig) -> ObjectStoreConfig {
    ObjectStoreConfig {
        backend: config.backend,
        root: config.root.clone(),
        endpoint: config.endpoint.clone(),
        bucket: config.bucket.clone(),
        region: config.region.clone(),
        prefix: config.prefix.clone(),
        file_concurrency: config.file_concurrency,
        multipart_concurrency: config.multipart_concurrency,
        multipart_chunk_bytes: config.multipart_chunk_bytes,
        retry_max_times: config.retry_max_times,
        verify_remote_sha256: config.verify_remote_sha256,
    }
}

pub async fn publish(config: PublishConfig) -> Result<PublishResult> {
    let object_store = object_store_config(&config);
    object_store.validate()?;
    if config.source.kind() == ArtifactKind::BuyerPackage && !config.verify_remote_sha256 {
        bail!("buyer package publication requires remote SHA-256 verification");
    }
    let artifact = verify_local_artifact(&config.source)?;
    validate_component("artifact_id", &artifact.id)?;
    let prefix = normalize_prefix(&config.prefix)?;
    let staging_base = join_key(
        &prefix,
        &format!(
            ".staging/{}/{}/{}",
            artifact.kind.object_namespace(),
            artifact.id,
            artifact.manifest_sha256
        ),
    );
    let commit_key = join_key(
        &prefix,
        &format!(
            "{}/{}/COMMIT.json",
            artifact.kind.object_namespace(),
            artifact.id
        ),
    );
    let operator = Arc::new(build_operator(&object_store)?);
    let local_files = artifact_files(&artifact, &staging_base)?;
    let expected_objects = object_entries(&local_files);
    let manifest_key = join_key(&staging_base, "manifest.json");
    if let Some(existing) = read_existing_commit(&operator, &commit_key).await? {
        validate_commit(&existing, &artifact, &manifest_key, &expected_objects)?;
        ensure_local_objects(&operator, local_files, &object_store).await?;
        return Ok(PublishResult {
            ok: true,
            idempotent: true,
            backend: config.backend.scheme().to_owned(),
            artifact_kind: artifact.kind.as_str().to_owned(),
            artifact_id: artifact.id,
            manifest_sha256: artifact.manifest_sha256,
            commit_key,
            objects: existing.objects.len() as u64,
            bytes: existing.objects.iter().map(|object| object.bytes).sum(),
        });
    }

    let objects = ensure_local_objects(&operator, local_files, &object_store).await?;
    let commit = ObjectCommit {
        schema_version: OBJECT_COMMIT_SCHEMA_VERSION.to_owned(),
        artifact_kind: artifact.kind.as_str().to_owned(),
        artifact_id: artifact.id.clone(),
        committed_at_utc: utc_now(),
        manifest_sha256: artifact.manifest_sha256.clone(),
        manifest_key: manifest_key.clone(),
        source_release_manifest_sha256: artifact.source_release_manifest_sha256.clone(),
        objects: objects.clone(),
    };
    let commit_bytes = serde_json::to_vec_pretty(&commit)?;
    let commit_created = write_commit(&operator, &commit_key, commit_bytes, &commit).await?;
    let committed: ObjectCommit =
        serde_json::from_slice(&operator.read(&commit_key).await?.to_vec())?;
    validate_commit(&committed, &artifact, &manifest_key, &objects)?;
    Ok(PublishResult {
        ok: true,
        idempotent: !commit_created,
        backend: config.backend.scheme().to_owned(),
        artifact_kind: artifact.kind.as_str().to_owned(),
        artifact_id: artifact.id,
        manifest_sha256: artifact.manifest_sha256,
        commit_key,
        objects: objects.len() as u64,
        bytes: objects.iter().map(|object| object.bytes).sum(),
    })
}

pub async fn verify_published(config: VerifyPublishedConfig) -> Result<VerifyPublishedResult> {
    validate_component("artifact_id", &config.artifact_id)?;
    if config.file_concurrency == 0 || config.retry_max_times == 0 {
        bail!("object-store concurrency and retries must be positive");
    }
    let object_store = ObjectStoreConfig {
        backend: config.backend,
        root: config.root,
        endpoint: config.endpoint,
        bucket: config.bucket,
        region: config.region,
        prefix: config.prefix.clone(),
        file_concurrency: config.file_concurrency,
        multipart_concurrency: 1,
        multipart_chunk_bytes: 5 * 1024 * 1024,
        retry_max_times: config.retry_max_times,
        verify_remote_sha256: true,
    };
    let operator = Arc::new(build_operator(&object_store)?);
    let prefix = normalize_prefix(&config.prefix)?;
    let commit_key = join_key(
        &prefix,
        &format!(
            "{}/{}/COMMIT.json",
            config.artifact_kind.object_namespace(),
            config.artifact_id
        ),
    );
    let commit = read_existing_commit(&operator, &commit_key)
        .await?
        .with_context(|| format!("published COMMIT does not exist: {commit_key}"))?;
    validate_committed_artifact(
        &operator,
        &commit,
        config.artifact_kind,
        &config.artifact_id,
        &prefix,
    )
    .await?;
    let operator_for_objects = Arc::clone(&operator);
    stream::iter(commit.objects.iter().map(move |object| {
        let operator = Arc::clone(&operator_for_objects);
        async move {
            validate_key(&object.key)?;
            let metadata = operator.stat(&object.key).await?;
            if metadata.content_length() != object.bytes
                || remote_sha256(&operator, &object.key).await? != object.sha256
            {
                bail!("published object verification failed: {}", object.key);
            }
            Ok::<(), anyhow::Error>(())
        }
    }))
    .buffer_unordered(config.file_concurrency)
    .try_collect::<Vec<_>>()
    .await?;
    Ok(VerifyPublishedResult {
        ok: true,
        backend: config.backend.scheme().to_owned(),
        artifact_kind: commit.artifact_kind,
        artifact_id: commit.artifact_id,
        manifest_sha256: commit.manifest_sha256,
        commit_key,
        objects: commit.objects.len() as u64,
        bytes: commit.objects.iter().map(|object| object.bytes).sum(),
    })
}

fn validate_commit(
    commit: &ObjectCommit,
    artifact: &VerifiedArtifact,
    manifest_key: &str,
    objects: &[ObjectEntry],
) -> Result<()> {
    if commit.schema_version != OBJECT_COMMIT_SCHEMA_VERSION
        || commit.artifact_kind != artifact.kind.as_str()
        || commit.artifact_id != artifact.id
        || commit.manifest_sha256 != artifact.manifest_sha256
        || commit.manifest_key != manifest_key
        || commit.source_release_manifest_sha256 != artifact.source_release_manifest_sha256
        || commit.objects != objects
    {
        bail!(
            "artifact ID {} is already committed with conflicting metadata",
            artifact.id
        );
    }
    Ok(())
}

fn verify_local_artifact(source: &PublishSource) -> Result<VerifiedArtifact> {
    let root = source.path().canonicalize()?;
    let kind = source.kind();
    let (id, source_release_manifest_sha256, mut files) = match source {
        PublishSource::Release(_) => {
            let manifest = verify_release(&root, true)?;
            let mut files = manifest
                .parts
                .iter()
                .chain(&manifest.reports)
                .map(|file| file.file.clone())
                .collect::<Vec<_>>();
            files.extend(["manifest.json".to_owned(), "SHA256SUMS".to_owned()]);
            (manifest.release_id, None, files)
        }
        PublishSource::BuyerPackage(_) => {
            let manifest = verify_buyer_package(&root)?;
            let mut files = manifest
                .packages
                .iter()
                .map(|file| file.file.clone())
                .collect::<Vec<_>>();
            files.extend(["manifest.json".to_owned(), "SHA256SUMS".to_owned()]);
            (
                manifest.release_id,
                Some(manifest.source_release_manifest_sha256),
                files,
            )
        }
    };
    files.sort();
    files.dedup();
    Ok(VerifiedArtifact {
        kind,
        id,
        manifest_sha256: sha256_file(&root.join("manifest.json"))?,
        source_release_manifest_sha256,
        root,
        files,
    })
}

fn artifact_files(artifact: &VerifiedArtifact, staging_base: &str) -> Result<Vec<LocalObject>> {
    artifact
        .files
        .iter()
        .map(|name| {
            let path = artifact.root.join(name);
            Ok(LocalObject {
                key: join_key(staging_base, name),
                sha256: sha256_file(&path)?,
                bytes: path.metadata()?.len(),
                path,
            })
        })
        .collect()
}

async fn validate_committed_artifact(
    operator: &Operator,
    commit: &ObjectCommit,
    kind: ArtifactKind,
    artifact_id: &str,
    prefix: &str,
) -> Result<()> {
    validate_key(&commit.manifest_key)?;
    let expected_manifest_key = join_key(
        prefix,
        &format!(
            ".staging/{}/{}/{}/manifest.json",
            kind.object_namespace(),
            artifact_id,
            commit.manifest_sha256
        ),
    );
    if commit.schema_version != OBJECT_COMMIT_SCHEMA_VERSION
        || commit.artifact_kind != kind.as_str()
        || commit.artifact_id != artifact_id
        || commit.manifest_key != expected_manifest_key
        || commit.objects.is_empty()
        || !is_sha256(&commit.manifest_sha256)
    {
        bail!("published COMMIT metadata is invalid");
    }
    let mut previous_key = None;
    for object in &commit.objects {
        validate_key(&object.key)?;
        if !is_sha256(&object.sha256)
            || previous_key.is_some_and(|previous: &str| previous >= object.key.as_str())
        {
            bail!("published COMMIT contains invalid or unsorted objects");
        }
        previous_key = Some(object.key.as_str());
    }
    let manifest_bytes = operator.read(&commit.manifest_key).await?.to_vec();
    if sha256_bytes(&manifest_bytes) != commit.manifest_sha256 {
        bail!("published manifest SHA-256 does not match COMMIT");
    }
    let mut names = vec!["manifest.json".to_owned(), "SHA256SUMS".to_owned()];
    let source_release_manifest_sha256 = match kind {
        ArtifactKind::Release => {
            let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)?;
            if manifest.schema_version != RELEASE_SCHEMA_VERSION
                || manifest.release_id != artifact_id
                || manifest.validation_status != "pass"
            {
                bail!("published Release manifest is not passing or has the wrong ID");
            }
            names.extend(manifest.parts.into_iter().map(|file| file.file));
            names.extend(manifest.reports.into_iter().map(|file| file.file));
            None
        }
        ArtifactKind::BuyerPackage => {
            let manifest: BuyerPackageManifest = serde_json::from_slice(&manifest_bytes)?;
            if manifest.schema_version != BUYER_PACKAGE_SCHEMA_VERSION
                || manifest.release_id != artifact_id
                || manifest.validation_status != "pass"
                || manifest.lineage_status != "complete"
                || manifest.buyer_profile != "buyer-v7"
                || manifest.minimum_score < 90.0
            {
                bail!("published buyer package manifest is not an accepted delivery");
            }
            names.extend(manifest.packages.into_iter().map(|file| file.file));
            Some(manifest.source_release_manifest_sha256)
        }
    };
    if commit.source_release_manifest_sha256 != source_release_manifest_sha256 {
        bail!("published COMMIT lineage does not match its manifest");
    }
    let base = commit
        .manifest_key
        .strip_suffix("/manifest.json")
        .context("published manifest key has an invalid suffix")?;
    names.sort();
    names.dedup();
    let expected = names
        .into_iter()
        .map(|name| join_key(base, &name))
        .collect::<HashSet<_>>();
    let actual = commit
        .objects
        .iter()
        .map(|object| object.key.clone())
        .collect::<HashSet<_>>();
    if expected != actual || actual.len() != commit.objects.len() {
        bail!("published COMMIT object set does not match its manifest");
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn write_commit(
    operator: &Operator,
    key: &str,
    bytes: Vec<u8>,
    expected: &ObjectCommit,
) -> Result<bool> {
    match operator.write_with(key, bytes).if_not_exists(true).await {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::AlreadyExists | ErrorKind::ConditionNotMatch
            ) =>
        {
            let existing: ObjectCommit =
                serde_json::from_slice(&operator.read(key).await?.to_vec())?;
            if existing.schema_version != expected.schema_version
                || existing.artifact_kind != expected.artifact_kind
                || existing.artifact_id != expected.artifact_id
                || existing.manifest_sha256 != expected.manifest_sha256
                || existing.manifest_key != expected.manifest_key
                || existing.source_release_manifest_sha256
                    != expected.source_release_manifest_sha256
                || existing.objects != expected.objects
            {
                bail!("immutable COMMIT conflict at {key}");
            }
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

async fn read_existing_commit(operator: &Operator, key: &str) -> Result<Option<ObjectCommit>> {
    match operator.read(key).await {
        Ok(value) => Ok(Some(
            serde_json::from_slice(&value.to_vec())
                .with_context(|| format!("parse existing commit {key}"))?,
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ReleaseCounts, ReleaseManifest};
    use crate::score::{Profile, assess_session, exact_content_fingerprint};
    use std::collections::BTreeMap;
    use std::fs;

    #[tokio::test]
    async fn filesystem_publish_commits_last_and_is_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let release = temporary.path().join("release");
        let object_root = temporary.path().join("objects");
        fs::create_dir_all(&release).unwrap();
        fs::create_dir_all(&object_root).unwrap();
        let mut session = serde_json::json!({
            "schema_version": "chiptrace.session.v1",
            "trajectory_id": "publish-fixture",
            "session_id": "publish-fixture",
            "provider": "OpenAI",
            "model": "gpt-5.6-sol",
            "created_at": "2026-08-27T00:00:00Z",
            "ended_at": "2026-08-27T00:01:00Z",
            "status": "completed",
            "is_final_snapshot": true,
            "source_request_count": 1,
            "system_prompt": "You are a coding agent.",
            "tools": [{
                "name": "run_test",
                "description": "Run a focused test.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Test target."}
                    }
                }
            }],
            "messages": [
                {"role": "system", "content": "You are a coding agent."},
                {"role": "user", "content": "Run the focused test in /workspace/repo."},
                {"role": "assistant", "content": "Running it.", "tool_calls": [{
                    "id": "call-1", "name": "run_test", "arguments": {"target": "unit"}
                }]},
                {"role": "tool", "tool_call_id": "call-1", "content": "passed", "status": "success"},
                {"role": "assistant", "content": "The focused test passed."},
                {"role": "user", "content": "Now summarize the result and the changed files."},
                {"role": "assistant", "content": "The test passed and no files were changed."}
            ],
            "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
            "meta": {
                "merge_divergences": 0,
                "schema_conflicts": [],
                "trace_conflicts": [],
                "system_prompt_conflicts": [],
                "capture_dag": {
                    "has_cycle": false,
                    "unresolved_parent_response_ids": [],
                    "unresolved_parent_span_ids": []
                },
                "task_dag": {"complete": true},
                "task_type": "code",
                "model_evidence": {
                    "request_models": ["gpt-5.6-sol"],
                    "response_models": ["gpt-5.6-sol"],
                    "providers": ["OpenAI"],
                    "attested": true
                }
            }
        });
        let quality = assess_session(&session, Profile::BuyerV6, 90.0);
        assert!(quality.buyer_acceptance.eligible);
        let eligible_tokens = quality.buyer_acceptance.tokens.clone();
        session["quality"] = serde_json::to_value(&quality).unwrap();
        let mut data_line = serde_json::to_vec(&session).unwrap();
        data_line.push(b'\n');
        fs::write(
            release.join("data.jsonl.zst"),
            zstd::encode_all(&data_line[..], 1).unwrap(),
        )
        .unwrap();
        let part = crate::schema::FileManifest {
            file: "data.jsonl.zst".to_owned(),
            sha256: sha256_file(&release.join("data.jsonl.zst")).unwrap(),
            bytes: release.join("data.jsonl.zst").metadata().unwrap().len(),
            records: Some(1),
            uncompressed_bytes: Some(data_line.len() as u64),
            oversized_session: Some(false),
        };
        fs::create_dir_all(release.join("reports")).unwrap();
        let assessment = serde_json::json!({
            "trajectory_id": session.get("trajectory_id"),
            "session_id": session.get("session_id"),
            "provider": session.get("provider"),
            "model": session.get("model"),
            "quality": quality,
            "release_decision": "eligible",
            "content_fingerprint": exact_content_fingerprint(&session),
        });
        let mut assessment_line = serde_json::to_vec(&assessment).unwrap();
        assessment_line.push(b'\n');
        let report_path = release.join("reports/assessments-part-00000.jsonl.zst");
        fs::write(
            &report_path,
            zstd::encode_all(&assessment_line[..], 1).unwrap(),
        )
        .unwrap();
        let report = crate::schema::FileManifest {
            file: "reports/assessments-part-00000.jsonl.zst".to_owned(),
            sha256: sha256_file(&report_path).unwrap(),
            bytes: report_path.metadata().unwrap().len(),
            records: Some(1),
            uncompressed_bytes: Some(assessment_line.len() as u64),
            oversized_session: None,
        };
        let manifest = ReleaseManifest {
            schema_version: crate::schema::RELEASE_SCHEMA_VERSION.to_owned(),
            release_id: "release-one".to_owned(),
            created_at_utc: utc_now(),
            format: "test".to_owned(),
            session_atomic: true,
            session_split_count: 0,
            buyer_profile: "buyer-v6".to_owned(),
            minimum_score: 90.0,
            tokenizer: "test".to_owned(),
            compression: "zstd-1".to_owned(),
            processing_workers: 1,
            target_part_bytes: 100,
            raw_sources: vec![],
            counts: ReleaseCounts {
                input_records: 1,
                assessed_sessions: 1,
                eligible_sessions: 1,
                ..ReleaseCounts::default()
            },
            eligible_tokens: eligible_tokens.clone(),
            assessed_tokens: eligible_tokens,
            failure_reason_counts: BTreeMap::new(),
            parts: vec![part],
            reports: vec![report],
            validation_status: "pass".to_owned(),
        };
        fs::write(
            release.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let mut sums = String::new();
        sums.push_str(&format!(
            "{}  manifest.json\n",
            sha256_file(&release.join("manifest.json")).unwrap()
        ));
        sums.push_str(&format!(
            "{}  data.jsonl.zst\n",
            sha256_file(&release.join("data.jsonl.zst")).unwrap()
        ));
        sums.push_str(&format!(
            "{}  reports/assessments-part-00000.jsonl.zst\n",
            sha256_file(&report_path).unwrap()
        ));
        fs::write(release.join("SHA256SUMS"), sums).unwrap();
        let config = PublishConfig {
            source: PublishSource::Release(release.clone()),
            backend: Backend::Fs,
            root: Some(object_root.clone()),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            file_concurrency: 4,
            multipart_concurrency: 2,
            multipart_chunk_bytes: 5 * 1024 * 1024,
            retry_max_times: 25,
            verify_remote_sha256: true,
        };
        let first = publish(config.clone()).await.unwrap();
        assert!(!first.idempotent);
        assert_eq!(first.objects, 4);
        assert!(object_root.join(&first.commit_key).is_file());
        let committed: ObjectCommit =
            serde_json::from_slice(&fs::read(object_root.join(&first.commit_key)).unwrap())
                .unwrap();
        let missing_key = committed
            .objects
            .iter()
            .find(|object| object.key.ends_with("data.jsonl.zst"))
            .unwrap()
            .key
            .clone();
        fs::remove_file(object_root.join(&missing_key)).unwrap();
        let second = publish(config).await.unwrap();
        assert!(second.idempotent);
        assert!(object_root.join(missing_key).is_file());
        assert_eq!(second.manifest_sha256, first.manifest_sha256);

        let verified = verify_published(VerifyPublishedConfig {
            artifact_kind: ArtifactKind::Release,
            artifact_id: "release-one".to_owned(),
            backend: Backend::Fs,
            root: Some(object_root.clone()),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            file_concurrency: 4,
            retry_max_times: 25,
        })
        .await
        .unwrap();
        assert!(verified.ok);
        assert_eq!(verified.objects, first.objects);

        let operator = Operator::via_iter(
            opendal::services::FS_SCHEME,
            [(
                "root".to_owned(),
                object_root.to_string_lossy().into_owned(),
            )],
        )
        .unwrap();
        write_immutable_bytes(&operator, "x/COMMIT.json", b"one".to_vec())
            .await
            .unwrap();
        write_immutable_bytes(&operator, "x/COMMIT.json", b"one".to_vec())
            .await
            .unwrap();
        assert!(
            write_immutable_bytes(&operator, "x/COMMIT.json", b"two".to_vec())
                .await
                .is_err()
        );
    }
}
