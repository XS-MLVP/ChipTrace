#[cfg(test)]
use crate::jsonl::sha256_bytes;
use crate::jsonl::{sha256_file, utc_now};
use crate::release::verify_release;
use crate::schema::{COMMIT_SCHEMA_VERSION, ObjectCommit, ObjectEntry};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures_util::io::AsyncReadExt as FuturesAsyncReadExt;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use opendal::layers::RetryLayer;
use opendal::{ErrorKind, Operator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
    Fs,
    Oss,
    S3,
}

impl Backend {
    fn scheme(self) -> &'static str {
        match self {
            Self::Fs => opendal::services::FS_SCHEME,
            Self::Oss => opendal::services::OSS_SCHEME,
            Self::S3 => opendal::services::S3_SCHEME,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PublishConfig {
    pub release: PathBuf,
    pub backend: Backend,
    pub root: Option<PathBuf>,
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub prefix: String,
    pub file_concurrency: usize,
    pub multipart_concurrency: usize,
    pub multipart_chunk_bytes: usize,
    pub verify_remote_sha256: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResult {
    pub ok: bool,
    pub idempotent: bool,
    pub backend: String,
    pub release_id: String,
    pub release_manifest_sha256: String,
    pub commit_key: String,
    pub objects: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
struct LocalObject {
    path: PathBuf,
    key: String,
    sha256: String,
    bytes: u64,
}

pub async fn publish(config: PublishConfig) -> Result<PublishResult> {
    if config.file_concurrency == 0
        || config.multipart_concurrency == 0
        || config.multipart_chunk_bytes < 5 * 1024 * 1024
    {
        bail!("upload concurrency must be positive and multipart chunks must be >= 5 MiB");
    }
    let release = config.release.canonicalize()?;
    let manifest = verify_release(&release, true)?;
    validate_component(&manifest.release_id)?;
    let manifest_sha256 = sha256_file(&release.join("manifest.json"))?;
    let prefix = normalize_prefix(&config.prefix)?;
    let staging_base = join_key(
        &prefix,
        &format!(".staging/{}/{}", manifest.release_id, manifest_sha256),
    );
    let commit_key = join_key(
        &prefix,
        &format!("releases/{}/COMMIT.json", manifest.release_id),
    );
    let operator = Arc::new(build_operator(&config)?);
    let local_files = release_files(&release, &manifest, &staging_base)?;
    let expected_objects = object_entries(&local_files);
    let manifest_key = join_key(&staging_base, "manifest.json");
    if let Some(existing) = read_existing_commit(&operator, &commit_key).await? {
        validate_commit(
            &existing,
            &manifest.release_id,
            &manifest_sha256,
            &manifest_key,
            &expected_objects,
        )?;
        ensure_local_objects(&operator, local_files, &config).await?;
        return Ok(PublishResult {
            ok: true,
            idempotent: true,
            backend: config.backend.scheme().to_owned(),
            release_id: manifest.release_id,
            release_manifest_sha256: manifest_sha256,
            commit_key,
            objects: existing.objects.len() as u64,
            bytes: existing.objects.iter().map(|object| object.bytes).sum(),
        });
    }

    let objects = ensure_local_objects(&operator, local_files, &config).await?;
    let commit = ObjectCommit {
        schema_version: COMMIT_SCHEMA_VERSION.to_owned(),
        release_id: manifest.release_id.clone(),
        committed_at_utc: utc_now(),
        release_manifest_sha256: manifest_sha256.clone(),
        release_manifest_key: manifest_key.clone(),
        objects: objects.clone(),
    };
    let commit_bytes = serde_json::to_vec_pretty(&commit)?;
    let commit_created = write_commit(&operator, &commit_key, commit_bytes, &commit).await?;
    let committed: ObjectCommit =
        serde_json::from_slice(&operator.read(&commit_key).await?.to_vec())?;
    validate_commit(
        &committed,
        &manifest.release_id,
        &manifest_sha256,
        &manifest_key,
        &objects,
    )?;
    Ok(PublishResult {
        ok: true,
        idempotent: !commit_created,
        backend: config.backend.scheme().to_owned(),
        release_id: manifest.release_id,
        release_manifest_sha256: manifest_sha256,
        commit_key,
        objects: objects.len() as u64,
        bytes: objects.iter().map(|object| object.bytes).sum(),
    })
}

async fn ensure_local_objects(
    operator: &Arc<Operator>,
    local_files: Vec<LocalObject>,
    config: &PublishConfig,
) -> Result<Vec<ObjectEntry>> {
    let objects: Vec<ObjectEntry> = stream::iter(local_files.into_iter().map(|local| {
        let operator = Arc::clone(operator);
        let config = config.clone();
        async move {
            ensure_object(
                &operator,
                &local,
                config.multipart_chunk_bytes,
                config.multipart_concurrency,
                config.verify_remote_sha256,
            )
            .await?;
            Ok::<ObjectEntry, anyhow::Error>(ObjectEntry {
                key: local.key,
                sha256: local.sha256,
                bytes: local.bytes,
            })
        }
    }))
    .buffer_unordered(config.file_concurrency)
    .try_collect()
    .await?;
    let mut objects = objects;
    objects.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(objects)
}

fn object_entries(local_files: &[LocalObject]) -> Vec<ObjectEntry> {
    let mut objects: Vec<ObjectEntry> = local_files
        .iter()
        .map(|local| ObjectEntry {
            key: local.key.clone(),
            sha256: local.sha256.clone(),
            bytes: local.bytes,
        })
        .collect();
    objects.sort_by(|left, right| left.key.cmp(&right.key));
    objects
}

fn validate_commit(
    commit: &ObjectCommit,
    release_id: &str,
    manifest_sha256: &str,
    manifest_key: &str,
    objects: &[ObjectEntry],
) -> Result<()> {
    if commit.schema_version != COMMIT_SCHEMA_VERSION
        || commit.release_id != release_id
        || commit.release_manifest_sha256 != manifest_sha256
        || commit.release_manifest_key != manifest_key
        || commit.objects != objects
    {
        bail!("release ID {release_id} is already committed with conflicting metadata");
    }
    Ok(())
}

fn build_operator(config: &PublishConfig) -> Result<Operator> {
    let mut options = BTreeMap::new();
    match config.backend {
        Backend::Fs => {
            let root = config
                .root
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--root is required for fs backend"))?;
            options.insert("root".to_owned(), root.to_string_lossy().into_owned());
            options.insert(
                "atomic_write_dir".to_owned(),
                root.join(".chiptrace-tmp").to_string_lossy().into_owned(),
            );
        }
        Backend::Oss => {
            options.insert(
                "bucket".to_owned(),
                config
                    .bucket
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("--bucket is required for oss backend"))?,
            );
            options.insert(
                "endpoint".to_owned(),
                config
                    .endpoint
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("--endpoint is required for oss backend"))?,
            );
        }
        Backend::S3 => {
            options.insert(
                "bucket".to_owned(),
                config
                    .bucket
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("--bucket is required for s3 backend"))?,
            );
            if let Some(endpoint) = &config.endpoint {
                options.insert("endpoint".to_owned(), endpoint.clone());
            }
            if let Some(region) = &config.region {
                options.insert("region".to_owned(), region.clone());
            }
        }
    }
    Operator::via_iter(config.backend.scheme(), options)
        .map(|operator| operator.layer(RetryLayer::default()))
        .context("build object-store operator")
}

fn release_files(
    root: &Path,
    manifest: &crate::schema::ReleaseManifest,
    staging_base: &str,
) -> Result<Vec<LocalObject>> {
    let mut names = vec!["manifest.json".to_owned(), "SHA256SUMS".to_owned()];
    names.extend(manifest.parts.iter().map(|file| file.file.clone()));
    names.extend(manifest.reports.iter().map(|file| file.file.clone()));
    names.sort();
    names.dedup();
    names
        .into_iter()
        .map(|name| {
            let path = root.join(&name);
            Ok(LocalObject {
                key: join_key(staging_base, &name),
                sha256: sha256_file(&path)?,
                bytes: path.metadata()?.len(),
                path,
            })
        })
        .collect()
}

async fn ensure_object(
    operator: &Operator,
    object: &LocalObject,
    chunk_bytes: usize,
    multipart_concurrency: usize,
    verify_sha256: bool,
) -> Result<()> {
    match operator.stat(&object.key).await {
        Ok(metadata) => {
            verify_remote_object(operator, object, metadata.content_length(), verify_sha256)
                .await?;
            return Ok(());
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut writer = match operator
        .writer_with(&object.key)
        .chunk(chunk_bytes)
        .concurrent(multipart_concurrency)
        .if_not_exists(true)
        .await
    {
        Ok(writer) => writer,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::AlreadyExists | ErrorKind::ConditionNotMatch
            ) =>
        {
            let metadata = operator.stat(&object.key).await?;
            verify_remote_object(operator, object, metadata.content_length(), verify_sha256)
                .await?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let mut file = tokio::fs::File::open(&object.path).await?;
    let mut buffer = vec![0_u8; chunk_bytes];
    loop {
        let count = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
        if count == 0 {
            break;
        }
        writer
            .write(Bytes::copy_from_slice(&buffer[..count]))
            .await?;
    }
    writer.close().await?;
    let metadata = operator.stat(&object.key).await?;
    verify_remote_object(operator, object, metadata.content_length(), verify_sha256).await
}

async fn verify_remote_object(
    operator: &Operator,
    object: &LocalObject,
    remote_bytes: u64,
    verify_sha256: bool,
) -> Result<()> {
    if remote_bytes != object.bytes {
        bail!(
            "remote object size mismatch for {}: local={}, remote={}",
            object.key,
            object.bytes,
            remote_bytes
        );
    }
    if verify_sha256 {
        let mut remote = operator
            .reader(&object.key)
            .await?
            .into_futures_async_read(..)
            .await?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 8 * 1024 * 1024];
        loop {
            let count = FuturesAsyncReadExt::read(&mut remote, &mut buffer).await?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let digest = hex::encode(hasher.finalize());
        if digest != object.sha256 {
            bail!("remote object SHA-256 mismatch for {}", object.key);
        }
    }
    Ok(())
}

#[cfg(test)]
async fn write_immutable_bytes(operator: &Operator, key: &str, bytes: Vec<u8>) -> Result<()> {
    match operator
        .write_with(key, bytes.clone())
        .if_not_exists(true)
        .await
    {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::AlreadyExists | ErrorKind::ConditionNotMatch
            ) =>
        {
            let existing = operator.read(key).await?.to_vec();
            if sha256_bytes(&existing) != sha256_bytes(&bytes) {
                bail!("immutable object conflict at {key}");
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
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
            validate_commit(
                &existing,
                &expected.release_id,
                &expected.release_manifest_sha256,
                &expected.release_manifest_key,
                &expected.objects,
            )?;
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

fn normalize_prefix(value: &str) -> Result<String> {
    let value = value.trim_matches('/');
    if value.split('/').any(|component| component == "..") {
        bail!("object prefix cannot contain '..'");
    }
    Ok(value.to_owned())
}

fn join_key(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        suffix.trim_start_matches('/').to_owned()
    } else {
        format!(
            "{}/{}",
            prefix.trim_matches('/'),
            suffix.trim_start_matches('/')
        )
    }
}

fn validate_component(value: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
    {
        bail!("release_id must be a single safe object-key component");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ReleaseCounts, ReleaseManifest, TokenCounts};
    use std::fs;

    #[tokio::test]
    async fn filesystem_publish_commits_last_and_is_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let release = temporary.path().join("release");
        let object_root = temporary.path().join("objects");
        fs::create_dir_all(&release).unwrap();
        fs::create_dir_all(&object_root).unwrap();
        let data_line = b"{\"quality\":{\"buyer_acceptance\":{\"eligible\":true}}}\n";
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
            counts: ReleaseCounts {
                eligible_sessions: 1,
                ..ReleaseCounts::default()
            },
            eligible_tokens: TokenCounts::default(),
            assessed_tokens: TokenCounts::default(),
            failure_reason_counts: BTreeMap::new(),
            parts: vec![part],
            reports: vec![],
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
        fs::write(release.join("SHA256SUMS"), sums).unwrap();
        let config = PublishConfig {
            release: release.clone(),
            backend: Backend::Fs,
            root: Some(object_root.clone()),
            endpoint: None,
            bucket: None,
            region: None,
            prefix: "datasets/chiptrace".to_owned(),
            file_concurrency: 4,
            multipart_concurrency: 2,
            multipart_chunk_bytes: 5 * 1024 * 1024,
            verify_remote_sha256: true,
        };
        let first = publish(config.clone()).await.unwrap();
        assert!(!first.idempotent);
        assert_eq!(first.objects, 3);
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
        assert_eq!(
            second.release_manifest_sha256,
            first.release_manifest_sha256
        );

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
