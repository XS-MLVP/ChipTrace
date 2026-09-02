use crate::jsonl::sha256_bytes;
use crate::schema::ObjectEntry;
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures_util::io::AsyncReadExt as FuturesAsyncReadExt;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use opendal::layers::RetryLayer;
use opendal::{ErrorKind, Operator};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
    Fs,
    Oss,
    S3,
}

impl Backend {
    pub fn scheme(self) -> &'static str {
        match self {
            Self::Fs => opendal::services::FS_SCHEME,
            Self::Oss => opendal::services::OSS_SCHEME,
            Self::S3 => opendal::services::S3_SCHEME,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObjectStoreConfig {
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
pub(crate) struct LocalObject {
    pub path: PathBuf,
    pub key: String,
    pub sha256: String,
    pub bytes: u64,
}

impl ObjectStoreConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.file_concurrency == 0
            || self.multipart_concurrency == 0
            || self.multipart_chunk_bytes < 5 * 1024 * 1024
            || self.retry_max_times == 0
        {
            bail!(
                "object-store concurrency and retries must be positive and multipart chunks must be >= 5 MiB"
            );
        }
        normalize_prefix(&self.prefix)?;
        Ok(())
    }
}

pub(crate) fn build_operator(config: &ObjectStoreConfig) -> Result<Operator> {
    config.validate()?;
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
    let retry = RetryLayer::new()
        .with_jitter()
        .with_factor(2.0)
        .with_min_delay(Duration::from_millis(250))
        .with_max_delay(Duration::from_secs(30))
        .with_max_times(config.retry_max_times);
    Operator::via_iter(config.backend.scheme(), options)
        .map(|operator| operator.layer(retry))
        .context("build object-store operator")
}

pub(crate) async fn ensure_local_objects(
    operator: &Arc<Operator>,
    local_files: Vec<LocalObject>,
    config: &ObjectStoreConfig,
) -> Result<Vec<ObjectEntry>> {
    let objects: Vec<ObjectEntry> = stream::iter(local_files.into_iter().map(|local| {
        let operator = Arc::clone(operator);
        let config = config.clone();
        async move {
            ensure_object(&operator, &local, &config).await?;
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

pub(crate) fn object_entries(local_files: &[LocalObject]) -> Vec<ObjectEntry> {
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

pub(crate) async fn ensure_object(
    operator: &Operator,
    object: &LocalObject,
    config: &ObjectStoreConfig,
) -> Result<()> {
    match operator.stat(&object.key).await {
        Ok(metadata) => {
            verify_remote_object(
                operator,
                &object.key,
                object.bytes,
                &object.sha256,
                metadata.content_length(),
                config.verify_remote_sha256,
            )
            .await?;
            return Ok(());
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut writer = match operator
        .writer_with(&object.key)
        .chunk(config.multipart_chunk_bytes)
        .concurrent(config.multipart_concurrency)
        .if_not_exists(true)
        .await
    {
        Ok(writer) => writer,
        Err(error) if is_immutable_write_conflict(&error) => {
            return verify_existing_local_object(operator, object, config).await;
        }
        Err(error) => return Err(error.into()),
    };
    let mut file = tokio::fs::File::open(&object.path).await?;
    let mut buffer = vec![0_u8; config.multipart_chunk_bytes];
    loop {
        let count = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
        if count == 0 {
            break;
        }
        if let Err(error) = writer.write(Bytes::copy_from_slice(&buffer[..count])).await {
            if is_immutable_write_conflict(&error) {
                return verify_existing_local_object(operator, object, config).await;
            }
            return Err(error.into());
        }
    }
    if let Err(error) = writer.close().await {
        if is_immutable_write_conflict(&error) {
            return verify_existing_local_object(operator, object, config).await;
        }
        return Err(error.into());
    }
    let metadata = operator.stat(&object.key).await?;
    verify_remote_object(
        operator,
        &object.key,
        object.bytes,
        &object.sha256,
        metadata.content_length(),
        config.verify_remote_sha256,
    )
    .await
}

fn is_immutable_write_conflict(error: &opendal::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::AlreadyExists | ErrorKind::ConditionNotMatch
    )
}

async fn verify_existing_local_object(
    operator: &Operator,
    object: &LocalObject,
    config: &ObjectStoreConfig,
) -> Result<()> {
    let metadata = operator.stat(&object.key).await?;
    verify_remote_object(
        operator,
        &object.key,
        object.bytes,
        &object.sha256,
        metadata.content_length(),
        config.verify_remote_sha256,
    )
    .await
}

pub(crate) async fn verify_remote_object(
    operator: &Operator,
    key: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    remote_bytes: u64,
    verify_sha256: bool,
) -> Result<()> {
    if remote_bytes != expected_bytes {
        bail!(
            "remote object size mismatch for {key}: expected={expected_bytes}, remote={remote_bytes}"
        );
    }
    if verify_sha256 {
        let digest = remote_sha256(operator, key).await?;
        if digest != expected_sha256 {
            bail!("remote object SHA-256 mismatch for {key}");
        }
    }
    Ok(())
}

pub(crate) async fn remote_sha256(operator: &Operator, key: &str) -> Result<String> {
    let mut remote = operator
        .reader(key)
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
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) async fn write_immutable_bytes(
    operator: &Operator,
    key: &str,
    bytes: Vec<u8>,
) -> Result<bool> {
    validate_key(key)?;
    match operator
        .write_with(key, bytes.clone())
        .if_not_exists(true)
        .await
    {
        Ok(_) => Ok(true),
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
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn read_optional(operator: &Operator, key: &str) -> Result<Option<Vec<u8>>> {
    match operator.read(key).await {
        Ok(value) => Ok(Some(value.to_vec())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn normalize_prefix(value: &str) -> Result<String> {
    let value = value.trim_matches('/');
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.split('/').any(|component| {
        component.is_empty()
            || component == "."
            || component == ".."
            || component.chars().any(char::is_control)
    }) {
        bail!("object prefix contains an empty, dot, or control-character component");
    }
    Ok(value.to_owned())
}

pub(crate) fn join_key(prefix: &str, suffix: &str) -> String {
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

pub(crate) fn validate_key(key: &str) -> Result<()> {
    let path = std::path::Path::new(key);
    if key.is_empty()
        || path.is_absolute()
        || key.contains('\\')
        || key.chars().any(char::is_control)
        || key
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("unsafe object key: {key:?}");
    }
    Ok(())
}

pub(crate) fn validate_component(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        bail!("{name} must be a single safe object-key component");
    }
    Ok(())
}
