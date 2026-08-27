use crate::capture::CaptureRecord;
use crate::jsonl::sha256_bytes;
use crate::store::{
    CaptureLocator, CaptureStore, SegmentMetadata, StoreConfig, StoreHealth, SubmitAck,
    SubmitError, audit_store,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

const TOPOLOGY_VERSION: &str = "chiptrace.shards.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ShardTopology {
    schema_version: String,
    shards: usize,
    hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShardHealth {
    pub shard: usize,
    pub store: StoreHealth,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShardedStoreHealth {
    pub ok: bool,
    pub ready: bool,
    pub shard_count: usize,
    pub captures: u64,
    pub attempts: u64,
    pub accepted_attempts: u64,
    pub duplicate_attempts: u64,
    pub conflict_attempts: u64,
    pub rejected_attempts: u64,
    pub active_segment_bytes: u64,
    pub active_segment_records: u64,
    pub sealed_segments: u64,
    pub sealed_bytes: u64,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub recovery_records: u64,
    pub last_commit_at: Option<String>,
    pub last_error: Option<String>,
    pub shards: Vec<ShardHealth>,
}

#[derive(Clone)]
pub struct ShardedCaptureStore {
    stores: Arc<Vec<CaptureStore>>,
}

impl ShardedCaptureStore {
    pub async fn open(config: StoreConfig, shards: usize) -> Result<Self> {
        if shards == 0 || shards > 1024 {
            bail!("store shard count must be between 1 and 1024");
        }
        ensure_topology(&config.state_root, shards)?;
        let mut stores = Vec::with_capacity(shards);
        for shard in 0..shards {
            let mut shard_config = config.clone();
            if shards > 1 {
                let name = format!("shard-{shard:05}");
                shard_config.root = config.root.join(&name);
                shard_config.state_root = config.state_root.join(&name);
            }
            match CaptureStore::open(shard_config).await {
                Ok(store) => stores.push(store),
                Err(error) => {
                    for store in &stores {
                        let _ = store.close().await;
                    }
                    return Err(error).with_context(|| format!("open capture shard {shard}"));
                }
            }
        }
        Ok(Self {
            stores: Arc::new(stores),
        })
    }

    pub fn shard_count(&self) -> usize {
        self.stores.len()
    }

    pub async fn submit(
        &self,
        record: CaptureRecord,
    ) -> std::result::Result<SubmitAck, SubmitError> {
        let shard = self.shard_for(&record.capture_id);
        self.stores[shard].submit(record).await
    }

    pub async fn submit_batch(
        &self,
        records: Vec<CaptureRecord>,
    ) -> Vec<std::result::Result<SubmitAck, SubmitError>> {
        let futures = records.into_iter().map(|record| {
            let store = self.stores[self.shard_for(&record.capture_id)].clone();
            async move { store.submit_wait(record).await }
        });
        futures_util::future::join_all(futures).await
    }

    pub async fn flush(&self) -> Result<Vec<SegmentMetadata>> {
        let futures = self.stores.iter().map(CaptureStore::flush);
        let results = futures_util::future::join_all(futures).await;
        results.into_iter().collect()
    }

    pub async fn close(&self) -> Result<()> {
        let futures = self.stores.iter().map(CaptureStore::close);
        let results = futures_util::future::join_all(futures).await;
        for result in results {
            result?;
        }
        Ok(())
    }

    pub fn health(&self) -> ShardedStoreHealth {
        let shards: Vec<ShardHealth> = self
            .stores
            .iter()
            .enumerate()
            .map(|(shard, store)| ShardHealth {
                shard,
                store: store.health(),
            })
            .collect();
        let stores: Vec<&StoreHealth> = shards.iter().map(|shard| &shard.store).collect();
        let sum_u64 = |field: fn(&StoreHealth) -> u64| {
            stores
                .iter()
                .fold(0_u64, |total, store| total.saturating_add(field(store)))
        };
        let sum_usize = |field: fn(&StoreHealth) -> usize| {
            stores
                .iter()
                .fold(0_usize, |total, store| total.saturating_add(field(store)))
        };
        let last_commit_at = stores
            .iter()
            .filter_map(|store| store.last_commit_at.as_ref())
            .max()
            .cloned();
        let errors: Vec<&str> = stores
            .iter()
            .filter_map(|store| store.last_error.as_deref())
            .collect();
        ShardedStoreHealth {
            ok: stores.iter().all(|store| store.ok),
            ready: stores.iter().all(|store| store.ready),
            shard_count: stores.len(),
            captures: sum_u64(|store| store.captures),
            attempts: sum_u64(|store| store.attempts),
            accepted_attempts: sum_u64(|store| store.accepted_attempts),
            duplicate_attempts: sum_u64(|store| store.duplicate_attempts),
            conflict_attempts: sum_u64(|store| store.conflict_attempts),
            rejected_attempts: sum_u64(|store| store.rejected_attempts),
            active_segment_bytes: sum_u64(|store| store.active_segment_bytes),
            active_segment_records: sum_u64(|store| store.active_segment_records),
            sealed_segments: sum_u64(|store| store.sealed_segments),
            sealed_bytes: sum_u64(|store| store.sealed_bytes),
            queue_depth: sum_usize(|store| store.queue_depth),
            queue_capacity: sum_usize(|store| store.queue_capacity),
            recovery_records: sum_u64(|store| store.recovery_records),
            last_commit_at,
            last_error: (!errors.is_empty()).then(|| errors.join("; ")),
            shards,
        }
    }

    pub async fn audit(&self, verify_payloads: bool) -> Result<Value> {
        let futures = self.stores.iter().map(|store| store.audit(verify_payloads));
        let results = futures_util::future::join_all(futures).await;
        let mut audits = Vec::with_capacity(results.len());
        let mut captures = 0_u64;
        let mut attempts = 0_u64;
        let mut ok = true;
        for (shard, result) in results.into_iter().enumerate() {
            let audit = result?;
            ok &= audit.get("ok").and_then(Value::as_bool) == Some(true);
            captures =
                captures.saturating_add(audit.get("captures").and_then(Value::as_u64).unwrap_or(0));
            attempts =
                attempts.saturating_add(audit.get("attempts").and_then(Value::as_u64).unwrap_or(0));
            audits.push(json!({"shard": shard, "audit": audit}));
        }
        Ok(json!({
            "ok": ok,
            "shard_count": self.shard_count(),
            "captures": captures,
            "attempts": attempts,
            "attempt_conservation": attempts >= captures,
            "shards": audits,
        }))
    }

    pub fn runtime_audit(&self) -> Value {
        let health = self.health();
        let mut failures = Vec::new();
        let shards: Vec<Value> = health
            .shards
            .iter()
            .map(|shard| {
                let store = &shard.store;
                let classified_attempts = store
                    .accepted_attempts
                    .saturating_add(store.duplicate_attempts)
                    .saturating_add(store.conflict_attempts)
                    .saturating_add(store.rejected_attempts);
                let conserved = store.attempts == classified_attempts
                    && store.captures == store.accepted_attempts;
                if !conserved {
                    failures.push(format!("attempt_conservation:shard-{:05}", shard.shard));
                }
                json!({
                    "shard": shard.shard,
                    "captures": store.captures,
                    "attempts": store.attempts,
                    "classified_attempts": classified_attempts,
                    "attempt_conservation": conserved,
                })
            })
            .collect();
        let ok = health.ok && failures.is_empty();
        json!({
            "ok": ok,
            "mode": "runtime_counters",
            "shard_count": health.shard_count,
            "captures": health.captures,
            "attempts": health.attempts,
            "attempt_conservation": failures.is_empty(),
            "failures": failures,
            "shards": shards,
        })
    }

    pub async fn read_capture(&self, capture_id: &str) -> Result<Vec<u8>> {
        self.stores[self.shard_for(capture_id)]
            .read_capture(capture_id)
            .await
    }

    pub async fn list_captures(&self) -> Result<Vec<CaptureLocator>> {
        let futures = self.stores.iter().map(CaptureStore::list_captures);
        let results = futures_util::future::join_all(futures).await;
        let mut output = Vec::new();
        for result in results {
            output.extend(result?);
        }
        output.sort_by(|left, right| left.capture_id.cmp(&right.capture_id));
        Ok(output)
    }

    fn shard_for(&self, capture_id: &str) -> usize {
        let digest = Sha256::digest(capture_id.as_bytes());
        let prefix = u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 prefix length"));
        prefix as usize % self.stores.len()
    }
}

fn ensure_topology(state_root: &Path, shards: usize) -> Result<()> {
    fs::create_dir_all(state_root)?;
    let path = state_root.join("sharding.json");
    let expected = ShardTopology {
        schema_version: TOPOLOGY_VERSION.to_owned(),
        shards,
        hash: "sha256-little-endian-u64-modulo".to_owned(),
    };
    if path.exists() {
        let observed: ShardTopology = serde_json::from_slice(&fs::read(&path)?)?;
        if observed != expected {
            bail!(
                "capture shard topology mismatch: configured {}, persisted {}",
                shards,
                observed.shards
            );
        }
        return Ok(());
    }
    let bytes = serde_json::to_vec_pretty(&expected)?;
    let temporary = state_root.join(format!(".sharding-{}.tmp", sha256_bytes(&bytes)));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    File::open(state_root)?.sync_all()?;
    Ok(())
}

pub fn audit_sharded_store(
    root: &Path,
    state_root: &Path,
    shards: usize,
    verify_payloads: bool,
) -> Result<Value> {
    if shards == 0 || shards > 1024 {
        bail!("store shard count must be between 1 and 1024");
    }
    let topology_path = state_root.join("sharding.json");
    if topology_path.is_file() {
        let topology: ShardTopology = serde_json::from_slice(&fs::read(&topology_path)?)?;
        if topology.shards != shards {
            bail!(
                "capture shard topology mismatch: configured {}, persisted {}",
                shards,
                topology.shards
            );
        }
    } else if shards > 1 {
        bail!("sharding.json is missing for a multi-shard store");
    }
    let mut audits = Vec::with_capacity(shards);
    let mut captures = 0_u64;
    let mut attempts = 0_u64;
    let mut ok = true;
    for shard in 0..shards {
        let shard_root = if shards == 1 {
            root.to_path_buf()
        } else {
            root.join(format!("shard-{shard:05}"))
        };
        let shard_state = if shards == 1 {
            state_root.to_path_buf()
        } else {
            state_root.join(format!("shard-{shard:05}"))
        };
        let audit = audit_store(&shard_root, &shard_state, verify_payloads)?;
        ok &= audit.get("ok").and_then(Value::as_bool) == Some(true);
        captures =
            captures.saturating_add(audit.get("captures").and_then(Value::as_u64).unwrap_or(0));
        attempts =
            attempts.saturating_add(audit.get("attempts").and_then(Value::as_u64).unwrap_or(0));
        audits.push(json!({"shard": shard, "audit": audit}));
    }
    Ok(json!({
        "ok": ok,
        "shard_count": shards,
        "captures": captures,
        "attempts": attempts,
        "attempt_conservation": attempts >= captures,
        "shards": audits,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::normalize_capture;
    use serde_json::json;
    use std::time::Duration;

    fn config(root: &Path) -> StoreConfig {
        StoreConfig {
            root: root.join("capture"),
            state_root: root.join("state"),
            segment_max_bytes: 1024 * 1024,
            segment_max_age: Duration::from_secs(60),
            queue_items: 16,
            batch_records: 8,
            batch_bytes: 1024 * 1024,
            batch_wait: Duration::from_millis(1),
            fsync: true,
        }
    }

    #[tokio::test]
    async fn shards_route_idempotently_and_freeze_topology() {
        let temporary = tempfile::tempdir().unwrap();
        let store = ShardedCaptureStore::open(config(temporary.path()), 4)
            .await
            .unwrap();
        let records = (0..16)
            .map(|index| {
                let value = json!({"captureId": format!("cap-shard-{index}")});
                normalize_capture(&serde_json::to_vec(&value).unwrap(), 4096).unwrap()
            })
            .collect();
        let results = store.submit_batch(records).await;
        assert!(results.iter().all(Result::is_ok));
        let health = store.health();
        assert_eq!(health.shard_count, 4);
        assert_eq!(health.captures, 16);
        assert!(
            health
                .shards
                .iter()
                .filter(|shard| shard.store.captures > 0)
                .count()
                > 1
        );
        store.close().await.unwrap();
        assert!(
            ShardedCaptureStore::open(config(temporary.path()), 2)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn runtime_audit_uses_conserved_counters() {
        let temporary = tempfile::tempdir().unwrap();
        let store = ShardedCaptureStore::open(config(temporary.path()), 2)
            .await
            .unwrap();
        let records = (0..4)
            .map(|index| {
                normalize_capture(
                    &serde_json::to_vec(&json!({"captureId": format!("cap-audit-{index}")}))
                        .unwrap(),
                    4096,
                )
                .unwrap()
            })
            .collect();
        assert!(store.submit_batch(records).await.iter().all(Result::is_ok));
        let audit = store.runtime_audit();
        assert_eq!(audit["ok"], true);
        assert_eq!(audit["captures"], 4);
        assert_eq!(audit["attempt_conservation"], true);
        store.close().await.unwrap();
    }
}
