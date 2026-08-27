use crate::capture::{CaptureRecord, normalize_capture, normalize_capture_batch};
use crate::ingest::{BodyReadError, InflightBodyBudget};
use crate::sharded::{ShardedCaptureStore, ShardedStoreHealth};
use crate::store::{CaptureLocator, StoreConfig, SubmitAck, SubmitError, SubmitErrorKind};
use anyhow::{Context, Result, bail};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::{self, StreamExt};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, watch};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

const DELIVERIES: TableDefinition<&str, &[u8]> = TableDefinition::new("deliveries");
const PENDING_DELIVERIES: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_deliveries");
const INFLIGHT_DELIVERIES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("inflight_deliveries");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const DELIVERY_SCHEMA_VERSION: &str = "chiptrace.delivery-ledger.v1";
const DELIVERY_COUNTERS_KEY: &str = "delivery_counters_v1";

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind: SocketAddr,
    pub store: StoreConfig,
    pub store_shards: usize,
    pub delivery_state_root: PathBuf,
    pub collector_url: String,
    pub delivery_concurrency: usize,
    pub delivery_queue_items: usize,
    pub delivery_batch_records: usize,
    pub delivery_batch_bytes: usize,
    pub delivery_batch_wait: Duration,
    pub max_delivery_inflight_bytes: usize,
    pub request_timeout: Duration,
    pub base_retry_delay: Duration,
    pub max_retry_delay: Duration,
    pub max_connections: usize,
    pub max_envelope_bytes: usize,
    pub max_inflight_body_bytes: usize,
    pub max_batch_records: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeliveryRecord {
    capture_id: String,
    raw_sha256: String,
    #[serde(default)]
    bytes: u64,
    state: String,
    attempts: u64,
    next_attempt_unix_ms: u64,
    #[serde(default)]
    lease_until_unix_ms: u64,
    last_attempt_at: Option<String>,
    delivered_at: Option<String>,
    last_error: Option<String>,
}

struct DeliveryUpdate {
    capture_id: String,
    state: &'static str,
    error: Option<String>,
    next_attempt: Option<Duration>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DeliveryCounters {
    total: u64,
    pending: u64,
    inflight: u64,
    delivered: u64,
    conflicts: u64,
    failed: u64,
    attempts: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayHealth {
    pub ok: bool,
    pub collector_url: String,
    pub local: ShardedStoreHealth,
    pub delivery_records: u64,
    pub pending: u64,
    pub inflight: u64,
    pub delivered: u64,
    pub conflicts: u64,
    pub failed: u64,
    pub delivery_attempts: u64,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub delivery_body_budget_available: usize,
    pub delivery_body_budget_capacity: usize,
    pub conservation_ok: bool,
}

struct DeliveryLedger {
    database: Database,
}

impl DeliveryLedger {
    fn open(path: &std::path::Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let database = Database::create(path)?;
        let transaction = database.begin_write()?;
        {
            transaction.open_table(DELIVERIES)?;
            transaction.open_table(PENDING_DELIVERIES)?;
            transaction.open_table(INFLIGHT_DELIVERIES)?;
            let mut meta = transaction.open_table(META)?;
            if let Some(version) = meta.get("schema_version")? {
                if std::str::from_utf8(version.value())? != DELIVERY_SCHEMA_VERSION {
                    bail!("unsupported Relay delivery ledger schema");
                }
            } else {
                meta.insert("schema_version", DELIVERY_SCHEMA_VERSION.as_bytes())?;
            }
            drop(meta);
            let mut deliveries = transaction.open_table(DELIVERIES)?;
            let keys: Vec<String> = deliveries
                .iter()?
                .filter_map(|row| row.ok().map(|(key, _)| key.value().to_owned()))
                .collect();
            for key in keys {
                let Some(value) = deliveries.get(key.as_str())? else {
                    continue;
                };
                let mut record: DeliveryRecord = serde_json::from_slice(value.value())?;
                drop(value);
                if record.state == "inflight" {
                    record.state = "pending".to_owned();
                    record.next_attempt_unix_ms = 0;
                    record.lease_until_unix_ms = 0;
                    deliveries.insert(key.as_str(), serde_json::to_vec(&record)?.as_slice())?;
                }
            }
            let counters = delivery_counters_from_table(&deliveries)?;
            let pending_rows: Vec<(String, String)> = deliveries
                .iter()?
                .filter_map(|row| {
                    row.ok().and_then(|(_, value)| {
                        serde_json::from_slice::<DeliveryRecord>(value.value())
                            .ok()
                            .filter(|record| record.state == "pending")
                            .map(|record| {
                                (
                                    delivery_index_key(
                                        record.next_attempt_unix_ms,
                                        &record.capture_id,
                                    ),
                                    record.capture_id,
                                )
                            })
                    })
                })
                .collect();
            drop(deliveries);
            let mut pending = transaction.open_table(PENDING_DELIVERIES)?;
            let old_pending_keys: Vec<String> = pending
                .iter()?
                .filter_map(|row| row.ok().map(|(key, _)| key.value().to_owned()))
                .collect();
            for key in old_pending_keys {
                pending.remove(key.as_str())?;
            }
            for (key, capture_id) in pending_rows {
                pending.insert(key.as_str(), capture_id.as_bytes())?;
            }
            drop(pending);
            let mut inflight = transaction.open_table(INFLIGHT_DELIVERIES)?;
            let old_inflight_keys: Vec<String> = inflight
                .iter()?
                .filter_map(|row| row.ok().map(|(key, _)| key.value().to_owned()))
                .collect();
            for key in old_inflight_keys {
                inflight.remove(key.as_str())?;
            }
            drop(inflight);
            let mut meta = transaction.open_table(META)?;
            write_delivery_counters(&mut meta, &counters)?;
        }
        transaction.commit()?;
        Ok(Self { database })
    }

    fn ensure(&self, locator: &CaptureLocator) -> Result<bool> {
        Ok(self.ensure_many(std::slice::from_ref(locator))? == 1)
    }

    fn ensure_many(&self, locators: &[CaptureLocator]) -> Result<usize> {
        let transaction = self.database.begin_write()?;
        let mut inserted = 0_usize;
        {
            let mut table = transaction.open_table(DELIVERIES)?;
            let mut pending = transaction.open_table(PENDING_DELIVERIES)?;
            let mut meta = transaction.open_table(META)?;
            let mut counters = read_delivery_counters(&meta)?;
            for locator in locators {
                let existing: Option<DeliveryRecord> = table
                    .get(locator.capture_id.as_str())?
                    .map(|value| serde_json::from_slice(value.value()))
                    .transpose()?;
                if let Some(mut existing) = existing {
                    if existing.raw_sha256 != locator.raw_sha256 {
                        bail!(
                            "delivery ledger capture hash conflict: {}",
                            locator.capture_id
                        );
                    }
                    if existing.bytes == 0 {
                        existing.bytes = locator.length;
                        table.insert(
                            locator.capture_id.as_str(),
                            serde_json::to_vec(&existing)?.as_slice(),
                        )?;
                    } else if existing.bytes != locator.length {
                        bail!(
                            "delivery ledger capture length conflict: {}",
                            locator.capture_id
                        );
                    }
                } else {
                    let record = DeliveryRecord {
                        capture_id: locator.capture_id.clone(),
                        raw_sha256: locator.raw_sha256.clone(),
                        bytes: locator.length,
                        state: "pending".to_owned(),
                        attempts: 0,
                        next_attempt_unix_ms: 0,
                        lease_until_unix_ms: 0,
                        last_attempt_at: None,
                        delivered_at: None,
                        last_error: None,
                    };
                    table.insert(
                        locator.capture_id.as_str(),
                        serde_json::to_vec(&record)?.as_slice(),
                    )?;
                    let key = delivery_index_key(0, &locator.capture_id);
                    pending.insert(key.as_str(), locator.capture_id.as_bytes())?;
                    inserted += 1;
                    counters.total += 1;
                    counters.pending += 1;
                }
            }
            write_delivery_counters(&mut meta, &counters)?;
        }
        transaction.commit()?;
        Ok(inserted)
    }

    fn claim_many(
        &self,
        capture_ids: &[String],
        lease_duration: Duration,
    ) -> Result<Vec<DeliveryRecord>> {
        let transaction = self.database.begin_write()?;
        let mut claimed = Vec::new();
        {
            let mut table = transaction.open_table(DELIVERIES)?;
            let mut pending = transaction.open_table(PENDING_DELIVERIES)?;
            let mut inflight = transaction.open_table(INFLIGHT_DELIVERIES)?;
            let mut meta = transaction.open_table(META)?;
            let mut counters = read_delivery_counters(&meta)?;
            let now = unix_millis();
            let timestamp = crate::jsonl::utc_now();
            for capture_id in capture_ids {
                let existing: Option<DeliveryRecord> = table
                    .get(capture_id.as_str())?
                    .map(|value| serde_json::from_slice(value.value()))
                    .transpose()?;
                let Some(mut record) = existing else {
                    continue;
                };
                if record.state != "pending" || record.next_attempt_unix_ms > now {
                    continue;
                }
                let pending_key =
                    delivery_index_key(record.next_attempt_unix_ms, &record.capture_id);
                pending.remove(pending_key.as_str())?;
                record.state = "inflight".to_owned();
                record.attempts += 1;
                record.last_attempt_at = Some(timestamp.clone());
                record.lease_until_unix_ms =
                    now.saturating_add(lease_duration.as_millis().try_into().unwrap_or(u64::MAX));
                let inflight_key =
                    delivery_index_key(record.lease_until_unix_ms, record.capture_id.as_str());
                inflight.insert(inflight_key.as_str(), record.capture_id.as_bytes())?;
                table.insert(capture_id.as_str(), serde_json::to_vec(&record)?.as_slice())?;
                claimed.push(record);
                counters.pending = counters.pending.saturating_sub(1);
                counters.inflight += 1;
                counters.attempts += 1;
            }
            write_delivery_counters(&mut meta, &counters)?;
        }
        transaction.commit()?;
        Ok(claimed)
    }

    fn finish_many(&self, updates: &[DeliveryUpdate]) -> Result<()> {
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(DELIVERIES)?;
            let mut pending = transaction.open_table(PENDING_DELIVERIES)?;
            let mut inflight = transaction.open_table(INFLIGHT_DELIVERIES)?;
            let mut meta = transaction.open_table(META)?;
            let mut counters = read_delivery_counters(&meta)?;
            let now = unix_millis();
            let timestamp = crate::jsonl::utc_now();
            for update in updates {
                let mut record: DeliveryRecord = table
                    .get(update.capture_id.as_str())?
                    .map(|value| serde_json::from_slice(value.value()))
                    .transpose()?
                    .ok_or_else(|| {
                        anyhow::anyhow!("delivery record missing: {}", update.capture_id)
                    })?;
                if record.state == "pending" {
                    let key = delivery_index_key(record.next_attempt_unix_ms, &record.capture_id);
                    pending.remove(key.as_str())?;
                } else if record.state == "inflight" {
                    let key = delivery_index_key(record.lease_until_unix_ms, &record.capture_id);
                    inflight.remove(key.as_str())?;
                }
                decrement_delivery_state(&mut counters, &record.state);
                record.state = update.state.to_owned();
                record.last_error = update
                    .error
                    .as_ref()
                    .map(|error| error.chars().take(500).collect());
                record.next_attempt_unix_ms = update
                    .next_attempt
                    .map(|delay| now.saturating_add(delay.as_millis() as u64))
                    .unwrap_or(0);
                record.lease_until_unix_ms = 0;
                if update.state == "delivered" {
                    record.delivered_at = Some(timestamp.clone());
                }
                if update.state == "pending" {
                    let key = delivery_index_key(record.next_attempt_unix_ms, &record.capture_id);
                    pending.insert(key.as_str(), record.capture_id.as_bytes())?;
                }
                table.insert(
                    update.capture_id.as_str(),
                    serde_json::to_vec(&record)?.as_slice(),
                )?;
                increment_delivery_state(&mut counters, update.state);
            }
            write_delivery_counters(&mut meta, &counters)?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn pending_ids(&self, limit: usize) -> Result<Vec<String>> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(PENDING_DELIVERIES)?;
        let now = unix_millis();
        let mut output = Vec::new();
        for row in table.iter()? {
            let (key, value) = row?;
            let due = key
                .value()
                .get(..20)
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| anyhow::anyhow!("invalid pending delivery key"))?;
            if due > now {
                break;
            }
            output.push(std::str::from_utf8(value.value())?.to_owned());
            if output.len() >= limit {
                break;
            }
        }
        Ok(output)
    }

    fn reclaim_expired_inflight(&self, limit: usize) -> Result<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let transaction = self.database.begin_write()?;
        let mut reclaimed = Vec::new();
        {
            let mut table = transaction.open_table(DELIVERIES)?;
            let mut pending = transaction.open_table(PENDING_DELIVERIES)?;
            let mut inflight = transaction.open_table(INFLIGHT_DELIVERIES)?;
            let mut meta = transaction.open_table(META)?;
            let mut counters = read_delivery_counters(&meta)?;
            let now = unix_millis();
            let expired: Vec<(String, String)> = inflight
                .iter()?
                .take(limit)
                .map(|row| {
                    let (key, value) = row?;
                    Ok((
                        key.value().to_owned(),
                        std::str::from_utf8(value.value())?.to_owned(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .take_while(|(key, _)| delivery_index_due(key).is_some_and(|due| due <= now))
                .collect();
            for (key, capture_id) in expired {
                inflight.remove(key.as_str())?;
                let Some(mut record) = table
                    .get(capture_id.as_str())?
                    .map(|value| serde_json::from_slice::<DeliveryRecord>(value.value()))
                    .transpose()?
                else {
                    continue;
                };
                if record.state != "inflight"
                    || record.lease_until_unix_ms > now
                    || delivery_index_due(&key) != Some(record.lease_until_unix_ms)
                {
                    continue;
                }
                decrement_delivery_state(&mut counters, &record.state);
                record.state = "pending".to_owned();
                record.next_attempt_unix_ms = 0;
                record.lease_until_unix_ms = 0;
                record.last_error = Some("delivery lease expired; retry scheduled".to_owned());
                let pending_key = delivery_index_key(0, &record.capture_id);
                pending.insert(pending_key.as_str(), record.capture_id.as_bytes())?;
                table.insert(
                    record.capture_id.as_str(),
                    serde_json::to_vec(&record)?.as_slice(),
                )?;
                increment_delivery_state(&mut counters, "pending");
                reclaimed.push(record.capture_id);
            }
            write_delivery_counters(&mut meta, &counters)?;
        }
        transaction.commit()?;
        Ok(reclaimed)
    }

    fn health(&self) -> Result<(u64, u64, u64, u64, u64, u64, u64)> {
        let transaction = self.database.begin_read()?;
        let meta = transaction.open_table(META)?;
        let counters = read_delivery_counters(&meta)?;
        let total = counters.total;
        let pending = counters.pending;
        let inflight = counters.inflight;
        let delivered = counters.delivered;
        let conflicts = counters.conflicts;
        let failed = counters.failed;
        let attempts = counters.attempts;
        Ok((
            total, pending, inflight, delivered, conflicts, failed, attempts,
        ))
    }
}

fn delivery_counters_from_table<T>(table: &T) -> Result<DeliveryCounters>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    let mut counters = DeliveryCounters {
        total: table.len()?,
        ..DeliveryCounters::default()
    };
    for row in table.iter()? {
        let (_, value) = row?;
        let record: DeliveryRecord = serde_json::from_slice(value.value())?;
        increment_delivery_state(&mut counters, &record.state);
        counters.attempts = counters.attempts.saturating_add(record.attempts);
    }
    Ok(counters)
}

fn read_delivery_counters<T>(meta: &T) -> Result<DeliveryCounters>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    meta.get(DELIVERY_COUNTERS_KEY)?
        .map(|value| serde_json::from_slice(value.value()).map_err(anyhow::Error::from))
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("Relay delivery counters are missing"))
}

fn write_delivery_counters(
    meta: &mut redb::Table<'_, &'static str, &'static [u8]>,
    counters: &DeliveryCounters,
) -> Result<()> {
    let bytes = serde_json::to_vec(counters)?;
    meta.insert(DELIVERY_COUNTERS_KEY, bytes.as_slice())?;
    Ok(())
}

fn increment_delivery_state(counters: &mut DeliveryCounters, state: &str) {
    match state {
        "pending" => counters.pending += 1,
        "inflight" => counters.inflight += 1,
        "delivered" => counters.delivered += 1,
        "conflict" => counters.conflicts += 1,
        "failed" => counters.failed += 1,
        _ => {}
    }
}

fn decrement_delivery_state(counters: &mut DeliveryCounters, state: &str) {
    match state {
        "pending" => counters.pending = counters.pending.saturating_sub(1),
        "inflight" => counters.inflight = counters.inflight.saturating_sub(1),
        "delivered" => counters.delivered = counters.delivered.saturating_sub(1),
        "conflict" => counters.conflicts = counters.conflicts.saturating_sub(1),
        "failed" => counters.failed = counters.failed.saturating_sub(1),
        _ => {}
    }
}

fn delivery_index_key(due_unix_ms: u64, capture_id: &str) -> String {
    format!("{due_unix_ms:020}:{capture_id}")
}

fn delivery_index_due(key: &str) -> Option<u64> {
    key.get(..20)?.parse().ok()
}

struct RelayInner {
    store: ShardedCaptureStore,
    ledger: Arc<Mutex<DeliveryLedger>>,
    client: reqwest::Client,
    delivery_body_budget: Arc<Semaphore>,
    sender: flume::Sender<String>,
    scheduled: Mutex<HashSet<String>>,
    shutdown: watch::Sender<bool>,
    tasks: AsyncMutex<Vec<tokio::task::JoinHandle<()>>>,
    config: RelayConfig,
}

#[derive(Clone)]
pub struct DurableRelay {
    inner: Arc<RelayInner>,
}

impl DurableRelay {
    pub async fn open(config: RelayConfig) -> Result<Self> {
        if config.delivery_concurrency == 0
            || config.delivery_queue_items == 0
            || config.delivery_batch_records == 0
            || config.delivery_batch_bytes == 0
            || config.max_delivery_inflight_bytes == 0
        {
            bail!("Relay delivery concurrency, queue, and batch sizes must be positive");
        }
        let maximum_delivery_record = config.max_envelope_bytes.saturating_add(1);
        if config.max_delivery_inflight_bytes < maximum_delivery_record {
            bail!(
                "Relay delivery body budget must be at least max envelope bytes plus one newline"
            );
        }
        let store = ShardedCaptureStore::open(config.store.clone(), config.store_shards).await?;
        let ledger_path = config.delivery_state_root.join("delivery-ledger.redb");
        let ledger = Arc::new(Mutex::new(DeliveryLedger::open(&ledger_path)?));
        let locators = store.list_captures().await?;
        for batch in locators.chunks(4096) {
            ledger
                .lock()
                .expect("delivery ledger poisoned")
                .ensure_many(batch)?;
        }
        let (sender, receiver) = flume::bounded(config.delivery_queue_items);
        let (shutdown, _) = watch::channel(false);
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()?;
        let inner = Arc::new(RelayInner {
            store,
            ledger,
            client,
            delivery_body_budget: Arc::new(Semaphore::new(config.max_delivery_inflight_bytes)),
            sender,
            scheduled: Mutex::new(HashSet::new()),
            shutdown,
            tasks: AsyncMutex::new(Vec::new()),
            config,
        });
        let relay = Self {
            inner: Arc::clone(&inner),
        };
        relay.spawn_workers(receiver).await;
        relay.queue_pending()?;
        Ok(relay)
    }

    pub async fn enqueue(&self, raw: &[u8]) -> Result<SubmitAck> {
        let record = normalize_capture(raw, self.inner.config.max_envelope_bytes)?;
        let capture_id = record.capture_id.clone();
        let raw_sha256 = record.sha256.clone();
        let ack = self
            .inner
            .store
            .submit(record)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let locator = CaptureLocator {
            capture_id: capture_id.clone(),
            raw_sha256,
            segment_id: ack.segment_id,
            offset: ack.offset,
            length: ack.length,
            received_at: None,
            model: None,
        };
        self.inner
            .ledger
            .lock()
            .expect("delivery ledger poisoned")
            .ensure(&locator)?;
        queue_capture(&self.inner, capture_id);
        Ok(ack)
    }

    pub async fn enqueue_batch(
        &self,
        records: Vec<CaptureRecord>,
    ) -> Result<Vec<std::result::Result<SubmitAck, SubmitError>>> {
        let identities: Vec<(String, String)> = records
            .iter()
            .map(|record| (record.capture_id.clone(), record.sha256.clone()))
            .collect();
        let results = self.inner.store.submit_batch(records).await;
        let locators: Vec<CaptureLocator> = identities
            .iter()
            .zip(&results)
            .filter_map(|((capture_id, raw_sha256), result)| {
                result.as_ref().ok().map(|ack| CaptureLocator {
                    capture_id: capture_id.clone(),
                    raw_sha256: raw_sha256.clone(),
                    segment_id: ack.segment_id,
                    offset: ack.offset,
                    length: ack.length,
                    received_at: None,
                    model: None,
                })
            })
            .collect();
        self.inner
            .ledger
            .lock()
            .expect("delivery ledger poisoned")
            .ensure_many(&locators)?;
        for locator in locators {
            queue_capture(&self.inner, locator.capture_id);
        }
        Ok(results)
    }

    pub async fn flush(&self) -> Result<Vec<crate::store::SegmentMetadata>> {
        self.inner.store.flush().await
    }

    pub async fn health(&self) -> Result<RelayHealth> {
        let local = self.inner.store.health();
        let (total, pending, inflight, delivered, conflicts, failed, attempts) = self
            .inner
            .ledger
            .lock()
            .expect("delivery ledger poisoned")
            .health()?;
        Ok(RelayHealth {
            ok: local.ok && total == pending + inflight + delivered + conflicts + failed,
            collector_url: self.inner.config.collector_url.clone(),
            local,
            delivery_records: total,
            pending,
            inflight,
            delivered,
            conflicts,
            failed,
            delivery_attempts: attempts,
            queue_depth: self.inner.sender.len(),
            queue_capacity: self.inner.sender.capacity().unwrap_or(0),
            delivery_body_budget_available: self.inner.delivery_body_budget.available_permits(),
            delivery_body_budget_capacity: self.inner.config.max_delivery_inflight_bytes,
            conservation_ok: total == pending + inflight + delivered + conflicts + failed,
        })
    }

    pub async fn close(&self) -> Result<()> {
        let _ = self.inner.shutdown.send(true);
        let handles = std::mem::take(&mut *self.inner.tasks.lock().await);
        for handle in handles {
            let _ = handle.await;
        }
        self.inner.store.close().await
    }

    fn queue_pending(&self) -> Result<()> {
        let available = self
            .inner
            .sender
            .capacity()
            .unwrap_or(self.inner.config.delivery_queue_items);
        let ids = self
            .inner
            .ledger
            .lock()
            .expect("delivery ledger poisoned")
            .pending_ids(available)?;
        for id in ids {
            if !queue_capture(&self.inner, id) {
                break;
            }
        }
        Ok(())
    }

    async fn spawn_workers(&self, receiver: flume::Receiver<String>) {
        let mut handles = self.inner.tasks.lock().await;
        for _ in 0..self.inner.config.delivery_concurrency {
            let inner = Arc::clone(&self.inner);
            let receiver = receiver.clone();
            let mut shutdown = inner.shutdown.subscribe();
            handles.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                        result = receiver.recv_async() => {
                            let Ok(capture_id) = result else {
                                break;
                            };
                            let capture_ids = collect_delivery_batch(&receiver, capture_id, &inner.config).await;
                            if let Err(error) = deliver_many(&inner, &capture_ids).await {
                                warn!(records = capture_ids.len(), error = %error, "Relay delivery batch failed");
                            }
                            let mut scheduled = inner
                                .scheduled
                                .lock()
                                .expect("Relay schedule poisoned");
                            for capture_id in capture_ids {
                                scheduled.remove(&capture_id);
                            }
                        }
                    }
                }
            }));
        }
        let inner = Arc::clone(&self.inner);
        let mut shutdown = inner.shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        let available = inner.sender.capacity().unwrap_or(0);
                        if available == 0 {
                            continue;
                        }
                        let reclaimed = inner
                            .ledger
                            .lock()
                            .expect("delivery ledger poisoned")
                            .reclaim_expired_inflight(available)
                            .unwrap_or_default();
                        if !reclaimed.is_empty() {
                            let mut scheduled = inner
                                .scheduled
                                .lock()
                                .expect("Relay schedule poisoned");
                            for capture_id in &reclaimed {
                                scheduled.remove(capture_id);
                            }
                        }
                        for id in reclaimed {
                            if !queue_capture(&inner, id) {
                                break;
                            }
                        }
                        let ids = inner
                            .ledger
                            .lock()
                            .expect("delivery ledger poisoned")
                            .pending_ids(available)
                            .unwrap_or_default();
                        for id in ids {
                            if !queue_capture(&inner, id) {
                                break;
                            }
                        }
                    }
                }
            }
        }));
    }
}

fn queue_capture(inner: &RelayInner, capture_id: String) -> bool {
    let mut scheduled = inner.scheduled.lock().expect("Relay schedule poisoned");
    if !scheduled.insert(capture_id.clone()) {
        return true;
    }
    if inner.sender.try_send(capture_id.clone()).is_err() {
        scheduled.remove(&capture_id);
        return false;
    }
    true
}

async fn collect_delivery_batch(
    receiver: &flume::Receiver<String>,
    first: String,
    config: &RelayConfig,
) -> Vec<String> {
    let mut batch = vec![first];
    let deadline = tokio::time::Instant::now() + config.delivery_batch_wait;
    while batch.len() < config.delivery_batch_records {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        match tokio::time::timeout(deadline - now, receiver.recv_async()).await {
            Ok(Ok(capture_id)) => batch.push(capture_id),
            _ => break,
        }
    }
    batch
}

async fn deliver_many(inner: &RelayInner, capture_ids: &[String]) -> Result<()> {
    let lease_duration = inner
        .config
        .request_timeout
        .saturating_mul(2)
        .max(Duration::from_secs(30));
    let records = inner
        .ledger
        .lock()
        .expect("delivery ledger poisoned")
        .claim_many(capture_ids, lease_duration)?;
    if records.is_empty() {
        return Ok(());
    }
    let mut updates = Vec::new();
    let reads = stream::iter(records.into_iter().map(|record| {
        let retry_record = record.clone();
        async move { (retry_record, load_delivery_payload(inner, record).await) }
    }));
    let mut reads = reads.buffer_unordered(4);
    let mut batch: Vec<DeliveryPayload> = Vec::new();
    let mut batch_bytes = 0_usize;
    while let Some((record, loaded)) = reads.next().await {
        let item = match loaded {
            Ok(item) => item,
            Err(error) => {
                updates.push(retry_update(inner, &record, error.to_string()));
                continue;
            }
        };
        let item_bytes = item.body.len().saturating_add(1);
        if !batch.is_empty()
            && batch_bytes.saturating_add(item_bytes) > inner.config.delivery_batch_bytes
        {
            updates.extend(send_delivery_batch(inner, std::mem::take(&mut batch)).await);
            batch_bytes = 0;
        }
        batch_bytes = batch_bytes.saturating_add(item_bytes);
        batch.push(item);
        if batch_bytes >= inner.config.delivery_batch_bytes {
            updates.extend(send_delivery_batch(inner, std::mem::take(&mut batch)).await);
            batch_bytes = 0;
        }
    }
    if !batch.is_empty() {
        updates.extend(send_delivery_batch(inner, batch).await);
    }
    inner
        .ledger
        .lock()
        .expect("delivery ledger poisoned")
        .finish_many(&updates)
}

struct DeliveryPayload {
    record: DeliveryRecord,
    body: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

async fn load_delivery_payload(
    inner: &RelayInner,
    record: DeliveryRecord,
) -> Result<DeliveryPayload> {
    let reservation = if record.bytes == 0 {
        inner.config.max_envelope_bytes.saturating_add(1)
    } else {
        usize::try_from(record.bytes).context("capture length exceeds usize")?
    };
    if reservation > inner.config.max_delivery_inflight_bytes {
        bail!(
            "capture {} requires {} delivery bytes, above Relay budget {}",
            record.capture_id,
            reservation,
            inner.config.max_delivery_inflight_bytes
        );
    }
    let permits = u32::try_from(reservation.max(1))
        .context("capture length exceeds semaphore reservation limit")?;
    let permit = Arc::clone(&inner.delivery_body_budget)
        .acquire_many_owned(permits)
        .await
        .context("Relay delivery body budget closed")?;
    let body = inner.store.read_capture(&record.capture_id).await?;
    Ok(DeliveryPayload {
        record,
        body,
        _permit: permit,
    })
}

async fn send_delivery_batch(
    inner: &RelayInner,
    batch: Vec<DeliveryPayload>,
) -> Vec<DeliveryUpdate> {
    if batch.len() == 1 {
        let payload = batch.into_iter().next().expect("single delivery batch");
        return vec![send_single(inner, &payload.record, payload.body).await];
    }
    let mut body = Vec::with_capacity(batch.iter().map(|item| item.body.len() + 1).sum());
    for payload in &batch {
        body.extend_from_slice(&payload.body);
        body.push(b'\n');
    }
    let url = format!(
        "{}/captures",
        inner.config.collector_url.trim_end_matches('/')
    );
    let response = match inner
        .client
        .post(url)
        .header("content-type", "application/x-ndjson")
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return batch
                .iter()
                .map(|payload| retry_update(inner, &payload.record, error.to_string()))
                .collect();
        }
    };
    let status = response.status();
    if matches!(
        status,
        StatusCode::NOT_FOUND
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
    ) {
        let futures = batch
            .into_iter()
            .map(|payload| async move { send_single(inner, &payload.record, payload.body).await });
        return futures_util::future::join_all(futures).await;
    }
    let payload: Value = match response.json().await {
        Ok(payload) => payload,
        Err(error) => {
            return batch
                .iter()
                .map(|payload| {
                    let record = &payload.record;
                    if status == StatusCode::CONFLICT {
                        conflict_update(record, error.to_string())
                    } else if is_retryable(status) {
                        retry_update(inner, record, error.to_string())
                    } else {
                        failed_update(record, error.to_string())
                    }
                })
                .collect();
        }
    };
    let outcomes = payload
        .get("results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let by_id: std::collections::HashMap<&str, &Value> = outcomes
        .iter()
        .filter_map(|outcome| {
            outcome
                .get("capture_id")
                .and_then(Value::as_str)
                .map(|capture_id| (capture_id, outcome))
        })
        .collect();
    batch
        .iter()
        .map(|payload| {
            let record = &payload.record;
            match by_id.get(record.capture_id.as_str()) {
                Some(outcome)
                    if outcome.get("ok").and_then(Value::as_bool) == Some(true)
                        && outcome.get("durable").and_then(Value::as_bool) == Some(true) =>
                {
                    delivered_update(record)
                }
                Some(outcome)
                    if outcome.get("http_status").and_then(Value::as_u64) == Some(409)
                        || outcome.get("reason").and_then(Value::as_str)
                            == Some("capture_id_conflict") =>
                {
                    conflict_update(record, "remote captureId conflict".to_owned())
                }
                Some(outcome) => {
                    let item_status = outcome
                        .get("http_status")
                        .and_then(Value::as_u64)
                        .and_then(|status| StatusCode::from_u16(status as u16).ok());
                    let error = outcome
                        .get("detail")
                        .and_then(Value::as_str)
                        .unwrap_or("remote batch item rejected")
                        .to_owned();
                    if item_status.is_none_or(is_retryable) {
                        retry_update(inner, record, error)
                    } else {
                        failed_update(record, error)
                    }
                }
                None if status == StatusCode::CONFLICT => conflict_update(
                    record,
                    format!("remote HTTP {status} omitted batch outcome"),
                ),
                None if is_retryable(status) => retry_update(
                    inner,
                    record,
                    format!("remote HTTP {status} omitted batch outcome"),
                ),
                None => failed_update(
                    record,
                    format!("remote HTTP {status} omitted batch outcome"),
                ),
            }
        })
        .collect()
}

async fn send_single(inner: &RelayInner, record: &DeliveryRecord, body: Vec<u8>) -> DeliveryUpdate {
    let url = format!(
        "{}/capture",
        inner.config.collector_url.trim_end_matches('/')
    );
    let response = match inner
        .client
        .post(url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return retry_update(inner, record, error.to_string()),
    };
    let status = response.status();
    let payload: Value = response.json().await.unwrap_or_else(|_| json!({}));
    if status.is_success()
        && payload.get("ok").and_then(Value::as_bool) == Some(true)
        && payload.get("durable").and_then(Value::as_bool) == Some(true)
    {
        delivered_update(record)
    } else if status == StatusCode::CONFLICT {
        conflict_update(record, format!("remote HTTP {status}"))
    } else if is_retryable(status) {
        retry_update(inner, record, format!("remote HTTP {status}"))
    } else {
        failed_update(record, format!("remote HTTP {status}"))
    }
}

fn delivered_update(record: &DeliveryRecord) -> DeliveryUpdate {
    DeliveryUpdate {
        capture_id: record.capture_id.clone(),
        state: "delivered",
        error: None,
        next_attempt: None,
    }
}

fn conflict_update(record: &DeliveryRecord, error: String) -> DeliveryUpdate {
    DeliveryUpdate {
        capture_id: record.capture_id.clone(),
        state: "conflict",
        error: Some(error),
        next_attempt: None,
    }
}

fn failed_update(record: &DeliveryRecord, error: String) -> DeliveryUpdate {
    DeliveryUpdate {
        capture_id: record.capture_id.clone(),
        state: "failed",
        error: Some(error),
        next_attempt: None,
    }
}

fn retry_update(inner: &RelayInner, record: &DeliveryRecord, error: String) -> DeliveryUpdate {
    let exponent = record.attempts.saturating_sub(1).min(20) as u32;
    let base_ms = inner.config.base_retry_delay.as_millis() as u64;
    let max_ms = inner.config.max_retry_delay.as_millis() as u64;
    let delay_ms = base_ms
        .saturating_mul(2_u64.saturating_pow(exponent))
        .min(max_ms);
    DeliveryUpdate {
        capture_id: record.capture_id.clone(),
        state: "pending",
        error: Some(error),
        next_attempt: Some(Duration::from_millis(delay_ms)),
    }
}

fn is_retryable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 425 | 429) || status.is_server_error()
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone)]
struct RelayAppState {
    relay: DurableRelay,
    body_budget: InflightBodyBudget,
    max_batch_records: usize,
}

pub async fn serve_relay(
    config: RelayConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let bind = config.bind;
    let max_connections = config.max_connections;
    let max_envelope_bytes = config.max_envelope_bytes;
    let relay = DurableRelay::open(config).await?;
    let body_budget = InflightBodyBudget::new(
        relay.inner.config.max_inflight_body_bytes,
        relay.inner.config.max_envelope_bytes,
    )?;
    let app = Router::new()
        .route("/capture", post(relay_capture))
        .route("/captures", post(relay_captures))
        .route("/health", get(relay_health))
        .route("/flush", post(relay_flush))
        .fallback(relay_not_found)
        .layer(DefaultBodyLimit::max(max_envelope_bytes))
        .layer(ConcurrencyLimitLayer::new(max_connections.max(1)))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(120),
        ))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(RelayAppState {
            max_batch_records: relay.inner.config.max_batch_records,
            relay: relay.clone(),
            body_budget,
        });
    let listener = TcpListener::bind(bind).await?;
    info!(address = %bind, "Relay ready");
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("Relay server failed");
    relay.close().await?;
    result
}

async fn relay_captures(State(state): State<RelayAppState>, request: Request) -> Response {
    let body = match state.body_budget.read_ndjson(request).await {
        Ok(body) => body,
        Err(error) => return relay_body_error_response(error),
    };
    let records = match normalize_capture_batch(
        &body.bytes,
        state.relay.inner.config.max_envelope_bytes,
        state.max_batch_records,
    ) {
        Ok(records) => records,
        Err(error) => {
            return relay_response(
                StatusCode::BAD_REQUEST,
                json!({"ok": false, "reason": "invalid_capture_batch", "detail": error.to_string()}),
            );
        }
    };
    let capture_ids: Vec<String> = records
        .iter()
        .map(|record| record.capture_id.clone())
        .collect();
    let results = match state.relay.enqueue_batch(records).await {
        Ok(results) => results,
        Err(error) => {
            return relay_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok": false, "reason": "relay_unavailable", "detail": error.to_string()}),
            );
        }
    };
    let mut durable = 0_u64;
    let mut duplicates = 0_u64;
    let mut conflicts = 0_u64;
    let mut unavailable = 0_u64;
    let outcomes: Vec<Value> = capture_ids
        .into_iter()
        .zip(results)
        .map(|(capture_id, result)| match result {
            Ok(ack) => {
                durable += 1;
                duplicates += u64::from(ack.duplicate);
                json!({
                    "capture_id": capture_id,
                    "ok": true,
                    "durable": true,
                    "local_durable": true,
                    "duplicate": ack.duplicate,
                    "capture": ack,
                })
            }
            Err(error) if error.kind == SubmitErrorKind::Conflict => {
                conflicts += 1;
                json!({
                    "capture_id": capture_id,
                    "ok": false,
                    "durable": false,
                    "reason": "capture_id_conflict",
                    "http_status": 409,
                    "detail": error.message,
                })
            }
            Err(error) => {
                unavailable += 1;
                json!({
                    "capture_id": capture_id,
                    "ok": false,
                    "durable": false,
                    "reason": "relay_unavailable",
                    "http_status": 503,
                    "detail": error.message,
                })
            }
        })
        .collect();
    let total = outcomes.len() as u64;
    relay_response(
        if durable == total {
            if duplicates == total {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            }
        } else {
            StatusCode::MULTI_STATUS
        },
        json!({
            "ok": durable == total,
            "durable": durable == total,
            "local_durable": durable == total,
            "counts": {
                "total": total,
                "durable": durable,
                "duplicates": duplicates,
                "conflicts": conflicts,
                "unavailable": unavailable,
            },
            "results": outcomes,
        }),
    )
}

async fn relay_capture(State(state): State<RelayAppState>, request: Request) -> Response {
    let body = match state.body_budget.read_json(request).await {
        Ok(body) => body,
        Err(error) => return relay_body_error_response(error),
    };
    match state.relay.enqueue(&body.bytes).await {
        Ok(ack) => relay_response(
            if ack.duplicate {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            },
            json!({
                "ok":true,
                "durable":true,
                "local_durable":true,
                "duplicate":ack.duplicate,
                "capture":ack,
            }),
        ),
        Err(error)
            if error
                .downcast_ref::<crate::store::SubmitError>()
                .is_some_and(|error| error.kind == SubmitErrorKind::Conflict) =>
        {
            relay_response(
                StatusCode::CONFLICT,
                json!({"ok":false,"reason":"capture_id_conflict"}),
            )
        }
        Err(error) => relay_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok":false,"reason":"relay_unavailable","detail":error.to_string()}),
        ),
    }
}

async fn relay_health(State(state): State<RelayAppState>) -> Response {
    match state.relay.health().await {
        Ok(health) => {
            let status = if health.ok {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            let mut value = serde_json::to_value(health).unwrap_or_else(|_| json!({"ok":false}));
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "body_budget_capacity".to_owned(),
                    json!(state.body_budget.capacity()),
                );
                object.insert(
                    "body_budget_available".to_owned(),
                    json!(state.body_budget.available()),
                );
            }
            relay_response(status, value)
        }
        Err(error) => relay_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"ok":false,"reason":"health_failed","detail":error.to_string()}),
        ),
    }
}

async fn relay_flush(State(state): State<RelayAppState>) -> Response {
    match state.relay.flush().await {
        Ok(segments) => relay_response(
            StatusCode::OK,
            json!({
                "ok": true,
                "sealed": segments.iter().all(|segment| segment.state == "sealed" || segment.records == 0),
                "segments": segments,
            }),
        ),
        Err(error) => relay_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok":false,"reason":"flush_failed","detail":error.to_string()}),
        ),
    }
}

async fn relay_not_found() -> Response {
    relay_response(
        StatusCode::NOT_FOUND,
        json!({"ok":false,"reason":"not_found"}),
    )
}

fn relay_response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

fn relay_body_error_response(error: BodyReadError) -> Response {
    match error {
        BodyReadError::UnsupportedMediaType => relay_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!({"ok":false,"reason":"content_type"}),
        ),
        BodyReadError::InvalidContentLength => relay_response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"reason":"content_length"}),
        ),
        BodyReadError::TooLarge => relay_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"ok":false,"reason":"body_limit"}),
        ),
        BodyReadError::BudgetExhausted => relay_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok":false,"reason":"body_budget"}),
        ),
        BodyReadError::Read(detail) => relay_response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"reason":"body_read","detail":detail}),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::routing::post;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn durable_ack() -> impl IntoResponse {
        (
            StatusCode::ACCEPTED,
            Json(json!({"ok":true,"durable":true,"duplicate":false})),
        )
    }

    async fn durable_batch(
        State(hits): State<Arc<AtomicUsize>>,
        request: Request,
    ) -> impl IntoResponse {
        hits.fetch_add(1, Ordering::Relaxed);
        let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
        let results: Vec<Value> = body
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let capture: Value = serde_json::from_slice(line).unwrap();
                json!({
                    "capture_id": capture["captureId"],
                    "ok": true,
                    "durable": true,
                    "duplicate": false,
                })
            })
            .collect();
        (
            StatusCode::ACCEPTED,
            Json(json!({"ok": true, "durable": true, "results": results})),
        )
    }

    #[tokio::test]
    async fn outbox_restarts_and_delivers_same_capture() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temporary = tempfile::tempdir().unwrap();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let config = RelayConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            store: StoreConfig {
                root: temporary.path().join("outbox"),
                state_root: temporary.path().join("outbox-state"),
                segment_max_bytes: 1024 * 1024,
                segment_max_age: Duration::from_secs(60),
                queue_items: 16,
                batch_records: 8,
                batch_bytes: 1024 * 1024,
                batch_wait: Duration::from_millis(1),
                fsync: true,
            },
            store_shards: 1,
            delivery_state_root: temporary.path().join("delivery"),
            collector_url: format!("http://{address}"),
            delivery_concurrency: 1,
            delivery_queue_items: 16,
            delivery_batch_records: 8,
            delivery_batch_bytes: 1024 * 1024,
            delivery_batch_wait: Duration::from_millis(1),
            max_delivery_inflight_bytes: 4 * 1024 * 1024,
            request_timeout: Duration::from_millis(100),
            base_retry_delay: Duration::from_millis(5),
            max_retry_delay: Duration::from_millis(20),
            max_connections: 16,
            max_envelope_bytes: 1024 * 1024,
            max_inflight_body_bytes: 4 * 1024 * 1024,
            max_batch_records: 32,
        };
        let relay = DurableRelay::open(config.clone()).await.unwrap();
        relay
            .enqueue(
                &serde_json::to_vec(&json!({
                    "captureId":"cap-relay-one",
                    "responseStatus":503,
                    "captureError":"kept"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let records = ["two", "three"]
            .into_iter()
            .map(|suffix| {
                let value = json!({
                    "captureId": format!("cap-relay-{suffix}"),
                    "responseStatus": 503,
                    "captureError": "kept"
                });
                normalize_capture(&serde_json::to_vec(&value).unwrap(), 1024 * 1024).unwrap()
            })
            .collect();
        let results = relay.enqueue_batch(records).await.unwrap();
        assert!(results.iter().all(std::result::Result::is_ok));
        relay.close().await.unwrap();
        drop(relay);

        let listener = TcpListener::bind(address).await.unwrap();
        let batch_hits = Arc::new(AtomicUsize::new(0));
        let server_batch_hits = Arc::clone(&batch_hits);
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/capture", post(durable_ack))
                    .route("/captures", post(durable_batch))
                    .with_state(server_batch_hits),
            )
            .await
            .unwrap();
        });
        let reopened = DurableRelay::open(config).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let health = loop {
            let health = reopened.health().await.unwrap();
            if health.delivered == 3 {
                break health;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(health.delivery_records, 3);
        assert_eq!(health.delivered, 3);
        assert!(batch_hits.load(Ordering::Relaxed) >= 1);
        assert!(health.conservation_ok);
        reopened.close().await.unwrap();
        server.abort();
    }

    #[test]
    fn expired_delivery_lease_returns_to_pending_index() {
        let temporary = tempfile::tempdir().unwrap();
        let ledger = DeliveryLedger::open(&temporary.path().join("delivery.redb")).unwrap();
        let locator = CaptureLocator {
            capture_id: "cap-expired-lease".to_owned(),
            raw_sha256: "0".repeat(64),
            segment_id: 1,
            offset: 0,
            length: 128,
            received_at: None,
            model: None,
        };
        ledger.ensure(&locator).unwrap();
        let claimed = ledger
            .claim_many(
                std::slice::from_ref(&locator.capture_id),
                Duration::from_millis(1),
            )
            .unwrap();
        assert_eq!(claimed.len(), 1);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            ledger.reclaim_expired_inflight(8).unwrap(),
            vec![locator.capture_id.clone()]
        );
        assert_eq!(ledger.pending_ids(8).unwrap(), vec![locator.capture_id]);
        let (_, pending, inflight, _, _, _, _) = ledger.health().unwrap();
        assert_eq!((pending, inflight), (1, 0));
    }
}
