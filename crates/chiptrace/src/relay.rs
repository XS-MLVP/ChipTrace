use crate::capture::{
    CaptureRecord, WireCaptureEvidence, normalize_capture, normalize_wire_capture,
    normalize_wire_capture_batch,
};
use crate::cloud_ingest::{
    CloudEndpoint, CloudIngestBatch, QUALITY_REASON_CODES, prepare_cloud_ingest,
    quality_error_reasons,
};
use crate::ingest::{BodyReadError, InflightBodyBudget};
use crate::jsonl::utc_now;
use crate::managed_models::{CATALOG_SOURCE_VERSION, managed_model_catalog};
use crate::sharded::{ShardedCaptureStore, ShardedStoreHealth};
use crate::store::{CaptureLocator, StoreConfig, SubmitAck, SubmitError, SubmitErrorKind};
use anyhow::{Context, Result, bail};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{StatusCode, header::AUTHORIZATION};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::{self, StreamExt};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
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
const INGEST_QUALITY_COUNTERS_KEY: &str = "ingest_quality_counters_v1";
const INGEST_QUALITY_SEED_SCHEMA_VERSION: &str = "chiptrace.ingest-quality-seed.v1";
const INGEST_QUALITY_SEED_FILE: &str = "ingest-quality-seed.json";
const MAX_INGEST_QUALITY_SEED_BYTES: u64 = 64 * 1024;
const INGEST_COVERAGE_FRESHNESS_WINDOW_MS: u64 = 5 * 60 * 1_000;
const LEGACY_UNCLASSIFIED_QUALITY_REASON: &str = "legacy_unclassified";
const MIN_DELIVERY_READ_CONCURRENCY: usize = 4;
const MAX_DELIVERY_READ_CONCURRENCY: usize = 16;

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
    /// Every mutating ingest route requires this token in production.
    pub ingest_bearer_token: Option<String>,
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

/// Quality errors are durable evidence about producer data, rather than a
/// process-local health sample. Keeping these counters in the Delivery ledger
/// prevents a Relay restart from turning a known malformed source into a
/// false green readiness result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IngestQualityCounters {
    #[serde(default)]
    otlp_logs_unknown_events: u64,
    #[serde(default)]
    otlp_logs_conversion_errors: u64,
    #[serde(default)]
    otlp_traces_unknown_events: u64,
    #[serde(default)]
    otlp_traces_conversion_errors: u64,
    #[serde(default)]
    codex_hook_unknown_events: u64,
    #[serde(default)]
    codex_hook_conversion_errors: u64,
    #[serde(default)]
    otlp_logs_quality_reasons: BTreeMap<String, u64>,
    #[serde(default)]
    otlp_traces_quality_reasons: BTreeMap<String, u64>,
    #[serde(default)]
    codex_hook_quality_reasons: BTreeMap<String, u64>,
}

/// One-time migration evidence for a Delivery ledger created before quality
/// counters were durable. The file is read only when the ledger has no
/// `ingest_quality_counters_v1` key; once imported, the ledger remains the
/// source of truth and later restarts cannot silently lower the counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IngestQualitySeed {
    schema_version: String,
    source_quality_errors: u64,
    counters: IngestQualityCounters,
}

impl IngestQualitySeed {
    fn into_counters(self) -> Result<IngestQualityCounters> {
        if self.schema_version != INGEST_QUALITY_SEED_SCHEMA_VERSION {
            bail!(
                "unsupported ingest quality seed schema: {}",
                self.schema_version
            );
        }
        let mut counters = self.counters;
        counters.reconcile_reason_maps()?;
        let total = counters.checked_total()?;
        if self.source_quality_errors != total {
            bail!(
                "ingest quality seed total mismatch: source={}, counters={}",
                self.source_quality_errors,
                total
            );
        }
        Ok(counters)
    }
}

impl IngestQualityCounters {
    fn add(
        &mut self,
        endpoint: CloudEndpoint,
        unknown_events: u64,
        conversion_errors: u64,
        reasons: &BTreeMap<String, u64>,
    ) -> Result<()> {
        let expected = unknown_events
            .checked_add(conversion_errors)
            .context("quality reason total overflow")?;
        let observed = reasons.values().try_fold(0_u64, |total, count| {
            total
                .checked_add(*count)
                .context("quality reason map total overflow")
        })?;
        if observed != expected {
            bail!(
                "quality reason total mismatch for {}: reasons={}, expected={}",
                endpoint.as_str(),
                observed,
                expected
            );
        }
        for reason in reasons.keys() {
            if !is_quality_reason(reason) {
                bail!("unsupported quality reason code: {reason}");
            }
        }
        // Build the new ledger value off to the side.  A failed checked
        // addition must leave the caller's in-memory counters untouched as
        // well as aborting the surrounding durable transaction.
        let mut updated = self.clone();
        match endpoint {
            CloudEndpoint::OtlpLogs => {
                updated.otlp_logs_unknown_events = updated
                    .otlp_logs_unknown_events
                    .checked_add(unknown_events)
                    .context("OTLP logs unknown-event counter overflow")?;
                updated.otlp_logs_conversion_errors = updated
                    .otlp_logs_conversion_errors
                    .checked_add(conversion_errors)
                    .context("OTLP logs conversion-error counter overflow")?;
            }
            CloudEndpoint::OtlpTraces => {
                updated.otlp_traces_unknown_events = updated
                    .otlp_traces_unknown_events
                    .checked_add(unknown_events)
                    .context("OTLP traces unknown-event counter overflow")?;
                updated.otlp_traces_conversion_errors = updated
                    .otlp_traces_conversion_errors
                    .checked_add(conversion_errors)
                    .context("OTLP traces conversion-error counter overflow")?;
            }
            CloudEndpoint::CodexHook => {
                updated.codex_hook_unknown_events = updated
                    .codex_hook_unknown_events
                    .checked_add(unknown_events)
                    .context("Hook unknown-event counter overflow")?;
                updated.codex_hook_conversion_errors = updated
                    .codex_hook_conversion_errors
                    .checked_add(conversion_errors)
                    .context("Hook conversion-error counter overflow")?;
            }
        }
        let destination = updated.reasons_mut(endpoint);
        for (reason, count) in reasons {
            let value = destination.entry(reason.clone()).or_insert(0);
            *value = value
                .checked_add(*count)
                .context("quality reason counter overflow")?;
        }
        *self = updated;
        Ok(())
    }

    fn reasons_mut(&mut self, endpoint: CloudEndpoint) -> &mut BTreeMap<String, u64> {
        match endpoint {
            CloudEndpoint::OtlpLogs => &mut self.otlp_logs_quality_reasons,
            CloudEndpoint::OtlpTraces => &mut self.otlp_traces_quality_reasons,
            CloudEndpoint::CodexHook => &mut self.codex_hook_quality_reasons,
        }
    }

    fn reasons(&self, endpoint: CloudEndpoint) -> &BTreeMap<String, u64> {
        match endpoint {
            CloudEndpoint::OtlpLogs => &self.otlp_logs_quality_reasons,
            CloudEndpoint::OtlpTraces => &self.otlp_traces_quality_reasons,
            CloudEndpoint::CodexHook => &self.codex_hook_quality_reasons,
        }
    }

    #[cfg(test)]
    fn total(&self) -> Result<u64> {
        self.checked_total()
    }

    fn checked_total(&self) -> Result<u64> {
        let mut total = 0_u64;
        for count in [
            self.otlp_logs_unknown_events,
            self.otlp_logs_conversion_errors,
            self.otlp_traces_unknown_events,
            self.otlp_traces_conversion_errors,
            self.codex_hook_unknown_events,
            self.codex_hook_conversion_errors,
        ] {
            total = total
                .checked_add(count)
                .context("durable quality counter total overflow")?;
        }
        Ok(total)
    }

    fn reconcile_reason_maps(&mut self) -> Result<()> {
        for endpoint in [
            CloudEndpoint::OtlpLogs,
            CloudEndpoint::OtlpTraces,
            CloudEndpoint::CodexHook,
        ] {
            let expected = match endpoint {
                CloudEndpoint::OtlpLogs => self
                    .otlp_logs_unknown_events
                    .checked_add(self.otlp_logs_conversion_errors)
                    .context("OTLP logs quality counter overflow")?,
                CloudEndpoint::OtlpTraces => self
                    .otlp_traces_unknown_events
                    .checked_add(self.otlp_traces_conversion_errors)
                    .context("OTLP traces quality counter overflow")?,
                CloudEndpoint::CodexHook => self
                    .codex_hook_unknown_events
                    .checked_add(self.codex_hook_conversion_errors)
                    .context("Hook quality counter overflow")?,
            };
            let reasons = self.reasons_mut(endpoint);
            if reasons.keys().any(|reason| !is_quality_reason(reason)) {
                bail!("ingest quality ledger contains an unsupported reason code");
            }
            let observed = reasons.values().try_fold(0_u64, |total, count| {
                total
                    .checked_add(*count)
                    .context("quality reason map total overflow")
            })?;
            if observed > expected {
                bail!(
                    "ingest quality reason total exceeds endpoint total for {}",
                    endpoint.as_str()
                );
            }
            if observed < expected {
                let legacy = reasons
                    .entry(LEGACY_UNCLASSIFIED_QUALITY_REASON.to_owned())
                    .or_insert(0);
                *legacy = legacy
                    .checked_add(expected - observed)
                    .context("legacy quality reason counter overflow")?;
            }
        }
        self.checked_total()?;
        Ok(())
    }
}

fn is_quality_reason(reason: &str) -> bool {
    reason == LEGACY_UNCLASSIFIED_QUALITY_REASON || QUALITY_REASON_CODES.contains(&reason)
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayHealth {
    pub ok: bool,
    pub status: &'static str,
    pub collector_url: String,
    pub local: ShardedStoreHealth,
    pub delivery_records: u64,
    pub pending: u64,
    pub inflight: u64,
    pub delivered: u64,
    pub conflicts: u64,
    pub failed: u64,
    pub delivery_attempts: u64,
    /// Attempts beyond the first attempt for each durable delivery record.
    /// This is derived from the durable counters and is an operational
    /// backpressure signal, not a delivery success claim.
    pub delivery_retries: u64,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub delivery_body_budget_available: usize,
    pub delivery_body_budget_capacity: usize,
    pub conservation_ok: bool,
    pub backlog_degraded: bool,
    pub ingest_auth_required: bool,
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
            let quality_history_missing = meta.get(INGEST_QUALITY_COUNTERS_KEY)?.is_none();
            drop(meta);
            let quality_seed = if quality_history_missing {
                read_ingest_quality_seed(path)?
            } else {
                None
            };
            if quality_history_missing {
                let deliveries = transaction.open_table(DELIVERIES)?;
                if deliveries.len()? > 0 && quality_seed.is_none() {
                    bail!(
                        "Relay delivery ledger requires ingest quality history migration; create {} beside the ledger",
                        INGEST_QUALITY_SEED_FILE
                    );
                }
                drop(deliveries);
                let mut meta = transaction.open_table(META)?;
                write_ingest_quality_counters(&mut meta, &quality_seed.unwrap_or_default())?;
                drop(meta);
            }

            // Delivery and index updates are committed in one redb
            // transaction.  Once the durable counters and index lengths agree,
            // rebuilding every delivery row on each restart only turns a
            // bounded recovery check into an O(total-records) NFS scan.  Keep
            // the old full rebuild as a repair path for old/corrupt ledgers,
            // and only inspect the small inflight index when a lease needs to
            // be returned to pending.
            let fast_startup = {
                let meta = transaction.open_table(META)?;
                let counters = meta
                    .get(DELIVERY_COUNTERS_KEY)?
                    .map(|value| serde_json::from_slice::<DeliveryCounters>(value.value()))
                    .transpose()?;
                drop(meta);
                let lengths = {
                    let deliveries = transaction.open_table(DELIVERIES)?;
                    let pending = transaction.open_table(PENDING_DELIVERIES)?;
                    let inflight = transaction.open_table(INFLIGHT_DELIVERIES)?;
                    (deliveries.len()?, pending.len()?, inflight.len()?)
                };
                match counters {
                    None => false,
                    Some(counters)
                        if counters.total != lengths.0
                            || counters.pending != lengths.1
                            || counters.inflight != lengths.2 =>
                    {
                        false
                    }
                    Some(counters) if counters.inflight == 0 => true,
                    Some(counters) => {
                        // Validate all indexed inflight rows before mutating the
                        // transaction.  Any stale index falls through to the
                        // existing full rebuild path without partial changes.
                        let inflight_rows: Vec<(String, String)> = {
                            let inflight = transaction.open_table(INFLIGHT_DELIVERIES)?;
                            inflight
                                .iter()?
                                .map(|row| {
                                    let (key, value) = row?;
                                    Ok((
                                        key.value().to_owned(),
                                        std::str::from_utf8(value.value())?.to_owned(),
                                    ))
                                })
                                .collect::<Result<Vec<_>>>()?
                        };
                        let valid = {
                            let deliveries = transaction.open_table(DELIVERIES)?;
                            inflight_rows.iter().try_fold(
                                true,
                                |valid, (key, capture_id)| -> Result<bool> {
                                    if !valid {
                                        return Ok(false);
                                    }
                                    let Some(value) = deliveries.get(capture_id.as_str())? else {
                                        return Ok(false);
                                    };
                                    let record: DeliveryRecord =
                                        serde_json::from_slice(value.value())?;
                                    Ok(record.state == "inflight"
                                        && record.capture_id == *capture_id
                                        && delivery_index_due(key)
                                            == Some(record.lease_until_unix_ms))
                                },
                            )?
                        };
                        if !valid {
                            false
                        } else {
                            let mut deliveries = transaction.open_table(DELIVERIES)?;
                            let mut pending = transaction.open_table(PENDING_DELIVERIES)?;
                            let mut inflight = transaction.open_table(INFLIGHT_DELIVERIES)?;
                            let mut meta = transaction.open_table(META)?;
                            let mut counters = counters;
                            for (key, capture_id) in inflight_rows {
                                inflight.remove(key.as_str())?;
                                let mut record: DeliveryRecord = serde_json::from_slice(
                                    deliveries
                                        .get(capture_id.as_str())?
                                        .context("inflight delivery row disappeared")?
                                        .value(),
                                )?;
                                counters.inflight = counters.inflight.saturating_sub(1);
                                counters.pending = counters.pending.saturating_add(1);
                                record.state = "pending".to_owned();
                                record.next_attempt_unix_ms = 0;
                                record.lease_until_unix_ms = 0;
                                record.last_error =
                                    Some("delivery lease recovered during startup".to_owned());
                                pending.insert(
                                    delivery_index_key(0, &record.capture_id).as_str(),
                                    record.capture_id.as_bytes(),
                                )?;
                                deliveries.insert(
                                    record.capture_id.as_str(),
                                    serde_json::to_vec(&record)?.as_slice(),
                                )?;
                            }
                            write_delivery_counters(&mut meta, &counters)?;
                            true
                        }
                    }
                }
            };
            if fast_startup {
                transaction.commit()?;
                return Ok(Self { database });
            }
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

    fn ingest_quality_counters(&self) -> Result<IngestQualityCounters> {
        let transaction = self.database.begin_read()?;
        let meta = transaction.open_table(META)?;
        read_ingest_quality_counters(&meta)
    }

    fn record_ingest_quality_with_reasons(
        &self,
        endpoint: CloudEndpoint,
        unknown_events: u64,
        conversion_errors: u64,
        reasons: &BTreeMap<String, u64>,
    ) -> Result<IngestQualityCounters> {
        if unknown_events == 0 && conversion_errors == 0 {
            return self.ingest_quality_counters();
        }
        let transaction = self.database.begin_write()?;
        let counters = {
            let mut meta = transaction.open_table(META)?;
            let mut counters = read_ingest_quality_counters(&meta)?;
            counters.add(endpoint, unknown_events, conversion_errors, reasons)?;
            write_ingest_quality_counters(&mut meta, &counters)?;
            counters
        };
        transaction.commit()?;
        Ok(counters)
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

fn read_ingest_quality_seed(path: &Path) -> Result<Option<IngestQualityCounters>> {
    let seed_path = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(INGEST_QUALITY_SEED_FILE);
    let metadata = match fs::symlink_metadata(&seed_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() {
        bail!(
            "Relay ingest quality seed must be a regular file: {}",
            seed_path.display()
        );
    }
    if metadata.len() > MAX_INGEST_QUALITY_SEED_BYTES {
        bail!(
            "Relay ingest quality seed exceeds {} bytes",
            MAX_INGEST_QUALITY_SEED_BYTES
        );
    }
    let bytes = fs::read(&seed_path)?;
    let seed: IngestQualitySeed = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid Relay ingest quality seed: {}", seed_path.display()))?;
    seed.into_counters().map(Some)
}

fn read_ingest_quality_counters<T>(meta: &T) -> Result<IngestQualityCounters>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    let mut counters: IngestQualityCounters = meta
        .get(INGEST_QUALITY_COUNTERS_KEY)?
        .map(|value| serde_json::from_slice(value.value()).map_err(anyhow::Error::from))
        .transpose()
        .map(|value| value.unwrap_or_default())?;
    counters.reconcile_reason_maps()?;
    Ok(counters)
}

fn write_ingest_quality_counters(
    meta: &mut redb::Table<'_, &'static str, &'static [u8]>,
    counters: &IngestQualityCounters,
) -> Result<()> {
    let mut checked = counters.clone();
    checked.reconcile_reason_maps()?;
    let bytes = serde_json::to_vec(&checked)?;
    meta.insert(INGEST_QUALITY_COUNTERS_KEY, bytes.as_slice())?;
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
        // `ensure_many` is transactional with every new Capture write.  The
        // monotonic Capture count and delivery-ledger total therefore provide
        // a safe normal-start check; only a mismatch needs the expensive full
        // WAL/index reconciliation (for example after an interrupted old
        // release or a manual repair).
        let delivery_total = ledger.lock().expect("delivery ledger poisoned").health()?.0;
        if delivery_total != store.health().captures {
            let locators = store.list_captures().await?;
            for batch in locators.chunks(4096) {
                ledger
                    .lock()
                    .expect("delivery ledger poisoned")
                    .ensure_many(batch)?;
            }
        }
        let (sender, receiver) = flume::bounded(config.delivery_queue_items);
        let (shutdown, _) = watch::channel(false);
        let _ = rustls::crypto::ring::default_provider().install_default();
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
        self.enqueue_record(record).await
    }

    async fn enqueue_record(&self, record: CaptureRecord) -> Result<SubmitAck> {
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

    fn ingest_quality_counters(&self) -> Result<IngestQualityCounters> {
        self.inner
            .ledger
            .lock()
            .expect("delivery ledger poisoned")
            .ingest_quality_counters()
    }

    fn record_ingest_quality_with_reasons(
        &self,
        endpoint: CloudEndpoint,
        unknown_events: u64,
        conversion_errors: u64,
        reasons: &BTreeMap<String, u64>,
    ) -> Result<IngestQualityCounters> {
        self.inner
            .ledger
            .lock()
            .expect("delivery ledger poisoned")
            .record_ingest_quality_with_reasons(
                endpoint,
                unknown_events,
                conversion_errors,
                reasons,
            )
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
        let conservation_ok = total == pending + inflight + delivered + conflicts + failed;
        let delivery_retries = attempts.saturating_sub(total);
        let unsettled = pending.saturating_add(inflight);
        let backlog_degraded = total >= 32 && unsettled.saturating_mul(10) > total;
        let ok = local.ok && conservation_ok && conflicts == 0 && failed == 0 && !backlog_degraded;
        Ok(RelayHealth {
            ok,
            status: if ok { "healthy" } else { "degraded" },
            collector_url: self.inner.config.collector_url.clone(),
            local,
            delivery_records: total,
            pending,
            inflight,
            delivered,
            conflicts,
            failed,
            delivery_attempts: attempts,
            delivery_retries,
            queue_depth: self.inner.sender.len(),
            queue_capacity: self.inner.sender.capacity().unwrap_or(0),
            delivery_body_budget_available: self.inner.delivery_body_budget.available_permits(),
            delivery_body_budget_capacity: self.inner.config.max_delivery_inflight_bytes,
            conservation_ok,
            backlog_degraded,
            ingest_auth_required: self.inner.config.ingest_bearer_token.is_some(),
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

fn delivery_read_concurrency(config: &RelayConfig) -> usize {
    config
        .delivery_concurrency
        .clamp(MIN_DELIVERY_READ_CONCURRENCY, MAX_DELIVERY_READ_CONCURRENCY)
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
    // Keep body reads proportional to the worker pool while bounding the
    // number of concurrent filesystem reads. The byte semaphore below still
    // limits aggregate resident delivery bodies, including very large ones.
    let mut reads = reads.buffer_unordered(delivery_read_concurrency(&inner.config));
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
    if !status.is_success() {
        return batch
            .iter()
            .map(|payload| http_delivery_failure(inner, &payload.record, status))
            .collect();
    }
    let payload: Value = match response.json().await {
        Ok(payload) => payload,
        Err(_) => {
            return batch
                .iter()
                .map(|payload| {
                    retry_update(
                        inner,
                        &payload.record,
                        "invalid Collector batch acknowledgement JSON".to_owned(),
                    )
                })
                .collect();
        }
    };
    let outcomes = payload
        .get("results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut by_id = std::collections::HashMap::new();
    let mut ambiguous_ids = HashSet::new();
    for outcome in outcomes {
        if let Some(capture_id) = outcome.get("capture_id").and_then(Value::as_str)
            && by_id.insert(capture_id, outcome).is_some()
        {
            ambiguous_ids.insert(capture_id);
        }
    }
    batch
        .iter()
        .map(|payload| {
            let record = &payload.record;
            if ambiguous_ids.contains(record.capture_id.as_str()) {
                return retry_update(
                    inner,
                    record,
                    "duplicate Collector batch outcomes for Capture".to_owned(),
                );
            }
            match by_id.get(record.capture_id.as_str()) {
                Some(outcome)
                    if outcome.get("ok").and_then(Value::as_bool) == Some(true)
                        || outcome.get("durable").and_then(Value::as_bool) == Some(true) =>
                {
                    match verify_collector_receipt(record, outcome) {
                        Ok(()) => delivered_update(record),
                        Err(error) => retry_update(inner, record, error.to_owned()),
                    }
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
                        .and_then(|status| u16::try_from(status).ok())
                        .and_then(|status| StatusCode::from_u16(status).ok());
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
                None => retry_update(
                    inner,
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
    if !status.is_success() {
        return http_delivery_failure(inner, record, status);
    }
    let payload: Value = match response.json().await {
        Ok(payload) => payload,
        Err(_) => {
            return retry_update(
                inner,
                record,
                "invalid Collector acknowledgement JSON".to_owned(),
            );
        }
    };
    match verify_collector_receipt(record, &payload) {
        Ok(()) => delivered_update(record),
        Err(error) => retry_update(inner, record, error.to_owned()),
    }
}

fn verify_collector_receipt(
    record: &DeliveryRecord,
    payload: &Value,
) -> std::result::Result<(), &'static str> {
    if payload.get("ok").and_then(Value::as_bool) != Some(true)
        || payload.get("durable").and_then(Value::as_bool) != Some(true)
    {
        return Err("Collector acknowledgement does not confirm durability");
    }
    let ack: SubmitAck =
        serde_json::from_value(payload.get("capture").cloned().unwrap_or(Value::Null))
            .map_err(|_| "Collector acknowledgement has no valid Capture receipt")?;
    if ack.capture_id != record.capture_id || ack.raw_sha256 != record.raw_sha256 {
        return Err("Collector Capture receipt identity or SHA-256 mismatch");
    }
    if record.bytes == 0 || ack.length != record.bytes {
        return Err("Collector Capture receipt byte length mismatch");
    }
    if !ack.durable
        || payload.get("duplicate").and_then(Value::as_bool) != Some(ack.duplicate)
        || !matches!(
            (ack.state.as_str(), ack.duplicate),
            ("accepted", false) | ("duplicate", true)
        )
    {
        return Err("Collector Capture receipt state is inconsistent");
    }
    // Collector and Relay have independent WAL layouts; only require a valid
    // remote locator, never equality with the Relay's local segment or offset.
    if ack.segment_id == 0 || ack.offset.checked_add(ack.length).is_none() {
        return Err("Collector Capture receipt locator is invalid");
    }
    if let Some(status) = payload.get("http_status")
        && !status
            .as_u64()
            .and_then(|status| u16::try_from(status).ok())
            .and_then(|status| StatusCode::from_u16(status).ok())
            .is_some_and(|status| status.is_success())
    {
        return Err("Collector Capture receipt contradicts item HTTP status");
    }
    Ok(())
}

fn http_delivery_failure(
    inner: &RelayInner,
    record: &DeliveryRecord,
    status: StatusCode,
) -> DeliveryUpdate {
    let error = format!("remote HTTP {status}");
    if status == StatusCode::CONFLICT {
        conflict_update(record, error)
    } else if is_retryable(status) {
        retry_update(inner, record, error)
    } else {
        failed_update(record, error)
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
    ingest_coverage: Arc<Mutex<IngestCoverageState>>,
}

#[derive(Debug, Clone, Default)]
struct RouteCoverage {
    requests: u64,
    source_records: u64,
    durable_captures: u64,
    duplicates: u64,
    quality_unknown_events: u64,
    quality_conversion_errors: u64,
    quality_reasons: BTreeMap<String, u64>,
    last_at: Option<String>,
    first_observed_millis: Option<u64>,
    last_observed_millis: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct WireTurnCoverage {
    turn_scoped_captures: u64,
    successful_turn_scoped_captures: u64,
    unscoped_captures: u64,
    identity_conflict_captures: u64,
    last_successful_at: Option<String>,
    last_successful_observed_millis: Option<u64>,
}

#[derive(Debug, Clone)]
struct IngestCoverageState {
    started_at: String,
    wire: RouteCoverage,
    wire_turn_coverage: WireTurnCoverage,
    otlp_logs: RouteCoverage,
    otlp_traces: RouteCoverage,
    hooks: RouteCoverage,
    lifecycle_events: u64,
    tool_executions: u64,
    quality_errors: u64,
    quality_errors_current_process: u64,
}

impl IngestCoverageState {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_quality_counters(IngestQualityCounters::default())
            .expect("default quality counters must be valid")
    }

    fn with_quality_counters(counters: IngestQualityCounters) -> Result<Self> {
        let quality_errors = counters.checked_total()?;
        let mut state = Self {
            started_at: utc_now(),
            wire: RouteCoverage::default(),
            wire_turn_coverage: WireTurnCoverage::default(),
            otlp_logs: RouteCoverage::default(),
            otlp_traces: RouteCoverage::default(),
            hooks: RouteCoverage::default(),
            lifecycle_events: 0,
            tool_executions: 0,
            quality_errors,
            quality_errors_current_process: 0,
        };
        state.otlp_logs.quality_unknown_events = counters.otlp_logs_unknown_events;
        state.otlp_logs.quality_conversion_errors = counters.otlp_logs_conversion_errors;
        state.otlp_logs.quality_reasons = counters.reasons(CloudEndpoint::OtlpLogs).clone();
        state.otlp_traces.quality_unknown_events = counters.otlp_traces_unknown_events;
        state.otlp_traces.quality_conversion_errors = counters.otlp_traces_conversion_errors;
        state.otlp_traces.quality_reasons = counters.reasons(CloudEndpoint::OtlpTraces).clone();
        state.hooks.quality_unknown_events = counters.codex_hook_unknown_events;
        state.hooks.quality_conversion_errors = counters.codex_hook_conversion_errors;
        state.hooks.quality_reasons = counters.reasons(CloudEndpoint::CodexHook).clone();
        Ok(state)
    }

    fn observe_wire(&mut self, acknowledged: &[(WireCaptureEvidence, bool)]) {
        if acknowledged.is_empty() {
            return;
        }
        let durable = acknowledged.len() as u64;
        let duplicates = acknowledged
            .iter()
            .filter(|(_, duplicate)| *duplicate)
            .count() as u64;
        let observed_millis = unix_millis();
        let observed_at = utc_now();
        self.wire.requests = self.wire.requests.saturating_add(1);
        self.wire.source_records = self.wire.source_records.saturating_add(durable);
        self.wire.durable_captures = self.wire.durable_captures.saturating_add(durable);
        self.wire.duplicates = self.wire.duplicates.saturating_add(duplicates);
        self.wire
            .first_observed_millis
            .get_or_insert(observed_millis);
        self.wire.last_observed_millis = Some(observed_millis);
        self.wire.last_at = Some(observed_at.clone());
        let turns = &mut self.wire_turn_coverage;
        for (evidence, duplicate) in acknowledged {
            if evidence.turn_scoped {
                turns.turn_scoped_captures = turns.turn_scoped_captures.saturating_add(1);
                if evidence.http_success {
                    turns.successful_turn_scoped_captures =
                        turns.successful_turn_scoped_captures.saturating_add(1);
                    // Retrying an already durable capture cannot keep business
                    // evidence fresh indefinitely.
                    if !duplicate {
                        turns.last_successful_at = Some(observed_at.clone());
                        turns.last_successful_observed_millis = Some(observed_millis);
                    }
                }
            } else {
                turns.unscoped_captures = turns.unscoped_captures.saturating_add(1);
            }
            if evidence.identity_conflict {
                turns.identity_conflict_captures =
                    turns.identity_conflict_captures.saturating_add(1);
            }
        }
    }

    fn observe_cloud(
        &mut self,
        endpoint: CloudEndpoint,
        summary: &crate::cloud_ingest::CloudIngestSummary,
        durable_captures: u64,
        duplicates: u64,
        lifecycle_events: u64,
        tool_executions: u64,
    ) {
        let route = match endpoint {
            CloudEndpoint::OtlpLogs => &mut self.otlp_logs,
            CloudEndpoint::OtlpTraces => &mut self.otlp_traces,
            CloudEndpoint::CodexHook => &mut self.hooks,
        };
        route.requests = route.requests.saturating_add(1);
        route.source_records = route.source_records.saturating_add(summary.source_records);
        route.durable_captures = route.durable_captures.saturating_add(durable_captures);
        route.duplicates = route.duplicates.saturating_add(duplicates);
        let observed_millis = unix_millis();
        route.first_observed_millis.get_or_insert(observed_millis);
        route.last_observed_millis = Some(observed_millis);
        route.last_at = Some(utc_now());
        self.lifecycle_events = self.lifecycle_events.saturating_add(lifecycle_events);
        self.tool_executions = self.tool_executions.saturating_add(tool_executions);
        let conversion_errors = summary.conversion_errors.len() as u64;
        let quality_errors = summary.unknown_events.saturating_add(conversion_errors);
        self.quality_errors = self.quality_errors.saturating_add(quality_errors);
        self.quality_errors_current_process = self
            .quality_errors_current_process
            .saturating_add(quality_errors);
        route.quality_unknown_events = route
            .quality_unknown_events
            .saturating_add(summary.unknown_events);
        route.quality_conversion_errors = route
            .quality_conversion_errors
            .saturating_add(conversion_errors);
        for (reason, count) in quality_error_reasons(summary) {
            let value = route.quality_reasons.entry(reason).or_insert(0);
            *value = value.saturating_add(count);
        }
    }

    fn snapshot(&self) -> Value {
        self.snapshot_at(unix_millis())
    }

    fn snapshot_at(&self, now_millis: u64) -> Value {
        let turns = &self.wire_turn_coverage;
        let successful_turn_scoped_age_ms = turns
            .last_successful_observed_millis
            .map(|last| now_millis.saturating_sub(last));
        let sources_observed = self.wire.requests > 0
            && self.otlp_logs.requests > 0
            && self.otlp_traces.requests > 0
            && self.hooks.requests > 0;
        let any_observed = self.wire.requests > 0
            || self.otlp_logs.requests > 0
            || self.otlp_traces.requests > 0
            || self.hooks.requests > 0;
        let required_routes = [
            ("otlp_logs", &self.otlp_logs),
            ("otlp_traces", &self.otlp_traces),
            ("hooks", &self.hooks),
        ];
        let wire_age_ms = self
            .wire
            .last_observed_millis
            .map(|last| now_millis.saturating_sub(last));
        let wire_active = wire_age_ms.is_some_and(|age| age <= INGEST_COVERAGE_FRESHNESS_WINDOW_MS);
        let latest_runtime_millis = required_routes
            .iter()
            .filter_map(|(_, route)| route.last_observed_millis)
            .max();
        let runtime_age_ms = latest_runtime_millis.map(|last| now_millis.saturating_sub(last));
        let runtime_active =
            runtime_age_ms.is_some_and(|age| age <= INGEST_COVERAGE_FRESHNESS_WINDOW_MS);
        let wire_lag_ms = latest_runtime_millis.and_then(|runtime_last| {
            self.wire
                .last_observed_millis
                .map(|wire_last| runtime_last.saturating_sub(wire_last))
        });
        let wire_observed_long_enough = self.wire.first_observed_millis.is_some_and(|first| {
            now_millis.saturating_sub(first) > INGEST_COVERAGE_FRESHNESS_WINDOW_MS
        });
        let missing_sources: Vec<&str> = std::iter::once(("wire", &self.wire))
            .chain(required_routes)
            .filter_map(|(name, route)| (route.requests == 0).then_some(name))
            .collect();
        let mut stale_sources: Vec<&str> = self
            .wire
            .last_observed_millis
            .map(|wire_last| {
                required_routes
                    .iter()
                    .filter_map(|(name, route)| {
                        route.last_observed_millis.and_then(|last| {
                            (wire_last.saturating_sub(last) > INGEST_COVERAGE_FRESHNESS_WINDOW_MS)
                                .then_some(*name)
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let wire_out_of_sync = runtime_active
            && (!wire_active
                || wire_lag_ms.is_some_and(|lag| lag > INGEST_COVERAGE_FRESHNESS_WINDOW_MS));
        if wire_out_of_sync {
            stale_sources.push("wire");
        }
        let required_sources_fresh = sources_observed && stale_sources.is_empty();
        let degraded = wire_out_of_sync
            || (wire_active
                && (!stale_sources.is_empty()
                    || (wire_observed_long_enough && !missing_sources.is_empty())));
        let status = if degraded {
            "degraded"
        } else if sources_observed && required_sources_fresh {
            "complete"
        } else if any_observed {
            "partial"
        } else {
            "warming"
        };
        let successful_turn_scoped_fresh = successful_turn_scoped_age_ms
            .is_some_and(|age| age <= INGEST_COVERAGE_FRESHNESS_WINDOW_MS);
        let quality_breakdown_complete = quality_reason_breakdown_complete(
            self.quality_errors,
            [&self.otlp_logs, &self.otlp_traces, &self.hooks],
        );
        // This is a process-level canary signal. It proves that the Relay has
        // recently received at least one fresh, identity-scoped successful
        // Turn Wire alongside synchronized source routes; it never claims
        // that any particular Session is complete.
        let turn_capture_ready = status == "complete"
            && turns.successful_turn_scoped_captures > 0
            && successful_turn_scoped_fresh;
        json!({
            "scope":"current_relay_process",
            "quality_errors_scope":"durable_relay_state",
            "started_at":self.started_at,
            "status":status,
            "required_sources_observed":sources_observed,
            "required_sources_fresh":required_sources_fresh,
            "freshness_applicable":wire_active || runtime_active,
            "freshness_window_ms":INGEST_COVERAGE_FRESHNESS_WINDOW_MS,
            "wire_age_ms":wire_age_ms,
            "runtime_age_ms":runtime_age_ms,
            "runtime_active":runtime_active,
            "wire_lag_ms":wire_lag_ms,
            "missing_sources":missing_sources,
            "stale_sources":stale_sources,
            "source_lag_ms":{
                "otlp_logs":source_lag_ms(&self.wire, &self.otlp_logs),
                "otlp_traces":source_lag_ms(&self.wire, &self.otlp_traces),
                "hooks":source_lag_ms(&self.wire, &self.hooks),
            },
            "buyer_eligibility_claimed":false,
            "session_delivery_claimed":false,
            "turn_capture_ready":turn_capture_ready,
            "wire":route_coverage_value(&self.wire),
            "wire_turn_coverage":{
                "success_definition":"http_2xx",
                "freshness_definition":"new_durable_capture",
                "turn_scoped_captures":turns.turn_scoped_captures,
                "successful_turn_scoped_captures":turns.successful_turn_scoped_captures,
                "unscoped_captures":turns.unscoped_captures,
                "identity_conflict_captures":turns.identity_conflict_captures,
                "last_successful_at":turns.last_successful_at,
                "last_successful_age_ms":successful_turn_scoped_age_ms,
                "successful_turn_scoped_fresh":successful_turn_scoped_fresh,
            },
            "otlp_logs":route_coverage_value(&self.otlp_logs),
            "otlp_traces":route_coverage_value(&self.otlp_traces),
            "hooks":route_coverage_value(&self.hooks),
            "quality_errors_by_endpoint":{
                "otlp_logs":route_quality_value(&self.otlp_logs),
                "otlp_traces":route_quality_value(&self.otlp_traces),
                "hooks":route_quality_value(&self.hooks),
            },
            "quality_reason_breakdown_complete":quality_breakdown_complete,
            "derived":{
                "lifecycle_events":self.lifecycle_events,
                "tool_executions":self.tool_executions,
            },
            "quality_errors":self.quality_errors,
            "quality_errors_current_process":self.quality_errors_current_process,
        })
    }
}

fn route_coverage_value(route: &RouteCoverage) -> Value {
    json!({
        "requests":route.requests,
        "source_records":route.source_records,
        "durable_captures":route.durable_captures,
        "duplicates":route.duplicates,
        "last_at":route.last_at,
    })
}

fn route_quality_value(route: &RouteCoverage) -> Value {
    json!({
        "unknown_events":route.quality_unknown_events,
        "conversion_errors":route.quality_conversion_errors,
        "total":route
            .quality_unknown_events
            .saturating_add(route.quality_conversion_errors),
        "reasons":route.quality_reasons,
    })
}

fn quality_reason_breakdown_complete(total: u64, routes: [&RouteCoverage; 3]) -> bool {
    let mut sum = 0_u64;
    for route in routes {
        let Some(route_total) = route
            .quality_unknown_events
            .checked_add(route.quality_conversion_errors)
        else {
            return false;
        };
        let Some(next_sum) = sum.checked_add(route_total) else {
            return false;
        };
        let reason_total = route
            .quality_reasons
            .values()
            .try_fold(0_u64, |sum, count| sum.checked_add(*count));
        if route
            .quality_reasons
            .keys()
            .any(|reason| !is_quality_reason(reason))
            || reason_total != Some(route_total)
        {
            return false;
        }
        sum = next_sum;
    }
    sum == total
}

fn source_lag_ms(wire: &RouteCoverage, source: &RouteCoverage) -> Option<u64> {
    Some(
        wire.last_observed_millis?
            .saturating_sub(source.last_observed_millis?),
    )
}

fn derived_record_counts(records: &[CaptureRecord]) -> (u64, u64) {
    records.iter().fold((0_u64, 0_u64), |mut counts, record| {
        if let Ok(value) = serde_json::from_slice::<Value>(&record.canonical) {
            match value.get("recordType").and_then(Value::as_str) {
                Some("lifecycle_event") => counts.0 = counts.0.saturating_add(1),
                Some("tool_execution") => counts.1 = counts.1.saturating_add(1),
                _ => {}
            }
        }
        counts
    })
}

pub async fn serve_relay(
    config: RelayConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let bind = config.bind;
    let max_connections = config.max_connections;
    let max_envelope_bytes = config.max_envelope_bytes;
    let relay = DurableRelay::open(config).await?;
    let ingest_quality_counters = relay.ingest_quality_counters()?;
    let body_budget = InflightBodyBudget::new(
        relay.inner.config.max_inflight_body_bytes,
        relay.inner.config.max_envelope_bytes,
    )?;
    let app = Router::new()
        .route("/capture", post(relay_capture))
        .route("/captures", post(relay_captures))
        .route("/otel/v1/logs", post(relay_otlp_logs))
        .route("/otel/v1/traces", post(relay_otlp_traces))
        .route("/hooks/codex", post(relay_codex_hook))
        .route("/models", get(relay_models))
        .route("/v1/models", get(relay_models))
        .route("/health", get(relay_health))
        .route("/ready", get(relay_ready))
        .route("/flush", post(relay_flush))
        .fallback(relay_not_found)
        .layer(DefaultBodyLimit::max(max_envelope_bytes))
        .layer(ConcurrencyLimitLayer::new(max_connections.max(1)))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(120),
        ))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http().on_failure(crate::http_trace::on_failure))
        .with_state(RelayAppState {
            max_batch_records: relay.inner.config.max_batch_records,
            relay: relay.clone(),
            body_budget,
            ingest_coverage: Arc::new(Mutex::new(IngestCoverageState::with_quality_counters(
                ingest_quality_counters,
            )?)),
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

async fn relay_models(State(state): State<RelayAppState>, request: Request) -> Response {
    if !ingest_authorized(&state, &request) {
        return relay_response(
            StatusCode::UNAUTHORIZED,
            json!({"ok":false,"reason":"ingest_auth_required"}),
        );
    }
    match managed_model_catalog() {
        Ok(catalog) => (
            StatusCode::OK,
            [
                ("content-type", "application/json; charset=utf-8"),
                ("cache-control", "private, max-age=300"),
                ("etag", catalog.etag.as_str()),
                ("x-chiptrace-catalog-source", CATALOG_SOURCE_VERSION),
            ],
            catalog.bytes,
        )
            .into_response(),
        Err(error) => relay_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"ok":false,"reason":"managed_model_catalog_invalid","detail":error.to_string()}),
        ),
    }
}

async fn relay_otlp_logs(State(state): State<RelayAppState>, request: Request) -> Response {
    relay_cloud_ingest(state, request, CloudEndpoint::OtlpLogs).await
}

async fn relay_otlp_traces(State(state): State<RelayAppState>, request: Request) -> Response {
    relay_cloud_ingest(state, request, CloudEndpoint::OtlpTraces).await
}

async fn relay_codex_hook(State(state): State<RelayAppState>, request: Request) -> Response {
    relay_cloud_ingest(state, request, CloudEndpoint::CodexHook).await
}

async fn relay_cloud_ingest(
    state: RelayAppState,
    request: Request,
    endpoint: CloudEndpoint,
) -> Response {
    if !ingest_authorized(&state, &request) {
        return relay_response(
            StatusCode::UNAUTHORIZED,
            json!({"ok":false,"reason":"ingest_auth_required"}),
        );
    }
    let body = match state.body_budget.read_json(request).await {
        Ok(body) => body,
        Err(error) => return relay_body_error_response(error),
    };
    let CloudIngestBatch { records, summary } = match prepare_cloud_ingest(
        endpoint,
        &body.bytes,
        state.relay.inner.config.max_envelope_bytes,
    ) {
        Ok(batch) => batch,
        Err(error) => {
            return relay_response(
                StatusCode::BAD_REQUEST,
                json!({"ok":false,"reason":"invalid_cloud_ingest","detail":error.to_string()}),
            );
        }
    };
    let capture_ids: Vec<String> = records
        .iter()
        .map(|record| record.capture_id.clone())
        .collect();
    let (lifecycle_events, tool_executions) = derived_record_counts(&records);
    let results = match state.relay.enqueue_batch(records).await {
        Ok(results) => results,
        Err(error) => {
            return relay_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"ok":false,"reason":"relay_unavailable","detail":error.to_string()}),
            );
        }
    };
    let mut duplicates = 0_u64;
    let mut conflict = None;
    let mut unavailable = None;
    for (capture_id, result) in capture_ids.iter().zip(results) {
        match result {
            Ok(ack) => duplicates = duplicates.saturating_add(u64::from(ack.duplicate)),
            Err(error) if error.kind == SubmitErrorKind::Conflict => {
                conflict = Some(capture_id.clone())
            }
            Err(error) => unavailable = Some(error.message),
        }
    }
    if let Some(capture_id) = conflict {
        return relay_response(
            StatusCode::CONFLICT,
            json!({"ok":false,"reason":"capture_id_conflict","capture_id":capture_id}),
        );
    }
    if let Some(detail) = unavailable {
        return relay_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok":false,"reason":"relay_unavailable","detail":detail}),
        );
    }
    let quality_rejections = summary
        .unknown_events
        .saturating_add(summary.conversion_errors.len() as u64);
    if quality_rejections > 0
        && let Err(error) = state.relay.record_ingest_quality_with_reasons(
            endpoint,
            summary.unknown_events,
            summary.conversion_errors.len() as u64,
            &quality_error_reasons(&summary),
        )
    {
        // The raw batch is already durable. Refuse the request until its
        // quality evidence can also be committed, so a ledger failure
        // cannot become a silent green health result after restart.
        warn!(error = %error, endpoint = endpoint.as_str(), "failed to persist ingest quality counters");
        return relay_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok":false,"reason":"quality_ledger_unavailable"}),
        );
    }
    state
        .ingest_coverage
        .lock()
        .expect("ingest coverage poisoned")
        .observe_cloud(
            endpoint,
            &summary,
            capture_ids.len() as u64,
            duplicates,
            lifecycle_events,
            tool_executions,
        );
    // A durable acknowledgement means the evidence is safe, but it does not
    // make an invalid or unknown producer event acceptable. Fail closed after
    // enqueueing so SDKs and required hooks stop/retry instead of silently
    // treating a partial trace as valid.
    let unattributed_quality_errors =
        quality_rejections.saturating_sub(summary.attributed_quality_errors);
    if quality_rejections > 0
        && (endpoint == CloudEndpoint::CodexHook || unattributed_quality_errors > 0)
    {
        let error_message = if summary.conversion_errors.is_empty() {
            format!("{} unknown cloud event(s)", summary.unknown_events)
        } else {
            summary.conversion_errors.join("; ")
        };
        return relay_response(
            StatusCode::BAD_REQUEST,
            json!({
                "ok":false,
                "durable":true,
                "local_durable":true,
                "reason":"cloud_ingest_quality_error",
                "detail":error_message,
                "summary":summary,
                "unattributed_quality_errors":unattributed_quality_errors,
                "captures":capture_ids.len(),
                "duplicates":duplicates,
            }),
        );
    }
    let error_message = (quality_rejections > 0).then(|| {
        if summary.conversion_errors.is_empty() {
            format!(
                "{} unknown event(s) retained as Raw",
                summary.unknown_events
            )
        } else {
            summary.conversion_errors.join("; ")
        }
    });
    relay_response(
        StatusCode::OK,
        json!({
            "partialSuccess":{
                "rejectedLogRecords":if endpoint == CloudEndpoint::OtlpLogs {quality_rejections} else {0},
                "rejectedSpans":if endpoint == CloudEndpoint::OtlpTraces {quality_rejections} else {0},
                "errorMessage":error_message,
            },
            "chiptrace":{
                "ok":true,
                "durable":true,
                "captures":capture_ids.len(),
                "duplicates":duplicates,
                "summary":summary,
            }
        }),
    )
}

async fn relay_captures(State(state): State<RelayAppState>, request: Request) -> Response {
    if !ingest_authorized(&state, &request) {
        return relay_response(
            StatusCode::UNAUTHORIZED,
            json!({"ok":false,"reason":"ingest_auth_required"}),
        );
    }
    let body = match state.body_budget.read_ndjson(request).await {
        Ok(body) => body,
        Err(error) => return relay_body_error_response(error),
    };
    let records = match normalize_wire_capture_batch(
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
    relay_enqueue_batch(&state, records).await
}

async fn relay_enqueue_batch(state: &RelayAppState, records: Vec<CaptureRecord>) -> Response {
    let capture_metadata: Vec<(String, WireCaptureEvidence)> = records
        .iter()
        .map(|record| (record.capture_id.clone(), record.wire_evidence))
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
    let mut acknowledged = Vec::new();
    let outcomes: Vec<Value> = capture_metadata
        .into_iter()
        .zip(results)
        .map(|((capture_id, evidence), result)| match result {
            Ok(ack) => {
                durable += 1;
                duplicates += u64::from(ack.duplicate);
                acknowledged.push((evidence, ack.duplicate));
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
    state
        .ingest_coverage
        .lock()
        .expect("ingest coverage poisoned")
        .observe_wire(&acknowledged);
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
    if !ingest_authorized(&state, &request) {
        return relay_response(
            StatusCode::UNAUTHORIZED,
            json!({"ok":false,"reason":"ingest_auth_required"}),
        );
    }
    let body = match state.body_budget.read_json(request).await {
        Ok(body) => body,
        Err(error) => return relay_body_error_response(error),
    };
    let record =
        match normalize_wire_capture(&body.bytes, state.relay.inner.config.max_envelope_bytes) {
            Ok(record) => record,
            Err(error) => {
                return relay_response(
                    StatusCode::BAD_REQUEST,
                    json!({"ok":false,"reason":"invalid_capture","detail":error.to_string()}),
                );
            }
        };
    let evidence = record.wire_evidence;
    match state.relay.enqueue_record(record).await {
        Ok(ack) => {
            state
                .ingest_coverage
                .lock()
                .expect("ingest coverage poisoned")
                .observe_wire(&[(evidence, ack.duplicate)]);
            relay_response(
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
                    "input_receipt": {
                        "schema_version": "chiptrace.capture-input-receipt.v1",
                        "bytes": body.bytes.len(),
                        "sha256": crate::jsonl::sha256_bytes(&body.bytes),
                    },
                    "capture":ack,
                }),
            )
        }
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

fn ingest_authorized(state: &RelayAppState, request: &Request) -> bool {
    let Some(expected) = state.relay.inner.config.ingest_bearer_token.as_deref() else {
        return true;
    };
    let Some(observed) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    constant_time_equal(expected.as_bytes(), observed.as_bytes())
}

fn constant_time_equal(expected: &[u8], observed: &[u8]) -> bool {
    let mut difference = expected.len() ^ observed.len();
    let length = expected.len().max(observed.len());
    for index in 0..length {
        difference |= usize::from(
            expected.get(index).copied().unwrap_or_default()
                ^ observed.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
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
                    "build".to_owned(),
                    json!({
                        "version": crate::VERSION,
                        "revision": crate::BUILD_REVISION,
                    }),
                );
                object.insert(
                    "body_budget_capacity".to_owned(),
                    json!(state.body_budget.capacity()),
                );
                object.insert(
                    "body_budget_available".to_owned(),
                    json!(state.body_budget.available()),
                );
                object.insert(
                    "ingest_coverage".to_owned(),
                    state
                        .ingest_coverage
                        .lock()
                        .expect("ingest coverage poisoned")
                        .snapshot(),
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

fn readiness_blocking_reasons(health: &RelayHealth, coverage: &Value) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if !health.ok {
        reasons.push("relay_not_healthy");
    }
    if health.pending != 0 {
        reasons.push("relay_pending_records");
    }
    if health.inflight != 0 {
        reasons.push("relay_inflight_records");
    }
    if health.failed != 0 {
        reasons.push("relay_failed_records");
    }
    if !health.conservation_ok {
        reasons.push("relay_delivery_not_conserved");
    }
    if coverage.get("status").and_then(Value::as_str) != Some("complete") {
        reasons.push("relay_coverage_not_complete");
    }
    if coverage
        .get("required_sources_observed")
        .and_then(Value::as_bool)
        != Some(true)
    {
        reasons.push("relay_required_sources_not_observed");
    }
    if coverage
        .get("required_sources_fresh")
        .and_then(Value::as_bool)
        != Some(true)
    {
        reasons.push("relay_required_sources_not_fresh");
    }
    if !coverage
        .get("missing_sources")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        reasons.push("relay_sources_missing");
    }
    if !coverage
        .get("stale_sources")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        reasons.push("relay_sources_stale");
    }
    if coverage.get("quality_errors").and_then(Value::as_u64) != Some(0) {
        reasons.push("relay_quality_errors_nonzero");
    }
    if coverage.get("quality_errors_scope").and_then(Value::as_str) != Some("durable_relay_state") {
        reasons.push("relay_quality_history_not_durable");
    }
    if coverage
        .get("quality_reason_breakdown_complete")
        .and_then(Value::as_bool)
        != Some(true)
    {
        reasons.push("relay_quality_reason_breakdown_missing");
    }
    if coverage.get("turn_capture_ready").and_then(Value::as_bool) != Some(true) {
        reasons.push("relay_turn_capture_not_ready");
    }
    if coverage
        .pointer("/wire_turn_coverage/successful_turn_scoped_captures")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        reasons.push("relay_no_successful_turn_scoped_wire");
    }
    if coverage
        .pointer("/wire_turn_coverage/successful_turn_scoped_fresh")
        .and_then(Value::as_bool)
        != Some(true)
    {
        reasons.push("relay_successful_turn_scoped_wire_not_fresh");
    }
    reasons
}

async fn relay_ready(State(state): State<RelayAppState>) -> Response {
    let health = match state.relay.health().await {
        Ok(health) => health,
        Err(error) => {
            return relay_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "ok": false,
                    "ready": false,
                    "status": "error",
                    "blocking_reasons": ["relay_health_failed"],
                    "detail": error.to_string(),
                }),
            );
        }
    };
    let coverage = state
        .ingest_coverage
        .lock()
        .expect("ingest coverage poisoned")
        .snapshot();
    let blocking_reasons = readiness_blocking_reasons(&health, &coverage);
    let ready = blocking_reasons.is_empty();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    relay_response(
        status,
        json!({
            "ok": ready,
            "ready": ready,
            "status": if ready { "ready" } else { "not_ready" },
            "blocking_reasons": blocking_reasons,
            "build": {
                "version": crate::VERSION,
                "revision": crate::BUILD_REVISION,
            },
            "relay": health,
            "ingest_coverage": coverage,
        }),
    )
}

async fn relay_flush(State(state): State<RelayAppState>, request: Request) -> Response {
    if !ingest_authorized(&state, &request) {
        return relay_response(
            StatusCode::UNAUTHORIZED,
            json!({"ok":false,"reason":"ingest_auth_required"}),
        );
    }
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
    use axum::body::{Body, to_bytes};
    use axum::routing::post;
    use serde_json::json;

    type ReceiptReply = Arc<Mutex<(StatusCode, String)>>;

    async fn receipt_reply(
        State(reply): State<ReceiptReply>,
        request: Request,
    ) -> impl IntoResponse {
        let _ = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
        reply.lock().unwrap().clone()
    }

    fn receipt_record(capture_id: &str) -> (DeliveryRecord, Vec<u8>) {
        let capture = normalize_capture(
            &serde_json::to_vec(&json!({
                "captureId": capture_id,
                "responseStatus": 503,
                "captureError": "synthetic receipt regression"
            }))
            .unwrap(),
            1024 * 1024,
        )
        .unwrap();
        let record = DeliveryRecord {
            capture_id: capture.capture_id,
            raw_sha256: capture.sha256,
            bytes: capture.canonical.len() as u64 + 1,
            state: "inflight".to_owned(),
            attempts: 1,
            next_attempt_unix_ms: 0,
            lease_until_unix_ms: 0,
            last_attempt_at: None,
            delivered_at: None,
            last_error: None,
        };
        (record, capture.canonical)
    }

    fn receipt(record: &DeliveryRecord, duplicate: bool) -> Value {
        json!({
            "capture_id": record.capture_id,
            "ok": true,
            "durable": true,
            "duplicate": duplicate,
            "capture": SubmitAck {
                capture_id: record.capture_id.clone(),
                state: if duplicate { "duplicate" } else { "accepted" }.to_owned(),
                durable: true,
                duplicate,
                raw_sha256: record.raw_sha256.clone(),
                segment_id: 42,
                offset: 8192,
                length: record.bytes,
            },
        })
    }

    fn invalid_receipts(record: &DeliveryRecord) -> Vec<(&'static str, Value)> {
        let valid = receipt(record, false);
        let mut cases = vec![
            (
                "ack_only",
                json!({"ok": true, "durable": true, "duplicate": false}),
            ),
            ("missing_receipt", valid.clone()),
            ("wrong_capture_id", valid.clone()),
            ("wrong_hash", valid.clone()),
            ("wrong_length", valid.clone()),
            ("not_durable", valid.clone()),
            ("invalid_state", valid.clone()),
            ("duplicate_disagrees", valid.clone()),
            ("invalid_segment", valid.clone()),
            ("overflowing_locator", valid.clone()),
            ("contradictory_http_status", valid.clone()),
            ("overflowing_http_status", valid),
        ];
        cases[1].1.as_object_mut().unwrap().remove("capture");
        cases[2].1["capture"]["capture_id"] = json!("cap-unrelated-receipt");
        cases[3].1["capture"]["raw_sha256"] = json!("0".repeat(64));
        cases[4].1["capture"]["length"] = json!(record.bytes + 1);
        cases[5].1["capture"]["durable"] = json!(false);
        cases[6].1["capture"]["state"] = json!("pending");
        cases[7].1["duplicate"] = json!(true);
        cases[8].1["capture"]["segment_id"] = json!(0);
        cases[9].1["capture"]["offset"] = json!(u64::MAX);
        cases[10].1["http_status"] = json!(409);
        cases[11].1["http_status"] = json!(65536 + 202);
        cases
    }

    async fn receipt_test_relay() -> (
        tempfile::TempDir,
        DurableRelay,
        ReceiptReply,
        tokio::task::JoinHandle<()>,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let reply = Arc::new(Mutex::new((StatusCode::ACCEPTED, "{}".to_owned())));
        let app = Router::new()
            .route("/capture", post(receipt_reply))
            .route("/captures", post(receipt_reply))
            .with_state(Arc::clone(&reply));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut config = test_config(&temporary);
        config.collector_url = format!("http://{address}");
        config.request_timeout = Duration::from_secs(2);
        let relay = DurableRelay::open(config).await.unwrap();
        (temporary, relay, reply, server)
    }

    async fn receipt_payload(
        relay: &DurableRelay,
        record: &DeliveryRecord,
        body: &[u8],
    ) -> DeliveryPayload {
        DeliveryPayload {
            record: record.clone(),
            body: body.to_vec(),
            _permit: Arc::clone(&relay.inner.delivery_body_budget)
                .acquire_many_owned(record.bytes as u32)
                .await
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn delivery_receipt_wire_input_binds_current_request_to_canonical_wal() {
        let temporary = tempfile::tempdir().unwrap();
        let relay = DurableRelay::open(test_config(&temporary)).await.unwrap();
        let state = RelayAppState {
            relay: relay.clone(),
            body_budget: InflightBodyBudget::new(4 * 1024 * 1024, 1024 * 1024).unwrap(),
            max_batch_records: 64,
            ingest_coverage: Arc::new(Mutex::new(IngestCoverageState::new())),
        };
        let wire = json!({
            "captureId": "cap-wire-input-receipt", "recordType": "api_snapshot",
            "sourceNamespace": "synthetic-input-receipt", "responseStatus": 200,
            "requestBodyText": "{\"input\":\"中文 request\"}",
            "responseBodyText": "{\"output\":\"保留 response\"}"
        });
        let mut stored_hash = None;
        for (body, expected_status) in [
            (format!(" \n{wire}\n"), StatusCode::ACCEPTED),
            (format!(" \n{wire}\n"), StatusCode::OK),
            (wire.to_string(), StatusCode::OK),
        ] {
            let request = Request::builder()
                .header("content-type", "application/json")
                .header(AUTHORIZATION, "Bearer test-cloud-token-at-least-32-bytes")
                .body(Body::from(body.clone()))
                .unwrap();
            let response = relay_capture(State(state.clone()), request).await;
            assert_eq!(response.status(), expected_status);
            let payload: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
                    .unwrap();
            assert_eq!(
                payload["input_receipt"],
                json!({
                    "schema_version": "chiptrace.capture-input-receipt.v1",
                    "bytes": body.len(),
                    "sha256": crate::jsonl::sha256_bytes(body.as_bytes()),
                })
            );
            let stored = relay
                .inner
                .store
                .read_capture("cap-wire-input-receipt")
                .await
                .unwrap();
            assert_eq!(
                payload["capture"]["raw_sha256"],
                crate::jsonl::sha256_bytes(&stored)
            );
            assert_eq!(payload["capture"]["length"], stored.len() as u64 + 1);
            if let Some(hash) = &stored_hash {
                assert_eq!(&payload["capture"]["raw_sha256"], hash);
            } else {
                stored_hash = Some(payload["capture"]["raw_sha256"].clone());
            }
        }
        assert_eq!(relay.inner.store.health().captures, 1);
        relay.close().await.unwrap();
    }

    #[tokio::test]
    async fn delivery_receipt_single_rejects_unproven_and_mismatched_acknowledgements() {
        let (_temporary, relay, reply, server) = receipt_test_relay().await;
        let (record, body) = receipt_record("cap-single-receipt");
        for (name, payload) in invalid_receipts(&record) {
            *reply.lock().unwrap() = (StatusCode::ACCEPTED, payload.to_string());
            let update = send_single(&relay.inner, &record, body.clone()).await;
            assert_eq!(update.state, "pending", "invalid receipt: {name}");
            assert!(update.error.is_some(), "invalid receipt: {name}");
        }
        relay.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn delivery_receipt_batch_rejects_unproven_and_mismatched_acknowledgements() {
        let (_temporary, relay, reply, server) = receipt_test_relay().await;
        let (first, first_body) = receipt_record("cap-first-receipt");
        let (second, second_body) = receipt_record("cap-second-receipt");
        for (name, mut invalid) in invalid_receipts(&first) {
            // The item ID routes this result but does not prove its stored bytes.
            invalid["capture_id"] = json!(first.capture_id);
            *reply.lock().unwrap() = (
                StatusCode::MULTI_STATUS,
                json!({"ok": false, "durable": false,
                    "results": [invalid, receipt(&second, true)]})
                .to_string(),
            );
            let batch = vec![
                receipt_payload(&relay, &first, &first_body).await,
                receipt_payload(&relay, &second, &second_body).await,
            ];
            let updates = send_delivery_batch(&relay.inner, batch).await;
            assert_eq!(updates[0].state, "pending", "invalid receipt: {name}");
            assert_eq!(updates[1].state, "delivered", "valid receipt: {name}");
        }
        relay.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn delivery_receipt_accepts_exact_accepted_and_duplicate_receipts() {
        let (_temporary, relay, reply, server) = receipt_test_relay().await;
        let (first, first_body) = receipt_record("cap-valid-first-receipt");
        let (second, second_body) = receipt_record("cap-valid-second-receipt");
        for (status, duplicate) in [(StatusCode::ACCEPTED, false), (StatusCode::OK, true)] {
            *reply.lock().unwrap() = (status, receipt(&first, duplicate).to_string());
            assert_eq!(
                send_single(&relay.inner, &first, first_body.clone())
                    .await
                    .state,
                "delivered"
            );
            *reply.lock().unwrap() = (
                status,
                json!({"ok": true, "durable": true,
                    "results": [receipt(&second, duplicate), receipt(&first, duplicate)]})
                .to_string(),
            );
            let batch = vec![
                receipt_payload(&relay, &first, &first_body).await,
                receipt_payload(&relay, &second, &second_body).await,
            ];
            let updates = send_delivery_batch(&relay.inner, batch).await;
            assert!(updates.iter().all(|update| update.state == "delivered"));
        }
        relay.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn delivery_receipt_preserves_http_errors_and_retries_invalid_json() {
        let (_temporary, relay, reply, server) = receipt_test_relay().await;
        let (first, first_body) = receipt_record("cap-http-first-receipt");
        let (second, second_body) = receipt_record("cap-http-second-receipt");
        for (status, expected) in [
            (StatusCode::SERVICE_UNAVAILABLE, "pending"),
            (StatusCode::TOO_MANY_REQUESTS, "pending"),
            (StatusCode::CONFLICT, "conflict"),
            (StatusCode::BAD_REQUEST, "failed"),
        ] {
            *reply.lock().unwrap() = (status, receipt(&first, false).to_string());
            assert_eq!(
                send_single(&relay.inner, &first, first_body.clone())
                    .await
                    .state,
                expected,
                "single HTTP {status}"
            );
            *reply.lock().unwrap() = (
                status,
                json!({"ok": true, "durable": true,
                    "results": [receipt(&first, false), receipt(&second, false)]})
                .to_string(),
            );
            let batch = vec![
                receipt_payload(&relay, &first, &first_body).await,
                receipt_payload(&relay, &second, &second_body).await,
            ];
            let updates = send_delivery_batch(&relay.inner, batch).await;
            assert!(
                updates.iter().all(|update| update.state == expected),
                "batch HTTP {status}"
            );
        }
        for body in ["{", "{}"] {
            *reply.lock().unwrap() = (StatusCode::ACCEPTED, body.to_owned());
            assert_eq!(
                send_single(&relay.inner, &first, first_body.clone())
                    .await
                    .state,
                "pending"
            );
            let batch = vec![
                receipt_payload(&relay, &first, &first_body).await,
                receipt_payload(&relay, &second, &second_body).await,
            ];
            let updates = send_delivery_batch(&relay.inner, batch).await;
            assert!(updates.iter().all(|update| update.state == "pending"));
        }
        relay.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn delivery_receipt_batch_rejects_duplicate_ids_and_keeps_proven_partial_results() {
        let (_temporary, relay, reply, server) = receipt_test_relay().await;
        let (first, first_body) = receipt_record("cap-ambiguous-first-receipt");
        let (second, second_body) = receipt_record("cap-ambiguous-second-receipt");
        let mut wrong_hash = receipt(&first, false);
        wrong_hash["capture"]["raw_sha256"] = json!("0".repeat(64));
        for results in [
            vec![
                wrong_hash.clone(),
                receipt(&first, false),
                receipt(&second, true),
            ],
            vec![receipt(&first, false), wrong_hash, receipt(&second, true)],
            vec![receipt(&second, true)],
        ] {
            *reply.lock().unwrap() = (
                StatusCode::MULTI_STATUS,
                json!({"ok": false, "durable": false, "results": results}).to_string(),
            );
            let batch = vec![
                receipt_payload(&relay, &first, &first_body).await,
                receipt_payload(&relay, &second, &second_body).await,
            ];
            let updates = send_delivery_batch(&relay.inner, batch).await;
            assert_eq!(updates[0].state, "pending");
            assert_eq!(updates[1].state, "delivered");
        }
        *reply.lock().unwrap() = (
            StatusCode::MULTI_STATUS,
            json!({"ok": false, "durable": false, "results": [
                {"capture_id": first.capture_id, "ok": false, "durable": false,
                    "http_status": 409, "reason": "capture_id_conflict"},
                receipt(&second, true)
            ]})
            .to_string(),
        );
        let batch = vec![
            receipt_payload(&relay, &first, &first_body).await,
            receipt_payload(&relay, &second, &second_body).await,
        ];
        let updates = send_delivery_batch(&relay.inner, batch).await;
        assert_eq!(updates[0].state, "conflict");
        assert_eq!(updates[1].state, "delivered");
        relay.close().await.unwrap();
        server.abort();
    }

    fn test_config(temporary: &tempfile::TempDir) -> RelayConfig {
        RelayConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            store: StoreConfig {
                root: temporary.path().join("outbox"),
                state_root: temporary.path().join("outbox-state"),
                segment_max_bytes: 1024 * 1024,
                segment_max_age: Duration::from_secs(60),
                queue_items: 64,
                batch_records: 8,
                batch_bytes: 1024 * 1024,
                batch_wait: Duration::from_millis(1),
                fsync: true,
            },
            store_shards: 1,
            delivery_state_root: temporary.path().join("delivery"),
            collector_url: "http://127.0.0.1:9".to_owned(),
            delivery_concurrency: 1,
            delivery_queue_items: 64,
            delivery_batch_records: 8,
            delivery_batch_bytes: 1024 * 1024,
            delivery_batch_wait: Duration::from_millis(1),
            max_delivery_inflight_bytes: 4 * 1024 * 1024,
            request_timeout: Duration::from_millis(50),
            base_retry_delay: Duration::from_millis(5),
            max_retry_delay: Duration::from_millis(20),
            max_connections: 16,
            max_envelope_bytes: 1024 * 1024,
            max_inflight_body_bytes: 4 * 1024 * 1024,
            max_batch_records: 64,
            ingest_bearer_token: Some("test-cloud-token-at-least-32-bytes".to_owned()),
        }
    }

    #[test]
    fn delivery_reads_follow_workers_with_a_bounded_parallelism() {
        let temporary = tempfile::tempdir().unwrap();
        let mut config = test_config(&temporary);
        config.delivery_concurrency = 1;
        assert_eq!(
            delivery_read_concurrency(&config),
            MIN_DELIVERY_READ_CONCURRENCY
        );
        config.delivery_concurrency = MIN_DELIVERY_READ_CONCURRENCY;
        assert_eq!(
            delivery_read_concurrency(&config),
            MIN_DELIVERY_READ_CONCURRENCY
        );
        config.delivery_concurrency = 8;
        assert_eq!(delivery_read_concurrency(&config), 8);
        config.delivery_concurrency = 64;
        assert_eq!(
            delivery_read_concurrency(&config),
            MAX_DELIVERY_READ_CONCURRENCY
        );
    }

    #[tokio::test]
    async fn cloud_auth_and_invalid_payload_fail_before_retry_queue() {
        let temporary = tempfile::tempdir().unwrap();
        let relay = DurableRelay::open(test_config(&temporary)).await.unwrap();
        let state = RelayAppState {
            relay: relay.clone(),
            body_budget: InflightBodyBudget::new(4 * 1024 * 1024, 1024 * 1024).unwrap(),
            max_batch_records: 64,
            ingest_coverage: Arc::new(Mutex::new(IngestCoverageState::new())),
        };

        let catalog_unauthorized = relay_models(
            State(state.clone()),
            Request::builder().body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(catalog_unauthorized.status(), StatusCode::UNAUTHORIZED);

        let catalog_response = relay_models(
            State(state.clone()),
            Request::builder()
                .header(AUTHORIZATION, "Bearer test-cloud-token-at-least-32-bytes")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(catalog_response.status(), StatusCode::OK);
        let catalog: Value = serde_json::from_slice(
            &to_bytes(catalog_response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(catalog["models"][0]["tool_mode"], "direct");

        let unauthorized = Request::builder()
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            relay_cloud_ingest(state.clone(), unauthorized, CloudEndpoint::OtlpLogs)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let authorized_bad = Request::builder()
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer test-cloud-token-at-least-32-bytes")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            relay_cloud_ingest(state.clone(), authorized_bad, CloudEndpoint::OtlpLogs)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let invalid_capture = Request::builder()
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer test-cloud-token-at-least-32-bytes")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            relay_capture(State(state.clone()), invalid_capture)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let non_wire_capture = Request::builder()
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer test-cloud-token-at-least-32-bytes")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "version":"chiptrace.capture.v2",
                    "recordType":"lifecycle_event",
                    "captureId":"cap-forbidden-online-lifecycle",
                    "sourceNamespace":"test",
                    "traceContext":{"session_id":"session-1"},
                    "lifecycleEvent":{"type":"session_start","status":"started"}
                }))
                .unwrap(),
            ))
            .unwrap();
        assert_eq!(
            relay_capture(State(state.clone()), non_wire_capture)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mixed_batch = [
            json!({
                "version":"chiptrace.capture.v2",
                "recordType":"api_snapshot",
                "captureId":"cap-current-wire",
                "sourceNamespace":"gateway-test",
                "requestBodyText":"{}",
                "responseBodyText":"{}",
                "responseStatus":200
            }),
            json!({
                "version":"chiptrace.capture.v2",
                "recordType":"evaluation",
                "captureId":"cap-forbidden-online-evaluation",
                "sourceNamespace":"test",
                "traceContext":{"session_id":"session-1"},
                "evaluationEvidence":[{"kind":"test","source":"test","status":"passed"}]
            }),
        ]
        .into_iter()
        .map(|value| serde_json::to_string(&value).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
        let mixed_batch = Request::builder()
            .header("content-type", "application/x-ndjson")
            .header(AUTHORIZATION, "Bearer test-cloud-token-at-least-32-bytes")
            .body(Body::from(mixed_batch))
            .unwrap();
        assert_eq!(
            relay_captures(State(state.clone()), mixed_batch)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let current_gateway_capture = Request::builder()
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer test-cloud-token-at-least-32-bytes")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "recordType":"api_snapshot",
                    "captureId":"cap-current-gateway-without-version",
                    "sourceNamespace":"router-v2-18084",
                    "requestBodyText":"{}",
                    "responseBodyText":"{}",
                    "responseStatus":200
                }))
                .unwrap(),
            ))
            .unwrap();
        assert_eq!(
            relay_capture(State(state.clone()), current_gateway_capture)
                .await
                .status(),
            StatusCode::ACCEPTED
        );
        let health = relay.health().await.unwrap();
        // Invalid cloud payloads are retained as an auditable raw batch before
        // the 400 response; they must never enter canonical Release.
        assert_eq!(health.delivery_records, 2);
        assert!(health.ingest_auth_required);
        let coverage = state
            .ingest_coverage
            .lock()
            .expect("ingest coverage poisoned")
            .snapshot();
        assert_eq!(coverage["status"], "partial");
        assert_eq!(coverage["required_sources_observed"], false);
        assert_eq!(coverage["otlp_logs"]["requests"], 1);
        assert_eq!(coverage["wire"]["requests"], 1);
        assert_eq!(coverage["wire"]["durable_captures"], 1);
        assert_eq!(coverage["quality_errors"], 1);
        assert_eq!(
            coverage["quality_errors_by_endpoint"]["otlp_logs"]["total"],
            1
        );
        assert_eq!(
            coverage["quality_errors_by_endpoint"]["otlp_traces"]["total"],
            0
        );
        assert_eq!(coverage["buyer_eligibility_claimed"], false);
        relay.close().await.unwrap();
        drop(state);
        drop(relay);
        let reopened = DurableRelay::open(test_config(&temporary)).await.unwrap();
        assert_eq!(
            reopened.ingest_quality_counters().unwrap().total().unwrap(),
            1
        );
        reopened.close().await.unwrap();
    }

    #[tokio::test]
    async fn ready_endpoint_fails_closed_until_fresh_turn_sources_are_complete() {
        let temporary = tempfile::tempdir().unwrap();
        let relay = DurableRelay::open(test_config(&temporary)).await.unwrap();
        let state = RelayAppState {
            relay: relay.clone(),
            body_budget: InflightBodyBudget::new(4 * 1024 * 1024, 1024 * 1024).unwrap(),
            max_batch_records: 64,
            ingest_coverage: Arc::new(Mutex::new(IngestCoverageState::new())),
        };

        let cold = relay_ready(State(state.clone())).await;
        assert_eq!(cold.status(), StatusCode::SERVICE_UNAVAILABLE);
        let cold_body: Value =
            serde_json::from_slice(&to_bytes(cold.into_body(), 4 * 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(cold_body["ready"], false);
        assert!(
            cold_body["blocking_reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason == "relay_required_sources_not_observed")
        );

        let mut coverage = IngestCoverageState::new();
        coverage.observe_wire(&[(
            WireCaptureEvidence {
                turn_scoped: true,
                http_success: true,
                identity_conflict: false,
            },
            false,
        )]);
        for endpoint in [
            CloudEndpoint::OtlpLogs,
            CloudEndpoint::OtlpTraces,
            CloudEndpoint::CodexHook,
        ] {
            coverage.observe_cloud(
                endpoint,
                &crate::cloud_ingest::CloudIngestSummary {
                    endpoint: endpoint.as_str().to_owned(),
                    source_records: 1,
                    derived_captures: 1,
                    unknown_events: 0,
                    attributed_quality_errors: 0,
                    conversion_errors: Vec::new(),
                },
                1,
                0,
                0,
                0,
            );
        }
        let ready_state = RelayAppState {
            ingest_coverage: Arc::new(Mutex::new(coverage)),
            ..state
        };
        let ready = relay_ready(State(ready_state)).await;
        assert_eq!(ready.status(), StatusCode::OK);
        let ready_body: Value =
            serde_json::from_slice(&to_bytes(ready.into_body(), 4 * 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(ready_body["ok"], true);
        assert_eq!(ready_body["ready"], true);
        assert_eq!(ready_body["blocking_reasons"], json!([]));
        assert_eq!(
            ready_body["ingest_coverage"]["quality_reason_breakdown_complete"],
            true
        );

        let health = relay.health().await.unwrap();
        let mut malformed = ready_body["ingest_coverage"].clone();
        malformed
            .as_object_mut()
            .unwrap()
            .remove("quality_reason_breakdown_complete");
        malformed
            .as_object_mut()
            .unwrap()
            .remove("quality_errors_scope");
        let reasons = readiness_blocking_reasons(&health, &malformed);
        assert!(reasons.contains(&"relay_quality_reason_breakdown_missing"));
        assert!(reasons.contains(&"relay_quality_history_not_durable"));
        relay.close().await.unwrap();
    }

    #[test]
    fn quality_reason_breakdown_requires_exact_durable_totals() {
        let mut coverage = IngestCoverageState::new();
        assert_eq!(
            coverage.snapshot()["quality_reason_breakdown_complete"],
            true
        );

        coverage.otlp_traces.quality_conversion_errors = 1;
        assert_eq!(
            coverage.snapshot()["quality_reason_breakdown_complete"],
            false
        );

        coverage
            .otlp_traces
            .quality_reasons
            .insert("conversion_error".to_owned(), 1);
        coverage.quality_errors = 1;
        assert_eq!(
            coverage.snapshot()["quality_reason_breakdown_complete"],
            true
        );
        coverage
            .otlp_traces
            .quality_reasons
            .insert("unknown_private_reason".to_owned(), 0);
        assert_eq!(
            coverage.snapshot()["quality_reason_breakdown_complete"],
            false
        );
        coverage.quality_errors = 0;
        assert_eq!(
            coverage.snapshot()["quality_reason_breakdown_complete"],
            false
        );
    }

    #[tokio::test]
    async fn wire_turn_coverage_counts_only_durable_single_and_partial_batch_acks() {
        let temporary = tempfile::tempdir().unwrap();
        let relay = DurableRelay::open(test_config(&temporary)).await.unwrap();
        let state = RelayAppState {
            relay: relay.clone(),
            body_budget: InflightBodyBudget::new(4 * 1024 * 1024, 1024 * 1024).unwrap(),
            max_batch_records: 64,
            ingest_coverage: Arc::new(Mutex::new(IngestCoverageState::new())),
        };
        let wire = |id, status, trace| {
            json!({
                "captureId":id,"recordType":"api_snapshot","sourceNamespace":"test",
                "requestBodyText":"{}","responseBodyText":"{}",
                "responseStatus":status,"traceContext":trace
            })
        };
        let request = |body: String, content_type| {
            Request::builder()
                .header("content-type", content_type)
                .header(AUTHORIZATION, "Bearer test-cloud-token-at-least-32-bytes")
                .body(Body::from(body))
                .unwrap()
        };
        let unscoped = wire("cap-unscoped-403", 403, json!({}));
        for status in [StatusCode::ACCEPTED, StatusCode::OK] {
            assert_eq!(
                relay_capture(
                    State(state.clone()),
                    request(unscoped.to_string(), "application/json")
                )
                .await
                .status(),
                status
            );
        }
        let snapshot = state.ingest_coverage.lock().unwrap().snapshot();
        assert_eq!(snapshot["wire"]["durable_captures"], 2);
        assert_eq!(snapshot["wire_turn_coverage"]["unscoped_captures"], 2);
        assert_eq!(
            snapshot["wire_turn_coverage"]["successful_turn_scoped_fresh"],
            false
        );

        let scoped = json!({"session_id":"s","turn_id":"t"});
        let success = wire("cap-single-success", 200, scoped.clone());
        assert_eq!(
            relay_capture(
                State(state.clone()),
                request(success.to_string(), "application/json")
            )
            .await
            .status(),
            StatusCode::ACCEPTED
        );
        let conflict = wire(
            "cap-single-success",
            200,
            json!({"session_id":"s","turn_id":"other"}),
        );
        assert_eq!(
            relay_capture(
                State(state.clone()),
                request(conflict.to_string(), "application/json")
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let mut identity_conflict = wire("cap-identity-conflict", 200, scoped.clone());
        identity_conflict["requestBodyText"] =
            json!("{\"client_metadata\":{\"session_id\":\"other\"}}");
        let batch = [
            wire("cap-unscoped-403", 200, scoped.clone()), // Conflicts with durable 403.
            wire("cap-batch-403", 403, json!({})),
            wire("cap-batch-429", 429, scoped.clone()),
            identity_conflict,
            wire("cap-batch-201", 201, scoped),
        ]
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
        let response = relay_captures(
            State(state.clone()),
            request(batch.clone(), "application/x-ndjson"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(body["counts"]["durable"], 4);
        assert_eq!(body["counts"]["conflicts"], 1);
        let response = relay_health(State(state.clone())).await;
        let health: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        let coverage = &health["ingest_coverage"];
        assert_eq!(coverage["wire"]["durable_captures"], 7);
        assert_eq!(coverage["wire"]["duplicates"], 1);
        let turns = &coverage["wire_turn_coverage"];
        assert_eq!(turns["turn_scoped_captures"], 3);
        assert_eq!(turns["successful_turn_scoped_captures"], 2);
        assert_eq!(turns["unscoped_captures"], 4);
        assert_eq!(turns["identity_conflict_captures"], 1);
        assert_eq!(turns["successful_turn_scoped_fresh"], true);
        assert_eq!(coverage["session_delivery_claimed"], false);

        let retry =
            relay_captures(State(state.clone()), request(batch, "application/x-ndjson")).await;
        assert_eq!(retry.status(), StatusCode::MULTI_STATUS);
        let after_retry = state.ingest_coverage.lock().unwrap().snapshot();
        assert_eq!(after_retry["wire"]["durable_captures"], 11);
        assert_eq!(after_retry["wire"]["duplicates"], 5);
        assert_eq!(
            after_retry["wire_turn_coverage"]["last_successful_at"],
            turns["last_successful_at"]
        );
        relay.close().await.unwrap();

        let closed_wire = wire(
            "cap-closed-single",
            200,
            json!({"session_id":"s","turn_id":"t"}),
        );
        assert_eq!(
            relay_capture(
                State(state.clone()),
                request(closed_wire.to_string(), "application/json")
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let closed_batch = wire(
            "cap-closed-batch",
            200,
            json!({"session_id":"s","turn_id":"t"}),
        );
        let response = relay_captures(
            State(state.clone()),
            request(closed_batch.to_string(), "application/x-ndjson"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(body["counts"]["durable"], 0);
        assert_eq!(body["counts"]["unavailable"], 1);
        let after_unavailable = state.ingest_coverage.lock().unwrap().snapshot();
        assert_eq!(after_unavailable["wire"], after_retry["wire"]);
        assert_eq!(
            after_unavailable["wire_turn_coverage"]["successful_turn_scoped_captures"],
            after_retry["wire_turn_coverage"]["successful_turn_scoped_captures"]
        );
        assert_eq!(
            after_unavailable["wire_turn_coverage"]["last_successful_at"],
            after_retry["wire_turn_coverage"]["last_successful_at"]
        );
    }

    #[test]
    fn unscoped_failed_and_duplicate_wire_cannot_refresh_successful_turn_evidence() {
        let mut coverage = IngestCoverageState::new();
        let success = WireCaptureEvidence {
            turn_scoped: true,
            http_success: true,
            identity_conflict: false,
        };
        coverage.observe_wire(&[(success, false)]);
        let before = coverage.wire_turn_coverage.last_successful_at.clone();
        coverage.wire_turn_coverage.last_successful_observed_millis = Some(1_000);
        coverage.observe_wire(&[
            (WireCaptureEvidence::default(), false),
            (
                WireCaptureEvidence {
                    http_success: false,
                    ..success
                },
                false,
            ),
            (success, true),
        ]);
        let snapshot = coverage.snapshot();
        assert!(snapshot["wire_age_ms"].as_u64().unwrap() <= INGEST_COVERAGE_FRESHNESS_WINDOW_MS);
        assert_eq!(
            snapshot["wire_turn_coverage"]["successful_turn_scoped_fresh"],
            false
        );
        assert_eq!(coverage.wire_turn_coverage.last_successful_at, before);
        assert_eq!(
            coverage.wire_turn_coverage.last_successful_observed_millis,
            Some(1_000)
        );
    }

    #[test]
    fn ingest_coverage_lists_all_missing_sources_while_warming() {
        let snapshot = IngestCoverageState::new().snapshot();
        assert_eq!(snapshot["status"], "warming");
        assert_eq!(snapshot["turn_capture_ready"], false);
        assert_eq!(snapshot["required_sources_observed"], false);
        assert_eq!(
            snapshot["missing_sources"],
            json!(["wire", "otlp_logs", "otlp_traces", "hooks"])
        );
    }

    #[test]
    fn ingest_coverage_lists_wire_when_only_runtime_arrives() {
        let mut coverage = IngestCoverageState::new();
        for endpoint in [
            CloudEndpoint::OtlpLogs,
            CloudEndpoint::OtlpTraces,
            CloudEndpoint::CodexHook,
        ] {
            coverage.observe_cloud(
                endpoint,
                &crate::cloud_ingest::CloudIngestSummary {
                    endpoint: "test".to_owned(),
                    source_records: 1,
                    derived_captures: 1,
                    unknown_events: 0,
                    attributed_quality_errors: 0,
                    conversion_errors: Vec::new(),
                },
                1,
                0,
                0,
                0,
            );
        }
        let snapshot = coverage.snapshot();
        assert_eq!(snapshot["status"], "degraded");
        assert_eq!(snapshot["turn_capture_ready"], false);
        assert_eq!(snapshot["required_sources_observed"], false);
        assert_eq!(snapshot["required_sources_fresh"], false);
        assert_eq!(snapshot["missing_sources"], json!(["wire"]));
        assert_eq!(snapshot["stale_sources"], json!(["wire"]));
        assert_eq!(snapshot["wire"]["requests"], 0);
    }

    #[test]
    fn ingest_coverage_separates_source_observation_from_buyer_eligibility() {
        let mut coverage = IngestCoverageState::new();
        coverage.observe_wire(&[(WireCaptureEvidence::default(), false); 2]);
        for endpoint in [
            CloudEndpoint::OtlpLogs,
            CloudEndpoint::OtlpTraces,
            CloudEndpoint::CodexHook,
        ] {
            coverage.observe_cloud(
                endpoint,
                &crate::cloud_ingest::CloudIngestSummary {
                    endpoint: "test".to_owned(),
                    source_records: 1,
                    derived_captures: 1,
                    unknown_events: 0,
                    attributed_quality_errors: 0,
                    conversion_errors: Vec::new(),
                },
                1,
                0,
                u64::from(endpoint == CloudEndpoint::CodexHook),
                u64::from(endpoint == CloudEndpoint::OtlpLogs),
            );
        }
        let snapshot = coverage.snapshot();
        assert_eq!(snapshot["status"], "complete");
        assert_eq!(snapshot["turn_capture_ready"], false);
        assert_eq!(snapshot["required_sources_observed"], true);
        assert_eq!(snapshot["required_sources_fresh"], true);
        assert_eq!(snapshot["freshness_applicable"], true);
        assert_eq!(snapshot["missing_sources"], json!([]));
        assert_eq!(snapshot["stale_sources"], json!([]));
        assert_eq!(snapshot["buyer_eligibility_claimed"], false);
        assert_eq!(snapshot["derived"]["lifecycle_events"], 1);
        assert_eq!(snapshot["derived"]["tool_executions"], 1);
    }

    #[test]
    fn ingest_coverage_turn_capture_ready_requires_fresh_successful_scoped_wire() {
        let mut coverage = IngestCoverageState::new();
        coverage.observe_wire(&[(
            WireCaptureEvidence {
                turn_scoped: true,
                http_success: true,
                identity_conflict: false,
            },
            false,
        )]);
        for endpoint in [
            CloudEndpoint::OtlpLogs,
            CloudEndpoint::OtlpTraces,
            CloudEndpoint::CodexHook,
        ] {
            coverage.observe_cloud(
                endpoint,
                &crate::cloud_ingest::CloudIngestSummary {
                    endpoint: "test".to_owned(),
                    source_records: 1,
                    derived_captures: 1,
                    unknown_events: 0,
                    attributed_quality_errors: 0,
                    conversion_errors: Vec::new(),
                },
                1,
                0,
                0,
                0,
            );
        }
        let snapshot = coverage.snapshot();
        assert_eq!(snapshot["status"], "complete");
        assert_eq!(snapshot["turn_capture_ready"], true);
        assert_eq!(
            snapshot["wire_turn_coverage"]["successful_turn_scoped_captures"],
            1
        );
        assert_eq!(
            snapshot["wire_turn_coverage"]["successful_turn_scoped_fresh"],
            true
        );
    }

    #[test]
    fn ingest_coverage_degrades_when_runtime_sources_lag_active_wire() {
        let mut coverage = IngestCoverageState::new();
        coverage.observe_wire(&[(WireCaptureEvidence::default(), false)]);
        for endpoint in [
            CloudEndpoint::OtlpLogs,
            CloudEndpoint::OtlpTraces,
            CloudEndpoint::CodexHook,
        ] {
            coverage.observe_cloud(
                endpoint,
                &crate::cloud_ingest::CloudIngestSummary {
                    endpoint: "test".to_owned(),
                    source_records: 1,
                    derived_captures: 1,
                    unknown_events: 0,
                    attributed_quality_errors: 0,
                    conversion_errors: Vec::new(),
                },
                1,
                0,
                0,
                0,
            );
        }
        let latest_runtime = [
            coverage.otlp_logs.last_observed_millis.unwrap(),
            coverage.otlp_traces.last_observed_millis.unwrap(),
            coverage.hooks.last_observed_millis.unwrap(),
        ]
        .into_iter()
        .max()
        .unwrap();
        let latest_wire = latest_runtime + INGEST_COVERAGE_FRESHNESS_WINDOW_MS + 1;
        coverage.wire.last_observed_millis = Some(latest_wire);

        let snapshot = coverage.snapshot_at(latest_wire);
        assert_eq!(snapshot["status"], "degraded");
        assert_eq!(snapshot["required_sources_observed"], true);
        assert_eq!(snapshot["required_sources_fresh"], false);
        assert_eq!(snapshot["freshness_applicable"], true);
        assert_eq!(snapshot["missing_sources"], json!([]));
        assert_eq!(
            snapshot["stale_sources"],
            json!(["otlp_logs", "otlp_traces", "hooks"])
        );
    }

    #[test]
    fn ingest_coverage_degrades_when_active_wire_never_gets_runtime_sources() {
        let mut coverage = IngestCoverageState::new();
        coverage.observe_wire(&[(WireCaptureEvidence::default(), false)]);
        let first_wire = coverage.wire.first_observed_millis.unwrap();
        let latest_wire = first_wire + INGEST_COVERAGE_FRESHNESS_WINDOW_MS + 1;
        coverage.wire.last_observed_millis = Some(latest_wire);

        let snapshot = coverage.snapshot_at(latest_wire);
        assert_eq!(snapshot["status"], "degraded");
        assert_eq!(snapshot["required_sources_observed"], false);
        assert_eq!(snapshot["required_sources_fresh"], false);
        assert_eq!(snapshot["freshness_applicable"], true);
        assert_eq!(
            snapshot["missing_sources"],
            json!(["otlp_logs", "otlp_traces", "hooks"])
        );
        assert_eq!(snapshot["stale_sources"], json!([]));
    }

    #[test]
    fn ingest_coverage_degrades_when_runtime_is_active_without_recent_wire() {
        let mut coverage = IngestCoverageState::new();
        coverage.observe_wire(&[(WireCaptureEvidence::default(), false)]);
        for endpoint in [
            CloudEndpoint::OtlpLogs,
            CloudEndpoint::OtlpTraces,
            CloudEndpoint::CodexHook,
        ] {
            coverage.observe_cloud(
                endpoint,
                &crate::cloud_ingest::CloudIngestSummary {
                    endpoint: "test".to_owned(),
                    source_records: 1,
                    derived_captures: 1,
                    unknown_events: 0,
                    attributed_quality_errors: 0,
                    conversion_errors: Vec::new(),
                },
                1,
                0,
                0,
                0,
            );
        }
        let latest_runtime = [
            coverage.otlp_logs.last_observed_millis.unwrap(),
            coverage.otlp_traces.last_observed_millis.unwrap(),
            coverage.hooks.last_observed_millis.unwrap(),
        ]
        .into_iter()
        .max()
        .unwrap();
        let stale_wire = latest_runtime - INGEST_COVERAGE_FRESHNESS_WINDOW_MS - 1;
        coverage.wire.last_observed_millis = Some(stale_wire);

        let snapshot = coverage.snapshot_at(latest_runtime);
        assert_eq!(snapshot["status"], "degraded");
        assert_eq!(snapshot["required_sources_observed"], true);
        assert_eq!(snapshot["required_sources_fresh"], false);
        assert_eq!(snapshot["freshness_applicable"], true);
        assert_eq!(snapshot["runtime_active"], true);
        assert_eq!(
            snapshot["wire_lag_ms"],
            INGEST_COVERAGE_FRESHNESS_WINDOW_MS + 1
        );
        assert_eq!(snapshot["stale_sources"], json!(["wire"]));
    }

    #[test]
    fn bearer_comparison_rejects_prefix_suffix_and_length_variants() {
        assert!(constant_time_equal(b"complete-token", b"complete-token"));
        assert!(!constant_time_equal(b"complete-token", b"complete"));
        assert!(!constant_time_equal(
            b"complete-token",
            b"complete-token-extra"
        ));
        assert!(!constant_time_equal(b"complete-token", b"complete-tokeN"));
    }

    #[tokio::test]
    async fn delivery_receipt_unproven_ack_survives_restart_to_real_collector() {
        let temporary = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let invalid_reply = Arc::new(Mutex::new((
            StatusCode::ACCEPTED,
            json!({"ok": true, "durable": true, "duplicate": false}).to_string(),
        )));
        let invalid_server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/capture", post(receipt_reply))
                    .route("/captures", post(receipt_reply))
                    .with_state(invalid_reply),
            )
            .await
            .unwrap();
        });
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
            request_timeout: Duration::from_secs(1),
            base_retry_delay: Duration::from_millis(500),
            max_retry_delay: Duration::from_secs(1),
            max_connections: 16,
            max_envelope_bytes: 1024 * 1024,
            max_inflight_body_bytes: 4 * 1024 * 1024,
            max_batch_records: 32,
            ingest_bearer_token: None,
        };
        let expected: Vec<(DeliveryRecord, Vec<u8>)> = ["one", "two", "three"]
            .into_iter()
            .map(|suffix| receipt_record(&format!("cap-relay-{suffix}")))
            .collect();
        let relay = DurableRelay::open(config.clone()).await.unwrap();
        relay.enqueue(&expected[0].1).await.unwrap();
        let records = expected[1..]
            .iter()
            .map(|(_, body)| normalize_capture(body, 1024 * 1024).unwrap())
            .collect();
        let results = relay.enqueue_batch(records).await.unwrap();
        assert!(results.iter().all(std::result::Result::is_ok));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let health = relay.health().await.unwrap();
            assert_eq!(health.delivered, 0);
            assert_eq!(health.failed, 0);
            assert!(health.conservation_ok);
            if health.delivery_attempts >= 3 && health.pending == 3 && health.inflight == 0 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for (record, body) in &expected {
            assert_eq!(
                relay
                    .inner
                    .store
                    .read_capture(&record.capture_id)
                    .await
                    .unwrap(),
                *body
            );
        }
        relay.close().await.unwrap();
        drop(relay);
        invalid_server.abort();
        let _ = invalid_server.await;

        let mut collector_store = config.store.clone();
        collector_store.root = temporary.path().join("collector");
        collector_store.state_root = temporary.path().join("collector-state");
        let collector_config = crate::collector::CollectorConfig {
            bind: address,
            store: collector_store.clone(),
            store_shards: 1,
            max_connections: 16,
            max_envelope_bytes: 1024 * 1024,
            max_inflight_body_bytes: 4 * 1024 * 1024,
            max_batch_records: 32,
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            crate::collector::serve(collector_config, async {
                let _ = shutdown_rx.await;
            })
            .await
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
        assert_eq!(
            health.delivery_retries,
            health
                .delivery_attempts
                .saturating_sub(health.delivery_records)
        );
        assert!(health.delivery_retries > 0);
        assert_eq!((health.pending, health.inflight, health.failed), (0, 0, 0));
        assert!(health.conservation_ok);
        // The real Collector returns a duplicate receipt on replay. It must
        // still bind to these exact bytes, not the Relay's WAL coordinates.
        for (record, body) in &expected {
            assert_eq!(
                send_single(&reopened.inner, record, body.clone())
                    .await
                    .state,
                "delivered"
            );
        }
        reopened.close().await.unwrap();
        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
        let collector = ShardedCaptureStore::open(collector_store, 1).await.unwrap();
        assert_eq!(collector.health().captures, 3);
        for (record, body) in &expected {
            let restored = collector.read_capture(&record.capture_id).await.unwrap();
            assert_eq!(restored, *body);
            assert_eq!(crate::jsonl::sha256_bytes(&restored), record.raw_sha256);
        }
        collector.close().await.unwrap();
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

    #[test]
    fn startup_fast_path_recovers_indexed_inflight_without_full_rebuild() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("delivery.redb");
        let locator = CaptureLocator {
            capture_id: "cap-startup-recovery".to_owned(),
            raw_sha256: "1".repeat(64),
            segment_id: 1,
            offset: 0,
            length: 128,
            received_at: None,
            model: None,
        };
        {
            let ledger = DeliveryLedger::open(&path).unwrap();
            ledger.ensure(&locator).unwrap();
            assert_eq!(
                ledger
                    .claim_many(
                        std::slice::from_ref(&locator.capture_id),
                        Duration::from_secs(60)
                    )
                    .unwrap()
                    .len(),
                1
            );
        }
        let reopened = DeliveryLedger::open(&path).unwrap();
        let (_, pending, inflight, _, _, _, _) = reopened.health().unwrap();
        assert_eq!((pending, inflight), (1, 0));
        assert_eq!(reopened.pending_ids(8).unwrap(), vec![locator.capture_id]);
    }

    #[test]
    fn ingest_quality_counters_survive_relay_ledger_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("delivery.redb");
        {
            let ledger = DeliveryLedger::open(&path).unwrap();
            assert_eq!(
                ledger.ingest_quality_counters().unwrap().total().unwrap(),
                0
            );
            let reasons = BTreeMap::from([
                ("unsupported_event".to_owned(), 2),
                ("invalid_structure".to_owned(), 3),
            ]);
            let counters = ledger
                .record_ingest_quality_with_reasons(CloudEndpoint::OtlpTraces, 2, 3, &reasons)
                .unwrap();
            assert_eq!(counters.total().unwrap(), 5);
            assert_eq!(counters.otlp_traces_unknown_events, 2);
            assert_eq!(counters.otlp_traces_conversion_errors, 3);
            assert_eq!(counters.otlp_traces_quality_reasons, reasons);
        }
        let reopened = DeliveryLedger::open(&path).unwrap();
        let counters = reopened.ingest_quality_counters().unwrap();
        assert_eq!(counters.total().unwrap(), 5);
        assert_eq!(counters.otlp_traces_unknown_events, 2);
        assert_eq!(counters.otlp_traces_conversion_errors, 3);
        assert_eq!(
            counters.otlp_traces_quality_reasons,
            BTreeMap::from([
                ("unsupported_event".to_owned(), 2),
                ("invalid_structure".to_owned(), 3),
            ])
        );
        let coverage = IngestCoverageState::with_quality_counters(counters)
            .unwrap()
            .snapshot();
        assert_eq!(coverage["quality_errors_scope"], "durable_relay_state");
        assert_eq!(coverage["quality_errors"], 5);
        assert_eq!(coverage["quality_errors_current_process"], 0);
        assert_eq!(
            coverage["quality_errors_by_endpoint"]["otlp_traces"]["total"],
            5
        );
    }

    #[test]
    fn ingest_quality_counter_overflow_fails_closed_without_partial_update() {
        let mut counters = IngestQualityCounters {
            otlp_logs_unknown_events: u64::MAX,
            otlp_logs_quality_reasons: BTreeMap::from([("unsupported_event".to_owned(), u64::MAX)]),
            ..IngestQualityCounters::default()
        };
        let before = counters.clone();
        let reasons = BTreeMap::from([("unsupported_event".to_owned(), 1)]);
        let error = counters
            .add(CloudEndpoint::OtlpLogs, 1, 0, &reasons)
            .expect_err("u64 quality counters must reject overflow");
        assert!(
            error
                .to_string()
                .contains("OTLP logs unknown-event counter overflow")
        );
        assert_eq!(
            counters.otlp_logs_unknown_events,
            before.otlp_logs_unknown_events
        );
        assert_eq!(
            counters.otlp_logs_quality_reasons,
            before.otlp_logs_quality_reasons
        );

        let mut reason_overflow = IngestQualityCounters {
            otlp_logs_quality_reasons: BTreeMap::from([("unsupported_event".to_owned(), u64::MAX)]),
            ..IngestQualityCounters::default()
        };
        let before_reason_overflow = reason_overflow.clone();
        let error = reason_overflow
            .add(CloudEndpoint::OtlpLogs, 1, 0, &reasons)
            .expect_err("quality reason counters must reject overflow");
        assert!(
            error
                .to_string()
                .contains("quality reason counter overflow")
        );
        assert_eq!(reason_overflow.otlp_logs_unknown_events, 0);
        assert_eq!(
            reason_overflow.otlp_logs_quality_reasons,
            before_reason_overflow.otlp_logs_quality_reasons
        );

        let coverage_error = IngestCoverageState::with_quality_counters(IngestQualityCounters {
            otlp_logs_unknown_events: u64::MAX,
            otlp_logs_conversion_errors: 1,
            ..IngestQualityCounters::default()
        })
        .expect_err("coverage state must reject an overflowing durable total");
        assert!(
            coverage_error
                .to_string()
                .contains("durable quality counter total overflow")
        );
    }

    #[test]
    fn legacy_delivery_ledger_requires_and_imports_quality_seed() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("delivery.redb");
        {
            let ledger = DeliveryLedger::open(&path).unwrap();
            ledger
                .ensure(&CaptureLocator {
                    capture_id: "legacy-capture".to_owned(),
                    raw_sha256: "a".repeat(64),
                    segment_id: 1,
                    offset: 0,
                    length: 12,
                    received_at: None,
                    model: None,
                })
                .unwrap();
        }
        {
            let database = Database::create(&path).unwrap();
            let transaction = database.begin_write().unwrap();
            let mut meta = transaction.open_table(META).unwrap();
            meta.remove(INGEST_QUALITY_COUNTERS_KEY).unwrap();
            drop(meta);
            transaction.commit().unwrap();
        }
        let error = match DeliveryLedger::open(&path) {
            Ok(_) => panic!("legacy ledger without quality seed must refuse startup"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("quality history migration"));

        let counters = IngestQualityCounters {
            otlp_traces_conversion_errors: 7,
            ..IngestQualityCounters::default()
        };
        let seed = IngestQualitySeed {
            schema_version: INGEST_QUALITY_SEED_SCHEMA_VERSION.to_owned(),
            source_quality_errors: counters.total().unwrap(),
            counters,
        };
        fs::write(
            temporary.path().join(INGEST_QUALITY_SEED_FILE),
            serde_json::to_vec(&seed).unwrap(),
        )
        .unwrap();
        let reopened = DeliveryLedger::open(&path).unwrap();
        assert_eq!(
            reopened.ingest_quality_counters().unwrap().total().unwrap(),
            7
        );
        assert_eq!(
            reopened
                .ingest_quality_counters()
                .unwrap()
                .otlp_traces_conversion_errors,
            7
        );
        assert_eq!(
            reopened
                .ingest_quality_counters()
                .unwrap()
                .otlp_traces_quality_reasons,
            BTreeMap::from([("legacy_unclassified".to_owned(), 7)])
        );
    }
}
