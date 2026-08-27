use crate::capture::CaptureRecord;
use crate::jsonl::{sha256_file, utc_now};
use anyhow::{Context, Result, bail};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const CAPTURES: TableDefinition<&str, &[u8]> = TableDefinition::new("captures");
const SEGMENTS: TableDefinition<u64, &[u8]> = TableDefinition::new("segments");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const ATTEMPTS: TableDefinition<u64, &[u8]> = TableDefinition::new("attempts");
const LEDGER_SCHEMA_VERSION: &str = "chiptrace.ledger.v1";
const COUNTERS_KEY: &str = "runtime_counters_v1";

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub root: PathBuf,
    pub state_root: PathBuf,
    pub segment_max_bytes: u64,
    pub segment_max_age: Duration,
    pub queue_items: usize,
    pub batch_records: usize,
    pub batch_bytes: usize,
    pub batch_wait: Duration,
    pub fsync: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureLocator {
    pub capture_id: String,
    pub raw_sha256: String,
    pub segment_id: u64,
    pub offset: u64,
    pub length: u64,
    pub received_at: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentMetadata {
    pub segment_id: u64,
    pub path: String,
    pub state: String,
    pub bytes: u64,
    pub records: u64,
    pub created_at: String,
    pub sealed_at: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attempt {
    pub attempt_id: u64,
    pub capture_id: Option<String>,
    pub raw_sha256: Option<String>,
    pub state: String,
    pub reason: Option<String>,
    pub received_at: String,
    pub committed_at: Option<String>,
    pub segment_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitAck {
    pub capture_id: String,
    pub state: String,
    pub durable: bool,
    pub duplicate: bool,
    pub raw_sha256: String,
    pub segment_id: u64,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoreHealth {
    pub ok: bool,
    pub ready: bool,
    pub captures: u64,
    pub attempts: u64,
    pub accepted_attempts: u64,
    pub duplicate_attempts: u64,
    pub conflict_attempts: u64,
    pub rejected_attempts: u64,
    pub active_segment_id: u64,
    pub active_segment_bytes: u64,
    pub active_segment_records: u64,
    pub sealed_segments: u64,
    pub sealed_bytes: u64,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub recovery_records: u64,
    pub last_commit_at: Option<String>,
    pub last_error: Option<String>,
    pub ledger_schema_version: String,
}

#[derive(Debug, Clone, Default)]
struct RuntimeState {
    ready: bool,
    captures: u64,
    attempts: u64,
    accepted_attempts: u64,
    duplicate_attempts: u64,
    conflict_attempts: u64,
    rejected_attempts: u64,
    active_segment_id: u64,
    active_segment_bytes: u64,
    active_segment_records: u64,
    sealed_segments: u64,
    sealed_bytes: u64,
    recovery_records: u64,
    last_commit_at: Option<String>,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct LedgerCounters {
    captures: u64,
    attempts: u64,
    accepted_attempts: u64,
    duplicate_attempts: u64,
    conflict_attempts: u64,
    rejected_attempts: u64,
    sealed_segments: u64,
    sealed_bytes: u64,
    last_commit_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
struct RecoverySummary {
    records: u64,
    ledger_changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitErrorKind {
    Conflict,
    Unavailable,
}

#[derive(Debug)]
pub struct SubmitError {
    pub kind: SubmitErrorKind,
    pub message: String,
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SubmitError {}

struct WriteTask {
    record: CaptureRecord,
    response: oneshot::Sender<std::result::Result<SubmitAck, SubmitError>>,
}

enum WriterCommand {
    Submit(WriteTask),
    Flush(oneshot::Sender<Result<SegmentMetadata>>),
    Audit(bool, oneshot::Sender<Result<serde_json::Value>>),
    ReadCapture(String, oneshot::Sender<Result<Vec<u8>>>),
    ListCaptures(oneshot::Sender<Result<Vec<CaptureLocator>>>),
    Shutdown(oneshot::Sender<Result<()>>),
}

#[derive(Clone)]
pub struct CaptureStore {
    sender: flume::Sender<WriterCommand>,
    state: Arc<RwLock<RuntimeState>>,
    config: Arc<StoreConfig>,
}

impl CaptureStore {
    pub async fn open(config: StoreConfig) -> Result<Self> {
        if config.segment_max_bytes == 0
            || config.queue_items == 0
            || config.batch_records == 0
            || config.batch_bytes == 0
        {
            bail!("store size and queue parameters must be positive");
        }
        fs::create_dir_all(config.root.join("segments"))?;
        fs::create_dir_all(&config.state_root)?;
        set_private_permissions(&config.root)?;
        set_private_permissions(&config.state_root)?;
        let config = Arc::new(config);
        let state = Arc::new(RwLock::new(RuntimeState::default()));
        let (sender, receiver) = flume::bounded(config.queue_items);
        let writer_config = Arc::clone(&config);
        let writer_state = Arc::clone(&state);
        let (started_tx, started_rx) = oneshot::channel();
        std::thread::Builder::new()
            .name("chiptrace-wal-writer".to_owned())
            .spawn(move || {
                let result = Writer::open(&writer_config, &writer_state);
                match result {
                    Ok(writer) => {
                        let _ = started_tx.send(Ok(()));
                        writer.run(receiver, writer_state);
                    }
                    Err(error) => {
                        let _ = started_tx.send(Err(error));
                    }
                }
            })?;
        started_rx
            .await
            .context("collector writer stopped during startup")??;
        Ok(Self {
            sender,
            state,
            config,
        })
    }

    pub async fn submit(
        &self,
        record: CaptureRecord,
    ) -> std::result::Result<SubmitAck, SubmitError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(WriterCommand::Submit(WriteTask { record, response }))
            .map_err(|error| SubmitError {
                kind: SubmitErrorKind::Unavailable,
                message: format!("capture queue unavailable: {error}"),
            })?;
        receiver.await.map_err(|_| SubmitError {
            kind: SubmitErrorKind::Unavailable,
            message: "capture writer stopped before acknowledgement".to_owned(),
        })?
    }

    pub async fn submit_wait(
        &self,
        record: CaptureRecord,
    ) -> std::result::Result<SubmitAck, SubmitError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_async(WriterCommand::Submit(WriteTask { record, response }))
            .await
            .map_err(|error| SubmitError {
                kind: SubmitErrorKind::Unavailable,
                message: format!("capture queue unavailable: {error}"),
            })?;
        receiver.await.map_err(|_| SubmitError {
            kind: SubmitErrorKind::Unavailable,
            message: "capture writer stopped before acknowledgement".to_owned(),
        })?
    }

    pub async fn flush(&self) -> Result<SegmentMetadata> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_async(WriterCommand::Flush(response))
            .await
            .context("capture writer stopped")?;
        receiver
            .await
            .context("capture writer stopped during flush")?
    }

    pub async fn close(&self) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_async(WriterCommand::Shutdown(response))
            .await
            .context("capture writer already stopped")?;
        receiver
            .await
            .context("capture writer stopped during shutdown")?
    }

    pub fn health(&self) -> StoreHealth {
        let state = self.state.read().expect("runtime state poisoned").clone();
        StoreHealth {
            ok: state.ready && state.last_error.is_none(),
            ready: state.ready,
            captures: state.captures,
            attempts: state.attempts,
            accepted_attempts: state.accepted_attempts,
            duplicate_attempts: state.duplicate_attempts,
            conflict_attempts: state.conflict_attempts,
            rejected_attempts: state.rejected_attempts,
            active_segment_id: state.active_segment_id,
            active_segment_bytes: state.active_segment_bytes,
            active_segment_records: state.active_segment_records,
            sealed_segments: state.sealed_segments,
            sealed_bytes: state.sealed_bytes,
            queue_depth: self.sender.len(),
            queue_capacity: self.config.queue_items,
            recovery_records: state.recovery_records,
            last_commit_at: state.last_commit_at,
            last_error: state.last_error,
            ledger_schema_version: LEDGER_SCHEMA_VERSION.to_owned(),
        }
    }

    pub async fn audit(&self, verify_payloads: bool) -> Result<serde_json::Value> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_async(WriterCommand::Audit(verify_payloads, response))
            .await
            .context("capture writer stopped")?;
        receiver
            .await
            .context("capture writer stopped during audit")?
    }

    pub async fn read_capture(&self, capture_id: &str) -> Result<Vec<u8>> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_async(WriterCommand::ReadCapture(capture_id.to_owned(), response))
            .await
            .context("capture writer stopped")?;
        receiver
            .await
            .context("capture writer stopped while reading capture")?
    }

    pub async fn list_captures(&self) -> Result<Vec<CaptureLocator>> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_async(WriterCommand::ListCaptures(response))
            .await
            .context("capture writer stopped")?;
        receiver
            .await
            .context("capture writer stopped while listing captures")?
    }
}

struct ActiveSegment {
    metadata: SegmentMetadata,
    path: PathBuf,
    handle: File,
    digest: Sha256,
    opened_at: Instant,
}

struct BatchCommit {
    results: Vec<std::result::Result<SubmitAck, SubmitError>>,
    counters: LedgerCounters,
}

struct Writer {
    config: Arc<StoreConfig>,
    database: Database,
    active: ActiveSegment,
    next_attempt_id: u64,
}

impl Writer {
    fn open(config: &Arc<StoreConfig>, state: &Arc<RwLock<RuntimeState>>) -> Result<Self> {
        let database_path = config.state_root.join("capture-ledger.redb");
        let database = Database::create(&database_path)
            .with_context(|| format!("open {}", database_path.display()))?;
        initialize_database(&database)?;
        let recovered = recover_segments(config, &database)?;
        let (active, next_attempt_id) = open_active_segment(config, &database)?;
        let mut writer = Self {
            config: Arc::clone(config),
            database,
            active,
            next_attempt_id,
        };
        writer.refresh_state(state, recovered.records, None)?;
        Ok(writer)
    }

    fn run(mut self, receiver: flume::Receiver<WriterCommand>, state: Arc<RwLock<RuntimeState>>) {
        while let Ok(first) = receiver.recv() {
            match first {
                WriterCommand::Submit(task) => {
                    let mut batch = vec![task];
                    let mut batch_bytes = batch[0].record.canonical.len();
                    let deadline = Instant::now() + self.config.batch_wait;
                    while batch.len() < self.config.batch_records
                        && batch_bytes < self.config.batch_bytes
                    {
                        let now = Instant::now();
                        if now >= deadline {
                            break;
                        }
                        match receiver.recv_timeout(deadline - now) {
                            Ok(WriterCommand::Submit(task)) => {
                                batch_bytes =
                                    batch_bytes.saturating_add(task.record.canonical.len());
                                batch.push(task);
                            }
                            Ok(WriterCommand::Flush(response)) => {
                                if !self.commit_batch(batch, &state) {
                                    self.mark_stopped(&state);
                                    return;
                                }
                                let result = self.seal_and_rotate(&state);
                                let _ = response.send(result);
                                batch = Vec::new();
                                break;
                            }
                            Ok(WriterCommand::Shutdown(response)) => {
                                if !self.commit_batch(batch, &state) {
                                    self.mark_stopped(&state);
                                    return;
                                }
                                let result = self.shutdown_active();
                                self.mark_stopped(&state);
                                drop(self);
                                let _ = response.send(result);
                                return;
                            }
                            Ok(WriterCommand::Audit(verify_payloads, response)) => {
                                if !self.commit_batch(batch, &state) {
                                    self.mark_stopped(&state);
                                    return;
                                }
                                let result = audit_database(
                                    &self.config.root,
                                    &mut self.database,
                                    verify_payloads,
                                );
                                let _ = response.send(result);
                                batch = Vec::new();
                                break;
                            }
                            Ok(WriterCommand::ReadCapture(capture_id, response)) => {
                                if !self.commit_batch(batch, &state) {
                                    self.mark_stopped(&state);
                                    return;
                                }
                                let result = self.read_capture(&capture_id);
                                let _ = response.send(result);
                                batch = Vec::new();
                                break;
                            }
                            Ok(WriterCommand::ListCaptures(response)) => {
                                if !self.commit_batch(batch, &state) {
                                    self.mark_stopped(&state);
                                    return;
                                }
                                let result = self.list_captures();
                                let _ = response.send(result);
                                batch = Vec::new();
                                break;
                            }
                            Err(flume::RecvTimeoutError::Timeout) => break,
                            Err(flume::RecvTimeoutError::Disconnected) => {
                                if !self.commit_batch(batch, &state) {
                                    self.mark_stopped(&state);
                                    return;
                                }
                                let _ = self.shutdown_active();
                                self.mark_stopped(&state);
                                return;
                            }
                        }
                    }
                    if !batch.is_empty() && !self.commit_batch(batch, &state) {
                        self.mark_stopped(&state);
                        return;
                    }
                }
                WriterCommand::Flush(response) => {
                    let result = self.seal_and_rotate(&state);
                    let _ = response.send(result);
                }
                WriterCommand::Shutdown(response) => {
                    let result = self.shutdown_active();
                    self.mark_stopped(&state);
                    drop(self);
                    let _ = response.send(result);
                    return;
                }
                WriterCommand::Audit(verify_payloads, response) => {
                    let result =
                        audit_database(&self.config.root, &mut self.database, verify_payloads);
                    let _ = response.send(result);
                }
                WriterCommand::ReadCapture(capture_id, response) => {
                    let result = self.read_capture(&capture_id);
                    let _ = response.send(result);
                }
                WriterCommand::ListCaptures(response) => {
                    let result = self.list_captures();
                    let _ = response.send(result);
                }
            }
        }
        let _ = self.shutdown_active();
        self.mark_stopped(&state);
    }

    fn commit_batch(&mut self, batch: Vec<WriteTask>, state: &Arc<RwLock<RuntimeState>>) -> bool {
        match self.commit_batch_inner(&batch) {
            Ok(commit) => {
                self.apply_runtime_counters(state, &commit.counters);
                for (task, result) in batch.into_iter().zip(commit.results) {
                    let _ = task.response.send(result);
                }
                true
            }
            Err(error) => {
                let message = format!("{error:#}");
                self.set_error(state, message.clone());
                for task in batch {
                    let _ = task.response.send(Err(SubmitError {
                        kind: SubmitErrorKind::Unavailable,
                        message: message.clone(),
                    }));
                }
                false
            }
        }
    }

    fn commit_batch_inner(&mut self, batch: &[WriteTask]) -> Result<BatchCommit> {
        enum DuplicateSource {
            Existing(CaptureLocator),
            Batch(usize),
        }

        let read = self.database.begin_read()?;
        let table = read.open_table(CAPTURES)?;
        let mut primary_by_id: HashMap<String, usize> = HashMap::new();
        let mut pending_indices = Vec::new();
        let mut duplicate_sources = Vec::new();
        let mut conflicts = Vec::new();
        for (index, task) in batch.iter().enumerate() {
            let existing: Option<CaptureLocator> = table
                .get(task.record.capture_id.as_str())?
                .map(|value| serde_json::from_slice(value.value()))
                .transpose()?;
            if let Some(locator) = existing {
                if locator.raw_sha256 == task.record.sha256 {
                    duplicate_sources.push((index, DuplicateSource::Existing(locator)));
                } else {
                    conflicts.push(index);
                }
                continue;
            }
            if let Some(primary_index) = primary_by_id.get(&task.record.capture_id).copied() {
                if batch[primary_index].record.sha256 == task.record.sha256 {
                    duplicate_sources.push((index, DuplicateSource::Batch(primary_index)));
                } else {
                    conflicts.push(index);
                }
                continue;
            }
            primary_by_id.insert(task.record.capture_id.clone(), index);
            pending_indices.push(index);
        }
        drop(table);
        drop(read);

        let mut pending = Vec::new();
        let mut primary_locators = HashMap::new();
        for index in pending_indices {
            let task = &batch[index];
            if self.active.metadata.records > 0
                && self
                    .active
                    .metadata
                    .bytes
                    .saturating_add(task.record.canonical.len() as u64 + 1)
                    > self.config.segment_max_bytes
            {
                self.seal_active()?;
                self.active = create_active_segment(&self.config, &self.database)?;
            }
            let offset = self.active.metadata.bytes;
            let length = task.record.canonical.len() as u64 + 1;
            self.active.handle.write_all(&task.record.canonical)?;
            self.active.handle.write_all(b"\n")?;
            self.active.digest.update(&task.record.canonical);
            self.active.digest.update(b"\n");
            self.active.metadata.bytes += length;
            self.active.metadata.records += 1;
            let locator = CaptureLocator {
                capture_id: task.record.capture_id.clone(),
                raw_sha256: task.record.sha256.clone(),
                segment_id: self.active.metadata.segment_id,
                offset,
                length,
                received_at: task.record.received_at.clone(),
                model: task.record.model.clone(),
            };
            primary_locators.insert(index, locator.clone());
            pending.push((index, locator));
        }
        if !pending.is_empty() {
            self.active.handle.flush()?;
            if self.config.fsync {
                self.active.handle.sync_data()?;
            }
        }

        let duplicates: Vec<(usize, CaptureLocator)> = duplicate_sources
            .into_iter()
            .map(|(index, source)| {
                let locator = match source {
                    DuplicateSource::Existing(locator) => locator,
                    DuplicateSource::Batch(primary_index) => primary_locators
                        .get(&primary_index)
                        .expect("batch primary locator missing")
                        .clone(),
                };
                (index, locator)
            })
            .collect();
        let now = utc_now();
        let transaction = self.database.begin_write()?;
        let mut counters;
        {
            let mut captures = transaction.open_table(CAPTURES)?;
            let mut attempts = transaction.open_table(ATTEMPTS)?;
            let mut segments = transaction.open_table(SEGMENTS)?;
            let mut meta = transaction.open_table(META)?;
            counters = read_counters(&meta)?;
            for (index, locator) in &pending {
                let task = &batch[*index];
                captures.insert(
                    task.record.capture_id.as_str(),
                    serde_json::to_vec(locator)?.as_slice(),
                )?;
                let attempt = self.attempt(
                    Some(task.record.capture_id.clone()),
                    Some(task.record.sha256.clone()),
                    "accepted",
                    None,
                    Some(locator.segment_id),
                    &now,
                );
                attempts.insert(attempt.attempt_id, serde_json::to_vec(&attempt)?.as_slice())?;
            }
            for (index, locator) in &duplicates {
                let task = &batch[*index];
                let attempt = self.attempt(
                    Some(task.record.capture_id.clone()),
                    Some(task.record.sha256.clone()),
                    "duplicate",
                    Some("already_committed".to_owned()),
                    Some(locator.segment_id),
                    &now,
                );
                attempts.insert(attempt.attempt_id, serde_json::to_vec(&attempt)?.as_slice())?;
            }
            for index in &conflicts {
                let task = &batch[*index];
                let attempt = self.attempt(
                    Some(task.record.capture_id.clone()),
                    Some(task.record.sha256.clone()),
                    "conflict",
                    Some("same_capture_id_different_payload".to_owned()),
                    None,
                    &now,
                );
                attempts.insert(attempt.attempt_id, serde_json::to_vec(&attempt)?.as_slice())?;
            }
            segments.insert(
                self.active.metadata.segment_id,
                serde_json::to_vec(&self.active.metadata)?.as_slice(),
            )?;
            counters.captures = counters.captures.saturating_add(pending.len() as u64);
            counters.attempts = counters.attempts.saturating_add(batch.len() as u64);
            counters.accepted_attempts = counters
                .accepted_attempts
                .saturating_add(pending.len() as u64);
            counters.duplicate_attempts = counters
                .duplicate_attempts
                .saturating_add(duplicates.len() as u64);
            counters.conflict_attempts = counters
                .conflict_attempts
                .saturating_add(conflicts.len() as u64);
            counters.last_commit_at = Some(now.clone());
            write_counters(&mut meta, &counters)?;
        }
        transaction.commit()?;

        let duplicate_map: HashMap<usize, CaptureLocator> = duplicates.into_iter().collect();
        let pending_map: HashMap<usize, CaptureLocator> = pending.into_iter().collect();
        let conflict_set: std::collections::HashSet<usize> = conflicts.into_iter().collect();
        let mut results = Vec::with_capacity(batch.len());
        for index in 0..batch.len() {
            let result = if let Some(locator) = pending_map.get(&index) {
                Ok(ack(locator, false, "accepted"))
            } else if let Some(locator) = duplicate_map.get(&index) {
                Ok(ack(locator, true, "duplicate"))
            } else if conflict_set.contains(&index) {
                Err(SubmitError {
                    kind: SubmitErrorKind::Conflict,
                    message: "captureId was reused with different canonical bytes".to_owned(),
                })
            } else {
                unreachable!("batch task has no durable outcome")
            };
            results.push(result);
        }
        if self.active.metadata.records > 0
            && (self.active.metadata.bytes >= self.config.segment_max_bytes
                || self.active.opened_at.elapsed() >= self.config.segment_max_age)
        {
            self.seal_active()?;
            self.active = create_active_segment(&self.config, &self.database)?;
            counters = self.load_counters()?;
        }
        Ok(BatchCommit { results, counters })
    }

    fn attempt(
        &mut self,
        capture_id: Option<String>,
        raw_sha256: Option<String>,
        state: &str,
        reason: Option<String>,
        segment_id: Option<u64>,
        now: &str,
    ) -> Attempt {
        let attempt = Attempt {
            attempt_id: self.next_attempt_id,
            capture_id,
            raw_sha256,
            state: state.to_owned(),
            reason,
            received_at: now.to_owned(),
            committed_at: Some(now.to_owned()),
            segment_id,
        };
        self.next_attempt_id += 1;
        attempt
    }

    fn seal_and_rotate(&mut self, state: &Arc<RwLock<RuntimeState>>) -> Result<SegmentMetadata> {
        if self.active.metadata.records == 0 {
            self.active.handle.flush()?;
            if self.config.fsync {
                self.active.handle.sync_all()?;
            }
            return Ok(self.active.metadata.clone());
        }
        let sealed = self.seal_active()?;
        self.active = create_active_segment(&self.config, &self.database)?;
        let recovered = state
            .read()
            .expect("runtime state poisoned")
            .recovery_records;
        self.refresh_state(state, recovered, None)?;
        Ok(sealed)
    }

    fn seal_active(&mut self) -> Result<SegmentMetadata> {
        if self.active.metadata.records == 0 {
            bail!("refusing to seal an empty WAL segment");
        }
        self.active.handle.flush()?;
        if self.config.fsync {
            self.active.handle.sync_all()?;
        }
        let open_path = self.active.path.clone();
        let sealed_path = open_path.with_file_name(
            open_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .replace(".open.ndjson", ".sealed.ndjson"),
        );
        let sha256 = hex::encode(self.active.digest.clone().finalize());
        fs::rename(&open_path, &sealed_path)?;
        if self.config.fsync {
            fsync_directory(sealed_path.parent().unwrap_or(&self.config.root))?;
        }
        self.active.path = sealed_path.clone();
        self.active.metadata.path = relative_path(&self.config.root, &sealed_path)?;
        self.active.metadata.state = "sealed".to_owned();
        self.active.metadata.sealed_at = Some(utc_now());
        self.active.metadata.sha256 = Some(sha256);
        let transaction = self.database.begin_write()?;
        {
            let mut segments = transaction.open_table(SEGMENTS)?;
            let mut meta = transaction.open_table(META)?;
            segments.insert(
                self.active.metadata.segment_id,
                serde_json::to_vec(&self.active.metadata)?.as_slice(),
            )?;
            let mut counters = read_counters(&meta)?;
            counters.sealed_segments = counters.sealed_segments.saturating_add(1);
            counters.sealed_bytes = counters
                .sealed_bytes
                .saturating_add(self.active.metadata.bytes);
            write_counters(&mut meta, &counters)?;
        }
        transaction.commit()?;
        Ok(self.active.metadata.clone())
    }

    fn shutdown_active(&mut self) -> Result<()> {
        if self.active.metadata.records == 0 {
            self.active.handle.flush()?;
            if self.config.fsync {
                self.active.handle.sync_all()?;
            }
            Ok(())
        } else {
            self.seal_active().map(|_| ())
        }
    }

    fn refresh_state(
        &mut self,
        state: &Arc<RwLock<RuntimeState>>,
        recovered: u64,
        error: Option<String>,
    ) -> Result<()> {
        let read = self.database.begin_read()?;
        let meta = read.open_table(META)?;
        let counters = read_counters(&meta)?;
        let runtime = RuntimeState {
            ready: true,
            captures: counters.captures,
            attempts: counters.attempts,
            accepted_attempts: counters.accepted_attempts,
            duplicate_attempts: counters.duplicate_attempts,
            conflict_attempts: counters.conflict_attempts,
            rejected_attempts: counters.rejected_attempts,
            active_segment_id: self.active.metadata.segment_id,
            active_segment_bytes: self.active.metadata.bytes,
            active_segment_records: self.active.metadata.records,
            sealed_segments: counters.sealed_segments,
            sealed_bytes: counters.sealed_bytes,
            recovery_records: recovered,
            last_commit_at: counters.last_commit_at,
            last_error: error,
        };
        *state.write().expect("runtime state poisoned") = runtime;
        Ok(())
    }

    fn apply_runtime_counters(&self, state: &Arc<RwLock<RuntimeState>>, counters: &LedgerCounters) {
        let mut runtime = state.write().expect("runtime state poisoned");
        runtime.ready = true;
        runtime.captures = counters.captures;
        runtime.attempts = counters.attempts;
        runtime.accepted_attempts = counters.accepted_attempts;
        runtime.duplicate_attempts = counters.duplicate_attempts;
        runtime.conflict_attempts = counters.conflict_attempts;
        runtime.rejected_attempts = counters.rejected_attempts;
        runtime.active_segment_id = self.active.metadata.segment_id;
        runtime.active_segment_bytes = self.active.metadata.bytes;
        runtime.active_segment_records = self.active.metadata.records;
        runtime.sealed_segments = counters.sealed_segments;
        runtime.sealed_bytes = counters.sealed_bytes;
        runtime.last_commit_at.clone_from(&counters.last_commit_at);
        runtime.last_error = None;
    }

    fn load_counters(&self) -> Result<LedgerCounters> {
        let read = self.database.begin_read()?;
        let meta = read.open_table(META)?;
        read_counters(&meta)
    }

    fn set_error(&self, state: &Arc<RwLock<RuntimeState>>, message: String) {
        let mut state = state.write().expect("runtime state poisoned");
        state.ready = false;
        state.last_error = Some(message);
    }

    fn mark_stopped(&self, state: &Arc<RwLock<RuntimeState>>) {
        state.write().expect("runtime state poisoned").ready = false;
    }

    fn list_captures(&self) -> Result<Vec<CaptureLocator>> {
        let read = self.database.begin_read()?;
        let table = read.open_table(CAPTURES)?;
        let mut output = Vec::with_capacity(table.len()? as usize);
        for row in table.iter()? {
            let (_, value) = row?;
            output.push(serde_json::from_slice(value.value())?);
        }
        Ok(output)
    }

    fn read_capture(&self, capture_id: &str) -> Result<Vec<u8>> {
        let read = self.database.begin_read()?;
        let captures = read.open_table(CAPTURES)?;
        let segments = read.open_table(SEGMENTS)?;
        let locator: CaptureLocator = captures
            .get(capture_id)?
            .map(|value| serde_json::from_slice(value.value()))
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("capture not found: {capture_id}"))?;
        let segment: SegmentMetadata = segments
            .get(locator.segment_id)?
            .map(|value| serde_json::from_slice(value.value()))
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("segment not found: {}", locator.segment_id))?;
        let mut file = File::open(self.config.root.join(segment.path))?;
        file.seek(SeekFrom::Start(locator.offset))?;
        let mut bytes = vec![0_u8; locator.length as usize];
        std::io::Read::read_exact(&mut file, &mut bytes)?;
        if bytes.pop() != Some(b'\n') {
            bail!("capture locator newline mismatch: {capture_id}");
        }
        if hex::encode(Sha256::digest(&bytes)) != locator.raw_sha256 {
            bail!("capture locator checksum mismatch: {capture_id}");
        }
        Ok(bytes)
    }
}

fn ack(locator: &CaptureLocator, duplicate: bool, state: &str) -> SubmitAck {
    SubmitAck {
        capture_id: locator.capture_id.clone(),
        state: state.to_owned(),
        durable: true,
        duplicate,
        raw_sha256: locator.raw_sha256.clone(),
        segment_id: locator.segment_id,
        offset: locator.offset,
        length: locator.length,
    }
}

fn read_counters<T>(meta: &T) -> Result<LedgerCounters>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    meta.get(COUNTERS_KEY)?
        .map(|value| serde_json::from_slice(value.value()).map_err(anyhow::Error::from))
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("ledger runtime counters are missing"))
}

fn write_counters(
    meta: &mut redb::Table<'_, &'static str, &'static [u8]>,
    counters: &LedgerCounters,
) -> Result<()> {
    let bytes = serde_json::to_vec(counters)?;
    meta.insert(COUNTERS_KEY, bytes.as_slice())?;
    Ok(())
}

fn counters_from_tables<C, A, S>(captures: &C, attempts: &A, segments: &S) -> Result<LedgerCounters>
where
    C: ReadableTable<&'static str, &'static [u8]>,
    A: ReadableTable<u64, &'static [u8]>,
    S: ReadableTable<u64, &'static [u8]>,
{
    let mut counters = LedgerCounters {
        captures: captures.len()?,
        attempts: attempts.len()?,
        ..LedgerCounters::default()
    };
    for row in attempts.iter()? {
        let (_, value) = row?;
        let attempt: Attempt = serde_json::from_slice(value.value())?;
        match attempt.state.as_str() {
            "accepted" | "recovered" => counters.accepted_attempts += 1,
            "duplicate" => counters.duplicate_attempts += 1,
            "conflict" => counters.conflict_attempts += 1,
            _ => counters.rejected_attempts += 1,
        }
        counters.last_commit_at = attempt.committed_at;
    }
    for row in segments.iter()? {
        let (_, value) = row?;
        let segment: SegmentMetadata = serde_json::from_slice(value.value())?;
        if segment.state == "sealed" {
            counters.sealed_segments += 1;
            counters.sealed_bytes = counters.sealed_bytes.saturating_add(segment.bytes);
        }
    }
    Ok(counters)
}

fn rebuild_counters(database: &Database) -> Result<()> {
    let transaction = database.begin_write()?;
    {
        let captures = transaction.open_table(CAPTURES)?;
        let attempts = transaction.open_table(ATTEMPTS)?;
        let segments = transaction.open_table(SEGMENTS)?;
        let counters = counters_from_tables(&captures, &attempts, &segments)?;
        let mut meta = transaction.open_table(META)?;
        write_counters(&mut meta, &counters)?;
    }
    transaction.commit()?;
    Ok(())
}

fn digest_file(path: &Path) -> Result<Sha256> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 8 * 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest)
}

fn initialize_database(database: &Database) -> Result<()> {
    let transaction = database.begin_write()?;
    {
        let captures = transaction.open_table(CAPTURES)?;
        let segments = transaction.open_table(SEGMENTS)?;
        let attempts = transaction.open_table(ATTEMPTS)?;
        let mut meta = transaction.open_table(META)?;
        if let Some(existing) = meta.get("schema_version")? {
            let existing = std::str::from_utf8(existing.value())?;
            if existing != LEDGER_SCHEMA_VERSION {
                bail!("unsupported ledger schema {existing:?}; expected {LEDGER_SCHEMA_VERSION:?}");
            }
        } else {
            meta.insert("schema_version", LEDGER_SCHEMA_VERSION.as_bytes())?;
            meta.insert("created_at", utc_now().as_bytes())?;
        }
        let counters_missing = meta.get(COUNTERS_KEY)?.is_none();
        if counters_missing {
            let counters = counters_from_tables(&captures, &attempts, &segments)?;
            write_counters(&mut meta, &counters)?;
        }
    }
    transaction.commit()?;
    Ok(())
}

fn recover_segments(config: &StoreConfig, database: &Database) -> Result<RecoverySummary> {
    let segment_directory = config.root.join("segments");
    let mut paths: Vec<PathBuf> = fs::read_dir(&segment_directory)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.ends_with(".open.ndjson") || name.ends_with(".sealed.ndjson")
                })
        })
        .collect();
    paths.sort();
    let mut summary = RecoverySummary::default();
    let mut next_attempt_id = {
        let read = database.begin_read()?;
        let attempts = read.open_table(ATTEMPTS)?;
        attempts
            .iter()?
            .next_back()
            .transpose()?
            .map(|(key, _)| key.value() + 1)
            .unwrap_or(1)
    };
    for path in paths {
        let segment_id = segment_id_from_path(&path)?;
        let is_open = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".open.ndjson"));
        let file = OpenOptions::new().read(true).write(is_open).open(&path)?;
        let size = file.metadata()?.len();
        let existing_metadata = {
            let read = database.begin_read()?;
            let segments = read.open_table(SEGMENTS)?;
            segments
                .get(segment_id)?
                .map(|value| serde_json::from_slice::<SegmentMetadata>(value.value()))
                .transpose()?
        };
        if !is_open
            && existing_metadata.as_ref().is_some_and(|metadata| {
                metadata.state == "sealed"
                    && config.root.join(&metadata.path) == path
                    && metadata.bytes == size
                    && metadata.sha256.is_some()
            })
        {
            continue;
        }
        let mut reader = BufReader::new(file);
        let mut offset = 0_u64;
        let mut records = 0_u64;
        let mut rows = Vec::new();
        loop {
            let mut line = Vec::new();
            let length = reader.read_until(b'\n', &mut line)? as u64;
            if length == 0 {
                break;
            }
            if !line.ends_with(b"\n") {
                if !is_open {
                    bail!("sealed segment has an incomplete tail: {}", path.display());
                }
                reader.get_mut().set_len(offset)?;
                break;
            }
            line.pop();
            if line.ends_with(b"\r") {
                line.pop();
            }
            let record = crate::capture::validate_stored_capture(&line)
                .with_context(|| format!("recover {} at offset {offset}", path.display()))?;
            let locator = CaptureLocator {
                capture_id: record.capture_id,
                raw_sha256: record.sha256,
                segment_id,
                offset,
                length,
                received_at: record.received_at,
                model: record.model,
            };
            rows.push(locator);
            offset += length;
            records += 1;
        }
        if !is_open && offset != size {
            bail!(
                "sealed segment locator coverage mismatch: {}",
                path.display()
            );
        }
        let metadata = SegmentMetadata {
            segment_id,
            path: relative_path(&config.root, &path)?,
            state: if is_open { "open" } else { "sealed" }.to_owned(),
            bytes: offset,
            records,
            created_at: existing_metadata
                .as_ref()
                .map(|metadata| metadata.created_at.clone())
                .unwrap_or_else(utc_now),
            sealed_at: if is_open {
                None
            } else {
                existing_metadata
                    .as_ref()
                    .and_then(|metadata| metadata.sealed_at.clone())
                    .or_else(|| Some(utc_now()))
            },
            sha256: if is_open {
                None
            } else {
                Some(sha256_file(&path)?)
            },
        };
        let transaction = database.begin_write()?;
        {
            let mut captures = transaction.open_table(CAPTURES)?;
            let mut attempts = transaction.open_table(ATTEMPTS)?;
            let mut segments = transaction.open_table(SEGMENTS)?;
            for locator in rows {
                let existing: Option<CaptureLocator> = captures
                    .get(locator.capture_id.as_str())?
                    .map(|value| serde_json::from_slice(value.value()))
                    .transpose()?;
                if let Some(existing) = existing {
                    if existing.raw_sha256 != locator.raw_sha256 {
                        bail!("captureId conflict during recovery: {}", locator.capture_id);
                    }
                } else {
                    captures.insert(
                        locator.capture_id.as_str(),
                        serde_json::to_vec(&locator)?.as_slice(),
                    )?;
                    let committed_at = utc_now();
                    let attempt = Attempt {
                        attempt_id: next_attempt_id,
                        capture_id: Some(locator.capture_id.clone()),
                        raw_sha256: Some(locator.raw_sha256.clone()),
                        state: "recovered".to_owned(),
                        reason: Some("wal_without_ledger_commit".to_owned()),
                        received_at: locator
                            .received_at
                            .clone()
                            .unwrap_or_else(|| committed_at.clone()),
                        committed_at: Some(committed_at),
                        segment_id: Some(locator.segment_id),
                    };
                    attempts
                        .insert(attempt.attempt_id, serde_json::to_vec(&attempt)?.as_slice())?;
                    next_attempt_id += 1;
                    summary.records += 1;
                    summary.ledger_changed = true;
                }
            }
            if existing_metadata.as_ref() != Some(&metadata) {
                summary.ledger_changed = true;
            }
            segments.insert(segment_id, serde_json::to_vec(&metadata)?.as_slice())?;
        }
        transaction.commit()?;
    }
    if summary.ledger_changed {
        rebuild_counters(database)?;
    }
    Ok(summary)
}

fn open_active_segment(
    config: &Arc<StoreConfig>,
    database: &Database,
) -> Result<(ActiveSegment, u64)> {
    let read = database.begin_read()?;
    let segments = read.open_table(SEGMENTS)?;
    let attempts = read.open_table(ATTEMPTS)?;
    let next_attempt = attempts
        .iter()?
        .next_back()
        .transpose()?
        .map(|(key, _)| key.value() + 1)
        .unwrap_or(1);
    let mut active_metadata = None;
    for row in segments.iter()? {
        let (_, value) = row?;
        let metadata: SegmentMetadata = serde_json::from_slice(value.value())?;
        if metadata.state == "open" {
            if active_metadata.is_some() {
                bail!("multiple open segments found");
            }
            active_metadata = Some(metadata);
        }
    }
    drop(attempts);
    drop(segments);
    drop(read);
    let active = if let Some(metadata) = active_metadata {
        let path = config.root.join(&metadata.path);
        let mut handle = OpenOptions::new().read(true).append(true).open(&path)?;
        handle.seek(SeekFrom::End(0))?;
        let digest = digest_file(&path)?;
        ActiveSegment {
            metadata,
            path,
            handle,
            digest,
            opened_at: Instant::now(),
        }
    } else {
        create_active_segment(config, database)?
    };
    Ok((active, next_attempt))
}

fn create_active_segment(config: &StoreConfig, database: &Database) -> Result<ActiveSegment> {
    let read = database.begin_read()?;
    let table = read.open_table(SEGMENTS)?;
    let segment_id = table
        .iter()?
        .next_back()
        .transpose()?
        .map(|(key, _)| key.value() + 1)
        .unwrap_or(1);
    drop(table);
    drop(read);
    let path = config
        .root
        .join("segments")
        .join(format!("segment-{segment_id:020}.open.ndjson"));
    let handle = OpenOptions::new()
        .create_new(true)
        .read(true)
        .append(true)
        .open(&path)?;
    if config.fsync {
        fsync_directory(path.parent().unwrap_or(&config.root))?;
    }
    let metadata = SegmentMetadata {
        segment_id,
        path: relative_path(&config.root, &path)?,
        state: "open".to_owned(),
        bytes: 0,
        records: 0,
        created_at: utc_now(),
        sealed_at: None,
        sha256: None,
    };
    let transaction = database.begin_write()?;
    {
        let mut segments = transaction.open_table(SEGMENTS)?;
        segments.insert(segment_id, serde_json::to_vec(&metadata)?.as_slice())?;
    }
    transaction.commit()?;
    Ok(ActiveSegment {
        metadata,
        path,
        handle,
        digest: Sha256::new(),
        opened_at: Instant::now(),
    })
}

pub fn audit_store(
    root: &Path,
    state_root: &Path,
    verify_payloads: bool,
) -> Result<serde_json::Value> {
    let database_path = state_root.join("capture-ledger.redb");
    let mut database = Database::open(&database_path)?;
    audit_database(root, &mut database, verify_payloads)
}

fn audit_database(
    root: &Path,
    database: &mut Database,
    verify_payloads: bool,
) -> Result<serde_json::Value> {
    let integrity = database.check_integrity()?;
    let read = database.begin_read()?;
    let captures = read.open_table(CAPTURES)?;
    let segments = read.open_table(SEGMENTS)?;
    let attempts = read.open_table(ATTEMPTS)?;
    let mut locators_by_segment: BTreeMap<u64, Vec<CaptureLocator>> = BTreeMap::new();
    let mut capture_ids = HashSet::new();
    for row in captures.iter()? {
        let (_, value) = row?;
        let locator: CaptureLocator = serde_json::from_slice(value.value())?;
        capture_ids.insert(locator.capture_id.clone());
        locators_by_segment
            .entry(locator.segment_id)
            .or_default()
            .push(locator);
    }
    let mut failures = Vec::new();
    let mut sealed = 0_u64;
    for row in segments.iter()? {
        let (_, value) = row?;
        let metadata: SegmentMetadata = serde_json::from_slice(value.value())?;
        let path = root.join(&metadata.path);
        if !path.is_file() {
            failures.push(format!("missing_segment:{}", metadata.segment_id));
            continue;
        }
        if metadata.state == "sealed" {
            sealed += 1;
            let digest = sha256_file(&path)?;
            if metadata.sha256.as_deref() != Some(digest.as_str()) {
                failures.push(format!("segment_sha256:{}", metadata.segment_id));
            }
        }
        let mut locators = locators_by_segment
            .remove(&metadata.segment_id)
            .unwrap_or_default();
        locators.sort_by_key(|locator| locator.offset);
        let mut expected_offset = 0_u64;
        let mut file = File::open(&path)?;
        for locator in locators {
            if locator.offset != expected_offset {
                failures.push(format!("locator_gap:{}", metadata.segment_id));
            }
            if verify_payloads {
                file.seek(SeekFrom::Start(locator.offset))?;
                let mut bytes = vec![0_u8; locator.length as usize];
                std::io::Read::read_exact(&mut file, &mut bytes)?;
                if bytes.pop() != Some(b'\n') {
                    failures.push(format!("locator_newline:{}", locator.capture_id));
                } else if hex::encode(Sha256::digest(&bytes)) != locator.raw_sha256 {
                    failures.push(format!("payload_sha256:{}", locator.capture_id));
                }
            }
            expected_offset = expected_offset.saturating_add(locator.length);
        }
        if expected_offset != metadata.bytes {
            failures.push(format!("locator_coverage:{}", metadata.segment_id));
        }
    }
    if !locators_by_segment.is_empty() {
        failures.push("captures_reference_missing_segments".to_owned());
    }
    let mut captures_with_durable_attempt = HashSet::new();
    for row in attempts.iter()? {
        let (_, value) = row?;
        let attempt: Attempt = serde_json::from_slice(value.value())?;
        if matches!(attempt.state.as_str(), "accepted" | "recovered")
            && let Some(capture_id) = attempt.capture_id
        {
            captures_with_durable_attempt.insert(capture_id);
        }
    }
    let capture_count = captures.len()?;
    let attempt_count = attempts.len()?;
    let captures_without_durable_attempt = capture_ids
        .difference(&captures_with_durable_attempt)
        .count() as u64;
    let attempt_conservation =
        attempt_count >= capture_count && captures_without_durable_attempt == 0;
    if !attempt_conservation {
        failures.push(format!(
            "captures_without_durable_attempt:{captures_without_durable_attempt}"
        ));
    }
    Ok(json!({
        "ok": integrity && failures.is_empty(),
        "ledger_integrity": integrity,
        "captures": capture_count,
        "attempts": attempt_count,
        "sealed_segments": sealed,
        "verify_payloads": verify_payloads,
        "failures": failures,
        "captures_without_durable_attempt": captures_without_durable_attempt,
        "attempt_conservation": attempt_conservation,
    }))
}

fn segment_id_from_path(path: &Path) -> Result<u64> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid segment path {}", path.display()))?;
    name.strip_prefix("segment-")
        .and_then(|value| value.split('.').next())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid segment filename {name:?}"))
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", path.display(), root.display()))?
        .to_string_lossy()
        .into_owned())
}

fn set_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn fsync_directory(path: &Path) -> Result<()> {
    let directory = File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::normalize_capture;
    use serde_json::json;

    fn record(id: &str, status: u64) -> CaptureRecord {
        normalize_capture(
            &serde_json::to_vec(&json!({
                "captureId": id,
                "startedAt": "2026-08-27T00:00:00Z",
                "responseStatus": status,
                "requestBodyText": "{\"model\":\"gpt-5.6-sol\"}",
                "responseBodyText": "{}"
            }))
            .unwrap(),
            1024 * 1024,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn durable_idempotence_recovery_and_conflict() {
        let temporary = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            root: temporary.path().join("capture"),
            state_root: temporary.path().join("state"),
            segment_max_bytes: 4096,
            segment_max_age: Duration::from_secs(60),
            queue_items: 16,
            batch_records: 8,
            batch_bytes: 4096,
            batch_wait: Duration::from_millis(1),
            fsync: true,
        };
        let store = CaptureStore::open(config.clone()).await.unwrap();
        let first = store.submit(record("cap-one", 200)).await.unwrap();
        let duplicate = store.submit(record("cap-one", 200)).await.unwrap();
        assert!(first.durable);
        assert!(duplicate.duplicate);
        let conflict = store.submit(record("cap-one", 503)).await.unwrap_err();
        assert_eq!(conflict.kind, SubmitErrorKind::Conflict);
        store.close().await.unwrap();

        let reopened = CaptureStore::open(config).await.unwrap();
        assert_eq!(reopened.health().captures, 1);
        assert!(reopened.audit(true).await.unwrap()["ok"].as_bool().unwrap());
        reopened.close().await.unwrap();
    }

    #[tokio::test]
    async fn wal_recovery_creates_a_conserved_attempt() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("capture");
        let state_root = temporary.path().join("state");
        let segments = root.join("segments");
        fs::create_dir_all(&segments).unwrap();
        let recovered = record("cap-recovered", 503);
        let path = segments.join("segment-00000000000000000001.open.ndjson");
        let mut file = File::create(path).unwrap();
        file.write_all(&recovered.canonical).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();

        let store = CaptureStore::open(StoreConfig {
            root,
            state_root,
            segment_max_bytes: 4096,
            segment_max_age: Duration::from_secs(60),
            queue_items: 16,
            batch_records: 8,
            batch_bytes: 4096,
            batch_wait: Duration::from_millis(1),
            fsync: true,
        })
        .await
        .unwrap();
        let health = store.health();
        assert_eq!(health.captures, 1);
        assert_eq!(health.attempts, 1);
        assert_eq!(health.accepted_attempts, 1);
        assert_eq!(health.recovery_records, 1);
        let audit = store.audit(true).await.unwrap();
        assert_eq!(audit["attempt_conservation"], true);
        assert_eq!(audit["captures_without_durable_attempt"], 0);
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn empty_store_restart_does_not_create_sealed_segments() {
        let temporary = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            root: temporary.path().join("capture"),
            state_root: temporary.path().join("state"),
            segment_max_bytes: 4096,
            segment_max_age: Duration::from_secs(60),
            queue_items: 16,
            batch_records: 8,
            batch_bytes: 4096,
            batch_wait: Duration::from_millis(1),
            fsync: true,
        };
        let store = CaptureStore::open(config.clone()).await.unwrap();
        assert_eq!(store.health().active_segment_id, 1);
        store.close().await.unwrap();
        let reopened = CaptureStore::open(config).await.unwrap();
        assert_eq!(reopened.health().active_segment_id, 1);
        assert_eq!(reopened.health().sealed_segments, 0);
        reopened.close().await.unwrap();
    }

    #[tokio::test]
    async fn missing_runtime_counters_are_rebuilt_from_ledger() {
        let temporary = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            root: temporary.path().join("capture"),
            state_root: temporary.path().join("state"),
            segment_max_bytes: 1024 * 1024,
            segment_max_age: Duration::from_secs(60),
            queue_items: 8,
            batch_records: 4,
            batch_bytes: 1024 * 1024,
            batch_wait: Duration::from_millis(1),
            fsync: true,
        };
        let store = CaptureStore::open(config.clone()).await.unwrap();
        store.submit(record("cap-counter", 200)).await.unwrap();
        store.close().await.unwrap();
        let database = Database::open(config.state_root.join("capture-ledger.redb")).unwrap();
        let transaction = database.begin_write().unwrap();
        {
            let mut meta = transaction.open_table(META).unwrap();
            meta.remove(COUNTERS_KEY).unwrap();
        }
        transaction.commit().unwrap();
        drop(database);
        let reopened = CaptureStore::open(config).await.unwrap();
        let health = reopened.health();
        assert_eq!(health.captures, 1);
        assert_eq!(health.attempts, 1);
        assert_eq!(health.accepted_attempts, 1);
        reopened.close().await.unwrap();
    }
}
