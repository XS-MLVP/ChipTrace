use crate::capture::normalize_capture;
use crate::codex_rollout::{
    ExportConfig, ExportSummary, export_codex_rollout, resolve_rollout_path,
};
use crate::delivery::{DeliveryConfig, DeliveryTarget, deliver_batch};
use crate::producer::{codex_hook_occurrence_digest, deterministic_codex_hook_capture_id};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const HOOK_SPOOL_SCHEMA_VERSION: &str = "chiptrace.codex-hook-spool.v2";
const LEGACY_HOOK_SPOOL_SCHEMA_VERSION: &str = "chiptrace.codex-hook-spool.v1";
const MAX_HOOK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HookSpoolConfig {
    pub queue_root: PathBuf,
    pub max_input_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookSpoolSummary {
    pub event_id: String,
    pub event_name: String,
    pub path: String,
    pub bytes: u64,
    pub duplicate: bool,
}

#[derive(Debug, Clone)]
pub struct CodexAgentConfig {
    pub queue_root: PathBuf,
    pub session_root: PathBuf,
    pub state_root: PathBuf,
    pub target: DeliveryTarget,
    pub source_namespace: String,
    pub batch_records: usize,
    pub max_envelope_bytes: usize,
    pub request_timeout: Duration,
    pub retry_max_times: usize,
    pub poll_interval: Duration,
    pub once: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexAgentSummary {
    pub cycles: u64,
    pub queued: u64,
    pub acknowledged: u64,
    pub failed: u64,
    pub duplicate_captures: u64,
    pub rollout_captures: u64,
    pub errors: Vec<String>,
    pub stop_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpooledHookEvent {
    schema_version: String,
    event_id: String,
    received_at: String,
    raw_input: String,
    raw_input_sha256: String,
    event: Value,
}

#[derive(Debug, Clone, Default)]
struct RolloutIdentity {
    session_id: Option<String>,
    thread_id: Option<String>,
    parent_thread_id: Option<String>,
    agent_path: Option<String>,
}

pub fn spool_hook_event(raw: &[u8], config: &HookSpoolConfig) -> Result<HookSpoolSummary> {
    let max_input_bytes = config.max_input_bytes.min(MAX_HOOK_BYTES);
    if raw.is_empty() || raw.len() > max_input_bytes {
        bail!("Codex hook input must be between 1 and {max_input_bytes} bytes");
    }
    let raw_input = std::str::from_utf8(raw).context("Codex hook input must be UTF-8")?;
    let event: Value = serde_json::from_slice(raw).context("parse Codex hook input")?;
    let event_name = required_string(&event, "hook_event_name")?.to_owned();
    if !matches!(
        event_name.as_str(),
        "SessionStart" | "SessionEnd" | "Stop" | "Interrupt" | "SubagentStart" | "SubagentStop"
    ) {
        bail!("unsupported Codex hook event {event_name}");
    }
    let session_id = required_string(&event, "session_id")?;
    if session_id.len() > 256 {
        bail!("Codex hook session_id exceeds 256 bytes");
    }
    for field in ["transcript_path", "agent_transcript_path"] {
        if event
            .get(field)
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            bail!("Codex hook {field} must be a string or null");
        }
    }

    let digest = sha256(raw);
    let received_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let identity_digest = codex_hook_occurrence_digest(&digest, &received_at);
    let event_id = format!("hook-{identity_digest}");
    let pending = config.queue_root.join("pending");
    let temporary = config.queue_root.join("tmp");
    create_queue_directory(&config.queue_root)?;
    create_queue_directory(&pending)?;
    create_queue_directory(&temporary)?;
    let destination = pending.join(format!("{event_id}.json"));
    if destination.exists() {
        verify_spooled_file(&destination, &event_id)?;
        return Ok(HookSpoolSummary {
            event_id,
            event_name: event_name.clone(),
            path: destination.display().to_string(),
            bytes: raw.len() as u64,
            duplicate: true,
        });
    }
    let record = SpooledHookEvent {
        schema_version: HOOK_SPOOL_SCHEMA_VERSION.to_owned(),
        event_id: event_id.clone(),
        received_at,
        raw_input: raw_input.to_owned(),
        raw_input_sha256: digest.clone(),
        event,
    };
    let bytes = serde_json::to_vec(&record)?;
    let temporary_path = temporary.join(format!(".{event_id}.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary_path)?;
    file.write_all(&bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    match fs::hard_link(&temporary_path, &destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_spooled_file(&destination, &event_id)?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(&temporary_path)?;
    File::open(&pending)?.sync_all()?;
    Ok(HookSpoolSummary {
        event_id,
        event_name,
        path: destination.display().to_string(),
        bytes: raw.len() as u64,
        duplicate: false,
    })
}

pub async fn run_codex_agent<S>(config: CodexAgentConfig, shutdown: S) -> Result<CodexAgentSummary>
where
    S: Future<Output = ()>,
{
    if config.retry_max_times < 20 {
        bail!("Codex agent delivery requires at least 20 retry attempts");
    }
    if config.poll_interval < Duration::from_millis(10) {
        bail!("Codex agent poll interval must be at least 10ms");
    }
    create_queue_directory(&config.queue_root)?;
    create_queue_directory(&config.queue_root.join("pending"))?;
    let mut summary = CodexAgentSummary::default();
    tokio::pin!(shutdown);
    loop {
        summary.cycles = summary.cycles.saturating_add(1);
        process_pending(&config, &mut summary).await?;
        if config.once {
            summary.stop_reason = "once".to_owned();
            return Ok(summary);
        }
        tokio::select! {
            _ = &mut shutdown => {
                summary.stop_reason = "shutdown".to_owned();
                return Ok(summary);
            }
            _ = tokio::time::sleep(config.poll_interval) => {}
        }
    }
}

async fn process_pending(config: &CodexAgentConfig, summary: &mut CodexAgentSummary) -> Result<()> {
    let pending = config.queue_root.join("pending");
    let mut paths: Vec<PathBuf> = fs::read_dir(&pending)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect();
    paths.sort();
    summary.queued = summary.queued.saturating_add(paths.len() as u64);
    for path in paths {
        match process_one(config, &path).await {
            Ok((duplicates, rollout_captures)) => {
                fs::remove_file(&path)?;
                File::open(&pending)?.sync_all()?;
                summary.acknowledged = summary.acknowledged.saturating_add(1);
                summary.duplicate_captures = summary.duplicate_captures.saturating_add(duplicates);
                summary.rollout_captures =
                    summary.rollout_captures.saturating_add(rollout_captures);
            }
            Err(error) => {
                summary.failed = summary.failed.saturating_add(1);
                if summary.errors.len() < 64 {
                    summary
                        .errors
                        .push(format!("{}: {error:#}", path.display()));
                }
            }
        }
    }
    Ok(())
}

async fn process_one(config: &CodexAgentConfig, path: &Path) -> Result<(u64, u64)> {
    let spooled = load_spooled_event(path)?;
    let rollouts = resolve_event_rollouts(&spooled.event, &config.session_root)?;
    let identity = select_hook_identity(&spooled.event, &rollouts)?;
    let capture = hook_capture(&spooled, &identity, &config.source_namespace)?;
    let receipt = deliver_batch(
        &DeliveryConfig {
            target: config.target.clone(),
            request_timeout: config.request_timeout,
            retry_max_times: config.retry_max_times,
        },
        &[capture],
    )
    .await?;
    let mut duplicates = receipt.duplicates;
    let mut rollout_captures = 0_u64;
    for rollout in rollouts {
        let export = export_codex_rollout(ExportConfig {
            input: rollout,
            state_root: config.state_root.join("rollout"),
            target: config.target.clone(),
            source_namespace: config.source_namespace.clone(),
            tool_registry: None,
            batch_records: config.batch_records,
            max_envelope_bytes: config.max_envelope_bytes,
            request_timeout: config.request_timeout,
            retry_max_times: config.retry_max_times,
            task_session_id: None,
            root_session_id: None,
            parent_session_id: None,
            goal_id: None,
        })
        .await?;
        ensure_complete_tail(&export)?;
        duplicates = duplicates.saturating_add(export.duplicate_captures);
        rollout_captures = rollout_captures.saturating_add(export.captures_emitted);
    }
    Ok((duplicates, rollout_captures))
}

fn resolve_event_rollouts(event: &Value, session_root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    for (field, verify_session) in [("transcript_path", true), ("agent_transcript_path", false)] {
        let Some(raw_path) = event.get(field).and_then(Value::as_str) else {
            continue;
        };
        let raw_path = raw_path.trim();
        if raw_path.is_empty() {
            continue;
        }
        let expected = verify_session
            .then(|| event.get("session_id").and_then(Value::as_str))
            .flatten();
        paths.insert(resolve_rollout_path(
            Path::new(raw_path),
            session_root,
            expected,
        )?);
    }
    Ok(paths.into_iter().collect())
}

fn select_hook_identity(event: &Value, rollouts: &[PathBuf]) -> Result<RolloutIdentity> {
    let identities: Vec<RolloutIdentity> = rollouts
        .iter()
        .map(|path| read_rollout_identity(path))
        .collect::<Result<_>>()?;
    let event_name = required_string(event, "hook_event_name")?;
    if matches!(event_name, "SubagentStart" | "SubagentStop") {
        let agent_id = required_string(event, "agent_id")?;
        return identities
            .into_iter()
            .find(|identity| identity.thread_id.as_deref() == Some(agent_id))
            .ok_or_else(|| {
                anyhow::anyhow!("Codex subagent Hook has no rollout matching agent_id")
            });
    }
    match identities.len() {
        0 => Ok(RolloutIdentity::default()),
        1 => Ok(identities.into_iter().next().unwrap_or_default()),
        _ => bail!("Codex Hook resolves to multiple rollout identities"),
    }
}

fn hook_capture(
    spooled: &SpooledHookEvent,
    identity: &RolloutIdentity,
    source_namespace: &str,
) -> Result<Vec<u8>> {
    let event_name = required_string(&spooled.event, "hook_event_name")?;
    let hook_session_id = required_string(&spooled.event, "session_id")?;
    let (lifecycle_type, status) = match event_name {
        "SessionStart" => ("session_start", "started"),
        "SessionEnd" => ("session_end", "unknown"),
        "Stop" => ("turn_stop", "completed"),
        "Interrupt" => ("turn_interrupt", "cancelled"),
        "SubagentStart" => ("subagent_start", "started"),
        "SubagentStop" => ("subagent_stop", "unknown"),
        _ => unreachable!(),
    };
    let identity_digest = spooled
        .event_id
        .strip_prefix("hook-")
        .context("Codex Hook event_id has an invalid prefix")?;
    let value = json!({
        "recordType":"lifecycle_event",
        "captureId":deterministic_codex_hook_capture_id(identity_digest),
        "captureStage":"event",
        "sourceNamespace":source_namespace,
        "receivedAt":spooled.received_at,
        "producerModel":spooled.event.get("model"),
        "traceContext":{
            "session_id":identity.session_id.as_deref().unwrap_or(hook_session_id),
            "thread_id":identity.thread_id.as_deref().unwrap_or(hook_session_id),
            "parent_thread_id":identity.parent_thread_id,
            "turn_id":spooled.event.get("turn_id"),
            "agent_id":spooled.event.get("agent_id"),
            "agent_path":identity.agent_path,
        },
        "lifecycleEvent":{
            "event_id":spooled.event_id,
            "type":lifecycle_type,
            "status":status,
            "reason":spooled.event.get("reason"),
            "occurred_at":spooled.received_at,
            "source_event":spooled.event,
        },
        "codexHook":{
            "schema_version":spooled.schema_version,
            "raw_input":spooled.raw_input,
            "raw_input_sha256":spooled.raw_input_sha256,
        }
    });
    Ok(normalize_capture(&serde_json::to_vec(&value)?, usize::MAX)?.canonical)
}

fn read_rollout_identity(path: &Path) -> Result<RolloutIdentity> {
    let mut line = String::new();
    BufReader::new(File::open(path)?).read_line(&mut line)?;
    let value: Value = serde_json::from_str(line.trim_end())?;
    if value.get("type").and_then(Value::as_str) != Some("session_meta") {
        bail!("Codex rollout first line is not session_meta");
    }
    let payload = value.get("payload").unwrap_or(&Value::Null);
    Ok(RolloutIdentity {
        session_id: optional_string(payload, "session_id").map(str::to_owned),
        thread_id: optional_string(payload, "id")
            .or_else(|| optional_string(payload, "session_id"))
            .map(str::to_owned),
        parent_thread_id: payload
            .pointer("/source/subagent/thread_spawn/parent_thread_id")
            .and_then(Value::as_str)
            .or_else(|| optional_string(payload, "parent_thread_id"))
            .map(str::to_owned),
        agent_path: payload
            .pointer("/source/subagent/thread_spawn/agent_path")
            .and_then(Value::as_str)
            .or_else(|| optional_string(payload, "agent_path"))
            .map(str::to_owned),
    })
}

fn ensure_complete_tail(summary: &ExportSummary) -> Result<()> {
    if summary.incomplete_tail_bytes > 0 {
        bail!(
            "Codex rollout has {} incomplete tail bytes",
            summary.incomplete_tail_bytes
        );
    }
    Ok(())
}

fn load_spooled_event(path: &Path) -> Result<SpooledHookEvent> {
    let bytes = fs::read(path)?;
    let spooled: SpooledHookEvent = serde_json::from_slice(&bytes)?;
    let expected_identity = match spooled.schema_version.as_str() {
        LEGACY_HOOK_SPOOL_SCHEMA_VERSION => spooled.raw_input_sha256.clone(),
        HOOK_SPOOL_SCHEMA_VERSION => {
            codex_hook_occurrence_digest(&spooled.raw_input_sha256, &spooled.received_at)
        }
        _ => bail!("unsupported Codex hook spool schema"),
    };
    if spooled.raw_input_sha256 != sha256(spooled.raw_input.as_bytes())
        || spooled.event_id != format!("hook-{expected_identity}")
        || serde_json::from_str::<Value>(&spooled.raw_input)? != spooled.event
    {
        bail!("invalid or modified Codex hook spool record");
    }
    Ok(spooled)
}

fn verify_spooled_file(path: &Path, expected_event_id: &str) -> Result<()> {
    let spooled = load_spooled_event(path)?;
    if spooled.event_id != expected_event_id {
        bail!("Codex hook event ID conflicts with existing bytes");
    }
    Ok(())
}

fn create_queue_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("Codex hook queue path must be a non-symlink directory");
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    optional_string(value, field)
        .ok_or_else(|| anyhow::anyhow!("Codex hook input is missing {field}"))
}

fn optional_string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/codex")
            .join(name)
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn hook_spool_is_atomic_and_distinguishes_occurrences() {
        let temporary = tempfile::tempdir().unwrap();
        let raw = br#"{"hook_event_name":"SessionStart","session_id":"thread-root","source":"startup","transcript_path":null,"cwd":"/workspace","model":"gpt-5.6-sol","permission_mode":"default"}"#;
        let config = HookSpoolConfig {
            queue_root: temporary.path().join("queue"),
            max_input_bytes: MAX_HOOK_BYTES,
        };
        let first = spool_hook_event(raw, &config).unwrap();
        let second = spool_hook_event(raw, &config).unwrap();
        assert!(!first.duplicate);
        assert!(!second.duplicate);
        assert_ne!(first.event_id, second.event_id);
        assert_eq!(
            fs::read_dir(config.queue_root.join("pending"))
                .unwrap()
                .count(),
            2
        );
        assert_eq!(
            fs::read_dir(config.queue_root.join("tmp")).unwrap().count(),
            0
        );
        let spooled = load_spooled_event(Path::new(&first.path)).unwrap();
        let identity = RolloutIdentity::default();
        assert_eq!(
            hook_capture(&spooled, &identity, "test-stock-codex").unwrap(),
            hook_capture(&spooled, &identity, "test-stock-codex").unwrap()
        );
    }

    #[test]
    fn subagent_hook_selects_the_agent_rollout_identity() {
        let event = json!({
            "hook_event_name":"SubagentStop",
            "session_id":"session-root",
            "agent_id":"thread-child"
        });
        let identity = select_hook_identity(
            &event,
            &[
                fixture("stock-rollout-root.jsonl"),
                fixture("stock-rollout-child.jsonl"),
            ],
        )
        .unwrap();
        assert_eq!(identity.session_id.as_deref(), Some("session-root"));
        assert_eq!(identity.thread_id.as_deref(), Some("thread-child"));
        assert_eq!(identity.parent_thread_id.as_deref(), Some("thread-root"));
        assert_eq!(identity.agent_path.as_deref(), Some("/root/reviewer"));
    }

    #[tokio::test]
    async fn agent_delivers_hook_and_rollout_before_removing_outbox_item() {
        let temporary = tempfile::tempdir().unwrap();
        let queue_root = temporary.path().join("queue");
        let rollout = fixture("stock-rollout-root.jsonl");
        let raw = serde_json::to_vec(&json!({
            "hook_event_name":"Stop",
            "session_id":"thread-root",
            "turn_id":"turn-root",
            "transcript_path":rollout,
            "cwd":"/workspace",
            "model":"gpt-5.6-sol",
            "permission_mode":"default",
            "stop_hook_active":false,
            "last_assistant_message":"done"
        }))
        .unwrap();
        spool_hook_event(
            &raw,
            &HookSpoolConfig {
                queue_root: queue_root.clone(),
                max_input_bytes: MAX_HOOK_BYTES,
            },
        )
        .unwrap();
        let output = temporary.path().join("captures.jsonl");
        let summary = run_codex_agent(
            CodexAgentConfig {
                queue_root: queue_root.clone(),
                session_root: fixture("stock-rollout-root.jsonl")
                    .parent()
                    .unwrap()
                    .to_owned(),
                state_root: temporary.path().join("state"),
                target: DeliveryTarget::Jsonl(output.clone()),
                source_namespace: "test-stock-codex".to_owned(),
                batch_records: 2,
                max_envelope_bytes: 4 * 1024 * 1024,
                request_timeout: Duration::from_secs(1),
                retry_max_times: 20,
                poll_interval: Duration::from_millis(10),
                once: true,
            },
            std::future::pending(),
        )
        .await
        .unwrap();
        assert_eq!(summary.acknowledged, 1);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.rollout_captures, 8);
        assert_eq!(fs::read_dir(queue_root.join("pending")).unwrap().count(), 0);
        let records: Vec<Value> = fs::read_to_string(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 9);
        assert_eq!(records[0]["lifecycleEvent"]["type"], "turn_stop");
        assert_eq!(records[0]["traceContext"]["session_id"], "session-root");
        assert_eq!(records[0]["traceContext"]["thread_id"], "thread-root");
    }

    #[tokio::test]
    async fn session_start_without_transcript_is_durable_but_not_runtime_complete() {
        let temporary = tempfile::tempdir().unwrap();
        let queue_root = temporary.path().join("queue");
        let raw = br#"{"hook_event_name":"SessionStart","session_id":"thread-start","source":"startup","transcript_path":null,"cwd":"/workspace","model":"gpt-5.6-sol","permission_mode":"default"}"#;
        spool_hook_event(
            raw,
            &HookSpoolConfig {
                queue_root: queue_root.clone(),
                max_input_bytes: MAX_HOOK_BYTES,
            },
        )
        .unwrap();
        let output = temporary.path().join("captures.jsonl");
        let summary = run_codex_agent(
            CodexAgentConfig {
                queue_root: queue_root.clone(),
                session_root: temporary.path().to_owned(),
                state_root: temporary.path().join("state"),
                target: DeliveryTarget::Jsonl(output.clone()),
                source_namespace: "test-stock-codex".to_owned(),
                batch_records: 2,
                max_envelope_bytes: 4 * 1024 * 1024,
                request_timeout: Duration::from_secs(1),
                retry_max_times: 20,
                poll_interval: Duration::from_millis(10),
                once: true,
            },
            std::future::pending(),
        )
        .await
        .unwrap();
        assert_eq!(summary.acknowledged, 1);
        assert_eq!(summary.rollout_captures, 0);
        let capture: Value =
            serde_json::from_str(fs::read_to_string(output).unwrap().trim()).unwrap();
        assert_eq!(capture["traceContext"]["thread_id"], "thread-start");
        assert_eq!(capture["traceContext"]["session_id"], "thread-start");
        assert_eq!(capture["lifecycleEvent"]["type"], "session_start");
    }
}
