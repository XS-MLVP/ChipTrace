//! Compact platform transport for an inspected Session; full Turns stay on disk.

use crate::model_interaction::SessionInspection;
use crate::session_view::{SessionView, TurnSourceCoverage, TurnView};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

pub const PLATFORM_INSPECTION_SCHEMA_VERSION: &str = "chiptrace.platform-inspection.v1";

pub(crate) struct SessionSummary<'a>(pub(crate) &'a SessionView);

// Match serde_json::Value's sorted object keys without cloning the Turn or
// allocating a complete JSON line. These bytes are also used by legacy jobs.
struct CanonicalTurn<'a>(&'a TurnView);

impl Serialize for CanonicalTurn<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let turn = self.0;
        let mut map = serializer.serialize_map(Some(13))?;
        map.serialize_entry("finished_at", &turn.finished_at)?;
        map.serialize_entry("model_interactions", &turn.model_interactions)?;
        map.serialize_entry("raw_capture_refs", &turn.raw_capture_refs)?;
        map.serialize_entry("root_turn_id", &turn.root_turn_id)?;
        map.serialize_entry("session_id", &turn.session_id)?;
        map.serialize_entry("source_coverage", &CanonicalCoverage(&turn.source_coverage))?;
        map.serialize_entry("start_events", &turn.start_events)?;
        map.serialize_entry("started_at", &turn.started_at)?;
        map.serialize_entry("state_conflict", &turn.state_conflict)?;
        map.serialize_entry("status", &turn.status)?;
        map.serialize_entry("terminal_events", &turn.terminal_events)?;
        map.serialize_entry("tool_execution_records", &turn.tool_execution_records)?;
        map.serialize_entry("turn_id", &turn.turn_id)?;
        map.end()
    }
}

struct CanonicalCoverage<'a>(&'a TurnSourceCoverage);

impl Serialize for CanonicalCoverage<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let coverage = self.0;
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("complete", &coverage.complete)?;
        map.serialize_entry("hooks", &coverage.hooks)?;
        map.serialize_entry("missing_sources", &coverage.missing_sources)?;
        map.serialize_entry("otlp_logs", &coverage.otlp_logs)?;
        map.serialize_entry("otlp_traces", &coverage.otlp_traces)?;
        map.serialize_entry("wire", &coverage.wire)?;
        map.end()
    }
}

struct TurnEvidenceWriter<W> {
    inner: W,
    digest: Sha256,
    bytes: u64,
    limit: u64,
}

impl<W: Write> Write for TurnEvidenceWriter<W> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let next = self.bytes.checked_add(input.len() as u64);
        if next.is_none_or(|bytes| bytes > self.limit) {
            return Err(std::io::Error::other(
                "platform Turn evidence exceeds disk limit",
            ));
        }
        let written = self.inner.write(input)?;
        self.digest.update(&input[..written]);
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Serialize for SessionSummary<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        // Borrow the scalar summary without serializing or cloning any Turn.
        macro_rules! fields {
            ($($field:ident),+ $(,)?) => {
                $(map.serialize_entry(stringify!($field), &self.0.$field)?;)+
            };
        }
        fields!(
            schema_version,
            session_id,
            session_epochs,
            closed_session_epochs,
            latest_epoch_closed,
            invalid_session_boundaries,
            native_turns,
            closed_turns,
            open_turns,
            conflicted_turns,
            incomplete_turns,
            turn_source_coverage_complete,
            unscoped_turn_records,
            unscoped_source_records,
            delivery_ready,
            model_interactions,
            tool_execution_records,
        );
        map.end()
    }
}

fn existing_turns_match(path: &Path, bytes: u64, sha256: &str) -> Result<()> {
    let stat = fs::symlink_metadata(path)?;
    if !stat.is_file()
        || stat.file_type().is_symlink()
        || stat.len() != bytes
        || crate::jsonl::sha256_file(path)? != sha256
    {
        bail!("existing platform Turn evidence does not match inspected Session");
    }
    Ok(())
}

pub(crate) fn persist_turn_evidence(
    session: &SessionView,
    artifact_output: &Path,
    max_turn_bytes: u64,
) -> Result<Value> {
    if max_turn_bytes == 0 {
        bail!("platform Turn evidence limit must be positive");
    }
    let artifact_output = crate::jsonl::absolute_path(artifact_output)?;
    let parent = artifact_output
        .parent()
        .context("platform artifact has no parent")?;
    let target = parent.join("turns.jsonl");
    let temporary = tempfile::Builder::new()
        .prefix(".turns-")
        .tempfile_in(parent)?;
    let (bytes, sha256) = {
        let mut writer = TurnEvidenceWriter {
            inner: BufWriter::new(temporary.as_file()),
            digest: Sha256::new(),
            bytes: 0,
            limit: max_turn_bytes,
        };
        for turn in &session.turns {
            serde_json::to_writer(&mut writer, &CanonicalTurn(turn))?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
        (writer.bytes, hex::encode(writer.digest.finalize()))
    };
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(&target) {
        Ok(file) => file.sync_all()?,
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            existing_turns_match(&target, bytes, &sha256)?;
        }
        Err(error) => return Err(error.error).context("persist platform Turn evidence"),
    }
    File::open(parent)?.sync_all()?;
    Ok(json!({"records":session.turns.len(),"bytes":bytes,"sha256":sha256}))
}

pub(crate) fn manifest_descriptor(output: &Path) -> Result<Value> {
    let manifest_path = output.join("manifest.json");
    let manifest_stat = fs::symlink_metadata(&manifest_path)?;
    if !manifest_stat.is_file() || manifest_stat.file_type().is_symlink() {
        bail!("platform artifact manifest is not a regular file");
    }
    Ok(json!({"file":"manifest.json","bytes":manifest_stat.len(),
        "sha256":crate::jsonl::sha256_file(&manifest_path)?}))
}

/// Used only with a persistent projection. No Raw is modified, and an existing
/// sidecar is reused only when its exact bytes match this inspected snapshot.
pub fn platform_inspection_report(
    inspection: &SessionInspection,
    projection_output: &Path,
    max_turn_bytes: u64,
) -> Result<Value> {
    if inspection.projection.session_view.as_ref() != Some(&inspection.session) {
        bail!("platform projection does not match inspected Session");
    }
    let turns = persist_turn_evidence(&inspection.session, projection_output, max_turn_bytes)?;
    let projection = &inspection.projection;
    Ok(json!({
        "schema_version":PLATFORM_INSPECTION_SCHEMA_VERSION,
        "delivery_ready":inspection.delivery_ready,
        "session":SessionSummary(&inspection.session),
        "source_coverage":inspection.source_coverage,
        "integrity":inspection.integrity,
        "validation_status":inspection.validation_status,
        "source_context_audit":inspection.source_context_audit,
        "scenario_evidence":inspection.scenario_evidence,
        "turns":turns,
        "interaction_projection":{
            "schema_version":projection.schema_version,"session_id":projection.session_id,
            "interactions":projection.interactions,"runtime_spans":projection.runtime_spans,
            "links":projection.links,"parts":projection.parts,
            "manifest":manifest_descriptor(projection_output)?
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_turn() -> TurnView {
        TurnView {
            session_id: "synthetic-sidecar-session".to_owned(),
            turn_id: "synthetic-sidecar-turn".to_owned(),
            root_turn_id: None,
            started_at: None,
            finished_at: None,
            status: "open".to_owned(),
            start_events: 1,
            terminal_events: 0,
            model_interactions: 0,
            tool_execution_records: 0,
            state_conflict: false,
            raw_capture_refs: Default::default(),
            source_coverage: TurnSourceCoverage {
                wire: 0,
                otlp_logs: 0,
                otlp_traces: 0,
                hooks: 0,
                missing_sources: vec![
                    "wire".to_owned(),
                    "otlp_logs".to_owned(),
                    "otlp_traces".to_owned(),
                    "hooks".to_owned(),
                ],
                complete: false,
            },
        }
    }

    #[test]
    fn canonical_turn_bytes_match_legacy_sidecars_and_enforce_newline_quota() {
        let mut turn = synthetic_turn();
        for populated in [false, true] {
            if populated {
                turn.session_id = "会话\"\\\n\t🙂".to_owned();
                turn.turn_id = "轮次\u{0000}".to_owned();
                turn.root_turn_id = Some("父轮次".to_owned());
                turn.started_at = Some("2026-10-15T01:02:03Z".to_owned());
                turn.finished_at = Some("2026-10-15T02:03:04Z".to_owned());
                turn.status = "closed".to_owned();
                turn.state_conflict = true;
                turn.model_interactions = 17;
                turn.tool_execution_records = 23;
                turn.terminal_events = 1;
                turn.raw_capture_refs = ["z", "a\n\\\"", "中"].map(str::to_owned).into();
                turn.source_coverage = TurnSourceCoverage {
                    complete: true,
                    wire: 1,
                    otlp_logs: 2,
                    otlp_traces: 3,
                    hooks: 4,
                    missing_sources: vec![],
                };
            }
            let mut expected = serde_json::to_vec(&serde_json::to_value(&turn).unwrap()).unwrap();
            assert_eq!(serde_json::to_vec(&CanonicalTurn(&turn)).unwrap(), expected);
            expected.push(b'\n');
            let root = tempfile::tempdir().unwrap();
            let output = root.path().join("projection");
            let mut session =
                crate::session_view::summarize_session(&[], &turn.session_id).unwrap();
            session.turns.push(turn.clone());
            // The final newline is included in both quota and digest; a failed
            // partial serialization must never publish or leave a temp file.
            assert!(persist_turn_evidence(&session, &output, expected.len() as u64 - 1).is_err());
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
            let evidence = persist_turn_evidence(&session, &output, expected.len() as u64).unwrap();
            assert_eq!(fs::read(root.path().join("turns.jsonl")).unwrap(), expected);
            assert_eq!(evidence["bytes"], expected.len());
            assert_eq!(evidence["sha256"], hex::encode(Sha256::digest(&expected)));
        }
    }

    #[test]
    #[ignore = "large synthetic metadata RSS gate runs separately"]
    fn large_turn_sidecar_memory() {
        let root = tempfile::tempdir().unwrap();
        let mut session =
            crate::session_view::summarize_session(&[], "synthetic-sidecar-session").unwrap();
        let mut turn = synthetic_turn();
        for index in 0..200_000 {
            turn.raw_capture_refs
                .insert(format!("cap-memory-{index:06}-{}", "x".repeat(180)));
        }
        session.turns.push(turn);
        session.native_turns = 1;
        session.open_turns = 1;
        session.incomplete_turns = 1;
        let evidence =
            persist_turn_evidence(&session, &root.path().join("projection"), 64 * 1024 * 1024)
                .unwrap();
        assert_eq!(evidence["records"], 1);
        let bytes = evidence["bytes"].as_u64().unwrap();
        assert!(bytes > 32 * 1024 * 1024);
        assert_eq!(
            evidence["sha256"],
            crate::jsonl::sha256_file(&root.path().join("turns.jsonl")).unwrap()
        );
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let peak: u64 = status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        println!(
            "{}",
            json!({"schema_version":"chiptrace.turn-writer-memory.v1","synthetic":true,
            "session_delivery_claimed":false,"references":200_000,"turn_bytes":bytes,
            "max_rss_kib":peak,"memory_budget_kib":128 * 1024})
        );
        assert!(
            peak <= 128 * 1024,
            "Turn writer RSS {peak} KiB exceeds 128 MiB metadata fixture budget"
        );
    }

    #[test]
    fn compact_summary_preserves_every_summary_field_without_turns() {
        let view = crate::session_view::summarize_session(&[], "summary-session").unwrap();
        let mut full = serde_json::to_value(&view).unwrap();
        full.as_object_mut().unwrap().remove("turns");
        assert_eq!(serde_json::to_value(SessionSummary(&view)).unwrap(), full);
    }
}
