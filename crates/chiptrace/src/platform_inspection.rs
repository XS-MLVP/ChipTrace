//! Compact platform transport for an inspected Session; full Turns stay on disk.

use crate::model_interaction::SessionInspection;
use crate::session_view::SessionView;
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
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    {
        let mut writer = BufWriter::new(temporary.as_file());
        for turn in &session.turns {
            // Canonical key order also preserves sidecars written by the
            // previous platform from the CLI's JSON Value representation.
            let line = serde_json::to_vec(&serde_json::to_value(turn)?)?;
            bytes = bytes
                .checked_add(line.len() as u64 + 1)
                .context("Turn evidence size overflow")?;
            if bytes > max_turn_bytes {
                bail!("platform Turn evidence exceeds disk limit");
            }
            writer.write_all(&line)?;
            writer.write_all(b"\n")?;
            digest.update(&line);
            digest.update(b"\n");
        }
        writer.flush()?;
    }
    temporary.as_file().sync_all()?;
    let sha256 = hex::encode(digest.finalize());
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

    #[test]
    fn compact_summary_preserves_every_summary_field_without_turns() {
        let view = crate::session_view::summarize_session(&[], "summary-session").unwrap();
        let mut full = serde_json::to_value(&view).unwrap();
        full.as_object_mut().unwrap().remove("turns");
        assert_eq!(serde_json::to_value(SessionSummary(&view)).unwrap(), full);
    }
}
