//! Compact platform transport for fully verified Buyer acceptance artifacts.

use crate::cloud_acceptance::CloudAcceptanceManifest;
use crate::platform_inspection::{SessionSummary, manifest_descriptor, persist_turn_evidence};
use anyhow::{Context, Result};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::{Value, json};
use std::path::Path;

pub const PLATFORM_ACCEPTANCE_SCHEMA_VERSION: &str = "chiptrace.platform-acceptance.v1";

struct AcceptanceSummary<'a>(&'a CloudAcceptanceManifest);

impl Serialize for AcceptanceSummary<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        macro_rules! fields {
            ($($field:ident),+ $(,)?) => {
                $(map.serialize_entry(stringify!($field), &self.0.$field)?;)+
            };
        }
        fields!(
            schema_version,
            created_at_utc,
            archive_id,
            session_id,
            release_id,
            quality_profile,
            minimum_score,
            score,
            hard_gate_pass,
            delivery_ready,
            effective_turns,
            source_context_audit,
            distinct_tool_names,
            complete_tool_definitions,
            pairing_rate_after_open_tail,
            eligible_sessions,
            api_total_tokens,
            normalized_corpus_tokens,
            source_coverage,
            root_spans,
            internal_parent_references,
            resolved_internal_parents,
            raw_records,
            raw_bytes,
            artifacts,
            validation_status,
        );
        if let Some(session) = &self.0.session_view {
            map.serialize_entry("session_view", &SessionSummary(session))?;
        }
        map.end()
    }
}

/// Call only after run_cloud_acceptance or verify_cloud_acceptance succeeds.
/// The full v2 manifest stays intact on disk; this derived transport omits only
/// its Turn array and publishes the exact same metadata as a durable sidecar.
pub fn platform_acceptance_report(
    acceptance: &CloudAcceptanceManifest,
    acceptance_output: &Path,
    max_turn_bytes: u64,
) -> Result<Value> {
    let session = acceptance
        .session_view
        .as_ref()
        .context("verified acceptance has no Session/Turn view")?;
    let turns = persist_turn_evidence(session, acceptance_output, max_turn_bytes)?;
    Ok(json!({
        "schema_version":PLATFORM_ACCEPTANCE_SCHEMA_VERSION,
        "acceptance":AcceptanceSummary(acceptance),
        "turns":turns,
        "manifest":manifest_descriptor(acceptance_output)?
    }))
}
