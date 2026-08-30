use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SESSION_SCHEMA_VERSION: &str = "chiptrace.session.v1";
pub const ASSESSMENT_SCHEMA_VERSION: &str = "chiptrace.assessment.v1";
pub const RELEASE_SCHEMA_VERSION: &str = "chiptrace.jsonl-release.v1";
pub const OBJECT_COMMIT_SCHEMA_VERSION: &str = "chiptrace.object-commit.v1";
pub const RAW_ARCHIVE_SCHEMA_VERSION: &str = "chiptrace.raw-archive.v1";
pub const RAW_CHECKPOINT_SCHEMA_VERSION: &str = "chiptrace.raw-checkpoint.v1";
pub const RAW_LINEAGE_SCHEMA_VERSION: &str = "chiptrace.raw-lineage.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GateResult {
    pub name: String,
    pub pass: bool,
    pub required: bool,
    pub observed: Value,
    pub expected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenCounts {
    pub api_input_tokens: u64,
    pub api_cached_input_tokens: u64,
    pub api_cache_write_tokens: u64,
    pub api_output_tokens: u64,
    pub api_reasoning_tokens: u64,
    pub api_total_tokens: u64,
    pub normalized_corpus_tokens: u64,
    pub supervised_output_tokens: u64,
    pub excluded_base64_bytes: u64,
    pub tokenizer: String,
}

impl TokenCounts {
    pub fn add_assign(&mut self, other: &Self) {
        if self.tokenizer.is_empty() {
            self.tokenizer = other.tokenizer.clone();
        } else if !other.tokenizer.is_empty() && self.tokenizer != other.tokenizer {
            self.tokenizer =
                "mixed tokenization policies; inspect per-session assessments".to_owned();
        }
        self.api_input_tokens = self.api_input_tokens.saturating_add(other.api_input_tokens);
        self.api_cached_input_tokens = self
            .api_cached_input_tokens
            .saturating_add(other.api_cached_input_tokens);
        self.api_cache_write_tokens = self
            .api_cache_write_tokens
            .saturating_add(other.api_cache_write_tokens);
        self.api_output_tokens = self
            .api_output_tokens
            .saturating_add(other.api_output_tokens);
        self.api_reasoning_tokens = self
            .api_reasoning_tokens
            .saturating_add(other.api_reasoning_tokens);
        self.api_total_tokens = self.api_total_tokens.saturating_add(other.api_total_tokens);
        self.normalized_corpus_tokens = self
            .normalized_corpus_tokens
            .saturating_add(other.normalized_corpus_tokens);
        self.supervised_output_tokens = self
            .supervised_output_tokens
            .saturating_add(other.supervised_output_tokens);
        self.excluded_base64_bytes = self
            .excluded_base64_bytes
            .saturating_add(other.excluded_base64_bytes);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AcceptanceMetrics {
    pub messages: u64,
    pub user_turns: u64,
    pub machine_turns: u64,
    pub machine_turn_ratio: f64,
    pub human_user_assistant_turns: u64,
    pub effective_turns: u64,
    pub tool_calls: u64,
    pub unique_tool_call_ids: u64,
    pub distinct_tool_names: u64,
    #[serde(default)]
    pub invalid_tool_arguments: u64,
    pub tool_results: u64,
    pub valid_tool_results: u64,
    pub tool_results_with_explicit_status: u64,
    pub unknown_tool_results: u64,
    pub conflicting_tool_results: u64,
    pub paired_required_tool_calls: u64,
    pub paired_required_tool_results: u64,
    pub orphan_tool_results: u64,
    pub pairing_rate_after_open_tail: f64,
    pub tool_definitions: u64,
    pub complete_tool_definitions: u64,
    pub user_corrections: u64,
    pub failed_tool_results: u64,
    pub lifecycle_retries: u64,
    pub assembly_merge_divergences: u64,
    pub assembly_schema_conflicts: u64,
    pub assembly_trace_conflicts: u64,
    pub assembly_system_prompt_conflicts: u64,
    pub assembly_usage_conflicts: u64,
    #[serde(default)]
    pub assembly_tool_execution_conflicts: u64,
    #[serde(default)]
    pub assembly_producer_event_conflicts: u64,
    pub rollout_unknown_events: u64,
    pub rollout_unmapped_tools: u64,
    pub response_dag_cycle: bool,
    pub response_dag_unresolved_parents: u64,
    pub capture_dag_present: bool,
    pub runtime_dag_present: bool,
    pub runtime_dag_applicable: bool,
    pub runtime_dag_complete: bool,
    pub runtime_dag_native_events: u64,
    pub runtime_dag_open_nodes: u64,
    pub runtime_dag_unresolved_nodes: u64,
    #[serde(default)]
    pub runtime_dag_status_conflicts: u64,
    #[serde(default)]
    pub inference_api_conservation_applicable: bool,
    #[serde(default)]
    pub inference_api_conservation_complete: bool,
    #[serde(default)]
    pub runtime_completed_inferences: u64,
    #[serde(default)]
    pub api_snapshots: u64,
    #[serde(default)]
    pub matched_runtime_inferences: u64,
    #[serde(default)]
    pub missing_api_captures: u64,
    pub task_dag_present: bool,
    pub task_dag_complete: bool,
    pub task_start_event_present: bool,
    pub task_terminal_event_present: bool,
    pub task_boundary_attested: bool,
    pub model_evidence_consistent: bool,
    #[serde(default)]
    pub provider_identity_attested: bool,
    #[serde(default)]
    pub model_attestation_candidate_count: u64,
    #[serde(default)]
    pub non_attestable_api_snapshot_count: u64,
    pub proxy_route_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuyerAssessment {
    pub schema_version: String,
    pub profile: String,
    pub profile_version: String,
    pub score: f64,
    pub hard_gate_pass: bool,
    pub eligible: bool,
    pub minimum_score: f64,
    pub metrics: AcceptanceMetrics,
    pub tokens: TokenCounts,
    pub gates: Vec<GateResult>,
    pub failure_reasons: Vec<String>,
    pub warnings: Vec<String>,
    pub scoring_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaptureCompleteness {
    pub policy_version: String,
    pub score: f64,
    pub closed: bool,
    pub source_request_count: u64,
    pub has_stable_session_identity: bool,
    pub has_timestamps: bool,
    pub has_usage: bool,
    pub has_trace_hierarchy: bool,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticQuality {
    pub policy_version: String,
    pub reward_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_source: Option<String>,
    pub realism_signal_score: f64,
    pub evidence_count: u64,
    pub signals: BTreeMap<String, Value>,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QualityEnvelope {
    pub capture_completeness: CaptureCompleteness,
    pub buyer_acceptance: BuyerAssessment,
    pub semantic_quality: SemanticQuality,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileManifest {
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncompressed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oversized_session: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseCounts {
    pub input_records: u64,
    pub parse_failures: u64,
    pub exact_duplicates_removed: u64,
    pub subset_snapshots_removed: u64,
    pub divergent_session_conflicts: u64,
    pub divergent_session_records: u64,
    pub assessed_sessions: u64,
    pub eligible_sessions: u64,
    pub rejected_sessions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseManifest {
    pub schema_version: String,
    pub release_id: String,
    pub created_at_utc: String,
    pub format: String,
    pub session_atomic: bool,
    pub session_split_count: u64,
    pub buyer_profile: String,
    pub minimum_score: f64,
    pub tokenizer: String,
    pub compression: String,
    pub processing_workers: usize,
    pub target_part_bytes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_sources: Vec<RawSourceLineage>,
    pub counts: ReleaseCounts,
    pub eligible_tokens: TokenCounts,
    pub assessed_tokens: TokenCounts,
    pub failure_reason_counts: BTreeMap<String, u64>,
    pub parts: Vec<FileManifest>,
    pub reports: Vec<FileManifest>,
    pub validation_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectCommit {
    pub schema_version: String,
    pub artifact_kind: String,
    pub artifact_id: String,
    pub committed_at_utc: String,
    pub manifest_sha256: String,
    pub manifest_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_release_manifest_sha256: Option<String>,
    pub objects: Vec<ObjectEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectEntry {
    pub key: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawSegmentEntry {
    pub shard: String,
    pub segment_id: u64,
    pub object_key: String,
    pub source_path: String,
    pub bytes: u64,
    pub records: u64,
    pub sha256: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawArchiveManifest {
    pub schema_version: String,
    pub archive_id: String,
    pub created_at_utc: String,
    pub format: String,
    pub completeness: String,
    pub segment_count: u64,
    /// Sealed zero-record rotation markers discovered in the source WAL.
    /// Their bytes are archived for audit and recovery, but they do not count
    /// as data segments or records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub empty_segments: Vec<RawEmptySegmentEntry>,
    pub total_records: u64,
    pub total_bytes: u64,
    pub segments: Vec<RawSegmentEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawEmptySegmentEntry {
    pub shard: String,
    pub segment_id: u64,
    pub object_key: String,
    pub source_path: String,
    pub bytes: u64,
    pub records: u64,
    pub sha256: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawArchiveCheckpoint {
    pub schema_version: String,
    pub archive_id: String,
    pub state: String,
    pub completeness: String,
    pub committed_at_utc: String,
    pub manifest_key: String,
    pub manifest_sha256: String,
    pub segment_count: u64,
    pub total_records: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawSourceLineage {
    pub schema_version: String,
    pub archive_id: String,
    pub completeness: String,
    pub checkpoint_key: String,
    pub checkpoint_sha256: String,
    pub manifest_key: String,
    pub manifest_sha256: String,
    pub segment_count: u64,
    pub total_records: u64,
    pub total_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn public_json_schemas_are_valid_json_documents() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
        let expected = [
            "assessment-v1.schema.json",
            "buyer-archive-v1.schema.json",
            "buyer-package-v1.schema.json",
            "capture-v1.schema.json",
            "capture-v2.schema.json",
            "codex-trace-bundle-v1.schema.json",
            "gateway-enrichment-v1.schema.json",
            "object-commit-v1.schema.json",
            "producer-event-v1.schema.json",
            "release-manifest-v1.schema.json",
            "raw-archive-v1.schema.json",
            "raw-checkpoint-v1.schema.json",
            "raw-lineage-v1.schema.json",
            "session-v1.schema.json",
            "tool-registry-v1.schema.json",
        ];
        for name in expected {
            let bytes = fs::read(root.join(name)).unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                value.get("$schema").and_then(Value::as_str),
                Some("https://json-schema.org/draft/2020-12/schema")
            );
        }
    }
}
