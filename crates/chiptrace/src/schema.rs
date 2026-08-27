use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SESSION_SCHEMA_VERSION: &str = "chiptrace.session.v1";
pub const ASSESSMENT_SCHEMA_VERSION: &str = "chiptrace.assessment.v1";
pub const RELEASE_SCHEMA_VERSION: &str = "chiptrace.jsonl-release.v1";
pub const COMMIT_SCHEMA_VERSION: &str = "chiptrace.object-commit.v1";

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
    pub effective_turns: u64,
    pub tool_calls: u64,
    pub unique_tool_call_ids: u64,
    pub distinct_tool_names: u64,
    pub tool_results: u64,
    pub valid_tool_results: u64,
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
    pub response_dag_cycle: bool,
    pub response_dag_unresolved_parents: u64,
    pub capture_dag_present: bool,
    pub task_dag_present: bool,
    pub task_dag_complete: bool,
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
    pub release_id: String,
    pub committed_at_utc: String,
    pub release_manifest_sha256: String,
    pub release_manifest_key: String,
    pub objects: Vec<ObjectEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectEntry {
    pub key: String,
    pub sha256: String,
    pub bytes: u64,
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
            "capture-v1.schema.json",
            "release-manifest-v1.schema.json",
            "session-v1.schema.json",
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
