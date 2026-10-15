//! Payload-free diagnostics for the exact Session/Turn OTLP join.
//! Counts do not certify delivery or exempt unresolved records.

#[cfg(test)]
use crate::session_view::allowed_source_sessions;
use crate::session_view::{otlp_record_name, otlp_source_observation};
use crate::turn_identity::{ExactTurnIndex, hex_id, visit_otlp};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const SOURCE_CONTEXT_AUDIT_SCHEMA_VERSION: &str = "chiptrace.source-context-audit.v2";
const MAX_GROUPS: usize = 128;
pub const MAX_CONTEXT_SAMPLES: usize = 1000;

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceContextCounts {
    pub total_records: u64,
    pub turn_assigned_records: u64,
    pub session_level_records: u64,
    pub process_level_records: u64,
    pub unscoped_turn_records: u64,
    pub other_session_records: u64,
    pub unknown_session_records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextGapGroup {
    pub source: String,
    pub disposition: String,
    pub record_name: String,
    pub reason: String,
    pub records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextGapSample {
    pub capture_id: String,
    /// Zero-based index across the OTLP records in this original envelope.
    pub record_index: u64,
    pub source: String,
    pub disposition: String,
    pub record_name: String,
    pub reason: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceContextAudit {
    pub schema_version: String,
    pub session_id: String,
    pub selected_captures: u64,
    pub duplicate_captures_removed: u64,
    pub sources: BTreeMap<String, SourceContextCounts>,
    pub unscoped_otlp_records: u64,
    pub group_limit: usize,
    pub gap_groups: Vec<ContextGapGroup>,
    pub omitted_gap_records: u64,
    pub sample_limit: usize,
    pub samples: Vec<ContextGapSample>,
    pub omitted_samples: u64,
}

impl SourceContextCounts {
    fn checked_total(&self) -> Result<u64> {
        self.turn_assigned_records
            .checked_add(self.session_level_records)
            .and_then(|value| value.checked_add(self.process_level_records))
            .and_then(|value| value.checked_add(self.unscoped_turn_records))
            .and_then(|value| value.checked_add(self.other_session_records))
            .and_then(|value| value.checked_add(self.unknown_session_records))
            .context("source context audit count overflow")
    }
}

impl SourceContextAudit {
    /// Verify source identity and count invariants, without certifying other delivery gates.
    pub fn verify_delivery_ready(&self, session_id: &str) -> Result<()> {
        if self.schema_version != SOURCE_CONTEXT_AUDIT_SCHEMA_VERSION {
            bail!("source context audit has an unsupported schema version");
        }
        if self.session_id != session_id {
            bail!("source context audit Session does not match requested Session");
        }
        let mut unscoped = 0_u64;
        for source in ["otlp_logs", "otlp_traces"] {
            let counts = self
                .sources
                .get(source)
                .with_context(|| format!("source context audit is missing {source}"))?;
            if counts.checked_total()? != counts.total_records {
                bail!("source context audit {source} counts do not conserve records");
            }
            if counts.unscoped_turn_records != 0 || counts.unknown_session_records != 0 {
                bail!(
                    "source context audit {source} has unresolved records: unscoped_turn_records={}, unknown_session_records={}",
                    counts.unscoped_turn_records,
                    counts.unknown_session_records
                );
            }
            unscoped = unscoped
                .checked_add(counts.unscoped_turn_records)
                .context("source context audit unscoped count overflow")?;
        }
        if self.unscoped_otlp_records != unscoped {
            bail!("source context audit unscoped count does not match source counts");
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn audit_selected_source_context(
    captures: &[Value],
    session_id: &str,
    global: &ExactTurnIndex,
    duplicates: u64,
    sample_limit: usize,
) -> Result<SourceContextAudit> {
    if sample_limit > MAX_CONTEXT_SAMPLES {
        bail!("source context sample limit must be at most {MAX_CONTEXT_SAMPLES}");
    }
    let mut index = ExactTurnIndex::for_turns();
    index.include_global_scopes(global);
    for capture in captures {
        index.observe_capture(capture)?;
    }
    let mut audit = SourceContextAuditBuilder::new(
        session_id,
        allowed_source_sessions(captures, session_id),
        sample_limit,
    )?;
    for capture in captures {
        audit.observe_capture(capture, &index)?;
    }
    Ok(audit.finish(duplicates))
}

/// Accumulate bounded diagnostics while each Capture is already being read.
pub(crate) struct SourceContextAuditBuilder {
    session_id: String,
    allowed: BTreeSet<String>,
    sample_limit: usize,
    selected_captures: u64,
    sources: BTreeMap<String, SourceContextCounts>,
    groups: BTreeMap<(String, String, String, String), u64>,
    samples: Vec<ContextGapSample>,
    omitted_gap_records: u64,
    gaps: u64,
}

impl SourceContextAuditBuilder {
    pub(crate) fn new(
        session_id: &str,
        allowed: BTreeSet<String>,
        sample_limit: usize,
    ) -> Result<Self> {
        if sample_limit > MAX_CONTEXT_SAMPLES {
            bail!("source context sample limit must be at most {MAX_CONTEXT_SAMPLES}");
        }
        Ok(Self {
            session_id: session_id.to_owned(),
            allowed,
            sample_limit,
            selected_captures: 0,
            sources: BTreeMap::new(),
            groups: BTreeMap::new(),
            samples: Vec::new(),
            omitted_gap_records: 0,
            gaps: 0,
        })
    }

    pub(crate) fn observe_capture(
        &mut self,
        capture: &Value,
        index: &ExactTurnIndex,
    ) -> Result<()> {
        self.selected_captures += 1;
        let capture_id = capture
            .get("captureId")
            .and_then(Value::as_str)
            .unwrap_or("missing");
        let mut ordinal = 0;
        visit_otlp(capture, |source, record, attributes| {
            let record_index = ordinal;
            ordinal += 1;
            let observed = otlp_source_observation(source, record, &attributes, index)?;
            let counts = self.sources.entry(source.to_owned()).or_default();
            counts.total_records += 1;
            let in_session = observed
                .session_id
                .as_deref()
                .is_some_and(|s| self.allowed.contains(s));
            let ambiguous_session = observed.session_id.is_none()
                && observed
                    .related_sessions
                    .iter()
                    .any(|s| self.allowed.contains(s));
            if observed.process_scoped {
                counts.process_level_records += 1;
                return Ok(());
            }
            let disposition = if in_session && observed.turn_id.is_some() {
                counts.turn_assigned_records += 1;
                return Ok(());
            } else if in_session && !observed.requires_turn {
                counts.session_level_records += 1;
                return Ok(());
            } else if (in_session || ambiguous_session) && observed.requires_turn {
                counts.unscoped_turn_records += 1;
                "unscoped_turn"
            } else if observed.session_id.is_some() {
                counts.other_session_records += 1;
                return Ok(());
            } else {
                counts.unknown_session_records += 1;
                "unknown_session"
            };
            self.gaps += 1;
            let reason = if ambiguous_session {
                "ambiguous_session_context"
            } else {
                index.unresolved_reason(record, &attributes)?
            };
            // Names are diagnostic metadata, not bodies, tool arguments or arbitrary attributes.
            // Bound their size and omit control characters before printing operator diagnostics.
            let name = otlp_record_name(source, record, &attributes)
                .filter(|name| name.len() <= 160 && !name.chars().any(char::is_control))
                .unwrap_or_else(|| "<unnamed>".to_owned());
            let key = (
                source.to_owned(),
                disposition.to_owned(),
                name.clone(),
                reason.to_owned(),
            );
            if let Some(count) = self.groups.get_mut(&key) {
                *count += 1;
            } else if self.groups.len() < MAX_GROUPS {
                self.groups.insert(key, 1);
            } else {
                self.omitted_gap_records += 1;
            }
            if self.samples.len() < self.sample_limit {
                self.samples.push(ContextGapSample {
                    capture_id: capture_id.to_owned(),
                    record_index,
                    source: source.to_owned(),
                    disposition: disposition.to_owned(),
                    record_name: name,
                    reason: reason.to_owned(),
                    trace_id: hex_id(record.get("traceId"), 32),
                    span_id: hex_id(record.get("spanId"), 16),
                    parent_span_id: hex_id(record.get("parentSpanId"), 16),
                });
            }
            Ok(())
        })
    }

    pub(crate) fn finish(self, duplicates: u64) -> SourceContextAudit {
        SourceContextAudit {
            schema_version: SOURCE_CONTEXT_AUDIT_SCHEMA_VERSION.to_owned(),
            session_id: self.session_id,
            selected_captures: self.selected_captures,
            duplicate_captures_removed: duplicates,
            unscoped_otlp_records: self.sources.values().map(|s| s.unscoped_turn_records).sum(),
            sources: self.sources,
            group_limit: MAX_GROUPS,
            gap_groups: self
                .groups
                .into_iter()
                .map(
                    |((source, disposition, record_name, reason), records)| ContextGapGroup {
                        source,
                        disposition,
                        record_name,
                        reason,
                        records,
                    },
                )
                .collect(),
            omitted_gap_records: self.omitted_gap_records,
            sample_limit: self.sample_limit,
            omitted_samples: self.gaps - self.samples.len() as u64,
            samples: self.samples,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_view::summarize_session;
    use serde_json::json;

    fn native_fixture() -> (Value, Vec<Value>) {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../fixtures/native-context-0163.json"))
                .unwrap();
        let captures = vec![
            json!({"recordType":"api_snapshot","captureId":"wire","traceContext":fixture["wire_context"]}),
            batch(
                "otlp_logs",
                json!({"resourceLogs":[{"scopeLogs":[{"logRecords":fixture["logs"]}]}]}),
            ),
            batch(
                "otlp_traces",
                json!({"resourceSpans":[{"scopeSpans":[{"spans":fixture["spans"]}]}]}),
            ),
        ];
        (fixture, captures)
    }

    fn batch(source: &str, raw: Value) -> Value {
        json!({"recordType":"telemetry_batch","captureId":source,"telemetryBatch":{
            "endpoint":source,"raw_json":serde_json::to_string(&raw).unwrap()
        }})
    }

    fn audit(captures: &[Value], session: &str, limit: usize) -> SourceContextAudit {
        let mut global = ExactTurnIndex::default();
        for capture in captures {
            global.observe_capture(capture).unwrap();
        }
        let result = audit_selected_source_context(captures, session, &global, 0, limit).unwrap();
        let schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/source-context-audit-v2.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::draft202012::new(&schema).unwrap();
        assert!(validator.is_valid(&serde_json::to_value(&result).unwrap()));
        result
    }

    #[test]
    fn explicit_session_scope_counts_conserve_records_without_exempting_business_events() {
        let trace = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let root = "1111111111111111";
        let init = "2222222222222222";
        let turn = "3333333333333333";
        let captures = vec![
            json!({"recordType":"api_snapshot","captureId":"wire","traceContext":{
                "session_id":"s","turn_id":"t","trace_id":trace,"parent_span_id":turn
            }}),
            batch(
                "otlp_traces",
                json!({"resourceSpans":[{"scopeSpans":[{"spans":[
                    {"traceId":trace,"spanId":root,"attributes":[
                        {"key":"codex.context_scope","value":{"stringValue":"session"}},
                        {"key":"conversation.id","value":{"stringValue":"s"}}
                    ]},
                    {"name":"fs.get_metadata","traceId":trace,"spanId":init,"parentSpanId":root},
                    {"traceId":trace,"spanId":turn,"parentSpanId":root},
                    {"name":"fs.get_metadata","traceId":trace,"spanId":"4444444444444444","parentSpanId":turn}
                ]}]}]}),
            ),
            batch(
                "otlp_logs",
                json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[
                    {"traceId":trace,"spanId":init,"attributes":[{"key":"event.name","value":{"stringValue":"codex.api_request"}}]},
                    {"traceId":trace,"spanId":init,"attributes":[{"key":"event.name","value":{"stringValue":"codex.sse_event"}}]},
                    {"traceId":trace,"spanId":turn,"attributes":[{"key":"event.name","value":{"stringValue":"codex.sse_event"}}]},
                    {"attributes":[{"key":"event.name","value":{"stringValue":"unknown"}}]}
                ]}]}]}),
            ),
        ];
        let result = audit(&captures, "s", 10);
        assert_eq!(
            result.sources["otlp_traces"],
            SourceContextCounts {
                total_records: 4,
                turn_assigned_records: 2,
                session_level_records: 2,
                process_level_records: 0,
                ..Default::default()
            }
        );
        assert_eq!(
            result.sources["otlp_logs"],
            SourceContextCounts {
                total_records: 4,
                turn_assigned_records: 1,
                session_level_records: 1,
                process_level_records: 0,
                unscoped_turn_records: 1,
                unknown_session_records: 1,
                ..Default::default()
            }
        );
        let view = summarize_session(&captures, "s").unwrap();
        assert_eq!(view.turns[0].source_coverage.otlp_traces, 2);
        assert_eq!(view.turns[0].source_coverage.otlp_logs, 1);
        assert_eq!(view.unscoped_turn_records, 1);
        assert!(!view.delivery_ready);
    }

    #[test]
    fn turn_business_events_cannot_be_exempted_by_process_scope() {
        let trace = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let root = "5555555555555555";
        for name in [
            "codex.sse_event",
            "codex.tool_result",
            "codex.tool_decision",
            "codex.sandbox_outcome",
            "codex.user_prompt",
            "codex.turn_ttft",
            "codex.turn_cost",
        ] {
            for inherited in [false, true] {
                let mut log =
                    json!({"attributes":[{"key":"event.name","value":{"stringValue":name}}]});
                if inherited {
                    log["traceId"] = json!(trace);
                    log["spanId"] = json!(root);
                } else {
                    log["attributes"].as_array_mut().unwrap().push(json!({
                        "key":"codex.context_scope","value":{"stringValue":"process"}
                    }));
                }
                let captures = vec![
                    json!({"recordType":"api_snapshot","captureId":"wire","traceContext":{
                        "session_id":"s","turn_id":"t"
                    }}),
                    batch(
                        "otlp_traces",
                        json!({"resourceSpans":[{"scopeSpans":[{"spans":[{
                            "traceId":trace,"spanId":root,"name":"process.bootstrap",
                            "attributes":[{"key":"codex.context_scope","value":{"stringValue":"process"}}]
                        }]}]}]}),
                    ),
                    batch(
                        "otlp_logs",
                        json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[log]}]}]}),
                    ),
                ];
                let mut global = ExactTurnIndex::default();
                for capture in &captures {
                    global.observe_capture(capture).unwrap();
                }
                let error =
                    audit_selected_source_context(&captures, "s", &global, 0, 0).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("Turn-level business event conflicts with Process scope")
                );
                assert!(summarize_session(&captures, "s").is_err());
            }
        }
    }

    #[test]
    fn current_native_fields_preserve_all_context_gaps_and_count_unknown_sessions() {
        let (fixture, captures) = native_fixture();
        let session = fixture["session_id"].as_str().unwrap();
        let result = audit(&captures, session, 5);
        assert_eq!(
            result.sources["otlp_logs"],
            SourceContextCounts {
                total_records: 3,
                turn_assigned_records: 1,
                session_level_records: 1,
                process_level_records: 0,
                unscoped_turn_records: 1,
                other_session_records: 0,
                unknown_session_records: 0,
            }
        );
        assert_eq!(
            result.sources["otlp_traces"],
            SourceContextCounts {
                total_records: 26,
                turn_assigned_records: 10,
                session_level_records: 0,
                process_level_records: 0,
                unscoped_turn_records: 15,
                other_session_records: 0,
                unknown_session_records: 1,
            }
        );
        assert_eq!(result.unscoped_otlp_records, 16);
        assert_eq!(result.samples.len(), 5);
        assert_eq!(result.omitted_samples, 12);
        let sse = result
            .gap_groups
            .iter()
            .find(|g| g.record_name == "codex.sse_event")
            .unwrap();
        assert_eq!(sse.reason, "missing_trace_context");
        let init = result
            .gap_groups
            .iter()
            .find(|g| g.record_name == "fs.get_metadata")
            .unwrap();
        assert_eq!(init.reason, "trace_without_native_turn");
        assert_eq!(init.records, 2);
        let view = summarize_session(&captures, session).unwrap();
        assert_eq!(
            view.unscoped_source_records["otlp_logs"],
            result.sources["otlp_logs"].unscoped_turn_records
        );
        assert_eq!(
            view.unscoped_source_records["otlp_traces"],
            result.sources["otlp_traces"].unscoped_turn_records
        );
        assert!(!view.delivery_ready);
    }

    #[test]
    fn sse_requires_original_span_context_even_when_another_turn_shares_the_trace() {
        let (fixture, captures) = native_fixture();
        let mut index = ExactTurnIndex::for_turns();
        for capture in &captures {
            index.observe_capture(capture).unwrap();
        }
        let stream = fixture["spans"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "model_client.stream_responses_api")
            .unwrap();
        index
            .observe_capture(&json!({"recordType":"api_snapshot","traceContext":{
                "session_id":fixture["session_id"],"turn_id":"another-turn",
                "trace_id":stream["traceId"],"parent_span_id":"ffffffffffffffff"
            }}))
            .unwrap();
        let original = &fixture["logs"][1];
        let attributes = BTreeMap::from([(
            "conversation.id".to_owned(),
            fixture["session_id"].as_str().unwrap().to_owned(),
        )]);
        assert_eq!(index.resolve(original, &attributes).unwrap(), None);
        let mut callback = original.clone();
        callback["traceId"] = stream["traceId"].clone();
        assert_eq!(index.resolve(&callback, &attributes).unwrap(), None);
        // Positive protocol input only, not a modification to historical Raw or proof of a producer fix.
        callback["spanId"] = stream["spanId"].clone();
        assert_eq!(
            index.resolve(&callback, &attributes).unwrap(),
            Some((
                fixture["session_id"].as_str().unwrap().to_owned(),
                fixture["turn_id"].as_str().unwrap().to_owned(),
            ))
        );
    }

    #[test]
    fn diagnostics_omit_bodies_paths_and_non_identity_attribute_values() {
        let (fixture, mut captures) = native_fixture();
        let marker = "private-body-and-credential-marker";
        let mut logs: Value =
            serde_json::from_str(captures[1]["telemetryBatch"]["raw_json"].as_str().unwrap())
                .unwrap();
        let record = &mut logs["resourceLogs"][0]["scopeLogs"][0]["logRecords"][1];
        record["body"] = json!({"stringValue":marker});
        record["attributes"].as_array_mut().unwrap().extend([
            json!({"key":"tool.output","value":{"stringValue":marker}}),
            json!({"key":"code.file.path","value":{"stringValue":marker}}),
            json!({"key":"authorization","value":{"stringValue":marker}}),
        ]);
        captures[1]["telemetryBatch"]["raw_json"] = json!(serde_json::to_string(&logs).unwrap());
        let result = audit(&captures, fixture["session_id"].as_str().unwrap(), 20);
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains(marker));
        assert!(!serialized.contains("delivery_ready"));
        assert_eq!(result.unscoped_otlp_records, 16);
    }

    #[test]
    fn diagnostic_cardinality_is_bounded_without_dropping_total_gap_counts() {
        let logs: Vec<_> = (0..1300)
            .map(|i| {
                json!({"attributes":[
                    {"key":"event.name","value":{"stringValue":format!("event-{i}")}},
                    {"key":"conversation.id","value":{"stringValue":"session"}}
                ]})
            })
            .collect();
        let captures = vec![batch(
            "otlp_logs",
            json!({"resourceLogs":[{"scopeLogs":[{"logRecords":logs}]}]}),
        )];
        let result = audit(&captures, "session", 7);
        assert_eq!(result.sources["otlp_logs"].total_records, 1300);
        assert_eq!(result.unscoped_otlp_records, 1300);
        assert_eq!(result.gap_groups.len(), MAX_GROUPS);
        assert_eq!(result.omitted_gap_records, 1300 - MAX_GROUPS as u64);
        assert_eq!(result.samples.len(), 7);
        assert_eq!(result.omitted_samples, 1293);
        assert!(
            audit_selected_source_context(
                &captures,
                "session",
                &ExactTurnIndex::default(),
                0,
                1001
            )
            .is_err()
        );
    }
}
