//! Native Session/Turn accounting, separate from Buyer-v7 effective rounds.

use crate::lifecycle::LifecycleState;
use crate::turn_identity::{ExactTurnIndex, session_attribute, turn_attribute, visit_otlp};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const SESSION_VIEW_SCHEMA_VERSION: &str = "chiptrace.session-view.v2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnSourceCoverage {
    pub wire: u64,
    pub otlp_logs: u64,
    pub otlp_traces: u64,
    pub hooks: u64,
    pub missing_sources: Vec<String>,
    pub complete: bool,
}

impl TurnSourceCoverage {
    fn new() -> Self {
        let mut coverage = Self {
            wire: 0,
            otlp_logs: 0,
            otlp_traces: 0,
            hooks: 0,
            missing_sources: Vec::new(),
            complete: false,
        };
        coverage.finalize();
        coverage
    }

    fn observe(&mut self, source: &str) {
        match source {
            "wire" => self.wire = self.wire.saturating_add(1),
            "otlp_logs" => self.otlp_logs = self.otlp_logs.saturating_add(1),
            "otlp_traces" => self.otlp_traces = self.otlp_traces.saturating_add(1),
            "hooks" => self.hooks = self.hooks.saturating_add(1),
            _ => return,
        }
        self.finalize();
    }

    fn finalize(&mut self) {
        self.missing_sources = [
            ("wire", self.wire),
            ("otlp_logs", self.otlp_logs),
            ("otlp_traces", self.otlp_traces),
            ("hooks", self.hooks),
        ]
        .into_iter()
        .filter(|(_, count)| *count == 0)
        .map(|(source, _)| source.to_owned())
        .collect();
        self.complete = self.missing_sources.is_empty();
    }

    fn is_consistent(&self) -> bool {
        let expected: Vec<String> = [
            ("wire", self.wire),
            ("otlp_logs", self.otlp_logs),
            ("otlp_traces", self.otlp_traces),
            ("hooks", self.hooks),
        ]
        .into_iter()
        .filter(|(_, count)| *count == 0)
        .map(|(source, _)| source.to_owned())
        .collect();
        self.missing_sources == expected && self.complete == expected.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnView {
    pub session_id: String,
    pub turn_id: String,
    pub root_turn_id: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub status: String,
    pub start_events: u64,
    pub terminal_events: u64,
    pub model_interactions: u64,
    pub tool_execution_records: u64,
    pub state_conflict: bool,
    pub raw_capture_refs: BTreeSet<String>,
    pub source_coverage: TurnSourceCoverage,
}

impl TurnView {
    fn incomplete(&self) -> bool {
        !self.source_coverage.complete
            || !matches!(self.status.as_str(), "closed" | "cancelled")
            || self.state_conflict
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionView {
    pub schema_version: String,
    pub session_id: String,
    pub session_epochs: u64,
    pub closed_session_epochs: u64,
    pub latest_epoch_closed: bool,
    pub invalid_session_boundaries: u64,
    pub native_turns: u64,
    pub closed_turns: u64,
    pub open_turns: u64,
    pub conflicted_turns: u64,
    pub incomplete_turns: u64,
    pub turn_source_coverage_complete: bool,
    pub unscoped_turn_records: u64,
    pub unscoped_source_records: BTreeMap<String, u64>,
    pub delivery_ready: bool,
    pub model_interactions: u64,
    pub tool_execution_records: u64,
    pub turns: Vec<TurnView>,
}

impl SessionView {
    fn ready(&self) -> bool {
        self.native_turns > 0
            && self.latest_epoch_closed
            && self.invalid_session_boundaries == 0
            && self.open_turns == 0
            && self.conflicted_turns == 0
            && self.incomplete_turns == 0
            && self.unscoped_turn_records == 0
            && self.turn_source_coverage_complete
    }

    pub(crate) fn validate(
        &self,
        session_id: Option<&str>,
        interactions: u64,
    ) -> anyhow::Result<()> {
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/session-view-v2.schema.json"))?;
        let validator = jsonschema::draft202012::new(&schema)
            .map_err(|error| anyhow::anyhow!("compile Session/Turn schema: {error}"))?;
        if !validator.is_valid(&serde_json::to_value(self)?) {
            anyhow::bail!("Session/Turn summary does not satisfy its schema");
        }
        let scoped_interactions = self.turns.iter().try_fold(0_u64, |total, turn| {
            total.checked_add(turn.model_interactions)
        });
        let scoped_tools = self.turns.iter().try_fold(0_u64, |total, turn| {
            total.checked_add(turn.tool_execution_records)
        });
        if self.schema_version != SESSION_VIEW_SCHEMA_VERSION
            || session_id != Some(self.session_id.as_str())
            || self.native_turns != self.turns.len() as u64
            || self
                .closed_turns
                .checked_add(self.open_turns)
                .and_then(|v| v.checked_add(self.conflicted_turns))
                != Some(self.native_turns)
            || self.model_interactions != interactions
            || self.delivery_ready != self.ready()
            || self
                .unscoped_source_records
                .values()
                .try_fold(0_u64, |n, v| n.checked_add(*v))
                != Some(self.unscoped_turn_records)
            || scoped_interactions.is_none_or(|total| total > self.model_interactions)
            || scoped_tools.is_none_or(|total| total > self.tool_execution_records)
            || self.open_turns != self.turns.iter().filter(|t| t.status == "open").count() as u64
            || self.closed_turns
                != self
                    .turns
                    .iter()
                    .filter(|t| matches!(t.status.as_str(), "closed" | "cancelled"))
                    .count() as u64
            || self.conflicted_turns
                != self.turns.iter().filter(|t| t.state_conflict).count() as u64
            || self.incomplete_turns != self.turns.iter().filter(|t| t.incomplete()).count() as u64
            || self.turn_source_coverage_complete
                != (self.native_turns > 0 && self.incomplete_turns == 0)
            || self
                .turns
                .iter()
                .any(|t| !t.source_coverage.is_consistent())
            || self.turns.iter().any(|t| {
                (t.status == "conflict") != t.state_conflict
                    || (matches!(t.status.as_str(), "closed" | "cancelled")
                        && t.terminal_events == 0)
                    || (t.status == "open" && t.terminal_events != 0)
            })
        {
            anyhow::bail!("Session/Turn summary is inconsistent with its projection");
        }
        let identities: BTreeSet<_> = self
            .turns
            .iter()
            .map(|t| (&t.session_id, &t.turn_id))
            .collect();
        if identities.len() != self.turns.len()
            || self
                .turns
                .iter()
                .any(|t| t.session_id.is_empty() || t.turn_id.is_empty())
        {
            anyhow::bail!("Session/Turn summary contains missing or duplicate native identities");
        }
        Ok(())
    }
}

fn string<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
}

fn source_session(capture: &Value) -> Option<&str> {
    string(capture, "/traceContext/source_session_id")
        .or_else(|| string(capture, "/lifecycleEvent/source_event/session_id"))
        .or_else(|| string(capture, "/traceContext/session_id"))
}

#[derive(Debug, Clone)]
pub(crate) struct SourceObservation {
    pub(crate) source: &'static str,
    pub(crate) session_id: Option<String>,
    pub(crate) turn_id: Option<String>,
    occurred_at: Option<String>,
    pub(crate) requires_turn: bool,
    pub(crate) related_sessions: BTreeSet<String>,
}

fn nonempty_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

fn first_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| nonempty_string(value.get(*key)))
}

pub(crate) fn allowed_source_sessions(captures: &[Value], session_id: &str) -> BTreeSet<String> {
    captures
        .iter()
        .filter(|capture| string(capture, "/recordType") != Some("telemetry_batch"))
        .filter_map(source_session)
        .chain(std::iter::once(session_id))
        .map(str::to_owned)
        .collect()
}

pub(crate) fn otlp_record_name(
    source: &str,
    record: &Value,
    attributes: &BTreeMap<String, String>,
) -> Option<String> {
    if source == "otlp_logs" {
        attributes.get("event.name").cloned()
    } else {
        nonempty_string(record.get("name"))
    }
}

pub(crate) fn otlp_source_observation(
    source: &'static str,
    record: &Value,
    attributes: &BTreeMap<String, String>,
    index: &ExactTurnIndex,
) -> Result<SourceObservation> {
    let event_name = otlp_record_name(source, record, attributes);
    let exempt = matches!(
        event_name.as_deref(),
        Some(
            "codex.conversation_starts"
                | "codex.startup_phase"
                | "codex.websocket_connect"
                | "codex.websocket_request"
                | "codex.auth_recovery"
                | "codex.agent_communication"
                | "codex.session"
                | "session"
        )
    );
    let identity = index.resolve(record, attributes)?;
    let related_sessions = index.record_sessions(record, attributes)?;
    let session_id = identity
        .as_ref()
        .map(|(s, _)| s.clone())
        .or(session_attribute(attributes)?)
        .or_else(|| {
            (related_sessions.len() == 1).then(|| related_sessions.first().unwrap().clone())
        });
    let turn_id = identity.map(|(_, t)| t).or(turn_attribute(attributes)?);
    Ok(SourceObservation {
        source,
        session_id,
        turn_id,
        occurred_at: first_string(record, &["timeUnixNano", "observedTimeUnixNano"]),
        requires_turn: !exempt,
        related_sessions,
    })
}

fn source_observations(capture: &Value, index: &ExactTurnIndex) -> Result<Vec<SourceObservation>> {
    if string(capture, "/recordType") != Some("telemetry_batch") {
        return Ok(Vec::new());
    }
    let endpoint = string(capture, "/telemetryBatch/endpoint");
    let Some(raw) = string(capture, "/telemetryBatch/raw_json")
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
    else {
        return Ok(Vec::new());
    };
    match endpoint {
        Some("codex_hook") => {
            let event_name = first_string(&raw, &["hook_event_name"]);
            let requires_turn = event_name
                .as_deref()
                .is_some_and(|event| !matches!(event, "SessionStart" | "SessionEnd"));
            Ok(vec![SourceObservation {
                source: "hooks",
                session_id: first_string(&raw, &["session_id", "sessionId"]),
                turn_id: first_string(&raw, &["turn_id", "turnId", "root_turn_id", "rootTurnId"]),
                occurred_at: first_string(&raw, &["occurred_at", "occurredAt", "timestamp"]),
                requires_turn,
                related_sessions: BTreeSet::new(),
            }])
        }
        Some("otlp_logs" | "otlp_traces") => {
            let mut output = Vec::new();
            visit_otlp(capture, |source, record, attributes| {
                output.push(otlp_source_observation(source, record, &attributes, index)?);
                Ok(())
            })?;
            Ok(output)
        }
        _ => Ok(Vec::new()),
    }
}

/// Call with deduplicated, chronologically ordered captures selected by the
/// canonical exact-ID join. Repeated model requests never create extra turns.
#[cfg(test)]
pub(crate) fn summarize_session(captures: &[Value], session_id: &str) -> Result<SessionView> {
    summarize_session_with_scopes(captures, session_id, None)
}

pub(crate) fn summarize_session_with_scopes(
    captures: &[Value],
    session_id: &str,
    global: Option<&ExactTurnIndex>,
) -> Result<SessionView> {
    let mut index = ExactTurnIndex::for_turns();
    if let Some(global) = global {
        index.include_global_scopes(global);
    }
    for capture in captures {
        index.observe_capture(capture)?;
    }
    let allowed_sessions = allowed_source_sessions(captures, session_id);
    let mut lifecycle = LifecycleState::new("stock_codex_hook");
    let mut turns: BTreeMap<(String, String), TurnView> = BTreeMap::new();
    let mut terminal_statuses: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut unscoped_turn_records = 0;
    let mut unscoped_source_records = BTreeMap::new();
    let mut model_interactions = 0;
    let mut tool_execution_records = 0;
    for capture in captures {
        let capture_id = string(capture, "/captureId").unwrap_or("missing");
        let source_session = source_session(capture);
        let hook = string(capture, "/lifecycleEvent/source_event_name");
        let compact = string(capture, "/lifecycleEvent/source_event/source")
            .is_some_and(|value| value.eq_ignore_ascii_case("compact"));
        if source_session == Some(session_id) {
            match hook {
                Some("SessionStart") if !compact => {
                    lifecycle.observe_event("session_start", capture_id, true);
                }
                Some("SessionEnd") => {
                    lifecycle.observe_event("session_end", capture_id, true);
                }
                _ => {}
            }
        }
        let kind = string(capture, "/recordType").unwrap_or("api_snapshot");
        let event = string(capture, "/lifecycleEvent/type").unwrap_or("");
        let is_wire = kind == "api_snapshot";
        let is_tool = kind == "tool_execution";
        let is_start = event == "turn_start";
        let is_terminal = matches!(
            event,
            "turn_end" | "turn_stop" | "turn_interrupt" | "turn_aborted"
        );
        model_interactions += u64::from(is_wire);
        tool_execution_records += u64::from(is_tool);
        if !(is_wire || is_tool || is_start || is_terminal) {
            continue;
        }
        let native_turn_id = string(capture, "/traceContext/turn_id")
            .or_else(|| string(capture, "/lifecycleEvent/source_event/turn_id"));
        let root_turn_id = string(capture, "/traceContext/root_turn_id");
        let mut attributes = BTreeMap::new();
        if let Some(session) = source_session {
            attributes.insert("session.id".to_owned(), session.to_owned());
        }
        if let Some(turn) = native_turn_id.or(root_turn_id) {
            attributes.insert("turn.id".to_owned(), turn.to_owned());
        }
        let context = serde_json::json!({"traceId":capture.pointer("/traceContext/trace_id"), "spanId":capture.pointer("/traceContext/parent_span_id")});
        let Some(key) = index.resolve(&context, &attributes)? else {
            unscoped_turn_records += 1;
            *unscoped_source_records
                .entry(if is_wire { "wire" } else { kind }.to_owned())
                .or_insert(0) += 1;
            continue;
        };
        let time = string(capture, "/lifecycleEvent/occurred_at")
            .or_else(|| string(capture, "/startedAt"))
            .or_else(|| string(capture, "/receivedAt"));
        let turn = turns.entry(key.clone()).or_insert_with(|| TurnView {
            session_id: key.0.clone(),
            turn_id: key.1.clone(),
            root_turn_id: root_turn_id.map(str::to_owned),
            started_at: time.map(str::to_owned),
            finished_at: None,
            status: "open".to_owned(),
            start_events: 0,
            terminal_events: 0,
            model_interactions: 0,
            tool_execution_records: 0,
            state_conflict: false,
            raw_capture_refs: BTreeSet::new(),
            source_coverage: TurnSourceCoverage::new(),
        });
        if let Some(root) = root_turn_id {
            if turn
                .root_turn_id
                .as_deref()
                .is_some_and(|existing| existing != root)
            {
                turn.state_conflict = true;
            } else {
                turn.root_turn_id = Some(root.to_owned());
            }
        }
        turn.raw_capture_refs.insert(capture_id.to_owned());
        turn.model_interactions += u64::from(is_wire);
        turn.tool_execution_records += u64::from(is_tool);
        if is_wire {
            turn.source_coverage.observe("wire");
        }
        // Hook coverage counts the durable original batch only. The derived
        // lifecycle/tool record remains boundary evidence, not another Hook.
        if is_start {
            // A second start for the same native identity after a terminal is
            // a conflicting boundary, not an invented second turn.
            turn.state_conflict |= turn.terminal_events > 0;
            turn.start_events += 1;
        }
        if is_terminal {
            turn.terminal_events += 1;
            turn.finished_at = time.map(str::to_owned);
            let status = match event {
                "turn_interrupt" | "turn_aborted" => "cancelled",
                _ => "closed",
            };
            terminal_statuses
                .entry(key)
                .or_default()
                .insert(status.to_owned());
            turn.status = status.to_owned();
        }
    }

    for capture in captures {
        let capture_id = string(capture, "/captureId").unwrap_or("missing");
        for observation in source_observations(capture, &index)? {
            if observation.session_id.is_none()
                && observation.requires_turn
                && observation
                    .related_sessions
                    .iter()
                    .any(|s| allowed_sessions.contains(s.as_str()))
            {
                unscoped_turn_records += 1;
                *unscoped_source_records
                    .entry(observation.source.to_owned())
                    .or_insert(0) += 1;
                continue;
            }
            if !observation
                .session_id
                .as_deref()
                .is_some_and(|s| allowed_sessions.contains(s))
            {
                continue;
            }
            let Some(turn_id) = observation.turn_id else {
                if observation.requires_turn {
                    unscoped_turn_records += 1;
                    *unscoped_source_records
                        .entry(observation.source.to_owned())
                        .or_insert(0) += 1;
                }
                continue;
            };
            let source_session = observation.session_id.unwrap();
            let key = (source_session.clone(), turn_id.clone());
            let turn = turns.entry(key).or_insert_with(|| TurnView {
                session_id: source_session,
                turn_id,
                root_turn_id: None,
                started_at: observation.occurred_at.clone(),
                finished_at: None,
                status: "open".to_owned(),
                start_events: 0,
                terminal_events: 0,
                model_interactions: 0,
                tool_execution_records: 0,
                state_conflict: false,
                raw_capture_refs: BTreeSet::new(),
                source_coverage: TurnSourceCoverage::new(),
            });
            turn.raw_capture_refs.insert(capture_id.to_owned());
            turn.source_coverage.observe(observation.source);
        }
    }
    for (key, turn) in &mut turns {
        turn.state_conflict |= terminal_statuses
            .get(key)
            .is_some_and(|statuses| statuses.len() > 1);
        if turn.state_conflict {
            turn.status = "conflict".to_owned();
        }
    }
    let turns: Vec<_> = turns.into_values().collect();
    let open_turns = turns.iter().filter(|t| t.status == "open").count() as u64;
    let conflicted_turns = turns.iter().filter(|t| t.state_conflict).count() as u64;
    let incomplete_turns = turns.iter().filter(|turn| turn.incomplete()).count() as u64;
    let mut view = SessionView {
        schema_version: SESSION_VIEW_SCHEMA_VERSION.to_owned(),
        session_id: session_id.to_owned(),
        session_epochs: lifecycle.start_count,
        closed_session_epochs: lifecycle.terminal_count,
        latest_epoch_closed: lifecycle.latest_epoch_closed && lifecycle.invalid_boundary_count == 0,
        invalid_session_boundaries: lifecycle.invalid_boundary_count,
        native_turns: turns.len() as u64,
        closed_turns: turns.len() as u64 - open_turns - conflicted_turns,
        open_turns,
        conflicted_turns,
        incomplete_turns,
        turn_source_coverage_complete: !turns.is_empty() && incomplete_turns == 0,
        unscoped_turn_records,
        unscoped_source_records,
        delivery_ready: false,
        model_interactions,
        tool_execution_records,
        turns,
    };
    view.delivery_ready = view.ready();
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn boundary(id: &str, hook: &str, source: &str) -> Value {
        json!({"captureId":id,"recordType":"lifecycle_event", "traceContext":{"session_id":"s"},
            "lifecycleEvent":{"source_event_name":hook,"source_event":{"session_id":"s","source":source}}})
    }

    fn telemetry(id: &str, endpoint: &str, raw: Value) -> Value {
        json!({"captureId":id,"recordType":"telemetry_batch","telemetryBatch":{
            "endpoint":endpoint,"raw_json":serde_json::to_string(&raw).unwrap()
        }})
    }

    #[test]
    fn native_otlp_unscoped_logs_keep_a_four_source_session_unready() {
        // Field layout observed in the 2026-09-05 Stock Codex canary: native
        // tool logs have W3C context, while SSE diagnostic logs may have none.
        let trace = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut captures = vec![
            boundary("start", "SessionStart", "startup"),
            boundary("end", "SessionEnd", ""),
        ];
        captures.push(
            json!({"captureId":"wire","recordType":"api_snapshot","traceContext":{
                "session_id":"s","turn_id":"t","trace_id":trace,"parent_span_id":"1111111111111111"
            }}),
        );
        captures.push(telemetry(
            "logs",
            "otlp_logs",
            json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[
                {"traceId":trace,"spanId":"1111111111111111","attributes":[
                    {"key":"event.name","value":{"stringValue":"codex.tool_result"}},
                    {"key":"conversation.id","value":{"stringValue":"s"}}
                ]},
                {"traceId":"","spanId":"","attributes":[
                    {"key":"event.name","value":{"stringValue":"codex.sse_event"}},
                    {"key":"conversation.id","value":{"stringValue":"s"}}
                ]}
            ]}]}]}),
        ));
        captures.push(telemetry(
            "traces",
            "otlp_traces",
            json!({"resourceSpans":[{"scopeSpans":[{"spans":[{
                "name":"session_task.turn","traceId":trace,"spanId":"2222222222222222",
                "attributes":[{"key":"turn.id","value":{"stringValue":"t"}}]
            }]}]}]}),
        ));
        captures.push(telemetry(
            "hook",
            "codex_hook",
            json!({"hook_event_name":"Stop","session_id":"s","turn_id":"t"}),
        ));
        captures.push(json!({"captureId":"stop","recordType":"lifecycle_event","traceContext":{"session_id":"s","turn_id":"t"},"lifecycleEvent":{"type":"turn_stop","source_event_name":"Stop"}}));
        let view = summarize_session(&captures, "s").unwrap();
        assert!(view.turn_source_coverage_complete);
        assert_eq!(view.turns[0].source_coverage.hooks, 1);
        assert_eq!(
            view.unscoped_source_records,
            BTreeMap::from([("otlp_logs".to_owned(), 1)])
        );
        assert!(!view.delivery_ready);
        view.validate(Some("s"), 1).unwrap();
    }

    #[test]
    fn unnamed_otlp_records_are_not_exempt_from_turn_accounting() {
        let session_attribute = json!({"key":"conversation.id","value":{"stringValue":"s"}});
        let captures = vec![
            telemetry(
                "unnamed-log",
                "otlp_logs",
                json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[{
                    "attributes":[session_attribute.clone()]
                }]}]}]}),
            ),
            telemetry(
                "unnamed-span",
                "otlp_traces",
                json!({"resourceSpans":[{"scopeSpans":[{"spans":[{
                    "attributes":[session_attribute]
                }]}]}]}),
            ),
        ];
        let view = summarize_session(&captures, "s").unwrap();
        assert_eq!(view.unscoped_turn_records, 2);
        assert_eq!(
            view.unscoped_source_records,
            BTreeMap::from([("otlp_logs".to_owned(), 1), ("otlp_traces".to_owned(), 1)])
        );
        assert!(!view.delivery_ready);
        view.validate(Some("s"), 0).unwrap();
    }

    #[test]
    fn native_otlp_child_session_sources_do_not_borrow_parent_coverage() {
        let mut captures = vec![
            boundary("start", "SessionStart", "startup"),
            boundary("end", "SessionEnd", ""),
        ];
        for session in ["s", "child"] {
            captures.push(
                json!({"captureId":format!("wire-{session}"),"recordType":"api_snapshot",
                "traceContext":{"session_id":"s","source_session_id":session,"turn_id":"t"}}),
            );
            captures.push(json!({"captureId":format!("stop-{session}"),"recordType":"lifecycle_event",
                "traceContext":{"session_id":"s","source_session_id":session,"turn_id":"t"},"lifecycleEvent":{"type":"turn_stop"}}));
            captures.push(telemetry(
                &format!("hook-{session}"),
                "codex_hook",
                json!({"hook_event_name":"Stop","session_id":session,"turn_id":"t"}),
            ));
            let attributes = json!([
                {"key":"conversation.id","value":{"stringValue":session}},
                {"key":"turn.id","value":{"stringValue":"t"}}
            ]);
            captures.push(telemetry(&format!("log-{session}"),"otlp_logs",json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":attributes}]}]}]})));
            if session == "s" {
                captures.push(telemetry("trace-root","otlp_traces",json!({"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"codex.turn","attributes":attributes}]}]}]})));
            }
        }
        let view = summarize_session(&captures, "s").unwrap();
        assert_eq!(view.native_turns, 2);
        assert_eq!(view.incomplete_turns, 1);
        let child = view.turns.iter().find(|t| t.session_id == "child").unwrap();
        assert_eq!(child.source_coverage.missing_sources, ["otlp_traces"]);
        assert_eq!(child.source_coverage.hooks, 1);
        assert!(!view.delivery_ready);
        view.validate(Some("s"), 2).unwrap();
    }

    #[test]
    fn retries_tools_and_compaction_do_not_inflate_native_turns_or_epochs() {
        let mut captures = vec![boundary("start", "SessionStart", "startup")];
        for id in ["wire-1", "wire-retry", "wire-2"] {
            captures.push(json!({"captureId":id,"recordType":"api_snapshot",
                "traceContext":{"session_id":"s","turn_id":"t","root_turn_id":"t"}}));
        }
        captures.push(boundary("compact", "SessionStart", "compact"));
        captures.push(json!({"captureId":"tool","recordType":"tool_execution",
            "traceContext":{"session_id":"s","turn_id":"t"}}));
        captures.push(json!({"captureId":"stop","recordType":"lifecycle_event",
            "traceContext":{"session_id":"s","turn_id":"t"},"lifecycleEvent":{"type":"turn_stop"}}));
        captures.push(boundary("end", "SessionEnd", ""));
        let view = summarize_session(&captures, "s").unwrap();
        assert_eq!(
            (view.session_epochs, view.native_turns, view.closed_turns),
            (1, 1, 1)
        );
        assert_eq!(
            (view.model_interactions, view.tool_execution_records),
            (3, 1)
        );
        assert!(view.latest_epoch_closed);
        view.validate(Some("s"), 3).unwrap();
        let mut invalid = view;
        invalid.turns[0].status = "invented".to_owned();
        assert!(invalid.validate(Some("s"), 3).is_err());
    }

    #[test]
    fn resume_requires_its_own_end_and_missing_turn_ids_are_not_inferred() {
        let mut captures = vec![
            boundary("s1", "SessionStart", "startup"),
            boundary("e1", "SessionEnd", ""),
            boundary("s2", "SessionStart", "resume"),
            json!({"captureId":"wire","recordType":"api_snapshot","traceContext":{"session_id":"s"}}),
        ];
        let open = summarize_session(&captures, "s").unwrap();
        assert_eq!((open.session_epochs, open.closed_session_epochs), (2, 1));
        assert!(!open.latest_epoch_closed);
        assert_eq!((open.native_turns, open.unscoped_turn_records), (0, 1));
        captures.push(boundary("e2", "SessionEnd", ""));
        assert!(
            summarize_session(&captures, "s")
                .unwrap()
                .latest_epoch_closed
        );
    }

    #[test]
    fn child_turn_identity_and_conflicting_terminals_stay_separate() {
        let captures = vec![
            json!({"captureId":"root","recordType":"api_snapshot","traceContext":{"session_id":"s","turn_id":"t"}}),
            json!({"captureId":"child","recordType":"api_snapshot","traceContext":{"session_id":"s","source_session_id":"child","turn_id":"t","root_turn_id":"t"}}),
            json!({"captureId":"stop","recordType":"lifecycle_event","traceContext":{"session_id":"s","turn_id":"t"},"lifecycleEvent":{"type":"turn_stop"}}),
            json!({"captureId":"cancel","recordType":"lifecycle_event","traceContext":{"session_id":"s","turn_id":"t"},"lifecycleEvent":{"type":"turn_interrupt"}}),
        ];
        let view = summarize_session(&captures, "s").unwrap();
        assert_eq!(
            (view.native_turns, view.open_turns, view.conflicted_turns),
            (2, 1, 1)
        );
        assert_eq!(view.closed_turns, 0);
    }

    #[test]
    fn every_native_turn_requires_all_four_source_observations() {
        let telemetry = |id: &str, endpoint: &str, raw: Value| {
            json!({
                "captureId":id,
                "recordType":"telemetry_batch",
                "telemetryBatch":{"endpoint":endpoint,"raw_json":serde_json::to_string(&raw).unwrap()}
            })
        };
        let wire = json!({
            "captureId":"wire",
            "recordType":"api_snapshot",
            "traceContext":{"session_id":"s","turn_id":"t"}
        });
        let logs = telemetry(
            "logs",
            "otlp_logs",
            json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[
                {"key":"event.name","value":{"stringValue":"codex.tool_result"}},
                {"key":"conversation.id","value":{"stringValue":"s"}},
                {"key":"turn.id","value":{"stringValue":"t"}}
            ]}]}]}]}),
        );
        let traces = telemetry(
            "traces",
            "otlp_traces",
            json!({"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"codex.turn","attributes":[
                {"key":"conversation.id","value":{"stringValue":"s"}},
                {"key":"turn.id","value":{"stringValue":"t"}}
            ]}]}]}]}),
        );
        let hook = telemetry(
            "hook",
            "codex_hook",
            json!({"hook_event_name":"Stop","session_id":"s","turn_id":"t"}),
        );
        let end = json!({
            "captureId":"end",
            "recordType":"lifecycle_event",
            "traceContext":{"session_id":"s","turn_id":"t"},
            "lifecycleEvent":{"type":"turn_end","source_event_name":"Stop"}
        });
        let complete =
            summarize_session(&[wire.clone(), logs, traces, hook, end.clone()], "s").unwrap();
        assert!(complete.turn_source_coverage_complete);
        assert_eq!(complete.incomplete_turns, 0);
        assert_eq!(complete.turns[0].source_coverage.hooks, 1);
        assert_eq!(
            complete.turns[0].source_coverage.missing_sources,
            Vec::<String>::new()
        );

        let incomplete = summarize_session(&[wire, end], "s").unwrap();
        assert!(!incomplete.turn_source_coverage_complete);
        assert_eq!(incomplete.incomplete_turns, 1);
        assert_eq!(
            incomplete.turns[0].source_coverage.missing_sources,
            ["otlp_logs", "otlp_traces", "hooks"]
        );
    }
}
