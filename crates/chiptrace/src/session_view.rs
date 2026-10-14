//! Native Session/Turn accounting, separate from Buyer-v7 effective rounds.

use crate::lifecycle::LifecycleState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const SESSION_VIEW_SCHEMA_VERSION: &str = "chiptrace.session-view.v1";

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
    pub unscoped_turn_records: u64,
    pub model_interactions: u64,
    pub tool_execution_records: u64,
    pub turns: Vec<TurnView>,
}

impl SessionView {
    pub(crate) fn validate(
        &self,
        session_id: Option<&str>,
        interactions: u64,
    ) -> anyhow::Result<()> {
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/session-view-v1.schema.json"))?;
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

/// Call with deduplicated, chronologically ordered captures selected by the
/// canonical exact-ID join. Repeated model requests never create extra turns.
pub(crate) fn summarize_session(captures: &[Value], session_id: &str) -> SessionView {
    let mut lifecycle = LifecycleState::new("stock_codex_hook");
    let mut turns: BTreeMap<(String, String), TurnView> = BTreeMap::new();
    let mut terminal_statuses: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut unscoped_turn_records = 0;
    let mut model_interactions = 0;
    let mut tool_execution_records = 0;
    for capture in captures {
        let capture_id = string(capture, "/captureId").unwrap_or("missing");
        let source_session = source_session(capture).unwrap_or(session_id);
        let hook = string(capture, "/lifecycleEvent/source_event_name");
        let compact = string(capture, "/lifecycleEvent/source_event/source")
            .is_some_and(|value| value.eq_ignore_ascii_case("compact"));
        if source_session == session_id {
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
        let Some(turn_id) = native_turn_id.or(root_turn_id) else {
            unscoped_turn_records += 1;
            continue;
        };
        let key = (source_session.to_owned(), turn_id.to_owned());
        let time = string(capture, "/lifecycleEvent/occurred_at")
            .or_else(|| string(capture, "/startedAt"))
            .or_else(|| string(capture, "/receivedAt"));
        let turn = turns.entry(key.clone()).or_insert_with(|| TurnView {
            session_id: source_session.to_owned(),
            turn_id: turn_id.to_owned(),
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
    SessionView {
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
        unscoped_turn_records,
        model_interactions,
        tool_execution_records,
        turns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn boundary(id: &str, hook: &str, source: &str) -> Value {
        json!({"captureId":id,"recordType":"lifecycle_event", "traceContext":{"session_id":"s"},
            "lifecycleEvent":{"source_event_name":hook,"source_event":{"session_id":"s","source":source}}})
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
        let view = summarize_session(&captures, "s");
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
        let open = summarize_session(&captures, "s");
        assert_eq!((open.session_epochs, open.closed_session_epochs), (2, 1));
        assert!(!open.latest_epoch_closed);
        assert_eq!((open.native_turns, open.unscoped_turn_records), (0, 1));
        captures.push(boundary("e2", "SessionEnd", ""));
        assert!(summarize_session(&captures, "s").latest_epoch_closed);
    }

    #[test]
    fn child_turn_identity_and_conflicting_terminals_stay_separate() {
        let captures = vec![
            json!({"captureId":"root","recordType":"api_snapshot","traceContext":{"session_id":"s","turn_id":"t"}}),
            json!({"captureId":"child","recordType":"api_snapshot","traceContext":{"session_id":"s","source_session_id":"child","turn_id":"t","root_turn_id":"t"}}),
            json!({"captureId":"stop","recordType":"lifecycle_event","traceContext":{"session_id":"s","turn_id":"t"},"lifecycleEvent":{"type":"turn_stop"}}),
            json!({"captureId":"cancel","recordType":"lifecycle_event","traceContext":{"session_id":"s","turn_id":"t"},"lifecycleEvent":{"type":"turn_interrupt"}}),
        ];
        let view = summarize_session(&captures, "s");
        assert_eq!(
            (view.native_turns, view.open_turns, view.conflicted_turns),
            (2, 1, 1)
        );
        assert_eq!(view.closed_turns, 0);
    }
}
