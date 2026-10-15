//! Standalone manual compaction has PreCompact/PostCompact, not a Stop hook.
//! Inline compaction must never close its enclosing business Turn. Match exact
//! native IDs and operation metadata; gateway and producer clocks may differ.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Default)]
pub(crate) struct CompactionBoundaries {
    starts: BTreeSet<String>,
    terminals: BTreeSet<String>,
}

#[derive(Default)]
struct Evidence<'a> {
    wire: Vec<&'a Value>,
    starts: Vec<&'a Value>,
    terminals: Vec<&'a Value>,
    business_turn: bool,
}

fn string<'a>(capture: &'a Value, pointer: &str) -> Option<&'a str> {
    capture
        .pointer(pointer)?
        .as_str()
        .filter(|value| !value.is_empty())
}

fn timestamp(capture: &Value, pointer: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(string(capture, pointer)?, &Rfc3339).ok()
}

fn metadata(capture: &Value) -> Option<Value> {
    let headers = capture.get("requestHeaders")?.as_object()?;
    let mut values = BTreeSet::new();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("x-codex-turn-metadata") {
            values.insert(value.as_str()?);
        }
    }
    (values.len() == 1)
        .then(|| values.into_iter().next())
        .flatten()
        .and_then(|value| serde_json::from_str(value).ok())
}

fn valid_hook(capture: &Value, name: &str, status: &str, session: &str, turn: &str) -> bool {
    string(capture, "/lifecycleEvent/source_event_name") == Some(name)
        && string(capture, "/lifecycleEvent/source_event/hook_event_name") == Some(name)
        && string(capture, "/lifecycleEvent/status") == Some(status)
        && string(capture, "/lifecycleEvent/source_event/session_id") == Some(session)
        && string(capture, "/lifecycleEvent/source_event/turn_id") == Some(turn)
        && string(capture, "/lifecycleEvent/source_event/trigger") == Some("manual")
}

impl CompactionBoundaries {
    pub(crate) fn from_captures(captures: &[Value]) -> Self {
        let mut groups: BTreeMap<(&str, &str), Evidence<'_>> = BTreeMap::new();
        for capture in captures {
            let (Some(session), Some(turn)) = (
                string(capture, "/traceContext/session_id"),
                string(capture, "/traceContext/turn_id"),
            ) else {
                continue;
            };
            let group = groups.entry((session, turn)).or_default();
            match string(capture, "/recordType") {
                Some("api_snapshot") => group.wire.push(capture),
                Some("tool_execution") => group.business_turn = true,
                _ => {}
            }
            match string(capture, "/lifecycleEvent/type") {
                Some("compaction_start") => group.starts.push(capture),
                Some("compaction_end") => group.terminals.push(capture),
                Some("turn_start" | "user_prompt_submit") => group.business_turn = true,
                _ => {}
            }
        }
        let mut boundaries = Self::default();
        for ((session, turn), group) in groups {
            if group.business_turn
                || group.wire.is_empty()
                || group.starts.len() != 1
                || group.terminals.len() != 1
            {
                continue;
            }
            let start = group.starts[0];
            let terminal = group.terminals[0];
            if !valid_hook(start, "PreCompact", "started", session, turn)
                || !valid_hook(terminal, "PostCompact", "completed", session, turn)
            {
                continue;
            }
            let (Some(started), Some(finished)) = (
                timestamp(start, "/lifecycleEvent/occurred_at"),
                timestamp(terminal, "/lifecycleEvent/occurred_at"),
            ) else {
                continue;
            };
            if finished < started
                || !group.wire.iter().all(|capture| {
                    let Some(metadata) = metadata(capture) else {
                        return false;
                    };
                    string(&metadata, "/session_id") == Some(session)
                        && string(&metadata, "/turn_id") == Some(turn)
                        && string(&metadata, "/request_kind") == Some("compaction")
                        && string(&metadata, "/compaction/phase") == Some("standalone_turn")
                        && string(&metadata, "/compaction/trigger") == Some("manual")
                })
            {
                continue;
            }
            if let (Some(start), Some(terminal)) =
                (string(start, "/captureId"), string(terminal, "/captureId"))
            {
                boundaries.starts.insert(start.to_owned());
                boundaries.terminals.insert(terminal.to_owned());
            }
        }
        boundaries
    }

    pub(crate) fn is_start(&self, capture: &Value) -> bool {
        string(capture, "/captureId").is_some_and(|id| self.starts.contains(id))
    }

    pub(crate) fn is_terminal(&self, capture: &Value) -> bool {
        string(capture, "/captureId").is_some_and(|id| self.terminals.contains(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn captures() -> Vec<Value> {
        let hook = |id, name, kind, status, time| {
            json!({
                "captureId":id,"recordType":"lifecycle_event",
                "traceContext":{"session_id":"s","turn_id":"t"},
                "lifecycleEvent":{"type":kind,"status":status,"occurred_at":time,
                    "source_event_name":name,"source_event":{"hook_event_name":name,
                        "session_id":"s","turn_id":"t","trigger":"manual"}}
            })
        };
        vec![
            hook(
                "pre",
                "PreCompact",
                "compaction_start",
                "started",
                "2026-10-16T00:00:00Z",
            ),
            json!({"captureId":"wire","recordType":"api_snapshot","startedAt":"2026-10-16T00:00:01Z",
                "traceContext":{"session_id":"s","turn_id":"t"},
                "requestHeaders":{"x-codex-turn-metadata":json!({"session_id":"s","turn_id":"t",
                    "request_kind":"compaction","compaction":{"phase":"standalone_turn","trigger":"manual"}}).to_string()}}),
            hook(
                "post",
                "PostCompact",
                "compaction_end",
                "completed",
                "2026-10-16T00:00:02Z",
            ),
        ]
    }

    #[test]
    fn standalone_compaction_requires_exact_hook_and_wire_evidence() {
        let mut captures = captures();
        captures.swap(0, 2); // Capture delivery order is not event time.
        captures[1]["startedAt"] = json!("2000-01-01T00:00:00Z"); // Gateway clock is not a join key.
        let boundaries = CompactionBoundaries::from_captures(&captures);
        assert!(boundaries.is_start(&captures[2]));
        assert!(boundaries.is_terminal(&captures[0]));
        assert!(!boundaries.is_terminal(&captures[1]));
    }

    #[test]
    fn inline_or_ambiguous_compaction_cannot_close_a_turn() {
        for case in 0..19 {
            let mut captures = captures();
            let mut metadata = metadata(&captures[1]).unwrap();
            match case {
                0 => metadata["compaction"]["phase"] = json!("pre_turn"),
                1 => metadata["compaction"]["phase"] = json!("post_turn"),
                2 => metadata["compaction"]["phase"] = Value::Null,
                3 => metadata["request_kind"] = json!("turn"),
                4 => metadata["turn_id"] = json!("other-turn"),
                5 => metadata["session_id"] = json!("other-session"),
                6 => metadata["compaction"]["trigger"] = json!("auto"),
                7 => captures[0]["lifecycleEvent"]["source_event"]["trigger"] = json!("auto"),
                8 => captures[2]["lifecycleEvent"]["status"] = json!("failed"),
                9 => captures[2]["lifecycleEvent"]["source_event"]["turn_id"] = json!("other-turn"),
                10 => captures[2]["lifecycleEvent"]["occurred_at"] = json!("2026-10-15T00:00:00Z"),
                11 => captures[1]["requestHeaders"]["X-Codex-Turn-Metadata"] = json!("invalid"),
                12 => captures[2]["lifecycleEvent"]["occurred_at"] = json!("invalid"),
                13 => captures[2]["lifecycleEvent"]["source_event_name"] = json!("untrusted"),
                14 => {
                    let mut normal = captures[1].clone();
                    normal["captureId"] = json!("normal-wire");
                    normal["requestHeaders"] = json!({});
                    captures.push(normal);
                }
                15 => captures.push(json!({"recordType":"tool_execution","traceContext":{"session_id":"s","turn_id":"t"}})),
                16 => captures.push(json!({"traceContext":{"session_id":"s","turn_id":"t"},"lifecycleEvent":{"type":"user_prompt_submit"}})),
                17 => captures[1]["requestHeaders"]["X-Codex-Turn-Metadata"] = json!("{}"),
                18 => captures.push(captures[0].clone()),
                _ => unreachable!(),
            }
            captures[1]["requestHeaders"]["x-codex-turn-metadata"] = json!(metadata.to_string());
            assert!(
                !CompactionBoundaries::from_captures(&captures).is_terminal(&captures[2]),
                "case {case}"
            );
        }
        for missing in [0, 1, 2] {
            let mut captures = captures();
            captures.remove(missing);
            assert!(
                CompactionBoundaries::from_captures(&captures)
                    .terminals
                    .is_empty()
            );
        }
    }
}
