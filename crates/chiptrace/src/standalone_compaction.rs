//! Compaction requires its own complete lifecycle inside a native Turn.
//! Standalone manual compaction has PreCompact/PostCompact, not a Stop hook.
//! Inline compaction must never close its enclosing business Turn. Match exact
//! native IDs and operation metadata; gateway and producer clocks may differ.

use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Default)]
pub(crate) struct CompactionBoundaries {
    starts: BTreeSet<String>,
    terminals: BTreeSet<String>,
    summaries: BTreeMap<(String, String), CompactionSummary>,
}

#[derive(Serialize)]
pub(crate) struct CompactionSummary {
    operations: usize,
    pre_hooks: usize,
    post_hooks: usize,
    complete: bool,
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

fn native_session(capture: &Value) -> Option<&str> {
    // Session selection may reparent a child while retaining its native ID.
    string(capture, "/traceContext/source_session_id")
        .or_else(|| string(capture, "/traceContext/session_id"))
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

fn valid_hook(
    capture: &Value,
    name: &str,
    status: &str,
    session: &str,
    turn: &str,
    trigger: &str,
) -> bool {
    string(capture, "/recordType") == Some("lifecycle_event")
        && string(capture, "/lifecycleEvent/source_event_name") == Some(name)
        && string(capture, "/lifecycleEvent/source_event/hook_event_name") == Some(name)
        && string(capture, "/lifecycleEvent/status") == Some(status)
        && string(capture, "/lifecycleEvent/source_event/session_id") == Some(session)
        && string(capture, "/lifecycleEvent/source_event/turn_id") == Some(turn)
        && string(capture, "/lifecycleEvent/source_event/trigger") == Some(trigger)
}

fn summarize(group: &Evidence<'_>, session: &str, turn: &str) -> Option<CompactionSummary> {
    let mut operations = BTreeSet::new();
    let mut valid = true;
    for capture in &group.wire {
        let Some(metadata) = metadata(capture) else {
            valid = false;
            continue;
        };
        if string(&metadata, "/request_kind") != Some("compaction") {
            continue;
        }
        let trigger = string(&metadata, "/compaction/trigger").unwrap_or("");
        let phase = string(&metadata, "/compaction/phase").unwrap_or("");
        let window = string(&metadata, "/window_id").unwrap_or("");
        valid &= string(&metadata, "/session_id") == Some(session)
            && string(&metadata, "/turn_id") == Some(turn)
            && match (trigger, phase) {
                ("manual", "standalone_turn") => true,
                ("auto", "pre_turn" | "mid_turn" | "post_turn") => {
                    !window.is_empty() && string(capture, "/traceContext/window_id") == Some(window)
                }
                _ => false,
            };
        // Native windows distinguish repeated compactions within one Turn.
        // HTTP retries for the same window/phase remain one operation.
        operations.insert((trigger.to_owned(), phase.to_owned(), window.to_owned()));
    }
    if operations.is_empty() && group.starts.is_empty() && group.terminals.is_empty() {
        return None;
    }
    if operations.iter().any(|(trigger, _, _)| trigger == "manual") {
        valid &= !group.business_turn
            && operations.len() == 1
            && group.wire.iter().all(|capture| {
                metadata(capture).is_some_and(|metadata| {
                    string(&metadata, "/request_kind") == Some("compaction")
                        && string(&metadata, "/compaction/trigger") == Some("manual")
                        && string(&metadata, "/compaction/phase") == Some("standalone_turn")
                })
            });
    }
    for trigger in ["manual", "auto"] {
        let expected = operations
            .iter()
            .filter(|(kind, _, _)| kind == trigger)
            .count();
        let mut hooks = Vec::new();
        for (captures, name, status, terminal) in [
            (&group.starts, "PreCompact", "started", false),
            (&group.terminals, "PostCompact", "completed", true),
        ] {
            let mut count = 0;
            for capture in captures {
                if string(capture, "/lifecycleEvent/source_event/trigger") != Some(trigger) {
                    continue;
                }
                count += 1;
                valid &= valid_hook(capture, name, status, session, turn, trigger);
                if let Some(time) = timestamp(capture, "/lifecycleEvent/occurred_at") {
                    hooks.push((time, terminal));
                } else {
                    valid = false;
                }
            }
            valid &= count == expected;
        }
        // Only compare producer Hook times, never gateway timestamps or time
        // windows to infer native identity or associate an HTTP request.
        hooks.sort_unstable();
        valid &= hooks.len() == expected * 2
            && hooks
                .iter()
                .enumerate()
                .all(|(index, (_, terminal))| *terminal == (index % 2 == 1));
    }
    valid &= group.starts.iter().chain(&group.terminals).all(|capture| {
        matches!(
            string(capture, "/lifecycleEvent/source_event/trigger"),
            Some("manual" | "auto")
        )
    });
    Some(CompactionSummary {
        operations: operations.len(),
        pre_hooks: group.starts.len(),
        post_hooks: group.terminals.len(),
        complete: valid && !operations.is_empty(),
    })
}

impl CompactionBoundaries {
    pub(crate) fn from_captures(captures: &[Value]) -> Self {
        let mut groups: BTreeMap<(&str, &str), Evidence<'_>> = BTreeMap::new();
        for capture in captures {
            let (Some(session), Some(turn)) = (
                native_session(capture),
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
            let Some(summary) = summarize(&group, session, turn) else {
                continue;
            };
            let complete = summary.complete;
            boundaries
                .summaries
                .insert((session.to_owned(), turn.to_owned()), summary);
            if !complete
                || group.business_turn
                || group.wire.is_empty()
                || group.starts.len() != 1
                || group.terminals.len() != 1
            {
                continue;
            }
            let start = group.starts[0];
            let terminal = group.terminals[0];
            if !valid_hook(start, "PreCompact", "started", session, turn, "manual")
                || !valid_hook(
                    terminal,
                    "PostCompact",
                    "completed",
                    session,
                    turn,
                    "manual",
                )
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

    pub(crate) fn summary(&self, session: &str, turn: &str) -> Option<&CompactionSummary> {
        self.summaries.get(&(session.to_owned(), turn.to_owned()))
    }

    pub(crate) fn is_complete(&self, session: &str, turn: &str) -> bool {
        self.summary(session, turn)
            .is_none_or(|summary| summary.complete)
    }

    pub(crate) fn summary_for_capture(&self, capture: &Value) -> Option<&CompactionSummary> {
        self.summary(
            native_session(capture)?,
            string(capture, "/traceContext/turn_id")?,
        )
    }

    pub(crate) fn capture_is_complete(&self, capture: &Value) -> bool {
        self.summary_for_capture(capture)
            .is_none_or(|summary| summary.complete)
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

    fn automatic_captures() -> Vec<Value> {
        let mut result = Vec::new();
        for (index, phase) in ["pre_turn", "mid_turn"].into_iter().enumerate() {
            let mut operation = captures();
            for (offset, hook) in [(0, "PreCompact"), (2, "PostCompact")] {
                operation[offset]["captureId"] = json!(format!("{hook}-{index}"));
                operation[offset]["lifecycleEvent"]["source_event"]["trigger"] = json!("auto");
                operation[offset]["lifecycleEvent"]["occurred_at"] =
                    json!(format!("2026-10-16T00:00:{:02}Z", index * 3 + offset));
            }
            let window = format!("s:{index}");
            operation[1]["captureId"] = json!(format!("wire-{index}"));
            operation[1]["traceContext"]["window_id"] = json!(window);
            operation[1]["requestHeaders"]["x-codex-turn-metadata"] =
                json!(json!({
                "session_id":"s","turn_id":"t","window_id":window,"request_kind":"compaction",
                "compaction":{"phase":phase,"trigger":"auto"}
            }).to_string());
            result.extend(operation);
        }
        result.push(
            json!({"captureId":"business-tool","recordType":"tool_execution",
            "traceContext":{"session_id":"s","turn_id":"t"}}),
        );
        result
    }

    #[test]
    fn automatic_windows_require_all_hook_pairs_without_closing_the_business_turn() {
        let mut captures = automatic_captures();
        // A completed retry is still the same operation identity, independent
        // of arrival order and the gateway clock.
        let mut retry = captures[1].clone();
        retry["captureId"] = json!("retry");
        retry["startedAt"] = json!("2000-01-01T00:00:00Z");
        captures.push(retry);
        captures.reverse();
        let boundaries = CompactionBoundaries::from_captures(&captures);
        assert!(boundaries.is_complete("s", "t"));
        assert_eq!(boundaries.summary("s", "t").unwrap().operations, 2);
        assert!(boundaries.starts.is_empty());
        assert!(boundaries.terminals.is_empty());
        for missing in [0, 2, 3, 5] {
            let mut captures = automatic_captures();
            captures.remove(missing);
            assert!(!CompactionBoundaries::from_captures(&captures).is_complete("s", "t"));
        }
    }

    #[test]
    fn automatic_compaction_rejects_ambiguous_windows_or_hook_identity_and_order() {
        for case in 0..9 {
            let mut captures = automatic_captures();
            match case {
                0 => captures[1]["traceContext"]["window_id"] = json!("other-window"),
                1 => captures[2]["lifecycleEvent"]["source_event"]["turn_id"] = json!("other-turn"),
                2 => captures[2]["lifecycleEvent"]["source_event"]["trigger"] = json!("manual"),
                3 => captures[2]["lifecycleEvent"]["occurred_at"] = json!("2026-10-16T00:00:04Z"),
                4 => captures[2]["lifecycleEvent"]["status"] = json!("failed"),
                5 => captures.push(captures[2].clone()),
                6 => captures[1]["requestHeaders"] = json!({"x-codex-turn-metadata":"invalid"}),
                7 => captures[2]["recordType"] = json!("api_snapshot"),
                8 => {
                    let mut metadata = metadata(&captures[1]).unwrap();
                    metadata["window_id"] = Value::Null;
                    captures[1]["requestHeaders"]["x-codex-turn-metadata"] =
                        json!(metadata.to_string());
                }
                _ => unreachable!(),
            }
            assert!(
                !CompactionBoundaries::from_captures(&captures).is_complete("s", "t"),
                "case {case}"
            );
        }
    }

    #[test]
    fn selected_parent_and_child_with_the_same_turn_id_keep_native_compaction_evidence_separate() {
        let mut captures = automatic_captures();
        let mut child = automatic_captures();
        child.remove(2); // Child has one missing PostCompact; parent is complete.
        for capture in &mut child {
            capture["captureId"] =
                json!(format!("child-{}", string(capture, "/captureId").unwrap()));
            capture["traceContext"]["source_session_id"] = json!("child");
            if capture.get("lifecycleEvent").is_some() {
                capture["lifecycleEvent"]["source_event"]["session_id"] = json!("child");
            }
            if let Some(mut metadata) = metadata(capture) {
                metadata["session_id"] = json!("child");
                capture["requestHeaders"]["x-codex-turn-metadata"] = json!(metadata.to_string());
            }
        }
        let child_wire = child
            .iter()
            .find(|capture| metadata(capture).is_some())
            .unwrap()
            .clone();
        captures.extend(child);
        let boundaries = CompactionBoundaries::from_captures(&captures);
        assert!(boundaries.is_complete("s", "t"));
        assert!(!boundaries.is_complete("child", "t"));
        assert!(!boundaries.capture_is_complete(&child_wire));
        assert_eq!(boundaries.summary("s", "t").unwrap().operations, 2);
        assert_eq!(boundaries.summary("child", "t").unwrap().operations, 2);
    }
}
