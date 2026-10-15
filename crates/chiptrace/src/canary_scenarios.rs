//! Small scenario witnesses from the same exact-ID snapshot as Session inspection.

use crate::session_view::SessionView;
use crate::tool_schema::is_stock_unified_exec_tool;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const PROCESS_PROVENANCE: &str = "stock_codex.unified_exec.log_output.header";
const SCENARIOS: [&str; 4] = [
    "second_turn",
    "resume",
    "failed_tool_process",
    "delayed_write_stdin",
];

fn text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer)?.as_str()
}

fn observation(capture: &Value, session_id: &str, turn_id: &str) -> Option<Value> {
    if text(capture, "/recordType") != Some("tool_execution") {
        return None;
    }
    let execution = capture.get("toolExecution")?;
    let name = text(execution, "/name")?;
    let tool = text(execution, "/runtime_tool").unwrap_or(name);
    let namespace = text(execution, "/runtime_namespace");
    if !is_stock_unified_exec_tool(namespace, tool)
        || name != tool
        || text(execution, "/source_event_name") != Some("codex.tool_result")
        || execution.get("output_truncated")?.as_bool() != Some(false)
        || text(execution, "/process_outcome/provenance") != Some(PROCESS_PROVENANCE)
    {
        return None;
    }
    let outcome = execution.get("process_outcome")?;
    if text(outcome, "/kind") != Some("process") {
        return None;
    }
    match text(outcome, "/state")? {
        "running"
            if outcome.get("session_id")?.as_i64()? > 0 && outcome.get("success")?.is_null() => {}
        "exited"
            if outcome.get("success")?.as_bool()? == (outcome.get("exit_code")?.as_i64()? == 0) => {
        }
        _ => return None,
    }
    let sequence = execution.get("tool_result_seq")?.as_u64()?;
    if sequence == 0 {
        return None;
    }
    let mut process = json!({
        "kind":"process","state":outcome["state"],"success":outcome["success"],
        "provenance":PROCESS_PROVENANCE
    });
    let field = if text(outcome, "/state") == Some("running") {
        "session_id"
    } else {
        "exit_code"
    };
    process[field] = outcome[field].clone();
    Some(json!({
        "capture_id":text(capture, "/captureId")?,
        "session_id":session_id,
        "turn_id":turn_id,
        "call_id":text(execution, "/call_id")?,
        "tool":tool,
        "runtime_namespace":namespace.unwrap_or("functions"),
        "source_event_name":"codex.tool_result",
        "tool_result_seq":sequence,
        "output_truncated":false,
        "process_outcome":process,
        "requested_session_id":execution.pointer("/arguments/session_id").and_then(Value::as_i64)
    }))
}

pub(crate) fn summarize(captures: &[Value], session: &SessionView) -> Value {
    // A tool Capture may inherit its Turn through exact W3C ancestry. Reuse
    // that resolved membership, never a timestamp or a neighbouring tool.
    let mut owners = BTreeMap::new();
    for turn in &session.turns {
        for capture_id in &turn.raw_capture_refs {
            owners
                .entry(capture_id.as_str())
                .and_modify(|owner| *owner = None)
                .or_insert(Some(turn));
        }
    }
    let mut observations: BTreeMap<(String, String), Value> = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for capture in captures {
        let Some(turn) = text(capture, "/captureId")
            .and_then(|id| owners.get(id))
            .and_then(|owner| *owner)
        else {
            continue;
        };
        if turn.session_id != session.session_id {
            continue;
        }
        let Some(witness) = observation(capture, &turn.session_id, &turn.turn_id) else {
            continue;
        };
        let key = (
            turn.turn_id.clone(),
            witness["call_id"].as_str().unwrap().to_owned(),
        );
        if let Some(previous) = observations.get(&key) {
            let mut repeated = witness.clone();
            repeated["capture_id"] = previous["capture_id"].clone();
            if *previous != repeated {
                conflicts.insert(key);
            }
        } else {
            observations.insert(key, witness);
        }
    }
    let observations: Vec<&Value> = observations
        .iter()
        .filter(|(key, _)| !conflicts.contains(*key))
        .map(|(_, witness)| witness)
        .collect();
    let turns: Vec<&str> = session
        .turns
        .iter()
        .filter(|turn| turn.session_id == session.session_id && turn.model_interactions > 0)
        .take(2)
        .map(|turn| turn.turn_id.as_str())
        .collect();
    let second_turn = (turns.len() == 2).then(|| json!({"turn_ids":turns}));
    let resume = captures.iter().find_map(|capture| {
        (text(capture, "/recordType") == Some("lifecycle_event")
            && text(capture, "/lifecycleEvent/type") == Some("session_start")
            && text(capture, "/traceContext/session_id") == Some(session.session_id.as_str())
            && text(capture, "/lifecycleEvent/source_event_name") == Some("SessionStart")
            && text(capture, "/lifecycleEvent/source_event/source") == Some("resume"))
        .then(|| {
            json!({
                "capture_id":text(capture, "/captureId"),
                "source_event_name":"SessionStart",
                "source":"resume"
            })
        })
    });
    let failed = observations.iter().find(|witness| {
        text(witness, "/process_outcome/state") == Some("exited")
            && witness
                .pointer("/process_outcome/exit_code")
                .and_then(Value::as_i64)
                .is_some_and(|code| code != 0)
    });
    let delayed = observations.iter().find_map(|launch| {
        if text(launch, "/tool") != Some("exec_command")
            || text(launch, "/process_outcome/state") != Some("running")
        {
            return None;
        }
        let process_id = &launch["process_outcome"]["session_id"];
        // Reused IDs in the same native Turn do not identify one process.
        if observations
            .iter()
            .filter(|other| {
                other["turn_id"] == launch["turn_id"]
                    && text(other, "/tool") == Some("exec_command")
                    && other.pointer("/process_outcome/session_id") == Some(process_id)
            })
            .count()
            != 1
        {
            return None;
        }
        let terminal = observations
            .iter()
            .filter(|poll| {
                text(poll, "/tool") == Some("write_stdin")
                    && poll["turn_id"] == launch["turn_id"]
                    && poll["requested_session_id"] == *process_id
                    && poll["tool_result_seq"].as_u64() > launch["tool_result_seq"].as_u64()
                    && text(poll, "/process_outcome/state") == Some("exited")
            })
            .min_by_key(|poll| poll["tool_result_seq"].as_u64())?;
        Some(json!({"launch":launch,"terminal":terminal}))
    });
    let mut evidence = json!({
        "schema_version":"chiptrace.native-canary-scenarios.v1",
        "session_id":session.session_id,
        "source":"exact_capture_snapshot",
        "second_turn":second_turn,
        "resume":resume,
        "failed_tool_process":failed,
        "delayed_write_stdin":delayed
    });
    let missing: Vec<&str> = SCENARIOS
        .into_iter()
        .filter(|name| evidence[*name].is_null())
        .collect();
    evidence["complete"] = json!(missing.is_empty());
    evidence["missing_scenarios"] = json!(missing);
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<Value> {
        let event = |id: &str, turn: Option<&str>, kind: &str, hook: &str, source: &str| {
            json!({
                "captureId":id,"recordType":"lifecycle_event",
                "traceContext":{"session_id":"s","turn_id":turn},
                "lifecycleEvent":{"type":kind,"source_event_name":hook,"source_event":{"source":source}}
            })
        };
        let tool = |id: &str, name: &str, seq: u64, process: Value| {
            json!({
                "captureId":id,"recordType":"tool_execution",
                "traceContext":{"session_id":"s","turn_id":"t1"},
                "toolExecution":{
                    "call_id":id,"name":name,"runtime_tool":name,"runtime_namespace":"functions",
                    "source_event_name":"codex.tool_result","status":"success",
                    "tool_result_seq":seq,"output_truncated":false,
                    "arguments":{"session_id":4242},"result":"private-tool-body",
                    "process_outcome":process
                }
            })
        };
        let exited = |code: i64| {
            json!({
                "kind":"process","state":"exited","exit_code":code,"success":code == 0,
                "provenance":PROCESS_PROVENANCE,"extra":"private-process-field"
            })
        };
        vec![
            event("start", None, "session_start", "SessionStart", "startup"),
            event("turn1", Some("t1"), "turn_start", "UserPromptSubmit", ""),
            json!({"captureId":"wire1","recordType":"api_snapshot","traceContext":{"session_id":"s","turn_id":"t1"}}),
            tool("failed", "exec_command", 1, exited(7)),
            tool(
                "launch",
                "exec_command",
                2,
                json!({"kind":"process","state":"running","session_id":4242,"success":null,"provenance":PROCESS_PROVENANCE}),
            ),
            tool("poll", "write_stdin", 3, exited(0)),
            event("stop1", Some("t1"), "turn_end", "Stop", ""),
            event("end1", None, "session_end", "SessionEnd", ""),
            event("resume", None, "session_start", "SessionStart", "resume"),
            event("turn2", Some("t2"), "turn_start", "UserPromptSubmit", ""),
            json!({"captureId":"wire2","recordType":"api_snapshot","traceContext":{"session_id":"s","turn_id":"t2"}}),
            event("stop2", Some("t2"), "turn_end", "Stop", ""),
            event("end2", None, "session_end", "SessionEnd", ""),
        ]
    }

    fn inspect(captures: &[Value]) -> Value {
        let session = crate::session_view::summarize_session(captures, "s").unwrap();
        summarize(captures, &session)
    }

    #[test]
    fn witnesses_come_from_observed_hooks_turns_and_typed_process_results() {
        let captures = fixture();
        let original = captures.clone();
        let evidence = inspect(&captures);
        assert_eq!(evidence["complete"], true);
        assert_eq!(evidence["resume"]["capture_id"], "resume");
        assert_eq!(
            evidence["failed_tool_process"]["process_outcome"]["exit_code"],
            7
        );
        assert_eq!(
            evidence["delayed_write_stdin"]["launch"]["call_id"],
            "launch"
        );
        assert_eq!(
            evidence["delayed_write_stdin"]["terminal"]["call_id"],
            "poll"
        );
        assert!(!evidence.to_string().contains("private-"));
        assert_eq!(captures, original);
    }

    #[test]
    fn labels_cannot_replace_missing_resume_failure_or_async_result_evidence() {
        let mut captures = fixture();
        captures[8]["lifecycleEvent"]["source_event"]["source"] = json!("startup");
        assert!(inspect(&captures)["resume"].is_null());
        let mut captures = fixture();
        captures[3]["toolExecution"]["process_outcome"]["exit_code"] = json!(0);
        captures[3]["toolExecution"]["process_outcome"]["success"] = json!(true);
        assert!(inspect(&captures)["failed_tool_process"].is_null());
        for field in ["session", "sequence", "namespace", "truncated", "turn"] {
            let mut captures = fixture();
            match field {
                "session" => captures[5]["toolExecution"]["arguments"]["session_id"] = json!(999),
                "sequence" => captures[5]["toolExecution"]["tool_result_seq"] = json!(1),
                "namespace" => captures[4]["toolExecution"]["runtime_namespace"] = json!("client"),
                "truncated" => captures[4]["toolExecution"]["output_truncated"] = json!(true),
                "turn" => captures[5]["traceContext"]["turn_id"] = json!("t2"),
                _ => unreachable!(),
            }
            assert!(
                inspect(&captures)["delayed_write_stdin"].is_null(),
                "{field}"
            );
        }
    }

    #[test]
    fn reused_process_ids_and_contradictory_duplicate_calls_do_not_join() {
        for same_call in [false, true] {
            let mut captures = fixture();
            let mut second = captures[4].clone();
            second["captureId"] = json!("second-launch");
            second["toolExecution"]["tool_result_seq"] = json!(4);
            if !same_call {
                second["toolExecution"]["call_id"] = json!("second-launch");
            }
            captures.insert(5, second);
            assert!(inspect(&captures)["delayed_write_stdin"].is_null());
        }
    }
}
