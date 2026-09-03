use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Default)]
pub(crate) struct StockSessionLineage {
    children: BTreeMap<String, ChildSession>,
}

#[derive(Debug, Clone)]
struct ChildSession {
    parent_session_id: String,
    root_turn_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct StockSessionSelection {
    root_session_id: String,
    members: BTreeMap<String, ChildSession>,
}

impl StockSessionLineage {
    pub(crate) fn observe(&mut self, capture: &Value) -> Result<()> {
        let event = capture.get("lifecycleEvent").and_then(Value::as_object);
        let event_type = event
            .and_then(|event| event.get("type"))
            .and_then(Value::as_str);
        if !matches!(event_type, Some("subagent_spawn" | "subagent_join")) {
            return Ok(());
        }

        let source = event
            .and_then(|event| event.get("source_event"))
            .and_then(Value::as_object);
        let trace = capture.get("traceContext").and_then(Value::as_object);
        let child_session_id = unique_identity(
            "subagent child Session",
            [
                source.and_then(|value| string(value, "agent_id")),
                source.and_then(|value| string(value, "agent_thread_id")),
                trace.and_then(|value| string(value, "agent_id")),
            ],
        )?
        .ok_or_else(|| anyhow::anyhow!("subagent lifecycle event has no child Session identity"))?;
        let parent_session_id = unique_identity(
            "subagent parent Session",
            [
                trace.and_then(|value| string(value, "session_id")),
                source.and_then(|value| string(value, "session_id")),
            ],
        )?
        .ok_or_else(|| {
            anyhow::anyhow!("subagent lifecycle event has no parent Session identity")
        })?;
        if child_session_id == parent_session_id {
            bail!("subagent lifecycle event links a Session to itself");
        }
        let root_turn_id = unique_identity(
            "subagent root turn",
            [
                trace.and_then(|value| string(value, "root_turn_id")),
                trace.and_then(|value| string(value, "turn_id")),
                source.and_then(|value| string(value, "turn_id")),
            ],
        )?;

        if let Some(existing) = self.children.get(&child_session_id) {
            if existing.parent_session_id != parent_session_id {
                bail!("subagent Session {child_session_id:?} has multiple explicit parents");
            }
            if existing.root_turn_id.is_some()
                && root_turn_id.is_some()
                && existing.root_turn_id != root_turn_id
            {
                bail!("subagent Session {child_session_id:?} has multiple explicit root turns");
            }
        }
        let entry = self
            .children
            .entry(child_session_id)
            .or_insert_with(|| ChildSession {
                parent_session_id,
                root_turn_id: None,
            });
        if entry.root_turn_id.is_none() {
            entry.root_turn_id = root_turn_id;
        }
        Ok(())
    }

    pub(crate) fn selection(&self, root_session_id: &str) -> Result<StockSessionSelection> {
        let mut members = BTreeMap::new();
        let mut queue = VecDeque::from([root_session_id.to_owned()]);
        let mut visited = BTreeSet::from([root_session_id.to_owned()]);
        while let Some(parent) = queue.pop_front() {
            for (child, lineage) in self
                .children
                .iter()
                .filter(|(_, lineage)| lineage.parent_session_id == parent)
            {
                if !visited.insert(child.clone()) {
                    bail!("subagent Session lineage contains a cycle at {child:?}");
                }
                members.insert(child.clone(), lineage.clone());
                queue.push_back(child.clone());
            }
        }
        Ok(StockSessionSelection {
            root_session_id: root_session_id.to_owned(),
            members,
        })
    }

    pub(crate) fn top_level_sessions(
        &self,
        available_sessions: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        available_sessions
            .iter()
            .filter(|session| !self.children.contains_key(*session))
            .cloned()
            .collect()
    }
}

impl StockSessionSelection {
    pub(crate) fn allows_session_id(&self, session_id: &str) -> bool {
        session_id == self.root_session_id || self.members.contains_key(session_id)
    }

    pub(crate) fn contains(&self, capture: &Value) -> bool {
        capture
            .pointer("/traceContext/session_id")
            .and_then(Value::as_str)
            .is_some_and(|session_id| self.allows_session_id(session_id))
    }

    /// Canonicalize only the derived projection. Raw Capture bytes remain
    /// immutable, while native child identities stay available for audit.
    pub(crate) fn canonicalize(&self, capture: &mut Value) -> Result<bool> {
        let Some(source_session_id) = capture
            .pointer("/traceContext/session_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Ok(false);
        };
        if source_session_id == self.root_session_id {
            return Ok(false);
        }
        let Some(lineage) = self.members.get(&source_session_id) else {
            return Ok(false);
        };
        let trace = capture
            .get_mut("traceContext")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| anyhow::anyhow!("selected child Capture has no traceContext object"))?;

        insert_consistent(trace, "source_session_id", &source_session_id)?;
        if let Some(source_conversation_id) = trace
            .get("conversation_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
        {
            insert_consistent(trace, "source_conversation_id", &source_conversation_id)?;
        }
        insert_consistent(trace, "root_session_id", &self.root_session_id)?;
        insert_consistent(trace, "parent_session_id", &lineage.parent_session_id)?;
        insert_consistent(trace, "agent_id", &source_session_id)?;
        if !trace.contains_key("thread_id") {
            trace.insert("thread_id".to_owned(), json!(source_session_id));
        }
        trace.insert("conversation_id".to_owned(), json!(self.root_session_id));
        if let Some(root_turn_id) = lineage.root_turn_id.as_deref() {
            insert_consistent(trace, "root_turn_id", root_turn_id)?;
        }
        trace.insert("session_id".to_owned(), json!(self.root_session_id));
        trace.insert(
            "session_lineage_evidence".to_owned(),
            json!("subagent_lifecycle"),
        );
        Ok(true)
    }
}

fn string<'a>(value: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn unique_identity<'a>(
    label: &str,
    values: impl IntoIterator<Item = Option<&'a str>>,
) -> Result<Option<String>> {
    let values: BTreeSet<String> = values.into_iter().flatten().map(str::to_owned).collect();
    if values.len() > 1 {
        bail!("{label} has conflicting explicit identities: {values:?}");
    }
    Ok(values.into_iter().next())
}

fn insert_consistent(trace: &mut Map<String, Value>, key: &str, expected: &str) -> Result<()> {
    if let Some(existing) = trace
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        if existing != expected {
            bail!("traceContext.{key} conflicts with explicit subagent lineage");
        }
        return Ok(());
    }
    trace.insert(key.to_owned(), json!(expected));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_subagent_lineage_selects_and_canonicalizes_child_capture() {
        let lifecycle = json!({
            "traceContext":{
                "session_id":"session-root","root_turn_id":"turn-child",
                "agent_id":"session-child"
            },
            "lifecycleEvent":{
                "type":"subagent_spawn",
                "source_event":{"session_id":"session-root","agent_id":"session-child","turn_id":"turn-child"}
            }
        });
        let mut child = json!({
            "traceContext":{
                "session_id":"session-child","thread_id":"session-child",
                "conversation_id":"session-child"
            }
        });
        let mut lineage = StockSessionLineage::default();
        lineage.observe(&lifecycle).unwrap();
        let selection = lineage.selection("session-root").unwrap();

        assert!(selection.contains(&child));
        assert!(selection.canonicalize(&mut child).unwrap());
        assert_eq!(child["traceContext"]["session_id"], "session-root");
        assert_eq!(child["traceContext"]["source_session_id"], "session-child");
        assert_eq!(child["traceContext"]["parent_session_id"], "session-root");
        assert_eq!(child["traceContext"]["root_turn_id"], "turn-child");
    }

    #[test]
    fn conflicting_subagent_parent_fails_closed() {
        let event = |parent: &str| {
            json!({
                "traceContext":{"session_id":parent,"agent_id":"session-child"},
                "lifecycleEvent":{
                    "type":"subagent_spawn",
                    "source_event":{"session_id":parent,"agent_id":"session-child"}
                }
            })
        };
        let mut lineage = StockSessionLineage::default();
        lineage.observe(&event("session-a")).unwrap();
        assert!(lineage.observe(&event("session-b")).is_err());
    }
}
