//! Exact native Turn attribution for OTLP records. Never join by time or position.

use anyhow::{Result, bail};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type NativeTurn = (String, String);
type SpanKey = (String, String);

#[derive(Default)]
struct TraceScope {
    sessions: BTreeSet<String>,
    turns: BTreeSet<String>,
}

#[derive(Default)]
struct SpanScope {
    sessions: BTreeSet<String>,
    turns: BTreeSet<String>,
    parents: BTreeSet<SpanKey>,
}

#[derive(Default)]
pub(crate) struct ExactTurnIndex {
    native: BTreeMap<String, BTreeSet<NativeTurn>>,
    traces: BTreeMap<String, TraceScope>,
    spans: BTreeMap<SpanKey, SpanScope>,
    // Whole-corpus Session selection only needs Trace and explicit Turn IDs;
    // retaining every diagnostic span there would inflate the selection heap.
    track_parents: bool,
}

impl ExactTurnIndex {
    pub(crate) fn include_global_scopes(&mut self, global: &Self) {
        // Keep ambiguity discovered in the full Raw snapshot. A selected
        // Session must not become "unique" merely because other sessions were
        // removed from its payload projection.
        self.native = global.native.clone();
        self.traces = global
            .traces
            .iter()
            .map(|(id, scope)| {
                (
                    id.clone(),
                    TraceScope {
                        sessions: scope.sessions.clone(),
                        turns: scope.turns.clone(),
                    },
                )
            })
            .collect();
        self.spans = global
            .spans
            .iter()
            .map(|(id, scope)| {
                (
                    id.clone(),
                    SpanScope {
                        sessions: scope.sessions.clone(),
                        turns: scope.turns.clone(),
                        parents: scope.parents.clone(),
                    },
                )
            })
            .collect();
    }

    pub(crate) fn for_turns() -> Self {
        Self {
            track_parents: true,
            ..Self::default()
        }
    }

    pub(crate) fn observe_capture(&mut self, capture: &Value) -> Result<()> {
        let session = capture_session(capture);
        let turn = text(capture.pointer("/traceContext/turn_id"))
            .or_else(|| text(capture.pointer("/lifecycleEvent/source_event/turn_id")))
            .or_else(|| text(capture.pointer("/traceContext/root_turn_id")));
        let trace = hex_id(capture.pointer("/traceContext/trace_id"), 32);
        let span = hex_id(capture.pointer("/traceContext/parent_span_id"), 16);
        self.observe(session, turn, trace, span, None);
        if capture
            .pointer("/telemetryBatch/endpoint")
            .and_then(Value::as_str)
            == Some("codex_hook")
        {
            let raw = raw_batch(capture)?;
            self.observe(
                text(raw.get("session_id")),
                text(raw.get("turn_id")),
                None,
                None,
                None,
            );
        }
        visit_otlp(capture, |_, record, attributes| {
            let session = session_attribute(&attributes)?;
            let turn = turn_attribute(&attributes)?;
            let trace = hex_id(record.get("traceId"), 32);
            let span = hex_id(record.get("spanId"), 16);
            let parent = hex_id(record.get("parentSpanId"), 16);
            self.observe(session, turn, trace, span, parent);
            Ok(())
        })
    }

    fn observe(
        &mut self,
        session: Option<String>,
        turn: Option<String>,
        trace: Option<String>,
        span: Option<String>,
        parent: Option<String>,
    ) {
        if let (Some(s), Some(t)) = (&session, &turn) {
            self.native
                .entry(t.clone())
                .or_default()
                .insert((s.clone(), t.clone()));
        }
        if let Some(trace) = trace {
            let scope = self.traces.entry(trace.clone()).or_default();
            scope.sessions.extend(session.clone());
            scope.turns.extend(turn.clone());
            if let Some(span) = span.filter(|_| self.track_parents || turn.is_some()) {
                let scope = self.spans.entry((trace.clone(), span)).or_default();
                scope.sessions.extend(session);
                scope.turns.extend(turn);
                scope.parents.extend(parent.map(|parent| (trace, parent)));
            }
        }
    }

    fn candidates(
        &self,
        sessions: &BTreeSet<String>,
        turns: &BTreeSet<String>,
    ) -> BTreeSet<NativeTurn> {
        turns
            .iter()
            .filter_map(|t| self.native.get(t))
            .flatten()
            .filter(|(s, _)| sessions.is_empty() || sessions.contains(s))
            .cloned()
            .collect()
    }

    fn span_candidates(
        &self,
        key: &SpanKey,
        visiting: &mut BTreeSet<SpanKey>,
    ) -> Result<BTreeSet<NativeTurn>> {
        let Some(scope) = self.spans.get(key) else {
            return Ok(BTreeSet::new());
        };
        if !visiting.insert(key.clone()) {
            bail!("OTLP span ancestry contains a cycle");
        }
        if scope.parents.len() > 1 {
            bail!("one OTLP span has conflicting explicit parents");
        }
        if scope.sessions.len() > 1 || scope.turns.len() > 1 {
            bail!("one OTLP span has conflicting explicit native identities");
        }
        let mut candidates = self.candidates(&scope.sessions, &scope.turns);
        if candidates.is_empty() && scope.turns.is_empty() {
            for parent in &scope.parents {
                candidates.extend(
                    self.span_candidates(parent, visiting)?
                        .into_iter()
                        .filter(|(s, _)| scope.sessions.is_empty() || scope.sessions.contains(s)),
                );
            }
        }
        visiting.remove(key);
        Ok(candidates)
    }

    pub(crate) fn resolve(
        &self,
        record: &Value,
        attributes: &BTreeMap<String, String>,
    ) -> Result<Option<NativeTurn>> {
        let session = session_attribute(attributes)?;
        let turn = turn_attribute(attributes)?;
        let trace = hex_id(record.get("traceId"), 32);
        let span = hex_id(record.get("spanId"), 16);
        let explicit = session
            .as_ref()
            .zip(turn.as_ref())
            .map(|(s, t)| (s.clone(), t.clone()));
        let span_matches = if let Some(key) = trace.as_ref().zip(span.as_ref()) {
            self.span_candidates(&(key.0.clone(), key.1.clone()), &mut BTreeSet::new())?
        } else {
            BTreeSet::new()
        };
        if span_matches.len() == 1 {
            let matched = span_matches.first().unwrap();
            if session.as_ref().is_some_and(|s| s != &matched.0)
                || turn.as_ref().is_some_and(|t| t != &matched.1)
            {
                bail!("OTLP explicit identity conflicts with its exact Span context");
            }
            return Ok(Some(matched.clone()));
        }
        if let Some(explicit) = explicit {
            return Ok(Some(explicit));
        }
        let candidates = if !span_matches.is_empty() {
            span_matches
        } else if let Some(scope) = trace.as_ref().and_then(|trace| self.traces.get(trace)) {
            self.candidates(&scope.sessions, &scope.turns)
        } else if let Some(turn) = &turn {
            self.native.get(turn).cloned().unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        let matched: BTreeSet<_> = candidates
            .into_iter()
            .filter(|(s, t)| {
                session.as_ref().is_none_or(|expected| expected == s)
                    && turn.as_ref().is_none_or(|expected| expected == t)
            })
            .collect();
        Ok((matched.len() == 1).then(|| matched.into_iter().next().unwrap()))
    }

    pub(crate) fn capture_sessions(&self, capture: &Value) -> Result<BTreeSet<String>> {
        let mut sessions = BTreeSet::new();
        sessions.extend(capture_session(capture));
        visit_otlp(capture, |_, record, attributes| {
            sessions.extend(self.record_sessions(record, &attributes)?);
            Ok(())
        })?;
        Ok(sessions)
    }

    pub(crate) fn record_sessions(
        &self,
        record: &Value,
        attributes: &BTreeMap<String, String>,
    ) -> Result<BTreeSet<String>> {
        let mut sessions = BTreeSet::new();
        sessions.extend(session_attribute(attributes)?);
        if let Some(turn) = turn_attribute(attributes)?.and_then(|t| self.native.get(&t)) {
            sessions.extend(turn.iter().map(|(s, _)| s.clone()));
        }
        if let Some(trace) = hex_id(record.get("traceId"), 32).and_then(|t| self.traces.get(&t)) {
            sessions.extend(trace.sessions.iter().cloned());
            sessions.extend(
                self.candidates(&BTreeSet::new(), &trace.turns)
                    .into_iter()
                    .map(|(s, _)| s),
            );
        }
        Ok(sessions)
    }
}

pub(crate) fn capture_session(capture: &Value) -> Option<String> {
    text(capture.pointer("/traceContext/source_session_id"))
        .or_else(|| text(capture.pointer("/lifecycleEvent/source_event/session_id")))
        .or_else(|| text(capture.pointer("/traceContext/session_id")))
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .map(str::to_owned)
}

fn hex_id(value: Option<&Value>, size: usize) -> Option<String> {
    text(value)
        .filter(|v| {
            v.len() == size
                && v.bytes().all(|b| b.is_ascii_hexdigit())
                && v.bytes().any(|b| b != b'0')
        })
        .map(|v| v.to_ascii_lowercase())
}

fn unique_attribute(
    attributes: &BTreeMap<String, String>,
    keys: &[&str],
) -> Result<Option<String>> {
    let values: BTreeSet<_> = keys
        .iter()
        .filter_map(|key| attributes.get(*key))
        .filter(|v| !v.trim().is_empty())
        .cloned()
        .collect();
    if values.len() > 1 {
        bail!("OTLP has conflicting explicit identity aliases: {keys:?}");
    }
    Ok(values.into_iter().next())
}

pub(crate) fn session_attribute(attributes: &BTreeMap<String, String>) -> Result<Option<String>> {
    // thread.id is an OS thread number in native tracing, not a Codex Session.
    let explicit = unique_attribute(
        attributes,
        &[
            "conversation.id",
            "session.id",
            "session_id",
            "conversation_id",
            "codex.session_id",
        ],
    )?;
    let native_thread = attributes.get("thread_id").filter(|id| {
        id.len() == 36
            && id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
    });
    if explicit
        .as_ref()
        .zip(native_thread)
        .is_some_and(|(s, t)| s != t)
    {
        bail!("OTLP native thread_id conflicts with its explicit Session");
    }
    Ok(explicit.or_else(|| native_thread.cloned()))
}

pub(crate) fn turn_attribute(attributes: &BTreeMap<String, String>) -> Result<Option<String>> {
    let native = unique_attribute(attributes, &["turn.id", "turn_id", "codex.turn_id"])?;
    Ok(native.or(unique_attribute(
        attributes,
        &["root_turn.id", "root_turn_id"],
    )?))
}

fn attributes(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| {
            let key = a.get("key")?.as_str()?;
            let value = a.get("value")?;
            let parsed = value.get("stringValue").or_else(|| value.get("intValue"))?;
            let parsed = parsed
                .as_str()
                .map(str::to_owned)
                .or_else(|| parsed.as_i64().map(|n| n.to_string()))?;
            Some((key.to_owned(), parsed))
        })
        .collect()
}

fn raw_batch(capture: &Value) -> Result<Value> {
    Ok(serde_json::from_str(
        capture
            .pointer("/telemetryBatch/raw_json")
            .and_then(Value::as_str)
            .unwrap_or("{}"),
    )?)
}

pub(crate) fn visit_otlp(
    capture: &Value,
    mut visit: impl FnMut(&'static str, &Value, BTreeMap<String, String>) -> Result<()>,
) -> Result<()> {
    let (source, resources, scopes, records) = match capture
        .pointer("/telemetryBatch/endpoint")
        .and_then(Value::as_str)
    {
        Some("otlp_logs") => ("otlp_logs", "resourceLogs", "scopeLogs", "logRecords"),
        Some("otlp_traces") => ("otlp_traces", "resourceSpans", "scopeSpans", "spans"),
        _ => return Ok(()),
    };
    let raw = raw_batch(capture)?;
    for resource in raw
        .get(resources)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let resource_attributes = attributes(resource.pointer("/resource/attributes"));
        for scope in resource
            .get(scopes)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut scoped = resource_attributes.clone();
            scoped.extend(attributes(scope.pointer("/scope/attributes")));
            for record in scope
                .get(records)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let mut merged = scoped.clone();
                merged.extend(attributes(record.get("attributes")));
                visit(source, record, merged)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TRACE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PARENT: &str = "1111111111111111";
    const CHILD: &str = "2222222222222222";

    fn wire(session: &str, turn: &str, span: &str) -> Value {
        json!({"recordType":"api_snapshot", "traceContext":{
            "session_id":session,"turn_id":turn,"trace_id":TRACE,"parent_span_id":span
        }})
    }

    fn batch(endpoint: &str, raw: Value) -> Value {
        json!({"recordType":"telemetry_batch","telemetryBatch":{
            "endpoint":endpoint,"raw_json":serde_json::to_string(&raw).unwrap()
        }})
    }

    #[test]
    fn native_otlp_logs_without_turn_attributes_join_exact_wire_context() {
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "t", PARENT)).unwrap();
        let log = json!({"traceId":TRACE,"spanId":PARENT});
        let attrs = BTreeMap::from([("conversation.id".to_owned(), "s".to_owned())]);
        assert_eq!(
            index.resolve(&log, &attrs).unwrap(),
            Some(("s".to_owned(), "t".to_owned()))
        );
        let traces = batch(
            "otlp_traces",
            json!({"resourceSpans":[{"scopeSpans":[{"spans":[{
                "name":"session_task.turn","traceId":TRACE,"spanId":CHILD,
                "attributes":[{"key":"turn.id","value":{"stringValue":"t"}}]
            }]}]}]}),
        );
        index.observe_capture(&traces).unwrap();
        assert!(index.capture_sessions(&traces).unwrap().contains("s"));
    }

    #[test]
    fn native_otlp_shared_trace_requires_specific_span_or_explicit_turn() {
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "first", PARENT)).unwrap();
        index
            .observe_capture(&wire("s", "second", "3333333333333333"))
            .unwrap();
        let traces = batch(
            "otlp_traces",
            json!({"resourceSpans":[{"scopeSpans":[{"spans":[{
                "name":"exec_command","traceId":TRACE,"spanId":CHILD,"parentSpanId":PARENT
            }]}]}]}),
        );
        index.observe_capture(&traces).unwrap();
        assert_eq!(
            index
                .resolve(&json!({"traceId":TRACE,"spanId":CHILD}), &BTreeMap::new())
                .unwrap(),
            Some(("s".to_owned(), "first".to_owned()))
        );
        assert_eq!(
            index
                .resolve(&json!({"traceId":TRACE}), &BTreeMap::new())
                .unwrap(),
            None
        );
    }

    #[test]
    fn conflicting_native_identities_on_one_span_cannot_be_overridden_by_a_log() {
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "first", PARENT)).unwrap();
        index.observe_capture(&wire("s", "second", PARENT)).unwrap();
        let attributes = BTreeMap::from([
            ("session.id".to_owned(), "s".to_owned()),
            ("turn.id".to_owned(), "first".to_owned()),
        ]);
        assert!(
            index
                .resolve(&json!({"traceId":TRACE,"spanId":PARENT}), &attributes)
                .is_err()
        );
    }

    #[test]
    fn native_otlp_zero_ids_and_session_only_logs_are_never_guessed() {
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "t", PARENT)).unwrap();
        let attrs = BTreeMap::from([("conversation.id".to_owned(), "s".to_owned())]);
        assert_eq!(index.resolve(&json!({"traceId":"00000000000000000000000000000000","spanId":"0000000000000000"}),&attrs).unwrap(),None);
        assert_eq!(
            index
                .resolve(&json!({"timeUnixNano":"123"}), &attrs)
                .unwrap(),
            None
        );
        assert_eq!(
            session_attribute(&BTreeMap::from([("thread.id".to_owned(), "3".to_owned())])).unwrap(),
            None
        );
    }

    #[test]
    fn native_otlp_conflicting_aliases_context_and_cycles_fail_closed() {
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "t", PARENT)).unwrap();
        let attrs = BTreeMap::from([("session.id".to_owned(), "other".to_owned())]);
        assert!(
            index
                .resolve(&json!({"traceId":TRACE,"spanId":PARENT}), &attrs)
                .is_err()
        );
        let attrs = BTreeMap::from([
            ("session.id".to_owned(), "s".to_owned()),
            ("conversation.id".to_owned(), "other".to_owned()),
        ]);
        assert!(index.resolve(&json!({}), &attrs).is_err());
        let traces = batch(
            "otlp_traces",
            json!({"resourceSpans":[{"scopeSpans":[{"spans":[
                {"traceId":TRACE,"spanId":"4444444444444444","parentSpanId":"5555555555555555"},
                {"traceId":TRACE,"spanId":"5555555555555555","parentSpanId":"4444444444444444"}
            ]}]}]}),
        );
        index.observe_capture(&traces).unwrap();
        assert!(
            index
                .resolve(
                    &json!({"traceId":TRACE,"spanId":"4444444444444444"}),
                    &BTreeMap::new()
                )
                .is_err()
        );
    }
}
