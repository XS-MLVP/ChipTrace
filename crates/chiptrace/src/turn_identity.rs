//! Exact native Turn attribution for OTLP records. Never join by time or position.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type NativeTurn = (String, String);
type SpanKey = (String, String);
const SESSION_ATTRIBUTES: &[&str] = &[
    "conversation.id",
    "session.id",
    "session_id",
    "conversation_id",
    "codex.session_id",
];
const TURN_ATTRIBUTES: &[&str] = &["turn.id", "turn_id", "codex.turn_id"];
const ROOT_TURN_ATTRIBUTES: &[&str] = &["root_turn.id", "root_turn_id", "codex.root_turn_id"];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ScopeKind {
    Process,
    Session,
    Turn,
}

/// A source-declared boundary, resolved only through an exact Span parent chain.
/// A Session boundary without its native identity remains unresolved.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SourceScope {
    Process,
    Session(Option<String>),
    Turn,
}

#[derive(Default)]
struct TraceScope {
    sessions: BTreeSet<String>,
    turns: BTreeSet<String>,
    process: bool,
}

#[derive(Default)]
struct SpanScope {
    sessions: BTreeSet<String>,
    turns: BTreeSet<String>,
    parents: BTreeSet<SpanKey>,
    kinds: BTreeSet<ScopeKind>,
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
                        process: scope.process,
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
                        kinds: scope.kinds.clone(),
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
        self.observe(session, turn, trace, span, None, None);
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
                None,
            );
        }
        visit_otlp(capture, |_, record, attributes| {
            let session = session_attribute(&attributes)?;
            let turn = turn_attribute(&attributes)?;
            let trace = hex_id(record.get("traceId"), 32);
            let span = hex_id(record.get("spanId"), 16);
            let parent = hex_id(record.get("parentSpanId"), 16);
            let kind = source_scope_attribute(&attributes)?;
            self.observe(session, turn, trace, span, parent, kind);
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
        kind: Option<ScopeKind>,
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
            if kind == Some(ScopeKind::Process) {
                scope.process = true;
            }
            if let Some(span) =
                span.filter(|_| self.track_parents || turn.is_some() || kind.is_some())
            {
                let scope = self.spans.entry((trace.clone(), span)).or_default();
                scope.sessions.extend(session);
                scope.turns.extend(turn);
                scope.parents.extend(parent.map(|parent| (trace, parent)));
                scope.kinds.extend(kind);
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
        validate_span_scope(scope)?;
        let mut candidates = self.candidates(&scope.sessions, &scope.turns);
        if candidates.is_empty() && scope.turns.is_empty() && scope.kinds.is_empty() {
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

    fn span_source_scope(&self, key: SpanKey) -> Result<Option<SourceScope>> {
        let mut key = Some(key);
        let mut visiting = BTreeSet::new();
        let mut nearest_boundary = None;
        let mut nearest_session = None;
        while let Some(current) = key {
            if !visiting.insert(current.clone()) {
                bail!("OTLP span ancestry contains a cycle");
            }
            let Some(scope) = self.spans.get(&current) else {
                break;
            };
            validate_span_scope(scope)?;
            if nearest_boundary.is_none() {
                nearest_boundary = scope
                    .kinds
                    .first()
                    .copied()
                    .or_else(|| (!scope.turns.is_empty()).then_some(ScopeKind::Turn));
                if nearest_boundary == Some(ScopeKind::Session) {
                    nearest_session = scope.sessions.first().cloned();
                }
            } else if nearest_boundary == Some(ScopeKind::Session)
                && nearest_session.is_none()
                && scope.kinds.first() == Some(&ScopeKind::Session)
            {
                // A child Session boundary may omit the repeated native ID;
                // inherit it from the nearest parent Session boundary only.
                nearest_session = scope.sessions.first().cloned();
            }
            // Keep validating the entire parent chain after finding a boundary,
            // including cycles and conflicts above a native Turn or child Session.
            key = scope.parents.first().cloned();
        }
        Ok(match nearest_boundary {
            Some(ScopeKind::Process) => Some(SourceScope::Process),
            Some(ScopeKind::Session) => Some(SourceScope::Session(nearest_session)),
            Some(ScopeKind::Turn) => Some(SourceScope::Turn),
            None => None,
        })
    }

    pub(crate) fn source_scope(
        &self,
        record: &Value,
        attributes: &BTreeMap<String, String>,
    ) -> Result<Option<SourceScope>> {
        let inherited = match (
            hex_id(record.get("traceId"), 32),
            hex_id(record.get("spanId"), 16),
        ) {
            (Some(trace), Some(span)) => self.span_source_scope((trace, span))?,
            _ => None,
        };
        let session = session_attribute(attributes)?;
        let turn = turn_attribute(attributes)?;
        match source_scope_attribute(attributes)? {
            Some(ScopeKind::Process) => {
                if session.is_some()
                    || turn.is_some()
                    || matches!(inherited, Some(SourceScope::Session(_) | SourceScope::Turn))
                {
                    bail!("OTLP Process scope conflicts with native Session or Turn context");
                }
                Ok(Some(SourceScope::Process))
            }
            Some(ScopeKind::Session) => {
                if turn.is_some()
                    || matches!(inherited, Some(SourceScope::Process | SourceScope::Turn))
                {
                    bail!("OTLP Session scope conflicts with native Turn context");
                }
                if let Some(SourceScope::Session(Some(parent))) = &inherited
                    && session.as_ref().is_some_and(|s| s != parent)
                {
                    bail!("OTLP explicit Session conflicts with inherited source scope");
                }
                Ok(Some(SourceScope::Session(session)))
            }
            Some(ScopeKind::Turn) => {
                if matches!(
                    inherited,
                    Some(SourceScope::Process | SourceScope::Session(_))
                ) {
                    bail!("OTLP Turn scope conflicts with inherited Process or Session context");
                }
                Ok(Some(SourceScope::Turn))
            }
            None if turn.is_some() => {
                if inherited == Some(SourceScope::Process) {
                    bail!("OTLP native Turn identity conflicts with inherited Process context");
                }
                Ok(Some(SourceScope::Turn))
            }
            None => {
                if inherited == Some(SourceScope::Process) && (session.is_some() || turn.is_some())
                {
                    bail!("OTLP native identity conflicts with inherited Process context");
                }
                if let Some(SourceScope::Session(Some(parent))) = &inherited
                    && session.as_ref().is_some_and(|s| s != parent)
                {
                    bail!("OTLP explicit Session conflicts with inherited source scope");
                }
                Ok(inherited)
            }
        }
    }

    pub(crate) fn resolve(
        &self,
        record: &Value,
        attributes: &BTreeMap<String, String>,
    ) -> Result<Option<NativeTurn>> {
        let session = session_attribute(attributes)?;
        let turn = turn_attribute(attributes)?;
        let source_scope = self.source_scope(record, attributes)?;
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
        // Explicit boundaries cannot borrow the sole Turn on a shared Trace.
        // An unbound Turn also cannot inherit a previous Turn across its boundary.
        if source_scope.is_some() && span_matches.is_empty() && turn.is_none() {
            return Ok(None);
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

    pub(crate) fn capture_has_process_scope(&self, capture: &Value) -> Result<bool> {
        let mut process = false;
        visit_otlp(capture, |_, record, attributes| {
            process |= matches!(
                self.source_scope(record, &attributes)?,
                Some(SourceScope::Process)
            ) || hex_id(record.get("traceId"), 32)
                .and_then(|trace| self.traces.get(&trace))
                .is_some_and(|scope| scope.process);
            Ok(())
        })?;
        Ok(process)
    }

    pub(crate) fn capture_has_unknown_session(&self, capture: &Value) -> Result<bool> {
        let mut unknown = false;
        visit_otlp(capture, |_, record, attributes| {
            unknown |= self.record_sessions(record, &attributes)?.is_empty()
                && self.source_scope(record, &attributes)? != Some(SourceScope::Process);
            Ok(())
        })?;
        Ok(unknown)
    }

    /// Diagnostic categories only: none of these establish a Turn identity.
    pub(crate) fn unresolved_reason(
        &self,
        record: &Value,
        attributes: &BTreeMap<String, String>,
    ) -> Result<&'static str> {
        if turn_attribute(attributes)?.is_some_and(|turn| !self.native.contains_key(&turn)) {
            return Ok("unknown_turn_owner");
        }
        let Some(trace) = hex_id(record.get("traceId"), 32) else {
            return Ok("missing_trace_context");
        };
        let Some(scope) = self.traces.get(&trace) else {
            return Ok("unobserved_trace_context");
        };
        if scope.turns.is_empty() {
            return Ok("trace_without_native_turn");
        }
        if self.candidates(&scope.sessions, &scope.turns).len() > 1 {
            return Ok("ambiguous_turn_context");
        }
        Ok("unresolved_turn_context")
    }

    pub(crate) fn record_sessions(
        &self,
        record: &Value,
        attributes: &BTreeMap<String, String>,
    ) -> Result<BTreeSet<String>> {
        let mut sessions = BTreeSet::new();
        sessions.extend(session_attribute(attributes)?);
        match self.source_scope(record, attributes)? {
            Some(SourceScope::Process) => return Ok(BTreeSet::new()),
            Some(SourceScope::Session(session)) => {
                sessions.extend(session);
                return Ok(sessions);
            }
            Some(SourceScope::Turn) | None => {}
        }
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

fn validate_span_scope(scope: &SpanScope) -> Result<()> {
    if scope.parents.len() > 1 {
        bail!("one OTLP span has conflicting explicit parents");
    }
    if scope.sessions.len() > 1 || scope.turns.len() > 1 {
        bail!("one OTLP span has conflicting explicit native identities");
    }
    if scope.kinds.len() > 1 {
        bail!("one OTLP span has conflicting explicit source scopes");
    }
    if scope.kinds.contains(&ScopeKind::Process)
        && (!scope.sessions.is_empty() || !scope.turns.is_empty())
    {
        bail!("OTLP Process scope conflicts with native Session or Turn context");
    }
    if scope.kinds.contains(&ScopeKind::Session) && !scope.turns.is_empty() {
        bail!("OTLP Session scope conflicts with native Turn context");
    }
    Ok(())
}

fn source_scope_attribute(attributes: &BTreeMap<String, String>) -> Result<Option<ScopeKind>> {
    match attributes.get("codex.context_scope").map(String::as_str) {
        None | Some("") => Ok(None),
        Some("process") => Ok(Some(ScopeKind::Process)),
        Some("session") => Ok(Some(ScopeKind::Session)),
        Some("turn") => Ok(Some(ScopeKind::Turn)),
        Some(_) => bail!("OTLP has an unsupported explicit source scope"),
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

pub(crate) fn hex_id(value: Option<&Value>, size: usize) -> Option<String> {
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
    let explicit = unique_attribute(attributes, SESSION_ATTRIBUTES)?;
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
    let native = unique_attribute(attributes, TURN_ATTRIBUTES)?;
    Ok(native.or(unique_attribute(attributes, ROOT_TURN_ATTRIBUTES)?))
}

fn is_identity_attribute(key: &str) -> bool {
    SESSION_ATTRIBUTES.contains(&key)
        || TURN_ATTRIBUTES.contains(&key)
        || ROOT_TURN_ATTRIBUTES.contains(&key)
        || key == "thread_id"
}

fn is_lifecycle_attribute(key: &str) -> bool {
    matches!(key, "outcome" | "status" | "tool_status" | "toolStatus")
}

/// Apply the same native identity rules before deriving a log's owner.
/// Read only identity scalars, avoiding copies of tool output or log bodies.
/// Resource/scope/record precedence matches the full OTLP visitor below.
pub(crate) fn validate_otlp_identity_layers(layers: [Option<&Value>; 3]) -> Result<()> {
    let mut merged = BTreeMap::new();
    for layer in layers {
        validate_otlp_attributes(layer)?;
        for attribute in layer.and_then(Value::as_array).into_iter().flatten() {
            let Some(key) = attribute.get("key").and_then(Value::as_str) else {
                continue;
            };
            if is_identity_attribute(key)
                && let Some(value) = attribute.get("value").and_then(attribute_text)
            {
                merged.insert(key.to_owned(), value);
            }
        }
    }
    session_attribute(&merged)?;
    turn_attribute(&merged)?;
    Ok(())
}

/// Metadata messages are optional, but a present non-message cannot be treated
/// as if it carried no attributes. Do not include the rejected value in errors.
pub(crate) fn otlp_message_attributes<'a>(
    message: Option<&'a Value>,
    field: &str,
) -> Result<Option<&'a Value>> {
    match message {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(fields)) => Ok(fields.get("attributes")),
        Some(_) => bail!("OTLP {field} must be an object"),
    }
}

/// Native tracing emits both OS thread numbers and legacy Session UUIDs as
/// thread.id, sometimes in the same list. Retain all of them in Raw only;
/// none may enter the interpreted map or supply a native Session identity.
pub(crate) fn otlp_attribute_key(attribute: &Value) -> Option<&str> {
    attribute
        .get("key")
        .and_then(Value::as_str)
        .filter(|key| *key != "thread.id")
}

pub(crate) fn validate_otlp_attributes(value: Option<&Value>) -> Result<()> {
    validate_otlp_attributes_mode(value, false, false)
}

fn validate_otlp_attributes_mode(
    value: Option<&Value>,
    allow_trace_code_metadata_duplicates: bool,
    allow_known_trace_lifecycle_duplicates: bool,
) -> Result<()> {
    let mut attribute_values = BTreeMap::new();
    for (index, attribute) in optional_otlp_array(value, "attributes")?.iter().enumerate() {
        if !attribute.is_object() {
            bail!("OTLP attributes[{index}] must be an object");
        }
        let Some(key) = otlp_attribute_key(attribute) else {
            continue;
        };
        let value = attribute.get("value");
        // Check the original AnyValue before scalar parsing or map insertion:
        // a duplicate must not erase identity, tool output, success or truncation
        // evidence, including a missing versus populated value. Borrow values
        // so this check does not copy payloads. Resource/scope/record remain
        // separate lists with their existing precedence.
        if let Some((previous_index, previous)) = attribute_values.insert(key, (index, value))
            && previous != value
        {
            // Some OTLP trace exporters repeat source-code location metadata
            // while merging instrumentation scopes. These fields cannot
            // establish a Session, Turn, tool owner, or lifecycle fact. Keep
            // the exact Raw, but ignore only this bounded trace-only case;
            // identity, tool, and unknown attribute conflicts remain strict.
            if allow_trace_code_metadata_duplicates && key.starts_with("code.") {
                continue;
            }
            // Stock Codex code-mode spans can receive two ordered outcome
            // updates while the handler is being interrupted and then
            // finalized. The span's status code remains successful and the
            // duplicate is limited to the known `interrupted -> completed`
            // or `interrupted -> failed` transition. Keep both values in Raw,
            // but do not turn this producer status update into a false
            // lifecycle quality error.
            if allow_known_trace_lifecycle_duplicates
                && key == "outcome"
                && known_code_mode_outcome_update(previous, value)
            {
                continue;
            }
            // A repeated terminal outcome/status is a lifecycle conflict, not
            // an identity conflict. Keep the Raw span and reject derivation,
            // while exposing the distinction to the durable quality ledger.
            if is_lifecycle_attribute(key) {
                bail!("OTLP has conflicting duplicate lifecycle attribute {key:?}");
            }
            if is_identity_attribute(key) || matches!(key, "codex.context_scope" | "event.name") {
                bail!("OTLP has conflicting duplicate context attribute {key:?}");
            }
            // Arbitrary attribute names can contain private data too.
            bail!(
                "conflicting duplicate OTLP attribute at attributes[{previous_index}] and attributes[{index}]"
            );
        }
    }
    Ok(())
}

fn known_code_mode_outcome_update(previous: Option<&Value>, current: Option<&Value>) -> bool {
    let previous_interrupted = previous
        .and_then(|value| value.get("stringValue"))
        .and_then(Value::as_str)
        .is_some_and(|value| value == "interrupted");
    let current_terminal = current
        .and_then(|value| value.get("stringValue"))
        .and_then(Value::as_str)
        .is_some_and(|value| matches!(value, "completed" | "failed"));
    previous_interrupted && current_terminal
}

fn attributes_for_endpoint(
    endpoint: &str,
    value: Option<&Value>,
    record_name: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    validate_otlp_attributes_mode(
        value,
        endpoint == "otlp_traces",
        endpoint == "otlp_traces" && record_name == Some("code_mode.handler.execute"),
    )?;
    Ok(value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|attribute| {
            let key = otlp_attribute_key(attribute)?;
            let parsed = attribute.get("value").and_then(attribute_text)?;
            Some((key.to_owned(), parsed))
        })
        .collect())
}

fn attribute_text(value: &Value) -> Option<String> {
    let parsed = value.get("stringValue").or_else(|| value.get("intValue"))?;
    parsed
        .as_str()
        .map(str::to_owned)
        .or_else(|| parsed.as_i64().map(|n| n.to_string()))
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
    visit: impl FnMut(&'static str, &Value, BTreeMap<String, String>) -> Result<()>,
) -> Result<()> {
    let endpoint = match capture
        .pointer("/telemetryBatch/endpoint")
        .and_then(Value::as_str)
    {
        Some(endpoint @ ("otlp_logs" | "otlp_traces")) => endpoint,
        _ => return Ok(()),
    };
    let raw = raw_batch(capture)?;
    visit_otlp_envelope(endpoint, &raw, visit)
}

pub(crate) fn visit_otlp_envelope(
    endpoint: &str,
    raw: &Value,
    mut visit: impl FnMut(&'static str, &Value, BTreeMap<String, String>) -> Result<()>,
) -> Result<()> {
    let Some((source, resources, scopes, records)) = otlp_fields(endpoint) else {
        return Ok(());
    };
    // A malformed sibling must not disappear from the source audit merely
    // because filter_map/as_array can still traverse the well-shaped subset.
    validate_otlp_structure(endpoint, raw)?;
    for resource in raw
        .get(resources)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let resource_attributes = attributes_for_endpoint(
            endpoint,
            otlp_message_attributes(resource.get("resource"), "resource")?,
            None,
        )?;
        for scope in resource
            .get(scopes)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut scoped = resource_attributes.clone();
            scoped.extend(attributes_for_endpoint(
                endpoint,
                otlp_message_attributes(scope.get("scope"), "scope")?,
                None,
            )?);
            for record in scope
                .get(records)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let mut merged = scoped.clone();
                merged.extend(attributes_for_endpoint(
                    endpoint,
                    record.get("attributes"),
                    record.get("name").and_then(Value::as_str),
                )?);
                visit(source, record, merged)?;
            }
        }
    }
    Ok(())
}

fn otlp_fields(endpoint: &str) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    match endpoint {
        "otlp_logs" => Some(("otlp_logs", "resourceLogs", "scopeLogs", "logRecords")),
        "otlp_traces" => Some(("otlp_traces", "resourceSpans", "scopeSpans", "spans")),
        _ => None,
    }
}

fn optional_otlp_array<'a>(value: Option<&'a Value>, path: &str) -> Result<&'a [Value]> {
    match value {
        // Omitted repeated fields and protobuf JSON null both mean empty.
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => bail!("OTLP {path} must be an array"),
    }
}

/// Validate the message containers before counting or assigning any records.
/// Errors include only structural paths, never the rejected field's contents.
pub(crate) fn validate_otlp_structure(endpoint: &str, raw: &Value) -> Result<()> {
    let Some((_, resources, scopes, records)) = otlp_fields(endpoint) else {
        return Ok(());
    };
    let resources_array = raw
        .get(resources)
        .and_then(Value::as_array)
        .with_context(|| format!("OTLP body requires {resources} array"))?;
    for (resource_index, resource) in resources_array.iter().enumerate() {
        if !resource.is_object() {
            bail!("OTLP {resources}[{resource_index}] must be an object");
        }
        let scope_path = format!("{resources}[{resource_index}].{scopes}");
        for (scope_index, scope) in optional_otlp_array(resource.get(scopes), &scope_path)?
            .iter()
            .enumerate()
        {
            if !scope.is_object() {
                bail!("OTLP {scope_path}[{scope_index}] must be an object");
            }
            let record_path = format!("{scope_path}[{scope_index}].{records}");
            for (record_index, record) in optional_otlp_array(scope.get(records), &record_path)?
                .iter()
                .enumerate()
            {
                if !record.is_object() {
                    bail!("OTLP {record_path}[{record_index}] must be an object");
                }
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

    fn attributes_at_layer(endpoint: &str, layer: &str, attributes: Value) -> Value {
        let (resources, scopes, records) = match endpoint {
            "otlp_logs" => ("resourceLogs", "scopeLogs", "logRecords"),
            "otlp_traces" => ("resourceSpans", "scopeSpans", "spans"),
            _ => unreachable!(),
        };
        let mut record = json!({"name":"auth"});
        let mut scope = json!({});
        let mut resource = json!({});
        match layer {
            "resource" => resource["resource"] = json!({"attributes":attributes}),
            "scope" => scope["scope"] = json!({"attributes":attributes}),
            "record" => record["attributes"] = attributes,
            _ => unreachable!(),
        }
        scope[records] = json!([record]);
        resource[scopes] = json!([scope]);
        let mut raw = json!({});
        raw[resources] = json!([resource]);
        batch(endpoint, raw)
    }

    #[test]
    fn malformed_otlp_sibling_cannot_be_skipped_by_source_auditing() {
        for (endpoint, resources, scopes, records) in [
            ("otlp_logs", "resourceLogs", "scopeLogs", "logRecords"),
            ("otlp_traces", "resourceSpans", "scopeSpans", "spans"),
        ] {
            let private = json!({"private":"BODY_MUST_NOT_APPEAR_IN_DIAGNOSTICS"});
            for raw in [
                json!({}),
                json!({resources:private}),
                json!({resources:null}),
                json!({resources:[{scopes:[{records:[{}]}]},null]}),
                json!({resources:[{scopes:[{records:[{}]}]},{scopes:private}]}),
                json!({resources:[{scopes:[{records:[{}]},null]}]}),
                json!({resources:[{scopes:[{records:[{}]}]}, {scopes:[{records:private}]}]}),
                json!({resources:[{scopes:[{records:[{},null]}]}]}),
                json!({resources:[{scopes:[{records:[{},"BODY_MUST_NOT_APPEAR_IN_DIAGNOSTICS"]}]}]}),
            ] {
                let mut visited = 0;
                let error = visit_otlp_envelope(endpoint, &raw, |_, _, _| {
                    visited += 1;
                    Ok(())
                })
                .expect_err("source auditing must not accept only the well-shaped subset");
                assert_eq!(visited, 0);
                assert!(!error.to_string().contains("BODY_MUST"));
            }
        }
    }

    #[test]
    fn malformed_otlp_metadata_cannot_be_erased_before_source_auditing() {
        let private = "PRIVATE_MALFORMED_CONTEXT_MUST_NOT_APPEAR";
        for endpoint in ["otlp_logs", "otlp_traces"] {
            for layer in ["resource", "scope", "record"] {
                for malformed in [
                    json!({"private":private}),
                    json!(private),
                    json!(42),
                    json!([null]),
                    json!([private]),
                    json!([[]]),
                ] {
                    let capture = attributes_at_layer(endpoint, layer, malformed);
                    let error = visit_otlp(&capture, |_, _, _| Ok(()))
                        .expect_err("malformed metadata must not disappear as empty attributes");
                    assert!(error.to_string().contains("OTLP"));
                    assert!(!error.to_string().contains(private));
                }
            }
            let (_, resources, scopes, _) = otlp_fields(endpoint).unwrap();
            for layer in ["resource", "scope"] {
                let mut raw =
                    raw_batch(&attributes_at_layer(endpoint, "record", json!([]))).unwrap();
                let message = if layer == "resource" {
                    &mut raw[resources][0]["resource"]
                } else {
                    &mut raw[resources][0][scopes][0]["scope"]
                };
                *message = json!([private]);
                let error = visit_otlp_envelope(endpoint, &raw, |_, _, _| Ok(()))
                    .expect_err("a malformed metadata message is not an omitted message");
                assert!(error.to_string().contains("OTLP"));
                assert!(!error.to_string().contains(private));
            }
        }
    }

    #[test]
    fn omitted_null_and_empty_metadata_remains_optional() {
        for endpoint in ["otlp_logs", "otlp_traces"] {
            for layer in ["resource", "scope", "record"] {
                for empty in [Value::Null, json!([])] {
                    let capture = attributes_at_layer(endpoint, layer, empty);
                    let mut visited = 0;
                    visit_otlp(&capture, |_, _, attributes| {
                        visited += 1;
                        assert!(attributes.is_empty());
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(visited, 1);
                }
            }
            let (_, resources, scopes, _) = otlp_fields(endpoint).unwrap();
            for empty in [Value::Null, json!({})] {
                let mut raw =
                    raw_batch(&attributes_at_layer(endpoint, "record", json!([]))).unwrap();
                raw[resources][0]["resource"] = empty.clone();
                raw[resources][0][scopes][0]["scope"] = empty;
                let mut visited = 0;
                visit_otlp_envelope(endpoint, &raw, |_, _, attributes| {
                    visited += 1;
                    assert!(attributes.is_empty());
                    Ok(())
                })
                .unwrap();
                assert_eq!(visited, 1);
            }
        }
    }

    #[test]
    fn omitted_null_and_empty_optional_otlp_arrays_do_not_invent_records() {
        for (endpoint, resources, scopes, records) in [
            ("otlp_logs", "resourceLogs", "scopeLogs", "logRecords"),
            ("otlp_traces", "resourceSpans", "scopeSpans", "spans"),
        ] {
            for raw in [
                json!({resources:[]}),
                json!({resources:[{},{scopes:null},{scopes:[]},
                    {scopes:[{},{records:null},{records:[]}]}]}),
            ] {
                let mut visited = 0;
                visit_otlp_envelope(endpoint, &raw, |_, _, _| {
                    visited += 1;
                    Ok(())
                })
                .unwrap();
                assert_eq!(visited, 0);
            }
        }
    }

    #[test]
    fn codex_root_turn_alias_preserves_fallback_and_conflict_checks() {
        let mut attributes =
            BTreeMap::from([("codex.root_turn_id".to_owned(), "root-turn".to_owned())]);
        assert_eq!(
            turn_attribute(&attributes).unwrap().as_deref(),
            Some("root-turn")
        );
        attributes.insert("turn.id".to_owned(), "native-turn".to_owned());
        assert_eq!(
            turn_attribute(&attributes).unwrap().as_deref(),
            Some("native-turn")
        );
        attributes.insert("root_turn.id".to_owned(), "root-turn".to_owned());
        assert!(turn_attribute(&attributes).is_ok());
        attributes.insert("root_turn_id".to_owned(), "PRIVATE_OTHER_ROOT".to_owned());
        let error = turn_attribute(&attributes).unwrap_err().to_string();
        assert!(error.contains("conflicting explicit identity aliases"));
        assert!(!error.contains("PRIVATE_"));
    }

    #[test]
    fn duplicate_context_conflicts_fail_before_attribute_maps_choose_an_owner() {
        let context_keys = [
            "conversation.id",
            "session.id",
            "session_id",
            "conversation_id",
            "codex.session_id",
            "thread_id",
            "turn.id",
            "turn_id",
            "codex.turn_id",
            "root_turn.id",
            "root_turn_id",
            "codex.root_turn_id",
            "codex.context_scope",
            "event.name",
        ];
        for endpoint in ["otlp_logs", "otlp_traces"] {
            for layer in ["resource", "scope", "record"] {
                for key in context_keys {
                    for values in [
                        [
                            json!({"stringValue":"private-first"}),
                            json!({"stringValue":"private-second"}),
                        ],
                        [
                            json!({"stringValue":"private-second"}),
                            json!({"stringValue":"private-first"}),
                        ],
                        [
                            json!({"boolValue":true}),
                            json!({"stringValue":"private-second"}),
                        ],
                        [
                            json!({"stringValue":"private-second"}),
                            json!({"boolValue":true}),
                        ],
                    ] {
                        let capture = attributes_at_layer(
                            endpoint,
                            layer,
                            json!([
                                {"key":key,"value":values[0]},
                                {"key":key,"value":values[1]}
                            ]),
                        );
                        let error = visit_otlp(&capture, |_, _, _| {
                            panic!("conflicting attributes must not reach the visitor")
                        })
                        .unwrap_err()
                        .to_string();
                        assert!(error.contains("conflicting duplicate context attribute"));
                        assert!(error.contains(key));
                        assert!(!error.contains("private-"));
                    }
                }
            }
        }
    }

    #[test]
    fn trace_code_metadata_duplicates_do_not_create_identity_quality_errors() {
        for key in ["code.file.path", "code.line.number"] {
            let capture = attributes_at_layer(
                "otlp_traces",
                "record",
                json!([
                    {"key":key,"value":{"stringValue":"first"}},
                    {"key":key,"value":{"stringValue":"second"}}
                ]),
            );
            let mut visited = 0;
            visit_otlp(&capture, |_, _, _| {
                visited += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(visited, 1, "{key}");

            let logs = attributes_at_layer(
                "otlp_logs",
                "record",
                json!([
                    {"key":key,"value":{"stringValue":"first"}},
                    {"key":key,"value":{"stringValue":"second"}}
                ]),
            );
            assert!(visit_otlp(&logs, |_, _, _| Ok(())).is_err(), "{key}");
        }
    }

    #[test]
    fn conflicting_duplicate_tool_attributes_fail_before_visitor_assignment() {
        for endpoint in ["otlp_logs", "otlp_traces"] {
            for layer in ["resource", "scope", "record"] {
                for key in [
                    "call_id",
                    "tool_name",
                    "tool_namespace",
                    "arguments",
                    "output",
                    "success",
                    "output_truncated",
                    // Real 0.157 producer traces emitted contradictory
                    // `outcome` values on one span. Keep this regression
                    // fail-closed until the producer emits one terminal fact.
                    "outcome",
                    "PRIVATE_ATTRIBUTE_KEY",
                ] {
                    for values in [
                        [
                            Some(json!({"stringValue":"PRIVATE_FIRST"})),
                            Some(json!({"stringValue":"PRIVATE_SECOND"})),
                        ],
                        [
                            Some(json!({"boolValue":true})),
                            Some(json!({"boolValue":false})),
                        ],
                        [None, Some(json!({"stringValue":"PRIVATE_SECOND"}))],
                        [Some(json!({"stringValue":"PRIVATE_FIRST"})), None],
                    ] {
                        let attributes = values
                            .into_iter()
                            .map(|value| {
                                let mut attribute = json!({"key":key});
                                if let Some(value) = value {
                                    attribute["value"] = value;
                                }
                                attribute
                            })
                            .collect::<Vec<_>>();
                        let capture = attributes_at_layer(endpoint, layer, json!(attributes));
                        let error = visit_otlp(&capture, |_, _, _| {
                            panic!("contradictory tool attributes must not reach the visitor")
                        })
                        .unwrap_err()
                        .to_string();
                        if key == "outcome" {
                            assert!(error.contains("conflicting duplicate lifecycle attribute"));
                        } else {
                            assert!(error.contains("conflicting duplicate OTLP attribute"));
                        }
                        assert!(
                            !error.contains("PRIVATE_"),
                            "only attribute positions may leave the validator"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn equal_context_duplicates_count_one_record_and_keep_attribute_layer_precedence() {
        for endpoint in ["otlp_logs", "otlp_traces"] {
            for layer in ["resource", "scope", "record"] {
                let capture = attributes_at_layer(
                    endpoint,
                    layer,
                    json!([
                        {"key":"conversation.id","value":{"stringValue":"s"}},
                        {"key":"conversation.id","value":{"stringValue":"s"}},
                        {"key":"turn.id","value":{"stringValue":"t"}},
                        {"key":"turn.id","value":{"stringValue":"t"}},
                        {"key":"call_id","value":{"stringValue":"call"}},
                        {"key":"call_id","value":{"stringValue":"call"}},
                        {"key":"success","value":{"boolValue":false}},
                        {"key":"success","value":{"boolValue":false}},
                        {"key":"unset"},
                        {"key":"unset"}
                    ]),
                );
                let mut observed = 0;
                visit_otlp(&capture, |_, _, attributes| {
                    observed += 1;
                    assert_eq!(session_attribute(&attributes)?.as_deref(), Some("s"));
                    assert_eq!(turn_attribute(&attributes)?.as_deref(), Some("t"));
                    assert_eq!(attributes.get("call_id").map(String::as_str), Some("call"));
                    Ok(())
                })
                .unwrap();
                assert_eq!(observed, 1);
            }
        }
        let capture = batch(
            "otlp_logs",
            json!({"resourceLogs":[{
                "resource":{"attributes":[{"key":"component","value":{"stringValue":"resource"}}]},
                "scopeLogs":[{
                    "scope":{"attributes":[{"key":"component","value":{"stringValue":"scope"}}]},
                    "logRecords":[{"attributes":[
                        {"key":"component","value":{"stringValue":"record"}},
                        {"key":"conversation.id","value":{"stringValue":"s"}},
                        {"key":"turn.id","value":{"stringValue":"t"}}
                    ]}]
                }]
            }]}),
        );
        visit_otlp(&capture, |_, _, attributes| {
            assert_eq!(
                attributes.get("component").map(String::as_str),
                Some("record")
            );
            assert_eq!(session_attribute(&attributes)?.as_deref(), Some("s"));
            assert_eq!(turn_attribute(&attributes)?.as_deref(), Some("t"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn overloaded_os_thread_attributes_stay_raw_without_supplying_a_session() {
        for endpoint in ["otlp_logs", "otlp_traces"] {
            for layer in ["resource", "scope", "record"] {
                for reverse in [false, true] {
                    let mut attributes = vec![
                        json!({"key":"thread.id","value":{"intValue":"3"}}),
                        json!({"key":"thread.id","value":{"stringValue":"00000000-0000-7000-8000-000000000001"}}),
                        json!({"key":"turn.id","value":{"stringValue":"t"}}),
                    ];
                    if reverse {
                        attributes.reverse();
                    }
                    let capture = attributes_at_layer(endpoint, layer, json!(attributes));
                    let before = capture.clone();
                    let mut observed = 0;
                    visit_otlp(&capture, |_, _, attributes| {
                        observed += 1;
                        assert!(!attributes.contains_key("thread.id"));
                        assert_eq!(session_attribute(&attributes)?, None);
                        assert_eq!(turn_attribute(&attributes)?.as_deref(), Some("t"));
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(observed, 1);
                    assert_eq!(capture, before);
                }
            }
        }
    }

    fn scoped_spans(spans: Value) -> Value {
        batch(
            "otlp_traces",
            json!({"resourceSpans":[{"scopeSpans":[{"spans":spans}]}]}),
        )
    }

    fn scope_attributes(session: Option<&str>, kind: &str) -> Value {
        let mut attributes =
            vec![json!({"key":"codex.context_scope","value":{"stringValue":kind}})];
        if let Some(session) = session {
            attributes.push(json!({"key":"conversation.id","value":{"stringValue":session}}));
        }
        json!(attributes)
    }

    #[test]
    fn explicit_session_chain_never_borrows_the_only_turn_on_its_trace() {
        let root = "3333333333333333";
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "t", PARENT)).unwrap();
        index.observe_capture(&scoped_spans(json!([
            {"traceId":TRACE,"spanId":root,"attributes":scope_attributes(Some("s"),"session")},
            {"name":"fs.get_metadata","traceId":TRACE,"spanId":CHILD,"parentSpanId":root},
            {"traceId":TRACE,"spanId":PARENT,"parentSpanId":root},
            {"name":"fs.get_metadata","traceId":TRACE,"spanId":"4444444444444444","parentSpanId":PARENT}
        ]))).unwrap();
        let init = json!({"traceId":TRACE,"spanId":CHILD});
        assert_eq!(index.resolve(&init, &BTreeMap::new()).unwrap(), None);
        assert_eq!(
            index.source_scope(&init, &BTreeMap::new()).unwrap(),
            Some(SourceScope::Session(Some("s".to_owned())))
        );
        assert_eq!(
            index.record_sessions(&init, &BTreeMap::new()).unwrap(),
            BTreeSet::from(["s".to_owned()])
        );
        let tool = json!({"traceId":TRACE,"spanId":"4444444444444444"});
        assert_eq!(
            index.resolve(&tool, &BTreeMap::new()).unwrap(),
            Some(("s".to_owned(), "t".to_owned()))
        );
        assert_eq!(
            index.source_scope(&tool, &BTreeMap::new()).unwrap(),
            Some(SourceScope::Turn)
        );
    }

    #[test]
    fn process_scope_never_borrows_a_native_turn_or_session() {
        let root = "7777777777777777";
        let child = "8888888888888888";
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "t", PARENT)).unwrap();
        index
            .observe_capture(&scoped_spans(json!([
                {"traceId":TRACE,"spanId":root,"attributes":scope_attributes(None,"process")},
                {"traceId":TRACE,"spanId":child,"parentSpanId":root,"name":"auth"}
            ])))
            .unwrap();
        let record = json!({"traceId":TRACE,"spanId":child});
        assert_eq!(
            index.source_scope(&record, &BTreeMap::new()).unwrap(),
            Some(SourceScope::Process)
        );
        assert!(
            index
                .record_sessions(&record, &BTreeMap::new())
                .unwrap()
                .is_empty()
        );
        assert_eq!(index.resolve(&record, &BTreeMap::new()).unwrap(), None);
        let invalid = BTreeMap::from([("conversation.id".to_owned(), "s".to_owned())]);
        assert!(index.source_scope(&record, &invalid).is_err());
    }

    #[test]
    fn turn_boundary_without_native_identity_cannot_borrow_an_ancestor_turn() {
        let mut index = ExactTurnIndex::for_turns();
        index
            .observe_capture(&wire("s", "previous", PARENT))
            .unwrap();
        index.observe_capture(&scoped_spans(json!([
            {"traceId":TRACE,"spanId":CHILD,"parentSpanId":PARENT,"attributes":scope_attributes(Some("s"),"turn")}
        ]))).unwrap();
        assert_eq!(
            index
                .resolve(&json!({"traceId":TRACE,"spanId":CHILD}), &BTreeMap::new())
                .unwrap(),
            None
        );
    }

    #[test]
    fn session_boundaries_keep_distinct_owners_on_a_shared_trace() {
        let mut index = ExactTurnIndex::for_turns();
        index
            .observe_capture(&wire("parent", "parent-turn", PARENT))
            .unwrap();
        index
            .observe_capture(&wire("child", "child-turn", CHILD))
            .unwrap();
        index.observe_capture(&scoped_spans(json!([
            {"traceId":TRACE,"spanId":"3333333333333333","parentSpanId":PARENT,"attributes":scope_attributes(Some("child"),"session")},
            {"traceId":TRACE,"spanId":"4444444444444444","parentSpanId":"3333333333333333"}
        ]))).unwrap();
        let child_init = json!({"traceId":TRACE,"spanId":"4444444444444444"});
        assert_eq!(index.resolve(&child_init, &BTreeMap::new()).unwrap(), None);
        assert_eq!(
            index
                .record_sessions(&child_init, &BTreeMap::new())
                .unwrap(),
            BTreeSet::from(["child".to_owned()])
        );
        let wrong_owner = BTreeMap::from([("conversation.id".to_owned(), "parent".to_owned())]);
        assert!(index.resolve(&child_init, &wrong_owner).is_err());
    }

    #[test]
    fn unresolved_session_boundary_remains_unknown_and_scope_conflicts_fail_closed() {
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "t", PARENT)).unwrap();
        index
            .observe_capture(&scoped_spans(json!([
                {"traceId":TRACE,"spanId":CHILD,"attributes":scope_attributes(None,"session")}
            ])))
            .unwrap();
        let record = json!({"traceId":TRACE,"spanId":CHILD});
        assert_eq!(index.resolve(&record, &BTreeMap::new()).unwrap(), None);
        assert!(
            index
                .record_sessions(&record, &BTreeMap::new())
                .unwrap()
                .is_empty()
        );
        let direct = BTreeMap::from([
            ("codex.context_scope".to_owned(), "session".to_owned()),
            ("conversation.id".to_owned(), "s".to_owned()),
        ]);
        assert!(
            index
                .resolve(&json!({"traceId":TRACE,"spanId":PARENT}), &direct)
                .is_err()
        );
        index
            .observe_capture(&scoped_spans(json!([
                {"traceId":TRACE,"spanId":CHILD,"attributes":scope_attributes(Some("s"),"turn")}
            ])))
            .unwrap();
        assert!(index.resolve(&record, &BTreeMap::new()).is_err());
        assert!(ExactTurnIndex::for_turns().observe_capture(&scoped_spans(json!([
            {"traceId":TRACE,"spanId":CHILD,"attributes":scope_attributes(Some("s"),"future-scope")}
        ]))).is_err());
    }

    #[test]
    fn child_session_scope_inherits_parent_identity_and_nearest_boundary_wins() {
        let root = "3333333333333333";
        let child = "4444444444444444";
        let grandchild = "5555555555555555";
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "t", PARENT)).unwrap();
        index
            .observe_capture(&scoped_spans(json!([
                {"traceId":TRACE,"spanId":root,"attributes":scope_attributes(Some("s"),"session")},
                {"traceId":TRACE,"spanId":child,"parentSpanId":root,"attributes":scope_attributes(None,"session")},
                {"traceId":TRACE,"spanId":grandchild,"parentSpanId":child}
            ])))
            .unwrap();
        let record = json!({"traceId":TRACE,"spanId":grandchild});
        assert_eq!(
            index.source_scope(&record, &BTreeMap::new()).unwrap(),
            Some(SourceScope::Session(Some("s".to_owned())))
        );
        assert_eq!(
            index.record_sessions(&record, &BTreeMap::new()).unwrap(),
            BTreeSet::from(["s".to_owned()])
        );

        let other = "6666666666666666";
        index
            .observe_capture(&scoped_spans(json!([
                {"traceId":TRACE,"spanId":other,"parentSpanId":child,"attributes":scope_attributes(Some("other"),"session")}
            ])))
            .unwrap();
        assert_eq!(
            index
                .source_scope(&json!({"traceId":TRACE,"spanId":other}), &BTreeMap::new())
                .unwrap(),
            Some(SourceScope::Session(Some("other".to_owned())))
        );
    }

    #[test]
    fn explicit_scope_or_native_identity_does_not_hide_parent_cycles() {
        let mut index = ExactTurnIndex::for_turns();
        index.observe_capture(&wire("s", "t", PARENT)).unwrap();
        index
            .observe_capture(&scoped_spans(json!([
                {"traceId":TRACE,"spanId":PARENT,"parentSpanId":CHILD},
                {"traceId":TRACE,"spanId":CHILD,"parentSpanId":PARENT}
            ])))
            .unwrap();
        assert!(
            index
                .resolve(&json!({"traceId":TRACE,"spanId":PARENT}), &BTreeMap::new())
                .is_err()
        );
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
        assert_eq!(
            index
                .resolve(
                    &json!({}),
                    &BTreeMap::from([("turn.id".to_owned(), "t".to_owned())])
                )
                .unwrap(),
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
