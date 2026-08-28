use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::LazyLock;

pub const CAPTURE_SCHEMA_VERSION: &str = "chiptrace.capture.v1";

static CAPTURE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^cap-[A-Za-z0-9._:-]+$").unwrap());

static SENSITIVE_HEADERS: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    BTreeSet::from([
        "api-key",
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    ])
});

#[derive(Debug, Clone)]
pub struct CaptureRecord {
    pub capture_id: String,
    pub canonical: Vec<u8>,
    pub sha256: String,
    pub received_at: Option<String>,
    pub model: Option<String>,
}

pub fn normalize_capture(raw: &[u8], max_bytes: usize) -> Result<CaptureRecord> {
    if raw.len() > max_bytes {
        bail!("capture envelope exceeds {max_bytes} bytes");
    }
    let mut value: Value = serde_json::from_slice(raw)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("capture envelope must be a JSON object"))?;
    let capture_id = object
        .get("captureId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("captureId is required"))?;
    if capture_id.len() > 256 || !CAPTURE_ID.is_match(capture_id) {
        bail!("captureId must match cap-[A-Za-z0-9._:-]+ and be <= 256 bytes");
    }
    let capture_id = capture_id.to_owned();
    validate_optional_string(object, "sourceNamespace")?;
    validate_optional_string(object, "receivedAt")?;
    validate_optional_string(object, "startedAt")?;
    validate_optional_string(object, "finishedAt")?;
    for field in ["requestHeaders", "responseHeaders"] {
        if object
            .get(field)
            .is_some_and(|value| !value.is_null() && !value.is_object())
        {
            bail!("{field} must be an object or null");
        }
    }
    validate_response_status(object.get("responseStatus"))?;
    if object
        .get("traceContext")
        .is_some_and(|value| !value.is_null() && !value.is_object())
    {
        bail!("traceContext must be an object or null");
    }
    if object.get("observedLifecycleEvents").is_some_and(|value| {
        !value.is_null()
            && value.as_array().is_none_or(|events| {
                events
                    .iter()
                    .any(|event| event.as_str().is_none_or(str::is_empty))
            })
    }) {
        bail!("observedLifecycleEvents must contain non-empty strings");
    }
    if object
        .get("evaluationEvidence")
        .or_else(|| object.get("evaluation_evidence"))
        .is_some_and(|value| {
            !value.is_null()
                && value
                    .as_array()
                    .is_none_or(|items| items.iter().any(|item| !item.is_object()))
        })
    {
        bail!("evaluationEvidence must contain JSON objects");
    }

    normalize_body_fields(object)?;
    let redacted = sanitize_headers(object);
    object.insert(
        "version".to_owned(),
        Value::String(CAPTURE_SCHEMA_VERSION.to_owned()),
    );
    object.insert(
        "redactedHeaders".to_owned(),
        Value::Array(redacted.into_iter().map(Value::String).collect()),
    );
    object
        .entry("traceContext".to_owned())
        .or_insert_with(|| json!({}));
    object
        .entry("observedLifecycleEvents".to_owned())
        .or_insert_with(|| json!([]));
    object
        .entry("requestTruncated".to_owned())
        .or_insert(Value::Bool(false));
    object
        .entry("responseTruncated".to_owned())
        .or_insert(Value::Bool(false));
    object
        .entry("stream".to_owned())
        .or_insert(Value::Bool(false));
    object
        .entry("captureError".to_owned())
        .or_insert(Value::Null);

    let received_at = ["receivedAt", "finishedAt", "startedAt"]
        .into_iter()
        .find_map(|field| {
            object
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        });
    if object.get("receivedAt").is_none_or(Value::is_null) {
        object.insert(
            "receivedAt".to_owned(),
            received_at
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
    }
    let model = extract_body(object.get("requestBody"))
        .and_then(Value::as_object)
        .and_then(|body| body.get("model"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let canonical = serde_json::to_vec(&value)?;
    if canonical.len() > max_bytes {
        bail!("normalized capture envelope exceeds {max_bytes} bytes");
    }
    let sha256 = hex::encode(Sha256::digest(&canonical));
    Ok(CaptureRecord {
        capture_id,
        canonical,
        sha256,
        received_at,
        model,
    })
}

pub fn normalize_capture_batch(
    raw: &[u8],
    max_envelope_bytes: usize,
    max_records: usize,
) -> Result<Vec<CaptureRecord>> {
    if max_records == 0 {
        bail!("batch record limit must be positive");
    }
    let mut records = Vec::new();
    for (index, line) in raw.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records.len() >= max_records {
            bail!("batch contains more than {max_records} records");
        }
        records.push(
            normalize_capture(line, max_envelope_bytes)
                .with_context(|| format!("invalid capture at NDJSON line {}", index + 1))?,
        );
    }
    if records.is_empty() {
        bail!("capture batch is empty");
    }
    Ok(records)
}

pub fn validate_stored_capture(raw: &[u8]) -> Result<CaptureRecord> {
    let value: Value = serde_json::from_slice(raw)?;
    // Run the current structural validator, but retain the exact historical
    // bytes. WAL locators and hashes must never change during migration.
    let _ = normalize_capture(raw, raw.len().saturating_add(1024 * 1024))?;
    let capture_id = value
        .get("captureId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("captureId is required"))?
        .to_owned();
    let received_at = ["receivedAt", "finishedAt", "startedAt"]
        .into_iter()
        .find_map(|field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
                .map(str::to_owned)
        });
    let model = extract_body(value.get("requestBody"))
        .and_then(Value::as_object)
        .and_then(|body| body.get("model"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(CaptureRecord {
        capture_id,
        canonical: raw.to_vec(),
        sha256: hex::encode(Sha256::digest(raw)),
        received_at,
        model,
    })
}

pub fn extract_body(value: Option<&Value>) -> Option<&Value> {
    let value = value?;
    match value.get("kind").and_then(Value::as_str) {
        Some("json" | "text" | "binary" | "sse") => value.get("value"),
        _ => Some(value),
    }
}

fn normalize_body_fields(object: &mut Map<String, Value>) -> Result<()> {
    for (text_field, body_field, bytes_field, sha_field) in [
        (
            "requestBodyText",
            "requestBody",
            "requestBytesCaptured",
            "requestBodySha256",
        ),
        (
            "responseBodyText",
            "responseBody",
            "responseBytesCaptured",
            "responseBodySha256",
        ),
    ] {
        if !object.contains_key(text_field) {
            continue;
        }
        let text = match object.remove(text_field).unwrap_or(Value::Null) {
            Value::Null => String::new(),
            Value::String(text) => text,
            _ => bail!("{text_field} must be a string or null"),
        };
        let body = match serde_json::from_str::<Value>(&text) {
            Ok(value) => json!({"kind": "json", "value": value}),
            Err(_) => json!({"kind": "text", "value": text}),
        };
        let bytes = text.len() as u64;
        let digest = hex::encode(Sha256::digest(text.as_bytes()));
        object.insert(body_field.to_owned(), body);
        object
            .entry(bytes_field.to_owned())
            .or_insert_with(|| Value::from(bytes));
        object.insert(sha_field.to_owned(), Value::String(digest));
    }
    Ok(())
}

fn sanitize_headers(object: &mut Map<String, Value>) -> BTreeSet<String> {
    let mut redacted = BTreeSet::new();
    for field in ["requestHeaders", "responseHeaders"] {
        let Some(headers) = object.get_mut(field).and_then(Value::as_object_mut) else {
            object.insert(field.to_owned(), json!({}));
            continue;
        };
        let names: Vec<String> = headers
            .keys()
            .filter(|name| SENSITIVE_HEADERS.contains(name.to_ascii_lowercase().as_str()))
            .cloned()
            .collect();
        for name in names {
            headers.remove(&name);
            redacted.insert(name.to_ascii_lowercase());
        }
    }
    if let Some(existing) = object.get("redactedHeaders").and_then(Value::as_array) {
        redacted.extend(existing.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    redacted
}

fn validate_optional_string(object: &Map<String, Value>, field: &str) -> Result<()> {
    if object
        .get(field)
        .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        bail!("{field} must be a string or null");
    }
    Ok(())
}

fn validate_response_status(value: Option<&Value>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let status = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .ok_or_else(|| anyhow::anyhow!("responseStatus must be an integer or null"))?;
    if !(100..=599).contains(&status) {
        bail!("responseStatus must be between 100 and 599");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_legacy_text_body_and_redacts_credentials() {
        let raw = br#"{
          "captureId":"cap-1",
          "requestHeaders":{"Authorization":"secret","x-id":"keep"},
          "requestBodyText":"{\"model\":\"gpt-5.6-sol\"}",
          "responseBodyText":"data: done",
          "responseStatus":500
        }"#;
        let record = normalize_capture(raw, 1024 * 1024).unwrap();
        let value: Value = serde_json::from_slice(&record.canonical).unwrap();
        assert_eq!(record.model.as_deref(), Some("gpt-5.6-sol"));
        assert!(value["requestHeaders"].get("Authorization").is_none());
        assert_eq!(value["requestHeaders"]["x-id"], "keep");
        assert_eq!(value["responseStatus"], 500);
    }

    #[test]
    fn accepts_failure_cancel_and_retry_evidence_without_filtering() {
        let value = json!({
            "captureId":"cap-failed",
            "responseStatus":503,
            "captureError":"upstream cancelled",
            "observedLifecycleEvents":["retry","cancel"]
        });
        let record = normalize_capture(&serde_json::to_vec(&value).unwrap(), 1024).unwrap();
        let normalized: Value = serde_json::from_slice(&record.canonical).unwrap();
        assert_eq!(normalized["captureError"], "upstream cancelled");
        assert_eq!(
            normalized["observedLifecycleEvents"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn historical_wal_bytes_keep_their_original_hash() {
        let raw =
            br#"{"version":"full-trace-spool-v3","captureId":"cap-old","responseStatus":200}"#;
        let record = validate_stored_capture(raw).unwrap();
        assert_eq!(record.canonical, raw);
        assert_eq!(record.sha256, hex::encode(Sha256::digest(raw)));
    }

    #[test]
    fn captured_body_wrappers_are_unwrapped_for_assembly() {
        for kind in ["json", "text", "binary", "sse"] {
            let value = json!({"kind": kind, "value": "payload"});
            assert_eq!(extract_body(Some(&value)), Some(&json!("payload")));
        }
        let native = json!({"model": "gpt-5.6-sol"});
        assert_eq!(extract_body(Some(&native)), Some(&native));
    }
}
