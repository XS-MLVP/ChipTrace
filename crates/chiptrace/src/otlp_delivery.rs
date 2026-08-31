use crate::jsonl::{open_jsonl_reader, sha256_file};
use crate::telemetry::{OtlpExportManifest, verify_otlp_export};
use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::write::GzEncoder;
use reqwest::{StatusCode, Url};
use serde::Serialize;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;

pub const OTLP_DELIVERY_SCHEMA_VERSION: &str = "chiptrace.otlp-delivery.v1";

#[derive(Debug, Clone)]
pub struct OtlpDeliveryConfig {
    pub projection: PathBuf,
    pub endpoint: String,
    pub public_key: String,
    pub secret_key: String,
    pub request_timeout: Duration,
    pub retry_max_times: usize,
    pub batch_spans: usize,
    pub max_batch_bytes: usize,
    pub allow_incomplete: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OtlpDeliveryResult {
    pub schema_version: String,
    pub endpoint: String,
    pub source_otlp_manifest_sha256: String,
    pub source_projection_manifest_sha256: String,
    pub source_delivery_ready: bool,
    pub spans: u64,
    pub batches: u64,
    pub attempts: u64,
    pub retries: u64,
    pub accepted: bool,
}

pub async fn send_otlp(config: OtlpDeliveryConfig) -> Result<OtlpDeliveryResult> {
    validate_config(&config)?;
    let projection = config.projection.canonicalize()?;
    let manifest = verify_otlp_export(&projection)?;
    if !manifest.source_delivery_ready && !config.allow_incomplete {
        bail!(
            "OTLP source is not delivery-ready; use --allow-incomplete only for an explicit observability projection"
        );
    }

    let records = read_records(&projection, &manifest)?;
    let batches = build_batches(&records, config.batch_spans, config.max_batch_bytes)?;
    let endpoint = validate_endpoint(&config.endpoint)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut attempts = 0_u64;
    for body in &batches {
        attempts = attempts.saturating_add(
            send_batch(
                &client,
                endpoint.clone(),
                &config.public_key,
                &config.secret_key,
                body,
                config.retry_max_times,
            )
            .await?,
        );
    }
    let batch_count = batches.len() as u64;
    Ok(OtlpDeliveryResult {
        schema_version: OTLP_DELIVERY_SCHEMA_VERSION.to_owned(),
        endpoint: endpoint.to_string(),
        source_otlp_manifest_sha256: sha256_file(&projection.join("manifest.json"))?,
        source_projection_manifest_sha256: manifest.source_projection_manifest_sha256,
        source_delivery_ready: manifest.source_delivery_ready,
        spans: records.len() as u64,
        batches: batch_count,
        attempts,
        retries: attempts.saturating_sub(batch_count),
        accepted: true,
    })
}

fn validate_config(config: &OtlpDeliveryConfig) -> Result<()> {
    if config.public_key.trim().is_empty() || config.secret_key.trim().is_empty() {
        bail!("LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be non-empty");
    }
    if config.retry_max_times < 20 {
        bail!("OTLP delivery requires at least 20 retry attempts");
    }
    if config.request_timeout.is_zero() {
        bail!("OTLP request timeout must be greater than zero");
    }
    if config.batch_spans == 0 || config.max_batch_bytes == 0 {
        bail!("OTLP batch limits must be greater than zero");
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<Url> {
    let endpoint = Url::parse(endpoint).context("parse OTLP endpoint")?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("OTLP endpoint must be an HTTP(S) URL without credentials, query, or fragment");
    }
    Ok(endpoint)
}

fn read_records(root: &std::path::Path, manifest: &OtlpExportManifest) -> Result<Vec<Value>> {
    let part = manifest
        .parts
        .first()
        .context("verified OTLP export has no data part")?;
    let mut reader = open_jsonl_reader(&root.join(&part.file))?;
    let mut line = Vec::new();
    let mut records = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        records.push(serde_json::from_slice(&line)?);
    }
    let expected = manifest.interactions.saturating_add(manifest.runtime_spans);
    if records.len() as u64 != expected {
        bail!(
            "OTLP delivery record count changed after verification: expected={expected}, actual={}",
            records.len()
        );
    }
    Ok(records)
}

fn build_batches(records: &[Value], max_spans: usize, max_bytes: usize) -> Result<Vec<Vec<u8>>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut estimated_bytes = envelope_overhead();
    for record in records {
        let resource_spans = record
            .get("resourceSpans")
            .and_then(Value::as_array)
            .context("verified OTLP record has no resourceSpans")?;
        if resource_spans.len() != 1 {
            bail!("each OTLP delivery record must contain exactly one resourceSpans entry");
        }
        let resource_span = resource_spans[0].clone();
        let item_bytes = serde_json::to_vec(&resource_span)?.len().saturating_add(1);
        if item_bytes.saturating_add(envelope_overhead()) > max_bytes {
            bail!("one OTLP span exceeds the configured maximum batch bytes");
        }
        if !current.is_empty()
            && (current.len() >= max_spans
                || estimated_bytes.saturating_add(item_bytes) > max_bytes)
        {
            batches.push(encode_batch(std::mem::take(&mut current), max_bytes)?);
            estimated_bytes = envelope_overhead();
        }
        estimated_bytes = estimated_bytes.saturating_add(item_bytes);
        current.push(resource_span);
    }
    if !current.is_empty() {
        batches.push(encode_batch(current, max_bytes)?);
    }
    Ok(batches)
}

fn envelope_overhead() -> usize {
    br#"{"resourceSpans":[]}"#.len()
}

fn encode_batch(resource_spans: Vec<Value>, max_bytes: usize) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(&json!({"resourceSpans": resource_spans}))?;
    if body.len() > max_bytes {
        bail!("OTLP batch exceeds the configured maximum batch bytes");
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&body)?;
    Ok(encoder.finish()?)
}

async fn send_batch(
    client: &reqwest::Client,
    endpoint: Url,
    public_key: &str,
    secret_key: &str,
    body: &[u8],
    retry_max_times: usize,
) -> Result<u64> {
    let mut last_error = String::new();
    for attempt in 1..=retry_max_times {
        let result = client
            .post(endpoint.clone())
            .basic_auth(public_key, Some(secret_key))
            .header("content-type", "application/json")
            .header("content-encoding", "gzip")
            .header("x-langfuse-sdk-name", "chiptrace")
            .header("x-langfuse-sdk-version", env!("CARGO_PKG_VERSION"))
            .body(body.to_vec())
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => return Ok(attempt as u64),
            Ok(response) => {
                let status = response.status();
                let detail = response_detail(response).await;
                if !retryable_status(status) {
                    bail!("OTLP endpoint rejected the batch with HTTP {status}: {detail}");
                }
                last_error = format!("HTTP {status}: {detail}");
            }
            Err(error) => last_error = error.to_string(),
        }
        if attempt < retry_max_times {
            sleep(retry_delay(attempt)).await;
        }
    }
    bail!("OTLP delivery failed after {retry_max_times} attempts: {last_error}")
}

async fn response_detail(response: reqwest::Response) -> String {
    response
        .bytes()
        .await
        .ok()
        .map(|body| String::from_utf8_lossy(&body[..body.len().min(1024)]).into_owned())
        .filter(|body| !body.trim().is_empty())
        .unwrap_or_else(|| "empty response".to_owned())
}

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

#[cfg(not(test))]
fn retry_delay(attempt: usize) -> Duration {
    let exponent = u32::try_from(attempt.saturating_sub(1).min(8)).unwrap_or(8);
    Duration::from_millis(100_u64.saturating_mul(2_u64.pow(exponent))).min(Duration::from_secs(10))
}

#[cfg(test)]
fn retry_delay(_attempt: usize) -> Duration {
    Duration::from_millis(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_interaction::INTERACTION_PROJECTION_SCHEMA_VERSION;
    use crate::schema::FileManifest;
    use crate::telemetry::OTLP_EXPORT_SCHEMA_VERSION;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use flate2::read::GzDecoder;
    use std::fs;
    use std::io::Read;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    fn root_record(index: usize) -> Value {
        json!({
            "resourceSpans":[{
                "resource":{"attributes":[]},
                "scopeSpans":[{
                    "scope":{"name":"chiptrace-test"},
                    "spans":[{
                        "traceId":format!("{index:032x}"),
                        "spanId":format!("{index:016x}"),
                        "name":"root",
                        "startTimeUnixNano":"1",
                        "endTimeUnixNano":"2",
                        "attributes":[],
                        "status":{"code":"STATUS_CODE_OK"}
                    }]
                }]
            }]
        })
    }

    fn export_fixture(delivery_ready: bool, count: usize) -> TempDir {
        let root = TempDir::new().unwrap();
        let data_dir = root.path().join("otlp");
        fs::create_dir_all(&data_dir).unwrap();
        let part_path = data_dir.join("otlp.jsonl.zst");
        let mut encoder =
            zstd::stream::Encoder::new(fs::File::create(&part_path).unwrap(), 1).unwrap();
        let mut uncompressed = 0_u64;
        for index in 1..=count {
            let mut line = serde_json::to_vec(&root_record(index)).unwrap();
            line.push(b'\n');
            uncompressed += line.len() as u64;
            encoder.write_all(&line).unwrap();
        }
        encoder.finish().unwrap().sync_all().unwrap();
        let manifest = OtlpExportManifest {
            schema_version: OTLP_EXPORT_SCHEMA_VERSION.to_owned(),
            created_at_utc: "2026-09-01T00:00:00Z".to_owned(),
            source_projection_schema_version: INTERACTION_PROJECTION_SCHEMA_VERSION.to_owned(),
            source_projection_manifest_sha256: "a".repeat(64),
            source_delivery_ready: delivery_ready,
            interactions: count as u64,
            runtime_spans: 0,
            links: 0,
            root_spans: count as u64,
            internal_parent_references: 0,
            resolved_internal_parents: 0,
            resolved_internal_parent_rate: 1.0,
            missing_parent_nodes: vec![],
            body_policy:
                "normalized_io_and_raw_references; raw wire request and response bodies are not copied"
                    .to_owned(),
            parts: vec![FileManifest {
                file: "otlp/otlp.jsonl.zst".to_owned(),
                sha256: sha256_file(&part_path).unwrap(),
                bytes: part_path.metadata().unwrap().len(),
                records: Some(count as u64),
                uncompressed_bytes: Some(uncompressed),
                oversized_session: None,
            }],
            validation_status: "verified".to_owned(),
        };
        fs::write(
            root.path().join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        root
    }

    fn config(root: &TempDir, endpoint: String) -> OtlpDeliveryConfig {
        OtlpDeliveryConfig {
            projection: root.path().to_path_buf(),
            endpoint,
            public_key: "public".to_owned(),
            secret_key: "secret".to_owned(),
            request_timeout: Duration::from_secs(1),
            retry_max_times: 21,
            batch_spans: 100,
            max_batch_bytes: 1024 * 1024,
            allow_incomplete: false,
        }
    }

    async fn spawn_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{address}/v1/traces"), task)
    }

    #[derive(Default)]
    struct MockState {
        attempts: AtomicUsize,
        spans: AtomicUsize,
    }

    #[tokio::test]
    async fn retries_twenty_times_and_sends_authenticated_gzip_batch() {
        async fn handler(
            State(state): State<Arc<MockState>>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            let attempt = state.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt <= 20 {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            assert_eq!(
                headers.get("authorization").unwrap(),
                "Basic cHVibGljOnNlY3JldA=="
            );
            assert_eq!(headers.get("content-encoding").unwrap(), "gzip");
            let mut decoder = GzDecoder::new(body.as_ref());
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).unwrap();
            let value: Value = serde_json::from_slice(&decoded).unwrap();
            state.spans.store(
                value["resourceSpans"].as_array().unwrap().len(),
                Ordering::SeqCst,
            );
            Json(json!({})).into_response()
        }

        let state = Arc::new(MockState::default());
        let router = Router::new()
            .route("/v1/traces", post(handler))
            .with_state(Arc::clone(&state));
        let (endpoint, server) = spawn_server(router).await;
        let root = export_fixture(true, 2);
        let result = send_otlp(config(&root, endpoint)).await.unwrap();
        server.abort();
        assert_eq!(state.attempts.load(Ordering::SeqCst), 21);
        assert_eq!(state.spans.load(Ordering::SeqCst), 2);
        assert_eq!(result.spans, 2);
        assert_eq!(result.batches, 1);
        assert_eq!(result.attempts, 21);
        assert_eq!(result.retries, 20);
        assert!(result.accepted);
    }

    #[tokio::test]
    async fn permanent_client_error_is_not_retried() {
        async fn handler(State(attempts): State<Arc<AtomicUsize>>) -> Response {
            attempts.fetch_add(1, Ordering::SeqCst);
            (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route("/v1/traces", post(handler))
            .with_state(Arc::clone(&attempts));
        let (endpoint, server) = spawn_server(router).await;
        let root = export_fixture(true, 1);
        let error = send_otlp(config(&root, endpoint)).await.unwrap_err();
        server.abort();
        assert!(error.to_string().contains("HTTP 401"));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn incomplete_export_is_rejected_before_network_access() {
        let root = export_fixture(false, 1);
        let error = send_otlp(config(&root, "http://127.0.0.1:9/v1/traces".to_owned()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not delivery-ready"));
    }

    #[tokio::test]
    async fn batch_limit_preserves_every_span() {
        async fn handler(State(spans): State<Arc<AtomicUsize>>, body: Bytes) -> Response {
            let mut decoder = GzDecoder::new(body.as_ref());
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).unwrap();
            let value: Value = serde_json::from_slice(&decoded).unwrap();
            spans.fetch_add(
                value["resourceSpans"].as_array().unwrap().len(),
                Ordering::SeqCst,
            );
            Json(json!({})).into_response()
        }

        let spans = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route("/v1/traces", post(handler))
            .with_state(Arc::clone(&spans));
        let (endpoint, server) = spawn_server(router).await;
        let root = export_fixture(true, 3);
        let mut config = config(&root, endpoint);
        config.batch_spans = 1;
        let result = send_otlp(config).await.unwrap();
        server.abort();
        assert_eq!(result.batches, 3);
        assert_eq!(result.attempts, 3);
        assert_eq!(spans.load(Ordering::SeqCst), 3);
    }
}
