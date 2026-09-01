use anyhow::{Context, Result, bail};
use reqwest::StatusCode;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub enum DeliveryTarget {
    Relay(String),
    /// Relay's producer contract endpoint. The payload is still a validated
    /// Capture envelope, but keeping this target explicit prevents producer
    /// clients from silently bypassing the producer route.
    ProducerRelay {
        base: String,
        bearer_token: String,
    },
    Jsonl(PathBuf),
}

#[derive(Debug, Clone)]
pub struct DeliveryConfig {
    pub target: DeliveryTarget,
    pub request_timeout: Duration,
    pub retry_max_times: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliveryReceipt {
    pub durable: u64,
    pub duplicates: u64,
}

enum RelayAck {
    Durable(DeliveryReceipt),
    Retryable(String),
    Conflict(String),
}

pub fn producer_relay_target(base: String) -> Result<DeliveryTarget> {
    let base = normalized_relay_base(&base)?;
    let bearer_token = std::env::var("CHIPTRACE_PRODUCER_TOKEN")
        .context("CHIPTRACE_PRODUCER_TOKEN is required for /producer/events")?;
    if bearer_token.trim().len() < 32 {
        bail!("CHIPTRACE_PRODUCER_TOKEN must contain at least 32 non-whitespace bytes");
    }
    Ok(DeliveryTarget::ProducerRelay { base, bearer_token })
}

fn normalized_relay_base(base: &str) -> Result<String> {
    let base = base.trim();
    let url = reqwest::Url::parse(base).context("parse ChipTrace Relay URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!(
            "ChipTrace Relay URL must be an HTTP(S) base URL without credentials, query, or fragment"
        );
    }
    Ok(base.trim_end_matches('/').to_owned())
}

pub async fn deliver_batch(
    config: &DeliveryConfig,
    records: &[Vec<u8>],
) -> Result<DeliveryReceipt> {
    if records.is_empty() {
        return Ok(DeliveryReceipt::default());
    }
    if config.retry_max_times < 20 {
        bail!("capture delivery requires at least 20 retry attempts");
    }
    match &config.target {
        DeliveryTarget::Jsonl(path) => deliver_to_jsonl(path, records),
        DeliveryTarget::Relay(base) => {
            deliver_to_relay(config, base, "captures", None, records).await
        }
        DeliveryTarget::ProducerRelay { base, bearer_token } => {
            deliver_to_relay(config, base, "producer/events", Some(bearer_token), records).await
        }
    }
}

/// The local sink is primarily for isolated validation, but it still needs the
/// same crash window semantics as Relay: a replay after data fsync and before a
/// producer checkpoint must not append the same Capture twice.
fn deliver_to_jsonl(path: &Path, records: &[Vec<u8>]) -> Result<DeliveryReceipt> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("JSONL delivery path has no parent"))?;
    fs::create_dir_all(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.file_type().is_file() || metadata.file_type().is_symlink())
    {
        bail!("JSONL delivery target must be a regular non-symlink file");
    }
    let existed = path.exists();
    if !existed {
        OpenOptions::new().write(true).create_new(true).open(path)?;
        File::open(parent)?.sync_all()?;
    }
    let mut identities = scan_jsonl_identities(path)?;
    let mut pending = Vec::new();
    let mut duplicates = 0_u64;
    for record in records {
        let (capture_id, digest) = jsonl_record_identity(record)?;
        match identities.get(&capture_id) {
            Some(existing) if existing == &digest => {
                duplicates = duplicates.saturating_add(1);
            }
            Some(_) => {
                bail!("JSONL target contains conflicting bytes for Capture ID {capture_id}")
            }
            None => {
                identities.insert(capture_id, digest);
                pending.push(record);
            }
        }
    }
    if !pending.is_empty() {
        let mut file = OpenOptions::new().append(true).open(path)?;
        for record in pending {
            file.write_all(record)?;
            file.write_all(b"\n")?;
        }
        file.flush()?;
        file.sync_all()?;
    }
    Ok(DeliveryReceipt {
        durable: records.len() as u64,
        duplicates,
    })
}

fn scan_jsonl_identities(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut identities = BTreeMap::new();
    let mut line = Vec::new();
    let mut complete_bytes = 0_u64;
    let mut incomplete_tail = false;
    loop {
        line.clear();
        let bytes = reader.read_until(b'\n', &mut line)?;
        if bytes == 0 {
            break;
        }
        if !line.ends_with(b"\n") {
            incomplete_tail = true;
            break;
        }
        complete_bytes = complete_bytes.saturating_add(bytes as u64);
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let (capture_id, digest) = jsonl_record_identity(&line)?;
        match identities.insert(capture_id.clone(), digest.clone()) {
            Some(existing) if existing != digest => {
                bail!("JSONL target contains conflicting bytes for Capture ID {capture_id}")
            }
            _ => {}
        }
    }
    drop(reader);
    if incomplete_tail {
        let file = OpenOptions::new().write(true).open(path)?;
        file.set_len(complete_bytes)?;
        file.sync_all()?;
    }
    Ok(identities)
}

fn jsonl_record_identity(record: &[u8]) -> Result<(String, String)> {
    let value: Value = serde_json::from_slice(record).context("parse JSONL delivery record")?;
    let capture_id = value
        .get("captureId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("JSONL delivery record is missing captureId"))?
        .to_owned();
    Ok((capture_id, hex::encode(Sha256::digest(record))))
}

async fn deliver_to_relay(
    config: &DeliveryConfig,
    base: &str,
    route: &str,
    bearer_token: Option<&str>,
    records: &[Vec<u8>],
) -> Result<DeliveryReceipt> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut body = Vec::new();
    for record in records {
        body.extend_from_slice(record);
        body.push(b'\n');
    }
    let client = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .build()?;
    let url = format!("{}/{}", base.trim_end_matches('/'), route);
    let mut last_error = String::new();
    for attempt in 1..=config.retry_max_times {
        let mut request = client
            .post(&url)
            .header("content-type", "application/x-ndjson")
            .body(body.clone());
        if let Some(token) = bearer_token {
            request = request.bearer_auth(token);
        }
        match request.send().await {
            Ok(response) if response.status() == StatusCode::CONFLICT => {
                bail!("Relay rejected a deterministic Capture ID with conflicting bytes");
            }
            Ok(response) => {
                let status = response.status();
                let body = response.bytes().await?;
                if status.is_success() {
                    let value: Value = serde_json::from_slice(&body).map_err(|error| {
                        anyhow::anyhow!("Relay returned an invalid JSON acknowledgement: {error}")
                    })?;
                    match parse_relay_ack(&value, records)? {
                        RelayAck::Durable(receipt) => return Ok(receipt),
                        RelayAck::Retryable(error) => last_error = error,
                        RelayAck::Conflict(error) => bail!("{error}"),
                    }
                } else if status.is_client_error()
                    && status != StatusCode::REQUEST_TIMEOUT
                    && status != StatusCode::TOO_MANY_REQUESTS
                {
                    bail!("Relay rejected the capture batch with HTTP {status}");
                } else {
                    last_error = format!("Relay returned HTTP {status}");
                }
            }
            Err(error) => last_error = error.to_string(),
        }
        if attempt < config.retry_max_times {
            sleep(retry_delay(attempt)).await;
        }
    }
    bail!(
        "capture delivery failed after {} attempts: {}",
        config.retry_max_times,
        last_error
    )
}

fn parse_relay_ack(value: &Value, records: &[Vec<u8>]) -> Result<RelayAck> {
    let expected = records.len() as u64;

    // Compatibility with the original numeric acknowledgement contract.
    if let Some(durable) = value.get("durable").and_then(Value::as_u64) {
        let duplicates = value.get("duplicates").and_then(Value::as_u64).unwrap_or(0);
        if durable != expected || duplicates > durable {
            bail!(
                "Relay acknowledgement is not conserved: expected={expected}, durable={durable}, duplicates={duplicates}"
            );
        }
        return Ok(RelayAck::Durable(DeliveryReceipt {
            durable,
            duplicates,
        }));
    }

    let counts = value
        .get("counts")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("Relay acknowledgement is missing counts"))?;
    let count = |name: &str| -> Result<u64> {
        counts
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("Relay acknowledgement is missing counts.{name}"))
    };
    let total = count("total")?;
    let durable = count("durable")?;
    let duplicates = count("duplicates")?;
    let conflicts = count("conflicts")?;
    let unavailable = count("unavailable")?;
    if total != expected
        || durable
            .saturating_add(conflicts)
            .saturating_add(unavailable)
            != total
        || duplicates > durable
    {
        bail!(
            "Relay acknowledgement is not conserved: expected={expected}, total={total}, durable={durable}, duplicates={duplicates}, conflicts={conflicts}, unavailable={unavailable}"
        );
    }

    let expected_ids: BTreeSet<String> = records
        .iter()
        .map(|record| -> Result<String> {
            let capture: Value = serde_json::from_slice(record)?;
            capture
                .get("captureId")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("delivered Capture is missing captureId"))
        })
        .collect::<Result<_>>()?;
    if expected_ids.len() as u64 != expected {
        bail!("delivery batch contains duplicate Capture IDs");
    }
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Relay acknowledgement is missing per-Capture results"))?;
    if results.len() as u64 != total {
        bail!(
            "Relay acknowledgement result count is not conserved: total={total}, results={}",
            results.len()
        );
    }
    let mut observed_ids = BTreeSet::new();
    let mut result_durable = 0_u64;
    let mut result_duplicates = 0_u64;
    let mut result_conflicts = 0_u64;
    let mut result_unavailable = 0_u64;
    for result in results {
        let capture_id = result
            .get("capture_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Relay result is missing capture_id"))?;
        if !expected_ids.contains(capture_id) || !observed_ids.insert(capture_id.to_owned()) {
            bail!("Relay result contains an unknown or duplicate Capture ID");
        }
        if result.get("durable").and_then(Value::as_bool) == Some(true) {
            result_durable = result_durable.saturating_add(1);
            result_duplicates = result_duplicates.saturating_add(u64::from(
                result.get("duplicate").and_then(Value::as_bool) == Some(true),
            ));
        } else if result.get("reason").and_then(Value::as_str) == Some("capture_id_conflict") {
            result_conflicts = result_conflicts.saturating_add(1);
        } else {
            result_unavailable = result_unavailable.saturating_add(1);
        }
    }
    if observed_ids != expected_ids
        || result_durable != durable
        || result_duplicates != duplicates
        || result_conflicts != conflicts
        || result_unavailable != unavailable
    {
        bail!("Relay acknowledgement counters do not match its per-Capture results");
    }
    if conflicts > 0 {
        return Ok(RelayAck::Conflict(
            "Relay rejected a deterministic Capture ID with conflicting bytes".to_owned(),
        ));
    }
    if unavailable > 0
        || durable != total
        || value.get("ok").and_then(Value::as_bool) != Some(true)
        || value.get("durable").and_then(Value::as_bool) != Some(true)
    {
        return Ok(RelayAck::Retryable(format!(
            "Relay did not durably acknowledge the complete capture batch: durable={durable}/{total}, unavailable={unavailable}"
        )));
    }
    Ok(RelayAck::Durable(DeliveryReceipt {
        durable,
        duplicates,
    }))
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
    use axum::extract::State;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    fn records() -> Vec<Vec<u8>> {
        vec![br#"{"captureId":"cap-1"}"#.to_vec()]
    }

    fn complete_ack() -> Value {
        json!({
            "ok":true,
            "durable":true,
            "counts":{"total":1,"durable":1,"duplicates":0,"conflicts":0,"unavailable":0},
            "results":[{"capture_id":"cap-1","ok":true,"durable":true,"duplicate":false}]
        })
    }

    #[test]
    fn relay_base_requires_a_clean_http_url() {
        assert_eq!(
            normalized_relay_base("  https://trace.example.com/api/  ").unwrap(),
            "https://trace.example.com/api"
        );
        for invalid in [
            "",
            "relay.internal",
            "ftp://relay.internal",
            "https://user:secret@relay.internal",
            "https://relay.internal?tenant=one",
            "https://relay.internal#fragment",
        ] {
            assert!(normalized_relay_base(invalid).is_err(), "{invalid}");
        }
    }

    async fn spawn_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn retries_twenty_transient_failures_then_accepts_conserved_ack() {
        async fn handler(State(attempts): State<Arc<AtomicUsize>>) -> Response {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt <= 20 {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"ok":false,"reason":"temporary"})),
                )
                    .into_response();
            }
            (StatusCode::ACCEPTED, Json(complete_ack())).into_response()
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route("/captures", post(handler))
            .with_state(Arc::clone(&attempts));
        let (base, server) = spawn_server(router).await;
        let receipt = deliver_batch(
            &DeliveryConfig {
                target: DeliveryTarget::Relay(base),
                request_timeout: Duration::from_secs(1),
                retry_max_times: 21,
            },
            &records(),
        )
        .await
        .unwrap();
        server.abort();
        assert_eq!(attempts.load(Ordering::SeqCst), 21);
        assert_eq!(receipt.durable, 1);
    }

    #[tokio::test]
    async fn deterministic_conflict_is_not_retried() {
        async fn handler(State(attempts): State<Arc<AtomicUsize>>) -> Response {
            attempts.fetch_add(1, Ordering::SeqCst);
            (
                StatusCode::CONFLICT,
                Json(json!({"ok":false,"reason":"capture_id_conflict"})),
            )
                .into_response()
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route("/captures", post(handler))
            .with_state(Arc::clone(&attempts));
        let (base, server) = spawn_server(router).await;
        let error = deliver_batch(
            &DeliveryConfig {
                target: DeliveryTarget::Relay(base),
                request_timeout: Duration::from_secs(1),
                retry_max_times: 25,
            },
            &records(),
        )
        .await
        .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("conflicting bytes"));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn non_conserved_durable_ack_is_rejected() {
        async fn handler() -> Response {
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "ok":true,
                    "durable":true,
                    "counts":{"total":2,"durable":2,"duplicates":0,"conflicts":0,"unavailable":0},
                    "results":[]
                })),
            )
                .into_response()
        }

        let router = Router::new().route("/captures", post(handler));
        let (base, server) = spawn_server(router).await;
        let error = deliver_batch(
            &DeliveryConfig {
                target: DeliveryTarget::Relay(base),
                request_timeout: Duration::from_secs(1),
                retry_max_times: 20,
            },
            &records(),
        )
        .await
        .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("not conserved"));
    }

    #[tokio::test]
    async fn producer_target_uses_the_producer_contract_route() {
        async fn handler(request: axum::extract::Request) -> Response {
            if request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                != Some("Bearer producer-test-token-at-least-32-bytes")
            {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            (StatusCode::ACCEPTED, Json(complete_ack())).into_response()
        }

        let router = Router::new().route("/producer/events", post(handler));
        let (base, server) = spawn_server(router).await;
        let receipt = deliver_batch(
            &DeliveryConfig {
                target: DeliveryTarget::ProducerRelay {
                    base,
                    bearer_token: "producer-test-token-at-least-32-bytes".to_owned(),
                },
                request_timeout: Duration::from_secs(1),
                retry_max_times: 20,
            },
            &records(),
        )
        .await
        .unwrap();
        server.abort();
        assert_eq!(receipt.durable, 1);
    }

    #[tokio::test]
    async fn jsonl_target_is_idempotent_across_checkpoint_replay() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("captures.jsonl");
        let config = DeliveryConfig {
            target: DeliveryTarget::Jsonl(path.clone()),
            request_timeout: Duration::from_secs(1),
            retry_max_times: 20,
        };
        let first = deliver_batch(&config, &records()).await.unwrap();
        let second = deliver_batch(&config, &records()).await.unwrap();
        assert_eq!(
            first,
            DeliveryReceipt {
                durable: 1,
                duplicates: 0
            }
        );
        assert_eq!(
            second,
            DeliveryReceipt {
                durable: 1,
                duplicates: 1
            }
        );
        assert_eq!(fs::read_to_string(path).unwrap().lines().count(), 1);
    }

    #[tokio::test]
    async fn jsonl_target_recovers_an_incomplete_tail_before_replay() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("captures.jsonl");
        fs::write(&path, b"{\"captureId\":\"cap-1\"}\n{\"captureId\":\"cap-").unwrap();
        let receipt = deliver_batch(
            &DeliveryConfig {
                target: DeliveryTarget::Jsonl(path.clone()),
                request_timeout: Duration::from_secs(1),
                retry_max_times: 20,
            },
            &[br#"{"captureId":"cap-2"}"#.to_vec()],
        )
        .await
        .unwrap();
        assert_eq!(receipt.durable, 1);
        let lines = fs::read_to_string(path).unwrap();
        assert_eq!(lines.lines().count(), 2);
        assert!(lines.contains("cap-1"));
        assert!(lines.contains("cap-2"));
    }
}
