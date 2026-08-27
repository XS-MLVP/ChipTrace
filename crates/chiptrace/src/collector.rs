use crate::capture::normalize_capture;
use crate::ingest::{BodyReadError, InflightBodyBudget};
use crate::sharded::ShardedCaptureStore;
use crate::store::{StoreConfig, SubmitError, SubmitErrorKind};
use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Debug, Clone)]
pub struct CollectorConfig {
    pub bind: SocketAddr,
    pub store: StoreConfig,
    pub store_shards: usize,
    pub max_connections: usize,
    pub max_envelope_bytes: usize,
    pub max_inflight_body_bytes: usize,
    pub max_batch_records: usize,
}

#[derive(Clone)]
struct AppState {
    store: ShardedCaptureStore,
    max_envelope_bytes: usize,
    max_batch_records: usize,
    body_budget: InflightBodyBudget,
}

pub async fn serve(
    config: CollectorConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let store = ShardedCaptureStore::open(config.store, config.store_shards).await?;
    let state = AppState {
        store: store.clone(),
        max_envelope_bytes: config.max_envelope_bytes,
        max_batch_records: config.max_batch_records,
        body_budget: InflightBodyBudget::new(
            config.max_inflight_body_bytes,
            config.max_envelope_bytes,
        )?,
    };
    let app = router(state, config.max_connections, config.max_envelope_bytes);
    let listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("bind collector {}", config.bind))?;
    info!(address = %config.bind, "collector ready");
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("collector server failed");
    store.close().await?;
    result
}

fn router(state: AppState, max_connections: usize, max_envelope_bytes: usize) -> Router {
    Router::new()
        .route("/capture", post(capture))
        .route("/captures", post(captures))
        .route("/health", get(health))
        .route("/audit", get(audit))
        .route("/flush", post(flush))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(max_envelope_bytes))
        .layer(ConcurrencyLimitLayer::new(max_connections.max(1)))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(120),
        ))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn captures(State(state): State<AppState>, request: Request) -> Response {
    let body = match state.body_budget.read_ndjson(request).await {
        Ok(body) => body,
        Err(error) => return body_error_response(error),
    };
    let mut records = Vec::new();
    for (index, raw) in body.bytes.split(|byte| *byte == b'\n').enumerate() {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records.len() >= state.max_batch_records {
            return response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"ok": false, "reason": "batch_record_limit", "maximum": state.max_batch_records}),
            );
        }
        match normalize_capture(raw, state.max_envelope_bytes) {
            Ok(record) => records.push(record),
            Err(error) => {
                return response(
                    StatusCode::BAD_REQUEST,
                    json!({
                        "ok": false,
                        "reason": "invalid_capture",
                        "line": index + 1,
                        "detail": error.to_string(),
                    }),
                );
            }
        }
    }
    if records.is_empty() {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "reason": "empty_batch"}),
        );
    }
    let capture_ids: Vec<String> = records
        .iter()
        .map(|record| record.capture_id.clone())
        .collect();
    let results = state.store.submit_batch(records).await;
    let mut durable = 0_u64;
    let mut duplicates = 0_u64;
    let mut conflicts = 0_u64;
    let mut unavailable = 0_u64;
    let outcomes: Vec<Value> = capture_ids
        .into_iter()
        .zip(results)
        .map(|(capture_id, result)| match result {
            Ok(ack) => {
                durable += 1;
                duplicates += u64::from(ack.duplicate);
                json!({
                    "capture_id": capture_id,
                    "ok": true,
                    "durable": true,
                    "duplicate": ack.duplicate,
                    "capture": ack,
                })
            }
            Err(error) if error.kind == SubmitErrorKind::Conflict => {
                conflicts += 1;
                batch_error(
                    &capture_id,
                    &error,
                    "capture_id_conflict",
                    StatusCode::CONFLICT,
                )
            }
            Err(error) => {
                unavailable += 1;
                batch_error(
                    &capture_id,
                    &error,
                    "collector_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
            }
        })
        .collect();
    let total = outcomes.len() as u64;
    response(
        if durable == total {
            if duplicates == total {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            }
        } else {
            StatusCode::MULTI_STATUS
        },
        json!({
            "ok": durable == total,
            "durable": durable == total,
            "counts": {
                "total": total,
                "durable": durable,
                "duplicates": duplicates,
                "conflicts": conflicts,
                "unavailable": unavailable,
            },
            "results": outcomes,
        }),
    )
}

fn batch_error(capture_id: &str, error: &SubmitError, reason: &str, status: StatusCode) -> Value {
    json!({
        "capture_id": capture_id,
        "ok": false,
        "durable": false,
        "reason": reason,
        "http_status": status.as_u16(),
        "detail": error.message,
    })
}

async fn capture(State(state): State<AppState>, request: Request) -> Response {
    let body = match state.body_budget.read_json(request).await {
        Ok(body) => body,
        Err(error) => return body_error_response(error),
    };
    let record = match normalize_capture(&body.bytes, state.max_envelope_bytes) {
        Ok(record) => record,
        Err(error) => {
            return response(
                StatusCode::BAD_REQUEST,
                json!({"ok": false, "reason": "invalid_capture", "detail": error.to_string()}),
            );
        }
    };
    let result = state.store.submit(record).await;
    match result {
        Ok(ack) => response(
            if ack.duplicate {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            },
            json!({
                "ok": true,
                "durable": true,
                "duplicate": ack.duplicate,
                "capture": ack,
            }),
        ),
        Err(error) if error.kind == SubmitErrorKind::Conflict => response(
            StatusCode::CONFLICT,
            json!({"ok": false, "reason": "capture_id_conflict", "detail": error.message}),
        ),
        Err(error) => response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "reason": "collector_unavailable", "detail": error.message}),
        ),
    }
}

async fn health(State(state): State<AppState>) -> Response {
    let health = state.store.health();
    let status = if health.ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    response(
        status,
        json!({
            "ok": health.ok,
            "collector": health,
            "http": {
                "body_budget_capacity": state.body_budget.capacity(),
                "body_budget_available": state.body_budget.available(),
            }
        }),
    )
}

async fn audit(State(state): State<AppState>) -> Response {
    let result = state.store.runtime_audit();
    let status = if result["ok"].as_bool().unwrap_or(false) {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    response(status, result)
}

async fn flush(State(state): State<AppState>) -> Response {
    match state.store.flush().await {
        Ok(segments) => response(
            StatusCode::OK,
            json!({
                "ok": true,
                "sealed": segments.iter().all(|segment| segment.state == "sealed" || segment.records == 0),
                "segments": segments,
            }),
        ),
        Err(error) => response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "reason": "flush_failed", "detail": error.to_string()}),
        ),
    }
}

async fn not_found() -> Response {
    response(
        StatusCode::NOT_FOUND,
        json!({"ok": false, "reason": "not_found"}),
    )
}

fn response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

fn body_error_response(error: BodyReadError) -> Response {
    match error {
        BodyReadError::UnsupportedMediaType => response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!({"ok": false, "reason": "content_type"}),
        ),
        BodyReadError::InvalidContentLength => response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "reason": "content_length"}),
        ),
        BodyReadError::TooLarge => response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"ok": false, "reason": "body_limit"}),
        ),
        BodyReadError::BudgetExhausted => response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "reason": "body_budget"}),
        ),
        BodyReadError::Read(detail) => response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "reason": "body_read", "detail": detail}),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoreConfig;
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::json;
    use std::time::Duration;
    use tower::ServiceExt;

    #[tokio::test]
    async fn collector_keeps_error_responses_and_is_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let store = ShardedCaptureStore::open(
            StoreConfig {
                root: temporary.path().join("capture"),
                state_root: temporary.path().join("state"),
                segment_max_bytes: 1024 * 1024,
                segment_max_age: Duration::from_secs(60),
                queue_items: 8,
                batch_records: 4,
                batch_bytes: 1024 * 1024,
                batch_wait: Duration::from_millis(1),
                fsync: true,
            },
            1,
        )
        .await
        .unwrap();
        let state = AppState {
            store: store.clone(),
            max_envelope_bytes: 1024 * 1024,
            max_batch_records: 32,
            body_budget: InflightBodyBudget::new(1024 * 1024, 1024 * 1024).unwrap(),
        };
        let app = router(state, 8, 1024 * 1024);
        let body = serde_json::to_vec(&json!({
            "captureId": "cap-http-failure",
            "responseStatus": 503,
            "captureError": "upstream failed"
        }))
        .unwrap();
        for expected in [StatusCode::ACCEPTED, StatusCode::OK] {
            let result = app
                .clone()
                .oneshot(
                    Request::post("/capture")
                        .header("content-type", "application/json")
                        .body(Body::from(body.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(result.status(), expected);
        }
        let batch = [
            json!({"captureId": "cap-http-batch-1", "responseStatus": 429}),
            json!({"captureId": "cap-http-batch-2", "captureError": "cancelled"}),
        ]
        .into_iter()
        .map(|value| serde_json::to_string(&value).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
        let result = app
            .oneshot(
                Request::post("/captures")
                    .header("content-type", "application/x-ndjson")
                    .body(Body::from(batch))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::ACCEPTED);
        assert_eq!(store.health().captures, 3);
        store.close().await.unwrap();
    }
}
