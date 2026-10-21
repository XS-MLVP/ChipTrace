//! HTTP trace logging policy shared by the Collector and Relay.
//!
//! A 429/503 response is the normal backpressure signal while a bounded
//! delivery queue is draining.  Tower HTTP's default failure hook logs every
//! such response at `ERROR`, which turns a healthy load test into a log storm
//! and makes real failures harder to find.  Keep the response visible at
//! `DEBUG` for those statuses while retaining error-level events for actual
//! server failures and transport errors.

use axum::http::StatusCode;
use std::time::Duration;
use tower_http::classify::ServerErrorsFailureClass;
use tracing::{Level, Span};

fn is_backpressure_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE
}

pub(crate) fn on_failure(classification: ServerErrorsFailureClass, latency: Duration, span: &Span) {
    match classification {
        ServerErrorsFailureClass::StatusCode(status) if is_backpressure_status(status) => {
            tracing::event!(
                parent: span,
                Level::DEBUG,
                http_status = status.as_u16(),
                latency_ms = latency.as_millis() as u64,
                backpressure = true,
                "response deferred by bounded backpressure",
            );
        }
        ServerErrorsFailureClass::StatusCode(status) => {
            tracing::event!(
                parent: span,
                Level::ERROR,
                http_status = status.as_u16(),
                latency_ms = latency.as_millis() as u64,
                "response failed",
            );
        }
        ServerErrorsFailureClass::Error(error) => {
            tracing::event!(
                parent: span,
                Level::ERROR,
                error = %error,
                latency_ms = latency.as_millis() as u64,
                "response failed",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_backpressure_status;
    use axum::http::StatusCode;

    #[test]
    fn only_retryable_capacity_statuses_are_backpressure() {
        assert!(is_backpressure_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_backpressure_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(!is_backpressure_status(StatusCode::BAD_REQUEST));
        assert!(!is_backpressure_status(StatusCode::INTERNAL_SERVER_ERROR));
    }
}
