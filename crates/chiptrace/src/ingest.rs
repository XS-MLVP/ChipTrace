use axum::body::Bytes;
use axum::extract::Request;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct InflightBodyBudget {
    semaphore: Arc<Semaphore>,
    capacity: usize,
    max_body_bytes: usize,
}

pub struct BufferedJsonBody {
    pub bytes: Bytes,
    _permits: Vec<OwnedSemaphorePermit>,
}

#[derive(Debug)]
pub enum BodyReadError {
    UnsupportedMediaType,
    InvalidContentLength,
    TooLarge,
    BudgetExhausted,
    Read(String),
}

impl InflightBodyBudget {
    pub fn new(capacity: usize, max_body_bytes: usize) -> anyhow::Result<Self> {
        if max_body_bytes == 0 || max_body_bytes > u32::MAX as usize || capacity < max_body_bytes {
            anyhow::bail!(
                "body budget must be >= max body bytes, and max body bytes must fit in u32"
            );
        }
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            capacity,
            max_body_bytes,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    pub async fn read_json(&self, request: Request) -> Result<BufferedJsonBody, BodyReadError> {
        self.read(request, &["application/json"]).await
    }

    pub async fn read_ndjson(&self, request: Request) -> Result<BufferedJsonBody, BodyReadError> {
        self.read(
            request,
            &[
                "application/x-ndjson",
                "application/ndjson",
                "application/jsonl",
            ],
        )
        .await
    }

    async fn read(
        &self,
        request: Request,
        accepted_content_types: &[&str],
    ) -> Result<BufferedJsonBody, BodyReadError> {
        let content_type = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type.is_none_or(|value| !accepted_content_types.contains(&value)) {
            return Err(BodyReadError::UnsupportedMediaType);
        }
        let declared = request
            .headers()
            .get(CONTENT_LENGTH)
            .map(|value| {
                value
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or(BodyReadError::InvalidContentLength)
            })
            .transpose()?;
        if declared.is_some_and(|bytes| bytes > self.max_body_bytes) {
            return Err(BodyReadError::TooLarge);
        }
        let mut permits = Vec::new();
        let mut accounted = declared.unwrap_or(0);
        if accounted > 0 {
            permits.push(
                Arc::clone(&self.semaphore)
                    .try_acquire_many_owned(accounted as u32)
                    .map_err(|_| BodyReadError::BudgetExhausted)?,
            );
        }
        let mut body = request.into_body();
        let mut buffer = Vec::with_capacity(accounted.min(self.max_body_bytes));
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| BodyReadError::Read(error.to_string()))?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            let new_length = buffer
                .len()
                .checked_add(data.len())
                .ok_or(BodyReadError::TooLarge)?;
            if new_length > self.max_body_bytes {
                return Err(BodyReadError::TooLarge);
            }
            if new_length > accounted {
                let extra = new_length - accounted;
                permits.push(
                    Arc::clone(&self.semaphore)
                        .try_acquire_many_owned(extra as u32)
                        .map_err(|_| BodyReadError::BudgetExhausted)?,
                );
                accounted = new_length;
            }
            buffer.extend_from_slice(&data);
        }
        Ok(BufferedJsonBody {
            bytes: Bytes::from(buffer),
            _permits: permits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request(body: &'static str, declared: Option<usize>) -> Request {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/capture")
            .header(CONTENT_TYPE, "application/json");
        if let Some(declared) = declared {
            builder = builder.header(CONTENT_LENGTH, declared);
        }
        builder.body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn reserves_capacity_before_reading_and_releases_on_drop() {
        let budget = InflightBodyBudget::new(16, 16).unwrap();
        let first = budget.read_json(request("{}", Some(16))).await.unwrap();
        assert_eq!(budget.available(), 0);
        assert!(matches!(
            budget.read_json(request("{}", None)).await,
            Err(BodyReadError::BudgetExhausted)
        ));
        drop(first);
        assert_eq!(budget.available(), 16);

        let streamed = budget.read_json(request("{}", None)).await.unwrap();
        assert_eq!(budget.available(), 14);
        drop(streamed);
        assert_eq!(budget.available(), 16);
    }

    #[tokio::test]
    async fn rejects_declared_and_streamed_oversize_bodies() {
        let budget = InflightBodyBudget::new(8, 8).unwrap();
        assert!(matches!(
            budget.read_json(request("{}", Some(9))).await,
            Err(BodyReadError::TooLarge)
        ));
        assert!(matches!(
            budget.read_json(request("123456789", None)).await,
            Err(BodyReadError::TooLarge)
        ));
    }
}
