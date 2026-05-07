// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Sliding-window per-bucket API rate limiter.
//!
//! Each request bucket (general, write, proxy_test) has an independent
//! sliding window of 1 second. When the window is full the middleware
//! returns `429 Too Many Requests` with a `Retry-After` header.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Identifies which rate-limit bucket a request belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitBucket {
    General,
    Write,
    ProxyTest,
    Ipc,
}

/// Sliding-window counter for a single bucket.
struct BucketLimiter {
    max_rps: u32,
    window: Duration,
    timestamps: Vec<Instant>,
}

impl BucketLimiter {
    fn new(max_rps: u32) -> Self {
        Self {
            max_rps,
            window: Duration::from_secs(1),
            timestamps: Vec::new(),
        }
    }

    /// Try to admit a request. Returns `Ok(())` if allowed, or
    /// `Err(retry_after)` with the duration until the oldest entry expires.
    fn check(&mut self, now: Instant) -> Result<(), Duration> {
        // A zero limit means "always rate-limited". Return a deterministic
        // retry window and avoid indexing an empty timestamp buffer.
        if self.max_rps == 0 {
            return Err(self.window);
        }

        let cutoff = now - self.window;
        self.timestamps.retain(|t| *t > cutoff);

        if self.timestamps.len() >= self.max_rps as usize {
            // Earliest timestamp still in window — caller must wait until it expires.
            let earliest = self.timestamps[0];
            let retry_after = self.window - (now - earliest);
            return Err(retry_after);
        }

        self.timestamps.push(now);
        Ok(())
    }
}

/// Thread-safe rate limiter holding all bucket counters.
pub struct ApiRateLimiter {
    enabled: bool,
    buckets: Mutex<HashMap<RateLimitBucket, BucketLimiter>>,
}

impl ApiRateLimiter {
    /// Create a rate limiter with the given per-bucket limits.
    pub fn new(general_rps: u32, write_rps: u32, proxy_test_rps: u32, ipc_rps: u32) -> Self {
        let mut map = HashMap::new();
        map.insert(RateLimitBucket::General, BucketLimiter::new(general_rps));
        map.insert(RateLimitBucket::Write, BucketLimiter::new(write_rps));
        map.insert(
            RateLimitBucket::ProxyTest,
            BucketLimiter::new(proxy_test_rps),
        );
        map.insert(RateLimitBucket::Ipc, BucketLimiter::new(ipc_rps));
        Self {
            enabled: true,
            buckets: Mutex::new(map),
        }
    }

    /// Create a disabled rate limiter that allows all requests.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether a request in the given bucket should be allowed.
    /// Returns `Ok(())` on success, `Err(retry_after)` on limit exceeded.
    fn check(&self, bucket: RateLimitBucket) -> Result<(), Duration> {
        if !self.enabled {
            return Ok(());
        }
        let mut buckets = match self.buckets.lock() {
            Ok(g) => g,
            Err(_) => return Ok(()), // poisoned lock — fail open
        };
        if let Some(limiter) = buckets.get_mut(&bucket) {
            limiter.check(Instant::now())
        } else {
            Ok(())
        }
    }
}

/// Axum middleware function that enforces rate limiting for a specific bucket.
///
/// Use with `axum::middleware::from_fn` by partially applying the limiter and
/// bucket via a closure. Returns 429 with JSON body and `Retry-After` header
/// when the limit is exceeded.
pub async fn check(
    limiter: std::sync::Arc<ApiRateLimiter>,
    bucket: RateLimitBucket,
    request: Request,
    next: Next,
) -> Response {
    match limiter.check(bucket) {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            let secs = retry_after.as_secs_f64().ceil().max(1.0);
            let body = serde_json::json!({
                "error": "rate limit exceeded",
                "code": "RATE_LIMITED",
                "retry_after_seconds": secs,
            });
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, format!("{}", secs as u64))],
                axum::Json(body),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn bucket_allows_within_limit() {
        let mut limiter = BucketLimiter::new(3);
        let now = Instant::now();
        assert!(limiter.check(now).is_ok());
        assert!(limiter.check(now).is_ok());
        assert!(limiter.check(now).is_ok());
    }

    #[test]
    fn bucket_rejects_over_limit() {
        let mut limiter = BucketLimiter::new(2);
        let now = Instant::now();
        assert!(limiter.check(now).is_ok());
        assert!(limiter.check(now).is_ok());
        let result = limiter.check(now);
        assert!(result.is_err());
    }

    #[test]
    fn bucket_returns_retry_after_duration() {
        let mut limiter = BucketLimiter::new(1);
        let now = Instant::now();
        assert!(limiter.check(now).is_ok());
        let err = limiter.check(now).unwrap_err();
        // retry_after should be close to 1 second (the window size)
        assert!(err.as_millis() > 0);
        assert!(err <= Duration::from_secs(1));
    }

    #[test]
    fn bucket_zero_limit_never_panics_and_always_rejects() {
        let mut limiter = BucketLimiter::new(0);
        let now = Instant::now();
        let err = limiter.check(now).unwrap_err();
        assert_eq!(err, Duration::from_secs(1));
        // Repeated checks remain stable.
        let err2 = limiter.check(now).unwrap_err();
        assert_eq!(err2, Duration::from_secs(1));
    }

    #[test]
    fn separate_buckets_are_independent() {
        let rl = ApiRateLimiter::new(1, 1, 1, 1);
        // Fill general bucket
        assert!(rl.check(RateLimitBucket::General).is_ok());
        assert!(rl.check(RateLimitBucket::General).is_err());
        // Write bucket should still be available
        assert!(rl.check(RateLimitBucket::Write).is_ok());
        // ProxyTest bucket should still be available
        assert!(rl.check(RateLimitBucket::ProxyTest).is_ok());
        // IPC bucket should still be available
        assert!(rl.check(RateLimitBucket::Ipc).is_ok());
    }

    #[test]
    fn disabled_limiter_allows_all() {
        let rl = ApiRateLimiter::disabled();
        for _ in 0..100 {
            assert!(rl.check(RateLimitBucket::General).is_ok());
            assert!(rl.check(RateLimitBucket::Write).is_ok());
            assert!(rl.check(RateLimitBucket::ProxyTest).is_ok());
            assert!(rl.check(RateLimitBucket::Ipc).is_ok());
        }
    }

    #[tokio::test]
    async fn middleware_returns_429_with_retry_after() {
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use axum::routing::get;
        use axum::Router;
        use tower::util::ServiceExt;

        let limiter = Arc::new(ApiRateLimiter::new(1, 1, 1, 1));

        let app =
            Router::new()
                .route("/test", get(|| async { "ok" }))
                .layer(axum::middleware::from_fn({
                    let limiter = Arc::clone(&limiter);
                    move |req, next| {
                        let limiter = Arc::clone(&limiter);
                        async move { check(limiter, RateLimitBucket::General, req, next).await }
                    }
                }));

        // First request should succeed
        let resp = app
            .clone()
            .oneshot(HttpRequest::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second request should be rate limited
        let resp = app
            .oneshot(HttpRequest::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // Check Retry-After header
        let retry_after = resp
            .headers()
            .get("retry-after")
            .expect("should have retry-after header")
            .to_str()
            .unwrap();
        let retry_secs: u64 = retry_after.parse().unwrap();
        assert!(retry_secs >= 1);

        // Check JSON body
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "RATE_LIMITED");
        assert_eq!(json["error"], "rate limit exceeded");
        assert!(json["retry_after_seconds"].is_number());
    }
}
