// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Sliding-window rate limiter for per-channel notification throttling.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-channel rate limiter using a sliding window.
pub struct RateLimiter {
    /// channel_id → list of send timestamps
    windows: Mutex<HashMap<String, Vec<Instant>>>,
    /// Maximum sends per channel within the window
    max_per_window: u32,
    /// Window duration
    window_duration: Duration,
    /// Global quiet hours (hour of day, UTC). None = no quiet hours.
    quiet_hours: Option<(u8, u8)>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32, window_duration: Duration) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            max_per_window,
            window_duration,
            quiet_hours: None,
        }
    }

    /// Set quiet hours (UTC). During quiet hours, only Critical-severity
    /// notifications are allowed. `start` and `end` are hours (0-23).
    pub fn set_quiet_hours(&mut self, start: u8, end: u8) {
        self.quiet_hours = Some((start, end));
    }

    /// Check if a send is allowed for the given channel. Returns `Ok(())` if
    /// allowed, or `Err(duration)` with the time until the next allowed send.
    pub fn check(&self, channel_id: &str) -> Result<(), Duration> {
        let now = Instant::now();

        let mut windows = self.windows.lock().unwrap();
        let timestamps = windows.entry(channel_id.to_string()).or_default();

        // Remove expired entries
        timestamps.retain(|ts| now.duration_since(*ts) < self.window_duration);

        if timestamps.len() >= self.max_per_window as usize {
            // Find oldest in window, calculate when it expires
            if let Some(oldest) = timestamps.first() {
                let wait = self.window_duration - now.duration_since(*oldest);
                return Err(wait);
            }
        }

        Ok(())
    }

    /// Record a send for the given channel. Call this after successfully
    /// sending a notification.
    pub fn record(&self, channel_id: &str) {
        let mut windows = self.windows.lock().unwrap();
        windows
            .entry(channel_id.to_string())
            .or_default()
            .push(Instant::now());
    }

    /// Check and record in one atomic operation. Returns `Ok(())` if allowed
    /// (and records the send), or `Err(duration)` if rate-limited.
    pub fn check_and_record(&self, channel_id: &str) -> Result<(), Duration> {
        let now = Instant::now();

        let mut windows = self.windows.lock().unwrap();
        let timestamps = windows.entry(channel_id.to_string()).or_default();

        // Remove expired entries
        timestamps.retain(|ts| now.duration_since(*ts) < self.window_duration);

        if timestamps.len() >= self.max_per_window as usize {
            if let Some(oldest) = timestamps.first() {
                let wait = self.window_duration - now.duration_since(*oldest);
                return Err(wait);
            }
        }

        timestamps.push(now);
        Ok(())
    }

    /// Whether the current UTC hour falls within quiet hours.
    pub fn is_quiet_hours(&self) -> bool {
        let Some((start, end)) = self.quiet_hours else {
            return false;
        };
        let hour = chrono::Utc::now()
            .format("%H")
            .to_string()
            .parse::<u8>()
            .unwrap_or(0);
        if start <= end {
            hour >= start && hour < end
        } else {
            // Wraps midnight, e.g. 22-06
            hour >= start || hour < end
        }
    }

    /// Reset rate limit state for a specific channel.
    pub fn reset(&self, channel_id: &str) {
        if let Ok(mut windows) = self.windows.lock() {
            windows.remove(channel_id);
        }
    }

    /// Reset all rate limit state.
    pub fn reset_all(&self) {
        if let Ok(mut windows) = self.windows.lock() {
            windows.clear();
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // Default: 60 notifications per channel per hour
        Self::new(60, Duration::from_secs(3600))
    }
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("max_per_window", &self.max_per_window)
            .field("window_duration", &self.window_duration)
            .field("quiet_hours", &self.quiet_hours)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_rate_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check_and_record("slack").is_ok());
        assert!(limiter.check_and_record("slack").is_ok());
        assert!(limiter.check_and_record("slack").is_err());

        // Different channel is independent
        assert!(limiter.check_and_record("telegram").is_ok());
    }

    #[test]
    fn test_reset() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check_and_record("slack").is_ok());
        assert!(limiter.check_and_record("slack").is_err());

        limiter.reset("slack");
        assert!(limiter.check_and_record("slack").is_ok());
    }

    #[test]
    fn test_reset_all() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        limiter.check_and_record("slack").ok();
        limiter.check_and_record("telegram").ok();

        limiter.reset_all();
        assert!(limiter.check_and_record("slack").is_ok());
        assert!(limiter.check_and_record("telegram").is_ok());
    }
}
