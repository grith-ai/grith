// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Egress rate limiting filter for outbound data volume control.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
// NOTE(M-4): std::sync::Mutex is intentionally used here instead of
// tokio::sync::Mutex because the lock is never held across .await points.
// The evaluate() method delegates to the synchronous evaluate_at(), so
// std::sync::Mutex is the more efficient choice.
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Configuration for per-session egress rate controls.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EgressRateConfig {
    pub enabled: bool,
    /// Maximum outbound network syscalls per minute per session.
    pub max_egress_per_minute: u32,
    /// Maximum unique destination hosts per minute per session.
    pub max_unique_destinations_per_minute: u32,
    /// Maximum unique destination ports per minute per session.
    pub max_unique_ports_per_minute: u32,
    /// Burst: max egress calls in the burst window before flagging.
    pub burst_threshold: u32,
    /// Duration of the burst detection window (seconds).
    pub burst_window_seconds: u64,
    /// Cool-down duration after a burst is detected (seconds).
    pub cooldown_seconds: u64,
    /// Number of file reads in the read window that constitutes a "read spike".
    pub read_spike_threshold: u32,
    /// Window for counting reads before an egress call (seconds).
    pub read_window_seconds: u64,
    /// Minimum egress calls in the read window to trigger read-then-send detection.
    pub read_then_send_egress_threshold: u32,
}

impl Default for EgressRateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_egress_per_minute: 30,
            max_unique_destinations_per_minute: 10,
            max_unique_ports_per_minute: 8,
            burst_threshold: 8,
            burst_window_seconds: 10,
            cooldown_seconds: 30,
            read_spike_threshold: 10,
            read_window_seconds: 15,
            read_then_send_egress_threshold: 3,
        }
    }
}

/// Per-session egress tracking state.
#[derive(Debug)]
struct SessionEgressState {
    /// Timestamps of *all* outbound (egress) calls, routine or not. Drives the
    /// read-then-send correlation signal, which stays sensitive regardless of
    /// destination trust (defence-in-depth against a mis-curated trust list).
    egress_timestamps: Vec<Instant>,
    /// Timestamps of *non-routine* egress only. Drives the purely volumetric
    /// anomaly signals (burst, rate-exceeded). Egress to an operator- or
    /// profile-trusted destination is the expected baseline, not an anomaly, so
    /// it is excluded here (A#2 — kills the headless-browser startup prompt
    /// storm without lowering the exfil bar).
    counted_egress_timestamps: Vec<Instant>,
    /// Unique *non-routine* destination hosts seen in the current minute window.
    destinations: Vec<(String, Instant)>,
    /// Unique *non-routine* destination ports seen in the current minute window.
    ports: Vec<(u16, Instant)>,
    /// Timestamps of file-read calls (for read-then-send detection).
    read_timestamps: Vec<Instant>,
    /// If in cooldown, when it expires.
    cooldown_until: Option<Instant>,
}

impl SessionEgressState {
    fn new() -> Self {
        Self {
            egress_timestamps: Vec::new(),
            counted_egress_timestamps: Vec::new(),
            destinations: Vec::new(),
            ports: Vec::new(),
            read_timestamps: Vec::new(),
            cooldown_until: None,
        }
    }

    /// Prune all timestamps older than `cutoff`.
    fn prune(&mut self, cutoff: Instant) {
        self.egress_timestamps.retain(|t| *t >= cutoff);
        self.counted_egress_timestamps.retain(|t| *t >= cutoff);
        self.destinations.retain(|(_, t)| *t >= cutoff);
        self.ports.retain(|(_, t)| *t >= cutoff);
        self.read_timestamps.retain(|t| *t >= cutoff);
        if let Some(until) = self.cooldown_until {
            if until <= Instant::now() {
                self.cooldown_until = None;
            }
        }
    }
}

/// Filter that enforces per-session outbound egress rate controls.
///
/// Runs in Phase 3 (Context) because it depends on accumulated per-session state.
///
/// Tracks per-session:
/// - Outbound egress syscall count (HttpRequest, NetConnect)
/// - Unique destination hosts and ports
/// - Read-then-send spike patterns (FileRead bursts followed by egress)
/// - Burst detection with cool-down enforcement
///
/// Scoring:
/// - `+5.0` read-then-send spike (strong exfil signal)
/// - `+4.0` egress burst detected
/// - `+3.0` unique destination spread exceeded
/// - `+2.5` unique port spread exceeded
/// - `+2.0` egress rate exceeded
/// - `+1.5` egress during cooldown period
pub struct EgressRateFilter {
    config: EgressRateConfig,
    /// Operator-global trusted destination domains (mirrors egress-policy's
    /// `trusted_domains`). Egress to a trusted destination is excluded from the
    /// volumetric anomaly counters (A#2).
    trusted_domains: HashSet<String>,
    /// Per-profile trusted destinations (mirrors egress-policy's
    /// `profile_trusted`), keyed by lowercased profile name from the
    /// `ToolCallContext`.
    profile_trusted: HashMap<String, HashSet<String>>,
    sessions: Mutex<HashMap<Uuid, SessionEgressState>>,
}

impl EgressRateFilter {
    pub fn from_config(config: EgressRateConfig) -> Self {
        Self::from_config_with_trust(config, Vec::new(), HashMap::new())
    }

    /// Construct with destination-trust awareness so routine/allowlisted egress
    /// is excluded from the volumetric anomaly counters (A#2). The trust inputs
    /// mirror the egress-policy filter's `trusted_domains` /
    /// `profile_trusted_domains` so the two filters agree on what "routine"
    /// means. In supervisor mode a session-allowlisted destination already
    /// bypasses the proxy entirely; this exemption is the backstop for the two
    /// paths where that bypass does not apply — the built-in agent (Path 1) and
    /// a supervised session under containment, where the allowlist is not
    /// consulted and every call runs the full pipeline.
    pub fn from_config_with_trust(
        config: EgressRateConfig,
        trusted_domains: Vec<String>,
        profile_trusted_domains: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            config,
            trusted_domains: normalize_domain_set(trusted_domains),
            profile_trusted: profile_trusted_domains
                .into_iter()
                .map(|(name, domains)| (name.to_lowercase(), normalize_domain_set(domains)))
                .collect(),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::from_config(EgressRateConfig::default())
    }

    /// True when the current egress call targets an operator- or profile-trusted
    /// destination — a routine/allowlisted host that must not count toward the
    /// volumetric anomaly signals (burst / rate / spread).
    fn is_routine_destination(&self, ctx: &ToolCallContext) -> bool {
        let Some(host) = Self::extract_destination_host(&ctx.call_type) else {
            return false;
        };
        if host_in_domain_set(&self.trusted_domains, &host) {
            return true;
        }
        ctx.profile_name
            .as_ref()
            .and_then(|name| self.profile_trusted.get(&name.to_lowercase()))
            .is_some_and(|set| host_in_domain_set(set, &host))
    }

    /// Check whether a call type is an outbound egress call.
    fn is_egress(call_type: &ToolCallType) -> bool {
        matches!(
            call_type,
            ToolCallType::HttpRequest { .. } | ToolCallType::NetConnect { .. }
        )
    }

    /// Check whether a call type is a source read.
    fn is_source_read(call_type: &ToolCallType) -> bool {
        matches!(call_type, ToolCallType::FileRead { .. })
    }

    /// Extract the destination host from a tool call, if applicable.
    fn extract_destination_host(call_type: &ToolCallType) -> Option<String> {
        match call_type {
            ToolCallType::HttpRequest { url, .. } => {
                // Extract host from URL: scheme://[user@]host[:port]/...
                let rest = url.split("://").nth(1)?;
                let authority = rest.split('/').next().unwrap_or(rest);
                let authority = authority.rsplit('@').next().unwrap_or(authority);
                // Strip port
                let host = if authority.starts_with('[') {
                    // IPv6: [::1]:port
                    authority.split(']').next().map(|h| &h[1..])
                } else {
                    Some(authority.rsplit_once(':').map_or(authority, |(h, _)| h))
                };
                host.map(|h| h.to_lowercase())
            }
            ToolCallType::NetConnect { address, .. } => Some(address.to_lowercase()),
            _ => None,
        }
    }

    /// Extract the destination port from a tool call, if applicable.
    fn extract_destination_port(call_type: &ToolCallType) -> Option<u16> {
        match call_type {
            ToolCallType::HttpRequest { url, .. } => {
                let rest = url.split("://").nth(1)?;
                let authority = rest.split('/').next().unwrap_or(rest);
                let authority = authority.rsplit('@').next().unwrap_or(authority);
                if authority.starts_with('[') {
                    // IPv6
                    authority
                        .split(']')
                        .nth(1)?
                        .strip_prefix(':')
                        .and_then(|p| p.parse().ok())
                } else {
                    authority.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
                }
                .or_else(|| {
                    // Default port from scheme
                    let scheme = url.split("://").next()?;
                    match scheme {
                        "https" | "wss" => Some(443),
                        "http" | "ws" => Some(80),
                        _ => None,
                    }
                })
            }
            ToolCallType::NetConnect { port, .. } => Some(*port),
            _ => None,
        }
    }

    /// Check for read-then-send spike: many file reads followed by egress calls.
    fn check_read_then_send(
        &self,
        state: &SessionEgressState,
        now: Instant,
    ) -> Option<FilterResult> {
        let read_window_start =
            instant_sub(now, Duration::from_secs(self.config.read_window_seconds));
        let recent_reads = state
            .read_timestamps
            .iter()
            .filter(|t| **t >= read_window_start)
            .count() as u32;
        let recent_egress = state
            .egress_timestamps
            .iter()
            .filter(|t| **t >= read_window_start)
            .count() as u32;

        if recent_reads >= self.config.read_spike_threshold
            && recent_egress >= self.config.read_then_send_egress_threshold
        {
            Some(FilterResult::matched(
                "egress-rate",
                "read-then-send-spike",
                5.0,
                Severity::Critical,
                format!(
                    "Read-then-send spike: {recent_reads} reads + {recent_egress} egress in {}s window",
                    self.config.read_window_seconds
                ),
            ))
        } else {
            None
        }
    }

    /// Check for egress burst: too many outbound calls in a short window.
    fn check_burst(&self, state: &mut SessionEgressState, now: Instant) -> Option<FilterResult> {
        let burst_window_start =
            instant_sub(now, Duration::from_secs(self.config.burst_window_seconds));
        let burst_count = state
            .counted_egress_timestamps
            .iter()
            .filter(|t| **t >= burst_window_start)
            .count() as u32;

        if burst_count >= self.config.burst_threshold {
            state.cooldown_until = Some(now + Duration::from_secs(self.config.cooldown_seconds));
            Some(FilterResult::matched(
                "egress-rate",
                "egress-burst",
                4.0,
                Severity::Error,
                format!(
                    "Egress burst: {burst_count} outbound calls in {}s (threshold: {})",
                    self.config.burst_window_seconds, self.config.burst_threshold
                ),
            ))
        } else {
            None
        }
    }

    /// Check for unique destination spread exceeding the per-minute limit.
    fn check_dest_spread(&self, state: &SessionEgressState) -> Option<FilterResult> {
        let unique_dests: HashSet<&str> =
            state.destinations.iter().map(|(h, _)| h.as_str()).collect();
        if unique_dests.len() as u32 > self.config.max_unique_destinations_per_minute {
            Some(FilterResult::matched(
                "egress-rate",
                "egress-dest-spread",
                3.0,
                Severity::Error,
                format!(
                    "Destination spread: {} unique hosts/min (limit: {})",
                    unique_dests.len(),
                    self.config.max_unique_destinations_per_minute
                ),
            ))
        } else {
            None
        }
    }

    /// Check for unique port spread exceeding the per-minute limit.
    fn check_port_spread(&self, state: &SessionEgressState) -> Option<FilterResult> {
        let unique_ports: HashSet<u16> = state.ports.iter().map(|(p, _)| *p).collect();
        if unique_ports.len() as u32 > self.config.max_unique_ports_per_minute {
            Some(FilterResult::matched(
                "egress-rate",
                "egress-port-spread",
                2.5,
                Severity::Warning,
                format!(
                    "Port spread: {} unique ports/min (limit: {})",
                    unique_ports.len(),
                    self.config.max_unique_ports_per_minute
                ),
            ))
        } else {
            None
        }
    }

    /// Check if the egress rate (calls per minute) has been exceeded.
    fn check_rate_exceeded(&self, state: &SessionEgressState) -> Option<FilterResult> {
        let egress_count = state.counted_egress_timestamps.len() as u32;
        if egress_count > self.config.max_egress_per_minute {
            Some(FilterResult::matched(
                "egress-rate",
                "egress-rate-exceeded",
                2.0,
                Severity::Warning,
                format!(
                    "Egress rate exceeded: {egress_count} outbound calls/min (limit: {})",
                    self.config.max_egress_per_minute
                ),
            ))
        } else {
            None
        }
    }

    /// Check if the session is in a post-burst cooldown period.
    fn check_cooldown(&self, state: &SessionEgressState, now: Instant) -> Option<FilterResult> {
        if let Some(until) = state.cooldown_until {
            if now < until {
                return Some(FilterResult::matched(
                    "egress-rate",
                    "egress-cooldown",
                    1.5,
                    Severity::Notice,
                    format!(
                        "Egress during cooldown ({:.0}s remaining)",
                        (until - now).as_secs_f64()
                    ),
                ));
            }
        }
        None
    }

    /// Evaluate using a specific `Instant` (for testability).
    fn evaluate_at(
        &self,
        ctx: &ToolCallContext,
        now: Instant,
    ) -> crate::error::Result<FilterResult> {
        let is_egress = Self::is_egress(&ctx.call_type);
        let is_read = Self::is_source_read(&ctx.call_type);

        // Only track egress and read calls.
        if !is_egress && !is_read {
            return Ok(FilterResult::no_match("egress-rate"));
        }

        // Resolve routine-ness before locking (borrows `self`, not the session
        // map). Only egress calls carry a destination.
        let routine = is_egress && self.is_routine_destination(ctx);

        let mut sessions = self.sessions.lock().expect("lock poisoned");
        let state = sessions
            .entry(ctx.session_id)
            .or_insert_with(SessionEgressState::new);

        // Prune old entries (anything older than 1 minute).
        let one_minute_ago = instant_sub(now, Duration::from_secs(60));
        state.prune(one_minute_ago);

        // Record reads for read-then-send tracking.
        if is_read {
            state.read_timestamps.push(now);
            return Ok(FilterResult::no_match("egress-rate"));
        }

        // --- From here on, it's an egress call ---

        // Record every egress call for the read-then-send correlation signal —
        // this stays sensitive regardless of destination trust.
        state.egress_timestamps.push(now);

        // Routine/allowlisted destinations are the expected baseline: exclude
        // them from the volumetric anomaly counters (burst / rate / spread) so
        // a browser's routine startup burst to trusted infrastructure does not
        // flag. Non-routine egress is counted and its host/port recorded.
        if !routine {
            state.counted_egress_timestamps.push(now);
            if let Some(host) = Self::extract_destination_host(&ctx.call_type) {
                state.destinations.push((host, now));
            }
            if let Some(port) = Self::extract_destination_port(&ctx.call_type) {
                state.ports.push((port, now));
            }
        }

        let mut best: Option<FilterResult> = None;
        best = select_higher(best, self.check_read_then_send(state, now));
        best = select_higher(best, self.check_burst(state, now));
        best = select_higher(best, self.check_dest_spread(state));
        best = select_higher(best, self.check_port_spread(state));
        best = select_higher(best, self.check_rate_exceeded(state));
        best = select_higher(best, self.check_cooldown(state, now));

        Ok(best.unwrap_or_else(|| FilterResult::no_match("egress-rate")))
    }
}

/// Subtract a duration from an instant, returning the earliest possible instant
/// if the subtraction would underflow.
fn instant_sub(instant: Instant, duration: Duration) -> Instant {
    instant.checked_sub(duration).unwrap_or(instant)
}

/// Normalise a domain list into a lowercase, wildcard/dot-stripped set for
/// suffix matching (mirrors egress-policy's `normalize_domains` so the two
/// filters agree on trust). `*.foo.com` and `.foo.com` both normalise to
/// `foo.com`.
fn normalize_domain_set(values: Vec<String>) -> HashSet<String> {
    values
        .into_iter()
        .map(|v| {
            v.trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .to_lowercase()
        })
        .filter(|v| !v.is_empty())
        .collect()
}

/// Suffix-match a host against a normalised domain set: `api.foo.com` matches
/// `foo.com`, but `evilfoo.com` does not (mirrors egress-policy's
/// `domain_matches`).
fn host_in_domain_set(domains: &HashSet<String>, host: &str) -> bool {
    let host = host.to_lowercase();
    domains
        .iter()
        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

fn select_higher(
    current: Option<FilterResult>,
    next: Option<FilterResult>,
) -> Option<FilterResult> {
    match (current, next) {
        (None, rhs) => rhs,
        (lhs, None) => lhs,
        (Some(lhs), Some(rhs)) => {
            if rhs.score > lhs.score {
                Some(rhs)
            } else {
                Some(lhs)
            }
        }
    }
}

#[async_trait::async_trait]
impl SecurityFilter for EgressRateFilter {
    fn name(&self) -> &str {
        "egress-rate"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Context
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        self.evaluate_at(ctx, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(call_type: ToolCallType, session_id: Uuid) -> ToolCallContext {
        ToolCallContext::new("test", call_type, session_id)
    }

    fn small_limit_config() -> EgressRateConfig {
        EgressRateConfig {
            enabled: true,
            max_egress_per_minute: 5,
            max_unique_destinations_per_minute: 3,
            max_unique_ports_per_minute: 3,
            burst_threshold: 4,
            burst_window_seconds: 10,
            cooldown_seconds: 30,
            read_spike_threshold: 3,
            read_window_seconds: 15,
            read_then_send_egress_threshold: 2,
        }
    }

    // ── Destination extraction ──────────────────────────────────────

    #[test]
    fn extract_host_from_http_request() {
        let ct = ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com/v1/data".into(),
        };
        assert_eq!(
            EgressRateFilter::extract_destination_host(&ct),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn extract_host_from_http_with_port() {
        let ct = ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com:8443/v1/data".into(),
        };
        assert_eq!(
            EgressRateFilter::extract_destination_host(&ct),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn extract_host_from_net_connect() {
        let ct = ToolCallType::NetConnect {
            address: "10.0.0.1".into(),
            port: 443,
        };
        assert_eq!(
            EgressRateFilter::extract_destination_host(&ct),
            Some("10.0.0.1".into())
        );
    }

    #[test]
    fn extract_port_from_net_connect() {
        let ct = ToolCallType::NetConnect {
            address: "10.0.0.1".into(),
            port: 8080,
        };
        assert_eq!(EgressRateFilter::extract_destination_port(&ct), Some(8080));
    }

    #[test]
    fn extract_port_from_https_url_default() {
        let ct = ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://example.com/path".into(),
        };
        assert_eq!(EgressRateFilter::extract_destination_port(&ct), Some(443));
    }

    #[test]
    fn extract_port_from_url_explicit() {
        let ct = ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://example.com:9090/path".into(),
        };
        assert_eq!(EgressRateFilter::extract_destination_port(&ct), Some(9090));
    }

    #[test]
    fn extract_host_returns_none_for_file_read() {
        let ct = ToolCallType::FileRead {
            path: "/etc/passwd".into(),
        };
        assert_eq!(EgressRateFilter::extract_destination_host(&ct), None);
    }

    // ── Classification ──────────────────────────────────────────────

    #[test]
    fn is_egress_for_network_calls() {
        assert!(EgressRateFilter::is_egress(&ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://x.com".into(),
        }));
        assert!(EgressRateFilter::is_egress(&ToolCallType::NetConnect {
            address: "1.2.3.4".into(),
            port: 443,
        }));
    }

    #[test]
    fn is_egress_false_for_file_ops() {
        assert!(!EgressRateFilter::is_egress(&ToolCallType::FileRead {
            path: "/tmp/x".into(),
        }));
        assert!(!EgressRateFilter::is_egress(&ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec![],
        }));
    }

    #[test]
    fn is_source_read_correct() {
        assert!(EgressRateFilter::is_source_read(&ToolCallType::FileRead {
            path: "/tmp/x".into(),
        }));
        assert!(!EgressRateFilter::is_source_read(
            &ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://x.com".into(),
            }
        ));
    }

    // ── No-match for non-egress, non-read calls ─────────────────────

    #[tokio::test]
    async fn non_egress_non_read_returns_no_match() {
        let filter = EgressRateFilter::with_defaults();
        let ctx = make_ctx(
            ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![],
            },
            Uuid::new_v4(),
        );
        let result = filter.evaluate_at(&ctx, Instant::now()).unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn file_read_returns_no_match() {
        let filter = EgressRateFilter::with_defaults();
        let ctx = make_ctx(
            ToolCallType::FileRead {
                path: "/tmp/x".into(),
            },
            Uuid::new_v4(),
        );
        let result = filter.evaluate_at(&ctx, Instant::now()).unwrap();
        assert!(!result.matched);
    }

    // ── Egress rate exceeded ────────────────────────────────────────

    #[tokio::test]
    async fn egress_rate_exceeded() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();

        // Make 5 egress calls spaced out (under burst threshold).
        for i in 0..5 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "10.0.0.1".into(),
                    port: 443,
                },
                session,
            );
            let _ = filter.evaluate_at(&ctx, now + Duration::from_secs(i * 3));
        }

        // 6th call exceeds max_egress_per_minute=5.
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "10.0.0.1".into(),
                port: 443,
            },
            session,
        );
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_secs(18))
            .unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "egress-rate-exceeded");
        assert_eq!(result.score, 2.0);
    }

    // ── Destination spread ──────────────────────────────────────────

    #[tokio::test]
    async fn destination_spread_exceeded() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();

        // Hit 4 unique destinations (limit is 3).
        let hosts = ["a.com", "b.com", "c.com", "d.com"];
        for (i, host) in hosts.iter().enumerate() {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: (*host).to_string(),
                    port: 443,
                },
                session,
            );
            let _ = filter.evaluate_at(&ctx, now + Duration::from_secs(i as u64 * 3));
        }

        // The 4th call should trigger dest spread.
        let sessions = filter.sessions.lock().unwrap();
        let state = sessions.get(&session).unwrap();
        let unique: HashSet<&str> = state.destinations.iter().map(|(h, _)| h.as_str()).collect();
        assert!(unique.len() as u32 > small_limit_config().max_unique_destinations_per_minute);
        drop(sessions);

        // Next call will also flag it.
        let ctx = make_ctx(
            ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://e.com/data".into(),
            },
            session,
        );
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_secs(15))
            .unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "egress-dest-spread");
        assert_eq!(result.score, 3.0);
    }

    // ── Port spread ─────────────────────────────────────────────────

    #[tokio::test]
    async fn port_spread_exceeded() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();

        // Hit 4 unique ports (limit is 3).
        let ports = [80, 443, 8080, 9090];
        for (i, port) in ports.iter().enumerate() {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "10.0.0.1".into(),
                    port: *port,
                },
                session,
            );
            let _ = filter.evaluate_at(&ctx, now + Duration::from_secs(i as u64 * 3));
        }

        // 5th call — destination and port spread should both trigger,
        // but dest-spread (3.0) > port-spread (2.5).
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "10.0.0.1".into(),
                port: 5555,
            },
            session,
        );
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_secs(15))
            .unwrap();
        assert!(result.matched);
        // The highest scoring rule wins — could be rate-exceeded or port-spread or dest-spread.
        assert!(result.score >= 2.5);
    }

    // ── Burst detection ─────────────────────────────────────────────

    #[tokio::test]
    async fn burst_detected() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();

        // 4 calls within 10s (burst_threshold=4).
        for i in 0..4 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "10.0.0.1".into(),
                    port: 443,
                },
                session,
            );
            let _ = filter.evaluate_at(&ctx, now + Duration::from_millis(i * 500));
        }

        // 5th call in the window should see burst already flagged on 4th.
        // Let's check the 4th call result.
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "10.0.0.1".into(),
                port: 443,
            },
            session,
        );
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_millis(2500))
            .unwrap();
        assert!(result.matched);
        // Burst (4.0) > rate-exceeded (2.0).
        assert_eq!(result.rule_id, "egress-burst");
        assert_eq!(result.score, 4.0);
    }

    // ── Cooldown enforcement ────────────────────────────────────────

    #[tokio::test]
    async fn cooldown_enforced_after_burst() {
        let cfg = EgressRateConfig {
            max_egress_per_minute: 100, // High limit so rate-exceeded doesn't trigger
            burst_threshold: 3,
            burst_window_seconds: 5,
            cooldown_seconds: 30,
            ..small_limit_config()
        };
        let filter = EgressRateFilter::from_config(cfg);
        let session = Uuid::new_v4();
        let now = Instant::now();

        // Trigger a burst (3 calls in 5s).
        for i in 0..3 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "10.0.0.1".into(),
                    port: 443,
                },
                session,
            );
            let _ = filter.evaluate_at(&ctx, now + Duration::from_millis(i * 100));
        }

        // After burst window passes but within cooldown (30s), egress should
        // still be flagged with cooldown.
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "10.0.0.1".into(),
                port: 443,
            },
            session,
        );
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_secs(15))
            .unwrap();
        assert!(result.matched);
        // The cooldown result (1.5) should be present; burst might still be active
        // if the 15s call is within burst window of itself... actually burst_window=5s
        // so only calls within 5s count. At t=15, only this call is in the window.
        // But cooldown_until is still active (set to ~30s after burst).
        assert_eq!(result.rule_id, "egress-cooldown");
        assert_eq!(result.score, 1.5);
    }

    // ── Read-then-send spike ────────────────────────────────────────

    #[tokio::test]
    async fn read_then_send_spike_detected() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();

        // Simulate 3 file reads (read_spike_threshold=3).
        for i in 0..3 {
            let ctx = make_ctx(
                ToolCallType::FileRead {
                    path: format!("/secrets/key_{i}.pem"),
                },
                session,
            );
            let _ = filter.evaluate_at(&ctx, now + Duration::from_secs(i));
        }

        // Now send 2 egress calls (read_then_send_egress_threshold=2).
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "evil.com".into(),
                port: 443,
            },
            session,
        );
        let _ = filter.evaluate_at(&ctx, now + Duration::from_secs(5));

        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "evil.com".into(),
                port: 443,
            },
            session,
        );
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_secs(6))
            .unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "read-then-send-spike");
        assert_eq!(result.score, 5.0);
    }

    #[tokio::test]
    async fn read_then_send_not_triggered_without_enough_reads() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();

        // Only 1 read (threshold is 3).
        let ctx = make_ctx(
            ToolCallType::FileRead {
                path: "/tmp/x".into(),
            },
            session,
        );
        let _ = filter.evaluate_at(&ctx, now);

        // 2 egress calls.
        for i in 1..=2 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "evil.com".into(),
                    port: 443,
                },
                session,
            );
            let result = filter
                .evaluate_at(&ctx, now + Duration::from_secs(i))
                .unwrap();
            assert_ne!(result.rule_id, "read-then-send-spike");
        }
    }

    // ── Session isolation ───────────────────────────────────────────

    #[tokio::test]
    async fn sessions_are_isolated() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();
        let now = Instant::now();

        // Flood session A.
        for i in 0..6 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "10.0.0.1".into(),
                    port: 443,
                },
                session_a,
            );
            let _ = filter.evaluate_at(&ctx, now + Duration::from_secs(i * 3));
        }

        // Session B should be unaffected.
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "10.0.0.1".into(),
                port: 443,
            },
            session_b,
        );
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_secs(20))
            .unwrap();
        assert!(!result.matched);
    }

    // ── Old entries pruned ──────────────────────────────────────────

    #[tokio::test]
    async fn old_entries_pruned() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();

        // 5 calls more than 60s ago.
        let old = now - Duration::from_secs(120);
        for i in 0..5 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "10.0.0.1".into(),
                    port: 443,
                },
                session,
            );
            let _ = filter.evaluate_at(&ctx, old + Duration::from_secs(i));
        }

        // New call at `now` should not be affected.
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "10.0.0.1".into(),
                port: 443,
            },
            session,
        );
        let result = filter.evaluate_at(&ctx, now).unwrap();
        assert!(!result.matched);
    }

    // ── Under limits returns no match ───────────────────────────────

    #[tokio::test]
    async fn under_limits_no_match() {
        let filter = EgressRateFilter::with_defaults();
        let session = Uuid::new_v4();
        let ctx = make_ctx(
            ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://api.example.com/data".into(),
            },
            session,
        );
        let result = filter.evaluate_at(&ctx, Instant::now()).unwrap();
        assert!(!result.matched);
    }

    // ── Default config ──────────────────────────────────────────────

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = EgressRateConfig::default();
        assert_eq!(cfg.max_egress_per_minute, 30);
        assert_eq!(cfg.max_unique_destinations_per_minute, 10);
        assert_eq!(cfg.max_unique_ports_per_minute, 8);
        assert_eq!(cfg.burst_threshold, 8);
        assert_eq!(cfg.cooldown_seconds, 30);
        assert_eq!(cfg.read_spike_threshold, 10);
    }

    // ── A#2: routine-destination exemption from volumetric counters ──

    /// A rapid burst of egress to a *trusted* destination must not trip the
    /// burst / rate / spread signals — this is the headless-browser startup
    /// storm the exemption exists to silence.
    #[tokio::test]
    async fn routine_destination_burst_not_flagged() {
        let filter = EgressRateFilter::from_config_with_trust(
            small_limit_config(),
            vec!["trusted.example.com".into()],
            HashMap::new(),
        );
        let session = Uuid::new_v4();
        let now = Instant::now();
        // 6 rapid calls: > burst_threshold(4), > max_egress_per_minute(5).
        for i in 0..6 {
            let ctx = make_ctx(
                ToolCallType::HttpRequest {
                    method: "GET".into(),
                    url: "https://api.trusted.example.com/v1/x".into(),
                },
                session,
            );
            let result = filter
                .evaluate_at(&ctx, now + Duration::from_millis(i * 200))
                .unwrap();
            assert!(
                !result.matched,
                "routine burst must not flag (call {i}, rule {})",
                result.rule_id
            );
        }
    }

    /// The same burst to an *untrusted* destination must still flag — the
    /// exemption is destination-scoped, not a blanket disable.
    #[tokio::test]
    async fn non_routine_burst_still_flagged() {
        let filter = EgressRateFilter::from_config_with_trust(
            small_limit_config(),
            vec!["trusted.example.com".into()],
            HashMap::new(),
        );
        let session = Uuid::new_v4();
        let now = Instant::now();
        let mut flagged = false;
        for i in 0..5 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "evil.example.net".into(),
                    port: 443,
                },
                session,
            );
            let result = filter
                .evaluate_at(&ctx, now + Duration::from_millis(i * 200))
                .unwrap();
            if result.rule_id == "egress-burst" {
                flagged = true;
            }
        }
        assert!(flagged, "untrusted burst must still flag");
    }

    /// The read-then-send exfil correlation stays sensitive even when the send
    /// targets a trusted destination — routine egress is still recorded for
    /// this signal (defence-in-depth against a mis-curated trust list).
    #[tokio::test]
    async fn read_then_send_fires_even_to_trusted_destination() {
        let filter = EgressRateFilter::from_config_with_trust(
            small_limit_config(), // read_spike=3, read_then_send_egress=2
            vec!["trusted.example.com".into()],
            HashMap::new(),
        );
        let session = Uuid::new_v4();
        let now = Instant::now();
        for i in 0..3 {
            let ctx = make_ctx(
                ToolCallType::FileRead {
                    path: format!("/secrets/k{i}.pem"),
                },
                session,
            );
            let _ = filter.evaluate_at(&ctx, now + Duration::from_secs(i));
        }
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "trusted.example.com".into(),
                port: 443,
            },
            session,
        );
        let _ = filter.evaluate_at(&ctx, now + Duration::from_secs(4));
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "trusted.example.com".into(),
                port: 443,
            },
            session,
        );
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_secs(5))
            .unwrap();
        assert_eq!(result.rule_id, "read-then-send-spike");
    }

    /// Profile-scoped trust: per-request random CDN subdomains (gvt1.com) under
    /// the profile's trusted set are exempt from both burst and dest-spread,
    /// keyed off `ctx.profile_name`.
    #[tokio::test]
    async fn profile_trusted_destination_burst_not_flagged() {
        let mut profile_trusted = HashMap::new();
        profile_trusted.insert("codex".to_string(), vec!["gvt1.com".to_string()]);
        let filter =
            EgressRateFilter::from_config_with_trust(small_limit_config(), vec![], profile_trusted);
        let session = Uuid::new_v4();
        let now = Instant::now();
        // 6 distinct random subdomains — would trip dest-spread(3) and burst(4)
        // if counted, but all match gvt1.com for the codex profile.
        for i in 0..6 {
            let mut ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: format!("r{i}---sn-abc.gvt1.com"),
                    port: 443,
                },
                session,
            );
            ctx.profile_name = Some("codex".into());
            let result = filter
                .evaluate_at(&ctx, now + Duration::from_millis(i * 200))
                .unwrap();
            assert!(
                !result.matched,
                "profile-trusted burst must not flag (call {i}, rule {})",
                result.rule_id
            );
        }
    }
}
