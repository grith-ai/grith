// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Egress rate limiting filter for outbound data volume control.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{
    CallOutcome, FilterResult, SessionScopeKey, Severity, ToolCallContext, ToolCallType,
    UnixSocketClass,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
// NOTE(M-4): std::sync::Mutex is intentionally used here instead of
// tokio::sync::Mutex because the lock is never held across .await points.
// The evaluate() method delegates to the synchronous evaluate_at(), so
// std::sync::Mutex is the more efficient choice.
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
    /// Distinct refused destinations in the retention window before the
    /// blocked-spread signal starts scoring.
    pub blocked_spread_notice_threshold: u32,
    /// Distinct refused destinations before blocked-spread reaches its ceiling.
    pub blocked_spread_warning_threshold: u32,
    /// The blocked-spread ceiling. This is a hard cap, NOT a per-destination
    /// increment: the 6th and the 600th refused destination score identically,
    /// so no volume of refusal can drive a deny on its own.
    pub blocked_spread_max_score: f64,
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
            blocked_spread_notice_threshold: 3,
            blocked_spread_warning_threshold: 6,
            blocked_spread_max_score: 2.0,
        }
    }
}

/// How far back the volumetric windows look, and how long committed state is
/// retained.
///
/// Every windowed check applies this internally. That is load-bearing rather
/// than belt-and-braces: the checks used to be correct only because
/// `state.prune()` ran microseconds earlier inside `evaluate`. Now that pruning
/// happens on the commit path, a session whose egress is all refused commits
/// nothing and would otherwise read unboundedly stale data.
const RETENTION_WINDOW: Duration = Duration::from_secs(60);

/// A destination that was refused. Keyed rather than appended so a retry storm
/// against one host stays one entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AttemptKey {
    host: Option<String>,
    port: Option<u16>,
}

/// The in-flight call, described as the delta it WOULD commit if it ran.
///
/// Checks read committed history plus this candidate, so every threshold stays
/// inclusive of the call being judged - exactly as it was when `evaluate`
/// mutated state before checking it. Nothing here reaches the session until
/// `observe_outcome` says the call actually happened.
struct EgressCandidate {
    is_egress: bool,
    /// Operator- or profile-trusted destination (A#2). Still counts toward the
    /// read-then-send correlation, which is deliberately trust-blind; never
    /// toward the volumetric signals.
    routine: bool,
    host: Option<String>,
    port: Option<u16>,
}

impl EgressCandidate {
    fn counts_volumetric(&self) -> bool {
        self.is_egress && !self.routine
    }
}

/// Per-session egress tracking state.
///
/// Every field is written ONLY by `observe_outcome`, and the gate that governs
/// it is documented at the field. `evaluate` reads these and never writes.
#[derive(Debug)]
struct SessionEgressState {
    /// EVERY egress that reached the pipeline - delivered or refused, routine
    /// or not. Feeds `check_read_then_send` ONLY, which measures intent to
    /// send rather than delivered volume, and is deliberately trust-blind as
    /// defence-in-depth against a mis-curated trust list.
    ///
    /// Committed on Executed, ObservedOnly and Denied. NOT on KernelRefused: a
    /// destination the kernel cannot reach carries no exfil intent, and a
    /// poller against a dead loopback port must not manufacture a signal.
    ///
    /// Counting refusals here cannot amplify. `check_read_then_send` is a
    /// boolean gate emitting a flat score, and `select_higher` returns the
    /// single highest result rather than a sum, so loop gain past the
    /// threshold is exactly zero.
    attempted_egress_timestamps: Vec<Instant>,
    /// Non-routine egress that ACTUALLY RAN. Feeds the volumetric signals
    /// (burst, rate-exceeded). Committed on Executed and ObservedOnly only: a
    /// refused call delivered zero bytes and is not throughput.
    delivered_egress_timestamps: Vec<Instant>,
    /// Hosts that actually RECEIVED data. Same gate - a refused host is not
    /// part of any scatter.
    delivered_destinations: Vec<(String, Instant)>,
    /// Ports that actually received data. Same gate.
    delivered_ports: Vec<(u16, Instant)>,
    /// File reads that ACTUALLY RETURNED DATA. Committed on Executed and
    /// ObservedOnly only. The read-then-send premise is that the agent now
    /// HOLDS sensitive bytes; a blocked read delivered nothing, so counting it
    /// manufactures the reads half of a correlation for data that never
    /// entered the process. Note the deliberate asymmetry with
    /// `attempted_egress_timestamps`, which feeds the same check.
    executed_read_timestamps: Vec<Instant>,
    /// Distinct non-routine destinations that were REFUSED, holding the most
    /// recent attempt per key. Committed on Denied and KernelRefused.
    ///
    /// KEYED, not appended: 44 retries against one host refresh one entry.
    /// That is the whole of retry-dedup - a property of counting destinations
    /// instead of attempts rather than a separate mechanism - and it is what
    /// bounds the map under a retry storm.
    blocked_attempts: HashMap<AttemptKey, Instant>,
    /// If in cooldown, when it expires.
    cooldown_until: Option<Instant>,
}

impl SessionEgressState {
    fn new() -> Self {
        Self {
            attempted_egress_timestamps: Vec::new(),
            delivered_egress_timestamps: Vec::new(),
            delivered_destinations: Vec::new(),
            delivered_ports: Vec::new(),
            executed_read_timestamps: Vec::new(),
            blocked_attempts: HashMap::new(),
            cooldown_until: None,
        }
    }

    /// Drop everything older than `retention` before `now`.
    ///
    /// Takes `now` rather than reading the clock so the whole file honours the
    /// injected-clock contract its tests rely on. The old implementation read
    /// `Instant::now()` for the cooldown expiry alone, which under the
    /// evaluate/observe split would let one logical evaluation see a cooldown
    /// as both live and expired.
    fn prune(&mut self, now: Instant, retention: Duration) {
        let cutoff = instant_sub(now, retention);
        self.attempted_egress_timestamps.retain(|t| *t >= cutoff);
        self.delivered_egress_timestamps.retain(|t| *t >= cutoff);
        self.delivered_destinations.retain(|(_, t)| *t >= cutoff);
        self.delivered_ports.retain(|(_, t)| *t >= cutoff);
        self.executed_read_timestamps.retain(|t| *t >= cutoff);
        self.blocked_attempts.retain(|_, t| *t >= cutoff);
        if let Some(until) = self.cooldown_until {
            if until <= now {
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
    sessions: Mutex<HashMap<SessionScopeKey, SessionEgressState>>,
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
        let Some(host) = Self::extract_destination_host(ctx) else {
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

    /// Check whether a call is an outbound egress call.
    ///
    /// Takes the full context (not just the call type) so the supervisor's
    /// unix-socket classification is visible: a `Control`-labelled connect
    /// (session D-Bus, X11, tmux/screen) is desktop control-injection IPC,
    /// not data egress — in the v0.2.5 FP regression `gh auth token` (keyring
    /// lookup over the session bus) and `xclip` (X11) scored as unknown
    /// outbound destinations and queued/denied. `Privileged` (docker.sock,
    /// systemd private) and unlabelled unix connects remain egress: excluding
    /// all unix sockets would strip docker.sock of the read-then-send +5.0
    /// correlation.
    fn is_egress(ctx: &ToolCallContext) -> bool {
        match &ctx.call_type {
            ToolCallType::HttpRequest { .. } => true,
            ToolCallType::NetConnect { .. } => {
                !matches!(ctx.unix_socket_class(), Some(UnixSocketClass::Control))
            }
            _ => false,
        }
    }

    /// Check whether a call type is a source read.
    fn is_source_read(call_type: &ToolCallType) -> bool {
        matches!(call_type, ToolCallType::FileRead { .. })
    }

    /// Extract the destination host from a tool call, if applicable. Takes the
    /// context for signature parity with [`Self::is_egress`]; extraction
    /// itself is label-independent.
    fn extract_destination_host(ctx: &ToolCallContext) -> Option<String> {
        match &ctx.call_type {
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
        cand: &EgressCandidate,
        now: Instant,
    ) -> Option<FilterResult> {
        let read_window_start =
            instant_sub(now, Duration::from_secs(self.config.read_window_seconds));
        let recent_reads = state
            .executed_read_timestamps
            .iter()
            .filter(|t| **t >= read_window_start)
            .count() as u32;
        let recent_egress = state
            .attempted_egress_timestamps
            .iter()
            .filter(|t| **t >= read_window_start)
            .count() as u32
            + u32::from(cand.is_egress);

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
    fn check_burst(
        &self,
        state: &SessionEgressState,
        cand: &EgressCandidate,
        now: Instant,
    ) -> Option<FilterResult> {
        let burst_window_start =
            instant_sub(now, Duration::from_secs(self.config.burst_window_seconds));
        let burst_count = state
            .delivered_egress_timestamps
            .iter()
            .filter(|t| **t >= burst_window_start)
            .count() as u32
            + u32::from(cand.counts_volumetric());

        if burst_count >= self.config.burst_threshold {
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
    fn check_dest_spread(
        &self,
        state: &SessionEgressState,
        cand: &EgressCandidate,
        now: Instant,
    ) -> Option<FilterResult> {
        let window_start = instant_sub(now, RETENTION_WINDOW);
        let mut unique_dests: HashSet<&str> = state
            .delivered_destinations
            .iter()
            .filter(|(_, t)| *t >= window_start)
            .map(|(h, _)| h.as_str())
            .collect();
        // SET UNION, never `+1`: five connects to one host are one destination,
        // and incrementing instead would falsely trip this on a repeat host.
        if cand.counts_volumetric() {
            if let Some(host) = cand.host.as_deref() {
                unique_dests.insert(host);
            }
        }
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
    fn check_port_spread(
        &self,
        state: &SessionEgressState,
        cand: &EgressCandidate,
        now: Instant,
    ) -> Option<FilterResult> {
        let window_start = instant_sub(now, RETENTION_WINDOW);
        let mut unique_ports: HashSet<u16> = state
            .delivered_ports
            .iter()
            .filter(|(_, t)| *t >= window_start)
            .map(|(p, _)| *p)
            .collect();
        if cand.counts_volumetric() {
            if let Some(port) = cand.port {
                unique_ports.insert(port);
            }
        }
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
    fn check_rate_exceeded(
        &self,
        state: &SessionEgressState,
        cand: &EgressCandidate,
        now: Instant,
    ) -> Option<FilterResult> {
        let window_start = instant_sub(now, RETENTION_WINDOW);
        let egress_count = state
            .delivered_egress_timestamps
            .iter()
            .filter(|t| **t >= window_start)
            .count() as u32
            + u32::from(cand.counts_volumetric());
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

    /// Distinct destinations REFUSED in the retention window.
    ///
    /// This is the one signal a refusal writes, and it exists to preserve the
    /// single thing genuinely lost by not counting refused calls as volume:
    /// enumeration. An agent probing twenty hosts to discover which are
    /// permitted used to trip destination-spread whether or not the probes were
    /// refused; once refusals stop counting as delivered volume, that probing
    /// would otherwise be free and invisible.
    ///
    /// Saturating by construction: the 6th and the 600th refused destination
    /// score identically, so loop gain past the ceiling is exactly zero and no
    /// volume of refusal can drive a deny on its own. It never arms or extends
    /// cooldown. Retries against one host are one key and never reach the band.
    ///
    /// The candidate deliberately does NOT add itself. At evaluate time we do
    /// not yet know whether this call will be refused, and synthesising a
    /// refusal that has not happened would reintroduce the exact "signal caused
    /// by what was attempted" failure this split exists to remove.
    fn check_blocked_spread(
        &self,
        state: &SessionEgressState,
        now: Instant,
    ) -> Option<FilterResult> {
        let window_start = instant_sub(now, RETENTION_WINDOW);
        let distinct = state
            .blocked_attempts
            .values()
            .filter(|t| **t >= window_start)
            .count() as u32;

        if distinct < self.config.blocked_spread_notice_threshold {
            return None;
        }
        let (score, severity) = if distinct >= self.config.blocked_spread_warning_threshold {
            (self.config.blocked_spread_max_score, Severity::Warning)
        } else {
            (1.0, Severity::Notice)
        };
        Some(FilterResult::matched(
            "egress-rate",
            "egress-blocked-spread",
            score,
            severity,
            format!("Blocked-destination spread: {distinct} distinct refused destinations/min"),
        ))
    }

    /// Arm the post-burst cooldown, edge-triggered.
    ///
    /// The previous arm had no guard on the existing value, so it re-armed on
    /// every call while the burst window stayed hot and slid the expiry forward
    /// indefinitely. Combined with counting refusals, that is how a retry storm
    /// produced a cooldown that could never expire. Arming only on the leading
    /// edge means a sustained burst now lets a 30s cooldown lapse - accepted,
    /// because burst itself keeps firing at its own (higher) score throughout,
    /// and `select_higher` reports the higher of the two anyway.
    fn maybe_arm_cooldown(&self, state: &mut SessionEgressState, at: Instant) {
        let start = instant_sub(at, Duration::from_secs(self.config.burst_window_seconds));
        let delivered = state
            .delivered_egress_timestamps
            .iter()
            .filter(|t| **t >= start)
            .count() as u32;
        if delivered < self.config.burst_threshold {
            return;
        }
        if state.cooldown_until.is_some_and(|until| until > at) {
            return;
        }
        state.cooldown_until = Some(at + Duration::from_secs(self.config.cooldown_seconds));
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
    ///
    /// PURE over session state. Call it N times with the same `ctx` and `now`
    /// and you get the same answer N times, with `self.sessions` byte-identical
    /// afterwards. The in-flight call is synthesised as an [`EgressCandidate`]
    /// so every threshold stays inclusive of the call being judged, exactly as
    /// it was when this function mutated state before checking it.
    fn evaluate_at(
        &self,
        ctx: &ToolCallContext,
        now: Instant,
    ) -> crate::error::Result<FilterResult> {
        let is_egress = Self::is_egress(ctx);
        let is_read = Self::is_source_read(&ctx.call_type);

        // Only egress and read calls are tracked; reads contribute to the
        // read-then-send correlation via `observe_outcome` but never produce a
        // result of their own.
        if !is_egress || is_read {
            return Ok(FilterResult::no_match("egress-rate"));
        }

        let cand = EgressCandidate {
            is_egress: true,
            routine: self.is_routine_destination(ctx),
            host: Self::extract_destination_host(ctx),
            port: Self::extract_destination_port(&ctx.call_type),
        };

        let Ok(sessions) = self.sessions.lock() else {
            return Ok(FilterResult::no_match("egress-rate"));
        };
        // `get`, never `entry().or_insert_with()`. Purity has to include the
        // map insert, or every evaluation from a caller that mints a fresh
        // session id per request (the dashboard's proxy-test endpoint) leaks a
        // state entry that nothing will ever evict.
        let empty = SessionEgressState::new();
        let state = sessions.get(&scope_of(ctx)).unwrap_or(&empty);

        let mut best: Option<FilterResult> = None;
        best = select_higher(best, self.check_read_then_send(state, &cand, now));
        best = select_higher(best, self.check_burst(state, &cand, now));
        best = select_higher(best, self.check_dest_spread(state, &cand, now));
        best = select_higher(best, self.check_port_spread(state, &cand, now));
        best = select_higher(best, self.check_rate_exceeded(state, &cand, now));
        best = select_higher(best, self.check_blocked_spread(state, now));
        best = select_higher(best, self.check_cooldown(state, now));

        Ok(best.unwrap_or_else(|| FilterResult::no_match("egress-rate")))
    }

    /// Commit a call's real outcome. See [`SecurityFilter::observe_outcome`].
    fn observe_outcome_at(
        &self,
        ctx: &ToolCallContext,
        outcome: CallOutcome,
        attempt_age: Duration,
        now: Instant,
    ) {
        let is_egress = Self::is_egress(ctx);
        let is_read = Self::is_source_read(&ctx.call_type);
        if !is_egress && !is_read {
            return;
        }

        // Stamp at the ATTEMPT, not at resolution. A queued call can resolve
        // minutes after it was evaluated, while the windows here are seconds:
        // stamping a queued-then-approved egress at `now` would land it after
        // its correlating reads had been pruned, destroying read-then-send for
        // exactly the calls suspicious enough to have been queued.
        let at = instant_sub(now, attempt_age);

        // Never `expect` on the lock in a commit path. Losing one commit
        // under-counts; panicking inside a security supervisor does not fail
        // safe.
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        let state = sessions
            .entry(scope_of(ctx))
            .or_insert_with(SessionEgressState::new);
        state.prune(now, RETENTION_WINDOW);

        if is_read {
            if outcome.executed() {
                state.executed_read_timestamps.push(at);
            }
            return;
        }

        let routine = self.is_routine_destination(ctx);

        // Intent to send: delivered or refused by policy, trusted or not.
        // KernelRefused is excluded - an unreachable destination carries no
        // exfil intent.
        if outcome.executed() || outcome == CallOutcome::Denied {
            state.attempted_egress_timestamps.push(at);
        }

        // Delivered volume: only what actually ran, and only to non-routine
        // destinations (A#2).
        if outcome.executed() && !routine {
            state.delivered_egress_timestamps.push(at);
            if let Some(host) = Self::extract_destination_host(ctx) {
                state.delivered_destinations.push((host, at));
            }
            if let Some(port) = Self::extract_destination_port(&ctx.call_type) {
                state.delivered_ports.push((port, at));
            }
            self.maybe_arm_cooldown(state, at);
        }

        // Refusal pressure: keyed by destination so retries collapse.
        if outcome.suppressed() && !routine {
            state.blocked_attempts.insert(
                AttemptKey {
                    host: Self::extract_destination_host(ctx),
                    port: Self::extract_destination_port(&ctx.call_type),
                },
                at,
            );
        }
    }
}

/// Scope key for filter state.
///
/// Prefer the explicit scope, falling back to the session id so a context
/// predating session scoping still gets isolated state. Keying on the scope
/// rather than the raw session id is what lets `evict_session_state` find the
/// entry at all.
fn scope_of(ctx: &ToolCallContext) -> SessionScopeKey {
    ctx.session_scope
        .unwrap_or_else(|| SessionScopeKey::from_session_id(ctx.session_id))
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

    fn observe_outcome(&self, ctx: &ToolCallContext, outcome: CallOutcome, attempt_age: Duration) {
        self.observe_outcome_at(ctx, outcome, attempt_age, Instant::now());
    }

    /// Drop this scope's state. Possible only because the map is keyed on
    /// `SessionScopeKey`; keyed on the raw session id it could never find the
    /// entry, so state grew for the life of the process.
    fn evict_session_state(&self, scope: SessionScopeKey) -> usize {
        match self.sessions.lock() {
            Ok(mut sessions) => usize::from(sessions.remove(&scope).is_some()),
            Err(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// Evaluate, then immediately commit the call as having run.
    ///
    /// The migration bridge for tests written when `evaluate` mutated state.
    /// Every assertion ported through this helper is byte-identical to the one
    /// it replaced: if a threshold had to move, the candidate synthesis in
    /// `evaluate_at` would be wrong, and that is a failure mode with no
    /// compile error and no other test to catch it.
    fn evaluate_and_execute(
        filter: &EgressRateFilter,
        ctx: &ToolCallContext,
        now: Instant,
    ) -> FilterResult {
        let result = filter
            .evaluate_at(ctx, now)
            .expect("evaluate_at is infallible");
        filter.observe_outcome_at(ctx, CallOutcome::Executed, Duration::ZERO, now);
        result
    }

    /// Commit a call with an explicit outcome at a simulated instant.
    fn observe(
        filter: &EgressRateFilter,
        ctx: &ToolCallContext,
        outcome: CallOutcome,
        now: Instant,
    ) {
        filter.observe_outcome_at(ctx, outcome, Duration::ZERO, now);
    }

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
            blocked_spread_notice_threshold: 3,
            blocked_spread_warning_threshold: 6,
            blocked_spread_max_score: 2.0,
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
            EgressRateFilter::extract_destination_host(&make_ctx(ct, Uuid::new_v4())),
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
            EgressRateFilter::extract_destination_host(&make_ctx(ct, Uuid::new_v4())),
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
            EgressRateFilter::extract_destination_host(&make_ctx(ct, Uuid::new_v4())),
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
        assert_eq!(
            EgressRateFilter::extract_destination_host(&make_ctx(ct, Uuid::new_v4())),
            None
        );
    }

    // ── Classification ──────────────────────────────────────────────

    /// Build a NetConnect ctx carrying the supervisor's unix-socket class
    /// label (`None` = unlabelled, as the LLM path or a pre-label
    /// supervisor would produce).
    /// Re-home a context onto `session`.
    ///
    /// Both fields, deliberately: `ToolCallContext::new` derives
    /// `session_scope` from the session id at construction, and filter state is
    /// keyed on the scope. Setting only `session_id` (as these tests used to)
    /// leaves the context pointing at its original scope.
    fn rehome(ctx: &mut ToolCallContext, session: Uuid) {
        ctx.session_id = session;
        ctx.session_scope = Some(SessionScopeKey::from_session_id(session));
    }

    fn unix_connect_ctx(address: &str, class: Option<&str>) -> ToolCallContext {
        let mut ctx = make_ctx(
            ToolCallType::NetConnect {
                address: address.into(),
                port: 0,
            },
            Uuid::new_v4(),
        );
        if let Some(class) = class {
            ctx.arguments = serde_json::json!({ UnixSocketClass::KEY: class });
        }
        ctx
    }

    #[test]
    fn is_egress_for_network_calls() {
        assert!(EgressRateFilter::is_egress(&make_ctx(
            ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://x.com".into(),
            },
            Uuid::new_v4()
        )));
        assert!(EgressRateFilter::is_egress(&make_ctx(
            ToolCallType::NetConnect {
                address: "1.2.3.4".into(),
                port: 443,
            },
            Uuid::new_v4()
        )));
    }

    #[test]
    fn is_egress_false_for_file_ops() {
        assert!(!EgressRateFilter::is_egress(&make_ctx(
            ToolCallType::FileRead {
                path: "/tmp/x".into(),
            },
            Uuid::new_v4()
        )));
        assert!(!EgressRateFilter::is_egress(&make_ctx(
            ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![],
            },
            Uuid::new_v4()
        )));
    }

    /// Control-class unix connects (session D-Bus, X11) are desktop IPC,
    /// not data egress; Privileged (docker.sock) and unlabelled unix
    /// connects MUST stay egress so the read-then-send correlation keeps
    /// covering them.
    #[test]
    fn is_egress_respects_unix_socket_class() {
        assert!(!EgressRateFilter::is_egress(&unix_connect_ctx(
            "unix:/run/user/1000/bus",
            Some("control")
        )));
        assert!(EgressRateFilter::is_egress(&unix_connect_ctx(
            "unix:/var/run/docker.sock",
            Some("privileged")
        )));
        assert!(EgressRateFilter::is_egress(&unix_connect_ctx(
            "unix:/tmp/app.sock",
            None
        )));
    }

    /// End-to-end correlation gate: a read spike followed by Control-class
    /// connects must not fire read-then-send (desktop IPC is not egress);
    /// the identical spike followed by Privileged connects still does.
    /// Recipe mirrors `read_then_send_spike_detected`.
    #[tokio::test]
    async fn read_then_send_correlation_ignores_control_class() {
        let run = |address: &str, class: &str| {
            let filter = EgressRateFilter::from_config(small_limit_config());
            let session = Uuid::new_v4();
            let now = Instant::now();
            for i in 0..3 {
                let ctx = make_ctx(
                    ToolCallType::FileRead {
                        path: format!("/secrets/key_{i}.pem"),
                    },
                    session,
                );
                let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(i));
            }
            let mut first = unix_connect_ctx(address, Some(class));
            rehome(&mut first, session);
            let _ = evaluate_and_execute(&filter, &first, now + Duration::from_secs(5));
            let mut second = unix_connect_ctx(address, Some(class));
            rehome(&mut second, session);
            evaluate_and_execute(&filter, &second, now + Duration::from_secs(6))
        };

        let control = run("unix:/run/user/1000/bus", "control");
        assert!(
            !control.matched,
            "control-class IPC must not correlate as egress: {}",
            control.message
        );

        let privileged = run("unix:/var/run/docker.sock", "privileged");
        assert!(
            privileged.matched,
            "privileged daemon socket must keep the read-then-send correlation"
        );
        assert_eq!(privileged.rule_id, "read-then-send-spike");
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
        let result = evaluate_and_execute(&filter, &ctx, Instant::now());
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
        let result = evaluate_and_execute(&filter, &ctx, Instant::now());
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
            let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(i * 3));
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
            let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(i as u64 * 3));
        }

        // The 4th call should trigger dest spread.
        let sessions = filter.sessions.lock().unwrap();
        let state = sessions
            .get(&SessionScopeKey::from_session_id(session))
            .unwrap();
        let unique: HashSet<&str> = state
            .delivered_destinations
            .iter()
            .map(|(h, _)| h.as_str())
            .collect();
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
            let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(i as u64 * 3));
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
            let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_millis(i * 500));
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
            let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_millis(i * 100));
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
            let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(i));
        }

        // Now send 2 egress calls (read_then_send_egress_threshold=2).
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "evil.com".into(),
                port: 443,
            },
            session,
        );
        let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(5));

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
        let _ = evaluate_and_execute(&filter, &ctx, now);

        // 2 egress calls.
        for i in 1..=2 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "evil.com".into(),
                    port: 443,
                },
                session,
            );
            let result = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(i));
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
            let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(i * 3));
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
            let _ = evaluate_and_execute(&filter, &ctx, old + Duration::from_secs(i));
        }

        // New call at `now` should not be affected.
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "10.0.0.1".into(),
                port: 443,
            },
            session,
        );
        let result = evaluate_and_execute(&filter, &ctx, now);
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
        let result = evaluate_and_execute(&filter, &ctx, Instant::now());
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
            let result = evaluate_and_execute(&filter, &ctx, now + Duration::from_millis(i * 200));
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
            let result = evaluate_and_execute(&filter, &ctx, now + Duration::from_millis(i * 200));
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
            let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(i));
        }
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "trusted.example.com".into(),
                port: 443,
            },
            session,
        );
        let _ = evaluate_and_execute(&filter, &ctx, now + Duration::from_secs(4));
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
            let result = evaluate_and_execute(&filter, &ctx, now + Duration::from_millis(i * 200));
            assert!(
                !result.matched,
                "profile-trusted burst must not flag (call {i}, rule {})",
                result.rule_id
            );
        }
    }

    // ── Purity and the evaluate/observe split ───────────────────────

    /// `evaluate` must be a predicate, not a recorder. This is the invariant
    /// the whole change rests on.
    #[test]
    fn evaluate_is_pure_over_session_state() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "evil.example.net".into(),
                port: 443,
            },
            session,
        );

        let first = filter.evaluate_at(&ctx, now).unwrap();
        for _ in 0..50 {
            let again = filter.evaluate_at(&ctx, now).unwrap();
            assert_eq!(again.matched, first.matched);
            assert_eq!(again.rule_id, first.rule_id);
            assert_eq!(again.score, first.score);
        }
        assert!(
            filter.sessions.lock().unwrap().is_empty(),
            "a never-committed evaluation must not create session state"
        );
    }

    /// A caller that mints a fresh session per request (the dashboard's
    /// proxy-test endpoint) must not leak a state entry per call.
    #[test]
    fn dashboard_test_evaluation_leaves_no_state() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        for _ in 0..100 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "api.example.com".into(),
                    port: 443,
                },
                Uuid::new_v4(),
            );
            let _ = filter.evaluate_at(&ctx, Instant::now());
        }
        assert!(filter.sessions.lock().unwrap().is_empty());
    }

    /// THE regression. A client retrying a refused destination must not drive
    /// its own score up, and must leave no cooldown tax on unrelated traffic.
    #[test]
    fn refused_retries_do_not_inflate_the_burst_signal() {
        let filter = EgressRateFilter::from_config(EgressRateConfig::default());
        let session = Uuid::new_v4();
        let now = Instant::now();
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "blocked.example.net".into(),
                port: 443,
            },
            session,
        );

        // 44 refused connects inside 10s - the shape that drove the counter
        // from 8 to 44 and re-armed cooldown on every retry.
        for i in 0..44 {
            let at = now + Duration::from_millis(i * 200);
            let result = filter.evaluate_at(&ctx, at).unwrap();
            assert_ne!(
                result.rule_id, "egress-burst",
                "refused retry {i} must not trip the burst signal"
            );
            observe(&filter, &ctx, CallOutcome::Denied, at);
        }

        let sessions = filter.sessions.lock().unwrap();
        let state = sessions
            .get(&SessionScopeKey::from_session_id(session))
            .unwrap();
        assert!(
            state.cooldown_until.is_none(),
            "refusals must never arm cooldown"
        );
        assert_eq!(
            state.blocked_attempts.len(),
            1,
            "44 retries to one host are one destination"
        );
        assert!(state.delivered_egress_timestamps.is_empty());
        drop(sessions);

        // An unrelated destination must not inherit a cooldown tax.
        let other = make_ctx(
            ToolCallType::NetConnect {
                address: "api.example.com".into(),
                port: 443,
            },
            session,
        );
        let result = filter
            .evaluate_at(&other, now + Duration::from_secs(9))
            .unwrap();
        assert!(!result.matched, "unrelated egress must score clean");
    }

    /// Ruling B: the refusal signal measures enumeration, not persistence.
    #[test]
    fn blocked_spread_fires_on_enumeration_not_on_retries() {
        let now = Instant::now();

        let spray = EgressRateFilter::from_config(EgressRateConfig::default());
        let session = Uuid::new_v4();
        for i in 0..8 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: format!("host{i}.example.net"),
                    port: 443,
                },
                session,
            );
            observe(&spray, &ctx, CallOutcome::Denied, now);
        }
        let probe = make_ctx(
            ToolCallType::NetConnect {
                address: "host9.example.net".into(),
                port: 443,
            },
            session,
        );
        let result = spray.evaluate_at(&probe, now).unwrap();
        assert_eq!(result.rule_id, "egress-blocked-spread");
        assert_eq!(
            result.score, 2.0,
            "eight distinct refusals reach the ceiling"
        );

        let retries = EgressRateFilter::from_config(EgressRateConfig::default());
        let session = Uuid::new_v4();
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "one.example.net".into(),
                port: 443,
            },
            session,
        );
        for _ in 0..800 {
            observe(&retries, &ctx, CallOutcome::Denied, now);
        }
        assert!(
            !retries.evaluate_at(&ctx, now).unwrap().matched,
            "800 retries to one destination are one key and must stay silent"
        );
    }

    /// Saturating: no volume of refusal can climb past the ceiling or reach
    /// cooldown, so the signal cannot feed the score that suppressed it.
    #[test]
    fn blocked_spread_saturates_and_never_arms_cooldown() {
        let score_for = |n: u64| {
            let filter = EgressRateFilter::from_config(EgressRateConfig::default());
            let session = Uuid::new_v4();
            let now = Instant::now();
            for i in 0..n {
                let ctx = make_ctx(
                    ToolCallType::NetConnect {
                        address: format!("h{i}.example.net"),
                        port: 443,
                    },
                    session,
                );
                observe(&filter, &ctx, CallOutcome::Denied, now);
            }
            let probe = make_ctx(
                ToolCallType::NetConnect {
                    address: "probe.example.net".into(),
                    port: 443,
                },
                session,
            );
            let score = filter.evaluate_at(&probe, now).unwrap().score;
            let sessions = filter.sessions.lock().unwrap();
            let cooling = sessions
                .get(&SessionScopeKey::from_session_id(session))
                .unwrap()
                .cooldown_until
                .is_some();
            (score, cooling)
        };
        let (six, six_cooling) = score_for(6);
        let (sixty, sixty_cooling) = score_for(60);
        assert_eq!(six, sixty, "the 6th and the 60th must score identically");
        assert!(!six_cooling && !sixty_cooling);
    }

    /// Ruling A: intent to send survives the refusal. Removing this would
    /// leave "read 15 secrets, hammer one blocked host" with no signal at all.
    #[test]
    fn refused_egress_still_feeds_read_then_send() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();
        for i in 0..3 {
            let read = make_ctx(
                ToolCallType::FileRead {
                    path: format!("/secrets/key_{i}.pem"),
                },
                session,
            );
            observe(&filter, &read, CallOutcome::Executed, now);
        }
        let egress = make_ctx(
            ToolCallType::NetConnect {
                address: "blocked.example.net".into(),
                port: 443,
            },
            session,
        );
        observe(&filter, &egress, CallOutcome::Denied, now);

        let result = filter.evaluate_at(&egress, now).unwrap();
        assert_eq!(
            result.rule_id, "read-then-send-spike",
            "a refused send still evidences intent"
        );
    }

    /// The deliberate asymmetry: a blocked read delivered no bytes, so it
    /// cannot supply the "holds sensitive data" half of the correlation.
    #[test]
    fn refused_read_does_not_feed_read_then_send() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();
        let reads: Vec<_> = (0..20)
            .map(|i| {
                make_ctx(
                    ToolCallType::FileRead {
                        path: format!("/secrets/key_{i}.pem"),
                    },
                    session,
                )
            })
            .collect();
        for read in &reads {
            observe(&filter, read, CallOutcome::Denied, now);
        }
        let egress = make_ctx(
            ToolCallType::NetConnect {
                address: "sink.example.net".into(),
                port: 443,
            },
            session,
        );
        observe(&filter, &egress, CallOutcome::Executed, now);
        assert_ne!(
            filter.evaluate_at(&egress, now).unwrap().rule_id,
            "read-then-send-spike",
            "blocked reads must not manufacture the correlation"
        );

        // Approve the same reads and the correlation appears.
        for read in &reads {
            observe(&filter, read, CallOutcome::Executed, now);
        }
        assert_eq!(
            filter.evaluate_at(&egress, now).unwrap().rule_id,
            "read-then-send-spike"
        );
    }

    /// An unreachable destination carries no exfil intent.
    #[test]
    fn kernel_refused_does_not_feed_read_then_send() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();
        for i in 0..20 {
            let read = make_ctx(
                ToolCallType::FileRead {
                    path: format!("/secrets/key_{i}.pem"),
                },
                session,
            );
            observe(&filter, &read, CallOutcome::Executed, now);
        }
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "127.0.0.1".into(),
                port: 9999,
            },
            session,
        );
        for _ in 0..40 {
            observe(&filter, &ctx, CallOutcome::KernelRefused, now);
        }
        let sessions = filter.sessions.lock().unwrap();
        let state = sessions
            .get(&SessionScopeKey::from_session_id(session))
            .unwrap();
        assert!(
            state.attempted_egress_timestamps.is_empty(),
            "an unreachable destination is not intent to send"
        );
        assert!(state.delivered_egress_timestamps.is_empty());
        assert_eq!(state.blocked_attempts.len(), 1);
    }

    /// Thresholds must stay inclusive of the call being judged, or the split
    /// silently loosens every limit by exactly one.
    #[test]
    fn thresholds_stay_inclusive_of_the_in_flight_call() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();
        // small_limit_config: max_egress_per_minute 5.
        for i in 0..5 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: format!("h{i}.example.net"),
                    port: 1000 + i as u16,
                },
                session,
            );
            observe(&filter, &ctx, CallOutcome::Executed, now);
        }
        let sixth = make_ctx(
            ToolCallType::NetConnect {
                address: "h5.example.net".into(),
                port: 1005,
            },
            session,
        );
        assert!(
            filter.evaluate_at(&sixth, now).unwrap().matched,
            "the 6th call must be judged as the 6th, not the 5th"
        );
    }

    /// Repeat hosts must union, not increment.
    #[test]
    fn repeat_host_unions_rather_than_increments() {
        // Burst is lifted out of range deliberately. `select_higher` returns
        // the single highest result, never a sum, so leaving burst (4.0)
        // reachable would mask port-spread (2.5) and the test would assert
        // nothing about spread at all.
        let filter = EgressRateFilter::from_config(EgressRateConfig {
            burst_threshold: 100,
            max_egress_per_minute: 100,
            ..small_limit_config()
        });
        let session = Uuid::new_v4();
        let now = Instant::now();
        // Five deliveries to ONE host across five ports. dest limit 3, port
        // limit 3: port-spread must fire, dest-spread must not.
        for port in 1000..1005u16 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "10.0.0.1".into(),
                    port,
                },
                session,
            );
            observe(&filter, &ctx, CallOutcome::Executed, now);
        }
        let probe = make_ctx(
            ToolCallType::NetConnect {
                address: "10.0.0.1".into(),
                port: 1005,
            },
            session,
        );
        let result = filter.evaluate_at(&probe, now).unwrap();
        assert_ne!(
            result.rule_id, "egress-dest-spread",
            "one host repeated is one destination"
        );
        assert_eq!(result.rule_id, "egress-port-spread");
    }

    /// Windows must hold without prune running on the evaluate path - the
    /// exact trap created by moving state commitment off `evaluate`.
    #[test]
    fn checks_are_window_correct_without_prune() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();
        for i in 0..5 {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: format!("h{i}.example.net"),
                    port: 1000 + i as u16,
                },
                session,
            );
            observe(&filter, &ctx, CallOutcome::Executed, now);
        }
        // Nothing commits again, so prune never runs. The checks must still
        // age the data out on their own.
        let later = make_ctx(
            ToolCallType::NetConnect {
                address: "fresh.example.net".into(),
                port: 443,
            },
            session,
        );
        let result = filter
            .evaluate_at(&later, now + Duration::from_secs(120))
            .unwrap();
        assert!(
            !result.matched,
            "state older than the retention window must not score: {}",
            result.message
        );
    }

    /// A queued call resolves long after its attempt, so the commit must be
    /// stamped at the ATTEMPT.
    ///
    /// Asserts the stored instant itself, not a vector length: a length is
    /// equally true whichever instant was used, so it cannot tell
    /// attempt-stamping from resolution-stamping. Mutating
    /// `observe_outcome_at` to stamp at `now` must fail this test.
    #[test]
    fn late_commit_uses_the_attempt_instant() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();
        let egress = make_ctx(
            ToolCallType::NetConnect {
                address: "sink.example.net".into(),
                port: 443,
            },
            session,
        );

        // Attempted at `now`, approved 40s later.
        let attempt_age = Duration::from_secs(40);
        filter.observe_outcome_at(
            &egress,
            CallOutcome::Executed,
            attempt_age,
            now + attempt_age,
        );

        let sessions = filter.sessions.lock().unwrap();
        let state = sessions
            .get(&SessionScopeKey::from_session_id(session))
            .unwrap();
        let stamped = *state
            .attempted_egress_timestamps
            .first()
            .expect("the approved call must be committed");
        // Stamped at the attempt (`now`), not at resolution (`now + 40s`).
        let skew = if stamped > now {
            stamped - now
        } else {
            now - stamped
        };
        assert!(
            skew < Duration::from_secs(1),
            "commit landed {skew:?} from the attempt instant; \
             resolution-stamping would be ~{attempt_age:?} out"
        );
    }

    /// A queued egress approved within the retention window still correlates
    /// with the reads that preceded it.
    ///
    /// Note this does NOT discriminate attempt- from resolution-stamping: at
    /// this spacing both instants fall inside the read window, and at a
    /// spacing where they would not, the reads have already been pruned. It
    /// pins the correlation itself; `late_commit_uses_the_attempt_instant`
    /// pins the stamping.
    #[test]
    fn a_queued_approval_still_correlates_with_its_reads() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();
        for i in 0..3 {
            let read = make_ctx(
                ToolCallType::FileRead {
                    path: format!("/secrets/key_{i}.pem"),
                },
                session,
            );
            observe(&filter, &read, CallOutcome::Executed, now);
        }
        let egress = make_ctx(
            ToolCallType::NetConnect {
                address: "sink.example.net".into(),
                port: 443,
            },
            session,
        );
        // Attempted alongside the reads, approved 10s later.
        let attempt_age = Duration::from_secs(10);
        filter.observe_outcome_at(
            &egress,
            CallOutcome::Executed,
            attempt_age,
            now + attempt_age,
        );

        // Judged from the attempt's own vantage point, where the reads and the
        // send sit inside one read window.
        let result = filter.evaluate_at(&egress, now).unwrap();
        assert_eq!(
            result.rule_id, "read-then-send-spike",
            "a queued-then-approved send must still correlate with its reads"
        );
    }

    /// Cooldown arms on the leading edge only, so a sustained burst cannot
    /// slide the expiry forward indefinitely.
    #[test]
    fn cooldown_arms_once_per_burst_episode() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "evil.example.net".into(),
                port: 443,
            },
            session,
        );
        // small_limit_config: burst_threshold 4.
        for i in 0..4 {
            observe(
                &filter,
                &ctx,
                CallOutcome::Executed,
                now + Duration::from_millis(i * 100),
            );
        }
        let armed = {
            let sessions = filter.sessions.lock().unwrap();
            sessions
                .get(&SessionScopeKey::from_session_id(session))
                .unwrap()
                .cooldown_until
        };
        assert!(
            armed.is_some(),
            "a genuine delivered burst must arm cooldown"
        );

        for i in 4..8 {
            observe(
                &filter,
                &ctx,
                CallOutcome::Executed,
                now + Duration::from_millis(i * 100),
            );
        }
        let sessions = filter.sessions.lock().unwrap();
        assert_eq!(
            sessions
                .get(&SessionScopeKey::from_session_id(session))
                .unwrap()
                .cooldown_until,
            armed,
            "further calls inside the episode must not re-arm"
        );
    }

    /// prune must expire cooldown against the injected clock, not the wall
    /// clock. The old implementation read `Instant::now()` here.
    #[test]
    fn prune_expires_cooldown_on_the_injected_clock() {
        let mut state = SessionEgressState::new();
        let now = Instant::now();
        state.cooldown_until = Some(now + Duration::from_secs(30));
        state.prune(now + Duration::from_secs(31), RETENTION_WINDOW);
        assert!(state.cooldown_until.is_none());
    }

    #[test]
    fn evict_session_state_drops_only_the_named_scope() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let keep = Uuid::new_v4();
        let drop_me = Uuid::new_v4();
        let now = Instant::now();
        for session in [keep, drop_me] {
            let ctx = make_ctx(
                ToolCallType::NetConnect {
                    address: "api.example.com".into(),
                    port: 443,
                },
                session,
            );
            observe(&filter, &ctx, CallOutcome::Executed, now);
        }
        assert_eq!(
            filter.evict_session_state(SessionScopeKey::from_session_id(drop_me)),
            1
        );
        let sessions = filter.sessions.lock().unwrap();
        assert!(sessions.contains_key(&SessionScopeKey::from_session_id(keep)));
        assert!(!sessions.contains_key(&SessionScopeKey::from_session_id(drop_me)));
    }

    /// The filter has no opinion on DNS, and must not grow state for it.
    #[test]
    fn dns_queries_are_ignored_by_both_halves() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let ctx = make_ctx(
            ToolCallType::DnsQuery {
                domain: "example.com".into(),
                query_type: "A".into(),
            },
            Uuid::new_v4(),
        );
        assert!(!filter.evaluate_at(&ctx, Instant::now()).unwrap().matched);
        observe(&filter, &ctx, CallOutcome::Executed, Instant::now());
        assert!(filter.sessions.lock().unwrap().is_empty());
    }

    /// evaluate and observe_outcome must agree about what a call IS.
    ///
    /// Both read `ctx.arguments` (for the unix-socket class) and
    /// `ctx.profile_name` (for profile-trusted destinations). Any transport
    /// that carries a call to the commit side without those fields makes the
    /// two halves disagree: a Control-class connect that `evaluate` correctly
    /// ignored would commit as egress, inflating the very counters this split
    /// exists to make honest.
    #[test]
    fn commit_side_agrees_with_evaluate_about_control_class() {
        let filter = EgressRateFilter::from_config(small_limit_config());
        let session = Uuid::new_v4();
        let now = Instant::now();

        let mut labelled = unix_connect_ctx("unix:/run/user/1000/bus", Some("control"));
        rehome(&mut labelled, session);
        for _ in 0..10 {
            observe(&filter, &labelled, CallOutcome::Executed, now);
        }
        assert!(
            filter.sessions.lock().unwrap().is_empty(),
            "a Control-class connect is not egress and must commit nothing"
        );

        // The same connect with the class label stripped - what a lossy
        // transport would deliver - is treated as egress and DOES commit.
        let mut unlabelled = unix_connect_ctx("unix:/run/user/1000/bus", None);
        rehome(&mut unlabelled, session);
        observe(&filter, &unlabelled, CallOutcome::Executed, now);
        assert!(
            !filter.sessions.lock().unwrap().is_empty(),
            "guard assumption: an unlabelled connect IS egress, which is why \
             the label has to survive the trip to the commit side"
        );
    }

    /// The routine/non-routine verdict must be identical on both sides, or
    /// thresholds drift: a profile-trusted destination excluded at evaluate
    /// would be committed as ordinary volume.
    #[test]
    fn commit_side_agrees_with_evaluate_about_profile_trust() {
        let filter = EgressRateFilter::from_config_with_trust(
            small_limit_config(),
            Vec::new(),
            HashMap::from([("codex".to_string(), vec!["trusted.example.com".to_string()])]),
        );
        let session = Uuid::new_v4();
        let now = Instant::now();

        let with_profile = make_ctx(
            ToolCallType::NetConnect {
                address: "trusted.example.com".into(),
                port: 443,
            },
            session,
        )
        .with_profile("codex");
        for _ in 0..10 {
            observe(&filter, &with_profile, CallOutcome::Executed, now);
        }
        let sessions = filter.sessions.lock().unwrap();
        let state = sessions
            .get(&SessionScopeKey::from_session_id(session))
            .unwrap();
        assert!(
            state.delivered_egress_timestamps.is_empty(),
            "a profile-trusted destination must not enter the volumetric counters"
        );
        // It still feeds the trust-blind correlation.
        assert_eq!(state.attempted_egress_timestamps.len(), 10);
    }

    /// End-to-end reproduction of the reported incident, at SHIPPED defaults.
    ///
    /// A session reads a .env file, then curl retries a refused destination.
    /// Before the split this drove the burst counter 8 -> 44 in ten seconds,
    /// each retry adding 4.0 and re-arming a 30s cooldown.
    #[test]
    fn the_reported_incident_no_longer_escalates() {
        let filter = EgressRateFilter::from_config(EgressRateConfig::default());
        let session = Uuid::new_v4();
        let now = Instant::now();

        // The session did read a sensitive file, so it is genuinely tainted.
        let read = make_ctx(
            ToolCallType::FileRead {
                path: "/home/dev/project/.env.local".into(),
            },
            session,
        );
        observe(&filter, &read, CallOutcome::Executed, now);

        // curl retries a refused connect 44 times inside ten seconds.
        let ctx = make_ctx(
            ToolCallType::NetConnect {
                address: "grith.ai".into(),
                port: 443,
            },
            session,
        );
        let mut peak: f64 = 0.0;
        for i in 0..44 {
            let at = now + Duration::from_millis(i * 200);
            let result = filter.evaluate_at(&ctx, at).unwrap();
            peak = peak.max(result.score);
            observe(&filter, &ctx, CallOutcome::Denied, at);
        }

        assert_eq!(
            peak, 0.0,
            "a retry storm against ONE refused destination must contribute \
             nothing; egress-rate peaked at {peak}"
        );

        let sessions = filter.sessions.lock().unwrap();
        let state = sessions
            .get(&SessionScopeKey::from_session_id(session))
            .unwrap();
        assert!(state.cooldown_until.is_none());
        assert_eq!(state.blocked_attempts.len(), 1);
        assert!(state.delivered_egress_timestamps.is_empty());
    }
}
