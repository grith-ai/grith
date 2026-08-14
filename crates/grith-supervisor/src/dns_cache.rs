// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! DNS resolution cache for enriching raw IP addresses with hostnames.
//!
//! When the ptrace supervisor intercepts a `connect()` syscall, the address
//! is a raw IP (IPv4 or IPv6) because DNS resolution happened in userspace
//! before the syscall. This module provides two resolution strategies:
//!
//! 1. **Forward cache** — on startup, resolves trusted/known domains to IPs
//!    and builds an IP→domain map. This handles services without PTR records
//!    (e.g., GitHub's IPv6 range).
//!
//! 2. **Reverse DNS** — for IPs not in the forward cache, attempts a reverse
//!    DNS lookup via `getnameinfo`. This handles services with PTR records.
//!
//! Both results are cached for the session lifetime.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use nix::libc;

const MAX_OBSERVED_TTL: Duration = Duration::from_secs(60 * 60);
const STARTUP_SEED_TTL: Duration = Duration::from_secs(5 * 60);
const REVERSE_TTL: Duration = Duration::from_secs(5 * 60);
const REVERSE_NEGATIVE_TTL: Duration = Duration::from_secs(15);
/// Attribution floor for observed DNS answers. Real clients cache resolutions
/// in-process and reuse pooled connections well past short CDN record TTLs
/// (GitHub serves 60s), so honouring the record TTL alone guarantees that a
/// reconnect after that window shows the operator a raw-IP prompt. Attribution
/// is display/policy metadata, not authoritative DNS: holding an entry longer
/// is safe because a conflicting later answer degrades the IP to an ambiguous
/// candidate list instead of silently trusting a stale name.
const OBSERVED_ATTRIBUTION_TTL_FLOOR: Duration = Duration::from_secs(10 * 60);
const MAX_OBSERVED_BATCH: usize = 256;

/// Failure returned before an observed DNS answer batch changes the cache.
///
/// Validation is performed for the complete batch first, so callers never see
/// a partially committed DNS response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsCacheError {
    #[error("observed DNS domain is empty")]
    EmptyDomain,
    #[error("observed DNS answer batch exceeds {MAX_OBSERVED_BATCH} records")]
    TooManyAnswers,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Exact(String),
    Ambiguous(Vec<String>),
    Unknown(IpAddr),
    NotAnIp(String),
}

/// Result of the non-blocking cache lookup phase.
///
/// Reverse DNS is deliberately separated from cache access so callers sharing
/// a `Mutex<DnsCache>` never hold that mutex across `getnameinfo(3)`. Connected
/// DNS response commits must not be delayed by an unrelated PTR lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttributionLookup {
    Ready(Resolution),
    NeedsReverse(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttributionSource {
    ObservedDns { tgid: u32 },
    StartupSeed,
}

#[derive(Debug, Clone)]
struct AttributionMetadata {
    source: AttributionSource,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct ReverseEntry {
    hostname: Option<String>,
    expires_at: Instant,
}

/// DNS resolution cache for mapping raw IPs to hostnames.
pub struct DnsCache {
    reverse_cache: HashMap<IpAddr, ReverseEntry>,
    /// Every active name is retained. Observed answers outrank speculative
    /// startup seeds, but conflicting observations remain ambiguous.
    forward_cache: HashMap<IpAddr, HashMap<String, AttributionMetadata>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            reverse_cache: HashMap::new(),
            forward_cache: HashMap::new(),
        }
    }

    /// Pre-resolve a list of domain names and populate the forward cache.
    /// Call this at session startup with the egress filter's trusted domains.
    pub fn seed_domains(&mut self, domains: &[&str]) {
        let resolved = resolve_domains(domains.iter().copied());
        self.record_resolved_domains(resolved);
    }

    /// Record a domain→IP mapping without re-resolving DNS.
    ///
    /// Used by the DNS proxy event handler to seed the cache with exact
    /// IP→domain mappings from intercepted DNS responses, avoiding the
    /// risk of `ToSocketAddrs` returning different IPs (CDN round-robin).
    pub fn record_domain(&mut self, domain: &str, ip: &str) {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            self.record_observed(domain, addr, Duration::from_secs(60), 0);
        }
    }

    /// Record an answer observed in the supervised process's DNS response.
    pub fn record_observed(&mut self, domain: &str, ip: IpAddr, ttl: Duration, tgid: u32) {
        // A single answer is always a valid bounded batch. Keep this legacy
        // convenience API infallible for startup/inline callers.
        let _ = self.commit_observed_batch(domain, [(ip, ttl)], tgid);
    }

    /// Atomically commit every validated A/AAAA answer from one DNS response.
    ///
    /// The complete iterator is collected and validated before any cache
    /// mutation. This lets the connected proxy enforce cache-before-reply
    /// without risking a partially attributed answer.
    pub fn commit_observed_batch(
        &mut self,
        domain: &str,
        answers: impl IntoIterator<Item = (IpAddr, Duration)>,
        tgid: u32,
    ) -> Result<usize, DnsCacheError> {
        let domain = domain.trim().trim_end_matches('.');
        if domain.is_empty() {
            return Err(DnsCacheError::EmptyDomain);
        }

        let answers: Vec<(IpAddr, Duration)> = answers.into_iter().collect();
        if answers.len() > MAX_OBSERVED_BATCH {
            return Err(DnsCacheError::TooManyAnswers);
        }

        let now = Instant::now();
        let staged: Vec<(IpAddr, Duration, Instant)> = answers
            .into_iter()
            .map(|(ip, ttl)| {
                let ttl = ttl.clamp(OBSERVED_ATTRIBUTION_TTL_FLOOR, MAX_OBSERVED_TTL);
                (ip, ttl, now + ttl)
            })
            .collect();

        for (ip, ttl, expires_at) in &staged {
            self.insert(
                domain,
                *ip,
                AttributionSource::ObservedDns { tgid },
                *expires_at,
            );
            // A previous negative PTR lookup must never hide an exact answer.
            self.reverse_cache.remove(ip);
            tracing::debug!(
                %ip,
                tgid,
                ttl_secs = ttl.as_secs(),
                "DNS exact cache insert"
            );
        }
        Ok(staged.len())
    }

    fn insert(&mut self, domain: &str, ip: IpAddr, source: AttributionSource, expires_at: Instant) {
        self.forward_cache.entry(ip).or_default().insert(
            domain.trim_end_matches('.').to_ascii_lowercase(),
            AttributionMetadata { source, expires_at },
        );
    }

    /// Record a batch of resolved domain → IP mappings.
    pub fn record_resolved_domains(
        &mut self,
        resolved: impl IntoIterator<Item = (String, IpAddr)>,
    ) {
        let mut count = 0usize;
        for (domain, ip) in resolved {
            self.insert(
                &domain,
                ip,
                AttributionSource::StartupSeed,
                Instant::now() + STARTUP_SEED_TTL,
            );
            count += 1;
        }
        if count > 0 {
            tracing::info!(count, "seeded DNS forward cache with IP→domain mappings");
        }
    }

    /// Look up exact/ambiguous attribution and cached PTR data without doing
    /// network I/O.
    pub(crate) fn lookup_attribution(&mut self, ip: &str) -> AttributionLookup {
        // Skip non-IP addresses (unix sockets, empty, etc.)
        if ip.is_empty() || ip.starts_with('/') || ip.starts_with('<') {
            return AttributionLookup::Ready(Resolution::NotAnIp(ip.to_string()));
        }

        let Ok(addr) = ip.parse::<IpAddr>() else {
            return AttributionLookup::Ready(Resolution::NotAnIp(ip.to_string()));
        };
        let now = Instant::now();
        if let Some(resolution) = self.lookup_forward(addr, now) {
            return AttributionLookup::Ready(resolution);
        }

        // Check reverse cache.
        if let Some(cached) = self.reverse_cache.get(&addr) {
            if cached.expires_at > now {
                return AttributionLookup::Ready(
                    cached
                        .hostname
                        .clone()
                        .map(Resolution::Exact)
                        .unwrap_or(Resolution::Unknown(addr)),
                );
            }
        }

        AttributionLookup::NeedsReverse(addr)
    }

    fn lookup_forward(&mut self, addr: IpAddr, now: Instant) -> Option<Resolution> {
        if let Some(records) = self.forward_cache.get_mut(&addr) {
            records.retain(|_, metadata| metadata.expires_at > now);
            let observed: HashSet<String> = records
                .iter()
                .filter(|(_, metadata)| {
                    matches!(metadata.source, AttributionSource::ObservedDns { .. })
                })
                .map(|(name, _)| name.clone())
                .collect();
            let names: Vec<String> = if observed.is_empty() {
                records.keys().cloned().collect()
            } else {
                observed.into_iter().collect()
            };
            if names.len() == 1 {
                tracing::trace!(%addr, "DNS exact cache hit");
                return Some(Resolution::Exact(names[0].clone()));
            }
            if names.len() > 1 {
                let mut names = names;
                names.sort();
                tracing::warn!(
                    %addr,
                    candidate_count = names.len(),
                    "ambiguous DNS IP attribution"
                );
                return Some(Resolution::Ambiguous(names));
            }
        }
        None
    }

    /// Commit a PTR result after the potentially blocking lookup completed.
    ///
    /// Exact observed DNS data wins if it arrived while the PTR lookup was in
    /// flight.
    pub(crate) fn commit_reverse_lookup(
        &mut self,
        addr: IpAddr,
        hostname: Option<String>,
    ) -> Resolution {
        let now = Instant::now();
        if let Some(resolution) = self.lookup_forward(addr, now) {
            return resolution;
        }
        let ttl = if hostname.is_some() {
            REVERSE_TTL
        } else {
            REVERSE_NEGATIVE_TTL
        };
        self.reverse_cache.insert(
            addr,
            ReverseEntry {
                hostname: hostname.clone(),
                expires_at: now + ttl,
            },
        );

        if hostname.is_some() {
            tracing::debug!(%addr, "reverse DNS resolved");
        }

        hostname
            .map(Resolution::Exact)
            .unwrap_or(Resolution::Unknown(addr))
    }

    /// Resolve a raw IP address to a hostname.
    ///
    /// This compatibility API performs PTR lookup synchronously. Shared-cache
    /// callers should use `lookup_attribution`, release their lock, perform
    /// `reverse_dns_lookup`, and then call `commit_reverse_lookup`.
    pub fn resolve_attribution(&mut self, ip: &str) -> Resolution {
        match self.lookup_attribution(ip) {
            AttributionLookup::Ready(resolution) => resolution,
            AttributionLookup::NeedsReverse(addr) => {
                let hostname = reverse_dns_lookup(&addr.to_string());
                self.commit_reverse_lookup(addr, hostname)
            }
        }
    }

    /// Compatibility helper for callers which do not need ambiguity context.
    /// Ambiguous and unknown addresses deliberately stay as raw IPs.
    pub fn resolve(&mut self, ip: &str) -> String {
        match self.resolve_attribution(ip) {
            Resolution::Exact(name) => name,
            Resolution::Ambiguous(_) | Resolution::Unknown(_) | Resolution::NotAnIp(_) => {
                ip.to_string()
            }
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimum interval between miss-triggered forward re-resolutions. A burst of
/// unknown connects re-resolving on every miss would add getaddrinfo latency
/// for no new information — a refresh from seconds ago already covers them.
const FORWARD_CONFIRM_MIN_INTERVAL: Duration = Duration::from_secs(15);

/// Miss-triggered forward re-resolution of the session's trusted destinations.
///
/// When a `NetConnect` attribution misses every cache source, the operator is
/// about to see a raw-IP prompt that a fresh resolution of the profile's
/// destinations may well convert into a silent allow: rotating-CDN pools hand
/// the supervisor's periodic refresh different answers than they handed the
/// supervised tool. This holds the ordered domain list and rate-limits the
/// re-resolve attempts; the lookup itself and the cache merge stay with the
/// caller so this struct never blocks.
pub(crate) struct DnsForwardConfirm {
    domains: Vec<String>,
    last_attempt: std::sync::Mutex<Option<Instant>>,
}

impl DnsForwardConfirm {
    /// `None` when there are no destinations worth re-resolving.
    pub(crate) fn new(domains: Vec<String>) -> Option<Self> {
        if domains.is_empty() {
            None
        } else {
            Some(Self {
                domains,
                last_attempt: std::sync::Mutex::new(None),
            })
        }
    }

    pub(crate) fn domains(&self) -> &[String] {
        &self.domains
    }

    /// Stamp and report whether a re-resolve may run now. At most one caller
    /// wins per interval; losers keep their miss without added latency.
    pub(crate) fn try_begin(&self) -> bool {
        let Ok(mut last) = self.last_attempt.lock() else {
            return false;
        };
        let now = Instant::now();
        if last.is_some_and(|at| now.duration_since(at) < FORWARD_CONFIRM_MIN_INTERVAL) {
            return false;
        }
        *last = Some(now);
        true
    }
}

/// Resolve a list of domains to IP addresses without mutating the cache.
///
/// Callers can do this work off-thread, then take the mutex only long enough
/// to insert the finished mappings.
pub fn resolve_domains<'a>(domains: impl IntoIterator<Item = &'a str>) -> Vec<(String, IpAddr)> {
    let mut resolved = Vec::new();
    for domain in domains {
        let lookup_addr = format!("{domain}:443");
        match lookup_addr.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    resolved.push((domain.to_string(), addr.ip()));
                }
            }
            Err(error) => {
                tracing::debug!(
                    error_kind = ?error.kind(),
                    "forward DNS seed failed"
                );
            }
        }
    }
    resolved
}

/// Perform a reverse DNS lookup on a raw IP address string using `getnameinfo`.
///
/// Returns `Some(hostname)` if a PTR record exists, `None` if the lookup
/// fails or returns the numeric address back (no PTR record found).
pub(crate) fn reverse_dns_lookup(ip: &str) -> Option<String> {
    use std::ffi::CStr;

    let addr: IpAddr = ip.parse().ok()?;

    let mut host_buf = [0u8; 256];

    // SAFETY: We construct valid sockaddr structures and pass correctly
    // sized buffers to getnameinfo.
    let result = unsafe {
        match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(octets),
                    },
                    sin_zero: [0; 8],
                };
                libc::getnameinfo(
                    std::ptr::from_ref(&sa).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host_buf.as_mut_ptr().cast::<libc::c_char>(),
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
            IpAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    sin6_scope_id: 0,
                };
                libc::getnameinfo(
                    std::ptr::from_ref(&sa).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host_buf.as_mut_ptr().cast::<libc::c_char>(),
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
        }
    };

    if result != 0 {
        return None;
    }

    // SAFETY: getnameinfo null-terminates the buffer on success.
    let hostname = unsafe { CStr::from_ptr(host_buf.as_ptr().cast::<libc::c_char>()) }
        .to_str()
        .ok()?
        .to_string();

    // If getnameinfo returned the numeric address back (no PTR record),
    // treat it as a failed lookup.
    if hostname == ip {
        return None;
    }

    Some(hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_returns_same_result() {
        let mut cache = DnsCache::new();
        // Localhost should always resolve
        let first = cache.resolve("127.0.0.1");
        let second = cache.resolve("127.0.0.1");
        assert_eq!(first, second);
    }

    #[test]
    fn non_ip_passthrough() {
        let mut cache = DnsCache::new();
        assert_eq!(cache.resolve(""), "");
        assert_eq!(cache.resolve("/var/run/socket"), "/var/run/socket");
        assert_eq!(cache.resolve("<unknown-af:99>"), "<unknown-af:99>");
    }

    #[test]
    fn ipv6_loopback_resolves() {
        let mut cache = DnsCache::new();
        let result = cache.resolve("::1");
        // Should resolve to localhost or ip6-localhost, or fall back to "::1"
        assert!(!result.is_empty());
    }

    #[test]
    fn forward_cache_seed_and_lookup() {
        let mut cache = DnsCache::new();
        // Seed with localhost — should resolve 127.0.0.1
        cache.seed_domains(&["localhost"]);
        // After seeding, 127.0.0.1 should map to "localhost"
        let result = cache.resolve("127.0.0.1");
        assert_eq!(result, "localhost");
    }

    #[test]
    fn observed_mapping_outranks_conflicting_startup_seed() {
        let mut cache = DnsCache::new();
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        cache.record_resolved_domains([("seed.example".into(), ip)]);
        cache.record_observed("exact.example", ip, Duration::from_secs(30), 42);
        assert_eq!(
            cache.resolve_attribution("192.0.2.10"),
            Resolution::Exact("exact.example".into())
        );
    }

    #[test]
    fn conflicting_observed_names_are_ambiguous() {
        let mut cache = DnsCache::new();
        let ip: IpAddr = "2001:db8::10".parse().unwrap();
        cache.record_observed("trusted.example", ip, Duration::from_secs(30), 42);
        cache.record_observed("untrusted.example", ip, Duration::from_secs(30), 42);
        assert_eq!(
            cache.resolve_attribution("2001:db8::10"),
            Resolution::Ambiguous(vec!["trusted.example".into(), "untrusted.example".into()])
        );
        assert_eq!(cache.resolve("2001:db8::10"), "2001:db8::10");
    }

    #[test]
    fn ttl_zero_is_bounded_and_expired_records_are_removed() {
        let mut cache = DnsCache::new();
        let ip: IpAddr = "192.0.2.20".parse().unwrap();
        cache.record_observed("short.example", ip, Duration::ZERO, 7);
        assert_eq!(
            cache.resolve_attribution("192.0.2.20"),
            Resolution::Exact("short.example".into())
        );
        for metadata in cache.forward_cache.get_mut(&ip).unwrap().values_mut() {
            metadata.expires_at = Instant::now() - Duration::from_secs(1);
        }
        assert_ne!(
            cache.resolve_attribution("192.0.2.20"),
            Resolution::Exact("short.example".into())
        );
    }

    #[test]
    fn observed_ttl_floor_outlives_short_record_ttls() {
        let mut cache = DnsCache::new();
        let ip: IpAddr = "192.0.2.50".parse().unwrap();
        cache.record_observed("floor.example", ip, Duration::from_secs(60), 7);
        let remaining = cache.forward_cache[&ip]["floor.example"].expires_at - Instant::now();
        assert!(remaining > OBSERVED_ATTRIBUTION_TTL_FLOOR - Duration::from_secs(5));
    }

    #[test]
    fn observed_ttl_above_floor_is_honoured_and_capped() {
        let mut cache = DnsCache::new();
        let ip: IpAddr = "192.0.2.51".parse().unwrap();
        cache.record_observed("long.example", ip, Duration::from_secs(30 * 60), 7);
        let remaining = cache.forward_cache[&ip]["long.example"].expires_at - Instant::now();
        assert!(remaining > Duration::from_secs(29 * 60));

        cache.record_observed("capped.example", ip, Duration::from_secs(2 * 60 * 60), 7);
        let remaining = cache.forward_cache[&ip]["capped.example"].expires_at - Instant::now();
        assert!(remaining <= MAX_OBSERVED_TTL);
    }

    #[test]
    fn forward_confirm_rate_limits_attempts() {
        assert!(DnsForwardConfirm::new(Vec::new()).is_none());
        let confirm = DnsForwardConfirm::new(vec!["example.com".into()]).unwrap();
        assert_eq!(confirm.domains(), ["example.com".to_string()]);
        assert!(confirm.try_begin());
        assert!(!confirm.try_begin());
    }

    #[test]
    fn observed_answer_clears_reverse_negative_cache() {
        let mut cache = DnsCache::new();
        let ip: IpAddr = "192.0.2.30".parse().unwrap();
        cache.reverse_cache.insert(
            ip,
            ReverseEntry {
                hostname: None,
                expires_at: Instant::now() + Duration::from_secs(30),
            },
        );
        cache.record_observed("later.example", ip, Duration::from_secs(30), 9);
        assert_eq!(
            cache.resolve_attribution("192.0.2.30"),
            Resolution::Exact("later.example".into())
        );
    }

    #[test]
    fn observed_answer_wins_if_it_arrives_during_reverse_lookup() {
        let mut cache = DnsCache::new();
        let ip: IpAddr = "192.0.2.31".parse().unwrap();
        assert_eq!(
            cache.lookup_attribution("192.0.2.31"),
            AttributionLookup::NeedsReverse(ip)
        );

        cache.record_observed("observed.example", ip, Duration::from_secs(30), 9);
        assert_eq!(
            cache.commit_reverse_lookup(ip, Some("ptr.example".into())),
            Resolution::Exact("observed.example".into())
        );
    }

    #[test]
    fn observed_batch_commits_all_answers_together() {
        let mut cache = DnsCache::new();
        let first: IpAddr = "192.0.2.40".parse().unwrap();
        let second: IpAddr = "2001:db8::40".parse().unwrap();

        let count = cache
            .commit_observed_batch(
                "Batch.Example.",
                [
                    (first, Duration::from_secs(30)),
                    (second, Duration::from_secs(45)),
                ],
                77,
            )
            .unwrap();

        assert_eq!(count, 2);
        assert_eq!(
            cache.resolve_attribution("192.0.2.40"),
            Resolution::Exact("batch.example".into())
        );
        assert_eq!(
            cache.resolve_attribution("2001:db8::40"),
            Resolution::Exact("batch.example".into())
        );
    }

    #[test]
    fn invalid_observed_batch_does_not_partially_commit() {
        let mut cache = DnsCache::new();
        let first: IpAddr = "192.0.2.41".parse().unwrap();
        let answers = std::iter::repeat_n((first, Duration::from_secs(30)), MAX_OBSERVED_BATCH + 1);

        assert_eq!(
            cache.commit_observed_batch("too-many.example", answers, 77),
            Err(DnsCacheError::TooManyAnswers)
        );
        assert_eq!(
            cache.resolve_attribution("192.0.2.41"),
            Resolution::Unknown(first)
        );
    }

    #[test]
    fn empty_observed_domain_is_rejected_before_mutation() {
        let mut cache = DnsCache::new();
        let ip: IpAddr = "192.0.2.42".parse().unwrap();
        assert_eq!(
            cache.commit_observed_batch(" . ", [(ip, Duration::from_secs(30))], 77),
            Err(DnsCacheError::EmptyDomain)
        );
        assert_eq!(
            cache.resolve_attribution("192.0.2.42"),
            Resolution::Unknown(ip)
        );
    }
}
