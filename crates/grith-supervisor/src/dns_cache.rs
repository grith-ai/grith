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

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};

use nix::libc;

/// DNS resolution cache for mapping raw IPs to hostnames.
pub struct DnsCache {
    /// Reverse DNS cache: raw IP → resolved hostname (or None if lookup failed).
    reverse_cache: HashMap<String, Option<String>>,
    /// Forward DNS cache: raw IP → domain name (built from pre-resolved domains).
    forward_cache: HashMap<IpAddr, String>,
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
            self.forward_cache.insert(addr, domain.to_string());
        }
    }

    /// Record a batch of resolved domain → IP mappings.
    pub fn record_resolved_domains(
        &mut self,
        resolved: impl IntoIterator<Item = (String, IpAddr)>,
    ) {
        let mut count = 0usize;
        for (domain, ip) in resolved {
            self.forward_cache.insert(ip, domain);
            count += 1;
        }
        if count > 0 {
            tracing::info!(count, "seeded DNS forward cache with IP→domain mappings");
        }
    }

    /// Resolve a raw IP address to a hostname.
    ///
    /// Resolution order:
    /// 1. Forward cache (pre-resolved trusted domains)
    /// 2. Reverse DNS lookup (`getnameinfo`)
    /// 3. Falls back to the original IP string
    pub fn resolve(&mut self, ip: &str) -> String {
        // Skip non-IP addresses (unix sockets, empty, etc.)
        if ip.is_empty() || ip.starts_with('/') || ip.starts_with('<') {
            return ip.to_string();
        }

        // Check forward cache first (handles services without PTR records).
        if let Ok(addr) = ip.parse::<IpAddr>() {
            if let Some(domain) = self.forward_cache.get(&addr) {
                return domain.clone();
            }
        }

        // Check reverse cache
        if let Some(cached) = self.reverse_cache.get(ip) {
            return cached.clone().unwrap_or_else(|| ip.to_string());
        }

        // Attempt reverse DNS lookup
        let hostname = reverse_dns_lookup(ip);
        self.reverse_cache.insert(ip.to_string(), hostname.clone());

        if let Some(ref name) = hostname {
            tracing::debug!(ip, hostname = %name, "reverse DNS resolved");
        }

        hostname.unwrap_or_else(|| ip.to_string())
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
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
            Err(e) => {
                tracing::debug!(domain, error = %e, "forward DNS seed failed");
            }
        }
    }
    resolved
}

/// Perform a reverse DNS lookup on a raw IP address string using `getnameinfo`.
///
/// Returns `Some(hostname)` if a PTR record exists, `None` if the lookup
/// fails or returns the numeric address back (no PTR record found).
fn reverse_dns_lookup(ip: &str) -> Option<String> {
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
}
