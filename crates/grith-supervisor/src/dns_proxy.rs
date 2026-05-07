// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Lightweight DNS inspection proxy for exfiltration defence.
//!
//! When enabled, the supervisor redirects port-53 `connect()`/`sendto()`
//! syscalls from supervised processes to this local UDP proxy. The proxy
//! extracts the QNAME from DNS wire format, sends it to the supervisor
//! for security evaluation, and either forwards clean queries to the real
//! upstream resolver or returns REFUSED.
//!
//! This closes the DNS exfiltration gap where an attacker encodes secrets
//! in subdomain labels (e.g., `AKIA1234.attacker.com`) and leaks data
//! purely through DNS lookups.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::dns_cache::DnsCache;

/// Decision returned to the DNS proxy after security evaluation.
#[derive(Debug)]
pub enum DnsDecision {
    /// Forward the query to the upstream resolver.
    Forward,
    /// Return a REFUSED response to the client.
    Refuse,
}

/// A DNS query intercepted by the proxy, sent to the supervisor for evaluation.
pub struct DnsQueryEvent {
    /// The queried domain name (e.g., `example.com`).
    pub domain: String,
    /// DNS query type as a string (e.g., `"A"`, `"AAAA"`, `"CNAME"`).
    pub query_type: String,
    /// Source address of the query (for routing the response back).
    pub source_addr: SocketAddr,
    /// Raw DNS query packet for forwarding to upstream.
    pub raw_query: Vec<u8>,
    /// Channel to send the allow/deny decision back to the proxy.
    pub response_tx: oneshot::Sender<DnsDecision>,
}

/// The DNS inspection proxy handle, returned after starting the proxy task.
pub struct DnsProxy {
    /// The local port the proxy is listening on.
    pub local_port: u16,
}

/// Maximum DNS UDP packet size (standard, no EDNS).
const MAX_DNS_UDP: usize = 512;

/// Start the DNS inspection proxy as a background Tokio task.
///
/// Returns a `DnsProxy` handle with the bound port and a receiver for
/// query events that the supervisor should evaluate.
pub async fn start_dns_proxy(
    upstream: SocketAddr,
    dns_cache: Arc<Mutex<DnsCache>>,
) -> std::io::Result<(DnsProxy, mpsc::Receiver<DnsQueryEvent>)> {
    let socket_v4 = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let local_port = socket_v4.local_addr()?.port();

    let (query_tx, query_rx) = mpsc::channel::<DnsQueryEvent>(64);

    info!(local_port, %upstream, "DNS inspection proxy started");

    let query_tx_v4 = query_tx.clone();
    let cache_v4 = Arc::clone(&dns_cache);
    tokio::spawn(async move {
        dns_proxy_loop(socket_v4, upstream, query_tx_v4, cache_v4).await;
    });

    match UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), local_port)).await {
        Ok(socket_v6) => {
            info!(local_port, %upstream, "DNS inspection proxy IPv6 listener started");
            let cache_v6 = Arc::clone(&dns_cache);
            tokio::spawn(async move {
                dns_proxy_loop(socket_v6, upstream, query_tx, cache_v6).await;
            });
        }
        Err(e) => {
            warn!(error = %e, local_port, "DNS proxy IPv6 listener unavailable; IPv6 DNS interception may fail");
        }
    }

    Ok((DnsProxy { local_port }, query_rx))
}

/// Main proxy loop: receive DNS queries, extract QNAME, wait for decision.
async fn dns_proxy_loop(
    socket: UdpSocket,
    upstream: SocketAddr,
    query_tx: mpsc::Sender<DnsQueryEvent>,
    dns_cache: Arc<Mutex<DnsCache>>,
) {
    let mut buf = [0u8; MAX_DNS_UDP];

    loop {
        let (len, src_addr) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                error!(error = %e, "DNS proxy recv_from failed");
                continue;
            }
        };

        if len < 12 {
            // Too short to be a valid DNS message
            debug!(len, "DNS proxy: ignoring short packet");
            continue;
        }

        let raw_query = buf[..len].to_vec();

        let (domain, query_type) = match parse_qname(&raw_query) {
            Some(result) => result,
            None => {
                warn!("DNS proxy: failed to parse QNAME, refusing query");
                let refused = build_refused_response(&raw_query);
                if let Err(e) = socket.send_to(&refused, src_addr).await {
                    debug!(error = %e, "DNS proxy: send REFUSED response failed");
                }
                continue;
            }
        };

        debug!(domain, query_type, %src_addr, "DNS proxy: intercepted query");

        let (response_tx, response_rx) = oneshot::channel();
        let event = DnsQueryEvent {
            domain: domain.clone(),
            query_type,
            source_addr: src_addr,
            raw_query: raw_query.clone(),
            response_tx,
        };

        // Send the query event to the supervisor for evaluation.
        // If the channel is full or closed, forward the query directly (fail-open).
        if query_tx.send(event).await.is_err() {
            warn!("DNS proxy: supervisor channel closed, forwarding directly");
            if let Err(e) =
                forward_and_relay(&socket, &raw_query, src_addr, upstream, &domain, &dns_cache)
                    .await
            {
                debug!(error = %e, "DNS proxy: forward failed");
            }
            continue;
        }

        // Wait for the decision from the supervisor.
        match response_rx.await {
            Ok(DnsDecision::Forward) => {
                if let Err(e) =
                    forward_and_relay(&socket, &raw_query, src_addr, upstream, &domain, &dns_cache)
                        .await
                {
                    debug!(error = %e, "DNS proxy: forward to upstream failed");
                }
            }
            Ok(DnsDecision::Refuse) => {
                let refused = build_refused_response(&raw_query);
                if let Err(e) = socket.send_to(&refused, src_addr).await {
                    debug!(error = %e, "DNS proxy: send REFUSED response failed");
                }
            }
            Err(_) => {
                // Decision channel dropped — fail open, forward the query
                warn!("DNS proxy: decision channel dropped, forwarding query");
                if let Err(e) =
                    forward_and_relay(&socket, &raw_query, src_addr, upstream, &domain, &dns_cache)
                        .await
                {
                    debug!(error = %e, "DNS proxy: forward failed after channel drop");
                }
            }
        }
    }
}

/// Forward a DNS query to the upstream resolver and relay the response back.
///
/// Also parses A/AAAA records from the response and records IP→domain
/// mappings in the DNS cache. This ensures that subsequent `NetConnect`
/// events can resolve Google CDN IPs (like `1e100.net`) back to the
/// original domain name (like `storage.googleapis.com`).
async fn forward_and_relay(
    proxy_socket: &UdpSocket,
    query: &[u8],
    client_addr: SocketAddr,
    upstream: SocketAddr,
    domain: &str,
    dns_cache: &Arc<Mutex<DnsCache>>,
) -> std::io::Result<()> {
    // Use a separate socket for the upstream conversation so we don't
    // confuse client and upstream traffic on the proxy socket.
    let bind_addr = match upstream {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let upstream_socket = UdpSocket::bind(bind_addr).await?;
    upstream_socket.send_to(query, upstream).await?;

    let mut response_buf = [0u8; MAX_DNS_UDP];
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        upstream_socket.recv_from(&mut response_buf),
    )
    .await;

    match timeout {
        Ok(Ok((resp_len, _))) => {
            let response = &response_buf[..resp_len];

            // Extract resolved IPs from the response and feed them into
            // the DNS cache so NetConnect can map IPs back to domains.
            let ips = parse_response_ips(response);
            if !ips.is_empty() {
                if let Ok(mut cache) = dns_cache.lock() {
                    for ip in &ips {
                        cache.record_domain(domain, &ip.to_string());
                    }
                }
                debug!(
                    domain,
                    count = ips.len(),
                    "DNS cache: recorded response IPs"
                );
            }

            proxy_socket.send_to(response, client_addr).await?;
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "upstream DNS timeout",
        )),
    }
}

/// Parse A and AAAA resource records from a DNS response packet.
///
/// Extracts IP addresses from answer section records. Only parses
/// type A (1) and AAAA (28) records. Returns an empty vec on any
/// parse failure.
fn parse_response_ips(packet: &[u8]) -> Vec<IpAddr> {
    if packet.len() < 12 {
        return Vec::new();
    }

    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if ancount == 0 {
        return Vec::new();
    }

    // Skip header (12 bytes) and question section
    let mut offset = 12;
    // Skip QNAME
    while offset < packet.len() {
        let len = packet[offset] as usize;
        if len == 0 {
            offset += 1; // root label
            break;
        }
        if len & 0xC0 == 0xC0 {
            offset += 2; // compression pointer
            break;
        }
        offset += 1 + len;
    }
    // Skip QTYPE (2) + QCLASS (2)
    offset += 4;

    let mut ips = Vec::new();

    for _ in 0..ancount {
        if offset >= packet.len() {
            break;
        }

        // Skip NAME (may be a compression pointer or label sequence)
        if offset < packet.len() && packet[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            while offset < packet.len() {
                let len = packet[offset] as usize;
                if len == 0 {
                    offset += 1;
                    break;
                }
                if len & 0xC0 == 0xC0 {
                    offset += 2;
                    break;
                }
                offset += 1 + len;
            }
        }

        // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes
        if offset + 10 > packet.len() {
            break;
        }

        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > packet.len() {
            break;
        }

        match rtype {
            1 if rdlength == 4 => {
                // A record
                let ip = Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                );
                ips.push(IpAddr::V4(ip));
            }
            28 if rdlength == 16 => {
                // AAAA record
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[offset..offset + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }

        offset += rdlength;
    }

    ips
}

/// Build a DNS REFUSED response from the original query.
///
/// Copies the transaction ID and question section from the query, sets
/// QR=1 (response), RCODE=5 (REFUSED), and QDCOUNT from original.
fn build_refused_response(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let mut response = query.to_vec();
    // Set QR=1 (response bit), keep opcode, set RCODE=5 (REFUSED)
    response[2] = (query[2] & 0x01) | 0x80; // QR=1, RD preserved
    response[3] = 0x05; // RCODE=5 (REFUSED), clear RA/Z/RCODE
                        // Zero out answer/authority/additional counts
    response[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    response
}

// ---------------------------------------------------------------------------
// DNS wire format parsing
// ---------------------------------------------------------------------------

/// Parse the QNAME and QTYPE from a DNS wire-format query.
///
/// DNS wire format (RFC 1035 §4.1):
/// - 12-byte header
/// - Question section: sequence of length-prefixed labels (QNAME),
///   followed by 2-byte QTYPE and 2-byte QCLASS.
///
/// Returns `(domain, query_type)` or `None` if parsing fails.
pub fn parse_qname(packet: &[u8]) -> Option<(String, String)> {
    if packet.len() < 12 {
        return None;
    }

    let mut offset = 12; // Skip header
    let mut labels: Vec<String> = Vec::new();

    loop {
        if offset >= packet.len() {
            return None;
        }

        let label_len = packet[offset] as usize;
        offset += 1;

        if label_len == 0 {
            // End of QNAME
            break;
        }

        // Compression pointer (top 2 bits set) — not expected in queries
        // but handle gracefully.
        if label_len & 0xC0 == 0xC0 {
            return None;
        }

        if label_len > 63 || offset + label_len > packet.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&packet[offset..offset + label_len]).to_string();
        labels.push(label);
        offset += label_len;
    }

    if labels.is_empty() {
        return None;
    }

    // Read QTYPE (2 bytes after QNAME)
    let query_type = if offset + 2 <= packet.len() {
        let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        qtype_to_string(qtype)
    } else {
        "UNKNOWN".to_string()
    };

    let domain = labels.join(".");
    Some((domain, query_type))
}

/// Convert a DNS QTYPE number to a human-readable string.
fn qtype_to_string(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE{other}"),
    }
}

// ---------------------------------------------------------------------------
// Upstream resolver discovery
// ---------------------------------------------------------------------------

/// Parse `/etc/resolv.conf` to find the upstream DNS resolver.
///
/// Skips `127.0.0.53` (systemd-resolved stub) since that's exactly
/// the resolver we're proxying. Falls back to `8.8.8.8:53`.
pub fn discover_upstream_resolver() -> SocketAddr {
    match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(content) => {
            for line in content.lines() {
                let line = line.trim();
                if let Some(addr_str) = line.strip_prefix("nameserver") {
                    let addr_str = addr_str.trim();
                    // Skip the systemd-resolved stub
                    if addr_str == "127.0.0.53" {
                        continue;
                    }
                    if let Ok(ip) = addr_str.parse::<std::net::IpAddr>() {
                        return SocketAddr::new(ip, 53);
                    }
                }
            }
            // All nameservers were 127.0.0.53 or unparseable
            default_upstream()
        }
        Err(_) => default_upstream(),
    }
}

fn default_upstream() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for testing.
    fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();

        // Header (12 bytes): ID=0x1234, flags=0x0100 (standard query, RD=1)
        packet.extend_from_slice(&[0x12, 0x34, 0x01, 0x00]);
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Question section: QNAME as length-prefixed labels
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // Root label terminator

        // QTYPE and QCLASS=IN(1)
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]);

        packet
    }

    #[test]
    fn parse_simple_a_query() {
        let packet = build_dns_query("example.com", 1);
        let (domain, qtype) = parse_qname(&packet).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, "A");
    }

    #[test]
    fn parse_aaaa_query() {
        let packet = build_dns_query("ipv6.example.com", 28);
        let (domain, qtype) = parse_qname(&packet).unwrap();
        assert_eq!(domain, "ipv6.example.com");
        assert_eq!(qtype, "AAAA");
    }

    #[test]
    fn parse_subdomain_exfil_pattern() {
        let packet = build_dns_query("AKIA1234ABCD.leak.attacker.com", 1);
        let (domain, _) = parse_qname(&packet).unwrap();
        assert_eq!(domain, "AKIA1234ABCD.leak.attacker.com");
    }

    #[test]
    fn parse_txt_query() {
        let packet = build_dns_query("_dmarc.example.com", 16);
        let (domain, qtype) = parse_qname(&packet).unwrap();
        assert_eq!(domain, "_dmarc.example.com");
        assert_eq!(qtype, "TXT");
    }

    #[test]
    fn parse_single_label() {
        let packet = build_dns_query("localhost", 1);
        let (domain, qtype) = parse_qname(&packet).unwrap();
        assert_eq!(domain, "localhost");
        assert_eq!(qtype, "A");
    }

    #[test]
    fn parse_short_packet_returns_none() {
        let short = vec![0u8; 5];
        assert!(parse_qname(&short).is_none());
    }

    #[test]
    fn parse_empty_qname_returns_none() {
        // Header + immediate root label (no actual labels)
        let mut packet = vec![0u8; 12];
        packet.push(0x00); // empty QNAME
        assert!(parse_qname(&packet).is_none());
    }

    #[test]
    fn refused_response_has_correct_rcode() {
        let query = build_dns_query("example.com", 1);
        let response = build_refused_response(&query);
        assert!(response.len() >= 12);
        // Check QR=1 (bit 7 of byte 2)
        assert_ne!(response[2] & 0x80, 0, "QR bit should be set");
        // Check RCODE=5 (low 4 bits of byte 3)
        assert_eq!(response[3] & 0x0F, 5, "RCODE should be REFUSED (5)");
        // Transaction ID preserved
        assert_eq!(response[0], 0x12);
        assert_eq!(response[1], 0x34);
    }

    #[test]
    fn discover_upstream_returns_valid_addr() {
        // This test just verifies it doesn't panic and returns a valid address.
        let upstream = discover_upstream_resolver();
        assert_eq!(upstream.port(), 53);
    }

    /// Build a minimal DNS response with A record answers.
    fn build_dns_response(domain: &str, ips: &[Ipv4Addr]) -> Vec<u8> {
        let mut packet = Vec::new();

        // Header: ID=0x1234, flags=0x8180 (response, RD=1, RA=1)
        packet.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]);
        // QDCOUNT=1, ANCOUNT=N, NSCOUNT=0, ARCOUNT=0
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&(ips.len() as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Question section
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

        // Answer section — each answer uses a compression pointer to the QNAME
        for ip in ips {
            packet.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
            packet.extend_from_slice(&[0x00, 0x01]); // TYPE=A
            packet.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
            packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL=300
            packet.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
            packet.extend_from_slice(&ip.octets());
        }

        packet
    }

    #[test]
    fn parse_response_extracts_a_records() {
        let response = build_dns_response(
            "example.com",
            &[
                Ipv4Addr::new(142, 250, 80, 46),
                Ipv4Addr::new(142, 250, 80, 47),
            ],
        );
        let ips = parse_response_ips(&response);
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(142, 250, 80, 46)));
        assert_eq!(ips[1], IpAddr::V4(Ipv4Addr::new(142, 250, 80, 47)));
    }

    #[test]
    fn parse_response_empty_answer() {
        let query = build_dns_query("example.com", 1);
        let ips = parse_response_ips(&query);
        assert!(ips.is_empty());
    }

    #[test]
    fn parse_response_short_packet() {
        let ips = parse_response_ips(&[0u8; 5]);
        assert!(ips.is_empty());
    }
}
