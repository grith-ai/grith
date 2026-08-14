// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Focused helpers for redirecting a connected UDP DNS socket.
//!
//! The live state machine lives in `events.rs`; this module keeps tracee-memory
//! mutation, byte-for-byte restoration, namespace checks, and inode-correlated
//! local-tuple discovery small enough to test independently.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::c_void;
use std::path::Path;

use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::error::{Error, Result};

const WORD: usize = std::mem::size_of::<libc::c_long>();

/// A tracee sockaddr which has been replaced for exactly one `connect(2)`.
#[derive(Debug, Clone)]
pub(crate) struct SavedSockaddr {
    pub(crate) ptr: u64,
    pub(crate) original: Vec<u8>,
    pub(crate) replacement: Vec<u8>,
}

impl SavedSockaddr {
    /// Restore only if the bytes still contain our replacement.
    ///
    /// A sibling mutation is treated as fatal instead of silently overwriting
    /// memory changed by the tracee while the connecting TID was stopped.
    pub(crate) fn restore(self, pid: Pid) -> Result<()> {
        let current = read_tracee_bytes(pid, self.ptr, self.replacement.len())?;
        if current != self.replacement {
            return Err(Error::InterceptionError(format!(
                "DNS connect sockaddr changed concurrently at {:#x}; refusing to overwrite it",
                self.ptr
            )));
        }
        write_tracee_bytes(pid, self.ptr, &self.original)
    }
}

/// Save and replace the caller's sockaddr with a same-family proxy endpoint.
pub(crate) fn replace_connect_sockaddr(
    pid: Pid,
    sockaddr_ptr: u64,
    addrlen: u32,
    endpoint: SocketAddr,
) -> Result<SavedSockaddr> {
    let replacement = sockaddr_bytes(endpoint);
    if sockaddr_ptr == 0 || (addrlen as usize) < replacement.len() {
        return Err(Error::InterceptionError(format!(
            "DNS connect sockaddr buffer is invalid: ptr={sockaddr_ptr:#x}, len={addrlen}, required={}",
            replacement.len()
        )));
    }
    let original = read_tracee_bytes(pid, sockaddr_ptr, replacement.len())?;
    if let Err(write_error) = write_tracee_bytes(pid, sockaddr_ptr, &replacement) {
        return match write_tracee_bytes(pid, sockaddr_ptr, &original) {
            Ok(()) => Err(write_error),
            Err(restore_error) => Err(Error::InterceptionError(format!(
                "DNS sockaddr rewrite failed ({write_error}); rollback also failed \
                 ({restore_error})"
            ))),
        };
    }
    Ok(SavedSockaddr {
        ptr: sockaddr_ptr,
        original,
        replacement,
    })
}

pub(crate) fn sockaddr_bytes(endpoint: SocketAddr) -> Vec<u8> {
    match endpoint {
        SocketAddr::V4(addr) => {
            let mut bytes = vec![0; std::mem::size_of::<libc::sockaddr_in>()];
            bytes[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            bytes[2..4].copy_from_slice(&addr.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&addr.ip().octets());
            bytes
        }
        SocketAddr::V6(addr) => {
            let mut bytes = vec![0; std::mem::size_of::<libc::sockaddr_in6>()];
            bytes[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            bytes[2..4].copy_from_slice(&addr.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&addr.flowinfo().to_ne_bytes());
            bytes[8..24].copy_from_slice(&addr.ip().octets());
            bytes[24..28].copy_from_slice(&addr.scope_id().to_ne_bytes());
            bytes
        }
    }
}

fn read_tracee_bytes(pid: Pid, base: u64, len: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(len);
    let mut offset = 0usize;
    while offset < len {
        let word = ptrace::read(pid, (base + offset as u64) as *mut c_void).map_err(|error| {
            Error::InterceptionError(format!(
                "DNS redirect PTRACE_PEEKDATA at {:#x} failed for {pid}: {error}",
                base + offset as u64
            ))
        })?;
        let chunk = word.to_ne_bytes();
        let take = (len - offset).min(WORD);
        bytes.extend_from_slice(&chunk[..take]);
        offset += WORD;
    }
    Ok(bytes)
}

fn write_tracee_bytes(pid: Pid, base: u64, bytes: &[u8]) -> Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let take = (bytes.len() - offset).min(WORD);
        let mut chunk = if take == WORD {
            [0u8; WORD]
        } else {
            ptrace::read(pid, (base + offset as u64) as *mut c_void)
                .map_err(|error| {
                    Error::InterceptionError(format!(
                        "DNS redirect trailing PTRACE_PEEKDATA at {:#x} failed for {pid}: {error}",
                        base + offset as u64
                    ))
                })?
                .to_ne_bytes()
        };
        chunk[..take].copy_from_slice(&bytes[offset..offset + take]);
        ptrace::write(
            pid,
            (base + offset as u64) as *mut c_void,
            i64::from_ne_bytes(chunk),
        )
        .map_err(|error| {
            Error::InterceptionError(format!(
                "DNS redirect PTRACE_POKEDATA at {:#x} failed for {pid}: {error}",
                base + offset as u64
            ))
        })?;
        offset += WORD;
    }
    Ok(())
}

/// Return true only when the tracee shares the supervisor's network namespace.
pub(crate) fn shares_supervisor_netns(tgid: u32) -> Result<bool> {
    let ours = std::fs::read_link("/proc/self/ns/net")?;
    let theirs = std::fs::read_link(format!("/proc/{tgid}/ns/net"))?;
    Ok(ours == theirs)
}

/// Resolve the exact local tuple for `fd`, correlating `/proc/net` with the
/// descriptor's socket inode so namespace-wide rows cannot be mistaken for the
/// tracee socket.
pub(crate) fn socket_local_addr(tgid: u32, fd: i32, family: i32) -> Result<SocketAddr> {
    let link = std::fs::read_link(format!("/proc/{tgid}/fd/{fd}"))?;
    let inode = socket_inode(&link).ok_or_else(|| {
        Error::InterceptionError(format!(
            "fd {fd} for tgid {tgid} is not a socket: {}",
            link.display()
        ))
    })?;
    let table = match family {
        libc::AF_INET => format!("/proc/{tgid}/net/udp"),
        libc::AF_INET6 => format!("/proc/{tgid}/net/udp6"),
        _ => {
            return Err(Error::InterceptionError(format!(
                "unsupported DNS route address family {family}"
            )));
        }
    };
    let contents = std::fs::read_to_string(&table)?;
    parse_proc_udp_local(&contents, inode, family).ok_or_else(|| {
        Error::InterceptionError(format!(
            "socket inode {inode} for tgid {tgid} fd {fd} was not found in {table}"
        ))
    })
}

fn socket_inode(link: &Path) -> Option<u64> {
    let text = link.to_str()?;
    text.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn parse_proc_udp_local(contents: &str, inode: u64, family: i32) -> Option<SocketAddr> {
    for line in contents.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 10 || columns[9].parse::<u64>().ok()? != inode {
            continue;
        }
        let (raw_ip, raw_port) = columns[1].split_once(':')?;
        let port = u16::from_str_radix(raw_port, 16).ok()?;
        let ip = match family {
            libc::AF_INET if raw_ip.len() == 8 => {
                let value = u32::from_str_radix(raw_ip, 16).ok()?;
                IpAddr::V4(Ipv4Addr::from(value.to_le_bytes()))
            }
            libc::AF_INET6 if raw_ip.len() == 32 => {
                let mut octets = [0u8; 16];
                for (index, chunk) in raw_ip.as_bytes().chunks_exact(8).enumerate() {
                    let text = std::str::from_utf8(chunk).ok()?;
                    let value = u32::from_str_radix(text, 16).ok()?;
                    octets[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };
        return Some(SocketAddr::new(ip, port));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ipv4_and_ipv6_sockaddrs() {
        let v4: SocketAddr = "127.0.0.1:42000".parse().unwrap();
        let bytes = sockaddr_bytes(v4);
        assert_eq!(bytes.len(), 16);
        assert_eq!(
            u16::from_ne_bytes([bytes[0], bytes[1]]),
            libc::AF_INET as u16
        );
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 42000);
        assert_eq!(&bytes[4..8], &[127, 0, 0, 1]);

        let v6: SocketAddr = "[::1]:42001".parse().unwrap();
        let bytes = sockaddr_bytes(v6);
        assert_eq!(bytes.len(), 28);
        assert_eq!(
            u16::from_ne_bytes([bytes[0], bytes[1]]),
            libc::AF_INET6 as u16
        );
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 42001);
        assert_eq!(&bytes[8..24], &Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn parses_inode_correlated_ipv4_proc_row() {
        let table = "\
  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
   1: 0100007F:A410 0100007F:0035 01 00000000:00000000 00:00000000 00000000 1000 0 4242 2 0 0\n";
        assert_eq!(
            parse_proc_udp_local(table, 4242, libc::AF_INET),
            Some("127.0.0.1:42000".parse().unwrap())
        );
        assert_eq!(parse_proc_udp_local(table, 9999, libc::AF_INET), None);
    }

    #[test]
    fn parses_inode_correlated_ipv6_proc_row() {
        let table = "\
  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
   1: 00000000000000000000000001000000:A411 00000000000000000000000001000000:0035 01 00000000:00000000 00:00000000 00000000 1000 0 4243 2 0 0\n";
        assert_eq!(
            parse_proc_udp_local(table, 4243, libc::AF_INET6),
            Some("[::1]:42001".parse().unwrap())
        );
    }
}
