// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Daemon instance identity (go-live review H-20, work/74 Phase 2).
//!
//! Before this existed, "is that daemon mine?" was answered by a PID file
//! naming a live process. That is enough to tell a running daemon from a dead
//! one, and nothing more:
//!
//! - A PID is reused. A restart-identified kill could target whatever process
//!   inherited the number.
//! - It cannot distinguish *this* daemon from a different daemon that replaced
//!   it between two calls, so a supervised session could silently transfer its
//!   authority to a daemon that never admitted it.
//! - It says nothing about which audit database the daemon is writing to, so a
//!   session could be recorded into a chain other than the one that was
//!   verified at admission.
//!
//! Every daemon therefore mints an **instance UUID** at startup and publishes
//! it — with the IPC protocol version and the audit directory it owns — to
//! `daemon.json`. The file is written with a temp-file + rename so a reader
//! never observes a half-written record, and only **after the listener is
//! bound**: an identity file published before bind is a claim the daemon
//! cannot yet honour, which is how the stale-daemon lockout incident produced
//! an unkillable orphan.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Version of the daemon↔CLI IPC contract.
///
/// Bumped when a change would make an older CLI misinterpret a newer daemon
/// (or vice versa) in a way the HTTP status code alone cannot express. The
/// daemon *version* string is a release identifier and moves for reasons that
/// have nothing to do with the wire contract; this does not.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

/// Identity of one running daemon instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonIdentity {
    /// Unique per daemon process. Regenerated on every start, so it changes
    /// across a restart even when the PID happens not to.
    pub instance_id: Uuid,
    /// OS process id, for cross-checking against the PID file.
    pub pid: u32,
    /// Port the daemon is listening on.
    pub port: u16,
    /// Release version of the daemon binary.
    pub version: String,
    /// IPC contract version — see [`IPC_PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// Absolute path of the audit database this daemon owns. A session
    /// admitted against one chain must not later heartbeat to a daemon
    /// writing a different one.
    pub audit_path: Option<String>,
}

impl DaemonIdentity {
    /// Mint a fresh identity for the current process.
    #[must_use]
    pub fn new(port: u16, version: impl Into<String>, audit_path: Option<String>) -> Self {
        Self {
            instance_id: Uuid::new_v4(),
            pid: std::process::id(),
            port,
            version: version.into(),
            protocol_version: IPC_PROTOCOL_VERSION,
            audit_path,
        }
    }

    /// Whether `instance_id` names this same daemon instance.
    ///
    /// Compares parsed UUIDs rather than strings so formatting differences
    /// (case, hyphenation) cannot produce a false mismatch that silently
    /// blocks a legitimate restart.
    #[must_use]
    pub fn is_same_instance_id(&self, instance_id: Uuid) -> bool {
        self.instance_id == instance_id
    }

    /// Whether this CLI can speak to a daemon advertising `protocol_version`.
    ///
    /// Equality for now. A compatibility range only makes sense once there is
    /// more than one version to be compatible across, and guessing at one now
    /// would encode a policy nobody has had to think about yet.
    #[must_use]
    pub const fn protocol_compatible(protocol_version: u32) -> bool {
        protocol_version == IPC_PROTOCOL_VERSION
    }
}

fn identity_path() -> PathBuf {
    super::pid::runtime_dir().join("daemon.json")
}

/// Publish this daemon's identity.
///
/// Call **after** the listener is bound. Writes to a temp file and renames, so
/// a concurrent reader sees either the previous identity or the new one and
/// never a partial record.
pub fn publish(identity: &DaemonIdentity) -> std::io::Result<()> {
    let dir = super::pid::runtime_dir();
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(identity)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Same-directory temp file so the rename cannot cross a filesystem.
    let tmp = dir.join(format!("daemon.json.{}.tmp", identity.pid));
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, identity_path())
}

/// Read the published identity, if any. A missing or malformed file is
/// `None` — callers treat that as "cannot identify", never as a match.
#[must_use]
pub fn read() -> Option<DaemonIdentity> {
    let content = std::fs::read_to_string(identity_path()).ok()?;
    serde_json::from_str(&content).ok()
}

/// Remove the identity file on shutdown.
pub fn remove() {
    let _ = std::fs::remove_file(identity_path());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(port: u16) -> DaemonIdentity {
        DaemonIdentity::new(port, "0.2.1", Some("/tmp/audit.db".into()))
    }

    #[test]
    fn each_instance_gets_a_distinct_id() {
        // Two daemons started back-to-back on the same port with the same
        // version must still be distinguishable — this is what a PID file
        // alone could not do.
        assert_ne!(identity(3141).instance_id, identity(3141).instance_id);
    }

    #[test]
    fn same_instance_compares_by_id_not_by_pid_or_port() {
        let a = identity(3141);
        assert!(a.is_same_instance_id(a.instance_id));

        // A different process that reused the PID and port is NOT us.
        assert!(!a.is_same_instance_id(Uuid::new_v4()));
    }

    /// Compared as parsed UUIDs, so formatting differences cannot produce a
    /// false mismatch that silently blocks a legitimate restart.
    #[test]
    fn instance_comparison_is_format_insensitive() {
        let a = identity(3141);
        let upper = a.instance_id.to_string().to_uppercase();
        assert!(a.is_same_instance_id(Uuid::parse_str(&upper).unwrap()));
    }

    #[test]
    fn protocol_compatibility_is_exact() {
        assert!(DaemonIdentity::protocol_compatible(IPC_PROTOCOL_VERSION));
        assert!(!DaemonIdentity::protocol_compatible(
            IPC_PROTOCOL_VERSION + 1
        ));
        assert!(!DaemonIdentity::protocol_compatible(0));
    }

    #[test]
    fn identity_round_trips_through_json() {
        let original = identity(3141);
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: DaemonIdentity = serde_json::from_str(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// A truncated or garbage file must read as "no identity", never as a
    /// partial match that could authorise a kill.
    #[test]
    fn malformed_identity_json_is_rejected() {
        assert!(serde_json::from_str::<DaemonIdentity>("{\"instance_id\":").is_err());
        assert!(serde_json::from_str::<DaemonIdentity>("{}").is_err());
    }
}
