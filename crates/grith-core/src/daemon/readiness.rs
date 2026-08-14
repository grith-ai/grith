// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Structured daemon readiness for fail-closed supervised execution.
//!
//! work/74 Phase 0 + Phase 2.
//!
//! `grith exec` used to treat "could not reach the daemon" as a cue to build
//! an in-process daemon and carry on. That silently changed the security
//! architecture: each fallback process got its own empty `SupervisorRegistry`,
//! so the Community two-session cap became per-process (trivially bypassed by
//! launching more processes), and every fallback process opened the same audit
//! database and ran its own verification, retention and repair.
//!
//! Supervised execution now has exactly two outcomes: an authenticated,
//! protocol-compatible daemon connection, or a non-zero exit with the target
//! never started.
//!
//! The one recovery we perform automatically is a **version-mismatch
//! restart**. The daemon outlives CLI invocations, so upgrading the binary
//! leaves an old daemon owning the port — precisely the state observed on
//! 2026-07-28 (v0.1.4 daemon, v0.2.1 CLI). Failing closed without handling
//! that would turn a silent bug into a hard stop for every upgrading user. We
//! restart only when the listener is *positively identified* as our own Grith
//! daemon; we never kill a process on port ownership alone.

use std::time::{Duration, Instant};

use super::client::DaemonClient;

/// This binary's version, compared against the running daemon's.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long to wait for a freshly spawned daemon to become authenticated-ready.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval while waiting for readiness.
const READY_POLL: Duration = Duration::from_millis(150);

/// How long to wait for a stopped daemon's port to be released.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Why supervised execution cannot proceed.
///
/// Each variant maps to a distinct operator action — the point of the enum is
/// that "daemon unavailable" is never reported as one undifferentiated
/// failure, because the remedies are different.
#[derive(Debug, Clone)]
pub enum DaemonUnready {
    /// The daemon process could not be spawned at all.
    SpawnFailed(String),
    /// Something is listening on the port but it is not a Grith daemon.
    PortOwnedByForeignProcess { port: u16 },
    /// A Grith daemon of a different build owns the port and we could not
    /// positively identify a process to stop.
    VersionMismatch {
        daemon_version: String,
        cli_version: String,
        port: u16,
    },
    /// The daemon is reachable but rejected our token.
    TokenRejected { port: u16 },
    /// The daemon started but never became authenticated-ready.
    NotReady { port: u16, waited: Duration },
    /// The daemon is up but its audit chain is quarantined, so it will not
    /// admit sessions.
    AuditQuarantined(String),
    /// The daemon is up but cannot write its audit database (another process
    /// owns it), so it will not admit sessions it cannot record.
    AuditReadOnly(String),
}

impl DaemonUnready {
    /// Operator-facing explanation and remedy.
    ///
    /// Deliberately concrete: the failure the user hits most often (a stale
    /// daemon after upgrade) must say exactly what to run.
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::SpawnFailed(e) => format!(
                "Grith could not start the local daemon.\n  {e}\n\n\
                 No supervised session was started.\n\
                 Check that the grith binary is executable and try: grith dashboard start"
            ),
            Self::PortOwnedByForeignProcess { port } => format!(
                "Grith could not establish a trusted connection to the local daemon.\n\
                 Port {port} is owned by a process that is not a Grith daemon.\n\n\
                 No supervised session was started.\n\
                 Free the port, or set a different one with `server.port` in your config."
            ),
            Self::VersionMismatch {
                daemon_version,
                cli_version,
                port,
            } => format!(
                "Grith could not establish a trusted connection to the local daemon.\n\
                 Found a Grith daemon on 127.0.0.1:{port} running {daemon_version}, \
                 but this CLI is {cli_version}.\n\n\
                 No supervised session was started.\n\
                 Run: grith dashboard restart\n\
                 Then retry the command."
            ),
            Self::TokenRejected { port } => format!(
                "Grith could not authenticate to the local daemon on 127.0.0.1:{port}.\n\n\
                 No supervised session was started.\n\
                 Run: grith dashboard restart\n\
                 Then retry the command."
            ),
            Self::NotReady { port, waited } => format!(
                "The Grith daemon on 127.0.0.1:{port} did not become ready within {:.0}s.\n\n\
                 No supervised session was started.\n\
                 Check the daemon log, then run: grith dashboard restart",
                waited.as_secs_f32()
            ),
            Self::AuditQuarantined(reason) => format!(
                "The Grith daemon is running but its audit chain is quarantined:\n  {reason}\n\n\
                 No supervised session was started — a session whose decisions cannot be \
                 verifiably recorded is not a supervised session.\n\
                 Every audit record has been preserved unmodified.\n\
                 Run: grith audit diagnose"
            ),
            Self::AuditReadOnly(reason) => format!(
                "The Grith daemon is running but cannot write its audit database:\n  {reason}\n\n\
                 No supervised session was started — a session whose decisions cannot be \
                 recorded is not a supervised session.\n\
                 Run: grith daemon restart\n\
                 Then retry the command."
            ),
        }
    }

    /// Stable short code for logs and tests.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::SpawnFailed(_) => "spawn_failed",
            Self::PortOwnedByForeignProcess { .. } => "port_owned_by_foreign_process",
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::TokenRejected { .. } => "token_rejected",
            Self::NotReady { .. } => "not_ready",
            Self::AuditQuarantined(_) => "audit_quarantined",
            Self::AuditReadOnly(_) => "audit_read_only",
        }
    }
}

impl std::fmt::Display for DaemonUnready {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.user_message())
    }
}

impl std::error::Error for DaemonUnready {}

/// What an unauthenticated probe of the configured port found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortProbe {
    /// Nothing is listening.
    Vacant,
    /// A Grith daemon responded to `/api/health` with this version.
    GrithDaemon {
        version: String,
        /// Reason the daemon's audit chain is quarantined, when it is.
        quarantined: Option<String>,
        /// Reason the daemon's audit database is read-only, when it is.
        /// `None` from a daemon predating the field.
        audit_read_only: Option<String>,
        /// Instance UUID advertised by the daemon (go-live review H-20).
        /// `None` from a daemon predating instance identity.
        instance_id: Option<String>,
        /// IPC contract version advertised by the daemon. `None` from a
        /// daemon predating instance identity.
        protocol_version: Option<u32>,
    },
    /// Something responded but it is not a Grith daemon.
    Foreign,
}

/// Probe the configured port without authenticating.
///
/// `/api/health` is unauthenticated by design (it is the liveness endpoint),
/// which is what lets us tell "old Grith daemon" apart from "someone else's
/// server" before deciding whether a restart is safe.
#[must_use]
pub fn probe_port(port: u16) -> PortProbe {
    let Ok(client) = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    else {
        return PortProbe::Foreign;
    };
    let url = format!("http://127.0.0.1:{port}/api/health");
    let Ok(resp) = client.get(&url).send() else {
        return PortProbe::Vacant;
    };
    let Ok(body) = resp.text() else {
        return PortProbe::Foreign;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else {
        return PortProbe::Foreign;
    };
    // A Grith health payload carries both `status` and `version`. Requiring
    // both keeps us from mistaking an arbitrary JSON service for our daemon.
    match (
        json.get("status"),
        json.get("version").and_then(|v| v.as_str()),
    ) {
        (Some(_), Some(version)) => PortProbe::GrithDaemon {
            version: version.to_string(),
            quarantined: json
                .get("audit_quarantined")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            audit_read_only: json
                .get("audit_read_only")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            instance_id: json
                .get("instance_id")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            protocol_version: json
                .get("protocol_version")
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| u32::try_from(v).ok()),
        },
        _ => PortProbe::Foreign,
    }
}

/// Poll until an authenticated client is available or the deadline passes.
fn await_authenticated(timeout: Duration) -> Option<DaemonClient> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(client) = DaemonClient::connect() {
            return Some(client);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(READY_POLL);
    }
}

/// Establish an authenticated, version-compatible daemon connection, or
/// explain precisely why that is impossible.
///
/// This is the only entry point supervised execution may use. It never falls
/// back to an in-process daemon.
///
/// `spawn_daemon` is injected so the caller supplies the existing auto-start
/// path (and so tests can drive this without spawning processes).
pub fn ensure_daemon_ready<F>(port: u16, spawn_daemon: F) -> Result<DaemonClient, DaemonUnready>
where
    F: FnMut() -> Result<(), String>,
{
    ensure_daemon_ready_with(DaemonClient::connect, port, spawn_daemon)
}

/// Testable core of [`ensure_daemon_ready`]: the initial fast-path connect is
/// injected because `DaemonClient::connect` reads the PID file for its port —
/// a test passing a synthetic `port` would otherwise still connect to
/// whatever daemon happens to be running on the developer's machine.
fn ensure_daemon_ready_with<C, F>(
    mut connect: C,
    port: u16,
    mut spawn_daemon: F,
) -> Result<DaemonClient, DaemonUnready>
where
    C: FnMut() -> Option<DaemonClient>,
    F: FnMut() -> Result<(), String>,
{
    // Fast path: a compatible daemon is already up and our token works. Still
    // confirm it can actually record decisions — a daemon whose audit chain is
    // quarantined (or whose audit database is read-only) will refuse admission
    // anyway, and catching it here means we say so before spawning anything
    // (work/74 Phase 2, readiness item 7).
    if let Some(client) = connect() {
        if let PortProbe::GrithDaemon {
            version,
            quarantined,
            audit_read_only,
            protocol_version,
            ..
        } = probe_port(port)
        {
            if let Some(reason) = quarantined {
                return Err(DaemonUnready::AuditQuarantined(reason));
            }
            if let Some(reason) = audit_read_only {
                return Err(DaemonUnready::AuditReadOnly(reason));
            }
            let protocol_incompatible = protocol_version
                .is_some_and(|v| !super::identity::DaemonIdentity::protocol_compatible(v));
            if version == CURRENT_VERSION && !protocol_incompatible {
                return Ok(client);
            }
            // A daemon from another build authenticated our token, but this
            // fast path can only trust the audit checks above on a daemon
            // that actually advertises them: an older daemon that silently
            // degraded to a read-only audit handle answers health with no
            // `audit_read_only` field and would break the session mid-flight
            // (the DNS-blackout incident this module's checks exist for).
            // Fall through to the version-mismatch recovery below — an
            // identity-guarded restart that replaces the stale daemon with
            // this build.
            tracing::info!(
                event = "daemon_version_skew_on_fast_path",
                daemon_version = %version,
                cli_version = CURRENT_VERSION,
                "authenticated daemon is a different build; \
                 routing through the version-mismatch recovery"
            );
        } else {
            // Transient probe failure while an authenticated connect
            // succeeded — keep the pre-existing behaviour and proceed.
            return Ok(client);
        }
    }

    let probe = probe_port(port);
    match probe {
        // Nothing there — start one and wait for it to become ready.
        PortProbe::Vacant => {
            spawn_daemon().map_err(DaemonUnready::SpawnFailed)?;
            await_authenticated(READY_TIMEOUT).ok_or(DaemonUnready::NotReady {
                port,
                waited: READY_TIMEOUT,
            })
        }

        // A Grith daemon is there but we could not authenticate to it.
        PortProbe::GrithDaemon {
            ref version,
            ref quarantined,
            ref audit_read_only,
            ref protocol_version,
            ..
        } => {
            let version = version.clone();
            // A quarantined daemon will refuse admission regardless of auth,
            // and restarting it would not clear a chain problem — report the
            // real cause rather than a token or version error.
            if let Some(reason) = quarantined {
                return Err(DaemonUnready::AuditQuarantined(reason.clone()));
            }
            // A read-only daemon also refuses admission regardless of auth.
            // Unlike quarantine a restart IS the remedy, but restarting a
            // daemon we could not authenticate to could disrupt another
            // user's sessions — report it and let the operator decide.
            if let Some(reason) = audit_read_only {
                return Err(DaemonUnready::AuditReadOnly(reason.clone()));
            }
            // go-live review H-20: an incompatible IPC contract is a version
            // problem, and the version-mismatch path already knows how to
            // recover from it (restart, then respawn). Routing it here rather
            // than failing outright keeps upgrades working.
            let protocol_incompatible = protocol_version
                .is_some_and(|v| !super::identity::DaemonIdentity::protocol_compatible(v));
            if version == CURRENT_VERSION && !protocol_incompatible {
                // Same build, but our token was refused. Restarting would not
                // obviously help and could disrupt another user's sessions, so
                // report it rather than guessing.
                return Err(DaemonUnready::TokenRejected { port });
            }

            // Different build. This is the upgrade case, and it is common
            // enough that failing here would break every upgrading user. Try
            // to recover — but only against a daemon we can positively
            // identify as ours.
            tracing::info!(
                event = "daemon_version_mismatch",
                daemon_version = %version,
                cli_version = CURRENT_VERSION,
                "stale daemon owns the port; attempting automatic restart"
            );
            // Reuse the probe we already have rather than re-fetching: the
            // identity check must be made against the daemon we actually
            // observed, not one that may have swapped in since.
            if restart_identified_daemon_with_probe(port, probe.clone()).is_err() {
                return Err(DaemonUnready::VersionMismatch {
                    daemon_version: version,
                    cli_version: CURRENT_VERSION.to_string(),
                    port,
                });
            }
            eprintln!("  Restarted the local Grith daemon (was {version}, now {CURRENT_VERSION}).");
            spawn_daemon().map_err(DaemonUnready::SpawnFailed)?;
            await_authenticated(READY_TIMEOUT).ok_or(DaemonUnready::NotReady {
                port,
                waited: READY_TIMEOUT,
            })
        }

        PortProbe::Foreign => Err(DaemonUnready::PortOwnedByForeignProcess { port }),
    }
}

/// Stop a daemon we can positively identify as ours, and wait for the port to
/// be released.
///
/// Positive identification means the PID file names a live process. We do
/// **not** derive a victim from port ownership alone: killing whatever holds a
/// port is not an acceptable automatic action.
///
/// The PID file is removed only after the port is confirmed released. It is
/// the only handle later commands have on the daemon: a daemon that survives
/// SIGTERM (e.g. wedged draining sessions) with its PID file already deleted
/// is unstoppable by every subsequent `stop`/`start`/`exec`. For the same
/// reason a SIGTERM survivor is escalated to SIGKILL — still the PID from our
/// own file, so still within the identification policy.
pub(crate) fn restart_identified_daemon(port: u16) -> Result<(), ()> {
    restart_identified_daemon_with_probe(port, probe_port(port))
}

/// Whether the observed daemon may be signalled (go-live review H-20).
///
/// Split out from the signalling itself so the identification policy can be
/// tested without a live daemon — a test that reached the `kill` would signal
/// whatever daemon happens to be running on the developer's machine.
fn may_terminate_identified_daemon(
    pid: u32,
    probe: &PortProbe,
    published: Option<super::identity::DaemonIdentity>,
) -> bool {
    // Deliberately permissive when either side is silent: a daemon predating
    // instance identity is exactly the upgrade case this restart path exists
    // to rescue, so demanding an id there would break every upgrading user —
    // the failure mode behind the stale-daemon lockout incident.
    let PortProbe::GrithDaemon {
        instance_id: Some(listening_instance),
        ..
    } = probe
    else {
        return true;
    };
    let Some(published) = published else {
        return true;
    };

    // A live PID file proves *a* process exists, not that it is the daemon
    // answering on this port — PIDs are reused, and a crashed daemon's file
    // can outlive it. When both sides advertise an id, they must agree.
    let published_instance = published.instance_id.to_string();
    let listening_matches = uuid::Uuid::parse_str(listening_instance)
        .is_ok_and(|listening| published.is_same_instance_id(listening));
    if published.pid != pid || !listening_matches {
        tracing::warn!(
            event = "daemon_restart_declined_identity_mismatch",
            pid_file_pid = pid,
            identity_pid = published.pid,
            listening_instance = %listening_instance,
            published_instance = %published_instance,
            "the daemon answering this port is not the one our identity \
             file names; refusing to terminate it"
        );
        return false;
    }
    true
}

/// Testable core of [`restart_identified_daemon`]: the probe result is passed
/// in so identity-agreement policy can be exercised without a live daemon.
pub(crate) fn restart_identified_daemon_with_probe(port: u16, probe: PortProbe) -> Result<(), ()> {
    let Some((pid, _)) = super::pid::is_dashboard_running() else {
        // No PID file, or it is stale. The listener may well be our daemon,
        // but we cannot prove which process it is, so we refuse to kill it and
        // let the caller tell the user to restart explicitly.
        tracing::warn!(
            event = "daemon_restart_declined",
            "a Grith daemon owns the port but no PID file identifies it; \
             refusing to terminate an unidentified process"
        );
        return Err(());
    };

    if !may_terminate_identified_daemon(pid, &probe, super::identity::read()) {
        return Err(());
    }

    #[cfg(unix)]
    {
        // SAFETY: SIGTERM to a PID read from our own PID file, verified live
        // by `is_dashboard_running`. The cast is valid for any OS-assigned pid.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
        if wait_for_port_release(port, STOP_TIMEOUT) {
            let _ = super::pid::remove_dashboard_pid();
            return Ok(());
        }

        tracing::warn!(
            event = "daemon_restart_escalated_sigkill",
            pid,
            "daemon did not release the port after SIGTERM; escalating to SIGKILL"
        );
        // SAFETY: same positively identified PID as above.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
        if wait_for_port_release(port, STOP_TIMEOUT) {
            let _ = super::pid::remove_dashboard_pid();
            return Ok(());
        }
        // Keep the PID file: it still names the live process we failed to
        // stop, and it is the only identification the next attempt has.
        Err(())
    }

    #[cfg(not(unix))]
    {
        // No signal-based stop on this platform. Leave the PID file alone and
        // let the caller tell the user to restart explicitly.
        let _ = pid;
        Err(())
    }
}

/// Poll until nothing is listening on `port`, or `timeout` passes. Spawning
/// into an occupied port just reproduces the orphaned-listener state this
/// module exists to fix, so callers must wait for release before starting.
pub(crate) fn wait_for_port_release(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if probe_port(port) == PortProbe::Vacant {
            return true;
        }
        std::thread::sleep(READY_POLL);
    }
    probe_port(port) == PortProbe::Vacant
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_names_a_remedy() {
        // Each message must tell the operator what to do next and must state
        // that nothing was started — the whole point of failing closed.
        let cases = vec![
            DaemonUnready::SpawnFailed("boom".into()),
            DaemonUnready::PortOwnedByForeignProcess { port: 3141 },
            DaemonUnready::VersionMismatch {
                daemon_version: "0.1.4".into(),
                cli_version: "0.2.1".into(),
                port: 3141,
            },
            DaemonUnready::TokenRejected { port: 3141 },
            DaemonUnready::NotReady {
                port: 3141,
                waited: Duration::from_secs(10),
            },
            DaemonUnready::AuditQuarantined("chain broken at 42".into()),
            DaemonUnready::AuditReadOnly("another process owns the audit database".into()),
        ];
        for case in cases {
            let msg = case.user_message();
            assert!(
                msg.contains("No supervised session was started")
                    || msg.contains("no supervised session was started"),
                "{} must state that nothing was started: {msg}",
                case.code()
            );
            assert!(!case.code().is_empty());
        }
    }

    #[test]
    fn version_mismatch_message_names_both_versions() {
        let msg = DaemonUnready::VersionMismatch {
            daemon_version: "0.1.4".into(),
            cli_version: "0.2.1".into(),
            port: 3141,
        }
        .user_message();
        assert!(msg.contains("0.1.4"), "must name the daemon version: {msg}");
        assert!(msg.contains("0.2.1"), "must name the CLI version: {msg}");
        assert!(msg.contains("grith dashboard restart"));
    }

    #[test]
    fn quarantine_message_promises_records_are_preserved() {
        let msg = DaemonUnready::AuditQuarantined("chain broken at 42".into()).user_message();
        assert!(msg.contains("preserved unmodified"), "{msg}");
        assert!(msg.contains("grith audit diagnose"), "{msg}");
    }

    #[test]
    fn read_only_message_names_the_restart_remedy() {
        let msg = DaemonUnready::AuditReadOnly("another process owns the audit database".into())
            .user_message();
        assert!(msg.contains("grith daemon restart"), "{msg}");
        assert!(msg.contains("owns the audit database"), "{msg}");
    }

    #[test]
    fn probe_of_a_vacant_port_is_vacant() {
        // Port 1 is privileged and will not have a listener in test envs.
        assert_eq!(probe_port(1), PortProbe::Vacant);
    }

    #[test]
    fn wait_for_port_release_returns_immediately_when_vacant() {
        assert!(wait_for_port_release(1, Duration::from_millis(10)));
    }

    #[test]
    fn spawn_failure_is_reported_not_swallowed() {
        // With nothing on the port and a spawn that fails, we must surface the
        // failure rather than silently proceeding — the fail-open path this
        // whole module exists to remove.
        // `DaemonClient` deliberately has no `Debug` (it holds the IPC bearer
        // token), so assert on the error side rather than debug-formatting the
        // whole Result. The connect fast-path is stubbed out: the real one
        // reads the PID file, so this test would otherwise flip between pass
        // and fail with whatever daemon is running on the machine.
        match ensure_daemon_ready_with(|| None, 1, || Err("exec format error".into())) {
            Ok(_) => panic!("expected SpawnFailed, got a connected client"),
            Err(DaemonUnready::SpawnFailed(e)) => assert!(e.contains("exec format error")),
            Err(other) => panic!("expected SpawnFailed, got {}", other.code()),
        }
    }

    // -- go-live review H-20: instance identity ---------------------------

    fn daemon_probe(instance: Option<&str>, protocol: Option<u32>) -> PortProbe {
        PortProbe::GrithDaemon {
            version: "0.1.4".into(),
            quarantined: None,
            audit_read_only: None,
            instance_id: instance.map(str::to_string),
            protocol_version: protocol,
        }
    }

    /// The health payload must carry identity so a peer can tell this daemon
    /// from one that replaced it. Parsing is what `probe_port` does with a
    /// live response; assert the shape it depends on.
    #[test]
    fn health_payload_identity_fields_are_parsed() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"status":"healthy","version":"0.2.1",
                "instance_id":"6f1e...","protocol_version":1}"#,
        )
        .unwrap();
        assert_eq!(
            json.get("instance_id").and_then(|v| v.as_str()),
            Some("6f1e...")
        );
        assert_eq!(
            json.get("protocol_version")
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| u32::try_from(v).ok()),
            Some(1)
        );
    }

    fn published_identity(
        pid: u32,
        instance: uuid::Uuid,
    ) -> super::super::identity::DaemonIdentity {
        let mut id = super::super::identity::DaemonIdentity::new(3141, "0.1.4", None);
        id.pid = pid;
        id.instance_id = instance;
        id
    }

    // These exercise the identification *policy* directly rather than
    // `restart_identified_daemon_with_probe`, which reads the real PID file
    // and would signal whatever daemon is running on the machine.

    /// A daemon that predates instance identity advertises neither field.
    /// That must stay restartable — it is precisely the upgrade case the
    /// restart path exists to rescue, and demanding an id would break every
    /// upgrading user (the stale-daemon lockout failure mode).
    #[test]
    fn daemon_without_advertised_identity_may_still_be_restarted() {
        assert!(may_terminate_identified_daemon(
            4321,
            &daemon_probe(None, None),
            None
        ));
        // Even if *we* published an identity, a listener that advertises none
        // is an older build and stays restartable.
        assert!(may_terminate_identified_daemon(
            4321,
            &daemon_probe(None, None),
            Some(published_identity(4321, uuid::Uuid::new_v4()))
        ));
    }

    /// An identity file naming a different instance than the one answering
    /// the port must veto the kill: PIDs are reused, and a stale file can
    /// outlive the daemon that wrote it.
    #[test]
    fn restart_is_declined_when_the_published_instance_disagrees() {
        let listening = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        assert!(!may_terminate_identified_daemon(
            4321,
            &daemon_probe(Some(&listening.to_string()), Some(1)),
            Some(published_identity(4321, other)),
        ));
    }

    /// Same instance id but a different PID means the identity file is stale
    /// relative to the PID file — refuse rather than guess which is right.
    #[test]
    fn restart_is_declined_when_the_published_pid_disagrees() {
        let listening = uuid::Uuid::new_v4();
        assert!(!may_terminate_identified_daemon(
            4321,
            &daemon_probe(Some(&listening.to_string()), Some(1)),
            Some(published_identity(9999, listening)),
        ));
    }

    #[test]
    fn restart_proceeds_when_pid_and_instance_both_agree() {
        let instance = uuid::Uuid::new_v4();
        assert!(may_terminate_identified_daemon(
            4321,
            &daemon_probe(Some(&instance.to_string()), Some(1)),
            Some(published_identity(4321, instance)),
        ));
    }

    #[test]
    fn protocol_compatibility_gates_the_same_version_fast_path() {
        // Same release version but an unknown protocol must not be treated as
        // "same build, token problem" — it routes into the restart path.
        assert!(
            !super::super::identity::DaemonIdentity::protocol_compatible(
                super::super::identity::IPC_PROTOCOL_VERSION + 1
            )
        );
        assert!(super::super::identity::DaemonIdentity::protocol_compatible(
            super::super::identity::IPC_PROTOCOL_VERSION
        ));
    }
}
