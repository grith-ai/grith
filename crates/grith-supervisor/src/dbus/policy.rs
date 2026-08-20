// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Which D-Bus method calls may proceed without asking a human.
//!
//! ## Curation policy
//!
//! This table is **security-relevant**. Adding an entry decides that a method
//! cannot be used to make a more-privileged peer act on the supervised tool's
//! behalf — the exact escape `enforce_control_socket_connect` exists to catch.
//! Changes here are gated on security-team review, like
//! [`crate::supervisor::authority_delegation`]'s binary list and
//! `grith_proxy::filters::outbound_binaries`.
//!
//! ## Allowlist, not denylist
//!
//! [`classify`] allows a `METHOD_CALL` only when its (destination, interface,
//! member) triple is listed. Everything else escalates. This is the same
//! fail-safe construction as `subcommand_policy`'s read-only spawn verbs: a
//! curation gap can only cost a prompt, never open an escape. It also means
//! this file starts deliberately small — the session bus carries a long tail of
//! desktop chatter, and the answer to "my tool prompts on some other service"
//! is a reviewed addition here, not a wildcard.
//!
//! ## Deliberate exclusions
//!
//! Living on an otherwise-allowlisted destination does not make a method safe:
//!
//! * `org.freedesktop.DBus.StartServiceByName` — bus activation. Starts a peer
//!   service outside the ptrace tree; that is the escape, spelled differently.
//! * `org.freedesktop.DBus.UpdateActivationEnvironment` — sets the environment
//!   every later activated service inherits. Not an escape by itself, an
//!   excellent way to arm one.
//! * `org.freedesktop.DBus.Properties.Set` — a property write is a mutation
//!   whose effect depends entirely on the peer. `Get`/`GetAll` are read-only by
//!   definition and are allowed against any destination.
//! * The whole `org.freedesktop.portal.*` tree — it carries `Flatpak.Spawn`
//!   (literally "run this command for me") and `OpenURI` (hands a URI to a
//!   handler process). A portal allowlist would have to be per-interface and
//!   nobody has needed one yet.
//! * `org.freedesktop.systemd1`, `org.freedesktop.login1`,
//!   `org.freedesktop.PolicyKit1` and the container managers — the escape
//!   itself. Never allowlist.

use super::wire::{DbusMessage, MessageType};

/// What the supervisor should do with one decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Curated as non-delegating, or not a method call at all. Proceed with no
    /// prompt and no proxy round trip.
    Allow,
    /// Route to the proxy for scoring and, in an interactive session, a prompt.
    /// The string names the call for the operator.
    Escalate { description: String },
}

/// Interfaces that are read-only by construction, whatever they are addressed
/// to. `Introspect`, `Ping` and `GetMachineId` return static facts; `Get` and
/// `GetAll` read properties. None of them can make a peer *do* anything.
fn universal_read_only(interface: &str, member: &str) -> bool {
    match interface {
        "org.freedesktop.DBus.Introspectable" => member == "Introspect",
        "org.freedesktop.DBus.Peer" => matches!(member, "Ping" | "GetMachineId"),
        // Set is deliberately absent — see the module exclusions.
        "org.freedesktop.DBus.Properties" => matches!(member, "Get" | "GetAll"),
        _ => false,
    }
}

/// Methods on the bus daemon itself (`org.freedesktop.DBus`) that every client
/// calls to join the bus and route signals. `StartServiceByName` and
/// `UpdateActivationEnvironment` are excluded — see the module exclusions.
const BUS_DAEMON_METHODS: &[&str] = &[
    "Hello",
    "RequestName",
    "ReleaseName",
    "GetNameOwner",
    "NameHasOwner",
    "ListNames",
    "ListActivatableNames",
    "ListQueuedOwners",
    "AddMatch",
    "RemoveMatch",
    "GetId",
    "GetConnectionUnixUser",
    "GetConnectionUnixProcessID",
    "GetConnectionCredentials",
];

/// Secret Service — the freedesktop keyring API. This is what `gh auth token`,
/// `git-credential-libsecret` and every other credential helper is doing on the
/// session bus.
///
/// Reading a secret is emphatically *not* harmless in general — but it is not
/// an authority-delegating escape, which is what this enforcement point is for,
/// and the read is already scored where it belongs: the taint filter registers
/// the credential access, and egress of the result is scored at the connect or
/// spawn that carries it. Prompting here would charge the operator twice for
/// one risk and is what made every `grith exec` session open with a dialog.
const SECRET_SERVICE_INTERFACES: &[&str] = &[
    "org.freedesktop.Secret.Service",
    "org.freedesktop.Secret.Collection",
    "org.freedesktop.Secret.Item",
    "org.freedesktop.Secret.Session",
    "org.freedesktop.Secret.Prompt",
];

/// Destination bus names whose own interfaces are allowlisted wholesale, with
/// the interface set that qualifies.
fn destination_allows(destination: &str, interface: &str, member: &str) -> bool {
    match destination {
        "org.freedesktop.DBus" => {
            interface == "org.freedesktop.DBus" && BUS_DAEMON_METHODS.contains(&member)
        }
        "org.freedesktop.secrets" => SECRET_SERVICE_INTERFACES.contains(&interface),
        _ => false,
    }
}

/// Decide what to do with one decoded message.
///
/// Only `METHOD_CALL` is gated. A method return, an error reply or a signal
/// cannot invoke anything on a peer — the threat model here is
/// `Manager.StartTransientUnit`, which is always a call — so they pass. A
/// message whose type the spec does not define does *not* pass: an undefined
/// type code means we are not reading what we think we are reading.
pub(crate) fn classify(message: &DbusMessage) -> Verdict {
    match message.msg_type {
        Some(MessageType::MethodReturn) | Some(MessageType::Error) | Some(MessageType::Signal) => {
            return Verdict::Allow;
        }
        Some(MessageType::MethodCall) => {}
        Some(MessageType::Other(_)) | None => {
            return Verdict::Escalate {
                description: format!("unrecognised D-Bus message ({})", message.describe()),
            };
        }
    }

    let escalate = || Verdict::Escalate {
        description: message.describe(),
    };

    // A method call with no member cannot be matched against the table, and a
    // call with no destination addresses whatever owns the object path — on a
    // bus connection that is the daemon's routing decision, not ours to guess.
    let (Some(destination), Some(member)) = (&message.destination, &message.member) else {
        return escalate();
    };
    let Some(interface) = &message.interface else {
        // The spec permits a call without INTERFACE; the daemon resolves it by
        // member alone. We cannot tell what it reaches, so it escalates.
        return escalate();
    };

    if universal_read_only(interface, member) || destination_allows(destination, interface, member)
    {
        return Verdict::Allow;
    }
    escalate()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(destination: &str, interface: &str, member: &str) -> DbusMessage {
        DbusMessage {
            msg_type: Some(MessageType::MethodCall),
            destination: Some(destination.into()),
            interface: Some(interface.into()),
            member: Some(member.into()),
            path: None,
        }
    }

    #[test]
    fn bus_handshake_is_allowed() {
        for member in ["Hello", "AddMatch", "GetNameOwner", "RequestName"] {
            assert_eq!(
                classify(&call(
                    "org.freedesktop.DBus",
                    "org.freedesktop.DBus",
                    member
                )),
                Verdict::Allow,
                "{member} must not prompt"
            );
        }
    }

    #[test]
    fn keyring_reads_are_allowed() {
        assert_eq!(
            classify(&call(
                "org.freedesktop.secrets",
                "org.freedesktop.Secret.Service",
                "OpenSession"
            )),
            Verdict::Allow
        );
        assert_eq!(
            classify(&call(
                "org.freedesktop.secrets",
                "org.freedesktop.Secret.Item",
                "GetSecret"
            )),
            Verdict::Allow
        );
    }

    #[test]
    fn systemd_transient_unit_escalates() {
        let verdict = classify(&call(
            "org.freedesktop.systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
        ));
        match verdict {
            Verdict::Escalate { description } => {
                assert!(description.contains("StartTransientUnit"), "{description}");
            }
            Verdict::Allow => panic!("StartTransientUnit must never be allowed"),
        }
    }

    #[test]
    fn bus_activation_escalates_despite_benign_destination() {
        for member in ["StartServiceByName", "UpdateActivationEnvironment"] {
            assert!(
                matches!(
                    classify(&call(
                        "org.freedesktop.DBus",
                        "org.freedesktop.DBus",
                        member
                    )),
                    Verdict::Escalate { .. }
                ),
                "{member} activates a peer and must escalate"
            );
        }
    }

    #[test]
    fn property_writes_escalate_but_reads_do_not() {
        assert_eq!(
            classify(&call(
                "org.freedesktop.systemd1",
                "org.freedesktop.DBus.Properties",
                "Get"
            )),
            Verdict::Allow
        );
        assert!(matches!(
            classify(&call(
                "org.freedesktop.systemd1",
                "org.freedesktop.DBus.Properties",
                "Set"
            )),
            Verdict::Escalate { .. }
        ));
    }

    #[test]
    fn portal_spawn_escalates() {
        assert!(matches!(
            classify(&call(
                "org.freedesktop.portal.Desktop",
                "org.freedesktop.portal.Flatpak",
                "Spawn"
            )),
            Verdict::Escalate { .. }
        ));
    }

    #[test]
    fn replies_and_signals_pass() {
        for msg_type in [
            MessageType::MethodReturn,
            MessageType::Error,
            MessageType::Signal,
        ] {
            let message = DbusMessage {
                msg_type: Some(msg_type),
                ..DbusMessage::default()
            };
            assert_eq!(classify(&message), Verdict::Allow);
        }
    }

    #[test]
    fn undefined_message_type_escalates() {
        let message = DbusMessage {
            msg_type: Some(MessageType::Other(9)),
            ..DbusMessage::default()
        };
        assert!(matches!(classify(&message), Verdict::Escalate { .. }));
    }

    #[test]
    fn call_without_interface_escalates() {
        let message = DbusMessage {
            msg_type: Some(MessageType::MethodCall),
            destination: Some("org.freedesktop.DBus".into()),
            interface: None,
            member: Some("Hello".into()),
            path: None,
        };
        assert!(matches!(classify(&message), Verdict::Escalate { .. }));
    }

    #[test]
    fn secret_service_name_must_match_exactly() {
        // A peer that merely looks like the keyring must not inherit its
        // allowlist.
        assert!(matches!(
            classify(&call(
                "org.freedesktop.secrets.evil",
                "org.freedesktop.Secret.Item",
                "GetSecret"
            )),
            Verdict::Escalate { .. }
        ));
    }
}
