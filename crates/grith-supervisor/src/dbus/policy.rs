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
//! * The `org.freedesktop.portal.*` tree, excepting two carved interfaces —
//!   it carries `Flatpak.Spawn` (literally "run this command for me") and
//!   `OpenURI` (hands a URI to a handler process), so the portal allowlist is
//!   per-interface: `portal.Settings` reads (the theme/colour-scheme query
//!   every GTK, Electron and Chromium process makes) and `portal.Secret`
//!   (the portal spelling of the already-allowlisted Secret Service, same
//!   rationale). Everything else on the portal escalates.
//! * `org.freedesktop.systemd1`, `org.freedesktop.login1`,
//!   `org.freedesktop.PolicyKit1` and the container managers — the escape
//!   itself. Never allowlist wholesale. Two narrow exceptions are carved
//!   below with their own rationale: `Manager.GetUnit` (a pure lookup that
//!   cannot make the manager act) and `Manager.StartTransientUnit` **only
//!   when the unit name in the message body ends in `.scope`** — a scope
//!   unit cannot carry `ExecStart`; it moves ALREADY-RUNNING pids into a
//!   cgroup, so the executing process is always a ptrace descendant of the
//!   caller (this is why `systemd-run --scope CMD` runs CMD as its own
//!   supervised child). The `.service` form — where the manager forks the
//!   process *outside* the supervised tree — still escalates, as does any
//!   `StartTransientUnit` whose body cannot be inspected.

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
        // The ObjectManager interface defines exactly one method, and it is a
        // bulk property read. Chrome calls it against org.bluez on the system
        // bus to enumerate adapters for Web Bluetooth; same read-only
        // contract whatever it is addressed to.
        "org.freedesktop.DBus.ObjectManager" => member == "GetManagedObjects",
        // GTK VFS mount enumeration — `gio open <uri>` asks gvfsd what mount
        // types exist and whether the target sits on one before it does
        // anything. Matched by interface, not destination: gvfsd is reached
        // by its unique connection name (`:1.N`), which no well-known-name
        // table can list. The members here only DESCRIBE mounts;
        // `MountLocation` — which performs one, network authentication
        // included — is deliberately absent and escalates.
        "org.gtk.vfs.MountTracker" => matches!(
            member,
            "ListMountableInfo" | "LookupMount" | "ListMounts" | "ListMounts2"
        ),
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
        // Notification-server INTROSPECTION only: what the server is and what
        // it supports. `Notify` is deliberately absent — grith's own security
        // prompts arrive through this service, so a supervised tool posting
        // notifications is a spoofing surface — and so is
        // `CloseNotification`, which could dismiss a real prompt.
        "org.freedesktop.Notifications" => {
            interface == "org.freedesktop.Notifications"
                && matches!(member, "GetCapabilities" | "GetServerInformation")
        }
        // Screensaver STATE READ only (browsers poll it for power/idle
        // handling). `Inhibit`/`SimulateUserActivity` mutate idle behaviour
        // and stay escalated.
        "org.freedesktop.ScreenSaver" | "org.gnome.ScreenSaver" => {
            member == "GetActive"
                && matches!(
                    interface,
                    "org.freedesktop.ScreenSaver" | "org.gnome.ScreenSaver"
                )
        }
        // The desktop portal, PER-INTERFACE — the tree as a whole stays
        // excluded (see the module exclusions: `Flatpak.Spawn`, `OpenURI`).
        //
        // `Settings` is the read-only appearance query (colour scheme,
        // contrast) every GTK/Electron/Chromium process makes at startup.
        //
        // `Secret.RetrieveSecret` is the portal spelling of the Secret
        // Service this table already allowlists, with the same rationale: a
        // keyring read is not an authority-delegating escape, the taint
        // filter registers the credential access, and egress of the result
        // is scored at the connect or spawn that carries it. Chromium uses
        // it for its os_crypt storage key on every launch.
        "org.freedesktop.portal.Desktop" => match interface {
            "org.freedesktop.portal.Settings" => matches!(member, "Read" | "ReadAll"),
            "org.freedesktop.portal.Secret" => member == "RetrieveSecret",
            // Host-app self-registration with the portal registry — Chromium
            // and Electron call this on every launch to associate their app
            // id with the connection. Registering an id delegates nothing by
            // itself; it only influences how the portal attributes LATER
            // requests, and every portal method that could act on that
            // attribution (`Flatpak.Spawn`, `OpenURI`, screen capture, …)
            // still escalates through this table.
            "org.freedesktop.host.portal.Registry" => member == "Register",
            _ => false,
        },
        // systemd's manager is the escape surface and stays excluded — with
        // one read-only member: `GetUnit` maps a unit name to an object path
        // (or a NoSuchUnit error). It cannot start, stop, or modify anything;
        // the same contract as the `Properties.Get` reads allowed against any
        // destination, and it discloses less than the already-allowlisted bus
        // daemon `ListNames`. Chromium calls it on every launch right after
        // its scope registration. `LoadUnit` is deliberately absent — it
        // makes the manager load a unit file from disk.
        "org.freedesktop.systemd1" => {
            interface == "org.freedesktop.systemd1.Manager" && member == "GetUnit"
        }
        _ => false,
    }
}

/// The one body-dependent rule: `Manager.StartTransientUnit` addressed to
/// systemd, when the unit NAME (the call's first argument) ends in `.scope`.
///
/// A transient scope cannot carry `ExecStart` — systemd rejects it — so the
/// call can only place pids that ALREADY exist into a cgroup. The executing
/// process is therefore always a child of the (supervised) caller: this is
/// the mechanism behind Chromium's per-launch self-registration
/// (`app-…-chrome-<pid>.scope`) and `systemd-run --scope`, where systemd-run
/// forks the command itself and stays inside the ptrace tree. The escape this
/// table exists to catch is the `.service` form, where the USER MANAGER forks
/// the process outside supervision — that form, and any call whose body could
/// not be decoded (`body_first_string == None`), still escalates.
fn is_scope_only_transient_unit(message: &DbusMessage) -> bool {
    message.destination.as_deref() == Some("org.freedesktop.systemd1")
        && message.interface.as_deref() == Some("org.freedesktop.systemd1.Manager")
        && message.member.as_deref() == Some("StartTransientUnit")
        && message
            .body_first_string
            .as_deref()
            .is_some_and(|unit| unit.ends_with(".scope"))
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
    if is_scope_only_transient_unit(message) {
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
            ..DbusMessage::default()
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
            Verdict::Allow => {
                panic!("StartTransientUnit without an inspectable body must never be allowed")
            }
        }
    }

    fn transient_unit_call(unit_name: Option<&str>) -> DbusMessage {
        let mut message = call(
            "org.freedesktop.systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
        );
        message.signature = Some("ssa(sv)a(sa(sv))".into());
        message.body_first_string = unit_name.map(String::from);
        message
    }

    /// The scope-vs-service split on `StartTransientUnit`.
    ///
    /// A `.scope` unit cannot carry `ExecStart` — it only places pids that
    /// already exist (Chromium's own, `systemd-run --scope`'s own child) into
    /// a cgroup, so the executing process stays a supervised descendant.
    /// Every other unit type is the escape (the user manager forks the
    /// process outside the ptrace tree) and must keep escalating, as must a
    /// call whose body could not be decoded: `None` means "could not
    /// inspect", never "assume benign".
    #[test]
    fn transient_scope_units_allow_but_every_other_form_escalates() {
        assert_eq!(
            classify(&transient_unit_call(Some("app-glib-chrome-1234.scope"))),
            Verdict::Allow,
            "a transient .scope cannot execute anything outside the tree"
        );
        for unit in [
            Some("evil.service"),
            Some("evil.timer"),
            Some("evil.socket"),
            // A name CONTAINING but not ENDING in .scope is not a scope.
            Some("evil.scope.service"),
            None,
        ] {
            assert!(
                matches!(
                    classify(&transient_unit_call(unit)),
                    Verdict::Escalate { .. }
                ),
                "StartTransientUnit({unit:?}) must escalate"
            );
        }
    }

    /// `Manager.GetUnit` is a pure name → object-path lookup: it cannot make
    /// the manager act, and it discloses less than the already-allowlisted
    /// bus daemon `ListNames`. Chromium calls it on every launch.
    #[test]
    fn systemd_get_unit_lookup_is_allowed() {
        assert_eq!(
            classify(&call(
                "org.freedesktop.systemd1",
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
            )),
            Verdict::Allow
        );
    }

    /// Host-app portal registration (Chromium/Electron per launch). The id it
    /// registers only shapes how the portal attributes LATER requests, and
    /// every portal method that could act on that attribution still
    /// escalates through this table.
    #[test]
    fn host_portal_registry_register_is_allowed() {
        assert_eq!(
            classify(&call(
                "org.freedesktop.portal.Desktop",
                "org.freedesktop.host.portal.Registry",
                "Register",
            )),
            Verdict::Allow
        );
    }

    /// The Chrome-session additions: read-only probes pass, and the members
    /// on the same services that could act — post or dismiss a notification,
    /// inhibit the screensaver, start a transient unit — still escalate.
    #[test]
    fn browser_probe_reads_allow_but_acting_members_escalate() {
        for (dest, iface, member) in [
            (
                "org.bluez",
                "org.freedesktop.DBus.ObjectManager",
                "GetManagedObjects",
            ),
            // gvfsd answers on its unique name; the interface carries the match.
            (":1.19", "org.gtk.vfs.MountTracker", "ListMountableInfo"),
            (":1.19", "org.gtk.vfs.MountTracker", "LookupMount"),
            (
                "org.freedesktop.Notifications",
                "org.freedesktop.Notifications",
                "GetCapabilities",
            ),
            (
                "org.freedesktop.Notifications",
                "org.freedesktop.Notifications",
                "GetServerInformation",
            ),
            (
                "org.freedesktop.ScreenSaver",
                "org.freedesktop.ScreenSaver",
                "GetActive",
            ),
            (
                "org.gnome.ScreenSaver",
                "org.gnome.ScreenSaver",
                "GetActive",
            ),
        ] {
            assert_eq!(
                classify(&call(dest, iface, member)),
                Verdict::Allow,
                "{dest} {member} is a read-only probe"
            );
        }
        for (dest, iface, member) in [
            (
                "org.freedesktop.portal.Desktop",
                "org.freedesktop.portal.Settings",
                "Read",
            ),
            (
                "org.freedesktop.portal.Desktop",
                "org.freedesktop.portal.Settings",
                "ReadAll",
            ),
            (
                "org.freedesktop.portal.Desktop",
                "org.freedesktop.portal.Secret",
                "RetrieveSecret",
            ),
        ] {
            assert_eq!(
                classify(&call(dest, iface, member)),
                Verdict::Allow,
                "{iface}.{member} is a carved portal interface"
            );
        }
        for (dest, iface, member) in [
            // The portal interfaces that ARE the escape: never ride the
            // Settings/Secret carve.
            (
                "org.freedesktop.portal.Desktop",
                "org.freedesktop.portal.Flatpak",
                "Spawn",
            ),
            (
                "org.freedesktop.portal.Desktop",
                "org.freedesktop.portal.OpenURI",
                "OpenURI",
            ),
            // Posting a notification is how a supervised tool would spoof a
            // grith prompt; dismissing one is how it would hide a real one.
            (
                "org.freedesktop.Notifications",
                "org.freedesktop.Notifications",
                "Notify",
            ),
            (
                "org.freedesktop.Notifications",
                "org.freedesktop.Notifications",
                "CloseNotification",
            ),
            (
                "org.freedesktop.ScreenSaver",
                "org.freedesktop.ScreenSaver",
                "Inhibit",
            ),
            // systemd1 members that make the manager ACT (or load state from
            // disk) stay excluded; only the pure `GetUnit` lookup is carved,
            // asserted in `systemd_get_unit_lookup_is_allowed`.
            (
                "org.freedesktop.systemd1",
                "org.freedesktop.systemd1.Manager",
                "LoadUnit",
            ),
            (
                "org.freedesktop.systemd1",
                "org.freedesktop.systemd1.Manager",
                "StartUnit",
            ),
            // Actually mounting something (with the network auth flow that
            // can involve) is an action, not a description.
            (":1.19", "org.gtk.vfs.MountTracker", "MountLocation"),
            // bluez members outside the ObjectManager read (pairing etc.).
            ("org.bluez", "org.bluez.Adapter1", "StartDiscovery"),
        ] {
            assert!(
                matches!(
                    classify(&call(dest, iface, member)),
                    Verdict::Escalate { .. }
                ),
                "{dest} {member} must escalate"
            );
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
            ..DbusMessage::default()
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
