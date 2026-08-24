// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! D-Bus message inspection.
//!
//! `enforce_control_socket_connect` treats a connection to the session bus as
//! the unit of risk, because at `connect(2)` a socket path is all there is to
//! judge: "read the keyring" and "ask systemd to run this command outside the
//! ptrace tree" are byte-identical syscalls. That costs a prompt on every
//! supervised session for what is usually a credential-helper lookup.
//!
//! This module moves the decision to the unit that actually carries the
//! authority — the method call. The supervisor steps the writing process (the
//! `promote_stepping` mechanism built for connected-datagram writes), decodes
//! what it is about to send, and escalates only the calls a curated allowlist
//! does not vouch for.
//!
//! * [`wire`] — bounded, panic-free decoding of adversarial tracee memory.
//! * [`policy`] — the curated allowlist. Security-team gated.
//! * [`channel`] — per-connection handshake and reassembly state.
//!
//! Every uncertainty — a failed read, an undecodable stream, an unlisted method
//! — falls back to escalating the connection, which is exactly what shipped
//! before this module existed. A bug here costs the prompt users already had.

pub(crate) mod channel;
pub(crate) mod policy;
pub(crate) mod wire;

pub(crate) use channel::{DbusChannelTracker, Feed};
pub(crate) use policy::{classify, Verdict};

/// True when a rendered socket address is a D-Bus endpoint — the subset of
/// [`crate::supervisor::authority_delegation::is_control_injection_socket`]
/// that speaks a protocol we can decode.
///
/// X11, tmux and screen are deliberately excluded: X11 has no per-message
/// destination to key a policy on, and its real threat (XTEST input injection)
/// is handled at the spawn level by the `xdotool`/`xte`/`ydotool`/`wtype`
/// classifier. They keep connect-time escalation.
///
/// Matching mirrors `is_control_injection_socket`: lowercase, strip the
/// `unix:` scheme and any abstract-namespace `@`, then test path-component
/// anchored markers so an unrelated socket cannot collide.
pub(crate) fn is_dbus_socket(address: &str) -> bool {
    let path = address
        .strip_prefix("unix:")
        .unwrap_or(address)
        .to_ascii_lowercase();
    let path = path.strip_prefix('@').unwrap_or(&path);
    path.contains("/dbus-")
        || path.contains("/dbus/")
        || (path.starts_with("/run/user/") && path.ends_with("/bus"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::is_control_injection_socket_for_test as is_control;

    /// Bytes a real GDBus client wrote after `BEGIN\r\n`, captured by pointing
    /// `DBUS_SESSION_BUS_ADDRESS` at a stub server and running:
    ///
    /// ```text
    /// gdbus call --session --dest org.freedesktop.systemd1 \
    ///   --object-path /org/freedesktop/systemd1 \
    ///   --method org.freedesktop.systemd1.Manager.StartTransientUnit \
    ///   evil.service replace '[]' '[]'
    /// ```
    ///
    /// Three messages: the mandatory `Hello`, an `Introspect` GDBus issues on
    /// its own, and the supervision escape itself. This is the fixture that
    /// matters most — every other decoder test is written against our own
    /// encoder, and would agree with itself if our reading of the spec were
    /// wrong.
    const GDBUS_CAPTURE: &str = concat!(
        "6c01000100000000010000006e00000001016f00150000002f6f72672f66726565646573",
        "6b746f702f4442757300000002017300140000006f72672e667265656465736b746f702e",
        "444275730000000006017300140000006f72672e667265656465736b746f702e44427573",
        "00000000030173000500000048656c6c6f0000006c010001000000000200000093000000",
        "01016f00190000002f6f72672f667265656465736b746f702f73797374656d6431000000",
        "0000000002017300230000006f72672e667265656465736b746f702e444275732e496e74",
        "726f737065637461626c65000000000006017300180000006f72672e667265656465736b",
        "746f702e73797374656d64310000000000000000030173000a000000496e74726f737065",
        "63740000000000006c0100012f00000003000000ab00000001016f00190000002f6f7267",
        "2f667265656465736b746f702f73797374656d6431000000000000000201730020000000",
        "6f72672e667265656465736b746f702e73797374656d64312e4d616e6167657200000000",
        "0000000006017300180000006f72672e667265656465736b746f702e73797374656d6431",
        "000000000000000008016700047373737300000000000000030173001200000053746172",
        "745472616e7369656e74556e69740000000000000c0000006576696c2e73657276696365",
        "00000000070000007265706c61636500020000005b5d0000020000005b5d00",
    );

    fn capture_bytes() -> Vec<u8> {
        (0..GDBUS_CAPTURE.len() / 2)
            .map(|i| u8::from_str_radix(&GDBUS_CAPTURE[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn decodes_a_real_gdbus_stream_and_reaches_the_right_verdicts() {
        let bytes = capture_bytes();
        let decoded = wire::decode(&bytes, wire::Phase::Messages).expect("real GDBus traffic");
        assert_eq!(
            decoded.consumed,
            bytes.len(),
            "every message must be framed exactly; a leftover means our lengths are wrong"
        );

        let members: Vec<_> = decoded
            .messages
            .iter()
            .map(|m| m.member.clone().unwrap_or_default())
            .collect();
        assert_eq!(members, ["Hello", "Introspect", "StartTransientUnit"]);

        // The body parse must see the real unit name on real traffic — this
        // is what the StartTransientUnit scope/service split keys on, and
        // this capture is the one fixture not written against our own
        // encoder.
        assert_eq!(
            decoded.messages[2].body_first_string.as_deref(),
            Some("evil.service")
        );

        // The two GDBus issues on its own account must not prompt...
        assert_eq!(classify(&decoded.messages[0]), Verdict::Allow);
        assert_eq!(classify(&decoded.messages[1]), Verdict::Allow);
        // ...and the escape (a .service transient unit) must.
        match classify(&decoded.messages[2]) {
            Verdict::Escalate { description } => {
                assert!(description.contains("StartTransientUnit"), "{description}");
                assert!(
                    description.contains("org.freedesktop.systemd1"),
                    "{description}"
                );
            }
            Verdict::Allow => panic!("a real StartTransientUnit must never be allowed"),
        }
    }

    /// The same capture delivered one byte at a time. A real client's writes do
    /// not align to message boundaries, and this is the cheapest way to prove
    /// reassembly holds for traffic we did not encode ourselves.
    #[test]
    fn a_real_stream_reassembles_one_byte_at_a_time() {
        let bytes = capture_bytes();
        let mut tracker = DbusChannelTracker::new();
        tracker.register(1, 3, "unix:/run/user/1000/bus".into());
        // Skip the handshake this capture starts after.
        tracker.peek(1, 3, b"\0BEGIN\r\n");
        tracker.commit(1, 3, b"\0BEGIN\r\n", 7 + 1);

        let mut seen = Vec::new();
        for byte in &bytes {
            let chunk = [*byte];
            if let Feed::Messages(messages) = tracker.peek(1, 3, &chunk) {
                seen = messages;
            }
            tracker.commit(1, 3, &chunk, 1);
        }
        assert!(
            !tracker.is_poisoned(1, 3),
            "byte-wise delivery must not desync"
        );
        assert_eq!(
            seen.last().and_then(|m| m.member.clone()).as_deref(),
            Some("StartTransientUnit"),
            "the final byte must complete the escape and surface it"
        );
    }

    #[test]
    fn recognises_the_session_bus() {
        for addr in [
            "unix:/run/user/1000/bus",
            "unix:/run/user/0/bus",
            "unix:@/tmp/dbus-AbCdEf",
            "unix:/tmp/dbus-AbCdEf",
            "unix:/run/dbus/system_bus_socket",
        ] {
            assert!(is_dbus_socket(addr), "{addr} is a D-Bus endpoint");
        }
    }

    #[test]
    fn excludes_the_control_sockets_we_cannot_decode() {
        for addr in [
            "unix:/tmp/.X11-unix/X0",
            "unix:@/tmp/.x11-unix/x1",
            "unix:/tmp/tmux-1000/default",
            "unix:/run/screen/S-dan/1.pts-0",
        ] {
            assert!(!is_dbus_socket(addr), "{addr} keeps connect-time policy");
            assert!(is_control(addr), "{addr} must still be a control socket");
        }
    }

    #[test]
    fn ignores_unrelated_sockets() {
        for addr in [
            "unix:/var/run/docker.sock",
            "unix:/home/dan/project/dbus.sock",
            "unix:/run/user/1000/bus/other.sock",
            "1.2.3.4",
        ] {
            assert!(!is_dbus_socket(addr), "{addr} is not a D-Bus endpoint");
        }
    }

    /// Every address this module claims must also be one the connect-time
    /// enforcement would have escalated. If they ever diverge, inspection
    /// would be arming itself on a socket nothing was gating — a silent
    /// widening rather than a narrowing.
    #[test]
    fn dbus_sockets_are_a_subset_of_control_sockets() {
        for addr in [
            "unix:/run/user/1000/bus",
            "unix:@/tmp/dbus-AbCdEf",
            "unix:/run/dbus/system_bus_socket",
        ] {
            assert!(is_dbus_socket(addr));
            assert!(
                is_control(addr),
                "{addr} must be gated by control-socket enforcement"
            );
        }
    }
}
