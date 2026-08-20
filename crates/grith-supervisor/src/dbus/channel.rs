// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Per-connection state for D-Bus message inspection.
//!
//! One [`Channel`] exists per `(tgid, fd)` a tracee has connected to a D-Bus
//! socket. It owns the two things a stream decoder needs and a syscall
//! interceptor cannot get for free:
//!
//! * **handshake phase** — binary framing only starts after the client's
//!   `BEGIN\r\n`, so the first writes on a connection are SASL text;
//! * **reassembly** — `write(2)` boundaries are not message boundaries. A
//!   partial message is retained until the bytes that complete it arrive.
//!
//! A channel can be **poisoned**. Once the byte stream stops making sense
//! (unparseable message, lost sync, buffer bound exceeded) the decoder cannot
//! honestly claim to know what the tracee is sending any more, so the channel
//! stops trying and the supervisor falls back to escalating the connection —
//! the behaviour that shipped before message inspection existed. Poisoning is
//! sticky for the life of the connection: a stream that desynchronised once
//! cannot re-synchronise by luck.
//!
//! Fd lifetime is handled by the caller, which mirrors the `DnsSocketTracker`
//! events it already handles (close, `execve`, process exit).

use std::collections::{HashMap, HashSet};

use super::wire::{self, DbusMessage, Phase, WireError, MAX_MESSAGE_LEN};

/// Cap on retained partial-message bytes. One in-flight message can be at most
/// [`MAX_MESSAGE_LEN`]; anything beyond that is not a message we will decode,
/// so holding more bytes cannot help.
const MAX_BUFFER: usize = MAX_MESSAGE_LEN;

/// Why a channel stopped being inspectable. Recorded for forensics so an
/// escalation that came from a decode failure is distinguishable from one that
/// came from policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Poison {
    pub(crate) tag: &'static str,
}

#[derive(Debug)]
pub(crate) struct Channel {
    /// Rendered socket address, e.g. `unix:/run/user/1000/bus`. Carried so the
    /// escalation can name the channel without a second sockaddr read.
    pub(crate) address: String,
    phase: Phase,
    buffer: Vec<u8>,
    poison: Option<Poison>,
}

impl Channel {
    fn new(address: String) -> Self {
        Self {
            address,
            phase: Phase::Auth,
            buffer: Vec::new(),
            poison: None,
        }
    }

    pub(crate) fn poison_tag(&self) -> Option<&'static str> {
        self.poison.as_ref().map(|p| p.tag)
    }

    fn poison(&mut self, tag: &'static str) {
        // Free the buffer: a poisoned channel never decodes again.
        self.buffer = Vec::new();
        self.buffer.shrink_to_fit();
        if self.poison.is_none() {
            self.poison = Some(Poison { tag });
        }
    }

    /// Decode what the tracee is *attempting* to send, without advancing the
    /// stream. Used to make the policy decision at the syscall-entry stop,
    /// where the kernel has not yet accepted any of it.
    ///
    /// Every message in the payload is judged, including any the kernel will
    /// go on to truncate: the tracee asked to send them, and a decision must
    /// not depend on how full a socket buffer happened to be.
    ///
    /// Poisons on a decode failure — a stream that cannot be framed is not one
    /// a later commit could rescue.
    fn peek(&mut self, bytes: &[u8]) -> Result<Vec<DbusMessage>, &'static str> {
        if let Some(tag) = self.poison_tag() {
            return Err(tag);
        }
        if self.buffer.len().saturating_add(bytes.len()) > MAX_BUFFER {
            self.poison("buffer-bound-exceeded");
            return Err("buffer-bound-exceeded");
        }
        let mut view = Vec::with_capacity(self.buffer.len() + bytes.len());
        view.extend_from_slice(&self.buffer);
        view.extend_from_slice(bytes);
        match wire::decode(&view, self.phase) {
            Ok(decoded) => Ok(decoded.messages),
            Err(err) => {
                let tag = wire_error_tag(&err);
                self.poison(tag);
                Err(tag)
            }
        }
    }

    /// Advance the stream by the bytes the kernel actually accepted.
    ///
    /// `write(2)` on a stream socket may accept fewer bytes than offered; the
    /// client library then re-sends the remainder. Committing the whole payload
    /// would leave the decoder one partial message ahead of the wire, and every
    /// subsequent frame would be read at the wrong offset — a desync that looks
    /// like garbage and would poison the channel on the *next* message rather
    /// than here. Committing exactly `accepted` keeps the decoder's position
    /// equal to the socket's.
    ///
    /// `accepted` larger than the payload we could read means bytes went out
    /// that we never saw, so the stream position is unknowable: poison.
    fn commit(&mut self, bytes: &[u8], accepted: usize) {
        if self.poison_tag().is_some() {
            return;
        }
        if accepted > bytes.len() {
            self.poison("write-exceeded-inspected-payload");
            return;
        }
        self.buffer.extend_from_slice(&bytes[..accepted]);
        match wire::decode(&self.buffer, self.phase) {
            Ok(decoded) => {
                self.phase = decoded.phase;
                self.buffer.drain(..decoded.consumed);
            }
            Err(err) => self.poison(wire_error_tag(&err)),
        }
    }
}

/// Static tag for a decode failure. `WireError::tag` already returns one; this
/// wrapper exists so the mapping lives next to the poisoning that consumes it.
fn wire_error_tag(err: &WireError) -> &'static str {
    err.tag()
}

/// Outcome of feeding a write to the tracker.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Feed {
    /// The fd is not a tracked D-Bus channel. Not our business.
    NotTracked,
    /// Decoded cleanly; these messages completed (possibly none, when the write
    /// carried only part of a message or only handshake text).
    Messages(Vec<DbusMessage>),
    /// The channel is no longer decodable. The caller must escalate the
    /// connection and stop inspecting it.
    Poisoned(&'static str),
}

/// Tracks every inspected D-Bus connection, keyed by `(tgid, fd)`.
///
/// Keyed by descriptor rather than by the `SocketId` identity the DNS tracker
/// uses, because a D-Bus stream's reassembly state belongs to the *connection*
/// as the writing process sees it. A `dup` alias writing into the same socket
/// is handled by [`Self::alias`], which shares nothing: the second descriptor
/// gets its own buffer and will poison on its first partial frame rather than
/// silently interleave with the original. Escalating a duplicated bus fd is the
/// safe direction and is not a shape any D-Bus client library produces.
#[derive(Debug, Default)]
pub(crate) struct DbusChannelTracker {
    channels: HashMap<(u32, i32), Channel>,
}

impl DbusChannelTracker {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Start inspecting `(tgid, fd)`. Replaces any previous channel on the same
    /// descriptor — a reconnect on a reused fd is a fresh stream.
    pub(crate) fn register(&mut self, tgid: u32, fd: i32, address: String) {
        self.channels.insert((tgid, fd), Channel::new(address));
    }

    pub(crate) fn is_tracked(&self, tgid: u32, fd: i32) -> bool {
        self.channels.contains_key(&(tgid, fd))
    }

    pub(crate) fn address(&self, tgid: u32, fd: i32) -> Option<&str> {
        self.channels.get(&(tgid, fd)).map(|c| c.address.as_str())
    }

    /// True once the channel has stopped being decodable.
    pub(crate) fn is_poisoned(&self, tgid: u32, fd: i32) -> bool {
        self.poison_tag_for(tgid, fd).is_some()
    }

    /// Why a channel stopped being decodable, for forensics on the escalation
    /// it causes.
    pub(crate) fn poison_tag_for(&self, tgid: u32, fd: i32) -> Option<&'static str> {
        self.channels.get(&(tgid, fd)).and_then(Channel::poison_tag)
    }

    /// Record a `dup`-family alias. The new descriptor is tracked so writes
    /// through it are not invisible, and is poisoned from the start so they
    /// escalate rather than being decoded against a buffer they do not own.
    pub(crate) fn alias(&mut self, tgid: u32, old_fd: i32, new_fd: i32) {
        let Some(address) = self.address(tgid, old_fd).map(str::to_string) else {
            return;
        };
        let mut channel = Channel::new(address);
        channel.poison("duplicated-descriptor");
        self.channels.insert((tgid, new_fd), channel);
    }

    /// Decode a pending write for the policy decision, without advancing the
    /// stream. Pair with [`Self::commit`] at the syscall-exit stop.
    pub(crate) fn peek(&mut self, tgid: u32, fd: i32, bytes: &[u8]) -> Feed {
        let Some(channel) = self.channels.get_mut(&(tgid, fd)) else {
            return Feed::NotTracked;
        };
        match channel.peek(bytes) {
            Ok(messages) => Feed::Messages(messages),
            Err(tag) => Feed::Poisoned(tag),
        }
    }

    /// Advance the stream by the `accepted` bytes the kernel took from a write
    /// previously offered to [`Self::peek`].
    pub(crate) fn commit(&mut self, tgid: u32, fd: i32, bytes: &[u8], accepted: usize) {
        if let Some(channel) = self.channels.get_mut(&(tgid, fd)) {
            channel.commit(bytes, accepted);
        }
    }

    /// Mark a channel undecodable without feeding it — used when the supervisor
    /// itself could not read the payload out of tracee memory.
    pub(crate) fn poison(&mut self, tgid: u32, fd: i32, tag: &'static str) {
        if let Some(channel) = self.channels.get_mut(&(tgid, fd)) {
            channel.poison(tag);
        }
    }

    pub(crate) fn close(&mut self, tgid: u32, fd: i32) {
        self.channels.remove(&(tgid, fd));
    }

    pub(crate) fn close_range(&mut self, tgid: u32, first: u32, last: u32) {
        self.channels
            .retain(|&(t, fd), _| t != tgid || fd < 0 || (fd as u32) < first || (fd as u32) > last);
    }

    /// Drop every channel of a process. Used at process exit.
    pub(crate) fn remove_process(&mut self, tgid: u32) {
        self.channels.retain(|&(t, _), _| t != tgid);
    }

    /// Reconcile across `execve`: forget channels whose descriptor did not
    /// survive, and poison those that did.
    ///
    /// A bus fd without `FD_CLOEXEC` outlives the image that opened it, but the
    /// client library holding the stream position does not — the new image
    /// inherits a socket mid-stream that we can no longer frame. Forgetting the
    /// survivor would make its writes invisible; decoding it would be a guess.
    /// Poisoning is the honest third option: the fd stays tracked, so writes are
    /// still seen, and each one escalates.
    ///
    /// Returns the surviving descriptors so the caller can re-arm stepping —
    /// without that they would be tracked but never surfaced.
    pub(crate) fn retain_and_poison(&mut self, tgid: u32, live_fds: &HashSet<i32>) -> Vec<i32> {
        let mut survivors = Vec::new();
        self.channels.retain(|&(t, fd), channel| {
            if t != tgid {
                return true;
            }
            if live_fds.contains(&fd) {
                channel.poison("survived-exec");
                survivors.push(fd);
                true
            } else {
                false
            }
        });
        survivors
    }

    /// Copy a forking process's channels to its child, poisoned.
    ///
    /// Parent and child share one open file description after `fork(2)`, so
    /// their writes interleave on the wire and neither side's reassembly is
    /// trustworthy. Sharing a bus connection across a fork is explicitly
    /// unsupported by every D-Bus client library, so this is not a shape real
    /// traffic takes — but a tool that does it must escalate, not be believed.
    ///
    /// Returns the child's descriptors so the caller can arm stepping for them.
    pub(crate) fn inherit_process(&mut self, parent_tgid: u32, child_tgid: u32) -> Vec<i32> {
        let inherited: Vec<(i32, String)> = self
            .channels
            .iter()
            .filter(|&(&(t, _), _)| t == parent_tgid)
            .map(|(&(_, fd), channel)| (fd, channel.address.clone()))
            .collect();
        let mut fds = Vec::with_capacity(inherited.len());
        for (fd, address) in inherited {
            let mut channel = Channel::new(address);
            channel.poison("forked-connection");
            self.channels.insert((child_tgid, fd), channel);
            fds.push(fd);
        }
        fds
    }

    /// Descriptors currently tracked for a process.
    pub(crate) fn tracked_fds(&self, tgid: u32) -> Vec<i32> {
        self.channels
            .keys()
            .filter(|&&(t, _)| t == tgid)
            .map(|&(_, fd)| fd)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal well-formed `Hello` call, little-endian.
    fn hello() -> Vec<u8> {
        let mut f = Vec::new();
        for (code, sig, value) in [
            (6u8, b's', "org.freedesktop.DBus"),
            (2u8, b's', "org.freedesktop.DBus"),
            (3u8, b's', "Hello"),
        ] {
            while f.len() % 8 != 0 {
                f.push(0);
            }
            f.push(code);
            f.push(1);
            f.push(sig);
            f.push(0);
            while f.len() % 4 != 0 {
                f.push(0);
            }
            f.extend_from_slice(&(value.len() as u32).to_le_bytes());
            f.extend_from_slice(value.as_bytes());
            f.push(0);
        }
        let mut out = vec![b'l', 1, 0, 1];
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&f);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out
    }

    /// The common case a real write takes: the kernel accepts everything, so
    /// peek and commit see the same bytes. Short writes are exercised
    /// explicitly by `short_write_does_not_desync_the_decoder`.
    fn feed(t: &mut DbusChannelTracker, tgid: u32, fd: i32, bytes: &[u8]) -> Feed {
        let outcome = t.peek(tgid, fd, bytes);
        t.commit(tgid, fd, bytes, bytes.len());
        outcome
    }

    fn tracker() -> DbusChannelTracker {
        let mut t = DbusChannelTracker::new();
        t.register(100, 7, "unix:/run/user/1000/bus".into());
        t
    }

    #[test]
    fn untracked_fd_is_not_our_business() {
        let mut t = tracker();
        assert_eq!(feed(&mut t, 100, 9, b"anything"), Feed::NotTracked);
    }

    #[test]
    fn handshake_then_message() {
        let mut t = tracker();
        assert_eq!(
            feed(&mut t, 100, 7, b"\0AUTH EXTERNAL 31303030\r\n"),
            Feed::Messages(Vec::new())
        );
        assert_eq!(
            feed(&mut t, 100, 7, b"BEGIN\r\n"),
            Feed::Messages(Vec::new())
        );
        let Feed::Messages(messages) = feed(&mut t, 100, 7, &hello()) else {
            panic!("expected messages");
        };
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].member.as_deref(), Some("Hello"));
    }

    #[test]
    fn message_split_across_writes_is_reassembled() {
        let mut t = tracker();
        feed(&mut t, 100, 7, b"\0BEGIN\r\n");
        let msg = hello();
        let (head, tail) = msg.split_at(msg.len() / 2);
        assert_eq!(feed(&mut t, 100, 7, head), Feed::Messages(Vec::new()));
        let Feed::Messages(messages) = feed(&mut t, 100, 7, tail) else {
            panic!("expected the completed message");
        };
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].member.as_deref(), Some("Hello"));
    }

    #[test]
    fn garbage_poisons_the_channel_permanently() {
        let mut t = tracker();
        feed(&mut t, 100, 7, b"\0BEGIN\r\n");
        assert!(matches!(
            feed(&mut t, 100, 7, &[0xff; 32]),
            Feed::Poisoned("bad-endianness-flag")
        ));
        assert!(t.is_poisoned(100, 7));
        // Even a perfectly good message afterwards must not un-poison it.
        assert!(matches!(feed(&mut t, 100, 7, &hello()), Feed::Poisoned(_)));
    }

    #[test]
    fn buffer_bound_poisons_rather_than_growing() {
        let mut t = tracker();
        feed(&mut t, 100, 7, b"\0BEGIN\r\n");
        // A valid header claiming a body we never complete: the buffer fills.
        let mut partial = hello();
        partial.truncate(8);
        for _ in 0..64 {
            if matches!(feed(&mut t, 100, 7, &vec![0u8; 8192]), Feed::Poisoned(_)) {
                return;
            }
        }
        panic!("an unbounded stream must poison the channel");
    }

    #[test]
    fn close_forgets_the_channel() {
        let mut t = tracker();
        t.close(100, 7);
        assert_eq!(feed(&mut t, 100, 7, b"x"), Feed::NotTracked);
    }

    #[test]
    fn close_range_forgets_the_span() {
        let mut t = tracker();
        t.register(100, 12, "unix:/run/user/1000/bus".into());
        t.close_range(100, 5, 10);
        assert!(!t.is_tracked(100, 7));
        assert!(t.is_tracked(100, 12));
    }

    #[test]
    fn exec_and_exit_drop_every_channel_of_the_process() {
        let mut t = tracker();
        t.register(100, 8, "unix:/run/user/1000/bus".into());
        t.register(200, 7, "unix:/run/user/1000/bus".into());
        t.remove_process(100);
        assert!(t.tracked_fds(100).is_empty());
        assert!(t.is_tracked(200, 7));
    }

    #[test]
    fn reconnect_on_a_reused_fd_starts_a_fresh_stream() {
        let mut t = tracker();
        feed(&mut t, 100, 7, b"\0BEGIN\r\n");
        // A full fixed header's worth of garbage — fewer bytes than that is an
        // incomplete message, not a malformed one.
        feed(&mut t, 100, 7, &[0xff; 32]);
        assert!(t.is_poisoned(100, 7));
        t.register(100, 7, "unix:/run/user/1000/bus".into());
        assert!(!t.is_poisoned(100, 7));
    }

    #[test]
    fn short_write_does_not_desync_the_decoder() {
        let mut t = tracker();
        feed(&mut t, 100, 7, b"\0BEGIN\r\n");
        let msg = hello();
        // The kernel accepts only the first half. The tracee's next write
        // re-sends the remainder, which must complete exactly one message —
        // not be framed as a fresh one.
        let accepted = msg.len() / 2;
        assert!(matches!(
            t.peek(100, 7, &msg),
            Feed::Messages(ref m) if m.len() == 1
        ));
        t.commit(100, 7, &msg, accepted);
        assert!(!t.is_poisoned(100, 7));

        let remainder = &msg[accepted..];
        let Feed::Messages(messages) = t.peek(100, 7, remainder) else {
            panic!("the re-sent remainder must complete the message");
        };
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].member.as_deref(), Some("Hello"));
        t.commit(100, 7, remainder, remainder.len());

        // And the stream is still framed correctly for the next message.
        let Feed::Messages(next) = feed(&mut t, 100, 7, &hello()) else {
            panic!("expected a cleanly framed follow-up message");
        };
        assert_eq!(next.len(), 1);
        assert!(!t.is_poisoned(100, 7));
    }

    #[test]
    fn a_failed_write_advances_nothing() {
        let mut t = tracker();
        feed(&mut t, 100, 7, b"\0BEGIN\r\n");
        let msg = hello();
        t.peek(100, 7, &msg);
        // write(2) returned an error: no bytes reached the socket.
        t.commit(100, 7, &msg, 0);
        assert!(!t.is_poisoned(100, 7));
        // The retry is the same bytes and must decode as one message.
        let Feed::Messages(messages) = feed(&mut t, 100, 7, &msg) else {
            panic!("the retried write must decode");
        };
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn a_write_larger_than_we_inspected_poisons() {
        let mut t = tracker();
        feed(&mut t, 100, 7, b"\0BEGIN\r\n");
        let msg = hello();
        t.peek(100, 7, &msg);
        // The kernel reports more bytes sent than we were able to read out of
        // tracee memory: the stream position is unknowable.
        t.commit(100, 7, &msg, msg.len() + 1);
        assert_eq!(
            t.poison_tag_for(100, 7),
            Some("write-exceeded-inspected-payload")
        );
    }

    #[test]
    fn peek_judges_messages_the_kernel_will_truncate() {
        let mut t = tracker();
        feed(&mut t, 100, 7, b"\0BEGIN\r\n");
        let mut batch = hello();
        batch.extend_from_slice(&hello());
        // Both messages must be judged even though only the first will be
        // accepted — the tracee asked to send both.
        let Feed::Messages(messages) = t.peek(100, 7, &batch) else {
            panic!("expected both messages");
        };
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn dup_alias_is_tracked_and_escalates() {
        let mut t = tracker();
        t.alias(100, 7, 11);
        assert!(t.is_tracked(100, 11));
        assert!(t.is_poisoned(100, 11));
        assert!(matches!(
            feed(&mut t, 100, 11, &hello()),
            Feed::Poisoned("duplicated-descriptor")
        ));
        // The original keeps working.
        assert!(!t.is_poisoned(100, 7));
    }

    #[test]
    fn alias_of_an_untracked_fd_is_a_no_op() {
        let mut t = tracker();
        t.alias(100, 99, 11);
        assert!(!t.is_tracked(100, 11));
    }
}
