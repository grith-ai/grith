// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! OSC 52 clipboard passthrough for the exec TUI.
//!
//! The supervised tool's output is rendered through a `vt100` parser, which
//! silently drops OSC sequences it does not model. That breaks the copy
//! feature of any child that sets the clipboard via OSC 52 — notably Claude
//! Code's fullscreen renderer, whose copy-on-select / Ctrl+Shift+C emit
//! `ESC ] 52 ; c ; <base64> BEL` and expect the *terminal* to apply it.
//!
//! This module scans the raw PTY byte stream (before the vt100 parser eats
//! it) and hands complete OSC 52 sequences back to the caller for re-emission
//! to the host terminal. Deliberate policy, because OSC 52 is a known
//! attack surface for supervised tools:
//!
//! * **Writes are forwarded, reads are dropped.** An OSC 52 whose data field
//!   is `?` asks the terminal to *send the clipboard contents back to the
//!   child* — a supervised tool reading whatever the user last copied
//!   (passwords included). No copy feature needs it; it never leaves this
//!   scanner.
//! * **Every forward is logged** by the caller (sequence length only — the
//!   payload may itself be a secret, so it must not land in a log file).
//!   Clipboard writes are the classic paste-hijack channel (planting
//!   `curl … | sh` for the user's next paste), so a forensic trail must
//!   exist even though the write is allowed.
//! * **Oversized sequences are dropped, not truncated.** Terminals cap OSC 52
//!   payloads (tmux at ~74 KiB); forwarding a truncated base64 blob would
//!   paste garbage. Past [`MAX_OSC_LEN`] the sequence is discarded to its
//!   terminator.
//!
//! The scanner is chunk-boundary safe: a sequence split across PTY reads is
//! reassembled, and non-52 OSC sequences are skipped without buffering their
//! payload.

/// Upper bound on a buffered OSC sequence (base64 of ~96 KiB of text).
const MAX_OSC_LEN: usize = 128 * 1024;

/// Chunk-boundary-safe scanner extracting complete OSC 52 sequences from a
/// PTY byte stream.
#[derive(Debug, Default)]
pub(crate) struct Osc52Scanner {
    state: ScanState,
}

#[derive(Debug, Default, PartialEq)]
enum ScanState {
    /// Not inside an escape sequence.
    #[default]
    Ground,
    /// Saw `ESC`, waiting to learn what it introduces.
    Esc,
    /// Inside an OSC sequence; `buf` holds the bytes after `ESC ]`.
    /// `overflowed` means the payload passed [`MAX_OSC_LEN`] and is being
    /// discarded to its terminator.
    Osc { buf: Vec<u8>, overflowed: bool },
    /// Inside an OSC sequence and the last byte was `ESC` (potential `ESC \`
    /// string terminator).
    OscEsc { buf: Vec<u8>, overflowed: bool },
}

impl Osc52Scanner {
    /// Feed one PTY chunk; returns every complete OSC 52 **write** sequence
    /// it contains (or completes), re-encoded with a BEL terminator, ready to
    /// forward to the host terminal verbatim.
    pub(crate) fn scan(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for &b in bytes {
            self.state = match std::mem::take(&mut self.state) {
                ScanState::Ground => {
                    if b == 0x1b {
                        ScanState::Esc
                    } else {
                        ScanState::Ground
                    }
                }
                ScanState::Esc => match b {
                    b']' => ScanState::Osc {
                        buf: Vec::new(),
                        overflowed: false,
                    },
                    // `ESC ESC` — stay armed on the second ESC.
                    0x1b => ScanState::Esc,
                    _ => ScanState::Ground,
                },
                ScanState::Osc {
                    mut buf,
                    overflowed,
                } => match b {
                    // BEL terminates the OSC.
                    0x07 => {
                        if !overflowed {
                            Self::emit(&buf, &mut out);
                        }
                        ScanState::Ground
                    }
                    0x1b => ScanState::OscEsc { buf, overflowed },
                    _ => {
                        if overflowed || buf.len() >= MAX_OSC_LEN {
                            ScanState::Osc {
                                buf: Vec::new(),
                                overflowed: true,
                            }
                        } else {
                            buf.push(b);
                            ScanState::Osc { buf, overflowed }
                        }
                    }
                },
                ScanState::OscEsc { buf, overflowed } => match b {
                    // `ESC \` (ST) terminates the OSC.
                    b'\\' => {
                        if !overflowed {
                            Self::emit(&buf, &mut out);
                        }
                        ScanState::Ground
                    }
                    // ESC followed by anything else aborts the OSC — the
                    // stream has moved on to a new sequence. Re-dispatch the
                    // byte as if it followed a bare ESC.
                    b']' => ScanState::Osc {
                        buf: Vec::new(),
                        overflowed: false,
                    },
                    0x1b => ScanState::OscEsc { buf, overflowed },
                    _ => ScanState::Ground,
                },
            };
        }
        out
    }

    /// Forward `buf` (the bytes between `ESC ]` and the terminator) if it is
    /// an OSC 52 clipboard **write**.
    fn emit(buf: &[u8], out: &mut Vec<Vec<u8>>) {
        // Shape: `52;<targets>;<base64-or-?>`. Targets are selection names
        // (`c`, `p`, `s`, …) and may be empty (defaults to clipboard).
        let Some(rest) = buf.strip_prefix(b"52;") else {
            return;
        };
        let Some(sep) = rest.iter().position(|&b| b == b';') else {
            return;
        };
        let data = &rest[sep + 1..];
        // `?` asks the terminal to reply with the CURRENT clipboard —
        // a clipboard READ by the supervised tool. Never forwarded.
        if data == b"?" {
            return;
        }
        let mut seq = Vec::with_capacity(buf.len() + 3);
        seq.extend_from_slice(b"\x1b]");
        seq.extend_from_slice(buf);
        seq.push(0x07);
        out.push(seq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_seq(payload: &str) -> Vec<u8> {
        format!("\x1b]52;c;{payload}\x07").into_bytes()
    }

    #[test]
    fn forwards_a_clipboard_write_terminated_by_bel() {
        let mut s = Osc52Scanner::default();
        let seqs = s.scan(b"hello\x1b]52;c;aGVsbG8=\x07world");
        assert_eq!(seqs, vec![write_seq("aGVsbG8=")]);
    }

    #[test]
    fn forwards_a_clipboard_write_terminated_by_st() {
        let mut s = Osc52Scanner::default();
        let seqs = s.scan(b"\x1b]52;c;aGVsbG8=\x1b\\");
        // Re-encoded with BEL — terminator normalisation is deliberate.
        assert_eq!(seqs, vec![write_seq("aGVsbG8=")]);
    }

    #[test]
    fn reassembles_a_sequence_split_across_chunks() {
        let mut s = Osc52Scanner::default();
        assert!(s.scan(b"\x1b]52").is_empty());
        assert!(s.scan(b";c;aGVs").is_empty());
        let seqs = s.scan(b"bG8=\x07");
        assert_eq!(seqs, vec![write_seq("aGVsbG8=")]);
    }

    #[test]
    fn split_esc_backslash_terminator_across_chunks() {
        let mut s = Osc52Scanner::default();
        assert!(s.scan(b"\x1b]52;c;aGVsbG8=\x1b").is_empty());
        let seqs = s.scan(b"\\");
        assert_eq!(seqs, vec![write_seq("aGVsbG8=")]);
    }

    #[test]
    fn clipboard_read_query_is_never_forwarded() {
        let mut s = Osc52Scanner::default();
        assert!(s.scan(b"\x1b]52;c;?\x07").is_empty());
    }

    #[test]
    fn non_52_osc_sequences_are_ignored() {
        let mut s = Osc52Scanner::default();
        // Window title (OSC 0) and hyperlink (OSC 8).
        assert!(s
            .scan(b"\x1b]0;my title\x07\x1b]8;;https://x\x07")
            .is_empty());
        // And a 52 right after them still forwards.
        let seqs = s.scan(b"\x1b]52;c;YQ==\x07");
        assert_eq!(seqs, vec![write_seq("YQ==")]);
    }

    #[test]
    fn oversized_sequence_is_dropped_not_truncated() {
        let mut s = Osc52Scanner::default();
        let mut big = b"\x1b]52;c;".to_vec();
        big.extend(std::iter::repeat_n(b'A', MAX_OSC_LEN + 10));
        big.push(0x07);
        assert!(s.scan(&big).is_empty());
        // Scanner recovered: the next write forwards.
        let seqs = s.scan(b"\x1b]52;c;YQ==\x07");
        assert_eq!(seqs, vec![write_seq("YQ==")]);
    }

    #[test]
    fn multiple_writes_in_one_chunk_all_forward() {
        let mut s = Osc52Scanner::default();
        let seqs = s.scan(b"\x1b]52;c;YQ==\x07mid\x1b]52;p;Yg==\x07");
        assert_eq!(
            seqs,
            vec![write_seq("YQ=="), b"\x1b]52;p;Yg==\x07".to_vec()]
        );
    }
}
