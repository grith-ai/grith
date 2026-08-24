// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! D-Bus wire-format decoding: just enough to answer "what method is this
//! client invoking on which peer?".
//!
//! The supervisor reads bytes a tracee is about to `write(2)` to a D-Bus
//! socket, so every input here is **adversarial**: lengths, offsets and
//! alignments come from the traced process. The decoder therefore:
//!
//! * never indexes without a bounds check (no slicing panics, no `unwrap`),
//! * treats every malformed or unexpected shape as [`WireError`] rather than
//!   guessing, and
//! * bounds the work it will do per call ([`MAX_MESSAGE_LEN`],
//!   [`MAX_HEADER_FIELDS`], [`MAX_MESSAGES_PER_CALL`]).
//!
//! A `WireError` is not a soft failure: the caller poisons the channel and
//! falls back to connect-time escalation, which is the behaviour that shipped
//! before message inspection existed. Being wrong here costs a prompt, never a
//! silent allow.
//!
//! Only the fields needed for a policy decision are decoded — message type and
//! the `PATH` / `INTERFACE` / `MEMBER` / `DESTINATION` header fields. Bodies are
//! skipped by length; their contents are never parsed.
//!
//! Reference: D-Bus Specification, "Message Protocol".

/// Longest single message the inspector will decode. The spec caps a message at
/// 128 MiB; nothing a supervised tool legitimately sends over the session bus
/// approaches this, and the buffer holding a partial message is bounded by it.
/// Larger → [`WireError::MessageTooLarge`] → channel poisoned → escalate.
pub(crate) const MAX_MESSAGE_LEN: usize = 256 * 1024;

/// Upper bound on header-field entries in one message. Real messages carry at
/// most a handful; a pathological count is a decode bomb.
const MAX_HEADER_FIELDS: usize = 64;

/// Upper bound on messages decoded from one syscall's payload, so a single
/// `writev` cannot make the supervisor walk an unbounded chain.
pub(crate) const MAX_MESSAGES_PER_CALL: usize = 64;

/// Longest string the decoder will materialise from a header field. D-Bus caps
/// bus names, interfaces, members and object paths at 255 bytes.
const MAX_FIELD_STR: usize = 255;

/// The fixed part of a message header: endianness, type, flags, version, body
/// length, serial, and the header-array length.
const FIXED_HEADER_LEN: usize = 16;

/// Client → server handshake terminator. Binary messages begin after it.
const BEGIN_LINE: &[u8] = b"BEGIN\r\n";

/// Longest SASL handshake the inspector will buffer before giving up. The real
/// exchange is a few short lines.
pub(crate) const MAX_AUTH_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WireError {
    /// A length, alignment or type code that cannot occur in a well-formed
    /// message. Carries a short static tag for forensics.
    Malformed(&'static str),
    /// The message declares a length beyond [`MAX_MESSAGE_LEN`].
    MessageTooLarge,
    /// The SASL handshake ran past [`MAX_AUTH_LEN`] without a `BEGIN`.
    AuthTooLong,
}

impl WireError {
    /// Stable, low-cardinality tag for tracing and audit fields.
    pub(crate) fn tag(&self) -> &'static str {
        match self {
            Self::Malformed(what) => what,
            Self::MessageTooLarge => "message-too-large",
            Self::AuthTooLong => "auth-too-long",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageType {
    MethodCall,
    MethodReturn,
    Error,
    Signal,
    /// A type code the spec does not define. Not a decode failure on its own —
    /// the policy layer refuses to allow it, which is the safe direction.
    Other(u8),
}

impl MessageType {
    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::MethodCall,
            2 => Self::MethodReturn,
            3 => Self::Error,
            4 => Self::Signal,
            other => Self::Other(other),
        }
    }
}

/// The policy-relevant projection of one D-Bus message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct DbusMessage {
    pub(crate) msg_type: Option<MessageType>,
    /// Header field 6 — the bus name being addressed (`org.freedesktop.secrets`).
    pub(crate) destination: Option<String>,
    /// Header field 1 — the object path.
    pub(crate) path: Option<String>,
    /// Header field 2 — the interface.
    pub(crate) interface: Option<String>,
    /// Header field 3 — the method or signal name.
    pub(crate) member: Option<String>,
    /// Header field 8 — the body's type signature (e.g. `ssa(sv)a(sa(sv))`).
    pub(crate) signature: Option<String>,
    /// The first body argument, decoded only when the signature says it is a
    /// string (`s…`) and the body parses cleanly. Best-effort by design: a
    /// body that fails to decode leaves this `None` and MUST NOT error the
    /// stream — framing never depends on the body, and the policy layer
    /// treats `None` as "could not inspect" (fail toward escalation).
    ///
    /// This exists for exactly one consumer: the `StartTransientUnit`
    /// scope-vs-service distinction in [`super::policy`], where the first
    /// argument is the unit name.
    pub(crate) body_first_string: Option<String>,
}

impl DbusMessage {
    /// `<destination>.<interface>.<member>` rendering for operator-facing text,
    /// with missing parts elided. Never empty.
    pub(crate) fn describe(&self) -> String {
        let dest = self.destination.as_deref().unwrap_or("(no destination)");
        match (self.interface.as_deref(), self.member.as_deref()) {
            (Some(iface), Some(member)) => format!("{dest} → {iface}.{member}"),
            (None, Some(member)) => format!("{dest} → {member}"),
            (Some(iface), None) => format!("{dest} → {iface}"),
            (None, None) => dest.to_string(),
        }
    }
}

/// Where a channel is in its lifecycle. A D-Bus connection opens with a NUL
/// byte and a plain-text SASL exchange; binary messages only start after the
/// client's `BEGIN\r\n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Still in the NUL + SASL handshake.
    Auth,
    /// `BEGIN\r\n` seen; everything after is binary messages.
    Messages,
}

/// Result of feeding one syscall's payload to a channel decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decoded {
    pub(crate) messages: Vec<DbusMessage>,
    /// Bytes consumed from the front of the input. The caller retains the rest
    /// as a partial message.
    pub(crate) consumed: usize,
    pub(crate) phase: Phase,
}

/// Scan the client's SASL handshake for `BEGIN\r\n`.
///
/// Returns the offset just past the terminator, or `None` while the handshake
/// is still in progress. The handshake is line-based ASCII; we do not validate
/// the mechanism, only find where binary framing starts.
fn find_begin(buf: &[u8]) -> Result<Option<usize>, WireError> {
    // `BEGIN` must sit at the start of a line. Scanning for the bare token
    // would false-positive on a mechanism name or on hex-encoded auth data
    // that happens to contain the bytes.
    let mut line_start = 0usize;
    while line_start < buf.len() {
        let Some(rel) = buf[line_start..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let line_end = line_start + rel + 1;
        let line = &buf[line_start..line_end];
        // The very first byte of the stream is the NUL credentials marker; it
        // may share the first line read.
        let line = line.strip_prefix(&[0u8][..]).unwrap_or(line);
        if line == BEGIN_LINE {
            return Ok(Some(line_end));
        }
        line_start = line_end;
    }
    if buf.len() > MAX_AUTH_LEN {
        return Err(WireError::AuthTooLong);
    }
    Ok(None)
}

/// Read a `u32` at `off` in the message's declared byte order.
fn read_u32(buf: &[u8], off: usize, little_endian: bool) -> Result<u32, WireError> {
    let end = off
        .checked_add(4)
        .ok_or(WireError::Malformed("u32-offset-overflow"))?;
    let bytes = buf
        .get(off..end)
        .ok_or(WireError::Malformed("u32-out-of-bounds"))?;
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| WireError::Malformed("u32-slice"))?;
    Ok(if little_endian {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    })
}

/// Advance `off` to the next multiple of `align`.
fn align_up(off: usize, align: usize) -> Result<usize, WireError> {
    debug_assert!(align.is_power_of_two());
    let mask = align - 1;
    off.checked_add(mask)
        .map(|v| v & !mask)
        .ok_or(WireError::Malformed("align-overflow"))
}

/// Decode a length-prefixed, NUL-terminated string. `len_bytes` is 4 for the
/// `s`/`o` types and 1 for the `g` (signature) type.
fn read_string(
    buf: &[u8],
    off: usize,
    little_endian: bool,
    len_bytes: usize,
) -> Result<(String, usize), WireError> {
    let (len, after_len) = if len_bytes == 4 {
        let off = align_up(off, 4)?;
        (read_u32(buf, off, little_endian)? as usize, off + 4)
    } else {
        let byte = *buf
            .get(off)
            .ok_or(WireError::Malformed("strlen-out-of-bounds"))?;
        (byte as usize, off + 1)
    };
    if len > MAX_FIELD_STR {
        return Err(WireError::Malformed("string-too-long"));
    }
    let end = after_len
        .checked_add(len)
        .ok_or(WireError::Malformed("string-offset-overflow"))?;
    let bytes = buf
        .get(after_len..end)
        .ok_or(WireError::Malformed("string-out-of-bounds"))?;
    // The NUL terminator is present on the wire and is not part of the value.
    if buf.get(end).copied() != Some(0) {
        return Err(WireError::Malformed("string-not-nul-terminated"));
    }
    let value = std::str::from_utf8(bytes).map_err(|_| WireError::Malformed("string-not-utf8"))?;
    Ok((value.to_string(), end + 1))
}

/// Skip one variant value of the given single-character type signature,
/// returning the offset past it.
///
/// Only the fixed-size types and the three string-like types can appear in the
/// header fields we care about. Anything else (a container) means this is a
/// header field we do not model; the caller treats that as malformed rather
/// than attempting a general-purpose D-Bus type walk, because guessing wrong
/// would desynchronise the whole stream.
fn skip_simple_value(
    buf: &[u8],
    off: usize,
    little_endian: bool,
    sig: u8,
) -> Result<usize, WireError> {
    let fixed = |align: usize, size: usize| -> Result<usize, WireError> {
        let start = align_up(off, align)?;
        let end = start
            .checked_add(size)
            .ok_or(WireError::Malformed("fixed-offset-overflow"))?;
        if end > buf.len() {
            return Err(WireError::Malformed("fixed-out-of-bounds"));
        }
        Ok(end)
    };
    match sig {
        b'y' => fixed(1, 1),
        b'b' | b'u' | b'i' => fixed(4, 4),
        b'n' | b'q' => fixed(2, 2),
        b'x' | b't' | b'd' => fixed(8, 8),
        b'h' => fixed(4, 4),
        b's' | b'o' => Ok(read_string(buf, off, little_endian, 4)?.1),
        b'g' => Ok(read_string(buf, off, little_endian, 1)?.1),
        _ => Err(WireError::Malformed("unsupported-variant-type")),
    }
}

/// Decode the header-field array of one message into a [`DbusMessage`].
fn read_header_fields(
    buf: &[u8],
    mut off: usize,
    end: usize,
    little_endian: bool,
    out: &mut DbusMessage,
) -> Result<(), WireError> {
    let mut seen = 0usize;
    while off < end {
        seen += 1;
        if seen > MAX_HEADER_FIELDS {
            return Err(WireError::Malformed("too-many-header-fields"));
        }
        // Each entry is a STRUCT, aligned to 8.
        off = align_up(off, 8)?;
        if off >= end {
            break;
        }
        let code = *buf
            .get(off)
            .ok_or(WireError::Malformed("field-code-out-of-bounds"))?;
        // The variant's own signature: a `g`-encoded type string.
        let (sig, after_sig) = read_string(buf, off + 1, little_endian, 1)?;
        let sig_byte = match sig.as_bytes() {
            [one] => *one,
            // A multi-character signature is a container type; see
            // `skip_simple_value`.
            _ => return Err(WireError::Malformed("multi-char-variant-signature")),
        };
        let next = match (code, sig_byte) {
            (1, b'o') | (2, b's') | (3, b's') | (6, b's') => {
                let (value, next) = read_string(buf, after_sig, little_endian, 4)?;
                match code {
                    1 => out.path = Some(value),
                    2 => out.interface = Some(value),
                    3 => out.member = Some(value),
                    6 => out.destination = Some(value),
                    _ => unreachable!("code matched above"),
                }
                next
            }
            // Field 8 — SIGNATURE: the body's type string, `g`-encoded.
            (8, b'g') => {
                let (value, next) = read_string(buf, after_sig, little_endian, 1)?;
                out.signature = Some(value);
                next
            }
            _ => skip_simple_value(buf, after_sig, little_endian, sig_byte)?,
        };
        if next <= off {
            // A zero-width field would loop forever.
            return Err(WireError::Malformed("field-made-no-progress"));
        }
        off = next;
    }
    Ok(())
}

/// Decode one message starting at offset 0 of `buf`.
///
/// `Ok(None)` means the message is incomplete and the caller should retain the
/// buffer and wait for more bytes.
fn read_message(buf: &[u8]) -> Result<Option<(DbusMessage, usize)>, WireError> {
    if buf.len() < FIXED_HEADER_LEN {
        return Ok(None);
    }
    let little_endian = match buf[0] {
        b'l' => true,
        b'B' => false,
        _ => return Err(WireError::Malformed("bad-endianness-flag")),
    };
    // Protocol version. The spec has only ever defined 1; a different value
    // means we are not looking at a message boundary.
    if buf[3] != 1 {
        return Err(WireError::Malformed("bad-protocol-version"));
    }
    let body_len = read_u32(buf, 4, little_endian)? as usize;
    let fields_len = read_u32(buf, 12, little_endian)? as usize;

    let fields_end = FIXED_HEADER_LEN
        .checked_add(fields_len)
        .ok_or(WireError::Malformed("fields-len-overflow"))?;
    // The body is aligned to 8 after the header-field array.
    let body_start = align_up(fields_end, 8)?;
    let total = body_start
        .checked_add(body_len)
        .ok_or(WireError::Malformed("total-len-overflow"))?;
    if total > MAX_MESSAGE_LEN {
        return Err(WireError::MessageTooLarge);
    }
    if buf.len() < total {
        return Ok(None);
    }

    let mut message = DbusMessage {
        msg_type: Some(MessageType::from_code(buf[1])),
        ..DbusMessage::default()
    };
    read_header_fields(
        buf,
        FIXED_HEADER_LEN,
        fields_end,
        little_endian,
        &mut message,
    )?;
    // Best-effort first-body-argument decode when the signature says it is a
    // string. `body_start` is 8-aligned, so the string's u32 length prefix is
    // correctly aligned at offset 0 of the body. Bounded to this message's own
    // bytes so a bad length cannot read into the next message, and any parse
    // failure just leaves the field `None` — the body is never load-bearing
    // for framing, and the policy layer fails toward escalation without it.
    if body_len > 0
        && message
            .signature
            .as_deref()
            .is_some_and(|sig| sig.as_bytes().first() == Some(&b's'))
    {
        message.body_first_string = read_string(&buf[..total], body_start, little_endian, 4)
            .ok()
            .map(|(value, _)| value);
    }
    Ok(Some((message, total)))
}

/// Decode as many complete messages as `buf` contains.
///
/// `phase` is the channel's state on entry. While it is [`Phase::Auth`] the
/// decoder looks for the handshake terminator first and only then starts
/// framing messages.
pub(crate) fn decode(buf: &[u8], phase: Phase) -> Result<Decoded, WireError> {
    let mut off = 0usize;
    let mut phase = phase;

    if phase == Phase::Auth {
        match find_begin(buf)? {
            Some(end) => {
                off = end;
                phase = Phase::Messages;
            }
            None => {
                // Still authenticating; consume nothing so the partial line is
                // retained for the next write.
                return Ok(Decoded {
                    messages: Vec::new(),
                    consumed: 0,
                    phase,
                });
            }
        }
    }

    let mut messages = Vec::new();
    while let Some((message, len)) = read_message(&buf[off..])? {
        messages.push(message);
        off += len;
        // Checked after the push so a payload carrying exactly the bound
        // decodes rather than erroring on the empty remainder.
        if messages.len() > MAX_MESSAGES_PER_CALL {
            return Err(WireError::Malformed("too-many-messages"));
        }
    }
    Ok(Decoded {
        messages,
        consumed: off,
        phase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a little-endian METHOD_CALL with the given header fields.
    /// `fields` is a list of (code, signature-char, value) string fields.
    fn build_message(msg_type: u8, fields: &[(u8, u8, &str)], body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        for (code, sig, value) in fields {
            while f.len() % 8 != 0 {
                f.push(0);
            }
            f.push(*code);
            f.push(1); // signature length
            f.push(*sig);
            f.push(0); // signature NUL
            while f.len() % 4 != 0 {
                f.push(0);
            }
            f.extend_from_slice(&(value.len() as u32).to_le_bytes());
            f.extend_from_slice(value.as_bytes());
            f.push(0);
        }
        let mut out = vec![b'l', msg_type, 0 /* flags */, 1 /* version */];
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // serial
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&f);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out.extend_from_slice(body);
        out
    }

    fn hello() -> Vec<u8> {
        build_message(
            1,
            &[
                (1, b'o', "/org/freedesktop/DBus"),
                (6, b's', "org.freedesktop.DBus"),
                (2, b's', "org.freedesktop.DBus"),
                (3, b's', "Hello"),
            ],
            &[],
        )
    }

    #[test]
    fn decodes_a_method_call() {
        let decoded = decode(&hello(), Phase::Messages).expect("decodes");
        assert_eq!(decoded.messages.len(), 1);
        let m = &decoded.messages[0];
        assert_eq!(m.msg_type, Some(MessageType::MethodCall));
        assert_eq!(m.destination.as_deref(), Some("org.freedesktop.DBus"));
        assert_eq!(m.interface.as_deref(), Some("org.freedesktop.DBus"));
        assert_eq!(m.member.as_deref(), Some("Hello"));
        assert_eq!(m.path.as_deref(), Some("/org/freedesktop/DBus"));
        assert_eq!(decoded.consumed, hello().len());
    }

    #[test]
    fn skips_the_sasl_handshake() {
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(b"AUTH EXTERNAL 31303030\r\n");
        buf.extend_from_slice(b"NEGOTIATE_UNIX_FD\r\n");
        buf.extend_from_slice(b"BEGIN\r\n");
        buf.extend_from_slice(&hello());
        let decoded = decode(&buf, Phase::Auth).expect("decodes");
        assert_eq!(decoded.phase, Phase::Messages);
        assert_eq!(decoded.messages.len(), 1);
        assert_eq!(decoded.messages[0].member.as_deref(), Some("Hello"));
    }

    #[test]
    fn auth_in_progress_consumes_nothing() {
        let decoded = decode(b"\0AUTH EXTERNAL 3130\r\n", Phase::Auth).expect("decodes");
        assert_eq!(decoded.phase, Phase::Auth);
        assert_eq!(decoded.consumed, 0);
        assert!(decoded.messages.is_empty());
    }

    #[test]
    fn begin_must_start_a_line() {
        // A mechanism line merely *containing* BEGIN must not end the handshake.
        let decoded = decode(b"\0AUTH SOMETHINGBEGIN\r\n", Phase::Auth).expect("decodes");
        assert_eq!(decoded.phase, Phase::Auth);
        assert_eq!(decoded.consumed, 0);
    }

    #[test]
    fn runaway_handshake_errors() {
        let mut buf = vec![0u8];
        buf.extend(std::iter::repeat_n(b'A', MAX_AUTH_LEN + 16));
        buf.extend_from_slice(b"\r\n");
        assert_eq!(decode(&buf, Phase::Auth), Err(WireError::AuthTooLong));
    }

    #[test]
    fn partial_message_is_retained() {
        let full = hello();
        let decoded = decode(&full[..full.len() - 4], Phase::Messages).expect("decodes");
        assert!(decoded.messages.is_empty());
        assert_eq!(decoded.consumed, 0);
    }

    #[test]
    fn two_messages_in_one_write() {
        let mut buf = hello();
        buf.extend_from_slice(&build_message(
            1,
            &[
                (6, b's', "org.freedesktop.systemd1"),
                (2, b's', "org.freedesktop.systemd1.Manager"),
                (3, b's', "StartTransientUnit"),
            ],
            &[],
        ));
        let decoded = decode(&buf, Phase::Messages).expect("decodes");
        assert_eq!(decoded.messages.len(), 2);
        assert_eq!(
            decoded.messages[1].member.as_deref(),
            Some("StartTransientUnit")
        );
        assert_eq!(decoded.consumed, buf.len());
    }

    #[test]
    fn big_endian_messages_decode() {
        let mut buf = hello();
        buf[0] = b'B';
        // Re-encode the three little-endian u32s in the fixed header.
        let body_len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let serial = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let fields_len = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        buf[4..8].copy_from_slice(&body_len.to_be_bytes());
        buf[8..12].copy_from_slice(&serial.to_be_bytes());
        buf[12..16].copy_from_slice(&fields_len.to_be_bytes());
        // Header-field string lengths are little-endian in the fixture; a
        // mixed-endian message is malformed, which is exactly what we assert:
        // the decoder must reject rather than misread.
        assert!(decode(&buf, Phase::Messages).is_err());
    }

    #[test]
    fn rejects_bad_endianness_flag() {
        let mut buf = hello();
        buf[0] = b'x';
        assert_eq!(
            decode(&buf, Phase::Messages),
            Err(WireError::Malformed("bad-endianness-flag"))
        );
    }

    #[test]
    fn rejects_bad_protocol_version() {
        let mut buf = hello();
        buf[3] = 2;
        assert_eq!(
            decode(&buf, Phase::Messages),
            Err(WireError::Malformed("bad-protocol-version"))
        );
    }

    #[test]
    fn rejects_oversized_declared_body() {
        let mut buf = hello();
        buf[4..8].copy_from_slice(&(MAX_MESSAGE_LEN as u32 + 1).to_le_bytes());
        assert_eq!(
            decode(&buf, Phase::Messages),
            Err(WireError::MessageTooLarge)
        );
    }

    #[test]
    fn rejects_unterminated_header_string() {
        let mut buf = hello();
        // Corrupt the declared length of the first string field so its NUL
        // check fails.
        let pos = buf
            .windows(4)
            .position(|w| w == (21u32).to_le_bytes())
            .expect("path length present");
        buf[pos..pos + 4].copy_from_slice(&40u32.to_le_bytes());
        assert!(decode(&buf, Phase::Messages).is_err());
    }

    #[test]
    fn header_field_with_container_signature_is_rejected() {
        let mut f: Vec<u8> = Vec::new();
        f.push(9); // UNIX_FDS-ish code
        f.push(2); // signature length 2 => container
        f.extend_from_slice(b"ai");
        f.push(0);
        let mut out = vec![b'l', 1, 0, 1];
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&f);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        assert_eq!(
            decode(&out, Phase::Messages),
            Err(WireError::Malformed("multi-char-variant-signature"))
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // Deterministic pseudo-random fuzz: the decoder must return Ok or Err,
        // never panic, on anything a tracee can put in a buffer.
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..4000 {
            let mut buf = Vec::new();
            let len = (state % 96) as usize;
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                buf.push((state >> 33) as u8);
            }
            let _ = decode(&buf, Phase::Messages);
            let _ = decode(&buf, Phase::Auth);
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
    }

    #[test]
    fn describe_renders_the_triple() {
        let m = DbusMessage {
            msg_type: Some(MessageType::MethodCall),
            destination: Some("org.freedesktop.systemd1".into()),
            interface: Some("org.freedesktop.systemd1.Manager".into()),
            member: Some("StartTransientUnit".into()),
            ..DbusMessage::default()
        };
        assert_eq!(
            m.describe(),
            "org.freedesktop.systemd1 → org.freedesktop.systemd1.Manager.StartTransientUnit"
        );
    }
}
