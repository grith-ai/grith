// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Fullscreen-repaint scrollback for paginated TUIs.
//!
//! Background — `vt100`'s built-in scrollback only retains rows that scroll
//! off the top of the visible grid. Fullscreen-repaint TUIs (Codex, Claude
//! Code, many Ink-based agents) clear and repaint in place using absolute
//! cursor addressing, so they never feed `vt100`'s scrollback. The host
//! terminal doesn't help either: WezTerm, xterm, kitty all map wheel-in-alt
//! to arrow keys by default and provide no scrollback for the alternate
//! screen.
//!
//! Solution — maintain a parallel "scrollback mirror" `vt100::Parser` that
//! receives each captured frame's plain-text content as new lines (one row
//! at a time, separated by `\r\n`). The mirror is in primary-screen mode
//! and never enters alt-screen, so each frame's lines naturally scroll off
//! the top of the mirror's visible area into its own scrollback. When the
//! user wheel-scrolls back in fullscreen-history mode, we render from the
//! mirror's screen at a `set_scrollback(N)` offset — exactly the same
//! mechanism that already powers grith's normal scrollback for
//! line-oriented tools.
//!
//! Frame boundaries are detected from the byte stream:
//!
//! * Preferred path: synchronized output markers
//!   (`CSI ?2026h` / `CSI ?2026l`). When we see the closing `l` we capture
//!   exactly one snapshot of the post-batch screen.
//! * Fallback path: repaint heuristics. Counts repeated fullscreen control
//!   traffic — `CSI 2J`, cursor-home / cursor-position, `CSI K`, `CSI r`,
//!   `ESC M`. Above a small threshold we enter repaint mode and capture on
//!   batch-end with a stable screen.
//!
//! The mirror is intentionally limited to fullscreen redrawers. Normal
//! line-oriented output continues to use `vt100`'s native scrollback on
//! the live parser.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Soft cap on accumulated scrollback lines. At 200 cols × ~1 byte/char
/// avg that's about 2 MB per session. Comfortably within budget for
/// hours of paginated-TUI use.
pub const HISTORY_LINE_CAPACITY: usize = 10_000;

/// Maximum scan-tail bytes retained between batches. Has to cover the longest
/// CSI sequence we care about (`\x1b[?2026h` = 8 bytes plus slack).
const SCAN_TAIL_MAX: usize = 32;

/// Minimum number of repaint signals before we treat the app as a fullscreen
/// redrawer. One-off clears (e.g. `clear` at the shell) shouldn't enter
/// repaint mode.
const REPAINT_SIGNAL_THRESHOLD: u8 = 3;

/// Saturating ceiling for `repaint_signal_score`. Once a tool has clearly
/// declared itself a fullscreen redrawer we don't need a bigger counter.
const REPAINT_SIGNAL_CEIL: u8 = 12;

/// Idle window after a repaint batch before we treat the screen as stable
/// enough to snapshot. Tuned to be small relative to the 30fps render budget.
const REPAINT_IDLE_WINDOW: Duration = Duration::from_millis(40);

/// Boundary signals observed in a single `observe_bytes` pass.
#[allow(clippy::struct_excessive_bools)] // bitfield-style observation flags
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedBoundaries {
    sync_opened: bool,
    sync_closed: bool,
    repaint_signals: u8,
    alt_screen_entered: bool,
    alt_screen_left: bool,
}

/// Accumulated scrollback + boundary-detection state.
///
/// Captured frames have their plain text appended row-by-row into a
/// `VecDeque<String>`. The live `vt100::Parser` stays untouched. On render,
/// when the user is scrolled back, we materialise a viewport-sized window
/// of these lines into a synthetic `vt100::Parser` and pass its screen to
/// the existing `render_vterm` widget — same render path as the live view.
///
/// Why text instead of cloned `vt100::Screen` per frame:
/// * vt100 0.15's `set_scrollback` semantics cap usable scrollback at one
///   viewport, so storing full screens doesn't translate to scrollable
///   distance. Storing lines and windowing them gives unbounded scroll
///   reach regardless of the underlying parser's limits.
/// * Text-line storage is 10–50× smaller per frame than a cloned screen
///   (no per-cell attrs), so the line cap can be much higher without
///   blowing the memory budget.
///
/// Trade-off: colours and per-cell attrs are not preserved in the scrolled
/// view (re-rendering goes through fresh parser bytes). Live view is
/// unchanged. Colour preservation is a tracked follow-up.
#[allow(clippy::struct_excessive_bools)] // boundary state machine is intentionally flag-shaped
pub struct FullscreenScrollback {
    /// Accumulated text lines from captured frames, newest at the back.
    /// FIFO-evicted past `capacity`.
    lines: VecDeque<String>,
    /// Maximum lines retained.
    capacity: usize,
    /// Number of complete frames pushed since the last `clear`. Used by
    /// callers to decide whether the user has anything to scroll back to.
    frames_pushed: usize,
    /// Cached signature of the last captured frame for dedupe — avoids
    /// pushing identical successive frames when the live screen hasn't
    /// changed between batches (Codex's animation spinner case).
    last_signature: Option<Vec<u8>>,
    /// Timestamp of the most recent capture.
    last_capture_at: Option<Instant>,
    /// Are we currently treating the app as a fullscreen redrawer?
    repaint_mode: bool,
    /// True while inside a `CSI ?2026 h ... CSI ?2026 l` batch.
    sync_update_open: bool,
    /// Set for one capture cycle when we observed the closing
    /// `CSI ?2026 l` marker. Cleared after we consider capturing.
    sync_just_closed: bool,
    /// Saturating counter of repaint markers seen since the last reset.
    /// Once it exceeds `REPAINT_SIGNAL_THRESHOLD` we enter repaint mode.
    repaint_signal_score: u8,
    /// Pending repaint signals from the current batch that haven't yet
    /// been committed to a capture decision.
    pending_repaint_signals: u8,
    /// True if alt-screen is currently active (informational only — we
    /// capture for both alt and primary repaint cases).
    in_alt_screen: bool,
    /// Tail bytes retained so split CSI sequences are stitched back
    /// together across PTY chunks.
    scan_tail: Vec<u8>,
    /// True after the mirror has been disabled (e.g. capacity == 0).
    enabled: bool,
}

impl FullscreenScrollback {
    pub fn new(enabled: bool) -> Self {
        let capacity = if enabled { HISTORY_LINE_CAPACITY } else { 0 };
        Self {
            lines: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
            frames_pushed: 0,
            last_signature: None,
            last_capture_at: None,
            repaint_mode: false,
            sync_update_open: false,
            sync_just_closed: false,
            repaint_signal_score: 0,
            pending_repaint_signals: 0,
            in_alt_screen: false,
            scan_tail: Vec::with_capacity(SCAN_TAIL_MAX),
            enabled,
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(true)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of frames pushed into the scrollback since reset.
    pub fn frames_pushed(&self) -> usize {
        self.frames_pushed
    }

    pub fn is_empty(&self) -> bool {
        self.frames_pushed == 0
    }

    /// Total accumulated lines (across all captured frames + separators).
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    pub fn repaint_mode(&self) -> bool {
        self.repaint_mode
    }

    pub fn sync_update_open(&self) -> bool {
        self.sync_update_open
    }

    /// Resize is now a no-op for the line-based storage (the render path
    /// re-builds a synthetic parser at the live viewport size each frame).
    /// Kept for API compatibility with the resize hook.
    pub fn resize_mirror(&mut self, _rows: u16, _cols: u16) -> bool {
        false
    }

    /// Return up to `viewport_rows` lines from the accumulated scrollback,
    /// starting `scroll_offset` rows back from the most recent end. Useful
    /// for rendering the scrolled view via a fresh synthetic parser.
    ///
    /// `scroll_offset = 0` returns the most recent viewport. Larger
    /// offsets walk into older content, clamped at the oldest line.
    pub fn visible_window(&self, viewport_rows: usize, scroll_offset: usize) -> Vec<&str> {
        let total = self.lines.len();
        if total == 0 || viewport_rows == 0 {
            return Vec::new();
        }
        // Bottom of the window sits `scroll_offset` lines above the end.
        let end = total.saturating_sub(scroll_offset);
        let start = end.saturating_sub(viewport_rows);
        self.lines.range(start..end).map(|s| s.as_str()).collect()
    }

    /// Maximum scroll offset that surfaces at least one line of new content.
    /// Used to clamp wheel input so PageUp/End/wheel-up stop at the oldest
    /// available line.
    pub fn max_scroll_offset(&self, viewport_rows: usize) -> usize {
        self.lines.len().saturating_sub(viewport_rows)
    }

    /// Scan PTY bytes for frame boundaries and repaint signals. Idempotent
    /// with respect to the live `vt100::Parser` — this method does NOT feed
    /// bytes to the parser, it only updates boundary state.
    pub fn observe_bytes(&mut self, bytes: &[u8]) {
        if !self.enabled || bytes.is_empty() {
            return;
        }

        // Stitch saved tail with the new chunk so split sequences resolve.
        let mut combined: Vec<u8> = Vec::with_capacity(self.scan_tail.len() + bytes.len());
        combined.extend_from_slice(&self.scan_tail);
        combined.extend_from_slice(bytes);

        let (observed, tail_start) = scan_for_boundaries(&combined);

        // Apply observations.
        if observed.sync_opened {
            self.sync_update_open = true;
        }
        if observed.sync_closed {
            self.sync_update_open = false;
            self.sync_just_closed = true;
        }
        if observed.alt_screen_entered {
            self.in_alt_screen = true;
            // Alt-screen enter is itself a strong fullscreen signal.
            self.bump_repaint_signal(2);
        }
        if observed.alt_screen_left {
            self.in_alt_screen = false;
        }
        if observed.repaint_signals > 0 {
            self.bump_repaint_signal(observed.repaint_signals);
            self.pending_repaint_signals = self
                .pending_repaint_signals
                .saturating_add(observed.repaint_signals);
        }

        // Preserve a small tail so partial sequences are resolved next call.
        self.scan_tail.clear();
        if tail_start < combined.len() {
            let tail_slice = &combined[tail_start..];
            let take = tail_slice.len().min(SCAN_TAIL_MAX);
            self.scan_tail
                .extend_from_slice(&tail_slice[tail_slice.len() - take..]);
        }
    }

    fn bump_repaint_signal(&mut self, by: u8) {
        self.repaint_signal_score = self
            .repaint_signal_score
            .saturating_add(by)
            .min(REPAINT_SIGNAL_CEIL);
        if self.repaint_signal_score >= REPAINT_SIGNAL_THRESHOLD {
            self.repaint_mode = true;
        }
    }

    /// Consider capturing a snapshot at the end of a drain batch.
    ///
    /// `last_pty_activity` is the wall-clock timestamp of the most recent
    /// PTY byte received — used to gate the heuristic-fallback path on a
    /// short idle window.
    pub fn capture_if_boundary_reached(
        &mut self,
        screen: &vt100::Screen,
        last_pty_activity: Instant,
    ) {
        if !self.enabled {
            return;
        }
        // Never capture while a sync-update is mid-flight: the screen is
        // intentionally in a transitional state.
        if self.sync_update_open {
            return;
        }
        if !self.repaint_mode {
            // Reset pending signals so a one-off clear doesn't accumulate.
            self.pending_repaint_signals = 0;
            self.sync_just_closed = false;
            return;
        }

        let now = Instant::now();
        let idle_for = now.saturating_duration_since(last_pty_activity);

        // Capture preconditions, by priority:
        // 1. Sync update just closed → strong signal, capture now.
        // 2. Repaint signals fired in this batch AND the batch tail is idle
        //    long enough that the redraw is likely settled.
        // 3. Repaint signals fired and the screen visibly changed vs newest.
        let should_capture = if self.sync_just_closed {
            true
        } else if self.pending_repaint_signals > 0 {
            // Idle window is the cheap path. Even mid-burst, capture when
            // the latest screen differs materially — protects against
            // tools that never go idle (Codex's animated spinner).
            idle_for >= REPAINT_IDLE_WINDOW || self.screen_differs_from_newest(screen)
        } else {
            false
        };

        if !should_capture {
            return;
        }

        // Dedup against the last captured frame.
        let signature = screen_signature(screen);
        if let Some(prev_sig) = &self.last_signature {
            if *prev_sig == signature {
                // Same frame — clear per-batch flags so subsequent
                // boundaries are observable.
                self.pending_repaint_signals = 0;
                self.sync_just_closed = false;
                return;
            }
        }

        // Push each row of the captured frame as a plain-text line.
        // Trailing whitespace is trimmed so blank-padded rows don't
        // create visually noisy padding in the scrolled view. A blank
        // separator line between frames preserves frame boundaries
        // when scrolling back through multiple captures.
        //
        // Plain text only for now (no colour). Colour preservation is a
        // documented follow-up.
        let (_rows, cols) = screen.size();
        for row_text in screen.rows(0, cols) {
            let trimmed = row_text.trim_end();
            self.lines.push_back(trimmed.to_string());
        }
        self.lines.push_back(String::new());

        // FIFO-evict past capacity.
        while self.lines.len() > self.capacity {
            self.lines.pop_front();
        }

        self.last_signature = Some(signature);
        self.last_capture_at = Some(now);
        self.frames_pushed = self.frames_pushed.saturating_add(1);

        // Per-batch flags reset.
        self.pending_repaint_signals = 0;
        self.sync_just_closed = false;
    }

    fn screen_differs_from_newest(&self, screen: &vt100::Screen) -> bool {
        match &self.last_signature {
            None => true,
            Some(sig) => *sig != screen_signature(screen),
        }
    }

    /// Wipe the scrollback + state. Used when the surface is intentionally
    /// reset (e.g. the supervised process exits and a new one starts).
    pub fn clear(&mut self) {
        self.lines.clear();
        self.frames_pushed = 0;
        self.last_signature = None;
        self.last_capture_at = None;
        self.repaint_mode = false;
        self.sync_update_open = false;
        self.sync_just_closed = false;
        self.repaint_signal_score = 0;
        self.pending_repaint_signals = 0;
        self.scan_tail.clear();
    }

    /// Most-recent capture time, for diagnostics / tests.
    #[cfg(test)]
    pub fn last_capture_at(&self) -> Option<Instant> {
        self.last_capture_at
    }
}

/// Cheap, stable signature of a screen for dedupe. Includes the rendered
/// cells AND cursor position so a "cursor moved but cells unchanged" frame
/// (common in shells that blink the cursor) still dedupes correctly.
fn screen_signature(screen: &vt100::Screen) -> Vec<u8> {
    let mut sig = screen.contents_formatted();
    let (row, col) = screen.cursor_position();
    sig.push(0xff);
    sig.extend_from_slice(&row.to_le_bytes());
    sig.extend_from_slice(&col.to_le_bytes());
    sig.push(if screen.hide_cursor() { 1 } else { 0 });
    sig.push(if screen.alternate_screen() { 1 } else { 0 });
    // Title-bar updates (e.g. a TUI showing elapsed time in the OS title)
    // should count as a new frame even when the cell grid is identical.
    let title = screen.title();
    sig.push(0xfe);
    sig.extend_from_slice(title.as_bytes());
    sig
}

/// Scan a byte stream for frame-boundary signals. Returns observations
/// across the whole pass plus the index from which a partial trailing
/// escape sequence (if any) should be retained for the next call.
fn scan_for_boundaries(bytes: &[u8]) -> (ObservedBoundaries, usize) {
    let mut o = ObservedBoundaries::default();
    let mut i = 0;
    // `tail_start` tracks the earliest index that might be part of an
    // incomplete sequence. Initially set past the buffer (no tail needed).
    let mut tail_start = bytes.len();
    let n = bytes.len();

    while i < n {
        let b = bytes[i];
        if b != 0x1b {
            i += 1;
            continue;
        }
        // ESC. Need at least one more byte to know what kind of sequence.
        if i + 1 >= n {
            tail_start = tail_start.min(i);
            break;
        }
        let kind = bytes[i + 1];
        match kind {
            b'[' => {
                // CSI ... <final byte in 0x40..=0x7e>
                match scan_csi(bytes, i) {
                    Some((end, _intermediates, params, final_byte)) => {
                        classify_csi(&params, final_byte, &mut o);
                        i = end + 1;
                    }
                    None => {
                        tail_start = tail_start.min(i);
                        break;
                    }
                }
            }
            b'M' => {
                // ESC M — Reverse Index (RI). A repaint-shaped signal.
                o.repaint_signals = o.repaint_signals.saturating_add(1);
                i += 2;
            }
            b'P' | b'X' | b'^' | b'_' => {
                // DCS / SOS / PM / APC string — bounded by ESC \ (ST) or BEL.
                match scan_string_terminated(bytes, i + 2) {
                    Some(end) => {
                        i = end;
                    }
                    None => {
                        tail_start = tail_start.min(i);
                        break;
                    }
                }
            }
            b']' => {
                // OSC — terminated by BEL or ESC \.
                match scan_string_terminated(bytes, i + 2) {
                    Some(end) => {
                        i = end;
                    }
                    None => {
                        tail_start = tail_start.min(i);
                        break;
                    }
                }
            }
            _ => {
                // Other ESC X two-byte sequences — ignore.
                i += 2;
            }
        }
    }

    (o, tail_start)
}

/// Scan a CSI sequence starting at `start` (where `bytes[start] == 0x1b` and
/// `bytes[start + 1] == b'['`). Returns the index of the final byte plus
/// the parsed components on success. Returns None if the sequence is
/// incomplete (partial — tail-stash it).
fn scan_csi(bytes: &[u8], start: usize) -> Option<(usize, Vec<u8>, Vec<u8>, u8)> {
    let mut j = start + 2;
    let mut params: Vec<u8> = Vec::new();
    let mut intermediates: Vec<u8> = Vec::new();
    // Parameter bytes 0x30..=0x3f (digits, ?, ; etc.).
    while j < bytes.len() && (0x30..=0x3f).contains(&bytes[j]) {
        params.push(bytes[j]);
        j += 1;
    }
    // Intermediate bytes 0x20..=0x2f.
    while j < bytes.len() && (0x20..=0x2f).contains(&bytes[j]) {
        intermediates.push(bytes[j]);
        j += 1;
    }
    if j >= bytes.len() {
        return None;
    }
    let final_byte = bytes[j];
    if !(0x40..=0x7e).contains(&final_byte) {
        // Malformed — treat as resolved (skip past) to avoid hanging.
        return Some((j, intermediates, params, final_byte));
    }
    Some((j, intermediates, params, final_byte))
}

/// Skip a string-terminated escape (DCS / OSC / SOS / PM / APC) starting at
/// `start`. Returns index just past the terminator on success, or None if
/// truncated mid-string (caller should tail-stash from the ESC).
fn scan_string_terminated(bytes: &[u8], start: usize) -> Option<usize> {
    let mut j = start;
    while j < bytes.len() {
        match bytes[j] {
            0x07 => return Some(j + 1), // BEL
            0x1b if j + 1 < bytes.len() && bytes[j + 1] == b'\\' => return Some(j + 2), // ST
            0x1b => return None,        // ESC alone — wait for the \.
            _ => j += 1,
        }
    }
    None
}

fn classify_csi(params: &[u8], final_byte: u8, observed: &mut ObservedBoundaries) {
    // DEC private mode CSI ? <n> [;n2;...] h / l
    if params.first() == Some(&b'?') {
        if matches!(final_byte, b'h' | b'l') {
            let setting = final_byte == b'h';
            for part in params[1..].split(|c| *c == b';') {
                if part == b"2026" {
                    if setting {
                        observed.sync_opened = true;
                    } else {
                        observed.sync_closed = true;
                    }
                } else if matches!(part, b"1049" | b"1047" | b"47") {
                    if setting {
                        observed.alt_screen_entered = true;
                    } else {
                        observed.alt_screen_left = true;
                    }
                }
            }
        }
        return;
    }

    match final_byte {
        // Erase in Display — `CSI J`, `CSI 2 J`, `CSI 3 J`. All three are
        // strong fullscreen-repaint signals.
        b'J' => {
            observed.repaint_signals = observed.repaint_signals.saturating_add(2);
        }
        // Erase in Line — line redraw is a softer signal, but common in
        // repainting TUIs. Score it low.
        b'K' => {
            observed.repaint_signals = observed.repaint_signals.saturating_add(1);
        }
        // CUP / HVP — cursor absolute position. `CSI H` is the canonical
        // "go to top-left" before a redraw.
        b'H' | b'f' => {
            observed.repaint_signals = observed.repaint_signals.saturating_add(1);
        }
        // DECSTBM — set top/bottom scrolling region. Very strong full-frame
        // redraw signal (tmux, vim, codex all use this).
        b'r' => {
            observed.repaint_signals = observed.repaint_signals.saturating_add(2);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen_from(bytes: &[u8]) -> vt100::Screen {
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(bytes);
        p.screen().clone()
    }

    #[test]
    fn detects_sync_open_and_close() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.observe_bytes(b"\x1b[?2026h");
        assert!(sb.sync_update_open);
        assert!(!sb.sync_just_closed);
        sb.observe_bytes(b"\x1b[?2026l");
        assert!(!sb.sync_update_open);
        assert!(sb.sync_just_closed);
    }

    #[test]
    fn detects_sync_split_across_chunks() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.observe_bytes(b"\x1b[?20");
        assert!(!sb.sync_update_open);
        sb.observe_bytes(b"26h");
        assert!(sb.sync_update_open);
        sb.observe_bytes(b"\x1b[?20");
        sb.observe_bytes(b"26l");
        assert!(!sb.sync_update_open);
        assert!(sb.sync_just_closed);
    }

    #[test]
    fn detects_alt_screen_enter_leave() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.observe_bytes(b"\x1b[?1049h");
        assert!(sb.in_alt_screen);
        // Alt-screen alone is +2, below the 3-signal threshold. Repaint
        // mode requires at least one additional repaint signal.
        assert!(!sb.repaint_mode);
        sb.observe_bytes(b"\x1b[H");
        assert!(sb.repaint_mode);
        sb.observe_bytes(b"\x1b[?1049l");
        assert!(!sb.in_alt_screen);
    }

    #[test]
    fn repaint_signals_accumulate_into_mode() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        // A single CSI 2J is not enough on its own (score 2 < threshold 3).
        sb.observe_bytes(b"\x1b[2J");
        assert!(!sb.repaint_mode);
        // Adding CSI H pushes us over.
        sb.observe_bytes(b"\x1b[H");
        assert!(sb.repaint_mode);
    }

    #[test]
    fn decstbm_scrolling_region_is_repaint_signal() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.observe_bytes(b"\x1b[1;24r");
        // CSI r scores 2; +1 for the H absent. Below threshold (3).
        assert!(!sb.repaint_mode);
        sb.observe_bytes(b"\x1b[K");
        // +1 → 3, threshold met.
        assert!(sb.repaint_mode);
    }

    #[test]
    fn capture_on_sync_close_pushes_one_frame() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.resize_mirror(24, 80);
        sb.observe_bytes(b"\x1b[?2026h");
        // Enter repaint mode via a 2J first so capture_if_boundary fires.
        sb.observe_bytes(b"\x1b[2J\x1b[H");
        assert!(sb.repaint_mode);
        sb.observe_bytes(b"\x1b[?2026l");
        let s = screen_from(b"hello");
        sb.capture_if_boundary_reached(&s, Instant::now());
        assert_eq!(sb.frames_pushed(), 1);
        // Accumulated lines should contain the frame's text.
        let stored = sb.visible_window(usize::MAX, 0).join("\n");
        assert!(stored.contains("hello"));
    }

    #[test]
    fn capture_dedup_skips_unchanged_screen() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.resize_mirror(24, 80);
        sb.observe_bytes(b"\x1b[?2026h\x1b[2J\x1b[H");
        sb.observe_bytes(b"\x1b[?2026l");
        let s = screen_from(b"hello");
        sb.capture_if_boundary_reached(&s, Instant::now());
        assert_eq!(sb.frames_pushed(), 1);

        // Same screen, new sync close — should NOT push a second frame.
        sb.observe_bytes(b"\x1b[?2026h\x1b[?2026l");
        sb.capture_if_boundary_reached(&s, Instant::now());
        assert_eq!(sb.frames_pushed(), 1);
    }

    #[test]
    fn capture_many_frames_accumulates_lines() {
        // Distinct frames pushed into the line scrollback. All frame
        // markers should be reachable via visible_window across the
        // full accumulated history.
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.observe_bytes(b"\x1b[2J\x1b[H\x1b[1;24r");
        assert!(sb.repaint_mode);

        for i in 0..5u8 {
            let frame_bytes = format!("frame{i}");
            let s = screen_from(frame_bytes.as_bytes());
            sb.observe_bytes(b"\x1b[?2026h\x1b[?2026l");
            sb.capture_if_boundary_reached(&s, Instant::now());
        }
        assert_eq!(sb.frames_pushed(), 5);

        let all = sb.visible_window(usize::MAX, 0).join("\n");
        for i in 0..5u8 {
            assert!(
                all.contains(&format!("frame{i}")),
                "stored history missing frame{i}; got:\n{all}",
            );
        }
    }

    #[test]
    fn primary_screen_repaint_still_captures() {
        // Repaint signals without an alt-screen enter — should still capture.
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.resize_mirror(24, 80);
        sb.observe_bytes(b"\x1b[2J\x1b[H\x1b[1;24r");
        assert!(sb.repaint_mode);
        assert!(!sb.in_alt_screen);

        let s = screen_from(b"primary fullscreen content");
        // Use idle-window path: simulate idle by passing a time deep in the past.
        let stale = Instant::now()
            .checked_sub(Duration::from_millis(500))
            .unwrap_or_else(Instant::now);
        sb.capture_if_boundary_reached(&s, stale);
        assert_eq!(sb.frames_pushed(), 1);
        let stored = sb.visible_window(usize::MAX, 0).join("\n");
        assert!(stored.contains("primary fullscreen content"));
    }

    #[test]
    fn no_capture_outside_repaint_mode() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.resize_mirror(24, 80);
        // No repaint signals seen yet.
        let s = screen_from(b"line oriented output");
        sb.capture_if_boundary_reached(&s, Instant::now());
        assert_eq!(sb.frames_pushed(), 0);
    }

    #[test]
    fn no_capture_while_sync_open() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.resize_mirror(24, 80);
        sb.observe_bytes(b"\x1b[2J\x1b[H\x1b[1;24r");
        assert!(sb.repaint_mode);
        sb.observe_bytes(b"\x1b[?2026h");
        assert!(sb.sync_update_open);

        let s = screen_from(b"mid-batch");
        sb.capture_if_boundary_reached(&s, Instant::now());
        assert_eq!(
            sb.frames_pushed(),
            0,
            "must not capture while sync update open"
        );
    }

    #[test]
    fn visible_window_walks_history() {
        // Push a chain of distinct frames, then verify the windowing
        // API surfaces older frames as scroll_offset increases. Frame
        // text lands at the TOP of each frame's chunk of stored lines
        // (the frame's screen has the marker at row 0 and 23 blank
        // padding rows below), so we walk by frame size to reveal
        // successively older frames.
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.observe_bytes(b"\x1b[2J\x1b[H\x1b[1;24r");

        for i in 0..3u8 {
            let s = screen_from(format!("frame{i}").as_bytes());
            sb.observe_bytes(b"\x1b[?2026h\x1b[?2026l");
            sb.capture_if_boundary_reached(&s, Instant::now());
        }
        assert_eq!(sb.frames_pushed(), 3);

        // Scroll back to the top should reveal the OLDEST frame's marker
        // in the visible window (frame0 sits at the top of the stored
        // history).
        let max = sb.max_scroll_offset(24);
        let oldest = sb.visible_window(24, max).join("\n");
        assert!(
            oldest.contains("frame0"),
            "scrolled to top should reveal oldest frame; got:\n{oldest}",
        );

        // The history accumulates with the OLDEST frame at index 0 and
        // the NEWEST at the end. line_count is N rows per frame plus
        // separator lines between frames; total grows monotonically.
        let total = sb.line_count();
        assert!(
            total >= 3 * 24,
            "expected at least 3 frames' worth of lines, got {total}"
        );
    }

    #[test]
    fn osc_strings_are_skipped_cleanly() {
        // OSC title-set must not produce false repaint signals.
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.observe_bytes(b"\x1b]0;some title\x07");
        assert_eq!(sb.repaint_signal_score, 0);
        assert!(!sb.repaint_mode);
    }

    #[test]
    fn partial_csi_is_stashed_and_resolved() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.observe_bytes(b"\x1b[?1");
        sb.observe_bytes(b"049h");
        assert!(sb.in_alt_screen);
    }

    #[test]
    fn clear_resets_all_state() {
        let mut sb = FullscreenScrollback::with_default_capacity();
        sb.resize_mirror(24, 80);
        sb.observe_bytes(b"\x1b[?2026h\x1b[2J\x1b[H\x1b[1;24r\x1b[?2026l");
        let s = screen_from(b"content");
        sb.capture_if_boundary_reached(&s, Instant::now());
        assert!(!sb.is_empty());
        sb.clear();
        assert_eq!(sb.frames_pushed(), 0);
        assert!(!sb.repaint_mode);
        assert!(!sb.sync_update_open);
        assert_eq!(sb.line_count(), 0);
    }

    #[test]
    fn disabled_skips_capture() {
        let mut sb = FullscreenScrollback::new(false);
        assert!(!sb.is_enabled());
        sb.observe_bytes(b"\x1b[?2026h\x1b[2J\x1b[H\x1b[?2026l");
        let s = screen_from(b"x");
        sb.capture_if_boundary_reached(&s, Instant::now());
        assert_eq!(sb.frames_pushed(), 0);
    }
}
