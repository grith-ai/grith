// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Scroll-region tracking so top-anchored region scrolls reach scrollback.
//!
//! Background — agent CLIs that keep a fixed composer at the bottom of the
//! primary screen (Codex, and every Ink-based TUI using the same idiom) emit
//! transcript history with the "insert lines above the viewport" dance:
//!
//! ```text
//! CSI 1;N r      set the scrolling region to the TOP N rows
//! CSI 1;1 H      park the cursor inside it
//! \r\n <line>    one newline per history line — each one scrolls the region
//! …              up, evicting the row that was on line 1
//! CSI r          restore the full-screen region, redraw the viewport
//! ```
//!
//! Real terminals (xterm and everything that copies it) save a row that
//! scrolls off the top **whenever the region's top margin is line 1**, which
//! is exactly why the idiom works: the transcript lands in the host's
//! scrollback. `vt100` 0.15 does not implement that rule — it only feeds its
//! scrollback on a full-screen scroll, so every row a top-anchored region
//! scrolls away is destroyed. Under `grith exec codex` that is the entire
//! transcript: scrolling back showed only what the frame mirror could
//! reconstruct from repaints, which is both lossy and duplicated.
//!
//! This module re-implements the xterm rule on top of `vt100`. It parses the
//! PTY byte stream for DECSTBM and the operations that scroll a region, and
//! splits the stream so the caller can snapshot the rows about to be evicted
//! *before* handing the scrolling bytes to the parser.
//!
//! Only top-anchored regions are tracked. A region whose top margin is below
//! line 1 (a bottom-anchored viewport region, `CSI 11;30 r`) drops its rows on
//! a real terminal too, and alt-screen scrolls are never saved anywhere.
//!
//! Known gap: the scroll triggers recognised here are the explicit ones
//! (LF/VT/FF, IND, NEL, SU). A row pushed out by **autowrap** — a printable
//! landing past the right margin on the region's last row — is not split out
//! and is still lost. Tools using this idiom wrap their own output to the
//! terminal width, so it does not arise in practice; catching it would mean
//! tracking the cursor column and DECAWM alongside `vt100`.

use std::ops::Range;

/// One step of a PTY chunk, split at the operations that scroll the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    /// Ordinary bytes — feed them to the parser as-is.
    Bytes(Range<usize>),
    /// A run that *begins* with a scroll-triggering byte, so the caller can
    /// capture the rows it is about to evict before handing it over. Only the
    /// trigger's final byte starts the run — the parser is a streaming one, so
    /// any parameter bytes ahead of it stay in the preceding `Bytes` piece.
    Scroll {
        /// The trigger byte and everything up to the next cut.
        range: Range<usize>,
        /// How many rows leave the top of the region, assuming the trigger
        /// actually scrolls.
        lines: u16,
        /// True for line-feed-shaped triggers, which scroll only when the
        /// cursor already sits on the region's last row. The caller resolves
        /// this against the live parser's cursor.
        needs_cursor_at_bottom: bool,
        /// The region's last row (0-based) at the moment of the trigger.
        region_bottom: u16,
    },
}

/// A recorded scroll trigger: where it starts in the chunk, and how the
/// region stood when the scan reached it.
struct Cut {
    at: usize,
    lines: u16,
    needs_cursor_at_bottom: bool,
    region_bottom: u16,
}

/// Byte-stream state machine for DECSTBM plus the scroll operations.
///
/// The scanner is fed the same bytes as the live `vt100::Parser` and keeps
/// its own copy of the scrolling region, because `vt100` does not expose it.
/// Escape-sequence state persists across chunks, so a sequence split over a
/// PTY read boundary is still classified correctly.
pub struct ScrollRegionTracker {
    rows: u16,
    /// 0-based inclusive region bounds.
    top: u16,
    bottom: u16,
    alt_screen: bool,
    /// Set once a top-anchored partial region has been seen. From then on
    /// this tool is known to emit its transcript through the history-insert
    /// idiom, so we take ownership of every row that leaves the top of the
    /// screen — full-screen scrolls included. Otherwise a tool that mixes the
    /// two would end up with half its transcript here and half in `vt100`'s
    /// own scrollback, with no way to interleave them back into one record.
    owns_evictions: bool,
    state: ScanState,
    /// Parameter bytes of the CSI sequence currently being scanned.
    params: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanState {
    Ground,
    Esc,
    Csi,
    /// OSC / DCS / SOS / PM / APC string. `esc_seen` tracks a pending ST.
    StringSeq {
        esc_seen: bool,
    },
}

/// Longest CSI parameter run we bother to retain. Real DECSTBM/SU parameters
/// are a handful of bytes; a longer run is malformed and gets ignored anyway.
const MAX_PARAMS: usize = 32;

impl ScrollRegionTracker {
    pub fn new(rows: u16) -> Self {
        Self {
            rows: rows.max(1),
            top: 0,
            bottom: rows.max(1).saturating_sub(1),
            alt_screen: false,
            owns_evictions: false,
            state: ScanState::Ground,
            params: Vec::new(),
        }
    }

    /// Re-anchor to a new terminal height. DECSTBM is reset by a resize.
    pub fn resize(&mut self, rows: u16) {
        self.rows = rows.max(1);
        self.reset_region();
    }

    fn reset_region(&mut self) {
        self.top = 0;
        self.bottom = self.rows.saturating_sub(1);
    }

    /// True when a scroll here pushes a row off the top of the screen into
    /// what a real terminal would call scrollback: top margin on line 1, on
    /// the primary screen. Once `owns_evictions` is set that includes the
    /// full-screen case; until then a full-screen scroll is left to `vt100`,
    /// whose own scrollback handles it (and keeps its colours).
    fn evicts_to_scrollback(&self) -> bool {
        !self.alt_screen
            && self.top == 0
            && (self.owns_evictions || self.bottom < self.rows.saturating_sub(1))
    }

    /// Split `bytes` at every operation that can scroll rows out of a
    /// top-anchored region. Regions and alt-screen transitions are applied as
    /// the scan walks the chunk, so a trigger is classified against the region
    /// in force at that point in the stream.
    ///
    /// A `Scroll` piece *starts* with its trigger byte and runs to the next
    /// cut, so the caller makes one parser call per trigger rather than two —
    /// the trigger is the first byte processed, so the rows the caller
    /// snapshots beforehand are still exactly the ones it evicts.
    ///
    /// Chunks with no eligible trigger return a single `Bytes` piece, which
    /// is the overwhelmingly common case (and the whole cost of this scan for
    /// tools that never use the idiom).
    pub fn split(&mut self, bytes: &[u8]) -> Vec<Piece> {
        let mut cuts: Vec<Cut> = Vec::new();
        let mut i = 0usize;

        while i < bytes.len() {
            let b = bytes[i];
            match self.state {
                ScanState::Ground => {
                    match b {
                        0x1b => {
                            self.state = ScanState::Esc;
                            i += 1;
                        }
                        // LF / VT / FF all index the cursor down one row.
                        0x0a..=0x0c => {
                            self.record_cut(&mut cuts, i, 1, true);
                            i += 1;
                        }
                        _ => i += 1,
                    }
                }
                ScanState::Esc => {
                    match b {
                        b'[' => {
                            self.state = ScanState::Csi;
                            self.params.clear();
                            i += 1;
                        }
                        // IND / NEL — index down, scrolling at the region end.
                        b'D' | b'E' => {
                            self.state = ScanState::Ground;
                            i += 1;
                            self.record_cut(&mut cuts, i - 1, 1, true);
                        }
                        // RIS — full reset, region goes back to the whole screen.
                        b'c' => {
                            self.reset_region();
                            self.alt_screen = false;
                            self.state = ScanState::Ground;
                            i += 1;
                        }
                        b']' | b'P' | b'X' | b'^' | b'_' => {
                            self.state = ScanState::StringSeq { esc_seen: false };
                            i += 1;
                        }
                        // ESC M (RI) scrolls DOWN — rows leave the bottom,
                        // which no terminal saves. Everything else here is a
                        // two-byte sequence we don't care about.
                        _ => {
                            self.state = ScanState::Ground;
                            i += 1;
                        }
                    }
                }
                ScanState::Csi => {
                    if (0x30..=0x3f).contains(&b) {
                        if self.params.len() < MAX_PARAMS {
                            self.params.push(b);
                        }
                        i += 1;
                    } else if (0x20..=0x2f).contains(&b) {
                        // Intermediate bytes — a sequence with them is never
                        // one of ours, but it still has to be consumed.
                        self.params.push(0xff);
                        i += 1;
                    } else {
                        let final_byte = b;
                        self.state = ScanState::Ground;
                        i += 1;
                        let params = std::mem::take(&mut self.params);
                        if params.contains(&0xff) {
                            continue;
                        }
                        match final_byte {
                            b'r' => self.apply_decstbm(&params),
                            b'S' => {
                                let n = first_param(&params).unwrap_or(1).max(1);
                                self.record_cut(&mut cuts, i - 1, n, false);
                            }
                            b'h' | b'l' => self.apply_private_mode(&params, final_byte == b'h'),
                            _ => {}
                        }
                    }
                }
                ScanState::StringSeq { esc_seen } => {
                    match b {
                        0x07 => self.state = ScanState::Ground,
                        0x1b => self.state = ScanState::StringSeq { esc_seen: true },
                        b'\\' if esc_seen => self.state = ScanState::Ground,
                        _ => self.state = ScanState::StringSeq { esc_seen: false },
                    }
                    i += 1;
                }
            }
        }

        if cuts.is_empty() {
            return vec![Piece::Bytes(0..bytes.len())];
        }

        let mut pieces: Vec<Piece> = Vec::with_capacity(cuts.len() * 2);
        let mut pos = 0usize;
        for (idx, cut) in cuts.iter().enumerate() {
            if cut.at > pos {
                pieces.push(Piece::Bytes(pos..cut.at));
            }
            let end = cuts.get(idx + 1).map_or(bytes.len(), |next| next.at);
            pieces.push(Piece::Scroll {
                range: cut.at..end,
                lines: cut.lines,
                needs_cursor_at_bottom: cut.needs_cursor_at_bottom,
                region_bottom: cut.region_bottom,
            });
            pos = end;
        }
        if pos < bytes.len() {
            pieces.push(Piece::Bytes(pos..bytes.len()));
        }
        pieces
    }

    /// Record a scroll trigger at `at`. Triggers outside an eviction-eligible
    /// region are ignored — the caller has nothing to capture and the parser
    /// handles them itself.
    fn record_cut(&self, cuts: &mut Vec<Cut>, at: usize, lines: u16, needs_cursor_at_bottom: bool) {
        if !self.evicts_to_scrollback() {
            return;
        }
        cuts.push(Cut {
            at,
            lines: lines.min(self.bottom.saturating_sub(self.top) + 1),
            needs_cursor_at_bottom,
            region_bottom: self.bottom,
        });
    }

    fn apply_decstbm(&mut self, params: &[u8]) {
        let text = String::from_utf8_lossy(params);
        if text.starts_with('?') {
            // DEC private "restore mode" — not DECSTBM.
            return;
        }
        let mut parts = text.split(';');
        let top = parts
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(0);
        let bottom = parts
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(0);
        if top == 0 && bottom == 0 {
            self.reset_region();
            return;
        }
        // DECSTBM parameters are 1-based and inclusive; a degenerate region
        // (top >= bottom, or bounds past the screen) is ignored by a real
        // terminal, leaving the previous region in force.
        let top0 = top.saturating_sub(1);
        let bottom0 = bottom.saturating_sub(1).min(self.rows.saturating_sub(1));
        if top0 >= bottom0 {
            return;
        }
        self.top = top0;
        self.bottom = bottom0;
        if !self.alt_screen && top0 == 0 && bottom0 < self.rows.saturating_sub(1) {
            self.owns_evictions = true;
        }
    }

    fn apply_private_mode(&mut self, params: &[u8], set: bool) {
        let text = String::from_utf8_lossy(params);
        let Some(rest) = text.strip_prefix('?') else {
            return;
        };
        for part in rest.split(';') {
            if matches!(part, "47" | "1047" | "1049") {
                self.alt_screen = set;
                // Both screens start with a full-screen region.
                self.reset_region();
            }
        }
    }
}

fn first_param(params: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(params);
    text.split(';').next()?.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(tracker: &mut ScrollRegionTracker, bytes: &[u8]) -> Vec<Piece> {
        tracker.split(bytes)
    }

    #[test]
    fn plain_output_is_one_piece() {
        let mut t = ScrollRegionTracker::new(24);
        assert_eq!(
            split(&mut t, b"hello\r\nworld\r\n"),
            vec![Piece::Bytes(0..14)]
        );
    }

    #[test]
    fn full_screen_region_is_left_to_vt100() {
        let mut t = ScrollRegionTracker::new(24);
        // CSI 1;24r is the whole screen — vt100's own scrollback path.
        let pieces = split(&mut t, b"\x1b[1;24r\r\n\r\n");
        assert_eq!(pieces.len(), 1);
        assert!(matches!(pieces[0], Piece::Bytes(_)));
    }

    #[test]
    fn bottom_anchored_region_is_not_eligible() {
        let mut t = ScrollRegionTracker::new(24);
        let pieces = split(&mut t, b"\x1b[11;24r\r\n\r\n");
        assert_eq!(pieces.len(), 1);
    }

    #[test]
    fn top_anchored_partial_region_isolates_line_feeds() {
        let mut t = ScrollRegionTracker::new(24);
        let pieces = split(&mut t, b"\x1b[1;4r\x1b[1;1Habc\ndef\n");
        let scrolls: Vec<&Piece> = pieces
            .iter()
            .filter(|p| matches!(p, Piece::Scroll { .. }))
            .collect();
        assert_eq!(scrolls.len(), 2);
        for piece in scrolls {
            let Piece::Scroll {
                lines,
                needs_cursor_at_bottom,
                region_bottom,
                ..
            } = piece
            else {
                unreachable!()
            };
            assert_eq!(*lines, 1);
            assert!(*needs_cursor_at_bottom);
            assert_eq!(*region_bottom, 3);
        }
        // Pieces must reconstruct the input exactly, in order.
        let mut covered = 0usize;
        for piece in &pieces {
            let range = match piece {
                Piece::Bytes(r) => r.clone(),
                Piece::Scroll { range, .. } => range.clone(),
            };
            assert_eq!(range.start, covered);
            covered = range.end;
        }
        assert_eq!(covered, b"\x1b[1;4r\x1b[1;1Habc\ndef\n".len());
    }

    #[test]
    fn scroll_up_carries_its_line_count() {
        let mut t = ScrollRegionTracker::new(24);
        let pieces = split(&mut t, b"\x1b[1;6r\x1b[3S");
        let scroll = pieces
            .iter()
            .find(|p| matches!(p, Piece::Scroll { .. }))
            .expect("SU is a scroll trigger");
        let Piece::Scroll {
            lines,
            needs_cursor_at_bottom,
            range,
            ..
        } = scroll
        else {
            unreachable!()
        };
        assert_eq!(*lines, 3);
        assert!(!needs_cursor_at_bottom);
        assert_eq!(&b"\x1b[1;6r\x1b[3S"[range.clone()], b"S");
        assert_eq!(range.end, b"\x1b[1;6r\x1b[3S".len());
    }

    #[test]
    fn scroll_up_is_capped_at_the_region_height() {
        let mut t = ScrollRegionTracker::new(24);
        let pieces = split(&mut t, b"\x1b[1;4r\x1b[99S");
        let Some(Piece::Scroll { lines, .. }) = pieces
            .iter()
            .find(|p| matches!(p, Piece::Scroll { .. }))
            .cloned()
        else {
            panic!("expected a scroll piece")
        };
        assert_eq!(lines, 4);
    }

    #[test]
    fn full_screen_scrolls_are_owned_once_the_idiom_is_seen() {
        let mut t = ScrollRegionTracker::new(24);
        // Before the idiom appears, a full-screen scroll belongs to vt100.
        assert_eq!(split(&mut t, b"\n\n").len(), 1);
        split(&mut t, b"\x1b[1;4r\x1b[r");
        // Afterwards the whole transcript has to come from one store, so we
        // take the full-screen scrolls too.
        assert_eq!(
            split(&mut t, b"\n\n")
                .iter()
                .filter(|p| matches!(p, Piece::Scroll { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn csi_r_restores_the_full_screen_region() {
        let mut t = ScrollRegionTracker::new(24);
        split(&mut t, b"\x1b[1;4r");
        assert_eq!(t.bottom, 3);
        split(&mut t, b"\x1b[r");
        assert_eq!(t.bottom, 23);
    }

    #[test]
    fn alt_screen_suspends_eviction() {
        let mut t = ScrollRegionTracker::new(24);
        split(&mut t, b"\x1b[?1049h\x1b[1;4r");
        assert!(!t.evicts_to_scrollback());
        assert!(!t.owns_evictions, "alt-screen scrolls are never scrollback");
        let pieces = split(&mut t, b"\n\n");
        assert_eq!(pieces.len(), 1);
        split(&mut t, b"\x1b[?1049l\x1b[1;4r");
        assert!(t.evicts_to_scrollback());
    }

    #[test]
    fn index_and_next_line_scroll_too() {
        let mut t = ScrollRegionTracker::new(24);
        let pieces = split(&mut t, b"\x1b[1;4r\x1bD\x1bE");
        assert_eq!(
            pieces
                .iter()
                .filter(|p| matches!(p, Piece::Scroll { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn reverse_index_is_not_an_eviction() {
        let mut t = ScrollRegionTracker::new(24);
        let pieces = split(&mut t, b"\x1b[1;4r\x1bM\x1bM");
        assert_eq!(pieces.len(), 1);
    }

    #[test]
    fn sequences_split_across_chunks_still_classify() {
        let mut t = ScrollRegionTracker::new(24);
        split(&mut t, b"\x1b[1;");
        split(&mut t, b"4r");
        assert!(t.evicts_to_scrollback());
        let pieces = split(&mut t, b"\n");
        assert_eq!(
            pieces
                .iter()
                .filter(|p| matches!(p, Piece::Scroll { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn newline_inside_an_osc_string_is_not_a_trigger() {
        let mut t = ScrollRegionTracker::new(24);
        let pieces = split(&mut t, b"\x1b[1;4r\x1b]0;ti\ntle\x07");
        assert_eq!(pieces.len(), 1);
    }

    #[test]
    fn resize_resets_the_region() {
        let mut t = ScrollRegionTracker::new(24);
        split(&mut t, b"\x1b[1;4r");
        assert_eq!(t.bottom, 3);
        t.resize(40);
        assert_eq!(t.bottom, 39);
    }

    #[test]
    fn degenerate_region_is_ignored() {
        let mut t = ScrollRegionTracker::new(24);
        split(&mut t, b"\x1b[1;4r");
        // top >= bottom is rejected by a real terminal; the previous region
        // must stay in force rather than silently becoming full-screen.
        split(&mut t, b"\x1b[5;5r");
        assert!(t.evicts_to_scrollback());
        assert_eq!(t.bottom, 3);
    }
}
