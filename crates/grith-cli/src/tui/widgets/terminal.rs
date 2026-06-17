// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Virtual terminal widget — renders a `vt100::Screen` into a ratatui frame.
//!
//! Used by the exec TUI to display the supervised tool's PTY output with full
//! color and cursor support inside grith's own TUI chrome.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::Frame;

/// Compute the first vterm row to display in the viewport for a given screen
/// and visible row count.
///
/// Uses `max(cursor_follow, bottom_follow)`:
///
/// - `bottom_follow`: always show the bottom `visible_rows` of the vterm. This is
///   what a real terminal emulator does. TUI tools like Claude/Ink render their
///   interactive UI near the bottom of the terminal; showing the bottom keeps their
///   content visible regardless of where they park the vt100 cursor.
///
/// - `cursor_follow`: scroll just enough to keep the cursor visible. This handles
///   editors (vim, nano) where the cursor is mid-content and bottom-follow alone
///   would hide the active line.
///
/// Taking the maximum satisfies both: the bottom is always visible, AND the cursor
/// is always visible (scrolls further down only when the cursor exceeds the
/// bottom-follow position).
///
/// Never uses content-scanning heuristics. Scanning for the first non-blank row
/// is unstable: TUI redraws have transient frames with different non-blank rows,
/// causing 1-row jitter. Content-scanning also moves content from bottom to top
/// (the opposite of correct) when the panel equals the vterm height.
pub fn compute_viewport_top(screen: &vt100::Screen, visible_rows: u16) -> u16 {
    let (screen_rows, _) = screen.size();
    let (cursor_row, _) = screen.cursor_position();
    let cursor_follow = (cursor_row + 1).saturating_sub(visible_rows);
    let bottom_follow = screen_rows.saturating_sub(visible_rows);
    cursor_follow.max(bottom_follow)
}

/// Render a vt100 screen buffer into the given area of a ratatui frame.
///
/// Maps vt100 cell attributes (fg/bg color, bold, italic, underline, inverse)
/// to ratatui styles cell-by-cell. When `show_cursor` is true, the real
/// terminal cursor is positioned at the vt100 cursor location.
pub fn render_vterm(
    frame: &mut Frame,
    area: Rect,
    screen: &vt100::Screen,
    show_cursor: bool,
    follow_cursor: bool,
) {
    let buf = frame.buffer_mut();
    let (screen_rows, screen_cols) = screen.size();
    let rows = area.height.min(screen_rows);
    let screen_row_start = if follow_cursor {
        compute_viewport_top(screen, rows)
    } else {
        screen_rows.saturating_sub(rows)
    };
    let area_row_start = area.height.saturating_sub(rows);

    for row in 0..rows {
        for col in 0..area.width.min(screen_cols) {
            let screen_row = screen_row_start + row;
            let cell = screen.cell(screen_row, col);
            let Some(cell) = cell else { continue };

            let contents = cell.contents();
            let ch = if contents.is_empty() {
                ' '
            } else {
                // Take first char; wide chars handled by vt100 internally
                contents.chars().next().unwrap_or(' ')
            };

            let mut style = Style::default();

            let (fg, bg) = if cell.inverse() {
                (convert_color(cell.bgcolor()), convert_color(cell.fgcolor()))
            } else {
                (convert_color(cell.fgcolor()), convert_color(cell.bgcolor()))
            };
            style = style.fg(fg).bg(bg);

            let mut modifiers = Modifier::empty();
            if cell.bold() {
                modifiers |= Modifier::BOLD;
            }
            if cell.italic() {
                modifiers |= Modifier::ITALIC;
            }
            if cell.underline() {
                modifiers |= Modifier::UNDERLINED;
            }
            // vt100 0.15 does not expose dim() on Cell
            style = style.add_modifier(modifiers);

            let buf_x = area.x + col;
            let buf_y = area.y + area_row_start + row;
            if buf_x < buf.area().right() && buf_y < buf.area().bottom() {
                let buf_cell = &mut buf[(buf_x, buf_y)];
                buf_cell.set_char(ch);
                buf_cell.set_style(style);
            }
        }
    }

    // Position the real terminal cursor at the vt100 cursor location.
    // We deliberately ignore `screen.hide_cursor()` (CSI ?25l): Ink-based
    // tools (Claude Code) hide the OS cursor and rely on an inverse-video
    // cell as a fake cursor, which can be invisible when the underlying
    // cell is a space with default fg/bg. Always positioning the real
    // cursor at the vt100 location keeps something visible for the user.
    if show_cursor {
        let (cursor_row, cursor_col) = screen.cursor_position();
        if cursor_row < screen_row_start {
            return;
        }
        let cx = area.x + cursor_col;
        let cy = area.y + area_row_start + (cursor_row - screen_row_start);
        if cx < area.right() && cy < area.bottom() {
            frame.set_cursor_position(ratatui::layout::Position { x: cx, y: cy });
        }
    }
}

/// Convert a vt100 color to a ratatui color.
pub(crate) fn convert_color(color: vt100::Color) -> Color {
    match color {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Idx(idx) => Color::Indexed(idx),
        vt100::Color::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn render_simple_text() {
        let backend = TestBackend::new(40, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut parser = vt100::Parser::new(10, 40, 0);
        parser.process(b"Hello, world!");
        terminal
            .draw(|frame| {
                render_vterm(frame, frame.area(), parser.screen(), true, true);
            })
            .unwrap();
    }

    #[test]
    fn render_colored_text() {
        let backend = TestBackend::new(40, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut parser = vt100::Parser::new(10, 40, 0);
        parser.process(b"\x1b[31mRed\x1b[0m Normal");
        terminal
            .draw(|frame| {
                render_vterm(frame, frame.area(), parser.screen(), false, true);
            })
            .unwrap();
    }

    #[test]
    fn convert_color_variants() {
        assert_eq!(convert_color(vt100::Color::Default), Color::Reset);
        assert_eq!(convert_color(vt100::Color::Idx(1)), Color::Indexed(1));
        assert_eq!(
            convert_color(vt100::Color::Rgb(0xff, 0x00, 0x80)),
            Color::Rgb(0xff, 0x00, 0x80)
        );
    }
}
