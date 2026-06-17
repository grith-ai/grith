// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Colour palette for the grith TUI. Uses `Color::Rgb` throughout.

use ratatui::style::Color;

pub const BG: Color = Color::Rgb(0x0d, 0x11, 0x17);
// Chrome panels (titlebar, subheader, log, statusbar). Significantly lighter
// than `BG` so the top/bottom chrome reads as clearly separate from the
// central terminal pane. Targets ~2.5× perceived-luminance ratio against BG
// — equivalent to GitHub's `canvas.overlay` / modern dark-UI "surface 2".
pub const BG_PANEL: Color = Color::Rgb(0x2d, 0x33, 0x3b);
pub const BORDER: Color = Color::Rgb(0x30, 0x36, 0x3d);
pub const TEXT: Color = Color::Rgb(0xc9, 0xd1, 0xd9);
pub const TEXT_DIM: Color = Color::Rgb(0x48, 0x4f, 0x58);
pub const TEXT_MID: Color = Color::Rgb(0x8b, 0x94, 0x9e);
pub const GREEN: Color = Color::Rgb(0x3f, 0xb9, 0x50);
pub const GREEN_HI: Color = Color::Rgb(0x56, 0xd3, 0x64);
pub const RED: Color = Color::Rgb(0xf8, 0x51, 0x49);
pub const AMBER: Color = Color::Rgb(0xd2, 0x99, 0x22);
pub const AMBER_HI: Color = Color::Rgb(0xe3, 0xb3, 0x41);
pub const WHITE: Color = Color::Rgb(0xf0, 0xf6, 0xfc);
pub const BLUE: Color = Color::Rgb(0x58, 0xa6, 0xff);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_colors_are_rgb() {
        let colors = [
            BG, BG_PANEL, BORDER, TEXT, TEXT_DIM, TEXT_MID, GREEN, GREEN_HI, RED, AMBER, AMBER_HI,
            WHITE, BLUE,
        ];
        for c in &colors {
            assert!(matches!(c, Color::Rgb(_, _, _)));
        }
    }
}
