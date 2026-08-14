// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Diagnostic harness: runs the real exec TUI against a fake child and
//! logs every byte chunk the TUI forwards to the child PTY. Drive it from
//! a scripted PTY (so crossterm sees a controlling terminal), feed it key
//! byte sequences, and compare what comes out the other side.
//!
//! Usage: tui_keyprobe <keylog-path>
//! Send Ctrl+R (0x12) to make the fake child enable ?1004 focus reporting.
//! Send Ctrl+Q (0x11) to make the probe exit.

use std::io::Write;
use std::sync::mpsc;

use grith_cli::tui::exec_tui::{run_exec_tui, ExecEvent, ExecState, PtyInput};

fn main() -> anyhow::Result<()> {
    let log_path = std::env::args()
        .nth(1)
        .expect("usage: tui_keyprobe <keylog-path>");

    let (event_tx, event_rx) = crossbeam_channel::unbounded();
    let (_perm_tx, perm_rx) = crossbeam_channel::unbounded();
    let (pty_tx, pty_rx) = mpsc::channel::<PtyInput>();

    // Fake child: log every forwarded chunk as a hex line. Ctrl+R (0x12)
    // makes the child "enable" ?1004 focus reporting; Ctrl+Q (0x11) acts
    // as the quit sentinel, ending the TUI via ProcessExited.
    let exit_tx = event_tx.clone();
    std::thread::spawn(move || {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("open keylog");
        while let Ok(input) = pty_rx.recv() {
            match input {
                PtyInput::Bytes(b) => {
                    let hex: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
                    writeln!(f, "BYTES {}", hex.join(" ")).ok();
                    f.flush().ok();
                    if b.contains(&0x12) {
                        let _ = exit_tx.send(ExecEvent::PtyOutput(b"\x1b[?1004h".to_vec()));
                    }
                    if b.contains(&0x11) {
                        let _ = exit_tx.send(ExecEvent::ProcessExited);
                    }
                }
                PtyInput::Resize { cols, rows } => {
                    writeln!(f, "RESIZE {cols}x{rows}").ok();
                    f.flush().ok();
                }
            }
        }
    });

    event_tx.send(ExecEvent::PtyOutput(b"keyprobe ready\r\n".to_vec()))?;

    let state = ExecState::new(
        "keyprobe".into(),
        "probe".into(),
        std::process::id(),
        30,
        100,
        0,
    );
    run_exec_tui(state, event_rx, perm_rx, pty_tx)
}
