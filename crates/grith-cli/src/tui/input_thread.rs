// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Dedicated OS thread that reads keyboard / mouse / resize events from
//! stdin and forwards them on a crossbeam channel. Moves crossterm's
//! blocking `event::read()` off the TUI main loop so the loop's biased
//! `select!` wakes on either supervisor events or keystrokes — instead
//! of polling stdin only after the supervisor channel has been drained.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::Sender;
use crossterm::event::{self, Event, KeyEventKind};

/// Short timeout for `event::poll` — keeps the thread responsive to
/// shutdown without busy-spinning when stdin is idle.
const POLL_TIMEOUT: Duration = Duration::from_millis(50);

/// Spawn the input reader thread. Returns its `JoinHandle`. The thread
/// exits when:
///   - `shutdown` is set to `true` and the next poll cycle observes it, OR
///   - the receiver end of `tx` is dropped (send returns `Err`).
pub fn spawn(tx: Sender<Event>, shutdown: Arc<AtomicBool>) -> JoinHandle<()> {
    thread::Builder::new()
        .name("grith-tui-input".into())
        .spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                match event::poll(POLL_TIMEOUT) {
                    Ok(true) => match event::read() {
                        // Drop key release/repeat events. The keyboard
                        // enhancement flags requested by the exec TUI can make
                        // some terminals report them, and forwarding them would
                        // double every keystroke sent to the PTY. Non-key
                        // events (mouse, resize, paste) always pass through.
                        Ok(Event::Key(k)) if k.kind != KeyEventKind::Press => {}
                        Ok(ev) => {
                            if tx.send(ev).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                    Ok(false) => {}
                    Err(_) => break,
                }
            }
        })
        .expect("spawn grith-tui-input thread")
}
