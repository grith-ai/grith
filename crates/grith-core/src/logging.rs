// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Tracing subscriber initialization for the grith daemon.
//!
//! Two output layers are wired in parallel:
//!
//! * **stderr** — the conventional layer; affected by `suppress()` /
//!   `restore()` so the supervisor doesn't write tracing noise over an
//!   interactive TUI session.
//!
//! * **persistent file** — `~/.local/share/grith/supervisor.log`, opened
//!   with `O_APPEND` at init and wrapped in a `Mutex<File>`. **This
//!   layer is NOT affected by `suppress()` or by the TUI's `dup2`
//!   redirect of `stderr` to `tui.log`** — it holds its own file
//!   descriptor and writes directly to it. Critical for diagnostics
//!   like the wedge watchdog: when the TUI is active, the only place
//!   the warn lines reach is this file.

use std::fs::OpenOptions;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use tracing_subscriber::{fmt, prelude::*, reload, EnvFilter};

type FilterHandle = reload::Handle<EnvFilter, tracing_subscriber::Registry>;

static STDERR_FILTER_HANDLE: OnceLock<FilterHandle> = OnceLock::new();

/// Tracing `MakeWriter` that hands out per-write `Mutex` guards on a
/// shared `std::fs::File`. Used for the persistent supervisor log so
/// the writes survive any `dup2` of stderr by the TUI.
#[derive(Clone)]
struct SharedFileWriter {
    file: Arc<Mutex<std::fs::File>>,
}

impl SharedFileWriter {
    fn new(path: &std::path::Path) -> io::Result<Self> {
        let file = OpenOptions::new().append(true).create(true).open(path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }
}

/// `io::Write` guard returned by `make_writer`. Acquires the inner
/// mutex for the duration of the write, then releases it. Brief
/// contention (microseconds) is fine for tracing volumes.
struct SharedFileWriteGuard {
    file: Arc<Mutex<std::fs::File>>,
}

impl io::Write for SharedFileWriteGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("supervisor log mutex poisoned"))?
            .write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("supervisor log mutex poisoned"))?
            .flush()
    }
}

impl<'a> fmt::MakeWriter<'a> for SharedFileWriter {
    type Writer = SharedFileWriteGuard;
    fn make_writer(&'a self) -> Self::Writer {
        SharedFileWriteGuard {
            file: self.file.clone(),
        }
    }
}

/// Resolve the supervisor log path. Lives under the XDG state-style
/// directory `~/.local/share/grith/` (same prefix as audit.db) so
/// operators looking for grith-related logs find it quickly.
fn supervisor_log_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let dir = home.join(".local").join("share").join("grith");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("supervisor.log"))
}

/// Initialize the tracing subscriber for structured logging.
///
/// Reads log level from the config, with `GRITH_LOG_LEVEL` env var as override.
/// The stderr filter can be changed at runtime via [`suppress()`] and
/// [`restore()`]; the persistent-file filter is fixed at WARN-and-above
/// regardless so the wedge watchdog and similar diagnostics always
/// have a log trail.
pub fn init(log_level: &str) {
    let env_filter =
        EnvFilter::try_from_env("GRITH_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new(log_level));

    // Reloadable filter is attached PER-LAYER to the stderr fmt layer,
    // NOT at the registry root. If it were at the root, `suppress()`
    // would also silence the persistent file layer — defeating the
    // point of having a separate persistent log.
    let (stderr_filter, reload_handle) = reload::Layer::new(env_filter);

    let stderr_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_filter(stderr_filter);

    // Best-effort persistent file layer. If we can't open the log file
    // (read-only home, disk full, …) we proceed without it rather than
    // failing daemon startup — tracing-to-stderr still works.
    let file_layer = supervisor_log_path()
        .and_then(|p| SharedFileWriter::new(&p).ok())
        .map(|writer| {
            fmt::layer()
                .with_writer(writer)
                .with_target(true)
                .with_thread_ids(true)
                .with_file(false)
                .with_line_number(false)
                // Capture WARN and above unconditionally — diagnostics
                // (wedge watchdog, audit-sink overflow, classify
                // failures) all log at this level and need to land
                // here regardless of stderr suppression.
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN)
        });

    let registry = tracing_subscriber::registry().with(stderr_layer);
    if let Some(file_layer) = file_layer {
        registry.with(file_layer).init();
    } else {
        registry.init();
    }

    let _ = STDERR_FILTER_HANDLE.set(reload_handle);
}

/// Suppress stderr tracing output (sets stderr filter to "off"). Used
/// by `grith exec` to keep the terminal clean during supervised
/// sessions. **Does NOT silence the persistent supervisor log** —
/// WARN+ lines still land in `~/.local/share/grith/supervisor.log`.
pub fn suppress() {
    if let Some(handle) = STDERR_FILTER_HANDLE.get() {
        let _ = handle.modify(|filter| *filter = EnvFilter::new("off"));
    }
}

/// Restore tracing output to the default level.
pub fn restore(log_level: &str) {
    if let Some(handle) = STDERR_FILTER_HANDLE.get() {
        let _ = handle.modify(|filter| {
            *filter = EnvFilter::try_from_env("GRITH_LOG_LEVEL")
                .unwrap_or_else(|_| EnvFilter::new(log_level));
        });
    }
}
