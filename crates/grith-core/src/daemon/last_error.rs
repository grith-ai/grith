// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Startup-failure handoff from the detached daemon child to its spawner.
//!
//! The background daemon is spawned with stdout and stderr on `/dev/null`, so
//! when it dies during startup — most often "another process still owns the
//! audit database after 10s, held by pid N" — the one message that names the
//! cause is discarded, and the parent can only report "did not become ready".
//! An operator then has no path from the symptom to the wedged process.
//!
//! This module is that path: the failing child records its error here, and
//! the parent prints it when its readiness wait expires. The file is removed
//! by the parent immediately before each spawn, so anything present after a
//! failed wait was written by the child of THIS attempt, never a stale one.

use std::path::PathBuf;

fn path() -> PathBuf {
    super::pid::runtime_dir().join("daemon.last-error")
}

/// Record the child's fatal startup error. Best-effort: a failure to record
/// must never mask the error being recorded.
pub fn record(message: &str) {
    let dir = super::pid::runtime_dir();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(path(), message);
}

/// Remove any recorded error. Called by the spawner before starting a child
/// so a later read cannot report a previous attempt's failure.
pub fn clear() {
    let _ = std::fs::remove_file(path());
}

/// Read and consume the recorded error, if any.
pub fn take() -> Option<String> {
    let message = std::fs::read_to_string(path()).ok()?;
    clear();
    let trimmed = message.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    // The public fns resolve `runtime_dir()` from HOME at call time, and
    // tests run in parallel in one process, so they are exercised against an
    // explicit path instead of by mutating the environment.
    use std::path::Path;

    fn record_at(path: &Path, message: &str) {
        std::fs::write(path, message).unwrap();
    }

    fn take_at(path: &Path) -> Option<String> {
        let message = std::fs::read_to_string(path).ok()?;
        let _ = std::fs::remove_file(path);
        let trimmed = message.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }

    #[test]
    fn take_consumes_and_empty_reads_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.last-error");

        record_at(&path, "audit database held by pid 42\n");
        assert_eq!(
            take_at(&path).as_deref(),
            Some("audit database held by pid 42")
        );
        assert_eq!(take_at(&path), None, "take must consume");

        record_at(&path, "   \n");
        assert_eq!(take_at(&path), None, "whitespace-only reads as absent");
    }
}
