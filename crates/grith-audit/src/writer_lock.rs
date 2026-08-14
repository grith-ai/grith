// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Exclusive audit-writer lock (work/74 Phase 4, go-live review B12 item 3).
//!
//! Every command that was not a thin client constructed its own `Daemon` and
//! opened the live audit database read-write — `grith run`, `audit`, `digest`,
//! `canary`, `proxy`, `log`, `notifications`, `pro sync`, and the bare REPL.
//! Each of those also ran startup backfill, chain verification (which writes
//! checkpoints and archive boundaries) and its own retention thread.
//!
//! Concurrent writers are what forked the chain: two connections read the same
//! `chain_head`, derived the same predecessor and sequence, and both inserted.
//! Transactional sequence allocation closes the race for inserts, but it does
//! not make two processes pruning, archiving and checkpointing the same
//! database at once a good idea.
//!
//! So exactly one process — the daemon — holds an exclusive `flock` on
//! `<audit_dir>/writer.lock` and is the only one permitted to write, verify
//! with writes, or run retention. Everyone else opens read-only and says so.
//!
//! `flock` rather than a lock *file*: the kernel releases it when the holder
//! dies, however it dies. A PID-file-style lock leaks on SIGKILL and needs
//! stale-detection heuristics, which is the class of bug this is meant to end.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// An acquired exclusive writer lock.
///
/// Held for the lifetime of the owning process. Dropping it (or the process
/// exiting for any reason) releases the lock.
#[derive(Debug)]
pub struct AuditWriterLock {
    /// Kept open because the lock lives on the open file description; closing
    /// the file releases it.
    _file: File,
    path: PathBuf,
}

impl AuditWriterLock {
    /// Path of the lock file this handle holds.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Outcome of trying to become the audit writer.
#[derive(Debug)]
pub enum LockOutcome {
    /// We hold the lock and may write.
    Acquired(AuditWriterLock),
    /// Another process holds it. The caller must open read-only.
    HeldByAnother,
}

/// Conventional lock path for an audit directory.
#[must_use]
pub fn lock_path(audit_dir: impl AsRef<Path>) -> PathBuf {
    audit_dir.as_ref().join("writer.lock")
}

/// Try to acquire the exclusive audit-writer lock without blocking.
///
/// Non-blocking deliberately: a command that cannot write should degrade to
/// read-only immediately, not stall behind a daemon that will hold the lock
/// for as long as it runs.
///
/// # Errors
///
/// Returns an error only when the lock file itself cannot be created or
/// opened. A lock held by another process is [`LockOutcome::HeldByAnother`],
/// not an error.
pub fn try_acquire(audit_dir: impl AsRef<Path>) -> std::io::Result<LockOutcome> {
    let path = lock_path(&audit_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;

    #[cfg(unix)]
    {
        // SAFETY: `file` is an open, valid file descriptor for the duration of
        // this call. LOCK_EX|LOCK_NB either takes the lock or fails with
        // EWOULDBLOCK; it never blocks and never affects other descriptors.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(code)
                    if code == libc::EWOULDBLOCK
                        || code == libc::EAGAIN
                        || code == libc::EACCES =>
                {
                    Ok(LockOutcome::HeldByAnother)
                }
                _ => Err(err),
            };
        }
        Ok(LockOutcome::Acquired(AuditWriterLock { _file: file, path }))
    }

    #[cfg(not(unix))]
    {
        // B12 #78 LOW: there is no flock equivalent wired up here, so
        // single-writer exclusivity is NOT actually enforced on this platform.
        // Reporting Acquired preserves today's behaviour (the daemon can still
        // write) but a second daemon would also be told it holds the lock —
        // the exact concurrent-writer hazard this module exists to prevent.
        // This is tolerable only because the runtime is Linux-first and
        // Windows support is not yet shipped; a real `LockFileEx`-based lock is
        // required before it is. Warn so the missing guarantee is never silent.
        tracing::warn!(
            event = "audit_writer_lock_unenforced",
            "exclusive audit-writer locking is not implemented on this platform; \
             concurrent audit writers are not prevented"
        );
        Ok(LockOutcome::Acquired(AuditWriterLock { _file: file, path }))
    }
}

/// How often [`acquire_with_wait`] re-attempts a contended lock.
const ACQUIRE_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Best-effort identification of the process holding the writer lock.
///
/// Linux only: matches the lock file's device and inode against the FLOCK
/// entries in `/proc/locks` and resolves the holder's comm. Returns e.g.
/// `"pid 12345 (grith)"`. `None` when the holder cannot be determined —
/// callers must treat this as a diagnostic garnish, never a guarantee.
#[must_use]
pub fn holder_hint(audit_dir: impl AsRef<Path>) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(lock_path(&audit_dir)).ok()?;
        let (want_major, want_minor, want_inode) =
            (libc::major(meta.dev()), libc::minor(meta.dev()), meta.ino());
        let locks = std::fs::read_to_string("/proc/locks").ok()?;
        for line in locks.lines() {
            // "1: FLOCK  ADVISORY  WRITE 12345 08:03:7344 0 EOF"
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 || fields[1] != "FLOCK" {
                continue;
            }
            let Ok(pid) = fields[4].parse::<u32>() else {
                continue;
            };
            let mut dev_ino = fields[5].split(':');
            let (Some(maj), Some(min), Some(ino)) =
                (dev_ino.next(), dev_ino.next(), dev_ino.next())
            else {
                continue;
            };
            // Device numbers are printed in hex, the inode in decimal.
            let matches = u32::from_str_radix(maj, 16) == Ok(want_major)
                && u32::from_str_radix(min, 16) == Ok(want_minor)
                && ino.parse::<u64>() == Ok(want_inode);
            if matches {
                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|c| c.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                return Some(format!("pid {pid} ({comm})"));
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = audit_dir;
        None
    }
}

/// Try to acquire the exclusive audit-writer lock, retrying for up to `wait`.
///
/// For the process that intends to *be* the daemon. A daemon restart releases
/// the predecessor's port early in shutdown but its writer lock only at
/// process exit (after connection drain and the final audit sync flush), so a
/// successor routinely starts while the lock is still held for a few more
/// seconds. A single non-blocking attempt turns that race into a daemon that
/// silently cannot record; waiting out the handover absorbs it.
///
/// Returns [`LockOutcome::HeldByAnother`] only if the lock is still held when
/// `wait` expires — the caller decides whether that is fatal.
///
/// # Errors
///
/// Returns an error only when the lock file itself cannot be created or
/// opened, exactly as [`try_acquire`] does.
pub fn acquire_with_wait(
    audit_dir: impl AsRef<Path>,
    wait: std::time::Duration,
) -> std::io::Result<LockOutcome> {
    let deadline = std::time::Instant::now() + wait;
    let mut logged_contention = false;
    loop {
        match try_acquire(&audit_dir)? {
            LockOutcome::Acquired(lock) => return Ok(LockOutcome::Acquired(lock)),
            LockOutcome::HeldByAnother => {
                if std::time::Instant::now() >= deadline {
                    return Ok(LockOutcome::HeldByAnother);
                }
                if !logged_contention {
                    logged_contention = true;
                    tracing::warn!(
                        event = "audit_writer_lock_wait",
                        wait_secs = wait.as_secs_f32(),
                        "another process owns the audit database; waiting for it to be released"
                    );
                }
                std::thread::sleep(
                    ACQUIRE_RETRY_INTERVAL
                        .min(deadline.saturating_duration_since(std::time::Instant::now())),
                );
            }
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn first_caller_acquires_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        match try_acquire(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => assert!(lock.path().ends_with("writer.lock")),
            LockOutcome::HeldByAnother => panic!("an uncontended lock must be acquired"),
        }
    }

    #[test]
    fn the_lock_file_is_created_under_the_audit_dir() {
        let dir = tempfile::tempdir().unwrap();
        let _lock = try_acquire(dir.path()).unwrap();
        assert!(dir.path().join("writer.lock").exists());
    }

    /// The lock must survive as long as its handle and no longer.
    #[test]
    fn dropping_the_handle_releases_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let lock = try_acquire(dir.path()).unwrap();
        drop(lock);
        // Re-acquiring in-process only proves the handle was dropped; the
        // cross-process guarantee is exercised by
        // `a_second_process_cannot_take_the_lock`.
        assert!(matches!(
            try_acquire(dir.path()).unwrap(),
            LockOutcome::Acquired(_)
        ));
    }

    /// The guarantee that matters: a *different process* is refused.
    ///
    /// flock locks live on the open file description, and each `open()`
    /// creates a new one — so on Linux a second in-process acquisition IS
    /// refused (see `a_second_in_process_acquire_is_refused`). This test still
    /// forks a child because the cross-process refusal is the guarantee the
    /// daemon actually relies on.
    #[test]
    fn a_second_process_cannot_take_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let _held = match try_acquire(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::HeldByAnother => panic!("parent should hold the lock"),
        };

        let path = lock_path(dir.path());
        // Exercise the same flock call from a child process.
        let status = std::process::Command::new("sh")
            .arg("-c")
            // `flock -n` exits 1 when the lock is held.
            .arg(format!(
                "command -v flock >/dev/null 2>&1 || exit 77; \
                 flock -n -e {} -c true",
                shell_quote(&path)
            ))
            .status()
            .expect("spawn flock probe");

        match status.code() {
            Some(77) => eprintln!("SKIP: flock(1) unavailable"),
            Some(0) => panic!("a second process acquired a lock the parent holds"),
            _ => {} // non-zero: correctly refused
        }
    }

    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
    }

    /// Each `open()` creates a new open file description, and flock locks on
    /// distinct OFDs conflict even within one process — the property the
    /// wait-based tests below depend on.
    #[test]
    fn a_second_in_process_acquire_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let _held = try_acquire(dir.path()).unwrap();
        assert!(matches!(
            try_acquire(dir.path()).unwrap(),
            LockOutcome::HeldByAnother
        ));
    }

    /// A holder that never lets go exhausts the wait and is reported, not
    /// spun on forever.
    #[test]
    fn acquire_with_wait_reports_a_persistent_holder() {
        let dir = tempfile::tempdir().unwrap();
        let _held = try_acquire(dir.path()).unwrap();
        let outcome = acquire_with_wait(dir.path(), std::time::Duration::from_millis(300)).unwrap();
        assert!(matches!(outcome, LockOutcome::HeldByAnother));
    }

    /// The restart-handover case: the predecessor releases the lock while the
    /// successor is waiting, and the successor becomes the owner.
    #[test]
    fn acquire_with_wait_succeeds_once_the_holder_releases() {
        let dir = tempfile::tempdir().unwrap();
        let held = match try_acquire(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::HeldByAnother => panic!("uncontended lock must be acquired"),
        };
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(400));
            drop(held);
        });
        let outcome = acquire_with_wait(dir.path(), std::time::Duration::from_secs(10)).unwrap();
        releaser.join().unwrap();
        assert!(matches!(outcome, LockOutcome::Acquired(_)));
    }

    /// work/74 acceptance 4: a non-owner opens read-only, and SQLite — not our
    /// own discipline — is what stops it writing. A bug that tries to insert
    /// gets an error rather than silently becoming the second writer that
    /// forked the chain.
    #[test]
    fn a_read_only_opener_cannot_write() {
        use crate::storage::AuditStorage;
        use crate::types::AuditRecord;

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");

        // Owner creates the schema and one record.
        let record = {
            let owner = AuditStorage::open(&db).unwrap();
            let record = AuditRecord::new(
                uuid::Uuid::new_v4(),
                "test".to_string(),
                "FileRead(/tmp/x)".to_string(),
                &serde_json::json!({}),
                0.0,
                crate::types::ProxyActionSummary::Allow,
                Vec::new(),
                0.0,
                None,
            );
            owner.insert_record(&record).unwrap();
            record
        };

        let reader = AuditStorage::open_read_only(&db).unwrap();
        // Reads work.
        assert!(reader.verify_chain().is_ok());
        // Writes do not.
        assert!(
            reader.insert_record(&record).is_err(),
            "a read-only opener must not be able to insert"
        );
    }

    /// A read-only open must not bring a database into existence — creating
    /// the schema is a write, and the reader is by definition not the owner.
    #[test]
    fn read_only_open_of_a_missing_database_fails() {
        let dir = tempfile::tempdir().unwrap();
        assert!(crate::storage::AuditStorage::open_read_only(dir.path().join("nope.db")).is_err());
    }
}
