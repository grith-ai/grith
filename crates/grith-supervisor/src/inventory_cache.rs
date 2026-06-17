// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Persistent SHA-256 cache for the session-pinned inventory walk.
//!
//! The walk in `provenance.rs` hashes every executable under each
//! `routine_exec_roots` glob at session start. On a typical Rust dev
//! box that's hundreds of cargo extension binaries plus `~/.local/bin`
//! plus distro binaries — re-hashing them on every `grith exec` start
//! is the dominant component of session-start latency once the file
//! cap is hit.
//!
//! Almost none of those binaries change between sessions. This module
//! is a tiny SQLite-backed map keyed by `canonical_path` and gated on
//! `(mtime_nanos, size)` so any update — `cargo install`, `apt
//! upgrade`, manual rebuild — invalidates the entry automatically.
//!
//! Concurrent access from `rayon` worker threads is serialised through
//! a single `Mutex<Connection>` (SQLite serialises writes anyway; the
//! Mutex just keeps the Rust borrow checker happy). The cache is
//! optional — when `dirs::cache_dir()` is unavailable or the open
//! fails for any reason, callers degrade to live hashing without
//! erroring out.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

/// SQLite-backed cache for `(canonical_path, mtime, size) → sha256_hex`.
pub struct InventoryCache {
    conn: Mutex<Connection>,
}

/// Stat fields tracked alongside each hash. Cache hits require both to
/// match — any in-place rewrite that bumps the mtime invalidates the
/// entry; any append-truncate cycle that produces the same mtime but a
/// different size also invalidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatTag {
    pub mtime_nanos: i64,
    pub size: u64,
}

impl InventoryCache {
    /// Open the cache at `<dirs::cache_dir>/grith/inventory_hashes.db`.
    /// Returns `None` if the cache dir can't be located (no HOME, etc.).
    pub fn open_default() -> Option<Self> {
        let cache_dir = dirs::cache_dir()?.join("grith");
        std::fs::create_dir_all(&cache_dir).ok()?;
        Self::open(&cache_dir.join("inventory_hashes.db")).ok()
    }

    /// Open the cache at the given path. Returns an error on connection
    /// or schema-init failure — callers should fall back to a no-op
    /// cache rather than failing the session.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        // Same PRAGMA stack as `grith-audit/src/storage.rs` so concurrent
        // writes from multiple supervisor sessions don't lock each other
        // out. WAL keeps readers unblocked during writes; synchronous=NORMAL
        // is safe with WAL; the 5s busy timeout covers the rare contention.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;
             CREATE TABLE IF NOT EXISTS inventory_hashes (
                canonical_path TEXT PRIMARY KEY,
                mtime_nanos INTEGER NOT NULL,
                size INTEGER NOT NULL,
                sha256_hex TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Return the cached sha256 if `(mtime, size)` still matches.
    pub fn try_get(&self, canonical_path: &str, tag: StatTag) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        let (mtime, size, sha): (i64, i64, String) = conn
            .query_row(
                "SELECT mtime_nanos, size, sha256_hex \
                 FROM inventory_hashes WHERE canonical_path = ?1",
                params![canonical_path],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .ok()
            .flatten()?;
        if mtime == tag.mtime_nanos && size as u64 == tag.size {
            Some(sha)
        } else {
            None
        }
    }

    /// Upsert the cache entry. Errors are swallowed — a write failure
    /// only means the next session will re-hash this binary.
    pub fn put(&self, canonical_path: &str, tag: StatTag, sha256_hex: &str) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT INTO inventory_hashes (canonical_path, mtime_nanos, size, sha256_hex) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(canonical_path) DO UPDATE SET \
                    mtime_nanos = excluded.mtime_nanos, \
                    size = excluded.size, \
                    sha256_hex = excluded.sha256_hex",
                params![canonical_path, tag.mtime_nanos, tag.size as i64, sha256_hex],
            );
        }
    }

    /// Count entries — for tests + dashboards.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.conn
            .lock()
            .ok()
            .and_then(|c| {
                c.query_row("SELECT COUNT(*) FROM inventory_hashes", [], |r| {
                    r.get::<_, i64>(0)
                })
                .ok()
            })
            .map(|n| n as usize)
            .unwrap_or(0)
    }
}

/// Extract `(mtime_nanos, size)` from `std::fs::Metadata`. Returns
/// `None` if mtime is missing or unrepresentable as nanoseconds since
/// the Unix epoch (extremely unusual; cache miss in that case).
pub fn stat_tag(metadata: &std::fs::Metadata) -> Option<StatTag> {
    let mtime = metadata.modified().ok()?;
    let nanos = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(StatTag {
        mtime_nanos: nanos.try_into().ok()?,
        size: metadata.len(),
    })
}

/// Helper for tests that want a fresh cache without depending on
/// `dirs::cache_dir()`.
#[cfg(test)]
pub fn open_in_tempdir() -> (InventoryCache, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("inventory_hashes.db");
    let cache = InventoryCache::open(&path).expect("open cache");
    (cache, dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_is_a_miss() {
        let (cache, _dir) = open_in_tempdir();
        assert!(cache
            .try_get(
                "/usr/bin/ls",
                StatTag {
                    mtime_nanos: 1,
                    size: 1
                }
            )
            .is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn put_then_get_round_trips() {
        let (cache, _dir) = open_in_tempdir();
        let tag = StatTag {
            mtime_nanos: 1_700_000_000_000_000_000,
            size: 12345,
        };
        cache.put("/usr/bin/cargo", tag, "deadbeef");
        assert_eq!(
            cache.try_get("/usr/bin/cargo", tag),
            Some("deadbeef".to_string())
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn mtime_change_invalidates() {
        let (cache, _dir) = open_in_tempdir();
        let original = StatTag {
            mtime_nanos: 1,
            size: 100,
        };
        cache.put("/usr/bin/cargo", original, "aaaa");
        let bumped = StatTag {
            mtime_nanos: 2,
            size: 100,
        };
        assert!(cache.try_get("/usr/bin/cargo", bumped).is_none());
    }

    #[test]
    fn size_change_invalidates() {
        let (cache, _dir) = open_in_tempdir();
        let original = StatTag {
            mtime_nanos: 1,
            size: 100,
        };
        cache.put("/usr/bin/cargo", original, "aaaa");
        let bumped = StatTag {
            mtime_nanos: 1,
            size: 101,
        };
        assert!(cache.try_get("/usr/bin/cargo", bumped).is_none());
    }

    #[test]
    fn upsert_replaces_existing_entry() {
        let (cache, _dir) = open_in_tempdir();
        cache.put(
            "/usr/bin/cargo",
            StatTag {
                mtime_nanos: 1,
                size: 100,
            },
            "aaaa",
        );
        cache.put(
            "/usr/bin/cargo",
            StatTag {
                mtime_nanos: 2,
                size: 200,
            },
            "bbbb",
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.try_get(
                "/usr/bin/cargo",
                StatTag {
                    mtime_nanos: 2,
                    size: 200
                }
            ),
            Some("bbbb".to_string())
        );
    }

    #[test]
    fn concurrent_puts_serialise_without_corruption() {
        use std::sync::Arc;
        let (cache, _dir) = open_in_tempdir();
        let cache = Arc::new(cache);
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || {
                    for j in 0..50 {
                        let path = format!("/bin/{i}_{j}");
                        cache.put(
                            &path,
                            StatTag {
                                mtime_nanos: i as i64,
                                size: j as u64,
                            },
                            &format!("hash_{i}_{j}"),
                        );
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(cache.len(), 400);
    }
}
