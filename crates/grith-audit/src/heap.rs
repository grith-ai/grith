// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Return free-listed heap to the operating system after a bulk pass.
//!
//! An analytics day rebuild allocates and frees hundreds of thousands of
//! small objects — one per event in the day. glibc's allocator does not hand
//! small freed chunks back to the kernel: they stay on the arena's free list,
//! so the process's resident size ratchets up to the high-water mark of the
//! largest day it has ever rebuilt and stays there. The daemon runs those
//! rebuilds from several threads (the background analytics worker, the
//! retention thread, and any tokio worker serving an analytics route), and
//! glibc gives each thread its own arena, so the ratchet is *per arena*.
//!
//! Measured on a developer machine on 2026-09-02: a daemon 20 minutes old
//! held 9.8 GB of anonymous RSS against a 150 MB target, and `malloc_trim(0)`
//! in a single-arena reproduction returned 590 MB to 9 MB. Nothing was
//! leaked in the C sense — every byte was free-listed and reusable — but the
//! kernel could not have it back, and systemd-oomd killed the cgroup the
//! daemon was sharing with the editor that had started it.
//!
//! Call this after a bounded bulk pass, never inside one: it walks every
//! arena and `madvise`s the free pages away, which costs microseconds to a
//! few milliseconds and is wasted if more of the same work follows
//! immediately.

/// Release free-listed heap back to the OS.
///
/// A no-op on allocators without the call (musl, macOS, Windows), where the
/// ratchet either does not occur or is not addressable this way.
pub fn release_free_heap() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: `malloc_trim` takes no pointers and touches only the
        // allocator's own free lists. It cannot invalidate a live
        // allocation — memory still owned by the program is never trimmed —
        // so it is safe to call at any point from any thread.
        unsafe {
            libc::malloc_trim(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The call must be safe to make when there is nothing to release, and
    /// safe to make repeatedly — the daemon calls it once per catch-up pass
    /// whether or not that pass did any work worth trimming.
    #[test]
    fn releasing_an_untouched_heap_is_a_no_op() {
        release_free_heap();
        release_free_heap();
    }

    /// A bulk allocate-then-free cycle must not leave the freed pages
    /// resident. Asserting an exact figure would be allocator-version
    /// dependent; asserting that the trim gives back the bulk of what the
    /// cycle took is the invariant the daemon relies on.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn a_bulk_free_is_returned_to_the_os() {
        fn rss_kb() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("RssAnon:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        }

        let before = rss_kb();
        // Many small allocations, the shape a day rebuild produces: small
        // chunks come from the arena's free list, not from mmap, so they are
        // exactly what `malloc_trim` exists to reclaim.
        let held: Vec<String> = (0..400_000).map(|i| format!("event-{i:0>64}")).collect();
        let peak = rss_kb();
        assert!(
            peak > before + 16_000,
            "test did not allocate enough to be meaningful: {before} -> {peak} kB"
        );
        drop(held);
        release_free_heap();
        let after = rss_kb();
        let grown = after.saturating_sub(before);
        let peak_growth = peak.saturating_sub(before);
        assert!(
            grown * 4 < peak_growth,
            "trim returned little: before={before} peak={peak} after={after} kB"
        );
    }
}
