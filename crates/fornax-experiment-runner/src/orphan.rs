//! Startup orphan sweep for [`crate::staging::StagedWorktree`] directories
//! (AC5, the "orphan-worktree/process cleanup" half).
//!
//! [`StagedWorktree`](crate::staging::StagedWorktree)'s `Drop` impl already
//! makes cleanup unconditional for every in-process exit path — success,
//! error, timeout, cancellation, even an unwinding panic. What `Drop`
//! cannot cover is the process being killed outright (`SIGKILL`, an OOM
//! kill, a host crash) before it ever gets to unwind. **This module is an
//! honest substitute for that case, not a literal process-kill test**: a
//! real "kill -9 mid-experiment, then verify cleanup" scenario is
//! impractical to simulate deterministically inside `cargo test` (it would
//! require actually killing the test process itself). Instead, every
//! executor caller is expected to run [`sweep_orphaned_staging_dirs`] once
//! at startup, before provisioning any new [`crate::staging::StagedWorktree`],
//! against [`crate::staging::staging_root`] — the one place every staged
//! worktree is ever created (see that module's docs). A directory that
//! survived a crash is just an ordinary directory sitting there the next
//! time this runs; age is the only signal available to tell it apart from
//! one belonging to a still-running experiment.
//!
//! # Choosing `max_age`
//!
//! `max_age` must exceed the longest permitted experiment runtime, or this
//! sweep can delete a live experiment's own staged directory out from under
//! it. [`DEFAULT_ORPHAN_MAX_AGE`] is deliberately generous (one hour) for
//! exactly this reason — the cost of sweeping late is a little disk left
//! around briefly; the cost of sweeping early is corrupting a running
//! experiment.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Default staleness threshold for [`sweep_orphaned_staging_dirs`]. See the
/// module docs' "Choosing `max_age`" section for why this must exceed the
/// longest permitted experiment runtime.
pub const DEFAULT_ORPHAN_MAX_AGE: Duration = Duration::from_secs(3600);

/// Removes every entry directly under `staging_root` whose last-modified
/// time is at least `max_age` old, returning the paths actually removed. A
/// missing `staging_root` is not an error — nothing has ever staged an
/// experiment yet, which is the common case on a fresh host.
///
/// Age is computed as `now.duration_since(modified)`, saturating to
/// [`Duration::ZERO`] rather than erroring when the modification time is in
/// the future (clock skew) or otherwise not comparable — a directory this
/// sweep cannot confidently age is treated as fresh (never swept early), a
/// conservative failure mode matching this module's "sweep late, not
/// early" bias.
pub fn sweep_orphaned_staging_dirs(
    staging_root: &Path,
    max_age: Duration,
) -> io::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(staging_root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let now = SystemTime::now();
    let mut removed = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let metadata = entry.metadata()?;
        let age = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .unwrap_or(Duration::ZERO);
        if age >= max_age {
            std::fs::remove_dir_all(&path)?;
            removed.push(path);
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "fornax-orphan-test-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn sweeping_a_nonexistent_staging_root_is_not_an_error() {
        let staging_root = temp_dir("nonexistent-parent").join("experiments");
        let removed = sweep_orphaned_staging_dirs(&staging_root, Duration::ZERO).unwrap();
        assert!(removed.is_empty());
    }

    /// AC5's orphan half: a directory nobody's `Drop` impl ever ran for
    /// (standing in for one left behind by a process kill) is gone after
    /// the sweep runs — the honest, documented substitute for a literal
    /// kill -9 test (see module docs).
    #[test]
    fn sweep_removes_an_orphaned_directory_older_than_max_age() {
        let staging_root = temp_dir("staging-root");
        let orphan = staging_root.join("fornax-experiment-orphan");
        std::fs::create_dir_all(&orphan).unwrap();

        // Zero threshold: any directory's age (even a few microseconds) is
        // "at least" it, making this deterministic without needing to
        // fabricate an old mtime.
        let removed = sweep_orphaned_staging_dirs(&staging_root, Duration::ZERO).unwrap();

        assert_eq!(removed, vec![orphan.clone()]);
        assert!(!orphan.exists());
    }

    #[test]
    fn sweep_leaves_directories_younger_than_max_age_alone() {
        let staging_root = temp_dir("staging-root");
        let live = staging_root.join("fornax-experiment-live");
        std::fs::create_dir_all(&live).unwrap();

        // A generous threshold no freshly-created directory can satisfy —
        // this is the "still-running experiment must survive" half of AC5.
        let removed =
            sweep_orphaned_staging_dirs(&staging_root, Duration::from_secs(3600)).unwrap();

        assert!(removed.is_empty());
        assert!(live.exists());

        std::fs::remove_dir_all(&staging_root).ok();
    }

    #[test]
    fn sweep_ignores_plain_files_directly_under_staging_root() {
        let staging_root = temp_dir("staging-root");
        std::fs::write(staging_root.join("not-a-worktree.txt"), b"stray file").unwrap();

        let removed = sweep_orphaned_staging_dirs(&staging_root, Duration::ZERO).unwrap();

        assert!(removed.is_empty());
        assert!(staging_root.join("not-a-worktree.txt").exists());

        std::fs::remove_dir_all(&staging_root).ok();
    }
}
