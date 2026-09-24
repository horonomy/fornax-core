//! Ephemeral, filesystem-level working-tree isolation (AC1: "experiments
//! cannot mutate the primary working tree by default").
//!
//! This deliberately duplicates the relevant working tree with plain
//! `std::fs` directory operations rather than shelling out to `git worktree
//! add` — `crates/fornax-daemon/tests/adversarial_daemon_input.rs`'s zero
//! subprocess-spawn invariant over every production module in this
//! workspace rules out launching an external `git` process, and this
//! isolation mechanism has no need for `HEAD`/index-aware git semantics in
//! the first place: it only ever needs an independent copy of files on
//! disk that an intervention can freely mutate without the source tree
//! noticing. `fornax-vcs`'s in-process `gix` layer stays the read-only
//! query path for git *state* elsewhere in this workspace; nothing here
//! competes with it.

use std::io;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// The staging directory's name, relative to `$FORNAX_HOME` — where every
/// [`StagedWorktree`] is created, and the one directory [`crate::orphan`]'s
/// startup sweep scans.
pub const EXPERIMENT_STAGING_DIR: &str = "experiments";

/// `<fornax_home>/experiments` — the root every [`StagedWorktree`] is
/// created inside, and the only directory [`crate::orphan::sweep_orphaned_staging_dirs`]
/// is ever pointed at.
pub fn staging_root(fornax_home: &Path) -> PathBuf {
    fornax_home.join(EXPERIMENT_STAGING_DIR)
}

/// Directory entry names never copied into a staged worktree: `target`
/// (Rust build output — large, regenerable, and never itself the subject of
/// a counterfactual experiment) and `.git` (copying the full object
/// database is both expensive and unnecessary — no [`fornax_types::experiment::ExperimentKind`]
/// this crate executes needs commit history inside the staged copy, only
/// working-tree file contents).
const SKIPPED_ENTRY_NAMES: &[&str] = &["target", ".git"];

/// Everything that can go wrong provisioning or using a [`StagedWorktree`].
#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    #[error("failed to create staging directory {path}: {source}")]
    CreateStagingRoot {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to provision ephemeral worktree under {staging_root}: {source}")]
    Provision {
        staging_root: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to copy working tree from {source_root} into staged worktree: {source}")]
    Copy {
        source_root: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A caller-supplied relative path resolves outside the staged
    /// worktree's own root — the exact escape AC1 exists to prevent. Never
    /// silently clamped or truncated; refused outright.
    #[error("intervention path '{attempted}' escapes the staged worktree boundary")]
    Escapes { attempted: String },
    #[error("failed to resolve path inside staged worktree: {source}")]
    Resolve {
        #[source]
        source: io::Error,
    },
}

/// An ephemeral, isolated copy of a source working tree. Backed by a
/// [`tempfile::TempDir`] created *inside* [`staging_root`] — the same
/// directory [`crate::orphan`]'s sweep scans, so a directory this guard
/// fails to clean up (process kill, `SIGKILL`, panic during unwind-unsafe
/// code) is still findable and reclaimable later, rather than silently
/// leaking into the OS temp directory the orphan sweep never looks at.
///
/// Cleanup is unconditional: dropping this value removes the entire staged
/// directory tree, on every path out of scope — a normal return, an early
/// `return`/`?` on error, a timeout abort, a cancellation, or an unwinding
/// panic — exactly matching `tempfile::TempDir`'s own `Drop` guarantee.
/// Nothing in this crate calls `std::mem::forget` on one or leaks its inner
/// `TempDir`.
pub struct StagedWorktree {
    dir: TempDir,
}

impl StagedWorktree {
    /// Create a fresh ephemeral directory under `staging_root` and copy
    /// `source_root`'s contents into it (skipping [`SKIPPED_ENTRY_NAMES`]
    /// and never following symlinks — a followed symlink would be a second
    /// way to escape the intended boundary). `source_root` itself is only
    /// ever read here, never written.
    pub fn provision(staging_root: &Path, source_root: &Path) -> Result<Self, StagingError> {
        std::fs::create_dir_all(staging_root).map_err(|source| {
            StagingError::CreateStagingRoot {
                path: staging_root.to_path_buf(),
                source,
            }
        })?;
        let dir = tempfile::Builder::new()
            .prefix("fornax-experiment-")
            .tempdir_in(staging_root)
            .map_err(|source| StagingError::Provision {
                staging_root: staging_root.to_path_buf(),
                source,
            })?;
        copy_dir_recursive(source_root, dir.path()).map_err(|source| StagingError::Copy {
            source_root: source_root.to_path_buf(),
            source,
        })?;
        Ok(Self { dir })
    }

    /// The staged copy's own root directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Resolve a caller-supplied, intervention-relative path (e.g. from
    /// [`fornax_types::experiment::Intervention::params`], opaque JSON this
    /// crate never trusts blindly) against this staged worktree's root and
    /// verify the resolved path genuinely stays inside it. Refuses any
    /// `..`-based or symlink-based escape attempt with
    /// [`StagingError::Escapes`] rather than silently clamping it — this is
    /// what makes AC1 ("experiments cannot mutate the primary working
    /// tree") true of a *real* caller-supplied path, not just of the
    /// well-behaved fixture paths this crate's own tests happen to pass.
    pub fn resolve_contained(&self, relative: &str) -> Result<PathBuf, StagingError> {
        let root_canon = self
            .dir
            .path()
            .canonicalize()
            .map_err(|source| StagingError::Resolve { source })?;
        let candidate = self.dir.path().join(relative);

        // `canonicalize` requires the path to exist. An intervention that
        // creates a brand-new file has a candidate path that does not exist
        // yet — check its parent directory's canonical form instead, which
        // must already exist inside the staged copy.
        let check_path: PathBuf = if candidate.exists() {
            candidate.clone()
        } else {
            match candidate.parent() {
                Some(parent) => parent.to_path_buf(),
                None => self.dir.path().to_path_buf(),
            }
        };
        let canon = check_path
            .canonicalize()
            .map_err(|source| StagingError::Resolve { source })?;

        if !canon.starts_with(&root_canon) {
            return Err(StagingError::Escapes {
                attempted: relative.to_string(),
            });
        }
        Ok(candidate)
    }
}

/// Recursively copies `src`'s contents into `dst` (which must already
/// exist). Skips [`SKIPPED_ENTRY_NAMES`] and never follows symlinks —
/// `DirEntry::metadata` does not traverse a symlink on any platform this
/// crate targets, so a symlink is detected and skipped rather than its
/// target being copied or followed.
fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_name = entry.file_name();
        if SKIPPED_ENTRY_NAMES
            .iter()
            .any(|skip| file_name == std::ffi::OsStr::new(skip))
        {
            continue;
        }
        let file_type = entry.file_type()?;
        let dst_path = dst.join(&file_name);
        if file_type.is_symlink() {
            continue;
        } else if file_type.is_dir() {
            std::fs::create_dir_all(&dst_path)?;
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "fornax-staging-test-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn provisioning_copies_files_without_touching_the_source() {
        let source_root = temp_dir("source");
        std::fs::write(source_root.join("claimed.txt"), b"original\n").unwrap();
        let staging_root_dir = temp_dir("staging-root");

        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();
        let staged_file = staged.path().join("claimed.txt");
        assert_eq!(std::fs::read(&staged_file).unwrap(), b"original\n");

        // Mutate the staged copy; the source must be untouched (AC1).
        std::fs::write(&staged_file, b"mutated\n").unwrap();
        assert_eq!(
            std::fs::read(source_root.join("claimed.txt")).unwrap(),
            b"original\n"
        );

        std::fs::remove_dir_all(&source_root).ok();
    }

    #[test]
    fn provisioning_skips_target_and_git_directories() {
        let source_root = temp_dir("source");
        std::fs::create_dir_all(source_root.join("target")).unwrap();
        std::fs::write(source_root.join("target").join("big.bin"), b"x").unwrap();
        std::fs::create_dir_all(source_root.join(".git")).unwrap();
        std::fs::write(
            source_root.join(".git").join("HEAD"),
            b"ref: refs/heads/main",
        )
        .unwrap();
        std::fs::write(source_root.join("kept.txt"), b"kept\n").unwrap();
        let staging_root_dir = temp_dir("staging-root");

        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();
        assert!(!staged.path().join("target").exists());
        assert!(!staged.path().join(".git").exists());
        assert!(staged.path().join("kept.txt").exists());

        std::fs::remove_dir_all(&source_root).ok();
    }

    #[test]
    fn staged_worktree_is_created_inside_the_staging_root() {
        let source_root = temp_dir("source");
        let staging_root_dir = temp_dir("staging-root");

        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();
        assert!(staged.path().starts_with(&staging_root_dir));

        std::fs::remove_dir_all(&source_root).ok();
    }

    #[test]
    fn drop_removes_the_staged_directory() {
        let source_root = temp_dir("source");
        let staging_root_dir = temp_dir("staging-root");

        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();
        let path = staged.path().to_path_buf();
        assert!(path.exists());
        drop(staged);
        assert!(!path.exists(), "staged directory must be gone after Drop");

        std::fs::remove_dir_all(&source_root).ok();
    }

    #[test]
    fn resolve_contained_accepts_a_path_inside_the_staged_copy() {
        let source_root = temp_dir("source");
        std::fs::write(source_root.join("claimed.txt"), b"hi\n").unwrap();
        let staging_root_dir = temp_dir("staging-root");
        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();

        let resolved = staged.resolve_contained("claimed.txt").unwrap();
        assert_eq!(resolved, staged.path().join("claimed.txt"));

        std::fs::remove_dir_all(&source_root).ok();
    }

    #[test]
    fn resolve_contained_refuses_a_traversal_escape() {
        let source_root = temp_dir("source");
        let staging_root_dir = temp_dir("staging-root");
        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();

        // Enough `..` segments to walk past the filesystem root regardless
        // of how deep the OS temp directory happens to be nested — the OS
        // clamps excess `..` at `/`, so this deterministically lands on a
        // real, existing path (`/etc/passwd`) outside the staged copy.
        let err = staged
            .resolve_contained("../../../../../../../../../../../../etc/passwd")
            .unwrap_err();
        assert!(matches!(err, StagingError::Escapes { .. }), "{err:?}");

        std::fs::remove_dir_all(&source_root).ok();
    }

    #[test]
    fn resolve_contained_accepts_a_not_yet_existing_new_file_inside_the_copy() {
        let source_root = temp_dir("source");
        let staging_root_dir = temp_dir("staging-root");
        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();

        let resolved = staged.resolve_contained("new_file.txt").unwrap();
        assert_eq!(resolved, staged.path().join("new_file.txt"));

        std::fs::remove_dir_all(&source_root).ok();
    }
}
