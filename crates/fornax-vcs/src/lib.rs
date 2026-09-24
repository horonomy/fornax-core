//! Thin, synchronous, in-process git query layer (FORNX-302).
//!
//! Exists as a standalone crate — not folded into `fornax-adapter-claude` or
//! any other adapter — because of two real workspace constraints:
//!
//! 1. `crates/fornax-daemon/tests/adversarial_daemon_input.rs::
//!    subprocess_surface_is_still_zero_in_production_code` (FORNX-238)
//!    asserts a zero subprocess-spawn surface across every production module
//!    in this workspace, which rules out shelling out to a `git` binary.
//! 2. `docs/contributing/adding-an-adapter.md`'s "Allowed core dependencies"
//!    restricts adapter crates to depending on `fornax-types` only, which
//!    rules out an in-process git library living directly inside an adapter
//!    crate.
//!
//! This crate depends on [`gix`] — a pure-Rust, in-process reimplementation
//! of git (the gitoxide project), not a wrapper around `libgit2` (no FFI to
//! a system library) and not a wrapper around the `git` binary (no
//! subprocess). It exposes a small, synchronous, adapter-callable interface;
//! adapters depend on this crate in addition to `fornax-types` — see
//! `docs/contributing/adding-an-adapter.md`'s narrowly-scoped amendment for
//! this exact exception.
//!
//! No network access, no subprocess spawn, no blocking beyond local disk
//! I/O — safe to call from the local critical path
//! (`docs/adr/0001-architecture-invariants.md`'s "no cloud dependency on the
//! local critical path").

use std::path::{Path, PathBuf};

/// The real, host-observed state of a git working tree at the moment this
/// was queried — independent of anything a coding agent claimed happened.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkingTreeStatus {
    /// `false` when `repo_path` (or any of its ancestors) is not inside a
    /// git working tree at all — a clean, non-error outcome, not folded into
    /// [`VcsError`].
    pub is_repo: bool,
    /// `HEAD`'s commit SHA, as a lowercase hex string. `None` for a real
    /// repository that has no commits yet (an "unborn" `HEAD`) — also not an
    /// error.
    pub head_commit: Option<String>,
    /// The working tree's root directory (`None` for a bare repository, or
    /// when [`Self::is_repo`] is `false`). Kept so a caller holding an
    /// absolute claimed path can resolve it against [`Self::dirty_paths`]
    /// via [`Self::is_absolute_path_dirty`] without independently
    /// re-discovering the repo root.
    pub work_dir: Option<PathBuf>,
    /// Paths (repo-root-relative, `/`-separated per git's own convention)
    /// that differ between `HEAD`'s tree, the index, and the working tree,
    /// or that are untracked — i.e. every path this git implementation's
    /// own status walk considers not clean, the same set
    /// `git status --ignored=no` would report. Empty when the working tree
    /// is clean.
    pub dirty_paths: Vec<String>,
}

impl WorkingTreeStatus {
    fn not_a_repo() -> Self {
        Self {
            is_repo: false,
            head_commit: None,
            work_dir: None,
            dirty_paths: Vec::new(),
        }
    }

    /// True when `path` (given relative to the queried repo root, using `/`
    /// separators — git's own convention, independent of host path
    /// separator) appears among [`Self::dirty_paths`].
    pub fn is_path_dirty(&self, path: &str) -> bool {
        self.dirty_paths.iter().any(|p| p == path)
    }

    /// Resolve an absolute (or otherwise host-path-shaped) `path` against
    /// [`Self::work_dir`] and report whether the result appears in
    /// [`Self::dirty_paths`]. Returns `None` when there is no known working
    /// directory to resolve against ([`Self::is_repo`] is `false`, the repo
    /// is bare) or `path` does not lie inside it — a caller with no
    /// meaningful yes/no answer, not a `false`.
    pub fn is_absolute_path_dirty(&self, path: &Path) -> Option<bool> {
        let work_dir = self.work_dir.as_deref()?;
        let rel = path.strip_prefix(work_dir).ok()?;
        let rel_str = rel.to_str()?.replace(std::path::MAIN_SEPARATOR, "/");
        Some(self.is_path_dirty(&rel_str))
    }
}

/// Everything that can go wrong querying working-tree state, distinct from
/// the honest, non-error "not a repo" / "no commits yet" outcomes above.
#[derive(Debug, thiserror::Error)]
pub enum VcsError {
    /// Discovery found *something* at or above `repo_path` that looks like a
    /// git directory but could not be opened as a valid repository (e.g. a
    /// corrupt `.git`) — distinct from [`WorkingTreeStatus::is_repo`] being
    /// `false`, which means no git directory was found at all.
    #[error("failed to open git repository: {0}")]
    Open(String),
    /// Repository opened successfully, but the status/tree query itself
    /// failed (e.g. an unreadable object database).
    #[error("failed to query git working-tree status: {0}")]
    Status(String),
}

/// Query `repo_path`'s working-tree status: whether it is (or is inside) a
/// git repository, its `HEAD` commit, and every path considered dirty
/// (uncommitted, unstaged, or untracked) by this git implementation's own
/// status walk.
///
/// Synchronous and local-only: no network access, no subprocess spawn, no
/// long-lived state. Searches upward from `repo_path` for a `.git`
/// directory, matching `git status`'s own behavior when run from a
/// subdirectory of a working tree.
pub fn working_tree_status(repo_path: &Path) -> Result<WorkingTreeStatus, VcsError> {
    let repo = match gix::discover(repo_path) {
        Ok(repo) => repo,
        // Only the "genuinely searched and found nothing" shapes of
        // `discover::upwards::Error` mean "not a repo" — `InaccessibleDirectory`,
        // `CurrentDir`, `CheckTrust`, etc. are real query failures (e.g. a
        // permission-denied directory on the search path) and must not be
        // silently folded into `is_repo: false`.
        Err(gix::discover::Error::Discover(
            gix::discover::upwards::Error::NoGitRepository { .. }
            | gix::discover::upwards::Error::NoGitRepositoryWithinCeiling { .. }
            | gix::discover::upwards::Error::NoGitRepositoryWithinFs { .. }
            | gix::discover::upwards::Error::NoMatchingCeilingDir,
        )) => return Ok(WorkingTreeStatus::not_a_repo()),
        Err(e) => return Err(VcsError::Open(e.to_string())),
    };

    // An unborn `HEAD` (a real repository with zero commits) is a legitimate
    // state, not a failure — reported as `head_commit: None`, matching
    // `WorkingTreeStatus::head_commit`'s documented contract.
    let head_commit = repo.head_id().ok().map(|id| id.to_string());
    let work_dir = repo.workdir().map(Path::to_path_buf);

    let dirty_paths = collect_dirty_paths(&repo)?;

    Ok(WorkingTreeStatus {
        is_repo: true,
        head_commit,
        work_dir,
        dirty_paths,
    })
}

fn collect_dirty_paths(repo: &gix::Repository) -> Result<Vec<String>, VcsError> {
    let status = repo
        .status(gix::progress::Discard)
        .map_err(|e| VcsError::Status(e.to_string()))?;
    let iter = status
        .into_iter(Vec::new())
        .map_err(|e| VcsError::Status(e.to_string()))?;

    let mut paths = Vec::new();
    for item in iter {
        let item = item.map_err(|e| VcsError::Status(e.to_string()))?;
        paths.push(item.location().to_string());
    }
    Ok(paths)
}

/// Real, host-observed status of exactly one path within a git working
/// tree, at the moment this was queried — independent of anything a coding
/// agent claimed happened.
///
/// Unlike [`working_tree_status`], which walks the *entire* working tree,
/// this restricts the underlying git status walk to `claimed_path` alone
/// via a pathspec. That distinction is not cosmetic: a full-repository
/// dirwalk (untracked-file scan included) run synchronously on every single
/// Edit/Write/MultiEdit — which is exactly when
/// `fornax-adapter-claude`'s `ClaudeGitWorkingTreeSensor` calls this — would
/// be a real, avoidable cost in a working tree with a large `node_modules`/
/// `target`/`.venv`, and that sensor only ever needs one path's answer. This
/// is the entry point it actually calls.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathStatus {
    /// `false` when `claimed_path` (or any of its ancestors) is not inside a
    /// git working tree at all.
    pub is_repo: bool,
    /// `HEAD`'s commit SHA, as a lowercase hex string. `None` for a real
    /// repository with no commits yet (an "unborn" `HEAD`).
    pub head_commit: Option<String>,
    /// `true` when git's status walk, restricted to `claimed_path`, reports
    /// it as uncommitted, unstaged, or untracked. Says nothing about
    /// whether `claimed_path` exists on disk at all (that's
    /// `ClaudeFileWriteConfirmedSensor`'s job) — a path that was never
    /// written and a path that is committed and unmodified both report
    /// `false` here, and so does a gitignored path (matching
    /// `git status --ignored=no`'s own default): this field answers "does
    /// git's status walk have anything pending for this path", not "is this
    /// path clean" in every sense that word could mean.
    pub is_dirty: bool,
}

impl PathStatus {
    fn not_a_repo() -> Self {
        Self {
            is_repo: false,
            head_commit: None,
            is_dirty: false,
        }
    }
}

/// Query whether `claimed_path` is dirty in its git working tree, restricted
/// to that one path (see [`PathStatus`] for why this is a separate, cheaper
/// entry point from [`working_tree_status`]).
///
/// Synchronous and local-only: no network access, no subprocess spawn.
/// Searches upward from `claimed_path`'s parent directory for a `.git`
/// directory, matching `git status`'s own behavior when run from a
/// subdirectory of a working tree.
pub fn path_status(claimed_path: &Path) -> Result<PathStatus, VcsError> {
    // `Path::parent()` returns `Some("")` for a bare relative filename
    // (e.g. `"claimed.txt"`), not `None` — `gix::discover("")` would then
    // resolve against an empty path rather than the current directory, so
    // that case is folded into the `"."` fallback too, not just a missing
    // parent.
    let start_dir = claimed_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let repo = match gix::discover(start_dir) {
        Ok(repo) => repo,
        Err(gix::discover::Error::Discover(
            gix::discover::upwards::Error::NoGitRepository { .. }
            | gix::discover::upwards::Error::NoGitRepositoryWithinCeiling { .. }
            | gix::discover::upwards::Error::NoGitRepositoryWithinFs { .. }
            | gix::discover::upwards::Error::NoMatchingCeilingDir,
        )) => return Ok(PathStatus::not_a_repo()),
        Err(e) => return Err(VcsError::Open(e.to_string())),
    };

    let head_commit = repo.head_id().ok().map(|id| id.to_string());

    let work_dir = repo.workdir().ok_or_else(|| {
        VcsError::Status("repository has no working directory (bare repo)".to_string())
    })?;
    let rel = claimed_path.strip_prefix(work_dir).map_err(|_| {
        VcsError::Status(format!(
            "{} is not inside the discovered repo's working directory {}",
            claimed_path.display(),
            work_dir.display()
        ))
    })?;
    let rel_str = rel
        .to_str()
        .ok_or_else(|| VcsError::Status(format!("{} is not valid UTF-8", claimed_path.display())))?
        .replace(std::path::MAIN_SEPARATOR, "/");

    let status = repo
        .status(gix::progress::Discard)
        .map_err(|e| VcsError::Status(e.to_string()))?;
    // Restricting the iterator to this one pathspec is what keeps the
    // underlying walk proportional to `claimed_path` rather than the whole
    // working tree — see this function's doc.
    let iter = status
        .into_iter(vec![gix::bstr::BString::from(rel_str)])
        .map_err(|e| VcsError::Status(e.to_string()))?;

    // The pathspec already restricts results to `claimed_path`; any item at
    // all (checking just the first is enough) means git considers it
    // changed.
    let is_dirty = match iter.into_iter().next() {
        Some(item) => {
            item.map_err(|e| VcsError::Status(e.to_string()))?;
            true
        }
        None => false,
    };

    Ok(PathStatus {
        is_repo: true,
        head_commit,
        is_dirty,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("fornax-vcs-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn reports_not_a_repo_for_a_plain_directory() {
        let dir = temp_dir();
        let status = working_tree_status(&dir).expect("query should not error");
        std::fs::remove_dir_all(&dir).ok();

        assert!(!status.is_repo);
        assert_eq!(status.head_commit, None);
        assert!(status.dirty_paths.is_empty());
    }

    #[test]
    fn reports_a_freshly_initialized_repo_as_a_clean_unborn_repo() {
        let dir = temp_dir();
        gix::init(&dir).expect("gix::init");

        let status = working_tree_status(&dir).expect("query should not error");
        std::fs::remove_dir_all(&dir).ok();

        assert!(status.is_repo);
        assert_eq!(status.head_commit, None);
        assert!(status.dirty_paths.is_empty());
    }

    #[test]
    fn reports_an_untracked_file_as_dirty() {
        let dir = temp_dir();
        gix::init(&dir).expect("gix::init");
        let file = dir.join("claimed.txt");
        std::fs::write(&file, "hello\n").expect("write file");

        let status = working_tree_status(&dir).expect("query should not error");
        std::fs::remove_dir_all(&dir).ok();

        assert!(status.is_repo);
        assert!(status.is_path_dirty("claimed.txt"));
        assert_eq!(
            status.is_absolute_path_dirty(&file),
            Some(true),
            "an absolute path under work_dir must resolve the same as its relative form"
        );
        assert_eq!(
            status.is_absolute_path_dirty(Path::new("/definitely/outside/repo.txt")),
            None,
            "a path outside work_dir has no meaningful dirty/clean answer"
        );
    }

    /// Writes a `[user]` section into `repo_dir/.git/config` and re-opens
    /// the repository so `gix`'s author/committer lookup resolves it.
    ///
    /// Earlier this set the process-wide `GIT_AUTHOR_*`/`GIT_COMMITTER_*`
    /// env vars instead. `std::env::set_var`/`var` mutate/read global
    /// process state that is not synchronized against other threads, and
    /// `cargo test` runs tests concurrently by default — a thread could
    /// call `repo.commit(..)` (which reads those env vars once, caching
    /// the result for the `gix::Repository` instance) in the brief window
    /// where another thread's `set_var` call was still in flight,
    /// intermittently observing an empty value and failing with
    /// `AuthorMissing` (seen in CI, not locally, exactly the profile of
    /// this race). Writing identity into this test's own repo-local
    /// config file instead touches no shared state, so it can't race.
    fn test_repo_with_identity(repo_dir: &Path) -> gix::Repository {
        let config_path = repo_dir.join(".git").join("config");
        let mut config = std::fs::read_to_string(&config_path).unwrap_or_default();
        config.push_str("\n[user]\n\tname = Fornax Test\n\temail = fornax-test@example.invalid\n");
        std::fs::write(&config_path, config).expect("write git config");
        gix::open(repo_dir).expect("re-open repo with identity config")
    }

    /// Writes `content` as a single-file commit named `filename` at the
    /// root of the repo at `repo_dir` — object database only, via `gix`'s
    /// own write/commit APIs (no `git` CLI, matching FORNX-238's
    /// zero-subprocess invariant). Returns the tree and commit IDs so
    /// callers can build a matching index (see
    /// `commit_and_index_single_file` for the fully-synced variant).
    fn commit_single_file(
        repo_dir: &Path,
        filename: &str,
        content: &[u8],
    ) -> (gix::ObjectId, gix::ObjectId) {
        let repo = test_repo_with_identity(repo_dir);
        let blob_id = repo.write_blob(content).expect("write blob").detach();
        let tree = gix::objs::Tree {
            entries: vec![gix::objs::tree::Entry {
                mode: gix::objs::tree::EntryKind::Blob.into(),
                filename: filename.into(),
                oid: blob_id,
            }],
        };
        let tree_id = repo.write_object(&tree).expect("write tree").detach();
        let commit_id = repo
            .commit(
                "HEAD",
                "initial commit",
                tree_id,
                std::iter::empty::<gix::ObjectId>(),
            )
            .expect("commit")
            .detach();
        (tree_id, commit_id)
    }

    /// Like `commit_single_file`, but also writes the working-tree file and
    /// persists a real `.git/index` built from the committed tree, so the
    /// resulting repository is genuinely clean end-to-end: `HEAD`'s tree,
    /// the index, and the working tree all agree — the real "committed and
    /// unmodified" case, distinct from an empty/unborn repo (which is
    /// trivially "clean" only because there is nothing to compare).
    fn commit_and_index_single_file(
        repo: &gix::Repository,
        repo_dir: &Path,
        filename: &str,
        content: &[u8],
    ) -> gix::ObjectId {
        std::fs::write(repo_dir.join(filename), content).expect("write working-tree file");
        let (tree_id, commit_id) = commit_single_file(repo_dir, filename, content);

        let index_state = gix::index::State::from_tree(&tree_id, &repo.objects, Default::default())
            .expect("build index state from tree");
        let mut index_file =
            gix::index::File::from_state(index_state, repo.git_dir().join("index"));
        index_file
            .write(gix::index::write::Options::default())
            .expect("persist index");

        commit_id
    }

    #[test]
    fn reports_head_commit_after_a_real_commit() {
        let dir = temp_dir();
        gix::init(&dir).expect("gix::init");
        let (_tree_id, commit_id) = commit_single_file(&dir, "claimed.txt", b"hello\n");

        let status = working_tree_status(&dir).expect("query should not error");
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            status.head_commit.as_deref(),
            Some(commit_id.to_string().as_str())
        );
    }

    #[test]
    fn reports_open_failure_for_a_path_discovery_cannot_even_access() {
        // A path that does not exist as a directory at all (as opposed to a
        // real, existing, non-repo directory — see
        // `reports_not_a_repo_for_a_plain_directory` above) is a genuine
        // access failure during discovery, not "searched and found no
        // repository" — must surface as `VcsError::Open`, not be folded
        // into `is_repo: false`.
        let bogus = std::env::temp_dir().join(format!(
            "fornax-vcs-test-does-not-exist-{}",
            uuid::Uuid::new_v4()
        ));

        let result = working_tree_status(&bogus);

        assert!(matches!(result, Err(VcsError::Open(_))), "{result:?}");
    }

    // --- path_status ---------------------------------------------------

    #[test]
    fn path_status_reports_not_a_repo_outside_any_git_repo() {
        let dir = temp_dir();
        let file = dir.join("claimed.txt");
        std::fs::write(&file, "hello\n").expect("write file");

        let status = path_status(&file).expect("query should not error");
        std::fs::remove_dir_all(&dir).ok();

        assert!(!status.is_repo);
        assert!(!status.is_dirty);
    }

    #[test]
    fn path_status_reports_an_untracked_claimed_file_as_dirty() {
        let dir = temp_dir();
        gix::init(&dir).expect("gix::init");
        let file = dir.join("claimed.txt");
        std::fs::write(&file, "hello\n").expect("write file");

        let status = path_status(&file).expect("query should not error");
        std::fs::remove_dir_all(&dir).ok();

        assert!(status.is_repo);
        assert!(status.is_dirty);
    }

    /// The real "clean" case per the task brief: the claimed file is
    /// committed, its index entry matches, and the working-tree copy is
    /// byte-identical — not merely "a repo with nothing in it yet".
    #[test]
    fn path_status_reports_a_committed_unmodified_file_as_clean() {
        let dir = temp_dir();
        let repo = gix::init(&dir).expect("gix::init");
        commit_and_index_single_file(&repo, &dir, "claimed.txt", b"hello\n");
        let file = dir.join("claimed.txt");

        let status = path_status(&file).expect("query should not error");
        std::fs::remove_dir_all(&dir).ok();

        assert!(status.is_repo);
        assert!(status.head_commit.is_some());
        assert!(
            !status.is_dirty,
            "a committed file whose working-tree copy is unmodified must not read as dirty"
        );
    }

    /// A genuinely just-modified tracked file (committed once, then
    /// overwritten on disk without a new commit) must read as dirty — the
    /// positive counterpart to the clean case above, both built from the
    /// same committed-and-indexed starting point.
    #[test]
    fn path_status_reports_a_modified_tracked_file_as_dirty() {
        let dir = temp_dir();
        let repo = gix::init(&dir).expect("gix::init");
        commit_and_index_single_file(&repo, &dir, "claimed.txt", b"hello\n");
        let file = dir.join("claimed.txt");
        std::fs::write(&file, "changed\n").expect("modify working-tree file");

        let status = path_status(&file).expect("query should not error");
        std::fs::remove_dir_all(&dir).ok();

        assert!(status.is_dirty);
    }

    /// Documents an honest boundary of `is_dirty`, rather than leaving it
    /// implicit: a gitignored path that was genuinely just written reports
    /// `false` here too, the same as a real clean file — `git
    /// status --ignored=no`'s own default behavior, which this sensor
    /// inherits rather than overrides. Callers must not read `is_dirty:
    /// false` as "this path is clean" in every sense; see `PathStatus::
    /// is_dirty`'s doc.
    #[test]
    fn path_status_does_not_flag_a_gitignored_file_as_dirty() {
        let dir = temp_dir();
        gix::init(&dir).expect("gix::init");
        std::fs::write(dir.join(".gitignore"), "ignored.txt\n").expect("write .gitignore");
        let file = dir.join("ignored.txt");
        std::fs::write(&file, "hello\n").expect("write ignored file");

        let status = path_status(&file).expect("query should not error");
        std::fs::remove_dir_all(&dir).ok();

        assert!(status.is_repo);
        assert!(!status.is_dirty);
    }
}
