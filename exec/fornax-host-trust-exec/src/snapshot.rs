//! Before/after tripwire over the three trust- and credential-bearing
//! files under `~/.codex` (internal-docs ADR-0015 R4/R5's backstop: even
//! though the Seatbelt profile denies writes to these paths by literal
//! name, this snapshot is what actually proves nothing changed, rather
//! than trusting the sandbox profile alone).
//!
//! `auth.json` is a credential file — its contents are never read or
//! hashed here, only filesystem metadata, per the global "never inspect
//! secret plaintext" rule. `hooks.json`/`config.toml` are hashed
//! in-process; the digest is compared, never printed.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {
    pub exists: bool,
    pub sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub exists: bool,
    pub len: Option<u64>,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub hooks_json: FileDigest,
    pub config_toml: FileDigest,
    /// Metadata only -- never the contents of this credential file.
    pub auth_json: FileMetadata,
}

fn digest_of(path: &Path) -> FileDigest {
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&hasher.finalize());
            FileDigest {
                exists: true,
                sha256: Some(out),
            }
        }
        Err(_) => FileDigest {
            exists: false,
            sha256: None,
        },
    }
}

fn metadata_of(path: &Path) -> FileMetadata {
    match std::fs::metadata(path) {
        Ok(m) => FileMetadata {
            exists: true,
            len: Some(m.len()),
            modified: m.modified().ok(),
        },
        Err(_) => FileMetadata {
            exists: false,
            len: None,
            modified: None,
        },
    }
}

impl Snapshot {
    /// `codex_home` is the directory (`~/.codex`, or a test's synthetic
    /// equivalent) holding all three files.
    pub fn take(codex_home: &Path) -> Self {
        Snapshot {
            hooks_json: digest_of(&codex_home.join("hooks.json")),
            config_toml: digest_of(&codex_home.join("config.toml")),
            auth_json: metadata_of(&codex_home.join("auth.json")),
        }
    }
}

/// Every file that changed between two snapshots, by path-relative name.
/// Empty means clean. Never includes file contents.
pub fn diff(before: &Snapshot, after: &Snapshot) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if before.hooks_json != after.hooks_json {
        changed.push("hooks.json");
    }
    if before.config_toml != after.config_toml {
        changed.push("config.toml");
    }
    if before.auth_json != after.auth_json {
        changed.push("auth.json");
    }
    changed
}

/// Convenience for call sites that only need yes/no plus the file list.
pub fn tripwire_tripped(before: &Snapshot, after: &Snapshot) -> Option<Vec<&'static str>> {
    let changed = diff(before, after);
    if changed.is_empty() {
        None
    } else {
        Some(changed)
    }
}

/// Resolves the canonical trust-bearing file paths this crate ever reads
/// or snapshots, for a given `$HOME`-style `.codex` directory. Centralized
/// here so `launch.rs`'s Seatbelt profile, this module's snapshot, and the
/// child process's own `CODEX_HOME` always agree on exactly which
/// directory matters -- the single source of truth for "where is the
/// real Codex home", honoring an operator-set `$CODEX_HOME` override the
/// same way Codex itself does, rather than always assuming `$HOME/.codex`.
/// Without this, an operator with `CODEX_HOME` pointing elsewhere would
/// get Seatbelt deny-write params and a before/after snapshot aimed at
/// the wrong directory while the real spawned `codex` process (which
/// also receives `CODEX_HOME`, see `launch::configure_env`) operated on
/// a different, unprotected one -- caught only after the fact by the
/// `codexHome` cross-check in `main.rs`, not prevented. Canonicalized for
/// the same symlinked-prefix reason `main.rs` canonicalizes `$HOME`
/// (falls back to the raw path if the override doesn't exist yet, so
/// callers that need an existence check still get one downstream).
pub fn codex_home_dir(home: &Path) -> PathBuf {
    if let Ok(over) = std::env::var("CODEX_HOME") {
        if !over.trim().is_empty() {
            let p = PathBuf::from(over);
            return std::fs::canonicalize(&p).unwrap_or(p);
        }
    }
    home.join(".codex")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fht-snapshot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_files_are_not_existing_but_comparable() {
        let dir = scratch();
        let a = Snapshot::take(&dir);
        let b = Snapshot::take(&dir);
        assert!(!a.hooks_json.exists);
        assert_eq!(diff(&a, &b), Vec::<&str>::new());
    }

    #[test]
    fn hooks_json_content_change_is_detected() {
        let dir = scratch();
        std::fs::write(dir.join("hooks.json"), "{}").unwrap();
        let before = Snapshot::take(&dir);
        std::fs::write(dir.join("hooks.json"), "{\"hooks\":{}}").unwrap();
        let after = Snapshot::take(&dir);
        assert_eq!(diff(&before, &after), vec!["hooks.json"]);
    }

    #[test]
    fn identical_rewrite_is_not_flagged() {
        let dir = scratch();
        std::fs::write(dir.join("config.toml"), "a = 1\n").unwrap();
        let before = Snapshot::take(&dir);
        std::fs::write(dir.join("config.toml"), "a = 1\n").unwrap();
        let after = Snapshot::take(&dir);
        assert!(tripwire_tripped(&before, &after).is_none());
    }

    #[test]
    fn auth_json_metadata_change_is_detected_without_reading_contents() {
        let dir = scratch();
        std::fs::write(dir.join("auth.json"), "secret-shaped-but-fake").unwrap();
        let before = Snapshot::take(&dir);
        // Appending changes len even if we never look at the bytes here.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("auth.json"))
            .unwrap();
        use std::io::Write;
        f.write_all(b"-more").unwrap();
        drop(f);
        let after = Snapshot::take(&dir);
        assert_eq!(diff(&before, &after), vec!["auth.json"]);
    }

    #[test]
    fn codex_home_dir_joins_dot_codex() {
        // SAFETY (test-only): this crate's test suite is the only place
        // that ever reads or sets `CODEX_HOME`, so these two tests racing
        // each other is the only hazard, and the saved/restored env var
        // confines the mutation to this test's own duration.
        let saved = std::env::var_os("CODEX_HOME");
        std::env::remove_var("CODEX_HOME");
        let home = Path::new("/home/op");
        assert_eq!(codex_home_dir(home), PathBuf::from("/home/op/.codex"));
        match saved {
            Some(v) => std::env::set_var("CODEX_HOME", v),
            None => std::env::remove_var("CODEX_HOME"),
        }
    }

    #[test]
    fn codex_home_dir_honors_codex_home_override() {
        let saved = std::env::var_os("CODEX_HOME");
        let scratch = scratch();
        std::env::set_var("CODEX_HOME", &scratch);
        let home = Path::new("/home/op");
        // The override wins outright -- `home` (what `$HOME` resolves to)
        // is not joined onto it, matching how Codex itself treats
        // `CODEX_HOME` as an absolute replacement, not a relative one.
        assert_eq!(
            codex_home_dir(home),
            std::fs::canonicalize(&scratch).unwrap()
        );
        match saved {
            Some(v) => std::env::set_var("CODEX_HOME", v),
            None => std::env::remove_var("CODEX_HOME"),
        }
    }
}
