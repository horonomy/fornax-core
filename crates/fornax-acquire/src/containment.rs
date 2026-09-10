//! Filesystem containment for acquisition targets.
//!
//! `fornax_types::FileDiffPayload::path` is agent-reported and untrusted by
//! construction — distrusting the agent's own self-report is the entire
//! premise of Fornax (see `fornax-adapter-claude`'s `ClaudeGitOutcomeSensor`,
//! which reads this field straight out of `tool_response`/`tool_input`
//! JSON with no validation at collection time). Nothing in this repository
//! today tracks a trusted "session repo root", so this module does not
//! invent one: an operator must explicitly configure which real directories
//! `fornax evidence-acquire` may ever read from, in `$FORNAX_HOME/config.toml`'s
//! `[acquisition]` table, mirroring `fornax_experiment_runner::GlobalExperimentPolicy`'s
//! own `[experiment]` table in the same file. No configured root -- the
//! default -- means every acquisition target is refused, matching this
//! workspace's deny-by-default posture everywhere else.
//!
//! ```toml
//! [acquisition]
//! allowed_roots = ["/Users/me/project"]
//! ```
//!
//! The containment check itself mirrors
//! `fornax_experiment_runner::staging::StagedWorktree::resolve_contained`'s
//! canonicalize-then-`starts_with` pattern (same reason: a nonexistent
//! target file has no canonical form yet, so its parent directory is
//! checked instead), applied here against a real, operator-configured root
//! rather than an ephemeral staged copy.

use std::path::{Path, PathBuf};

use fornax_types::sensor_config::SENSOR_CONFIG_FILE;

/// Everything that can go wrong resolving an acquisition target.
#[derive(Debug, thiserror::Error)]
pub enum ContainmentError {
    #[error("no acquisition root is configured -- every target is refused by default")]
    NoRootsConfigured,
    /// Refused outright, never silently clamped -- this is the actual
    /// enforcement of "an attacker-controlled path cannot read/hash
    /// anything outside an operator-approved directory".
    #[error("target '{requested}' does not resolve inside any configured acquisition root")]
    Escapes { requested: String },
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml_edit::TomlError,
    },
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// `[acquisition]` exists but `allowed_roots` is present and is not an
    /// array of strings.
    #[error("{path}: [acquisition].allowed_roots must be an array of path strings")]
    InvalidRoots { path: PathBuf },
}

/// The operator-approved set of real directories acquisition targets may
/// resolve inside. Empty by default -- deny every target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcquisitionRoots {
    roots: Vec<PathBuf>,
}

impl AcquisitionRoots {
    /// Build from an explicit set of root directories (e.g. in a test).
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> Self {
        Self {
            roots: roots.into_iter().collect(),
        }
    }

    fn from_toml_str_with_path(contents: &str, path: &Path) -> Result<Self, ContainmentError> {
        let doc: toml_edit::DocumentMut =
            contents.parse().map_err(|source| ContainmentError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        let Some(acquisition) = doc.get("acquisition") else {
            return Ok(Self::default());
        };
        let Some(item) = acquisition.get("allowed_roots") else {
            return Ok(Self::default());
        };
        let Some(array) = item.as_array() else {
            return Err(ContainmentError::InvalidRoots {
                path: path.to_path_buf(),
            });
        };
        let mut roots = Vec::with_capacity(array.len());
        for value in array.iter() {
            let Some(s) = value.as_str() else {
                return Err(ContainmentError::InvalidRoots {
                    path: path.to_path_buf(),
                });
            };
            roots.push(PathBuf::from(s));
        }
        Ok(Self { roots })
    }

    /// Parses a `config.toml` document already read into memory (e.g. in a
    /// test).
    pub fn from_toml_str(contents: &str) -> Result<Self, ContainmentError> {
        Self::from_toml_str_with_path(contents, Path::new("<in-memory config.toml>"))
    }

    /// Reads and parses `<fornax_home>/config.toml`'s `[acquisition]`
    /// table. A nonexistent file yields the empty (deny-all) default, not
    /// an error -- matching `GlobalExperimentPolicy::load`'s own
    /// missing-file handling.
    pub fn load(fornax_home: &Path) -> Result<Self, ContainmentError> {
        let path = fornax_home.join(SENSOR_CONFIG_FILE);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => return Err(ContainmentError::Io { path, source }),
        };
        Self::from_toml_str_with_path(&contents, &path)
    }

    /// Resolve `requested` (as reported in evidence -- untrusted, may be
    /// absolute, relative, `..`-laden, or symlink-laden) against every
    /// configured root and refuse it unless it genuinely resolves inside
    /// one. Tries each root in configured order and returns the first
    /// containing resolution; refuses (never clamps) if none contain it.
    pub fn resolve_contained(&self, requested: &str) -> Result<PathBuf, ContainmentError> {
        if self.roots.is_empty() {
            return Err(ContainmentError::NoRootsConfigured);
        }
        let requested_path = Path::new(requested);
        for root in &self.roots {
            let Ok(root_canon) = root.canonicalize() else {
                continue;
            };
            let candidate = if requested_path.is_absolute() {
                requested_path.to_path_buf()
            } else {
                root.join(requested_path)
            };
            let check_path: PathBuf = if candidate.exists() {
                candidate.clone()
            } else {
                match candidate.parent() {
                    Some(parent) => parent.to_path_buf(),
                    None => continue,
                }
            };
            let Ok(canon) = check_path.canonicalize() else {
                continue;
            };
            if canon.starts_with(&root_canon) {
                return Ok(candidate);
            }
        }
        Err(ContainmentError::Escapes {
            requested: requested.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "fornax-acquire-containment-test-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn no_roots_configured_refuses_every_target() {
        let roots = AcquisitionRoots::default();
        assert!(matches!(
            roots.resolve_contained("anything.txt"),
            Err(ContainmentError::NoRootsConfigured)
        ));
    }

    #[test]
    fn a_relative_path_inside_the_root_is_contained() {
        let root = temp_root("inside");
        std::fs::write(root.join("claimed.txt"), b"x").unwrap();
        let roots = AcquisitionRoots::new([root.clone()]);
        let resolved = roots.resolve_contained("claimed.txt").unwrap();
        assert_eq!(resolved, root.join("claimed.txt"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_traversal_escape_is_refused() {
        let root = temp_root("traversal-root");
        let roots = AcquisitionRoots::new([root.clone()]);
        let err = roots.resolve_contained("../../etc/passwd").unwrap_err();
        assert!(matches!(err, ContainmentError::Escapes { .. }));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_absolute_path_outside_every_root_is_refused() {
        let root = temp_root("absolute-root");
        let roots = AcquisitionRoots::new([root.clone()]);
        let err = roots.resolve_contained("/etc/passwd").unwrap_err();
        assert!(matches!(err, ContainmentError::Escapes { .. }));
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_escape_is_refused() {
        let root = temp_root("symlink-root");
        let outside = temp_root("symlink-outside");
        std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let roots = AcquisitionRoots::new([root.clone()]);
        let err = roots.resolve_contained("escape/secret.txt").unwrap_err();
        assert!(matches!(err, ContainmentError::Escapes { .. }));
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn from_toml_str_reads_allowed_roots() {
        let roots = AcquisitionRoots::from_toml_str(
            "[acquisition]\nallowed_roots = [\"/tmp/a\", \"/tmp/b\"]\n",
        )
        .unwrap();
        assert_eq!(
            roots,
            AcquisitionRoots::new([PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")])
        );
    }

    #[test]
    fn a_missing_acquisition_table_yields_the_empty_default() {
        let roots = AcquisitionRoots::from_toml_str("other_key = 1\n").unwrap();
        assert_eq!(roots, AcquisitionRoots::default());
    }

    #[test]
    fn a_non_array_allowed_roots_is_an_error() {
        let err =
            AcquisitionRoots::from_toml_str("[acquisition]\nallowed_roots = \"not-an-array\"\n")
                .unwrap_err();
        assert!(matches!(err, ContainmentError::InvalidRoots { .. }));
    }
}
