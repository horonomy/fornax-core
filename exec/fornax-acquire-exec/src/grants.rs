//! `ExecutorGrants` -- FORNX-346 Part 2's second, independent deny-by-default
//! gate on top of `fornax_experiment_runner::GlobalExperimentPolicy`
//! (see this crate's own docs and `docs/adr/0022-privileged-acquisition-executor.md`).
//!
//! `GlobalExperimentPolicy` answers "is `ProcessSpawn`/`NetworkCall` granted
//! at all, host-wide". That is necessary but not sufficient for this
//! executor: an operator who grants `ProcessSpawn` still needs to name
//! *which* commands may ever run, and an operator who grants `NetworkCall`
//! still needs to name *which* CI repository may ever be queried. This
//! module is that second gate -- both must independently agree before
//! `RerunTest`/`QueryCiStatus` executes anything; see `crate::rerun`/
//! `crate::ci` for where each is actually enforced.
//!
//! Configured in `$FORNAX_HOME/config.toml`'s own `[acquisition_exec]`
//! table, mirroring `fornax_acquire::containment::AcquisitionRoots`'s
//! `[acquisition]` table and `GlobalExperimentPolicy`'s `[experiment]` table
//! in the same file:
//!
//! ```toml
//! [acquisition_exec]
//! allowed_commands = ["cargo test", "pytest"]     # absent/empty = deny all
//! allowed_ci_repos = ["horonomy/fornax-core"]     # absent/empty = deny all
//! ```
//!
//! A missing file, missing `[acquisition_exec]` table, or missing key
//! resolves to [`ExecutorGrants::default`] -- empty, deny-all -- not an
//! error, matching `AcquisitionRoots::load`/`GlobalExperimentPolicy::load`'s
//! own missing-file handling.
//!
//! # Why `allowed_commands` strings are split into argv at LOAD time only
//!
//! Each `allowed_commands` entry is whitespace-split into an argv prefix
//! **once, here, at config-load time** -- this is trusted operator
//! configuration, entered deliberately into a file only the operator
//! controls. This is the deliberate asymmetry with `crate::rerun`, which
//! never splits a string into argv: an agent-reported command (untrusted,
//! from evidence) is accepted only as an already-structured
//! `serde_json::Value::Array`, never as a string to be shell-split. Splitting
//! *trusted* config strings here and refusing to split *untrusted* evidence
//! strings there is the actual security property -- see `crate::rerun`'s
//! doc comment for the full rationale.

use std::path::{Path, PathBuf};

use fornax_types::sensor_config::SENSOR_CONFIG_FILE;

/// Failure modes for reading/parsing `config.toml`'s `[acquisition_exec]`
/// table. A missing file, table, or key is *not* one of these -- see
/// [`ExecutorGrants::load`].
#[derive(Debug, thiserror::Error)]
pub enum ExecutorGrantsError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path} as TOML: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml_edit::TomlError,
    },
    #[error("{path}: [acquisition_exec].allowed_commands must be an array of command strings")]
    InvalidAllowedCommands { path: PathBuf },
    #[error("{path}: [acquisition_exec].allowed_ci_repos must be an array of repo strings")]
    InvalidAllowedCiRepos { path: PathBuf },
}

/// The operator-approved allowlists this executor gates every `RerunTest`/
/// `QueryCiStatus` attempt against. Empty by default in both dimensions --
/// deny every command and every CI repo until an operator explicitly
/// configures otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutorGrants {
    allowed_commands: Vec<Vec<String>>,
    allowed_ci_repos: Vec<String>,
}

impl ExecutorGrants {
    /// Build from already-parsed argv prefixes and repo slugs (e.g. in a
    /// test).
    pub fn new(allowed_commands: Vec<Vec<String>>, allowed_ci_repos: Vec<String>) -> Self {
        Self {
            allowed_commands,
            allowed_ci_repos,
        }
    }

    fn from_toml_str_with_path(contents: &str, path: &Path) -> Result<Self, ExecutorGrantsError> {
        let doc: toml_edit::DocumentMut =
            contents
                .parse()
                .map_err(|source| ExecutorGrantsError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;

        let Some(section) = doc.get("acquisition_exec") else {
            return Ok(Self::default());
        };

        let allowed_commands = match section.get("allowed_commands") {
            None => Vec::new(),
            Some(item) => {
                let Some(array) = item.as_array() else {
                    return Err(ExecutorGrantsError::InvalidAllowedCommands {
                        path: path.to_path_buf(),
                    });
                };
                let mut out = Vec::with_capacity(array.len());
                for value in array.iter() {
                    let Some(s) = value.as_str() else {
                        return Err(ExecutorGrantsError::InvalidAllowedCommands {
                            path: path.to_path_buf(),
                        });
                    };
                    // Trusted operator config, split into argv here -- see
                    // module docs for why this is never done to
                    // agent-supplied evidence.
                    let argv: Vec<String> = s.split_whitespace().map(String::from).collect();
                    if !argv.is_empty() {
                        out.push(argv);
                    }
                }
                out
            }
        };

        let allowed_ci_repos = match section.get("allowed_ci_repos") {
            None => Vec::new(),
            Some(item) => {
                let Some(array) = item.as_array() else {
                    return Err(ExecutorGrantsError::InvalidAllowedCiRepos {
                        path: path.to_path_buf(),
                    });
                };
                let mut out = Vec::with_capacity(array.len());
                for value in array.iter() {
                    let Some(s) = value.as_str() else {
                        return Err(ExecutorGrantsError::InvalidAllowedCiRepos {
                            path: path.to_path_buf(),
                        });
                    };
                    out.push(s.to_string());
                }
                out
            }
        };

        Ok(Self {
            allowed_commands,
            allowed_ci_repos,
        })
    }

    /// Parses a `config.toml` document already read into memory (e.g. in a
    /// test).
    pub fn from_toml_str(contents: &str) -> Result<Self, ExecutorGrantsError> {
        Self::from_toml_str_with_path(contents, Path::new("<in-memory config.toml>"))
    }

    /// Reads and parses `<fornax_home>/config.toml`'s `[acquisition_exec]`
    /// table. A nonexistent file yields the empty (deny-all) default, not an
    /// error -- matching `AcquisitionRoots::load`/`GlobalExperimentPolicy::load`.
    pub fn load(fornax_home: &Path) -> Result<Self, ExecutorGrantsError> {
        let path = fornax_home.join(SENSOR_CONFIG_FILE);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => return Err(ExecutorGrantsError::Io { path, source }),
        };
        Self::from_toml_str_with_path(&contents, &path)
    }

    /// `true` when `argv` (untrusted -- e.g. derived from agent-reported
    /// evidence) starts with one of the operator-approved command prefixes.
    /// Exact prefix match, in order -- never a substring/fuzzy match.
    pub fn permits_argv(&self, argv: &[String]) -> bool {
        self.allowed_commands
            .iter()
            .any(|allowed| argv.len() >= allowed.len() && argv[..allowed.len()] == allowed[..])
    }

    /// `true` when `repo` (e.g. `"owner/repo"`) is one of the
    /// operator-approved CI repos.
    pub fn permits_repo(&self, repo: &str) -> bool {
        self.allowed_ci_repos.iter().any(|r| r == repo)
    }

    /// Every operator-approved CI repo, in configured order. Empty means
    /// deny every `QueryCiStatus` attempt.
    pub fn ci_repos(&self) -> &[String] {
        &self.allowed_ci_repos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_grants_deny_every_command_and_repo() {
        let grants = ExecutorGrants::default();
        assert!(!grants.permits_argv(&["cargo".to_string(), "test".to_string()]));
        assert!(!grants.permits_repo("horonomy/fornax-core"));
        assert!(grants.ci_repos().is_empty());
    }

    #[test]
    fn missing_acquisition_exec_table_yields_the_empty_default() {
        let grants = ExecutorGrants::from_toml_str("other_key = 1\n").unwrap();
        assert_eq!(grants, ExecutorGrants::default());
    }

    #[test]
    fn an_allowed_command_prefix_permits_a_longer_argv() {
        let grants = ExecutorGrants::from_toml_str(
            "[acquisition_exec]\nallowed_commands = [\"cargo test\"]\n",
        )
        .unwrap();
        assert!(grants.permits_argv(&[
            "cargo".to_string(),
            "test".to_string(),
            "--workspace".to_string()
        ]));
    }

    #[test]
    fn a_command_not_matching_any_prefix_is_denied() {
        let grants = ExecutorGrants::from_toml_str(
            "[acquisition_exec]\nallowed_commands = [\"cargo test\"]\n",
        )
        .unwrap();
        assert!(!grants.permits_argv(&["rm".to_string(), "-rf".to_string(), "/".to_string()]));
    }

    #[test]
    fn a_short_argv_that_only_partially_matches_a_longer_prefix_is_denied() {
        let grants = ExecutorGrants::from_toml_str(
            "[acquisition_exec]\nallowed_commands = [\"cargo test\"]\n",
        )
        .unwrap();
        assert!(!grants.permits_argv(&["cargo".to_string()]));
    }

    #[test]
    fn allowed_ci_repos_are_read_and_matched_exactly() {
        let grants = ExecutorGrants::from_toml_str(
            "[acquisition_exec]\nallowed_ci_repos = [\"horonomy/fornax-core\"]\n",
        )
        .unwrap();
        assert!(grants.permits_repo("horonomy/fornax-core"));
        assert!(!grants.permits_repo("someone-else/fork"));
        assert_eq!(grants.ci_repos(), ["horonomy/fornax-core".to_string()]);
    }

    #[test]
    fn a_non_array_allowed_commands_is_an_error() {
        let err = ExecutorGrants::from_toml_str(
            "[acquisition_exec]\nallowed_commands = \"not-an-array\"\n",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExecutorGrantsError::InvalidAllowedCommands { .. }
        ));
    }

    #[test]
    fn load_with_no_file_present_yields_the_empty_default() {
        let dir = std::env::temp_dir().join(format!(
            "fornax-acquire-exec-grants-test-{}",
            uuid::Uuid::new_v4()
        ));
        let grants = ExecutorGrants::load(&dir).unwrap();
        assert_eq!(grants, ExecutorGrants::default());
    }
}
