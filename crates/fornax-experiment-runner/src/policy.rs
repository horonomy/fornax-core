//! Global, config-file-gated policy on which [`SideEffectClass`]es this
//! *host* ever grants to an experiment, independent of what any one
//! [`ExperimentSpec`]'s own [`SideEffectAllowList`] asks for (FORNX-99).
//!
//! FORNX-99's `SideEffectAllowList` answers "what does this experiment's
//! author say it's allowed to do". That is necessary but not sufficient for
//! AC2 ("production credentials/network access are absent unless explicitly
//! approved by policy") — a spec author naming `network_call` in their own
//! allow-list must not be enough, on its own, to grant network access. This
//! module is the second, independent gate: [`is_permitted`] requires *both*
//! the spec's allow-list *and* this host-level policy to agree before a
//! [`SideEffectClass`] is actually exercised.
//!
//! Configured via the same `$FORNAX_HOME/config.toml` file
//! [`fornax_types::sensor_config::SensorDisableConfig`] already reads, in
//! its own `[experiment]` section (mirroring that module's `[sensors]`
//! section in the same file rather than inventing a second config file):
//!
//! ```toml
//! [experiment]
//! allowed_side_effects = ["network_call"]
//! ```
//!
//! # Default: worktree mutation only
//!
//! [`GlobalExperimentPolicy::default`] (used whenever `config.toml`, its
//! `[experiment]` table, or its `allowed_side_effects` key is absent)
//! permits only [`SideEffectClass::EphemeralWorktreeMutation`] — the one
//! side effect the isolation mechanism itself depends on to run any
//! experiment at all, confined to a disposable copy the executor discards
//! afterward. `NetworkCall`, `ProcessSpawn`, and
//! `FilesystemWriteOutsideWorktree` are denied by default: a user who has
//! never touched this config gets the basic sandboxed-experiment mechanism
//! working out of the box, with every higher-risk class opt-in only. An
//! explicit `allowed_side_effects = []` in `config.toml` denies even
//! worktree mutation — explicit configuration always wins over the default,
//! never merely widens it.

use std::path::{Path, PathBuf};

use fornax_types::experiment::SideEffectClass;
use fornax_types::sensor_config::SENSOR_CONFIG_FILE;

/// Failure modes for reading/parsing `config.toml`'s `[experiment]` table.
/// A missing file, table, or key is *not* one of these — see
/// [`GlobalExperimentPolicy::load`].
#[derive(Debug, thiserror::Error)]
pub enum ExperimentPolicyError {
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
    /// `[experiment]` exists but `allowed_side_effects` is present and is
    /// not an array of recognized [`SideEffectClass`] names (the same
    /// `snake_case` spelling the wire contract itself serializes to).
    #[error(
        "{path}: [experiment].allowed_side_effects must be an array of known side-effect-class names"
    )]
    InvalidAllowList { path: PathBuf },
}

/// Which [`SideEffectClass`]es this host is willing to ever grant, no matter
/// what an individual [`ExperimentSpec`]'s own allow-list requests. See the
/// module docs for the default and the two-layer gate this composes with
/// via [`is_permitted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalExperimentPolicy(Vec<SideEffectClass>);

impl Default for GlobalExperimentPolicy {
    fn default() -> Self {
        Self(vec![SideEffectClass::EphemeralWorktreeMutation])
    }
}

impl GlobalExperimentPolicy {
    /// Build a policy from an explicit set of globally-permitted classes.
    /// An empty set is a legitimate, fully-deny policy — distinct from
    /// [`Self::default`], which is not empty.
    pub fn new(classes: impl IntoIterator<Item = SideEffectClass>) -> Self {
        let mut v: Vec<SideEffectClass> = classes.into_iter().collect();
        v.sort();
        v.dedup();
        Self(v)
    }

    /// `true` if `class` is granted by this host's global policy. Does not,
    /// on its own, mean an experiment may exercise `class` — see
    /// [`is_permitted`] for the full two-layer check.
    pub fn permits(&self, class: SideEffectClass) -> bool {
        self.0.contains(&class)
    }

    fn from_toml_str_with_path(contents: &str, path: &Path) -> Result<Self, ExperimentPolicyError> {
        let doc: toml_edit::DocumentMut =
            contents
                .parse()
                .map_err(|source| ExperimentPolicyError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;

        let Some(experiment) = doc.get("experiment") else {
            return Ok(Self::default());
        };
        let Some(allow_item) = experiment.get("allowed_side_effects") else {
            return Ok(Self::default());
        };
        let Some(array) = allow_item.as_array() else {
            return Err(ExperimentPolicyError::InvalidAllowList {
                path: path.to_path_buf(),
            });
        };

        let mut classes = Vec::with_capacity(array.len());
        for value in array.iter() {
            let Some(name) = value.as_str() else {
                return Err(ExperimentPolicyError::InvalidAllowList {
                    path: path.to_path_buf(),
                });
            };
            let Some(class) = parse_side_effect_class(name) else {
                return Err(ExperimentPolicyError::InvalidAllowList {
                    path: path.to_path_buf(),
                });
            };
            classes.push(class);
        }
        // Explicit configuration always wins over the default, even an
        // explicit empty list (deny everything, including worktree
        // mutation) — see module docs.
        Ok(Self::new(classes))
    }

    /// Parses a `config.toml` document already read into memory (e.g. in a
    /// test).
    pub fn from_toml_str(contents: &str) -> Result<Self, ExperimentPolicyError> {
        Self::from_toml_str_with_path(contents, Path::new("<in-memory config.toml>"))
    }

    /// Reads and parses `<fornax_home>/config.toml`'s `[experiment]` table.
    /// A nonexistent file yields [`Self::default`], not an error — matching
    /// [`fornax_types::sensor_config::SensorDisableConfig::load`]'s own
    /// missing-file handling.
    pub fn load(fornax_home: &Path) -> Result<Self, ExperimentPolicyError> {
        let path = fornax_home.join(SENSOR_CONFIG_FILE);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => return Err(ExperimentPolicyError::Io { path, source }),
        };
        Self::from_toml_str_with_path(&contents, &path)
    }
}

fn parse_side_effect_class(name: &str) -> Option<SideEffectClass> {
    match name {
        "ephemeral_worktree_mutation" => Some(SideEffectClass::EphemeralWorktreeMutation),
        "process_spawn" => Some(SideEffectClass::ProcessSpawn),
        "network_call" => Some(SideEffectClass::NetworkCall),
        "filesystem_write_outside_worktree" => {
            Some(SideEffectClass::FilesystemWriteOutsideWorktree)
        }
        _ => None,
    }
}

/// The two-layer permission check AC2 requires: `class` is only actually
/// permitted when *both* the experiment's own [`SideEffectAllowList`]
/// (`spec_allow`) and this host's [`GlobalExperimentPolicy`] (`global`)
/// grant it. Either one denying is enough to deny.
pub fn is_permitted(
    spec_allow: &fornax_types::experiment::SideEffectAllowList,
    global: &GlobalExperimentPolicy,
    class: SideEffectClass,
) -> bool {
    spec_allow.permits(class) && global.permits(class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::experiment::SideEffectAllowList;

    #[test]
    fn default_policy_permits_only_ephemeral_worktree_mutation() {
        let policy = GlobalExperimentPolicy::default();
        assert!(policy.permits(SideEffectClass::EphemeralWorktreeMutation));
        for class in [
            SideEffectClass::ProcessSpawn,
            SideEffectClass::NetworkCall,
            SideEffectClass::FilesystemWriteOutsideWorktree,
        ] {
            assert!(!policy.permits(class));
        }
    }

    #[test]
    fn missing_experiment_table_yields_default_policy() {
        let policy = GlobalExperimentPolicy::from_toml_str("other_key = 1\n").unwrap();
        assert_eq!(policy, GlobalExperimentPolicy::default());
    }

    #[test]
    fn missing_allowed_side_effects_key_yields_default_policy() {
        let policy = GlobalExperimentPolicy::from_toml_str("[experiment]\n").unwrap();
        assert_eq!(policy, GlobalExperimentPolicy::default());
    }

    #[test]
    fn explicit_empty_allow_list_denies_even_worktree_mutation() {
        let policy =
            GlobalExperimentPolicy::from_toml_str("[experiment]\nallowed_side_effects = []\n")
                .unwrap();
        assert!(!policy.permits(SideEffectClass::EphemeralWorktreeMutation));
    }

    #[test]
    fn explicit_allow_list_grants_named_classes_only() {
        let policy = GlobalExperimentPolicy::from_toml_str(
            "[experiment]\nallowed_side_effects = [\"network_call\", \"ephemeral_worktree_mutation\"]\n",
        )
        .unwrap();
        assert!(policy.permits(SideEffectClass::NetworkCall));
        assert!(policy.permits(SideEffectClass::EphemeralWorktreeMutation));
        assert!(!policy.permits(SideEffectClass::ProcessSpawn));
    }

    #[test]
    fn unrecognized_side_effect_name_is_an_error() {
        let err = GlobalExperimentPolicy::from_toml_str(
            "[experiment]\nallowed_side_effects = [\"summon_a_dragon\"]\n",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExperimentPolicyError::InvalidAllowList { .. }
        ));
    }

    #[test]
    fn load_with_no_file_present_yields_default_policy() {
        let dir = std::env::temp_dir().join(format!(
            "fornax-experiment-policy-test-{}",
            uuid::Uuid::new_v4()
        ));
        let policy = GlobalExperimentPolicy::load(&dir).unwrap();
        assert_eq!(policy, GlobalExperimentPolicy::default());
    }

    // --- AC2: two-layer gate -------------------------------------------

    #[test]
    fn network_call_named_in_spec_allow_list_is_still_denied_without_global_grant() {
        let spec_allow = SideEffectAllowList::new([SideEffectClass::NetworkCall]);
        let global = GlobalExperimentPolicy::default(); // does not grant NetworkCall
        assert!(!is_permitted(
            &spec_allow,
            &global,
            SideEffectClass::NetworkCall
        ));
    }

    #[test]
    fn network_call_is_permitted_only_when_both_layers_grant_it() {
        let spec_allow = SideEffectAllowList::new([SideEffectClass::NetworkCall]);
        let global = GlobalExperimentPolicy::new([SideEffectClass::NetworkCall]);
        assert!(is_permitted(
            &spec_allow,
            &global,
            SideEffectClass::NetworkCall
        ));
    }

    #[test]
    fn global_grant_alone_is_not_enough_without_spec_allow_list() {
        let spec_allow = SideEffectAllowList::default(); // deny-by-default, names nothing
        let global = GlobalExperimentPolicy::new([SideEffectClass::NetworkCall]);
        assert!(!is_permitted(
            &spec_allow,
            &global,
            SideEffectClass::NetworkCall
        ));
    }
}
