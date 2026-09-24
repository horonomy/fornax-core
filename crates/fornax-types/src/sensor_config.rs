//! Per-sensor disable configuration (FORNX-302 sub-item 3, split off
//! FORNX-91's unmet "sensors are individually disableable for privacy/
//! performance reasons" AC).
//!
//! A user names a sensor to turn off by its stable [`crate::EvidenceSensor::name`]
//! identifier, in a small TOML file:
//!
//! ```toml
//! [sensors]
//! disabled = ["claude_file_write_confirmed_sensor_v1"]
//! ```
//!
//! at `$FORNAX_HOME/config.toml` — reusing the `$FORNAX_HOME` convention
//! `fornax-cli` already uses for `fornax.db` (`crates/fornax-cli/src/main.rs`),
//! rather than inventing a second home-directory convention. Live here in
//! `fornax-types`, not duplicated per adapter crate, because every adapter
//! crate already depends on `fornax-types` and nothing else
//! (`docs/contributing/adding-an-adapter.md`'s "Allowed core dependencies"),
//! so this is the one place the check can live without adapters taking on a
//! second Fornax-crate dependency.
//!
//! A disabled sensor must never be silently skipped — see
//! [`crate::SensorOutcome::disabled`] and [`crate::collect_with_disable_check`],
//! which report [`crate::SignalAvailability::Disabled`] explicitly instead of
//! producing no evidence with no explanation.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The config file's name, relative to `$FORNAX_HOME`.
pub const SENSOR_CONFIG_FILE: &str = "config.toml";

/// Failure modes for reading/parsing `config.toml`. A missing file is *not*
/// one of these — see [`SensorDisableConfig::load`].
#[derive(Debug, thiserror::Error)]
pub enum SensorConfigError {
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
    /// `[sensors]` exists but `disabled` is present and not an array of
    /// strings. A missing `[sensors]` table or missing `disabled` key is
    /// not an error — see [`SensorDisableConfig::from_toml_str`].
    #[error("{path}: [sensors].disabled must be an array of strings")]
    InvalidDisabledList { path: PathBuf },
}

/// Which named sensors are turned off. Constructed via [`Self::load`]
/// (reads `$FORNAX_HOME/config.toml`) or [`Self::from_toml_str`] (parses an
/// in-memory TOML document, e.g. from a test). Absence — no file, no
/// `[sensors]` table, no `disabled` key — always means "nothing disabled",
/// never an error: a user who has never touched sensor config gets every
/// sensor running, exactly as before this feature existed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SensorDisableConfig {
    disabled: HashSet<String>,
}

impl SensorDisableConfig {
    /// Nothing disabled — the default when no config file exists.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parses a `config.toml` document already read into memory. `path` is
    /// used only to make [`SensorConfigError`] messages point at a real
    /// file when called from [`Self::load`]; pass any placeholder when
    /// parsing an in-memory string directly (e.g. in a test).
    fn from_toml_str_with_path(contents: &str, path: &Path) -> Result<Self, SensorConfigError> {
        let doc: toml_edit::DocumentMut =
            contents
                .parse()
                .map_err(|source| SensorConfigError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;

        let Some(sensors) = doc.get("sensors") else {
            return Ok(Self::empty());
        };
        let Some(disabled_item) = sensors.get("disabled") else {
            return Ok(Self::empty());
        };
        let Some(array) = disabled_item.as_array() else {
            return Err(SensorConfigError::InvalidDisabledList {
                path: path.to_path_buf(),
            });
        };

        let mut disabled = HashSet::with_capacity(array.len());
        for value in array.iter() {
            let Some(name) = value.as_str() else {
                return Err(SensorConfigError::InvalidDisabledList {
                    path: path.to_path_buf(),
                });
            };
            disabled.insert(name.to_string());
        }
        Ok(Self { disabled })
    }

    /// Parses a `config.toml` document already read into memory (e.g. in a
    /// test, or by a caller that already has the contents).
    pub fn from_toml_str(contents: &str) -> Result<Self, SensorConfigError> {
        Self::from_toml_str_with_path(contents, Path::new("<in-memory config.toml>"))
    }

    /// Reads and parses `<fornax_home>/config.toml`. A nonexistent file
    /// yields [`Self::empty`] (nothing disabled), not an error — most users
    /// never create this file. Any other I/O failure, or a `disabled` key
    /// that isn't an array of strings, is a real [`SensorConfigError`].
    pub fn load(fornax_home: &Path) -> Result<Self, SensorConfigError> {
        let path = fornax_home.join(SENSOR_CONFIG_FILE);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(source) => return Err(SensorConfigError::Io { path, source }),
        };
        Self::from_toml_str_with_path(&contents, &path)
    }

    /// [`Self::load`] against the same `$FORNAX_HOME` resolution
    /// `fornax-cli` uses (`$FORNAX_HOME` env var, else `$HOME/.fornax`),
    /// collapsing any error (missing `$HOME`, malformed TOML, wrong-typed
    /// `disabled` key) to [`Self::empty`] — a one-shot hook adapter process
    /// must never fail evidence collection outright over a config-file
    /// problem it can't surface to a human synchronously. Prefer
    /// [`Self::load`] directly when the caller can report a
    /// [`SensorConfigError`] (e.g. a future `fornax config` CLI command).
    pub fn load_default() -> Self {
        Self::load(&default_fornax_home()).unwrap_or_else(|_| Self::empty())
    }

    /// True only if `sensor_name` is named in the `disabled` list. Absence
    /// (including an empty config) is always "not disabled" — see the
    /// module docs.
    pub fn is_disabled(&self, sensor_name: &str) -> bool {
        self.disabled.contains(sensor_name)
    }

    /// The full set of disabled sensor names (FORNX-116: the policy-as-data
    /// `LocalUser` layer maps this into `policy::SensorScope::disabled`).
    /// Empty and "never configured" are indistinguishable here by design —
    /// see the module docs — which is safe for that mapping because
    /// `SensorScope::disabled`'s precedence meet is union: an empty set
    /// folded into any other level's set is a no-op either way.
    pub fn disabled_names(&self) -> &HashSet<String> {
        &self.disabled
    }
}

/// `$FORNAX_HOME` if set, else `$HOME/.fornax` — the same resolution
/// `fornax-cli`'s `fornax_home()` uses for `fornax.db`
/// (`crates/fornax-cli/src/main.rs`). Falls back to `.fornax` (relative to
/// the current directory) if `$HOME` is also unset, matching that
/// function's own fallback.
pub fn default_fornax_home() -> PathBuf {
    std::env::var("FORNAX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|home| PathBuf::from(home).join(".fornax"))
                .unwrap_or_else(|_| PathBuf::from(".fornax"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_disables_nothing() {
        let cfg = SensorDisableConfig::empty();
        assert!(!cfg.is_disabled("anything"));
    }

    #[test]
    fn missing_sensors_table_disables_nothing() {
        let cfg = SensorDisableConfig::from_toml_str("other_key = 1\n").unwrap();
        assert!(!cfg.is_disabled("claude_file_write_confirmed_sensor_v1"));
    }

    #[test]
    fn missing_disabled_key_disables_nothing() {
        let cfg = SensorDisableConfig::from_toml_str("[sensors]\n").unwrap();
        assert!(!cfg.is_disabled("claude_file_write_confirmed_sensor_v1"));
    }

    #[test]
    fn named_sensor_is_disabled_others_are_not() {
        let cfg = SensorDisableConfig::from_toml_str(
            "[sensors]\ndisabled = [\"claude_file_write_confirmed_sensor_v1\", \"opencode_command_duration_sensor_v1\"]\n",
        )
        .unwrap();
        assert!(cfg.is_disabled("claude_file_write_confirmed_sensor_v1"));
        assert!(cfg.is_disabled("opencode_command_duration_sensor_v1"));
        assert!(!cfg.is_disabled("claude_bash_exit_code_sensor_v1"));
    }

    #[test]
    fn non_string_entry_in_disabled_array_is_an_error() {
        let err = SensorDisableConfig::from_toml_str("[sensors]\ndisabled = [1, 2]\n").unwrap_err();
        assert!(matches!(err, SensorConfigError::InvalidDisabledList { .. }));
    }

    #[test]
    fn disabled_key_that_is_not_an_array_is_an_error() {
        let err = SensorDisableConfig::from_toml_str("[sensors]\ndisabled = \"not-an-array\"\n")
            .unwrap_err();
        assert!(matches!(err, SensorConfigError::InvalidDisabledList { .. }));
    }

    #[test]
    fn malformed_toml_is_a_parse_error() {
        let err = SensorDisableConfig::from_toml_str("this is not [ valid toml").unwrap_err();
        assert!(matches!(err, SensorConfigError::Parse { .. }));
    }

    #[test]
    fn load_with_no_file_present_yields_empty_config() {
        let dir = std::env::temp_dir().join(format!(
            "fornax-sensor-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        // Deliberately not created — `load` must treat a missing directory
        // the same as a missing file.
        let cfg = SensorDisableConfig::load(&dir).unwrap();
        assert!(!cfg.is_disabled("claude_file_write_confirmed_sensor_v1"));
    }

    #[test]
    fn load_round_trips_a_real_file_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "fornax-sensor-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(SENSOR_CONFIG_FILE),
            "[sensors]\ndisabled = [\"claude_bash_exit_code_sensor_v1\"]\n",
        )
        .unwrap();

        let cfg = SensorDisableConfig::load(&dir).unwrap();
        assert!(cfg.is_disabled("claude_bash_exit_code_sensor_v1"));
        assert!(!cfg.is_disabled("claude_file_write_confirmed_sensor_v1"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_default_never_panics_and_falls_back_to_empty_on_any_error() {
        // No assertion on FORNAX_HOME/HOME here (this test must not mutate
        // process-global env vars shared with other tests) — the contract
        // under test is just "never panics, always returns something".
        let _ = SensorDisableConfig::load_default();
    }
}
