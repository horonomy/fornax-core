//! Maps today's env-var/config.toml gates into the `LocalUser` policy layer
//! (FORNX-116 AC5).
//!
//! **The exact place AC5 breaks.** Today's code is `unwrap_or(false)`. If
//! this layer wrote `Some(false)` when `FORNAX_CLOUD_SYNC_ENABLED` is
//! *unset*, `LocalUser` (the most specific level) would become the layer
//! that sets the field and would permanently defeat every published policy
//! — an org publishing `cloud_sync_allowed = true` would never take effect
//! for a user who never touched the env var. `None` (this layer has no
//! opinion) is the only value that preserves "an org policy can turn this
//! on" — see `parse_bool_gate`'s doc.
//!
//! **Mid-session flip ownership.** `crate::privacy`'s doc comment commits to
//! the cloud-sync gate being checked *before every network call*, so a user
//! can disable sync mid-session. A cached [`crate::policy::ResolvedPolicy`]
//! would silently kill that. Ownership is split: published layers are
//! cached (a future caching ticket owns invalidation); **this layer is
//! re-read from the environment on every evaluation** — see
//! [`local_user_layer`]. An env read is cheap; this preserves the existing
//! guarantee without depending on that caching ticket shipping first.
//!
//! **Split for testability.** [`local_user_layer_from_values`] is the pure
//! mapping core — no environment or filesystem access — so tests exercise
//! it directly with zero risk of racing `std::env::set_var` across
//! parallel test threads (see `crate::privacy`'s own tests, which document
//! exactly this race and consolidate into one test per gate for it).
//! [`local_user_layer`] is the thin, real-environment wrapper.

use super::content::{CollectionScope, EgressScope, PolicyContent, SensorScope};
use super::diagnostics::{DiagnosticCode, DiagnosticSeverity, PolicyDiagnostic};
use crate::sensor_config::SensorDisableConfig;

/// `"1"`/`"true"` (case-insensitive) enable; unset means "no opinion"
/// (`None`); anything else is treated as `Some(false)` plus a Warning — this
/// preserves today's "only 1/true enable" behavior verbatim (see
/// `crate::privacy::cloud_sync_allowed`) and can only ever *tighten*
/// relative to what an env-var typo might have intended, never loosen it.
/// `None` for the unset case specifically is what lets an org policy's
/// `Some(true)` take effect for a user who never touched the variable — see
/// this module's doc comment.
fn parse_bool_gate(
    raw: Option<&str>,
    env_var_name: &str,
) -> (Option<bool>, Option<PolicyDiagnostic>) {
    match raw {
        None => (None, None),
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => (Some(true), None),
        Some(other) => (
            Some(false),
            Some(PolicyDiagnostic::new(
                DiagnosticCode::UnrecognizedEnvValue,
                DiagnosticSeverity::Warning,
                format!("{env_var_name}={other:?} is not \"1\" or \"true\"; treating as disabled"),
                "set the variable to \"1\" or \"true\" to enable it, or unset it entirely",
            )),
        ),
    }
}

/// Pure mapping core — no environment or filesystem access. See module
/// docs.
pub fn local_user_layer_from_values(
    cloud_sync_env: Option<&str>,
    longitudinal_env: Option<&str>,
    sensor_config: &SensorDisableConfig,
) -> (PolicyContent, Vec<PolicyDiagnostic>) {
    let mut diagnostics = Vec::new();

    let (cloud_sync_allowed, cloud_sync_warning) =
        parse_bool_gate(cloud_sync_env, "FORNAX_CLOUD_SYNC_ENABLED");
    if let Some(d) = cloud_sync_warning {
        diagnostics.push(d);
    }

    let (longitudinal_aggregation_allowed, longitudinal_warning) =
        parse_bool_gate(longitudinal_env, "FORNAX_LONGITUDINAL_COLLECTION_ENABLED");
    if let Some(d) = longitudinal_warning {
        diagnostics.push(d);
    }

    // `None` here, not `Some(empty)`, whenever the config file/table/key was
    // never present — see `SensorDisableConfig::disabled_names`'s doc for
    // why the two are safely indistinguishable for this specific field.
    let disabled = sensor_config.disabled_names();
    let sensors_disabled = if disabled.is_empty() {
        None
    } else {
        Some(disabled.iter().cloned().collect())
    };

    let content = PolicyContent {
        collection: CollectionScope {
            longitudinal_aggregation_allowed,
        },
        egress: EgressScope {
            cloud_sync_allowed,
            redaction_profile: None,
            allowed_content: None,
        },
        sensors: SensorScope {
            disabled: sensors_disabled,
            required_signals: None,
        },
        enforcement: Default::default(),
        cache: Default::default(),
    };

    (content, diagnostics)
}

/// Real-environment wrapper around [`local_user_layer_from_values`]: reads
/// `FORNAX_CLOUD_SYNC_ENABLED`/`FORNAX_LONGITUDINAL_COLLECTION_ENABLED` from
/// the process environment and `config.toml`'s `[sensors].disabled` from
/// `home` (see `crate::sensor_config::SensorDisableConfig::load`, collapsed
/// to empty on any read error — a one-shot evaluation must never fail
/// outright over a config-file problem, matching
/// `SensorDisableConfig::load_default`'s own precedent).
pub fn local_user_layer(home: &std::path::Path) -> (PolicyContent, Vec<PolicyDiagnostic>) {
    let cloud_sync_env = std::env::var("FORNAX_CLOUD_SYNC_ENABLED").ok();
    let longitudinal_env = std::env::var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED").ok();
    let sensor_config =
        SensorDisableConfig::load(home).unwrap_or_else(|_| SensorDisableConfig::empty());
    local_user_layer_from_values(
        cloud_sync_env.as_deref(),
        longitudinal_env.as_deref(),
        &sensor_config,
    )
}
