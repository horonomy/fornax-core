//! Calibration provenance schema (FORNX-348, Stage 8 / Active Evidence
//! Intelligence). Computation and comparison live in `fornax-verify`
//! (`calibration.rs` there) -- this module only defines the wire shape,
//! mirroring `reliability_context.rs`'s own split between types and
//! statistics.
//!
//! **Every field here is either directly observable in this codebase
//! today, or explicitly optional and caller-supplied.** Nothing defaults
//! to a fabricated `"unknown"` placeholder — see
//! `fornax-corpus`'s `CandidateCase::context` for the established
//! precedent this follows: `model_version`/`model_family` have no local
//! source anywhere in this workspace (no adapter/sensor observes a model
//! release), so they stay `Option` and are `None` unless a caller
//! explicitly supplies them.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub const CALIBRATION_SCHEMA_VERSION: u32 = 1;

/// Every observable dimension a calibration revision snapshots, and a live
/// assessment re-reads, to decide whether the two still match. Field order
/// is declaration order and is never reordered by a caller — a stable,
/// deterministic comparison order is what makes
/// `CalibrationState::Stale::changed_dimensions` reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationProvenance {
    pub schema_version: u32,
    /// `RuntimeCapabilities::provider`, as its wire tag.
    pub provider: String,
    /// `RuntimeCapabilities::notes["adapter_version"]` — `None` when no
    /// capability announcement for this session/provider carries one
    /// (an honest absence, never a placeholder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_version: Option<String>,
    pub capability_schema_version: u32,
    /// `fornax_types::reliability_context::capability_fingerprint`'s
    /// output, reused verbatim -- never re-derived locally, so this can
    /// never silently disagree with the one true fingerprint computation.
    pub capability_fingerprint: Vec<(String, String)>,
    pub fusion_policy_name: String,
    pub fusion_policy_version: u32,
    pub decision_policy_name: String,
    pub decision_policy_version: u32,
    pub reliability_policy_version: u32,
    /// `SensorDisableConfig::disabled_names()`, sorted -- a *current*
    /// config read, not a standing history. Comparing two snapshots'
    /// disabled-sensor sets is comparing config-at-two-points-in-time, not
    /// diffing a persisted history table (none exists).
    pub disabled_sensors: Vec<String>,
    /// The active policy bundle's revision digest, when one is loaded --
    /// `fornax_types::policy::PolicyRevisionRef::digest`, as its wire
    /// string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_policy_revision_digest: Option<String>,
    /// Caller-supplied only -- no local source observes a model release.
    /// `None` means "not supplied", never "unknown model".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_family: Option<String>,
}

impl CalibrationProvenance {
    /// Sorts `disabled_sensors` and dedupes -- the one piece of this
    /// struct a caller might otherwise hand in unsorted (a `HashSet`
    /// iteration order). Every other field is either a scalar or already
    /// produced in a stable order by its own source function.
    pub fn normalize(mut self) -> Self {
        self.disabled_sensors.sort();
        self.disabled_sensors.dedup();
        self
    }

    /// Builds the sorted list from a real `disabled_names()` set, for
    /// callers that have the `HashSet` rather than an already-sorted
    /// `Vec`.
    pub fn disabled_sensors_from(names: &HashSet<String>) -> Vec<String> {
        let mut v: Vec<String> = names.iter().cloned().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> CalibrationProvenance {
        CalibrationProvenance {
            schema_version: CALIBRATION_SCHEMA_VERSION,
            provider: "claude_code".to_string(),
            adapter_version: Some("claude-adapter-0.3.0".to_string()),
            capability_schema_version: 1,
            capability_fingerprint: vec![("tool_invocation".to_string(), "available".to_string())],
            fusion_policy_name: "deterministic_baseline_v1".to_string(),
            fusion_policy_version: 2,
            decision_policy_name: "default_risk_policy_v1".to_string(),
            decision_policy_version: 1,
            reliability_policy_version: 1,
            disabled_sensors: vec!["sensor_b".to_string(), "sensor_a".to_string()],
            active_policy_revision_digest: None,
            model_version: None,
            model_family: None,
        }
    }

    #[test]
    fn model_version_is_none_unless_explicitly_supplied() {
        let p = provenance();
        assert_eq!(p.model_version, None);
        assert_eq!(p.model_family, None);
    }

    #[test]
    fn normalize_sorts_and_dedupes_disabled_sensors() {
        let mut p = provenance();
        p.disabled_sensors = vec!["b".into(), "a".into(), "a".into()];
        let p = p.normalize();
        assert_eq!(p.disabled_sensors, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn json_round_trips_and_omits_absent_optionals() {
        let p = provenance();
        let json = serde_json::to_value(&p).unwrap();
        assert!(json.get("model_version").is_none());
        assert!(json.get("active_policy_revision_digest").is_none());
        let back: CalibrationProvenance = serde_json::from_value(json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn disabled_sensors_from_a_hash_set_is_sorted() {
        let mut set = HashSet::new();
        set.insert("zeta".to_string());
        set.insert("alpha".to_string());
        assert_eq!(
            CalibrationProvenance::disabled_sensors_from(&set),
            vec!["alpha".to_string(), "zeta".to_string()]
        );
    }
}
