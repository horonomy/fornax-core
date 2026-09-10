//! Calibration validity assessment (FORNX-348, parent epic FORNX-20 /
//! discovery thesis HVDL-15).
//!
//! [`fornax_types::calibration::CalibrationProvenance`] defines what a
//! calibration revision snapshots. This module is the first place that
//! snapshot is actually compared against a live read to decide whether a
//! prior calibration still applies — [`assess_calibration`] is pure (no
//! I/O, no clock read), mirroring [`crate::reliability::compute_reliability`]
//! and [`crate::reliability::detect_drift`], which it reuses rather than
//! reimplements for the drift half of this decision.
//!
//! # Two independent triggers, not one
//!
//! A calibration can go bad two different ways, and conflating them would
//! hide which one actually happened:
//!
//! - **Stale**: the *environment* changed — a different adapter version, a
//!   different fusion/decision policy, a sensor got disabled — so the
//!   revision's provenance no longer matches what's running now. This is a
//!   pure equality check over [`fornax_types::calibration::CalibrationProvenance`]
//!   and needs zero historical observations to detect. It is never gated
//!   by [`crate::reliability::ReliabilityAggregationConfig::historical_aggregation_enabled`]
//!   — a provenance mismatch is true regardless of whether the aggregation
//!   feature is on.
//! - **Suspect**: the *statistics* changed — [`crate::reliability::detect_drift`]
//!   reports [`crate::reliability::DriftState::Drifted`] between the
//!   revision's baseline cohort and a live comparison cohort, even though
//!   provenance still matches. This consumes the exact observation corpus
//!   `historical_aggregation_enabled` governs, so it IS gated by that flag
//!   — with it off, this module never reports `Suspect`, only `Valid` or
//!   `Stale`.
//!
//! # Why this never touches `fuse()`
//!
//! [`crate::fusion::BaselineFusionPolicy::fuse`] must stay pure over frozen
//! evidence input for [`fornax_replay`]'s byte-identical-replay guarantee
//! (FORNX-98 AC1; ADR-0001's immutable-observation-before-interpretation
//! invariant). A calibration state is a live-environment judgment, not a
//! property of the evidence being replayed — it must never change what a
//! historical replay of the same evidence produces. [`assess_calibration`]
//! and [`crate::decision::apply_calibration_floor`] (this ticket's
//! decision-layer counterpart) are the only places calibration ever
//! participates in the pipeline, both strictly downstream of `fuse()`. See
//! ADR-0018.

use serde::{Deserialize, Serialize};

use crate::reliability::{DriftAssessment, DriftState};
use fornax_types::calibration::CalibrationProvenance;
use fornax_types::SampleSupport;

pub const CALIBRATION_POLICY_VERSION: u32 = 1;

/// Closed calibration vocabulary. `NoActiveCalibration` is distinct from
/// `Valid` — no revision has ever been recorded yet, versus one was
/// recorded and still matches. A caller must not collapse the two: the
/// former has nothing to apply a floor against, the latter has actively
/// confirmed agreement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationState {
    /// No active calibration revision has been recorded at all.
    NoActiveCalibration,
    /// Live provenance matches the active revision's provenance
    /// (and, when drift comparison ran, showed no drift).
    Valid,
    /// Live provenance disagrees with the active revision's provenance on
    /// at least one dimension — named explicitly, never left implicit.
    Stale { changed_dimensions: Vec<String> },
    /// Provenance still matches, but the observation corpus itself shows a
    /// statistically meaningful reliability change since the revision was
    /// recorded. Only reachable when historical aggregation is enabled.
    Suspect { drift_state: DriftState },
    /// Provenance matches, but there isn't enough observation support on
    /// one side of the drift comparison to say anything at all — distinct
    /// from `Valid` (which asserts agreement) and from `Suspect` (which
    /// asserts a detected change).
    InsufficientSupport { sample_support: SampleSupport },
}

/// Output of [`assess_calibration`] — the decided state plus the inputs it
/// was computed from, so a caller can render *why* without recomputing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationAssessment {
    pub state: CalibrationState,
    pub policy_version: u32,
}

/// Every dimension whose disagreement makes a calibration `Stale`, named
/// explicitly rather than left as a single boolean. Field order matches
/// [`CalibrationProvenance`]'s declaration order for a stable,
/// reproducible `changed_dimensions` list.
pub fn changed_dimensions(
    active: &CalibrationProvenance,
    live: &CalibrationProvenance,
) -> Vec<String> {
    let mut changed = Vec::new();
    if active.provider != live.provider {
        changed.push("provider".to_string());
    }
    if active.adapter_version != live.adapter_version {
        changed.push("adapter_version".to_string());
    }
    if active.capability_schema_version != live.capability_schema_version {
        changed.push("capability_schema_version".to_string());
    }
    if active.capability_fingerprint != live.capability_fingerprint {
        changed.push("capability_fingerprint".to_string());
    }
    if active.fusion_policy_name != live.fusion_policy_name
        || active.fusion_policy_version != live.fusion_policy_version
    {
        changed.push("fusion_policy".to_string());
    }
    if active.decision_policy_name != live.decision_policy_name
        || active.decision_policy_version != live.decision_policy_version
    {
        changed.push("decision_policy".to_string());
    }
    if active.reliability_policy_version != live.reliability_policy_version {
        changed.push("reliability_policy_version".to_string());
    }
    if active.disabled_sensors != live.disabled_sensors {
        changed.push("disabled_sensors".to_string());
    }
    if active.active_policy_revision_digest != live.active_policy_revision_digest {
        changed.push("active_policy_revision_digest".to_string());
    }
    if active.model_version != live.model_version {
        changed.push("model_version".to_string());
    }
    if active.model_family != live.model_family {
        changed.push("model_family".to_string());
    }
    changed
}

/// Decide the [`CalibrationState`] for one active revision against a live
/// provenance read. Pure — no I/O, no clock read.
///
/// `drift` is `None` whenever the caller has no comparison cohort to run
/// (including whenever `historical_aggregation_enabled` is false — a
/// caller should not even attempt [`crate::reliability::detect_drift`] in
/// that case). When `drift` is `Some`, its `drift_state` is only consulted
/// if `historical_aggregation_enabled` is true and provenance already
/// matches — a stale provenance is reported as `Stale` regardless of what
/// the drift comparison says, since a provenance mismatch already means
/// the two cohorts are not the same logical calibration.
pub fn assess_calibration(
    active: Option<&CalibrationProvenance>,
    live: &CalibrationProvenance,
    drift: Option<&DriftAssessment>,
    historical_aggregation_enabled: bool,
) -> CalibrationAssessment {
    let state = match active {
        None => CalibrationState::NoActiveCalibration,
        Some(active) => {
            let changed = changed_dimensions(active, live);
            if !changed.is_empty() {
                CalibrationState::Stale {
                    changed_dimensions: changed,
                }
            } else if !historical_aggregation_enabled {
                CalibrationState::Valid
            } else {
                match drift {
                    None => CalibrationState::Valid,
                    Some(assessment) => match &assessment.drift_state {
                        DriftState::Stable => CalibrationState::Valid,
                        // Not a drift comparison at all (differing
                        // non-version dimensions) -- provenance already
                        // matched above, so this arm is defensive, not
                        // expected to fire in practice.
                        DriftState::NotComparable { .. } => CalibrationState::Valid,
                        DriftState::Drifted => CalibrationState::Suspect {
                            drift_state: assessment.drift_state.clone(),
                        },
                        DriftState::InsufficientDataForComparison => {
                            CalibrationState::InsufficientSupport {
                                sample_support: assessment.comparison_signal.sample_support,
                            }
                        }
                    },
                }
            }
        }
    };
    CalibrationAssessment {
        state,
        policy_version: CALIBRATION_POLICY_VERSION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reliability::{ConfidenceInterval, ReliabilityEstimate, ReliabilitySignal};
    use fornax_types::{
        aggregate_context, CapabilitySignal, ModelFamily, RawReliabilityContext,
        RawRepositoryContext, ReliabilityContextKey, RepositoryClass, RuntimeCapabilities,
        SignalAvailability, SignalClass, TaskClass, ToolClass,
    };
    use std::collections::HashMap;

    fn caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: fornax_types::Provider::ClaudeCode,
            signals: vec![CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: HashMap::new(),
        }
    }

    fn provenance() -> CalibrationProvenance {
        CalibrationProvenance {
            schema_version: 1,
            provider: "claude_code".to_string(),
            adapter_version: Some("claude-adapter-0.3.0".to_string()),
            capability_schema_version: 1,
            capability_fingerprint: vec![("tool_invocation".to_string(), "available".to_string())],
            fusion_policy_name: "deterministic_baseline_v1".to_string(),
            fusion_policy_version: 2,
            decision_policy_name: "default_risk_policy_v1".to_string(),
            decision_policy_version: 1,
            reliability_policy_version: 1,
            disabled_sensors: vec![],
            active_policy_revision_digest: None,
            model_version: None,
            model_family: None,
        }
    }

    fn context_key() -> ReliabilityContextKey {
        aggregate_context(RawReliabilityContext {
            provider: fornax_types::Provider::ClaudeCode,
            model_family: ModelFamily::Claude,
            model_version: "claude-sonnet-5".to_string(),
            adapter_version: "0.0.4".to_string(),
            task_class: TaskClass::TestExecution,
            toolset: vec![ToolClass::Shell, ToolClass::FileEdit],
            repository: RawRepositoryContext {
                identifying_hint: None,
                class: RepositoryClass::PublicOss,
            },
            policy_version: "policy-v3".to_string(),
            verifier_version: "verifier-v2".to_string(),
            fusion_version: "fusion-v1".to_string(),
            capabilities: caps(),
        })
    }

    fn drift_assessment(state: DriftState) -> DriftAssessment {
        let signal = ReliabilitySignal {
            context_key: context_key(),
            sample_support: SampleSupport::Confident { sample_count: 30 },
            not_evaluable_count: 0,
            policy_version: 1,
            reliability_estimate: Some(ReliabilityEstimate {
                success_rate: 0.9,
                confidence_interval: ConfidenceInterval {
                    lower: 0.8,
                    upper: 0.95,
                    confidence_level: 0.95,
                },
            }),
        };
        DriftAssessment {
            baseline_signal: signal.clone(),
            comparison_signal: signal,
            drift_state: state,
            policy_version: 1,
        }
    }

    #[test]
    fn no_active_revision_is_reported_honestly() {
        let assessment = assess_calibration(None, &provenance(), None, false);
        assert_eq!(assessment.state, CalibrationState::NoActiveCalibration);
    }

    #[test]
    fn matching_provenance_with_aggregation_disabled_is_valid() {
        let active = provenance();
        let assessment = assess_calibration(Some(&active), &provenance(), None, false);
        assert_eq!(assessment.state, CalibrationState::Valid);
    }

    #[test]
    fn adapter_version_mismatch_is_stale_regardless_of_aggregation_flag() {
        let active = provenance();
        let mut live = provenance();
        live.adapter_version = Some("claude-adapter-0.4.0".to_string());
        let assessment = assess_calibration(Some(&active), &live, None, true);
        assert_eq!(
            assessment.state,
            CalibrationState::Stale {
                changed_dimensions: vec!["adapter_version".to_string()]
            }
        );
    }

    #[test]
    fn capability_fingerprint_mismatch_is_stale() {
        let active = provenance();
        let mut live = provenance();
        live.capability_fingerprint =
            vec![("tool_invocation".to_string(), "unavailable".to_string())];
        let assessment = assess_calibration(Some(&active), &live, None, true);
        assert_eq!(
            assessment.state,
            CalibrationState::Stale {
                changed_dimensions: vec!["capability_fingerprint".to_string()]
            }
        );
    }

    #[test]
    fn drift_is_not_consulted_when_aggregation_disabled() {
        let active = provenance();
        let assessment = assess_calibration(
            Some(&active),
            &provenance(),
            Some(&drift_assessment(DriftState::Drifted)),
            false,
        );
        assert_eq!(assessment.state, CalibrationState::Valid);
    }

    #[test]
    fn drifted_cohort_reports_suspect_when_provenance_matches_and_aggregation_enabled() {
        let active = provenance();
        let assessment = assess_calibration(
            Some(&active),
            &provenance(),
            Some(&drift_assessment(DriftState::Drifted)),
            true,
        );
        assert_eq!(
            assessment.state,
            CalibrationState::Suspect {
                drift_state: DriftState::Drifted
            }
        );
    }

    #[test]
    fn stale_provenance_wins_over_drift_state() {
        let active = provenance();
        let mut live = provenance();
        live.adapter_version = Some("claude-adapter-0.4.0".to_string());
        let assessment = assess_calibration(
            Some(&active),
            &live,
            Some(&drift_assessment(DriftState::Drifted)),
            true,
        );
        assert_eq!(
            assessment.state,
            CalibrationState::Stale {
                changed_dimensions: vec!["adapter_version".to_string()]
            }
        );
    }

    #[test]
    fn insufficient_drift_support_is_a_distinct_state() {
        let active = provenance();
        let assessment = assess_calibration(
            Some(&active),
            &provenance(),
            Some(&drift_assessment(DriftState::InsufficientDataForComparison)),
            true,
        );
        assert_eq!(
            assessment.state,
            CalibrationState::InsufficientSupport {
                sample_support: SampleSupport::Confident { sample_count: 30 }
            }
        );
    }
}
