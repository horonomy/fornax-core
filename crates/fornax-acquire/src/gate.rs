//! Re-checks a candidate's side-effect gate at execution time.
//!
//! `fornax_verify::voi::EvidencePlan` is a snapshot computed at plan time;
//! execution happens later, and `GlobalExperimentPolicy`/`SensorDisableConfig`
//! are file-backed configuration that can change in between. Trusting a
//! stale `AcquisitionCandidate::availability` field would let a probe that
//! was `Available` when planned execute even after an operator tightened
//! the policy in the meantime -- this module exists so that never happens.

use fornax_experiment_runner::{is_permitted, GlobalExperimentPolicy};
use fornax_types::experiment::SideEffectClass;
use fornax_verify::voi::{AcquisitionCandidate, CandidateAvailability};

/// Every [`SideEffectClass`] variant this workspace defines. Kept in one
/// place so re-checking "every effective class" means literally every
/// variant, not a list that silently drifts if the enum grows.
const ALL_SIDE_EFFECT_CLASSES: [SideEffectClass; 4] = [
    SideEffectClass::EphemeralWorktreeMutation,
    SideEffectClass::ProcessSpawn,
    SideEffectClass::NetworkCall,
    SideEffectClass::FilesystemWriteOutsideWorktree,
];

/// Re-run the real two-layer side-effect check (`is_permitted`) against
/// *current* `policy`, for every class `candidate.request.required_side_effects`
/// actually names -- never reads `candidate.availability`, which was
/// computed at plan time and may now be stale.
///
/// `FilesystemWriteOutsideWorktree` is always refused, mirroring
/// `fornax_verify::voi::classify_availability`'s own always-forbidden rule
/// for that class -- no policy can ever grant it through this path.
pub fn classify_for_execution(
    candidate: &AcquisitionCandidate,
    policy: &GlobalExperimentPolicy,
) -> CandidateAvailability {
    let request = &candidate.request;

    if request
        .required_side_effects
        .permits(SideEffectClass::FilesystemWriteOutsideWorktree)
    {
        return CandidateAvailability::Forbidden {
            reason: "FilesystemWriteOutsideWorktree is never approvable through this executor"
                .to_string(),
        };
    }

    for class in ALL_SIDE_EFFECT_CLASSES {
        if !request.required_side_effects.permits(class) {
            continue;
        }
        // The spec-level allow-list already grants `class` (checked above
        // via `permits`); `is_permitted` additionally re-checks the current
        // host-level `GlobalExperimentPolicy` -- the layer that can have
        // changed since planning.
        if !is_permitted(&request.required_side_effects, policy, class) {
            return CandidateAvailability::RequiresApproval {
                missing_grant: format!("{class:?}"),
            };
        }
    }

    CandidateAvailability::Available
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::experiment::SideEffectAllowList;
    use fornax_types::sensor::TrustClass;
    use fornax_types::SignalClass;
    use fornax_verify::voi::{EvidenceRequest, ProbeKind, UtilityEstimate};

    fn candidate(effects: &[SideEffectClass]) -> AcquisitionCandidate {
        AcquisitionCandidate {
            request: EvidenceRequest {
                kind: ProbeKind::InspectVcsState,
                target_signal_class: SignalClass::ToolTrace,
                expected_trust_class: TrustClass::HostObserved,
                required_side_effects: SideEffectAllowList::new(effects.iter().copied()),
                description: "test".to_string(),
            },
            utility: test_utility(),
            availability: CandidateAvailability::Available,
            addresses_gaps: vec![],
            rank: Some(1),
            why_it_matters: "test".to_string(),
        }
    }

    fn test_utility() -> UtilityEstimate {
        use fornax_verify::voi::{
            AcquisitionCost, AcquisitionLatency, ActionRisk, Discrimination, Independence,
            PrivacySensitivity, Recency,
        };
        UtilityEstimate {
            discrimination: Discrimination::High,
            independence: Independence::IndependentOfCounted,
            recency: Recency::FreshObservation,
            cost: AcquisitionCost::Free,
            latency: AcquisitionLatency::SubSecond,
            privacy: PrivacySensitivity::None,
            action_risk: ActionRisk::ReadOnly,
        }
    }

    #[test]
    fn a_read_only_request_is_available_under_the_default_policy() {
        let c = candidate(&[]);
        let policy = GlobalExperimentPolicy::default();
        assert_eq!(
            classify_for_execution(&c, &policy),
            CandidateAvailability::Available
        );
    }

    #[test]
    fn an_ungranted_class_requires_approval_naming_it() {
        let c = candidate(&[SideEffectClass::NetworkCall]);
        let policy = GlobalExperimentPolicy::default();
        assert_eq!(
            classify_for_execution(&c, &policy),
            CandidateAvailability::RequiresApproval {
                missing_grant: "NetworkCall".to_string()
            }
        );
    }

    #[test]
    fn filesystem_write_outside_worktree_is_always_forbidden() {
        let c = candidate(&[SideEffectClass::FilesystemWriteOutsideWorktree]);
        let policy = GlobalExperimentPolicy::new([SideEffectClass::FilesystemWriteOutsideWorktree]);
        assert!(matches!(
            classify_for_execution(&c, &policy),
            CandidateAvailability::Forbidden { .. }
        ));
    }

    /// The actual regression this module exists to prevent: a candidate
    /// planned as `Available` under a looser policy must be re-refused if
    /// the policy tightens before execution.
    #[test]
    fn a_policy_tightened_after_planning_blocks_execution() {
        let mut c = candidate(&[SideEffectClass::ProcessSpawn]);
        c.availability = CandidateAvailability::Available; // stale, from planning
        let tightened = GlobalExperimentPolicy::new(std::iter::empty());
        assert_eq!(
            classify_for_execution(&c, &tightened),
            CandidateAvailability::RequiresApproval {
                missing_grant: "ProcessSpawn".to_string()
            }
        );
    }
}
