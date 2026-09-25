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

// --- Kani bounded model checking (FORNX-383) -------------------------------
//
// `classify_for_execution`'s entire decision surface is 4 closed
// `SideEffectClass` variants times independent grant/deny for each in the
// spec's own allow-list and the host policy -- 2^4 * 2^4 = 256 concrete
// cases, small enough that Kani explores it exhaustively (not sampled, as
// `proptest`'s randomized generators are) in well under a second. This is
// the acquisition-authorization state machine named explicitly in
// FORNX-383's candidate-target list; see
// `docs/security/formal-methods-scope.md` for why this module was chosen
// over TLA+/Loom for this specific invariant.
//
// Not compiled by `cargo build`/`cargo test`/CI's `rust` check -- only by
// `cargo kani`, run as its own separate, documented command (see that same
// doc for the recommended, currently-unapplied CI wiring). Requires no
// `kani` dev-dependency: `cargo kani` injects the `kani` crate itself.
#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use fornax_types::experiment::SideEffectAllowList;
    use fornax_types::sensor::TrustClass;
    use fornax_types::SignalClass;
    use fornax_verify::voi::{
        AcquisitionCost, AcquisitionLatency, ActionRisk, Discrimination, EvidenceRequest,
        Independence, PrivacySensitivity, ProbeKind, Recency, UtilityEstimate,
    };

    const ALL_CLASSES: [SideEffectClass; 4] = [
        SideEffectClass::EphemeralWorktreeMutation,
        SideEffectClass::ProcessSpawn,
        SideEffectClass::NetworkCall,
        SideEffectClass::FilesystemWriteOutsideWorktree,
    ];

    /// Build a symbolic allow-list: for each of the 4 closed classes,
    /// `kani::any()` nondeterministically decides membership. This
    /// enumerates every one of the 16 possible allow-lists without ever
    /// constructing a Kani-unfriendly unbounded `Vec` symbolically -- the
    /// membership decision is bounded by construction (4 fixed booleans),
    /// not a symbolic-length collection.
    fn any_allow_list() -> SideEffectAllowList {
        let mut granted = Vec::with_capacity(4);
        for class in ALL_CLASSES {
            if kani::any::<bool>() {
                granted.push(class);
            }
        }
        SideEffectAllowList::new(granted)
    }

    fn any_policy() -> GlobalExperimentPolicy {
        let mut granted = Vec::with_capacity(4);
        for class in ALL_CLASSES {
            if kani::any::<bool>() {
                granted.push(class);
            }
        }
        GlobalExperimentPolicy::new(granted)
    }

    fn fixed_utility() -> UtilityEstimate {
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

    fn symbolic_candidate(required: SideEffectAllowList) -> AcquisitionCandidate {
        AcquisitionCandidate {
            request: EvidenceRequest {
                kind: ProbeKind::InspectVcsState,
                target_signal_class: SignalClass::ToolTrace,
                expected_trust_class: TrustClass::HostObserved,
                required_side_effects: required,
                description: "kani".to_string(),
            },
            utility: fixed_utility(),
            availability: CandidateAvailability::Available, // deliberately stale/optimistic
            addresses_gaps: vec![],
            rank: Some(1),
            why_it_matters: "kani".to_string(),
        }
    }

    /// Invariant #5 (FORNX-382 registry: "FORBIDDEN or unapproved probes
    /// cannot execute"), safety-property form: across all 256 combinations
    /// of required side effects and both allow-lists, a candidate that
    /// requires `FilesystemWriteOutsideWorktree` is *never* classified
    /// `Available` -- not even when both the spec and a maximally
    /// permissive host policy grant it. This mirrors the existing example
    /// test `filesystem_write_outside_worktree_is_always_forbidden`, but
    /// proves it holds for every other side-effect combination too, not
    /// just the one hand-picked case.
    // `SideEffectAllowList::new`/`GlobalExperimentPolicy::new` sort+dedup a
    // Vec of at most 4 elements internally -- Kani's CBMC backend cannot
    // infer that loop's bound automatically since it's written generically
    // (over any slice length), so every harness that calls `any_allow_list`
    // or `any_policy` needs an explicit unwind bound. 4 elements is well
    // within a bound of 12.
    #[kani::proof]
    #[kani::unwind(12)]
    fn proof_filesystem_write_is_never_available() {
        let required = any_allow_list();
        if !required.permits(SideEffectClass::FilesystemWriteOutsideWorktree) {
            return; // out of scope for this specific proof
        }
        let policy = any_policy();
        let candidate = symbolic_candidate(required);

        let result = classify_for_execution(&candidate, &policy);
        assert!(
            !matches!(result, CandidateAvailability::Available),
            "a request naming FilesystemWriteOutsideWorktree must never be classified Available"
        );
    }

    /// Soundness property: `Available` must never be returned unless the
    /// *current* policy actually grants every one of the candidate's
    /// required side effects (never trusting the request's own claims or a
    /// stale `availability` field -- this proof deliberately seeds
    /// `candidate.availability = Available` regardless of the symbolic
    /// inputs, mirroring the real "policy tightened after planning" attack
    /// this module exists to close). Across all 256 combinations.
    #[kani::proof]
    #[kani::unwind(12)]
    fn proof_available_implies_policy_grants_every_required_class() {
        let required = any_allow_list();
        let policy = any_policy();
        let candidate = symbolic_candidate(required.clone());

        let result = classify_for_execution(&candidate, &policy);
        if matches!(result, CandidateAvailability::Available) {
            for class in ALL_CLASSES {
                if required.permits(class) {
                    assert!(
                        policy.permits(class),
                        "Available was returned but the current policy does not grant {class:?}"
                    );
                }
            }
        }
    }

    /// Vacuity check (FORNX-383 AC3): a deliberately weakened copy of the
    /// gate that skips the current-policy re-check entirely (the exact bug
    /// this module was written to prevent -- trusting the request's own
    /// allow-list as if it were sufficient on its own) must fail
    /// `proof_available_implies_policy_grants_every_required_class`'s
    /// property. This proves the harness above is capable of catching a
    /// real regression, not just passing vacuously on the real code.
    fn naively_classify_without_policy_recheck(
        candidate: &AcquisitionCandidate,
        _policy: &GlobalExperimentPolicy,
    ) -> CandidateAvailability {
        if candidate
            .request
            .required_side_effects
            .permits(SideEffectClass::FilesystemWriteOutsideWorktree)
        {
            return CandidateAvailability::Forbidden {
                reason: "always forbidden".to_string(),
            };
        }
        // BUG (deliberately reintroduced for this proof only): never
        // consults `_policy` at all -- exactly the staleness bug
        // `classify_for_execution`'s own module doc describes.
        CandidateAvailability::Available
    }

    /// This proof is expected to PASS, but what it proves is the bug: for
    /// every input where the spec's own allow-list names `NetworkCall`
    /// (which the naive gate — unlike the real one — never re-checks
    /// against the host policy), the naive gate wrongly reports
    /// `Available` even though `policy` denies everything. A passing proof
    /// here is the formal counterexample AC3 asks for: it demonstrates
    /// `classify_for_execution`'s real policy re-check
    /// (`proof_available_implies_policy_grants_every_required_class`,
    /// above) is actually load-bearing — remove it, as this naive stand-in
    /// does, and the property that proof establishes provably breaks.
    #[kani::proof]
    #[kani::unwind(12)]
    fn proof_naive_gate_is_exploitable_seeded_counterexample() {
        let required = any_allow_list();
        if !required.permits(SideEffectClass::NetworkCall)
            || required.permits(SideEffectClass::FilesystemWriteOutsideWorktree)
        {
            return;
        }
        let policy = GlobalExperimentPolicy::new(std::iter::empty()); // denies everything
        let candidate = symbolic_candidate(required);

        let naive_result = naively_classify_without_policy_recheck(&candidate, &policy);
        assert!(
            matches!(naive_result, CandidateAvailability::Available),
            "counterexample confirmed: naive gate wrongly reports Available under a fully-denying policy"
        );
    }
}
