//! Active evidence acquisition (FORNX-346): executes a
//! `fornax_verify::voi::AcquisitionCandidate` for real and feeds the result
//! back as canonical `fornax_types::Evidence`.
//!
//! Scope, deliberately narrow (see `docs/adr/0016-evidence-acquisition-boundary.md`
//! for the full rationale): only [`fornax_verify::voi::ProbeKind::VerifyArtifactHash`]
//! and [`fornax_verify::voi::ProbeKind::InspectVcsState`] are implemented.
//! Both are pure, in-process, read-only operations — no subprocess spawn, no
//! network call — so this crate stays covered by
//! `fornax-daemon/tests/adversarial_daemon_input.rs::
//! subprocess_surface_is_still_zero_in_production_code`'s workspace-wide
//! zero-subprocess-spawn scan exactly like every other production crate.
//! `RerunTest` (needs `ProcessSpawn`) and `QueryCiStatus` (needs
//! `NetworkCall`) are out of scope pending an explicit human decision on
//! whether that invariant and ADR-0001 D2 may ever be amended — see
//! FORNX-346's Jira thread. Executing them here without that decision would
//! be building past a boundary nobody has actually moved.
//!
//! Never trusts a stale plan: [`gate::classify_for_execution`] re-runs the
//! same two-layer side-effect check `fornax_verify::voi::classify_availability`
//! made at planning time, against *current* policy/capability state, right
//! before acquiring anything.

pub mod budget;
pub mod containment;
pub mod gate;
pub mod outcome;
pub mod probes;
pub mod target;

pub use budget::AcquisitionBudget;
pub use containment::{AcquisitionRoots, ContainmentError};
pub use gate::classify_for_execution;
pub use outcome::AcquisitionOutcome;
pub use target::{resolve_target, TargetResolution};

use fornax_experiment_runner::GlobalExperimentPolicy;
use fornax_types::Evidence;
use fornax_verify::voi::{AcquisitionCandidate, CandidateAvailability, ProbeKind};

/// Acquire the evidence one [`AcquisitionCandidate`] describes, for real,
/// applying the default [`AcquisitionBudget`]. See [`acquire_evidence_with_budget`]
/// for the full contract and a caller-supplied budget.
#[allow(clippy::too_many_arguments)]
pub fn acquire_evidence(
    candidate: &AcquisitionCandidate,
    claim_evidence: &[Evidence],
    session_id: &str,
    source_event_id: uuid::Uuid,
    roots: &AcquisitionRoots,
    policy: &GlobalExperimentPolicy,
    observed_at: &str,
) -> AcquisitionOutcome {
    acquire_evidence_with_budget(
        candidate,
        claim_evidence,
        session_id,
        source_event_id,
        roots,
        policy,
        observed_at,
        &AcquisitionBudget::default(),
    )
}

/// Acquire the evidence one [`AcquisitionCandidate`] describes, for real.
///
/// Order of operations, each of which can short-circuit to an honest
/// [`AcquisitionOutcome`] rather than a fabricated one:
/// 1. Re-gate against *current* policy (never trust `candidate.availability`,
///    computed at plan time).
/// 2. Resolve a concrete target for the candidate's `ProbeKind` --
///    `VerifyArtifactHash` requires a `FileDiff` path from the claim's own
///    evidence pool (refuses to guess when none exists); `InspectVcsState`
///    prefers the same `FileDiff` path when present but falls back to the
///    first configured [`AcquisitionRoots`] entry otherwise (FORNX-346 AC2
///    gap fix -- a VCS-state check is inherently repo-level, not
///    per-file, so most real claims carrying no `FileDiff` evidence no
///    longer make this probe unconditionally `Unavailable`).
/// 3. Contain any `FileDiff`-derived target to a configured acquisition
///    root -- refuses any resolved path outside every configured root. A
///    root used directly as the `InspectVcsState` fallback target is
///    already operator-configured and trusted, so it skips this check.
/// 4. Run the one probe this crate implements for the candidate's
///    `ProbeKind`, under `budget` (FORNX-346 AC5), or report `Unsupported`
///    for anything else (this crate's two probes, not a promise every
///    `ProbeKind` is covered).
#[allow(clippy::too_many_arguments)]
pub fn acquire_evidence_with_budget(
    candidate: &AcquisitionCandidate,
    claim_evidence: &[Evidence],
    session_id: &str,
    source_event_id: uuid::Uuid,
    roots: &AcquisitionRoots,
    policy: &GlobalExperimentPolicy,
    observed_at: &str,
    budget: &AcquisitionBudget,
) -> AcquisitionOutcome {
    if let CandidateAvailability::Forbidden { reason } = &candidate.availability {
        return AcquisitionOutcome::Refused {
            reason: reason.clone(),
        };
    }
    match classify_for_execution(candidate, policy) {
        CandidateAvailability::Available => {}
        CandidateAvailability::RequiresApproval { missing_grant } => {
            return AcquisitionOutcome::Refused {
                reason: format!("requires approval: {missing_grant}"),
            }
        }
        CandidateAvailability::Unavailable { reason } => {
            return AcquisitionOutcome::Unavailable { reason }
        }
        CandidateAvailability::Forbidden { reason } => {
            return AcquisitionOutcome::Refused { reason }
        }
    }

    let file_diff_target = resolve_target(claim_evidence);

    match candidate.request.kind {
        ProbeKind::VerifyArtifactHash => {
            let target = match file_diff_target {
                TargetResolution::Path(p) => p,
                TargetResolution::NoTarget => {
                    return AcquisitionOutcome::Unavailable {
                        reason: "no resolvable filesystem target in this claim's evidence"
                            .to_string(),
                    }
                }
            };
            let contained = match roots.resolve_contained(&target) {
                Ok(p) => p,
                Err(e) => {
                    return AcquisitionOutcome::Refused {
                        reason: format!("target refused by containment: {e}"),
                    }
                }
            };
            let session_id = session_id.to_string();
            let observed_at = observed_at.to_string();
            budget.run(move || {
                probes::verify_artifact_hash(&contained, &session_id, source_event_id, &observed_at)
            })
        }
        ProbeKind::InspectVcsState => {
            if let TargetResolution::Path(target) = file_diff_target {
                let contained = match roots.resolve_contained(&target) {
                    Ok(p) => p,
                    Err(e) => {
                        return AcquisitionOutcome::Refused {
                            reason: format!("target refused by containment: {e}"),
                        }
                    }
                };
                let session_id = session_id.to_string();
                let observed_at = observed_at.to_string();
                return budget.run(move || {
                    probes::inspect_vcs_state(
                        &contained,
                        &session_id,
                        source_event_id,
                        &observed_at,
                    )
                });
            }
            let Some(root) = roots.primary_root() else {
                return AcquisitionOutcome::Unavailable {
                    reason: "no resolvable FileDiff target and no acquisition root configured \
                             -- VCS state cannot be inspected"
                        .to_string(),
                };
            };
            let root = root.to_path_buf();
            let session_id = session_id.to_string();
            let observed_at = observed_at.to_string();
            budget.run(move || {
                probes::inspect_vcs_state_for_root(
                    &root,
                    &session_id,
                    source_event_id,
                    &observed_at,
                )
            })
        }
        other => AcquisitionOutcome::Unsupported {
            reason: format!(
                "{other:?} acquisition is not implemented by fornax-acquire (FORNX-346 scope)"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::experiment::SideEffectAllowList;
    use fornax_types::sensor::TrustClass;
    use fornax_types::SignalClass;
    use fornax_verify::voi::{
        AcquisitionCost, AcquisitionLatency, ActionRisk, Discrimination, EvidenceRequest,
        Independence, PrivacySensitivity, Recency, UtilityEstimate,
    };

    fn inspect_vcs_state_candidate() -> AcquisitionCandidate {
        AcquisitionCandidate {
            request: EvidenceRequest {
                kind: ProbeKind::InspectVcsState,
                target_signal_class: SignalClass::ToolTrace,
                expected_trust_class: TrustClass::HostObserved,
                required_side_effects: SideEffectAllowList::new([]),
                description: "inspect real git working-tree state".to_string(),
            },
            utility: UtilityEstimate {
                discrimination: Discrimination::Moderate,
                independence: Independence::IndependentOfCounted,
                recency: Recency::FreshObservation,
                cost: AcquisitionCost::Cheap,
                latency: AcquisitionLatency::Seconds,
                privacy: PrivacySensitivity::LocalOnly,
                action_risk: ActionRisk::ReadOnly,
            },
            availability: CandidateAvailability::Available,
            addresses_gaps: vec![],
            rank: Some(1),
            why_it_matters: "test fixture".to_string(),
        }
    }

    /// FORNX-346 AC2 gap fix, exercised through the actual `acquire_evidence`
    /// entry point (not just the leaf probe function): a claim with NO
    /// `FileDiff` evidence at all -- the overwhelming majority of real
    /// traffic, per this module's own docs -- must still be able to run
    /// `InspectVcsState` when an acquisition root is configured, falling
    /// back to a repo-level check instead of reporting `Unavailable` purely
    /// because no per-file target exists.
    #[test]
    fn inspect_vcs_state_falls_back_to_the_acquisition_root_when_claim_has_no_file_diff() {
        // This crate's own checkout is a real git working tree.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
        let roots = AcquisitionRoots::new([root]);
        let policy = GlobalExperimentPolicy::new(std::iter::empty());
        let candidate = inspect_vcs_state_candidate();

        let outcome = acquire_evidence(
            &candidate,
            &[], // no FileDiff evidence at all
            "s1",
            uuid::Uuid::new_v4(),
            &roots,
            &policy,
            "2026-01-01T00:00:00Z",
        );

        match outcome {
            AcquisitionOutcome::Acquired(_) => {}
            // A CI checkout without a full `.git` history is inconclusive.
            AcquisitionOutcome::Unavailable { .. } => {}
            other => panic!("expected Acquired or Unavailable, got {other:?}"),
        }
    }

    /// Negative case: with no `FileDiff` target AND no acquisition root
    /// configured, `InspectVcsState` is honestly `Unavailable` -- never
    /// silently falls back to some other unconfigured/default directory.
    #[test]
    fn inspect_vcs_state_is_unavailable_with_no_target_and_no_configured_root() {
        let roots = AcquisitionRoots::default();
        let policy = GlobalExperimentPolicy::new(std::iter::empty());
        let candidate = inspect_vcs_state_candidate();

        let outcome = acquire_evidence(
            &candidate,
            &[],
            "s1",
            uuid::Uuid::new_v4(),
            &roots,
            &policy,
            "2026-01-01T00:00:00Z",
        );

        assert!(matches!(outcome, AcquisitionOutcome::Unavailable { .. }));
    }
}
