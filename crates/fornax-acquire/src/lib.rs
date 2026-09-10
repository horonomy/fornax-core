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

pub mod containment;
pub mod gate;
pub mod outcome;
pub mod probes;
pub mod target;

pub use containment::{AcquisitionRoots, ContainmentError};
pub use gate::classify_for_execution;
pub use outcome::AcquisitionOutcome;
pub use target::{resolve_target, TargetResolution};

use fornax_experiment_runner::GlobalExperimentPolicy;
use fornax_types::Evidence;
use fornax_verify::voi::{AcquisitionCandidate, CandidateAvailability, ProbeKind};

/// Acquire the evidence one [`AcquisitionCandidate`] describes, for real.
///
/// Order of operations, each of which can short-circuit to an honest
/// [`AcquisitionOutcome`] rather than a fabricated one:
/// 1. Re-gate against *current* policy (never trust `candidate.availability`,
///    computed at plan time).
/// 2. Resolve a concrete filesystem target from the claim's own evidence
///    pool -- refuses to guess when no `FileDiff` payload exists.
/// 3. Contain that target to a configured acquisition root -- refuses any
///    resolved path outside every configured root.
/// 4. Run the one probe this crate implements for the candidate's
///    `ProbeKind`, or report `Unsupported` for anything else (this crate's
///    two probes, not a promise every `ProbeKind` is covered).
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

    let target = match resolve_target(claim_evidence) {
        TargetResolution::Path(p) => p,
        TargetResolution::NoTarget => {
            return AcquisitionOutcome::Unavailable {
                reason: "no resolvable filesystem target in this claim's evidence".to_string(),
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

    match candidate.request.kind {
        ProbeKind::VerifyArtifactHash => {
            probes::verify_artifact_hash(&contained, session_id, source_event_id, observed_at)
        }
        ProbeKind::InspectVcsState => {
            probes::inspect_vcs_state(&contained, session_id, source_event_id, observed_at)
        }
        other => AcquisitionOutcome::Unsupported {
            reason: format!(
                "{other:?} acquisition is not implemented by fornax-acquire (FORNX-346 scope)"
            ),
        },
    }
}
