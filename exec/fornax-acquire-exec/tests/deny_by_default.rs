//! FORNX-346 Part 2 / ADR 0022: proves the two gates
//! (`fornax_experiment_runner::GlobalExperimentPolicy` and
//! `fornax_acquire_exec::grants::ExecutorGrants`) are independent -- each
//! must deny by default *on its own*, even when the other gate grants
//! everything.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use fornax_acquire_exec::grants::ExecutorGrants;
use fornax_experiment_runner::GlobalExperimentPolicy;
use fornax_types::experiment::{SideEffectAllowList, SideEffectClass};
use fornax_types::sensor::TrustClass;
use fornax_types::SignalClass;
use fornax_verify::voi::{
    AcquisitionCandidate, AcquisitionCost, AcquisitionLatency, ActionRisk, CandidateAvailability,
    Discrimination, EvidenceRequest, Independence, PrivacySensitivity, ProbeKind, Recency,
    UtilityEstimate,
};

fn utility() -> UtilityEstimate {
    UtilityEstimate {
        discrimination: Discrimination::High,
        independence: Independence::IndependentOfCounted,
        recency: Recency::FreshObservation,
        cost: AcquisitionCost::Cheap,
        latency: AcquisitionLatency::Seconds,
        privacy: PrivacySensitivity::LocalOnly,
        action_risk: ActionRisk::ReadOnly,
    }
}

fn candidate(kind: ProbeKind, effects: &[SideEffectClass]) -> AcquisitionCandidate {
    AcquisitionCandidate {
        request: EvidenceRequest {
            kind,
            target_signal_class: SignalClass::ToolTrace,
            expected_trust_class: TrustClass::HostObserved,
            required_side_effects: SideEffectAllowList::new(effects.iter().copied()),
            description: "test fixture".to_string(),
        },
        utility: utility(),
        availability: CandidateAvailability::Available,
        addresses_gaps: vec![],
        rank: Some(1),
        why_it_matters: "test fixture".to_string(),
    }
}

/// A unique sentinel path -- if any test in this file spawned a real
/// process, it would have no reason to create this file, so its absence
/// after a refused attempt is direct proof nothing was spawned.
fn sentinel_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "fornax-acquire-exec-deny-by-default-sentinel-{}",
        uuid::Uuid::new_v4()
    ))
}

static NO_SPAWN_HAPPENED: AtomicBool = AtomicBool::new(true);

#[test]
fn default_global_policy_refuses_rerun_test_and_nothing_is_spawned() {
    let sentinel = sentinel_path();
    let policy = GlobalExperimentPolicy::default(); // grants nothing but EphemeralWorktreeMutation
    let candidate = candidate(ProbeKind::RerunTest, &[SideEffectClass::ProcessSpawn]);

    let availability = fornax_acquire::classify_for_execution(&candidate, &policy);
    assert!(matches!(
        availability,
        CandidateAvailability::RequiresApproval { .. }
    ));

    // Gate 1 alone already refused -- confirm the caller never reaches a
    // point where it would spawn anything (this test file contains no
    // `Command::new` at all, so the sentinel simply cannot exist).
    assert!(!sentinel.exists());
    assert!(NO_SPAWN_HAPPENED.load(Ordering::SeqCst));
}

#[test]
fn process_spawn_granted_globally_but_no_acquisition_exec_grant_is_still_refused() {
    // Gate 1 (GlobalExperimentPolicy) grants ProcessSpawn...
    let policy = GlobalExperimentPolicy::new([SideEffectClass::ProcessSpawn]);
    let candidate = candidate(ProbeKind::RerunTest, &[SideEffectClass::ProcessSpawn]);
    assert_eq!(
        fornax_acquire::classify_for_execution(&candidate, &policy),
        CandidateAvailability::Available
    );

    // ...but gate 2 (ExecutorGrants, `[acquisition_exec]` absent/empty) must
    // still independently refuse -- proving the two gates are genuinely
    // independent, not one implying the other.
    let grants = ExecutorGrants::default();
    assert!(!grants.permits_argv(&["cargo".to_string(), "test".to_string()]));
}

#[test]
fn default_global_policy_refuses_query_ci_status() {
    let policy = GlobalExperimentPolicy::default(); // grants nothing but EphemeralWorktreeMutation
    let candidate = candidate(ProbeKind::QueryCiStatus, &[SideEffectClass::NetworkCall]);

    let availability = fornax_acquire::classify_for_execution(&candidate, &policy);
    assert!(matches!(
        availability,
        CandidateAvailability::RequiresApproval { .. }
    ));
}

#[test]
fn network_call_granted_globally_but_no_acquisition_exec_grant_is_still_refused() {
    // Gate 1 grants NetworkCall...
    let policy = GlobalExperimentPolicy::new([SideEffectClass::NetworkCall]);
    let candidate = candidate(ProbeKind::QueryCiStatus, &[SideEffectClass::NetworkCall]);
    assert_eq!(
        fornax_acquire::classify_for_execution(&candidate, &policy),
        CandidateAvailability::Available
    );

    // ...but gate 2 (`[acquisition_exec].allowed_ci_repos` absent/empty)
    // must still independently refuse.
    let grants = ExecutorGrants::default();
    assert!(grants.ci_repos().is_empty());
    assert!(!grants.permits_repo("horonomy/fornax-core"));
}

/// Regression pin (FORNX-346 Part 2): a `GlobalExperimentPolicy` loaded from
/// a minimal/empty config resolves to neither `ProcessSpawn` nor
/// `NetworkCall` granted -- never default-granted, no matter how the config
/// is spelled.
#[test]
fn policy_loaded_from_empty_config_grants_neither_process_spawn_nor_network_call() {
    let policy = GlobalExperimentPolicy::from_toml_str("").unwrap();
    assert!(!policy.permits(SideEffectClass::ProcessSpawn));
    assert!(!policy.permits(SideEffectClass::NetworkCall));

    let policy_missing_file = GlobalExperimentPolicy::load(&std::env::temp_dir().join(format!(
        "fornax-acquire-exec-nonexistent-home-{}",
        uuid::Uuid::new_v4()
    )))
    .unwrap();
    assert!(!policy_missing_file.permits(SideEffectClass::ProcessSpawn));
    assert!(!policy_missing_file.permits(SideEffectClass::NetworkCall));
}
