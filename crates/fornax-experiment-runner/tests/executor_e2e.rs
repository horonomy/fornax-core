//! End-to-end tests against [`fornax_experiment_runner::ExperimentExecutor`],
//! one per ticket AC (FORNX-100).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fornax_experiment_runner::{
    is_permitted, staging_root, sweep_orphaned_staging_dirs, Cancellation, ExperimentExecutor,
    GlobalExperimentPolicy, InterventionObservation, InterventionObserver, StagedWorktree,
};
use fornax_types::experiment::{
    Baseline, ExpectedObservation, ExperimentKind, ExperimentOutcome, ExperimentProvenance,
    ExperimentSpec, Hypothesis, Intervention, SideEffectAllowList, SideEffectClass, StopCondition,
};
use fornax_types::graph::EvidenceRelation;
use fornax_types::SignalClass;
use uuid::Uuid;

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "fornax-experiment-runner-e2e-{label}-{}",
        Uuid::new_v4()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn provenance() -> ExperimentProvenance {
    ExperimentProvenance {
        created_at: "2026-01-01T00:00:00Z".into(),
        created_by: "test-harness".into(),
        environment: "worktree:fornax-FORNX-100-isolation".into(),
        tool_version: "fornax-cli-0.0.4".into(),
        runtime_versions: BTreeMap::new(),
    }
}

fn hypothesis() -> Hypothesis {
    Hypothesis {
        claim_id: Uuid::new_v4(),
        expected_observations: vec![ExpectedObservation {
            signal_class: SignalClass::ProcessResult,
            description: "exit code changes after reverting the file".into(),
        }],
        narrative: None,
    }
}

fn baseline() -> Baseline {
    Baseline {
        description: "file at HEAD before intervention".into(),
        evidence_ids: vec![Uuid::new_v4()],
    }
}

fn revert_intervention(path: &str, content: &str) -> Intervention {
    Intervention {
        kind: ExperimentKind::RevertFileToBaseline,
        description: "revert file to baseline content".into(),
        params: serde_json::json!({"path": path, "content": content}),
        provider_extension: None,
    }
}

/// A spec permitted to mutate its own ephemeral worktree, with a
/// caller-chosen timeout, ready to run against `revert_intervention`.
fn spec_with(intervention: Intervention, timeout_seconds: u64) -> ExperimentSpec {
    ExperimentSpec::new(
        Uuid::new_v4(),
        1,
        "session-1",
        hypothesis(),
        baseline(),
        intervention,
        vec![StopCondition::TimeoutElapsed {
            max_seconds: timeout_seconds,
        }],
        SideEffectAllowList::new([SideEffectClass::EphemeralWorktreeMutation]),
        provenance(),
    )
}

struct FixedObserver {
    evidence_ids: Vec<Uuid>,
    relation: Option<EvidenceRelation>,
}

impl InterventionObserver for FixedObserver {
    fn observe(&self, _staged: &StagedWorktree, _spec: &ExperimentSpec) -> InterventionObservation {
        InterventionObservation {
            evidence_ids: self.evidence_ids.clone(),
            relation: self.relation,
            summary: "observed the staged copy after intervention".into(),
        }
    }
}

fn supports_observer() -> FixedObserver {
    FixedObserver {
        evidence_ids: vec![Uuid::new_v4()],
        relation: Some(EvidenceRelation::Supports),
    }
}

/// Every entry directly under `root`, empty (and not an error) when `root`
/// does not exist at all.
fn staging_entries(root: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(root)
        .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------
// AC1: experiments cannot mutate the primary working tree by default
// ---------------------------------------------------------------------

#[test]
fn ac1_primary_working_tree_is_byte_identical_after_a_successful_experiment() {
    let source_root = temp_dir("ac1-source");
    std::fs::write(source_root.join("claimed.txt"), b"original content\n").unwrap();
    let staging = temp_dir("ac1-staging");

    let before: BTreeMap<String, Vec<u8>> = std::fs::read_dir(&source_root)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();

    let policy = GlobalExperimentPolicy::default();
    let observer = supports_observer();
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    let spec = spec_with(
        revert_intervention("claimed.txt", "intervention-mutated content\n"),
        60,
    );

    let result = executor.run(&spec, &source_root, &Cancellation::new());
    assert!(
        matches!(result.outcome, ExperimentOutcome::Completed(_)),
        "{:?}",
        result.outcome
    );

    let after: BTreeMap<String, Vec<u8>> = std::fs::read_dir(&source_root)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();

    assert_eq!(
        before, after,
        "the primary working tree must be byte-identical after the experiment ran"
    );

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
}

#[test]
fn ac1_traversal_shaped_intervention_path_is_blocked_not_applied() {
    let source_root = temp_dir("ac1-traversal-source");
    let staging = temp_dir("ac1-traversal-staging");
    let sibling_secret = temp_dir("ac1-traversal-sibling");
    std::fs::write(sibling_secret.join("real.txt"), b"do not touch\n").unwrap();

    let policy = GlobalExperimentPolicy::default();
    let observer = supports_observer();
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    // A path that escapes the staged copy into a real, existing directory —
    // never applied, regardless of what the intervention's own JSON claims.
    // Two `..` segments: one out of the `tempdir_in(staging_root)` staged
    // directory itself, one out of `staging_root`, landing back at the
    // shared OS temp directory both `staging` and `sibling_secret` were
    // created under.
    let escape_path = format!(
        "../../{}/real.txt",
        sibling_secret.file_name().unwrap().to_string_lossy()
    );
    let spec = spec_with(revert_intervention(&escape_path, "hijacked\n"), 60);

    let result = executor.run(&spec, &source_root, &Cancellation::new());
    assert!(
        matches!(result.outcome, ExperimentOutcome::Blocked { .. }),
        "{:?}",
        result.outcome
    );
    assert_eq!(
        std::fs::read(sibling_secret.join("real.txt")).unwrap(),
        b"do not touch\n"
    );

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
    std::fs::remove_dir_all(&sibling_secret).ok();
}

// ---------------------------------------------------------------------
// AC2: production credentials/network access are absent unless approved
// ---------------------------------------------------------------------

#[test]
fn ac2_ephemeral_worktree_mutation_denied_by_spec_allow_list_is_blocked() {
    let source_root = temp_dir("ac2-source");
    let staging = temp_dir("ac2-staging");

    let policy = GlobalExperimentPolicy::default(); // grants EphemeralWorktreeMutation
    let observer = supports_observer();
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    let mut spec = spec_with(revert_intervention("claimed.txt", "x"), 60);
    spec.allowed_side_effects = SideEffectAllowList::default(); // deny-by-default: names nothing

    let result = executor.run(&spec, &source_root, &Cancellation::new());
    assert!(matches!(result.outcome, ExperimentOutcome::Blocked { .. }));
    assert!(
        staging_entries(&staging).is_empty(),
        "nothing should ever be staged for a denied experiment"
    );

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
}

#[test]
fn ac2_ephemeral_worktree_mutation_denied_by_global_policy_is_blocked_even_when_spec_allows_it() {
    let source_root = temp_dir("ac2-global-source");
    let staging = temp_dir("ac2-global-staging");

    // Global policy explicitly denies everything, including the class the
    // spec itself grants — the two-layer gate must honor the stricter side.
    let policy = GlobalExperimentPolicy::new([]);
    let observer = supports_observer();
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    let spec = spec_with(revert_intervention("claimed.txt", "x"), 60);
    assert!(spec
        .allowed_side_effects
        .permits(SideEffectClass::EphemeralWorktreeMutation));

    let result = executor.run(&spec, &source_root, &Cancellation::new());
    assert!(matches!(result.outcome, ExperimentOutcome::Blocked { .. }));

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
}

/// The two-layer gate function itself, for the class AC2 names directly
/// (`network_call`) — no built-in `ExperimentKind` this executor runs
/// actually needs `NetworkCall`, so this is exercised at the policy layer
/// rather than through a full `run()` (see `fornax-experiment-runner`'s
/// module docs on why `ProcessSpawn`/network-touching kinds report
/// `Unsupported` rather than actually being executed).
#[test]
fn ac2_network_call_named_by_spec_alone_is_not_enough() {
    let spec_allow = SideEffectAllowList::new([SideEffectClass::NetworkCall]);
    let global = GlobalExperimentPolicy::default();
    assert!(!is_permitted(
        &spec_allow,
        &global,
        SideEffectClass::NetworkCall
    ));
}

// ---------------------------------------------------------------------
// AC3: cleanup on success, failure, timeout, and cancellation
// ---------------------------------------------------------------------

#[test]
fn ac3_cleanup_after_success() {
    let source_root = temp_dir("ac3-success-source");
    std::fs::write(source_root.join("claimed.txt"), b"before\n").unwrap();
    let staging = temp_dir("ac3-success-staging");

    let policy = GlobalExperimentPolicy::default();
    let observer = supports_observer();
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    let spec = spec_with(revert_intervention("claimed.txt", "after\n"), 60);

    let result = executor.run(&spec, &source_root, &Cancellation::new());
    assert!(matches!(result.outcome, ExperimentOutcome::Completed(_)));
    assert!(
        staging_entries(&staging).is_empty(),
        "staged directory must be gone after a successful run"
    );

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
}

#[test]
fn ac3_cleanup_after_failure() {
    let source_root = temp_dir("ac3-failure-source");
    let staging = temp_dir("ac3-failure-staging");

    let policy = GlobalExperimentPolicy::default();
    let observer = supports_observer();
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    // Missing `content` — the built-in applier reports Failed.
    let intervention = Intervention {
        kind: ExperimentKind::RevertFileToBaseline,
        description: "malformed intervention".into(),
        params: serde_json::json!({"path": "claimed.txt"}),
        provider_extension: None,
    };
    let spec = spec_with(intervention, 60);

    let result = executor.run(&spec, &source_root, &Cancellation::new());
    assert!(
        matches!(result.outcome, ExperimentOutcome::Failed { .. }),
        "{:?}",
        result.outcome
    );
    assert!(
        staging_entries(&staging).is_empty(),
        "staged directory must be gone after a failed run"
    );

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
}

#[test]
fn ac3_cleanup_after_timeout() {
    let source_root = temp_dir("ac3-timeout-source");
    std::fs::write(source_root.join("claimed.txt"), b"before\n").unwrap();
    let staging = temp_dir("ac3-timeout-staging");

    let policy = GlobalExperimentPolicy::default();
    let observer = supports_observer();
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    // A zero-second deadline: by the time the phase-boundary check runs
    // (immediately after the intervention is applied), any nonzero elapsed
    // time already exceeds it — deterministic without a real sleep.
    let spec = spec_with(revert_intervention("claimed.txt", "after\n"), 0);

    let result = executor.run(&spec, &source_root, &Cancellation::new());
    assert!(
        matches!(result.outcome, ExperimentOutcome::Failed { .. }),
        "{:?}",
        result.outcome
    );
    assert!(
        staging_entries(&staging).is_empty(),
        "staged directory must be gone after a timed-out run"
    );

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
}

#[test]
fn ac3_cleanup_after_cancellation() {
    let source_root = temp_dir("ac3-cancel-source");
    let staging = temp_dir("ac3-cancel-staging");

    let policy = GlobalExperimentPolicy::default();
    let observer = supports_observer();
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    let spec = spec_with(revert_intervention("claimed.txt", "after\n"), 60);

    let cancellation = Cancellation::new();
    cancellation.cancel();
    let result = executor.run(&spec, &source_root, &cancellation);

    assert!(
        matches!(result.outcome, ExperimentOutcome::Blocked { .. }),
        "{:?}",
        result.outcome
    );
    assert!(
        staging_entries(&staging).is_empty(),
        "no staged directory should survive (or ever be created for) a cancelled run"
    );

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
}

// ---------------------------------------------------------------------
// AC4: baseline and intervention evidence remain separately attributable
// ---------------------------------------------------------------------

#[test]
fn ac4_baseline_and_intervention_evidence_ids_are_disjoint_and_correctly_attributed() {
    let source_root = temp_dir("ac4-source");
    std::fs::write(source_root.join("claimed.txt"), b"before\n").unwrap();
    let staging = temp_dir("ac4-staging");

    let policy = GlobalExperimentPolicy::default();
    let intervention_evidence_id = Uuid::new_v4();
    let observer = FixedObserver {
        evidence_ids: vec![intervention_evidence_id],
        relation: Some(EvidenceRelation::Contradicts),
    };
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    let spec = spec_with(revert_intervention("claimed.txt", "after\n"), 60);
    let baseline_evidence_ids = spec.baseline.evidence_ids.clone();

    let result = executor.run(&spec, &source_root, &Cancellation::new());
    let ExperimentOutcome::Completed(completed) = result.outcome else {
        panic!("expected Completed, got {:?}", result.outcome);
    };

    assert_eq!(completed.baseline_evidence_ids, baseline_evidence_ids);
    assert_eq!(
        completed.intervention_evidence_ids,
        vec![intervention_evidence_id]
    );
    assert!(
        completed
            .baseline_evidence_ids
            .iter()
            .all(|id| !completed.intervention_evidence_ids.contains(id)),
        "baseline and intervention evidence ids must be disjoint sets, not merely both populated"
    );
    assert_eq!(completed.hypothesis_claim_id, spec.hypothesis.claim_id);

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
}

#[test]
fn ac4_no_evidence_observed_is_inconclusive_never_a_fabricated_completed_result() {
    let source_root = temp_dir("ac4-empty-source");
    std::fs::write(source_root.join("claimed.txt"), b"before\n").unwrap();
    let staging = temp_dir("ac4-empty-staging");

    let policy = GlobalExperimentPolicy::default();
    let observer = FixedObserver {
        evidence_ids: vec![],
        relation: None,
    };
    let executor = ExperimentExecutor {
        global_policy: &policy,
        staging_root: &staging,
        observer: &observer,
        applier: None,
    };
    let spec = spec_with(revert_intervention("claimed.txt", "after\n"), 60);

    let result = executor.run(&spec, &source_root, &Cancellation::new());
    assert!(
        matches!(result.outcome, ExperimentOutcome::Inconclusive { .. }),
        "{:?}",
        result.outcome
    );

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&staging).ok();
}

// ---------------------------------------------------------------------
// AC5: orphan cleanup for a crashed/killed process
// ---------------------------------------------------------------------

/// **Honest simulation, not a literal process kill.** A real `kill -9`
/// mid-experiment cannot be deterministically reproduced inside `cargo
/// test` (see `fornax_experiment_runner::orphan`'s module docs). This test
/// instead uses `std::mem::forget` to skip `StagedWorktree`'s `Drop`
/// impl entirely on a real, successfully-provisioned staged worktree — the
/// same end state a `SIGKILL` between provisioning and cleanup would leave
/// on disk — and then verifies the startup orphan sweep finds and removes
/// exactly that leftover directory.
#[test]
fn ac5_startup_sweep_reclaims_a_worktree_orphaned_by_a_forgotten_drop() {
    let source_root = temp_dir("ac5-source");
    let fornax_home = temp_dir("ac5-home");
    let staging = staging_root(&fornax_home);

    let staged = StagedWorktree::provision(&staging, &source_root).unwrap();
    let orphaned_path = staged.path().to_path_buf();
    assert!(orphaned_path.exists());
    std::mem::forget(staged); // simulates the process being killed here

    assert!(
        orphaned_path.exists(),
        "sanity: the leftover directory really is still there before the sweep runs"
    );

    let removed = sweep_orphaned_staging_dirs(&staging, std::time::Duration::ZERO).unwrap();

    assert_eq!(removed, vec![orphaned_path.clone()]);
    assert!(!orphaned_path.exists());

    std::fs::remove_dir_all(&source_root).ok();
    std::fs::remove_dir_all(&fornax_home).ok();
}
