//! The executor: takes a validated [`ExperimentSpec`] (FORNX-99), actually
//! runs it inside [`crate::staging::StagedWorktree`]'s isolation boundary,
//! and produces an [`ExperimentResult`].
//!
//! # What this module does *not* decide
//!
//! - **How to apply an intervention.** [`Intervention::params`] is opaque
//!   caller JSON by contract (FORNX-99); this module only knows how to
//!   apply [`ExperimentKind::RevertFileToBaseline`] itself (a built-in,
//!   generic "write this content to this path inside the staged copy"
//!   operation). [`ExperimentKind::SubstituteToolResult`] and
//!   [`ExperimentKind::DisableSensor`] require a caller-supplied
//!   [`InterventionApplier`]; without one they report
//!   [`ExperimentOutcome::Unsupported`] honestly rather than guessing at
//!   semantics this contract never specified.
//! - **What the intervention proves.** Whether observed evidence
//!   [`EvidenceRelation::Supports`]/[`Contradicts`](EvidenceRelation::Contradicts)/[`Neutral`](EvidenceRelation::Neutral)
//!   the hypothesis is a caller-supplied [`InterventionObserver`]'s job —
//!   this executor has no comparison logic of its own to inject a sixth
//!   interpretation scheme alongside [`crate::graph`]'s three-state
//!   vocabulary.
//! - **Whether to spawn a subprocess.** [`SideEffectClass::ProcessSpawn`]
//!   exists in FORNX-99's closed vocabulary as a permission an executor
//!   *could* one day need, but this executor never launches an external
//!   program under any circumstance — every [`ExperimentKind`] it actually
//!   executes is satisfied by in-process filesystem operations alone, which
//!   keeps this crate compliant with this workspace's zero subprocess-spawn
//!   surface for production code without needing an exception. A
//!   [`Intervention`] that genuinely requires launching an external program
//!   is out of this executor's supported scope and reports
//!   [`ExperimentOutcome::Unsupported`], the same as any other capability
//!   this executor does not have — never granted and then silently ignored.
//!
//! # Timeout and cancellation: honest scope
//!
//! Enforcement is checked at phase boundaries (before staging, before
//! applying the intervention, before observing), not preemptively mid-copy
//! or mid-write — a single [`std::fs::copy`] or [`std::fs::write`] call is
//! not interruptible from the outside without spawning a second thread and
//! accepting the underlying I/O keeps running after this function returns,
//! which is a worse guarantee than what phase-boundary checks give: this
//! function never returns *before* an in-flight filesystem operation
//! settles. The deadline comes from the spec's own
//! [`StopCondition::TimeoutElapsed`] (FORNX-99's existing vocabulary,
//! reused rather than inventing a second timeout config) when present, else
//! [`DEFAULT_TIMEOUT_CEILING_SECONDS`].

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fornax_types::experiment::{
    CompletedExperiment, ExperimentKind, ExperimentOutcome, ExperimentResult, ExperimentSpec,
    Intervention, SideEffectClass, StopCondition,
};
use fornax_types::graph::EvidenceRelation;
use uuid::Uuid;

use crate::policy::{is_permitted, GlobalExperimentPolicy};
use crate::staging::{StagedWorktree, StagingError};

/// Timeout ceiling used when `spec.stop_conditions` names no
/// [`StopCondition::TimeoutElapsed`] at all. A spec's own timeout is always
/// honored when present, even if smaller or larger than this — this
/// constant is only the fallback for a spec that never names one.
pub const DEFAULT_TIMEOUT_CEILING_SECONDS: u64 = 300;

/// A cooperative cancellation flag, cheap to clone and share with whatever
/// caller-side signal (a user abort, a supervising process shutting down)
/// should stop a running experiment. Checked at the same phase boundaries
/// as the timeout deadline — see module docs' "Timeout and cancellation"
/// section for why this is phase-boundary, not preemptive.
#[derive(Debug, Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Request cancellation. Idempotent — calling this more than once, or
    /// after the run it was meant to cancel has already finished, has no
    /// further effect.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What a caller-supplied observer found after an intervention was applied
/// inside a [`StagedWorktree`]. Distinct from
/// [`fornax_types::experiment::Baseline::evidence_ids`], which the spec
/// author already populated before authoring the spec (FORNX-99: "this
/// module does not collect it") — this struct is only ever about evidence
/// observed *after* the intervention, which is this executor's own job to
/// capture and hand back distinctly from the baseline set (AC4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InterventionObservation {
    /// [`fornax_types::Evidence`] ids produced by observing the
    /// intervention's effect. Empty means "nothing could be observed" —
    /// mapped to [`ExperimentOutcome::Inconclusive`], never treated as a
    /// zero-evidence [`CompletedExperiment`].
    pub evidence_ids: Vec<Uuid>,
    /// How the observed evidence relates to the hypothesis under test.
    /// `None` means the observer could not determine a relation — also
    /// mapped to [`ExperimentOutcome::Inconclusive`].
    pub relation: Option<EvidenceRelation>,
    /// Human-readable summary for [`CompletedExperiment::summary`] /
    /// [`ExperimentOutcome::Inconclusive`]'s `reason`.
    pub summary: String,
}

/// Observes the effect of an intervention already applied inside a staged
/// worktree. Caller-supplied because interpreting what an intervention's
/// evidence means is domain logic this executor deliberately does not
/// own — see module docs.
///
/// Takes `&StagedWorktree`, not a bare `&Path`, for the same containment
/// reason [`InterventionApplier`] does (FORNX-107 security review): any
/// implementation that reads a path named by [`ExperimentSpec`]/
/// `Intervention::params` must resolve it via
/// [`StagedWorktree::resolve_contained`] rather than joining it against a
/// raw root directly — a bare `&Path` gives an implementation no way to do
/// that even if it wanted to.
pub trait InterventionObserver {
    fn observe(&self, staged: &StagedWorktree, spec: &ExperimentSpec) -> InterventionObservation;
}

/// Applies an [`Intervention`] this executor has no built-in handling for
/// ([`ExperimentKind::SubstituteToolResult`], [`ExperimentKind::DisableSensor`]).
/// Implementations must resolve every filesystem path via
/// [`StagedWorktree::resolve_contained`] — never construct a path against
/// `staged_root` independently — so containment (AC1) holds regardless of
/// which applier is plugged in.
pub trait InterventionApplier {
    fn apply(&self, staged: &StagedWorktree, intervention: &Intervention) -> Result<(), String>;
}

/// Everything needed to run one [`ExperimentSpec`] to completion.
pub struct ExperimentExecutor<'a> {
    pub global_policy: &'a GlobalExperimentPolicy,
    pub staging_root: &'a Path,
    pub observer: &'a dyn InterventionObserver,
    /// Handles [`ExperimentKind::SubstituteToolResult`] /
    /// [`ExperimentKind::DisableSensor`]. `None` means those kinds always
    /// report [`ExperimentOutcome::Unsupported`].
    pub applier: Option<&'a dyn InterventionApplier>,
}

impl<'a> ExperimentExecutor<'a> {
    /// Run `spec` against `source_root` (the real working tree an
    /// intervention must never mutate — AC1). `cancellation` is checked at
    /// every phase boundary; see module docs.
    pub fn run(
        &self,
        spec: &ExperimentSpec,
        source_root: &Path,
        cancellation: &Cancellation,
    ) -> ExperimentResult {
        let outcome = self.run_inner(spec, source_root, cancellation);
        ExperimentResult {
            experiment_id: spec.id,
            experiment_version: spec.version,
            outcome,
            computed_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn run_inner(
        &self,
        spec: &ExperimentSpec,
        source_root: &Path,
        cancellation: &Cancellation,
    ) -> ExperimentOutcome {
        if cancellation.is_cancelled() {
            return blocked("cancelled before the experiment began");
        }

        // Two-layer gate (AC2): the mechanism itself always needs
        // EphemeralWorktreeMutation, regardless of `ExperimentKind`.
        if !is_permitted(
            &spec.allowed_side_effects,
            self.global_policy,
            SideEffectClass::EphemeralWorktreeMutation,
        ) {
            return blocked(
                "ephemeral worktree mutation is not permitted by the experiment's own \
                 allow-list and/or this host's global experiment policy",
            );
        }

        // Kind support is checked before provisioning anything — an
        // unsupported kind should never cost a worktree copy.
        if matches!(spec.intervention.kind, ExperimentKind::Custom(_)) {
            return ExperimentOutcome::Unsupported {
                reason: "no core dispatch handles ExperimentKind::Custom; a provider-specific \
                         executor extension is required and none is wired into this run"
                    .to_string(),
            };
        }
        if matches!(
            spec.intervention.kind,
            ExperimentKind::SubstituteToolResult | ExperimentKind::DisableSensor
        ) && self.applier.is_none()
        {
            return ExperimentOutcome::Unsupported {
                reason: format!(
                    "{:?} requires an InterventionApplier and none was provided to this executor",
                    spec.intervention.kind
                ),
            };
        }

        let deadline = timeout_deadline(spec);
        let started = Instant::now();

        let staged = match StagedWorktree::provision(self.staging_root, source_root) {
            Ok(staged) => staged,
            Err(e) => return failed(format!("failed to provision isolated worktree: {e}")),
        };
        // `staged` unconditionally cleans itself up (Drop) on every path
        // out of this function from here on — early return, error, or
        // falling through to the end.

        if cancellation.is_cancelled() {
            return blocked("cancelled before the intervention was applied");
        }

        if let Err(outcome) = self.apply_intervention(&staged, spec) {
            return outcome;
        }

        if started.elapsed() >= deadline {
            return failed(format!(
                "experiment exceeded its {}s timeout while applying the intervention",
                deadline.as_secs()
            ));
        }
        if cancellation.is_cancelled() {
            return blocked("cancelled before evidence could be observed");
        }

        let observation = self.observer.observe(&staged, spec);

        if started.elapsed() >= deadline {
            return failed(format!(
                "experiment exceeded its {}s timeout while observing evidence",
                deadline.as_secs()
            ));
        }

        finalize(spec, observation)
    }

    fn apply_intervention(
        &self,
        staged: &StagedWorktree,
        spec: &ExperimentSpec,
    ) -> Result<(), ExperimentOutcome> {
        match &spec.intervention.kind {
            ExperimentKind::RevertFileToBaseline => {
                apply_revert_file_to_baseline(staged, &spec.intervention)
            }
            ExperimentKind::SubstituteToolResult | ExperimentKind::DisableSensor => {
                let applier = self.applier.expect(
                    "checked in run_inner: these kinds only reach here when an applier is present",
                );
                applier
                    .apply(staged, &spec.intervention)
                    .map_err(|e| failed(format!("intervention applier failed: {e}")))
            }
            ExperimentKind::Custom(_) => {
                unreachable!("checked in run_inner before provisioning")
            }
        }
    }
}

/// Built-in handling for [`ExperimentKind::RevertFileToBaseline`]:
/// `intervention.params` must be a JSON object with a string `path` (relative
/// to the staged worktree's root) and a string `content` — the file at
/// `path` inside the staged copy is overwritten with `content`. Every other
/// shape is a [`Failed`](ExperimentOutcome::Failed) result naming what was
/// missing, never a panic.
fn apply_revert_file_to_baseline(
    staged: &StagedWorktree,
    intervention: &Intervention,
) -> Result<(), ExperimentOutcome> {
    let path = intervention
        .params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            failed("revert_file_to_baseline requires intervention.params.path (a string)")
        })?;
    let content = intervention
        .params
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            failed("revert_file_to_baseline requires intervention.params.content (a string)")
        })?;

    let resolved = staged.resolve_contained(path).map_err(|e| match e {
        StagingError::Escapes { .. } => blocked(format!(
            "intervention path '{path}' escapes the staged worktree boundary — refused"
        )),
        other => failed(format!("failed to resolve intervention path: {other}")),
    })?;

    if let Some(parent) = resolved.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| failed(format!("failed to create parent directories: {e}")))?;
    }
    std::fs::write(&resolved, content)
        .map_err(|e| failed(format!("failed to write reverted file contents: {e}")))
}

fn timeout_deadline(spec: &ExperimentSpec) -> Duration {
    let seconds = spec
        .stop_conditions
        .iter()
        .find_map(|c| match c {
            StopCondition::TimeoutElapsed { max_seconds } => Some(*max_seconds),
            _ => None,
        })
        .unwrap_or(DEFAULT_TIMEOUT_CEILING_SECONDS);
    Duration::from_secs(seconds)
}

/// Assembles the final outcome from what the observer found (AC3/AC4): no
/// evidence or no determined relation is an honest
/// [`ExperimentOutcome::Inconclusive`], never a fabricated comparison, and
/// [`CompletedExperiment::new`]'s own empty-id-list rejection is respected
/// rather than unwrapped — see module docs.
fn finalize(spec: &ExperimentSpec, observation: InterventionObservation) -> ExperimentOutcome {
    let Some(relation) = observation.relation else {
        return ExperimentOutcome::Inconclusive {
            reason: if observation.summary.is_empty() {
                "observer could not determine a hypothesis relation".to_string()
            } else {
                observation.summary
            },
        };
    };
    if observation.evidence_ids.is_empty() {
        return ExperimentOutcome::Inconclusive {
            reason:
                "observer determined a relation but produced no evidence ids to attribute it to"
                    .to_string(),
        };
    }

    match CompletedExperiment::new(
        spec.hypothesis.claim_id,
        relation,
        spec.baseline.evidence_ids.clone(),
        observation.evidence_ids,
        observation.summary,
    ) {
        Ok(completed) => ExperimentOutcome::Completed(completed),
        Err(reason) => ExperimentOutcome::Inconclusive { reason },
    }
}

fn blocked(reason: impl Into<String>) -> ExperimentOutcome {
    ExperimentOutcome::Blocked {
        reason: reason.into(),
    }
}

fn failed(reason: impl Into<String>) -> ExperimentOutcome {
    ExperimentOutcome::Failed {
        reason: reason.into(),
    }
}
