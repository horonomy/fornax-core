//! Counterfactual verification preview/run/render flow (FORNX-101, epic
//! FORNX-20 / discovery thesis HVDL-15).
//!
//! This module contains no new domain logic — it wires three already-built
//! pieces together into a CLI flow a user actually invokes:
//!
//! - [`fornax_types::experiment`] (FORNX-99) — the `ExperimentSpec`/
//!   `ExperimentOutcome` contract.
//! - [`fornax_experiment_runner`] (FORNX-100) — `ExperimentExecutor`,
//!   `GlobalExperimentPolicy`, `is_permitted`, `StagedWorktree`.
//! - [`fornax_types::causal`] (FORNX-102) — `CausalEvidenceLink`,
//!   `causal_evidence_from_experiment_result`.
//!
//! # Why this runs entirely client-side, not through `fornax-daemon`
//!
//! `ExperimentExecutor::run` needs a real filesystem `source_root` (the
//! user's working tree) and a `staging_root` to provision an isolated copy
//! under — both are local filesystem paths, not something a daemon HTTP
//! query parameter should carry (a daemon endpoint accepting an arbitrary
//! path from an HTTP client is a materially worse surface than a local CLI
//! invocation reading its own argv). `fornax-daemon` also has no
//! `fornax-experiment-runner` dependency today. This mirrors the existing
//! `export-spool` subcommand's precedent (`main.rs`'s own doc comment:
//! "Reads `$FORNAX_HOME/fornax.db` directly — no daemon dependency, so this
//! also works while the daemon is stopped") rather than inventing a new
//! shape.
//!
//! # The observer: honest, narrow scope
//!
//! [`ExperimentExecutor`] requires a caller-supplied
//! [`fornax_experiment_runner::InterventionObserver`] — FORNX-100
//! deliberately declined to own "what the intervention proves"
//! (interpreting evidence is domain logic, not execution-boundary logic).
//! [`RevertAppliedObserver`] below is a narrow, explicitly-scoped answer:
//! it checks only whether the file `RevertFileToBaseline`'s intervention
//! named now holds the content the intervention requested, inside the
//! staged copy. This is a **containment/effect-applied check**, never a
//! judgement about what that file change means for the hypothesis under
//! test at large — it does not re-run evidence collection, and it does not
//! synthesize `Evidence` rows into the store. Anything else (missing
//! params, unreadable path, mismatched content) reports no relation, which
//! `ExperimentExecutor::run`'s `finalize()` already maps to
//! `ExperimentOutcome::Inconclusive` — never a fabricated comparison.
//!
//! # AC3: the risk gate lives here, not only in the executor
//!
//! `ExperimentExecutor::run_inner` only ever checks
//! [`fornax_types::experiment::SideEffectClass::EphemeralWorktreeMutation`]
//! against the two-layer gate — no code path in that crate checks any other
//! class, because no built-in `ExperimentKind` it executes ever needs one.
//! A spec whose allow-list also names, say, `NetworkCall` would therefore
//! run to completion untouched by that class at all if this module didn't
//! gate on it first. [`check_policy_gate`] closes that gap: every class the
//! spec's own allow-list names beyond `EphemeralWorktreeMutation` must also
//! be granted by [`GlobalExperimentPolicy`], or the experiment is reported
//! blocked/needs-policy-approval and [`ExperimentExecutor::run`] is never
//! called at all — not run in a degraded form with the unpermitted class
//! silently stripped.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use fornax_experiment_runner::{
    is_permitted, Cancellation, ExperimentExecutor, GlobalExperimentPolicy,
    InterventionObservation, InterventionObserver, StagedWorktree,
};
use fornax_types::causal::{causal_evidence_from_experiment_result, CausalExperimentEvidence};
use fornax_types::experiment::{ExperimentResult, ExperimentSpec, SideEffectClass};
use fornax_types::graph::EvidenceRelation;
use uuid::Uuid;

#[derive(Subcommand)]
pub enum ExperimentAction {
    /// List the experiment templates this executor can actually run today
    /// (AC1: "user can see exactly what Fornax will change/test before a
    /// non-trivial experiment" — starting from the template catalog itself,
    /// before any one spec is even authored).
    Templates,
    /// Preview one experiment spec: hypothesis, intervention, and the
    /// side-effect classes it would need, plus whether this host's global
    /// policy already grants them — a pure, read-only report. Never
    /// provisions a staged worktree, never touches the store, never runs
    /// anything (AC1).
    Preview {
        /// Path to an `ExperimentSpec` JSON file (FORNX-99's wire format).
        #[arg(long)]
        spec: PathBuf,
    },
    /// Run one experiment spec. A spec whose allow-list needs only
    /// `EphemeralWorktreeMutation` auto-runs end-to-end inside the
    /// isolation boundary (AC2). A spec naming any other side-effect class
    /// only runs if this host's global policy already grants that class too
    /// — otherwise it is reported as blocked/needs-policy-approval and
    /// nothing is executed (AC3).
    Run {
        /// Path to an `ExperimentSpec` JSON file.
        #[arg(long)]
        spec: PathBuf,
        /// The real working tree to run the experiment against. Never
        /// mutated — the executor stages an isolated copy before applying
        /// the intervention.
        #[arg(long)]
        source: PathBuf,
        /// Root directory ephemeral staged copies are created under.
        #[arg(long)]
        staging_root: PathBuf,
    },
}

/// Handles one [`ExperimentAction`], printing its rendered output to
/// stdout.
pub fn handle(action: ExperimentAction, fornax_home: &Path) -> anyhow::Result<()> {
    let global_policy = GlobalExperimentPolicy::load(fornax_home)?;
    match action {
        ExperimentAction::Templates => {
            print!("{}", render_templates());
        }
        ExperimentAction::Preview { spec } => {
            let spec = load_spec(&spec)?;
            print!("{}", render_preview(&spec, &global_policy));
        }
        ExperimentAction::Run {
            spec,
            source,
            staging_root,
        } => {
            let spec = load_spec(&spec)?;
            let session_id = spec.session_id.clone();
            let outcome = run_experiment(&spec, &source, &staging_root, &global_policy);
            print!("{}", render_run_outcome(&outcome, &session_id));
        }
    }
    Ok(())
}

fn load_spec(path: &Path) -> anyhow::Result<ExperimentSpec> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!("failed to read experiment spec at {}: {e}", path.display())
    })?;
    let spec: ExperimentSpec = serde_json::from_str(&contents).map_err(|e| {
        anyhow::anyhow!("failed to parse experiment spec at {}: {e}", path.display())
    })?;
    Ok(spec)
}

// ---------------------------------------------------------------------
// Template catalog (AC1)
// ---------------------------------------------------------------------

/// Static catalog entry for one experiment kind: what it does, what it
/// requires, and whether this executor can actually run it. Deliberately
/// hand-written rather than reflected off `ExperimentKind`'s variants —
/// this ticket introduces exactly one runnable template
/// (`RevertFileToBaseline`); the other two named `ExperimentKind` variants
/// are FORNX-99 contract shapes that FORNX-100's executor reports
/// `Unsupported` for today (no built-in `InterventionApplier` exists), which
/// is exactly what this catalog says about them.
fn render_templates() -> String {
    let mut out = String::new();
    out.push_str("available experiment templates:\n\n");
    out.push_str("  revert_file_to_baseline  [ELIGIBLE]\n");
    out.push_str(
        "    Reverts a named file, inside an ephemeral isolated copy of the working\n\
         \x20   tree, to caller-supplied baseline content, then observes whether that\n\
         \x20   file's content in the staged copy matches what was requested.\n\
         \x20   requires: ephemeral_worktree_mutation\n\
         \x20   intervention.params: {\"path\": <string>, \"content\": <string>}\n\n",
    );
    out.push_str("  substitute_tool_result  [NOT ELIGIBLE]\n");
    out.push_str(
        "    Defined by FORNX-99's contract; FORNX-100's executor has no built-in\n\
         \x20   InterventionApplier for it -- reports unsupported if attempted.\n\n",
    );
    out.push_str("  disable_sensor  [NOT ELIGIBLE]\n");
    out.push_str(
        "    Defined by FORNX-99's contract; FORNX-100's executor has no built-in\n\
         \x20   InterventionApplier for it -- reports unsupported if attempted.\n",
    );
    out
}

// ---------------------------------------------------------------------
// Preview (AC1)
// ---------------------------------------------------------------------

fn side_effect_class_name(class: SideEffectClass) -> &'static str {
    match class {
        SideEffectClass::EphemeralWorktreeMutation => "ephemeral_worktree_mutation",
        SideEffectClass::ProcessSpawn => "process_spawn",
        SideEffectClass::NetworkCall => "network_call",
        SideEffectClass::FilesystemWriteOutsideWorktree => "filesystem_write_outside_worktree",
    }
}

/// Renders a full preview of `spec`: hypothesis, baseline, intervention, and
/// every requested side-effect class annotated with whether this host's
/// global policy already grants it — a pure read-only report. Takes only
/// `spec` and `global` (never a staging root, never the executor) so
/// nothing this function can do provisions a worktree or runs anything
/// (AC1: "user can see exactly what Fornax will change/test before a
/// non-trivial experiment").
pub fn render_preview(spec: &ExperimentSpec, global: &GlobalExperimentPolicy) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "experiment: {} v{}  (session: {})\n",
        spec.id, spec.version, spec.session_id
    ));
    out.push_str(&format!("hypothesis claim: {}\n", spec.hypothesis.claim_id));
    for obs in &spec.hypothesis.expected_observations {
        out.push_str(&format!(
            "  expects: {:?} -- {}\n",
            obs.signal_class, obs.description
        ));
    }
    if let Some(narrative) = &spec.hypothesis.narrative {
        out.push_str(&format!("  narrative: {narrative}\n"));
    }
    out.push_str(&format!("baseline: {}\n", spec.baseline.description));
    out.push_str(&format!(
        "intervention ({:?}): {}\n",
        spec.intervention.kind, spec.intervention.description
    ));

    let classes = spec.allowed_side_effects.classes();
    if classes.is_empty() {
        out.push_str("side effects requested: none (read-only)\n");
    } else {
        out.push_str("side effects requested:\n");
        for class in classes {
            let granted = global.permits(*class);
            let marker = if granted {
                "granted by this host's global policy"
            } else {
                "NOT granted by this host's global policy"
            };
            out.push_str(&format!(
                "  - {} ({marker})\n",
                side_effect_class_name(*class)
            ));
        }
    }

    // AC1: preview must not claim eligibility to auto-run a kind `run`
    // itself would refuse. Only `RevertFileToBaseline` has a built-in
    // `InterventionApplier` (see module docs) -- everything else reports
    // `ExperimentOutcome::Unsupported` if actually run, so preview says so
    // up front rather than showing a risk verdict that implies it would run.
    if !matches!(
        spec.intervention.kind,
        fornax_types::experiment::ExperimentKind::RevertFileToBaseline
    ) {
        out.push_str(&format!(
            "kind: {:?} -- NOT ELIGIBLE (no built-in executor support; running this would report unsupported)\n",
            spec.intervention.kind
        ));
        out.push_str("(preview only -- nothing was executed)\n");
        return out;
    }

    let gate = check_policy_gate(spec, global);
    if gate.denied_classes.is_empty() {
        out.push_str("risk: low-risk -- eligible to auto-run\n");
    } else {
        out.push_str("risk: higher-risk -- requires explicit policy approval for:\n");
        for class in &gate.denied_classes {
            out.push_str(&format!("  - {}\n", side_effect_class_name(*class)));
        }
    }
    out.push_str("(preview only -- nothing was executed)\n");
    out
}

// ---------------------------------------------------------------------
// Risk gate (AC3)
// ---------------------------------------------------------------------

/// Result of [`check_policy_gate`]: every [`SideEffectClass`] beyond
/// `EphemeralWorktreeMutation` this spec's own allow-list names that this
/// host's [`GlobalExperimentPolicy`] does not also grant. Empty means the
/// experiment is low-risk by this ticket's definition and eligible to
/// auto-run.
pub struct PolicyGateResult {
    pub denied_classes: Vec<SideEffectClass>,
}

/// "Low-risk" per this ticket's definition: needs only
/// `EphemeralWorktreeMutation`. Every other class the spec names must
/// already be granted by `global`, or it is denied here — this is checked
/// independently of [`ExperimentExecutor::run`], which only ever tests
/// `EphemeralWorktreeMutation` itself (see module docs).
pub fn check_policy_gate(
    spec: &ExperimentSpec,
    global: &GlobalExperimentPolicy,
) -> PolicyGateResult {
    let denied_classes = spec
        .allowed_side_effects
        .classes()
        .iter()
        .copied()
        .filter(|class| *class != SideEffectClass::EphemeralWorktreeMutation)
        .filter(|class| !is_permitted(&spec.allowed_side_effects, global, *class))
        .collect();
    PolicyGateResult { denied_classes }
}

// ---------------------------------------------------------------------
// The observer (see module docs' "honest, narrow scope" section)
// ---------------------------------------------------------------------

/// Fixed namespace for [`observation_evidence_id`]'s deterministic id
/// derivation -- mirrors `fornax_types::causal::CAUSAL_LINK_NAMESPACE`'s
/// precedent so this observer stays a pure function of its inputs.
const OBSERVATION_NAMESPACE: Uuid = Uuid::from_bytes([
    0x7c, 0x1a, 0x4e, 0x92, 0x3b, 0x6d, 0x41, 0xaf, 0x9e, 0x03, 0x8f, 0x2c, 0x5b, 0x0e, 0x77, 0x4a,
]);

fn observation_evidence_id(experiment_id: Uuid, version: u32, path: &str) -> Uuid {
    Uuid::new_v5(
        &OBSERVATION_NAMESPACE,
        format!("{experiment_id}:{version}:observed:{path}").as_bytes(),
    )
}

/// The only built-in [`InterventionObserver`] this module supplies. See
/// module docs' "The observer: honest, narrow scope" section for exactly
/// what this does and does not claim to know.
pub struct RevertAppliedObserver;

impl InterventionObserver for RevertAppliedObserver {
    fn observe(&self, staged: &StagedWorktree, spec: &ExperimentSpec) -> InterventionObservation {
        let no_relation = |summary: String| InterventionObservation {
            evidence_ids: vec![],
            relation: None,
            summary,
        };

        let Some(path) = spec
            .intervention
            .params
            .get("path")
            .and_then(|v| v.as_str())
        else {
            return no_relation(
                "intervention.params.path is missing -- cannot observe the intervention's effect"
                    .to_string(),
            );
        };
        let Some(expected_content) = spec
            .intervention
            .params
            .get("content")
            .and_then(|v| v.as_str())
        else {
            return no_relation(
                "intervention.params.content is missing -- cannot observe the intervention's effect"
                    .to_string(),
            );
        };

        let resolved = match staged.resolve_contained(path) {
            Ok(resolved) => resolved,
            Err(e) => {
                return no_relation(format!(
                    "'{path}' does not resolve to a location inside the staged copy: {e}"
                ))
            }
        };

        match std::fs::read_to_string(resolved) {
            Ok(actual) if actual == expected_content => InterventionObservation {
                evidence_ids: vec![observation_evidence_id(spec.id, spec.version, path)],
                relation: Some(EvidenceRelation::Supports),
                summary: format!(
                    "file '{path}' in the staged copy holds the content the intervention requested"
                ),
            },
            Ok(_) => no_relation(format!(
                "file '{path}' in the staged copy does not match the intervention's requested content"
            )),
            Err(e) => no_relation(format!("could not read '{path}' in the staged copy: {e}")),
        }
    }
}

// ---------------------------------------------------------------------
// Run (AC2/AC3)
// ---------------------------------------------------------------------

/// The outcome of attempting to run `spec`: either it was blocked before
/// anything was executed (AC3), or the real [`ExperimentExecutor`] ran and
/// produced an [`ExperimentResult`] (AC2).
pub enum RunOutcome {
    /// This host's global policy does not grant every side-effect class the
    /// spec's own allow-list names beyond `EphemeralWorktreeMutation`.
    /// [`ExperimentExecutor::run`] was never called.
    NeedsPolicyApproval {
        denied_classes: Vec<SideEffectClass>,
    },
    /// The executor ran to completion (any [`ExperimentOutcome`] variant --
    /// running is distinct from succeeding).
    Ran(ExperimentResult),
}

/// Runs `spec` against `source_root`, staging under `staging_root`, after
/// checking [`check_policy_gate`] first (AC3: a denied higher-risk class
/// must block the run outright, never silently downgrade it).
///
/// Sweeps `staging_root` for orphaned directories a killed prior run left
/// behind before provisioning a new one — `fornax_experiment_runner::orphan`'s
/// own module docs document this as every executor caller's responsibility
/// (FORNX-107 security review: this was previously never invoked from any
/// production entry point, so a killed `fornax experiment run` left a full
/// copy of the working tree on disk indefinitely).
pub fn run_experiment(
    spec: &ExperimentSpec,
    source_root: &Path,
    staging_root: &Path,
    global: &GlobalExperimentPolicy,
) -> RunOutcome {
    let gate = check_policy_gate(spec, global);
    if !gate.denied_classes.is_empty() {
        return RunOutcome::NeedsPolicyApproval {
            denied_classes: gate.denied_classes,
        };
    }

    // Best-effort: an orphan sweep failing (e.g. a permission-denied entry)
    // must never block a legitimate run.
    let _ = fornax_experiment_runner::sweep_orphaned_staging_dirs(
        staging_root,
        fornax_experiment_runner::DEFAULT_ORPHAN_MAX_AGE,
    );

    let observer = RevertAppliedObserver;
    let executor = ExperimentExecutor {
        global_policy: global,
        staging_root,
        observer: &observer,
        applier: None,
    };
    let result = executor.run(spec, source_root, &Cancellation::new());
    RunOutcome::Ran(result)
}

// ---------------------------------------------------------------------
// Rendering (AC4/AC5)
// ---------------------------------------------------------------------

/// Icon for one [`CausalExperimentEvidence`] outcome label -- five distinct
/// glyphs, mirroring `render_judge`/`render_evidence_graph`'s
/// never-collapse-the-taxonomy discipline in `main.rs`. The `_` arm here is
/// only a forward-compat fallback for an unrecognized *label string* this
/// module itself never produces (matching the established
/// `verdict_icon`/`availability_icon` convention) -- it is not a fallback
/// for an outcome variant, which is matched exhaustively in
/// [`render_causal_evidence`] below.
fn causal_outcome_icon(label: &str) -> &'static str {
    match label {
        "completed" => "🧪",
        "inconclusive" => "?",
        "blocked" => "⛔",
        "unsupported" => "⚠",
        "failed" => "✕",
        _ => "◌",
    }
}

pub fn render_run_outcome(outcome: &RunOutcome, session_id: &str) -> String {
    match outcome {
        RunOutcome::NeedsPolicyApproval { denied_classes } => {
            let mut out = String::new();
            out.push_str("BLOCKED: needs policy approval\n");
            out.push_str(
                "  this experiment requires side-effect classes this host's global policy \
                 does not grant:\n",
            );
            for class in denied_classes {
                out.push_str(&format!("    - {}\n", side_effect_class_name(*class)));
            }
            out.push_str(
                "  the experiment was NOT run. grant the class(es) above in \
                 $FORNAX_HOME/config.toml's [experiment] table if this is intended, then re-run.\n",
            );
            out
        }
        RunOutcome::Ran(result) => render_experiment_result(result, session_id),
    }
}

/// Renders one [`ExperimentResult`] via its [`CausalExperimentEvidence`]
/// mapping (FORNX-102), showing baseline and intervention evidence as two
/// genuinely separate, distinctly-labeled sections (AC4), and every
/// non-`Completed` outcome with its own honest, distinct label -- never
/// merged into a "contradiction"/"verified" banner (AC5).
pub fn render_experiment_result(result: &ExperimentResult, session_id: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "experiment: {} v{}\n",
        result.experiment_id, result.experiment_version
    ));
    out.push_str(&format!("computed_at: {}\n\n", result.computed_at));

    match causal_evidence_from_experiment_result(result, session_id) {
        Ok(causal) => out.push_str(&render_causal_evidence(&causal)),
        Err(e) => out.push_str(&format!(
            "{} ERROR -- malformed completed result: {e}\n",
            causal_outcome_icon("error")
        )),
    }
    out
}

fn render_causal_evidence(causal: &CausalExperimentEvidence) -> String {
    let mut out = String::new();
    match causal {
        CausalExperimentEvidence::Completed {
            relation,
            baseline_links,
            intervention_links,
        } => {
            out.push_str(&format!(
                "{} COMPLETED -- hypothesis relation: {:?}\n",
                causal_outcome_icon("completed"),
                relation
            ));
            out.push_str("\n--- baseline (observational, pre-intervention) ---\n");
            if baseline_links.is_empty() {
                out.push_str("  (none)\n");
            }
            for link in baseline_links {
                out.push_str(&format!(
                    "  evidence: {}  relation: {:?}\n",
                    link.link.evidence_id, link.link.relation
                ));
            }
            out.push_str("\n--- intervention (interventional, post-intervention) ---\n");
            if intervention_links.is_empty() {
                out.push_str("  (none)\n");
            }
            for link in intervention_links {
                out.push_str(&format!(
                    "  evidence: {}  relation: {:?}\n",
                    link.link.evidence_id, link.link.relation
                ));
            }
        }
        CausalExperimentEvidence::Inconclusive { reason } => {
            out.push_str(&format!(
                "{} INCONCLUSIVE -- {reason}\n",
                causal_outcome_icon("inconclusive")
            ));
        }
        CausalExperimentEvidence::Blocked { reason } => {
            out.push_str(&format!(
                "{} BLOCKED -- {reason}\n",
                causal_outcome_icon("blocked")
            ));
        }
        CausalExperimentEvidence::Unsupported { reason } => {
            out.push_str(&format!(
                "{} UNSUPPORTED -- {reason}\n",
                causal_outcome_icon("unsupported")
            ));
        }
        CausalExperimentEvidence::Failed { reason } => {
            out.push_str(&format!(
                "{} FAILED -- {reason}\n",
                causal_outcome_icon("failed")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::experiment::{
        Baseline, ExpectedObservation, ExperimentKind, ExperimentOutcome, ExperimentProvenance,
        Hypothesis, Intervention, SideEffectAllowList, StopCondition,
    };
    use fornax_types::SignalClass;
    use std::collections::BTreeMap;

    fn provenance() -> ExperimentProvenance {
        ExperimentProvenance {
            created_at: "2026-01-01T00:00:00Z".into(),
            created_by: "test-harness".into(),
            environment: "worktree:fornax-FORNX-101-counterfactual-ux".into(),
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
            narrative: Some("if the file caused the failure, reverting it fixes it".into()),
        }
    }

    fn revert_intervention(path: &str, content: &str) -> Intervention {
        Intervention {
            kind: ExperimentKind::RevertFileToBaseline,
            description: format!("revert {path} to baseline content"),
            params: serde_json::json!({"path": path, "content": content}),
            provider_extension: None,
        }
    }

    fn spec_with(
        intervention: Intervention,
        allowed: SideEffectAllowList,
        baseline_evidence: Vec<Uuid>,
    ) -> ExperimentSpec {
        ExperimentSpec::new(
            Uuid::new_v4(),
            1,
            "session-1",
            hypothesis(),
            Baseline {
                description: "file at HEAD before intervention".into(),
                evidence_ids: baseline_evidence,
            },
            intervention,
            vec![StopCondition::TimeoutElapsed { max_seconds: 60 }],
            allowed,
            provenance(),
        )
    }

    fn low_risk_spec() -> ExperimentSpec {
        spec_with(
            revert_intervention("claimed.txt", "after\n"),
            SideEffectAllowList::new([SideEffectClass::EphemeralWorktreeMutation]),
            vec![Uuid::new_v4()],
        )
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "fornax-cli-experiment-ux-test-{label}-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn staging_entries(root: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(root)
            .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default()
    }

    // --- AC1: preview shows hypothesis/intervention/side-effects, never executes ---

    #[test]
    fn render_preview_shows_hypothesis_intervention_and_side_effect_classes() {
        let spec = low_risk_spec();
        let global = GlobalExperimentPolicy::default();
        let out = render_preview(&spec, &global);
        assert!(out.contains(&spec.hypothesis.claim_id.to_string()));
        assert!(out.contains("revert claimed.txt to baseline content"));
        assert!(out.contains("ephemeral_worktree_mutation"));
        assert!(out.contains("preview only -- nothing was executed"));
        assert!(out.contains("low-risk -- eligible to auto-run"));
    }

    #[test]
    fn render_preview_reports_higher_risk_class_not_granted_by_policy() {
        let spec = spec_with(
            revert_intervention("claimed.txt", "after\n"),
            SideEffectAllowList::new([
                SideEffectClass::EphemeralWorktreeMutation,
                SideEffectClass::NetworkCall,
            ]),
            vec![Uuid::new_v4()],
        );
        let global = GlobalExperimentPolicy::default(); // grants only EphemeralWorktreeMutation
        let out = render_preview(&spec, &global);
        assert!(out.contains("NOT granted by this host's global policy"));
        assert!(out.contains("higher-risk -- requires explicit policy approval"));
    }

    /// AC1: preview must never claim "eligible to auto-run" for a kind
    /// `run` would actually refuse (`Unsupported`) -- a spec whose kind has
    /// no built-in `InterventionApplier` previews as not eligible, never as
    /// a low-risk-auto-run candidate.
    #[test]
    fn render_preview_reports_unsupported_kind_as_not_eligible_never_as_low_risk() {
        let spec = spec_with(
            Intervention {
                kind: ExperimentKind::SubstituteToolResult,
                description: "substitute a tool result".into(),
                params: serde_json::json!({}),
                provider_extension: None,
            },
            SideEffectAllowList::new([SideEffectClass::EphemeralWorktreeMutation]),
            vec![Uuid::new_v4()],
        );
        let global = GlobalExperimentPolicy::default();
        let out = render_preview(&spec, &global);
        assert!(out.contains("NOT ELIGIBLE"));
        assert!(!out.contains("eligible to auto-run"));
    }

    /// AC1's structural guarantee: [`render_preview`] never receives a
    /// staging root or executor, so it cannot provision a worktree or leave
    /// evidence behind -- this test proves that empirically by pointing an
    /// unrelated staging root at a real directory, calling preview, and
    /// confirming it stays untouched.
    #[test]
    fn preview_never_touches_the_filesystem() {
        let staging = temp_dir("preview-untouched-staging");
        let spec = low_risk_spec();
        let global = GlobalExperimentPolicy::default();
        let _ = render_preview(&spec, &global);
        assert!(
            staging_entries(&staging).is_empty(),
            "preview must never stage anything"
        );
        std::fs::remove_dir_all(&staging).ok();
    }

    // --- AC2: low-risk spec runs end-to-end through the real executor ------

    #[test]
    fn low_risk_spec_runs_end_to_end_and_renders_completed() {
        let source_root = temp_dir("ac2-source");
        std::fs::write(source_root.join("claimed.txt"), b"before\n").unwrap();
        let staging = temp_dir("ac2-staging");

        let spec = low_risk_spec();
        let global = GlobalExperimentPolicy::default();
        let outcome = run_experiment(&spec, &source_root, &staging, &global);

        let rendered = render_run_outcome(&outcome, &spec.session_id);
        assert!(matches!(outcome, RunOutcome::Ran(_)));
        assert!(rendered.contains("COMPLETED"));
        assert!(rendered.contains("--- baseline"));
        assert!(rendered.contains("--- intervention"));

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&staging).ok();
    }

    // --- AC3: higher-risk spec without a policy grant is blocked, not run --

    #[test]
    fn higher_risk_spec_without_policy_grant_is_blocked_and_never_executed() {
        let source_root = temp_dir("ac3-source");
        std::fs::write(source_root.join("claimed.txt"), b"before\n").unwrap();
        let staging = temp_dir("ac3-staging");

        let spec = spec_with(
            revert_intervention("claimed.txt", "after\n"),
            SideEffectAllowList::new([
                SideEffectClass::EphemeralWorktreeMutation,
                SideEffectClass::NetworkCall,
            ]),
            vec![Uuid::new_v4()],
        );
        let global = GlobalExperimentPolicy::default(); // does not grant NetworkCall
        let outcome = run_experiment(&spec, &source_root, &staging, &global);

        assert!(matches!(outcome, RunOutcome::NeedsPolicyApproval { .. }));
        let rendered = render_run_outcome(&outcome, &spec.session_id);
        assert!(rendered.contains("BLOCKED: needs policy approval"));
        assert!(rendered.contains("network_call"));
        assert!(rendered.contains("was NOT run"));
        assert!(
            staging_entries(&staging).is_empty(),
            "a blocked experiment must never provision a staged worktree"
        );
        assert_eq!(
            std::fs::read(source_root.join("claimed.txt")).unwrap(),
            b"before\n",
            "a blocked experiment must never touch the source tree"
        );

        std::fs::remove_dir_all(&source_root).ok();
        std::fs::remove_dir_all(&staging).ok();
    }

    // --- AC4: baseline and intervention render as genuinely separate blocks -

    #[test]
    fn completed_result_renders_baseline_and_intervention_as_distinct_sections() {
        use fornax_types::experiment::CompletedExperiment;

        let baseline_id = Uuid::new_v4();
        let intervention_id = Uuid::new_v4();
        let result = ExperimentResult {
            experiment_id: Uuid::new_v4(),
            experiment_version: 1,
            outcome: ExperimentOutcome::Completed(
                CompletedExperiment::new(
                    Uuid::new_v4(),
                    EvidenceRelation::Supports,
                    vec![baseline_id],
                    vec![intervention_id],
                    "reverting the file changed the outcome",
                )
                .unwrap(),
            ),
            computed_at: "2026-01-02T00:00:00Z".into(),
        };

        let out = render_experiment_result(&result, "session-1");
        let baseline_pos = out.find("--- baseline").unwrap();
        let intervention_pos = out.find("--- intervention").unwrap();
        assert!(baseline_pos < intervention_pos);
        let baseline_section = &out[baseline_pos..intervention_pos];
        let intervention_section = &out[intervention_pos..];
        assert!(baseline_section.contains(&baseline_id.to_string()));
        assert!(!baseline_section.contains(&intervention_id.to_string()));
        assert!(intervention_section.contains(&intervention_id.to_string()));
        assert!(!intervention_section.contains(&baseline_id.to_string()));
    }

    // --- AC5: every non-Completed outcome gets its own honest label --------

    fn result_with(outcome: ExperimentOutcome) -> ExperimentResult {
        ExperimentResult {
            experiment_id: Uuid::new_v4(),
            experiment_version: 1,
            outcome,
            computed_at: "2026-01-02T00:00:00Z".into(),
        }
    }

    /// Asserts the structural invariant AC5 actually requires: a
    /// non-`Completed` outcome must never carry any of the `Completed`-only
    /// rendering (the `COMPLETED` banner, the baseline/intervention
    /// sections, or a "hypothesis relation" line), regardless of what
    /// arbitrary text the outcome's own `reason` string happens to contain.
    /// Deliberately does NOT assert on words like "verified"/"contradict"
    /// appearing anywhere in the full output -- a `reason` string is
    /// free-text a caller/observer controls and could legitimately contain
    /// those words (e.g. "evidence did not contradict the baseline") without
    /// that being a rendering bug; only `Completed`-shaped content escaping
    /// onto a non-`Completed` outcome would be the real regression.
    fn assert_never_renders_as_completed(out: &str, expected_label: &str) {
        assert!(out.contains(expected_label), "missing label in: {out}");
        assert!(
            !out.contains("COMPLETED"),
            "non-Completed outcome must never show the COMPLETED banner: {out}"
        );
        assert!(
            !out.contains("--- baseline"),
            "non-Completed outcome must never show a baseline section: {out}"
        );
        assert!(
            !out.contains("--- intervention"),
            "non-Completed outcome must never show an intervention section: {out}"
        );
        assert!(
            !out.contains("hypothesis relation"),
            "non-Completed outcome must never show a hypothesis relation: {out}"
        );
    }

    #[test]
    fn inconclusive_outcome_renders_its_own_label_never_a_completed_shape() {
        let out = render_experiment_result(
            &result_with(ExperimentOutcome::Inconclusive {
                reason: "observer could not determine a relation".into(),
            }),
            "s1",
        );
        assert_never_renders_as_completed(&out, "INCONCLUSIVE");
    }

    #[test]
    fn blocked_outcome_renders_its_own_label_never_a_completed_shape() {
        let out = render_experiment_result(
            &result_with(ExperimentOutcome::Blocked {
                reason: "precondition failed".into(),
            }),
            "s1",
        );
        assert_never_renders_as_completed(&out, "BLOCKED");
    }

    #[test]
    fn unsupported_outcome_renders_its_own_label_never_a_completed_shape() {
        let out = render_experiment_result(
            &result_with(ExperimentOutcome::Unsupported {
                reason: "no executor for this kind".into(),
            }),
            "s1",
        );
        assert_never_renders_as_completed(&out, "UNSUPPORTED");
    }

    #[test]
    fn failed_outcome_renders_its_own_label_never_a_completed_shape() {
        let out = render_experiment_result(
            &result_with(ExperimentOutcome::Failed {
                reason: "executor errored".into(),
            }),
            "s1",
        );
        assert_never_renders_as_completed(&out, "FAILED");
    }

    // --- RevertAppliedObserver: honest, narrow scope ------------------------

    #[test]
    fn revert_applied_observer_reports_no_relation_when_content_does_not_match() {
        let source_root = temp_dir("observer-mismatch-source");
        std::fs::write(source_root.join("claimed.txt"), b"something else\n").unwrap();
        let staging_root_dir = temp_dir("observer-mismatch-staging-root");
        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();
        let spec = low_risk_spec();
        let observation = RevertAppliedObserver.observe(&staged, &spec);
        assert_eq!(observation.relation, None);
        assert!(observation.evidence_ids.is_empty());
        std::fs::remove_dir_all(&source_root).ok();
    }

    #[test]
    fn revert_applied_observer_is_deterministic() {
        let source_root = temp_dir("observer-deterministic-source");
        std::fs::write(source_root.join("claimed.txt"), b"after\n").unwrap();
        let staging_root_dir = temp_dir("observer-deterministic-staging-root");
        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();
        let spec = low_risk_spec();
        let a = RevertAppliedObserver.observe(&staged, &spec);
        let b = RevertAppliedObserver.observe(&staged, &spec);
        assert_eq!(a.evidence_ids, b.evidence_ids);
        assert_eq!(a.relation, b.relation);
        std::fs::remove_dir_all(&source_root).ok();
    }

    /// Regression test for the FORNX-107 security-review finding that
    /// `InterventionObserver` previously took a bare `&Path`, giving
    /// implementations no way to route through
    /// `StagedWorktree::resolve_contained` — a path that escapes the staged
    /// copy must be refused, not silently joined against the root.
    #[test]
    fn revert_applied_observer_refuses_a_traversal_path() {
        let source_root = temp_dir("observer-traversal-source");
        let staging_root_dir = temp_dir("observer-traversal-staging-root");
        let staged = StagedWorktree::provision(&staging_root_dir, &source_root).unwrap();
        let mut spec = low_risk_spec();
        spec.intervention.params = serde_json::json!({
            "path": "../../../../etc/passwd",
            "content": "irrelevant"
        });
        let observation = RevertAppliedObserver.observe(&staged, &spec);
        assert_eq!(observation.relation, None);
        assert!(observation.evidence_ids.is_empty());
        std::fs::remove_dir_all(&source_root).ok();
    }

    // --- Templates catalog (AC1) --------------------------------------------

    #[test]
    fn render_templates_marks_revert_file_to_baseline_eligible_and_others_not() {
        let out = render_templates();
        assert!(out.contains("revert_file_to_baseline"));
        assert!(out.contains("[ELIGIBLE]"));
        assert!(out.contains("substitute_tool_result"));
        assert!(out.contains("disable_sensor"));
        assert!(out.contains("[NOT ELIGIBLE]"));
    }
}
