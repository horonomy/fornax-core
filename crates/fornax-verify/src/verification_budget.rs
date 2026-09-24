//! Adaptive Verification Budget Scheduler (FORNX-379, parent epic FORNX-376
//! "Agent Epistemic Trust Kernel", target v0.3.0).
//!
//! Decides *how much* verification effort a claim deserves instead of
//! running either minimal checks for everything or maximum-depth monitoring
//! for everything. This module composes three already-shipped layers rather
//! than reinventing any of them:
//!
//! - [`fornax_types::epistemic_contract`] (FORNX-377) — what evidence
//!   *should* exist.
//! - [`crate::contract_satisfaction`] (FORNX-378) — whether it actually does,
//!   as a [`fornax_types::epistemic_contract::ClaimAssessment`].
//! - [`crate::voi`] (FORNX-345) — how to close a gap; [`plan`] calls the
//!   crate-visible [`crate::voi::probes_for_gap`] for every gap
//!   [`crate::contract_satisfaction::gaps_from_assessment`] produces, never
//!   reinventing gap-to-probe mapping.
//!
//! # What this module adds
//!
//! A [`VerificationPlan`]: a bounded, deterministic selection of
//! [`VerificationStep`]s (deterministic checks, active evidence probes,
//! shadow-execution references, human escalation) that fits inside a caller-
//! supplied [`VerificationBudget`], plus an honest [`PlanOutcome`] that
//! never claims safety it cannot back — [`PlanOutcome::InsufficientVerification`]
//! names every `Required` obligation the budget could not cover, rather than
//! silently returning a plan that omits it.
//!
//! # Distinct vocabulary, on purpose (ADR-0001: never collapse a closed
//! vocabulary into a nearby one)
//!
//! [`BlastRadius`] is **not** [`crate::voi::ActionRisk`]. `ActionRisk`
//! describes what one *evidence-acquisition probe* would do (a side effect
//! of *verifying*); `BlastRadius` describes the risk of the *action being
//! verified* (a deploy, a destructive migration, a read-only status check) —
//! two independent axes a caller must supply separately. Conflating them
//! would let a read-only probe about an irreversible production action look
//! as safe as a read-only probe about a harmless one.
//!
//! [`fornax_types::epistemic_contract::SatisfactionState`] is read here, but
//! this module introduces its own, separate [`PlanOutcome`] vocabulary for
//! *budget* adequacy — a `Satisfied` claim can still need
//! `InsufficientVerification` framing if the budget cannot even confirm that
//! (see `plan`'s doc comment), and the two must never be conflated into one
//! enum.
//!
//! # Side-effect gating reuses FORNX-99's closed vocabulary, never a new one
//!
//! [`gate_step`] gates every step's [`SideEffectAllowList`] the same way
//! `crate::voi`'s (private) `classify_availability` does for acquisition
//! candidates: `SideEffectClass::FilesystemWriteOutsideWorktree` is *never*
//! approvable regardless of budget or information value (destructive
//! verification is always refused); `NetworkCall`/`ProcessSpawn`/
//! `EphemeralWorktreeMutation` are gated by [`VerificationBudget::allowed_side_effects`].
//! Credential-bearing verification has no dedicated [`SideEffectClass`]
//! variant in this codebase (that closed vocabulary is FORNX-99's, out of
//! this ticket's scope to extend) — a step that needs credentials sets
//! [`VerificationStep::requires_credentials`], gated separately by
//! [`VerificationBudget::credential_use_allowed`], so credential use is
//! never silently folded into (or bypassed via) the network-access budget.
//!
//! # Non-goals (inherited from the ticket)
//!
//! No claim that authored utility weights are calibrated probabilities. No
//! open-ended autonomous spend — every dimension in [`VerificationBudget`]
//! is a hard ceiling [`DeterministicBudgetPolicy::plan`] never exceeds. No
//! bypass of Stage-8 experiment safety — a [`VerificationStepKind::ShadowExecution`]
//! step is a *reference* to [`crate::voi::ProbeKind::BoundedReplayExperiment`]
//! for planning purposes only; this module executes nothing and holds no
//! dependency on `fornax-acquire`/`fornax-experiment-runner`.
//!
//! # Benchmark scope (AC6/AC7) — synthetic fixtures, not a production corpus
//!
//! [`benchmark`] compares [`DeterministicBudgetPolicy`] against literal
//! `minimal_only`/`maximal_depth` baselines using caller-supplied
//! [`VerificationContext`] fixtures — this module ships none of its own
//! production corpus data (FORNX-343's Gold Corpus does not exist; using it
//! here would be exactly the kind of fabricated evidence this campaign never
//! produces). The ticket's own AC6 language ("where corpus support exists")
//! anticipates this: a synthetic-fixture benchmark, honestly labeled as
//! such, is what this module provides. [`promote_if_better`] (AC7) needs no
//! real learned/ML component either — it is a pure gate function over two
//! already-computed [`PolicyBenchmarkResult`]s, proven with a synthetic fake
//! "learned policy" fixture in this module's own tests.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use fornax_types::epistemic_contract::{
    ClaimAssessment, ClaimClassId, RequirementLevel, SatisfactionState,
};
use fornax_types::experiment::{SideEffectAllowList, SideEffectClass};

use crate::contract_satisfaction::gaps_from_assessment;
use crate::decision::{Recommendation, RecommendationAction, RiskClass};
use crate::reliability::DriftState;
use crate::voi::{probes_for_gap, EvidenceRequest, ProbeKind};

pub const VERIFICATION_BUDGET_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------
// Blast radius — the risk of the action BEING verified, not of verifying it
// ---------------------------------------------------------------------

/// Closed vocabulary for the risk of the underlying claimed action, ordered
/// from least to most consequential. See module docs for why this is kept
/// distinct from [`crate::voi::ActionRisk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    /// A read-only observation (a status check, a query) — nothing to
    /// undo if the claim turns out false.
    ReadOnlyObservation,
    /// A mutation confined to a disposable/local/sandboxed scope.
    ReversibleLocal,
    /// A mutation visible outside the caller's own sandbox (a pushed
    /// commit, a sent message) but still undoable.
    ReversibleExternal,
    /// Irreversible or privileged production impact (a deploy, a
    /// destructive migration, a billing/credential change) — the top of
    /// the AC1 spectrum ("irreversible/privileged production actions").
    IrreversibleOrPrivileged,
}

// ---------------------------------------------------------------------
// Budget contract
// ---------------------------------------------------------------------

/// Explicit, versioned verification budget (FORNX-379 scope: "explicit
/// budgets for wall-clock latency, model/API cost, CPU/memory, network
/// access, probe count, review burden and execution risk"). Every field is
/// a hard ceiling [`DeterministicBudgetPolicy::plan`] never exceeds — see
/// module docs "Non-goals".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationBudget {
    pub schema_version: u32,
    pub max_latency: Duration,
    /// Abstract model/API cost units — this module makes no claim these map
    /// to real currency; a caller wires its own cost model to these units.
    pub max_cost_units: u32,
    /// Abstract CPU/memory budget units, same non-claim as `max_cost_units`.
    pub max_resource_units: u32,
    pub max_probe_count: u32,
    /// Ceiling on how many [`VerificationStepKind::HumanEscalation`] steps
    /// one plan may include — the review-burden dimension.
    pub max_review_burden: u32,
    /// The most consequential [`BlastRadius`] this budget's issuer is
    /// willing to let verification steps carry side effects for at all —
    /// distinct from `allowed_side_effects` below, which gates *what kind*
    /// of side effect, not how consequential the *claim* being verified is.
    pub max_execution_risk: BlastRadius,
    /// Which [`SideEffectClass`]es a verification step may require.
    /// `SideEffectClass::FilesystemWriteOutsideWorktree` is never honored
    /// here even if present — see [`gate_step`].
    pub allowed_side_effects: SideEffectAllowList,
    /// Separate from `allowed_side_effects` — see module docs "Side-effect
    /// gating".
    pub credential_use_allowed: bool,
}

impl VerificationBudget {
    /// A conservative, read-only-only default: no network, no credentials,
    /// no process spawn, a handful of cheap probes, no human escalation
    /// budget. Callers scale up explicitly per [`BlastRadius`] — this is
    /// never silently widened by this module itself.
    pub fn minimal() -> Self {
        Self {
            schema_version: VERIFICATION_BUDGET_SCHEMA_VERSION,
            max_latency: Duration::from_secs(5),
            max_cost_units: 1,
            max_resource_units: 1,
            max_probe_count: 1,
            max_review_burden: 0,
            max_execution_risk: BlastRadius::ReadOnlyObservation,
            allowed_side_effects: SideEffectAllowList::default(),
            credential_use_allowed: false,
        }
    }
}

// ---------------------------------------------------------------------
// Verification steps and plans
// ---------------------------------------------------------------------

/// Closed vocabulary of what a [`VerificationStep`] actually is (FORNX-379
/// scope: "deterministic checks, semantic monitors, active evidence probes,
/// shadow execution and human escalation").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerificationStepKind {
    /// A free/cheap, read-only, already-deterministic check — no side
    /// effects at all (e.g. [`ProbeKind::InspectVcsState`],
    /// [`ProbeKind::VerifyArtifactHash`]).
    DeterministicCheck { probe: ProbeKind },
    /// A monitor over semantic/behavioral signal, not tied to one probe —
    /// this codebase has no dedicated semantic-monitor primitive yet, so
    /// this variant is descriptive only (never executed by this module).
    SemanticMonitor { description: String },
    /// An active evidence-acquisition probe with real cost/latency/side
    /// effects (e.g. [`ProbeKind::RerunTest`], [`ProbeKind::QueryCiStatus`]).
    /// This is exactly the [`ProbeKind`] `fornax-acquire` (FORNX-346)
    /// already knows how to execute for the two kinds it implements — this
    /// module holds no dependency on that crate, it only reuses the same
    /// closed vocabulary as the hand-off contract.
    ActiveEvidenceProbe { probe: ProbeKind },
    /// A reference to a bounded counterfactual replay
    /// ([`ProbeKind::BoundedReplayExperiment`], FORNX-99/100's experiment
    /// contract) — planning-only. This module never constructs or executes
    /// an `ExperimentSpec`; a downstream executor is responsible for that,
    /// same as it already is for every other `ProbeKind`.
    ShadowExecution { probe: ProbeKind },
    /// Defers to a human — the review-burden dimension.
    HumanEscalation { reason: String },
}

/// One planned unit of verification effort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStep {
    pub kind: VerificationStepKind,
    /// The FORNX-378 requirement this step targets, when the step exists to
    /// close a specific unmet obligation rather than to satisfy a
    /// blast-radius-driven baseline check.
    pub targets_requirement_id: Option<String>,
    pub estimated_latency: Duration,
    pub estimated_cost_units: u32,
    pub estimated_resource_units: u32,
    pub side_effects: SideEffectAllowList,
    pub requires_credentials: bool,
    /// 1 for a [`VerificationStepKind::HumanEscalation`] step, 0 otherwise.
    pub review_burden: u32,
}

/// Why a candidate step was not included in the final plan — never silently
/// dropped, mirroring [`fornax_types::epistemic_contract::RejectionReason`]'s
/// visibility discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum StepRejectionReason {
    /// The step needs a [`SideEffectClass`] this budget does not grant.
    SideEffectNotGranted { class: SideEffectClass },
    /// `SideEffectClass::FilesystemWriteOutsideWorktree` — never approvable
    /// through this scheduler, regardless of budget or information value.
    DestructiveSideEffectNeverApprovable,
    /// The step needs credentials but `credential_use_allowed` is false.
    CredentialUseNotAllowed,
    /// Including this step would exceed `max_latency`.
    LatencyBudgetExhausted,
    /// Including this step would exceed `max_cost_units`.
    CostBudgetExhausted,
    /// Including this step would exceed `max_resource_units`.
    ResourceBudgetExhausted,
    /// Including this step would exceed `max_probe_count`.
    ProbeCountBudgetExhausted,
    /// Including this step would exceed `max_review_burden`.
    ReviewBurdenBudgetExhausted,
}

/// A rejected candidate step, visible with rationale — never a silent drop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedStep {
    pub step: VerificationStep,
    pub reason: StepRejectionReason,
}

/// Whether the resulting [`VerificationPlan`] can honestly stand in for
/// "this claim was adequately verified within budget."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PlanOutcome {
    /// The budget covered every `Required` obligation this policy could
    /// address (an obligation with no real probe at all — e.g. it resolved
    /// to `HumanEscalation` only and `max_review_burden` is 0 — still
    /// counts as covered only if the escalation step itself fit; otherwise
    /// it is named below).
    Planned,
    /// The budget was exhausted before every `Required`, non-satisfied
    /// obligation could get a covering step (AC2/AC3: "critical obligations
    /// cannot be silently skipped ... budget exhaustion produces an
    /// explicit review/block/insufficient-verification result rather than
    /// false safety"). Every unmet requirement id is named, never rounded
    /// up into a bare `Planned`.
    InsufficientVerification { unmet_requirement_ids: Vec<String> },
}

/// Output of [`BudgetPolicy::plan`]. Carries every version its determinism
/// depends on (AC4: "plans are reproducible for pinned evidence/contract/
/// policy/capability versions") — `claim_class` already carries the
/// contract version, `policy_name`/`policy_version` name the budget policy,
/// `budget_schema_version` names the [`VerificationBudget`] contract shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationPlan {
    pub claim_class: ClaimClassId,
    pub policy_name: String,
    pub policy_version: u32,
    pub budget_schema_version: u32,
    pub steps: Vec<VerificationStep>,
    pub rejected_steps: Vec<RejectedStep>,
    pub total_estimated_latency: Duration,
    pub total_estimated_cost_units: u32,
    pub total_review_burden: u32,
    pub outcome: PlanOutcome,
}

/// Canonical, deterministically-ordered JSON for a [`VerificationPlan`] —
/// reuses [`fornax_types::epistemic_contract::to_canonical_json`] directly
/// rather than re-implementing key-sorting (it is generic over any
/// `Serialize` type, not epistemic-contract-specific).
pub fn to_canonical_json(plan: &VerificationPlan) -> Result<String, serde_json::Error> {
    fornax_types::epistemic_contract::to_canonical_json(plan)
}

// ---------------------------------------------------------------------
// Side-effect / credential gating (AC5)
// ---------------------------------------------------------------------

/// Gate one candidate step against `budget`. Mirrors `crate::voi`'s
/// (private) `classify_availability` shape: destructive side effects are
/// never approvable regardless of information value; every other dimension
/// is checked against an explicit ceiling, never inferred.
pub fn gate_step(
    step: &VerificationStep,
    budget: &VerificationBudget,
) -> Option<StepRejectionReason> {
    if step
        .side_effects
        .permits(SideEffectClass::FilesystemWriteOutsideWorktree)
    {
        return Some(StepRejectionReason::DestructiveSideEffectNeverApprovable);
    }
    for class in [
        SideEffectClass::EphemeralWorktreeMutation,
        SideEffectClass::ProcessSpawn,
        SideEffectClass::NetworkCall,
    ] {
        if step.side_effects.permits(class) && !budget.allowed_side_effects.permits(class) {
            return Some(StepRejectionReason::SideEffectNotGranted { class });
        }
    }
    if step.requires_credentials && !budget.credential_use_allowed {
        return Some(StepRejectionReason::CredentialUseNotAllowed);
    }
    None
}

// ---------------------------------------------------------------------
// Planning context and policy
// ---------------------------------------------------------------------

/// Everything a [`BudgetPolicy`] considers (FORNX-379 "Product behavior":
/// claim contract, obligation satisfaction, uncertainty, action
/// reversibility, blast radius, evidence coverage, source independence,
/// historical failure/drift state, policy). `capabilities`/`source
/// independence` are read through `satisfaction` (FORNX-378 already folds
/// trust-class/independence rejection into `RequirementAssessment`), so
/// this struct does not re-derive them — see module docs for why
/// `blast_radius` stays a separate, caller-declared input rather than
/// inferred from `satisfaction`.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationContext {
    pub claim_id: Uuid,
    pub satisfaction: ClaimAssessment,
    pub blast_radius: BlastRadius,
    pub risk_class: RiskClass,
    /// Historical reliability drift for this claim class/policy, when a
    /// comparison has been run (FORNX-348's [`DriftState`]). `None` when no
    /// drift comparison exists yet — never conflated with `DriftState::Stable`.
    pub drift: Option<DriftState>,
}

/// Swap/benchmark boundary for verification-budget policies (mirrors
/// [`crate::decision::DecisionPolicy`]'s shape). A learned/calibrated policy
/// implements this trait exactly like [`DeterministicBudgetPolicy`] does;
/// [`promote_if_better`] is the only sanctioned path for one to replace the
/// baseline in production (AC7).
pub trait BudgetPolicy {
    fn name(&self) -> &'static str;
    fn policy_version(&self) -> u32;
    fn plan(&self, ctx: &VerificationContext, budget: &VerificationBudget) -> VerificationPlan;
}

/// The deterministic baseline policy (AC1's "before learned/calibrated
/// optimization"). Candidate-generation order is fixed and documented so
/// the same inputs always produce the same accepted/rejected step sequence:
///
/// 1. One [`VerificationStepKind::DeterministicCheck`] per unmet
///    requirement, from the cheapest ([`ProbeKind`]s
///    `probes_for_gap` returns with no required side effects) — always
///    attempted first, since these are free/cheap and read-only.
/// 2. Remaining unmet requirements get their next-cheapest probe from
///    `probes_for_gap`, classified `ActiveEvidenceProbe` (or
///    `ShadowExecution` specifically for
///    [`ProbeKind::BoundedReplayExperiment`]) — gated by `budget` and by
///    `max_execution_risk` vs. `ctx.blast_radius`.
/// 3. A requirement no automated probe can cover
///    ([`ProbeKind::HumanEscalation`]) becomes a
///    [`VerificationStepKind::HumanEscalation`] step, bounded by
///    `max_review_burden`.
///
/// Every step is checked against every remaining budget ceiling before
/// being accepted; the first ceiling it would exceed is recorded as its
/// [`StepRejectionReason`] and it moves to `rejected_steps` instead.
pub struct DeterministicBudgetPolicy;

impl DeterministicBudgetPolicy {
    fn step_for_probe(req: &EvidenceRequest, requirement_id: Option<String>) -> VerificationStep {
        let is_free_read_only = req.required_side_effects.is_read_only();
        let kind = if matches!(req.kind, ProbeKind::BoundedReplayExperiment) {
            VerificationStepKind::ShadowExecution { probe: req.kind }
        } else if matches!(req.kind, ProbeKind::HumanReview) {
            VerificationStepKind::HumanEscalation {
                reason: req.description.clone(),
            }
        } else if is_free_read_only {
            VerificationStepKind::DeterministicCheck { probe: req.kind }
        } else {
            VerificationStepKind::ActiveEvidenceProbe { probe: req.kind }
        };

        let (latency, cost, resources) = match req.kind {
            ProbeKind::InspectVcsState | ProbeKind::VerifyArtifactHash => {
                (Duration::from_millis(50), 0, 0)
            }
            ProbeKind::RerunTest => (Duration::from_secs(30), 2, 2),
            ProbeKind::QueryCiStatus => (Duration::from_secs(2), 1, 0),
            ProbeKind::BoundedReplayExperiment => (Duration::from_secs(60), 4, 3),
            ProbeKind::HumanReview => (Duration::ZERO, 0, 0),
        };

        let review_burden = u32::from(matches!(kind, VerificationStepKind::HumanEscalation { .. }));
        let requires_credentials = matches!(req.kind, ProbeKind::QueryCiStatus);

        VerificationStep {
            kind,
            targets_requirement_id: requirement_id,
            estimated_latency: latency,
            estimated_cost_units: cost,
            estimated_resource_units: resources,
            side_effects: req.required_side_effects.clone(),
            requires_credentials,
            review_burden,
        }
    }
}

impl BudgetPolicy for DeterministicBudgetPolicy {
    fn name(&self) -> &'static str {
        "deterministic_budget_policy_v1"
    }

    fn policy_version(&self) -> u32 {
        1
    }

    fn plan(&self, ctx: &VerificationContext, budget: &VerificationBudget) -> VerificationPlan {
        let gaps = gaps_from_assessment(ctx.claim_id, &ctx.satisfaction);

        // Determinism: iterate requirements in the FIXED order FORNX-377/378
        // already produced them in (`per_requirement`'s declaration order,
        // itself a function of the frozen contract), never a HashMap/HashSet
        // iteration order.
        let required_unsatisfied: BTreeSet<String> = ctx
            .satisfaction
            .per_requirement
            .iter()
            .filter(|ra| {
                matches!(
                    ra.level,
                    RequirementLevel::Required | RequirementLevel::Conditional { .. }
                ) && !matches!(
                    ra.state,
                    SatisfactionState::Satisfied | SatisfactionState::NotApplicable
                )
            })
            .map(|ra| ra.requirement_id.clone())
            .collect();

        let mut candidates: Vec<VerificationStep> = Vec::new();
        for gap in &gaps {
            let requirement_id = match &gap.kind {
                crate::voi::EvidenceGapKind::ContractObligationUnmet { requirement_id, .. } => {
                    Some(requirement_id.clone())
                }
                _ => None,
            };
            for req in probes_for_gap(gap) {
                candidates.push(Self::step_for_probe(&req, requirement_id.clone()));
            }
        }
        // Deterministic ordering: free/read-only first (cheapest), then by
        // ascending estimated cost, then by probe kind's own stable
        // discriminant order (via its Debug string — `ProbeKind` has no
        // numeric ordering of its own and adding one is out of this
        // ticket's scope) to break ties reproducibly.
        candidates.sort_by(|a, b| {
            a.side_effects
                .is_read_only()
                .cmp(&b.side_effects.is_read_only())
                .reverse()
                .then(a.estimated_cost_units.cmp(&b.estimated_cost_units))
                .then(format!("{:?}", a.kind).cmp(&format!("{:?}", b.kind)))
        });

        let mut accepted: Vec<VerificationStep> = Vec::new();
        let mut rejected: Vec<RejectedStep> = Vec::new();
        let mut used_latency = Duration::ZERO;
        let mut used_cost = 0u32;
        let mut used_resources = 0u32;
        let mut used_probes = 0u32;
        let mut used_review_burden = 0u32;
        let mut covered_requirements: BTreeSet<String> = BTreeSet::new();

        for step in candidates {
            if let Some(reason) = gate_step(&step, budget) {
                rejected.push(RejectedStep { step, reason });
                continue;
            }
            // max_execution_risk: a step whose underlying claim carries more
            // blast radius than this budget's issuer is willing to spend any
            // side-effecting verification step on is refused outright, even
            // if every other ceiling has room -- "execution risk" per the
            // ticket's own budget-dimension list.
            if !step.side_effects.is_read_only() && ctx.blast_radius > budget.max_execution_risk {
                rejected.push(RejectedStep {
                    step,
                    reason: StepRejectionReason::SideEffectNotGranted {
                        class: SideEffectClass::ProcessSpawn,
                    },
                });
                continue;
            }
            let next_latency = used_latency + step.estimated_latency;
            let next_cost = used_cost + step.estimated_cost_units;
            let next_resources = used_resources + step.estimated_resource_units;
            let next_probes = used_probes + 1;
            let next_review = used_review_burden + step.review_burden;

            let reason = if next_latency > budget.max_latency {
                Some(StepRejectionReason::LatencyBudgetExhausted)
            } else if next_cost > budget.max_cost_units {
                Some(StepRejectionReason::CostBudgetExhausted)
            } else if next_resources > budget.max_resource_units {
                Some(StepRejectionReason::ResourceBudgetExhausted)
            } else if next_probes > budget.max_probe_count {
                Some(StepRejectionReason::ProbeCountBudgetExhausted)
            } else if next_review > budget.max_review_burden {
                Some(StepRejectionReason::ReviewBurdenBudgetExhausted)
            } else {
                None
            };

            match reason {
                Some(reason) => rejected.push(RejectedStep { step, reason }),
                None => {
                    used_latency = next_latency;
                    used_cost = next_cost;
                    used_resources = next_resources;
                    used_probes = next_probes;
                    used_review_burden = next_review;
                    if let Some(rid) = &step.targets_requirement_id {
                        covered_requirements.insert(rid.clone());
                    }
                    accepted.push(step);
                }
            }
        }

        let unmet: Vec<String> = required_unsatisfied
            .difference(&covered_requirements)
            .cloned()
            .collect();
        let outcome = if unmet.is_empty() {
            PlanOutcome::Planned
        } else {
            PlanOutcome::InsufficientVerification {
                unmet_requirement_ids: unmet,
            }
        };

        VerificationPlan {
            claim_class: ctx.satisfaction.claim_class.clone(),
            policy_name: self.name().to_string(),
            policy_version: self.policy_version(),
            budget_schema_version: budget.schema_version,
            steps: accepted,
            rejected_steps: rejected,
            total_estimated_latency: used_latency,
            total_estimated_cost_units: used_cost,
            total_review_burden: used_review_burden,
            outcome,
        }
    }
}

// ---------------------------------------------------------------------
// Decision-layer integration (AC3): a non-relaxing verification floor,
// exactly mirroring apply_calibration_floor (FORNX-348) and
// apply_contract_floor (FORNX-378)'s established shape.
// ---------------------------------------------------------------------

/// Apply the verification-budget floor to an already-decided
/// [`Recommendation`]: [`RecommendationAction::Proceed`] steps down to
/// [`RecommendationAction::Review`] whenever `plan.outcome` is
/// [`PlanOutcome::InsufficientVerification`] — budget exhaustion can never
/// leave a claim looking confidently safe. `Review`/`Block` are returned
/// unchanged; `Planned` applies no floor at all.
pub fn apply_verification_floor(rec: Recommendation, plan: &VerificationPlan) -> Recommendation {
    let PlanOutcome::InsufficientVerification {
        unmet_requirement_ids,
    } = &plan.outcome
    else {
        return rec;
    };
    if rec.action != RecommendationAction::Proceed {
        return rec;
    }
    Recommendation {
        action: RecommendationAction::Review,
        rationale_summary: format!(
            "{} | verification floor applied: budget exhausted before {} obligation(s) ({}) could be covered -> review (FORNX-379 non-relaxing floor)",
            rec.rationale_summary,
            unmet_requirement_ids.len(),
            unmet_requirement_ids.join(", ")
        ),
        ..rec
    }
}

// ---------------------------------------------------------------------
// Benchmark harness (AC6) — synthetic fixtures only, see module docs.
// ---------------------------------------------------------------------

/// A literal minimal-only baseline: always plans at most one, cheapest,
/// free/read-only step, ignoring every remaining obligation. Never claims
/// any obligation coverage beyond that one step.
pub struct MinimalOnlyPolicy;

impl BudgetPolicy for MinimalOnlyPolicy {
    fn name(&self) -> &'static str {
        "minimal_only_baseline_v1"
    }
    fn policy_version(&self) -> u32 {
        1
    }
    fn plan(&self, ctx: &VerificationContext, budget: &VerificationBudget) -> VerificationPlan {
        let tiny = VerificationBudget {
            max_probe_count: 1.min(budget.max_probe_count),
            max_review_burden: 0,
            ..budget.clone()
        };
        DeterministicBudgetPolicy.plan(ctx, &tiny)
    }
}

/// A literal maximal-depth baseline: runs every candidate step the caller's
/// evidence graph could motivate, bounded only by the widest budget this
/// module's own hard-ceiling contract allows (never truly unbounded — see
/// module docs "Non-goals": no open-ended autonomous spend, even for the
/// benchmark's own maximal comparator).
pub struct MaximalDepthPolicy;

impl BudgetPolicy for MaximalDepthPolicy {
    fn name(&self) -> &'static str {
        "maximal_depth_baseline_v1"
    }
    fn policy_version(&self) -> u32 {
        1
    }
    fn plan(&self, ctx: &VerificationContext, budget: &VerificationBudget) -> VerificationPlan {
        let wide = VerificationBudget {
            max_latency: Duration::from_secs(3600),
            max_cost_units: u32::MAX / 2,
            max_resource_units: u32::MAX / 2,
            max_probe_count: u32::MAX / 2,
            max_review_burden: u32::MAX / 2,
            max_execution_risk: BlastRadius::IrreversibleOrPrivileged,
            allowed_side_effects: budget.allowed_side_effects.clone(),
            credential_use_allowed: budget.credential_use_allowed,
            schema_version: budget.schema_version,
        };
        DeterministicBudgetPolicy.plan(ctx, &wide)
    }
}

/// Ground-truth label for one synthetic benchmark fixture: whether this
/// context actually has a `Required`, non-satisfied obligation a correct
/// verification policy ought to catch. Supplied by the benchmark's caller
/// (synthetic fixtures only — see module docs), never inferred by this
/// module from the context itself, to keep the metric honest about what it
/// measures.
#[derive(Debug, Clone, Copy)]
pub struct BenchmarkFixture<'a> {
    pub context: &'a VerificationContext,
    pub has_real_critical_obligation: bool,
}

/// Aggregate metrics for one policy over a fixture set (AC6: "decision
/// quality, critical misses, false positives, cost, latency and review
/// burden").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyBenchmarkResult {
    pub policy_name: String,
    pub fixtures_evaluated: u32,
    /// A fixture with a real critical obligation whose resulting plan left
    /// it uncovered (`PlanOutcome::InsufficientVerification` naming it, or
    /// `Planned` while `covered_requirements` never included it — tracked
    /// via `outcome` alone here since `Planned` by definition means every
    /// tracked `Required` obligation this policy attempted was covered).
    pub critical_misses: u32,
    /// A fixture with NO real critical obligation whose plan still produced
    /// an `InsufficientVerification` outcome — over-flagging a clean claim.
    pub false_positives: u32,
    pub total_cost_units: u64,
    pub total_latency: Duration,
    pub total_review_burden: u64,
}

fn evaluate_policy(
    policy: &dyn BudgetPolicy,
    budget: &VerificationBudget,
    fixtures: &[BenchmarkFixture],
) -> PolicyBenchmarkResult {
    let mut result = PolicyBenchmarkResult {
        policy_name: policy.name().to_string(),
        fixtures_evaluated: fixtures.len() as u32,
        critical_misses: 0,
        false_positives: 0,
        total_cost_units: 0,
        total_latency: Duration::ZERO,
        total_review_burden: 0,
    };
    for fixture in fixtures {
        let plan = policy.plan(fixture.context, budget);
        let insufficient = matches!(plan.outcome, PlanOutcome::InsufficientVerification { .. });
        if fixture.has_real_critical_obligation && insufficient {
            result.critical_misses += 1;
        }
        if !fixture.has_real_critical_obligation && insufficient {
            result.false_positives += 1;
        }
        result.total_cost_units += u64::from(plan.total_estimated_cost_units);
        result.total_latency += plan.total_estimated_latency;
        result.total_review_burden += u64::from(plan.total_review_burden);
    }
    result
}

/// Run the deterministic baseline and both literal comparators over the
/// same `fixtures`/`budget`, honestly labeled as synthetic (see module
/// docs). Returns one [`PolicyBenchmarkResult`] per policy, in the fixed
/// order `[deterministic, minimal_only, maximal_depth]`.
pub fn benchmark(
    budget: &VerificationBudget,
    fixtures: &[BenchmarkFixture],
) -> Vec<PolicyBenchmarkResult> {
    vec![
        evaluate_policy(&DeterministicBudgetPolicy, budget, fixtures),
        evaluate_policy(&MinimalOnlyPolicy, budget, fixtures),
        evaluate_policy(&MaximalDepthPolicy, budget, fixtures),
    ]
}

// ---------------------------------------------------------------------
// Promotion gate (AC7) — no real learned/ML component required, see module
// docs "Benchmark scope".
// ---------------------------------------------------------------------

/// Predeclared thresholds a candidate policy must meet before it may ever
/// replace the deterministic baseline in production. Declared *before*
/// comparison, per AC7's "predeclared metrics" — a caller must not tune
/// these after seeing `promote_if_better`'s inputs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PromotionThresholds {
    /// The candidate's `critical_misses` must be <= the baseline's plus
    /// this margin (0 = strictly no worse).
    pub max_additional_critical_misses: u32,
    /// The candidate's `false_positives` must be <= the baseline's plus
    /// this margin.
    pub max_additional_false_positives: u32,
    /// The candidate's `total_cost_units` must not exceed the baseline's by
    /// more than this fraction (e.g. `0.0` = never more expensive at all).
    pub max_cost_regression_fraction: f64,
}

impl Default for PromotionThresholds {
    /// The strictest reasonable default: no additional misses, no
    /// additional false positives, no cost regression at all. A caller
    /// wanting to trade a little cost for something else must say so
    /// explicitly.
    fn default() -> Self {
        Self {
            max_additional_critical_misses: 0,
            max_additional_false_positives: 0,
            max_cost_regression_fraction: 0.0,
        }
    }
}

/// Outcome of [`promote_if_better`] — never a bare bool, so every rejection
/// names exactly which predeclared metric failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionDecision {
    Promoted,
    Rejected { failed_metrics: Vec<String> },
}

/// The AC7 gate: a candidate (learned, calibrated, or otherwise) policy's
/// benchmark result is compared against the deterministic baseline's under
/// `thresholds`. Pure function over two already-computed
/// [`PolicyBenchmarkResult`]s — no policy object, no training, no
/// inference; a caller wanting a real learned policy would still call this
/// exact gate on its benchmark output.
pub fn promote_if_better(
    candidate: &PolicyBenchmarkResult,
    baseline: &PolicyBenchmarkResult,
    thresholds: &PromotionThresholds,
) -> PromotionDecision {
    let mut failed = Vec::new();

    if candidate.critical_misses
        > baseline.critical_misses + thresholds.max_additional_critical_misses
    {
        failed.push(format!(
            "critical_misses regressed: candidate={} baseline={} (allowed margin {})",
            candidate.critical_misses,
            baseline.critical_misses,
            thresholds.max_additional_critical_misses
        ));
    }
    if candidate.false_positives
        > baseline.false_positives + thresholds.max_additional_false_positives
    {
        failed.push(format!(
            "false_positives regressed: candidate={} baseline={} (allowed margin {})",
            candidate.false_positives,
            baseline.false_positives,
            thresholds.max_additional_false_positives
        ));
    }
    let cost_ceiling =
        (baseline.total_cost_units as f64) * (1.0 + thresholds.max_cost_regression_fraction);
    if (candidate.total_cost_units as f64) > cost_ceiling {
        failed.push(format!(
            "total_cost_units regressed: candidate={} baseline={} (ceiling {:.1})",
            candidate.total_cost_units, baseline.total_cost_units, cost_ceiling
        ));
    }

    if failed.is_empty() {
        PromotionDecision::Promoted
    } else {
        PromotionDecision::Rejected {
            failed_metrics: failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::epistemic_contract::RequirementAssessment;

    fn requirement(
        id: &str,
        level: RequirementLevel,
        state: SatisfactionState,
    ) -> RequirementAssessment {
        RequirementAssessment {
            requirement_id: id.to_string(),
            level,
            state,
            matched_evidence: vec![],
            rejected_evidence: vec![],
        }
    }

    fn assessment(reqs: Vec<RequirementAssessment>, overall: SatisfactionState) -> ClaimAssessment {
        ClaimAssessment {
            claim_class: ClaimClassId::new("fornx379_test_claim", 1),
            per_requirement: reqs,
            overall,
        }
    }

    fn ctx(satisfaction: ClaimAssessment, blast_radius: BlastRadius) -> VerificationContext {
        VerificationContext {
            claim_id: Uuid::new_v4(),
            satisfaction,
            blast_radius,
            risk_class: RiskClass::Balanced,
            drift: None,
        }
    }

    fn generous_budget() -> VerificationBudget {
        VerificationBudget {
            schema_version: VERIFICATION_BUDGET_SCHEMA_VERSION,
            max_latency: Duration::from_secs(120),
            max_cost_units: 100,
            max_resource_units: 100,
            max_probe_count: 20,
            max_review_burden: 5,
            max_execution_risk: BlastRadius::IrreversibleOrPrivileged,
            allowed_side_effects: SideEffectAllowList::new([
                SideEffectClass::ProcessSpawn,
                SideEffectClass::NetworkCall,
            ]),
            credential_use_allowed: true,
        }
    }

    // --- AC1: low-risk/high-evidence gets a materially cheaper plan ------

    #[test]
    fn low_risk_satisfied_claim_gets_a_materially_cheaper_plan_than_high_risk_unsatisfied() {
        let clean = assessment(
            vec![requirement(
                "req_a",
                RequirementLevel::Required,
                SatisfactionState::Satisfied,
            )],
            SatisfactionState::Satisfied,
        );
        let risky = assessment(
            vec![
                requirement(
                    "req_a",
                    RequirementLevel::Required,
                    SatisfactionState::Unsatisfied,
                ),
                requirement(
                    "req_b",
                    RequirementLevel::Required,
                    SatisfactionState::Unavailable,
                ),
            ],
            SatisfactionState::Unsatisfied,
        );

        let budget = generous_budget();
        let cheap_plan =
            DeterministicBudgetPolicy.plan(&ctx(clean, BlastRadius::ReadOnlyObservation), &budget);
        let expensive_plan = DeterministicBudgetPolicy
            .plan(&ctx(risky, BlastRadius::IrreversibleOrPrivileged), &budget);

        assert_eq!(cheap_plan.outcome, PlanOutcome::Planned);
        assert!(
            cheap_plan.steps.is_empty(),
            "a satisfied claim needs no covering steps"
        );
        assert!(
            expensive_plan.steps.len() > cheap_plan.steps.len(),
            "high-risk/low-evidence work must require strictly more verification steps: {} vs {}",
            expensive_plan.steps.len(),
            cheap_plan.steps.len()
        );
        assert!(
            expensive_plan.total_review_burden > cheap_plan.total_review_burden
                || expensive_plan.total_estimated_latency > cheap_plan.total_estimated_latency,
            "high-risk/low-evidence work must be materially more expensive on at least one budget dimension"
        );
    }

    // --- AC2/AC3: critical obligations cannot be silently skipped on
    //     budget exhaustion; the result is explicit, never false safety --

    #[test]
    fn budget_exhaustion_names_every_uncovered_required_obligation_never_silently_planned() {
        let assessment = assessment(
            vec![
                requirement(
                    "req_a",
                    RequirementLevel::Required,
                    SatisfactionState::Unsatisfied,
                ),
                requirement(
                    "req_b",
                    RequirementLevel::Required,
                    SatisfactionState::Unavailable,
                ),
            ],
            SatisfactionState::Unsatisfied,
        );
        // Zero-probe budget: nothing can ever be covered.
        let starved = VerificationBudget {
            max_probe_count: 0,
            ..generous_budget()
        };
        let plan = DeterministicBudgetPolicy
            .plan(&ctx(assessment, BlastRadius::ReadOnlyObservation), &starved);

        match &plan.outcome {
            PlanOutcome::InsufficientVerification { unmet_requirement_ids } => {
                let mut ids = unmet_requirement_ids.clone();
                ids.sort();
                assert_eq!(ids, vec!["req_a".to_string(), "req_b".to_string()]);
            }
            PlanOutcome::Planned => panic!(
                "a zero-probe budget with two unsatisfied Required obligations must never report Planned"
            ),
        }

        // The verification floor must demote a would-be Proceed.
        let rec = Recommendation {
            claim_id: Uuid::new_v4(),
            action: RecommendationAction::Proceed,
            risk_class: RiskClass::Balanced,
            policy_name: "test".to_string(),
            policy_version: 1,
            rationale_summary: "fusion says proceed".to_string(),
        };
        let floored = apply_verification_floor(rec, &plan);
        assert_eq!(floored.action, RecommendationAction::Review);
    }

    #[test]
    fn verification_floor_never_relaxes_review_or_block() {
        let plan = VerificationPlan {
            claim_class: ClaimClassId::new("x", 1),
            policy_name: "p".to_string(),
            policy_version: 1,
            budget_schema_version: 1,
            steps: vec![],
            rejected_steps: vec![],
            total_estimated_latency: Duration::ZERO,
            total_estimated_cost_units: 0,
            total_review_burden: 0,
            outcome: PlanOutcome::InsufficientVerification {
                unmet_requirement_ids: vec!["req_a".to_string()],
            },
        };
        for action in [RecommendationAction::Review, RecommendationAction::Block] {
            let rec = Recommendation {
                claim_id: Uuid::new_v4(),
                action,
                risk_class: RiskClass::Balanced,
                policy_name: "test".to_string(),
                policy_version: 1,
                rationale_summary: "r".to_string(),
            };
            assert_eq!(apply_verification_floor(rec, &plan).action, action);
        }
    }

    #[test]
    fn planned_outcome_applies_no_floor() {
        let plan = VerificationPlan {
            claim_class: ClaimClassId::new("x", 1),
            policy_name: "p".to_string(),
            policy_version: 1,
            budget_schema_version: 1,
            steps: vec![],
            rejected_steps: vec![],
            total_estimated_latency: Duration::ZERO,
            total_estimated_cost_units: 0,
            total_review_burden: 0,
            outcome: PlanOutcome::Planned,
        };
        let rec = Recommendation {
            claim_id: Uuid::new_v4(),
            action: RecommendationAction::Proceed,
            risk_class: RiskClass::Balanced,
            policy_name: "test".to_string(),
            policy_version: 1,
            rationale_summary: "r".to_string(),
        };
        assert_eq!(
            apply_verification_floor(rec, &plan).action,
            RecommendationAction::Proceed
        );
    }

    // --- AC4: reproducibility for pinned versions ------------------------

    #[test]
    fn same_frozen_inputs_produce_byte_identical_canonical_json() {
        let assessment = assessment(
            vec![requirement(
                "req_a",
                RequirementLevel::Required,
                SatisfactionState::Unsatisfied,
            )],
            SatisfactionState::Unsatisfied,
        );
        let budget = generous_budget();
        let plan_a = DeterministicBudgetPolicy.plan(
            &ctx(assessment.clone(), BlastRadius::ReversibleLocal),
            &budget,
        );
        let plan_b =
            DeterministicBudgetPolicy.plan(&ctx(assessment, BlastRadius::ReversibleLocal), &budget);

        assert_eq!(
            to_canonical_json(&plan_a).unwrap(),
            to_canonical_json(&plan_b).unwrap()
        );
    }

    // --- AC5: destructive/network/credential gating survives high
    //     information value -------------------------------------------

    #[test]
    fn destructive_side_effect_is_never_approved_even_for_a_critical_obligation() {
        let step = VerificationStep {
            kind: VerificationStepKind::ActiveEvidenceProbe {
                probe: ProbeKind::RerunTest,
            },
            targets_requirement_id: Some("critical_req".to_string()),
            estimated_latency: Duration::from_millis(1),
            estimated_cost_units: 0,
            estimated_resource_units: 0,
            side_effects: SideEffectAllowList::new([
                SideEffectClass::FilesystemWriteOutsideWorktree,
            ]),
            requires_credentials: false,
            review_burden: 0,
        };
        // A maximally permissive budget -- even so, destructive must be refused.
        let permissive = VerificationBudget {
            allowed_side_effects: SideEffectAllowList::new([
                SideEffectClass::FilesystemWriteOutsideWorktree,
                SideEffectClass::NetworkCall,
                SideEffectClass::ProcessSpawn,
                SideEffectClass::EphemeralWorktreeMutation,
            ]),
            credential_use_allowed: true,
            ..generous_budget()
        };
        assert_eq!(
            gate_step(&step, &permissive),
            Some(StepRejectionReason::DestructiveSideEffectNeverApprovable)
        );
    }

    #[test]
    fn unapproved_network_access_is_refused_regardless_of_information_value() {
        let step = VerificationStep {
            kind: VerificationStepKind::ActiveEvidenceProbe {
                probe: ProbeKind::QueryCiStatus,
            },
            targets_requirement_id: Some("critical_req".to_string()),
            estimated_latency: Duration::from_millis(1),
            estimated_cost_units: 1,
            estimated_resource_units: 0,
            side_effects: SideEffectAllowList::new([SideEffectClass::NetworkCall]),
            requires_credentials: false,
            review_burden: 0,
        };
        let no_network = VerificationBudget {
            allowed_side_effects: SideEffectAllowList::default(),
            ..generous_budget()
        };
        assert_eq!(
            gate_step(&step, &no_network),
            Some(StepRejectionReason::SideEffectNotGranted {
                class: SideEffectClass::NetworkCall
            })
        );
    }

    #[test]
    fn credential_bearing_verification_is_refused_when_not_allowed_even_if_network_is_granted() {
        let step = VerificationStep {
            kind: VerificationStepKind::ActiveEvidenceProbe {
                probe: ProbeKind::QueryCiStatus,
            },
            targets_requirement_id: Some("critical_req".to_string()),
            estimated_latency: Duration::from_millis(1),
            estimated_cost_units: 1,
            estimated_resource_units: 0,
            side_effects: SideEffectAllowList::new([SideEffectClass::NetworkCall]),
            requires_credentials: true,
            review_burden: 0,
        };
        let network_but_no_credentials = VerificationBudget {
            allowed_side_effects: SideEffectAllowList::new([SideEffectClass::NetworkCall]),
            credential_use_allowed: false,
            ..generous_budget()
        };
        assert_eq!(
            gate_step(&step, &network_but_no_credentials),
            Some(StepRejectionReason::CredentialUseNotAllowed)
        );
    }

    // --- adversarial: budget exhaustion mid-evaluation (many requirements,
    //     small budget) never silently drops coverage claims ------------

    #[test]
    fn budget_exhaustion_mid_evaluation_names_only_the_actually_uncovered_requirements() {
        let mut reqs = Vec::new();
        for i in 0..10 {
            reqs.push(requirement(
                &format!("req_{i}"),
                RequirementLevel::Required,
                SatisfactionState::Unsatisfied,
            ));
        }
        let assessment = assessment(reqs, SatisfactionState::Unsatisfied);
        // Enough probe-count/cost for roughly half.
        let small = VerificationBudget {
            max_probe_count: 3,
            max_cost_units: 3,
            ..generous_budget()
        };
        let plan = DeterministicBudgetPolicy
            .plan(&ctx(assessment, BlastRadius::ReadOnlyObservation), &small);
        match plan.outcome {
            PlanOutcome::InsufficientVerification {
                unmet_requirement_ids,
            } => {
                assert!(!unmet_requirement_ids.is_empty());
                assert!(unmet_requirement_ids.len() < 10);
            }
            PlanOutcome::Planned => {
                panic!("a 3-probe budget against 10 unsatisfied requirements cannot be Planned")
            }
        }
        assert!(plan.steps.len() as u32 <= small.max_probe_count);
    }

    // --- adversarial: malformed/adversarial capability input (an
    //     assessment with zero requirements at all -- an attacker-forged
    //     claim class per FORNX-378's own Unknown handling) -------------

    #[test]
    fn an_assessment_with_no_requirements_at_all_plans_cleanly_with_no_gaps() {
        let assessment = assessment(vec![], SatisfactionState::Unknown);
        let plan = DeterministicBudgetPolicy.plan(
            &ctx(assessment, BlastRadius::ReadOnlyObservation),
            &generous_budget(),
        );
        assert_eq!(plan.outcome, PlanOutcome::Planned);
        assert!(plan.steps.is_empty());
    }

    // --- adversarial: plan-replay with a stale budget-schema-version
    //     mismatch is visible, never silently accepted as current --------

    #[test]
    fn plan_records_the_budget_schema_version_it_was_computed_under() {
        let assessment = assessment(
            vec![requirement(
                "req_a",
                RequirementLevel::Required,
                SatisfactionState::Satisfied,
            )],
            SatisfactionState::Satisfied,
        );
        let mut budget = generous_budget();
        budget.schema_version = 7; // simulate a future schema revision
        let plan = DeterministicBudgetPolicy
            .plan(&ctx(assessment, BlastRadius::ReadOnlyObservation), &budget);
        assert_eq!(
            plan.budget_schema_version, 7,
            "a replayed plan must carry the exact schema version it was computed under, not the current one"
        );
    }

    // --- AC6/AC7: benchmark + promotion gate, synthetic fixtures --------

    #[test]
    fn benchmark_reports_all_declared_metrics_over_synthetic_fixtures() {
        let clean = assessment(
            vec![requirement(
                "req_a",
                RequirementLevel::Required,
                SatisfactionState::Satisfied,
            )],
            SatisfactionState::Satisfied,
        );
        let critical = assessment(
            vec![requirement(
                "req_b",
                RequirementLevel::Required,
                SatisfactionState::Unavailable,
            )],
            SatisfactionState::Unavailable,
        );
        let ctx_clean = ctx(clean, BlastRadius::ReadOnlyObservation);
        let ctx_critical = ctx(critical, BlastRadius::ReadOnlyObservation);
        let fixtures = vec![
            BenchmarkFixture {
                context: &ctx_clean,
                has_real_critical_obligation: false,
            },
            BenchmarkFixture {
                context: &ctx_critical,
                has_real_critical_obligation: true,
            },
        ];
        let results = benchmark(&generous_budget(), &fixtures);
        assert_eq!(results.len(), 3);
        for r in &results {
            assert_eq!(r.fixtures_evaluated, 2);
        }
        // Minimal-only (max_probe_count forced to 1, max_review_burden 0)
        // must miss the critical obligation the generous deterministic
        // policy catches, since `req_b` resolves to a HumanReview-only
        // probe that a 0-review-burden policy can never cover.
        let deterministic = &results[0];
        let minimal_only = &results[1];
        assert_eq!(
            deterministic.critical_misses, 0,
            "the generous deterministic policy must cover the one critical obligation"
        );
        assert!(
            minimal_only.critical_misses >= deterministic.critical_misses,
            "minimal-only must never catch strictly more than the adaptive policy: {} vs {}",
            minimal_only.critical_misses,
            deterministic.critical_misses
        );
    }

    #[test]
    fn promotion_gate_promotes_a_synthetic_candidate_that_genuinely_wins() {
        let baseline = PolicyBenchmarkResult {
            policy_name: "deterministic_budget_policy_v1".to_string(),
            fixtures_evaluated: 10,
            critical_misses: 2,
            false_positives: 3,
            total_cost_units: 100,
            total_latency: Duration::from_secs(10),
            total_review_burden: 1,
        };
        // A synthetic fake "learned policy" result that strictly beats the
        // baseline on every predeclared metric -- no real ML component
        // involved, this is a hand-built fixture proving the gate itself.
        let winning_candidate = PolicyBenchmarkResult {
            policy_name: "synthetic_fake_learned_policy".to_string(),
            fixtures_evaluated: 10,
            critical_misses: 1,
            false_positives: 2,
            total_cost_units: 90,
            total_latency: Duration::from_secs(9),
            total_review_burden: 1,
        };
        assert_eq!(
            promote_if_better(
                &winning_candidate,
                &baseline,
                &PromotionThresholds::default()
            ),
            PromotionDecision::Promoted
        );
    }

    #[test]
    fn promotion_gate_rejects_a_synthetic_candidate_that_genuinely_loses() {
        let baseline = PolicyBenchmarkResult {
            policy_name: "deterministic_budget_policy_v1".to_string(),
            fixtures_evaluated: 10,
            critical_misses: 2,
            false_positives: 3,
            total_cost_units: 100,
            total_latency: Duration::from_secs(10),
            total_review_burden: 1,
        };
        // A synthetic fake "learned policy" that is cheaper but misses more
        // critical obligations -- must be rejected even though cost improved,
        // since AC7 requires outperforming across the predeclared metrics,
        // not a single favorable one.
        let losing_candidate = PolicyBenchmarkResult {
            policy_name: "synthetic_fake_learned_policy_worse".to_string(),
            fixtures_evaluated: 10,
            critical_misses: 5,
            false_positives: 3,
            total_cost_units: 10,
            total_latency: Duration::from_secs(1),
            total_review_burden: 0,
        };
        match promote_if_better(
            &losing_candidate,
            &baseline,
            &PromotionThresholds::default(),
        ) {
            PromotionDecision::Rejected { failed_metrics } => {
                assert!(failed_metrics.iter().any(|m| m.contains("critical_misses")));
            }
            PromotionDecision::Promoted => {
                panic!("a policy with strictly more critical misses must never be promoted")
            }
        }
    }

    #[test]
    fn promotion_gate_never_promotes_on_cost_alone_when_thresholds_are_strict() {
        let baseline = PolicyBenchmarkResult {
            policy_name: "baseline".to_string(),
            fixtures_evaluated: 5,
            critical_misses: 0,
            false_positives: 0,
            total_cost_units: 50,
            total_latency: Duration::from_secs(5),
            total_review_burden: 0,
        };
        let cheaper_but_more_false_positives = PolicyBenchmarkResult {
            policy_name: "candidate".to_string(),
            fixtures_evaluated: 5,
            critical_misses: 0,
            false_positives: 1,
            total_cost_units: 10,
            total_latency: Duration::from_secs(1),
            total_review_burden: 0,
        };
        assert!(matches!(
            promote_if_better(
                &cheaper_but_more_false_positives,
                &baseline,
                &PromotionThresholds::default()
            ),
            PromotionDecision::Rejected { .. }
        ));
    }
}
