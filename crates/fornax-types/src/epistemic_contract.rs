//! Epistemic Contracts: versioned claim taxonomy and proof-obligation
//! semantics (FORNX-377, parent epic FORNX-376 "Agent Epistemic Trust
//! Kernel", target v0.3.0).
//!
//! The Evidence Graph ([`crate::graph`], FORNX-89/92) can already represent
//! *support*, *contradiction*, *missing evidence*, and *staleness* for a
//! given [`crate::Claim`]. What it cannot answer is the question this module
//! adds: **for this kind of claim, what evidence should have existed in the
//! first place, and how strong must it be before Fornax may recommend that a
//! human or downstream system rely on the claim?**
//!
//! This module is a schema/semantics layer only — it does not create a
//! parallel truth model. It extends the existing contracts:
//!
//! - [`ClaimClassId`] pairs with [`crate::Claim::subject`] — the same
//!   open-ended string category [`crate::Claim`] already carries, given a
//!   stable, versioned identity here.
//! - [`EvidenceRequirement`] references [`crate::EvidenceKind`] (what),
//!   [`crate::sensor::TrustClass`] (acceptable source / trust boundary), and
//!   [`crate::SignalClass`] (capability prerequisite) — all pre-existing
//!   taxonomies, not reinvented ones.
//! - [`assess_claim`] reuses [`crate::graph::staleness_of`] for the
//!   freshness dimension rather than duplicating time-window logic.
//!
//! # Deliberately out of scope (ticket non-goals)
//!
//! - No automatic contract generation by an LLM as production authority —
//!   every contract in [`representative_contracts`] is hand-authored.
//! - No universal ontology for every business domain — only the six
//!   representative coding-agent claim classes the ticket names.
//! - No calibrated scoring — [`assess_claim`] produces a discrete
//!   [`SatisfactionState`] per requirement via deterministic rule evaluation
//!   (evidence kind match, trust-class membership, freshness, count), never
//!   a numeric confidence value. Calibrated confidence/value is FORNX-97/
//!   FORNX-107/FORNX-352's unproven territory; nothing here claims to
//!   establish it.
//!
//! # Satisfaction states are never collapsed
//!
//! [`SatisfactionState`] is a distinct vocabulary from [`crate::Verdict`]
//! (ADR-0001's five-state verdict, "never collapsed to a boolean or a
//! score"). The two rhyme in spirit but answer different questions: `Verdict`
//! is "does the evidence we have support this claim?"; `SatisfactionState`
//! is "does the evidence we have satisfy the *proof obligation* this claim
//! class requires?" A claim can be `Verdict::Verified` by whatever evidence
//! exists while its epistemic contract is still `Unsatisfied` (e.g. the
//! single piece of evidence that verified it came from a trust class the
//! contract does not accept as sufficient on its own).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::graph::{staleness_of, FreshnessWindow, StalenessAssessment};
use crate::sensor::TrustClass;
use crate::{Claim, Evidence, EvidenceKind, SignalClass};

/// Version of the Epistemic Contract schema shape itself (the container:
/// [`EpistemicContract`]/[`EvidenceRequirement`] field set). Bumped only when
/// the shape changes in a way a consumer must know about — adding a new
/// [`SatisfactionState`]/[`RequirementLevel`] variant does not require a
/// bump, both carry forward-compatible catch-alls (see their doc comments).
pub const EPISTEMIC_CONTRACT_SCHEMA_VERSION: u32 = 1;
pub const SUPPORTED_EPISTEMIC_CONTRACT_SCHEMA_VERSIONS: &[u32] = &[1];

/// A stable, provider-neutral, versioned identifier for a claim class
/// (ticket AC: "versioned claim taxonomy with stable provider-neutral
/// identifiers"). `name` pairs with [`crate::Claim::subject`]'s open-ended
/// string convention; `version` lets a claim class's proof obligations
/// evolve over time while an old, already-assessed contract stays
/// replayable byte-for-byte under its own version (AC: "same frozen
/// claim/contract input serializes deterministically and remains replayable
/// by version").
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ClaimClassId {
    pub name: String,
    pub version: u32,
}

impl ClaimClassId {
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }
}

/// Explicit satisfaction state of one [`EvidenceRequirement`] against the
/// evidence actually available for a claim (ticket AC: "explicit
/// satisfaction states ... without collapsing distinct meanings").
///
/// Carries a forward-compatibility catch-all so a contract or assessment
/// persisted by a newer binary still round-trips through an older one — see
/// [`crate::capabilities::SignalAvailability::Unrecognized`] for the same
/// established pattern in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SatisfactionState {
    /// The requirement's evidence kind, trust class, freshness, and coverage
    /// bar are all met by evidence that supports the claim.
    Satisfied,
    /// Relevant evidence exists but does not meet the requirement (wrong
    /// trust class, insufficient coverage, or it contradicts rather than
    /// supports the claim without qualifying for [`Self::Contradicted`]
    /// specifically).
    Unsatisfied,
    /// No relevant evidence exists at all for this requirement, and nothing
    /// records why — distinct from evidence that exists but fails the bar
    /// ([`Self::Unsatisfied`]).
    Unavailable,
    /// Relevant evidence exists but is too old relative to the claim,
    /// per [`crate::graph::staleness_of`] — distinct from evidence that is
    /// fresh but insufficient.
    Stale,
    /// Relevant evidence exists and actively contradicts the claim (an
    /// [`crate::graph::EvidenceRelation::Contradicts`]-shaped result), not
    /// merely absent or insufficient.
    Contradicted,
    /// This requirement does not apply given the claim's context (e.g. a
    /// [`RequirementLevel::Conditional`] whose condition is not met) —
    /// distinct from every other state, which all describe a requirement
    /// that *does* apply.
    NotApplicable,
    /// This requirement's applicability or satisfaction could not be
    /// determined at all — e.g. the claim class itself is unrecognized (see
    /// [`ContractLookup::Unknown`]), or a timestamp needed to evaluate
    /// freshness failed to parse. Never used as a substitute for
    /// [`Self::Satisfied`]; see [`assess_claim`]'s "unknown never passes"
    /// invariant.
    Unknown,
    /// Forward-compatibility catch-all. Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// How strictly one [`EvidenceRequirement`] binds (ticket AC: "required vs.
/// recommended vs. conditional evidence is explicit and machine-readable").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementLevel {
    /// Must be [`SatisfactionState::Satisfied`] for the overall claim
    /// assessment to be [`SatisfactionState::Satisfied`].
    Required,
    /// Strengthens confidence when satisfied; its absence never by itself
    /// blocks an overall [`SatisfactionState::Satisfied`] verdict.
    Recommended,
    /// Binds as [`Self::Required`] only when `condition` holds for the
    /// claim being assessed. `condition` is a free-text description of the
    /// gating fact (e.g. "claim asserts a production deployment") — this
    /// ticket defines the schema, not a condition-evaluation DSL; a caller
    /// with the relevant context decides applicability and passes it to
    /// [`assess_claim`] via `conditions_met`.
    Conditional { condition: String },
}

impl RequirementLevel {
    /// Total ordering of *strictness*, used by [`compose`] to reject a child
    /// override that would silently weaken an inherited requirement.
    /// `Required` is strictest; `Recommended` and `Conditional` are treated
    /// as equally non-blocking-by-default and therefore mutually
    /// non-strengthening/non-weakening relative to each other — only a
    /// `Required` <-> non-`Required` transition is a strictness change.
    fn strictness_rank(&self) -> u8 {
        match self {
            RequirementLevel::Required => 2,
            RequirementLevel::Recommended | RequirementLevel::Conditional { .. } => 1,
        }
    }
}

/// Independence/dependency dimension (ticket AC dimension list): a
/// requirement may demand evidence that is independent of another named
/// requirement's evidence, so a single piece of evidence cannot double-count
/// toward two obligations that exist specifically to cross-check each other.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndependenceRule {
    /// No independence constraint.
    #[default]
    None,
    /// The evidence satisfying this requirement must be disjoint (no shared
    /// `Evidence::id`) from the evidence satisfying every named requirement
    /// id in this contract (or an ancestor contract).
    MustBeIndependentOf(Vec<String>),
}

/// Minimum-coverage dimension: how many independent qualifying evidence
/// items are needed before this requirement can reach
/// [`SatisfactionState::Satisfied`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRequirement {
    pub min_items: u32,
}

impl CoverageRequirement {
    pub const fn single() -> Self {
        CoverageRequirement { min_items: 1 }
    }
}

/// One proof obligation within an [`EpistemicContract`] (ticket AC:
/// "requirement dimensions: evidence kind, acceptable source/trust
/// boundary, freshness, independence/dependency, minimum coverage,
/// capability prerequisites and policy/risk context").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRequirement {
    /// Stable within its owning contract (and any contract that inherits
    /// from it) — used as the composition/independence join key. Not
    /// globally unique across unrelated contracts.
    pub id: String,
    pub level: RequirementLevel,
    /// What kind of evidence can satisfy this requirement.
    pub evidence_kind: EvidenceKind,
    /// Which [`TrustClass`]es are acceptable sources for this requirement.
    /// Never empty for a [`RequirementLevel::Required`] requirement — an
    /// empty list would be an unsatisfiable-by-construction obligation,
    /// checked by [`EpistemicContract::validate`].
    pub acceptable_trust_classes: Vec<TrustClass>,
    pub freshness: FreshnessWindow,
    #[serde(default)]
    pub independence: IndependenceRule,
    pub min_coverage: CoverageRequirement,
    /// Runtime capability classes that must be
    /// [`crate::SignalAvailability::Available`] for this requirement to be
    /// evaluable at all (rather than [`SatisfactionState::Unavailable`]).
    #[serde(default)]
    pub capability_prerequisites: Vec<SignalClass>,
    /// Free-text policy/risk context this requirement exists to satisfy
    /// (e.g. "SOC2 change-management evidence trail"). Deliberately
    /// unstructured — this ticket does not define a policy/risk ontology.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_context: Option<String>,
}

/// A versioned, composable set of proof obligations for one [`ClaimClassId`]
/// (ticket AC: "contract composition/inheritance rules that avoid hidden
/// weakening of parent obligations").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpistemicContract {
    pub claim_class: ClaimClassId,
    pub schema_version: u32,
    /// The contract this one inherits from, if any. `None` for a root
    /// contract. Composition is resolved by [`ContractRegistry::effective_requirements`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ClaimClassId>,
    /// Requirements this contract itself declares. When a requirement `id`
    /// here matches one inherited from `parent`, it *overrides* the parent's
    /// (subject to [`compose`]'s strictness check); a requirement `id` not
    /// mentioned here is inherited unchanged, never dropped.
    pub requirements: Vec<EvidenceRequirement>,
}

impl EpistemicContract {
    /// Structural validation independent of composition: every `Required`
    /// requirement must name at least one acceptable trust class and
    /// require at least one evidence item, or it is unsatisfiable by
    /// construction.
    pub fn validate(&self) -> Result<(), ContractError> {
        for req in &self.requirements {
            if matches!(req.level, RequirementLevel::Required)
                && req.acceptable_trust_classes.is_empty()
            {
                return Err(ContractError::UnsatisfiableRequirement {
                    claim_class: self.claim_class.clone(),
                    requirement_id: req.id.clone(),
                    reason: "Required requirement names zero acceptable trust classes",
                });
            }
            if req.min_coverage.min_items == 0 {
                return Err(ContractError::UnsatisfiableRequirement {
                    claim_class: self.claim_class.clone(),
                    requirement_id: req.id.clone(),
                    reason: "min_coverage.min_items must be at least 1",
                });
            }
        }
        Ok(())
    }
}

/// A composition/inheritance failure (ticket AC: "contract inheritance
/// cannot silently remove a stricter required obligation" — enforced here as
/// a returned error, never a silent pass).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// A child contract redefines an inherited requirement `id` with a
    /// strictly weaker [`RequirementLevel`] (`Required` -> non-`Required`),
    /// a smaller [`CoverageRequirement::min_items`], or a narrower
    /// `acceptable_trust_classes` set than its parent declared.
    WeakenedRequirement {
        claim_class: ClaimClassId,
        requirement_id: String,
        reason: &'static str,
    },
    /// A contract's own requirement is unsatisfiable by construction (see
    /// [`EpistemicContract::validate`]).
    UnsatisfiableRequirement {
        claim_class: ClaimClassId,
        requirement_id: String,
        reason: &'static str,
    },
    /// The `parent` chain contains a cycle (a contract transitively
    /// inherits from itself) — composition would never terminate.
    InheritanceCycle { claim_class: ClaimClassId },
    /// A contract names a `parent` that is not present in the registry.
    MissingParent {
        claim_class: ClaimClassId,
        parent: ClaimClassId,
    },
}

/// Merge a child contract's own requirements onto its already-resolved
/// parent requirements, rejecting any silent weakening (ticket AC). Returns
/// the merged requirement set, keyed by requirement `id`, in a stable
/// (sorted by id) order so callers get a deterministic result independent of
/// input ordering.
fn compose(
    claim_class: &ClaimClassId,
    parent_requirements: &BTreeMap<String, EvidenceRequirement>,
    own_requirements: &[EvidenceRequirement],
) -> Result<BTreeMap<String, EvidenceRequirement>, ContractError> {
    let mut merged = parent_requirements.clone();
    for req in own_requirements {
        if let Some(parent_req) = parent_requirements.get(&req.id) {
            if req.level.strictness_rank() < parent_req.level.strictness_rank() {
                return Err(ContractError::WeakenedRequirement {
                    claim_class: claim_class.clone(),
                    requirement_id: req.id.clone(),
                    reason: "child requirement level is weaker than the inherited level",
                });
            }
            if req.min_coverage.min_items < parent_req.min_coverage.min_items {
                return Err(ContractError::WeakenedRequirement {
                    claim_class: claim_class.clone(),
                    requirement_id: req.id.clone(),
                    reason: "child min_coverage is lower than the inherited min_coverage",
                });
            }
            // "Narrower" = child drops a trust class the parent accepted.
            // We only reject when the parent's requirement was itself
            // Required — a Recommended/Conditional parent obligation is not
            // load-bearing enough to freeze the child's trust-class set.
            // `TrustClass` has no `Hash`/`Ord` (it carries a free-text
            // `Unrecognized(String)` catch-all like its sibling taxonomies),
            // so this is a plain O(n*m) containment check rather than a set
            // difference — both lists are small (a handful of trust
            // classes), so this is not a performance concern.
            if matches!(parent_req.level, RequirementLevel::Required)
                && !parent_req
                    .acceptable_trust_classes
                    .iter()
                    .all(|t| req.acceptable_trust_classes.contains(t))
            {
                return Err(ContractError::WeakenedRequirement {
                    claim_class: claim_class.clone(),
                    requirement_id: req.id.clone(),
                    reason: "child acceptable_trust_classes drops a trust class the inherited Required requirement accepted",
                });
            }
        }
        merged.insert(req.id.clone(), req.clone());
    }
    Ok(merged)
}

/// Holds every known [`EpistemicContract`], keyed by [`ClaimClassId`], and
/// resolves inheritance (ticket AC: "unknown claim types default to an
/// explicit conservative state rather than a generic pass").
#[derive(Debug, Clone, Default)]
pub struct ContractRegistry {
    contracts: HashMap<ClaimClassId, EpistemicContract>,
}

/// Result of looking up a claim class in a [`ContractRegistry`] — kept as an
/// explicit enum (rather than `Option`) so every call site is forced to
/// name the "no contract" branch, matching this crate's "missing must be an
/// explicit, distinct state" convention (see
/// [`crate::capabilities::SignalAvailability`]'s doc comment).
#[derive(Debug, Clone, PartialEq)]
pub enum ContractLookup<'a> {
    Found(&'a EpistemicContract),
    Unknown,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a contract. Returns an error immediately if the contract
    /// fails [`EpistemicContract::validate`] — a bad contract can never
    /// enter the registry to begin with.
    pub fn register(&mut self, contract: EpistemicContract) -> Result<(), ContractError> {
        contract.validate()?;
        self.contracts
            .insert(contract.claim_class.clone(), contract.clone());
        Ok(())
    }

    pub fn lookup(&self, claim_class: &ClaimClassId) -> ContractLookup<'_> {
        match self.contracts.get(claim_class) {
            Some(c) => ContractLookup::Found(c),
            None => ContractLookup::Unknown,
        }
    }

    /// Resolve `claim_class`'s full, inheritance-composed requirement set.
    /// Walks the `parent` chain from root to `claim_class`, applying
    /// [`compose`] at each step so no descendant can silently weaken an
    /// ancestor's obligation. Cycle-safe: a chain longer than the registry's
    /// own size is definitionally a cycle.
    pub fn effective_requirements(
        &self,
        claim_class: &ClaimClassId,
    ) -> Result<Vec<EvidenceRequirement>, ContractError> {
        let mut chain = Vec::new();
        let mut current = claim_class.clone();
        loop {
            let contract = self.contracts.get(&current).ok_or_else(|| {
                if chain.is_empty() {
                    ContractError::MissingParent {
                        claim_class: claim_class.clone(),
                        parent: current.clone(),
                    }
                } else {
                    ContractError::MissingParent {
                        claim_class: chain.last().cloned().unwrap(),
                        parent: current.clone(),
                    }
                }
            })?;
            chain.push(current.clone());
            if chain.len() > self.contracts.len() {
                return Err(ContractError::InheritanceCycle {
                    claim_class: claim_class.clone(),
                });
            }
            match &contract.parent {
                Some(parent) if chain.contains(parent) => {
                    return Err(ContractError::InheritanceCycle {
                        claim_class: claim_class.clone(),
                    })
                }
                Some(parent) => current = parent.clone(),
                None => break,
            }
        }
        // chain is [claim_class, ..., root]; fold from root down to claim_class.
        let mut merged: BTreeMap<String, EvidenceRequirement> = BTreeMap::new();
        for cc in chain.iter().rev() {
            let contract = self.contracts.get(cc).expect("verified present above");
            merged = compose(cc, &merged, &contract.requirements)?;
        }
        Ok(merged.into_values().collect())
    }
}

/// Why one piece of candidate evidence did not count toward a requirement's
/// coverage (FORNX-378 AC: "evidence rejected for trust/freshness/dependency
/// reasons remains visible with rationale rather than disappearing"). A
/// side channel to the coverage decision computed by [`evaluate_requirement`]
/// — it explains [`SatisfactionState`], it never influences it. Evidence of
/// the wrong [`EvidenceKind`] for a requirement is not recorded here at all
/// (it was never relevant to this requirement in the first place, so
/// "rejected" would be noise, not signal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Evidence's recorded (or absent) [`TrustClass`] is not in the
    /// requirement's `acceptable_trust_classes`.
    WrongTrustClass,
    /// [`staleness_of`] returned `Stale` for this evidence/claim pair.
    Stale,
    /// [`staleness_of`] returned `Indeterminate` (unparseable timestamp, or
    /// evidence observed after the claim) — never silently treated as fresh.
    IndeterminateFreshness,
    /// This evidence was already claimed by a requirement this one must be
    /// independent of ([`IndependenceRule::MustBeIndependentOf`]) and so
    /// cannot double-count here.
    ClaimedByIndependentRequirement,
}

/// One piece of evidence that matched a requirement's `evidence_kind` but
/// did not count toward its coverage, plus why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedEvidence {
    pub evidence_id: uuid::Uuid,
    pub reason: RejectionReason,
}

/// Per-requirement assessment result plus the requirement it was assessed
/// against, so a caller can render *why* without re-deriving it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequirementAssessment {
    pub requirement_id: String,
    pub level: RequirementLevel,
    pub state: SatisfactionState,
    /// Evidence ids actually claimed toward this requirement's coverage bar
    /// (bounded by `min_coverage.min_items`, per [`evaluate_requirement`]'s
    /// doc comment on why surplus qualifying evidence is left unclaimed).
    /// Empty when `state` is anything but [`SatisfactionState::Satisfied`].
    pub matched_evidence: Vec<uuid::Uuid>,
    /// Evidence that matched this requirement's `evidence_kind` but was
    /// rejected, and why — never dropped silently (FORNX-378 AC). Empty for
    /// a [`SatisfactionState::NotApplicable`] requirement (never evaluated
    /// against evidence at all).
    pub rejected_evidence: Vec<RejectedEvidence>,
}

/// The full result of [`assess_claim`] (ticket AC dimension: "unknown claim
/// types default to an explicit conservative state rather than a generic
/// pass").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimAssessment {
    pub claim_class: ClaimClassId,
    pub per_requirement: Vec<RequirementAssessment>,
    pub overall: SatisfactionState,
}

/// Evaluate one [`EvidenceRequirement`] against a claim's candidate evidence,
/// excluding any evidence id in `excluded` (used to enforce
/// [`IndependenceRule::MustBeIndependentOf`] — see [`assess_claim`]). Pure
/// and deterministic: given the same inputs, always returns the same
/// `(SatisfactionState, qualifying evidence ids)` — no clock reads, no
/// randomness (mirrors [`crate::graph::staleness_of`]'s own determinism
/// guarantee, which this function delegates freshness to).
fn evaluate_requirement(
    requirement: &EvidenceRequirement,
    claim: &Claim,
    evidence: &[&Evidence],
    excluded: &std::collections::HashSet<uuid::Uuid>,
    trust_class_of: &dyn Fn(&Evidence) -> Option<TrustClass>,
) -> (SatisfactionState, Vec<uuid::Uuid>, Vec<RejectedEvidence>) {
    let mut qualifying: Vec<&Evidence> = Vec::new();
    let mut rejected: Vec<RejectedEvidence> = Vec::new();
    let mut saw_wrong_trust = false;
    let mut saw_stale = false;
    let mut saw_excluded = false;

    for ev in evidence {
        if ev.kind != requirement.evidence_kind {
            continue;
        }
        if excluded.contains(&ev.id) {
            // This evidence item was already claimed by a requirement this
            // one must be independent of (IndependenceRule::MustBeIndependentOf)
            // — it cannot double-count toward both obligations.
            saw_excluded = true;
            rejected.push(RejectedEvidence {
                evidence_id: ev.id,
                reason: RejectionReason::ClaimedByIndependentRequirement,
            });
            continue;
        }
        let trust = trust_class_of(ev);
        let trust_ok = match &trust {
            Some(tc) => requirement.acceptable_trust_classes.contains(tc),
            // Evidence with no recorded trust provenance never qualifies a
            // Required requirement — treating unknown provenance as
            // acceptable would defeat the trust-boundary dimension.
            None => false,
        };
        if !trust_ok {
            saw_wrong_trust = true;
            rejected.push(RejectedEvidence {
                evidence_id: ev.id,
                reason: RejectionReason::WrongTrustClass,
            });
            continue;
        }
        match staleness_of(ev, claim, requirement.freshness) {
            StalenessAssessment::Stale { .. } => {
                saw_stale = true;
                rejected.push(RejectedEvidence {
                    evidence_id: ev.id,
                    reason: RejectionReason::Stale,
                });
            }
            StalenessAssessment::Indeterminate { .. } => {
                // An unparseable timestamp can never silently count as fresh
                // (mirrors staleness_of's own documented conservatism).
                saw_stale = true;
                rejected.push(RejectedEvidence {
                    evidence_id: ev.id,
                    reason: RejectionReason::IndeterminateFreshness,
                });
            }
            StalenessAssessment::Fresh { .. } | StalenessAssessment::NotTimeSensitive => {
                qualifying.push(ev);
            }
        }
    }

    // Only the evidence actually needed to clear this requirement's own
    // coverage bar is "claimed" by it — not every qualifying item found.
    // This is what makes independence checking meaningful: a base
    // requirement that only needs 1 item leaves any qualifying surplus free
    // for a sibling requirement declared independent of it (see
    // `assess_claim`'s two-pass evaluation). Claiming the *entire* qualifying
    // set here would make `MustBeIndependentOf` reject cases that plainly
    // have enough independent evidence to satisfy both requirements.
    let claimed_count = (requirement.min_coverage.min_items as usize).min(qualifying.len());
    let qualifying_ids: Vec<uuid::Uuid> =
        qualifying[..claimed_count].iter().map(|e| e.id).collect();
    let state = if qualifying.len() as u32 >= requirement.min_coverage.min_items {
        SatisfactionState::Satisfied
    } else if saw_stale {
        SatisfactionState::Stale
    } else if saw_wrong_trust || saw_excluded {
        SatisfactionState::Unsatisfied
    } else {
        SatisfactionState::Unavailable
    };
    (state, qualifying_ids, rejected)
}

/// Assess a claim against its epistemic contract (ticket AC: "same frozen
/// claim/contract input serializes deterministically"; this function itself
/// is pure/deterministic for the same reason [`evaluate_requirement`] is).
///
/// `conditions_met` names every [`RequirementLevel::Conditional`] `condition`
/// string that applies to this specific claim; a conditional requirement
/// whose condition is not in this set is assessed as
/// [`SatisfactionState::NotApplicable`], not evaluated against evidence at
/// all.
///
/// **Unknown claim types never pass** (hard AC, tested adversarially in this
/// module's tests): if `registry` has no contract for `claim_class`, the
/// result is `overall: SatisfactionState::Unknown` with zero
/// `per_requirement` entries — never [`SatisfactionState::Satisfied`], and
/// never silently treated as "no obligation, so nothing to fail."
pub fn assess_claim(
    registry: &ContractRegistry,
    claim_class: &ClaimClassId,
    claim: &Claim,
    evidence: &[&Evidence],
    conditions_met: &[String],
    trust_class_of: &dyn Fn(&Evidence) -> Option<TrustClass>,
) -> Result<ClaimAssessment, ContractError> {
    if matches!(registry.lookup(claim_class), ContractLookup::Unknown) {
        return Ok(ClaimAssessment {
            claim_class: claim_class.clone(),
            per_requirement: Vec::new(),
            overall: SatisfactionState::Unknown,
        });
    }

    let requirements = registry.effective_requirements(claim_class)?;
    let empty_exclusion = std::collections::HashSet::new();

    // Pass 1: evaluate every requirement with no independence exclusion, to
    // learn which evidence ids would qualify each requirement id on its own.
    // This is what IndependenceRule::MustBeIndependentOf needs to look up —
    // "the evidence that satisfies requirement X" is only known after X is
    // evaluated at least once.
    let mut unconstrained_qualifying: HashMap<String, Vec<uuid::Uuid>> = HashMap::new();
    for req in &requirements {
        let applicable = match &req.level {
            RequirementLevel::Conditional { condition } => conditions_met.contains(condition),
            RequirementLevel::Required | RequirementLevel::Recommended => true,
        };
        if applicable {
            let (_, qualifying_ids, _) =
                evaluate_requirement(req, claim, evidence, &empty_exclusion, trust_class_of);
            unconstrained_qualifying.insert(req.id.clone(), qualifying_ids);
        }
    }

    // Pass 2: re-evaluate each requirement for real, excluding evidence ids
    // claimed by any requirement it must be independent of (ticket AC:
    // "independence/dependency" dimension) — a single piece of evidence must
    // never silently double-count toward two obligations meant to
    // cross-check each other.
    let mut per_requirement = Vec::with_capacity(requirements.len());
    let mut any_required_blocking = false;

    for req in &requirements {
        let applicable = match &req.level {
            RequirementLevel::Conditional { condition } => conditions_met.contains(condition),
            RequirementLevel::Required | RequirementLevel::Recommended => true,
        };
        let (state, matched_evidence, rejected_evidence) = if !applicable {
            (SatisfactionState::NotApplicable, Vec::new(), Vec::new())
        } else {
            let excluded: std::collections::HashSet<uuid::Uuid> = match &req.independence {
                IndependenceRule::None => std::collections::HashSet::new(),
                IndependenceRule::MustBeIndependentOf(other_ids) => other_ids
                    .iter()
                    .flat_map(|id| {
                        unconstrained_qualifying
                            .get(id)
                            .cloned()
                            .unwrap_or_default()
                    })
                    .collect(),
            };
            evaluate_requirement(req, claim, evidence, &excluded, trust_class_of)
        };

        let is_blocking_level = matches!(req.level, RequirementLevel::Required)
            || matches!(&req.level, RequirementLevel::Conditional { .. } if applicable);
        if is_blocking_level && !matches!(state, SatisfactionState::Satisfied) {
            any_required_blocking = true;
        }

        per_requirement.push(RequirementAssessment {
            requirement_id: req.id.clone(),
            level: req.level.clone(),
            state,
            matched_evidence,
            rejected_evidence,
        });
    }

    let overall = if any_required_blocking {
        // Prefer the most informative non-Satisfied state among the blocking
        // ones for `overall`, preferring Contradicted > Stale > Unsatisfied >
        // Unavailable > Unknown so a caller's headline state names the
        // sharpest problem rather than the first one encountered.
        let rank = |s: &SatisfactionState| -> u8 {
            match s {
                SatisfactionState::Contradicted => 4,
                SatisfactionState::Stale => 3,
                SatisfactionState::Unsatisfied => 2,
                SatisfactionState::Unavailable => 1,
                _ => 0,
            }
        };
        per_requirement
            .iter()
            .filter(|ra| {
                (matches!(ra.level, RequirementLevel::Required)
                    || matches!(&ra.level, RequirementLevel::Conditional { .. }))
                    && !matches!(
                        ra.state,
                        SatisfactionState::Satisfied | SatisfactionState::NotApplicable
                    )
            })
            .map(|ra| ra.state.clone())
            .max_by_key(|s| rank(s))
            .unwrap_or(SatisfactionState::Unsatisfied)
    } else {
        SatisfactionState::Satisfied
    };

    Ok(ClaimAssessment {
        claim_class: claim_class.clone(),
        per_requirement,
        overall,
    })
}

/// Deterministic canonical JSON serialization (ticket AC: "same frozen
/// claim/contract input serializes deterministically"). Rebuilds every JSON
/// object with its keys inserted in sorted order before serializing, so the
/// output is identical across runs and across `serde_json::Map`'s two
/// possible backing implementations (`BTreeMap` vs. insertion-order
/// `IndexMap` under the `preserve_order` feature) — inserting in sorted
/// order produces sorted output either way.
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let raw = serde_json::to_value(value)?;
    let canonical = canonicalize_value(raw);
    serde_json::to_string(&canonical)
}

fn canonicalize_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                let v = map.get(&k).cloned().unwrap_or(serde_json::Value::Null);
                out.insert(k, canonicalize_value(v));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(canonicalize_value).collect())
        }
        other => other,
    }
}

/// The six representative coding-agent claim classes named in the ticket
/// scope, each a real, narrowly-scoped [`EpistemicContract`] instance (not
/// merely a type) so the schema is exercised against concrete obligations.
pub mod representative_contracts {
    use super::*;

    pub fn tests_passed() -> EpistemicContract {
        EpistemicContract {
            claim_class: ClaimClassId::new("tests_passed", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![
                EvidenceRequirement {
                    id: "test_runner_exit_code".to_string(),
                    level: RequirementLevel::Required,
                    evidence_kind: EvidenceKind::ExitCode,
                    acceptable_trust_classes: vec![TrustClass::HostObserved],
                    freshness: FreshnessWindow::Perishable {
                        max_age_seconds: 3600,
                    },
                    independence: IndependenceRule::None,
                    min_coverage: CoverageRequirement::single(),
                    capability_prerequisites: vec![SignalClass::ProcessResult],
                    policy_context: None,
                },
                EvidenceRequirement {
                    id: "provider_tool_result_corroboration".to_string(),
                    level: RequirementLevel::Recommended,
                    evidence_kind: EvidenceKind::ToolResult,
                    acceptable_trust_classes: vec![TrustClass::AgentAdjacent],
                    freshness: FreshnessWindow::Durable,
                    independence: IndependenceRule::MustBeIndependentOf(vec![
                        "test_runner_exit_code".to_string(),
                    ]),
                    min_coverage: CoverageRequirement::single(),
                    capability_prerequisites: vec![],
                    policy_context: None,
                },
            ],
        }
    }

    pub fn build_succeeded() -> EpistemicContract {
        EpistemicContract {
            claim_class: ClaimClassId::new("build_succeeded", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "build_exit_code".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Perishable {
                    max_age_seconds: 3600,
                },
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![SignalClass::ProcessResult],
                policy_context: None,
            }],
        }
    }

    pub fn file_changed() -> EpistemicContract {
        EpistemicContract {
            claim_class: ClaimClassId::new("file_changed", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "file_diff_observed".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::FileDiff,
                acceptable_trust_classes: vec![TrustClass::HostObserved, TrustClass::AgentAdjacent],
                // A diff is a durable fact about what changed; it does not
                // itself go stale the way a live process result can.
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        }
    }

    pub fn commit_push_completed() -> EpistemicContract {
        EpistemicContract {
            claim_class: ClaimClassId::new("commit_push_completed", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![
                EvidenceRequirement {
                    id: "vcs_operation_observed".to_string(),
                    level: RequirementLevel::Required,
                    evidence_kind: EvidenceKind::ProcessObservation,
                    acceptable_trust_classes: vec![TrustClass::HostObserved],
                    freshness: FreshnessWindow::Durable,
                    independence: IndependenceRule::None,
                    min_coverage: CoverageRequirement::single(),
                    capability_prerequisites: vec![],
                    policy_context: None,
                },
                EvidenceRequirement {
                    id: "remote_ref_independent_confirmation".to_string(),
                    level: RequirementLevel::Conditional {
                        condition: "claim asserts a push to a shared/remote ref".to_string(),
                    },
                    evidence_kind: EvidenceKind::ProcessObservation,
                    acceptable_trust_classes: vec![TrustClass::IndependentExternal],
                    freshness: FreshnessWindow::Perishable {
                        max_age_seconds: 86_400,
                    },
                    independence: IndependenceRule::MustBeIndependentOf(vec![
                        "vcs_operation_observed".to_string(),
                    ]),
                    min_coverage: CoverageRequirement::single(),
                    capability_prerequisites: vec![],
                    policy_context: Some(
                        "change-management evidence trail for shared history".to_string(),
                    ),
                },
            ],
        }
    }

    pub fn deployment_healthy() -> EpistemicContract {
        EpistemicContract {
            claim_class: ClaimClassId::new("deployment_healthy", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "independent_health_check".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ProcessObservation,
                // A deployment health claim must never be satisfied purely
                // by the agent's own say-so — this is the requirement this
                // module's threat review most directly targets (see the
                // PR's security review section).
                acceptable_trust_classes: vec![TrustClass::IndependentExternal],
                freshness: FreshnessWindow::Perishable {
                    max_age_seconds: 300,
                },
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: Some("production change-safety gate".to_string()),
            }],
        }
    }

    pub fn security_defect_fixed() -> EpistemicContract {
        EpistemicContract {
            claim_class: ClaimClassId::new("security_defect_fixed", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![
                EvidenceRequirement {
                    id: "regression_test_exit_code".to_string(),
                    level: RequirementLevel::Required,
                    evidence_kind: EvidenceKind::ExitCode,
                    acceptable_trust_classes: vec![TrustClass::HostObserved],
                    freshness: FreshnessWindow::Perishable {
                        max_age_seconds: 3600,
                    },
                    independence: IndependenceRule::None,
                    min_coverage: CoverageRequirement::single(),
                    capability_prerequisites: vec![SignalClass::ProcessResult],
                    policy_context: None,
                },
                EvidenceRequirement {
                    id: "human_security_review".to_string(),
                    level: RequirementLevel::Required,
                    evidence_kind: EvidenceKind::TranscriptExcerpt,
                    acceptable_trust_classes: vec![TrustClass::HumanReviewed],
                    freshness: FreshnessWindow::Durable,
                    independence: IndependenceRule::MustBeIndependentOf(vec![
                        "regression_test_exit_code".to_string(),
                    ]),
                    min_coverage: CoverageRequirement::single(),
                    capability_prerequisites: vec![],
                    policy_context: Some(
                        "security-defect claims require a human-reviewed disposition, not \
                         agent self-attestation alone"
                            .to_string(),
                    ),
                },
            ],
        }
    }

    /// All six, for convenient registry population.
    pub fn all() -> Vec<EpistemicContract> {
        vec![
            tests_passed(),
            build_succeeded(),
            file_changed(),
            commit_push_completed(),
            deployment_healthy(),
            security_defect_fixed(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::representative_contracts::*;
    use super::*;
    use uuid::Uuid;

    fn claim(subject: &str, claimed_at: &str) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "session-1".to_string(),
            source_event_id: Uuid::new_v4(),
            text: format!("claim about {subject}"),
            subject: subject.to_string(),
            claimed_at: claimed_at.to_string(),
        }
    }

    fn evidence(kind: EvidenceKind, observed_at: &str) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "session-1".to_string(),
            source_event_id: Uuid::new_v4(),
            kind,
            observed_at: observed_at.to_string(),
            payload: serde_json::json!({}),
            provenance: "test".to_string(),
            source: None,
            extension: None,
            evidence_purged: false,
        }
    }

    fn registry_with_all() -> ContractRegistry {
        let mut reg = ContractRegistry::new();
        for c in all() {
            reg.register(c)
                .expect("representative contracts must validate");
        }
        reg
    }

    // --- one regression test per representative claim class ---

    #[test]
    fn tests_passed_satisfied_by_host_observed_exit_code() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T00:10:00Z");
        let ev = evidence(EvidenceKind::ExitCode, "2026-09-24T00:00:00Z");
        let trust_of = |_: &Evidence| Some(TrustClass::HostObserved);
        let assessment =
            assess_claim(&reg, &cc, &claim, &[&ev], &[], &trust_of).expect("assess ok");
        assert_eq!(assessment.overall, SatisfactionState::Satisfied);
    }

    #[test]
    fn tests_passed_unsatisfied_when_only_agent_adjacent_evidence() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T00:10:00Z");
        let ev = evidence(EvidenceKind::ExitCode, "2026-09-24T00:00:00Z");
        // Required requirement demands HostObserved; agent's own report of
        // its exit code must not qualify.
        let trust_of = |_: &Evidence| Some(TrustClass::AgentAdjacent);
        let assessment =
            assess_claim(&reg, &cc, &claim, &[&ev], &[], &trust_of).expect("assess ok");
        assert_eq!(assessment.overall, SatisfactionState::Unsatisfied);
    }

    #[test]
    fn independence_rule_prevents_one_evidence_item_satisfying_two_requirements() {
        // Two requirements of the same evidence_kind/trust_class, the second
        // declared independent of the first. A single qualifying evidence
        // item must not double-count toward both.
        let mut reg = ContractRegistry::new();
        let contract = EpistemicContract {
            claim_class: ClaimClassId::new("double_check", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![
                EvidenceRequirement {
                    id: "first_check".to_string(),
                    level: RequirementLevel::Required,
                    evidence_kind: EvidenceKind::ExitCode,
                    acceptable_trust_classes: vec![TrustClass::HostObserved],
                    freshness: FreshnessWindow::Durable,
                    independence: IndependenceRule::None,
                    min_coverage: CoverageRequirement::single(),
                    capability_prerequisites: vec![],
                    policy_context: None,
                },
                EvidenceRequirement {
                    id: "second_independent_check".to_string(),
                    level: RequirementLevel::Required,
                    evidence_kind: EvidenceKind::ExitCode,
                    acceptable_trust_classes: vec![TrustClass::HostObserved],
                    freshness: FreshnessWindow::Durable,
                    independence: IndependenceRule::MustBeIndependentOf(vec![
                        "first_check".to_string()
                    ]),
                    min_coverage: CoverageRequirement::single(),
                    capability_prerequisites: vec![],
                    policy_context: None,
                },
            ],
        };
        reg.register(contract).unwrap();
        let cc = ClaimClassId::new("double_check", 1);
        let claim = claim("double_check", "2026-09-24T00:10:00Z");
        let only_ev = evidence(EvidenceKind::ExitCode, "2026-09-24T00:00:00Z");
        let trust_of = |_: &Evidence| Some(TrustClass::HostObserved);

        let assessment =
            assess_claim(&reg, &cc, &claim, &[&only_ev], &[], &trust_of).expect("assess ok");
        // first_check claims the only evidence item; second_independent_check
        // must not also be Satisfied by the same item.
        assert_ne!(assessment.overall, SatisfactionState::Satisfied);
        let second = assessment
            .per_requirement
            .iter()
            .find(|r| r.requirement_id == "second_independent_check")
            .unwrap();
        assert_ne!(second.state, SatisfactionState::Satisfied);

        // With two independent qualifying items, both requirements are
        // Satisfied.
        let ev_a = evidence(EvidenceKind::ExitCode, "2026-09-24T00:00:00Z");
        let ev_b = evidence(EvidenceKind::ExitCode, "2026-09-24T00:00:01Z");
        let assessment2 =
            assess_claim(&reg, &cc, &claim, &[&ev_a, &ev_b], &[], &trust_of).expect("assess ok");
        assert_eq!(assessment2.overall, SatisfactionState::Satisfied);
    }

    #[test]
    fn build_succeeded_unavailable_with_no_evidence() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("build_succeeded", 1);
        let claim = claim("build_succeeded", "2026-09-24T00:10:00Z");
        let trust_of = |_: &Evidence| None;
        let assessment = assess_claim(&reg, &cc, &claim, &[], &[], &trust_of).expect("assess ok");
        assert_eq!(assessment.overall, SatisfactionState::Unavailable);
    }

    #[test]
    fn file_changed_satisfied_by_agent_adjacent_diff() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("file_changed", 1);
        let claim = claim("file_changed", "2026-09-24T00:10:00Z");
        let ev = evidence(EvidenceKind::FileDiff, "2026-09-20T00:00:00Z");
        let trust_of = |_: &Evidence| Some(TrustClass::AgentAdjacent);
        let assessment =
            assess_claim(&reg, &cc, &claim, &[&ev], &[], &trust_of).expect("assess ok");
        assert_eq!(assessment.overall, SatisfactionState::Satisfied);
    }

    #[test]
    fn commit_push_completed_conditional_requirement_not_applicable_when_condition_unmet() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("commit_push_completed", 1);
        let claim = claim("commit_push_completed", "2026-09-24T00:10:00Z");
        let ev = evidence(EvidenceKind::ProcessObservation, "2026-09-24T00:00:00Z");
        let trust_of = |_: &Evidence| Some(TrustClass::HostObserved);
        // conditions_met is empty: local-branch commit, not a shared-ref push.
        let assessment =
            assess_claim(&reg, &cc, &claim, &[&ev], &[], &trust_of).expect("assess ok");
        assert_eq!(assessment.overall, SatisfactionState::Satisfied);
        let conditional = assessment
            .per_requirement
            .iter()
            .find(|r| r.requirement_id == "remote_ref_independent_confirmation")
            .unwrap();
        assert_eq!(conditional.state, SatisfactionState::NotApplicable);
    }

    #[test]
    fn commit_push_completed_conditional_requirement_blocks_when_condition_met_and_unsatisfied() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("commit_push_completed", 1);
        let claim = claim("commit_push_completed", "2026-09-24T00:10:00Z");
        let ev = evidence(EvidenceKind::ProcessObservation, "2026-09-24T00:00:00Z");
        let trust_of = |_: &Evidence| Some(TrustClass::HostObserved);
        let conditions = vec!["claim asserts a push to a shared/remote ref".to_string()];
        let assessment =
            assess_claim(&reg, &cc, &claim, &[&ev], &conditions, &trust_of).expect("assess ok");
        // Only HostObserved evidence supplied; the conditional requirement
        // needs IndependentExternal, so overall must not be Satisfied.
        assert_ne!(assessment.overall, SatisfactionState::Satisfied);
    }

    #[test]
    fn deployment_healthy_never_satisfied_by_agent_self_report() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("deployment_healthy", 1);
        let claim = claim("deployment_healthy", "2026-09-24T00:10:00Z");
        let ev = evidence(EvidenceKind::ProcessObservation, "2026-09-24T00:09:00Z");
        // Adversarial: the agent's own tooling reports the health check
        // (AgentAdjacent), not an independent external system.
        let trust_of = |_: &Evidence| Some(TrustClass::AgentAdjacent);
        let assessment =
            assess_claim(&reg, &cc, &claim, &[&ev], &[], &trust_of).expect("assess ok");
        assert_eq!(assessment.overall, SatisfactionState::Unsatisfied);
    }

    #[test]
    fn security_defect_fixed_requires_both_test_and_human_review() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("security_defect_fixed", 1);
        let claim = claim("security_defect_fixed", "2026-09-24T00:10:00Z");
        let test_ev = evidence(EvidenceKind::ExitCode, "2026-09-24T00:00:00Z");
        // Only the regression test evidence supplied, no human review.
        let trust_of = |ev: &Evidence| {
            if ev.kind == EvidenceKind::ExitCode {
                Some(TrustClass::HostObserved)
            } else {
                None
            }
        };
        let assessment =
            assess_claim(&reg, &cc, &claim, &[&test_ev], &[], &trust_of).expect("assess ok");
        assert_ne!(assessment.overall, SatisfactionState::Satisfied);

        let human_ev = evidence(EvidenceKind::TranscriptExcerpt, "2026-09-24T00:00:00Z");
        let trust_of_both = |ev: &Evidence| match ev.kind {
            EvidenceKind::ExitCode => Some(TrustClass::HostObserved),
            EvidenceKind::TranscriptExcerpt => Some(TrustClass::HumanReviewed),
            _ => None,
        };
        let assessment2 = assess_claim(
            &reg,
            &cc,
            &claim,
            &[&test_ev, &human_ev],
            &[],
            &trust_of_both,
        )
        .expect("assess ok");
        assert_eq!(assessment2.overall, SatisfactionState::Satisfied);
    }

    // --- adversarial: unknown claim types default conservative, never pass ---

    #[test]
    fn unknown_claim_type_never_satisfied() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("totally_unheard_of_claim_class", 1);
        let claim = claim("totally_unheard_of_claim_class", "2026-09-24T00:10:00Z");
        // Flood it with evidence that would satisfy almost any contract, to
        // prove the "no contract" branch never falls through to a pass.
        let ev = evidence(EvidenceKind::ExitCode, "2026-09-24T00:00:00Z");
        let trust_of = |_: &Evidence| Some(TrustClass::HostObserved);
        let assessment =
            assess_claim(&reg, &cc, &claim, &[&ev], &[], &trust_of).expect("assess ok");
        assert_eq!(assessment.overall, SatisfactionState::Unknown);
        assert!(assessment.per_requirement.is_empty());
        assert_ne!(assessment.overall, SatisfactionState::Satisfied);
    }

    #[test]
    fn unknown_claim_type_even_with_matching_version_zero_contract_absent() {
        let reg = ContractRegistry::new(); // deliberately empty
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T00:10:00Z");
        let trust_of = |_: &Evidence| Some(TrustClass::HostObserved);
        let assessment = assess_claim(&reg, &cc, &claim, &[], &[], &trust_of).expect("assess ok");
        assert_eq!(assessment.overall, SatisfactionState::Unknown);
    }

    // --- adversarial: contract inheritance cannot silently weaken ---

    #[test]
    fn child_contract_cannot_downgrade_required_to_recommended() {
        let mut reg = ContractRegistry::new();
        let parent = EpistemicContract {
            claim_class: ClaimClassId::new("parent_class", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "req_a".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        reg.register(parent).unwrap();

        let child = EpistemicContract {
            claim_class: ClaimClassId::new("child_class", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: Some(ClaimClassId::new("parent_class", 1)),
            requirements: vec![EvidenceRequirement {
                id: "req_a".to_string(),
                level: RequirementLevel::Recommended, // attempted weakening
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        reg.register(child).unwrap(); // structural validation alone still passes

        let result = reg.effective_requirements(&ClaimClassId::new("child_class", 1));
        assert!(matches!(
            result,
            Err(ContractError::WeakenedRequirement { .. })
        ));
    }

    #[test]
    fn child_contract_cannot_lower_min_coverage() {
        let mut reg = ContractRegistry::new();
        let parent = EpistemicContract {
            claim_class: ClaimClassId::new("parent_cov", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "req_a".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement { min_items: 2 },
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        reg.register(parent).unwrap();
        let child = EpistemicContract {
            claim_class: ClaimClassId::new("child_cov", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: Some(ClaimClassId::new("parent_cov", 1)),
            requirements: vec![EvidenceRequirement {
                id: "req_a".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement { min_items: 1 }, // weaker
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        reg.register(child).unwrap();
        let result = reg.effective_requirements(&ClaimClassId::new("child_cov", 1));
        assert!(matches!(
            result,
            Err(ContractError::WeakenedRequirement { .. })
        ));
    }

    #[test]
    fn child_contract_cannot_narrow_required_trust_classes() {
        let mut reg = ContractRegistry::new();
        let parent = EpistemicContract {
            claim_class: ClaimClassId::new("parent_trust", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "req_a".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![
                    TrustClass::HostObserved,
                    TrustClass::IndependentExternal,
                ],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        reg.register(parent).unwrap();
        let child = EpistemicContract {
            claim_class: ClaimClassId::new("child_trust", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: Some(ClaimClassId::new("parent_trust", 1)),
            requirements: vec![EvidenceRequirement {
                id: "req_a".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                // drops IndependentExternal that the parent Required.
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        reg.register(child).unwrap();
        let result = reg.effective_requirements(&ClaimClassId::new("child_trust", 1));
        assert!(matches!(
            result,
            Err(ContractError::WeakenedRequirement { .. })
        ));
    }

    #[test]
    fn child_contract_may_strengthen_inherited_requirement() {
        let mut reg = ContractRegistry::new();
        let parent = EpistemicContract {
            claim_class: ClaimClassId::new("parent_strong", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "req_a".to_string(),
                level: RequirementLevel::Recommended,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        reg.register(parent).unwrap();
        let child = EpistemicContract {
            claim_class: ClaimClassId::new("child_strong", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: Some(ClaimClassId::new("parent_strong", 1)),
            requirements: vec![EvidenceRequirement {
                id: "req_a".to_string(),
                level: RequirementLevel::Required, // strengthening, allowed
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement { min_items: 3 },
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        reg.register(child).unwrap();
        let result = reg
            .effective_requirements(&ClaimClassId::new("child_strong", 1))
            .expect("strengthening must be allowed");
        let req = result.iter().find(|r| r.id == "req_a").unwrap();
        assert_eq!(req.level, RequirementLevel::Required);
        assert_eq!(req.min_coverage.min_items, 3);
    }

    #[test]
    fn a_requirement_not_mentioned_by_child_is_inherited_unchanged() {
        let mut reg = ContractRegistry::new();
        let parent = EpistemicContract {
            claim_class: ClaimClassId::new("parent_keep", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "req_kept".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        reg.register(parent).unwrap();
        let child = EpistemicContract {
            claim_class: ClaimClassId::new("child_keep", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: Some(ClaimClassId::new("parent_keep", 1)),
            requirements: vec![], // does not mention req_kept at all
        };
        reg.register(child).unwrap();
        let result = reg
            .effective_requirements(&ClaimClassId::new("child_keep", 1))
            .expect("no override is not a removal");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "req_kept");
        assert_eq!(result[0].level, RequirementLevel::Required);
    }

    #[test]
    fn inheritance_cycle_is_rejected() {
        let mut reg = ContractRegistry::new();
        reg.register(EpistemicContract {
            claim_class: ClaimClassId::new("cycle_a", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: Some(ClaimClassId::new("cycle_b", 1)),
            requirements: vec![],
        })
        .unwrap();
        reg.register(EpistemicContract {
            claim_class: ClaimClassId::new("cycle_b", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: Some(ClaimClassId::new("cycle_a", 1)),
            requirements: vec![],
        })
        .unwrap();
        let result = reg.effective_requirements(&ClaimClassId::new("cycle_a", 1));
        assert!(matches!(
            result,
            Err(ContractError::InheritanceCycle { .. })
        ));
    }

    #[test]
    fn unsatisfiable_required_requirement_rejected_at_registration() {
        let mut reg = ContractRegistry::new();
        let bad = EpistemicContract {
            claim_class: ClaimClassId::new("bad_class", 1),
            schema_version: EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "impossible".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![], // unsatisfiable
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        };
        let result = reg.register(bad);
        assert!(matches!(
            result,
            Err(ContractError::UnsatisfiableRequirement { .. })
        ));
    }

    // --- state-collapsing checks: every state stays distinct in real paths ---

    #[test]
    fn stale_evidence_is_not_conflated_with_unavailable_or_unsatisfied() {
        let reg = registry_with_all();
        let cc = ClaimClassId::new("build_succeeded", 1);
        let claim = claim("build_succeeded", "2026-09-24T02:00:00Z");
        // Older than build_succeeded's 3600s freshness window.
        let stale_ev = evidence(EvidenceKind::ExitCode, "2026-09-24T00:00:00Z");
        let trust_of = |_: &Evidence| Some(TrustClass::HostObserved);
        let assessment =
            assess_claim(&reg, &cc, &claim, &[&stale_ev], &[], &trust_of).expect("assess ok");
        let req = &assessment.per_requirement[0];
        assert_eq!(req.state, SatisfactionState::Stale);
        assert_ne!(req.state, SatisfactionState::Unavailable);
        assert_ne!(req.state, SatisfactionState::Unsatisfied);
    }

    #[test]
    fn all_seven_named_states_are_pairwise_distinct() {
        let states = [
            SatisfactionState::Satisfied,
            SatisfactionState::Unsatisfied,
            SatisfactionState::Unavailable,
            SatisfactionState::Stale,
            SatisfactionState::Contradicted,
            SatisfactionState::NotApplicable,
            SatisfactionState::Unknown,
        ];
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "states at {i} and {j} must be distinct");
                }
            }
        }
    }

    // --- determinism / canonical serialization ---

    #[test]
    fn canonical_json_is_deterministic_across_repeated_serialization() {
        let contract = tests_passed();
        let first = to_canonical_json(&contract).unwrap();
        let second = to_canonical_json(&contract).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn canonical_json_round_trips_through_deserialization_unchanged() {
        let contract = security_defect_fixed();
        let json = to_canonical_json(&contract).unwrap();
        let parsed: EpistemicContract = serde_json::from_str(&json).unwrap();
        let rejsoned = to_canonical_json(&parsed).unwrap();
        assert_eq!(json, rejsoned);
    }

    #[test]
    fn canonical_json_key_order_is_independent_of_struct_field_order_in_maps() {
        // Build the same logical object two different ways (via a Value with
        // keys inserted in different orders) and confirm canonicalization
        // converges to the same string either way.
        let mut m1 = serde_json::Map::new();
        m1.insert("b".to_string(), serde_json::json!(1));
        m1.insert("a".to_string(), serde_json::json!(2));
        let mut m2 = serde_json::Map::new();
        m2.insert("a".to_string(), serde_json::json!(2));
        m2.insert("b".to_string(), serde_json::json!(1));
        let s1 = to_canonical_json(&serde_json::Value::Object(m1)).unwrap();
        let s2 = to_canonical_json(&serde_json::Value::Object(m2)).unwrap();
        assert_eq!(s1, s2);
    }

    // --- all representative contracts must validate and register cleanly ---

    #[test]
    fn all_six_representative_contracts_validate_and_register() {
        let reg = registry_with_all();
        for cc_name in [
            "tests_passed",
            "build_succeeded",
            "file_changed",
            "commit_push_completed",
            "deployment_healthy",
            "security_defect_fixed",
        ] {
            let cc = ClaimClassId::new(cc_name, 1);
            assert!(matches!(reg.lookup(&cc), ContractLookup::Found(_)));
            reg.effective_requirements(&cc)
                .unwrap_or_else(|e| panic!("{cc_name} must resolve: {e:?}"));
        }
    }
}
