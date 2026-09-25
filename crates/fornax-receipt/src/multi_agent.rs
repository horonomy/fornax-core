//! Multi-agent shared-failure and coordination-signal detection (FORNX-385,
//! parent epic FORNX-376 / Stage 9).
//!
//! **What this extends.** [`crate::delegation`] (FORNX-384) already tracks,
//! per envelope, the deduplicated [`FamilyBasis`] set backing one delegated
//! task (`aggregate_source_family_bases`) and a linear ancestor chain
//! (`lineage`). This module generalizes that into a genuine *cross-agent*
//! graph: when several distinct agents' delegation envelopes purportedly
//! confirm the same underlying claim, this module answers how many
//! *effectively independent* sources actually back them -- never how many
//! agents merely reported.
//!
//! **Ground truth on which lineage dimensions are actually modeled, and
//! which ones actually reduce the independent count.** The ticket's scope
//! names eight dimensions (agent instance, model/provider/version, prompt/
//! template lineage, parent task, retrieval source, shared tool/
//! environment, judge/monitor lineage, delegation chain). Only **shared
//! retrieval/tool/evidence source** genuinely reduces
//! [`MultiAgentDependencyReport::effective_independent_sources`] (AC1/AC4)
//! -- captured through [`FamilyBasis`]: two agents whose receipts trace to
//! the same underlying `source_event_id`/`derived_from` ancestry/
//! `correlation_group` already share a family basis regardless of which
//! agent reported it, and this is the *only* key space
//! [`analyze_dependency`]'s union-find merges on.
//!
//! **Agent instance** ([`DelegationIdentity::agent_id`]) and **parent
//! task**/**delegation chain** ([`LineageEntry::parent_task_id`],
//! [`DelegationEnvelopeBody::lineage`]) are real, structural facts this
//! crate observes without inventing new schema, but they are deliberately
//! **not** used to merge independence -- see [`CoordinationPattern`]'s doc
//! comment for why (a parent legitimately fanning out unrelated sub-checks
//! to N children must not read as one source merely because an
//! orchestrator exists). They instead feed
//! [`detect_coordination_signals`]'s output-agreement check (AC6:
//! "delegation envelopes preserve enough lineage for downstream
//! detection").
//!
//! Model/provider/version *is* present on a receipt
//! (`ReceiptBody::provenance.provider`/`.adapter_version`), but sharing a
//! provider is common between genuinely independent agents (many
//! unrelated deployments legitimately run the same model) and is
//! deliberately **not** used to reduce the independent-source count --
//! doing so would be exactly the "inference from correlation alone" the
//! ticket's own Non-goals forbid. Prompt/template lineage, shared
//! tool/environment (beyond what a shared `source_event_id` already
//! implies) and judge/monitor lineage have no supporting field anywhere in
//! this workspace today; this module does not fabricate detection for them.
//! This is a disclosed, honest scope boundary, not a silent gap.
//!
//! **Conservative vocabulary, never collapsed into another layer's.**
//! [`MultiAgentSignal`] is its own closed type -- distinct from
//! [`fornax_types::Verdict`], [`fornax_verify::decision::RecommendationAction`],
//! [`fornax_types::epistemic_contract::SatisfactionState`],
//! [`crate::gate::GateOutcome`], and [`crate::delegation::DelegationOutcome`],
//! mirroring [`crate::delegation`]'s own five-vocabularies discipline (now a
//! sixth). [`MultiAgentSignal::CollusionHypothesis`] is the strongest,
//! rarest variant and is **only constructible with non-empty supporting
//! evidence** via [`MultiAgentSignal::collusion_hypothesis`] -- this
//! module's own structural detectors never emit one; that variant exists
//! for a downstream caller who has gathered real corroborating evidence
//! beyond what a bare dependency graph can show. See its doc comment.
//!
//! **Unknown lineage is handled conservatively by default (AC3).** An
//! envelope with zero embedded receipts carries no evidentiary backing to
//! judge independence from at all. [`MultiAgentPolicy::default`] treats
//! this case conservatively: such an envelope is excluded from
//! `effective_independent_sources` (it is never *counted* as adding
//! confirmation) and surfaced as [`MultiAgentSignal::SharedFailureRisk`]
//! with [`SharedFailureReason::UnknownLineage`]. Setting
//! [`MultiAgentPolicy::treat_unknown_lineage_as_independent`] to `true`
//! reverts to counting it as its own singleton source -- an explicit,
//! auditable policy choice, never a silent default.
//!
//! **Cost is bounded by agent count, not evidence count (AC7).** This
//! module never re-derives [`fornax_verify::independence::SourceFamilyMap`]
//! from raw evidence -- it only reads each envelope's already-computed
//! `aggregate_source_family_bases` (bounded by that envelope's own receipt
//! count, computed once at issuance by [`crate::delegation`]). Grouping is a
//! union-find over `O(agents × bases_per_agent)` reverse-index insertions,
//! not over evidence at all, so it does not re-trigger the O(n² log n)
//! `SourceFamilyMap::build` cost `fornax_verify::independence`'s own module
//! docs already disclose (that gap remains fornax-verify's, unaddressed
//! here as out of this ticket's scope -- it was already out of scope for
//! FORNX-378/382/384, which cite it rather than fix it).
//!
//! # Non-goals (inherited, restated)
//!
//! No universal collusion detector. No inference of intent from text or
//! provider similarity alone -- shared model/provider is visible in the
//! underlying receipts but is deliberately never used by this module to
//! reduce an independent-source count or to emit
//! [`MultiAgentSignal::CoordinationSignal`]/[`MultiAgentSignal::CollusionHypothesis`]
//! on its own. No new multi-agent orchestration runtime.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use fornax_verify::independence::FamilyBasis;

use crate::delegation::{DelegationEnvelope, DelegationOutcome};

/// Why an envelope was excluded from, or flagged alongside,
/// [`MultiAgentDependencyReport::effective_independent_sources`] under
/// conservative-unknown-lineage handling (AC3). Its own small closed
/// vocabulary -- never a `String` reason, so a caller can match
/// exhaustively rather than pattern-match on prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedFailureReason {
    /// The envelope carries zero embedded receipts -- no evidentiary
    /// backing exists to judge independence from at all.
    UnknownLineage,
}

/// A structurally-observed agreement pattern across sibling envelopes
/// (delegated under the same parent task) that share **no** evidence-level
/// [`FamilyBasis`] with each other, yet produced an identical result --
/// worth a human's attention, but a fact about the *outputs*, not an
/// assertion about *why* they agree. See [`detect_coordination_signals`].
///
/// **Why sharing a parent task alone never merges independence.** A parent
/// legitimately fanning out N *unrelated* sub-checks to N children (e.g.
/// "verify tests", "verify lint", "verify deploy health") is the ordinary,
/// benign shape of delegation -- those children's evidence is genuinely
/// independent of each other even though they share a `parent_task_id`.
/// Collapsing them into one effective source merely because an orchestrator
/// exists would be exactly the "inference from correlation alone" the
/// ticket's own Non-goals forbid, just at the delegation-structure layer
/// instead of the text-similarity layer. `parent_task_id`/lineage sharing
/// is real, useful *input* for the coordination-pattern detector below
/// (AC6: "delegation envelopes preserve enough lineage for downstream
/// detection") -- but only [`FamilyBasis`] sharing, a genuine evidence-level
/// fact, ever reduces [`MultiAgentDependencyReport::effective_independent_sources`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationPattern {
    /// Two or more envelopes delegated under the same parent task, sharing
    /// no [`FamilyBasis`] with each other, nonetheless report the identical
    /// [`DelegationOutcome`] and the identical set of unresolved
    /// requirement ids.
    IdenticalOutcomeAcrossUnrelatedSiblings,
}

/// This module's own closed vocabulary -- never conflated with
/// [`fornax_types::Verdict`], [`fornax_verify::decision::RecommendationAction`],
/// [`fornax_types::epistemic_contract::SatisfactionState`],
/// [`crate::gate::GateOutcome`], or [`crate::delegation::DelegationOutcome`].
/// See module docs for the conservative-naming discipline and why
/// [`Self::CollusionHypothesis`] is the one variant this module's own
/// detectors never emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiAgentSignal {
    /// One or more agents' delegation envelopes had no evidentiary backing
    /// to judge independence from (AC3).
    SharedFailureRisk {
        agent_ids: Vec<String>,
        reason: SharedFailureReason,
    },
    /// Two or more agents' apparent confirmations trace to the same
    /// underlying evidence source and were merged into one effective source
    /// (AC1) -- always backed by at least one real [`FamilyBasis`], never a
    /// delegation-structure heuristic (see [`CoordinationPattern`]'s doc
    /// comment for why parent-task sharing alone is excluded here).
    CommonSource {
        agent_ids: Vec<String>,
        bases: Vec<FamilyBasis>,
    },
    /// A structural agreement pattern was observed among agents that do
    /// *not* share a common source (module docs: "a fact about the
    /// outputs, not an assertion about why they agree").
    CoordinationSignal {
        agent_ids: Vec<String>,
        pattern: CoordinationPattern,
    },
    /// The strongest signal: an explicit hypothesis that observed
    /// coordination reflects deliberate collusion rather than incidental
    /// shared infrastructure. **Never constructible with empty evidence**
    /// -- see [`Self::collusion_hypothesis`]. No detector in this module
    /// ever emits one; this variant exists for a caller supplying evidence
    /// this module cannot itself derive (e.g. an out-of-band audit
    /// finding).
    CollusionHypothesis {
        agent_ids: Vec<String>,
        supporting_evidence: Vec<String>,
    },
}

impl MultiAgentSignal {
    /// The only constructor for [`Self::CollusionHypothesis`]. Returns
    /// `None` if `supporting_evidence` is empty -- by construction, this
    /// variant can never be created from correlation/similarity alone
    /// (Non-goals: "no inference of intent from text similarity alone";
    /// AC5: "never label malicious collusion without supporting
    /// evidence").
    pub fn collusion_hypothesis(
        agent_ids: Vec<String>,
        supporting_evidence: Vec<String>,
    ) -> Option<Self> {
        if supporting_evidence.is_empty() {
            return None;
        }
        Some(Self::CollusionHypothesis {
            agent_ids,
            supporting_evidence,
        })
    }
}

/// One group of agents this module judged to be a single effective source
/// (or, for a singleton group, a genuinely independent one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyGroup {
    /// Sorted, deduplicated.
    pub agent_ids: Vec<String>,
    /// Sorted, deduplicated real [`FamilyBasis`] values shared across this
    /// group's envelopes. Never empty for a listed group -- see
    /// [`MultiAgentDependencyReport::dependent_groups`].
    pub bases: Vec<FamilyBasis>,
}

/// How to treat an envelope with no evidentiary backing at all. See module
/// docs' "Unknown lineage is handled conservatively by default (AC3)".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MultiAgentPolicy {
    /// `false` (the conservative default): an envelope with zero embedded
    /// receipts is excluded from `effective_independent_sources` and
    /// surfaced as [`MultiAgentSignal::SharedFailureRisk`]. `true`: count
    /// it as its own independent singleton -- an explicit, auditable
    /// opt-out, never silent.
    pub treat_unknown_lineage_as_independent: bool,
}

/// The result of analyzing a set of delegation envelopes purportedly
/// confirming the same underlying claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiAgentDependencyReport {
    pub total_agents: usize,
    /// Never greater than `total_agents`. The number a fusion/decision
    /// layer should treat as the real corroboration count (AC1/AC4) --
    /// strictly less than `total_agents` whenever any [`DependencyGroup`]
    /// has more than one member, or any envelope was excluded under
    /// conservative unknown-lineage handling.
    pub effective_independent_sources: usize,
    /// One entry per group with 2+ members that shares a
    /// shared [`FamilyBasis`] -- genuinely independent singletons are not
    /// listed here (they contribute to the counts above without needing
    /// an explanation).
    pub dependent_groups: Vec<DependencyGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub signals: Vec<MultiAgentSignal>,
}

fn agent_ids_of(envelopes: &[DelegationEnvelope]) -> Vec<String> {
    let mut ids: BTreeSet<String> = envelopes
        .iter()
        .map(|e| e.body().child.agent_id.clone())
        .collect();
    ids.retain(|s| !s.is_empty());
    ids.into_iter().collect()
}

/// Union-find over envelope indices. Internal only -- callers never see raw
/// indices, only agent ids (envelope ownership by agent is the externally
/// meaningful identity; two envelopes from the same agent are already the
/// same "agent" for this analysis by construction of the caller's input).
struct UnionFind {
    parent: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
        }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            let root = self.find(self.parent[x]);
            self.parent[x] = root;
        }
        self.parent[x]
    }

    fn union(&mut self, a: usize, b: usize) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
            self.parent[hi] = lo;
        }
    }
}

/// Computes, for `envelopes` purportedly confirming the same underlying
/// claim, how many effectively independent sources actually back them --
/// see module docs. `envelopes` may be any size and in any order; output is
/// deterministic regardless of input order (agent ids and bases are sorted
/// before comparison/serialization).
///
/// Cost: `O(A × B log(A × B))` where `A = envelopes.len()` and `B` is the
/// average number of `aggregate_source_family_bases`/lineage entries per
/// envelope -- never a function of the underlying evidence pool size (AC7,
/// module docs).
pub fn analyze_dependency(
    envelopes: &[DelegationEnvelope],
    policy: MultiAgentPolicy,
) -> MultiAgentDependencyReport {
    let n = envelopes.len();
    let mut uf = UnionFind::new(n);

    // The *only* key space that ever merges independence: a real,
    // evidence-level FamilyBasis. Parent-task/lineage-ancestor sharing is
    // deliberately excluded here -- see [`CoordinationPattern`]'s doc
    // comment for why.
    let mut by_basis: BTreeMap<FamilyBasis, Vec<usize>> = BTreeMap::new();
    for (i, env) in envelopes.iter().enumerate() {
        for basis in &env.body().aggregate_source_family_bases {
            by_basis.entry(basis.clone()).or_default().push(i);
        }
    }

    let mut basis_of_pair: BTreeMap<(usize, usize), BTreeSet<FamilyBasis>> = BTreeMap::new();
    let mut record_pair = |a: usize, b: usize, basis: FamilyBasis| {
        let key = if a < b { (a, b) } else { (b, a) };
        basis_of_pair.entry(key).or_default().insert(basis);
    };

    for (basis, ids) in &by_basis {
        for w in ids.windows(2) {
            uf.union(w[0], w[1]);
        }
        if ids.len() > 1 {
            for i in 1..ids.len() {
                record_pair(ids[0], ids[i], basis.clone());
            }
        }
    }

    // Unknown-lineage envelopes (zero receipts) never contribute a basis
    // key above, so union-find already leaves them as their own singleton
    // root -- exactly the "not merged with anything" starting state. What
    // remains is whether the *policy* counts that singleton at all.
    let mut members_by_root: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let root = uf.find(i);
        members_by_root.entry(root).or_default().push(i);
    }

    let mut dependent_groups = Vec::new();
    let mut signals = Vec::new();
    let mut effective_independent_sources = 0usize;

    for (_, members) in members_by_root {
        let is_unknown_lineage_singleton =
            members.len() == 1 && envelopes[members[0]].body().receipts.is_empty();

        if is_unknown_lineage_singleton {
            let agent_id = envelopes[members[0]].body().child.agent_id.clone();
            signals.push(MultiAgentSignal::SharedFailureRisk {
                agent_ids: vec![agent_id],
                reason: SharedFailureReason::UnknownLineage,
            });
            if policy.treat_unknown_lineage_as_independent {
                effective_independent_sources += 1;
            }
            continue;
        }

        effective_independent_sources += 1;

        if members.len() > 1 {
            let mut agent_ids: BTreeSet<String> = BTreeSet::new();
            let mut bases: BTreeSet<FamilyBasis> = BTreeSet::new();
            for w in 0..members.len() {
                for v in (w + 1)..members.len() {
                    if let Some(b) =
                        basis_of_pair.get(&(members[w].min(members[v]), members[w].max(members[v])))
                    {
                        bases.extend(b.iter().cloned());
                    }
                }
            }
            for &idx in &members {
                agent_ids.insert(envelopes[idx].body().child.agent_id.clone());
            }
            let agent_ids: Vec<String> = agent_ids.into_iter().collect();
            let bases: Vec<FamilyBasis> = bases.into_iter().collect();
            signals.push(MultiAgentSignal::CommonSource {
                agent_ids: agent_ids.clone(),
                bases: bases.clone(),
            });
            dependent_groups.push(DependencyGroup { agent_ids, bases });
        }
    }

    signals.extend(detect_coordination_signals(envelopes, &basis_of_pair));

    dependent_groups.sort_by(|a, b| a.agent_ids.cmp(&b.agent_ids));

    MultiAgentDependencyReport {
        total_agents: agent_ids_of(envelopes).len(),
        effective_independent_sources,
        dependent_groups,
        signals,
    }
}

/// Detects [`CoordinationPattern::IdenticalOutcomeAcrossUnrelatedSiblings`]:
/// two or more envelopes sharing a parent task (siblings) that share **no**
/// [`FamilyBasis`] with each other, yet report the identical
/// [`DelegationOutcome`] and identical unresolved-requirement-id set. A
/// purely structural observation about outputs -- asserts nothing about
/// *why* they agree (module docs, AC5, Non-goals). This is the one place
/// `LineageEntry::parent_task_id` is used at all (AC6) -- deliberately never
/// to reduce `effective_independent_sources` (see [`CoordinationPattern`]'s
/// doc comment).
fn detect_coordination_signals(
    envelopes: &[DelegationEnvelope],
    basis_of_pair: &BTreeMap<(usize, usize), BTreeSet<FamilyBasis>>,
) -> Vec<MultiAgentSignal> {
    let mut by_parent_task: BTreeMap<Uuid, Vec<usize>> = BTreeMap::new();
    for (i, env) in envelopes.iter().enumerate() {
        for entry in &env.body().lineage {
            by_parent_task
                .entry(entry.parent_task_id)
                .or_default()
                .push(i);
        }
    }

    let mut signals = Vec::new();
    for ids in by_parent_task.values() {
        if ids.len() < 2 {
            continue;
        }
        // `DelegationOutcome` deliberately carries no `Ord` impl (FORNX-384
        // never needed to sort/key by it) -- a serialized discriminant
        // string is a fine, purely-internal grouping key here; it is never
        // exposed.
        let outcome_key = |o: &DelegationOutcome| {
            serde_json::to_string(o).expect("DelegationOutcome serialization cannot fail")
        };
        let mut by_signature: BTreeMap<(String, Vec<String>), Vec<usize>> = BTreeMap::new();
        for &i in ids {
            let body = envelopes[i].body();
            let mut unresolved = body.unresolved_requirement_ids.clone();
            unresolved.sort();
            by_signature
                .entry((outcome_key(&body.outcome), unresolved))
                .or_default()
                .push(i);
        }
        for group in by_signature.values() {
            if group.len() < 2 {
                continue;
            }
            let shares_no_basis = group.iter().enumerate().all(|(a_pos, &a)| {
                group[(a_pos + 1)..].iter().all(|&b| {
                    let key = if a < b { (a, b) } else { (b, a) };
                    !basis_of_pair.contains_key(&key)
                })
            });
            if shares_no_basis {
                let agent_ids: Vec<String> = group
                    .iter()
                    .map(|&i| envelopes[i].body().child.agent_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                signals.push(MultiAgentSignal::CoordinationSignal {
                    agent_ids,
                    pattern: CoordinationPattern::IdenticalOutcomeAcrossUnrelatedSiblings,
                });
            }
        }
    }
    signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::{
        issue_delegation_envelope, DelegationIdentity, DelegationInputs, LineageEntry,
    };
    use crate::schema::IntegrityReceipt;
    use fornax_types::epistemic_contract::ClaimClassId;
    use fornax_types::sensor::{CollectionMethod, EvidenceSource, TrustClass};
    use fornax_types::{
        Claim, Evidence, EvidenceGraph, EvidenceKind, EvidenceLink, EvidenceRelation,
    };
    use fornax_verify::contract_satisfaction::default_registry;
    use fornax_verify::decision::{Recommendation, RecommendationAction, RiskClass};
    use fornax_verify::fusion::{FusedFinding, UncertaintyBand};
    use fornax_verify::independence::SourceFamilyMap;

    fn claim(session_id: &str, event: Uuid) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            source_event_id: event,
            text: "claim about tests_passed".to_string(),
            subject: "tests_passed".to_string(),
            claimed_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn evidence_on_event(session_id: &str, event: Uuid, trust: TrustClass) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            source_event_id: event,
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test".to_string(),
            source: Some(EvidenceSource {
                sensor_name: "test_sensor".to_string(),
                trust_class: trust,
                collected_at: "2026-01-01T00:00:00Z".to_string(),
                provider: None,
                collection_method: CollectionMethod::HookCallback,
                collector_version: None,
                freshness: Default::default(),
                tamper_boundary: Default::default(),
                correlation_group: None,
                derived_from: Vec::new(),
            }),
            extension: None,
            evidence_purged: false,
        }
    }

    fn provenance() -> fornax_types::calibration::CalibrationProvenance {
        fornax_types::calibration::CalibrationProvenance {
            schema_version: 1,
            provider: "claude_code".into(),
            adapter_version: None,
            capability_schema_version: 1,
            capability_fingerprint: vec![],
            fusion_policy_name: "baseline".into(),
            fusion_policy_version: 2,
            decision_policy_name: "default".into(),
            decision_policy_version: 1,
            reliability_policy_version: 1,
            disabled_sensors: vec![],
            active_policy_revision_digest: None,
            model_version: None,
            model_family: None,
        }
    }

    fn calibration() -> fornax_verify::calibration::CalibrationAssessment {
        fornax_verify::calibration::CalibrationAssessment {
            state: fornax_verify::calibration::CalibrationState::NoActiveCalibration,
            policy_version: 1,
        }
    }

    /// `families` is built by the caller over the *combined* evidence pool
    /// across every agent in a scenario -- exactly how a real coordinator
    /// observing all its delegated agents' evidence in one shared store
    /// would compute it (mirroring `contract_satisfaction::assess`'s own
    /// "one `SourceFamilyMap` over the full pool" discipline). A receipt
    /// still only *references* its own `evs`; `families` only supplies the
    /// family-membership lookup so a basis spanning receipts is visible in
    /// each one's own `coverage.source_family_bases`.
    fn issue_one_receipt(
        c: &Claim,
        evs: &[Evidence],
        families: &SourceFamilyMap,
    ) -> IntegrityReceipt {
        let links: Vec<EvidenceLink> = evs
            .iter()
            .map(|e| EvidenceLink {
                id: Uuid::new_v4(),
                session_id: c.session_id.clone(),
                claim_id: c.id,
                evidence_id: e.id,
                relation: EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:00Z".to_string(),
            })
            .collect();
        let graph = EvidenceGraph {
            links,
            missing: vec![],
        };
        let fused = FusedFinding {
            claim_id: c.id,
            verdict: fornax_types::Verdict::Verified,
            uncertainty: UncertaintyBand::Qualified,
            rationale: vec![],
            counted_link_ids: evs.iter().map(|e| e.id).collect(),
            discounted_link_ids: vec![],
            missing_evidence_ids: vec![],
            unresolved_conflict: false,
            policy_name: "baseline".to_string(),
            policy_version: 2,
            computed_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let rec = Recommendation {
            claim_id: c.id,
            action: RecommendationAction::Proceed,
            risk_class: RiskClass::Balanced,
            policy_name: "default".to_string(),
            policy_version: 1,
            rationale_summary: "ok".to_string(),
        };
        let prov = provenance();
        let cal = calibration();
        let inputs = crate::issue::ReceiptInputs {
            claim: c,
            graph: &graph,
            evidence: evs,
            fused: &fused,
            recommendation: &rec,
            gaps: &[],
            families,
            provenance: &prov,
            calibration: &cal,
            issuer: "fornax-cli/multi-agent-test/v1",
            home_identity: "abcd1234",
        };
        crate::issue::issue_receipt(&inputs, "2026-01-01T00:00:00Z", None)
            .expect("well-formed test inputs always issue")
    }

    fn envelope_for(
        agent_id: &str,
        claim: &Claim,
        receipts: Vec<IntegrityReceipt>,
        lineage: Vec<LineageEntry>,
    ) -> DelegationEnvelope {
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        // Assessment content doesn't matter for this module's tests -- only
        // the receipts' own family bases and the envelope's lineage do.
        let assessment =
            fornax_verify::contract_satisfaction::assess(&registry, &cc, claim, &[], &[])
                .expect("assess ok");
        issue_delegation_envelope(
            DelegationInputs {
                parent: DelegationIdentity {
                    agent_id: "agent-parent".to_string(),
                    task_id: Uuid::from_u128(999),
                },
                child: DelegationIdentity {
                    agent_id: agent_id.to_string(),
                    task_id: Uuid::new_v4(),
                },
                claim_class: cc,
                permitted_actions_text: "run the suite",
                expected_outputs_text: "a verdict",
                assessment: &assessment,
                receipts,
                lineage,
                child_reported_unavailable: false,
            },
            "2026-01-01T00:00:00Z",
            None,
        )
    }

    // --- AC1/AC4: N agents sharing a material root source cannot create N
    // independent confirmations; a real false-uplift case is prevented ---

    #[test]
    fn three_agents_fanned_out_from_one_agent_turn_collapse_to_one_effective_source() {
        // The live FORNX-347 case: one AgentAdjacent event fanned out to
        // three "independent" agent reports, all citing evidence stamped
        // with the same source_event_id on the agent-reported channel.
        let event = Uuid::new_v4();
        let claims: Vec<Claim> = (0..3).map(|_| claim("session-1", event)).collect();
        let all_evidence: Vec<Evidence> = (0..3)
            .map(|_| evidence_on_event("session-1", event, TrustClass::AgentAdjacent))
            .collect();
        // Built once over the *combined* pool -- exactly how a real
        // coordinator observing all three agents' evidence in one shared
        // store would compute family membership (see `issue_one_receipt`'s
        // doc comment above).
        let families = SourceFamilyMap::build(&all_evidence);

        let mut envelopes = Vec::new();
        for (i, agent) in ["agent-a", "agent-b", "agent-c"].into_iter().enumerate() {
            let receipt = issue_one_receipt(
                &claims[i],
                std::slice::from_ref(&all_evidence[i]),
                &families,
            );
            envelopes.push(envelope_for(agent, &claims[i], vec![receipt], vec![]));
        }

        let report = analyze_dependency(&envelopes, MultiAgentPolicy::default());
        assert_eq!(report.total_agents, 3);
        assert_eq!(
            report.effective_independent_sources, 1,
            "three agents citing the same underlying agent turn must not be counted as three independent confirmations -- this is the false-uplift case"
        );
        assert_eq!(report.dependent_groups.len(), 1);
        assert_eq!(report.dependent_groups[0].agent_ids.len(), 3);
        assert!(report
            .signals
            .iter()
            .any(|s| matches!(s, MultiAgentSignal::CommonSource { .. })));
    }

    // --- AC2: independent CI/runtime/DB/probe evidence remains
    // distinguishable from agent-family evidence -------------------------

    #[test]
    fn a_genuinely_independent_probe_agent_is_never_merged_into_the_shared_family() {
        let shared_event = Uuid::new_v4();
        let c1 = claim("session-1", shared_event);
        let e1 = evidence_on_event("session-1", shared_event, TrustClass::AgentAdjacent);
        let e2 = evidence_on_event("session-1", shared_event, TrustClass::AgentAdjacent);

        // A third, genuinely independent agent whose receipt is backed by
        // HostObserved evidence on a *different* event -- must never be
        // pulled into the shared-agent-turn family (independence.rs's own
        // "never collapse HostObserved into an agent-channel union" rule,
        // FORNX-347).
        let c3 = claim("session-2", Uuid::new_v4());
        let e3 = evidence_on_event("session-2", Uuid::new_v4(), TrustClass::HostObserved);

        let families = SourceFamilyMap::build(&[e1.clone(), e2.clone(), e3.clone()]);
        let receipt_a = issue_one_receipt(&c1, std::slice::from_ref(&e1), &families);
        let receipt_b = issue_one_receipt(&c1, std::slice::from_ref(&e2), &families);
        let receipt_c = issue_one_receipt(&c3, std::slice::from_ref(&e3), &families);

        let envelopes = vec![
            envelope_for("agent-a", &c1, vec![receipt_a], vec![]),
            envelope_for("agent-b", &c1, vec![receipt_b], vec![]),
            envelope_for("agent-c", &c3, vec![receipt_c], vec![]),
        ];

        let report = analyze_dependency(&envelopes, MultiAgentPolicy::default());
        assert_eq!(report.total_agents, 3);
        assert_eq!(
            report.effective_independent_sources, 2,
            "agent-a/agent-b collapse to one shared-turn source; agent-c's independent probe evidence must remain its own distinct source"
        );
        assert_eq!(report.dependent_groups.len(), 1);
        assert!(!report.dependent_groups[0]
            .agent_ids
            .contains(&"agent-c".to_string()));
    }

    // --- AC3: unknown lineage is explicit and handled conservatively/
    // configurably -------------------------------------------------------

    #[test]
    fn an_envelope_with_no_receipts_is_excluded_by_default_and_flagged() {
        let c = claim("session-1", Uuid::new_v4());
        let envelopes = vec![envelope_for("agent-a", &c, vec![], vec![])];

        let report = analyze_dependency(&envelopes, MultiAgentPolicy::default());
        assert_eq!(report.total_agents, 1);
        assert_eq!(
            report.effective_independent_sources, 0,
            "an envelope with zero evidentiary backing must not be silently counted as an independent confirmation"
        );
        assert!(report.signals.iter().any(|s| matches!(
            s,
            MultiAgentSignal::SharedFailureRisk {
                reason: SharedFailureReason::UnknownLineage,
                ..
            }
        )));
    }

    #[test]
    fn unknown_lineage_is_counted_only_when_the_policy_explicitly_opts_in() {
        let c = claim("session-1", Uuid::new_v4());
        let envelopes = vec![envelope_for("agent-a", &c, vec![], vec![])];

        let report = analyze_dependency(
            &envelopes,
            MultiAgentPolicy {
                treat_unknown_lineage_as_independent: true,
            },
        );
        assert_eq!(report.effective_independent_sources, 1);
    }

    // --- AC5: coordination findings expose evidence/uncertainty and never
    // label malicious collusion without supporting evidence --------------

    #[test]
    fn collusion_hypothesis_cannot_be_constructed_with_empty_evidence() {
        assert!(
            MultiAgentSignal::collusion_hypothesis(vec!["agent-a".to_string()], vec![]).is_none()
        );
        assert!(MultiAgentSignal::collusion_hypothesis(
            vec!["agent-a".to_string()],
            vec!["an auditor manually confirmed shared credentials".to_string()]
        )
        .is_some());
    }

    #[test]
    fn no_detector_in_this_module_ever_emits_a_collusion_hypothesis() {
        // Even the strongest structural signal this module can find on its
        // own -- three agents sharing one root source -- must never
        // escalate past CommonSource.
        let event = Uuid::new_v4();
        let claims: Vec<Claim> = (0..3).map(|_| claim("session-1", event)).collect();
        let all_evidence: Vec<Evidence> = (0..3)
            .map(|_| evidence_on_event("session-1", event, TrustClass::AgentAdjacent))
            .collect();
        let families = SourceFamilyMap::build(&all_evidence);
        let mut envelopes = Vec::new();
        for (i, agent) in ["agent-a", "agent-b", "agent-c"].into_iter().enumerate() {
            let receipt = issue_one_receipt(
                &claims[i],
                std::slice::from_ref(&all_evidence[i]),
                &families,
            );
            envelopes.push(envelope_for(agent, &claims[i], vec![receipt], vec![]));
        }
        let report = analyze_dependency(&envelopes, MultiAgentPolicy::default());
        assert!(!report
            .signals
            .iter()
            .any(|s| matches!(s, MultiAgentSignal::CollusionHypothesis { .. })));
    }

    #[test]
    fn identical_outcome_across_unrelated_siblings_is_flagged_as_a_coordination_signal_not_collusion(
    ) {
        let parent_task = Uuid::from_u128(42);
        let lineage = vec![LineageEntry {
            parent_envelope_digest: "sha256:deadbeef".to_string(),
            parent_task_id: parent_task,
            depth: 1,
        }];
        // Two siblings under the same parent task, backed by evidence on
        // two *distinct* events (no shared basis), yet both report
        // Fulfilled with an empty unresolved set -- structurally identical
        // outputs from structurally unrelated inputs.
        let c1 = claim("session-1", Uuid::new_v4());
        let e1 = evidence_on_event("session-1", c1.source_event_id, TrustClass::HostObserved);
        let c2 = claim("session-2", Uuid::new_v4());
        let e2 = evidence_on_event("session-2", c2.source_event_id, TrustClass::HostObserved);
        let families = SourceFamilyMap::build(&[e1.clone(), e2.clone()]);
        let receipt1 = issue_one_receipt(&c1, std::slice::from_ref(&e1), &families);
        let receipt2 = issue_one_receipt(&c2, std::slice::from_ref(&e2), &families);

        let envelopes = vec![
            envelope_for("agent-a", &c1, vec![receipt1], lineage.clone()),
            envelope_for("agent-b", &c2, vec![receipt2], lineage),
        ];

        let report = analyze_dependency(&envelopes, MultiAgentPolicy::default());
        assert!(
            report
                .signals
                .iter()
                .any(|s| matches!(s, MultiAgentSignal::CoordinationSignal { pattern: CoordinationPattern::IdenticalOutcomeAcrossUnrelatedSiblings, .. })),
            "identical outcome/unresolved-set across siblings sharing no evidence family must surface as a CoordinationSignal"
        );
        assert!(
            !report
                .signals
                .iter()
                .any(|s| matches!(s, MultiAgentSignal::CollusionHypothesis { .. })),
            "a coordination pattern alone must never escalate to a collusion hypothesis"
        );
    }

    // --- AC6: delegation envelopes preserve enough lineage for downstream
    // detection ------------------------------------------------------------

    #[test]
    fn shared_parent_task_alone_never_reduces_the_independent_count() {
        // Two children legitimately fanned out from one parent to verify
        // two *unrelated* things (the ordinary, benign delegation shape) --
        // sharing a parent_task_id must never by itself collapse their
        // independent count, or every fan-out delegation would wrongly
        // read as one source. See CoordinationPattern's doc comment.
        let parent_task = Uuid::from_u128(7);
        let lineage = vec![LineageEntry {
            parent_envelope_digest: "sha256:cafebabe".to_string(),
            parent_task_id: parent_task,
            depth: 1,
        }];
        let c1 = claim("session-1", Uuid::new_v4());
        let e1 = evidence_on_event("session-1", c1.source_event_id, TrustClass::HostObserved);
        let c2 = claim("session-2", Uuid::new_v4());
        let e2 = evidence_on_event("session-2", c2.source_event_id, TrustClass::HostObserved);
        let families = SourceFamilyMap::build(&[e1.clone(), e2.clone()]);
        let receipt1 = issue_one_receipt(&c1, std::slice::from_ref(&e1), &families);
        let receipt2 = issue_one_receipt(&c2, std::slice::from_ref(&e2), &families);

        let envelopes = vec![
            envelope_for("agent-a", &c1, vec![receipt1], lineage.clone()),
            envelope_for("agent-b", &c2, vec![receipt2], lineage),
        ];

        let report = analyze_dependency(&envelopes, MultiAgentPolicy::default());
        assert_eq!(
            report.effective_independent_sources, 2,
            "sharing a parent task with no shared evidence family must not collapse two genuinely independent children into one source"
        );
        assert!(report.dependent_groups.is_empty());
    }

    #[test]
    fn shared_parent_task_lineage_is_still_used_for_coordination_detection() {
        // The corrected AC6 case: parent-task lineage never merges
        // independence (previous test), but it is still real, sufficient
        // input for the *coordination-signal* detector below -- these two
        // siblings share a parent task, share no evidence family, and
        // produce an identical result, which is exactly what
        // detect_coordination_signals flags.
        let parent_task = Uuid::from_u128(8);
        let lineage = vec![LineageEntry {
            parent_envelope_digest: "sha256:f00dcafe".to_string(),
            parent_task_id: parent_task,
            depth: 1,
        }];
        let c1 = claim("session-1", Uuid::new_v4());
        let e1 = evidence_on_event("session-1", c1.source_event_id, TrustClass::HostObserved);
        let c2 = claim("session-2", Uuid::new_v4());
        let e2 = evidence_on_event("session-2", c2.source_event_id, TrustClass::HostObserved);
        let families = SourceFamilyMap::build(&[e1.clone(), e2.clone()]);
        let receipt1 = issue_one_receipt(&c1, std::slice::from_ref(&e1), &families);
        let receipt2 = issue_one_receipt(&c2, std::slice::from_ref(&e2), &families);

        let envelopes = vec![
            envelope_for("agent-a", &c1, vec![receipt1], lineage.clone()),
            envelope_for("agent-b", &c2, vec![receipt2], lineage),
        ];

        let report = analyze_dependency(&envelopes, MultiAgentPolicy::default());
        assert_eq!(
            report.effective_independent_sources, 2,
            "still two independent sources -- coordination detection is informational, never count-reducing"
        );
        assert!(report.signals.iter().any(|s| matches!(
            s,
            MultiAgentSignal::CoordinationSignal {
                pattern: CoordinationPattern::IdenticalOutcomeAcrossUnrelatedSiblings,
                ..
            }
        )));
    }

    // --- AC7: cost/latency remains bounded for realistic multi-agent
    // graphs; graph-abuse cases are tested ---------------------------------

    #[test]
    fn a_large_adversarial_graph_of_shared_and_unshared_agents_does_not_hang_or_panic() {
        // Graph-abuse case: 300 agents, most sharing one of a handful of
        // root events (an attacker fanning out many "confirmations" from
        // few real sources), a few genuinely independent. This module never
        // re-derives SourceFamilyMap from raw evidence -- it only reads
        // each envelope's own already-computed aggregate_source_family_bases
        // (module docs) -- so this stays fast regardless of the underlying
        // evidence pool shape.
        let shared_events: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();
        let claims: Vec<Claim> = (0..300)
            .map(|i| {
                claim(
                    &format!("session-{i}"),
                    shared_events[i % shared_events.len()],
                )
            })
            .collect();
        let all_evidence: Vec<Evidence> = (0..300)
            .map(|i| {
                evidence_on_event(
                    &format!("session-{i}"),
                    shared_events[i % shared_events.len()],
                    TrustClass::AgentAdjacent,
                )
            })
            .collect();
        let families = SourceFamilyMap::build(&all_evidence);
        let mut envelopes = Vec::new();
        for i in 0..300 {
            let receipt = issue_one_receipt(
                &claims[i],
                std::slice::from_ref(&all_evidence[i]),
                &families,
            );
            envelopes.push(envelope_for(
                &format!("agent-{i}"),
                &claims[i],
                vec![receipt],
                vec![],
            ));
        }
        let report = analyze_dependency(&envelopes, MultiAgentPolicy::default());
        assert_eq!(report.total_agents, 300);
        assert_eq!(
            report.effective_independent_sources,
            shared_events.len(),
            "300 agents fanned out from 5 real root events must collapse to 5 effective sources"
        );
    }
}
