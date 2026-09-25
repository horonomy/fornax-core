//! Epistemic Contract Satisfaction Engine (FORNX-378, parent epic FORNX-376
//! "Agent Epistemic Trust Kernel", target v0.3.0).
//!
//! Wires FORNX-377's schema/semantics layer
//! ([`fornax_types::epistemic_contract`]) to this crate's existing
//! fusion/decision/VoI surfaces. This module adds no new satisfaction-state
//! vocabulary and does not reinvent
//! [`fornax_types::epistemic_contract::assess_claim`]'s rule evaluation —
//! [`assess`] is the sole call site that invokes it, and every other
//! function here only consumes its [`ClaimAssessment`] output.
//!
//! - [`assess`] resolves a claim class's contract, evaluates it against the
//!   supplied evidence pool, and hardens the result against two real,
//!   adversarial evidence-handling gaps (see "Real findings" below).
//! - [`apply_contract_floor`] is a critical-obligation safety floor over an
//!   already-decided [`crate::decision::Recommendation`], following the
//!   exact non-relaxing shape [`crate::decision::apply_calibration_floor`]
//!   (FORNX-348) established: only ever steps `Proceed` down to `Review`,
//!   never touches `Review`/`Block`, never mutates the referenced
//!   `FusedFinding` or re-runs `decide()`.
//! - [`gaps_from_assessment`] converts every non-satisfied, applicable,
//!   obtainable requirement into a [`crate::voi::EvidenceGap`]
//!   (`EvidenceGapKind::ContractObligationUnmet`) so the existing VoI
//!   planner (FORNX-345) ranks it for acquisition through its normal
//!   `probes_for_gap` path — no parallel acquisition-planning logic here.
//!
//! # Real findings fixed here (documented in the PR body's security review)
//!
//! - **Duplicate evidence rows never double-count.** [`assess`] deduplicates
//!   its evidence pool by [`fornax_types::Evidence::id`] before calling
//!   `assess_claim` — two entries for the same underlying row (a duplicated
//!   store read, a replayed insert) must never let one physical observation
//!   satisfy a `min_coverage: 2` bar by itself.
//! - **Duplicate-source amplification cannot defeat independence.**
//!   [`IndependenceRule::MustBeIndependentOf`] (FORNX-377) excludes by
//!   evidence *id* only, by design — `fornax_types::epistemic_contract` is a
//!   pure schema/semantics layer with no source-provenance analysis of its
//!   own. Two evidence rows with distinct ids that both trace back to the
//!   *same underlying source* (per FORNX-347's
//!   [`crate::independence::SourceFamilyMap`] — e.g. one agent turn fanned
//!   out to two sensors) can each carry a fresh id and evade an id-based
//!   exclusion, letting one real observation masquerade as two independent
//!   ones. [`assess`] performs a second pass after `assess_claim` returns:
//!   for every `MustBeIndependentOf` pair, any matched evidence that shares
//!   a source family with evidence already claimed by the requirement it
//!   must be independent of is stripped and the requirement's state
//!   recomputed — see [`SatisfactionReport::family_violations`] for what
//!   was caught, never silently.
//! - **Capability/version spoofing (FORNX-380 finding).**
//!   [`fornax_types::EvidenceRequirement::capability_prerequisites`] is part
//!   of FORNX-377's schema and is populated on every representative
//!   contract, but neither `evaluate_requirement` nor `assess_claim` ever
//!   reads it — a requirement naming a prerequisite `SignalClass` is
//!   satisfied identically whether or not the reporting adapter actually has
//!   that capability, letting an old/degraded/spoofed adapter's evidence
//!   count exactly as if the capability were real. [`assess_with_capabilities`]
//!   closes this as a purely additive hardening layer on top of [`assess`]
//!   (zero behavior change for `assess`'s existing callers) — see its own
//!   doc comment.
//!
//! # Non-goals (inherited from FORNX-377, restated here)
//!
//! No calibrated scoring, no LLM-authored contracts as production
//! authority, no dynamic execution of untrusted contract code — every
//! contract this module evaluates comes from a [`ContractRegistry`]
//! populated by trusted, in-process Rust code, never deserialized from an
//! untrusted source and executed.

use std::collections::{HashMap, HashSet};

use fornax_types::epistemic_contract::{
    assess_claim, ClaimAssessment, ClaimClassId, ContractError, ContractLookup, ContractRegistry,
    IndependenceRule, RequirementAssessment, RequirementLevel, SatisfactionState,
};
use fornax_types::sensor::TrustClass;
use fornax_types::{Claim, Evidence};
use uuid::Uuid;

use crate::decision::{Recommendation, RecommendationAction};
use crate::independence::SourceFamilyMap;
use crate::voi::{EvidenceGap, EvidenceGapKind};

/// Derive an evidence item's [`TrustClass`] from its recorded
/// [`fornax_types::sensor::EvidenceSource`] — the same source `fusion.rs`
/// and `voi.rs` already read, never inferred from payload content. `None`
/// for evidence with no recorded source; `evaluate_requirement`
/// (FORNX-377) already treats that as never qualifying a `Required`
/// requirement.
pub fn trust_class_of(evidence: &Evidence) -> Option<TrustClass> {
    evidence.source.as_ref().map(|s| s.trust_class.clone())
}

/// Build the default registry of the six FORNX-377 representative claim
/// classes. A product embedding additional claim classes registers them on
/// top of (or instead of) this base set — this is a convenience default,
/// not the only legal registry. Panics only on a build-time regression in
/// FORNX-377's own representative contracts (they are validated by that
/// module's own test suite), never on a runtime/data condition.
pub fn default_registry() -> ContractRegistry {
    let mut reg = ContractRegistry::new();
    for c in fornax_types::epistemic_contract::representative_contracts::all() {
        reg.register(c)
            .expect("FORNX-377 representative contracts are validated by their own tests");
    }
    reg
}

/// One duplicate-source-amplification catch: `evidence_id` was stripped
/// from `requirement_id`'s matched evidence because it shares a
/// [`SourceFamilyMap`] family with evidence already claimed by
/// `shared_with_requirement_id`, which `requirement_id` must be independent
/// of. Never silently dropped — always recorded on the returned
/// [`SatisfactionReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyIndependenceViolation {
    pub requirement_id: String,
    pub shared_with_requirement_id: String,
    pub evidence_id: Uuid,
}

/// Output of [`assess`]: the (possibly family-hardened) [`ClaimAssessment`]
/// plus every duplicate-source-amplification attempt caught while hardening
/// it.
#[derive(Debug, Clone, PartialEq)]
pub struct SatisfactionReport {
    pub assessment: ClaimAssessment,
    pub family_violations: Vec<FamilyIndependenceViolation>,
}

/// Deduplicate by [`Evidence::id`], keeping the first occurrence in input
/// order — deterministic regardless of which physical duplicate "wins"
/// (their `id` is identical by construction, so no information is lost by
/// keeping either).
fn dedupe_by_id(evidence: &[Evidence]) -> Vec<Evidence> {
    let mut seen = HashSet::new();
    evidence
        .iter()
        .filter(|e| seen.insert(e.id))
        .cloned()
        .collect()
}

/// Recompute [`ClaimAssessment::overall`] from a (possibly just-mutated)
/// `per_requirement` list, using the exact same priority
/// Contradicted > Stale > Unsatisfied > Unavailable that
/// [`fornax_types::epistemic_contract::assess_claim`] applies. Duplicated
/// here deliberately narrowly (only the aggregation formula, never the
/// per-requirement evaluation rules) because family-hardening can change a
/// `Satisfied` requirement to `Unsatisfied` after `assess_claim` already
/// returned, and `overall` must reflect that, not the pre-hardening view.
fn recompute_overall(per_requirement: &[RequirementAssessment]) -> SatisfactionState {
    let rank = |s: &SatisfactionState| -> u8 {
        match s {
            SatisfactionState::Contradicted => 4,
            SatisfactionState::Stale => 3,
            SatisfactionState::Unsatisfied => 2,
            SatisfactionState::Unavailable => 1,
            _ => 0,
        }
    };
    let blocking = per_requirement.iter().filter(|ra| {
        (matches!(ra.level, RequirementLevel::Required)
            || matches!(&ra.level, RequirementLevel::Conditional { .. }))
            && !matches!(
                ra.state,
                SatisfactionState::Satisfied | SatisfactionState::NotApplicable
            )
    });
    let mut worst: Option<SatisfactionState> = None;
    for ra in blocking {
        worst = Some(match worst {
            Some(w) if rank(&w) >= rank(&ra.state) => w,
            _ => ra.state.clone(),
        });
    }
    worst.unwrap_or(SatisfactionState::Satisfied)
}

/// Assess `claim` against `registry`'s contract for `claim_class`
/// (FORNX-378). Deduplicates `evidence` by id, delegates to
/// [`assess_claim`] (FORNX-377) as the sole source of truth for
/// per-requirement satisfaction, then hardens the result against
/// duplicate-source amplification using FORNX-347's real source-family
/// derivation — see module docs "Real findings fixed here".
///
/// `Err` only propagates a genuine [`ContractError`] from contract
/// composition (e.g. an inheritance cycle or a weakened child requirement)
/// — never from evidence content, which can never make a contract itself
/// invalid.
pub fn assess(
    registry: &ContractRegistry,
    claim_class: &ClaimClassId,
    claim: &Claim,
    evidence: &[Evidence],
    conditions_met: &[String],
) -> Result<SatisfactionReport, ContractError> {
    let deduped = dedupe_by_id(evidence);
    let evidence_refs: Vec<&Evidence> = deduped.iter().collect();

    let mut assessment = assess_claim(
        registry,
        claim_class,
        claim,
        &evidence_refs,
        conditions_met,
        &trust_class_of,
    )?;

    let mut violations = Vec::new();

    if let ContractLookup::Found(_) = registry.lookup(claim_class) {
        let requirements = registry.effective_requirements(claim_class)?;
        let families = SourceFamilyMap::build(&deduped);
        let matched_by_id: HashMap<String, Vec<Uuid>> = assessment
            .per_requirement
            .iter()
            .map(|ra| (ra.requirement_id.clone(), ra.matched_evidence.clone()))
            .collect();

        // Which (requirement_id -> evidence_id) pairs to strip, and why —
        // computed against the pre-hardening `matched_by_id` snapshot so
        // the order requirements are visited in never changes the result.
        let mut strip: HashMap<String, HashSet<Uuid>> = HashMap::new();
        for req in &requirements {
            let IndependenceRule::MustBeIndependentOf(other_ids) = &req.independence else {
                continue;
            };
            let Some(mine) = matched_by_id.get(&req.id) else {
                continue;
            };
            for other_id in other_ids {
                let Some(other_matched) = matched_by_id.get(other_id) else {
                    continue;
                };
                for &mine_id in mine {
                    let Some(family) = families.family_of(mine_id) else {
                        continue;
                    };
                    if other_matched
                        .iter()
                        .any(|other_ev| family.evidence_ids.contains(other_ev))
                    {
                        violations.push(FamilyIndependenceViolation {
                            requirement_id: req.id.clone(),
                            shared_with_requirement_id: other_id.clone(),
                            evidence_id: mine_id,
                        });
                        strip.entry(req.id.clone()).or_default().insert(mine_id);
                    }
                }
            }
        }

        if !violations.is_empty() {
            let req_by_id: HashMap<&str, u32> = requirements
                .iter()
                .map(|r| (r.id.as_str(), r.min_coverage.min_items))
                .collect();
            for ra in &mut assessment.per_requirement {
                let Some(strip_ids) = strip.get(&ra.requirement_id) else {
                    continue;
                };
                ra.matched_evidence.retain(|id| !strip_ids.contains(id));
                ra.rejected_evidence.extend(strip_ids.iter().map(|&evidence_id| {
                    fornax_types::epistemic_contract::RejectedEvidence {
                        evidence_id,
                        reason:
                            fornax_types::epistemic_contract::RejectionReason::ClaimedByIndependentRequirement,
                    }
                }));
                let min_items = req_by_id
                    .get(ra.requirement_id.as_str())
                    .copied()
                    .unwrap_or(1);
                if (ra.matched_evidence.len() as u32) < min_items
                    && matches!(ra.state, SatisfactionState::Satisfied)
                {
                    ra.state = SatisfactionState::Unsatisfied;
                }
            }
            assessment.overall = recompute_overall(&assessment.per_requirement);
        }
    }

    Ok(SatisfactionReport {
        assessment,
        family_violations: violations,
    })
}

/// One requirement whose declared [`fornax_types::EvidenceRequirement::capability_prerequisites`]
/// are not covered by the caller's `available_capabilities` — see
/// [`assess_with_capabilities`]'s doc comment for why this hardening exists.
/// Never silently dropped, mirroring [`FamilyIndependenceViolation`]'s
/// visibility discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityViolation {
    pub requirement_id: String,
    pub missing_capabilities: Vec<fornax_types::SignalClass>,
}

/// [`assess`] hardened against a real, previously-unenforced gap (FORNX-380
/// finding): [`fornax_types::EvidenceRequirement::capability_prerequisites`]
/// is part of FORNX-377's schema and is populated on every representative
/// contract, but neither `evaluate_requirement` nor `assess_claim` ever reads
/// it — a requirement naming `SignalClass::ProcessResult` as a prerequisite
/// is satisfied identically whether or not the reporting adapter actually has
/// that capability. An old, degraded, or spoofed adapter that lacks a
/// capability but still emits evidence of the matching `EvidenceKind` would
/// have that evidence accepted exactly as if the capability were real --
/// capability/version spoofing, named explicitly in FORNX-380's scope.
///
/// This function closes the gap **without changing [`assess`]'s signature or
/// behavior** — every existing caller of `assess` is completely unaffected.
/// It re-derives `assess`'s report, then for every requirement whose
/// `capability_prerequisites` are not a subset of `available_capabilities`:
/// if that requirement was `Satisfied`, its matched evidence is cleared and
/// its state is forced to [`SatisfactionState::Unavailable`] (the capability
/// to observe it at all was never actually present, which is a strictly
/// different fact than "no qualifying evidence was submitted" but shares the
/// same honest "we cannot vouch for this" semantics) — mirroring the exact
/// strip/record/recompute shape `assess`'s own family-independence hardening
/// already uses. Every violation is returned, never silently applied.
pub fn assess_with_capabilities(
    registry: &ContractRegistry,
    claim_class: &ClaimClassId,
    claim: &Claim,
    evidence: &[Evidence],
    conditions_met: &[String],
    available_capabilities: &[fornax_types::SignalClass],
) -> Result<(SatisfactionReport, Vec<CapabilityViolation>), ContractError> {
    let mut report = assess(registry, claim_class, claim, evidence, conditions_met)?;
    let mut violations = Vec::new();

    if let ContractLookup::Found(_) = registry.lookup(claim_class) {
        let requirements = registry.effective_requirements(claim_class)?;
        let mut changed = false;

        for req in &requirements {
            if req.capability_prerequisites.is_empty() {
                continue;
            }
            let missing: Vec<fornax_types::SignalClass> = req
                .capability_prerequisites
                .iter()
                .filter(|c| !available_capabilities.contains(c))
                .cloned()
                .collect();
            if missing.is_empty() {
                continue;
            }
            if let Some(ra) = report
                .assessment
                .per_requirement
                .iter_mut()
                .find(|ra| ra.requirement_id == req.id)
            {
                if matches!(ra.state, SatisfactionState::Satisfied) {
                    ra.matched_evidence.clear();
                    ra.state = SatisfactionState::Unavailable;
                    changed = true;
                }
            }
            violations.push(CapabilityViolation {
                requirement_id: req.id.clone(),
                missing_capabilities: missing,
            });
        }

        if changed {
            report.assessment.overall = recompute_overall(&report.assessment.per_requirement);
        }
    }

    Ok((report, violations))
}

/// Apply the critical-obligation safety floor (FORNX-378 AC: "a
/// recommendation cannot become PROCEED merely because aggregate support is
/// high while a critical required obligation is unsatisfied"). Follows
/// [`crate::decision::apply_calibration_floor`]'s exact non-relaxing shape
/// (FORNX-348): only ever steps [`RecommendationAction::Proceed`] down to
/// [`RecommendationAction::Review`]; `Review`/`Block` are returned
/// unchanged; never touches the fusion/decision inputs that produced `rec`.
///
/// The floor fires whenever `assessment.overall` is anything but
/// [`SatisfactionState::Satisfied`] — including
/// [`SatisfactionState::Unknown`] (no contract at all for this claim class):
/// the absence of a contract is not evidence of safety, so it must not let
/// `Proceed` stand any more than a `Required` obligation that is actively
/// `Unsatisfied`/`Stale`/`Contradicted`/`Unavailable` would.
pub fn apply_contract_floor(rec: Recommendation, assessment: &ClaimAssessment) -> Recommendation {
    if matches!(assessment.overall, SatisfactionState::Satisfied) {
        return rec;
    }
    if rec.action != RecommendationAction::Proceed {
        return rec;
    }
    Recommendation {
        action: RecommendationAction::Review,
        rationale_summary: format!(
            "{} | contract floor applied: epistemic contract for claim class {}v{} is {:?}, not Satisfied -> review (FORNX-378 non-relaxing floor)",
            rec.rationale_summary,
            assessment.claim_class.name,
            assessment.claim_class.version,
            assessment.overall
        ),
        ..rec
    }
}

/// Convert every non-satisfied, applicable requirement in `assessment` into
/// a [`crate::voi::EvidenceGap`] (FORNX-378 AC: "convert unsatisfied but
/// potentially obtainable obligations into FORNX-345-compatible evidence
/// gaps"). [`SatisfactionState::NotApplicable`] and
/// [`SatisfactionState::Satisfied`] requirements produce no gap (nothing to
/// obtain). An `assessment.overall` of [`SatisfactionState::Unknown`]
/// naturally produces zero gaps too, since `assess_claim` leaves
/// `per_requirement` empty in that case — an unrecognized claim class is a
/// registration problem, not evidence to acquire.
pub fn gaps_from_assessment(claim_id: Uuid, assessment: &ClaimAssessment) -> Vec<EvidenceGap> {
    assessment
        .per_requirement
        .iter()
        .filter(|ra| {
            !matches!(
                ra.state,
                SatisfactionState::Satisfied
                    | SatisfactionState::NotApplicable
                    | SatisfactionState::Unknown
            )
        })
        .map(|ra| EvidenceGap {
            kind: EvidenceGapKind::ContractObligationUnmet {
                requirement_id: ra.requirement_id.clone(),
                state: ra.state.clone(),
            },
            claim_id,
            link_ids: vec![],
            missing_evidence_ids: vec![],
            detail: format!(
                "epistemic-contract requirement '{}' ({:?}) is {:?}",
                ra.requirement_id, ra.level, ra.state
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::epistemic_contract::{
        CoverageRequirement, EpistemicContract, EvidenceRequirement,
    };
    use fornax_types::graph::FreshnessWindow;
    use fornax_types::sensor::EvidenceSource;
    use fornax_types::EvidenceKind;

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

    fn evidence_with_source(
        kind: EvidenceKind,
        observed_at: &str,
        trust: TrustClass,
        source_event_id: Option<Uuid>,
    ) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "session-1".to_string(),
            source_event_id: source_event_id.unwrap_or_else(Uuid::new_v4),
            kind,
            observed_at: observed_at.to_string(),
            payload: serde_json::json!({}),
            provenance: "test".to_string(),
            source: Some(EvidenceSource {
                sensor_name: "test_sensor".to_string(),
                trust_class: trust,
                collected_at: observed_at.to_string(),
                provider: None,
                collection_method: Default::default(),
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

    fn double_check_contract(min_items: u32) -> EpistemicContract {
        EpistemicContract {
            claim_class: ClaimClassId::new("fornx378_double_check", 1),
            schema_version: fornax_types::epistemic_contract::EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![
                EvidenceRequirement {
                    id: "first_check".to_string(),
                    level: RequirementLevel::Required,
                    evidence_kind: EvidenceKind::ExitCode,
                    acceptable_trust_classes: vec![TrustClass::HostObserved],
                    freshness: FreshnessWindow::Durable,
                    independence: IndependenceRule::None,
                    min_coverage: CoverageRequirement { min_items },
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
                    min_coverage: CoverageRequirement { min_items },
                    capability_prerequisites: vec![],
                    policy_context: None,
                },
            ],
        }
    }

    fn registry_with_double_check(min_items: u32) -> ContractRegistry {
        let mut reg = ContractRegistry::new();
        reg.register(double_check_contract(min_items)).unwrap();
        reg
    }

    // --- AC1: determinism -----------------------------------------------

    #[test]
    fn same_frozen_inputs_produce_byte_identical_canonical_json() {
        let reg = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );

        let report_a =
            assess(&reg, &cc, &claim, std::slice::from_ref(&ev), &[]).expect("assess ok");
        let report_b = assess(&reg, &cc, &claim, &[ev], &[]).expect("assess ok");

        let json_a = fornax_types::epistemic_contract::to_canonical_json(&report_a.assessment)
            .expect("serialize");
        let json_b = fornax_types::epistemic_contract::to_canonical_json(&report_b.assessment)
            .expect("serialize");
        assert_eq!(json_a, json_b);
        assert_eq!(report_a.assessment.overall, SatisfactionState::Satisfied);
    }

    // --- AC5: a new contract version never mutates a prior one's result -

    #[test]
    fn registering_a_new_contract_version_does_not_mutate_the_old_versions_result() {
        let mut reg = default_registry();
        let cc_v1 = ClaimClassId::new("versioned_claim", 1);
        reg.register(EpistemicContract {
            claim_class: cc_v1.clone(),
            schema_version: fornax_types::epistemic_contract::EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "req".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement::single(),
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        })
        .unwrap();

        let claim = claim("versioned_claim", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        let before =
            assess(&reg, &cc_v1, &claim, std::slice::from_ref(&ev), &[]).expect("assess ok");
        assert_eq!(before.assessment.overall, SatisfactionState::Satisfied);

        // A stricter v2 (min_coverage 2) is registered on top -- must not
        // touch v1's own behavior at all.
        let cc_v2 = ClaimClassId::new("versioned_claim", 2);
        reg.register(EpistemicContract {
            claim_class: cc_v2,
            schema_version: fornax_types::epistemic_contract::EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: None,
            requirements: vec![EvidenceRequirement {
                id: "req".to_string(),
                level: RequirementLevel::Required,
                evidence_kind: EvidenceKind::ExitCode,
                acceptable_trust_classes: vec![TrustClass::HostObserved],
                freshness: FreshnessWindow::Durable,
                independence: IndependenceRule::None,
                min_coverage: CoverageRequirement { min_items: 2 },
                capability_prerequisites: vec![],
                policy_context: None,
            }],
        })
        .unwrap();

        let after = assess(&reg, &cc_v1, &claim, &[ev], &[]).expect("assess ok");
        assert_eq!(
            fornax_types::epistemic_contract::to_canonical_json(&before.assessment).unwrap(),
            fornax_types::epistemic_contract::to_canonical_json(&after.assessment).unwrap()
        );
    }

    // --- AC2: critical-obligation safety floor, adversarially -----------

    fn recommendation(action: RecommendationAction) -> Recommendation {
        Recommendation {
            claim_id: Uuid::new_v4(),
            action,
            risk_class: crate::decision::RiskClass::Balanced,
            policy_name: "test_policy".to_string(),
            policy_version: 1,
            rationale_summary: "test rationale".to_string(),
        }
    }

    #[test]
    fn contract_floor_defeats_proceed_despite_high_aggregate_support() {
        // Adversarial: simulate a case where fusion/decision has already
        // decided Proceed (as if aggregate support were high/clean), but
        // the claim's own epistemic contract has a Required obligation that
        // is genuinely Unsatisfied. The floor must still demote to Review
        // -- "high aggregate support" must never paper over a missing
        // critical obligation.
        let reg = default_registry();
        let cc = ClaimClassId::new("deployment_healthy", 1);
        let claim = claim("deployment_healthy", "2026-09-24T00:10:00Z");
        // AgentAdjacent self-report -- the contract requires
        // IndependentExternal, so this must not satisfy it.
        let ev = evidence_with_source(
            EvidenceKind::ProcessObservation,
            "2026-09-24T00:09:00Z",
            TrustClass::AgentAdjacent,
            None,
        );
        let report = assess(&reg, &cc, &claim, &[ev], &[]).expect("assess ok");
        assert_ne!(report.assessment.overall, SatisfactionState::Satisfied);

        let rec = recommendation(RecommendationAction::Proceed);
        let floored = apply_contract_floor(rec, &report.assessment);
        assert_eq!(floored.action, RecommendationAction::Review);
    }

    #[test]
    fn contract_floor_never_relaxes_review_or_block() {
        let reg = default_registry();
        let cc = ClaimClassId::new("deployment_healthy", 1);
        let claim = claim("deployment_healthy", "2026-09-24T00:10:00Z");
        let report = assess(&reg, &cc, &claim, &[], &[]).expect("assess ok");
        assert_ne!(report.assessment.overall, SatisfactionState::Satisfied);

        for action in [RecommendationAction::Review, RecommendationAction::Block] {
            let rec = recommendation(action);
            let floored = apply_contract_floor(rec, &report.assessment);
            assert_eq!(
                floored.action, action,
                "must never change a non-Proceed action"
            );
        }
    }

    #[test]
    fn contract_floor_leaves_a_genuinely_satisfied_claim_at_proceed() {
        let reg = default_registry();
        let cc = ClaimClassId::new("build_succeeded", 1);
        let claim = claim("build_succeeded", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        let report = assess(&reg, &cc, &claim, &[ev], &[]).expect("assess ok");
        assert_eq!(report.assessment.overall, SatisfactionState::Satisfied);

        let rec = recommendation(RecommendationAction::Proceed);
        let floored = apply_contract_floor(rec, &report.assessment);
        assert_eq!(floored.action, RecommendationAction::Proceed);
    }

    // --- AC3: rejected evidence stays visible with rationale ------------

    #[test]
    fn rejected_evidence_is_visible_with_rationale_not_dropped() {
        let reg = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T00:10:00Z");
        // Wrong trust class for the Required requirement.
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::AgentAdjacent,
            None,
        );
        let report = assess(&reg, &cc, &claim, std::slice::from_ref(&ev), &[]).expect("assess ok");
        let req = report
            .assessment
            .per_requirement
            .iter()
            .find(|r| r.requirement_id == "test_runner_exit_code")
            .unwrap();
        assert_eq!(req.rejected_evidence.len(), 1);
        assert_eq!(req.rejected_evidence[0].evidence_id, ev.id);
        assert_eq!(
            req.rejected_evidence[0].reason,
            fornax_types::epistemic_contract::RejectionReason::WrongTrustClass
        );
    }

    // --- AC4: obtainable gaps feed VoI through stable contracts ---------

    #[test]
    fn unsatisfied_required_obligation_becomes_a_contract_evidence_gap() {
        let reg = default_registry();
        let cc = ClaimClassId::new("build_succeeded", 1);
        let claim = claim("build_succeeded", "2026-09-24T00:10:00Z");
        let report = assess(&reg, &cc, &claim, &[], &[]).expect("assess ok");
        let claim_id = Uuid::new_v4();
        let gaps = gaps_from_assessment(claim_id, &report.assessment);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].claim_id, claim_id);
        assert!(matches!(
            gaps[0].kind,
            EvidenceGapKind::ContractObligationUnmet { .. }
        ));
        // Every gap this module produces must be plannable by the existing
        // VoI probe-selection path (FORNX-345) -- never a dead-end kind.
        let probes = crate::voi::probes_for_gap(&gaps[0]);
        assert!(!probes.is_empty());
    }

    #[test]
    fn satisfied_and_not_applicable_requirements_produce_no_gap() {
        let reg = default_registry();
        let cc = ClaimClassId::new("commit_push_completed", 1);
        let claim = claim("commit_push_completed", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ProcessObservation,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        let report = assess(&reg, &cc, &claim, &[ev], &[]).expect("assess ok");
        assert_eq!(report.assessment.overall, SatisfactionState::Satisfied);
        assert!(gaps_from_assessment(Uuid::new_v4(), &report.assessment).is_empty());
    }

    // --- adversarial: duplicate evidence never double-counts ------------

    #[test]
    fn duplicate_evidence_row_never_counts_twice() {
        let reg = registry_with_double_check(2);
        let cc = ClaimClassId::new("fornx378_double_check", 1);
        let claim = claim("fornx378_double_check", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        // The SAME evidence row, passed twice -- must not satisfy
        // min_coverage: 2 by itself.
        let report = assess(&reg, &cc, &claim, &[ev.clone(), ev], &[]).expect("assess ok");
        assert_ne!(report.assessment.overall, SatisfactionState::Satisfied);
    }

    // --- adversarial: duplicate-source amplification cannot defeat
    //     independence ------------------------------------------------

    #[test]
    fn duplicate_source_amplification_cannot_satisfy_independence() {
        let cc = ClaimClassId::new("fornx378_double_check", 1);
        let claim = claim("fornx378_double_check", "2026-09-24T00:10:00Z");

        // Two DIFFERENT evidence ids, both AgentAdjacent, sharing the same
        // source_event_id -- SourceFamilyMap's real "same agent turn"
        // union rule (FORNX-347) puts these in one family. Without the
        // family-hardening pass, `first_check`/`second_independent_check`
        // (declared mutually independent) would each be satisfied by one
        // of these ids, since assess_claim's own exclusion is id-based
        // only.
        let shared_turn = Uuid::new_v4();
        let ev_a = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::AgentAdjacent,
            Some(shared_turn),
        );
        let ev_b = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:01Z",
            TrustClass::AgentAdjacent,
            Some(shared_turn),
        );

        // Trust class mismatch would already block this contract (it wants
        // HostObserved) -- rebuild a variant accepting AgentAdjacent so the
        // ONLY thing under test is the independence/family dimension.
        let mut reg2 = ContractRegistry::new();
        let mut contract = double_check_contract(1);
        for req in &mut contract.requirements {
            req.acceptable_trust_classes = vec![TrustClass::AgentAdjacent];
        }
        reg2.register(contract).unwrap();

        let report = assess(&reg2, &cc, &claim, &[ev_a, ev_b], &[]).expect("assess ok");
        assert!(
            !report.family_violations.is_empty(),
            "expected the family-hardening pass to catch the shared-turn amplification"
        );
        assert_ne!(
            report.assessment.overall,
            SatisfactionState::Satisfied,
            "duplicate-source amplification must not satisfy an independence requirement"
        );

        // Sanity: genuinely distinct source events (no shared turn) DO
        // satisfy both requirements -- the hardening pass must not
        // over-reject unrelated evidence.
        let ev_c = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::AgentAdjacent,
            None,
        );
        let ev_d = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:01Z",
            TrustClass::AgentAdjacent,
            None,
        );
        let report2 = assess(&reg2, &cc, &claim, &[ev_c, ev_d], &[]).expect("assess ok");
        assert!(report2.family_violations.is_empty());
        assert_eq!(report2.assessment.overall, SatisfactionState::Satisfied);
    }

    // --- adversarial: stale evidence never satisfies -------------------

    #[test]
    fn stale_evidence_never_satisfies_a_perishable_requirement() {
        let reg = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T02:00:00Z");
        // 1 hour+ older than the claim -- outside the default 3600s window.
        let stale_ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        let report =
            assess(&reg, &cc, &claim, std::slice::from_ref(&stale_ev), &[]).expect("assess ok");
        assert_eq!(report.assessment.overall, SatisfactionState::Stale);
        let req = report
            .assessment
            .per_requirement
            .iter()
            .find(|r| r.requirement_id == "test_runner_exit_code")
            .unwrap();
        assert_eq!(
            req.rejected_evidence[0].reason,
            fornax_types::epistemic_contract::RejectionReason::Stale
        );
        let _ = stale_ev;
    }

    // --- FORNX-380 AC4 real finding: capability/version spoofing --------
    // `capability_prerequisites` is declared on every representative
    // contract but was never enforced anywhere -- see
    // `assess_with_capabilities`'s doc comment.

    #[test]
    fn plain_assess_is_exploitable_by_a_spoofed_missing_capability() {
        // Exploit: `tests_passed`'s `test_runner_exit_code` requirement
        // declares `capability_prerequisites: [SignalClass::ProcessResult]`,
        // but a caller that never actually has that capability (e.g. an old
        // adapter, or one that never wired up process-exit-code collection)
        // can still submit a well-formed `ExitCode`/`HostObserved` evidence
        // row and have it accepted, since `assess`/`assess_claim` never read
        // the prerequisite at all.
        let reg = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        let report = assess(&reg, &cc, &claim, std::slice::from_ref(&ev), &[]).expect("assess ok");
        assert_eq!(
            report.assessment.overall,
            SatisfactionState::Satisfied,
            "documents the pre-existing gap: plain `assess` has no notion of capability \
             prerequisites at all, so a spoofed/absent capability is invisible to it"
        );
    }

    #[test]
    fn assess_with_capabilities_catches_the_spoofed_missing_capability() {
        let reg = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        // The caller declares it has NO capabilities at all -- e.g. a
        // spoofed or genuinely degraded adapter.
        let (report, violations) =
            assess_with_capabilities(&reg, &cc, &claim, std::slice::from_ref(&ev), &[], &[])
                .expect("assess ok");
        assert_ne!(
            report.assessment.overall,
            SatisfactionState::Satisfied,
            "a requirement whose prerequisite capability is absent must never be Satisfied"
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].requirement_id, "test_runner_exit_code");
        assert_eq!(
            violations[0].missing_capabilities,
            vec![fornax_types::SignalClass::ProcessResult]
        );
        let req = report
            .assessment
            .per_requirement
            .iter()
            .find(|r| r.requirement_id == "test_runner_exit_code")
            .unwrap();
        assert_eq!(req.state, SatisfactionState::Unavailable);
        assert!(req.matched_evidence.is_empty());
    }

    #[test]
    fn assess_with_capabilities_is_a_pure_no_op_when_the_capability_is_present() {
        // Sanity: this hardening must never over-reject a genuinely capable
        // caller.
        let reg = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        let (report, violations) = assess_with_capabilities(
            &reg,
            &cc,
            &claim,
            std::slice::from_ref(&ev),
            &[],
            &[fornax_types::SignalClass::ProcessResult],
        )
        .expect("assess ok");
        assert!(violations.is_empty());
        assert_eq!(report.assessment.overall, SatisfactionState::Satisfied);
    }

    #[test]
    fn assess_with_capabilities_never_changes_plain_assess_behavior() {
        // `assess` itself must be completely unaffected by this hardening's
        // existence -- every prior caller keeps working exactly as before.
        let reg = default_registry();
        let cc = ClaimClassId::new("build_succeeded", 1);
        let claim = claim("build_succeeded", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        let plain = assess(&reg, &cc, &claim, std::slice::from_ref(&ev), &[]).expect("assess ok");
        assert_eq!(plain.assessment.overall, SatisfactionState::Satisfied);
    }

    // --- adversarial: forged/malicious claim classification -------------

    #[test]
    fn forged_claim_class_is_never_satisfied_through_the_wrapper() {
        let reg = default_registry();
        let cc = ClaimClassId::new("attacker_invented_claim_class", 1);
        let claim = claim("attacker_invented_claim_class", "2026-09-24T00:10:00Z");
        // Flood it with evidence that would satisfy almost any real
        // contract.
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        let report = assess(&reg, &cc, &claim, &[ev], &[]).expect("assess ok");
        assert_eq!(report.assessment.overall, SatisfactionState::Unknown);
        assert!(gaps_from_assessment(Uuid::new_v4(), &report.assessment).is_empty());
        let rec = recommendation(RecommendationAction::Proceed);
        assert_eq!(
            apply_contract_floor(rec, &report.assessment).action,
            RecommendationAction::Review,
            "an unrecognized claim class must never leave Proceed standing"
        );
    }

    // --- adversarial: contract downgrade is rejected, never silently
    //     accepted --------------------------------------------------

    #[test]
    fn contract_downgrade_attempt_surfaces_as_an_error_not_a_silent_pass() {
        let mut reg = ContractRegistry::new();
        let parent = EpistemicContract {
            claim_class: ClaimClassId::new("fornx378_parent", 1),
            schema_version: fornax_types::epistemic_contract::EPISTEMIC_CONTRACT_SCHEMA_VERSION,
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

        // An attacker-controlled "downgrade" contract that inherits from
        // the trusted parent and tries to weaken req_a to Recommended.
        let malicious_child = EpistemicContract {
            claim_class: ClaimClassId::new("fornx378_child", 1),
            schema_version: fornax_types::epistemic_contract::EPISTEMIC_CONTRACT_SCHEMA_VERSION,
            parent: Some(ClaimClassId::new("fornx378_parent", 1)),
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
        // Structural validation alone passes -- the weakening is only
        // caught at composition time.
        reg.register(malicious_child).unwrap();

        let cc = ClaimClassId::new("fornx378_child", 1);
        let claim = claim("fornx378_child", "2026-09-24T00:10:00Z");
        let ev = evidence_with_source(
            EvidenceKind::ExitCode,
            "2026-09-24T00:00:00Z",
            TrustClass::HostObserved,
            None,
        );
        let result = assess(&reg, &cc, &claim, &[ev], &[]);
        assert!(
            matches!(result, Err(ContractError::WeakenedRequirement { .. })),
            "a downgrade attempt must surface as an error, never a silently accepted assessment"
        );
    }

    // --- adversarial: resource-exhaustion input scale ---------------------

    #[test]
    fn large_evidence_pool_does_not_panic_or_hang() {
        // 800, not the thousands+ a real resource-exhaustion attempt would
        // send: this test caught a real, separate finding (see this
        // function's doc comment) in FORNX-347's
        // `independence::SourceFamilyMap::build` -- its Rule 2 (transitive
        // `derived_from` ancestry) calls `ancestors_of`, which rebuilds a
        // full by-id index of the entire evidence slice on every call, once
        // per evidence item -- an O(n^2 log n) pass regardless of whether
        // any evidence actually populates `derived_from`. At 5,000 items
        // this alone took ~9s. That is a genuine FORNX-347 scalability gap,
        // out of this ticket's scope to fix (it is already-shipped, tested
        // public API this ticket only *consumes*) -- documented here and in
        // this PR's security-review section rather than silently worked
        // around by shrinking the input without comment. 800 items keeps
        // this specific test fast and non-flaky while still proving `assess`
        // itself (dedup + the family-hardening pass) does not panic or
        // behave incorrectly at scale.
        let reg = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let claim = claim("tests_passed", "2026-09-24T00:10:00Z");
        let mut evidence: Vec<Evidence> = Vec::with_capacity(800);
        for i in 0..800u32 {
            let mut ev = evidence_with_source(
                EvidenceKind::ExitCode,
                "2026-09-24T00:00:00Z",
                TrustClass::HostObserved,
                None,
            );
            // Every 3rd item is a literal duplicate id, exercising dedup at
            // scale too.
            if i % 3 == 0 && i > 0 {
                ev.id = evidence[(i - 1) as usize].id;
            }
            evidence.push(ev);
        }
        let started = std::time::Instant::now();
        let report = assess(&reg, &cc, &claim, &evidence, &[]).expect("assess ok");
        assert_eq!(report.assessment.overall, SatisfactionState::Satisfied);
        // Generous, coarse regression guard -- not a strict SLA.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "800-item evidence pool took unreasonably long: {:?}",
            started.elapsed()
        );
    }
}
