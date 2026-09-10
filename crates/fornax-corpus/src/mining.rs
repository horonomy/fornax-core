//! Candidate mining strategies (FORNX-341 scope: "candidate mining
//! strategies for contradiction, uncertainty, sensor disagreement, human
//! override, unusual decision changes and known benign controls").
//!
//! A closed enum plus one pure function, not a trait/registry — every
//! strategy here is a pure predicate over the same input, and the enum
//! gives exhaustiveness plus a serializable name for the corpus manifest.
//! `fornax_verify::fusion::FusionRule` is the in-repo precedent for this
//! shape.
//!
//! **`HumanOverride` is deliberately not a variant.** There is no override
//! concept and no break-glass row anywhere in `fornax-store` today — adding
//! a variant that structurally cannot fire would misrepresent what this
//! mechanism actually detects. Documented here as a real gap, not shipped
//! as dead code.

use fornax_types::{Claim, Evidence, EvidenceGraph, Verdict};
use fornax_verify::fusion::{FusedFinding, UncertaintyBand};

/// One reason a claim was mined as a candidate integrity case. `Ord` so a
/// [`crate::CandidateCase::mined_by`] list can be sorted into a
/// deterministic, canonical order.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MiningStrategy {
    EvidenceContradiction,
    HighUncertainty,
    SensorDisagreement,
    VerdictChangedAcrossFindings,
    /// A known-good, unremarkable case with no contradiction/uncertainty —
    /// deliberately mined too, so a corpus is never only positive-case
    /// harvesting (FORNX-341 AC).
    BenignControl,
}

/// Everything [`evaluate`] needs to decide which strategies fire for one
/// claim. Deliberately store-agnostic (no `fornax-store` dependency in this
/// module) — a caller resolves these values from the real store once, then
/// this function is pure over them.
pub struct MiningInput<'a> {
    pub claim: &'a Claim,
    pub graph: &'a EvidenceGraph,
    pub evidence_pool: &'a [Evidence],
    pub fused: &'a FusedFinding,
    /// This claim's verdict across every finding row recorded for it,
    /// oldest first (a verifier rerun leaves the old row in place and
    /// inserts a new one — see `0001_init.sql`'s own note on this).
    pub prior_verdicts: &'a [Verdict],
}

/// Which [`MiningStrategy`] variants fire for `input`. Empty means "not a
/// candidate" — a caller should not mine a [`crate::CandidateCase`] for a
/// claim with no strategy firing at all.
pub fn evaluate(input: &MiningInput) -> Vec<MiningStrategy> {
    let mut fired = Vec::new();

    let conflict = input.graph.conflict();
    if conflict.is_some() {
        fired.push(MiningStrategy::EvidenceContradiction);
    }

    // `HighUncertainty` must be exactly the two bands that reflect real
    // fusion trouble, never "anything but Corroborated" — `Corroborated`'s
    // own doc says it is unreachable on real traffic today (no shipped
    // sensor stamps `correlation_group`), so every real vote currently
    // lands in `Qualified`. Treating "not Corroborated" as high uncertainty
    // would fire on effectively all real cases.
    if matches!(
        input.fused.uncertainty,
        UncertaintyBand::Undetermined | UncertaintyBand::Conflicted
    ) {
        fired.push(MiningStrategy::HighUncertainty);
    }

    if let Some(conflict) = &conflict {
        let mut sensors = std::collections::BTreeSet::new();
        for link in conflict.supports.iter().chain(conflict.contradicts.iter()) {
            if let Some(evidence) = input
                .evidence_pool
                .iter()
                .find(|e| e.id == link.evidence_id)
            {
                if let Some(source) = &evidence.source {
                    sensors.insert(source.sensor_name.clone());
                }
            }
        }
        if sensors.len() >= 2 {
            fired.push(MiningStrategy::SensorDisagreement);
        }
    }

    if input.prior_verdicts.len() >= 2 && !input.prior_verdicts.windows(2).all(|w| w[0] == w[1]) {
        fired.push(MiningStrategy::VerdictChangedAcrossFindings);
    }

    if input.fused.verdict == Verdict::Verified && conflict.is_none() && fired.is_empty() {
        fired.push(MiningStrategy::BenignControl);
    }

    fired
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{
        ClockSource, CollectionMethod, EvidenceLink, EvidenceRelation, EvidenceSource, TrustClass,
    };
    use uuid::Uuid;

    fn claim() -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn evidence_with_sensor(sensor_name: &str) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: fornax_types::EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({}),
            provenance: "test".into(),
            source: Some(EvidenceSource {
                sensor_name: sensor_name.into(),
                trust_class: TrustClass::AgentAdjacent,
                collected_at: "2026-01-01T00:00:00Z".into(),
                provider: None,
                collection_method: CollectionMethod::HookCallback,
                collector_version: None,
                freshness: fornax_types::Freshness {
                    clock_source: ClockSource::HostClock,
                    caveat: None,
                },
                tamper_boundary: Default::default(),
                correlation_group: None,
                derived_from: vec![],
            }),
            extension: None,
            evidence_purged: false,
        }
    }

    fn link(
        claim_id: uuid::Uuid,
        evidence_id: uuid::Uuid,
        relation: EvidenceRelation,
    ) -> EvidenceLink {
        EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id,
            evidence_id,
            relation,
            linked_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn fused(verdict: Verdict, uncertainty: UncertaintyBand, claim_id: uuid::Uuid) -> FusedFinding {
        FusedFinding {
            claim_id,
            verdict,
            uncertainty,
            rationale: vec![],
            counted_link_ids: vec![],
            discounted_link_ids: vec![],
            missing_evidence_ids: vec![],
            unresolved_conflict: false,
            policy_name: "test".into(),
            policy_version: 1,
            computed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn contradiction_and_sensor_disagreement_fire_together_for_a_real_conflict() {
        let c = claim();
        let e1 = evidence_with_sensor("sensor_a");
        let e2 = evidence_with_sensor("sensor_b");
        let graph = EvidenceGraph {
            links: vec![
                link(c.id, e1.id, EvidenceRelation::Supports),
                link(c.id, e2.id, EvidenceRelation::Contradicts),
            ],
            missing: vec![],
        };
        let pool = vec![e1, e2];
        let f = fused(Verdict::Review, UncertaintyBand::Conflicted, c.id);
        let input = MiningInput {
            claim: &c,
            graph: &graph,
            evidence_pool: &pool,
            fused: &f,
            prior_verdicts: &[],
        };
        let strategies = evaluate(&input);
        assert!(strategies.contains(&MiningStrategy::EvidenceContradiction));
        assert!(strategies.contains(&MiningStrategy::SensorDisagreement));
        assert!(strategies.contains(&MiningStrategy::HighUncertainty));
        assert!(!strategies.contains(&MiningStrategy::BenignControl));
    }

    #[test]
    fn qualified_band_is_not_high_uncertainty() {
        // Qualified is where every real vote lands today (no sensor stamps
        // correlation_group) -- it must never be treated as high
        // uncertainty, or this would fire on ~all real traffic.
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(Verdict::Verified, UncertaintyBand::Qualified, c.id);
        let input = MiningInput {
            claim: &c,
            graph: &graph,
            evidence_pool: &[],
            fused: &f,
            prior_verdicts: &[],
        };
        assert!(!evaluate(&input).contains(&MiningStrategy::HighUncertainty));
    }

    #[test]
    fn verdict_changed_across_findings_fires_on_a_real_disagreement() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(Verdict::Verified, UncertaintyBand::Qualified, c.id);
        let prior = [Verdict::Contradicted, Verdict::Verified];
        let input = MiningInput {
            claim: &c,
            graph: &graph,
            evidence_pool: &[],
            fused: &f,
            prior_verdicts: &prior,
        };
        assert!(evaluate(&input).contains(&MiningStrategy::VerdictChangedAcrossFindings));
    }

    #[test]
    fn stable_repeated_verdicts_do_not_fire_verdict_changed() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(Verdict::Verified, UncertaintyBand::Qualified, c.id);
        let prior = [Verdict::Verified, Verdict::Verified];
        let input = MiningInput {
            claim: &c,
            graph: &graph,
            evidence_pool: &[],
            fused: &f,
            prior_verdicts: &prior,
        };
        assert!(!evaluate(&input).contains(&MiningStrategy::VerdictChangedAcrossFindings));
    }

    #[test]
    fn a_clean_verified_claim_with_no_conflict_is_mined_as_a_benign_control() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(Verdict::Verified, UncertaintyBand::Qualified, c.id);
        let input = MiningInput {
            claim: &c,
            graph: &graph,
            evidence_pool: &[],
            fused: &f,
            prior_verdicts: &[],
        };
        assert_eq!(evaluate(&input), vec![MiningStrategy::BenignControl]);
    }

    #[test]
    fn benign_control_is_exclusive_and_never_joins_a_real_finding() {
        let c = claim();
        let graph = EvidenceGraph::default();
        // Verified + Qualified but a verdict change did occur -- must not
        // also claim BenignControl.
        let f = fused(Verdict::Verified, UncertaintyBand::Qualified, c.id);
        let prior = [Verdict::Contradicted, Verdict::Verified];
        let input = MiningInput {
            claim: &c,
            graph: &graph,
            evidence_pool: &[],
            fused: &f,
            prior_verdicts: &prior,
        };
        let strategies = evaluate(&input);
        assert!(strategies.contains(&MiningStrategy::VerdictChangedAcrossFindings));
        assert!(!strategies.contains(&MiningStrategy::BenignControl));
    }

    #[test]
    fn no_strategy_fires_for_an_unremarkable_unverified_claim() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(Verdict::Unverified, UncertaintyBand::Qualified, c.id);
        let input = MiningInput {
            claim: &c,
            graph: &graph,
            evidence_pool: &[],
            fused: &f,
            prior_verdicts: &[],
        };
        assert!(evaluate(&input).is_empty());
    }
}
