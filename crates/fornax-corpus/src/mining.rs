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
