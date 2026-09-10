//! [`CandidateCorpusManifest`]: the deterministic, versioned artifact
//! `fornax corpus export` writes, and the next adjudication stage consumes.

use std::collections::BTreeMap;

use crate::candidate::CandidateCase;

pub const CORPUS_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Failure to build a [`CandidateCorpusManifest`].
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    /// FORNX-341 AC: "candidate mining includes both suspicious cases and
    /// benign/hard-negative controls; it is not only positive-case
    /// harvesting." A manifest with candidates but zero
    /// [`crate::mining::MiningStrategy::BenignControl`] cases violates that
    /// AC structurally, not just by convention — enforced here rather than
    /// only documented.
    #[error(
        "corpus manifest has {candidate_count} candidate(s) but zero benign controls -- mine \
         more sessions (a control is a Verified claim with no conflict and no other strategy \
         firing), or if this corpus is deliberately scoped to a known-suspicious sample only, \
         state that scope explicitly rather than exporting it as a general corpus"
    )]
    ControlsAbsent { candidate_count: usize },
}

/// The versioned, deterministic artifact `fornax corpus export` writes.
/// `contains_adjudicated_labels` is always `false` here — no
/// [`CandidateCase`] carries a label (see that type's doc comment); this
/// field exists so a downstream consumer can assert it without re-deriving
/// the invariant.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CandidateCorpusManifest {
    pub manifest_schema_version: u32,
    pub corpus_version: String,
    /// `fornax_bench::dataset::content_hash_of` over this manifest's own
    /// canonical serialized `candidates` — a reproducibility pin, not a
    /// copy of `corpus_version` a caller could forget to bump.
    pub content_hash: String,
    /// `fornax_types::home_identity` of the machine this corpus was mined
    /// on (FORNX-339) — not a secret, just enough to tell two corpora mined
    /// on different machines apart.
    pub home_identity: String,
    pub candidate_count: usize,
    pub control_count: usize,
    pub strategy_counts: BTreeMap<String, usize>,
    pub withheld_evidence_count: usize,
    pub contains_adjudicated_labels: bool,
    pub candidates: Vec<CandidateCase>,
    pub mined_at: String,
}

/// Build a manifest from a set of already-mined candidates. `mined_at` is
/// passed in by the caller, never read from the clock here — mirrors
/// `fornax_verify::fusion`'s "pure and sync" discipline and
/// `fornax_replay::ReplayManifest::recorded_at`'s precedent.
pub fn build_corpus_manifest(
    mut candidates: Vec<CandidateCase>,
    corpus_version: String,
    home_identity: String,
    mined_at: String,
) -> Result<CandidateCorpusManifest, CorpusError> {
    // Sort by id for a byte-identical manifest across re-mining runs over
    // the same underlying data (FORNX-341 AC: deterministic/replayable).
    candidates.sort_by_key(|c| c.id);

    let candidate_count = candidates.len();
    let control_count = candidates
        .iter()
        .filter(|c| c.mined_by.as_slice() == [crate::mining::MiningStrategy::BenignControl])
        .count();

    if candidate_count > 0 && control_count == 0 {
        return Err(CorpusError::ControlsAbsent { candidate_count });
    }

    let mut strategy_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut withheld_evidence_count = 0;
    for candidate in &candidates {
        for strategy in &candidate.mined_by {
            let key = serde_json::to_value(strategy)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            *strategy_counts.entry(key).or_insert(0) += 1;
        }
        withheld_evidence_count += candidate.withheld_evidence.len();
    }

    let content_hash = fornax_bench::dataset::content_hash_of(
        &serde_json::to_vec(&candidates).unwrap_or_default(),
    );

    Ok(CandidateCorpusManifest {
        manifest_schema_version: CORPUS_MANIFEST_SCHEMA_VERSION,
        corpus_version,
        content_hash,
        home_identity,
        candidate_count,
        control_count,
        strategy_counts,
        withheld_evidence_count,
        contains_adjudicated_labels: false,
        candidates,
        mined_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining::MiningStrategy;
    use fornax_replay::manifest::REPLAY_MANIFEST_SCHEMA_VERSION;
    use fornax_types::{Claim, EvidenceGraph, Provider, Verdict};
    use fornax_verify::decision::{RecommendationAction, RiskClass};
    use fornax_verify::fusion::UncertaintyBand;
    use uuid::Uuid;

    fn candidate(mined_by: Vec<MiningStrategy>) -> CandidateCase {
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        };
        let replay = fornax_replay::manifest::ReplayManifest {
            manifest_schema_version: REPLAY_MANIFEST_SCHEMA_VERSION,
            adapter_provider: Provider::ClaudeCode,
            adapter_runtime_version: "1.0.0".into(),
            fusion_policy_name: "baseline".into(),
            fusion_policy_version: 1,
            decision_policy_name: "default".into(),
            decision_policy_version: 1,
            risk_class: RiskClass::Balanced,
            disabled_sensors: Default::default(),
            claim: claim.clone(),
            evidence_pool: vec![],
            evidence_graph: EvidenceGraph::default(),
            recorded_verdict: Verdict::Verified,
            recorded_uncertainty: UncertaintyBand::Qualified,
            recorded_action: RecommendationAction::Proceed,
            recorded_at: "2026-01-01T00:00:00Z".into(),
        };
        CandidateCase {
            schema_version: crate::candidate::CANDIDATE_SCHEMA_VERSION,
            id: CandidateCase::derive_id("s1", &replay),
            session_id: "s1".into(),
            replay,
            context: None,
            local_verdict: Verdict::Verified,
            local_uncertainty: UncertaintyBand::Qualified,
            mined_by,
            withheld_evidence: vec![],
            mined_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn refuses_to_build_when_candidates_exist_with_zero_controls() {
        let candidates = vec![candidate(vec![MiningStrategy::EvidenceContradiction])];
        let err = build_corpus_manifest(
            candidates,
            "v1".into(),
            "home-abc".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CorpusError::ControlsAbsent { candidate_count: 1 }
        ));
    }

    #[test]
    fn an_empty_corpus_is_not_an_error() {
        let manifest = build_corpus_manifest(
            vec![],
            "v1".into(),
            "home-abc".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .expect("empty corpus must not trip the controls-present gate");
        assert_eq!(manifest.candidate_count, 0);
    }

    #[test]
    fn builds_successfully_once_a_control_is_present_and_reports_it() {
        let candidates = vec![
            candidate(vec![MiningStrategy::EvidenceContradiction]),
            candidate(vec![MiningStrategy::BenignControl]),
        ];
        let manifest = build_corpus_manifest(
            candidates,
            "v1".into(),
            "home-abc".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .expect("one control present must satisfy the gate");
        assert_eq!(manifest.candidate_count, 2);
        assert_eq!(manifest.control_count, 1);
        assert!(!manifest.contains_adjudicated_labels);
    }

    #[test]
    fn manifest_building_is_deterministic_across_shuffled_input_order() {
        let a = candidate(vec![MiningStrategy::EvidenceContradiction]);
        let b = candidate(vec![MiningStrategy::BenignControl]);

        let m1 = build_corpus_manifest(
            vec![a.clone(), b.clone()],
            "v1".into(),
            "home-abc".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
        let m2 = build_corpus_manifest(
            vec![b, a],
            "v1".into(),
            "home-abc".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();

        assert_eq!(m1.content_hash, m2.content_hash);
        assert_eq!(
            m1.candidates.iter().map(|c| c.id).collect::<Vec<_>>(),
            m2.candidates.iter().map(|c| c.id).collect::<Vec<_>>()
        );
    }
}
