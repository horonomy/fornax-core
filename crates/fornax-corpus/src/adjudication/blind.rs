//! Blind review (FORNX-342 scope: "blind-review mode that hides Fornax's
//! original verdict/recommendation where practical to reduce confirmation
//! bias").
//!
//! [`blind`] destructures [`CandidateCase`] **exhaustively by field name** —
//! not `..Default::default()`, not a partial match. If a field is ever added
//! to `CandidateCase`, this function fails to compile until someone decides
//! whether the new field leaks the model's judgment. That compile-time
//! enforcement is the real guarantee here; [`blinded_case_never_contains_a_model_verdict`]
//! is the backstop, not the mechanism.
//!
//! **Named limit** (see `docs/adr/0014-corpus-adjudication.md`): this is
//! presentational blinding, not a sealed/encrypted view. A reviewer with
//! direct SQLite access, or who runs `fornax corpus export` themselves,
//! can still read `local_verdict`. The guarantee is narrower and real: the
//! rendered review view built from a [`BlindedCase`] contains no verdict
//! field to leak.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use fornax_types::{Claim, Evidence, EvidenceGraph};

use crate::candidate::{CandidateCase, WithheldEvidence};

pub const BLINDED_CASE_SCHEMA_VERSION: u32 = 1;

/// A candidate case with every model-computed judgment stripped — see
/// module docs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlindedCase {
    pub schema_version: u32,
    pub case_id: Uuid,
    pub claim: Claim,
    pub evidence_pool: Vec<Evidence>,
    pub evidence_graph: EvidenceGraph,
    pub withheld_evidence: Vec<WithheldEvidence>,
    /// `hex(sha256(canonical json of this struct excluding this field))` —
    /// recomputed at review submission time to detect the underlying
    /// candidate having changed since the view was issued (stale evidence).
    pub blinded_digest: String,
}

/// Build a [`BlindedCase`] from `candidate`. `case_id` is safe to expose:
/// `CandidateCase::derive_id` hashes only `session_id` + `claim.id` +
/// `evidence_pool` — no verdict input.
pub fn blind(candidate: &CandidateCase) -> BlindedCase {
    // Exhaustive destructuring by name -- see module docs. `local_verdict`,
    // `local_uncertainty`, `mined_by`, `replay.recorded_verdict`,
    // `replay.recorded_uncertainty`, and `replay.recorded_action` are
    // deliberately never read here.
    let CandidateCase {
        schema_version: _,
        id,
        session_id: _,
        replay,
        context: _,
        local_verdict: _,
        local_uncertainty: _,
        mined_by: _,
        withheld_evidence,
        mined_at: _,
    } = candidate.clone();

    let mut blinded = BlindedCase {
        schema_version: BLINDED_CASE_SCHEMA_VERSION,
        case_id: id,
        claim: replay.claim,
        evidence_pool: replay.evidence_pool,
        evidence_graph: replay.evidence_graph,
        withheld_evidence,
        blinded_digest: String::new(),
    };
    blinded.blinded_digest = digest_of(&blinded);
    blinded
}

/// Recompute the digest a [`BlindedCase`] would have, for staleness checks
/// against a freshly re-blinded candidate.
pub fn digest_of(blinded: &BlindedCase) -> String {
    let mut for_hashing = blinded.clone();
    for_hashing.blinded_digest = String::new();
    let canonical = serde_json::to_vec(&for_hashing).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::CANDIDATE_SCHEMA_VERSION;
    use crate::mining::MiningStrategy;
    use fornax_replay::manifest::{ReplayManifest, REPLAY_MANIFEST_SCHEMA_VERSION};
    use fornax_types::{Provider, Verdict};
    use fornax_verify::decision::{RecommendationAction, RiskClass};
    use fornax_verify::fusion::UncertaintyBand;

    fn candidate() -> CandidateCase {
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        };
        let replay = ReplayManifest {
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
            recorded_verdict: Verdict::Contradicted,
            recorded_uncertainty: UncertaintyBand::Conflicted,
            recorded_action: RecommendationAction::Block,
            recorded_at: "2026-01-01T00:00:00Z".into(),
        };
        CandidateCase {
            schema_version: CANDIDATE_SCHEMA_VERSION,
            id: CandidateCase::derive_id("s1", &replay),
            session_id: "s1".into(),
            replay,
            context: None,
            local_verdict: Verdict::Contradicted,
            local_uncertainty: UncertaintyBand::Conflicted,
            mined_by: vec![MiningStrategy::EvidenceContradiction],
            withheld_evidence: vec![],
            mined_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn blinded_case_never_contains_a_model_verdict() {
        let blinded = blind(&candidate());
        let value = serde_json::to_value(&blinded).unwrap();
        let serialized = serde_json::to_string(&value).unwrap();
        for leak in [
            "contradicted",
            "conflicted",
            "block",
            "evidence_contradiction",
        ] {
            assert!(
                !serialized.to_lowercase().contains(leak),
                "blinded case leaked a model judgment token: {leak}"
            );
        }
        assert!(value.get("local_verdict").is_none());
        assert!(value.get("local_uncertainty").is_none());
        assert!(value.get("mined_by").is_none());
        assert!(value.get("recorded_verdict").is_none());
        assert!(value.get("recorded_action").is_none());
    }

    #[test]
    fn case_id_is_stable_and_matches_the_candidates_id() {
        let c = candidate();
        let blinded = blind(&c);
        assert_eq!(blinded.case_id, c.id);
    }

    #[test]
    fn digest_changes_when_the_evidence_pool_changes() {
        let mut c = candidate();
        let blinded_a = blind(&c);

        c.replay.evidence_pool.push(fornax_types::Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: fornax_types::EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"code": 1}),
            provenance: "test".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        });
        let blinded_b = blind(&c);

        assert_ne!(blinded_a.blinded_digest, blinded_b.blinded_digest);
    }

    #[test]
    fn digest_is_deterministic_for_the_same_content() {
        let c = candidate();
        assert_eq!(blind(&c).blinded_digest, blind(&c).blinded_digest);
    }
}
