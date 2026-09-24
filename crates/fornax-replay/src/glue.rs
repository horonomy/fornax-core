//! Small, adapter-agnostic glue for turning already-normalized
//! `Claim`/`Evidence` (however they were produced — a live adapter, a golden
//! fixture replayed through one, or hand-built test data) into the frozen
//! [`fornax_types::EvidenceGraph`] shape [`crate::manifest::build_manifest`]
//! needs.
//!
//! This module deliberately depends on nothing beyond `fornax-types`: it
//! does not know what an `AgentAdapter` or a `GoldenFixture` is. The actual
//! "replay a real fixture through a real adapter" step (FORNX-98 AC 5) lives
//! in `tests/fixture_end_to_end.rs`, which pulls in
//! `fornax-adapter-conformance` and the concrete adapter crates as
//! dev-dependencies only — mirroring `fornax-adapter-conformance` itself
//! keeping the concrete adapter crates as dev-dependencies, so this crate's
//! shipped library never gains an adapter-crate dependency it doesn't need
//! for `replay` itself.

use uuid::Uuid;

use fornax_types::{Claim, Evidence, EvidenceGraph, EvidenceLink, EvidenceRelation};

/// Links every entry in `evidence` to `claim` with `relation`, producing the
/// [`EvidenceGraph`] `build_manifest` expects. No [`fornax_types::MissingEvidence`]
/// notes are synthesized — a caller with an actual gap to record should add
/// one to the returned graph directly.
pub fn link_all_evidence_to_claim(
    claim: &Claim,
    evidence: &[Evidence],
    relation: EvidenceRelation,
    linked_at: &str,
) -> EvidenceGraph {
    let links = evidence
        .iter()
        .map(|e| EvidenceLink {
            id: Uuid::new_v4(),
            session_id: claim.session_id.clone(),
            claim_id: claim.id,
            evidence_id: e.id,
            relation,
            linked_at: linked_at.to_string(),
        })
        .collect();
    EvidenceGraph {
        links,
        missing: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::EvidenceKind;

    fn claim() -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "t".into(),
            subject: "s".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn evidence() -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        }
    }

    #[test]
    fn links_every_evidence_entry_to_the_claim() {
        let c = claim();
        let evs = vec![evidence(), evidence()];
        let graph = link_all_evidence_to_claim(
            &c,
            &evs,
            EvidenceRelation::Supports,
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(graph.links.len(), 2);
        for (link, ev) in graph.links.iter().zip(evs.iter()) {
            assert_eq!(link.claim_id, c.id);
            assert_eq!(link.evidence_id, ev.id);
            assert_eq!(link.relation, EvidenceRelation::Supports);
        }
        assert!(graph.missing.is_empty());
    }
}
