//! Projects a live finding into a reference-only [`schema::IntegrityReceipt`]
//! (FORNX-350 AC1/AC3). Pure and sync -- `issued_at` is injected by the
//! caller, never read from the clock here, mirroring
//! [`fornax_verify::fusion::FusionPolicy::fuse`]'s "pure and sync" discipline.

use std::collections::BTreeSet;

use fornax_types::{Claim, Evidence, EvidenceGraph};
use fornax_verify::decision::Recommendation;
use fornax_verify::fusion::FusedFinding;
use fornax_verify::independence::SourceFamilyMap;
use fornax_verify::voi::EvidenceGap;

use crate::schema::{
    self, digest_of, evidence_root_of, referenced_ids, short_fingerprint, sorted_deduped_bases,
    sorted_deduped_rules, ClaimRef, CoverageSummary, EmbedPolicy, EvidenceRef, FindingSummary,
    IntegrityReceipt, MissingEvidenceRef, ReceiptBody, ReceiptGap, RecommendationSummary,
    WithheldReason, WithheldRef, EXPORTABLE_EVIDENCE_KINDS, MAX_FINGERPRINTED_PAYLOAD_BYTES,
    RECEIPT_PAYLOAD_SCHEMA_VERSION,
};

/// Every input [`issue_receipt`] needs, already computed by the caller
/// (the daemon's live pipeline or `fornax receipt issue`'s own store-direct
/// re-fusion) -- this function performs no fusion/decision/VoI computation
/// itself, only projection.
pub struct ReceiptInputs<'a> {
    pub claim: &'a Claim,
    pub graph: &'a EvidenceGraph,
    pub evidence: &'a [Evidence],
    pub fused: &'a FusedFinding,
    pub recommendation: &'a Recommendation,
    pub gaps: &'a [EvidenceGap],
    pub families: &'a SourceFamilyMap,
    pub provenance: &'a fornax_types::calibration::CalibrationProvenance,
    pub calibration: &'a fornax_verify::calibration::CalibrationAssessment,
    pub issuer: &'a str,
    pub home_identity: &'a str,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum IssueError {
    #[error(
        "recommendation.claim_id {recommendation_claim_id} does not match claim.id {claim_id}"
    )]
    ClaimIdMismatch {
        claim_id: uuid::Uuid,
        recommendation_claim_id: uuid::Uuid,
    },
    #[error("fused.claim_id {fused_claim_id} does not match claim.id {claim_id}")]
    FusedClaimIdMismatch {
        claim_id: uuid::Uuid,
        fused_claim_id: uuid::Uuid,
    },
}

fn is_exportable(evidence: &Evidence) -> Result<(), WithheldReason> {
    if evidence.evidence_purged {
        return Err(WithheldReason::AlreadyPurged);
    }
    if !EXPORTABLE_EVIDENCE_KINDS.contains(&evidence.kind) {
        return Err(WithheldReason::KindNotExportable);
    }
    let payload_bytes = serde_json::to_vec(&evidence.payload).unwrap_or_default();
    if payload_bytes.len() > MAX_FINGERPRINTED_PAYLOAD_BYTES {
        return Err(WithheldReason::OversizedPayload {
            bytes: payload_bytes.len(),
        });
    }
    Ok(())
}

/// Projects `inputs` into a signed-nothing, reference-only
/// [`IntegrityReceipt`], stamped `issued_at`. `ttl_seconds` controls
/// [`ReceiptBody::not_after`]: `None` leaves it unset (see
/// [`crate::freshness`] for why an absent `not_after` is its own,
/// non-"fresh forever" state under the default gate policy).
pub fn issue_receipt(
    inputs: &ReceiptInputs<'_>,
    issued_at: &str,
    ttl_seconds: Option<i64>,
) -> Result<IntegrityReceipt, IssueError> {
    if inputs.recommendation.claim_id != inputs.claim.id {
        return Err(IssueError::ClaimIdMismatch {
            claim_id: inputs.claim.id,
            recommendation_claim_id: inputs.recommendation.claim_id,
        });
    }
    if inputs.fused.claim_id != inputs.claim.id {
        return Err(IssueError::FusedClaimIdMismatch {
            claim_id: inputs.claim.id,
            fused_claim_id: inputs.fused.claim_id,
        });
    }

    let evidence_by_id: std::collections::BTreeMap<uuid::Uuid, &Evidence> =
        inputs.evidence.iter().map(|e| (e.id, e)).collect();

    let mut referenced_evidence = Vec::new();
    let mut withheld = Vec::new();
    let mut sorted_links = inputs.graph.links.clone();
    sorted_links.sort_by_key(|l| l.evidence_id);
    for link in &sorted_links {
        let Some(evidence) = evidence_by_id.get(&link.evidence_id) else {
            continue; // unresolvable -- already captured via FusionRule::EvidenceUnresolved
        };
        match is_exportable(evidence) {
            Ok(()) => {
                referenced_evidence.push(EvidenceRef {
                    evidence_id: evidence.id,
                    kind: evidence.kind,
                    relation: link.relation,
                    observed_at: evidence.observed_at.clone(),
                    trust_class: evidence.source.as_ref().map(|s| s.trust_class.clone()),
                    sensor_name: evidence.source.as_ref().map(|s| s.sensor_name.clone()),
                    collection_method: evidence
                        .source
                        .as_ref()
                        .map(|s| s.collection_method.clone()),
                    payload_fingerprint: short_fingerprint(
                        &serde_json::to_vec(&evidence.payload).unwrap_or_default(),
                    ),
                    evidence_purged: evidence.evidence_purged,
                });
            }
            Err(reason) => {
                withheld.push(WithheldRef {
                    evidence_id: evidence.id,
                    kind: evidence.kind,
                    reason,
                });
            }
        }
    }
    referenced_evidence.sort_by_key(|e| e.evidence_id);
    withheld.sort_by_key(|w| w.evidence_id);

    let mut missing_evidence: Vec<MissingEvidenceRef> = inputs
        .graph
        .missing
        .iter()
        .map(|m| MissingEvidenceRef {
            signal_class: m.signal_class.clone(),
            availability: m.availability.clone(),
            noted_at: m.noted_at.clone(),
        })
        .collect();
    missing_evidence.sort_by(|a, b| a.noted_at.cmp(&b.noted_at));

    let gaps: Vec<ReceiptGap> = inputs
        .gaps
        .iter()
        .map(|g| ReceiptGap {
            kind: g.kind.clone(),
            detail: g.detail.clone(),
        })
        .collect();

    let referenced_ids_set: BTreeSet<uuid::Uuid> = referenced_ids(&referenced_evidence);
    let referenced_ids_vec: Vec<uuid::Uuid> = referenced_ids_set.into_iter().collect();
    let source_family_bases = sorted_deduped_bases(
        inputs
            .families
            .families_among(&referenced_ids_vec)
            .into_iter()
            .flat_map(|family| family.bases.clone())
            .collect(),
    );

    let fired_rules = sorted_deduped_rules(inputs.fused.rationale.iter().map(|r| r.rule).collect());

    let not_after = ttl_seconds.and_then(|ttl| {
        let issued: chrono::DateTime<chrono::Utc> = issued_at.parse().ok()?;
        Some((issued + chrono::Duration::seconds(ttl)).to_rfc3339())
    });

    let evidence_root = evidence_root_of(&referenced_evidence);

    let claim_text_fingerprint =
        short_fingerprint(fornax_types::redact::redact_text(&inputs.claim.text).as_bytes());

    let mut body = ReceiptBody {
        receipt_schema_version: RECEIPT_PAYLOAD_SCHEMA_VERSION,
        receipt_id: uuid::Uuid::nil(),
        issuer: inputs.issuer.to_string(),
        home_identity: inputs.home_identity.to_string(),
        issued_at: issued_at.to_string(),
        not_after,
        embed_policy: EmbedPolicy::ReferenceOnly,
        claim: ClaimRef {
            claim_id: inputs.claim.id,
            session_id: inputs.claim.session_id.clone(),
            subject: inputs.claim.subject.clone(),
            claim_text_fingerprint,
            claimed_at: inputs.claim.claimed_at.clone(),
        },
        finding: FindingSummary {
            verdict: inputs.fused.verdict,
            uncertainty: inputs.fused.uncertainty,
            unresolved_conflict: inputs.fused.unresolved_conflict,
            counted_link_count: inputs.fused.counted_link_ids.len(),
            discounted_link_count: inputs.fused.discounted_link_ids.len(),
            fired_rules,
            fusion_policy_name: inputs.fused.policy_name.clone(),
            fusion_policy_version: inputs.fused.policy_version,
            computed_at: inputs.fused.computed_at.clone(),
        },
        recommendation: RecommendationSummary {
            action: inputs.recommendation.action,
            risk_class: inputs.recommendation.risk_class,
            decision_policy_name: inputs.recommendation.policy_name.clone(),
            decision_policy_version: inputs.recommendation.policy_version,
        },
        coverage: CoverageSummary {
            evidence_root,
            referenced_evidence,
            missing_evidence,
            gaps,
            source_family_bases,
            withheld,
        },
        provenance: inputs.provenance.clone(),
        calibration: inputs.calibration.clone(),
    };
    body.receipt_id = body.derive_id();
    let digest = digest_of(&body);

    Ok(schema::IntegrityReceipt::new_trusted(body, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{
        Claim, CollectionMethod, EvidenceKind, EvidenceLink, EvidenceRelation, EvidenceSource,
        TrustClass,
    };
    use fornax_verify::decision::{RecommendationAction, RiskClass};
    use fornax_verify::fusion::UncertaintyBand;
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

    fn evidence(claim_id: Uuid) -> (fornax_types::Evidence, fornax_types::EvidenceLink) {
        let e = fornax_types::Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test".into(),
            source: Some(EvidenceSource::now(
                "exit_code_probe",
                TrustClass::AgentAdjacent,
                None,
                CollectionMethod::HookCallback,
                None,
            )),
            extension: None,
            evidence_purged: false,
        };
        let l = EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id,
            evidence_id: e.id,
            relation: EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:00Z".into(),
        };
        (e, l)
    }

    fn fused(claim_id: Uuid, counted: Vec<Uuid>) -> FusedFinding {
        FusedFinding {
            claim_id,
            verdict: fornax_types::Verdict::Verified,
            uncertainty: UncertaintyBand::Qualified,
            rationale: vec![],
            counted_link_ids: counted,
            discounted_link_ids: vec![],
            missing_evidence_ids: vec![],
            unresolved_conflict: false,
            policy_name: "baseline".into(),
            policy_version: 2,
            computed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn recommendation(claim_id: Uuid) -> Recommendation {
        Recommendation {
            claim_id,
            action: RecommendationAction::Proceed,
            risk_class: RiskClass::Balanced,
            policy_name: "default".into(),
            policy_version: 1,
            rationale_summary: "ok".into(),
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

    #[test]
    fn issuing_the_same_inputs_twice_is_byte_identical() {
        let c = claim();
        let (e, l) = evidence(c.id);
        let graph = EvidenceGraph {
            links: vec![l],
            missing: vec![],
        };
        let fused_finding = fused(c.id, vec![e.id]);
        let rec = recommendation(c.id);
        let prov = provenance();
        let cal = calibration();
        let families = SourceFamilyMap::build(std::slice::from_ref(&e));
        let inputs = ReceiptInputs {
            claim: &c,
            graph: &graph,
            evidence: &[e],
            fused: &fused_finding,
            recommendation: &rec,
            gaps: &[],
            families: &families,
            provenance: &prov,
            calibration: &cal,
            issuer: "fornax-cli/receipt-issue/v1",
            home_identity: "abcd1234",
        };

        let a = issue_receipt(&inputs, "2026-01-01T00:00:00Z", None).unwrap();
        let b = issue_receipt(&inputs, "2026-01-01T00:00:00Z", None).unwrap();
        assert_eq!(
            schema::canonical_bytes(a.body()),
            schema::canonical_bytes(b.body())
        );
        assert_eq!(a.body().receipt_id, b.body().receipt_id);
    }

    #[test]
    fn no_raw_payload_bytes_appear_anywhere_in_the_issued_receipt() {
        let c = claim();
        let (e, l) = evidence(c.id);
        let graph = EvidenceGraph {
            links: vec![l],
            missing: vec![],
        };
        let fused_finding = fused(c.id, vec![e.id]);
        let rec = recommendation(c.id);
        let prov = provenance();
        let cal = calibration();
        let families = SourceFamilyMap::build(std::slice::from_ref(&e));
        let inputs = ReceiptInputs {
            claim: &c,
            graph: &graph,
            evidence: &[e],
            fused: &fused_finding,
            recommendation: &rec,
            gaps: &[],
            families: &families,
            provenance: &prov,
            calibration: &cal,
            issuer: "fornax-cli/receipt-issue/v1",
            home_identity: "abcd1234",
        };
        let receipt = issue_receipt(&inputs, "2026-01-01T00:00:00Z", None).unwrap();
        let json = serde_json::to_string(receipt.body()).unwrap();
        // The evidence's raw payload was `{"exit_code": 0}` -- the schema
        // has no `payload` field anywhere, so its presence would mean a
        // raw payload leaked in verbatim rather than being fingerprinted.
        assert!(
            !json.contains("\"payload\""),
            "the raw payload must never appear in the receipt: {json}"
        );
        assert_eq!(receipt.body().coverage.referenced_evidence.len(), 1);
    }

    #[test]
    fn a_mismatched_claim_id_is_rejected() {
        let c = claim();
        let graph = EvidenceGraph {
            links: vec![],
            missing: vec![],
        };
        let fused_finding = fused(c.id, vec![]);
        let rec = recommendation(Uuid::new_v4()); // mismatched
        let prov = provenance();
        let cal = calibration();
        let families = SourceFamilyMap::build(&[]);
        let inputs = ReceiptInputs {
            claim: &c,
            graph: &graph,
            evidence: &[],
            fused: &fused_finding,
            recommendation: &rec,
            gaps: &[],
            families: &families,
            provenance: &prov,
            calibration: &cal,
            issuer: "fornax-cli/receipt-issue/v1",
            home_identity: "abcd1234",
        };
        let err = issue_receipt(&inputs, "2026-01-01T00:00:00Z", None).unwrap_err();
        assert!(matches!(err, IssueError::ClaimIdMismatch { .. }));
    }

    #[test]
    fn ttl_seconds_sets_not_after_relative_to_issued_at() {
        let c = claim();
        let graph = EvidenceGraph {
            links: vec![],
            missing: vec![],
        };
        let fused_finding = fused(c.id, vec![]);
        let rec = recommendation(c.id);
        let prov = provenance();
        let cal = calibration();
        let families = SourceFamilyMap::build(&[]);
        let inputs = ReceiptInputs {
            claim: &c,
            graph: &graph,
            evidence: &[],
            fused: &fused_finding,
            recommendation: &rec,
            gaps: &[],
            families: &families,
            provenance: &prov,
            calibration: &cal,
            issuer: "fornax-cli/receipt-issue/v1",
            home_identity: "abcd1234",
        };
        let receipt = issue_receipt(&inputs, "2026-01-01T00:00:00Z", Some(3600)).unwrap();
        assert_eq!(
            receipt.body().not_after.as_deref(),
            Some("2026-01-01T01:00:00+00:00")
        );
    }
}
