//! Typed receipt payload (FORNX-350). Field order in every struct below is
//! normative wire order -- `canonical_bytes` serializes with
//! `serde_json::to_vec`, which preserves declaration order, and never a
//! `HashMap`/`#[serde(flatten)]` anywhere in this module, since either one
//! destroys deterministic field ordering (see
//! `fornax_types::policy::revision`'s identical discipline, which this
//! mirrors).
//!
//! **What a receipt references, never embeds** (FORNX-350 AC3): every
//! evidence item is a reference plus a `payload_fingerprint`
//! (`hex(sha256(canonical payload)[..8])`, the same shape
//! `fornax_corpus::candidate::WithheldEvidence` already uses) -- never the
//! raw payload. `ClaimRef::claim_text_fingerprint` fingerprints the
//! *redacted* claim text, never the text itself. `EmbedPolicy::ReferenceOnly`
//! is the only variant in v1; there is no path in this module that embeds a
//! raw payload.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use fornax_types::graph::EvidenceRelation;
use fornax_types::sensor::{CollectionMethod, TrustClass};
use fornax_types::{EvidenceKind, SignalAvailability, SignalClass};
use fornax_verify::decision::{RecommendationAction, RiskClass};
use fornax_verify::fusion::{FusionRule, UncertaintyBand};
use fornax_verify::independence::FamilyBasis;
use fornax_verify::voi::EvidenceGapKind;

pub const RECEIPT_PAYLOAD_SCHEMA_VERSION: u32 = 1;

/// Fixed namespace for [`ReceiptBody::derive_id`]'s `Uuid::new_v5`
/// derivation -- an arbitrary constant, the same trick
/// `fornax_bench::dataset::content_hash_of`'s `DATASET_HASH_NAMESPACE` and
/// `fornax_corpus::candidate`'s `CANDIDATE_ID_NAMESPACE` already use to get
/// a deterministic id without a second hashing scheme.
const RECEIPT_ID_NAMESPACE: Uuid = Uuid::from_bytes([
    0x7a, 0x1e, 0x4c, 0x9b, 0x2f, 0x8d, 0x4a, 0x61, 0x9e, 0x03, 0x5b, 0x7c, 0x2a, 0x91, 0xd4, 0x6e,
]);

/// Only these [`EvidenceKind`]s may leave the local boundary in a receipt.
/// Mirrors `fornax_corpus::candidate::EXPORTABLE_EVIDENCE_KINDS` -- same
/// redaction posture, independently declared since `fornax-receipt` does
/// not depend on `fornax-corpus` (receipts are issued from a live finding,
/// not a mined candidate case).
pub const EXPORTABLE_EVIDENCE_KINDS: &[EvidenceKind] =
    &[EvidenceKind::ExitCode, EvidenceKind::ProcessObservation];

/// A single evidence payload above this size is withheld rather than
/// referenced with a fingerprint computed here, independent of its kind.
pub const MAX_FINGERPRINTED_PAYLOAD_BYTES: usize = 64 * 1024;

/// `hex(sha256(canonical bytes)[..8])` -- same shape as
/// `fornax_types::home_identity`/`fornax_corpus::candidate::WithheldEvidence::payload_fingerprint`:
/// enough to notice a mismatch, never reversible.
pub fn short_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..8])
}

/// `"sha256:<hex>"` -- the full digest form used for [`ReceiptDigest`] and
/// [`CoverageSummary::evidence_root`]. Distinct from [`short_fingerprint`]:
/// this one is a tamper-evidence digest over an entire body/list, not a
/// per-item fingerprint.
fn full_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Deterministic content bytes of `body` -- the input to [`digest_of`].
/// `serde_json::to_vec` preserves declaration order and never reorders
/// keys, so this is stable across processes as long as `ReceiptBody`'s own
/// field order never changes without a schema-version bump.
pub fn canonical_bytes(body: &ReceiptBody) -> Vec<u8> {
    serde_json::to_vec(body).expect("ReceiptBody serialization cannot fail")
}

/// A receipt body's content digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReceiptDigest(String);

impl ReceiptDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ReceiptDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn digest_of(body: &ReceiptBody) -> ReceiptDigest {
    ReceiptDigest(full_digest(&canonical_bytes(body)))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRef {
    pub claim_id: Uuid,
    pub session_id: String,
    /// [`fornax_types::Claim::subject`] -- a coarse category
    /// (`"command_succeeded"`, `"test_result"`, ...), never claim text.
    pub subject: String,
    /// `short_fingerprint(fornax_types::redact::redact_text(&claim.text))` --
    /// the *redacted* text is fingerprinted, never the raw text.
    pub claim_text_fingerprint: String,
    pub claimed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingSummary {
    pub verdict: fornax_types::Verdict,
    pub uncertainty: UncertaintyBand,
    pub unresolved_conflict: bool,
    pub counted_link_count: usize,
    pub discounted_link_count: usize,
    /// Sorted (by wire tag) and deduplicated -- the closed rule vocabulary
    /// that fired, never the free-text `RationaleEntry::detail` (which can
    /// name local paths/commands and stays reachable only via
    /// `fornax timeline`, not embedded here).
    pub fired_rules: Vec<FusionRule>,
    pub fusion_policy_name: String,
    pub fusion_policy_version: u32,
    pub computed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendationSummary {
    pub action: RecommendationAction,
    pub risk_class: RiskClass,
    pub decision_policy_name: String,
    pub decision_policy_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub evidence_id: Uuid,
    pub kind: EvidenceKind,
    pub relation: EvidenceRelation,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_class: Option<TrustClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_method: Option<CollectionMethod>,
    pub payload_fingerprint: String,
    pub evidence_purged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingEvidenceRef {
    pub signal_class: SignalClass,
    pub availability: SignalAvailability,
    pub noted_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptGap {
    pub kind: EvidenceGapKind,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithheldReason {
    /// This evidence's [`EvidenceKind`] is not in
    /// [`EXPORTABLE_EVIDENCE_KINDS`].
    KindNotExportable,
    /// The payload exceeded [`MAX_FINGERPRINTED_PAYLOAD_BYTES`].
    OversizedPayload { bytes: usize },
    /// This row's raw payload was already purged by the local retention
    /// sweep (`fornax_types::Evidence::evidence_purged`).
    AlreadyPurged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithheldRef {
    pub evidence_id: Uuid,
    pub kind: EvidenceKind,
    pub reason: WithheldReason,
}

/// Exactly one variant in v1: nothing embeds a raw payload anywhere in this
/// module. Kept as an enum (not a bare marker constant) so a future variant
/// requires an explicit, reviewable schema-version bump rather than a
/// silent behavior change under the same tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbedPolicy {
    ReferenceOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummary {
    /// `"sha256:<hex>"` over the canonical bytes of `referenced_evidence`
    /// (already sorted by `evidence_id`) -- a single digest a downstream
    /// consumer can compare without re-walking the whole evidence list.
    pub evidence_root: String,
    pub referenced_evidence: Vec<EvidenceRef>,
    pub missing_evidence: Vec<MissingEvidenceRef>,
    pub gaps: Vec<ReceiptGap>,
    /// Sorted, deduplicated -- every [`FamilyBasis`] the fused finding's
    /// referenced evidence was grouped under. Reused verbatim from
    /// `fornax_verify::independence`, never re-derived.
    pub source_family_bases: Vec<FamilyBasis>,
    pub withheld: Vec<WithheldRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBody {
    pub receipt_schema_version: u32,
    /// Deterministic -- see [`ReceiptBody::derive_id`]. Not a random UUID:
    /// re-issuing a receipt from byte-identical inputs at the same
    /// `issued_at` produces the same id.
    pub receipt_id: Uuid,
    pub issuer: String,
    /// `fornax_types::sensor_config::home_identity()` -- a non-authenticating
    /// pseudonym for detecting cross-`$FORNAX_HOME` data mixups, never a
    /// signing/authentication identity. See module docs.
    pub home_identity: String,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub embed_policy: EmbedPolicy,
    pub claim: ClaimRef,
    pub finding: FindingSummary,
    pub recommendation: RecommendationSummary,
    pub coverage: CoverageSummary,
    pub provenance: fornax_types::calibration::CalibrationProvenance,
    pub calibration: fornax_verify::calibration::CalibrationAssessment,
}

impl ReceiptBody {
    /// `Uuid::new_v5(RECEIPT_ID_NAMESPACE, sha256(canonical_bytes(self with receipt_id nil)))` --
    /// deterministic given every other field, so two calls to `issue_receipt`
    /// with byte-identical inputs and the same `issued_at` produce the same
    /// id.
    pub fn derive_id(&self) -> Uuid {
        let mut for_id = self.clone();
        for_id.receipt_id = Uuid::nil();
        let bytes = serde_json::to_vec(&for_id).expect("ReceiptBody serialization cannot fail");
        let digest = Sha256::digest(&bytes);
        Uuid::new_v5(&RECEIPT_ID_NAMESPACE, &digest)
    }
}

/// Wire form: body plus its own digest, deserialized together so the
/// digest can be recomputed and checked before [`IntegrityReceipt`] ever
/// exists (see [`IntegrityReceipt`]'s `TryFrom` impl).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntegrityReceiptWire {
    body: ReceiptBody,
    digest: ReceiptDigest,
}

/// A receipt is malformed the instant its own declared digest disagrees
/// with a fresh recompute over its body -- this is the tamper detector
/// [`fornax_types::policy::revision::PublishedPolicyRevision`] already
/// uses (`#[serde(try_from = ...)]` + digest recompute), applied here so a
/// hand-edited body can never enter the type system via `Deserialize`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("receipt digest {declared} does not match recomputed digest {recomputed} -- body was altered after issuance")]
pub struct ReceiptDigestMismatch {
    pub declared: String,
    pub recomputed: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "IntegrityReceiptWire")]
pub struct IntegrityReceipt {
    body: ReceiptBody,
    digest: ReceiptDigest,
}

impl IntegrityReceipt {
    pub fn body(&self) -> &ReceiptBody {
        &self.body
    }

    pub fn digest(&self) -> &ReceiptDigest {
        &self.digest
    }

    /// Only constructor bypassing the digest recompute -- used exclusively
    /// by [`crate::issue::issue_receipt`], which computed `digest` from
    /// `body` itself one line earlier and would only be re-deriving the
    /// identical value.
    pub(crate) fn new_trusted(body: ReceiptBody, digest: ReceiptDigest) -> Self {
        Self { body, digest }
    }
}

impl TryFrom<IntegrityReceiptWire> for IntegrityReceipt {
    type Error = ReceiptDigestMismatch;

    fn try_from(wire: IntegrityReceiptWire) -> Result<Self, Self::Error> {
        let recomputed = digest_of(&wire.body);
        if recomputed != wire.digest {
            return Err(ReceiptDigestMismatch {
                declared: wire.digest.0,
                recomputed: recomputed.0,
            });
        }
        Ok(IntegrityReceipt {
            body: wire.body,
            digest: wire.digest,
        })
    }
}

/// Sorts and deduplicates `rules` by their own serde wire tag -- `FusionRule`
/// has no `Ord` impl (a small closed-world identity enum), mirroring
/// `fornax_bench::slice::SliceKey::label`'s identical technique for a type
/// in the same position.
pub fn sorted_deduped_rules(mut rules: Vec<FusionRule>) -> Vec<FusionRule> {
    rules.sort_by_key(|r| serde_json::to_string(r).unwrap_or_default());
    rules.dedup();
    rules
}

/// Sorts and deduplicates [`FamilyBasis`] values -- it does have `Ord`, so
/// this is a plain sort+dedup, kept as a named helper for symmetry with
/// [`sorted_deduped_rules`] and so callers never forget the dedup half.
pub fn sorted_deduped_bases(mut bases: Vec<FamilyBasis>) -> Vec<FamilyBasis> {
    bases.sort();
    bases.dedup();
    bases
}

/// `"sha256:<hex>"` over the canonical bytes of `refs` (assumed
/// pre-sorted by the caller) -- [`CoverageSummary::evidence_root`].
pub fn evidence_root_of(refs: &[EvidenceRef]) -> String {
    full_digest(&serde_json::to_vec(refs).expect("Vec<EvidenceRef> serialization cannot fail"))
}

/// Ids present in `refs`, for callers building [`WithheldRef`] lists that
/// must never double-count an id already referenced.
pub fn referenced_ids(refs: &[EvidenceRef]) -> BTreeSet<Uuid> {
    refs.iter().map(|r| r.evidence_id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body() -> ReceiptBody {
        ReceiptBody {
            receipt_schema_version: RECEIPT_PAYLOAD_SCHEMA_VERSION,
            receipt_id: Uuid::nil(),
            issuer: "fornax-cli/receipt-issue/v1".to_string(),
            home_identity: "abcd1234".to_string(),
            issued_at: "2026-09-10T00:00:00Z".to_string(),
            not_after: Some("2026-09-11T00:00:00Z".to_string()),
            embed_policy: EmbedPolicy::ReferenceOnly,
            claim: ClaimRef {
                claim_id: Uuid::from_u128(1),
                session_id: "s1".to_string(),
                subject: "command_succeeded".to_string(),
                claim_text_fingerprint: "deadbeef".to_string(),
                claimed_at: "2026-09-10T00:00:00Z".to_string(),
            },
            finding: FindingSummary {
                verdict: fornax_types::Verdict::Verified,
                uncertainty: UncertaintyBand::Qualified,
                unresolved_conflict: false,
                counted_link_count: 1,
                discounted_link_count: 0,
                fired_rules: vec![],
                fusion_policy_name: "baseline".to_string(),
                fusion_policy_version: 2,
                computed_at: "2026-09-10T00:00:00Z".to_string(),
            },
            recommendation: RecommendationSummary {
                action: RecommendationAction::Proceed,
                risk_class: RiskClass::Balanced,
                decision_policy_name: "default".to_string(),
                decision_policy_version: 1,
            },
            coverage: CoverageSummary {
                evidence_root: "sha256:abc".to_string(),
                referenced_evidence: vec![],
                missing_evidence: vec![],
                gaps: vec![],
                source_family_bases: vec![],
                withheld: vec![],
            },
            provenance: fornax_types::calibration::CalibrationProvenance {
                schema_version: 1,
                provider: "claude_code".to_string(),
                adapter_version: None,
                capability_schema_version: 1,
                capability_fingerprint: vec![],
                fusion_policy_name: "baseline".to_string(),
                fusion_policy_version: 2,
                decision_policy_name: "default".to_string(),
                decision_policy_version: 1,
                reliability_policy_version: 1,
                disabled_sensors: vec![],
                active_policy_revision_digest: None,
                model_version: None,
                model_family: None,
            },
            calibration: fornax_verify::calibration::CalibrationAssessment {
                state: fornax_verify::calibration::CalibrationState::NoActiveCalibration,
                policy_version: 1,
            },
        }
    }

    #[test]
    fn canonical_bytes_is_deterministic_across_calls() {
        let body = sample_body();
        assert_eq!(canonical_bytes(&body), canonical_bytes(&body));
    }

    #[test]
    fn digest_changes_when_body_changes() {
        let mut body = sample_body();
        let d1 = digest_of(&body);
        body.finding.unresolved_conflict = true;
        let d2 = digest_of(&body);
        assert_ne!(d1, d2);
    }

    #[test]
    fn derive_id_is_deterministic_and_ignores_the_receipt_id_field_itself() {
        let mut a = sample_body();
        a.receipt_id = Uuid::nil();
        let mut b = sample_body();
        b.receipt_id = Uuid::from_u128(999); // pre-existing id must not matter
        assert_eq!(a.derive_id(), b.derive_id());
    }

    #[test]
    fn a_hand_edited_body_fails_the_digest_check_on_deserialize() {
        let mut body = sample_body();
        body.receipt_id = body.derive_id();
        let digest = digest_of(&body);
        let wire = IntegrityReceiptWire {
            body: body.clone(),
            digest,
        };
        let mut json: serde_json::Value = serde_json::to_value(&wire).unwrap();
        json["body"]["finding"]["unresolved_conflict"] = serde_json::json!(true);

        let result: Result<IntegrityReceipt, _> = serde_json::from_value(json)
            .map_err(|e| e.to_string())
            .and_then(|w: IntegrityReceiptWire| {
                IntegrityReceipt::try_from(w).map_err(|e| e.to_string())
            });
        assert!(result.is_err(), "hand-edited body must fail digest check");
    }

    #[test]
    fn an_unaltered_receipt_round_trips_through_deserialize() {
        let mut body = sample_body();
        body.receipt_id = body.derive_id();
        let digest = digest_of(&body);
        let receipt = IntegrityReceipt::new_trusted(body, digest);
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: IntegrityReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn no_numeric_confidence_field_anywhere_in_the_receipt_json() {
        // Mirrors fusion_tests::fused_finding_json_carries_no_numeric_confidence_field --
        // a receipt must never carry a numeric "honesty percentage" either.
        let mut body = sample_body();
        body.receipt_id = body.derive_id();
        let json = serde_json::to_value(&body).unwrap();
        let text = json.to_string();
        assert!(
            !text.contains("confidence"),
            "receipt body must never carry a confidence field: {text}"
        );
    }
}
