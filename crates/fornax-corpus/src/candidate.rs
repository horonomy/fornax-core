//! [`CandidateCase`] and the redaction/classification boundary
//! ([`sanitize`]) a full evidence pool must pass through before it can be
//! frozen into one.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use fornax_types::reliability_context::CohortIdentity;
use fornax_types::Verdict;
use fornax_types::{Claim, Evidence, EvidenceKind};
use fornax_verify::fusion::UncertaintyBand;

use fornax_replay::manifest::ReplayManifest;

use crate::mining::MiningStrategy;

pub const CANDIDATE_SCHEMA_VERSION: u32 = 1;

/// Fixed namespace for [`CandidateCase::id`]'s `Uuid::new_v5` derivation —
/// same trick as `fornax_bench::dataset::DATASET_HASH_NAMESPACE`, an
/// arbitrary constant frozen for stable, deterministic ids across re-mining.
const CANDIDATE_ID_NAMESPACE: Uuid = Uuid::from_bytes([
    0x7a, 0x1f, 0x3e, 0x9c, 0x4b, 0x8d, 0x41, 0x2a, 0x9e, 0x63, 0x0c, 0x5d, 0x8a, 0x1b, 0x77, 0x44,
]);

/// Only these [`EvidenceKind`]s may leave the local boundary in a
/// [`CandidateCase`]. A per-kind allowlist, not a new redactor: everything
/// else (`ToolResult`, `TranscriptExcerpt`, `FileDiff`) is exactly the kind
/// of payload most likely to carry raw tool output, source, or transcript
/// content, and is withheld whole rather than redacted-and-shipped.
pub const EXPORTABLE_EVIDENCE_KINDS: &[EvidenceKind] =
    &[EvidenceKind::ExitCode, EvidenceKind::ProcessObservation];

/// A single evidence payload above this size is withheld rather than
/// exported, independent of its kind — a coarse backstop against an
/// oversized or malformed record, not a substitute for the kind allowlist.
pub const MAX_CANDIDATE_PAYLOAD_BYTES: usize = 64 * 1024;

/// Why one piece of evidence did not make it into a [`CandidateCase`]'s
/// sanitized pool. The evidence's own id/kind/timestamp are kept (they are
/// meaningful only against this machine's local store — resolvable locally,
/// meaningless off-machine) plus a fingerprint of the withheld payload, so a
/// human reviewer can ask "was anything withheld, and does that change the
/// verdict?" without the payload itself ever leaving.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WithheldEvidence {
    pub evidence_id: Uuid,
    pub kind: EvidenceKind,
    pub observed_at: String,
    /// `hex(sha256(canonical payload)[..8])` — same shape as
    /// `fornax_types::home_identity`: enough to notice a mismatch, never
    /// reversible.
    pub payload_fingerprint: String,
    pub reason: WithheldReason,
}

/// See [`WithheldEvidence::reason`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithheldReason {
    /// This evidence's [`EvidenceKind`] is not in
    /// [`EXPORTABLE_EVIDENCE_KINDS`] (e.g. `TranscriptExcerpt`, `FileDiff`,
    /// `ToolResult`).
    KindNotExportable,
    /// The payload exceeded [`MAX_CANDIDATE_PAYLOAD_BYTES`].
    OversizedPayload { bytes: usize },
    /// `fornax_types::redact::redact_json` changed this payload — the
    /// conservative rule is to withhold the whole item rather than export a
    /// partially-redacted version, since a redactor that fired at all is
    /// exactly the item most likely to carry an adjacent, unfired secret
    /// (see `redact.rs`'s own documented gaps).
    RedactionTripped,
    /// This row's raw payload was already purged by the local retention
    /// sweep (`fornax_types::Evidence::evidence_purged`) before mining ran.
    AlreadyPurged,
}

fn payload_fingerprint(payload: &serde_json::Value) -> String {
    let canonical = serde_json::to_vec(payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// Redact and classify one full evidence pool plus its claim before a
/// [`CandidateCase`] freezes them into a [`ReplayManifest`] (FORNX-341
/// scope: "redaction/classification before any research/cloud export").
/// Returns the sanitized pool, the sanitized claim, and a record of
/// everything withheld and why.
///
/// `claim.text` is passed through `redact_text` — `fornax-verify::fusion`
/// never reads claim text (only `subject`/id/timestamps), so this cannot
/// change fusion's recomputed verdict when the manifest is later replayed.
pub fn sanitize(
    pool: Vec<Evidence>,
    claim: Claim,
) -> (Vec<Evidence>, Claim, Vec<WithheldEvidence>) {
    let mut kept = Vec::with_capacity(pool.len());
    let mut withheld = Vec::new();

    for evidence in pool {
        if evidence.evidence_purged {
            withheld.push(WithheldEvidence {
                evidence_id: evidence.id,
                kind: evidence.kind,
                observed_at: evidence.observed_at.clone(),
                payload_fingerprint: payload_fingerprint(&evidence.payload),
                reason: WithheldReason::AlreadyPurged,
            });
            continue;
        }

        if !EXPORTABLE_EVIDENCE_KINDS.contains(&evidence.kind) {
            withheld.push(WithheldEvidence {
                evidence_id: evidence.id,
                kind: evidence.kind,
                observed_at: evidence.observed_at.clone(),
                payload_fingerprint: payload_fingerprint(&evidence.payload),
                reason: WithheldReason::KindNotExportable,
            });
            continue;
        }

        let payload_bytes = serde_json::to_vec(&evidence.payload)
            .unwrap_or_default()
            .len();
        if payload_bytes > MAX_CANDIDATE_PAYLOAD_BYTES {
            withheld.push(WithheldEvidence {
                evidence_id: evidence.id,
                kind: evidence.kind,
                observed_at: evidence.observed_at.clone(),
                payload_fingerprint: payload_fingerprint(&evidence.payload),
                reason: WithheldReason::OversizedPayload {
                    bytes: payload_bytes,
                },
            });
            continue;
        }

        let redacted_payload = fornax_types::redact::redact_json(&evidence.payload);
        if redacted_payload != evidence.payload {
            withheld.push(WithheldEvidence {
                evidence_id: evidence.id,
                kind: evidence.kind,
                observed_at: evidence.observed_at.clone(),
                payload_fingerprint: payload_fingerprint(&evidence.payload),
                reason: WithheldReason::RedactionTripped,
            });
            continue;
        }

        kept.push(evidence);
    }

    let mut sanitized_claim = claim;
    sanitized_claim.text = fornax_types::redact::redact_text(&sanitized_claim.text);

    (kept, sanitized_claim, withheld)
}

/// One mined, redacted candidate integrity case awaiting human adjudication.
/// Deliberately carries **no** `adjudicated_expected_outcome` and **no**
/// `labeling_provenance` field — there is no code path from this type to a
/// `fornax_bench::dataset::LabeledTrajectory` other than
/// [`crate::promote::promote_to_labeled_trajectory`], which requires the
/// caller to supply a real human adjudication record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CandidateCase {
    pub schema_version: u32,
    pub id: Uuid,
    pub session_id: String,
    /// Frozen over the SANITIZED evidence pool/claim — this is what a
    /// downstream adjudication/replay consumer reads.
    pub replay: ReplayManifest,
    /// `None` unless the caller supplied every `RawReliabilityContext`
    /// dimension explicitly (e.g. via CLI flags) — `model_family`,
    /// `model_version`, `task_class`, and `repository_class` have no local
    /// source in the store, so this is never fabricated as "unknown".
    pub context: Option<CohortIdentity>,
    /// What fusion actually concluded over the FULL (unsanitized) evidence
    /// pool — may differ from `replay.recorded_verdict`, which was computed
    /// over the sanitized pool. See [`Self::sanitization_altered_outcome`].
    pub local_verdict: Verdict,
    pub local_uncertainty: UncertaintyBand,
    pub mined_by: Vec<MiningStrategy>,
    pub withheld_evidence: Vec<WithheldEvidence>,
    pub mined_at: String,
}

impl CandidateCase {
    /// Deterministic id derived from this case's content — mining the same
    /// session/claim state twice produces the same id (FORNX-341 AC: the
    /// candidate manifest must be deterministic/replayable).
    pub fn derive_id(session_id: &str, replay: &ReplayManifest) -> Uuid {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(replay.claim.id.as_bytes());
        hasher.update(
            serde_json::to_vec(&replay.evidence_pool)
                .unwrap_or_default()
                .as_slice(),
        );
        let digest = hasher.finalize();
        Uuid::new_v5(&CANDIDATE_ID_NAMESPACE, &digest)
    }

    /// True when sanitization withheld evidence that changed the recorded
    /// verdict — i.e. the machine's real conclusion over the full pool
    /// (`local_verdict`) differs from what a replay of the sanitized
    /// manifest alone would show (`replay.recorded_verdict`). Mining always
    /// runs over the full pool and sanitization always runs after, so these
    /// two verdicts are never reconciled into one field — a reviewer needs
    /// to see both, not a value that silently picked one.
    pub fn sanitization_altered_outcome(&self) -> bool {
        self.local_verdict != self.replay.recorded_verdict
    }
}
