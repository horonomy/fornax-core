//! Audit checkpoints (FORNX-317, epic FORNX-20): anchoring local ledger
//! heads to signed remote checkpoints.
//!
//! **Normative wire contract.** See `docs/adr/0012-audit-checkpoints.md`
//! (ADR-0012 draft) for the single source of truth this module implements
//! byte-for-byte, jointly consumed by the `fornax-cloud` issuer/witness
//! implementation. Any field name, nesting, byte format, or status code
//! decided there must not be re-derived or "fixed" here.
//!
//! **The cloud is a witness, never a verifier of the chain.** A checkpoint
//! is a cloud-countersigned witness statement about what a device claimed
//! its ledger head was at a point in time. The cloud stores only
//! `(ledger_seq, entry_hash)` pairs and structurally cannot verify the
//! device's hash chain (see `fornax_store::audit_ledger`'s
//! `compute_entry_hash`, which never leaves this device). See ADR-0012 §1
//! for the full "what this contract is, and what it is not" statement.
//!
//! **Domain separation.** The signed message is
//! [`AUDIT_CHECKPOINT_SIGNING_DOMAIN`] concatenated with the raw decoded
//! payload bytes -- never the payload alone, and never re-serialized by
//! Rust (Python/`fornax-cloud` is the sole producer; this crate is only
//! ever the verifier). See [`super::policy::BUNDLE_SIGNING_DOMAIN`]
//! for the identical discipline this mirrors.
//!
//! **The `seq` naming rule (ADR-0012 §0.1, anti-FORNX-312 measure).** The
//! bare token `seq` must never appear as a wire field name here. Every use
//! is qualified: [`LedgerHead::ledger_seq`] (the device's local hash-chain
//! position, `fornax_store::audit_ledger`'s `audit_events.seq`) is
//! disjoint from `checkpoint_seq` (the cloud-side attestation series
//! counter).

use serde::{Deserialize, Serialize};

use super::policy::{verify_signed_envelope, BundleSignature, KeyId, MAX_PAYLOAD_BYTES};

pub const AUDIT_CHECKPOINT_SCHEMA_VERSION: u32 = 1;
pub const SUPPORTED_CHECKPOINT_SCHEMA_VERSIONS: &[u32] = &[1];

/// 27 bytes, LF-terminated. Must be byte-identical to the constant of the
/// same name in `fornax-cloud`'s `policy/signing.py` (ADR-0012 §5.1) --
/// enforced by this module's own
/// `checkpoint_domain_matches_adr_0012_literal_bytes` test.
pub const AUDIT_CHECKPOINT_SIGNING_DOMAIN: &[u8] = b"fornax-audit-checkpoint/v1\n";

/// One position in the device's local hash chain, echoed on the wire.
/// Nesting under `head` (never flat `ledger_seq`/`entry_hash` fields on the
/// enclosing object) is normative -- see ADR-0012 §2.2's anti-FORNX-312
/// note and this module's `flat_head_fields_are_rejected_not_silently_...`
/// regression test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerHead {
    pub ledger_seq: i64,
    pub entry_hash: String,
}

/// Self-reported and unverifiable (ADR-0012 §2.3): the cloud records this
/// verbatim and cannot check it, since it never receives audit event
/// payloads and so cannot recompute
/// `fornax_store::audit_ledger::compute_entry_hash`. `status` is
/// `"valid"` | `"diverged"`; `first_bad_ledger_seq`/`divergence_kind` are
/// always present as keys, `null` iff `status == "valid"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReportedChainStatus {
    pub status: String,
    pub first_bad_ledger_seq: Option<i64>,
    pub divergence_kind: Option<String>,
}

/// The device's request body for `POST /v1/devices/me/audit-checkpoints`
/// (ADR-0012 §2.2). Field order below is the wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpointRequest {
    pub checkpoint_schema_version: u32,
    pub checkpoint_seq: u64,
    pub observed_at: String,
    pub head: LedgerHead,
    pub device_reported_chain_status: DeviceReportedChainStatus,
}

/// A prior checkpoint's identity, embedded so each receipt is
/// self-contained evidence of head movement without fetching every prior
/// receipt (ADR-0012 §3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevCheckpoint {
    pub checkpoint_seq: u64,
    pub head: LedgerHead,
}

/// Wire/envelope form. Structurally identical to
/// [`super::policy::SignedPolicyBundle`] / [`super::policy::revocation::SignedRevocationList`]
/// with only the version field renamed -- reuses [`BundleSignature`]
/// verbatim (ADR-0012 §3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditCheckpoint {
    pub checkpoint_schema_version: u32,
    pub payload_b64: String,
    pub signatures: Vec<BundleSignature>,
}

/// The authenticated content of a checkpoint, parsed only *after*
/// signature verification succeeds (ADR-0012 §3.2). **Key order below is
/// the wire order and is normative** -- the cloud builds this dict in
/// exactly this order; this struct declares fields in exactly this order,
/// verified byte-for-byte by this module's golden-vector test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpointPayload {
    pub checkpoint_schema_version: u32,
    pub issuer: String,
    pub device_id: String,
    pub checkpoint_seq: u64,
    pub issued_at: String,
    pub observed_at: String,
    pub head: LedgerHead,
    pub device_reported_chain_status: DeviceReportedChainStatus,
    pub prev_checkpoint: Option<PrevCheckpoint>,
}

/// Verified, authenticated audit checkpoint. Private fields, accessors
/// only -- [`verify_audit_checkpoint`] is the sole constructor, mirroring
/// [`super::policy::revocation::VerifiedRevocationList`]'s discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuditCheckpoint {
    payload: AuditCheckpointPayload,
    verified_by: KeyId,
}

impl VerifiedAuditCheckpoint {
    pub fn payload(&self) -> &AuditCheckpointPayload {
        &self.payload
    }

    pub fn checkpoint_seq(&self) -> u64 {
        self.payload.checkpoint_seq
    }

    pub fn head(&self) -> &LedgerHead {
        &self.payload.head
    }

    pub fn issued_at(&self) -> &str {
        &self.payload.issued_at
    }

    pub fn device_id(&self) -> &str {
        &self.payload.device_id
    }

    pub fn verified_by(&self) -> &KeyId {
        &self.verified_by
    }
}

/// Exhaustive rejection vocabulary for [`verify_audit_checkpoint`]. Not a
/// re-use of [`super::policy::revocation::RevocationRejection`]'s shape --
/// this artifact checks different structural invariants (nested `head`,
/// mutually-consistent `device_reported_chain_status`, `prev_checkpoint`
/// presence tied to `checkpoint_seq == 1`) that revocation lists don't
/// have, and has no window/expiry check at all (ADR-0012 §1.1).
#[derive(Debug, Clone, thiserror::Error)]
pub enum CheckpointRejection {
    #[error("envelope is malformed: {detail}")]
    MalformedEnvelope { detail: String },
    #[error("checkpoint_schema_version {found} is not supported (supported: {supported:?})")]
    UnsupportedCheckpointSchemaVersion { found: u32, supported: Vec<u32> },
    #[error("envelope checkpoint_schema_version {envelope} does not match payload's {payload}")]
    SchemaVersionMismatch { envelope: u32, payload: u32 },
    #[error("payload_b64 is not valid strict-canonical base64: {detail}")]
    MalformedPayloadEncoding { detail: String },
    #[error("payload is {found} bytes, exceeding the {max}-byte limit")]
    PayloadTooLarge { found: usize, max: usize },
    #[error("checkpoint carries no signatures")]
    NoSignatures,
    #[error("checkpoint carries {found} signatures, exceeding the {max} limit")]
    TooManySignatures { found: usize, max: usize },
    #[error("no signature names a key_id present in the trust store: offered {offered:?}")]
    UnknownKeyId { offered: Vec<KeyId> },
    #[error("key {key_id:?} uses unsupported algorithm {algorithm:?}")]
    UnsupportedAlgorithm {
        key_id: KeyId,
        algorithm: super::policy::SignatureAlgorithm,
    },
    #[error("signature for key {key_id:?} is malformed")]
    MalformedSignature { key_id: KeyId },
    #[error("key {key_id:?} is not yet valid: not_before={not_before}, now={now}")]
    KeyNotYetValid {
        key_id: KeyId,
        not_before: String,
        now: chrono::DateTime<chrono::Utc>,
    },
    #[error("key {key_id:?} has been retired: not_after={not_after}, now={now}")]
    KeyRetired {
        key_id: KeyId,
        not_after: String,
        now: chrono::DateTime<chrono::Utc>,
    },
    #[error("signature is invalid for trusted, current key(s): {key_ids:?}")]
    SignatureInvalid { key_ids: Vec<KeyId> },
    #[error("field {field} has a malformed timestamp: {value:?}")]
    MalformedTimestamp { field: &'static str, value: String },
    #[error("payload is malformed: {detail}")]
    MalformedPayload { detail: String },
    /// ADR-0012 §3.3: "Neither side may rely on serde's/Pydantic's implicit
    /// missing-`Option` tolerance." Without this explicit check, a payload
    /// that simply omits `prev_checkpoint` (or
    /// `device_reported_chain_status`'s `first_bad_ledger_seq`/
    /// `divergence_kind`) would silently deserialize as `None` -- serde
    /// treats a missing `Option<T>` field as `None` even without
    /// `#[serde(default)]`, and `deny_unknown_fields` only rejects EXTRA
    /// keys, never absent ones. This variant closes that gap.
    #[error("required key {key:?} is missing from the payload (a null value must still be present, never an absent key)")]
    MissingRequiredKey { key: &'static str },
    #[error("issuer must not be empty")]
    EmptyIssuer,
    #[error("device_id must not be empty")]
    EmptyDeviceId,
    #[error("head.entry_hash is malformed: {value:?}")]
    MalformedEntryHash { value: String },
    #[error("head.ledger_seq must be at least 1, found {found}")]
    LedgerSeqBelowOne { found: i64 },
    #[error("checkpoint_seq must be at least 1, found {found}")]
    CheckpointSeqBelowOne { found: u64 },
    #[error("prev_checkpoint presence is inconsistent with checkpoint_seq {checkpoint_seq}")]
    PrevCheckpointPresenceInconsistent { checkpoint_seq: u64 },
    #[error(
        "device_reported_chain_status.status {found:?} is not one of {{\"valid\", \"diverged\"}}"
    )]
    UnrecognizedChainStatus { found: String },
    #[error("device_reported_chain_status is internally inconsistent")]
    ChainStatusInconsistent,
}

impl From<super::policy::EnvelopeVerificationError> for CheckpointRejection {
    fn from(e: super::policy::EnvelopeVerificationError) -> Self {
        use super::policy::EnvelopeVerificationError as E;
        match e {
            E::MalformedPayloadEncoding { detail } => {
                CheckpointRejection::MalformedPayloadEncoding { detail }
            }
            E::PayloadTooLarge { found, max } => {
                CheckpointRejection::PayloadTooLarge { found, max }
            }
            E::NoSignatures => CheckpointRejection::NoSignatures,
            E::TooManySignatures { found, max } => {
                CheckpointRejection::TooManySignatures { found, max }
            }
            E::UnknownKeyId { offered } => CheckpointRejection::UnknownKeyId { offered },
            E::UnsupportedAlgorithm { key_id, algorithm } => {
                CheckpointRejection::UnsupportedAlgorithm { key_id, algorithm }
            }
            E::MalformedSignature { key_id } => CheckpointRejection::MalformedSignature { key_id },
            E::KeyNotYetValid {
                key_id,
                not_before,
                now,
            } => CheckpointRejection::KeyNotYetValid {
                key_id,
                not_before,
                now,
            },
            E::KeyRetired {
                key_id,
                not_after,
                now,
            } => CheckpointRejection::KeyRetired {
                key_id,
                not_after,
                now,
            },
            E::SignatureInvalid { key_ids } => CheckpointRejection::SignatureInvalid { key_ids },
            E::MalformedKeyTimestamp { field, value } => {
                CheckpointRejection::MalformedTimestamp { field, value }
            }
        }
    }
}

fn entry_hash_is_well_formed(value: &str) -> bool {
    // `^sha256:[0-9a-f]{64}$` (ADR-0012 §4.1), checked without pulling in a
    // regex dependency for one fixed-shape pattern.
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn parse_rfc3339(field: &'static str, value: &str) -> Result<(), CheckpointRejection> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| CheckpointRejection::MalformedTimestamp {
            field,
            value: value.to_string(),
        })
}

/// Evaluation order (normative -- ADR-0012 §3.4, mirroring
/// `verify_revocation_list`'s signature-before-semantics discipline):
///
/// 1. Parse envelope.
/// 2. `checkpoint_schema_version` supported.
/// 3. Signature-count bounds, strict-decode `payload_b64`, and
///    per-signature verification -- all delegated to
///    [`verify_signed_envelope`] under [`AUDIT_CHECKPOINT_SIGNING_DOMAIN`]
///    (steps 3-5 of the shared helper's own evaluation order).
/// 6. Parse [`AuditCheckpointPayload`] (only now, post-authentication).
/// 7. Cross-check envelope/payload `checkpoint_schema_version`.
/// 8. Parse `issued_at`/`observed_at`.
/// 9. Structural checks (`issuer`/`device_id` non-empty, `entry_hash`
///    shape, `ledger_seq >= 1`, `checkpoint_seq >= 1`, `prev_checkpoint`
///    presence tied to `checkpoint_seq == 1`, `status` closed vocabulary,
///    `status`/`first_bad_ledger_seq`/`divergence_kind` mutual
///    consistency).
/// 10. Construct [`VerifiedAuditCheckpoint`].
///
/// **No window check** -- no `not_before`/`expires_at` exists on this
/// artifact (ADR-0012 §1.1).
pub fn verify_audit_checkpoint(
    envelope_bytes: &[u8],
    trusted: &super::policy::TrustedVerificationKeys,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<VerifiedAuditCheckpoint, CheckpointRejection> {
    // 1. Parse envelope.
    let envelope: SignedAuditCheckpoint = serde_json::from_slice(envelope_bytes).map_err(|e| {
        CheckpointRejection::MalformedEnvelope {
            detail: e.to_string(),
        }
    })?;

    // 2. Schema version supported.
    if !SUPPORTED_CHECKPOINT_SCHEMA_VERSIONS.contains(&envelope.checkpoint_schema_version) {
        return Err(CheckpointRejection::UnsupportedCheckpointSchemaVersion {
            found: envelope.checkpoint_schema_version,
            supported: SUPPORTED_CHECKPOINT_SCHEMA_VERSIONS.to_vec(),
        });
    }

    // 3-5. Signature-count bounds, strict-decode + size bound, and
    // per-signature verification, under this module's own signing domain.
    let verified_envelope = verify_signed_envelope(
        &envelope.payload_b64,
        &envelope.signatures,
        AUDIT_CHECKPOINT_SIGNING_DOMAIN,
        MAX_PAYLOAD_BYTES,
        trusted,
        now,
    )
    .map_err(CheckpointRejection::from)?;
    let payload_bytes = verified_envelope.payload_bytes;
    let verified_by = verified_envelope.verified_by;

    // 6. Parse payload (only now, post-authentication). Parsed first as a
    // `serde_json::Value` so literal key presence can be checked (ADR-0012
    // §3.3) BEFORE the typed parse, which would otherwise silently accept
    // a missing `Option` field as `None` -- see `MissingRequiredKey`'s doc
    // comment.
    let payload_value: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        CheckpointRejection::MalformedPayload {
            detail: e.to_string(),
        }
    })?;
    let top = payload_value
        .as_object()
        .ok_or_else(|| CheckpointRejection::MalformedPayload {
            detail: "payload is not a JSON object".to_string(),
        })?;
    for key in [
        "checkpoint_schema_version",
        "issuer",
        "device_id",
        "checkpoint_seq",
        "issued_at",
        "observed_at",
        "head",
        "device_reported_chain_status",
        "prev_checkpoint",
    ] {
        if !top.contains_key(key) {
            return Err(CheckpointRejection::MissingRequiredKey { key });
        }
    }
    let status_obj = top
        .get("device_reported_chain_status")
        .and_then(|v| v.as_object())
        .ok_or_else(|| CheckpointRejection::MalformedPayload {
            detail: "device_reported_chain_status is not a JSON object".to_string(),
        })?;
    for key in ["status", "first_bad_ledger_seq", "divergence_kind"] {
        if !status_obj.contains_key(key) {
            return Err(CheckpointRejection::MissingRequiredKey { key });
        }
    }

    // Typed parse comes from `payload_bytes` directly, NOT from
    // `payload_value` -- `serde_json::Value`'s `Map::insert` silently keeps
    // only the last occurrence of a repeated key, which would mask a
    // duplicate-field payload that `serde_json::from_slice`'s derived
    // struct visitor correctly rejects (`duplicate field "x"`). The `Value`
    // parse above exists solely for the key-PRESENCE check; it must never
    // become the source of the typed value.
    let payload: AuditCheckpointPayload = serde_json::from_slice(&payload_bytes).map_err(|e| {
        CheckpointRejection::MalformedPayload {
            detail: e.to_string(),
        }
    })?;

    // 7. Schema version cross-check.
    if payload.checkpoint_schema_version != envelope.checkpoint_schema_version {
        return Err(CheckpointRejection::SchemaVersionMismatch {
            envelope: envelope.checkpoint_schema_version,
            payload: payload.checkpoint_schema_version,
        });
    }

    // 8. Parse timestamps.
    parse_rfc3339("issued_at", &payload.issued_at)?;
    parse_rfc3339("observed_at", &payload.observed_at)?;

    // 9. Structural checks.
    if payload.issuer.trim().is_empty() {
        return Err(CheckpointRejection::EmptyIssuer);
    }
    if payload.device_id.trim().is_empty() {
        return Err(CheckpointRejection::EmptyDeviceId);
    }
    if !entry_hash_is_well_formed(&payload.head.entry_hash) {
        return Err(CheckpointRejection::MalformedEntryHash {
            value: payload.head.entry_hash.clone(),
        });
    }
    if payload.head.ledger_seq < 1 {
        return Err(CheckpointRejection::LedgerSeqBelowOne {
            found: payload.head.ledger_seq,
        });
    }
    if payload.checkpoint_seq < 1 {
        return Err(CheckpointRejection::CheckpointSeqBelowOne {
            found: payload.checkpoint_seq,
        });
    }
    if payload.prev_checkpoint.is_none() != (payload.checkpoint_seq == 1) {
        return Err(CheckpointRejection::PrevCheckpointPresenceInconsistent {
            checkpoint_seq: payload.checkpoint_seq,
        });
    }
    match payload.device_reported_chain_status.status.as_str() {
        "valid" => {
            if payload
                .device_reported_chain_status
                .first_bad_ledger_seq
                .is_some()
                || payload
                    .device_reported_chain_status
                    .divergence_kind
                    .is_some()
            {
                return Err(CheckpointRejection::ChainStatusInconsistent);
            }
        }
        "diverged" => {
            if payload
                .device_reported_chain_status
                .first_bad_ledger_seq
                .is_none()
                || payload
                    .device_reported_chain_status
                    .divergence_kind
                    .is_none()
            {
                return Err(CheckpointRejection::ChainStatusInconsistent);
            }
        }
        other => {
            return Err(CheckpointRejection::UnrecognizedChainStatus {
                found: other.to_string(),
            });
        }
    }

    // 10. Construct.
    Ok(VerifiedAuditCheckpoint {
        payload,
        verified_by,
    })
}

/// The exact wire-string mapping for `fornax_store::audit_ledger::DivergenceKind`
/// (ADR-0012 §2.3's normative table). Lives here rather than in
/// `fornax-store` because it names the wire vocabulary of a type this
/// module defines (`DeviceReportedChainStatus::divergence_kind`), even
/// though the enum it maps *from* lives in `fornax-store` --
/// `fornax-store` depends on `fornax-types`, never the reverse, so the
/// caller (the daemon's checkpoint submission path, which depends on both
/// crates) is the one that actually invokes this: it matches on its own
/// `fornax_store::audit_ledger::DivergenceKind` value and passes the
/// already-mapped string in. This function exists purely to pin the
/// literal strings in one normative place with a test, not to take the
/// enum as a parameter (which would require an unwanted crate-graph
/// inversion).
pub mod divergence_kind_wire {
    /// `DivergenceKind::HashMismatch` -> `"hash_mismatch"`.
    pub const HASH_MISMATCH: &str = "hash_mismatch";
    /// `DivergenceKind::MissingSeq` -> `"missing_ledger_seq"` (NOT
    /// `"missing_seq"` -- ADR-0012 §0.1's bare-`seq` rule).
    pub const MISSING_SEQ: &str = "missing_ledger_seq";
    /// `DivergenceKind::TruncatedTail` -> `"truncated_tail"`.
    pub const TRUNCATED_TAIL: &str = "truncated_tail";
    /// `DivergenceKind::RelinkedPrevHash` -> `"relinked_prev_hash"`.
    pub const RELINKED_PREV_HASH: &str = "relinked_prev_hash";
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    use super::super::policy::{SignatureAlgorithm, TrustedKey, TrustedVerificationKeys};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn trust_store(key_id: &str, key: &SigningKey) -> TrustedVerificationKeys {
        TrustedVerificationKeys {
            schema_version: 1,
            keys: vec![TrustedKey {
                key_id: KeyId(key_id.to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_b64: B64.encode(key.verifying_key().to_bytes()),
                not_before: None,
                not_after: None,
                comment: None,
            }],
        }
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        "2026-09-03T12:00:10Z".parse().unwrap()
    }

    fn sample_payload() -> AuditCheckpointPayload {
        AuditCheckpointPayload {
            checkpoint_schema_version: 1,
            issuer: "fornax-cloud:7f3d1c2a-9b4e-4d80-a1f6-2c5e8d0b1234".to_string(),
            device_id: "d41d8cd9-8f00-4204-a980-0998ecf8427e".to_string(),
            checkpoint_seq: 1,
            issued_at: "2026-09-03T12:00:05Z".to_string(),
            observed_at: "2026-09-03T12:00:00Z".to_string(),
            head: LedgerHead {
                ledger_seq: 5,
                entry_hash:
                    "sha256:e967d0e31e6afd2a3a0f5bd805e39f85eb0eeb4e176e88e0e65d3c26a1cba464"
                        .to_string(),
            },
            device_reported_chain_status: DeviceReportedChainStatus {
                status: "valid".to_string(),
                first_bad_ledger_seq: None,
                divergence_kind: None,
            },
            prev_checkpoint: None,
        }
    }

    fn sign_payload(key: &SigningKey, payload_bytes: &[u8]) -> String {
        let mut signed_message = AUDIT_CHECKPOINT_SIGNING_DOMAIN.to_vec();
        signed_message.extend_from_slice(payload_bytes);
        B64.encode(key.sign(&signed_message).to_bytes())
    }

    fn envelope_json(key_id: &str, key: &SigningKey, payload_bytes: &[u8]) -> Vec<u8> {
        let envelope = SignedAuditCheckpoint {
            checkpoint_schema_version: 1,
            payload_b64: B64.encode(payload_bytes),
            signatures: vec![BundleSignature {
                key_id: KeyId(key_id.to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                signature_b64: sign_payload(key, payload_bytes),
            }],
        };
        serde_json::to_vec(&envelope).unwrap()
    }

    // --- §5.1/§5.2: golden vectors, independently verified byte-for-byte ---

    const GOLDEN_PAYLOAD_B64: &str = "eyJjaGVja3BvaW50X3NjaGVtYV92ZXJzaW9uIjoxLCJpc3N1ZXIiOiJmb3JuYXgtY2xvdWQ6N2YzZDFjMmEtOWI0ZS00ZDgwLWExZjYtMmM1ZThkMGIxMjM0IiwiZGV2aWNlX2lkIjoiZDQxZDhjZDktOGYwMC00MjA0LWE5ODAtMDk5OGVjZjg0MjdlIiwiY2hlY2twb2ludF9zZXEiOjEsImlzc3VlZF9hdCI6IjIwMjYtMDktMDNUMTI6MDA6MDVaIiwib2JzZXJ2ZWRfYXQiOiIyMDI2LTA5LTAzVDEyOjAwOjAwWiIsImhlYWQiOnsibGVkZ2VyX3NlcSI6NSwiZW50cnlfaGFzaCI6InNoYTI1NjplOTY3ZDBlMzFlNmFmZDJhM2EwZjViZDgwNWUzOWY4NWViMGVlYjRlMTc2ZTg4ZTBlNjVkM2MyNmExY2JhNDY0In0sImRldmljZV9yZXBvcnRlZF9jaGFpbl9zdGF0dXMiOnsic3RhdHVzIjoidmFsaWQiLCJmaXJzdF9iYWRfbGVkZ2VyX3NlcSI6bnVsbCwiZGl2ZXJnZW5jZV9raW5kIjpudWxsfSwicHJldl9jaGVja3BvaW50IjpudWxsfQ==";
    const GOLDEN_PAYLOAD_SHA256: &str =
        "sha256:77bb07ff65394e758255e34214e50c29500af0b44fc649889adcab1df2bf579c";
    const GOLDEN_DOMAIN_PREFIXED_SHA256: &str =
        "sha256:d378934c57fd4fce5b51224e6a5d8272692274ebf8fc09928b04d3c1e7074625";
    const GOLDEN_PAYLOAD_LEN: usize = 469;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(bytes);
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256:{hex}")
    }

    #[test]
    fn golden_vector_payload_serializes_to_the_exact_adr_0012_bytes_and_base64() {
        let payload = sample_payload();
        let bytes = serde_json::to_vec(&payload).unwrap();
        assert_eq!(bytes.len(), GOLDEN_PAYLOAD_LEN);
        assert_eq!(sha256_hex(&bytes), GOLDEN_PAYLOAD_SHA256);

        let mut domain_prefixed = AUDIT_CHECKPOINT_SIGNING_DOMAIN.to_vec();
        domain_prefixed.extend_from_slice(&bytes);
        assert_eq!(sha256_hex(&domain_prefixed), GOLDEN_DOMAIN_PREFIXED_SHA256);

        let payload_b64 = B64.encode(&bytes);
        assert_eq!(payload_b64, GOLDEN_PAYLOAD_B64);
    }

    #[test]
    fn golden_vector_verifies_end_to_end_through_verify_audit_checkpoint() {
        let key = signing_key(7);
        let trusted = trust_store("k1", &key);
        let payload_bytes = B64.decode(GOLDEN_PAYLOAD_B64).unwrap();
        let envelope_bytes = envelope_json("k1", &key, &payload_bytes);

        let verified = verify_audit_checkpoint(&envelope_bytes, &trusted, now())
            .expect("golden vector must verify");
        assert_eq!(verified.checkpoint_seq(), 1);
        assert_eq!(verified.head().ledger_seq, 5);
        assert_eq!(verified.device_id(), "d41d8cd9-8f00-4204-a980-0998ecf8427e");
    }

    // --- §5.1: domain constant ---

    #[test]
    fn checkpoint_domain_matches_adr_0012_literal_bytes() {
        assert_eq!(
            AUDIT_CHECKPOINT_SIGNING_DOMAIN,
            b"fornax-audit-checkpoint/v1\n"
        );
        assert_eq!(AUDIT_CHECKPOINT_SIGNING_DOMAIN.len(), 27);
        assert_eq!(*AUDIT_CHECKPOINT_SIGNING_DOMAIN.last().unwrap(), b'\n');
        assert_ne!(
            AUDIT_CHECKPOINT_SIGNING_DOMAIN,
            super::super::policy::BUNDLE_SIGNING_DOMAIN
        );
        assert_ne!(
            AUDIT_CHECKPOINT_SIGNING_DOMAIN,
            super::super::policy::REVOCATION_SIGNING_DOMAIN
        );
    }

    /// A payload signed under a DIFFERENT domain (the revocation domain)
    /// but presented as a `SignedAuditCheckpoint` must be rejected.
    #[test]
    fn domain_confusion_with_revocation_domain_is_rejected() {
        let key = signing_key(9);
        let trusted = trust_store("k1", &key);
        let payload = sample_payload();
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        let mut wrong_domain_message = super::super::policy::REVOCATION_SIGNING_DOMAIN.to_vec();
        wrong_domain_message.extend_from_slice(&payload_bytes);
        let signature = key.sign(&wrong_domain_message);

        let envelope = SignedAuditCheckpoint {
            checkpoint_schema_version: 1,
            payload_b64: B64.encode(&payload_bytes),
            signatures: vec![BundleSignature {
                key_id: KeyId("k1".to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                signature_b64: B64.encode(signature.to_bytes()),
            }],
        };
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();

        let err = verify_audit_checkpoint(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(matches!(err, CheckpointRejection::SignatureInvalid { .. }));
    }

    // --- deny_unknown_fields ---

    #[test]
    fn payload_with_unknown_field_is_rejected() {
        let payload = sample_payload();
        let mut value = serde_json::to_value(&payload).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("surprise".to_string(), serde_json::json!(true));
        let err = serde_json::from_value::<AuditCheckpointPayload>(value).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    // --- §2.2 anti-FORNX-312 regression: flat head fields must be rejected ---

    /// Direct struct-level check: a request body with `ledger_seq`/
    /// `entry_hash` flat instead of nested under `head` fails to parse at
    /// all (missing the required `head` key).
    #[test]
    fn flat_head_fields_on_the_request_are_rejected_not_silently_nested() {
        let flat = serde_json::json!({
            "checkpoint_schema_version": 1,
            "checkpoint_seq": 1,
            "observed_at": "2026-09-03T12:00:00Z",
            "ledger_seq": 5,
            "entry_hash": "sha256:e967d0e31e6afd2a3a0f5bd805e39f85eb0eeb4e176e88e0e65d3c26a1cba464",
            "device_reported_chain_status": {
                "status": "valid",
                "first_bad_ledger_seq": null,
                "divergence_kind": null
            }
        });
        let err = serde_json::from_value::<AuditCheckpointRequest>(flat).unwrap_err();
        // `deny_unknown_fields` rejects `ledger_seq`/`entry_hash` sitting at
        // the wrong (flat) level before serde ever gets to notice `head`
        // itself is absent -- either failure mode proves the flat shape is
        // rejected, not silently accepted.
        let msg = err.to_string();
        assert!(
            msg.contains("missing field") || msg.contains("unknown field"),
            "flat ledger_seq/entry_hash must not silently parse: {msg}"
        );
    }

    /// The real FORNX-312 failure mode: a signed, otherwise well-formed
    /// RESPONSE payload with `ledger_seq`/`entry_hash` flat instead of
    /// nested under `head` -- exercised end-to-end through
    /// `verify_audit_checkpoint`, i.e. AFTER the signature has verified,
    /// exactly where the original bug lived (signature-before-semantics
    /// means a structurally wrong payload under a valid signature is
    /// exactly the case that must still be caught).
    #[test]
    fn flat_head_fields_on_the_response_payload_are_rejected_after_signature_verifies() {
        let key = signing_key(21);
        let trusted = trust_store("k1", &key);
        let flat_payload = serde_json::json!({
            "checkpoint_schema_version": 1,
            "issuer": "fornax-cloud:org-1",
            "device_id": "device-1",
            "checkpoint_seq": 1,
            "issued_at": "2026-09-03T12:00:05Z",
            "observed_at": "2026-09-03T12:00:00Z",
            "ledger_seq": 5,
            "entry_hash": "sha256:e967d0e31e6afd2a3a0f5bd805e39f85eb0eeb4e176e88e0e65d3c26a1cba464",
            "device_reported_chain_status": {
                "status": "valid",
                "first_bad_ledger_seq": null,
                "divergence_kind": null
            },
            "prev_checkpoint": null
        });
        let payload_bytes = serde_json::to_vec(&flat_payload).unwrap();
        let envelope_bytes = envelope_json("k1", &key, &payload_bytes);

        let err = verify_audit_checkpoint(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(
            matches!(err, CheckpointRejection::MissingRequiredKey { key: "head" }),
            "a flat, unnested response payload must be rejected as missing the `head` key, got: {err}"
        );
    }

    // --- §3.4 step 9: structural checks ---

    /// §4.1: "Uppercase hex is invalid" -- exercised with a correctly
    /// `sha256:`-prefixed, correctly-64-char value that fails only the hex
    /// case check, distinct from `malformed_entry_hash_is_rejected`'s
    /// wrong-prefix case below.
    #[test]
    fn uppercase_hex_entry_hash_is_rejected() {
        let key = signing_key(22);
        let trusted = trust_store("k1", &key);
        let mut payload = sample_payload();
        payload.head.entry_hash =
            "sha256:E967D0E31E6AFD2A3A0F5BD805E39F85EB0EEB4E176E88E0E65D3C26A1CBA464".to_string();
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let envelope_bytes = envelope_json("k1", &key, &payload_bytes);
        let err = verify_audit_checkpoint(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(matches!(
            err,
            CheckpointRejection::MalformedEntryHash { .. }
        ));
    }

    /// §3.3: a response payload that OMITS the `prev_checkpoint` key
    /// entirely (rather than sending it as explicit `null`) must be
    /// rejected -- serde would otherwise silently default a missing
    /// `Option` field to `None`.
    #[test]
    fn payload_missing_prev_checkpoint_key_entirely_is_rejected() {
        let key = signing_key(23);
        let trusted = trust_store("k1", &key);
        let payload = sample_payload();
        let mut value = serde_json::to_value(&payload).unwrap();
        value.as_object_mut().unwrap().remove("prev_checkpoint");
        let payload_bytes = serde_json::to_vec(&value).unwrap();
        let envelope_bytes = envelope_json("k1", &key, &payload_bytes);
        let err = verify_audit_checkpoint(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(matches!(
            err,
            CheckpointRejection::MissingRequiredKey {
                key: "prev_checkpoint"
            }
        ));
    }

    /// §3.3: same rule for a NESTED optional key --
    /// `device_reported_chain_status.divergence_kind` omitted entirely.
    #[test]
    fn payload_missing_divergence_kind_key_entirely_is_rejected() {
        let key = signing_key(24);
        let trusted = trust_store("k1", &key);
        let payload = sample_payload();
        let mut value = serde_json::to_value(&payload).unwrap();
        value
            .get_mut("device_reported_chain_status")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("divergence_kind");
        let payload_bytes = serde_json::to_vec(&value).unwrap();
        let envelope_bytes = envelope_json("k1", &key, &payload_bytes);
        let err = verify_audit_checkpoint(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(matches!(
            err,
            CheckpointRejection::MissingRequiredKey {
                key: "divergence_kind"
            }
        ));
    }

    /// Regression: the §3.3 key-presence check parses the payload bytes
    /// into a `serde_json::Value` first, whose `Map::insert` would
    /// silently collapse a REPEATED field to its last occurrence if the
    /// typed parse were ever performed from that `Value` rather than from
    /// the original bytes -- masking a duplicate-field payload that
    /// `serde_json`'s derived struct visitor otherwise correctly rejects.
    /// Hand-built JSON text (not `serde_json::json!`, which cannot express
    /// a literal duplicate key) proves the typed parse still runs against
    /// the raw bytes.
    #[test]
    fn duplicate_checkpoint_seq_key_in_raw_bytes_is_still_rejected() {
        let key = signing_key(25);
        let trusted = trust_store("k1", &key);
        let payload_text = r#"{
            "checkpoint_schema_version":1,
            "issuer":"fornax-cloud:org-1",
            "device_id":"device-1",
            "checkpoint_seq":1,
            "checkpoint_seq":99,
            "issued_at":"2026-09-03T12:00:05Z",
            "observed_at":"2026-09-03T12:00:00Z",
            "head":{"ledger_seq":5,"entry_hash":"sha256:e967d0e31e6afd2a3a0f5bd805e39f85eb0eeb4e176e88e0e65d3c26a1cba464"},
            "device_reported_chain_status":{"status":"valid","first_bad_ledger_seq":null,"divergence_kind":null},
            "prev_checkpoint":null
        }"#;
        let payload_bytes = payload_text.as_bytes().to_vec();
        let envelope_bytes = envelope_json("k1", &key, &payload_bytes);
        let err = verify_audit_checkpoint(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(
            matches!(err, CheckpointRejection::MalformedPayload { ref detail } if detail.contains("duplicate field")),
            "a duplicate checkpoint_seq key must still be rejected as a malformed payload, got: {err}"
        );
    }

    #[test]
    fn malformed_entry_hash_is_rejected() {
        let key = signing_key(11);
        let trusted = trust_store("k1", &key);
        let mut payload = sample_payload();
        payload.head.entry_hash = "SHA256:UPPERCASE".to_string();
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let envelope_bytes = envelope_json("k1", &key, &payload_bytes);
        let err = verify_audit_checkpoint(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(matches!(
            err,
            CheckpointRejection::MalformedEntryHash { .. }
        ));
    }

    #[test]
    fn prev_checkpoint_presence_must_match_checkpoint_seq_one() {
        let key = signing_key(12);
        let trusted = trust_store("k1", &key);
        let mut payload = sample_payload();
        payload.checkpoint_seq = 2; // prev_checkpoint still None -> inconsistent
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let envelope_bytes = envelope_json("k1", &key, &payload_bytes);
        let err = verify_audit_checkpoint(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(matches!(
            err,
            CheckpointRejection::PrevCheckpointPresenceInconsistent { checkpoint_seq: 2 }
        ));
    }

    #[test]
    fn diverged_status_without_first_bad_seq_is_rejected() {
        let key = signing_key(13);
        let trusted = trust_store("k1", &key);
        let mut payload = sample_payload();
        payload.device_reported_chain_status.status = "diverged".to_string();
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let envelope_bytes = envelope_json("k1", &key, &payload_bytes);
        let err = verify_audit_checkpoint(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(matches!(err, CheckpointRejection::ChainStatusInconsistent));
    }
}
