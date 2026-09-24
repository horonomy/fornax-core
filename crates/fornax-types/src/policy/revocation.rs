//! Signed policy revocation lists (FORNX-123, epic FORNX-69).
//!
//! **A new, separately-signed artifact type**, not a field bolted onto
//! [`super::bundle::SignedPolicyBundle`]. It reuses the envelope/signature
//! machinery [`super::bundle::verify_signed_envelope`] extracted from
//! `verify_bundle`, but under its OWN signing domain
//! ([`REVOCATION_SIGNING_DOMAIN`]) — a revocation list signed with the
//! bundle's domain (or vice versa) must be rejected; see this module's
//! domain-separation tests.
//!
//! **Enforced at the cache layer, never here.** [`verify_revocation_list`]
//! only authenticates and structurally validates a revocation list. It
//! never consults [`super::cache::PolicyCacheState`] and never decides
//! whether any digest is actually revoked — that is
//! [`super::cache::RevocationSet::hit`] and the check inserted at the top of
//! [`super::cache::evaluate_activation`]. A revoked bundle's own signature
//! is still perfectly valid; no signature-layer check can ever catch it,
//! which is exactly why revocation cannot live in `verify_bundle`.
//!
//! **Sticky, union-only, no expiry.** Once a digest is revoked locally, it
//! stays revoked: a newer revocation list that omits a previously-seen
//! entry never un-revokes it (see
//! [`super::cache::evaluate_revocation_ingest`]), and revocation entries
//! carry no `expires_at`/`not_before` of their own — an expiring revocation
//! would let a bad artifact resurrect itself once the clock passed a
//! date the *attacker* (or a merely misconfigured issuer) controls the
//! shape of. See `docs/adr/0009-policy-revocation-and-emergency-control.md`.

use serde::{Deserialize, Serialize};

use super::bundle::{
    verify_signed_envelope, BundleSignature, KeyId, PayloadDigest, MAX_PAYLOAD_BYTES,
};
use super::revision::RevisionDigest;

pub const REVOCATION_SCHEMA_VERSION: u32 = 1;
pub const SUPPORTED_REVOCATION_SCHEMA_VERSIONS: &[u32] = &[1];
pub const REVOCATION_SIGNING_DOMAIN: &[u8] = b"fornax-policy-revocation/v1\n";
pub const MAX_REVOCATION_ENTRIES: usize = 4096;

/// Wire/envelope form. Deliberately minimal, mirroring
/// [`super::bundle::SignedPolicyBundle`] — no nested types, nothing read
/// before a signature has been checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRevocationList {
    pub revocation_schema_version: u32,
    pub payload_b64: String,
    pub signatures: Vec<BundleSignature>,
}

/// What one [`RevocationEntry`] names as revoked. Internally tagged on
/// `target_kind` with `#[serde(other)]` as the forward-compat tail: one
/// unrecognized entry kind must never make the whole list unparseable — an
/// unrecognized entry is counted
/// ([`super::cache::RevocationSet::unrecognized_entry_count`]), produces a
/// [`super::diagnostics::DiagnosticCode::PolicyRevocationEntryNotUnderstood`]
/// warning, and is un-actionable but never fatal to parsing the rest of the
/// list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target_kind", rename_all = "snake_case")]
pub enum RevocationTarget {
    RevisionDigest {
        digest: RevisionDigest,
    },
    PayloadDigest {
        digest: PayloadDigest,
    },
    #[serde(other)]
    Unrecognized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    pub target: RevocationTarget,
    /// RFC3339.
    pub revoked_at: String,
    /// Non-empty, enforced by [`verify_revocation_list`].
    pub reason: String,
    pub audit_ref: Option<String>,
    pub superseded_by: Option<RevisionDigest>,
}

/// The authenticated content of a revocation list, parsed only *after*
/// signature verification succeeds. `entries` is always the COMPLETE
/// current set for this `(issuer, sequence)`, never a delta — see
/// [`super::cache::evaluate_revocation_ingest`]'s set-difference logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationPayload {
    pub revocation_schema_version: u32,
    pub issuer: String,
    /// Per-issuer, monotonically increasing. **Disjoint** from
    /// `policy_sequence_high_water`'s `(issuer, policy_id)`-keyed counter —
    /// a revocation list has no `policy_id` at all, it names digests
    /// directly, so conflating the two counters would be a category error,
    /// not just a naming collision.
    pub sequence: u64,
    pub issued_at: String,
    pub entries: Vec<RevocationEntry>,
}

/// Verified, authenticated revocation list. Private fields, accessors
/// only — [`verify_revocation_list`] is the sole constructor, mirroring
/// [`super::bundle::VerifiedPolicyBundle`]'s discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRevocationList {
    payload: RevocationPayload,
    verified_by: KeyId,
    payload_digest: PayloadDigest,
}

impl VerifiedRevocationList {
    pub fn issuer(&self) -> &str {
        &self.payload.issuer
    }

    pub fn sequence(&self) -> u64 {
        self.payload.sequence
    }

    pub fn entries(&self) -> &[RevocationEntry] {
        &self.payload.entries
    }

    pub fn verified_by(&self) -> &KeyId {
        &self.verified_by
    }

    pub fn payload_digest(&self) -> &PayloadDigest {
        &self.payload_digest
    }
}

fn digest_payload_bytes(bytes: &[u8]) -> PayloadDigest {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(bytes);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    // `PayloadDigest`'s constructor is private to `bundle.rs`; round-trip
    // through the same "sha256:<hex>" wire shape via serde rather than
    // widening its visibility for one helper.
    serde_json::from_value(serde_json::Value::String(format!("sha256:{hex}")))
        .expect("PayloadDigest deserializes from its own wire shape")
}

/// Exhaustive rejection vocabulary for [`verify_revocation_list`]. Not a
/// re-use of [`super::bundle::BundleRejection`]'s shape — that enum has
/// variants (e.g. an expiry window) this function never checks, and
/// claiming them here would misrepresent what was actually verified.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RevocationRejection {
    #[error("envelope is malformed: {detail}")]
    MalformedEnvelope { detail: String },
    #[error("revocation_schema_version {found} is not supported (supported: {supported:?})")]
    UnsupportedRevocationSchemaVersion { found: u32, supported: Vec<u32> },
    #[error("envelope revocation_schema_version {envelope} does not match payload's {payload}")]
    SchemaVersionMismatch { envelope: u32, payload: u32 },
    #[error("payload_b64 is not valid strict-canonical base64: {detail}")]
    MalformedPayloadEncoding { detail: String },
    #[error("payload is {found} bytes, exceeding the {max}-byte limit")]
    PayloadTooLarge { found: usize, max: usize },
    #[error("revocation list carries no signatures")]
    NoSignatures,
    #[error("revocation list carries {found} signatures, exceeding the {max} limit")]
    TooManySignatures { found: usize, max: usize },
    #[error("no signature names a key_id present in the trust store: offered {offered:?}")]
    UnknownKeyId { offered: Vec<KeyId> },
    #[error("key {key_id:?} uses unsupported algorithm {algorithm:?}")]
    UnsupportedAlgorithm {
        key_id: KeyId,
        algorithm: super::bundle::SignatureAlgorithm,
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
    #[error("entries[{index}].revoked_at has a malformed timestamp: {value:?}")]
    EntryTimestampMalformed { index: usize, value: String },
    #[error("payload is malformed: {detail}")]
    MalformedPayload { detail: String },
    #[error("revocation list carries {found} entries, exceeding the {max} limit")]
    TooManyEntries { found: usize, max: usize },
    #[error("entry {index} has an empty reason")]
    EmptyReason { index: usize },
    #[error("issuer must not be empty")]
    EmptyIssuer,
}

impl From<super::bundle::EnvelopeVerificationError> for RevocationRejection {
    fn from(e: super::bundle::EnvelopeVerificationError) -> Self {
        use super::bundle::EnvelopeVerificationError as E;
        match e {
            E::MalformedPayloadEncoding { detail } => {
                RevocationRejection::MalformedPayloadEncoding { detail }
            }
            E::PayloadTooLarge { found, max } => {
                RevocationRejection::PayloadTooLarge { found, max }
            }
            E::NoSignatures => RevocationRejection::NoSignatures,
            E::TooManySignatures { found, max } => {
                RevocationRejection::TooManySignatures { found, max }
            }
            E::UnknownKeyId { offered } => RevocationRejection::UnknownKeyId { offered },
            E::UnsupportedAlgorithm { key_id, algorithm } => {
                RevocationRejection::UnsupportedAlgorithm { key_id, algorithm }
            }
            E::MalformedSignature { key_id } => RevocationRejection::MalformedSignature { key_id },
            E::KeyNotYetValid {
                key_id,
                not_before,
                now,
            } => RevocationRejection::KeyNotYetValid {
                key_id,
                not_before,
                now,
            },
            E::KeyRetired {
                key_id,
                not_after,
                now,
            } => RevocationRejection::KeyRetired {
                key_id,
                not_after,
                now,
            },
            E::SignatureInvalid { key_ids } => RevocationRejection::SignatureInvalid { key_ids },
            E::MalformedKeyTimestamp { field, value } => {
                RevocationRejection::MalformedTimestamp { field, value }
            }
        }
    }
}

/// Evaluation order (normative — signature-before-semantics, mirroring
/// `verify_bundle`'s own discipline):
///
/// 1. Parse envelope.
/// 2. `revocation_schema_version` supported.
/// 3. `1..=MAX_SIGNATURES` signatures.
/// 4. Strict-decode `payload_b64`, bound by [`MAX_PAYLOAD_BYTES`] (the same
///    constant `verify_bundle` uses).
/// 5. Signature verification over `REVOCATION_SIGNING_DOMAIN ‖
///    payload_bytes` via [`super::bundle::verify_signed_envelope`] — the
///    exact same helper `verify_bundle` calls, parameterized by this
///    module's own domain constant.
/// 6. Parse [`RevocationPayload`] (post-authentication only).
/// 7. Cross-check envelope/payload `revocation_schema_version` match.
/// 8. Parse `issued_at`; parse each entry's `revoked_at`.
/// 9. `entries.len() <= MAX_REVOCATION_ENTRIES`; every entry's `reason`
///    non-empty; `issuer` non-empty.
/// 10. Construct [`VerifiedRevocationList`].
///
/// **No window check** — no `not_before`/`expires_at` check anywhere in
/// this function. This is deliberate, not an oversight: see the module
/// docs' "Sticky, union-only, no expiry" section.
pub fn verify_revocation_list(
    envelope_bytes: &[u8],
    trusted: &super::bundle::TrustedVerificationKeys,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<VerifiedRevocationList, RevocationRejection> {
    // 1. Parse envelope.
    let envelope: SignedRevocationList = serde_json::from_slice(envelope_bytes).map_err(|e| {
        RevocationRejection::MalformedEnvelope {
            detail: e.to_string(),
        }
    })?;

    // 2. Schema version supported.
    if !SUPPORTED_REVOCATION_SCHEMA_VERSIONS.contains(&envelope.revocation_schema_version) {
        return Err(RevocationRejection::UnsupportedRevocationSchemaVersion {
            found: envelope.revocation_schema_version,
            supported: SUPPORTED_REVOCATION_SCHEMA_VERSIONS.to_vec(),
        });
    }

    // 3-5. Signature-count bounds, strict-decode + size bound, and
    // per-signature verification -- delegated to the shared helper, under
    // THIS module's own signing domain.
    let verified_envelope = verify_signed_envelope(
        &envelope.payload_b64,
        &envelope.signatures,
        REVOCATION_SIGNING_DOMAIN,
        MAX_PAYLOAD_BYTES,
        trusted,
        now,
    )
    .map_err(RevocationRejection::from)?;
    let payload_bytes = verified_envelope.payload_bytes;
    let verified_by = verified_envelope.verified_by;

    // 6. Parse payload (only now, post-authentication).
    let payload: RevocationPayload = serde_json::from_slice(&payload_bytes).map_err(|e| {
        RevocationRejection::MalformedPayload {
            detail: e.to_string(),
        }
    })?;

    // 7. Schema version cross-check.
    if payload.revocation_schema_version != envelope.revocation_schema_version {
        return Err(RevocationRejection::SchemaVersionMismatch {
            envelope: envelope.revocation_schema_version,
            payload: payload.revocation_schema_version,
        });
    }

    // 8. Parse timestamps.
    parse_rfc3339("issued_at", &payload.issued_at)?;
    for (index, entry) in payload.entries.iter().enumerate() {
        if chrono::DateTime::parse_from_rfc3339(&entry.revoked_at).is_err() {
            return Err(RevocationRejection::EntryTimestampMalformed {
                index,
                value: entry.revoked_at.clone(),
            });
        }
    }

    // 9. Structural bounds.
    if payload.entries.len() > MAX_REVOCATION_ENTRIES {
        return Err(RevocationRejection::TooManyEntries {
            found: payload.entries.len(),
            max: MAX_REVOCATION_ENTRIES,
        });
    }
    for (index, entry) in payload.entries.iter().enumerate() {
        if entry.reason.trim().is_empty() {
            return Err(RevocationRejection::EmptyReason { index });
        }
    }
    if payload.issuer.trim().is_empty() {
        return Err(RevocationRejection::EmptyIssuer);
    }

    // 10. Construct.
    let payload_digest = digest_payload_bytes(&payload_bytes);
    Ok(VerifiedRevocationList {
        payload,
        verified_by,
        payload_digest,
    })
}

fn parse_rfc3339(field: &'static str, value: &str) -> Result<(), RevocationRejection> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| RevocationRejection::MalformedTimestamp {
            field,
            value: value.to_string(),
        })
}
