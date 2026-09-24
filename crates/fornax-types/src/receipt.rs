//! Signed receipt envelope (FORNX-350, epic FORNX-340 / Stage 8): the
//! signature-verification layer for a `fornax-receipt::IntegrityReceipt`.
//!
//! This module carries only the envelope -- signature-count bounds, strict
//! base64, per-signature verification -- never the typed receipt payload
//! itself. The typed payload lives in the `fornax-receipt` crate (which
//! depends on `fornax-verify` for `UncertaintyBand`/`RecommendationAction`/
//! etc.); this crate has no such dependency, so it can only ever hand back
//! authenticated raw bytes for that crate to parse -- the same
//! verify-then-parse split [`super::policy::bundle`]/[`super::audit_checkpoint`]
//! already use.
//!
//! **Verification-only in this ticket, by explicit owner decision
//! (FORNX-350).** There is no `SigningKey`, no `Signer` import, and no
//! key-generation code anywhere in this module's non-test paths -- the
//! same invariant [`super::policy::bundle`]'s and [`super::audit_checkpoint`]'s
//! own module docs state. Receipts signed by something else may be
//! verified here; Fornax does not sign receipts in production. An unsigned
//! receipt is represented explicitly as unsigned (see
//! `fornax_receipt::verify::SignatureStatus::Unsigned`) -- never silently
//! treated as invalid, and never silently treated as authenticated. If
//! production signing is wanted later, it needs its own ticket scoping key
//! ownership, provisioning, storage, rotation, revocation, and compromise
//! recovery -- none of that is decided or built here.
//!
//! **Domain separation.** The signed message is
//! [`RECEIPT_SIGNING_DOMAIN`] concatenated with the raw decoded payload
//! bytes -- never the payload alone. See
//! [`super::policy::BUNDLE_SIGNING_DOMAIN`] for the identical discipline
//! this mirrors.

use serde::{Deserialize, Serialize};

use super::policy::{verify_signed_envelope, BundleSignature, KeyId, MAX_PAYLOAD_BYTES};

pub const RECEIPT_SCHEMA_VERSION: u32 = 1;
pub const SUPPORTED_RECEIPT_SCHEMA_VERSIONS: &[u32] = &[1];

/// 28 bytes, LF-terminated -- this crate's own signing domain, distinct
/// from [`super::policy::bundle::BUNDLE_SIGNING_DOMAIN`]/
/// [`super::audit_checkpoint::AUDIT_CHECKPOINT_SIGNING_DOMAIN`], so a
/// signature over one artifact type can never be replayed as valid over
/// another.
pub const RECEIPT_SIGNING_DOMAIN: &[u8] = b"fornax-integrity-receipt/v1\n";

/// Wire/envelope form. Structurally identical to
/// [`super::policy::SignedPolicyBundle`]/
/// [`super::audit_checkpoint::SignedAuditCheckpoint`] with only the version
/// field renamed -- reuses [`BundleSignature`] verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIntegrityReceipt {
    pub receipt_schema_version: u32,
    pub payload_b64: String,
    pub signatures: Vec<BundleSignature>,
}

/// Authenticated payload bytes plus which trusted key authenticated them.
/// Private fields, accessors only -- [`verify_receipt_envelope`] is the
/// sole constructor. The payload is intentionally still raw bytes here;
/// `fornax-receipt` parses it into a typed `ReceiptBody` only after
/// authentication succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedReceiptEnvelope {
    payload_bytes: Vec<u8>,
    verified_by: KeyId,
}

impl AuthenticatedReceiptEnvelope {
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }

    pub fn verified_by(&self) -> &KeyId {
        &self.verified_by
    }
}

/// Exhaustive envelope-layer rejection vocabulary for
/// [`verify_receipt_envelope`]. 1:1 map of
/// [`super::policy::EnvelopeVerificationError`] plus this module's own
/// schema-version check -- mirrors [`super::audit_checkpoint::CheckpointRejection`]'s
/// discipline of never reusing another artifact's rejection enum, so this
/// type can never end up claiming a check (e.g. a payload-level expiry
/// window, which lives in `fornax-receipt::freshness`) that this
/// envelope-layer function never performs.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReceiptEnvelopeRejection {
    #[error("envelope is malformed: {detail}")]
    MalformedEnvelope { detail: String },
    #[error("receipt_schema_version {found} is not supported (supported: {supported:?})")]
    UnsupportedReceiptSchemaVersion { found: u32, supported: Vec<u32> },
    #[error("payload_b64 is not valid strict-canonical base64: {detail}")]
    MalformedPayloadEncoding { detail: String },
    #[error("payload is {found} bytes, exceeding the {max}-byte limit")]
    PayloadTooLarge { found: usize, max: usize },
    #[error("receipt carries no signatures")]
    NoSignatures,
    #[error("receipt carries {found} signatures, exceeding the {max} limit")]
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
    MalformedKeyTimestamp { field: &'static str, value: String },
}

impl From<super::policy::EnvelopeVerificationError> for ReceiptEnvelopeRejection {
    fn from(e: super::policy::EnvelopeVerificationError) -> Self {
        use super::policy::EnvelopeVerificationError as E;
        match e {
            E::MalformedPayloadEncoding { detail } => {
                ReceiptEnvelopeRejection::MalformedPayloadEncoding { detail }
            }
            E::PayloadTooLarge { found, max } => {
                ReceiptEnvelopeRejection::PayloadTooLarge { found, max }
            }
            E::NoSignatures => ReceiptEnvelopeRejection::NoSignatures,
            E::TooManySignatures { found, max } => {
                ReceiptEnvelopeRejection::TooManySignatures { found, max }
            }
            E::UnknownKeyId { offered } => ReceiptEnvelopeRejection::UnknownKeyId { offered },
            E::UnsupportedAlgorithm { key_id, algorithm } => {
                ReceiptEnvelopeRejection::UnsupportedAlgorithm { key_id, algorithm }
            }
            E::MalformedSignature { key_id } => {
                ReceiptEnvelopeRejection::MalformedSignature { key_id }
            }
            E::KeyNotYetValid {
                key_id,
                not_before,
                now,
            } => ReceiptEnvelopeRejection::KeyNotYetValid {
                key_id,
                not_before,
                now,
            },
            E::KeyRetired {
                key_id,
                not_after,
                now,
            } => ReceiptEnvelopeRejection::KeyRetired {
                key_id,
                not_after,
                now,
            },
            E::SignatureInvalid { key_ids } => {
                ReceiptEnvelopeRejection::SignatureInvalid { key_ids }
            }
            E::MalformedKeyTimestamp { field, value } => {
                ReceiptEnvelopeRejection::MalformedKeyTimestamp { field, value }
            }
        }
    }
}

/// Verifies a [`SignedIntegrityReceipt`] envelope: parses it, checks
/// `receipt_schema_version` is supported, then delegates signature-count
/// bounds / strict base64 / per-signature verification to
/// [`verify_signed_envelope`] under [`RECEIPT_SIGNING_DOMAIN`]. Returns the
/// authenticated payload bytes, unparsed -- `fornax-receipt` parses them
/// into a typed `ReceiptBody` only after this call succeeds. Performs no
/// freshness/expiry check; that is a payload-semantics concern owned by
/// `fornax-receipt::freshness`, exactly as `verify_audit_checkpoint`
/// performs no window check (ADR-0012 §1.1) even though `verify_bundle`
/// (a different artifact) does.
pub fn verify_receipt_envelope(
    envelope_bytes: &[u8],
    trusted: &super::policy::TrustedVerificationKeys,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AuthenticatedReceiptEnvelope, ReceiptEnvelopeRejection> {
    let envelope: SignedIntegrityReceipt = serde_json::from_slice(envelope_bytes).map_err(|e| {
        ReceiptEnvelopeRejection::MalformedEnvelope {
            detail: e.to_string(),
        }
    })?;

    if !SUPPORTED_RECEIPT_SCHEMA_VERSIONS.contains(&envelope.receipt_schema_version) {
        return Err(ReceiptEnvelopeRejection::UnsupportedReceiptSchemaVersion {
            found: envelope.receipt_schema_version,
            supported: SUPPORTED_RECEIPT_SCHEMA_VERSIONS.to_vec(),
        });
    }

    let verified_envelope = verify_signed_envelope(
        &envelope.payload_b64,
        &envelope.signatures,
        RECEIPT_SIGNING_DOMAIN,
        MAX_PAYLOAD_BYTES,
        trusted,
        now,
    )
    .map_err(ReceiptEnvelopeRejection::from)?;

    Ok(AuthenticatedReceiptEnvelope {
        payload_bytes: verified_envelope.payload_bytes,
        verified_by: verified_envelope.verified_by,
    })
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
        "2026-09-10T12:00:00Z".parse().unwrap()
    }

    fn sign_envelope(payload: &[u8], key_id: &str, key: &SigningKey) -> Vec<u8> {
        let payload_b64 = B64.encode(payload);
        let mut signed_message = RECEIPT_SIGNING_DOMAIN.to_vec();
        signed_message.extend_from_slice(payload);
        let signature = key.sign(&signed_message);
        let envelope = SignedIntegrityReceipt {
            receipt_schema_version: RECEIPT_SCHEMA_VERSION,
            payload_b64,
            signatures: vec![BundleSignature {
                key_id: KeyId(key_id.to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                signature_b64: B64.encode(signature.to_bytes()),
            }],
        };
        serde_json::to_vec(&envelope).unwrap()
    }

    #[test]
    fn a_correctly_signed_envelope_verifies_and_returns_the_raw_payload() {
        let key = signing_key(1);
        let trusted = trust_store("k1", &key);
        let payload = br#"{"hello":"world"}"#;
        let envelope_bytes = sign_envelope(payload, "k1", &key);

        let authenticated = verify_receipt_envelope(&envelope_bytes, &trusted, now()).unwrap();
        assert_eq!(authenticated.payload_bytes(), payload);
        assert_eq!(authenticated.verified_by(), &KeyId("k1".to_string()));
    }

    #[test]
    fn a_tampered_payload_is_rejected_as_signature_invalid() {
        let key = signing_key(1);
        let trusted = trust_store("k1", &key);
        let envelope_bytes = sign_envelope(br#"{"a":1}"#, "k1", &key);

        // Flip the payload after signing, keeping the original signature.
        let mut envelope: SignedIntegrityReceipt = serde_json::from_slice(&envelope_bytes).unwrap();
        envelope.payload_b64 = B64.encode(br#"{"a":2}"#);
        let tampered = serde_json::to_vec(&envelope).unwrap();

        let err = verify_receipt_envelope(&tampered, &trusted, now()).unwrap_err();
        assert!(matches!(
            err,
            ReceiptEnvelopeRejection::SignatureInvalid { .. }
        ));
    }

    #[test]
    fn a_signature_from_an_untrusted_key_is_rejected() {
        let signer = signing_key(1);
        let other = signing_key(2);
        let trusted = trust_store("k1", &other); // trust store has a different key
        let envelope_bytes = sign_envelope(br#"{"a":1}"#, "k1", &signer);

        let err = verify_receipt_envelope(&envelope_bytes, &trusted, now()).unwrap_err();
        assert!(matches!(
            err,
            ReceiptEnvelopeRejection::SignatureInvalid { .. }
        ));
    }

    #[test]
    fn an_unsupported_schema_version_is_rejected_before_signature_verification() {
        let key = signing_key(1);
        let trusted = trust_store("k1", &key);
        let mut envelope: SignedIntegrityReceipt =
            serde_json::from_slice(&sign_envelope(br#"{}"#, "k1", &key)).unwrap();
        envelope.receipt_schema_version = 99;
        let bytes = serde_json::to_vec(&envelope).unwrap();

        let err = verify_receipt_envelope(&bytes, &trusted, now()).unwrap_err();
        assert!(matches!(
            err,
            ReceiptEnvelopeRejection::UnsupportedReceiptSchemaVersion { found: 99, .. }
        ));
    }

    #[test]
    fn no_signatures_is_rejected() {
        let key = signing_key(1);
        let trusted = trust_store("k1", &key);
        let envelope = SignedIntegrityReceipt {
            receipt_schema_version: RECEIPT_SCHEMA_VERSION,
            payload_b64: B64.encode(b"{}"),
            signatures: vec![],
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();

        let err = verify_receipt_envelope(&bytes, &trusted, now()).unwrap_err();
        assert!(matches!(err, ReceiptEnvelopeRejection::NoSignatures));
    }

    #[test]
    fn receipt_signing_domain_is_distinct_from_other_artifact_domains() {
        assert_ne!(
            RECEIPT_SIGNING_DOMAIN,
            super::super::policy::BUNDLE_SIGNING_DOMAIN
        );
        assert_ne!(
            RECEIPT_SIGNING_DOMAIN,
            super::super::audit_checkpoint::AUDIT_CHECKPOINT_SIGNING_DOMAIN
        );
    }
}
