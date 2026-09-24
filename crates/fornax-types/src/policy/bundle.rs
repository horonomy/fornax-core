//! Signed policy bundles (FORNX-118, epic FORNX-69).
//!
//! **Trust boundary.** `fornax-core` (this crate, and every crate that
//! depends on it) only ever *verifies* a bundle produced elsewhere
//! (`fornax-cloud`, out of scope here). There is no `SigningKey`, no
//! `Signer` import, and no key-generation code anywhere in this module's
//! non-test paths — [`verify_bundle`] is a read-only operation over
//! untrusted bytes. See the module-level "Deviation" note below on exactly
//! how far `ed25519-dalek` itself enforces that boundary at the dependency
//! level, and how far it does not.
//!
//! **Sign the transmitted bytes verbatim.** [`SignedPolicyBundle::payload_b64`]
//! is the exact base64 the signature covers. `verify_bundle` never
//! re-serializes a parsed [`BundlePayload`] to reconstruct the signed
//! bytes — Python (`fornax-cloud`) is the producer, Rust is only ever the
//! verifier; re-serializing risks a `json.dumps`-vs-`serde_json` byte
//! divergence that would silently break verification (or worse, silently
//! accept a payload the signer never actually signed).
//!
//! **Domain separation.** The signed message is
//! [`BUNDLE_SIGNING_DOMAIN`] concatenated with the raw decoded payload
//! bytes — never the payload alone. See `docs/adr/0007-signed-policy-bundles.md`.
//!
//! **Verify-then-parse.** The envelope ([`SignedPolicyBundle`]) is
//! intentionally minimal — no nested types, no timestamps read before a
//! signature has been checked. [`MAX_PAYLOAD_BYTES`]/[`MAX_SIGNATURES`]
//! bound the pre-authentication work an attacker can force onto this path.
//!
//! **Fail-closed trust, unlike ADR-0006's fail-open selectors.** An
//! unrecognized [`SignatureAlgorithm`] is *always* a rejection here. This
//! is a deliberate inversion of `docs/adr/0006-policy-as-data.md`'s
//! "an unrecognized selector value still matches" rule: policy
//! *application* fails open (an admin policy you can't fully parse should
//! still apply, rather than silently vanish); a trust decision fails
//! closed (an algorithm this binary doesn't recognize must never be
//! treated as an accepted signature).

use std::collections::BTreeMap;

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::diagnostics::PolicyValidationReport;
use super::revision::PublishedPolicyRevision;
use super::target::{BoundRevision, PolicyBinding};

pub const BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const SUPPORTED_BUNDLE_SCHEMA_VERSIONS: &[u32] = &[1];
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_SIGNATURES: usize = 8;
pub const BUNDLE_SIGNING_DOMAIN: &[u8] = b"fornax-policy-bundle/v1\n";
pub const CLOCK_SKEW_TOLERANCE_SECONDS: i64 = 300;

/// Strict canonical base64: standard alphabet, required padding, no
/// trailing bits. Used for both the envelope's `payload_b64` and each
/// [`TrustedKey::public_key_b64`]/[`BundleSignature::signature_b64`] — an
/// attacker-controlled payload must decode exactly one way or be rejected,
/// never be interpreted leniently.
fn strict_base64() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
            .with_decode_allow_trailing_bits(false),
    )
}

/// Newtype over a trust-store key identifier. Distinct from any digest or
/// revision id — a `KeyId` names a verification key, never signed content.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

/// Closed for anything this binary can act on, but never rejects unknown
/// wire values at parse time — `Unrecognized` carries them forward so
/// [`verify_bundle`] can reject with the specific
/// [`BundleRejection::UnsupportedAlgorithm`] variant instead of a generic
/// parse failure. This is the trust-fails-closed inversion of ADR-0006's
/// selector rule: the *value* is accepted structurally so a precise
/// rejection can be produced, but it can never be treated as a match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
    #[serde(untagged)]
    Unrecognized(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    pub key_id: KeyId,
    pub algorithm: SignatureAlgorithm,
    pub signature_b64: String,
}

/// Wire/envelope form. Deliberately minimal and a plain `Deserialize` —
/// this type asserts nothing about its own validity. All authentication
/// and semantic checks happen in [`verify_bundle`], never here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyBundle {
    pub bundle_schema_version: u32,
    pub payload_b64: String,
    pub signatures: Vec<BundleSignature>,
}

/// `"sha256:<hex>"` over the exact signed payload bytes. Distinct from
/// [`super::revision::RevisionDigest`]: this digests opaque transmitted
/// bytes, not a typed, re-serializable body.
///
/// `PartialOrd`/`Ord` added in FORNX-123 so this can key a `BTreeSet`/
/// `BTreeMap` in [`super::cache::RevocationSet`] — ordering is over the
/// opaque `"sha256:<hex>"` string, never interpreted, just a total order for
/// the collection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PayloadDigest(String);

impl PayloadDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PayloadDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn digest_payload_bytes(bytes: &[u8]) -> PayloadDigest {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(bytes);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    PayloadDigest(format!("sha256:{hex}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleProvenance {
    pub issuer: String,
    pub audit_ref: Option<String>,
    pub authorized_by: Option<String>,
}

/// The authenticated content of a bundle, parsed only *after* signature
/// verification succeeds (see [`verify_bundle`]'s evaluation order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundlePayload {
    pub bundle_schema_version: u32,
    pub bundle_id: Uuid,
    /// Strictly increasing per issuer. **Not checked by [`verify_bundle`]** —
    /// rejecting a stale-but-validly-signed `sequence` requires a
    /// last-known-good comparison point that only a future
    /// activation/cache ticket (FORNX-119) has. See
    /// `docs/adr/0007-signed-policy-bundles.md`'s residual-risks section.
    pub sequence: u64,
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    pub provenance: BundleProvenance,
    pub revision: PublishedPolicyRevision,
    pub bindings: Vec<PolicyBinding>,
}

/// Verified, authenticated policy bundle. Private fields, accessors only —
/// [`verify_bundle`] is the sole constructor, mirroring
/// [`PublishedPolicyRevision`]'s discipline: this type cannot be conjured
/// from untrusted input via `Deserialize`, because it has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPolicyBundle {
    payload: BundlePayload,
    verified_by: KeyId,
    payload_digest: PayloadDigest,
}

impl VerifiedPolicyBundle {
    pub fn payload(&self) -> &BundlePayload {
        &self.payload
    }

    pub fn revision(&self) -> &PublishedPolicyRevision {
        &self.payload.revision
    }

    pub fn bindings(&self) -> &[PolicyBinding] {
        &self.payload.bindings
    }

    pub fn verified_by(&self) -> &KeyId {
        &self.verified_by
    }

    pub fn payload_digest(&self) -> &PayloadDigest {
        &self.payload_digest
    }

    /// Joins every binding in this bundle with its (already digest-matched)
    /// revision via [`BoundRevision::new`]. The digest match is guaranteed
    /// by [`verify_bundle`]'s step 10 before this type can exist, so that
    /// specific failure mode of `BoundRevision::new` can never trigger
    /// here — but `BoundRevision::new` also rejects a pin declared at
    /// `TargetLevel::LocalUser` (`PinAtLocalUserLayer`), which
    /// `verify_bundle` never checks, so this can genuinely return `Err` for
    /// that reason. `BoundRevision::new` is the sole authority on both
    /// invariants; nothing here duplicates or re-derives them.
    pub fn into_bound_revisions(self) -> Result<Vec<BoundRevision>, PolicyValidationReport> {
        let revision = self.payload.revision;
        self.payload
            .bindings
            .into_iter()
            .map(|binding| BoundRevision::new(binding, revision.clone()))
            .collect()
    }
}

/// One entry in a [`TrustedVerificationKeys`] store. Trust roots are static
/// configuration (compiled-in default, operator file, env override) — this
/// type is never fetched from a network by anything in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub key_id: KeyId,
    pub algorithm: SignatureAlgorithm,
    /// 32 raw Ed25519 public-key bytes, strict canonical base64.
    pub public_key_b64: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedVerificationKeys {
    pub schema_version: u32,
    pub keys: Vec<TrustedKey>,
}

impl TrustedVerificationKeys {
    /// Rejects duplicate `key_id`s (with differing material) and malformed
    /// key bytes up front, rather than deferring either failure into
    /// [`verify_bundle`]'s per-signature loop.
    pub fn load(raw: &str) -> Result<Self, TrustStoreError> {
        let parsed: TrustedVerificationKeys =
            serde_json::from_str(raw).map_err(|e| TrustStoreError::Malformed {
                detail: e.to_string(),
            })?;

        if parsed.keys.is_empty() {
            return Err(TrustStoreError::Empty);
        }

        let mut seen: BTreeMap<&KeyId, &TrustedKey> = BTreeMap::new();
        for key in &parsed.keys {
            if let Some(existing) = seen.get(&key.key_id) {
                if *existing != key {
                    return Err(TrustStoreError::DuplicateKeyId {
                        key_id: key.key_id.clone(),
                    });
                }
            } else {
                seen.insert(&key.key_id, key);
            }

            decode_verifying_key(key).map_err(|_| TrustStoreError::MalformedKey {
                key_id: key.key_id.clone(),
            })?;

            for (label, value) in [
                ("not_before", &key.not_before),
                ("not_after", &key.not_after),
            ] {
                if let Some(v) = value {
                    if DateTime::parse_from_rfc3339(v).is_err() {
                        return Err(TrustStoreError::Malformed {
                            detail: format!(
                                "key_id {:?} has a malformed {label} timestamp: {v:?}",
                                key.key_id
                            ),
                        });
                    }
                }
            }
        }

        Ok(parsed)
    }

    pub fn get(&self, key_id: &KeyId) -> Option<&TrustedKey> {
        self.keys.iter().find(|k| &k.key_id == key_id)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum TrustStoreError {
    #[error("trust store is malformed: {detail}")]
    Malformed { detail: String },
    #[error("key_id {key_id:?} appears more than once with differing key material")]
    DuplicateKeyId { key_id: KeyId },
    #[error("key_id {key_id:?} has malformed key bytes")]
    MalformedKey { key_id: KeyId },
    #[error("trust store contains no keys")]
    Empty,
}

/// Exhaustive rejection vocabulary for [`verify_bundle`]. Every variant
/// names exactly one failure mode in the evaluation order documented on
/// [`verify_bundle`] itself.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BundleRejection {
    #[error("envelope is malformed: {detail}")]
    MalformedEnvelope { detail: String },
    #[error("bundle_schema_version {found} is not supported (supported: {supported:?})")]
    UnsupportedBundleSchemaVersion { found: u32, supported: Vec<u32> },
    #[error("envelope bundle_schema_version {envelope} does not match payload's {payload}")]
    SchemaVersionMismatch { envelope: u32, payload: u32 },
    #[error("payload_b64 is not valid strict-canonical base64: {detail}")]
    MalformedPayloadEncoding { detail: String },
    #[error("payload is {found} bytes, exceeding the {max}-byte limit")]
    PayloadTooLarge { found: usize, max: usize },
    #[error("bundle carries no signatures")]
    NoSignatures,
    #[error("bundle carries {found} signatures, exceeding the {max} limit")]
    TooManySignatures { found: usize, max: usize },
    #[error("no signature names a key_id present in the trust store: offered {offered:?}")]
    UnknownKeyId { offered: Vec<KeyId> },
    #[error("key {key_id:?} uses unsupported algorithm {algorithm:?}")]
    UnsupportedAlgorithm {
        key_id: KeyId,
        algorithm: SignatureAlgorithm,
    },
    #[error("signature for key {key_id:?} is malformed")]
    MalformedSignature { key_id: KeyId },
    #[error("key {key_id:?} is not yet valid: not_before={not_before}, now={now}")]
    KeyNotYetValid {
        key_id: KeyId,
        not_before: String,
        now: DateTime<Utc>,
    },
    #[error("key {key_id:?} has been retired: not_after={not_after}, now={now}")]
    KeyRetired {
        key_id: KeyId,
        not_after: String,
        now: DateTime<Utc>,
    },
    #[error("signature is invalid for trusted, current key(s): {key_ids:?}")]
    SignatureInvalid { key_ids: Vec<KeyId> },
    #[error("payload is malformed: {detail}")]
    MalformedPayload { detail: String },
    #[error("field {field} has a malformed timestamp: {value:?}")]
    MalformedTimestamp { field: &'static str, value: String },
    #[error("bundle not yet valid: not_before={not_before}, now={now}, tolerance_seconds={tolerance_seconds}")]
    BundleNotYetValid {
        not_before: String,
        now: DateTime<Utc>,
        tolerance_seconds: i64,
    },
    #[error("bundle expired: expires_at={expires_at}, now={now}")]
    BundleExpired {
        expires_at: String,
        now: DateTime<Utc>,
    },
    #[error("binding {binding_id} references digest {expected}, but the bundle's revision digest is {actual}")]
    BindingRevisionMismatch {
        binding_id: Uuid,
        expected: String,
        actual: String,
    },
}

fn decode_verifying_key(key: &TrustedKey) -> Result<VerifyingKey, ()> {
    let bytes = strict_base64()
        .decode(&key.public_key_b64)
        .map_err(|_| ())?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ())?;
    VerifyingKey::from_bytes(&arr).map_err(|_| ())
}

fn parse_rfc3339(field: &'static str, value: &str) -> Result<DateTime<Utc>, BundleRejection> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| BundleRejection::MalformedTimestamp {
            field,
            value: value.to_string(),
        })
}

/// Shared timestamp parser for the envelope-verification helper below. Not
/// `BundleRejection`-typed, unlike [`parse_rfc3339`] above — the helper is
/// shared with [`super::revocation::verify_revocation_list`], which must
/// never inherit a `BundleRejection` variant for a check it doesn't perform.
fn parse_rfc3339_plain(value: &str) -> Result<DateTime<Utc>, ()> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ())
}

/// The authenticated result of [`verify_signed_envelope`]: the raw payload
/// bytes (not yet parsed into any typed payload) and which trusted key
/// verified them.
///
/// `pub(crate)` (not `pub(super)`) so [`super::super::audit_checkpoint`]
/// (FORNX-317) -- a top-level sibling of `policy`, not one of its
/// submodules -- can reuse [`verify_signed_envelope`] under its own signing
/// domain, exactly as [`super::revocation::verify_revocation_list`] already
/// does from inside this module tree.
pub(crate) struct VerifiedEnvelope {
    pub(crate) payload_bytes: Vec<u8>,
    pub(crate) verified_by: KeyId,
}

/// Exhaustive envelope/signature-layer failure vocabulary for
/// [`verify_signed_envelope`] -- deliberately **not** [`BundleRejection`].
/// [`verify_bundle`], [`super::revocation::verify_revocation_list`], and
/// [`super::super::audit_checkpoint::verify_audit_checkpoint`] each map
/// this 1:1 into their own rejection enum, so none of them can end up
/// claiming a check (e.g. a bundle-specific expiry window) that this
/// envelope-layer helper never performs. `pub(crate)`, see
/// [`VerifiedEnvelope`]'s doc comment for why.
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum EnvelopeVerificationError {
    #[error("payload_b64 is not valid strict-canonical base64: {detail}")]
    MalformedPayloadEncoding { detail: String },
    #[error("payload is {found} bytes, exceeding the {max}-byte limit")]
    PayloadTooLarge { found: usize, max: usize },
    #[error("envelope carries no signatures")]
    NoSignatures,
    #[error("envelope carries {found} signatures, exceeding the {max} limit")]
    TooManySignatures { found: usize, max: usize },
    #[error("no signature names a key_id present in the trust store: offered {offered:?}")]
    UnknownKeyId { offered: Vec<KeyId> },
    #[error("key {key_id:?} uses unsupported algorithm {algorithm:?}")]
    UnsupportedAlgorithm {
        key_id: KeyId,
        algorithm: SignatureAlgorithm,
    },
    #[error("signature for key {key_id:?} is malformed")]
    MalformedSignature { key_id: KeyId },
    #[error("key {key_id:?} is not yet valid: not_before={not_before}, now={now}")]
    KeyNotYetValid {
        key_id: KeyId,
        not_before: String,
        now: DateTime<Utc>,
    },
    #[error("key {key_id:?} has been retired: not_after={not_after}, now={now}")]
    KeyRetired {
        key_id: KeyId,
        not_after: String,
        now: DateTime<Utc>,
    },
    #[error("signature is invalid for trusted, current key(s): {key_ids:?}")]
    SignatureInvalid { key_ids: Vec<KeyId> },
    #[error("field {field} has a malformed timestamp: {value:?}")]
    MalformedKeyTimestamp { field: &'static str, value: String },
}

fn record_envelope_skip(
    slot: &mut Option<EnvelopeVerificationError>,
    reason: EnvelopeVerificationError,
) {
    if slot.is_none() {
        *slot = Some(reason);
    }
}

/// The envelope/signature-verification steps shared by [`verify_bundle`] and
/// [`super::revocation::verify_revocation_list`], parameterized by `domain`
/// (each artifact type has its own signing domain constant -- see
/// [`BUNDLE_SIGNING_DOMAIN`]/`super::revocation::REVOCATION_SIGNING_DOMAIN`).
///
/// Evaluation order (normative, identical to `verify_bundle`'s former steps
/// 3-5): signature-count bounds; strict-decode `payload_b64` bound by
/// `max_payload_bytes`; per-signature verification over `domain ‖
/// payload_bytes`, first success wins (threshold 1), the loop always runs to
/// completion rather than returning on the first unusable signature so a
/// key past its validity window earlier in the list can never mask a later,
/// currently-valid signature (this is what makes D4 key rotation work); on
/// total failure the 4-level precedence is `SignatureInvalid` (a trusted,
/// current key whose signature simply doesn't check out -- tampering) >
/// first_skip_reason (deterministic: the *first* known-but-unusable key's
/// reason) > `UnknownKeyId`.
pub(crate) fn verify_signed_envelope(
    payload_b64: &str,
    signatures: &[BundleSignature],
    domain: &'static [u8],
    max_payload_bytes: usize,
    trusted: &TrustedVerificationKeys,
    now: DateTime<Utc>,
) -> Result<VerifiedEnvelope, EnvelopeVerificationError> {
    if signatures.is_empty() {
        return Err(EnvelopeVerificationError::NoSignatures);
    }
    if signatures.len() > MAX_SIGNATURES {
        return Err(EnvelopeVerificationError::TooManySignatures {
            found: signatures.len(),
            max: MAX_SIGNATURES,
        });
    }

    let payload_bytes = strict_base64().decode(payload_b64).map_err(|e| {
        EnvelopeVerificationError::MalformedPayloadEncoding {
            detail: e.to_string(),
        }
    })?;
    if payload_bytes.len() > max_payload_bytes {
        return Err(EnvelopeVerificationError::PayloadTooLarge {
            found: payload_bytes.len(),
            max: max_payload_bytes,
        });
    }

    let mut signed_message = Vec::with_capacity(domain.len() + payload_bytes.len());
    signed_message.extend_from_slice(domain);
    signed_message.extend_from_slice(&payload_bytes);

    let mut offered_key_ids: Vec<KeyId> = Vec::new();
    let mut trusted_current_but_failed: Vec<KeyId> = Vec::new();
    let mut first_skip_reason: Option<EnvelopeVerificationError> = None;
    let mut verified_by: Option<KeyId> = None;

    for sig_entry in signatures {
        offered_key_ids.push(sig_entry.key_id.clone());

        let Some(trusted_key) = trusted.get(&sig_entry.key_id) else {
            continue;
        };

        if let Some(not_before) = &trusted_key.not_before {
            match parse_rfc3339_plain(not_before) {
                Ok(nb) if now < nb => {
                    record_envelope_skip(
                        &mut first_skip_reason,
                        EnvelopeVerificationError::KeyNotYetValid {
                            key_id: sig_entry.key_id.clone(),
                            not_before: not_before.clone(),
                            now,
                        },
                    );
                    continue;
                }
                Err(()) => {
                    record_envelope_skip(
                        &mut first_skip_reason,
                        EnvelopeVerificationError::MalformedKeyTimestamp {
                            field: "trusted_key.not_before",
                            value: not_before.clone(),
                        },
                    );
                    continue;
                }
                Ok(_) => {}
            }
        }
        if let Some(not_after) = &trusted_key.not_after {
            match parse_rfc3339_plain(not_after) {
                Ok(na) if now > na => {
                    record_envelope_skip(
                        &mut first_skip_reason,
                        EnvelopeVerificationError::KeyRetired {
                            key_id: sig_entry.key_id.clone(),
                            not_after: not_after.clone(),
                            now,
                        },
                    );
                    continue;
                }
                Err(()) => {
                    record_envelope_skip(
                        &mut first_skip_reason,
                        EnvelopeVerificationError::MalformedKeyTimestamp {
                            field: "trusted_key.not_after",
                            value: not_after.clone(),
                        },
                    );
                    continue;
                }
                Ok(_) => {}
            }
        }

        if !matches!(sig_entry.algorithm, SignatureAlgorithm::Ed25519)
            || !matches!(trusted_key.algorithm, SignatureAlgorithm::Ed25519)
        {
            record_envelope_skip(
                &mut first_skip_reason,
                EnvelopeVerificationError::UnsupportedAlgorithm {
                    key_id: sig_entry.key_id.clone(),
                    algorithm: sig_entry.algorithm.clone(),
                },
            );
            continue;
        }

        let Ok(verifying_key) = decode_verifying_key(trusted_key) else {
            record_envelope_skip(
                &mut first_skip_reason,
                EnvelopeVerificationError::MalformedSignature {
                    key_id: sig_entry.key_id.clone(),
                },
            );
            continue;
        };

        let Ok(sig_bytes) = strict_base64().decode(&sig_entry.signature_b64) else {
            record_envelope_skip(
                &mut first_skip_reason,
                EnvelopeVerificationError::MalformedSignature {
                    key_id: sig_entry.key_id.clone(),
                },
            );
            continue;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
            record_envelope_skip(
                &mut first_skip_reason,
                EnvelopeVerificationError::MalformedSignature {
                    key_id: sig_entry.key_id.clone(),
                },
            );
            continue;
        };
        let signature = Signature::from_bytes(&sig_arr);

        match verifying_key.verify_strict(&signed_message, &signature) {
            Ok(()) => {
                verified_by = Some(sig_entry.key_id.clone());
                break;
            }
            Err(_) => trusted_current_but_failed.push(sig_entry.key_id.clone()),
        }
    }

    let verified_by = if let Some(k) = verified_by {
        k
    } else if !trusted_current_but_failed.is_empty() {
        return Err(EnvelopeVerificationError::SignatureInvalid {
            key_ids: trusted_current_but_failed,
        });
    } else if let Some(reason) = first_skip_reason {
        return Err(reason);
    } else {
        return Err(EnvelopeVerificationError::UnknownKeyId {
            offered: offered_key_ids,
        });
    };

    Ok(VerifiedEnvelope {
        payload_bytes,
        verified_by,
    })
}

impl From<EnvelopeVerificationError> for BundleRejection {
    fn from(e: EnvelopeVerificationError) -> Self {
        match e {
            EnvelopeVerificationError::MalformedPayloadEncoding { detail } => {
                BundleRejection::MalformedPayloadEncoding { detail }
            }
            EnvelopeVerificationError::PayloadTooLarge { found, max } => {
                BundleRejection::PayloadTooLarge { found, max }
            }
            EnvelopeVerificationError::NoSignatures => BundleRejection::NoSignatures,
            EnvelopeVerificationError::TooManySignatures { found, max } => {
                BundleRejection::TooManySignatures { found, max }
            }
            EnvelopeVerificationError::UnknownKeyId { offered } => {
                BundleRejection::UnknownKeyId { offered }
            }
            EnvelopeVerificationError::UnsupportedAlgorithm { key_id, algorithm } => {
                BundleRejection::UnsupportedAlgorithm { key_id, algorithm }
            }
            EnvelopeVerificationError::MalformedSignature { key_id } => {
                BundleRejection::MalformedSignature { key_id }
            }
            EnvelopeVerificationError::KeyNotYetValid {
                key_id,
                not_before,
                now,
            } => BundleRejection::KeyNotYetValid {
                key_id,
                not_before,
                now,
            },
            EnvelopeVerificationError::KeyRetired {
                key_id,
                not_after,
                now,
            } => BundleRejection::KeyRetired {
                key_id,
                not_after,
                now,
            },
            EnvelopeVerificationError::SignatureInvalid { key_ids } => {
                BundleRejection::SignatureInvalid { key_ids }
            }
            EnvelopeVerificationError::MalformedKeyTimestamp { field, value } => {
                BundleRejection::MalformedTimestamp { field, value }
            }
        }
    }
}

/// See module docs for the trust-boundary/domain-separation/verify-then-parse
/// invariants. Evaluation order (normative — signature-before-semantics):
///
/// 1. Parse envelope.
/// 2. Check `bundle_schema_version` is supported.
///    3-5. Delegated to the shared [`verify_signed_envelope`] helper (also
///    used by [`super::revocation::verify_revocation_list`] with its own
///    signing domain): check `1..=MAX_SIGNATURES` signatures are present;
///    strict-decode `payload_b64` enforcing [`MAX_PAYLOAD_BYTES`]; for
///    each signature, in order, look up `key_id` in the trust store,
///    check the key's own validity window against `now` (never against
///    the bundle's unauthenticated `issued_at`), check algorithm, decode
///    signature bytes, `verify_strict` over `BUNDLE_SIGNING_DOMAIN ‖
///    payload_bytes`. First success wins (threshold 1) — the loop always
///    runs to completion (or to the first success) rather than returning
///    on the first unusable signature, so an out-of-window or otherwise
///    unusable key earlier in the list can never mask a later signature
///    that verifies against a different, currently-valid key. This is
///    what makes D4 rotation work: a bundle signed by both an outgoing
///    key past its `not_after` and an incoming key still verifies via the
///    incoming key regardless of which signature appears first.
/// 6. Parse `payload_bytes` into [`BundlePayload`] (subsumes the inner
///    revision's own digest-mismatch rejection via its `TryFrom`).
/// 7. Check `payload.bundle_schema_version == envelope`'s.
/// 8. Parse timestamps.
/// 9. Window check: `not_before` gets [`CLOCK_SKEW_TOLERANCE_SECONDS`] of
///    grace; `expires_at` gets none — this asymmetry is deliberate, see
///    module docs and `docs/adr/0007-signed-policy-bundles.md`.
/// 10. Every binding's `revision_ref.digest` must equal the revision's own
///     digest.
/// 11. Construct [`VerifiedPolicyBundle`].
pub fn verify_bundle(
    envelope_bytes: &[u8],
    trusted: &TrustedVerificationKeys,
    now: DateTime<Utc>,
) -> Result<VerifiedPolicyBundle, BundleRejection> {
    // 1. Parse envelope.
    let envelope: SignedPolicyBundle =
        serde_json::from_slice(envelope_bytes).map_err(|e| BundleRejection::MalformedEnvelope {
            detail: e.to_string(),
        })?;

    // 2. Schema version supported.
    if !SUPPORTED_BUNDLE_SCHEMA_VERSIONS.contains(&envelope.bundle_schema_version) {
        return Err(BundleRejection::UnsupportedBundleSchemaVersion {
            found: envelope.bundle_schema_version,
            supported: SUPPORTED_BUNDLE_SCHEMA_VERSIONS.to_vec(),
        });
    }

    // 3-5. Signature-count bounds, strict-decode + size bound, and
    // per-signature verification -- all delegated to the shared helper (see
    // its own doc comment for the full evaluation order and D4-rotation
    // rationale). `verify_revocation_list` calls the exact same helper with
    // its own signing domain.
    let verified_envelope = verify_signed_envelope(
        &envelope.payload_b64,
        &envelope.signatures,
        BUNDLE_SIGNING_DOMAIN,
        MAX_PAYLOAD_BYTES,
        trusted,
        now,
    )
    .map_err(BundleRejection::from)?;
    let payload_bytes = verified_envelope.payload_bytes;
    let verified_by = verified_envelope.verified_by;

    // 6. Parse payload (only now, post-authentication).
    let payload: BundlePayload =
        serde_json::from_slice(&payload_bytes).map_err(|e| BundleRejection::MalformedPayload {
            detail: e.to_string(),
        })?;

    // 7. Schema version cross-check.
    if payload.bundle_schema_version != envelope.bundle_schema_version {
        return Err(BundleRejection::SchemaVersionMismatch {
            envelope: envelope.bundle_schema_version,
            payload: payload.bundle_schema_version,
        });
    }

    // 8. Parse timestamps.
    let not_before = parse_rfc3339("not_before", &payload.not_before)?;
    let expires_at = parse_rfc3339("expires_at", &payload.expires_at)?;
    // issued_at is parsed for validation shape only; it is not otherwise
    // authenticated or trusted for any decision here.
    parse_rfc3339("issued_at", &payload.issued_at)?;

    // 9. Window check -- asymmetric clock skew (see module docs).
    if now < not_before - chrono::Duration::seconds(CLOCK_SKEW_TOLERANCE_SECONDS) {
        return Err(BundleRejection::BundleNotYetValid {
            not_before: payload.not_before.clone(),
            now,
            tolerance_seconds: CLOCK_SKEW_TOLERANCE_SECONDS,
        });
    }
    if now > expires_at {
        return Err(BundleRejection::BundleExpired {
            expires_at: payload.expires_at.clone(),
            now,
        });
    }

    // 10. Binding digests must match the bundle's revision digest.
    let revision_digest = payload.revision.digest().as_str().to_string();
    for binding in &payload.bindings {
        let expected = binding.revision_ref.digest.as_str();
        if expected != revision_digest {
            return Err(BundleRejection::BindingRevisionMismatch {
                binding_id: binding.binding_id,
                expected: expected.to_string(),
                actual: revision_digest,
            });
        }
    }

    // 11. Construct.
    let payload_digest = digest_payload_bytes(&payload_bytes);
    Ok(VerifiedPolicyBundle {
        payload,
        verified_by,
        payload_digest,
    })
}
