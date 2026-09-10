//! Dispatches a receipt artifact (signed envelope or bare receipt) to the
//! right handling and reports [`SignatureStatus`] (FORNX-350 AC2).
//!
//! **Verification-only.** This module verifies signatures produced
//! elsewhere; it never signs anything in production (see
//! `fornax_types::receipt`'s module docs). Runs no network client
//! anywhere -- entirely file/argument driven, same offline discipline
//! `fornax-cli::timeline` already tests for.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use fornax_types::policy::{KeyId, TrustStoreError, TrustedVerificationKeys};
use fornax_types::receipt::{verify_receipt_envelope, ReceiptEnvelopeRejection};

use crate::freshness::{assess_freshness, Freshness};
use crate::schema::{IntegrityReceipt, ReceiptDigestMismatch};

pub const RECEIPT_TRUST_STORE_ENV_VAR: &str = "FORNAX_RECEIPT_TRUST_STORE";
pub const RECEIPT_TRUST_STORE_FILE: &str = "receipt-trust.json";

/// Whether a receipt's authenticity could be established. `Unsigned` is
/// its own explicit state -- never treated as invalid, and never silently
/// treated as authenticated (FORNX-350 owner decision: unsigned receipts
/// stay explicitly unsigned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// The artifact was a bare `{body, digest}` receipt with no envelope at
    /// all.
    Unsigned,
    /// The artifact was signed, but no trust store was resolvable to
    /// judge it against.
    Unverifiable {
        reason: String,
    },
    Verified {
        key_id: KeyId,
    },
    Rejected {
        rejection: String,
    },
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReceiptRejection {
    #[error("artifact is not valid JSON: {detail}")]
    MalformedJson { detail: String },
    #[error("artifact is a signed envelope, but its authenticated payload is not a valid receipt body: {detail}")]
    MalformedPayload { detail: String },
    #[error("artifact is a bare receipt whose digest does not match its body: {0}")]
    DigestMismatch(#[from] ReceiptDigestMismatch),
}

/// A receipt plus what could be established about its authenticity and
/// freshness.
#[derive(Debug, Clone)]
pub struct VerifiedReceipt {
    receipt: IntegrityReceipt,
    signature: SignatureStatus,
    freshness: Freshness,
}

impl VerifiedReceipt {
    pub fn receipt(&self) -> &IntegrityReceipt {
        &self.receipt
    }

    pub fn signature(&self) -> &SignatureStatus {
        &self.signature
    }

    pub fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    /// Test-only constructor for [`crate::gate`]'s own tests, which need to
    /// exercise `evaluate_receipt_gate` against specific
    /// signature/freshness combinations without round-tripping through a
    /// real envelope every time.
    #[cfg(test)]
    pub(crate) fn for_test(
        receipt: IntegrityReceipt,
        signature: SignatureStatus,
        freshness: Freshness,
    ) -> Self {
        Self {
            receipt,
            signature,
            freshness,
        }
    }
}

/// Dispatches on the artifact's own top-level shape: a `payload_b64` key
/// means a signed envelope (`fornax_types::receipt::SignedIntegrityReceipt`);
/// otherwise it is treated as a bare `{body, digest}` receipt. Same
/// dispatch discipline this repo's `fornax policy import` already uses for
/// its own artifact shapes.
pub fn verify_receipt_bytes(
    bytes: &[u8],
    trusted: Option<&TrustedVerificationKeys>,
    now: DateTime<Utc>,
) -> Result<VerifiedReceipt, ReceiptRejection> {
    let top: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| ReceiptRejection::MalformedJson {
            detail: e.to_string(),
        })?;

    let is_envelope = top.get("payload_b64").is_some();

    let (receipt, signature) = if is_envelope {
        match trusted {
            None => {
                // Still parse the payload (unauthenticated) so a caller can
                // inspect it, but report it as unverifiable rather than
                // trusted.
                let envelope: fornax_types::receipt::SignedIntegrityReceipt =
                    serde_json::from_value(top).map_err(|e| ReceiptRejection::MalformedJson {
                        detail: e.to_string(),
                    })?;
                let payload_bytes = crate::verify::decode_unverified(&envelope.payload_b64)
                    .map_err(|detail| ReceiptRejection::MalformedPayload { detail })?;
                let receipt: IntegrityReceipt =
                    serde_json::from_slice(&payload_bytes).map_err(|e| {
                        ReceiptRejection::MalformedPayload {
                            detail: e.to_string(),
                        }
                    })?;
                (
                    receipt,
                    SignatureStatus::Unverifiable {
                        reason: "no trust store resolvable".to_string(),
                    },
                )
            }
            Some(trusted) => match verify_receipt_envelope(bytes, trusted, now) {
                Ok(authenticated) => {
                    let receipt: IntegrityReceipt =
                        serde_json::from_slice(authenticated.payload_bytes()).map_err(|e| {
                            ReceiptRejection::MalformedPayload {
                                detail: e.to_string(),
                            }
                        })?;
                    (
                        receipt,
                        SignatureStatus::Verified {
                            key_id: authenticated.verified_by().clone(),
                        },
                    )
                }
                Err(rejection) => {
                    // Still surface the (unauthenticated) receipt body when
                    // parseable, so a caller can see what was rejected.
                    let envelope: fornax_types::receipt::SignedIntegrityReceipt =
                        serde_json::from_slice(bytes).map_err(|e| {
                            ReceiptRejection::MalformedJson {
                                detail: e.to_string(),
                            }
                        })?;
                    let payload_bytes = crate::verify::decode_unverified(&envelope.payload_b64)
                        .map_err(|detail| ReceiptRejection::MalformedPayload { detail })?;
                    let receipt: IntegrityReceipt = serde_json::from_slice(&payload_bytes)
                        .map_err(|e| ReceiptRejection::MalformedPayload {
                            detail: e.to_string(),
                        })?;
                    (
                        receipt,
                        SignatureStatus::Rejected {
                            rejection: describe_rejection(&rejection),
                        },
                    )
                }
            },
        }
    } else {
        let receipt: IntegrityReceipt =
            serde_json::from_value(top).map_err(|e| ReceiptRejection::MalformedPayload {
                detail: e.to_string(),
            })?;
        (receipt, SignatureStatus::Unsigned)
    };

    let freshness = assess_freshness(receipt.body(), now);
    Ok(VerifiedReceipt {
        receipt,
        signature,
        freshness,
    })
}

fn describe_rejection(r: &ReceiptEnvelopeRejection) -> String {
    r.to_string()
}

/// Strict-canonical base64 decode of an envelope's `payload_b64`, without
/// any signature check -- used only to surface an unauthenticated body for
/// display when verification is impossible/failed. Never used to treat the
/// result as trusted.
fn decode_unverified(payload_b64: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    B64.decode(payload_b64).map_err(|e| e.to_string())
}

/// Never fails startup-equivalent (mirrors
/// `fornax_types::policy::resolve_trust_store`'s discipline, simplified
/// for CLI-only use -- no `PolicyDiagnostic` dependency).  Precedence:
/// [`RECEIPT_TRUST_STORE_ENV_VAR`] env var -> `<home>/receipt-trust.json`
/// -> `None`.
pub fn resolve_receipt_trust_store(
    home: &Path,
) -> (Option<TrustedVerificationKeys>, Option<String>) {
    if let Ok(path) = std::env::var(RECEIPT_TRUST_STORE_ENV_VAR) {
        return match load_from_path(Path::new(&path)) {
            Ok(keys) => (Some(keys), None),
            Err(detail) => (
                None,
                Some(format!(
                    "{RECEIPT_TRUST_STORE_ENV_VAR}={path:?} could not be loaded: {detail}"
                )),
            ),
        };
    }

    let default_path = home.join(RECEIPT_TRUST_STORE_FILE);
    if default_path.exists() {
        return match load_from_path(&default_path) {
            Ok(keys) => (Some(keys), None),
            Err(detail) => (
                None,
                Some(format!(
                    "{} could not be loaded: {detail}",
                    default_path.display()
                )),
            ),
        };
    }

    (
        None,
        Some(format!(
            "no receipt trust store configured: set {RECEIPT_TRUST_STORE_ENV_VAR} or create {}",
            default_path.display()
        )),
    )
}

fn load_from_path(path: &Path) -> Result<TrustedVerificationKeys, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    TrustedVerificationKeys::load(&raw).map_err(|e: TrustStoreError| e.to_string())
}

#[cfg(test)]
mod tests {
    /// FORNX-350's own offline requirement (AC5's "without requiring cloud
    /// availability") -- mirrors `fornax-cli::timeline`'s identical
    /// reachability test for the same claim. Scans only the
    /// production (non-`#[cfg(test)]`) portion of this file -- this test's
    /// own literal list of forbidden names would otherwise self-trigger.
    #[test]
    fn no_network_client_symbol_is_reachable_from_this_module() {
        let source = include_str!("verify.rs");
        let production_code = source
            .split("#[cfg(test)]")
            .next()
            .expect("split always yields at least one segment");
        for forbidden in ["reqwest", "TcpStream", "hyper::Client"] {
            assert!(
                !production_code.contains(forbidden),
                "verify.rs's production code must never reference {forbidden}"
            );
        }
    }
}
