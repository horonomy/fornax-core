//! FORNX-123 policy revocation acceptance-test scenarios, T78 onward (see
//! `docs/adr/0009-policy-revocation-and-emergency-control.md`). Continues
//! the numbering `policy/tests.rs`/`policy/cache_tests.rs` established
//! (T1-T70 there) and `fornax-store::policy_cache`'s own tests (T71-T77)
//! continued. Pure decision-function tests only -- store-level
//! integration/crash-safety scenarios (cached-then-revoked via a real
//! generation reload, stickiness across a trust-store edit, crash safety)
//! live in `fornax-store::policy_cache`'s own test module instead, since
//! they need a real SQLite-backed `Store`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use uuid::Uuid;

use super::tests::{
    base_now, device_ctx, org_binding, primary_signing_key, sample_revision, trust_store,
    trusted_key_for,
};
use super::*;
use crate::Verdict;

fn revocation_signing_key() -> SigningKey {
    primary_signing_key()
}

fn sign_revocation_domain(payload_bytes: &[u8], signing_key: &SigningKey) -> String {
    let mut msg = Vec::with_capacity(REVOCATION_SIGNING_DOMAIN.len() + payload_bytes.len());
    msg.extend_from_slice(REVOCATION_SIGNING_DOMAIN);
    msg.extend_from_slice(payload_bytes);
    let sig = signing_key.sign(&msg);
    STANDARD.encode(sig.to_bytes())
}

fn build_revocation_envelope(
    issuer: &str,
    sequence: u64,
    entries: Vec<serde_json::Value>,
    key_id: &str,
    signing_key: &SigningKey,
    domain_correct: bool,
) -> Vec<u8> {
    let payload = serde_json::json!({
        "revocation_schema_version": REVOCATION_SCHEMA_VERSION,
        "issuer": issuer,
        "sequence": sequence,
        "issued_at": "2026-01-01T00:00:00Z",
        "entries": entries,
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let sig_b64 = if domain_correct {
        sign_revocation_domain(&payload_bytes, signing_key)
    } else {
        // Bare-payload signature, no domain prefix -- used only by the
        // domain-separation test.
        let sig = signing_key.sign(&payload_bytes);
        STANDARD.encode(sig.to_bytes())
    };
    let envelope = serde_json::json!({
        "revocation_schema_version": REVOCATION_SCHEMA_VERSION,
        "payload_b64": STANDARD.encode(&payload_bytes),
        "signatures": [{
            "key_id": key_id,
            "algorithm": "ed25519",
            "signature_b64": sig_b64,
        }],
    });
    serde_json::to_vec(&envelope).unwrap()
}

fn revision_digest_entry(digest: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "target": {
            "target_kind": "revision_digest",
            "digest": digest,
        },
        "revoked_at": "2026-01-01T00:00:00Z",
        "reason": reason,
        "audit_ref": null,
        "superseded_by": null,
    })
}

#[allow(dead_code)]
fn payload_digest_entry(digest: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "target": {
            "target_kind": "payload_digest",
            "digest": digest,
        },
        "revoked_at": "2026-01-01T00:00:00Z",
        "reason": reason,
        "audit_ref": null,
        "superseded_by": null,
    })
}

fn trust_for(key_id: &str, sk: &SigningKey) -> TrustedVerificationKeys {
    trust_store(vec![trusted_key_for(key_id, sk, None, None)])
}

/// Builds a verified bundle for `bundle_id` at `sequence`, all sharing one
/// `revision` -- used to construct "the same revision, re-wrapped under a
/// different bundle_id" scenarios (T83).
fn build_verified_bundle(
    revision: PublishedPolicyRevision,
    bundle_id: Uuid,
    sequence: u64,
    key_id: &str,
    sk: &SigningKey,
) -> VerifiedPolicyBundle {
    let binding = org_binding("org-1", &revision);
    let payload = BundlePayload {
        bundle_schema_version: BUNDLE_SCHEMA_VERSION,
        bundle_id,
        sequence,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        not_before: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        provenance: BundleProvenance {
            issuer: "fornax-cloud-test".to_string(),
            audit_ref: None,
            authorized_by: None,
        },
        revision,
        bindings: vec![binding],
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let mut msg = Vec::with_capacity(BUNDLE_SIGNING_DOMAIN.len() + payload_bytes.len());
    msg.extend_from_slice(BUNDLE_SIGNING_DOMAIN);
    msg.extend_from_slice(&payload_bytes);
    let sig = sk.sign(&msg);
    let envelope = SignedPolicyBundle {
        bundle_schema_version: BUNDLE_SCHEMA_VERSION,
        payload_b64: STANDARD.encode(&payload_bytes),
        signatures: vec![BundleSignature {
            key_id: KeyId(key_id.to_string()),
            algorithm: SignatureAlgorithm::Ed25519,
            signature_b64: STANDARD.encode(sig.to_bytes()),
        }],
    };
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    let trust = trust_for(key_id, sk);
    verify_bundle(&envelope_bytes, &trust, base_now()).expect("bundle must verify")
}

fn empty_state_with_revocations(revocations: RevocationSet) -> PolicyCacheState {
    PolicyCacheState {
        schema_version: POLICY_CACHE_SCHEMA_VERSION,
        active: None,
        pending: None,
        last_known_good: None,
        high_water: std::collections::BTreeMap::new(),
        ever_configured: false,
        revocations,
    }
}

fn hit_meta(reason: &str) -> RevocationHitMeta {
    RevocationHitMeta {
        reason: reason.to_string(),
        revoked_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

// ------------------------------------------------------------------------
// T78 -- THE TRAP TEST
// ------------------------------------------------------------------------

/// A bundle that `verify_bundle` still ACCEPTS (valid signature, unexpired,
/// trusted current key) must be REJECTED on re-import with
/// `ActivationRejection::Revoked`. If this test can be made to pass by any
/// change inside `bundle.rs`, the design was implemented wrong -- it must
/// be a cache-layer rejection, never a signature-layer one.
#[test]
fn t78_revoked_bundle_still_passes_verify_bundle_but_is_rejected_at_activation() {
    let sk = primary_signing_key();
    let revision = sample_revision();
    let candidate = build_verified_bundle(revision.clone(), Uuid::new_v4(), 1, "k1", &sk);

    // The candidate is, unambiguously, a validly-signed, in-window, trusted
    // bundle: re-verifying it directly must still succeed. This is the
    // load-bearing assertion of the whole ticket.
    let trust = trust_for("k1", &sk);
    let re_verified = {
        let binding = org_binding("org-1", &revision);
        let payload = BundlePayload {
            bundle_schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: candidate.payload().bundle_id,
            sequence: 1,
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            provenance: BundleProvenance {
                issuer: "fornax-cloud-test".to_string(),
                audit_ref: None,
                authorized_by: None,
            },
            revision: revision.clone(),
            bindings: vec![binding],
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut msg = Vec::with_capacity(BUNDLE_SIGNING_DOMAIN.len() + payload_bytes.len());
        msg.extend_from_slice(BUNDLE_SIGNING_DOMAIN);
        msg.extend_from_slice(&payload_bytes);
        let sig = sk.sign(&msg);
        let envelope = SignedPolicyBundle {
            bundle_schema_version: BUNDLE_SCHEMA_VERSION,
            payload_b64: STANDARD.encode(&payload_bytes),
            signatures: vec![BundleSignature {
                key_id: KeyId("k1".to_string()),
                algorithm: SignatureAlgorithm::Ed25519,
                signature_b64: STANDARD.encode(sig.to_bytes()),
            }],
        };
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
        verify_bundle(&envelope_bytes, &trust, base_now())
    };
    assert!(
        re_verified.is_ok(),
        "verify_bundle must still accept a revoked-but-validly-signed bundle -- \
         no signature-layer check can ever catch revocation"
    );

    // Now the cache layer knows this revision_digest is revoked.
    let mut revocations = RevocationSet::default();
    revocations.revision_digests.insert(
        candidate.revision().digest().clone(),
        hit_meta("compromised signing key"),
    );
    let state = empty_state_with_revocations(revocations);

    let outcome = evaluate_activation(&candidate, &state, base_now());
    assert!(
        matches!(outcome, Err(ActivationRejection::Revoked { .. })),
        "a revoked bundle must be rejected by evaluate_activation, not by verify_bundle"
    );
}

// ------------------------------------------------------------------------
// T82/T83 -- payload_digest vs revision_digest revocation reach
// ------------------------------------------------------------------------

/// Revoking by `payload_digest` catches an exact resubmission of the same
/// envelope (identical `bundle_id`, therefore identical `payload_digest`).
#[test]
fn t82_revocation_by_payload_digest_catches_exact_resubmission() {
    let sk = primary_signing_key();
    let revision = sample_revision();
    let bundle_id = Uuid::new_v4();
    let candidate = build_verified_bundle(revision, bundle_id, 1, "k1", &sk);

    let mut revocations = RevocationSet::default();
    revocations.payload_digests.insert(
        candidate.payload_digest().clone(),
        hit_meta("leaked bundle"),
    );
    let state = empty_state_with_revocations(revocations);

    let outcome = evaluate_activation(&candidate, &state, base_now());
    assert!(matches!(outcome, Err(ActivationRejection::Revoked { .. })));
}

/// Revoking by `revision_digest` catches a bundle "re-wrapped" under a
/// DIFFERENT `bundle_id` (hence a different `payload_digest`) but the SAME
/// underlying revision content/digest -- the broader net a payload_digest-
/// only revocation cannot provide, since a re-wrap changes the payload
/// bytes (and therefore the payload_digest) but not the revision digest.
#[test]
fn t83_revocation_by_revision_digest_catches_a_rewrapped_bundle() {
    let sk = primary_signing_key();
    let revision = sample_revision();
    let original = build_verified_bundle(revision.clone(), Uuid::new_v4(), 1, "k1", &sk);
    let rewrapped = build_verified_bundle(revision, Uuid::new_v4(), 2, "k1", &sk);

    assert_ne!(
        original.payload_digest(),
        rewrapped.payload_digest(),
        "a re-wrap must produce a different payload_digest (different bundle_id/sequence)"
    );
    assert_eq!(
        original.revision().digest(),
        rewrapped.revision().digest(),
        "a re-wrap shares the same underlying revision digest"
    );

    let mut revocations = RevocationSet::default();
    revocations.revision_digests.insert(
        original.revision().digest().clone(),
        hit_meta("compromised revision"),
    );
    let state = empty_state_with_revocations(revocations);

    // Even though `rewrapped` was never itself named, its shared revision
    // digest is caught.
    let outcome = evaluate_activation(&rewrapped, &state, base_now());
    assert!(matches!(outcome, Err(ActivationRejection::Revoked { .. })));
}

// ------------------------------------------------------------------------
// evaluate_revocation_ingest -- sequence discipline, union-only, sticky
// ------------------------------------------------------------------------

#[test]
fn t86_lower_sequence_is_rejected_and_entries_are_never_removed() {
    let sk = revocation_signing_key();
    let trust = trust_for("k1", &sk);

    let env_seq5 = build_revocation_envelope(
        "issuer-a",
        5,
        vec![revision_digest_entry(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "r1",
        )],
        "k1",
        &sk,
        true,
    );
    let candidate5 = verify_revocation_list(&env_seq5, &trust, base_now()).expect("verify seq5");

    let mut state = empty_state_with_revocations(RevocationSet::default());
    let decision = evaluate_revocation_ingest(&candidate5, &state, base_now())
        .expect("seq5 must be accepted against an empty state");
    let RevocationIngestDecision::Apply { new_entries, .. } = decision else {
        panic!("expected Apply");
    };
    assert_eq!(new_entries.len(), 1);
    // Simulate persistence.
    state
        .revocations
        .max_sequence_by_issuer
        .insert("issuer-a".to_string(), 5);
    for e in &new_entries {
        if let RevocationTarget::RevisionDigest { digest } = &e.target {
            state
                .revocations
                .revision_digests
                .insert(digest.clone(), hit_meta(&e.reason));
        }
    }

    // A lower sequence (e.g. 3) from the same issuer must be rejected --
    // and critically, the previously-recorded entry must still be present
    // (a rejected ingest can never remove anything).
    let env_seq3 = build_revocation_envelope("issuer-a", 3, vec![], "k1", &sk, true);
    let candidate3 = verify_revocation_list(&env_seq3, &trust, base_now()).expect("verify seq3");
    let rejection = evaluate_revocation_ingest(&candidate3, &state, base_now())
        .expect_err("seq3 must be rejected: it is below the seq5 high-water");
    assert!(matches!(
        rejection,
        RevocationIngestRejection::SequenceNotAdvanced { .. }
    ));
    assert_eq!(state.revocations.revision_digests.len(), 1);

    // A newer list (seq7) that OMITS the seq5 entry must still leave it in
    // place -- union-only, sticky.
    let env_seq7 = build_revocation_envelope(
        "issuer-a",
        7,
        vec![revision_digest_entry(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "r2",
        )],
        "k1",
        &sk,
        true,
    );
    let candidate7 = verify_revocation_list(&env_seq7, &trust, base_now()).expect("verify seq7");
    let decision7 = evaluate_revocation_ingest(&candidate7, &state, base_now())
        .expect("seq7 must be accepted: it advances past seq5");
    let RevocationIngestDecision::Apply { new_entries, .. } = decision7 else {
        panic!("expected Apply");
    };
    assert_eq!(
        new_entries.len(),
        1,
        "only the genuinely new entry is returned -- the seq5 entry, though \
         omitted from this list, is not re-emitted and (per the caller's own \
         persistence contract) is never removed"
    );
}

// ------------------------------------------------------------------------
// T87 -- serde(other) forward-compat
// ------------------------------------------------------------------------

#[test]
fn t87_unknown_target_kind_alongside_a_known_entry_applies_the_known_one() {
    let sk = revocation_signing_key();
    let trust = trust_for("k1", &sk);

    let known = revision_digest_entry(
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "known-bad",
    );
    let unknown = serde_json::json!({
        "target": {
            "target_kind": "future_kind_v2",
            "some_future_field": "opaque",
        },
        "revoked_at": "2026-01-01T00:00:00Z",
        "reason": "future-reason",
        "audit_ref": null,
        "superseded_by": null,
    });
    let env = build_revocation_envelope("issuer-a", 1, vec![known, unknown], "k1", &sk, true);
    let verified = verify_revocation_list(&env, &trust, base_now())
        .expect("list with one unknown entry kind must still parse");

    assert_eq!(verified.entries().len(), 2);
    let unrecognized_count = verified
        .entries()
        .iter()
        .filter(|e| matches!(e.target, RevocationTarget::Unrecognized))
        .count();
    assert_eq!(unrecognized_count, 1);

    let state = empty_state_with_revocations(RevocationSet::default());
    let decision =
        evaluate_revocation_ingest(&verified, &state, base_now()).expect("must be accepted");
    let RevocationIngestDecision::Apply { new_entries, .. } = decision else {
        panic!("expected Apply");
    };
    // Both are "new" from evaluate_revocation_ingest's point of view (the
    // Unrecognized one always passes the filter since it can never be
    // matched against an already-stored digest) -- the store layer is
    // responsible for not persisting it as an actionable row and instead
    // bumping `unrecognized_entry_count` (see fornax-store's own test for
    // that half).
    assert_eq!(new_entries.len(), 2);
    assert!(new_entries
        .iter()
        .any(|e| matches!(e.target, RevocationTarget::RevisionDigest { .. })));
    assert!(new_entries
        .iter()
        .any(|e| matches!(e.target, RevocationTarget::Unrecognized)));
}

// ------------------------------------------------------------------------
// T88 -- domain separation
// ------------------------------------------------------------------------

#[test]
fn t88_domain_separation_both_directions() {
    let sk = primary_signing_key();

    // A revocation payload signed with BUNDLE_SIGNING_DOMAIN must be
    // rejected by verify_revocation_list.
    let revocation_payload_bytes = serde_json::to_vec(&serde_json::json!({
        "revocation_schema_version": REVOCATION_SCHEMA_VERSION,
        "issuer": "issuer-a",
        "sequence": 1,
        "issued_at": "2026-01-01T00:00:00Z",
        "entries": [],
    }))
    .unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(BUNDLE_SIGNING_DOMAIN);
    msg.extend_from_slice(&revocation_payload_bytes);
    let wrong_domain_sig = sk.sign(&msg);
    let envelope = serde_json::json!({
        "revocation_schema_version": REVOCATION_SCHEMA_VERSION,
        "payload_b64": STANDARD.encode(&revocation_payload_bytes),
        "signatures": [{
            "key_id": "k1",
            "algorithm": "ed25519",
            "signature_b64": STANDARD.encode(wrong_domain_sig.to_bytes()),
        }],
    });
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    let trust = trust_for("k1", &sk);
    let result = verify_revocation_list(&envelope_bytes, &trust, base_now());
    assert!(
        result.is_err(),
        "a revocation payload signed under BUNDLE_SIGNING_DOMAIN must be rejected"
    );

    // And vice versa: a bundle payload signed with REVOCATION_SIGNING_DOMAIN
    // must be rejected by verify_bundle.
    let revision = sample_revision();
    let binding = org_binding("org-1", &revision);
    let bundle_payload = BundlePayload {
        bundle_schema_version: BUNDLE_SCHEMA_VERSION,
        bundle_id: Uuid::new_v4(),
        sequence: 1,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        not_before: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        provenance: BundleProvenance {
            issuer: "fornax-cloud-test".to_string(),
            audit_ref: None,
            authorized_by: None,
        },
        revision,
        bindings: vec![binding],
    };
    let bundle_payload_bytes = serde_json::to_vec(&bundle_payload).unwrap();
    let mut msg2 = Vec::new();
    msg2.extend_from_slice(REVOCATION_SIGNING_DOMAIN);
    msg2.extend_from_slice(&bundle_payload_bytes);
    let wrong_domain_sig2 = sk.sign(&msg2);
    let bundle_envelope = SignedPolicyBundle {
        bundle_schema_version: BUNDLE_SCHEMA_VERSION,
        payload_b64: STANDARD.encode(&bundle_payload_bytes),
        signatures: vec![BundleSignature {
            key_id: KeyId("k1".to_string()),
            algorithm: SignatureAlgorithm::Ed25519,
            signature_b64: STANDARD.encode(wrong_domain_sig2.to_bytes()),
        }],
    };
    let bundle_envelope_bytes = serde_json::to_vec(&bundle_envelope).unwrap();
    let bundle_result = verify_bundle(&bundle_envelope_bytes, &trust, base_now());
    assert!(
        bundle_result.is_err(),
        "a bundle payload signed under REVOCATION_SIGNING_DOMAIN must be rejected"
    );
}

// ------------------------------------------------------------------------
// T92 -- single-byte-mutation property test
// ------------------------------------------------------------------------

#[test]
fn t92_single_byte_mutations_of_a_valid_revocation_envelope_never_panic_and_always_err() {
    let sk = revocation_signing_key();
    let trust = trust_for("k1", &sk);
    let valid = build_revocation_envelope(
        "issuer-a",
        1,
        vec![revision_digest_entry(
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "r",
        )],
        "k1",
        &sk,
        true,
    );
    assert!(verify_revocation_list(&valid, &trust, base_now()).is_ok());

    for i in 0..valid.len() {
        for bit in 0..8u8 {
            let mut mutated = valid.clone();
            mutated[i] ^= 1 << bit;
            if mutated == valid {
                continue;
            }
            // Must never panic, and a single-byte mutation must never
            // still verify (either it's no longer valid JSON, or the
            // signature/digest no longer matches).
            let result =
                std::panic::catch_unwind(|| verify_revocation_list(&mutated, &trust, base_now()));
            assert!(result.is_ok(), "verify_revocation_list must never panic");
            let verify_result = result.unwrap();
            assert!(
                verify_result.is_err(),
                "a single-byte mutation at byte {i} bit {bit} must never still verify"
            );
        }
    }
}

// ------------------------------------------------------------------------
// T93 -- THE HONEST TEST
// ------------------------------------------------------------------------

/// With `usable = []` and `ever_configured = true`, `EffectivePolicy::
/// enforcement_outcome_for` returns `ObserveOnly` for every action class
/// (baseline has an EMPTY `enforcement_rules` Vec, so the FORNX-119
/// staleness floors are unreachable -- they are rule-anchored and there are
/// zero rules), and `PolicyPosture` is `Degraded`. This pins the documented
/// gap as tested behavior, not silently hoped-for: revocation does NOT
/// tighten enforcement on its own; it only stops the revoked artifact from
/// being loaded/trusted. See ADR-0009.
#[test]
fn t93_the_honest_test_empty_cache_reads_observe_only_everywhere_but_posture_is_degraded() {
    let baseline = PolicyContent::baseline();
    let resolved = resolve(&[], &device_ctx());
    let pf = freshness(
        &[],
        true, // ever_configured
        baseline.cache_max_age_seconds_by_risk,
        baseline.cache_offline_grace_seconds,
        base_now(),
    );
    let effective = EffectivePolicy {
        resolved: resolved.0,
        freshness: pf,
    };

    for ac in [
        ActionClass::CodeEdit,
        ActionClass::ShellCommand,
        ActionClass::VersionControlWrite,
        ActionClass::NetworkFetch,
        ActionClass::PackageInstall,
        ActionClass::CredentialAccess,
        ActionClass::InfrastructureMutation,
        ActionClass::DataEgress,
    ] {
        for v in [
            Verdict::Verified,
            Verdict::Unverified,
            Verdict::Contradicted,
            Verdict::Review,
            Verdict::Unavailable,
        ] {
            assert_eq!(
                effective.enforcement_outcome_for(&ac, v),
                EnforcementOutcome::ObserveOnly,
                "with zero rules, every action class/verdict combination must read ObserveOnly \
                 -- this is the documented gap, not a bug to silently fix here"
            );
        }
    }

    let posture = compute_posture(
        true, // ever_configured
        true, // usable_is_empty
        &[PolicyDiagnostic::new(
            DiagnosticCode::PolicyCacheRevoked,
            DiagnosticSeverity::Error,
            "revoked",
            "publish a fresh bundle",
        )],
    );
    assert!(matches!(
        posture,
        PolicyPosture::Degraded {
            reason: PolicyDegradationReason::Revoked
        }
    ));
}
