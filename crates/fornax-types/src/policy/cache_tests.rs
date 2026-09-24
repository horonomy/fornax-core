//! FORNX-119 local policy cache acceptance-test scenarios, T54 onward (see
//! `docs/adr/0008-local-policy-cache-and-activation.md`). Continues the
//! numbering `policy/tests.rs` established for T1-T53; does not renumber
//! anything there.
//!
//! These tests exercise [`super::cache`]'s pure decision functions
//! (`evaluate_activation`, `freshness`, `staleness_floor`,
//! `effective_outcome`) directly. For T54-T63 (activation/rollback), a
//! small in-memory [`apply_bundle`] reducer models the same state
//! transitions `fornax-store::policy_cache::Store::submit_policy_bundle`
//! performs against real SQLite (generation bump, slot rotation, high-water
//! upsert) so a full submit-and-observe-outcome scenario can be asserted
//! without a database. It is a test-only mirror of that contract, not a
//! duplicate implementation of it — the real store's crash-safety and
//! transactional guarantees are proven separately by
//! `fornax-store::policy_cache`'s own tests (T71-T77).

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use super::bundle::{
    verify_bundle, BundlePayload, BundleProvenance, BundleRejection, PayloadDigest,
    TrustedVerificationKeys, VerifiedPolicyBundle,
};
use super::cache::*;
use super::content::{EnforcementOutcome, RiskClass, RiskClassSeconds};
use super::revision::PolicyId;
use super::tests::{
    build_envelope_bytes, cloud_sync_content, draft, primary_signing_key, sign_domain, trust_store,
    trusted_key_for, valid_signature_entry,
};
use crate::policy::bundle::KeyId;

fn base_now() -> DateTime<Utc> {
    "2026-06-01T00:00:00Z".parse().unwrap()
}

fn empty_state() -> PolicyCacheState {
    PolicyCacheState {
        schema_version: POLICY_CACHE_SCHEMA_VERSION,
        active: None,
        pending: None,
        last_known_good: None,
        high_water: BTreeMap::new(),
        ever_configured: false,
        revocations: RevocationSet::default(),
    }
}

/// Builds one signed-and-verified bundle for `issuer`/`policy_id`(via a
/// fresh policy draft each call)/`sequence`, in-window at [`base_now`].
fn make_bundle(
    issuer: &str,
    sequence: u64,
    policy_id: Uuid,
    key_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> (Vec<u8>, TrustedVerificationKeys) {
    let mut d = draft(cloud_sync_content(true));
    d.policy_id = PolicyId(policy_id);
    d.revision = 1;
    let revision = d.publish("2026-01-01T00:00:00Z".to_string()).unwrap();
    let binding = super::tests::deterministic_org_binding("org-1", &revision, Uuid::new_v4());
    let payload = BundlePayload {
        bundle_schema_version: super::bundle::BUNDLE_SCHEMA_VERSION,
        bundle_id: Uuid::new_v4(),
        sequence,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        not_before: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        provenance: BundleProvenance {
            issuer: issuer.to_string(),
            audit_ref: None,
            authorized_by: None,
        },
        revision,
        bindings: vec![binding],
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let sig = valid_signature_entry(key_id, &payload_bytes, signing_key);
    let envelope = build_envelope_bytes(&payload_bytes, vec![sig]);
    let trust = trust_store(vec![trusted_key_for(key_id, signing_key, None, None)]);
    (envelope, trust)
}

fn verify(
    envelope: &[u8],
    trust: &TrustedVerificationKeys,
    now: DateTime<Utc>,
) -> VerifiedPolicyBundle {
    verify_bundle(envelope, trust, now).expect("bundle should verify")
}

/// Test-only reducer mirroring `Store::submit_policy_bundle`'s state
/// transitions in memory. See module docs.
fn apply_bundle(
    state: &PolicyCacheState,
    envelope: &[u8],
    trust: &TrustedVerificationKeys,
    now: DateTime<Utc>,
) -> (PolicyCacheState, ActivationOutcome) {
    let active_generation = state.active.as_ref().map(|g| g.generation);
    let candidate = match verify_bundle(envelope, trust, now) {
        Ok(c) => c,
        Err(e) => {
            return (
                state.clone(),
                ActivationOutcome::Rejected {
                    rejection: ActivationRejection::NotVerified(e),
                    active_generation,
                },
            )
        }
    };

    match evaluate_activation(&candidate, state, now) {
        Err(rejection) => (
            state.clone(),
            ActivationOutcome::Rejected {
                rejection,
                active_generation,
            },
        ),
        Ok(ActivationDecision::Activate { members, replaced }) => {
            let new_gen_num = active_generation.unwrap_or(0) + 1;
            let mut new_state = state.clone();
            new_state.last_known_good = state.active.clone();
            new_state.active = Some(CacheGeneration {
                generation: new_gen_num,
                members,
                written_at: now,
            });
            new_state.pending = None;
            new_state.ever_configured = true;
            let issuer = candidate.payload().provenance.issuer.clone();
            let policy_id = candidate.revision().body().policy_id;
            new_state.high_water.insert(
                (issuer.clone(), policy_id),
                SequenceHighWater {
                    issuer,
                    policy_id,
                    max_sequence: candidate.payload().sequence,
                    last_bundle_id: candidate.payload().bundle_id,
                    last_payload_digest: candidate.payload_digest().clone(),
                    last_seen_at: now,
                },
            );
            (
                new_state,
                ActivationOutcome::Activated {
                    generation: new_gen_num,
                    superseded: active_generation,
                    replaced_member: replaced,
                },
            )
        }
        Ok(ActivationDecision::Confirm {
            policy_id,
            bundle_id: _,
            payload_digest: _,
        }) => {
            let mut new_state = state.clone();
            if let Some(active) = new_state.active.as_mut() {
                for m in active.members.iter_mut() {
                    if m.policy_id == policy_id {
                        m.confirmed_at = now;
                    }
                }
            }
            let issuer = candidate.payload().provenance.issuer.clone();
            if let Some(hw) = new_state.high_water.get_mut(&(issuer, policy_id)) {
                hw.last_seen_at = now;
            }
            let generation = new_state.active.as_ref().map(|g| g.generation).unwrap_or(0);
            (
                new_state,
                ActivationOutcome::Confirmed {
                    generation,
                    policy_id,
                    confirmed_at: now,
                },
            )
        }
    }
}

// ============================================================================
// T54-T63 -- activation, rollback defense, lineage/issuer binding
// ============================================================================

#[test]
fn t54_fresh_activation_activates_generation_one_with_member_and_high_water() {
    let sk = primary_signing_key();
    let policy_id = Uuid::from_u128(54);
    let (envelope, trust) = make_bundle("issuer-a", 1, policy_id, "k1", &sk);
    let state = empty_state();
    let now = base_now();

    let (new_state, outcome) = apply_bundle(&state, &envelope, &trust, now);

    match outcome {
        ActivationOutcome::Activated {
            generation,
            superseded,
            replaced_member,
        } => {
            assert_eq!(generation, 1);
            assert_eq!(superseded, None);
            assert_eq!(replaced_member, None);
        }
        other => panic!("expected Activated, got {other:?}"),
    }
    let active = new_state.active.expect("active generation must be set");
    assert_eq!(active.generation, 1);
    assert_eq!(active.members.len(), 1);
    assert_eq!(active.members[0].policy_id, PolicyId(policy_id));
    let hw = new_state
        .high_water
        .get(&("issuer-a".to_string(), PolicyId(policy_id)))
        .expect("high-water must be set");
    assert_eq!(hw.max_sequence, 1);
}

#[test]
fn t55_invalid_bundle_never_replaces_last_known_good() {
    let sk = primary_signing_key();
    let policy_id = Uuid::from_u128(55);
    let (good_envelope, trust) = make_bundle("issuer-a", 1, policy_id, "k1", &sk);
    let now = base_now();
    let (state_with_lkg, outcome) = apply_bundle(&empty_state(), &good_envelope, &trust, now);
    assert!(matches!(outcome, ActivationOutcome::Activated { .. }));
    let state_before = state_with_lkg.clone();

    // Sub-case: tampered signature (flip a byte in payload_b64 without
    // re-signing).
    let mut tampered: serde_json::Value = serde_json::from_slice(&good_envelope).unwrap();
    let payload_b64 = tampered["payload_b64"].as_str().unwrap().to_string();
    let mut bytes = payload_b64.into_bytes();
    if let Some(b) = bytes.first_mut() {
        *b ^= 0xFF;
    }
    tampered["payload_b64"] =
        serde_json::Value::String(String::from_utf8_lossy(&bytes).to_string());
    let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
    let (state_after, outcome) = apply_bundle(&state_before, &tampered_bytes, &trust, now);
    assert!(matches!(
        outcome,
        ActivationOutcome::Rejected {
            rejection: ActivationRejection::NotVerified(_),
            ..
        }
    ));
    assert_eq!(
        state_after, state_before,
        "tampered sig must not change state"
    );

    // Sub-case: unknown key.
    let unknown_trust = trust_store(vec![trusted_key_for(
        "someone-else",
        &super::tests::rotated_signing_key(),
        None,
        None,
    )]);
    let (state_after, outcome) = apply_bundle(&state_before, &good_envelope, &unknown_trust, now);
    assert!(matches!(
        outcome,
        ActivationOutcome::Rejected {
            rejection: ActivationRejection::NotVerified(_),
            ..
        }
    ));
    assert_eq!(
        state_after, state_before,
        "unknown key must not change state"
    );

    // Sub-case: expired at submission time.
    let far_future = now + Duration::days(400);
    let (state_after, outcome) = apply_bundle(&state_before, &good_envelope, &trust, far_future);
    assert!(matches!(
        outcome,
        ActivationOutcome::Rejected {
            rejection: ActivationRejection::NotVerified(BundleRejection::BundleExpired { .. }),
            ..
        }
    ));
    assert_eq!(
        state_after, state_before,
        "expired bundle must not change state"
    );

    // Sub-case: oversized payload.
    let oversized_envelope = serde_json::json!({
        "bundle_schema_version": super::bundle::BUNDLE_SCHEMA_VERSION,
        "payload_b64": base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            vec![0u8; super::bundle::MAX_PAYLOAD_BYTES + 1],
        ),
        "signatures": [{
            "key_id": "k1",
            "algorithm": "ed25519",
            "signature_b64": sign_domain(&[0u8; 64], &sk),
        }],
    });
    let oversized_bytes = serde_json::to_vec(&oversized_envelope).unwrap();
    let (state_after, outcome) = apply_bundle(&state_before, &oversized_bytes, &trust, now);
    assert!(matches!(
        outcome,
        ActivationOutcome::Rejected {
            rejection: ActivationRejection::NotVerified(BundleRejection::PayloadTooLarge { .. }),
            ..
        }
    ));
    assert_eq!(
        state_after, state_before,
        "oversized payload must not change state"
    );
}

#[test]
fn t56_sequence_below_high_water_is_rejected() {
    let sk = primary_signing_key();
    let policy_id = Uuid::from_u128(56);
    let (env5, trust) = make_bundle("issuer-a", 5, policy_id, "k1", &sk);
    let now = base_now();
    let (state, _) = apply_bundle(&empty_state(), &env5, &trust, now);

    let (env3, _trust3) = make_bundle("issuer-a", 3, policy_id, "k1", &sk);
    let (state_after, outcome) = apply_bundle(&state, &env3, &trust, now);
    assert!(matches!(
        outcome,
        ActivationOutcome::Rejected {
            rejection: ActivationRejection::SequenceNotAdvanced { .. },
            ..
        }
    ));
    assert_eq!(state_after, state);
}

#[test]
fn t57_resubmitting_same_sequence_and_bytes_confirms_and_advances_confirmed_at() {
    let sk = primary_signing_key();
    let policy_id = Uuid::from_u128(57);
    let (env, trust) = make_bundle("issuer-a", 1, policy_id, "k1", &sk);
    let now = base_now();
    let (state, _) = apply_bundle(&empty_state(), &env, &trust, now);
    let original_confirmed_at = state.active.as_ref().unwrap().members[0].confirmed_at;

    let later = now + Duration::hours(1);
    let (state_after, outcome) = apply_bundle(&state, &env, &trust, later);
    match outcome {
        ActivationOutcome::Confirmed {
            policy_id: pid,
            confirmed_at,
            ..
        } => {
            assert_eq!(pid, PolicyId(policy_id));
            assert_eq!(confirmed_at, later);
        }
        other => panic!("expected Confirmed, got {other:?}"),
    }
    let new_confirmed_at = state_after.active.as_ref().unwrap().members[0].confirmed_at;
    assert_eq!(new_confirmed_at, later);
    assert_ne!(new_confirmed_at, original_confirmed_at);
}

#[test]
fn t58_same_sequence_different_bytes_is_sequence_reused() {
    let sk = primary_signing_key();
    let policy_id = Uuid::from_u128(58);
    let (env1, trust) = make_bundle("issuer-a", 1, policy_id, "k1", &sk);
    let now = base_now();
    let (state, _) = apply_bundle(&empty_state(), &env1, &trust, now);

    // A different bundle at the SAME sequence (different bundle_id/content).
    let (env1b, _trust1b) = make_bundle("issuer-a", 1, policy_id, "k1", &sk);
    let (state_after, outcome) = apply_bundle(&state, &env1b, &trust, now);
    assert!(matches!(
        outcome,
        ActivationOutcome::Rejected {
            rejection: ActivationRejection::SequenceReused { .. },
            ..
        }
    ));
    assert_eq!(state_after, state);
}

#[test]
fn t59_high_water_survives_rollback() {
    let sk = primary_signing_key();
    let policy_id = Uuid::from_u128(59);
    let now = base_now();

    let (env5, trust) = make_bundle("issuer-a", 5, policy_id, "k1", &sk);
    let (state, _) = apply_bundle(&empty_state(), &env5, &trust, now);

    let (env7, _) = make_bundle("issuer-a", 7, policy_id, "k1", &sk);
    let (state, _) = apply_bundle(&state, &env7, &trust, now);

    // Rollback: active <- last_known_good; high-water rows untouched.
    let mut rolled_back = state.clone();
    rolled_back.active = state.last_known_good.clone();
    rolled_back.pending = None;

    let (env6, _) = make_bundle("issuer-a", 6, policy_id, "k1", &sk);
    let (state_after, outcome) = apply_bundle(&rolled_back, &env6, &trust, now);
    assert!(
        matches!(
            outcome,
            ActivationOutcome::Rejected {
                rejection: ActivationRejection::SequenceNotAdvanced { .. },
                ..
            }
        ),
        "high-water (max_sequence=7) must still reject sequence 6 after rollback"
    );
    assert_eq!(
        state_after
            .high_water
            .get(&("issuer-a".to_string(), PolicyId(policy_id)))
            .unwrap()
            .max_sequence,
        7,
        "rollback must never lower the high-water mark"
    );
}

#[test]
fn t60_cross_lineage_independence() {
    let sk = primary_signing_key();
    let p1 = Uuid::from_u128(601);
    let p2 = Uuid::from_u128(602);
    let now = base_now();

    let (env_p1, trust) = make_bundle("issuer-a", 7, p1, "k1", &sk);
    let (state, outcome1) = apply_bundle(&empty_state(), &env_p1, &trust, now);
    assert!(matches!(outcome1, ActivationOutcome::Activated { .. }));

    let (env_p2, _) = make_bundle("issuer-a", 6, p2, "k1", &sk);
    let (state_after, outcome2) = apply_bundle(&state, &env_p2, &trust, now);
    assert!(
        matches!(outcome2, ActivationOutcome::Activated { .. }),
        "a different policy_id lineage from the same issuer must not be blocked by p1's high-water"
    );
    assert_eq!(state_after.active.unwrap().members.len(), 2);
}

#[test]
fn t61_issuer_mismatch_for_lineage_is_rejected() {
    let sk = primary_signing_key();
    let policy_id = Uuid::from_u128(61);
    let now = base_now();

    let (env_a, trust_a) = make_bundle("issuer-a", 1, policy_id, "k1", &sk);
    let (state, _) = apply_bundle(&empty_state(), &env_a, &trust_a, now);

    let (env_b, trust_b) = make_bundle("issuer-b", 1, policy_id, "k1", &sk);
    let candidate_b = verify(&env_b, &trust_b, now);
    let rejection = evaluate_activation(&candidate_b, &state, now).unwrap_err();
    assert!(matches!(
        rejection,
        ActivationRejection::IssuerMismatchForLineage { .. }
    ));
}

#[test]
fn t62_multi_lineage_generation_preserves_independent_confirmed_at() {
    let sk = primary_signing_key();
    let p1 = Uuid::from_u128(621);
    let p2 = Uuid::from_u128(622);
    let now = base_now();

    let (env_p1, trust) = make_bundle("issuer-a", 1, p1, "k1", &sk);
    let (state, _) = apply_bundle(&empty_state(), &env_p1, &trust, now);
    let (env_p2, _) = make_bundle("issuer-a", 1, p2, "k1", &sk);
    let (state, _) = apply_bundle(&state, &env_p2, &trust, now);

    let later = now + Duration::hours(2);
    let (state_after, _) = apply_bundle(&state, &env_p1, &trust, later);

    let active = state_after.active.unwrap();
    let m1 = active
        .members
        .iter()
        .find(|m| m.policy_id == PolicyId(p1))
        .unwrap();
    let m2 = active
        .members
        .iter()
        .find(|m| m.policy_id == PolicyId(p2))
        .unwrap();
    assert_eq!(m1.confirmed_at, later, "p1 was re-confirmed");
    assert_eq!(
        m2.confirmed_at, now,
        "p2's clock must be untouched by p1's confirm"
    );
}

#[test]
fn t63_into_bound_revisions_failure_leaves_cache_untouched() {
    let sk = primary_signing_key();
    let now = base_now();

    // A revision with a pinned field, bound at TargetLevel::LocalUser --
    // BoundRevision::new (via into_bound_revisions) rejects this with
    // PinAtLocalUserLayer.
    let content = cloud_sync_content(true);
    let mut d = draft(content);
    d.policy_id = PolicyId(Uuid::from_u128(63));
    d.revision = 1;
    d.pinned_fields = {
        let mut s = std::collections::BTreeSet::new();
        s.insert(super::resolve::PolicyFieldId::EgressCloudSyncAllowed);
        s
    };
    let revision = d.publish("2026-01-01T00:00:00Z".to_string()).unwrap();
    let binding = super::target::PolicyBinding {
        binding_id: Uuid::new_v4(),
        scope: super::target::TargetScope::LocalUser,
        selector: super::target::TargetSelector::default(),
        revision_ref: revision.reference(),
    };
    let payload = BundlePayload {
        bundle_schema_version: super::bundle::BUNDLE_SCHEMA_VERSION,
        bundle_id: Uuid::new_v4(),
        sequence: 1,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        not_before: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        provenance: BundleProvenance {
            issuer: "issuer-a".to_string(),
            audit_ref: None,
            authorized_by: None,
        },
        revision,
        bindings: vec![binding],
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let sig = valid_signature_entry("k1", &payload_bytes, &sk);
    let envelope = build_envelope_bytes(&payload_bytes, vec![sig]);
    let trust = trust_store(vec![trusted_key_for("k1", &sk, None, None)]);

    let state = empty_state();
    let (state_after, outcome) = apply_bundle(&state, &envelope, &trust, now);
    assert!(matches!(
        outcome,
        ActivationOutcome::Rejected {
            rejection: ActivationRejection::BindingsUnusable(_),
            ..
        }
    ));
    assert_eq!(
        state_after, state,
        "cache must be untouched by a bindings failure"
    );
}

// ============================================================================
// T64-T67 -- risk-class-differentiated expiry
// ============================================================================

fn cached_ref(
    policy_id: Uuid,
    confirmed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> CachedBundleRef {
    CachedBundleRef {
        bundle_id: Uuid::new_v4(),
        issuer: "issuer-a".to_string(),
        sequence: 1,
        policy_id: PolicyId(policy_id),
        revision: 1,
        revision_digest: super::revision::digest_of(&super::revision::PolicyRevisionBody {
            schema_version: super::content::POLICY_SCHEMA_VERSION,
            policy_id: PolicyId(policy_id),
            revision: 1,
            supersedes: None,
            published_at: "2026-01-01T00:00:00Z".to_string(),
            display_name: "x".to_string(),
            content: super::content::PolicyContent::default(),
            pinned_fields: std::collections::BTreeSet::new(),
        }),
        payload_digest: payload_digest_of("sha256:test-fixture-payload-digest"),
        verified_by: KeyId("k1".to_string()),
        not_before: confirmed_at,
        expires_at,
        first_activated_at: confirmed_at,
        confirmed_at,
    }
}

/// `PayloadDigest`'s single field is private (constructed only by
/// `bundle::verify_bundle`'s internal hashing) but derives `Deserialize` as
/// a transparent newtype, so a fixture value can be built the same way
/// `fornax-store` reconstructs one from a persisted TEXT column.
fn payload_digest_of(s: &str) -> PayloadDigest {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap()
}

fn seconds(low: u32, elevated: u32, high: u32, critical: u32) -> RiskClassSeconds {
    RiskClassSeconds {
        low,
        elevated,
        high,
        critical,
    }
}

#[test]
fn t64_risk_classes_diverge_at_the_same_now() {
    let confirmed_at: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
    let expires_at = confirmed_at + Duration::days(365);
    let member = cached_ref(Uuid::from_u128(64), confirmed_at, expires_at);
    // low=1000s, elevated=1000s, high=100s, critical=50s; now is 500s later.
    let max_age = seconds(1000, 1000, 100, 50);
    let now = confirmed_at + Duration::seconds(500);
    let mf = member_freshness(&member, max_age, 10_000, now);
    assert_eq!(mf.tier_by_risk.low, FreshnessTier::Fresh);
    assert_eq!(mf.tier_by_risk.elevated, FreshnessTier::Fresh);
    assert_eq!(mf.tier_by_risk.high, FreshnessTier::Stale);
}

#[test]
fn t65_grace_expired_only_past_confirmed_at_plus_max_age_plus_grace() {
    let confirmed_at: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
    let expires_at = confirmed_at + Duration::days(365);
    let member = cached_ref(Uuid::from_u128(65), confirmed_at, expires_at);
    let max_age = seconds(100, 100, 100, 100);
    let grace = 100u32;

    let just_stale = confirmed_at + Duration::seconds(150);
    let mf = member_freshness(&member, max_age, grace, just_stale);
    assert_eq!(mf.tier_by_risk.low, FreshnessTier::Stale);

    let past_grace = confirmed_at + Duration::seconds(300);
    let mf = member_freshness(&member, max_age, grace, past_grace);
    assert_eq!(mf.tier_by_risk.low, FreshnessTier::GraceExpired);
}

#[test]
fn t66_now_past_expires_at_alone_yields_exactly_stale_never_grace_expired() {
    let confirmed_at: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
    let expires_at = confirmed_at + Duration::seconds(10);
    let member = cached_ref(Uuid::from_u128(66), confirmed_at, expires_at);
    // max_age is huge (so confirmed_at + max_age is far in the future) --
    // only expires_at forces staleness here.
    let max_age = seconds(1_000_000, 1_000_000, 1_000_000, 1_000_000);
    let now = confirmed_at + Duration::seconds(20);
    let mf = member_freshness(&member, max_age, 1_000_000, now);
    assert_eq!(mf.tier_by_risk.low, FreshnessTier::Stale);
    assert_eq!(mf.tier_by_risk.critical, FreshnessTier::Stale);
}

#[test]
fn t67_generation_tier_is_the_strictest_member() {
    let confirmed_at: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
    let far_expiry = confirmed_at + Duration::days(365);
    let fresh_member = cached_ref(Uuid::from_u128(671), confirmed_at, far_expiry);
    let stale_member = cached_ref(
        Uuid::from_u128(672),
        confirmed_at - Duration::seconds(10_000),
        far_expiry,
    );
    let max_age = seconds(100_000, 100_000, 100_000, 100_000);
    let now = confirmed_at + Duration::seconds(1);
    let members = vec![fresh_member, stale_member];
    let pf = freshness(&members, true, max_age, 100_000, now);
    // stale_member is already 10_001s old at `now`, still under
    // max_age+grace (200_000s) so it reads Fresh too here; recompute with a
    // grace that makes it GraceExpired to prove the meet picks it up.
    let pf2 = freshness(&members, true, seconds(100, 100, 100, 100), 0, now);
    assert_eq!(pf2.tier_by_risk.low, FreshnessTier::GraceExpired);
    assert_eq!(pf.members.len(), 2);
}

// ============================================================================
// T68-T70 -- floor properties
// ============================================================================

#[test]
fn t68_floor_never_loosens_the_resolved_outcome() {
    let risks = [
        RiskClass::Low,
        RiskClass::Elevated,
        RiskClass::High,
        RiskClass::Critical,
    ];
    let tiers = [
        FreshnessTier::Unconfigured,
        FreshnessTier::Fresh,
        FreshnessTier::Stale,
        FreshnessTier::GraceExpired,
    ];
    let outcomes = [
        EnforcementOutcome::Allow,
        EnforcementOutcome::ObserveOnly,
        EnforcementOutcome::Warn,
        EnforcementOutcome::Block,
    ];
    for &risk in &risks {
        for &tier in &tiers {
            for &outcome in &outcomes {
                let effective = effective_outcome(outcome, risk, tier);
                assert!(
                    effective >= outcome,
                    "effective_outcome({outcome:?}, {risk:?}, {tier:?}) = {effective:?} must be >= {outcome:?}"
                );
            }
        }
    }
}

#[test]
fn t69_unconfigured_has_no_floor_and_grace_expired_baseline_has_floors() {
    for risk in [
        RiskClass::Low,
        RiskClass::Elevated,
        RiskClass::High,
        RiskClass::Critical,
    ] {
        assert_eq!(staleness_floor(risk, FreshnessTier::Unconfigured), None);
    }
    // ever_configured + no usable member -> GraceExpired floors apply to
    // the baseline resolved value.
    let members: Vec<CachedBundleRef> = Vec::new();
    let pf = freshness(&members, true, seconds(1, 1, 1, 1), 1, base_now());
    assert_eq!(pf.tier_by_risk.critical, FreshnessTier::GraceExpired);
    assert_eq!(
        effective_outcome(
            EnforcementOutcome::Allow,
            RiskClass::Critical,
            pf.tier_by_risk.critical
        ),
        EnforcementOutcome::Block
    );

    let pf_unconfigured = freshness(&members, false, seconds(1, 1, 1, 1), 1, base_now());
    assert_eq!(
        pf_unconfigured.tier_by_risk.critical,
        FreshnessTier::Unconfigured
    );
    assert_eq!(
        effective_outcome(
            EnforcementOutcome::Allow,
            RiskClass::Critical,
            pf_unconfigured.tier_by_risk.critical
        ),
        EnforcementOutcome::Allow,
        "a fresh install must not silently gain blocking power"
    );
}

#[test]
fn t70_unmatched_action_class_reads_observe_only_at_every_tier() {
    use super::content::{ActionClass, ResolvedValues};
    use super::resolve::{FieldProvenance, PolicyFieldId, ResolvedPolicy};
    use crate::Verdict;

    let resolved = ResolvedPolicy {
        values: ResolvedValues {
            enforcement_rules: Vec::new(),
            ..super::content::PolicyContent::baseline()
        },
        provenance: PolicyFieldId::ALL
            .into_iter()
            .map(|f| (f, FieldProvenance::Baseline))
            .collect(),
        contributing: Vec::new(),
    };

    for tier in [
        FreshnessTier::Unconfigured,
        FreshnessTier::Fresh,
        FreshnessTier::Stale,
        FreshnessTier::GraceExpired,
    ] {
        let ep = EffectivePolicy {
            resolved: resolved.clone(),
            freshness: PolicyFreshness {
                tier_by_risk: RiskClassTiers::uniform(tier),
                members: Vec::new(),
                evaluated_at: base_now(),
            },
        };
        assert_eq!(
            ep.enforcement_outcome_for(&ActionClass::ShellCommand, Verdict::Contradicted),
            EnforcementOutcome::ObserveOnly
        );
    }
}
