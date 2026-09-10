//! FORNX-323 (epic FORNX-70 Release Gate): a broader adversarial sweep
//! against the audit ledger (FORNX-315, `fornax-store::audit_ledger`) and
//! audit checkpoints (FORNX-317, `fornax-store::audit_checkpoint` +
//! `fornax-types::audit_checkpoint`), beyond the four basic mutations
//! `audit_ledger.rs`'s own test module already covers (payload edit,
//! middle-row delete, tail truncation, prev_hash relink) and the
//! flat-vs-nested / domain-confusion regressions
//! `fornax-types::audit_checkpoint`'s own test module already covers.
//!
//! This file adds NO product surface. It only attacks what FORNX-315/317
//! already built, through the crates' own public APIs plus a second raw
//! `sqlx::SqlitePool` opened against the same on-disk file -- exactly the
//! "direct SQLite access, bypassing this crate's own API" attacker model
//! `audit_ledger.rs`'s own trust-boundary doc comment already names.
//!
//! Every test here proves either a **detection** (a broader adversarial
//! sweep of the same class the existing tests cover) or an **honest,
//! explicit limitation** (a mutation class the existing design cannot and
//! does not claim to catch) -- never a false guarantee. See
//! `docs/release/v0.7.0-audit-integrity-gate-signoff.md` for the release-gate
//! mapping of test name -> claim.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use fornax_store::{ChainVerification, CheckpointConsistencyVerdict, DivergenceKind, Store};
use fornax_types::policy::{
    BundleSignature, KeyId, SignatureAlgorithm, TrustedKey, TrustedVerificationKeys,
};
use fornax_types::{
    verify_audit_checkpoint, AuditAction, AuditActor, AuditCheckpointPayload, AuditEvent,
    AuditExportClass, AuditOutcome, AuditTarget, DeviceReportedChainStatus, LedgerHead,
    SignedAuditCheckpoint, AUDIT_CHECKPOINT_SCHEMA_VERSION, AUDIT_CHECKPOINT_SIGNING_DOMAIN,
};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use uuid::Uuid;

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

fn tmp_db_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fornax-daemon-audit-integrity-gate-{name}-{}.db",
        Uuid::new_v4()
    ))
}

fn now() -> chrono::DateTime<chrono::Utc> {
    "2026-09-03T00:00:00Z".parse().unwrap()
}

fn sample_event(n: usize) -> AuditEvent {
    AuditEvent::new(
        format!("event-{n}"),
        "2026-09-03T00:00:00Z",
        AuditActor::Device {
            actor_id: format!("device-{n}"),
        },
        AuditAction::PermissionCheck,
        AuditTarget::Permission {
            target_id: format!("perm-{n}"),
        },
        AuditOutcome::Granted,
        AuditExportClass::Metadata,
    )
}

/// A second, independent connection pool against the SAME on-disk SQLite
/// file `Store` already opened -- the "direct SQLite access, bypassing this
/// crate's own API" attacker model that `audit_ledger.rs`'s own
/// trust-boundary doc comment names. `fornax_store::Store::pool` is
/// `pub(crate)`, deliberately not visible outside that crate, so an
/// external attacker (and this external integration test) can only ever
/// reach the database through a route like this one -- opening the file
/// directly -- never through `Store`'s own field.
async fn raw_pool(path: &std::path::Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .connect(&format!("sqlite:{}", path.display()))
        .await
        .expect("open raw second connection to the same sqlite file")
}

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

/// Builds a real, independently-verifiable `SignedAuditCheckpoint` envelope
/// attesting `head_ledger_seq`/`head_entry_hash`, signs it, and runs it
/// through `fornax_types::verify_audit_checkpoint` -- the same flow
/// `fornax-daemon`'s real submission path follows, and the same helper
/// shape `fornax-store::audit_checkpoint`'s own `store_integration_tests`
/// module uses -- reproduced here because that module is private to
/// `fornax-store` and not visible to this external integration test crate.
fn verified_checkpoint(
    key_id: &str,
    key: &SigningKey,
    checkpoint_seq: u64,
    head_ledger_seq: i64,
    head_entry_hash: &str,
    device_id: &str,
) -> (fornax_types::VerifiedAuditCheckpoint, Vec<u8>) {
    let payload = AuditCheckpointPayload {
        checkpoint_schema_version: AUDIT_CHECKPOINT_SCHEMA_VERSION,
        issuer: "fornax-cloud:org-1".to_string(),
        device_id: device_id.to_string(),
        checkpoint_seq,
        issued_at: "2026-09-03T00:00:05Z".to_string(),
        observed_at: "2026-09-03T00:00:00Z".to_string(),
        head: LedgerHead {
            ledger_seq: head_ledger_seq,
            entry_hash: head_entry_hash.to_string(),
        },
        device_reported_chain_status: DeviceReportedChainStatus {
            status: "valid".to_string(),
            first_bad_ledger_seq: None,
            divergence_kind: None,
        },
        prev_checkpoint: None,
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let mut signed_message = AUDIT_CHECKPOINT_SIGNING_DOMAIN.to_vec();
    signed_message.extend_from_slice(&payload_bytes);
    let signature = key.sign(&signed_message);
    let envelope = SignedAuditCheckpoint {
        checkpoint_schema_version: AUDIT_CHECKPOINT_SCHEMA_VERSION,
        payload_b64: B64.encode(&payload_bytes),
        signatures: vec![BundleSignature {
            key_id: KeyId(key_id.to_string()),
            algorithm: SignatureAlgorithm::Ed25519,
            signature_b64: B64.encode(signature.to_bytes()),
        }],
    };
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    let trusted = trust_store(key_id, key);
    let verified = verify_audit_checkpoint(&envelope_bytes, &trusted, now())
        .expect("hand-built checkpoint must verify");
    (verified, envelope_bytes)
}

// ---------------------------------------------------------------------
// 1. Seq reuse -- prevented, not merely detected
// ---------------------------------------------------------------------

/// Attack: a direct-SQL attacker attempts to insert a SECOND row occupying
/// a `seq` value that already exists (e.g. to make an inserted forged row
/// "hide" alongside a real one at the same position).
///
/// Finding, stated honestly: `audit_events.seq` is declared `INTEGER
/// PRIMARY KEY` (`migrations/0010_audit_ledger.sql`), which SQLite aliases
/// to the table's `rowid` -- a literal second row at the same `seq` is not
/// a state `verify_audit_chain` has to notice after the fact, because
/// SQLite's own uniqueness constraint refuses to create it in the first
/// place. This is a STRONGER guarantee than detection (prevention beats
/// detection), so this test proves prevention rather than asserting a
/// `ChainVerification::Diverged` result that would never actually be
/// reached.
#[tokio::test]
async fn direct_sql_seq_reuse_insert_is_rejected_by_the_primary_key_constraint() {
    let path = tmp_db_path("seq-reuse");
    let store = Store::open(&path).await.expect("open db");
    for i in 0..5 {
        store
            .append_audit_event(&sample_event(i), now())
            .await
            .expect("append event");
    }

    let raw = raw_pool(&path).await;

    // Attempt to insert a second row at seq=3 (already occupied), reusing
    // arbitrary-but-well-formed-looking column values. Any content works
    // here -- the point under test is whether the insert is even accepted,
    // not what it would contain if it were.
    let result = sqlx::query(
        "INSERT INTO audit_events (seq, event_id, recorded_at, prev_hash, entry_hash, export_class, payload)
         VALUES (3, 'forged-duplicate', ?1, 'sha256:deadbeef', 'sha256:deadbeef', 'metadata', ?2)",
    )
    .bind(now().to_rfc3339())
    .bind(serde_json::to_string(&sample_event(999)).unwrap())
    .execute(&raw)
    .await;

    assert!(
        result.is_err(),
        "a duplicate seq=3 row must be rejected outright by the PRIMARY KEY constraint, \
         never silently accepted for verify_audit_chain to notice later"
    );

    // The chain is untouched by the rejected attempt and remains Valid.
    let verification = store.verify_audit_chain().await.expect("verify chain");
    assert_eq!(verification, ChainVerification::Valid);

    raw.close().await;
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// 2. Out-of-order insert that skips the high-water mechanism entirely
// ---------------------------------------------------------------------

/// Attack: rather than reusing an existing `seq`, a direct-SQL attacker
/// inserts a row at a `seq` far ahead of the current tail (e.g. `seq=15`
/// when only 1..=10 exist), entirely bypassing
/// `append_audit_event_locked`'s high-water allocation. This differs from
/// the existing `TruncatedTail` coverage (which deletes trailing rows) --
/// here a row is ADDED, creating an internal gap AND leaving the
/// high-water marker (`10`) stale relative to the new max `seq` (`15`).
///
/// Expected: the very next row after the real tail is checked against
/// `expected_seq` (`GENESIS_SEQ + index`) in the same linear scan that
/// already exists -- the gap at seq=11 is caught as `MissingSeq`, exactly
/// the same taxonomy the deleted-middle-row case uses, because from the
/// verifier's point of view "a slot that should be occupied isn't" is the
/// same fact whether the row was deleted or simply never inserted in
/// order.
#[tokio::test]
async fn direct_sql_out_of_order_insert_skipping_high_water_is_detected_as_missing_seq() {
    let path = tmp_db_path("out-of-order-insert");
    let store = Store::open(&path).await.expect("open db");
    for i in 0..10 {
        store
            .append_audit_event(&sample_event(i), now())
            .await
            .expect("append event");
    }

    let raw = raw_pool(&path).await;
    sqlx::query(
        "INSERT INTO audit_events (seq, event_id, recorded_at, prev_hash, entry_hash, export_class, payload)
         VALUES (15, 'forged-out-of-order', ?1, 'sha256:deadbeef', 'sha256:deadbeef', 'metadata', ?2)",
    )
    .bind(now().to_rfc3339())
    .bind(serde_json::to_string(&sample_event(999)).unwrap())
    .execute(&raw)
    .await
    .expect("insert a far-ahead seq directly via raw SQL");

    let verification = store.verify_audit_chain().await.expect("verify chain");
    assert_eq!(
        verification,
        ChainVerification::Diverged {
            first_bad_seq: 11,
            kind: DivergenceKind::MissingSeq,
        },
        "an out-of-order insert that skips the high-water mechanism must surface as a gap \
         at the first seq after the real tail, not as a silently accepted extra row"
    );

    raw.close().await;
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// 3. Whole-file replacement -- honest limitation, and what closes it
// ---------------------------------------------------------------------

/// Attack: an attacker with full filesystem access replaces the ENTIRE
/// `fornax.db` file with a different, internally self-consistent chain --
/// its own genesis, its own valid sequence, all hashes internally correct.
///
/// Part A (the honest limitation): `verify_audit_chain` on the replacement
/// file reports `Valid`. This is not a bug to fix -- it is exactly what
/// `audit_ledger.rs`'s own trust-boundary doc comment already says: the
/// chain "only binds *this store's own rows to each other*, not to any
/// ground truth outside the store." A wholesale file swap, with no
/// external reference point, is undetectable by the local chain alone BY
/// DESIGN. This test asserts that limitation explicitly rather than
/// silently relying on it.
///
/// Part B (what actually closes the gap): a verifier holding a checkpoint
/// receipt from the ORIGINAL chain (ADR-0012 -- an external witness,
/// recoverable from the cloud independent of the local file, see ADR-0012
/// §7.4/§8.1) is NOT fooled. Comparing the replacement chain's current
/// state against the original checkpoint's attested
/// `head_ledger_seq`/`head_entry_hash` via
/// `evaluate_checkpoint_consistency` -- the exact ADR-0012 §8.2 function --
/// surfaces the swap as `AnchorMissing` (the replacement chain is shorter
/// than the attested head) or `AnchorRewritten` (a same-length or longer
/// replacement, whose row at the attested seq holds different content).
/// Both are exercised.
#[tokio::test]
async fn whole_file_replacement_is_invisible_to_the_local_chain_alone_but_caught_by_a_prior_checkpoint(
) {
    // --- Original chain: 10 events, checkpoint anchored at the tail. ---
    let original_path = tmp_db_path("whole-file-replacement-original");
    let original_store = Store::open(&original_path).await.expect("open original db");
    let mut tail = None;
    for i in 0..10 {
        tail = Some(
            original_store
                .append_audit_event(&sample_event(i), now())
                .await
                .expect("append original event"),
        );
    }
    let original_tail = tail.expect("at least one event appended");

    // A verifier (standing in for "the cloud", per ADR-0012 -- an external
    // witness independent of the local file) holds a REAL, independently
    // verified checkpoint attesting the original tail. It is never written
    // into `original_path` at all, matching ADR-0012 §8.1's own note that
    // "local receipt storage is not the trust anchor" -- the prior
    // knowledge under test here lives entirely outside the file that gets
    // replaced.
    let key = signing_key(51);
    let (verified_checkpoint_of_original, _envelope_bytes) = verified_checkpoint(
        "k1",
        &key,
        1,
        original_tail.seq,
        &original_tail.entry_hash,
        "device-abc",
    );

    // --- Attack: replace the WHOLE file with a different, shorter, but
    // internally self-consistent chain (its own genesis, own sequence). ---
    std::fs::remove_file(&original_path).expect("remove original file to simulate replacement");
    let replacement_store = Store::open(&original_path)
        .await
        .expect("open replacement db at the same path");
    for i in 0..3 {
        replacement_store
            .append_audit_event(&sample_event(1000 + i), now())
            .await
            .expect("append replacement event");
    }

    // Part A: the local chain alone reports Valid -- it has no idea a swap
    // ever happened, by design.
    let local_only_verdict = replacement_store
        .verify_audit_chain()
        .await
        .expect("verify replacement chain");
    assert_eq!(
        local_only_verdict,
        ChainVerification::Valid,
        "PROVING THE LIMITATION: a wholesale file replacement with an internally \
         self-consistent replacement chain is, by design, invisible to local chain \
         verification alone -- there is no ground truth outside the store for it to \
         compare against. This is not a gap in the test; it is the documented trust \
         boundary in audit_ledger.rs's module doc."
    );

    // Part B: a verifier that also holds the ORIGINAL checkpoint is not
    // fooled. Query the row current occupying the attested seq (10) in the
    // REPLACEMENT file directly -- only 3 rows exist, so there is none.
    let raw = raw_pool(&original_path).await;
    let row_entry_hash_at_head: Option<String> =
        sqlx::query_scalar("SELECT entry_hash FROM audit_events WHERE seq = ?1")
            .bind(original_tail.seq)
            .fetch_optional(&raw)
            .await
            .expect("query replacement file for the attested seq");
    assert_eq!(
        row_entry_hash_at_head, None,
        "the replacement chain is shorter than the attested head"
    );

    let anchored_verdict = fornax_store::evaluate_checkpoint_consistency(
        &local_only_verdict,
        verified_checkpoint_of_original.head().ledger_seq,
        &verified_checkpoint_of_original.head().entry_hash,
        row_entry_hash_at_head.as_deref(),
    );
    assert_eq!(
        anchored_verdict,
        CheckpointConsistencyVerdict::AnchorMissing,
        "a checkpoint-anchored verifier DOES catch the whole-file replacement, \
         via AnchorMissing, exactly as ADR-0012 section 8.2 row 3 specifies"
    );

    // Variant: a same-length-or-longer replacement (10 events, so a row
    // DOES occupy the attested seq=10) is caught as AnchorRewritten instead,
    // since its content necessarily differs from the original.
    std::fs::remove_file(&original_path).expect("remove file for the second replacement variant");
    let replacement_store_2 = Store::open(&original_path)
        .await
        .expect("open second replacement db");
    let mut replacement_2_tail = None;
    for i in 0..10 {
        replacement_2_tail = Some(
            replacement_store_2
                .append_audit_event(&sample_event(2000 + i), now())
                .await
                .expect("append second replacement event"),
        );
    }
    let replacement_2_tail = replacement_2_tail.expect("at least one event appended");
    assert_ne!(
        replacement_2_tail.entry_hash, original_tail.entry_hash,
        "the second replacement's row at the same seq must actually differ in content"
    );

    let chain_2 = replacement_store_2
        .verify_audit_chain()
        .await
        .expect("verify second replacement chain");
    assert_eq!(chain_2, ChainVerification::Valid);

    let raw_2 = raw_pool(&original_path).await;
    let row_entry_hash_at_head_2: Option<String> =
        sqlx::query_scalar("SELECT entry_hash FROM audit_events WHERE seq = ?1")
            .bind(original_tail.seq)
            .fetch_optional(&raw_2)
            .await
            .expect("query second replacement file for the attested seq");

    let anchored_verdict_2 = fornax_store::evaluate_checkpoint_consistency(
        &chain_2,
        verified_checkpoint_of_original.head().ledger_seq,
        &verified_checkpoint_of_original.head().entry_hash,
        row_entry_hash_at_head_2.as_deref(),
    );
    assert_eq!(
        anchored_verdict_2,
        CheckpointConsistencyVerdict::AnchorRewritten {
            attested: original_tail.entry_hash.clone(),
            found: replacement_2_tail.entry_hash.clone(),
        },
        "a same-length replacement is caught as AnchorRewritten, per ADR-0012 section 8.2 row 4"
    );

    raw.close().await;
    raw_2.close().await;
    std::fs::remove_file(&original_path).ok();
}

// ---------------------------------------------------------------------
// 4. Rollback-then-diverge against a receipted checkpoint (ADR-0012 §8.2
//    worked example, end to end with real stores)
// ---------------------------------------------------------------------

/// The exact ADR-0012 §8.2 worked example: rewind the ledger to before a
/// checkpointed head, then let the (unaware, still-running, legitimate)
/// process append different events. This combines `audit_ledger.rs` +
/// `audit_checkpoint.rs` end to end, with a real signed-and-verified
/// checkpoint receipt actually persisted via `Store::
/// store_audit_checkpoint_receipt` and a real `Store::
/// evaluate_all_checkpoint_receipts` call -- not the pure-function fixture
/// tests already in `audit_checkpoint.rs`'s own test module.
///
/// Attack shape, chosen to be realistic rather than requiring an attacker
/// with full process control (that stronger attacker -- one who can also
/// recompute hashes forward -- is already covered by
/// `evaluate_all_checkpoint_receipts_detects_a_real_anchor_rewrite` in
/// `fornax-store`'s own test suite, which produces `AnchorRewritten`, not
/// this test's `AttestedPrefixCorrupted`): an attacker with ONLY raw
/// SQLite file access (no ability to also recompute hashes forward, and no
/// ability to touch the monotonic, untouched-by-DELETE
/// `audit_ledger_high_water` marker -- see `audit_ledger.rs`'s own doc
/// comment for why that table is immune to this) deletes the tail past
/// seq=5. The legitimate daemon process, unaware of the tampering, later
/// appends a new event through `Store`'s own API -- which allocates its
/// `seq`/`prev_hash` from the untouched high-water marker (still `10`,
/// `entry_hash` of the real original seq=10 row), landing at `seq=11` with
/// a `prev_hash` naming a row that the deletion just erased. The result is
/// a real internal gap at seq=6, squarely inside the range the checkpoint
/// already attested (`head_ledger_seq=10`) -- `AttestedPrefixCorrupted`,
/// the strongest of the five §8.2 verdicts.
#[tokio::test]
async fn rollback_then_diverge_against_a_receipted_checkpoint_is_attested_prefix_corrupted() {
    let path = tmp_db_path("rollback-then-diverge");
    let store = Store::open(&path).await.expect("open db");

    let mut tail = None;
    for i in 0..10 {
        tail = Some(
            store
                .append_audit_event(&sample_event(i), now())
                .await
                .expect("append event"),
        );
    }
    let original_tail = tail.expect("at least one event appended");
    assert_eq!(original_tail.seq, 10);

    // A real, independently verified checkpoint is stored, anchored to the
    // tail -- exactly the flow `fornax-daemon`'s own submission path
    // follows (verify first, store only on Ok, per ADR-0012 §8.1).
    let key = signing_key(52);
    let (verified, envelope_bytes) = verified_checkpoint(
        "k1",
        &key,
        1,
        original_tail.seq,
        &original_tail.entry_hash,
        "device-abc",
    );
    let envelope_json = String::from_utf8(envelope_bytes).unwrap();
    store
        .store_audit_checkpoint_receipt(&verified, &envelope_json)
        .await
        .expect("store checkpoint receipt");

    // Sanity: before any tampering, the receipt is Consistent.
    let before = store
        .evaluate_all_checkpoint_receipts()
        .await
        .expect("evaluate before rollback");
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].1, CheckpointConsistencyVerdict::Consistent);

    // Attack: rewind to before the checkpointed head via raw SQL, deleting
    // everything after seq=5. `audit_ledger_high_water` is untouched --
    // this attacker has only DELETE access, not the ability to also
    // recompute or relink hashes forward.
    let raw = raw_pool(&path).await;
    sqlx::query("DELETE FROM audit_events WHERE seq > 5")
        .execute(&raw)
        .await
        .expect("rewind past the checkpointed head via raw SQL");

    // The legitimate process, unaware of the rollback, keeps running and
    // appends one more event through Store's own API.
    let post_rollback = store
        .append_audit_event(&sample_event(999), now())
        .await
        .expect("legitimate append after undetected rollback");
    assert_eq!(
        post_rollback.seq, 11,
        "the new row must continue from the untouched high-water mark (10), \
         not the rolled-back table's shortened max (5)"
    );

    // The local chain alone already reports a real divergence: a gap at
    // seq=6, since seq=11's prev_hash names the (now-deleted) real seq=10
    // row's hash, which is not what immediately follows seq=5 in the
    // ordered scan.
    let chain = store.verify_audit_chain().await.expect("verify chain");
    assert_eq!(
        chain,
        ChainVerification::Diverged {
            first_bad_seq: 6,
            kind: DivergenceKind::MissingSeq,
        }
    );

    // The checkpoint comparison classifies this correctly as the STRONGEST
    // verdict: the divergence (first_bad_seq=6) sits at-or-before the
    // attested head (head_ledger_seq=10), so the corruption lies INSIDE
    // the range the cloud already witnessed.
    let after = store
        .evaluate_all_checkpoint_receipts()
        .await
        .expect("evaluate after rollback");
    assert_eq!(after.len(), 1);
    assert_eq!(
        after[0].1,
        CheckpointConsistencyVerdict::AttestedPrefixCorrupted {
            first_bad_ledger_seq: 6,
            kind: DivergenceKind::MissingSeq,
        },
        "a rollback-then-diverge against a receipted checkpoint must be classified as \
         AttestedPrefixCorrupted, per ADR-0012 section 8.2 row 1"
    );

    raw.close().await;
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// 5. Boundary claims -- no overclaiming about what verification proves
// ---------------------------------------------------------------------

/// Source-inspection regression guard (mirroring `audit_ledger.rs`'s own
/// `no_write_path_other_than_append_audit_event_touches_audit_events` and
/// `module_doc_states_the_local_ledger_trust_boundary` precedent): asserts
/// that (a) the trust-boundary caveats this ADR/module set already commits
/// to are actually present in the specific files that are supposed to
/// carry them, and (b) no file anywhere in this repository's Rust source
/// or Markdown docs makes a STRONGER, uncaveated claim about what audit
/// chain verification or checkpoint anchoring proves -- e.g. that it
/// implies endpoint trustworthiness, completeness, or general
/// tamper-proofing.
///
/// This is necessarily a judgment call on which literal phrases count as
/// "overclaiming" -- the goal is a real regression guard against a future
/// log line, doc comment, CLI string, or report sentence quietly dropping
/// the caveat (e.g. "audit chain verified -- history is authentic and
/// complete"), not exhaustive natural-language understanding.
#[test]
fn no_source_or_doc_overclaims_what_audit_verification_proves() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/fornax-daemon is two levels below the workspace root")
        .to_path_buf();

    // --- Part A: the required caveats are present where they should be. ---
    let adr_0011 = std::fs::read_to_string(repo_root.join("docs/adr/0011-audit-event-model.md"))
        .expect("read ADR-0011");
    assert!(
        adr_0011.contains("does NOT attest that the endpoint recorded every event"),
        "ADR-0011 must keep stating the ledger does not attest completeness"
    );
    assert!(
        adr_0011.contains("does NOT make a compromised endpoint trustworthy"),
        "ADR-0011 must keep stating a compromised endpoint is not made trustworthy"
    );

    let adr_0012 = std::fs::read_to_string(repo_root.join("docs/adr/0012-audit-checkpoints.md"))
        .expect("read ADR-0012");
    assert!(
        adr_0012.contains("does not attest the device recorded every event"),
        "ADR-0012 must keep stating a checkpoint does not attest completeness"
    );
    assert!(
        adr_0012.contains("does not make a compromised endpoint trustworthy"),
        "ADR-0012 must keep stating a checkpoint does not make a compromised endpoint trustworthy"
    );
    assert!(
        adr_0012.contains("Nothing more."),
        "ADR-0012 must keep the 'witness statement... Nothing more' framing of what a \
         checkpoint is"
    );

    let audit_ledger_src =
        std::fs::read_to_string(repo_root.join("crates/fornax-store/src/audit_ledger.rs"))
            .expect("read audit_ledger.rs");
    assert!(
        audit_ledger_src.contains("does NOT attest that the endpoint recorded every event"),
        "audit_ledger.rs's module doc must keep the completeness caveat"
    );
    assert!(
        audit_ledger_src.contains("does NOT make a compromised endpoint trustworthy"),
        "audit_ledger.rs's module doc must keep the compromised-endpoint caveat"
    );

    let audit_checkpoint_store_src =
        std::fs::read_to_string(repo_root.join("crates/fornax-store/src/audit_checkpoint.rs"))
            .expect("read fornax-store's audit_checkpoint.rs");
    assert!(
        audit_checkpoint_store_src.contains("It also never")
            && audit_checkpoint_store_src.contains("attests completeness or endpoint honesty"),
        "fornax-store's audit_checkpoint.rs module doc must keep its own caveat, or point at \
         audit_ledger.rs's -- this exact phrase changed, update this assertion deliberately, \
         not accidentally"
    );

    // --- Part B: nothing else overclaims. ---
    //
    // Scan every tracked `.rs` and `.md` file (skipping build/vendor
    // output) for phrases that would assert a stronger guarantee than the
    // caveated one this codebase actually provides. Each phrase below is
    // deliberately absolutist and UNCAVEATED -- the caveat sentences
    // quoted above ("does NOT...", "not the trust anchor", etc.) contain
    // negations and so never match these positive-absolutist patterns.
    let overclaim_phrases = [
        "tamper-proof",
        "tamperproof",
        "tamper proof",
        "guarantees completeness",
        "guarantees integrity",
        "guarantees authenticity",
        "proves the endpoint",
        "trustworthy endpoint",
        "endpoint is trustworthy",
        "verified events are authentic",
        "immutable and complete",
        "complete audit trail",
        "provably complete",
        "cannot be tampered with",
        "impossible to tamper",
    ];

    // This test file, and this ticket's own release sign-off doc, both
    // legitimately quote every one of the phrases above verbatim -- as the
    // literal patterns under test, and as a description of them in the
    // sign-off's gate-item table, respectively. Exclude both from the scan
    // they describe/perform against everything else.
    let this_file =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/audit_integrity_gate.rs");
    let signoff_doc = repo_root.join("docs/release/v0.7.0-audit-integrity-gate-signoff.md");

    let mut offending: Vec<(String, &str)> = Vec::new();
    for entry in walk_source_and_doc_files(&repo_root) {
        if entry == this_file || entry == signoff_doc {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&entry) else {
            continue; // binary or non-UTF8 file, not a source/doc file we care about
        };
        let lower = contents.to_lowercase();
        for phrase in overclaim_phrases {
            if lower.contains(phrase) {
                offending.push((entry.display().to_string(), phrase));
            }
        }
    }

    assert!(
        offending.is_empty(),
        "found uncaveated overclaiming language about audit verification: {offending:#?}"
    );
}

/// Recursively lists every `.rs` and `.md` file under `root`, skipping
/// `target/`, `.git/`, and other non-source directories -- kept as a
/// small, dependency-free walker (no `walkdir` crate) mirroring this
/// crate's existing style of doing filesystem scans with `std::fs` alone.
fn walk_source_and_doc_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules", ".codegraph"];

    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !SKIP_DIRS.contains(&name) {
                    stack.push(path);
                }
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext == "rs" || ext == "md" {
                    out.push(path);
                }
            }
        }
    }
    out
}
