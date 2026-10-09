//! Persisted sibling of `fornax_types::provenance_guard`'s in-memory
//! `EvidenceConsumptionLedger` (FORNX-431 slice 2, parent FORNX-146).
//!
//! Slice 1 (`fornax-types::provenance_guard`) defined the pure decision
//! functions -- [`EvidenceOrigin`], [`SessionOwner`],
//! [`classify_consumption_by_anchor`] -- but has no cross-restart,
//! cross-process memory of its own. This module is that memory: a real
//! `ingress_origin` column on `evidence` (never a field the wire `Evidence`
//! type can set -- see `provenance_guard.rs`'s doc comment), and a durable
//! `evidence_consumption` table recording which claim first consumed which
//! evidence row.
//!
//! Deliberately standalone: nothing in `fornax-daemon` calls any of this
//! yet (that's slice 3's job), and `insert_evidence` does not yet stamp
//! `ingress_origin` (also slice 3) -- every row this slice reads back
//! today is `NULL`/`Unknown` in practice, exactly as intended for a
//! not-yet-wired column.

use chrono::Utc;
use fornax_types::provenance_guard::{
    classify_consumption_by_anchor, ClaimAnchor, EvidenceOrigin, ReplayVerdict, SessionOwner,
};
use fornax_types::{DatasetLineageTag, Provider, TenantRef};
use uuid::Uuid;

use crate::{insert_lineage_tag_row, retention, Result, Store, StoreError};

fn origin_from_column(raw: Option<String>) -> EvidenceOrigin {
    match raw.as_deref() {
        Some("uds_ingest") => EvidenceOrigin::UdsIngest,
        Some("daemon_acquisition") => EvidenceOrigin::DaemonAcquisition,
        Some("privileged_executor") => EvidenceOrigin::PrivilegedExecutor,
        // NULL (legacy/not-yet-stamped) and any other value both read back
        // as `Unknown` -- `admission_decision` always quarantines `Unknown`,
        // so an unrecognized value fails closed rather than silently
        // matching a trusted variant.
        _ => EvidenceOrigin::Unknown,
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ConsumptionOwnerRow {
    claim_id: String,
    session_id: String,
    anchor_event_id: String,
}

impl Store {
    /// How `evidence_id` was stamped at ingest, per the `ingress_origin`
    /// column (FORNX-431 slice 2). A missing row (the id doesn't exist at
    /// all) is indistinguishable from `Unknown` here deliberately -- the
    /// caller is asking "can I trust this row's origin", and a row this
    /// crate can't even find is certainly not trustworthy.
    pub async fn evidence_origin(&self, evidence_id: Uuid) -> Result<EvidenceOrigin> {
        let raw: Option<(Option<String>,)> =
            sqlx::query_as("SELECT ingress_origin FROM evidence WHERE id = ?1")
                .bind(evidence_id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        Ok(origin_from_column(raw.and_then(|(o,)| o)))
    }

    /// Who, if anyone, `session_id` has actually announced as its owning
    /// provider (FORNX-431 slice 2) -- read from the real
    /// `runtime_capabilities` announcements via
    /// [`Store::capabilities_for_session`], never guessed from any other
    /// signal. Zero announcements is [`SessionOwner::Unknown`]; more than
    /// one distinct provider is [`SessionOwner::Ambiguous`] (two adapters
    /// racing, or a forged announcement) -- fails closed, per
    /// `admission_decision`'s own doc comment.
    pub async fn session_owner(&self, session_id: &str) -> Result<SessionOwner> {
        let caps = self.capabilities_for_session(session_id).await?;
        let mut providers: Vec<Provider> = caps.into_iter().map(|c| c.provider).collect();
        providers.sort_by_key(|p| format!("{p:?}"));
        providers.dedup();
        Ok(match providers.len() {
            0 => SessionOwner::Unknown,
            1 => SessionOwner::Single(providers[0]),
            _ => SessionOwner::Ambiguous,
        })
    }

    /// Check-and-record one evidence-consumption attempt (FORNX-431 slice
    /// 2): is `evidence_id` already owned by a different claim's anchor,
    /// and if not, record `claim_id` as its new owner. `BEGIN IMMEDIATE`
    /// (matching `sweep_expired_records`/`delete_records_for_tenant`'s own
    /// precedent) acquires the write lock before the read, so two
    /// concurrent callers racing the same `evidence_id` are serialized by
    /// SQLite itself -- the second caller's transaction does not even begin
    /// executing its own `SELECT` until the first has committed, so it
    /// always sees the first's already-recorded owner. Only a genuinely
    /// fresh consumption inserts a row; every other verdict
    /// (`AlreadyConsumedBySameClaim`/`ReusedByRelatedClaim`/
    /// `ReplayedAcrossClaims`) is returned for the caller (a future slice)
    /// to act on -- this function never decides what a non-fresh verdict
    /// should do to the finding being computed.
    pub async fn record_consumption(
        &self,
        evidence_id: Uuid,
        claim_id: Uuid,
        anchor: &ClaimAnchor,
        verifier_name: Option<&str>,
    ) -> Result<ReplayVerdict> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        let existing: Option<ConsumptionOwnerRow> = sqlx::query_as(
            "SELECT claim_id, session_id, anchor_event_id FROM evidence_consumption
             WHERE evidence_id = ?1 AND outcome = 'consumed'
             ORDER BY recorded_at ASC LIMIT 1",
        )
        .bind(evidence_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;

        let existing_owner = existing
            .map(|row| -> Result<(Uuid, ClaimAnchor)> {
                let owner_claim_id = Uuid::parse_str(&row.claim_id).map_err(|e| {
                    StoreError::EvidenceConsumptionCorrupt(format!(
                        "claim_id {:?} is not a valid UUID: {e}",
                        row.claim_id
                    ))
                })?;
                let owner_event_id = Uuid::parse_str(&row.anchor_event_id).map_err(|e| {
                    StoreError::EvidenceConsumptionCorrupt(format!(
                        "anchor_event_id {:?} is not a valid UUID: {e}",
                        row.anchor_event_id
                    ))
                })?;
                Ok((owner_claim_id, (row.session_id, owner_event_id)))
            })
            .transpose()?;

        let verdict = classify_consumption_by_anchor(existing_owner, claim_id, anchor);

        if matches!(verdict, ReplayVerdict::FreshlyRecorded) {
            let id = Uuid::new_v4().to_string();
            let recorded_at = Utc::now().to_rfc3339();
            sqlx::query(
                "INSERT INTO evidence_consumption
                    (id, evidence_id, claim_id, session_id, anchor_event_id, verifier_name,
                     outcome, reason, recorded_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'consumed', NULL, ?7)
                 ON CONFLICT (evidence_id, claim_id) DO NOTHING",
            )
            .bind(&id)
            .bind(evidence_id.to_string())
            .bind(claim_id.to_string())
            .bind(&anchor.0)
            .bind(anchor.1.to_string())
            .bind(verifier_name)
            .bind(&recorded_at)
            .execute(&mut *tx)
            .await?;

            let lineage_tag = DatasetLineageTag::new(
                retention::retention_class_for_table("evidence_consumption"),
                TenantRef(anchor.0.clone()),
            );
            insert_lineage_tag_row(&mut *tx, "evidence_consumption", &id, &lineage_tag).await?;
        }

        tx.commit().await?;
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{AgentEvent, Claim, Evidence, EvidenceKind};

    async fn tmp_store(name: &str) -> (Store, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "fornax-evidence-consumption-{name}-{}.db",
            Uuid::new_v4()
        ));
        let store = Store::open(&path).await.expect("open db");
        (store, path)
    }

    async fn seed_evidence(store: &Store, session_id: &str) -> Uuid {
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            provider: Provider::ClaudeCode,
            kind: fornax_types::EventKind::PostToolUse,
            observed_at: Utc::now().to_rfc3339(),
            tool_name: None,
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        let ev = Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: Utc::now().to_rfc3339(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test-fixture".to_string(),
            source: None,
            extension: None,
            evidence_purged: false,
        };
        store.insert_evidence(&ev).await.expect("insert evidence");
        ev.id
    }

    fn claim_for(session_id: &str, source_event_id: Uuid) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            source_event_id,
            text: "tests passed".to_string(),
            subject: "test_result".to_string(),
            claimed_at: Utc::now().to_rfc3339(),
        }
    }

    #[tokio::test]
    async fn legacy_evidence_row_reads_back_as_unknown_origin() {
        let (store, path) = tmp_store("legacy-origin").await;
        let evidence_id = seed_evidence(&store, "s1").await;
        let origin = store.evidence_origin(evidence_id).await.expect("origin");
        assert_eq!(origin, EvidenceOrigin::Unknown);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn fresh_consumption_is_recorded_and_survives_a_reopen() {
        let (store, path) = tmp_store("persist-reopen").await;
        let evidence_id = seed_evidence(&store, "s1").await;
        let claim = claim_for("s1", Uuid::new_v4());
        let anchor = fornax_types::provenance_guard::anchor_of(&claim);

        let verdict = store
            .record_consumption(evidence_id, claim.id, &anchor, Some("exit_code_verifier"))
            .await
            .expect("record consumption");
        assert_eq!(verdict, ReplayVerdict::FreshlyRecorded);
        drop(store);

        // Reopen against the same file -- this is the actual "persisted,
        // not in-memory" claim under test.
        let reopened = Store::open(&path).await.expect("reopen db");
        let verdict_again = reopened
            .record_consumption(evidence_id, claim.id, &anchor, Some("exit_code_verifier"))
            .await
            .expect("re-check consumption after reopen");
        assert_eq!(verdict_again, ReplayVerdict::AlreadyConsumedBySameClaim);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn identical_retry_is_idempotent_not_a_double_insert() {
        let (store, path) = tmp_store("idempotent-retry").await;
        let evidence_id = seed_evidence(&store, "s1").await;
        let claim = claim_for("s1", Uuid::new_v4());
        let anchor = fornax_types::provenance_guard::anchor_of(&claim);

        for _ in 0..3 {
            store
                .record_consumption(evidence_id, claim.id, &anchor, None)
                .await
                .expect("record consumption");
        }
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM evidence_consumption WHERE evidence_id = ?1")
                .bind(evidence_id.to_string())
                .fetch_one(&store.pool)
                .await
                .expect("count consumption rows");
        assert_eq!(
            count, 1,
            "repeated identical consumption must not double-insert"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn cross_anchor_replay_is_refused_and_does_not_steal_ownership() {
        let (store, path) = tmp_store("cross-anchor-replay").await;
        let evidence_id = seed_evidence(&store, "s1").await;
        let claim_a = claim_for("session-a", Uuid::new_v4());
        let anchor_a = fornax_types::provenance_guard::anchor_of(&claim_a);
        let claim_b = claim_for("session-b", Uuid::new_v4());
        let anchor_b = fornax_types::provenance_guard::anchor_of(&claim_b);

        let verdict_a = store
            .record_consumption(evidence_id, claim_a.id, &anchor_a, None)
            .await
            .expect("first consumption");
        assert_eq!(verdict_a, ReplayVerdict::FreshlyRecorded);

        let verdict_b = store
            .record_consumption(evidence_id, claim_b.id, &anchor_b, None)
            .await
            .expect("second, cross-anchor consumption attempt");
        assert_eq!(
            verdict_b,
            ReplayVerdict::ReplayedAcrossClaims {
                originally_consumed_by: claim_a.id
            }
        );

        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM evidence_consumption WHERE evidence_id = ?1")
                .bind(evidence_id.to_string())
                .fetch_one(&store.pool)
                .await
                .expect("count consumption rows");
        assert_eq!(
            count, 1,
            "a refused replay must not create a second owning row"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn same_turn_related_claim_reuse_does_not_steal_ownership_either() {
        let (store, path) = tmp_store("related-reuse").await;
        let evidence_id = seed_evidence(&store, "s1").await;
        let event_id = Uuid::new_v4();
        let claim_a = claim_for("s1", event_id);
        let anchor_a = fornax_types::provenance_guard::anchor_of(&claim_a);
        let mut claim_b = claim_for("s1", event_id);
        claim_b.subject = "command_success".to_string();
        let anchor_b = fornax_types::provenance_guard::anchor_of(&claim_b);
        assert_eq!(anchor_a, anchor_b, "same turn => same anchor");

        store
            .record_consumption(evidence_id, claim_a.id, &anchor_a, None)
            .await
            .expect("first consumption");
        let verdict_b = store
            .record_consumption(evidence_id, claim_b.id, &anchor_b, None)
            .await
            .expect("related-claim reuse attempt");
        assert_eq!(
            verdict_b,
            ReplayVerdict::ReusedByRelatedClaim {
                originally_consumed_by: claim_a.id
            }
        );
        std::fs::remove_file(&path).ok();
    }

    fn caps_for(provider: Provider) -> fornax_types::RuntimeCapabilities {
        fornax_types::RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider,
            signals: Vec::new(),
            notes: Default::default(),
        }
    }

    #[tokio::test]
    async fn session_owner_reflects_zero_one_and_ambiguous_announcements() {
        let (store, path) = tmp_store("session-owner").await;

        assert_eq!(
            store.session_owner("no-announcement").await.expect("owner"),
            SessionOwner::Unknown
        );

        store
            .upsert_capabilities("single-owner", &caps_for(Provider::ClaudeCode))
            .await
            .expect("announce single provider");
        assert_eq!(
            store.session_owner("single-owner").await.expect("owner"),
            SessionOwner::Single(Provider::ClaudeCode)
        );

        store
            .upsert_capabilities("ambiguous-owner", &caps_for(Provider::ClaudeCode))
            .await
            .expect("announce first provider");
        store
            .upsert_capabilities("ambiguous-owner", &caps_for(Provider::Codex))
            .await
            .expect("announce second, conflicting provider");
        assert_eq!(
            store.session_owner("ambiguous-owner").await.expect("owner"),
            SessionOwner::Ambiguous
        );

        std::fs::remove_file(&path).ok();
    }
}
