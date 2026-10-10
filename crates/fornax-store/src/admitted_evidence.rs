//! FORNX-441: the one canonical, origin-aware read path every
//! verdict-bearing consumer must go through instead of `Store::
//! evidence_for_session`'s raw rows. `fornax_types::provenance_guard::
//! admit_evidence_rows` is the pure rule; this module is the I/O around
//! it -- resolving each row's real persisted `EvidenceOrigin`, the
//! session's real `SessionOwner`, and (for the claim-scoped variant) the
//! evidence-consumption ledger's existing owners, in the same single
//! query shape `evidence_for_session`/`record_consumption` already use,
//! never a per-row round trip.
//!
//! **Read-only, always.** Neither method here calls `record_consumption`
//! or `record_admission_quarantine` -- see `admit_evidence_rows`'s own doc
//! comment for why a read that wrote would risk stealing evidence
//! ownership away from whichever claim should legitimately consume it.
//! The live verdict path (`run_verifiers_and_persist_findings` in
//! `fornax-daemon`) is the only place admission rejections and
//! consumption are durably recorded, and it keeps doing so exactly as
//! before -- this module gives it (and every other consumer) the same
//! admission rule to apply, not a replacement for its own recording.

use std::collections::HashMap;

use fornax_types::provenance_guard::{
    admit_evidence_rows, AdmissionOutcome, ClaimReplayScope, CollectorAuthority,
};
use fornax_types::{Claim, Evidence};
use uuid::Uuid;

use crate::evidence_consumption::origin_from_column;
use crate::{EvidenceReadFailure, EvidenceRow, Result, Store, StoreError};

/// Result of an admitted-evidence read: the rows a caller may actually
/// use, every rejected row named by id and reason (never silently
/// dropped — same discipline as `EvidenceReadOutcome::failed`), and the
/// unrelated-but-adjacent case of a row that simply failed to
/// deserialize at all (same meaning as `EvidenceReadOutcome::failed`,
/// kept separate from `rejected` because a row this crate can't even
/// parse was never evaluated against the admission rule in the first
/// place).
#[derive(Debug, Clone, Default)]
pub struct AdmittedEvidenceRead {
    pub admitted: Vec<Evidence>,
    pub rejected: Vec<fornax_types::provenance_guard::EvidenceRejection>,
    pub failed: Vec<EvidenceReadFailure>,
}

#[derive(Debug, sqlx::FromRow)]
struct EvidenceRowWithOrigin {
    id: String,
    session_id: String,
    source_event_id: String,
    kind: String,
    observed_at: String,
    payload: String,
    provenance: String,
    source: Option<String>,
    extension: Option<String>,
    evidence_purged: bool,
    ingress_origin: Option<String>,
}

impl EvidenceRowWithOrigin {
    fn split(self) -> (EvidenceRow, Option<String>) {
        (
            EvidenceRow {
                id: self.id,
                session_id: self.session_id,
                source_event_id: self.source_event_id,
                kind: self.kind,
                observed_at: self.observed_at,
                payload: self.payload,
                provenance: self.provenance,
                source: self.source,
                extension: self.extension,
                evidence_purged: self.evidence_purged,
            },
            self.ingress_origin,
        )
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ConsumptionOwnerJoinRow {
    evidence_id: String,
    claim_id: String,
    anchor_session_id: String,
    anchor_event_id: String,
}

impl Store {
    /// Every row for `session_id`, filtered through `admit_evidence_rows`
    /// with no replay scope -- the shape a session-scoped (not
    /// claim-scoped) consumer needs: receipt issuance's own session-wide
    /// evidence pool, spool export, timeline display. Cross-claim replay
    /// is not evaluated here (there is no single claim to scope it to);
    /// callers that need replay exclusion too should prefer
    /// `admitted_evidence_for_claim`.
    pub async fn admitted_evidence_for_session(
        &self,
        session_id: &str,
    ) -> Result<AdmittedEvidenceRead> {
        let (rows, failed) = self.evidence_rows_with_origin(session_id).await?;
        let owner = self.session_owner(session_id).await?;
        let authority = CollectorAuthority::known_sensors();
        let AdmissionOutcome { admitted, rejected } =
            admit_evidence_rows(rows, session_id, owner, &authority, None);
        Ok(AdmittedEvidenceRead {
            admitted,
            rejected,
            failed,
        })
    }

    /// Every row for `claim.session_id`, filtered through
    /// `admit_evidence_rows` with `claim`'s own replay scope applied --
    /// evidence already durably consumed by a *different* claim from a
    /// genuinely different turn is excluded here too, read-only (see this
    /// module's doc comment). The shape every fusion/contract/judge/
    /// decision/evidence-plan/evidence-graph/receipt-per-claim consumer
    /// needs.
    pub async fn admitted_evidence_for_claim(&self, claim: &Claim) -> Result<AdmittedEvidenceRead> {
        let (rows, failed) = self.evidence_rows_with_origin(&claim.session_id).await?;
        let owner = self.session_owner(&claim.session_id).await?;
        let authority = CollectorAuthority::known_sensors();
        let consumed_by = self.consumed_owners_for_session(&claim.session_id).await?;
        let AdmissionOutcome { admitted, rejected } = admit_evidence_rows(
            rows,
            &claim.session_id,
            owner,
            &authority,
            Some(ClaimReplayScope {
                claim,
                consumed_by: &consumed_by,
            }),
        );
        Ok(AdmittedEvidenceRead {
            admitted,
            rejected,
            failed,
        })
    }

    /// `evidence_for_session`'s own query, plus `ingress_origin` -- one
    /// query, never a per-row follow-up (the live verdict path's old
    /// per-row `evidence_origin` call is exactly the N+1 this replaces).
    async fn evidence_rows_with_origin(
        &self,
        session_id: &str,
    ) -> Result<(
        Vec<(Evidence, fornax_types::provenance_guard::EvidenceOrigin)>,
        Vec<EvidenceReadFailure>,
    )> {
        let rows = sqlx::query_as::<_, EvidenceRowWithOrigin>(
            "SELECT id, session_id, source_event_id, kind, observed_at, payload, provenance, \
             source, extension, evidence_purged, ingress_origin
             FROM evidence WHERE session_id = ?1 ORDER BY observed_at ASC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;

        let mut evidence = Vec::with_capacity(rows.len());
        let mut failed = Vec::new();
        for row in rows {
            let id = row.id.clone();
            let (plain_row, origin_raw) = row.split();
            match Evidence::try_from(plain_row) {
                Ok(ev) => evidence.push((ev, origin_from_column(origin_raw))),
                Err(e) => failed.push(EvidenceReadFailure {
                    id,
                    error: e.to_string(),
                }),
            }
        }
        Ok((evidence, failed))
    }

    /// The first (`recorded_at` ascending) `outcome='consumed'` owner per
    /// evidence id, across the whole session, in one query -- the batch
    /// form of `record_consumption`'s own single-row lookup. Read-only:
    /// this never writes to `evidence_consumption`.
    async fn consumed_owners_for_session(
        &self,
        session_id: &str,
    ) -> Result<HashMap<Uuid, (Uuid, fornax_types::provenance_guard::ClaimAnchor)>> {
        let rows: Vec<ConsumptionOwnerJoinRow> = sqlx::query_as(
            "SELECT c.evidence_id, c.claim_id, c.session_id AS anchor_session_id, \
             c.anchor_event_id
             FROM evidence_consumption c
             JOIN evidence e ON e.id = c.evidence_id
             WHERE e.session_id = ?1 AND c.outcome = 'consumed'
             ORDER BY c.recorded_at ASC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;

        let mut owners = HashMap::new();
        for row in rows {
            let evidence_id = Uuid::parse_str(&row.evidence_id).map_err(|e| {
                StoreError::EvidenceConsumptionCorrupt(format!(
                    "evidence_id {:?} is not a valid UUID: {e}",
                    row.evidence_id
                ))
            })?;
            // First row per evidence id wins -- ORDER BY recorded_at ASC
            // above means the first row seen per key is already the
            // earliest owner; a later row for the same key is never
            // actually a different owner in practice (the ledger's own
            // UNIQUE(evidence_id, claim_id) plus `admission_decision`'s
            // single-owner model guarantee that), but checking explicitly
            // keeps this correct even if that invariant is ever relaxed --
            // and, unlike `entry().or_insert_with`, lets UUID parsing fail
            // loudly instead of silently defaulting.
            if owners.contains_key(&evidence_id) {
                continue;
            }
            let claim_id = Uuid::parse_str(&row.claim_id).map_err(|e| {
                StoreError::EvidenceConsumptionCorrupt(format!(
                    "claim_id {:?} is not a valid UUID: {e}",
                    row.claim_id
                ))
            })?;
            let anchor_event_id = Uuid::parse_str(&row.anchor_event_id).map_err(|e| {
                StoreError::EvidenceConsumptionCorrupt(format!(
                    "anchor_event_id {:?} is not a valid UUID: {e}",
                    row.anchor_event_id
                ))
            })?;
            owners.insert(
                evidence_id,
                (claim_id, (row.anchor_session_id, anchor_event_id)),
            );
        }
        Ok(owners)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use fornax_types::provenance_guard::EvidenceOrigin;
    use fornax_types::sensor::{CollectionMethod, EvidenceSource, TrustClass};
    use fornax_types::{AgentEvent, EvidenceKind, Provider};

    async fn tmp_store(name: &str) -> (Store, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "fornax-admitted-evidence-{name}-{}.db",
            Uuid::new_v4()
        ));
        let store = Store::open(&path).await.expect("open db");
        (store, path)
    }

    async fn seed_event(store: &Store, session_id: &str) -> Uuid {
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
        event.id
    }

    fn evidence_with_source(
        session_id: &str,
        source_event_id: Uuid,
        source: Option<EvidenceSource>,
    ) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            source_event_id,
            kind: EvidenceKind::ExitCode,
            observed_at: Utc::now().to_rfc3339(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test-fixture".to_string(),
            source,
            extension: None,
            evidence_purged: false,
        }
    }

    fn registered_source(sensor_name: &str, trust_class: TrustClass) -> EvidenceSource {
        EvidenceSource {
            sensor_name: sensor_name.to_string(),
            trust_class,
            collected_at: Utc::now().to_rfc3339(),
            provider: Some(Provider::ClaudeCode),
            collection_method: CollectionMethod::HookCallback,
            collector_version: None,
            freshness: Default::default(),
            tamper_boundary: Default::default(),
            correlation_group: None,
            derived_from: Vec::new(),
        }
    }

    fn caps_for(provider: Provider) -> fornax_types::RuntimeCapabilities {
        fornax_types::RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider,
            signals: Vec::new(),
            notes: Default::default(),
        }
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

    // --- F1-F3: provenance rejections surface through the Store, not just the pure fn ---

    #[tokio::test]
    async fn f1_forged_host_observed_label_is_rejected_at_the_store_boundary() {
        let (store, path) = tmp_store("f1").await;
        let event_id = seed_event(&store, "s1").await;
        // Claims HostObserved, but `claude_bash_exit_code_sensor_v1` is only
        // ever authorized for AgentAdjacent -- the FORNX-380 exploit shape.
        let ev = evidence_with_source(
            "s1",
            event_id,
            Some(registered_source(
                "claude_bash_exit_code_sensor_v1",
                TrustClass::HostObserved,
            )),
        );
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::UdsIngest)
            .await
            .expect("insert");

        let read = store
            .admitted_evidence_for_session("s1")
            .await
            .expect("admitted read");
        assert!(read.admitted.is_empty());
        assert_eq!(read.rejected.len(), 1);
        assert_eq!(read.rejected[0].evidence_id, ev.id);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn f2_unregistered_sensor_is_rejected_at_the_store_boundary() {
        let (store, path) = tmp_store("f2").await;
        let event_id = seed_event(&store, "s1").await;
        let ev = evidence_with_source(
            "s1",
            event_id,
            Some(registered_source(
                "totally_made_up_sensor_v99",
                TrustClass::HostObserved,
            )),
        );
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::UdsIngest)
            .await
            .expect("insert");

        let read = store
            .admitted_evidence_for_session("s1")
            .await
            .expect("admitted read");
        assert!(read.admitted.is_empty());
        assert_eq!(read.rejected.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn f3_uds_row_with_no_source_is_rejected_at_the_store_boundary() {
        let (store, path) = tmp_store("f3").await;
        let event_id = seed_event(&store, "s1").await;
        let ev = evidence_with_source("s1", event_id, None);
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::UdsIngest)
            .await
            .expect("insert");

        let read = store
            .admitted_evidence_for_session("s1")
            .await
            .expect("admitted read");
        assert!(read.admitted.is_empty());
        assert_eq!(read.rejected.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn f5_unknown_origin_is_rejected_even_with_a_valid_registered_source() {
        let (store, path) = tmp_store("f5").await;
        let event_id = seed_event(&store, "s1").await;
        let ev = evidence_with_source(
            "s1",
            event_id,
            Some(registered_source(
                "claude_bash_exit_code_sensor_v1",
                TrustClass::AgentAdjacent,
            )),
        );
        // Plain `insert_evidence` -- no origin stamped, reads back Unknown.
        store.insert_evidence(&ev).await.expect("insert");

        let read = store
            .admitted_evidence_for_session("s1")
            .await
            .expect("admitted read");
        assert!(read.admitted.is_empty());
        assert_eq!(read.rejected.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn f6_cross_session_evidence_is_rejected_by_the_claim_scoped_read() {
        let (store, path) = tmp_store("f6").await;
        let event_id = seed_event(&store, "victim-session").await;
        let ev = evidence_with_source(
            "victim-session",
            event_id,
            Some(registered_source(
                "claude_bash_exit_code_sensor_v1",
                TrustClass::AgentAdjacent,
            )),
        );
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::DaemonAcquisition)
            .await
            .expect("insert");

        // A claim from a different session must not admit victim-session's evidence.
        let attacker_claim = claim_for("attacker-session", Uuid::new_v4());
        let read = store
            .admitted_evidence_for_claim(&attacker_claim)
            .await
            .expect("admitted read");
        assert!(read.admitted.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn f7_cross_anchor_replay_is_rejected_only_by_the_claim_scoped_read() {
        let (store, path) = tmp_store("f7").await;
        let event_id = seed_event(&store, "s1").await;
        let ev = evidence_with_source(
            "s1",
            event_id,
            Some(registered_source(
                "claude_bash_exit_code_sensor_v1",
                TrustClass::AgentAdjacent,
            )),
        );
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::DaemonAcquisition)
            .await
            .expect("insert");

        let claim_a = claim_for("s1", Uuid::new_v4());
        let anchor_a = fornax_types::provenance_guard::anchor_of(&claim_a);
        store
            .record_consumption(ev.id, claim_a.id, &anchor_a, None)
            .await
            .expect("record consumption by claim_a");

        // claim_b has a genuinely different anchor (different source_event_id).
        let claim_b = claim_for("s1", Uuid::new_v4());

        let session_scoped = store
            .admitted_evidence_for_session("s1")
            .await
            .expect("session-scoped read");
        assert_eq!(
            session_scoped.admitted.len(),
            1,
            "session-scoped read has no replay scope -- it must still admit"
        );

        let claim_scoped = store
            .admitted_evidence_for_claim(&claim_b)
            .await
            .expect("claim-scoped read");
        assert!(
            claim_scoped.admitted.is_empty(),
            "claim-scoped read must exclude evidence already consumed by a different claim"
        );
        assert_eq!(claim_scoped.rejected.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    // --- P1-P4: legitimate evidence is actually admitted, not just "not rejected" ---

    #[tokio::test]
    async fn p1_legitimate_uds_ingest_row_is_admitted() {
        let (store, path) = tmp_store("p1").await;
        let event_id = seed_event(&store, "s1").await;
        let ev = evidence_with_source(
            "s1",
            event_id,
            Some(registered_source(
                "claude_bash_exit_code_sensor_v1",
                TrustClass::AgentAdjacent,
            )),
        );
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::UdsIngest)
            .await
            .expect("insert");

        let read = store
            .admitted_evidence_for_session("s1")
            .await
            .expect("admitted read");
        assert_eq!(read.admitted.len(), 1);
        assert_eq!(read.admitted[0].id, ev.id);
        assert!(read.rejected.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn p2_daemon_acquisition_with_no_source_is_admitted() {
        let (store, path) = tmp_store("p2").await;
        let event_id = seed_event(&store, "s1").await;
        let ev = evidence_with_source("s1", event_id, None);
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::DaemonAcquisition)
            .await
            .expect("insert");

        let read = store
            .admitted_evidence_for_claim(&claim_for("s1", Uuid::new_v4()))
            .await
            .expect("admitted read");
        assert_eq!(read.admitted.len(), 1);
        assert!(read.rejected.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn p3_privileged_executor_with_no_source_is_admitted() {
        let (store, path) = tmp_store("p3").await;
        let event_id = seed_event(&store, "s1").await;
        let ev = evidence_with_source("s1", event_id, None);
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::PrivilegedExecutor)
            .await
            .expect("insert");

        let read = store
            .admitted_evidence_for_session("s1")
            .await
            .expect("admitted read");
        assert_eq!(read.admitted.len(), 1);
        assert!(read.rejected.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn p4_a_same_anchor_related_claim_reuse_is_still_admitted() {
        let (store, path) = tmp_store("p4").await;
        let event_id = seed_event(&store, "s1").await;
        let ev = evidence_with_source(
            "s1",
            event_id,
            Some(registered_source(
                "claude_bash_exit_code_sensor_v1",
                TrustClass::AgentAdjacent,
            )),
        );
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::DaemonAcquisition)
            .await
            .expect("insert");

        let claim_a = claim_for("s1", event_id);
        let anchor_a = fornax_types::provenance_guard::anchor_of(&claim_a);
        store
            .record_consumption(ev.id, claim_a.id, &anchor_a, None)
            .await
            .expect("record consumption by claim_a");

        // claim_b shares the same source_event_id (same anchor) as claim_a --
        // a related claim from the same turn, not a genuine cross-claim replay.
        let mut claim_b = claim_for("s1", event_id);
        claim_b.subject = "a_different_subject".to_string();
        let anchor_b = fornax_types::provenance_guard::anchor_of(&claim_b);
        assert_eq!(anchor_a, anchor_b, "same turn => same anchor");

        let read = store
            .admitted_evidence_for_claim(&claim_b)
            .await
            .expect("admitted read");
        assert_eq!(
            read.admitted.len(),
            1,
            "a same-anchor related-claim reuse must not be treated as a replay rejection"
        );
        assert!(read.rejected.is_empty());
        std::fs::remove_file(&path).ok();
    }

    // --- Owner/SessionOwner scoping actually reaches the Store boundary ---

    #[tokio::test]
    async fn ambiguous_owner_rejects_a_provider_claiming_uds_row() {
        let (store, path) = tmp_store("ambiguous-owner").await;
        store
            .upsert_capabilities("s1", &caps_for(Provider::ClaudeCode))
            .await
            .expect("announce claude code");
        store
            .upsert_capabilities("s1", &caps_for(Provider::Codex))
            .await
            .expect("announce codex too -- now ambiguous");

        let event_id = seed_event(&store, "s1").await;
        let ev = evidence_with_source(
            "s1",
            event_id,
            Some(registered_source(
                "claude_bash_exit_code_sensor_v1",
                TrustClass::AgentAdjacent,
            )),
        );
        store
            .insert_evidence_with_origin(&ev, EvidenceOrigin::UdsIngest)
            .await
            .expect("insert");

        let read = store
            .admitted_evidence_for_session("s1")
            .await
            .expect("admitted read");
        assert!(
            read.admitted.is_empty(),
            "an ambiguous session owner must fail closed on a provider-asserting sensor"
        );
        std::fs::remove_file(&path).ok();
    }
}
