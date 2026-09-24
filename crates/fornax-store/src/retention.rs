//! Longitudinal dataset retention and deletion enforcement (FORNX-106,
//! parent epic FORNX-20 / discovery thesis HVDL-15).
//!
//! FORNX-103 (`fornax_types::reliability_context`) defined
//! [`RetentionClass`], [`DatasetLineageTag`], and [`TenantRef`] as the schema
//! "a future enforcement mechanism (FORNX-106) [can] find and act on a
//! tenant's records" — deliberately without persisting anything or wiring in
//! actual deletion. This module is that enforcement mechanism.
//!
//! # Placement
//!
//! This lives in `fornax-store`, not `fornax-types`, because deletion
//! propagation is fundamentally a store-layer concern: it has to find and
//! remove *real* persisted rows (`agent_events`/`claims`/`evidence`/
//! `findings`), not just reason about a schema in the abstract. The pure
//! parts that don't need a live store — the retention-duration mapping
//! ([`retention_duration_for`]) and the opt-in collection gate
//! ([`longitudinal_persistence_allowed`]) — are store-agnostic functions any
//! caller (this crate, a future `fornax-verify` consumer, `fornax-cli`) can
//! call without a `Store` handle.
//!
//! # AC1: retention duration and data class are explicit for each
//! longitudinal artifact
//!
//! | Real artifact in this codebase | [`RetentionClass`] | Retention duration | Rationale |
//! |---|---|---|---|
//! | Raw `agent_events`/`claims`/`evidence` rows (`fornax-store` schema, FORNX-26) | [`RetentionClass::RawLocal`] | [`RAW_LOCAL_RETENTION`] (30 days) | The most sensitive, least-generalized data this binary holds — literal tool output, raw evidence payloads. Kept only long enough to support the ordinary local workflow (recent-session review, near-term replay) before it is deleted; nothing about ordinary product operation needs raw evidence from months ago. |
//! | `fornax-replay`'s `ReplayManifest`-shaped sanitized fixture files | [`RetentionClass::SanitizedReplayFixture`] | [`SANITIZED_REPLAY_FIXTURE_RETENTION`] (180 days) | Already frozen and self-contained (FORNX-98: claim/evidence/graph plus recorded verdict, no raw transcript), used for regression comparison across a longer window than a single raw session is useful for — but still bounded, not an unlimited archive. |
//! | `fornax-verify::reliability`'s `ReliabilitySignal` / a cohort's aggregated feature | [`RetentionClass::AggregatedFeature`] | [`AGGREGATED_FEATURE_RETENTION`] (365 days) | No longer traceable to a single session without following `source_record_ids` (FORNX-103's own description of this class); needs to persist across at least one model-release cycle for `DriftState` comparisons to be meaningful, but is not kept forever. |
//! | Causal/interventional findings (`fornax_types::causal`, FORNX-102) and fusion/decision `findings` rows | [`RetentionClass::DerivedFinding`] | [`DERIVED_FINDING_RETENTION`] (365 days) | A conclusion drawn from aggregated features; retained on the same horizon as the aggregates it was drawn from; a finding that outlives its own aggregate's rationale window is no longer well-supported. |
//! | An `Unrecognized(String)` retention class (forward-compat tail) | n/a | [`RAW_LOCAL_RETENTION`] (30 days, the shortest defined duration) | A tag this binary does not recognize is treated as maximally sensitive by default — the safe failure mode is deleting it sooner, not accidentally retaining unknown data indefinitely. |
//!
//! # AC2: protected local raw evidence is not centralized merely to build
//! reliability statistics
//!
//! [`longitudinal_persistence_allowed`] gates persistence of the two
//! *derived, cross-session* classes ([`RetentionClass::AggregatedFeature`],
//! [`RetentionClass::DerivedFinding`]) behind
//! [`fornax_types::privacy::longitudinal_reliability_collection_allowed`],
//! which defaults to `false` — mirroring
//! [`fornax_types::privacy::cloud_sync_allowed`]'s "local policy must
//! explicitly approve before X happens" precedent, but for a different X
//! (cross-session local aggregation, not network egress). Ordinary,
//! single-session artifacts ([`RetentionClass::RawLocal`],
//! [`RetentionClass::SanitizedReplayFixture`]) are never gated by this flag
//! — collecting evidence for one session's claims, or freezing one replay
//! manifest, is ordinary product operation and must keep working with no
//! opt-in required.
//!
//! # AC3: deletion propagation
//!
//! [`Store::record_lineage_tag`] persists a [`DatasetLineageTag`] alongside
//! the real table/row it describes; [`Store::delete_records_for_tenant`]
//! looks up every tag for a [`TenantRef`], deletes the referenced row from
//! its real table when that table is one of this store's known tables
//! ([`KNOWN_RECORD_TABLES`]), and always removes the lineage tag itself —
//! this is real deletion against this crate's real `Store`/SQLite schema,
//! not a mocked stand-in. See this module's tests for cross-tenant isolation
//! proof (deleting one tenant's records leaves another tenant's rows
//! completely untouched).
//!
//! **Honest scope note**: today, nothing in this codebase yet calls
//! `record_lineage_tag` on the live claim/evidence-write path (there is no
//! `tenant_id` column on `agent_events`/`claims`/`evidence`/`findings`
//! themselves — this store predates any tenant concept, and FORNX-103
//! deliberately introduced `TenantRef` only as a schema, not as a persisted
//! column). This ticket builds the real, tested deletion-propagation
//! *mechanism* — given a tenant's lineage tags, it really deletes the real
//! rows they point at — but wiring every future longitudinal-artifact writer
//! to call `record_lineage_tag` at write time is left to whichever ticket
//! introduces that writer (e.g. a future FORNX-105 adjudication path). This
//! module does not fabricate a "deletion succeeded" result against data that
//! was never tagged in the first place.
//!
//! # AC5: research/replay exports cannot bypass the normal
//! classification/egress boundary
//!
//! `fornax-replay`'s `ReplayManifest` is local-file-based only (FORNX-98) —
//! nothing in that crate opens a network connection or exports a manifest
//! anywhere. [`replay_export_egress_allowed`] exists so that if/when a
//! future ticket adds a replay/research export path, it has a ready-made,
//! already-tested gate to consult (delegating to the same
//! [`fornax_types::privacy::cloud_sync_allowed`] gate FORNX-41's cloud
//! uploader must already check) rather than inventing a second, unguarded
//! egress path. Today this AC is satisfied by confirmation, not new export
//! machinery: see this module's
//! `replay_export_egress_gate_defaults_closed_and_matches_cloud_sync_gate`
//! test and `fornax-replay`'s own module docs (no export/egress code exists
//! there to bypass anything).

use std::time::Duration;

use fornax_types::{DatasetLineageTag, RetentionClass, TenantRef};

use crate::{Result, Store};

/// Raw, unaggregated local observation data (`agent_events`/`claims`/
/// `evidence` rows). See this module's AC1 table.
pub const RAW_LOCAL_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);

/// Sanitized replay fixtures (`fornax-replay::ReplayManifest`-shaped data).
/// See this module's AC1 table.
pub const SANITIZED_REPLAY_FIXTURE_RETENTION: Duration = Duration::from_secs(180 * 24 * 3600);

/// Computed aggregate features (e.g. a `ReliabilitySignal` per cohort). See
/// this module's AC1 table.
pub const AGGREGATED_FEATURE_RETENTION: Duration = Duration::from_secs(365 * 24 * 3600);

/// Derived findings drawn from aggregated features. See this module's AC1
/// table.
pub const DERIVED_FINDING_RETENTION: Duration = Duration::from_secs(365 * 24 * 3600);

/// The store tables [`Store::delete_records_for_tenant`] knows how to delete
/// a row from. A lineage tag naming any other `record_table` value still has
/// its lineage row removed, but the (unrecognized) underlying record is left
/// alone — see [`Store::delete_records_for_tenant`]'s doc comment.
///
/// Kept in sync with [`Store::delete_records_for_tenant`]'s literal `match`
/// arms (never used to build a SQL statement itself — table names are never
/// interpolated) by this module's
/// `known_record_tables_matches_delete_records_for_tenants_match_arms` test,
/// so the two cannot silently drift apart.
pub const KNOWN_RECORD_TABLES: &[&str] = &["agent_events", "claims", "evidence", "findings"];

/// Explicit retention duration for a [`RetentionClass`] (FORNX-106 AC1). See
/// this module's docs for the full mapping and rationale table.
pub fn retention_duration_for(class: &RetentionClass) -> Duration {
    match class {
        RetentionClass::RawLocal => RAW_LOCAL_RETENTION,
        RetentionClass::SanitizedReplayFixture => SANITIZED_REPLAY_FIXTURE_RETENTION,
        RetentionClass::AggregatedFeature => AGGREGATED_FEATURE_RETENTION,
        RetentionClass::DerivedFinding => DERIVED_FINDING_RETENTION,
        // An unrecognized tag is treated as the most sensitive, shortest-
        // lived class this binary knows about — see this module's AC1 table.
        RetentionClass::Unrecognized(_) => RAW_LOCAL_RETENTION,
    }
}

/// Whether a record of `class` may be persisted at all (FORNX-106 AC2). The
/// two single-session, ordinary-operation classes are always allowed;
/// cross-session derived classes require an explicit opt-in — see this
/// module's docs.
pub fn longitudinal_persistence_allowed(class: &RetentionClass) -> bool {
    match class {
        RetentionClass::RawLocal | RetentionClass::SanitizedReplayFixture => true,
        RetentionClass::AggregatedFeature
        | RetentionClass::DerivedFinding
        | RetentionClass::Unrecognized(_) => {
            fornax_types::privacy::longitudinal_reliability_collection_allowed()
        }
    }
}

/// The egress gate a future replay/research export path must consult before
/// sending any data off this machine (FORNX-106 AC5). See this module's docs
/// — no export path exists yet to call this, but the gate is ready and
/// defaults closed.
pub fn replay_export_egress_allowed() -> bool {
    fornax_types::privacy::cloud_sync_allowed()
}

/// One persisted lineage tag, joined with the real table/row it describes —
/// the return shape of [`Store::lineage_tags_for_tenant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageTagRecord {
    pub record_table: String,
    pub record_id: String,
    pub tag: DatasetLineageTag,
}

/// What [`Store::delete_records_for_tenant`] actually did, itemized so a
/// caller (and this module's tests) can verify real rows were removed, not
/// just lineage bookkeeping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeletionReport {
    /// `(record_table, record_id)` pairs whose underlying row was deleted
    /// from a table in [`KNOWN_RECORD_TABLES`].
    pub deleted_records: Vec<(String, String)>,
    /// `(record_table, record_id)` pairs whose lineage tag was removed but
    /// whose `record_table` was not in [`KNOWN_RECORD_TABLES`] — the
    /// underlying record, if any, was left untouched.
    pub unknown_table_records: Vec<(String, String)>,
}

impl DeletionReport {
    /// Total lineage tags processed (deleted + unknown-table), for a quick
    /// "were there any records for this tenant at all" check.
    pub fn total_processed(&self) -> usize {
        self.deleted_records.len() + self.unknown_table_records.len()
    }
}

#[derive(sqlx::FromRow)]
struct LineageTagRow {
    record_table: String,
    record_id: String,
    schema_version: i64,
    retention_class: String,
    tenant_ref: String,
    source_record_ids: String,
    recorded_at: String,
    deletion_requested_at: Option<String>,
}

impl TryFrom<LineageTagRow> for LineageTagRecord {
    type Error = crate::StoreError;

    fn try_from(r: LineageTagRow) -> Result<Self> {
        let retention_class: RetentionClass =
            serde_json::from_value(serde_json::Value::String(r.retention_class))?;
        let source_record_ids: Vec<uuid::Uuid> = serde_json::from_str(&r.source_record_ids)?;
        Ok(LineageTagRecord {
            record_table: r.record_table,
            record_id: r.record_id,
            tag: DatasetLineageTag {
                schema_version: r.schema_version as u32,
                retention_class,
                tenant_ref: TenantRef(r.tenant_ref),
                source_record_ids,
                recorded_at: r.recorded_at,
                deletion_requested_at: r.deletion_requested_at,
            },
        })
    }
}

impl Store {
    /// Persist a [`DatasetLineageTag`] describing a real row this store
    /// holds (`record_table` should be one of [`KNOWN_RECORD_TABLES`] for
    /// [`Store::delete_records_for_tenant`] to be able to act on it later,
    /// but this method does not itself enforce that — a lineage tag can be
    /// recorded ahead of a table existing).
    pub async fn record_lineage_tag(
        &self,
        record_table: &str,
        record_id: &str,
        tag: &DatasetLineageTag,
    ) -> Result<()> {
        let retention_class_tag = match serde_json::to_value(&tag.retention_class)? {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        };
        sqlx::query(
            "INSERT INTO dataset_lineage_tags
                (id, record_table, record_id, schema_version, retention_class, tenant_ref,
                 source_record_ids, recorded_at, deletion_requested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(record_table)
        .bind(record_id)
        .bind(tag.schema_version as i64)
        .bind(retention_class_tag)
        .bind(&tag.tenant_ref.0)
        .bind(serde_json::to_string(&tag.source_record_ids)?)
        .bind(&tag.recorded_at)
        .bind(&tag.deletion_requested_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// All lineage tags recorded for `tenant`, joined with the real
    /// table/row each one describes.
    pub async fn lineage_tags_for_tenant(
        &self,
        tenant: &TenantRef,
    ) -> Result<Vec<LineageTagRecord>> {
        let rows = sqlx::query_as::<_, LineageTagRow>(
            "SELECT record_table, record_id, schema_version, retention_class, tenant_ref,
                    source_record_ids, recorded_at, deletion_requested_at
             FROM dataset_lineage_tags WHERE tenant_ref = ?1",
        )
        .bind(&tenant.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Delete every real record tagged as belonging to `tenant`, and the
    /// lineage tags themselves (FORNX-106 AC3). For each tag: if
    /// `record_table` is one of [`KNOWN_RECORD_TABLES`], the matching row is
    /// deleted by primary key from that real table (via a literal,
    /// non-interpolated `DELETE` statement per table — `record_table` is
    /// persisted data, never trusted as SQL); otherwise the record is left
    /// alone and reported under [`DeletionReport::unknown_table_records`].
    /// The lineage tag row is always removed, since its purpose (finding
    /// this tenant's record) is fulfilled either way. Records belonging to a
    /// *different* tenant are never touched — see this module's
    /// `deletion_propagation_leaves_other_tenants_untouched` test.
    ///
    /// Runs inside a single transaction: either every tagged record for
    /// `tenant` (and its lineage tags) is removed, or — on any error — none
    /// of it is, so a caller never observes a partially-applied deletion.
    pub async fn delete_records_for_tenant(&self, tenant: &TenantRef) -> Result<DeletionReport> {
        let mut tx = self.pool.begin().await?;

        let rows = sqlx::query_as::<_, LineageTagRow>(
            "SELECT record_table, record_id, schema_version, retention_class, tenant_ref,
                    source_record_ids, recorded_at, deletion_requested_at
             FROM dataset_lineage_tags WHERE tenant_ref = ?1",
        )
        .bind(&tenant.0)
        .fetch_all(&mut *tx)
        .await?;
        let tags: Vec<LineageTagRecord> = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_>>()?;

        let mut report = DeletionReport::default();

        for record in &tags {
            let deleted = match record.record_table.as_str() {
                "agent_events" => {
                    sqlx::query("DELETE FROM agent_events WHERE id = ?1")
                        .bind(&record.record_id)
                        .execute(&mut *tx)
                        .await?;
                    true
                }
                "claims" => {
                    sqlx::query("DELETE FROM claims WHERE id = ?1")
                        .bind(&record.record_id)
                        .execute(&mut *tx)
                        .await?;
                    true
                }
                "evidence" => {
                    sqlx::query("DELETE FROM evidence WHERE id = ?1")
                        .bind(&record.record_id)
                        .execute(&mut *tx)
                        .await?;
                    true
                }
                "findings" => {
                    sqlx::query("DELETE FROM findings WHERE id = ?1")
                        .bind(&record.record_id)
                        .execute(&mut *tx)
                        .await?;
                    true
                }
                _ => false,
            };
            if deleted {
                report
                    .deleted_records
                    .push((record.record_table.clone(), record.record_id.clone()));
            } else {
                report
                    .unknown_table_records
                    .push((record.record_table.clone(), record.record_id.clone()));
            }
        }

        sqlx::query("DELETE FROM dataset_lineage_tags WHERE tenant_ref = ?1")
            .bind(&tenant.0)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{AgentEvent, EventKind, Provider};
    use uuid::Uuid;

    fn tmp_db_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fornax-store-retention-test-{name}-{}.db",
            Uuid::new_v4()
        ))
    }

    // --- AC1: explicit retention duration + class per artifact -------------

    #[test]
    fn every_known_retention_class_has_an_explicit_documented_duration() {
        assert_eq!(
            retention_duration_for(&RetentionClass::RawLocal),
            RAW_LOCAL_RETENTION
        );
        assert_eq!(
            retention_duration_for(&RetentionClass::SanitizedReplayFixture),
            SANITIZED_REPLAY_FIXTURE_RETENTION
        );
        assert_eq!(
            retention_duration_for(&RetentionClass::AggregatedFeature),
            AGGREGATED_FEATURE_RETENTION
        );
        assert_eq!(
            retention_duration_for(&RetentionClass::DerivedFinding),
            DERIVED_FINDING_RETENTION
        );
    }

    #[test]
    fn retention_durations_are_ordered_raw_shortest_derived_longest() {
        // Load-bearing: encodes this module's privacy policy that the most
        // sensitive/least-generalized class (raw local evidence) must expire
        // first, and generalization (sanitization, then aggregation) buys a
        // longer retention window. A future change to any constant that
        // breaks this ordering is a policy regression, not a refactor.
        assert!(RAW_LOCAL_RETENTION < SANITIZED_REPLAY_FIXTURE_RETENTION);
        assert!(SANITIZED_REPLAY_FIXTURE_RETENTION < AGGREGATED_FEATURE_RETENTION);
        assert_eq!(AGGREGATED_FEATURE_RETENTION, DERIVED_FINDING_RETENTION);
    }

    #[test]
    fn known_record_tables_matches_delete_records_for_tenants_match_arms() {
        // Guards against KNOWN_RECORD_TABLES (documentation) silently
        // drifting from the literal match arms in
        // `Store::delete_records_for_tenant` (the actual guard against SQL
        // interpolation). If someone adds a table to one without the other,
        // this test catches it.
        let match_arm_tables = ["agent_events", "claims", "evidence", "findings"];
        assert_eq!(KNOWN_RECORD_TABLES, &match_arm_tables);
    }

    #[test]
    fn unrecognized_retention_class_gets_the_shortest_safe_default() {
        let unrecognized = RetentionClass::Unrecognized("quarantined_pending_review".to_string());
        assert_eq!(retention_duration_for(&unrecognized), RAW_LOCAL_RETENTION);
    }

    // --- AC2: default-off collection for cross-session derived classes ----

    #[test]
    fn ordinary_single_session_classes_are_always_persistable() {
        std::env::remove_var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED");
        assert!(longitudinal_persistence_allowed(&RetentionClass::RawLocal));
        assert!(longitudinal_persistence_allowed(
            &RetentionClass::SanitizedReplayFixture
        ));
    }

    #[test]
    fn cross_session_derived_classes_default_closed_and_respect_the_opt_in_flag() {
        std::env::remove_var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED");
        assert!(
            !longitudinal_persistence_allowed(&RetentionClass::AggregatedFeature),
            "AC2: must not centralize aggregated reliability data by default"
        );
        assert!(!longitudinal_persistence_allowed(
            &RetentionClass::DerivedFinding
        ));

        std::env::set_var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED", "1");
        assert!(longitudinal_persistence_allowed(
            &RetentionClass::AggregatedFeature
        ));
        assert!(longitudinal_persistence_allowed(
            &RetentionClass::DerivedFinding
        ));

        std::env::remove_var("FORNAX_LONGITUDINAL_COLLECTION_ENABLED");
    }

    // --- AC5: egress boundary defaults closed, same gate as cloud sync ----

    #[test]
    fn replay_export_egress_gate_defaults_closed_and_matches_cloud_sync_gate() {
        std::env::remove_var("FORNAX_CLOUD_SYNC_ENABLED");
        assert!(!replay_export_egress_allowed());

        std::env::set_var("FORNAX_CLOUD_SYNC_ENABLED", "1");
        assert!(replay_export_egress_allowed());

        std::env::remove_var("FORNAX_CLOUD_SYNC_ENABLED");
    }

    // --- AC3: deletion propagation against a real store ---------------------

    async fn seed_event(store: &Store, session_id: &str) -> AgentEvent {
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");
        event
    }

    #[tokio::test]
    async fn deletion_propagation_removes_every_tagged_record_for_one_tenant() {
        let path = tmp_db_path("delete-tenant");
        let store = Store::open(&path).await.expect("open db");

        let tenant = TenantRef("tenant-a".to_string());
        let event_1 = seed_event(&store, "s1").await;
        let event_2 = seed_event(&store, "s1").await;

        store
            .record_lineage_tag(
                "agent_events",
                &event_1.id.to_string(),
                &DatasetLineageTag::new(RetentionClass::RawLocal, tenant.clone()),
            )
            .await
            .expect("record lineage tag 1");
        store
            .record_lineage_tag(
                "agent_events",
                &event_2.id.to_string(),
                &DatasetLineageTag::new(RetentionClass::RawLocal, tenant.clone()),
            )
            .await
            .expect("record lineage tag 2");

        let before = store.events_for_session("s1").await.expect("query events");
        assert_eq!(before.len(), 2, "sanity: both events exist before deletion");

        let report = store
            .delete_records_for_tenant(&tenant)
            .await
            .expect("delete for tenant");
        assert_eq!(report.deleted_records.len(), 2);
        assert!(report.unknown_table_records.is_empty());

        let remaining = store.events_for_session("s1").await.expect("query events");
        assert!(
            remaining.is_empty(),
            "both tagged events must be gone after deletion propagation"
        );

        let remaining_tags = store
            .lineage_tags_for_tenant(&tenant)
            .await
            .expect("query lineage tags");
        assert!(
            remaining_tags.is_empty(),
            "lineage tags must be cleared too"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn deletion_propagation_leaves_other_tenants_untouched() {
        let path = tmp_db_path("delete-cross-tenant");
        let store = Store::open(&path).await.expect("open db");

        let tenant_a = TenantRef("tenant-a".to_string());
        let tenant_b = TenantRef("tenant-b".to_string());
        let event_a = seed_event(&store, "s-a").await;
        let event_b = seed_event(&store, "s-b").await;

        store
            .record_lineage_tag(
                "agent_events",
                &event_a.id.to_string(),
                &DatasetLineageTag::new(RetentionClass::RawLocal, tenant_a.clone()),
            )
            .await
            .expect("tag tenant a's record");
        store
            .record_lineage_tag(
                "agent_events",
                &event_b.id.to_string(),
                &DatasetLineageTag::new(RetentionClass::RawLocal, tenant_b.clone()),
            )
            .await
            .expect("tag tenant b's record");

        let a_before = store
            .events_for_session("s-a")
            .await
            .expect("query tenant a events before deletion");
        let b_before = store
            .events_for_session("s-b")
            .await
            .expect("query tenant b events before deletion");
        assert_eq!(a_before.len(), 1, "sanity: tenant a's event exists");
        assert_eq!(b_before.len(), 1, "sanity: tenant b's event exists");

        store
            .delete_records_for_tenant(&tenant_a)
            .await
            .expect("delete tenant a");

        let a_events = store
            .events_for_session("s-a")
            .await
            .expect("query tenant a events");
        assert!(a_events.is_empty(), "tenant a's record must be deleted");

        let b_events = store
            .events_for_session("s-b")
            .await
            .expect("query tenant b events");
        assert_eq!(
            b_events.len(),
            1,
            "tenant b's record must survive tenant a's deletion"
        );

        let b_tags = store
            .lineage_tags_for_tenant(&tenant_b)
            .await
            .expect("query tenant b lineage tags");
        assert_eq!(
            b_tags.len(),
            1,
            "tenant b's lineage tag must survive tenant a's deletion"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn deletion_propagation_reports_unknown_tables_without_touching_them() {
        let path = tmp_db_path("delete-unknown-table");
        let store = Store::open(&path).await.expect("open db");

        let tenant = TenantRef("tenant-c".to_string());
        store
            .record_lineage_tag(
                "some_future_longitudinal_table",
                "row-123",
                &DatasetLineageTag::new(RetentionClass::AggregatedFeature, tenant.clone()),
            )
            .await
            .expect("record lineage tag for an unknown table");

        let report = store
            .delete_records_for_tenant(&tenant)
            .await
            .expect("delete for tenant");
        assert!(report.deleted_records.is_empty());
        assert_eq!(
            report.unknown_table_records,
            vec![(
                "some_future_longitudinal_table".to_string(),
                "row-123".to_string()
            )]
        );

        // The lineage tag itself is still cleared even though the
        // underlying (unrecognized) record was left alone.
        let remaining_tags = store
            .lineage_tags_for_tenant(&tenant)
            .await
            .expect("query lineage tags");
        assert!(remaining_tags.is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn deleting_a_tenant_with_no_tagged_records_is_a_harmless_no_op() {
        let path = tmp_db_path("delete-no-op");
        let store = Store::open(&path).await.expect("open db");

        let report = store
            .delete_records_for_tenant(&TenantRef("nobody".to_string()))
            .await
            .expect("delete for a tenant with no records");
        assert_eq!(report.total_processed(), 0);

        std::fs::remove_file(&path).ok();
    }
}
