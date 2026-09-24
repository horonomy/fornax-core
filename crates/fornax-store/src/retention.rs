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
//! **FORNX-319 update — the live write path is now wired.**
//! `Store::insert_event`/`insert_claim`/`insert_evidence`/`insert_finding`
//! each record a [`DatasetLineageTag`] atomically alongside the row they
//! insert (see [`retention_class_for_table`] for the classification rule
//! and each method's own doc comment). There is still no `tenant_id`
//! column on `agent_events`/`claims`/`evidence`/`findings` themselves —
//! FORNX-103/106 deliberately kept [`TenantRef`] schema-only locally, and
//! this ticket does not add one — so each insert path uses the record's own
//! `session_id` as this local daemon's closest available tenant-scoping
//! key (`Finding` has no `session_id` of its own; `insert_finding` resolves
//! it from the referenced `claims` row instead). [`Store::sweep_expired_records`]
//! is the bounded, incremental consumer of these tags: unlike
//! [`Store::delete_records_for_tenant`]'s tenant-scoped hard delete of
//! every known table, the sweep soft-purges `"evidence"` rows in place
//! ([`Store::purge_evidence_payload`]) so a finding's verdict/rationale
//! stay intact and readable after its evidence expires (AC2/AC3 below).
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

use chrono::{DateTime, Utc};
use fornax_types::audit::{
    AuditAction, AuditActor, AuditEvent, AuditExportClass, AuditOutcome, AuditTarget,
};
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

/// Which [`RetentionClass`] a record written to `record_table` is tagged
/// with at the live write path (FORNX-319 AC1, applying this module's own
/// AC1 table to `Store::insert_event`/`insert_claim`/`insert_evidence`/
/// `insert_finding`). `agent_events`/`claims`/`evidence` are all raw,
/// single-session observations -> [`RetentionClass::RawLocal`]; `findings`
/// are derived conclusions drawn from aggregated evidence ->
/// [`RetentionClass::DerivedFinding`] — matching this module's own AC1
/// table above. A table name outside [`KNOWN_RECORD_TABLES`] (should never
/// happen at a real call site in this crate) falls back to
/// [`RetentionClass::Unrecognized`], which [`retention_duration_for`]
/// sweeps at the shortest, safest duration rather than silently retaining
/// it forever.
pub fn retention_class_for_table(record_table: &str) -> RetentionClass {
    match record_table {
        "agent_events" | "claims" | "evidence" => RetentionClass::RawLocal,
        "findings" => RetentionClass::DerivedFinding,
        other => RetentionClass::Unrecognized(other.to_string()),
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
        crate::insert_lineage_tag_row(&self.pool, record_table, record_id, tag).await
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

    /// How many [`dataset_lineage_tags`] rows currently in this store carry
    /// `class`, and the oldest (`MIN`) `recorded_at` among them (FORNX-322:
    /// `fornax audit report`'s retention section). `None` when `class` has
    /// zero records currently tagged — never fabricated as a timestamp, so a
    /// caller can render "no records observed for this class" honestly
    /// instead of inventing an oldest-record time that does not exist.
    /// `record_table` is deliberately not filtered to
    /// [`KNOWN_RECORD_TABLES`] — a tag for an as-yet-unknown table (see
    /// [`Store::delete_records_for_tenant`]'s handling of that case) still
    /// counts toward this class's real observed coverage.
    pub async fn retention_class_observation(
        &self,
        class: &RetentionClass,
    ) -> Result<(u64, Option<String>)> {
        // Same wire-tag serialization `insert_lineage_tag_row` uses to
        // populate the `retention_class` column, so this query matches
        // exactly the string form actually stored — never re-derived by a
        // different path that could silently drift from it.
        let class_tag = match serde_json::to_value(class)? {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        };
        let row: (i64, Option<String>) = sqlx::query_as(
            "SELECT COUNT(*), MIN(recorded_at) FROM dataset_lineage_tags WHERE retention_class = ?1",
        )
        .bind(&class_tag)
        .fetch_one(&self.pool)
        .await?;
        Ok((row.0 as u64, row.1))
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
        // FORNX-319: use BEGIN IMMEDIATE, matching the four insert paths and
        // the sweep. Before this ticket nothing wrote to the store without
        // holding `AppState::processing`; the sweep now does, which makes a
        // deferred BEGIN here newly reachable for the same
        // SQLITE_BUSY_SNAPSHOT race that busy_timeout + BEGIN IMMEDIATE
        // already fixed on the insert paths (see this file's module doc).
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

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

    /// FORNX-319 AC2/AC3: purge one `evidence` row's raw `payload` in
    /// place. This NEVER deletes the row, unlike
    /// [`Store::delete_records_for_tenant`]'s handling of the other three
    /// known tables — the finding/verdict/rationale/audit trail this
    /// evidence once supported is stored elsewhere (`findings`, never on
    /// `evidence` itself) and is completely untouched by this call; there
    /// is no code path here that can recompute or alter a verdict as a
    /// side effect (ADR-0001 D4). Sets `evidence_purged = 1` and overwrites
    /// `payload` with [`evidence_expired_payload_marker`] — an explicit,
    /// unmistakable "evidence expired" statement, never `{}` (an empty
    /// object reads as "empty evidence was collected", exactly the false
    /// impression this ticket's AC3 forbids) — so any reader of
    /// `Evidence::payload`, present or future, sees an honest marker
    /// instead of silence. Returns `true` if a row with this id existed.
    ///
    /// FORNX-319 AC "every purge action emits an AuditEvent": when a row
    /// really was purged, this also appends an
    /// `AuditAction::EvidencePurged` event to the local audit ledger
    /// (`Store::append_audit_event`, FORNX-315), after the `UPDATE` above
    /// has committed. The append runs in the ledger's own separate `BEGIN
    /// IMMEDIATE` transaction (`audit_ledger.rs`) on a different pool
    /// connection — it MUST happen after this method's own write commits,
    /// never while an update/insert transaction of this store's is still
    /// open, because SQLite serializes writers at the file level, not the
    /// connection level: two overlapping write transactions on the same
    /// database file, even from different pool connections, self-deadlock.
    /// The purge and its audit event are therefore not cross-table-atomic
    /// — a crash in the narrow window between them leaves that one purge
    /// unaudited; see [`Store::sweep_expired_records`]'s doc comment for
    /// the same trade-off made there for the same reason.
    pub async fn purge_evidence_payload(
        &self,
        evidence_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let purged = purge_evidence_payload_row(&self.pool, evidence_id).await?;
        if purged {
            self.append_audit_event(&evidence_purged_audit_event(evidence_id, now), now)
                .await?;
        }
        Ok(purged)
    }

    /// Whether the `evidence` row named `evidence_id` has been purged
    /// (FORNX-319 AC3) — `None` if no such row exists (never fabricated as
    /// `false`, which would be indistinguishable from "exists and not
    /// purged"). Lets a renderer (e.g. `fornax-daemon`'s
    /// `/api/evidence-graph`) annotate a linked evidence id as "evidence
    /// expired" without re-fetching and re-parsing the whole row.
    pub async fn is_evidence_purged(&self, evidence_id: &str) -> Result<Option<bool>> {
        let row: Option<(bool,)> =
            sqlx::query_as("SELECT evidence_purged FROM evidence WHERE id = ?1")
                .bind(evidence_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(purged,)| purged))
    }

    /// Bounded incremental retention sweep (FORNX-319 AC4/AC5/AC6).
    /// Examines up to `batch_size` lineage tags, in `recorded_at` ascending
    /// order starting strictly after `cursor` (`None` starts from the
    /// beginning of the table), in ONE transaction bounded by rows
    /// *examined* — never a single transaction over the whole table, so an
    /// arbitrarily large backlog cannot hold a lock for longer than one
    /// small batch, and a concurrent live insert (a separate connection out
    /// of this store's pool) is never measurably delayed by a sweep in
    /// progress.
    ///
    /// Every examined row is checked against
    /// [`retention_duration_for`](tag.retention_class) (AC5: the sweep
    /// calls this directly, never re-derives a duration) measured from
    /// `tag.recorded_at` against `now` (a parameter so tests simulate
    /// elapsed time instead of sleeping; an
    /// [`RetentionClass::Unrecognized`] tag is swept at the shortest safe
    /// default per AC6, exactly like every other caller of
    /// `retention_duration_for`). An unexpired row's tag is left
    /// completely untouched — a LATER call, once its window elapses, can
    /// still find and process it; this is what keeps the sweep correct
    /// without a single giant "find every expired row" query. An expired
    /// row is dispatched by `record_table`: `"evidence"` is soft-purged via
    /// [`Store::purge_evidence_payload`]; `"agent_events"`/`"claims"`/
    /// `"findings"` are hard-deleted (matching
    /// [`Store::delete_records_for_tenant`]'s own per-table match arms);
    /// any other table is left alone. Either way, an EXPIRED row's lineage
    /// tag is always removed, its purpose (find this record when its
    /// window elapses) having been fulfilled.
    ///
    /// Returns [`SweepReport::next_cursor`] — the `recorded_at` of the last
    /// examined row, or `None` once fewer than `batch_size` rows were
    /// returned (the whole table has been examined this pass; a caller
    /// should restart its own cursor at `None` on the next cycle rather
    /// than getting stuck at the end).
    ///
    /// **Known ordering caveat**: `recorded_at` is an RFC3339 string
    /// (`DatasetLineageTag::new` stamps `chrono::Utc::now().to_rfc3339()`,
    /// whose subsecond digit count varies), and `ORDER BY recorded_at ASC`
    /// is a plain SQLite text comparison — two timestamps a few
    /// microseconds apart with different subsecond digit counts could sort
    /// out of true chronological order. This never affects *correctness*
    /// of what gets purged (that check always re-parses `recorded_at` with
    /// `chrono` in Rust, not SQL text comparison) — only the exact
    /// processing order within one very tight time window, which no AC
    /// depends on.
    pub async fn sweep_expired_records(
        &self,
        now: DateTime<Utc>,
        cursor: Option<&str>,
        batch_size: i64,
    ) -> Result<SweepReport> {
        // BEGIN IMMEDIATE (never the plain deferred BEGIN `Pool::begin()`
        // issues): this transaction races a concurrent live insert on a
        // different pool connection with neither side holding
        // `AppState::processing` (see this method's module-level "does not
        // block a concurrent insert" doc). A deferred transaction that
        // later tries to write after another writer has committed gets an
        // immediate `SQLITE_BUSY_SNAPSHOT` — not a bounded wait — because
        // its read snapshot is now stale; acquiring the write lock
        // immediately avoids that class of error entirely, leaving only an
        // ordinary, `busy_timeout`-bounded lock wait.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        // Keyset pagination on (recorded_at, record_table, record_id) —
        // NOT `recorded_at` alone. Many tags can legitimately share the
        // exact same `recorded_at` (multiple records written in the same
        // instant, or a synthetic backlog for testing); a cursor on
        // `recorded_at` alone would silently strand every row tied with
        // the last-examined one on the far side of `>`, since none of them
        // compares strictly greater. `(record_table, record_id)` is
        // already this table's natural identity for one lineage tag (see
        // the DELETE below), so it is a correct, always-available
        // tie-breaker with no schema change needed.
        let (cursor_recorded_at, cursor_table, cursor_id) = parse_sweep_cursor(cursor);
        let rows = sqlx::query_as::<_, LineageTagRow>(
            "SELECT record_table, record_id, schema_version, retention_class, tenant_ref,
                    source_record_ids, recorded_at, deletion_requested_at
             FROM dataset_lineage_tags
             WHERE (recorded_at, record_table, record_id) > (?1, ?2, ?3)
             ORDER BY recorded_at ASC, record_table ASC, record_id ASC
             LIMIT ?4",
        )
        .bind(&cursor_recorded_at)
        .bind(&cursor_table)
        .bind(&cursor_id)
        .bind(batch_size)
        .fetch_all(&mut *tx)
        .await?;

        let examined = rows.len();
        let mut report = SweepReport {
            examined,
            ..Default::default()
        };
        let mut last_key: Option<(String, String, String)> = None;
        // Evidence ids purged this batch, audited only AFTER `tx` commits
        // (see below) — `Store::append_audit_event` opens its own `BEGIN
        // IMMEDIATE` on a separate pool connection, and SQLite serializes
        // writers at the FILE level, not the connection level: calling it
        // while `tx` is still open self-deadlocks (this pool's own
        // in-progress write transaction blocks the audit ledger's write
        // lock acquisition, forever, since both would need the other to
        // finish first).
        let mut purged_evidence_ids: Vec<String> = Vec::new();

        for row in rows {
            let recorded_at = row.recorded_at.clone();
            let record: LineageTagRecord = row.try_into()?;
            last_key = Some((
                recorded_at.clone(),
                record.record_table.clone(),
                record.record_id.clone(),
            ));

            if !is_expired(&recorded_at, &record.tag.retention_class, now) {
                continue;
            }

            match record.record_table.as_str() {
                "evidence" => {
                    purge_evidence_payload_row(&mut *tx, &record.record_id).await?;
                    report.purged_evidence += 1;
                    purged_evidence_ids.push(record.record_id.clone());
                }
                "agent_events" => {
                    sqlx::query("DELETE FROM agent_events WHERE id = ?1")
                        .bind(&record.record_id)
                        .execute(&mut *tx)
                        .await?;
                    report.deleted_records += 1;
                }
                "claims" => {
                    sqlx::query("DELETE FROM claims WHERE id = ?1")
                        .bind(&record.record_id)
                        .execute(&mut *tx)
                        .await?;
                    report.deleted_records += 1;
                }
                "findings" => {
                    sqlx::query("DELETE FROM findings WHERE id = ?1")
                        .bind(&record.record_id)
                        .execute(&mut *tx)
                        .await?;
                    report.deleted_records += 1;
                }
                _ => {
                    report.unknown_table_skipped += 1;
                }
            }

            sqlx::query(
                "DELETE FROM dataset_lineage_tags WHERE record_table = ?1 AND record_id = ?2",
            )
            .bind(&record.record_table)
            .bind(&record.record_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // FORNX-319/FORNX-315: every purge action emits an AuditEvent —
        // appended only now, after `tx` has committed (see the comment
        // above `purged_evidence_ids` for why appending any earlier
        // self-deadlocks). This does mean the purge and its audit event
        // are not cross-table-atomic: a crash between the commit above and
        // one of these appends leaves that one purge unaudited. Given a
        // local single-process daemon with no concurrent writer racing
        // this exact window, that gap is accepted rather than engineered
        // away — the alternative (holding `tx` open across the ledger's
        // own transaction) is the deadlock this code avoids.
        for evidence_id in &purged_evidence_ids {
            self.append_audit_event(&evidence_purged_audit_event(evidence_id, now), now)
                .await?;
        }

        report.more_remaining = examined == batch_size as usize;
        report.next_cursor = if report.more_remaining {
            last_key.map(|(recorded_at, table, id)| sweep_cursor_token(&recorded_at, &table, &id))
        } else {
            None
        };
        Ok(report)
    }
}

/// Unit-separator-joined opaque cursor token for
/// [`Store::sweep_expired_records`]'s keyset pagination — never meant to be
/// parsed by a caller, only round-tripped back as the next call's `cursor`.
fn sweep_cursor_token(recorded_at: &str, record_table: &str, record_id: &str) -> String {
    format!("{recorded_at}\u{1}{record_table}\u{1}{record_id}")
}

/// Inverse of [`sweep_cursor_token`]. `None`, or a token that doesn't split
/// into exactly three parts (should never happen for a token this module
/// itself produced), starts from the very beginning of the table — every
/// real `recorded_at`/`record_table`/`record_id` sorts strictly greater
/// than three empty strings.
fn parse_sweep_cursor(cursor: Option<&str>) -> (String, String, String) {
    let Some(cursor) = cursor else {
        return (String::new(), String::new(), String::new());
    };
    let mut parts = cursor.splitn(3, '\u{1}');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), Some(c)) => (a.to_string(), b.to_string(), c.to_string()),
        _ => (String::new(), String::new(), String::new()),
    }
}

/// The explicit marker [`Store::purge_evidence_payload`] writes in place of
/// a purged row's original payload (FORNX-319 AC3). A public function (not
/// inlined at each call site) so a test or a future renderer can match on
/// the exact honest shape rather than guessing at `Evidence::payload` once
/// `evidence_purged` is `true`.
pub fn evidence_expired_payload_marker() -> serde_json::Value {
    serde_json::json!({
        "evidence_expired": true,
        "detail": "raw evidence payload purged per local retention policy; the finding/verdict this evidence once supported is unaffected",
    })
}

/// The `AuditAction::EvidencePurged` event both [`Store::purge_evidence_payload`]
/// and [`Store::sweep_expired_records`] append (FORNX-319/FORNX-315).
/// `AuditActor::System` — a retention purge is this binary's own automatic,
/// unattended action, never attributable to a specific device/user/service
/// caller. `AuditOutcome::Expired` — the target's retention window had
/// elapsed, matching that variant's documented meaning exactly.
/// `AuditExportClass::Metadata` — only structural fields (which evidence id,
/// when), no raw evidence content is embedded in the event itself.
fn evidence_purged_audit_event(evidence_id: &str, now: DateTime<Utc>) -> AuditEvent {
    AuditEvent::new(
        uuid::Uuid::new_v4().to_string(),
        now.to_rfc3339(),
        AuditActor::System,
        AuditAction::EvidencePurged,
        AuditTarget::Evidence {
            target_id: evidence_id.to_string(),
        },
        AuditOutcome::Expired,
        AuditExportClass::Metadata,
    )
}

async fn purge_evidence_payload_row<'e, E>(executor: E, evidence_id: &str) -> Result<bool>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let result = sqlx::query("UPDATE evidence SET payload = ?1, evidence_purged = 1 WHERE id = ?2")
        .bind(evidence_expired_payload_marker().to_string())
        .bind(evidence_id)
        .execute(executor)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Whether a lineage tag's record has outlived
/// [`retention_duration_for`]'s duration for its `RetentionClass`, measured
/// from `recorded_at` (parsed as RFC3339) to `now`. A `recorded_at` that
/// fails to parse (should never happen for a row this crate itself wrote)
/// is treated as NOT expired — this function never guesses a record is due
/// for deletion from a value it cannot actually read.
fn is_expired(recorded_at: &str, class: &RetentionClass, now: DateTime<Utc>) -> bool {
    let Ok(recorded_at) = DateTime::parse_from_rfc3339(recorded_at) else {
        return false;
    };
    let recorded_at = recorded_at.with_timezone(&Utc);
    let Ok(duration) = chrono::Duration::from_std(retention_duration_for(class)) else {
        return false;
    };
    now.signed_duration_since(recorded_at) >= duration
}

/// What one [`Store::sweep_expired_records`] call did, for a caller (and
/// this module's tests) to verify the sweep is genuinely bounded and
/// incremental rather than an unbounded full-table pass (FORNX-319 AC4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Rows read from `dataset_lineage_tags` this call, regardless of
    /// whether they turned out to be expired — the actual bound enforced
    /// per call.
    pub examined: usize,
    /// `"evidence"` rows soft-purged (payload overwritten, row kept).
    pub purged_evidence: usize,
    /// `"agent_events"`/`"claims"`/`"findings"` rows hard-deleted.
    pub deleted_records: usize,
    /// Expired rows whose `record_table` was not one this store knows how
    /// to act on — their lineage tag was still removed, but the
    /// (unrecognized) underlying record, if any, was left untouched.
    pub unknown_table_skipped: usize,
    /// `true` when `examined == batch_size` — there may be more rows past
    /// this batch; a caller should call again (with [`Self::next_cursor`])
    /// rather than assuming the table is fully swept.
    pub more_remaining: bool,
    /// Pass this back as the next call's `cursor` to resume where this
    /// batch left off. `None` once a call examines fewer than
    /// `batch_size` rows (the end of the table was reached this pass).
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{
        AgentEvent, Claim, EventKind, Evidence, EvidenceKind, Finding, Provider, Verdict,
    };
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

    // --- FORNX-322: retention_class_observation ----------------------------

    #[tokio::test]
    async fn retention_class_observation_reports_none_for_a_class_with_zero_records() {
        let path = tmp_db_path("retention-observation-empty");
        let store = Store::open(&path).await.expect("open db");

        let (count, oldest) = store
            .retention_class_observation(&RetentionClass::DerivedFinding)
            .await
            .expect("query retention class observation");
        assert_eq!(count, 0);
        assert_eq!(
            oldest, None,
            "a class with zero records must never fabricate an oldest-record timestamp"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn retention_class_observation_reports_the_real_count_and_oldest_recorded_at() {
        let path = tmp_db_path("retention-observation-populated");
        let store = Store::open(&path).await.expect("open db");
        let tenant = TenantRef("tenant-obs".to_string());

        store
            .record_lineage_tag(
                "agent_events",
                "row-older",
                &DatasetLineageTag {
                    schema_version: 1,
                    retention_class: RetentionClass::RawLocal,
                    tenant_ref: tenant.clone(),
                    source_record_ids: vec![],
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    deletion_requested_at: None,
                },
            )
            .await
            .expect("record older tag");
        store
            .record_lineage_tag(
                "agent_events",
                "row-newer",
                &DatasetLineageTag {
                    schema_version: 1,
                    retention_class: RetentionClass::RawLocal,
                    tenant_ref: tenant.clone(),
                    source_record_ids: vec![],
                    recorded_at: "2026-06-01T00:00:00Z".to_string(),
                    deletion_requested_at: None,
                },
            )
            .await
            .expect("record newer tag");
        // A different class must not be counted toward RawLocal's observation.
        store
            .record_lineage_tag(
                "findings",
                "row-derived",
                &DatasetLineageTag::new(RetentionClass::DerivedFinding, tenant),
            )
            .await
            .expect("record a differently-classed tag");

        let (count, oldest) = store
            .retention_class_observation(&RetentionClass::RawLocal)
            .await
            .expect("query retention class observation");
        assert_eq!(count, 2);
        assert_eq!(oldest.as_deref(), Some("2026-01-01T00:00:00Z"));

        std::fs::remove_file(&path).ok();
    }

    // --- FORNX-319 AC1: every insert path records a lineage tag ------------

    async fn seed_full_record_set(store: &Store) -> (AgentEvent, Claim, Evidence, Finding) {
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "fornx-319-session".to_string(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            text: "all tests passed".into(),
            subject: "test_result".into(),
            claimed_at: "2026-01-01T00:00:01Z".into(),
        };
        store.insert_claim(&claim).await.expect("insert claim");

        let evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:01Z".into(),
            payload: serde_json::json!({"command": ["pytest"], "exit_code": 0}),
            provenance: "test".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        };
        store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");

        let finding = Finding {
            id: Uuid::new_v4(),
            claim_id: claim.id,
            verdict: Verdict::Verified,
            evidence_ids: vec![evidence.id],
            verifier_name: "test_result_verifier_v1".into(),
            rationale: "exit_code=0".into(),
            computed_at: "2026-01-01T00:00:02Z".into(),
        };
        store
            .insert_finding(&finding)
            .await
            .expect("insert finding");

        (event, claim, evidence, finding)
    }

    #[tokio::test]
    async fn every_row_written_through_the_four_insert_paths_gets_a_lineage_tag() {
        let path = tmp_db_path("ac1-lineage-tagging");
        let store = Store::open(&path).await.expect("open db");

        let (event, claim, evidence, finding) = seed_full_record_set(&store).await;

        for (table, id, expected_class) in [
            (
                "agent_events",
                event.id.to_string(),
                RetentionClass::RawLocal,
            ),
            ("claims", claim.id.to_string(), RetentionClass::RawLocal),
            (
                "evidence",
                evidence.id.to_string(),
                RetentionClass::RawLocal,
            ),
            (
                "findings",
                finding.id.to_string(),
                RetentionClass::DerivedFinding,
            ),
        ] {
            let row: (String,) = sqlx::query_as(
                "SELECT retention_class FROM dataset_lineage_tags WHERE record_table = ?1 AND record_id = ?2",
            )
            .bind(table)
            .bind(&id)
            .fetch_one(&store.pool)
            .await
            .unwrap_or_else(|e| panic!("{table} row {id} must have exactly one lineage tag: {e}"));
            let actual_class: RetentionClass =
                serde_json::from_value(serde_json::Value::String(row.0)).unwrap();
            assert_eq!(
                actual_class, expected_class,
                "{table} row must be tagged with the AC1-documented retention class"
            );
        }

        // AC1 also requires: no untagged rows exist in any of the four
        // tables. A positive per-row check (above) can't catch a fifth
        // insert path added later that forgets to tag — walk each table
        // with a LEFT JOIN against dataset_lineage_tags instead.
        for table in ["agent_events", "claims", "evidence", "findings"] {
            let untagged: (i64,) = sqlx::query_as(&format!(
                "SELECT COUNT(*) FROM {table} t \
                 LEFT JOIN dataset_lineage_tags d \
                 ON d.record_table = '{table}' AND d.record_id = t.id \
                 WHERE d.record_id IS NULL"
            ))
            .fetch_one(&store.pool)
            .await
            .unwrap_or_else(|e| panic!("count untagged rows in {table}: {e}"));
            assert_eq!(
                untagged.0, 0,
                "{table} must have zero untagged rows after live-path inserts"
            );
        }

        std::fs::remove_file(&path).ok();
    }

    // --- FORNX-319 AC2/AC3: evidence/metadata separation --------------------

    #[tokio::test]
    async fn purge_evidence_payload_overwrites_only_the_payload_with_an_honest_marker() {
        let path = tmp_db_path("ac2-purge-payload");
        let store = Store::open(&path).await.expect("open db");
        let (_event, _claim, evidence, _finding) = seed_full_record_set(&store).await;

        let purged = store
            .purge_evidence_payload(&evidence.id.to_string(), Utc::now())
            .await
            .expect("purge evidence payload");
        assert!(purged, "a real row existed and must report as purged");

        let fetched = store
            .evidence_for_session("fornx-319-session")
            .await
            .expect("query evidence")
            .evidence;
        let ev = fetched
            .iter()
            .find(|e| e.id == evidence.id)
            .expect("evidence row must still exist — purge is a soft update, not a delete");
        assert!(ev.evidence_purged);
        assert_eq!(ev.payload, evidence_expired_payload_marker());
        assert_ne!(
            ev.payload,
            serde_json::json!({}),
            "an empty object reads as 'empty evidence was collected' — AC3 forbids exactly this"
        );
        // FORNX-319/FORNX-315: the purge itself must have emitted an
        // EvidencePurged audit event naming this evidence row.
        let audit_events = store.audit_events().await.expect("read audit ledger");
        assert_eq!(audit_events.len(), 1);
        assert_eq!(
            audit_events[0].event.action,
            fornax_types::audit::AuditAction::EvidencePurged
        );
        assert_eq!(
            audit_events[0].event.target,
            fornax_types::audit::AuditTarget::Evidence {
                target_id: evidence.id.to_string()
            }
        );

        assert_eq!(
            ev.payload["evidence_expired"],
            serde_json::json!(true),
            "the payload must explicitly say evidence expired, not render as UNAVAILABLE or absent"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn sweep_purges_expired_evidence_leaving_finding_verdict_and_rationale_byte_for_byte_intact(
    ) {
        let path = tmp_db_path("ac2-ac3-sweep-purge");
        let store = Store::open(&path).await.expect("open db");
        let (_event, _claim, evidence, finding) = seed_full_record_set(&store).await;

        // Backdate ONLY the evidence lineage tag past RAW_LOCAL_RETENTION —
        // simulates real elapsed time without waiting 30 real days.
        let backdated = (Utc::now()
            - chrono::Duration::from_std(RAW_LOCAL_RETENTION).unwrap()
            - chrono::Duration::days(1))
        .to_rfc3339();
        sqlx::query(
            "UPDATE dataset_lineage_tags SET recorded_at = ?1 WHERE record_table = 'evidence' AND record_id = ?2",
        )
        .bind(&backdated)
        .bind(evidence.id.to_string())
        .execute(&store.pool)
        .await
        .expect("backdate evidence lineage tag");

        let before = store
            .finding_by_id(&finding.id.to_string())
            .await
            .expect("query finding before sweep")
            .expect("finding exists before sweep");

        // AC2: a pre-existing, unrelated audit event must survive the
        // sweep-driven purge byte-for-byte, and the chain must extend
        // (not fork/corrupt) when the sweep appends its own event.
        let sentinel = fornax_types::audit::AuditEvent::new(
            "pre-existing-unrelated-event",
            "2026-09-03T00:00:00Z",
            fornax_types::audit::AuditActor::Device {
                actor_id: "device-sentinel".to_string(),
            },
            fornax_types::audit::AuditAction::PermissionCheck,
            fornax_types::audit::AuditTarget::Permission {
                target_id: "perm-sentinel".to_string(),
            },
            fornax_types::audit::AuditOutcome::Granted,
            fornax_types::audit::AuditExportClass::Metadata,
        );
        let sentinel_appended = store
            .append_audit_event(&sentinel, Utc::now())
            .await
            .expect("append sentinel audit event");

        let report = store
            .sweep_expired_records(Utc::now(), None, 100)
            .await
            .expect("sweep");
        assert_eq!(report.purged_evidence, 1);
        assert_eq!(
            report.deleted_records, 0,
            "the event/claim/finding lineage tags are not yet expired"
        );

        let after = store
            .finding_by_id(&finding.id.to_string())
            .await
            .expect("query finding after sweep")
            .expect("finding must survive a purge of its own evidence (ADR-0001 D4)");
        assert_eq!(before.verdict, after.verdict, "verdict must never change");
        assert_eq!(before.rationale, after.rationale);
        assert_eq!(before.evidence_ids, after.evidence_ids);
        assert_eq!(before.verifier_name, after.verifier_name);
        assert_eq!(before.computed_at, after.computed_at);

        let evidence_after = store
            .evidence_for_session("fornx-319-session")
            .await
            .expect("query evidence after sweep")
            .evidence;
        let ev = evidence_after
            .iter()
            .find(|e| e.id == evidence.id)
            .expect("evidence row still exists — soft purge, not delete");
        assert!(ev.evidence_purged);
        assert_eq!(ev.payload, evidence_expired_payload_marker());

        // FORNX-319/FORNX-315: the sweep-driven purge must have emitted an
        // EvidencePurged audit event too, after tx committed.
        let audit_events = store.audit_events().await.expect("read audit ledger");
        assert_eq!(audit_events.len(), 2);
        assert_eq!(
            audit_events[0].event, sentinel,
            "the pre-existing sentinel event must survive the purge unchanged"
        );
        assert_eq!(audit_events[0].seq, sentinel_appended.seq);
        assert_eq!(audit_events[0].entry_hash, sentinel_appended.entry_hash);
        assert_eq!(
            audit_events[1].event.action,
            fornax_types::audit::AuditAction::EvidencePurged
        );
        assert_eq!(
            audit_events[1].event.target,
            fornax_types::audit::AuditTarget::Evidence {
                target_id: evidence.id.to_string()
            }
        );

        // The sweep's append must extend the chain, not fork or corrupt it.
        let chain_state = store
            .verify_audit_chain()
            .await
            .expect("verify audit chain");
        assert_eq!(chain_state, crate::ChainVerification::Valid);

        let remaining_tag_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dataset_lineage_tags WHERE record_table = 'evidence' AND record_id = ?1",
        )
        .bind(evidence.id.to_string())
        .fetch_one(&store.pool)
        .await
        .expect("count remaining lineage tags");
        assert_eq!(
            remaining_tag_count, 0,
            "a processed (expired) tag must be removed"
        );

        std::fs::remove_file(&path).ok();
    }

    // --- FORNX-319 AC5/AC6: sweep expiry check reuses retention_duration_for,
    // including for Unrecognized ---------------------------------------------

    #[test]
    fn is_expired_uses_retention_duration_for_the_exact_threshold_and_the_unrecognized_safe_default(
    ) {
        let now = Utc::now();
        let raw_local = chrono::Duration::from_std(RAW_LOCAL_RETENTION).unwrap();
        let just_under = (now - raw_local + chrono::Duration::seconds(5)).to_rfc3339();
        let just_over = (now - raw_local - chrono::Duration::seconds(5)).to_rfc3339();

        assert!(!is_expired(&just_under, &RetentionClass::RawLocal, now));
        assert!(is_expired(&just_over, &RetentionClass::RawLocal, now));

        // AC6 regression: an Unrecognized class is swept at the same
        // (shortest, safest) duration as RawLocal, per
        // retention_duration_for's own safe default.
        let unrecognized = RetentionClass::Unrecognized("quarantined_pending_review".to_string());
        assert!(!is_expired(&just_under, &unrecognized, now));
        assert!(is_expired(&just_over, &unrecognized, now));

        // A malformed timestamp must never be guessed as expired.
        assert!(!is_expired(
            "not-a-timestamp",
            &RetentionClass::RawLocal,
            now
        ));
    }

    // --- FORNX-319 AC4: bounded, incremental sweep --------------------------

    async fn insert_synthetic_backlog(store: &Store, count: usize, recorded_at: &str) {
        let mut tx = store.pool.begin().await.expect("begin backlog tx");
        for i in 0..count {
            sqlx::query(
                "INSERT INTO dataset_lineage_tags
                    (id, record_table, record_id, schema_version, retention_class, tenant_ref,
                     source_record_ids, recorded_at, deletion_requested_at)
                 VALUES (?1, 'ac4_synthetic_backlog_table', ?2, 1, 'raw_local', 'ac4-tenant', '[]', ?3, NULL)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(format!("synthetic-row-{i}"))
            .bind(recorded_at)
            .execute(&mut *tx)
            .await
            .expect("hand-insert synthetic backlog row");
        }
        tx.commit().await.expect("commit backlog");
    }

    #[tokio::test]
    async fn sweep_processes_a_large_backlog_in_bounded_batches_across_multiple_calls() {
        let path = tmp_db_path("ac4-bounded-batches");
        let store = Store::open(&path).await.expect("open db");

        let expired_at = (Utc::now() - chrono::Duration::days(400)).to_rfc3339();
        insert_synthetic_backlog(&store, 2500, &expired_at).await;

        let batch_size = 400i64;
        let mut cursor: Option<String> = None;
        let mut total_examined = 0usize;
        let mut total_unknown_skipped = 0usize;
        let mut calls = 0usize;

        loop {
            let report = store
                .sweep_expired_records(Utc::now(), cursor.as_deref(), batch_size)
                .await
                .expect("sweep batch");
            calls += 1;
            assert!(
                report.examined <= batch_size as usize,
                "one call must never examine more than one bounded batch"
            );
            total_examined += report.examined;
            total_unknown_skipped += report.unknown_table_skipped;
            if report.examined == 0 {
                break;
            }
            cursor = report.next_cursor.clone();
            if cursor.is_none() {
                break;
            }
        }

        assert!(
            calls > 1,
            "a 2500-row backlog with a 400-row batch must take multiple calls, never one pass"
        );
        assert_eq!(total_examined, 2500);
        assert_eq!(
            total_unknown_skipped, 2500,
            "the synthetic backlog's table is unrecognized, so every expired row is skipped \
             (not deleted) but its lineage tag is still removed"
        );

        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dataset_lineage_tags WHERE record_table = 'ac4_synthetic_backlog_table'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            remaining, 0,
            "every processed (expired) tag must be removed"
        );

        std::fs::remove_file(&path).ok();
    }

    /// Scoped to the store layer directly (not the full daemon-binary
    /// harness `concurrent_hook_submission.rs` uses) — the sweep logic
    /// under test lives entirely in `Store`, with no daemon-process
    /// involvement, so a real subprocess adds cost without adding
    /// evidence. Mirrors that test's actual concern: a background task
    /// (there, another hook submission; here, a sweep batch) must not
    /// measurably delay ordinary live work sharing the same store.
    #[tokio::test]
    async fn sweeping_a_large_backlog_does_not_block_a_concurrent_insert_beyond_one_bounded_batch()
    {
        let path = tmp_db_path("ac4-concurrency");
        let store = Store::open(&path).await.expect("open db");

        let expired_at = (Utc::now() - chrono::Duration::days(400)).to_rfc3339();
        insert_synthetic_backlog(&store, 5000, &expired_at).await;

        let sweep_store = store.clone();
        let sweep_task = tokio::spawn(async move {
            // One bounded batch, deliberately far smaller than the 5000-row
            // backlog — the property under test.
            sweep_store
                .sweep_expired_records(Utc::now(), None, 200)
                .await
        });

        let insert_store = store.clone();
        let insert_task = tokio::spawn(async move {
            let event = AgentEvent {
                id: Uuid::new_v4(),
                session_id: "ac4-concurrent-insert".to_string(),
                provider: Provider::ClaudeCode,
                kind: EventKind::PostToolUse,
                observed_at: "2026-01-01T00:00:00Z".into(),
                tool_name: Some("Bash".into()),
                tool_input: None,
                tool_response: None,
                raw: serde_json::json!({}),
            };
            insert_store.insert_event(&event).await
        });

        let (sweep_result, insert_result) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(sweep_task, insert_task)
            })
            .await
            .expect(
                "neither task should take anywhere near 10s if the sweep is genuinely bounded to \
             one small batch rather than the whole 5000-row backlog",
            );

        let report = sweep_result
            .expect("sweep task panicked")
            .expect("sweep failed");
        assert_eq!(
            report.examined, 200,
            "one call processes one bounded batch, not the whole backlog"
        );
        insert_result
            .expect("insert task panicked")
            .expect("a concurrent insert must succeed while a bounded sweep batch runs");

        std::fs::remove_file(&path).ok();
    }

    // --- FORNX-319 AC8: no tenant_id column on any local table --------------

    #[tokio::test]
    async fn no_tenant_id_column_exists_on_any_known_record_table() {
        let path = tmp_db_path("ac8-no-tenant-id-column");
        let store = Store::open(&path).await.expect("open db");

        for table in KNOWN_RECORD_TABLES {
            let columns: Vec<(String,)> =
                sqlx::query_as(&format!("SELECT name FROM pragma_table_info('{table}')"))
                    .fetch_all(&store.pool)
                    .await
                    .unwrap_or_else(|e| panic!("read table_info for {table}: {e}"));
            assert!(
                !columns.iter().any(|(name,)| name == "tenant_id"),
                "{table} must not have a tenant_id column — TenantRef stays schema-only \
                 locally (FORNX-103/106 constraint)"
            );
        }

        std::fs::remove_file(&path).ok();
    }
}
