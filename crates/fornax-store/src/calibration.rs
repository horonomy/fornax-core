//! Persistence for calibration revision snapshots (FORNX-348). This crate
//! has no dependency on `fornax-verify`/`fornax-types::calibration` — a
//! revision is stored and returned as opaque canonical JSON (`document`),
//! matching `acquisition_log.document`/`corpus_candidates.document`'s
//! existing precedent for an opaque JSON column.
//!
//! Insert-only — there is deliberately no update/delete method here. A
//! calibration going stale or drifted is recorded as a *new* revision, not
//! an edit of the old one, so the history of every baseline this
//! deployment has adopted stays intact. See the migration's own doc
//! comment for why this table is not session/tenant-scoped, unlike
//! [`crate::acquisition`].

use crate::{Result, Store};

/// One row read back from `calibration_revisions`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CalibrationRevisionRow {
    pub id: String,
    pub recorded_at: String,
    pub document: String,
}

impl Store {
    /// Record a new calibration revision. Never overwrites or replaces an
    /// existing row — this table has no update path at all.
    pub async fn insert_calibration_revision(
        &self,
        id: &str,
        recorded_at: &str,
        document: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO calibration_revisions (id, recorded_at, document) VALUES (?1, ?2, ?3)",
        )
        .bind(id)
        .bind(recorded_at)
        .bind(document)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The most recently recorded calibration revision, if any has ever
    /// been recorded. "Most recent" is by `recorded_at`, not by
    /// auto-increment rowid, since `id` is a caller-supplied string, not a
    /// sequence.
    pub async fn latest_calibration_revision(&self) -> Result<Option<CalibrationRevisionRow>> {
        let row = sqlx::query_as::<_, CalibrationRevisionRow>(
            "SELECT id, recorded_at, document FROM calibration_revisions
             ORDER BY recorded_at DESC, id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// One calibration revision by id, for a caller that already has a
    /// specific revision id in hand (e.g. from an earlier
    /// `latest_calibration_revision` read it wants to re-verify).
    pub async fn calibration_revision_by_id(
        &self,
        id: &str,
    ) -> Result<Option<CalibrationRevisionRow>> {
        let row = sqlx::query_as::<_, CalibrationRevisionRow>(
            "SELECT id, recorded_at, document FROM calibration_revisions WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> Store {
        let path = std::env::temp_dir().join(format!(
            "fornax-calibration-test-{}.db",
            uuid::Uuid::new_v4()
        ));
        Store::open(&path).await.expect("open store")
    }

    #[tokio::test]
    async fn no_revision_recorded_yet_reads_back_none() {
        let store = store().await;
        assert!(store
            .latest_calibration_revision()
            .await
            .expect("query")
            .is_none());
    }

    #[tokio::test]
    async fn insert_and_read_back_the_latest_revision() {
        let store = store().await;
        store
            .insert_calibration_revision("rev-1", "2026-01-01T00:00:00Z", "{}")
            .await
            .expect("insert");
        store
            .insert_calibration_revision("rev-2", "2026-01-02T00:00:00Z", "{\"n\":2}")
            .await
            .expect("insert");

        let latest = store
            .latest_calibration_revision()
            .await
            .expect("query")
            .expect("a revision exists");
        assert_eq!(latest.id, "rev-2");
        assert_eq!(latest.document, "{\"n\":2}");
    }

    #[tokio::test]
    async fn earlier_revision_is_never_overwritten_by_a_later_insert() {
        let store = store().await;
        store
            .insert_calibration_revision("rev-1", "2026-01-01T00:00:00Z", "{}")
            .await
            .expect("insert");
        store
            .insert_calibration_revision("rev-2", "2026-01-02T00:00:00Z", "{}")
            .await
            .expect("insert");

        let first = store
            .calibration_revision_by_id("rev-1")
            .await
            .expect("query")
            .expect("rev-1 still exists");
        assert_eq!(first.id, "rev-1");
    }
}
