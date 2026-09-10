//! Persistence for `fornax-corpus`'s adjudication workflow (FORNX-342). Same
//! opaque-canonical-JSON `document` shape as `crate::corpus`'s
//! `corpus_candidates` -- this crate has no dependency on `fornax-corpus`
//! and never parses these documents. See `migrations/0014_adjudication.sql`
//! for the full table-by-table rationale, in particular why
//! `adjudication_reviewers` and `gold_labels` are the two tables NOT wired
//! into FORNX-106 tenant lineage.

use fornax_types::{DatasetLineageTag, RetentionClass, TenantRef};

use crate::{insert_lineage_tag_row, Result, Store, StoreError};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReviewerRow {
    pub id: String,
    pub document: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct QueueEntryRow {
    pub case_id: String,
    pub document: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ViewRow {
    pub id: String,
    pub case_id: String,
    pub reviewer_id: String,
    pub document: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReviewRow {
    pub id: String,
    pub case_id: String,
    pub reviewer_id: String,
    pub round: i64,
    pub document: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GoldLabelRow {
    pub case_id: String,
    pub revision: i64,
    pub document: String,
}

fn require_mining_gate() -> Result<()> {
    if !crate::retention::longitudinal_persistence_allowed(&RetentionClass::SanitizedCandidate) {
        return Err(StoreError::CorpusMiningDisabled);
    }
    Ok(())
}

impl Store {
    // --- Reviewers (NOT lineage-tagged -- see module docs) -----------------

    pub async fn insert_reviewer(&self, id: &str, document: &str) -> Result<()> {
        require_mining_gate()?;
        sqlx::query("INSERT OR REPLACE INTO adjudication_reviewers (id, document) VALUES (?1, ?2)")
            .bind(id)
            .bind(document)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_reviewer(&self, id: &str) -> Result<Option<ReviewerRow>> {
        let row = sqlx::query_as::<_, ReviewerRow>(
            "SELECT id, document FROM adjudication_reviewers WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn all_reviewers(&self) -> Result<Vec<ReviewerRow>> {
        let rows =
            sqlx::query_as::<_, ReviewerRow>("SELECT id, document FROM adjudication_reviewers")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows)
    }

    // --- Queue entries (lineage-tagged) -------------------------------------

    pub async fn insert_queue_entry(
        &self,
        case_id: &str,
        session_id: &str,
        document: &str,
        source_record_ids: Vec<uuid::Uuid>,
    ) -> Result<()> {
        require_mining_gate()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO adjudication_queue (case_id, document) VALUES (?1, ?2)",
        )
        .bind(case_id)
        .bind(document)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() > 0 {
            let tag = DatasetLineageTag::new(
                RetentionClass::SanitizedCandidate,
                TenantRef(session_id.to_string()),
            )
            .derived_from(source_record_ids);
            insert_lineage_tag_row(&mut *tx, "adjudication_queue", case_id, &tag).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_queue_entry(&self, case_id: &str) -> Result<Option<QueueEntryRow>> {
        let row = sqlx::query_as::<_, QueueEntryRow>(
            "SELECT case_id, document FROM adjudication_queue WHERE case_id = ?1",
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn all_queue_entries(&self) -> Result<Vec<QueueEntryRow>> {
        let rows =
            sqlx::query_as::<_, QueueEntryRow>("SELECT case_id, document FROM adjudication_queue")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows)
    }

    // --- Issued views (lineage-tagged) --------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_view(
        &self,
        id: &str,
        case_id: &str,
        reviewer_id: &str,
        session_id: &str,
        document: &str,
        source_record_ids: Vec<uuid::Uuid>,
    ) -> Result<()> {
        require_mining_gate()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO adjudication_views (id, case_id, reviewer_id, document)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(id)
        .bind(case_id)
        .bind(reviewer_id)
        .bind(document)
        .execute(&mut *tx)
        .await?;
        let tag = DatasetLineageTag::new(
            RetentionClass::SanitizedCandidate,
            TenantRef(session_id.to_string()),
        )
        .derived_from(source_record_ids);
        insert_lineage_tag_row(&mut *tx, "adjudication_views", id, &tag).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_view(&self, id: &str) -> Result<Option<ViewRow>> {
        let row = sqlx::query_as::<_, ViewRow>(
            "SELECT id, case_id, reviewer_id, document FROM adjudication_views WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn views_for_case(&self, case_id: &str) -> Result<Vec<ViewRow>> {
        let rows = sqlx::query_as::<_, ViewRow>(
            "SELECT id, case_id, reviewer_id, document FROM adjudication_views WHERE case_id = ?1",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // --- Reviews (lineage-tagged) --------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_review(
        &self,
        id: &str,
        case_id: &str,
        reviewer_id: &str,
        round: u32,
        session_id: &str,
        document: &str,
        source_record_ids: Vec<uuid::Uuid>,
    ) -> Result<()> {
        require_mining_gate()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO adjudication_reviews (id, case_id, reviewer_id, round, document)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(id)
        .bind(case_id)
        .bind(reviewer_id)
        .bind(round as i64)
        .bind(document)
        .execute(&mut *tx)
        .await?;
        let tag = DatasetLineageTag::new(
            RetentionClass::SanitizedCandidate,
            TenantRef(session_id.to_string()),
        )
        .derived_from(source_record_ids);
        insert_lineage_tag_row(&mut *tx, "adjudication_reviews", id, &tag).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn reviews_for_case(&self, case_id: &str) -> Result<Vec<ReviewRow>> {
        let rows = sqlx::query_as::<_, ReviewRow>(
            "SELECT id, case_id, reviewer_id, round, document FROM adjudication_reviews
             WHERE case_id = ?1",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // --- Gold labels (insert-only, NOT lineage-tagged -- see module docs) --

    /// Refuses with [`StoreError::GoldLabelAlreadyFrozen`] if `(case_id,
    /// revision)` already exists -- this table is insert-only by contract,
    /// not merely by convention.
    pub async fn insert_gold_label(
        &self,
        case_id: &str,
        revision: u32,
        document: &str,
    ) -> Result<()> {
        require_mining_gate()?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO gold_labels (case_id, revision, document) VALUES (?1, ?2, ?3)",
        )
        .bind(case_id)
        .bind(revision as i64)
        .bind(document)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::GoldLabelAlreadyFrozen {
                case_id: case_id.to_string(),
                revision,
            });
        }
        Ok(())
    }

    pub async fn gold_labels_for_case(&self, case_id: &str) -> Result<Vec<GoldLabelRow>> {
        let rows = sqlx::query_as::<_, GoldLabelRow>(
            "SELECT case_id, revision, document FROM gold_labels
             WHERE case_id = ?1 ORDER BY revision ASC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn latest_gold_label_for_case(&self, case_id: &str) -> Result<Option<GoldLabelRow>> {
        let row = sqlx::query_as::<_, GoldLabelRow>(
            "SELECT case_id, revision, document FROM gold_labels
             WHERE case_id = ?1 ORDER BY revision DESC LIMIT 1",
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn all_gold_labels(&self) -> Result<Vec<GoldLabelRow>> {
        let rows = sqlx::query_as::<_, GoldLabelRow>(
            "SELECT case_id, revision, document FROM gold_labels ORDER BY case_id ASC, revision ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fornax-adjudication-store-test-{name}-{}.db",
            uuid::Uuid::new_v4()
        ))
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn reviewers_are_not_lineage_tagged_and_survive_a_tenant_delete() {
        let _guard = crate::CORPUS_MINING_GATE_TEST_LOCK.lock().unwrap();
        std::env::set_var("FORNAX_CORPUS_MINING_ENABLED", "1");
        let path = tmp_db_path("reviewers");
        let store = Store::open(&path).await.expect("open db");

        store
            .insert_reviewer("r1", "{\"kind\":\"human\"}")
            .await
            .expect("insert reviewer");

        // Reviewers carry no lineage tag, so a tenant delete for any session
        // (even one this reviewer never touched) cannot possibly remove one.
        store
            .delete_records_for_tenant(&TenantRef("some-session".to_string()))
            .await
            .expect("delete for an unrelated tenant");

        let reviewer = store
            .get_reviewer("r1")
            .await
            .expect("query reviewer")
            .expect("reviewer must survive since it was never tenant-tagged");
        assert_eq!(reviewer.document, "{\"kind\":\"human\"}");

        std::env::remove_var("FORNAX_CORPUS_MINING_ENABLED");
        std::fs::remove_file(&path).ok();
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn queue_view_and_review_are_tenant_deleted_but_gold_label_survives() {
        let _guard = crate::CORPUS_MINING_GATE_TEST_LOCK.lock().unwrap();
        std::env::set_var("FORNAX_CORPUS_MINING_ENABLED", "1");
        let path = tmp_db_path("tenant-delete-mix");
        let store = Store::open(&path).await.expect("open db");

        let case_id = "case-1";
        store
            .insert_queue_entry(case_id, "s1", "{}", vec![])
            .await
            .expect("insert queue entry");
        store
            .insert_view("view-1", case_id, "r1", "s1", "{}", vec![])
            .await
            .expect("insert view");
        store
            .insert_review("review-1", case_id, "r1", 1, "s1", "{}", vec![])
            .await
            .expect("insert review");
        store
            .insert_gold_label(case_id, 1, "{\"label\":\"reliable\"}")
            .await
            .expect("insert gold label");

        store
            .delete_records_for_tenant(&TenantRef("s1".to_string()))
            .await
            .expect("delete tenant s1");

        assert!(store
            .get_queue_entry(case_id)
            .await
            .expect("query queue")
            .is_none());
        assert!(store
            .views_for_case(case_id)
            .await
            .expect("query views")
            .is_empty());
        assert!(store
            .reviews_for_case(case_id)
            .await
            .expect("query reviews")
            .is_empty());

        let gold = store
            .latest_gold_label_for_case(case_id)
            .await
            .expect("query gold label")
            .expect("gold_labels is insert-only metadata and must survive a tenant delete");
        assert_eq!(gold.document, "{\"label\":\"reliable\"}");

        std::env::remove_var("FORNAX_CORPUS_MINING_ENABLED");
        std::fs::remove_file(&path).ok();
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_second_insert_at_the_same_revision_is_refused() {
        let _guard = crate::CORPUS_MINING_GATE_TEST_LOCK.lock().unwrap();
        std::env::set_var("FORNAX_CORPUS_MINING_ENABLED", "1");
        let path = tmp_db_path("gold-immutable");
        let store = Store::open(&path).await.expect("open db");

        store
            .insert_gold_label("case-1", 1, "{\"label\":\"reliable\"}")
            .await
            .expect("first freeze");
        let err = store
            .insert_gold_label("case-1", 1, "{\"label\":\"unreliable\"}")
            .await
            .expect_err("must refuse overwriting an existing revision");
        assert!(matches!(err, StoreError::GoldLabelAlreadyFrozen { .. }));

        // Revision 1's original content must be untouched.
        let gold = store
            .latest_gold_label_for_case("case-1")
            .await
            .expect("query")
            .unwrap();
        assert_eq!(gold.document, "{\"label\":\"reliable\"}");

        // A different revision number for the same case is fine.
        store
            .insert_gold_label("case-1", 2, "{\"label\":\"unreliable\"}")
            .await
            .expect("a genuinely new revision succeeds");

        std::env::remove_var("FORNAX_CORPUS_MINING_ENABLED");
        std::fs::remove_file(&path).ok();
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn writes_are_refused_while_the_mining_gate_is_closed() {
        let _guard = crate::CORPUS_MINING_GATE_TEST_LOCK.lock().unwrap();
        std::env::remove_var("FORNAX_CORPUS_MINING_ENABLED");
        let path = tmp_db_path("gate-closed-adjudication");
        let store = Store::open(&path).await.expect("open db");

        assert!(matches!(
            store.insert_reviewer("r1", "{}").await.unwrap_err(),
            StoreError::CorpusMiningDisabled
        ));
        assert!(matches!(
            store
                .insert_queue_entry("c1", "s1", "{}", vec![])
                .await
                .unwrap_err(),
            StoreError::CorpusMiningDisabled
        ));
        assert!(matches!(
            store.insert_gold_label("c1", 1, "{}").await.unwrap_err(),
            StoreError::CorpusMiningDisabled
        ));

        std::fs::remove_file(&path).ok();
    }
}
