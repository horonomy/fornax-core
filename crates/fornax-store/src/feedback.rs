//! Persistence for `fornax-corpus`'s product feedback (FORNX-349). This
//! crate has no dependency on `fornax-corpus` -- feedback is stored and
//! returned as opaque canonical JSON (`document`), matching
//! `corpus_candidates.document`/`acquisition_log.document`'s existing
//! precedent for an opaque JSON column. Wired into the same
//! `RetentionClass::SanitizedCandidate` lineage as `corpus_candidates`
//! itself (see [`crate::retention`]) -- feedback about a case is exactly
//! as research-sensitive as the case it is about, gated behind the same
//! `FORNAX_CORPUS_MINING_ENABLED` opt-in.

use fornax_types::{DatasetLineageTag, RetentionClass, TenantRef};

use crate::{insert_lineage_tag_row, Result, Store, StoreError};

/// One row read back from `review_feedback`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReviewFeedbackRow {
    pub id: String,
    pub case_id: String,
    pub session_id: String,
    pub submitted_at: String,
    pub document: String,
}

impl Store {
    /// Persist one piece of feedback, tagged with `session_id` as its
    /// tenant, plus the `DatasetLineageTag` that lets
    /// `Store::delete_records_for_tenant`/`sweep_expired_records` find and
    /// remove it later. Refuses with [`StoreError::CorpusMiningDisabled`]
    /// while `FORNAX_CORPUS_MINING_ENABLED` is unset/false -- same gate as
    /// `insert_corpus_candidate`, so feedback never accumulates silently
    /// while the operator has not opted into corpus mining at all.
    pub async fn insert_feedback(
        &self,
        id: &str,
        case_id: &str,
        session_id: &str,
        submitted_at: &str,
        document: &str,
        source_record_ids: Vec<uuid::Uuid>,
    ) -> Result<()> {
        if !crate::retention::longitudinal_persistence_allowed(&RetentionClass::SanitizedCandidate)
        {
            return Err(StoreError::CorpusMiningDisabled);
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO review_feedback (id, case_id, session_id, submitted_at, document)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(id)
        .bind(case_id)
        .bind(session_id)
        .bind(submitted_at)
        .bind(document)
        .execute(&mut *tx)
        .await?;

        let lineage_tag = DatasetLineageTag::new(
            RetentionClass::SanitizedCandidate,
            TenantRef(session_id.to_string()),
        )
        .derived_from(source_record_ids);
        insert_lineage_tag_row(&mut *tx, "review_feedback", id, &lineage_tag).await?;

        tx.commit().await?;
        Ok(())
    }

    /// All feedback recorded against one case, oldest first.
    pub async fn feedback_for_case(&self, case_id: &str) -> Result<Vec<ReviewFeedbackRow>> {
        let rows = sqlx::query_as::<_, ReviewFeedbackRow>(
            "SELECT id, case_id, session_id, submitted_at, document
             FROM review_feedback WHERE case_id = ?1 ORDER BY submitted_at ASC",
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Every piece of feedback in this store, oldest first -- the input
    /// `fornax adjudicate sample` reads to derive
    /// `SamplingSignal::HumanFeedbackDisagreement`.
    pub async fn all_feedback(&self) -> Result<Vec<ReviewFeedbackRow>> {
        let rows = sqlx::query_as::<_, ReviewFeedbackRow>(
            "SELECT id, case_id, session_id, submitted_at, document
             FROM review_feedback ORDER BY submitted_at ASC",
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
            "fornax-feedback-store-test-{name}-{}.db",
            uuid::Uuid::new_v4()
        ))
    }

    // One test, not several -- same reasoning as
    // `crate::corpus::tests::insert_respects_the_mining_gate_and_isolates_by_session`:
    // std::env::set_var/remove_var is process-global and cargo runs tests
    // in parallel by default, so every assertion depending on
    // FORNAX_CORPUS_MINING_ENABLED lives in one function under the shared
    // lock.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn insert_respects_the_mining_gate_and_is_scoped_by_case() {
        let _guard = crate::CORPUS_MINING_GATE_TEST_LOCK.lock().unwrap();
        std::env::remove_var("FORNAX_CORPUS_MINING_ENABLED");
        let path = tmp_db_path("gate-and-case-scope");
        let store = Store::open(&path).await.expect("open db");

        let err = store
            .insert_feedback("fb-1", "case-1", "s1", "2026-01-01T00:00:00Z", "{}", vec![])
            .await
            .expect_err("insert must refuse while the gate is closed");
        assert!(matches!(err, StoreError::CorpusMiningDisabled));

        std::env::set_var("FORNAX_CORPUS_MINING_ENABLED", "1");
        store
            .insert_feedback(
                "fb-1",
                "case-1",
                "s1",
                "2026-01-01T00:00:00Z",
                "{\"k\":1}",
                vec![],
            )
            .await
            .expect("insert once the gate is open");

        let for_case1 = store.feedback_for_case("case-1").await.expect("query");
        assert_eq!(for_case1.len(), 1);
        assert_eq!(for_case1[0].document, "{\"k\":1}");

        let for_case2 = store.feedback_for_case("case-2").await.expect("query");
        assert!(for_case2.is_empty());

        let tenant_s1 = TenantRef("s1".to_string());
        store
            .delete_records_for_tenant(&tenant_s1)
            .await
            .expect("delete session s1");
        let after_delete = store.feedback_for_case("case-1").await.expect("query");
        assert!(
            after_delete.is_empty(),
            "tenant delete must remove feedback"
        );

        std::env::remove_var("FORNAX_CORPUS_MINING_ENABLED");
        std::fs::remove_file(&path).ok();
    }
}
