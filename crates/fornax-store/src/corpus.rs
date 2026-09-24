//! Persistence for `fornax-corpus`'s mined `CandidateCase` artifacts
//! (FORNX-341). This crate has no dependency on `fornax-corpus` — a
//! candidate is stored and returned as opaque canonical JSON (`document`),
//! matching `evidence.payload`'s existing precedent for an opaque JSON
//! column. Every insert is wired into the same FORNX-106 lineage machinery
//! as `insert_finding` (see [`crate::retention`]).

use fornax_types::{DatasetLineageTag, RetentionClass, TenantRef};

use crate::{insert_lineage_tag_row, Result, Store, StoreError};

/// One row read back from `corpus_candidates`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CorpusCandidateRow {
    pub id: String,
    pub session_id: String,
    pub schema_version: i64,
    pub mined_at: String,
    pub document: String,
}

impl Store {
    /// Persist one mined candidate's canonical JSON `document` under `id`,
    /// tagged with `session_id` as its tenant, plus the `DatasetLineageTag`
    /// that lets `Store::delete_records_for_tenant`/`sweep_expired_records`
    /// find and remove it later.
    ///
    /// Refuses with [`StoreError::CorpusMiningDisabled`] while
    /// `FORNAX_CORPUS_MINING_ENABLED` is unset/false — this is the actual
    /// enforcement point for that gate; nothing upstream of this call
    /// already checks it (unlike the two longitudinal-collection classes,
    /// which have no other write path to guard).
    ///
    /// **Idempotent** (FORNX-342 fix): `id` is content-derived
    /// (`CandidateCase::derive_id`), so re-mining an unchanged session
    /// produces the same id. `INSERT OR IGNORE` plus checking rows-affected
    /// makes a duplicate insert a silent no-op instead of a `UNIQUE`
    /// constraint error — before this fix, `fornax corpus mine` re-run
    /// against an already-mined session aborted the rest of that mining
    /// run on the first duplicate claim.
    pub async fn insert_corpus_candidate(
        &self,
        id: &str,
        session_id: &str,
        schema_version: u32,
        mined_at: &str,
        document: &str,
        source_record_ids: Vec<uuid::Uuid>,
    ) -> Result<()> {
        if !crate::retention::longitudinal_persistence_allowed(&RetentionClass::SanitizedCandidate)
        {
            return Err(StoreError::CorpusMiningDisabled);
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO corpus_candidates (id, session_id, schema_version, mined_at, document)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(id)
        .bind(session_id)
        .bind(schema_version as i64)
        .bind(mined_at)
        .bind(document)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            // Already present (same content-derived id) -- the lineage tag
            // was written the first time this id was inserted; nothing more
            // to do.
            tx.commit().await?;
            return Ok(());
        }

        let lineage_tag = DatasetLineageTag::new(
            RetentionClass::SanitizedCandidate,
            TenantRef(session_id.to_string()),
        )
        .derived_from(source_record_ids);
        insert_lineage_tag_row(&mut *tx, "corpus_candidates", id, &lineage_tag).await?;

        tx.commit().await?;
        Ok(())
    }

    /// All mined candidates for one session, oldest first.
    pub async fn corpus_candidates_for_session(
        &self,
        session_id: &str,
    ) -> Result<Vec<CorpusCandidateRow>> {
        let rows = sqlx::query_as::<_, CorpusCandidateRow>(
            "SELECT id, session_id, schema_version, mined_at, document
             FROM corpus_candidates WHERE session_id = ?1 ORDER BY mined_at ASC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// One candidate by its own id, if it has not been deleted/expired
    /// (FORNX-342: the adjudication workflow looks candidates up by id, not
    /// by session).
    pub async fn get_corpus_candidate(&self, id: &str) -> Result<Option<CorpusCandidateRow>> {
        let row = sqlx::query_as::<_, CorpusCandidateRow>(
            "SELECT id, session_id, schema_version, mined_at, document
             FROM corpus_candidates WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Every mined candidate in this store, oldest first — the input
    /// `fornax corpus export` reads to build a manifest.
    pub async fn all_corpus_candidates(&self) -> Result<Vec<CorpusCandidateRow>> {
        let rows = sqlx::query_as::<_, CorpusCandidateRow>(
            "SELECT id, session_id, schema_version, mined_at, document
             FROM corpus_candidates ORDER BY mined_at ASC",
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
            "fornax-corpus-store-test-{name}-{}.db",
            uuid::Uuid::new_v4()
        ))
    }

    // One test, not several: std::env::set_var/remove_var is process-global
    // and cargo runs tests in parallel by default -- every assertion that
    // depends on FORNAX_CORPUS_MINING_ENABLED's value lives in this one
    // function so no other test can race it (same reason
    // fornax_types::privacy's own gate tests are single functions).
    // Held across await points deliberately -- this is a #[tokio::test]'s
    // own single-threaded runtime, not a shared server, so there is no
    // deadlock risk; the guard's whole job is to keep this function's env
    // var mutations from interleaving with any other test's.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn insert_respects_the_mining_gate_and_isolates_by_session() {
        let _guard = crate::CORPUS_MINING_GATE_TEST_LOCK.lock().unwrap();
        std::env::remove_var("FORNAX_CORPUS_MINING_ENABLED");
        let path = tmp_db_path("gate-and-isolation");
        let store = Store::open(&path).await.expect("open db");

        let err = store
            .insert_corpus_candidate("c1", "s1", 1, "2026-01-01T00:00:00Z", "{}", vec![])
            .await
            .expect_err("insert must refuse while the gate is closed");
        assert!(matches!(err, StoreError::CorpusMiningDisabled));
        let all = store
            .all_corpus_candidates()
            .await
            .expect("query candidates");
        assert!(all.is_empty(), "a refused insert must not leave a row");

        std::env::set_var("FORNAX_CORPUS_MINING_ENABLED", "1");
        store
            .insert_corpus_candidate("c1", "s1", 1, "2026-01-01T00:00:00Z", "{\"k\":1}", vec![])
            .await
            .expect("insert candidate once the gate is open");

        let for_session = store
            .corpus_candidates_for_session("s1")
            .await
            .expect("query by session");
        assert_eq!(for_session.len(), 1);
        assert_eq!(for_session[0].document, "{\"k\":1}");

        let tenant_s1 = TenantRef("s1".to_string());
        let tags = store
            .lineage_tags_for_tenant(&tenant_s1)
            .await
            .expect("query lineage tags");
        assert_eq!(tags.len(), 1);

        // Cross-session isolation: a second session's candidate must
        // survive deleting the first session's.
        store
            .insert_corpus_candidate("c2", "session-b", 1, "2026-01-01T00:00:00Z", "{}", vec![])
            .await
            .expect("insert candidate for session-b");

        store
            .delete_records_for_tenant(&tenant_s1)
            .await
            .expect("delete session s1");

        let s1_after = store
            .corpus_candidates_for_session("s1")
            .await
            .expect("query s1 after delete");
        assert!(s1_after.is_empty());

        let b_after = store
            .corpus_candidates_for_session("session-b")
            .await
            .expect("query session-b after deleting s1");
        assert_eq!(
            b_after.len(),
            1,
            "deleting one session's candidate must leave another session's untouched"
        );

        std::env::remove_var("FORNAX_CORPUS_MINING_ENABLED");
        std::fs::remove_file(&path).ok();
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn inserting_the_same_candidate_id_twice_is_idempotent_not_an_error() {
        let _guard = crate::CORPUS_MINING_GATE_TEST_LOCK.lock().unwrap();
        std::env::set_var("FORNAX_CORPUS_MINING_ENABLED", "1");
        let path = tmp_db_path("idempotent-insert");
        let store = Store::open(&path).await.expect("open db");

        store
            .insert_corpus_candidate("c1", "s1", 1, "2026-01-01T00:00:00Z", "{\"k\":1}", vec![])
            .await
            .expect("first insert");
        store
            .insert_corpus_candidate("c1", "s1", 1, "2026-01-01T00:00:00Z", "{\"k\":1}", vec![])
            .await
            .expect("re-mining the same content-derived id must not error");

        let rows = store
            .corpus_candidates_for_session("s1")
            .await
            .expect("query by session");
        assert_eq!(
            rows.len(),
            1,
            "duplicate insert must not create a second row"
        );

        let tags = store
            .lineage_tags_for_tenant(&TenantRef("s1".to_string()))
            .await
            .expect("query lineage tags");
        assert_eq!(
            tags.len(),
            1,
            "duplicate insert must not create a second lineage tag either"
        );

        std::env::remove_var("FORNAX_CORPUS_MINING_ENABLED");
        std::fs::remove_file(&path).ok();
    }
}
