//! Persistence for `fornax-acquire`'s real evidence-acquisition attempts
//! (FORNX-346). This crate has no dependency on `fornax-acquire` — an
//! attempt is stored and returned as opaque canonical JSON (`document`),
//! matching `corpus_candidates.document`/`evidence.payload`'s existing
//! precedent for an opaque JSON column. Wired into `RetentionClass::RawLocal`
//! (see [`crate::retention`]) -- the same class as `evidence` itself.

use crate::{Result, Store};

/// One row read back from `acquisition_log`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AcquisitionLogRow {
    pub id: String,
    pub session_id: String,
    pub claim_id: String,
    pub probe_kind: String,
    pub policy_name: String,
    pub policy_version: i64,
    pub outcome_kind: String,
    pub requested_at: String,
    pub document: String,
}

impl Store {
    /// Persist one acquisition attempt, whatever its outcome. Never
    /// refused/gated at this layer -- gating happens before this is ever
    /// called (`fornax_acquire::gate`); this method's only job is to record
    /// what happened.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_acquisition_log_entry(
        &self,
        id: &str,
        session_id: &str,
        claim_id: &str,
        probe_kind: &str,
        policy_name: &str,
        policy_version: u32,
        outcome_kind: &str,
        requested_at: &str,
        document: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO acquisition_log
                (id, session_id, claim_id, probe_kind, policy_name, policy_version, outcome_kind, requested_at, document)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(id)
        .bind(session_id)
        .bind(claim_id)
        .bind(probe_kind)
        .bind(policy_name)
        .bind(policy_version as i64)
        .bind(outcome_kind)
        .bind(requested_at)
        .bind(document)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Every acquisition attempt for one `(session_id, claim_id)` pair.
    /// Session-scoped -- a caller cannot list another session's attempts
    /// (FORNX-339 discipline).
    pub async fn acquisition_log_for_claim(
        &self,
        session_id: &str,
        claim_id: &str,
    ) -> Result<Vec<AcquisitionLogRow>> {
        let rows = sqlx::query_as::<_, AcquisitionLogRow>(
            "SELECT id, session_id, claim_id, probe_kind, policy_name, policy_version, outcome_kind, requested_at, document
             FROM acquisition_log WHERE session_id = ?1 AND claim_id = ?2 ORDER BY requested_at ASC",
        )
        .bind(session_id)
        .bind(claim_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> Store {
        let path = std::env::temp_dir().join(format!(
            "fornax-acquisition-test-{}.db",
            uuid::Uuid::new_v4()
        ));
        Store::open(&path).await.expect("open store")
    }

    #[tokio::test]
    async fn insert_and_read_back_an_acquisition_log_entry() {
        let store = store().await;
        store
            .insert_acquisition_log_entry(
                "log-1",
                "s1",
                "c1",
                "verify_artifact_hash",
                "fornax_acquire_v1",
                1,
                "acquired",
                "2026-01-01T00:00:00Z",
                "{}",
            )
            .await
            .expect("insert");

        let rows = store
            .acquisition_log_for_claim("s1", "c1")
            .await
            .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome_kind, "acquired");
    }

    #[tokio::test]
    async fn acquisition_log_is_scoped_by_session() {
        let store = store().await;
        store
            .insert_acquisition_log_entry(
                "log-1",
                "s1",
                "c1",
                "verify_artifact_hash",
                "p",
                1,
                "acquired",
                "2026-01-01T00:00:00Z",
                "{}",
            )
            .await
            .expect("insert");

        let rows = store
            .acquisition_log_for_claim("s2", "c1")
            .await
            .expect("query");
        assert!(rows.is_empty());
    }
}
