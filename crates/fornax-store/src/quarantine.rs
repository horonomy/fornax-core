//! Durable quarantine for ingest input the daemon could not process
//! (FORNX-212, parent FORNX-146).
//!
//! Before this module, `fornax-daemon::process_line` handled both a line
//! that failed to parse as `IngestMessage` and a line that parsed but
//! failed `handle_message` the same way: `tracing::warn!` and move on. The
//! line itself was gone — nothing queryable, nothing an operator could
//! inspect or replay. That is exactly the "critical evidence cannot be
//! silently dropped" acceptance criterion failing on real (if malformed or
//! transiently unprocessable) input, independent of any overload
//! scenario. This module gives that path somewhere durable to land
//! instead.
//!
//! Deliberately minimal: a flat append-only table, no retry/backoff state
//! machine, no automatic replay. Automatic replay of arbitrary quarantined
//! input is itself a correctness hazard (e.g. replaying a line that failed
//! because of a real schema mismatch would just fail again, or worse,
//! succeed partially) — out of scope for this slice; `list`/`count` make
//! the backlog observable and inspectable, which is what the acceptance
//! criterion actually asks for.

use chrono::Utc;
use uuid::Uuid;

use crate::{Result, Store};

/// Why a line was quarantined. Closed on purpose, mirroring
/// `fornax_types::EvidenceKind`'s own closed-enum precedent — a third
/// reason should widen one of these two, not add silently incompatible
/// cases a caller's `match` might not expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReason {
    /// The line was not valid JSON, or did not match any `IngestMessage`
    /// variant's shape.
    ParseError,
    /// The line parsed fine but `handle_message` returned an error (e.g. a
    /// store write failure).
    HandleError,
}

impl QuarantineReason {
    fn as_str(&self) -> &'static str {
        match self {
            QuarantineReason::ParseError => "parse_error",
            QuarantineReason::HandleError => "handle_error",
        }
    }
}

/// One row read back from `ingest_quarantine`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct QuarantinedLine {
    pub id: String,
    pub received_at: String,
    pub reason_kind: String,
    pub reason: String,
    pub raw_line: String,
}

impl Store {
    /// Durably records one unprocessable ingest line. Never fails the
    /// caller's connection — same contract `process_line` already has —
    /// but a failure here (e.g. a full disk) is returned, not silently
    /// swallowed a second time; the caller decides how loudly to warn.
    pub async fn record_quarantine(
        &self,
        raw_line: &str,
        reason: &str,
        kind: QuarantineReason,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let received_at = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO ingest_quarantine (id, received_at, reason_kind, reason, raw_line)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&id)
        .bind(&received_at)
        .bind(kind.as_str())
        .bind(reason)
        .bind(raw_line)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Most recent `limit` quarantined lines, newest first — the operator
    /// inspection/replay surface this table exists to support.
    pub async fn list_quarantine(&self, limit: i64) -> Result<Vec<QuarantinedLine>> {
        let rows = sqlx::query_as::<_, QuarantinedLine>(
            "SELECT id, received_at, reason_kind, reason, raw_line
             FROM ingest_quarantine ORDER BY received_at DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Total quarantined-line count — the measurable signal FORNX-212's
    /// "non-critical telemetry drop/sampling is explicit and measurable"
    /// AC asks for, applied here to the ingest-parse-failure path.
    pub async fn quarantine_count(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ingest_quarantine")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }
}
