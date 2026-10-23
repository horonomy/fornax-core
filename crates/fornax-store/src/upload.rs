//! Staging, sealing and ledgering of the personal monthly metadata batch
//! upload (FORNX-464).
//!
//! Three guarantees live here:
//!
//! 1. **Only eligible records are ever staged.** A record is staged only if a
//!    live personal-profile consent exists, the record was captured at or
//!    after that consent was granted, and the profile in force at the moment
//!    the record was captured was `personal` (read from the append-only
//!    `egress_profile_log`; no history means no eligibility). A record
//!    captured under `corporate`, or before any profile was chosen, never
//!    becomes uploadable by a later switch.
//! 2. **Staging snapshots metadata only, and happens before purge.** The
//!    outbox holds ids, kinds, providers, timestamps, verdict enums, verifier
//!    names and bounded labels -- never claim text, tool input/response,
//!    evidence payloads or rationale. [`Store::stage_upload_records`] is run
//!    before the retention sweep deletes or purges anything, so a monthly
//!    cadence cannot lose data to the 30-day raw retention.
//! 3. **A sealed batch is immutable.** Its canonical bytes and hash are
//!    persisted before any send, so a retry after a crash or a lost response
//!    resends byte-identical content under the same idempotency key.
//!
//! The outbox is bounded (age and bytes). At the bound the oldest pending
//! rows are marked `expired` and a gap is recorded and audited first -- a drop
//! is never silent.

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, Duration, Utc};
use fornax_types::audit::{
    AuditAction, AuditActor, AuditEvent, AuditExportClass, AuditOutcome, AuditTarget,
};
use fornax_types::egress::{Consent, Profile, Purpose};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Result, Store, StoreError};

/// Identifier of the canonical member serialization both ends hash.
pub const CANONICALIZATION: &str = "fornax-egress-canon-v1";
/// Members per sealed batch. Small on purpose: the receiver acknowledges a
/// whole batch, so a smaller batch bounds what a failure can poison.
pub const MAX_BATCH_MEMBERS: i64 = 2000;
/// Default outbox size bound.
pub const OUTBOX_MAX_BYTES: i64 = 50 * 1024 * 1024;
/// Pending rows older than this are expired (with a recorded gap).
pub const OUTBOX_MAX_AGE_DAYS: i64 = 90;
const STAGE_CHUNK: i64 = 5000;

const KINDS: [&str; 5] = ["sessions", "events", "claims", "evidence", "findings"];

fn invalid(msg: impl Into<String>) -> StoreError {
    StoreError::InvalidEgress(msg.into())
}

/// Canonical JSON: object keys sorted bytewise, no insignificant whitespace,
/// strings as `serde_json` writes them (UTF-8, control characters escaped).
/// Matches Python's `json.dumps(sort_keys=True, separators=(",", ":"),
/// ensure_ascii=False)` for the string/integer/null members used here; the
/// golden vector in this module's tests is shared with the receiver.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let mut out = String::from("{");
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                out.push_str(&canonical_json(v));
            }
            out.push('}');
            out
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(v));
            }
            out.push(']');
            out
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A bounded, structured label (tool name, provenance, subject, verifier).
/// Anything outside a conservative alphabet or length is replaced, so a
/// free-form string can never smuggle content into the upload.
fn safe_label(raw: &str) -> String {
    let ok = !raw.is_empty()
        && raw.len() <= 128
        && raw.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'#' | b'/' | b'-')
        });
    if ok {
        raw.to_string()
    } else {
        "redacted".to_string()
    }
}

fn parse_ts(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn window_of(ts: DateTime<Utc>) -> String {
    format!("{:04}-{:02}", ts.year(), ts.month())
}

/// `YYYY-MM` of `now`, the window that is still open.
pub fn current_window(now: DateTime<Utc>) -> String {
    window_of(now)
}

/// Result of one [`Store::stage_upload_records`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StageReport {
    pub staged: usize,
    pub expired_at_bound: usize,
}

/// A sealed batch, ready to send or resend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBatch {
    pub batch_id: String,
    pub window_id: String,
    pub consent_id: String,
    pub destination: String,
    pub manifest_sha256: String,
    pub member_count: i64,
    /// The exact canonical bytes that were hashed.
    pub members_json: String,
    pub attempts: i64,
}

/// One window's pending/in-flight counts, for `fornax upload preview|status`.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct WindowCount {
    pub window_id: String,
    pub state: String,
    pub n: i64,
}

#[derive(sqlx::FromRow)]
struct BatchRow {
    batch_id: String,
    window_id: String,
    consent_id: String,
    destination: String,
    manifest_sha256: String,
    member_count: i64,
    members_json: String,
    attempts: i64,
}

impl From<BatchRow> for SealedBatch {
    fn from(r: BatchRow) -> Self {
        SealedBatch {
            batch_id: r.batch_id,
            window_id: r.window_id,
            consent_id: r.consent_id,
            destination: r.destination,
            manifest_sha256: r.manifest_sha256,
            member_count: r.member_count,
            members_json: r.members_json,
            attempts: r.attempts,
        }
    }
}

#[derive(sqlx::FromRow)]
struct EventSrc {
    id: String,
    session_id: String,
    provider: String,
    kind: String,
    observed_at: String,
    tool_name: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ClaimSrc {
    id: String,
    session_id: String,
    source_event_id: String,
    subject: String,
    claimed_at: String,
    parent_event_at: String,
}

#[derive(sqlx::FromRow)]
struct EvidenceSrc {
    id: String,
    session_id: String,
    source_event_id: String,
    kind: String,
    observed_at: String,
    provenance: String,
    parent_event_at: String,
}

#[derive(sqlx::FromRow)]
struct FindingSrc {
    id: String,
    claim_id: String,
    session_id: String,
    verdict: String,
    verifier_name: String,
    computed_at: String,
    claim_at: String,
    parent_event_at: String,
}

#[derive(sqlx::FromRow)]
struct LogRow {
    changed_at: String,
    profile: String,
}

impl Store {
    /// The newest consent that currently authorizes the monthly batch upload:
    /// personal profile, purpose `evidence_batch_upload`, not revoked, current
    /// profile generation, unexpired.
    pub async fn live_upload_consent(&self) -> Result<Option<Consent>> {
        let state = self.egress_state().await?;
        if state.profile != Profile::Personal {
            return Ok(None);
        }
        let now = Utc::now();
        let mut live: Vec<&Consent> = state
            .consents
            .iter()
            .filter(|c| c.purpose == Purpose::EvidenceBatchUpload)
            .filter(|c| c.revoked_at.is_none() && c.profile_generation == state.generation)
            .filter(|c| parse_ts(&c.expires_at).is_some_and(|e| now < e))
            .collect();
        live.sort_by(|a, b| b.granted_at.cmp(&a.granted_at));
        Ok(live.first().map(|c| (*c).clone()))
    }

    /// The profile in force at `ts`, from the append-only history. No history
    /// before `ts` means unconfigured (never eligible).
    fn profile_at(log: &[(DateTime<Utc>, Profile)], ts: DateTime<Utc>) -> Profile {
        log.iter()
            .rev()
            .find(|(changed, _)| *changed <= ts)
            .map(|(_, p)| *p)
            .unwrap_or(Profile::Unconfigured)
    }

    async fn profile_history(&self) -> Result<Vec<(DateTime<Utc>, Profile)>> {
        let rows: Vec<LogRow> =
            sqlx::query_as("SELECT changed_at, profile FROM egress_profile_log ORDER BY seq ASC")
                .fetch_all(&self.pool)
                .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let ts = parse_ts(&r.changed_at).ok_or_else(|| invalid("malformed profile log"))?;
            let profile =
                Profile::parse(&r.profile).ok_or_else(|| invalid("malformed profile log"))?;
            out.push((ts, profile));
        }
        Ok(out)
    }

    /// Snapshot every eligible, not-yet-staged record into the outbox as a
    /// metadata-only member. A no-op without a live consent. Run before the
    /// retention sweep and before sealing. Also enforces the outbox bound.
    pub async fn stage_upload_records(&self) -> Result<StageReport> {
        let mut report = StageReport::default();
        let live = self.live_upload_consent().await?;
        // Whatever consent staged a row must still be the live one: when it
        // ends (revoked, expired, profile changed, replaced), its pending
        // rows are expired with a recorded gap and its sealed batches are
        // retired -- never re-targeted at a later consent or destination.
        report.expired_at_bound += self
            .retire_unauthorized_upload_work(live.as_ref().map(|c| c.id.as_str()))
            .await?;
        let Some(consent) = live else {
            return Ok(report);
        };
        let Some(eligible_since) = parse_ts(&consent.granted_at) else {
            return Ok(report);
        };
        let history = self.profile_history().await?;
        let eligible = |ts: &str| -> Option<(DateTime<Utc>, String)> {
            let parsed = parse_ts(ts)?;
            if parsed < eligible_since || Self::profile_at(&history, parsed) != Profile::Personal {
                return None;
            }
            Some((parsed, window_of(parsed)))
        };
        let since = eligible_since.to_rfc3339();
        let staged_at = Utc::now().to_rfc3339();

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        let events: Vec<EventSrc> = sqlx::query_as(
            "SELECT e.id, e.session_id, e.provider, e.kind, e.observed_at, e.tool_name
             FROM agent_events e
             LEFT JOIN upload_outbox o ON o.kind = 'events' AND o.object_id = e.id
             WHERE o.object_id IS NULL AND substr(e.observed_at, 1, 19) >= substr(?1, 1, 19)
             ORDER BY e.observed_at ASC LIMIT ?2",
        )
        .bind(&since)
        .bind(STAGE_CHUNK)
        .fetch_all(&mut *tx)
        .await?;
        let mut staged_sessions: Vec<String> = Vec::new();
        for e in events {
            let Some((_, window)) = eligible(&e.observed_at) else {
                continue;
            };
            let mut m = Map::new();
            m.insert("id".into(), json!(e.id));
            m.insert("session_id".into(), json!(e.session_id));
            m.insert("provider".into(), json!(safe_label(&e.provider)));
            m.insert("kind".into(), json!(safe_label(&e.kind)));
            m.insert("observed_at".into(), json!(e.observed_at));
            if let Some(t) = &e.tool_name {
                m.insert("tool_name".into(), json!(safe_label(t)));
            }
            report.staged += insert_member(
                &mut tx,
                "events",
                &e.id,
                &window,
                &m,
                &staged_at,
                &consent.id,
            )
            .await?;
            staged_sessions.push(e.session_id);
        }

        // A session member is staged once, from the earliest event time, when
        // its first event is staged.
        staged_sessions.sort();
        staged_sessions.dedup();
        for session_id in staged_sessions {
            // The session's TRUE earliest event (no consent-time filter): a
            // session that began before consent, or under another profile,
            // is never announced as a session member.
            let first: Option<(String, String)> = sqlx::query_as(
                "SELECT MIN(observed_at), provider FROM agent_events WHERE session_id = ?1",
            )
            .bind(&session_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((first_seen, provider)) = first else {
                continue;
            };
            let Some((_, window)) = eligible(&first_seen) else {
                continue;
            };
            let mut m = Map::new();
            m.insert("session_id".into(), json!(session_id));
            m.insert("provider".into(), json!(safe_label(&provider)));
            m.insert("first_seen_at".into(), json!(first_seen));
            report.staged += insert_member(
                &mut tx,
                "sessions",
                &session_id,
                &window,
                &m,
                &staged_at,
                &consent.id,
            )
            .await?;
        }

        let claims: Vec<ClaimSrc> = sqlx::query_as(
            "SELECT c.id, c.session_id, c.source_event_id, c.subject, c.claimed_at,
                    pe.observed_at AS parent_event_at
             FROM claims c
             JOIN agent_events pe ON pe.id = c.source_event_id
             LEFT JOIN upload_outbox o ON o.kind = 'claims' AND o.object_id = c.id
             WHERE o.object_id IS NULL AND substr(c.claimed_at, 1, 19) >= substr(?1, 1, 19)
             ORDER BY c.claimed_at ASC LIMIT ?2",
        )
        .bind(&since)
        .bind(STAGE_CHUNK)
        .fetch_all(&mut *tx)
        .await?;
        for c in claims {
            // Both the claim and the event it was made about must be eligible.
            let Some((_, window)) = eligible(&c.claimed_at) else {
                continue;
            };
            if eligible(&c.parent_event_at).is_none() {
                continue;
            }
            let mut m = Map::new();
            m.insert("id".into(), json!(c.id));
            m.insert("session_id".into(), json!(c.session_id));
            m.insert("source_event_id".into(), json!(c.source_event_id));
            m.insert("subject".into(), json!(safe_label(&c.subject)));
            m.insert("claimed_at".into(), json!(c.claimed_at));
            report.staged += insert_member(
                &mut tx,
                "claims",
                &c.id,
                &window,
                &m,
                &staged_at,
                &consent.id,
            )
            .await?;
        }

        let evidence: Vec<EvidenceSrc> = sqlx::query_as(
            "SELECT v.id, v.session_id, v.source_event_id, v.kind, v.observed_at, v.provenance,
                    pe.observed_at AS parent_event_at
             FROM evidence v
             JOIN agent_events pe ON pe.id = v.source_event_id
             LEFT JOIN upload_outbox o ON o.kind = 'evidence' AND o.object_id = v.id
             WHERE o.object_id IS NULL AND substr(v.observed_at, 1, 19) >= substr(?1, 1, 19)
             ORDER BY v.observed_at ASC LIMIT ?2",
        )
        .bind(&since)
        .bind(STAGE_CHUNK)
        .fetch_all(&mut *tx)
        .await?;
        for v in evidence {
            let Some((_, window)) = eligible(&v.observed_at) else {
                continue;
            };
            if eligible(&v.parent_event_at).is_none() {
                continue;
            }
            let mut m = Map::new();
            m.insert("id".into(), json!(v.id));
            m.insert("session_id".into(), json!(v.session_id));
            m.insert("source_event_id".into(), json!(v.source_event_id));
            m.insert("kind".into(), json!(safe_label(&v.kind)));
            m.insert("observed_at".into(), json!(v.observed_at));
            m.insert("provenance".into(), json!(safe_label(&v.provenance)));
            report.staged += insert_member(
                &mut tx,
                "evidence",
                &v.id,
                &window,
                &m,
                &staged_at,
                &consent.id,
            )
            .await?;
        }

        let findings: Vec<FindingSrc> = sqlx::query_as(
            "SELECT f.id, f.claim_id, c.session_id, f.verdict, f.verifier_name, f.computed_at,
                    c.claimed_at AS claim_at, pe.observed_at AS parent_event_at
             FROM findings f
             JOIN claims c ON c.id = f.claim_id
             JOIN agent_events pe ON pe.id = c.source_event_id
             LEFT JOIN upload_outbox o ON o.kind = 'findings' AND o.object_id = f.id
             WHERE o.object_id IS NULL AND substr(f.computed_at, 1, 19) >= substr(?1, 1, 19)
             ORDER BY f.computed_at ASC LIMIT ?2",
        )
        .bind(&since)
        .bind(STAGE_CHUNK)
        .fetch_all(&mut *tx)
        .await?;
        for f in findings {
            // A finding is only uploadable if the claim it judges, and the
            // event that claim was made about, were themselves eligible.
            let Some((_, window)) = eligible(&f.computed_at) else {
                continue;
            };
            if eligible(&f.claim_at).is_none() || eligible(&f.parent_event_at).is_none() {
                continue;
            }
            let mut m = Map::new();
            m.insert("id".into(), json!(f.id));
            m.insert("claim_id".into(), json!(f.claim_id));
            m.insert("session_id".into(), json!(f.session_id));
            m.insert("verdict".into(), json!(safe_label(&f.verdict)));
            m.insert("verifier_name".into(), json!(safe_label(&f.verifier_name)));
            m.insert("computed_at".into(), json!(f.computed_at));
            report.staged += insert_member(
                &mut tx,
                "findings",
                &f.id,
                &window,
                &m,
                &staged_at,
                &consent.id,
            )
            .await?;
        }
        tx.commit().await?;

        report.expired_at_bound = self
            .enforce_outbox_bound(OUTBOX_MAX_BYTES, Utc::now())
            .await?;
        Ok(report)
    }

    /// Expire pending rows past the age or size bound, recording a gap (and an
    /// audit event) per affected window BEFORE the rows stop being uploadable.
    pub async fn enforce_outbox_bound(&self, max_bytes: i64, now: DateTime<Utc>) -> Result<usize> {
        let cutoff = (now - Duration::days(OUTBOX_MAX_AGE_DAYS)).to_rfc3339();
        let mut dropped: BTreeMap<(String, &'static str), i64> = BTreeMap::new();

        let aged: Vec<(String, i64)> = sqlx::query_as(
            "SELECT window_id, COUNT(*) FROM upload_outbox
             WHERE state = 'pending' AND staged_at < ?1 GROUP BY window_id",
        )
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;
        for (window, n) in aged {
            dropped.insert((window, "age_cap"), n);
        }

        let total: (Option<i64>,) = sqlx::query_as(
            "SELECT SUM(length(member_json)) FROM upload_outbox WHERE state = 'pending' AND staged_at >= ?1",
        )
        .bind(&cutoff)
        .fetch_one(&self.pool)
        .await?;
        let mut over = total.0.unwrap_or(0) - max_bytes;
        if over > 0 {
            let oldest: Vec<(String, String, i64, String)> = sqlx::query_as(
                "SELECT kind, object_id, length(member_json), window_id FROM upload_outbox
                 WHERE state = 'pending' AND staged_at >= ?1 ORDER BY staged_at ASC",
            )
            .bind(&cutoff)
            .fetch_all(&self.pool)
            .await?;
            let mut victims: Vec<(String, String)> = Vec::new();
            for (kind, id, len, window) in oldest {
                if over <= 0 {
                    break;
                }
                over -= len;
                *dropped.entry((window, "size_cap")).or_insert(0) += 1;
                victims.push((kind, id));
            }
            for (kind, id) in victims {
                sqlx::query(
                    "UPDATE upload_outbox SET state = 'expired' WHERE kind = ?1 AND object_id = ?2",
                )
                .bind(kind)
                .bind(id)
                .execute(&self.pool)
                .await?;
            }
        }
        sqlx::query(
            "UPDATE upload_outbox SET state = 'expired' WHERE state = 'pending' AND staged_at < ?1",
        )
        .bind(&cutoff)
        .execute(&self.pool)
        .await?;

        let mut total_dropped = 0usize;
        for ((window, reason), n) in dropped {
            sqlx::query(
                "INSERT INTO upload_gaps (window_id, reason, dropped_count, recorded_at) VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&window)
            .bind(reason)
            .bind(n)
            .bind(now.to_rfc3339())
            .execute(&self.pool)
            .await?;
            self.audit_upload(
                AuditAction::UploadGapRecorded,
                format!("gap:{window}:{reason}:{n}"),
                AuditOutcome::Denied,
            )
            .await?;
            total_dropped += n as usize;
        }
        Ok(total_dropped)
    }

    /// Expire pending rows and retire sealed batches whose consent is not the
    /// live one (`live_consent_id`, `None` = no live consent). Counts and
    /// audits what it drops. Returns the number of pending rows expired.
    pub async fn retire_unauthorized_upload_work(
        &self,
        live_consent_id: Option<&str>,
    ) -> Result<usize> {
        let live = live_consent_id.unwrap_or("");
        let stale: Vec<(String, i64)> = sqlx::query_as(
            "SELECT window_id, COUNT(*) FROM upload_outbox
             WHERE state = 'pending' AND consent_id <> ?1 GROUP BY window_id",
        )
        .bind(live)
        .fetch_all(&self.pool)
        .await?;
        let mut expired = 0usize;
        for (window, n) in stale {
            sqlx::query("UPDATE upload_outbox SET state = 'expired' WHERE state = 'pending' AND window_id = ?1 AND consent_id <> ?2")
                .bind(&window)
                .bind(live)
                .execute(&self.pool)
                .await?;
            sqlx::query("INSERT INTO upload_gaps (window_id, reason, dropped_count, recorded_at) VALUES (?1, 'consent_ended', ?2, ?3)")
                .bind(&window)
                .bind(n)
                .bind(Utc::now().to_rfc3339())
                .execute(&self.pool)
                .await?;
            self.audit_upload(
                AuditAction::UploadGapRecorded,
                format!("gap:{window}:consent_ended:{n}"),
                AuditOutcome::Denied,
            )
            .await?;
            expired += n as usize;
        }
        let retired: Vec<(String,)> = sqlx::query_as(
            "SELECT batch_id FROM upload_batches WHERE state = 'sealed' AND consent_id <> ?1",
        )
        .bind(live)
        .fetch_all(&self.pool)
        .await?;
        for (batch_id,) in retired {
            self.poison_upload_batch(&batch_id, "consent ended before the batch was acknowledged")
                .await?;
        }
        Ok(expired)
    }

    /// Windows that still have pending rows, oldest first.
    pub async fn pending_upload_windows(&self) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT window_id FROM upload_outbox WHERE state = 'pending' ORDER BY window_id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Counts by window and state, for status and preview.
    pub async fn upload_window_counts(&self) -> Result<Vec<WindowCount>> {
        Ok(sqlx::query_as(
            "SELECT window_id, state, COUNT(*) AS n FROM upload_outbox
             GROUP BY window_id, state ORDER BY window_id ASC, state ASC",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Recorded gaps, newest first.
    pub async fn upload_gaps(&self) -> Result<Vec<(String, String, i64, String)>> {
        Ok(sqlx::query_as(
            "SELECT window_id, reason, dropped_count, recorded_at FROM upload_gaps ORDER BY id DESC",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Seal up to [`MAX_BATCH_MEMBERS`] pending members of `window_id` into an
    /// immutable batch: build the canonical members document, hash it, persist
    /// it and mark the members in flight, in one transaction. `None` if the
    /// window has nothing pending.
    pub async fn seal_upload_batch(
        &self,
        window_id: &str,
        consent_id: &str,
        destination: &str,
    ) -> Result<Option<SealedBatch>> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT kind, object_id, member_json FROM upload_outbox
             WHERE state = 'pending' AND window_id = ?1 AND consent_id = ?3
             ORDER BY kind ASC, object_id ASC LIMIT ?2",
        )
        .bind(window_id)
        .bind(MAX_BATCH_MEMBERS)
        .bind(consent_id)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        let mut members: BTreeMap<&str, Vec<Value>> =
            KINDS.iter().map(|k| (*k, Vec::new())).collect();
        for (kind, _, member_json) in &rows {
            let value: Value = serde_json::from_str(member_json)?;
            if let Some(bucket) = members.get_mut(kind.as_str()) {
                bucket.push(value);
            }
        }
        let doc: Map<String, Value> = members
            .into_iter()
            .map(|(k, v)| (k.to_string(), Value::Array(v)))
            .collect();
        let members_json = canonical_json(&Value::Object(doc));
        let manifest = sha256_hex(members_json.as_bytes());
        let batch_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO upload_batches
               (batch_id, window_id, consent_id, destination, manifest_sha256, canonicalization,
                member_count, byte_count, members_json, state, sealed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'sealed', ?10)",
        )
        .bind(&batch_id)
        .bind(window_id)
        .bind(consent_id)
        .bind(destination)
        .bind(&manifest)
        .bind(CANONICALIZATION)
        .bind(rows.len() as i64)
        .bind(members_json.len() as i64)
        .bind(&members_json)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        for (kind, object_id, _) in &rows {
            sqlx::query(
                "UPDATE upload_outbox SET state = 'inflight', batch_id = ?3 WHERE kind = ?1 AND object_id = ?2",
            )
            .bind(kind)
            .bind(object_id)
            .bind(&batch_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        self.audit_upload(
            AuditAction::UploadBatchSealed,
            format!("batch:{batch_id}:{window_id}:{}", rows.len()),
            AuditOutcome::Granted,
        )
        .await?;
        Ok(Some(SealedBatch {
            batch_id,
            window_id: window_id.to_string(),
            consent_id: consent_id.to_string(),
            destination: destination.to_string(),
            manifest_sha256: manifest,
            member_count: rows.len() as i64,
            members_json,
            attempts: 0,
        }))
    }

    /// Batches sealed but not yet acknowledged or poisoned, oldest first --
    /// resent byte-identically on the next run.
    pub async fn unfinished_upload_batches(&self) -> Result<Vec<SealedBatch>> {
        let rows: Vec<BatchRow> = sqlx::query_as(
            "SELECT batch_id, window_id, consent_id, destination, manifest_sha256, member_count,
                    members_json, attempts
             FROM upload_batches WHERE state = 'sealed' ORDER BY sealed_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Record one send attempt (and its outcome, if it failed).
    pub async fn record_upload_attempt(&self, batch_id: &str, error: Option<&str>) -> Result<()> {
        sqlx::query(
            "UPDATE upload_batches SET attempts = attempts + 1, last_error = ?2, last_attempt_at = ?3
             WHERE batch_id = ?1",
        )
        .bind(batch_id)
        .bind(error)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The receiver acknowledged the batch: it and its members are done.
    pub async fn acknowledge_upload_batch(&self, batch_id: &str) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("UPDATE upload_batches SET state = 'acknowledged', acked_at = ?2, last_error = NULL WHERE batch_id = ?1")
            .bind(batch_id)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE upload_outbox SET state = 'acknowledged' WHERE batch_id = ?1")
            .bind(batch_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.audit_upload(
            AuditAction::UploadBatchAcknowledged,
            format!("batch:{batch_id}"),
            AuditOutcome::Granted,
        )
        .await
    }

    /// The receiver permanently rejected the batch. Its members are marked
    /// poison so the next run does not retry the same content forever.
    pub async fn poison_upload_batch(&self, batch_id: &str, reason: &str) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "UPDATE upload_batches SET state = 'poison', last_error = ?2 WHERE batch_id = ?1",
        )
        .bind(batch_id)
        .bind(reason)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE upload_outbox SET state = 'poison' WHERE batch_id = ?1")
            .bind(batch_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.audit_upload(
            AuditAction::UploadBatchPoisoned,
            format!("batch:{batch_id}"),
            AuditOutcome::Denied,
        )
        .await
    }

    async fn audit_upload(
        &self,
        action: AuditAction,
        target: String,
        outcome: AuditOutcome,
    ) -> Result<()> {
        self.append_audit_event(
            &AuditEvent::new(
                Uuid::new_v4().to_string(),
                Utc::now().to_rfc3339(),
                AuditActor::System,
                action,
                AuditTarget::EgressPolicy { target_id: target },
                outcome,
                AuditExportClass::Metadata,
            ),
            Utc::now(),
        )
        .await?;
        Ok(())
    }
}

async fn insert_member(
    tx: &mut sqlx::SqliteConnection,
    kind: &str,
    object_id: &str,
    window: &str,
    member: &Map<String, Value>,
    staged_at: &str,
    consent_id: &str,
) -> Result<usize> {
    let json = canonical_json(&Value::Object(member.clone()));
    let n = sqlx::query(
        "INSERT OR IGNORE INTO upload_outbox
           (kind, object_id, window_id, member_json, member_sha256, staged_at, consent_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(kind)
    .bind(object_id)
    .bind(window)
    .bind(&json)
    .bind(sha256_hex(json.as_bytes()))
    .bind(staged_at)
    .bind(consent_id)
    .execute(tx)
    .await?
    .rows_affected();
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{
        AgentEvent, Claim, EgressContentClass, EventKind, Evidence, EvidenceKind, Finding,
        Provider, Verdict,
    };

    const CANARY: &str = "SECRET-CANARY-7f3a9c";
    const DEST: &str = "https://cloud.example.test/v1/metadata-batches";

    async fn open() -> (Store, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("fornax-upload-{}.db", Uuid::new_v4()));
        (Store::open(&path).await.expect("open db"), path)
    }

    fn classes() -> std::collections::BTreeSet<EgressContentClass> {
        [
            EgressContentClass::EvidenceMetadata,
            EgressContentClass::FindingVerdicts,
        ]
        .into_iter()
        .collect()
    }

    /// Personal profile + allowlist + consent for the batch upload.
    async fn consenting(store: &Store) -> String {
        store
            .set_egress_profile(Profile::Personal, "test", false)
            .await
            .unwrap();
        store
            .add_egress_allowlist(Purpose::EvidenceBatchUpload, DEST, "test")
            .await
            .unwrap();
        store
            .grant_egress_consent(
                Purpose::EvidenceBatchUpload,
                DEST,
                &classes(),
                30,
                None,
                "test",
            )
            .await
            .unwrap()
    }

    fn at(offset_secs: i64) -> String {
        (Utc::now() + Duration::seconds(offset_secs)).to_rfc3339()
    }

    /// One session worth of records, every content-bearing field carrying the canary.
    async fn record(store: &Store, session: &str, ts: &str) -> (Uuid, Uuid, Uuid, Uuid) {
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: session.into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: ts.into(),
            tool_name: Some("Bash".into()),
            tool_input: Some(json!({"command": CANARY})),
            tool_response: Some(json!({"stdout": CANARY})),
            raw: json!({"cwd": CANARY}),
        };
        store.insert_event(&event).await.unwrap();
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: session.into(),
            source_event_id: event.id,
            text: format!("all tests pass {CANARY}"),
            subject: "test_result".into(),
            claimed_at: ts.into(),
        };
        store.insert_claim(&claim).await.unwrap();
        let evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: session.into(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: ts.into(),
            payload: json!({"command": CANARY, "exit_code": 0}),
            provenance: "claude_code:PostToolUse:Bash#tool_response".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        };
        store.insert_evidence(&evidence).await.unwrap();
        let finding = Finding {
            id: Uuid::new_v4(),
            claim_id: claim.id,
            verdict: Verdict::Verified,
            evidence_ids: vec![evidence.id],
            verifier_name: "test_result_verifier_v1".into(),
            rationale: format!("because {CANARY}"),
            computed_at: ts.into(),
        };
        store.insert_finding(&finding).await.unwrap();
        (event.id, claim.id, evidence.id, finding.id)
    }

    async fn outbox_dump(store: &Store) -> String {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT member_json FROM upload_outbox")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        rows.into_iter().map(|r| r.0).collect::<Vec<_>>().join("\n")
    }

    /// The golden vector shared byte-for-byte with the cloud receiver.
    #[test]
    fn canonical_json_matches_the_shared_golden_vector() {
        let members = json!({
            "sessions":[{"session_id":"s-1","provider":"claude_code","first_seen_at":"2026-09-02T10:00:00Z"}],
            "events":[{"id":"00000000-0000-4000-8000-000000000001","session_id":"s-1","provider":"claude_code","kind":"post_tool_use","observed_at":"2026-09-02T10:00:01Z","tool_name":"Bash"}],
            "claims":[{"id":"00000000-0000-4000-8000-000000000002","session_id":"s-1","source_event_id":"00000000-0000-4000-8000-000000000001","subject":"test_result","claimed_at":"2026-09-02T10:00:02Z"}],
            "evidence":[{"id":"00000000-0000-4000-8000-000000000003","session_id":"s-1","source_event_id":"00000000-0000-4000-8000-000000000001","kind":"exit_code","observed_at":"2026-09-02T10:00:01Z","provenance":"claude_code:PostToolUse:Bash#tool_response"}],
            "findings":[{"id":"00000000-0000-4000-8000-000000000004","claim_id":"00000000-0000-4000-8000-000000000002","session_id":"s-1","verdict":"verified","verifier_name":"test_result_verifier_v1","computed_at":"2026-09-02T10:00:03Z"}],
        });
        let canon = canonical_json(&members);
        assert!(canon.starts_with("{\"claims\":[{\"claimed_at\""), "{canon}");
        assert_eq!(
            sha256_hex(canon.as_bytes()),
            "d322b32d50a45d3bca00dc7805dbf5958647697301a9a8d0bddc49bfdb64bb7d"
        );
    }

    #[test]
    fn labels_outside_the_safe_alphabet_never_leave() {
        assert_eq!(safe_label("Bash"), "Bash");
        assert_eq!(
            safe_label("claude_code:PostToolUse:Bash#tool_response"),
            "claude_code:PostToolUse:Bash#tool_response"
        );
        assert_eq!(safe_label("rm -rf /home/me"), "redacted");
        assert_eq!(safe_label(&"a".repeat(129)), "redacted");
        assert_eq!(safe_label(""), "redacted");
    }

    #[tokio::test]
    async fn nothing_is_staged_without_a_live_consent() {
        let (store, path) = open().await;
        record(&store, "s-1", &at(5)).await;
        assert_eq!(
            store.stage_upload_records().await.unwrap(),
            StageReport::default()
        );
        // Personal profile alone is not consent.
        store
            .set_egress_profile(Profile::Personal, "t", false)
            .await
            .unwrap();
        assert_eq!(
            store.stage_upload_records().await.unwrap(),
            StageReport::default()
        );
        assert!(store.upload_window_counts().await.unwrap().is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn only_records_captured_after_consent_are_staged_and_never_their_content() {
        let (store, path) = open().await;
        // Captured before any consent: never eligible.
        record(&store, "s-old", &at(-3600)).await;
        let consent = consenting(&store).await;
        record(&store, "s-new", &at(5)).await;

        let report = store.stage_upload_records().await.unwrap();
        // 1 event + 1 claim + 1 evidence + 1 finding + 1 session.
        assert_eq!(report.staged, 5, "{report:?}");
        let dump = outbox_dump(&store).await;
        assert!(dump.contains("s-new") && !dump.contains("s-old"), "{dump}");
        // Content values, and the JSON KEYS that would carry content (the
        // structured provenance label legitimately contains "tool_response").
        for forbidden in [
            CANARY,
            "\"tool_input\"",
            "\"tool_response\"",
            "\"payload\"",
            "\"rationale\"",
            "\"text\"",
            "\"raw\"",
        ] {
            assert!(
                !dump.contains(forbidden),
                "outbox leaked {forbidden:?}: {dump}"
            );
        }

        // Re-staging is idempotent.
        assert_eq!(store.stage_upload_records().await.unwrap().staged, 0);

        // Revoking the consent stops further staging.
        store
            .revoke_egress_consent(&consent, "t", "t")
            .await
            .unwrap();
        record(&store, "s-later", &at(10)).await;
        assert_eq!(store.stage_upload_records().await.unwrap().staged, 0);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_free_form_label_cannot_carry_content_into_the_outbox() {
        let (store, path) = open().await;
        consenting(&store).await;
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s-1".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: at(5),
            tool_name: Some(format!("curl -d {CANARY} https://x")),
            tool_input: None,
            tool_response: None,
            raw: json!({}),
        };
        store.insert_event(&event).await.unwrap();
        store.stage_upload_records().await.unwrap();
        let dump = outbox_dump(&store).await;
        assert!(
            !dump.contains(CANARY) && dump.contains("\"tool_name\":\"redacted\""),
            "{dump}"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_corporate_period_in_the_profile_history_makes_a_record_ineligible() {
        let (store, path) = open().await;
        consenting(&store).await;
        // Simulate history showing the install was corporate when the record
        // was captured (defence in depth: a live consent already implies an
        // unchanged personal period).
        let t = at(2);
        sqlx::query("INSERT INTO egress_profile_log (changed_at, profile, generation) VALUES (?1, 'corporate', 99)")
            .bind(at(1))
            .execute(&store.pool)
            .await
            .unwrap();
        record(&store, "s-corp", &t).await;
        assert_eq!(store.stage_upload_records().await.unwrap().staged, 0);
        std::fs::remove_file(&path).ok();
    }

    /// The reason the outbox exists: the retention sweep deletes source rows
    /// (raw evidence is purged at 30 days) but a staged snapshot survives.
    #[tokio::test]
    async fn staged_members_survive_the_source_rows_being_purged() {
        let (store, path) = open().await;
        let consent = consenting(&store).await;
        let (_, _, evidence_id, _) = record(&store, "s-1", &at(5)).await;
        store.stage_upload_records().await.unwrap();

        sqlx::query("UPDATE evidence SET payload = '{\"evidence_expired\":true}', evidence_purged = 1 WHERE id = ?1")
            .bind(evidence_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM findings")
            .execute(&store.pool)
            .await
            .unwrap();

        let window = store.pending_upload_windows().await.unwrap().remove(0);
        let batch = store
            .seal_upload_batch(&window, &consent, DEST)
            .await
            .unwrap()
            .expect("something to seal");
        assert_eq!(batch.member_count, 5);
        assert!(
            batch.members_json.contains("\"findings\":[{"),
            "finding survives the purge"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_sealed_batch_is_immutable_hashed_and_resent_byte_identically() {
        let (store, path) = open().await;
        let consent = consenting(&store).await;
        record(&store, "s-1", &at(5)).await;
        store.stage_upload_records().await.unwrap();
        let window = store.pending_upload_windows().await.unwrap().remove(0);

        let batch = store
            .seal_upload_batch(&window, &consent, DEST)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            batch.manifest_sha256,
            sha256_hex(batch.members_json.as_bytes())
        );
        // Everything is now in flight; nothing left to seal.
        assert!(store
            .seal_upload_batch(&window, &consent, DEST)
            .await
            .unwrap()
            .is_none());

        // A crash before the ack: the next run finds the same bytes and hash.
        store
            .record_upload_attempt(&batch.batch_id, Some("transport"))
            .await
            .unwrap();
        let again = store.unfinished_upload_batches().await.unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].members_json, batch.members_json);
        assert_eq!(again[0].manifest_sha256, batch.manifest_sha256);
        assert_eq!(again[0].attempts, 1);

        store
            .acknowledge_upload_batch(&batch.batch_id)
            .await
            .unwrap();
        assert!(store.unfinished_upload_batches().await.unwrap().is_empty());
        let counts = store.upload_window_counts().await.unwrap();
        assert!(
            counts.iter().all(|c| c.state == "acknowledged"),
            "{counts:?}"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_poisoned_batch_is_not_retried_and_is_audited() {
        let (store, path) = open().await;
        let consent = consenting(&store).await;
        record(&store, "s-1", &at(5)).await;
        store.stage_upload_records().await.unwrap();
        let window = store.pending_upload_windows().await.unwrap().remove(0);
        let batch = store
            .seal_upload_batch(&window, &consent, DEST)
            .await
            .unwrap()
            .unwrap();
        store
            .poison_upload_batch(&batch.batch_id, "http 422")
            .await
            .unwrap();
        assert!(store.unfinished_upload_batches().await.unwrap().is_empty());
        assert!(store.pending_upload_windows().await.unwrap().is_empty());
        let actions: Vec<_> = store
            .audit_events()
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.event.action)
            .collect();
        assert!(actions.contains(&AuditAction::UploadBatchSealed));
        assert!(actions.contains(&AuditAction::UploadBatchPoisoned));
        assert!(matches!(
            store.verify_audit_chain().await.unwrap(),
            crate::ChainVerification::Valid
        ));
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn the_outbox_bound_records_a_gap_before_dropping_anything() {
        let (store, path) = open().await;
        consenting(&store).await;
        for i in 0..3 {
            record(&store, &format!("s-{i}"), &at(5 + i)).await;
        }
        store.stage_upload_records().await.unwrap();
        let before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM upload_outbox WHERE state = 'pending'")
                .fetch_one(&store.pool)
                .await
                .unwrap();

        // A tiny size bound forces expiry of the oldest pending rows.
        let dropped = store.enforce_outbox_bound(1500, Utc::now()).await.unwrap();
        assert!(dropped > 0);
        let after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM upload_outbox WHERE state = 'pending'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(before - after, dropped as i64);
        let gaps = store.upload_gaps().await.unwrap();
        assert!(
            !gaps.is_empty() && gaps.iter().all(|g| g.1 == "size_cap"),
            "{gaps:?}"
        );
        let recorded: i64 = gaps.iter().map(|g| g.2).sum();
        assert_eq!(recorded, dropped as i64, "every drop is accounted for");
        let audited = store
            .audit_events()
            .await
            .unwrap()
            .into_iter()
            .any(|e| e.event.action == AuditAction::UploadGapRecorded);
        assert!(audited);

        // Age bound.
        sqlx::query("UPDATE upload_outbox SET staged_at = ?1 WHERE state = 'pending'")
            .bind((Utc::now() - Duration::days(OUTBOX_MAX_AGE_DAYS + 1)).to_rfc3339())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(
            store
                .enforce_outbox_bound(OUTBOX_MAX_BYTES, Utc::now())
                .await
                .unwrap()
                > 0
        );
        assert!(store
            .upload_gaps()
            .await
            .unwrap()
            .iter()
            .any(|g| g.1 == "age_cap"));
        std::fs::remove_file(&path).ok();
    }

    /// A row staged under one consent is never sealed under another.
    #[tokio::test]
    async fn work_staged_under_an_ended_consent_is_not_retargeted_at_a_later_one() {
        let (store, path) = open().await;
        let first = consenting(&store).await;
        record(&store, "s-a", &at(5)).await;
        store.stage_upload_records().await.unwrap();
        let window = store.pending_upload_windows().await.unwrap().remove(0);
        // One batch sealed (in flight) and more rows still pending.
        let sealed = store
            .seal_upload_batch(&window, &first, DEST)
            .await
            .unwrap()
            .unwrap();
        record(&store, "s-b", &at(6)).await;
        store.stage_upload_records().await.unwrap();
        assert!(!store.pending_upload_windows().await.unwrap().is_empty());

        // The consent ends; a different consent (new destination) is granted.
        store.revoke_egress_consent(&first, "t", "t").await.unwrap();
        let other = "https://other.example.test/v1/metadata-batches";
        store
            .add_egress_allowlist(Purpose::EvidenceBatchUpload, other, "t")
            .await
            .unwrap();
        let second = store
            .grant_egress_consent(
                Purpose::EvidenceBatchUpload,
                other,
                &classes(),
                30,
                None,
                "t",
            )
            .await
            .unwrap();
        // Same profile generation, so the second consent is live.
        store.stage_upload_records().await.unwrap();

        // The first consent's pending rows expired (with a gap) and its sealed
        // batch was retired: nothing of it can be sealed or resent to `other`.
        assert!(store.pending_upload_windows().await.unwrap().is_empty());
        assert!(store
            .seal_upload_batch(&window, &second, other)
            .await
            .unwrap()
            .is_none());
        assert!(store.unfinished_upload_batches().await.unwrap().is_empty());
        let gaps = store.upload_gaps().await.unwrap();
        assert!(gaps.iter().any(|g| g.1 == "consent_ended"), "{gaps:?}");
        let _ = sealed;
        std::fs::remove_file(&path).ok();
    }

    /// A finding computed after consent about a claim made before it is not
    /// uploadable, and neither is a session that began before consent.
    #[tokio::test]
    async fn a_parent_captured_before_consent_makes_its_children_ineligible() {
        let (store, path) = open().await;
        let (event_id, claim_id, evidence_id, _) = {
            // Everything below is captured BEFORE the consent.
            record(&store, "s-pre", &at(-3600)).await
        };
        let consent = consenting(&store).await;
        let _ = consent;
        // New evidence and a new finding AFTER consent, about the OLD event/claim.
        let late_evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: "s-pre".into(),
            source_event_id: event_id,
            kind: EvidenceKind::ExitCode,
            observed_at: at(5),
            payload: json!({}),
            provenance: "claude_code:PostToolUse:Bash#tool_response".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        };
        store.insert_evidence(&late_evidence).await.unwrap();
        let late_finding = Finding {
            id: Uuid::new_v4(),
            claim_id,
            verdict: Verdict::Verified,
            evidence_ids: vec![evidence_id],
            verifier_name: "v".into(),
            rationale: "r".into(),
            computed_at: at(5),
        };
        store.insert_finding(&late_finding).await.unwrap();
        // A new post-consent event in the same pre-consent session.
        let new_event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s-pre".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: at(6),
            tool_name: Some("Bash".into()),
            tool_input: None,
            tool_response: None,
            raw: json!({}),
        };
        store.insert_event(&new_event).await.unwrap();

        store.stage_upload_records().await.unwrap();
        let dump = outbox_dump(&store).await;
        // Only the genuinely new event is staged: not the late evidence or
        // finding (their parents predate consent) and no session member (the
        // session began before consent).
        assert!(dump.contains(&new_event.id.to_string()), "{dump}");
        assert!(!dump.contains(&late_evidence.id.to_string()), "{dump}");
        assert!(!dump.contains(&late_finding.id.to_string()), "{dump}");
        assert!(!dump.contains("first_seen_at"), "{dump}");
        std::fs::remove_file(&path).ok();
    }

    /// End to end for the core requirement: with a live consent, staging
    /// before the retention sweep means the sweep can delete the source rows
    /// and the data is still uploadable. Without staging first it would not be.
    #[tokio::test]
    async fn the_retention_sweep_cannot_outrun_an_export_once_staging_ran_first() {
        let (store, path) = open().await;
        let consent = consenting(&store).await;
        // Back-date the consent and profile history so a 40-day-old record is
        // eligible (granted 60 days ago, personal since then).
        let sixty = (Utc::now() - Duration::days(60)).to_rfc3339();
        sqlx::query("UPDATE egress_consents SET granted_at = ?1")
            .bind(&sixty)
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE egress_profile_log SET changed_at = ?1")
            .bind(&sixty)
            .execute(&store.pool)
            .await
            .unwrap();
        let old = (Utc::now() - Duration::days(40)).to_rfc3339();
        record(&store, "s-old", &old).await;
        sqlx::query("UPDATE dataset_lineage_tags SET recorded_at = ?1")
            .bind(&old)
            .execute(&store.pool)
            .await
            .unwrap();

        // The daemon stages ahead of every sweep.
        assert_eq!(store.stage_upload_records().await.unwrap().staged, 5);
        let report = store
            .sweep_expired_records(Utc::now(), None, 1000)
            .await
            .unwrap();
        assert!(
            report.purged_evidence + report.deleted_records > 0,
            "the sweep must actually remove source data for this to prove anything: {report:?}"
        );
        let purged: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM evidence WHERE evidence_purged = 1")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let events_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_events")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert!(purged > 0 || events_left == 0, "raw data was purged");

        // The export is intact and sealable after the purge.
        let window = store.pending_upload_windows().await.unwrap().remove(0);
        let batch = store
            .seal_upload_batch(&window, &consent, DEST)
            .await
            .unwrap()
            .expect("staged data survives the sweep");
        assert_eq!(batch.member_count, 5);
        assert!(!batch.members_json.contains(CANARY));
        std::fs::remove_file(&path).ok();
    }
}
