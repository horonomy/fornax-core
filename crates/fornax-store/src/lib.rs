//! Local immutable evidence store (FORNX-26). SQLite in WAL mode. Rows are
//! inserted, never mutated — sessions can be replayed against future
//! verifiers (FORNX-49) from this store alone, with no network/adapter
//! dependency.

use fornax_types::{
    AgentEvent, Claim, Evidence, EvidenceGraph, EvidenceLink, Finding, LegacyCapabilitiesWire,
    MissingEvidence, RuntimeCapabilities,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;

pub mod policy_cache;
pub mod retention;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// FORNX-119: a persisted policy-cache row failed to reconstruct into
    /// its typed form (e.g. a timestamp column that fails RFC3339 parsing).
    /// This should never happen for a row this crate itself wrote — it
    /// indicates on-disk corruption or manual tampering with `fornax.db`.
    #[error("policy cache data corrupt: {0}")]
    PolicyCacheCorrupt(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Serialize a simple string-like enum (serde `rename_all = "snake_case"`) to
/// its bare tag, e.g. `Verdict::Contradicted` -> `"contradicted"`, not the
/// JSON-quoted `"\"contradicted\""` that plain `to_string()` would produce.
fn tag(v: &impl serde::Serialize) -> Result<String> {
    match serde_json::to_value(v)? {
        serde_json::Value::String(s) => Ok(s),
        other => Ok(other.to_string()),
    }
}

fn from_tag<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_string(),
    ))?)
}

/// `<path>` with `suffix` appended to the file name, e.g.
/// `append_ext("a/db.sqlite", "-wal")` -> `a/db.sqlite-wal` (SQLite's own
/// naming convention for WAL-mode sidecar files, not a `.` extension).
#[cfg(unix)]
fn append_ext(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

/// Best-effort 0600 chmod. Silently does nothing if the file doesn't exist
/// yet (WAL/SHM sidecars may not be created until the first checkpoint) or
/// the chmod fails for another reason — never block store startup on this.
#[cfg(unix)]
fn chmod_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[derive(Clone)]
pub struct Store {
    pub(crate) pool: SqlitePool,
}

impl Store {
    /// Open (creating if absent) the SQLite store at `path` in WAL mode, and
    /// run migrations. On Unix, the file is created with 0600 permissions —
    /// evidence payloads may carry secrets from raw tool output (see
    /// docs/research/adapter-capability-matrix.md), so the store must never
    /// default to world-readable (FORNX-33 acceptance).
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .map_err(StoreError::Db)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| StoreError::Db(e.into()))?;

        #[cfg(unix)]
        {
            // In WAL mode the most recently written rows live in the
            // `-wal` sidecar (and its `-shm` index) until a checkpoint, not
            // in the main file — chmod all three or the 0600 guarantee
            // above is defeated for exactly the newest evidence/claims.
            for sidecar in [
                path.to_path_buf(),
                append_ext(path, "-wal"),
                append_ext(path, "-shm"),
            ] {
                chmod_owner_only(&sidecar);
            }
        }

        Ok(Self { pool })
    }

    pub async fn insert_event(&self, e: &AgentEvent) -> Result<()> {
        sqlx::query(
            "INSERT INTO agent_events (id, session_id, provider, kind, observed_at, tool_name, tool_input, tool_response, raw)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(e.id.to_string())
        .bind(&e.session_id)
        .bind(tag(&e.provider)?)
        .bind(tag(&e.kind)?)
        .bind(&e.observed_at)
        .bind(&e.tool_name)
        .bind(e.tool_input.as_ref().map(|v| v.to_string()))
        .bind(e.tool_response.as_ref().map(|v| v.to_string()))
        .bind(e.raw.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_claim(&self, c: &Claim) -> Result<()> {
        sqlx::query(
            "INSERT INTO claims (id, session_id, source_event_id, text, subject, claimed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(c.id.to_string())
        .bind(&c.session_id)
        .bind(c.source_event_id.to_string())
        .bind(&c.text)
        .bind(&c.subject)
        .bind(&c.claimed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_evidence(&self, ev: &Evidence) -> Result<()> {
        let source = ev.source.as_ref().map(serde_json::to_string).transpose()?;
        let extension = ev
            .extension
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        sqlx::query(
            "INSERT INTO evidence (id, session_id, source_event_id, kind, observed_at, payload, provenance, source, extension)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(ev.id.to_string())
        .bind(&ev.session_id)
        .bind(ev.source_event_id.to_string())
        .bind(tag(&ev.kind)?)
        .bind(&ev.observed_at)
        .bind(ev.payload.to_string())
        .bind(&ev.provenance)
        .bind(source)
        .bind(extension)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_finding(&self, f: &Finding) -> Result<()> {
        sqlx::query(
            "INSERT INTO findings (id, claim_id, verdict, evidence_ids, verifier_name, rationale, computed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(f.id.to_string())
        .bind(f.claim_id.to_string())
        .bind(tag(&f.verdict)?)
        .bind(serde_json::to_string(&f.evidence_ids)?)
        .bind(&f.verifier_name)
        .bind(&f.rationale)
        .bind(&f.computed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a typed claim-to-evidence relationship (FORNX-89). Additive
    /// linkage row — does not change how `claims`/`evidence` are stored or
    /// interpreted. The caller is responsible for `link.session_id` matching
    /// the session the referenced claim actually belongs to; this method
    /// does not validate that against the `claims` table. A mismatched
    /// `session_id` does not leak the row into another session's queries —
    /// `evidence_graph_for_claim` scopes on the `(claim_id, session_id)`
    /// pair — but it does make the row invisible to every query, since no
    /// query will ever present that exact wrong pair.
    pub async fn insert_evidence_link(&self, link: &EvidenceLink) -> Result<()> {
        sqlx::query(
            "INSERT INTO claim_evidence_links (id, session_id, claim_id, evidence_id, relation, linked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(link.id.to_string())
        .bind(&link.session_id)
        .bind(link.claim_id.to_string())
        .bind(link.evidence_id.to_string())
        .bind(tag(&link.relation)?)
        .bind(&link.linked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a claim's explicit note that evidence of a given `SignalClass`
    /// was expected but could not be collected/observed (FORNX-89) — keeps
    /// "no evidence found" distinguishable from "evidence could not exist".
    pub async fn insert_missing_evidence(&self, missing: &MissingEvidence) -> Result<()> {
        sqlx::query(
            "INSERT INTO claim_missing_evidence (id, session_id, claim_id, signal_class, availability, detail, noted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(missing.id.to_string())
        .bind(&missing.session_id)
        .bind(missing.claim_id.to_string())
        .bind(tag(&missing.signal_class)?)
        .bind(tag(&missing.availability)?)
        .bind(&missing.detail)
        .bind(&missing.noted_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The full evidence graph for one claim (FORNX-89): every typed
    /// claim-to-evidence link plus every explicit missing-evidence note,
    /// both ordered oldest first. Read-only, in-process — no HTTP surface
    /// (FORNX-90 "Evidence Explorer" is the separate ticket that exposes
    /// this to users). A `Finding` reaches its evidence graph via
    /// `finding.claim_id` — there is no separate `evidence_graph_for_finding`.
    ///
    /// Scoped by `(claim_id, session_id)`, not `claim_id` alone (FORNX-89 AC:
    /// "graph queries cannot cross tenant/session authorization boundaries")
    /// — a caller must already know which session a claim belongs to, and a
    /// mismatched pair returns an empty graph rather than another session's
    /// rows.
    pub async fn evidence_graph_for_claim(
        &self,
        claim_id: &str,
        session_id: &str,
    ) -> Result<EvidenceGraph> {
        let link_rows = sqlx::query_as::<_, EvidenceLinkRow>(
            "SELECT id, session_id, claim_id, evidence_id, relation, linked_at
             FROM claim_evidence_links WHERE claim_id = ?1 AND session_id = ?2 ORDER BY linked_at ASC",
        )
        .bind(claim_id)
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        let links = link_rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;

        let missing_rows = sqlx::query_as::<_, MissingEvidenceRow>(
            "SELECT id, session_id, claim_id, signal_class, availability, detail, noted_at
             FROM claim_missing_evidence WHERE claim_id = ?1 AND session_id = ?2 ORDER BY noted_at ASC",
        )
        .bind(claim_id)
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        let missing = missing_rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;

        Ok(EvidenceGraph { links, missing })
    }

    /// All evidence rows for a session, oldest first — the input a verifier
    /// needs alongside a claim.
    ///
    /// FORNX-289: one row that fails to deserialize (e.g. an `extension`
    /// blob stamped with a `schema_version` this binary no longer/doesn't
    /// yet support, see `ExtensionEnvelope`'s `TryFrom`) must not take down
    /// the whole session's evidence read — a verifier still needs the N-1
    /// good rows. The failure is not silently dropped either: it comes back
    /// in `failed`, named by row id, so the caller can decide what "N of M
    /// evidence rows for this session failed to deserialize" means for it
    /// (log, surface to an operator, etc). This is deliberately scoped to
    /// *this* session-wide query — a direct single-row read/version-check
    /// elsewhere still fails loudly per FORNX-158's original design.
    pub async fn evidence_for_session(&self, session_id: &str) -> Result<EvidenceReadOutcome> {
        let rows = sqlx::query_as::<_, EvidenceRow>(
            "SELECT id, session_id, source_event_id, kind, observed_at, payload, provenance, source, extension
             FROM evidence WHERE session_id = ?1 ORDER BY observed_at ASC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        let mut evidence = Vec::with_capacity(rows.len());
        let mut failed = Vec::new();
        for row in rows {
            let id = row.id.clone();
            match Evidence::try_from(row) {
                Ok(ev) => evidence.push(ev),
                Err(e) => failed.push(EvidenceReadFailure {
                    id,
                    error: e.to_string(),
                }),
            }
        }
        Ok(EvidenceReadOutcome { evidence, failed })
    }

    /// All events for a session, oldest first (FORNX-60: needed alongside
    /// `claims_for_session`/`evidence_for_session` to export a session's full
    /// record to an external spool, e.g. `fornax-cloud`'s uploader).
    pub async fn events_for_session(&self, session_id: &str) -> Result<Vec<AgentEvent>> {
        let rows = sqlx::query_as::<_, EventRow>(
            "SELECT id, session_id, provider, kind, observed_at, tool_name, tool_input, tool_response, raw
             FROM agent_events WHERE session_id = ?1 ORDER BY observed_at ASC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Persist (or overwrite) the capabilities a provider adapter announced
    /// for `session_id` (FORNX-62). Unlike `insert_*`, this is an upsert on
    /// `(session_id, provider)` — see `migrations/0002_runtime_capabilities.sql`
    /// for why capabilities don't follow the insert-only convention.
    ///
    /// Writes both the formalized `signals`/`schema_version` columns
    /// (FORNX-155, source of truth) and the six legacy `supports_*` bool
    /// columns (write-only compatibility mirror, derived via
    /// `LegacyCapabilitiesWire` — see `migrations/0003_capability_signals.sql`).
    pub async fn upsert_capabilities(
        &self,
        session_id: &str,
        caps: &RuntimeCapabilities,
    ) -> Result<()> {
        let legacy = LegacyCapabilitiesWire::from(caps);
        sqlx::query(
            "INSERT INTO runtime_capabilities
                (session_id, provider, supports_pre_tool_use, supports_post_tool_use,
                 supports_tool_response_capture, supports_session_stop_event,
                 supports_transcript_tail, supports_subagent_lifecycle, notes,
                 schema_version, signals, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT(session_id, provider) DO UPDATE SET
                supports_pre_tool_use = excluded.supports_pre_tool_use,
                supports_post_tool_use = excluded.supports_post_tool_use,
                supports_tool_response_capture = excluded.supports_tool_response_capture,
                supports_session_stop_event = excluded.supports_session_stop_event,
                supports_transcript_tail = excluded.supports_transcript_tail,
                supports_subagent_lifecycle = excluded.supports_subagent_lifecycle,
                notes = excluded.notes,
                schema_version = excluded.schema_version,
                signals = excluded.signals,
                observed_at = excluded.observed_at",
        )
        .bind(session_id)
        .bind(tag(&caps.provider)?)
        .bind(legacy.supports_pre_tool_use)
        .bind(legacy.supports_post_tool_use)
        .bind(legacy.supports_tool_response_capture)
        .bind(legacy.supports_session_stop_event)
        .bind(legacy.supports_transcript_tail)
        .bind(legacy.supports_subagent_lifecycle)
        .bind(serde_json::to_string(&caps.notes)?)
        .bind(caps.schema_version as i64)
        .bind(serde_json::to_string(&caps.signals)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// All capabilities announcements for a session, one row per provider
    /// that has announced (FORNX-62/FORNX-60: `export-spool` reads this to
    /// emit a `capabilities` envelope alongside events/claims/evidence).
    pub async fn capabilities_for_session(
        &self,
        session_id: &str,
    ) -> Result<Vec<RuntimeCapabilities>> {
        let rows = sqlx::query_as::<_, CapabilitiesRow>(
            "SELECT provider, supports_pre_tool_use, supports_post_tool_use,
                    supports_tool_response_capture, supports_session_stop_event,
                    supports_transcript_tail, supports_subagent_lifecycle, notes,
                    schema_version, signals
             FROM runtime_capabilities WHERE session_id = ?1 ORDER BY provider ASC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// All claims for a session, oldest first (FORNX-60).
    pub async fn claims_for_session(&self, session_id: &str) -> Result<Vec<Claim>> {
        let rows = sqlx::query_as::<_, ClaimRow>(
            "SELECT id, session_id, source_event_id, text, subject, claimed_at
             FROM claims WHERE session_id = ?1 ORDER BY claimed_at ASC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Most recent findings across all sessions, for the localhost dashboard
    /// (FORNX-32) and detail command (FORNX-31).
    pub async fn recent_findings(&self, limit: i64) -> Result<Vec<FindingRow>> {
        let rows = sqlx::query_as::<_, FindingRow>(
            "SELECT f.id, f.claim_id, f.verdict, f.evidence_ids, f.verifier_name, f.rationale, f.computed_at,
                    c.text as claim_text, c.session_id as session_id
             FROM findings f JOIN claims c ON c.id = f.claim_id
             ORDER BY f.computed_at DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// One finding row by id, joined with its claim (FORNX-18: the
    /// dashboard's finding-detail page). `None` if no such finding exists.
    pub async fn finding_by_id(&self, id: &str) -> Result<Option<FindingRow>> {
        let row = sqlx::query_as::<_, FindingRow>(
            "SELECT f.id, f.claim_id, f.verdict, f.evidence_ids, f.verifier_name, f.rationale, f.computed_at,
                    c.text as claim_text, c.session_id as session_id
             FROM findings f JOIN claims c ON c.id = f.claim_id
             WHERE f.id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// One overview row per session that has at least one event, newest
    /// activity first (FORNX-18: the dashboard's session-list page). The
    /// `provider` column comes straight from `agent_events` — a session's
    /// events are always normalized by the one adapter connection that
    /// produced them, so this needs no capability-table lookup and stays
    /// correct even for a session that never explicitly announced
    /// `RuntimeCapabilities`.
    pub async fn sessions_overview(&self) -> Result<Vec<SessionSummary>> {
        let rows = sqlx::query_as::<_, SessionSummary>(
            "SELECT e.session_id as session_id,
                    e.provider as provider,
                    COUNT(DISTINCT e.id) as event_count,
                    COUNT(DISTINCT c.id) as claim_count,
                    COUNT(DISTINCT f.id) as finding_count,
                    MAX(e.observed_at) as last_activity
             FROM agent_events e
             LEFT JOIN claims c ON c.session_id = e.session_id
             LEFT JOIN findings f ON f.claim_id = c.id
             GROUP BY e.session_id, e.provider
             ORDER BY last_activity DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// All findings for one session, newest first (FORNX-18: the
    /// dashboard's session-detail page — distinct from `recent_findings`,
    /// which is cross-session).
    pub async fn findings_for_session(&self, session_id: &str) -> Result<Vec<FindingRow>> {
        let rows = sqlx::query_as::<_, FindingRow>(
            "SELECT f.id, f.claim_id, f.verdict, f.evidence_ids, f.verifier_name, f.rationale, f.computed_at,
                    c.text as claim_text, c.session_id as session_id
             FROM findings f JOIN claims c ON c.id = f.claim_id
             WHERE c.session_id = ?1
             ORDER BY f.computed_at DESC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

/// One row of `Store::sessions_overview` — a session's activity summary for
/// the dashboard's session-list page (FORNX-18). Not the canonical session
/// concept (there is no `sessions` table; a session is implicitly whatever
/// `session_id` its events/claims/findings share) — purely a read-side
/// aggregate.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub provider: String,
    pub event_count: i64,
    pub claim_count: i64,
    pub finding_count: i64,
    pub last_activity: String,
}

/// Result of `Store::evidence_for_session`: the rows that deserialized
/// successfully, plus an explicit account of the ones that didn't (M minus
/// `evidence.len()` gives the failed count; see `evidence_for_session`'s
/// doc comment for why a bad row is reported rather than either silently
/// dropped or failing the whole query).
#[derive(Debug, Clone, Default)]
pub struct EvidenceReadOutcome {
    pub evidence: Vec<Evidence>,
    pub failed: Vec<EvidenceReadFailure>,
}

/// One evidence row that could not be deserialized, named by its (opaque,
/// unparsed — a bad row is not a place to introduce a second failure mode)
/// id, with the deserialization error that was reported.
#[derive(Debug, Clone)]
pub struct EvidenceReadFailure {
    pub id: String,
    pub error: String,
}

#[derive(sqlx::FromRow)]
struct EvidenceRow {
    id: String,
    session_id: String,
    source_event_id: String,
    kind: String,
    observed_at: String,
    payload: String,
    provenance: String,
    /// `NULL` for any row written before FORNX-157's 0004 migration, or by
    /// code not yet migrated onto the `EvidenceSensor` contract — reads
    /// back as `Evidence::source == None`, not a fabricated value (see
    /// `migrations/0004_evidence_source.sql`).
    source: Option<String>,
    /// `NULL` for any row with no provider-extension data (the common
    /// case) or written before FORNX-158's 0005 migration — reads back as
    /// `Evidence::extension == None` (see
    /// `migrations/0005_evidence_extension.sql`).
    extension: Option<String>,
}

impl TryFrom<EvidenceRow> for Evidence {
    type Error = StoreError;
    fn try_from(r: EvidenceRow) -> Result<Self> {
        Ok(Evidence {
            id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
            session_id: r.session_id,
            source_event_id: uuid::Uuid::parse_str(&r.source_event_id).unwrap_or_default(),
            kind: from_tag(&r.kind)?,
            observed_at: r.observed_at,
            payload: serde_json::from_str(&r.payload)?,
            provenance: r.provenance,
            source: r.source.map(|s| serde_json::from_str(&s)).transpose()?,
            extension: r.extension.map(|s| serde_json::from_str(&s)).transpose()?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: String,
    session_id: String,
    provider: String,
    kind: String,
    observed_at: String,
    tool_name: Option<String>,
    tool_input: Option<String>,
    tool_response: Option<String>,
    raw: String,
}

impl TryFrom<EventRow> for AgentEvent {
    type Error = StoreError;
    fn try_from(r: EventRow) -> Result<Self> {
        Ok(AgentEvent {
            id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
            session_id: r.session_id,
            provider: from_tag(&r.provider)?,
            kind: from_tag(&r.kind)?,
            observed_at: r.observed_at,
            tool_name: r.tool_name,
            tool_input: r.tool_input.map(|s| serde_json::from_str(&s)).transpose()?,
            tool_response: r
                .tool_response
                .map(|s| serde_json::from_str(&s))
                .transpose()?,
            raw: serde_json::from_str(&r.raw)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ClaimRow {
    id: String,
    session_id: String,
    source_event_id: String,
    text: String,
    subject: String,
    claimed_at: String,
}

impl TryFrom<ClaimRow> for Claim {
    type Error = StoreError;
    fn try_from(r: ClaimRow) -> Result<Self> {
        Ok(Claim {
            id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
            session_id: r.session_id,
            source_event_id: uuid::Uuid::parse_str(&r.source_event_id).unwrap_or_default(),
            text: r.text,
            subject: r.subject,
            claimed_at: r.claimed_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct EvidenceLinkRow {
    id: String,
    session_id: String,
    claim_id: String,
    evidence_id: String,
    relation: String,
    linked_at: String,
}

impl TryFrom<EvidenceLinkRow> for EvidenceLink {
    type Error = StoreError;
    fn try_from(r: EvidenceLinkRow) -> Result<Self> {
        Ok(EvidenceLink {
            id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
            session_id: r.session_id,
            claim_id: uuid::Uuid::parse_str(&r.claim_id).unwrap_or_default(),
            evidence_id: uuid::Uuid::parse_str(&r.evidence_id).unwrap_or_default(),
            relation: from_tag(&r.relation)?,
            linked_at: r.linked_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct MissingEvidenceRow {
    id: String,
    session_id: String,
    claim_id: String,
    signal_class: String,
    availability: String,
    detail: Option<String>,
    noted_at: String,
}

impl TryFrom<MissingEvidenceRow> for MissingEvidence {
    type Error = StoreError;
    fn try_from(r: MissingEvidenceRow) -> Result<Self> {
        Ok(MissingEvidence {
            id: uuid::Uuid::parse_str(&r.id).unwrap_or_default(),
            session_id: r.session_id,
            claim_id: uuid::Uuid::parse_str(&r.claim_id).unwrap_or_default(),
            signal_class: from_tag(&r.signal_class)?,
            availability: from_tag(&r.availability)?,
            detail: r.detail,
            noted_at: r.noted_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct CapabilitiesRow {
    provider: String,
    supports_pre_tool_use: bool,
    supports_post_tool_use: bool,
    supports_tool_response_capture: bool,
    supports_session_stop_event: bool,
    supports_transcript_tail: bool,
    supports_subagent_lifecycle: bool,
    notes: String,
    /// `NULL` for any row written before FORNX-155's 0003 migration.
    schema_version: Option<i64>,
    /// `NULL` for any row written before FORNX-155's 0003 migration —
    /// reconstruct from the six bool columns above in that case. Non-NULL
    /// rows are authoritative and complete; the bool columns are then only a
    /// write-only compatibility mirror (see 0003's migration comment).
    signals: Option<String>,
}

impl TryFrom<CapabilitiesRow> for RuntimeCapabilities {
    type Error = StoreError;
    fn try_from(r: CapabilitiesRow) -> Result<Self> {
        // Route both the pre-0003 (bools only) and post-0003 (signals JSON)
        // row shapes through `RuntimeCapabilities`'s own tolerant
        // `Deserialize` impl (`fornax_types::capabilities`), rather than
        // duplicating its legacy-bool-reconstruction rule here — one
        // reconstruction rule, exercised by both the wire path and this
        // store path, cannot drift apart.
        let mut value = serde_json::json!({});
        value["provider"] = serde_json::Value::String(r.provider.clone());
        value["supports_pre_tool_use"] = serde_json::Value::Bool(r.supports_pre_tool_use);
        value["supports_post_tool_use"] = serde_json::Value::Bool(r.supports_post_tool_use);
        value["supports_tool_response_capture"] =
            serde_json::Value::Bool(r.supports_tool_response_capture);
        value["supports_session_stop_event"] =
            serde_json::Value::Bool(r.supports_session_stop_event);
        value["supports_transcript_tail"] = serde_json::Value::Bool(r.supports_transcript_tail);
        value["supports_subagent_lifecycle"] =
            serde_json::Value::Bool(r.supports_subagent_lifecycle);
        value["notes"] = serde_json::from_str(&r.notes)?;
        if let Some(schema_version) = r.schema_version {
            value["schema_version"] = serde_json::Value::Number(schema_version.into());
        }
        if let Some(signals) = &r.signals {
            value["signals"] = serde_json::from_str(signals)?;
        }
        Ok(serde_json::from_value(value)?)
    }
}

/// Denormalized finding + claim text, for read-only display surfaces (status
/// line, detail command, dashboard). Not the canonical `Finding` type.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct FindingRow {
    pub id: String,
    pub claim_id: String,
    pub verdict: String,
    pub evidence_ids: String,
    pub verifier_name: String,
    pub rationale: String,
    pub computed_at: String,
    pub claim_text: String,
    pub session_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{EventKind, EvidenceKind, Provider, Verdict};
    use uuid::Uuid;

    fn tmp_db_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("fornax-store-test-{name}-{}.db", Uuid::new_v4()))
    }

    #[tokio::test]
    async fn fresh_db_creates_with_owner_only_permissions() {
        let path = tmp_db_path("perms");
        let _store = Store::open(&path).await.expect("open fresh db");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "DB file must not be group/world readable");
        }
        std::fs::remove_file(&path).ok();
    }

    /// FORNX-57: WAL mode keeps the newest rows — including claim text and
    /// evidence payloads that may carry secrets — in the `-wal` sidecar
    /// until a checkpoint. That file must be as locked-down as the main db.
    #[cfg(unix)]
    #[tokio::test]
    async fn wal_and_shm_sidecars_are_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = tmp_db_path("wal-perms");
        let store = Store::open(&path).await.expect("open fresh db");

        // Force a write so the -wal file actually has content, not just
        // exist with default perms from being newly created.
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "wal-perms".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: None,
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        for suffix in ["-wal", "-shm"] {
            let sidecar = append_ext(&path, suffix);
            let mode = std::fs::metadata(&sidecar)
                .unwrap_or_else(|e| panic!("expected {} to exist: {e}", sidecar.display()))
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                0o600,
                "{} must not be group/world readable",
                sidecar.display()
            );
        }

        drop(store);
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(append_ext(&path, "-wal")).ok();
        std::fs::remove_file(append_ext(&path, "-shm")).ok();
    }

    #[tokio::test]
    async fn event_evidence_claim_finding_round_trip() {
        let path = tmp_db_path("roundtrip");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            provider: Provider::Codex,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("exec_command".into()),
            tool_input: Some(serde_json::json!(["pytest"])),
            tool_response: Some(serde_json::json!({"exit_code": 1})),
            raw: serde_json::json!({"type": "exec_command_end"}),
        };
        store.insert_event(&event).await.expect("insert event");

        let evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:01Z".into(),
            payload: serde_json::json!({"command": ["pytest"], "exit_code": 1}),
            provenance: "test".into(),
            source: Some(fornax_types::EvidenceSource {
                sensor_name: "test_sensor_v1".into(),
                trust_class: fornax_types::TrustClass::HostObserved,
                collected_at: "2026-01-01T00:00:01Z".into(),
                provider: Some(Provider::Codex),
                collection_method: fornax_types::CollectionMethod::ProcessObservation,
                collector_version: Some("test-sensor-0.1.0".into()),
                freshness: fornax_types::Freshness {
                    clock_source: fornax_types::ClockSource::HostClock,
                    caveat: None,
                },
                tamper_boundary: fornax_types::TamperBoundary::for_trust_class(
                    &fornax_types::TrustClass::HostObserved,
                    &fornax_types::CollectionMethod::ProcessObservation,
                ),
                correlation_group: None,
                derived_from: Vec::new(),
            }),
            extension: None,
        };
        store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");

        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: event.id,
            text: "All tests passed.".into(),
            subject: "test_result".into(),
            claimed_at: "2026-01-01T00:00:02Z".into(),
        };
        store.insert_claim(&claim).await.expect("insert claim");

        let finding = Finding {
            id: Uuid::new_v4(),
            claim_id: claim.id,
            verdict: Verdict::Contradicted,
            evidence_ids: vec![evidence.id],
            verifier_name: "test_result_verifier_v1".into(),
            rationale: "exit_code=1".into(),
            computed_at: "2026-01-01T00:00:03Z".into(),
        };
        store
            .insert_finding(&finding)
            .await
            .expect("insert finding");

        let fetched_evidence = store
            .evidence_for_session("s1")
            .await
            .expect("query evidence")
            .evidence;
        assert_eq!(fetched_evidence.len(), 1);
        assert_eq!(fetched_evidence[0].id, evidence.id);
        assert_eq!(fetched_evidence[0].payload["exit_code"], 1);
        // FORNX-157: structured EvidenceSource/trust-class metadata must
        // survive the local persistence round trip byte-for-byte.
        assert_eq!(fetched_evidence[0].source, evidence.source);

        let recent = store.recent_findings(10).await.expect("query findings");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].verdict, "contradicted");
        assert_eq!(recent[0].claim_text, "All tests passed.");

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reopening_existing_db_preserves_prior_data() {
        let path = tmp_db_path("restart");
        {
            let store = Store::open(&path).await.expect("open db first time");
            let event = AgentEvent {
                id: Uuid::new_v4(),
                session_id: "s2".into(),
                provider: Provider::ClaudeCode,
                kind: EventKind::SessionStart,
                observed_at: "2026-01-01T00:00:00Z".into(),
                tool_name: None,
                tool_input: None,
                tool_response: None,
                raw: serde_json::json!({}),
            };
            store.insert_event(&event).await.expect("insert event");
        }
        // Simulate a daemon restart: reopen the same path.
        let store = Store::open(&path).await.expect("reopen db after restart");
        let evidence = store
            .evidence_for_session("s2")
            .await
            .expect("query after restart")
            .evidence;
        assert!(
            evidence.is_empty(),
            "no evidence was inserted, only an event"
        );

        std::fs::remove_file(&path).ok();
    }

    fn sample_capabilities() -> RuntimeCapabilities {
        use fornax_types::{CapabilitySignal, SignalAvailability, SignalClass};
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolInvocation,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ToolResultPayload,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::SessionLifecycle,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::SubagentLifecycle,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
            ],
            notes: [("session_id".to_string(), "s3".to_string())].into(),
        }
    }

    /// FORNX-62: a capabilities announcement must survive a daemon restart
    /// (reopen of the same store path), the same guarantee already proven
    /// for events/evidence in `reopening_existing_db_preserves_prior_data`.
    #[tokio::test]
    async fn capabilities_round_trip_survives_reopen() {
        let path = tmp_db_path("caps-roundtrip");
        {
            let store = Store::open(&path).await.expect("open db first time");
            store
                .upsert_capabilities("s3", &sample_capabilities())
                .await
                .expect("upsert capabilities");
        }
        // Simulate a daemon restart: reopen the same path.
        let store = Store::open(&path).await.expect("reopen db after restart");

        let fetched = store
            .capabilities_for_session("s3")
            .await
            .expect("query capabilities after restart");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].provider, Provider::ClaudeCode);
        assert!(fetched[0].is_observable(&fornax_types::SignalClass::ToolInvocation));
        assert!(!fetched[0].is_observable(&fornax_types::SignalClass::SessionLifecycle));
        assert_eq!(fetched[0].notes.get("session_id").unwrap(), "s3");

        std::fs::remove_file(&path).ok();
    }

    /// A later announcement for the same (session_id, provider) overwrites
    /// the previous one rather than accumulating a second row — this is the
    /// one place this store deviates from insert-only (see
    /// `migrations/0002_runtime_capabilities.sql`).
    #[tokio::test]
    async fn capabilities_reannouncement_overwrites_not_accumulates() {
        let path = tmp_db_path("caps-upsert");
        let store = Store::open(&path).await.expect("open db");

        store
            .upsert_capabilities("s4", &sample_capabilities())
            .await
            .expect("first announcement");

        let mut updated = sample_capabilities();
        if let Some(s) = updated
            .signals
            .iter_mut()
            .find(|s| s.class == fornax_types::SignalClass::SessionLifecycle)
        {
            s.state = fornax_types::SignalAvailability::Available;
        }
        store
            .upsert_capabilities("s4", &updated)
            .await
            .expect("second announcement");

        let fetched = store
            .capabilities_for_session("s4")
            .await
            .expect("query capabilities");
        assert_eq!(
            fetched.len(),
            1,
            "re-announcement must overwrite, not add a row"
        );
        assert!(fetched[0].is_observable(&fornax_types::SignalClass::SessionLifecycle));

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn capabilities_for_session_empty_when_none_announced() {
        let path = tmp_db_path("caps-empty");
        let store = Store::open(&path).await.expect("open db");

        let fetched = store
            .capabilities_for_session("no-such-session")
            .await
            .expect("query capabilities");
        assert!(fetched.is_empty());

        std::fs::remove_file(&path).ok();
    }

    /// FORNX-155: a row written before the 0003 migration (bool columns
    /// populated, `schema_version`/`signals` both NULL) must still read back
    /// correctly, reconstructed via the exact same legacy rule the wire path
    /// uses. Simulates that shape by hand-inserting directly rather than via
    /// `upsert_capabilities` (which always writes the new columns).
    #[tokio::test]
    async fn pre_migration_row_with_null_signals_reconstructs_from_legacy_bools() {
        let path = tmp_db_path("caps-pre-migration");
        let store = Store::open(&path).await.expect("open db");

        sqlx::query(
            "INSERT INTO runtime_capabilities
                (session_id, provider, supports_pre_tool_use, supports_post_tool_use,
                 supports_tool_response_capture, supports_session_stop_event,
                 supports_transcript_tail, supports_subagent_lifecycle, notes)
             VALUES ('s5', 'codex', 0, 1, 1, 1, 1, 0, '{}')",
        )
        .execute(&store.pool)
        .await
        .expect("hand-insert pre-migration row");

        let fetched = store
            .capabilities_for_session("s5")
            .await
            .expect("query capabilities");
        assert_eq!(fetched.len(), 1);
        assert_eq!(
            fetched[0].schema_version,
            fornax_types::CAPABILITY_SCHEMA_VERSION
        );
        assert!(!fetched[0].is_observable(&fornax_types::SignalClass::ToolInvocation));
        assert!(fetched[0].is_observable(&fornax_types::SignalClass::ToolTrace));
        assert!(fetched[0].is_observable(&fornax_types::SignalClass::SessionLifecycle));
        assert!(!fetched[0].is_observable(&fornax_types::SignalClass::SubagentLifecycle));
        // A class the old bools never covered is ordinary absence, not a
        // fabricated Unsupported/Unavailable claim.
        assert_eq!(
            fetched[0].state_of(&fornax_types::SignalClass::ProcessResult),
            fornax_types::SignalAvailability::Unknown
        );

        std::fs::remove_file(&path).ok();
    }

    /// FORNX-157: a row written before the 0004 migration (or by code not
    /// yet migrated onto `EvidenceSensor`) has `source IS NULL`. It must
    /// still read back cleanly, with `Evidence::source == None` — not a
    /// fabricated value and not a query error. Mirrors
    /// `pre_migration_row_with_null_signals_reconstructs_from_legacy_bools`'s
    /// hand-insert pattern for `runtime_capabilities`.
    #[tokio::test]
    async fn pre_migration_evidence_row_with_null_source_reads_back_as_none() {
        let path = tmp_db_path("evidence-pre-migration");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s6".into(),
            provider: Provider::Codex,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("exec_command".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        sqlx::query(
            "INSERT INTO evidence (id, session_id, source_event_id, kind, observed_at, payload, provenance)
             VALUES (?1, 's6', ?2, 'exit_code', '2026-01-01T00:00:01Z', '{\"exit_code\":0}', 'legacy')",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(event.id.to_string())
        .execute(&store.pool)
        .await
        .expect("hand-insert pre-migration evidence row with no source column value");

        let fetched = store
            .evidence_for_session("s6")
            .await
            .expect("query evidence")
            .evidence;
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].source, None);

        std::fs::remove_file(&path).ok();
    }

    /// FORNX-159 AC: "Existing Stage 1/2 evidence is migrated with honest
    /// defaults/unknowns where history lacks detail." Distinct from
    /// `pre_migration_evidence_row_with_null_source_reads_back_as_none`
    /// above: this row's `source` column is *not* NULL — it holds a
    /// genuine FORNX-157-era `EvidenceSource` JSON blob (trust_class,
    /// sensor_name, collected_at, provider all known and real), written
    /// before FORNX-159's `collection_method`/`collector_version`/
    /// `freshness`/`tamper_boundary` fields existed at all. No new
    /// `fornax-store` column is added for these fields — they live inside
    /// the same JSON blob (see `fornax_types::sensor`'s module docs' "no new
    /// fornax-store column" design note) — so the honesty guarantee lives
    /// entirely in `EvidenceSource`'s `#[serde(default)]`s, proven here
    /// through the full store round trip (not just an in-memory serde
    /// round trip, matching `evidence_extension_unknown_field_survives_store_round_trip`'s
    /// precedent below).
    #[tokio::test]
    async fn pre_migration_evidence_source_reads_back_new_fields_as_honest_unknown() {
        let path = tmp_db_path("evidence-source-pre-fornx-159");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s6b".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        // The exact shape FORNX-157 persisted: sensor_name, trust_class,
        // collected_at, provider — nothing more.
        let legacy_source_json = serde_json::json!({
            "sensor_name": "claude_bash_exit_code_sensor_v1",
            "trust_class": "agent_adjacent",
            "collected_at": "2026-01-01T00:00:01Z",
            "provider": "claude_code",
        })
        .to_string();

        sqlx::query(
            "INSERT INTO evidence (id, session_id, source_event_id, kind, observed_at, payload, provenance, source)
             VALUES (?1, 's6b', ?2, 'exit_code', '2026-01-01T00:00:01Z', '{\"exit_code\":0}', 'legacy', ?3)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(event.id.to_string())
        .bind(&legacy_source_json)
        .execute(&store.pool)
        .await
        .expect("hand-insert pre-FORNX-159 evidence row with a FORNX-157-shaped source blob");

        let fetched = store
            .evidence_for_session("s6b")
            .await
            .expect("query evidence")
            .evidence;
        assert_eq!(fetched.len(), 1);
        let source = fetched[0]
            .source
            .as_ref()
            .expect("legacy source blob must still deserialize, not become None");

        // Known fields from FORNX-157 stay known — not touched by this
        // migration.
        assert_eq!(source.sensor_name, "claude_bash_exit_code_sensor_v1");
        assert_eq!(source.trust_class, fornax_types::TrustClass::AgentAdjacent);
        assert_eq!(source.provider, Some(Provider::ClaudeCode));

        // New fields must read as an explicit pre-provenance/unknown
        // marker, never a fabricated specific-sounding value (e.g. must not
        // silently become `CollectionMethod::HookCallback`, even though
        // that happens to be the real answer for this sensor — the point is
        // this binary cannot know that from the persisted row alone).
        assert_eq!(
            source.collection_method,
            fornax_types::CollectionMethod::PreProvenance,
            "missing collection_method must not be fabricated"
        );
        assert_eq!(source.collector_version, None);
        assert_eq!(
            source.freshness.clock_source,
            fornax_types::ClockSource::PreProvenance
        );
        assert_eq!(source.freshness.caveat, None);
        assert_eq!(
            source.tamper_boundary.description,
            "unknown (record predates tamper-boundary tracking)",
            "tamper boundary must not be reconstructed from trust_class alone"
        );

        // Read-modify-write stability: re-persisting the deserialized
        // Evidence (as a replay/migration pass would) must keep emitting
        // the honest markers explicitly, not silently drop back to an
        // absent key or acquire a real-looking value on the round trip.
        let mut migrated = fetched[0].clone();
        migrated.id = Uuid::new_v4();
        store
            .insert_evidence(&migrated)
            .await
            .expect("re-insert migrated evidence");
        let refetched = store
            .evidence_for_session("s6b")
            .await
            .expect("query evidence after re-insert")
            .evidence;
        let rewritten_source = refetched
            .iter()
            .find(|e| e.id == migrated.id)
            .and_then(|e| e.source.as_ref())
            .expect("re-persisted row must still carry a source");
        assert_eq!(
            rewritten_source.collection_method,
            fornax_types::CollectionMethod::PreProvenance
        );
        assert_eq!(
            rewritten_source.tamper_boundary.description,
            "unknown (record predates tamper-boundary tracking)"
        );

        std::fs::remove_file(&path).ok();
    }

    /// FORNX-92: a row written before `correlation_group`/`derived_from`
    /// existed (a FORNX-157/159-era `EvidenceSource` blob) must read those
    /// two fields back as their honest empty defaults (`None`, `[]`), never
    /// a fabricated correlation group or origin — mirrors
    /// `pre_migration_evidence_source_reads_back_new_fields_as_honest_unknown`
    /// above for the same reason: no new `fornax-store` column was added,
    /// so the honesty guarantee lives entirely in `EvidenceSource`'s
    /// `#[serde(default)]`s, proven here through a full store round trip.
    #[tokio::test]
    async fn pre_fornx_92_evidence_source_reads_back_correlation_fields_as_honest_empty() {
        let path = tmp_db_path("evidence-source-pre-fornx-92");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s6c".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        // The exact shape FORNX-157/159 persisted: no correlation_group,
        // no derived_from key at all.
        let legacy_source_json = serde_json::json!({
            "sensor_name": "claude_bash_exit_code_sensor_v1",
            "trust_class": "agent_adjacent",
            "collected_at": "2026-01-01T00:00:01Z",
            "provider": "claude_code",
            "collection_method": "hook_callback",
        })
        .to_string();

        sqlx::query(
            "INSERT INTO evidence (id, session_id, source_event_id, kind, observed_at, payload, provenance, source)
             VALUES (?1, 's6c', ?2, 'exit_code', '2026-01-01T00:00:01Z', '{\"exit_code\":0}', 'legacy', ?3)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(event.id.to_string())
        .bind(&legacy_source_json)
        .execute(&store.pool)
        .await
        .expect("hand-insert pre-FORNX-92 evidence row");

        let fetched = store
            .evidence_for_session("s6c")
            .await
            .expect("query evidence")
            .evidence;
        assert_eq!(fetched.len(), 1);
        let source = fetched[0]
            .source
            .as_ref()
            .expect("legacy source blob must still deserialize, not become None");

        assert_eq!(
            source.correlation_group, None,
            "missing correlation_group must not be fabricated"
        );
        assert!(
            source.derived_from.is_empty(),
            "missing derived_from must not be fabricated"
        );

        std::fs::remove_file(&path).ok();
    }

    /// FORNX-158: a row written before the 0005 migration (or with no
    /// provider-extension data at all, the common case) has `extension IS
    /// NULL`. It must read back cleanly as `Evidence::extension == None`,
    /// not a fabricated value or a query error. Mirrors
    /// `pre_migration_evidence_row_with_null_source_reads_back_as_none`.
    #[tokio::test]
    async fn pre_migration_evidence_row_with_null_extension_reads_back_as_none() {
        let path = tmp_db_path("evidence-extension-pre-migration");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s7".into(),
            provider: Provider::Codex,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("exec_command".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        sqlx::query(
            "INSERT INTO evidence (id, session_id, source_event_id, kind, observed_at, payload, provenance)
             VALUES (?1, 's7', ?2, 'exit_code', '2026-01-01T00:00:01Z', '{\"exit_code\":0}', 'legacy')",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(event.id.to_string())
        .execute(&store.pool)
        .await
        .expect("hand-insert pre-migration evidence row with no extension column value");

        let fetched = store
            .evidence_for_session("s7")
            .await
            .expect("query evidence")
            .evidence;
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].extension, None);

        std::fs::remove_file(&path).ok();
    }

    /// FORNX-158 required test: an unknown top-level field on an
    /// `ExtensionEnvelope`, within a compatible `schema_version`, must
    /// survive the SQLite store round trip (insert -> read back ->
    /// re-serialize), not just an in-memory serde round trip — this is
    /// where a naive "deserialize into a fixed struct" implementation would
    /// actually drop it.
    #[tokio::test]
    async fn evidence_extension_unknown_field_survives_store_round_trip() {
        let path = tmp_db_path("evidence-extension-unknown-field");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s8".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        let mut extension = fornax_types::ExtensionEnvelope::new(
            Provider::ClaudeCode,
            "claude-adapter-0.3.0",
            fornax_types::ContentClass::ToolTelemetry,
            serde_json::json!({"cache_read_tokens": 7}),
        );
        extension
            .unknown
            .insert("future_field".into(), serde_json::json!("keep me"));

        let evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: "s8".into(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:01Z".into(),
            payload: serde_json::json!({"command": [], "exit_code": 0}),
            provenance: "test".into(),
            source: None,
            extension: Some(extension),
        };
        store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");

        let fetched = store
            .evidence_for_session("s8")
            .await
            .expect("query evidence")
            .evidence;
        assert_eq!(fetched.len(), 1);
        let got = fetched[0].extension.as_ref().expect("extension present");
        assert_eq!(
            got.unknown.get("future_field"),
            Some(&serde_json::json!("keep me")),
            "unknown extension field must not be dropped across the store round trip"
        );
        assert_eq!(got.fields["cache_read_tokens"], serde_json::json!(7));

        std::fs::remove_file(&path).ok();
    }

    /// FORNX-289: a session with one good evidence row and one row whose
    /// `extension` blob carries an incompatible `schema_version` (per
    /// `ExtensionEnvelope`'s `TryFrom`, see `extension.rs`) must not fail
    /// the whole session read — the caller still needs the good row, plus
    /// an explicit account of the bad one (not a silent drop, and not a
    /// fabricated success).
    #[tokio::test]
    async fn one_bad_extension_row_does_not_fail_the_whole_session_read() {
        let path = tmp_db_path("evidence-partial-failure");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s9".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        // Good row, inserted via the normal API.
        let good = Evidence {
            id: Uuid::new_v4(),
            session_id: "s9".into(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:01Z".into(),
            payload: serde_json::json!({"command": [], "exit_code": 0}),
            provenance: "test".into(),
            source: None,
            extension: None,
        };
        store.insert_evidence(&good).await.expect("insert good row");

        // Bad row: hand-inserted directly (bypassing `insert_evidence`,
        // which would require a valid `ExtensionEnvelope` to serialize in
        // the first place) with an `extension` blob whose `schema_version`
        // is outside `SUPPORTED_EXTENSION_SCHEMA_VERSIONS`.
        let bad_id = Uuid::new_v4();
        let bad_extension = serde_json::json!({
            "schema_version": 999,
            "provider": "claude_code",
            "adapter_version": "claude-adapter-0.3.0",
            "content_class": "tool_telemetry",
            "fields": {}
        })
        .to_string();
        sqlx::query(
            "INSERT INTO evidence (id, session_id, source_event_id, kind, observed_at, payload, provenance, extension)
             VALUES (?1, 's9', ?2, 'exit_code', '2026-01-01T00:00:02Z', '{\"exit_code\":0}', 'legacy', ?3)",
        )
        .bind(bad_id.to_string())
        .bind(event.id.to_string())
        .bind(&bad_extension)
        .execute(&store.pool)
        .await
        .expect("hand-insert row with an incompatible extension schema_version");

        let outcome = store
            .evidence_for_session("s9")
            .await
            .expect("session read must succeed despite one bad row");

        assert_eq!(
            outcome.evidence.len(),
            1,
            "the good row must still come back"
        );
        assert_eq!(outcome.evidence[0].id, good.id);

        assert_eq!(
            outcome.failed.len(),
            1,
            "the bad row must be reported, not silently dropped"
        );
        assert_eq!(outcome.failed[0].id, bad_id.to_string());
        assert!(
            outcome.failed[0].error.contains("incompatible"),
            "failure reason must name the FORNX-158 incompatibility, got: {}",
            outcome.failed[0].error
        );

        std::fs::remove_file(&path).ok();
    }

    // --- FORNX-89: evidence graph ------------------------------------------

    fn sample_evidence(session_id: &str, source_event_id: Uuid) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.into(),
            source_event_id,
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:01Z".into(),
            payload: serde_json::json!({"command": ["pytest"], "exit_code": 0}),
            provenance: "test".into(),
            source: None,
            extension: None,
        }
    }

    /// FORNX-89 core scenario: a claim with 2 supporting + 1 contradicting
    /// evidence link, plus one explicit missing-evidence marker, round-trips
    /// through the store — and none of this touches how `Evidence`/`Claim`
    /// themselves are stored (asserted via the untouched
    /// `evidence_for_session`/`claims_for_session` reads below).
    #[tokio::test]
    async fn claim_evidence_graph_round_trips_with_supports_contradicts_and_missing() {
        use fornax_types::{EvidenceRelation, SignalAvailability, SignalClass};

        let path = tmp_db_path("evidence-graph-roundtrip");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "sg1".into(),
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
            session_id: "sg1".into(),
            source_event_id: event.id,
            text: "All tests passed.".into(),
            subject: "test_result".into(),
            claimed_at: "2026-01-01T00:00:02Z".into(),
        };
        store.insert_claim(&claim).await.expect("insert claim");

        let ev_a = sample_evidence("sg1", event.id);
        let ev_b = sample_evidence("sg1", event.id);
        let ev_c = sample_evidence("sg1", event.id);
        for ev in [&ev_a, &ev_b, &ev_c] {
            store.insert_evidence(ev).await.expect("insert evidence");
        }

        let link_a = EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "sg1".into(),
            claim_id: claim.id,
            evidence_id: ev_a.id,
            relation: EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:03Z".into(),
        };
        let link_b = EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "sg1".into(),
            claim_id: claim.id,
            evidence_id: ev_b.id,
            relation: EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:04Z".into(),
        };
        let link_c = EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "sg1".into(),
            claim_id: claim.id,
            evidence_id: ev_c.id,
            relation: EvidenceRelation::Contradicts,
            linked_at: "2026-01-01T00:00:05Z".into(),
        };
        for link in [&link_a, &link_b, &link_c] {
            store
                .insert_evidence_link(link)
                .await
                .expect("insert evidence link");
        }

        let missing = MissingEvidence {
            id: Uuid::new_v4(),
            session_id: "sg1".into(),
            claim_id: claim.id,
            signal_class: SignalClass::ProcessResult,
            availability: SignalAvailability::Unavailable,
            detail: Some("no process-result sensor observed this claim".into()),
            noted_at: "2026-01-01T00:00:06Z".into(),
        };
        store
            .insert_missing_evidence(&missing)
            .await
            .expect("insert missing evidence");

        let graph = store
            .evidence_graph_for_claim(&claim.id.to_string(), "sg1")
            .await
            .expect("query evidence graph");

        assert_eq!(graph.links.len(), 3);
        let supports = graph
            .links
            .iter()
            .filter(|l| l.relation == EvidenceRelation::Supports)
            .count();
        let contradicts = graph
            .links
            .iter()
            .filter(|l| l.relation == EvidenceRelation::Contradicts)
            .count();
        assert_eq!(supports, 2);
        assert_eq!(contradicts, 1);

        assert_eq!(graph.missing.len(), 1);
        assert_eq!(graph.missing[0].signal_class, SignalClass::ProcessResult);
        assert_eq!(
            graph.missing[0].availability,
            SignalAvailability::Unavailable
        );
        assert_eq!(
            graph.missing[0].detail.as_deref(),
            Some("no process-result sensor observed this claim")
        );

        // Nothing about existing Evidence/Claim storage changed shape.
        let evidence = store
            .evidence_for_session("sg1")
            .await
            .expect("query evidence")
            .evidence;
        assert_eq!(evidence.len(), 3);
        let claims = store.claims_for_session("sg1").await.expect("query claims");
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, claim.id);

        std::fs::remove_file(&path).ok();
    }

    /// A claim with zero links and zero missing-evidence notes ("nobody has
    /// looked yet") must be distinguishable from a claim with zero links but
    /// a non-empty missing-evidence list ("evidence could not exist") — the
    /// FORNX-89 core invariant, proven end-to-end through the store.
    #[tokio::test]
    async fn claim_with_no_evidence_is_distinguishable_from_claim_with_missing_evidence_noted() {
        use fornax_types::{SignalAvailability, SignalClass};

        let path = tmp_db_path("evidence-graph-missing-distinct");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "sg2".into(),
            provider: Provider::Codex,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: None,
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        let claim_untouched = Claim {
            id: Uuid::new_v4(),
            session_id: "sg2".into(),
            source_event_id: event.id,
            text: "Nobody has verified this yet.".into(),
            subject: "test_result".into(),
            claimed_at: "2026-01-01T00:00:01Z".into(),
        };
        let claim_known_absent = Claim {
            id: Uuid::new_v4(),
            session_id: "sg2".into(),
            source_event_id: event.id,
            text: "Deployment succeeded.".into(),
            subject: "deployment_result".into(),
            claimed_at: "2026-01-01T00:00:02Z".into(),
        };
        store
            .insert_claim(&claim_untouched)
            .await
            .expect("insert claim");
        store
            .insert_claim(&claim_known_absent)
            .await
            .expect("insert claim");

        store
            .insert_missing_evidence(&MissingEvidence {
                id: Uuid::new_v4(),
                session_id: "sg2".into(),
                claim_id: claim_known_absent.id,
                signal_class: SignalClass::ProcessResult,
                availability: SignalAvailability::Unsupported,
                detail: Some("this runtime cannot observe deployment outcomes".into()),
                noted_at: "2026-01-01T00:00:03Z".into(),
            })
            .await
            .expect("insert missing evidence");

        let untouched_graph = store
            .evidence_graph_for_claim(&claim_untouched.id.to_string(), "sg2")
            .await
            .expect("query untouched graph");
        let known_absent_graph = store
            .evidence_graph_for_claim(&claim_known_absent.id.to_string(), "sg2")
            .await
            .expect("query known-absent graph");

        assert!(untouched_graph.links.is_empty());
        assert!(untouched_graph.missing.is_empty());

        assert!(known_absent_graph.links.is_empty());
        assert_eq!(known_absent_graph.missing.len(), 1);

        std::fs::remove_file(&path).ok();
    }

    /// FORNX-89 AC: "graph queries cannot cross tenant/session authorization
    /// boundaries." A correct `claim_id` paired with the *wrong*
    /// `session_id` must come back empty, not leak another session's links.
    #[tokio::test]
    async fn evidence_graph_query_does_not_cross_session_boundary() {
        use fornax_types::EvidenceRelation;

        let path = tmp_db_path("evidence-graph-session-boundary");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "sg3".into(),
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
            session_id: "sg3".into(),
            source_event_id: event.id,
            text: "All tests passed.".into(),
            subject: "test_result".into(),
            claimed_at: "2026-01-01T00:00:01Z".into(),
        };
        store.insert_claim(&claim).await.expect("insert claim");

        let evidence = sample_evidence("sg3", event.id);
        store
            .insert_evidence(&evidence)
            .await
            .expect("insert evidence");

        store
            .insert_evidence_link(&EvidenceLink {
                id: Uuid::new_v4(),
                session_id: "sg3".into(),
                claim_id: claim.id,
                evidence_id: evidence.id,
                relation: EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:02Z".into(),
            })
            .await
            .expect("insert evidence link");

        let correct_session = store
            .evidence_graph_for_claim(&claim.id.to_string(), "sg3")
            .await
            .expect("query with correct session");
        assert_eq!(correct_session.links.len(), 1);

        let wrong_session = store
            .evidence_graph_for_claim(&claim.id.to_string(), "some-other-session")
            .await
            .expect("query with wrong session must not error");
        assert!(
            wrong_session.links.is_empty(),
            "a mismatched session_id must not return another session's evidence links"
        );

        std::fs::remove_file(&path).ok();
    }

    /// FORNX-89 AC: "existing v0.2 evidence can migrate/replay into the
    /// graph model." Simulates a pre-FORNX-89 evidence row (hand-inserted,
    /// `source IS NULL`, same shape as
    /// `pre_migration_evidence_row_with_null_source_reads_back_as_none`)
    /// being linked into the new graph model exactly as a replay pass would
    /// — proving the graph accepts legacy evidence with no special-casing.
    #[tokio::test]
    async fn legacy_pre_migration_evidence_can_be_linked_into_the_evidence_graph() {
        use fornax_types::EvidenceRelation;

        let path = tmp_db_path("evidence-graph-legacy-replay");
        let store = Store::open(&path).await.expect("open db");

        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "sg4".into(),
            provider: Provider::Codex,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("exec_command".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        store.insert_event(&event).await.expect("insert event");

        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "sg4".into(),
            source_event_id: event.id,
            text: "All tests passed.".into(),
            subject: "test_result".into(),
            claimed_at: "2026-01-01T00:00:01Z".into(),
        };
        store.insert_claim(&claim).await.expect("insert claim");

        // Legacy evidence row: no `source` column value at all, as a v0.2
        // (pre-FORNX-157) evidence row would look on disk.
        let legacy_evidence_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO evidence (id, session_id, source_event_id, kind, observed_at, payload, provenance)
             VALUES (?1, 'sg4', ?2, 'exit_code', '2026-01-01T00:00:02Z', '{\"exit_code\":0}', 'legacy')",
        )
        .bind(legacy_evidence_id.to_string())
        .bind(event.id.to_string())
        .execute(&store.pool)
        .await
        .expect("hand-insert legacy pre-FORNX-89 evidence row");

        // A replay pass links the legacy evidence into the graph model with
        // no special API, no migration of the `evidence` row itself.
        store
            .insert_evidence_link(&EvidenceLink {
                id: Uuid::new_v4(),
                session_id: "sg4".into(),
                claim_id: claim.id,
                evidence_id: legacy_evidence_id,
                relation: EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:03Z".into(),
            })
            .await
            .expect("link legacy evidence into the graph");

        let graph = store
            .evidence_graph_for_claim(&claim.id.to_string(), "sg4")
            .await
            .expect("query evidence graph");
        assert_eq!(graph.links.len(), 1);
        assert_eq!(graph.links[0].evidence_id, legacy_evidence_id);

        // The legacy evidence row itself is untouched: still reads back with
        // `source == None`, exactly as before this ticket.
        let evidence = store
            .evidence_for_session("sg4")
            .await
            .expect("query evidence")
            .evidence;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].source, None);

        std::fs::remove_file(&path).ok();
    }
}
