-- FORNX-431 slice 2: persist what slice 1's pure decision functions
-- (fornax_types::provenance_guard::admission_decision /
-- classify_consumption_by_anchor) can only decide about in memory.
-- Additive only, matching 0004/0005/0011's precedent -- a single nullable
-- column on the existing `evidence` table, plus one new table.
--
-- `ingress_origin` (store-only, never on the wire `Evidence` type -- see
-- provenance_guard.rs's `EvidenceOrigin` doc comment): how a row physically
-- arrived, stamped by the *receiving* process, never by the payload. NULL
-- reads back as `EvidenceOrigin::Unknown` -- every pre-FORNX-431 row, and
-- any row written by code not yet updated to stamp an origin (slice 3's
-- job) -- which `admission_decision` always quarantines. This is the same
-- fail-closed-on-NULL precedent `source IS NULL` (0004) already set for
-- this table.
ALTER TABLE evidence ADD COLUMN ingress_origin TEXT; -- uds_ingest|daemon_acquisition|privileged_executor, or NULL = unknown

-- The persisted sibling of `EvidenceConsumptionLedger` (in-memory, slice 1) --
-- cross-restart, cross-process memory of which claim first consumed a given
-- evidence row, keyed by the same anchor rule
-- (`classify_consumption_by_anchor`) slice 1 already decided and tested.
--
-- `anchor_event_id` is the consuming claim's `source_event_id` at the time
-- it first consumed this row -- recorded, not re-derived, so a later schema
-- change to how an anchor is computed can never retroactively reinterpret
-- an already-recorded consumption.
--
-- No `session_id`/`anchor_event_id` foreign key: this table may legitimately
-- outlive a `claims` row the retention sweep has since hard-deleted, and
-- must never block that deletion.
--
-- UNIQUE(evidence_id, claim_id): the same claim re-consuming the same
-- evidence row is a no-op, enforced by the schema itself, not just
-- application logic -- `ON CONFLICT DO NOTHING` at the call site turns a
-- would-be constraint violation into the intended idempotent retry, never
-- a surfaced SQL error.
--
-- Retention: `RawLocal`, same class as `evidence` itself (see
-- retention.rs's `retention_class_for_table`). Ordering invariant a
-- consumption row must never outlive its evidence row -- once the payload
-- is purged, it can no longer support anything, so a surviving consumption
-- record would be stale, not merely harmless. This holds structurally: a
-- consumption row is only ever written by `record_consumption`, which is
-- only ever called after the evidence row it references has already been
-- durably inserted (see fornax-store's evidence_consumption module).
CREATE TABLE IF NOT EXISTS evidence_consumption (
    id              TEXT PRIMARY KEY,
    evidence_id     TEXT NOT NULL,
    claim_id        TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    anchor_event_id TEXT NOT NULL,
    verifier_name   TEXT,
    outcome         TEXT NOT NULL, -- consumed|quarantined|refused_replay
    reason          TEXT,
    recorded_at     TEXT NOT NULL,
    UNIQUE (evidence_id, claim_id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_consumption_evidence
    ON evidence_consumption(evidence_id, outcome);
CREATE INDEX IF NOT EXISTS idx_evidence_consumption_session
    ON evidence_consumption(session_id);
