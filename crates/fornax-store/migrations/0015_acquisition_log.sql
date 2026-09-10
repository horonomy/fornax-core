-- FORNX-346: local persistence for real evidence-acquisition attempts
-- (Stage 8, Active Evidence Intelligence). Additive only -- touches no
-- existing table.
--
-- One row per `POST /api/acquire-evidence` attempt, whatever its outcome
-- (`outcome_kind` is one of the fornax_acquire::AcquisitionOutcome variant
-- names -- acquired/refused/unavailable/failed/unsupported). `document` is
-- opaque canonical JSON (the full request + outcome), mirroring
-- `corpus_candidates.document`/`evidence.payload`'s existing precedent for
-- an opaque JSON column in this schema -- this crate has no dependency on
-- fornax-acquire and never parses it.
--
-- Session-scoped only: every read in `crates/fornax-store/src/acquisition.rs`
-- takes `session_id`, matching FORNX-339's cross-session-identity
-- discipline -- a caller cannot list another session's acquisition
-- attempts through this table.
CREATE TABLE IF NOT EXISTS acquisition_log (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL,
    claim_id       TEXT NOT NULL,
    probe_kind     TEXT NOT NULL,
    policy_name    TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    outcome_kind   TEXT NOT NULL,
    requested_at   TEXT NOT NULL,
    document       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_acquisition_log_session_claim
    ON acquisition_log(session_id, claim_id);
