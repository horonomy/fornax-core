-- FORNX-212: durable quarantine record for ingest input the daemon could
-- not process, instead of `tracing::warn!` + silent drop. Additive only --
-- touches no existing table.
--
-- Two real gaps this closes (see crates/fornax-daemon/src/main.rs's
-- `process_line`): a line that fails `serde_json::from_str::<IngestMessage>`
-- (malformed/wrong-shape input, e.g. from a buggy/mismatched adapter
-- version) and a line that parses fine but fails `handle_message` (e.g. a
-- store write error). Both previously vanished with nothing queryable left
-- behind, which is exactly the "critical evidence cannot be silently
-- dropped" acceptance criterion failing for real input, not just overload.
--
-- `raw_line` is the untouched original line (so a human/tool can inspect or
-- replay it later -- this table is the DLQ an operator drains, not just an
-- audit trail). No `session_id` column: a parse failure may not even have
-- a well-formed enough payload to know which session it belonged to.
CREATE TABLE IF NOT EXISTS ingest_quarantine (
    id          TEXT PRIMARY KEY,
    received_at TEXT NOT NULL,
    reason_kind TEXT NOT NULL,
    reason      TEXT NOT NULL,
    raw_line    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ingest_quarantine_received_at
    ON ingest_quarantine(received_at);
