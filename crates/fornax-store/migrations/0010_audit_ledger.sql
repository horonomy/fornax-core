-- FORNX-315: local append-only, hash-chained audit ledger persistence.
-- Additive only -- touches no existing table.
--
-- `audit_events` is the append-only chain itself: one row per appended
-- `AuditEvent` (FORNX-314, `fornax_types::audit::AuditEvent`), post-
-- redaction. `seq` is `INTEGER PRIMARY KEY`, which SQLite aliases to the
-- rowid -- a monotonically increasing integer assigned by
-- `Store::append_audit_event`, never by SQLite's own autoincrement
-- default (the value is computed explicitly from the previous row so the
-- hash chain and the sequence number can never drift apart). `recorded_at`
-- is when this store appended the row -- distinct from
-- `AuditEvent.occurred_at`, which is baked into `payload` and is whatever
-- the original event producer claimed.
--
-- `audit_ledger_high_water` is a single-row marker of the highest `seq`
-- ever assigned by this store, plus that row's own `entry_hash`, updated
-- in the same transaction as every append. Two distinct reasons this
-- exists, not one:
--
-- 1. Detecting a truncated tail: without it, deleting only the *trailing*
--    rows of `audit_events` leaves no internal gap and no broken
--    `prev_hash` link for `Store::verify_audit_chain` to notice -- the
--    remaining rows still form a perfectly coherent, shorter chain. See
--    `verify_audit_chain`'s `DivergenceKind::TruncatedTail` path.
-- 2. Making that truncation permanent, not merely detectable-until-the-next-
--    append: `Store::append_audit_event` allocates the next `seq`/`prev_hash`
--    from THIS table, never by re-reading `audit_events`'s own live max
--    row. If it re-read the live table instead, an attacker who deletes
--    trailing rows via direct SQLite access could have the very next
--    legitimate append silently "heal" the sequence by continuing from the
--    now-shorter tail, erasing every trace of the truncation. Because
--    `max_seq`/`last_entry_hash` are themselves append-only (monotonic --
--    an `ON CONFLICT` update never lowers `max_seq`) and untouched by
--    anything that deletes from `audit_events`, a subsequent legitimate
--    append instead resumes from where the ledger truly left off, which
--    `verify_audit_chain` then correctly reports as a `MissingSeq` gap
--    over the deleted rows rather than `Valid`.
--
-- No update or delete statement anywhere in this crate touches
-- `audit_events` -- `Store::append_audit_event` is the only write path (see
-- its own doc comment and the crate's
-- `no_write_path_other_than_append_audit_event_touches_audit_events` test).

CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    export_class TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_ledger_high_water (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    max_seq INTEGER NOT NULL,
    last_entry_hash TEXT NOT NULL
);
