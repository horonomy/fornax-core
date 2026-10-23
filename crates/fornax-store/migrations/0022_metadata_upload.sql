-- FORNX-464: the personal monthly metadata batch upload.
--
-- `upload_outbox` holds an immutable, metadata-only snapshot of each record
-- that was eligible for upload when it was staged (eligibility: captured under
-- the personal profile, after a live consent was granted). It is written
-- BEFORE the retention sweep deletes or purges the source row, so a monthly
-- cadence cannot lose data to the 30-day raw-evidence retention. It never
-- holds claim text, tool input/response, evidence payloads or rationale.
CREATE TABLE upload_outbox (
    kind         TEXT NOT NULL CHECK (kind IN ('sessions', 'events', 'claims', 'evidence', 'findings')),
    object_id    TEXT NOT NULL,
    window_id    TEXT NOT NULL,                      -- 'YYYY-MM' (UTC) of the record's own timestamp
    member_json  TEXT NOT NULL,                      -- canonical JSON of the metadata member
    member_sha256 TEXT NOT NULL,
    staged_at    TEXT NOT NULL,
    -- The consent that authorized staging this row. A row is only ever sealed
    -- under that same live consent; when it ends, pending rows expire and
    -- sealed batches are retired, never re-targeted at a later consent.
    consent_id   TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'inflight', 'acknowledged', 'poison', 'expired')),
    batch_id     TEXT,
    PRIMARY KEY (kind, object_id)
);
CREATE INDEX idx_upload_outbox_state_window ON upload_outbox (state, window_id);

-- One row per sealed batch. `members_json` is the exact canonical bytes that
-- were hashed, so a resend after a crash or lost response is byte-identical
-- and carries the same Idempotency-Key.
CREATE TABLE upload_batches (
    batch_id         TEXT PRIMARY KEY,
    window_id        TEXT NOT NULL,
    consent_id       TEXT NOT NULL,
    destination      TEXT NOT NULL,
    manifest_sha256  TEXT NOT NULL,
    canonicalization TEXT NOT NULL,
    member_count     INTEGER NOT NULL,
    byte_count       INTEGER NOT NULL,
    members_json     TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'sealed'
        CHECK (state IN ('sealed', 'acknowledged', 'poison')),
    attempts         INTEGER NOT NULL DEFAULT 0,
    last_error       TEXT,
    sealed_at        TEXT NOT NULL,
    last_attempt_at  TEXT,
    acked_at         TEXT
);

-- Records that could not be uploaded because the outbox hit its bound.
-- Never silent: every drop is counted here and audited.
CREATE TABLE upload_gaps (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id      TEXT NOT NULL,
    reason         TEXT NOT NULL,
    dropped_count  INTEGER NOT NULL,
    recorded_at    TEXT NOT NULL
);
