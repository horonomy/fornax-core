-- FORNX-123: local policy revocation persistence. Additive only -- touches
-- no existing table. RFC3339 TEXT timestamps, matching every other table in
-- this store.
--
-- Three tables, not two -- deviation from the design sketch, which showed
-- only `policy_revocation_state`/`policy_revocations` but required (in
-- prose) an append-only artifacts table so `fornax policy status` has real
-- provenance and "immutable and reconstructable" is literally true
-- on-device. `policy_revocation_state.envelope` from the sketch is dropped
-- in favor of `policy_revocation_artifacts` -- a duplicated blob in the
-- pointer table would be dead weight once the artifacts table exists.

-- Append-only: the signed envelope bytes exactly as received, one row per
-- (issuer, sequence) ever successfully ingested. Never re-verified after
-- ingest (sticky rule) -- this is provenance, not a re-verification source.
CREATE TABLE IF NOT EXISTS policy_revocation_artifacts (
    issuer TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    envelope BLOB NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY (issuer, sequence)
);

-- Latest-pointer table: one row per issuer, the high-water sequence and the
-- payload digest of the list that set it. Never lowered.
-- `unrecognized_entry_count` accumulates across every list ever ingested
-- from this issuer (an unrecognized `target_kind` carries no digest to key
-- an actionable row on -- see `policy_revocations` below -- so this running
-- total is its only persisted trace).
CREATE TABLE IF NOT EXISTS policy_revocation_state (
    issuer TEXT PRIMARY KEY,
    max_sequence INTEGER NOT NULL,
    last_payload_digest TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    unrecognized_entry_count INTEGER NOT NULL DEFAULT 0
);

-- The union-only, sticky set of revoked digests. A row is never deleted or
-- updated by a newer list that omits it -- only inserted, once, the first
-- time a given (issuer, target_kind, target_digest) is observed. An
-- Unrecognized-kind entry carries no digest at all (see
-- `RevocationTarget::Unrecognized`) and is never given a row here -- it is
-- only ever reflected in `policy_revocation_state.unrecognized_entry_count`.
CREATE TABLE IF NOT EXISTS policy_revocations (
    issuer TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_digest TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    audit_ref TEXT,
    superseded_by TEXT,
    first_seen_sequence INTEGER NOT NULL,
    first_seen_at TEXT NOT NULL,
    PRIMARY KEY (issuer, target_kind, target_digest)
);
