-- FORNX-341: local persistence for mined integrity-corpus candidate cases
-- (Stage 8, Active Evidence Intelligence). Additive only -- touches no
-- existing table.
--
-- `document` is opaque canonical JSON (`fornax_corpus::CandidateCase`) --
-- this table has no business parsing it; `Store` fields are `pub(crate)`,
-- so the candidate schema lives above this crate in `fornax-corpus`. This
-- mirrors `evidence.payload`, the existing precedent for an opaque JSON
-- column in this schema.
--
-- Every insert is paired, in the same transaction, with a
-- `DatasetLineageTag` row (`RetentionClass::SanitizedCandidate`) so
-- deletion/opt-out/sweep propagate through the existing FORNX-106
-- mechanism -- see `crates/fornax-store/src/retention.rs`. This table is
-- deliberately NOT enforced with a CHECK constraint tying it to a
-- retention class, per `0007_dataset_lineage.sql`'s own note that a
-- future longitudinal artifact table should be addable with only an
-- application-layer allow-list update.
CREATE TABLE IF NOT EXISTS corpus_candidates (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    mined_at       TEXT NOT NULL,
    document       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_corpus_candidates_session
    ON corpus_candidates(session_id);
