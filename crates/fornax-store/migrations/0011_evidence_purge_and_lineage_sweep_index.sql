-- FORNX-319: wire dataset-lineage tagging into the live write path and
-- support the bounded incremental retention sweep. Additive only, following
-- 0004-0009's precedent.
--
-- `evidence_purged` (FORNX-319 AC2/AC3): a `RetentionClass::RawLocal`
-- evidence row's raw `payload` is purged in place once its retention window
-- elapses, rather than the row being deleted -- the referencing finding's
-- verdict/rationale/audit trail must stay intact and readable, and a
-- purged row must still say so explicitly (see
-- `fornax_store::retention::purge_evidence_payload`), never render as if no
-- evidence was ever collected. `NULL`/absent old rows read back as `0`
-- (not purged) via the column's `DEFAULT 0`.
ALTER TABLE evidence ADD COLUMN evidence_purged INTEGER NOT NULL DEFAULT 0;

-- The bounded incremental sweep (`fornax_store::retention::sweep_expired_records`)
-- walks `dataset_lineage_tags` in `recorded_at` order, one bounded batch per
-- call, so it can resume from a cursor instead of re-scanning the whole
-- table every cycle. No index existed on this column before this ticket.
CREATE INDEX IF NOT EXISTS idx_dataset_lineage_tags_recorded_at ON dataset_lineage_tags(recorded_at);
