-- Longitudinal dataset lineage/retention ledger (FORNX-106, parent epic
-- FORNX-20 / discovery thesis HVDL-15). Additive only, following
-- 0004/0005/0006's precedent: a new table, no change to any existing
-- table's schema or interpretation.
--
-- FORNX-103 (`fornax_types::reliability_context::DatasetLineageTag`) defined
-- an in-memory schema for a future enforcement mechanism to attach to
-- derived/raw records, deliberately without persisting it or wiring it into
-- any store table. This table is where FORNX-106 actually persists that
-- schema, plus enough addressing (record_table/record_id) for the deletion-
-- propagation function in `fornax_store::retention` to find and remove the
-- real row a tag refers to.
--
-- `record_table` is restricted, at the application layer
-- (`fornax_store::retention::KNOWN_RECORD_TABLES`), to the small closed set
-- of tables this store defines today (agent_events/claims/evidence/
-- findings) -- this migration deliberately does not enforce that with a
-- CHECK constraint so a future longitudinal artifact table can be added
-- without a schema migration, only an application-layer allow-list update.
CREATE TABLE IF NOT EXISTS dataset_lineage_tags (
    id                     TEXT PRIMARY KEY,
    record_table           TEXT NOT NULL,
    record_id              TEXT NOT NULL,
    schema_version         INTEGER NOT NULL,
    retention_class        TEXT NOT NULL,
    tenant_ref             TEXT NOT NULL,
    source_record_ids      TEXT NOT NULL, -- JSON array of uuids
    recorded_at            TEXT NOT NULL,
    deletion_requested_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_dataset_lineage_tags_tenant ON dataset_lineage_tags(tenant_ref);
CREATE INDEX IF NOT EXISTS idx_dataset_lineage_tags_record ON dataset_lineage_tags(record_table, record_id);
