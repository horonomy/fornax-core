-- Evidence graph: claim-to-evidence relationship linkage and explicit
-- missing-evidence markers (FORNX-89, parent epic FORNX-66).
--
-- Additive only, following 0004/0005's precedent of extending the schema
-- without reinterpreting existing tables: two new tables alongside the
-- existing `claims`/`evidence` tables. Neither table's presence changes how
-- a `claims`/`evidence` row is written or read by existing code -- this is a
-- new linkage layer, not a migration of prior data (FORNX-89 AC: since the
-- graph starts empty, no backfill of Stage 1/2 evidence is required; a
-- verifier replay pass can populate links/missing-evidence for historical
-- sessions later with no schema change).
CREATE TABLE IF NOT EXISTS claim_evidence_links (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    claim_id        TEXT NOT NULL REFERENCES claims(id),
    evidence_id     TEXT NOT NULL REFERENCES evidence(id),
    relation        TEXT NOT NULL, -- 'supports' | 'contradicts' | 'neutral'
    linked_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_claim_evidence_links_claim ON claim_evidence_links(claim_id);
CREATE INDEX IF NOT EXISTS idx_claim_evidence_links_session ON claim_evidence_links(session_id);

-- A claim's explicit note that evidence of a given SignalClass was expected
-- but is Unavailable/Unsupported/CollectionFailed/Redacted (reuses the
-- existing SignalClass/SignalAvailability taxonomy from
-- 0002_runtime_capabilities.sql/0003_capability_signals.sql, no parallel
-- taxonomy). Keeps "no evidence found" (zero rows in claim_evidence_links)
-- distinguishable from "evidence could not exist" (a row here).
CREATE TABLE IF NOT EXISTS claim_missing_evidence (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    claim_id        TEXT NOT NULL REFERENCES claims(id),
    signal_class    TEXT NOT NULL,
    availability    TEXT NOT NULL,
    detail          TEXT,
    noted_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_claim_missing_evidence_claim ON claim_missing_evidence(claim_id);
