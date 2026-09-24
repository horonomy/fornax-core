-- FORNX-348: local persistence for calibration revision snapshots (Stage
-- 8, Active Evidence Intelligence). Additive only -- touches no existing
-- table.
--
-- One row per recorded calibration baseline -- a snapshot of
-- `fornax_types::calibration::CalibrationProvenance` at the moment it was
-- adopted as "the calibration currently in force". `document` is opaque
-- canonical JSON, mirroring `acquisition_log.document`/
-- `corpus_candidates.document`/`evidence.payload`'s existing precedent for
-- an opaque JSON column in this schema -- this crate has no dependency on
-- fornax-verify or fornax-types::calibration and never parses it.
--
-- Insert-only: there is no UPDATE or DELETE path for this table anywhere
-- in this crate. A stale or drifted calibration is never edited in place
-- -- a new revision is recorded, and `latest_calibration_revision` always
-- reads the most recently recorded row. This preserves an honest history
-- of every calibration baseline this deployment has ever adopted, rather
-- than overwriting the prior one.
--
-- Deliberately NOT session- or tenant-scoped, unlike `acquisition_log`:
-- calibration provenance describes the deployment's own environment
-- (adapter version, policy identity, disabled sensors), not a single
-- session's observed evidence, so it has no session/tenant owner to scope
-- reads by.
CREATE TABLE IF NOT EXISTS calibration_revisions (
    id           TEXT PRIMARY KEY,
    recorded_at  TEXT NOT NULL,
    document     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_calibration_revisions_recorded_at
    ON calibration_revisions(recorded_at);
