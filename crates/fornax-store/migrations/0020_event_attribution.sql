-- FORNX-466: provider-native agent / turn attribution for a stored event.
--
-- One nullable-by-absence row per event that carried at least one of
-- agent_id / agent_type / turn_id in its provider payload; no row means the
-- payload carried none ("unattributed", NOT "root agent"). Claims, evidence
-- and findings are attributed through their source event, so a subagent's
-- claim and the evidence it produced resolve to the same (session, agent).
--
-- A side table rather than columns on agent_events/claims/evidence/findings:
-- the same four-dimension attribution is then written in the one place every
-- event passes through (Store::insert_event, in the event's own transaction),
-- with no wire or adapter change. Rows written before this migration have no
-- attribution row and are never backfilled (the execution identity contract:
-- a record's scope is fixed when it is recorded).
--
-- `lineage_status` is always 'unknown' today: no provider hook exposes a
-- parent link. The column exists so a future capturer can record 'root' or
-- 'child' without a migration.
CREATE TABLE event_attribution (
    event_id       TEXT PRIMARY KEY REFERENCES agent_events(id) ON DELETE CASCADE,
    agent_id       TEXT,
    agent_type     TEXT,
    turn_id        TEXT,
    lineage_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (lineage_status IN ('root', 'child', 'unknown'))
);
