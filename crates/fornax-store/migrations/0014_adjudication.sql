-- FORNX-342: corpus adjudication (Stage 8). Additive only -- touches no
-- existing table.
--
-- Every domain type is stored as opaque canonical JSON in `document`,
-- matching `corpus_candidates.document`'s precedent (0013) -- this crate
-- has no dependency on `fornax-corpus` and never parses these documents.
--
-- `adjudication_reviewers` is NOT lineage-tagged: a reviewer identity is not
-- one session's data and is not scoped to any one tenant.
--
-- `adjudication_queue`/`adjudication_views`/`adjudication_reviews` ARE
-- lineage-tagged (tenant = the case's session_id) in the same transaction as
-- their insert, exactly like `corpus_candidates`, so FORNX-106 deletion/
-- sweep really removes them.
--
-- `gold_labels` is deliberately NOT lineage-tagged. It is insert-only and
-- metadata-only (see `fornax_corpus::adjudication::gold`'s doc comment) --
-- there is no session content in this table for a tenant delete to need to
-- touch. After a tenant delete removes a case's candidate/reviews, an
-- orphaned gold_labels row is excluded at export time with an explicit
-- reason, never silently emitted as a trajectory with no evidence.
CREATE TABLE IF NOT EXISTS adjudication_reviewers (
    id             TEXT PRIMARY KEY,
    document       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS adjudication_queue (
    case_id        TEXT PRIMARY KEY,
    document       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS adjudication_views (
    id             TEXT PRIMARY KEY,
    case_id        TEXT NOT NULL,
    reviewer_id    TEXT NOT NULL,
    document       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_adjudication_views_case ON adjudication_views(case_id);

CREATE TABLE IF NOT EXISTS adjudication_reviews (
    id             TEXT PRIMARY KEY,
    case_id        TEXT NOT NULL,
    reviewer_id    TEXT NOT NULL,
    round          INTEGER NOT NULL,
    document       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_adjudication_reviews_case ON adjudication_reviews(case_id);

CREATE TABLE IF NOT EXISTS gold_labels (
    case_id             TEXT NOT NULL,
    revision            INTEGER NOT NULL,
    document            TEXT NOT NULL,
    PRIMARY KEY (case_id, revision)
);
