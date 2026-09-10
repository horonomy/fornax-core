-- FORNX-349: local persistence for product feedback on a live
-- finding/recommendation (Stage 8, Active Evidence Intelligence).
-- Additive only -- touches no existing table.
--
-- `document` is opaque canonical JSON (`fornax_corpus::feedback::ReviewFeedback`)
-- -- mirrors `corpus_candidates.document`/`acquisition_log.document`'s
-- existing precedent for an opaque JSON column; this crate has no
-- dependency on `fornax-corpus` and never parses it.
--
-- Session-scoped, like `acquisition_log` -- every read takes `session_id`,
-- matching FORNX-339's cross-session-identity discipline. Wired into
-- RetentionClass::SanitizedCandidate lineage exactly like
-- `corpus_candidates` itself: feedback about a case is exactly as
-- research-sensitive as the case it is about.
CREATE TABLE IF NOT EXISTS review_feedback (
    id           TEXT PRIMARY KEY,
    case_id      TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    document     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_review_feedback_case
    ON review_feedback(case_id);
