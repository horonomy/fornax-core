-- FORNX-119: local policy cache persistence. Additive only -- touches no
-- existing table. RFC3339 TEXT timestamps, matching every other table in
-- this store.

CREATE TABLE IF NOT EXISTS policy_cache_bundles (
    bundle_id TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    envelope BLOB NOT NULL,
    issuer TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    policy_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    revision_digest TEXT NOT NULL,
    verified_by TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    first_activated_at TEXT NOT NULL,
    confirmed_at TEXT NOT NULL,
    PRIMARY KEY (bundle_id, payload_digest)
);

CREATE TABLE IF NOT EXISTS policy_cache_generations (
    generation INTEGER PRIMARY KEY,
    written_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_cache_generation_members (
    generation INTEGER NOT NULL REFERENCES policy_cache_generations(generation),
    policy_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    PRIMARY KEY (generation, policy_id)
);

CREATE TABLE IF NOT EXISTS policy_cache_slots (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    active_generation INTEGER,
    pending_generation INTEGER,
    last_known_good_generation INTEGER,
    ever_configured INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_sequence_high_water (
    issuer TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    max_sequence INTEGER NOT NULL,
    last_bundle_id TEXT NOT NULL,
    last_payload_digest TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (issuer, policy_id)
);
