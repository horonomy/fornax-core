-- FORNX-464: persisted egress profile, consent records and destination
-- allowlist. Backs fornax_types::egress::decide.
--
-- No row in `egress_profile` means the install has never chosen a profile:
-- 'unconfigured', which ships nothing. Existing databases come up
-- unconfigured with no consent and an empty allowlist; nothing is
-- auto-populated.
CREATE TABLE egress_profile (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    profile     TEXT NOT NULL CHECK (profile IN ('unconfigured', 'personal', 'corporate')),
    -- Bumped on every profile change; a consent granted under an earlier
    -- generation is stale and denies.
    generation  INTEGER NOT NULL,
    changed_at  TEXT NOT NULL,
    source      TEXT NOT NULL
);

CREATE TABLE egress_consents (
    id                  TEXT PRIMARY KEY,
    purpose             TEXT NOT NULL,
    destination         TEXT NOT NULL,            -- canonical Destination string
    data_classes        TEXT NOT NULL,            -- sorted JSON array of class strings
    granted_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,            -- required: consent always expires
    revoked_at          TEXT,
    revoked_reason      TEXT,
    profile_generation  INTEGER NOT NULL,
    authorization_ref   TEXT                      -- corporate processing authorization reference
);

CREATE TABLE egress_allowlist (
    id           TEXT PRIMARY KEY,
    purpose      TEXT NOT NULL,
    destination  TEXT NOT NULL,                   -- canonical Destination string
    added_at     TEXT NOT NULL,
    removed_at   TEXT
);
