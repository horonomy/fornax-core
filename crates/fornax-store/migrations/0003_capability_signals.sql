-- Formalized capability taxonomy columns (FORNX-155).
--
-- Additive only, on the existing (session_id, provider)-keyed
-- `runtime_capabilities` table from 0002 -- the upsert cardinality rationale
-- there still holds; this is not a new table. Both new columns are nullable
-- with no default, and `signals IS NULL` is the exact marker for "this row
-- predates FORNX-155, reconstruct from the six legacy bool columns" -- the
-- same reconstruction rule `fornax_types::capabilities::RuntimeCapabilities`'s
-- `Deserialize` impl already applies to a legacy-shaped wire payload, reused
-- here (see `TryFrom<CapabilitiesRow>` in fornax-store::lib) so the two
-- reconstruction paths cannot drift apart.
--
-- The six `supports_*` bool columns are kept, not dropped: they become a
-- write-only compatibility mirror (derived from `signals` via
-- `LegacyCapabilitiesWire`/`is_observable` at write time), so any external
-- tooling reading this table directly during the migration window still
-- sees a value. `signals` is the sole source of truth going forward -- do
-- not re-derive meaning from the bool columns in new code.
ALTER TABLE runtime_capabilities ADD COLUMN schema_version INTEGER;
ALTER TABLE runtime_capabilities ADD COLUMN signals TEXT; -- JSON array of CapabilitySignal
