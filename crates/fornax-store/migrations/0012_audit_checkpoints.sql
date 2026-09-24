-- FORNX-317: local persistence for verified signed audit checkpoints
-- (ADR-0012). Additive only -- touches no existing table.
--
-- NOTE ON MIGRATION NUMBERING: ADR-0012 (as originally drafted) named this
-- file `0011_audit_checkpoints.sql`, on the assumption `0010_audit_ledger.sql`
-- was the highest existing migration. By the time this ticket (FORNX-317)
-- was implemented, no `0011_*.sql` migration existed in this crate's
-- `migrations/` directory on the base branch (`0010_audit_ledger.sql`
-- remained the highest), despite FORNX-319 (a concurrently-developed,
-- already-merged ticket) having landed other changes. This file is
-- nonetheless named `0012_audit_checkpoints.sql`, per this ticket's
-- explicit instruction, to avoid any future collision with a `0011_*.sql`
-- migration landing from elsewhere before this one merges.
--
-- `audit_checkpoints` persists each verified `SignedAuditCheckpoint`
-- envelope (`fornax_types::VerifiedAuditCheckpoint`, ADR-0012 §3) this
-- device has received and successfully verified -- never an unverified
-- envelope; see `Store::store_audit_checkpoint_receipt`'s doc comment.
-- `checkpoint_seq` is the cloud-side attestation series counter (ADR-0012
-- §0.1's naming rule: never called `seq`, and disjoint from
-- `audit_events.seq`/`ledger_seq`), `head_ledger_seq`/`head_entry_hash`
-- are the local ledger position/hash this checkpoint attests to,
-- `device_id` is the verified payload's own `device_id` (ADR-0012 §3.2:
-- "A device must check this equals its own" -- persisted so a later
-- receipt's `device_id` can be cross-checked against the FIRST stored
-- receipt's, which bootstraps the anchor; see
-- `Store::store_audit_checkpoint_receipt`'s doc comment for the residual
-- gap this cannot close), and `envelope` is the raw verified envelope
-- JSON text, kept verbatim for read-back/audit purposes.
--
-- This local copy is NOT the trust anchor -- an attacker with direct
-- SQLite access can delete it. The cloud's own copy (recoverable via
-- `GET /v1/devices/me/audit-checkpoints/{checkpoint_seq}`, ADR-0012 §7.4)
-- is. See ADR-0012 §8.1.
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    checkpoint_seq INTEGER PRIMARY KEY,
    head_ledger_seq INTEGER NOT NULL,
    head_entry_hash TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    device_id TEXT NOT NULL,
    envelope TEXT NOT NULL
);
