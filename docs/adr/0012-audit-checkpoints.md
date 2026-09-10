# ADR 0012 — Audit Checkpoints: Anchoring Local Ledger Heads to Signed Remote Checkpoints

**Status:** Accepted
**Ticket:** FORNX-317 · **Epic:** FORNX-20
**Repos:** `fornax-core` (device/verifier) + `fornax-cloud` (issuer/witness)

> **This document is the single normative wire contract.** Both implementers received it verbatim. Where this document and a repo-local comment disagree, **this document wins** — raise the conflict, do not resolve it locally.
>
> **Read the FORNX-312 post-mortem first.** That Critical bug was **not** a canonicalization failure. The signature verified correctly; the payload then failed `serde_json::from_slice::<RevocationPayload>` with `unknown field "target_kind"`, because one side emitted `{"target_kind":…,"digest":…}` flat on the entry and the other expected it nested under `target`. Both sides' unit tests passed. Only a live cross-repo poll caught it. **Therefore §3 (exact payload shape, with nesting spelled out) is the highest-risk section in this document, not §5 (canonicalization).**

---

## Migration numbering note (as implemented)

This ADR was originally drafted assuming `0010_audit_ledger.sql` was the highest existing `fornax-store` migration, making the natural next number `0011`. By the time FORNX-317 was implemented against `origin/next/v0.0.4`, no `0011_*.sql` migration existed in `crates/fornax-store/migrations/` on that base (`0010_audit_ledger.sql` remained the highest), even though FORNX-319 — a concurrently developed, already-merged ticket touching related audit/evidence concepts — had landed other changes. The migration added by this ticket is nonetheless named **`0012_audit_checkpoints.sql`**, per explicit implementation instruction, to avoid any future collision with an `0011_*.sql` migration landing from elsewhere before this one merges. See that file's own header comment for the same note.

---

## 0. Naming triple — fixed, use verbatim in both repos

The precedent vocabulary is `Signed*` (envelope) / `*Payload` (signed content) / `Verified*` (post-verification), established by `SignedPolicyBundle`/`BundlePayload`/`VerifiedPolicyBundle` and `SignedRevocationList`/`RevocationPayload`/`VerifiedRevocationList`. This ADR follows it:

| Role | Name | Where |
|---|---|---|
| Envelope (the signed wire artifact) | `SignedAuditCheckpoint` | Rust type; cloud emits as plain JSON dict |
| Signed content (base64-decoded) | `AuditCheckpointPayload` | Rust type; cloud builds as a Python dict |
| Post-verification value | `VerifiedAuditCheckpoint` | Rust only — the cloud never verifies |
| Device request body | `AuditCheckpointRequest` | Pydantic schema on the cloud; Rust serializes it |

The FORNX-317 ticket title's informal phrase *"AuditCheckpointReceipt"* refers to **`SignedAuditCheckpoint`**. That name is retired — no `Receipt` type exists on the wire in either repo. (`fornax-core` does use `AuditCheckpointReceipt` as the name of its *local persisted row* type in `fornax-store` — this is a storage-layer concept, distinct from any wire type, and never serialized to the wire under that name.)

### 0.1 The `seq` naming rule (anti-FORNX-312 measure)

Three distinct integer sequence spaces are in play. **The bare token `seq` must never appear as a wire field name, a JSON key, a Pydantic field, a Rust struct field, or a substring of an HTTP error `detail` string.** Every use is qualified:

| Concept | Wire/field name | Source of truth | Scope | Starts at |
|---|---|---|---|---|
| Position in the device's local hash chain | **`ledger_seq`** | `audit_events.seq` column (`fornax-store`, migration `0010`) | per-device, local | `GENESIS_SEQ = 1` |
| Position in the checkpoint attestation series | **`checkpoint_seq`** | `audit_checkpoints.checkpoint_seq` (cloud, new) | per `(organization_id, device_id)` | `1` |
| Revocation artifact counter (**not used here**) | `sequence` | `policy_revocation_artifacts.sequence` | per `organization_id` | `1` |

Explicit mapping statement, reproduced in both repos' code comments:

> Local column `audit_events.seq` (Rust `i64`) → wire field `head.ledger_seq`. They are the same number. The wire name differs from the column name deliberately, so that no reader can confuse it with `checkpoint_seq`.

---

## 1. What this contract is, and what it is not

A checkpoint is a **cloud-countersigned witness statement about what a device claimed its ledger head was at a point in time**. Nothing more.

**The cloud is a witness, never a verifier of the chain.** The cloud stores only `(ledger_seq, entry_hash)` pairs. It never receives audit event payloads, so it **structurally cannot** call `compute_entry_hash` and **cannot** verify the device's hash chain. Any cloud-side design that implies chain verification is wrong. See §7's four-case table for the only checks the cloud can perform.

**Why this ticket has security value.** Per ADR-0011's "Local ledger trust boundary" addendum and `audit_ledger.rs`'s module docs, `DivergenceKind::TruncatedTail` is currently detectable *only* by comparing `audit_events` against the device's own `audit_ledger_high_water` table — which an attacker with direct SQLite access can also reach and rewrite. A cloud-held checkpoint is a **second, external witness** to the same fact, outside the attacker's reach. That is the entire point of FORNX-317.

**What a checkpoint still does not prove** (stated in both repos; not overclaiming beyond ADR-0011):

- It does not attest the device recorded every event it should have. A device that never calls `append_audit_event` produces a valid chain and a valid checkpoint while being silently incomplete.
- It does not make a compromised endpoint trustworthy. An attacker in full control of the Fornax process can fabricate a self-consistent chain *and* get it checkpointed.
- It only makes **retroactive rewriting of already-checkpointed history** detectable.

### 1.1 Explicit non-goals (not implemented)

- **No `not_before` / `expires_at` on the payload.** Mirrors `RevocationPayload`'s deliberate no-expiry (`revocation.rs`, "Sticky, union-only, no expiry"). An expiring historical attestation is meaningless — the fact being attested is permanent.
- **No device-side signature.** `bundle.rs` states there is no signing key anywhere in `fornax-core`'s non-test paths. The device bearer credential is the authentication.
- **No attachment to `GET /v1/devices/me/policy-artifacts`.** That route's deliberate no-304 design is load-bearing for FORNX-119's `confirmed_at` staleness clock. The surfaces stay separate.
- **No audit event payloads sent to the cloud.** Only `(ledger_seq, entry_hash)`. The cloud's existing `audit_events` table is the cloud's **own** org-scoped administrative trail (FORNX-316) and is **unrelated** to the device's local ledger.
- **No new signature bounds.** Reuses `MAX_PAYLOAD_BYTES` (1 MiB) and `MAX_SIGNATURES` (8) via `verify_signed_envelope`, exactly as `verify_revocation_list` does.

---

## 2. Route, authentication, and the request shape

### 2.1 Route

```
POST /v1/devices/me/audit-checkpoints
```

Router prefix `/v1/devices/me`, matching `routers/device_policy.py`. Auth is `Depends(require_tenant_context)` (the device-credential path) — **not** `require_acting_organization`, and there is **no `organization_id` path parameter**. The organization comes solely from the authenticated device's `TenantContext`. This mirrors `device_policy.py`'s stated authorization rationale exactly.

`TenantContext.device_id` is `str | None`. If `ctx.device_id is None`, return **401** `{"detail": "device identity not resolved"}` — the identical guard `device_policy.py` already applies.

Success status: **201 Created** (mirrors `POST .../revocations`).

### 2.2 Request body — `AuditCheckpointRequest`

**Nesting is normative. `ledger_seq` and `entry_hash` are nested under `head`. They are never flat top-level keys.** (This is the exact class of mistake that caused FORNX-312.)

```json
{
  "checkpoint_schema_version": 1,
  "checkpoint_seq": 1,
  "observed_at": "2026-09-03T12:00:00Z",
  "head": {
    "ledger_seq": 5,
    "entry_hash": "sha256:e967d0e31e6afd2a3a0f5bd805e39f85eb0eeb4e176e88e0e65d3c26a1cba464"
  },
  "device_reported_chain_status": {
    "status": "valid",
    "first_bad_ledger_seq": null,
    "divergence_kind": null
  }
}
```

Field by field:

| Path | Type | Null/optional | Meaning |
|---|---|---|---|
| `checkpoint_schema_version` | integer | required, must be `1` | Rejected with 400 if unsupported |
| `checkpoint_seq` | integer ≥ 1 | required | Device's proposal: `last_received_checkpoint_seq + 1`, or `1` if none. Optimistic-concurrency token — see §6 |
| `observed_at` | string | required | RFC3339-Z (§4.2). When the device *sampled* its head — distinct from the cloud's `issued_at` |
| `head` | object | required, never null | See below |
| `head.ledger_seq` | integer ≥ 1 | required | `audit_events.seq` of the tail row. `i64` in Rust |
| `head.entry_hash` | string | required | That row's `entry_hash` (§4.1 format) |
| `device_reported_chain_status` | object | required, never null | See below |
| `device_reported_chain_status.status` | string | required | `"valid"` \| `"diverged"` |
| `device_reported_chain_status.first_bad_ledger_seq` | integer or `null` | **key always present** | `null` iff `status == "valid"` |
| `device_reported_chain_status.divergence_kind` | string or `null` | **key always present** | `null` iff `status == "valid"` |

**Empty-ledger case:** a device with zero audit events **must not** POST. There is no head to attest. The cloud rejects `head.ledger_seq < 1` with 400. `fornax-core`'s submission task (`fornax-daemon`'s `audit_checkpoint_submit`) skips the cycle entirely rather than posting when the local ledger is empty.

### 2.3 `device_reported_chain_status` is self-reported and unverifiable

The name is deliberately long. It carries its own provenance so no reader mistakes it for a cloud finding.

> The cloud records this value verbatim into the signed payload and **does not, and cannot, verify it.** A checkpoint attests only *"at `issued_at`, this authenticated device claimed status X for head H"*. A compromised device can claim `"valid"` about a chain it has rewritten. This is the same trust boundary ADR-0011's addendum states for the local chain itself.

Its value is non-repudiation: the device's own claim is now countersigned and outside its control.

`divergence_kind` wire vocabulary — `DivergenceKind` in `fornax-store` derives only `Debug, Clone, Copy, PartialEq, Eq` (**no `Serialize`**), so a manual mapping function is required on the Rust side regardless. This table is that mapping, and is normative:

| Rust `DivergenceKind` variant | Wire string |
|---|---|
| `HashMismatch` | `"hash_mismatch"` |
| `MissingSeq` | `"missing_ledger_seq"` |
| `TruncatedTail` | `"truncated_tail"` |
| `RelinkedPrevHash` | `"relinked_prev_hash"` |

Note `MissingSeq` → `"missing_ledger_seq"`, not `"missing_seq"` — per §0.1's rule. The cloud treats `divergence_kind` as an **open string** (persist and re-emit any value verbatim, matching `models/audit_events.py`'s open-VARCHAR precedent), so a future Rust variant is forward-compatible. On the `fornax-core` side, this mapping lives as `fornax_types::divergence_kind_wire`'s named constants (`fornax-types/src/audit_checkpoint.rs`), consumed by `fornax-daemon`'s submission task, which owns the actual `match` over `fornax_store::DivergenceKind`.

---

## 3. Response shape — `SignedAuditCheckpoint` (HIGHEST-RISK SECTION)

### 3.1 The envelope

Structurally identical to `SignedRevocationList`, with only the version field renamed. The `signatures` array is **exactly what `policy/signing.py::sign()` already returns** — `[{"key_id", "algorithm", "signature_b64"}]` — so the cloud needs **zero new signature-shaping code**, and Rust reuses `BundleSignature` unchanged.

```json
{
  "checkpoint_schema_version": 1,
  "payload_b64": "<strict canonical base64 of the exact UTF-8 payload bytes>",
  "signatures": [
    {
      "key_id": "fornax-cloud-signing-2026-09",
      "algorithm": "ed25519",
      "signature_b64": "<base64 of 64 raw Ed25519 signature bytes>"
    }
  ]
}
```

Rust (`fornax-types/src/audit_checkpoint.rs`):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditCheckpoint {
    pub checkpoint_schema_version: u32,
    pub payload_b64: String,
    pub signatures: Vec<BundleSignature>,   // reused verbatim from bundle.rs
}
```

### 3.2 The payload (base64-decoded contents of `payload_b64`)

**Key order below is the wire order and is normative.** The cloud builds this dict in exactly this order; Rust declares the struct fields in exactly this order.

```json
{
  "checkpoint_schema_version": 1,
  "issuer": "fornax-cloud:7f3d1c2a-9b4e-4d80-a1f6-2c5e8d0b1234",
  "device_id": "d41d8cd9-8f00-4204-a980-0998ecf8427e",
  "checkpoint_seq": 1,
  "issued_at": "2026-09-03T12:00:05Z",
  "observed_at": "2026-09-03T12:00:00Z",
  "head": {
    "ledger_seq": 5,
    "entry_hash": "sha256:e967d0e31e6afd2a3a0f5bd805e39f85eb0eeb4e176e88e0e65d3c26a1cba464"
  },
  "device_reported_chain_status": {
    "status": "valid",
    "first_bad_ledger_seq": null,
    "divergence_kind": null
  },
  "prev_checkpoint": null
}
```

| Path | Type | Nullable | Notes |
|---|---|---|---|
| `checkpoint_schema_version` | integer | no | Must equal the envelope's — cross-checked (§3.4 step 7) |
| `issuer` | string | no | `f"fornax-cloud:{organization_id}"` — same construction as `RevocationPayload.issuer` |
| `device_id` | string | no | `ctx.device_id` verbatim. A device **must** check this equals its own |
| `checkpoint_seq` | integer | no | The accepted value; always equals the request's |
| `issued_at` | string | no | Cloud clock, RFC3339-Z |
| `observed_at` | string | no | Echoed verbatim from the request — the device's clock |
| `head` | object | **no — never null** | Echoed verbatim from the request |
| `head.ledger_seq` | integer | no | |
| `head.entry_hash` | string | no | |
| `device_reported_chain_status` | object | **no — never null** | Echoed verbatim |
| `device_reported_chain_status.status` | string | no | |
| `device_reported_chain_status.first_bad_ledger_seq` | integer | **yes** | Key always present |
| `device_reported_chain_status.divergence_kind` | string | **yes** | Key always present |
| `prev_checkpoint` | object | **yes** | `null` **iff `checkpoint_seq == 1`**. Key always present |
| `prev_checkpoint.checkpoint_seq` | integer | no | |
| `prev_checkpoint.head` | object | no | |
| `prev_checkpoint.head.ledger_seq` | integer | no | |
| `prev_checkpoint.head.entry_hash` | string | no | |

`prev_checkpoint` makes each receipt self-contained evidence that the cloud saw this device move from one head to another, without needing to fetch every prior receipt.

Rust (field order matches the table exactly):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpointPayload {
    pub checkpoint_schema_version: u32,
    pub issuer: String,
    pub device_id: String,
    pub checkpoint_seq: u64,
    pub issued_at: String,
    pub observed_at: String,
    pub head: LedgerHead,
    pub device_reported_chain_status: DeviceReportedChainStatus,
    pub prev_checkpoint: Option<PrevCheckpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerHead {
    pub ledger_seq: i64,
    pub entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReportedChainStatus {
    pub status: String,
    pub first_bad_ledger_seq: Option<i64>,
    pub divergence_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevCheckpoint {
    pub checkpoint_seq: u64,
    pub head: LedgerHead,
}
```

### 3.3 `deny_unknown_fields` + `Option` convention — both decided here, not inferred

Both conventions exist in this repo (`RevocationPayload` uses `deny_unknown_fields`; `AuditEvent` uses `#[serde(flatten)] unknown`). **This artifact uses `deny_unknown_fields` on every struct above**, matching the signed-artifact family (`SignedPolicyBundle`, `SignedRevocationList`, `BundlePayload`, `RevocationEntry`) rather than the audit-event family.

Standing consequence:

> Because every checkpoint struct is `deny_unknown_fields`, **adding any field to `AuditCheckpointPayload` or its nested objects is a breaking change** and requires bumping `checkpoint_schema_version` to `2` and adding it to `SUPPORTED_CHECKPOINT_SCHEMA_VERSIONS` on the Rust side *before* the cloud emits it. There is no additive-field path. This is the same fail-closed posture `bundle.rs` takes on unrecognized signature algorithms.

**`Option` fields: present-with-`null`, never omitted.** Every key in §3.2's table is emitted unconditionally.

- **Cloud:** builds the dict with every key literally present, exactly as `_entry_dict` emits `"audit_ref": None`. Never conditional key insertion.
- **Rust:** `Option<T>` with **no `#[serde(skip_serializing_if)]`** anywhere in this module — matching `RevocationEntry.audit_ref`/`superseded_by` and `canon.py`'s stated reasoning, and deliberately *not* `AuditEvent.correlation_id`'s `skip_serializing_if`. `serde_json` then emits `None` as explicit `null`.
- **Neither side may rely on serde's/Pydantic's implicit missing-`Option` tolerance.** A payload with an absent `prev_checkpoint` key is malformed even though `Option` would technically accept it.

### 3.4 Rust verification order (normative — mirrors `verify_revocation_list`)

`verify_audit_checkpoint(envelope_bytes, trusted, now) -> Result<VerifiedAuditCheckpoint, CheckpointRejection>`:

1. Parse `SignedAuditCheckpoint`.
2. `checkpoint_schema_version` ∈ `SUPPORTED_CHECKPOINT_SCHEMA_VERSIONS`.
3. Signature-count bounds, strict-decode `payload_b64`, and per-signature verification, all delegated to **`verify_signed_envelope(&payload_b64, &signatures, AUDIT_CHECKPOINT_SIGNING_DOMAIN, MAX_PAYLOAD_BYTES, trusted, now)`** — the same shared helper `verify_revocation_list` uses, parameterized by this module's own domain. This covers signature-count bounds, strict canonical base64 decode, size bound, key-id lookup, algorithm check, key validity window, and signature verification.
4. Parse `AuditCheckpointPayload` — **only now, post-authentication**.
5. Cross-check envelope vs payload `checkpoint_schema_version` → `SchemaVersionMismatch`.
6. Parse `issued_at` and `observed_at` as RFC3339 → `MalformedTimestamp { field, value }`.
7. Structural checks: `issuer` non-empty; `device_id` non-empty; `head.entry_hash` matches §4.1's regex; `head.ledger_seq >= 1`; `checkpoint_seq >= 1`; `prev_checkpoint.is_none() == (checkpoint_seq == 1)`; `device_reported_chain_status.status` ∈ `{"valid","diverged"}`; if `status == "valid"` then both `first_bad_ledger_seq` and `divergence_kind` are `None`, and if `"diverged"` then both are `Some`.
8. Construct `VerifiedAuditCheckpoint` (private fields, accessors only — `verify_audit_checkpoint` is the sole constructor, mirroring `VerifiedRevocationList`).

**No window check** — no `not_before`/`expires_at` exists on this artifact, by §1.1.

`fornax-core` implements this exactly as `fornax_types::audit_checkpoint::verify_audit_checkpoint`, reusing `verify_signed_envelope`/`BundleSignature`/`MAX_PAYLOAD_BYTES` from `policy::bundle` (that helper and its error type were widened from `pub(super)` to `pub(crate)` to make this cross-module reuse possible — no other change to `bundle.rs`/`revocation.rs`).

---

## 4. Pinned string formats

### 4.1 `entry_hash`

Produced by `compute_entry_hash`'s `format!("sha256:{hex}")` where `hex` comes from `format!("{b:02x}")` per byte. Therefore, byte-for-byte:

- literal ASCII prefix `sha256:` (7 bytes), then
- **exactly 64 lowercase hex characters** `[0-9a-f]`.

Total length **71**. Uppercase hex is invalid. Regex both sides validate against:

```
^sha256:[0-9a-f]{64}$
```

The genesis marker is `"sha256:" + "0"*64` (all-zero). It is a valid `entry_hash` *string* but can never legitimately be a checkpointed **head**, since a head is always a real appended row's hash. The cloud need not special-case it; the pattern check accepts it and §7's monotonicity rules handle it.

### 4.2 Timestamps

Exactly the output of the existing `_rfc3339_z` helper (present in both `routers/device_policy.py` and `routers/policy_revocations.py`):

```python
value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
```

Yielding `"2026-09-03T12:00:05Z"`: **seconds precision, no fractional part, literal trailing `Z`, never `+00:00`**. Rust emits the same shape for `observed_at` in the request (`chrono`'s `.format("%Y-%m-%dT%H:%M:%SZ")` on a `DateTime<Utc>`, **not** `to_rfc3339()`, which emits `+00:00`). Rust parsing uses `DateTime::parse_from_rfc3339` and therefore accepts both, but only ever *emits* the `Z` form.

### 4.3 Integer widths

`ledger_seq` is `i64` in Rust (`audit_events.seq` is a SQLite `INTEGER PRIMARY KEY`). The cloud column **must be `sa.BigInteger()`**, not `sa.Integer()` — note this differs from `PolicyRevocationArtifact.sequence`, which uses `sa.Integer()`. `checkpoint_seq` may be `sa.Integer()`.

---

## 5. Domain separation and canonicalization

### 5.1 The domain constant

```
b"fornax-audit-checkpoint/v1\n"
```

**27 bytes**, terminated by a single LF (`0x0A`).

**Definition sites:**

- **Rust:** `crates/fornax-types/src/audit_checkpoint.rs` (registered in `lib.rs`'s `pub mod` list and re-exported). It belongs in `fornax-types`, **not** `fornax-store`, per `audit_ledger.rs`'s own stated rule: wire-crossing signing domains live alongside the artifacts that cross the wire; `AUDIT_LEDGER_DOMAIN` stays in `fornax-store` precisely because it is local-storage-only.
- **Python:** `backend/src/fornax_cloud_backend/policy/signing.py`, as a module-level constant beside `REVOCATION_SIGNING_DOMAIN`.

**Both files must contain the identical 27-byte sequence.**

**Required test** (Rust side, present in `audit_checkpoint.rs`'s test module):

```rust
#[test]
fn checkpoint_domain_matches_adr_0012_literal_bytes() {
    assert_eq!(AUDIT_CHECKPOINT_SIGNING_DOMAIN, b"fornax-audit-checkpoint/v1\n");
    assert_eq!(AUDIT_CHECKPOINT_SIGNING_DOMAIN.len(), 27);
    assert_eq!(*AUDIT_CHECKPOINT_SIGNING_DOMAIN.last().unwrap(), b'\n');
    assert_ne!(AUDIT_CHECKPOINT_SIGNING_DOMAIN, BUNDLE_SIGNING_DOMAIN);
    assert_ne!(AUDIT_CHECKPOINT_SIGNING_DOMAIN, REVOCATION_SIGNING_DOMAIN);
}
```

Rust additionally has a **domain-confusion rejection test**: a payload signed under `REVOCATION_SIGNING_DOMAIN` but presented as a `SignedAuditCheckpoint` fails with `SignatureInvalid`, mirroring `revocation.rs`'s existing domain-separation tests.

### 5.2 Canonicalization — one method, no re-derivation

**The signed message is `AUDIT_CHECKPOINT_SIGNING_DOMAIN ‖ payload_bytes`**, where `payload_bytes` is the raw base64-decode of `payload_b64` — never the payload alone, never a re-serialization.

**Rust never re-serializes to reconstruct signed bytes.** It verifies over the bytes it received, exactly as `bundle.rs` mandates ("Sign the transmitted bytes verbatim"). Python is the sole producer; Rust is only ever the verifier. This eliminates the entire `json.dumps`-vs-`serde_json` divergence class for the signed artifact.

`payload_b64` is **strict canonical base64**: standard alphabet, required padding, no trailing bits (`bundle.rs::strict_base64`).

**Golden vectors (independently re-verified against this implementation's own serialization):**

For the exact JSON payload object shown in §3.2 above, serialized as compact JSON (no whitespace, keys in the exact order shown):
- `len(payload_bytes)` = **469**
- `SHA-256(payload_bytes)` = `sha256:77bb07ff65394e758255e34214e50c29500af0b44fc649889adcab1df2bf579c`
- `SHA-256(AUDIT_CHECKPOINT_SIGNING_DOMAIN ‖ payload_bytes)` = `sha256:d378934c57fd4fce5b51224e6a5d8272692274ebf8fc09928b04d3c1e7074625`
- The exact `payload_b64` for this object: `eyJjaGVja3BvaW50X3NjaGVtYV92ZXJzaW9uIjoxLCJpc3N1ZXIiOiJmb3JuYXgtY2xvdWQ6N2YzZDFjMmEtOWI0ZS00ZDgwLWExZjYtMmM1ZThkMGIxMjM0IiwiZGV2aWNlX2lkIjoiZDQxZDhjZDktOGYwMC00MjA0LWE5ODAtMDk5OGVjZjg0MjdlIiwiY2hlY2twb2ludF9zZXEiOjEsImlzc3VlZF9hdCI6IjIwMjYtMDktMDNUMTI6MDA6MDVaIiwib2JzZXJ2ZWRfYXQiOiIyMDI2LTA5LTAzVDEyOjAwOjAwWiIsImhlYWQiOnsibGVkZ2VyX3NlcSI6NSwiZW50cnlfaGFzaCI6InNoYTI1NjplOTY3ZDBlMzFlNmFmZDJhM2EwZjViZDgwNWUzOWY4NWViMGVlYjRlMTc2ZTg4ZTBlNjVkM2MyNmExY2JhNDY0In0sImRldmljZV9yZXBvcnRlZF9jaGFpbl9zdGF0dXMiOnsic3RhdHVzIjoidmFsaWQiLCJmaXJzdF9iYWRfbGVkZ2VyX3NlcSI6bnVsbCwiZGl2ZXJnZW5jZV9raW5kIjpudWxsfSwicHJldl9jaGVja3BvaW50IjpudWxsfQ==`

`fornax-types/src/audit_checkpoint.rs`'s test module asserts the Rust `AuditCheckpointPayload` struct, when serialized per this spec, produces exactly these bytes/hash/base64 for this exact input, and separately verifies the same golden `payload_b64` end-to-end through `verify_audit_checkpoint`. This is the primary cross-repo correctness check — if the `fornax-cloud` implementer's output matches these same vectors independently, byte-level agreement between the two repos is proven without either side needing the other's code.

---

## 6. Sequence space disjointness

**`checkpoint_seq` is a counter scoped per `(organization_id, device_id)`, starting at 1, strictly increasing by exactly 1.** This is a cloud-side concept — `fornax-core` never allocates it, it only ever receives it back in responses and echoes/validates it locally against what it last received.

Local ledger: `crates/fornax-store/migrations/0012_audit_checkpoints.sql` (see "Migration numbering note" above for why `0012`, not `0011`).

---

## 7. Cloud-side validation and error shapes

(This section governs the `fornax-cloud` implementation; included here so `fornax-core` understands what responses to expect.)

### 7.1 The monotonicity table

Let `last` be the highest-`checkpoint_seq` row for this `(organization_id, device_id)`, and `new` the request's `head`.

| Case | Condition | Result |
|---|---|---|
| 1 | `new.ledger_seq < last.head_ledger_seq` | **409** — head regression |
| 2 | `new.ledger_seq == last.head_ledger_seq` **and** `new.entry_hash != last.head_entry_hash` | **409** — same slot, contradictory content |
| 3 | `new.ledger_seq == last.head_ledger_seq` **and** `new.entry_hash == last.head_entry_hash` | **201** — legitimate re-attestation, no new events |
| 4 | `new.ledger_seq > last.head_ledger_seq` | **201** — accepted; no hash relationship is checkable, by design |

If there is **no** `last` row (bootstrap), skip this table entirely and accept.

### 7.2 Error responses

All bodies are FastAPI's standard `{"detail": "<string>"}`. **No `detail` string may contain the bare token `seq`** (§0.1).

| Condition | Status | `detail` |
|---|---|---|
| `ctx.device_id is None` | **401** | `device identity not resolved` |
| `checkpoint_schema_version` unsupported | **400** | `unsupported checkpoint_schema_version` |
| `head.entry_hash` fails `^sha256:[0-9a-f]{64}$` | **400** | `head.entry_hash is malformed` |
| `head.ledger_seq < 1` | **400** | `head.ledger_seq must be at least 1` |
| `status`/`first_bad_ledger_seq`/`divergence_kind` mutually inconsistent (§2.2) | **400** | `device_reported_chain_status is internally inconsistent` |
| `checkpoint_seq != last_known_checkpoint_seq + 1` | **409** | `checkpoint_seq must be exactly one greater than the last accepted checkpoint for this device` |
| Head regression (case 1) | **409** | `head.ledger_seq is lower than the last checkpointed head for this device` |
| Contradictory head at same position (case 2) | **409** | `head.entry_hash contradicts the last checkpointed head at the same head.ledger_seq` |
| Signing key unavailable | **503** | `policy signing is not configured` |
| Unique-constraint race | **409** | same string as the `checkpoint_seq` row above |

### 7.4 Read-back route (for recovery)

```
GET /v1/devices/me/audit-checkpoints/latest      -> envelope verbatim, or 404
GET /v1/devices/me/audit-checkpoints/{checkpoint_seq} -> envelope verbatim, or 404
```

`fornax-core` does not yet call this route (no local gap requiring recovery has been observed in practice); it is documented here for completeness and for a future ticket to wire up if needed.

---

## 8. Device-side divergence detection (fornax-core)

### 8.1 What the device stores

The device persists each verified `SignedAuditCheckpoint` locally (`fornax-store` migration `0012_audit_checkpoints.sql`, table `audit_checkpoints`): `checkpoint_seq`, `head_ledger_seq`, `head_entry_hash`, `issued_at`, and the verbatim envelope JSON. **A stored receipt is only ever written after `verify_audit_checkpoint` returns `Ok`** — never from an unverified response (`Store::store_audit_checkpoint_receipt`).

Local receipt storage is *not* the trust anchor (an attacker with SQLite access can delete it). The cloud copy is, recoverable via §7.4.

### 8.2 The exact comparison

Inputs: (a) `Store::verify_audit_chain() -> ChainVerification`, run once; (b) for a stored receipt `R`, the row currently in `audit_events` at `seq == R.head_ledger_seq`, if any.

Evaluated **in this order**, per receipt, most-severe first (`fornax_store::audit_checkpoint::evaluate_checkpoint_consistency`):

| # | Condition | Verdict |
|---|---|---|
| 1 | `ChainVerification::Diverged { first_bad_seq, kind }` **and** `first_bad_seq <= R.head_ledger_seq` | **`AttestedPrefixCorrupted { first_bad_ledger_seq: first_bad_seq, kind }`** — the corruption lies *inside* the range the cloud already witnessed. Strongest finding. |
| 2 | `ChainVerification::Diverged { first_bad_seq, kind }` **and** `first_bad_seq > R.head_ledger_seq` | **`DivergedAfterAnchor { first_bad_ledger_seq: first_bad_seq, kind }`** — attested prefix intact; damage is later. |
| 3 | `Valid` **and** no row exists at `seq == R.head_ledger_seq` | **`AnchorMissing`** — the ledger was truncated past a point the cloud witnessed. |
| 4 | `Valid` **and** row exists **and** `row.entry_hash != R.head_entry_hash` | **`AnchorRewritten { attested: R.head_entry_hash, found: row.entry_hash }`** — history rewritten at the exact anchored position. |
| 5 | `Valid` **and** row exists **and** `row.entry_hash == R.head_entry_hash` | **`Consistent`** — the only consistent verdict. |

Notes:

- Comparison in rows 4/5 is **exact string equality** on the full `"sha256:<64 lowercase hex>"` value, including the `sha256:` prefix.
- Row 1's `<=` is deliberate and inclusive: a corruption *at* `R.head_ledger_seq` itself is inside the attested range.
- Rows 1 and 2 use only `ChainVerification`; they do **not** additionally require the row lookup. Rows 3–5 apply only when the chain is `Valid`.
- `Store::evaluate_all_checkpoint_receipts` runs this comparison for every stored receipt against one shared `verify_audit_chain()` call, and is invoked by `fornax-daemon`'s checkpoint-submission cycle (`audit_checkpoint_submit`) before each new submission.
- The device also confirms `payload.head` equals what it submitted (`fornax-daemon`'s submission path checks this before storing a receipt) — a response that does not echo the submitted head is refused and never stored. `payload.device_id` is likewise cross-checked, but against a locally-bootstrapped anchor rather than independent config: `fornax-core` has no separate source of its own `device_id` outside the checkpoint flow itself, so the FIRST receipt a device ever stores (`Store::first_audit_checkpoint_receipt`) becomes that anchor, and every subsequent response's `device_id` must match it exactly or is refused and never stored. The one residual gap this cannot close: the very first receipt has nothing to check against and is trusted on first use (TOFU) — a compromise of the very first checkpoint response would poison the anchor. This is a narrower, already-scoped instance of the same "the endpoint itself could be compromised" caveat §1 already states for the whole mechanism, not a new one.
- The device still submits a new checkpoint even when a prior receipt's verdict is not `Consistent`, with `device_reported_chain_status.status` reflecting the CURRENT chain's own `ChainVerification` result (see `audit_checkpoint_submit`'s module doc for why this field is derived from `verify_audit_chain` directly rather than from this per-receipt comparison) — suppressing the report would hide the divergence from the only external witness.

---

## 11. Implementation boundaries (fornax-core)

**In scope, implemented:** `crates/fornax-types/src/audit_checkpoint.rs` (constants, `SignedAuditCheckpoint`, `AuditCheckpointPayload`, `LedgerHead`, `DeviceReportedChainStatus`, `PrevCheckpoint`, `VerifiedAuditCheckpoint`, `CheckpointRejection`, `verify_audit_checkpoint`, `divergence_kind_wire`); `lib.rs` module registration + re-exports; `crates/fornax-store/migrations/0012_audit_checkpoints.sql` + receipt persistence (`Store::store_audit_checkpoint_receipt`/`audit_checkpoint_receipts`/`latest_audit_checkpoint_receipt`) and the §8.2 comparison (`evaluate_checkpoint_consistency`/`Store::evaluate_all_checkpoint_receipts`); the `DivergenceKind` → wire-string mapping (§2.3); client submission path (`fornax-daemon`'s `audit_checkpoint_submit` module) — an HTTP client call to `POST /v1/devices/me/audit-checkpoints`, gated on `fornax_types::privacy::cloud_sync_allowed()`, best-effort/async per D2 — a failed submission never blocks or fails local evidence capture.

**Explicitly out of scope, untouched:** `audit_ledger.rs`'s hashing, `AUDIT_LEDGER_DOMAIN`, `compute_entry_hash`, `verify_audit_chain`, and the `0010` migration. Any signing key. Any change to `bundle.rs`/`revocation.rs` beyond *using* `verify_signed_envelope`, `BundleSignature`, `MAX_PAYLOAD_BYTES` (and widening `verify_signed_envelope`/`EnvelopeVerificationError`/`VerifiedEnvelope` from `pub(super)` to `pub(crate)` so `audit_checkpoint.rs`, a top-level sibling of `policy`, could reuse them — no behavioral change).
