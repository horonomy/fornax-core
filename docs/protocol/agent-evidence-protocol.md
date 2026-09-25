# Agent Evidence Protocol — wire specification v1

Jira: [FORNX-391](https://lightning-dust-mite.atlassian.net/browse/FORNX-391), parent epic
[FORNX-376](https://lightning-dust-mite.atlassian.net/browse/FORNX-376) (Stage 9).

This document is the public material an independent implementation is built
from — see `crates/fornax-protocol-refclient`, which implements everything
below with zero dependency on `fornax-protocol`'s Rust types (FORNX-391 AC1).

## What this is, and isn't

The Agent Evidence Protocol is a vendor-neutral wire format for exchanging
one Fornax trust-kernel object — today, a proof-carrying delegation result
— between two parties that do not share a Rust codebase. It is **not**:

- A transport protocol. These are plain bytes; how they travel (a file, a
  local Unix socket, an HTTP body, a message-bus payload) is entirely up to
  the two parties.
- A claim of formal standardization. No standards-body process has
  reviewed this; "protocol" here means "documented, versioned wire format,"
  nothing more, until external adoption changes that.
- A proof that the wrapped claim is semantically true. See
  [Authenticity vs. semantic truth](#authenticity-vs-semantic-truth) below.

## Envelope shape

```json
{
  "protocol_version": 1,
  "object_kind": "delegation_result",
  "object_schema_version": 1,
  "issued_at": "2026-09-25T00:11:00Z",
  "not_after": "2026-09-25T01:11:00Z",
  "capabilities": [],
  "payload": { "...": "the wrapped object's own wire form" },
  "payload_digest": "sha256:<hex>"
}
```

| Field | Type | Meaning |
|---|---|---|
| `protocol_version` | u32 | Must be in the implementation's supported range (v1: `1..=1`). Any other value is a hard rejection — never a best-effort parse. |
| `object_kind` | string enum | `"delegation_result"`, `"integrity_receipt"`, or `"assurance_case"`. An unrecognized value is a hard rejection. |
| `object_schema_version` | u32 | The wrapped object's own internal schema version (e.g. `DELEGATION_SCHEMA_VERSION`) — informational for a consumer that understands `object_kind` but wants to check the inner shape before deserializing. |
| `issued_at` / `not_after` | RFC 3339 string | Freshness window. `not_after` absent means "no declared expiry" — a consumer's own policy decides whether that is acceptable, exactly as `fornax_receipt::freshness` already treats an absent `not_after` as its own explicit state, never "fresh forever" by default. |
| `capabilities` | array of string enum | Optional semantics this payload relies on (see [Capability negotiation](#capability-negotiation)). Empty means none. |
| `payload` | JSON object | The wrapped object's own wire form, unmodified. |
| `payload_digest` | string | `"sha256:" + hex(sha256(canonical_json(payload)))` — see [Canonical JSON](#canonical-json-not-struct-order) below. This is the *only* digest a cross-implementation consumer needs to reproduce to detect payload tampering at the envelope level. |
| *(any other top-level key)* | any | An **unknown field**. Never rejected, never silently dropped by a conforming implementation — see [Forward/backward compatibility](#forwardbackward-compatibility). |

## Canonical JSON, not struct order

Every internal Fornax wire type in this repo (`ReceiptBody`,
`DelegationEnvelopeBody`, ...) computes its own tamper-evidence digest over
`serde_json::to_vec(&typed_struct)`. That is deterministic *within this
Rust codebase* because serde's derive macro serializes struct fields in
declaration order — but it is not something a second implementation, in
any language, can reproduce without first learning that exact field order
from the source, which defeats the point of a public specification.

`payload_digest` uses a different, genuinely portable scheme instead:

1. Recursively sort every JSON object's keys, at every nesting level.
2. Serialize with no insignificant whitespace.
3. `sha256` the resulting bytes; encode as lowercase hex; prefix `"sha256:"`.

Any implementation that does step 1 correctly gets byte-identical output
for structurally-equal JSON, regardless of what order the keys arrived in
on the wire. This is the *only* digest scheme a cross-implementation
consumer needs — it never needs to know how `fornax-protocol`'s Rust types
happen to be declared.

(Objects wrapped inside `payload` — a `DelegationEnvelope`, say — may carry
*their own*, additional, Rust-struct-order-dependent digest internally.
That inner digest remains meaningful only to an implementation that shares
the producer's typed schema; it is a stricter, additional check available
to a same-language consumer, never a substitute for `payload_digest` at the
protocol layer.)

## Authenticity vs. semantic truth

A successful `decode_envelope` (protocol version supported, digest matches)
means exactly this: **the bytes you received are the bytes that were
sealed, and you understand the envelope's version.** It says nothing about
whether the wrapped claim, finding, or delegation outcome is *true*. A
perfectly valid, unaltered envelope can wrap a delegation whose outcome is
`insufficient` or `unavailable` — decoding it successfully is not an
endorsement of the underlying result, only proof that you are looking at
what the producer actually sent. This mirrors every other layer in this
repo's own discipline (`fornax_receipt`'s own module docs: "receipt
authenticity/integrity never proves the underlying semantic claim is true
beyond the evidence represented").

## Forward/backward compatibility

- **Unknown top-level fields** are preserved, never dropped. A consumer
  reading a message from a producer using a *newer, but still supported*
  `protocol_version` may see fields it does not recognize; it must keep
  them available for inspection (round-tripping decode → re-encode must not
  lose them) rather than silently discarding them.
- **An unsupported `protocol_version`** is a hard rejection with a typed
  reason, never a best-effort parse of a version the implementation was not
  built to understand. Widening `SUPPORTED_PROTOCOL_VERSIONS` is itself a
  reviewed protocol change — see `agent-evidence-protocol-compatibility-policy.md`.
- **An unrecognized `object_kind`** is likewise a hard rejection, never
  treated as one of the known kinds by best-effort guessing.

## Capability negotiation

Some payload semantics only make sense to a consumer that implements a
specific, later-added concept — for example, a delegation whose
independence reasoning depends on
`fornax_receipt::multi_agent::MultiAgentSignal` (FORNX-385). The `capabilities`
array names every such optional semantic the payload actually relies on.
A consumer checks the declared list against what it implements
(`missing_capabilities`); a non-empty result means "I can verify this
envelope's authenticity, but I cannot correctly interpret everything its
payload means" — an explicit, typed signal, never a silent misreading.

## Object kinds

### `delegation_result`

Wraps a `fornax_receipt::delegation::DelegationEnvelope` verbatim as
`payload`. See `crates/fornax-receipt/src/delegation.rs`'s own module docs
for that object's full shape and tamper-evidence contract. This is the
"representative proof-carrying delegation/result" this protocol's own
conformance suite and cross-implementation test build against.

### `integrity_receipt` / `assurance_case`

Declared for schema completeness (a bare receipt or assurance case not
wrapped in a delegation). Not exercised by this version's cross-implementation
proof, which uses `delegation_result` specifically.

## Security notes

See `docs/security/agent-evidence-protocol-threat-model.md` for the full
threat model (parser abuse, schema downgrade, signature confusion,
dependency forgery, unsafe remote reference resolution).
