# Agent Evidence Protocol — threat model

Jira: [FORNX-391](https://lightning-dust-mite.atlassian.net/browse/FORNX-391) scope item:
"threat model for parser abuse, schema downgrade, signature confusion,
dependency forgery and unsafe remote reference resolution."

Scope: `crates/fornax-protocol`, `crates/fornax-protocol-refclient`, and any
future implementation built against `docs/protocol/agent-evidence-protocol.md`.
Attacker model: an untrusted producer of protocol messages, or an
on-path party able to modify bytes in transit, targeting a consumer that
decodes and acts on those messages.

## Parser abuse

**Threat.** A malicious message causes excessive resource consumption
(deeply nested JSON, huge strings/arrays) or a parser crash/panic in a
consumer, potentially denying service or forcing an unsafe fallback.

**Mitigation.** `serde_json`'s recursion limit (128 levels by default,
compiled into the library both `fornax-protocol` and
`fornax-protocol-refclient` use) rejects pathologically nested input before
[`canonicalize`](../../crates/fornax-protocol/src/canonical.rs) ever
recurses over it — [`canonicalize`] itself recurses once per nesting level
already present in a successfully-parsed `Value`, so it cannot be driven
deeper than whatever `serde_json` already accepted. No unbounded
allocation before a size/depth check: `serde_json::from_slice` streams the
input directly. **Residual risk, disclosed rather than silently accepted:**
this crate does not itself impose an additional payload-size ceiling beyond
what the calling process's own memory limits enforce — a caller embedding
this in a resource-constrained or shared-tenant consumer should impose its
own byte-length check on `bytes` *before* calling `decode_envelope`, the
same way `fornax_receipt::schema::MAX_FINGERPRINTED_PAYLOAD_BYTES` bounds a
different, unrelated payload class in this repo.

## Schema downgrade

**Threat.** A malicious or compromised producer declares an older
`protocol_version` than it actually used, to have the consumer apply an
older (potentially weaker) verification path, hoping the consumer applies
the newer message's assumptions under the older version's laxer rules.

**Mitigation.** `protocol_version` is checked as the very first step of
`decode_envelope`, before anything about `payload` is interpreted — there
is no code path that reads `object_schema_version` or `capabilities` under
one version's rules while treating `payload` as though it were produced
under a different version. Each supported version's own conformance
fixtures (`fornax_protocol::conformance`) are specific to that version's
rules; there is no shared "best current understanding" applied
irrespective of the declared version. Widening
`SUPPORTED_PROTOCOL_VERSIONS` is a reviewed change (see the compatibility
policy doc), not an automatic acceptance of anything a producer claims.

## Signature confusion

**Threat.** A consumer mistakes an unsigned message for an authenticated
one, or a message signed for one purpose/domain for one signed for
another.

**Mitigation.** This protocol version carries **no signature scheme of its
own** — `payload_digest` is a tamper-evidence digest (proves the bytes were
not altered after sealing), never an authentication signature (proves who
sealed them). This is a deliberate, disclosed limitation, matching
`fornax-receipt`'s own explicit "verification-only, unsigned by default"
posture (see `fornax_receipt::verify::SignatureStatus::Unsigned`'s doc
comment) — never silently upgraded to imply authenticity. Should a future
protocol version add signing, `docs/protocol/agent-evidence-protocol.md`
must document the exact signing domain (what bytes are signed, under what
key-derivation/algorithm) so a signature cannot be replayed across domains
— tracked as a real gap for that future version, not solved here.

## Dependency forgery

**Threat.** A message claims to depend on or reference a contract, policy,
or claim class by name in a way that resolves differently depending on
mutable local state, letting an attacker redirect a reference to something
other than what the producer intended.

**Mitigation.** Every reference in the wrapped `DelegationEnvelope` payload
is by explicit, versioned identity (`ClaimClassId { name, version }`), never
by a bare name resolved against a mutable registry at verification time —
this is inherited unchanged from `fornax_types::epistemic_contract`'s own
design (FORNX-377) and `fornax_receipt::delegation`'s scope binding
(FORNX-384), not something this protocol layer weakens or re-derives.

## Unsafe remote reference resolution

**Threat.** A message contains a URL or other remote pointer that, if a
consumer naively fetches it (e.g. to "resolve" a reference), enables SSRF,
data exfiltration, or supply-chain-style injection of attacker-controlled
content into the verification path.

**Mitigation.** This protocol version's schema carries **no fetchable
remote reference at all** — closed by design, not mitigated live. There is
no field anywhere in `ProtocolEnvelope` or the wrapped `DelegationEnvelope`
shaped like a URL, and no code in `fornax-protocol` or
`fornax-protocol-refclient` ever performs a network call while decoding or
verifying a message. See
`no_protocol_type_carries_a_url_shaped_field` in
`crates/fornax-protocol/tests/two_independent_implementations.rs` for a
literal, structural test of this claim over the wire JSON shape. A future
version that *does* add a remote-resolvable reference must define an
explicit allowlist/fetch-authorization model before doing so — tracked as
a future concern, not a present gap.
