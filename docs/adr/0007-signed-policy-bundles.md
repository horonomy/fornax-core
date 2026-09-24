# ADR 0007: Signed policy bundles

Status: Accepted
Date: 2026-09-03
Jira: FORNX-118 (child of FORNX-69)

## Context

FORNX-116 (ADR-0006) defined policy as immutable, digested data
(`PublishedPolicyRevision` + `PolicyBinding`), but a digest alone proves
nothing about *who* published a revision — anything that can write bytes to
the local cache can forge a `PolicyRevisionBody` whose digest matches
itself. This ADR adds signature verification on top of that model: a
[`SignedPolicyBundle`] is the wire envelope `fornax-cloud` (out of scope
here) produces; `fornax-core` verifies it against a locally-trusted key set
before any revision or binding inside it is trusted.

## Decision

### Trust boundary

`fornax-core` — this crate and everything that depends on it — only ever
**verifies**. There is no signing key, no `Signer` implementation, and no
key-generation code in `bundle.rs`'s non-test paths; `verify_bundle` is a
pure function over untrusted bytes plus a locally-supplied trust store.

**How far this is mechanically enforced, and how far it is not (a real
deviation from this ticket's original design).** The design that kicked off
this ticket assumed `ed25519-dalek 3.0.0`'s signing capability (`SigningKey`,
the `Signer` impl) lived behind a Cargo feature named `signature`, so
depending on the crate with `default-features = false` in `[dependencies]`
and enabling `features = ["signature"]` only in `[dev-dependencies]` would
make "this crate cannot sign" a compile-time, dependency-level guarantee.
That assumption does not hold against the real crate: `ed25519-dalek`
does have an optional dependency literally named `signature`, but it gates
only the prehashed (`Ed25519ph`/`digest`) signing path, not the ordinary
`Signer for SigningKey` implementation — that impl uses `ed25519::signature`
re-exported through the always-required `ed25519` crate, and is compiled in
unconditionally regardless of feature flags. Verified empirically: a
minimal crate depending on `ed25519-dalek = { version = "3",
default-features = false }` with no dev-only feature at all still signs and
verifies successfully. There is no way to strip `SigningKey`/`Signer` out
of the dependency tree via Cargo features in this crate version.

Given that, the trust boundary here is enforced by **code convention, not
the compiler**: `bundle.rs`'s non-test code never imports `SigningKey` or
`Signer`, and the only place either name appears in this crate is
`policy/tests.rs`, under `#[cfg(test)]`, for fixture generation. This is a
weaker guarantee than the original design intended, and worth stating
plainly rather than implying a compiler-enforced boundary that does not
actually exist. `fornax-types/Cargo.toml` still declares
`ed25519-dalek.workspace = true` with `default-features = false` in
`[dependencies]` only (no separate `[dev-dependencies]` entry, since one
would have implied a distinction that provides no actual isolation) —
`default-features = false` still matters for skipping the `fast`/`zeroize`
features (performance and secret-zeroing conveniences irrelevant to a
verify-only crate that never generates or stores a private key).

### D1: sign the transmitted bytes verbatim

The envelope's `payload_b64` is the *exact* base64 the signature covers.
`verify_bundle` never re-serializes a parsed `BundlePayload` to reconstruct
signed bytes. `fornax-cloud` (Python, `json.dumps`) is the producer;
`fornax-core` (Rust, `serde_json`) is only ever the verifier. Re-serializing
before checking a signature risks two independent JSON serializers
producing different byte sequences for semantically identical data —
silently breaking verification of a legitimate bundle, or worse, silently
accepting a payload the signer never actually signed if the two
serializations happened to both parse to the same signature check target
through some other path. Signing and verifying the transmitted bytes
directly makes this divergence impossible by construction.

### D2: verify-then-parse

The envelope (`SignedPolicyBundle`) is intentionally minimal: a schema
version, a base64 payload, and a signature list — no nested types, no
timestamps read before a signature has been checked. `MAX_PAYLOAD_BYTES`
(1 MiB) and `MAX_SIGNATURES` (8) bound the pre-authentication work an
attacker can force onto this path before any cryptographic check occurs.
`BundlePayload` — the authenticated content, including the full
`PublishedPolicyRevision` and its `PolicyBinding`s — is parsed only after
a signature has verified successfully (evaluation order below).

### D3: trust fails closed — inverting ADR-0006's fail-open selector rule

An unrecognized `SignatureAlgorithm` is **always** a rejection
(`UnsupportedAlgorithm`), for both the signature entry's own algorithm and
the trusted key's algorithm. This is a deliberate inversion of ADR-0006's
"an unrecognized selector value still matches" rule
(`TargetSelector::matches`'s `SelectorNotUnderstood` path). The two rules
optimize for opposite failure directions on purpose:

- **Policy application fails open** (ADR-0006): an admin policy binding you
  can't fully parse should still apply rather than silently vanish —
  silently *not* enforcing a policy nobody knows failed to apply is the
  unsafe direction there.
- **Trust decisions fail closed** (this ADR): an algorithm this binary
  doesn't recognize must never be treated as an accepted signature —
  silently accepting an unrecognized algorithm as "probably fine" is the
  unsafe direction here. There is no data-integrity case for "apply
  anyway" when the question is literally "was this authenticated."

### D4: rotation via pre-distribution + multi-signature, no self-updating trust root

A bundle may carry more than one signature (up to `MAX_SIGNATURES`); any
one signature that verifies against a currently-valid trusted key is
sufficient (threshold 1). Key rotation works by a publisher signing with
both the outgoing and incoming key during an overlap window, while
operators roll `TrustedVerificationKeys` forward at their own pace — a
verifier trusting only the old key, only the new key, or both, all accept
the same bundle during that window.

**Explicit non-goal**: no self-updating trust root, no fetch-and-refresh of
trusted keys over the network, no TUF-style delegation chain. The trust
root is static configuration only — a compiled-in default, an operator
file, or an environment override — resolved and loaded entirely locally,
consistent with ADR-0001 D2 (no cloud dependency on the local critical
path). `TrustedVerificationKeys::load` never performs I/O itself; it
parses and validates a string a caller already obtained.

### D5: clock skew asymmetry

`CLOCK_SKEW_TOLERANCE_SECONDS` (300s) applies to `not_before` only: a
bundle is accepted up to 5 minutes before its stated `not_before`. It does
**not** apply to `expires_at` — expiry is exact, no grace period, at all.
This asymmetry is visible in the rejection vocabulary itself:
`BundleNotYetValid` carries a `tolerance_seconds` field; `BundleExpired`
does not, by construction, so a caller can't accidentally reason about a
grace period that isn't there. The rationale: undershooting `not_before` by
a few minutes of clock skew just delays when a legitimately-issued bundle
takes effect (harmless); overshooting `expires_at` by even a few minutes
means running expired policy past the point its issuer decided it should
stop applying, which especially matters for a bundle that *loosens*
restrictions and was deliberately given a short lifetime for that reason.

`now: DateTime<Utc>` is a parameter to `verify_bundle`, never `Utc::now()`
internally — the same discipline `PolicyDraft::publish`'s `published_at`
parameter already established in ADR-0006, for the same reason:
deterministic, reproducible tests, and no hidden wall-clock dependency in a
security-relevant check.

### D6: the inner revision digest is a liveness check, not a security control here — and a cross-repo canonicalization hazard

`BundlePayload.revision` is a full `PublishedPolicyRevision`, which
revalidates its own digest via its existing `TryFrom<PolicyRevisionWire>`
(ADR-0006) the moment `serde_json::from_slice::<BundlePayload>` runs.
`verify_bundle` additionally checks that every binding's
`revision_ref.digest` equals `revision.digest()`
(`BindingRevisionMismatch`). Both checks catch a bundle that is internally
inconsistent or was tampered with *before* signing (which would already
fail the outer signature check) or corrupted in a way that happens to
survive JSON parsing but not digest recomputation — they are a
belt-and-suspenders correctness/liveness check, not what makes this bundle
trustworthy. The signature is what makes it trustworthy; the digest check
only proves the payload the signer signed is *internally* self-consistent.

This matters because `canonical_bytes` (ADR-0006) is `serde_json::to_vec`
on the typed Rust struct, and its exact byte layout depends on collection
ordering that is a property of the *Rust* type definitions, not something
visible in the JSON schema alone:

- `PolicyContent::pinned_fields` (a `BTreeSet<PolicyFieldId>`) sorts by
  `PolicyFieldId`'s **enum declaration order**, not alphabetically.
- `EnforcementRule` lists sort by `ActionClass`'s **enum declaration
  order** (enforced at publish time by `PolicyDraft::publish`).
- `SensorScope::required_signals` sorts by `SignalClass`'s **wire-tag
  string** (`signal_class_sort_key`), because `SignalClass` has no `Ord`.
- `CacheScope::max_age_seconds_by_risk` (`RiskClassSeconds`) is a
  fixed-field struct, not a map, so its four fields serialize in
  **declaration order**, not `RiskClass`'s own enum order (the two happen
  to coincide today; nothing enforces they must).

`fornax-cloud`'s Python producer must reproduce every one of these
orderings exactly, or a revision it signs will digest-mismatch on the Rust
side despite being semantically identical. The frozen fixture
(`tests/fixtures/signed_policy_bundle_v1.json`) is the executable contract
for this — `fornax-cloud`'s own test suite should assert it can reproduce
this exact fixture's `canonical_bytes` given equivalent input, not just
that its output "looks like" the schema.

## Wire types

```
SignedPolicyBundle { bundle_schema_version: u32, payload_b64: String, signatures: Vec<BundleSignature> }
BundleSignature    { key_id: KeyId, algorithm: SignatureAlgorithm, signature_b64: String }
BundlePayload      { bundle_schema_version, bundle_id: Uuid, sequence: u64, issued_at, not_before,
                      expires_at: String, provenance: BundleProvenance,
                      revision: PublishedPolicyRevision, bindings: Vec<PolicyBinding> }
TrustedKey                 { key_id, algorithm, public_key_b64: String, not_before, not_after, comment }
TrustedVerificationKeys    { schema_version: u32, keys: Vec<TrustedKey> }
VerifiedPolicyBundle       -- private fields, accessors only; verify_bundle is the sole constructor
```

Base64 throughout is strict canonical: standard alphabet, required padding,
non-canonical trailing bits rejected — `base64::engine::GeneralPurposeConfig`
with `DecodePaddingMode::RequireCanonical` and
`with_decode_allow_trailing_bits(false)`. An attacker-controlled string must
decode exactly one way or be rejected outright, never interpreted leniently.

The signed message is `BUNDLE_SIGNING_DOMAIN` (`b"fornax-policy-bundle/v1\n"`)
concatenated with the raw decoded payload bytes — domain separation so a
signature produced for this purpose can never be replayed as a valid
signature over some unrelated message an issuer's key might also sign.

## `verify_bundle` evaluation order (normative)

1. Parse envelope (`MalformedEnvelope`).
2. Check `bundle_schema_version` is supported (`UnsupportedBundleSchemaVersion`).
3. Check `1..=MAX_SIGNATURES` signatures present (`NoSignatures`/`TooManySignatures`).
4. Strict-decode `payload_b64`, enforce `MAX_PAYLOAD_BYTES`
   (`MalformedPayloadEncoding`/`PayloadTooLarge`).
5. For each signature, in order: look up `key_id` in the trust store
   (skip to the next signature if absent); check the key's own
   `not_before`/`not_after` window against `now` (never against the
   bundle's own unauthenticated `issued_at`); check algorithm; decode
   signature bytes; `verify_strict` (never plain `verify` — rejects
   non-canonical point encodings and small-order keys) over
   `BUNDLE_SIGNING_DOMAIN ‖ payload_bytes`. **The loop always runs to
   completion, or to the first success — it never returns on the first
   unusable signature.** A known key_id that is out of its validity
   window, uses an unsupported algorithm, or has malformed key/signature
   material is recorded as a *skip reason* and the loop continues to the
   next signature; only the first such reason is kept, for a deterministic
   error later. This is what makes D4 rotation work: a bundle signed by
   both an outgoing key already past its `not_after` and an incoming key
   still verifies via the incoming key, regardless of which signature
   appears first in the list — an early-return implementation would report
   `KeyRetired` on the first signature and never try the second, which
   would defeat rotation entirely.

   Once every signature has been tried, resolve in this exact precedence:
   1. some signature verified → success, `verified_by` is that `key_id`.
   2. else, if any trusted-and-current key's signature was checked and
      failed → `SignatureInvalid` (tampering — a trusted, currently-valid
      key whose signature simply doesn't cover these bytes — outranks a
      mere configuration problem found on a *different* signature entry).
   3. else, if any known key_id was skipped for a window/algorithm/malformed
      reason → that first-recorded reason (`KeyNotYetValid`, `KeyRetired`,
      `UnsupportedAlgorithm`, or `MalformedSignature`).
   4. else → `UnknownKeyId` (no offered `key_id` was ever present in the
      trust store at all).
6. Parse `payload_bytes` into `BundlePayload` (`MalformedPayload` —
   subsumes the inner revision's own digest-mismatch rejection via its
   `TryFrom`, since that runs during this deserialization).
7. Check `payload.bundle_schema_version == envelope`'s (`SchemaVersionMismatch`).
8. Parse `not_before`/`expires_at`/`issued_at` as RFC3339 (`MalformedTimestamp`).
9. Window check with the D5 asymmetry (`BundleNotYetValid`/`BundleExpired`).
10. Every binding's `revision_ref.digest` must equal the revision's own
    digest (`BindingRevisionMismatch`).
11. Construct `VerifiedPolicyBundle`.

## Residual risks (named, deferred to FORNX-119)

1. **Rollback.** A validly-signed, unexpired *old* bundle can revert policy
   to a weaker state. `BundlePayload.sequence` exists in the wire schema
   specifically so a future check can reject `sequence <=
   last_known_good.sequence` — but `verify_bundle` does **not** check it.
   Doing so requires a last-known-good comparison point this ticket has no
   persistence layer for; that is FORNX-119's job (the same ticket that
   owns `CacheScope` activation per ADR-0006).
2. **Binding-set omission.** A bundle names exactly one revision. A
   transport-level attacker (not a forger — they cannot produce a new valid
   signature) can withhold a more-restrictive bundle while replaying an
   older, more-permissive one that is still unexpired and still validly
   signed. Detecting *withholding* (as opposed to detecting a forged or
   stale bundle) needs the same last-known-good/activation machinery as
   risk 1 and is equally out of scope here — also FORNX-119.
3. **No revocation.** ADR-0006 already notes revocation is a separate
   record referencing a digest, out of scope for that ticket. The only
   lever available here is key retirement via a `TrustedKey`'s `not_after`
   — there is no mechanism to revoke one specific *bundle* while its
   signing key remains otherwise valid.

## Non-goals (explicit for this ticket)

- No wiring into `fornax-store`, the daemon, or any CLI command — this
  ticket defines and tests the verification boundary in `fornax-types`
  only; a later ticket is responsible for a real caller ever invoking
  `verify_bundle` against a network-fetched or file-loaded bundle.
- No signing capability of any kind lives in this repository outside
  `#[cfg(test)]` fixture generation, per the trust-boundary discussion
  above.
- No `sequence`/last-known-good rollback defense, no binding-withholding
  detection (residual risks 1–2) — FORNX-119.
- No revocation beyond key retirement (residual risk 3).
- No self-updating trust root / TUF-style delegation (D4).

## Test coverage

`crates/fornax-types/src/policy/tests.rs`, T28 onward (continuing FORNX-116's
T1–T27): valid-signature acceptance; tamper detection distinguishing
`SignatureInvalid` (trusted key, bad signature) from `UnknownKeyId` (no
trusted key offered); the full clock-skew asymmetry (`BundleNotYetValid`
within/beyond tolerance, `BundleExpired` with no grace at all); rotation
where a signature list carries an already-retired key alongside a still-valid
one (in both orderings), proving the per-signature loop never returns early
on the first unusable signature; rotation
across old-key-only/new-key-only/both-keys trust stores; `KeyNotYetValid`/
`KeyRetired` from a trusted key's own validity window; the fail-closed
`UnsupportedAlgorithm` inversion of ADR-0006's fail-open selector rule;
strict base64 rejection (non-canonical characters, missing padding,
nonzero trailing bits); `MalformedPayload` for non-JSON bytes and a
hand-edited inner digest; signature-count and payload-size bounds;
schema-version cross-check; binding/revision digest mismatch; the frozen
fixture (`tests/fixtures/signed_policy_bundle_v1.json`) both verifying and
being exactly reproduced by its `#[ignore]`d regenerator; a dedicated
domain-separation test (a signature over the bare payload, without
`BUNDLE_SIGNING_DOMAIN`, must be rejected); a single-byte-mutation property
test over a valid envelope (every mutation errs, none panics); and
`TrustedVerificationKeys::load`'s own validation (duplicate key ids with
differing material, an empty key set, malformed key bytes).
