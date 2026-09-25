# Agent Evidence Protocol — compatibility and deprecation policy

Jira: [FORNX-391](https://lightning-dust-mite.atlassian.net/browse/FORNX-391) AC7:
"SDK/conformance changes are governed by compatibility/deprecation policy
and release evidence."

## What counts as a breaking change

A change to `crates/fornax-protocol` or
`docs/protocol/agent-evidence-protocol.md` requires a `protocol_version`
bump (and, before release, addition to
`fornax_protocol::envelope::SUPPORTED_PROTOCOL_VERSIONS`) if it:

- Removes or renames an existing top-level envelope field.
- Changes the meaning of an existing field's value (not just its type).
- Adds a *required* top-level field with no default — a consumer built
  against the prior version could no longer produce a valid message a
  same-version consumer accepts.
- Changes `object_kind`'s wire representation for an existing variant.
- Changes the canonical-JSON digest algorithm itself
  (`fornax_protocol::canonical::canonical_json_digest`) — every existing
  implementation's digest recomputation would silently disagree.

## What does not require a version bump

- Adding a new, optional top-level field with `#[serde(default)]` (or
  equivalent in another implementation) — an older consumer simply sees it
  as an unknown field, preserved per the forward-compatibility rule in
  `agent-evidence-protocol.md`.
- Adding a new `Capability` variant — a consumer that does not implement it
  already has an explicit, typed way to detect the gap
  (`missing_capabilities`), by design.
- Adding a new `ObjectKind` variant for a wholly new object type — existing
  consumers of the *existing* kinds are unaffected; a consumer that
  receives the new kind unexpectedly still gets an explicit
  `UnsupportedObjectKind` rejection, never a misinterpretation.

## Process for a version bump

1. The change lands behind a new value added to
   `SUPPORTED_PROTOCOL_VERSIONS` (widening the range, e.g. `1..=2`) —
   never by silently repurposing an existing version number.
2. New conformance fixtures are added to `fornax_protocol::conformance`
   covering the new version's specific behavior (a message declaring the
   old version must still round-trip correctly; a message declaring the
   new version exercises whatever changed).
3. `docs/protocol/agent-evidence-protocol.md` is updated in the same PR —
   the spec and the code are never allowed to drift.
4. The change goes through this repository's ordinary PR → CI → merge-commit
   → release-assurance pipeline like any other change (this policy adds no
   new gate; it says what the *existing* gate must additionally check for a
   protocol change specifically: conformance-suite coverage and spec-doc
   parity, verified in code review, not a separate approval track).
5. A version is only ever *added* to `SUPPORTED_PROTOCOL_VERSIONS`, never
   silently removed from underneath live consumers — deprecating an old
   version is itself a decision requiring the same review, with an explicit
   sunset note added to this document naming the version and the release
   it will be dropped in.

## Currently supported

| Protocol version | Status | Notes |
|---|---|---|
| 1 | Current | Initial release (FORNX-391). |
