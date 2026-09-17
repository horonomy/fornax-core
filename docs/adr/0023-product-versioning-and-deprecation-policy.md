# ADR 0023: Product versioning and deprecation policy

Status: proposed (FORNX-364, GA prep — input to FORNX-227's v0.1.0 release
docs, not a replacement for that release-blocking review)

## Scope

This ADR states Fornax's own **product-facing** versioning and
deprecation/compatibility policy: what version number means what, what
counts as a breaking change to the CLI/config/on-disk data, and how long an
old behavior is supported after it's superseded.

It is deliberately narrow and does not duplicate two adjacent, already-
existing documents:

- `docs/adr/0003-dependency-version-policy.md` governs *third-party
  dependency* version selection/pinning across every Fornax repo — not
  Fornax's own product version.
- `docs/adr/0005-schema-evolution.md` governs the internal
  `ExtensionEnvelope`/`schema_version` wire-format's own retirement
  mechanics — a specific internal format, not the product as a whole.

## Current, observed versioning scheme (not invented)

Fornax already follows a pre-1.0 sequence, visible in `CHANGELOG.md` and
git tags: `v0.0.1` → … → `v0.1.0` (General Availability), tracked in Jira
epic FORNX-20. This ADR does not introduce a new scheme — it states the one
already in use and commits to standard pre-1.0 SemVer semantics for it:

- **`0.y.z` (pre-GA):** any `y` bump (minor) may include breaking changes.
  A `z` bump (patch) is backward compatible. There is no promise of
  compatibility between `0.y.z` releases at different `y`.
- **`1.0.0` and later (post-GA):** standard SemVer applies — a `MAJOR` bump
  may break compatibility, `MINOR` adds functionality compatibly, `PATCH`
  is a compatible bug fix. This ADR does not itself declare GA; it states
  what will be true once FORNX-266's gate closes and `v0.1.0` ships.

## What counts as a breaking change

A change is breaking if, without an explicit migration step, it causes any
of the following to stop working for a user on a supported prior version:

- A previously-valid CLI invocation (subcommand, flag, or its accepted
  values) no longer works or changes its meaning.
- A previously-valid `$FORNAX_HOME/config.toml` key/table is no longer
  read, or its meaning changes.
- The on-disk schema (`$FORNAX_HOME/fornax.db`) is read or written in a way
  that an older binary can no longer open it, or a newer binary cannot open
  data written by a supported older version, without an automatic/documented
  migration.
- A previously-supported adapter/provider integration point (hook payload
  shape, `notify` wiring, plugin interface) changes incompatibly.

This mirrors the fields `docs/release/release-docs-governance.md` already
requires a changelog entry to state for a breaking change (Breaking/Removed,
Migration, Security, Compatibility) — this ADR is the standing *policy*
those fields exist to document per-change, not a new mechanism.

## Deprecation and support window

Consistent with the pre-1.0 stance already stated in `SECURITY.md`
("only the latest commit on `main` is supported for security fixes — there
is no maintained release branch to backport to at this stage"):

- **Pre-1.0 (`0.y.z`):** no fixed deprecation notice period is committed.
  A breaking change is called out explicitly in `CHANGELOG.md`'s
  `[Unreleased]` → versioned section per `release-docs-governance.md`, with
  a stated migration path or an explicit statement that none exists yet
  (the same pattern `v0.0.1`'s entry already uses for `$FORNAX_HOME`'s
  on-disk schema).
- **Post-1.0:** a deprecated CLI flag, config key, or on-disk format is
  marked `Deprecated` in the changelog at least one `MINOR` release before
  removal, with a stated replacement and removal target `MAJOR` version.
  This is a policy commitment to be exercised starting at `v1.0.0`; it does
  not retroactively apply to pre-GA releases.

## Non-goals

- This ADR does not set an SLA or response-time commitment — see
  `SUPPORT.md` and `SECURITY.md`'s "Response Expectations" section for that,
  and FORNX-367 for why a real SLA is founder-gated on operational evidence
  that doesn't exist yet.
- This ADR does not decide GA scope or timing — that's FORNX-148/FORNX-266.
- This ADR does not restate `docs/adr/0003` or `docs/adr/0005` — see those
  documents directly for dependency-version and wire-schema-evolution policy.

## Relationship to FORNX-227

FORNX-227 ("[v0.1.0 Release Docs] Complete GA documentation...") is the
release-blocking task that will publish the final, founder-reviewed
migration/compatibility/deprecation guarantees for the actual `v0.1.0`
release. This ADR is an input to that work — the underlying policy it can
point to — not a substitute for FORNX-227's own review and publication.
