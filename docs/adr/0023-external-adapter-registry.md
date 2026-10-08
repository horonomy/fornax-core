# ADR 0023: Configuration adapters and separate host descriptor registration

Status: Accepted
Date: 2026-10-02
Jira: HORO-1619, FORNX-428 (S4 design, S6 implementation), HORO-1745 (descriptor registration amendment)

## Context

FORNX-428 S2/S3 replaced seven hand-maintained `match` tables with
`crates/fornax-cli/src/adapter_registry.rs`: one `AdapterPlugin` trait, one
`registry()` array, and `AdapterArg` parsing straight through `resolve()`.
Adding a *built-in* adapter is now one struct plus one `registry()` entry.

That is not enough for HORO-1619 AC#3 ("a third test adapter can be
registered without rebuilding Fornax") or AC#11's anti-vacuity demand. Both
require an adapter to enter the registry at **runtime**, from data on disk.

Note on naming: this ADR's `AdapterPlugin` is the *host-configuration
install* boundary in `fornax-cli`. It is a different concept from ADR-0004's
`AgentAdapter`, the *observation/normalization* boundary in `fornax-types`.
Two unrelated traits, both historically called "adapter". ADR-0004 is
unchanged by this ADR; `docs/contributing/adding-an-adapter.md` continues to
document that other concept.

The original S6 decision below governs configuration manifests. HORO-1745
extends the same registry with the separately versioned shared host-adapter
manifest; it does not change configuration manifest v1 or authorize core
process execution. Host descriptors are passive metadata in this delivery.
Execution belongs to the founder-approved, separately invoked
`exec/fornax-host-adapter-exec`; no core crate may depend on or spawn it.
ADR-0004 observation semantics and ADR-0022 acquisition remain unchanged.

### Three candidate configuration plugin boundaries

1. **In-process dynamic library loading** (`dlopen`/`libloading`). Rejected.
   It grants arbitrary native code the full address space of a process that
   holds the user's audit ledger and policy cache, has no containment story
   short of OS sandboxing Fornax does not have, and HORO-1619 forbids it
   absent an explicit security review proving it correct. No such proof
   exists, and the need does not justify producing one.
2. **Subprocess/protocol boundary** (manifest declares an executable; Fornax
   spawns it and speaks a versioned protocol over stdio). Rejected on a
   hard, pre-existing repo invariant:
   `crates/fornax-daemon/tests/adversarial_daemon_input.rs::
   subprocess_surface_is_still_zero_in_production_code` (FORNX-238) scans
   every non-`tests/` `.rs` file under `crates/` and fails on any occurrence
   of `process::Command`, `Command::new`, or `sh -c`. ADR-0004 already
   treated this as binding when it routed git access through `fornax-vcs`
   (pure-Rust `gix`) rather than shelling out, and ADR-0016/ADR-0022 reason
   from the same invariant. Introducing a subprocess *as the plugin
   mechanism* would make Fornax's most load-bearing security invariant the
   first casualty of its extensibility story.
3. **Declarative data-only manifest.** Chosen.

### What an install actually is

Both built-ins do the same narrow thing. Claude Code: ensure a hook group
carrying `command: "fornax-hook-claude"` exists under
`hooks.<event>[]` in `~/.claude/settings.json`, idempotently, refusing to
overwrite a value of unexpected shape, writing via temp-file + rename.
Codex: ensure a `notify` entry bearing the `fornax-codex-notify.sh` marker
in `~/.codex/config.toml`. Uninstall removes exactly the marker-bearing
entries and prunes containers it emptied.

That is not a general-purpose capability. It is one operation:
*ensure a marker-bearing element exists in a declared container, and be able
to remove exactly it again.* It is expressible as data, so an external
adapter needs no code — and therefore no code-execution boundary.

## Decision

### D1. Configuration manifests are data; host descriptors do not grant execution.

There is **no** `executable`, `entrypoint`, `command`, or `script` field in
the configuration manifest v1 schema, by design. This is a deliberate
omission from HORO-1619's "fields to consider" list: a field named
`executable` that is never executed is a trap for the next maintainer, and
the first bug report asking "why doesn't my entrypoint run" would be
answered by adding execution in the configuration interpreter. Its schema is `deny_unknown_fields`, so a
manifest carrying such a field is a parse failure naming the field, not a
silently-ignored key.

A host descriptor instead carries the existing shared executable declaration.
Registration and inspection never resolve, hash or execute that code, probe a
host, grant implementation trust, or produce a runtime capability snapshot.
These require the separate execution boundary and its own acceptance gates.

Consequence for configuration manifest v1: every HORO-1619 security requirement phrased in terms of
execution ("bounded subprocess execution/timeouts", "sanitized
environment", "no silent PATH-wide plugin execution", "no execution during
--help") is satisfied by the absence of an execution surface, not by a
mitigation that could regress. `subprocess_surface_is_still_zero_in_
production_code` is the standing proof, and it runs on every CI build.

### D2. Manifest schema v1

A single JSON file. `schema_version` is gated through this repo's existing
`#[serde(try_from = "...Wire")]` + `SUPPORTED_MANIFEST_SCHEMA_VERSIONS`
pattern (as in `fornax-types/src/audit.rs`), so an unsupported version is a
specific, named error rather than a confusing field-level parse failure.
The wire struct and every nested struct are `#[serde(deny_unknown_fields)]`.

```json
{
  "schema_version": 1,
  "id": "acme-agent",
  "display_name": "Acme Agent",
  "summary": "Wires the Fornax hook into Acme Agent's settings.json.",
  "min_fornax_version": "0.0.8",
  "provenance": "https://github.com/acme/fornax-adapter-acme",
  "capabilities": ["plan", "install", "uninstall"],
  "target": { "format": "json", "path": "~/.acme/settings.json" },
  "operations": [
    {
      "kind": "ensure_marked_array_element",
      "pointer": "/hooks/PostToolUse",
      "marker_key": "command",
      "marker_value": "fornax-hook-acme",
      "element": { "type": "command", "command": "fornax-hook-acme" }
    }
  ]
}
```

| Field | Type | Req | Rule |
|---|---|---|---|
| `schema_version` | `u32` | yes | must be in `SUPPORTED_MANIFEST_SCHEMA_VERSIONS` (`&[1]`) |
| `id` | `String` | yes | 3..=64 chars, `^[a-z0-9][a-z0-9-]*[a-z0-9]$` (ASCII only — no unicode, no uppercase, so no homoglyph/case-fold spoof of a built-in id); must not collide with a built-in or another entry |
| `display_name` | `String` | yes | 1..=64 chars, no control chars, no newline |
| `summary` | `String` | yes | 1..=200 chars, no control chars, no newline |
| `min_fornax_version` | `String` | yes | `major.minor.patch` of plain integers; parsed to `(u64,u64,u64)` and compared against `env!("CARGO_PKG_VERSION")`. Deliberately not semver-range syntax — avoids a new dependency and avoids range semantics nobody asked for |
| `provenance` | `String` | yes | 1..=256 chars, no control chars. Display-only, unverified, and labelled as such in `adapter info` output |
| `capabilities` | `Vec<Capability>` | yes | non-empty subset of `plan` \| `install` \| `uninstall`; duplicates rejected. `install` or `uninstall` requires `operations` non-empty |
| `target.format` | enum | yes | `"json"` only in v1. `"toml"` is a clean "unsupported target format" rejection today and a purely additive v1 change later |
| `target.path` | `String` | yes | see D6 containment rules |
| `operations` | `Vec<Operation>` | yes | 1..=16 entries; `(pointer, marker_key, marker_value)` must be unique within the manifest |

**Deliberately absent fields**, against HORO-1619's "fields to consider":

- `executable`/`entrypoint` — absent from configuration manifest v1; see D1.
- `aliases` — deferred. An alias namespace is a second place ids can collide
  with built-ins and with each other, for zero current demand. `resolve()`
  stays a single-key lookup.
- `supported_host_tools` — subsumed. The host tool *is* `target.path` plus
  `display_name`; a separate free-text field would be unverifiable
  duplication.
- `enabled` — not a manifest field. Enabled state is Fornax-owned registry
  state (D3), not something a manifest asserts about itself.

### D3. One operation kind, not a DSL

```rust
enum Operation {
    EnsureMarkedArrayElement {
        pointer: String,          // RFC 6901 JSON pointer to a JSON array
        marker_key: String,       // key within each array element
        marker_value: String,     // the Fornax-owned marker value
        element: serde_json::Value, // object to insert; element[marker_key] must == marker_value
    },
}
```

Semantics mirror `claude_adapter::install_claude_hooks`/
`uninstall_claude_hooks` exactly:

- **plan/install** — resolve `pointer`, creating missing intermediate
  *objects* only; if any existing intermediate value is not an object, or
  the terminal value exists and is not an array, **refuse and error** rather
  than overwrite (the existing non-clobber rule, unchanged). If no element
  already satisfies `element[marker_key] == marker_value`, append `element`.
  Otherwise no change.
- **uninstall** — remove every element where
  `element[marker_key] == marker_value`; prune containers emptied *by this
  removal only*; never remove a container that still holds another tool's
  entry.
- `changed` is computed by `before != after` on the parsed document, so
  idempotence is structural, not asserted.

`element[marker_key]` is validated at parse time to equal `marker_value`.
Without that, a manifest could install an entry it can never uninstall —
a one-way mutation dressed as a reversible one.

This is the only operation kind. Adding a second requires an ADR amendment.
Stated explicitly so the next ticket does not grow a config-mutation DSL by
accretion.

### D4. Discovery: exactly one Fornax-owned directory

`$FORNAX_HOME/adapters/` (default `~/.fornax/adapters/`), containing:

- `registry.json` — the Fornax-owned index (below)
- `<id>.manifest.json` — owned configuration manifest copy
- `<id>.host-adapter.json` — owned shared host descriptor copy
- `registry.lock` — stable advisory lock inode for cooperating registry mutators

**No** `PATH` scan, **no** XDG directory chain, **no** CWD, **no**
environment variable listing extra directories, **no** recursion. A manifest
file merely *present* in that directory is not registered and is never read:
only entries in `registry.json` are loaded. There is no filesystem-presence
path to registration — only `fornax adapter register`.

Read paths **never create** this directory. `adapter list` on a machine with
no `$FORNAX_HOME/adapters/` reports only built-ins and creates nothing. Only
`register` creates the directory.

```json
{
  "schema_version": 1,
  "entries": [
    {
      "id": "acme-agent",
      "manifest_file": "acme-agent.manifest.json",
      "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "source_path": "/Users/x/src/acme/acme.manifest.json",
      "registered_at": "2026-10-02T11:04:19Z",
      "enabled": true
    }
  ]
}
```

The legacy closed index shapes (stored version0, version1 or an omitted
version with effective legacy1) contain configuration records only. Fresh
configuration indexes explicitly default to1. Passive reads preserve the
stored version; historical0 is explained without rewriting the index.

Confirmed host registration migrates the sole index to a closed v2 root:
`{"schema_version":2,"registry_kind":"fornax-adapter-registry-v2","entries":[...]}`.
Each v2 record retains the six legacy fields and adds required `kind`, either
`config-v1` or `host-adapter-v1`. IDs remain one global namespace: no second
facet, automatic association or kind precedence. Configuration IDs keep their
original grammar; host IDs follow the shared manifest contract.

The mandatory root marker remains after the final host record is removed,
including an empty index. Old S6 readers reject that marker rather than
mistaking an empty v2 index for legacy state. Quiesce old mutators for initial
migration: an old process that already read v1 does not participate in the
new lock and can still overwrite a migration. Locking is not universal CAS.
Review does not migrate; it must disclose this compatibility change before
confirmation. Unsupported future index versions refuse every mutation.

`source_path` is recorded for provenance display only. **It is never read
after registration.** All loading reads `manifest_file` inside
`$FORNAX_HOME/adapters/`, which removes the entire class of "user's manifest
file changed under us between invocations".

### D5. Trust model

**What the digest pin is.** `digest` is `sha256:<64 lowercase hex>` over the
**raw bytes of the manifest file**, not over a canonicalized parse. Hashing
raw bytes means the pin covers exactly what was shown to the user, including
whitespace and key order — a canonical-form hash would let two
byte-different files share a pin.

**Register is a two-invocation ceremony.** Invocation 1 reviews and refuses;
invocation 2 registers. Within *each* invocation the source file's bytes are
read exactly once into memory, and the digest, the parse, the displayed
summary, and the bytes copied to the owned location are all derived from
that same in-memory buffer — never from a second read of the path. Across
the two invocations, invocation 2 necessarily re-reads the source path; the
digest passed to `--confirm-digest` is precisely what makes that re-read
safe, because a file swapped between the two invocations produces a
different digest and is refused by name. This is the mechanism, not a
ceremony: without the flag the second read would be an unchecked TOCTOU
window.

**Load-time verification.** On every `registry()` load, each enabled entry's
owned copy is read and re-digested; a mismatch against the pin rejects that
entry with reason `digest mismatch` and does not load it. This catches
drift, truncation, partial writes, and clumsy hand-editing of the owned
copy.

**What the pin is not.** `registry.json` and the owned manifest copies live
in the same directory and the same trust domain. An attacker who can write
`$FORNAX_HOME/adapters/` can update both the copy and its pin consistently,
so the pin is **an integrity check against drift and tampering-by-accident,
not an authenticity boundary against a local attacker with write access to
`$FORNAX_HOME`.** That threat is out of scope because such an attacker can
replace the `fornax` binary itself, and no in-process check survives that.
Authenticity against an untrusted publisher would require signature
verification against a key Fornax trusts — deliberately not built here: this
is a local-only CLI with no distribution channel for third-party adapters,
so there is no publisher to authenticate. If such a channel ever exists,
ADR-0007's signed-bundle machinery is the precedent to extend, not this
digest field. This paragraph exists so no future reader mistakes the pin for
a trust boundary it is not.

**`$FORNAX_HOME/adapters/` permissions.** Directory `0700`, files `0600`, on
unix, set at creation — matching `codex_adapter::save_codex_config`'s
existing reasoning about not widening a sensitive file to the umask default.

**Source-path permission check.** `register` additionally refuses a source
manifest whose file, or whose containing directory, is group- or
world-writable (`mode & 0o022 != 0`), checked before the source is ever
read. This is a precondition on *who may plausibly have written the
file being registered*, not a replacement for the digest pin above:
the digest proves the bytes didn't change between the review and
confirm invocations; this check narrows who could have written those
bytes in the first place.

### D6. `target.path` containment

`target.path` is the one genuinely dangerous field: it is a file-write
primitive with a manifest-chosen destination, where both built-ins had their
paths hardcoded in Rust. Containment is structural, applied at **parse time
and again immediately before any write**:

1. A single leading `~/` is expanded to `$HOME`; `~` elsewhere, or `~user`,
   is rejected. No other variable or tilde expansion of any kind.
2. The resolved path must be absolute and must have `$HOME` as a prefix
   after normalization. Anything outside `$HOME` is rejected.
3. No `..` component anywhere, pre- or post-expansion. No empty components.
4. The final component must have an extension matching `target.format`
   (`json`), so a manifest cannot target a shell profile, a key file, an
   authorized_keys, or a binary.
5. The parent directory **must already exist**. External adapters get no
   `create_dir_all` — unlike `claude_adapter::save_settings`, which may
   create its parent because its path is a compile-time constant. Reusing
   that helper for an external target would hand a manifest a
   directory-creation primitive on a chosen path.
6. Immediately before writing, `symlink_metadata` the final component; if it
   is a symlink, refuse. Fornax writes the file it named, never a link's
   target. (The built-ins never needed this; with a manifest-chosen path a
   pre-planted symlink is a real escape.)
7. The temp file for the atomic write is created in the **target's own
   parent directory** with the target's filename plus a `.fornax-tmp`
   suffix, so rename stays same-filesystem and the temp path is as contained
   as the target. It is created with `create_new` so an existing/planted
   temp path is an error, not a silent overwrite.

These checks run at parse time (so `register` and `adapter list` reject a
bad manifest without ever touching the target) and again at write time (so a
path that became a symlink after registration is still caught).

### D7. Bounds

Fail closed, with a named limit, on: manifest file larger than 64 KiB;
`registry.json` larger than 1 MiB or more than 64 entries; more than 16
operations; JSON pointer longer than 256 bytes or deeper than 16 segments;
`element` serializing to more than 4 KiB; target config file larger than
8 MiB. A data-only design has no runaway-process failure mode, but it does
have parse and write amplification, and an unbounded `element` written into
a user's real `settings.json` is a real denial-of-service against their
coding agent.

### D8. Duplicate and collision resolution — one namespace, built-in wins

- `register` rejects an `id` equal to any built-in id, or to any existing
  entry's id, before writing anything.
- Load time re-checks, because a built-in added in a later Fornax release
  must not be shadowed by an already-registered external. On collision the
  **built-in loads and the external is rejected** with reason
  `id collides with built-in adapter`.
- Rejections are never silent. `adapter list` prints a `Rejected entries`
  section with each id and reason; `adapter info <id>` reports the rejection;
  and `AdapterArg::from_str` on a registered-but-rejected id returns that
  specific reason rather than a misleading "unknown adapter". Silent
  skipping would turn a security rejection into a mystery.

### D9. Registry assembly keeps `registry()`'s signature

`registry()` continues to return `&'static [&'static dyn AdapterPlugin]`,
for configuration dispatch, backed by a `OnceLock` populated once per process: the two built-in
statics first, in display order, then successfully-loaded external adapters
(`Box::leak`-ed — process-lifetime by construction in a short-lived CLI).
`resolve()`, `AdapterArg`, `install`, `uninstall`, `plan`, `doctor`, and
every `Commands`/`AdapterAction` shape in `main.rs` are **unchanged**:
`registry()` was already the single registration point, and it still is. The
only trait change is `&'static str` → `&str` on `id`/`display_name`/
`summary`, so a manifest-owned `String` can be returned; called on a
`&'static dyn AdapterPlugin` these still yield `&'static str`, so
`AdapterArg`'s accessors keep their signatures too.

Authoritative index decoding, storage transactions and passive host descriptor
lookup belong to the existing `fornax-store::adapter_registry` module. The
CLI uses that owner rather than maintaining a second index codec. Host
records never become `AdapterPlugin` configuration drivers by registration;
install/uninstall/plan/doctor refuse that kind explicitly until an owning
configuration surface exists. Help parses without reading the registry.

This is the concrete configuration answer to AC#11: adding an external adapter touches no
enum, no parser, and no `match`.

### D10. Lifecycle verbs

`register`, `info`, `enable`, `disable`, `remove` operate on
`registry.json` only. `disable` sets `enabled: false` (entry and owned copy
retained, excluded from `registry()`, still visible to `list` and `info`);
`remove` deletes the index entry but, as of HORO-1745 (Strict Retention),
never deletes its owned copy -- see D10.1. Independent per entry, so AC's
"enabled/disabled/removed independently" is a property of the index shape
rather than a special case.

Host descriptor registration uses the same digest-confirmation ceremony,
with exact `manifest_kind:"host-adapter"` selecting the pinned shared validator.
Absent marker selects the unchanged configuration validator; unknown markers
are refused. Declared future protocol or contract ranges are inspectable
incompatibility, not activation. New host records are disabled; enable refuses
`execution_boundary_unavailable` without changing the record. Disable/remove
remain available. Registration, installation and activation stay distinct.

All upgraded mutators share a kernel advisory lock on the stable
`registry.lock` inode, using bounded nonblocking contention. Never unlink,
replace, truncate, reclaim or change permissions on an existing lock file.
Passive reads create nothing. Lock acquisition may create its directory and
sidecar, disclosed separately from whether an index mutation occurred.

Under the held lock, reread authoritative state and detect drift before
publication. Publish an owned copy with create-new semantics; an unindexed
existing destination is a refusal. Use invocation-owned index staging and
atomic index rename. The index rename is the commit point, not a claim of
crash atomicity across both files. Before publication, an invocation-owned
staging file is retained, not deleted (D10.1); its random name is single-use
and never looked up again, so this is inert disk litter, never a
re-registration hazard. After publication, sync/readback failure reports
committed with verification unverified and never retries, rolls back or
deletes the registered copy. Removal publishes the updated index first; its
owned copy is likewise retained, not deleted, and the operation reports a
partial/`cleanup_failed` outcome with the index change confirmed committed.

#### D10.1. Strict Retention: owned-copy deletion is never attempted (HORO-1745)

`remove_owned`'s `fstat`-verify-identity step cannot be followed by a
race-free pathname `unlinkat`: POSIX has no atomic "unlink this exact
already-open inode by name" primitive, so a same-user noncooperating writer
can replace the file in the window between the identity check and any
subsequent unlink, causing deletion of a different inode than the one
verified. Narrowing the window (fewer syscalls between check and unlink, a
directory-replacement guard, a cooperating-writer assumption) only shrinks
it; independent review found no technique that closes it, and a
cooperating-writer assumption is exactly the assumption that finding showed
is not load-bearing here.

The accepted trade: `remove_owned` always retains the file (returns an
error whose caller takes the existing "could not be safely cleaned" /
`CleanupFailed` path) rather than ever attempting the unlink, whether or not
the identity check above it succeeds. An invocation-owned staging or
descriptor file this function would otherwise have deleted is left on disk,
inert and unreferenced by the index once the index mutation has committed.
The accepted cost is that a removed id's filename is not released until
something clears the orphan by hand: re-registering the same id refuses at
`create_owned` with `RegistryErrorCode::OwnedDestinationOccupied` (the
underlying OS cause is `EEXIST`) rather than silently reusing or
overwriting it -- distinct from `InvalidRecord`, since the new
registration's own bytes are not malformed; `create_owned` simply cannot
tell a retained orphan apart from a file placed at that path outside the
registry, and refuses either the same way. This applies uniformly to
configuration and host-adapter registrations alike -- there is no
"ordinary, uncontested case" exception, because any such exception would
reintroduce the same unproven assumption.

Bound regular-file reads before allocation, holding directory descriptors
and refusing symlinks or special files. Manifest validation covers the whole
pinned executable schema, its bounded configuration-schema profile, duplicate
keys, numeric bounds and declared version ranges. Source paths remain display
metadata after registration. Owned descriptor integrity never implies code
trust, installed state or native observation.

## Consequences

- An external configuration adapter can wire a marker-bearing entry into one JSON config
  file under `$HOME` and remove it again. It cannot run code, read
  credentials, touch a second file, write outside `$HOME`, or mutate a TOML
  file. A TOML host tool needs a built-in adapter until a future amendment
  extends `target.format` — a real limitation, accepted: the alternative was
  doubling the mutation engine in its first slice.
- `registry()` performs filesystem reads on first call. It is lazy, never
  creates anything, and cannot panic: all failures become rejections.
  `--version` and `--help` never call it (help text does not enumerate ids),
  so AC#8's side-effect-free guarantee is untouched.
- `adapter_registry.rs`'s existing
  `all_lists_exactly_the_two_known_adapters` test must be rewritten to
  assert over built-ins via an explicit seam — it would otherwise fail on
  any developer machine that has registered an external adapter.
- `provenance` is unverified free text, displayed as such. This ADR does not
  introduce adapter authenticity; see D5.

## Security considerations

The table records configuration manifest v1 acceptance. Its execution N/A
claims do not discharge any future runner requirement. Host descriptor
registration adds no execution surface and no implementation trust.

| Requirement | Mechanism |
|---|---|
| Explicit registration or trusted discovery location | D4: one Fornax-owned directory; only `registry.json` entries load; presence of a file registers nothing. D5: registration requires `--confirm-digest` and refuses a group-/world-writable source file or directory. |
| No silent PATH-wide plugin execution | D1 (configuration interpretation never executes code) + D4 (`PATH` is never consulted) + the `subprocess_surface_is_still_zero_in_production_code` invariant as the standing proof. |
| No execution during `--help`/`adapter list` | D1: passive configuration and descriptor operations have no execution surface. `--help`/`--version` additionally never reach `registry()`; `adapter list` reads data and creates nothing (asserted by test). |
| Bounded subprocess execution/timeouts | **N/A by construction, with proof, not by assertion.** There is no subprocess to bound and no call that can hang; the FORNX-238 invariant test guarantees none can be introduced without failing CI. D7 bounds the surface that *does* exist: parse size and write amplification. |
| Sanitized environment | **N/A by construction** — no child process inherits an environment. Manifest path handling performs no environment interpolation at all beyond a single leading `~/` → `$HOME` (D6.1), so a manifest cannot reference `$ANYTHING`. |
| Non-destructive ownership-aware config mutation | D3: marker-based, additive, idempotent, refuses to overwrite a value of unexpected shape, uninstall removes only marker-bearing elements and prunes only what it emptied — the same rules `uninstall_claude_hooks` already enforces. D6.5/6/7: no directory creation, no symlink follow, contained atomic temp+rename. |
| Clear provenance in adapter info | D10/`adapter info`: source path, registered-at, pinned digest, enabled state, declared capabilities, compat range, and the `provenance` string explicitly labelled unverified. |
| No credential values in registry/help output | Structural: `deny_unknown_fields` on every manifest struct means a manifest carrying a `token`/`api_key` field **fails to parse** — undeclared credential fields are refused; free-text metadata must not be treated as credential-free proof. All displayed strings are length-capped and control-char-rejected (D2). `AdapterActionResult.message` never includes config file contents. |
| Reject duplicate/conflicting IDs | D8: rejected at register time and re-checked at load time; built-in always wins; rejections surfaced in `list`, `info`, and `AdapterArg::from_str`. |
| Fail closed on malformed/untrusted descriptors | Every validation failure (schema version, regex, bounds, path containment, digest mismatch, missing owned copy, unsupported `target.format`) yields a `Rejection` carrying a reason; the entry does not load, malformed input grants no dispatch authority. D10 distinguishes pre-publication failure, inert cleanup residue and committed-but-unverified outcomes. |

### Acceptance criteria coverage

- **AC#3** — D4+D9+D10: `fornax adapter register --manifest <path>
  --confirm-digest <d>` adds a working adapter to `registry()` with no
  rebuild. Test `external_adapter_is_resolvable_after_register`.
- **AC#4** — `list`/`info` read manifest data only. Nothing is executed
  (D1), the target config file is not opened by `list`/`info`, and no
  directory is created. Tests
  `adapter_list_with_external_registered_touches_no_filesystem_state`,
  `adapter_info_renders_provenance_without_reading_target_file`.
- **AC#5** — `plan`/`install`/`uninstall` touch the target file only when
  that verb is the explicitly selected operation; `plan` never writes
  (same property `plan_matches_install_without_writing` already asserts for
  the built-ins). An operation absent from `capabilities` is refused before
  any filesystem access.
- **AC#6** — D2 (schema/regex/version gating), D6 (path containment), D7
  (bounds), D8 (collisions), D5 (digest). Each is a named rejection reason,
  each has a test.
- **AC#9** — this ADR plus
  `docs/contributing/registering-an-external-adapter.md`.
- **AC#10** — see the S6 implementation plan's test matrix; the "timeout"
  case is N/A-with-proof per the table above, discharged by an explicit test
  asserting the manifest wire struct has no execution-bearing field.
- **AC#11** — D9: `registry()` keeps its signature and remains the single
  registration point; no enum, parser, or `match` changes. Test
  `registering_an_external_adapter_requires_no_cli_enum_change`.
