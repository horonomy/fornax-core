# Privacy and redaction policy

Status: Accepted
Jira: FORNX-19 (local-scope gaps identified against FORNX-33's redaction work)

## Scope

This document describes Fornax's **local** privacy boundary: what is
redacted before data is written to the local SQLite store, and the gate that
must be consulted before any data leaves this machine. It does not cover
`fornax-cloud` (the separate uploader/sync repo) — that repo's retry/upload
logic is out of scope here and is not duplicated in this repo.

## Where redaction happens

Redaction is applied once, at the ingest boundary in `fornax-daemon`
(`crates/fornax-daemon/src/main.rs`, `handle_message`), immediately before
each record is persisted — not re-derived by downstream readers:

| Data | Redaction call | Field(s) |
|---|---|---|
| `AgentEvent` | `redact::redact_json` | `tool_input`, `tool_response`, `raw` |
| `Evidence` | `redact::redact_json` | `payload` |
| `Claim` | `redact::redact_text` | `text` |

The classifier itself lives in `crates/fornax-types/src/redact.rs` and is
covered by unit tests there; `crates/fornax-daemon/src/main.rs` has an
additional regression test (`tool_input_and_claim_text_are_redacted_before_storage`)
proving a canary secret placed in `tool_input`/claim text never reaches
storage unredacted (FORNX-280).

**Gap found and fixed before release (FORNX-219/FORNX-244, SEC-v0.0.3-0001):
`Evidence::extension` was not passed through `handle_message`'s redaction
calls at all** — only `Evidence::payload` was (see the table above).
`ExtensionEnvelope::fields`/`unknown` (`docs/adr/0005-schema-evolution.md`)
are deliberately untyped, provider-specific JSON an adapter author chooses
to attach — real content observed today includes tool-call title/timing
telemetry (the opencode adapter's first use of the envelope). This was a
structural gap (an entire field never reached the classifier), not a
detector weakness like the ones listed below. `handle_message`'s
`IngestMessage::Evidence` arm now calls `redact_json` on `extension.fields`
and `extension.unknown` the same way it already did on `payload`; see
`docs/release/v0.0.3-security-signoff.md` for the finding and its
regression test.

`Evidence::source` (`EvidenceSource`) is deliberately not passed through
`redact_json` — every one of its fields (sensor name, trust class,
timestamps, provider, collection method) is a short structured
identifier/enum, with no free-text content a secret could hide in.

## Detectors that run today

`redact::detectors()` runs exactly three pattern-based detectors, applied
token-by-token (or line-by-line for the env-assignment shape) over every
string value in a JSON payload (`redact_json`) or over free text
(`redact_text`):

1. **`github_token`** — a token starting with `ghp_`, `gho_`, `ghu_`, or
   `ghs_` (GitHub personal-access/OAuth/user/server token prefixes).
2. **`env_secret_assignment`** — a whole line containing (case-insensitively)
   `TOKEN=`, `API_KEY=`, `APIKEY=`, `SECRET=`, `PASSWORD=`, or
   `PRIVATE_KEY=`. When this matches, the **entire line** is replaced with
   `[REDACTED: possible secret assignment]`, not just the value — the
   assumption is that a line shaped like `NAME=value` is a credential
   assignment end to end.
3. **`high_entropy_token`** — a single whitespace-delimited token that is:
   - between 20 and 200 characters long,
   - contains no whitespace,
   - built only from `[A-Za-z0-9_.\-/+=]`,
   - and contains at least one digit **and** at least one letter.

   This is the generic catch-all: anything shaped like an opaque
   token/key/hash, regardless of which service issued it. Matching tokens
   are replaced with `[REDACTED]`; every other token on the line is kept.

`redact_json` walks a `serde_json::Value` recursively and redacts every
**string value**; object keys and non-string values (numbers, bools, null)
are left untouched. `redact_text` operates line-by-line: a whole matching
env-assignment line is replaced outright, otherwise each token is tested
independently against the non-env-assignment detectors and the line is
rebuilt by rejoining tokens with a single space.

**Fidelity caveat (not a detection gap):** because `redact_text` rebuilds
each line as `line.split_whitespace().collect().join(" ")`, it normalizes
whitespace even on lines where nothing matched — leading/trailing
whitespace is stripped and any run of spaces/tabs collapses to one space.
`redact_text("  indented\ttext  with   gaps")` returns
`"indented text with gaps"`, not the original spacing. Indentation-sensitive
tool output (diffs, tracebacks, YAML) can come out reshaped by the
redaction boundary even when no secret was present.

## What this explicitly does NOT catch

This is a conservative, pattern-based classifier, not a guarantee. Known
gaps, stated plainly so they are not mistaken for coverage:

- **Secrets embedded mid-sentence in natural language**, e.g. "the password
  is hunter2 for now" — `hunter2` is 7 characters, well under the 20-character
  floor for `high_entropy_token`, and there is no `PASSWORD=`-shaped
  assignment on the line, so nothing here catches it.
- **Multi-word or space-containing secrets** — the high-entropy detector
  requires an unbroken, whitespace-free token, so a secret split across
  spaces (e.g. copy-pasted with line wrapping, or a passphrase) is missed.
- **Secrets shorter than 20 characters or longer than 200 characters** —
  both bounds are hard cutoffs with no adaptive sizing.
- **Structurally distinctive but low-entropy identifiers** — a file path
  containing a real username (e.g. `/Users/alice/.ssh/id_rsa` or
  `C:\Users\alice\secrets.env`) is not redacted: path separators and
  lowercase-only alphabetic runs don't reliably trip the alnum-mixed,
  digit-and-letter shape the high-entropy detector requires, and there is no
  path- or username-specific detector. A path is redacted only incidentally,
  if some unrelated segment of it happens to look like a high-entropy
  token.
- **Command-line arguments that are semantically secrets but don't look
  like opaque tokens** — e.g. `--password hunter2` or `mysql -u root -phunter2`
  — are not redacted unless the value portion independently satisfies the
  high-entropy shape. A short, human-chosen password used as a literal CLI
  argument is exactly the case this system is weakest against.
- **Any provider-issued secret shape not in the explicit prefix list** —
  only GitHub token prefixes are special-cased; AWS (`AKIA...`), Slack
  (`xox...`), Stripe (`sk_live_...`), JWTs, and every other vendor's secret
  format relies entirely on falling into the generic high-entropy shape
  (which many of them do, but this is coincidental, not by design).
- **Object/array keys** — `redact_json` only rewrites string *values*; a key
  named `"password"` whose value is a short, low-entropy string still passes
  through unredacted.

Redaction is deliberately biased toward false positives over false
negatives (see the module doc comment in `redact.rs`): when in doubt, over-
redact rather than under-redact. The gaps above are underclaims to be
tracked as future detector work, not claims that the current set is
sufficient.

## Test coverage for the categories above

FORNX-19 adds tests confirming, empirically, which of the "does NOT catch"
categories above are and are not caught by the *existing* detector set (no
new detector was added — see "Why no new detector" below):

- A path containing a username (`/Users/alice/.ssh/id_rsa`) is **not**
  redacted by the current detectors.
- A short CLI-argument-shaped secret (`--password hunter2`) is **not**
  redacted.
- A long, high-entropy value passed as a literal shell argument (e.g.
  `--api-key sk_live_<~40-char high-entropy suffix>`) **is** redacted by
  the existing `high_entropy_token` detector, because the value itself —
  not the flag name — satisfies the generic shape.

### Why no new detector was added

The two gap categories named for this ticket (path-with-username,
shell-argument-shaped secret) were evaluated against the existing
`high_entropy_token` and `env_secret_assignment` detectors rather than
building bespoke path/argument parsers:

- A **long, high-entropy value used as a CLI argument** (e.g. an API key
  passed with `--api-key`) is already caught, because the redaction unit of
  work is the whitespace-delimited token, not the "assignment" or "flag"
  shape around it — the token itself is what's tested. Adding a
  flag-name-aware detector would be redundant with this case.
- A **path with a username** and a **short, low-entropy CLI secret** (e.g.
  `hunter2`) are genuine, confirmed gaps — but a purpose-built detector for
  either is out of scope for FORNX-19 (documentation + gap-*confirmation*,
  not new pattern-matching surface). They are recorded above as known,
  intentional non-coverage for a future ticket to close, consistent with
  "don't overclaim" rather than "add speculative detection."

## The cloud-egress gate

`fornax_types::privacy::cloud_sync_allowed()` reads the
`FORNAX_CLOUD_SYNC_ENABLED` environment variable and returns `true` only for
the exact values `"1"` or `"true"`/`"TRUE"`/any case-insensitive match of
`true` — every other value (including other truthy-looking strings like
`"yes"`) returns `false`. It is unset (`false`) by default: cloud sync is
opt-in, never assumed.

This repo contains **no cloud-sync/upload code** — that logic lives in the
separate `fornax-cloud` repository, deliberately (see
`docs/adr/0001-architecture-invariants.md`: no cloud dependency on the local
critical path). `cloud_sync_allowed()` is the policy primitive that
`fornax-cloud`'s uploader must consult before any network call; there is
currently no caller of it inside this repo other than its own unit test,
because there is nothing here that syncs to the cloud yet. Its presence here,
ahead of the uploader, is intentional (FORNX-33/FORNX-41): the gate exists
before there is anything for it to gate, so the uploader has no path to
ship without checking it.

## REDACTED / NOT_COLLECTED / UNAVAILABLE-style semantics

Fornax represents "this data is absent" with more than one vocabulary,
depending on what is absent and why. Do not conflate them:

### Signal availability (per-capability, `fornax_types::capabilities::SignalAvailability`)

Describes whether a given signal class was observable during a session, used
to gate whether a verifier may attempt verification at all
(`RuntimeCapabilities::is_observable`):

| State | Meaning |
|---|---|
| `Available` | Confirmed observable this session — the only state that may gate a verifier into attempting verification. |
| `Unsupported` | This runtime fundamentally cannot expose this signal class. |
| `Unavailable` | The signal exists in principle for this provider, but this session/version/config did not expose it. |
| `Redacted` | The signal was observed, then withheld by this privacy/redaction boundary before it could be reported as available. |
| `CollectionFailed` | Collection was attempted and failed (parse error, IO error, etc.) — distinct from never attempting collection. |
| `Unknown` | Ordinary absence: no adapter declared an opinion about this signal class. |
| `Unrecognized(String)` | Forward-compatibility catch-all for a state tag this binary doesn't recognize. |

Every state except `Available` reads as "not observable" for verification
purposes — there is no partial credit.

### Claim verdicts (five-state vocabulary, ADR 0001)

A claim is judged `VERIFIED` / `UNVERIFIED` / `CONTRADICTED` / `REVIEW` /
`UNAVAILABLE` from observed evidence. `UNAVAILABLE` here is the claim-level
outcome when the evidence needed to judge the claim was never observable
(often *because* the underlying signal was `Unavailable`, `Unsupported`, or
`Redacted` at the capability level above) — this vocabulary is never
collapsed to fewer states (ADR 0001).

### In-line text markers

Within redacted text/JSON itself, two literal markers appear:

- `[REDACTED]` — a single token replaced in place by `redact_text`/`redact_json`.
- `[REDACTED: possible secret assignment]` — a whole line replaced when it
  matched the `env_secret_assignment` shape.

There is no `NOT_COLLECTED` marker in this codebase today; "not collected"
is represented by the `SignalAvailability` states above (`Unavailable`,
`Unsupported`, `Unknown`), not by a distinct string literal.

## Related documents

- `docs/adr/0001-architecture-invariants.md` — five-state verdict vocabulary,
  no-cloud-dependency-on-local-critical-path invariant.
- `docs/research/adapter-capability-matrix.md` — what each provider adapter
  can and cannot observe, the source of most `Unsupported`/`Unavailable`
  determinations.
- `crates/fornax-types/src/redact.rs` — detector implementation and unit tests.
- `crates/fornax-types/src/privacy.rs` — the cloud-egress gate.
- `crates/fornax-types/src/capabilities.rs` — `SignalAvailability` definition.
