# ADR-0027: A single fail-closed egress decision for every outbound path

- Status: Accepted (FORNX-464, v0.0.9)
- Supersedes: the "explicit non-goal" in ADR-0006 (`privacy::cloud_sync_allowed()`
  call sites are not rewired onto the policy model).

## Context

Before this ADR, whether data could leave the machine was answered differently
at every call site: one process-wide environment variable
(`FORNAX_CLOUD_SYNC_ENABLED`) gated the audit-checkpoint push; the policy poll
and the semantic judge had no egress gate; the separate `fornax-cloud`
uploader trusted only the env var; no HTTP client refused redirects; consent
was that env var, with no record of who agreed to what or when; and a
corporate "local-only" mode existed only as the env var's default-off state.

The founder mandate: **personal** is local-first dogfooding, with
periodic/monthly batch upload only under configured authorization and consent;
**corporate** is local-only, with no external evidence or work-data upload
without an explicitly approved corporate processing authorization. Corporate
must fail closed, not be a label.

## Decision

`fornax_types::egress::decide` is the one pure, deny-by-default decision. The
only way to obtain an `EgressPermit` is a successful `decide`. State (profile,
consents, allowlist) lives in `fornax-store` (migration 0021); every outbound
path asks `Store::decide_egress` on **every attempt**, so a revocation, a
removed allowlist entry or a switch to corporate stops the next request. Any
failure to read the state is a denial; capture and verification never call it,
so a denial cannot block them.

Precedence, strongest first:

1. **Corporate** never ships evidence or checkpoints. No consent, allowlist
   entry, environment variable or published policy overrides it. Entering
   corporate revokes every consent in the same transaction; leaving it needs
   an explicit confirmation. Its only outbound options are an allowlisted
   policy fetch (no evidence) and a semantic-judge gateway recorded with a
   corporate processing-authorization reference.
2. **Unconfigured** (the default; no profile chosen) ships nothing.
3. **Personal** may ship only under all of: a live, unexpired consent for that
   exact purpose and destination granted under the current profile
   generation; an allowlist entry; uploadable content classes; and the legacy
   `FORNAX_CLOUD_SYNC_ENABLED` kill switch. The env var can only tighten.

Content: only `evidence_metadata`, `finding_verdicts` and
`capability_declarations` are uploadable. Claim text, redacted evidence
payloads and unknown classes are never uploadable, and raw evidence is not
representable. Destinations match exactly (scheme, host, port, path on a
segment boundary); userinfo, query, fragment and non-loopback `http` are
refused. Every HTTP client refuses redirects and no longer falls back to a
default client that would follow them.

Judge versus upload: the semantic judge is a different purpose from evidence
upload. A judge grant never licenses upload, and the reverse. A loopback judge
needs no chain because nothing leaves the machine; a non-loopback judge needs
the persisted decision and never receives raw evidence.

The separate `fornax-cloud` uploader does not link this code. Core writes a
derived `$FORNAX_HOME/egress-projection.json`; the uploader fails closed
unless it authorizes `uploader_spool_stream`. That purpose is reserved and not
grantable in v0.0.9, so the uploader is inert.

## Consequences

- **Behaviour changes.** `FORNAX_CLOUD_SYNC_ENABLED=1` alone no longer enables
  the checkpoint push; `FORNAX_POLICY_POLL_URL` alone no longer polls (it needs
  `fornax egress allow-add --purpose policy_fetch`); the uploader goes inert.
  `fornax egress status` names what is denied.
- **Not delivered here.** There is no monthly or periodic batch upload, no
  outbox, no export-before-purge guarantee and no upload ledger. Raw evidence
  is still purged at 30 days regardless of export. These need a metadata-only
  envelope on the receiver and are a separate slice.
- **Tamper resistance.** Policy lives in the user-writable `fornax.db`. A local
  user who edits the database can bypass it; a root-owned managed corporate
  file is a future hardening.
- **Hostname matching** does not address DNS rebinding.
- **Audit.** Every change appends a hash-chained audit event; denials are
  logged with a bounded reason code, not audited.
- A recorded deviation from ADR-0012's per-profile stores: one store, with the
  profile generation and revoke-on-corporate giving the eligibility guarantee.
