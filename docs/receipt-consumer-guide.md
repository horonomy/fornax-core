# Integrity Receipt Consumer Guide

A Fornax integrity receipt is a portable, offline-inspectable, tamper-evident
record of one finding — what claim was assessed, what evidence/policy
versions produced it, what remains missing, and whether the package itself
has been altered since issuance. This guide is for anything downstream that
wants to gate on one: a CI job, a GitHub Check, a deployment pipeline, or a
human reviewer.

## What a receipt proves, and what it does not

**A receipt is not a cryptographic proof that a semantic claim is true.**
It proves what Fornax observed and decided, and that the package describing
it hasn't been altered since issuance (when signed) or since deserialization
(digest-checked, for accidental edits, even unsigned). It never proves the
underlying claim is objectively correct — weak evidence, faithfully
receipted, is still weak evidence. See
`docs/adr/0021-portable-integrity-receipts.md` for the full reasoning.

## Producing a receipt

```bash
fornax receipt issue \
  --session <session-id> \
  --claim <claim-uuid> \
  --ttl-seconds 86400 \
  --out receipt.json
```

Re-fuses that claim's real, current evidence graph and issues a
reference-only receipt — no raw evidence payload is ever embedded, only
references plus fingerprints. Omitting `--ttl-seconds` issues a receipt with
no declared expiry, which the default gate policy treats as `Hold`
(insufficient to authorize), never as "fresh forever."

## Verifying a receipt

```bash
fornax receipt verify receipt.json
```

Prints the verification result and gate decision as JSON, and exits with
one of:

| Exit code | Outcome | Meaning |
|---|---|---|
| `0` | `Accept` | Every policy check was satisfied |
| `10` | `Reject` | A check actively failed (expired, tampered, disallowed verdict/action, critical evidence gap) |
| `11` | `Hold` | Not a detected defect, but insufficient to authorize (unsigned when a signature is required, no declared expiry) |
| `12` | `Untested` | The gate policy itself is uncalibrated or names no rules — never treated as a pass |

By default, `fornax receipt verify` applies
`ReceiptGatePolicy::require_proceed_no_critical_gaps()`: requires verdict
`Verified` and action `Proceed`, blocks on `NoEvidenceAtAll`/
`UnresolvedConflict`/`AllVotesDiscounted`, and requires a declared,
unexpired TTL. Pass `--policy <file.json>` for a different policy (see
`crates/fornax-cli/fixtures/receipts/` for two worked examples — an
uncalibrated policy that always resolves `Untested`, and a
signature-required policy that `Hold`s an unsigned receipt).

## Wiring it into a CI job (example — documentation only)

The snippet below shows the shape of a real integration; it is not tested
infrastructure in this repository (this repo's own `receipt-gate` CI job
runs `fornax receipt verify` against committed fixtures, not against a
live GitHub Check).

```yaml
- name: Verify integrity receipt
  run: |
    fornax receipt verify artifacts/receipt.json --policy ci-receipt-policy.json
    # exit 0 = merge may proceed; any other code fails this step.
```

## Signing (not built in this ticket)

Fornax does not sign receipts in production today — see
`docs/adr/0021-portable-integrity-receipts.md`'s "Verification-only, by
explicit owner decision" section. A receipt signed by something else can
be verified: point `fornax receipt verify` at a trust store via
`FORNAX_RECEIPT_TRUST_STORE=<path>` or `<home>/receipt-trust.json`
(mirroring `fornax_types::policy::trust_store`'s own precedence exactly),
containing the same `TrustedVerificationKeys` shape the policy-bundle trust
store uses. An unsigned receipt is never treated as invalid and never
silently treated as authenticated — it is reported as
`"signature": "unsigned"` in `fornax receipt verify`'s JSON output.
