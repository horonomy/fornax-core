# ADR 0002: Repository, CI, and environment-isolation conventions

Status: Accepted
Date: 2026-08-28
Jira: FORNX-22/FORNX-23, informed by survey of `~/Bryant-Developments/horonomy/*`

## Context

The epic requires Fornax's Neon/GCP/CI conventions to match "existing Horonom
product conventions." A survey of `octans`/`ophiuchus`/`circinus`/
`official-website` found two divergent real precedents; this ADR picks one
per concern and records why, so it isn't re-derived per ticket.

## Decisions

### GitHub organization and repository topology (FORNX-21)

Fornax is a Horonomy product. Canonical org: `horonomy`
(https://github.com/horonomy) — no dedicated Fornax GitHub organization.
`fornax-core` was bootstrapped under a personal account and transferred via
native GitHub repository transfer once this was confirmed (2026-08-29),
preserving history/PRs/branches/tags.

Repository topology under `horonomy`:

```
Horonomy GitHub organization
├── fornax-core       PUBLIC   (this repo — local Rust runtime, adapters, CLI)
├── fornax-cloud      PRIVATE  (ingest, backend, SaaS frontend)
├── fornax-docs       PUBLIC   (technical documentation)
├── fornax-website    PUBLIC   (marketing/product site)
└── fornax-infra      PRIVATE  (Terraform, deployment config)
```

`fornax-cloud`/`fornax-docs`/`fornax-website`/`fornax-infra` are created when
their corresponding tickets actually need them — not speculatively. Always
verify the current ticket key live in Jira before citing it here; this ADR
has twice recorded a stale FORNX-<n> mapping after renumbering. No separate
GitHub organization per Horonomy product unless a future explicit owner
decision changes this.

### CI

Per-build-unit, path-filtered GitHub Actions workflows (not one monolith):
`ci.yml` (fmt/clippy/test, matches `circinus`'s pattern), later a separate
`infra.yml` (terraform fmt/validate only — no apply credentials in CI) and a
`workflow_dispatch`-only `relay-deploy.yml` once Beta infra exists (FORNX-35+).
Third-party actions pinned by commit SHA. `permissions: contents: read`
default. No push-to-deploy for infra — deploy workflows are manual dispatch
only, per `ophiuchus`'s ADR-0010 amendment (this was a deliberate correction
there after an unattended-apply incident risk was identified).

### Docs — distributed authoring, centralized publishing (superseded 2026-08-29)

Originally this ADR picked the `circinus`/`ophiuchus` precedent — one
Docusaurus site per product, no central aggregator repo. **Superseded by an
explicit owner directive (2026-08-29)**: Fornax uses a dedicated
`horonomy/fornax-docs` repo (public) that owns the Docusaurus shell, theme,
navigation, and centralized build/publish, aggregating content authored
close to the code (`fornax-core/docs/**`, `fornax-cloud/docs/public/**`) —
"distributed authoring + centralized publishing" as the epic originally
specified, not the single-site precedent.

Hosting stays reconciled with the rest of this ADR's one-domain-per-product
convention: the canonical URL is still `fornax.horo.run/docs` (no separate
`docs.*` subdomain), it's just that the content serving that path is now
built and owned by a separate repo rather than living inside
`fornax-website`'s own codebase. The actual routing (reverse proxy /
Cloudflare path rule from `fornax.horo.run/docs` to the `fornax-docs`
deploy) is Beta-infra work (FORNX-43, Cloudflare domain topology) and is not
implemented yet — recorded here as the intended hostname, not a live deploy.

`fornax-docs` was created and its MVP content shipped under FORNX-45.

### Terraform / environment isolation

Folder-per-environment (`infra/envs/beta/`, `infra/envs/prod/`), separate GCP
projects, separate GCS state buckets, `workflow_dispatch`-only deploys via
GitHub Environments, images digest-pinned, auth via Workload Identity
Federation (no service-account JSON keys) — matches both `ophiuchus` and
`circinus`. No decision needed; both repos agree here.

### Neon Postgres

The epic is explicit: **one Neon project, environment isolation by branches**
(matches `ophiuchus`'s pattern, not `circinus`'s later two-project reversal).
Followed as specified — `circinus`'s two-project reasoning (a leaked
project-scoped API key can reach every branch) is noted for awareness but not
adopted; if Fornax's Beta credential surface later proves as sensitive as
`circinus`'s billing/webhook surface, revisit via a new ADR, not silently.

### Repo layout

`src`-equivalent is `crates/` (Rust workspace, not `src/` — Rust convention
takes precedence over the Python-repo precedent here). `docs/adr/NNNN-kebab-title.md`
(MADR-lite, matches all four precedent repos). `.claude/CLAUDE.md` +
`AGENTS.md` (pointer only) + `README.md` — same four-file precedence chain
used across Horonom repos.

### Commits / branches

Gitmoji + scoped imperative subject (`✨ (scope): Description`), matching
observed `circinus` git log and the global CLAUDE.md commit policy. Branch
naming `<release>/FORNX-<n>/<type>/<snake_case_slug>`, matching the Horonom
family's `v<version>/<TICKET>/<type>/<slug>` pattern.

> **Superseded (FORNX-358, 2026-09-10):** "PR-only to `main`" described only
> the initial v0.0.1 release-freeze period. The actual, current convention —
> PRs target a single rolling integration branch (`next/v0.0.4` as of this
> writing), not `main` directly — is documented in `CONTRIBUTING.md`, the
> canonical source of truth per its own header. `main` stays the base only
> for release-line-scoped work (governance/branding, a release promotion).

## Consequences

- FORNX-45 (Docs) uses a dedicated `fornax-docs` repo per the 2026-08-29
  owner directive (superseding this ADR's original single-site stance);
  canonical hostname stays `fornax.horo.run/docs`, routing not yet deployed.
- FORNX-37 (Neon) uses one project + branches per the epic; the alternative
  two-project pattern is documented here as a known trade-off, not adopted.
