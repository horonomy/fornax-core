# Lane ↔ surface mapping

Jira: FORNX-230. This is the mechanism behind [`SKILL.md`](SKILL.md)'s
Step 2 — it turns FORNX-231's shared surface vocabulary
(`docs/release-candidate-evidence.md`) into the 8 verification lanes named
in FORNX-230's own scope, so lane selection is a mechanical join rather than
a judgment call made fresh per release.

A feature-delta item's `surfaces[]` (1 or more values) selects every lane
its surfaces map to. A lane is selected for this candidate if **any**
feature-delta item maps to it. This table is the single source of truth for
that join — extending it is a change to this file, reviewed like any other
policy change, never inferred ad hoc by a worker.

| Lane | Surfaces that select it | What the lane verifies |
|---|---|---|
| Local/runtime | `daemon_socket`, `cli` | Local daemon/socket behavior, CLI commands, fresh-checkout local flows. |
| Adapters/providers | `adapter_provider_input` | `fornax-hook-claude`/`fornax-hook-codex` input handling and event-shape correctness against the installed CLI. |
| Evidence/verifier semantics | `evidence_provenance`, `judge_replay_execution` | Five-state finding vocabulary correctness, evidence/provenance integrity, judge/replay execution. |
| Cloud/API/data | `cloud_identity_tenant`, `public_api_schema_migration`, `egress_redaction` | Cloud ingest/backend API behavior, tenant/identity authorization, schema/migration correctness, redaction-before-egress at the cloud boundary. |
| Browser/SaaS | `browser_rendering_injection`, `egress_redaction` | SaaS Evidence dashboard rendering, injection-surface checks (XSS-class), redaction-before-egress at the browser/dashboard boundary. |
| Docs/public claims | `ui_docs` | Release notes/docs/website claims match actual candidate behavior. |
| Reliability/migration | `event_transport`, `public_api_schema_migration` | Event transport correctness, restart/recovery, migration reversibility. |
| Release artifact/install | `enterprise_policy_deployment`, `sdk_plugin_trust`, `infra_config` | Build/tag/publish artifact identity, install/deployment posture, SDK/plugin trust boundary. |

`egress_redaction` is listed under both "Cloud/API/data" and "Browser/SaaS"
above (not a third, separate lane) because redaction-before-egress must be
verified at the boundary the data actually crosses, and a candidate
touching this surface may need it checked in more than one lane rather than
picking just one.

An item whose only surface is FORNX-231's unclassified fallback
(`infra_config` used as the "surface could not be determined" catch-all)
selects "Release artifact/install" at minimum — this keeps an unclassified
item from silently selecting zero lanes, matching FORNX-231's "unknown ⇒
never `COVERED`" principle applied to lane selection.

## Depth scaling by risk class

Once a lane is selected, `docs/release-assurance-policy.md`'s
assurance-depth-by-risk table decides how deep that lane runs — this file
does not restate that table. In short: `PATCH_LOW_RISK` runs only the
touched-surface P0 golden journeys mapped into a selected lane and reuses
green CI for the rest; `MAJOR_OR_GA` runs the full P0/P1/P2 sweep in every
lane regardless of which surfaces were actually touched.
