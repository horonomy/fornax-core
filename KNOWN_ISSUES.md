# Known issues and limitations

This is a plain, discoverable list of currently-true limitations, pulled from
existing docs and the security policy. It is **not** a real-time status or
uptime page — Fornax has no hosted Beta/production service to report uptime
for; see [`README.md`](README.md#local-storage-privacy-and-known-limitations)
for the local-first architecture this reflects.

## Stability

- **On-disk schema is not yet guaranteed stable across releases.**
  `$FORNAX_HOME`'s SQLite schema may change between versions without a
  migration path, pre-1.0. See `README.md`'s "Local storage, privacy and
  known limitations" section.

## Version support

- **Fornax is pre-1.0.** Only the latest commit on `main` is supported for
  security fixes — there is no maintained release branch to backport to at
  this stage. See [`SECURITY.md`](SECURITY.md).
- There is no guaranteed response-time SLA for bug reports or security
  reports yet — see [`SUPPORT.md`](SUPPORT.md) and `SECURITY.md`'s "Response
  Expectations" section.

## Adapter/provider asymmetry

- **Claude Code and Codex CLI support is not symmetric.** Codex's hook
  surface is opt-in and can be admin-disabled, so its adapter relies
  primarily on tailing Codex's own rollout-file transcripts rather than
  hooks. See `docs/research/adapter-capability-matrix.md` for the exact,
  empirically verified differences.
- **opencode integration has no `install-opencode` command.** Unlike the
  Claude/Codex integrations, enabling opencode monitoring requires manually
  placing the plugin file (or referencing it by path) in the target
  project's opencode config. See the opencode section of `README.md` and
  `docs/research/0002-third-provider-fitness-report.md` for the capability
  gaps versus Claude Code/Codex.

## Reporting a new issue

If you hit something not listed here, please file it — see
[`SUPPORT.md`](SUPPORT.md).
