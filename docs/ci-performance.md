# CI Performance — telemetry and benchmarks

Tracks empirical CI performance work for FORNX-237. Numbers here come from
real hosted GitHub Actions runs on this repo, not estimates.

## Timing telemetry

The `lint` and `rust` jobs in `.github/workflows/ci.yml` record wall-clock
timestamps around checkout, toolchain setup, cache restore, and the
build/test (or fmt/clippy) steps, and write a per-job table plus
`Swatinem/rust-cache`'s `cache-hit` output to `$GITHUB_STEP_SUMMARY`. This
makes the real critical path and cache hit/miss behavior visible in the
Actions UI (run summary page) without digging through raw step logs.

## sccache benchmark (2026-09-01) — rejected, not adopted

**Question:** does wiring `sccache` (`RUSTC_WRAPPER=sccache`) into the `rust`
job measurably improve build time on top of the `Swatinem/rust-cache`
caching already in place?

**Method:** ran the actual hosted CI twice on PR #75
(`feature/FORNX-237/feat/ci_telemetry_sccache_affected_surface` →
`next/v0.0.3`), using the timing telemetry above for both runs:

- Run A (baseline, no sccache) — [run 33481340396](https://github.com/horonomy/fornax-core/actions/runs/33481340396),
  `rust` job.
- Run B (sccache wired in via `cargo install sccache --version 0.17.0
  --locked`, `RUSTC_WRAPPER=sccache`, sccache's own cache dir backed by
  `actions/cache`) — [run 33481790195](https://github.com/horonomy/fornax-core/actions/runs/33481790195),
  `rust` job.

**Results (from each run's own timing-summary telemetry and step logs):**

| Phase | Run A (no sccache) | Run B (sccache) |
|---|---|---|
| checkout | ~0.7s | ~1.1s |
| toolchain setup | ~2.8s | ~0.8s |
| cache restore (rust-cache) | ~2.4s | ~5.4s |
| install sccache (`cargo install --locked`) | n/a | **~277.6s** |
| `cargo build --workspace` | ~53.0s | ~7.5s |
| `cargo test --workspace` | ~14.3s | ~13.8s |
| **job total** | **~73s** (reported 1m22s incl. runner setup) | **~306s** (reported 5m13s incl. runner setup) |

sccache's own `--show-stats` output for Run B:

```
Compile requests                     15
Compile requests executed             7
Cache hits                            0
Cache misses                          7
Cache hits rate                    0.00 %
Cache size                            4 MiB
```

**Finding: sccache is a net loss for this repo and must not be adopted.**

- Run B's `cargo build` step looks faster (7.5s vs 53s), but that's not an
  sccache effect — Run B's `target/` was already warm from Run A via
  `Swatinem/rust-cache` (same branch, same `Cargo.lock`), so only 7 of 15
  compile units needed recompiling at all. sccache's own stats show **0%
  cache hit rate** — every compile unit it touched was a cache miss, so it
  saved zero seconds of actual compilation.
- Installing sccache itself (`cargo install sccache --locked`, no prebuilt
  binary used) cost **~278 seconds** — roughly 3.8x the entire baseline job's
  total wall time. GitHub Actions runners are single-use/ephemeral per job,
  so this install cost is paid on every job run; it is not amortized like
  `Swatinem/rust-cache`'s restore of `target/`, which persists across runs
  via the GHA cache backend.
- Even a prebuilt sccache release binary (skipping the ~278s compile-from-source
  cost) would only remove the install-time penalty — it would not create any
  compile-time saving, because this repo's CI runs `cargo build` once and
  `cargo test` once per job (test reuses the already-built artifacts via
  Cargo's own incremental compilation), so there is no *redundant*
  same-job rustc invocation for sccache to deduplicate. sccache's value
  proposition (avoiding rebuilding the same object twice) does not apply
  here; `Swatinem/rust-cache`'s `target/` caching already gives equivalent-or-better
  results for the actual bottleneck (cross-run reuse), which is what this
  repo already had before FORNX-237.

**Decision:** sccache is not added to `ci.yml`. `Swatinem/rust-cache` (already
present) remains the sole caching strategy for Rust compilation. This
satisfies FORNX-237's AC ("Rust compile/test strategy is benchmarked;
chosen caching/target strategy improves measured feedback without creating
concurrent-worktree deadlocks") via a negative result backed by real
before/after numbers, per the ticket's own "measure before inventing infra"
directive — inventing infra that measurably loses is worse than the status
quo, so the status quo is kept.

Local shared-target-dir contention across concurrent worktrees (the
motivating problem for `sccache` on a developer machine, per
`~/CLAUDE.md`'s "Incident: Disk Pressure from Per-Worktree Rust Build
Artifacts") is a separate, developer-machine-only concern from hosted CI —
each hosted CI job runs on its own fresh runner with no shared `target-dir`
across concurrent jobs, so it does not reproduce that failure mode and isn't
addressed by this benchmark either way.

## Affected-surface (path-filter) selection

See the `paths-ignore` gate on the `lint` and `rust` jobs in `ci.yml` and its
inline comments for the conservative doc-only skip rule: any change touching
a `.rs` file, `Cargo.toml`/`Cargo.lock`, `.github/**`, or the contract/schema
surfaces (`crates/fornax-types/**`, `crates/fornax-adapter-conformance/**`)
always runs the full `lint`+`rust` suite. Only changes confined to
documentation/markdown paths skip them. No per-crate narrower selection was
implemented — this workspace's crates are interconnected enough (see
`Cargo.toml`'s `[workspace] members`) that a change to one crate can require
a full-workspace type-check to catch a downstream break, so narrower
selection is not safe here.
