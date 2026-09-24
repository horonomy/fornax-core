//! Deterministic replay engine (FORNX-98, epic FORNX-20): reproduces a
//! frozen agent trajectory's verifier/fusion outcome without re-running the
//! original adapter/provider.
//!
//! # Why a new crate, not an extension of `fornax-bench`
//!
//! `fornax-bench` (FORNX-95) already runs the real `fornax-verify`
//! fusion/decision pipeline over frozen `Claim`/`EvidenceGraph`/evidence-pool
//! input and stamps a versioned manifest onto the result — mechanically very
//! close to half of this ticket's scope, and [`manifest`]/[`engine`] below
//! deliberately mirror its conventions (`RunManifest`'s field shape,
//! `harness::run_harness`'s "sort before iterating, pure and sync" discipline)
//! rather than reinventing them.
//!
//! But FORNX-98's scope is broader than `fornax-bench`'s in a way that
//! matters for dependency hygiene: it must be able to rebuild a claim's
//! evidence from a *real adapter's* golden fixture (FORNX-98 AC 5), which
//! means depending on `fornax-adapter-conformance` and the concrete adapter
//! crates. `fornax-bench`'s own module docs are explicit that it deliberately
//! stays adapter-free — going through an adapter "would break AC 1
//! (reproducible from frozen inputs/config), since [replaying a native event]
//! is not a pure function of its input file" in the way `fornax-bench` wants
//! for a *calibration* run. That tension is real but not a contradiction:
//! this crate's replay step is still pure over its own frozen manifest (the
//! *manifest already contains* the rebuilt `Claim`/`Evidence`/`EvidenceGraph`,
//! not raw native provider events to renormalize on every replay) — only the
//! one-time *construction* of a manifest from a fixture touches an adapter,
//! and that step is exercised by this crate's tests, never by [`engine::replay`]
//! itself. Bolting adapter crates onto `fornax-bench` as non-dev dependencies
//! to get that one capability would blur its established boundary for every
//! other consumer of that crate. A new crate keeps `fornax-bench` unchanged
//! and gives the broader "adapter + verifier + fusion" replay scope a home
//! that can depend on adapters directly, following this repo's
//! module-doc-explains-crate-boundary convention (see `fornax-vcs`/`fornax-ci`).
//!
//! # What "replay" means here
//!
//! A [`manifest::ReplayManifest`] is a fully self-describing, frozen record
//! of one interpretation: which schema version produced it, which adapter
//! (provider + runtime version) observed the underlying session, which
//! fusion/decision policy (name + version) computed the recorded outcome,
//! which risk class and sensor-disable configuration were in effect, the
//! frozen `Claim`/evidence pool/evidence graph itself, and the
//! verdict/uncertainty/action that were recorded for it.
//!
//! [`engine::replay`] takes only that manifest as input, validates it
//! structurally ([`engine::ReplayError`] — never a panic, never a silent
//! empty result), and re-runs the *current* real
//! `fornax_verify::fusion::BaselineFusionPolicy` +
//! `fornax_verify::decision::DefaultRiskPolicy` pipeline over the frozen
//! input, pinned to the manifest's own `computed_at`. It never reads the
//! network, spawns a subprocess, or talks to an adapter/provider — see
//! `tests/no_side_effects.rs` for the structural check backing that
//! guarantee, and the crate's own dependency list in `Cargo.toml`, which
//! carries nothing capable of either. The result is a
//! [`engine::ReplayComparison`]: the live-computed outcome side by side with
//! the manifest's recorded one, plus explicit policy-name/version drift
//! fields so a version difference between "what produced the recorded
//! result" and "what this binary would compute today" is visible in the
//! output, never silently masked by recomputing under whichever policy
//! happens to be pinned today.

pub mod engine;
pub mod glue;
pub mod manifest;

pub use engine::{replay, validate_manifest, ReplayComparison, ReplayError};
pub use manifest::{build_manifest, ReplayManifest, REPLAY_MANIFEST_SCHEMA_VERSION};
