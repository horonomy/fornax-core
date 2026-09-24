//! Calibration/ablation benchmark harness (FORNX-95, parent epic FORNX-66).
//!
//! **Scope of this crate, stated plainly (owner directive):** this crate
//! builds the dataset-independent engineering FORNX-95 needs — a harness
//! that runs the REAL `fornax-verify` fusion/decision pipeline over frozen,
//! labeled trajectory input; metrics that distinguish evidence-unavailable
//! from incorrect; a per-sensor ablation sweep; and a versioned run
//! manifest. It does **not** contain, and must never be mistaken for, a real
//! labeled calibration dataset. No such dataset exists in this repository —
//! see this ticket's PR body for the search that confirmed that, and
//! [`dataset`]'s module docs for the structural refusal gate
//! (`LabelingProvenance::SyntheticMechanismTest` + `contains_synthetic_labels`
//! propagated onto every report) that keeps a synthetic mechanism-test run
//! from being read back as one.
//!
//! # Why a new crate, not a module inside `fornax-verify`
//!
//! `fornax-verify` is core verification logic — `fornax-daemon` depends on
//! it for the live claim path. This crate is a distinct concern: a
//! CLI-runnable offline benchmark tool that *consumes* `fornax-verify`'s
//! public policies without ever being on that live path itself (compare
//! `fornax-vcs`/`fornax-ci`, which are similarly separate "consumes core
//! types, runs as its own tool/binary" crates rather than modules inside
//! `fornax-verify` or `fornax-types`). Keeping it separate also means this
//! crate's own `[[bin]]` and its `clap`/`anyhow` dependencies never become
//! transitive dependencies of `fornax-daemon`.
//!
//! # Module map
//!
//! - [`dataset`] — the labeled-trajectory wire format (AC 5).
//! - [`harness`] — runs the real pipeline over a dataset under a
//!   [`harness::HarnessConfig`] (AC 1, AC 3's ablation lever).
//! - [`metrics`] — fixed-risk operational metrics with the
//!   evidence-unavailable/incorrect distinction (AC 3, AC 4).
//! - [`ablation`] — the per-sensor sweep (AC 2).
//! - [`manifest`] — the versioned, reproducible run manifest (AC 1).

pub mod ablation;
pub mod dataset;
pub mod harness;
pub mod manifest;
pub mod metrics;
