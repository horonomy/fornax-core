//! Bounded execution boundary for FORNX-99's counterfactual experiment
//! contract (FORNX-100, epic FORNX-20 / discovery thesis HVDL-15).
//!
//! `fornax-types::experiment` (FORNX-99) defines what an experiment *is* —
//! [`fornax_types::experiment::ExperimentSpec`] in,
//! [`fornax_types::experiment::ExperimentOutcome`] out — as a pure,
//! serializable contract with no executor, sandbox, or isolation mechanism
//! of its own. This crate is that executor: given a validated spec, it
//! actually runs it, inside an ephemeral, isolated boundary the primary
//! working tree can never see, and produces the outcome.
//!
//! Standalone crate, not folded into `fornax-daemon` or any adapter — the
//! same reasoning `fornax-vcs`'s and `fornax-ci`'s module docs give for
//! their own crate boundaries: this has real, non-trivial execution logic
//! (filesystem staging, permission gating, timeout/cancellation, orphan
//! cleanup) that is neither the pure contract layer (`fornax-types`) nor a
//! provider adapter's per-hook translation.
//!
//! # Module map
//!
//! - [`policy`] — the second, host-level permission gate (AC2) that must
//!   agree with a spec's own allow-list before any side effect runs.
//! - [`staging`] — ephemeral, `std::fs`-based working-tree isolation (AC1),
//!   never a `git worktree add` subprocess (see that module's docs for why).
//! - [`orphan`] — startup sweep for staged directories a crashed process
//!   left behind (AC5).
//! - [`executor`] — ties the above together: two-layer gate, then stage,
//!   apply, observe, and unconditionally clean up (AC3).
//!
//! # Invoked on demand, never on the critical path
//!
//! Nothing in this crate runs as part of ordinary passive evidence
//! collection. It exists to be called explicitly when a hypothesis needs a
//! counterfactual test — matching `docs/adr/0001-architecture-invariants.md`
//! D2's "no cloud dependency on the local critical path" invariant by the
//! same shape `fornax-verify`'s optional `/api/judge` path already follows:
//! ordinary verification keeps working with this crate entirely unused.

pub mod executor;
pub mod orphan;
pub mod policy;
pub mod staging;

pub use executor::{
    Cancellation, ExperimentExecutor, InterventionApplier, InterventionObservation,
    InterventionObserver, DEFAULT_TIMEOUT_CEILING_SECONDS,
};
pub use orphan::{sweep_orphaned_staging_dirs, DEFAULT_ORPHAN_MAX_AGE};
pub use policy::{is_permitted, ExperimentPolicyError, GlobalExperimentPolicy};
pub use staging::{staging_root, StagedWorktree, StagingError, EXPERIMENT_STAGING_DIR};
