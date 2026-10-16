//! FORNX-450: operator-invoked Codex `hooks/list` host_trust verification.
//!
//! Implements `horonomy/internal-docs` ADR-0015 Option A. See
//! `docs/adr/0026-codex-host-trust-verification.md` for the full design and
//! the seven binding requirements this crate satisfies. This crate is
//! deliberately dependency-free of every `fornax-*` crate (see
//! `Cargo.toml`'s comment and `tests/boundary_invariants.rs`).
//!
//! Module map:
//! - [`protocol`] — NDJSON JSON-RPC framing over a generic `Read`/`Write`
//!   pair. No process spawning here; this module never touches a child
//!   process directly, only the pipes it's handed.
//! - [`identity`] — the Fornax-hook identity predicate (duplicated from
//!   `crates/fornax-cli/src/codex_hooks.rs`, not imported) and the
//!   `hooks.json` reader.
//! - [`verdict`] — reconciliation of expected hooks against a `hooks/list`
//!   response; the fail-closed aggregation rule.
//! - [`snapshot`] — before/after tripwire over the trust-bearing files.
//! - [`launch`] — the only module allowed to spawn a process. Not reachable
//!   from unit tests; see `tests/session_streams.rs` and
//!   `tests/verify_codex_e2e.rs` for how the spawn boundary is tested.

pub mod identity;
pub mod launch;
pub mod protocol;
pub mod snapshot;
pub mod verdict;
