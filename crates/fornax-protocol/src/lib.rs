//! Agent Evidence Protocol (FORNX-391, parent epic FORNX-376 / Stage 9).
//!
//! Turns Fornax's internal trust-kernel wire types -- [`fornax_receipt::delegation::DelegationEnvelope`]
//! (FORNX-384), [`fornax_receipt::schema::IntegrityReceipt`] (FORNX-350),
//! [`fornax_receipt::assurance_case::AssuranceCase`] (FORNX-387) -- into a
//! vendor-neutral, versioned, independently-implementable interoperability
//! surface, so a second implementation that has never seen this crate's
//! source can still produce and verify a portable Fornax message. See
//! `docs/protocol/agent-evidence-protocol.md` for the published wire
//! specification and `crates/fornax-protocol-refclient` for a second,
//! independent implementation of that specification (FORNX-391 AC1/AC2).
//!
//! # Module map
//!
//! - [`canonical`] — the protocol's own canonical-JSON digest scheme,
//!   independent of any Rust struct's field order (why this exists, and why
//!   it differs from every internal digest in this repo, is explained in
//!   that module's docs).
//! - [`envelope`] — [`envelope::ProtocolEnvelope`]: version, capability
//!   declaration, canonical digest, and explicit forward-compatible
//!   unknown-field handling (AC1/AC3/AC4).
//! - [`capability`] — capability negotiation so an envelope relying on
//!   optional semantics a consumer does not implement is detected
//!   explicitly, never silently misread.
//! - [`objects`] — typed wrap/unwrap between [`envelope::ProtocolEnvelope`]
//!   and this repo's existing portable types, starting with
//!   [`fornax_receipt::delegation::DelegationEnvelope`] (AC2's headline
//!   "representative proof-carrying delegation/result").
//! - [`conformance`] — fixtures and a runner covering valid, malformed,
//!   tampered (at two independent layers), stale, unsupported-version,
//!   wrong-kind, and forward-compatible messages, each with a typed
//!   [`conformance::ConformanceOutcome`] (AC3).
//!
//! # Non-goals (unchanged from the ticket)
//!
//! No standards-body claim before external adoption. No replacement for
//! generic observability protocols. No transport requirement -- everything
//! here operates on plain bytes; how those bytes travel (file, local IPC,
//! HTTP, message bus) is a caller concern this crate is deliberately silent
//! about.

pub mod canonical;
pub mod capability;
pub mod conformance;
pub mod envelope;
pub mod objects;
