//! Portable integrity receipts (FORNX-350, parent epic FORNX-340 / Stage 8).
//!
//! Turns a Fornax finding into a portable, offline-inspectable,
//! tamper-evident artifact a downstream human, agent, CI pipeline, or
//! deployment gate can consume without trusting a prose summary.
//!
//! **What a receipt proves, and what it does not.** A receipt is not a
//! cryptographic proof that a semantic claim is true. It is a verifiable
//! package describing what claim was assessed, what evidence/version/
//! policy produced the finding, what remains missing, and whether the
//! package itself has been altered. Receipt authenticity/integrity never
//! proves the underlying semantic claim is true beyond the evidence
//! represented -- weak evidence, faithfully receipted, is still weak
//! evidence. See `docs/adr/0021-portable-integrity-receipts.md`.
//!
//! **Verification-only, by explicit owner decision (FORNX-350).** This
//! crate can verify a receipt signed by something else; it never signs one
//! in production. See [`fornax_types::receipt`]'s module docs for the
//! signing-domain/envelope layer this crate builds on, and [`verify::SignatureStatus::Unsigned`]
//! for how an unsigned receipt is represented -- explicitly, never as
//! invalid, and never as authenticated.
//!
//! # Module map
//!
//! - [`schema`] — the typed [`schema::ReceiptBody`]/[`schema::IntegrityReceipt`],
//!   canonical serialization, and content digest (AC1).
//! - [`issue`] — projects a live finding into a reference-only receipt
//!   (AC3: never embeds a raw payload).
//! - [`freshness`] — fail-closed expiry/clock-skew semantics (AC4).
//! - [`verify`] — dispatches a receipt artifact to signed/unsigned
//!   handling and reports [`verify::SignatureStatus`] (AC2).
//! - [`gate`] — the fail-closed ACCEPT/REJECT/HOLD/UNTESTED policy verdict
//!   over a [`verify::VerifiedReceipt`] (AC5).

pub mod freshness;
pub mod gate;
pub mod issue;
pub mod schema;
pub mod verify;
