//! Honest acquisition outcomes -- mirrors
//! `fornax_types::experiment::ExperimentOutcome`'s existing discipline of
//! naming every non-success state explicitly rather than folding them into
//! a single failure/error case. Never fabricates negative evidence: a
//! probe that could not run produces `Unavailable`/`Refused`/`Failed`, not
//! an `Acquired` evidence row that pretends to have observed something.

use fornax_types::Evidence;

#[derive(Debug)]
pub enum AcquisitionOutcome {
    /// The probe ran and produced real, canonical evidence. Boxed:
    /// `Evidence` is far larger than every other variant here, and
    /// `clippy::large_enum_variant` wants that size difference contained in
    /// one heap allocation rather than paid on every `AcquisitionOutcome`
    /// value (same reasoning as `fornax-daemon`'s `FusionOutcome::Found`).
    Acquired(Box<Evidence>),
    /// The probe's own side-effect gate refused it -- an ungranted class,
    /// or a class this executor never approves regardless of policy
    /// (`FilesystemWriteOutsideWorktree`). Never conflated with
    /// `Unavailable`: this is a policy refusal, not an absence of data.
    Refused { reason: String },
    /// The target could not be resolved, contained, or found -- an honest
    /// absence, never evidence about the claim in either direction.
    Unavailable { reason: String },
    /// The probe was attempted and encountered a real execution error
    /// (e.g. an I/O error reading a file that does exist but is
    /// unreadable).
    Failed { reason: String },
    /// This candidate's `ProbeKind` has no implementation in this crate
    /// (FORNX-346 scope: only `VerifyArtifactHash`/`InspectVcsState`).
    Unsupported { reason: String },
}
