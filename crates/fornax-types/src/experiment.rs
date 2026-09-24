//! Counterfactual experiment contract (FORNX-99, epic FORNX-20 / discovery
//! thesis HVDL-15).
//!
//! This module defines a constrained, replayable, serializable data contract
//! for testing a hypothesis about a claim by comparing a baseline state
//! against the effect of a deliberate intervention. It is a **contract
//! only** — no experiment executor, sandbox, or isolation mechanism lives
//! here (that is FORNX-100), and no end-user CLI/UX flow lives here either
//! (that is FORNX-101). Nothing in this module spawns a process, mutates a
//! filesystem, or issues a network call; it only describes, in typed and
//! versioned form, what such an execution would be permitted to do and what
//! it produced.
//!
//! # Guardrails this contract encodes (epic FORNX-67)
//!
//! - **Side effects are explicit, never inferred.** [`SideEffectAllowList`]
//!   is empty by default — both when constructed with
//!   [`SideEffectAllowList::default`] and when a wire payload omits
//!   `allowed_side_effects` entirely (`#[serde(default)]` on the wire
//!   struct). An empty list means read-only; nothing here scans a command
//!   string, intervention `params`, or any other field to *infer* what side
//!   effects an experiment will have. A caller wanting a mutating
//!   experiment must name every [`SideEffectClass`] it needs, explicitly.
//! - **Failed/blocked/unsupported/inconclusive experiments cannot be
//!   interpreted as contradictory evidence.** [`ExperimentOutcome`] is a
//!   closed five-variant enum, but only [`ExperimentOutcome::Completed`]
//!   carries an [`EvidenceRelation`] comparison
//!   ([`ExperimentOutcome::hypothesis_relation`] returns `None` for every
//!   other variant, both in Rust and on the wire — see the module tests).
//!   `Inconclusive`/`Blocked`/`Unsupported`/`Failed` each carry only a
//!   `reason: String`; there is no field on any of them a caller could
//!   coerce into looking like a comparison result.
//! - **Every completed result links back to its evidence and hypothesis.**
//!   [`CompletedExperiment`]'s `baseline_evidence_ids`,
//!   `intervention_evidence_ids`, and `hypothesis_claim_id` are non-optional
//!   fields, and [`CompletedExperiment::new`] is the only public
//!   constructor — it rejects empty baseline/intervention id lists rather
//!   than merely documenting that they should be populated (AC4;
//!   `Vec::is_empty()` still type-checks, so the constructor is what makes
//!   this a real guarantee rather than a convention).
//! - **An experiment is evidence, not a competing source of truth.** This
//!   module composes with [`crate::graph`] rather than duplicating it: a
//!   completed experiment's baseline/intervention evidence references are
//!   ordinary [`crate::Evidence`]/[`uuid::Uuid`] ids a caller is expected to
//!   have already linked into the [`crate::EvidenceGraph`] for
//!   `hypothesis_claim_id` via ordinary [`crate::EvidenceLink`]s — nothing
//!   here introduces a parallel claim/evidence store.
//! - **No implicit cloud/network access.** [`SideEffectClass::NetworkCall`]
//!   exists in the closed vocabulary precisely so a network-touching
//!   experiment must say so explicitly; it is never included in any default
//!   allow-list this module constructs (ADR-0001 D2).
//! - **No global trust score.** Provenance fields below name concrete
//!   environment/tool/runtime versions (mirroring
//!   `fornax-adapter-conformance::fixtures::FixtureMetadata`'s
//!   `provider_runtime_version` naming), never an aggregate trust/reliability
//!   number.
//!
//! # Versioning and replay (AC1)
//!
//! [`ExperimentSpec`] follows `crate::extension::ExtensionEnvelope`'s
//! versioning idiom: a `schema_version` field gates deserialization via
//! [`ExperimentSpecWire`]'s `TryFrom` (an unsupported version fails loudly,
//! see [`SUPPORTED_EXPERIMENT_SCHEMA_VERSIONS`]), while any top-level JSON
//! key this binary's struct doesn't name is preserved verbatim via a
//! `#[serde(flatten)] unknown` catch-all rather than silently dropped. A
//! spec additionally carries its own `version: u32`, independent of
//! `schema_version` — re-running the same experiment id with a changed
//! baseline/intervention is a new *spec version* of that id, not a new id,
//! which is what "replayable" means at this contract layer: the same
//! `(id, version)` spec, replayed later by FORNX-100/98's replay engine
//! against the same frozen evidence, is expected to be reproducible. This
//! module defines the serializable, versioned shape that guarantee rests
//! on; it does not itself implement replay.
//!
//! # Extension point without provider conditionals (epic FORNX-67 AC)
//!
//! [`ExperimentKind`] is a small closed set of provider-agnostic
//! intervention shapes core replay logic (FORNX-100) can switch on
//! exhaustively, plus one [`ExperimentKind::Custom`] escape hatch (a plain
//! `String` tag) for anything else — mirroring
//! `crate::extension::ContentClass::Unrecognized`'s forward-compatible
//! pattern. A provider-specific experiment variant therefore never requires
//! adding a `match provider { .. }` arm to core dispatch: it rides
//! `ExperimentKind::Custom("claude_code:thinking_block_probe")` (or
//! whatever tag it needs) plus [`Intervention::provider_extension`], an
//! ordinary [`ExtensionEnvelope`] — the same escape hatch
//! [`crate::Evidence::extension`] already uses, not a new wrapper type.
//!
//! # Out of scope
//!
//! - Executing an intervention, sandboxing, or filesystem/process isolation
//!   (FORNX-100).
//! - Any CLI/UX flow for authoring or reviewing an experiment (FORNX-101).
//! - A generic workflow/scripting language: [`StopCondition`] and
//!   [`SideEffectClass`] are closed enums, never predicate strings or
//!   expressions, exactly so this contract cannot grow into one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::extension::ExtensionEnvelope;
use crate::graph::EvidenceRelation;
use crate::SignalClass;

/// The `schema_version` values this binary knows how to interpret for
/// [`ExperimentSpec`]. See [`crate::extension::SUPPORTED_EXTENSION_SCHEMA_VERSIONS`]
/// for the precedent this mirrors.
pub const SUPPORTED_EXPERIMENT_SCHEMA_VERSIONS: &[u32] = &[1];

/// The `schema_version` a newly-constructed [`ExperimentSpec`] stamps.
pub const EXPERIMENT_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------
// Side-effect permissions (AC2: explicit, never inferred)
// ---------------------------------------------------------------------

/// Closed vocabulary of side-effect classes an experiment's intervention may
/// need permission for. Deliberately excludes any read-only marker — the
/// *absence* of every class here (an empty [`SideEffectAllowList`]) already
/// means read-only; adding a `ReadOnly` member would let a spec claim
/// read-only-ness as an entry in an otherwise-populated allow-list instead
/// of it being the list's natural empty state, undermining "empty = deny
/// everything but reads."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    /// A mutation confined to a disposable/ephemeral worktree FORNX-100's
    /// executor is responsible for provisioning and discarding — never the
    /// caller's real working tree or any production state.
    EphemeralWorktreeMutation,
    /// Spawning a subprocess (a compiler, a test runner, a git invocation)
    /// scoped to the experiment's own ephemeral environment.
    ProcessSpawn,
    /// Any outbound or inbound network call. Never included in a default
    /// allow-list this module constructs (ADR-0001 D2, "no cloud dependency
    /// on the local critical path").
    NetworkCall,
    /// A filesystem write outside the ephemeral worktree boundary — the
    /// class an executor must treat as the highest-risk permission, since
    /// it can touch state the experiment does not own.
    FilesystemWriteOutsideWorktree,
}

/// Explicit, closed allow-list of [`SideEffectClass`]es an [`ExperimentSpec`]
/// permits its intervention to perform. **Deny-by-default**: both
/// [`Self::default`] and deserializing a wire payload that omits
/// `allowed_side_effects` entirely produce an empty list — see the module
/// tests for the deserialization case specifically, which is the path a
/// real caller actually exercises.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SideEffectAllowList(Vec<SideEffectClass>);

impl SideEffectAllowList {
    /// Build an allow-list from an explicit set of classes. Deduplicates and
    /// canonically orders its contents so two allow-lists built from the
    /// same set, in any order, compare equal and serialize identically.
    pub fn new(classes: impl IntoIterator<Item = SideEffectClass>) -> Self {
        let mut v: Vec<SideEffectClass> = classes.into_iter().collect();
        v.sort();
        v.dedup();
        Self(v)
    }

    /// `true` if `class` is explicitly permitted.
    pub fn permits(&self, class: SideEffectClass) -> bool {
        self.0.contains(&class)
    }

    /// `true` if this allow-list permits nothing at all — the deny-by-default
    /// state, and the only state a read-only experiment can be in.
    pub fn is_read_only(&self) -> bool {
        self.0.is_empty()
    }

    /// The permitted classes, in canonical order.
    pub fn classes(&self) -> &[SideEffectClass] {
        &self.0
    }
}

// ---------------------------------------------------------------------
// Hypothesis / baseline / intervention / stop conditions
// ---------------------------------------------------------------------

/// What the intervention is predicted to change, expressed against a
/// [`SignalClass`] rather than only as free text (epic FORNX-67 guardrail:
/// "causal claims require intervention/replay evidence, not merely an LLM
/// explanation").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedObservation {
    pub signal_class: SignalClass,
    /// Human-readable description of what a passing observation looks like
    /// for this signal class. Free text, but always paired with a structured
    /// `signal_class` above — never the sole way an observation is named.
    pub description: String,
}

/// A structured reference to the claim/evidence question an experiment
/// tests, plus what observing the intervention is expected to show.
/// `narrative` may add human framing alongside the structured fields, but is
/// never the only linkage back to a claim — see module docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    /// The [`crate::Claim`] this experiment tests.
    pub claim_id: Uuid,
    pub expected_observations: Vec<ExpectedObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrative: Option<String>,
}

/// The pre-intervention state an experiment compares against, and the
/// evidence already establishing it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub description: String,
    /// [`crate::Evidence`] ids establishing the pre-intervention state.
    /// Populated by the caller from evidence already collected/linked
    /// against `Hypothesis::claim_id`; this module does not collect it.
    pub evidence_ids: Vec<Uuid>,
}

/// A small, closed set of provider-agnostic intervention shapes core replay
/// logic (FORNX-100) can switch on exhaustively, plus [`Self::Custom`] as a
/// forward-compatible/provider-specific escape hatch — see module docs'
/// "Extension point without provider conditionals" section. Never a command
/// string: what an [`ExperimentKind`] concretely does is FORNX-100's job to
/// define and execute, this type only names *which* shape it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentKind {
    /// Revert a file (or set of files) to the state recorded in `Baseline`
    /// before observing the claim's evidence again.
    RevertFileToBaseline,
    /// Substitute a different recorded/synthetic tool result in place of
    /// what a provider actually returned, then observe downstream evidence.
    SubstituteToolResult,
    /// Disable a named sensor for the duration of the experiment, to test
    /// whether a claim's evidence depends on that sensor's output.
    DisableSensor,
    /// Forward-compatible/provider-specific escape hatch for a kind this
    /// binary's core dispatch does not recognize by name. Carries only an
    /// opaque tag — core logic must never require a wildcard-then-panic
    /// match on this variant's contents; a caller with a `Custom` kind is
    /// expected to route on `Intervention::provider_extension` instead.
    #[serde(untagged)]
    Custom(String),
}

/// The deliberate mutation/intervention an experiment applies, and the
/// structured parameters FORNX-100's executor interprets. `params` is opaque
/// JSON exactly like `ExtensionEnvelope::fields` — this module treats it as
/// inert data, never inspecting or dispatching on its contents to decide
/// side-effect permissions (see [`SideEffectAllowList`]'s doc comment: side
/// effects are named explicitly, never inferred from any field here).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Intervention {
    pub kind: ExperimentKind,
    pub description: String,
    #[serde(default)]
    pub params: serde_json::Value,
    /// Provider-specific detail this intervention needs, when `kind` is
    /// [`ExperimentKind::Custom`] or a core kind needs provider-specific
    /// extra context. `None` is the common case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_extension: Option<ExtensionEnvelope>,
}

/// Closed vocabulary of conditions that stop an experiment's execution
/// (FORNX-100's job to enforce; this module only names the vocabulary).
/// Deliberately closed, not a predicate string or expression — see module
/// docs' "not a generic workflow language" line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopCondition {
    /// Stop once this many observations of the expected signal have been
    /// collected.
    ObservationCountReached { count: u32 },
    /// Stop once this many seconds have elapsed since the experiment began.
    TimeoutElapsed { max_seconds: u64 },
    /// Stop once every [`ExpectedObservation`] has been satisfied.
    ExpectedObservationMet,
    /// Stop immediately if the intervention attempts a side effect outside
    /// its [`SideEffectAllowList`] — a safety condition every experiment
    /// implicitly carries, named explicitly so it is inspectable rather than
    /// assumed.
    SafetyPolicyViolated,
    /// Stop immediately if a side effect occurs that was not anticipated by
    /// any [`SideEffectClass`] the spec named, even one nominally within an
    /// otherwise-permitted class's scope (e.g. a filesystem write landing
    /// outside the ephemeral worktree despite `EphemeralWorktreeMutation`
    /// being permitted).
    UnexpectedSideEffectDetected,
}

// ---------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------

/// Environment/tool/runtime provenance for one [`ExperimentSpec`] (epic
/// FORNX-67 AC). Deliberately concrete named-version fields, never an
/// aggregate trust/reliability score — see module docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExperimentProvenance {
    /// RFC3339 timestamp this spec was authored — caller-supplied, never
    /// read from the clock inside this module (see the "Clock purity" note
    /// on [`ExperimentSpec::new`]).
    pub created_at: String,
    /// Identity of whatever authored this spec (a person, a coding agent
    /// session id, an automated proposer) — free text, no closed vocabulary
    /// imposed here.
    pub created_by: String,
    /// Where this experiment is scoped to run, e.g. `"worktree:<path>"` or
    /// `"ci"` — never implies production or a shared environment.
    pub environment: String,
    /// This contract-producing tool's own version (e.g. `fornax-cli`'s
    /// version), independent of `runtime_versions` below.
    pub tool_version: String,
    /// Named runtime/tool versions relevant to reproducing this experiment
    /// (e.g. `{"rustc": "1.82.0", "claude_code": "1.2.3"}`), mirroring
    /// `fornax-adapter-conformance::fixtures::FixtureMetadata`'s
    /// `provider_runtime_version` naming precedent. A `BTreeMap` for
    /// canonical, replay-stable ordering.
    #[serde(default)]
    pub runtime_versions: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------
// ExperimentSpec
// ---------------------------------------------------------------------

/// A constrained, replayable, versioned specification of one counterfactual
/// experiment (FORNX-99). See the module docs for the full guardrail set
/// this type enforces. Deserialization is asymmetric with serialization,
/// matching [`ExtensionEnvelope`]'s precedent: this type always *serializes*
/// its full named-field shape plus any preserved unknown fields, but
/// *deserializes* through [`ExperimentSpecWire`] so an incompatible
/// `schema_version` is rejected before construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ExperimentSpecWire")]
pub struct ExperimentSpec {
    pub schema_version: u32,
    pub id: Uuid,
    /// This experiment id's own version — a re-run with a changed
    /// baseline/intervention is a new version of the same `id`, never a
    /// mutation of a previously-recorded version (AC1 replayability: a past
    /// version stays byte-identical and independently replayable).
    pub version: u32,
    pub session_id: String,
    pub hypothesis: Hypothesis,
    /// Free-text preconditions that must hold before the experiment begins
    /// (e.g. "target file exists", "no other experiment is running against
    /// this claim"). Unlike `hypothesis`/outcome comparisons, preconditions
    /// are not evidence-bearing claims about causality, so no structured
    /// evidence reference is required here.
    #[serde(default)]
    pub preconditions: Vec<String>,
    pub baseline: Baseline,
    pub intervention: Intervention,
    pub stop_conditions: Vec<StopCondition>,
    /// Deny-by-default — see [`SideEffectAllowList`].
    #[serde(default)]
    pub allowed_side_effects: SideEffectAllowList,
    pub provenance: ExperimentProvenance,
    /// Extension point for spec-level provider-specific data that doesn't
    /// belong on `Intervention::provider_extension` specifically (e.g. a
    /// provider-specific stop-condition detail). `None` is the common case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<ExtensionEnvelope>,
    /// Any top-level JSON key present on the wire that this binary's struct
    /// does not name above — preserved verbatim, matching
    /// [`ExtensionEnvelope::unknown`]'s precedent.
    #[serde(flatten)]
    pub unknown: serde_json::Map<String, serde_json::Value>,
}

impl ExperimentSpec {
    /// Construct a fresh spec stamped with the current
    /// [`EXPERIMENT_SCHEMA_VERSION`] and no unknown fields. `allowed_side_effects`
    /// defaults to deny-by-default unless the caller passes a non-empty
    /// [`SideEffectAllowList`] explicitly — this constructor never grants a
    /// permission on the caller's behalf. `provenance.created_at` (inside
    /// `provenance`) must be supplied by the caller — this constructor never
    /// reads the clock itself, so the same inputs always produce the same
    /// spec (byte-identical modulo `id`/explicit fields), which is what
    /// keeps this contract genuinely replayable rather than merely
    /// versioned.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        version: u32,
        session_id: impl Into<String>,
        hypothesis: Hypothesis,
        baseline: Baseline,
        intervention: Intervention,
        stop_conditions: Vec<StopCondition>,
        allowed_side_effects: SideEffectAllowList,
        provenance: ExperimentProvenance,
    ) -> Self {
        Self {
            schema_version: EXPERIMENT_SCHEMA_VERSION,
            id,
            version,
            session_id: session_id.into(),
            hypothesis,
            preconditions: Vec::new(),
            baseline,
            intervention,
            stop_conditions,
            allowed_side_effects,
            provenance,
            extension: None,
            unknown: serde_json::Map::new(),
        }
    }
}

/// Wire shape accepted on deserialization. Structurally identical to
/// [`ExperimentSpec`]; exists only so [`TryFrom`] can gate on
/// `schema_version` before the domain type is constructed, and so
/// `allowed_side_effects` defaults to empty (deny) when absent from the
/// wire payload entirely — see the module tests for why this specific path
/// (omission, not just `SideEffectAllowList::default()`) is the one that
/// matters.
#[derive(Debug, Deserialize)]
struct ExperimentSpecWire {
    schema_version: u32,
    id: Uuid,
    version: u32,
    session_id: String,
    hypothesis: Hypothesis,
    #[serde(default)]
    preconditions: Vec<String>,
    baseline: Baseline,
    intervention: Intervention,
    stop_conditions: Vec<StopCondition>,
    #[serde(default)]
    allowed_side_effects: SideEffectAllowList,
    provenance: ExperimentProvenance,
    #[serde(default)]
    extension: Option<ExtensionEnvelope>,
    #[serde(flatten)]
    unknown: serde_json::Map<String, serde_json::Value>,
}

impl TryFrom<ExperimentSpecWire> for ExperimentSpec {
    type Error = String;

    fn try_from(w: ExperimentSpecWire) -> Result<Self, Self::Error> {
        if !SUPPORTED_EXPERIMENT_SCHEMA_VERSIONS.contains(&w.schema_version) {
            return Err(format!(
                "incompatible ExperimentSpec schema_version {}: this binary supports {:?}",
                w.schema_version, SUPPORTED_EXPERIMENT_SCHEMA_VERSIONS
            ));
        }
        Ok(ExperimentSpec {
            schema_version: w.schema_version,
            id: w.id,
            version: w.version,
            session_id: w.session_id,
            hypothesis: w.hypothesis,
            preconditions: w.preconditions,
            baseline: w.baseline,
            intervention: w.intervention,
            stop_conditions: w.stop_conditions,
            allowed_side_effects: w.allowed_side_effects,
            provenance: w.provenance,
            extension: w.extension,
            unknown: w.unknown,
        })
    }
}

// ---------------------------------------------------------------------
// ExperimentOutcome / ExperimentResult
// ---------------------------------------------------------------------

/// A [`ExperimentOutcome::Completed`] result: the only variant permitted to
/// carry a comparison between baseline and intervention evidence (AC3). The
/// only public constructor, [`Self::new`], rejects empty
/// `baseline_evidence_ids`/`intervention_evidence_ids` — see module docs'
/// "Every completed result links back to its evidence and hypothesis"
/// section for why this must be enforced at construction, not merely
/// documented.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletedExperiment {
    /// The claim this experiment tested — duplicated from the originating
    /// [`Hypothesis::claim_id`] so a `CompletedExperiment` is
    /// self-describing without requiring its `ExperimentSpec` alongside it.
    pub hypothesis_claim_id: Uuid,
    /// How the intervention's observed evidence relates to the hypothesis
    /// under test — reuses [`EvidenceRelation`] rather than inventing a
    /// second three/five-state vocabulary alongside it (see module docs).
    pub hypothesis_relation: EvidenceRelation,
    /// [`crate::Evidence`] ids establishing the pre-intervention state.
    /// Never empty — see [`Self::new`].
    pub baseline_evidence_ids: Vec<Uuid>,
    /// [`crate::Evidence`] ids observed as a result of the intervention.
    /// Never empty — see [`Self::new`].
    pub intervention_evidence_ids: Vec<Uuid>,
    pub summary: String,
}

impl CompletedExperiment {
    /// The only way to construct a [`CompletedExperiment`]. Returns `Err`
    /// if either evidence id list is empty, rather than silently accepting
    /// a "completed" result with nothing to point back to (AC4).
    pub fn new(
        hypothesis_claim_id: Uuid,
        hypothesis_relation: EvidenceRelation,
        baseline_evidence_ids: Vec<Uuid>,
        intervention_evidence_ids: Vec<Uuid>,
        summary: impl Into<String>,
    ) -> Result<Self, String> {
        if baseline_evidence_ids.is_empty() {
            return Err(
                "CompletedExperiment requires at least one baseline evidence id".to_string(),
            );
        }
        if intervention_evidence_ids.is_empty() {
            return Err(
                "CompletedExperiment requires at least one intervention evidence id".to_string(),
            );
        }
        Ok(Self {
            hypothesis_claim_id,
            hypothesis_relation,
            baseline_evidence_ids,
            intervention_evidence_ids,
            summary: summary.into(),
        })
    }
}

/// Closed, five-state result vocabulary for one experiment run (FORNX-99
/// AC, matching the ticket's own listed states). **Never widened with a
/// catch-all/`Unrecognized` variant** — unlike `ContentClass`, a sixth
/// result state is a real, versioned schema change to this contract, not
/// forward-compatible noise (mirroring [`crate::Verdict`]'s own closed,
/// never-collapsed five-state vocabulary, ADR-0001 D4).
///
/// Only [`Self::Completed`] carries a comparison
/// ([`Self::hypothesis_relation`] returns `None` for every other variant).
/// The other four variants each carry only a `reason: String` — there is no
/// field on any of them a caller could read as "the intervention
/// contradicted the hypothesis" (AC3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentOutcome {
    /// The experiment ran to completion and produced a real comparison.
    Completed(CompletedExperiment),
    /// The experiment ran but its evidence did not resolve the hypothesis
    /// either way (an honest "we tried and can't tell" — never conflated
    /// with `Completed` carrying a `Neutral` relation, and never treated as
    /// contradicting evidence).
    Inconclusive { reason: String },
    /// The experiment could not run at all — a precondition failed, a
    /// safety/stop condition fired before any comparison was possible, or a
    /// side effect outside the allow-list was attempted. Never evidence
    /// about the hypothesis in either direction.
    Blocked { reason: String },
    /// This experiment's kind/environment is not supported by the executor
    /// that attempted it (e.g. an `ExperimentKind::Custom` tag no available
    /// executor recognizes). Distinct from `Failed`: nothing was attempted
    /// and failed, the capability to attempt it did not exist.
    Unsupported { reason: String },
    /// The experiment was attempted and encountered an execution error
    /// (e.g. the executor itself errored) before producing a comparison.
    /// Never conflated with a `Completed` result carrying
    /// `EvidenceRelation::Contradicts`.
    Failed { reason: String },
}

impl ExperimentOutcome {
    /// The comparison this outcome carries, if any. `None` for every
    /// variant except [`Self::Completed`] — this is the AC3 guarantee as a
    /// callable function rather than only a doc comment: any caller that
    /// wants to interpret an outcome as evidence must go through this
    /// method (or match on `Completed` directly) and cannot get a relation
    /// out of `Blocked`/`Failed`/`Unsupported`/`Inconclusive` no matter how
    /// it is pattern-matched.
    pub fn hypothesis_relation(&self) -> Option<EvidenceRelation> {
        match self {
            ExperimentOutcome::Completed(c) => Some(c.hypothesis_relation),
            ExperimentOutcome::Inconclusive { .. }
            | ExperimentOutcome::Blocked { .. }
            | ExperimentOutcome::Unsupported { .. }
            | ExperimentOutcome::Failed { .. } => None,
        }
    }
}

/// The result of running one [`ExperimentSpec`] (a specific `id` + `version`
/// pair), produced by FORNX-100's executor. This module defines only the
/// shape; nothing here computes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExperimentResult {
    pub experiment_id: Uuid,
    pub experiment_version: u32,
    pub outcome: ExperimentOutcome,
    /// RFC3339 timestamp, supplied by the caller that ran the experiment —
    /// never read from the clock inside this module.
    pub computed_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hypothesis() -> Hypothesis {
        Hypothesis {
            claim_id: Uuid::new_v4(),
            expected_observations: vec![ExpectedObservation {
                signal_class: SignalClass::ProcessResult,
                description: "exit code changes after reverting the file".into(),
            }],
            narrative: Some("if the file caused the failure, reverting it fixes it".into()),
        }
    }

    fn baseline() -> Baseline {
        Baseline {
            description: "file at HEAD before intervention".into(),
            evidence_ids: vec![Uuid::new_v4()],
        }
    }

    fn intervention() -> Intervention {
        Intervention {
            kind: ExperimentKind::RevertFileToBaseline,
            description: "revert src/main.rs to baseline".into(),
            params: serde_json::json!({"path": "src/main.rs"}),
            provider_extension: None,
        }
    }

    fn provenance() -> ExperimentProvenance {
        ExperimentProvenance {
            created_at: "2026-01-01T00:00:00Z".into(),
            created_by: "test-harness".into(),
            environment: "worktree:fornax-FORNX-99-counterfactual".into(),
            tool_version: "fornax-cli-0.0.4".into(),
            runtime_versions: BTreeMap::from([("rustc".to_string(), "1.82.0".to_string())]),
        }
    }

    fn spec() -> ExperimentSpec {
        ExperimentSpec::new(
            Uuid::new_v4(),
            1,
            "s1",
            hypothesis(),
            baseline(),
            intervention(),
            vec![StopCondition::TimeoutElapsed { max_seconds: 60 }],
            SideEffectAllowList::new([SideEffectClass::EphemeralWorktreeMutation]),
            provenance(),
        )
    }

    // --- AC1: ExperimentSpec is serializable/versioned/replayable ---------

    #[test]
    fn experiment_spec_round_trips_through_json() {
        let s = spec();
        let json = serde_json::to_string(&s).unwrap();
        let back: ExperimentSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn experiment_spec_new_stamps_current_schema_version_and_empty_unknown() {
        let s = spec();
        assert_eq!(s.schema_version, EXPERIMENT_SCHEMA_VERSION);
        assert!(s.unknown.is_empty());
        assert!(s.extension.is_none());
    }

    #[test]
    fn unknown_top_level_field_on_a_compatible_version_survives_round_trip() {
        let mut value = serde_json::to_value(spec()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("future_field".to_string(), serde_json::json!("noise"));
        let parsed: ExperimentSpec = serde_json::from_value(value).unwrap();
        assert_eq!(
            parsed.unknown.get("future_field"),
            Some(&serde_json::json!("noise"))
        );
        let reser = serde_json::to_value(&parsed).unwrap();
        assert_eq!(reser["future_field"], serde_json::json!("noise"));
    }

    #[test]
    fn truly_incompatible_schema_version_fails_explicitly_rather_than_silently_parsing() {
        let mut value = serde_json::to_value(spec()).unwrap();
        value["schema_version"] = serde_json::json!(999);
        let err = serde_json::from_value::<ExperimentSpec>(value).unwrap_err();
        assert!(
            err.to_string().contains("incompatible"),
            "expected an explicit incompatibility error, got: {err}"
        );
    }

    /// Frozen v1 fixture: since there is only one supported schema version
    /// today, this pins the literal wire shape a real v1 payload must keep
    /// deserializing as, rather than fabricating a fictitious v2 (unlike
    /// `extension.rs`, which has two real historical versions to fix).
    #[test]
    fn frozen_v1_fixture_still_reads_correctly() {
        let json = r#"{
            "schema_version": 1,
            "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "version": 1,
            "session_id": "s1",
            "hypothesis": {
                "claim_id": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
                "expected_observations": [
                    {"signal_class": "process_result", "description": "exit code changes"}
                ]
            },
            "baseline": {
                "description": "before intervention",
                "evidence_ids": ["3fa85f64-5717-4562-b3fc-2c963f66afa8"]
            },
            "intervention": {
                "kind": "revert_file_to_baseline",
                "description": "revert file"
            },
            "stop_conditions": [{"timeout_elapsed": {"max_seconds": 60}}],
            "provenance": {
                "created_at": "2026-01-01T00:00:00Z",
                "created_by": "test-harness",
                "environment": "worktree:fornax-FORNX-99",
                "tool_version": "fornax-cli-0.0.4"
            }
        }"#;
        let s: ExperimentSpec = serde_json::from_str(json).unwrap();
        assert_eq!(s.schema_version, 1);
        assert_eq!(s.session_id, "s1");
        // No allowed_side_effects/extension/preconditions present on the
        // wire at all -- confirms both the schema-version fixture AND
        // deny-by-default-on-omission in one fixture.
        assert!(s.allowed_side_effects.is_read_only());
        assert!(s.preconditions.is_empty());
        assert!(s.extension.is_none());
    }

    // --- AC2: deny-by-default side-effect permissions ----------------------

    #[test]
    fn default_side_effect_allow_list_permits_nothing() {
        let list = SideEffectAllowList::default();
        assert!(list.is_read_only());
        for class in [
            SideEffectClass::EphemeralWorktreeMutation,
            SideEffectClass::ProcessSpawn,
            SideEffectClass::NetworkCall,
            SideEffectClass::FilesystemWriteOutsideWorktree,
        ] {
            assert!(!list.permits(class));
        }
    }

    #[test]
    fn wire_payload_omitting_allowed_side_effects_deserializes_to_deny_by_default() {
        // The path that actually matters: a real caller's JSON simply never
        // mentions the field, not merely `SideEffectAllowList::default()`
        // constructed directly in Rust.
        let mut value = serde_json::to_value(spec()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("allowed_side_effects");
        let parsed: ExperimentSpec = serde_json::from_value(value).unwrap();
        assert!(parsed.allowed_side_effects.is_read_only());
    }

    #[test]
    fn explicit_allow_list_only_permits_named_classes() {
        let list = SideEffectAllowList::new([SideEffectClass::ProcessSpawn]);
        assert!(list.permits(SideEffectClass::ProcessSpawn));
        assert!(!list.permits(SideEffectClass::NetworkCall));
        assert!(!list.is_read_only());
    }

    // --- AC3: non-Completed outcomes cannot look like a comparison ---------

    #[test]
    fn only_completed_outcome_carries_a_hypothesis_relation() {
        let completed = ExperimentOutcome::Completed(
            CompletedExperiment::new(
                Uuid::new_v4(),
                EvidenceRelation::Contradicts,
                vec![Uuid::new_v4()],
                vec![Uuid::new_v4()],
                "reverting the file made the exit code succeed",
            )
            .unwrap(),
        );
        assert_eq!(
            completed.hypothesis_relation(),
            Some(EvidenceRelation::Contradicts)
        );

        for non_completed in [
            ExperimentOutcome::Inconclusive {
                reason: "evidence did not resolve either way".into(),
            },
            ExperimentOutcome::Blocked {
                reason: "precondition failed".into(),
            },
            ExperimentOutcome::Unsupported {
                reason: "no executor for this kind".into(),
            },
            ExperimentOutcome::Failed {
                reason: "executor errored".into(),
            },
        ] {
            assert_eq!(
                non_completed.hypothesis_relation(),
                None,
                "{non_completed:?} must never yield a hypothesis_relation"
            );
        }
    }

    /// The AC3 requirement pinned at the wire level, not just in Rust: a
    /// naive downstream consumer reading JSON (not matching on the Rust
    /// enum) must not find any field on a non-`Completed` outcome that
    /// looks like "the intervention contradicted the hypothesis".
    #[test]
    fn blocked_outcome_json_carries_no_relation_or_verdict_shaped_key() {
        let blocked = ExperimentOutcome::Blocked {
            reason: "safety policy violated".into(),
        };
        let json = serde_json::to_value(&blocked).unwrap();
        let blocked_body = &json["blocked"];
        assert!(blocked_body.get("hypothesis_relation").is_none());
        assert!(blocked_body.get("verdict").is_none());
        assert!(blocked_body.get("contradicted").is_none());
        assert!(blocked_body.get("baseline_evidence_ids").is_none());
        assert!(blocked_body.get("intervention_evidence_ids").is_none());
        assert_eq!(
            blocked_body["reason"],
            serde_json::json!("safety policy violated")
        );
    }

    #[test]
    fn experiment_outcome_round_trips_for_every_variant() {
        let variants = vec![
            ExperimentOutcome::Completed(
                CompletedExperiment::new(
                    Uuid::new_v4(),
                    EvidenceRelation::Supports,
                    vec![Uuid::new_v4()],
                    vec![Uuid::new_v4()],
                    "summary",
                )
                .unwrap(),
            ),
            ExperimentOutcome::Inconclusive { reason: "r".into() },
            ExperimentOutcome::Blocked { reason: "r".into() },
            ExperimentOutcome::Unsupported { reason: "r".into() },
            ExperimentOutcome::Failed { reason: "r".into() },
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: ExperimentOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // --- AC4: Completed always links back to baseline/intervention/hypothesis --

    #[test]
    fn completed_experiment_rejects_empty_baseline_evidence_ids() {
        let err = CompletedExperiment::new(
            Uuid::new_v4(),
            EvidenceRelation::Supports,
            vec![],
            vec![Uuid::new_v4()],
            "summary",
        )
        .unwrap_err();
        assert!(err.contains("baseline"));
    }

    #[test]
    fn completed_experiment_rejects_empty_intervention_evidence_ids() {
        let err = CompletedExperiment::new(
            Uuid::new_v4(),
            EvidenceRelation::Supports,
            vec![Uuid::new_v4()],
            vec![],
            "summary",
        )
        .unwrap_err();
        assert!(err.contains("intervention"));
    }

    #[test]
    fn completed_experiment_populates_hypothesis_and_both_evidence_sides() {
        let claim_id = Uuid::new_v4();
        let baseline_id = Uuid::new_v4();
        let intervention_id = Uuid::new_v4();
        let completed = CompletedExperiment::new(
            claim_id,
            EvidenceRelation::Supports,
            vec![baseline_id],
            vec![intervention_id],
            "summary",
        )
        .unwrap();
        assert_eq!(completed.hypothesis_claim_id, claim_id);
        assert_eq!(completed.baseline_evidence_ids, vec![baseline_id]);
        assert_eq!(completed.intervention_evidence_ids, vec![intervention_id]);
    }

    // --- ExperimentResult round trip / versioning pinning -------------------

    #[test]
    fn experiment_result_round_trips_through_json() {
        let result = ExperimentResult {
            experiment_id: Uuid::new_v4(),
            experiment_version: 1,
            outcome: ExperimentOutcome::Inconclusive {
                reason: "no signal moved".into(),
            },
            computed_at: "2026-01-02T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ExperimentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // --- ExperimentKind: closed core + Custom escape hatch -------------------

    #[test]
    fn custom_experiment_kind_round_trips_the_original_string() {
        let json = r#""claude_code:thinking_block_probe""#;
        let kind: ExperimentKind = serde_json::from_str(json).unwrap();
        assert_eq!(
            kind,
            ExperimentKind::Custom("claude_code:thinking_block_probe".to_string())
        );
        let back = serde_json::to_string(&kind).unwrap();
        assert_eq!(back, json);
    }
}
