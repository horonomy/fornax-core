//! [`CandidateCorpusManifest`]: the deterministic, versioned artifact
//! `fornax corpus export` writes, and the next adjudication stage consumes.

use std::collections::BTreeMap;

use crate::candidate::CandidateCase;

pub const CORPUS_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Failure to build a [`CandidateCorpusManifest`].
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    /// FORNX-341 AC: "candidate mining includes both suspicious cases and
    /// benign/hard-negative controls; it is not only positive-case
    /// harvesting." A manifest with candidates but zero
    /// [`crate::mining::MiningStrategy::BenignControl`] cases violates that
    /// AC structurally, not just by convention — enforced here rather than
    /// only documented.
    #[error(
        "corpus manifest has {candidate_count} candidate(s) but zero benign controls -- mine \
         more sessions (a control is a Verified claim with no conflict and no other strategy \
         firing), or if this corpus is deliberately scoped to a known-suspicious sample only, \
         state that scope explicitly rather than exporting it as a general corpus"
    )]
    ControlsAbsent { candidate_count: usize },
}

/// The versioned, deterministic artifact `fornax corpus export` writes.
/// `contains_adjudicated_labels` is always `false` here — no
/// [`CandidateCase`] carries a label (see that type's doc comment); this
/// field exists so a downstream consumer can assert it without re-deriving
/// the invariant.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CandidateCorpusManifest {
    pub manifest_schema_version: u32,
    pub corpus_version: String,
    /// `fornax_bench::dataset::content_hash_of` over this manifest's own
    /// canonical serialized `candidates` — a reproducibility pin, not a
    /// copy of `corpus_version` a caller could forget to bump.
    pub content_hash: String,
    /// `fornax_types::home_identity` of the machine this corpus was mined
    /// on (FORNX-339) — not a secret, just enough to tell two corpora mined
    /// on different machines apart.
    pub home_identity: String,
    pub candidate_count: usize,
    pub control_count: usize,
    pub strategy_counts: BTreeMap<String, usize>,
    pub withheld_evidence_count: usize,
    pub contains_adjudicated_labels: bool,
    pub candidates: Vec<CandidateCase>,
    pub mined_at: String,
}

/// Build a manifest from a set of already-mined candidates. `mined_at` is
/// passed in by the caller, never read from the clock here — mirrors
/// `fornax_verify::fusion`'s "pure and sync" discipline and
/// `fornax_replay::ReplayManifest::recorded_at`'s precedent.
pub fn build_corpus_manifest(
    mut candidates: Vec<CandidateCase>,
    corpus_version: String,
    home_identity: String,
    mined_at: String,
) -> Result<CandidateCorpusManifest, CorpusError> {
    // Sort by id for a byte-identical manifest across re-mining runs over
    // the same underlying data (FORNX-341 AC: deterministic/replayable).
    candidates.sort_by_key(|c| c.id);

    let candidate_count = candidates.len();
    let control_count = candidates
        .iter()
        .filter(|c| c.mined_by.as_slice() == [crate::mining::MiningStrategy::BenignControl])
        .count();

    if candidate_count > 0 && control_count == 0 {
        return Err(CorpusError::ControlsAbsent { candidate_count });
    }

    let mut strategy_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut withheld_evidence_count = 0;
    for candidate in &candidates {
        for strategy in &candidate.mined_by {
            let key = serde_json::to_value(strategy)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            *strategy_counts.entry(key).or_insert(0) += 1;
        }
        withheld_evidence_count += candidate.withheld_evidence.len();
    }

    let content_hash = fornax_bench::dataset::content_hash_of(
        &serde_json::to_vec(&candidates).unwrap_or_default(),
    );

    Ok(CandidateCorpusManifest {
        manifest_schema_version: CORPUS_MANIFEST_SCHEMA_VERSION,
        corpus_version,
        content_hash,
        home_identity,
        candidate_count,
        control_count,
        strategy_counts,
        withheld_evidence_count,
        contains_adjudicated_labels: false,
        candidates,
        mined_at,
    })
}
