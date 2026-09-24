//! Semantic Judge: an AI-judge provider interface as one additional evidence
//! source, never the sole verifier (FORNX-94, parent epic FORNX-66).
//!
//! # Why this exists
//!
//! Deterministic verifiers ([`crate::Verifier`]) and the fusion engine
//! ([`crate::fusion`]) are grounded, replayable, and cloud-free by design
//! (ADR-0001 D2/D3) — but purely deterministic string/exit-code heuristics
//! cannot capture claim ambiguity, paraphrase, or semantic nuance an LLM is
//! good at. This module lets an LLM's *opinion* about a claim enter Fornax's
//! evidence model as clearly-labeled, model-derived evidence — never as an
//! independent verifier, never as the sole or final word.
//!
//! # Local-only, no cloud dependency on the critical path
//!
//! The only shipped [`SemanticJudgeProvider`] implementation
//! ([`LocalSelfHostedJudgeProvider`]) talks to a local Ollama-compatible HTTP
//! endpoint (default `http://localhost:11434/v1`, same convention documented
//! in `docs/research/0002-third-provider-fitness-report.md` /
//! `docs/research/0003-opencode-live-transport-verification.md` for a
//! different subsystem). This is a local network call, not a cloud
//! dependency — ADR-0001 D2 ("local critical path has no cloud dependency...
//! must work with all cloud network access disabled") is unaffected. No
//! external-cloud provider is added here, though the trait shape leaves room
//! for one later without requiring it now.
//!
//! Judge calls are never on the deterministic critical path: nothing in
//! [`crate::fusion`] or [`crate::decision`] calls into this module, and
//! deterministic verification/fusion/decision continue to work byte-for-byte
//! identically whether or not Ollama is reachable, running, or even
//! configured. A judge call that times out or errors reports
//! [`JudgeError`]/[`JudgeVerdict::Unavailable`] honestly — never a fabricated
//! pass/fail.
//!
//! # Labeled model-derived, never independent evidence
//!
//! [`judge_output_to_evidence`] stamps every judge-produced [`Evidence`] with
//! [`fornax_types::TrustClass::ModelInternal`] via
//! [`fornax_types::EvidenceSource::derived`] — the same trust class
//! [`fornax_types::sensor`]'s own worked `ReasoningSummarySensor` example
//! uses for model-internal telemetry, so no new `TrustClass` variant is
//! needed. `ModelInternal` already reads distinctly from
//! `AgentAdjacent`/`HostObserved`/`IndependentExternal`/`HumanReviewed` in
//! every UI/rationale surface that renders `TrustClass` — a judge verdict
//! can never masquerade as independent system evidence because it is, by
//! construction, impossible to stamp any other trust class through this
//! path.
//!
//! # Replay
//!
//! [`JudgeOutput`] carries enough metadata (`model`, `endpoint`,
//! `prompt_version`, `called_at`) that the *same* [`JudgeInput`] can be
//! replayed later against a different judge/model version for comparison —
//! nothing in [`JudgeInput`] is mutated or consumed by a call, and
//! `JudgeOutput` never overwrites a prior call's record (callers persist
//! each `JudgeOutput` as its own evidence row via
//! [`judge_output_to_evidence`], keyed by its own id).
//!
//! # Raw protected evidence
//!
//! [`JudgeInput::allow_raw_evidence`] defaults to `false` via
//! [`JudgeInput::new`]. When `false`, [`JudgeInput::redacted_evidence_excerpt`]
//! is sent to the model instead of the raw evidence graph excerpt — see that
//! method's doc comment. A caller must explicitly opt in
//! (`with_raw_evidence_allowed`) before raw (unredacted) evidence payload
//! text is included in a prompt.
//!
//! # Disagreement stays visible, never silently overwrites objective evidence
//!
//! [`JudgeOutput::disagreement`] is populated whenever the judge's verdict
//! differs from what deterministic evidence already indicates for the same
//! claim (a caller passes in the objective verdict, if known, via
//! [`JudgeOutput::with_disagreement_check`]). Nothing in this module ever
//! deletes, mutates, or supersedes an existing `Evidence`/`Finding`/
//! `FusedFinding` — a judge's evidence is additive, appearing in the graph
//! alongside (never instead of) the deterministic evidence it may disagree
//! with; fusion/decision continue to weigh it only as one more
//! `ModelInternal` vote, per [`crate::fusion`]'s own module docs ("FORNX-94
//! ... enters as an ordinary EvidenceLink upstream of this trait").

use std::time::Duration;

use fornax_types::redact::redact_text;
use fornax_types::{Claim, Evidence, EvidenceGraph, EvidenceKind, EvidenceSource, TrustClass};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The judge's own opinion about whether a claim holds, kept deliberately
/// distinct from [`fornax_types::Verdict`] — see [`JudgeOutput`]'s doc
/// comment for why this is not a reuse of that type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeVerdict {
    /// The model's semantic read is that the claim holds.
    Supported,
    /// The model's semantic read is that the claim does not hold.
    Contradicted,
    /// The model could not form a confident opinion from the evidence it was
    /// given (an honest "I don't know", not a forced binary choice).
    Inconclusive,
    /// The judge could not be reached, timed out, or returned an error.
    /// Never conflated with `Inconclusive` — `Inconclusive` means "the model
    /// tried and couldn't decide"; `Unavailable` means "the model never
    /// weighed in at all". See module docs: this must never be silently
    /// upgraded to a real verdict.
    Unavailable,
}

/// Failure modes for a [`SemanticJudgeProvider::judge`] call. Distinct from
/// [`JudgeVerdict::Unavailable`] (a *value* callers can serialize/inspect);
/// `JudgeError` is the `Err` side of the `Result` a provider returns, which a
/// caller is expected to convert into `JudgeVerdict::Unavailable` +
/// [`JudgeOutput`] rather than propagate as a hard failure — see
/// [`LocalSelfHostedJudgeProvider::judge`]'s doc comment.
#[derive(Debug, thiserror::Error)]
pub enum JudgeError {
    #[error("semantic judge disabled via config")]
    Disabled,
    #[error("semantic judge request to {endpoint} timed out after {timeout_ms}ms")]
    Timeout { endpoint: String, timeout_ms: u64 },
    #[error("semantic judge request to {endpoint} failed: {detail}")]
    RequestFailed { endpoint: String, detail: String },
    #[error("semantic judge at {endpoint} returned an unparseable response: {detail}")]
    UnparseableResponse { endpoint: String, detail: String },
}

/// Input to one [`SemanticJudgeProvider::judge`] call (FORNX-94 AC: "raw
/// protected evidence is not sent unless an explicit policy permits it").
///
/// Deliberately narrow and structured — never unrestricted repo/file access:
/// a claim's text plus a bounded, already-collected evidence excerpt, not a
/// filesystem or shell handle the model could use to go fetch more.
///
/// `Serialize`/`Deserialize` (FORNX-94 replay AC: "same *saved* input can be
/// replayed against judge versions for comparison") -- every field is a
/// plain `String`/`bool`, so a `JudgeInput` can be written to disk once and
/// fed to two different [`SemanticJudgeProvider`]s (or the same provider
/// under two [`SemanticJudgeConfig`]s) later, producing two [`JudgeOutput`]s
/// whose `model`/`prompt_version`/`called_at` are directly comparable. See
/// `judge_tests::a_saved_judge_input_can_be_replayed_against_two_different_judge_configs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeInput {
    /// The claim under evaluation.
    pub claim_text: String,
    pub claim_subject: String,
    /// Free-text summary of the relevant evidence-graph excerpt for this
    /// claim (e.g. rendered from an [`EvidenceGraph`] plus its resolved
    /// [`Evidence`] — see [`JudgeInput::from_claim_and_graph`]). Bounded,
    /// structured input, not raw file/tool access.
    pub evidence_excerpt: String,
    /// Whether the caller's policy permits sending `evidence_excerpt`
    /// unredacted. Defaults to `false` (excluded/redacted) via
    /// [`JudgeInput::new`] — a caller must opt in explicitly.
    pub allow_raw_evidence: bool,
}

impl JudgeInput {
    /// Construct with raw-evidence policy defaulted to `false`
    /// (excluded/redacted) — the safe default per FORNX-94's AC.
    pub fn new(claim_text: impl Into<String>, claim_subject: impl Into<String>) -> Self {
        Self {
            claim_text: claim_text.into(),
            claim_subject: claim_subject.into(),
            evidence_excerpt: String::new(),
            allow_raw_evidence: false,
        }
    }

    /// Explicit opt-in: this policy permits sending unredacted evidence
    /// content to the judge. Never the default — see module docs.
    pub fn with_raw_evidence_allowed(mut self, allowed: bool) -> Self {
        self.allow_raw_evidence = allowed;
        self
    }

    pub fn with_evidence_excerpt(mut self, excerpt: impl Into<String>) -> Self {
        self.evidence_excerpt = excerpt.into();
        self
    }

    /// Build a [`JudgeInput`] from a real [`Claim`] plus its resolved
    /// [`EvidenceGraph`]/[`Evidence`] pool — a bounded, structured excerpt
    /// (link relation + evidence kind + a short payload summary per link),
    /// never the full raw evidence payload or any filesystem access.
    pub fn from_claim_and_graph(
        claim: &Claim,
        graph: &EvidenceGraph,
        evidence_pool: &[Evidence],
        allow_raw_evidence: bool,
    ) -> Self {
        let mut lines = Vec::new();
        for link in &graph.links {
            let Some(ev) = evidence_pool.iter().find(|e| e.id == link.evidence_id) else {
                lines.push(format!(
                    "- relation={:?} evidence=<unresolved:{}>",
                    link.relation, link.evidence_id
                ));
                continue;
            };
            let summary = evidence_payload_summary(ev, allow_raw_evidence);
            lines.push(format!(
                "- relation={:?} kind={:?} observed_at={} summary={}",
                link.relation, ev.kind, ev.observed_at, summary
            ));
        }
        for missing in &graph.missing {
            lines.push(format!(
                "- missing signal_class={:?} availability={:?}",
                missing.signal_class, missing.availability
            ));
        }
        let excerpt = if lines.is_empty() {
            "no evidence links or missing-evidence notes recorded for this claim".to_string()
        } else {
            lines.join("\n")
        };
        Self {
            claim_text: claim.text.clone(),
            claim_subject: claim.subject.clone(),
            evidence_excerpt: excerpt,
            allow_raw_evidence,
        }
    }

    /// The evidence excerpt actually safe to send given
    /// `allow_raw_evidence`: verbatim when raw evidence is explicitly
    /// permitted, otherwise redacted via [`fornax_types::redact::redact_text`]
    /// (FORNX-94 AC: "raw protected evidence is not sent unless an explicit
    /// policy permits it").
    pub fn redacted_evidence_excerpt(&self) -> String {
        if self.allow_raw_evidence {
            self.evidence_excerpt.clone()
        } else {
            redact_text(&self.evidence_excerpt)
        }
    }
}

/// Short, non-exhaustive summary of one evidence payload for a judge prompt
/// — bounded text, not the full JSON payload, even when raw evidence is
/// allowed (a full dump is not "structured, bounded input"; a summary is).
fn evidence_payload_summary(evidence: &Evidence, allow_raw_evidence: bool) -> String {
    let raw = match evidence.kind {
        EvidenceKind::ExitCode => evidence
            .payload
            .get("exit_code")
            .map(|v| format!("exit_code={v}"))
            .unwrap_or_else(|| "exit_code=<unknown>".to_string()),
        _ => evidence.payload.to_string(),
    };
    // Redact before truncating: a secret whose matchable span straddles the
    // 200-char cut would otherwise have only a short prefix survive into an
    // already-truncated redaction pass, since the detectors need the whole
    // span to recognize it.
    let redacted = if allow_raw_evidence {
        raw
    } else {
        redact_text(&raw)
    };
    redacted.chars().take(200).collect()
}

/// Structured verdict-shaped signal returned by one [`SemanticJudgeProvider::judge`]
/// call (FORNX-94). Deliberately its own type, not a reuse of
/// [`fornax_types::Verdict`] — `Verdict` is the deterministic-verifier
/// five-state vocabulary (ADR-0001's invariant that it is "never collapsed");
/// folding a model's semantic opinion into it would blur the "judge output
/// cannot masquerade as independent system evidence" AC at the type level,
/// not just the trust-class level. `JudgeOutput` is converted to
/// `ModelInternal`-trust `Evidence` by [`judge_output_to_evidence`], which is
/// how it actually reaches the evidence graph/fusion engine — never by
/// pretending to be a `Finding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeOutput {
    pub verdict: JudgeVerdict,
    /// The model's own explanation for `verdict` — free text, always
    /// present (even for `Unavailable`, where it names the failure).
    pub rationale: String,
    /// Model/version/config metadata for replay and provenance (FORNX-94 AC:
    /// "same saved input can be replayed against judge versions for
    /// comparison"). Never logged verbatim if it could carry secrets — see
    /// module docs.
    pub model: String,
    pub endpoint: String,
    /// A version tag for the prompt/config shape used to build the request
    /// this output answers, independent of `model` — bumping the prompt
    /// template without changing the model name still changes what a
    /// replay compares against.
    pub prompt_version: u32,
    /// RFC3339 timestamp this call was made.
    pub called_at: String,
    /// `true` when this judge's `verdict` disagrees with an objective
    /// deterministic verdict the caller already knows for the same claim
    /// (set via [`Self::with_disagreement_check`]). `None` when no objective
    /// comparison was supplied — absence of a disagreement flag must never
    /// be read as "the judge agrees"; it means "nothing to compare against
    /// was given". FORNX-94 AC: "judge disagreement with objective evidence
    /// remains visible instead of overwriting it".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disagreement: Option<bool>,
}

impl JudgeOutput {
    fn unavailable(
        rationale: impl Into<String>,
        model: &str,
        endpoint: &str,
        called_at: &str,
    ) -> Self {
        Self {
            verdict: JudgeVerdict::Unavailable,
            rationale: rationale.into(),
            model: model.to_string(),
            endpoint: endpoint.to_string(),
            prompt_version: JUDGE_PROMPT_VERSION,
            called_at: called_at.to_string(),
            disagreement: None,
        }
    }

    /// Compare this judge's verdict against an already-known objective
    /// deterministic verdict for the same claim, populating
    /// [`Self::disagreement`] rather than silently letting the two sit
    /// side-by-side unexamined (FORNX-94 AC). `objective_supported` is
    /// `Some(true)` if deterministic evidence supports the claim,
    /// `Some(false)` if it contradicts it, `None` if there is no
    /// deterministic verdict yet to compare against (in which case this is
    /// a no-op — `disagreement` stays whatever it already was, i.e. `None`
    /// unless a prior call set it).
    pub fn with_disagreement_check(mut self, objective_supported: Option<bool>) -> Self {
        if let Some(objective) = objective_supported {
            let judge_supported = match self.verdict {
                JudgeVerdict::Supported => Some(true),
                JudgeVerdict::Contradicted => Some(false),
                JudgeVerdict::Inconclusive | JudgeVerdict::Unavailable => None,
            };
            self.disagreement = judge_supported.map(|j| j != objective);
        }
        self
    }
}

/// Prompt/config shape version — bump when the prompt template built inside
/// [`LocalSelfHostedJudgeProvider::judge`] changes in a way that could
/// change output for the same [`JudgeInput`], independent of `model` name
/// changes (FORNX-94 replay AC).
pub const JUDGE_PROMPT_VERSION: u32 = 1;

/// Vendor-neutral contract for an AI-judge evidence source (FORNX-94).
/// Synchronous/blocking by design, matching [`crate::fusion::FusionPolicy`]'s
/// sync shape (module docs there: a judge-derived signal enters fusion as an
/// ordinary, already-collected [`Evidence`]/[`fornax_types::EvidenceLink`],
/// never something fusion calls out to mid-computation). A caller invoking
/// this from an async context should run it via
/// `tokio::task::spawn_blocking`.
///
/// A judge call must never hang indefinitely and must never fabricate a real
/// pass/fail verdict when it cannot honestly form one — see [`judge`]'s doc
/// comment.
pub trait SemanticJudgeProvider {
    /// Stable identity for this provider implementation.
    fn name(&self) -> &'static str;

    /// Attempt to judge `input`. Implementations must apply a bounded
    /// timeout internally and return `Ok(JudgeOutput { verdict:
    /// Unavailable, .. })` (never fabricate `Supported`/`Contradicted`) for
    /// any failure that is reasonably expected in normal operation (the
    /// judge disabled, unreachable, timed out, or returning a malformed
    /// response) — [`JudgeError`] is reserved for a caller that wants the
    /// raw failure detail (e.g. for a CLI to print), not for signaling "the
    /// claim is unjudgeable", which is exactly what
    /// `JudgeVerdict::Unavailable` already means.
    fn judge(&self, input: &JudgeInput) -> Result<JudgeOutput, JudgeError>;
}

/// `[semantic_judge]` config table read from `$FORNAX_HOME/config.toml`
/// (FORNX-94), mirroring [`fornax_types::sensor_config::SensorDisableConfig`]'s
/// own load pattern rather than inventing a second config-file convention.
///
/// ```toml
/// [semantic_judge]
/// enabled = true
/// endpoint = "http://localhost:11434/v1"
/// model = "llama3.1"
/// timeout_ms = 5000
/// ```
///
/// Absence of the file, absence of the `[semantic_judge]` table, or absence
/// of any individual key all fall back to [`Self::default`] — `enabled:
/// false`, the documented Ollama-compatible default endpoint/model, and a
/// conservative timeout. A user who has never touched this config gets the
/// judge off by default (AC: judge is one evidence source, never load-bearing
/// unless a user opts in).
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticJudgeConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub model: String,
    pub timeout_ms: u64,
}

impl Default for SemanticJudgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:11434/v1".to_string(),
            model: "llama3.1".to_string(),
            timeout_ms: 5000,
        }
    }
}

/// Failure modes reading/parsing the `[semantic_judge]` table. Mirrors
/// [`fornax_types::sensor_config::SensorConfigError`]'s shape.
#[derive(Debug, thiserror::Error)]
pub enum SemanticJudgeConfigError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path} as TOML: {source}")]
    Parse {
        path: std::path::PathBuf,
        #[source]
        source: toml_edit::TomlError,
    },
}

impl SemanticJudgeConfig {
    fn from_toml_str_with_path(
        contents: &str,
        path: &std::path::Path,
    ) -> Result<Self, SemanticJudgeConfigError> {
        let doc: toml_edit::DocumentMut =
            contents
                .parse()
                .map_err(|source| SemanticJudgeConfigError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;
        let default = Self::default();
        let Some(table) = doc.get("semantic_judge") else {
            return Ok(default);
        };
        let enabled = table
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(default.enabled);
        let endpoint = table
            .get("endpoint")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or(default.endpoint);
        let model = table
            .get("model")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or(default.model);
        let timeout_ms = table
            .get("timeout_ms")
            .and_then(|v| v.as_integer())
            .map(|n| n.max(0) as u64)
            .unwrap_or(default.timeout_ms);
        Ok(Self {
            enabled,
            endpoint,
            model,
            timeout_ms,
        })
    }

    /// Parse an in-memory `config.toml` document (e.g. from a test).
    pub fn from_toml_str(contents: &str) -> Result<Self, SemanticJudgeConfigError> {
        Self::from_toml_str_with_path(contents, std::path::Path::new("<in-memory config.toml>"))
    }

    /// Read `<fornax_home>/config.toml`'s `[semantic_judge]` table. A
    /// nonexistent file yields [`Self::default`] (disabled), not an error —
    /// same contract as [`fornax_types::sensor_config::SensorDisableConfig::load`].
    pub fn load(fornax_home: &std::path::Path) -> Result<Self, SemanticJudgeConfigError> {
        let path = fornax_home.join(fornax_types::sensor_config::SENSOR_CONFIG_FILE);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => return Err(SemanticJudgeConfigError::Io { path, source }),
        };
        Self::from_toml_str_with_path(&contents, &path)
    }

    /// [`Self::load`] against
    /// [`fornax_types::sensor_config::default_fornax_home`], collapsing any
    /// error to [`Self::default`] (disabled) — same "never fail evidence
    /// collection outright over a config-file problem" contract as
    /// [`fornax_types::sensor_config::SensorDisableConfig::load_default`].
    pub fn load_default() -> Self {
        Self::load(&fornax_types::sensor_config::default_fornax_home()).unwrap_or_default()
    }
}

/// The canonical Stage-4 Semantic Judge baseline (FORNX-94): a local,
/// self-hosted judge talking to an Ollama-compatible `/chat/completions`
/// endpoint over plain HTTP to `localhost` — no cloud/external LLM API
/// credential, client, or dependency, per this ticket's binding architecture
/// decision. Endpoint/model/timeout are configurable via
/// [`SemanticJudgeConfig`], never compiled in.
pub struct LocalSelfHostedJudgeProvider {
    config: SemanticJudgeConfig,
    client: reqwest::blocking::Client,
}

impl LocalSelfHostedJudgeProvider {
    pub fn new(config: SemanticJudgeConfig) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            // A client-builder failure here means a malformed timeout value
            // or a genuinely broken TLS backend, not a runtime condition
            // `judge()`'s callers can meaningfully recover from -- fall back
            // to an un-timed-out default client rather than panicking; the
            // per-request timeout is still enforced by `judge()`'s own
            // wall-clock check below as a second line of defense.
            .unwrap_or_default();
        Self { config, client }
    }

    fn chat_completions_url(&self) -> String {
        format!(
            "{}/chat/completions",
            self.config.endpoint.trim_end_matches('/')
        )
    }
}

#[derive(Serialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
}

#[derive(Deserialize)]
struct ChatCompletionChoice {
    message: ChatCompletionResponseMessage,
}

#[derive(Deserialize)]
struct ChatCompletionResponseMessage {
    content: String,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatCompletionChoice>,
}

fn build_prompt(input: &JudgeInput) -> String {
    format!(
        "You are a semantic evidence judge. Given a claim and a bounded evidence \
         excerpt, decide whether the evidence supports, contradicts, or is \
         inconclusive about the claim.\n\n\
         Claim (subject: {}): {}\n\n\
         Evidence excerpt:\n{}\n\n\
         Respond with exactly one first line of SUPPORTED, CONTRADICTED, or \
         INCONCLUSIVE, followed by a one-paragraph rationale.",
        input.claim_subject,
        input.claim_text,
        input.redacted_evidence_excerpt()
    )
}

/// Parse the model's free-text response into a [`JudgeVerdict`] +
/// rationale. Deliberately tolerant: an unrecognized first line is
/// `Inconclusive` with the raw text preserved as rationale, never an error —
/// a judge that answered in an unexpected shape still answered, it just
/// didn't commit to a clean verdict.
fn parse_model_response(content: &str) -> (JudgeVerdict, String) {
    let trimmed = content.trim();
    let mut lines = trimmed.splitn(2, '\n');
    let first = lines.next().unwrap_or("").trim().to_uppercase();
    let rest = lines.next().unwrap_or("").trim().to_string();
    // "CONTRADICTED" is checked first, and a negated "UNSUPPORTED"/"NOT
    // SUPPORTED" reply is treated as unrecognized (falls to Inconclusive)
    // rather than matched by `contains("SUPPORTED")` -- that substring
    // check alone would silently invert a negated answer to `Supported`,
    // the opposite of what the model said. The prompt asks for one of
    // exactly three words; anything else is honestly reported as
    // Inconclusive rather than guessed.
    let verdict = if first.contains("CONTRADICTED") {
        JudgeVerdict::Contradicted
    } else if first.contains("SUPPORTED")
        && !first.contains("UNSUPPORTED")
        && !first.contains("NOT SUPPORTED")
    {
        JudgeVerdict::Supported
    } else {
        JudgeVerdict::Inconclusive
    };
    let rationale = if rest.is_empty() {
        trimmed.to_string()
    } else {
        rest
    };
    (verdict, rationale)
}

impl SemanticJudgeProvider for LocalSelfHostedJudgeProvider {
    fn name(&self) -> &'static str {
        "local_self_hosted_judge_provider_v1"
    }

    fn judge(&self, input: &JudgeInput) -> Result<JudgeOutput, JudgeError> {
        let called_at = chrono::Utc::now().to_rfc3339();
        if !self.config.enabled {
            // Honest, structured "unavailable" -- never a hard error a
            // caller must handle specially, and never a fabricated verdict.
            return Ok(JudgeOutput::unavailable(
                "semantic judge disabled via [semantic_judge].enabled = false",
                &self.config.model,
                &self.config.endpoint,
                &called_at,
            ));
        }

        let request = ChatCompletionRequest {
            model: self.config.model.clone(),
            messages: vec![ChatMessage {
                role: "user",
                content: build_prompt(input),
            }],
            stream: false,
        };

        let url = self.chat_completions_url();
        let response = match self.client.post(&url).json(&request).send() {
            Ok(r) => r,
            Err(e) if e.is_timeout() => {
                return Ok(JudgeOutput::unavailable(
                    format!(
                        "semantic judge request to {url} timed out after \
                         {}ms -- treated as unavailable, never a fabricated verdict",
                        self.config.timeout_ms
                    ),
                    &self.config.model,
                    &self.config.endpoint,
                    &called_at,
                ));
            }
            Err(e) => {
                return Ok(JudgeOutput::unavailable(
                    format!(
                        "semantic judge request to {url} failed (is Ollama running? -- \
                         treated as unavailable, never a fabricated verdict): {e}"
                    ),
                    &self.config.model,
                    &self.config.endpoint,
                    &called_at,
                ));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            return Ok(JudgeOutput::unavailable(
                format!("semantic judge at {url} responded with HTTP {status}"),
                &self.config.model,
                &self.config.endpoint,
                &called_at,
            ));
        }

        let parsed: ChatCompletionResponse = match response.json() {
            Ok(p) => p,
            Err(e) => {
                return Ok(JudgeOutput::unavailable(
                    format!("semantic judge at {url} returned an unparseable response: {e}"),
                    &self.config.model,
                    &self.config.endpoint,
                    &called_at,
                ));
            }
        };

        let Some(choice) = parsed.choices.into_iter().next() else {
            return Ok(JudgeOutput::unavailable(
                format!("semantic judge at {url} returned zero completion choices"),
                &self.config.model,
                &self.config.endpoint,
                &called_at,
            ));
        };

        let (verdict, rationale) = parse_model_response(&choice.message.content);
        Ok(JudgeOutput {
            verdict,
            rationale,
            model: self.config.model.clone(),
            endpoint: self.config.endpoint.clone(),
            prompt_version: JUDGE_PROMPT_VERSION,
            called_at,
            disagreement: None,
        })
    }
}

/// Convert a computed [`JudgeOutput`] into an [`Evidence`] record stamped
/// with [`TrustClass::ModelInternal`] (FORNX-94), so the judge's opinion
/// flows into the existing Evidence Graph/Explorer and Fusion Engine as
/// ordinary derived evidence, without either system needing judge-specific
/// special-casing beyond recognizing `ModelInternal`.
///
/// Uses [`EvidenceSource::derived`] rather than [`EvidenceSource::now`]: the
/// judge's opinion is *computed from* `derived_from_evidence_ids` (the
/// resolved evidence it was shown), not directly observed — the same
/// "derived" shape [`fornax_types::sensor`]'s FORNX-92 fields already model
/// for e.g. a computed duration. `origin_trust_class` is passed as
/// `ModelInternal` explicitly (not copied from whatever trust class the
/// input evidence carried) — see module docs: a judge output must never
/// silently inherit a higher/independent trust class than `ModelInternal`,
/// regardless of what it was derived from.
///
/// `kind` is [`EvidenceKind::ToolResult`] — a deliberate choice among
/// today's five [`EvidenceKind`] variants, not the accidental default: a
/// judge verdict is not `ExitCode` (no exit code), `FileDiff`/
/// `ProcessObservation` (nothing was diffed or process-observed), or
/// `TranscriptExcerpt` (it is a synthesized opinion, not a quoted
/// transcript). `ToolResult` — an opaque structured payload from something
/// that was invoked and returned a result — is the closest existing fit for
/// "a bounded, structured response from an invoked tool-like thing", which
/// is exactly what an HTTP call to the judge endpoint is. One real
/// consequence follows from this choice, also deliberate:
/// [`EvidenceKind::default_freshness_window`] maps `ToolResult` to
/// [`fornax_types::FreshnessWindow::Durable`], so fusion's R4 staleness rule
/// (`fornax_verify::fusion`) never demotes a judge-supporting vote purely
/// for elapsed time — a recorded opinion about a claim does not go stale
/// the way a live process exit code does. A future dedicated
/// `EvidenceKind::ModelJudgment` variant would be a reasonable follow-up if
/// judge evidence needs its own freshness policy later.
pub fn judge_output_to_evidence(
    output: &JudgeOutput,
    session_id: &str,
    source_event_id: Uuid,
    derived_from_evidence_ids: Vec<Uuid>,
) -> Evidence {
    let source = EvidenceSource::derived(
        "local_self_hosted_judge_provider_v1",
        TrustClass::ModelInternal,
        None,
        Some(output.model.clone()),
        derived_from_evidence_ids,
    );
    Evidence {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        source_event_id,
        kind: EvidenceKind::ToolResult,
        observed_at: output.called_at.clone(),
        payload: serde_json::json!({
            "judge_verdict": output.verdict,
            "judge_rationale": output.rationale,
            "judge_model": output.model,
            "judge_endpoint": output.endpoint,
            "judge_prompt_version": output.prompt_version,
            "judge_disagreement": output.disagreement,
        }),
        provenance: format!(
            "semantic_judge:{}:{}",
            output.model,
            match output.verdict {
                JudgeVerdict::Supported => "supported",
                JudgeVerdict::Contradicted => "contradicted",
                JudgeVerdict::Inconclusive => "inconclusive",
                JudgeVerdict::Unavailable => "unavailable",
            }
        ),
        source: Some(source),
        extension: None,
    }
}

#[cfg(test)]
mod judge_tests {
    use super::*;
    use fornax_types::{
        EvidenceLink, EvidenceRelation, MissingEvidence, SignalAvailability, SignalClass,
    };

    fn claim() -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    // A fake provider used for tests that don't need real HTTP behavior --
    // `LocalSelfHostedJudgeProvider`'s own HTTP-layer behavior (disabled,
    // unreachable, timeout, malformed response) is exercised directly below
    // without requiring a real running Ollama instance.
    struct FakeProvider(JudgeOutput);
    impl SemanticJudgeProvider for FakeProvider {
        fn name(&self) -> &'static str {
            "fake_judge_provider_for_tests"
        }
        fn judge(&self, _input: &JudgeInput) -> Result<JudgeOutput, JudgeError> {
            Ok(self.0.clone())
        }
    }

    // --- Trust-class labeling: judge output cannot masquerade as independent evidence ---

    #[test]
    fn judge_output_to_evidence_is_always_stamped_model_internal() {
        let output = JudgeOutput {
            verdict: JudgeVerdict::Supported,
            rationale: "evidence excerpt is consistent with the claim".into(),
            model: "llama3.1".into(),
            endpoint: "http://localhost:11434/v1".into(),
            prompt_version: JUDGE_PROMPT_VERSION,
            called_at: "2026-01-01T00:00:00Z".into(),
            disagreement: None,
        };
        let evidence = judge_output_to_evidence(&output, "s1", Uuid::new_v4(), vec![]);
        let source = evidence.source.expect("judge evidence must carry a source");
        assert_eq!(source.trust_class, TrustClass::ModelInternal);
        assert_ne!(source.trust_class, TrustClass::HostObserved);
        assert_ne!(source.trust_class, TrustClass::IndependentExternal);
    }

    #[test]
    fn judge_output_to_evidence_never_inherits_a_higher_trust_class_than_model_internal() {
        // Even when derived_from points at HostObserved-trust evidence, the
        // judge's own output must still be stamped ModelInternal -- this is
        // the deliberate divergence from EvidenceSource::derived's usual
        // "copy the origin's trust_class verbatim" behavior (module docs).
        let output = JudgeOutput {
            verdict: JudgeVerdict::Contradicted,
            rationale: "evidence excerpt is inconsistent with the claim".into(),
            model: "llama3.1".into(),
            endpoint: "http://localhost:11434/v1".into(),
            prompt_version: JUDGE_PROMPT_VERSION,
            called_at: "2026-01-01T00:00:00Z".into(),
            disagreement: None,
        };
        let host_observed_evidence_id = Uuid::new_v4();
        let evidence = judge_output_to_evidence(
            &output,
            "s1",
            Uuid::new_v4(),
            vec![host_observed_evidence_id],
        );
        let source = evidence.source.unwrap();
        assert_eq!(source.trust_class, TrustClass::ModelInternal);
        assert_eq!(source.derived_from, vec![host_observed_evidence_id]);
    }

    // --- Unavailable/timeout is honest, never a fabricated pass/fail ---

    #[test]
    fn disabled_judge_reports_unavailable_never_a_fabricated_verdict() {
        let provider = LocalSelfHostedJudgeProvider::new(SemanticJudgeConfig {
            enabled: false,
            ..Default::default()
        });
        let input = JudgeInput::new("the command exited successfully", "command_succeeded");
        let output = provider.judge(&input).unwrap();
        assert_eq!(output.verdict, JudgeVerdict::Unavailable);
        assert_ne!(output.verdict, JudgeVerdict::Supported);
        assert_ne!(output.verdict, JudgeVerdict::Contradicted);
    }

    #[test]
    fn unreachable_endpoint_reports_unavailable_never_hangs_or_panics() {
        let provider = LocalSelfHostedJudgeProvider::new(SemanticJudgeConfig {
            enabled: true,
            // Reserved TEST-NET-1 address per RFC 5737 -- guaranteed
            // unroutable, so this exercises the "unreachable" path
            // deterministically without depending on a real Ollama
            // instance being absent from the test machine.
            endpoint: "http://192.0.2.1:1".into(),
            model: "llama3.1".into(),
            timeout_ms: 500,
        });
        let input = JudgeInput::new("the command exited successfully", "command_succeeded");
        let output = provider.judge(&input).unwrap();
        assert_eq!(output.verdict, JudgeVerdict::Unavailable);
        assert!(!output.rationale.is_empty());
    }

    #[test]
    fn fake_provider_inconclusive_is_distinct_from_unavailable() {
        let provider = FakeProvider(JudgeOutput {
            verdict: JudgeVerdict::Inconclusive,
            rationale: "evidence excerpt does not clearly bear on the claim".into(),
            model: "llama3.1".into(),
            endpoint: "http://localhost:11434/v1".into(),
            prompt_version: JUDGE_PROMPT_VERSION,
            called_at: "2026-01-01T00:00:00Z".into(),
            disagreement: None,
        });
        let input = JudgeInput::new("the command exited successfully", "command_succeeded");
        let output = provider.judge(&input).unwrap();
        assert_eq!(output.verdict, JudgeVerdict::Inconclusive);
        assert_ne!(output.verdict, JudgeVerdict::Unavailable);
    }

    // --- Raw evidence redaction policy ---

    #[test]
    fn raw_evidence_is_redacted_by_default() {
        let input = JudgeInput::new("claim", "subject")
            .with_evidence_excerpt("GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz");
        assert!(!input.allow_raw_evidence);
        let sent = input.redacted_evidence_excerpt();
        assert!(!sent.contains("ghp_1234567890abcdefghijklmnopqrstuvwxyz"));
        assert!(sent.contains("[REDACTED"));
    }

    #[test]
    fn raw_evidence_passes_through_verbatim_only_when_explicitly_allowed() {
        let input = JudgeInput::new("claim", "subject")
            .with_evidence_excerpt("exit_code=0")
            .with_raw_evidence_allowed(true);
        assert!(input.allow_raw_evidence);
        assert_eq!(input.redacted_evidence_excerpt(), "exit_code=0");
    }

    #[test]
    fn from_claim_and_graph_defaults_to_excluding_raw_evidence() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let input = JudgeInput::from_claim_and_graph(&c, &graph, &[], false);
        assert!(!input.allow_raw_evidence);
    }

    /// Regression test for a security-review finding: redaction must run
    /// before truncation, not after. A secret placed just past the 200-char
    /// cut previously survived (only its short, truncated-away prefix was
    /// exposed to redaction) because the payload was sliced to 200 chars
    /// first; redacting the full payload before truncating catches it.
    #[test]
    fn evidence_payload_summary_redacts_a_secret_that_straddles_the_truncation_boundary() {
        let padding = "x".repeat(190);
        let secret = "ghp_aaaabbbbccccddddeeeeffffgggghhhhiiii"; // GitHub-token-shaped
        let ev = Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ProcessObservation,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"note": format!("{padding}{secret}")}),
            provenance: "test".into(),
            source: None,
            extension: None,
        };
        let summary = evidence_payload_summary(&ev, false);
        assert!(
            !summary.contains(secret),
            "secret must not survive redaction regardless of where it falls relative to the 200-char cut"
        );
    }

    #[test]
    fn from_claim_and_graph_summarizes_links_and_missing_notes() {
        let c = claim();
        let evidence_id = Uuid::new_v4();
        let ev = Evidence {
            id: evidence_id,
            session_id: c.session_id.clone(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test".into(),
            source: None,
            extension: None,
        };
        let link = EvidenceLink {
            id: Uuid::new_v4(),
            session_id: c.session_id.clone(),
            claim_id: c.id,
            evidence_id,
            relation: EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:00Z".into(),
        };
        let missing = MissingEvidence {
            id: Uuid::new_v4(),
            session_id: c.session_id.clone(),
            claim_id: c.id,
            signal_class: SignalClass::ProcessResult,
            availability: SignalAvailability::Unavailable,
            detail: None,
            noted_at: "2026-01-01T00:00:00Z".into(),
        };
        let graph = EvidenceGraph {
            links: vec![link],
            missing: vec![missing],
        };
        let input = JudgeInput::from_claim_and_graph(&c, &graph, &[ev], false);
        assert!(input.evidence_excerpt.contains("Supports"));
        assert!(input.evidence_excerpt.contains("ExitCode"));
        assert!(input.evidence_excerpt.contains("missing"));
    }

    // --- Disagreement stays visible ---

    #[test]
    fn disagreement_is_flagged_when_judge_contradicts_known_objective_verdict() {
        let output = JudgeOutput {
            verdict: JudgeVerdict::Supported,
            rationale: "looks fine to me".into(),
            model: "llama3.1".into(),
            endpoint: "http://localhost:11434/v1".into(),
            prompt_version: JUDGE_PROMPT_VERSION,
            called_at: "2026-01-01T00:00:00Z".into(),
            disagreement: None,
        }
        // Objective deterministic evidence says the claim is NOT supported
        // (e.g. fusion produced Verdict::Contradicted).
        .with_disagreement_check(Some(false));
        assert_eq!(output.disagreement, Some(true));
    }

    #[test]
    fn no_disagreement_flag_when_judge_agrees_with_objective_verdict() {
        let output = JudgeOutput {
            verdict: JudgeVerdict::Supported,
            rationale: "looks fine to me".into(),
            model: "llama3.1".into(),
            endpoint: "http://localhost:11434/v1".into(),
            prompt_version: JUDGE_PROMPT_VERSION,
            called_at: "2026-01-01T00:00:00Z".into(),
            disagreement: None,
        }
        .with_disagreement_check(Some(true));
        assert_eq!(output.disagreement, Some(false));
    }

    #[test]
    fn disagreement_stays_none_when_no_objective_verdict_is_known() {
        let output = JudgeOutput {
            verdict: JudgeVerdict::Supported,
            rationale: "looks fine to me".into(),
            model: "llama3.1".into(),
            endpoint: "http://localhost:11434/v1".into(),
            prompt_version: JUDGE_PROMPT_VERSION,
            called_at: "2026-01-01T00:00:00Z".into(),
            disagreement: None,
        }
        .with_disagreement_check(None);
        assert_eq!(
            output.disagreement, None,
            "absence of a comparison must never be conflated with agreement"
        );
    }

    #[test]
    fn inconclusive_or_unavailable_verdicts_never_produce_a_disagreement_flag() {
        for verdict in [JudgeVerdict::Inconclusive, JudgeVerdict::Unavailable] {
            let output = JudgeOutput {
                verdict,
                rationale: "n/a".into(),
                model: "llama3.1".into(),
                endpoint: "http://localhost:11434/v1".into(),
                prompt_version: JUDGE_PROMPT_VERSION,
                called_at: "2026-01-01T00:00:00Z".into(),
                disagreement: None,
            }
            .with_disagreement_check(Some(true));
            assert_eq!(output.disagreement, None, "verdict={verdict:?}");
        }
    }

    // --- Response parsing ---

    #[test]
    fn parse_model_response_recognizes_all_three_committed_verdicts() {
        let (v, _) = parse_model_response("SUPPORTED\nlooks good");
        assert_eq!(v, JudgeVerdict::Supported);
        let (v, _) = parse_model_response("CONTRADICTED\nlooks bad");
        assert_eq!(v, JudgeVerdict::Contradicted);
        let (v, _) = parse_model_response("INCONCLUSIVE\nnot sure");
        assert_eq!(v, JudgeVerdict::Inconclusive);
    }

    #[test]
    fn parse_model_response_falls_back_to_inconclusive_for_unrecognized_shape() {
        let (v, rationale) = parse_model_response("uh, I think maybe yes?");
        assert_eq!(v, JudgeVerdict::Inconclusive);
        assert!(!rationale.is_empty());
    }

    /// Regression test for a real verdict-inversion bug found in security
    /// review: "UNSUPPORTED"/"NOT SUPPORTED" both contain the substring
    /// "SUPPORTED", so a naive `contains("SUPPORTED")` check (checked before
    /// "CONTRADICTED") flipped a negated reply to `Supported` -- the
    /// opposite of what the model said, with no attacker-controlled HTTP
    /// call needed, just word choice in the model's own reply.
    #[test]
    fn parse_model_response_does_not_invert_a_negated_supported_reply() {
        let (v, _) = parse_model_response("UNSUPPORTED\nthe evidence does not back this up");
        assert_eq!(v, JudgeVerdict::Inconclusive);
        let (v, _) = parse_model_response("NOT SUPPORTED\nno backing evidence");
        assert_eq!(v, JudgeVerdict::Inconclusive);
    }

    // --- Config loading ---

    #[test]
    fn missing_config_file_defaults_to_disabled() {
        let cfg = SemanticJudgeConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.endpoint, "http://localhost:11434/v1");
    }

    #[test]
    fn config_round_trips_from_toml() {
        let cfg = SemanticJudgeConfig::from_toml_str(
            "[semantic_judge]\nenabled = true\nendpoint = \"http://localhost:11434/v1\"\n\
             model = \"llama3.1\"\ntimeout_ms = 3000\n",
        )
        .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.model, "llama3.1");
        assert_eq!(cfg.timeout_ms, 3000);
    }

    #[test]
    fn missing_semantic_judge_table_yields_default_disabled_config() {
        let cfg = SemanticJudgeConfig::from_toml_str("[sensors]\ndisabled = []\n").unwrap();
        assert_eq!(cfg, SemanticJudgeConfig::default());
    }

    #[test]
    fn partial_table_falls_back_to_defaults_for_missing_keys() {
        let cfg = SemanticJudgeConfig::from_toml_str("[semantic_judge]\nenabled = true\n").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.endpoint, SemanticJudgeConfig::default().endpoint);
        assert_eq!(cfg.model, SemanticJudgeConfig::default().model);
    }

    #[test]
    fn load_with_no_file_present_yields_disabled_default() {
        let dir = std::env::temp_dir().join(format!("fornax-judge-config-test-{}", Uuid::new_v4()));
        let cfg = SemanticJudgeConfig::load(&dir).unwrap();
        assert_eq!(cfg, SemanticJudgeConfig::default());
    }

    #[test]
    fn load_round_trips_a_real_file_on_disk() {
        let dir = std::env::temp_dir().join(format!("fornax-judge-config-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(fornax_types::sensor_config::SENSOR_CONFIG_FILE),
            "[semantic_judge]\nenabled = true\nmodel = \"mixtral\"\n",
        )
        .unwrap();
        let cfg = SemanticJudgeConfig::load(&dir).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.model, "mixtral");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- Deterministic path unaffected: judge is additive, not load-bearing ---

    #[test]
    fn judge_disabled_by_default_never_participates_unless_configured() {
        // A fresh, never-touched $FORNAX_HOME directory (no config.toml at
        // all) -- deterministic, unlike asserting against this test
        // machine's real $FORNAX_HOME -- is off by default. This is the
        // guarantee that deterministic fusion/decision never implicitly
        // depend on the judge.
        let dir = std::env::temp_dir().join(format!("fornax-judge-config-test-{}", Uuid::new_v4()));
        let cfg = SemanticJudgeConfig::load(&dir).unwrap();
        assert!(!cfg.enabled);
    }

    // --- Replay: same saved input against two different judge configs ----

    #[test]
    fn a_saved_judge_input_can_be_replayed_against_two_different_judge_configs() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let input = JudgeInput::from_claim_and_graph(&c, &graph, &[], false);

        // Simulate "saved to disk, loaded back later" via a real JSON
        // round-trip -- the FORNX-94 replay AC is specifically about a
        // *saved* input, not merely an in-memory value reused twice.
        let saved = serde_json::to_string(&input).unwrap();
        let reloaded: JudgeInput = serde_json::from_str(&saved).unwrap();

        let provider_a = LocalSelfHostedJudgeProvider::new(SemanticJudgeConfig {
            enabled: true,
            model: "llama3.1".into(),
            ..Default::default()
        });
        let provider_b = LocalSelfHostedJudgeProvider::new(SemanticJudgeConfig {
            enabled: true,
            model: "mixtral".into(),
            ..Default::default()
        });

        let output_a = provider_a.judge(&reloaded).unwrap();
        let output_b = provider_b.judge(&reloaded).unwrap();

        // Same saved input, two judge versions -- outputs are independently
        // comparable via their own recorded model/prompt_version metadata.
        assert_eq!(output_a.model, "llama3.1");
        assert_eq!(output_b.model, "mixtral");
        assert_ne!(output_a.model, output_b.model);
        assert_eq!(output_a.prompt_version, JUDGE_PROMPT_VERSION);
        assert_eq!(output_b.prompt_version, JUDGE_PROMPT_VERSION);
    }
}
