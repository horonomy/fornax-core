//! `fornax` CLI (FORNX-31): compact status-line segment + detail drill-down,
//! reading from the same daemon-local API the dashboard uses (FORNX-32) — one
//! source of truth, not three interpretations of session integrity.

use clap::{Parser, Subcommand};

mod experiment_ux;

#[derive(Parser)]
#[command(
    name = "fornax",
    version,
    about = "Fornax local evidence-integrity CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compact one-line integrity summary, suitable for embedding in a
    /// status line segment.
    Status,
    /// Full evidence/finding detail for recent sessions.
    Detail,
    /// Per-`SignalClass` capability availability for one session (FORNX-85):
    /// which signals the announcing runtime(s) actually exposed this
    /// session — available, unsupported, unavailable, redacted, collection-
    /// failed, or not yet announced. Reads `GET /api/capabilities` on the
    /// daemon. Never collapses the six-state availability taxonomy into a
    /// boolean (`capabilities.rs`'s own doc comments, ADR-0001 D4) — each
    /// signal class is rendered with its real, distinct state.
    Capabilities {
        /// Session id to look up.
        session: String,
    },
    /// Claim-centered evidence graph (FORNX-90, local half): every typed
    /// claim-to-evidence link plus every explicit missing-evidence note for
    /// one claim, grouped by relation. Reads `GET /api/evidence-graph` on
    /// the daemon (`fornax-store::Store::evidence_graph_for_claim`,
    /// FORNX-89). Never collapses the graph into a single count/score — a
    /// claim with genuinely zero evidence renders differently from one with
    /// evidence explicitly noted missing, which renders differently again
    /// from a claim id the daemon has never seen.
    EvidenceGraph {
        /// Claim id to look up.
        claim: String,
        /// Session id the claim belongs to.
        session: String,
    },
    /// Live fused verdict for one claim (FORNX-304): computes
    /// `fornax_verify::fusion::BaselineFusionPolicy::fuse` over the claim's
    /// real evidence graph (FORNX-89), falling back to the `project_graph`
    /// projection when the real graph is empty — the same fallback FORNX-93
    /// documents as today's actual production state. Reads `GET
    /// /api/fusion` on the daemon. Every `RationaleEntry` is rendered
    /// individually, never collapsed into a summary — the same
    /// never-collapse-the-taxonomy discipline as `evidence-graph`/
    /// `capabilities`.
    Fusion {
        /// Claim id to look up.
        claim: String,
        /// Session id the claim belongs to.
        session: String,
    },
    /// Actionable recommendation for one claim (FORNX-96, local half):
    /// computes `fornax_verify::fusion::BaselineFusionPolicy::fuse` exactly
    /// like `fusion`, then applies
    /// `fornax_verify::decision::DefaultRiskPolicy` for the requested risk
    /// class to produce a `PROCEED`/`REVIEW`/`BLOCK` recommendation. Reads
    /// `GET /api/decision` on the daemon.
    ///
    /// Never shows the recommendation alone — always renders it together
    /// with the same full fusion detail `fusion` renders (verdict,
    /// uncertainty band, every rationale entry), reusing that rendering
    /// function rather than duplicating it. This is what "user can inspect
    /// why the recommendation changed" means: the recommendation and its
    /// full evidence trail are shown together, and re-running with a
    /// different `--risk` shows how the same evidence can yield a
    /// different action.
    Decision {
        /// Claim id to look up.
        claim: String,
        /// Session id the claim belongs to.
        session: String,
        /// Risk class to evaluate under: `strict`, `balanced`, or
        /// `lenient`. Defaults to `balanced` — the class every hard safety
        /// floor in `fornax_verify::decision` is written against.
        #[arg(long, default_value = "balanced")]
        risk: String,
    },
    /// Semantic Judge opinion for one claim (FORNX-94): sends the claim plus
    /// a bounded, structured evidence-graph excerpt to the configured local
    /// self-hosted judge (Ollama-compatible endpoint, `[semantic_judge]` in
    /// `$FORNAX_HOME/config.toml`, disabled by default) and renders the
    /// resulting model-derived verdict alongside the same full fusion detail
    /// `fusion`/`decision` render — the judge's opinion never replaces or
    /// hides the deterministic evidence trail. Reads `GET /api/judge` on the
    /// daemon.
    ///
    /// A disabled/unreachable/timed-out judge is rendered honestly as
    /// unavailable, never a fabricated pass/fail.
    Judge {
        /// Claim id to look up.
        claim: String,
        /// Session id the claim belongs to.
        session: String,
        /// Explicit opt-in to send unredacted evidence content to the
        /// judge. Off by default — see FORNX-94's "raw protected evidence"
        /// AC.
        #[arg(long, default_value_t = false)]
        allow_raw_evidence: bool,
    },
    /// Context-scoped historical reliability signal, plus an optional drift
    /// check against a second model/adapter version (FORNX-105). Renders
    /// FORNX-103's `ReliabilityContextKey` schema and FORNX-104's
    /// `compute_reliability`/`detect_drift` statistics as a purely local,
    /// display/wiring layer -- this subcommand computes no new statistic
    /// itself. Reads `GET /api/reliability` on the daemon.
    ///
    /// Never shows a bare provider/model trust percentage: a reliability
    /// estimate is only ever rendered together with the full context
    /// dimensions it is scoped to (provider, model family/version, adapter
    /// version, task class, toolset, repository class, policy/verifier/
    /// fusion versions), in the same output. Sparse cohorts render an
    /// explicit "insufficient data -- N of M needed" message, never a
    /// numeric-looking placeholder. A `Drifted` comparison renders an
    /// explicit `⚠ drift detected` banner and marks the baseline's
    /// confidence as stale/superseded rather than showing it plainly beside
    /// the new one.
    ///
    /// Historical reliability aggregation is off by default: the daemon
    /// refuses to aggregate at all unless
    /// `[reliability].historical_aggregation_enabled = true` is set in
    /// `$FORNAX_HOME/config.toml` (the local/SaaS privacy policy gate) --
    /// rendered as its own distinct "aggregation unavailable" message, never
    /// conflated with "insufficient support".
    // Boxed (clippy::large_enum_variant): this variant's context-describing
    // args are ~10 owned `String`/`Option<String>` fields, several times
    // every other variant's size -- boxing keeps `Commands` itself cheap to
    // move/match regardless of which subcommand is chosen.
    Reliability(Box<ReliabilityArgs>),
    /// Export one session's events/claims/evidence/capabilities from the
    /// local store into a directory-based spool, as one wire-compatible
    /// envelope JSON file per message (FORNX-60, FORNX-62). Reads
    /// `$FORNAX_HOME/fornax.db` directly — no daemon dependency, so this
    /// also works while the daemon is stopped.
    ///
    /// Written to `<out>/pending/<id>.json`, matching the layout a consumer
    /// such as fornax-cloud's uploader spool expects: one JSON object per
    /// file, internally tagged with a `"type"` field of `"event"`,
    /// `"claim"`, `"evidence"`, or `"capabilities"`. A `capabilities` file is
    /// only emitted when the session has at least one announcement on
    /// record (FORNX-62) — a session with none produces the same 3-category
    /// output as before this ticket.
    ExportSpool {
        /// Session id to export.
        #[arg(long)]
        session: String,
        /// Spool root directory to write into (its `pending/` subdirectory
        /// is created if missing).
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Idempotently wire the Fornax hooks into `~/.claude/settings.json`
    /// (FORNX-15), matching the `fornax-adapter-claude` doc comment's
    /// documented hook set: SessionStart, UserPromptSubmit, PreToolUse,
    /// PostToolUse, Stop. Safe to run more than once — never duplicates an
    /// entry, and never touches unrelated hooks or settings already present
    /// in the file.
    InstallClaude,
    /// Reverse of `install-claude`: removes only the Fornax hook entries
    /// from `~/.claude/settings.json`, leaving every other hook and setting
    /// untouched. Safe to run when nothing is installed — including when
    /// `~/.claude/settings.json` does not exist, in which case it is left
    /// absent rather than created.
    UninstallClaude,
    /// Idempotently wires Fornax's ambient-status notify script into
    /// `~/.codex/config.toml`'s `notify` entry (FORNX-16/FORNX-17).
    ///
    /// This does **not** configure Codex's evidence-capture path — the
    /// rollout-JSONL tailer (`fornax-hook-codex`) reads Codex's always-on
    /// session transcripts directly and needs no Codex-side configuration
    /// at all; just run it (see the README's Codex section). `notify` is
    /// the separate, optional ambient-status surface documented in
    /// `docs/dogfooding-codex-notify.md`.
    ///
    /// Codex's `notify` holds exactly one command (unlike Claude's
    /// per-event hook arrays), so if it is already wired to something else
    /// this refuses to overwrite it and leaves the file byte-for-byte
    /// unchanged — wire Fornax in manually instead. Comments and unrelated
    /// tables in the file are preserved.
    InstallCodex,
    /// Reverse of `install-codex`: removes the Fornax `notify` entry from
    /// `~/.codex/config.toml` if and only if it is the one `install-codex`
    /// added, leaving every other key/table (and comments) untouched. Safe
    /// to run when nothing is installed, including when
    /// `~/.codex/config.toml` does not exist.
    UninstallCodex,
    /// Counterfactual verification flow (FORNX-101): preview/run/render a
    /// bounded robustness experiment against a claim, wiring together
    /// FORNX-99's `ExperimentSpec` contract, FORNX-100's isolated
    /// `ExperimentExecutor`, and FORNX-102's causal evidence mapping. Runs
    /// entirely client-side against local filesystem paths (no daemon
    /// dependency) — see `experiment_ux`'s module docs for why.
    Experiment {
        #[command(subcommand)]
        action: experiment_ux::ExperimentAction,
    },
    /// Local policy cache (FORNX-119): status and file-based import of a
    /// signed policy bundle over the existing UDS ingest channel.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

/// `fornax policy <action>` (FORNX-119).
#[derive(Subcommand)]
enum PolicyAction {
    /// Renders the local policy cache's slots, per-member freshness tiers,
    /// and degraded/diagnostic state (`GET /api/policy`). Never collapses
    /// the 4-tier x 4-risk-class matrix into one boolean.
    Status,
    /// Reads a signed policy bundle envelope from `path` and submits it to
    /// the daemon over the existing UDS ingest channel
    /// (`IngestMessage::PolicyBundle`, fire-and-forget, no ack). Since
    /// there is no ack, this then re-reads `GET /api/policy` (after a short
    /// delay for the daemon to process the message) and reports whether
    /// the submitted bundle's payload digest is now an active member --
    /// falling back to `last_rejection` for the reason if not.
    Import {
        /// Path to a signed policy bundle envelope JSON file.
        path: std::path::PathBuf,
    },
}

/// Args for `fornax reliability` (FORNX-105), factored out of the `Commands`
/// enum and boxed at the call site (`Commands::Reliability(Box<Self>)`) so
/// this variant's ~10 owned string fields don't blow up `Commands`' overall
/// stack size (`clippy::large_enum_variant`).
#[derive(clap::Args)]
struct ReliabilityArgs {
    /// Session id whose announced capabilities supply the context key's
    /// capability fingerprint.
    session: String,
    #[arg(long)]
    provider: String,
    #[arg(long)]
    model_family: String,
    #[arg(long)]
    model_version: String,
    #[arg(long)]
    adapter_version: String,
    #[arg(long)]
    task_class: String,
    /// Comma-separated tool classes, e.g. `shell,file_edit`. Required, like
    /// every other context dimension (FORNX-103's `ReliabilityContextKey`
    /// deliberately has no `Default`/partial constructor) -- pass `""`
    /// explicitly for a genuinely tool-less context rather than omitting the
    /// flag, so an empty toolset is always a stated fact, never an
    /// accidental omission silently scoping a different cohort.
    #[arg(long)]
    toolset: String,
    #[arg(long)]
    repository_class: String,
    #[arg(long)]
    policy_version: String,
    #[arg(long)]
    verifier_version: String,
    #[arg(long)]
    fusion_version: String,
    /// Compare against this model version for a drift check
    /// (`fornax_verify::reliability::detect_drift`) instead of a plain
    /// reliability read. May be supplied independently of
    /// `--compare-adapter-version` -- either one alone is a legitimate
    /// drift query; any dimension left unspecified falls back to the
    /// baseline's own value.
    #[arg(long)]
    compare_model_version: Option<String>,
    #[arg(long)]
    compare_adapter_version: Option<String>,
}

fn base_url() -> String {
    let port = std::env::var("FORNAX_HTTP_PORT").unwrap_or_else(|_| "4317".to_string());
    format!("http://127.0.0.1:{port}")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => match fetch_json(&format!("{}/api/status", base_url())).await {
            Ok(v) => println!("{}", render_status_line(&v)),
            Err(_) => println!("🛡 fornax: daemon unreachable"),
        },
        Commands::Detail => {
            match fetch_json(&format!("{}/api/findings/recent", base_url())).await {
                Ok(v) => print_detail(&v),
                Err(_) => println!("fornax: daemon unreachable (is `fornax-daemon` running?)"),
            }
        }
        Commands::Capabilities { session } => {
            let url = format!("{}/api/capabilities?session={}", base_url(), session);
            match fetch_json(&url).await {
                Ok(v) => print!("{}", render_capabilities(&v)),
                Err(_) => println!("fornax: daemon unreachable (is `fornax-daemon` running?)"),
            }
        }
        Commands::EvidenceGraph { claim, session } => {
            let url = format!(
                "{}/api/evidence-graph?claim={}&session={}",
                base_url(),
                claim,
                session
            );
            match fetch_json(&url).await {
                Ok(v) => print!("{}", render_evidence_graph(&v)),
                Err(_) => println!("fornax: daemon unreachable (is `fornax-daemon` running?)"),
            }
        }
        Commands::Fusion { claim, session } => {
            let url = format!(
                "{}/api/fusion?claim={}&session={}",
                base_url(),
                claim,
                session
            );
            match fetch_json(&url).await {
                Ok(v) => print!("{}", render_fusion(&v)),
                Err(_) => println!("fornax: daemon unreachable (is `fornax-daemon` running?)"),
            }
        }
        Commands::Decision {
            claim,
            session,
            risk,
        } => {
            let url = format!(
                "{}/api/decision?claim={}&session={}&risk={}",
                base_url(),
                claim,
                session,
                risk
            );
            match fetch_json(&url).await {
                Ok(v) => print!("{}", render_decision(&v)),
                Err(_) => println!("fornax: daemon unreachable (is `fornax-daemon` running?)"),
            }
        }
        Commands::Judge {
            claim,
            session,
            allow_raw_evidence,
        } => {
            let url = format!(
                "{}/api/judge?claim={}&session={}&allow_raw_evidence={}",
                base_url(),
                claim,
                session,
                allow_raw_evidence
            );
            match fetch_json(&url).await {
                Ok(v) => print!("{}", render_judge(&v)),
                Err(_) => println!("fornax: daemon unreachable (is `fornax-daemon` running?)"),
            }
        }
        Commands::Reliability(args) => {
            let ReliabilityArgs {
                session,
                provider,
                model_family,
                model_version,
                adapter_version,
                task_class,
                toolset,
                repository_class,
                policy_version,
                verifier_version,
                fusion_version,
                compare_model_version,
                compare_adapter_version,
            } = *args;
            let mut url = format!(
                "{}/api/reliability?session={session}&provider={provider}&model_family={model_family}\
                 &model_version={model_version}&adapter_version={adapter_version}&task_class={task_class}\
                 &toolset={toolset}&repository_class={repository_class}&policy_version={policy_version}\
                 &verifier_version={verifier_version}&fusion_version={fusion_version}",
                base_url()
            );
            if let Some(cmv) = compare_model_version {
                url.push_str(&format!("&compare_model_version={cmv}"));
            }
            if let Some(cav) = compare_adapter_version {
                url.push_str(&format!("&compare_adapter_version={cav}"));
            }
            match fetch_json(&url).await {
                Ok(v) => print!("{}", render_reliability(&v)),
                Err(_) => println!("fornax: daemon unreachable (is `fornax-daemon` running?)"),
            }
        }
        Commands::ExportSpool { session, out } => export_spool(&session, &out).await?,
        Commands::InstallClaude => install_claude()?,
        Commands::UninstallClaude => uninstall_claude()?,
        Commands::InstallCodex => install_codex()?,
        Commands::UninstallCodex => uninstall_codex()?,
        Commands::Experiment { action } => experiment_ux::handle(action, &fornax_home())?,
        Commands::Policy { action } => handle_policy_action(action).await?,
    }
    Ok(())
}

async fn handle_policy_action(action: PolicyAction) -> anyhow::Result<()> {
    match action {
        PolicyAction::Status => match fetch_json(&format!("{}/api/policy", base_url())).await {
            Ok(v) => print!("{}", render_policy_status(&v)),
            Err(_) => println!("fornax: daemon unreachable (is `fornax-daemon` running?)"),
        },
        PolicyAction::Import { path } => policy_import(&path).await?,
    }
    Ok(())
}

/// Digests the raw envelope bytes the same way `fornax_types::policy::bundle`
/// digests a verified payload -- used only to compare against `GET
/// /api/policy`'s reported member `payload_digest`s locally, so this CLI
/// command can report "did my import take effect" without needing an ack
/// from the fire-and-forget UDS protocol. This is a best-effort match on
/// the *envelope* file's own payload bytes decoded the same way
/// `verify_bundle` does -- not a re-implementation of verification.
fn compute_payload_digest_hint(envelope_bytes: &[u8]) -> Option<String> {
    let envelope: serde_json::Value = serde_json::from_slice(envelope_bytes).ok()?;
    let payload_b64 = envelope.get("payload_b64")?.as_str()?;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let payload_bytes = STANDARD.decode(payload_b64).ok()?;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&payload_bytes);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("sha256:{hex}"))
}

/// FORNX-123: which artifact kind an imported file names, by its own
/// top-level shape -- an emergency responder must not have to pick the
/// right subcommand. Unknown/ambiguous shape refuses with a clear message
/// rather than guessing.
enum PolicyArtifactKind {
    Bundle,
    Revocation,
}

fn detect_artifact_kind(envelope_bytes: &[u8]) -> anyhow::Result<PolicyArtifactKind> {
    let envelope: serde_json::Value = serde_json::from_slice(envelope_bytes)
        .map_err(|e| anyhow::anyhow!("not valid JSON: {e}"))?;
    let has_bundle_key = envelope.get("bundle_schema_version").is_some();
    let has_revocation_key = envelope.get("revocation_schema_version").is_some();
    match (has_bundle_key, has_revocation_key) {
        (true, false) => Ok(PolicyArtifactKind::Bundle),
        (false, true) => Ok(PolicyArtifactKind::Revocation),
        (true, true) => Err(anyhow::anyhow!(
            "ambiguous artifact: carries both bundle_schema_version and \
             revocation_schema_version -- refusing to guess which kind this is"
        )),
        (false, false) => Err(anyhow::anyhow!(
            "unrecognized artifact: carries neither bundle_schema_version nor \
             revocation_schema_version at the top level"
        )),
    }
}

async fn policy_import(path: &std::path::Path) -> anyhow::Result<()> {
    let envelope_bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
    let envelope_text = String::from_utf8(envelope_bytes.clone())
        .map_err(|e| anyhow::anyhow!("{} is not valid UTF-8: {e}", path.display()))?;

    let kind = match detect_artifact_kind(&envelope_bytes) {
        Ok(k) => k,
        Err(e) => {
            println!("fornax: refusing to import {}: {e}", path.display());
            return Ok(());
        }
    };

    let expected_digest = compute_payload_digest_hint(&envelope_bytes);

    let sock_path = fornax_home().join("fornax.sock");
    let mut stream = match tokio::net::UnixStream::connect(&sock_path).await {
        Ok(s) => s,
        Err(e) => {
            println!(
                "fornax: could not reach fornax-daemon at {} ({e}) -- is it running?",
                sock_path.display()
            );
            return Ok(());
        }
    };
    let msg = match kind {
        PolicyArtifactKind::Bundle => fornax_types::IngestMessage::PolicyBundle {
            envelope: envelope_text,
        },
        PolicyArtifactKind::Revocation => fornax_types::IngestMessage::PolicyRevocation {
            envelope: envelope_text,
        },
    };
    let mut line = serde_json::to_string(&msg)?;
    line.push('\n');
    use tokio::io::AsyncWriteExt;
    stream.write_all(line.as_bytes()).await?;
    drop(stream);

    // Fire-and-forget over UDS carries no ack (FORNX-281 precedent) -- give
    // the daemon a moment to process the message before polling for the
    // result.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let status = match fetch_json(&format!("{}/api/policy", base_url())).await {
        Ok(v) => v,
        Err(_) => {
            println!("fornax: submitted, but could not reach the daemon's HTTP API to confirm");
            return Ok(());
        }
    };

    match kind {
        PolicyArtifactKind::Bundle => {
            let active_digests: Vec<String> = status["active"]["members"]
                .as_array()
                .map(|members| {
                    members
                        .iter()
                        .filter_map(|m| m["payload_digest"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();

            match &expected_digest {
                Some(digest) if active_digests.iter().any(|d| d == digest) => {
                    println!(
                        "fornax: policy bundle imported and is now an active member ({digest})"
                    );
                }
                _ => {
                    if let Some(rejection) = status["last_rejection"].as_object() {
                        println!(
                            "fornax: policy bundle was NOT activated -- {} ({})\n  remediation: {}",
                            rejection
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown reason"),
                            rejection
                                .get("code")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown_code"),
                            rejection
                                .get("remediation")
                                .and_then(|v| v.as_str())
                                .unwrap_or("none")
                        );
                    } else {
                        println!(
                            "fornax: submitted, but could not confirm activation yet -- \
                             run `fornax policy status` to check current state"
                        );
                    }
                }
            }
        }
        PolicyArtifactKind::Revocation => {
            // A revocation never becomes an "active member" -- there is no
            // digest-in-active-generation check to make here. The issuer
            // lives inside the signed payload, not the plaintext envelope,
            // so there is nothing authenticated client-side to compare
            // against `revocations.max_sequence_by_issuer` -- report the
            // current state instead of a specific "your list took effect"
            // confirmation.
            println!(
                "fornax: revocation list submitted -- run `fornax policy status` to confirm \
                 the issuer's max_sequence advanced and see the current revocation count"
            );
            if let Some(revocations) = status.get("revocations") {
                println!(
                    "  revocations: entry_count={} unrecognized_entry_count={} max_sequence_by_issuer={}",
                    revocations
                        .get("entry_count")
                        .unwrap_or(&serde_json::Value::Null),
                    revocations
                        .get("unrecognized_entry_count")
                        .unwrap_or(&serde_json::Value::Null),
                    revocations
                        .get("max_sequence_by_issuer")
                        .unwrap_or(&serde_json::Value::Null),
                );
            }
        }
    }
    Ok(())
}

fn render_policy_status(v: &serde_json::Value) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "configured: {}  degraded: {}  loaded_slot: {}\n",
        v.get("configured").unwrap_or(&serde_json::Value::Null),
        v.get("degraded").unwrap_or(&serde_json::Value::Null),
        v.get("loaded_slot")
            .and_then(|s| s.as_str())
            .unwrap_or("none")
    ));
    // FORNX-123: posture is rendered as its own line, never collapsed into
    // the pre-existing `degraded` boolean above -- `degraded` and `posture`
    // answer different questions (see `compute_posture`'s doc comment).
    if let Some(posture) = v.get("posture") {
        out.push_str(&format!("posture: {posture}\n"));
    }
    if let Some(revocations) = v.get("revocations") {
        out.push_str(&format!(
            "revocations: entry_count={} unrecognized_entry_count={} max_sequence_by_issuer={}\n",
            revocations
                .get("entry_count")
                .unwrap_or(&serde_json::Value::Null),
            revocations
                .get("unrecognized_entry_count")
                .unwrap_or(&serde_json::Value::Null),
            revocations
                .get("max_sequence_by_issuer")
                .unwrap_or(&serde_json::Value::Null),
        ));
    }
    if let Some(tiers) = v.get("freshness").and_then(|f| f.get("tier_by_risk")) {
        out.push_str(&format!(
            "freshness (baseline): low={} elevated={} high={} critical={}\n",
            tiers.get("low").unwrap_or(&serde_json::Value::Null),
            tiers.get("elevated").unwrap_or(&serde_json::Value::Null),
            tiers.get("high").unwrap_or(&serde_json::Value::Null),
            tiers.get("critical").unwrap_or(&serde_json::Value::Null),
        ));
    }
    if let Some(members) = v
        .get("active")
        .and_then(|a| a.get("members"))
        .and_then(|m| m.as_array())
    {
        out.push_str(&format!("active generation members: {}\n", members.len()));
        for m in members {
            out.push_str(&format!(
                "  - policy_id={} sequence={} revision={} verified_by={} expires_at={}\n",
                m.get("policy_id").unwrap_or(&serde_json::Value::Null),
                m.get("sequence").unwrap_or(&serde_json::Value::Null),
                m.get("revision").unwrap_or(&serde_json::Value::Null),
                m.get("verified_by").unwrap_or(&serde_json::Value::Null),
                m.get("expires_at").unwrap_or(&serde_json::Value::Null),
            ));
        }
    } else {
        out.push_str("active generation: none\n");
    }
    if let Some(diags) = v.get("diagnostics").and_then(|d| d.as_array()) {
        if !diags.is_empty() {
            out.push_str(&format!("diagnostics ({}):\n", diags.len()));
            for d in diags {
                out.push_str(&format!(
                    "  - [{}] {}: {}\n",
                    d.get("severity").unwrap_or(&serde_json::Value::Null),
                    d.get("code").unwrap_or(&serde_json::Value::Null),
                    d.get("message").and_then(|m| m.as_str()).unwrap_or(""),
                ));
            }
        }
    }
    if let Some(rejection) = v.get("last_rejection").and_then(|r| r.as_object()) {
        out.push_str(&format!(
            "last_rejection: [{}] {}\n",
            rejection.get("code").unwrap_or(&serde_json::Value::Null),
            rejection
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or(""),
        ));
    }
    // FORNX-311: rendered as its own line, one of 8 outcomes -- never
    // collapsed into a boolean.
    match v.get("last_poll") {
        Some(poll) if !poll.is_null() => {
            out.push_str(&format!(
                "last_poll: [{}] {} (bundles_received={} consecutive_failures={} \
                 attempted_at={} next_attempt_at={})\n",
                poll.get("outcome").unwrap_or(&serde_json::Value::Null),
                poll.get("detail").and_then(|m| m.as_str()).unwrap_or(""),
                poll.get("bundles_received")
                    .unwrap_or(&serde_json::Value::Null),
                poll.get("consecutive_failures")
                    .unwrap_or(&serde_json::Value::Null),
                poll.get("attempted_at").unwrap_or(&serde_json::Value::Null),
                poll.get("next_attempt_at")
                    .unwrap_or(&serde_json::Value::Null),
            ));
        }
        _ => out.push_str("last_poll: none (no poll cycle has completed yet)\n"),
    }
    out
}

fn fornax_home() -> std::path::PathBuf {
    std::env::var("FORNAX_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| dirs_home().join(".fornax"))
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// The `command` value the `fornax-adapter-claude` doc comment documents for
/// wiring into `~/.claude/settings.json` hooks.
const FORNAX_HOOK_COMMAND: &str = "fornax-hook-claude";

/// Hook event names the `fornax-adapter-claude` doc comment documents as
/// the wired set. Kept in sync with that doc comment — see
/// `crates/fornax-adapter-claude/src/main.rs`.
const CLAUDE_HOOK_EVENTS: [&str; 5] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
];

fn claude_settings_path() -> std::path::PathBuf {
    dirs_home().join(".claude").join("settings.json")
}

fn load_settings(path: &std::path::Path) -> anyhow::Result<serde_json::Value> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let contents = std::fs::read_to_string(path)?;
    if contents.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    let value: serde_json::Value = serde_json::from_str(&contents)?;
    anyhow::ensure!(
        value.is_object(),
        "{} does not contain a JSON object at its root — refusing to touch it",
        path.display()
    );
    Ok(value)
}

/// Atomically overwrites `path` with `settings` (write-to-temp then rename,
/// same pattern `write_envelope` uses below) so a crash or concurrent read
/// never observes a half-written `~/.claude/settings.json`.
fn save_settings(path: &std::path::Path, settings: &serde_json::Value) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut json = serde_json::to_string_pretty(settings)?;
    json.push('\n');
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// True if this hook group already carries a Fornax command entry.
fn group_has_fornax_command(group: &serde_json::Value) -> bool {
    group
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|entries| {
            entries
                .iter()
                .any(|h| h.get("command").and_then(|c| c.as_str()) == Some(FORNAX_HOOK_COMMAND))
        })
        .unwrap_or(false)
}

/// Idempotently ensures each hook in `CLAUDE_HOOK_EVENTS` has one group
/// running `fornax-hook-claude`, without touching any other group/event
/// already present in `settings`.
///
/// `settings` must already be a JSON object (guaranteed by `load_settings`).
/// If an existing `"hooks"` value, or an existing per-event value, is
/// present but not the shape Claude Code expects (object / array
/// respectively), this refuses to clobber it and returns an error instead —
/// per the "safe failure mode rather than corrupting Claude Code config"
/// constraint.
fn install_claude_hooks(settings: &mut serde_json::Value) -> anyhow::Result<()> {
    let root = settings
        .as_object_mut()
        .expect("caller guarantees settings is a JSON object");
    let hooks = root.entry("hooks").or_insert_with(|| serde_json::json!({}));
    anyhow::ensure!(
        hooks.is_object(),
        "existing \"hooks\" value in settings.json is not an object — refusing to overwrite it"
    );
    let hooks_obj = hooks.as_object_mut().expect("just checked is_object");

    for event in CLAUDE_HOOK_EVENTS {
        let entries = hooks_obj
            .entry(event)
            .or_insert_with(|| serde_json::json!([]));
        anyhow::ensure!(
            entries.is_array(),
            "existing \"hooks.{event}\" value in settings.json is not an array — refusing to overwrite it"
        );
        let entries_arr = entries.as_array_mut().expect("just checked is_array");
        let already_installed = entries_arr.iter().any(group_has_fornax_command);
        if !already_installed {
            entries_arr.push(serde_json::json!({
                "hooks": [{ "type": "command", "command": FORNAX_HOOK_COMMAND }]
            }));
        }
    }
    Ok(())
}

/// Removes only Fornax hook entries from `settings`, leaving every other
/// hook group, hook event, and top-level setting exactly as it was. Cleans
/// up groups/events left empty by the removal, but never removes a group
/// that still carries another tool's hook entry.
fn uninstall_claude_hooks(settings: &mut serde_json::Value) {
    let Some(hooks_obj) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return;
    };

    for event in CLAUDE_HOOK_EVENTS {
        let Some(entries) = hooks_obj.get_mut(event).and_then(|e| e.as_array_mut()) else {
            continue;
        };
        for group in entries.iter_mut() {
            if let Some(group_hooks) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                group_hooks.retain(|h| {
                    h.get("command").and_then(|c| c.as_str()) != Some(FORNAX_HOOK_COMMAND)
                });
            }
        }
        entries.retain(|group| {
            group
                .get("hooks")
                .and_then(|h| h.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(true)
        });
    }

    hooks_obj.retain(|_, v| v.as_array().map(|a| !a.is_empty()).unwrap_or(true));
    if hooks_obj.is_empty() {
        settings
            .as_object_mut()
            .expect("checked object above")
            .remove("hooks");
    }
}

fn install_claude_at(path: &std::path::Path) -> anyhow::Result<()> {
    let before = load_settings(path)?;
    let mut settings = before.clone();
    install_claude_hooks(&mut settings)?;
    if settings == before {
        println!(
            "Fornax Claude Code hooks already installed in {}",
            path.display()
        );
        return Ok(());
    }
    save_settings(path, &settings)?;
    println!("Installed Fornax Claude Code hooks in {}", path.display());
    Ok(())
}

fn uninstall_claude_at(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.exists() {
        // Nothing was ever installed — leave the machine exactly as it was
        // rather than creating a settings.json the user never had.
        println!(
            "No Fornax Claude Code hooks to remove ({} does not exist)",
            path.display()
        );
        return Ok(());
    }
    let before = load_settings(path)?;
    let mut settings = before.clone();
    uninstall_claude_hooks(&mut settings);
    if settings == before {
        println!("No Fornax Claude Code hooks found in {}", path.display());
        return Ok(());
    }
    save_settings(path, &settings)?;
    println!("Removed Fornax Claude Code hooks from {}", path.display());
    Ok(())
}

fn install_claude() -> anyhow::Result<()> {
    install_claude_at(&claude_settings_path())
}

fn uninstall_claude() -> anyhow::Result<()> {
    uninstall_claude_at(&claude_settings_path())
}

/// Filename marker identifying a Fornax-owned `notify` entry in
/// `~/.codex/config.toml`. Matched by suffix (rather than requiring a
/// byte-for-byte absolute-path match) so uninstall still recognizes an
/// install made from a different checkout of this repo.
const CODEX_NOTIFY_SCRIPT_MARKER: &str = "fornax-codex-notify.sh";

fn codex_config_path() -> std::path::PathBuf {
    dirs_home().join(".codex").join("config.toml")
}

/// Absolute path to `scripts/fornax-codex-notify.sh`, resolved relative to
/// this crate's location in the workspace at compile time — matches the
/// documented from-source workflow (`cargo build --workspace` from the
/// repo root; see `docs/dogfooding-codex-notify.md`).
fn default_codex_notify_script() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/fornax-codex-notify.sh")
}

/// Parses `path` as a format-preserving TOML document (comments and table
/// ordering survive edits), or an empty document if `path` does not exist.
/// Unlike `load_settings`'s JSON equivalent, a `~/.codex/config.toml` that
/// fails to parse as TOML is always a hard error — there is no sensible
/// "treat it as empty" fallback for a file this consequential.
fn load_codex_config(path: &std::path::Path) -> anyhow::Result<toml_edit::DocumentMut> {
    if !path.exists() {
        return Ok(toml_edit::DocumentMut::new());
    }
    let contents = std::fs::read_to_string(path)?;
    contents.parse::<toml_edit::DocumentMut>().map_err(|e| {
        anyhow::anyhow!(
            "{} is not valid TOML — refusing to touch it: {e}",
            path.display()
        )
    })
}

/// Atomically overwrites `path` with `doc` (write-to-temp then rename, same
/// pattern `save_settings` uses for Claude's JSON). Additionally preserves
/// the original file's Unix permissions on the replacement — a real
/// `~/.codex/config.toml` on this machine is mode 0600, and this repo's own
/// capability-matrix research (FORNX-33) has found plaintext secrets in
/// other Codex on-disk files, so silently widening this file to the
/// process umask's default mode on rename would be a real regression, not
/// a cosmetic one. A freshly created file gets 0600 rather than an
/// umask-dependent default.
fn save_codex_config(path: &std::path::Path, doc: &toml_edit::DocumentMut) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, doc.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map(|m| m.permissions().mode())
            .unwrap_or(0o600);
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// True if `notify`'s first element is a Fornax-owned notify script.
///
/// Compares the path's basename exactly, not a bare `ends_with` on the
/// whole string — a foreign script at e.g. `/opt/my-fornax-codex-notify.sh`
/// would `ends_with(CODEX_NOTIFY_SCRIPT_MARKER)` even though its basename
/// is a different file, which would make `uninstall-codex` delete a
/// user's real, unrelated `notify` configuration.
fn notify_is_fornax(item: &toml_edit::Item) -> bool {
    item.as_array()
        .and_then(|a| a.get(0))
        .and_then(|v| v.as_str())
        .map(|s| {
            std::path::Path::new(s).file_name().and_then(|f| f.to_str())
                == Some(CODEX_NOTIFY_SCRIPT_MARKER)
        })
        .unwrap_or(false)
}

/// Idempotently wires `script_path` into `config_path`'s `notify` entry.
///
/// Codex's `notify` holds exactly one command — its first element is the
/// program, any remaining elements are that program's own extra arguments,
/// not additional commands (see `docs/dogfooding-codex-notify.md`'s
/// live-captured invocation shape). So unlike Claude's per-event hook
/// arrays, this can never safely *add* Fornax alongside an existing
/// foreign `notify` value — doing so would either replace the user's
/// configured command outright or corrupt it by appending Fornax's path as
/// that command's own argument. If `notify` is already set to something
/// other than this exact script, this refuses to touch the file and
/// returns an error instead.
fn install_codex_notify_at(
    config_path: &std::path::Path,
    script_path: &std::path::Path,
) -> anyhow::Result<()> {
    let mut doc = load_codex_config(config_path)?;
    let script_str = script_path.to_string_lossy().into_owned();

    if let Some(existing) = doc.get("notify") {
        anyhow::ensure!(
            existing.is_array(),
            "existing \"notify\" value in {} is not an array — refusing to overwrite it",
            config_path.display()
        );
        let existing_first = existing
            .as_array()
            .and_then(|a| a.get(0))
            .and_then(|v| v.as_str());
        if existing_first == Some(script_str.as_str()) {
            println!(
                "Fornax Codex notify already installed in {}",
                config_path.display()
            );
            return Ok(());
        }
        anyhow::bail!(
            "existing \"notify\" in {} is already wired to {:?} — refusing to overwrite it \
             (Codex's notify holds exactly one command; wire Fornax in manually alongside \
             it, or remove the existing entry first)",
            config_path.display(),
            existing_first.unwrap_or("<non-string entry>")
        );
    }

    let mut arr = toml_edit::Array::new();
    arr.push(script_str);
    doc["notify"] = toml_edit::Item::Value(toml_edit::Value::Array(arr));
    save_codex_config(config_path, &doc)?;
    println!(
        "Installed Fornax Codex notify wiring in {}",
        config_path.display()
    );
    Ok(())
}

/// Removes the Fornax `notify` entry from `config_path` iff it is the one
/// `install-codex` added, leaving every other key/table and comment
/// exactly as it was.
fn uninstall_codex_notify_at(config_path: &std::path::Path) -> anyhow::Result<()> {
    if !config_path.exists() {
        // Nothing was ever installed — leave the machine exactly as it
        // was rather than creating a config.toml the user never had.
        println!(
            "No Fornax Codex notify wiring to remove ({} does not exist)",
            config_path.display()
        );
        return Ok(());
    }
    let mut doc = load_codex_config(config_path)?;
    let Some(existing) = doc.get("notify") else {
        println!(
            "No Fornax Codex notify wiring found in {}",
            config_path.display()
        );
        return Ok(());
    };
    if !notify_is_fornax(existing) {
        println!(
            "No Fornax Codex notify wiring found in {}",
            config_path.display()
        );
        return Ok(());
    }
    doc.remove("notify");
    save_codex_config(config_path, &doc)?;
    println!(
        "Removed Fornax Codex notify wiring from {}",
        config_path.display()
    );
    Ok(())
}

fn install_codex() -> anyhow::Result<()> {
    install_codex_notify_at(&codex_config_path(), &default_codex_notify_script())
}

fn uninstall_codex() -> anyhow::Result<()> {
    uninstall_codex_notify_at(&codex_config_path())
}

/// Writes one envelope JSON file into `<out>/pending/<id>.json`, internally
/// tagged with `"type"` alongside the value's own fields — matching how
/// `#[serde(tag = "type")]` on a newtype-of-struct enum variant serializes,
/// without depending on that enum type directly (it lives in a separate
/// repo/crate; fornax-core intentionally has no dependency on fornax-cloud).
fn write_envelope(
    pending_dir: &std::path::Path,
    type_tag: &str,
    id: uuid::Uuid,
    value: &impl serde::Serialize,
) -> anyhow::Result<()> {
    let mut obj = serde_json::to_value(value)?;
    obj.as_object_mut()
        .expect("envelope payload must serialize to a JSON object")
        .insert(
            "type".to_string(),
            serde_json::Value::String(type_tag.to_string()),
        );
    let final_path = pending_dir.join(format!("{id}.json"));
    let tmp_path = pending_dir.join(format!("{id}.json.tmp"));
    std::fs::write(&tmp_path, serde_json::to_vec(&obj)?)?;
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

async fn export_spool(session: &str, out: &std::path::Path) -> anyhow::Result<()> {
    let db_path = fornax_home().join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await?;
    export_spool_from_store(&store, session, out).await
}

/// Does the actual read + write work for `export_spool`, taking an
/// already-open `Store` so it can be exercised in tests without touching
/// `$FORNAX_HOME` (which is process-global and unsafe to mutate per-test).
async fn export_spool_from_store(
    store: &fornax_store::Store,
    session: &str,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let events = store.events_for_session(session).await?;
    let claims = store.claims_for_session(session).await?;
    let evidence_read = store.evidence_for_session(session).await?;
    if !evidence_read.failed.is_empty() {
        eprintln!(
            "fornax: {} of {} evidence rows for session {session} failed to deserialize and were not exported: {}",
            evidence_read.failed.len(),
            evidence_read.evidence.len() + evidence_read.failed.len(),
            evidence_read
                .failed
                .iter()
                .map(|f| format!("{} ({})", f.id, f.error))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let evidence = evidence_read.evidence;
    let capabilities = store.capabilities_for_session(session).await?;

    let pending_dir = out.join("pending");
    std::fs::create_dir_all(&pending_dir)?;

    for e in &events {
        write_envelope(&pending_dir, "event", e.id, e)?;
    }
    for c in &claims {
        write_envelope(&pending_dir, "claim", c.id, c)?;
    }
    for ev in &evidence {
        write_envelope(&pending_dir, "evidence", ev.id, ev)?;
    }
    for caps in &capabilities {
        // RuntimeCapabilities carries no id of its own on the wire (the
        // cloud backend keys these on (device_id, provider), never on an
        // envelope id — see fornax-cloud's fornax-uploader::types::IngestMessage
        // ::canonical_id doc comment) — synthesize one purely for the spool
        // filename, matching that same convention.
        //
        // FORNX-155: the domain `RuntimeCapabilities` now carries
        // `schema_version`/`signals`. FORNX-301 additively includes both of
        // those, plus `session_id`, on the exported wire shape so
        // fornax-cloud can receive the rich per-signal taxonomy instead of
        // only the down-projected bools — the nine legacy flat-bool keys
        // remain unchanged, since `fornax-cloud`'s `device_capabilities`
        // worker-gate consumer still reads exactly those. See
        // `fornax_types::capabilities::LegacyCapabilitiesWire`'s doc comment.
        let mut legacy = fornax_types::LegacyCapabilitiesWire::from(caps);
        legacy.session_id = Some(session.to_string());
        write_envelope(&pending_dir, "capabilities", uuid::Uuid::new_v4(), &legacy)?;
    }

    println!(
        "exported session {session}: {} event(s), {} claim(s), {} evidence, {} capabilities -> {}",
        events.len(),
        claims.len(),
        evidence.len(),
        capabilities.len(),
        pending_dir.display()
    );
    Ok(())
}

async fn fetch_json(url: &str) -> anyhow::Result<serde_json::Value> {
    Ok(reqwest::get(url).await?.json::<serde_json::Value>().await?)
}

fn render_status_line(v: &serde_json::Value) -> String {
    let Some(latest) = v.get("latest").filter(|l| !l.is_null()) else {
        return "🛡 fornax: no findings yet".to_string();
    };
    let verdict = latest
        .get("verdict")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");
    let icon = verdict_icon(verdict);
    format!("{icon} {}", verdict.to_uppercase())
}

fn verdict_icon(verdict: &str) -> &'static str {
    match verdict {
        "verified" => "🛡 ✓",
        "contradicted" => "🛡 ✕",
        "unverified" => "🛡 ?",
        "review" => "🛡 !",
        "unavailable" => "🛡 —",
        _ => "🛡",
    }
}

fn print_detail(v: &serde_json::Value) {
    let empty = vec![];
    let findings = v
        .get("findings")
        .and_then(|f| f.as_array())
        .unwrap_or(&empty);
    if findings.is_empty() {
        println!("No findings recorded yet.");
        return;
    }
    for f in findings {
        let verdict = f.get("verdict").and_then(|s| s.as_str()).unwrap_or("?");
        let claim = f.get("claim_text").and_then(|s| s.as_str()).unwrap_or("");
        let rationale = f.get("rationale").and_then(|s| s.as_str()).unwrap_or("");
        let verifier = f
            .get("verifier_name")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        let when = f.get("computed_at").and_then(|s| s.as_str()).unwrap_or("");
        println!("{} {}", verdict_icon(verdict), verdict.to_uppercase());
        println!("  claim:     {claim}");
        println!("  rationale: {rationale}");
        println!("  verifier:  {verifier}");
        println!("  when:      {when}");
        println!();
    }
}

/// Icon for a `SignalAvailability` state, mirroring `verdict_icon`'s
/// distinct-per-state convention. FORNX-85/ADR-0001 D4: the six-state
/// availability taxonomy must never collapse into a boolean — each state
/// gets its own icon and label, and an unrecognized tag is shown verbatim
/// rather than mapped onto an existing state.
fn availability_icon(state: &str) -> &'static str {
    match state {
        "available" => "✓",
        "unsupported" => "⛔",
        "unavailable" => "—",
        "redacted" => "▮",
        "collection_failed" => "✕",
        "unknown" => "?",
        _ => "◌",
    }
}

/// Renders `GET /api/capabilities`'s response: one section per announcing
/// provider, one line per declared `SignalClass`, each showing its exact
/// `SignalAvailability` state (and `detail`, when present) rather than a
/// summarized available/not-available boolean. Returns the rendered text
/// (rather than printing directly) so it can be asserted on in tests, the
/// same shape as `render_status_line`.
fn render_capabilities(v: &serde_json::Value) -> String {
    let mut out = String::new();
    let session = v.get("session").and_then(|s| s.as_str()).unwrap_or("?");
    let announced = v
        .get("announced")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    out.push_str(&format!("session: {session}\n"));
    if !announced {
        let reason = v
            .get("reason")
            .and_then(|s| s.as_str())
            .unwrap_or("no capabilities announced yet");
        out.push_str(&format!("  no capabilities announced yet ({reason})\n"));
        return out;
    }
    let empty = vec![];
    let capabilities = v
        .get("capabilities")
        .and_then(|c| c.as_array())
        .unwrap_or(&empty);
    for caps in capabilities {
        let provider = caps.get("provider").and_then(|s| s.as_str()).unwrap_or("?");
        out.push_str(&format!("  provider: {provider}\n"));
        let empty_signals = vec![];
        let signals = caps
            .get("signals")
            .and_then(|s| s.as_array())
            .unwrap_or(&empty_signals);
        if signals.is_empty() {
            out.push_str("    (no signal classes declared)\n");
            continue;
        }
        for signal in signals {
            let class = signal.get("class").and_then(|s| s.as_str()).unwrap_or("?");
            let state = signal.get("state").and_then(|s| s.as_str()).unwrap_or("?");
            let icon = availability_icon(state);
            match signal.get("detail").and_then(|s| s.as_str()) {
                Some(detail) => out.push_str(&format!("    {icon} {class}: {state} ({detail})\n")),
                None => out.push_str(&format!("    {icon} {class}: {state}\n")),
            }
        }
    }
    out
}

/// Icon for an `EvidenceRelation`, mirroring `verdict_icon`/`availability_icon`'s
/// distinct-per-state convention (FORNX-90). An unrecognized tag is shown
/// verbatim rather than mapped onto an existing relation.
fn relation_icon(relation: &str) -> &'static str {
    match relation {
        "supports" => "✚",
        "contradicts" => "✕",
        "neutral" => "•",
        _ => "◌",
    }
}

/// Renders `GET /api/evidence-graph`'s response (FORNX-90, local Evidence
/// Explorer): every linked-evidence relation grouped by
/// `EvidenceRelation`, plus every missing-evidence note, each item shown
/// individually rather than collapsed into a count. Returns the rendered
/// text (rather than printing directly) so it can be asserted on in tests,
/// the same shape as `render_capabilities`.
///
/// Deliberately renders three distinguishable outcomes for the same "empty
/// links" surface state, the core product invariant this ticket exists
/// for: the claim id is unknown to the daemon at all; the claim exists but
/// nobody has linked or noted anything ("nobody has looked"); and the claim
/// exists with evidence explicitly noted missing even though no link exists
/// ("looked, but it could not be collected").
fn render_evidence_graph(v: &serde_json::Value) -> String {
    let mut out = String::new();
    let claim = v.get("claim").and_then(|s| s.as_str()).unwrap_or("?");
    let session = v.get("session").and_then(|s| s.as_str()).unwrap_or("?");
    out.push_str(&format!("claim: {claim}\nsession: {session}\n"));

    // A daemon-side error (e.g. a store read failure) carries no `found`
    // key at all — must be reported as its own distinct outcome, never
    // defaulted into the "claim not found" case (that would conflate "we
    // don't know" with "we looked and it's absent").
    if let Some(error) = v.get("error").and_then(|s| s.as_str()) {
        out.push_str(&format!("  error: {error}\n"));
        return out;
    }

    let found = v.get("found").and_then(|b| b.as_bool()).unwrap_or(false);
    if !found {
        let reason = v
            .get("reason")
            .and_then(|s| s.as_str())
            .unwrap_or("no claim with this id is on record for this session");
        out.push_str(&format!("  no such claim on record ({reason})\n"));
        return out;
    }

    let empty = vec![];
    let links = v.get("links").and_then(|l| l.as_array()).unwrap_or(&empty);
    let missing = v
        .get("missing")
        .and_then(|m| m.as_array())
        .unwrap_or(&empty);

    if links.is_empty() && missing.is_empty() {
        out.push_str(
            "  no evidence linked and no missing-evidence notes recorded for this claim\n",
        );
        return out;
    }

    if links.is_empty() {
        out.push_str("  no evidence linked to this claim\n");
    } else {
        // FORNX-92 AC: "Conflicts remain inspectable in Evidence Explorer" —
        // surface, but do not resolve, a claim carrying both a `supports`
        // and a `contradicts` link.
        let supports_count = links
            .iter()
            .filter(|l| l.get("relation").and_then(|r| r.as_str()) == Some("supports"))
            .count();
        let contradicts_count = links
            .iter()
            .filter(|l| l.get("relation").and_then(|r| r.as_str()) == Some("contradicts"))
            .count();
        if supports_count > 0 && contradicts_count > 0 {
            out.push_str(&format!(
                "  ⚠ conflict: {supports_count} supports vs {contradicts_count} contradicts (unresolved)\n"
            ));
        }

        let known_relations = ["supports", "contradicts", "neutral"];
        // Forward-compat: a link whose relation is not one of the three
        // known states must still be shown, not silently dropped — the AC
        // requires every item to appear, never a collapsed count.
        let mut unrecognized_relations: Vec<&str> = links
            .iter()
            .filter_map(|l| l.get("relation").and_then(|r| r.as_str()))
            .filter(|r| !known_relations.contains(r))
            .collect();
        unrecognized_relations.sort_unstable();
        unrecognized_relations.dedup();

        for relation in known_relations
            .iter()
            .copied()
            .chain(unrecognized_relations.iter().copied())
        {
            let group: Vec<&serde_json::Value> = links
                .iter()
                .filter(|l| l.get("relation").and_then(|r| r.as_str()) == Some(relation))
                .collect();
            if group.is_empty() {
                continue;
            }
            out.push_str(&format!(
                "  {} {} ({})\n",
                relation_icon(relation),
                relation,
                group.len()
            ));
            for link in group {
                let evidence_id = link
                    .get("evidence_id")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");
                let linked_at = link
                    .get("linked_at")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");
                out.push_str(&format!(
                    "    evidence: {evidence_id}  linked_at: {linked_at}\n"
                ));
            }
        }
    }

    if !missing.is_empty() {
        out.push_str(&format!("  ◌ missing ({})\n", missing.len()));
        for note in missing {
            let signal_class = note
                .get("signal_class")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            let availability = note
                .get("availability")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            match note.get("detail").and_then(|s| s.as_str()) {
                Some(detail) => {
                    out.push_str(&format!("    {signal_class}: {availability} ({detail})\n"))
                }
                None => out.push_str(&format!("    {signal_class}: {availability}\n")),
            }
        }
    }

    out
}

/// Icon for a `RuleEffect` tag, mirroring `verdict_icon`/`availability_icon`'s
/// distinct-per-state convention. An unrecognized tag is shown verbatim
/// rather than mapped onto an existing effect.
fn rule_effect_icon(effect: &str) -> &'static str {
    match effect {
        "counted" => "✚",
        "discounted" => "✕",
        "caveat" => "⚠",
        "decided" => "🛡",
        _ => "◌",
    }
}

/// Renders `GET /api/fusion`'s response (FORNX-304): the live `FusedFinding`
/// computed from a claim's real evidence graph (FORNX-89/FORNX-93), or the
/// `project_graph` fallback when that graph is empty. Every
/// `RationaleEntry` is rendered individually — rule name, effect, every
/// referenced link/missing-evidence/evidence id, and the detail text —
/// never collapsed into a summary count, the same never-collapse-the-
/// taxonomy discipline `render_evidence_graph`/`render_capabilities` follow.
/// Returns the rendered text (rather than printing directly) so it can be
/// asserted on in tests.
fn render_fusion(v: &serde_json::Value) -> String {
    let mut out = String::new();
    let claim = v.get("claim").and_then(|s| s.as_str()).unwrap_or("?");
    let session = v.get("session").and_then(|s| s.as_str()).unwrap_or("?");
    out.push_str(&format!("claim: {claim}\nsession: {session}\n"));

    if let Some(error) = v.get("error").and_then(|s| s.as_str()) {
        out.push_str(&format!("  error: {error}\n"));
        return out;
    }

    let found = v.get("found").and_then(|b| b.as_bool()).unwrap_or(false);
    if !found {
        let reason = v
            .get("reason")
            .and_then(|s| s.as_str())
            .unwrap_or("no claim with this id is on record for this session");
        out.push_str(&format!("  no such claim on record ({reason})\n"));
        return out;
    }

    let graph_source = v
        .get("graph_source")
        .and_then(|s| s.as_str())
        .unwrap_or("?");
    out.push_str(&format!("  graph_source: {graph_source}\n"));

    let fused = v.get("fused").cloned().unwrap_or_default();
    let verdict = fused.get("verdict").and_then(|s| s.as_str()).unwrap_or("?");
    let uncertainty = fused
        .get("uncertainty")
        .and_then(|s| s.as_str())
        .unwrap_or("?");
    let policy_name = fused
        .get("policy_name")
        .and_then(|s| s.as_str())
        .unwrap_or("?");
    let policy_version = fused
        .get("policy_version")
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    let computed_at = fused
        .get("computed_at")
        .and_then(|s| s.as_str())
        .unwrap_or("?");
    let unresolved_conflict = fused
        .get("unresolved_conflict")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);

    out.push_str(&format!(
        "  {} {}  (uncertainty: {})\n",
        verdict_icon(verdict),
        verdict.to_uppercase(),
        uncertainty
    ));
    if unresolved_conflict {
        out.push_str("  ⚠ unresolved conflict: not auto-resolved\n");
    }
    out.push_str(&format!(
        "  policy: {policy_name} v{policy_version}  computed_at: {computed_at}\n"
    ));

    let empty = vec![];
    let rationale = fused
        .get("rationale")
        .and_then(|r| r.as_array())
        .unwrap_or(&empty);
    if rationale.is_empty() {
        out.push_str("  rationale: (none)\n");
        return out;
    }
    out.push_str(&format!("  rationale ({}):\n", rationale.len()));
    for entry in rationale {
        let rule = entry.get("rule").and_then(|s| s.as_str()).unwrap_or("?");
        let effect = entry.get("effect").and_then(|s| s.as_str()).unwrap_or("?");
        let detail = entry.get("detail").and_then(|s| s.as_str()).unwrap_or("");
        out.push_str(&format!(
            "    {} {} [{}]: {}\n",
            rule_effect_icon(effect),
            rule,
            effect,
            detail
        ));
        let ids_line = |key: &str| -> Option<String> {
            let ids: Vec<&str> = entry
                .get(key)
                .and_then(|a| a.as_array())
                .into_iter()
                .flatten()
                .filter_map(|id| id.as_str())
                .collect();
            if ids.is_empty() {
                None
            } else {
                Some(format!("      {key}: {}\n", ids.join(", ")))
            }
        };
        for key in ["link_ids", "missing_evidence_ids", "evidence_ids"] {
            if let Some(line) = ids_line(key) {
                out.push_str(&line);
            }
        }
    }

    out
}

/// Icon for a `Recommendation::action` value, mirroring `verdict_icon`'s
/// never-collapse-the-vocabulary discipline: three actions, three distinct
/// icons, no default that could be mistaken for a real one.
fn recommendation_icon(action: &str) -> &'static str {
    match action {
        "proceed" => "✓",
        "review" => "!",
        "block" => "✕",
        _ => "?",
    }
}

/// Renders `GET /api/decision`'s response (FORNX-96, local half): the
/// `Recommendation` computed for the requested risk class, followed by the
/// SAME full fusion detail `render_fusion` renders for `fornax fusion` —
/// reusing that function rather than duplicating its rendering logic. This
/// is what "recommendation never replaces the underlying Finding/evidence
/// graph" means at the CLI layer: both are always shown together. When the
/// claim isn't found or the daemon reports an error, `render_fusion` alone
/// already handles both cases correctly (this response shares that shape),
/// so no `recommendation` block is printed in either case.
fn render_decision(v: &serde_json::Value) -> String {
    let mut out = String::new();
    let found = v.get("found").and_then(|b| b.as_bool()).unwrap_or(false);
    let has_error = v.get("error").is_some();
    if found && !has_error {
        if let Some(rec) = v.get("recommendation") {
            let action = rec.get("action").and_then(|s| s.as_str()).unwrap_or("?");
            let risk_class = rec
                .get("risk_class")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            let policy_name = rec
                .get("policy_name")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            let policy_version = rec
                .get("policy_version")
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            let rationale_summary = rec
                .get("rationale_summary")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            out.push_str(&format!(
                "recommendation: {} {}  (risk: {}, policy: {} v{})\n  {}\n\n",
                recommendation_icon(action),
                action.to_uppercase(),
                risk_class,
                policy_name,
                policy_version,
                rationale_summary
            ));
        }
    }
    out.push_str(&render_fusion(v));
    out
}

/// Icon for a `JudgeOutput::verdict` value -- four distinct icons, never
/// collapsed, mirroring `verdict_icon`/`recommendation_icon`'s discipline.
/// `unavailable` gets its own icon distinct from `inconclusive` -- "the
/// judge tried and couldn't decide" must read differently from "the judge
/// never weighed in at all" (FORNX-94 module docs).
fn judge_verdict_icon(verdict: &str) -> &'static str {
    match verdict {
        "supported" => "✓",
        "contradicted" => "✕",
        "inconclusive" => "?",
        "unavailable" => "—",
        _ => "?",
    }
}

/// Renders `GET /api/judge`'s response (FORNX-94): the Semantic Judge's
/// model-derived opinion, clearly labeled as such, followed by the same
/// full fusion detail `render_fusion`/`render_decision` render -- the
/// judge's opinion is always shown alongside, never instead of, the
/// deterministic evidence trail. A disagreement between the judge and
/// already-known deterministic evidence is surfaced as an explicit banner,
/// never silently dropped.
fn render_judge(v: &serde_json::Value) -> String {
    let mut out = String::new();
    let found = v.get("found").and_then(|b| b.as_bool()).unwrap_or(false);
    let has_error = v.get("error").is_some();
    if found && !has_error {
        if let Some(judge) = v.get("judge") {
            let verdict = judge.get("verdict").and_then(|s| s.as_str()).unwrap_or("?");
            let model = judge.get("model").and_then(|s| s.as_str()).unwrap_or("?");
            let endpoint = judge
                .get("endpoint")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            let rationale = judge
                .get("rationale")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            let called_at = judge
                .get("called_at")
                .and_then(|s| s.as_str())
                .unwrap_or("?");
            out.push_str(&format!(
                "judge (model-derived, NOT independent evidence): {} {}\n  \
                 model: {}  endpoint: {}  called_at: {}\n  rationale: {}\n",
                judge_verdict_icon(verdict),
                verdict.to_uppercase(),
                model,
                endpoint,
                called_at,
                rationale
            ));
            if let Some(true) = judge.get("disagreement").and_then(|d| d.as_bool()) {
                out.push_str(
                    "  ⚠ disagreement: the judge's verdict differs from the deterministic \
                     evidence for this claim -- shown, not resolved\n",
                );
            }
            out.push('\n');
        }
    }
    out.push_str(&render_fusion(v));
    out
}

/// Extract the context-key dimensions a reader needs to judge whether a
/// historical prior is applicable to their current claim (FORNX-105 AC:
/// "user can inspect the cohort/context behind a reliability signal") —
/// provider, model family/version, adapter version, task class, toolset,
/// repository class, and the policy/verifier/fusion versions the cohort was
/// recorded under. Returns `None` if any required dimension is missing or
/// malformed.
///
/// This is the **structural AC1 guard**: [`render_reliability_signal`] calls
/// this *before* it ever reads `reliability_estimate`, and returns early
/// on `None` without looking at the estimate at all — there is no code path
/// in this renderer that can print a percentage without this context string
/// having been produced first, in the same output.
fn extract_context_dimensions(context_key: &serde_json::Value) -> Option<String> {
    let provider = context_key.get("provider")?.as_str()?;
    let model_family = context_key.get("model_family")?.as_str()?;
    let model_version = context_key.get("model_version")?.as_str()?;
    let adapter_version = context_key.get("adapter_version")?.as_str()?;
    let task_class = context_key.get("task_class")?.as_str()?;
    let repository_class = context_key.get("repository_class")?.as_str()?;
    let toolset: Vec<&str> = context_key
        .get("toolset")?
        .as_array()?
        .iter()
        .filter_map(|t| t.as_str())
        .collect();
    let policy_version = context_key.get("policy_version")?.as_str()?;
    let verifier_version = context_key.get("verifier_version")?.as_str()?;
    let fusion_version = context_key.get("fusion_version")?.as_str()?;
    Some(format!(
        "  context: provider={provider} model_family={model_family} model_version={model_version} \
         adapter_version={adapter_version} task_class={task_class} toolset=[{}] \
         repository_class={repository_class} policy_version={policy_version} \
         verifier_version={verifier_version} fusion_version={fusion_version}\n",
        toolset.join(",")
    ))
}

/// Renders a serialized `SampleSupport` (FORNX-103), distinguishing
/// `Confident` from `InsufficientSupport` explicitly (FORNX-105 AC: sparse
/// data is clearly labeled uncertain, never a bare/misleading number).
fn render_sample_support(support: &serde_json::Value) -> String {
    if let Some(confident) = support.get("confident") {
        let n = confident
            .get("sample_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        format!("  sample support: confident ({n} observations)\n")
    } else if let Some(insufficient) = support.get("insufficient_support") {
        let n = insufficient
            .get("sample_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let needed = insufficient
            .get("minimum_required")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        format!("  sample support: insufficient data -- {n} of {needed} needed\n")
    } else {
        "  sample support: unknown\n".to_string()
    }
}

/// Renders a serialized `ReliabilityEstimate` (FORNX-104): the point
/// estimate plus its Wilson-score confidence interval. Only ever called from
/// [`render_reliability_signal`] after the full context has already been
/// printed into the same output — see that function's doc comment.
fn render_reliability_estimate(estimate: &serde_json::Value) -> String {
    let rate = estimate
        .get("success_rate")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let ci = estimate.get("confidence_interval");
    let lower = ci
        .and_then(|c| c.get("lower"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let upper = ci
        .and_then(|c| c.get("upper"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let level = ci
        .and_then(|c| c.get("confidence_level"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    format!(
        "  reliability estimate: {:.1}% (CI [{:.1}%, {:.1}%] @ {:.0}% confidence)\n",
        rate * 100.0,
        lower * 100.0,
        upper * 100.0,
        level * 100.0
    )
}

/// Renders one serialized `ReliabilitySignal` (FORNX-104): full context,
/// sample support, and — only when both the context prints successfully AND
/// the cohort is `Confident` AND the signal is not superseded by drift — the
/// reliability estimate.
///
/// **This is the function AC1 ("no UI presents a context-free provider/model
/// trust percentage") is a structural property of, not just a documented
/// promise of**: `reliability_estimate` is read from `signal` only after
/// [`extract_context_dimensions`] has already produced (and pushed into
/// `out`) the context string — on `None` this returns immediately, before
/// ever touching `reliability_estimate`. There is no reachable path that
/// prints an estimate without the context dimensions already present in the
/// same returned string.
///
/// `superseded_by_drift`, when `true` (FORNX-105 AC: "drift ... does not
/// silently reuse stale confidence"), replaces the estimate line with an
/// explicit stale/superseded marker instead of the numeric estimate — used
/// by [`render_drift_assessment`] on the baseline side of a `Drifted`
/// comparison.
fn render_reliability_signal(
    label: &str,
    signal: &serde_json::Value,
    superseded_by_drift: bool,
) -> String {
    let mut out = String::new();
    let Some(context_block) = signal
        .get("context_key")
        .and_then(extract_context_dimensions)
    else {
        out.push_str(&format!(
            "{label}context key incomplete -- no reliability estimate can be shown\n"
        ));
        return out;
    };
    out.push_str(&context_block);
    if let Some(support) = signal.get("sample_support") {
        out.push_str(&render_sample_support(support));
    }
    if let Some(not_evaluable) = signal.get("not_evaluable_count").and_then(|v| v.as_u64()) {
        if not_evaluable > 0 {
            out.push_str(&format!("  not evaluable: {not_evaluable}\n"));
        }
    }
    if superseded_by_drift {
        out.push_str("  ⚠ stale -- superseded by drift, not shown as current confidence\n");
    } else if let Some(estimate) = signal.get("reliability_estimate") {
        out.push_str(&render_reliability_estimate(estimate));
    }
    out
}

/// Renders a serialized `DriftState` (FORNX-104), covering all four states
/// distinctly plus a forward-compat fallback — mirroring
/// `verdict_icon`/`availability_icon`/`relation_icon`/`rule_effect_icon`'s
/// never-collapse-the-taxonomy convention. `NotComparable` names every
/// differing dimension explicitly (FORNX-105 AC: "explain why a historical
/// prior is or is not applicable").
fn drift_state_label(state: &serde_json::Value) -> String {
    if let Some(s) = state.as_str() {
        return match s {
            "stable" => "✓ stable -- no meaningful reliability change detected".to_string(),
            "drifted" => "⚠ drift detected -- reliability changed between versions".to_string(),
            "insufficient_data_for_comparison" => {
                "? insufficient data for comparison -- at least one side lacks sample support"
                    .to_string()
            }
            other => format!("◌ {other}"),
        };
    }
    if let Some(not_comparable) = state.get("not_comparable") {
        let dims: Vec<&str> = not_comparable
            .get("differing_dimensions")
            .and_then(|d| d.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        return format!(
            "✕ not comparable -- this historical prior does not apply: differs in {}",
            dims.join(", ")
        );
    }
    "◌ unrecognized drift state".to_string()
}

/// Renders `GET /api/reliability`'s response (FORNX-105): a context-scoped
/// reliability signal, or a drift assessment when a comparison version was
/// requested. Distinguishes three structurally different "no number shown"
/// outcomes, never conflating them: aggregation forbidden by local policy
/// (AC5), no capabilities announced for the session (a context key cannot be
/// built), and an error. Returns the rendered text so it can be asserted on
/// in tests, matching this file's other `render_*` functions.
fn render_reliability(v: &serde_json::Value) -> String {
    let mut out = String::new();
    let session = v.get("session").and_then(|s| s.as_str()).unwrap_or("?");
    out.push_str(&format!("session: {session}\n"));

    if let Some(false) = v.get("available").and_then(|b| b.as_bool()) {
        let reason = v
            .get("reason")
            .and_then(|s| s.as_str())
            .unwrap_or("historical reliability aggregation is disabled by local policy");
        out.push_str(&format!(
            "  reliability aggregation unavailable: {reason}\n"
        ));
        return out;
    }

    if let Some(error) = v.get("error").and_then(|s| s.as_str()) {
        out.push_str(&format!("  error: {error}\n"));
        return out;
    }

    if let Some(false) = v.get("capabilities_announced").and_then(|b| b.as_bool()) {
        let reason = v
            .get("reason")
            .and_then(|s| s.as_str())
            .unwrap_or("no capabilities announced yet for this session");
        out.push_str(&format!("  {reason}\n"));
        return out;
    }

    if let Some(signal) = v.get("signal") {
        out.push_str(&render_reliability_signal("  ", signal, false));
        return out;
    }

    if let Some(assessment) = v.get("drift_assessment") {
        let state = assessment
            .get("drift_state")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        out.push_str(&format!("  drift: {}\n", drift_state_label(&state)));
        let is_drifted = state.as_str() == Some("drifted");

        if let Some(baseline) = assessment.get("baseline_signal") {
            out.push_str("  baseline:\n");
            out.push_str(&render_reliability_signal("    ", baseline, is_drifted));
        }
        if let Some(comparison) = assessment.get("comparison_signal") {
            out.push_str("  comparison:\n");
            out.push_str(&render_reliability_signal("    ", comparison, false));
        }
        return out;
    }

    out.push_str("  no reliability data returned\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_status_line_shows_no_findings_message_when_null() {
        let v = serde_json::json!({"latest": null});
        assert_eq!(render_status_line(&v), "🛡 fornax: no findings yet");
    }

    #[test]
    fn render_status_line_shows_contradicted_icon_and_verdict() {
        let v = serde_json::json!({"latest": {"verdict": "contradicted"}});
        assert_eq!(render_status_line(&v), "🛡 ✕ CONTRADICTED");
    }

    #[test]
    fn render_status_line_shows_verified_icon() {
        let v = serde_json::json!({"latest": {"verdict": "verified"}});
        assert_eq!(render_status_line(&v), "🛡 ✓ VERIFIED");
    }

    #[test]
    fn verdict_icon_covers_all_five_states_never_collapsing() {
        assert_eq!(verdict_icon("verified"), "🛡 ✓");
        assert_eq!(verdict_icon("unverified"), "🛡 ?");
        assert_eq!(verdict_icon("contradicted"), "🛡 ✕");
        assert_eq!(verdict_icon("review"), "🛡 !");
        assert_eq!(verdict_icon("unavailable"), "🛡 —");
    }

    #[test]
    fn availability_icon_covers_every_state_distinctly() {
        assert_eq!(availability_icon("available"), "✓");
        assert_eq!(availability_icon("unsupported"), "⛔");
        assert_eq!(availability_icon("unavailable"), "—");
        assert_eq!(availability_icon("redacted"), "▮");
        assert_eq!(availability_icon("collection_failed"), "✕");
        assert_eq!(availability_icon("unknown"), "?");
        // Forward-compat: an unrecognized tag must not collapse onto an
        // existing state's icon.
        assert_eq!(availability_icon("quantum_pending"), "◌");
    }

    #[test]
    fn render_capabilities_reports_not_announced_when_absent() {
        let v = serde_json::json!({
            "session": "s1",
            "announced": false,
            "reason": "no capabilities announced yet by any adapter for this session",
            "capabilities": [],
        });
        let rendered = render_capabilities(&v);
        assert!(rendered.contains("session: s1"));
        assert!(rendered.contains("no capabilities announced yet"));
    }

    /// FORNX-85: the rendering must never collapse the six-state
    /// availability taxonomy — each declared signal class's real state must
    /// appear distinctly in the output, including its `detail` when present.
    #[test]
    fn render_capabilities_shows_each_signal_class_state_distinctly() {
        let v = serde_json::json!({
            "session": "s2",
            "announced": true,
            "capabilities": [{
                "provider": "claude_code",
                "schema_version": 1,
                "signals": [
                    {"class": "tool_invocation", "state": "available"},
                    {"class": "process_result", "state": "unsupported"},
                    {"class": "raw_reasoning", "state": "redacted", "detail": "withheld by privacy boundary"},
                ],
                "notes": {},
            }],
        });
        let rendered = render_capabilities(&v);
        assert!(rendered.contains("tool_invocation: available"));
        assert!(rendered.contains("process_result: unsupported"));
        assert!(rendered.contains("raw_reasoning: redacted (withheld by privacy boundary)"));
        // The verdict-vocabulary states and the capability-availability
        // states must never bleed into each other's rendering.
        assert!(!rendered.contains("VERIFIED"));
        assert!(!rendered.contains("CONTRADICTED"));
    }

    #[test]
    fn relation_icon_covers_all_three_states_never_collapsing() {
        assert_eq!(relation_icon("supports"), "✚");
        assert_eq!(relation_icon("contradicts"), "✕");
        assert_eq!(relation_icon("neutral"), "•");
        // Forward-compat: an unrecognized tag must not collapse onto an
        // existing relation's icon.
        assert_eq!(relation_icon("quantum_pending"), "◌");
    }

    #[test]
    fn render_evidence_graph_reports_not_found_for_unknown_claim() {
        let v = serde_json::json!({
            "claim": "c1",
            "session": "s1",
            "found": false,
            "reason": "no claim with this id is on record for this session",
        });
        let rendered = render_evidence_graph(&v);
        assert!(rendered.contains("claim: c1"));
        assert!(rendered.contains("no such claim on record"));
    }

    /// FORNX-90: the core product invariant — a claim with genuinely zero
    /// links and zero missing notes ("nobody has looked") must render a
    /// distinct message from a claim with zero links but one or more
    /// missing notes ("looked, evidence could not be collected"), and both
    /// must be distinct from the "claim not found" case above.
    #[test]
    fn render_evidence_graph_distinguishes_nobody_looked_from_looked_but_absent() {
        let nobody_looked = serde_json::json!({
            "claim": "c1", "session": "s1", "found": true, "links": [], "missing": [],
        });
        let rendered = render_evidence_graph(&nobody_looked);
        assert!(rendered.contains("no evidence linked and no missing-evidence notes recorded"));

        let looked_but_absent = serde_json::json!({
            "claim": "c1", "session": "s1", "found": true, "links": [],
            "missing": [{
                "signal_class": "process_result",
                "availability": "unavailable",
                "detail": "no exit code sensor ran for this claim",
            }],
        });
        let rendered2 = render_evidence_graph(&looked_but_absent);
        assert!(rendered2.contains("no evidence linked to this claim"));
        assert!(rendered2
            .contains("process_result: unavailable (no exit code sensor ran for this claim)"));
        assert_ne!(rendered, rendered2);
    }

    /// FORNX-90: linked evidence must be grouped by relation and each item
    /// shown individually — never collapsed into a single count/score.
    #[test]
    fn render_evidence_graph_groups_links_by_relation_and_shows_each_item() {
        let v = serde_json::json!({
            "claim": "c1", "session": "s1", "found": true,
            "links": [
                {"evidence_id": "e1", "relation": "supports", "linked_at": "2026-09-01T00:00:00Z"},
                {"evidence_id": "e2", "relation": "supports", "linked_at": "2026-09-01T00:00:01Z"},
                {"evidence_id": "e3", "relation": "contradicts", "linked_at": "2026-09-01T00:00:02Z"},
            ],
            "missing": [],
        });
        let rendered = render_evidence_graph(&v);
        assert!(rendered.contains("✚ supports (2)"));
        assert!(rendered.contains("✕ contradicts (1)"));
        assert!(rendered.contains("evidence: e1"));
        assert!(rendered.contains("evidence: e2"));
        assert!(rendered.contains("evidence: e3"));
        assert!(!rendered.contains("no evidence linked"));
    }

    /// FORNX-90 regression: a link with an unrecognized relation tag must
    /// still be shown, never silently dropped — "show each item" applies
    /// even to a state this renderer doesn't yet name.
    #[test]
    fn render_evidence_graph_never_drops_a_link_with_an_unrecognized_relation() {
        let v = serde_json::json!({
            "claim": "c1", "session": "s1", "found": true,
            "links": [
                {"evidence_id": "e1", "relation": "quantum_pending", "linked_at": "2026-09-01T00:00:00Z"},
            ],
            "missing": [],
        });
        let rendered = render_evidence_graph(&v);
        assert!(rendered.contains("evidence: e1"));
        assert!(rendered.contains("quantum_pending (1)"));
    }

    /// FORNX-92 AC: "Conflicts remain inspectable in Evidence Explorer" —
    /// a claim with both a supports and a contradicts link must render a
    /// distinct conflict banner, without resolving which side is right.
    #[test]
    fn render_evidence_graph_surfaces_a_conflict_banner_for_opposing_links() {
        let v = serde_json::json!({
            "claim": "c1", "session": "s1", "found": true,
            "links": [
                {"evidence_id": "e1", "relation": "supports", "linked_at": "2026-09-01T00:00:00Z"},
                {"evidence_id": "e2", "relation": "contradicts", "linked_at": "2026-09-01T00:00:01Z"},
            ],
            "missing": [],
        });
        let rendered = render_evidence_graph(&v);
        assert!(rendered.contains("⚠ conflict: 1 supports vs 1 contradicts (unresolved)"));
    }

    /// No conflict banner when links agree.
    #[test]
    fn render_evidence_graph_shows_no_conflict_banner_when_links_agree() {
        let v = serde_json::json!({
            "claim": "c1", "session": "s1", "found": true,
            "links": [
                {"evidence_id": "e1", "relation": "supports", "linked_at": "2026-09-01T00:00:00Z"},
            ],
            "missing": [],
        });
        let rendered = render_evidence_graph(&v);
        assert!(!rendered.contains("conflict"));
    }

    /// FORNX-90 regression: a daemon-side error must render as its own
    /// distinct outcome, never defaulted into "claim not found" — "we don't
    /// know" must stay distinguishable from "we looked and it's absent".
    #[test]
    fn render_evidence_graph_shows_daemon_error_distinctly_from_not_found() {
        let v = serde_json::json!({
            "claim": "c1", "session": "s1", "error": "store unavailable",
        });
        let rendered = render_evidence_graph(&v);
        assert!(rendered.contains("error: store unavailable"));
        assert!(!rendered.contains("no such claim on record"));
    }

    // FORNX-15: install-claude / uninstall-claude must idempotently
    // add/remove the documented Fornax hook entries in a
    // `~/.claude/settings.json`-shaped fixture without disturbing anything
    // else already in the file.
    mod claude_hooks_install_uninstall {
        use super::*;
        use uuid::Uuid;

        fn tmp_settings_path(name: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!(
                "fornax-cli-test-settings-{name}-{}.json",
                Uuid::new_v4()
            ))
        }

        fn fornax_group_count(settings: &serde_json::Value, event: &str) -> usize {
            settings["hooks"][event]
                .as_array()
                .map(|entries| {
                    entries
                        .iter()
                        .filter(|g| group_has_fornax_command(g))
                        .count()
                })
                .unwrap_or(0)
        }

        #[test]
        fn install_adds_all_documented_hooks_to_fresh_file() {
            let path = tmp_settings_path("fresh-install");
            // No file exists yet — install must create it from scratch.

            install_claude_at(&path).expect("install");

            let settings: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            for event in CLAUDE_HOOK_EVENTS {
                assert_eq!(
                    fornax_group_count(&settings, event),
                    1,
                    "expected exactly one fornax hook group for {event}"
                );
            }

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn install_is_idempotent_no_duplicate_entries() {
            let path = tmp_settings_path("idempotent-install");

            install_claude_at(&path).expect("first install");
            install_claude_at(&path).expect("second install");

            let settings: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            for event in CLAUDE_HOOK_EVENTS {
                assert_eq!(
                    fornax_group_count(&settings, event),
                    1,
                    "expected no duplicate fornax hook group for {event} after second install"
                );
            }

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn install_preserves_unrelated_settings_and_hooks() {
            let path = tmp_settings_path("preserve-unrelated");
            let existing = serde_json::json!({
                "model": "opus",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{ "type": "command", "command": "some-other-tool" }]
                        }
                    ],
                    "Notification": [
                        { "hooks": [{ "type": "command", "command": "notify-tool" }] }
                    ]
                }
            });
            std::fs::write(&path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

            install_claude_at(&path).expect("install");

            let settings: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(settings["model"], "opus");
            // The unrelated PreToolUse group survives alongside the new one.
            let pre_tool_use = settings["hooks"]["PreToolUse"].as_array().unwrap();
            assert_eq!(pre_tool_use.len(), 2);
            assert!(pre_tool_use
                .iter()
                .any(|g| g["hooks"][0]["command"] == "some-other-tool"));
            assert_eq!(fornax_group_count(&settings, "PreToolUse"), 1);
            // The unrelated Notification event is untouched entirely.
            assert_eq!(
                settings["hooks"]["Notification"][0]["hooks"][0]["command"],
                "notify-tool"
            );

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn uninstall_removes_fornax_hooks_and_leaves_everything_else() {
            let path = tmp_settings_path("uninstall-clean");
            let existing = serde_json::json!({
                "model": "opus",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{ "type": "command", "command": "some-other-tool" }]
                        }
                    ]
                }
            });
            std::fs::write(&path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

            install_claude_at(&path).expect("install");
            uninstall_claude_at(&path).expect("uninstall");

            let settings: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(settings["model"], "opus");
            for event in CLAUDE_HOOK_EVENTS {
                assert_eq!(
                    fornax_group_count(&settings, event),
                    0,
                    "expected no fornax hook group left for {event}"
                );
            }
            // The pre-existing, unrelated PreToolUse group must survive.
            let pre_tool_use = settings["hooks"]["PreToolUse"].as_array().unwrap();
            assert_eq!(pre_tool_use.len(), 1);
            assert_eq!(pre_tool_use[0]["hooks"][0]["command"], "some-other-tool");

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn uninstall_on_never_installed_file_is_a_safe_no_op() {
            let path = tmp_settings_path("uninstall-noop");
            let existing = serde_json::json!({ "model": "opus" });
            std::fs::write(&path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

            uninstall_claude_at(&path).expect("uninstall on file without fornax hooks");

            let settings: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(settings, serde_json::json!({ "model": "opus" }));

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn uninstall_on_missing_file_is_a_safe_no_op_and_creates_nothing() {
            let path = tmp_settings_path("uninstall-missing-file");
            // No file exists.

            uninstall_claude_at(&path).expect("uninstall on missing file");

            assert!(
                !path.exists(),
                "uninstall must not create a settings.json the user never had"
            );
        }
    }

    // FORNX-16: install-codex / uninstall-codex must idempotently
    // add/remove the Fornax `notify` entry in a `~/.codex/config.toml`-
    // shaped fixture without disturbing anything else already in the
    // file — including comments and unrelated tables, which the JSON-based
    // Claude equivalent doesn't need to worry about but format-preserving
    // TOML editing does.
    mod codex_notify_install_uninstall {
        use super::*;
        use uuid::Uuid;

        fn tmp_config_path(name: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!(
                "fornax-cli-test-codex-config-{name}-{}.toml",
                Uuid::new_v4()
            ))
        }

        fn script_path() -> std::path::PathBuf {
            std::path::PathBuf::from("/opt/fornax/scripts/fornax-codex-notify.sh")
        }

        #[test]
        fn install_adds_notify_to_fresh_file() {
            let path = tmp_config_path("fresh-install");
            // No file exists yet — install must create it from scratch.

            install_codex_notify_at(&path, &script_path()).expect("install");

            let contents = std::fs::read_to_string(&path).unwrap();
            let doc: toml_edit::DocumentMut = contents.parse().unwrap();
            assert_eq!(
                doc["notify"][0].as_str().unwrap(),
                script_path().to_string_lossy()
            );

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn install_is_idempotent_no_duplicate_or_error() {
            let path = tmp_config_path("idempotent-install");

            install_codex_notify_at(&path, &script_path()).expect("first install");
            install_codex_notify_at(&path, &script_path()).expect("second install");

            let contents = std::fs::read_to_string(&path).unwrap();
            let doc: toml_edit::DocumentMut = contents.parse().unwrap();
            let notify = doc["notify"].as_array().unwrap();
            assert_eq!(notify.len(), 1);

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn install_preserves_comments_and_unrelated_tables() {
            let path = tmp_config_path("preserve-unrelated");
            let existing = "\
# a user comment that must survive\n\
model = \"gpt-5.6-luna\"\n\
\n\
[projects.\"/tmp/some-project\"]\n\
trust_level = \"trusted\"\n";
            std::fs::write(&path, existing).unwrap();

            install_codex_notify_at(&path, &script_path()).expect("install");

            let contents = std::fs::read_to_string(&path).unwrap();
            assert!(
                contents.contains("# a user comment that must survive"),
                "comment must survive format-preserving edit, got:\n{contents}"
            );
            let doc: toml_edit::DocumentMut = contents.parse().unwrap();
            assert_eq!(doc["model"].as_str().unwrap(), "gpt-5.6-luna");
            assert_eq!(
                doc["projects"]["/tmp/some-project"]["trust_level"]
                    .as_str()
                    .unwrap(),
                "trusted"
            );
            assert_eq!(
                doc["notify"][0].as_str().unwrap(),
                script_path().to_string_lossy()
            );

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn install_refuses_to_overwrite_foreign_notify() {
            let path = tmp_config_path("foreign-notify");
            let existing = "notify = [\"/usr/local/bin/some-other-notifier\", \"extra-arg\"]\n";
            std::fs::write(&path, existing).unwrap();
            let before = std::fs::read_to_string(&path).unwrap();

            let err = install_codex_notify_at(&path, &script_path())
                .expect_err("must refuse to overwrite a foreign notify command");
            assert!(err.to_string().contains("some-other-notifier"));

            let after = std::fs::read_to_string(&path).unwrap();
            assert_eq!(
                before, after,
                "file must be byte-for-byte unchanged on refusal"
            );

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn uninstall_does_not_remove_lookalike_foreign_notify() {
            // Review finding: notify_is_fornax used to compare with a bare
            // `ends_with` on the whole path string, so a foreign script whose
            // path merely *ends with* the marker (but has a different
            // basename) would be misidentified as Fornax-owned and deleted.
            let path = tmp_config_path("lookalike-foreign-notify-uninstall");
            let existing = "notify = [\"/opt/my-fornax-codex-notify.sh\"]\n";
            std::fs::write(&path, existing).unwrap();

            uninstall_codex_notify_at(&path).expect("uninstall must not error");

            let after = std::fs::read_to_string(&path).unwrap();
            assert_eq!(
                existing, after,
                "a lookalike foreign notify entry must survive uninstall untouched"
            );

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn uninstall_removes_notify_and_leaves_everything_else() {
            let path = tmp_config_path("uninstall-clean");
            let existing = "\
model = \"gpt-5.6-luna\"\n\
\n\
[projects.\"/tmp/some-project\"]\n\
trust_level = \"trusted\"\n";
            std::fs::write(&path, existing).unwrap();

            install_codex_notify_at(&path, &script_path()).expect("install");
            uninstall_codex_notify_at(&path).expect("uninstall");

            let contents = std::fs::read_to_string(&path).unwrap();
            let doc: toml_edit::DocumentMut = contents.parse().unwrap();
            assert!(doc.get("notify").is_none());
            assert_eq!(doc["model"].as_str().unwrap(), "gpt-5.6-luna");
            assert_eq!(
                doc["projects"]["/tmp/some-project"]["trust_level"]
                    .as_str()
                    .unwrap(),
                "trusted"
            );

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn uninstall_never_touches_a_foreign_notify() {
            let path = tmp_config_path("uninstall-foreign");
            let existing = "notify = [\"/usr/local/bin/some-other-notifier\"]\n";
            std::fs::write(&path, existing).unwrap();

            uninstall_codex_notify_at(&path).expect("uninstall");

            let contents = std::fs::read_to_string(&path).unwrap();
            assert_eq!(contents, existing);

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn uninstall_on_never_installed_file_is_a_safe_no_op() {
            let path = tmp_config_path("uninstall-noop");
            let existing = "model = \"gpt-5.6-luna\"\n";
            std::fs::write(&path, existing).unwrap();

            uninstall_codex_notify_at(&path).expect("uninstall on file without fornax notify");

            let contents = std::fs::read_to_string(&path).unwrap();
            assert_eq!(contents, existing);

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn uninstall_on_missing_file_is_a_safe_no_op_and_creates_nothing() {
            let path = tmp_config_path("uninstall-missing-file");
            // No file exists.

            uninstall_codex_notify_at(&path).expect("uninstall on missing file");

            assert!(
                !path.exists(),
                "uninstall must not create a config.toml the user never had"
            );
        }

        /// FORNX-244 coverage-gap closure: install -> uninstall -> install
        /// round-trip must leave exactly one `notify` entry, not accumulate
        /// duplicates and not fail on the second install after an uninstall.
        #[test]
        fn install_uninstall_install_round_trip_leaves_exactly_one_entry() {
            let path = tmp_config_path("round-trip");

            install_codex_notify_at(&path, &script_path()).expect("first install");
            uninstall_codex_notify_at(&path).expect("uninstall");
            install_codex_notify_at(&path, &script_path()).expect("second install after uninstall");

            let contents = std::fs::read_to_string(&path).unwrap();
            let doc: toml_edit::DocumentMut = contents.parse().unwrap();
            let notify = doc["notify"].as_array().unwrap();
            assert_eq!(notify.len(), 1);
            assert_eq!(
                notify.get(0).unwrap().as_str().unwrap(),
                script_path().to_string_lossy()
            );

            std::fs::remove_file(&path).ok();
        }

        /// FORNX-244 coverage-gap closure: uninstalling twice in a row must
        /// be a safe no-op the second time (idempotent unwiring), mirroring
        /// `install_is_idempotent_no_duplicate_or_error` for the install side.
        #[test]
        fn uninstall_is_idempotent_second_call_is_a_safe_no_op() {
            let path = tmp_config_path("idempotent-uninstall");

            install_codex_notify_at(&path, &script_path()).expect("install");
            uninstall_codex_notify_at(&path).expect("first uninstall");
            let after_first = std::fs::read_to_string(&path).unwrap();

            uninstall_codex_notify_at(&path).expect("second uninstall must not error");
            let after_second = std::fs::read_to_string(&path).unwrap();

            assert_eq!(
                after_first, after_second,
                "second uninstall must be a byte-for-byte no-op"
            );
            let doc: toml_edit::DocumentMut = after_second.parse().unwrap();
            assert!(doc.get("notify").is_none());

            std::fs::remove_file(&path).ok();
        }

        #[cfg(unix)]
        #[test]
        fn install_preserves_existing_file_permissions() {
            use std::os::unix::fs::PermissionsExt;

            let path = tmp_config_path("preserve-perms");
            std::fs::write(&path, "model = \"gpt-5.6-luna\"\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

            install_codex_notify_at(&path, &script_path()).expect("install");

            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "install must not widen an existing file's permissions"
            );

            std::fs::remove_file(&path).ok();
        }
    }

    // FORNX-62: export-spool must emit a `capabilities` envelope for a
    // session that received a real Capabilities message, using the FORNX-53
    // aha-scenario fixture pattern (`caps()`/claim-with-exit-code style)
    // already established in fornax-verify's test suite.
    mod export_spool_capabilities {
        use super::*;
        use fornax_types::{
            CapabilitySignal, EventKind, EvidenceKind, Provider, RuntimeCapabilities,
            SignalAvailability, SignalClass,
        };
        use uuid::Uuid;

        fn tmp_db_path(name: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!("fornax-cli-test-{name}-{}.db", Uuid::new_v4()))
        }

        fn aha_scenario_capabilities() -> RuntimeCapabilities {
            RuntimeCapabilities {
                schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
                provider: Provider::Codex,
                signals: vec![
                    CapabilitySignal {
                        class: SignalClass::ToolInvocation,
                        state: SignalAvailability::Available,
                        detail: None,
                    },
                    CapabilitySignal {
                        class: SignalClass::ToolTrace,
                        state: SignalAvailability::Available,
                        detail: None,
                    },
                    CapabilitySignal {
                        class: SignalClass::ToolResultPayload,
                        state: SignalAvailability::Available,
                        detail: None,
                    },
                    CapabilitySignal {
                        class: SignalClass::SessionLifecycle,
                        state: SignalAvailability::Available,
                        detail: None,
                    },
                    CapabilitySignal {
                        class: SignalClass::FinalResponse,
                        state: SignalAvailability::Available,
                        detail: None,
                    },
                    CapabilitySignal {
                        class: SignalClass::SubagentLifecycle,
                        state: SignalAvailability::Unsupported,
                        detail: None,
                    },
                ],
                notes: [("session_id".to_string(), "s-aha".to_string())].into(),
            }
        }

        async fn seeded_store(path: &std::path::Path) -> fornax_store::Store {
            let store = fornax_store::Store::open(path).await.expect("open db");

            let event = fornax_types::AgentEvent {
                id: Uuid::new_v4(),
                session_id: "s-aha".into(),
                provider: Provider::Codex,
                kind: EventKind::PostToolUse,
                observed_at: "2026-01-01T00:00:00Z".into(),
                tool_name: Some("exec_command".into()),
                tool_input: Some(serde_json::json!(["pytest"])),
                tool_response: Some(serde_json::json!({"exit_code": 1})),
                raw: serde_json::json!({"type": "exec_command_end"}),
            };
            store.insert_event(&event).await.expect("insert event");

            let evidence = fornax_types::Evidence {
                id: Uuid::new_v4(),
                session_id: "s-aha".into(),
                source_event_id: event.id,
                kind: EvidenceKind::ExitCode,
                observed_at: "2026-01-01T00:00:01Z".into(),
                payload: serde_json::json!({"command": ["pytest"], "exit_code": 1}),
                provenance: "codex:rollout:exec_command_end".into(),
                source: None,
                extension: None,
            };
            store
                .insert_evidence(&evidence)
                .await
                .expect("insert evidence");

            let claim = fornax_types::Claim {
                id: Uuid::new_v4(),
                session_id: "s-aha".into(),
                source_event_id: event.id,
                text: "All tests passed.".into(),
                subject: "test_result".into(),
                claimed_at: "2026-01-01T00:00:02Z".into(),
            };
            store.insert_claim(&claim).await.expect("insert claim");

            store
        }

        fn read_pending_types(pending_dir: &std::path::Path) -> Vec<String> {
            std::fs::read_dir(pending_dir)
                .expect("read pending dir")
                .map(|e| e.expect("dir entry"))
                .map(|e| std::fs::read_to_string(e.path()).expect("read envelope file"))
                .map(|contents| {
                    let v: serde_json::Value =
                        serde_json::from_str(&contents).expect("envelope is valid json");
                    v["type"].as_str().expect("type field present").to_string()
                })
                .collect()
        }

        #[tokio::test]
        async fn emits_capabilities_envelope_when_announced() {
            let db_path = tmp_db_path("with-caps");
            let store = seeded_store(&db_path).await;
            store
                .upsert_capabilities("s-aha", &aha_scenario_capabilities())
                .await
                .expect("upsert capabilities");

            let out_dir = std::env::temp_dir().join(format!("fornax-spool-{}", Uuid::new_v4()));
            export_spool_from_store(&store, "s-aha", &out_dir)
                .await
                .expect("export spool");

            let pending_dir = out_dir.join("pending");
            let types = read_pending_types(&pending_dir);
            assert_eq!(
                types.iter().filter(|t| *t == "capabilities").count(),
                1,
                "expected exactly one capabilities envelope, got: {types:?}"
            );
            assert!(types.contains(&"event".to_string()));
            assert!(types.contains(&"claim".to_string()));
            assert!(types.contains(&"evidence".to_string()));

            // The emitted capabilities file must remain wire-compatible
            // with fornax-cloud's original fornax-uploader::types::
            // RuntimeCapabilities nine-key shape (FORNX-301 adds
            // session_id/schema_version/signals additively on top — see
            // `LegacyCapabilitiesWire`'s doc comment).
            let caps_file = std::fs::read_dir(&pending_dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    let v: serde_json::Value =
                        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
                    v["type"] == "capabilities"
                })
                .expect("capabilities file exists");
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&caps_file).unwrap()).unwrap();
            let keys: std::collections::HashSet<&str> =
                v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
            let frozen = [
                "notes",
                "provider",
                "supports_post_tool_use",
                "supports_pre_tool_use",
                "supports_session_stop_event",
                "supports_subagent_lifecycle",
                "supports_tool_response_capture",
                "supports_transcript_tail",
                "type",
            ];
            for key in frozen {
                assert!(keys.contains(key), "frozen legacy key {key} missing");
            }
            // FORNX-301: session_id is set by export_spool_from_store from
            // its `session` parameter, schema_version/signals come through
            // `From<&RuntimeCapabilities>`.
            assert_eq!(v["session_id"], "s-aha");
            assert_eq!(v["schema_version"], fornax_types::CAPABILITY_SCHEMA_VERSION);
            assert_eq!(v["signals"].as_array().unwrap().len(), 6);

            std::fs::remove_file(&db_path).ok();
            std::fs::remove_dir_all(&out_dir).ok();
        }

        /// FORNX-301: proves the byte-identical backward-compat guarantee
        /// end-to-end through the real export path — a capabilities
        /// announcement using only the legacy six bools (no rich `signals`)
        /// still exports to exactly the original nine legacy keys, with no
        /// `session_id`/`schema_version`/`signals` keys appearing, once
        /// `notes` doesn't carry a session id of its own either. This is the
        /// export-path counterpart to `fornax_types::capabilities`'s
        /// `empty_signals_and_absent_session_id_serialize_to_exactly_the_original_nine_keys`
        /// unit test — but `export_spool_from_store` always stamps
        /// `session_id` from its `session` parameter, so this test instead
        /// confirms the new keys are present and additive, not exact-set.
        #[tokio::test]
        async fn full_signal_capabilities_export_round_trips_every_field() {
            let db_path = tmp_db_path("full-signals");
            let store = seeded_store(&db_path).await;
            let caps = RuntimeCapabilities {
                schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
                provider: Provider::Codex,
                signals: vec![
                    CapabilitySignal {
                        class: SignalClass::ToolInvocation,
                        state: SignalAvailability::Unsupported,
                        detail: Some("rollout tail cannot intercept pre-execution".to_string()),
                    },
                    CapabilitySignal {
                        class: SignalClass::ToolTrace,
                        state: SignalAvailability::Available,
                        detail: None,
                    },
                    CapabilitySignal {
                        class: SignalClass::ProcessResult,
                        state: SignalAvailability::CollectionFailed,
                        detail: Some("no literal exit code in tool_response".to_string()),
                    },
                    CapabilitySignal {
                        class: SignalClass::ReasoningSummary,
                        state: SignalAvailability::Redacted,
                        detail: None,
                    },
                    CapabilitySignal {
                        class: SignalClass::InternalModelSignals,
                        state: SignalAvailability::Unknown,
                        detail: None,
                    },
                    CapabilitySignal {
                        class: SignalClass::Unrecognized("neural_trace".to_string()),
                        state: SignalAvailability::Unrecognized("quantum_entangled".to_string()),
                        detail: None,
                    },
                ],
                notes: [("session_id".to_string(), "s-1".to_string())].into(),
            };
            store
                .upsert_capabilities("s-1", &caps)
                .await
                .expect("upsert capabilities");

            let out_dir = std::env::temp_dir().join(format!("fornax-spool-{}", Uuid::new_v4()));
            export_spool_from_store(&store, "s-1", &out_dir)
                .await
                .expect("export spool");

            let pending_dir = out_dir.join("pending");
            let caps_file = std::fs::read_dir(&pending_dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    let v: serde_json::Value =
                        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
                    v["type"] == "capabilities"
                })
                .expect("capabilities file exists");
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&caps_file).unwrap()).unwrap();

            assert_eq!(v["type"], "capabilities");
            assert_eq!(v["provider"], "codex");
            assert_eq!(v["supports_pre_tool_use"], false);
            assert_eq!(v["supports_post_tool_use"], true);
            assert_eq!(v["supports_tool_response_capture"], false);
            assert_eq!(v["supports_session_stop_event"], false);
            assert_eq!(v["supports_transcript_tail"], false);
            assert_eq!(v["supports_subagent_lifecycle"], false);
            assert_eq!(v["session_id"], "s-1");
            assert_eq!(v["schema_version"], fornax_types::CAPABILITY_SCHEMA_VERSION);

            let signals = v["signals"].as_array().unwrap();
            assert_eq!(signals.len(), 6);
            assert_eq!(signals[0]["class"], "tool_invocation");
            assert_eq!(signals[0]["state"], "unsupported");
            assert_eq!(
                signals[0]["detail"],
                "rollout tail cannot intercept pre-execution"
            );
            assert_eq!(signals[2]["class"], "process_result");
            assert_eq!(signals[2]["state"], "collection_failed");
            assert_eq!(signals[5]["class"], "neural_trace");
            assert_eq!(signals[5]["state"], "quantum_entangled");

            std::fs::remove_file(&db_path).ok();
            std::fs::remove_dir_all(&out_dir).ok();
        }

        #[tokio::test]
        async fn no_capabilities_envelope_when_none_announced() {
            let db_path = tmp_db_path("without-caps");
            let store = seeded_store(&db_path).await;
            // No `upsert_capabilities` call — this session never announced.

            let out_dir = std::env::temp_dir().join(format!("fornax-spool-{}", Uuid::new_v4()));
            export_spool_from_store(&store, "s-aha", &out_dir)
                .await
                .expect("export spool");

            let pending_dir = out_dir.join("pending");
            let types = read_pending_types(&pending_dir);
            assert!(
                !types.contains(&"capabilities".to_string()),
                "expected no capabilities envelope, got: {types:?}"
            );
            assert!(types.contains(&"event".to_string()));

            std::fs::remove_file(&db_path).ok();
            std::fs::remove_dir_all(&out_dir).ok();
        }

        /// FORNX-157 AC: "Provenance/trust metadata survives ... cloud-safe
        /// projection." Unlike `RuntimeCapabilities` (which projects through
        /// `LegacyCapabilitiesWire` to a frozen bool set for wire-compat with
        /// an out-of-repo consumer), `Evidence` has no such frozen-shape
        /// contract — it is spooled as-is (see `export_spool_from_store`).
        /// So "cloud-safe projection" for `Evidence::source` means: the
        /// structured metadata ships through unmodified, not stripped.
        #[tokio::test]
        async fn evidence_envelope_carries_source_metadata_through_export() {
            let db_path = tmp_db_path("evidence-source-export");
            let store = fornax_store::Store::open(&db_path).await.expect("open db");

            let event = fornax_types::AgentEvent {
                id: Uuid::new_v4(),
                session_id: "s-source".into(),
                provider: Provider::Codex,
                kind: EventKind::PostToolUse,
                observed_at: "2026-01-01T00:00:00Z".into(),
                tool_name: Some("exec_command".into()),
                tool_input: Some(serde_json::json!(["pytest"])),
                tool_response: Some(serde_json::json!({"exit_code": 0})),
                raw: serde_json::json!({"type": "exec_command_end"}),
            };
            store.insert_event(&event).await.expect("insert event");

            let evidence = fornax_types::Evidence {
                id: Uuid::new_v4(),
                session_id: "s-source".into(),
                source_event_id: event.id,
                kind: EvidenceKind::ExitCode,
                observed_at: "2026-01-01T00:00:01Z".into(),
                payload: serde_json::json!({"command": ["pytest"], "exit_code": 0}),
                provenance: "codex:rollout:exec_command_end".into(),
                source: Some(fornax_types::EvidenceSource {
                    sensor_name: "codex_exec_command_end_sensor_v1".into(),
                    trust_class: fornax_types::TrustClass::AgentAdjacent,
                    collected_at: "2026-01-01T00:00:01Z".into(),
                    provider: Some(Provider::Codex),
                    collection_method: fornax_types::CollectionMethod::FilePoll,
                    collector_version: Some("codex-adapter-0.1.0".into()),
                    freshness: fornax_types::Freshness {
                        clock_source: fornax_types::ClockSource::HostClock,
                        caveat: None,
                    },
                    tamper_boundary: fornax_types::TamperBoundary::for_trust_class(
                        &fornax_types::TrustClass::AgentAdjacent,
                        &fornax_types::CollectionMethod::FilePoll,
                    ),
                    correlation_group: None,
                    derived_from: Vec::new(),
                }),
                extension: None,
            };
            store
                .insert_evidence(&evidence)
                .await
                .expect("insert evidence");

            let out_dir = std::env::temp_dir().join(format!("fornax-spool-{}", Uuid::new_v4()));
            export_spool_from_store(&store, "s-source", &out_dir)
                .await
                .expect("export spool");

            let pending_dir = out_dir.join("pending");
            let evidence_file = std::fs::read_dir(&pending_dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    let v: serde_json::Value =
                        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
                    v["type"] == "evidence"
                })
                .expect("evidence file exists");
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&evidence_file).unwrap()).unwrap();
            assert_eq!(
                v["source"]["sensor_name"], "codex_exec_command_end_sensor_v1",
                "structured sensor/trust metadata must survive the spool export projection"
            );
            assert_eq!(v["source"]["trust_class"], "agent_adjacent");
            assert_eq!(v["source"]["provider"], "codex");
            // FORNX-159: collection_method/collector_version/freshness/
            // tamper_boundary must survive the same cloud-safe projection
            // boundary as the FORNX-157 fields above.
            assert_eq!(v["source"]["collection_method"], "file_poll");
            assert_eq!(v["source"]["collector_version"], "codex-adapter-0.1.0");
            assert_eq!(v["source"]["freshness"]["clock_source"], "host_clock");
            assert!(v["source"]["tamper_boundary"]["description"].is_string());

            std::fs::remove_file(&db_path).ok();
            std::fs::remove_dir_all(&out_dir).ok();
        }

        /// FORNX-158 AC: provider-extension data must survive the same
        /// cloud-safe projection boundary as `EvidenceSource` above —
        /// `Evidence` spools as-is, so the extension envelope (including a
        /// preserved unknown field) should ship through unmodified.
        #[tokio::test]
        async fn evidence_envelope_carries_extension_data_through_export() {
            let db_path = tmp_db_path("evidence-extension-export");
            let store = fornax_store::Store::open(&db_path).await.expect("open db");

            let event = fornax_types::AgentEvent {
                id: Uuid::new_v4(),
                session_id: "s-ext".into(),
                provider: Provider::ClaudeCode,
                kind: EventKind::PostToolUse,
                observed_at: "2026-01-01T00:00:00Z".into(),
                tool_name: Some("Bash".into()),
                tool_input: Some(serde_json::json!({"command": ["pytest"]})),
                tool_response: Some(serde_json::json!({"stdout": ""})),
                raw: serde_json::json!({"hook_event_name": "PostToolUse"}),
            };
            store.insert_event(&event).await.expect("insert event");

            let mut extension = fornax_types::ExtensionEnvelope::new(
                Provider::ClaudeCode,
                "claude-adapter-0.3.0",
                fornax_types::ContentClass::ToolTelemetry,
                serde_json::json!({"cache_read_tokens": 128}),
            );
            // Prove unknown-field preservation across the persistence +
            // export boundary, not just an in-memory round trip.
            extension
                .unknown
                .insert("retention_hint_days".into(), serde_json::json!(30));

            let evidence = fornax_types::Evidence {
                id: Uuid::new_v4(),
                session_id: "s-ext".into(),
                source_event_id: event.id,
                kind: EvidenceKind::ExitCode,
                observed_at: "2026-01-01T00:00:01Z".into(),
                payload: serde_json::json!({"command": ["pytest"], "exit_code": 0}),
                provenance: "claude_code:PostToolUse:Bash#heuristic:stderr_empty".into(),
                source: None,
                extension: Some(extension),
            };
            store
                .insert_evidence(&evidence)
                .await
                .expect("insert evidence");

            let out_dir = std::env::temp_dir().join(format!("fornax-spool-{}", Uuid::new_v4()));
            export_spool_from_store(&store, "s-ext", &out_dir)
                .await
                .expect("export spool");

            let pending_dir = out_dir.join("pending");
            let evidence_file = std::fs::read_dir(&pending_dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    let v: serde_json::Value =
                        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
                    v["type"] == "evidence"
                })
                .expect("evidence file exists");
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&evidence_file).unwrap()).unwrap();
            assert_eq!(
                v["extension"]["schema_version"],
                fornax_types::EXTENSION_SCHEMA_VERSION
            );
            assert_eq!(v["extension"]["content_class"], "tool_telemetry");
            assert_eq!(v["extension"]["fields"]["cache_read_tokens"], 128);
            assert_eq!(
                v["extension"]["retention_hint_days"], 30,
                "unknown extension field must survive the store + export round trip, not be dropped"
            );

            std::fs::remove_file(&db_path).ok();
            std::fs::remove_dir_all(&out_dir).ok();
        }
    }

    // --- FORNX-304: render_fusion -------------------------------------------

    /// Fixture shaped exactly like `GET /api/fusion`'s real response body —
    /// a `FusedFinding` with two rationale entries, one `Counted` and one
    /// `Decided`, so the rendering test below can pin that every entry (and
    /// every id it names) is shown individually rather than collapsed into a
    /// summary.
    fn fusion_fixture() -> serde_json::Value {
        serde_json::json!({
            "claim": "c1",
            "session": "s1",
            "found": true,
            "graph_source": "graph",
            "fused": {
                "claim_id": "c1",
                "verdict": "verified",
                "uncertainty": "qualified",
                "rationale": [
                    {
                        "rule": "independence_unverified",
                        "effect": "caveat",
                        "link_ids": ["link-1"],
                        "missing_evidence_ids": [],
                        "evidence_ids": ["ev-1"],
                        "detail": "link link-1's evidence carries no recorded correlation group",
                    },
                    {
                        "rule": "verdict_decided",
                        "effect": "decided",
                        "link_ids": ["link-1"],
                        "missing_evidence_ids": [],
                        "evidence_ids": [],
                        "detail": "1 distinct supporting vote(s) survived fusion, no contradicting votes",
                    },
                ],
                "counted_link_ids": ["link-1"],
                "discounted_link_ids": [],
                "missing_evidence_ids": [],
                "unresolved_conflict": false,
                "policy_name": "deterministic_baseline_v1",
                "policy_version": 1,
                "computed_at": "2026-09-02T00:00:00+00:00",
            },
        })
    }

    #[test]
    fn render_fusion_shows_verdict_and_every_rationale_entry_individually() {
        let v = fusion_fixture();
        let rendered = render_fusion(&v);
        assert!(rendered.contains("claim: c1"));
        assert!(rendered.contains("session: s1"));
        assert!(rendered.contains("graph_source: graph"));
        assert!(rendered.contains("VERIFIED"));
        assert!(rendered.contains("uncertainty: qualified"));
        assert!(rendered.contains("policy: deterministic_baseline_v1 v1"));
        assert!(rendered.contains("computed_at: 2026-09-02T00:00:00+00:00"));
        // Both rationale entries must appear, each with its rule name,
        // effect, referenced ids, and detail text -- never collapsed into a
        // single summary line.
        assert!(rendered.contains("independence_unverified [caveat]"));
        assert!(rendered.contains("link link-1's evidence carries no recorded correlation group"));
        assert!(rendered.contains("verdict_decided [decided]"));
        assert!(rendered
            .contains("1 distinct supporting vote(s) survived fusion, no contradicting votes"));
        assert!(rendered.contains("link_ids: link-1"));
        assert!(rendered.contains("evidence_ids: ev-1"));
    }

    #[test]
    fn render_fusion_reports_not_found_for_unknown_claim() {
        let v = serde_json::json!({
            "claim": "c-missing",
            "session": "s1",
            "found": false,
            "reason": "no claim with this id is on record for this session",
        });
        let rendered = render_fusion(&v);
        assert!(rendered.contains("no such claim on record"));
    }

    #[test]
    fn render_fusion_shows_daemon_error_distinctly_from_not_found() {
        let v = serde_json::json!({
            "claim": "c1",
            "session": "s1",
            "error": "database error: disk I/O error",
        });
        let rendered = render_fusion(&v);
        assert!(rendered.contains("error: database error"));
        assert!(!rendered.contains("no such claim on record"));
    }

    #[test]
    fn render_fusion_surfaces_unresolved_conflict_banner() {
        let mut v = fusion_fixture();
        v["fused"]["verdict"] = serde_json::json!("review");
        v["fused"]["unresolved_conflict"] = serde_json::json!(true);
        let rendered = render_fusion(&v);
        assert!(rendered.contains("⚠ unresolved conflict"));
    }

    // --- FORNX-96: render_decision (local half) -----------------------------

    /// Fixture shaped exactly like `GET /api/decision`'s real response body
    /// -- `fusion_fixture` plus a `recommendation` block.
    fn decision_fixture() -> serde_json::Value {
        let mut v = fusion_fixture();
        v["recommendation"] = serde_json::json!({
            "claim_id": "c1",
            "action": "review",
            "risk_class": "balanced",
            "policy_name": "default_risk_policy_v1",
            "policy_version": 1,
            "rationale_summary": "verdict=Verified uncertainty=Qualified risk=Balanced -> Review",
        });
        v
    }

    #[test]
    fn render_decision_shows_recommendation_and_full_fusion_detail_together() {
        let v = decision_fixture();
        let rendered = render_decision(&v);
        // The recommendation is shown...
        assert!(rendered.contains("recommendation: ! REVIEW"));
        assert!(rendered.contains("risk: balanced"));
        assert!(rendered.contains("policy: default_risk_policy_v1 v1"));
        assert!(rendered.contains("verdict=Verified uncertainty=Qualified risk=Balanced -> Review"));
        // ...together with the SAME full fusion detail `fusion` renders --
        // never instead of it.
        assert!(rendered.contains("VERIFIED"));
        assert!(rendered.contains("uncertainty: qualified"));
        assert!(rendered.contains("independence_unverified"));
        assert!(rendered.contains("verdict_decided"));
    }

    #[test]
    fn render_decision_icons_cover_all_three_actions_distinctly() {
        assert_eq!(recommendation_icon("proceed"), "✓");
        assert_eq!(recommendation_icon("review"), "!");
        assert_eq!(recommendation_icon("block"), "✕");
    }

    #[test]
    fn render_decision_reports_not_found_for_unknown_claim() {
        let v = serde_json::json!({
            "claim": "missing",
            "session": "s1",
            "found": false,
            "reason": "no claim with this id is on record for this session",
        });
        let rendered = render_decision(&v);
        assert!(rendered.contains("no such claim on record"));
        assert!(!rendered.contains("recommendation:"));
    }

    #[test]
    fn render_decision_shows_daemon_error_without_a_recommendation_block() {
        let v = serde_json::json!({
            "claim": "c1",
            "session": "s1",
            "error": "unknown risk class 'reckless' -- expected one of strict, balanced, lenient",
        });
        let rendered = render_decision(&v);
        assert!(rendered.contains("error:"));
        assert!(!rendered.contains("recommendation:"));
    }

    #[test]
    fn render_decision_reflects_a_different_action_under_a_different_risk_class() {
        let mut strict_view = decision_fixture();
        strict_view["recommendation"]["action"] = serde_json::json!("block");
        strict_view["recommendation"]["risk_class"] = serde_json::json!("strict");
        let rendered = render_decision(&strict_view);
        assert!(rendered.contains("recommendation: ✕ BLOCK"));
        assert!(rendered.contains("risk: strict"));
    }

    fn judge_fixture() -> serde_json::Value {
        let mut v = fusion_fixture();
        v["judge"] = serde_json::json!({
            "verdict": "supported",
            "rationale": "the evidence excerpt is consistent with the claim",
            "model": "llama3.1",
            "endpoint": "http://localhost:11434/v1",
            "prompt_version": 1,
            "called_at": "2026-09-02T00:00:00+00:00",
            "disagreement": false,
        });
        v
    }

    #[test]
    fn render_judge_shows_labeled_model_derived_opinion_and_full_fusion_detail_together() {
        let v = judge_fixture();
        let rendered = render_judge(&v);
        assert!(rendered.contains("judge (model-derived, NOT independent evidence): ✓ SUPPORTED"));
        assert!(rendered.contains("model: llama3.1"));
        assert!(rendered.contains("endpoint: http://localhost:11434/v1"));
        // ...together with the SAME full fusion detail `fusion` renders --
        // never instead of it.
        assert!(rendered.contains("VERIFIED"));
        assert!(rendered.contains("uncertainty: qualified"));
    }

    #[test]
    fn render_judge_icons_cover_all_four_verdicts_distinctly() {
        assert_eq!(judge_verdict_icon("supported"), "✓");
        assert_eq!(judge_verdict_icon("contradicted"), "✕");
        assert_eq!(judge_verdict_icon("inconclusive"), "?");
        assert_eq!(judge_verdict_icon("unavailable"), "—");
    }

    #[test]
    fn render_judge_surfaces_disagreement_banner_without_hiding_it() {
        let mut v = judge_fixture();
        v["judge"]["verdict"] = serde_json::json!("contradicted");
        v["judge"]["disagreement"] = serde_json::json!(true);
        let rendered = render_judge(&v);
        assert!(rendered.contains("⚠ disagreement"));
        // The underlying deterministic verdict is still shown, unresolved --
        // never overwritten by the judge's disagreement.
        assert!(rendered.contains("VERIFIED"));
    }

    #[test]
    fn render_judge_shows_unavailable_honestly_never_a_fabricated_verdict() {
        let mut v = judge_fixture();
        v["judge"]["verdict"] = serde_json::json!("unavailable");
        v["judge"]["rationale"] =
            serde_json::json!("semantic judge disabled via [semantic_judge].enabled = false");
        v["judge"]["disagreement"] = serde_json::Value::Null;
        let rendered = render_judge(&v);
        assert!(rendered.contains("— UNAVAILABLE"));
        assert!(!rendered.contains("⚠ disagreement"));
    }

    #[test]
    fn render_judge_reports_not_found_for_unknown_claim() {
        let v = serde_json::json!({
            "claim": "missing",
            "session": "s1",
            "found": false,
            "reason": "no claim with this id is on record for this session",
        });
        let rendered = render_judge(&v);
        assert!(rendered.contains("no such claim on record"));
        assert!(!rendered.contains("judge ("));
    }

    #[test]
    fn render_judge_shows_daemon_error_without_a_judge_block() {
        let v = serde_json::json!({
            "claim": "c1",
            "session": "s1",
            "error": "judge task panicked",
        });
        let rendered = render_judge(&v);
        assert!(rendered.contains("error:"));
        assert!(!rendered.contains("judge ("));
    }

    // --- render_reliability (FORNX-105) -------------------------------------

    fn context_key_fixture(model_version: &str) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "provider": "claude_code",
            "model_family": "claude",
            "model_version": model_version,
            "adapter_version": "0.0.4",
            "task_class": "test_execution",
            "toolset": ["shell", "file_edit"],
            "repository_class": "public_oss",
            "policy_version": "policy-v3",
            "verifier_version": "verifier-v2",
            "fusion_version": "fusion-v1",
            "capability_schema_version": 1,
            "capability_fingerprint": [["tool_trace", "available"]],
        })
    }

    fn confident_signal_fixture(model_version: &str, success_rate: f64) -> serde_json::Value {
        serde_json::json!({
            "context_key": context_key_fixture(model_version),
            "sample_support": {"confident": {"sample_count": 40}},
            "not_evaluable_count": 0,
            "policy_version": 1,
            "reliability_estimate": {
                "success_rate": success_rate,
                "confidence_interval": {
                    "lower": (success_rate - 0.1).max(0.0),
                    "upper": (success_rate + 0.1).min(1.0),
                    "confidence_level": 0.95,
                },
            },
        })
    }

    fn insufficient_signal_fixture(model_version: &str) -> serde_json::Value {
        serde_json::json!({
            "context_key": context_key_fixture(model_version),
            "sample_support": {"insufficient_support": {"sample_count": 3, "minimum_required": 30}},
            "not_evaluable_count": 0,
            "policy_version": 1,
        })
    }

    #[test]
    fn render_reliability_reports_unavailable_when_privacy_gate_is_closed() {
        let v = serde_json::json!({
            "session": "s1",
            "available": false,
            "reason": "historical reliability aggregation is disabled by local policy",
        });
        let rendered = render_reliability(&v);
        assert!(rendered.contains("reliability aggregation unavailable"));
        assert!(rendered.contains("disabled by local policy"));
        // Must never be rendered as, or alongside, an "insufficient data" message
        // -- these are two structurally distinct outcomes (AC5 vs AC2).
        assert!(!rendered.contains("insufficient data"));
    }

    #[test]
    fn render_reliability_reports_no_capabilities_announced_distinctly() {
        let v = serde_json::json!({
            "session": "s1",
            "available": true,
            "capabilities_announced": false,
            "reason": "no capabilities announced yet by any adapter for this session -- \
                       a reliability context key cannot be built without one",
        });
        let rendered = render_reliability(&v);
        assert!(rendered.contains("no capabilities announced"));
        assert!(!rendered.contains("insufficient data"));
        assert!(!rendered.contains("unavailable"));
    }

    #[test]
    fn render_reliability_shows_insufficient_support_as_explicit_message_never_a_number() {
        let v = serde_json::json!({
            "session": "s1",
            "available": true,
            "capabilities_announced": true,
            "signal": insufficient_signal_fixture("claude-sonnet-5"),
        });
        let rendered = render_reliability(&v);
        assert!(rendered.contains("insufficient data -- 3 of 30 needed"));
        assert!(!rendered.contains("reliability estimate:"));
        // Full context must still be inspectable even when sparse (AC3).
        assert!(rendered.contains("provider=claude_code"));
        assert!(rendered.contains("model_version=claude-sonnet-5"));
    }

    #[test]
    fn render_reliability_never_shows_a_percentage_without_the_full_context_in_the_same_output() {
        let v = serde_json::json!({
            "session": "s1",
            "available": true,
            "capabilities_announced": true,
            "signal": confident_signal_fixture("claude-sonnet-5", 0.90),
        });
        let rendered = render_reliability(&v);
        assert!(rendered.contains("reliability estimate: 90.0%"));
        // AC1: the exact context dimensions must appear in the SAME output
        // as the percentage.
        for expected in [
            "provider=claude_code",
            "model_family=claude",
            "model_version=claude-sonnet-5",
            "adapter_version=0.0.4",
            "task_class=test_execution",
            "repository_class=public_oss",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected:?} in:\n{rendered}"
            );
        }
    }

    #[test]
    fn render_reliability_signal_suppresses_the_estimate_when_context_key_is_missing() {
        // Adversarial payload: an estimate present but no context_key at all
        // -- this must never be reachable as a rendered percentage.
        let mut signal = confident_signal_fixture("claude-sonnet-5", 0.93);
        signal.as_object_mut().unwrap().remove("context_key");
        let rendered = render_reliability_signal("  ", &signal, false);
        assert!(!rendered.contains("93.0%"));
        assert!(!rendered.contains("reliability estimate:"));
        assert!(rendered.contains("context key incomplete"));
    }

    #[test]
    fn render_reliability_drift_detected_shows_banner_and_suppresses_stale_baseline_estimate() {
        let v = serde_json::json!({
            "session": "s1",
            "available": true,
            "capabilities_announced": true,
            "drift_assessment": {
                "baseline_signal": confident_signal_fixture("claude-sonnet-4", 0.95),
                "comparison_signal": confident_signal_fixture("claude-sonnet-5", 0.55),
                "drift_state": "drifted",
                "policy_version": 1,
            },
        });
        let rendered = render_reliability(&v);
        assert!(rendered.contains("⚠ drift detected"));
        // The comparison's live estimate is shown plainly...
        assert!(rendered.contains("reliability estimate: 55.0%"));
        // ...but the baseline's stale confidence must be qualified, never
        // shown plain beside the new one (AC4).
        assert!(!rendered.contains("95.0%"));
        assert!(rendered.contains("stale -- superseded by drift"));
    }

    #[test]
    fn render_reliability_stable_drift_shows_both_estimates_plainly_with_no_stale_marker() {
        let v = serde_json::json!({
            "session": "s1",
            "available": true,
            "capabilities_announced": true,
            "drift_assessment": {
                "baseline_signal": confident_signal_fixture("claude-sonnet-4", 0.90),
                "comparison_signal": confident_signal_fixture("claude-sonnet-5", 0.92),
                "drift_state": "stable",
                "policy_version": 1,
            },
        });
        let rendered = render_reliability(&v);
        assert!(rendered.contains("✓ stable"));
        assert!(rendered.contains("90.0%"));
        assert!(rendered.contains("92.0%"));
        assert!(!rendered.contains("stale -- superseded by drift"));
    }

    #[test]
    fn render_reliability_not_comparable_drift_names_the_differing_dimensions() {
        let v = serde_json::json!({
            "session": "s1",
            "available": true,
            "capabilities_announced": true,
            "drift_assessment": {
                "baseline_signal": confident_signal_fixture("claude-sonnet-4", 0.90),
                "comparison_signal": confident_signal_fixture("claude-sonnet-5", 0.30),
                "drift_state": {"not_comparable": {"differing_dimensions": ["task_class"]}},
                "policy_version": 1,
            },
        });
        let rendered = render_reliability(&v);
        assert!(rendered.contains("✕ not comparable"));
        assert!(rendered.contains("differs in task_class"));
        assert!(rendered.contains("does not apply"));
    }

    #[test]
    fn render_reliability_insufficient_data_for_comparison_is_its_own_distinct_state() {
        let v = serde_json::json!({
            "session": "s1",
            "available": true,
            "capabilities_announced": true,
            "drift_assessment": {
                "baseline_signal": insufficient_signal_fixture("claude-sonnet-4"),
                "comparison_signal": insufficient_signal_fixture("claude-sonnet-5"),
                "drift_state": "insufficient_data_for_comparison",
                "policy_version": 1,
            },
        });
        let rendered = render_reliability(&v);
        assert!(rendered.contains("insufficient data for comparison"));
        assert!(!rendered.contains("stale -- superseded by drift"));
    }

    #[test]
    fn drift_state_label_covers_every_state_distinctly_with_a_forward_compat_fallback() {
        assert!(drift_state_label(&serde_json::json!("stable")).starts_with("✓"));
        assert!(drift_state_label(&serde_json::json!("drifted")).starts_with("⚠"));
        assert!(
            drift_state_label(&serde_json::json!("insufficient_data_for_comparison"))
                .starts_with("?")
        );
        assert!(drift_state_label(
            &serde_json::json!({"not_comparable": {"differing_dimensions": []}})
        )
        .starts_with("✕"));
        // Forward-compat: an unrecognized tag must not collapse onto an
        // existing state's icon.
        assert_eq!(
            drift_state_label(&serde_json::json!("quantum_pending")),
            "◌ quantum_pending"
        );
    }
}
