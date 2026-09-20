//! `fornax` CLI (FORNX-31): compact status-line segment + detail drill-down,
//! reading from the same daemon-local API the dashboard uses (FORNX-32) — one
//! source of truth, not three interpretations of session integrity.

use clap::{Parser, Subcommand};

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
        Commands::ExportSpool { session, out } => export_spool(&session, &out).await?,
        Commands::InstallClaude => install_claude()?,
        Commands::UninstallClaude => uninstall_claude()?,
        Commands::InstallCodex => install_codex()?,
        Commands::UninstallCodex => uninstall_codex()?,
    }
    Ok(())
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
        // `schema_version`/`signals`, which fornax-cloud's
        // `fornax-uploader::types::RuntimeCapabilities` (a separate,
        // out-of-scope repo) does not know about. Project to the frozen
        // flat-bool wire shape at the export boundary so the spool envelope
        // stays byte-for-byte wire-compatible — see
        // `fornax_types::capabilities::LegacyCapabilitiesWire`'s doc comment.
        let legacy = fornax_types::LegacyCapabilitiesWire::from(caps);
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

            // The emitted capabilities file must be wire-compatible with
            // fornax-cloud's fornax-uploader::types::RuntimeCapabilities:
            // the flat field set below, plus "type" — no extra fields such
            // as a store-internal session_id/id (the cloud backend keys
            // capabilities on (device_id, provider), never on an envelope
            // id — see that crate's IngestMessage::canonical_id doc).
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
            let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec![
                    "notes",
                    "provider",
                    "supports_post_tool_use",
                    "supports_pre_tool_use",
                    "supports_session_stop_event",
                    "supports_subagent_lifecycle",
                    "supports_tool_response_capture",
                    "supports_transcript_tail",
                    "type",
                ]
            );

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
}
