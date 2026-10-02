//! Adapter install/integration registry (HORO-1621, FORNX-428, ADR-0013 §8).
//!
//! Before HORO-1621, each coding-agent adapter Fornax could wire into a host
//! tool's own configuration (`~/.claude/settings.json`,
//! `~/.codex/config.toml`) got its own pair of top-level CLI commands
//! (`install-claude`/`uninstall-claude`, `install-codex`/`uninstall-codex`).
//! HORO-1621 replaced that with one coherent `install <adapter>`/
//! `uninstall <adapter>` entry point, but still dispatched through
//! `AdapterId`'s closed enum and 7 hand-maintained `match` tables — adding a
//! third adapter meant editing all 7.
//!
//! FORNX-428 replaces those match tables with [`AdapterPlugin`]: one trait
//! every adapter implements, and [`registry`]/[`resolve`] as the single
//! runtime-resolved lookup. Adding a built-in adapter now means one struct
//! implementing the trait plus one entry in [`registry`]'s array — never a
//! new top-level `Commands` variant, and (per FORNX-428's registry-
//! completeness test below) never a partially-wired adapter that compiles
//! with a wrong or missing method.
//!
//! `AdapterId` (the `clap::ValueEnum` the CLI parses) is unchanged by this
//! slice — see FORNX-428's S2 for retiring it in favor of a table-driven
//! `value_parser`. This slice only changes what happens *after* parsing.

use std::path::PathBuf;

/// One coding-agent integration Fornax can wire into a host tool's own
/// config. Implementors own their target path(s) — this is what absorbs the
/// real asymmetry between adapters (Codex's `install`/`plan` need a second
/// path, the notify script; Claude Code's need only one).
///
/// An adapter must not gain unrestricted access to arbitrary CLI internals
/// merely to register itself — every method here is scoped to exactly the
/// one host-config surface this adapter owns.
pub trait AdapterPlugin: Send + Sync {
    /// Stable registry key, matching the `clap::ValueEnum` name in
    /// `AdapterId` for every built-in adapter (checked by the
    /// registry-completeness test below).
    fn id(&self) -> &'static str;

    /// Human display name, e.g. "Claude Code".
    fn display_name(&self) -> &'static str;

    /// One-line description of what this adapter's install/uninstall
    /// actually wires, for `fornax install list`.
    fn summary(&self) -> &'static str;

    /// The one config path `install list`'s rendering and tests use to
    /// describe this adapter. Adapters with more than one owned path (e.g.
    /// Codex's config file plus its notify script) report the primary one
    /// mutated by `settings.json`/`config.toml`-shaped install/uninstall.
    fn target_path(&self) -> PathBuf;

    /// Computes, without writing anything, what `install` would do right
    /// now.
    fn plan(&self) -> anyhow::Result<AdapterActionResult>;

    /// Wires this adapter into its host tool's configuration.
    fn install(&self) -> anyhow::Result<AdapterActionResult>;

    /// Removes exactly what `install` added.
    fn uninstall(&self) -> anyhow::Result<AdapterActionResult>;
}

struct ClaudeCodeAdapter;

impl AdapterPlugin for ClaudeCodeAdapter {
    fn id(&self) -> &'static str {
        "claude-code"
    }

    fn display_name(&self) -> &'static str {
        "Claude Code"
    }

    fn summary(&self) -> &'static str {
        "Wires Fornax hooks into ~/.claude/settings.json (SessionStart, \
         UserPromptSubmit, PreToolUse, PostToolUse, Stop)."
    }

    fn target_path(&self) -> PathBuf {
        crate::claude_adapter::default_path()
    }

    fn plan(&self) -> anyhow::Result<AdapterActionResult> {
        crate::claude_adapter::plan_install_at(&self.target_path())
    }

    fn install(&self) -> anyhow::Result<AdapterActionResult> {
        crate::claude_adapter::install_at(&self.target_path())
    }

    fn uninstall(&self) -> anyhow::Result<AdapterActionResult> {
        crate::claude_adapter::uninstall_at(&self.target_path())
    }
}

struct CodexAdapter;

impl AdapterPlugin for CodexAdapter {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn display_name(&self) -> &'static str {
        "Codex"
    }

    fn summary(&self) -> &'static str {
        "Wires Fornax's ambient-status notify script into \
         ~/.codex/config.toml's `notify` entry."
    }

    fn target_path(&self) -> PathBuf {
        crate::codex_adapter::default_path()
    }

    fn plan(&self) -> anyhow::Result<AdapterActionResult> {
        crate::codex_adapter::plan_install_at(
            &self.target_path(),
            &crate::codex_adapter::default_notify_script(),
        )
    }

    fn install(&self) -> anyhow::Result<AdapterActionResult> {
        crate::codex_adapter::install_at(
            &self.target_path(),
            &crate::codex_adapter::default_notify_script(),
        )
    }

    fn uninstall(&self) -> anyhow::Result<AdapterActionResult> {
        crate::codex_adapter::uninstall_at(&self.target_path())
    }
}

/// Every built-in adapter, in display order. The single registration point
/// FORNX-428's S2 extends with runtime-registered external adapters.
pub fn registry() -> &'static [&'static dyn AdapterPlugin] {
    &[&ClaudeCodeAdapter, &CodexAdapter]
}

/// Looks up a registered adapter by its stable id string.
pub fn resolve(id: &str) -> Option<&'static dyn AdapterPlugin> {
    registry().iter().copied().find(|a| a.id() == id)
}

/// Stable adapter id. This is the registry key referenced by `fornax
/// install <adapter>` et al. — never a free-form string internally, so an
/// unknown adapter is a clap parse error (clean, non-zero exit, no stack
/// trace) rather than a silently-ignored no-op.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum AdapterId {
    #[value(name = "claude-code")]
    ClaudeCode,
    #[value(name = "codex")]
    Codex,
}

impl AdapterId {
    /// Every adapter currently registered, in display order.
    pub const ALL: [AdapterId; 2] = [AdapterId::ClaudeCode, AdapterId::Codex];

    /// Stable id string, matching the `clap::ValueEnum` name above.
    pub fn id(self) -> &'static str {
        match self {
            AdapterId::ClaudeCode => "claude-code",
            AdapterId::Codex => "codex",
        }
    }

    /// Human display name.
    pub fn display_name(self) -> &'static str {
        self.plugin().display_name()
    }

    /// One-line description of what this adapter's install/uninstall
    /// actually wires, for `fornax install list`.
    pub fn summary(self) -> &'static str {
        self.plugin().summary()
    }

    /// Resolves this id against [`registry`]. Always succeeds for a
    /// built-in `AdapterId` — see `adapter_id_resolves_against_the_registry`
    /// below.
    fn plugin(self) -> &'static dyn AdapterPlugin {
        resolve(self.id())
            .unwrap_or_else(|| unreachable!("every AdapterId variant must have a registry() entry"))
    }
}

/// Outcome of an install/uninstall/plan operation, suitable for human
/// rendering and as a machine-readable payload (`--json` on `plan`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AdapterActionResult {
    pub adapter: String,
    pub action: String,
    /// Whether applying this action would change (or did change) anything
    /// on disk. `false` means "already in the target state" for
    /// install/uninstall, or "nothing to do" for plan.
    pub changed: bool,
    /// Bounded, human-readable summary — never a credential, file content,
    /// or unrestricted path beyond the one config path this adapter owns.
    pub message: String,
    pub path: String,
}

/// `fornax install <adapter>` — routes to the same install logic the
/// deprecated `install-claude`/`install-codex` aliases call; see
/// `crate::claude_adapter`/`crate::codex_adapter` doc comments for why
/// there is exactly one implementation per adapter, never a forked one for
/// the new vs. old command spelling.
pub fn install(adapter: AdapterId) -> anyhow::Result<AdapterActionResult> {
    adapter.plugin().install()
}

/// `fornax uninstall <adapter>`.
pub fn uninstall(adapter: AdapterId) -> anyhow::Result<AdapterActionResult> {
    adapter.plugin().uninstall()
}

/// `fornax install plan <adapter>` — computes, without writing anything,
/// what `install` would do right now.
pub fn plan(adapter: AdapterId) -> anyhow::Result<AdapterActionResult> {
    adapter.plugin().plan()
}

/// `fornax install doctor <adapter>` — current install status, read-only.
/// Reuses the same plan computation `plan` uses; doctor and plan differ
/// only in rendering/action label, not in what they compute.
pub fn doctor(adapter: AdapterId) -> anyhow::Result<AdapterActionResult> {
    let mut outcome = plan(adapter)?;
    outcome.action = "doctor".to_string();
    Ok(outcome)
}

/// Default on-disk path an adapter's install/uninstall mutates — used by
/// `fornax install list`'s rendering and by tests.
pub fn default_config_path(adapter: AdapterId) -> PathBuf {
    adapter.plugin().target_path()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    #[test]
    fn adapter_id_round_trips_stable_ids() {
        for &a in AdapterId::ALL.iter() {
            let v = a.to_possible_value().expect("every AdapterId has a value");
            assert_eq!(v.get_name(), a.id());
        }
    }

    #[test]
    fn all_lists_exactly_the_two_known_adapters() {
        let ids: Vec<&str> = AdapterId::ALL.iter().map(|a| a.id()).collect();
        assert_eq!(ids, vec!["claude-code", "codex"]);
    }
}
