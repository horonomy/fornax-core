//! Adapter install/integration registry (HORO-1621, ADR-0013 §8).
//!
//! Before this ticket, each coding-agent adapter Fornax could wire into a
//! host tool's own configuration (`~/.claude/settings.json`,
//! `~/.codex/config.toml`) got its own pair of top-level CLI commands
//! (`install-claude`/`uninstall-claude`, `install-codex`/`uninstall-codex`).
//! That means the root command list grows by two for every new adapter, and
//! a product engineer has to edit the root `Commands` enum just to add one.
//! ADR-0013 §8 calls this out directly: "a product introducing its second
//! adapter-shaped top-level command is the trigger to make this move."
//!
//! This module is that move: `AdapterId` is a small, closed enum (a stable
//! registry key, not a free-form string) and [`install`]/[`uninstall`]/
//! [`plan`]/[`doctor`] are the one coherent entry point every adapter target
//! routes through. Adding a third known adapter means adding one more
//! `AdapterId` variant and one more arm in each `match` below — never a new
//! top-level `Commands` variant, and never a new CLI surface to document.
//!
//! ## Why a static match table, not dynamic plugin/manifest loading
//!
//! HORO-1621 asks us to consider dynamic discovery/registration (a product-
//! owned adapter manifest or plugin directory) so a third-party or future
//! adapter could register without a Fornax rebuild at all. We deliberately
//! do not build that here:
//!
//! - Only two adapters exist today (`claude-code`, `codex`), and both mutate
//!   security-sensitive host configuration (HORO-996/ADR-0009's non-
//!   destructive invariant). A manifest-loaded adapter would need its own
//!   trust boundary (who signs it, what it's allowed to touch, how a
//!   malicious manifest is prevented from running arbitrary code merely by
//!   being present on disk) — that is a meaningfully larger design surface
//!   than this ticket's scope, and HORO-1621 itself says to document the
//!   deferral rather than silently skip it if dynamic loading isn't safe to
//!   build now.
//! - A fixed, closed `AdapterId` enum is exhaustively matched by the
//!   compiler (`match` without a wildcard arm fails to build if a variant is
//!   unhandled), which is a stronger safety property for code that mutates
//!   `~/.claude/settings.json`/`~/.codex/config.toml` than a dynamically
//!   registered table would give us for free.
//!
//! The extension point this leaves for a future dynamic registry: every
//! operation below is a plain function of `AdapterId` with no dependency on
//! the root `Commands` enum. A future manifest-backed adapter would plug in
//! by adding a non-exhaustive `AdapterId::External(String)` variant (or a
//! parallel lookup keyed by manifest id) whose operations are dispatched
//! through a constrained, reviewed manifest schema — not by restructuring
//! this module's shape. `fornax-adapter-opencode` (FORNX-161) is the
//! concrete candidate for the next registry entry: it already exists as a
//! long-lived transport adapter, but has no CLI-driven install flow yet
//! today (its wiring is a manual `opencode.json` `"plugin"` entry, not a
//! settings file this CLI mutates) — registering it is future work, not
//! this ticket's.

use std::path::PathBuf;

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
        match self {
            AdapterId::ClaudeCode => "Claude Code",
            AdapterId::Codex => "Codex",
        }
    }

    /// One-line description of what this adapter's install/uninstall
    /// actually wires, for `fornax install list`.
    pub fn summary(self) -> &'static str {
        match self {
            AdapterId::ClaudeCode => {
                "Wires Fornax hooks into ~/.claude/settings.json (SessionStart, \
                 UserPromptSubmit, PreToolUse, PostToolUse, Stop)."
            }
            AdapterId::Codex => {
                "Wires Fornax's ambient-status notify script into \
                 ~/.codex/config.toml's `notify` entry."
            }
        }
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
    match adapter {
        AdapterId::ClaudeCode => {
            crate::claude_adapter::install_at(&crate::claude_adapter::default_path())
        }
        AdapterId::Codex => crate::codex_adapter::install_at(
            &crate::codex_adapter::default_path(),
            &crate::codex_adapter::default_notify_script(),
        ),
    }
}

/// `fornax uninstall <adapter>`.
pub fn uninstall(adapter: AdapterId) -> anyhow::Result<AdapterActionResult> {
    match adapter {
        AdapterId::ClaudeCode => {
            crate::claude_adapter::uninstall_at(&crate::claude_adapter::default_path())
        }
        AdapterId::Codex => {
            crate::codex_adapter::uninstall_at(&crate::codex_adapter::default_path())
        }
    }
}

/// `fornax install plan <adapter>` — computes, without writing anything,
/// what `install` would do right now. Built by reusing the exact same
/// plan-computation function `install` itself calls before saving (see
/// `claude_adapter::plan_install_at`/`codex_adapter::plan_install_at`), so
/// this can never silently disagree with what `install` actually does.
pub fn plan(adapter: AdapterId) -> anyhow::Result<AdapterActionResult> {
    match adapter {
        AdapterId::ClaudeCode => {
            crate::claude_adapter::plan_install_at(&crate::claude_adapter::default_path())
        }
        AdapterId::Codex => crate::codex_adapter::plan_install_at(
            &crate::codex_adapter::default_path(),
            &crate::codex_adapter::default_notify_script(),
        ),
    }
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
    match adapter {
        AdapterId::ClaudeCode => crate::claude_adapter::default_path(),
        AdapterId::Codex => crate::codex_adapter::default_path(),
    }
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
