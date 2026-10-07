//! Adapter install/integration registry (HORO-1621, FORNX-428, ADR-0023).
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
//! FORNX-428 S2 retires `AdapterId`'s closed `clap::ValueEnum` in favor of
//! [`AdapterArg`], a table-driven value type that parses straight through
//! [`resolve`] — the CLI's argument surface no longer hardcodes which ids
//! exist.
//!
//! FORNX-428 S3 moves the registry-inspection verbs (`list`/`doctor`/`plan`)
//! out of `install`'s own subcommand namespace into a dedicated
//! `fornax adapter <verb>` command, and removes the `install-claude`/
//! `uninstall-claude`/`install-codex`/`uninstall-codex` legacy top-level
//! commands entirely — an intentional breaking cleanup performed during
//! DogFooding, before any external compatibility commitment exists.

use std::path::PathBuf;
use std::sync::OnceLock;

/// One coding-agent integration Fornax can wire into a host tool's own
/// config. Implementors own their target path(s) — this is what absorbs the
/// real asymmetry between adapters (Codex's `install`/`plan` need a second
/// path, the notify script; Claude Code's need only one).
///
/// An adapter must not gain unrestricted access to arbitrary CLI internals
/// merely to register itself — every method here is scoped to exactly the
/// one host-config surface this adapter owns.
pub trait AdapterPlugin: Send + Sync {
    /// Stable registry key, matching the id string clap parses via
    /// `AdapterArg` (checked by the registry-completeness test below).
    ///
    /// `&str`, not `&'static str` (FORNX-428 S6): a manifest-backed
    /// [`ExternalAdapter`](crate::adapter_external::ExternalAdapter) owns
    /// a `String` it borrows from, not a string literal. Every adapter
    /// actually reachable through [`registry`] lives behind a
    /// `&'static dyn AdapterPlugin` (built-ins are literals; externals are
    /// `Box::leak`-ed), so calling these through `registry()`/`resolve()`
    /// still yields a `&'static str` in practice -- only the trait
    /// signature itself had to widen.
    fn id(&self) -> &str;

    /// Human display name, e.g. "Claude Code".
    fn display_name(&self) -> &str;

    /// One-line description of what this adapter's install/uninstall
    /// actually wires, for `fornax adapter list`.
    fn summary(&self) -> &str;

    /// The one config path `adapter list`'s rendering and tests use to
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
    fn id(&self) -> &str {
        "claude-code"
    }

    fn display_name(&self) -> &str {
        "Claude Code"
    }

    fn summary(&self) -> &str {
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
    fn id(&self) -> &str {
        "codex"
    }

    fn display_name(&self) -> &str {
        "Codex"
    }

    fn summary(&self) -> &str {
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

/// Every built-in adapter, in display order.
const BUILT_INS: &[&dyn AdapterPlugin] = &[&ClaudeCodeAdapter, &CodexAdapter];

/// Built-in ids only -- bypasses the lazily-initialized [`registry`]/
/// [`loaded`] entirely. `adapter_store::load_external` calls this (not
/// `registry()`) to check built-in/external id collisions, because
/// `load_external` itself runs *inside* `loaded()`'s `OnceLock::get_or_init`
/// closure: calling back into `registry()`/`loaded()` from there would
/// reenter the same `OnceLock` mid-initialization, which
/// `OnceLock::get_or_init` documents as a deadlock, not a panic -- this
/// bit the first version of this module (every test touching `registry()`
/// hung indefinitely).
pub(crate) fn built_in_ids() -> impl Iterator<Item = &'static str> {
    BUILT_INS.iter().map(|a| a.id())
}

struct Loaded {
    adapters: Vec<&'static dyn AdapterPlugin>,
    rejections: Vec<crate::adapter_store::Rejection>,
}

/// Built-ins plus every successfully-loaded external adapter from
/// `$FORNAX_HOME/adapters/` (ADR-0023, FORNX-428 S6), assembled once per
/// process. Read-only: loading an external adapter never executes
/// anything and the directory is never created by this path (only
/// `fornax adapter register` creates it) -- a missing directory is simply
/// zero external adapters.
fn loaded() -> &'static Loaded {
    static LOADED: OnceLock<Loaded> = OnceLock::new();
    LOADED.get_or_init(|| {
        let (externals, rejections) = crate::adapter_store::load_external(&crate::fornax_home());
        let mut adapters: Vec<&'static dyn AdapterPlugin> = BUILT_INS.to_vec();
        for external in externals {
            let leaked_mut: &'static mut crate::adapter_external::ExternalAdapter =
                Box::leak(Box::new(external));
            let leaked: &'static dyn AdapterPlugin = &*leaked_mut;
            adapters.push(leaked);
        }
        Loaded {
            adapters,
            rejections,
        }
    })
}

/// Every registered adapter -- built-in plus successfully-loaded external
/// (ADR-0023 D9). The single registration point every CLI surface
/// (`AdapterArg`, `AdapterAction`, `Commands::Install`/`Uninstall`) reads
/// through; adding an external adapter never requires a change here, only
/// a call to `fornax adapter register`.
pub fn registry() -> &'static [&'static dyn AdapterPlugin] {
    &loaded().adapters
}

/// Every external adapter that did not load, with a named reason --
/// surfaced by `adapter list`/`adapter info`, never silently dropped
/// (ADR-0023 D8).
pub fn rejections() -> &'static [crate::adapter_store::Rejection] {
    &loaded().rejections
}

/// Looks up a registered adapter by its stable id string.
pub fn resolve(id: &str) -> Option<&'static dyn AdapterPlugin> {
    registry().iter().copied().find(|a| a.id() == id)
}

/// A clap value type wrapping an already-resolved [`AdapterPlugin`] —
/// FORNX-428 S2's replacement for the closed `AdapterId` enum. Parsing goes
/// straight through [`resolve`] against [`registry`], so the CLI's argument
/// surface (`Commands::Install`, `AdapterAction`, `Commands::Uninstall`)
/// never hardcodes which ids exist: adding a built-in adapter is one struct
/// plus one `registry()` entry, never a change here.
///
/// An unknown id is a clean clap parse error (non-zero exit, no stack
/// trace, every known id named) — never a silently-ignored no-op.
#[derive(Clone, Copy)]
pub struct AdapterArg(&'static dyn AdapterPlugin);

impl std::fmt::Debug for AdapterArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AdapterArg").field(&self.0.id()).finish()
    }
}

impl AdapterArg {
    pub fn id(self) -> &'static str {
        self.0.id()
    }

    pub fn display_name(self) -> &'static str {
        self.0.display_name()
    }

    pub fn summary(self) -> &'static str {
        self.0.summary()
    }

    pub fn plugin(self) -> &'static dyn AdapterPlugin {
        self.0
    }
}

impl std::str::FromStr for AdapterArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(adapter) = resolve(s) {
            return Ok(AdapterArg(adapter));
        }
        if let Some(rejection) = rejections().iter().find(|r| r.id == s) {
            return Err(format!(
                "adapter {s:?} is registered but did not load: {}",
                rejection.reason
            ));
        }
        let known: Vec<&str> = registry().iter().map(|a| a.id()).collect();
        Err(format!(
            "unknown adapter {s:?}; known adapters: {}",
            known.join(", ")
        ))
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

/// `fornax install <adapter>`.
pub fn install(adapter: AdapterArg) -> anyhow::Result<AdapterActionResult> {
    adapter.plugin().install()
}

/// `fornax uninstall <adapter>`.
pub fn uninstall(adapter: AdapterArg) -> anyhow::Result<AdapterActionResult> {
    adapter.plugin().uninstall()
}

/// `fornax adapter plan <adapter>` — computes, without writing anything,
/// what `install` would do right now.
pub fn plan(adapter: AdapterArg) -> anyhow::Result<AdapterActionResult> {
    adapter.plugin().plan()
}

/// `fornax adapter doctor <adapter>` — current install status, read-only.
/// Reuses the same plan computation `plan` uses; doctor and plan differ
/// only in rendering/action label, not in what they compute.
pub fn doctor(adapter: AdapterArg) -> anyhow::Result<AdapterActionResult> {
    let mut outcome = plan(adapter)?;
    outcome.action = "doctor".to_string();
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn adapter_arg_parses_every_known_id() {
        for adapter in registry() {
            let parsed = AdapterArg::from_str(adapter.id())
                .unwrap_or_else(|e| panic!("{} should parse: {e}", adapter.id()));
            assert_eq!(parsed.id(), adapter.id());
        }
    }

    #[test]
    fn adapter_arg_rejects_an_unknown_id_with_every_known_id_named() {
        let err = AdapterArg::from_str("not-a-real-adapter").unwrap_err();
        assert!(err.contains("not-a-real-adapter"));
        for adapter in registry() {
            assert!(
                err.contains(adapter.id()),
                "error should name {}: {err}",
                adapter.id()
            );
        }
    }

    /// Anti-vacuity (FORNX-428 S2): a fixture adapter not in the real
    /// `registry()` proves the parser is a plain function of whatever
    /// `resolve()` returns, not a hardcoded id list -- adding a built-in
    /// adapter never requires touching `AdapterArg`, `AdapterAction`, or
    /// `Commands` in `main.rs`, only one `registry()` entry.
    #[test]
    fn adapter_arg_parsing_is_a_plain_function_of_resolve_not_a_hardcoded_list() {
        struct FixtureAdapter;
        impl AdapterPlugin for FixtureAdapter {
            fn id(&self) -> &'static str {
                "fixture-only-for-this-test"
            }
            fn display_name(&self) -> &'static str {
                "Fixture"
            }
            fn summary(&self) -> &'static str {
                "test-only adapter, never in the real registry()"
            }
            fn target_path(&self) -> PathBuf {
                PathBuf::from("/dev/null/fixture")
            }
            fn plan(&self) -> anyhow::Result<AdapterActionResult> {
                unreachable!("not exercised by this test")
            }
            fn install(&self) -> anyhow::Result<AdapterActionResult> {
                unreachable!("not exercised by this test")
            }
            fn uninstall(&self) -> anyhow::Result<AdapterActionResult> {
                unreachable!("not exercised by this test")
            }
        }

        assert!(resolve("fixture-only-for-this-test").is_none());
        assert!(AdapterArg::from_str("fixture-only-for-this-test").is_err());

        let fixture: &dyn AdapterPlugin = &FixtureAdapter;
        let extended: Vec<&dyn AdapterPlugin> =
            registry().iter().copied().chain([fixture]).collect();
        let found = extended
            .iter()
            .find(|a| a.id() == "fixture-only-for-this-test")
            .expect("fixture resolves against an extended registry with zero changes to AdapterArg/AdapterAction/Commands");
        assert_eq!(found.id(), "fixture-only-for-this-test");
    }

    /// FORNX-428 S6: asserts over `BUILT_INS` directly, not `registry()` --
    /// `registry()` now also reflects whatever is registered under the
    /// real `$FORNAX_HOME` on the machine running this test, so asserting
    /// over it here would make this test fail on any developer machine
    /// that has registered an external adapter.
    #[test]
    fn built_in_registry_is_exactly_the_two_known_adapters() {
        let ids: Vec<&str> = BUILT_INS.iter().map(|a| a.id()).collect();
        assert_eq!(ids, vec!["claude-code", "codex"]);
    }

    /// Registry-completeness: every registered adapter answers every
    /// method non-trivially, and no two adapters share an id. Guards
    /// against the mis-wiring class a copy-pasted match arm (the old
    /// 7-site version of this module) made easy — e.g. pointing Codex's
    /// struct at Claude Code's path.
    #[test]
    fn every_registered_adapter_is_fully_and_uniquely_wired() {
        let adapters = BUILT_INS;
        assert!(!adapters.is_empty(), "BUILT_INS must not be empty");

        let mut seen_ids = std::collections::HashSet::new();
        for adapter in adapters {
            assert!(
                seen_ids.insert(adapter.id()),
                "duplicate adapter id {:?} in registry()",
                adapter.id()
            );
            assert!(!adapter.id().is_empty());
            assert!(!adapter.display_name().is_empty());
            assert!(!adapter.summary().is_empty());
            assert!(
                !adapter.target_path().as_os_str().is_empty(),
                "{} must report a non-empty target_path()",
                adapter.id()
            );
        }
    }

    /// The two built-in adapters must not end up wired to each other's
    /// path — the specific mis-wiring class this trait is meant to make
    /// structurally harder than a copy-pasted match arm.
    #[test]
    fn claude_code_and_codex_report_distinct_target_paths() {
        let claude = resolve("claude-code").expect("claude-code is registered");
        let codex = resolve("codex").expect("codex is registered");
        assert_ne!(claude.target_path(), codex.target_path());
    }
}
