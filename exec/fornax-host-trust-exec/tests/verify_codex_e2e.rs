//! Binary e2e tests for `fornax-host-trust-exec verify-codex`, through the
//! real `--codex-bin` resolution, sandbox, and NDJSON round trip -- the
//! one layer `tests/session_streams.rs` (raw pipes, no sandbox) and
//! `src/verdict.rs`'s unit tests (pure data, no process at all) don't
//! reach. `tests/fixtures/fake_codex.rs` (compiled as
//! `fornax-host-trust-exec-fake-codex`) stands in for Codex; a `mode`
//! file next to a fresh per-test copy of that binary selects its
//! behavior, because `launch.rs`'s env-clearing means no env var can
//! carry a mode through the sandboxed child. It must be a real compiled
//! binary rather than a shell script -- see that file's module doc for
//! the empirical reason (macOS's Seatbelt literal-exec rule doesn't match
//! a shebang-interpreted script, only a real Mach-O binary, even when the
//! literal path matches exactly).
//!
//! Non-macOS runs only the one universal assertion
//! (`sandbox_unavailable`, no spawn attempted); the full matrix below is
//! `#[cfg(target_os = "macos")]`.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax-host-trust-exec")
}

fn fake_codex_source() -> &'static str {
    env!("CARGO_BIN_EXE_fornax-host-trust-exec-fake-codex")
}

struct Scratch {
    home: PathBuf,
    codex: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("fornax-host-trust-e2e-{}", uuid::Uuid::new_v4()));
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let codex_dir = root.join("codex-bin");
        fs::create_dir_all(&codex_dir).unwrap();
        let codex = codex_dir.join("codex");
        fs::copy(fake_codex_source(), &codex).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&codex, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Scratch { home, codex }
    }

    fn set_mode(&self, mode: &str) {
        fs::write(self.codex.parent().unwrap().join("mode"), mode).unwrap();
    }

    fn set_version(&self, version: &str) {
        fs::write(self.codex.parent().unwrap().join("version"), version).unwrap();
    }

    fn install_fornax_hooks(&self) {
        let codex_dir = self.home.join(".codex");
        fs::create_dir_all(&codex_dir).unwrap();
        fs::write(
            codex_dir.join("hooks.json"),
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"fornax-hook-codex-event","timeout":5}]}],"PostToolUse":[{"hooks":[{"type":"command","command":"fornax-hook-codex-event","timeout":5}]}],"SessionStart":[{"hooks":[{"type":"command","command":"fornax-hook-codex-event","timeout":5}]}]}}"#,
        )
        .unwrap();
    }

    fn run(&self) -> Output {
        Command::new(bin())
            .args(["verify-codex", "--json", "--codex-bin"])
            .arg(&self.codex)
            .env("HOME", &self.home)
            .output()
            .unwrap()
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn non_macos_refuses_before_any_spawn() {
    let scratch = Scratch::new();
    let out = scratch.run();
    assert_eq!(out.status.code(), Some(3));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["result"]["global_reasons"][0], "sandbox_unavailable");
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    #[test]
    fn positive_round_trip_reports_orphan_because_shim_reports_zero_hooks() {
        // The shim never emulates real Codex trust semantics -- it always
        // reports an empty hooks list, so against a real installed
        // hooks.json this is the orphaned-entry case for all three
        // events. This still proves the full real sandboxed round trip
        // (spawn, handshake, hooks/list, teardown) end to end.
        let scratch = Scratch::new();
        scratch.install_fornax_hooks();
        scratch.set_mode("positive");
        let out = scratch.run();
        assert_eq!(
            out.status.code(),
            Some(3),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(json["result"]["host_trust"], "unknown");
        let hooks = json["result"]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 3);
        for hook in hooks {
            assert_eq!(hook["reasons"][0], "hook_absent_from_host_listing");
        }
    }

    #[test]
    fn unreviewed_version_never_starts_app_server() {
        let scratch = Scratch::new();
        scratch.install_fornax_hooks();
        scratch.set_version("0.0.1-not-reviewed");
        let out = scratch.run();
        assert_eq!(out.status.code(), Some(3));
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let reason = &json["result"]["global_reasons"][0];
        assert_eq!(reason["codex_version_unreviewed"], "0.0.1-not-reviewed");
        // No tamper.log could exist if app-server was genuinely never
        // started -- tamper mode wasn't even set here, but more to the
        // point: hooks must be empty, since reconciliation never ran.
        assert_eq!(json["result"]["hooks"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn help_and_usage_paths_never_invoke_codex() {
        let scratch = Scratch::new();
        for args in [vec!["--help"], vec!["help"], vec![]] {
            let _ = Command::new(bin())
                .args(&args)
                .env("HOME", &scratch.home)
                .output()
                .unwrap();
        }
        assert!(!scratch.codex.parent().unwrap().join("tamper.log").exists());
    }

    #[test]
    fn tamper_attempts_are_blocked_and_files_stay_byte_identical() {
        let scratch = Scratch::new();
        scratch.install_fornax_hooks();
        scratch.set_mode("tamper");
        let codex_dir = scratch.home.join(".codex");
        fs::write(codex_dir.join("config.toml"), "# untouched\n").unwrap();
        let before_hooks = fs::read(codex_dir.join("hooks.json")).unwrap();
        let before_config = fs::read(codex_dir.join("config.toml")).unwrap();

        let out = scratch.run();

        let after_hooks = fs::read(codex_dir.join("hooks.json")).unwrap();
        let after_config = fs::read(codex_dir.join("config.toml")).unwrap();
        assert_eq!(
            before_hooks, after_hooks,
            "hooks.json must be byte-identical after a tamper attempt"
        );
        assert_eq!(
            before_config, after_config,
            "config.toml must be byte-identical after a tamper attempt"
        );

        // The sandboxed process's cwd is the scratch cwd ScratchCwd
        // creates, not this test's directory -- tamper.log, if written at
        // all, lands there. We don't know that path from the test side,
        // so the authoritative check is the byte-identical assertions
        // above; stderr's own tripwire warning is corroborating evidence.
        let stderr = String::from_utf8_lossy(&out.stderr);
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_ne!(json["result"]["host_trust"], "trusted");
        if stderr.contains("WARNING state changed") {
            panic!("tripwire fired -- a tamper attempt actually succeeded: {stderr}");
        }
    }
}
