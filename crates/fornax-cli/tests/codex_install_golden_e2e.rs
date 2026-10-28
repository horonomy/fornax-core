//! FORNX-450: pins `fornax install codex`'s real `hooks.json` output
//! against a committed golden fixture.
//!
//! `exec/fornax-host-trust-exec`'s identity predicate is a deliberate
//! duplicate (not an import — that crate must depend on no `fornax-*`
//! crate) of `codex_hooks.rs`'s own Fornax-handler predicate. This test is
//! the other half of that cross-check: it proves the golden fixture
//! `tests/fixtures/codex-hooks-install-golden.json` — which
//! `fornax-host-trust-exec`'s own tests read by relative path — still
//! matches what `fornax install codex` genuinely writes today. If this
//! test ever fails, the golden fixture is stale, not necessarily the
//! install path; regenerate it from a real run before assuming either
//! side is wrong.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

struct Scratch {
    home: PathBuf,
    fornax_home: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("fornax-codex-golden-{}", uuid::Uuid::new_v4()));
        let home = root.join("home");
        let fornax_home = root.join("fornax");
        fs::create_dir_all(&home).unwrap();
        Self { home, fornax_home }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(fornax_bin())
            .args(args)
            .env("HOME", &self.home)
            .env_remove("CODEX_HOME")
            .env("FORNAX_HOME", &self.fornax_home)
            .output()
            .unwrap()
    }
}

#[test]
fn real_install_output_matches_golden_fixture() {
    let scratch = Scratch::new();
    let output = scratch.run(&["install", "codex"]);
    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let hooks_json_path = scratch.home.join(".codex").join("hooks.json");
    let actual_raw =
        fs::read_to_string(&hooks_json_path).expect("hooks.json must exist after install");
    let actual: Value = serde_json::from_str(&actual_raw).unwrap();

    let golden_raw = include_str!("fixtures/codex-hooks-install-golden.json");
    let golden: Value = serde_json::from_str(golden_raw).unwrap();

    assert_eq!(
        actual, golden,
        "fornax install codex's real hooks.json output no longer matches \
         tests/fixtures/codex-hooks-install-golden.json -- regenerate the \
         golden fixture from a real run (see this test's module doc) and \
         re-check exec/fornax-host-trust-exec's identity predicate against \
         the new shape before updating it"
    );
}
