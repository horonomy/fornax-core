//! Public-binary acceptance tests for passive adapter registration inspection.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

struct Scratch {
    root: PathBuf,
    home: PathBuf,
    fornax_home: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fornax-adapter-inspection-{}",
            uuid::Uuid::new_v4()
        ));
        let home = root.join("home");
        let fornax_home = root.join("fornax");
        fs::create_dir_all(&home).unwrap();
        Self {
            root,
            home,
            fornax_home,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(fornax_bin())
            .args(args)
            .env("HOME", &self.home)
            .env("FORNAX_HOME", &self.fornax_home)
            .output()
            .unwrap()
    }

    #[cfg(unix)]
    fn run_with_timeout(&self, args: &[&str], timeout: Duration) -> Output {
        let mut child = Command::new(fornax_bin())
            .args(args)
            .env("HOME", &self.home)
            .env("FORNAX_HOME", &self.fornax_home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        loop {
            match child.try_wait().unwrap() {
                Some(_) => return child.wait_with_output().unwrap(),
                None if started.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                None => {
                    child.kill().ok();
                    let output = child.wait_with_output().unwrap();
                    panic!(
                        "fornax {:?} did not exit within {:?}; stderr: {}",
                        args,
                        timeout,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).ok();
    }
}

fn write_manifest(path: &Path, id: &str) {
    let body = serde_json::json!({
        "schema_version": 1,
        "id": id,
        "display_name": "Inspection fixture",
        "summary": "A synthetic data-only adapter for CLI inspection",
        "min_fornax_version": "0.0.1",
        "provenance": "https://example.com/inspection-fixture",
        "capabilities": ["plan", "install", "uninstall"],
        "target": {"format": "json", "path": "~/.not-created/settings.json"},
        "operations": [{
            "kind": "ensure_marked_array_element",
            "pointer": "/hooks/PostToolUse",
            "marker_key": "command",
            "marker_value": "fornax-inspection-fixture",
            "element": {"type": "command", "command": "fornax-inspection-fixture"}
        }]
    });
    fs::write(path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn register(scratch: &Scratch, id: &str) -> (PathBuf, Value) {
    let source = scratch.root.join("source.json");
    write_manifest(&source, id);
    let source_arg = source.to_str().unwrap();
    let review = scratch.run(&["adapter", "register", "--manifest", source_arg, "--json"]);
    assert!(review.status.success(), "{}", stdout(&review));
    let reviewed: Value = serde_json::from_slice(&review.stdout).unwrap();
    let digest = reviewed["digest"].as_str().unwrap();
    let confirmed = scratch.run(&[
        "adapter",
        "register",
        "--manifest",
        source_arg,
        "--confirm-digest",
        digest,
    ]);
    assert!(confirmed.status.success(), "{}", stdout(&confirmed));
    (source, reviewed)
}

fn load_index(scratch: &Scratch) -> (PathBuf, Value) {
    let path = scratch.fornax_home.join("adapters/registry.json");
    let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    (path, value)
}

fn save_index(path: &Path, index: &Value) {
    fs::write(path, serde_json::to_vec_pretty(index).unwrap()).unwrap();
}

fn synthetic_entry(id: &str, manifest_file: &str) -> Value {
    serde_json::json!({
        "id": id,
        "manifest_file": manifest_file,
        "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "source_path": "synthetic-source-only",
        "registered_at": "2026-10-08T00:00:00Z",
        "enabled": true
    })
}

fn test_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    let mut digest = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        write!(&mut digest, "{byte:02x}").unwrap();
    }
    digest
}

#[cfg(unix)]
fn create_fifo(path: &Path) {
    assert!(Command::new("mkfifo").arg(path).status().unwrap().success());
}

#[test]
fn disabled_registration_remains_inspectable_from_public_binary() {
    let scratch = Scratch::new();
    let id = "inspection-fixture";
    let (source, reviewed) = register(&scratch, id);
    let disabled = scratch.run(&["adapter", "disable", id]);
    assert!(disabled.status.success(), "{}", stdout(&disabled));
    fs::remove_file(&source).unwrap();
    let registry_path = scratch.fornax_home.join("adapters/registry.json");
    let owned_manifest_path = scratch
        .fornax_home
        .join("adapters/inspection-fixture.manifest.json");
    let registry_before = fs::read(&registry_path).unwrap();
    let owned_before = fs::read(&owned_manifest_path).unwrap();

    let inspected = scratch.run(&["adapter", "info", id]);
    assert!(
        inspected.status.success(),
        "stdout: {}\nstderr: {}",
        stdout(&inspected),
        String::from_utf8_lossy(&inspected.stderr)
    );
    assert!(stdout(&inspected).contains("enabled: false"));
    assert!(stdout(&inspected).contains("registration state: disabled"));

    let info = scratch.run(&["adapter", "info", id, "--json"]);
    let inspect = scratch.run(&["adapter", "inspect", id, "--json"]);
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let info_json: Value = serde_json::from_slice(&info.stdout).unwrap();
    let inspect_json: Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(info_json, inspect_json, "aliases must use one projection");
    assert_eq!(info_json["schema_version"], 1);
    assert_eq!(info_json["operation"], "inspect");
    assert_eq!(info_json["adapter_id"], id);
    assert_eq!(info_json["outcome"], "success");
    assert_eq!(info_json["verification_state"], "unverified");
    assert_eq!(info_json["result"]["origin"], "external_data_only");
    assert_eq!(info_json["result"]["registration"]["id"], id);
    assert_eq!(info_json["result"]["registration"]["enabled"], false);
    assert_eq!(
        info_json["result"]["registration"]["manifest_digest"],
        reviewed["digest"]
    );
    assert_eq!(
        info_json["result"]["registration"]["source_path"],
        source.display().to_string()
    );
    assert_eq!(
        info_json["result"]["registration"]["registry_schema_version"],
        0
    );
    assert!(info_json["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "legacy_registry_schema_version_zero"));
    assert_eq!(info_json["result"]["host"]["installation"], "unknown");
    assert_eq!(info_json["result"]["host"]["trust"], "unknown");
    assert_eq!(
        info_json["result"]["host"]["native_observation"],
        "not_observed"
    );
    assert_eq!(
        info_json["result"]["executable_driver"]["code_trust"],
        "not_applicable_data_only_descriptor"
    );
    assert_eq!(fs::read(registry_path).unwrap(), registry_before);
    assert_eq!(fs::read(owned_manifest_path).unwrap(), owned_before);
    assert!(!source.exists());
    assert!(!scratch.home.join(".not-created/settings.json").exists());

    let enabled = scratch.run(&["adapter", "enable", id]);
    assert!(enabled.status.success(), "{}", stdout(&enabled));
    let reenabled = scratch.run(&["adapter", "inspect", id, "--json"]);
    assert!(
        reenabled.status.success(),
        "{}",
        String::from_utf8_lossy(&reenabled.stderr)
    );
    let reenabled_json: Value = serde_json::from_slice(&reenabled.stdout).unwrap();
    assert_eq!(reenabled_json["result"]["load_state"], "enabled_valid");
    assert_eq!(
        reenabled_json["result"]["configuration_dispatch_registration"],
        "enabled"
    );
    assert_eq!(reenabled_json["result"]["registration"]["enabled"], true);
}

#[test]
fn digit_leading_config_id_is_preserved_without_host_spi_adapter_id() {
    let scratch = Scratch::new();
    let id = "0future-agent";
    let (source, _) = register(&scratch, id);
    fs::remove_file(source).unwrap();
    let info = scratch.run(&["adapter", "info", id, "--json"]);
    let inspect = scratch.run(&["adapter", "inspect", id, "--json"]);
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let info_json: Value = serde_json::from_slice(&info.stdout).unwrap();
    let inspect_json: Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(info_json, inspect_json);
    assert_eq!(info_json["adapter_id"], Value::Null);
    assert_eq!(info_json["result"]["registration"]["id"], id);
    assert!(info_json["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "config_id_outside_host_spi_namespace"));
}

#[test]
fn schema_one_record_is_inspected_without_rewrite() {
    let scratch = Scratch::new();
    let id = "schema-one-fixture";
    let (source, _) = register(&scratch, id);
    fs::remove_file(source).unwrap();
    let (registry_path, mut index) = load_index(&scratch);
    index["schema_version"] = serde_json::json!(1);
    save_index(&registry_path, &index);
    let before = fs::read(&registry_path).unwrap();

    let inspected = scratch.run(&["adapter", "inspect", id, "--json"]);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(
        envelope["result"]["registration"]["registry_schema_version"],
        1
    );
    assert_eq!(envelope["result"]["load_state"], "enabled_valid");
    assert!(envelope["reasons"].as_array().unwrap().is_empty());
    assert_eq!(fs::read(registry_path).unwrap(), before);
}

#[test]
fn newer_registry_version_fails_without_echoing_or_rewriting_payload() {
    let scratch = Scratch::new();
    let id = "future-version-fixture";
    let (source, _) = register(&scratch, id);
    fs::remove_file(source).unwrap();
    let (registry_path, mut index) = load_index(&scratch);
    index["schema_version"] = serde_json::json!(99);
    save_index(&registry_path, &index);
    let before = fs::read(&registry_path).unwrap();

    let inspected = scratch.run(&["adapter", "info", id, "--json"]);
    assert!(!inspected.status.success());
    let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(envelope["outcome"], "failed");
    assert_eq!(
        envelope["reasons"],
        serde_json::json!(["registry_index_unsupported_version"])
    );
    assert!(!stdout(&inspected).contains("untrusted-source"));
    assert_eq!(fs::read(registry_path).unwrap(), before);
}

#[test]
fn malformed_and_oversized_indexes_fail_with_stable_codes() {
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (br#"{"schema_version":0,"entries":[}"#.to_vec(), "registry_index_malformed"),
        (br#"{"schema_version":0,"entries":[],"future_field":"hidden"}"#.to_vec(), "registry_index_malformed"),
        (br#"{"entries":[]}"#.to_vec(), "registry_index_malformed"),
        (br#"{"schema_version":0}"#.to_vec(), "registry_index_malformed"),
        (br#"{"schema_version":99,"entries":[]}"#.to_vec(), "registry_index_unsupported_version"),
        (
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "entries": (0..65).map(|_| serde_json::json!({
                    "id": "fixture-adapter",
                    "manifest_file": "fixture-adapter.manifest.json",
                    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "source_path": "untrusted-source",
                    "registered_at": "now",
                    "enabled": true
                })).collect::<Vec<_>>()
            }))
            .unwrap(),
            "registry_index_too_many_entries",
        ),
        (vec![b' '; 1024 * 1024 + 1], "registry_index_oversized"),
    ];

    for (bytes, expected_reason) in cases {
        let scratch = Scratch::new();
        let registry = scratch.fornax_home.join("adapters/registry.json");
        fs::create_dir_all(registry.parent().unwrap()).unwrap();
        fs::write(&registry, &bytes).unwrap();
        let before = fs::read(&registry).unwrap();
        let inspected = scratch.run(&["adapter", "info", "inspection-fixture", "--json"]);
        assert!(!inspected.status.success());
        let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
        assert_eq!(envelope["reasons"], serde_json::json!([expected_reason]));
        assert_eq!(fs::read(registry).unwrap(), before);
        assert!(!stdout(&inspected).contains("untrusted-source"));
    }
}

#[test]
fn escaped_owned_filename_is_rejected_without_path_traversal() {
    let scratch = Scratch::new();
    let adapters = scratch.fornax_home.join("adapters");
    fs::create_dir_all(&adapters).unwrap();
    let index = serde_json::json!({
        "schema_version": 1,
        "entries": [{
            "id": "path-fixture",
            "manifest_file": "../../outside.json",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "source_path": "untrusted-source",
            "registered_at": "now",
            "enabled": true
        }]
    });
    save_index(&adapters.join("registry.json"), &index);
    let inspected = scratch.run(&["adapter", "info", "path-fixture", "--json"]);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(envelope["result"]["load_state"], "rejected");
    assert_eq!(
        envelope["reasons"],
        serde_json::json!(["invalid_owned_filename"])
    );
}

#[test]
fn duplicate_selected_id_fails_instead_of_choosing_a_registration() {
    let scratch = Scratch::new();
    let id = "duplicate-fixture";
    let (source, _) = register(&scratch, id);
    fs::remove_file(source).unwrap();
    let (registry_path, mut index) = load_index(&scratch);
    let duplicate = index["entries"][0].clone();
    index["entries"].as_array_mut().unwrap().push(duplicate);
    save_index(&registry_path, &index);

    let inspected = scratch.run(&["adapter", "info", id, "--json"]);
    assert!(!inspected.status.success());
    let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(
        envelope["reasons"],
        serde_json::json!(["duplicate_registration_id"])
    );
}

#[test]
fn missing_owned_copy_and_digest_pinned_malformed_copy_remain_explainable() {
    let missing_scratch = Scratch::new();
    let id = "missing-copy-fixture";
    let (source, _) = register(&missing_scratch, id);
    fs::remove_file(source).unwrap();
    fs::remove_file(
        missing_scratch
            .fornax_home
            .join("adapters/missing-copy-fixture.manifest.json"),
    )
    .unwrap();

    let missing = missing_scratch.run(&["adapter", "inspect", id, "--json"]);
    assert!(
        missing.status.success(),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );
    let missing_json: Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(missing_json["outcome"], "success");
    assert_eq!(missing_json["result"]["load_state"], "rejected");
    assert!(missing_json["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "owned_manifest_unavailable"));

    let malformed_scratch = Scratch::new();
    let id = "malformed-copy-fixture";
    let (source, _) = register(&malformed_scratch, id);
    fs::remove_file(source).unwrap();
    let malformed = b"{ malformed owned manifest sentinel";
    let owned = malformed_scratch
        .fornax_home
        .join("adapters/malformed-copy-fixture.manifest.json");
    fs::write(&owned, malformed).unwrap();
    let (registry_path, mut index) = load_index(&malformed_scratch);
    index["entries"][0]["digest"] = test_digest(malformed).into();
    save_index(&registry_path, &index);

    let inspected = malformed_scratch.run(&["adapter", "info", id, "--json"]);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(envelope["outcome"], "success");
    assert_eq!(envelope["verification_state"], "failed");
    assert_eq!(envelope["result"]["load_state"], "rejected");
    assert!(envelope["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "malformed_manifest"));
    assert!(!stdout(&inspected).contains("owned manifest sentinel"));
}

#[test]
fn an_unregistered_manifest_file_alone_does_not_create_a_registration() {
    let scratch = Scratch::new();
    let adapters = scratch.fornax_home.join("adapters");
    fs::create_dir_all(&adapters).unwrap();
    write_manifest(&adapters.join("orphaned-file.json"), "orphaned-file");

    let inspected = scratch.run(&["adapter", "info", "orphaned-file", "--json"]);
    assert!(!inspected.status.success());
    let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(
        envelope["reasons"],
        serde_json::json!(["unknown_adapter_id"])
    );
}

#[test]
fn long_invalid_manifest_filename_is_rejected_with_bounded_json() {
    let scratch = Scratch::new();
    let adapters = scratch.fornax_home.join("adapters");
    fs::create_dir_all(&adapters).unwrap();
    let long_name = format!("{}.CANARY", "x".repeat(600_000));
    let index = serde_json::json!({
        "schema_version": 1,
        "entries": [synthetic_entry("long-name-fixture", &long_name)]
    });
    save_index(&adapters.join("registry.json"), &index);

    let inspected = scratch.run(&["adapter", "inspect", "long-name-fixture", "--json"]);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let output = stdout(&inspected);
    assert!(
        output.len() < 8 * 1024,
        "JSON inspection output was {} bytes",
        output.len()
    );
    assert!(!output.contains("CANARY"));
    let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(envelope["result"]["load_state"], "rejected");
    assert_eq!(
        envelope["result"]["registration"]["owned_manifest_file"],
        Value::Null
    );
}

#[test]
fn human_source_path_escapes_control_characters_and_bounds_length() {
    let scratch = Scratch::new();
    let id = "source-display-fixture";
    let (source, _) = register(&scratch, id);
    let (registry_path, mut index) = load_index(&scratch);
    index["entries"][0]["source_path"] = format!("source\ninjected{}", "x".repeat(800)).into();
    save_index(&registry_path, &index);
    fs::remove_file(source).unwrap();

    let inspected = scratch.run(&["adapter", "info", id]);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let output = stdout(&inspected);
    assert!(output.contains(r"source\u{a}injected"));
    assert!(!output.contains("\ninjected"));
    assert!(output.len() < 2048);
}

#[test]
fn known_digest_mismatch_is_explainable_without_echoing_manifest_bytes() {
    let scratch = Scratch::new();
    let id = "integrity-fixture";
    let (source, _) = register(&scratch, id);
    fs::remove_file(source).unwrap();
    let owned = scratch
        .fornax_home
        .join("adapters/integrity-fixture.manifest.json");
    fs::write(&owned, "private fixture payload").unwrap();

    let inspected = scratch.run(&["adapter", "info", id, "--json"]);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(envelope["outcome"], "success");
    assert_eq!(envelope["verification_state"], "failed");
    assert_eq!(envelope["result"]["load_state"], "rejected");
    assert!(envelope["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "digest_mismatch"));
    assert!(!stdout(&inspected).contains("private fixture payload"));
}

#[cfg(unix)]
#[test]
fn owned_manifest_symlink_is_rejected_without_reading_its_target() {
    use std::os::unix::fs::symlink;

    let scratch = Scratch::new();
    let id = "symlink-fixture";
    let (source, _) = register(&scratch, id);
    fs::remove_file(source).unwrap();
    let outside = scratch.root.join("outside.json");
    fs::write(&outside, "outside sentinel").unwrap();
    let owned = scratch
        .fornax_home
        .join("adapters/symlink-fixture.manifest.json");
    fs::remove_file(&owned).unwrap();
    symlink(&outside, &owned).unwrap();

    let inspected = scratch.run(&["adapter", "inspect", id, "--json"]);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let envelope: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(envelope["result"]["load_state"], "rejected");
    assert!(envelope["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "invalid_owned_file_type"));
    assert!(!stdout(&inspected).contains("outside sentinel"));
}

#[test]
fn builtin_aliases_emit_the_same_honest_inspection_without_creating_state() {
    let scratch = Scratch::new();
    let info = scratch.run(&["adapter", "info", "claude-code", "--json"]);
    let inspect = scratch.run(&["adapter", "inspect", "claude-code", "--json"]);
    assert!(info.status.success());
    assert!(inspect.status.success());
    let info_json: Value = serde_json::from_slice(&info.stdout).unwrap();
    let inspect_json: Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(info_json, inspect_json);
    assert_eq!(info_json["result"]["origin"], "builtin");
    assert_eq!(info_json["result"]["external_registration"], Value::Null);
    assert_eq!(info_json["verification_state"], "not_applicable");
    assert!(info_json["result"]["adapter"]["target"]["path_truncated"].is_boolean());
    assert!(!scratch.fornax_home.exists());
}

#[cfg(unix)]
#[test]
fn fifo_registry_and_owned_copy_refuse_without_blocking() {
    let index_scratch = Scratch::new();
    // Cold macOS loader validation can delay a newly linked image before
    // any Rust code runs. Prove this same binary can execute before timing
    // file refusal; the two-second blocking guard remains unchanged.
    let positive = index_scratch.run(&["--help"]);
    assert!(positive.status.success());
    assert!(stdout(&positive).contains("Usage:"));
    let adapters = index_scratch.fornax_home.join("adapters");
    fs::create_dir_all(&adapters).unwrap();
    create_fifo(&adapters.join("registry.json"));
    let index_result = index_scratch.run_with_timeout(
        &["adapter", "info", "fifo-fixture", "--json"],
        Duration::from_secs(2),
    );
    assert!(!index_result.status.success());
    let index_json: Value = serde_json::from_slice(&index_result.stdout).unwrap();
    assert_eq!(
        index_json["reasons"],
        serde_json::json!(["registry_index_unreadable"])
    );

    let owned_scratch = Scratch::new();
    let adapters = owned_scratch.fornax_home.join("adapters");
    fs::create_dir_all(&adapters).unwrap();
    let index = serde_json::json!({
        "schema_version": 1,
        "entries": [synthetic_entry("fifo-fixture", "fifo-fixture.manifest.json")]
    });
    save_index(&adapters.join("registry.json"), &index);
    create_fifo(&adapters.join("fifo-fixture.manifest.json"));
    let owned_result = owned_scratch.run_with_timeout(
        &["adapter", "inspect", "fifo-fixture", "--json"],
        Duration::from_secs(2),
    );
    assert!(
        owned_result.status.success(),
        "{}",
        String::from_utf8_lossy(&owned_result.stderr)
    );
    let owned_json: Value = serde_json::from_slice(&owned_result.stdout).unwrap();
    assert_eq!(owned_json["result"]["load_state"], "rejected");
    assert!(owned_json["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "invalid_owned_file_type"));
}

#[test]
fn missing_id_json_fails_with_a_bounded_reason_and_help_never_reads_home() {
    let scratch = Scratch::new();
    let missing = scratch.run(&["adapter", "info", "missing-adapter", "--json"]);
    assert!(!missing.status.success());
    let envelope: Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(envelope["outcome"], "failed");
    assert_eq!(
        envelope["reasons"],
        serde_json::json!(["unknown_adapter_id"])
    );
    assert!(!scratch.fornax_home.exists());

    for args in [
        &["adapter", "info", "missing-adapter", "--help"][..],
        &["adapter", "inspect", "missing-adapter", "--help"][..],
    ] {
        let help = scratch.run(args);
        assert!(
            help.status.success(),
            "{}",
            String::from_utf8_lossy(&help.stderr)
        );
        assert!(stdout(&help).to_lowercase().contains("usage"));
        assert!(!scratch.fornax_home.exists());
    }
}
