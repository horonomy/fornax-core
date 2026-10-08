//! Public registration/inspection behavior; no host or adapter code is run.
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    state: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("fornax-host-descriptor-{}", uuid::Uuid::new_v4()));
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        Self {
            state: root.join("state"),
            root,
            home,
        }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fornax"))
            .args(args)
            .env("HOME", &self.home)
            .env("FORNAX_HOME", &self.state)
            .output()
            .unwrap()
    }
    fn source(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }
    fn confirm(&self, source: &Path) -> Value {
        let source = source.to_str().unwrap();
        let review = self.run(&["adapter", "register", "--manifest", source, "--json"]);
        assert!(review.status.success(), "{:?}", review);
        let review: Value = serde_json::from_slice(&review.stdout).unwrap();
        let digest = review["result"]["manifest_digest"].as_str().unwrap();
        let confirmed = self.run(&[
            "adapter",
            "register",
            "--manifest",
            source,
            "--confirm-digest",
            digest,
            "--json",
        ]);
        assert!(confirmed.status.success(), "{:?}", confirmed);
        serde_json::from_slice(&confirmed.stdout).unwrap()
    }
    fn index(&self) -> Vec<u8> {
        fs::read(self.state.join("adapters/registry.json")).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).ok();
    }
}

// Pinned shared47b manifest shape, with a dynamic id and a never-launched path.
fn descriptor(id: &str) -> Value {
    json!({"manifest_kind":"host-adapter","manifest_version":1,"adapter_id":id,"adapter_version":"1.2.0","protocol_versions":[1],"contract_version_range":{"minimum":1,"maximum":1},"roles":["LifecycleSource","IdentitySource"],"capabilities":["lifecycle.session","identity.agent","future.partial_capability"],"host_version_constraints":[{"provider":"synthetic_host","minimum":null,"maximum":null}],"configuration_schema":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"additionalProperties":false},"launch":{"executable":"/opt/horonom/never-launched-synthetic","argv":["--stdio-json"]},"runtime_files":[],"input_limits":{"max_bytes":1048576},"needs":{"environment":[],"read_paths":[],"write_paths":[]}})
}

#[test]
fn host_review_is_passive_and_discloses_storage_upgrade_and_missing_trust() {
    let f = Fixture::new();
    let source = f.source("descriptor.json", &descriptor("dynamic_fixture"));
    let out = f.run(&[
        "adapter",
        "register",
        "--manifest",
        source.to_str().unwrap(),
        "--json",
    ]);
    assert!(out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["operation"], "register");
    assert_eq!(body["outcome"], "refused");
    assert_eq!(body["result"]["registration"], "not_registered");
    assert_eq!(body["result"]["registry_upgrade_on_confirmation"], true);
    assert_eq!(body["result"]["implementation_trust"], "not_granted");
    assert!(!f.state.exists());
}

#[test]
fn confirmation_registers_dynamic_descriptor_disabled_without_installing_or_executing() {
    let f = Fixture::new();
    let source = f.source("descriptor.json", &descriptor("new_external_family"));
    let out = f.confirm(&source);
    assert_eq!(out["operation"], "register");
    assert_eq!(out["result"]["enabled"], false);
    let index: Value = serde_json::from_slice(&f.index()).unwrap();
    assert_eq!(index["schema_version"], 2);
    assert_eq!(index["registry_kind"], "fornax-adapter-registry-v2");
    assert_eq!(index["entries"][0]["kind"], "host-adapter-v1");
    assert_eq!(
        fs::read(&source).unwrap(),
        fs::read(
            f.state
                .join("adapters/new_external_family.host-adapter.json")
        )
        .unwrap()
    );
    assert!(!f.state.join("fornax.db").exists());
    assert!(!f.home.join(".codex").exists());
    assert!(!f.home.join(".claude").exists());
}

#[test]
fn future_only_declarations_are_inspectable_but_not_activated_or_configuration_drivers() {
    let f = Fixture::new();
    let mut manifest = descriptor("future_only");
    manifest["protocol_versions"] = json!([999]);
    manifest["contract_version_range"] = json!({"minimum":99,"maximum":99});
    let source = f.source("descriptor.json", &manifest);
    f.confirm(&source);
    let before = f.index();
    let info = f.run(&["adapter", "inspect", "future_only", "--json"]);
    assert!(info.status.success());
    let body: Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(
        body["result"]["compatibility"]["protocol_v1_declared"],
        false
    );
    assert_eq!(
        body["result"]["compatibility"]["contract_v1_declared"],
        false
    );
    assert_eq!(body["result"]["host"]["native_observation"], "not_observed");
    let enable = f.run(&["adapter", "enable", "future_only", "--json"]);
    assert!(!enable.status.success());
    let failure: Value = serde_json::from_slice(&enable.stdout).unwrap();
    assert_eq!(
        failure["reasons"],
        json!(["execution_boundary_unavailable"])
    );
    assert_eq!(f.index(), before);
    let plan = f.run(&["adapter", "plan", "future_only"]);
    assert!(!plan.status.success());
    assert!(String::from_utf8_lossy(&plan.stderr).contains("configuration_dispatch_unavailable"));
    assert_eq!(f.index(), before);
}

#[test]
fn list_and_inspect_use_retained_owned_copy_after_source_deletion() {
    let f = Fixture::new();
    let source = f.source("descriptor.json", &descriptor("retained_external"));
    f.confirm(&source);
    fs::remove_file(source).unwrap();
    let before = f.index();
    let list = f.run(&["adapter", "list", "--json"]);
    assert!(list.status.success());
    let body: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(body["operation"], "list");
    assert!(body["result"]["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["id"] == "retained_external" && entry["kind"] == "host-adapter-v1"));
    let info = f.run(&["adapter", "info", "retained_external", "--json"]);
    let inspect = f.run(&["adapter", "inspect", "retained_external", "--json"]);
    assert!(info.status.success() && inspect.status.success());
    assert_eq!(info.stdout, inspect.stdout);
    assert_eq!(f.index(), before);
}

#[test]
fn late_v1_protocol_declaration_is_not_lost_to_display_truncation() {
    let f = Fixture::new();
    let mut manifest = descriptor("many_versions");
    let mut protocols: Vec<u32> = (2..=32).collect();
    protocols.push(1);
    manifest["protocol_versions"] = json!(protocols);
    let source = f.source("descriptor.json", &manifest);
    f.confirm(&source);
    let out = f.run(&["adapter", "inspect", "many_versions", "--json"]);
    assert!(out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        body["result"]["compatibility"]["protocol_v1_declared"],
        true
    );
    assert_eq!(
        body["result"]["declared_manifest"]["protocol_versions"]
            .as_array()
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn large_exact_schema_numbers_remain_pinned_and_are_explicitly_omitted_from_projection() {
    let f = Fixture::new();
    let mut manifest = descriptor("exact_numbers");
    manifest["configuration_schema"]["properties"]["count"] = json!({"type":"integer","minimum":0});
    let bytes = serde_json::to_string(&manifest)
        .unwrap()
        .replace("\"minimum\":0", "\"minimum\":18446744073709551617");
    let source = f.root.join("descriptor.json");
    fs::write(&source, bytes.as_bytes()).unwrap();
    f.confirm(&source);
    let retained = fs::read(f.state.join("adapters/exact_numbers.host-adapter.json")).unwrap();
    assert_eq!(retained, bytes.as_bytes());
    let out = f.run(&["adapter", "inspect", "exact_numbers", "--json"]);
    assert!(out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(body["result"]["declared_manifest"]["configuration_schema"].is_null());
    assert_eq!(
        body["result"]["declared_manifest"]["projection"],
        "partial_configuration_schema_omitted"
    );
}

#[test]
fn unknown_manifest_marker_is_refused_without_creating_registry_state() {
    let f = Fixture::new();
    let mut manifest = descriptor("unknown_kind");
    manifest["manifest_kind"] = json!("unreviewed-plugin");
    let source = f.source("descriptor.json", &manifest);
    let out = f.run(&[
        "adapter",
        "register",
        "--manifest",
        source.to_str().unwrap(),
        "--json",
    ]);
    assert!(!out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["operation"], "register");
    assert_eq!(body["outcome"], "refused");
    assert!(!f.state.exists());
}

#[test]
fn host_review_escapes_source_filename_control_characters() {
    let f = Fixture::new();
    let source = f.source("descriptor\n\x1b.json", &descriptor("escaped_source"));
    let out = f.run(&[
        "adapter",
        "register",
        "--manifest",
        source.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{:?}", out);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains('\x1b'));
    assert!(!text.contains("descriptor\n"));
    assert!(text.contains("descriptor\\u{a}\\u{1b}.json"));
    assert!(!f.state.exists());
}

#[test]
fn local_schema_capacity_refusal_is_distinct_from_contract_failure() {
    let f = Fixture::new();
    let bytes = serde_json::to_string(&descriptor("capacity_fixture"))
        .unwrap()
        .replace(
            "\"configuration_schema\":{",
            &format!("\"configuration_schema\":{{{}", " ".repeat(65_536)),
        );
    let source = f.root.join("capacity.json");
    fs::write(&source, bytes).unwrap();
    let out = f.run(&[
        "adapter",
        "register",
        "--manifest",
        source.to_str().unwrap(),
        "--json",
    ]);
    assert!(!out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        body["reasons"],
        json!(["configuration_schema_byte_capacity_exceeded"])
    );
    assert_eq!(body["outcome"], "refused");
    assert!(!f.state.exists());
}

#[test]
fn confirmed_configuration_registration_emits_one_canonical_json_envelope() {
    let f = Fixture::new();
    let config = json!({
        "schema_version":1, "id":"json-config", "display_name":"JSON config",
        "summary":"Fixture", "min_fornax_version":"0.0.1",
        "provenance":"https://example.com/synthetic-fixture",
        "capabilities":["plan","install","uninstall"],
        "target":{"format":"json","path":"~/.synthetic-host/settings.json"},
        "operations":[{"kind":"ensure_marked_array_element", "pointer":"/hooks/PostToolUse",
            "marker_key":"command", "marker_value":"synthetic-marker",
            "element":{"type":"command","command":"synthetic-marker"}}]
    });
    let source = f.source("config.json", &config);
    let source_text = source.to_str().unwrap();
    let review = f.run(&["adapter", "register", "--manifest", source_text, "--json"]);
    assert!(review.status.success(), "{:?}", review);
    let reviewed: Value = serde_json::from_slice(&review.stdout).unwrap();
    let digest = reviewed["digest"].as_str().unwrap();
    let out = f.run(&[
        "adapter",
        "register",
        "--manifest",
        source_text,
        "--confirm-digest",
        digest,
        "--json",
    ]);
    assert!(out.status.success(), "{:?}", out);
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["operation"], "register");
    assert_eq!(body["outcome"], "success");
    assert_eq!(body["result"]["kind"], "config-v1");
    assert_eq!(body["result"]["enabled"], true);
    assert!(!f.home.join(".synthetic-host").exists());
}

#[test]
fn first_host_registration_migrates_legacy_config_metadata_and_owned_bytes() {
    for (version, enabled) in [(0, false), (1, true)] {
        let f = Fixture::new();
        let config = json!({
            "schema_version":1, "id":"json-config", "display_name":"JSON config",
            "summary":"Fixture", "min_fornax_version":"0.0.1",
            "provenance":"https://example.com/synthetic-fixture",
            "capabilities":["plan","install","uninstall"],
            "target":{"format":"json","path":"~/.synthetic-host/settings.json"},
            "operations":[{"kind":"ensure_marked_array_element", "pointer":"/hooks/PostToolUse",
                "marker_key":"command", "marker_value":"synthetic-marker",
                "element":{"type":"command","command":"synthetic-marker"}}]
        });
        let source = f.source("config.json", &config);
        let source_text = source.to_str().unwrap();
        let review = f.run(&["adapter", "register", "--manifest", source_text, "--json"]);
        assert!(review.status.success(), "{:?}", review);
        let reviewed: Value = serde_json::from_slice(&review.stdout).unwrap();
        let digest = reviewed["digest"].as_str().unwrap();
        let registered = f.run(&[
            "adapter",
            "register",
            "--manifest",
            source_text,
            "--confirm-digest",
            digest,
            "--json",
        ]);
        assert!(registered.status.success(), "{:?}", registered);

        let index_path = f.state.join("adapters/registry.json");
        let mut legacy: Value = serde_json::from_slice(&f.index()).unwrap();
        legacy["schema_version"] = json!(version);
        legacy["entries"][0]["source_path"] = json!(format!("legacy-source-{version}"));
        legacy["entries"][0]["registered_at"] = json!(format!("legacy-time-{version}"));
        legacy["entries"][0]["enabled"] = json!(enabled);
        let old_record = legacy["entries"][0].clone();
        fs::write(&index_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let config_copy = f.state.join("adapters/json-config.manifest.json");
        let config_bytes = fs::read(&config_copy).unwrap();

        let host_source = f.source("host.json", &descriptor("migration_host"));
        f.confirm(&host_source);

        let migrated: Value = serde_json::from_slice(&f.index()).unwrap();
        assert_eq!(migrated["schema_version"], 2);
        assert_eq!(migrated["registry_kind"], "fornax-adapter-registry-v2");
        let migrated_config = migrated["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == "json-config")
            .unwrap();
        assert_eq!(migrated_config["kind"], "config-v1");
        for field in [
            "id",
            "manifest_file",
            "digest",
            "source_path",
            "registered_at",
            "enabled",
        ] {
            assert_eq!(
                migrated_config[field], old_record[field],
                "version {version}, field {field}"
            );
        }
        assert_eq!(migrated_config["enabled"], enabled);
        assert_eq!(fs::read(config_copy).unwrap(), config_bytes);
    }
}

#[test]
fn unregister_reports_published_partial_cleanup_without_removing_replacement_directory() {
    let f = Fixture::new();
    let source = f.source("descriptor.json", &descriptor("cleanup_fixture"));
    f.confirm(&source);

    let owned = f.state.join("adapters/cleanup_fixture.host-adapter.json");
    fs::remove_file(&owned).unwrap();
    fs::create_dir(&owned).unwrap();
    let sentinel = owned.join("preserve.txt");
    fs::write(&sentinel, b"replacement directory sentinel").unwrap();

    let out = f.run(&["adapter", "unregister", "cleanup_fixture", "--json"]);
    assert!(!out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["operation"], "unregister");
    assert_eq!(body["outcome"], "partial");
    assert_eq!(body["verification_state"], "unverified");
    assert_eq!(body["reasons"], json!(["cleanup_failed"]));
    assert_eq!(body["result"]["publication"], "committed");

    let index: Value = serde_json::from_slice(&f.index()).unwrap();
    assert!(index["entries"].as_array().unwrap().is_empty());
    assert!(owned.is_dir());
    assert_eq!(
        fs::read(sentinel).unwrap(),
        b"replacement directory sentinel"
    );
}
