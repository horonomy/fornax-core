use fornax_store::adapter_registry::{
    read_registry, register_config, remove_registration, set_registration_enabled,
    ConfigRegistration, RegistrationKind, RegistryErrorCode, REGISTRY_INDEX_FILE, REGISTRY_KIND_V2,
};
use std::path::{Path, PathBuf};

fn scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!("fornax-owner-registry-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&path).expect("create scratch directory");
    path
}

fn adapters(home: &Path) -> PathBuf {
    let path = home.join("adapters");
    std::fs::create_dir_all(&path).expect("create adapters directory");
    path
}

fn digest() -> &'static str {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

fn host_v2_index(id: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 2,
        "registry_kind": REGISTRY_KIND_V2,
        "entries": [{
            "id": id,
            "manifest_file": format!("{id}.host-adapter.json"),
            "digest": digest(),
            "source_path": "/tmp/source.json",
            "registered_at": "2026-10-08T00:00:00Z",
            "enabled": false,
            "kind": "host-adapter-v1"
        }]
    })
}

#[test]
fn missing_home_is_a_passive_empty_read() {
    let parent = scratch();
    let home = parent.join("absent-home");
    let snapshot = read_registry(&home).expect("missing home is empty");
    assert_eq!(snapshot.stored_schema_version(), None);
    assert_eq!(snapshot.effective_schema_version(), 1);
    assert!(snapshot.entries().is_empty());
    assert!(!home.exists(), "passive read must not create the home");
    std::fs::remove_dir_all(parent).ok();
}

#[test]
fn stored_zero_and_digit_leading_configuration_id_are_truthful_and_unchanged() {
    let home = scratch();
    let directory = adapters(&home);
    let raw = br#"{"schema_version":0,"entries":[{"id":"123adapter","manifest_file":"123adapter.manifest.json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","source_path":"/tmp/manifest.json","registered_at":"legacy","enabled":false}]}"#;
    std::fs::write(directory.join(REGISTRY_INDEX_FILE), raw).unwrap();

    let snapshot = read_registry(&home).expect("legacy zero index reads");
    assert_eq!(snapshot.stored_schema_version(), Some(0));
    assert_eq!(snapshot.effective_schema_version(), 0);
    assert_eq!(snapshot.entries().len(), 1);
    let row = &snapshot.entries()[0];
    assert_eq!(row.id(), "123adapter");
    assert_eq!(row.kind(), RegistrationKind::ConfigV1);
    assert!(!row.enabled());
    assert_eq!(
        std::fs::read(directory.join(REGISTRY_INDEX_FILE)).unwrap(),
        raw
    );
    assert!(
        !directory.join("registry.lock").exists(),
        "read must not create a lock"
    );
    std::fs::remove_dir_all(home).ok();
}

#[test]
fn omitted_version_remains_omitted_and_effectively_uses_one() {
    let home = scratch();
    let directory = adapters(&home);
    std::fs::write(directory.join(REGISTRY_INDEX_FILE), br#"{"entries":[]}"#).unwrap();
    let snapshot = read_registry(&home).unwrap();
    assert_eq!(snapshot.stored_schema_version(), None);
    assert_eq!(snapshot.effective_schema_version(), 1);
    std::fs::remove_dir_all(home).ok();
}

#[test]
fn closed_legacy_roots_reject_duplicates_and_v2_markers() {
    let home = scratch();
    let directory = adapters(&home);
    let index = directory.join(REGISTRY_INDEX_FILE);
    std::fs::write(
        &index,
        br#"{"schema_version":1,"schema_version":1,"entries":[]}"#,
    )
    .unwrap();
    assert_eq!(
        read_registry(&home).unwrap_err().code(),
        RegistryErrorCode::Malformed
    );

    std::fs::write(&index, br#"{"schema_version":1}"#).unwrap();
    assert_eq!(
        read_registry(&home).unwrap_err().code(),
        RegistryErrorCode::Malformed
    );

    std::fs::write(
        &index,
        br#"{"schema_version":1,"registry_kind":"fornax-adapter-registry-v2","entries":[]}"#,
    )
    .unwrap();
    assert_eq!(
        read_registry(&home).unwrap_err().code(),
        RegistryErrorCode::Malformed
    );

    std::fs::write(
        &index,
        br#"{"schema_version":2,"registry_kind":"fornax-adapter-registry-v2"}"#,
    )
    .unwrap();
    assert_eq!(
        read_registry(&home).unwrap_err().code(),
        RegistryErrorCode::Malformed
    );
    std::fs::remove_dir_all(home).ok();
}

#[test]
fn v2_marker_survives_removal_of_last_host_record_and_owned_descriptor_is_retained() {
    use std::os::unix::fs::MetadataExt;

    let home = scratch();
    let directory = adapters(&home);
    let id = "sample-host";
    std::fs::write(
        directory.join(REGISTRY_INDEX_FILE),
        serde_json::to_vec(&host_v2_index(id)).unwrap(),
    )
    .unwrap();
    std::fs::write(
        directory.join(format!("{id}.host-adapter.json")),
        b"descriptor bytes",
    )
    .unwrap();

    let before = read_registry(&home).unwrap();
    assert_eq!(before.stored_schema_version(), Some(2));
    assert_eq!(before.entries()[0].kind(), RegistrationKind::HostAdapterV1);
    assert_eq!(
        set_registration_enabled(&home, id, true)
            .unwrap_err()
            .code(),
        RegistryErrorCode::ExecutionBoundaryUnavailable
    );
    let lock_path = directory.join("registry.lock");
    let lock_inode = std::fs::metadata(&lock_path).unwrap().ino();
    assert!(!read_registry(&home).unwrap().entries()[0].enabled());

    // Strict Retention (HORO-1745): the index entry is genuinely removed,
    // but the owned descriptor file is never unlinked -- no code path here
    // can prove a pathname unlink would hit the exact inode just verified,
    // so the committed-but-uncleaned outcome is reported truthfully rather
    // than claimed as a clean removal.
    let error = remove_registration(&home, id).unwrap_err();
    assert_eq!(error.code(), RegistryErrorCode::CleanupFailed);
    assert!(error.index_published());
    let after = read_registry(&home).unwrap();
    assert_eq!(after.stored_schema_version(), Some(2));
    assert_eq!(after.effective_schema_version(), 2);
    assert!(after.entries().is_empty());
    let published: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join(REGISTRY_INDEX_FILE)).unwrap())
            .unwrap();
    assert_eq!(published["registry_kind"], REGISTRY_KIND_V2);
    assert_eq!(std::fs::metadata(lock_path).unwrap().ino(), lock_inode);
    assert_eq!(
        std::fs::read(directory.join(format!("{id}.host-adapter.json"))).unwrap(),
        b"descriptor bytes"
    );
    std::fs::remove_dir_all(home).ok();
}

#[test]
fn enabled_host_record_cannot_be_removed_before_disable() {
    let home = scratch();
    let directory = adapters(&home);
    let id = "sample-host";
    let mut index = host_v2_index(id);
    index["entries"][0]["enabled"] = serde_json::Value::Bool(true);
    let index_path = directory.join(REGISTRY_INDEX_FILE);
    let bytes = serde_json::to_vec(&index).unwrap();
    std::fs::write(&index_path, &bytes).unwrap();
    std::fs::write(
        directory.join(format!("{id}.host-adapter.json")),
        b"descriptor bytes",
    )
    .unwrap();

    assert_eq!(
        remove_registration(&home, id).unwrap_err().code(),
        RegistryErrorCode::RegistrationEnabled
    );
    assert_eq!(std::fs::read(&index_path).unwrap(), bytes);
    assert!(directory.join(format!("{id}.host-adapter.json")).exists());
    std::fs::remove_dir_all(home).ok();
}

#[cfg(unix)]
#[test]
fn published_removal_cleanup_error_reports_commit_truth() {
    let home = scratch();
    let directory = adapters(&home);
    let id = "cleanup-case";
    let manifest = directory.join(format!("{id}.manifest.json"));
    std::fs::create_dir(&manifest).unwrap();
    let index = serde_json::json!({
        "schema_version": 1,
        "entries": [{
            "id": id,
            "manifest_file": format!("{id}.manifest.json"),
            "digest": digest(),
            "source_path": "/tmp/source.json",
            "registered_at": "legacy",
            "enabled": false
        }]
    });
    let index_path = directory.join(REGISTRY_INDEX_FILE);
    std::fs::write(&index_path, serde_json::to_vec(&index).unwrap()).unwrap();

    let error = remove_registration(&home, id).unwrap_err();
    assert_eq!(error.code(), RegistryErrorCode::CleanupFailed);
    assert!(error.index_published());
    let published: serde_json::Value =
        serde_json::from_slice(&std::fs::read(index_path).unwrap()).unwrap();
    assert!(published["entries"].as_array().unwrap().is_empty());
    assert!(manifest.is_dir());
    std::fs::remove_dir_all(home).ok();
}

#[cfg(unix)]
#[test]
fn v2_config_mutation_preserves_existing_host_kinds_and_metadata() {
    let home = scratch();
    let directory = adapters(&home);
    let mut index = host_v2_index("host-alpha");
    let mut second = index["entries"][0].clone();
    second["id"] = serde_json::Value::String("host-beta".into());
    second["manifest_file"] = serde_json::Value::String("host-beta.host-adapter.json".into());
    index["entries"].as_array_mut().unwrap().push(second);
    let before_rows = index["entries"].clone();
    std::fs::write(
        directory.join(REGISTRY_INDEX_FILE),
        serde_json::to_vec(&index).unwrap(),
    )
    .unwrap();

    let id = "legacy-config";
    let raw = format!(r#"{{"schema_version":1,"id":"{id}"}}"#);
    register_config(
        &home,
        ConfigRegistration {
            id,
            source_path: "/tmp/config.json",
            registered_at: "now",
            raw_bytes: raw.as_bytes(),
        },
    )
    .unwrap();

    let snapshot = read_registry(&home).unwrap();
    assert_eq!(snapshot.stored_schema_version(), Some(2));
    assert_eq!(snapshot.entries().len(), 3);
    assert_eq!(
        snapshot.entries()[0].kind(),
        RegistrationKind::HostAdapterV1
    );
    assert_eq!(
        snapshot.entries()[1].kind(),
        RegistrationKind::HostAdapterV1
    );
    assert_eq!(snapshot.entries()[2].kind(), RegistrationKind::ConfigV1);
    let published: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join(REGISTRY_INDEX_FILE)).unwrap())
            .unwrap();
    for (index, old) in before_rows.as_array().unwrap().iter().enumerate() {
        assert_eq!(published["entries"][index], *old);
    }
    std::fs::remove_dir_all(home).ok();
}

#[test]
fn special_index_files_are_refused_without_blocking() {
    #[cfg(unix)]
    {
        let home = scratch();
        let directory = adapters(&home);
        assert!(std::process::Command::new("mkfifo")
            .arg(directory.join(REGISTRY_INDEX_FILE))
            .status()
            .expect("create isolated FIFO fixture")
            .success());
        assert_eq!(
            read_registry(&home).unwrap_err().code(),
            RegistryErrorCode::Unavailable
        );
        std::fs::remove_dir_all(home).ok();
    }
}

#[cfg(unix)]
#[test]
fn config_registration_uses_create_new_and_keeps_lock_inode() {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    assert_eq!(
        serde_json::to_string(&RegistrationKind::ConfigV1).unwrap(),
        "\"config-v1\""
    );
    assert_eq!(
        serde_json::to_string(&RegistrationKind::HostAdapterV1).unwrap(),
        "\"host-adapter-v1\""
    );
    let home = scratch();
    let directory = adapters(&home);
    let id = "123legacy";
    let raw = format!(r#"{{"schema_version":1,"id":"{id}"}}"#);
    let request = ConfigRegistration {
        id,
        source_path: "/tmp/source.json",
        registered_at: "2026-10-08T00:00:00Z",
        raw_bytes: raw.as_bytes(),
    };
    let row = register_config(&home, request.clone()).expect("bounded config storage request");
    assert_eq!(row.id(), id);
    assert!(row.enabled());
    assert_eq!(row.kind(), RegistrationKind::ConfigV1);
    let looked_up = fornax_store::adapter_registry::lookup_config_descriptor(&home, id).unwrap();
    assert_eq!(looked_up.entry().id(), id);
    assert_eq!(looked_up.raw_bytes(), raw.as_bytes());
    let lock = directory.join("registry.lock");
    let inode = std::fs::metadata(&lock).unwrap().ino();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();

    let registered = directory.join(format!("{id}.manifest.json"));
    let original = std::fs::read(&registered).unwrap();
    assert_eq!(original, raw.as_bytes());
    assert_eq!(
        register_config(&home, request).unwrap_err().code(),
        RegistryErrorCode::DuplicateId
    );
    assert_eq!(std::fs::read(&registered).unwrap(), original);

    set_registration_enabled(&home, id, false).unwrap();
    assert!(!read_registry(&home).unwrap().entries()[0].enabled());
    // Strict Retention (HORO-1745): the index entry is removed, but the
    // owned copy is never unlinked.
    let error = remove_registration(&home, id).unwrap_err();
    assert_eq!(error.code(), RegistryErrorCode::CleanupFailed);
    assert!(error.index_published());
    assert_eq!(std::fs::read(&registered).unwrap(), original);
    assert_eq!(std::fs::metadata(&lock).unwrap().ino(), inode);
    assert_eq!(
        std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
        0o644
    );
    std::fs::remove_dir_all(home).ok();
}

#[cfg(unix)]
#[test]
fn unindexed_destination_is_never_replaced() {
    let home = scratch();
    let directory = adapters(&home);
    let id = "fixture-a";
    let destination = directory.join(format!("{id}.manifest.json"));
    std::fs::write(&destination, b"owned by someone else").unwrap();
    let raw = format!(r#"{{"schema_version":1,"id":"{id}"}}"#);
    let err = register_config(
        &home,
        ConfigRegistration {
            id,
            source_path: "/tmp/source.json",
            registered_at: "now",
            raw_bytes: raw.as_bytes(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code(), RegistryErrorCode::InvalidRecord);
    assert_eq!(
        std::fs::read(destination).unwrap(),
        b"owned by someone else"
    );
    assert!(read_registry(&home).unwrap().entries().is_empty());
    std::fs::remove_dir_all(home).ok();
}

#[cfg(unix)]
#[test]
fn lock_contention_is_bounded_and_leaves_the_index_unchanged() {
    let home = scratch();
    let directory = adapters(&home);
    let id = "fixture-b";
    let raw = format!(r#"{{"schema_version":1,"id":"{id}"}}"#);
    register_config(
        &home,
        ConfigRegistration {
            id,
            source_path: "/tmp/source.json",
            registered_at: "now",
            raw_bytes: raw.as_bytes(),
        },
    )
    .unwrap();
    let index = directory.join(REGISTRY_INDEX_FILE);
    let before = std::fs::read(&index).unwrap();
    let lock = std::fs::File::from(
        rustix::fs::open(
            directory.join("registry.lock"),
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .unwrap(),
    );
    // This open file description has never been flock'd by anyone, so the
    // first attempt should always succeed immediately. A transient
    // WouldBlock here has been observed on a loaded CI runner (not
    // reproduced locally across repeated runs); retried a few times with a
    // short backoff rather than treating a scheduling hiccup in this test's
    // own setup as the product behavior under test, which starts below.
    let mut attempts = 0;
    loop {
        match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => break,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::WOULDBLOCK) if attempts < 20 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("test setup could not acquire its own fresh lock fd: {error}"),
        }
    }

    let started = std::time::Instant::now();
    let error = set_registration_enabled(&home, id, false).unwrap_err();
    assert_eq!(error.code(), RegistryErrorCode::RegistryBusy);
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
    assert_eq!(std::fs::read(index).unwrap(), before);
    drop(lock);
    std::fs::remove_dir_all(home).ok();
}

#[test]
fn host_capacity_refusal_preserves_specific_cause_without_creating_registry_state() {
    let home = scratch();
    let raw = vec![b' '; fornax_types::MAX_HOST_ADAPTER_MANIFEST_BYTES + 1];
    let error = fornax_store::adapter_registry::register_host_descriptor(
        &home,
        "synthetic-source",
        "fixture",
        &raw,
    )
    .unwrap_err();
    assert_eq!(error.code(), RegistryErrorCode::DescriptorCapacity);
    assert_eq!(error.code_str(), "manifest_byte_capacity_exceeded");
    assert!(!error.index_published());
    assert!(!home.join("adapters").exists());
    std::fs::remove_dir_all(home).ok();
}
