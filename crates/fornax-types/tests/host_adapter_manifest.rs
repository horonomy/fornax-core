use fornax_types::host_adapter_manifest::{
    MAX_CONFIGURATION_SCHEMA_BYTES, MAX_HOST_ADAPTER_MANIFEST_NODES,
};
use fornax_types::{
    decode_host_adapter_manifest, HostManifestRejection, MAX_HOST_ADAPTER_MANIFEST_BYTES,
};
use serde_json::{json, Value};

const VALID_MANIFEST: &str = r#"{"manifest_kind":"host-adapter","manifest_version":1,"adapter_id":"synthetic_external","adapter_version":"1.2.0","protocol_versions":[1],"contract_version_range":{"minimum":1,"maximum":1},"roles":["LifecycleSource","IdentitySource"],"capabilities":["lifecycle.session","identity.agent"],"host_version_constraints":[{"provider":"synthetic_host","minimum":null,"maximum":null}],"configuration_schema":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"additionalProperties":false},"launch":{"executable":"/opt/horonom/adapters/synthetic","argv":["--stdio-json"]},"runtime_files":[{"path":"/opt/horonom/adapters/synthetic","kind":"entrypoint","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"input_limits":{"max_bytes":1048576},"needs":{"environment":[],"read_paths":[],"write_paths":[]}}"#;

fn valid() -> Value {
    serde_json::from_str(VALID_MANIFEST).expect("shared fixture JSON")
}

fn encode(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("manifest JSON")
}

fn node_count(value: &Value) -> usize {
    1 + match value {
        Value::Array(values) => values.iter().map(node_count).sum(),
        Value::Object(values) => values.values().map(node_count).sum(),
        _ => 0,
    }
}

fn config_schema_mut(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    value["configuration_schema"]
        .as_object_mut()
        .expect("schema object")
}

#[test]
fn shared_v1_fixture_decodes_and_keeps_exact_source_and_lossless_json() {
    let bytes = VALID_MANIFEST.as_bytes();
    let manifest = decode_host_adapter_manifest(bytes).expect("valid shared manifest");
    assert_eq!(manifest.id(), "synthetic_external");
    assert_eq!(manifest.as_manifest_bytes(), bytes);
    let encoded = serde_json::to_string(&manifest).expect("lossless raw JSON serialization");
    assert!(encoded.contains("\"adapter_id\":\"synthetic_external\""));
    assert_eq!(manifest.as_raw_json().get(), VALID_MANIFEST);
}

#[test]
fn closed_manifest_duplicate_keys_and_cross_field_versions_are_rejected() {
    let mut value = valid();
    value["unexpected"] = json!(true);
    assert_eq!(
        decode_host_adapter_manifest(&encode(&value)).unwrap_err(),
        HostManifestRejection::ContractViolation
    );

    let duplicate = VALID_MANIFEST.replacen(
        "\"adapter_id\":\"synthetic_external\"",
        "\"adapter_id\":\"synthetic_external\",\"adapter_\\u0069d\":\"synthetic_external\"",
        1,
    );
    assert_eq!(
        decode_host_adapter_manifest(duplicate.as_bytes()).unwrap_err(),
        HostManifestRejection::DuplicateKey
    );

    let mut value = valid();
    value["contract_version_range"]["minimum"] = json!(2);
    value["contract_version_range"]["maximum"] = json!(1);
    assert_eq!(
        decode_host_adapter_manifest(&encode(&value)).unwrap_err(),
        HostManifestRejection::ContractViolation
    );

    let mut value = valid();
    value["host_version_constraints"][0]["minimum"] = json!("2.0.0");
    value["host_version_constraints"][0]["maximum"] = json!("1.9.9");
    assert_eq!(
        decode_host_adapter_manifest(&encode(&value)).unwrap_err(),
        HostManifestRejection::ContractViolation
    );
}

#[test]
fn valid_future_only_protocol_and_contract_declarations_remain_descriptive() {
    let mut value = valid();
    value["protocol_versions"] = json!([2_147_483_647]);
    value["contract_version_range"] =
        json!({"minimum": 2_147_483_647_i64, "maximum": 2_147_483_647_i64});
    assert!(decode_host_adapter_manifest(&encode(&value)).is_ok());
}

#[test]
fn complete_configuration_profile_rejects_unknown_refs_and_reversed_families() {
    let mut value = valid();
    config_schema_mut(&mut value).insert("$ref".into(), json!("https://example.invalid/schema"));
    assert_eq!(
        decode_host_adapter_manifest(&encode(&value)).unwrap_err(),
        HostManifestRejection::ContractViolation
    );

    let mut value = valid();
    let first_family = value["host_version_constraints"][0].clone();
    value["host_version_constraints"]
        .as_array_mut()
        .unwrap()
        .push(first_family);
    assert_eq!(
        decode_host_adapter_manifest(&encode(&value)).unwrap_err(),
        HostManifestRejection::ContractViolation
    );

    let mut value = valid();
    let mut schema = value["configuration_schema"].clone();
    schema["properties"] = json!({"$ref": {"type": "string"}});
    value["configuration_schema"] = schema;
    assert!(
        decode_host_adapter_manifest(&encode(&value)).is_ok(),
        "literal property key $ref is data"
    );
}

#[test]
fn exact_numeric_semantics_preserve_large_values_and_detect_integral_intervals() {
    let exact_values = VALID_MANIFEST.replace(
        "\"properties\":{}",
        "\"properties\":{\"n\":{\"type\":\"number\",\"enum\":[9007199254740992,9007199254740993]}}",
    );
    let manifest = decode_host_adapter_manifest(exact_values.as_bytes())
        .expect("adjacent large integers differ");
    let json = serde_json::to_string(&manifest).unwrap();
    assert!(json.contains("9007199254740992"));
    assert!(json.contains("9007199254740993"));

    let duplicate_numbers = VALID_MANIFEST.replace(
        "\"properties\":{}",
        "\"properties\":{\"n\":{\"type\":\"number\",\"enum\":[1,1.0,1e0]}}",
    );
    assert_eq!(
        decode_host_adapter_manifest(duplicate_numbers.as_bytes()).unwrap_err(),
        HostManifestRejection::ContractViolation
    );

    let signed_floor_ceil = VALID_MANIFEST.replace(
        "\"properties\":{}",
        "\"properties\":{\"n\":{\"type\":\"integer\",\"exclusiveMinimum\":-1.5,\"maximum\":-1}}",
    );
    assert!(decode_host_adapter_manifest(signed_floor_ceil.as_bytes()).is_ok());

    let no_integer = VALID_MANIFEST.replace(
        "\"properties\":{}",
        "\"properties\":{\"n\":{\"type\":\"integer\",\"minimum\":-1.5,\"maximum\":-1.1}}",
    );
    assert_eq!(
        decode_host_adapter_manifest(no_integer.as_bytes()).unwrap_err(),
        HostManifestRejection::ContractViolation
    );

    let dense_interval = VALID_MANIFEST.replace(
        "\"properties\":{}",
        "\"properties\":{\"n\":{\"type\":\"number\",\"exclusiveMinimum\":1,\"exclusiveMaximum\":1}}",
    );
    assert_eq!(
        decode_host_adapter_manifest(dense_interval.as_bytes()).unwrap_err(),
        HostManifestRejection::ContractViolation
    );
}

#[test]
fn numeric_resource_refusals_are_distinct_from_schema_rejections() {
    let long_number = format!("{}{}", "1", "0".repeat(4_096));
    let input = VALID_MANIFEST.replace(
        "\"properties\":{}",
        &format!("\"properties\":{{\"n\":{{\"type\":\"number\",\"minimum\":{long_number}}}}}"),
    );
    assert_eq!(
        decode_host_adapter_manifest(input.as_bytes()).unwrap_err(),
        HostManifestRejection::NumericTokenSizeLimit
    );

    let long_exponent = format!("1e{}", "0".repeat(129));
    let input = VALID_MANIFEST.replace(
        "\"properties\":{}",
        &format!("\"properties\":{{\"n\":{{\"type\":\"number\",\"minimum\":{long_exponent}}}}}"),
    );
    assert_eq!(
        decode_host_adapter_manifest(input.as_bytes()).unwrap_err(),
        HostManifestRejection::NumericExponentDigitLimit
    );
}

#[test]
fn full_manifest_byte_and_node_caps_are_inclusive() {
    let mut oversize = valid();
    oversize["needs"]["read_paths"] = json!(["x".repeat(MAX_HOST_ADAPTER_MANIFEST_BYTES)]);
    assert_eq!(
        decode_host_adapter_manifest(&encode(&oversize)).unwrap_err(),
        HostManifestRejection::InputTooLarge
    );

    let mut exact = valid();
    let baseline = node_count(&exact);
    let paths = exact["needs"]["read_paths"].as_array_mut().unwrap();
    paths.extend((baseline..MAX_HOST_ADAPTER_MANIFEST_NODES).map(|_| json!("x")));
    assert_eq!(node_count(&exact), MAX_HOST_ADAPTER_MANIFEST_NODES);
    assert!(decode_host_adapter_manifest(&encode(&exact)).is_ok());
    exact["needs"]["read_paths"]
        .as_array_mut()
        .unwrap()
        .push(json!("x"));
    assert_eq!(
        decode_host_adapter_manifest(&encode(&exact)).unwrap_err(),
        HostManifestRejection::NodeLimit
    );
}

#[test]
fn embedded_schema_has_its_own_byte_node_and_depth_budgets() {
    let mut exact = valid();
    {
        let schema = config_schema_mut(&mut exact);
        let properties = schema
            .get_mut("properties")
            .unwrap()
            .as_object_mut()
            .unwrap();
        let mut property = serde_json::Map::new();
        property.insert("type".into(), json!("null"));
        properties.insert("x".into(), Value::Object(property));
    }
    let initial_len = serde_json::to_vec(&exact["configuration_schema"])
        .unwrap()
        .len();
    let key_len = 1 + (MAX_CONFIGURATION_SCHEMA_BYTES - initial_len);
    {
        let schema = config_schema_mut(&mut exact);
        schema["properties"].as_object_mut().unwrap().clear();
        schema["properties"]
            .as_object_mut()
            .unwrap()
            .insert("x".repeat(key_len), json!({"type":"null"}));
    }
    assert_eq!(
        serde_json::to_vec(&exact["configuration_schema"])
            .unwrap()
            .len(),
        MAX_CONFIGURATION_SCHEMA_BYTES
    );
    assert!(decode_host_adapter_manifest(&encode(&exact)).is_ok());
    config_schema_mut(&mut exact)["properties"]
        .as_object_mut()
        .unwrap()
        .clear();
    config_schema_mut(&mut exact)["properties"]
        .as_object_mut()
        .unwrap()
        .insert("y".repeat(key_len + 1), json!({"type":"null"}));
    assert_eq!(
        serde_json::to_vec(&exact["configuration_schema"])
            .unwrap()
            .len(),
        MAX_CONFIGURATION_SCHEMA_BYTES + 1
    );
    assert_eq!(
        decode_host_adapter_manifest(&encode(&exact)).unwrap_err(),
        HostManifestRejection::ConfigurationSchemaTooLarge
    );

    let mut schema_nodes = valid();
    {
        let properties = schema_nodes["configuration_schema"]["properties"]
            .as_object_mut()
            .unwrap();
        for index in 0..2_045 {
            properties.insert(format!("p{index}"), json!({"type":"null"}));
        }
    }
    schema_nodes["configuration_schema"]["title"] = json!("x");
    assert_eq!(node_count(&schema_nodes["configuration_schema"]), 4096);
    assert!(decode_host_adapter_manifest(&encode(&schema_nodes)).is_ok());
    schema_nodes["configuration_schema"]["required"] = json!([]);
    assert_eq!(node_count(&schema_nodes["configuration_schema"]), 4097);
    assert_eq!(
        decode_host_adapter_manifest(&encode(&schema_nodes)).unwrap_err(),
        HostManifestRejection::ConfigurationSchemaNodeLimit
    );
}

#[test]
fn manifest_depth_is_checked_before_contract_validation() {
    let at_limit = format!(
        "{},\"extra\":{}{}",
        &VALID_MANIFEST[..VALID_MANIFEST.len() - 1],
        "[".repeat(31) + "0" + &"]".repeat(31),
        "}"
    );
    assert_eq!(
        decode_host_adapter_manifest(at_limit.as_bytes()).unwrap_err(),
        HostManifestRejection::ContractViolation
    );
    let over = format!(
        "{},\"extra\":{}{}",
        &VALID_MANIFEST[..VALID_MANIFEST.len() - 1],
        "[".repeat(32) + "0" + &"]".repeat(32),
        "}"
    );
    assert_eq!(
        decode_host_adapter_manifest(over.as_bytes()).unwrap_err(),
        HostManifestRejection::ExcessiveNesting
    );
}

fn with_raw_schema(schema: &str) -> String {
    let mut manifest = valid();
    manifest["configuration_schema"] = Value::Null;
    String::from_utf8(encode(&manifest)).unwrap().replace(
        "\"configuration_schema\":null",
        &format!("\"configuration_schema\":{schema}"),
    )
}

fn with_number_node(schema: &str) -> String {
    with_raw_schema(&format!(
        r#"{{"type":"object","properties":{{"n":{schema}}},"additionalProperties":false}}"#
    ))
}

#[test]
fn optional_root_dialect_and_repeated_environment_names_follow_shared_schema() {
    let minimal =
        with_raw_schema(r#"{"type":"object","properties":{},"additionalProperties":false}"#);
    assert!(decode_host_adapter_manifest(minimal.as_bytes()).is_ok());
    let mut repeated = valid();
    repeated["needs"]["environment"] = json!(["PATH", "PATH"]);
    assert!(decode_host_adapter_manifest(&encode(&repeated)).is_ok());
    for schema in [
        r#"{"$schema":"https://example.invalid","type":"object","properties":{},"additionalProperties":false}"#,
        r#"{"type":"object","properties":{"n":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null"}},"additionalProperties":false}"#,
    ] {
        assert_eq!(
            decode_host_adapter_manifest(with_raw_schema(schema).as_bytes()).unwrap_err(),
            HostManifestRejection::ContractViolation
        );
    }
}

#[test]
fn raw_schema_whitespace_counts_toward_the_exact_embedded_byte_limit() {
    let value = valid();
    let schema_length = encode(&value["configuration_schema"]).len();
    let base = String::from_utf8(encode(&value)).unwrap();
    for (extra, valid) in [(0, true), (1, false)] {
        let input = base.replace(
            "\"configuration_schema\":{",
            &format!(
                "\"configuration_schema\":{{{}",
                " ".repeat(MAX_CONFIGURATION_SCHEMA_BYTES - schema_length + extra)
            ),
        );
        let result = decode_host_adapter_manifest(input.as_bytes());
        if valid {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                result.unwrap_err(),
                HostManifestRejection::ConfigurationSchemaTooLarge
            );
        }
    }
}

#[test]
fn schema_container_depth_is_inclusive_and_does_not_count_scalar_leaves() {
    let mut leaf = json!({"type":"null"});
    // Schema root and its properties map consume two container levels.
    // Thirteen array-schema objects plus the null schema make levels3..16.
    for _ in 0..13 {
        leaf = json!({"type":"array","items":leaf});
    }
    let mut manifest = valid();
    manifest["configuration_schema"]["properties"]["nested"] = leaf.clone();
    assert!(decode_host_adapter_manifest(&encode(&manifest)).is_ok());
    manifest["configuration_schema"]["properties"]["nested"] = json!({"type":"array","items":leaf});
    assert_eq!(
        decode_host_adapter_manifest(&encode(&manifest)).unwrap_err(),
        HostManifestRejection::ConfigurationSchemaExcessiveNesting
    );
}

#[test]
fn full_manifest_byte_boundary_accepts_exact_capacity_and_refuses_one_more() {
    let mut manifest = valid();
    manifest["needs"]["read_paths"] = json!([""]);
    let length = encode(&manifest).len();
    manifest["needs"]["read_paths"][0] =
        json!("x".repeat(MAX_HOST_ADAPTER_MANIFEST_BYTES - length));
    assert_eq!(encode(&manifest).len(), MAX_HOST_ADAPTER_MANIFEST_BYTES);
    assert!(decode_host_adapter_manifest(&encode(&manifest)).is_ok());
    manifest["needs"]["read_paths"][0].as_str().unwrap();
    let extra = format!("{}x", manifest["needs"]["read_paths"][0].as_str().unwrap());
    manifest["needs"]["read_paths"][0] = json!(extra);
    assert_eq!(
        decode_host_adapter_manifest(&encode(&manifest)).unwrap_err(),
        HostManifestRejection::InputTooLarge
    );
}

#[test]
fn exact_decimal_values_outside_u64_and_below_f64_resolution_stay_distinct() {
    for node in [
        r#"{"type":"number","enum":[18446744073709551616,18446744073709551617]}"#,
        r#"{"type":"number","enum":[1.0000000000000000000000001,1.0000000000000000000000002]}"#,
    ] {
        let input = with_number_node(node);
        let manifest = decode_host_adapter_manifest(input.as_bytes()).unwrap();
        assert_eq!(manifest.as_manifest_bytes(), input.as_bytes());
        assert_eq!(serde_json::to_string(&manifest).unwrap(), input);
    }
    for node in [
        r#"{"type":"number","enum":[0,-0.0,0e-99]}"#,
        r#"{"type":"number","enum":[1,1.0,1e0]}"#,
    ] {
        assert_eq!(
            decode_host_adapter_manifest(with_number_node(node).as_bytes()).unwrap_err(),
            HostManifestRejection::ContractViolation
        );
    }
}

#[test]
fn signed_fractional_and_strict_intervals_use_exact_integer_floor_and_ceil() {
    for (node, valid) in [
        (r#"{"type":"integer","minimum":-1.5,"maximum":-1.1}"#, false),
        (r#"{"type":"integer","minimum":-0.5,"maximum":0}"#, true),
        (r#"{"type":"integer","minimum":0.1,"maximum":0.9}"#, false),
        (r#"{"type":"number","minimum":0.1,"maximum":0.9}"#, true),
        (
            r#"{"type":"integer","exclusiveMinimum":-1,"exclusiveMaximum":0}"#,
            false,
        ),
        (
            r#"{"type":"integer","minimum":-1,"exclusiveMaximum":0}"#,
            true,
        ),
        (
            r#"{"type":"integer","exclusiveMinimum":0,"maximum":1}"#,
            true,
        ),
        (
            r#"{"type":"integer","minimum":1,"exclusiveMaximum":1}"#,
            false,
        ),
        (
            r#"{"type":"integer","exclusiveMinimum":1,"maximum":1}"#,
            false,
        ),
        (r#"{"type":"number","minimum":1,"maximum":1}"#, true),
        (
            r#"{"type":"number","exclusiveMinimum":1,"maximum":1}"#,
            false,
        ),
        (r#"{"type":"number","minimum":2,"maximum":1}"#, false),
        (
            r#"{"type":"integer","minimum":-0.1,"exclusiveMaximum":0}"#,
            false,
        ),
        (
            r#"{"type":"integer","exclusiveMinimum":-0.1,"maximum":0}"#,
            true,
        ),
    ] {
        let result = decode_host_adapter_manifest(with_number_node(node).as_bytes());
        if valid {
            assert!(result.is_ok(), "{node}: {result:?}");
        } else {
            assert_eq!(
                result.unwrap_err(),
                HostManifestRejection::ContractViolation,
                "{node}"
            );
        }
    }
}

#[test]
fn numeric_token_and_exponent_capacities_are_inclusive_and_exponents_never_expand() {
    for (number, error) in [
        ("1".repeat(4096), None),
        (
            "1".repeat(4097),
            Some(HostManifestRejection::NumericTokenSizeLimit),
        ),
        (format!("1e{}", "0".repeat(128)), None),
        (
            format!("1e{}", "0".repeat(129)),
            Some(HostManifestRejection::NumericExponentDigitLimit),
        ),
        (format!("1e{}", "9".repeat(128)), None),
        (format!("1e-{}", "9".repeat(128)), None),
    ] {
        let input = with_number_node(&format!(r#"{{"type":"number","minimum":{number}}}"#));
        let result = decode_host_adapter_manifest(input.as_bytes());
        match error {
            None => assert!(result.is_ok(), "{result:?}"),
            Some(error) => assert_eq!(result.unwrap_err(), error),
        }
    }
    let exponent = "9".repeat(128);
    let impossible = with_number_node(&format!(
        r#"{{"type":"integer","minimum":1e-{exponent},"maximum":0}}"#
    ));
    assert_eq!(
        decode_host_adapter_manifest(impossible.as_bytes()).unwrap_err(),
        HostManifestRejection::ContractViolation
    );
    let exact = with_number_node(&format!(
        r#"{{"type":"integer","minimum":1e{exponent},"maximum":1e{exponent}}}"#
    ));
    assert!(decode_host_adapter_manifest(exact.as_bytes()).is_ok());
}

#[test]
fn integral_protocol_spellings_are_valid_but_equivalent_duplicate_versions_are_not() {
    let valid = VALID_MANIFEST.replace("\"protocol_versions\":[1]", "\"protocol_versions\":[1.0]");
    assert!(decode_host_adapter_manifest(valid.as_bytes()).is_ok());
    let duplicate =
        VALID_MANIFEST.replace("\"protocol_versions\":[1]", "\"protocol_versions\":[1,1e0]");
    assert_eq!(
        decode_host_adapter_manifest(duplicate.as_bytes()).unwrap_err(),
        HostManifestRejection::ContractViolation
    );
}

#[test]
fn literal_private_serde_tokens_remain_ordinary_property_names_and_objects() {
    let input = with_raw_schema(
        r#"{"type":"object","properties":{"$serde_json::private::Number":{"type":"string"},"$serde_json::private::RawValue":{"type":"null"}},"additionalProperties":false}"#,
    );
    assert!(decode_host_adapter_manifest(input.as_bytes()).is_ok());
    let object =
        with_number_node(r#"{"type":"number","const":{"$serde_json::private::Number":"1"}}"#);
    assert_eq!(
        decode_host_adapter_manifest(object.as_bytes()).unwrap_err(),
        HostManifestRejection::ContractViolation
    );
}

#[test]
fn host_semver_core_ranges_are_unbounded_lexically_and_inclusive_by_precedence() {
    let large = "18446744073709551616";
    let next = "18446744073709551617";
    for index in 0..3 {
        let mut lower = ["0", "0", "0"];
        let mut upper = lower;
        lower[index] = large;
        upper[index] = next;
        let lower = lower.join(".");
        let upper = upper.join(".");
        let mut manifest = valid();
        manifest["host_version_constraints"][0]["minimum"] = json!(lower);
        assert!(decode_host_adapter_manifest(&encode(&manifest)).is_ok());
        manifest["host_version_constraints"][0]["maximum"] = json!(upper);
        assert!(decode_host_adapter_manifest(&encode(&manifest)).is_ok());
        manifest["host_version_constraints"][0]["minimum"] = json!(upper);
        manifest["host_version_constraints"][0]["maximum"] = json!(lower);
        assert_eq!(
            decode_host_adapter_manifest(&encode(&manifest)).unwrap_err(),
            HostManifestRejection::ContractViolation
        );
    }
    let sequence = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ];
    for pair in sequence.windows(2) {
        for (minimum, maximum, valid) in [(pair[0], pair[1], true), (pair[1], pair[0], false)] {
            let mut manifest = self::valid();
            manifest["host_version_constraints"][0]["minimum"] = json!(minimum);
            manifest["host_version_constraints"][0]["maximum"] = json!(maximum);
            assert_eq!(
                decode_host_adapter_manifest(&encode(&manifest)).is_ok(),
                valid
            );
        }
    }
    for (minimum, maximum) in [
        ("1.0.0-18446744073709551616", "1.0.0-18446744073709551617"),
        ("1.0.0-9", "1.0.0-alpha"),
        ("1.0.0-a", "1.0.0-a.0"),
        ("1.0.0-A", "1.0.0-a"),
        ("1.2.3+001", "1.2.3+other.9"),
        ("1.2.3+other.9", "1.2.3+001"),
        ("1.2.3-a+001", "1.2.3-a+other"),
    ] {
        let mut manifest = valid();
        manifest["host_version_constraints"][0]["minimum"] = json!(minimum);
        manifest["host_version_constraints"][0]["maximum"] = json!(maximum);
        assert!(decode_host_adapter_manifest(&encode(&manifest)).is_ok());
    }
}

#[test]
fn host_semver_rejects_invalid_lexemes_without_restricting_valid_identifier_sizes() {
    for version in [
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2",
        "1.2.3.4",
        "v1.2.3",
        "1.2.3-01",
        "1.2.3-",
        "1.2.3-a..b",
        "1.2.3+",
        "1.2.3+a..b",
        "1.2.3+a+b",
        " 1.2.3",
        "1.2.3-ä",
    ] {
        let mut manifest = valid();
        manifest["host_version_constraints"][0]["minimum"] = json!(version);
        assert_eq!(
            decode_host_adapter_manifest(&encode(&manifest)).unwrap_err(),
            HostManifestRejection::ContractViolation,
            "{version}"
        );
    }
    for version in [
        "1.2.3-01a".to_owned(),
        "1.2.3--".to_owned(),
        "1.2.3+--".to_owned(),
        format!("{}.0.0-{}", "9".repeat(4096), "8".repeat(4096)),
    ] {
        let mut manifest = valid();
        manifest["host_version_constraints"][0]["minimum"] = json!(version);
        assert!(decode_host_adapter_manifest(&encode(&manifest)).is_ok());
    }
}
