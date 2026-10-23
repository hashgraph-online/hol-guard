use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_contracts::canonicalize;
use gauntlet_evidence::verify_control_opening;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}

fn signed(record: Value, key: &Ed25519KeyPair) -> Value {
    let canonical = canonicalize(record.to_string().as_bytes()).unwrap();
    json!({
        "record": record,
        "signature": STANDARD.encode(key.sign(&canonical).as_ref()),
    })
}

fn fixture() -> (Value, Value, Vec<u8>) {
    let key = key();
    let expected = json!({
        "source_sha":"source", "prefix_digest":"prefix", "bwrap_sha256":"bwrap",
        "executor_image_id":"executor", "mcp_image_id":"mcp", "package_version":"3.50.0a0",
        "private_cell":{
            "artifact_manifest_sha256":"artifacts", "initializer_sha256":"initializer",
            "native_sha256":"native", "runtime_tree_digest":"runtime",
            "idmap_runtime":"ubuntu2404-product-v1", "cpu_profile":"quota-v1"
        }
    });
    let mut settings = expected.clone();
    settings["contained_output_binding"] = json!("controller-contained-output.v1");
    settings["contained_completion_profile"] = json!("guard-contained-completion.v1");
    let plane = json!({"synthetic_plane":73});
    let builtin = signed(json!({"product_plane":plane}), &key);
    let runtime = signed(
        json!({
            "schema_version":"5.0", "settings":settings, "native_builtin_audit":builtin,
        }),
        &key,
    );
    let public_key = key.public_key().as_ref().to_vec();
    let key_hex: String = public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let control = json!({
        "control_completed":true, "sdk_exercised":true, "model_exercised":false,
        "root_imported_product":false, "image_released":true,
        "agent_cgroup_absent":true, "agent_profile_removed":true,
        "agent_remove_returncode":0, "controller_public_key_hex":key_hex,
        "developer_runtime":runtime, "plane":plane,
        "passed":true
    });
    (control, expected, public_key)
}

fn result(control: &Value, expected: &Value, key: &[u8]) -> String {
    verify_control_opening(
        &serde_json::to_vec(control).unwrap(),
        "success",
        key,
        expected,
    )
    .unwrap_err()
    .to_string()
}

#[test]
fn signed_runtime_builtin_and_outside_tuple_open_without_a_verdict() {
    let (control, expected, public_key) = fixture();
    let opened = verify_control_opening(
        &serde_json::to_vec_pretty(&control).unwrap(),
        "success",
        &public_key,
        &expected,
    )
    .unwrap();
    assert_eq!(opened.plane, control["plane"]);
    assert_eq!(opened.runtime["schema_version"], "5.0");
    assert_eq!(opened.builtin["product_plane"], control["plane"]);
    assert_eq!(opened.settings["source_sha"], expected["source_sha"]);
    assert!(opened.runtime.get("passed").is_none());
    assert_eq!(
        verify_control_opening(
            &serde_json::to_vec(&control).unwrap(),
            "injection",
            &public_key,
            &expected,
        )
        .err()
        .unwrap()
        .to_string(),
        "unknown conformance role"
    );
}

#[test]
fn failure_cleanup_key_and_runtime_tampering_refuse_in_order() {
    let (control, expected, public_key) = fixture();
    let mut changed = control.clone();
    changed["model_exercised"] = json!(true);
    assert_eq!(
        result(&changed, &expected, &public_key),
        "control failed, imported product into Root or exercised inference"
    );
    changed = control.clone();
    changed["agent_cgroup_absent"] = json!(false);
    assert_eq!(
        result(&changed, &expected, &public_key),
        "control resources survived"
    );
    changed = control.clone();
    changed["agent_remove_returncode"] = json!(false);
    assert_eq!(
        result(&changed, &expected, &public_key),
        "control resources survived"
    );
    changed = control.clone();
    changed["controller_public_key_hex"] = json!("00".repeat(32));
    assert_eq!(
        result(&changed, &expected, &public_key),
        "control key differs from outside pin"
    );
    changed = control.clone();
    changed["developer_runtime"]["record"]["settings"]["source_sha"] = json!("other");
    assert_eq!(
        result(&changed, &expected, &public_key),
        "externally pinned controller signature invalid"
    );
    changed = control.clone();
    changed["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"] =
        json!({"synthetic_plane":74});
    assert_eq!(
        result(&changed, &expected, &public_key),
        "externally pinned controller signature invalid"
    );
}

#[test]
fn independently_pinned_tuple_and_detached_plane_are_required() {
    let (control, expected, public_key) = fixture();
    let mut changed_expected = expected.clone();
    changed_expected["source_sha"] = json!("other");
    assert_eq!(
        result(&control, &changed_expected, &public_key),
        "control runtime differs from conformance tuple"
    );
    changed_expected = expected.clone();
    changed_expected["package_version"] = json!("other");
    assert_eq!(
        result(&control, &changed_expected, &public_key),
        "control package version differs from conformance tuple"
    );
    changed_expected = expected.clone();
    changed_expected["private_cell"]["native_sha256"] = json!("other");
    assert_eq!(
        result(&control, &changed_expected, &public_key),
        "control backend differs from tuple"
    );
    let mut changed = control.clone();
    changed["plane"] = json!({"synthetic_plane":74});
    assert_eq!(
        result(&changed, &expected, &public_key),
        "detached control plane differs from signed observation"
    );
    assert_eq!(
        verify_control_opening(
            br#"{"plane":{},"plane":{}}"#,
            "success",
            &public_key,
            &expected,
        )
        .err()
        .unwrap()
        .to_string(),
        "invalid deterministic control record"
    );
}

#[test]
fn exact_python_opening_ast_matches_twenty_three_signed_cases() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_control_opening_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    for (name, path) in [
        (
            "source_sha256",
            "ci/gauntlet/benchmark/local_executor_controls.py",
        ),
        (
            "custody_sha256",
            "ci/gauntlet/benchmark/developer_product_custody.py",
        ),
    ] {
        let source = manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == path)
            .unwrap();
        assert_eq!(fixture[name], source["sha256"]);
    }
    assert_eq!(fixture["schema"], "gauntlet-control-opening-fixtures.v1");
    assert_eq!(fixture["ast_statements"], "verify_control body[1:17]");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 23);
    for case in cases {
        let key: Vec<u8> = case["public_key_hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let raw = serde_json::to_vec(&case["control"]).unwrap();
        let result = verify_control_opening(
            &raw,
            case["role"].as_str().unwrap(),
            &key,
            &case["expected"],
        );
        if case["accepted"] == true {
            let actual = result.unwrap();
            let expected = &case["result"];
            assert_eq!(actual.runtime, expected["runtime"], "{}", case["name"]);
            assert_eq!(actual.builtin, expected["builtin"], "{}", case["name"]);
            assert_eq!(actual.settings, expected["settings"], "{}", case["name"]);
            assert_eq!(actual.plane, expected["plane"], "{}", case["name"]);
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case["error"],
                "{}",
                case["name"]
            );
        }
    }
}
