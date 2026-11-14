//! Configs were accepted by Python `ci_runner_config.load_config` at b4efd817.

use gauntlet_contracts::{canonical_sha256, validate_runner_declaration, RunnerConfigError};
use serde_json::{json, Value};
use std::path::Path;

fn fixture(version: u8) -> (Vec<u8>, String) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let raw = std::fs::read(root.join(format!("runner_config_v{version}.json"))).unwrap();
    let pins: Value =
        serde_json::from_slice(&std::fs::read(root.join("runner_config_pins.json")).unwrap())
            .unwrap();
    let pin = pins[version.to_string()].as_str().unwrap().to_owned();
    (raw, pin)
}

fn mutated(mut value: Value, change: impl FnOnce(&mut Value)) -> (Vec<u8>, String) {
    change(&mut value);
    let raw = serde_json::to_vec(&value).unwrap();
    let digest = canonical_sha256(&raw).unwrap();
    (raw, digest)
}

#[test]
fn seven_python_validated_versions_share_exact_canonical_digests() {
    for version in 1..=7 {
        let (raw, pin) = fixture(version);
        let declaration = validate_runner_declaration(&raw, &pin).unwrap();
        assert_eq!(declaration.version, version);
        assert_eq!(declaration.config_digest, pin);
        assert_eq!(
            declaration.record.value()["schema"],
            format!("gauntlet-ci-runner.v{version}")
        );
    }
}

#[test]
fn caller_pin_and_version_cannot_be_replaced_by_candidate_config() {
    let (raw, pin) = fixture(7);
    assert!(matches!(
        validate_runner_declaration(&raw, &"0".repeat(64)),
        Err(RunnerConfigError::DigestMismatch)
    ));
    assert!(matches!(
        validate_runner_declaration(&raw, "untrusted"),
        Err(RunnerConfigError::InvalidPin)
    ));
    let (changed, digest) = mutated(serde_json::from_slice(&raw).unwrap(), |value| {
        value["schema"] = json!("gauntlet-ci-runner.v6");
    });
    assert!(validate_runner_declaration(&changed, &digest).is_err());
    assert_eq!(canonical_sha256(&raw).unwrap(), pin);
}

#[test]
fn python_negative_declarations_fail_before_asset_use() {
    let (raw, _) = fixture(7);
    let original: Value = serde_json::from_slice(&raw).unwrap();
    let changes: [fn(&mut Value); 8] = [
        |value| value["shards"] = json!(10_000),
        |value| value["assets"]["node"]["path"] = json!("a//node"),
        |value| value["assets"]["node"]["path"] = json!("../node"),
        |value| value["assets"]["node"]["path"] = json!("node-v2"),
        |value| value["assets"]["sdk"]["kind"] = json!("file"),
        |value| value["assets"]["wheel"] = Value::Null,
        |value| value["runtime"]["base_url"] = json!("http://remote.test:8002/v1"),
        |value| value["runtime"]["private_cell"]["native_sha256"] = json!("0".repeat(64)),
    ];
    for change in changes {
        let (candidate, digest) = mutated(original.clone(), change);
        assert!(validate_runner_declaration(&candidate, &digest).is_err());
    }
}
