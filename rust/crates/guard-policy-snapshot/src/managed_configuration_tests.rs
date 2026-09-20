use crate::*;
use serde_json::{json, Value};

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/native-policy-snapshot/v4/managed-configuration-vector.json"
    ))
    .unwrap()
}
fn check(snapshot: &PolicySnapshotV4, key: &[u8]) -> Result<(), SnapshotError> {
    validate_v4(snapshot, 7, &"a".repeat(64), &"b".repeat(64), key, 1500)
}

#[test]
fn authenticates_actual_python_managed_origin_projection() {
    let vector = vector();
    let snapshot: PolicySnapshotV4 = serde_json::from_value(vector["snapshot"].clone()).unwrap();
    let key = hex::decode(vector["verifierKeyHex"].as_str().unwrap()).unwrap();
    assert_eq!(check(&snapshot, &key), Ok(()));
    assert_eq!(
        digest_bytes(&snapshot_signing_bytes_v4(&snapshot).unwrap()),
        vector["signingBytesSha256"]
    );
    let origin = snapshot.scoped_authority.managed_config().unwrap();
    assert_eq!(
        origin.effective_policy().risk_actions["local_secret_read"],
        "block"
    );
    assert_eq!(origin.mode(), snapshot.mode);
    assert_eq!(origin.source_digest().len(), 64);
    assert!(!origin.default_action_present());
}

#[test]
fn strict_managed_wire_refuses_null_unknown_missing_and_invalid_values() {
    let snapshot = vector()["snapshot"].clone();
    for (path, replacement) in [
        ("/scoped_authority/managed_config", Value::Null),
        ("/scoped_authority/managed_config/schema", json!("future")),
        (
            "/scoped_authority/managed_config/source_digest",
            json!("F".repeat(64)),
        ),
        ("/scoped_authority/managed_config/mode", json!(true)),
        (
            "/scoped_authority/managed_config/default_action_present",
            json!(1),
        ),
        (
            "/scoped_authority/managed_config/default_action_present",
            json!("false"),
        ),
        (
            "/scoped_authority/managed_config/default_action_present",
            Value::Null,
        ),
        ("/scoped_authority/managed_config/mode", json!("prompt")),
        (
            "/scoped_authority/managed_config/effective_policy/default_action",
            json!("permit"),
        ),
        (
            "/scoped_authority/managed_config/effective_policy/risk_actions",
            json!({"future": "allow"}),
        ),
    ] {
        let mut changed = snapshot.clone();
        *changed.pointer_mut(path).unwrap() = replacement;
        assert!(
            serde_json::from_value::<PolicySnapshotV4>(changed).is_err(),
            "{path}"
        );
    }
    for path in [
        "/scoped_authority/managed_config",
        "/scoped_authority/managed_config/effective_policy",
    ] {
        let mut changed = snapshot.clone();
        changed
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), json!(true));
        assert!(serde_json::from_value::<PolicySnapshotV4>(changed).is_err());
    }
    for key in [
        "source_digest",
        "effective_policy",
        "mode",
        "default_action_present",
    ] {
        let mut changed = snapshot.clone();
        changed["scoped_authority"]["managed_config"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(serde_json::from_value::<PolicySnapshotV4>(changed).is_err());
    }
}

#[test]
fn managed_origin_removal_and_substitution_cannot_reuse_snapshot_mac() {
    let vector = vector();
    let key = hex::decode(vector["verifierKeyHex"].as_str().unwrap()).unwrap();
    for change in ["remove", "source", "policy", "mode", "presence"] {
        let mut value = vector["snapshot"].clone();
        match change {
            "remove" => {
                value["scoped_authority"]
                    .as_object_mut()
                    .unwrap()
                    .remove("managed_config");
            }
            "source" => {
                value["scoped_authority"]["managed_config"]["source_digest"] = json!("f".repeat(64))
            }
            "policy" => {
                value["scoped_authority"]["managed_config"]["effective_policy"]["risk_actions"]
                    ["local_secret_read"] = json!("allow")
            }
            "mode" => value["scoped_authority"]["managed_config"]["mode"] = json!("observe"),
            "presence" => {
                value["scoped_authority"]["managed_config"]["default_action_present"] = json!(true)
            }
            _ => unreachable!(),
        }
        let mut snapshot: PolicySnapshotV4 = serde_json::from_value(value).unwrap();
        assert!(check(&snapshot, &key).is_err(), "{change}");
        snapshot.policy_digest = policy_digest_v4(&snapshot).unwrap();
        assert!(check(&snapshot, &key).is_err(), "{change}");
        snapshot.integrity.mac = integrity_mac_v4(&snapshot, &key).unwrap();
        if change == "mode" {
            assert_eq!(check(&snapshot, &key), Err(SnapshotError::Mode));
        } else {
            assert_eq!(check(&snapshot, &key), Ok(()));
        }
    }
}
