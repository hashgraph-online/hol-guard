use serde_json::{json, Value};

use super::*;

fn handshake(listed: Value) -> Value {
    dispatch(&json!({ "supported_protocol_versions": listed })).unwrap()
}

#[test]
fn a_client_without_versions_gets_the_current_version() {
    let answer = handshake(json!([]));
    assert_eq!(answer["negotiated_version"], "1.1");
    assert_eq!(
        answer["protocol"],
        json!({
            "current_version": "1.1",
            "minimum_version": "1.0",
            "supported_versions": ["1.1", "1.0"],
            "compatibility": "same-major",
            "negotiated_version": "1.1",
        })
    );
}

#[test]
fn negotiation_picks_the_newest_same_major_version() {
    for (listed, expected) in [
        (json!(["1.0"]), json!("1.1")),
        (json!(["1.7"]), json!("1.1")),
        (json!(["1"]), json!("1.1")),
        (json!([5, "1.0"]), json!("1.1")),
        (json!(["99.0"]), Value::Null),
        (json!(["2.0", "0.9"]), Value::Null),
        (json!([1, null]), Value::Null),
    ] {
        let answer = handshake(listed.clone());
        assert_eq!(answer["negotiated_version"], expected, "{listed}");
        assert_eq!(answer["protocol"]["negotiated_version"], expected);
    }
}

#[test]
fn the_contract_keeps_the_published_shape() {
    let contract = handshake(json!([]))["contract"].clone();
    assert_eq!(contract["schema_version"], "guard-surface-server.v1");
    assert_eq!(contract["protocol_versions"], json!(["1.1", "1.0"]));
    assert!(contract["protocol"].get("negotiated_version").is_none());
    let entities = contract["entities"].as_object().unwrap();
    assert_eq!(
        entities.keys().collect::<Vec<_>>(),
        ["item", "operation", "runtime_snapshot", "session"]
    );
    assert_eq!(
        entities["session"]["states"],
        json!(["created", "attached", "active", "idle", "archived"])
    );
    assert_eq!(
        entities["operation"]["json_schema"]["required"],
        entities["operation"]["required_fields"]
    );
    assert_eq!(entities["item"]["states"], json!(["created", "completed"]));
    let snapshot = &entities["runtime_snapshot"];
    assert!(snapshot.get("states").is_none());
    assert_eq!(snapshot["required_fields"].as_array().unwrap().len(), 19);
    let pairing = &snapshot["json_schema"]["properties"]["cloud_pairing_state"];
    assert_eq!(pairing["required"].as_array().unwrap().len(), 8);
    assert_eq!(
        pairing["properties"]["state"]["enum"],
        json!(["local_only", "paired_waiting", "paired_active"])
    );
    assert_eq!(contract["methods"].as_array().unwrap().len(), 9);
    assert_eq!(contract["notifications"][3], "operation/waitingApproval");
}

#[test]
fn malformed_arguments_are_refused() {
    for args in [
        json!([]),
        json!({}),
        json!({"supported_protocol_versions": "1.0"}),
        json!({"supported_protocol_versions": null}),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
