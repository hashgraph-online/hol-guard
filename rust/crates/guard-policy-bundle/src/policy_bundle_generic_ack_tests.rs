//! Acknowledgements for v2 bundles without Extension semantics.

use serde_json::{json, Value};

use crate::policy_bundle_op_vectors_tests::run_page;

const HASH: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_HASH: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const AT: &str = "2026-07-15T12:00:00Z";

fn bundle(rules: Value) -> Value {
    json!({
        "contractVersion": "guard-policy-bundle.v2",
        "workspaceId": "workspace-alpha",
        "bundleHash": HASH,
        "bundleVersion": 8,
        "payload": {"metadata": {"revision": 3}, "spec": {"rules": rules}},
    })
}

fn ack_request(bundle: &Value, status: &str, previous: Value) -> Value {
    json!({
        "device_id": "dev-1",
        "device_name": "Dev One",
        "bundle_chunks": [bundle.to_string()],
        "synced_at": AT,
        "status": status,
        "previous": previous,
        "delivery": null,
        "applied_revision": null,
        "applied_digest": null,
    })
}

fn generic_ack(sequence: u64, status: &str) -> Value {
    json!({
        "contractVersion": "guard-policy-bundle.v2",
        "workspaceId": "workspace-alpha",
        "deviceId": "dev-1",
        "bundleVersion": 8,
        "bundleHash": HASH,
        "sequence": sequence,
        "status": status,
        "observedAt": AT,
        "errorCode": null,
    })
}

fn verdict(ack: Value, previous: Value) -> Value {
    run_page(
        "v2_acknowledgement",
        json!({"ack": ack, "previous": previous}),
    )
}

#[test]
fn unmanaged_bundle_gets_a_generic_acknowledgement() {
    let result = run_page(
        "ack_payload",
        ack_request(&bundle(json!([])), "applied", Value::Null),
    );
    assert_eq!(result, json!({"ack": generic_ack(1, "applied")}));
}

#[test]
fn generic_acknowledgement_continues_its_sequence() {
    let previous = generic_ack(1, "applied");
    let result = run_page(
        "ack_payload",
        ack_request(&bundle(json!([])), "validated", previous),
    );
    assert_eq!(result, json!({"ack": generic_ack(2, "applied")}));
}

#[test]
fn a_new_bundle_restarts_the_sequence() {
    let mut previous = generic_ack(4, "applied");
    previous["bundleHash"] = json!(OTHER_HASH);
    let result = run_page(
        "ack_payload",
        ack_request(&bundle(json!([])), "validated", previous),
    );
    assert_eq!(result, json!({"ack": generic_ack(1, "validated")}));
}

#[test]
fn a_bundle_cloud_cannot_acknowledge_still_gets_no_acknowledgement() {
    let mut bare_hash = bundle(json!([]));
    bare_hash["bundleHash"] = json!("b".repeat(64));
    let result = run_page(
        "ack_payload",
        ack_request(&bare_hash, "applied", Value::Null),
    );
    assert_eq!(result, json!({"ack": {}}));
}

#[test]
fn managed_bundle_without_delivery_is_not_acknowledged() {
    let managed = bundle(json!([{"x-hol-extension-targets": []}]));
    let result = run_page("ack_payload", ack_request(&managed, "applied", Value::Null));
    assert_eq!(result, json!({"ack": {}}));
}

#[test]
fn activating_an_unmanaged_bundle_acknowledges_it() {
    let result = run_page(
        "effective_ack",
        json!({
            "device_id": "dev-1",
            "device_name": "Dev One",
            "effective_chunks": [bundle(json!([])).to_string()],
            "validated": {"bundleHash": HASH},
            "delivery": null,
            "stored": null,
            "synced_at": AT,
        }),
    );
    assert_eq!(result, json!({"ack": generic_ack(1, "applied")}));
}

#[test]
fn validator_accepts_the_generic_shape() {
    assert_eq!(
        verdict(generic_ack(1, "applied"), Value::Null),
        json!({"ok": true})
    );
    assert_eq!(
        verdict(generic_ack(2, "applied"), generic_ack(1, "validated")),
        json!({"ok": true})
    );
}

#[test]
fn validator_rejects_malformed_generic_acknowledgements() {
    let mut unknown = generic_ack(1, "applied");
    unknown["surprise"] = json!(true);
    assert_eq!(
        verdict(unknown, Value::Null),
        json!({"error": "unknown_field"})
    );

    let mut missing = generic_ack(1, "applied");
    missing.as_object_mut().unwrap().remove("bundleHash");
    assert_eq!(
        verdict(missing, Value::Null),
        json!({"error": "missing_required_field"})
    );

    let mut weak_hash = generic_ack(1, "applied");
    weak_hash["bundleHash"] = json!("h");
    assert_eq!(
        verdict(weak_hash, Value::Null),
        json!({"error": "invalid_acknowledgement"})
    );

    let mut zero = generic_ack(1, "applied");
    zero["sequence"] = json!(0);
    assert_eq!(
        verdict(zero, Value::Null),
        json!({"error": "invalid_acknowledgement"})
    );
}

#[test]
fn generic_acknowledgement_cannot_follow_a_delivery() {
    let mut managed_previous = generic_ack(1, "applied");
    managed_previous["deliveryId"] = json!("123e4567-e89b-42d3-a456-426614174000");
    assert_eq!(
        verdict(generic_ack(2, "applied"), managed_previous),
        json!({"error": "acknowledgement_identity_mismatch"})
    );
}
