//! Failed acknowledgements for bundles that fail local validation, and the
//! way a v2 acknowledgement climbs back to applied once the bundle validates.

use serde_json::{json, Value};

use crate::policy_bundle_op_vectors_tests::run_page;

const HASH: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const AT: &str = "2026-07-15T12:00:00Z";
const LATER: &str = "2026-07-15T12:05:00Z";

fn legacy_bundle() -> Value {
    json!({
        "contractVersion": "guard-policy-bundle.v1",
        "bundleHash": "legacy-hash",
        "bundleVersion": "7",
        "payload": {"rules": []},
    })
}

fn v2_bundle(rules: Value) -> Value {
    json!({
        "contractVersion": "guard-policy-bundle.v2",
        "workspaceId": "workspace-alpha",
        "bundleHash": HASH,
        "bundleVersion": 8,
        "payload": {"metadata": {"revision": 3}, "spec": {"rules": rules}},
    })
}

fn failed_request(bundle: &Value, error_code: &str, previous: Value, at: &str) -> Value {
    json!({
        "device_id": "dev-1",
        "device_name": "Dev One",
        "bundle_chunks": [bundle.to_string()],
        "synced_at": at,
        "error_code": error_code,
        "previous": previous,
    })
}

fn failed(bundle: &Value, error_code: &str, previous: Value) -> Value {
    run_page(
        "failed_ack",
        failed_request(bundle, error_code, previous, AT),
    )["ack"]
        .clone()
}

fn generic_ack(sequence: u64, status: &str, error_code: Value) -> Value {
    json!({
        "contractVersion": "guard-policy-bundle.v2",
        "workspaceId": "workspace-alpha",
        "deviceId": "dev-1",
        "bundleVersion": 8,
        "bundleHash": HASH,
        "sequence": sequence,
        "status": status,
        "observedAt": AT,
        "errorCode": error_code,
    })
}

fn applied_request(previous: Value) -> Value {
    json!({
        "device_id": "dev-1",
        "device_name": "Dev One",
        "bundle_chunks": [v2_bundle(json!([])).to_string()],
        "synced_at": AT,
        "status": "applied",
        "previous": previous,
        "delivery": null,
        "applied_revision": null,
        "applied_digest": null,
    })
}

#[test]
fn legacy_bundle_reports_a_failed_acknowledgement() {
    let ack = failed(&legacy_bundle(), "wrong_workspace", Value::Null);
    assert_eq!(
        ack,
        json!({
            "appliedAt": AT,
            "bundleHash": "legacy-hash",
            "bundleVersion": "7",
            "deviceId": "dev-1",
            "deviceName": "Dev One",
            "status": "failed",
        })
    );
}

#[test]
fn legacy_failure_keeps_its_first_timestamp() {
    let first = failed(&legacy_bundle(), "wrong_workspace", Value::Null);
    let again = run_page(
        "failed_ack",
        failed_request(&legacy_bundle(), "wrong_workspace", first.clone(), LATER),
    )["ack"]
        .clone();
    assert_eq!(again, first);
}

#[test]
fn legacy_failure_replaces_a_synced_acknowledgement() {
    let mut synced = failed(&legacy_bundle(), "wrong_workspace", Value::Null);
    synced["status"] = json!("synced");
    let ack = run_page(
        "failed_ack",
        failed_request(&legacy_bundle(), "wrong_workspace", synced, LATER),
    )["ack"]
        .clone();
    assert_eq!(ack["status"], "failed");
    assert_eq!(ack["appliedAt"], LATER);
}

#[test]
fn legacy_bundle_without_identity_reports_nothing() {
    let mut bundle = legacy_bundle();
    bundle.as_object_mut().unwrap().remove("bundleHash");
    assert_eq!(failed(&bundle, "wrong_workspace", Value::Null), json!({}));
}

#[test]
fn v2_bundle_reports_a_generic_failure() {
    let ack = failed(&v2_bundle(json!([])), "wrong_workspace", Value::Null);
    assert_eq!(ack, generic_ack(1, "failed", json!("wrong_workspace")));
}

#[test]
fn v2_failure_continues_a_validated_sequence() {
    let previous = generic_ack(3, "validated", Value::Null);
    let ack = failed(&v2_bundle(json!([])), "wrong_workspace", previous);
    assert_eq!(ack, generic_ack(4, "failed", json!("wrong_workspace")));
}

#[test]
fn v2_failure_with_the_same_code_is_resent_unchanged() {
    let previous = generic_ack(2, "failed", json!("wrong_workspace"));
    let ack = failed(&v2_bundle(json!([])), "wrong_workspace", previous.clone());
    assert_eq!(ack, previous);
}

#[test]
fn v2_failure_with_a_new_code_advances_the_sequence() {
    let previous = generic_ack(2, "failed", json!("wrong_workspace"));
    let ack = failed(&v2_bundle(json!([])), "policy_bundle_downgrade", previous);
    assert_eq!(
        ack,
        generic_ack(3, "failed", json!("policy_bundle_downgrade"))
    );
}

#[test]
fn v2_failure_after_applied_reports_nothing() {
    // Cloud refuses applied -> failed, and a refused sync-context
    // acknowledgement would fail the whole sync.
    let previous = generic_ack(2, "applied", Value::Null);
    assert_eq!(
        failed(&v2_bundle(json!([])), "wrong_workspace", previous),
        json!({})
    );
}

#[test]
fn v2_failure_ignores_an_acknowledgement_for_another_bundle() {
    let mut previous = generic_ack(5, "applied", Value::Null);
    previous["bundleVersion"] = json!(7);
    let ack = failed(&v2_bundle(json!([])), "wrong_workspace", previous);
    assert_eq!(ack, generic_ack(1, "failed", json!("wrong_workspace")));
}

#[test]
fn managed_bundle_reports_nothing() {
    let managed = v2_bundle(json!([{"x-hol-extension-targets": []}]));
    assert_eq!(failed(&managed, "wrong_workspace", Value::Null), json!({}));
}

#[test]
fn malformed_v2_bundle_reports_nothing() {
    let mut bundle = v2_bundle(json!([]));
    bundle["bundleHash"] = json!("not-a-digest");
    assert_eq!(failed(&bundle, "wrong_workspace", Value::Null), json!({}));
}

#[test]
fn empty_or_oversized_error_code_reports_nothing() {
    assert_eq!(failed(&legacy_bundle(), "", Value::Null), json!({}));
    let long = "x".repeat(129);
    assert_eq!(failed(&v2_bundle(json!([])), &long, Value::Null), json!({}));
}

#[test]
fn recovered_v2_bundle_climbs_back_to_applied() {
    let failure = generic_ack(2, "failed", json!("wrong_workspace"));
    let received = run_page("ack_payload", applied_request(failure))["ack"].clone();
    assert_eq!(received, generic_ack(3, "received", Value::Null));
    let validated = run_page("ack_payload", applied_request(received))["ack"].clone();
    assert_eq!(validated, generic_ack(4, "validated", Value::Null));
    let applied = run_page("ack_payload", applied_request(validated))["ack"].clone();
    assert_eq!(applied, generic_ack(5, "applied", Value::Null));
}

fn retained(stored: Value) -> Value {
    run_page(
        "effective_ack",
        json!({
            "device_id": "dev-1",
            "device_name": "Dev One",
            "effective_chunks": [v2_bundle(json!([])).to_string()],
            "validated": null,
            "delivery": null,
            "stored": stored,
            "synced_at": AT,
        }),
    )["ack"]
        .clone()
}

#[test]
fn retained_bundle_climbs_past_a_stored_failure() {
    let failure = generic_ack(2, "failed", json!("wrong_workspace"));
    assert_eq!(retained(failure), generic_ack(3, "received", Value::Null));
    let received = generic_ack(3, "received", Value::Null);
    assert_eq!(retained(received), generic_ack(4, "validated", Value::Null));
}

#[test]
fn retained_bundle_keeps_a_stored_applied_acknowledgement() {
    let applied = generic_ack(4, "applied", Value::Null);
    assert_eq!(retained(applied.clone()), applied);
}
