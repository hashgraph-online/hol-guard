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

fn retraction(bundle_hash: &str, bundle_version: &str) -> Value {
    json!({
        "appliedAt": AT,
        "bundleHash": bundle_hash,
        "bundleVersion": bundle_version,
        "deviceId": "dev-1",
        "deviceName": "Dev One",
        "status": "failed",
    })
}

#[test]
fn v2_failure_after_applied_retracts_it_in_the_legacy_shape() {
    // Cloud refuses a v2 applied -> failed transition, and a refused
    // sync-context acknowledgement would fail the whole sync. A legacy failed
    // acknowledgement replaces the stored v2 one instead.
    let previous = generic_ack(2, "applied", Value::Null);
    assert_eq!(
        failed(&v2_bundle(json!([])), "wrong_workspace", previous),
        retraction(HASH, "8")
    );
}

#[test]
fn failure_retracts_the_acknowledgement_of_another_bundle() {
    let mut previous = generic_ack(5, "applied", Value::Null);
    previous["bundleVersion"] = json!(7);
    let ack = failed(&v2_bundle(json!([])), "wrong_workspace", previous);
    assert_eq!(ack, retraction(HASH, "7"));
}

#[test]
fn dropped_bundle_retracts_the_synced_acknowledgement() {
    let previous = json!({
        "appliedAt": "2026-07-15T11:00:00Z",
        "bundleHash": "sha256:previous-bundle",
        "bundleVersion": "policy-2026-06-05.4",
        "deviceId": "dev-1",
        "status": "synced",
    });
    let ack = failed(&json!({}), "wrong_workspace", previous);
    assert_eq!(
        ack,
        retraction("sha256:previous-bundle", "policy-2026-06-05.4")
    );
}

#[test]
fn managed_applied_acknowledgement_is_retracted() {
    let mut previous = generic_ack(4, "applied", Value::Null);
    previous["deliveryId"] = json!("delivery-1");
    let managed = v2_bundle(json!([{"x-hol-extension-targets": []}]));
    assert_eq!(
        failed(&managed, "wrong_workspace", previous),
        retraction(HASH, "8")
    );
}

#[test]
fn stored_legacy_failure_is_resent_for_any_rejected_bundle() {
    let first = failed(&json!({}), "wrong_workspace", retraction("sha256:old", "3"));
    assert_eq!(first, retraction("sha256:old", "3"));
    let again = run_page(
        "failed_ack",
        failed_request(
            &v2_bundle(json!([])),
            "wrong_workspace",
            first.clone(),
            LATER,
        ),
    )["ack"]
        .clone();
    assert_eq!(again, first);
}

#[test]
fn dropped_bundle_without_any_acknowledgement_reports_nothing() {
    assert_eq!(
        failed(&json!({}), "wrong_workspace", Value::Null),
        json!({})
    );
}

#[test]
fn acknowledgement_without_identity_is_not_retracted() {
    let previous = json!({"deviceId": "dev-1", "status": "synced", "bundleVersion": 0});
    assert_eq!(failed(&json!({}), "wrong_workspace", previous), json!({}));
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
fn retained_bundle_keeps_the_stored_failure_of_another_bundle() {
    let mut other = generic_ack(2, "failed", json!("wrong_workspace"));
    other["bundleVersion"] = json!(9);
    other["bundleHash"] = json!(format!("sha256:{}", "2".repeat(64)));
    assert_eq!(retained(other.clone()), other);
    let mut foreign_device = generic_ack(2, "failed", json!("wrong_workspace"));
    foreign_device["deviceId"] = json!("dev-2");
    assert_eq!(retained(foreign_device.clone()), foreign_device);
}

#[test]
fn retained_bundle_keeps_a_stored_applied_acknowledgement() {
    let applied = generic_ack(4, "applied", Value::Null);
    assert_eq!(retained(applied.clone()), applied);
}
