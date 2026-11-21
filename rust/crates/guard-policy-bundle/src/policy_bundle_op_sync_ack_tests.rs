//! The stored acknowledgement the cloud sync may report.

use serde_json::{json, Value};

use super::sync_acknowledgement;
use crate::policy_bundle_op::Fail;
use crate::policy_bundle_py::Obj;

const HASH: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn input(ack: Value, bundle: Option<Value>) -> Obj {
    let mut request = json!({"ack": ack, "device_id": "dev-1", "device_name": "Dev One"});
    if let Some(bundle) = bundle {
        request["bundle"] = bundle;
    }
    request.as_object().unwrap().clone()
}

fn v2_ack() -> Value {
    json!({
        "contractVersion": "guard-policy-bundle.v2",
        "workspaceId": "workspace-alpha",
        "deviceId": "dev-1",
        "bundleVersion": 8,
        "bundleHash": HASH,
        "sequence": 1,
        "status": "applied",
        "observedAt": "2026-07-15T12:00:00Z",
        "errorCode": null,
    })
}

fn v1_ack() -> Value {
    json!({
        "bundleHash": "sha256:bundle-3",
        "bundleVersion": "3",
        "deviceId": "dev-1",
        "deviceName": "Dev One",
        "status": "synced",
        "appliedAt": "2026-07-15T12:00:00Z",
    })
}

fn v1_bundle() -> Value {
    json!({"bundleHash": "sha256:bundle-3", "bundleVersion": "3"})
}

fn reported(ack: Value, bundle: Option<Value>) -> Value {
    sync_acknowledgement(&input(ack, bundle)).unwrap()
}

#[test]
fn a_valid_v2_acknowledgement_is_reported_without_a_bundle() {
    assert_eq!(reported(v2_ack(), None), json!({"ack": v2_ack()}));
}

#[test]
fn an_invalid_v2_acknowledgement_is_dropped() {
    let mut ack = v2_ack();
    ack["status"] = json!("unknown");
    assert_eq!(reported(ack, None), json!({"ack": null}));
}

#[test]
fn a_legacy_acknowledgement_asks_for_the_validated_bundle() {
    assert_eq!(reported(v1_ack(), None), json!({"needs_bundle": true}));
}

#[test]
fn a_legacy_acknowledgement_without_a_validated_bundle_is_dropped() {
    assert_eq!(reported(v1_ack(), Some(Value::Null)), json!({"ack": null}));
}

#[test]
fn a_matching_legacy_acknowledgement_is_reported() {
    assert_eq!(
        reported(v1_ack(), Some(v1_bundle())),
        json!({"ack": v1_ack()})
    );
}

#[test]
fn a_naive_applied_at_is_accepted() {
    let mut ack = v1_ack();
    ack["appliedAt"] = json!("2026-07-15T12:00:00");
    assert_eq!(
        reported(ack.clone(), Some(v1_bundle())),
        json!({"ack": ack})
    );
}

#[test]
fn each_legacy_mismatch_drops_the_acknowledgement() {
    let changes = [
        ("bundleHash", json!("sha256:bundle-4")),
        ("bundleVersion", json!("4")),
        ("bundleVersion", json!(3)),
        ("deviceId", json!("dev-2")),
        ("deviceName", json!("Dev Two")),
        ("status", json!("failed")),
        ("appliedAt", json!("yesterday")),
        ("appliedAt", json!("   ")),
        ("appliedAt", json!(17)),
    ];
    for (field, value) in changes {
        let mut ack = v1_ack();
        ack[field] = value;
        assert_eq!(
            reported(ack, Some(v1_bundle())),
            json!({"ack": null}),
            "{field}"
        );
    }
}

#[test]
fn a_bundle_without_a_hash_or_version_matches_nothing() {
    for bundle in [
        json!({"bundleVersion": "3"}),
        json!({"bundleHash": "sha256:bundle-3", "bundleVersion": " "}),
        json!({"bundleHash": "sha256:bundle-3", "bundleVersion": 3}),
    ] {
        assert_eq!(reported(v1_ack(), Some(bundle)), json!({"ack": null}));
    }
}

#[test]
fn a_malformed_request_is_invalid() {
    let mut request = input(v1_ack(), Some(json!("bundle")));
    assert!(matches!(sync_acknowledgement(&request), Err(Fail::Invalid)));
    request.remove("device_name");
    request.remove("bundle");
    assert!(sync_acknowledgement(&request).is_err());
    let not_an_object = input(json!("ack"), None);
    assert!(matches!(
        sync_acknowledgement(&not_an_object),
        Err(Fail::Invalid)
    ));
}
