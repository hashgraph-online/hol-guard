//! Live-authority and replay checks of the `validate_cached` kind.

use serde_json::{json, Value};

use super::judge;

fn v1_verdict() -> Value {
    json!({
        "ok": true,
        "contract": "v1",
        "payload_keys": ["bundleVersion", "bundleHash", "rolloutState", "payloadHash"],
        "payload_hash": "sha256:computed",
        "anchored_keys": [],
    })
}

fn v1_bundle(version: u64, rollout: &str) -> Value {
    json!({
        "bundleVersion": version,
        "bundleHash": format!("sha256:bundle-{version}"),
        "rolloutState": rollout,
        "payloadHash": "sha256:claimed",
        "unsigned": "dropped",
    })
}

#[test]
fn an_accepted_live_bundle_keeps_its_verdict() {
    let verdict = judge(&v1_bundle(3, "enforcing"), v1_verdict(), &Value::Null).unwrap();
    assert_eq!(verdict, v1_verdict());
}

#[test]
fn a_rejection_passes_through_unchanged() {
    let rejected = json!({"error": "signing_key_revoked", "anchored_keys": []});
    let verdict = judge(&v1_bundle(3, "enforcing"), rejected.clone(), &Value::Null).unwrap();
    assert_eq!(verdict, rejected);
}

#[test]
fn an_inactive_rollout_is_not_live_authority() {
    let verdict = judge(&v1_bundle(3, "draft"), v1_verdict(), &Value::Null).unwrap();
    assert_eq!(verdict["error"], "inactive_rollout_state");
}

#[test]
fn rollout_state_outside_the_signed_payload_is_ignored() {
    let mut verdict = v1_verdict();
    verdict["payload_keys"] = json!(["bundleVersion", "bundleHash", "payloadHash"]);
    let judged = judge(&v1_bundle(3, "enforcing"), verdict, &Value::Null).unwrap();
    assert_eq!(judged["error"], "inactive_rollout_state");
}

#[test]
fn an_older_bundle_than_the_checkpoint_is_a_downgrade() {
    let checkpoint = json!({"bundleVersion": 4, "bundleHash": "sha256:bundle-4"});
    let verdict = judge(&v1_bundle(3, "enforcing"), v1_verdict(), &checkpoint).unwrap();
    assert_eq!(verdict["error"], "bundle_version_downgrade");
}

#[test]
fn the_same_or_a_newer_bundle_is_not_a_downgrade() {
    for accepted in [3, 2] {
        let checkpoint = json!({
            "bundleVersion": accepted,
            "bundleHash": format!("sha256:bundle-{accepted}"),
            "cloudExceptionsHash": "sha256:ignored",
        });
        let verdict = judge(&v1_bundle(3, "enforcing"), v1_verdict(), &checkpoint).unwrap();
        assert_eq!(verdict, v1_verdict());
    }
}

#[test]
fn the_same_version_with_another_hash_is_a_downgrade() {
    let checkpoint = json!({"bundleVersion": 3, "bundleHash": "sha256:other"});
    let verdict = judge(&v1_bundle(3, "enforcing"), v1_verdict(), &checkpoint).unwrap();
    assert_eq!(verdict["error"], "bundle_version_downgrade");
}

#[test]
fn a_v2_bundle_is_live_and_judged_whole() {
    let bundle = json!({
        "contractVersion": "guard-policy-bundle.v2",
        "bundleVersion": 2,
        "bundleHash": "sha256:v2",
    });
    let verdict = json!({"ok": true, "contract": "v2", "anchored_keys": []});
    assert_eq!(
        judge(&bundle, verdict.clone(), &Value::Null).unwrap(),
        verdict
    );
    let checkpoint = json!({"bundleVersion": 5, "bundleHash": "sha256:newer"});
    let judged = judge(&bundle, verdict, &checkpoint).unwrap();
    assert_eq!(judged["error"], "bundle_version_downgrade");
}

#[test]
fn a_v1_verdict_without_payload_fields_is_invalid() {
    let verdict = json!({"ok": true, "contract": "v1"});
    assert!(judge(&v1_bundle(3, "enforcing"), verdict, &Value::Null).is_err());
}
