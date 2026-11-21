//! Cached JSON is not a current signed package verdict.

use serde_json::{json, Value};

use super::{evaluate_case, VECTORS};

#[test]
#[cfg(not(windows))]
fn cache_authority_offline_recorded_vectors_remain_compatible() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let failures: Vec<String> = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["network"].is_null())
        .filter_map(|case| super::run_case(&vectors, case).err())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn fixture() -> (Value, Value) {
    fixture_named("offline_eval_cache_hit")
}

fn fixture_named(name: &str) -> (Value, Value) {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
        .clone();
    assert!(
        case["network"].is_null(),
        "this lane must not use a network service"
    );
    (vectors, case)
}

fn attach_allow_cache(case: &mut Value) {
    let bundle = &case["rows"]["guard_supply_chain_bundle_cache"][0];
    let mut row = serde_json::Map::new();
    for key in [
        "workspace_id",
        "bundle_version",
        "feed_snapshot_hash",
        "policy_hash",
        "scoring_version",
    ] {
        row.insert(key.into(), bundle[key].clone());
    }
    row.insert(
        "package_intent_hash".into(),
        json!(case["artifact"]["artifact_id"]
            .as_str()
            .unwrap()
            .rsplit(':')
            .next()
            .unwrap()),
    );
    row.insert(
        "decision_json".into(),
        json!(serde_json::to_string(&case["expect"]).unwrap()),
    );
    row.insert("updated_at".into(), json!("2026-05-19T00:00:00Z"));
    case["rows"]["guard_supply_chain_eval_cache"] = json!([row]);
    changed_cache(case);
}

fn seed_sync_context(case: &mut Value) {
    let row = &case["rows"]["guard_supply_chain_bundle_cache"][0];
    let response: Value = serde_json::from_str(row["response_json"].as_str().unwrap()).unwrap();
    let entries = [
        (
            "supply_chain_bundle_keyring",
            json!({
                "workspace_id": row["workspace_id"], "keys": response["verificationKeys"]
            }),
        ),
        (
            "supply_chain_bundle_entitlement",
            json!({
                "workspace_id": row["workspace_id"], "bundle_version": row["bundle_version"]
            }),
        ),
    ];
    for (key, value) in entries {
        case["rows"]["sync_state"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "state_key": key, "payload_json": serde_json::to_string(&value).unwrap(),
                "updated_at": "2026-05-19T00:00:00Z"
            }));
    }
}

fn edit_sync_context(case: &mut Value, state_key: &str, edit: impl FnOnce(&mut Value)) {
    let row = case["rows"]["sync_state"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["state_key"] == state_key)
        .unwrap();
    let mut payload: Value = serde_json::from_str(row["payload_json"].as_str().unwrap()).unwrap();
    edit(&mut payload);
    row["payload_json"] = json!(serde_json::to_string(&payload).unwrap());
}

fn current_cached_allow() -> (Value, Value) {
    let (vectors, mut case) = fixture_named("offline_bundle_allow_exception");
    attach_allow_cache(&mut case);
    case["auth_context_override"] = json!({
        "access_token": "fixture-only-token", "sync_url": "https://hol.org/api/guard/receipts/sync"
    });
    case["entitlement"] = json!({"allowed": true, "reason": "fixture_entitled"});
    case["offline_egress_error"] = json!("fixture Cloud is offline");
    seed_sync_context(&mut case);
    (vectors, case)
}

fn changed_cache(case: &mut Value) {
    let row = &mut case["rows"]["guard_supply_chain_eval_cache"][0];
    let mut decision: Value = serde_json::from_str(row["decision_json"].as_str().unwrap()).unwrap();
    decision["decision"] = json!("allow");
    decision["policy_action"] = json!("allow");
    decision["risk_summary"] = json!("unverified cached text");
    decision["packages"] = json!([]);
    decision["reasons"] = json!([]);
    row["decision_json"] = json!(serde_json::to_string(&decision).unwrap());
}

fn mutate_bundle(case: &mut Value, edit: impl FnOnce(&mut Value)) {
    let row = &mut case["rows"]["guard_supply_chain_bundle_cache"][0];
    let mut response: Value = serde_json::from_str(row["response_json"].as_str().unwrap()).unwrap();
    edit(&mut response);
    row["response_json"] = json!(serde_json::to_string(&response).unwrap());
}

fn evaluate(vectors: &Value, case: &Value) -> Value {
    let (result, sent) = evaluate_case(vectors, case).expect("native offline evaluation");
    assert!(sent.is_empty());
    result
}

#[test]
fn cache_authority_valid_bundle_retains_a_cached_block_without_egress() {
    let (vectors, case) = fixture();
    let result = evaluate(&vectors, &case);
    assert_eq!(result["decision"], "block");
    assert_eq!(result["cache_status"], "hit");
    assert_eq!(result["entitlement_state"], "unknown");
}

#[test]
fn cache_authority_changed_verdict_cannot_weaken_the_signed_package_decision() {
    let (vectors, mut case) = fixture();
    changed_cache(&mut case);
    let result = evaluate(&vectors, &case);
    assert_eq!(result["decision"], "block");
    assert_eq!(result["policy_action"], "block");
    assert_ne!(result["risk_summary"], "unverified cached text");
    assert!(result["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| { reason["code"] == "known_malware_or_kev" }));
}

#[test]
fn cache_authority_expired_bundle_cannot_replay_a_cached_allow() {
    let (mut vectors, mut case) = fixture();
    changed_cache(&mut case);
    mutate_bundle(&mut case, |response| {
        assert!(response["bundle"]["expiresAt"].as_str().unwrap() < "2100-01-01T00:00:00Z");
    });
    vectors["now"] = json!("2100-01-01T00:00:00Z");
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_invalid_payload_hash_cannot_replay_a_cached_allow() {
    let (vectors, mut case) = fixture();
    changed_cache(&mut case);
    mutate_bundle(&mut case, |response| {
        response["payloadHash"] = json!("0".repeat(64))
    });
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_revoked_signing_key_cannot_replay_a_cached_allow() {
    let (vectors, mut case) = fixture();
    changed_cache(&mut case);
    mutate_bundle(&mut case, |response| {
        let key_id = response["bundle"]["keyId"].clone();
        let key = response["verificationKeys"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|key| key["keyId"] == key_id)
            .unwrap();
        key["state"] = json!("revoked");
    });
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_foreign_workspace_bundle_is_not_current_account_intelligence() {
    let (vectors, mut case) = fixture();
    // Keep the signed response unchanged; move its database lookup to a different
    // paired workspace. A valid signature does not confer authority there.
    for table in [
        "guard_supply_chain_bundle_cache",
        "guard_supply_chain_eval_cache",
    ] {
        case["rows"][table][0]["workspace_id"] = json!("other-fixture-workspace");
    }
    for row in case["rows"]["sync_state"].as_array_mut().unwrap() {
        if row["state_key"] == "oauth_local_credentials" {
            let mut credentials: Value =
                serde_json::from_str(row["payload_json"].as_str().unwrap()).unwrap();
            credentials["workspace_id"] = json!("other-fixture-workspace");
            row["payload_json"] = json!(serde_json::to_string(&credentials).unwrap());
        }
    }
    let result = evaluate(&vectors, &case);
    assert!(result["bundle_version"].is_null());
    assert_ne!(result["enforcement"], "offline_cached");
}

#[test]
fn cache_authority_current_saved_block_cannot_reuse_changed_error_verdict_or_copy() {
    let (vectors, mut case) = fixture_named("cached_cloud_error_saved_block");
    let row = &mut case["rows"]["guard_supply_chain_eval_cache"][0];
    let mut cached: Value = serde_json::from_str(row["decision_json"].as_str().unwrap()).unwrap();
    cached["decision"] = json!("allow");
    cached["policy_action"] = json!("allow");
    cached["risk_summary"] = json!("unverified cached text");
    row["decision_json"] = json!(serde_json::to_string(&cached).unwrap());
    let result = evaluate(&vectors, &case);
    assert_eq!(result["decision"], "block");
    assert_eq!(result["policy_action"], "block");
    assert_eq!(result["entitlement_state"], "unknown");
    assert_eq!(result["enforcement"], "policy_override");
    assert_eq!(result["refresh_required"], true);
    assert!(result["bundle_version"].is_null());
    assert_ne!(result["risk_summary"], "unverified cached text");
}

#[test]
fn cache_authority_missing_current_session_cannot_promote_cached_signed_allow() {
    let (vectors, mut case) = fixture_named("offline_bundle_allow_exception");
    attach_allow_cache(&mut case);
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_current_session_and_feature_can_reuse_signed_allow_without_egress() {
    let (vectors, case) = current_cached_allow();
    let result = evaluate(&vectors, &case);
    assert_eq!(result["decision"], "allow");
    assert_eq!(result["cache_status"], "hit");
    assert_eq!(result["entitlement_state"], "premium");
    assert_ne!(result["risk_summary"], "unverified cached text");
}

#[test]
fn cache_authority_current_keyring_mismatch_cannot_reuse_a_permissive_verdict() {
    let (vectors, mut case) = current_cached_allow();
    edit_sync_context(&mut case, "supply_chain_bundle_keyring", |payload| {
        payload["keys"][0]["fingerprintSha256"] = json!("f".repeat(64));
    });
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_newer_synced_version_cannot_replay_an_older_allow() {
    let (vectors, mut case) = current_cached_allow();
    edit_sync_context(&mut case, "supply_chain_bundle_entitlement", |payload| {
        payload["bundle_version"] = json!("1747612800001-newer");
    });
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_foreign_sync_context_cannot_replay_a_permissive_verdict() {
    for state_key in [
        "supply_chain_bundle_keyring",
        "supply_chain_bundle_entitlement",
    ] {
        let (vectors, mut case) = current_cached_allow();
        edit_sync_context(&mut case, state_key, |payload| {
            payload["workspace_id"] = json!("other-fixture-workspace");
        });
        let result = evaluate(&vectors, &case);
        assert_ne!(result["decision"], "allow", "{state_key}");
        assert_ne!(result["cache_status"], "hit", "{state_key}");
    }
}

#[test]
fn cache_authority_missing_sync_keyring_cannot_establish_a_permissive_cache_hit() {
    let (vectors, mut case) = current_cached_allow();
    case["rows"]["sync_state"]
        .as_array_mut()
        .unwrap()
        .retain(|row| row["state_key"] != "supply_chain_bundle_keyring");
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_current_key_state_cannot_be_laundered_by_an_old_active_advertisement() {
    for (state, until) in [
        ("revoked", None),
        ("grace", Some("2020-01-01T00:00:00Z")),
        ("grace", None),
    ] {
        let (vectors, mut case) = current_cached_allow();
        edit_sync_context(&mut case, "supply_chain_bundle_keyring", |payload| {
            payload["keys"][0]["state"] = json!(state);
            payload["keys"][0]["validUntil"] = json!(until);
        });
        let result = evaluate(&vectors, &case);
        assert_ne!(result["decision"], "allow", "{state} {until:?}");
        assert_ne!(result["cache_status"], "hit", "{state} {until:?}");
    }
}

#[test]
fn cache_authority_current_grace_key_retains_a_verified_cache_hit() {
    let (vectors, mut case) = current_cached_allow();
    edit_sync_context(&mut case, "supply_chain_bundle_keyring", |payload| {
        payload["keys"][0]["state"] = json!("grace");
        payload["keys"][0]["validUntil"] = json!("2027-01-01T00:00:00Z");
    });
    let result = evaluate(&vectors, &case);
    assert_eq!(result["decision"], "allow");
    assert_eq!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_active_alias_cannot_hide_a_current_revocation() {
    let (vectors, mut case) = current_cached_allow();
    edit_sync_context(&mut case, "supply_chain_bundle_keyring", |payload| {
        let mut revoked = payload["keys"][0].clone();
        revoked["keyId"] = json!("fixture-revoked-alias");
        revoked["state"] = json!("revoked");
        payload["keys"].as_array_mut().unwrap().push(revoked);
    });
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_missing_sync_version_cannot_establish_a_permissive_cache_hit() {
    let (vectors, mut case) = current_cached_allow();
    case["rows"]["sync_state"]
        .as_array_mut()
        .unwrap()
        .retain(|row| row["state_key"] != "supply_chain_bundle_entitlement");
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_unavailable_feature_cannot_promote_cached_signed_allow() {
    for reason in ["free", "stale", "revoked", "unknown"] {
        let (vectors, mut case) = fixture_named("offline_bundle_allow_exception");
        attach_allow_cache(&mut case);
        case["auth_context_override"] = json!({
            "access_token": "fixture-only-token", "sync_url": "https://hol.org/api/guard/receipts/sync"
        });
        case["entitlement"] = json!({"allowed": false, "reason": reason});
        case["offline_egress_error"] = json!("fixture Cloud is offline");
        let result = evaluate(&vectors, &case);
        assert_ne!(result["decision"], "allow", "{reason}");
        assert_ne!(result["cache_status"], "hit", "{reason}");
    }
}

#[test]
fn cache_authority_untrusted_session_endpoint_cannot_promote_cached_signed_allow() {
    let (vectors, mut case) = fixture_named("offline_bundle_allow_exception");
    attach_allow_cache(&mut case);
    case["auth_context_override"] = json!({
        "access_token": "fixture-only-token", "sync_url": "https://untrusted.example/api/sync"
    });
    case["entitlement"] = json!({"allowed": true, "reason": "fixture_entitled"});
    let result = evaluate(&vectors, &case);
    assert_ne!(result["decision"], "allow");
    assert_ne!(result["cache_status"], "hit");
}

#[test]
fn cache_authority_partial_package_coverage_requires_current_evaluation() {
    let (vectors, mut case) = fixture_named("offline_bundle_multi_package");
    attach_allow_cache(&mut case);
    // This signed bundle covers both targets. The control proves this request
    // reaches the cache path before substituting another valid signed bundle.
    assert_eq!(evaluate(&vectors, &case)["cache_status"], "hit");
    let (_, one_package) = fixture();
    case["rows"]["guard_supply_chain_bundle_cache"] =
        one_package["rows"]["guard_supply_chain_bundle_cache"].clone();
    attach_allow_cache(&mut case);
    let result = evaluate(&vectors, &case);
    assert_eq!(result["decision"], "block");
    assert_ne!(result["cache_status"], "hit");
}
