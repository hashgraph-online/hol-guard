use super::*;
use serde_json::json;

fn receipt() -> NativeHookDecisionReceiptV1 {
    serde_json::from_value(json!({
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "a".repeat(64),
        "request_id": "origin-test",
        "request_digest": "b".repeat(64),
        "harness": "codex",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 7,
        "policy_digest": "c".repeat(64),
        "rule_digest": "d".repeat(64),
        "runtime_identity": "e".repeat(64),
        "decision": "review",
        "model_output_action": "allow",
        "policy_action": "review",
        "observed_policy_action": null,
        "reason_code": "native_pre_tool_review",
        "workspace_bound": true,
        "source_ref_external_allowed": false,
        "reviewed_output_sha256": null,
        "observe_mode": false,
        "deadline_budget_ms": 100,
    }))
    .unwrap()
}

#[test]
fn origin_authentication_survives_serialization_without_changing_receipt_identity() {
    let mut original = receipt();
    let key = [0x5a; 32];
    let before = authenticated_bytes(&original).unwrap();
    authenticate_with_key(&mut original, &key).unwrap();
    assert_eq!(authenticated_bytes(&original).unwrap(), before);
    let encoded = serde_json::to_vec(&original).unwrap();
    let decoded = serde_json::from_slice(&encoded).unwrap();
    verify_with_key(&decoded, &key).unwrap();
    assert_eq!(decoded.decision_id, "a".repeat(64));
}

#[test]
fn execution_intent_evidence_is_authenticated_without_changing_decision_id() {
    let key = [0x5a; 32];
    let mut original = receipt();
    original.execution_intent_digest = Some("f".repeat(64));
    let legacy_decision_id = original.decision_id.clone();
    authenticate_with_key(&mut original, &key).unwrap();
    assert_eq!(original.decision_id, legacy_decision_id);
    verify_with_key(&original, &key).unwrap();

    original.execution_intent_digest = Some("e".repeat(64));
    assert_eq!(
        verify_with_key(&original, &key).unwrap_err(),
        INVALID_ORIGIN
    );
}

#[test]
fn every_receipt_field_is_authenticated() {
    let key = [0x5a; 32];
    let mut original = receipt();
    original.business_review_binding = Some("f".repeat(64));
    authenticate_with_key(&mut original, &key).unwrap();
    let value = serde_json::to_value(&original).unwrap();
    for (field, previous) in value.as_object().unwrap() {
        if field == "origin_authentication" {
            continue;
        }
        let mut changed = value.clone();
        changed[field] = match previous {
            serde_json::Value::String(value) => json!(format!("{value}x")),
            serde_json::Value::Number(_) => json!(99),
            serde_json::Value::Bool(value) => json!(!value),
            serde_json::Value::Null => json!("changed"),
            _ => panic!("unexpected field type: {field}"),
        };
        // Enum and bounded-schema changes may fail decoding before MAC verification.
        if let Ok(changed) = serde_json::from_value::<NativeHookDecisionReceiptV1>(changed) {
            assert_eq!(
                verify_with_key(&changed, &key).unwrap_err(),
                INVALID_ORIGIN,
                "{field}"
            );
        }
    }
}

#[test]
fn missing_malformed_wrong_key_and_wrong_domain_proofs_are_rejected() {
    let key = [0x5a; 32];
    let mut original = receipt();
    assert_eq!(
        verify_with_key(&original, &key).unwrap_err(),
        INVALID_ORIGIN
    );
    authenticate_with_key(&mut original, &key).unwrap();
    assert_eq!(
        verify_with_key(&original, &[0x5b; 32]).unwrap_err(),
        INVALID_ORIGIN
    );
    for invalid in [
        "".to_owned(),
        "0".repeat(63),
        "A".repeat(64),
        "z".repeat(64),
        "0".repeat(64),
    ] {
        original.origin_authentication = Some(invalid);
        assert_eq!(
            verify_with_key(&original, &key).unwrap_err(),
            INVALID_ORIGIN
        );
    }
    original.origin_authentication = Some(hex::encode(crate::hmac_sha256(
        &key,
        b"hol-guard.other-origin.v1\0",
        &authenticated_bytes(&original).unwrap(),
    )));
    assert_eq!(
        verify_with_key(&original, &key).unwrap_err(),
        INVALID_ORIGIN
    );
}

#[test]
fn authentication_does_not_invent_approval_or_raw_action_material() {
    let mut original = receipt();
    authenticate_with_key(&mut original, &[0x5a; 32]).unwrap();
    let value = serde_json::to_value(&original).unwrap();
    assert_eq!(value["decision"], "review");
    for forbidden in [
        "command",
        "raw_payload",
        "retry_token",
        "approval",
        "path",
        "url",
    ] {
        assert!(value.get(forbidden).is_none(), "{forbidden}");
    }
}

#[test]
fn private_request_loading_rejects_forged_origin_and_preserves_legacy_review() {
    use std::io::Write;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "guard-origin-request-{}-{suffix}",
        std::process::id()
    ));
    let root = crate::resident_state::ensure_private_directory(&path, true).unwrap();
    let key_bytes = [0x5a; 32];
    let mut key =
        crate::resident_state::private_file(&root.join("policy-verifier.key"), false, &root)
            .unwrap();
    key.write_all(&key_bytes).unwrap();
    drop(key);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let directory = crate::resident_state::ensure_private_directory(
        &root.join("workspace-review-requests"),
        true,
    )
    .unwrap();
    let mut original = receipt();
    authenticate(&store, &mut original).unwrap();
    let mut state = json!({
        "schema": "guard-native-workspace-review-request.v1",
        "version": 1,
        "request_id": "request-1",
        "status": "pending",
        "action": {"action_envelope": {"native_origin_receipt": original}},
        "intent": {}, "revision": {}, "policy": {},
    });
    let write = |state: &serde_json::Value| {
        let path = directory.join("request-1.json");
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        let mut file = crate::resident_state::private_file(&path, true, &root).unwrap();
        file.write_all(&canonical_json_bytes(state).unwrap())
            .unwrap();
    };
    write(&state);
    super::super::workspace_review_request::load(&store, "request-1").unwrap();
    assert_eq!(
        super::super::workspace_review_decision::verify_and_claim_request(
            &store,
            "request-1",
            &json!({}),
        )
        .unwrap_err(),
        "native_policy_snapshot_missing"
    );
    // Also cover loading after ordinary policy admission, preserving the
    // bot-added fixture while checking the missing-policy boundary first.
    let snapshot = super::super::tests::signed_snapshot(1, &key_bytes, &root);
    store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1", "snapshot":snapshot}))
        .unwrap();
    super::super::workspace_review_request::load(&store, "request-1").unwrap();
    state["action"]["action_envelope"]["native_origin_receipt"]["request_digest"] =
        json!("c".repeat(64));
    write(&state);
    assert_eq!(
        super::super::workspace_review_request::load(&store, "request-1").unwrap_err(),
        INVALID_ORIGIN
    );
    state["action"]["action_envelope"] = json!({});
    write(&state);
    // Historical business requests stay reviewable. Absence cannot become retry authority.
    super::super::workspace_review_request::load(&store, "request-1").unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
