use super::*;
use guard_contracts::{
    GuardHookSourceMetadataV2, GUARD_HOOK_ENVELOPE_V2_SCHEMA, MAX_NATIVE_REQUEST_BYTES,
};
use serde_json::json;

fn fixture() -> GuardHookEnvelopeV2 {
    GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: None,
        harness: "claude-code".into(),
        event: "PreToolUse".into(),
        deadline_budget_ms: None,
        policy_generation: 1,
        policy_snapshot: json!({"generation":1,"policy_digest":"a".repeat(64),
            "rule_digest":"b".repeat(64),"runtime_identity":{"z":2,"a":1},
            "scope_contract":{"scope_digest":"c".repeat(64)}}),
        raw_payload: json!({"tool_name":"Bash","tool_input":{"command":"pwd", "timestamp":42}}),
        source: GuardHookSourceMetadataV2 {
            cwd: Some("/workspace".into()),
            home_dir: "/home/fixture".into(),
            guard_home: "/home/fixture/.guard".into(),
            source_ref_external_allowed: false,
        },
    }
}

// Independent copy of the previously shipped allocation-heavy identity recipe.
// Do not build expected bytes through the new borrowed wrappers or key list.
fn reference(envelope: &GuardHookEnvelopeV2) -> Vec<u8> {
    let mut payload = envelope.raw_payload.as_object().unwrap().clone();
    for key in [
        "event",
        "eventName",
        "hook_event_name",
        "hookEventName",
        "hook_name",
        "hookName",
        "timestamp",
        "timestamp_ms",
        "timestampMs",
        "created_at",
        "createdAt",
        "received_at",
        "receivedAt",
    ] {
        payload.remove(key);
    }
    let snapshot = &envelope.policy_snapshot;
    let value = json!({
        "schema":"guard-native-request-identity.v3", "version":3,
        "event":"PreToolUse", "harness":"claude-code", "payload":payload,
        "policy":{
            "generation":envelope.policy_generation,
            "policy_digest":snapshot.get("policy_digest").cloned().unwrap_or(Value::Null),
            "rule_digest":snapshot.get("rule_digest").cloned().unwrap_or(Value::Null),
            "runtime_identity":snapshot.get("runtime_identity").cloned().unwrap_or(Value::Null),
            "scope_digest":snapshot.get("scope_contract").and_then(Value::as_object)
                .and_then(|scope|scope.get("scope_digest")).cloned().unwrap_or(Value::Null),
        },
        "source": {"cwd":envelope.source.cwd, "guard_home":envelope.source.guard_home,
            "home_dir":envelope.source.home_dir,
            "source_ref_external_allowed":envelope.source.source_ref_external_allowed},
    });
    guard_policy_snapshot::canonical_json_bytes(&value).unwrap()
}

fn check_identity(envelope: &GuardHookEnvelopeV2) -> String {
    let bytes =
        serde_json::to_vec(&Identity::new(envelope, "claude-code", "PreToolUse").unwrap()).unwrap();
    assert_eq!(bytes, reference(envelope));
    let expected = hex::encode(Sha256::digest(&bytes));
    let (request_id, digest) =
        request_identity_for_event(envelope, "claude-code", "PreToolUse").unwrap();
    assert_eq!(digest, expected);
    assert_eq!(
        request_id,
        envelope
            .request_id
            .clone()
            .unwrap_or_else(|| format!("sha256:{expected}"))
    );
    digest
}

#[test]
fn borrowed_identity_preserves_legacy_bytes_and_root_only_omissions() {
    for command in [
        "pwd",
        "rm -rf /",
        "pwd && cat ~/.ssh/id_rsa",
        "printf café\n'🦀'",
    ] {
        let mut envelope = fixture();
        envelope.raw_payload["tool_input"]["command"] = json!(command);
        let original = check_identity(&envelope);
        for key in OMITTED_PAYLOAD_KEYS {
            envelope.raw_payload[*key] = json!("transport metadata");
        }
        assert_eq!(check_identity(&envelope), original);
        for key in OMITTED_PAYLOAD_KEYS {
            let mut nested = envelope.clone();
            nested.raw_payload["tool_input"][*key] = json!("semantic tool argument");
            assert_ne!(check_identity(&nested), original);
        }
    }
}

#[test]
fn borrowed_identity_binds_source_policy_and_arbitrary_json_values() {
    let envelope = fixture();
    let initial = check_identity(&envelope);
    for key in ["policy_digest", "rule_digest", "runtime_identity"] {
        for value in [Value::Null, json!([1, 2.0, false, {"z":"é", "a":null}])] {
            let mut changed = envelope.clone();
            changed.policy_snapshot[key] = value;
            assert_ne!(check_identity(&changed), initial);
        }
    }
    for field in [
        "cwd",
        "home_dir",
        "guard_home",
        "external",
        "scope",
        "generation",
    ] {
        let mut changed = envelope.clone();
        match field {
            "cwd" => changed.source.cwd = None,
            "home_dir" => changed.source.home_dir.push('x'),
            "guard_home" => changed.source.guard_home.push('x'),
            "external" => changed.source.source_ref_external_allowed = true,
            "scope" => {
                changed.policy_snapshot["scope_contract"]["scope_digest"] = json!("different")
            }
            _ => changed.policy_generation += 1,
        }
        assert_ne!(check_identity(&changed), initial);
    }
    for policy in [Value::Null, json!(false), json!([]), json!({})] {
        let mut changed = envelope.clone();
        changed.policy_snapshot = policy;
        check_identity(&changed);
    }
    let mut unchanged = envelope;
    unchanged.deadline_budget_ms = Some(7);
    unchanged.policy_snapshot["issued_at_ms"] = json!(100);
    unchanged.policy_snapshot["expires_at_ms"] = json!(200);
    unchanged.policy_snapshot["scope_contract"]["transport_metadata"] = json!("ignored");
    assert_eq!(check_identity(&unchanged), initial);
}

#[test]
fn streamed_envelope_size_preserves_exact_limit_and_rejects_one_extra_byte() {
    let mut envelope = fixture();
    envelope.raw_payload["padding"] = json!(vec!["x".repeat(1024 * 1024); 6]);
    let excess = serde_json::to_vec(&envelope).unwrap().len() - MAX_NATIVE_REQUEST_BYTES;
    envelope.raw_payload["padding"][5] = json!("x".repeat(1024 * 1024 - excess));
    assert_eq!(
        serde_json::to_vec(&envelope).unwrap().len(),
        MAX_NATIVE_REQUEST_BYTES
    );
    check_identity(&envelope);
    let validated =
        super::super::validate_envelope_shape(envelope.clone(), std::time::Instant::now()).unwrap();
    assert_eq!(validated.request_digest, check_identity(&envelope));
    let mut padding = envelope.raw_payload["padding"][5]
        .as_str()
        .unwrap()
        .to_owned();
    padding.push('x');
    envelope.raw_payload["padding"][5] = json!(padding);
    assert_eq!(
        super::super::validate_envelope_shape(envelope, std::time::Instant::now())
            .err()
            .unwrap(),
        "native_hook_request_bounds_exceeded"
    );
}

#[test]
fn malformed_payload_and_explicit_request_ids_keep_error_contract() {
    let mut envelope = fixture();
    for payload in [Value::Null, json!([]), json!(1)] {
        envelope.raw_payload = payload;
        assert_eq!(
            request_identity_for_event(&envelope, "claude-code", "PreToolUse").unwrap_err(),
            "native_hook_payload_invalid"
        );
    }
    let mut envelope = fixture();
    for id in ["token_1.0".to_owned(), "a".repeat(256)] {
        envelope.request_id = Some(id);
        check_identity(&envelope);
    }
    for id in [
        "".to_owned(),
        "a".repeat(257),
        "Token".to_owned(),
        "secret/path".to_owned(),
        "é".to_owned(),
    ] {
        envelope.request_id = Some(id);
        assert_eq!(
            request_identity_for_event(&envelope, "claude-code", "PreToolUse").unwrap_err(),
            "native_hook_request_id_invalid"
        );
    }
}
