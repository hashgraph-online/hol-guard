use super::*;

#[test]
fn frozen_python_discovery_vectors_are_exact() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/claude-launcher-pilot-auth.json"
    ))
    .unwrap();
    let key = hex::decode(fixture["synthetic_key_hex"].as_str().unwrap()).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        assert_eq!(
            auth::canonical(&vector["payload"]).unwrap(),
            vector["canonical"].as_str().unwrap()
        );
        assert_eq!(
            auth::sign(&key, &vector["payload"]).unwrap(),
            vector["mac"].as_str().unwrap()
        );
    }
}

#[test]
fn challenge_requires_exact_event_nonce_state_key_and_lifetime() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/claude-launcher-pilot-auth.json"
    ))
    .unwrap();
    let vector = &fixture["vectors"][3];
    let mut response = vector["payload"].clone();
    response["proof"] = vector["mac"].clone();
    let key = hex::decode(fixture["synthetic_key_hex"].as_str().unwrap()).unwrap();
    let state = auth::State {
        key,
        value: response.as_object().unwrap().clone(),
    };
    let now = response["issued_at_ms"].as_u64().unwrap();
    let nonce = "a".repeat(64);
    assert!(auth::challenge_proof(&response, &state, &nonce, "PreToolUse", now).is_ok());
    for name in [
        "state_id",
        "host",
        "port",
        "pid",
        "started_at",
        "guard_home",
        "nonce",
        "hook_event",
        "proof",
    ] {
        let mut changed = response.clone();
        changed[name] = Value::String("changed".into());
        assert!(
            auth::challenge_proof(&changed, &state, &nonce, "PreToolUse", now).is_err(),
            "{name}"
        );
    }
    assert!(auth::challenge_proof(&response, &state, &nonce, "PostToolUse", now).is_err());
    assert!(auth::challenge_proof(&response, &state, &nonce, "PreToolUse", now + 5001).is_err());
    let mut changed = response.clone();
    changed["issued_at_ms"] = Value::from(now + 1001);
    assert!(auth::challenge_proof(&changed, &state, &nonce, "PreToolUse", now).is_err());
}

#[test]
fn handoff_bounds_cover_maximum_input_and_worst_response_escaping() {
    let before = encode_handoff(
        &vec![0xff; 4_000_005],
        1,
        serde_json::json!({"kind": "before_send"}),
    )
    .unwrap();
    assert!(before.len() < 5_334_000);
    // Responses exist only on the native <=1 MB input path. Each response
    // byte can become six JSON escape bytes, larger than UTF-8 replacement.
    let response = encode_handoff(
        &vec![b'a'; 1_000_000],
        1,
        serde_json::json!({"kind": "response", "response": "\0".repeat(1_000_000)}),
    )
    .unwrap();
    assert!(response.len() < 7_334_000);
    assert!(encode_handoff(
        &vec![0; 6_000_000],
        1,
        serde_json::json!({"kind":"before_send"})
    )
    .is_err());
}
