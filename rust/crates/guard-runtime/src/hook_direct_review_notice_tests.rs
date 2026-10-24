//! Replays Claude Code review-notice vectors recorded from the original
//! Python implementation (see
//! `testdata/guard_store/record_claude_review_notice_vectors.py`). Every
//! expected op argument comes from Python, never from Rust output.

use super::super::CLAUDE_CODE;
use super::*;
use crate::policy_store::policy_store_direct_lane::{DirectLaneBinding, DirectLaneIntegrityKey};
use zeroize::Zeroizing;

const VECTORS: &str = include_str!("../testdata/guard_store/claude_review_notice_vectors.json");

fn vectors() -> Value {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-claude-review-notice-vectors.v1");
    vectors
}

#[test]
fn replays_every_recorded_notice() {
    let vectors = vectors();
    let now = vectors["now"].as_str().unwrap();
    let code = vectors["approval_code"].as_str().unwrap();
    let mut replayed = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let built = notice(
            scenario["harness"].as_str().unwrap(),
            scenario["payload"].as_object().unwrap(),
            scenario["result"].as_object().unwrap(),
            scenario["binding"].as_str(),
            scenario["workspace"].as_str().unwrap(),
            now,
            code,
        )
        .unwrap_or_else(|defer| panic!("{name}: {defer:?}"));
        let calls = scenario["calls"].as_array().unwrap();
        let Some(built) = built else {
            assert!(calls.is_empty(), "{name}: Python recorded a notice");
            replayed += 1;
            continue;
        };
        assert_eq!(calls.len(), 1, "{name}: one op call");
        let call = &calls[0];
        assert_eq!(call["op"], "claude_record_notice", "{name}");
        assert_eq!(call["create_key"], true, "{name}");
        assert_eq!(call["now"], now, "{name}: clock");
        assert_eq!(call["session_id"], built.session_id.as_str(), "{name}");
        assert_eq!(call["tool_name"], json!(built.tool_name), "{name}");
        assert_eq!(call["payload"], Value::Object(built.payload), "{name}");
        replayed += 1;
    }
    assert!(replayed >= 15, "only {replayed} recorded scenarios");
}

#[test]
fn a_reason_python_would_stringify_defers() {
    let vectors = vectors();
    let scenario = &vectors["scenarios"][0];
    let mut result = scenario["result"].as_object().unwrap().clone();
    result.insert("reason".to_owned(), json!(7));
    let built = notice(
        CLAUDE_CODE,
        scenario["payload"].as_object().unwrap(),
        &result,
        Some("rb-1"),
        "/work/space",
        "2026-03-01T13:00:00.654321+00:00",
        "0a1b2c3d4e5f",
    );
    assert!(built.is_err());
}

fn args_for(
    payload: &Map<String, Value>,
    binding: &DirectLaneBinding,
) -> Result<Option<Value>, HookDirectDefer> {
    let result = json!({"decision": "review", "reason": "Deletes files."});
    let context = Context {
        harness: CLAUDE_CODE,
        payload,
        recorded_payload: payload,
        workspace: "/work/space",
        home_dir: "/home/user",
        guard_home: "/home/user/.hol-guard",
        binding,
        hint: None,
    };
    store_args(&context, result.as_object().unwrap(), Some("rb-1"))
}

#[test]
fn only_a_keyed_binding_records_a_session_notice() {
    let payload = vectors()["scenarios"][0]["payload"]
        .as_object()
        .unwrap()
        .clone();
    let mut binding = super::super::super::tests::binding();
    binding.integrity_key = None;
    let unkeyed = Context {
        harness: CLAUDE_CODE,
        payload: &payload,
        recorded_payload: &payload,
        workspace: "/work/space",
        home_dir: "/home/user",
        guard_home: "/home/user/.hol-guard",
        binding: &binding,
        hint: None,
    };
    let result = json!({"decision": "review"});
    assert!(store_args(&unkeyed, result.as_object().unwrap(), None).is_err());
    // A hook without a session records no notice, so needs no key.
    let mut sessionless = payload.clone();
    sessionless.remove("session_id");
    assert_eq!(args_for(&sessionless, &binding), Ok(None));

    binding.integrity_key = Some(DirectLaneIntegrityKey {
        key: Zeroizing::new(vec![7; 32]),
        key_id: "bound".to_owned(),
    });
    let args = args_for(&payload, &binding).unwrap().unwrap();
    assert_eq!(args["session_id"], "sess-1");
    assert_eq!(args["tool_name"], "Bash");
    assert_eq!(args["integrity_key_id"], "bound");
    assert_eq!(args["payload"]["saved_at"], args["now"]);
    let code = args["payload"]["approval_code"].as_str().unwrap();
    assert!(code.len() == 12 && code.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let key = Base64UrlUnpadded::decode_vec(args["integrity_key_b64"].as_str().unwrap()).unwrap();
    assert_eq!(key, vec![7; 32]);
}
