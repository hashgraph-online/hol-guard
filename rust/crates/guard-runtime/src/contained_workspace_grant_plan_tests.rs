use super::*;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/workspace_grant_plan/parity_vectors.json");

fn expected(value: &Value) -> Option<ExpectedGrant> {
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect()
    };
    (!value.is_null()).then(|| ExpectedGrant {
        identity_hash: value["identity_hash"].as_str().unwrap().to_owned(),
        capabilities: strings(&value["capabilities"]),
        state_dir: value["state_dir"].as_str().map(str::to_owned),
    })
}

#[test]
fn parity_vectors_hold() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for case in cases {
        let got = grant_script_roots(
            case["plan"].as_object().unwrap(),
            expected(&case["expected"]).as_ref(),
        );
        assert_eq!(
            got.unwrap_or(Value::Null),
            case["result"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn the_reply_the_sink_reads_carries_every_vector_the_reading_holds() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let reply = evaluate(&serde_json::json!({
            "plan": case["plan"],
            "expected": case["expected"],
        }));
        if case["result"].is_null() {
            assert_eq!(
                reply["reason_code"], "pytest_restricted_invalid_command",
                "{}",
                case["name"]
            );
        } else {
            assert_eq!(reply["value"], case["result"], "{}", case["name"]);
        }
    }
}

#[test]
fn a_request_that_spells_no_plan_is_refused() {
    for input in [
        serde_json::json!({}),
        serde_json::json!({ "plan": Value::Null }),
        serde_json::json!({ "plan": ["read_only_roots"] }),
    ] {
        assert_eq!(
            evaluate(&input)["reason_code"],
            "pytest_restricted_invalid_command"
        );
    }
}

#[test]
fn a_decided_grant_the_caller_cannot_spell_is_refused_rather_than_read_as_none() {
    // A grant the caller spells wrongly must not fall through to the no-grant
    // reading, which would admit the plan as a base one on its own say-so.
    let plan = serde_json::json!({
        "profile_version": "workspace-contained-v1",
        "grant_identity_hash": Value::Null,
        "capabilities": [],
        "read_only_roots": ["/opt/tool/run.js"],
    });
    for broken in [
        serde_json::json!({ "capabilities": [] }),
        serde_json::json!({ "identity_hash": 7, "capabilities": [] }),
        serde_json::json!({ "identity_hash": "abc", "capabilities": "loopback-network" }),
        serde_json::json!({ "identity_hash": "abc", "capabilities": [7] }),
        serde_json::json!({ "identity_hash": "abc", "capabilities": [], "state_dir": 7 }),
    ] {
        let reply = evaluate(&serde_json::json!({ "plan": plan, "expected": broken }));
        assert_eq!(
            reply["reason_code"], "pytest_restricted_invalid_command",
            "{broken}"
        );
        assert!(reply.get("value").is_none(), "{broken}");
    }
}

#[test]
fn a_state_directory_the_caller_leaves_out_decides_nothing() {
    // A caller that omits `state_dir` has named no decided directory, which is
    // the same refusal as naming none: a stateful plan cannot pass by silence.
    let plan = serde_json::json!({
        "profile_version": "workspace-contained-grant-v1",
        "grant_identity_hash": "a".repeat(64),
        "capabilities": ["state-dir-read"],
        "read_only_roots": ["/opt/tool/run.js", "/home/dev/.lanectl"],
    });
    let reply = evaluate(&serde_json::json!({
        "plan": plan,
        "expected": { "identity_hash": "a".repeat(64), "capabilities": ["state-dir-read"] },
    }));
    assert_eq!(reply["reason_code"], "pytest_restricted_invalid_command");
}
