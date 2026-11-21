use super::{answer, registry_retry, PACKAGE_REVIEW_REASON};
use serde_json::{json, Value};

fn request(action: &str, reason: Option<&str>, may_allow: bool) -> Value {
    json!({
        "verdict": {"minimum_action": "review", "reason_code": PACKAGE_REVIEW_REASON},
        "settlement": {"action": action, "reason": reason},
        "package": {
            "harness": "omp",
            "artifact_id": "omp:project:package-request:example",
            "command": "npm install 'name@1.0.0' --ignore-scripts"
        },
        "keyed": true,
        "may_allow": may_allow,
    })
}

fn settle(value: &Value) -> Value {
    Value::Object(answer("omp", value.as_object().expect("request object")))
}

#[test]
fn a_registry_block_wins_even_with_a_saved_allow() {
    let mut input = request("block", Some("The package is unsafe."), true);
    assert!(settle(&input)["lookup"].is_null());
    input["reuse"] = json!({"artifact_hash": "identity", "found": true, "policy_action": "allow"});

    let result = settle(&input);
    assert_eq!(result["response"]["decision"], "deny");
    assert_eq!(result["response"]["reason"], "The package is unsafe.");
    assert_eq!(result["response"]["prompted"], false);
    assert!(result["package_approval"].is_null());
}

#[test]
fn only_a_proven_install_can_use_evaluator_allow_or_guidance() {
    for (action, reason, decision) in [
        ("allow", None, "allow"),
        ("guide", Some("Use --ignore-scripts."), "deny"),
    ] {
        let mut input = request(action, reason, false);
        input["reuse"] = Value::Null;
        assert!(settle(&input)["response"].is_null());
        input["may_allow"] = json!(true);
        let result = settle(&input);
        assert_eq!(result["response"]["decision"], decision);
        if let Some(reason) = reason {
            assert_eq!(result["response"]["reason"], reason);
            assert_eq!(result["response"]["prompted"], false);
        }
    }
}

#[test]
fn key_lookup_uses_the_planned_argv_and_the_stamped_path_and_home() {
    let mut input = request("review", None, false);
    input["execution_environment"] = json!({
        "path": "/opt/example/bin",
        "home": "/example/agent",
        "NODE_OPTIONS": "--example",
    });
    let result = settle(&input);
    assert_eq!(
        result["lookup"],
        json!({
            "argv": ["npm", "install", "name@1.0.0", "--ignore-scripts"],
            "environment": {"PATH": "/opt/example/bin", "HOME": "/example/agent"},
            "approval_key": {"harness": "omp", "artifact_id": "omp:project:package-request:example"},
        })
    );
    assert!(result["response"].is_null());
    for stamp in [
        Value::Null,
        json!("PATH=/bin"),
        json!({"path": 3, "home": ""}),
    ] {
        input["execution_environment"] = stamp;
        assert_eq!(settle(&input)["lookup"]["environment"], json!({}));
    }
    for command in ["", "npm '\""] {
        input["package"]["command"] = json!(command);
        assert!(settle(&input)["lookup"].is_null());
    }
}

#[test]
fn queued_reviews_keep_the_key_until_an_applicable_saved_allow_is_found() {
    let mut input = request("review", None, false);
    input["reuse"] = json!({"artifact_hash": "identity", "found": false, "policy_action": "allow"});
    let result = settle(&input);
    assert!(result["response"].is_null());
    assert_eq!(
        result["package_approval"],
        json!({
            "harness": "omp",
            "artifact_id": "omp:project:package-request:example",
            "artifact_hash": "identity",
        })
    );
    input["reuse"]["found"] = json!(true);
    assert_eq!(settle(&input)["response"]["decision"], "allow");
    input["reuse"]["policy_action"] = json!("review");
    assert!(settle(&input)["response"].is_null());
}

#[test]
fn only_keyed_package_reviews_request_a_saved_policy_lookup() {
    let mut input = request("review", None, false);
    input["keyed"] = json!(false);
    assert!(settle(&input)["lookup"].is_null());
    input["keyed"] = json!(true);
    input["verdict"]["reason_code"] = json!("native_command_review_required");
    assert!(settle(&input)["lookup"].is_null());
    input["verdict"]["reason_code"] = json!("native_package_review");
    input["verdict"]["minimum_action"] = json!("block");
    assert!(settle(&input)["lookup"].is_null());
}

#[test]
fn registry_retry_is_a_terminal_harness_deny() {
    let reply = registry_retry("omp");
    assert_eq!(reply["decision"], "deny");
    assert_eq!(reply["prompted"], false);
    assert_eq!(reply["reason_code"], PACKAGE_REVIEW_REASON);
    assert!(reply["reason"]
        .as_str()
        .expect("reason text")
        .contains("Run the same command again."));
    let reply = registry_retry("claude");
    assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "deny");
}
