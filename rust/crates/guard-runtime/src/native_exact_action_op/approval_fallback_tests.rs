//! Every review can be approved (`docs/guard/approval-invariant.md`).
//!
//! A command Guard cannot prove still gets an approval token and a retry
//! binding. The token is the hash of the command, so an approval holds until
//! the command, its directory or its workspace changes.

use guard_contracts::{NativeExactActionPayloadV1, NativeExactActionRequestV1};
use serde_json::{json, Value};

use super::context::ResidentEngines;
use super::{decide, decide_with, Fallback};

const UNPROVABLE: &str = "browser-tool --cdp 9303 tabs";

fn exact_request(root: &str, edit: impl FnOnce(&mut Value)) -> NativeExactActionRequestV1 {
    let mut request = json!({
        "schema": "guard-native-exact-action-request.v1",
        "request_id": "req-fallback",
        "query": {
            "kind": "exact_action", "harness": "codex", "tool_name": "Bash", "command": UNPROVABLE,
            "tool_input": [["command", UNPROVABLE]], "payload_cwd": root, "workspace": root, "home_dir": root,
            "environment": {"PATH": root},
            "facts": {
                "decision": "ask", "minimum_action": "review", "policy_action": "review",
                "reason_code": "native_workspace_containment_executable_outside_roots", "action_type": "shell"
            },
            "policy_binding": {"state": "unbound"},
            "extension_control_digest": "e".repeat(64), "budget_ms": 20000
        }
    });
    edit(&mut request["query"]);
    serde_json::from_value(request).unwrap()
}

fn outcome(
    request: &NativeExactActionRequestV1,
    fallback: Fallback,
) -> (Option<String>, Option<String>) {
    match decide_with(request, &ResidentEngines, fallback).unwrap() {
        NativeExactActionPayloadV1::ExactAction {
            token,
            once_only_reason,
        } => (token, once_only_reason),
        _ => panic!("an exact-action query answers with an exact action"),
    }
}

fn token(root: &str, edit: impl FnOnce(&mut Value)) -> Option<String> {
    outcome(&exact_request(root, edit), Fallback::CommandHash).0
}

fn root() -> String {
    std::env::temp_dir().to_string_lossy().into_owned()
}

#[test]
fn an_unprovable_command_still_gets_an_approval_token() {
    let request = exact_request(&root(), |_| {});
    let (strict, reason) = outcome(&request, Fallback::Strict);
    assert!(strict.is_none());
    assert!(reason.is_some());
    let (token, reason) = outcome(&request, Fallback::CommandHash);
    assert!(token.is_some(), "every review offers Always allow");
    assert!(reason.is_none());
}

#[test]
fn the_command_hash_holds_until_the_command_changes() {
    let root = root();
    let first = token(&root, |_| {}).unwrap();
    assert_eq!(token(&root, |_| {}).as_deref(), Some(first.as_str()));
    // Policy, rules, reason, extensions and environment never revoke it.
    let kept: [fn(&mut Value); 5] = [
        |query: &mut Value| query["environment"] = json!({"PATH": "/usr/bin"}),
        |query: &mut Value| query["extension_control_digest"] = json!("f".repeat(64)),
        |query: &mut Value| query["facts"]["reason_code"] = json!("first_seen"),
        |query: &mut Value| query["facts"]["action_type"] = json!("guard_control"),
        |query: &mut Value| query["facts"]["policy_action"] = json!("require-reapproval"),
    ];
    for edit in kept {
        assert_eq!(token(&root, edit).as_deref(), Some(first.as_str()));
    }
    // The command, its directory and its workspace are the hash.
    let changed: [fn(&mut Value); 5] = [
        |query: &mut Value| query["command"] = json!("browser-tool --cdp 9304 tabs"),
        |query: &mut Value| query["payload_cwd"] = json!("/"),
        |query: &mut Value| query["workspace"] = json!("/"),
        |query: &mut Value| query["harness"] = json!("claude-code"),
        |query: &mut Value| query["tool_name"] = json!("Shell"),
    ];
    for edit in changed {
        assert_ne!(token(&root, edit).unwrap(), first);
    }
}

#[test]
fn a_tool_called_with_no_input_can_be_approved() {
    let bare = token(&root(), |query| {
        query["tool_name"] = json!("todo");
        query["command"] = Value::Null;
        query["tool_input"] = Value::Null;
    });
    assert!(bare.is_some(), "an argument-free tool offers Always allow");
    let sent = |raw: Value| {
        token(&root(), move |query| {
            query["tool_name"] = json!("todo");
            query["command"] = Value::Null;
            query["tool_input"] = Value::Null;
            query["raw_tool_input"] = raw;
        })
        .unwrap()
    };
    // An input that is not an object binds the hash as it was sent.
    let first = sent(json!("list"));
    assert_eq!(sent(json!("list")), first);
    assert_ne!(sent(json!("delete all")), first);
    assert_ne!(sent(json!(["list"])), first);
    assert_ne!(bare.unwrap(), first);
}

#[test]
fn every_field_of_a_non_shell_tool_binds_the_hash() {
    let call = |host: &str| {
        token(&root(), move |query| {
            query["tool_name"] = json!("mcp__remote__run");
            query["command"] = json!("ls");
            query["tool_input"] = json!([["command", "ls"], ["host", host]]);
        })
        .unwrap()
    };
    assert_eq!(call("staging"), call("staging"));
    assert_ne!(call("staging"), call("prod"));
    // A shell's other fields do not change what it runs.
    let shell = |description: &str| {
        token(&root(), move |query| {
            query["tool_input"] = json!([["command", UNPROVABLE], ["description", description]]);
        })
        .unwrap()
    };
    assert_eq!(shell("list tabs"), shell("show tabs"));
}

#[test]
fn guard_control_and_package_reviews_can_be_approved() {
    let root = root();
    for kind in ["guard_control", "guard-control-operation", "package"] {
        let request = exact_request(&root, |query| query["facts"]["action_type"] = json!(kind));
        let (token, reason) = outcome(&request, Fallback::CommandHash);
        assert!(token.is_some(), "{kind} offers Always allow");
        assert!(reason.is_none());
    }
}

#[test]
fn risky_reviews_can_be_approved() {
    let root = root();
    for code in ["secret_read", "credential_exfiltration", "prompt_injection"] {
        let request = exact_request(&root, |query| query["facts"]["reason_code"] = json!(code));
        let (token, reason) = outcome(&request, Fallback::CommandHash);
        assert!(token.is_some(), "{code} offers Always allow");
        assert!(reason.is_none());
    }
}

#[test]
fn only_a_review_gets_an_approval_token() {
    let root = root();
    for action in ["block", "allow", "sandbox-required"] {
        let request = exact_request(&root, |query| {
            query["facts"]["policy_action"] = json!(action)
        });
        let (token, reason) = outcome(&request, Fallback::CommandHash);
        assert!(token.is_none(), "{action} is not a review");
        assert!(reason.is_some());
    }
}

fn binding_request(command: &str, action_type: &str) -> NativeExactActionRequestV1 {
    serde_json::from_value(json!({
        "schema": "guard-native-exact-action-request.v1",
        "request_id": "req-fallback-binding",
        "query": {
            "kind": "review_binding", "harness": "codex", "command": command, "workspace_bound": true,
            "facts": {
                "decision": "ask", "minimum_action": "review", "policy_action": "review",
                "reason_code": "r", "action_type": action_type
            },
            "receipt": {
                "schema": "guard-native-hook-decision-receipt.v1", "version": 1, "authority": "rust",
                "harness": "codex", "event_name": "PreToolUse", "workspace_bound": true,
                "request_digest": "ab".repeat(32), "review_anchor_digest": "cd".repeat(32),
                "decision": "ask", "policy_action": "review", "reason_code": "r"
            },
            "policy_binding": {"state": "unbound"}
        }
    }))
    .unwrap()
}

fn binding(request: &NativeExactActionRequestV1, fallback: Fallback) -> Option<String> {
    match decide_with(request, &ResidentEngines, fallback).unwrap() {
        NativeExactActionPayloadV1::ReviewBinding { binding } => binding,
        _ => panic!("a review-binding query answers with a binding"),
    }
}

#[test]
fn allow_once_reaches_the_retry_of_any_review() {
    let anchored = format!("native-review-v4:{}:ask:review:review:r", "cd".repeat(32));
    for (command, kind) in [
        (UNPROVABLE, "shell"),
        ("npm install left-pad", "package"),
        ("hol-guard approvals clear", "guard_control"),
    ] {
        let request = binding_request(command, kind);
        assert_eq!(
            binding(&request, Fallback::CommandHash).as_deref(),
            Some(anchored.as_str()),
            "{command}"
        );
        let NativeExactActionPayloadV1::ReviewBinding { binding } =
            decide(&request, &ResidentEngines).unwrap()
        else {
            panic!("a review-binding query answers with a binding");
        };
        assert_eq!(binding.as_deref(), Some(anchored.as_str()));
    }
}
