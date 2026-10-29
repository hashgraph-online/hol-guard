//! The queue write a `queue_native_review` call stands for.

use serde_json::{json, Map, Value};

use super::{Delegated, METHOD};
use crate::guard_store_db::StoreError;

const CONNECTOR_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A call with no admitted snapshot, as the unit tests have none.
fn delegate(args: &Map<String, Value>) -> Result<Delegated, StoreError> {
    super::delegate(args, None, 10_000)
}

fn query(payload: Value) -> Value {
    json!({
        "envelope": {
            "harness": "claude-code",
            "event_name": "PreToolUse",
            "payload": crate::hook_direct::saved_decision::review_request::tagged(&payload),
            "workspace": "/work",
            "home_dir": "/home/u",
            "devin_project_dir": null,
            "path_env": null,
            "host": {"tilde_home": "/home/u", "default_home": "/home/u", "cwd": "/work"},
        },
        "result": {"decision": "review", "reason": "Deletes files."},
        "native_receipt": null,
        "request_id": "req1",
        "approval_center_url": "http://127.0.0.1:4781/approvals",
        "guard_home": "/home/u/.hol-guard",
        "review_binding": "binding-1",
        "exact_token": null,
        "once_only_reason": "no exact action",
        "queue_group_id": null,
        "bound_bash": null,
    })
}

fn shell() -> Value {
    json!({
        "session_id": "sess-1",
        "tool_name": "Bash",
        "cwd": "/work",
        "tool_input": {"command": "rm -rf build", "description": "x".repeat(4096)},
    })
}

fn args(extra: Value) -> Map<String, Value> {
    let mut args = json!({
        "review": query(shell()),
        "hint": null,
        "now": "2026-10-29T00:00:00+00:00",
        "return_row": true,
        "cwd": "/work",
    });
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    args.as_object().unwrap().clone()
}

fn invalid(result: Result<Delegated, StoreError>) -> bool {
    matches!(
        result,
        Err(StoreError::Invalid(
            "native_guard_store_review_queue_invalid"
        ))
    )
}

#[test]
fn the_method_name_is_the_one_the_daemon_sends() {
    assert_eq!(METHOD, "queue_native_review");
}

#[test]
fn a_prompted_review_becomes_the_plain_queue_write() {
    let delegated = delegate(&args(json!({}))).unwrap();
    assert_eq!(delegated.method, "add_approval_request");
    let request = &delegated.args["request"];
    assert_eq!(request["request_id"], "req1");
    assert_eq!(request["artifact_hash"], "binding-1");
    assert_eq!(request["launch_target"], "rm -rf build");
    assert_eq!(request["extension_allow_hint"], Value::Null);
    // The query and the flags never reach the queue write; its own args do.
    for key in ["review", "hint", "silent", "claude_notice", "daemon"] {
        assert!(!delegated.args.contains_key(key), "{key}");
    }
    assert_eq!(delegated.args["now"], "2026-10-29T00:00:00+00:00");
    assert_eq!(delegated.args["return_row"], true);
    assert_eq!(delegated.args["cwd"], "/work");
}

fn paused_with(extensions: Value) -> Value {
    let mut review = query(shell());
    review["result"]["command_extensions"] = extensions;
    review
}

fn local_cli() -> Value {
    json!({
        "cli_id": "local-cli.acme@1+x",
        "identity_hash": CONNECTOR_HASH,
        "name": " acme ",
        "surface": "cli",
        "queue_group_id": format!("connector:{CONNECTOR_HASH}:0123456789abcdef"),
    })
}

#[test]
fn a_missing_hint_is_stored_as_none() {
    let mut without = args(json!({}));
    without.remove("hint");
    let delegated = delegate(&without).unwrap();
    assert_eq!(
        delegated.args["request"]["extension_allow_hint"],
        Value::Null
    );
}

#[test]
fn a_review_without_extension_evidence_has_no_hint() {
    let delegated = delegate(&args(json!({"hint": {"budget_ms": 2_000}}))).unwrap();
    assert_eq!(
        delegated.args["request"]["extension_allow_hint"],
        Value::Null
    );
}

#[test]
fn a_connector_review_stores_its_setup_hint() {
    let delegated = delegate(&args(json!({
        "review": paused_with(json!({"observations": []})),
        "hint": {"budget_ms": 2_000, "connector": local_cli()},
    })))
    .unwrap();
    let hint = &delegated.args["request"]["extension_allow_hint"];
    assert_eq!(hint["schema"], "guard.connector-setup-hint.v1");
    assert_eq!(hint["cli_id"], "local-cli.acme@1+x");
    assert_eq!(hint["display_name"], "acme");
    assert_eq!(hint["risk_classes"], json!([]));
}

#[test]
fn the_hint_never_spends_the_time_the_write_needs() {
    let connector = args(json!({
        "review": paused_with(json!({"observations": []})),
        "hint": {"budget_ms": 2_000, "connector": local_cli()},
    }));
    let delegated = super::delegate(&connector, None, 350).unwrap();
    assert_eq!(
        delegated.args["request"]["extension_allow_hint"],
        Value::Null
    );
    let delegated = super::delegate(&connector, None, 351).unwrap();
    assert_eq!(
        delegated.args["request"]["extension_allow_hint"]["schema"],
        "guard.connector-setup-hint.v1"
    );
}

#[test]
fn a_connector_hint_needs_a_local_cli() {
    let mut mcp = local_cli();
    mcp["surface"] = json!("mcp");
    let delegated = delegate(&args(json!({
        "review": paused_with(json!({"observations": []})),
        "hint": {"budget_ms": 2_000, "connector": mcp},
    })))
    .unwrap();
    assert_eq!(
        delegated.args["request"]["extension_allow_hint"],
        Value::Null
    );
}

#[test]
fn a_silent_review_becomes_the_daemon_write() {
    let delegated = delegate(&args(json!({"silent": true}))).unwrap();
    assert_eq!(
        delegated.method,
        "add_silent_native_review_approval_request"
    );
    assert_eq!(delegated.args["daemon"], true);
}

#[test]
fn a_claude_review_carries_its_notice_facts_and_key() {
    let delegated = delegate(&args(json!({
        "claude_notice": true,
        "integrity_key_b64": "a2V5",
        "integrity_key_id": "kid",
    })))
    .unwrap();
    assert_eq!(delegated.method, "add_claude_approval_request");
    assert_eq!(delegated.args["integrity_key_b64"], "a2V5");
    assert_eq!(delegated.args["integrity_key_id"], "kid");
    let request = &delegated.args["request"];
    // Only what the notice reads: the full hook payload stays out.
    assert_eq!(
        delegated.args["claude_review"],
        json!({
            "harness": "claude-code",
            "hook_payload": {
                "session_id": "sess-1",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf build"},
            },
            "reason": "Deletes files.",
            "review_binding": "binding-1",
            "config_path": request["config_path"],
            "source_scope": request["source_scope"],
        })
    );
}

#[test]
fn a_claude_review_without_a_key_queues_without_a_notice() {
    let delegated = delegate(&args(json!({"claude_notice": true}))).unwrap();
    assert_eq!(delegated.method, "add_approval_request");
    assert!(!delegated.args.contains_key("claude_review"));
}

#[test]
fn a_key_without_a_notice_is_dropped() {
    let delegated = delegate(&args(json!({
        "integrity_key_b64": "a2V5",
        "integrity_key_id": "kid",
    })))
    .unwrap();
    assert_eq!(delegated.method, "add_approval_request");
    assert!(!delegated.args.contains_key("integrity_key_b64"));
    assert!(!delegated.args.contains_key("integrity_key_id"));
}

#[test]
fn malformed_calls_are_refused() {
    let mut missing = args(json!({}));
    missing.remove("review");
    assert!(invalid(delegate(&missing)));
    let mut unknown = query(shell());
    unknown["kind"] = json!("review_request");
    assert!(invalid(delegate(&args(json!({"review": unknown})))));
    assert!(invalid(delegate(&args(json!({"hint": "hint"})))));
    assert!(invalid(delegate(&args(
        json!({"hint": {"budget_ms": 2_000, "paused": {}}})
    ))));
    assert!(invalid(delegate(&args(json!({"hint": {"budget_ms": -1}})))));
    assert!(invalid(delegate(&args(json!({"silent": "yes"})))));
    assert!(invalid(delegate(&args(json!({
        "silent": true,
        "claude_notice": true,
        "integrity_key_b64": "a2V5",
        "integrity_key_id": "kid",
    })))));
    let mut unreadable = query(shell());
    unreadable["result"] = json!("review");
    // A well-formed call whose review cannot be built names that apart.
    assert!(matches!(
        delegate(&args(json!({"review": unreadable}))),
        Err(StoreError::Invalid(
            "native_guard_store_review_request_refused"
        ))
    ));
}
