//! The queue write a `queue_native_review` call stands for.

use serde_json::{json, Map, Value};

use super::{Delegated, METHOD};
use crate::guard_store_db::StoreError;
use crate::hook_direct::saved_decision::review_queue::connector::Connector;

const CONNECTOR_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A call with no admitted snapshot, as the unit tests have none, whose
/// launch names no connector.
pub(super) fn delegate(args: &Map<String, Value>) -> Result<Delegated, StoreError> {
    super::delegate(args, None, 10_000, |_| None)
}

/// A call whose launch names `connector`, within `budget_ms`.
pub(super) fn looked_up(
    args: &Map<String, Value>,
    budget_ms: u64,
    connector: Value,
) -> Result<Delegated, StoreError> {
    super::delegate(args, None, budget_ms, move |_| Connector::parse(&connector))
}

/// The launch the daemon names for a non-recognition review.
fn launch() -> Value {
    json!({
        "command": "acme deploy staging",
        "cwd": "/work",
        "home_dir": "/home/u",
        "user_home": "/home/u",
        "env": {"PATH": "/home/u/.local/bin:/usr/bin"},
    })
}

/// A non-recognition review with the launch it paused.
pub(super) fn unrecognised(extra: Value) -> Map<String, Value> {
    let mut review = paused_with(json!({"observations": []}));
    review["result"]["reason_code"] = json!("native_command_review_required");
    let mut call = args(json!({"review": review, "connector_lookup": launch()}));
    for (key, value) in extra.as_object().unwrap() {
        call.insert(key.clone(), value.clone());
    }
    call
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

pub(super) fn args(extra: Value) -> Map<String, Value> {
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

pub(super) fn local_cli() -> Value {
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
fn a_connector_review_queues_under_its_group_with_its_setup_hint() {
    let call = unrecognised(json!({"hint": {"budget_ms": 2_000}}));
    let delegated = looked_up(&call, 10_000, local_cli()).unwrap();
    assert!(!delegated.args.contains_key("connector_lookup"));
    let request = &delegated.args["request"];
    assert_eq!(request["queue_group_id"], local_cli()["queue_group_id"]);
    let hint = &request["extension_allow_hint"];
    assert_eq!(hint["schema"], "guard.connector-setup-hint.v1");
    assert_eq!(hint["cli_id"], "local-cli.acme@1+x");
    assert_eq!(hint["display_name"], "acme");
    assert_eq!(hint["risk_classes"], json!([]));
}

#[test]
fn the_hint_never_spends_the_time_the_write_needs() {
    let call = unrecognised(json!({"hint": {"budget_ms": 2_000}}));
    let delegated = looked_up(&call, 350, local_cli()).unwrap();
    assert_eq!(
        delegated.args["request"]["extension_allow_hint"],
        Value::Null
    );
    let delegated = looked_up(&call, 1_000, local_cli()).unwrap();
    assert_eq!(
        delegated.args["request"]["extension_allow_hint"]["schema"],
        "guard.connector-setup-hint.v1"
    );
}

#[test]
fn a_launch_that_names_no_local_cli_stays_an_ordinary_review() {
    let mut mcp = local_cli();
    mcp["surface"] = json!("mcp");
    let call = unrecognised(json!({"hint": {"budget_ms": 2_000}}));
    let delegated = looked_up(&call, 10_000, mcp).unwrap();
    let request = &delegated.args["request"];
    assert_eq!(request["queue_group_id"], Value::Null);
    assert_eq!(request["extension_allow_hint"], Value::Null);
    let reply = delegated.with_response(stored_reply(), NO_TOKEN_HOME);
    assert!(reply.get("connector_setup").is_none());
}

#[test]
fn only_a_non_recognition_review_looks_up_its_launch() {
    let mut call = unrecognised(json!({}));
    call["review"]["result"]["reason_code"] = json!("native_network_review");
    let delegated = super::delegate(&call, None, 10_000, |_| -> Option<Connector> {
        panic!("a review with a risk signal looked up its launch")
    })
    .unwrap();
    assert_eq!(delegated.args["request"]["queue_group_id"], Value::Null);
    let mut call = unrecognised(json!({}));
    call.remove("connector_lookup");
    let delegated = super::delegate(&call, None, 10_000, |_| -> Option<Connector> {
        panic!("a review without its launch looked it up")
    })
    .unwrap();
    assert_eq!(delegated.args["request"]["queue_group_id"], Value::Null);
}

#[test]
fn the_lookup_asks_about_the_launch_in_the_store_the_call_names() {
    let store: guard_contracts::GuardStoreRequestV1 = serde_json::from_value(json!({
        "schema": "guard-store-request.v1",
        "request_id": "store-1",
        "store_path": "/home/u/.hol-guard/guard.db",
        "guard_home": "/home/u/.hol-guard",
        "method": METHOD,
        "source": "local",
        "busy_timeout_ms": 5_000,
        "args": {},
    }))
    .unwrap();
    let ask: super::LookupAsk = serde_json::from_value(launch()).unwrap();
    let request = ask.request(&store);
    assert_eq!(request.schema, "guard-local-cli-hook-request.v1");
    assert_eq!(request.request_id, "local-cli-hook-store-1");
    assert_eq!(request.store_path, store.store_path);
    assert_eq!(request.guard_home, store.guard_home);
    assert_eq!(request.source, "local");
    assert_eq!(request.busy_timeout_ms, 250);
    assert_eq!(request.command, "acme deploy staging");
    assert_eq!(request.cwd, "/work");
    assert_eq!(request.home_dir.as_deref(), Some("/home/u"));
    assert_eq!(request.env["PATH"], "/home/u/.local/bin:/usr/bin");
    assert_eq!(request.current_action, "review");
    assert_eq!(request.current_reason_code, None);
    assert!(request.grant_allowed);
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
    assert!(invalid(delegate(&args(
        json!({"hint": {"budget_ms": 2_000, "connector": local_cli()}})
    ))));
    assert!(invalid(delegate(&args(
        json!({"connector_lookup": "acme"})
    ))));
    let mut extra = launch();
    extra["shell"] = json!("/bin/sh");
    assert!(invalid(delegate(&args(json!({"connector_lookup": extra})))));
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

/// A Guard home with no daemon token: the link is left unsigned.
const NO_TOKEN_HOME: &str = "/nonexistent/hol-guard";

fn stored_reply() -> Value {
    json!({
        "request_id": "req1",
        "row": {"request_id": "req1", "approval_url": "http://127.0.0.1:4781/requests/req1"},
    })
}

#[test]
fn a_paused_review_is_rendered_with_its_stored_row() {
    let reply = delegate(&args(json!({"respond": {"paused_review": {}}})))
        .unwrap()
        .with_response(stored_reply(), NO_TOKEN_HOME);
    assert_eq!(reply["row"], stored_reply()["row"]);
    assert!(reply["response"].to_string().contains("Deletes files."));
    assert!(reply.get("connector_setup").is_none());
}

#[test]
fn a_connector_review_answers_the_agent_with_its_setup_text() {
    let call = unrecognised(json!({"respond": {"paused_review": {}}}));
    let reply = looked_up(&call, 10_000, local_cli())
        .unwrap()
        .with_response(stored_reply(), NO_TOKEN_HOME);
    // The setup text replaces the verdict's reason for the agent only.
    let text = reply["response"].to_string();
    assert!(
        text.contains("`acme` (local CLI) on this device."),
        "{text}"
    );
    assert!(!text.contains("Deletes files."), "{text}");
    let setup = &reply["connector_setup"];
    assert_eq!(setup["name"], "acme");
    assert_eq!(setup["is_local"], true);
    assert!(setup["setup_reason"]
        .as_str()
        .is_some_and(|reason| text.contains(reason)));
}

#[test]
fn a_local_row_only_an_exact_always_releases_keeps_the_review_text() {
    let mut call = unrecognised(json!({"respond": {"paused_review": {}}}));
    call["review"]["review_binding"] = Value::Null;
    call["review"]["exact_token"] = json!("exact-1");
    let reply = looked_up(&call, 10_000, local_cli())
        .unwrap()
        .with_response(stored_reply(), NO_TOKEN_HOME);
    assert!(reply["response"].to_string().contains("Deletes files."));
    assert_eq!(reply["connector_setup"]["setup_reason"], Value::Null);
    assert_eq!(reply["connector_setup"]["name"], "acme");
}

#[test]
fn a_silent_block_is_rendered_with_its_stored_row() {
    let delegated = delegate(&args(json!({
        "silent": true,
        "respond": {"silent_review_block": {"ask": false, "home_dir": "/home/u"}},
    })))
    .unwrap();
    let reply = delegated.with_response(stored_reply(), NO_TOKEN_HOME);
    let response = &reply["response"];
    assert_eq!(response["prompted"], false);
    assert_eq!(response["blocked_request_mode"], "safe-alternative");
}

#[test]
fn the_facts_an_older_resident_renders_from_are_ignored() {
    // The daemon keeps naming them so an older resident still queues the
    // review; this call renders from the review and its own lookup.
    let delegated = delegate(&args(json!({
        "silent": true,
        "respond": {"silent_review_block": {
            "ask": false,
            "home_dir": "/home/u",
            "setup_reason": "Set up lanectl first.",
            "retry_reuses_approval": true,
            "exact_action_allowable": true,
            "connector_is_local": true,
        }},
    })))
    .unwrap();
    let reply = delegated.with_response(stored_reply(), NO_TOKEN_HOME);
    assert!(!reply["response"]
        .to_string()
        .contains("Set up lanectl first."));
    let paused = delegate(&args(json!({
        "respond": {"paused_review": {"reason": "Set up lanectl first."}},
    })))
    .unwrap();
    let reply = paused.with_response(stored_reply(), NO_TOKEN_HOME);
    assert!(!reply["response"]
        .to_string()
        .contains("Set up lanectl first."));
}

#[test]
fn a_response_that_would_not_fit_the_reply_frame_is_left_to_the_hook() {
    let mut reply = stored_reply();
    // The row alone fits; with the rendered response it would not.
    reply["row"]["raw_command_text"] = json!("y".repeat(super::REPLY_BUDGET_BYTES - 200));
    let delegated = delegate(&args(json!({
        "respond": {"paused_review": {}},
    })))
    .unwrap();
    assert_eq!(delegated.with_response(reply.clone(), NO_TOKEN_HOME), reply);
}

#[test]
fn a_reply_without_its_row_or_a_respond_carries_no_response() {
    let read_back = json!({"request_id": "req1", "row_error": "native_guard_store_invalid"});
    let delegated = delegate(&args(json!({"respond": {"paused_review": {}}}))).unwrap();
    assert_eq!(
        delegated.with_response(read_back.clone(), NO_TOKEN_HOME),
        read_back
    );
    let plain = delegate(&args(json!({}))).unwrap();
    assert_eq!(
        plain.with_response(stored_reply(), NO_TOKEN_HOME),
        stored_reply()
    );
}

#[test]
fn a_respond_that_does_not_match_the_call_is_refused() {
    let silent_facts = json!({"ask": false, "home_dir": "/home/u"});
    assert!(invalid(delegate(&args(
        json!({"respond": "paused_review"})
    ))));
    assert!(invalid(delegate(&args(json!({
        "respond": {"approval_card": {}},
    })))));
    assert!(invalid(delegate(&args(json!({
        "silent": true,
        "respond": {"silent_review_block": {"home_dir": "/home/u"}},
    })))));
    // A silent block answers only a silent queue, and a paused review only a prompted one.
    assert!(invalid(delegate(&args(json!({
        "respond": {"silent_review_block": silent_facts},
    })))));
    assert!(invalid(delegate(&args(json!({
        "silent": true,
        "respond": {"paused_review": {}},
    })))));
}

#[test]
fn the_lookup_never_waits_into_the_writes_reserve() {
    for (busy_timeout_ms, lookup_ms) in [(5_000, 250), (400, 50), (351, 1), (350, 1), (1, 1)] {
        let store: guard_contracts::GuardStoreRequestV1 = serde_json::from_value(json!({
            "schema": "guard-store-request.v1",
            "request_id": "store-1",
            "store_path": "/home/u/.hol-guard/guard.db",
            "guard_home": "/home/u/.hol-guard",
            "method": METHOD,
            "source": "local",
            "busy_timeout_ms": busy_timeout_ms,
            "args": {},
        }))
        .unwrap();
        let ask: super::LookupAsk = serde_json::from_value(launch()).unwrap();
        assert_eq!(ask.request(&store).busy_timeout_ms, lookup_ms);
    }
}

#[test]
fn a_call_with_no_time_past_the_writes_reserve_skips_the_lookup() {
    let mut asked = false;
    let delegated = super::delegate(&unrecognised(json!({})), None, 350, |_| {
        asked = true;
        None
    })
    .unwrap();

    assert!(!asked);
    assert_eq!(delegated.args["request"]["queue_group_id"], Value::Null);
    let delegated = looked_up(&unrecognised(json!({})), 351, local_cli()).unwrap();
    assert_eq!(
        delegated.args["request"]["queue_group_id"],
        local_cli()["queue_group_id"]
    );
}
