use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn plan(harness: &str, event: &str, action: &str, timeout: i64, response: Value) -> Value {
    let request = json!({
        "op": "plan",
        "harness": harness,
        "event": event,
        "policy_action": action,
        "timeout": timeout,
        "response": response,
    });
    dispatch(&request).unwrap()
}

fn queued(ids: &[&str]) -> Value {
    let items: Vec<Value> = ids.iter().map(|id| json!({ "request_id": id })).collect();
    json!({ "approval_requests": items })
}

#[test]
fn only_a_pretool_review_waits() {
    let response = queued(&["req-1"]);
    for harness in ["grok", "muse"] {
        for event in ["PreToolUse", "pre_tool_use", "pre-tool-use", "PRETOOLUSE"] {
            for action in ["review", "require-reapproval"] {
                let answer = plan(harness, event, action, 4, response.clone());
                assert_eq!(answer, json!({ "request_ids": ["req-1"], "seconds": 4 }));
            }
        }
        for (event, action) in [
            ("UserPromptSubmit", "review"),
            ("PostToolUse", "review"),
            ("PreToolUse", "block"),
            ("PreToolUse", "allow"),
            ("PreToolUse", ""),
        ] {
            let answer = plan(harness, event, action, 4, response.clone());
            assert_eq!(
                answer,
                json!({ "request_ids": [], "seconds": 0 }),
                "{event} {action}"
            );
        }
    }
}

#[test]
fn grok_caps_the_wait_below_its_hook_deadline() {
    let response = queued(&["req-1"]);
    assert_eq!(
        plan("grok", "PreToolUse", "review", 120, response.clone())["seconds"],
        80
    );
    assert_eq!(
        plan("grok", "PreToolUse", "review", 80, response.clone())["seconds"],
        80
    );
    assert_eq!(
        plan("muse", "PreToolUse", "review", 120, response.clone())["seconds"],
        120
    );
    for harness in ["grok", "muse"] {
        for timeout in [0, -5] {
            let answer = plan(harness, "PreToolUse", "review", timeout, response.clone());
            assert_eq!(answer, json!({ "request_ids": [], "seconds": 0 }));
        }
    }
}

#[test]
fn no_named_request_means_no_wait() {
    for harness in ["grok", "muse"] {
        for response in [
            json!({}),
            json!({ "approval_requests": [] }),
            json!({ "approval_request_id": "  " }),
            json!({ "approval_requests": [{ "request_id": 7 }], "approval_request_id": 7 }),
        ] {
            let answer = plan(harness, "PreToolUse", "review", 4, response.clone());
            assert_eq!(answer["request_ids"], json!([]), "{harness} {response}");
            assert_eq!(answer["seconds"], 0);
        }
    }
}

#[test]
fn grok_prefers_every_queued_request_over_one_single_id() {
    let response = json!({
        "approval_requests": [
            { "request_id": " req-a " },
            { "id": "req-ignored" },
            "req-bare",
            { "request_id": "req-a" },
        ],
        "primary_approval_request_id": "req-primary",
    });
    let answer = plan("grok", "PreToolUse", "review", 4, response);
    assert_eq!(answer["request_ids"], json!(["req-a", "req-a"]));

    let singles = json!({
        "approval_requests": [{ "id": "req-ignored" }],
        "primary_approval_request_id": "",
        "approval_request_id": "req-singular",
        "guardApprovalRequestId": "req-guard",
    });
    let answer = plan("grok", "PreToolUse", "review", 4, singles);
    assert_eq!(answer["request_ids"], json!(["req-singular"]));
}

#[test]
fn muse_names_each_request_once_in_order() {
    let response = json!({
        "guardApprovalRequestId": "req-guard",
        "primary_approval_request_id": " req-primary ",
        "approval_request_id": "req-primary",
        "approval_requests": [
            { "request_id": "req-queued" },
            { "request_id": "", "id": "req-by-id" },
            { "request_id": null, "id": "req-guard" },
            "req-bare",
            { "request_id": [0], "id": "req-hidden" },
            { "request_id": 0, "id": "req-zero" },
            7,
        ],
    });
    let answer = plan("muse", "PreToolUse", "review", 4, response);
    assert_eq!(
        answer["request_ids"],
        json!([
            "req-primary",
            "req-guard",
            "req-queued",
            "req-by-id",
            "req-bare",
            "req-zero"
        ])
    );
}

fn settle(harness: &str, resolved: Value, rows: Value) -> Value {
    let request = json!({
        "op": "settle",
        "harness": harness,
        "resolved": resolved,
        "rows": rows,
        "request_id": "req-1",
    });
    dispatch(&request).unwrap()
}

#[test]
fn an_unresolved_wait_stays_pending() {
    for resolved in [json!(false), json!(null), json!(0), json!([])] {
        let answer = settle("grok", resolved, json!([{ "action": "allow" }]));
        assert_eq!(
            answer,
            json!({
                "decision": null,
                "fields": [[
                    "review_hint",
                    "Approval is still pending in HOL Guard. Approve it, and Grok will resume this exact tool call."
                ]],
                "edits": null,
            })
        );
    }
    let answer = settle("muse", json!(false), json!([]));
    assert_eq!(
        answer["fields"][0][1],
        "Approval is still pending in HOL Guard. Approve it, and Muse will resume this exact tool call."
    );
}

#[test]
fn only_explicit_allows_resume_the_call() {
    let rows = json!([{ "action": "allow" }, null, { "action": "allow" }]);
    let allowed = settle("muse", json!(true), rows);
    assert_eq!(allowed["decision"], "allow");
    assert_eq!(
        allowed["fields"],
        json!([
            ["browser_resolution_request_id", "req-1"],
            [
                "review_hint",
                "Approval received in HOL Guard. Muse is resuming this action."
            ],
        ])
    );
    assert_eq!(
        settle("grok", json!([0]), json!([{ "action": "allow" }]))["decision"],
        "allow"
    );

    for rows in [
        json!([]),
        json!([null]),
        json!([{ "action": "deny" }]),
        json!([{ "action": "allow" }, { "action": "block" }]),
        json!([{ "action": null }]),
        json!([{}]),
        json!([{ "action": "ALLOW" }]),
    ] {
        let answer = settle("grok", json!(true), rows.clone());
        assert_eq!(answer["decision"], "block", "{rows}");
        assert_eq!(
            answer["fields"],
            json!([["review_hint", "HOL Guard kept this Grok action blocked."]]),
            "{rows}"
        );
    }
}

fn rewrite(harness: &str, decision: &str) -> Value {
    let rows = json!([{ "action": decision }]);
    let answer = settle(harness, json!(true), rows);
    let expected = if decision == "allow" {
        "allow"
    } else {
        "block"
    };
    assert_eq!(answer["decision"], expected);
    answer["edits"].clone()
}

#[test]
fn an_allow_drops_the_reason_and_spells_the_harness_decision() {
    assert_eq!(
        rewrite("grok", "allow"),
        json!({
            "set": [["decision", "allow"], ["policy_action", "allow"]],
            "drop": ["reason"],
            "hook_set": [["permissionDecision", "allow"]],
            "hook_drop": ["permissionDecisionReason"],
        })
    );
    // Muse rejects a bare `permissionDecision: "allow"`.
    assert_eq!(
        rewrite("muse", "allow"),
        json!({
            "set": [["decision", "allow"], ["policy_action", "allow"]],
            "drop": ["reason"],
            "hook_set": [],
            "hook_drop": ["permissionDecision", "permissionDecisionReason"],
        })
    );
}

#[test]
fn a_block_keeps_the_reason() {
    let blocked = json!({
        "set": [["decision", "deny"], ["policy_action", "block"]],
        "drop": [],
        "hook_set": [["permissionDecision", "deny"]],
        "hook_drop": [],
    });
    assert_eq!(rewrite("grok", "deny"), blocked);
    assert_eq!(rewrite("muse", "deny"), blocked);
}

#[test]
fn refuses_malformed_requests() {
    for request in [
        json!([]),
        json!({ "op": "plan", "harness": "codex", "event": "PreToolUse", "policy_action": "review", "timeout": 4, "response": {} }),
        json!({ "op": "plan", "harness": "grok", "event": "PreToolUse", "policy_action": "review", "timeout": 4.5, "response": {} }),
        json!({ "op": "plan", "harness": "grok", "event": "PreToolUse", "policy_action": "review", "timeout": true, "response": {} }),
        json!({ "op": "plan", "harness": "grok", "event": "PreToolUse", "policy_action": null, "timeout": 4, "response": {} }),
        json!({ "op": "plan", "harness": "grok", "event": "PreToolUse", "policy_action": "review", "timeout": 4, "response": [] }),
        json!({ "op": "plan", "harness": "grok", "event": "PreToolUse", "policy_action": "review", "timeout": 4 }),
        json!({ "op": "settle", "harness": "grok", "resolved": true, "rows": {}, "request_id": "r" }),
        json!({ "op": "settle", "harness": "grok", "rows": [], "request_id": "r", "extra": 1 }),
        json!({ "op": "settle", "harness": "grok", "resolved": true, "rows": [], "request_id": 1 }),
        json!({ "op": "rewrite", "harness": "muse", "decision": "allow" }),
        json!({ "op": "resume_metadata", "harness": "muse", "payload": {} }),
        json!({ "op": "resume_metadata", "harness": "grok", "payload": null }),
        json!({ "op": "wait", "harness": "grok" }),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
