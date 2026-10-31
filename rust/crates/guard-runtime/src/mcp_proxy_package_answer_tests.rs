//! The `package_answer` check against the responses `runtime_mcp.py` rendered
//! for each stopped package-lane call.

use guard_contracts::{GuardAction, McpPackageAnswerKindV1, McpPackageAnswerQueryV1};
use serde_json::{json, Map, Value};

use super::*;

const TOOL: &str = "install_package";
const SERVER: &str = "registry";

fn evaluation() -> Value {
    json!({
        "decision": "review",
        "policy_action": "review",
        "risk_summary": "left-pad has a known advisory",
        "reasons": [
            {"code": "advisory", "message": "left-pad has an advisory", "severity": "high"},
            {"code": "cloud_timeout", "message": ""},
            {"severity": "low"},
        ],
        "user_copy": {
            "title": "Package request needs review",
            "summary": "left-pad has a known advisory",
            "next_step": "Approve it in the dashboard.",
            "dashboard_url": "http://127.0.0.1:4781/approvals",
            "harness_message": "Approve the request, then retry.",
        },
    })
}

fn query(kind: McpPackageAnswerKindV1, policy_action: Option<&str>) -> McpPackageAnswerQueryV1 {
    McpPackageAnswerQueryV1 {
        kind,
        tool_name: TOOL.to_owned(),
        server_name: SERVER.to_owned(),
        policy_action: policy_action.map(str::to_owned),
        package_request: false,
        signals: vec!["writes outside the workspace".to_owned()],
        evaluation: Some(evaluation()),
    }
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("an object")
}

#[test]
fn a_terminal_tool_block_names_the_tool_and_echoes_its_signals() {
    let answer = package_answer(&query(McpPackageAnswerKindV1::TerminalTool, Some("block")))
        .expect("the answer is rendered");
    assert_eq!(answer["kind"], json!("block"));
    assert_eq!(
        answer["message"],
        json!("HOL Guard blocked tool call install_package from registry.")
    );
    assert_eq!(
        answer["data"],
        json!({"approvalRequests": [], "guardPolicyAction": "block"})
    );
    assert_eq!(answer["decision"], json!("terminal-block"));
    assert_eq!(answer["policy_action"], json!("block"));
    assert_eq!(answer["decision_source"], json!("policy-block"));
    assert_eq!(answer["signals"], json!(["writes outside the workspace"]));
    assert_eq!(answer["scanner_evidence_always"], json!(false));
}

#[test]
fn a_terminal_sandbox_requirement_says_the_runtime_cannot_provide_one() {
    let answer = package_answer(&query(
        McpPackageAnswerKindV1::TerminalTool,
        Some("sandbox-required"),
    ))
    .expect("the answer is rendered");
    assert_eq!(
        answer["message"],
        json!(
            "HOL Guard requires an enforceable sandbox for tool call install_package from \
             registry; this runtime cannot provide one."
        )
    );
    assert_eq!(answer["decision"], json!("terminal-sandbox-required"));
    assert_eq!(
        answer["data"]["guardPolicyAction"],
        json!("sandbox-required")
    );
}

#[test]
fn a_terminal_kind_refuses_an_action_that_is_not_terminal() {
    for action in [None, Some("review"), Some("allow"), Some("unknown")] {
        for kind in [
            McpPackageAnswerKindV1::TerminalTool,
            McpPackageAnswerKindV1::TerminalPackage,
        ] {
            assert_eq!(
                package_answer(&query(kind, action)),
                Err(PACKAGE_ANSWER_INVALID)
            );
        }
    }
}

#[test]
fn a_stored_tool_block_names_a_package_tool_call_when_it_carried_one() {
    let mut stored = query(McpPackageAnswerKindV1::StoredToolBlock, None);
    let plain = package_answer(&stored).expect("the answer is rendered");
    assert_eq!(
        plain["message"],
        json!(
            "HOL Guard blocked tool call install_package from registry. This exact request is \
             already blocked by authenticated saved policy."
        )
    );
    stored.package_request = true;
    let package = package_answer(&stored).expect("the answer is rendered");
    assert_eq!(
        package["message"],
        json!(
            "HOL Guard blocked package tool call install_package from registry. This exact \
             request is already blocked by authenticated saved policy."
        )
    );
    assert_eq!(package["decision"], json!("block-stored-policy"));
    assert_eq!(package["policy_action"], json!("block"));
    assert_eq!(package["scanner_evidence_always"], json!(false));
}

#[test]
fn a_package_block_carries_its_reason_signals_without_echoing_the_evaluation() {
    let terminal = package_answer(&query(
        McpPackageAnswerKindV1::TerminalPackage,
        Some("block"),
    ))
    .expect("the answer is rendered");
    assert_eq!(
        terminal["message"],
        json!("HOL Guard blocked package install request install_package from registry.")
    );
    assert_eq!(terminal["decision"], json!("terminal-package-block"));
    // The proxy attaches the evaluation it already holds; the answer stays
    // small however large the evaluation is.
    assert_eq!(terminal["data"].get("supplyChainEvaluation"), None);
    // A message, an empty message falling back to its code, and neither.
    assert_eq!(
        terminal["signals"],
        json!(["left-pad has an advisory", "cloud_timeout", ""])
    );
    assert_eq!(terminal["scanner_evidence_always"], json!(true));

    let stored = package_answer(&query(McpPackageAnswerKindV1::StoredPackageBlock, None))
        .expect("the answer is rendered");
    assert_eq!(
        stored["message"],
        json!(
            "HOL Guard blocked package install request install_package from registry. This \
             exact request is already blocked by stored policy with authenticated local \
             integrity."
        )
    );
    assert_eq!(stored["decision"], json!("package-block-stored"));
    assert_eq!(stored["policy_action"], json!("block"));
    assert_eq!(stored["data"]["guardPolicyAction"], json!("block"));
    assert_eq!(stored["data"].get("supplyChainEvaluation"), None);
}

#[test]
fn a_package_kind_without_its_evaluation_is_refused() {
    for kind in [
        McpPackageAnswerKindV1::StoredPackageBlock,
        McpPackageAnswerKindV1::TerminalPackage,
        McpPackageAnswerKindV1::QueuePackage,
    ] {
        let mut missing = query(kind, Some("block"));
        missing.evaluation = None;
        assert_eq!(package_answer(&missing), Err(PACKAGE_ANSWER_INVALID));
        missing.evaluation = Some(json!(["not", "an", "object"]));
        assert_eq!(package_answer(&missing), Err(PACKAGE_ANSWER_INVALID));
    }
}

#[test]
fn a_queued_package_carries_its_decision_signals_and_safe_alternative_restatement() {
    let answer = package_answer(&query(
        McpPackageAnswerKindV1::QueuePackage,
        Some("require-reapproval"),
    ))
    .expect("the answer is rendered");
    assert_eq!(answer["kind"], json!("queue"));
    assert_eq!(answer["policy_action"], json!("require-reapproval"));
    assert_eq!(
        answer["risk_summary"],
        json!("left-pad has a known advisory")
    );
    assert_eq!(
        answer["risk_signals"],
        json!(["left-pad has an advisory", "cloud_timeout", ""])
    );
    // `(package_evaluation.risk_summary, *risk_signals)`.
    assert_eq!(
        answer["safe_alternative_signals"],
        json!([
            "left-pad has a known advisory",
            "left-pad has an advisory",
            "cloud_timeout",
            ""
        ])
    );
    let decision = &answer["decision_v2"];
    assert_eq!(
        decision["user_title"],
        json!("Package request needs review")
    );
    assert_eq!(
        decision["user_body"],
        json!("left-pad has a known advisory")
    );
    assert_eq!(
        decision["harness_message"],
        json!("Approve the request, then retry.")
    );

    let (message, _) = safe_alternative_block(
        TOOL,
        SERVER,
        &[
            "left-pad has a known advisory".to_owned(),
            "left-pad has an advisory".to_owned(),
            "cloud_timeout".to_owned(),
            String::new(),
        ],
    );
    // Only what the restatement changes, never the evaluation itself.
    assert_eq!(answer.get("safe_alternative_evaluation"), None);
    assert_eq!(
        answer["safe_alternative_overlay"],
        json!({
            "decision": "block",
            "policy_action": "block",
            "user_copy": {
                "title": "Package request blocked",
                "summary": "left-pad has a known advisory",
                "dashboard_url": null,
                "next_step": message,
                "harness_message": message,
            },
        })
    );

    let restated = blocked_package_evaluation(&object(evaluation()), &message);
    assert_eq!(restated["decision"], json!("block"));
    assert_eq!(restated["policy_action"], json!("block"));
    assert_eq!(
        restated["user_copy"]["title"],
        json!("Package request blocked")
    );
    assert_eq!(restated["user_copy"]["dashboard_url"], Value::Null);
    assert_eq!(restated["user_copy"]["next_step"], json!(message));
    assert_eq!(restated["user_copy"]["harness_message"], json!(message));
    // Everything else the evaluation stated is kept.
    assert_eq!(restated["reasons"], evaluation()["reasons"]);
}

/// A reporter that wrote a number or a boolean for a reason's text: the
/// signal is that value as text, and a falsy one falls through to the code.
#[test]
fn reason_signals_read_numeric_and_boolean_reason_text() {
    let evaluation = object(json!({
        "reasons": [
            {"message": 404, "code": "ignored"},
            {"message": 1.5},
            {"message": 2.0},
            {"message": true},
            {"message": false, "code": "fallback"},
            {"message": 0, "code": 7},
            {"message": null, "code": false},
            {"message": "", "code": ""},
        ],
    }));
    assert_eq!(
        reason_signals(&evaluation),
        vec![
            "404".to_owned(),
            "1.5".to_owned(),
            "2.0".to_owned(),
            "True".to_owned(),
            "fallback".to_owned(),
            "7".to_owned(),
            String::new(),
            String::new(),
        ]
    );
}

#[test]
fn a_queued_package_refuses_an_action_outside_the_lattice() {
    for action in [None, Some("deny")] {
        assert_eq!(
            package_answer(&query(McpPackageAnswerKindV1::QueuePackage, action)),
            Err(PACKAGE_ANSWER_INVALID)
        );
    }
}

/// `test_package_decision_v2_ignores_malformed_reason_items`: a reason that is
/// not an object projects no signal, and the well-formed one beside it still
/// does.
#[test]
fn the_package_decision_ignores_malformed_reason_items() {
    let evaluation = object(json!({
        "reasons": ["malformed", {"code": "cloud_timeout", "message": "Cloud timed out."}],
        "user_copy": {
            "title": "Review package request",
            "summary": "Current package safety data was unavailable.",
            "harness_message": "Review the package request.",
        },
    }));
    let decision = package_decision_v2(&evaluation, GuardAction::RequireReapproval)
        .expect("the decision is built");
    let ids: Vec<Value> = decision["signals"]
        .as_array()
        .expect("signals")
        .iter()
        .map(|signal| signal["signal_id"].clone())
        .collect();
    assert_eq!(ids, vec![json!("supply-chain.cloud_timeout")]);
    assert_eq!(
        decision["dashboard_primary_detail"],
        json!("Current package safety data was unavailable.")
    );
    // A malformed reason states no signal text either.
    assert_eq!(
        reason_signals(&evaluation),
        vec![String::new(), "Cloud timed out.".to_owned()]
    );
}

#[test]
fn an_evaluation_with_no_user_copy_restates_the_block_with_its_own_copy() {
    let mut bare = object(evaluation());
    bare.remove("user_copy");
    let restated = blocked_package_evaluation(&bare, "Use a safer path.");
    assert_eq!(
        restated["user_copy"],
        json!({
            "title": "Package request blocked",
            "summary": "left-pad has a known advisory",
            "dashboard_url": null,
            "next_step": "Use a safer path.",
            "harness_message": "Use a safer path.",
        })
    );
}

#[test]
fn the_check_reaches_the_resident_op_by_name() {
    let query: guard_contracts::McpProxyQueryV1 = serde_json::from_value(json!({
        "check": "package_answer",
        "kind": "stored_tool_block",
        "tool_name": TOOL,
        "server_name": SERVER,
    }))
    .expect("the query parses");
    let answer = crate::mcp_proxy_decision_op::evaluate_query(&query).expect("answered");
    assert_eq!(answer["decision"], json!("block-stored-policy"));
    assert_eq!(answer["signals"], json!([]));

    let refused: guard_contracts::McpProxyQueryV1 = serde_json::from_value(json!({
        "check": "package_answer",
        "kind": "terminal_tool",
        "tool_name": TOOL,
        "server_name": SERVER,
        "policy_action": "allow",
    }))
    .expect("the query parses");
    assert_eq!(
        crate::mcp_proxy_decision_op::evaluate_query(&refused),
        Err(PACKAGE_ANSWER_INVALID)
    );
}
