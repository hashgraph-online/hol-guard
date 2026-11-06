use super::super::approval::Pending;
use crate::codex_hook_bridge::{route_response, Route};
use crate::codex_hook_response::PRE_TOOL_USE;
use crate::pyjson::PyVal;

/// Daemon answers and what Python's `_bridge_output` wrote for each,
/// recorded from `codex_daemon_hook_bridge.py`.
const PLAIN_DENIES: [(&str, &str); 6] = [
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"HOL Guard blocked this command. Open http://127.0.0.1:4781/dashboard for details."},"policy_action":"block","decision":"deny","reason_code":"native_command_block","receipt":{"id":"r"}}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"HOL Guard blocked this command. Open http://127.0.0.1:4781/dashboard for details."}}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"blocked \u00e9 \ud800"},"policy_action":"deny","systemMessage":"m"}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"blocked \u00e9 \ud800"},"systemMessage":"m"}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":""},"continue":true}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"},"continue":true}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":7}}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}"#,
    ),
    (
        r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"see /request/abcdefgh"}}"#,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"see /request/abcdefgh"}}"#,
    ),
];

#[test]
fn a_deny_naming_no_approval_renders_as_the_python_handoff_does() {
    for (answer, python) in PLAIN_DENIES {
        assert_eq!(
            route_response(answer, PRE_TOOL_USE),
            Route::Respond(python.to_owned()),
            "{answer}"
        );
    }
}

/// `{"hookSpecificOutput":{"permissionDecision":"deny"}}` as Python renders
/// it.
const BARE_DENY: &str =
    r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}"#;

fn pending(request_id: &str, approval_url: Option<&str>) -> Pending {
    Pending {
        request_id: request_id.to_owned(),
        approval_url: approval_url.map(str::to_owned),
    }
}

#[test]
fn a_deny_naming_a_pending_approval_waits_for_the_browser() {
    let link = "http://127.0.0.1:4781/requests/req_12345678";
    let reason = format!("Approve at {link} then retry");
    let answer = format!(
        r#"{{"hookSpecificOutput":{{"permissionDecision":"deny","permissionDecisionReason":"{reason}"}}}}"#
    );
    let rendered = format!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"{reason}"}}}}"#
    );
    assert_eq!(
        route_response(&answer, PRE_TOOL_USE),
        Route::AwaitApproval(pending("req_12345678", Some(link)), rendered)
    );
    assert_eq!(
        route_response(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"HTTP://h/REQUEſTS/abcdefgh"}}"#,
            PRE_TOOL_USE
        ),
        Route::AwaitApproval(
            pending("abcdefgh", None),
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"HTTP://h/REQUE\u017fTS/abcdefgh"}}"#
                .to_owned()
        )
    );
    assert_eq!(
        route_response(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guardApprovalRequestId":"req_12345678"}"#,
            PRE_TOOL_USE
        ),
        Route::AwaitApproval(pending("req_12345678", None), BARE_DENY.to_owned())
    );
}

#[test]
fn a_request_key_python_refuses_keeps_the_deny() {
    for answer in [
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guardApprovalRequestId":null}"#,
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guardApprovalRequestId":7}"#,
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guardApprovalRequestId":"short"}"#,
        // An id the daemon never resolves keeps the deny without a wait.
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guardApprovalRequestId":"req_abcd\u00e9fgh"}"#,
    ] {
        assert_eq!(
            route_response(answer, PRE_TOOL_USE),
            Route::Respond(BARE_DENY.to_owned()),
            "{answer}"
        );
    }
}

#[test]
fn a_sandbox_requirement_is_contained_natively() {
    let answer = r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"policy_action":"sandbox-required"}"#;
    let Route::Contain(response, mapped) = route_response(answer, PRE_TOOL_USE) else {
        panic!("a sandbox requirement is settled by `contain`");
    };
    assert_eq!(
        response.get("policy_action").and_then(PyVal::as_str),
        Some("sandbox-required")
    );
    assert!(!mapped);
    // Only a `PreToolUse` answer is contained.
    assert!(matches!(
        route_response(answer, "PermissionRequest"),
        Route::Respond(_)
    ));
}

#[test]
fn an_observation_wraps_the_settled_route() {
    let observed = |answer: &str| match route_response(answer, PRE_TOOL_USE) {
        Route::Observed(envelope, route) => {
            assert_eq!(envelope, PyVal::Dict(Vec::new()), "{answer}");
            *route
        }
        route => panic!("{answer}: {route:?}"),
    };
    assert!(matches!(
        observed(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"policy_action":"sandbox-required","guard_transition_observation":{}}"#
        ),
        Route::Contain(..)
    ));
    assert_eq!(
        observed(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guard_transition_observation":{}}"#
        ),
        Route::Respond(BARE_DENY.to_owned())
    );
    assert!(matches!(
        observed(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny"},"guardApprovalRequestId":"req_12345678","guard_transition_observation":{}}"#
        ),
        Route::AwaitApproval(..)
    ));
}
