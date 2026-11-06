//! What one relayed package call answers with, and when the lane asks for the
//! second resolution at all.

use std::cell::Cell;

use guard_command::effect_decision::GuardAction;
use guard_command::package_execution_context::PackageExecutionContext;
use serde_json::json;

use super::*;
use crate::mcp_tool_policy_decision::Current;

const TOOL: &str = "install_package";
const SERVER: &str = "registry";

/// The blocked-request mode a queued request is answered under, with the
/// receipt redaction level the silent inbox row is written with.
fn bound(blocked_request_mode: &'static str) -> QueueBinding<'static> {
    QueueBinding {
        blocked_request_mode: Some(blocked_request_mode),
        redaction_level: Some("full"),
    }
}

/// A resolved package policy whose evaluation settled on `policy_action` and
/// reported `reasons`.
fn policy(policy_action: &str, reasons: Value) -> PackagePolicy {
    let mut evaluation = Map::new();
    evaluation.insert("policy_action".to_owned(), json!(policy_action));
    evaluation.insert("decision".to_owned(), json!(policy_action));
    evaluation.insert("reasons".to_owned(), reasons);
    evaluation.insert("packages".to_owned(), json!([]));
    evaluation.insert(
        "risk_summary".to_owned(),
        json!("left-pad was published yesterday"),
    );
    evaluation.insert(
        "user_copy".to_owned(),
        json!({"title": "Package request needs review", "dashboard_url": "https://hol.org/guard"}),
    );
    PackagePolicy {
        evaluation,
        current_action: GuardAction::Review,
        artifact_hash: "guard-approval-context:v1:abc".to_owned(),
        policy_workspace: Some("package-request-workspace:v2:abc".to_owned()),
        execution_context: PackageExecutionContext {
            digest: "ctx".to_owned(),
            portable: true,
            components: Vec::new(),
            non_portable_reason: None,
        },
        reused_decision: None,
        claim_disposition: None,
    }
}

/// The lane's own answer, for a call no tool leg decided.
fn answered(outcome: PackageOutcome) -> PackageAnswer {
    match outcome {
        PackageOutcome::Answered(answer)
        | PackageOutcome::AskPackage(answer)
        | PackageOutcome::ObservePackage { answer, .. } => answer,
        PackageOutcome::ToolLeg(leg) => panic!("the package lane answers this leg: {leg:?}"),
        PackageOutcome::ClaimPackage(leg) => {
            panic!("the caller claims this forward's rows: {leg:?}")
        }
    }
}

fn tool(action: GuardAction) -> Decision {
    Decision::plain(Current {
        action,
        source: "policy".to_owned(),
        signals: Vec::new(),
        summary: "installs a package".to_owned(),
        risk_categories: Vec::new(),
    })
}

#[test]
fn a_call_the_precheck_stops_is_never_re_resolved() {
    let asked = Cell::new(false);
    let saved_block = policy("allow", json!([{"code": "saved_package_block"}]));
    let answer = answered(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &saved_block,
            bound("safe-alternative"),
            || {
                asked.set(true);
                Ok((tool(GuardAction::Allow), policy("allow", json!([]))))
            },
        )
        .expect("the precheck answers the call"),
    );
    assert!(
        !asked.get(),
        "the proxy re-resolves nothing for a stopped call"
    );
    let (message, data) = answer.block.expect("a stopped call answers with a block");
    assert!(
        message.contains("already blocked by stored policy"),
        "{message}"
    );
    assert_eq!(data["guardPolicyAction"], json!("block"));
    assert_eq!(answer.decision, "package-block-stored");
    assert_eq!(answer.decision_source, package_answer::BLOCK_SOURCE);
    assert_eq!(answer.policy_action, "block");
    // The receipt binds the decision to the request the precheck read.
    assert_eq!(answer.artifact_hash, saved_block.artifact_hash);
    assert_eq!(answer.policy_workspace, saved_block.policy_workspace);
    assert_eq!(answer.signals, vec!["saved_package_block".to_owned()]);
}

#[test]
fn a_forwarded_call_answers_from_the_re_resolved_policy() {
    let answer = answered(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            bound("safe-alternative"),
            || {
                Ok((
                    tool(GuardAction::Warn),
                    policy("allow", json!([{"message": "left-pad is newly published"}])),
                ))
            },
        )
        .expect("neither policy stops the call"),
    );
    assert_eq!(answer.block, None);
    assert_eq!(answer.policy_action, "warn");
    assert_eq!(answer.decision_source, "policy-warn");
    assert_eq!(answer.decision, "package-warn");
    // The reasons are the second resolution's, not the precheck's.
    assert_eq!(
        answer.signals,
        vec!["left-pad is newly published".to_owned()],
    );
}

#[test]
fn a_composed_terminal_answers_as_the_package_response() {
    let answer = answered(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            bound("safe-alternative"),
            || Ok((tool(GuardAction::Block), policy("allow", json!([])))),
        )
        .expect("the composition stops the call"),
    );
    let (message, data) = answer.block.expect("a stopped call answers with a block");
    assert_eq!(
        message,
        "HOL Guard blocked package install request install_package from registry."
    );
    assert_eq!(data["supplyChainEvaluation"]["decision"], json!("allow"));
    assert_eq!(answer.decision, "terminal-package-block");
}

#[test]
fn a_queued_request_blocks_in_place_under_safe_alternative() {
    let reviewed = policy(
        "review",
        json!([{"message": "left-pad is newly published"}]),
    );
    let answer = answered(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &reviewed,
            bound("safe-alternative"),
            || panic!("a queued precheck re-resolves nothing"),
        )
        .expect("the precheck queues the request"),
    );
    let (message, data) = answer.block.expect("a queued request answers with a block");
    assert!(
        message.contains("HOL Guard blocked tool call install_package from registry."),
        "{message}"
    );
    // The guidance names the risk summary before the reasons, as the proxy's
    // own signals do.
    assert!(
        message.contains("left-pad was published yesterday left-pad is newly published"),
        "{message}"
    );
    assert_eq!(data["transportOutcome"], json!("not-forwarded"));
    assert_eq!(data["guardPolicyAction"], json!("block"));
    assert_eq!(data["approvalRequests"], json!([]));
    // The evaluation is restated as the block the agent was actually given.
    let evaluation = &data["supplyChainEvaluation"];
    assert_eq!(evaluation["decision"], json!("block"));
    assert_eq!(evaluation["policy_action"], json!("block"));
    assert_eq!(
        evaluation["user_copy"]["title"],
        json!("Package request blocked")
    );
    assert_eq!(
        evaluation["user_copy"]["summary"],
        json!("left-pad was published yesterday")
    );
    assert_eq!(evaluation["user_copy"]["dashboard_url"], Value::Null);
    assert_eq!(evaluation["user_copy"]["next_step"], json!(message));
    assert_eq!(evaluation["user_copy"]["harness_message"], json!(message));
    // The receipt is the queue route's, recorded under the action the policy
    // settled on rather than the `block` the agent was answered with.
    assert_eq!(answer.decision_source, queue::SAFE_ALTERNATIVE_SOURCE);
    assert_eq!(answer.decision, "safe-alternative");
    assert_eq!(answer.policy_action, "review");
    assert_eq!(answer.redaction_level.as_deref(), Some("full"));
    assert_eq!(
        answer.signals,
        vec![
            "left-pad was published yesterday".to_owned(),
            "left-pad is newly published".to_owned(),
        ],
    );
}

#[test]
fn the_composed_queue_blocks_in_place_on_the_re_resolved_policy() {
    let answer = answered(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            bound("safe-alternative"),
            || Ok((tool(GuardAction::Allow), policy("review", json!([])))),
        )
        .expect("the composition queues the request"),
    );
    assert!(answer.block.is_some(), "a queued request is stopped");
    assert_eq!(answer.decision_source, queue::SAFE_ALTERNATIVE_SOURCE);
    assert_eq!(answer.policy_action, "review");
    assert_eq!(answer.redaction_level.as_deref(), Some("full"));
}

#[test]
fn a_queued_request_the_ask_mode_bound_is_left_for_the_caller_to_write() {
    // The caller writes the package-shaped approval row and completes the
    // answer, so the lane states the facts the row and the receipt are built
    // from and names neither a block nor a receipt redaction level.
    for outcome in [
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy(
                "review",
                json!([{"code": "advisory", "message": "left-pad has an advisory"}]),
            ),
            bound("ask"),
            || panic!("a queued precheck re-resolves nothing"),
        ),
        // The composition's, once the fresh package policy asks for approval.
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            bound("ask"),
            || {
                Ok((
                    tool(GuardAction::Allow),
                    policy(
                        "review",
                        json!([{"code": "advisory", "message": "left-pad has an advisory"}]),
                    ),
                ))
            },
        ),
    ] {
        let outcome = outcome.expect("the lane answers the queued request");
        assert!(matches!(outcome, PackageOutcome::AskPackage(_)));
        let answer = answered(outcome);
        assert_eq!(answer.block, None);
        assert_eq!(answer.policy_action, "review");
        assert_eq!(answer.decision_source, "approval-center-pending");
        assert_eq!(answer.decision, "queue-package-approval");
        // The reason signals alone, not the risk summary the
        // `safe-alternative` branch leads its own with.
        assert_eq!(answer.signals, vec!["left-pad has an advisory".to_owned()]);
        assert_eq!(answer.redaction_level, None);
        assert_eq!(answer.approval, None);
    }
}

#[test]
fn a_queued_request_defers_under_every_other_blocked_request_mode() {
    // A binding whose configs left no mode or no redaction level at all.
    for binding in [
        QueueBinding {
            blocked_request_mode: None,
            redaction_level: Some("full"),
        },
        QueueBinding {
            blocked_request_mode: Some("safe-alternative"),
            redaction_level: None,
        },
    ] {
        assert_eq!(
            decide_package(
                "enforce",
                TOOL,
                SERVER,
                &policy("review", json!([])),
                binding,
                || panic!("a queued precheck re-resolves nothing"),
            )
            .err(),
            Some(package_route::PACKAGE_QUEUE),
        );
    }
}

#[test]
fn a_leg_the_tool_policy_decided_is_named_for_the_tool_lane() {
    // `queue_tool`, `terminal_tool` and `stored_tool_block` are answered by
    // the plain tool-policy responses, so the lane hands them back rather than
    // rendering a package answer and its `mcp_package_call` receipt.
    assert_eq!(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            bound("safe-alternative"),
            || Ok((tool(GuardAction::Review), policy("allow", json!([]))))
        ),
        Ok(PackageOutcome::ToolLeg(ToolLeg::Queue {
            policy_action: "review".to_owned(),
        })),
    );
    let mut blocked = tool(GuardAction::Allow);
    blocked.saved_action = Some(GuardAction::Block);
    assert_eq!(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            bound("safe-alternative"),
            || Ok((blocked, policy("allow", json!([]))))
        ),
        Ok(PackageOutcome::ToolLeg(ToolLeg::StoredBlock)),
    );
    assert_eq!(
        decide_package(
            "observe",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            bound("safe-alternative"),
            || Ok((tool(GuardAction::Block), policy("allow", json!([]))))
        ),
        Ok(PackageOutcome::ToolLeg(ToolLeg::Terminal {
            policy_action: "block".to_owned(),
        })),
    );
}

#[test]
fn a_second_resolution_the_caller_could_not_read_defers_the_call() {
    assert_eq!(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            bound("safe-alternative"),
            || Err("mcp_relay_store_unreadable")
        )
        .err(),
        Some("mcp_relay_store_unreadable"),
    );
}

#[test]
fn a_forward_the_relay_cannot_bind_to_its_archives_is_blocked_instead() {
    let mut demanding = policy("allow", json!([]));
    demanding.evaluation.insert(
        "external_archive_source_hashes".to_owned(),
        json!(["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]),
    );
    let answer = answered(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            bound("safe-alternative"),
            || Ok((tool(GuardAction::Allow), demanding)),
        )
        .expect("the refused binding answers the call"),
    );
    let (message, data) = answer.block.expect("the call is not forwarded");
    assert_eq!(
        message,
        "HOL Guard blocked package install request install_package from registry."
    );
    assert_eq!(answer.policy_action, "block");
    assert_eq!(answer.decision, "terminal-package-block");
    assert_eq!(answer.decision_source, package_answer::BLOCK_SOURCE);
    // The evaluation the agent is given is the override's, and the receipt
    // records its reason.
    let evaluation = &data["supplyChainEvaluation"];
    assert_eq!(evaluation["decision"], json!("block"));
    assert_eq!(
        evaluation["reasons"][0]["code"],
        json!("external_archive_digest_mismatch")
    );
    assert_eq!(
        answer.signals,
        vec![
            "The inspected external archive changed or was absent from the forwarded request."
                .to_owned()
        ],
    );
}
