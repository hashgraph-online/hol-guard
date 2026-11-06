//! The text, payload and receipt facts each stopped or forwarded package call
//! answers with, against the proxy's own renderers.

use guard_command::effect_decision::GuardAction;
use guard_command::package_execution_context::PackageExecutionContext;
use serde_json::{json, Map};

use super::*;

const TOOL: &str = "install_package";
const SERVER: &str = "registry";

fn policy(reasons: serde_json::Value) -> PackagePolicy {
    let mut evaluation = Map::new();
    evaluation.insert("policy_action".to_owned(), json!("block"));
    evaluation.insert("decision".to_owned(), json!("block"));
    evaluation.insert("reasons".to_owned(), reasons);
    PackagePolicy {
        evaluation,
        current_action: GuardAction::Review,
        artifact_hash: "deadbeef".to_owned(),
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

#[test]
fn a_stored_package_block_names_the_authenticated_saved_policy() {
    let policy = policy(json!([{"code": "saved_package_block"}]));
    let (message, data) = block(
        &PackageRoute::StoredPackageBlock,
        TOOL,
        SERVER,
        &policy,
        &[],
    )
    .expect("a stopped call answers with a block");
    assert_eq!(
        message,
        "HOL Guard blocked package install request install_package from registry. This exact \
         request is already blocked by stored policy with authenticated local integrity."
    );
    assert_eq!(data["guardPolicyAction"], json!("block"));
    assert_eq!(data["approvalRequests"], json!([]));
    // The caller sees the evaluation the lane settled on, not just the action.
    assert_eq!(data["supplyChainEvaluation"]["decision"], json!("block"));
    assert_eq!(
        decision_label(&PackageRoute::StoredPackageBlock),
        "package-block-stored"
    );
}

#[test]
fn a_terminal_package_action_reads_as_a_block_or_a_missing_sandbox() {
    for (action, expected) in [
        (
            "block",
            "HOL Guard blocked package install request install_package from registry.",
        ),
        (
            "sandbox-required",
            "HOL Guard requires an enforceable sandbox for package install request \
             install_package from registry; this runtime cannot provide one.",
        ),
    ] {
        let route = PackageRoute::TerminalPackage {
            policy_action: action.to_owned(),
        };
        let (message, data) = block(&route, TOOL, SERVER, &policy(json!([])), &[])
            .expect("a stopped call answers with a block");
        assert_eq!(message, expected, "{action}");
        assert_eq!(data["guardPolicyAction"], json!(action), "{action}");
        assert!(data.get("supplyChainEvaluation").is_some(), "{action}");
        assert_eq!(decision_label(&route), format!("terminal-package-{action}"));
    }
}

#[test]
fn a_forwarded_call_answers_with_no_block_and_records_the_action_it_ran_under() {
    let route = PackageRoute::Forward {
        policy_action: "warn".to_owned(),
    };
    assert_eq!(block(&route, TOOL, SERVER, &policy(json!([])), &[]), None);
    assert_eq!(decision_source(&route), "policy-warn");
    assert_eq!(decision_label(&route), "package-warn");
    // A stopped call records the block source instead.
    assert_eq!(
        decision_source(&PackageRoute::StoredPackageBlock),
        BLOCK_SOURCE,
    );
}

#[test]
fn the_receipt_signals_are_each_reasons_message_then_its_code() {
    let evaluated = policy(json!([
        {"code": "advisory", "message": "left-pad has an advisory"},
        {"code": "unsigned"},
        {"message": ""},
        {},
    ]));
    assert_eq!(
        reason_signals(&evaluated),
        vec![
            "left-pad has an advisory".to_owned(),
            "unsigned".to_owned(),
            String::new(),
            String::new(),
        ],
    );
    // An evaluation with no reasons at all signals nothing.
    let mut empty = policy(json!([]));
    empty.evaluation.remove("reasons");
    assert!(reason_signals(&empty).is_empty());
}
