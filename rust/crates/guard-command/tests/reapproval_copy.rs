use guard_command::decisions;
use guard_contracts::{build_authoritative_decision, GuardAction};
use serde_json::{json, Map};

#[test]
fn rejected_authority_reuse_retains_fresh_approval_without_claiming_changed_content() {
    let reason = "approval_reuse_expired";
    let mut trace = Map::new();
    trace.insert("final_action".into(), json!("require-reapproval"));
    let command = decisions::build_authoritative_decision(
        GuardAction::RequireReapproval,
        reason,
        &trace,
        &[],
        true,
        "composed-consumer-policy",
    )
    .unwrap();
    let contract = build_authoritative_decision(
        GuardAction::RequireReapproval,
        reason,
        trace,
        &[],
        true,
        "composed-consumer-policy",
    )
    .unwrap();

    for (body, blocking, launch_permitted, prompt_required, preserved_reason) in [
        (
            &command.decision_v2.user_body,
            command.enforcement.blocking,
            command.enforcement.launch_permitted,
            command.enforcement.prompt_required,
            &command.reason,
        ),
        (
            &contract.decision_v2.user_body,
            contract.enforcement.blocking,
            contract.enforcement.launch_permitted,
            contract.enforcement.prompt_required,
            &contract.reason,
        ),
    ] {
        assert_eq!(
            body,
            "HOL Guard needs a fresh approval before this action can run."
        );
        assert_eq!(preserved_reason, reason);
        assert!(blocking);
        assert!(!launch_permitted);
        assert!(prompt_required);
    }
    assert_eq!(
        command.decision_v2.action.as_str(),
        contract.decision_v2.action
    );
    // The command adapter and shared contract expose different existing scope vocabularies.
    assert_eq!(
        command.decision_v2.approval_scopes,
        ["artifact", "workspace", "publisher", "harness"]
    );
    assert_eq!(
        contract.decision_v2.approval_scopes,
        ["once", "task", "always"]
    );
}
