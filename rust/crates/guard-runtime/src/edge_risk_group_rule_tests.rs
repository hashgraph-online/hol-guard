//! Guard Cloud rules that name a command risk group, as the hook applies them.

use super::super::tests::{allowed, call, home, result, rule, NOW};
use super::super::*;
use crate::policy_enforcement::validate_pre_tool_result_matrix;

/// A Guard home whose store holds one risk-group rule per `(group, action,
/// harness, workspace)`.
fn group_home(groups: &[(&str, &str, &str, Option<&str>)]) -> tempfile::TempDir {
    let home = home(&[]);
    let connection = rusqlite::Connection::open(home.path().join(STORE_FILE_NAME)).unwrap();
    for (group, action, harness, workspace) in groups {
        connection
            .execute(
                "insert into policy_decisions values (?1, ?2, ?3, ?4, 'policy-bundle-canonical', null, ?5)",
                params![
                    harness,
                    if workspace.is_some() { "workspace" } else { "harness" },
                    format!("risk-group:{group}"),
                    action,
                    workspace
                ],
            )
            .unwrap();
    }
    home
}

#[test]
fn a_delete_rule_asks_before_any_command_that_deletes() {
    let home = group_home(&[("deletes", "review", "*", None)]);
    for command in [
        "rm -rf build",
        "sudo rm -f notes.txt",
        "git clean -fdx",
        "find . -name '*.log' -delete",
    ] {
        let raised = apply(home.path(), &call(command), Some(NOW), allowed());
        assert_eq!(raised.decision, "deny", "{command}");
        assert_eq!(raised.minimum_action, "review", "{command}");
        assert_eq!(raised.reason_code, "policy_risk_group_review", "{command}");
        assert!(raised.reason.contains("delete files or data"), "{command}");
        assert!(is_review_finding(&raised.reason_code));
        validate_pre_tool_result_matrix(&raised).unwrap();
    }
}

#[test]
fn a_command_outside_the_group_runs_as_before() {
    let home = group_home(&[("deletes", "review", "*", None)]);
    for command in ["ls -la", "git status", "echo rm -rf build", "cat notes.txt"] {
        assert_eq!(
            apply(home.path(), &call(command), Some(NOW), allowed()),
            allowed(),
            "{command}"
        );
    }
}

#[test]
fn a_block_rule_stops_the_command_and_no_approval_runs_it() {
    let home = group_home(&[("deletes", "block", "*", None)]);
    let blocked = apply(home.path(), &call("rm -rf build"), Some(NOW), allowed());
    assert_eq!(blocked.decision, "deny");
    assert_eq!(blocked.minimum_action, "block");
    assert_eq!(blocked.reason_code, "policy_risk_group_block");
    assert!(!is_review_finding(&blocked.reason_code));
    validate_pre_tool_result_matrix(&blocked).unwrap();
}

#[test]
fn a_group_block_wins_over_an_exact_review() {
    let home = home(&[rule("rm -rf build")]);
    let connection = rusqlite::Connection::open(home.path().join(STORE_FILE_NAME)).unwrap();
    connection
        .execute(
            "insert into policy_decisions values ('*', 'harness', 'risk-group:deletes', 'block', 'policy-bundle-canonical', null, null)",
            [],
        )
        .unwrap();
    let blocked = apply(home.path(), &call("rm -rf build"), Some(NOW), allowed());
    assert_eq!(blocked.reason_code, "policy_risk_group_block");
}

#[test]
fn an_exact_review_keeps_its_own_words_over_a_group_review() {
    let home = home(&[rule("rm -rf build")]);
    let connection = rusqlite::Connection::open(home.path().join(STORE_FILE_NAME)).unwrap();
    connection
        .execute(
            "insert into policy_decisions values ('*', 'harness', 'risk-group:deletes', 'review', 'policy-bundle-canonical', null, null)",
            [],
        )
        .unwrap();
    let raised = apply(home.path(), &call("rm -rf build"), Some(NOW), allowed());
    assert_eq!(raised.reason_code, "policy_exact_command_review");
}

#[test]
fn a_rule_for_another_harness_or_folder_does_not_apply() {
    let home = group_home(&[
        ("deletes", "review", "codex", None),
        ("deletes", "block", "*", Some("/work/other")),
    ]);
    assert_eq!(
        apply(home.path(), &call("rm -rf build"), Some(NOW), allowed()),
        allowed()
    );
    let here = Call {
        commands: vec!["rm -rf build"],
        workspace: Some("/work/other"),
    };
    assert_eq!(
        apply(home.path(), &here, Some(NOW), allowed()).reason_code,
        "policy_risk_group_block"
    );
}

#[test]
fn a_stronger_result_is_kept() {
    let home = group_home(&[("deletes", "review", "*", None)]);
    for minimum in ["review", "require-reapproval", "sandbox-required", "block"] {
        let stronger = result(PreToolActionTypeV1::Command, minimum);
        assert_eq!(
            apply(
                home.path(),
                &call("rm -rf build"),
                Some(NOW),
                stronger.clone()
            ),
            stronger,
            "{minimum}"
        );
    }
}
