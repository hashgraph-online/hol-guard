use super::*;
use crate::policy_enforcement::validate_pre_tool_result_matrix;
use guard_contracts::{PreToolActionV1, PreToolOperationV1, PRE_TOOL_ACTION_V1_SCHEMA};

/// 2026-11-01T00:00:00Z.
const NOW: i64 = 1_793_491_200_000_000;

fn result(action_type: PreToolActionTypeV1, minimum_action: &str) -> PreToolResultV1 {
    PreToolResultV1 {
        schema: "guard-pre-tool-result.v1".into(),
        version: 1,
        authority: "rust".into(),
        action: PreToolActionV1 {
            schema: PRE_TOOL_ACTION_V1_SCHEMA.into(),
            version: 1,
            harness: "claude-code".into(),
            event: "PreToolUse".into(),
            action_type,
            operation: PreToolOperationV1::Execute,
            bounded: true,
            sensitive_target: false,
        },
        decision: if matches!(minimum_action, "allow" | "warn") {
            "allow"
        } else {
            "deny"
        }
        .into(),
        policy_action: minimum_action.into(),
        minimum_action: minimum_action.into(),
        reason_code: "native_test".into(),
        reason: "native test".into(),
        explicitly_benign: minimum_action == "allow",
        command_extensions: None,
        prompt_risk_classes: Vec::new(),
    }
}

fn allowed() -> PreToolResultV1 {
    result(PreToolActionTypeV1::Command, "allow")
}

struct Row<'a> {
    harness: &'a str,
    command: &'a str,
    action: &'a str,
    source: &'a str,
    expires_at: Option<&'a str>,
}

fn rule(command: &str) -> Row<'_> {
    Row {
        harness: "*",
        command,
        action: "review",
        source: "policy-bundle",
        expires_at: None,
    }
}

fn exact_id(command: &str) -> String {
    crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
        command: Some(command),
        artifact_type: Some("shell_command"),
        artifact_id: None,
        artifact_name: None,
        harness: None,
    })
    .exact_artifact_ids[0]
        .clone()
}

fn home(rows: &[Row<'_>]) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let connection = rusqlite::Connection::open(home.path().join(STORE_FILE_NAME)).unwrap();
    connection
        .execute_batch(
            "create table policy_decisions (harness text, scope text, artifact_id text, \
             action text, source text, expires_at text)",
        )
        .unwrap();
    for row in rows {
        connection
            .execute(
                "insert into policy_decisions values (?1, 'artifact', ?2, ?3, ?4, ?5)",
                params![
                    row.harness,
                    exact_id(row.command),
                    row.action,
                    row.source,
                    row.expires_at
                ],
            )
            .unwrap();
    }
    home
}

#[test]
fn a_cloud_review_rule_asks_before_its_exact_command() {
    let home = home(&[rule("git status")]);
    let raised = apply(home.path(), "git status", Some(NOW), allowed());
    assert_eq!(raised.decision, "deny");
    assert_eq!(raised.minimum_action, "review");
    assert_eq!(raised.policy_action, "review");
    assert!(!raised.explicitly_benign);
    assert_eq!(raised.reason_code, "policy_exact_command_review");
    assert!(raised.reason.contains("Guard Cloud policy"));
    assert!(is_review_finding(&raised.reason_code));
    validate_pre_tool_result_matrix(&raised).unwrap();
}

#[test]
fn another_command_runs_as_before() {
    let home = home(&[rule("git status")]);
    for command in ["git status --short", "git  status", "git status "] {
        assert_eq!(
            apply(home.path(), command, Some(NOW), allowed()),
            allowed(),
            "{command}"
        );
    }
}

#[test]
fn a_warning_is_raised_and_a_stronger_result_is_kept() {
    let home = home(&[rule("git status")]);
    let warned = apply(
        home.path(),
        "git status",
        Some(NOW),
        result(PreToolActionTypeV1::Command, "warn"),
    );
    assert_eq!(warned.minimum_action, "review");
    validate_pre_tool_result_matrix(&warned).unwrap();
    for minimum in ["review", "require-reapproval", "sandbox-required", "block"] {
        let stronger = result(PreToolActionTypeV1::Command, minimum);
        assert_eq!(
            apply(home.path(), "git status", Some(NOW), stronger.clone()),
            stronger,
            "{minimum}"
        );
    }
}

#[test]
fn a_raised_policy_action_is_never_lowered() {
    let home = home(&[rule("git status")]);
    let mut stronger_policy = allowed();
    stronger_policy.policy_action = "require-reapproval".into();
    let raised = apply(home.path(), "git status", Some(NOW), stronger_policy);
    assert_eq!(raised.policy_action, "require-reapproval");
    assert_eq!(raised.minimum_action, "review");
    validate_pre_tool_result_matrix(&raised).unwrap();
}

#[test]
fn only_shell_actions_are_checked() {
    let home = home(&[rule("git status")]);
    for action_type in [
        PreToolActionTypeV1::Package,
        PreToolActionTypeV1::Network,
        PreToolActionTypeV1::ProcessService,
    ] {
        let raised = apply(
            home.path(),
            "git status",
            Some(NOW),
            result(action_type, "allow"),
        );
        assert_eq!(raised.minimum_action, "review", "{action_type:?}");
    }
    for action_type in [PreToolActionTypeV1::FileRead, PreToolActionTypeV1::McpTool] {
        let untouched = result(action_type, "allow");
        assert_eq!(
            apply(home.path(), "git status", Some(NOW), untouched.clone()),
            untouched,
            "{action_type:?}"
        );
    }
}

#[test]
fn harness_scope_is_honored() {
    let other = home(&[Row {
        harness: "codex",
        ..rule("git status")
    }]);
    assert_eq!(
        apply(other.path(), "git status", Some(NOW), allowed()),
        allowed()
    );
    let own = home(&[Row {
        harness: "claude-code",
        ..rule("git status")
    }]);
    assert_eq!(
        apply(own.path(), "git status", Some(NOW), allowed()).minimum_action,
        "review"
    );
}

#[test]
fn an_expired_rule_no_longer_asks() {
    let expired = home(&[Row {
        expires_at: Some("2026-10-31T23:59:59Z"),
        ..rule("git status")
    }]);
    assert_eq!(
        apply(expired.path(), "git status", Some(NOW), allowed()),
        allowed()
    );
    // A live row beside an expired one still asks.
    let mixed = home(&[
        Row {
            expires_at: Some("2026-10-31T23:59:59Z"),
            ..rule("git status")
        },
        Row {
            expires_at: Some("2026-11-02T00:00:00+00:00"),
            ..rule("git status")
        },
    ]);
    assert_eq!(
        apply(mixed.path(), "git status", Some(NOW), allowed()).minimum_action,
        "review"
    );
    // An expiry Guard cannot read keeps the rule.
    let unreadable = home(&[Row {
        expires_at: Some("someday"),
        ..rule("git status")
    }]);
    assert_eq!(
        apply(unreadable.path(), "git status", Some(NOW), allowed()).minimum_action,
        "review"
    );
}

#[test]
fn a_local_rule_names_itself() {
    let home = home(&[Row {
        source: "local",
        ..rule("git status")
    }]);
    let raised = apply(home.path(), "git status", Some(NOW), allowed());
    assert_eq!(raised.reason_code, "saved_exact_command_review");
    assert!(is_review_finding(&raised.reason_code));
}

#[test]
fn other_rule_actions_are_left_to_the_daemon() {
    for action in ["block", "allow", "warn"] {
        let home = home(&[Row {
            action,
            ..rule("git status")
        }]);
        assert_eq!(
            apply(home.path(), "git status", Some(NOW), allowed()),
            allowed(),
            "{action}"
        );
    }
}

#[test]
fn a_missing_store_or_table_changes_nothing() {
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        apply(empty.path(), "git status", Some(NOW), allowed()),
        allowed()
    );
    let bare = tempfile::tempdir().unwrap();
    rusqlite::Connection::open(bare.path().join(STORE_FILE_NAME))
        .unwrap()
        .execute_batch("create table other (x text)")
        .unwrap();
    assert_eq!(
        apply(bare.path(), "git status", Some(NOW), allowed()),
        allowed()
    );
}

#[test]
fn other_finding_codes_are_not_this_step() {
    assert!(!is_review_finding("native_command_unproven"));
    assert!(!is_review_finding("network_known_bad_host"));
}
