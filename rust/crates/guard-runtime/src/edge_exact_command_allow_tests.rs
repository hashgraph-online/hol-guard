use std::path::Path;

use guard_contracts::{
    PreToolActionTypeV1, PreToolActionV1, PreToolOperationV1, PreToolResultV1,
    PRE_TOOL_ACTION_V1_SCHEMA,
};
use rusqlite::{params, Connection};

use super::*;
use crate::edge_exact_command_review::{apply_with, Call};
use crate::policy_enforcement::validate_pre_tool_result_matrix;

/// 2026-11-01T00:00:00Z.
const NOW: i64 = 1_793_491_200_000_000;
const COMMAND: &str = "npm publish --tag next";

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
        decision: "deny".into(),
        policy_action: minimum_action.into(),
        minimum_action: minimum_action.into(),
        reason_code: "native_test".into(),
        reason: "native test".into(),
        explicitly_benign: false,
        command_extensions: None,
        prompt_risk_classes: Vec::new(),
    }
}

fn call(command: &str) -> Call<'_> {
    Call {
        commands: vec![command],
        workspace: None,
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

struct Row<'a> {
    harness: &'a str,
    command: &'a str,
    scope: &'a str,
    action: &'a str,
    source: &'a str,
    expires_at: Option<&'a str>,
}

fn allow_rule(command: &str) -> Row<'_> {
    Row {
        harness: "*",
        command,
        scope: "artifact",
        action: "allow",
        source: "policy-bundle",
        expires_at: None,
    }
}

fn home(rows: &[Row<'_>]) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let connection = Connection::open(home.path().join(STORE_FILE_NAME)).unwrap();
    connection
        .execute_batch(
            "create table policy_decisions (harness text, scope text, artifact_id text, \
             artifact_hash text, workspace text, publisher text, action text, reason text, \
             owner text, source text, expires_at text)",
        )
        .unwrap();
    for row in rows {
        connection
            .execute(
                "insert into policy_decisions values (?1, ?2, ?3, null, null, null, ?4, \
                 'Allowed from an approval', 'team', ?5, ?6)",
                params![
                    row.harness,
                    row.scope,
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

/// A signed bundle that still yields every saved `policy-bundle` row.
fn yields_every_row(connection: &Connection, _now: &str) -> Option<Vec<Identity>> {
    let mut statement = connection
        .prepare(
            "select harness, scope, artifact_id, artifact_hash, workspace, publisher, action, \
             reason, owner, source, expires_at from policy_decisions \
             where source = 'policy-bundle'",
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            (0..11)
                .map(|index| {
                    row.get::<_, Option<String>>(index)
                        .map(|value| value.map_or(Value::Null, Value::String))
                })
                .collect::<rusqlite::Result<Identity>>()
        })
        .unwrap();
    Some(rows.map(Result::unwrap).collect())
}

/// A bundle Guard validated that no longer yields the rows, such as one
/// replaced or rolled back.
fn yields_nothing(_connection: &Connection, _now: &str) -> Option<Vec<Identity>> {
    Some(Vec::new())
}

/// A bundle Guard cannot validate.
fn unavailable(_connection: &Connection, _now: &str) -> Option<Vec<Identity>> {
    None
}

fn reviewed(reason_code: &str) -> PreToolResultV1 {
    let mut reviewed = result(PreToolActionTypeV1::Package, "review");
    reviewed.reason_code = reason_code.into();
    reviewed
}

fn edge(
    home: &Path,
    call: &Call<'_>,
    result: PreToolResultV1,
    identities: BundleIdentities,
) -> PreToolResultV1 {
    apply_with(home, call, Some(NOW), result, identities)
}

#[test]
fn a_cloud_allow_rule_settles_the_review_of_its_exact_command() {
    let home = home(&[allow_rule(COMMAND)]);
    for reason_code in LIFTABLE_REASONS {
        let settled = edge(
            home.path(),
            &call(COMMAND),
            reviewed(reason_code),
            yields_every_row,
        );
        assert_eq!(settled.decision, "allow", "{reason_code}");
        assert_eq!(settled.minimum_action, "allow");
        assert_eq!(settled.policy_action, "allow");
        assert!(settled.explicitly_benign);
        assert_eq!(settled.reason_code, "policy_exact_command_allow");
        assert!(settled.reason.contains("Guard Cloud policy"));
        validate_pre_tool_result_matrix(&settled).unwrap();
    }
}

#[test]
fn a_rule_the_signed_bundle_does_not_yield_lifts_nothing() {
    let home = home(&[allow_rule(COMMAND)]);
    let review = reviewed("native_package_review");
    for identities in [yields_nothing as BundleIdentities, unavailable] {
        assert_eq!(
            edge(home.path(), &call(COMMAND), review.clone(), identities),
            review
        );
    }
}

#[test]
fn only_the_exact_command_is_allowed() {
    let home = home(&[allow_rule(COMMAND)]);
    let review = reviewed("native_package_review");
    for command in [
        "npm publish --tag latest",
        "npm publish --tag next --access public",
        "npm publish --tag next; rm -rf build",
        "CI=1 npm publish --tag next",
    ] {
        assert_eq!(
            edge(
                home.path(),
                &call(command),
                review.clone(),
                yields_every_row
            ),
            review,
            "{command}"
        );
    }
}

#[test]
fn a_review_that_is_not_a_shape_judgment_stays() {
    let home = home(&[allow_rule(COMMAND)]);
    for reason_code in [
        "native_secret_access",
        "native_guard_control",
        "network_protection_review",
        "native_test",
    ] {
        let review = reviewed(reason_code);
        assert_eq!(
            edge(
                home.path(),
                &call(COMMAND),
                review.clone(),
                yields_every_row
            ),
            review,
            "{reason_code}"
        );
    }
    for minimum in ["require-reapproval", "sandbox-required", "block"] {
        let mut stronger = result(PreToolActionTypeV1::Package, minimum);
        stronger.reason_code = "native_package_review".into();
        assert_eq!(
            edge(
                home.path(),
                &call(COMMAND),
                stronger.clone(),
                yields_every_row
            ),
            stronger,
            "{minimum}"
        );
    }
    let mut sensitive = reviewed("native_package_review");
    sensitive.action.sensitive_target = true;
    let mut unbounded = reviewed("native_package_review");
    unbounded.action.bounded = false;
    let mut raised_policy = reviewed("native_package_review");
    raised_policy.policy_action = "require-reapproval".into();
    for review in [sensitive, unbounded, raised_policy] {
        assert_eq!(
            edge(
                home.path(),
                &call(COMMAND),
                review.clone(),
                yields_every_row
            ),
            review
        );
    }
}

#[test]
fn a_block_or_review_rule_wins_over_the_allow() {
    let review = reviewed("native_package_review");
    for action in ["block", "review"] {
        let home = home(&[
            allow_rule(COMMAND),
            Row {
                action,
                ..allow_rule(COMMAND)
            },
        ]);
        let answered = edge(
            home.path(),
            &call(COMMAND),
            review.clone(),
            yields_every_row,
        );
        assert_ne!(answered.decision, "allow", "{action}");
    }
}

#[test]
fn only_a_live_signed_bundle_rule_for_this_harness_lifts() {
    let review = reviewed("native_package_review");
    for row in [
        Row {
            harness: "codex",
            ..allow_rule(COMMAND)
        },
        Row {
            expires_at: Some("2026-10-31T23:59:59Z"),
            ..allow_rule(COMMAND)
        },
        Row {
            source: "approval-gate",
            ..allow_rule(COMMAND)
        },
        Row {
            source: "cloud-sync",
            ..allow_rule(COMMAND)
        },
        Row {
            scope: "workspace",
            ..allow_rule(COMMAND)
        },
    ] {
        let home = home(&[row]);
        assert_eq!(
            edge(
                home.path(),
                &call(COMMAND),
                review.clone(),
                yields_every_row
            ),
            review
        );
    }
    let own = home(&[Row {
        harness: "claude-code",
        ..allow_rule(COMMAND)
    }]);
    assert_eq!(
        edge(own.path(), &call(COMMAND), review, yields_every_row).decision,
        "allow"
    );
}

#[test]
fn a_store_without_rules_keeps_the_review() {
    let empty = tempfile::tempdir().unwrap();
    let review = reviewed("native_package_review");
    assert_eq!(
        edge(
            empty.path(),
            &call(COMMAND),
            review.clone(),
            yields_every_row
        ),
        review
    );
}
