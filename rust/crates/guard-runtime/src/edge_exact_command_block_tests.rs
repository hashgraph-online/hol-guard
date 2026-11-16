//! Exact-command block rules at the hook edge, under every spelling.

use super::tests::{allowed, call, home, result, rule, Row, NOW};
use super::*;
use crate::policy_enforcement::validate_pre_tool_result_matrix;

#[test]
fn a_cloud_block_denies_every_spelling() {
    let home = home(&[Row {
        action: "block",
        ..rule("npm publish")
    }]);
    for command in [
        "npm publish",
        "  npm publish",
        "npm  publish",
        "npm publish;",
        "npm test && npm publish",
        "npm test; npm publish",
        "CI=1 npm publish",
        "(npm publish)",
        "bash -c 'npm publish'",
        "/usr/local/bin/npm publish",
    ] {
        for minimum in [
            "allow",
            "warn",
            "review",
            "require-reapproval",
            "sandbox-required",
        ] {
            let blocked = apply(
                home.path(),
                &call(command),
                Some(NOW),
                result(PreToolActionTypeV1::Package, minimum),
            );
            assert_eq!(blocked.minimum_action, "block", "{command} {minimum}");
            assert_eq!(blocked.policy_action, "block", "{command} {minimum}");
            assert_eq!(blocked.decision, "deny", "{command} {minimum}");
            assert!(!blocked.explicitly_benign);
            assert_eq!(blocked.reason_code, "policy_exact_command_block");
            validate_pre_tool_result_matrix(&blocked).unwrap();
        }
    }
}

#[test]
fn a_block_leaves_other_commands_alone() {
    let home = home(&[Row {
        action: "block",
        ..rule("npm publish")
    }]);
    for command in [
        "npm publish --dry-run",
        "echo npm publish",
        "git commit -m 'npm publish'",
        "echo \"x; npm publish\"",
        "cat <<EOF\nnpm publish\nEOF",
        "npm pack",
    ] {
        assert_eq!(
            apply(home.path(), &call(command), Some(NOW), allowed()),
            allowed(),
            "{command}"
        );
    }
}

#[test]
fn a_block_wins_over_a_review_and_names_its_source() {
    let home = home(&[
        rule("npm publish"),
        Row {
            action: "block",
            source: "approval-gate",
            ..rule("npm publish")
        },
    ]);
    let blocked = apply(home.path(), &call("npm  publish"), Some(NOW), allowed());
    assert_eq!(blocked.minimum_action, "block");
    assert_eq!(blocked.reason_code, "saved_exact_command_block");
}

#[test]
fn an_expired_or_foreign_block_does_not_apply() {
    let expired = home(&[Row {
        action: "block",
        expires_at: Some("2026-10-31T23:59:59Z"),
        ..rule("npm publish")
    }]);
    assert_eq!(
        apply(expired.path(), &call("npm  publish"), Some(NOW), allowed()),
        allowed()
    );
    let foreign = home(&[Row {
        action: "block",
        harness: "codex",
        ..rule("npm publish")
    }]);
    assert_eq!(
        apply(foreign.path(), &call("npm  publish"), Some(NOW), allowed()),
        allowed()
    );
}

#[test]
fn a_blocked_result_is_kept() {
    let home = home(&[Row {
        action: "block",
        ..rule("npm publish")
    }]);
    let blocked = result(PreToolActionTypeV1::Command, "block");
    assert_eq!(
        apply(
            home.path(),
            &call("npm publish"),
            Some(NOW),
            blocked.clone()
        ),
        blocked
    );
}

#[test]
fn padding_a_line_does_not_hide_the_blocked_step() {
    let home = home(&[Row {
        action: "block",
        ..rule("npm publish")
    }]);
    let trues = (1..=60).map(|n| format!("true {n}")).collect::<Vec<_>>();
    let echoes = (1..=60).map(|n| format!("echo {n}")).collect::<Vec<_>>();
    for command in [
        format!("{} && npm publish", trues.join(" && ")),
        format!("{}; npm publish", echoes.join("; ")),
    ] {
        let blocked = apply(home.path(), &call(&command), Some(NOW), allowed());
        assert_eq!(blocked.minimum_action, "block", "{command}");
    }
}

#[test]
fn a_heredoc_or_shift_does_not_hide_the_blocked_step() {
    let home = home(&[Row {
        action: "block",
        ..rule("npm publish")
    }]);
    for command in [
        "(npm publish); echo '<<'",
        "(npm publish) <<< x",
        "(npm publish); echo $((1<<2))",
        "echo $((1<<2))\nnpm publish",
        "cat <<EOF\nx\nEOF\nnpm publish",
        "cat <<-'EOF' > notes\n\tx\n\tEOF\n(npm publish)",
        "cat <<EOF\nnpm publish",
        "cat <<'E O F'\nx\nE O F\nnpm publish",
        "((npm publish); true)",
        "(true) # <<EOF\nnpm publish\nEOF",
        "bash -euo pipefail -c 'npm publish'",
    ] {
        let blocked = apply(home.path(), &call(command), Some(NOW), allowed());
        assert_eq!(blocked.minimum_action, "block", "{command}");
    }
}

#[test]
fn a_line_too_long_to_read_asks() {
    let ruled = home(&[Row {
        action: "block",
        ..rule("npm publish")
    }]);
    let command = format!(
        "echo {}; npm publish",
        "x".repeat(guard_command::MAX_COMMAND_BYTES)
    );
    let raised = apply(ruled.path(), &call(&command), Some(NOW), allowed());
    assert_eq!(raised.minimum_action, "review");
    assert_eq!(raised.reason_code, "exact_command_line_unreadable");
    validate_pre_tool_result_matrix(&raised).unwrap();

    let other = home(&[]);
    let untouched = apply(other.path(), &call(&command), Some(NOW), allowed());
    assert_eq!(untouched.minimum_action, "allow");
}

#[test]
fn a_line_whose_comments_read_two_ways_asks() {
    let ruled = home(&[Row {
        action: "block",
        ..rule("npm publish")
    }]);
    let command = "(true); echo ${x:- #'}\n<<END '}  # '\nnpm publish\nEND";
    let raised = apply(ruled.path(), &call(command), Some(NOW), allowed());
    assert_ne!(raised.minimum_action, "allow");
    validate_pre_tool_result_matrix(&raised).unwrap();
}
