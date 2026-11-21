use super::{edge, post_edge, pre_edge};
use crate::hook_direct::{budget_bound_review, post_tool_answer, pre_tool_answer, HookDirectDefer};
use serde_json::{json, Value};

#[test]
fn only_a_verdict_the_daemon_passes_through_is_answered() {
    for (decision, minimum_action) in [
        ("allow", "allow"),
        ("allow", "warn"),
        ("deny", "block"),
        ("deny", "sandbox-required"),
    ] {
        let answered = pre_tool_answer(&edge(decision, minimum_action), false).unwrap();
        assert_eq!(answered["result"]["minimum_action"], minimum_action);
    }
    for (decision, minimum_action) in [
        ("deny", "review"),
        ("deny", "require-reapproval"),
        ("allow", "review"),
        ("allow", "require-reapproval"),
        ("allow", "block"),
        ("deny", "warn"),
        ("deny", "allow"),
    ] {
        assert_eq!(
            pre_tool_answer(&edge(decision, minimum_action), false),
            Err(HookDirectDefer::NotAllow),
            "{decision} {minimum_action}"
        );
    }
    let mut missing_response: Value = serde_json::from_slice(&edge("allow", "allow")).unwrap();
    missing_response
        .as_object_mut()
        .unwrap()
        .remove("harness_response");
    assert_eq!(
        pre_tool_answer(&serde_json::to_vec(&missing_response).unwrap(), false),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        pre_tool_answer(b"not json", false),
        Err(HookDirectDefer::EdgeFailed)
    );
}

#[test]
fn an_authority_block_carrying_its_repair_link_is_answered() {
    // The resident composes the command-control repair link at the edge, so
    // this denial no longer has to reach the daemon to be told how to recover.
    let repairable = pre_edge(json!({
        "decision": "deny",
        "minimum_action": "block",
        "reason_code": "native_command_control_authority_block",
    }));
    assert!(pre_tool_answer(&repairable, false).is_ok());
    let other = pre_edge(json!({
        "decision": "deny",
        "minimum_action": "block",
        "reason_code": "native_command_destructive",
    }));
    assert!(pre_tool_answer(&other, false).is_ok());
}

#[test]
fn a_claude_code_sandbox_requirement_defers_to_contained_execution() {
    // The daemon rewrites this Claude Code denial into a contained run.
    assert_eq!(
        pre_tool_answer(&edge("deny", "sandbox-required"), true),
        Err(HookDirectDefer::NotAllow)
    );
    assert!(pre_tool_answer(&edge("deny", "block"), true).is_ok());
    assert!(pre_tool_answer(&edge("deny", "sandbox-required"), false).is_ok());
}

#[test]
fn every_reviewed_post_tool_use_is_answered() {
    let blocked = json!({ "decision": "block", "minimum_action": "block" });
    let answered = post_tool_answer(&post_edge(blocked.clone())).unwrap();
    assert_eq!(answered["result"], blocked);
    assert_eq!(
        post_tool_answer(&post_edge(json!("allow"))),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        post_tool_answer(&edge("allow", "allow")),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        pre_tool_answer(
            &post_edge(json!({ "decision": "allow", "minimum_action": "allow" })),
            false
        ),
        Err(HookDirectDefer::EdgeFailed)
    );
}

#[test]
fn only_a_pre_tool_review_the_short_budget_may_cause_goes_to_the_daemon() {
    for (reason, defer) in [
        (
            "native_git_execution_context_review",
            HookDirectDefer::GitContextReview,
        ),
        (
            "native_git_helper_context_review",
            HookDirectDefer::GitContextReview,
        ),
        (
            "native_command_extension_evaluation_timed_out",
            HookDirectDefer::ExtensionTimedOut,
        ),
    ] {
        let held = json!({
            "decision": "deny",
            "minimum_action": "review",
            "reason_code": reason,
        });
        assert_eq!(budget_bound_review(&pre_edge(held.clone())), Some(defer));
        assert_eq!(budget_bound_review(&post_edge(held)), None, "{reason}");
    }
    for reason in [
        "native_command_destructive",
        "native_command_extension_evaluation_failed",
    ] {
        assert_eq!(
            budget_bound_review(&pre_edge(json!({
                "decision": "deny",
                "minimum_action": "review",
                "reason_code": reason,
            }))),
            None,
            "{reason}"
        );
    }
    assert_eq!(budget_bound_review(&edge("deny", "review")), None);
    assert_eq!(budget_bound_review(b"not json"), None);
}

#[test]
fn a_git_read_held_on_its_checkout_configuration_goes_to_the_daemon() {
    let lane = super::lane("git-context-review", json!({}));
    let git = |arguments: &[&str]| {
        let status = std::process::Command::new("git")
            .args(arguments)
            .current_dir(&lane.workspace)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?}");
    };
    git(&["init", "-q"]);
    // A helper the read would run: the resident keeps no review of its own
    // for it, and leaves the decision to the daemon's longer budget.
    git(&["config", "core.fsmonitor", "/usr/bin/true"]);
    let result = super::run_as(
        &lane,
        "claude-code",
        Some(super::HOME),
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "git status" },
            "cwd": lane.workspace,
        }),
    );
    assert_eq!(super::deferred(&result), "direct_hook_git_context_review");
}
