#![cfg(unix)]

//! Oh My Pi's code mode sends `tool.bash({command, cwd})` through `eval`.
//! The bridge hands `cwd` to the same `bash` tool, so the bridged call gets
//! the verdict the direct call gets: allowed where the direct call is
//! allowed, and never allowed where the direct call is not.

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use crate::pretool_git_session_ops::{default_controls, session, Session};
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};

fn evaluate(session: &Session, harness: &str, tool: &str, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        Some(&default_controls()),
        None,
        session.home.to_str(),
        session.org.to_str(),
    )
}

fn direct(session: &Session, command: &str, cwd: &str) -> PreToolResultV1 {
    evaluate(
        session,
        "omp",
        "bash",
        json!({"command": command, "cwd": cwd}),
    )
}

fn bridged(session: &Session, harness: &str, command: &str, cwd: &str) -> PreToolResultV1 {
    let code = format!(
        "const r = await tool.bash({{command:{}, cwd:{}}}); display(r);",
        serde_json::to_string(command).unwrap(),
        serde_json::to_string(cwd).unwrap(),
    );
    evaluate(
        session,
        harness,
        "eval",
        json!({"language": "js", "code": code, "title": "Inspect", "timeout": null, "reset": false}),
    )
}

/// The shape Oh My Pi's code mode actually writes: the session-tool wrapper's
/// own `i` label and `timeout` beside the call's arguments.
fn bridged_with_timeout(
    session: &Session,
    command: &str,
    cwd: &str,
    label: Option<&str>,
) -> PreToolResultV1 {
    let label = label.map_or(String::new(), |label| {
        format!("i:{}, ", serde_json::to_string(label).unwrap())
    });
    let code = format!(
        "const r = await tool.bash({{{label}command:{}, cwd:{}, timeout:300}}); display(r);",
        serde_json::to_string(command).unwrap(),
        serde_json::to_string(cwd).unwrap(),
    );
    evaluate(
        session,
        "omp",
        "eval",
        json!({"language": "js", "code": code, "title": "Inspect", "timeout": 300, "reset": false}),
    )
}

#[test]
fn bridged_bash_in_a_linked_worktree_matches_the_direct_call() {
    let session = session("omp-eval-cwd-worktree");
    let worktree = session.worktree.to_str().unwrap();
    for command in [
        "git status --short --branch",
        "git log --oneline -3",
        "git status && git log --oneline -3 && git diff",
    ] {
        let alone = direct(&session, command, worktree);
        let result = bridged(&session, "omp", command, worktree);
        assert_eq!(
            result.minimum_action == "allow",
            alone.minimum_action == "allow",
            "{command}: eval {} / direct {}",
            result.reason_code,
            alone.reason_code
        );
    }
    for command in ["git status --short --branch", "git log --oneline -3"] {
        let result = bridged(&session, "omp", command, worktree);
        assert_eq!(result.minimum_action, "allow", "{command}");
        assert_eq!(result.reason_code, "native_omp_eval_bounded_tools");
    }
    // macOS spells the temporary root through the `/tmp` alias.
    if let Ok(rest) = session.worktree.strip_prefix("/private/tmp") {
        let alias = std::path::Path::new("/tmp").join(rest);
        let result = bridged(
            &session,
            "omp",
            "git status --short --branch",
            alias.to_str().unwrap(),
        );
        assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
    }
    let result = bridged(&session, "omp", "git status --short", "app-portal");
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
}

#[test]
fn bridged_bash_keeps_review_where_the_direct_call_has_it() {
    let session = session("omp-eval-cwd-review");
    let worktree = session.worktree.to_str().unwrap();
    std::fs::write(session.worktree.join(".env"), "TOKEN=fixture\n").unwrap();
    let ssh = session.home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("config"), "Host fixture\n").unwrap();
    for (command, cwd) in [
        ("cat .env", worktree),
        ("rm -rf ~/notes", worktree),
        ("cat config", "~/.ssh"),
        ("cat config", ssh.to_str().unwrap()),
        ("rm -rf build", "~/.ssh"),
        ("git status --short", "@app-portal"),
        ("git status --short", "missing"),
    ] {
        let alone = direct(&session, command, cwd);
        assert_ne!(alone.minimum_action, "allow", "direct {command} in {cwd}");
        let result = bridged(&session, "omp", command, cwd);
        assert_ne!(
            result.minimum_action, "allow",
            "{command} in {cwd}: {}",
            result.reason_code
        );
    }
}

#[test]
fn pi_bridged_bash_still_accepts_only_the_session_directory() {
    let session = session("omp-eval-cwd-pi");
    let worktree = session.worktree.to_str().unwrap();
    let result = bridged(&session, "pi", "git status --short --branch", worktree);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}

#[test]
fn a_bridged_timeout_keeps_the_verdict_the_direct_call_gives() {
    let session = session("omp-eval-timeout");
    let worktree = session.worktree.to_str().unwrap();
    for command in ["git status --short --branch", "git log --oneline -3"] {
        let alone = direct(&session, command, worktree);
        assert_eq!(alone.minimum_action, "allow", "{command}: {}", alone.reason);
        let result =
            bridged_with_timeout(&session, command, worktree, Some("inspect the worktree"));
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
        assert_eq!(
            result.reason_code, "native_omp_eval_bounded_tools",
            "{command}"
        );
    }
}

#[test]
fn one_bridged_call_carries_the_reason_the_direct_call_gives() {
    let session = session("omp-eval-one-call");
    let worktree = session.worktree.to_str().unwrap();
    for command in ["rm -rf build", "npm install zod"] {
        let alone = direct(&session, command, worktree);
        assert_ne!(alone.minimum_action, "allow", "{command}: {}", alone.reason);
        let result = bridged_with_timeout(&session, command, worktree, None);
        // Whatever the direct call's verdict is, the bridge never degrades it
        // to "not yet supported", which named no reason the person could act
        // on and left the review without the approval the direct call offers.
        assert_ne!(
            result.reason_code, "native_pre_tool_unknown_review",
            "{command}: {}",
            result.reason
        );
        if matches!(alone.minimum_action.as_str(), "review" | "block") {
            // The bridge adds nothing to judge, so the program says exactly
            // what the direct call says.
            assert_eq!(result.minimum_action, alone.minimum_action, "{command}");
            assert_eq!(result.reason_code, alone.reason_code, "{command}");
        } else {
            // Containment is the inner call's own hook to arrange, so the
            // program stays bounded and that hook contains the call.
            assert_eq!(
                result.reason_code, "native_omp_eval_bounded_tools",
                "{command}: {}",
                result.reason
            );
        }
    }
}
