#![cfg(unix)]

//! Oh My Pi's eval prelude exposes `sh(command)`, which runs the command on
//! the eval shell bridge (`__omp_call_tool__("__shell__")`) instead of through
//! the `bash` tool, so no `bash` hook fires for it. A program that is one
//! literal `sh('…')` call carries the verdict the same command gets as a
//! direct `bash` call, except that containment, which only the `bash` tool's
//! own hook can arrange, is not available to it.

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use crate::pretool_git_session_ops::{default_controls, session, Session};
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};

fn evaluate(session: &Session, tool: &str, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        Some(&default_controls()),
        None,
        session.home.to_str(),
        session.worktree.to_str(),
    )
}

fn direct(session: &Session, command: &str) -> PreToolResultV1 {
    evaluate(session, "bash", json!({"command": command}))
}

fn eval(session: &Session, code: &str) -> PreToolResultV1 {
    evaluate(
        session,
        "eval",
        json!({"language": "js", "code": code, "title": "Run", "timeout": null, "reset": false}),
    )
}

fn with_env(label: &str) -> Session {
    let session = session(label);
    std::fs::write(session.worktree.join(".env"), "MARKER=synthetic\n").unwrap();
    std::fs::create_dir_all(session.worktree.join("output")).unwrap();
    session
}

/// The direct `cp` is a sensitive-access review the person can approve on
/// the `bash` tool. Through `sh()` the same approval would have to be given to
/// the whole eval, so the copy is blocked outright, with no approval request,
/// and the reason sends the person to the `bash` tool.
#[test]
fn a_literal_sh_secret_copy_is_blocked_with_nothing_to_approve() {
    let session = with_env("omp-eval-sh-copy");
    let standalone = direct(&session, "cp .env output/copied.env");
    assert_ne!(standalone.minimum_action, "allow", "{standalone:?}");
    assert!(standalone.action.sensitive_target, "{standalone:?}");
    for code in [
        "await sh('cp .env output/copied.env')",
        "await sh(\"cp .env output/copied.env\");",
        "await sh(`cp .env output/copied.env`)",
        "await sh`cp .env output/copied.env`",
        // Physical CR and CRLF become shell linefeeds in JS template literals.
        "await sh(`echo harmless #\rcp .env output/copied.env`)",
        "await sh`echo harmless #\rcp .env output/copied.env`",
        "await sh(`echo harmless #\r\ncp .env output/copied.env`)",
        "  await sh('cp .env output/copied.env') ;\n",
        "console.log(await sh('cp .env output/copied.env'))",
        // Wherever it sits in the program.
        "await sh('git status --short'); await sh('cp .env output/copied.env')",
        "display(await read('tracked.txt')); await sh('cp .env output/copied.env')",
        "const [a, b] = await Promise.all([read('tracked.txt'), sh('cat .env')]); display(a);",
    ] {
        let result = eval(&session, code);
        assert_eq!(result.decision, "deny", "{code}: {result:?}");
        assert_eq!(result.minimum_action, "block", "{code}: {result:?}");
        assert_eq!(result.policy_action, "block", "{code}: {result:?}");
        assert_eq!(result.reason_code, "native_secret_exfiltration", "{code}");
        assert!(
            result.reason.contains("bash tool"),
            "{code}: {}",
            result.reason
        );
    }
}

/// An unmodeled tool call does not make an earlier or later sh() secret
/// copy approvable. Only the unsafe literal shell command gets precedence;
/// a harmless shell command beside an unmodeled call remains reviewed.
#[test]
fn unmodeled_sibling_cannot_hide_a_secret_copy() {
    let session = with_env("omp-eval-sh-unmodeled-sibling");
    for code in [
        "await sh('cp .env output/copied.env'); await tool.read({path:'tracked.txt', unknown:'x'})",
        "await tool.read({path:'tracked.txt', unknown:'x'}); await sh('cp .env output/copied.env')",
        "await sh('cat .env'); await tool.read({path:'tracked.txt', unknown:'x'})",
    ] {
        let result = eval(&session, code);
        assert_eq!(result.minimum_action, "block", "{code}: {result:?}");
        assert_eq!(result.decision, "deny", "{code}: {result:?}");
        assert_eq!(result.reason_code, "native_secret_exfiltration", "{code}");
    }

    for code in [
        "await sh('git status --short'); await tool.read({path:'tracked.txt', unknown:'x'})",
        "await tool.read({path:'tracked.txt', unknown:'x'}); await sh('git status --short')",
    ] {
        let result = eval(&session, code);
        assert_ne!(result.minimum_action, "allow", "{code}: {result:?}");
        assert_eq!(
            result.reason_code, "native_pre_tool_unknown_review",
            "{code}"
        );
    }
}

/// A command the direct call blocks stays blocked through `sh()`.
#[test]
fn a_command_the_direct_call_blocks_stays_blocked() {
    let session = with_env("omp-eval-sh-destructive");
    let command = "rm -rf ~";
    let standalone = direct(&session, command);
    assert_eq!(standalone.minimum_action, "block", "{standalone:?}");
    let result = eval(&session, &format!("await sh({command:?})"));
    assert_eq!(result.minimum_action, "block", "{result:?}");
    assert_eq!(result.reason_code, standalone.reason_code);
}

#[test]
fn a_literal_sh_read_is_allowed_like_the_direct_read() {
    let session = with_env("omp-eval-sh-status");
    let command = "git status --short";
    let standalone = direct(&session, command);
    assert_eq!(standalone.minimum_action, "allow", "{standalone:?}");
    for code in [
        "console.log(await sh('git status --short'))",
        "await sh`git status --short`",
        "const out = await sh('git status --short'); display(out);",
    ] {
        let result = eval(&session, code);
        assert_eq!(result.minimum_action, "allow", "{code}: {result:?}");
    }
}

#[test]
fn sh_calls_the_grammar_cannot_pin_down_stay_reviewed() {
    let session = with_env("omp-eval-sh-dynamic");
    for code in [
        // Options, computed commands, interpolation and escaped templates.
        "await sh('git status --short', { cwd: 'sub' })",
        "await sh('git status --short', { timeout: 5 })",
        "const c = 'git status'; await sh(c)",
        "await sh('git ' + 'status')",
        "await sh`git ${'status'}`",
        "await sh`git status\\n`",
        "await sh(`git ${'status'}`)",
        "await sh()",
        "await sh('')",
        // A local `sh` binding is not the prelude's helper.
        "const sh = 'x'; await sh('git status --short')",
        "await globalThis.sh('git status --short')",
    ] {
        let result = eval(&session, code);
        assert_ne!(result.minimum_action, "allow", "{code}: {result:?}");
        assert_eq!(
            result.reason_code, "native_pre_tool_unknown_review",
            "{code}: {result:?}"
        );
    }
}

/// The eval shell bridge raises no `bash` hook, so a command Guard would only
/// run contained gets no containment through `sh()`: the program stays
/// reviewed rather than allowed on the strength of a sandbox that never runs.
#[test]
fn sh_never_borrows_the_bash_tools_containment() {
    let session = with_env("omp-eval-sh-contained");
    // An inline interpreter that touches the OS: macOS runs it contained.
    let command = "python3 -I -c 'import os; print(os.getpid())'";
    let standalone = direct(&session, command);
    // Containment verdicts are only available on macOS. Assert that
    // platform's precondition rather than silently passing if it regresses.
    if !cfg!(target_os = "macos") {
        return;
    }
    assert_eq!(
        standalone.minimum_action, "sandbox-required",
        "{standalone:?}"
    );
    let code = format!("await sh({})", serde_json::to_string(command).unwrap());
    let result = eval(&session, &code);
    assert_ne!(result.minimum_action, "allow", "{result:?}");
    assert_ne!(result.minimum_action, "sandbox-required", "{result:?}");
    let bridged = format!(
        "await tool.bash({{command: {}}})",
        serde_json::to_string(command).unwrap()
    );
    assert_eq!(eval(&session, &bridged).minimum_action, "allow");
}
