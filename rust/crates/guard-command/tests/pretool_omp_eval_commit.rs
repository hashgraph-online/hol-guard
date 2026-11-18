#![cfg(unix)]

//! Oh My Pi 18.22 commits through the `commit` eval prelude. The prelude
//! runs git itself and raises no tool hook, so the eval carries the verdict
//! of the git commands the draft performs, judged as direct `bash` calls.

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

fn eval(session: &Session, code: &str) -> PreToolResultV1 {
    evaluate(
        session,
        "eval",
        json!({"language": "js", "code": code, "title": "Commit work", "timeout": 300}),
    )
}

#[test]
fn a_commit_draft_is_allowed_when_its_git_commit_is() {
    let session = session("omp-eval-commit-allow");
    let direct = evaluate(
        &session,
        "bash",
        json!({"command": "git add -A && git commit -q -m commit"}),
    );
    // A direct call may be contained instead; the prelude raises no hook a
    // sandbox could take, so the eval needs the proof that settles it bare.
    assert!(
        matches!(direct.minimum_action.as_str(), "allow" | "sandbox-required"),
        "{direct:?}"
    );
    for code in [
        "const d = await commit.draft(); return await d.commit('Fix sum', ['Start at index 0.']);",
        "const d = await commit.draft({ agents: 'self' }); await d.take('tracked.txt'); return await d.commit('Fix sum', {body: ['- Start at index 0.']});",
        "const d=await commit.draft(); for (const p of ['tracked.txt']) await d.take(p); return await d.commit('Update',['Body.']);",
        "const d = await commit.draft(); print(d); print(await d.take(['tracked.txt'])); return await d.diff();",
        "return await read('xd://eval/commit');",
    ] {
        let result = eval(&session, code);
        assert_eq!(result.minimum_action, "allow", "{code}: {result:?}");
        assert_eq!(result.reason_code, "native_omp_eval_bounded_tools", "{code}");
    }
}

#[test]
fn a_commit_draft_outside_the_grammar_keeps_the_unknown_program_review() {
    let session = session("omp-eval-commit-review");
    for code in [
        "return await d.take();",
        "const d = await commit.draft(); const s = 'x'; return await d.commit(s);",
        "const d = await commit.draft(); await d.push();",
        "const mod = await import('xd://eval/commit'); print(Object.keys(mod));",
    ] {
        let result = eval(&session, code);
        assert_ne!(result.minimum_action, "allow", "{code}: {result:?}");
    }
}

#[test]
fn a_commit_beside_a_destructive_shell_call_is_not_allowed() {
    let session = session("omp-eval-commit-shell");
    let result = eval(
        &session,
        "const d = await commit.draft(); await sh('rm -rf ~/.ssh'); return await d.commit('x');",
    );
    assert_ne!(result.minimum_action, "allow", "{result:?}");
}
