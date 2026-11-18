#![cfg(unix)]

//! Oh My Pi's `commit` eval prelude, which commits from the host process.

use crate::pretool_git_session_ops::{default_controls, executable_hook, session, Session};
use serde_json::json;

fn eval(session: &Session, code: &str) -> guard_contracts::PreToolResultV1 {
    crate::git_helper_fixture::evaluate_with_node(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "eval", "tool_input": {"language": "js", "code": code}}),
        Some(&default_controls()),
        &session.home,
        session.primary.to_str(),
    )
}

/// Programs agents wrote in the release gate's full-task lane. Each drafts a
/// commit in the session's repository, picks files and commits them with a
/// literal message.
const AGENT_PROGRAMS: &[&str] = &[
    r#"const d = await commit.draft(); return await d.commit("Add zod user validation", ["Add zod as a runtime dependency.", "Cover valid and invalid inputs."]);"#,
    r#"const d = await commit.draft({ agents: "self" }); await d.take("package.json"); await d.take("src/user.js"); return await d.commit("Add zod user validation", ["Add zod as a runtime dependency."]);"#,
    r#"const d = await commit.draft(); print(await d.take(["src/config.js", "docs/config-changes.md"])); return await d.commit("Raise widgets request timeout", ["Document requestTimeoutMs."]);"#,
    r#"const d = await commit.draft(); print(d); await d.take("src/config.js"); return await d.commit("Raise widgets request timeout", ["- Documented requestTimeoutMs."]);"#,
    "const d = await commit.draft(); return await d.take('src/sum.js');",
    "const d = await commit.draft(); return await d;",
    "const d = await commit.draft(); await d.take('**'); return await d.commit('Add temperature conversion CLI', {body:['Implement commands.','Document usage.']});",
    r#"const d = await commit.draft(); print(await d.commit("Fix punctuation in slugs", ["Normalize punctuation."]));"#,
    "const d=await commit.draft(); return await d.take(['index.html','style.css','game.js']);",
    "const d = await commit.draft(); await d.take('docs/environment.md'); await d.commit('Document local development environment', ['Add verified details.']);",
    "const d = await commit.draft(); await d.drop('notes.md'); print(await d.diff()); return await d.commit('Add report', {body: 'One line.', fixes: [12], noVerify: true});",
];

/// With no hook, filter, fsmonitor or signing program configured, the draft
/// runs nothing but Git, so the program is allowed like the same commit
/// through `bash` with no sandbox to fall back on.
#[test]
fn a_commit_draft_in_a_plain_repository_is_allowed() {
    let session = session("omp-eval-commit");
    std::fs::write(session.primary.join("notes.md"), "draft\n").unwrap();
    for code in AGENT_PROGRAMS {
        let result = eval(&session, code);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("allow", "native_omp_eval_bounded_tools"),
            "{code}"
        );
    }
    // A draft in another checkout is judged in that checkout.
    let worktree = session.worktree.to_str().unwrap();
    let code = format!(
        "const d = await commit.draft({{ repo: '{worktree}' }}); await d.take('reports/**'); await d.commit('Add weekly report');"
    );
    let result = eval(&session, &code);
    assert_eq!(result.minimum_action, "allow", "{code}");
}

/// The prelude runs in the harness process, so no workspace sandbox can hold
/// what Git starts. A hook, a moved hooks directory or a chosen signing
/// program keeps the review, even though
/// the same commit through `bash` could run contained.
#[test]
fn a_commit_draft_that_would_start_a_configured_program_stays_reviewed() {
    let hooked = session("omp-eval-commit-hook");
    executable_hook(&hooked.primary.join(".git/hooks/pre-commit"));
    let signed = session("omp-eval-commit-signed");
    signed.config(&["commit.gpgsign", "true"]);
    signed.config(&["gpg.program", "/tmp/guard-fixture-sign"]);
    let moved = session("omp-eval-commit-hooks-path");
    let hooks = moved.home.join("shared-hooks");
    executable_hook(&hooks.join("pre-commit"));
    moved.config(&["core.hooksPath", hooks.to_str().unwrap()]);
    for session in [&hooked, &signed, &moved] {
        for code in AGENT_PROGRAMS {
            let result = eval(session, code);
            assert_eq!(result.minimum_action, "review", "{code}");
        }
    }
}

/// A program the grammar does not model keeps the unknown-program review:
/// `amend`, a loop, an import, computed arguments, unknown options, and draft
/// methods on anything but an awaited draft.
#[test]
fn a_commit_program_outside_the_grammar_stays_reviewed() {
    let session = session("omp-eval-commit-refused");
    for code in [
        "const d = await commit.draft(); return await d.commit('x', {amend: true});",
        "const d = await commit.draft(); for (const p of ['a']) await d.take(p); return await d.commit('x');",
        "const d = await import('xd://eval/commit'); print(d)",
        "const m = 'x'; const d = await commit.draft(); return await d.commit(m);",
        "const d = await commit.draft({ cwd: '/' }); return await d.commit('x');",
        "const d = await commit.draft(); return await d.commit('');",
        "const d = await commit.draft(); return await d.push('x');",
        "const d = commit.draft(); return await d.commit('x');",
        "const d = await commit.draft(); const e = d; return await e.commit('x');",
        "return await commit.run('x');",
        "const d = await commit.draft(); return await d.commit('x', {body: 'y', hooks: false});",
    ] {
        let result = eval(&session, code);
        assert_ne!(result.minimum_action, "allow", "{code}");
    }
}

/// Reading the prelude's own documentation is a device-docs read.
#[test]
fn reading_the_commit_prelude_docs_is_allowed() {
    let session = session("omp-eval-commit-docs");
    for code in [
        "return await read('xd://eval/commit');",
        "await read('xd://eval/commit');",
    ] {
        let result = eval(&session, code);
        assert_eq!(result.minimum_action, "allow", "{code}");
    }
}
