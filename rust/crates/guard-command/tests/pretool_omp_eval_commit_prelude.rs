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
    "const d = await commit.draft(); return await d.show();",
    "const d = await commit.draft(); return await d.show('notes.md');",
    "const d = await commit.draft(); return await d.show('notes.md', {silent: true});",
    "const d = await commit.draft(); await d.take('**'); return await d.commit('Add temperature conversion CLI', {body:['Implement commands.','Document usage.']});",
    r#"const d = await commit.draft(); print(await d.commit("Fix punctuation in slugs", ["Normalize punctuation."]));"#,
    "const d=await commit.draft(); return await d.take(['index.html','style.css','game.js']);",
    "const d = await commit.draft(); await d.take('docs/environment.md'); await d.commit('Document local development environment', ['Add verified details.']);",
    "const d = await commit.draft(); await d.drop('notes.md'); print(await d.diff()); return await d.commit('Add report', {body: 'One line.', fixes: [12], noVerify: true});",
    r#"const d = await commit.draft(); return await d.commit({body:"Fix sum to include first value\n\nStart iteration at index 0."});"#,
    r#"const d = await commit.draft(); return await d.commit({subject: "docs: document the environment", body: ["- Add Node and npm details."]});"#,
    // After a failed commit, agents look at the draft to learn its API.
    "const d = await commit.draft(); return {type:typeof d, keys:Object.keys(d), commit:typeof d.commit};",
    "const d = await commit.draft(); return d.commit.toString();",
    "const d = await commit.draft(); return d.details;",
    r#"const d = await commit.draft(); await d.take("scripts/check.sh"); return await d.commit("Add release check script", "Mirror the release checklist steps.");"#,
    "const d = await commit.draft(); return { keys: Object.keys(d), proto: Object.getOwnPropertyNames(Object.getPrototypeOf(d)) };",
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
/// `amend`, a loop, an import, computed arguments, unknown options, draft
/// methods on anything but an awaited draft, and a draft method reached
/// through `call`, `bind` or the prototype.
#[test]
fn a_commit_program_outside_the_grammar_stays_reviewed() {
    let session = session("omp-eval-commit-refused");
    for code in [
        "const d = await commit.draft(); return await d.commit('x', {amend: true});",
        // `show(path)` prints that path's hunks, the read `git diff HEAD --
        // <path>` performs and Guard reviews when the path names a secret.
        "const d = await commit.draft(); return await d.show('.env');",
        "const d = await commit.draft(); return await d.show('config/.env.local');",
        "const d = await commit.draft(); return await d.show('deploy/id_rsa', {silent: true});",
        "const d = await commit.draft(); return await d.show(['notes.md', '.env']);",
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
        "const d = await commit.draft(); return await d.commit({subject: 'x', amend: true});",
        "const d = await commit.draft(); return await d.commit({subject: 1, body: 'y'});",
        "const d = await commit.draft(); return await d.commit({subject: 'x', hooks: false});",
        "const d = await commit.draft(); return await d.commit.call(d, 'x', {amend: true});",
        "const d = await commit.draft(); return d.commit.bind(d)('x');",
        "const d = await commit.draft(); return d.constructor;",
        "const d = await commit.draft(); return Object.assign(d, {});",
        "const d = await commit.draft(); return Object.keys(globalThis);",
        "const d = await commit.draft(); const p = Object.getPrototypeOf(d); return await p.commit.call(d, 'x');",
        "const d = await commit.draft(); return typeof d.commit('x', {amend: true});",
        "const d = await commit.draft(); return {then: d.commit};",
        "const d = await commit.draft(); return JSON.stringify({toJSON: d.drop});",
        "const d = await commit.draft(); return d.commit;",
        "const d = await commit.draft(); return typeof d.commit.call(d, 'x', {amend: true});",
        "const Object = 'x'; const d = await commit.draft(); return Object.keys(d);",
    ] {
        let result = eval(&session, code);
        assert_ne!(result.minimum_action, "allow", "{code}");
    }
}

/// Each eval cell is judged on its own, so a cell cannot prove a name bound
/// by an earlier cell still holds a draft. Those cells stay reviewed, and the
/// review tells the agent to make and use the draft in one cell, which is
/// allowed.
#[test]
fn a_draft_from_an_earlier_cell_stays_reviewed_with_one_cell_advice() {
    let session = session("omp-eval-commit-earlier-cell");
    std::fs::write(session.primary.join("notes.md"), "draft\n").unwrap();
    let first = eval(&session, "const d = await commit.draft(); print(d);");
    assert_eq!(first.minimum_action, "allow");
    for code in [
        "await d.show();",
        "await d.take('docs/branch-audit.md'); print(d);",
        "await d.commit('docs: record audit logs summary', ['- Summarize the audit.']);",
        "print(await d.diff()); return d.details;",
    ] {
        let result = eval(&session, code);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("review", "native_pre_tool_unknown_review"),
            "{code}"
        );
        assert!(
            result.reason.contains("in the same cell"),
            "{code}: {}",
            result.reason
        );
    }
    let one_cell = eval(
        &session,
        "const d = await commit.draft(); await d.take('notes.md'); await d.commit('docs: add notes', ['- Add notes.']);",
    );
    assert_eq!(one_cell.minimum_action, "allow");
    // A carried name used outside the draft grammar keeps the plain eval review.
    for code in [
        "await d.commit('x', {amend: true});",
        "const d = {show() {}}; await d.show();",
        "await d.push('x');",
        "globalThis.d = 1; await d.show();",
    ] {
        let result = eval(&session, code);
        assert_eq!(result.minimum_action, "review", "{code}");
        assert!(
            !result.reason.contains("in the same cell"),
            "{code}: {}",
            result.reason
        );
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

/// The git command extension judges a draft as the Git write it runs. When
/// the user allows the extension's `add` and `commit` permissions, a draft is
/// allowed as `git add -A && git commit` through `bash` is, even with a hook
/// Git would start. With the packaged defaults the hook keeps the extension's
/// own review, with its reason, rather than the review for an unknown program.
#[test]
fn a_commit_draft_follows_the_git_extension() {
    use crate::git_helper_fixture::{evaluate_with_node, local_admin_controls};
    let hooked = session("omp-eval-commit-extension");
    executable_hook(&hooked.primary.join(".git/hooks/pre-commit"));
    std::fs::write(hooked.primary.join("notes.md"), "draft\n").unwrap();
    let allowed = local_admin_controls(vec![
        json!({"target_kind": "extension", "target_id": "command.git", "state": "enabled"}),
        json!({"target_kind": "permission", "target_id": "command.git.permission.add", "state": "enabled"}),
        json!({"target_kind": "permission", "target_id": "command.git.permission.commit", "state": "enabled"}),
    ]);
    let bash = evaluate_with_node(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": "git add -A && git commit -m 'Add notes'"}}),
        Some(&allowed),
        &hooked.home,
        hooked.primary.to_str(),
    );
    assert_eq!(bash.minimum_action, "allow");
    for code in AGENT_PROGRAMS {
        let draft = evaluate_with_node(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "eval", "tool_input": {"language": "js", "code": code}}),
            Some(&allowed),
            &hooked.home,
            hooked.primary.to_str(),
        );
        assert_eq!(draft.minimum_action, "allow", "{code}");
        let reviewed = eval(&hooked, code);
        assert_eq!(
            (
                reviewed.minimum_action.as_str(),
                reviewed.reason_code.as_str()
            ),
            ("review", "native_command_review_required"),
            "{code}"
        );
        assert_eq!(
            reviewed.action.action_type,
            guard_contracts::PreToolActionTypeV1::Command
        );
    }
}
