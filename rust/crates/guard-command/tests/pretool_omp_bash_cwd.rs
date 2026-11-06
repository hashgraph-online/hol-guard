#![cfg(unix)]

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use crate::pretool_git_session_ops::{default_controls, session, Session};
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};

const REVIEW: &str = "native_omp_bash_cwd_review";

fn omp(session: &Session, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": input}),
        Some(&default_controls()),
        None,
        session.home.to_str(),
        session.org.to_str(),
    )
}

fn outcome(result: &PreToolResultV1) -> (String, String) {
    (result.minimum_action.clone(), result.reason_code.clone())
}

#[test]
fn bash_cwd_below_the_session_directory_is_the_command_directory() {
    let session = session("omp-cwd-within");
    let primary = session.primary.to_str().unwrap();
    let chain = "git fetch origin main && git log -6 --oneline --decorate origin/main \
        && git merge-base --is-ancestor HEAD origin/main; printf 'exit=%s\\n' \"$?\"";
    for cwd in [primary, "app-portal", "./app-portal/", "~/org/app-portal"] {
        for command in ["git fetch origin main", chain] {
            let result = omp(&session, json!({"command": command, "cwd": cwd}));
            assert_eq!(
                result.minimum_action, "allow",
                "{cwd}: {command}: {}",
                result.reason_code
            );
        }
    }
    // The command stays judged in that directory, not the session one.
    std::fs::write(session.primary.join(".env"), "TOKEN=fixture\n").unwrap();
    let result = omp(
        &session,
        json!({"command": "cat .env", "cwd": "app-portal"}),
    );
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}

#[test]
fn bash_cwd_naming_the_session_directory_changes_nothing() {
    let session = session("omp-cwd-session");
    for command in ["git status --short", "git fetch origin main", "rm -rf ~/x"] {
        let bare = outcome(&omp(&session, json!({"command": command})));
        for cwd in ["", ".", "/", "//", session.org.to_str().unwrap()] {
            let result = omp(&session, json!({"command": command, "cwd": cwd}));
            assert_eq!(outcome(&result), bare, "{cwd:?}: {command}");
        }
    }
}

#[test]
fn bash_cwd_outside_the_session_directory_is_judged_as_a_leading_cd() {
    let session = session("omp-cwd-outside");
    let ssh = session.home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("config"), "Host fixture\n").unwrap();
    // A link inside the session directory still runs in its target.
    std::os::unix::fs::symlink(&ssh, session.org.join("keys")).unwrap();
    for cwd in ["~/.ssh", ssh.to_str().unwrap(), "../.ssh", "keys"] {
        let result = omp(&session, json!({"command": "cat config", "cwd": cwd}));
        assert_ne!(
            result.minimum_action, "allow",
            "{cwd}: {}",
            result.reason_code
        );
        let result = omp(&session, json!({"command": "rm -rf build", "cwd": cwd}));
        assert_ne!(
            result.minimum_action, "allow",
            "{cwd}: {}",
            result.reason_code
        );
    }
    let notes = session.home.join("notes");
    std::fs::create_dir_all(&notes).unwrap();
    let directory = notes.to_str().unwrap();
    let projected = omp(
        &session,
        json!({"command": format!("cd '{directory}' && ls")}),
    );
    let result = omp(&session, json!({"command": "ls", "cwd": directory}));
    assert_eq!(outcome(&result), outcome(&projected));
}

#[test]
fn bash_cwd_in_a_linked_worktree_of_a_session_repository_is_the_command_directory() {
    let session = session("omp-cwd-worktree");
    let worktree = session.worktree.to_str().unwrap();
    // The host runs the whole list in the worktree, so the `;` tail is judged
    // there rather than also from the session directory.
    let probe = "test -d node_modules && printf 'present\\n' || printf 'absent'; \
        git status --short --branch";
    for command in [probe, "git status --short --branch", "git log --oneline -3"] {
        let result = omp(&session, json!({"command": command, "cwd": worktree}));
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    std::fs::write(session.worktree.join(".env"), "TOKEN=fixture\n").unwrap();
    for command in ["cat .env", "rm -rf ~/notes"] {
        let result = omp(&session, json!({"command": command, "cwd": worktree}));
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    // A copied `.git` file names the worktree's registry entry, but the
    // registry's backlink still names the real checkout, so the copy is
    // judged as a leading `cd` into it.
    let forged = session.home.join("forged");
    std::fs::create_dir_all(&forged).unwrap();
    std::fs::copy(session.worktree.join(".git"), forged.join(".git")).unwrap();
    let directory = forged.canonicalize().unwrap();
    let directory = directory.to_str().unwrap();
    for command in [probe, "cat .env", "rm -rf ~/notes"] {
        let projected = omp(
            &session,
            json!({"command": format!("cd '{directory}' && {command}")}),
        );
        let result = omp(&session, json!({"command": command, "cwd": directory}));
        assert_eq!(outcome(&result), outcome(&projected), "{command}");
    }
}

#[test]
fn unmodeled_bash_cwd_forms_require_review() {
    let session = session("omp-cwd-unresolved");
    let primary = session.primary.to_str().unwrap();
    std::fs::write(session.org.join("notes.txt"), "notes\n").unwrap();
    for cwd in [
        json!("@app-portal"),
        json!(format!(":{primary}")),
        json!(format!("file://{primary}")),
        json!("skill://example"),
        json!("notes.txt"),
        json!("~other"),
        json!("app\\portal"),
        json!("app\u{00a0}portal"),
        json!(5),
        json!(null),
    ] {
        let result = omp(
            &session,
            json!({"command": "git status --short", "cwd": cwd}),
        );
        assert_eq!(outcome(&result), ("review".into(), REVIEW.into()), "{cwd}");
    }
    let conflicting = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({
            "tool_name": "bash",
            "tool_input": {"command": "git status --short", "cwd": "app-portal"},
            "toolInput": {"command": "git status --short", "cwd": "."},
        }),
        Some(&default_controls()),
        None,
        session.home.to_str(),
        session.org.to_str(),
    );
    assert_eq!(outcome(&conflicting), ("review".into(), REVIEW.into()));
}

#[test]
fn a_missing_bash_cwd_is_stopped_with_a_correctable_reason() {
    let session = session("omp-cwd-missing");
    for cwd in ["missing", "~/missing", "../app-portal-gone"] {
        let result = omp(
            &session,
            json!({"command": "git status --short", "cwd": cwd}),
        );
        assert_eq!(
            outcome(&result),
            ("block".into(), "native_missing_path".into()),
            "{cwd}"
        );
    }
}

fn read(session: &Session, harness: &str, tool: &str, path: &str) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": {"path": path, "file_path": path}}),
        Some(&default_controls()),
        None,
        session.home.to_str(),
        session.org.to_str(),
    )
}

#[test]
fn a_read_of_a_missing_path_is_stopped_with_a_correctable_reason() {
    let session = session("omp-read-missing");
    let notes = session.home.join("notes");
    std::fs::create_dir_all(&notes).unwrap();
    std::fs::write(notes.join("plan.md"), "plan\n").unwrap();
    let missing = session.home.join("app-portal-fix-gone/src/report.ts");
    let missing = missing.to_str().unwrap();
    for (harness, tool, path) in [
        ("omp", "read", missing.to_owned()),
        ("omp", "read", format!("{missing}:74-145")),
        (
            "omp",
            "read",
            "~/app-portal-fix-gone/src/report.ts".to_owned(),
        ),
        ("claude-code", "Read", missing.to_owned()),
    ] {
        let result = read(&session, harness, tool, &path);
        assert_eq!(
            outcome(&result),
            ("block".into(), "native_missing_path".into()),
            "{harness} {path}"
        );
        // Nothing waits for approval, so the agent must be told to fix the path.
        assert!(result.reason.contains("try again with the correct one"));
    }
    // A missing file inside the workspace is already allowed; the host reports
    // the error itself.
    let result = read(&session, "omp", "read", "app-portal/missing.ts");
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
    // Existing files keep their own decision, and a missing secret keeps the
    // sensitive-path handling rather than this explanation.
    let plan = notes.join("plan.md");
    let result = read(&session, "omp", "read", &format!("{}:1-5", plan.display()));
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
    let result = read(&session, "omp", "read", "~/.ssh/id_gone");
    assert_ne!(result.reason_code, "native_missing_path");
}
