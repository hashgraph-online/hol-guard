//! `find -exec PROG` names the program it runs, so it is bounded by that
//! program's owners instead of refused outright.

use crate::git_helper_fixture as fixture;

use fixture::{
    canonical_spelling, evaluate_pre_tool_envelope_with_context, git_github_controls,
    FixtureCleanup,
};
use guard_command::native_command_controls::CompiledNativeCommandControls;
use serde_json::json;

const EVALUATION_FAILED: &str = "native_command_extension_evaluation_failed";

fn workspace(name: &str) -> (std::path::PathBuf, FixtureCleanup) {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "guard-find-exec-{name}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("project/src")).unwrap();
    std::fs::write(root.join("project/src/cli.js"), "console.log(1)\n").unwrap();
    let cleanup = FixtureCleanup(root.clone());
    (canonical_spelling(&root), cleanup)
}

fn evaluate(
    root: &std::path::Path,
    controls: &CompiledNativeCommandControls,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
}

#[test]
fn an_exec_child_the_text_names_is_reviewed_rather_than_refused() {
    let (root, _cleanup) = workspace("named");
    let controls = git_github_controls("default", "default");
    for command in [
        "find src -type f -name '*.js' -exec basename {} \\;",
        "find src -type f -name '*.js' -exec dirname {} \\;",
        "find . -mindepth 1 -maxdepth 1 -type d -exec basename {} \\;",
        "find src -type f -exec file {} +",
        "find src -type d -execdir basename {} \\;",
        "find src -exec echo sh {} \\;",
        "find src -name '*.js' -exec grep -l 'foo\\.bar' {} +",
        "find src -exec printf '%s\\n' {} \\;",
        "find src -exec basename {} \\; ; \\ls",
        "find src -exec \\basename {} \\;",
        // A backslash inside an argument is part of the argument. Reading
        // every one of them as an interpreter took these back to the
        // evaluation failure.
        "find src -type f -name '*.js' -exec grep -l 'foo\\.bar' {} +",
        "find src -type f -exec \\ls {} +",
    ] {
        let result = evaluate(&root, &controls, command);
        // The owners of the program it names decide. Before this, no owner
        // set could be bounded at all and the command blocked outright, with
        // no approval left to give it.
        assert_ne!(result.reason_code, EVALUATION_FAILED, "{command}");
        assert_ne!(
            result.minimum_action, "block",
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn an_exec_child_that_is_not_named_keeps_its_evaluation_failure() {
    let (root, _cleanup) = workspace("unnamed");
    let controls = git_github_controls("default", "default");
    for command in [
        // An interpreter runs whatever it reads, so nothing bounds it.
        "find src -type f -exec sh -c 'cat \"$1\"' _ {} \\;",
        "find src -type f -exec bash -c 'cat {}' \\;",
        "find src -type f -exec xargs cat \\;",
        // A program built from an expansion or a glob names nothing.
        "find src -type f -exec $TOOL {} \\;",
        "find src -type f -exec ./bin/* {} \\;",
        // `-exec` with nothing after it names no program either.
        "find src -type f -exec",
    ] {
        let result = evaluate(&root, &controls, command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn an_exec_child_that_changes_files_is_still_stopped() {
    let (root, _cleanup) = workspace("changes");
    let controls = git_github_controls("default", "default");
    for command in [
        "find src -type f -name '*.js' -exec rm -f {} \\;",
        "find src -type f -name '*.js' -exec mv {} /tmp/out \\;",
        "find src -type f -exec chmod 777 {} +",
        "find src -type f -exec truncate -s 0 {} \\;",
    ] {
        let result = evaluate(&root, &controls, command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn a_shell_the_find_does_not_name_keeps_the_evaluation_failure() {
    let (root, _cleanup) = workspace("hidden-shell");
    let controls = git_github_controls("default", "default");
    for command in [
        // A second command runs its own shell: naming the find's child bounds
        // only the half of the text that was never the uncertainty.
        "find src -type f -exec basename {} \\; ; sh -c 'echo hi'",
        "find src -type f -exec basename {} \\; && bash -c 'echo hi'",
        // A wrapper in front of the child hides the shell it launches.
        "find src -type f -exec nohup sh -c 'echo hi' \\;",
        "find src -type f -exec /usr/bin/nohup sh -c 'echo hi' \\;",
        "find src -type f -exec command sh -c 'echo hi' \\;",
        "find src -type f -exec time python3 -c 'print(1)' \\;",
        // An escaped name the shell unescapes to `sh` must not read as `h`.
        "find src -type f -exec s\\h -c 'echo hi' \\;",
    ] {
        let result = evaluate(&root, &controls, command);
        assert_eq!(
            result.reason_code, EVALUATION_FAILED,
            "{command}: {}",
            result.reason
        );
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn a_batch_script_the_text_names_is_not_a_bounded_program() {
    let (root, _cleanup) = workspace("batch-child");
    let controls = git_github_controls("default", "default");
    for command in [
        "find src -type f -exec ./bin/report.cmd {} +",
        "find src -type f -exec report.cmd {} +",
    ] {
        let result = evaluate(&root, &controls, command);
        assert_eq!(
            result.reason_code, EVALUATION_FAILED,
            "{command}: {}",
            result.reason
        );
    }
}
