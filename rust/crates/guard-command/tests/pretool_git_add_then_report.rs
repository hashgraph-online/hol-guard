#![cfg(unix)]

//! `cd <checkout> && git add <files> && git status --short; echo "exit $?"`.
//!
//! The user's Git Allow settles the floor's order check for a staging step
//! before the reads, and a trailing report of how the run went joins no work
//! to the directory the command started in. Adding that report must not turn
//! the allowed chain back into a review.

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use crate::pretool_git_session_ops::{default_controls, session, Session};
use guard_command::native_command_controls::CompiledNativeCommandControls;
use serde_json::json;

const FILES: &str = "'app/(group)/items/view.tsx' 'app/(group)/items/__tests__/view.test.tsx'";

/// The packaged program with the Git permissions these chains use enabled,
/// as the Extensions page writes them.
fn git_allowed() -> CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls: Vec<_> = ["add", "status", "diff", "index-inspection", "log"]
        .iter()
        .map(|name| {
            json!({"target_kind":"permission",
                "target_id":format!("command.git.permission.{name}"), "state":"enabled"})
        })
        .collect();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema":"guard.native-command-control-binding.v1",
            "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
            "trust_digest":program.trust_digest, "health":"protected", "revision":1,
            "managed_revision":0, "effective_digest":"", "layers":[{
                "schema_version":"1.0.0", "kind":"local-admin",
                "catalog_digest":program.catalog_digest, "global_lockdown":false,
                "controls":controls
            }]
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

fn staged_session(label: &str) -> Session {
    let s = session(label);
    std::fs::create_dir_all(s.worktree.join("app/(group)/items/__tests__")).unwrap();
    for file in [
        "app/(group)/items/view.tsx",
        "app/(group)/items/__tests__/view.test.tsx",
    ] {
        std::fs::write(s.worktree.join(file), "export const value = 1;\n").unwrap();
    }
    s
}

fn evaluate(
    s: &Session,
    harness: &str,
    command: &str,
    controls: &CompiledNativeCommandControls,
) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        s.home.to_str(),
        s.primary.to_str(),
    )
}

#[test]
fn allowed_add_then_reads_keeps_its_allow_with_a_trailing_report() {
    let s = staged_session("add-report");
    let w = s.worktree.display().to_string();
    let controls = git_allowed();
    for command in [
        format!("cd {w} && git add -- {FILES} && git status --short; echo \"check exit: $?\""),
        format!("cd {w} && git add -- {FILES} && git diff --cached --check; echo done"),
        format!(
            "cd {w} && git add -- {FILES} && git status --short && echo '--- staged ---' \
             && git diff --cached --name-status && echo '--- check ---' \
             && git diff --cached --check; echo \"check exit: $?\""
        ),
    ] {
        for harness in ["codex", "claude-code"] {
            let result = evaluate(&s, harness, &command, &controls);
            assert_eq!(
                result.minimum_action, "allow",
                "{harness} {command}: {} {}",
                result.reason_code, result.reason
            );
        }
        // The same chain without the report was already allowed; both
        // spellings keep one answer.
        let bare = command.rsplit_once(';').unwrap().0.to_owned();
        assert_eq!(
            evaluate(&s, "codex", &bare, &controls).minimum_action,
            "allow"
        );
    }
}

#[test]
fn the_allow_covers_each_part_after_the_fork_and_nothing_without_it() {
    let s = staged_session("add-report-floor");
    let w = s.worktree.display().to_string();
    let reported =
        format!("cd {w} && git add -- {FILES} && git status --short; echo \"check exit: $?\"");
    // Without the user's Git Allow the staging step still waits.
    let result = evaluate(&s, "codex", &reported, &default_controls());
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
    // After the fork every part is answered where it runs: the head in the
    // worktree, and the tail there after the head or alone in the starting
    // directory. Each Git read is probed in its own directory, so the Allow
    // covers a Git tail and any Git-free tail alike.
    for tail in ["git log -1", "true", "echo done; true"] {
        let other = format!("cd {w} && git add -- {FILES} && git status --short; {tail}");
        let result = evaluate(&s, "codex", &other, &git_allowed());
        assert_eq!(
            result.minimum_action, "allow",
            "{other}: {} {}",
            result.reason_code, result.reason
        );
    }
    // A listing reads whichever directory the fork left it in, which no
    // Git permission covers.
    let listing = format!("cd {w} && git add -- {FILES} && git status --short; ls");
    let result = evaluate(&s, "codex", &listing, &git_allowed());
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}
