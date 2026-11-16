#![cfg(unix)]

use crate::pretool_git_session_ops::session;

/// Sending a read's output to the null device discards it, so the command
/// beside the redirect keeps the read's own decision. The parser change this
/// locks is covered by `a_redirect_to_the_null_device_leaves_the_command_it`
/// `_follows` in `parser_tests.rs`, which fails without it; this test holds the
/// decision layer to the same answer for every spelling and both cwds.
#[test]
fn a_read_whose_output_goes_to_the_null_device_keeps_the_reads_decision() {
    let session = session("redirect-null-sink");
    for cwd in [&session.primary, &session.worktree] {
        for command in [
            "git status --short > /dev/null",
            "git status --short >/dev/null",
            "git status --short 1>/dev/null",
            "git status --short 1> /dev/null",
            "git status --short 2> /dev/null",
            "git status --short >> /dev/null",
            "git status --short 2>>/dev/null",
            "git status --short &>/dev/null",
            "git status --short >/dev/null 2>&1",
            "git log --oneline -5 >/dev/null",
            "ls -la 1>/dev/null",
            "git status --short > /dev/null && git log --oneline -5",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
    }
}

/// The discard is not a licence. A target that only reads like the null device
/// is an ordinary file, and the command the discard follows keeps whatever
/// decision it had on its own.
#[test]
fn a_target_that_is_not_the_null_device_still_answers_for_the_write() {
    let session = session("redirect-null-lookalike");
    let home_profile = session.home.join(".zshrc");
    let home_profile = home_profile.to_string_lossy().into_owned();
    for command in [
        "git status --short > /dev/nullx".to_string(),
        "git status --short > /dev/null/other".to_string(),
        "git status --short > .env".to_string(),
        format!("git status --short > {home_profile}"),
        "rm -rf / >/dev/null".to_string(),
        "cat ~/.aws/credentials > /dev/null".to_string(),
    ] {
        let result = session.evaluate_at(&command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
