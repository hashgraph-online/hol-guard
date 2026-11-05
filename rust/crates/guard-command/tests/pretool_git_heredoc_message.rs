#![cfg(unix)]

use crate::pretool_git_session_ops::session;

const WRITE: &str = "native_exact_safe_git_local_write";

/// A commit message carried on standard input is the message, nothing else.
///
/// Writing a multi-line message is how an agent commits: the shell holds the
/// subject and body in a quoted heredoc and `git commit` records them. The
/// bytes run nothing, so the commit answers for itself the way every other
/// spelling of it does.
///
/// A file redirect in the same chain is out of scope here: the chain's own
/// write still has to be settled by the local Git write proof, which this
/// fixture does not reach, and the heredoc leaves no workspace sandbox route
/// to fall back on, so that shape keeps its review.
#[test]
fn a_quoted_heredoc_that_carries_a_commit_message_is_quiet() {
    let session = session("heredoc-message");
    // The workspace sandbox may run the chain in the worktree instead of
    // Git's write proof allowing it; either way it raises no review.
    let quiet = |command: &str| session.quiet_at(command, &session.worktree, WRITE);
    for command in [
        "git commit -q -F - <<'MSG'\nfeat(report): add the lane\n\nSecond paragraph.\nMSG",
        "git commit --file - <<'MSG'\nfeat(report): add the lane\nMSG",
        "git commit --file=- <<'MSG'\nfeat(report): add the lane\nMSG",
        "git commit -F- <<'MSG'\nfeat(report): add the lane\nMSG",
        "git add -A && git commit -q -F - <<'MSG'\nfeat(report): add the lane\nMSG",
        // The message is already on the command line; standard input is spare.
        "git commit -m 'feat(report): add the lane' <<'MSG'\nunused\nMSG",
    ] {
        quiet(command).unwrap();
    }
}

/// Only the command that reads the bytes may receive them.
#[test]
fn literal_standard_input_fed_to_anything_else_stays_reviewed() {
    let session = session("heredoc-message-refused");
    for command in [
        // A path is a file read, which this proof does not cover.
        "git commit -F notes.txt <<'MSG'\nfeat(report): add the lane\nMSG",
        // These git subcommands apply, store or replay what they read.
        "git apply <<'MSG'\ndiff --git a/x b/x\nMSG",
        "git am <<'MSG'\nFrom: someone\nMSG",
        "git hash-object -w --stdin <<'MSG'\npayload\nMSG",
        // A global option chooses the repository the commit runs in, so the
        // subcommand is no longer the first word and the proof closes.
        "git -C ../org/app-portal commit -F - <<'MSG'\nfeat(report): add the lane\nMSG",
        // A shell runs the body as a script.
        "sh <<'MSG'\nrm -rf build\nMSG",
        "cat <<'MSG' | sh\nrm -rf build\nMSG",
        // Something follows the body, so which command the shell hands the
        // bytes to is no longer in the text and every command answers.
        "git commit -F - <<'MSG'\nfeat(report): add the lane\nMSG\nrm -rf build",
        // The command that reads the patch comes first and a filter follows
        // it. Reading only the last command would miss the one the shell
        // actually feeds, so every command still has to answer.
        "git apply <<'MSG'\ndiff --git a/x b/x\nMSG\ncat",
        "git hash-object -w --stdin <<'MSG'\npayload\nMSG\nwc -c",
        // An unquoted delimiter expands the body before git ever sees it.
        "git commit -F - <<MSG\n$(cat ~/.ssh/id_rsa)\nMSG",
    ] {
        session.assert_not_allow(command);
    }
}
