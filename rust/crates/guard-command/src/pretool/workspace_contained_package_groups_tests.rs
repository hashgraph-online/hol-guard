use super::reads;

/// A group word followed by a subcommand that only reports what is on disk
/// is read here, so the registry scan no longer refuses the group word.
#[test]
fn a_reporting_subcommand_is_read() {
    for arguments in [
        vec!["pm", "ls"],
        vec!["pm", "ls", "--all"],
        vec!["pm", "bin"],
        vec!["pm", "bin", "-g"],
        vec!["pm", "cache"],
        vec!["pm", "hash"],
        vec!["pm", "hash-string"],
        vec!["pm", "hash-print"],
        vec!["pm", "trusted"],
        vec!["pm", "untrusted"],
        vec!["pm", "default-trusted"],
        vec!["store", "path"],
        vec!["store", "status"],
        vec!["cache", "ls"],
        vec!["cache", "list"],
        vec!["cache", "dir"],
    ] {
        assert!(reads(&arguments), "{arguments:?}");
    }
}

/// Everything the families also carry keeps the review it has today: the
/// verbs that write or fetch, the group word with no subcommand at all, a
/// subcommand belonging to another group, and the one verb that sends the
/// stored registry credential.
#[test]
fn a_writing_or_fetching_subcommand_is_not_read() {
    for arguments in [
        vec!["pm"],
        vec!["store"],
        vec!["cache"],
        vec!["pm", "cache", "rm"],
        vec!["pm", "trust"],
        vec!["pm", "trust", "esbuild"],
        vec!["pm", "pack"],
        vec!["pm", "version"],
        vec!["pm", "migrate"],
        vec!["pm", "whoami"],
        vec!["store", "add", "lodash"],
        vec!["store", "prune"],
        vec!["cache", "clean"],
        vec!["cache", "add", "lodash"],
        vec!["cache", "verify"],
        // Each group reads its own subcommands and no other group's.
        vec!["store", "ls"],
        vec!["cache", "path"],
        vec!["pm", "dir"],
        // The word in front has to be a group word.
        vec!["install", "ls"],
        vec!["ls"],
    ] {
        assert!(!reads(&arguments), "{arguments:?}");
    }
}

/// An operand behind a reporting subcommand carries no dash, so it is
/// refused as the package or path it names, and an inline value naming a
/// place on disk is refused with the options a verb reads in front.
#[test]
fn an_operand_or_a_directory_value_is_not_read() {
    for arguments in [
        vec!["pm", "ls", "lodash"],
        vec!["pm", "bin", "esbuild"],
        vec!["cache", "ls", "lodash"],
        vec!["store", "status", "--dir=../other"],
        vec!["store", "status", "--dir=/opt/other"],
        vec!["store", "status", "--dir=~/other"],
        vec!["pm", "ls", "--cwd=C:/other"],
        vec!["pm", "ls", "--filter={/opt/other}"],
        vec!["pm", "ls", "--reporter=$(id)"],
        // A value given as the next word is refused as a positional.
        vec!["store", "status", "--dir", "/opt/other"],
    ] {
        assert!(!reads(&arguments), "{arguments:?}");
    }
}
