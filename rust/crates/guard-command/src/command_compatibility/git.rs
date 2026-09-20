use super::{CommandSegmentV1, CompatibilityObservations};

const RULES: &[(&str, &str)] = &[
    ("branch", "command.git.branch"),
    ("pull", "command.git.pull"),
    ("push", "command.git.push"),
    ("clone", "command.git.clone"),
    ("fetch", "command.git.fetch"),
    ("remote", "command.git.remote"),
    ("status", "command.git.status"),
    ("log", "command.git.log"),
    ("diff", "command.git.diff"),
    ("show", "command.git.show"),
    ("blame", "command.git.blame"),
    ("grep", "command.git.grep"),
    ("describe", "command.git.describe"),
    ("ls-files", "command.git.ls-files"),
    ("reflog", "command.git.reflog"),
];

fn command_index(arguments: &[String]) -> Option<usize> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let option = argument.split('=').next().unwrap_or(argument);
        if matches!(
            option,
            "-c" | "-C"
                | "--config-env"
                | "--exec-path"
                | "--git-dir"
                | "--namespace"
                | "--super-prefix"
                | "--work-tree"
        ) {
            index += if argument.contains('=') { 1 } else { 2 };
        } else if ((argument.starts_with("-c") || argument.starts_with("-C")) && argument.len() > 2)
            || matches!(
                argument.as_str(),
                "--no-pager"
                    | "--paginate"
                    | "--bare"
                    | "--no-replace-objects"
                    | "--literal-pathspecs"
                    | "--glob-pathspecs"
                    | "--noglob-pathspecs"
                    | "--icase-pathspecs"
                    | "--no-optional-locks"
            )
        {
            index += 1;
        } else if argument.starts_with('-') {
            return None;
        } else {
            return Some(index);
        }
    }
    None
}

pub(super) fn observe(
    segment: &CommandSegmentV1,
    index: usize,
    result: &mut CompatibilityObservations,
) {
    let arguments = &segment.arguments;
    if arguments.len() == 1 && matches!(arguments[0].as_str(), "--help" | "--version" | "-h") {
        return;
    }
    let Some(command_index) = command_index(arguments) else {
        // An unknown global option may consume a token that looks like a
        // subcommand. Admit no native no-match for any of the affected owners.
        for (_, rule) in RULES {
            result.rule(rule, index, true);
        }
        return;
    };
    let command = arguments[command_index].as_str();
    if let Some((_, rule)) = RULES.iter().find(|(name, _)| *name == command) {
        // Attribution is deliberately stronger than legacy Python's inert
        // matcher=None porcelain entries: disabling a permission must work.
        result.rule(rule, index, command_index != 0);
    } else if !matches!(
        command,
        "switch"
            | "checkout"
            | "restore"
            | "stash"
            | "add"
            | "commit"
            | "mv"
            | "rm"
            | "worktree"
            | "tag"
            | "clean"
            | "rebase"
            | "merge"
            | "cherry-pick"
            | "revert"
            | "reset"
    ) {
        // Those fixed built-ins already have declarative owners. Aliases and
        // helper/plumbing commands have no proved compatibility/control owner
        // in this tranche, even when another native classifier calls them safe.
        for (_, rule) in RULES {
            result.rule(rule, index, true);
        }
    }
    if command == "fetch" {
        // Proving a named origin requires repository/configuration bindings
        // unavailable in CanonicalCommandV1. Never claim the Python exemption.
        result.rule("command.git.unverified-fetch", index, true);
    }
    if command == "diff"
        && arguments[command_index + 1..]
            .iter()
            .take_while(|argument| argument.as_str() != "--")
            .any(|argument| matches!(argument.as_str(), "--cached" | "--staged"))
    {
        result.rule("command.git.index-inspection", index, true);
    }
}
