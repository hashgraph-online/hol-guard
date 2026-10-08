use super::{CommandSegmentV1, CompatibilityObservations};

const RULES: &[(&str, &str)] = &[
    ("branch", "command.git.branch"),
    ("worktree", "command.git.worktree"),
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
                "-P" | "--no-pager"
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

fn bounded_inspection(arguments: &[String]) -> bool {
    if arguments == ["rev-parse", "--show-toplevel"] {
        return true;
    }
    let [command, mode, patch] = arguments else {
        return false;
    };
    // These fixed built-ins cannot be replaced by aliases. This admits their
    // capability attribution only; patch read and workspace proofs remain the
    // responsibility of the ordinary command decision, not this classifier.
    command == "apply"
        && mode == "--check"
        && !patch.is_empty()
        && patch.len() <= 4096
        && !patch.starts_with(['-', '/', '\\'])
        && patch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte))
        && patch
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

fn read_only_plumbing(arguments: &[String]) -> bool {
    let Some((command, rest)) = arguments.split_first() else {
        return false;
    };
    // Git ignores aliases that shadow built-ins, so these names always run the
    // read-only built-in. Forms that read arbitrary files, run configured
    // drivers, touch the network, or write are excluded.
    match command.as_str() {
        "rev-parse" | "merge-base" | "show-ref" | "ls-tree" | "for-each-ref" => true,
        "rev-list" => !rest.iter().any(|argument| {
            matches!(argument.as_str(), "--output" | "-o") || argument.starts_with("--output=")
        }),
        "symbolic-ref" => {
            let operands: Vec<&String> = rest
                .iter()
                .filter(|argument| !matches!(argument.as_str(), "-q" | "--quiet" | "--short"))
                .collect();
            operands.len() == 1 && !operands[0].starts_with('-')
        }
        "config" => {
            let mut reads = false;
            for argument in rest {
                let option = argument.split('=').next().unwrap_or(argument);
                match option {
                    "--get" | "--get-all" | "--get-regexp" | "--get-urlmatch" | "--list" | "-l" => {
                        reads = true;
                    }
                    "--local" | "--global" | "--system" | "--worktree" | "--show-origin"
                    | "--show-scope" | "--name-only" | "--null" | "-z" | "--type" | "--bool"
                    | "--int" | "--path" | "--default" | "--includes" | "--no-includes" => {}
                    _ if option.starts_with('-') => return false,
                    _ => {}
                }
            }
            reads
        }
        _ => false,
    }
}

pub(super) fn inspection_arguments<'a>(
    arguments: &'a [String],
    context: crate::pretool::PathContext<'_>,
) -> Option<&'a [String]> {
    let mut index = 0;
    let mut saw_change_directory = false;
    while let Some(argument) = arguments.get(index) {
        if matches!(
            argument.as_str(),
            "-P" | "--no-pager" | "--no-optional-locks"
        ) {
            index += 1;
            continue;
        }
        if argument == "-c" {
            let (key, value) = arguments.get(index + 1)?.split_once('=')?;
            let boolean = value.to_ascii_lowercase();
            let safe = match key.to_ascii_lowercase().as_str() {
                "core.fsmonitor" => matches!(boolean.as_str(), "false" | "0" | "no" | "off"),
                "core.quotepath" => matches!(
                    boolean.as_str(),
                    "true" | "false" | "1" | "0" | "yes" | "no" | "on" | "off"
                ),
                _ => false,
            };
            if !safe {
                return None;
            }
            index += 2;
            continue;
        }
        let target = if argument == "-C" {
            index += 1;
            arguments.get(index)?.as_str()
        } else {
            break;
        };
        if saw_change_directory && !std::path::Path::new(target).is_absolute() {
            return None;
        }
        if !crate::pretool::safe_directory_target(target)
            || !crate::pretool::git_route_within_workspace(target, context)
        {
            return None;
        }
        // Like `cd`, an absolute Windows target must be its exact canonical spelling.
        #[cfg(windows)]
        if std::path::Path::new(target).is_absolute()
            && !crate::pretool::directory_targets::exact_existing_drive_target(target)
        {
            return None;
        }
        saw_change_directory = true;
        index += 1;
    }
    let remaining = arguments.get(index..)?;
    matches!(
        remaining.first().map(String::as_str),
        Some("status" | "diff" | "log" | "show" | "rev-parse" | "ls-files" | "remote")
    )
    .then_some(remaining)
}

pub(super) fn observe_with_context(
    segment: &CommandSegmentV1,
    index: usize,
    result: &mut CompatibilityObservations,
    context: crate::pretool::PathContext<'_>,
) {
    let arguments = &segment.arguments;
    if arguments
        .first()
        .is_some_and(|argument| matches!(argument.as_str(), "--help" | "--version" | "-h"))
    {
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
    let inspection = inspection_arguments(arguments, context)
        .filter(|_| crate::pretool::directory_targets::drive_targets_quoted(segment));
    let plumbing = (command_index == 0 && read_only_plumbing(arguments))
        || inspection.is_some_and(read_only_plumbing);
    if plumbing {
        // The command stays read-only, but a disabled Git permission or
        // extension can still block it.
        result.permission("command.git.permission.ls-files", index, false);
    }
    if plumbing
        || (command_index == 0 && bounded_inspection(arguments))
        || inspection.is_some_and(bounded_inspection)
    {
        return;
    }
    if let Some((_, rule)) = RULES.iter().find(|(name, _)| *name == command) {
        // Attribution is deliberately stronger than legacy Python's inert
        // matcher=None porcelain entries: disabling a permission must work.
        result.rule(rule, index, command_index != 0 && inspection.is_none());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn observations(command: &str) -> CompatibilityObservations {
        let model = crate::parse_command(
            &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
        )
        .unwrap();
        let mut result = CompatibilityObservations::default();
        observe_with_context(
            &model.segments[0],
            0,
            &mut result,
            crate::pretool::PathContext::default(),
        );
        result
    }

    #[test]
    fn fixed_read_only_inspections_do_not_invent_unrelated_git_owners() {
        for command in [
            "git rev-parse --show-toplevel",
            "git rev-parse --git-dir",
            "git rev-parse --abbrev-ref HEAD",
            "git merge-base HEAD origin/main",
            "git show-ref --verify refs/heads/main",
            "git for-each-ref '--format=%(refname)' refs/heads",
            "git rev-list --count HEAD",
            "git ls-tree -r HEAD",
            "git symbolic-ref --short HEAD",
            "git config --get remote.origin.url",
            "git config --global --get user.email",
            "git config --list --show-origin",
            "git apply --check workspace/patches/change.patch",
        ] {
            assert!(observations(command).rule_matches.is_empty(), "{command}");
        }
    }

    #[test]
    fn inspection_exemption_does_not_cover_execution_routing_or_mutation() {
        for command in [
            "git -C workspace status",
            "git -c alias.apply=payload apply --check change.patch",
            "git -c core.pager=payload rev-parse HEAD",
            "git config user.name payload",
            "git config --unset user.name",
            "git config --file /home/user/.aws/credentials --list",
            "git config --get --file other.cfg key",
            "git symbolic-ref HEAD refs/heads/other",
            "git cat-file --textconv HEAD:file",
            "git apply change.patch",
            "git apply --check --unsafe-paths change.patch",
            "git apply --check ../change.patch",
            "git apply --check -",
        ] {
            let result = observations(command);
            assert!(!result.rule_matches.is_empty(), "{command}");
            assert!(
                result.rule_matches.iter().all(|item| item.uncertainty),
                "{command}"
            );
        }
    }
}
