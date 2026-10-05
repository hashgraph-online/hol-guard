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
    let inspection = inspection_arguments(arguments, context);
    if (command_index == 0 && bounded_inspection(arguments))
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
            "git rev-parse --git-dir",
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
