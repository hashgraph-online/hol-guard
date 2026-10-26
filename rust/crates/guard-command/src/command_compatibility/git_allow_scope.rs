//! What an explicit Git extension Allow may settle.
//!
//! The Allow is consent to the command Guard can read. Configuration that
//! makes Git run a program (a shell alias, a pager, a credential helper, an
//! included config file) carries text the shell interprets later, and
//! `--config-env` or `GIT_CONFIG_*` take the value from somewhere Guard never
//! sees, so those shapes keep the native decision instead.

use crate::CommandSegmentV1;

/// Sections in which no setting names a program, a config file, a filter or
/// a hook template for Git to run (`init.templateDir` copies hooks, so `init`
/// is not one).
const INERT_SECTIONS: &[&str] = &[
    "advice",
    "author",
    "blame",
    "branch",
    "checkout",
    "color",
    "column",
    "commit",
    "committer",
    "fetch",
    "gc",
    "grep",
    "http",
    "i18n",
    "log",
    "maintenance",
    "push",
    "rebase",
    "status",
    "tag",
    "user",
];

/// Inert settings in sections that also hold program-valued settings
/// (`core.pager`, `diff.external`, `merge.<driver>.driver`, ...).
const INERT_KEYS: &[&str] = &[
    "core.abbrev",
    "core.autocrlf",
    "core.commentchar",
    "core.eol",
    "core.filemode",
    "core.ignorecase",
    "core.longpaths",
    "core.precomposeunicode",
    "core.preloadindex",
    "core.quotepath",
    "core.safecrlf",
    "core.symlinks",
    "core.untrackedcache",
    "core.whitespace",
    "diff.algorithm",
    "diff.colormoved",
    "diff.context",
    "diff.indentheuristic",
    "diff.mnemonicprefix",
    "diff.noprefix",
    "diff.relative",
    "diff.renames",
    "init.defaultbranch",
    "merge.conflictstyle",
    "merge.ff",
    "merge.log",
    "protocol.version",
    "pull.ff",
    "pull.rebase",
];

/// Git built-ins whose program-running options the scan below holds, so an
/// explicit Git Allow may settle uncertainty about them. Anything else keeps
/// its review: `send-email`, `instaweb`, `daemon`, `credential*`, `help`,
/// bridges such as `p4`, `svn` and `cvs*`, `maintenance` (which installs
/// scheduler jobs), and `git <name>` resolving to a `git-<name>` on `PATH`.
const SETTLEABLE_SUBCOMMANDS: &[&str] = &[
    "add",
    "am",
    "apply",
    "archive",
    "bisect",
    "blame",
    "branch",
    "cat-file",
    "check-attr",
    "checkout",
    "cherry-pick",
    "clean",
    "clone",
    "commit",
    "config",
    "count-objects",
    "describe",
    "diff",
    "fetch",
    "for-each-ref",
    "format-patch",
    "gc",
    "grep",
    "init",
    "log",
    "ls-files",
    "ls-remote",
    "merge",
    "mv",
    "notes",
    "pull",
    "push",
    "range-diff",
    "rebase",
    "reflog",
    "remote",
    "reset",
    "restore",
    "rev-list",
    "rev-parse",
    "revert",
    "rm",
    "shortlog",
    "show",
    "show-ref",
    "sparse-checkout",
    "stash",
    "status",
    "submodule",
    "switch",
    "symbolic-ref",
    "tag",
    "worktree",
];

/// Merge strategies built into Git. Any other `-s <name>` runs a
/// `git-merge-<name>` program from the exec path or `PATH`.
const BUILTIN_STRATEGIES: &[&str] = &["ort", "recursive", "resolve", "octopus", "ours", "subtree"];

/// Whether a Git segment's subcommand is one an explicit Allow may settle
/// uncertainty about.
pub(crate) fn subcommand_settles_uncertainty(segment: &CommandSegmentV1) -> bool {
    super::command_index(&segment.arguments)
        .and_then(|index| segment.arguments.get(index))
        .is_some_and(|command| SETTLEABLE_SUBCOMMANDS.contains(&command.as_str()))
}

/// Whether a Git segment carries configuration or options that can make Git
/// run a program Guard cannot read: any alias, a program-valued or unknown
/// key from `-c`, any non-inert key from `--config-env`, `--exec-path`, a
/// `GIT_*` environment prefix other than the commit identity, or a
/// subcommand option naming a local program. Unknown keys and unparseable
/// global options fail closed.
pub(crate) fn runs_configured_program(segment: &CommandSegmentV1) -> bool {
    // The same normalised name the compatibility observer routes on, so
    // `/usr/bin/git`, `git.exe` and `GIT` are judged too.
    if crate::command_compatibility::basename(segment) != "git" {
        return false;
    }
    if segment
        .environment_names
        .iter()
        .any(|name| !crate::command_compatibility::inert_git_environment_name(name))
    {
        return true;
    }
    let arguments = &segment.arguments;
    let Some(command_index) = super::command_index(arguments) else {
        return true;
    };
    let mut index = 0;
    while index < command_index {
        let argument = arguments[index].as_str();
        let (setting, from_environment) = if argument == "-c" || argument == "--config-env" {
            index += 1;
            (arguments.get(index).map(String::as_str), argument != "-c")
        } else if let Some(setting) = argument.strip_prefix("--config-env=") {
            (Some(setting), true)
        } else if let Some(setting) = argument.strip_prefix("-c").filter(|rest| !rest.is_empty()) {
            (Some(setting), false)
        } else if argument.starts_with("--exec-path") {
            return true;
        } else {
            index += 1;
            continue;
        };
        index += 1;
        let Some(setting) = setting else {
            return true;
        };
        if config_setting_runs_program(setting, from_environment) {
            return true;
        }
    }
    subcommand_runs_program(&arguments[command_index..])
}

/// `-c <key>` sets the boolean true. `--config-env=<key>=<variable>` names a
/// variable, not the value.
fn config_setting_runs_program(setting: &str, from_environment: bool) -> bool {
    let (key, value) = setting.split_once('=').unwrap_or((setting, "true"));
    setting_runs_program(
        &key.to_ascii_lowercase(),
        (!from_environment).then_some(value),
    )
}

/// Subcommand options that make Git run a program locally: the pack programs
/// of a local transport, `--exec`, hook templates for a new repository,
/// settings `clone` writes into the repository it creates, and the shell text
/// that `rebase -x`, `difftool -x`, `filter-branch`, `submodule foreach` and
/// `bisect run` execute, the viewer `bisect visualize` opens, a pager `grep -O` opens, and merge strategies that
/// are not built in. Git accepts any unambiguous prefix of a long option,
/// so prefixes count too. A `--` can be the value of an option this scan does
/// not model, so words after it are scanned as well and a path that looks
/// like one of these options is held.
fn subcommand_runs_program(arguments: &[String]) -> bool {
    let Some((command, rest)) = arguments.split_first() else {
        return false;
    };
    let command = command.as_str();
    let operand = || {
        rest.iter()
            .map(String::as_str)
            .find(|a| !a.starts_with('-'))
    };
    match command {
        "filter-branch" => return true,
        "submodule" if operand() == Some("foreach") => return true,
        "bisect" if matches!(operand(), Some("run" | "visualize" | "view")) => return true,
        _ => {}
    }
    let mut index = 0;
    while let Some(argument) = rest.get(index) {
        index += 1;
        let argument = argument.as_str();
        if let Some(long) = argument.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let names = |option: &str| !name.is_empty() && option.starts_with(name);
            if names("upload-pack")
                || names("receive-pack")
                || names("exec")
                || (matches!(command, "clone" | "init") && names("template"))
                || (command == "grep" && names("open-files-in-pager"))
                || (matches!(command, "difftool" | "mergetool")
                    && (names("extcmd") || (name.starts_with("tool-") && names("tool-help"))))
            {
                return true;
            }
            if command == "clone" && names("config") {
                let setting = attached.or_else(|| rest.get(index).map(String::as_str));
                if attached.is_none() {
                    index += 1;
                }
                if setting.is_none_or(|setting| config_setting_runs_program(setting, false)) {
                    return true;
                }
            }
            if merges(command) && names("strategy") {
                let strategy = attached.or_else(|| rest.get(index).map(String::as_str));
                if attached.is_none() {
                    index += 1;
                }
                if strategy.is_none_or(|strategy| !BUILTIN_STRATEGIES.contains(&strategy)) {
                    return true;
                }
            }
            // Push and server options carry text for the remote, even `--`.
            if attached.is_none() && (names("push-option") || names("server-option")) {
                index += 1;
            }
            continue;
        }
        let Some(cluster) = argument.strip_prefix('-').filter(|rest| !rest.is_empty()) else {
            continue;
        };
        // Short flags that run a program, and those that take a value, which
        // ends the cluster. `-u <program>` is `--upload-pack` for clone and
        // ls-remote; for push, fetch and pull it sets the upstream or updates
        // HEAD. Rebase `-S` takes its key only when attached.
        let (holding, valued) = match command {
            "clone" => ("u", "cobj"),
            "ls-remote" => ("u", "o"),
            "push" | "fetch" => ("", "o"),
            "pull" => ("", "osXS"),
            "merge" => ("", "sXmFS"),
            "cherry-pick" | "revert" => ("", "XmS"),
            "rebase" => ("x", "sXCS"),
            "grep" => ("O", "efABCm"),
            "difftool" | "mergetool" => ("x", "t"),
            _ => continue,
        };
        for (offset, flag) in cluster.char_indices() {
            if holding.contains(flag) {
                return true;
            }
            if valued.contains(flag) {
                let attached = &cluster[offset + flag.len_utf8()..];
                let value = if attached.is_empty() && flag != 'S' {
                    index += 1;
                    rest.get(index - 1).map(String::as_str)
                } else {
                    Some(attached)
                };
                if command == "clone"
                    && flag == 'c'
                    && value.is_none_or(|setting| config_setting_runs_program(setting, false))
                {
                    return true;
                }
                if merges(command)
                    && flag == 's'
                    && value.is_none_or(|strategy| !BUILTIN_STRATEGIES.contains(&strategy))
                {
                    return true;
                }
                break;
            }
        }
    }
    false
}

fn merges(command: &str) -> bool {
    matches!(
        command,
        "merge" | "pull" | "rebase" | "cherry-pick" | "revert"
    )
}

fn setting_runs_program(key: &str, value: Option<&str>) -> bool {
    let section = key.split('.').next().unwrap_or(key);
    if INERT_SECTIONS.contains(&section) || INERT_KEYS.contains(&key) {
        return false;
    }
    // Every alias is held: a shell alias runs its body through `sh`, and any
    // other expands to a subcommand and options the parser never saw.
    let Some(value) = value.filter(|_| section != "alias") else {
        return true;
    };
    let disabled = |value: &str| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "false" | "0" | "no" | "off"
        )
    };
    // Settings that switch a program off rather than name one.
    let switched_off = match key {
        "core.fsmonitor" => disabled(value),
        "core.hookspath" => super::git_hooks_path::null_hooks_path(value),
        "core.pager" => matches!(value, "" | "cat"),
        "credential.helper" => value.is_empty(),
        _ if section == "pager" => disabled(value) || matches!(value, "" | "cat"),
        _ => false,
    };
    !switched_off
}

/// Whether a Git segment runs in a repository Guard has proven: no environment
/// overrides, and every global option before the subcommand is either
/// configuration (judged by [`runs_configured_program`]) or a `-C` or
/// `--git-dir` route that verifies. Any other option, such as `--work-tree`,
/// fails closed.
pub(crate) fn repository_routes_verified(
    segment: &CommandSegmentV1,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    let arguments = &segment.arguments;
    let Some(command_index) = super::command_index(arguments) else {
        return false;
    };
    let mut routes = Vec::with_capacity(arguments.len() + 1);
    let mut index = 0;
    while index < command_index {
        let argument = &arguments[index];
        if argument == "-c" || argument == "--config-env" {
            index += 2;
            continue;
        }
        if let Some(target) = argument.strip_prefix("-C").filter(|rest| !rest.is_empty()) {
            routes.push("-C".to_owned());
            routes.push(target.to_owned());
        } else if !(argument.starts_with("-c")
            || argument.starts_with("--config-env=")
            || argument.starts_with("--exec-path"))
        {
            routes.push(argument.clone());
        }
        index += 1;
    }
    let command_length = arguments.len() - command_index;
    routes.extend_from_slice(&arguments[command_index..]);
    segment.environment_names.is_empty()
        && crate::pretool::directory_targets::drive_targets_quoted(segment)
        && crate::pretool::directory_targets::home_targets_unquoted(segment)
        // `routed` stops at the first option it does not model; the routes
        // verify only when it stopped at the subcommand itself.
        && super::routed(&routes, context, true).is_some_and(|rest| rest.len() == command_length)
}
