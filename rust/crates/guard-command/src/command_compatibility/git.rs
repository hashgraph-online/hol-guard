use super::{CommandSegmentV1, CompatibilityObservations};

#[path = "git_allow_scope.rs"]
mod git_allow_scope;
#[path = "git_fetch.rs"]
mod git_fetch;
#[path = "git_hooks_path.rs"]
mod git_hooks_path;
pub(crate) use git_allow_scope::{
    repository_routes_verified, runs_configured_program, subcommand_settles_uncertainty,
};
use git_hooks_path::hooks_path_names_no_hooks;

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

/// A staged-index diff that prints to stdout like `git diff HEAD`, which the
/// ordinary diff proof already admits. The staged content is no more private
/// than the working tree beside it, so the shared read proof (configuration
/// probe, textconv and sensitive-pathspec screens) decides it. Forms that
/// write a file or compare against another revision keep the index owner.
fn bounded_cached_diff(arguments: &[String]) -> bool {
    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .all(|argument| {
            let option = argument.as_str();
            matches!(
                option,
                "--cached"
                    | "--staged"
                    | "HEAD"
                    | "--check"
                    | "--stat"
                    | "--numstat"
                    | "--shortstat"
                    | "--summary"
                    | "--name-only"
                    | "--name-status"
                    | "--patch"
                    | "-p"
                    | "--quiet"
                    | "--exit-code"
                    | "--no-color"
                    | "--color=never"
                    | "--no-ext-diff"
                    | "--no-textconv"
            ) || option
                .strip_prefix("-U")
                .or_else(|| option.strip_prefix("--unified="))
                .is_some_and(|lines| {
                    !lines.is_empty()
                        && lines.len() <= 6
                        && lines.bytes().all(|b| b.is_ascii_digit())
                })
        })
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
        "cat-file" => crate::pretool::git_object_reads::read_form(command, rest),
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
        "config" if crate::pretool::git_config_reads::read_form(rest).is_some() => true,
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
    let remaining = routed(arguments, context, true)?;
    matches!(
        remaining.first().map(String::as_str),
        Some(
            "status"
                | "diff"
                | "log"
                | "show"
                | "branch"
                | "hash-object"
                | "rev-parse"
                | "merge-base"
                | "ls-files"
                | "remote"
                | "worktree"
                | "config"
                | "grep"
                | "ls-tree"
                | "cat-file"
                | "show-ref"
                | "for-each-ref"
                | "rev-list"
        )
    )
    .then_some(remaining)
}

pub(super) fn fetch_origin_shaped(arguments: &[String]) -> bool {
    git_fetch::origin_shaped_arguments(arguments)
}

pub(super) fn routed_arguments<'a>(
    arguments: &'a [String],
    context: crate::pretool::PathContext<'_>,
) -> Option<&'a [String]> {
    routed(arguments, context, false)
}

/// `inspection` additionally admits read-only routing and hardening options
/// (`--git-dir=<bare repository>`, a `core.hooksPath` that names no hooks)
/// that proofs for operations which run hooks must keep refusing.
fn routed<'a>(
    arguments: &'a [String],
    context: crate::pretool::PathContext<'_>,
    inspection: bool,
) -> Option<&'a [String]> {
    let mut index = 0;
    let mut saw_change_directory = false;
    let mut saw_git_dir = false;
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
                "core.hookspath" => inspection && hooks_path_names_no_hooks(value),
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
        let git_dir = match argument.as_str() {
            "--git-dir" if inspection => {
                index += 1;
                Some(arguments.get(index)?.as_str())
            }
            _ => argument.strip_prefix("--git-dir=").filter(|_| inspection),
        };
        if let Some(git_dir) = git_dir {
            // A repository named by `--git-dir` is a read route like `-C`.
            if saw_change_directory
                || saw_git_dir
                || !crate::pretool::safe_directory_target(git_dir)
                || !crate::pretool::git_dir_route_within_scope(git_dir, context)
            {
                return None;
            }
            saw_git_dir = true;
            index += 1;
            continue;
        }
        let target = if argument == "-C" {
            if saw_git_dir {
                return None;
            }
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
    arguments.get(index..)
}

#[cfg(test)]
pub(super) fn observe_with_context(
    segment: &CommandSegmentV1,
    index: usize,
    result: &mut CompatibilityObservations,
    context: crate::pretool::PathContext<'_>,
) {
    observe_with_contexts(segment, index, result, context, context);
}

/// `proof_context` is where native proofs ran this segment: the directory a
/// verified leading `cd` entered, or `context` itself.
pub(super) fn observe_with_contexts(
    segment: &CommandSegmentV1,
    index: usize,
    result: &mut CompatibilityObservations,
    context: crate::pretool::PathContext<'_>,
    proof_context: crate::pretool::PathContext<'_>,
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
        .filter(|_| crate::pretool::directory_targets::drive_targets_quoted(segment))
        .filter(|_| crate::pretool::directory_targets::home_targets_unquoted(segment));
    // A remote operation behind proven `-C` routes names its subcommand
    // exactly, like the bare form; its own floors then apply.
    let routed_remote = command_index != 0
        && matches!(command, "push" | "fetch" | "pull")
        && routed_arguments(arguments, context)
            .filter(|_| crate::pretool::directory_targets::drive_targets_quoted(segment))
            .filter(|_| crate::pretool::directory_targets::home_targets_unquoted(segment))
            .is_some_and(|remaining| remaining.first().map(String::as_str) == Some(command));
    let plumbing = (command_index == 0 && read_only_plumbing(arguments))
        || inspection.is_some_and(read_only_plumbing);
    if plumbing {
        // The command stays read-only, but a disabled Git permission or
        // extension can still block it.
        result.permission("command.git.permission.ls-files", index, false);
    }
    // A proven pure listing is read-only inspection, not branch mutation.
    let branch_listing = command == "branch"
        && inspection.is_some_and(|remaining| {
            crate::pretool::git_branch_listing::is_listing(&remaining[1..])
        });
    // Printing object ids of named files writes nothing to the repository.
    let hash_read = command == "hash-object"
        && inspection.is_some_and(|remaining| {
            crate::pretool::git_hash_object::read_operands(&remaining[1..]).is_some()
        });
    // `init` is a built-in, so no alias can replace it. Creating a repository
    // in the current directory or one absolute target with only a quiet flag
    // or an initial branch name touches none of the porcelain owners above;
    // the native proof still decides the target. Templates, separate git
    // directories and other options keep every owner uncertain.
    let plain_init = command_index == 0
        && command == "init"
        && (crate::pretool::init_arguments(&arguments[1..]).is_some()
            || crate::pretool::git_init_target::target(&arguments[1..])
                .is_some_and(crate::pretool::git_init_target::absolute_target));
    // A plain configuration write sets a key Git never runs; its own proof
    // still decides the repository.
    let plain_config_write = command == "config"
        && crate::pretool::directory_targets::drive_targets_quoted(segment)
        && crate::pretool::directory_targets::home_targets_unquoted(segment)
        && routed_arguments(arguments, context).is_some_and(|remaining| {
            remaining.first().map(String::as_str) == Some("config")
                && crate::pretool::git_config_reads::writes::plain_write(&remaining[1..]).is_some()
        });
    if plumbing
        || plain_config_write
        || branch_listing
        || hash_read
        || plain_init
        || (command_index == 0 && bounded_inspection(arguments))
        || inspection.is_some_and(bounded_inspection)
    {
        return;
    }
    if let Some((_, rule)) = RULES.iter().find(|(name, _)| *name == command) {
        // Attribution is deliberately stronger than legacy Python's inert
        // matcher=None porcelain entries: disabling a permission must work.
        result.rule(
            rule,
            index,
            command_index != 0 && inspection.is_none() && !routed_remote,
        );
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
        // Repository/configuration bindings are unavailable in
        // CanonicalCommandV1, so Guard still never proves the fetch benign.
        // A plain named-origin refresh is a definite review rule, though, so an
        // explicit Allow of its permission can settle it. Every wrapped,
        // option-prefixed, URL, or otherwise non-exact form stays uncertain.
        // The hook's native proof already checked the repository's origin,
        // transport, credential helpers and hooks for exactly this segment.
        // A trailing `2>&1` only merges the fetch's progress into stdout.
        let stripped = crate::pretool::without_stderr_merge(segment);
        let refresh = stripped.as_ref().unwrap_or(segment);
        let plain = git_fetch::plain_origin_refresh(refresh, command_index)
            || (routed_remote && git_fetch::routed_origin_refresh(refresh, command_index));
        if !(plain && crate::pretool::verified_origin_operation(refresh, proof_context)) {
            result.rule("command.git.unverified-fetch", index, !plain);
        }
    }
    if command == "diff"
        && arguments[command_index + 1..]
            .iter()
            .take_while(|argument| argument.as_str() != "--")
            .any(|argument| matches!(argument.as_str(), "--cached" | "--staged"))
        && !inspection.is_some_and(|remaining| bounded_cached_diff(&remaining[1..]))
    {
        result.rule("command.git.index-inspection", index, true);
    }
}

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;
