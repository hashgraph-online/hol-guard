//! Closed static CLI grammar. Ambiguous flags, bindings and GraphQL stay unsupported.
use super::{catalog::github_owner, CommandSegmentV1, CompatibilityObservations};
use crate::pretool::shell_literal::literal_everywhere;

#[path = "github_api.rs"]
mod api;
#[path = "github_options.rs"]
mod options;

type Capabilities = Option<Vec<&'static str>>;

/// Options that take a GitHub user, where `gh` reads `@me` as the signed-in
/// account. A user is never a file, so `--author @me` reads nothing local.
const USER_OPTIONS: &[&str] = &[
    "--add-assignee",
    "--add-reviewer",
    "--assignee",
    "--author",
    "--commenter",
    "--involves",
    "--mention",
    "--mentions",
    "--remove-assignee",
    "--remove-reviewer",
    "--review-requested",
    "--reviewed-by",
    "--reviewer",
];

/// `@me` as the separate value of a user option. The `--author=@me` spelling
/// never starts with `@`, and the `-F key=@path` file form stays with `api`.
/// After a bare `--` every token is positional, so no option precedes it.
fn names_signed_in_user(original: &[String], index: usize) -> bool {
    original[index] == "@me"
        && index
            .checked_sub(1)
            .and_then(|option| original.get(option))
            .is_some_and(|option| USER_OPTIONS.contains(&option.as_str()))
        && !original[..index].iter().any(|value| value == "--")
}

/// `probe` is where native proofs run the segment (after a verified leading
/// `cd`), with the deadline and the environment the command inherits.
pub(super) fn observe(
    segment: &CommandSegmentV1,
    index: usize,
    result: &mut CompatibilityObservations,
    probe: crate::pretool::github_conversation::ProbeContext<'_>,
) {
    match classify(&segment.arguments, &segment.text) {
        Some(mut capabilities) => {
            // One secret-free comment or review reply on the work tree's own
            // repository is review conversation, owned like a routine
            // review-thread resolution instead of a content mutation.
            if capabilities == ["content_remote"]
                && crate::pretool::github_conversation::current_repository_write(segment, probe)
            {
                capabilities = vec!["routine_review_thread_remote"];
            }
            for capability in capabilities {
                let (owner, permission_only) = github_owner(capability);
                if permission_only {
                    result.permission(owner, index, false);
                } else {
                    result.rule(owner, index, false);
                }
            }
        }
        None => result.rule("command.github.unknown", index, true),
    }
}

fn one(capability: &'static str) -> Capabilities {
    Some(vec![capability])
}

pub(super) fn repository_selector(value: &str) -> bool {
    options::repository(value)
}

pub(super) fn arguments_are_read_only(arguments: &[String], text: &str) -> bool {
    // A glued `-Rowner/repo` selector is an unproven content read and stays
    // on the review path. A separate `--repo` read keeps the benign floor.
    !arguments.iter().any(|argument| {
        argument == "--web"
            || argument.starts_with("--web=")
            || argument == "--cache"
            || argument.starts_with("--cache=")
            || (argument.starts_with("-R") && argument != "-R")
            || (argument.starts_with('-')
                && !argument.starts_with("--")
                && !argument.starts_with("-R")
                && argument[1..]
                    .split('=')
                    .next()
                    .is_some_and(|flags| flags.contains('w')))
    }) && classify(arguments, text).is_some_and(|capabilities| {
        !capabilities.is_empty()
            && capabilities
                .iter()
                .all(|capability| matches!(*capability, "read_local" | "read_remote"))
    })
}

/// `--jq @tsv`: a bare jq rendering format given as the whole filter, which
/// names a formatter rather than a file.
fn bare_jq_format(original: &[String], index: usize) -> bool {
    index > 0
        && matches!(original[index - 1].as_str(), "--jq" | "-q")
        && original[index]
            .strip_prefix('@')
            .is_some_and(crate::pretool::safe_reads::jq_rendering_format)
}

/// `--jq '.[] | (.state // "") as $state | $state'`: a response filter whose
/// every `$` names a variable it binds itself, written where the shell passes
/// each `$` through. Such a variable holds a value the filter computed from
/// the response, never the environment or an outside argument.
fn self_bound_jq_filter(original: &[String], index: usize, text: &str) -> bool {
    let value = original[index].as_str();
    let filter = value
        .strip_prefix("--jq=")
        .or_else(|| (value.starts_with("-q") && value.len() > 2).then(|| &value[2..]))
        .or_else(|| {
            (index > 0 && matches!(original[index - 1].as_str(), "--jq" | "-q")).then_some(value)
        });
    filter.is_some_and(|filter| {
        !filter.contains(['\n', '\r'])
            && literal_everywhere(text, '$')
            && crate::pretool::safe_reads::jq_variables_bound(filter)
    })
}

fn classify(original: &[String], text: &str) -> Capabilities {
    // Quoted dynamic-looking values are deliberately outside this small native
    // grammar too. Distinguishing their expansion provenance needs literal proof.
    // The one exception is a single-quoted `gh api graphql` document whose
    // `$variables` it declares itself: the shell never expands those. A
    // `--jq` filter that binds its own `$variables` is the other.
    // A backtick the raw text escapes or single-quotes is Markdown code
    // formatting in a body, never a command substitution.
    let graphql = original.len() > 1 && original[0] == "api" && original[1] == "graphql";
    if original.iter().enumerate().any(|(index, value)| {
        value.contains('\0')
            || (value.contains('`') && !literal_everywhere(text, '`'))
            || (value.starts_with('@')
                && !bare_jq_format(original, index)
                && !names_signed_in_user(original, index))
            || (value.contains('$')
                && !(graphql
                    && literal_everywhere(text, '$')
                    && value
                        .strip_prefix("query=")
                        .is_some_and(api::graphql_text_is_static))
                && !self_bound_jq_filter(original, index, text))
    }) {
        return None;
    }
    // Every `gh` read accepts a `--jq`/`-q` response filter; none may read the
    // environment or load jq modules.
    let mut filters = original.iter().enumerate().filter_map(|(index, value)| {
        value
            .strip_prefix("--jq=")
            .or_else(|| (value.starts_with("-q") && value.len() > 2).then(|| &value[2..]))
            .or_else(|| {
                matches!(value.as_str(), "--jq" | "-q")
                    .then(|| original.get(index + 1).map_or("", String::as_str))
            })
    });
    if filters.any(|filter| !api::jq_is_static(filter) || !api::jq_formats_are_bare(filter)) {
        return None;
    }
    options::validate_selectors(original)?;
    let args = options::strip_globals(original)?;
    // A trailing `--help` prints the subcommand's help and runs nothing, so
    // `gh repo delete owner/name --help` reads as locally as `gh --help`. The
    // capability grammar reads it with the same function, so the two cannot
    // drift back apart.
    if crate::github_capability_contract::github_cli_invocation_is_help(args) {
        return one("read_local");
    }
    let Some(top) = args.first().map(|value| value.to_ascii_lowercase()) else {
        return one("unknown");
    };
    if matches!(
        top.as_str(),
        "--version" | "-v" | "completion" | "help" | "version"
    ) {
        return one("read_local");
    }
    if top == "api" {
        return api::classify(&args[1..]);
    }
    if matches!(top.as_str(), "search" | "status") {
        return one("read_remote");
    }
    if let Some(capability) = crate::github_additional_commands::classify(args) {
        return one(capability.as_str());
    }
    if top == "secret" {
        return one("secret_remote");
    }
    let Some(subcommand) = args.get(1).map(|value| value.to_ascii_lowercase()) else {
        return one("unknown");
    };
    // Interspersed group-global options are not reconstructed by token guessing.
    // A help invocation already returned above.
    if subcommand.starts_with('-') {
        return None;
    }
    let tail = &args[2..];
    if top == "auth" {
        return match subcommand.as_str() {
            "token" => one("secret_remote"),
            "status"
                if options::has_option(tail, "--show-token")
                    || tail.iter().any(|argument| {
                        argument.starts_with('-')
                            && !argument.starts_with("--")
                            && argument[1..]
                                .split('=')
                                .next()
                                .is_some_and(|flags| flags.contains('t'))
                    }) =>
            {
                one("secret_remote")
            }
            "status" => Some(vec!["read_local", "read_remote"]),
            "login" | "logout" | "switch" | "refresh" | "setup-git" => one("write_local"),
            _ => one("unknown"),
        };
    }
    if matches!(top.as_str(), "gpg-key" | "ssh-key") {
        return match subcommand.as_str() {
            "help" => one("read_local"),
            "list" => one("read_remote"),
            "delete" => Some(vec!["delete_remote", "access_remote"]),
            _ => one("access_remote"),
        };
    }
    if matches!(top.as_str(), "cache" | "codespace" | "label" | "variable") {
        return if subcommand == "delete" {
            one("delete_remote")
        } else if top == "label" {
            one("content_remote")
        } else if top == "variable" {
            one("workflow_remote")
        } else {
            one("mutate_remote")
        };
    }
    if !matches!(
        top.as_str(),
        "issue" | "pr" | "release" | "repo" | "run" | "workflow"
    ) {
        return one("unknown");
    }
    if subcommand == "help" {
        return one("read_local");
    }
    if read_command(&top, &subcommand) {
        return one("read_remote");
    }
    if subcommand == "delete" && top != "workflow" {
        return one("delete_remote");
    }
    if top == "pr" && subcommand == "merge" {
        return options::merge(tail);
    }
    if top == "release" && matches!(subcommand.as_str(), "create" | "edit" | "upload") {
        return one("publish_remote");
    }
    if (top == "run" && matches!(subcommand.as_str(), "cancel" | "rerun"))
        || (top == "workflow" && matches!(subcommand.as_str(), "disable" | "enable" | "run"))
    {
        return if top == "run" && subcommand == "rerun" && options::routine_rerun(original, tail) {
            one("routine_workflow_remote")
        } else {
            one("workflow_remote")
        };
    }
    if top == "repo" {
        match subcommand.as_str() {
            "edit" => return one("access_remote"),
            "set-default" => return one("write_local"),
            "sync" if options::has_option(tail, "--force") => return one("force_remote"),
            "create" if crate::github_command_capabilities::private_repo_create(tail) => {
                return one("create_private_remote")
            }
            _ => {}
        }
    }
    if top == "pr" && subcommand == "create" {
        return match options::inline_proposal(tail) {
            Some(true) => one("propose_remote"),
            Some(false) => one("content_remote"),
            None => None,
        };
    }
    if (top == "issue" && matches!(subcommand.as_str(), "lock" | "pin" | "unlock" | "unpin"))
        || (top == "pr" && matches!(subcommand.as_str(), "lock" | "ready" | "unlock"))
    {
        return one("maintain_remote");
    }
    if (top == "issue"
        && matches!(
            subcommand.as_str(),
            "close" | "comment" | "create" | "develop" | "edit" | "reopen" | "transfer"
        ))
        || (top == "pr"
            && matches!(
                subcommand.as_str(),
                "close" | "comment" | "edit" | "reopen" | "review"
            ))
        || (top == "repo" && matches!(subcommand.as_str(), "create" | "fork" | "rename" | "sync"))
    {
        return one("content_remote");
    }
    one("unknown")
}

fn read_command(top: &str, subcommand: &str) -> bool {
    match top {
        "issue" => matches!(subcommand, "list" | "status" | "view"),
        "pr" => matches!(subcommand, "checks" | "diff" | "list" | "status" | "view"),
        "release" | "repo" => matches!(subcommand, "list" | "view"),
        "run" => matches!(subcommand, "list" | "view" | "watch"),
        "workflow" => matches!(subcommand, "list" | "view"),
        _ => false,
    }
}
