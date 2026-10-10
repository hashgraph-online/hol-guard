//! Closed static CLI grammar. Ambiguous flags, bindings and GraphQL stay unsupported.
use super::{catalog::github_owner, CommandSegmentV1, CompatibilityObservations};

#[path = "github_api.rs"]
mod api;
#[path = "github_options.rs"]
mod options;

type Capabilities = Option<Vec<&'static str>>;

pub(super) fn observe(
    segment: &CommandSegmentV1,
    index: usize,
    result: &mut CompatibilityObservations,
) {
    match classify(&segment.arguments, dollars_single_quoted(&segment.text)) {
        Some(capabilities) => {
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
    }) && classify(arguments, dollars_single_quoted(text)).is_some_and(|capabilities| {
        !capabilities.is_empty()
            && capabilities
                .iter()
                .all(|capability| matches!(*capability, "read_local" | "read_remote"))
    })
}

/// True when every `$` in the raw segment text sits inside single quotes, so
/// the shell passes it through literally instead of expanding a variable.
fn dollars_single_quoted(text: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for character in text.chars() {
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                }
            }
            _ if escaped => escaped = false,
            _ if character == '\\' => escaped = true,
            _ if character == '$' => return false,
            Some(_) if character == '"' => quote = None,
            None if matches!(character, '\'' | '"') => quote = Some(character),
            _ => {}
        }
    }
    true
}

fn classify(original: &[String], literal_dollars: bool) -> Capabilities {
    // Quoted dynamic-looking values are deliberately outside this small native
    // grammar too. Distinguishing their expansion provenance needs literal proof.
    // The one exception is a single-quoted `gh api graphql` document whose
    // `$variables` it declares itself: the shell never expands those.
    let graphql = original.len() > 1 && original[0] == "api" && original[1] == "graphql";
    if original.iter().any(|value| {
        value.contains(['`', '\0'])
            || value.starts_with('@')
            || (value.contains('$')
                && !(graphql
                    && literal_dollars
                    && value
                        .strip_prefix("query=")
                        .is_some_and(api::graphql_text_is_static)))
    }) {
        return None;
    }
    options::validate_selectors(original)?;
    let args = options::strip_globals(original)?;
    let Some(top) = args.first().map(|value| value.to_ascii_lowercase()) else {
        return one("unknown");
    };
    if matches!(
        top.as_str(),
        "--version" | "-v" | "--help" | "-h" | "completion" | "help" | "version"
    ) {
        return one("read_local");
    }
    if top == "api" {
        return api::classify(&args[1..]);
    }
    if matches!(top.as_str(), "search" | "status") {
        return one("read_remote");
    }
    if top == "secret" {
        return one("secret_remote");
    }
    let Some(subcommand) = args.get(1).map(|value| value.to_ascii_lowercase()) else {
        return one("unknown");
    };
    // Interspersed group-global options are not reconstructed by token guessing.
    if subcommand.starts_with('-') {
        return if subcommand == "--help"
            && matches!(
                top.as_str(),
                "issue" | "pr" | "release" | "repo" | "run" | "workflow" | "gpg-key" | "ssh-key"
            ) {
            one("read_local")
        } else {
            None
        };
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
            "switch" if tail.len() == 1 && tail[0] == "--help" => one("read_local"),
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
