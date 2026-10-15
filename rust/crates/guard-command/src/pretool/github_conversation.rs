//! A review-conversation write on the repository the agent works in: one
//! comment on an issue or pull request (`gh issue|pr comment`), or one
//! comment or review-comment reply through `gh api`.
//!
//! The write can only reach the work tree's own repository: a `--repo`
//! selector and a `gh api` path must name its `origin`. A command without a
//! selector posts to the base repository gh resolves from the checkout, so it
//! passes only when that can be nothing but `origin`: no `GH_REPO`, no other
//! remote, and no `gh repo set-default` choice other than origin itself. With
//! no remote at all gh resolves no base repository and posts nothing. Git
//! itself lists the remotes, in the environment the command inherits, so
//! every configuration scope, include and URL rewrite counts.
//! The posted text is literal and must carry no credential shape, so the
//! comment cannot carry a secret out. A `--body-file` must be a plain,
//! bounded file in the work tree or a private temporary directory, and its
//! content passes the same scan. Anything else keeps the normal review.

use crate::CommandSegmentV1;
use std::time::Instant;

/// Variables that move gh to another host than the `github.com` origin names.
const HOST_VARIABLES: [&str; 4] = [
    "GH_HOST",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "GH_CONFIG_DIR",
];

#[path = "github_conversation_files.rs"]
mod files;
#[path = "github_conversation_remotes.rs"]
mod remotes;

/// Where the proof runs the segment, its deadline, and the execution
/// environment the command inherits.
pub(crate) type ProbeContext<'a> = (
    super::PathContext<'a>,
    Option<Instant>,
    Option<&'a guard_contracts::GuardExecutionEnvironmentV1>,
);

/// GitHub rejects a comment body longer than this many characters.
const MAX_BODY_BYTES: usize = 65_536;

enum Body<'a> {
    Text(&'a str),
    File(&'a str),
}

/// Whether the `gh` segment (arguments without the executable) posts one
/// secret-free comment or reply to the work tree's own repository.
pub(crate) fn current_repository_write(
    segment: &CommandSegmentV1,
    (context, deadline, environment): ProbeContext<'_>,
) -> bool {
    let Some(cwd) = context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()) else {
        return false;
    };
    let home = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok());
    let Some(root) = super::workspace_git_config::work_tree(&cwd, home.as_deref()) else {
        return false;
    };
    let arguments = &segment.arguments;
    let (selector, body) = if arguments.first().is_some_and(|word| word == "api") {
        let Some((owner, repository, text)) = api_write(&arguments[1..]) else {
            return false;
        };
        (Some((owner, repository)), Body::Text(text))
    } else {
        let Some((selector, body)) = comment_write(arguments) else {
            return false;
        };
        let selector = match selector.map(repository_selector) {
            Some(None) => return false,
            Some(Some(pair)) => Some(pair),
            None => None,
        };
        (selector, body)
    };
    // gh takes the base repository from `GH_REPO` before any remote when no
    // `--repo` is given, and the host for `--repo owner/name` and `gh api`
    // from `GH_HOST`, an enterprise token or the hosts in `GH_CONFIG_DIR`,
    // whether the segment sets them or inherits them.
    let names = |test: &dyn Fn(&String) -> bool| {
        segment.environment_names.iter().any(test)
            || environment.is_some_and(|stamped| stamped.environment_names.iter().any(test))
    };
    let host = |name: &String| {
        HOST_VARIABLES
            .iter()
            .any(|variable| name.eq_ignore_ascii_case(variable))
    };
    if names(&host)
        || (selector.is_none() && names(&|name: &String| name.eq_ignore_ascii_case("GH_REPO")))
    {
        return false;
    }
    let Some(remotes) = remotes::resolve(context, deadline, environment) else {
        return false;
    };
    match (selector, remotes.origin) {
        (Some((owner, repository)), Some((origin_owner, origin_repository))) => {
            if !owner.eq_ignore_ascii_case(&origin_owner)
                || !repository.eq_ignore_ascii_case(&origin_repository)
            {
                return false;
            }
        }
        (Some(_), None) => return false,
        (None, _) if !remotes.origin_only => return false,
        (None, _) => {}
    }
    let text = match body {
        Body::Text(text) => text.to_owned(),
        Body::File(value) => match files::body_file_text(value, context, &root) {
            Some(text) => text,
            None => return false,
        },
    };
    !text.trim().is_empty()
        && text.len() <= MAX_BODY_BYTES
        && !super::curl_reads::url_secrets::text_carries_secret(&text)
}

/// `[--repo <selector>] issue|pr comment [<number>] (--body <text> |
/// --body-file <path>) [--repo <selector>]`, with no other option.
fn comment_write(arguments: &[String]) -> Option<(Option<&str>, Body<'_>)> {
    let mut selector = None;
    let mut body = None;
    let mut words = 0;
    let mut number = false;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let (name, attached) = match argument.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (argument.as_str(), None),
        };
        if matches!(
            name,
            "-R" | "--repo" | "-b" | "--body" | "-F" | "--body-file"
        ) {
            let value = match attached {
                Some(value) => value,
                None => {
                    index += 1;
                    arguments.get(index)?.as_str()
                }
            };
            match name {
                "-R" | "--repo" => {
                    if selector.replace(value).is_some() {
                        return None;
                    }
                }
                // A body belongs to the comment subcommand, never before it.
                _ if words < 2 || body.is_some() => return None,
                "-b" | "--body" => body = Some(Body::Text(value)),
                _ => body = Some(Body::File(value)),
            }
        } else if argument.starts_with('-') {
            return None;
        } else if words == 0 && matches!(argument.as_str(), "issue" | "pr") {
            words = 1;
        } else if words == 1 && argument == "comment" {
            words = 2;
        } else if words == 2 && !number && positive_number(argument) {
            number = true;
        } else {
            return None;
        }
        index += 1;
    }
    if words != 2 {
        return None;
    }
    Some((selector, body?))
}

/// `gh api [-X POST] <endpoint> (-f|-F) body=<text> [--jq <filter>]
/// [--silent]` against one issue or pull-request comment list or one
/// review-comment reply list. Returns the endpoint's owner and repository.
fn api_write(arguments: &[String]) -> Option<(&str, &str, &str)> {
    let mut endpoint = None;
    let mut body = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let (name, attached) = match argument.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ if argument.len() > 2
                && argument
                    .get(..2)
                    .is_some_and(|head| matches!(head, "-X" | "-f" | "-F")) =>
            {
                (&argument[..2], Some(&argument[2..]))
            }
            _ => (argument.as_str(), None),
        };
        match name {
            "--silent" if attached.is_none() => {}
            "-X" | "--method" | "-f" | "--raw-field" | "-F" | "--field" | "--jq" => {
                let value = match attached {
                    Some(value) => value,
                    None => {
                        index += 1;
                        arguments.get(index)?.as_str()
                    }
                };
                match name {
                    "-X" | "--method" if !value.eq_ignore_ascii_case("POST") => return None,
                    "-f" | "--raw-field" | "-F" | "--field" => {
                        // A typed `-F body=@path` uploads a file instead.
                        let text = value.strip_prefix("body=")?;
                        if body.replace(text).is_some()
                            || (matches!(name, "-F" | "--field") && text.starts_with('@'))
                        {
                            return None;
                        }
                    }
                    _ => {}
                }
            }
            _ if argument.starts_with('-') || endpoint.is_some() => return None,
            _ => endpoint = Some(argument.as_str()),
        }
        index += 1;
    }
    let (owner, repository) = conversation_endpoint(endpoint?)?;
    Some((owner, repository, body?))
}

/// `repos/<owner>/<repo>/issues/<n>/comments` or
/// `repos/<owner>/<repo>/pulls/<n>/comments/<id>/replies`.
fn conversation_endpoint(endpoint: &str) -> Option<(&str, &str)> {
    let path = endpoint.strip_prefix('/').unwrap_or(endpoint);
    let parts: Vec<&str> = path.split('/').collect();
    let shape = match parts.as_slice() {
        ["repos", _, _, "issues", number, "comments"] => positive_number(number),
        ["repos", _, _, "pulls", number, "comments", comment, "replies"] => {
            positive_number(number) && positive_number(comment)
        }
        _ => false,
    };
    (shape && repository_name(parts[1]) && repository_name(parts[2])).then(|| (parts[1], parts[2]))
}

/// `<owner>/<repo>` or `github.com/<owner>/<repo>`.
fn repository_selector(value: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = value.split('/').collect();
    let pair = match parts.as_slice() {
        [host, owner, repository] if host.eq_ignore_ascii_case("github.com") => {
            (*owner, *repository)
        }
        [owner, repository] => (*owner, *repository),
        _ => return None,
    };
    (repository_name(pair.0) && repository_name(pair.1)).then_some(pair)
}

/// The lowercase owner and repository of a plain GitHub HTTPS or SSH URL.
fn github_repository(url: &str) -> Option<(String, String)> {
    let rest = [
        "https://github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
    ]
    .iter()
    .find_map(|prefix| {
        url.get(..prefix.len())
            .filter(|head| head.eq_ignore_ascii_case(prefix))
            .map(|_| &url[prefix.len()..])
    })?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let (owner, repository) = rest.split_once('/')?;
    (repository_name(owner) && repository_name(repository))
        .then(|| (owner.to_ascii_lowercase(), repository.to_ascii_lowercase()))
}

fn repository_name(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn positive_number(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.bytes().any(|byte| byte != b'0')
}

#[cfg(all(test, unix))]
#[path = "github_conversation_probe_tests.rs"]
mod probe_tests;
#[cfg(test)]
#[path = "github_conversation_tests.rs"]
mod tests;
