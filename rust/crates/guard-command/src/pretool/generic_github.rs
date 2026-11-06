//! Oh My Pi's `github` tool: its lookups are reads, not unknown actions.
//!
//! The tool takes an `op` and a handful of search or repository arguments.
//! Oh My Pi itself marks `repo_view`, `file_read`, the five `search_*`
//! operations and `run_watch` as read-only; `pr_create`, `pr_checkout` and
//! `pr_push` are not, and keep their review. A search `query` is GitHub search
//! syntax (`is:pr metrics OR analytics`) sent to GitHub, so a lookup is proven
//! only for plain `owner/name` repositories, with arguments the tool's schema
//! names for these operations and nothing else. The call still counts as
//! network use, and the installed network setting decides whether it runs.

use super::extract::GenericSignals;
use serde_json::{Map, Value};

/// The arguments each read-only operation takes beside `op`, `repo` and the
/// intent label `i`, or `None` for any other operation. A key that belongs to
/// another operation, such as `path` on a pull request search, is not part of
/// the lookup and keeps the call under review.
fn operation_arguments(operation: &str) -> Option<&'static [&'static str]> {
    Some(match operation {
        "repo_view" => &["branch"],
        "file_read" => &["path", "branch"],
        "search_issues" | "search_prs" | "search_commits" => {
            &["query", "limit", "since", "until", "dateField"]
        }
        "search_code" | "search_repos" => &["query", "limit"],
        "run_watch" => &["run", "branch", "tail"],
        _ => return None,
    })
}

/// Text arguments of the read operations. `i` is Oh My Pi's intent label.
const TEXT_ARGUMENTS: [&str; 8] = [
    "branch",
    "path",
    "query",
    "since",
    "until",
    "dateField",
    "run",
    "i",
];

/// Count arguments of the read operations.
const COUNT_ARGUMENTS: [&str; 2] = ["limit", "tail"];

const MAX_TEXT_BYTES: usize = 1024;

/// True when the call is one of the read-only operations with only the
/// arguments those operations take. Whether anything else about the call
/// (a credential-shaped query, a command, a URL) lets it through is decided by
/// the caller from the shared signals.
pub(super) fn read_only_call(input: &Map<String, Value>, tool: Option<&str>) -> bool {
    let Some(operation_arguments) = input
        .get("op")
        .and_then(Value::as_str)
        .and_then(operation_arguments)
    else {
        return false;
    };
    tool == Some("github")
        && input.iter().all(|(key, value)| {
            (matches!(key.as_str(), "op" | "repo" | "i")
                || operation_arguments.contains(&key.as_str()))
                && argument_allowed(key, value)
        })
}

fn argument_allowed(key: &str, value: &Value) -> bool {
    match (key, value) {
        ("op", Value::String(_)) => true,
        ("repo", Value::String(repo)) => plain_repository(repo),
        (key, Value::String(text)) if TEXT_ARGUMENTS.contains(&key) => bounded_text(text),
        (key, Value::Number(count)) if COUNT_ARGUMENTS.contains(&key) => {
            count.as_u64().is_some_and(|count| count <= 100_000)
        }
        _ => false,
    }
}

fn bounded_text(text: &str) -> bool {
    if text.len() > MAX_TEXT_BYTES || text.contains('\0') {
        return false;
    }
    // These values go straight to GitHub. The generic signal extractor does
    // not necessarily notice an embedded URL or token inside a search query.
    // An uncertain outbound value keeps the normal review, not the read proof.
    let lower = text.to_ascii_lowercase();
    let at_token_start = |marker: &str| {
        lower
            .match_indices(marker)
            .any(|(index, _)| index == 0 || !lower.as_bytes()[index - 1].is_ascii_alphanumeric())
    };
    let anywhere = [
        "http://",
        "https://",
        "%3a%2f%2f",
        "github_pat_",
        "bearer ",
        "authorization:",
        "access_token=",
        "api_key=",
        "apikey=",
        "password=",
        "secret=",
    ];
    let prefixes = [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "xoxb-", "xoxp-", "sk-",
    ];
    !(anywhere.iter().any(|marker| lower.contains(marker))
        || prefixes.iter().any(|marker| at_token_start(marker)))
}

/// `owner/name` on github.com. A host or a URL in front of the slug would send
/// the request to another server, and an owner is never a dotted name, so
/// `server.example/name` cannot pass for one.
fn plain_repository(repo: &str) -> bool {
    let mut parts = repo.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let owner_ok = !owner.is_empty()
        && owner.len() <= 39
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    let name_ok = !name.is_empty()
        && name.len() <= 100
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    owner_ok && name_ok
}

/// The extracted signals leave nothing else to review: no sensitive text, no
/// command, package, URL or request body beside the lookup.
pub(super) fn proven_read(signals: &GenericSignals) -> bool {
    signals.github_read_only
        && !signals.sensitive_target
        && signals.command.is_none()
        && !signals.package_present
        && signals.url_values.is_empty()
        && !signals.request_body_or_method
}

#[cfg(test)]
#[path = "generic_github_tests.rs"]
mod tests;
