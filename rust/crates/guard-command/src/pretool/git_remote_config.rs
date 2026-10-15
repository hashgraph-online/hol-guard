//! Pure predicates over the effective Git configuration of a remote
//! refresh. Keys are case-folded when parsed, and any shape
//! these predicates do not recognize is treated as unsafe.
//!
//! These mirror the resident runtime's origin checks so the hook decision and
//! the compound executor agree on what a safe `origin` looks like.

use std::collections::BTreeMap;

pub(super) type GitConfig = BTreeMap<String, Vec<String>>;

const DISABLED: &[&str] = &["", "0", "false", "no", "off"];

/// Parses `git config --show-scope --null --list` into the effective
/// configuration and the repository-scoped (`local` and `worktree`) part.
pub(super) fn parse_scoped(output: &[u8]) -> Option<(GitConfig, GitConfig)> {
    let output = std::str::from_utf8(output).ok()?;
    let mut effective = GitConfig::new();
    let mut repository = GitConfig::new();
    let mut records = output.split('\0');
    while let Some(scope) = records.next() {
        if scope.is_empty() {
            continue;
        }
        let (key, value) = records.next()?.split_once('\n')?;
        if key.is_empty() {
            return None;
        }
        let key = key.to_ascii_lowercase();
        if matches!(scope, "local" | "worktree") {
            repository
                .entry(key.clone())
                .or_default()
                .push(value.to_owned());
        }
        effective.entry(key).or_default().push(value.to_owned());
    }
    Some((effective, repository))
}

fn values<'a>(config: &'a GitConfig, key: &str) -> &'a [String] {
    config.get(key).map_or(&[], Vec::as_slice)
}

fn enables_behavior(values: &[String]) -> bool {
    values
        .iter()
        .any(|value| !DISABLED.contains(&value.trim().to_ascii_lowercase().as_str()))
}

/// Settings that would make a fetch from `origin` run a program, reach a
/// different host, or rewrite more refs than the plain remote-tracking set.
pub(super) fn fetch_config_routes_execution(config: &GitConfig) -> bool {
    if [
        "remote.origin.uploadpack",
        "remote.origin.vcs",
        "fetch.bundleuri",
        "transfer.bundleuri",
    ]
    .iter()
    .any(|key| config.contains_key(*key))
    {
        return true;
    }
    if [
        "core.askpass",
        "core.sshcommand",
        "core.alternaterefscommand",
    ]
    .iter()
    .any(|key| {
        values(config, key)
            .iter()
            .any(|value| !value.trim().is_empty())
    }) {
        return true;
    }
    for (key, entries) in config {
        if !(key.starts_with("url.") && key.ends_with(".insteadof")) {
            continue;
        }
        if key != "url.https://github.com/.insteadof"
            || entries.is_empty()
            || entries
                .iter()
                .any(|value| value.trim() != "git@github.com:")
        {
            return true;
        }
    }
    if !values(config, "remote.origin.fetch")
        .iter()
        .all(|value| safe_origin_fetch_refspec(value))
    {
        return true;
    }
    const BOOLEAN_KEYS: &[&str] = &[
        "remote.origin.mirror",
        "remote.origin.prune",
        "remote.origin.prunetags",
        "remote.origin.recursesubmodules",
        "fetch.prune",
        "fetch.prunetags",
        "fetch.recursesubmodules",
        "submodule.recurse",
    ];
    if BOOLEAN_KEYS
        .iter()
        .any(|key| enables_behavior(values(config, key)))
    {
        return true;
    }
    values(config, "remote.origin.tagopt")
        .iter()
        .any(|value| value.trim() != "--no-tags")
}

/// Repository-scoped transport or credential settings a cloned repository
/// could carry to redirect where a push authenticates.
pub(super) fn repository_config_routes_transport(config: &GitConfig) -> bool {
    config.keys().any(|key| {
        key.starts_with("http.")
            || key.starts_with("credential.")
            || matches!(
                key.as_str(),
                "core.askpass"
                    | "core.gitproxy"
                    | "core.hookspath"
                    | "remote.origin.proxy"
                    | "remote.origin.proxyauthmethod"
            )
    })
}

/// Effective settings that weaken TLS verification or add headers to a push.
pub(super) fn config_weakens_transport(config: &GitConfig) -> bool {
    const SUFFIXES: &[&str] = &[
        ".cookiefile",
        ".extraheader",
        ".followredirects",
        ".pinnedpubkey",
        ".proxy",
        ".proxyauthmethod",
        ".schannelcheckrevoke",
        ".schannelusesslcainfo",
        ".sslbackend",
        ".sslcainfo",
        ".sslcapath",
        ".sslcert",
        ".sslcipherlist",
        ".sslkey",
        ".sslverify",
        ".sslversion",
    ];
    config
        .keys()
        .any(|key| key.starts_with("http.") && SUFFIXES.iter().any(|suffix| key.ends_with(suffix)))
}

pub(super) fn credential_helpers(config: &GitConfig) -> Vec<&str> {
    config
        .iter()
        .filter(|(key, _)| {
            key.as_str() == "credential.helper"
                || (key.starts_with("credential.") && key.ends_with(".helper"))
        })
        .flat_map(|(_, values)| values.iter())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect()
}

fn safe_origin_fetch_refspec(value: &str) -> bool {
    let normalized = value.trim();
    normalized.strip_prefix('+').unwrap_or(normalized) == "refs/heads/*:refs/remotes/origin/*"
}

/// `https://github.com/<owner>/<repo>[.git]` with no credentials, query,
/// fragment, non-ASCII byte or non-default port.
pub(super) fn safe_github_https_remote_url(value: &str) -> bool {
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return false;
    }
    let Some(prefix) = value.get(..8) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case("https://") {
        return false;
    }
    let rest = &value[8..];
    let Some(index) = rest.find('/') else {
        return false;
    };
    let (authority, path) = rest.split_at(index);
    if authority.contains(['@', '?', '#', '\\', '[', ']']) || path.contains(['?', '#', '\\']) {
        return false;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, "443")) => host,
        Some(_) => return false,
        None => authority,
    };
    if !host.eq_ignore_ascii_case("github.com") {
        return false;
    }
    let stripped = path.strip_suffix(".git").unwrap_or(path);
    let parts: Vec<&str> = stripped.split('/').collect();
    parts.len() == 3
        && parts[0].is_empty()
        && parts[1..].iter().all(|part| {
            !matches!(*part, "" | "." | "..")
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        })
}

/// A credential helper Guard can resolve to one executable on disk.
pub(super) enum HelperShape<'a> {
    /// `!<gh> auth git-credential` with a bare `gh` or an absolute path.
    GithubCli(&'a str),
    /// A bare helper name resolved under Git's exec path.
    Named(&'a str),
}

pub(super) fn credential_helper_shape(value: &str) -> Option<HelperShape<'_>> {
    if let Some(command) = value.strip_prefix('!') {
        if !command.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'.' | b'/' | b'-' | b'+')
        }) {
            return None;
        }
        let tokens: Vec<&str> = command.split_ascii_whitespace().collect();
        if tokens.len() != 3 || tokens[1..] != ["auth", "git-credential"] {
            return None;
        }
        let binary = tokens[0];
        let absolute_gh = binary.starts_with('/') && binary.rsplit('/').next() == Some("gh");
        return (binary == "gh" || absolute_gh).then_some(HelperShape::GithubCli(binary));
    }
    let named = !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    named.then_some(HelperShape::Named(value))
}

#[cfg(test)]
#[path = "git_remote_config_tests.rs"]
mod tests;

/// The URL Git connects to for `url` after one `url.<base>.insteadOf`
/// rewrite: the longest matching prefix wins, as in Git. `None` when the
/// choice is ambiguous (an empty prefix or several rules matching with the
/// same length). `pushInsteadOf` never applies here; callers refuse it.
pub(super) fn rewritten_remote_url(config: &GitConfig, url: &str) -> Option<String> {
    let mut best: Option<(usize, &str, &str)> = None;
    let mut tied = false;
    for (key, values) in config {
        let Some(base) = key
            .strip_prefix("url.")
            .and_then(|rest| rest.strip_suffix(".insteadof"))
        else {
            continue;
        };
        for prefix in values {
            let prefix = prefix.trim();
            if prefix.is_empty() {
                return None;
            }
            if !url.starts_with(prefix) {
                continue;
            }
            match best {
                Some((length, _, _)) if length > prefix.len() => {}
                Some((length, _, _)) if length == prefix.len() => tied = true,
                _ => {
                    best = Some((prefix.len(), base, prefix));
                    tied = false;
                }
            }
        }
    }
    if tied {
        return None;
    }
    Some(match best {
        Some((length, base, _)) => format!("{base}{}", &url[length..]),
        None => url.to_owned(),
    })
}
