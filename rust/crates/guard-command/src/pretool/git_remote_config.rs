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
        // Git lowercases a key's section and variable but keeps the case of a
        // subsection, so `remote.Origin` and `remote.origin` are two remotes.
        // Every exact lookup reads the lowercased key, so that one is always
        // recorded; a remote whose name is not already lowercase is recorded a
        // second time under its own spelling, so a reader counting remotes
        // sees it rather than the one it was folded onto.
        let lowered = key.to_ascii_lowercase();
        let spelled = key
            .strip_prefix("remote.")
            .and_then(|rest| rest.rsplit_once('.'))
            .map(|(name, variable)| format!("remote.{name}.{}", variable.to_ascii_lowercase()))
            .filter(|spelled| *spelled != lowered);
        for key in std::iter::once(lowered).chain(spelled) {
            if matches!(scope, "local" | "worktree") {
                repository
                    .entry(key.clone())
                    .or_default()
                    .push(value.to_owned());
            }
            effective.entry(key).or_default().push(value.to_owned());
        }
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
        if !github_rewrite_pair(key, entries) {
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
        "remote.origin.prunetags",
        "remote.origin.recursesubmodules",
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
/// could carry to redirect where a push authenticates. A hooks directory
/// below the repository, which hook managers such as Husky set, is not
/// one: the hook files in it are judged by `Probe::hooks_inert`.
pub(super) fn repository_config_routes_transport(config: &GitConfig) -> bool {
    config.iter().any(|(key, entries)| {
        key.starts_with("http.")
            || key.starts_with("credential.")
            || (key == "core.hookspath"
                && !entries
                    .iter()
                    .all(|value| super::git_hook_files::repository_relative_hooks_path(value)))
            || matches!(
                key.as_str(),
                "core.askpass"
                    | "core.gitproxy"
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
        && parts[1..].iter().all(|part| plain_repository_name(part))
}

/// `git@github.com:<owner>/<repo>[.git]` or `ssh://git@github.com/<owner>/<repo>[.git]`:
/// the `git` user, no port, and an owner and repository of plain name bytes.
/// Git then starts only `ssh` with `git@github.com` and a quoted repository
/// path; the session's `GIT_SSH*` variables and `core.sshCommand` are refused
/// elsewhere, so nothing but the user's own `ssh` configuration is in play.
pub(super) fn safe_github_ssh_remote_url(value: &str) -> bool {
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return false;
    }
    let path = if let Some(path) = value.strip_prefix("git@github.com:") {
        path
    } else if let Some(path) = value.strip_prefix("ssh://git@github.com/") {
        path
    } else {
        return false;
    };
    let stripped = path.strip_suffix(".git").unwrap_or(path);
    let parts: Vec<&str> = stripped.split('/').collect();
    parts.len() == 2 && parts.iter().all(|part| plain_repository_name(part))
}

fn plain_repository_name(part: &str) -> bool {
    !matches!(part, "" | "." | "..")
        && part
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// A GitHub origin Git reaches over HTTPS or SSH.
pub(super) fn safe_github_remote_url(value: &str) -> bool {
    safe_github_https_remote_url(value) || safe_github_ssh_remote_url(value)
}

/// `url.<base>.insteadOf` rules that only exchange one GitHub spelling for
/// another: HTTPS for `git@github.com:` and the reverse. The rewritten
/// origin is judged afterwards as any other.
fn github_rewrite_pair(key: &str, entries: &[String]) -> bool {
    let Some(base) = key
        .strip_prefix("url.")
        .and_then(|rest| rest.strip_suffix(".insteadof"))
    else {
        return false;
    };
    let prefixes: &[&str] = match base {
        "https://github.com/" => &["git@github.com:", "ssh://git@github.com/"],
        "git@github.com:" | "ssh://git@github.com/" => &["https://github.com/"],
        _ => return false,
    };
    !entries.is_empty() && entries.iter().all(|value| prefixes.contains(&value.trim()))
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

/// Whether `origin` is the only remote the repository can reach: no key in
/// another remote's subsection, and no `branch.<name>.remote` naming anything
/// else. A refresh that names no remote resolves one through
/// `branch.<current>.remote`, and `--all` walks every configured remote, so
/// both reach only `origin` when this holds. A `branch.<name>.remote` that is
/// not a configured remote name is a URL Git fetches directly, which the
/// origin URL proof does not cover either way.
///
/// Any `remote.<name>.<variable>` key builds a remote, not just `.url`: a
/// remote with no URL falls back to its own name as a local path, and one
/// with `uploadpack` or `vcs` names a program `--all` would run. A key with
/// no subsection, such as `remote.pushdefault`, configures no remote.
pub(super) fn only_origin_remote(effective: &GitConfig) -> bool {
    effective.iter().all(|(key, values)| {
        if let Some(name) = key
            .strip_prefix("remote.")
            .and_then(|rest| rest.rsplit_once('.'))
            .map(|(name, _)| name)
        {
            return name == "origin";
        }
        if key.starts_with("branch.") && key.ends_with(".remote") {
            return values.iter().all(|value| value.trim() == "origin");
        }
        true
    })
}

/// Remotes can also be files under `remotes/` or `branches/` in the common
/// directory, which the configuration listing never shows. A directory this
/// cannot read counts as holding one.
pub(super) fn legacy_remotes_absent(common_dir: &std::path::Path) -> Option<bool> {
    for directory in ["remotes", "branches"] {
        match std::fs::read_dir(common_dir.join(directory)) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return Some(false);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    Some(true)
}
