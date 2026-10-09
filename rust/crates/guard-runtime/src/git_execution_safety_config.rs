//! Pure predicates over parsed Git configuration and Git arguments.
//!
//! Ported from `runtime/git_execution_safety.py`; keys are case-folded at
//! parse time and every predicate treats an unexpected shape as unsafe.

use std::collections::BTreeMap;

pub(crate) type GitConfig = BTreeMap<String, Vec<String>>;

const ROUTING_ENVIRONMENT: &[&str] = &[
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_NAMESPACE",
    "GIT_WORK_TREE",
];
const FETCH_ENVIRONMENT: &[&str] = &[
    "GIT_ASKPASS",
    "GIT_EXEC_PATH",
    "GIT_PROXY_COMMAND",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "GIT_SSL_CERT",
    "GIT_SSL_CIPHER_LIST",
    "GIT_SSL_KEY",
    "GIT_SSL_NO_VERIFY",
    "GIT_SSL_VERSION",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_ASKPASS",
];
const CHECKOUT_ENVIRONMENT: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_EXEC_PATH",
    "GIT_OBJECT_DIRECTORY",
];
const STATUS_FLAGS: &[&str] = &[
    "--ahead-behind",
    "--branch",
    "--ignored",
    "--long",
    "--no-ahead-behind",
    "--no-renames",
    "--porcelain",
    "--renames",
    "--short",
    "--show-stash",
    "--untracked-files",
    "-b",
    "-s",
    "-u",
    "-z",
];
const STATUS_VALUE_FLAGS: &[&str] = &[
    "--column",
    "--find-renames",
    "--ignored",
    "--porcelain",
    "--untracked-files",
];
const DISABLED: &[&str] = &["", "0", "false", "no", "off"];

pub(crate) type Environment = BTreeMap<String, String>;

fn any_set(environment: &Environment, names: &[&str], strip: bool) -> bool {
    names.iter().any(|name| {
        environment.get(*name).is_some_and(|value| {
            if strip {
                !value.trim().is_empty()
            } else {
                !value.is_empty()
            }
        })
    })
}

pub(crate) fn routing_environment_is_clean(environment: &Environment) -> bool {
    // Compared without stripping: a whitespace-only value still names a path
    // for Git, while probes run with these variables removed.
    !any_set(environment, ROUTING_ENVIRONMENT, false)
}

pub(crate) fn fetch_environment_is_set(environment: &Environment) -> bool {
    any_set(environment, FETCH_ENVIRONMENT, true)
}

pub(crate) fn checkout_environment_is_set(environment: &Environment) -> bool {
    any_set(environment, CHECKOUT_ENVIRONMENT, false)
}

pub(crate) fn status_arguments_are_read_only(arguments: &[String]) -> bool {
    if arguments
        .first()
        .is_none_or(|first| !first.eq_ignore_ascii_case("status"))
    {
        return false;
    }
    let mut after_terminator = false;
    for token in &arguments[1..] {
        if after_terminator {
            continue;
        }
        if token == "--" {
            after_terminator = true;
            continue;
        }
        let normalized = token.to_lowercase();
        if STATUS_FLAGS.contains(&normalized.as_str()) {
            continue;
        }
        if let Some((name, _)) = normalized.split_once('=') {
            if STATUS_VALUE_FLAGS.contains(&name) {
                continue;
            }
        }
        if normalized.starts_with('-')
            && normalized.chars().count() > 2
            && !normalized.starts_with("--")
            && normalized
                .chars()
                .skip(1)
                .all(|flag| STATUS_FLAGS.contains(&format!("-{flag}").as_str()))
        {
            continue;
        }
        return false;
    }
    true
}

/// Parse `git config --null` output: `key\nvalue\0` records, keys case-folded.
pub(crate) fn parse_null_config(output: &str) -> Option<GitConfig> {
    let mut parsed = GitConfig::new();
    for entry in output.split('\0') {
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('\n')?;
        if key.is_empty() {
            return None;
        }
        parsed
            .entry(key.to_lowercase())
            .or_default()
            .push(value.to_owned());
    }
    Some(parsed)
}

fn values<'a>(config: &'a GitConfig, key: &str) -> &'a [String] {
    config.get(key).map_or(&[], Vec::as_slice)
}

fn present(config: &GitConfig, key: &str) -> bool {
    config.contains_key(key)
}

fn enables_behavior(values: &[String]) -> bool {
    values
        .iter()
        .any(|value| !DISABLED.contains(&value.trim().to_lowercase().as_str()))
}

pub(crate) fn checkout_config_can_fetch(config: &GitConfig) -> bool {
    config.iter().any(|(key, values)| {
        ((key == "extensions.partialclone" || key.ends_with(".partialclonefilter"))
            && values.iter().any(|value| !value.is_empty()))
            || (key.ends_with(".promisor") && enables_behavior(values))
    })
}

pub(crate) fn fetch_config_routes_execution(config: &GitConfig) -> bool {
    if present(config, "remote.origin.uploadpack") {
        return true;
    }
    if ["core.askpass", "core.sshcommand"].iter().any(|key| {
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

pub(crate) fn push_config_routes_execution(config: &GitConfig, branch: &str) -> bool {
    if present(config, "core.gitproxy") {
        return true;
    }
    if config.keys().any(|key| {
        (key.starts_with("url.") && key.ends_with(".pushinsteadof")) || key.starts_with("hook.")
    }) {
        return true;
    }
    let branch_remote = format!("branch.{}.pushremote", branch.to_lowercase());
    if [
        "remote.origin.push",
        "remote.origin.pushurl",
        "remote.origin.receivepack",
        "remote.origin.vcs",
        "remote.pushdefault",
        branch_remote.as_str(),
    ]
    .iter()
    .any(|key| present(config, key))
    {
        return true;
    }
    if ["push.followtags", "push.gpgsign", "remote.origin.mirror"]
        .iter()
        .any(|key| enables_behavior(values(config, key)))
    {
        return true;
    }
    values(config, "push.recursesubmodules")
        .iter()
        .any(|value| {
            !["", "0", "false", "no", "off", "check"]
                .contains(&value.trim().to_lowercase().as_str())
        })
}

pub(crate) fn push_scoped_config_routes_transport(config: &GitConfig) -> bool {
    config.keys().any(|key| {
        key.starts_with("http.")
            || key.starts_with("credential.")
            || matches!(
                key.as_str(),
                "core.askpass"
                    | "core.gitproxy"
                    | "remote.origin.proxy"
                    | "remote.origin.proxyauthmethod"
            )
    })
}

pub(crate) fn push_effective_config_weakens_transport(config: &GitConfig) -> bool {
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

pub(crate) fn credential_helpers(config: &GitConfig) -> Vec<&str> {
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

/// `https://github.com/<owner>/<repo>[.git]` with no credentials, query or
/// fragment. Stricter than the Python `urlsplit` form: non-ASCII,
/// whitespace and zero-padded ports are rejected rather than normalized.
pub(crate) fn safe_github_https_remote_url(value: &str) -> bool {
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
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => return false,
    };
    if path.contains(['?', '#', '\\']) || authority.contains(['?', '#', '\\', '[', ']']) {
        return false;
    }
    // Userinfo is ignored like `urlsplit().hostname`; the last `@` ends it.
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match authority.rsplit_once(':') {
        Some((host, "443")) => host,
        Some(_) => return false,
        None => authority,
    };
    if !host.eq_ignore_ascii_case("github.com") {
        return false;
    }
    let segment_characters = |segment: &str| {
        segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    };
    let stripped = path.strip_suffix(".git").unwrap_or(path);
    let parts: Vec<&str> = stripped.split('/').collect();
    parts.len() == 3
        && parts[1..]
            .iter()
            .all(|part| !matches!(*part, "" | "." | ".."))
        && path[1..]
            .split('/')
            .all(|segment| !segment.is_empty() && segment_characters(segment))
        && path.matches('/').count() == 2
}

/// Whether `value` is a safe credential helper *shape*. Returns the helper
/// kind so the caller can verify the executable on disk.
pub(crate) enum HelperShape<'a> {
    /// `!<gh> auth git-credential` with a bare `gh` or an absolute path.
    GithubCli(&'a str),
    /// A bare helper name resolved under Git's exec path.
    Named(&'a str),
}

pub(crate) fn credential_helper_shape(value: &str) -> Option<HelperShape<'_>> {
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
