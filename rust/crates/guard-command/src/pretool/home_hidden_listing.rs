//! Name-only listing of a hidden directory in the home directory
//! (`ls ~/.config/`, `ls ~/.agents/skills/`, `find ~/.config -maxdepth 1`).
//!
//! A listing prints entry names and metadata, never file content, so a
//! dot-directory that stores no credentials, and its visible subdirectories,
//! are as safe to list as the home directory itself. `~/.codex` and
//! `~/.claude` keep their logins in known files that content reads still
//! refuse, so their names list too. Credential, key, wallet, browser-profile,
//! other agent-login and Guard state stores keep their review at any depth, and so do the stores that live below `~/.config` and
//! `~/.local/share` (`~/.config/gh`). Callers must bound the listing to the
//! directory's own entries: a recursive listing of `~/.config` prints the
//! names inside `~/.config/gh` and keeps its review.

use std::path::{Component, Path, PathBuf};

/// Hidden directories that hold credentials, keys, wallets, browser profiles
/// or Guard's own state. Their entry names alone reveal which accounts, hosts
/// and keys exist.
pub(super) const CREDENTIAL_STORE_NAMES: [&str; 18] = [
    ".aws",
    ".azure",
    ".bitcoin",
    ".docker",
    ".electrum",
    ".ethereum",
    ".gcloud",
    ".gnupg",
    ".hol-guard",
    ".kube",
    ".mozilla",
    ".password-store",
    ".pki",
    ".ssh",
    ".terraform",
    ".terraform.d",
    ".thunderbird",
    ".vault-token",
];

/// Harness directories that share skills, rules or Git hooks rather than an
/// agent login. Every other harness directory (`~/.gemini`, `~/.omp`,
/// `~/.copilot`) may hold login tokens under names Guard does not know, so it
/// keeps review.
const HARNESS_SHARED_NAMES: [&str; 5] = [".agent", ".agents", ".clinerules", ".githooks", ".husky"];

/// Harness homes whose login and secret-bearing config live in files the
/// credential and hidden-name screens already refuse to read
/// (`auth.json`, `.credentials.json`, `config.toml`, `settings.json`).
/// Listing them prints plan, memory and session names, never a secret.
pub(super) const HARNESS_HOME_NAMES: [&str; 2] = [".claude", ".codex"];

/// Credential, password-manager, keyring, browser-profile and agent-login
/// stores kept directly below `~/.config` or `~/.local/share`. A tool whose
/// directory holds only fixed-name config files (`~/.config/doctl/config.yaml`,
/// with its tokens inside the file) is not listed: its entry names reveal no
/// account, host or key, and content reads of the file stay guarded.
const NESTED_CREDENTIAL_STORE_NAMES: [&str; 16] = [
    "1password",
    "bravesoftware",
    "chromium",
    "gcloud",
    "gh",
    "github-copilot",
    "gnupg",
    "google-chrome",
    "gopass",
    "hub",
    "keyrings",
    "microsoft-edge",
    "op",
    "opencode",
    "password-store",
    "solana",
];

/// Whether `value` names an existing directory below a hidden component of
/// the home directory that is not, and is not inside, a credential store.
pub(in crate::pretool) fn home_hidden_directory(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains(|c: char| {
            // Windows spells the home path with `\`, so there it is a separator.
            (c == '\\' && !cfg!(windows))
                || [
                    '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{',
                    '}',
                ]
                .contains(&c)
        })
        || value.split(['/', '\\']).any(|part| part == "..")
        || !super::super::verified_path_context(home_dir, cwd)
    {
        return false;
    }
    let (Some(raw_home), Some(expanded)) = (home_dir, expanded(value, home_dir, cwd)) else {
        return false;
    };
    let Ok(home) = std::fs::canonicalize(raw_home) else {
        return false;
    };
    let Ok(canonical) = std::fs::canonicalize(&expanded) else {
        return false;
    };
    // The spelled path must be the resolved one: a link anywhere below the
    // home directory could dress another store, or the home directory
    // itself, as an ordinary dot-directory.
    let Some(relative) = expanded
        .strip_prefix(raw_home)
        .or_else(|_| expanded.strip_prefix(&home))
        .ok()
        .filter(|relative| home.join(relative) == canonical)
    else {
        return false;
    };
    let Some(first) = relative.components().next() else {
        return false;
    };
    // Only the home entry itself is hidden: a dot-directory nested deeper
    // (`~/.nvm/.cache`) is private state of the tool that owns it.
    let mut names = relative.components().skip(1);
    canonical.is_dir()
        && first.as_os_str().to_string_lossy().starts_with('.')
        && !names.any(|name| name.as_os_str().to_string_lossy().starts_with('.'))
        && clears_store_screen(relative)
        && super::super::resolved_location_allowed(&canonical, home_dir, cwd, false)
}

fn expanded(value: &str, home_dir: Option<&str>, cwd: Option<&str>) -> Option<PathBuf> {
    let path = if value == "~" || value.starts_with("~/") || value.starts_with("~\\") {
        PathBuf::from(super::super::expand_home_read_path(value, home_dir)?)
    } else if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        let cwd = cwd?;
        let root =
            super::super::expand_home_read_path(cwd, home_dir).unwrap_or_else(|| cwd.to_owned());
        Path::new(&root).join(value)
    };
    Some(path.components().collect())
}

/// No component below the home directory is a credential store, and no
/// store sits directly below `.config` or `.local/share` on the way.
fn clears_store_screen(path: &Path) -> bool {
    let names: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    !names.iter().enumerate().any(|(index, name)| {
        let parent = index.checked_sub(1).map(|at| names[at].as_str());
        let grandparent = index.checked_sub(2).map(|at| names[at].as_str());
        let config_child =
            parent == Some(".config") || (parent == Some("share") && grandparent == Some(".local"));
        CREDENTIAL_STORE_NAMES.contains(&name.as_str())
            || (harness_login_store(name) && !names[index + 1..].iter().any(|n| n == "plugins"))
            || name.starts_with(".env")
            || (config_child && NESTED_CREDENTIAL_STORE_NAMES.contains(&name.as_str()))
    })
}

/// A harness directory other than the shared skill and hook trees. Its
/// `plugins` subtree (`~/.zcode/cli/plugins/cache`) holds installed plugin
/// code rather than the login, so listings below it are screened like any
/// other dot-directory.
fn harness_login_store(name: &str) -> bool {
    crate::harness_config_names::HARNESS_DIRECTORIES.contains(&name)
        && !HARNESS_SHARED_NAMES.contains(&name)
        && !HARNESS_HOME_NAMES.contains(&name)
}
