//! The caller settings a restricted launch forwards into the run.
//!
//! The restricted launchers filter the caller's environment down to this set,
//! and the pre-tool review of an environment prefix reads the same set to tell
//! a setting the run would have received anyway from one it would not. Both
//! read it from here so neither layer owns the other's copy.

pub(crate) const SAFE_ENV_KEYS: &[&str] = &[
    "CI",
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "COLORTERM",
    "COLUMNS",
    "FORCE_COLOR",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "LANG",
    "LANGUAGE",
    "LINES",
    "LOGNAME",
    "NO_COLOR",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "PYTHONIOENCODING",
    "PYTHONUNBUFFERED",
    "PYTHONUTF8",
    "SOURCE_DATE_EPOCH",
    "TERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "TF_BUILD",
    "TZ",
    "USER",
    "VIRTUAL_ENV_PROMPT",
];

/// The version a manager's shims dispatch to, named by its own setting.
/// `~/.pyenv/shims/python` and its kind pick an interpreter from the version
/// named here before any file; dropping the setting runs a different version
/// inside the sandbox than the caller asked for outside it. Only the managers
/// whose installs a run may be granted, and only the name of a version: the
/// settings that move a manager's root instead name a directory and stay out.
const VERSION_SELECTORS: &[&str] = &[
    "GOENV_VERSION",
    "JENV_VERSION",
    "NODENV_VERSION",
    "PYENV_VERSION",
    "RBENV_VERSION",
    "TFENV_VERSION",
];

/// Whether `key` names a version for a manager's shims to resolve.
pub(crate) fn version_selector(key: &str) -> bool {
    VERSION_SELECTORS.contains(&key)
        || (key.starts_with("ASDF_") && key.ends_with("_VERSION") && key.len() > 13)
}

/// Whether a restricted launch passes the caller's setting `key` to the run;
/// it drops every other name.
pub(crate) fn forwarded_setting(key: &str) -> bool {
    matches!(key, "PYTHONPATH" | "VIRTUAL_ENV")
        || SAFE_ENV_KEYS.contains(&key)
        || version_selector(key)
        || key.starts_with("LC_")
}
