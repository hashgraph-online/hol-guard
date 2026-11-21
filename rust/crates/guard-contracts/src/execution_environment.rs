//! Caller-declared lookup context shared by hook and command entry points.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_EXECUTION_ENVIRONMENT_PATH_BYTES: usize = 32 * 1024;
pub const MAX_EXECUTION_ENVIRONMENT_NAMES: usize = 512;
pub const MAX_EXECUTION_ENVIRONMENT_NAME_BYTES: usize = 256;
pub const EXECUTION_ENVIRONMENT_DIGEST_HEX_BYTES: usize = 64;
/// Dynamic-loader search paths whose values the hook stamps so a receiver can
/// check each directory. Injection variables such as `LD_PRELOAD` are never
/// stamped; a receiver treats them by name only.
pub const LIBRARY_SEARCH_PATH_NAMES: &[&str] = &[
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
];
/// `NODE_OPTIONS` flags that take no value and change only what the engine
/// prints or which of its own APIs it exposes. None of them loads code, reads
/// a file or opens a port.
///
/// `--experimental-vm-modules` is here because it unlocks `node:vm`'s module
/// classes for the program to call, the way an ESM Jest run needs; it compiles
/// nothing by itself, and a program that wanted to evaluate a string could
/// already do so without it.
const INERT_NODE_FLAGS: &[&str] = &[
    "no-warnings",
    "no-deprecation",
    "enable-source-maps",
    "experimental-vm-modules",
    "trace-warnings",
    "trace-deprecation",
    "trace-uncaught",
];
/// `NODE_OPTIONS` flags that take a plain number and only size the engine.
const INERT_NODE_SIZES: &[&str] = &[
    "max-old-space-size",
    "max-semi-space-size",
    "stack-trace-limit",
];

/// Whether `value`, a `NODE_OPTIONS` value, holds only flags that size the
/// heap, change diagnostics or expose an engine API, such as
/// `--max-old-space-size=8192`. A preload (`--require`, `--import`), a
/// loader, an inspector or anything else is not inert, and neither is an
/// empty value, quoting or a flag Node would read from a file.
pub fn node_options_inert(value: &str) -> bool {
    let mut tokens = value
        .split(' ')
        .filter(|token| !token.is_empty())
        .peekable();
    tokens.peek().is_some()
        && tokens.all(|token| {
            let Some(option) = token.strip_prefix("--") else {
                return false;
            };
            let option = option.replace('_', "-");
            match option.split_once('=') {
                Some((name, size)) => {
                    INERT_NODE_SIZES.contains(&name)
                        && !size.is_empty()
                        && size.bytes().all(|byte| byte.is_ascii_digit())
                }
                None => INERT_NODE_FLAGS.contains(&option.as_str()),
            }
        })
}

/// Whether `cargo_home`, a `CARGO_HOME` value, names the directory Cargo
/// would read anyway: `<home>/.cargo`. Cargo merges the configuration file in
/// `CARGO_HOME` with the ones above the working directory, so a value that
/// moves the file hides the settings a reading proof checks -- but the default
/// spelling moves nothing. Continuous-integration images and devcontainers
/// export it at its own default, and refusing that spelling would take the
/// reading away on hosts whose configuration is exactly where it always was.
///
/// Only an absolute value matching the default counts. A relative value is
/// resolved against a working directory this function does not know, and any
/// other directory is a move.
pub fn cargo_home_default(home: Option<&str>, cargo_home: Option<&str>) -> bool {
    let Some(cargo_home) = cargo_home.filter(|value| !value.is_empty()) else {
        return false;
    };
    let Some(home) = home.filter(|value| !value.is_empty()) else {
        return false;
    };
    let trimmed = |value: &str| value.trim_end_matches('/').to_owned();
    let home = trimmed(home);
    !home.is_empty() && trimmed(cargo_home) == format!("{home}/.cargo")
}

/// Configuration keys an editor's Git integration hands every child process
/// through `GIT_CONFIG_COUNT` that change only how Git prints paths. None of
/// them names a program, a hook, a file Git reads or a place it writes. Cursor
/// and VS Code export `core.quotePath=false` in every terminal they open.
pub const INERT_GIT_CONFIG_ENVIRONMENT_KEYS: &[&str] = &["core.quotepath"];

/// More entries than this are not judged; no editor exports that many.
pub const MAX_INERT_GIT_CONFIG_ENVIRONMENT_ENTRIES: usize = 8;

/// Whether the `GIT_CONFIG_COUNT` entries `lookup` sees only set keys in
/// [`INERT_GIT_CONFIG_ENVIRONMENT_KEYS`]. Git reads `GIT_CONFIG_KEY_<n>` and
/// `GIT_CONFIG_VALUE_<n>` for every `n` below the count and ignores the rest.
///
/// The count must be plain decimal digits: Git also accepts unit suffixes such
/// as `1k`, which would read entries this never looked at. A missing key makes
/// Git refuse to start, but it is still not judged inert. Values are not
/// checked: a value Git cannot parse as a boolean stops Git before it reads
/// anything.
pub fn git_config_environment_inert<'a>(lookup: impl Fn(&str) -> Option<&'a str>) -> bool {
    let Some(count) = lookup("GIT_CONFIG_COUNT") else {
        return false;
    };
    if count.is_empty() || count.len() > 2 || !count.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Ok(count) = count.parse::<usize>() else {
        return false;
    };
    if count > MAX_INERT_GIT_CONFIG_ENVIRONMENT_ENTRIES {
        return false;
    }
    (0..count).all(|index| {
        lookup(&format!("GIT_CONFIG_KEY_{index}")).is_some_and(|key| {
            INERT_GIT_CONFIG_ENVIRONMENT_KEYS.contains(&key.to_ascii_lowercase().as_str())
        }) && lookup(&format!("GIT_CONFIG_VALUE_{index}")).is_some()
    })
}

/// Whether `name` is one of the variables Git reads for `GIT_CONFIG_COUNT`:
/// the count itself, `GIT_CONFIG_KEY_<n>` or `GIT_CONFIG_VALUE_<n>`.
pub fn git_config_count_entry(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    name == "GIT_CONFIG_COUNT"
        || ["GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"]
            .iter()
            .any(|prefix| {
                name.strip_prefix(prefix).is_some_and(|index| {
                    !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardExecutionEnvironmentV1 {
    pub path: String,
    pub environment_names: Vec<String>,
    /// Opaque sender commitment for request identity, not verified integrity.
    /// Withheld values cannot be recomputed by the receiver; this is not a MAC.
    pub environment_digest: String,
    #[serde(default)]
    pub home: Option<String>,
    #[serde(default)]
    pub git_pager_disabled: bool,
    #[serde(default)]
    pub pager_disabled: bool,
    #[serde(default)]
    pub xdg_config_home: Option<String>,
    #[serde(default)]
    pub git_config_no_system: bool,
    /// Values of the exported variables in [`LIBRARY_SEARCH_PATH_NAMES`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub library_search_paths: BTreeMap<String, String>,
    /// The hook saw an exported `NODE_OPTIONS` that [`node_options_inert`]
    /// accepts. The value itself is never stamped.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub node_options_inert: bool,
    /// The hook saw an exported `CARGO_HOME` that [`cargo_home_default`]
    /// accepts. The value itself is never stamped.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cargo_home_default: bool,
    /// The hook saw `GIT_CONFIG_COUNT` entries that
    /// [`git_config_environment_inert`] accepts. The values are never stamped.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub git_config_environment_inert: bool,
}

impl GuardExecutionEnvironmentV1 {
    /// Validate the bounds needed for Git lookup admission, not sender integrity.
    /// Other hooks remain subject to the independent whole-envelope limits.
    pub fn has_valid_shape(&self) -> bool {
        let path_valid =
            |path: &str| path.len() <= MAX_EXECUTION_ENVIRONMENT_PATH_BYTES && !path.contains('\0');
        path_valid(&self.path)
            && self.home.as_deref().is_none_or(path_valid)
            && self.xdg_config_home.as_deref().is_none_or(path_valid)
            && self.library_search_paths.iter().all(|(name, value)| {
                LIBRARY_SEARCH_PATH_NAMES.contains(&name.as_str()) && path_valid(value)
            })
            && self.environment_names.len() <= MAX_EXECUTION_ENVIRONMENT_NAMES
            && self.environment_names.iter().all(|name| {
                name.len() <= MAX_EXECUTION_ENVIRONMENT_NAME_BYTES
                    && !name.chars().any(char::is_control)
            })
            && self.environment_digest.len() == EXECUTION_ENVIRONMENT_DIGEST_HEX_BYTES
            && self
                .environment_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    pub fn unavailable() -> Self {
        Self {
            path: String::new(),
            environment_names: Vec::new(),
            environment_digest: String::new(),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
            library_search_paths: BTreeMap::new(),
            node_options_inert: false,
            cargo_home_default: false,
            git_config_environment_inert: false,
        }
    }
}

#[cfg(test)]
#[path = "execution_environment_tests.rs"]
mod tests;
