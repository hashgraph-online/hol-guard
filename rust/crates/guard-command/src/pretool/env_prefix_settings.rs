//! Which environment settings the projection removes outright, which it
//! removes only on the reviewed path, and which a one-time approval may bind
//! by its spelling.

use super::leading::{assignment_name_shape, code_loading_name};
use super::{
    CREDENTIAL_MARKERS, MAX_SCALAR_CHARS, MAX_SETTING_CHARS, PRESENTATION_NAMES, QUIETING_SETTINGS,
    UNREVIEWABLE_NAMES, UNREVIEWABLE_PREFIXES,
};
use crate::pretool::PathContext;

pub(super) fn inert_assignment(name: &str, value: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if QUIETING_SETTINGS
        .iter()
        .any(|(known, quiet)| upper == *known && value == *quiet)
    {
        return true;
    }
    // The same `NODE_OPTIONS` the runtime already treats as inert when a
    // developer's shell exports it: only flags that size the engine or change
    // what it prints. Written in front of the command it is the same setting,
    // so reading it differently would block `NODE_OPTIONS=--max-old-space-size=4096 npm test`
    // while the identical inherited value passes. A preload, a loader or an
    // inspector is not inert, and those keep failing closed below.
    if upper == "NODE_OPTIONS" && guard_contracts::node_options_inert(value) {
        return true;
    }
    // Clearing a credential only removes authority from the command.
    if value.is_empty()
        && CREDENTIAL_MARKERS
            .iter()
            .any(|marker| upper.contains(marker))
    {
        return true;
    }
    if (upper.starts_with("LC_") || PRESENTATION_NAMES.contains(&upper.as_str()))
        && plain_scalar(value)
    {
        return true;
    }
    // Any program may read any other name, so other settings are reviewed
    // through the projection instead of passing as inert.
    false
}

/// An ordinary project setting carries a value the command reads for itself.
/// The shared screen keeps every family that can redirect what runs — lookup,
/// loading, configuration, a home, a credential, the trust anchor and the
/// endpoint — out of this branch, and a plain scalar cannot spell a path or
/// an option for the program to act on. A reviewed projection still names
/// such a setting, so this widening belongs to the proof side alone.
///
/// A build or test setting whose name says "options" or "flags" while the
/// value only chooses how the run reports or how often it repeats belongs
/// here rather than with the inert settings. The name alone cannot tell
/// `GOFLAGS=-count=1` from `GOFLAGS=-toolexec=./x`, so that module reads the
/// value against a closed list; but `-count=1` is still a value `go` reads,
/// and a contained run of the projected command would repeat a cached test
/// the caller asked to rerun. Keeping it on the proof side leaves the
/// value screen in `env_prefix_values` free to say so.
pub(super) fn ordinary_project_setting(name: &str, value: &str) -> bool {
    inert_tool_setting(name, value)
        || plain_project_value(value)
            && crate::command_compatibility::environment::ordinary_setting_name(name)
}

/// [`crate::pretool::generic::inert_tool_settings::inert_tool_setting`], reachable
/// from the `reviewed` child module beside this one.
pub(super) fn inert_tool_setting(name: &str, value: &str) -> bool {
    crate::pretool::generic::inert_tool_settings::inert_tool_setting(name, value)
}

fn plain_scalar(value: &str) -> bool {
    value.len() <= MAX_SCALAR_CHARS
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:+,-".contains(character))
}

/// [`plain_scalar`] widened by the pathname and brace characters a shell
/// leaves alone in an assignment's value, for a setting whose name is already
/// an ordinary one. `DEBUG=app:*` names a debug namespace the program itself
/// matches, and `npm_config_*`, credential, endpoint and code-loading names
/// never reach here, so the characters add no reach. The approval binding in
/// [`bindable_setting`] keeps the narrower set: a bound retry must run the
/// text that was reviewed.
fn plain_project_value(value: &str) -> bool {
    value.len() <= MAX_SCALAR_CHARS
        && !value.starts_with('-')
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || "._:+,-*?[]{}".contains(character)
        })
}

/// Unsetting removes context; only names whose absence changes which config
/// or executables a tool loads stay unproven.
/// Commit identity a caller may clear so Git falls back to its configured
/// author and committer; clearing one changes no program, path or config.
const GIT_IDENTITY_SETTINGS: &[&str] = &[
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_DATE",
];

pub(super) fn inert_unset(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if GIT_IDENTITY_SETTINGS.contains(&upper.as_str()) {
        return true;
    }
    assignment_name_shape(name)
        && !matches!(upper.as_str(), "PATH" | "HOME")
        && ![
            "XDG_", "GIT_", "GUARD_", "HOL_", "CLAUDE", "CODEX_", "ZCODE",
        ]
        .iter()
        .any(|prefix| upper.starts_with(prefix))
}

/// A setting that may change behavior but leaves the program, its loader and
/// its credentials alone, so a human can review the command it prefixes.
pub(super) fn reviewable_assignment(name: &str, value: &str, context: PathContext<'_>) -> bool {
    // `GOFLAGS`, `RUSTFLAGS` and `PYTEST_ADDOPTS` are spelled like loader
    // settings, so the name test below refuses them outright and the command
    // keeps no reviewable form at all. Their values are read against a closed
    // list first, and one that passes it only chooses how the run reports,
    // how often it repeats or which lint it refuses -- nothing a reviewer
    // could not read off the command as written.
    if inert_tool_setting(name, value) {
        return true;
    }
    let upper = name.to_ascii_uppercase();
    if upper == "NODE_PATH" {
        return trusted_node_path(value, context);
    }
    name.len() <= MAX_SETTING_CHARS
        && !UNREVIEWABLE_NAMES.contains(&upper.as_str())
        && !UNREVIEWABLE_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
        && !upper.ends_with("PROXY")
        && !CREDENTIAL_MARKERS
            .iter()
            .any(|marker| upper.contains(marker))
        && !code_loading_name(&upper)
}

/// Whether `NAME=value` is a setting a one-time approval may bind by its
/// spelling: a reviewable name (the same test as above) with a short plain
/// value. A search path, a file or any text a program could parse as a
/// program stays outside, so the approved retry runs what was reviewed.
pub fn bindable_setting(name: &str, value: &str) -> bool {
    assignment_name_shape(name)
        && !name.eq_ignore_ascii_case("NODE_PATH")
        && reviewable_assignment(name, value, PathContext::default())
        && plain_scalar(value)
}

/// `NODE_PATH` as one canonical, existing `node_modules` directory inside the
/// working directory or home, with no hidden component, symlink or list
/// separator. Module lookup then falls back to a dependency tree the project
/// already trusts. The command still never settles below review.
fn trusted_node_path(value: &str, context: PathContext<'_>) -> bool {
    use std::path::{Component, Path};
    let path = Path::new(value);
    if value.len() > 1024
        || !path.is_absolute()
        || value.contains([':', ';', '\\'])
        || path.file_name().is_none_or(|name| name != "node_modules")
        || path.components().any(|component| match component {
            Component::Normal(name) => name.to_string_lossy().starts_with('.'),
            Component::RootDir | Component::Prefix(_) => false,
            _ => true,
        })
    {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    if canonical != path || !canonical.is_dir() {
        return false;
    }
    let inside = |root: Option<&str>| {
        root.and_then(|root| std::fs::canonicalize(root).ok())
            .is_some_and(|root| canonical.starts_with(root))
    };
    (inside(context.cwd) || inside(context.home_dir))
        && guard_secure_fs::sensitive_path_family(&canonical).is_none()
        && !guard_secure_fs::credential_named_path(&canonical)
}
