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
    // A time zone named the way the zone database spells it, such as
    // `America/Los_Angeles` or `Etc/GMT+5`, only chooses which rules the C
    // library reads to format a date. The slash keeps it out of the plain
    // scalar above, so it is read here on its own terms. A value led by `:`
    // or `/` names a file, and dots could climb out of the zone directory;
    // neither is admitted.
    if upper == "TZ" && zone_name(value) {
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
pub(super) fn ordinary_project_setting(
    name: &str,
    value: &str,
    context: PathContext<'_>,
    first_command: bool,
) -> bool {
    inert_tool_setting(name, value)
        || (plain_project_value(value) || workspace_path_value(value, context, first_command))
            && (crate::command_compatibility::environment::ordinary_setting_name(name)
                || crate::command_compatibility::data_file_setting::data_file_path_setting(
                    name, value,
                ))
}

/// A value that spells a location inside the working directory, written in
/// the characters [`plain_project_value`] already admits plus the separator
/// that keeps it out of them.
///
/// The name screens above have already removed every family a program reads
/// as a path of its own: program lookup, code loading, configuration, a home,
/// a credential, the trust anchor and the endpoint. What is left is a name
/// whose value the command reads for itself, and the separator alone said
/// nothing about whether reading it reaches past the command's own work. It
/// reaches nothing new while every file the value can name sits in the
/// directory the command already runs in, which is what this screen checks:
/// an absolute value only under the working directory, a relative one only
/// while no component climbs out of it. A credential directory is refused
/// wherever it sits, because a setting may name one inside a workspace too;
/// the screen reads the location the value resolves to rather than the value
/// as written, so `DATA_DIR=.aws/credentials` is refused for the same reason
/// `DATA_DIR=/work/site/.aws/credentials` is.
///
/// A relative value names a location only once the directory it is read from
/// is known. The caller's working directory is the one the command line
/// started in, so it answers for the first simple command alone: after
/// `cd /etc &&` the shell has moved, and `ssl/private` no longer names
/// anything inside the workspace. `first_command` carries that, and a
/// relative value is read only while it holds. An absolute value needs no
/// such care, because it names the same location wherever it is read.
fn workspace_path_value(value: &str, context: PathContext<'_>, first_command: bool) -> bool {
    if value.len() > MAX_SCALAR_CHARS
        || value.starts_with('-')
        || !value.contains('/')
        || !value.chars().all(|character| {
            character == '/' || character.is_ascii_alphanumeric() || "._-".contains(character)
        })
        // A leading separator other than `/` is the program's own notation,
        // not a path component: `TZ=:/zoneinfo/UTC` names a file through a
        // colon the screens above never read.
        || !value
            .chars()
            .next()
            .is_some_and(|first| first == '/' || first == '.' || first == '_' || first.is_ascii_alphanumeric())
    {
        return false;
    }
    // Without a working directory there is nothing to measure the value
    // against, so a literal or offline context reads no path value here.
    let Some(workspace) = context.cwd.and_then(workspace_root) else {
        return false;
    };
    let workspace = workspace.as_str();
    let relative = if value.starts_with('/') {
        let Some(rest) = value.strip_prefix(workspace) else {
            return false;
        };
        // `/work/site` is not a path under `/work/sit`; only a separator or
        // the end of the value says the prefix was a whole component.
        match rest.strip_prefix('/') {
            Some(rest) => rest,
            None if rest.is_empty() => rest,
            None => return false,
        }
    } else {
        value
    };
    if !(value.starts_with('/') || first_command) {
        return false;
    }
    if !(relative.is_empty()
        || relative
            .split('/')
            .all(|component| !component.is_empty() && component != ".."))
    {
        return false;
    }
    let resolved = if relative.is_empty() {
        workspace.to_owned()
    } else {
        format!("{workspace}/{relative}")
    };
    // `sensitive_location_text` looks for a credential's spelling inside the
    // text, so it reads `vendor/.ssh/id_rsa` but not a value that stops at
    // the store itself (`vendor/.ssh`, `vendor/.gnupg`) or names a key by a
    // spelling its needles do not carry (`vendor/id_ecdsa`). A setting hands
    // the program a location to read, so the resolved value faces the same
    // screen a read argument does, which answers for the store and for the
    // key file's own name.
    !crate::pretool::sensitive_location_text(&resolved)
        && !crate::pretool::sensitive_read_path_argument(&resolved)
}

/// The working directory as an absolute location [`workspace_path_value`]
/// can measure a value against: a Unix path below `/`, or a Windows drive
/// path below its drive root (`C:\work\site`, as a Windows harness reports
/// it), spelled with `/` so the value joins it the same way.
///
/// A drive root, a drive-relative spelling (`C:work`), a UNC or device path
/// (`\\server\share`, `\\?\C:\work`) and a name carrying a stream
/// (`C:\work:data`) name no single folder the command is known to run in.
fn workspace_root(cwd: &str) -> Option<String> {
    if cwd.starts_with('/') {
        let trimmed = cwd.trim_end_matches('/');
        return (trimmed.len() > 1).then(|| trimmed.to_owned());
    }
    let bytes = cwd.as_bytes();
    if !(bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/'))
        || cwd[2..].contains(':')
    {
        return None;
    }
    let unified = cwd.replace('\\', "/");
    let trimmed = unified.trim_end_matches('/');
    (trimmed.len() > 3 && !trimmed[2..].contains("//")).then(|| trimmed.to_owned())
}

/// [`crate::pretool::generic::inert_tool_settings::inert_tool_setting`], reachable
/// from the `reviewed` child module beside this one.
pub(super) fn inert_tool_setting(name: &str, value: &str) -> bool {
    crate::pretool::generic::inert_tool_settings::inert_tool_setting(name, value)
}

/// A zone database name: non-empty segments of letters, digits, `_`, `+` and
/// `-`, joined by single slashes, with no segment opening on `-`.
fn zone_name(value: &str) -> bool {
    value.len() <= MAX_SCALAR_CHARS
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && !segment.starts_with('-')
                && segment
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "_+-".contains(character))
        })
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
