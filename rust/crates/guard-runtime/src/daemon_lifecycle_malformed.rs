//! `_malformed_command_may_launch_guard`: whether a command line the shell
//! grammar rejects could still be a Guard daemon launch. A `true` answer makes
//! the process inventory unknown rather than proven.

use crate::daemon_lifecycle_facts::{FROZEN_DAEMON_SERVE_ARG, LAUNCHER_NAMES};
use crate::daemon_lifecycle_text::{ntpath_basename, py_isspace, py_lstrip};

fn is_space_or_end(rest: &str) -> bool {
    rest.chars().next().is_none_or(py_isspace)
}

/// Byte offsets where `(?:^|\s)` can end: the start and after each space.
fn boundaries(text: &str) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(
        text.char_indices()
            .filter(|(_, character)| py_isspace(*character))
            .map(|(index, character)| index + character.len_utf8()),
    )
}

fn after_spaces(text: &str) -> Option<&str> {
    let rest = text.trim_start_matches(py_isspace);
    (rest.len() < text.len()).then_some(rest)
}

/// `daemon\s+--serve(?:\s|$)` at the start of `rest`.
fn serve_tail(rest: &str) -> bool {
    rest.strip_prefix("daemon")
        .and_then(after_spaces)
        .and_then(|tail| tail.strip_prefix("--serve"))
        .is_some_and(is_space_or_end)
}

/// `(?:^|\s)(?:guard\s+)?daemon\s+--serve(?:\s|$)` anywhere in `lowered`.
fn has_daemon_invocation(lowered: &str) -> bool {
    boundaries(lowered).any(|start| {
        let rest = &lowered[start..];
        serve_tail(rest)
            || rest
                .strip_prefix("guard")
                .and_then(after_spaces)
                .is_some_and(serve_tail)
    })
}

/// `(?:^|\s)-m\s+codex_plugin_scanner\.cli(?:\s|$)` anywhere in `lowered`.
fn has_module_flag(lowered: &str) -> bool {
    boundaries(lowered).any(|start| {
        lowered[start..]
            .strip_prefix("-m")
            .and_then(after_spaces)
            .and_then(|tail| tail.strip_prefix("codex_plugin_scanner.cli"))
            .is_some_and(is_space_or_end)
    })
}

/// `(?:^|\s)(?:hol-guard|plugin-guard)(?:\.exe)?(?:\s|$)` anywhere in `lowered`.
fn has_bare_launcher(lowered: &str) -> bool {
    boundaries(lowered).any(|start| {
        let rest = &lowered[start..];
        ["hol-guard", "plugin-guard"].iter().any(|name| {
            rest.strip_prefix(name).is_some_and(|tail| {
                is_space_or_end(tail) || tail.strip_prefix(".exe").is_some_and(is_space_or_end)
            })
        })
    })
}

/// `(?:^|[\\/\s])<name>(?:$|[\\/\s"'])` for any launcher name.
fn has_path_launcher(lowered: &str) -> bool {
    LAUNCHER_NAMES.iter().any(|name| {
        lowered.match_indices(name).any(|(index, _)| {
            let before = lowered[..index].chars().next_back();
            let after = lowered[index + name.len()..].chars().next();
            before.is_none_or(|c| matches!(c, '\\' | '/') || py_isspace(c))
                && after.is_none_or(|c| matches!(c, '\\' | '/' | '"' | '\'') || py_isspace(c))
        })
    })
}

pub(crate) fn may_launch_guard(command_line: &str) -> bool {
    let trimmed = py_lstrip(command_line);
    let Some(first) = trimmed.chars().next() else {
        return false;
    };
    let first_token = if first == '"' || first == '\'' {
        match trimmed[1..].find(first) {
            Some(offset) if offset > 0 => &trimmed[1..1 + offset],
            _ => {
                let lowered = trimmed.to_lowercase();
                let launcher_present = has_path_launcher(&lowered);
                if lowered.contains(FROZEN_DAEMON_SERVE_ARG) {
                    return launcher_present;
                }
                return has_daemon_invocation(&lowered) && launcher_present;
            }
        }
    } else {
        trimmed.split(py_isspace).next().unwrap_or("")
    };
    let launcher = ntpath_basename(first_token).to_lowercase();
    let lowered = command_line.to_lowercase();
    let is_named_launcher = LAUNCHER_NAMES.contains(&launcher.as_str());
    if lowered.contains(FROZEN_DAEMON_SERVE_ARG) {
        return is_named_launcher;
    }
    if !has_daemon_invocation(&lowered) {
        return false;
    }
    if launcher.starts_with("python") {
        let module_launch = lowered.contains("runpy.run_module") || has_module_flag(&lowered);
        return lowered.contains("codex_plugin_scanner.cli") && module_launch;
    }
    if matches!(launcher.as_str(), "env" | "uv" | "uv.exe") {
        return has_bare_launcher(&lowered);
    }
    is_named_launcher
}
