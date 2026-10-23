//! Shell settings that change how a command prints, not what it runs.
//!
//! Agents routinely pin a locale or turn colour off before a search, as
//! `export LC_ALL=C; rg ...` or `LC_ALL=C rg ...`, and open a script with
//! `set -e`. None of that redirects an executable, a loader, a pager program
//! or a configuration file, yet an unproven leading step made the whole
//! chain ask for review. These screens prove that narrow shape and leave
//! every variable that can redirect execution — `PATH`, the loader family,
//! `GIT_*` routing, askpass and proxy settings — unproven as before.

use crate::CommandSegmentV1;

/// Variables whose whole effect is collation, formatting or colour.
const PRESENTATION_NAMES: &[&str] = &[
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "COLUMNS",
    "FORCE_COLOR",
    "LANG",
    "LANGUAGE",
    "LINES",
    "NO_COLOR",
];

/// Pager variables, which name a program and so are proven by value only.
const PAGER_NAMES: &[&str] = &["GIT_PAGER", "PAGER"];

/// The pagers that run no more than Git's own default. An empty value
/// disables paging outright.
const DEFAULT_EQUIVALENT_PAGERS: &[&str] = &["", "cat"];

/// Shell options that only change how the shell reacts to a failure or
/// echoes what it runs.
const SHELL_OPTIONS: &[&str] = &["errexit", "nounset", "pipefail", "xtrace"];

/// The longest assignment these screens read, so a pathological word cannot
/// turn a proof into a scan.
const VALUE_LIMIT: usize = 256;

/// Whether `name` names a presentation variable, including the `LC_*` family.
fn presentation_name(name: &str) -> bool {
    PRESENTATION_NAMES.contains(&name)
        || name
            .strip_prefix("LC_")
            .is_some_and(|rest| !rest.is_empty())
}

/// Whether `value` is a literal the shell passes through unchanged. A word
/// that expands could name anything at run time, so it stays unproven.
fn literal_value(value: &str) -> bool {
    value.len() <= VALUE_LIMIT
        && !value.contains(['$', '`', '\\', '\n', '\r'])
        && !value.chars().any(char::is_control)
}

/// Whether `NAME=VALUE` sets a variable that cannot redirect execution.
///
/// Presentation names and a default-equivalent pager are proven here. Every
/// other name goes through the shared settings screen, which keeps lookup,
/// loading, configuration, home, credential, trust-anchor and endpoint
/// families unproven, so `NODE_ENV=test`, `CI=1` and a project's own
/// `LOG_LEVEL=debug` read as the values they are.
pub(super) fn inert_assignment(token: &str) -> bool {
    let Some((name, value)) = token.split_once('=') else {
        return false;
    };
    literal_value(value)
        && (presentation_name(name)
            || (PAGER_NAMES.contains(&name) && DEFAULT_EQUIVALENT_PAGERS.contains(&value))
            || crate::command_compatibility::environment::ordinary_setting_name(name))
}

/// Whether `name` alone, with no value, is one of those variables.
fn inert_name(name: &str) -> bool {
    // A bare export or unset of a pager can expose an unsafe fallback
    // program (e.g. unset GIT_PAGER reveals PAGER=/tmp/pager.sh).
    presentation_name(name)
}

/// Whether a `NAME=VALUE ... command` prefix sets only inert variables.
///
/// The tokens are read rather than `environment_names` because the value is
/// what proves a pager, and a prefix that a wrapper or a `PATH` override
/// reaches is not this shape.
pub(super) fn inert_prefix(segment: &CommandSegmentV1) -> bool {
    if segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || guard_launcher(segment)
    {
        return false;
    }
    let Some(settings) = segment
        .tokens
        .len()
        .checked_sub(segment.arguments.len() + 1)
    else {
        return false;
    };
    settings == segment.environment_names.len()
        && segment
            .tokens
            .iter()
            .take(settings)
            .all(|token| inert_assignment(token))
}

/// Guard's own launchers prove their exact invocation, the environment they
/// run with included, so a prefix in front of one is never set aside. The
/// projection in `env_prefix_projection` keeps the same carve-out.
fn guard_launcher(segment: &CommandSegmentV1) -> bool {
    segment.executable.as_deref().is_some_and(|executable| {
        executable
            .rsplit(['/', '\\'])
            .next()
            .is_some_and(|name| name.to_ascii_lowercase().starts_with("hol-guard"))
    })
}

/// Whether `set` carries only shell options. A cluster that includes `o`,
/// as in `set -euo pipefail`, names the option in the next word. Bare `set`
/// prints every variable the shell holds, so it is not this shape.
fn safe_set_arguments(arguments: &[String]) -> bool {
    if arguments.is_empty() {
        return false;
    }
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        let Some(flags) = argument.strip_prefix(['-', '+']).filter(|flags| {
            !flags.is_empty() && flags.chars().all(|flag| flag.is_ascii_alphabetic())
        }) else {
            return false;
        };
        // `set -k` sends assignment-like arguments into subprocesses;
        // -a and other shell flags can change execution environment too.
        // Only the documented e/u/x flags and one trailing -o operand
        // are safe to compose in this read-only prelude.
        if !flags
            .chars()
            .all(|flag| matches!(flag, 'e' | 'u' | 'x' | 'o'))
        {
            return false;
        }
        if flags.contains('o') {
            if !flags.ends_with('o') || flags.bytes().filter(|flag| *flag == b'o').count() != 1 {
                return false;
            }
            let Some(name) = arguments.get(index) else {
                return false;
            };
            index += 1;
            if !SHELL_OPTIONS.contains(&name.as_str()) {
                return false;
            }
        }
    }
    true
}

/// Whether a shell setting built-in only changes presentation or shell
/// options. `export` and `unset` are limited to the inert variables so a
/// later step cannot be re-routed, and neither reads or writes a file.
pub(super) fn safe_shell_setting(basename: &str, segment: &CommandSegmentV1) -> bool {
    if !segment.wrapper_chain.is_empty() || !segment.environment_names.is_empty() {
        return false;
    }
    match basename {
        "export" => {
            !segment.arguments.is_empty()
                && segment.arguments.iter().all(|argument| {
                    if argument.contains('=') {
                        inert_assignment(argument)
                    } else {
                        inert_name(argument)
                    }
                })
        }
        "unset" => {
            !segment.arguments.is_empty()
                && segment
                    .arguments
                    .iter()
                    .all(|argument| inert_name(argument))
        }
        "set" => safe_set_arguments(&segment.arguments),
        _ => false,
    }
}

#[cfg(test)]
#[path = "inert_environment_tests.rs"]
mod tests;
