//! Naming the one leading setting a refusal reason echoes. The projection
//! removes a prefix it can prove inert, so a reason that named a removed
//! setting would send the agent after the wrong word; these readings name
//! only a setting that is still there.

use super::settings::inert_assignment;
use super::words::shell_assignment;
use super::{COMMAND_SEPARATORS, MAX_PROJECTED_CHARS, MAX_SETTING_CHARS};
use crate::cloud_scrub_shell::shell_tokens;

pub(super) fn code_loading_name(upper: &str) -> bool {
    crate::command_compatibility::code_or_redirect_environment_name(upper)
}

/// The first leading setting of any simple command that can load other code
/// and whose value this module does not read as inert, as a shape-checked
/// name a reason may echo. A setting the projection removes stopped nothing,
/// so naming it would send the agent after the wrong word.
pub(crate) fn code_loading_setting(command: &str) -> Option<String> {
    leading_setting(command, |name, value| {
        crate::command_compatibility::code_or_redirect_environment_name(&name.to_ascii_uppercase())
            && !inert_assignment(name, value)
    })
}

/// The first leading setting of any simple command named for a credential
/// (`API_KEY`, `GH_TOKEN`), as a shape-checked name a reason may echo.
pub(crate) fn credential_setting(command: &str) -> Option<String> {
    leading_setting(command, |name, _| {
        crate::command_compatibility::credential_routing_environment_name(
            &name.to_ascii_uppercase(),
        )
    })
}

fn leading_setting(command: &str, matches: impl Fn(&str, &str) -> bool) -> Option<String> {
    leading_assignment(command, matches).map(|(name, _)| name)
}

fn leading_assignment(
    command: &str,
    matches: impl Fn(&str, &str) -> bool,
) -> Option<(String, String)> {
    if command.len() > MAX_PROJECTED_CHARS {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let tokens = shell_tokens(&chars)?;
    let mut command_start = true;
    let mut in_prefix = false;
    for token in &tokens {
        if token.is_control {
            command_start = COMMAND_SEPARATORS.contains(&token.value.as_str());
            in_prefix = false;
            continue;
        }
        if command_start {
            command_start = false;
            in_prefix = true;
        }
        if !in_prefix {
            continue;
        }
        if token.value == "env" || token.value == "/usr/bin/env" {
            continue;
        }
        let Some((name, value)) = shell_assignment(chars.as_slice(), token) else {
            in_prefix = false;
            continue;
        };
        if name.len() <= MAX_SETTING_CHARS && assignment_name_shape(name) && matches(name, value) {
            return Some((name.to_owned(), value.to_owned()));
        }
    }
    None
}

/// The first leading setting of any simple command whose value carries a
/// command substitution, backtick or variable expansion, as a shape-checked
/// name a reason may echo.
pub(crate) fn substituted_setting(command: &str) -> Option<String> {
    if command.len() > MAX_PROJECTED_CHARS {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let tokens = shell_tokens(&chars)?;
    let mut command_start = true;
    let mut in_prefix = false;
    // Only a setting that a command follows reaches that command's
    // environment. A bare `n=$((n+1))` sets a shell variable.
    let mut pending: Option<String> = None;
    let mut bare_env = false;
    for token in &tokens {
        if token.is_control {
            // `env` with nothing after it still passes the setting on.
            if bare_env && pending.is_some() {
                return pending;
            }
            bare_env = false;
            command_start = COMMAND_SEPARATORS.contains(&token.value.as_str());
            in_prefix = false;
            pending = None;
            continue;
        }
        if command_start {
            command_start = false;
            in_prefix = true;
        }
        if !in_prefix || token.value == "env" || token.value == "/usr/bin/env" {
            bare_env = in_prefix;
            continue;
        }
        let Some((name, _)) = shell_assignment(chars.as_slice(), token) else {
            bare_env = false;
            if pending.is_some() {
                return pending;
            }
            in_prefix = false;
            continue;
        };
        let raw = chars.get(token.start..token.end)?;
        if pending.is_none()
            && name.len() <= MAX_SETTING_CHARS
            && assignment_name_shape(name)
            && raw.iter().any(|character| matches!(character, '$' | '`'))
        {
            pending = Some(name.to_owned());
        }
    }
    if bare_env {
        return pending;
    }
    None
}

pub(super) fn assignment_name_shape(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && characters.all(|value| value == '_' || value.is_ascii_alphanumeric())
}
