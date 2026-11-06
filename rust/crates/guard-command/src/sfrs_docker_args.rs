//! Docker and buildx argument sensitivity checks used by the request
//! classifier (`request_artifacts.py` and `shell_tokenization.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::hook_adapter_pytext::py_strip;
use crate::sfrs_constants::{
    DOCKER_BUILDX_FLAG_OPTIONS, DOCKER_BUILDX_OPTIONS_WITH_VALUES, DOCKER_BUILD_ARG_SECRET_MARKERS,
    DOCKER_BUILD_ARG_TOKEN_PREFIXES, DOCKER_BUILD_METADATA_FLAGS, DOCKER_BUILD_OUTPUT_FLAGS,
    DOCKER_BUILD_SECRET_FLAGS, DOCKER_GLOBAL_FLAG_OPTIONS, DOCKER_GLOBAL_OPTIONS_WITH_VALUES,
};

fn is_or_prefixed(token: &str, options: &[&str]) -> bool {
    options.iter().any(|option| {
        token == *option
            || token
                .strip_prefix(option)
                .is_some_and(|rest| rest.starts_with('='))
    })
}

/// Index of the subcommand after the leading option run, shared by the
/// docker and buildx forms.
fn subcommand_index(args: &[String], with_value: &[&str], flags: &[&str]) -> Option<usize> {
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if token == "--" {
            return (index + 1 < args.len()).then_some(index + 1);
        }
        if is_or_prefixed(token, with_value) {
            index += if token.contains('=') { 1 } else { 2 };
            continue;
        }
        if is_or_prefixed(token, flags) {
            index += 1;
            continue;
        }
        if token.starts_with('-') && !token.starts_with("--") {
            index += 1;
            continue;
        }
        return Some(index);
    }
    None
}

pub(crate) fn docker_subcommand_index(args: &[String]) -> Option<usize> {
    subcommand_index(
        args,
        DOCKER_GLOBAL_OPTIONS_WITH_VALUES,
        DOCKER_GLOBAL_FLAG_OPTIONS,
    )
}

pub(crate) fn docker_buildx_subcommand_index(args: &[String]) -> Option<usize> {
    subcommand_index(
        args,
        DOCKER_BUILDX_OPTIONS_WITH_VALUES,
        DOCKER_BUILDX_FLAG_OPTIONS,
    )
}

pub(crate) fn docker_global_option_has_value(token: &str) -> bool {
    is_or_prefixed(token, DOCKER_GLOBAL_OPTIONS_WITH_VALUES)
}

pub(crate) fn docker_global_flag_option_matches(token: &str) -> bool {
    is_or_prefixed(token, DOCKER_GLOBAL_FLAG_OPTIONS)
}

pub(crate) fn docker_buildx_option_has_value(token: &str) -> bool {
    is_or_prefixed(token, DOCKER_BUILDX_OPTIONS_WITH_VALUES)
}

pub(crate) fn docker_buildx_flag_option_matches(token: &str) -> bool {
    is_or_prefixed(token, DOCKER_BUILDX_FLAG_OPTIONS)
}

pub(crate) fn docker_subcommand_help_requested(args: &[String]) -> bool {
    for (offset, token) in args.iter().skip(1).enumerate() {
        if token != "--help" {
            continue;
        }
        return args[1..1 + offset]
            .iter()
            .all(|previous| previous.starts_with('-'));
    }
    false
}

/// `-c`/`-H` with an attached value, returned as `(flag, value)`.
pub(crate) fn docker_attached_short_context_option(token: &str) -> Option<(&'static str, String)> {
    for flag in ["-c", "-H"] {
        let bare_equals = format!("{flag}=");
        if token.starts_with(flag) && token != flag && token != bare_equals {
            let value = &token[flag.len()..];
            return Some((flag, value.strip_prefix('=').unwrap_or(value).to_owned()));
        }
    }
    None
}

pub(crate) fn docker_build_output_flag_matches(token: &str) -> bool {
    if is_or_prefixed(token, DOCKER_BUILD_OUTPUT_FLAGS) {
        return true;
    }
    token.starts_with("-o") && token.chars().count() > 2
}

pub(crate) fn docker_build_arg_is_sensitive(value: &str) -> bool {
    let (key, separator, assigned) = partition_equals(value);
    let key = py_strip(key);
    !key.is_empty()
        && (!separator
            || docker_build_arg_name_is_sensitive(key)
            || docker_build_arg_value_is_sensitive(py_strip(assigned)))
}

fn partition_equals(value: &str) -> (&str, bool, &str) {
    match value.split_once('=') {
        Some((key, rest)) => (key, true, rest),
        None => (value, false, ""),
    }
}

pub(crate) fn docker_build_arg_name_is_sensitive(value: &str) -> bool {
    let normalized = value.to_uppercase().replace('-', "_");
    if normalized
        .split('_')
        .any(|part| DOCKER_BUILD_ARG_SECRET_MARKERS.contains(&part))
    {
        return true;
    }
    DOCKER_BUILD_ARG_SECRET_MARKERS
        .iter()
        .filter(|marker| **marker != "KEY")
        .any(|marker| normalized.contains(marker))
}

pub(crate) fn docker_build_arg_value_is_sensitive(value: &str) -> bool {
    let lowered = value.to_lowercase();
    let lowered = lowered.trim_matches(|c| c == '"' || c == '\'');
    if DOCKER_BUILD_ARG_TOKEN_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
    {
        return true;
    }
    if value.contains("$(") || value.contains('`') {
        return true;
    }
    shell_variable_names(value)
        .iter()
        .any(|name| docker_build_arg_name_is_sensitive(name))
}

fn is_name_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `$NAME`, `${NAME}` and `${!NAME}` references in `value`, in order.
pub(crate) fn shell_variable_names(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let find = |from: usize, needle: char| {
        chars[from..]
            .iter()
            .position(|c| *c == needle)
            .map(|i| i + from)
    };
    let mut names = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let Some(dollar) = find(index, '$') else {
            break;
        };
        if dollar + 1 >= chars.len() {
            break;
        }
        if chars[dollar + 1] == '{' {
            let Some(closing) = find(dollar + 2, '}') else {
                index = dollar + 2;
                continue;
            };
            let inner = &chars[dollar + 2..closing];
            let start = usize::from(inner.first() == Some(&'!'));
            let (name, _) = unbraced_name(inner, start);
            if !name.is_empty() {
                names.push(name);
            }
            index = closing + 1;
            continue;
        }
        let (name, next) = unbraced_name(&chars, dollar + 1);
        if !name.is_empty() {
            names.push(name);
        }
        index = next;
    }
    names
}

fn unbraced_name(chars: &[char], start: usize) -> (String, usize) {
    if start >= chars.len() || !is_name_start(chars[start]) {
        return (String::new(), start + 1);
    }
    let mut end = start + 1;
    while end < chars.len() && is_name_char(chars[end]) {
        end += 1;
    }
    (chars[start..end].iter().collect(), end)
}

pub(crate) fn docker_build_metadata_value_is_sensitive(value: &str) -> bool {
    let (key, separator, assigned) = partition_equals(value);
    if !separator {
        return docker_build_arg_value_is_sensitive(py_strip(value));
    }
    docker_build_arg_value_is_sensitive(py_strip(key))
        || docker_build_arg_value_is_sensitive(py_strip(assigned))
}

pub(crate) fn docker_build_args_are_sensitive(args: &[String]) -> bool {
    let value_at = |index: usize| args.get(index).map_or("", String::as_str);
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if token == "--" {
            return false;
        }
        if is_or_prefixed(token, DOCKER_BUILD_SECRET_FLAGS)
            || docker_build_output_flag_matches(token)
        {
            return true;
        }
        if token == "--build-arg" {
            if docker_build_arg_is_sensitive(value_at(index + 1)) {
                return true;
            }
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--build-arg=") {
            if docker_build_arg_is_sensitive(value) {
                return true;
            }
        }
        if DOCKER_BUILD_METADATA_FLAGS.contains(&token) {
            if docker_build_metadata_value_is_sensitive(value_at(index + 1)) {
                return true;
            }
            index += 2;
            continue;
        }
        if token.starts_with("--") {
            if let Some((flag, value)) = token.split_once('=') {
                if DOCKER_BUILD_METADATA_FLAGS.contains(&flag)
                    && docker_build_metadata_value_is_sensitive(value)
                {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn variable_names_follow_shell_forms() {
        assert_eq!(
            shell_variable_names("$A ${B} ${!C} $1 x$D_E"),
            ["A", "B", "C", "D_E"]
        );
        assert!(shell_variable_names("${open").is_empty());
    }

    #[test]
    fn build_arg_sensitivity() {
        assert!(docker_build_arg_is_sensitive("TOKEN=abc"));
        assert!(docker_build_arg_is_sensitive("BARE"));
        assert!(!docker_build_arg_is_sensitive("MODE=release"));
        assert!(docker_build_args_are_sensitive(&args(&[
            "--secret", "id=x"
        ])));
        assert!(!docker_build_args_are_sensitive(&args(&[
            "--tag", "x", "."
        ])));
    }

    #[test]
    fn subcommand_scan_skips_global_options() {
        assert_eq!(
            docker_subcommand_index(&args(&["--host", "h", "build"])),
            Some(2)
        );
        assert_eq!(
            docker_subcommand_index(&args(&["--debug", "-D", "ps"])),
            Some(2)
        );
        assert_eq!(docker_subcommand_index(&args(&["--"])), None);
    }

    #[test]
    fn help_request_needs_only_option_prefix() {
        assert!(docker_subcommand_help_requested(&args(&[
            "build", "--help"
        ])));
        assert!(!docker_subcommand_help_requested(&args(&[
            "build", "x", "--help"
        ])));
    }
}
