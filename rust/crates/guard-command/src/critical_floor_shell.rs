//! Bounded transparent shell and environment option parsing for critical floors.
use super::rules::{destructive_remove, executable_name};
use crate::canonical_command::CanonicalCommand;
use crate::command_launcher_floors::shlex_split;
use crate::{parse_command, CommandModelRequestV1};

const ENV_LONG_BOOLEAN_OPTIONS: &[&str] = &[
    "--debug",
    "--ignore-environment",
    "--list-signal-handling",
    "--null",
];
const ENV_LONG_VALUE_OPTIONS: &[&str] = &["--argv0", "--chdir", "--unset"];
const ENV_SHORT_BOOLEAN_OPTIONS: &[char] = &['0', 'i', 'v'];
const ENV_SHORT_VALUE_OPTIONS: &[char] = &['C', 'P', 'a', 'u'];

/// `_destructive_timeout_shell` (:325). `parse_shell_command` on the native
/// path cannot raise — `parse_command` returns `Ok(uncertain)` — matching the
/// Python call site which has no exception handling.
pub(super) fn destructive_timeout_shell(arguments: &[String]) -> bool {
    let expanded = expand_env_split_string(arguments);
    // `enumerate(expanded[:-1])` — last token cannot pair with a `-c` arg.
    for index in 0..expanded.len().saturating_sub(1) {
        let shell = expanded[index]
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_lowercase();
        if !["ash", "bash", "dash", "sh", "zsh"].contains(&shell.as_str()) {
            continue;
        }
        let Some(command_text) = shell_command_text(&expanded[index + 1..]) else {
            continue;
        };
        let nested = parse_command(&CommandModelRequestV1 {
            command: command_text,
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .expect("resident parse_command always returns a CanonicalCommandV1");
        let nested = CanonicalCommand::from_v1(&nested);
        return nested.segments.iter().any(|segment| {
            executable_name(segment) == "rm" && destructive_remove(&segment.arguments)
        });
    }
    false
}

/// `_expand_env_split_string` (:341).
fn expand_env_split_string(arguments: &[String]) -> Vec<String> {
    for index in 0..arguments.len().saturating_sub(1) {
        let name = arguments[index]
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_lowercase();
        if name != "env" {
            continue;
        }
        let Some((split_string, consumed)) = env_split_string(arguments, index + 1) else {
            return arguments.to_vec();
        };
        let split = match shlex_split(&split_string) {
            Ok(split) => split,
            Err(_) => return arguments.to_vec(),
        };
        if split.is_empty() {
            return arguments.to_vec();
        }
        let mut out: Vec<String> = Vec::with_capacity(arguments.len() + split.len());
        out.extend_from_slice(&arguments[..index + 1]);
        out.extend(split);
        out.extend_from_slice(&arguments[consumed..]);
        return out;
    }
    arguments.to_vec()
}

/// `_env_split_string` (:356): returns `(split_string, consumed)` or `None`.
fn env_split_string(arguments: &[String], start: usize) -> Option<(String, usize)> {
    let mut index = start;
    while index < arguments.len() {
        let argument = &arguments[index];
        if ENV_LONG_BOOLEAN_OPTIONS.contains(&argument.as_str()) {
            index += 1;
            continue;
        }
        let (option, separator, value) = partition(argument, '=');
        if ENV_LONG_VALUE_OPTIONS.contains(&option) {
            if !separator.is_empty() {
                if value.is_empty() {
                    return None;
                }
                index += 1;
                continue;
            }
            if index + 1 >= arguments.len() || arguments[index + 1].is_empty() {
                return None;
            }
            index += 2;
            continue;
        }
        if option == "--split-string" {
            if !separator.is_empty() {
                return if value.is_empty() {
                    None
                } else {
                    Some((value.to_owned(), index + 1))
                };
            }
            if index + 1 >= arguments.len() || arguments[index + 1].is_empty() {
                return None;
            }
            return Some((arguments[index + 1].clone(), index + 2));
        }
        if argument.starts_with("--") || !argument.starts_with('-') || argument == "-" {
            return None;
        }
        let chars: Vec<char> = argument.chars().collect();
        let mut cursor = 1usize;
        let mut loop_broke = false;
        while cursor < chars.len() {
            let short_option = chars[cursor];
            if ENV_SHORT_BOOLEAN_OPTIONS.contains(&short_option) {
                cursor += 1;
                continue;
            }
            if short_option == 'S' {
                let attached: String = chars[cursor + 1..].iter().collect();
                if !attached.is_empty() {
                    return Some((attached, index + 1));
                }
                if index + 1 >= arguments.len() || arguments[index + 1].is_empty() {
                    return None;
                }
                return Some((arguments[index + 1].clone(), index + 2));
            }
            if !ENV_SHORT_VALUE_OPTIONS.contains(&short_option) {
                return None;
            }
            if cursor + 1 < chars.len() {
                index += 1;
            } else if index + 1 < arguments.len() && !arguments[index + 1].is_empty() {
                index += 2;
            } else {
                return None;
            }
            loop_broke = true;
            break;
        }
        if !loop_broke {
            index += 1;
        }
    }
    None
}

/// `_shell_command_text` (:398).
fn shell_command_text(arguments: &[String]) -> Option<String> {
    const OPTIONS_WITH_VALUES: &[&str] = &["-O", "-o", "--init-file", "--rcfile"];
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        if OPTIONS_WITH_VALUES.contains(&argument.as_str()) {
            index += 2;
            continue;
        }
        if argument == "--" {
            return None;
        }
        if let Some(stripped) = argument.strip_prefix('-') {
            if !argument.starts_with("--") && stripped.contains('c') {
                return arguments.get(index + 1).cloned();
            }
            index += 1;
            continue;
        }
        return None;
    }
    None
}

/// `str.partition` equivalent over a single char.
pub(super) fn partition(argument: &str, separator: char) -> (&str, &str, &str) {
    match argument.find(separator) {
        Some(at) => (&argument[..at], &argument[at..at + 1], &argument[at + 1..]),
        None => (argument, "", ""),
    }
}
