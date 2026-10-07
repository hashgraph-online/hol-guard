//! Rust port of `runtime/command_launcher_floors.py`.
//!
//! Bounded-grammar launcher expansion: `xargs`/`parallel`/`find` children are
//! `shlex.join`ed and re-parsed through the resident `parse_command`. Python
//! `shlex` semantics are reproduced locally (`split` posix, `join` quoting).

use crate::canonical_command::CanonicalCommand;
use crate::{parse_command, CommandModelRequestV1};

const XARGS_VALUE_OPTIONS: &[&str] = &[
    "--arg-file",
    "--delimiter",
    "--eof",
    "--max-args",
    "--max-chars",
    "--max-lines",
    "--max-procs",
    "--replace",
    "-E",
    "-I",
    "-J",
    "-L",
    "-P",
    "-R",
    "-S",
    "-a",
    "-d",
    "-e",
    "-n",
    "-s",
];

const PARALLEL_VALUE_OPTIONS: &[&str] = &[
    "--colsep",
    "--delay",
    "--header",
    "--joblog",
    "--jobs",
    "--load",
    "--max-procs",
    "--results",
    "--retries",
    "--sshlogin",
    "--tagstring",
    "--timeout",
    "--workdir",
    "-P",
    "-j",
];

const FIND_MARKERS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

const MAX_OPTION_PARSE_STATES: usize = 256;

/// `launcher_child_commands` (:57).
pub fn launcher_child_commands(executable: &str, arguments: &[String]) -> Vec<CanonicalCommand> {
    let children: Vec<Vec<String>> = if executable == "xargs" {
        possible_children(arguments, XARGS_VALUE_OPTIONS)
    } else if executable == "parallel" {
        possible_children(arguments, PARALLEL_VALUE_OPTIONS)
    } else if executable == "find" {
        find_children(arguments)
    } else {
        Vec::new()
    };
    children
        .iter()
        .filter(|child| !child.is_empty())
        .map(|child| {
            parse_command(&CommandModelRequestV1 {
                command: shlex_join(child),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "guard-shell".to_owned(),
            })
            .map(|v1| CanonicalCommand::from_v1(&v1))
            .expect("launcher children are generated tokens; parse must not fail")
        })
        .collect()
}

/// `_possible_children` (:70). DFS over option-parse states.
fn possible_children(arguments: &[String], value_options: &[&str]) -> Vec<Vec<String>> {
    let mut pending = vec![0usize];
    let mut visited: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut children: std::collections::BTreeSet<Vec<String>> = std::collections::BTreeSet::new();
    while let Some(index) = pending.pop() {
        if visited.contains(&index) || index >= arguments.len() {
            continue;
        }
        if visited.len() >= MAX_OPTION_PARSE_STATES {
            return arguments
                .iter()
                .enumerate()
                .filter(|(_, item)| !item.starts_with('-'))
                .map(|(cursor, _)| arguments[cursor..].to_vec())
                .collect();
        }
        visited.insert(index);
        let argument = &arguments[index];
        if argument == "--" {
            if !arguments[index + 1..].is_empty() {
                children.insert(arguments[index + 1..].to_vec());
            }
            continue;
        }
        let (mut option, mut separator, _value) = partition(argument, '=');
        if let Some(attached) = attached_short_option(argument, value_options) {
            option = attached;
            separator = "attached";
        }
        if value_options.contains(&option) {
            pending.push(index + if separator.is_empty() { 2 } else { 1 });
            continue;
        }
        if argument.starts_with('-') {
            pending.push(index + 1);
            if separator.is_empty() {
                pending.push(index + 2);
            }
            continue;
        }
        children.insert(arguments[index..].to_vec());
    }
    children.into_iter().collect()
}

/// `_attached_short_option` (:102).
fn attached_short_option<'a>(argument: &str, value_options: &[&'a str]) -> Option<&'a str> {
    if argument.len() <= 2 || !argument.starts_with('-') || argument.starts_with("--") {
        return None;
    }
    let matches: Vec<&&str> = value_options
        .iter()
        .filter(|option| option.len() == 2 && argument.starts_with(**option))
        .collect();
    if matches.len() == 1 {
        Some(*matches[0])
    } else {
        None
    }
}

/// `_find_children` (:109).
fn find_children(arguments: &[String]) -> Vec<Vec<String>> {
    let mut children = Vec::new();
    let mut index = 0usize;
    while index < arguments.len() {
        if !FIND_MARKERS.contains(&arguments[index].as_str()) {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < arguments.len() && ![";", "+"].contains(&arguments[end].as_str()) {
            end += 1;
        }
        if start < end {
            children.push(arguments[start..end].to_vec());
        }
        index = end + 1;
    }
    children
}

/// `str.partition` equivalent.
fn partition(argument: &str, separator: char) -> (&str, &str, &str) {
    match argument.find(separator) {
        Some(at) => (&argument[..at], &argument[at..at + 1], &argument[at + 1..]),
        None => (argument, "", ""),
    }
}

// ---------------------------------------------------------------------------
// shlex reproduction
// ---------------------------------------------------------------------------

/// `shlex.join` (posix): quote every unsafe token via `shlex.quote`.
pub(crate) fn shlex_join(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|token| shlex_quote(token))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `shlex.quote` (:271): safe chars `[A-Za-z0-9@%_+=:,./-]`; single-quote
/// otherwise with `'` → `'"'"'`.
pub(crate) fn shlex_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "@%_+=:,./-".contains(c))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// `shlex.split` posix over the subset used by `_expand_env_split_string`:
/// whitespace split, single/double quotes, backslash escapes, comment char
/// `#` when `comments=True`? — Python call site uses defaults (comments off),
/// so `#` is a word char. Unterminated quote → Err (ValueError).
pub(crate) fn shlex_split(input: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    let end = chars.len();
    while index < end {
        // skip whitespace
        while index < end && chars[index].is_whitespace() {
            index += 1;
        }
        if index >= end {
            break;
        }
        let mut token = String::new();
        // state machine within a word: quotes and escapes
        while index < end && !chars[index].is_whitespace() {
            let c = chars[index];
            match c {
                '\'' => {
                    index += 1;
                    let mut closed = false;
                    while index < end {
                        if chars[index] == '\'' {
                            index += 1;
                            closed = true;
                            break;
                        }
                        token.push(chars[index]);
                        index += 1;
                    }
                    if !closed {
                        return Err("No closing quotation".to_owned());
                    }
                }
                '"' => {
                    index += 1;
                    let mut closed = false;
                    while index < end {
                        if chars[index] == '"' {
                            index += 1;
                            closed = true;
                            break;
                        }
                        if chars[index] == '\\'
                            && index + 1 < end
                            && matches!(chars[index + 1], '"' | '\\' | '$' | '`')
                        {
                            index += 1;
                            token.push(chars[index]);
                            index += 1;
                            continue;
                        }
                        token.push(chars[index]);
                        index += 1;
                    }
                    if !closed {
                        return Err("No closing quotation".to_owned());
                    }
                }
                '\\' => {
                    index += 1;
                    if index < end {
                        token.push(chars[index]);
                        index += 1;
                    }
                }
                _ => {
                    token.push(c);
                    index += 1;
                }
            }
        }
        tokens.push(token);
    }
    Ok(tokens)
}
