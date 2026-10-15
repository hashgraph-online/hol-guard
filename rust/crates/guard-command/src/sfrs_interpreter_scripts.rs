//! Inline interpreter script extraction and read-only observer checks
//! (`shell_static_safety.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::codex_output_py::py_strip;
use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_constants::{
    PYTHON_INTERPRETER_OPTIONS_WITH_VALUES, SHELL_COMMAND_STRING_INTERPRETERS,
    UNMODELED_INLINE_INTERPRETER_COMMANDS,
};
use crate::sfrs_patterns::READ_ONLY_INTERPRETER_MUTATION_PATTERNS;
use crate::sfrs_python_imports::script_has_aliased_risky_import;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, normalized_shell_command_name, shell_segment_primary_command,
};

static SLEEP_COMMAND: LazyLock<Regex> =
    LazyLock::new(|| compile_fancy(r"\Asleep\s+\d+(?:\.\d+)?\z"));
static PYTHON_SLEEP: LazyLock<Regex> = LazyLock::new(|| {
    compile_fancy(r"\A(?:import\s+time\s*;\s*)?time\.sleep\(\s*\d+(?:\.\d+)?\s*\)\z")
});
static PYTHON_COMMAND: LazyLock<Regex> =
    LazyLock::new(|| compile_fancy(r"\Apythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?\z"));

/// `_InterpreterFlagPayload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterpreterFlagPayload {
    pub(crate) script_text: String,
    pub(crate) tokens_consumed: usize,
}

/// `_script_is_benign_wait`.
pub(crate) fn script_is_benign_wait(script_text: &str) -> bool {
    let normalized = py_strip(script_text);
    if normalized.is_empty() {
        return false;
    }
    SLEEP_COMMAND.is_match(normalized).unwrap_or(false)
        || PYTHON_SLEEP.is_match(normalized).unwrap_or(false)
}

/// `_script_is_read_only_observer`.
pub(crate) fn script_is_read_only_observer(script_text: &str) -> bool {
    let normalized = py_strip(script_text);
    if normalized.is_empty() {
        return false;
    }
    if script_is_benign_wait(normalized) {
        return true;
    }
    if script_has_aliased_risky_import(normalized) {
        return false;
    }
    !READ_ONLY_INTERPRETER_MUTATION_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(normalized).unwrap_or(false))
}

/// `_is_python_interpreter_command`.
pub(crate) fn is_python_interpreter_command(command_name: &str) -> bool {
    PYTHON_COMMAND
        .is_match(&normalized_shell_command_name(command_name))
        .unwrap_or(false)
}

/// `_is_script_interpreter_command`.
pub(crate) fn is_script_interpreter_command(command_name: &str) -> bool {
    is_python_interpreter_command(command_name)
        || UNMODELED_INLINE_INTERPRETER_COMMANDS.contains(&command_name)
}

/// `_interpreter_flag_payload`.
pub(crate) fn interpreter_flag_payload(
    parts: &[String],
    index: usize,
) -> Option<InterpreterFlagPayload> {
    let token = py_strip(&parts[index])
        .trim_start_matches('(')
        .trim_end_matches(')');
    if !token.starts_with('-') {
        return None;
    }
    if token.starts_with("--") {
        for long_flag in ["--command", "--eval", "--execute"] {
            if token == long_flag {
                let next = py_strip(parts.get(index + 1)?);
                if next.is_empty() {
                    return None;
                }
                return Some(payload(next, 2));
            }
            if let Some(attached) = token
                .strip_prefix(long_flag)
                .and_then(|rest| rest.strip_prefix('='))
            {
                let attached = py_strip(attached);
                if attached.is_empty() {
                    return None;
                }
                return Some(payload(attached, 1));
            }
        }
        return None;
    }
    let flag_text = &token[1..];
    for (offset, flag) in flag_text.char_indices() {
        if flag != 'c' && flag != 'e' {
            continue;
        }
        let attached = py_strip(&flag_text[offset + flag.len_utf8()..]);
        if !attached.is_empty() {
            return Some(payload(attached, 1));
        }
        let next = py_strip(parts.get(index + 1)?);
        if next.is_empty() {
            return None;
        }
        return Some(payload(next, 2));
    }
    None
}

fn payload(script_text: &str, tokens_consumed: usize) -> InterpreterFlagPayload {
    InterpreterFlagPayload {
        script_text: script_text.to_owned(),
        tokens_consumed,
    }
}

/// `_script_interpreter_texts`.
pub(crate) fn script_interpreter_texts(parts: &[String]) -> Vec<String> {
    let mut scripts = Vec::new();
    for segment in iter_shell_command_segments(parts) {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            continue;
        };
        if !SHELL_COMMAND_STRING_INTERPRETERS.contains(&command_name.as_str())
            && !is_script_interpreter_command(&command_name)
        {
            continue;
        }
        let mut index = command_index + 1;
        while index < segment.len() {
            let token = segment[index].as_str();
            if token == "--" {
                break;
            }
            if let Some(found) = interpreter_flag_payload(&segment, index) {
                scripts.push(found.script_text);
                break;
            }
            if is_python_interpreter_command(&command_name)
                && PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&token)
            {
                if index + 1 >= segment.len() {
                    break;
                }
                index += 2;
                continue;
            }
            if token.starts_with("--") {
                if token.contains('=') {
                    index += 1;
                    continue;
                }
                break;
            }
            if token.starts_with('-') {
                index += 1;
                continue;
            }
            break;
        }
    }
    scripts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn benign_waits_and_mutations() {
        assert!(script_is_benign_wait("sleep 1.5"));
        assert!(script_is_benign_wait("import time; time.sleep(2)"));
        assert!(!script_is_benign_wait("sleep x"));
        assert!(script_is_read_only_observer("print(1)"));
        assert!(!script_is_read_only_observer("open('a', 'w')"));
        assert!(!script_is_read_only_observer("import os as o"));
        assert!(!script_is_read_only_observer("  "));
    }

    #[test]
    fn interpreter_command_names() {
        assert!(is_python_interpreter_command("python3.12"));
        assert!(is_python_interpreter_command("/usr/bin/pythonw.exe"));
        assert!(!is_python_interpreter_command("pythonic"));
        assert!(is_script_interpreter_command("perl"));
    }

    #[test]
    fn flag_payloads() {
        let argv = parts(&["-c", "print(1)"]);
        let found = interpreter_flag_payload(&argv, 0).expect("payload");
        assert_eq!(
            (found.script_text.as_str(), found.tokens_consumed),
            ("print(1)", 2)
        );
        let argv = parts(&["--eval=x"]);
        assert_eq!(
            interpreter_flag_payload(&argv, 0).map(|p| p.tokens_consumed),
            Some(1)
        );
        assert_eq!(interpreter_flag_payload(&parts(&["-c"]), 0), None);
        assert_eq!(
            script_interpreter_texts(&parts(&["python3", "-W", "ignore", "-c", "x=1"])),
            vec!["x=1".to_owned()]
        );
    }
}
