//! Pytest target and invocation detection
//! (`secret_file_request_services/pytest_target_detection.py`).
//!
//! The inline-Python half walks a `ast.parse` tree in Python. Rust has no
//! Python parser, so `inline_python_payload_runs_pytest` answers `false` only
//! when a lexical argument proves the payload cannot reach pytest (no call,
//! no route that names it, or no mention of pytest at all) and `true`
//! otherwise. Every route Python recognizes is a name in code, so text
//! inside plain string literals is not a route. That is exact for the
//! `false` answers and stricter than Python for a payload that names pytest
//! near one of the routes without running it.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use unicode_normalization::UnicodeNormalization;

use crate::false_positive_rules::fd_arg_requests_exec;
use crate::sfrs_constants::{
    FIND_EXEC_ACTION_FLAGS, PYTHON_INTERPRETER_OPTIONS_WITH_VALUES,
    SHELL_COMMAND_STRING_INTERPRETERS,
};
use crate::sfrs_gh_pr_expansion::is_pytest_python_interpreter_command;
use crate::sfrs_patterns::{
    PYTEST_COMMAND_NAMES, PYTEST_COMMAND_RUNNER_SUBCOMMANDS, PYTEST_EXECUTOR_COMMANDS,
    PYTEST_RUNNER_OPTIONS_WITH_VALUES, PYTEST_RUNNER_POSITIONAL_PREFIX_COUNTS,
    SHELL_ASSIGNMENT_PATTERN,
};
use crate::sfrs_selectors::{pytest_args_from_python, python_segment_targets_module};
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, normalized_shell_command_name, shell_segment_primary_command,
    split_shell_parts,
};
use crate::sfrs_substitution::shell_command_substitution_payloads;
use crate::shell_secret_read_support::shell_interpreter_command_payload;

/// `_shell_token_has_active_glob`.
pub(crate) fn shell_token_has_active_glob(raw_token: &str) -> bool {
    let chars: Vec<char> = raw_token.chars().collect();
    let mut index = 0;
    let mut quote: Option<char> = None;
    while index < chars.len() {
        let character = chars[index];
        if character == '\\' {
            index += 2;
            continue;
        }
        if let Some(open) = quote {
            if character == open {
                quote = None;
            }
            index += 1;
            continue;
        }
        if character == '\'' || character == '"' {
            quote = Some(character);
        } else if matches!(character, '*' | '?' | '[') {
            return true;
        }
        index += 1;
    }
    false
}

fn is_pytest_name(token: &str) -> bool {
    PYTEST_COMMAND_NAMES.contains(&normalized_shell_command_name(token).as_str())
}

/// `_shell_command_targets_pytest`.
pub(crate) fn shell_command_targets_pytest(command_text: &str, depth: usize) -> bool {
    if depth > 8 {
        return split_shell_parts(command_text)
            .iter()
            .any(|token| is_pytest_name(token));
    }
    let parts = split_shell_parts(command_text);
    for segment in iter_shell_command_segments(&parts) {
        let (Some(command_name), Some(command_index)) = shell_segment_primary_command(&segment)
        else {
            continue;
        };
        if segment_targets_pytest(&segment, &command_name, command_index, depth) {
            return true;
        }
        if SHELL_COMMAND_STRING_INTERPRETERS.contains(&command_name.as_str()) {
            if let Some(payload) = shell_interpreter_command_payload(&segment, command_index) {
                if shell_command_targets_pytest(&payload.script_text, depth + 1) {
                    return true;
                }
            }
        }
    }
    shell_command_substitution_payloads(command_text)
        .iter()
        .any(|payload| shell_command_targets_pytest(payload, depth + 1))
}

fn table_lookup<'a, T>(table: &'a [(&str, T)], key: &str) -> Option<&'a T> {
    table.iter().find(|(name, _)| *name == key).map(|(_, v)| v)
}

/// `_segment_targets_pytest`.
pub(crate) fn segment_targets_pytest(
    segment: &[String],
    command_name: &str,
    command_index: usize,
    depth: usize,
) -> bool {
    if PYTEST_COMMAND_NAMES.contains(&command_name) {
        return true;
    }
    let command_args = &segment[command_index + 1..];
    if is_pytest_python_interpreter_command(command_name) {
        return python_segment_targets_module(command_args, "pytest")
            || python_inline_script_runs_pytest(command_args);
    }
    if command_name == "uvx" {
        return argument_sequence_targets_pytest(command_args);
    }
    if let Some(subcommands) = table_lookup(PYTEST_COMMAND_RUNNER_SUBCOMMANDS, command_name) {
        return command_args.iter().enumerate().any(|(index, token)| {
            subcommands.contains(&token.as_str())
                && pytest_args_from_runner_argument_sequence(
                    command_name,
                    &command_args[index + 1..],
                )
                .is_some()
        });
    }
    if PYTEST_EXECUTOR_COMMANDS.contains(&command_name) {
        return argument_sequence_targets_pytest(command_args);
    }
    if command_name == "eval" {
        return shell_command_targets_pytest(&command_args.join(" "), depth + 1);
    }
    if command_name == "find" {
        return command_args.iter().enumerate().any(|(index, token)| {
            FIND_EXEC_ACTION_FLAGS.contains(&token.as_str())
                && argument_sequence_targets_pytest(&command_args[index + 1..])
        });
    }
    if command_name == "fd" {
        return command_args.iter().enumerate().any(|(index, token)| {
            fd_arg_requests_exec(token)
                && argument_sequence_targets_pytest(&command_args[index + 1..])
        });
    }
    false
}

/// `_argument_sequence_targets_pytest`.
pub(crate) fn argument_sequence_targets_pytest(args: &[String]) -> bool {
    pytest_args_from_argument_sequence(args).is_some()
}

/// `_pytest_args_from_argument_sequence`.
pub(crate) fn pytest_args_from_argument_sequence(args: &[String]) -> Option<Vec<String>> {
    pytest_args_from_argument_sequence_ignoring(args, &[])
}

/// `_pytest_args_from_runner_argument_sequence`.
pub(crate) fn pytest_args_from_runner_argument_sequence(
    command_name: &str,
    args: &[String],
) -> Option<Vec<String>> {
    let value_options: &[&str] =
        table_lookup(PYTEST_RUNNER_OPTIONS_WITH_VALUES, command_name).map_or(&[], |v| *v);
    let mut ignored: Vec<usize> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if token == "--" {
            break;
        }
        if value_options.contains(&token) {
            if index + 1 >= args.len() {
                return None;
            }
            ignored.push(index + 1);
            index += 2;
            continue;
        }
        index += 1;
    }
    let mut prefix_count = table_lookup(PYTEST_RUNNER_POSITIONAL_PREFIX_COUNTS, command_name)
        .copied()
        .unwrap_or(0);
    for (index, token) in args.iter().enumerate() {
        if ignored.contains(&index) || token == "--" || token.starts_with('-') {
            continue;
        }
        if SHELL_ASSIGNMENT_PATTERN.is_match(token).unwrap_or(false) {
            continue;
        }
        if prefix_count > 0 {
            prefix_count -= 1;
            continue;
        }
        return pytest_args_from_command_position(args, index);
    }
    None
}

/// `_pytest_args_from_argument_sequence_ignoring`.
pub(crate) fn pytest_args_from_argument_sequence_ignoring(
    args: &[String],
    ignored_indices: &[usize],
) -> Option<Vec<String>> {
    (0..args.len())
        .filter(|index| !ignored_indices.contains(index))
        .find_map(|index| pytest_args_from_command_position(args, index))
}

/// `_pytest_args_from_command_position`.
pub(crate) fn pytest_args_from_command_position(
    args: &[String],
    index: usize,
) -> Option<Vec<String>> {
    let command_token = args[index].rsplit(':').next().unwrap_or("");
    let command_name = normalized_shell_command_name(command_token);
    if PYTEST_COMMAND_NAMES.contains(&command_name.as_str()) {
        return Some(args[index + 1..].to_vec());
    }
    if !is_pytest_python_interpreter_command(&command_name) {
        return None;
    }
    if let Some(python_args) = pytest_args_from_python(&args[index + 1..]) {
        return Some(python_args);
    }
    python_inline_script_runs_pytest(&args[index + 1..]).then(Vec::new)
}

/// `_python_inline_script_runs_pytest`.
pub(crate) fn python_inline_script_runs_pytest(args: &[String]) -> bool {
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if (token == "-c" || token == "--command") && index + 1 < args.len() {
            return inline_python_payload_runs_pytest(&args[index + 1], 0);
        }
        if let Some(payload) = token.strip_prefix("--command=") {
            return inline_python_payload_runs_pytest(payload, 0);
        }
        if token.starts_with("-c") && token != "-c" {
            return inline_python_payload_runs_pytest(&token[2..], 0);
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&token) {
            index += 2;
            continue;
        }
        if !token.starts_with('-') {
            return false;
        }
        index += 1;
    }
    false
}

/// Identifiers that open a string-driven route to pytest.
const STRING_ROUTE_WORDS: &[&str] = &[
    "system",
    "popen",
    "call",
    "check_call",
    "check_output",
    "run",
    "eval",
    "exec",
    "import_module",
    "run_module",
    "__import__",
    "getattr",
];

fn has_adjacent_quotes(text: &str) -> bool {
    let mut previous_quote = false;
    for character in text.chars() {
        if character == '\'' || character == '"' {
            if previous_quote {
                return true;
            }
            previous_quote = true;
        } else if !character.is_whitespace() {
            previous_quote = false;
        }
    }
    false
}

/// `_inline_python_payload_runs_pytest` (see the module header).
pub(crate) fn inline_python_payload_runs_pytest(payload: &str, depth: usize) -> bool {
    let folded = payload
        .to_lowercase()
        .replace('\u{17f}', "s")
        .replace('\u{df}', "ss");
    if depth > 8 {
        return folded.contains("pytest");
    }
    let normalized: String = folded.nfkc().collect();
    if !normalized.contains('(') {
        return false;
    }
    let stripped = code_outside_plain_literals(&folded);
    let code: String = match &stripped {
        Some(code) => code.nfkc().collect(),
        None => normalized.clone(),
    };
    // A triple-quoted delimiter is one literal. Adjacent quotes and
    // backslashes fail closed only when that split is uncertain.
    let uncertain = stripped.is_none();
    // A route word only reaches pytest when the payload names it somewhere,
    // including inside the literals the split removed. Python resolves the
    // call's own arguments for that name, so a route carrying nothing else
    // (`subprocess.run(["echo", "harmless"])`) runs no test there either.
    // The name is matched with quotes, spaces and operators removed, because
    // a shell drops quotes (`py""test`) and Python joins pieces
    // (`'py' + 'test'`, `''.join(['py', 'test'])`) before either runs it.
    let compact: String = normalized
        .chars()
        .filter(|character| character.is_alphanumeric() || *character == '.')
        .collect();
    let names_pytest = compact.contains("pytest") || compact.contains("py.test");
    code.contains("pytest")
        || code.contains("py.test")
        || (uncertain && (normalized.contains('\\') || has_adjacent_quotes(&normalized)))
        || (names_pytest && STRING_ROUTE_WORDS.iter().any(|word| code.contains(word)))
}

fn is_line_end(character: char) -> bool {
    character == '\n' || character == '\r'
}

/// `payload` with the contents of its plain string literals removed, so only
/// code and comments remain. `None` when the split is not certain: an f- or
/// t-string (its fields are code), any backslash, an unterminated literal,
/// or another literal after only whitespace (implicit concatenation).
/// Python's tokenizer only opens strings on ASCII quotes, so this runs
/// before NFKC folding, which could otherwise mint new quotes.
fn code_outside_plain_literals(payload: &str) -> Option<String> {
    if payload.contains('\\') {
        return None;
    }
    let chars: Vec<char> = payload.chars().collect();
    let mut code = String::new();
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if character == '#' {
            while index < chars.len() && !is_line_end(chars[index]) {
                code.push(chars[index]);
                index += 1;
            }
            continue;
        }
        if character != '\'' && character != '"' {
            code.push(character);
            index += 1;
            continue;
        }
        let prefix_has_fields = code
            .chars()
            .rev()
            .take_while(|letter| letter.is_alphanumeric() || *letter == '_')
            .any(|letter| letter == 'f' || letter == 't');
        if prefix_has_fields {
            return None;
        }
        let quoted_at = |at: usize| chars.get(at) == Some(&character);
        let triple = quoted_at(index + 1) && quoted_at(index + 2);
        let quote_len = if triple { 3 } else { 1 };
        let mut cursor = index + quote_len;
        loop {
            let current = *chars.get(cursor)?;
            if !triple && is_line_end(current) {
                return None;
            }
            if current == character && (!triple || (quoted_at(cursor + 1) && quoted_at(cursor + 2)))
            {
                break;
            }
            cursor += 1;
        }
        code.push_str("\"\"");
        index = cursor + quote_len;
        let mut look = index;
        while look < chars.len() && chars[look].is_whitespace() {
            look += 1;
        }
        // Implicit concatenation can assemble a route from pieces this
        // splitter would otherwise delete.
        if matches!(chars.get(look), Some('\'' | '"')) {
            return None;
        }
    }
    Some(code)
}

#[cfg(test)]
mod tests {
    use super::{inline_python_payload_runs_pytest, shell_token_has_active_glob};

    #[test]
    fn inline_payload_prefilter_is_exact_for_false() {
        assert!(!inline_python_payload_runs_pytest("print(1)", 0));
        assert!(!inline_python_payload_runs_pytest("x = 1", 0));
        assert!(inline_python_payload_runs_pytest(
            "import pytest; pytest.main()",
            0
        ));
    }

    #[test]
    fn plain_string_literals_are_not_routes() {
        assert!(!inline_python_payload_runs_pytest(
            r#"print("pytest.main()")"#,
            0
        ));
        assert!(!inline_python_payload_runs_pytest(
            "print('''run\nsystem''', b'exec')",
            0
        ));
        assert!(!inline_python_payload_runs_pytest(
            "print('run system', b'exec')",
            0
        ));
        // A quote inside a comment does not open a string.
        assert!(inline_python_payload_runs_pytest(
            "# it's\nimport pytest; pytest.main()",
            0
        ));
        // Routes in code still count with the target inside a literal.
        assert!(inline_python_payload_runs_pytest(
            "import subprocess; subprocess.check_call('pytest')",
            0
        ));
        assert!(inline_python_payload_runs_pytest(
            "import os; os.system('pytest')",
            0
        ));
        assert!(inline_python_payload_runs_pytest(
            "__import__('pytest').main()",
            0
        ));
        // Uncertain splits keep the full text.
        assert!(inline_python_payload_runs_pytest(
            r#"print(f"{__import__('pytest').main()}")"#,
            0
        ));
        // A route whose arguments never name pytest runs no test.
        assert!(!inline_python_payload_runs_pytest(
            "import subprocess as sp; sp.run(['echo', 'harmless'])",
            0
        ));
        assert!(!inline_python_payload_runs_pytest(
            "import os; os.system('echo harmless')",
            0
        ));
        // A name split by shell quotes or Python concatenation still counts.
        assert!(inline_python_payload_runs_pytest(
            r#"import os; os.system('py""test -x')"#,
            0
        ));
        assert!(inline_python_payload_runs_pytest(
            "import subprocess; subprocess.run(['py' + 'test'])",
            0
        ));
        assert!(inline_python_payload_runs_pytest(
            "import subprocess; subprocess.run([''.join(['py', 'test'])])",
            0
        ));
        assert!(inline_python_payload_runs_pytest("print('pytest", 0));
        assert!(inline_python_payload_runs_pytest(r"print('pyt\x65st')", 0));
    }

    #[test]
    fn glob_detection_respects_quotes() {
        assert!(shell_token_has_active_glob("a*"));
        assert!(!shell_token_has_active_glob("'a*'"));
        assert!(!shell_token_has_active_glob("a\\*"));
    }
}
