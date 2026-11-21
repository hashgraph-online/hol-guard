//! Shell bindings that can resolve to GitHub commands
//! (`runtime/github_shell_bindings.py`).

// Consumed by the GitHub shell classifier slice.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use regex::Regex;

use crate::command_option_parsing::python_is_alphanumeric;
use crate::hook_adapter_pytext::{is_py_space, py_strip};

pub(crate) use crate::sfrs_gh_definitions::{
    case_arm_segments, definition_payload, executable_control_flow_segment,
    function_definition_payloads, scoped_command_substitutions,
};

pub(crate) type Bindings = HashSet<String>;
pub(crate) type Updates = Vec<(String, bool)>;

/// Rewrites `\s` so it matches what `re` matches in a `str` pattern: Unicode
/// white space plus the ASCII separators `\x1c`-`\x1f`.
pub(crate) fn py_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut in_class = false;
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('s') => out.push_str(if in_class {
                    r"\s\x1c-\x1f"
                } else {
                    r"[\s\x1c-\x1f]"
                }),
                Some(next) => {
                    out.push('\\');
                    out.push(next);
                }
                None => out.push('\\'),
            },
            '[' if !in_class => {
                in_class = true;
                out.push(c);
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn compile(pattern: &str) -> Regex {
    Regex::new(&py_pattern(pattern)).expect("github shell pattern is a compile-time constant")
}

const LOOKUP_EXPRESSION: &str = r"\$\(\s*(?:command\s+-v|which)\s+gh\s*\)";
const EXECUTABLE: &str = r"(?:[A-Za-z]:)?(?:[/\\][A-Za-z0-9_.~-]+)*[/\\]?gh(?:\.exe)?";
const VARIABLE_REFERENCE: &str =
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))";

static LOOKUP_ASSIGNMENT: LazyLock<FancyRegex> = LazyLock::new(|| {
    let pattern = format!(
        r#"(?<![A-Za-z0-9_])(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:{LOOKUP_EXPRESSION}|"{LOOKUP_EXPRESSION}")"#
    );
    FancyRegex::new(&py_pattern(&pattern)).expect("constant pattern")
});
static COMMAND_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r#"(?i)(?:^|[=;&|()\s])["']?{EXECUTABLE}(?:[;&|)\s]|$)"#
    ))
});
static SINGLE_QUOTED: LazyLock<Regex> = LazyLock::new(|| compile(r"'[^']*'"));
static VARIABLE: LazyLock<Regex> = LazyLock::new(|| compile(VARIABLE_REFERENCE));
static COMPOUND_FLOW: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?:^|[;&|]\s*)(?:case|for|if|until|while)\b|(?:^|[;&|]\s*)[({]\s+"));
static GITHUB_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?i)\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*["']?(?:(?:[A-Za-z]:)?(?:[/\\][A-Za-z0-9_.~-]+)*[/\\])?gh(?:\.exe)?(?:["']|[;&|\s]|$)"#,
    )
});
pub(crate) fn strip_quotes(token: &str) -> &str {
    token.trim_matches(['"', '\''])
}

/// `normalize_github_lookup_assignments`. `None` when the matcher gave up.
pub(crate) fn normalize_github_lookup_assignments(command_text: &str) -> Option<String> {
    let mut out = String::with_capacity(command_text.len());
    let mut last = 0usize;
    for captures in LOOKUP_ASSIGNMENT.captures_iter(command_text) {
        let captures = captures.ok()?;
        let whole = captures.get(0)?;
        out.push_str(&command_text[last..whole.start()]);
        out.push_str(captures.name("name")?.as_str());
        out.push_str("=gh");
        last = whole.end();
    }
    out.push_str(&command_text[last..]);
    Some(out)
}

/// `contains_github_command_text`.
pub(crate) fn contains_github_command_text(text: &str) -> bool {
    COMMAND_TEXT.is_match(text)
}

/// `pipeline_executes_github_text`.
pub(crate) fn pipeline_executes_github_text(
    pipeline: &[Vec<String>],
    github_command_text_variables: &Bindings,
) -> bool {
    for (index, segment) in pipeline.iter().enumerate().skip(1) {
        let (name, _) = crate::sfrs_shell_tokens::shell_segment_primary_command(segment);
        if !matches!(
            name.as_deref(),
            Some("bash" | "dash" | "eval" | "sh" | "xargs" | "zsh")
        ) {
            continue;
        }
        let upstream: Vec<String> = pipeline[..index].iter().flatten().cloned().collect();
        if contains_github_command_text(&upstream.join(" "))
            || tokens_reference_github_variable(
                &upstream,
                &Bindings::new(),
                github_command_text_variables,
            )
        {
            return true;
        }
    }
    false
}

/// `assignment_updates`.
pub(crate) fn assignment_updates(
    segment: &[String],
    command_index: Option<usize>,
    text_values: bool,
    text_value_classifier: Option<&dyn Fn(&str) -> bool>,
) -> Updates {
    let limit = command_index.unwrap_or(segment.len());
    let mut updates = Vec::new();
    for token in &segment[..limit] {
        let Some((name, value)) = token.split_once('=') else {
            continue;
        };
        if !is_shell_variable_name(name) {
            continue;
        }
        let names_github = if text_values {
            match text_value_classifier {
                Some(classifier) => classifier(value),
                None => !py_strip(value).is_empty() && contains_github_command_text(value),
            }
        } else {
            value_names_github_executable(value)
        };
        updates.push((name.to_owned(), names_github));
    }
    updates
}

/// `persistent_assignment_updates`.
pub(crate) fn persistent_assignment_updates(
    segment: &[String],
    command_name: Option<&str>,
    command_index: Option<usize>,
    text_values: bool,
    text_value_classifier: Option<&dyn Fn(&str) -> bool>,
) -> Updates {
    if segment_is_standalone_assignment(segment) {
        return assignment_updates(segment, None, text_values, text_value_classifier);
    }
    if let (Some("declare" | "export" | "local" | "readonly" | "typeset"), Some(index)) =
        (command_name, command_index)
    {
        let assignments: Vec<String> = segment[index + 1..]
            .iter()
            .filter(|token| !token.starts_with('-'))
            .cloned()
            .collect();
        return assignment_updates(&assignments, None, text_values, text_value_classifier);
    }
    if let (Some("unset"), Some(index)) = (command_name, command_index) {
        return segment[index + 1..]
            .iter()
            .filter(|token| !token.starts_with('-') && is_shell_variable_name(token))
            .map(|token| (token.clone(), false))
            .collect();
    }
    Vec::new()
}

/// `apply_assignment_updates`.
pub(crate) fn apply_assignment_updates(bindings: &mut Bindings, updates: &[(String, bool)]) {
    for (name, names_github) in updates {
        if *names_github {
            bindings.insert(name.clone());
        } else {
            bindings.remove(name);
        }
    }
}

/// `update_exported_bindings`.
pub(crate) fn update_exported_bindings(
    segment: &[String],
    command_name: Option<&str>,
    command_index: Option<usize>,
    current_bindings: &Bindings,
    exported_bindings: &mut Bindings,
    suppress_removals: bool,
) {
    if let (Some("unset"), Some(index)) = (command_name, command_index) {
        if !suppress_removals {
            for token in &segment[index + 1..] {
                exported_bindings.remove(token);
            }
        }
        return;
    }
    let Some(index) = command_index else {
        return;
    };
    let arguments = &segment[index + 1..];
    let exports = command_name == Some("export")
        || (matches!(command_name, Some("declare" | "typeset"))
            && arguments
                .iter()
                .any(|token| token.starts_with('-') && token[1..].contains('x')));
    if !exports {
        return;
    }
    let removes_export = arguments
        .iter()
        .any(|token| token == "--unexport" || (token.starts_with('-') && token[1..].contains('n')));
    for token in arguments {
        if token.starts_with('-') {
            continue;
        }
        let name = token.split('=').next().unwrap_or("");
        if !is_shell_variable_name(name) {
            continue;
        }
        if !removes_export && current_bindings.contains(name) {
            exported_bindings.insert(name.to_owned());
        } else if !suppress_removals {
            exported_bindings.remove(name);
        }
    }
}

/// `segment_is_standalone_assignment`.
pub(crate) fn segment_is_standalone_assignment(segment: &[String]) -> bool {
    !segment.is_empty() && segment.iter().all(|token| token_is_shell_assignment(token))
}

/// `token_is_shell_assignment`.
pub(crate) fn token_is_shell_assignment(token: &str) -> bool {
    token
        .split_once('=')
        .is_some_and(|(name, _)| is_shell_variable_name(name))
}

/// `str.isdigit` for the first character of a variable name. Non-ASCII digits
/// are approximated by Unicode numerics that are not letters.
fn is_py_digit(character: char) -> bool {
    character.is_ascii_digit()
        || (!character.is_ascii() && character.is_numeric() && !character.is_alphabetic())
}

/// `is_shell_variable_name`.
pub(crate) fn is_shell_variable_name(name: &str) -> bool {
    let Some(first) = name.chars().next() else {
        return false;
    };
    !is_py_digit(first)
        && name
            .chars()
            .all(|character| character == '_' || python_is_alphanumeric(character))
}

/// `value_names_github_executable`.
pub(crate) fn value_names_github_executable(value: &str) -> bool {
    let normalized = strip_quotes(value);
    if normalized.chars().any(is_py_space) {
        return false;
    }
    let slashed = normalized.replace('\\', "/");
    let executable = slashed.rsplit('/').next().unwrap_or("").to_lowercase();
    executable.strip_suffix(".exe").unwrap_or(&executable) == "gh"
}

/// `conditional_pipeline_indexes`.
pub(crate) fn conditional_pipeline_indexes(parts: &[String]) -> HashSet<usize> {
    conditional_pipeline_connectors(parts).into_keys().collect()
}

/// `conditional_pipeline_connectors`.
pub(crate) fn conditional_pipeline_connectors(parts: &[String]) -> HashMap<usize, String> {
    let mut connectors = HashMap::new();
    let mut completed = 0usize;
    let mut in_pipeline = false;
    let mut pending: Option<String> = None;
    for raw_token in parts {
        let token = py_strip(raw_token);
        if token.is_empty() || token == "|" || token == "|&" {
            continue;
        }
        if !matches!(token, "&" | "&&" | ";" | "||") {
            if !in_pipeline {
                if completed > 0 {
                    if let Some(connector) = pending.take() {
                        connectors.insert(completed, connector);
                    }
                }
                pending = None;
                in_pipeline = true;
            }
            continue;
        }
        let follows_pipeline = in_pipeline;
        if in_pipeline {
            completed += 1;
            in_pipeline = false;
        }
        pending = if matches!(token, "&&" | "||") && follows_pipeline {
            Some(token.to_owned())
        } else {
            None
        };
    }
    connectors
}

/// `parent_expanded_variable_names`.
pub(crate) fn parent_expanded_variable_names(command_text: &str) -> Bindings {
    let visible = SINGLE_QUOTED.replace_all(command_text, "");
    VARIABLE
        .captures_iter(&visible)
        .filter_map(|captures| {
            captures
                .name("braced")
                .or_else(|| captures.name("plain"))
                .map(|found| found.as_str().to_owned())
        })
        .collect()
}

/// `complex_control_flow_may_invoke_github`.
pub(crate) fn complex_control_flow_may_invoke_github(
    command_text: &str,
    github_command_variables: &Bindings,
    github_command_text_variables: &Bindings,
) -> bool {
    if !COMPOUND_FLOW.is_match(command_text) {
        return false;
    }
    GITHUB_ASSIGNMENT.is_match(command_text)
        || LOOKUP_ASSIGNMENT.is_match(command_text).unwrap_or(true)
        || tokens_reference_github_variable(
            &[command_text.to_owned()],
            github_command_variables,
            github_command_text_variables,
        )
}

/// `dynamic_command_may_invoke_github`.
pub(crate) fn dynamic_command_may_invoke_github(
    command_name: &str,
    github_command_variables: &Bindings,
    github_command_text_variables: &Bindings,
) -> bool {
    let normalized = strip_quotes(command_name);
    let tracked = |name: &str| {
        matches!(name, "GH" | "gh")
            || github_command_variables.contains(name)
            || github_command_text_variables.contains(name)
    };
    if normalized.starts_with("${") && normalized.ends_with('}') && normalized.len() >= 3 {
        let expression = &normalized[2..normalized.len() - 1];
        let (variable_name, fallback) = [":-", "-"]
            .iter()
            .find_map(|operator| expression.split_once(operator))
            .unwrap_or((expression, ""));
        return tracked(variable_name) || value_names_github_executable(fallback);
    }
    if let Some(variable_name) = normalized.strip_prefix('$') {
        return tracked(variable_name);
    }
    false
}

/// `tokens_reference_github_variable`.
pub(crate) fn tokens_reference_github_variable(
    tokens: &[String],
    github_command_variables: &Bindings,
    github_command_text_variables: &Bindings,
) -> bool {
    tokens.iter().any(|token| {
        VARIABLE.captures_iter(token).any(|captures| {
            let name = captures
                .name("braced")
                .or_else(|| captures.name("plain"))
                .map_or("", |found| found.as_str());
            matches!(name, "GH" | "gh")
                || github_command_variables.contains(name)
                || github_command_text_variables.contains(name)
        })
    })
}
