//! Node heredoc and generated-file safety (`node_heredoc_safety.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::codex_output_py::py_strip;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::command_option_parsing::python_is_alphanumeric;
use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_gh_body_safety::path_text_looks_sensitive;
use crate::sfrs_node_redaction::{
    node_script_contains_non_file_generation_risk, script_references_destructive_file_call,
};
use crate::sfrs_node_templates::{
    js_string_literal_text, node_expand_template_value, node_generated_path_has_safe_root,
    node_path_without_template_placeholders, node_string_assignments,
    node_template_placeholders_are_safe_filename_fragments,
    single_node_heredoc_delimiter_is_quoted, single_node_heredoc_script, Assignments,
};
use crate::sfrs_patterns::{
    NODE_LOCAL_FILE_ACCESS_PATTERN, NODE_MUTATING_HTTP_PATTERN, NODE_READ_ONLY_HTTP_PATTERN,
    NODE_SENSITIVE_RUNTIME_PATTERN, SAFE_NODE_GENERATED_FILE_EXTENSIONS,
};

static WRITE_FILE_CALL: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r"(?:^|[^A-Za-z0-9_$])(?:fs[\s\x1c-\x1f]*\.[\s\x1c-\x1f]*)?writeFile(?:Sync)?[\s\x1c-\x1f]*\(",
    )
});

/// `_looks_like_safe_node_generated_file_heredoc`.
pub(crate) fn looks_like_safe_node_generated_file_heredoc(
    command_text: &str,
    script_text: &str,
) -> bool {
    if single_node_heredoc_script(command_text).is_none()
        || !single_node_heredoc_delimiter_is_quoted(command_text)
        || node_script_contains_non_file_generation_risk(script_text)
        || node_script_contains_disallowed_destructive_file_call(script_text)
    {
        return false;
    }
    let Some(targets) = node_write_file_targets(script_text) else {
        return false;
    };
    if targets.is_empty() {
        return false;
    }
    let assignments = node_string_assignments(script_text);
    targets
        .iter()
        .all(|target| node_write_target_is_safe_generated_file(target, &assignments))
}

/// `_looks_like_safe_node_read_only_http_heredoc`. A matcher failure refuses.
pub(crate) fn looks_like_safe_node_read_only_http_heredoc(
    command_text: &str,
    script_text: &str,
) -> bool {
    if !single_node_heredoc_delimiter_is_quoted(command_text) {
        return false;
    }
    if !NODE_READ_ONLY_HTTP_PATTERN
        .is_match(script_text)
        .unwrap_or(false)
    {
        return false;
    }
    [
        &NODE_MUTATING_HTTP_PATTERN,
        &NODE_LOCAL_FILE_ACCESS_PATTERN,
        &NODE_SENSITIVE_RUNTIME_PATTERN,
    ]
    .iter()
    .all(|pattern| !pattern.is_match(script_text).unwrap_or(true))
        && !node_script_contains_disallowed_destructive_file_call(script_text)
}

/// `_node_script_contains_disallowed_destructive_file_call`.
pub(crate) fn node_script_contains_disallowed_destructive_file_call(script_text: &str) -> bool {
    script_references_destructive_file_call(script_text, &["writeFile", "writeFileSync"])
}

/// `_node_write_file_targets`. `None` is a matcher failure.
pub(crate) fn node_write_file_targets(script_text: &str) -> Option<Vec<String>> {
    let mut targets = Vec::new();
    for found in WRITE_FILE_CALL.find_iter(script_text) {
        let found = found.ok()?;
        if let Some(target) = first_js_call_argument(script_text, found.end()) {
            targets.push(target);
        }
    }
    Some(targets)
}

/// `_first_js_call_argument`: `start` is a byte offset just after `(`.
pub(crate) fn first_js_call_argument(script_text: &str, start: usize) -> Option<String> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escape_next = false;
    let argument = |end: usize| {
        let text = py_strip(&script_text[start..end]);
        (!text.is_empty()).then(|| text.to_owned())
    };
    for (offset, character) in script_text[start..].char_indices() {
        let index = start + offset;
        if escape_next {
            escape_next = false;
        } else if character == '\\' {
            escape_next = true;
        } else if let Some(open) = quote {
            if character == open {
                quote = None;
            }
        } else if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
        } else if matches!(character, '(' | '[' | '{') {
            depth += 1;
        } else if matches!(character, ')' | ']' | '}') {
            if depth == 0 {
                return argument(index);
            }
            depth -= 1;
        } else if character == ',' && depth == 0 {
            return argument(index);
        }
    }
    None
}

/// `_node_write_target_is_safe_generated_file`.
pub(crate) fn node_write_target_is_safe_generated_file(
    target: &str,
    assignments: &Assignments,
) -> bool {
    let stripped = py_strip(target);
    let normalized = if let Some(value) = assignments.get(stripped) {
        value.to_owned()
    } else if let Some(text) = js_string_literal_text(stripped) {
        node_expand_template_value(text, assignments)
    } else {
        return false;
    };
    if node_generated_path_contains_shell_expansion(&normalized)
        || path_text_looks_sensitive(&normalized)
        || normalized.contains("../")
    {
        return false;
    }
    node_generated_path_has_safe_root(&normalized)
        && node_generated_path_has_safe_extension(&normalized)
}

/// `_node_generated_path_contains_shell_expansion`.
pub(crate) fn node_generated_path_contains_shell_expansion(path_text: &str) -> bool {
    if path_text.contains("$(")
        || path_text.contains('`')
        || path_text.contains("$'")
        || path_text.contains("$\"")
        || !node_template_placeholders_are_safe_filename_fragments(path_text)
    {
        return true;
    }
    let redacted = node_path_without_template_placeholders(path_text);
    if redacted.contains(['*', '?', '[', ']']) {
        return true;
    }
    let characters: Vec<char> = redacted.chars().collect();
    characters
        .windows(2)
        .any(|pair| pair[0] == '$' && (python_is_alphanumeric(pair[1]) || pair[1] == '_'))
}

/// `os.path.splitext(path)[1]`.
fn splitext_extension(path: &str) -> &str {
    let separator = path.rfind('/').map_or(0, |index| index + 1);
    let Some(dot) = path.rfind('.') else {
        return "";
    };
    if dot < separator {
        return "";
    }
    let bytes = path.as_bytes();
    let mut filename_index = separator;
    while filename_index < dot {
        if bytes[filename_index] != b'.' {
            return &path[dot..];
        }
        filename_index += 1;
    }
    ""
}

/// `_node_generated_path_has_safe_extension`.
pub(crate) fn node_generated_path_has_safe_extension(path_text: &str) -> bool {
    let without_templates = node_path_without_template_placeholders(path_text);
    let extension = splitext_extension(&without_templates).to_lowercase();
    SAFE_NODE_GENERATED_FILE_EXTENSIONS.contains(&extension.as_str())
}
