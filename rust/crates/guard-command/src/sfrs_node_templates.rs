//! Node script string assignments and template placeholders
//! (`node_generated_workflows.py`: the pure text helpers).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::codex_output_py::{py_lstrip, py_splitlines, py_strip};
use crate::command_option_parsing::python_is_alphanumeric;
use crate::sfrs_patterns::{SAFE_NODE_GENERATED_FILE_ROOTS, SINGLE_NODE_HEREDOC_PATTERN};

/// Insertion-ordered `dict[str, str]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Assignments {
    entries: Vec<(String, String)>,
}

impl Assignments {
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    fn set(&mut self, name: &str, value: String) {
        match self.entries.iter_mut().find(|(key, _)| key == name) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((name.to_owned(), value)),
        }
    }

    /// A mapping built from ordered pairs (test replay of recorded dicts).
    #[cfg(test)]
    pub(crate) fn from_pairs(pairs: &[(String, String)]) -> Self {
        let mut assignments = Self::default();
        for (name, value) in pairs {
            assignments.set(name, value.clone());
        }
        assignments
    }

    pub(crate) fn items(&self) -> &[(String, String)] {
        &self.entries
    }
}

/// `_single_node_heredoc_script`: a `node` heredoc with no or a `-` argument.
pub(crate) fn single_node_heredoc_script(command_text: &str) -> Option<String> {
    let captures = SINGLE_NODE_HEREDOC_PATTERN
        .captures(py_strip(command_text))
        .ok()??;
    let args = py_strip(captures.name("args")?.as_str());
    if !args.is_empty() && args != "-" {
        return None;
    }
    let script = py_strip(captures.name("body")?.as_str());
    (!script.is_empty()).then(|| script.to_owned())
}

/// `_single_node_heredoc_delimiter_is_quoted`.
pub(crate) fn single_node_heredoc_delimiter_is_quoted(command_text: &str) -> bool {
    let Ok(Some(captures)) = SINGLE_NODE_HEREDOC_PATTERN.captures(py_strip(command_text)) else {
        return false;
    };
    let args = captures
        .name("args")
        .map_or("", |group| py_strip(group.as_str()));
    (args.is_empty() || args == "-")
        && captures
            .name("quote")
            .is_some_and(|group| !group.as_str().is_empty())
}

/// `_node_string_assignments`: up to three passes over the script lines.
pub(crate) fn node_string_assignments(script_text: &str) -> Assignments {
    let mut assignments = Assignments::default();
    for _ in 0..3 {
        let mut changed = false;
        for line in py_splitlines(script_text) {
            let Some((name, raw_value)) = node_string_assignment_from_line(&line) else {
                continue;
            };
            let expanded = node_expand_template_value(&raw_value, &assignments);
            if assignments.get(&name) != Some(expanded.as_str()) {
                assignments.set(&name, expanded);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    assignments
}

/// `_node_string_assignment_from_line`.
pub(crate) fn node_string_assignment_from_line(line: &str) -> Option<(String, String)> {
    let stripped = py_strip(line).trim_end_matches(';');
    for prefix in ["const ", "let ", "var "] {
        let Some(rest) = stripped.strip_prefix(prefix) else {
            continue;
        };
        let rest = py_lstrip(rest);
        let name_end = rest
            .char_indices()
            .find(|(_, c)| !(python_is_alphanumeric(*c) || *c == '_' || *c == '$'))
            .map_or(rest.len(), |(index, _)| index);
        if name_end == 0 {
            return None;
        }
        let name = &rest[..name_end];
        let remainder = py_lstrip(&rest[name_end..]);
        let value = py_lstrip(remainder.strip_prefix('=')?);
        let quote = value.chars().next()?;
        if !matches!(quote, '\'' | '"' | '`') {
            return None;
        }
        let literal = read_js_quoted_literal(value, quote)?;
        return Some((name.to_owned(), literal));
    }
    None
}

/// `_read_js_quoted_literal`: `value[0]` is the opening quote.
pub(crate) fn read_js_quoted_literal(value: &str, quote: char) -> Option<String> {
    let mut result = String::new();
    let mut escape_next = false;
    for character in value.chars().skip(1) {
        if escape_next {
            result.push(character);
            escape_next = false;
        } else if character == '\\' {
            escape_next = true;
        } else if character == quote {
            return Some(result);
        } else {
            result.push(character);
        }
    }
    None
}

/// `_node_expand_template_value`.
pub(crate) fn node_expand_template_value(value: &str, assignments: &Assignments) -> String {
    let mut expanded = value.to_owned();
    for (name, assigned) in assignments.items() {
        expanded = expanded.replace(&format!("${{{name}}}"), assigned);
    }
    expanded
}

/// `_js_string_literal_text`.
pub(crate) fn js_string_literal_text(value: &str) -> Option<&str> {
    let mut chars = value.chars();
    let (first, last) = (chars.next()?, chars.next_back()?);
    (first == last && matches!(first, '\'' | '"' | '`')).then(|| &value[1..value.len() - 1])
}

/// `_node_generated_path_has_safe_root`.
pub(crate) fn node_generated_path_has_safe_root(path_text: &str) -> bool {
    let lowered = path_text.to_lowercase();
    SAFE_NODE_GENERATED_FILE_ROOTS
        .iter()
        .any(|root| lowered.starts_with(root))
}

/// `_node_template_placeholders_are_safe_filename_fragments`.
pub(crate) fn node_template_placeholders_are_safe_filename_fragments(path_text: &str) -> bool {
    let mut rest = path_text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return false;
        };
        if !node_template_placeholder_is_safe_filename_fragment(py_strip(&after[..end])) {
            return false;
        }
        rest = &after[end + 1..];
    }
    true
}

/// `_node_template_placeholder_is_safe_filename_fragment`.
pub(crate) fn node_template_placeholder_is_safe_filename_fragment(placeholder: &str) -> bool {
    if !placeholder.starts_with("String(") || !placeholder.contains(".padStart(") {
        return false;
    }
    let lowered = placeholder.to_lowercase();
    if ["process", "require", "env", "import", "fs", "path", "child"]
        .iter()
        .any(|token| lowered.contains(token))
    {
        return false;
    }
    let Some((numeric_prefix, padding_suffix)) = placeholder.split_once(".padStart(") else {
        return false;
    };
    !numeric_prefix.contains(['\'', '"', '\\', '`', '[', ']'])
        && !padding_suffix.contains(['/', '\\', '`', '[', ']'])
}

/// `_node_path_without_template_placeholders`: each `${...}` becomes `x`.
pub(crate) fn node_path_without_template_placeholders(path_text: &str) -> String {
    let mut result = String::new();
    let mut rest = path_text;
    loop {
        let Some(start) = rest.find("${") else {
            result.push_str(rest);
            break;
        };
        result.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            result.push_str(&rest[start..]);
            break;
        };
        result.push('x');
        rest = &after[end + 1..];
    }
    result
}
