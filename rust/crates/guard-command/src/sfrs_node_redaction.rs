//! Node script scanning for destructive file calls
//! (`typescript_graphql_safety.py`: `_redacted_node_inline_string_literals`,
//! `script_references_destructive_file_call` and the sensitive-runtime checks).
//!
//! The scan runs over two redactions of the script so a string-literal member
//! name cannot smuggle a call through. A matcher failure counts as a hit:
//! the answer feeds an allow-list, so the safe side is "destructive".

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::codex_output_py::is_py_space;
use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_gh_body_safety::path_text_looks_sensitive;
use crate::sfrs_patterns::DESTRUCTIVE_NODE_INLINE_CALLS;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Comment {
    Line,
    Block,
}

/// Mutable scanner state of `_redacted_node_inline_string_literals`.
#[derive(Default)]
struct Redactor {
    result: Vec<String>,
    quote: Option<char>,
    escape_next: bool,
    preserve: bool,
    depth: usize,
    comment: Option<Comment>,
    regex_literal: bool,
    regex_escape: bool,
    regex_class: bool,
}

/// `_last_non_whitespace_character` over the chunk list.
pub(crate) fn last_non_whitespace_character(result: &[String]) -> Option<char> {
    result
        .iter()
        .rev()
        .flat_map(|chunk| chunk.chars().rev())
        .find(|character| !is_py_space(*character))
}

/// `_js_slash_starts_regex`.
pub(crate) fn js_slash_starts_regex(result: &[String]) -> bool {
    last_non_whitespace_character(result).is_none_or(|previous| {
        matches!(
            previous,
            '(' | '{'
                | '['
                | '='
                | ':'
                | ','
                | ';'
                | '!'
                | '?'
                | '|'
                | '&'
                | '+'
                | '-'
                | '*'
                | '%'
                | '^'
                | '~'
        )
    })
}

impl Redactor {
    fn push(&mut self, text: impl Into<String>) {
        self.result.push(text.into());
    }

    /// One character while inside a template expression; `true` when consumed.
    fn template_expression(&mut self, chars: &[char], index: &mut usize) -> bool {
        let character = chars[*index];
        if self.comment == Some(Comment::Line) {
            self.push(character);
            if matches!(character, '\n' | '\r') {
                self.comment = None;
            }
            *index += 1;
            return true;
        }
        if self.comment == Some(Comment::Block) {
            self.push(character);
            let len = self.result.len();
            if character == '/' && len >= 2 && self.result[len - 2] == "*" {
                self.comment = None;
            }
            *index += 1;
            return true;
        }
        if self.regex_literal {
            self.push(character);
            if self.regex_escape {
                self.regex_escape = false;
            } else if character == '\\' {
                self.regex_escape = true;
            } else if character == '[' && !self.regex_class {
                self.regex_class = true;
            } else if character == ']' && self.regex_class {
                self.regex_class = false;
            } else if character == '/' && !self.regex_class {
                self.regex_literal = false;
            }
            *index += 1;
            return true;
        }
        if character == '/' && *index + 1 < chars.len() {
            match chars[*index + 1] {
                '/' => {
                    self.push("//");
                    self.comment = Some(Comment::Line);
                    *index += 2;
                    return true;
                }
                '*' => {
                    self.push("/*");
                    self.comment = Some(Comment::Block);
                    *index += 2;
                    return true;
                }
                _ if js_slash_starts_regex(&self.result) => {
                    self.push(character);
                    self.regex_literal = true;
                    self.regex_escape = false;
                    self.regex_class = false;
                    *index += 1;
                    return true;
                }
                _ => {}
            }
        }
        if character == '{' {
            self.depth += 1;
            self.push(character);
            *index += 1;
            return true;
        }
        if character == '}' {
            self.depth -= 1;
            self.push(character);
            if self.depth == 0 {
                self.quote = Some('`');
                self.comment = None;
                self.regex_literal = false;
                self.regex_escape = false;
                self.regex_class = false;
            }
            *index += 1;
            return true;
        }
        false
    }

    fn outside_string(&mut self, chars: &[char], index: &mut usize, bracket_members: bool) {
        if self.depth > 0 && self.template_expression(chars, index) {
            return;
        }
        let character = chars[*index];
        if matches!(character, '\'' | '"' | '`') {
            self.preserve =
                bracket_members && last_non_whitespace_character(&self.result) == Some('[');
            self.quote = Some(character);
        }
        self.push(character);
        *index += 1;
    }

    fn inside_string(&mut self, chars: &[char], index: &mut usize, quote: char) {
        let character = chars[*index];
        let redacted = |preserve: bool| if preserve { character } else { 'Q' };
        if self.escape_next {
            self.push(redacted(self.preserve));
            self.escape_next = false;
            *index += 1;
        } else if character == '\\' {
            self.push(character);
            self.escape_next = true;
            *index += 1;
        } else if quote == '`' && character == '$' && chars.get(*index + 1) == Some(&'{') {
            self.push("${");
            self.quote = None;
            self.preserve = false;
            self.depth = 1;
            *index += 2;
        } else if character == quote {
            self.push(character);
            self.quote = None;
            self.preserve = false;
            *index += 1;
        } else {
            self.push(redacted(self.preserve));
            *index += 1;
        }
    }
}

/// `_redacted_node_inline_string_literals`.
pub(crate) fn redacted_node_inline_string_literals(
    script: &str,
    preserve_bracket_member_strings: bool,
) -> String {
    let chars: Vec<char> = script.chars().collect();
    let mut state = Redactor::default();
    let mut index = 0;
    while index < chars.len() {
        match state.quote {
            None => state.outside_string(&chars, &mut index, preserve_bracket_member_strings),
            Some(quote) => state.inside_string(&chars, &mut index, quote),
        }
    }
    state.result.concat()
}

struct CallPatterns {
    name: &'static str,
    direct: FancyRegex,
    members: Vec<FancyRegex>,
}

static CALL_PATTERNS: LazyLock<Vec<CallPatterns>> = LazyLock::new(|| {
    DESTRUCTIVE_NODE_INLINE_CALLS
        .iter()
        .map(|name| {
            let escaped = fancy_regex::escape(name);
            let members = [
                format!(r"\.\s*{escaped}"),
                format!(r#"\[\s*['"]{escaped}['"]\s*\]"#),
            ]
            .iter()
            .flat_map(|base| {
                [
                    format!(r"{base}\s*(?:\?\.\s*)?(?:\)\s*)?\("),
                    format!(r"{base}\s*(?:\?\s*)?\.\s*call\s*\("),
                    format!(r"{base}\s*(?:\?\s*)?\.\s*apply\s*\("),
                ]
            })
            .map(|pattern| compile_fancy(&pattern))
            .collect();
            CallPatterns {
                name,
                direct: compile_fancy(&format!(
                    r#"(?<![A-Za-z0-9_$'"]){escaped}\s*(?:\?\.\s*)?\("#
                )),
                members,
            }
        })
        .collect()
});

fn hit(pattern: &FancyRegex, text: &str) -> bool {
    pattern.is_match(text).unwrap_or(true)
}

/// `script_references_destructive_file_call`.
pub(crate) fn script_references_destructive_file_call(script: &str, allowed: &[&str]) -> bool {
    let redacted = redacted_node_inline_string_literals(script, false);
    let member_scan = redacted_node_inline_string_literals(script, true);
    CALL_PATTERNS
        .iter()
        .filter(|calls| !allowed.contains(&calls.name))
        .any(|calls| {
            hit(&calls.direct, &redacted)
                || calls.members.iter().any(|member| hit(member, &member_scan))
        })
}

/// `_contains_destructive_node_inline_script`.
pub(crate) fn contains_destructive_node_inline_script(script: &str) -> bool {
    script_references_destructive_file_call(script, &[])
}

static NON_FILE_RISK: LazyLock<Vec<FancyRegex>> = LazyLock::new(|| {
    [
        r"\b(?:fetch|xmlhttprequest)[\s\x1c-\x1f]*\(",
        r"\b(?:http|https|net|tls|dgram)[\s\x1c-\x1f]*\.",
        r#"\brequire[\s\x1c-\x1f]*\([\s\x1c-\x1f]*['"](?:child_process|http|https|net|tls|dgram)['"][\s\x1c-\x1f]*\)"#,
        r"\b(?:exec|execfile|execfilesync|execsync|spawn|spawnsync|fork)[\s\x1c-\x1f]*\(",
        r"\b(?:eval|function)[\s\x1c-\x1f]*\(",
    ]
    .iter()
    .map(|pattern| compile_fancy(pattern))
    .collect()
});

/// `_node_script_contains_non_file_generation_risk`.
pub(crate) fn node_script_contains_non_file_generation_risk(script_text: &str) -> bool {
    if path_text_looks_sensitive(script_text) {
        return true;
    }
    let lowered = script_text.to_lowercase();
    NON_FILE_RISK.iter().any(|pattern| hit(pattern, &lowered))
}

/// `_node_script_contains_sensitive_runtime_behavior`.
pub(crate) fn node_script_contains_sensitive_runtime_behavior(script_text: &str) -> bool {
    script_references_destructive_file_call(script_text, &[])
        || node_script_contains_non_file_generation_risk(script_text)
}
