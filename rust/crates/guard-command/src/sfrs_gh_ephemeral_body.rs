//! Bounded recognition for one statically authored temporary PR body
//! (`secret_file_request_services/github_pr_ephemeral_body.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use regex::Regex;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::py_strip;
use crate::github_command_capabilities::static_markdown_pr_body_file_operand;
use crate::sfrs_gh_pr_expansion::shell_token_has_active_expansion;
use crate::sfrs_quote_tokens::{
    shell_token_segments, shell_tokens_preserving_quote_context, QuotedToken,
};
use crate::sfrs_substitution::github_argument_token_has_untrusted_expansion;
use crate::shell_structure::{
    extract_command_substitution_spans, extract_heredocs, mask_complete_heredocs,
};

const MAX_WORKFLOW_BYTES: usize = 192 * 1024;
const MAX_BODY_BYTES: usize = 128 * 1024;
const VARIABLE: &str = "[A-Za-z_][A-Za-z0-9_]*";

static VARIABLE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\A{VARIABLE}\z")).expect("variable pattern"));
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r#"\A(?P<name>{VARIABLE})="\$\(mktemp\)"\z"#)).expect("assignment pattern")
});
static STATIC_UNQUOTED_ARGUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[A-Za-z0-9_@%+=:,./-]+\z").expect("unquoted argument pattern"));

fn raws(segment: &[QuotedToken]) -> Vec<&str> {
    segment.iter().map(|token| token.raw.as_str()).collect()
}

/// `gh_pr_create_uses_safe_ephemeral_body`: accept one closed static heredoc
/// flowing only into one PR proposal.
pub(crate) fn gh_pr_create_uses_safe_ephemeral_body(command_text: &str, ctx: &Ctx) -> bool {
    if command_text.is_empty() || command_text.len() > MAX_WORKFLOW_BYTES {
        return false;
    }
    let heredocs = extract_heredocs(command_text);
    if heredocs.len() != 1 {
        return false;
    }
    let heredoc = &heredocs[0];
    if !heredoc.quoted || heredoc.body_end >= heredoc.end {
        return false;
    }
    if heredoc.body.is_empty() || heredoc.body.len() > MAX_BODY_BYTES {
        return false;
    }
    if ctx.host.secret_content_found(&heredoc.body, false) {
        return false;
    }
    let masked = mask_complete_heredocs(command_text, &heredocs);
    let segments = shell_token_segments(&shell_tokens_preserving_quote_context(&masked));
    if segments.len() < 3 {
        return false;
    }
    let Some(variable) = assignment_variable(&segments[0]) else {
        return false;
    };
    if !heredoc_writer_is_safe(&segments[1], &variable) {
        return false;
    }
    let substitutions = extract_command_substitution_spans(&masked);
    if substitutions.len() != 1 || py_strip(&substitutions[0].body) != "mktemp" {
        return false;
    }
    let mut pr_create_count = 0;
    let mut control_tokens: Vec<&str> = Vec::new();
    for segment in &segments[2..] {
        let Some(first) = segment.first() else {
            return false;
        };
        if first.raw == "#" {
            continue;
        }
        match first.plain.as_str() {
            command @ ("then" | "else" | "fi") => {
                if segment.len() != 1 || first.raw != command {
                    return false;
                }
                control_tokens.push(command);
            }
            "if" => {
                if !body_grep_is_safe(segment, &variable) {
                    return false;
                }
                control_tokens.push("if");
            }
            "echo" => {
                if !echo_is_safe(segment, &variable) {
                    return false;
                }
            }
            "cat" => {
                if !body_cat_is_safe(segment, &variable) {
                    return false;
                }
            }
            "exit" => {
                if raws(segment) != ["exit", "1"] {
                    return false;
                }
            }
            "gh" => {
                if !pr_create_is_safe(segment, &variable) {
                    return false;
                }
                pr_create_count += 1;
            }
            _ => return false,
        }
    }
    pr_create_count == 1
        && (control_tokens.is_empty() || control_tokens == ["if", "then", "else", "fi"])
}

/// `_assignment_variable`.
pub(crate) fn assignment_variable(segment: &[QuotedToken]) -> Option<String> {
    let [token] = segment else {
        return None;
    };
    ASSIGNMENT
        .captures(&token.raw)
        .map(|captures| captures["name"].to_owned())
}

/// `_heredoc_writer_is_safe`.
pub(crate) fn heredoc_writer_is_safe(segment: &[QuotedToken], variable: &str) -> bool {
    raws(segment) == ["cat", ">", format!("\"${variable}\"").as_str()]
}

/// `_body_cat_is_safe`.
pub(crate) fn body_cat_is_safe(segment: &[QuotedToken], variable: &str) -> bool {
    raws(segment) == ["cat", format!("\"${variable}\"").as_str()]
}

/// `_body_grep_is_safe`.
pub(crate) fn body_grep_is_safe(segment: &[QuotedToken], variable: &str) -> bool {
    segment.len() == 5
        && raws(&segment[..3]) == ["if", "grep", "-nE"]
        && segment[3].raw.starts_with('\'')
        && is_one_fully_quoted_word(&segment[3].raw)
        && !segment[3].plain.starts_with('-')
        && !shell_token_has_active_expansion(&segment[3].raw)
        && segment[4].raw == format!("\"${variable}\"")
}

/// `_echo_is_safe`.
pub(crate) fn echo_is_safe(segment: &[QuotedToken], variable: &str) -> bool {
    let Some(first) = segment.first() else {
        return false;
    };
    if first.raw != "echo" {
        return false;
    }
    if segment.len() == 1 {
        return true;
    }
    if segment.len() != 2 {
        return false;
    }
    let raw = &segment[1].raw;
    if let Some(inner) = raw
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix(&format!("=${variable}\"")))
    {
        if VARIABLE_PATTERN.is_match(inner) {
            return true;
        }
    }
    static_shell_argument(raw, false)
}

/// `_static_shell_argument`.
pub(crate) fn static_shell_argument(raw: &str, allow_unquoted: bool) -> bool {
    if raw.is_empty()
        || shell_token_has_active_expansion(raw)
        || raw.contains("<(")
        || raw.contains(">(")
    {
        return false;
    }
    if is_one_fully_quoted_word(raw) {
        return true;
    }
    allow_unquoted && STATIC_UNQUOTED_ARGUMENT.is_match(raw)
}

/// `_is_one_fully_quoted_word`.
pub(crate) fn is_one_fully_quoted_word(raw: &str) -> bool {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() < 2 {
        return false;
    }
    let quote = chars[0];
    if (quote != '\'' && quote != '"') || chars[chars.len() - 1] != quote {
        return false;
    }
    let mut index = 1;
    while index < chars.len() - 1 {
        let character = chars[index];
        if quote == '"' && character == '\\' {
            index += 2;
            continue;
        }
        if character == quote {
            return false;
        }
        index += 1;
    }
    index == chars.len() - 1
}

/// `_pr_create_is_safe`.
pub(crate) fn pr_create_is_safe(segment: &[QuotedToken], variable: &str) -> bool {
    if segment.len() < 5 || raws(&segment[..3]) != ["gh", "pr", "create"] {
        return false;
    }
    let body_operand = format!("${variable}");
    let quoted_operand = format!("\"${variable}\"");
    let mut sanitized_args: Vec<String> = Vec::new();
    let mut saw_body_variable = false;
    for token in &segment[3..] {
        if token.plain == body_operand {
            if token.raw != quoted_operand || saw_body_variable {
                return false;
            }
            sanitized_args.push("pr-body.md".to_owned());
            saw_body_variable = true;
            continue;
        }
        if github_argument_token_has_untrusted_expansion(&token.raw) {
            return false;
        }
        if !static_shell_argument(&token.raw, true) {
            return false;
        }
        sanitized_args.push(token.plain.clone());
    }
    saw_body_variable
        && static_markdown_pr_body_file_operand(&sanitized_args).as_deref() == Some("pr-body.md")
}
