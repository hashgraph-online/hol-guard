//! Source-file read exemption: words such as "password" in a plain source
//! file name describe code, not a credential store.

use super::{exact_safe_command, executable_basename, parse_command, sensitive_command};
use crate::CommandModelRequestV1;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::Path;

#[path = "source_reader_options.rs"]
mod source_reader_options;

/// A single plain relative-or-absolute path token naming a source-code file.
/// Words such as "password" in its name describe code, not a credential store.
pub(super) fn plain_source_code_path(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.contains(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '$' | '`'
                        | ';'
                        | '|'
                        | '&'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '{'
                        | '}'
                        | '*'
                        | '?'
                        | '"'
                        | '\''
                        | '='
                        | ':'
                        | '\\'
                        | '~'
                        | '!'
                )
        })
    {
        return false;
    }
    Path::new(trimmed)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(guard_secure_fs::is_source_code_extension)
}

/// Plain source-file reads only. Each argument is rechecked on its own, so
/// credential-family paths still match. A chain qualifies when every segment
/// is such a read, a `cd` into a plain directory or a literal `echo` line.
fn exact_source_file_read(model: &CanonicalCommandV1) -> bool {
    if model.confidence != "exact"
        || model.path_overridden
        || model.segments.is_empty()
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    model.segments.iter().any(source_file_read_segment)
        && model.segments.iter().all(|segment| {
            source_file_read_segment(segment)
                || plain_directory_change(segment)
                || literal_echo(segment)
        })
}

/// `echo ---` and the like: literal words printed to the same output, with no
/// expansion, redirect or credential word.
fn literal_echo(segment: &CommandSegmentV1) -> bool {
    segment.executable.as_deref() == Some("echo")
        && segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && segment.tokens.len() == segment.arguments.len() + 1
        && segment.arguments.iter().all(|word| {
            !word.contains(['$', '`', '>', '<', '~', '*', '?']) && !sensitive_command(word)
        })
}

/// `cd DIR` into a plain directory whose name carries no credential word.
fn plain_directory_change(segment: &CommandSegmentV1) -> bool {
    segment.executable.as_deref().map(executable_basename) == Some("cd")
        && segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && matches!(segment.arguments.as_slice(), [directory]
            if !directory.starts_with('-')
                && !directory.contains(['$', '`', '~', '*', '?'])
                && !sensitive_command(directory))
}

/// `cat`, `head`, `tail`, `wc`, `nl` or a line-printing `sed -n` over plain
/// source-code file tokens only.
pub(super) fn source_file_read_segment(segment: &CommandSegmentV1) -> bool {
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let name = executable_basename(executable);
    let operands = if name == "sed" {
        source_reader_options::sed_print_operands(&segment.arguments)
    } else {
        source_reader_options::reader_operands(name, &segment.arguments)
    };
    // A lone `-` is the stdin operand, and stdin is not a source file.
    operands.is_some_and(|operands| {
        !operands.is_empty()
            && operands
                .iter()
                .all(|argument| plain_source_code_path(argument) && !sensitive_command(argument))
    })
}

fn exact_safe_search_command(model: &CanonicalCommandV1) -> bool {
    exact_safe_command(model, false)
        && model.segments.iter().all(|segment| {
            segment
                .executable
                .as_deref()
                .is_some_and(|executable| matches!(executable_basename(executable), "rg" | "grep"))
        })
}

pub(super) fn sensitive_command_input(value: &str) -> bool {
    let value = &super::data_heredocs::without_data_bodies(value);
    if !sensitive_command(value) {
        return false;
    }
    let request = CommandModelRequestV1 {
        command: value.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    };
    // Only parsed, bounded search data may shed the raw keyword signal.
    // Structured paths, prompts, URLs and arbitrary executable text keep it.
    !parse_command(&request).is_ok_and(|model| {
        exact_safe_search_command(&model)
            || exact_source_file_read(&model)
            || super::search_pattern_text::command_without_patterns(&model).is_some_and(|rest| {
                !super::git_search_text::sensitive_beyond_patterns(value, Some(rest))
            })
    })
}
