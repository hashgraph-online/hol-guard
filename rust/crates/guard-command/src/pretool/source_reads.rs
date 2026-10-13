//! Source-file read exemption: words such as "password" in a plain source
//! file name describe code, not a credential store.

use super::{exact_safe_command, executable_basename, parse_command, sensitive_command};
use crate::CommandModelRequestV1;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::Path;

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

/// `cat`/`head`/`tail`/`wc` over plain source-code file tokens only. Each
/// argument is rechecked on its own, so credential-family paths still match.
fn exact_source_file_read(model: &CanonicalCommandV1) -> bool {
    if model.confidence != "exact"
        || model.path_overridden
        || model.segments.len() != 1
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    source_file_read_segment(&model.segments[0])
}

pub(super) fn source_file_read_segment(segment: &CommandSegmentV1) -> bool {
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    if !matches!(
        executable_basename(executable),
        "cat" | "head" | "tail" | "wc" | "nl"
    ) {
        return false;
    }
    // Options end at `--`; a lone `-` is the stdin operand, never an option,
    // and stdin is not a source file, so it disqualifies the exemption.
    let mut options_ended = false;
    let mut operands = 0_usize;
    for argument in &segment.arguments {
        if !options_ended && argument == "--" {
            options_ended = true;
        } else if !options_ended && argument.starts_with('-') && argument != "-" {
            if argument.len() > 3 || argument.contains(|c: char| c.is_alphabetic() && c != 'n') {
                return false;
            }
        } else if plain_source_code_path(argument) && !sensitive_command(argument) {
            operands += 1;
        } else {
            return false;
        }
    }
    operands > 0
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
            || super::git_search_text::command_without_patterns(&model).is_some_and(|rest| {
                !super::git_search_text::sensitive_beyond_patterns(value, Some(rest))
            })
    })
}
