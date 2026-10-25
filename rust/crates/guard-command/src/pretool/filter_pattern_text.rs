//! Text a pipeline filter matches: the pattern a later `grep` or `rg` stage
//! applies to the standard input it is handed. A stage proven to read only
//! its standard input opens no file, so a word such as `.git`, `.ssh/` or
//! `config` there names no path: it selects lines of output the earlier
//! stages already produced. Every other token of the command still meets the
//! sensitive-text and path screens, and a credential keyword in a pattern
//! still reads as a credential search.

use crate::{CanonicalCommandV1, CommandSegmentV1};

/// Whether `text`, the whole command, trips the sensitive-text floor once its
/// filter patterns are left out. `without_patterns` is the same text with the
/// arguments of each stdin-only matcher removed.
pub(super) fn sensitive_beyond_filters(text: &str, without_patterns: &str) -> bool {
    super::credential_keyword_text(text) || super::sensitive_command(without_patterns)
}

/// The command's text with each stdin-only matcher's arguments left out, or
/// `None` when no segment is one.
pub(super) fn command_without_patterns(model: &CanonicalCommandV1) -> Option<String> {
    let mut masked = false;
    let parts = model
        .segments
        .iter()
        .map(|segment| match segment_without_patterns(segment) {
            Some(text) => {
                masked = true;
                text
            }
            None => segment.text.clone(),
        })
        .collect::<Vec<_>>();
    masked.then(|| parts.join(" ; "))
}

/// Shell text that makes a word do more than match the lines it is handed: a
/// redirect opens a file, a glob or a brace expansion splits into further
/// operands, and a substitution brings in text no screen has seen. The model
/// keeps each of them inside the word it was written against.
const EXPANDABLE: [char; 12] = ['<', '>', '*', '?', '[', '{', '}', '$', '`', '&', ';', '('];

/// Whether a segment is a later pipeline stage whose words a caller may set
/// aside as patterns. Being handed standard input is not enough on its own:
/// `grep .env<.env` opens the very file the mask would hide, `grep -v .env*`
/// expands into one once `.env.local` exists beside it, and
/// `grep -v .env{,.local}` writes that second operand out itself, so a word
/// carrying shell syntax stays in view.
pub(super) fn maskable_filter_segment(segment: &CommandSegmentV1) -> bool {
    segment.pipeline_index > 0
        && !segment.arguments.is_empty()
        && segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.tokens.len() == segment.arguments.len() + 1
        && !segment
            .tokens
            .iter()
            .any(|token| token.contains(EXPANDABLE))
}

/// One segment's program name alone, when the segment is a later pipeline
/// stage whose arguments are proven to read only standard input. Those
/// arguments are switches, counts and patterns; the proof refuses a file
/// operand, a pattern file and a recursive walk, so none of them is a path
/// the stage opens.
fn segment_without_patterns(segment: &CommandSegmentV1) -> Option<String> {
    let executable = segment.executable.as_deref()?;
    if !maskable_filter_segment(segment) {
        return None;
    }
    let stdin_only = match super::executable_basename(executable) {
        "grep" | "egrep" | "fgrep" => super::search::safe_grep_stdin_arguments(&segment.arguments),
        "rg" => super::search::safe_rg_stdin_arguments(&segment.arguments),
        _ => false,
    };
    stdin_only.then(|| segment.tokens[0].clone())
}

#[cfg(test)]
#[path = "filter_pattern_text_tests.rs"]
mod tests;
