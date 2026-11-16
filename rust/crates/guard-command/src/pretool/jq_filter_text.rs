//! The text a `jq` step shows the credential-word screen, without its filter.
//!
//! That screen looks for words such as `secret` or `password` anywhere in a
//! step. A filter that clears the grammar in `jq_filter` is a pure function of
//! the value jq reads: it reaches no file, no environment and no module. A word
//! inside it, as in `test("secret-blast")` or `.password`, names a key or a
//! string in that value, never anything on this machine. Only the filter's own
//! quoted word is blanked, so input files, `--arg` values and redirects keep
//! the screen.

use crate::CommandSegmentV1;

/// `segment.text` with the filter at `index` blanked to `''`.
///
/// The filter must be written as one single-quoted word, and that word must
/// appear exactly once in the text, with blank space or the end of the text on
/// both sides, and the blanked text must parse to the same words with only
/// the filter emptied. Any other spelling keeps the whole text on the screen.
pub(super) fn without_jq_filter(segment: &CommandSegmentV1, index: usize) -> Option<String> {
    let filter = segment.arguments.get(index)?;
    if filter.contains('\'') {
        return None;
    }
    let quoted = format!("'{filter}'");
    let mut found = segment.text.match_indices(&quoted).map(|(start, _)| start);
    let start = found.next()?;
    if found.next().is_some() {
        return None;
    }
    let end = start + quoted.len();
    let before = segment.text[..start].chars().next_back();
    let after = segment.text[end..].chars().next();
    if !before.is_some_and(char::is_whitespace) || !after.is_none_or(char::is_whitespace) {
        return None;
    }
    let mut text = segment.text.clone();
    text.replace_range(start..end, "''");
    only_the_filter_changed(segment, index, &text).then_some(text)
}

/// Whether `text` parses to `segment`'s own words with only the word at
/// `index` emptied. A quoted copy of the filter inside another word, as in
/// `--arg note " '.secret' "` before a filter spelled `.se''cret`, changes a
/// different word and so keeps the whole text on the screen.
fn only_the_filter_changed(segment: &CommandSegmentV1, index: usize, text: &str) -> bool {
    let Ok(model) = crate::parse_command(&crate::CommandModelRequestV1 {
        command: text.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    }) else {
        return false;
    };
    let [blanked] = model.segments.as_slice() else {
        return false;
    };
    blanked.executable == segment.executable
        && blanked.arguments.len() == segment.arguments.len()
        && blanked
            .arguments
            .iter()
            .zip(&segment.arguments)
            .enumerate()
            .all(|(position, (now, before))| {
                if position == index {
                    now.is_empty()
                } else {
                    now == before
                }
            })
}

#[cfg(test)]
#[path = "jq_filter_text_tests.rs"]
mod tests;
