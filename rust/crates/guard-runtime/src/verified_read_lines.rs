//! Line boundaries for a verified read: which bytes of a permitted file the
//! plan's selection names.
//!
//! The resident is shared, so a read of a permitted file never holds a
//! reference for every line of it. Boundaries are walked once and only the
//! selected byte range is kept, which bounds the work a dense file can ask
//! for to the slice the request actually shows.

use std::iter::Peekable;
use std::str::CharIndices;

use guard_contracts::VerifiedReadSelectionV1;

/// The end offset of each line of `text`, in order, with Python's line
/// boundaries. A final line without a terminator ends at `text.len()`.
struct LineEnds<'a> {
    text: &'a str,
    characters: Peekable<CharIndices<'a>>,
    start: usize,
}

impl Iterator for LineEnds<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        while let Some((index, character)) = self.characters.next() {
            let end = match character {
                '\r' if self
                    .characters
                    .peek()
                    .is_some_and(|(_, next)| *next == '\n') =>
                {
                    self.characters.next();
                    index + 2
                }
                '\r' | '\n' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}'
                | '\u{2028}' | '\u{2029}' => index + character.len_utf8(),
                _ => continue,
            };
            self.start = end;
            return Some(end);
        }
        if self.start < self.text.len() {
            self.start = self.text.len();
            return Some(self.text.len());
        }
        None
    }
}

/// `str.splitlines(keepends=True)`, with every line boundary Python reads.
fn line_ends(text: &str) -> LineEnds<'_> {
    LineEnds {
        text,
        characters: text.char_indices().peekable(),
        start: 0,
    }
}

/// `_selected`: the text of the lines the plan allows, clamped the way Python
/// slicing clamps, without materializing a reference for every line.
pub(crate) fn selected<'a>(text: &'a str, selection: &VerifiedReadSelectionV1) -> &'a str {
    let (from, to) = match selection {
        VerifiedReadSelectionV1::WorkingDirectory {} => (0, 0),
        VerifiedReadSelectionV1::LeadingLines { count } => (0, *count as usize),
        VerifiedReadSelectionV1::TrailingLines { count } => {
            // A tail names its lines from the end, so the count is the one
            // thing a single pass cannot know; counting boundaries keeps no
            // line and walks the same text twice.
            let total = line_ends(text).count();
            (total.saturating_sub(*count as usize), total)
        }
        VerifiedReadSelectionV1::LineRange { start, end } => {
            ((*start as usize).saturating_sub(1), *end as usize)
        }
    };
    slice_lines(text, from, to)
}

/// The bytes of lines `from..to`, or nothing when the file has no line `from`.
fn slice_lines(text: &str, from: usize, to: usize) -> &str {
    if to <= from {
        return "";
    }
    let mut begin = None;
    let mut finish = text.len();
    let mut previous = 0;
    for (index, end) in line_ends(text).enumerate() {
        if index == from {
            begin = Some(previous);
        }
        previous = end;
        if index + 1 == to {
            finish = end;
            break;
        }
    }
    match begin {
        Some(start) => &text[start..finish.max(start)],
        None => "",
    }
}

/// The lines themselves, kept for the parity tests that pin the boundaries
/// against `str.splitlines(keepends=True)`.
#[cfg(test)]
pub(crate) fn split_lines_keepends(text: &str) -> Vec<&str> {
    let mut start = 0;
    line_ends(text)
        .map(|end| {
            let line = &text[start..end];
            start = end;
            line
        })
        .collect()
}

#[cfg(test)]
#[path = "verified_read_lines_tests.rs"]
mod tests;
