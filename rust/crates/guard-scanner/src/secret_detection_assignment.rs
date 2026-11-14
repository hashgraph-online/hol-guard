//! Generic credential assignments, found from their separators.
//!
//! The assignment pattern's bounded name and value repetitions are more than
//! the lazy DFA can hold for a long run of name-like text, such as a base64
//! payload: it gives up and the whole haystack falls to the PikeVM, about
//! 300 ms for one mebibyte. A name holds no separator, so a match's name ends
//! where the whitespace before its first separator starts, and its value
//! starts where the whitespace after that separator ends (a value may hold
//! more separators). Each match therefore lies inside a short window around
//! its first separator. The pattern runs only in windows whose separator can
//! carry a match, and yields what `captures_iter` over the whole text yields,
//! in the same order.
//!
//! Text dense with separators could make windows rescan each byte many times,
//! so the windows share a budget of a few times the text length. Once it is
//! spent, the rest of the text is searched whole, as `captures_iter` would.
use regex::{Captures, Regex};

/// Longest name the pattern accepts: one leading character and up to 80 more.
const MAX_NAME_BYTES: usize = 81;
/// Fewest name characters the pattern accepts.
const MIN_NAME_CHARS: usize = 2;
/// Value length bounds, and the most characters a value takes with both its
/// quotes.
const MIN_VALUE_CHARS: usize = 12;
const MAX_VALUE_CHARS: usize = 256;
const MAX_VALUE_CHARACTERS: usize = MAX_VALUE_CHARS + 2;
/// Window bytes allowed per text byte before searching the rest whole.
const WINDOW_BUDGET_PER_BYTE: usize = 4;

pub(super) struct AssignmentCaptures<'r, 't> {
    pattern: &'r Regex,
    text: &'t str,
    /// Where the next separator search starts.
    cursor: usize,
    /// Where the last match ended; no later match starts before it.
    matched_end: usize,
    /// No match starts before this: earlier windows found none there.
    floor: usize,
    /// Window bytes still allowed; at zero the rest is searched whole.
    budget: usize,
}

/// The pattern's matches in `text`, as `pattern.captures_iter(text)` gives
/// them. `pattern` must be the assignment pattern.
pub(super) fn assignment_captures<'r, 't>(
    pattern: &'r Regex,
    text: &'t str,
) -> AssignmentCaptures<'r, 't> {
    AssignmentCaptures {
        pattern,
        text,
        cursor: 0,
        matched_end: 0,
        floor: 0,
        budget: text.len().saturating_mul(WINDOW_BUDGET_PER_BYTE).max(4096),
    }
}

impl<'t> Iterator for AssignmentCaptures<'_, 't> {
    type Item = Captures<'t>;

    fn next(&mut self) -> Option<Captures<'t>> {
        let text = self.text;
        while self.cursor < text.len() {
            if self.budget == 0 {
                return self.whole();
            }
            let separator = self.cursor
                + text.as_bytes()[self.cursor..]
                    .iter()
                    .position(|byte| matches!(byte, b':' | b'='))?;
            self.cursor = separator + 1;
            let name_end = whitespace_start_before(text, separator);
            let value_start = whitespace_end_after(text, separator + 1);
            if !name_can_end(text, name_end) || !value_can_start(text, value_start) {
                continue;
            }
            // No earlier separator carries a match, so one that starts at or
            // after the last match and no later than this separator uses this
            // one, and its name ends at `name_end`.
            let mut start = name_end
                .saturating_sub(MAX_NAME_BYTES)
                .max(self.matched_end)
                .max(self.floor);
            while !text.is_char_boundary(start) {
                start += 1;
            }
            let end = text[value_start..]
                .char_indices()
                .nth(MAX_VALUE_CHARACTERS)
                .map_or(text.len(), |(index, _)| value_start + index);
            if start > separator {
                continue;
            }
            self.budget = self.budget.saturating_sub(end - start);
            let Some(captures) = self.pattern.captures_at(&text[..end], start) else {
                // Nothing starts between `start` and this separator.
                self.floor = separator + 1;
                continue;
            };
            let whole = captures.get(0).expect("whole match always present");
            // A match that starts past this separator uses a later one, whose
            // value this window may have cut short. That separator's own
            // window finds it whole.
            if whole.start() > separator {
                self.floor = separator + 1;
                continue;
            }
            self.cursor = whole.end();
            self.matched_end = whole.end();
            return Some(captures);
        }
        None
    }
}

impl<'t> AssignmentCaptures<'_, 't> {
    /// The next match searched over the whole rest of the text.
    fn whole(&mut self) -> Option<Captures<'t>> {
        let captures = self.pattern.captures_at(self.text, self.matched_end)?;
        let end = captures.get(0).expect("whole match always present").end();
        // The pattern never matches empty text; step past one anyway.
        self.matched_end = if end > self.matched_end {
            end
        } else {
            self.text.len()
        };
        self.cursor = self.matched_end;
        Some(captures)
    }
}

fn whitespace_start_before(text: &str, at: usize) -> usize {
    text[..at]
        .char_indices()
        .rev()
        .find(|(_, character)| !character.is_whitespace())
        .map_or(0, |(index, character)| index + character.len_utf8())
}

fn whitespace_end_after(text: &str, at: usize) -> usize {
    text[at..]
        .char_indices()
        .find(|(_, character)| !character.is_whitespace())
        .map_or(text.len(), |(index, _)| at + index)
}

/// At least the shortest name stands right before `at`.
fn name_can_end(text: &str, at: usize) -> bool {
    at >= MIN_NAME_CHARS
        && text.as_bytes()[at - MIN_NAME_CHARS..at]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// A value the pattern accepts starts at `at`: a quoted one closed by its own
/// quote within the bounds, or an unquoted one of at least the shortest length.
fn value_can_start(text: &str, at: usize) -> bool {
    let rest = &text[at..];
    let quote = rest
        .chars()
        .next()
        .filter(|character| matches!(character, '"' | '\''));
    let body = &rest[quote.map_or(0, char::len_utf8)..];
    let length = body
        .chars()
        .take(MAX_VALUE_CHARS + 1)
        .take_while(|character| value_character(*character))
        .count();
    match quote {
        None => length >= MIN_VALUE_CHARS,
        Some(quote) => {
            (MIN_VALUE_CHARS..=MAX_VALUE_CHARS).contains(&length)
                && body[body
                    .char_indices()
                    .nth(length)
                    .map_or(body.len(), |(index, _)| index)..]
                    .starts_with(quote)
        }
    }
}

fn value_character(character: char) -> bool {
    !character.is_whitespace() && !matches!(character, '"' | '\'' | ',' | '}' | '{')
}

#[cfg(test)]
#[path = "secret_detection_assignment_tests.rs"]
mod tests;
