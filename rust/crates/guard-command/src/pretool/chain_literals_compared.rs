//! A substitution whose value is only compared as a string: `[ -n "$(git
//! status --porcelain)" ]` or `test "$(git rev-parse HEAD)" = "$(git
//! rev-parse origin/main)"`.
//!
//! An agent checks a read's output before deciding what to run next. The
//! value lands in a double-quoted operand of `[` or `test`, a builtin that
//! compares strings and has no other effect. What the shell does is then the
//! inner command plus a comparison of its output, and the inner command is
//! judged as a command of its own by the caller before the projection is
//! used. The value is written as the printed stand-in, and the rest of the
//! chain is judged on that text.
//!
//! Only the string forms are read: one operand (`[ "$(cmd)" ]`), `-n` or
//! `-z` and one operand, or two operands joined by `=`, `==` or `!=`. The
//! slot is refused when:
//!
//! - the operand is not a double-quoted substitution of its own, where the
//!   shell would split and glob the value into words of its own;
//! - the test is `[[ ... ]]`, which matches its right operand as a pattern
//!   and evaluates arithmetic operands;
//! - an operator compares numbers (`-eq`, `-gt`, ...): zsh evaluates those
//!   operands as arithmetic expressions, which can assign a variable or run
//!   a substitution held in the value;
//! - an operator tests a file (`-f`, `-d`, ...), so the value would be a path;
//! - any other word of the test is not a plain literal: a variable, a
//!   pattern, a `~` or a zsh `=name` expansion;
//! - grouping, a subshell or a redirection appears in the text up to the end
//!   of the test (`(`, `)`, `{`, `}`, `<`, `>`);
//! - anything earlier in the chain could change what the inner command reads
//!   (`cd`, an assignment, `alias`, a function definition), or a loop runs
//!   the test again after such a change;
//! - the command uses `$'...'`, `$"..."` or a `#` comment, whose quoting this
//!   scan does not read as the shell does.

use super::{commented, dollar_quoted, looped, steered, MAX_BODY_CHARS};
use crate::shell_structure::ShellCommandSubstitution;

/// One word of the test: a double-quoted substitution or a plain literal.
#[derive(Debug, PartialEq)]
enum Word {
    Value(usize),
    Literal(String),
}

/// Whether `substitution` is an operand of a `[` or `test` that only
/// compares it as a string.
///
/// `chars` is the heredoc-masked command, which keeps every index.
pub(in super::super) fn compared(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    substitution: &ShellCommandSubstitution,
) -> bool {
    let body = &substitution.body;
    if substitution.kind != "dollar"
        || body.len() > MAX_BODY_CHARS
        || body.contains('$')
        || body.contains('`')
        || body.contains("<<")
        || body.contains('\n')
    {
        return false;
    }
    if dollar_quoted(chars, spans) || commented(chars, spans) || looped(chars, spans) {
        return false;
    }
    let Some((begins, ends)) = bounds(chars, spans, substitution) else {
        return false;
    };
    // The test's own words are read below, and its `[` and `=` are not an
    // assignment, so only the chain ahead of the test is read for steering.
    // An earlier string test is not one either, so it is blanked first.
    if steered(&earlier_tests_blanked(chars, spans, begins), spans, begins) {
        return false;
    }
    let Some(words) = words(chars, spans, begins, ends) else {
        return false;
    };
    let at = spans
        .iter()
        .position(|span| span.start == substitution.start && span.end == substitution.end);
    string_test(
        &words,
        |word| matches!(word, Word::Value(index) if Some(*index) == at),
    )
}

/// Whether `words` is a `[` or `test` that only compares strings, with an
/// operand `holds` accepts in a slot a value can fill.
fn string_test(words: &[Word], holds: impl Fn(&Word) -> bool) -> bool {
    let mut words = words;
    while let Some((Word::Literal(first), rest)) = words.split_first() {
        if matches!(first.as_str(), "if" | "elif" | "then" | "else" | "do" | "!") {
            words = rest;
        } else {
            break;
        }
    }
    let operands = match words.split_first() {
        Some((Word::Literal(program), rest)) if program == "[" => match rest.split_last() {
            Some((Word::Literal(close), operands)) if close == "]" => operands,
            _ => return false,
        },
        Some((Word::Literal(program), rest)) if program == "test" => rest,
        _ => return false,
    };
    let literal = |word: &Word, wanted: &[&str]| matches!(word, Word::Literal(text) if wanted.contains(&text.as_str()));
    match operands {
        [only] => holds(only),
        [operator, operand] => literal(operator, &["-n", "-z"]) && holds(operand),
        [left, operator, right] => {
            literal(operator, &["=", "==", "!="])
                && (holds(left) || holds(right))
                && [left, right].iter().all(|word| operand(word))
        }
        _ => false,
    }
}

/// `chars` with each command before `end` that is itself a string test
/// blanked outside its substitutions, so the steering scan does not read its
/// `[` and `=` as an assignment. Its substitutions are judged by the caller
/// as commands of their own.
fn earlier_tests_blanked(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    end: usize,
) -> Vec<char> {
    let mut blanked = chars.to_vec();
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut begins = 0usize;
    for at in 0..end.min(chars.len()) {
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match chars[at] {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            ';' | '&' | '|' | '\n' if !single && !double => {
                let any = |word: &Word| matches!(word, Word::Value(_)) || operand(word);
                if words(chars, spans, begins, at).is_some_and(|words| string_test(&words, any)) {
                    for (index, slot) in blanked.iter_mut().enumerate().take(at).skip(begins) {
                        if !spans
                            .iter()
                            .any(|span| span.start <= index && index < span.end)
                        {
                            *slot = ' ';
                        }
                    }
                }
                begins = at + 1;
            }
            _ => {}
        }
    }
    blanked
}

/// Whether `word` is read as one string: a substitution, or a literal that
/// spells no operator the test would read in its place.
fn operand(word: &Word) -> bool {
    match word {
        Word::Value(_) => true,
        Word::Literal(text) => !text.starts_with(['-', '!', '(', ')', '=']),
    }
}

/// The start and end of the simple command holding `substitution`; `None`
/// when grouping, a subshell or a redirection appears up to its end.
fn bounds(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    substitution: &ShellCommandSubstitution,
) -> Option<(usize, usize)> {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut begins = 0usize;
    for (at, &character) in chars.iter().enumerate() {
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '(' | ')' | '{' | '}' | '<' | '>' if !single && !double => return None,
            ';' | '&' | '|' | '\n' if !single && !double => {
                if at >= substitution.end {
                    return Some((begins, at));
                }
                begins = at + 1;
            }
            _ => {}
        }
    }
    (!single && !double && !escaped).then_some((begins, chars.len()))
}

/// The words of `chars[begins..ends]`; `None` when any word is neither a
/// double-quoted substitution alone nor a plain literal.
fn words(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    begins: usize,
    ends: usize,
) -> Option<Vec<Word>> {
    let mut words = Vec::new();
    let mut at = begins;
    while at < ends {
        let character = chars[at];
        if character.is_ascii_whitespace() {
            at += 1;
            continue;
        }
        let end = (at..ends)
            .find(|&index| {
                chars[index].is_ascii_whitespace()
                    && !spans
                        .iter()
                        .any(|span| span.start <= index && index < span.end)
                    && !inside_quotes(chars, spans, at, index)
            })
            .unwrap_or(ends);
        words.push(word(chars, spans, at, end)?);
        at = end;
    }
    Some(words)
}

/// Whether `index` falls inside a quote opened at or after `from`. A
/// substitution's own text is skipped: its quotes belong to the inner
/// command, not to the word around it.
fn inside_quotes(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    from: usize,
    index: usize,
) -> bool {
    let (mut single, mut double) = (false, false);
    for (at, &character) in chars.iter().enumerate().take(index).skip(from) {
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        match character {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            _ => {}
        }
    }
    single || double
}

fn word(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    start: usize,
    end: usize,
) -> Option<Word> {
    if let Some(index) = spans
        .iter()
        .position(|span| span.start == start + 1 && span.end + 1 == end)
    {
        return (chars[start] == '"' && chars[end - 1] == '"').then_some(Word::Value(index));
    }
    if spans
        .iter()
        .any(|span| start <= span.start && span.start < end)
    {
        return None;
    }
    let raw: String = chars[start..end].iter().collect();
    let text = match raw.as_bytes() {
        [b'\'', .., b'\''] | [b'"', .., b'"'] if raw.len() >= 2 => &raw[1..raw.len() - 1],
        _ => raw.as_str(),
    };
    if raw == "[" || raw == "]" {
        return Some(Word::Literal(raw));
    }
    text.chars()
        .all(|c| c.is_ascii_alphanumeric() || "._/:@+-=!,%".contains(c))
        .then(|| Word::Literal(text.to_owned()))
}

#[cfg(test)]
#[path = "chain_literals_compared_tests.rs"]
mod tests;
