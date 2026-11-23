//! A substitution whose value is only printed: `echo "version: $(grep -m1
//! version package.json)"`.
//!
//! An agent labels what it reads by wrapping the read in `echo` or `printf`.
//! The value lands inside a double-quoted argument of a command that does
//! nothing but print it, so it is never split, matched as a pattern, run, or
//! used as a path, an option or a format. What the shell does is then the
//! inner command plus a print of its output, and the inner command is judged
//! as a command of its own by the caller before the projection is used. The
//! value is written as a plain stand-in, and the rest of the chain, pipes and
//! redirections included, is judged on that text: `echo "$(cat f)" | sh`
//! still reviews for the `sh`.
//!
//! The slot is refused when:
//!
//! - the substitution is not inside double quotes, where the shell would
//!   split and glob the value into words of its own;
//! - the command holding it is not `echo` or `printf`, so the value could be
//!   a path, an option or a program another command acts on;
//! - a `printf` has no format ahead of the substitution, or takes `-v`, so
//!   the value would be the format or a variable name;
//! - a redirection operator stands ahead of it in the same command, so the
//!   value could name the file a redirection opens;
//! - anything earlier in the chain could change what the inner command
//!   reads (`cd`, an assignment, `alias`, a function definition), since the
//!   inner command is judged where the chain starts;
//! - the inner command expands a variable or a substitution of its own,
//!   which judging it alone would not resolve as the shell does;
//! - the command uses `$'...'` or `$"..."`, whose escapes this scan reads
//!   differently from the shell, so the quoting state ahead of the slot
//!   cannot be trusted;
//! - grouping, a subshell, a process substitution or a redirection stands
//!   ahead of the slot (`(`, `)`, `{`, `}`, `<`, `>`), where the word
//!   boundaries are not the ones this scan reads;
//! - a loop keyword opens a body that runs again, in which case steering
//!   written after the slot still runs before it on the next pass, so the
//!   whole command is read for steering rather than the text ahead;
//! - the print adds no text of its own (`printf '%s' "$(cat f)"`), so the
//!   wrapper does nothing but put a second layer around the read.

use crate::shell_structure::ShellCommandSubstitution;

/// Stand-in for a printed value: a plain word with no path, glob or option
/// meaning.
pub(super) const DISPLAY_VALUE: &str = "hol-guard-substituted-output";

const MAX_BODY_CHARS: usize = 256;

/// Words that change, for the rest of the chain, the directory, the
/// variables or the meaning of a command name.
/// Keywords that open a body the shell runs more than once.
const LOOP_WORDS: &str = "for while until select";

const STEERING_WORDS: &str = ". alias builtin cd command declare enable eval exec export \
    function getopts hash let local mapfile popd pushd read readarray readonly set \
    setopt shopt source trap typeset unalias unset";

/// Whether `substitution` sits where its value is only printed.
///
/// `chars` is the heredoc-masked command, which keeps every index.
pub(super) fn display_slot(
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
    if dollar_quoted(chars, spans) {
        return false;
    }
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut begins = 0usize;
    for (at, &character) in chars.iter().enumerate().take(substitution.start) {
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
            // Grouping, a subshell, a process substitution and a redirection
            // all put the command holding the slot somewhere this scan does
            // not read: `}` can close a group or end a word, `{a,b}` is one
            // word, and `>&` or `>|` is a redirection, not a separator.
            '(' | ')' | '{' | '}' | '<' | '>' if !single && !double => return false,
            ';' | '&' | '|' | '\n' if !single && !double => begins = at + 1,
            _ => {}
        }
    }
    // A loop body runs again, so a `cd` written after the slot still runs
    // before it on the next pass; read the whole command for steering then.
    let steering_end = if looped(chars, spans) {
        chars.len()
    } else {
        substitution.start
    };
    if single || !double || steered(chars, spans, steering_end) {
        return false;
    }
    let segment: Vec<char> = chars[begins..substitution.start].to_vec();
    let words = unquoted_words(&segment, begins, spans);
    let Some(words) = words else {
        return false;
    };
    // Keywords that open a body leave the command after them.
    let mut words = words.as_slice();
    while let Some((first, rest)) = words.split_first() {
        if matches!(first.as_str(), "do" | "then" | "else" | "!") {
            words = rest;
        } else {
            break;
        }
    }
    let printf = match words.split_first() {
        Some((program, _)) if program == "echo" => false,
        Some((program, arguments))
            if program == "printf"
                && arguments
                    .first()
                    .is_some_and(|format| !format.starts_with('-')) =>
        {
            true
        }
        _ => return false,
    };
    labelled(chars, spans, begins, substitution, printf)
}

/// Whether the print adds text of its own to the value, as in `echo
/// "version: $(...)"` or `printf 'lines: %s\n' "$(...)"`.
///
/// A bare `printf '%s' "$(cat f)"` or `echo "$(cat f)"` prints exactly what
/// the inner command would print alone, so the wrapper adds nothing but a
/// second layer around the read, and it keeps review. The label is looked
/// for from the print's first argument to the quote that closes the value.
/// Echo options, printf conversions, escapes, quotes and other substitutions
/// are not a label.
fn labelled(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    begins: usize,
    substitution: &ShellCommandSubstitution,
    printf: bool,
) -> bool {
    let mut close = None;
    let mut escaped = false;
    for (at, &character) in chars.iter().enumerate().skip(substitution.end) {
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            close = Some(at);
            break;
        }
    }
    let Some(close) = close else {
        return false;
    };
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    for (at, &character) in chars.iter().enumerate().take(close).skip(begins) {
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            // An escape is not a label, quoted or not: printf reads `\n`
            // in its format as a newline.
            '\\' => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            c if c.is_ascii_whitespace() && !single && !double => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    let mut words = words.as_slice();
    while let Some((first, rest)) = words.split_first() {
        if matches!(first.as_str(), "do" | "then" | "else" | "!") {
            words = rest;
        } else {
            break;
        }
    }
    words
        .iter()
        .skip(1)
        .filter(|word| printf || !word.starts_with('-'))
        .any(|word| {
            let text = if printf {
                without_conversions(word)
            } else {
                word.clone()
            };
            text.chars().any(char::is_alphanumeric)
        })
}

/// `word` with its printf conversions (`%s`, `%-10.3d`, `%%`) removed.
fn without_conversions(word: &str) -> String {
    let mut text = String::with_capacity(word.len());
    let mut characters = word.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '%' {
            text.push(character);
            continue;
        }
        while characters
            .next_if(|c| matches!(c, '-' | '+' | ' ' | '#' | '0'..='9' | '.' | '*'))
            .is_some()
        {}
        if characters
            .next_if(|c| c.is_ascii_alphabetic() || *c == '%')
            .is_none()
        {
            text.push(character);
        }
    }
    text
}

/// The complete words of `segment` that end before the substitution, with
/// quotes left in place. `None` when an unquoted redirection operator
/// appears, so the value could name a file a redirection opens.
fn unquoted_words(
    segment: &[char],
    offset: usize,
    spans: &[ShellCommandSubstitution],
) -> Option<Vec<String>> {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut words = Vec::new();
    let mut word = String::new();
    for (index, &character) in segment.iter().enumerate() {
        let at = offset + index;
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            word.push('x');
            continue;
        }
        if escaped {
            escaped = false;
            word.push(character);
            continue;
        }
        match character {
            '\\' if !single => {
                escaped = true;
                word.push(character);
            }
            '\'' if !double => {
                single = !single;
                word.push(character);
            }
            '"' if !single => {
                double = !double;
                word.push(character);
            }
            '<' | '>' if !single && !double => return None,
            c if c.is_ascii_whitespace() && !single && !double => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
    }
    // The word still open holds the substitution, so it is not a complete
    // word before it.
    Some(words)
}

/// Whether the text ahead of `end` could change what the inner command reads
/// once it runs: a directory change, an assignment, a function definition or
/// a builtin that rebinds names. The inner command is judged where the chain
/// starts, so any of these leaves that judgement about a different command.
fn steered(chars: &[char], spans: &[ShellCommandSubstitution], end: usize) -> bool {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut word = String::new();
    let mut previous = ' ';
    let mut words: Vec<String> = Vec::new();
    for (at, &character) in chars.iter().enumerate().take(end) {
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            word.push('x');
            continue;
        }
        if escaped {
            escaped = false;
            word.push(character);
            continue;
        }
        let quoted = single || double;
        match character {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            // `name()` opens a function definition.
            ')' if !quoted && previous == '(' => return true,
            c if !quoted && (c.is_ascii_whitespace() || ";&|(){}".contains(c)) => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
        if !quoted && character == '=' && assignment_head(&word) {
            return true;
        }
        if !character.is_ascii_whitespace() {
            previous = character;
        }
    }
    words.iter().any(|word| {
        STEERING_WORDS
            .split_ascii_whitespace()
            .any(|entry| entry == word)
    }) || words
        .windows(2)
        .any(|pair| pair[0] == "printf" && pair[1].starts_with("-v"))
}

/// Whether `word` so far is `NAME=`, the start of an assignment.
fn assignment_head(word: &str) -> bool {
    let Some(name) = word.strip_suffix('=') else {
        return false;
    };
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether the command uses `$'...'` or `$"..."`, whose contents the shell
/// reads with its own escape rules. The scans here walk quotes one character
/// at a time, so a `\\'` inside `$'...'` would leave them a quote out of step
/// with the shell and the word holding the slot would be the wrong one.
fn dollar_quoted(chars: &[char], spans: &[ShellCommandSubstitution]) -> bool {
    chars.windows(2).enumerate().any(|(at, pair)| {
        pair[0] == '$'
            && (pair[1] == '\'' || pair[1] == '"')
            && !spans.iter().any(|span| span.start <= at && at < span.end)
    })
}

/// Whether an unquoted loop keyword appears anywhere in the command. A word
/// inside quotes counts too: reading it as a keyword only refuses the slot.
fn looped(chars: &[char], spans: &[ShellCommandSubstitution]) -> bool {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut word = String::new();
    let mut words: Vec<String> = Vec::new();
    for (at, &character) in chars.iter().enumerate() {
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            word.push('x');
            continue;
        }
        if escaped {
            escaped = false;
            word.push(character);
            continue;
        }
        match character {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            c if c.is_ascii_whitespace() || ";&|(){}".contains(c) => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words.iter().any(|word| {
        LOOP_WORDS
            .split_ascii_whitespace()
            .any(|entry| entry == word)
    })
}
