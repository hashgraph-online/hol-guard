//! Text scanning for [`super`]: list operators, quoting, expansions of a
//! name and the words that steer what a later command runs.

use super::super::ShellCommandSubstitution;

/// Words that open a group, a loop or a conditional, or negate a status.
const COMPOUND_WORDS: &str = "! [[ case coproc do done elif else esac fi for foreach function if \
    repeat select then time until while";

/// Words that run their arguments or change, for the rest of the chain, the
/// directory or the meaning of a command name.
const STEERING_WORDS: &str = ". alias builtin cd chdir command declare enable eval exec export \
    function getopts hash let local mapfile popd pushd read readarray readonly set setopt shopt \
    source trap typeset unalias unset";
/// Whether `body` expands anything: a `$` or backtick outside single quotes.
/// An earlier assignment in the chain could bind the name it expands, which
/// the body judged on its own would not see. Inside single quotes, as in
/// `awk '{print $1}'` or a `jq` filter, both are literal text.
pub(super) fn expands(body: &str) -> bool {
    let (mut single, mut double, mut escaped) = (false, false, false);
    for character in body.chars() {
        if escaped {
            escaped = false;
        } else if single {
            single = character != '\'';
        } else {
            match character {
                '\\' => escaped = true,
                '\'' if !double => single = true,
                '"' => double = !double,
                '$' | '`' => return true,
                _ => {}
            }
        }
    }
    single || double || escaped
}

/// Whether the text ahead of `end` is unquoted at `end` and opens no group,
/// loop or conditional.
pub(super) fn plain_ahead(masked: &[char], spans: &[ShellCommandSubstitution], end: usize) -> bool {
    let Some(words) = words(masked, spans, 0, end) else {
        return false;
    };
    !words
        .iter()
        .any(|word| listed(COMPOUND_WORDS, word) || matches!(word.as_str(), "(" | ")" | "{" | "}"))
}

/// `Some(None)` at the start of the text, `Some(Some(..))` after `;`, a line
/// break or `&&`, and `None` after anything else.
pub(super) fn operator_before(masked: &[char], name_start: usize) -> Option<Option<(usize, bool)>> {
    let Some(at) = masked[..name_start]
        .iter()
        .rposition(|c| !matches!(c, ' ' | '\t'))
    else {
        return Some(None);
    };
    match masked[at] {
        '\n' => Some(Some((at, false))),
        ';' if at == 0 || masked[at - 1] != ';' => Some(Some((at, false))),
        '&' if at > 0 && masked[at - 1] == '&' => Some(Some((at - 1, true))),
        _ => None,
    }
}

/// `Some(None)` at the end of the text, `Some(Some(end))` before `;`, a line
/// break or `&&` (with the blanks after it), and `None` before anything else.
pub(super) fn operator_after(masked: &[char], value_end: usize) -> Option<Option<usize>> {
    let mut at = value_end;
    while masked.get(at).is_some_and(|c| matches!(c, ' ' | '\t')) {
        at += 1;
    }
    let end = match (masked.get(at), masked.get(at + 1)) {
        (None, _) => return Some(None),
        (Some('\n'), _) => at + 1,
        (Some(';'), next) if next != Some(&';') => at + 1,
        (Some('&'), Some('&')) => at + 2,
        _ => return None,
    };
    let mut end = end;
    while masked.get(end).is_some_and(|c| c.is_ascii_whitespace()) {
        end += 1;
    }
    Some(Some(end))
}

/// Where the `&&` list holding `from` ends: the first `;`, line break, `||`
/// or background `&` after it.
pub(super) fn list_end(masked: &[char], spans: &[ShellCommandSubstitution], from: usize) -> usize {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut at = from;
    while at < masked.len() {
        let character = masked[at];
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            at += 1;
            continue;
        }
        if escaped {
            escaped = false;
        } else if single {
            single = character != '\'';
        } else {
            match character {
                '\\' => escaped = true,
                '\'' if !double => single = true,
                '"' => double = !double,
                ';' | '\n' if !double => return at,
                '|' if !double && masked.get(at + 1) == Some(&'|') => return at,
                '&' if !double => {
                    if masked.get(at + 1) == Some(&'&') {
                        at += 1;
                    } else {
                        return at;
                    }
                }
                _ => {}
            }
        }
        at += 1;
    }
    masked.len()
}

/// Each place `name` stands as a whole identifier.
pub(super) fn occurrences(chars: &[char], name: &str) -> Vec<usize> {
    let name: Vec<char> = name.chars().collect();
    let word = |c: Option<&char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_');
    (0..chars.len().saturating_sub(name.len() - 1))
        .filter(|&at| {
            chars[at..].starts_with(&name)
                && !(at > 0 && word(chars.get(at - 1)))
                && !word(chars.get(at + name.len()))
        })
        .collect()
}

/// The range `$NAME` or `${NAME}` covers when the name at `at` is one of
/// those whole, unescaped expansions.
pub(super) fn expansion(chars: &[char], at: usize, length: usize) -> Option<(usize, usize)> {
    let end = at + length;
    let escaped = |dollar: usize| dollar > 0 && chars[dollar - 1] == '\\';
    if at >= 2 && chars[at - 2] == '$' && chars[at - 1] == '{' {
        return (chars.get(end) == Some(&'}') && !escaped(at - 2)).then_some((at - 2, end + 1));
    }
    // `$NAME[1]` subscripts and `$NAME:h` modifies the value in zsh.
    (at >= 1
        && chars[at - 1] == '$'
        && !escaped(at - 1)
        && !matches!(chars.get(end), Some('[' | ':')))
    .then_some((at - 1, end))
}

/// Where the simple command holding each character begins.
pub(super) fn command_begins(masked: &[char], spans: &[ShellCommandSubstitution]) -> Vec<usize> {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut begin = 0;
    let mut begins = Vec::with_capacity(masked.len());
    for (at, &character) in masked.iter().enumerate() {
        begins.push(begin);
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        if escaped {
            escaped = false;
        } else if single {
            single = character != '\'';
        } else {
            match character {
                '\\' => escaped = true,
                '\'' if !double => single = true,
                '"' => double = !double,
                ';' | '&' | '|' | '\n' | '(' | ')' | '{' | '}' if !double => begin = at + 1,
                _ => {}
            }
        }
    }
    begins
}

/// Whether each character is inside single quotes, where `$NAME` is text.
pub(super) fn single_quoted(masked: &[char], spans: &[ShellCommandSubstitution]) -> Vec<bool> {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut quoted = Vec::with_capacity(masked.len());
    for (at, &character) in masked.iter().enumerate() {
        quoted.push(single);
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        if escaped {
            escaped = false;
        } else if single {
            single = character != '\'';
        } else {
            match character {
                '\\' => escaped = true,
                '\'' if !double => single = true,
                '"' => double = !double,
                _ => {}
            }
        }
    }
    quoted
}

/// Whether the expansion at `start` is an argument of `echo`, ahead of any
/// redirection in that command. It prints the value the judged command
/// printed, so it is read as the printed stand-in.
pub(super) fn echoed(
    masked: &[char],
    spans: &[ShellCommandSubstitution],
    begin: usize,
    start: usize,
) -> bool {
    let Some(words) = words_to(masked, spans, begin, start) else {
        return false;
    };
    let mut words = words.as_slice();
    while let Some((first, rest)) = words.split_first() {
        if matches!(first.as_str(), "do" | "then" | "else") {
            words = rest;
        } else {
            break;
        }
    }
    words.first().is_some_and(|program| program == "echo")
        && !masked[begin..start].iter().any(|c| matches!(c, '<' | '>'))
        && !piped(masked, spans, begin)
}

/// Whether the simple command holding `from` hands its output to a pipe,
/// where the next program would read the real value, not the stand-in.
pub(super) fn piped(masked: &[char], spans: &[ShellCommandSubstitution], from: usize) -> bool {
    let (mut single, mut double, mut escaped) = (false, false, false);
    for at in from..masked.len() {
        let character = masked[at];
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        if escaped {
            escaped = false;
        } else if single {
            single = character != '\'';
        } else {
            match character {
                '\\' => escaped = true,
                '\'' if !double => single = true,
                '"' => double = !double,
                '|' if !double => return masked.get(at + 1) != Some(&'|'),
                ';' | '&' | '\n' | '(' | ')' if !double => return false,
                _ => {}
            }
        }
    }
    false
}

/// Whether anything from `start` to `end` could change what a command run
/// later reads or runs: a steering word, an assignment to a name the shell or
/// a program reads for itself, or a group, subshell or function.
pub(super) fn steers(
    masked: &[char],
    spans: &[ShellCommandSubstitution],
    start: usize,
    end: usize,
) -> bool {
    if start >= end {
        return false;
    }
    let Some(words) = words_to(masked, spans, start, end) else {
        return true;
    };
    words.iter().any(|word| {
        listed(STEERING_WORDS, word)
            || matches!(word.as_str(), "(" | ")" | "{" | "}")
            || word.split_once('=').is_some_and(|(name, _)| {
                assignment_name(name) && !super::super::super::ordinary_name(name)
            })
            || word.contains(['(', ')'])
    })
}

/// The unquoted words of `masked[start..end]`, each substitution read as a
/// plain character and each group or subshell character as a word of its
/// own; `None` when the range ends inside quotes.
pub(super) fn words(
    masked: &[char],
    spans: &[ShellCommandSubstitution],
    start: usize,
    end: usize,
) -> Option<Vec<String>> {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut words = Vec::new();
    let mut word = String::new();
    for (at, &character) in masked.iter().enumerate().take(end).skip(start) {
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            if spans.iter().any(|span| span.start == at) {
                word.push('x');
            }
            continue;
        }
        if escaped {
            escaped = false;
            word.push(character);
            continue;
        }
        if single {
            single = character != '\'';
            word.push(character);
            continue;
        }
        match character {
            '\\' => {
                escaped = true;
                word.push(character);
            }
            '\'' if !double => {
                single = true;
                word.push(character);
            }
            '"' => {
                double = !double;
                word.push(character);
            }
            '(' | ')' | '{' | '}' if !double && word.is_empty() => {
                words.push(character.to_string());
            }
            c if !double && (c.is_ascii_whitespace() || ";&|<>".contains(c)) => {
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
    (!single && !double && !escaped).then_some(words)
}

/// [`words`] up to `end`, which may fall inside a double-quoted word such
/// as `"$NAME"`: that word is read as if its quote closed there.
pub(super) fn words_to(
    masked: &[char],
    spans: &[ShellCommandSubstitution],
    start: usize,
    end: usize,
) -> Option<Vec<String>> {
    words(masked, spans, start, end).or_else(|| {
        let mut closed = masked[..end].to_vec();
        closed.push('"');
        words(&closed, spans, start, end + 1)
    })
}

pub(super) fn assignment_name(name: &str) -> bool {
    let name = name.strip_suffix('+').unwrap_or(name);
    let name = name.split_once('[').map_or(name, |(name, _)| name);
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A comment hides its quotes from the shell, and `$'...'` reads escapes this
/// scan does not, so the quoting state of either text cannot be trusted.
pub(super) fn commented_or_dollar_quoted(
    masked: &[char],
    spans: &[ShellCommandSubstitution],
) -> bool {
    let outside = |at: usize| !spans.iter().any(|span| span.start <= at && at < span.end);
    masked.iter().enumerate().any(|(at, &character)| {
        outside(at)
            && ((character == '#'
                && at.checked_sub(1).is_none_or(|before| {
                    masked[before].is_ascii_whitespace() || ";&|()".contains(masked[before])
                }))
                || (character == '$' && matches!(masked.get(at + 1), Some('\'' | '"'))))
    })
}

pub(super) fn listed(list: &str, word: &str) -> bool {
    list.split_ascii_whitespace().any(|entry| entry == word)
}
