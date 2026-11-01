//! Which program may be fed literal bytes on standard input.
//!
//! A quoted heredoc and a here-string both put bytes on standard input and
//! nothing else: the projection strips the operator and the redirects and
//! hands the rest of the command back to be evaluated in full. The bytes are
//! not expanded, read no file and reach no network. The only way they can
//! matter is a program that runs, applies or installs what it reads.
//!
//! The list is positive because that risk has no shape to test for. A shell
//! and an interpreter are the obvious cases, but `xargs` builds a command line
//! from stdin, `psql`, `mysql` and `sqlite3` execute it, `patch` and
//! `git apply` apply it, `tar -x` and `dd` write it, `crontab -` installs it
//! and `kubectl apply -f -` deploys it. None of them looks like an
//! interpreter, so naming the programs that only read is the only test that
//! stays correct as programs are added.

use super::Quote;
use crate::CanonicalCommandV1;

/// Programs that read standard input as data. Each prints, counts, filters or
/// reshapes what it reads; none runs, applies or installs it.
const FILTERS: &[&str] = &[
    "cat", "column", "cut", "diff", "fmt", "fold", "grep", "head", "jq", "nl", "rev", "sort",
    "tail", "tee", "tr", "uniq", "wc", "yq",
];

/// Whether the command is one plain filter spelled by name, with no wrapper,
/// environment assignment or path override, so the bytes it reads on standard
/// input are data and nothing else. The caller still proves every file the
/// command writes on its own.
pub(super) fn reads_data(model: &CanonicalCommandV1) -> bool {
    model.wrapper_chain.is_empty()
        && !model.path_overridden
        && model.segments.len() == 1
        && model.segments[0].wrapper_chain.is_empty()
        && model.segments[0].environment_names.is_empty()
        && !model.segments[0].path_overridden
        && model.segments[0]
            .executable
            .as_deref()
            .is_some_and(|executable| FILTERS.contains(&executable))
}

/// The bare `cat` the caller may stand a no-op in for. Reading standard input
/// is the whole of what it does, so once the write is proven there is nothing
/// left for the command itself to do. Every other filter, and `cat` with
/// arguments, still has the files it names read.
pub(super) fn is_bare_cat(model: &CanonicalCommandV1) -> bool {
    model.segments.len() == 1
        && model.segments[0].executable.as_deref() == Some("cat")
        && model.segments[0].arguments.is_empty()
}

/// Read a `<<< WORD` here-string off the text, leaving the command behind.
///
/// A here-string is one word, so the whole of what reaches standard input is
/// in the text. That holds only while the word substitutes values: a command
/// substitution inside it runs a program the projected text no longer names,
/// so the word is checked before the operator is taken away.
pub(super) fn remove_here_string(chars: &[char], start: usize, out: &mut String) -> Option<usize> {
    if chars.get(start + 1) != Some(&'<') || chars.get(start + 2) != Some(&'<') {
        return None;
    }
    // `foo<<<bar` redirects a file descriptor the projection cannot read.
    if !super::trailing_word(out).is_empty() {
        return None;
    }
    let mut index = start + 3;
    while matches!(chars.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    let word_start = index;
    let mut quote = Quote::None;
    while let Some(&current) = chars.get(index) {
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                }
            }
            Quote::Double => match current {
                '\\' => index += 1,
                '"' => quote = Quote::None,
                _ => {}
            },
            Quote::None => match current {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '\\' => index += 1,
                _ if current.is_whitespace() || matches!(current, ';' | '|' | '&' | '<' | '>') => {
                    break
                }
                _ => {}
            },
        }
        index += 1;
    }
    if quote != Quote::None || index == word_start || index > chars.len() {
        return None;
    }
    if !word_is_data(&chars[word_start..index]) {
        return None;
    }
    out.push(' ');
    Some(index)
}

/// Whether the here-string word substitutes values and nothing else.
///
/// `$NAME` and `${NAME}` put a value on standard input, which is the common
/// shape and runs nothing. A command substitution, a backtick, a process
/// substitution, `$'...'` and an arithmetic expansion each evaluate inside the
/// word, so the projected text would no longer name everything the shell runs.
/// Arithmetic reaches furthest of those: it evaluates the values of the names
/// it mentions, and a subscript inside one of those values substitutes a
/// command, so `$[x]` runs whatever `x` holds.
fn word_is_data(chars: &[char]) -> bool {
    let mut index = 0;
    let mut quote = Quote::None;
    while index < chars.len() {
        let current = chars[index];
        if quote == Quote::Single {
            if current == '\'' {
                quote = Quote::None;
            }
            index += 1;
            continue;
        }
        match current {
            '\\' => index += 1,
            '\'' if quote == Quote::None => quote = Quote::Single,
            '"' => {
                quote = if quote == Quote::Double {
                    Quote::None
                } else {
                    Quote::Double
                }
            }
            '`' => return false,
            '<' | '>' if chars.get(index + 1) == Some(&'(') => return false,
            '$' => match chars.get(index + 1) {
                Some(&('(' | '[' | '\'' | '"')) => return false,
                Some(&'{') => match plain_expansion(chars, index + 2) {
                    Some(close) => index = close,
                    None => return false,
                },
                _ => {}
            },
            _ => {}
        }
        index += 1;
    }
    true
}

/// The `}` of a `${NAME}` that substitutes a value, or `${#NAME}` for its
/// length. Every other brace form expands a replacement, evaluates an
/// arithmetic offset or changes shell state, so none of them is a value.
fn plain_expansion(chars: &[char], start: usize) -> Option<usize> {
    let start = start + usize::from(chars.get(start) == Some(&'#'));
    let mut index = start;
    while chars
        .get(index)
        .is_some_and(|value| value.is_ascii_alphanumeric() || *value == '_')
    {
        index += 1;
    }
    if index == start || chars.get(index) != Some(&'}') {
        return None;
    }
    Some(index)
}
