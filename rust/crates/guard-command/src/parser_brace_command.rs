//! `${ cmd; }`, the brace form Bash 5.3 runs, found in text that still
//! carries its quotes.

use super::*;

/// Bash 5.3 runs the commands in `${ cmd; }` and `${| cmd; }`. What tells
/// those apart from an ordinary `${NAME}` is the character right after the
/// brace: a parameter name cannot begin with a space or a `|`. Unquoted, the
/// brace is already refused as a parameter expansion; inside double quotes
/// only `$(` and a backtick were read as running a command, so a `${| gh pr
/// merge --squash; }` written there ran with nothing to answer for it.
pub(crate) fn brace_runs_a_command(text: &str) -> bool {
    text.match_indices("${").any(|(at, _)| {
        text[at + 2..]
            .chars()
            .next()
            .is_some_and(opens_brace_command)
    })
}

pub(crate) fn opens_brace_command(character: char) -> bool {
    character.is_whitespace() || character == '|'
}

/// Spellings whose quoting this reader does not follow. In `$'…'` a `\'` is
/// an escape that leaves the word open, and a `#` that opens a word begins a
/// comment that runs to the newline; reading either as a plain single quote
/// leaves the scan one quote out of step with the shell, which hides the
/// brace standing behind it. Both fall back to the raw reading, which
/// answers for more text rather than less.
fn quoting_is_beyond_this_reader(text: &str) -> bool {
    if text.contains("$'") {
        return true;
    }
    let mut previous: Option<char> = None;
    for character in text.chars() {
        if character == '#' && previous.is_none_or(opens_a_word) {
            return true;
        }
        previous = Some(character);
    }
    false
}

/// What can stand in front of a `#` that begins a comment: Bash takes the
/// word after an unquoted operator as a fresh word, so `cmd;# note` is a
/// comment just as `cmd # note` is.
fn opens_a_word(character: char) -> bool {
    character.is_whitespace() || matches!(character, ';' | '&' | '|' | '(' | ')' | '<' | '>')
}

/// The same reading for text that still carries its quotes. A single quote
/// makes everything up to the next one literal, so a `${ note; }` written
/// there runs nothing and must not cost the command its review. Inside double
/// quotes a single quote is an ordinary character and the brace still runs,
/// which is why the quoted scanner above reads the raw span.
pub(crate) fn brace_runs_a_command_unquoted(text: &str) -> bool {
    if quoting_is_beyond_this_reader(text) {
        return brace_runs_a_command(text);
    }
    let characters: Vec<char> = text.chars().collect();
    let mut index = 0;
    let mut quote = Quote::None;
    while index < characters.len() {
        let current = characters[index];
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                }
            }
            Quote::None | Quote::Double => {
                if current == '\\' {
                    index += 2;
                    continue;
                }
                if current == '\'' && quote == Quote::None {
                    quote = Quote::Single;
                } else if current == '"' {
                    quote = if quote == Quote::Double {
                        Quote::None
                    } else {
                        Quote::Double
                    };
                } else if current == '$'
                    && characters.get(index + 1) == Some(&'{')
                    && characters
                        .get(index + 2)
                        .copied()
                        .is_some_and(opens_brace_command)
                {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}
