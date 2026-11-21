//! Whether a `printf` assigns a shell variable rather than only printing.
//!
//! `printf -v NAME` stores its output in `NAME`, and a `%n` conversion stores
//! a count in the variable it names. Both change the shell state a later step
//! of the same command runs under, so neither is a step that only prints.

use crate::CommandSegmentV1;

/// Whether a `printf` segment may assign a shell variable; see [`printf_assigns`].
pub(super) fn printf_sets_variable(segment: &CommandSegmentV1) -> bool {
    segment
        .executable
        .as_deref()
        .is_some_and(|executable| super::executable_basename(executable) == "printf")
        && printf_assigns(&segment.text)
}

/// Whether the `printf` in `text` may assign a variable: `-v NAME` before the format or `--`,
/// or a `%n` conversion. Quotes are removed (`"-"v` is `-v`) and redirections dropped wherever
/// they stand; another leading option, an expanded format or a mixed redirect word counts.
pub(super) fn printf_assigns(text: &str) -> bool {
    let words = shell_words(text);
    let Some(at) = words
        .iter()
        .position(|word| word.value == "printf" || word.value.ends_with("/printf"))
    else {
        return true;
    };
    let mut arguments = Vec::new();
    let mut rest = words[at + 1..].iter();
    while let Some(word) = rest.next() {
        if !word.redirect {
            arguments.push(word);
            continue;
        }
        let operator = word
            .value
            .trim_start_matches(|character: char| character.is_ascii_digit());
        match operator.trim_start_matches(['<', '>', '&', '|']) {
            // A bare operator (`2>`) takes the next word as its target.
            "" => drop(rest.next()),
            target if target.len() < operator.len() && !target.contains(['<', '>']) => {}
            _ => return true,
        }
    }
    let mut arguments = arguments.into_iter();
    let mut format = arguments.next();
    if format.is_some_and(|word| word.value == "--" && !word.expands) {
        format = arguments.next();
    } else if format.is_some_and(|word| word.value.starts_with('-')) {
        return true;
    }
    format.is_some_and(|word| word.expands || format_counts(&word.value))
}

/// A word of shell text with its quoting removed.
#[derive(Default)]
struct ShellWord {
    value: String,
    /// `$` or backquote outside single quotes, or unquoted brace or glob syntax.
    expands: bool,
    /// An unquoted `<` or `>`.
    redirect: bool,
}

/// The words of `text`. ANSI-C quoting (`$'...'`) is literal text.
fn shell_words(text: &str) -> Vec<ShellWord> {
    let mut words = Vec::new();
    let mut word = ShellWord::default();
    let (mut started, mut single, mut double, mut ansi) = (false, false, false, false);
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\'' if ansi => ansi = false,
            // A numeric escape is the character it names (`$'\x25n'` is `%n`);
            // an octal one keeps only its low byte.
            '\\' if ansi => match characters.next() {
                Some(kind @ ('x' | 'u' | 'U' | '0'..='7')) => {
                    let (radix, most) = match kind {
                        'x' => (16, 2),
                        'u' => (16, 4),
                        'U' => (16, 8),
                        _ => (8, 3),
                    };
                    let mut digits: String = kind.is_digit(8).then_some(kind).into_iter().collect();
                    while digits.len() < most
                        && characters.peek().is_some_and(|next| next.is_digit(radix))
                    {
                        digits.extend(characters.next());
                    }
                    let value = u32::from_str_radix(&digits, radix).ok();
                    match value
                        .map(|value| if radix == 8 { value & 0xff } else { value })
                        .filter(|value| *value != 0)
                        .and_then(char::from_u32)
                    {
                        Some(decoded) => word.value.push(decoded),
                        // A NUL ends the string in bash (`$'%\0'n` is `%n`).
                        None => word.expands = true,
                    }
                }
                Some('c') => word.expands = true,
                escaped => word.value.extend(escaped),
            },
            character if ansi => word.value.push(character),
            '$' if !single && !double && characters.peek() == Some(&'\'') => {
                characters.next();
                ansi = true;
            }
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            // A backslash-newline is a line continuation; the shell drops both.
            '\\' if !single => match characters.next() {
                Some('\n') => {}
                escaped => word.value.extend(escaped),
            },
            '$' | '`' if !single => {
                word.expands = true;
                word.value.push(character);
            }
            // Brace and glob expansion can build a word: `{-v,PATH,%s,dir}`.
            '{' | '*' | '?' | '[' if !single && !double => {
                word.expands = true;
                word.value.push(character);
            }
            '<' | '>' if !single && !double => {
                word.redirect = true;
                word.value.push(character);
            }
            character if character.is_whitespace() && !single && !double => {
                let ended = std::mem::take(&mut word);
                if started {
                    words.push(ended);
                }
                started = false;
                continue;
            }
            character => word.value.push(character),
        }
        started = true;
    }
    if started {
        words.push(word);
    }
    words
}

/// Whether a printf format holds `%n` after flags, width, precision and length (`%%` is `%`).
fn format_counts(format: &str) -> bool {
    let mut characters = format.chars();
    while characters.any(|character| character == '%') {
        if characters
            .by_ref()
            .find(|character| !"-+ #'0123456789.*hjlLqtz".contains(*character))
            == Some('n')
        {
            return true;
        }
    }
    false
}
