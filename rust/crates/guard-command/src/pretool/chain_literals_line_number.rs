//! `sed -n "$(grep -n 'fn main' src/main.rs | cut -d: -f1),+20p" src/main.rs`
//! prints the lines from a match onward. The substitution looks up a line
//! number: `grep -n` over one named file starts each matching line with its
//! number and a colon, and `cut -d: -f1` keeps the number. It prints digits,
//! one line per match, or nothing.
//!
//! The value is read only where it opens the script of a `sed` command and a
//! `,` follows it, so it is the start of a range. There every value the lookup
//! can print gives the script the meaning the stand-in `1` gives it, or a
//! script sed refuses:
//!
//! - one number is a range start, as `1` is;
//! - no match leaves `,+20p`, a range with no start, which sed refuses;
//! - several matches break the script at a line that holds an address and no
//!   command, which sed refuses too.
//!
//! Anywhere else, a file name or an option, digits are a name in the working
//! directory the stand-in would not name, so the substitution stays opaque.
//!
//! Only this lookup is recognised: `grep` with `-n` and a few matching flags
//! over one pattern and one plain file, an optional `head` that keeps the
//! first lines, and `cut` keeping the first `:`-separated field. A second file,
//! a recursive search or a file name with a pattern character would put file
//! names into the output, so none of them is taken.

use crate::shell_structure::ShellCommandSubstitution;

/// Stand-in for the line number the lookup prints.
pub(super) const LINE_VALUE: &str = "1";

const MAX_BODY_CHARS: usize = 512;

/// The stand-in for `body` when it is a line-number lookup.
pub(super) fn stand_in(body: &str) -> Option<&'static str> {
    if body.len() > MAX_BODY_CHARS {
        return None;
    }
    let stages = stages(body)?;
    let found = match stages.as_slice() {
        [grep, cut] => numbered_match(grep) && first_field(cut),
        [grep, middle, last] => {
            numbered_match(grep)
                && ((first_lines(middle) && first_field(last))
                    || (first_field(middle) && first_lines(last)))
        }
        _ => false,
    };
    found.then_some(LINE_VALUE)
}

/// Whether the substitution opens the script of a `sed` command and a `,`
/// follows it. Every word before it is an option, so the word it opens is the
/// script, and a whitespace or an opening quote before it means nothing is
/// glued to its front.
pub(super) fn opens_sed_range(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    substitution: &ShellCommandSubstitution,
) -> bool {
    if chars.get(substitution.end) != Some(&',') {
        return false;
    }
    let Some(before) = super::git_value::command_before(chars, spans, substitution.start) else {
        return false;
    };
    let words = before.strip_suffix('"').unwrap_or(&before);
    if !words.ends_with([' ', '\t']) {
        return false;
    }
    let mut words = words.split_whitespace();
    words.next() == Some("sed") && words.all(|word| word.starts_with('-'))
}

/// The body's pipeline stages as unquoted words. Single quotes hold any
/// printable text; double quotes hold no expansion or escape; an unquoted
/// word holds plain path and option characters. Anything else is `None`.
fn stages(body: &str) -> Option<Vec<Vec<String>>> {
    let mut stages: Vec<Vec<String>> = vec![Vec::new()];
    let mut word: Option<String> = None;
    let mut chars = body.chars();
    while let Some(character) = chars.next() {
        match character {
            ' ' | '\t' | '|' => {
                if let Some(done) = word.take() {
                    stages.last_mut()?.push(done);
                }
                if character == '|' {
                    stages.push(Vec::new());
                }
            }
            '\'' | '"' => {
                let text = word.get_or_insert_with(String::new);
                loop {
                    match chars.next()? {
                        closing if closing == character => break,
                        c if c.is_control() => return None,
                        '$' | '`' | '\\' | '!' if character == '"' => return None,
                        c => text.push(c),
                    }
                }
            }
            c if c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | '+' | ',' | '@') =>
            {
                word.get_or_insert_with(String::new).push(c);
            }
            _ => return None,
        }
    }
    if let Some(done) = word {
        stages.last_mut()?.push(done);
    }
    Some(stages)
}

/// `grep` with `-n` among `-E`, `-F`, `-i`, `-w` and `-m N`, then one
/// pattern and one plain file.
fn numbered_match(words: &[String]) -> bool {
    let Some((head, arguments)) = words.split_first() else {
        return false;
    };
    if head != "grep" {
        return false;
    }
    let (mut numbered, mut operands) = (false, Vec::new());
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        let Some(flags) = argument.strip_prefix('-') else {
            operands.push(argument.as_str());
            continue;
        };
        // GNU grep reads an option after an operand too.
        if !operands.is_empty() {
            return false;
        }
        if flags == "-line-number" {
            numbered = true;
            continue;
        }
        if let Some(count) = flags.strip_prefix('m') {
            let count = if count.is_empty() {
                arguments.next().map(String::as_str).unwrap_or_default()
            } else {
                count
            };
            if !digits(count) {
                return false;
            }
            continue;
        }
        if flags.is_empty()
            || !flags
                .chars()
                .all(|c| matches!(c, 'n' | 'E' | 'F' | 'i' | 'w'))
        {
            return false;
        }
        numbered |= flags.contains('n');
    }
    numbered
        && matches!(operands.as_slice(), [pattern, file]
            if !pattern.is_empty() && plain_file(file))
}

/// A file name with no option, pattern, home or field-separator meaning.
fn plain_file(file: &str) -> bool {
    !file.is_empty()
        && !file.starts_with('-')
        && file
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '@' | '+'))
}

/// `head -N`, `head -n N` or `head -nN`.
fn first_lines(words: &[String]) -> bool {
    match words {
        [head, count] if head == "head" => count
            .strip_prefix("-n")
            .or_else(|| count.strip_prefix('-'))
            .is_some_and(digits),
        [head, flag, count] => head == "head" && flag == "-n" && digits(count),
        _ => false,
    }
}

/// `cut` with `-d:` and `-f1`, in either order and either spelling.
fn first_field(words: &[String]) -> bool {
    let Some((head, arguments)) = words.split_first() else {
        return false;
    };
    let (mut delimiter, mut field) = (false, false);
    let mut arguments = arguments.iter().map(String::as_str);
    while let Some(argument) = arguments.next() {
        let (flag, value) = match argument.get(..2) {
            Some(flag @ ("-d" | "-f")) if argument.len() > 2 => (flag, &argument[2..]),
            Some(flag @ ("-d" | "-f")) => (flag, arguments.next().unwrap_or_default()),
            _ => return false,
        };
        match (flag, value) {
            ("-d", ":") if !delimiter => delimiter = true,
            ("-f", "1") if !field => field = true,
            _ => return false,
        }
    }
    head == "cut" && delimiter && field
}

fn digits(text: &str) -> bool {
    !text.is_empty() && text.len() <= 6 && text.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
#[path = "chain_literals_line_number_tests.rs"]
mod tests;
