//! A bare `echo` or `printf` that prints a US Social Security number.
//!
//! The literal-secret screen reviews a command that spells out a key or a
//! password, but a printed SSN passed: nothing in it is a program Guard
//! watches. The shape is kept to a single print with no pipe, redirect,
//! substitution or second command, so a test that feeds a sample number to a
//! redaction tool, or a search for one in a fixture, is never asked about.
//! Only numbers the Social Security Administration could have issued count:
//! area 001-899 except 666, group 01-99, serial 0001-9999.

use std::sync::LazyLock;

use regex::Regex;

// Do not consume neighboring bytes in the regex: adjacent candidates,
// including an invalid SSN followed by a valid one, need separate checks.
static SSN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([0-9]{3})-([0-9]{2})-([0-9]{4})").expect("ssn pattern")
});

const PRINTERS: [&str; 2] = ["echo", "printf"];

fn issuable(area: &str, group: &str, serial: &str) -> bool {
    let area_ok = area != "000" && area != "666" && !area.starts_with('9');
    area_ok && group != "00" && serial != "0000"
}

fn attached_to_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'/' | b':')
}

// Quoted parentheses are printed punctuation, not shell control operators.
// Reject executable shell syntax and substitutions, including in double quotes.
fn single_literal_print(command: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut chars = command.chars();
    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                }
            }
            Some('"') => match ch {
                '"' => quote = None,
                '$' | '\x60' | '\n' | '\r' => return false,
                '\\' => {
                    if chars.next().is_none() {
                        return false;
                    }
                }
                _ => {}
            },
            _ => match ch {
                '\'' | '"' => quote = Some(ch),
                '|' | ';' | '&' | '<' | '>' | '$' | '\x60' | '\n' | '\r' | '(' | ')' => {
                    return false;
                }
                '\\' => {
                    if chars.next().is_none() {
                        return false;
                    }
                }
                _ => {}
            },
        }
    }
    quote.is_none()
}

/// Whether command is a single echo/printf that prints a plausible US SSN.
pub(super) fn echoes_ssn(command: &str) -> bool {
    let trimmed = command.trim();
    let program = trimmed.split_whitespace().next().unwrap_or("");
    if !PRINTERS.contains(&program) || !single_literal_print(trimmed) {
        return false;
    }
    let bytes = trimmed.as_bytes();
    SSN.captures_iter(trimmed).any(|found| {
        let span = found.get(0).expect("SSN capture");
        (span.start() == 0 || !attached_to_word(bytes[span.start() - 1]))
            && (span.end() == bytes.len() || !attached_to_word(bytes[span.end()]))
            && issuable(&found[1], &found[2], &found[3])
    })
}

#[cfg(test)]
#[path = "literal_ssn_echo_tests.rs"]
mod tests;
