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
static SSN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([0-9]{3})-([0-9]{2})-([0-9]{4})").expect("ssn pattern"));

const PRINTERS: [&str; 2] = ["echo", "printf"];

fn issuable(area: &str, group: &str, serial: &str) -> bool {
    let area_ok = area != "000" && area != "666" && !area.starts_with('9');
    area_ok && group != "00" && serial != "0000"
}

// Keep the original asymmetric boundaries: a period before the candidate
// can be part of a version, but trailing sentence punctuation is harmless.
fn attached_before(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'/' | b':')
}

fn attached_after(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/' | b':')
}

// Decode the printable escapes supported by shell printf format strings.
// Interpret only these escaped format bytes; echo (without -e) is untouched.
// Octal and hex forms must not conceal a printed SSN from the review floor.
fn decode_printf_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('a') => out.push('\x07'),
            Some('b') => out.push('\x08'),
            Some('f') => out.push('\x0c'),
            Some('v') => out.push('\x0b'),
            Some('e') => out.push('\x1b'),
            Some('\\') => out.push('\\'),
            Some('x') => {
                let mut hex = String::new();
                while hex.len() < 2 && chars.peek().is_some_and(char::is_ascii_hexdigit) {
                    hex.push(chars.next().expect("peeked hexadecimal digit"));
                }
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    out.push(char::from(byte));
                } else {
                    out.push('\\');
                    out.push('x');
                }
            }
            Some(digit @ '0'..='7') => {
                let mut octal = digit.to_string();
                while octal.len() < 3 && chars.peek().is_some_and(|c| ('0'..='7').contains(c)) {
                    octal.push(chars.next().expect("peeked octal digit"));
                }
                let byte = u16::from_str_radix(&octal, 8).expect("octal digits") as u8;
                out.push(char::from(byte));
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

// Parse only a single literal print. Shell quote removal can join fragments:
// 123-45-67"89" prints 123-45-6789, while '123-45-6789'0 is attached.
// A comment starts at an unquoted, unescaped word boundary, so syntax after
// it is not executable. Reject substitutions, operators and multiline input.
fn literal_print_text(command: &str) -> Option<String> {
    let mut decoded = String::with_capacity(command.len());
    let mut quote: Option<char> = None;
    let mut word_start = true;
    let mut chars = command.chars();
    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    decoded.push(ch);
                }
            }
            Some('"') => match ch {
                '"' => quote = None,
                '$' | '\x60' | '\n' | '\r' => return None,
                '\\' => {
                    let escaped = chars.next()?;
                    match escaped {
                        '$' | '\x60' | '"' | '\\' => decoded.push(escaped),
                        '\n' | '\r' => return None,
                        _ => {
                            decoded.push('\\');
                            decoded.push(escaped);
                        }
                    }
                }
                _ => decoded.push(ch),
            },
            _ => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    word_start = false;
                }
                ' ' | '\t' => {
                    decoded.push(ch);
                    word_start = true;
                }
                '#' if word_start => break,
                '\\' => {
                    let escaped = chars.next()?;
                    if matches!(escaped, '\n' | '\r') {
                        return None;
                    }
                    decoded.push(escaped);
                    word_start = false;
                }
                '|' | ';' | '&' | '<' | '>' | '$' | '\x60' | '\n' | '\r' | '(' | ')' => {
                    return None;
                }
                _ => {
                    decoded.push(ch);
                    word_start = false;
                }
            },
        }
    }
    quote.is_none().then_some(decoded)
}

/// Whether command is a single echo/printf that prints a plausible US SSN.
pub(super) fn echoes_ssn(command: &str) -> bool {
    let trimmed = command.trim();
    let program = trimmed.split_whitespace().next().unwrap_or("");
    if !PRINTERS.contains(&program) {
        return false;
    }
    let Some(decoded) = literal_print_text(trimmed) else {
        return false;
    };
    let decoded = if program == "printf" {
        decode_printf_escapes(&decoded)
    } else {
        decoded
    };
    let bytes = decoded.as_bytes();
    SSN.captures_iter(&decoded).any(|found| {
        let span = found.get(0).expect("SSN capture");
        (span.start() == 0 || !attached_before(bytes[span.start() - 1]))
            && (span.end() == bytes.len() || !attached_after(bytes[span.end()]))
            && issuable(&found[1], &found[2], &found[3])
    })
}

#[cfg(test)]
#[path = "literal_ssn_echo_tests.rs"]
mod tests;
