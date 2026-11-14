//! The value Python gives a string literal: escapes decoded, and a
//! formatted string's replacement fields set apart.

use std::iter::Peekable;
use std::str::Chars;

/// Reads up to `count` digits in `radix` and returns the character they
/// number.
fn escaped_char(chars: &mut Peekable<Chars<'_>>, count: usize, radix: u32) -> Option<char> {
    let mut digits = String::new();
    while digits.len() < count {
        let digit = chars.next_if(|c| c.is_digit(radix))?;
        digits.push(digit);
    }
    u32::from_str_radix(&digits, radix)
        .ok()
        .and_then(char::from_u32)
}

/// The value Python gives a string literal's body. `None` when an escape
/// names a character the scan does not resolve (`\N{...}`) or is malformed.
pub(super) fn literal_value(body: &str, raw: bool) -> Option<String> {
    if raw || !body.contains('\\') {
        return Some(body.to_owned());
    }
    let mut value = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            value.push(c);
            continue;
        }
        let Some(escape) = chars.next() else {
            value.push('\\');
            break;
        };
        match escape {
            '\n' => {}
            '\\' | '\'' | '"' => value.push(escape),
            'n' => value.push('\n'),
            't' => value.push('\t'),
            'r' => value.push('\r'),
            'a' => value.push('\x07'),
            'b' => value.push('\x08'),
            'f' => value.push('\x0c'),
            'v' => value.push('\x0b'),
            'x' => value.push(escaped_char(&mut chars, 2, 16)?),
            'u' => value.push(escaped_char(&mut chars, 4, 16)?),
            'U' => value.push(escaped_char(&mut chars, 8, 16)?),
            '0'..='7' => {
                let mut code = escape.to_digit(8)?;
                for _ in 0..2 {
                    match chars.next_if(|c| c.is_digit(8)) {
                        Some(digit) => code = code * 8 + digit.to_digit(8)?,
                        None => break,
                    }
                }
                value.push(char::from_u32(code)?);
            }
            'N' => return None,
            other => {
                value.push('\\');
                value.push(other);
            }
        }
    }
    Some(value)
}

/// A formatted string's body with each replacement field replaced by an
/// unknown word, `{{` and `}}` read as braces, and the field expressions it
/// held. A field left open runs to the end of the body.
pub(super) fn format_template(body: &str) -> (String, Vec<&str>) {
    let mut template = String::with_capacity(body.len());
    let mut fields = Vec::new();
    let mut chars = body.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        match c {
            '{' if chars.next_if(|(_, next)| *next == '{').is_some() => template.push('{'),
            '}' if chars.next_if(|(_, next)| *next == '}').is_some() => template.push('}'),
            '{' => {
                let mut depth = 1usize;
                let mut end = body.len();
                for (inner, c) in chars.by_ref() {
                    match c {
                        '{' => depth += 1,
                        '}' => depth -= 1,
                        _ => {}
                    }
                    if depth == 0 {
                        end = inner;
                        break;
                    }
                }
                fields.push(&body[index + 1..end]);
                template.push('x');
            }
            _ => template.push(c),
        }
    }
    (template, fields)
}
