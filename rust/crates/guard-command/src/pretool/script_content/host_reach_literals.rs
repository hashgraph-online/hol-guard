//! The value Python gives a string literal: escapes decoded, and a
//! formatted string's replacement fields set apart.

use std::iter::Peekable;
use std::str::{CharIndices, Chars};

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

/// A formatted string's body split at its replacement fields: the text
/// around them, with `{{` and `}}` read as braces, and the field expressions
/// between, so there is always one more piece of text than fields. A quote
/// inside a field opens a string that runs to its closing quote, so the `}`
/// in `{len("}")}` does not end the field. `None` when a field or a string
/// inside one is left open, as the scan cannot tell where the field ends.
pub(super) fn format_template(body: &str) -> Option<(Vec<String>, Vec<&str>)> {
    let mut pieces = vec![String::new()];
    let mut fields = Vec::new();
    let mut chars = body.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        match c {
            '{' if chars.next_if(|(_, next)| *next == '{').is_some() => {
                pieces.last_mut()?.push('{')
            }
            '}' if chars.next_if(|(_, next)| *next == '}').is_some() => {
                pieces.last_mut()?.push('}')
            }
            '{' => {
                let end = field_end(&mut chars)?;
                fields.push(&body[index + 1..end]);
                pieces.push(String::new());
            }
            _ => pieces.last_mut()?.push(c),
        }
    }
    Some((pieces, fields))
}

/// Where the replacement field just opened ends, counting nested braces and
/// skipping over the strings inside it.
fn field_end(chars: &mut Peekable<CharIndices<'_>>) -> Option<usize> {
    let mut depth = 1usize;
    let mut quote = None;
    while let Some((index, c)) = chars.next() {
        if let Some(open) = quote {
            if c == '\\' {
                chars.next();
            } else if c == open {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// The fill characters a replacement field's format spec may pad with: `/`
/// for `{"etc":/>4}`, and when a nested field supplies the fill, as in
/// `{"etc":{fill}>4}`, each character that can turn a relative path into
/// one that reaches out (`/`, `.`, `~`). A nested width such as
/// `{"Total":{width}}` names no fill. Only a spec at the field's top
/// level counts: a `:` inside a string, brackets or a call belongs to the
/// expression.
pub(super) fn spec_fill(field: &str) -> Vec<char> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut chars = field.char_indices();
    while let Some((index, c)) = chars.next() {
        if let Some(open) = quote {
            if c == '\\' {
                chars.next();
            } else if c == open {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ':' if depth == 0 => {
                let spec = &field[index + 1..];
                if let Some(nested) = spec.strip_prefix('{') {
                    let after = nested.find('}').map_or("", |end| &nested[end + 1..]);
                    let quoted = nested.contains(['\'', '"']);
                    return if quoted || after.starts_with(['<', '>', '^', '=', '{']) {
                        vec!['/', '.', '~']
                    } else {
                        Vec::new()
                    };
                }
                let mut spec = spec.chars();
                return match (spec.next(), spec.next()) {
                    (Some(fill), Some(align)) if "<>^={".contains(align) => vec![fill],
                    _ => Vec::new(),
                };
            }
            _ => {}
        }
    }
    Vec::new()
}
