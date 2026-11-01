//! Python's `html.unescape`: numeric character references and the HTML5
//! named references, including the legacy names a browser accepts without
//! the closing semicolon.
//!
//! The named references come from `html5_entities.json`, generated from
//! `html.entities.html5`.

use std::collections::HashMap;
use std::sync::OnceLock;

/// The longest named reference the scan reads, in characters.
const MAX_NAME_CHARS: usize = 32;

/// What references to 0x80-0x9F decode to: the Windows-1252 characters,
/// where that code page defines one.
const C1_REPLACEMENTS: [char; 32] = [
    '\u{20ac}', '\u{81}', '\u{201a}', '\u{192}', '\u{201e}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{2c6}', '\u{2030}', '\u{160}', '\u{2039}', '\u{152}', '\u{8d}', '\u{17d}', '\u{8f}',
    '\u{90}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{2dc}', '\u{2122}', '\u{161}', '\u{203a}', '\u{153}', '\u{9d}', '\u{17e}', '\u{178}',
];

fn entities() -> &'static HashMap<String, String> {
    static TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();
    TABLE.get_or_init(|| {
        serde_json::from_str(include_str!("html5_entities.json")).unwrap_or_default()
    })
}

/// `value` with every character reference decoded once.
pub(crate) fn unescape(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        decoded.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match reference(after) {
            Some((consumed, text)) => {
                decoded.push_str(&text);
                rest = &after[consumed..];
            }
            None => {
                decoded.push('&');
                rest = after;
            }
        }
    }
    decoded.push_str(rest);
    decoded
}

/// The reference at the start of `text`, which follows an `&`: how many
/// bytes it spans and what it decodes to.
fn reference(text: &str) -> Option<(usize, String)> {
    if let Some(number) = text.strip_prefix('#') {
        let (digits, radix, prefix) = match number.strip_prefix(['x', 'X']) {
            Some(hex) if hex.starts_with(|c: char| c.is_ascii_hexdigit()) => (hex, 16, 2),
            _ => (number, 10, 1),
        };
        let length = digits
            .bytes()
            .take_while(|byte| match radix {
                16 => byte.is_ascii_hexdigit(),
                _ => byte.is_ascii_digit(),
            })
            .count();
        if length == 0 {
            return None;
        }
        let semicolon = usize::from(digits[length..].starts_with(';'));
        // A number too large for `u32` is past the last code point.
        let code = u32::from_str_radix(&digits[..length], radix).unwrap_or(u32::MAX);
        return Some((prefix + length + semicolon, numeric(code)));
    }
    let name_length: usize = text
        .chars()
        .take_while(|c| !matches!(c, '\t' | '\n' | '\x0c' | ' ' | '<' | '&' | '#' | ';'))
        .take(MAX_NAME_CHARS)
        .map(char::len_utf8)
        .sum();
    if name_length == 0 {
        return None;
    }
    let end = name_length + usize::from(text[name_length..].starts_with(';'));
    let candidate = &text[..end];
    let table = entities();
    if let Some(value) = table.get(candidate) {
        return Some((end, value.clone()));
    }
    // Otherwise the longest defined name, of two characters or more, that
    // begins the reference; the rest is kept as written.
    let cuts: Vec<usize> = candidate
        .char_indices()
        .map(|(index, _)| index)
        .skip(2)
        .collect();
    cuts.into_iter().rev().find_map(|cut| {
        table
            .get(&candidate[..cut])
            .map(|value| (end, format!("{value}{}", &candidate[cut..])))
    })
}

fn numeric(code: u32) -> String {
    match code {
        0 | 0xd800..=0xdfff | 0x11_0000.. => "\u{fffd}".to_owned(),
        0x0d => "\r".to_owned(),
        0x80..=0x9f => C1_REPLACEMENTS[(code - 0x80) as usize].to_string(),
        _ if not_a_character(code) => String::new(),
        _ => char::from_u32(code).map(String::from).unwrap_or_default(),
    }
}

/// Control characters and noncharacters a reference may not produce.
fn not_a_character(code: u32) -> bool {
    matches!(code, 0x1..=0x8 | 0xb | 0xe..=0x1f | 0x7f..=0x9f | 0xfdd0..=0xfdef)
        || code & 0xfffe == 0xfffe
}

#[cfg(test)]
#[path = "html_unescape_tests.rs"]
mod tests;
