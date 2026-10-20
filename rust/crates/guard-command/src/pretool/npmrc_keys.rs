//! The key npm reads from an `.npmrc` line, not the key as it is written.
//!
//! npm parses its configuration with the `ini` package. A quoted key is read
//! as JSON, so `"\u0072egistry"` sets `registry`; an unquoted one drops its
//! escapes and ends at the first unescaped `;` or `#`, so `registry;x` sets
//! `registry` too. Screening the written text would read either as a key npm
//! never sets, so the inertness proof decodes the line the same way and
//! refuses whatever it cannot decode exactly.

use std::str::Chars;

/// The key `ini` records for this line, or `None` when the decoding cannot be
/// reproduced here.
pub(super) fn parsed_key(line: &str) -> Option<String> {
    let written = js_trim(line.split('=').next().unwrap_or_default());
    if quoted(written, '"') {
        // A key JSON cannot read keeps its quotes, which names nothing npm
        // acts on, but the proof does not need to tell those cases apart.
        return json_string(written);
    }
    if quoted(written, '\'') {
        let inner = &written[1..written.len() - 1];
        // `JSON.parse` skips its own whitespace, so the padding around a
        // quoted key inside the single quotes is not part of what it reads.
        let read = inner.trim_matches([' ', '\t', '\n', '\r']);
        return match json_string(read) {
            Some(decoded) => Some(decoded),
            // `ini` drops the quotes first, so anything JSON cannot read is
            // left as it stands.
            None if json_literal(read) => None,
            None => Some(inner.to_owned()),
        };
    }
    Some(unquoted(written))
}

fn quoted(written: &str, mark: char) -> bool {
    written.len() >= 2 && written.starts_with(mark) && written.ends_with(mark)
}

/// Text that `JSON.parse` may read as something other than a string, where
/// this screen stops guessing.
fn json_literal(text: &str) -> bool {
    matches!(text, "true" | "false" | "null")
        || text.starts_with(['{', '[', '"'])
        || text.parse::<f64>().is_ok()
}

fn unquoted(written: &str) -> String {
    let mut decoded = String::new();
    let mut escaped = false;
    for character in written.chars() {
        if escaped {
            if !matches!(character, '\\' | ';' | '#') {
                decoded.push('\\');
            }
            decoded.push(character);
            escaped = false;
        } else if matches!(character, ';' | '#') {
            break;
        } else if character == '\\' {
            escaped = true;
        } else {
            decoded.push(character);
        }
    }
    if escaped {
        decoded.push('\\');
    }
    js_trim(&decoded).to_owned()
}

/// `String.prototype.trim`, which counts U+FEFF as whitespace where Rust's
/// `str::trim` does not. `ini` trims the written key this way, and nothing
/// strips a byte-order mark from the file before it.
pub(super) fn js_trim(text: &str) -> &str {
    text.trim_matches(|character: char| character.is_whitespace() || character == '\u{feff}')
}

fn json_string(written: &str) -> Option<String> {
    let mut characters = written.chars();
    if characters.next()? != '"' {
        return None;
    }
    let mut decoded = String::new();
    loop {
        match characters.next()? {
            '"' => return characters.next().is_none().then_some(decoded),
            '\\' => decoded.push(escape(&mut characters)?),
            control if (control as u32) < 0x20 => return None,
            character => decoded.push(character),
        }
    }
}

fn escape(characters: &mut Chars<'_>) -> Option<char> {
    let decoded = match characters.next()? {
        '"' => '"',
        '\\' => '\\',
        '/' => '/',
        'b' => '\u{8}',
        'f' => '\u{c}',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'u' => return code_point(characters),
        _ => return None,
    };
    Some(decoded)
}

/// A lone surrogate is a string JavaScript can hold and Rust cannot, so it
/// decodes to nothing here and the line stays unproven.
fn code_point(characters: &mut Chars<'_>) -> Option<char> {
    let leading = hex_quad(characters)?;
    if !(0xD800..0xDC00).contains(&leading) {
        return char::from_u32(leading);
    }
    if characters.next()? != '\\' || characters.next()? != 'u' {
        return None;
    }
    let trailing = hex_quad(characters)?;
    if !(0xDC00..0xE000).contains(&trailing) {
        return None;
    }
    char::from_u32(0x10000 + ((leading - 0xD800) << 10) + (trailing - 0xDC00))
}

fn hex_quad(characters: &mut Chars<'_>) -> Option<u32> {
    let mut value = 0;
    for _ in 0..4 {
        value = value * 16 + characters.next()?.to_digit(16)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::parsed_key;

    #[test]
    fn a_quoted_key_is_the_key_json_reads() {
        assert_eq!(parsed_key("\"registry\"=x").as_deref(), Some("registry"));
        assert_eq!(
            parsed_key("\"\\u0072egistry\"=x").as_deref(),
            Some("registry")
        );
        assert_eq!(
            parsed_key("\"regist\\u0072y\" = x").as_deref(),
            Some("registry")
        );
        assert_eq!(parsed_key("'registry'=x").as_deref(), Some("registry"));
        assert_eq!(parsed_key("\"\\ud83d\\ude00\"=x").as_deref(), Some("😀"));
    }

    #[test]
    fn an_unquoted_key_ends_where_the_comment_starts() {
        assert_eq!(
            parsed_key("registry;ignored=x").as_deref(),
            Some("registry")
        );
        assert_eq!(
            parsed_key("registry#ignored=x").as_deref(),
            Some("registry")
        );
        assert_eq!(parsed_key(r"regist\;ry=x").as_deref(), Some("regist;ry"));
        assert_eq!(parsed_key("save-exact=true").as_deref(), Some("save-exact"));
        assert_eq!(parsed_key(r"re\gistry=x").as_deref(), Some(r"re\gistry"));
    }

    #[test]
    fn an_unclosed_quote_is_the_key_it_is_written_as() {
        assert_eq!(parsed_key("\"registry=x").as_deref(), Some("\"registry"));
    }

    #[test]
    fn padding_inside_single_quotes_is_json_whitespace() {
        assert_eq!(
            parsed_key("' \"registry\" '=x").as_deref(),
            Some("registry")
        );
        assert_eq!(
            parsed_key("'\t\"registry\"\n'=x").as_deref(),
            Some("registry")
        );
        assert_eq!(parsed_key("' [\"registry\"] '=x"), None);
        assert_eq!(parsed_key("' 12 '=x"), None);
        assert_eq!(parsed_key("'  '=x").as_deref(), Some("  "));
    }

    #[test]
    fn a_byte_order_mark_is_whitespace_the_way_javascript_reads_it() {
        assert_eq!(
            parsed_key("\u{feff}registry=x").as_deref(),
            Some("registry")
        );
        assert_eq!(
            parsed_key("\u{feff}\"registry\"=x").as_deref(),
            Some("registry")
        );
        assert_eq!(
            parsed_key("registry\u{feff}=x").as_deref(),
            Some("registry")
        );
    }

    #[test]
    fn a_key_this_screen_cannot_decode_stays_unproven() {
        for line in [
            "\"\\q\"=x",
            "\"\\ud800\"=x",
            "\"\\u00\"=x",
            "'12'=x",
            "'true'=x",
        ] {
            assert_eq!(parsed_key(line), None, "{line}");
        }
    }
}
