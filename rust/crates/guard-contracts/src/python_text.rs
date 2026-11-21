//! Text compatibility shared by native ports of Python contracts.

/// CPython's `str.isspace()` set, including the information separators
/// U+001C through U+001F that Rust's `char::is_whitespace` excludes.
#[must_use]
pub fn is_python_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{09}'..='\u{0d}'
            | ' '
            | '\u{1c}'..='\u{1f}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// Borrow the substring Python's `str.strip()` would return.
#[must_use]
pub fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

#[cfg(test)]
mod tests {
    use super::{is_python_space, python_strip};

    #[test]
    fn whitespace_matches_cpython_for_every_unicode_scalar() {
        let expected = "\t\n\u{0b}\u{0c}\r\u{1c}\u{1d}\u{1e}\u{1f} \u{85}\u{a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}";
        let actual: String = (0..=0x10ffff)
            .filter_map(char::from_u32)
            .filter(|ch| is_python_space(*ch))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn strip_keeps_interior_whitespace_and_non_whitespace_boundaries() {
        assert_eq!(python_strip("\u{1c}\u{a0}a\u{1d} b\u{3000}\n"), "a\u{1d} b");
        assert_eq!(
            python_strip("\u{200b} value \u{feff}"),
            "\u{200b} value \u{feff}"
        );
        assert_eq!(python_strip("\u{1c}\u{3000}"), "");
        assert_eq!(python_strip(""), "");
    }
}
