//! Faithful ports of the Python text and path primitives the daemon lifecycle
//! decisions were written against: `shlex.split`, `ntpath.basename`,
//! `int()` for decimal text, `str.splitlines`, `str.isspace` and the lexical
//! `pathlib.PurePosixPath` normalisation.

/// `str.isspace`: Unicode White_Space plus the ASCII information separators.
pub(crate) fn py_isspace(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

pub(crate) fn py_strip(text: &str) -> &str {
    text.trim_matches(py_isspace)
}

pub(crate) fn py_lstrip(text: &str) -> &str {
    text.trim_start_matches(py_isspace)
}

/// `str.splitlines()` without keeping line ends.
pub(crate) fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        let breaks = matches!(
            character,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}'
        ) || matches!(character, '\u{2028}' | '\u{2029}');
        if !breaks {
            continue;
        }
        lines.push(&text[start..index]);
        let mut end = index + character.len_utf8();
        if character == '\r' && chars.peek().is_some_and(|(_, next)| *next == '\n') {
            chars.next();
            end += 1;
        }
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `shlex.split(text)` (POSIX rules, no comments). `None` is `ValueError`.
pub(crate) fn shlex_split(text: &str) -> Option<Vec<String>> {
    let mut chars = text.chars();
    let mut tokens = Vec::new();
    while let Some(token) = read_token(&mut chars)? {
        tokens.push(token);
    }
    Some(tokens)
}

fn is_shlex_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

/// Outer `None` is a parse error; inner `None` is end of input.
fn read_token(chars: &mut std::str::Chars<'_>) -> Option<Option<String>> {
    let mut token = String::new();
    let mut quoted = false;
    let mut state = ' ';
    let mut escaped_from = ' ';
    loop {
        let next = chars.next();
        match state {
            ' ' => match next {
                None => break,
                Some(c) if is_shlex_space(c) => {
                    if !token.is_empty() || quoted {
                        break;
                    }
                }
                Some('\\') => {
                    escaped_from = 'a';
                    state = '\\';
                }
                Some(c @ ('\'' | '"')) => state = c,
                Some(c) => {
                    token.push(c);
                    state = 'a';
                }
            },
            '\'' | '"' => {
                quoted = true;
                match next? {
                    c if c == state => state = 'a',
                    '\\' if state == '"' => {
                        escaped_from = state;
                        state = '\\';
                    }
                    c => token.push(c),
                }
            }
            '\\' => {
                let c = next?;
                if matches!(escaped_from, '\'' | '"') && c != '\\' && c != escaped_from {
                    token.push('\\');
                }
                token.push(c);
                state = escaped_from;
            }
            _ => match next {
                None => break,
                Some(c) if is_shlex_space(c) => {
                    state = ' ';
                    if !token.is_empty() || quoted {
                        break;
                    }
                }
                Some(c @ ('\'' | '"')) => state = c,
                Some('\\') => {
                    escaped_from = 'a';
                    state = '\\';
                }
                Some(c) => token.push(c),
            },
        }
    }
    if token.is_empty() && !quoted {
        return Some(None);
    }
    Some(Some(token))
}

/// Index where the tail begins after `ntpath.splitroot` (Python 3.12).
fn nt_root_end(chars: &[char]) -> usize {
    let find = |from: usize| {
        chars
            .get(from..)
            .and_then(|rest| rest.iter().position(|c| *c == '\\'))
            .map(|offset| from + offset)
    };
    if chars.first() == Some(&'\\') {
        if chars.get(1) != Some(&'\\') {
            return 1;
        }
        let unc: [char; 8] = ['\\', '\\', '?', '\\', 'U', 'N', 'C', '\\'];
        let verbatim = chars.len() >= 8
            && chars[..8]
                .iter()
                .zip(unc)
                .all(|(have, want)| have.eq_ignore_ascii_case(&want));
        let start = if verbatim { 8 } else { 2 };
        let Some(index) = find(start) else {
            return chars.len();
        };
        return find(index + 1).map_or(chars.len(), |second| second + 1);
    }
    if chars.get(1) == Some(&':') {
        return if chars.get(2) == Some(&'\\') { 3 } else { 2 };
    }
    0
}

/// `ntpath.basename`, used to name a launcher on any host.
pub(crate) fn ntpath_basename(path: &str) -> String {
    let chars: Vec<char> = path
        .chars()
        .map(|c| if c == '/' { '\\' } else { c })
        .collect();
    let tail = &chars[nt_root_end(&chars)..];
    let start = tail
        .iter()
        .rposition(|c| *c == '\\')
        .map_or(0, |index| index + 1);
    tail[start..].iter().collect()
}

/// Inclusive Unicode `Nd` ranges whose first code point is digit zero.
/// Generated from Python's `unicodedata.decimal`.
const DECIMAL_RANGES: &[(u32, u32)] = &[
    (0x0030, 0x0039),
    (0x0660, 0x0669),
    (0x06F0, 0x06F9),
    (0x07C0, 0x07C9),
    (0x0966, 0x096F),
    (0x09E6, 0x09EF),
    (0x0A66, 0x0A6F),
    (0x0AE6, 0x0AEF),
    (0x0B66, 0x0B6F),
    (0x0BE6, 0x0BEF),
    (0x0C66, 0x0C6F),
    (0x0CE6, 0x0CEF),
    (0x0D66, 0x0D6F),
    (0x0DE6, 0x0DEF),
    (0x0E50, 0x0E59),
    (0x0ED0, 0x0ED9),
    (0x0F20, 0x0F29),
    (0x1040, 0x1049),
    (0x1090, 0x1099),
    (0x17E0, 0x17E9),
    (0x1810, 0x1819),
    (0x1946, 0x194F),
    (0x19D0, 0x19D9),
    (0x1A80, 0x1A89),
    (0x1A90, 0x1A99),
    (0x1B50, 0x1B59),
    (0x1BB0, 0x1BB9),
    (0x1C40, 0x1C49),
    (0x1C50, 0x1C59),
    (0xA620, 0xA629),
    (0xA8D0, 0xA8D9),
    (0xA900, 0xA909),
    (0xA9D0, 0xA9D9),
    (0xA9F0, 0xA9F9),
    (0xAA50, 0xAA59),
    (0xABF0, 0xABF9),
    (0xFF10, 0xFF19),
    (0x104A0, 0x104A9),
    (0x10D30, 0x10D39),
    (0x11066, 0x1106F),
    (0x110F0, 0x110F9),
    (0x11136, 0x1113F),
    (0x111D0, 0x111D9),
    (0x112F0, 0x112F9),
    (0x11450, 0x11459),
    (0x114D0, 0x114D9),
    (0x11650, 0x11659),
    (0x116C0, 0x116C9),
    (0x11730, 0x11739),
    (0x118E0, 0x118E9),
    (0x11950, 0x11959),
    (0x11C50, 0x11C59),
    (0x11D50, 0x11D59),
    (0x11DA0, 0x11DA9),
    (0x11F50, 0x11F59),
    (0x16A60, 0x16A69),
    (0x16AC0, 0x16AC9),
    (0x16B50, 0x16B59),
    (0x1D7CE, 0x1D7D7),
    (0x1D7D8, 0x1D7E1),
    (0x1D7E2, 0x1D7EB),
    (0x1D7EC, 0x1D7F5),
    (0x1D7F6, 0x1D7FF),
    (0x1E140, 0x1E149),
    (0x1E2F0, 0x1E2F9),
    (0x1E4F0, 0x1E4F9),
    (0x1E950, 0x1E959),
    (0x1FBF0, 0x1FBF9),
];

fn decimal_value(character: char) -> Option<u32> {
    let code = u32::from(character);
    for &(start, end) in DECIMAL_RANGES {
        if code < start {
            return None;
        }
        if code <= end {
            return Some(code - start);
        }
    }
    None
}

/// `int(text)` for base-10 text: surrounding whitespace, one sign, Unicode
/// decimal digits with single underscores between them. Values beyond `i64`
/// are rejected.
pub(crate) fn python_int(text: &str) -> Option<i64> {
    let trimmed = py_strip(text);
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let mut value: i64 = 0;
    let mut previous_underscore = false;
    let mut saw_digit = false;
    for character in digits.chars() {
        if character == '_' {
            if previous_underscore || !saw_digit {
                return None;
            }
            previous_underscore = true;
            continue;
        }
        let digit = decimal_value(character)?;
        previous_underscore = false;
        saw_digit = true;
        value = value.checked_mul(10)?.checked_add(i64::from(digit))?;
    }
    if previous_underscore || !saw_digit {
        return None;
    }
    Some(if negative { -value } else { value })
}

/// `str(PurePosixPath(text))`: drop empty and `.` components and trailing
/// separators; exactly two leading slashes stay, more collapse to one.
pub(crate) fn norm_path(text: &str) -> String {
    let leading = text.chars().take_while(|c| *c == '/').count();
    let root = match leading {
        0 => "",
        2 => "//",
        _ => "/",
    };
    let components: Vec<&str> = text
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    if components.is_empty() && root.is_empty() {
        return ".".to_owned();
    }
    format!("{root}{}", components.join("/"))
}

/// Lexical comparison used when a path cannot be resolved.
pub(crate) fn lexical_equal(left: &str, right: &str, nt: bool) -> bool {
    if !nt {
        return norm_path(left) == norm_path(right);
    }
    let fold = |text: &str| norm_path(&text.replace('\\', "/")).to_lowercase();
    fold(left) == fold(right)
}
