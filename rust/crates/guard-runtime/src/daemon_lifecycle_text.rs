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

/// `int(text)` for base-10 text: surrounding whitespace, one sign, digits
/// with single underscores between them. Values beyond `i64` are rejected.
pub(crate) fn python_int(text: &str) -> Option<i64> {
    let trimmed = py_strip(text);
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let bytes = digits.as_bytes();
    if bytes.is_empty() || bytes[0] == b'_' || bytes[bytes.len() - 1] == b'_' {
        return None;
    }
    let mut value: i64 = 0;
    let mut previous_underscore = false;
    for byte in bytes {
        if *byte == b'_' {
            if previous_underscore {
                return None;
            }
            previous_underscore = true;
            continue;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        previous_underscore = false;
        value = value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))?;
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
