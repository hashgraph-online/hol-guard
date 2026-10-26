//! Python 3.12 `str` semantics the artifact risk wording and matching relied
//! on: `re` word characters, `str.isspace`, `strip`, `capitalize` and
//! `PurePath.name`.

use std::sync::LazyLock;

use regex::Regex;

/// Python `re` word characters for `str` patterns: letters, numbers and `_`.
const WORD_CLASS: &str = r"\p{L}\p{N}_";

static WORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!("^[{WORD_CLASS}]$")).expect("word character class compiles")
});

/// Whether Python `re` treats `value` as a word character.
pub(super) fn is_word(value: char) -> bool {
    if value.is_ascii() {
        return value.is_ascii_alphanumeric() || value == '_';
    }
    let mut buffer = [0u8; 4];
    WORD.is_match(value.encode_utf8(&mut buffer))
}

/// Python `str.isspace()` for one character.
pub(super) fn is_space(value: char) -> bool {
    value.is_whitespace() || ('\u{1C}'..='\u{1F}').contains(&value)
}

/// Python `str.strip()` with no arguments.
pub(super) fn strip(value: &str) -> &str {
    value.trim_matches(is_space)
}

/// Python `str.capitalize()`: the first character titlecased, the rest
/// lowercased with the whole string as final-sigma context.
pub(super) fn capitalize(value: &str) -> String {
    let Some(first) = value.chars().next() else {
        return String::new();
    };
    let lowered = value.to_lowercase();
    let first_lower = first.to_lowercase().collect::<String>();
    let rest = lowered.get(first_lower.len()..).unwrap_or_default();
    let mut capitalized = title_case(first);
    capitalized.push_str(rest);
    capitalized
}

/// `RiskSignalV2` title: the stripped reason with its first character
/// uppercased, or a fixed title when nothing is left.
pub(super) fn title_from_reason(reason: &str) -> String {
    let stripped = strip(reason);
    let Some(first) = stripped.chars().next() else {
        return "Guard risk signal".to_owned();
    };
    let mut title = first.to_uppercase().collect::<String>();
    title.push_str(&stripped[first.len_utf8()..]);
    title
}

/// Python's full titlecase mapping for one character. Only these characters
/// titlecase differently from their full uppercase mapping.
fn title_case(value: char) -> String {
    let mapped: &str = match value {
        '\u{DF}' => "Ss",
        '\u{1C4}'..='\u{1C6}' => "\u{1C5}",
        '\u{1C7}'..='\u{1C9}' => "\u{1C8}",
        '\u{1CA}'..='\u{1CC}' => "\u{1CB}",
        '\u{1F1}'..='\u{1F3}' => "\u{1F2}",
        '\u{587}' => "\u{535}\u{582}",
        '\u{10D0}'..='\u{10FA}'
        | '\u{10FD}'..='\u{10FF}'
        | '\u{1F88}'..='\u{1F8F}'
        | '\u{1F98}'..='\u{1F9F}'
        | '\u{1FA8}'..='\u{1FAF}'
        | '\u{1FBC}'
        | '\u{1FCC}'
        | '\u{1FFC}' => return value.to_string(),
        '\u{1F80}'..='\u{1F87}' | '\u{1F90}'..='\u{1F97}' | '\u{1FA0}'..='\u{1FA7}' => {
            return char::from_u32(u32::from(value) | 0x8)
                .map_or_else(|| value.to_string(), |mapped| mapped.to_string());
        }
        '\u{1FB2}' => "\u{1FBA}\u{345}",
        '\u{1FB3}' => "\u{1FBC}",
        '\u{1FB4}' => "\u{386}\u{345}",
        '\u{1FB7}' => "\u{391}\u{342}\u{345}",
        '\u{1FC2}' => "\u{1FCA}\u{345}",
        '\u{1FC3}' => "\u{1FCC}",
        '\u{1FC4}' => "\u{389}\u{345}",
        '\u{1FC7}' => "\u{397}\u{342}\u{345}",
        '\u{1FF2}' => "\u{1FFA}\u{345}",
        '\u{1FF3}' => "\u{1FFC}",
        '\u{1FF4}' => "\u{38F}\u{345}",
        '\u{1FF7}' => "\u{3A9}\u{342}\u{345}",
        '\u{FB00}' => "Ff",
        '\u{FB01}' => "Fi",
        '\u{FB02}' => "Fl",
        '\u{FB03}' => "Ffi",
        '\u{FB04}' => "Ffl",
        '\u{FB05}' | '\u{FB06}' => "St",
        '\u{FB13}' => "\u{544}\u{576}",
        '\u{FB14}' => "\u{544}\u{565}",
        '\u{FB15}' => "\u{544}\u{56B}",
        '\u{FB16}' => "\u{54E}\u{576}",
        '\u{FB17}' => "\u{544}\u{56D}",
        _ => return value.to_uppercase().collect(),
    };
    mapped.to_owned()
}

/// `PurePath(path).name` on POSIX: the last component, ignoring empty and
/// `.` components.
#[cfg(not(windows))]
pub(super) fn path_name(path: &str) -> &str {
    path.split('/')
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or_default()
}

/// `PureWindowsPath(path).name`: the last component after the drive or UNC
/// share, splitting on both separators.
#[cfg(windows)]
pub(super) fn path_name(path: &str) -> &str {
    let separator = |value: char| value == '/' || value == '\\';
    let mut rest = path;
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        rest = &path[2..];
    } else if bytes.len() >= 2 && separator(char::from(bytes[0])) && separator(char::from(bytes[1]))
    {
        let mut parts = path[2..].splitn(3, separator);
        let server = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        if server.is_empty() || share.is_empty() {
            return "";
        }
        rest = parts.next().unwrap_or_default();
    }
    rest.split(separator)
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or_default()
}
