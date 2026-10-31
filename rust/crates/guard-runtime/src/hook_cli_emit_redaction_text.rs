//! The string rules of the document `hol-guard hook` prints: the string
//! branch of `render._redact_payload(command="hook")`, which runs
//! `_SENSITIVE_STRING_PATTERNS` in order, then
//! `_redact_sensitive_assignments`, then `redaction.redact_local_path`.
//!
//! Python `re` semantics are kept by hand where Rust's `regex` differs: `\s`
//! also matches U+001C..U+001F as `str.isspace` does, `\b` reads Python's
//! `isalnum` word class, and IGNORECASE letters are spelled out as the
//! classes Python matches (`i` also U+0130 and U+0131, `k` also U+212A, `s`
//! also U+017F), so no case-fold table decides a match.

use std::sync::OnceLock;

use guard_command::command_option_parsing::python_is_alphanumeric;
use regex::{Captures, Regex};

use crate::daemon_lifecycle_text::py_isspace;

pub(crate) const MASK: &str = "*****";
/// `_SENSITIVE_ASSIGNMENT_TOKENS` and `_SENSITIVE_API_KEY_FORMS`.
const SENSITIVE_ASSIGNMENT_TOKENS: [&str; 7] = [
    "token",
    "secret",
    "password",
    "credential",
    "apikey",
    "api_key",
    "api-key",
];
/// Python `\s` inside a character class.
const SPACE: &str = r"\s\x{1c}-\x{1f}";

pub(crate) fn compiled(
    cell: &'static OnceLock<Regex>,
    pattern: impl FnOnce() -> String,
) -> &'static Regex {
    cell.get_or_init(|| Regex::new(&pattern()).expect("static pattern"))
}

/// `literal` as Python's IGNORECASE matches it.
fn ignore_case(literal: &str) -> String {
    literal
        .chars()
        .map(|character| match character.to_ascii_lowercase() {
            'i' => r"[iI\x{130}\x{131}]".to_owned(),
            'k' => r"[kK\x{212a}]".to_owned(),
            's' => r"[sS\x{17f}]".to_owned(),
            lower if lower.is_ascii_alphabetic() => {
                format!("[{lower}{}]", lower.to_ascii_uppercase())
            }
            other => regex::escape(other.encode_utf8(&mut [0; 4])),
        })
        .collect()
}

/// Python's `\w` for a `str` pattern.
fn is_word(character: char) -> bool {
    character == '_' || python_is_alphanumeric(character)
}

/// Python's `\b` between `before` and `after` (`None` past either end).
fn word_boundary(before: Option<char>, after: Option<char>) -> bool {
    before.is_some_and(is_word) != after.is_some_and(is_word)
}

/// The string branch of `_redact_payload`: `_SENSITIVE_STRING_PATTERNS` in
/// order, then `_redact_sensitive_assignments`, then `redact_local_path`.
pub(crate) fn redact_text(text: &str, home_dir: Option<&str>) -> String {
    static PRIVATE_KEY: OnceLock<Regex> = OnceLock::new();
    static AUTHORIZATION: OnceLock<Regex> = OnceLock::new();
    static API_KEY: OnceLock<Regex> = OnceLock::new();
    static BEARER: OnceLock<Regex> = OnceLock::new();
    static NPM_TOKEN: OnceLock<Regex> = OnceLock::new();
    static DATABASE_URL: OnceLock<Regex> = OnceLock::new();
    let private_key = compiled(&PRIVATE_KEY, || {
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
            .to_owned()
    });
    let mut redacted = private_key.replace_all(text, MASK).into_owned();
    let authorization = compiled(&AUTHORIZATION, || {
        format!(
            "({}:[{SPACE}]*)({}[{SPACE}]+)?[^{SPACE},;]+",
            ignore_case("authorization"),
            ignore_case("bearer"),
        )
    });
    redacted = authorization
        .replace_all(&redacted, keep_prefix)
        .into_owned();
    let api_key = compiled(&API_KEY, || {
        format!(
            "({}[-_ ]?{}:[{SPACE}]*)[^{SPACE},;]+",
            ignore_case("api"),
            ignore_case("key"),
        )
    });
    redacted = api_key.replace_all(&redacted, keep_prefix).into_owned();
    redacted = redact_openai_keys(&redacted);
    let bearer = compiled(&BEARER, || {
        format!("({}[{SPACE}]+)[^{SPACE},;]+", ignore_case("bearer"))
    });
    redacted = bearer.replace_all(&redacted, keep_prefix).into_owned();
    let npm_token = compiled(&NPM_TOKEN, || {
        format!(
            "(?:_{}|{}[_ -]?{})[{SPACE}]*[:=][{SPACE}]*[^{SPACE}]+",
            ignore_case("authToken"),
            ignore_case("npm"),
            ignore_case("token"),
        )
    });
    redacted = replace_at_word_start(npm_token, &redacted, "npm token redacted");
    let database_url = compiled(&DATABASE_URL, || {
        format!(
            r"(?:{}(?:{})?|{}|{}(?:\+{})?|{}|{})://[^{SPACE}]+",
            ignore_case("postgres"),
            ignore_case("ql"),
            ignore_case("mysql"),
            ignore_case("mongodb"),
            ignore_case("srv"),
            ignore_case("redis"),
            ignore_case("amqp"),
        )
    });
    redacted = replace_at_word_start(database_url, &redacted, MASK);
    redacted = redact_sensitive_assignments(&redacted);
    redact_local_path(&redacted, home_dir)
}

/// `\1*****`: the matched label stays, the secret after it does not.
fn keep_prefix(captures: &Captures<'_>) -> String {
    format!("{}{MASK}", &captures[1])
}

/// `pattern.sub(replacement, text)` for a Python pattern that opens with
/// `\b`: a candidate the boundary rejects is retried one character later,
/// as Python's scan does.
fn replace_at_word_start(pattern: &Regex, text: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(found) = pattern.find_at(text, search) {
        let before = text[..found.start()].chars().next_back();
        let after = text[found.start()..].chars().next();
        if word_boundary(before, after) {
            out.push_str(&text[copied..found.start()]);
            out.push_str(replacement);
            copied = found.end();
            search = found.end();
        } else {
            search = found.start() + after.map_or(1, char::len_utf8);
        }
        if search > text.len() {
            break;
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// `\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`. The `proj-` prefix is itself made
/// of key characters, so either branch ends a match at the last boundary at
/// least twenty key characters past `sk-`.
fn redact_openai_keys(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if let Some(end) = openai_key_end(&chars, index) {
            out.push_str(MASK);
            index = end;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

fn openai_key_end(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start..start + 3) != Some(&['s', 'k', '-'][..]) {
        return None;
    }
    let before = start.checked_sub(1).map(|index| chars[index]);
    if !word_boundary(before, Some('s')) {
        return None;
    }
    let body = start + 3;
    let key_char =
        |character: &&char| character.is_ascii_alphanumeric() || matches!(**character, '_' | '-');
    let run_end = body + chars[body..].iter().take_while(key_char).count();
    (body + 20..=run_end)
        .rev()
        .find(|end| word_boundary(Some(chars[end - 1]), chars.get(*end).copied()))
}

fn sensitive_assignment_key(key: &[char]) -> bool {
    let lowered: String = key.iter().map(char::to_ascii_lowercase).collect();
    SENSITIVE_ASSIGNMENT_TOKENS
        .iter()
        .any(|token| lowered.contains(token))
}

/// `_redact_sensitive_assignments`: one forward scan that masks the value of
/// every `key=value` whose key names a secret. Indices are characters, as
/// Python's are.
fn redact_sensitive_assignments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let length = chars.len();
    let unquoted_end = |from: usize| {
        let mut end = from;
        while end < length && chars[end] != '&' && !py_isspace(chars[end]) {
            end += 1;
        }
        end
    };
    let mut out = String::new();
    let mut redacted_any = false;
    let mut copied_until = 0;
    let mut search_from = 0;
    // The first index past which each quote is known to have no closing
    // match: `missing_quote_from`.
    let mut missing_single: Option<usize> = None;
    let mut missing_double: Option<usize> = None;
    while let Some(offset) = chars[search_from.min(length)..]
        .iter()
        .position(|character| *character == '=')
    {
        let equals = search_from + offset;
        let mut key_start = equals;
        while key_start > 0
            && chars[key_start - 1].is_ascii()
            && (chars[key_start - 1].is_ascii_alphanumeric()
                || matches!(chars[key_start - 1], '_' | '-'))
        {
            key_start -= 1;
        }
        let key = &chars[key_start..equals];
        if key.is_empty() || !sensitive_assignment_key(key) {
            search_from = equals + 1;
            continue;
        }
        let value_start = equals + 1;
        if value_start >= length {
            search_from = value_start;
            continue;
        }
        let quote = chars[value_start];
        let value_end = if quote == '\'' || quote == '"' {
            let missing = if quote == '\'' {
                &mut missing_single
            } else {
                &mut missing_double
            };
            let limit = *missing;
            let closing = if limit.is_some_and(|limit| value_start + 1 >= limit) {
                None
            } else {
                chars[value_start + 1..]
                    .iter()
                    .position(|character| *character == quote)
                    .map(|offset| value_start + 1 + offset)
            };
            match closing {
                Some(closing) => closing + 1,
                None => {
                    *missing = Some(limit.unwrap_or(length).min(value_start + 1));
                    unquoted_end(value_start)
                }
            }
        } else {
            unquoted_end(value_start)
        };
        if value_end <= value_start {
            search_from = value_start;
            continue;
        }
        out.extend(&chars[copied_until..=equals]);
        out.push_str(MASK);
        redacted_any = true;
        copied_until = value_end;
        search_from = value_end;
    }
    if !redacted_any {
        return text.to_owned();
    }
    out.extend(&chars[copied_until..]);
    out
}

/// `redaction.redact_local_path(value)` with `Path.home()` as `home_dir`.
fn redact_local_path(text: &str, home_dir: Option<&str>) -> String {
    static POSIX_USER_PATH: OnceLock<Regex> = OnceLock::new();
    static WINDOWS_USER_PATH: OnceLock<Regex> = OnceLock::new();
    let shortened = match home_dir {
        Some(home) => replace_home_prefix(text, home),
        None => text.to_owned(),
    };
    let posix = compiled(&POSIX_USER_PATH, || {
        format!(
            r#"(?P<prefix>^|[{SPACE}"'=({{\[])(?P<root>/(?:Users|home)/[^/{SPACE}"'`,;:)}}\]]+)(?P<rest>(?:/[^{SPACE}"'`,;:)}}\]]*)?)"#
        )
    });
    let shortened = posix.replace_all(&shortened, "${prefix}~${rest}");
    let windows = compiled(&WINDOWS_USER_PATH, || {
        format!(
            r#"(?P<prefix>^|[{SPACE}"'=({{\[])(?P<root>[A-Za-z]:[\\/]+Users[\\/]+[^\\/{SPACE}"'`,;:)}}\]]+)(?P<rest>(?:[\\/][^{SPACE}"'`,;:)}}\]]*)?)"#
        )
    });
    windows
        .replace_all(&shortened, "${prefix}~${rest}")
        .into_owned()
}

/// `_replace_home_prefix`.
fn replace_home_prefix(value: &str, home: &str) -> String {
    let prefix = home.trim_end_matches(['/', '\\']);
    if prefix.is_empty() {
        return value.to_owned();
    }
    if value == prefix {
        return "~".to_owned();
    }
    match value.strip_prefix(prefix) {
        Some(rest) if rest.starts_with(['/', '\\']) => format!("~{rest}"),
        _ => value.to_owned(),
    }
}
