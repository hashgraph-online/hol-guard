//! Cloud-safe text scrub (`local_request_snapshots.py` `_cloud_scrub_text`
//! plus `redaction.py` `redact_sensitive_text`): the one rule set every Guard
//! Cloud payload (review requests, receipts, retry messages) is scrubbed with.

use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::cloud_scrub_shell::{py_isspace, shlex_quote, shlex_split};
use crate::cloud_scrub_source_search::{protect_spans, source_search_pattern_spans};
use crate::redacted_command_tokens::redact_text;

/// Python `\s` also matches the ASCII separators `\x1c`-`\x1f`.
const S: &str = r"[\s\x1c-\x1f]";
/// Python `\w` for `str` patterns (alphanumeric or underscore), as class members.
const W: &str = r"\p{L}\p{N}_";
const MAX_DEPTH: usize = 128;

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("cloud scrub pattern compiles")
}

static SPACED_SECRET_ARGUMENT: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r#"(?i)(?P<prefix>(?:^|{S})--?(?:[{W}-]*(?:api[-_]?key|token|secret|password|credential|authorization|cookie)[{W}-]*)(?:{S}+|=))(?:"[^"]*"|'[^']*'|[^\s\x1c-\x1f]+)"#
    ))
});

static INLINE_PREFIXES: LazyLock<[Regex; 2]> = LazyLock::new(|| {
    [
        compile(&format!(r#"(?i)"?sync_state\.credentials"?{S}*[:=]{S}*"#)),
        compile(&format!(
            r#"(?i)"?(?:access[_-]?token|refresh[_-]?token|authorization[_-]?code|user[_-]?code|dpop[_-]?private[_-]?key(?:[_-]?(?:pem|ref))?)"?{S}*[:=]{S}*"#
        )),
    ]
});

static SENSITIVE_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r#"(?i)(sk-[a-z0-9_-]+|(?:token|secret|password|passwd|credentials?|authorization|access[_-]?key|api[_-]?key)(?:{S}*[:=]{S}*|{S}+)(?:bearer{S}+|basic{S}+)?(?P<value>"(?:\\[^\r\n]|[^"\\\r\n])*"|'(?:\\[^\r\n]|[^'\\\r\n])*'|"(?:\\[^\r\n]|[^"\\\r\n])*|'(?:\\[^\r\n]|[^'\\\r\n])*|[^\s\x1c-\x1f,;"']+))"#
    ))
});

static SECRET_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r#"(?is)(?P<prefix>["']?(?:access[_-]?token|refresh[_-]?token|authorization[_-]?code|user[_-]?code|dpop[_-]?private[_-]?key(?:[_-]?(?:pem|ref))?|api[_-]?key|token|secret|password|credential)["']?{S}*[:=]{S}*)(?P<value>"(?:\\.|[^"\\])*\\?"|'(?:\\.|[^'\\])*\\?'|[^\s\x1c-\x1f,;)}}\]]+)"#
    ))
});

static CODE_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?i)\A(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|(?:os\.(?:getenv|environ)|process\.env|getenv|env(?:iron)?\[|config(?:uration)?(?:\.|\[)|settings(?:\.|\[)|secrets?(?:\.|\[)|credentials?(?:\.|\[))|[A-Za-z_][A-Za-z0-9_.]*\([^\n]*\)|(?:none|null|undefined|true|false|value|variable|placeholder))\z",
    )
});

const CODE_VALUE_PREFIXES: [&str; 20] = [
    "os.getenv(",
    "os.environ",
    "process.env",
    "getenv(",
    "env[",
    "environment[",
    "config.",
    "config[",
    "configuration.",
    "configuration[",
    "settings.",
    "settings[",
    "secret.",
    "secret[",
    "secrets.",
    "secrets[",
    "credential.",
    "credential[",
    "credentials.",
    "credentials[",
];

fn py_strip(value: &str) -> &str {
    value.trim_matches(py_isspace)
}

fn is_code_value(value: &str) -> bool {
    let mut candidate = py_strip(value);
    let chars: Vec<char> = candidate.chars().collect();
    if chars.len() >= 2 && chars[0] == chars[chars.len() - 1] && matches!(chars[0], '\'' | '"') {
        let inner_start = chars[0].len_utf8();
        candidate = py_strip(&candidate[inner_start..candidate.len() - inner_start]);
    }
    let lower = candidate.to_lowercase();
    if CODE_VALUE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return true;
    }
    CODE_VALUE.is_match(candidate)
}

fn scrub_search_pattern(value: &str) -> String {
    let known_secret_safe = redact_text(value).text;
    SECRET_ASSIGNMENT
        .replace_all(&known_secret_safe, |captures: &Captures| {
            if is_code_value(&captures["value"]) {
                return captures[0].to_owned();
            }
            format!("{}[redacted]", &captures["prefix"])
        })
        .into_owned()
}

fn safe_source_search_token(raw: &str, depth: usize) -> String {
    let Some(parsed) = shlex_split(raw) else {
        return raw.to_owned();
    };
    if parsed.len() != 1 {
        return raw.to_owned();
    }
    let original = &parsed[0];
    let nested = depth < MAX_DEPTH
        && !source_search_pattern_spans(&original.chars().collect::<Vec<_>>()).is_empty();
    let safe = if nested {
        scrub(original, depth + 1)
    } else {
        scrub_search_pattern(original)
    };
    if &safe == original {
        raw.to_owned()
    } else {
        shlex_quote(&safe)
    }
}

/// `redact_sensitive_text`.
pub fn redact_sensitive_text(value: &str) -> String {
    let mut redacted = value.to_owned();
    for pattern in INLINE_PREFIXES.iter() {
        redacted = redact_inline_secret_assignments(&redacted, pattern);
    }
    SENSITIVE_TEXT
        .replace_all(&redacted, |captures: &Captures| {
            if let Some(value) = captures.name("value") {
                let stripped = value.as_str().trim_matches(|c| c == '"' || c == '\'');
                if matches!(stripped, "[redacted]" | "***" | "*****") {
                    return captures[0].to_owned();
                }
            }
            "[redacted]".to_owned()
        })
        .into_owned()
}

fn redact_inline_secret_assignments(value: &str, pattern: &Regex) -> String {
    let mut redacted = String::with_capacity(value.len());
    let mut search_start = 0usize;
    loop {
        let Some(found) = pattern.find_at(value, search_start) else {
            redacted.push_str(&value[search_start..]);
            return redacted;
        };
        redacted.push_str(&value[search_start..found.start()]);
        redacted.push_str("[redacted]");
        search_start = consume_inline_secret_value(value, found.end());
    }
}

fn consume_inline_secret_value(value: &str, start: usize) -> usize {
    let bytes = value.as_bytes();
    if start >= bytes.len() {
        return start;
    }
    match bytes[start] {
        quote @ (b'"' | b'\'') => consume_quoted(bytes, start, quote),
        b'{' | b'[' => consume_balanced(bytes, start),
        _ => {
            let mut end = start;
            while end < bytes.len() && !b", \t\r\n;}]".contains(&bytes[end]) {
                end += 1;
            }
            end
        }
    }
}

fn consume_quoted(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut index = start + 1;
    while index < bytes.len() {
        let character = bytes[index];
        if character == b'\\' {
            index += 2;
            continue;
        }
        index += 1;
        if character == quote {
            return index;
        }
    }
    bytes.len()
}

fn consume_balanced(bytes: &[u8], start: usize) -> usize {
    let closing = |c: u8| if c == b'{' { b'}' } else { b']' };
    let mut stack = vec![closing(bytes[start])];
    let mut index = start + 1;
    let mut active_quote: Option<u8> = None;
    while index < bytes.len() {
        let character = bytes[index];
        if let Some(quote) = active_quote {
            if character == b'\\' {
                index += 2;
                continue;
            }
            index += 1;
            if character == quote {
                active_quote = None;
            }
            continue;
        }
        if character == b'"' || character == b'\'' {
            active_quote = Some(character);
            index += 1;
            continue;
        }
        if character == b'{' || character == b'[' {
            stack.push(closing(character));
            index += 1;
            continue;
        }
        index += 1;
        if stack.last() == Some(&character) {
            stack.pop();
            if stack.is_empty() {
                return index;
            }
        }
    }
    bytes.len()
}

fn scrub(value: &str, depth: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    let spans = source_search_pattern_spans(&chars);
    let (protected, replacements) = if spans.is_empty() {
        (value.to_owned(), Vec::new())
    } else {
        protect_spans(&chars, &spans, |raw| safe_source_search_token(raw, depth))
    };
    let without_spaced = SPACED_SECRET_ARGUMENT
        .replace_all(&protected, |captures: &Captures| {
            format!("{}[redacted]", &captures["prefix"])
        })
        .into_owned();
    let mut scrubbed = redact_sensitive_text(&redact_text(&without_spaced).text);
    for (placeholder, replacement) in replacements {
        scrubbed = scrubbed.replace(&placeholder, &replacement);
    }
    scrubbed
}

/// `_cloud_scrub_text`.
pub fn cloud_scrub_text(value: &str) -> String {
    scrub(value, 0)
}
