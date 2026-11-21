//! The pieces of a script's syntax its dispatch read needs: string literals,
//! lists of words, assignment statements and call arguments, and an
//! expression without what leaves its value's word unchanged.

use std::sync::LazyLock;

use regex::Regex;

use super::values::MAX_DEPTH;

const MAX_WORDS: usize = 64;

const SUFFIXES: [&str; 12] = [
    ".toLowerCase()",
    ".toUpperCase()",
    ".trim()",
    ".lower()",
    ".upper()",
    ".strip()",
    ".casefold()",
    ".downcase",
    ".upcase",
    ".strip",
    ".to_s",
    ".to_sym",
];

static LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"\\]*)"|'([^'\\]*)'"#).unwrap());

static LITERAL_ONLY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^(?:"([^"\\]*)"|'([^'\\]*)'|`([^`\\$]*)`)$"#).unwrap());

/// `command || 'help'`, `command ?? "help"` or `command or "help"`.
static FALLBACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(.+?)\s*(?:\|\||\?\?|\bor\b)\s*(?:"[^"\\]*"|'[^'\\]*'|\[\])$"#).unwrap()
});

/// Python's `command if len(sys.argv) > 1 else "help"`.
static CONDITIONAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(.+?)\s+if\s+.+\s+else\s+.+$").unwrap());

/// `String(command)`, `str(command)`: the brackets are checked by [`enclosed`].
static WRAPPER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:String|str|Array\.from|list)(\(.+\))$").unwrap());

static DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:export\s+)?(?:const|let|var|my|our|local)\s+").unwrap());

static TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:[A-Za-z_$@][\w$.]*|\[.*\]|\{.*\}|\(.*\)",
        r"|\*?[A-Za-z_$][\w$]*(?:\s*,\s*\*?[A-Za-z_$][\w$]*)+\s*,?)$",
    ))
    .unwrap()
});

static WORD_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:new\s+Set\s*\(|Object\.freeze\s*\(|frozenset\s*\(|set\s*\(|tuple\s*\()?",
        r"\s*(\[.*\]|\(.*\)|\{.*\}|%w[\[(].*[\])])\s*\)?$",
    ))
    .unwrap()
});

/// An expression without what leaves its value's word unchanged: case and
/// whitespace conversions, a literal fallback, `String(...)`, and the
/// brackets around it.
pub(super) fn bare(text: &str) -> &str {
    let mut text = text.trim();
    for _ in 0..MAX_DEPTH {
        let before = text;
        for suffix in SUFFIXES {
            if let Some(stripped) = text.strip_suffix(suffix) {
                text = stripped.trim_end();
            }
        }
        for regex in [&*FALLBACK, &*CONDITIONAL] {
            if let Some(inner) = regex.captures(text).and_then(|captures| captures.get(1)) {
                text = inner.as_str().trim();
            }
        }
        let wrapped = WRAPPER.captures(text).and_then(|captures| captures.get(1));
        if let Some(inner) = wrapped.and_then(|m| enclosed(m.as_str())) {
            text = inner.trim();
        }
        if let Some(inner) = enclosed(text) {
            text = inner.trim();
        }
        if text == before {
            break;
        }
    }
    text
}

/// The text inside one pair of brackets that encloses all of `text`.
fn enclosed(text: &str) -> Option<&str> {
    let inner = text.strip_prefix('(')?.strip_suffix(')')?;
    let mut depth = 0i32;
    for c in inner.chars() {
        depth += match c {
            '(' => 1,
            ')' => -1,
            _ => 0,
        };
        if depth < 0 {
            return None;
        }
    }
    (depth == 0).then_some(inner)
}

/// A whole expression that is one string literal.
pub(super) fn literal(text: &str) -> Option<String> {
    let captures = LITERAL_ONLY.captures(text.trim())?;
    let word = (1..=3).find_map(|group| captures.get(group))?;
    Some(word.as_str().to_owned())
}

/// Every string literal in `text`, in order.
pub(super) fn literals(text: &str) -> Vec<String> {
    LITERAL
        .captures_iter(text)
        .filter_map(|captures| captures.get(1).or(captures.get(2)))
        .map(|m| m.as_str().to_owned())
        .take(MAX_WORDS)
        .collect()
}

/// The words of a list literal whose items are all strings.
pub(super) fn word_list(value: &str) -> Option<Vec<String>> {
    let list = WORD_LIST.captures(value.trim())?.get(1)?.as_str();
    let words: Vec<String> = if let Some(inner) = list.strip_prefix("%w") {
        inner[1..inner.len() - 1]
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    } else {
        let mut words = Vec::new();
        for item in list[1..list.len() - 1].split(',') {
            if item.trim().is_empty() {
                continue;
            }
            words.push(literal(item)?);
        }
        words
    };
    (!words.is_empty()).then(|| words.into_iter().take(MAX_WORDS).collect())
}

/// `target` and `value` of an assignment statement, at its first `=` outside
/// quotes and brackets that is not part of a comparison or arrow.
pub(super) fn split_assignment(statement: &str) -> Option<(&str, &str)> {
    let statement = match DECLARATION.find(statement) {
        Some(declaration) => &statement[declaration.end()..],
        None => statement,
    };
    let bytes = statement.as_bytes();
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    for (index, &byte) in bytes.iter().enumerate() {
        if let Some(open) = quote {
            if byte == open && bytes.get(index.wrapping_sub(1)) != Some(&b'\\') {
                quote = None;
            }
            continue;
        }
        match byte {
            b'"' | b'\'' | b'`' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 0 => {
                let previous = index.checked_sub(1).map(|at| bytes[at]);
                let next = bytes.get(index + 1).copied();
                let compound = previous.is_some_and(|p| b"=!<>+-*/%&|^:~?.".contains(&p));
                if compound || matches!(next, Some(b'=' | b'>' | b'~')) {
                    return None;
                }
                let target = statement[..index].trim();
                let value = statement[index + 1..].trim();
                return TARGET.is_match(target).then_some((target, value));
            }
            _ => {}
        }
    }
    None
}

/// The items of a destructuring or tuple target: `[, , command, ...rest]`,
/// `(a, b)` or `_, command, *rest`. Holes are empty items.
pub(super) fn sequence(target: &str) -> Option<Vec<&str>> {
    let inner = if let Some(inner) = target.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        inner
    } else if let Some(inner) = target.strip_prefix('(').and_then(|t| t.strip_suffix(')')) {
        inner
    } else if target.contains(',') && !target.starts_with('{') {
        target
    } else {
        return None;
    };
    Some(inner.split(',').map(str::trim).collect())
}

/// A call's first argument: the text up to its first comma or closing
/// bracket outside nested brackets and quotes.
pub(super) fn first_argument(arguments: &str) -> &str {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for (index, c) in arguments.char_indices() {
        if let Some(open) = quote {
            if c == open {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return arguments[..index].trim(),
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return arguments[..index].trim(),
            _ => {}
        }
    }
    arguments.trim()
}
