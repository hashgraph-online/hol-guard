//! The `jsonpath` template screen for Kubernetes read commands.
//!
//! A `kubectl -o jsonpath=…` argument carries a selector that a credential
//! screen reading raw command text mistakes for a dotenv path. These helpers
//! decide what a template actually renders, so a template that prints names
//! alone can lose its payload before that screen runs.

#![allow(dead_code)]

use std::sync::LazyLock;

use regex::Regex;

static SAFE_JSONPATH_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\A\{?\.?(?:items(?:\[-?\d+\]|\[\*\])?\.)?(?:metadata\.(?:name|namespace|uid)|status\.phase)\}?\z",
    )
    .expect("safe jsonpath field pattern")
});

/// A `{range …}` selector: a dotted path with optional list indices.
///
/// The selector chooses which objects the loop walks. It renders nothing
/// itself, so it is screened only for shape -- a name that could carry shell
/// metacharacters or another brace group is refused.
static JSONPATH_RANGE_SELECTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\A\.?[A-Za-z0-9_\-]+(?:\[(?:\*|-?\d+)\])?(?:\.[A-Za-z0-9_\-]+(?:\[(?:\*|-?\d+)\])?)*\z",
    )
    .expect("jsonpath range selector pattern")
});

/// The brace groups of a `jsonpath` template, or `None` when anything renders
/// outside them.
///
/// Text between groups is emitted verbatim, so a template that carries any is
/// refused rather than screened character by character.
fn jsonpath_brace_groups(template: &str) -> Option<Vec<String>> {
    let mut groups = Vec::new();
    let mut rest = template;
    loop {
        let Some(open) = rest.find('{') else {
            return rest.trim().is_empty().then_some(groups);
        };
        if !rest[..open].trim().is_empty() {
            return None;
        }
        let body = &rest[open + 1..];
        let close = body.find('}')?;
        groups.push(body[..close].trim().to_owned());
        rest = &body[close + 1..];
    }
}

/// Whether a brace group is a quoted separator such as `{"\n"}`.
fn jsonpath_string_literal(group: &str) -> bool {
    let mut characters = group.chars();
    let Some(quote) = characters
        .next()
        .filter(|first| *first == '"' || *first == '\'')
    else {
        return false;
    };
    group.len() >= 2
        && group.ends_with(quote)
        && !group[1..group.len() - 1].contains(['{', '}', '$', '`', quote])
}

/// Whether a `jsonpath` template renders names and separators alone.
///
/// A `kubectl` template may loop: `{range …}{.name}{"\n"}{end}` walks a list
/// and prints one field for each entry it reaches. The `range` selector picks
/// the objects the loop visits and prints nothing itself, so what the template
/// renders is decided entirely by the groups inside the loop. A body that emits
/// a name field and quoted separators cannot print a value, whatever the
/// selector reached -- `{.value}` beside it would, and is refused.
pub(crate) fn jsonpath_renders_only_names(template: &str) -> bool {
    let groups = jsonpath_brace_groups(template).unwrap_or_default();
    let Some(first) = groups.first() else {
        return false;
    };
    let Some(selector) = first.strip_prefix("range ") else {
        return false;
    };
    if groups.last().map(String::as_str) != Some("end")
        || !JSONPATH_RANGE_SELECTOR.is_match(selector.trim())
    {
        return false;
    }
    let body = &groups[1..groups.len() - 1];
    let renders_a_name =
        |group: &String| group == ".name" || SAFE_JSONPATH_FIELD.is_match(group.as_str());
    body.iter().any(renders_a_name)
        && body
            .iter()
            .all(|group| renders_a_name(group) || jsonpath_string_literal(group))
}

/// Whether a `jsonpath` template is one bare safe field such as
/// `{.metadata.name}`.
pub(crate) fn safe_jsonpath_field(template: &str) -> bool {
    SAFE_JSONPATH_FIELD.is_match(template)
}

/// `value` with every names-only `jsonpath` template payload removed.
///
/// A credential-location screen reads raw command text, where a selector such
/// as `…containers[*].env[*]` looks like a dotenv path. The selector names a
/// container's environment list, and a template that renders names alone
/// cannot print what that list holds, so only those payloads are dropped --
/// a template carrying `{.value}` keeps its text and its screen.
pub(crate) fn without_names_only_jsonpath_templates(value: &str) -> String {
    const KINDS: [&str; 2] = ["jsonpath-as-json=", "jsonpath="];
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    let mut offset = 0usize;
    while let Some(at) = rest.find("jsonpath") {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let absolute = offset + at;
        let Some(kind) = KINDS.iter().find(|kind| tail.starts_with(**kind)) else {
            out.push_str("jsonpath");
            rest = &tail["jsonpath".len()..];
            offset = absolute + "jsonpath".len();
            continue;
        };
        out.push_str(kind);
        let after = &tail[kind.len()..];
        let (payload, consumed) = jsonpath_payload(value, absolute, after);
        if !jsonpath_renders_only_names(&payload) {
            out.push_str(&after[..consumed]);
        }
        rest = &after[consumed..];
        offset = absolute + kind.len() + consumed;
    }
    out.push_str(rest);
    out
}

/// The template an argument carries, and how much of `after` it occupies.
///
/// `at` is the offset of `jsonpath` within `value`, not within the remainder
/// being walked: the character before it decides whether the whole argument
/// was quoted, and reading it at the wrong offset both splits a later
/// template at the wrong place and can index inside a multibyte character.
///
/// A template holds blanks, so the payload runs to the end of the argument
/// rather than to the end of a quoted run. The shell joins adjacent quoted
/// strings into one word, so `jsonpath=\'{range …}{.name}{end}\'\'{..value}\'`
/// is one template that prints values; stopping at the first closing quote
/// would read only its names-only half and drop that half from the screen.
/// Quotes are consumed the way the shell consumes them, so the payload is what
/// the command actually receives. A quote that opened before `jsonpath`
/// (`\'jsonpath={…}\'`) is already open when the walk starts, and closing it
/// ends the argument only if a blank follows; `\'jsonpath={…}\'\'{..value}\'`
/// is one word too.
fn jsonpath_payload(value: &str, at: usize, after: &str) -> (String, usize) {
    let mut payload = String::new();
    let mut open = value[..at]
        .chars()
        .next_back()
        .filter(|character| *character == '\'' || *character == '"');
    let mut consumed = 0usize;
    for character in after.chars() {
        let width = character.len_utf8();
        match open {
            Some(quote) if character == quote => {
                consumed += width;
                open = None;
            }
            Some(_) => {
                consumed += width;
                payload.push(character);
            }
            None if character == '\'' || character == '"' => {
                consumed += width;
                open = Some(character);
            }
            None if character.is_whitespace() => return (payload, consumed),
            None => {
                consumed += width;
                payload.push(character);
            }
        }
    }
    (payload, consumed)
}
