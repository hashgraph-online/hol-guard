//! The jq filter grammar admitted by the bounded `jq` read proofs.
//!
//! A filter is a short pipeline over the value jq already read. Each stage is
//! a field/index projection (`.scripts`, `.items[0].name`, `.[]`), a builtin
//! that only reshapes that value (argument-free ones such as `keys`, `length`
//! or `sort`, optionally iterated or indexed as in `keys[]`; a few that take
//! one plain literal such as `has("name")` or `join("\n")`; and a few whose
//! one argument is itself an admitted filter, such as `select(.draft)` or
//! `map(.number)`), an object or array built from admitted filters, or a
//! parenthesised group. Stages may compare two such operands against each
//! other or against a plain literal, combine comparisons with `and`/`or`, and
//! fall back to a second filter with `//`.
//!
//! Every form here is a pure function of the value read: none of them reaches
//! the environment, further input, files or modules, and the characters that
//! would let one do so are refused outright. `$` (variable bindings, `$ENV`,
//! `$__loc__`), `@` (format strings), `;` (which every multi-argument and
//! binding builtin needs: `def`, `reduce`, `foreach`, `limit`, `range`,
//! `getpath`), string interpolation, a `,` or `:` outside a bracket, computed
//! object keys, and every builtin outside the lists below are all rejected.

const MAX_STAGES: usize = 8;

/// How many `//` fallbacks one operand may chain.
const MAX_ALTERNATIVES: usize = 4;

const MAX_LITERAL: usize = 128;

const VALUE_BUILTINS: &[&str] = &[
    "add",
    "arrays",
    "ascii_downcase",
    "ascii_upcase",
    "booleans",
    "first",
    "flatten",
    "floor",
    "from_entries",
    "iterables",
    "keys",
    "keys_unsorted",
    "last",
    "length",
    "max",
    "min",
    "not",
    "nulls",
    "numbers",
    "objects",
    "reverse",
    "scalars",
    "sort",
    "strings",
    "to_entries",
    "tonumber",
    "tostring",
    "type",
    "unique",
    "utf8bytelength",
    "values",
];

/// Builtins whose one argument is a plain literal. None of them evaluates
/// the argument as a program, a regex or a path outside the value.
const LITERAL_BUILTINS: &[&str] = &[
    "contains",
    "endswith",
    "has",
    "index",
    "indices",
    "join",
    "ltrimstr",
    "rindex",
    "rtrimstr",
    "split",
    "startswith",
];

/// Builtins whose one argument is itself a filter over the value already
/// read. Each applies that filter to the value or its elements and keeps,
/// drops or reshapes them by the result, so the argument is parsed as a
/// program by the same grammar rather than screened as text.
const FILTER_BUILTINS: &[&str] = &[
    "all",
    "any",
    "del",
    "first",
    "group_by",
    "last",
    "map",
    "map_values",
    "max_by",
    "min_by",
    "select",
    "sort_by",
    "unique_by",
    "with_entries",
];

/// Comparisons, longest spelling first so `<=` is never read as `<`.
const COMPARISONS: &[&str] = &["==", "!=", "<=", ">=", "<", ">"];

pub(super) fn safe_filter(filter: &str) -> bool {
    filter.len() <= 256 && valid_characters(filter) && pipeline(filter)
}

fn pipeline(filter: &str) -> bool {
    let Some(stages) = split_marker(filter, b"|") else {
        return false;
    };
    stages.len() <= MAX_STAGES && stages.iter().all(|stage| sequence(stage))
}

/// `,` is admitted only inside a bracket, so a sequence of outputs is reached
/// only from an object entry, an array or a call body — never as the whole
/// filter, where a stray comma stays a parse the proof refuses to read.
fn sequence(stage: &str) -> bool {
    let Some(parts) = split_marker(stage, b",") else {
        return false;
    };
    parts.len() <= MAX_STAGES && parts.iter().all(|part| alternative(part))
}

/// `.body // ""`: the left side when it yields neither null nor false, else
/// the right. Both sides only reshape the value already read.
fn alternative(part: &str) -> bool {
    let Some(sides) = split_marker(part, b"//") else {
        return false;
    };
    if sides.len() > MAX_ALTERNATIVES {
        return false;
    }
    match sides.as_slice() {
        [only] => disjunction(only),
        // A fallback ends in a constant when the field is absent, as in
        // `.body // ""`. A plain literal is admitted here and as a comparison
        // operand, never as a stage of its own.
        sides => sides.iter().all(|side| disjunction(side) || literal(side)),
    }
}

fn disjunction(part: &str) -> bool {
    boolean_parts(part, b" or ", conjunction)
}

fn conjunction(part: &str) -> bool {
    boolean_parts(part, b" and ", comparison)
}

/// Splits on a spaced `and`/`or` keyword and checks each side. The spaces are
/// part of the marker, so a name that merely contains the word — `.order`,
/// `keys_unsorted`, `.candidate` — is never cut in two.
fn boolean_parts(part: &str, marker: &[u8], side: impl Fn(&str) -> bool) -> bool {
    let Some(parts) = split_marker(part, marker) else {
        return false;
    };
    parts.len() <= MAX_STAGES && parts.iter().all(|part| side(part))
}

/// `.conclusion != "SUCCESS"`: one comparison of two operands, each a filter
/// over the value read or a plain literal. A chain of them is refused rather
/// than read with a precedence this grammar does not model.
fn comparison(part: &str) -> bool {
    match compare(part) {
        Compare::Absent => stage(part),
        Compare::Pair(left, right) => operand(left) && operand(right),
        Compare::Refused => false,
    }
}

enum Compare<'a> {
    Absent,
    Pair(&'a str, &'a str),
    Refused,
}

fn compare(part: &str) -> Compare<'_> {
    let bytes = part.as_bytes();
    let mut found: Option<(usize, usize)> = None;
    let mut depth = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => match string_end(bytes, index) {
                Some(end) => index = end,
                None => return Compare::Refused,
            },
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return Compare::Refused,
            },
            _ if depth == 0 => {
                if let Some(operator) = COMPARISONS
                    .iter()
                    .find(|operator| part[index..].starts_with(**operator))
                {
                    if found.is_some() {
                        return Compare::Refused;
                    }
                    found = Some((index, index + operator.len()));
                    index += operator.len();
                    continue;
                }
            }
            _ => {}
        }
        index += 1;
    }
    match found {
        Some((start, end)) => Compare::Pair(part[..start].trim(), part[end..].trim()),
        None => Compare::Absent,
    }
}

/// One side of a comparison or a `//` fallback. A plain literal is admitted
/// here and nowhere else, so a bare `"x"` is still not a stage of its own.
fn operand(part: &str) -> bool {
    literal(part) || stage(part)
}

fn stage(part: &str) -> bool {
    projection(part)
        || iterated_builtin(part)
        || literal_builtin(part)
        || filter_builtin(part)
        || object(part)
        || array(part)
        || group(part)
}

/// Outside string literals only names, projections, spaces, call and group
/// parentheses, comparison operators, the `+` and `-` a number literal
/// uses, `//` and bracket punctuation may appear; inside one only printable
/// ASCII and the `\n`, `\t` and `\\`
/// escapes, so neither `\(` interpolation nor an escaped quote can appear.
/// Brackets must balance and close in the kind they opened.
fn valid_characters(filter: &str) -> bool {
    let bytes = filter.as_bytes();
    let mut open: Vec<u8> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => match string_end(bytes, index) {
                Some(end) => index = end,
                None => return false,
            },
            byte @ (b'{' | b'[' | b'(') => open.push(byte),
            byte @ (b'}' | b']' | b')') => {
                let opener = match byte {
                    b'}' => b'{',
                    b']' => b'[',
                    _ => b'(',
                };
                if open.pop() != Some(opener) {
                    return false;
                }
            }
            b':' if open.last() == Some(&b'{') => {}
            b',' if !open.is_empty() => {}
            byte if byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'_' | b' ' | b'|' | b'/' | b'=' | b'!' | b'<' | b'>' | b'+' | b'-'
                ) => {}
            _ => return false,
        }
        index += 1;
    }
    open.is_empty()
}

/// The index of the closing quote of the string literal opening at `start`.
fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    while bytes.get(index) != Some(&b'"') {
        match bytes.get(index)? {
            b'\\' if matches!(bytes.get(index + 1)?, b'n' | b't' | b'\\') => index += 2,
            b'\\' => return None,
            byte if (b' '..=b'~').contains(byte) => index += 1,
            _ => return None,
        }
    }
    Some(index)
}

/// Splits on `marker` outside string literals and brackets, trimming each
/// part. An unbalanced bracket or string refuses the split rather than
/// splitting at a position the real parse would read differently.
fn split_marker<'a>(text: &'a str, marker: &[u8]) -> Option<Vec<&'a str>> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = string_end(bytes, index)?,
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => depth = depth.checked_sub(1)?,
            _ if depth == 0 && bytes[index..].starts_with(marker) => {
                parts.push(text[start..index].trim());
                index += marker.len();
                start = index;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    parts.push(text[start..].trim());
    Some(parts)
}

/// `{"a": .x | has("y"), b: .z}`: every entry is a name or plain string key
/// and an admitted filter. Shorthand (`{a}`) and computed keys are rejected.
fn object(stage: &str) -> bool {
    let Some(inner) = stage
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return false;
    };
    let Some(entries) = split_marker(inner, b",") else {
        return false;
    };
    entries.iter().all(|entry| {
        let Some(colon) = split_marker(entry, b":") else {
            return false;
        };
        let [key, value] = colon.as_slice() else {
            return false;
        };
        object_key(key) && pipeline(value)
    })
}

/// `[.[] | .name]`: the outputs of an admitted filter collected into an
/// array. An empty one carries no filter to admit, as `{}` does not.
fn array(stage: &str) -> bool {
    bounded_by(stage, '[', ']').is_some_and(pipeline)
}

/// `(.a // .b) | length`: a group, so a fallback or comparison can precede a
/// stage that would otherwise bind tighter.
fn group(stage: &str) -> bool {
    bounded_by(stage, '(', ')').is_some_and(pipeline)
}

/// The non-empty body of `stage` when it opens with `open` and closes with
/// `close`. The body is parsed in turn, so a stage that merely starts and
/// ends with the pair — `[.a][0]`, `(.a)(.b)` — fails on the body it leaves.
fn bounded_by(stage: &str, open: char, close: char) -> Option<&str> {
    stage
        .strip_prefix(open)
        .and_then(|rest| rest.strip_suffix(close))
        .filter(|body| !body.is_empty())
}

/// A name (`a`, `_id`) or a plain string literal of names, spaces and dashes.
fn object_key(key: &str) -> bool {
    match key
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        Some(name) => {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b' '))
        }
        None => {
            key.starts_with(|value: char| value.is_ascii_alphabetic() || value == '_')
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }
    }
}

/// `keys`, `keys[]` or `to_entries[0]`: an argument-free builtin, optionally
/// followed by an iterate or index suffix.
fn iterated_builtin(stage: &str) -> bool {
    let end = stage
        .find(|value: char| !(value.is_ascii_alphanumeric() || value == '_'))
        .unwrap_or(stage.len());
    let (name, suffix) = stage.split_at(end);
    VALUE_BUILTINS.contains(&name)
        && (suffix.is_empty() || (suffix.starts_with('[') && projection(&format!(".{suffix}"))))
}

/// `has("name")`, `join("\n")` or `has(0)`: one plain literal argument.
fn literal_builtin(stage: &str) -> bool {
    let Some((name, argument)) = call(stage) else {
        return false;
    };
    LITERAL_BUILTINS.contains(&name) && literal(argument)
}

/// `select(.draft == false)`, `map(.number)`: one argument that is itself an
/// admitted filter, parsed by this same grammar.
fn filter_builtin(stage: &str) -> bool {
    let Some((name, argument)) = call(stage) else {
        return false;
    };
    FILTER_BUILTINS.contains(&name) && pipeline(argument)
}

/// The name and single argument of `name(argument)`. The argument keeps its
/// own brackets, so a trailing call or index — `has("x")("y")` — leaves a
/// body neither reading of the argument admits.
fn call(stage: &str) -> Option<(&str, &str)> {
    let (name, rest) = stage.split_once('(')?;
    Some((name.trim_end(), rest.strip_suffix(')')?))
}

/// A plain value: a bounded string with no inner quote, a jq number, or a
/// JSON keyword. The number is jq's own literal — an optional minus, digits
/// or a leading fraction, and an optional exponent — and nothing else. A
/// `+` or `-` standing between two operands is arithmetic, which [`stage`]
/// never reads, so allowing the signs through [`valid_characters`] does not
/// admit `.a + 1` or `.a - 1`.
fn literal(part: &str) -> bool {
    matches!(part, "true" | "false" | "null")
        || (part.len() <= MAX_LITERAL
            && part
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .is_some_and(|value| !value.contains('"')))
        || numeric_literal(part)
}

/// `1`, `-1`, `1.5`, `.5`, `1e-2`: a bounded jq number. A leading `+` is the
/// addition operator, not a sign, and a trailing dot or a bare exponent is
/// not a number this grammar will guess at.
fn numeric_literal(part: &str) -> bool {
    let bytes = part.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let mut index = 0;
    if bytes[0] == b'-' {
        index = 1;
    }
    if index >= bytes.len() {
        return false;
    }
    let mut saw_digit = false;
    if bytes[index] == b'.' {
        index += 1;
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        saw_digit = index > start;
    } else if bytes[index].is_ascii_digit() {
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        saw_digit = true;
        if index < bytes.len() && bytes[index] == b'.' {
            index += 1;
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if index == start {
                return false;
            }
        }
    }
    if !saw_digit {
        return false;
    }
    if index < bytes.len() && matches!(bytes[index], b'e' | b'E') {
        index += 1;
        if index < bytes.len() && matches!(bytes[index], b'+' | b'-') {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    index == bytes.len()
}

/// Field/index projections only: no functions, file operands, modules or
/// env access.
fn projection(filter: &str) -> bool {
    if !filter.starts_with('.') {
        return false;
    }
    let bytes = filter.as_bytes();
    let mut index = 1;
    while index < bytes.len() {
        if bytes[index] == b'[' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if bytes.get(index) != Some(&b']') {
                return false;
            }
            index += 1;
            if index < bytes.len() && !matches!(bytes[index], b'.' | b'[') {
                return false;
            }
        } else {
            if bytes[index] == b'.' {
                if index == 1 {
                    return false;
                }
                index += 1;
            }
            if index >= bytes.len() || !(bytes[index].is_ascii_alphabetic() || bytes[index] == b'_')
            {
                return false;
            }
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if index < bytes.len() && !matches!(bytes[index], b'.' | b'[') {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
#[path = "jq_filter_tests.rs"]
mod tests;
