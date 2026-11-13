//! The jq filter grammar admitted by the bounded `jq` read proofs.
//!
//! A filter is a pipeline over the value jq already read. Each stage is a
//! field/index projection (`.scripts`, `.items[0].name`, `.[]`), a builtin
//! that only reshapes that value (argument-free ones such as `keys`, `length`
//! or `sort`, optionally iterated or indexed as in `keys[]`; and the ones
//! whose arguments are themselves admitted filters or plain literals, such as
//! `select(.draft)`, `test("^fix"; "i")` or `limit(3; .[])`), an object or
//! array built from admitted filters, a parenthesised group, a conditional,
//! a `reduce` or `foreach` fold, a `try`, an assignment to a path of the
//! value, or arithmetic over admitted operands. Stages may compare two
//! operands, combine comparisons with `and`/`or`, fall back to a second
//! filter with `//`, emit several results with the comma operator, and drop
//! an error with the optional `?`. A stage may also be a bare format such as
//! `@tsv` or `@base64`, which only renders the value as text, or bind a term
//! to a name (`(.state // "") as $state`) that later stages read back as
//! `$state`. Leading zero-arity `def`s are inlined before the parse.
//!
//! Every form here is a pure function of the value read: none of them reaches
//! the environment, further input, files or modules, and the characters that
//! would let one do so are refused outright. A `$` that names anything but a
//! variable the filter binds itself (so `$ENV`, `$__loc__` and a `--arg`
//! value stay out), `@` outside a bare rendering format (so `@sh` and a
//! `@fmt "string"` template stay out), a `;` outside the parentheses of a
//! call or fold (so `import`, `include` and a `def` that is not inlined stay
//! out), a `:` outside an object or a subscript, a `#` comment, and every
//! builtin outside the lists here and in [`terms`] are all rejected.
//! A string may render admitted filters into its text
//! (`"\(.name) \(.state)"`): each interpolation is read as a filter over the
//! same value, so the whole string stays a pure function of it.
//! A shorthand object entry (`{number, title}`) names a field of the value
//! read, so it is admitted under the same key rules as `{number: .number}`.

#[path = "jq_filter_budget.rs"]
mod budget;
#[path = "jq_filter_program.rs"]
mod program;
#[path = "jq_filter_terms.rs"]
mod terms;

use program::literal;

const MAX_STAGES: usize = 16;

/// How many `//` fallbacks one operand may chain.
const MAX_ALTERNATIVES: usize = 4;

const VALUE_BUILTINS: &[&str] = &[
    "add",
    "arrays",
    "ascii_downcase",
    "ascii_upcase",
    "booleans",
    "empty",
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

/// Format strings that only render the value read as text. `@sh` is left
/// out: its output is shell-quoted words meant to be run, which is not a read.
const FORMATS: &[&str] = &[
    "base32", "base32d", "base64", "base64d", "csv", "html", "json", "text", "tsv", "uri",
];

/// Comparisons, longest spelling first so `<=` is never read as `<`.
const COMPARISONS: &[&str] = &["==", "!=", "<=", ">=", "<", ">"];

pub(super) fn safe_filter(filter: &str) -> bool {
    budget::reset();
    program::prepared(filter).is_some_and(|program| {
        budget::range_budget(&program)
            && valid_characters(&program)
            && variables_bound(&program)
            && pipeline(&program)
    })
}

fn pipeline(filter: &str) -> bool {
    if !budget::spend() {
        return false;
    }
    let Some(stages) = split_marker(filter, b"|") else {
        return false;
    };
    stages.len() <= MAX_STAGES
        && stages
            .iter()
            .enumerate()
            .all(|(index, part)| match binding(part) {
                Some(term) => index + 1 < stages.len() && stage(term),
                None => sequence(part),
            })
}

/// The term of `(.a // .b) as $s`, which the stages after it read back as
/// `$s`. jq binds `as` tighter than every operator, so `.a // .b as $s`
/// binds `.b` alone; only a lone term is read here, and the operator form
/// fails as a stage.
fn binding(part: &str) -> Option<&str> {
    let (term, name) = part.rsplit_once(" as $")?;
    variable_name(name).then(|| term.trim_end())
}

fn variable_name(name: &str) -> bool {
    name.starts_with(|value: char| value.is_ascii_alphabetic() || value == '_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Whether every `$name` in `filter` is a variable the filter binds itself
/// with `... as $name`, read inside that binding's scope, so each one holds a
/// value the filter computed from its input. jq looks any other name up
/// outside the filter: `$ENV` is the process environment, `$__loc__` the
/// source position, and the rest come from `--arg` and friends. Those names
/// are refused even when bound, and so is a `$` that opens no name. A binding
/// jq reads differently, such as a destructuring `as [$a, $b]`, binds nothing
/// here, so its names stay out.
///
/// A binding reaches the end of the group it was made in, so a name read
/// before its `as`, or after the bracket around its binding closes, is not
/// bound. String text is skipped and the code of an interpolation is read,
/// so `as $x` written inside a string binds nothing.
pub(crate) fn variables_bound(filter: &str) -> bool {
    let bytes = filter.as_bytes();
    // Each open group with the number of bindings in scope when it opened. A
    // `\(` interpolation returns to string text when its `)` closes.
    let mut groups: Vec<(u8, usize)> = Vec::new();
    let mut bound: Vec<&str> = Vec::new();
    // Where the name of the latest binding ends.
    let mut binding_end: Option<usize> = None;
    let mut in_string = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            match byte {
                b'"' => in_string = false,
                b'\\' if bytes.get(index + 1) == Some(&b'(') => {
                    groups.push((b'\\', bound.len()));
                    in_string = false;
                    index += 1;
                }
                b'\\' => index += 1,
                _ => {}
            }
            index += 1;
            continue;
        }
        match byte {
            // A `#` opens a jq comment that ends at the newline, so a quote
            // after it starts no string and the rest of the scan is unsound.
            b'#' => return false,
            b'"' => in_string = true,
            // `reduce .[] as $x (0; . + $x)`: a fold's binding reaches into
            // the parentheses that follow it and no further.
            b'(' | b'[' | b'{' => {
                let folds = byte == b'('
                    && binding_end.is_some_and(|end| filter[end..index].trim().is_empty());
                groups.push((byte, bound.len() - usize::from(folds)));
            }
            b')' | b']' | b'}' => {
                let Some((open, in_scope)) = groups.pop() else {
                    return false;
                };
                let close = match open {
                    b'[' => b']',
                    b'{' => b'}',
                    _ => b')',
                };
                if byte != close {
                    return false;
                }
                bound.truncate(in_scope);
                in_string = open == b'\\';
            }
            b'$' => {
                let rest = &filter[index + 1..];
                let end = rest
                    .find(|value: char| !(value.is_ascii_alphanumeric() || value == '_'))
                    .unwrap_or(rest.len());
                let name = &rest[..end];
                if !variable_name(name) || name == "ENV" || name.starts_with("__") {
                    return false;
                }
                let before = filter[..index].trim_end();
                if before
                    .strip_suffix("as")
                    .is_some_and(|term| term.ends_with(' '))
                {
                    bound.push(name);
                    binding_end = Some(index + 1 + end);
                } else if !bound.contains(&name) {
                    return false;
                }
                index += end;
            }
            _ => {}
        }
        index += 1;
    }
    !in_string && groups.is_empty()
}

/// `.headBranch, .headSha`: the comma operator runs each side over the same
/// value and emits both results. Each side is an admitted filter in its own
/// right, so a sequence reaches no further than the widest of them.
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
    // A side is an assignment, a boolean, or a plain literal: a fallback
    // ends in a constant when the field is absent, as in `.body // ""`, and
    // `map(1)` or `if .a then "x" else "y" end` yield one too.
    sides
        .iter()
        .all(|side| terms::assignment(side).unwrap_or_else(|| disjunction(side) || literal(side)))
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
        Compare::Absent => terms::arithmetic(part).unwrap_or_else(|| stage(part)),
        Compare::Pair(left, right) => [left, right]
            .iter()
            .all(|side| terms::arithmetic(side).unwrap_or_else(|| operand(side))),
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
        if let Some(length) = program::opens_block(bytes, index) {
            depth += 1;
            index += length;
            continue;
        }
        if let Some(length) = program::closes_block(bytes, index) {
            let Some(up) = depth.checked_sub(1) else {
                return Compare::Refused;
            };
            depth = up;
            index += length;
            continue;
        }
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

/// One side of a comparison.
fn operand(part: &str) -> bool {
    literal(part) || stage(part)
}

fn stage(part: &str) -> bool {
    if !budget::spend() {
        return false;
    }
    // `map(.a)?`, `(.a)?`: the optional operator drops the error a stage
    // raises on a value of the wrong type, and reads nothing the stage did not.
    let part = part.strip_suffix('?').map_or(part, str::trim_end);
    projection(part)
        || iterated_builtin(part)
        || literal_builtin(part)
        || filter_builtin(part)
        || object(part)
        || array(part)
        || group(part)
        || format(part)
        || interpolated_string(part)
        || variable(part)
        || terms::term(part)
}

/// `$state`, `$check.name` or `$items[0]`: a variable read back, optionally
/// projected. [`variables_bound`] has already checked that the filter binds
/// the name itself.
fn variable(part: &str) -> bool {
    let Some(rest) = part.strip_prefix('$') else {
        return false;
    };
    let end = rest
        .find(|value: char| !(value.is_ascii_alphanumeric() || value == '_'))
        .unwrap_or(rest.len());
    let (name, suffix) = rest.split_at(end);
    variable_name(name)
        && (suffix.is_empty()
            || (suffix.starts_with('.') && projection(suffix))
            || (suffix.starts_with('[') && projection(&format!(".{suffix}"))))
}

/// `"\(.type)\t\(.name)"`: text with admitted filters rendered into it.
/// Each interpolation is read as a filter over the value jq already read, so
/// the string is a pure function of that value exactly as `join` and `@tsv`
/// are. A template a format is applied to — `@sh "\(.x)"`, whose output is
/// shell-quoted words meant to be run — never reaches here: `@sh` fails
/// [`valid_characters`], and a format followed by a string is neither a bare
/// format nor a string, so [`stage`] refuses it.
///
/// A string with no interpolation is a plain literal, read by [`literal`].
fn interpolated_string(stage: &str) -> bool {
    let bytes = stage.as_bytes();
    if bytes.first() != Some(&b'"') || string_end(bytes, 0) != Some(bytes.len() - 1) {
        return false;
    }
    let mut interpolations = 0usize;
    let mut index = 1;
    while index + 1 < bytes.len() {
        if bytes[index] != b'\\' {
            index += 1;
            continue;
        }
        if bytes[index + 1] != b'(' {
            // `\n`, `\t` or `\\`, already checked by `string_end`.
            index += 2;
            continue;
        }
        let Some(close) = interpolation_end(bytes, index + 1) else {
            return false;
        };
        let code = &stage[index + 2..close];
        if code.trim().is_empty() || !valid_characters(code) || !pipeline(code) {
            return false;
        }
        interpolations += 1;
        index = close + 1;
    }
    interpolations > 0 && interpolations <= MAX_STAGES
}

/// `@tsv`, `@base64`: a bare rendering format, applied to the value read.
fn format(stage: &str) -> bool {
    stage.strip_prefix('@').is_some_and(rendering_format)
}

/// Whether `name` is a format that only renders the value read as text.
pub(crate) fn rendering_format(name: &str) -> bool {
    FORMATS.contains(&name)
}

/// Outside string literals only names, projections, spaces, brackets,
/// comparison, arithmetic and assignment operators, `//`, the comma
/// operator, the `?` of an optional projection, a `@` that opens a known
/// rendering format and a `$` that opens a variable name may appear; inside
/// one only printable ASCII and jq's escapes, with each interpolation read
/// by [`interpolated_string`]. A `:` is admitted inside an object, where it
/// parts key from value, and inside a subscript, where it parts the two ends
/// of a slice. A `;` is admitted inside parentheses, where it parts the
/// arguments of a call or a fold. Brackets must balance and close in the
/// kind they opened.
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
            b':' if matches!(open.last(), Some(&b'{' | &b'[')) => {}
            b';' if open.last() == Some(&b'(') => {}
            b'@' => {
                let name = filter[index + 1..]
                    .split(|value: char| !value.is_ascii_alphanumeric())
                    .next()
                    .unwrap_or_default();
                if !FORMATS.contains(&name) {
                    return false;
                }
                index += name.len();
            }
            b'$' => {
                let name = filter[index + 1..]
                    .split(|value: char| !(value.is_ascii_alphanumeric() || value == '_'))
                    .next()
                    .unwrap_or_default();
                if name.is_empty() {
                    return false;
                }
                index += name.len();
            }
            byte if byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'_'
                        | b' '
                        | b'|'
                        | b'/'
                        | b'='
                        | b'!'
                        | b'<'
                        | b'>'
                        | b'+'
                        | b'-'
                        | b'*'
                        | b'%'
                        | b','
                        | b'?'
                ) => {}
            _ => return false,
        }
        index += 1;
    }
    open.is_empty()
}

/// The index of the closing quote of the string literal opening at `start`.
///
/// An interpolation is skipped whole, so a quote, bracket or marker in the
/// filter it carries is never read as part of the text around the string.
/// Its code is checked by [`interpolated_string`], which reads it as a
/// filter rather than as text.
fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    while bytes.get(index) != Some(&b'"') {
        match bytes.get(index)? {
            b'\\' if bytes.get(index + 1) == Some(&b'(') => {
                index = interpolation_end(bytes, index + 1)? + 1;
            }
            b'\\'
                if matches!(
                    bytes.get(index + 1)?,
                    b'n' | b't' | b'r' | b'b' | b'f' | b'\\' | b'/' | b'"'
                ) =>
            {
                index += 2;
            }
            b'\\' if bytes.get(index + 1) == Some(&b'u') => {
                let digits = bytes.get(index + 2..index + 6)?;
                if !digits.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                index += 6;
            }
            b'\\' => return None,
            byte if (b' '..=b'~').contains(byte) => index += 1,
            _ => return None,
        }
    }
    Some(index)
}

/// The index of the `)` closing the interpolation whose `(` stands at
/// `start`. A string inside it is skipped whole, so a parenthesis written in
/// one does not close the interpolation early.
fn interpolation_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = string_end(bytes, index)?,
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Splits on `marker` outside string literals, brackets and `if ... end`
/// blocks, trimming each part. An unbalanced bracket, block or string
/// refuses the split rather than splitting at a position the real parse
/// would read differently. The `|` of `|=` and the `//` of `//=` are
/// assignments, not markers.
fn split_marker<'a>(text: &'a str, marker: &[u8]) -> Option<Vec<&'a str>> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut index = 0;
    let assigns =
        |at: usize| matches!(marker, b"|" | b"//") && bytes.get(at + marker.len()) == Some(&b'=');
    while index < bytes.len() {
        if let Some(length) = program::opens_block(bytes, index) {
            depth += 1;
            index += length;
            continue;
        }
        if let Some(length) = program::closes_block(bytes, index) {
            depth = depth.checked_sub(1)?;
            index += length;
            continue;
        }
        match bytes[index] {
            b'"' => index = string_end(bytes, index)?,
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => depth = depth.checked_sub(1)?,
            _ if depth == 0 && bytes[index..].starts_with(marker) && !assigns(index) => {
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
/// and an admitted filter, or a shorthand entry (`{a}`, `{"a b"}`) that reads
/// the field of that name. A key may also be computed by an admitted filter
/// in parentheses (`{(.name): .value}`), and `{$name}` reads back a variable
/// the filter bound itself, which [`variables_bound`] has checked.
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
        match colon.as_slice() {
            [key] => object_key(key) || key.strip_prefix('$').is_some_and(variable_name),
            [key, value] => (object_key(key) || group(key)) && pipeline(value),
            _ => false,
        }
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

/// A name (`a`, `_id`) or a plain string literal.
fn object_key(key: &str) -> bool {
    match key.strip_prefix('"') {
        Some(_) => key.len() > 2 && literal(key),
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
    (VALUE_BUILTINS.contains(&name) || terms::value_builtin(name))
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
            if !subscript(bytes, &mut index) || bytes.get(index) != Some(&b']') {
                return false;
            }
            index += 1;
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
        }
        // `.a?`, `.[]?`: the optional operator drops the error an absent field
        // or a value of the wrong type raises, and selects nothing further.
        if bytes.get(index) == Some(&b'?') {
            index += 1;
        }
        if index < bytes.len() && !matches!(bytes[index], b'.' | b'[') {
            return false;
        }
    }
    true
}

/// The body of a `[...]` subscript: empty for the iterate `.[]`, one signed
/// index, or a slice whose two ends are each optional, as in `.[1:]`,
/// `.[:12]` and `.[-2:-1]`. Every spelling selects from the value already
/// read, so none of them reaches past it.
fn subscript(bytes: &[u8], index: &mut usize) -> bool {
    if !signed_index(bytes, index) {
        return false;
    }
    if bytes.get(*index) == Some(&b':') {
        *index += 1;
        return signed_index(bytes, index);
    }
    true
}

/// One end of a subscript: nothing, digits, or a minus and digits. A lone
/// minus is refused rather than read as an end left out.
fn signed_index(bytes: &[u8], index: &mut usize) -> bool {
    if bytes.get(*index) == Some(&b'-') {
        *index += 1;
        if !bytes.get(*index).is_some_and(u8::is_ascii_digit) {
            return false;
        }
    }
    while bytes.get(*index).is_some_and(u8::is_ascii_digit) {
        *index += 1;
    }
    true
}

#[cfg(test)]
#[path = "jq_filter_tests.rs"]
mod tests;
