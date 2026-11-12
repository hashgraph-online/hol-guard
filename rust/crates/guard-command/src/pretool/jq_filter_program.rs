//! How the jq read grammar takes in a whole filter before it parses one:
//! line breaks read as spaces, each leading zero-arity `def` inlined where it
//! is used, and the length and nesting bounded so the recursive parse stays
//! shallow. Also the keyword scanner the splitters use to step over
//! `if ... end` blocks, and the plain values — strings, numbers, JSON
//! keywords, empty arrays and objects — every part of the grammar reads.

use super::{
    interpolation_end, pipeline, split_marker, string_end, valid_characters, variable_name,
    variables_bound,
};

/// The longest filter read, before and after its `def`s are inlined.
const MAX_FILTER: usize = 2048;
const MAX_PROGRAM: usize = 4096;

/// How deep brackets, string interpolations and `if` blocks may nest. Each
/// level is parsed by recursion, so the bound keeps a filter from
/// exhausting the stack.
const MAX_DEPTH: usize = 32;

const MAX_LITERAL: usize = 512;

/// Names jq reserves, which no `def` may take.
const KEYWORDS: &[&str] = &[
    "__loc__", "and", "as", "break", "catch", "def", "elif", "else", "end", "foreach", "if",
    "import", "include", "label", "or", "reduce", "then", "try",
];

/// The filter as the grammar reads it: line breaks and tabs outside strings
/// read as spaces, and each leading zero-arity `def` inlined where it is
/// used. `None` when the filter is too long or nests too deep, or when a
/// definition is one this grammar does not read.
pub(super) fn prepared(filter: &str) -> Option<String> {
    if filter.len() > MAX_FILTER {
        return None;
    }
    let spaced = plain_whitespace(filter)?;
    let program = inline_definitions(spaced.trim())?;
    (program.len() <= MAX_PROGRAM && nesting_bounded(&program)).then_some(program)
}

fn plain_whitespace(filter: &str) -> Option<String> {
    let bytes = filter.as_bytes();
    let mut spaced = String::with_capacity(filter.len());
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = string_end(bytes, index)?,
            b'\n' | b'\r' | b'\t' => {
                spaced.push_str(&filter[start..index]);
                spaced.push(' ');
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    spaced.push_str(&filter[start..]);
    Some(spaced)
}

/// `def internal: .login == "bot"; map(select(internal | not))`: each
/// leading definition takes no parameters, never names itself, and is an
/// admitted filter on its own, with every variable it reads bound inside it.
/// Its uses are replaced by its body in parentheses, which is what jq runs
/// for a zero-arity definition. Because each body is admitted on its own, a
/// use the replacement misses still names an admitted filter.
fn inline_definitions(text: &str) -> Option<String> {
    if !starts_word(text, "def") {
        return Some(text.to_owned());
    }
    let parts = split_marker(text, b";")?;
    let (program, definitions) = parts.split_last()?;
    let mut bodies: Vec<(&str, String)> = Vec::new();
    for definition in definitions {
        let (name, body) = definition.strip_prefix("def ")?.split_once(':')?;
        let (name, body) = (name.trim(), body.trim());
        if !variable_name(name) || KEYWORDS.contains(&name) || names_word(body, name) {
            return None;
        }
        let body = substitute(body, &bodies)?;
        if body.is_empty()
            || body.len() > MAX_PROGRAM
            || !nesting_bounded(&body)
            || !valid_characters(&body)
            || !variables_bound(&body)
            || !pipeline(&body)
        {
            return None;
        }
        bodies.push((name, format!("({body})")));
    }
    if starts_word(program, "def") {
        return None;
    }
    substitute(program, &bodies)
}

fn starts_word(text: &str, word: &str) -> bool {
    keyword(text.as_bytes(), 0, word)
}

/// Whether `text` uses `word` as a filter: as a call anywhere in its code,
/// string interpolations included. Field names, variables, object keys and
/// plain string text are not uses. A definition that uses itself recurses,
/// so any such use refuses it.
fn names_word(text: &str, word: &str) -> bool {
    substitute(text, &[(word, String::new())]).is_none_or(|replaced| replaced != text)
}

pub(super) fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// `text` with every use of a defined name replaced by its body. A name
/// read as a field (`.name`), a variable, a format or an object key is not
/// a use. A call with arguments refuses the filter, since only zero-arity
/// definitions are inlined. Output past [`MAX_PROGRAM`] refuses it too, so
/// definitions that each use the one before twice cannot double their way
/// to an unbounded program.
fn substitute(text: &str, bodies: &[(&str, String)]) -> Option<String> {
    if bodies.is_empty() {
        return Some(text.to_owned());
    }
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            index = substitute_string(text, index, bodies, &mut output)?;
            continue;
        }
        let word_start = (byte.is_ascii_alphabetic() || byte == b'_')
            && !index.checked_sub(1).is_some_and(|at| {
                identifier_byte(bytes[at]) || matches!(bytes[at], b'.' | b'$' | b'@')
            });
        if !word_start {
            output.push(char::from(byte));
            index += 1;
            continue;
        }
        let end = text[index..]
            .find(|value: char| !(value.is_ascii_alphanumeric() || value == '_'))
            .map_or(text.len(), |offset| index + offset);
        let word = &text[index..end];
        let next = text[end..].trim_start().as_bytes().first().copied();
        match bodies.iter().rev().find(|(name, _)| *name == word) {
            Some(_) if next == Some(b'(') => return None,
            Some((_, body)) if next != Some(b':') => output.push_str(body),
            _ => output.push_str(word),
        }
        if output.len() > MAX_PROGRAM {
            return None;
        }
        index = end;
    }
    Some(output)
}

/// Copies the string starting at `start` into `output`, substituting inside
/// each interpolation, and returns the index just past its closing quote.
fn substitute_string(
    text: &str,
    start: usize,
    bodies: &[(&str, String)],
    output: &mut String,
) -> Option<usize> {
    let bytes = text.as_bytes();
    let end = string_end(bytes, start)?;
    let mut copied = start;
    let mut index = start + 1;
    while index < end {
        if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'(') {
            let close = interpolation_end(bytes, index + 1)?;
            output.push_str(&text[copied..index + 2]);
            output.push_str(&substitute(&text[index + 2..close], bodies)?);
            copied = close;
            index = close + 1;
        } else {
            index += if bytes[index] == b'\\' { 2 } else { 1 };
        }
    }
    output.push_str(&text[copied..=end]);
    Some(end + 1)
}

/// Whether brackets, string interpolations and `if` blocks nest no deeper
/// than [`MAX_DEPTH`] and every `end` closes an `if`.
fn nesting_bounded(program: &str) -> bool {
    let bytes = program.as_bytes();
    let mut open: Vec<u8> = Vec::new();
    let mut in_string = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            match byte {
                b'"' => in_string = false,
                b'\\' if bytes.get(index + 1) == Some(&b'(') => {
                    open.push(b'\\');
                    in_string = false;
                    index += 1;
                }
                b'\\' => index += 1,
                _ => {}
            }
        } else if byte == b'"' {
            in_string = true;
        } else if matches!(byte, b'(' | b'[' | b'{') {
            open.push(byte);
        } else if matches!(byte, b')' | b']' | b'}') {
            match open.pop() {
                Some(b'\\') => in_string = true,
                Some(b'i') | None => return false,
                Some(_) => {}
            }
        } else if keyword(bytes, index, "if") {
            open.push(b'i');
            index += 1;
        } else if keyword(bytes, index, "end") {
            if open.pop() != Some(b'i') {
                return false;
            }
            index += 2;
        }
        if open.len() > MAX_DEPTH {
            return false;
        }
        index += 1;
    }
    !in_string && open.is_empty()
}

/// Whether the keyword `word` stands at `index` as a whole word. A field
/// (`.end`), a variable (`$if`), a format or an object key (`{if: 1}`) of
/// the same spelling is not the keyword.
pub(super) fn keyword(bytes: &[u8], index: usize, word: &str) -> bool {
    let end = index + word.len();
    bytes[index..].starts_with(word.as_bytes())
        && !index
            .checked_sub(1)
            .is_some_and(|at| identifier_byte(bytes[at]) || matches!(bytes[at], b'.' | b'$' | b'@'))
        && !bytes.get(end).copied().is_some_and(identifier_byte)
        && bytes[end..].iter().find(|byte| **byte != b' ') != Some(&b':')
}

/// The length of the `if` that opens a block at `index`, which the
/// splitters count as an opening bracket.
pub(super) fn opens_block(bytes: &[u8], index: usize) -> Option<usize> {
    keyword(bytes, index, "if").then_some(2)
}

/// The length of the `end` that closes a block at `index`.
pub(super) fn closes_block(bytes: &[u8], index: usize) -> Option<usize> {
    keyword(bytes, index, "end").then_some(3)
}

/// Calls `each` with every byte index of `text` outside strings, brackets
/// and `if ... end` blocks. `each` returns false to refuse. Returns false
/// too when a bracket, block or string does not close.
pub(super) fn top_level(text: &str, mut each: impl FnMut(usize) -> bool) -> bool {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        if let Some(length) = opens_block(bytes, index) {
            depth += 1;
            index += length;
            continue;
        }
        if let Some(length) = closes_block(bytes, index) {
            let Some(up) = depth.checked_sub(1) else {
                return false;
            };
            depth = up;
            index += length;
            continue;
        }
        match bytes[index] {
            b'"' => match string_end(bytes, index) {
                Some(end) => index = end,
                None => return false,
            },
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return false,
            },
            _ if depth == 0 => {
                if !each(index) {
                    return false;
                }
            }
            _ => {}
        }
        index += 1;
    }
    depth == 0
}

/// A plain value: a bounded string with no interpolation, a jq number, a
/// JSON keyword, or an empty array or object. An interpolated string
/// carries a filter, which `interpolated_string` reads as one; admitting it
/// here would take its code for text. The number is jq's own literal — an
/// optional minus, digits or a leading fraction, and an optional exponent —
/// and nothing else.
pub(super) fn literal(part: &str) -> bool {
    matches!(part, "true" | "false" | "null" | "[]" | "{}")
        || (part.len() <= MAX_LITERAL
            && part.starts_with('"')
            && string_end(part.as_bytes(), 0) == Some(part.len() - 1)
            && !interpolates(&part[1..part.len() - 1]))
        || numeric_literal(part)
}

/// Whether `value`, the text inside a jq string, opens an interpolation. jq
/// reads `\(` as the start of one, but a backslash escapes whatever follows
/// it, so the `\\(` of `has("\\(")` is an escaped backslash and then a plain
/// parenthesis, which is text. Walking the escapes the way
/// `interpolated_string` does is the only way to tell the two apart: a
/// substring test reads the second as the first and sends a plain filter to
/// review.
fn interpolates(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] != b'\\' {
            index += 1;
            continue;
        }
        if bytes[index + 1] == b'(' {
            return true;
        }
        index += 2;
    }
    false
}

/// `1`, `-1`, `1.5`, `.5`, `1e-2`: a bounded jq number. A leading `+` is the
/// addition operator, not a sign, and a trailing dot or a bare exponent is
/// not a number this grammar will guess at.
fn numeric_literal(part: &str) -> bool {
    let bytes = part.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let mut index = usize::from(bytes[0] == b'-');
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

/// The index of the bracket closing the one that opens at `open`, skipping
/// strings.
pub(super) fn closing(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = string_end(bytes, index)?,
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => {
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

/// The largest literal bound `range` may count to or from.
const MAX_RANGE_BOUND: f64 = 100_000.0;

/// `range(5)`, `range(1; length)`, `range(0; 100; 10)`: bounds that are
/// plain decimal literals within [`MAX_RANGE_BOUND`] or the input's
/// `length`, and a literal step of at least one. `range(0; infinite)`,
/// `range(0; 1e18)` or a bound read from a field could count without end.
pub(super) fn bounded_range(arguments: &[&str]) -> bool {
    let literal = |text: &str| {
        let text = text.trim();
        !text.is_empty()
            && text.len() <= 12
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'.'))
            && text
                .parse::<f64>()
                .is_ok_and(|value| value.abs() <= MAX_RANGE_BOUND)
    };
    let bound = |text: &str| text.trim() == "length" || literal(text);
    match arguments {
        [upto] => bound(upto),
        [from, upto] => bound(from) && bound(upto),
        [from, upto, by] => {
            bound(from)
                && bound(upto)
                && literal(by)
                && by
                    .trim()
                    .parse::<f64>()
                    .is_ok_and(|value| value.abs() >= 1.0)
        }
        _ => false,
    }
}
