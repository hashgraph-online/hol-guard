//! The jq terms the read grammar admits beyond projections and the
//! one-argument builtins: arithmetic, assignments, conditionals, `reduce`
//! and `foreach`, `try`, calls taking several arguments, paths with quoted
//! or computed subscripts, and projections of a term's output.
//!
//! Every form here is a pure function of the value jq read. Each one is
//! admitted only when every filter it carries is admitted in turn, so none
//! of them reaches the environment, further input, files or modules.
//! Builtins that read outside state (`env`, `$ENV`, `input`, `inputs`,
//! `input_filename`, `debug`, `stderr`, `halt_error`, `@sh`, `import`,
//! `include`, `label`) and the ones that can run without end or blow up on
//! a finite value (`recurse(f)`, `while`, `until`, `repeat`, `infinite`,
//! `combinations`) appear in no list here. `range` is admitted only over
//! small literal bounds or the input's `length`, and only one call may appear
//! in the fully inlined filter so separate per-call bounds cannot multiply.

use super::program::{bounded_range, closing, identifier_byte, keyword, literal, top_level};
use super::{
    alternative, call, pipeline, split_marker, stage, string_end, subscript, variable_name,
};

/// How many operands one arithmetic expression may join.
const MAX_OPERANDS: usize = 16;

/// Argument-free builtins beyond the core list: math, conversions between a
/// value and its JSON text or code points, date conversions of a number or
/// string, and walks over the value's own paths.
const VALUE_BUILTINS: &[&str] = &[
    "abs",
    "all",
    "any",
    "ascii",
    "ceil",
    "explode",
    "fabs",
    "fromdate",
    "fromdateiso8601",
    "fromjson",
    "gmtime",
    "implode",
    "isinfinite",
    "isnan",
    "isnormal",
    "leaf_paths",
    "ltrim",
    "mktime",
    "nan",
    "now",
    "paths",
    "recurse",
    "round",
    "rtrim",
    "sqrt",
    "toarray",
    "todate",
    "todateiso8601",
    "tojson",
    "tostream",
    "transpose",
    "trim",
];

/// Builtins called with arguments, each argument an admitted filter over the
/// value read, with the argument counts jq defines for them. None evaluates
/// an argument as a program, a file name or a module.
const CALLS: &[(&str, &[usize])] = &[
    ("IN", &[1, 2]),
    ("INDEX", &[1, 2]),
    ("add", &[1]),
    ("all", &[1, 2]),
    ("any", &[1, 2]),
    ("capture", &[1, 2]),
    ("contains", &[1]),
    ("del", &[1]),
    ("delpaths", &[1]),
    ("endswith", &[1]),
    ("first", &[1]),
    ("flatten", &[1]),
    ("getpath", &[1]),
    ("group_by", &[1]),
    ("gsub", &[2, 3]),
    ("has", &[1]),
    ("in", &[1]),
    ("index", &[1]),
    ("indices", &[1]),
    ("inside", &[1]),
    ("isempty", &[1]),
    ("join", &[1]),
    ("last", &[1]),
    ("limit", &[2]),
    ("ltrimstr", &[1]),
    ("map", &[1]),
    ("map_values", &[1]),
    ("match", &[1, 2]),
    ("max_by", &[1]),
    ("min_by", &[1]),
    ("nth", &[1, 2]),
    ("path", &[1]),
    ("paths", &[1]),
    ("pick", &[1]),
    ("pow", &[2]),
    ("range", &[1, 2, 3]),
    ("rindex", &[1]),
    ("rtrimstr", &[1]),
    ("scan", &[1, 2]),
    ("select", &[1]),
    ("setpath", &[2]),
    ("sort_by", &[1]),
    ("split", &[1, 2]),
    ("splits", &[1, 2]),
    ("startswith", &[1]),
    ("strftime", &[1]),
    ("strptime", &[1]),
    ("sub", &[2, 3]),
    ("test", &[1, 2]),
    ("unique_by", &[1]),
    ("walk", &[1]),
    ("with_entries", &[1]),
];

/// `.cost * 1000 | round / 1000`, `.name + " " + .state`: operands joined
/// by `+`, `-`, `*`, `/` or `%`. Arithmetic only combines the values its
/// operands produce, so it reaches no further than they do. `None` when
/// `part` joins nothing at its top level.
pub(super) fn arithmetic(part: &str) -> Option<bool> {
    let bytes = part.as_bytes();
    let mut cuts = Vec::new();
    let balanced = top_level(part, |index| {
        let byte = bytes[index];
        if !matches!(byte, b'+' | b'-' | b'*' | b'/' | b'%') {
            return true;
        }
        // An assignment or a `//` fallback belongs to an outer level.
        if matches!(bytes.get(index + 1), Some(b'=' | b'/')) {
            return false;
        }
        if binary(bytes, index) {
            cuts.push(index);
        }
        true
    });
    if !balanced {
        return Some(false);
    }
    if cuts.is_empty() {
        return part.starts_with('-').then(|| operand(part));
    }
    let mut operands = Vec::with_capacity(cuts.len() + 1);
    let mut start = 0;
    for cut in cuts {
        operands.push(part[start..cut].trim());
        start = cut + 1;
    }
    operands.push(part[start..].trim());
    Some(operands.len() <= MAX_OPERANDS && operands.iter().all(|value| operand(value)))
}

/// `1`, `.count`, `-.number`: a value arithmetic combines. One minus sign
/// may negate a stage; `--1` and `-+1` are not read.
fn operand(value: &str) -> bool {
    literal(value)
        || stage(value)
        || value.strip_prefix('-').is_some_and(|rest| {
            let rest = rest.trim_start();
            !rest.starts_with(['-', '+']) && stage(rest)
        })
}

/// Whether the operator at `index` joins two operands. A `+` or `-` with no
/// operand before it is a sign, and so is the one in an exponent (`1e-2`).
fn binary(bytes: &[u8], index: usize) -> bool {
    if !matches!(bytes[index], b'+' | b'-') {
        return true;
    }
    let Some(&last) = bytes[..index].trim_ascii_end().last() else {
        return false;
    };
    if matches!(last, b'+' | b'-' | b'*' | b'/' | b'%') {
        return false;
    }
    if index > 0 && matches!(bytes[index - 1], b'e' | b'E') {
        let mantissa_end = index - 1;
        let mantissa_start = bytes[..mantissa_end]
            .iter()
            .rposition(|byte| !(byte.is_ascii_digit() || *byte == b'.'))
            .map_or(0, |at| at + 1);
        let named = mantissa_start
            .checked_sub(1)
            .is_some_and(|at| identifier_byte(bytes[at]));
        if !named
            && bytes[mantissa_start..mantissa_end]
                .iter()
                .any(u8::is_ascii_digit)
        {
            return false;
        }
    }
    true
}

/// `.a |= sort_by(.id)`, `.[$k] += [$v]`, `.a //= 0`: an assignment outputs
/// the value read with the value at one path replaced. jq writes nothing
/// else, so the assignment reads no further than its path and its new
/// value, each an admitted filter. `None` when `part` assigns nothing at
/// its top level.
pub(super) fn assignment(part: &str) -> Option<bool> {
    let bytes = part.as_bytes();
    let mut found: Option<(usize, usize)> = None;
    let mut several = false;
    let balanced = top_level(part, |index| {
        if bytes[index] != b'=' {
            return true;
        }
        let previous = index.checked_sub(1).map(|at| bytes[at]);
        let next = bytes.get(index + 1).copied();
        // `==`, `!=`, `<=` and `>=` compare.
        if next == Some(b'=') || matches!(previous, Some(b'=' | b'!' | b'<' | b'>')) {
            return true;
        }
        let start = match previous {
            Some(b'/') if index >= 2 && bytes[index - 2] == b'/' => index - 2,
            Some(b'|' | b'+' | b'-' | b'*' | b'/' | b'%') => index - 1,
            _ => index,
        };
        several |= found.replace((start, index + 1)).is_some();
        true
    });
    let (start, end) = found?;
    let (path, value) = (part[..start].trim(), part[end..].trim());
    Some(
        balanced
            && !several
            && !path.is_empty()
            && !value.is_empty()
            && stage(path)
            && alternative(value),
    )
}

/// The terms of this module that stand as a stage.
pub(super) fn term(part: &str) -> bool {
    call_builtin(part)
        || conditional(part)
        || reduction(part)
        || attempt(part)
        || path(part)
        || postfixed(part)
}

/// `test("^fix"; "i")`, `gsub("\\s+"; " ")`, `limit(3; .[])`: a builtin
/// from [`CALLS`] with as many arguments as jq defines for it, each an
/// admitted filter.
fn call_builtin(stage: &str) -> bool {
    let Some((name, argument)) = call(stage) else {
        return false;
    };
    let Some((_, arities)) = CALLS.iter().find(|(known, _)| *known == name) else {
        return false;
    };
    let Some(arguments) = split_marker(argument, b";") else {
        return false;
    };
    arities.contains(&arguments.len())
        && (name != "range" || bounded_range(&arguments))
        && arguments
            .iter()
            .all(|argument| !argument.is_empty() && pipeline(argument))
}

/// `if .draft then "draft" elif .merged then "merged" else .state end`:
/// each condition and branch an admitted filter. The `else` may be left
/// out, as jq 1.7 allows.
fn conditional(stage: &str) -> bool {
    let bytes = stage.as_bytes();
    if !keyword(bytes, 0, "if") {
        return false;
    }
    let mut marks: Vec<(&str, usize, usize)> = vec![("if", 0, 2)];
    let mut depth = 0usize;
    let mut blocks = 1usize;
    let mut index = 2;
    'scan: while index < bytes.len() {
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
                if keyword(bytes, index, "if") {
                    blocks += 1;
                    index += 2;
                    continue;
                }
                if keyword(bytes, index, "end") {
                    blocks -= 1;
                    if blocks == 0 {
                        marks.push(("end", index, index + 3));
                        if index + 3 != bytes.len() {
                            return false;
                        }
                        break;
                    }
                    index += 3;
                    continue;
                }
                if blocks == 1 {
                    for word in ["then", "elif", "else"] {
                        if keyword(bytes, index, word) {
                            marks.push((word, index, index + word.len()));
                            index += word.len();
                            continue 'scan;
                        }
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    let shape = marks.windows(2).all(|pair| {
        matches!(
            (pair[0].0, pair[1].0),
            ("if" | "elif", "then") | ("then", "elif" | "else" | "end") | ("else", "end")
        )
    });
    shape
        && marks.last().is_some_and(|mark| mark.0 == "end")
        && marks.windows(2).all(|pair| {
            let piece = stage[pair[0].2..pair[1].1].trim();
            !piece.is_empty() && pipeline(piece)
        })
}

/// `reduce .[] as $item ({}; .[$item.kind] += [$item.name])`, and `foreach`
/// with or without its extract: a fold over the outputs of an admitted term,
/// its state and update admitted filters.
fn reduction(stage: &str) -> bool {
    let (rest, arities): (&str, &[usize]) = if let Some(rest) = stage.strip_prefix("reduce ") {
        (rest, &[2])
    } else if let Some(rest) = stage.strip_prefix("foreach ") {
        (rest, &[2, 3])
    } else {
        return false;
    };
    let Some(halves) = split_marker(rest, b" as $") else {
        return false;
    };
    let [source, after] = halves.as_slice() else {
        return false;
    };
    let end = after
        .find(|value: char| !(value.is_ascii_alphanumeric() || value == '_'))
        .unwrap_or(after.len());
    let (name, body) = after.split_at(end);
    let Some(body) = body
        .trim_start()
        .strip_prefix('(')
        .and_then(|body| body.strip_suffix(')'))
    else {
        return false;
    };
    let Some(parts) = split_marker(body, b";") else {
        return false;
    };
    variable_name(name)
        && arities.contains(&parts.len())
        && super::stage(source)
        && parts.iter().all(|part| !part.is_empty() && pipeline(part))
}

/// `try .a catch "none"`: the body's output, or the handler's when the
/// body raises an error.
fn attempt(stage: &str) -> bool {
    let Some(rest) = stage.strip_prefix("try ") else {
        return false;
    };
    let Some(parts) = split_marker(rest, b" catch ") else {
        return false;
    };
    match parts.as_slice() {
        [body] => super::stage(body),
        [body, handler] => super::stage(body) && (literal(handler) || super::stage(handler)),
        _ => false,
    }
}

/// `.a."b-c"[0]`, `.["dependabot[bot]"]`, `.[$item.kind]`, `..`: a
/// projection whose segments may also be quoted names, string subscripts or
/// subscripts that are admitted filters, each optionally `?`.
fn path(filter: &str) -> bool {
    if filter == ".." {
        return true;
    }
    let bytes = filter.as_bytes();
    if bytes.first() != Some(&b'.') {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'.' => {
                index += 1;
                match bytes.get(index) {
                    Some(b'"') => {
                        let Some(end) = string_end(bytes, index) else {
                            return false;
                        };
                        if !literal(&filter[index..=end]) {
                            return false;
                        }
                        index = end + 1;
                    }
                    Some(byte) if byte.is_ascii_alphabetic() || *byte == b'_' => {
                        while bytes.get(index).copied().is_some_and(identifier_byte) {
                            index += 1;
                        }
                    }
                    Some(b'[') => continue,
                    None if index == 1 => {}
                    _ => return false,
                }
            }
            b'[' => {
                let Some(close) = closing(bytes, index) else {
                    return false;
                };
                let inner = filter[index + 1..close].trim();
                let mut at = 0;
                let plain = subscript(inner.as_bytes(), &mut at) && at == inner.len();
                if !plain && !pipeline(inner) {
                    return false;
                }
                index = close + 1;
            }
            _ => return false,
        }
        if bytes.get(index) == Some(&b'?') {
            index += 1;
        }
    }
    true
}

/// `(.args | tostring)[0:160]`, `(.content // [])[]?`, `[.a][0]`,
/// `capture("x").name`, `capture("x")?.name`, `$row[.key]`: an admitted term followed by a
/// projection of its output.
fn postfixed(stage: &str) -> bool {
    let bytes = stage.as_bytes();
    let close = match bytes.first() {
        Some(b'(' | b'[' | b'{') => closing(bytes, 0),
        Some(b'$') => Some(
            stage[1..]
                .find(|value: char| !(value.is_ascii_alphanumeric() || value == '_'))
                .unwrap_or(stage.len() - 1),
        ),
        Some(byte) if byte.is_ascii_alphabetic() || *byte == b'_' => stage
            .find(|value: char| !(value.is_ascii_alphanumeric() || value == '_'))
            .filter(|open| bytes[*open] == b'(')
            .and_then(|open| closing(bytes, open)),
        _ => None,
    };
    let Some(close) = close else {
        return false;
    };
    let (term, suffix) = stage.split_at(close + 1);
    // `capture("x")?.name`: a `?` only drops the term's error.
    let suffix = suffix.strip_prefix('?').unwrap_or(suffix);
    if suffix.is_empty() || !matches!(suffix.as_bytes()[0], b'.' | b'[') {
        return false;
    }
    let suffix_path = if suffix.starts_with('.') {
        suffix.to_owned()
    } else {
        format!(".{suffix}")
    };
    path(&suffix_path) && super::stage(term)
}

/// Whether `name` is an argument-free builtin from this module's list.
pub(super) fn value_builtin(name: &str) -> bool {
    VALUE_BUILTINS.contains(&name)
}

#[cfg(test)]
#[path = "jq_filter_terms_tests.rs"]
mod tests;
