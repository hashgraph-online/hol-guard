//! The jq filter grammar admitted by the bounded `jq` read proofs.
//!
//! A filter is a short pipeline. Each stage is a field/index projection
//! (`.scripts`, `.items[0].name`, `.[]`), a builtin that only reshapes the
//! value already read (argument-free ones such as `keys`, `length` or
//! `sort`, optionally iterated or indexed as in `keys[]`, and a few that take
//! one plain string or number literal such as `has("name")` or `join("\n")`),
//! or an object whose keys are names or plain string literals and whose values
//! are themselves admitted filters (`{"a": .x | has("y")}`). Nothing that
//! reads the environment, further input, files or modules can appear: `$`,
//! `@`, string interpolation, `;`, a `,` or `:` outside an object or literal,
//! computed object keys, and every builtin outside the lists are rejected.

const MAX_STAGES: usize = 8;

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

const MAX_LITERAL: usize = 128;

pub(super) fn safe_filter(filter: &str) -> bool {
    filter.len() <= 256 && valid_characters(filter) && pipeline(filter)
}

fn pipeline(filter: &str) -> bool {
    let Some(stages) = split_top(filter, b'|') else {
        return false;
    };
    stages.len() <= MAX_STAGES
        && stages.iter().all(|stage| {
            projection(stage) || iterated_builtin(stage) || literal_builtin(stage) || object(stage)
        })
}

/// Outside string literals only names, projections, spaces, literal-call
/// parentheses and object punctuation may appear; inside one only printable
/// ASCII and the `\n`, `\t` and `\\` escapes, so neither `\(` interpolation
/// nor an escaped quote can appear. Braces must balance.
fn valid_characters(filter: &str) -> bool {
    let bytes = filter.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => match string_end(bytes, index) {
                Some(end) => index = end,
                None => return false,
            },
            b'{' => depth += 1,
            b'}' => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return false,
            },
            b':' | b',' if depth > 0 => {}
            byte if byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'[' | b']' | b' ' | b'(' | b')' | b'|') => {}
            _ => return false,
        }
        index += 1;
    }
    depth == 0
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

/// Splits on `separator` outside string literals and objects, trimming each
/// part. Assumes `valid_characters` already held for the whole filter.
fn split_top(text: &str, separator: u8) -> Option<Vec<&str>> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = string_end(bytes, index)?,
            b'{' => depth += 1,
            b'}' => depth = depth.checked_sub(1)?,
            byte if byte == separator && depth == 0 => {
                parts.push(text[start..index].trim());
                start = index + 1;
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
    let Some(entries) = split_top(inner, b',') else {
        return false;
    };
    entries.iter().all(|entry| {
        let Some(colon) = split_top(entry, b':') else {
            return false;
        };
        let [key, value] = colon.as_slice() else {
            return false;
        };
        object_key(key) && pipeline(value)
    })
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
    let Some((name, rest)) = stage.split_once('(') else {
        return false;
    };
    let Some(argument) = rest.strip_suffix(')') else {
        return false;
    };
    let string = argument.len() <= MAX_LITERAL
        && argument
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .is_some_and(|value| !value.contains('"'));
    let number =
        (1..=18).contains(&argument.len()) && argument.bytes().all(|byte| byte.is_ascii_digit());
    LITERAL_BUILTINS.contains(&name.trim_end()) && (string || number)
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
mod tests {
    use super::safe_filter;

    #[test]
    fn pipelines_of_projections_and_value_builtins_are_allowed() {
        for filter in [
            ".scripts",
            ".scripts | keys | length",
            ".dependencies|keys_unsorted|sort",
            ".items[0] | .name",
            ".[] | type",
            ".queries | keys[]",
            ".queries | to_entries[] | .key",
            ".items | keys[0]",
            ".queries | has(\"auth_attempts\")",
            ".queries | keys | join(\"\\n\")",
            ".name | split(\"/\") | .[0]",
            ".list | has(0)",
            ".name | startswith(\"a|b\")",
            "keys",
            "length",
            "keys[]",
            "to_entries | length",
            "{\"a\": .queries|has(\"x\"), \"b\": .queries|has(\"y\")}",
            "{name: .name, count: .items | length}",
            "{\"a b\": {inner: .x | keys}}",
            ".queries | {\"q x\": has(\"a:b,c\")}",
        ] {
            assert!(safe_filter(filter), "{filter}");
        }
    }

    #[test]
    fn environment_input_and_arbitrary_functions_are_rejected() {
        for filter in [
            "env",
            ".a | env",
            ".a | $ENV",
            ".a | input",
            ".a | inputs",
            ".a | input_filename",
            ".a | debug",
            ".a | halt_error",
            ".a | @sh",
            ".a | tostring(1)",
            ".a, .b",
            ".a | \"x\"",
            ".a |",
            ".a | | length",
            ". | keys | keys | keys | keys | keys | keys | keys | keys",
            ".a | has(\"\\(env)\")",
            ".a | has(\"\\\"\")",
            ".a | has(\"x\", \"y\")",
            ".a | has(.b)",
            ".a | has($x)",
            ".a | has(\"x\")(\"y\")",
            ".a | test(\"x\")",
            ".a | env[]",
            ".a | input[]",
            ".a | keys[] | \"x\"",
            ".a | has(\"x)",
            ".a | keys()",
            "input",
            "inputs",
            "$__loc__",
            "input_filename",
            "{a}",
            "{$ENV}",
            "{(.a): .b}",
            "{a: env}",
            "{a: input}",
            "{a: .x, .y}",
            "{a: .x: .y}",
            "{a-b: .x}",
            "{\"\\(env)\": .x}",
            "{a: .x}{b: .y}",
            "{a: .x",
            "a: .x}",
            ".a : .b",
            "{}",
            "{a: .x | @sh}",
            "{a: .x | tostring(1)}",
        ] {
            assert!(!safe_filter(filter), "{filter}");
        }
    }
}
