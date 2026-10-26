//! JSON helpers that reproduce the Python value handling of the shim code:
//! the `isinstance` filters, `json.dumps` formatting and `str()`/`repr()` of
//! decoded JSON.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::hook_adapter_pytext::py_repr_str;

/// `_string_items`: the string members of a list.
pub(crate) fn string_items(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// `_dict_items`: the object members of a list.
pub(crate) fn dict_items(value: Option<&Value>) -> Vec<Map<String, Value>> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_object().cloned())
            .collect(),
        _ => Vec::new(),
    }
}

/// `_string_map`: the string-to-string members of an object.
pub(crate) fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    match value {
        Some(Value::Object(map)) => map
            .iter()
            .filter_map(|(key, item)| item.as_str().map(|text| (key.clone(), text.to_owned())))
            .collect(),
        _ => BTreeMap::new(),
    }
}

/// `repr(float)`.
pub(crate) fn py_float_repr(value: f64) -> String {
    let text = format!("{value:?}");
    let Some((mantissa, exponent)) = text.split_once('e') else {
        return text;
    };
    let (sign, digits) = match exponent.strip_prefix('-') {
        Some(rest) => ('-', rest),
        None => ('+', exponent),
    };
    format!("{mantissa}e{sign}{digits:0>2}")
}

/// `repr(list[str])`.
pub(crate) fn py_repr_list(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|item| py_repr_str(item)).collect();
    format!("[{}]", inner.join(", "))
}

/// `repr()` of decoded JSON.
pub(crate) fn py_repr_value(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => py_number_text(number),
        Value::String(text) => py_repr_str(text),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(py_repr_value).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(key, item)| format!("{}: {}", py_repr_str(key), py_repr_value(item)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// `str()` of decoded JSON.
pub(crate) fn py_str_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => py_repr_value(other),
    }
}

fn py_number_text(number: &serde_json::Number) -> String {
    let text = number.to_string();
    if text
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'-')
    {
        return text;
    }
    text.parse::<f64>().map_or(text, py_float_repr)
}

/// `json.dumps(value)` with the default separators; `sort_keys` orders object
/// keys by code point, which is the byte order of their UTF-8 encoding.
pub(crate) fn py_json_dumps(value: &Value, sort_keys: bool) -> String {
    let mut out = String::new();
    dump(value, sort_keys, &mut out);
    out
}

fn dump(value: &Value, sort_keys: bool, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&py_number_text(number)),
        Value::String(text) => dump_str(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                dump(item, sort_keys, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if sort_keys {
                entries.sort_by(|left, right| left.0.cmp(right.0));
            }
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                dump_str(key, out);
                out.push_str(": ");
                dump(item, sort_keys, out);
            }
            out.push('}');
        }
    }
}

fn dump_str(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 || (ch as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

pub(crate) use crate::codex_output_py::{is_py_space as py_is_space, py_splitlines, py_strip};

/// `hashlib.sha256(content).hexdigest()`.
pub(crate) fn sha256_hex(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(content))
}

/// `ast.literal_eval` restricted to a list of plain string literals, which is
/// all the generated shims contain. Anything else is `None`.
pub(crate) fn parse_py_str_list(text: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = text.trim().chars().collect();
    let mut index = 0usize;
    if chars.get(index) != Some(&'[') {
        return None;
    }
    index += 1;
    let mut items = Vec::new();
    loop {
        skip_spaces(&chars, &mut index);
        match chars.get(index) {
            Some(']') => {
                index += 1;
                break;
            }
            Some('\'' | '"') => {
                items.push(parse_str_literal(&chars, &mut index)?);
                skip_spaces(&chars, &mut index);
                match chars.get(index) {
                    Some(',') => index += 1,
                    Some(']') => {}
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    skip_spaces(&chars, &mut index);
    (index == chars.len()).then_some(items)
}

fn skip_spaces(chars: &[char], index: &mut usize) {
    while chars.get(*index).is_some_and(|ch| ch.is_whitespace()) {
        *index += 1;
    }
}

fn parse_str_literal(chars: &[char], index: &mut usize) -> Option<String> {
    let quote = *chars.get(*index)?;
    *index += 1;
    let mut out = String::new();
    loop {
        let ch = *chars.get(*index)?;
        *index += 1;
        if ch == quote {
            return Some(out);
        }
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let escape = *chars.get(*index)?;
        *index += 1;
        match escape {
            '\\' | '\'' | '"' => out.push(escape),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '0' => out.push('\0'),
            'x' => out.push(hex_escape(chars, index, 2)?),
            'u' => out.push(hex_escape(chars, index, 4)?),
            'U' => out.push(hex_escape(chars, index, 8)?),
            _ => return None,
        }
    }
}

fn hex_escape(chars: &[char], index: &mut usize, width: usize) -> Option<char> {
    let digits: String = chars.get(*index..*index + width)?.iter().collect();
    *index += width;
    char::from_u32(u32::from_str_radix(&digits, 16).ok()?)
}
