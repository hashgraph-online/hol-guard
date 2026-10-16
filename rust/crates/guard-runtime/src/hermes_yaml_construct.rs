//! Construct Python values from composed YAML nodes the way PyYAML's
//! `SafeConstructor` does, then apply the Hermes value validation.

use std::collections::BTreeSet;

use super::hermes_yaml::{
    fail, step, Built, Failure, Foreign, Node, Value, ERR_UNREPRESENTABLE, MAX_DEPTH,
    MAX_INT_DIGITS, MAX_NODES, MAX_RADIX_DIGITS, TAG_MERGE, TAG_PREFIX, TAG_VALUE,
};
use super::hermes_yaml_resolve::{
    all, digit, resolved_tag, strip_sign, timestamp_parts, timestamp_value,
};
use super::pyjson::{float_repr, PyVal};

pub(crate) fn construct(node: &Node) -> Built<Value> {
    let tag = resolved_tag(node);
    let Some(name) = tag.strip_prefix(TAG_PREFIX) else {
        // No constructor for the tag.
        return fail(Failure::Parse);
    };
    match name {
        "null" => match node {
            Node::Scalar { .. } => Ok(Ok(Value::Null)),
            _ => fail(Failure::Parse),
        },
        "bool" => {
            let text = step!(scalar_text(node));
            match text.to_lowercase().as_str() {
                "yes" | "true" | "on" => Ok(Ok(Value::Bool(true))),
                "no" | "false" | "off" => Ok(Ok(Value::Bool(false))),
                // A KeyError, not a YAMLError.
                _ => Err(ERR_UNREPRESENTABLE),
            }
        }
        "int" => construct_int(&step!(scalar_text(node))),
        "float" => construct_float(&step!(scalar_text(node))),
        "str" => Ok(Ok(Value::Str(step!(scalar_text(node))))),
        "binary" => {
            let text = step!(scalar_text(node));
            Ok(decode_base64(&text).map(|bytes| Value::Foreign(Foreign::Bytes(bytes))))
        }
        "timestamp" => {
            let text = step!(scalar_text(node));
            match timestamp_parts(&text, false) {
                Some(stamp) => match timestamp_value(&stamp) {
                    Some(value) => Ok(Ok(Value::Foreign(value))),
                    // The date arguments are out of range: a ValueError.
                    None => fail(Failure::Parse),
                },
                // An explicit tag on text that is not a timestamp is an
                // AttributeError, not a YAMLError.
                None => Err(ERR_UNREPRESENTABLE),
            }
        }
        "seq" => match node {
            Node::Seq { items, .. } => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(step!(construct(item)));
                }
                Ok(Ok(Value::List(out)))
            }
            _ => fail(Failure::Parse),
        },
        "map" => match node {
            Node::Map { pairs, .. } => construct_map(pairs),
            _ => fail(Failure::Parse),
        },
        "set" => match node {
            Node::Map { pairs, .. } => {
                for (key_node, value_node) in step!(flatten(pairs)) {
                    let key = step!(construct(key_node));
                    if hashable(&key).is_none() {
                        return fail(Failure::Parse);
                    }
                    step!(construct(value_node));
                }
                Ok(Ok(Value::Foreign(Foreign::Set)))
            }
            _ => fail(Failure::Parse),
        },
        "omap" | "pairs" => match node {
            Node::Seq { items, .. } => {
                for item in items {
                    let Node::Map { pairs, .. } = item else {
                        return fail(Failure::Parse);
                    };
                    let [(key_node, value_node)] = pairs.as_slice() else {
                        return fail(Failure::Parse);
                    };
                    step!(construct(key_node));
                    step!(construct(value_node));
                }
                if items.is_empty() {
                    Ok(Ok(Value::List(Vec::new())))
                } else {
                    Ok(Ok(Value::Foreign(Foreign::Pairs)))
                }
            }
            _ => fail(Failure::Parse),
        },
        _ => fail(Failure::Parse),
    }
}

fn scalar_text(node: &Node) -> Built<String> {
    match node {
        Node::Scalar { value, .. } => Ok(Ok(value.clone())),
        _ => fail(Failure::Parse),
    }
}

/// `SafeConstructor.flatten_mapping`: `<<` merges are folded in front.
fn flatten(pairs: &[(Node, Node)]) -> Built<Vec<(&Node, &Node)>> {
    let mut merge: Vec<(&Node, &Node)> = Vec::new();
    let mut rest: Vec<(&Node, &Node)> = Vec::new();
    for (key, value) in pairs {
        if resolved_tag(key) != TAG_MERGE {
            rest.push((key, value));
            continue;
        }
        match value {
            Node::Map { pairs, .. } => merge.extend(step!(flatten(pairs))),
            Node::Seq { items, .. } => {
                let mut groups: Vec<Vec<(&Node, &Node)>> = Vec::new();
                for item in items {
                    let Node::Map { pairs, .. } = item else {
                        return fail(Failure::Parse);
                    };
                    groups.push(step!(flatten(pairs)));
                }
                groups.reverse();
                for group in groups {
                    merge.extend(group);
                }
            }
            Node::Scalar { .. } => return fail(Failure::Parse),
        }
    }
    merge.extend(rest);
    Ok(Ok(merge))
}

/// The Hermes constructor: a mapping with a duplicate key is an error.
fn construct_map(pairs: &[(Node, Node)]) -> Built<Value> {
    let merged = step!(flatten(pairs));
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(merged.len());
    let mut seen: BTreeSet<Key> = BTreeSet::new();
    for (key_node, value_node) in merged {
        // A `=` key is an ordinary string key.
        let key = if resolved_tag(key_node) == TAG_VALUE {
            Value::Str("=".to_owned())
        } else {
            step!(construct(key_node))
        };
        let Some(identity) = hashable(&key) else {
            return fail(Failure::Invalid);
        };
        if !seen.insert(identity) {
            return fail(Failure::Duplicate);
        }
        let value = step!(construct(value_node));
        entries.push((key, value));
    }
    Ok(Ok(Value::Dict(entries)))
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Null,
    Number(String),
    NotANumber,
    Text(String),
    Timestamp(String),
    Bytes(Vec<u8>),
}

/// Python hash/equality identity of a key, or `None` when unhashable.
fn hashable(value: &Value) -> Option<Key> {
    Some(match value {
        Value::Null => Key::Null,
        Value::Bool(flag) => Key::Number(if *flag { "1" } else { "0" }.to_owned()),
        Value::Int(digits) => Key::Number(digits.clone()),
        Value::Float(number) => {
            if number.is_nan() {
                Key::NotANumber
            } else if number.is_finite() && number.fract() == 0.0 {
                let digits = format!("{number:.0}");
                Key::Number(if digits == "-0" {
                    "0".to_owned()
                } else {
                    digits
                })
            } else {
                Key::Number(format!("f{}", float_repr(*number)))
            }
        }
        Value::Str(text) => Key::Text(text.clone()),
        Value::Foreign(Foreign::Timestamp(text)) => Key::Timestamp(text.clone()),
        Value::Foreign(Foreign::Bytes(bytes)) => Key::Bytes(bytes.clone()),
        Value::List(_) | Value::Dict(_) | Value::Foreign(Foreign::Set | Foreign::Pairs) => {
            return None;
        }
    })
}

fn construct_int(raw: &str) -> Built<Value> {
    let cleaned: String = raw.chars().filter(|ch| *ch != '_').collect();
    let Some(first) = cleaned.chars().next() else {
        // `value[0]` on an empty scalar is an IndexError, not a YAMLError.
        return Err(ERR_UNREPRESENTABLE);
    };
    let negative = first == '-';
    let body = strip_sign(&cleaned);
    let magnitude = if body == "0" {
        "0".to_owned()
    } else if let Some(rest) = body.strip_prefix("0b") {
        step!(radix_digits(rest, 2))
    } else if let Some(rest) = body.strip_prefix("0x") {
        step!(radix_digits(rest, 16))
    } else if body.starts_with('0') {
        step!(radix_digits(body, 8))
    } else if body.contains(':') {
        let mut total: u128 = 0;
        let mut weight: u128 = 1;
        for part in body.split(':').rev() {
            if part.len() > MAX_INT_DIGITS {
                return fail(Failure::Parse);
            }
            let Some(parsed) = decimal(part) else {
                return fail(Failure::Parse);
            };
            let Ok(parsed) = parsed.parse::<u128>() else {
                return Err(ERR_UNREPRESENTABLE);
            };
            let term = parsed.checked_mul(weight).ok_or(ERR_UNREPRESENTABLE)?;
            total = total.checked_add(term).ok_or(ERR_UNREPRESENTABLE)?;
            weight = weight.checked_mul(60).ok_or(ERR_UNREPRESENTABLE)?;
        }
        total.to_string()
    } else {
        if body.len() > MAX_INT_DIGITS {
            return fail(Failure::Parse);
        }
        match decimal(body) {
            Some(digits) => digits,
            None => return fail(Failure::Parse),
        }
    };
    Ok(Ok(Value::Int(if negative && magnitude != "0" {
        format!("-{magnitude}")
    } else {
        magnitude
    })))
}

/// Decimal digits with leading zeros dropped; `None` when not all digits
/// (Python's `int()` raises ValueError).
fn decimal(text: &str) -> Option<String> {
    if text.is_empty() || !all(text, digit) {
        return None;
    }
    let trimmed = text.trim_start_matches('0');
    Some(if trimmed.is_empty() { "0" } else { trimmed }.to_owned())
}

/// `int(text, radix)` as canonical decimal digits.
fn radix_digits(text: &str, radix: u32) -> Built<String> {
    if text.is_empty() || !all(text, |ch| ch.is_digit(radix)) {
        return fail(Failure::Parse);
    }
    if text.len() > MAX_RADIX_DIGITS {
        return Err(ERR_UNREPRESENTABLE);
    }
    // Little-endian base-1e9 limbs.
    let mut limbs: Vec<u64> = vec![0];
    for ch in text.chars() {
        let mut carry = u64::from(ch.to_digit(radix).unwrap_or(0));
        for limb in &mut limbs {
            let value = *limb * u64::from(radix) + carry;
            *limb = value % 1_000_000_000;
            carry = value / 1_000_000_000;
        }
        if carry > 0 {
            limbs.push(carry);
        }
    }
    let mut out = String::new();
    for (index, limb) in limbs.iter().rev().enumerate() {
        if index == 0 {
            out.push_str(&limb.to_string());
        } else {
            out.push_str(&format!("{limb:09}"));
        }
    }
    Ok(Ok(out))
}

fn construct_float(raw: &str) -> Built<Value> {
    let cleaned: String = raw
        .chars()
        .filter(|ch| *ch != '_')
        .collect::<String>()
        .to_lowercase();
    let Some(first) = cleaned.chars().next() else {
        return Err(ERR_UNREPRESENTABLE);
    };
    let sign = if first == '-' { -1.0 } else { 1.0 };
    let body = strip_sign(&cleaned);
    if body == ".inf" {
        return Ok(Ok(Value::Float(sign * f64::INFINITY)));
    }
    if body == ".nan" {
        return Ok(Ok(Value::Float(f64::NAN)));
    }
    if body.contains(':') {
        let mut total = 0.0f64;
        let mut weight = 1.0f64;
        for part in body.split(':').rev() {
            let Some(parsed) = python_float(part) else {
                return fail(Failure::Parse);
            };
            total += parsed * weight;
            weight *= 60.0;
        }
        return Ok(Ok(Value::Float(sign * total)));
    }
    match python_float(body) {
        Some(parsed) => Ok(Ok(Value::Float(sign * parsed))),
        None => fail(Failure::Parse),
    }
}

/// `float(text)` for the unsigned forms the resolver admits.
fn python_float(text: &str) -> Option<f64> {
    if text.is_empty() || text.starts_with(['+', '-']) {
        return None;
    }
    text.parse::<f64>().ok()
}

/// `base64.decodebytes`: characters outside the alphabet are skipped and the
/// padding must complete the last group.
fn decode_base64(text: &str) -> Result<Vec<u8>, Failure> {
    if !text.is_ascii() {
        return Err(Failure::Parse);
    }
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut out = Vec::new();
    let mut padding = 0usize;
    let mut symbols = 0usize;
    for ch in text.chars() {
        let value = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => {
                padding += 1;
                continue;
            }
            _ => continue,
        };
        if padding > 0 {
            return Err(Failure::Parse);
        }
        symbols += 1;
        bits = (bits << 6) | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(((bits >> count) & 0xFF) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if (symbols + padding) % 4 != 0 || padding > 2 {
        return Err(Failure::Parse);
    }
    Ok(out)
}

/// `_validate_config_value`, with its traversal order.
pub(crate) fn validate(root: &Value) -> Built<()> {
    let mut stack: Vec<(&Value, usize)> = vec![(root, 1)];
    let mut nodes = 0usize;
    while let Some((current, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES {
            return fail(Failure::Nodes);
        }
        if depth > MAX_DEPTH {
            return fail(Failure::Depth);
        }
        match current {
            Value::Dict(entries) => {
                for (key, item) in entries {
                    if !matches!(key, Value::Str(_)) {
                        return fail(Failure::Invalid);
                    }
                    stack.push((item, depth + 1));
                }
            }
            Value::List(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Float(number) if !number.is_finite() => return fail(Failure::Invalid),
            Value::Foreign(_) => return fail(Failure::Invalid),
            _ => {}
        }
    }
    Ok(Ok(()))
}

pub(crate) fn into_pyval(value: Value) -> PyVal {
    match value {
        Value::Null => PyVal::Null,
        Value::Bool(flag) => PyVal::Bool(flag),
        Value::Int(digits) => PyVal::Int(digits),
        Value::Float(number) => PyVal::Float(number),
        Value::Str(text) => PyVal::Str(text),
        Value::List(items) => PyVal::List(items.into_iter().map(into_pyval).collect()),
        Value::Dict(entries) => PyVal::Dict(
            entries
                .into_iter()
                .filter_map(|(key, value)| match key {
                    Value::Str(text) => Some((text, into_pyval(value))),
                    _ => None,
                })
                .collect(),
        ),
        // Validation rejected every foreign value before this point.
        Value::Foreign(_) => PyVal::Null,
    }
}

fn from_pyval(value: PyVal) -> Value {
    match value {
        PyVal::Null => Value::Null,
        PyVal::Bool(flag) => Value::Bool(flag),
        PyVal::Int(digits) => Value::Int(digits),
        PyVal::Float(number) => Value::Float(number),
        PyVal::Str(text) => Value::Str(text),
        PyVal::List(items) => Value::List(items.into_iter().map(from_pyval).collect()),
        PyVal::Dict(entries) => Value::Dict(
            entries
                .into_iter()
                .map(|(key, value)| (Value::Str(key), from_pyval(value)))
                .collect(),
        ),
    }
}

/// The Hermes value limits applied to a parsed JSON document.
pub(crate) fn validate_json(value: PyVal) -> Built<PyVal> {
    let value = from_pyval(value);
    step!(validate(&value));
    Ok(Ok(into_pyval(value)))
}
