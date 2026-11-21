//! The canonical policy-document hash a signed v2 policy bundle binds.
//!
//! The payload is a GuardPolicy document carried as JSON. Guard Cloud hashes
//! it the way the policy parser reads it: canonical JSON text loaded as YAML,
//! validated as a policy document, and canonicalized again. A JSON value the
//! strict YAML loader refuses or reads differently must hash the same way, so
//! `loaded` reproduces what that loader does to canonical JSON text: it
//! refuses non-printable characters, deep or token-heavy documents, long
//! scalars and keys, merge keys and wide integers, and folds the line breaks
//! a double-quoted YAML scalar may carry raw (NEL, LS and PS).

use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding};
use guard_command::command_expression_match::validate_expression;
use guard_contracts::{CommandExpressionV1, COMMAND_EXPRESSION_VALIDATION_MAX_EXPRESSIONS};
use guard_policy_snapshot::business_policy_document::satisfies_policy_document_schema;
use guard_policy_snapshot::digest_bytes;
use serde_json::{json, Map, Value};

#[cfg(test)]
#[path = "policy_bundle_payload_hash_tests.rs"]
mod tests;

const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_ITEMS: usize = 2_048;
const MAX_JSON_STRING_BYTES: usize = 1_048_576;
const MAX_POLICY_BYTES: usize = 1_048_576;
const MAX_YAML_TOKENS: usize = 200_000;
const MAX_YAML_DEPTH: usize = 33;
const MAX_SCALAR_CHARS: usize = 4_096;
const MAX_PLAIN_INTEGER_DIGITS: usize = 16;
/// A YAML simple key may span at most this many characters before its `:`.
const MAX_SIMPLE_KEY_SPAN: usize = 1_024;
const BREAKS: [char; 3] = ['\u{85}', '\u{2028}', '\u{2029}'];
const DOCUMENT_CLASS: &str = "GuardPolicyDocument";
const TIMEOUT: Duration = Duration::from_secs(5);

/// `sha256:<hex>` of the canonical policy document `payload` carries, or
/// `None` when the payload is not a valid policy document.
pub(crate) fn payload_hash(payload: &Value) -> Option<String> {
    if !payload.is_object() || !json_value(payload, 0) {
        return None;
    }
    let deadline = Instant::now() + TIMEOUT;
    let text = query("canonical", &json!({ "value": payload }), deadline)?;
    let text = text.as_str()?;
    if text.len() > MAX_POLICY_BYTES || !text.chars().all(printable) {
        return None;
    }
    // Stream start and stream end.
    let mut tokens = 2;
    let value = loaded(payload, 0, &mut tokens)?;
    if tokens > MAX_YAML_TOKENS {
        return None;
    }
    let document = validated_document(&value, deadline)?;
    let canonical = query("canonical", &json!({ "value": document }), deadline)?;
    Some(format!(
        "sha256:{}",
        digest_bytes(canonical.as_str()?.as_bytes())
    ))
}

/// The JSON subset a payload may use: no floats, bounded depth and size.
fn json_value(value: &Value, depth: usize) -> bool {
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) => true,
        Value::Number(number) => !number.is_f64(),
        Value::String(text) => text.len() <= MAX_JSON_STRING_BYTES,
        Value::Array(items) => {
            items.len() <= MAX_JSON_ITEMS && items.iter().all(|item| json_value(item, depth + 1))
        }
        Value::Object(map) => {
            map.len() <= MAX_JSON_ITEMS && map.values().all(|item| json_value(item, depth + 1))
        }
    }
}

/// YAML's printable set; a reader error otherwise.
fn printable(ch: char) -> bool {
    matches!(ch,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{7e}' | '\u{85}' | '\u{a0}'..='\u{d7ff}'
        | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

/// The value the strict YAML loader reads from `value`'s canonical JSON text,
/// counting scanner tokens into `tokens`; `None` where the loader refuses it.
fn loaded(value: &Value, depth: usize, tokens: &mut usize) -> Option<Value> {
    if *tokens > MAX_YAML_TOKENS {
        return None;
    }
    match value {
        Value::Object(map) => {
            let depth = container(depth, map.len(), tokens)?;
            let mut out = Map::new();
            for (key, item) in map {
                // Key, the key's scalar and value indicator.
                *tokens += 3;
                out.insert(simple_key(key)?, loaded(item, depth, tokens)?);
            }
            Some(Value::Object(out))
        }
        Value::Array(items) => {
            let depth = container(depth, items.len(), tokens)?;
            let items = items.iter().map(|item| loaded(item, depth, tokens));
            Some(Value::Array(items.collect::<Option<_>>()?))
        }
        Value::String(text) => {
            *tokens += 1;
            let folded = folded(text)?;
            (folded.chars().count() <= MAX_SCALAR_CHARS).then_some(Value::String(folded))
        }
        Value::Number(number) => {
            *tokens += 1;
            let digits = number.to_string();
            let digits = digits.strip_prefix('-').unwrap_or(&digits);
            (digits.len() <= MAX_PLAIN_INTEGER_DIGITS).then(|| value.clone())
        }
        Value::Null | Value::Bool(_) => {
            *tokens += 1;
            Some(value.clone())
        }
    }
}

/// Counts a flow collection's start, end and entry separators.
fn container(depth: usize, len: usize, tokens: &mut usize) -> Option<usize> {
    *tokens += 2 + len.saturating_sub(1);
    (depth < MAX_YAML_DEPTH).then_some(depth + 1)
}

/// A mapping key as the loader reads it. A key cannot span lines or run past
/// the simple-key limit, so it is never folded; `<<` is a refused merge key.
fn simple_key(key: &str) -> Option<String> {
    let span = 2 + key.chars().map(escaped_len).sum::<usize>();
    (!key.contains(BREAKS) && span <= MAX_SIMPLE_KEY_SPAN && key != "<<").then(|| key.to_owned())
}

/// Characters `ch` takes in canonical JSON text.
fn escaped_len(ch: char) -> usize {
    match ch {
        '"' | '\\' | '\u{8}' | '\t' | '\n' | '\u{c}' | '\r' => 2,
        '\0'..='\u{1f}' => 6,
        _ => 1,
    }
}

/// A double-quoted scalar's value after YAML line folding. Canonical JSON
/// escapes every break but NEL, LS and PS, and leaves only spaces raw.
fn folded(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch != ' ' && !BREAKS.contains(&ch) {
            out.push(ch);
            index += 1;
            continue;
        }
        let mut next = index;
        while chars.get(next) == Some(&' ') {
            next += 1;
        }
        let Some(&found) = chars.get(next).filter(|ch| BREAKS.contains(*ch)) else {
            out.extend(&chars[index..next]);
            index = next;
            continue;
        };
        next += 1;
        let mut breaks = Vec::new();
        loop {
            if separator_at(&chars, next) {
                return None;
            }
            while chars.get(next) == Some(&' ') {
                next += 1;
            }
            match chars.get(next) {
                Some(&ch) if BREAKS.contains(&ch) => {
                    breaks.push(line_break(ch));
                    next += 1;
                }
                _ => break,
            }
        }
        match line_break(found) {
            '\n' if breaks.is_empty() => out.push(' '),
            '\n' => {}
            other => out.push(other),
        }
        out.extend(breaks);
        index = next;
    }
    Some(out)
}

fn line_break(ch: char) -> char {
    if ch == '\u{85}' {
        '\n'
    } else {
        ch
    }
}

/// A `---` or `...` document marker starting a continuation line.
fn separator_at(chars: &[char], index: usize) -> bool {
    let marker = chars.get(index..index + 3);
    matches!(marker, Some(['-', '-', '-'] | ['.', '.', '.']))
        && chars
            .get(index + 3)
            .is_some_and(|ch| *ch == ' ' || BREAKS.contains(ch))
}

/// The policy parser's checks, then its ordered mapping of the document.
fn validated_document(value: &Value, deadline: Instant) -> Option<Value> {
    let bounds = query(
        "validate_bounds",
        &json!({ "claim": claim(value) }),
        deadline,
    )?;
    if !bounds.is_null() || !satisfies_policy_document_schema(value)? || !value.is_object() {
        return None;
    }
    for name in ["bounds", "validate_ids", "validate_timestamps"] {
        if !query(name, &json!({ "value": value }), deadline)?.is_null() {
            return None;
        }
    }
    if !command_expressions_valid(value, deadline)? {
        return None;
    }
    let input = json!({ "class_name": DOCUMENT_CLASS, "value": value });
    let dto = query("from_mapping_dto", &input, deadline)?;
    let input = json!({ "class_name": DOCUMENT_CLASS, "dto": dto });
    let mapping = ordered(&query("to_mapping_ordered", &input, deadline)?)?;
    mapping.is_object().then_some(mapping)
}

/// Whether every command expression the document carries compiles.
fn command_expressions_valid(value: &Value, deadline: Instant) -> Option<bool> {
    let rules = query("command_expressions", &json!({ "value": value }), deadline)?;
    let rules = rules.as_object()?;
    if rules.contains_key("invalid") {
        return Some(false);
    }
    let carried = rules.get("expressions")?.as_array()?;
    if rules.len() != 1 || carried.len() > COMMAND_EXPRESSION_VALIDATION_MAX_EXPRESSIONS {
        return None;
    }
    for rule in carried {
        let expression = rule.get("expression")?.clone();
        let expression: CommandExpressionV1 = serde_json::from_value(expression).ok()?;
        if validate_expression(&expression).is_err() {
            return Some(false);
        }
    }
    Some(true)
}

/// The claim framing `validate_bounds` reads: text as UTF-32LE, containers
/// in order, and every other scalar opaque.
fn claim(value: &Value) -> Value {
    match value {
        Value::String(text) => {
            let units: Vec<u8> = text
                .chars()
                .flat_map(|ch| u32::from(ch).to_le_bytes())
                .collect();
            json!(["text", Base64::encode_string(&units)])
        }
        Value::Array(items) => json!(["list", items.iter().map(claim).collect::<Vec<_>>()]),
        Value::Object(map) => {
            let pairs: Vec<Value> = map
                .iter()
                .map(|(key, item)| json!([claim(&Value::String(key.clone())), claim(item)]))
                .collect();
            json!(["mapping", pairs])
        }
        _ => json!(["scalar", null]),
    }
}

/// Decodes the `{"object": [[key, value]]}` / `{"array": [...]}` framing.
fn ordered(value: &Value) -> Option<Value> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Some(value.clone()),
        Value::Number(number) => (!number.is_f64()).then(|| value.clone()),
        Value::Object(frame) if frame.len() == 1 => {
            if let Some(Value::Array(pairs)) = frame.get("object") {
                let mut out = Map::new();
                for pair in pairs {
                    let [Value::String(key), item] = pair.as_array()?.as_slice() else {
                        return None;
                    };
                    if out.insert(key.clone(), ordered(item)?).is_some() {
                        return None;
                    }
                }
                Some(Value::Object(out))
            } else if let Some(Value::Array(items)) = frame.get("array") {
                Some(Value::Array(
                    items.iter().map(ordered).collect::<Option<_>>()?,
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// One policy-document query's `ok` answer; an error answers `None`.
fn query(name: &str, input: &Value, deadline: Instant) -> Option<Value> {
    match guard_command::policy_document::evaluate(name, input, deadline).ok()? {
        Value::Object(mut answer) if answer.len() == 1 => answer.remove("ok"),
        _ => None,
    }
}
