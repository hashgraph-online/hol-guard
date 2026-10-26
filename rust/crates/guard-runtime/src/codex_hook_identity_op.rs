//! `CodexHookIdentity` - resident op deriving a Codex hook's canonical
//! identity.
//!
//! Two hooks are the same hook when their definitions agree, whatever file
//! format spelled them and whatever coordinate they sit at today. That
//! judgement is a digest over a canonical form of the definition, and it
//! decides whether an approval the user already gave still applies, so it is
//! derived here rather than anywhere a caller might drift from.
//!
//! The canonical form is the one the Python source produced: mappings sorted
//! by key, a command reduced to its argv when its tokenization is provably
//! uncomplicated, floats that happen to be whole written as integers, and the
//! whole payload hashed as CPython's `json.dumps(..., sort_keys=True,
//! separators=(",", ":"), ensure_ascii=False)` writes it.

use std::collections::BTreeMap;

use guard_contracts::{
    python_float_repr, write_json_string_utf8, CodexHookIdentityEntryV1,
    CodexHookIdentityRequestV1, CodexHookIdentityResultV1, CODEX_HOOK_IDENTITY_MAX_BYTES,
    CODEX_HOOK_IDENTITY_MAX_ENTRIES, CODEX_HOOK_IDENTITY_REQUEST_SCHEMA,
    CODEX_HOOK_IDENTITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::package_authority_op::request_digest_with_limit;

/// The schema every identity payload names, as the Python source spells it.
const IDENTITY_SCHEMA: &str = "codex-hook-identity-v1";
/// The characters whose presence means a command's tokenization is not
/// provably uncomplicated, matching `_SHELL_SENSITIVE_COMMAND_RE`.
const SHELL_SENSITIVE: [char; 23] = [
    '\\', '\'', '"', '`', '$', '|', '&', ';', '<', '>', '(', ')', '{', '}', '[', ']', '*', '?',
    '!', '~', '#', '\r', '\n',
];

pub(crate) fn evaluate_codex_hook_identity_request(
    request: &CodexHookIdentityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, CODEX_HOOK_IDENTITY_MAX_BYTES)
        .map_err(|_| "native_codex_hook_identity_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate_request(request))),
    };
    crate::encode_response(&CodexHookIdentityResultV1 {
        schema: CODEX_HOOK_IDENTITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &CodexHookIdentityRequestV1) -> Option<&'static str> {
    if request.schema != CODEX_HOOK_IDENTITY_REQUEST_SCHEMA {
        return Some("native_codex_hook_identity_schema_mismatch");
    }
    if request.entries.len() > CODEX_HOOK_IDENTITY_MAX_ENTRIES {
        return Some("native_codex_hook_identity_too_many_entries");
    }
    if request
        .entries
        .iter()
        .any(|entry| !entry_is_well_formed(entry))
    {
        return Some("native_codex_hook_identity_entry_invalid");
    }
    None
}

/// Whether an entry carries what its kind needs.
///
/// A malformed entry is refused for the whole batch rather than answered with
/// a placeholder: the Python source would have raised on it, and an identity
/// nobody can derive must not come back looking like one that was.
fn entry_is_well_formed(entry: &CodexHookIdentityEntryV1) -> bool {
    match entry.kind.as_str() {
        "handler" => {
            entry.group.as_ref().is_some_and(Value::is_object)
                && entry.handler.as_ref().is_some_and(Value::is_object)
        }
        "group" | "conflict" => entry.group.as_ref().is_some_and(Value::is_object),
        "argv" => true,
        _ => false,
    }
}

/// One answer per requested entry, in the request's order.
pub(crate) fn evaluate_request(request: &CodexHookIdentityRequestV1) -> Value {
    let tokens = &request.scalar_tokens;
    let empty = Map::new();
    let identities: Vec<Value> = request
        .entries
        .iter()
        .map(|entry| match entry.kind.as_str() {
            "handler" => json!({ "digest": handler_identity(entry, &empty, tokens) }),
            "group" => json!({ "digest": group_identity(entry, &empty, tokens) }),
            "conflict" => json!({ "digests": conflict_keys(entry, &empty, tokens) }),
            _ => json!({ "argv": canonical_command_argv(entry.command.as_deref()) }),
        })
        .collect();
    json!({ "identities": identities })
}

/// One format- and coordinate-independent handler identity.
fn handler_identity(
    entry: &CodexHookIdentityEntryV1,
    empty: &Map<String, Value>,
    tokens: &BTreeMap<String, Value>,
) -> String {
    let group = object_of(entry.group.as_ref(), empty);
    let handler = object_of(entry.handler.as_ref(), empty);
    canonical_digest(&Canon::Obj(vec![
        ("schema".to_owned(), Canon::Str(IDENTITY_SCHEMA.to_owned())),
        (
            "source_scope".to_owned(),
            Canon::Str(entry.source_scope.clone()),
        ),
        (
            "source_hooks_enabled".to_owned(),
            Canon::Bool(entry.source_hooks_enabled),
        ),
        ("event".to_owned(), Canon::Str(entry.event_name.clone())),
        ("matcher".to_owned(), matcher_of(group, tokens)),
        (
            "group".to_owned(),
            canonical_mapping(group, &["hooks", "matcher"], tokens),
        ),
        ("handler".to_owned(), canonical_handler(handler, tokens)),
    ]))
}

/// A canonical identity for one complete matcher group.
fn group_identity(
    entry: &CodexHookIdentityEntryV1,
    empty: &Map<String, Value>,
    tokens: &BTreeMap<String, Value>,
) -> String {
    let group = object_of(entry.group.as_ref(), empty);
    let raw_handlers = group.get("hooks");
    let handlers = match raw_handlers {
        Some(Value::Array(items)) => Canon::Arr(
            items
                .iter()
                .map(|item| match item {
                    Value::Object(handler) => canonical_handler(handler, tokens),
                    other => canonical_value(other, tokens),
                })
                .collect(),
        ),
        Some(other) => canonical_value(other, tokens),
        None => Canon::Null,
    };
    canonical_digest(&Canon::Obj(vec![
        (
            "schema".to_owned(),
            Canon::Str(format!("{IDENTITY_SCHEMA}:group")),
        ),
        (
            "source_scope".to_owned(),
            Canon::Str(entry.source_scope.clone()),
        ),
        (
            "source_hooks_enabled".to_owned(),
            Canon::Bool(entry.source_hooks_enabled),
        ),
        ("event".to_owned(), Canon::Str(entry.event_name.clone())),
        ("matcher".to_owned(), matcher_of(group, tokens)),
        (
            "group".to_owned(),
            canonical_mapping(group, &["hooks", "matcher"], tokens),
        ),
        ("handlers".to_owned(), handlers),
    ]))
}

/// The handler slots whose differing definitions must not be collapsed.
fn conflict_keys(
    entry: &CodexHookIdentityEntryV1,
    empty: &Map<String, Value>,
    tokens: &BTreeMap<String, Value>,
) -> Vec<String> {
    let group = object_of(entry.group.as_ref(), empty);
    let Some(Value::Array(items)) = group.get("hooks") else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| match item {
            Value::Object(handler) => Some(handler),
            _ => None,
        })
        .map(|handler| {
            canonical_digest(&Canon::Obj(vec![
                (
                    "schema".to_owned(),
                    Canon::Str(format!("{IDENTITY_SCHEMA}:conflict")),
                ),
                (
                    "source_scope".to_owned(),
                    Canon::Str(entry.source_scope.clone()),
                ),
                (
                    "source_hooks_enabled".to_owned(),
                    Canon::Bool(entry.source_hooks_enabled),
                ),
                ("event".to_owned(), Canon::Str(entry.event_name.clone())),
                ("matcher".to_owned(), matcher_of(group, tokens)),
                (
                    "handler_type".to_owned(),
                    optional_value(handler.get("type"), tokens),
                ),
                ("command".to_owned(), command_field(handler, tokens)),
            ]))
        })
        .collect()
}

/// Only commands whose shell tokenization is provably uncomplicated.
///
/// `shlex.split` with `posix=True` splits on runs of space, tab, carriage
/// return and newline. The sensitive-character class above rejects every
/// quoting, escaping and expansion form along with the last two of those, so
/// what is left tokenizes by splitting on spaces and tabs and can never raise.
pub(crate) fn canonical_command_argv(command: Option<&str>) -> Option<Vec<String>> {
    let command = command?;
    if command.contains(&SHELL_SENSITIVE[..]) {
        return None;
    }
    let argv: Vec<String> = command
        .split([' ', '\t'])
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect();
    (!argv.is_empty()).then_some(argv)
}

/// The canonical form of one handler: its own keys, with `command` replaced by
/// the command block and always present.
fn canonical_handler(handler: &Map<String, Value>, tokens: &BTreeMap<String, Value>) -> Canon {
    let Canon::Obj(mut values) = canonical_mapping(handler, &["command"], tokens) else {
        unreachable!("canonical_mapping always answers an object")
    };
    values.push(("command".to_owned(), command_field(handler, tokens)));
    Canon::Obj(values)
}

/// A handler's `command`, as a command block when it is plain text and as an
/// ordinary canonical value otherwise.
fn command_field(handler: &Map<String, Value>, tokens: &BTreeMap<String, Value>) -> Canon {
    match handler.get("command") {
        Some(Value::String(text)) if !tokens.contains_key(text) => canonical_command(text),
        other => optional_value(other, tokens),
    }
}

/// A command as argv when that is provable, and as its own text otherwise.
fn canonical_command(command: &str) -> Canon {
    match canonical_command_argv(Some(command)) {
        Some(argv) => Canon::Obj(vec![
            ("mode".to_owned(), Canon::Str("argv".to_owned())),
            (
                "argv".to_owned(),
                Canon::Arr(argv.into_iter().map(Canon::Str).collect()),
            ),
        ]),
        None => Canon::Obj(vec![
            ("mode".to_owned(), Canon::Str("shell".to_owned())),
            ("text".to_owned(), Canon::Str(command.to_owned())),
        ]),
    }
}

/// The group's matcher, or null when it carries none.
fn matcher_of(group: &Map<String, Value>, tokens: &BTreeMap<String, Value>) -> Canon {
    optional_value(group.get("matcher"), tokens)
}

/// `Mapping.get` semantics: an absent key is `None`, which canonicalizes to
/// null rather than being left out.
fn optional_value(value: Option<&Value>, tokens: &BTreeMap<String, Value>) -> Canon {
    value.map_or(Canon::Null, |value| canonical_value(value, tokens))
}

/// Every key but the excluded ones, canonicalized and sorted.
fn canonical_mapping(
    value: &Map<String, Value>,
    excluded_keys: &[&str],
    tokens: &BTreeMap<String, Value>,
) -> Canon {
    let mut items: Vec<(String, Canon)> = value
        .iter()
        .filter(|(key, _)| !excluded_keys.contains(&key.as_str()))
        .map(|(key, item)| (key.clone(), canonical_value(item, tokens)))
        .collect();
    items.sort_by(|left, right| left.0.cmp(&right.0));
    Canon::Obj(items)
}

/// One value in its canonical form.
///
/// A string the request listed in `scalar_tokens` stands in for a scalar JSON
/// could not carry, and the canonical form the Python source would have given
/// that scalar is what the request sent alongside it.
fn canonical_value(value: &Value, tokens: &BTreeMap<String, Value>) -> Canon {
    match value {
        Value::Null => Canon::Null,
        Value::Bool(flag) => Canon::Bool(*flag),
        Value::Number(number) => canonical_number(number),
        Value::String(text) => match tokens.get(text) {
            Some(scalar) => canonical_scalar(scalar),
            None => Canon::Str(text.clone()),
        },
        Value::Array(items) => Canon::Arr(
            items
                .iter()
                .map(|item| canonical_value(item, tokens))
                .collect(),
        ),
        Value::Object(entries) => canonical_mapping(entries, &[], tokens),
    }
}

/// What a token stood in for.
///
/// An integer too wide for a JSON number travels as its decimal digits, since
/// the canonical form of a Python integer is the integer itself and reading it
/// back through a float would drop its low digits. Every other scalar already
/// canonicalizes to a mapping, so it is read as one.
fn canonical_scalar(scalar: &Value) -> Canon {
    match scalar {
        Value::Object(fields) if fields.len() == 1 => match fields.get("__int__") {
            Some(Value::String(digits)) => Canon::Int(digits.clone()),
            _ => canonical_value(scalar, &BTreeMap::new()),
        },
        _ => canonical_value(scalar, &BTreeMap::new()),
    }
}

/// An integer stays one; a float that happens to be whole becomes one, as
/// `int(value)` does, and any other float keeps its own repr.
fn canonical_number(number: &serde_json::Number) -> Canon {
    if let Some(value) = number.as_i64() {
        return Canon::Int(value.to_string());
    }
    if let Some(value) = number.as_u64() {
        return Canon::Int(value.to_string());
    }
    let Some(value) = number.as_f64() else {
        return Canon::Null;
    };
    if value.fract() == 0.0 {
        return Canon::Int(whole_float_digits(value));
    }
    Canon::Float(value)
}

/// The exact decimal digits of a float with no fractional part, as CPython's
/// `int()` writes them for any magnitude.
fn whole_float_digits(value: f64) -> String {
    let bits = value.to_bits();
    let raw_exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & 0x000f_ffff_ffff_ffff;
    let (mut mantissa, mut exponent) = if raw_exponent == 0 {
        (fraction, -1074_i32)
    } else {
        (fraction | 1 << 52, raw_exponent - 1075)
    };
    while exponent < 0 {
        mantissa >>= 1;
        exponent += 1;
    }
    let mut digits: Vec<u8> = Vec::new();
    let mut rest = mantissa;
    while rest > 0 {
        digits.push((rest % 10) as u8);
        rest /= 10;
    }
    for _ in 0..exponent {
        let mut carry = 0_u8;
        for digit in &mut digits {
            let doubled = *digit * 2 + carry;
            *digit = doubled % 10;
            carry = doubled / 10;
        }
        if carry > 0 {
            digits.push(carry);
        }
    }
    if digits.is_empty() {
        return "0".to_owned();
    }
    let mut text = String::with_capacity(digits.len() + 1);
    if value < 0.0 {
        text.push('-');
    }
    for digit in digits.iter().rev() {
        text.push(char::from(b'0' + digit));
    }
    text
}

/// The group or handler mapping an entry carries. `refusal` has already proven
/// it is an object for every kind that reads one, so the empty stand-in is
/// unreachable rather than a silent default.
fn object_of<'a>(
    value: Option<&'a Value>,
    empty: &'a Map<String, Value>,
) -> &'a Map<String, Value> {
    match value {
        Some(Value::Object(entries)) => entries,
        _ => empty,
    }
}

/// A canonical value, in the shape CPython's `json.dumps` writes.
///
/// `serde_json::Value` cannot hold an integer wider than 64 bits and writes
/// floats its own way, so the canonical form is carried here instead and
/// written by `write_canon` below.
#[derive(Debug, Clone, PartialEq)]
enum Canon {
    Null,
    Bool(bool),
    Int(String),
    Float(f64),
    Str(String),
    Arr(Vec<Canon>),
    Obj(Vec<(String, Canon)>),
}

/// SHA-256 over the payload as `json.dumps(..., sort_keys=True,
/// separators=(",", ":"), ensure_ascii=False)` encodes it.
fn canonical_digest(payload: &Canon) -> String {
    let mut out = Vec::new();
    write_canon(payload, &mut out);
    hex::encode(Sha256::digest(&out))
}

fn write_canon(value: &Canon, out: &mut Vec<u8>) {
    match value {
        Canon::Null => out.extend_from_slice(b"null"),
        Canon::Bool(true) => out.extend_from_slice(b"true"),
        Canon::Bool(false) => out.extend_from_slice(b"false"),
        Canon::Int(digits) => out.extend_from_slice(digits.as_bytes()),
        Canon::Float(number) => out.extend_from_slice(python_float_repr(*number).as_bytes()),
        Canon::Str(text) => write_json_string_utf8(text, out),
        Canon::Arr(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canon(item, out);
            }
            out.push(b']');
        }
        Canon::Obj(entries) => {
            let mut sorted: Vec<&(String, Canon)> = entries.iter().collect();
            sorted.sort_by(|left, right| left.0.cmp(&right.0));
            out.push(b'{');
            for (index, (key, item)) in sorted.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_string_utf8(key, out);
                out.push(b':');
                write_canon(item, out);
            }
            out.push(b'}');
        }
    }
}

#[cfg(test)]
#[path = "codex_hook_identity_op_tests.rs"]
mod tests;
