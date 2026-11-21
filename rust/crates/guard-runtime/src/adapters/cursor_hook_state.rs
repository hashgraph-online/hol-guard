//! `runner_authority` kind `cursor_hook_state`: whether Guard's Cursor hooks
//! still protect this machine, the verdict `cursor_native_hook_state` reports.
//!
//! Python checks the native bridge, resolves the attested Guard CLI, renders
//! the expected hook script and each managed hook entry, and reads the state
//! file, both hook scripts and `hooks.json`. This kind walks the original
//! checks in their original order over what Python read and rendered.
//!
//! A read or render that raised in Python is sent as `false`. When the walk
//! reaches it the answer is `{"raise": label}` and Python raises the error it
//! kept, so an error surfaces only where the original surfaced it.
//!
//! Values compare the way Python's `==` compares the decoded JSON: `1`, `1.0`
//! and `true` are equal. Python's decoder also accepted `NaN`, `Infinity` and
//! lone surrogate escapes; such a document reads as unparseable here, which
//! only ever reports protection inactive.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::cursor_hook_config::SUPPORTED_EVENTS;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

/// `_MANAGED_HOOK_EVENTS`, in the order the original checked them.
const MANAGED_EVENTS: [&str; 6] = [
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "preToolUse",
    "afterShellExecution",
    "afterMCPExecution",
];
const KEYS: [&str; 6] = [
    "source",
    "identity",
    "state_text",
    "scripts",
    "hooks_text",
    "entries",
];
/// The live script under the Cursor home, then Guard's managed copy.
const SCRIPT_LABELS: [&str; 2] = ["script", "managed_script"];
const HOOKS_LABEL: &str = "hooks";

/// One read or render Python performed.
enum Observed<T> {
    /// The read failed the way the original treated as absent.
    Missing,
    /// The read or render raised; Python keeps the error.
    Raised,
    Read(T),
}

/// A hook script as read back: whether `lstat` saw a regular file, and its text.
type Script<'a> = Observed<(bool, &'a str)>;
/// Each managed event's expected entry, `None` where rendering it raised.
type Entries<'a> = Vec<Option<&'a Value>>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    if fields.len() != KEYS.len() || !KEYS.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let source = fields["source"].as_str().ok_or(ERR_INVALID)?;
    let state_text = match &fields["state_text"] {
        Value::Null => None,
        Value::String(text) => Some(text.as_str()),
        _ => return Err(ERR_INVALID),
    };
    let scripts = scripts(&fields["scripts"])?;
    let hooks_text = observed(&fields["hooks_text"], Value::as_str)?;
    let entries = entries(&fields["entries"])?;
    Ok(verdict(
        source,
        &fields["identity"],
        state_text,
        &scripts,
        &hooks_text,
        &entries,
    ))
}

fn observed<'a, T>(
    value: &'a Value,
    read: impl Fn(&'a Value) -> Option<T>,
) -> Result<Observed<T>, &'static str> {
    match value {
        Value::Null => Ok(Observed::Missing),
        Value::Bool(false) => Ok(Observed::Raised),
        other => read(other).map(Observed::Read).ok_or(ERR_INVALID),
    }
}

fn script(value: &Value) -> Option<(bool, &str)> {
    let fields = value.as_object()?;
    if fields.len() != 2 {
        return None;
    }
    let regular = fields.get("regular")?.as_bool()?;
    Some((regular, fields.get("text")?.as_str()?))
}

fn scripts(value: &Value) -> Result<Vec<Script<'_>>, &'static str> {
    let list = value.as_array().ok_or(ERR_INVALID)?;
    if list.len() != SCRIPT_LABELS.len() {
        return Err(ERR_INVALID);
    }
    list.iter().map(|item| observed(item, script)).collect()
}

fn entries(value: &Value) -> Result<Entries<'_>, &'static str> {
    let fields = value.as_object().ok_or(ERR_INVALID)?;
    if fields.len() != MANAGED_EVENTS.len() {
        return Err(ERR_INVALID);
    }
    MANAGED_EVENTS
        .iter()
        .map(|event| match fields.get(*event) {
            Some(Value::Bool(false)) => Ok(None),
            Some(entry @ Value::Object(_)) => Ok(Some(entry)),
            _ => Err(ERR_INVALID),
        })
        .collect()
}

fn inactive(status: &str, reason: &str) -> Value {
    json!({ "integrity_status": status, "reason": reason })
}

fn raised(label: &str) -> Value {
    json!({ "raise": label })
}

fn parse(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok()
}

/// The original checks, first failure wins.
fn verdict(
    source: &str,
    identity: &Value,
    state_text: Option<&str>,
    scripts: &[Script<'_>],
    hooks_text: &Observed<&str>,
    entries: &[Option<&Value>],
) -> Value {
    let Some(state) = state_text.and_then(parse) else {
        return inactive("missing", "guard_cursor_hook_state_missing");
    };
    let Some(state) = state.as_object() else {
        return inactive("tampered", "guard_cursor_cli_identity_mismatch");
    };
    if !py_eq(
        state.get("guard_cli_identity").unwrap_or(&Value::Null),
        identity,
    ) {
        return inactive("tampered", "guard_cursor_cli_identity_mismatch");
    }
    let digest = hex::encode(Sha256::digest(source.as_bytes()));
    if state.get("hook_script_sha256").and_then(Value::as_str) != Some(digest.as_str()) {
        return inactive("stale", "guard_cursor_hook_script_identity_stale");
    }
    for (label, observation) in SCRIPT_LABELS.iter().zip(scripts) {
        match observation {
            Observed::Raised => return raised(label),
            Observed::Missing => return inactive("missing", "guard_cursor_hook_script_missing"),
            Observed::Read((regular, text)) => {
                if !*regular || *text != source {
                    return inactive("tampered", "guard_cursor_hook_script_tampered");
                }
            }
        }
    }
    let document = match hooks_text {
        Observed::Raised => return raised(HOOKS_LABEL),
        Observed::Missing => None,
        Observed::Read(text) => parse(text),
    };
    let Some(Value::Object(document)) = document else {
        return inactive("missing", "guard_cursor_hook_registration_missing");
    };
    registration(&document, entries)
}

/// The `hooks` object of a parsed `hooks.json` against each managed entry.
fn registration(document: &Map<String, Value>, entries: &[Option<&Value>]) -> Value {
    let mismatch = || inactive("tampered", "guard_cursor_hook_registration_mismatch");
    let Some(hooks) = document.get("hooks").and_then(Value::as_object) else {
        return mismatch();
    };
    // Cursor ignores the whole file when it names an unknown event.
    if hooks
        .keys()
        .any(|event| !SUPPORTED_EVENTS.contains(&event.as_str()))
    {
        return inactive("tampered", "guard_cursor_hook_unsupported_event");
    }
    for (event, expected) in MANAGED_EVENTS.iter().zip(entries) {
        let Some(expected) = expected else {
            return raised(event);
        };
        let matching = hooks
            .get(*event)
            .and_then(Value::as_array)
            .map(|list| list.iter().filter(|entry| py_eq(entry, expected)).count());
        if matching != Some(1) {
            return mismatch();
        }
    }
    json!({ "integrity_status": "valid", "reason": null })
}

/// A JSON number or boolean as the Python value `json.loads` decodes it to.
enum PyNumber {
    Int(i128),
    Float(f64),
}

fn py_number(value: &Value) -> Option<PyNumber> {
    match value {
        Value::Bool(flag) => Some(PyNumber::Int(i128::from(*flag))),
        Value::Number(number) => {
            let text = number.to_string();
            if text.contains(['.', 'e', 'E']) {
                text.parse::<f64>().ok().map(PyNumber::Float)
            } else {
                text.parse::<i128>().ok().map(PyNumber::Int)
            }
        }
        _ => None,
    }
}

/// Python's exact comparison of an `int` with a `float`.
fn int_equals_float(int: i128, float: f64) -> bool {
    float.is_finite() && float.fract() == 0.0 && float.abs() < 1e38 && float as i128 == int
}

/// Python's `==` over two decoded JSON values.
fn py_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(l, r)| py_eq(l, r))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .all(|(key, value)| right.get(key).is_some_and(|other| py_eq(value, other)))
        }
        _ => match (py_number(left), py_number(right)) {
            (Some(PyNumber::Int(l)), Some(PyNumber::Int(r))) => l == r,
            (Some(PyNumber::Float(l)), Some(PyNumber::Float(r))) => l == r,
            (Some(PyNumber::Int(int)), Some(PyNumber::Float(float)))
            | (Some(PyNumber::Float(float)), Some(PyNumber::Int(int))) => {
                int_equals_float(int, float)
            }
            _ => left == right,
        },
    }
}
