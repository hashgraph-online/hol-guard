//! `inventory_contract_redaction` serializer half — the string and payload
//! safety net every exported inventory snapshot passes through.
//!
//! Three CPython behaviours decide the output and none is the Rust default:
//!
//! * `json.dumps(payload, sort_keys=True)` writes `", "`/`": "` separators and
//!   escapes every non-ASCII character, so the text the safety assertion scans
//!   is not `serde_json::to_string`. The quoting matters: `{"token": "abc"}`
//!   is accepted because `"` sits between the key and the colon, while
//!   `token = abc` inside one string is rejected.
//! * CPython `re` treats `\s`/`\S` as `Py_UNICODE_ISSPACE`, which covers
//!   U+001C..U+001F. Rust's `\s` follows Unicode `White_Space` and excludes
//!   them, so `bearer\u{1d}secret` would slip past a naive port.
//! * `isinstance(candidate, int)` accepts `bool`, and `str(True)` is `"True"`.
//!
//! The path half of the seam (`redact_local_path`, `_redact_known_path`,
//! `_redact_command_value`) lives in [`crate::inventory_path_redaction`], which
//! reuses the pattern classes below. Both halves export free functions rather
//! than an `InventoryRedactionApi` implementor until the resident operation
//! that carries a request's home, workspace and working directory lands. The
//! URL half below leans on [`crate::python_url`] for CPython's `urllib.parse`.
//!
//! `scripts/ci/generate_inventory_redaction_parity.py` records the corpus in
//! `testdata/inventory_redaction_parity.json` that pins every case below.

use std::borrow::Cow;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use regex::Regex;
use serde_json::{Map, Value};

use crate::inventory_fingerprints::{python_float_repr, python_json, DEFAULT_SEPARATORS};
use crate::python_netloc::ip_address_is_private;
use crate::python_url::{parse_qsl_keep_blank, urlencode, urlsplit, urlunsplit};

/// CPython `re` `\s`: Unicode `White_Space` plus the C0 separators Rust omits.
pub(crate) const PYTHON_SPACE_CLASS: &str = r"\s\x{1c}-\x{1f}";

/// CPython `re` `\w`: `str.isalnum()` plus `_`. Rust's `\w` also counts
/// combining marks, connector punctuation and Join_Control, so `\b` lands in
/// different places and a `\b`-anchored secret pattern would fail open on
/// `e\u{301}token=abc`. Spell the class out instead of using `\b`.
pub(crate) const PYTHON_WORD_CLASS: &str = r"\p{L}\p{N}_";

/// CPython `re.IGNORECASE` folds `\u{130}` and `\u{131}` onto `i`; Rust's
/// simple case folding leaves both alone, so `credent\u{131}al` or
/// `guard_l\u{131}ve_abc` would stay in the clear. Fold them before matching.
/// `\u{17f}` needs no help: Rust already folds it onto `s`, as CPython does.
fn fold_python_case_extras(value: &str) -> Cow<'_, str> {
    if !value.contains(['\u{130}', '\u{131}']) {
        return Cow::Borrowed(value);
    }
    Cow::Owned(
        value
            .chars()
            .map(|c| {
                if c == '\u{130}' || c == '\u{131}' {
                    'i'
                } else {
                    c
                }
            })
            .collect(),
    )
}

/// `_SERIALIZER_REDACTED_VALUE`.
pub const SERIALIZER_REDACTED_VALUE: &str = "[REDACTED]";

/// `_SAFE_SERIALIZED_MARKERS` — values the serializer already produced.
const SAFE_SERIALIZED_MARKERS: &[&str] = &[
    SERIALIZER_REDACTED_VALUE,
    "present_redacted",
    "present",
    "redacted",
    "malformed_url_redacted",
];

/// `_SENSITIVE_KEY_RE`. `(?i)` folds the negated class the same way CPython
/// does, so `api[^a-z0-9]?key` keeps rejecting `apiXkey`.
static SENSITIVE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(auth|authorization|bearer|token|secret|password|credential|api[^a-z0-9]?key)")
        .expect("sensitive key pattern")
});

/// `_SENSITIVE_VALUE_RE`, with `\s`/`\S` spelled out as `Py_UNICODE_ISSPACE`.
static SENSITIVE_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)(gh[pousr]_[a-z0-9_]+|sk-[a-z0-9_-]+|guard_live_[a-z0-9_-]+|bearer[{PYTHON_SPACE_CLASS}]+[^{PYTHON_SPACE_CLASS}]+)",
    ))
    .expect("sensitive value pattern")
});

/// `_SERIALIZER_UNSAFE_PATH_RE` over `_UNSAFE_PATH_MARKERS`.
static SERIALIZER_UNSAFE_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)(?:^|[{PYTHON_SPACE_CLASS}"'=:({{])(?:/Users/|/home/|/root/|\\Users\\|/var/folders/|/workspace/|/tmp/|/etc/|/mnt/)"#,
    ))
    .expect("unsafe path pattern")
});

/// `_SERIALIZER_SECRET_ASSIGNMENT_RE`. The `(?!redacted\b)` lookahead needs
/// `fancy-regex`; the `regex` crate cannot express it. Every `\b` is written
/// as a lookaround over CPython's word class for the reason given there.
static SERIALIZER_SECRET_ASSIGNMENT_RE: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(&format!(
        r"(?i)(?<![{PYTHON_WORD_CLASS}])(?:api[_-]?key|authorization|password|secret|token|access[_-]?token|refresh[_-]?token)(?![{PYTHON_WORD_CLASS}])[{PYTHON_SPACE_CLASS}]*[:=][{PYTHON_SPACE_CLASS}]*(?!redacted(?![{PYTHON_WORD_CLASS}]))[^{PYTHON_SPACE_CLASS}]+",
    ))
    .expect("secret assignment pattern")
});

/// A backtrack-limit error must not read as "no secret here", so an
/// undecidable match counts as a match.
fn matches_secret_assignment(value: &str) -> bool {
    SERIALIZER_SECRET_ASSIGNMENT_RE
        .is_match(&*fold_python_case_extras(value))
        .unwrap_or(true)
}

/// `_SENSITIVE_KEY_RE.search(key)` with CPython's case folding.
fn matches_sensitive_key(key: &str) -> bool {
    SENSITIVE_KEY_RE.is_match(&fold_python_case_extras(key))
}

/// `_SENSITIVE_VALUE_RE.search(value)` with CPython's case folding.
fn matches_sensitive_value(value: &str) -> bool {
    SENSITIVE_VALUE_RE.is_match(&fold_python_case_extras(value))
}

/// `_sanitize_serializer_string(value, *, parent_key="", parent_sensitive=False)`
pub fn sanitize_serializer_string(value: &str, parent_key: &str, parent_sensitive: bool) -> String {
    if SAFE_SERIALIZED_MARKERS.contains(&value) {
        return value.to_string();
    }
    if parent_sensitive || (!parent_key.is_empty() && matches_sensitive_key(parent_key)) {
        return SERIALIZER_REDACTED_VALUE.to_string();
    }
    if SERIALIZER_UNSAFE_PATH_RE.is_match(value)
        || matches_sensitive_value(value)
        || matches_secret_assignment(value)
    {
        return SERIALIZER_REDACTED_VALUE.to_string();
    }
    value.to_string()
}

/// `_safe_json(value, *, parent_key="", parent_sensitive=False)`.
///
/// `Path` inputs reach the Python function as `value.name`; the JSON mirror has
/// no `Path` variant, so callers project paths before they get here.
///
/// Two keys that redact to the same text collapse into one entry, as they do
/// in the Python dict comprehension. The surviving value is the later key in
/// sort order rather than in insertion order, because the mirror's object type
/// is already sorted; no producer emits two keys that collide this way.
pub fn safe_json(value: &Value, parent_key: &str, parent_sensitive: bool) -> Value {
    let key_sensitive =
        parent_sensitive || (!parent_key.is_empty() && matches_sensitive_key(parent_key));
    match value {
        Value::Object(entries) => {
            let mut projected = Map::new();
            for (key, item) in entries {
                projected.insert(
                    sanitize_serializer_string(key, "", false),
                    safe_json(item, key, key_sensitive),
                );
            }
            Value::Object(projected)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| safe_json(item, parent_key, parent_sensitive))
                .collect(),
        ),
        Value::String(text) => Value::String(sanitize_serializer_string(
            text,
            parent_key,
            parent_sensitive,
        )),
        other => other.clone(),
    }
}

/// `_assert_serialized_inventory_payload_safe(payload)`.
pub fn assert_serialized_inventory_payload_safe(payload: &Value) -> Result<(), String> {
    let encoded = python_json(payload, DEFAULT_SEPARATORS);
    if SERIALIZER_UNSAFE_PATH_RE.is_match(&encoded)
        || matches_sensitive_value(&encoded)
        || matches_secret_assignment(&encoded)
    {
        return Err("Inventory snapshot serialization produced unsafe payload.".to_string());
    }
    Ok(())
}

/// `_safe_source_detail(run)`.
///
/// `run` is the duck-typed scanner run the Python caller reads `status` and
/// `metadata` from. Every producer sets `status` to a string; the scalar
/// fallbacks below reproduce `str()` for the rest. A container `status` is
/// rendered with Python's `repr` punctuation, which matches CPython except for
/// format/private-use/surrogate/unassigned code points inside a string, where
/// reproducing `repr` would need Unicode category data this crate does not
/// carry.
pub fn safe_source_detail(run: &Map<String, Value>) -> String {
    let status = run
        .get("status")
        .map(python_str)
        .unwrap_or_else(|| "unknown".to_string());
    let finding_count = run
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("totalFindings"))
        .and_then(python_int_text);
    match finding_count {
        Some(count) => format!("status={status}, findings={count}"),
        None => format!("status={status}"),
    }
}

/// `isinstance(candidate, int)` — `True`/`False` are `int` in CPython, floats
/// are not.
fn python_int_text(value: &Value) -> Option<String> {
    match value {
        Value::Bool(true) => Some("True".to_string()),
        Value::Bool(false) => Some("False".to_string()),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some(number.to_string()),
        _ => None,
    }
}

/// `str(value)` for the scalars a mirrored attribute can hold.
fn python_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(number) => {
            if number.is_f64() {
                python_float_repr(number.as_f64().unwrap_or(0.0))
            } else {
                number.to_string()
            }
        }
        Value::String(text) => text.clone(),
        container => python_repr(container),
    }
}

/// `repr(value)` for the container shapes `str()` falls back to.
fn python_repr(value: &Value) -> String {
    match value {
        Value::String(text) => python_string_repr(text),
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(python_repr).collect();
            format!("[{}]", rendered.join(", "))
        }
        Value::Object(entries) => {
            let rendered: Vec<String> = entries
                .iter()
                .map(|(key, item)| format!("{}: {}", python_string_repr(key), python_repr(item)))
                .collect();
            format!("{{{}}}", rendered.join(", "))
        }
        scalar => python_str(scalar),
    }
}

/// `repr(str)`: single quotes unless the text needs them escaped and no double
/// quote is present.
fn python_string_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut rendered = String::new();
    rendered.push(quote);
    for character in value.chars() {
        match character {
            '\\' => rendered.push_str("\\\\"),
            '\t' => rendered.push_str("\\t"),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            _ if character == quote => {
                rendered.push('\\');
                rendered.push(character);
            }
            _ if character.is_control() || (character.is_whitespace() && character != ' ') => {
                let code = character as u32;
                if code <= 0xff {
                    rendered.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    rendered.push_str(&format!("\\u{code:04x}"));
                } else {
                    rendered.push_str(&format!("\\U{code:08x}"));
                }
            }
            _ => rendered.push(character),
        }
    }
    rendered.push(quote);
    rendered
}

/// `_MALFORMED_URL`, the value every `urlsplit` rejection collapses to.
const MALFORMED_URL_REDACTED: &str = "malformed_url_redacted";

/// `redact_headers(headers)` — the Python function reads only the keys, so the
/// port takes them directly.
///
/// Two keys that differ only in case collapse into one entry, as they do in
/// the Python dict comprehension. The sensitivity test is case-insensitive, so
/// the surviving value is the same either way.
pub fn redact_headers(header_names: &[String]) -> Vec<(String, String)> {
    let mut redacted: Vec<(String, String)> = Vec::new();
    for name in header_names {
        let key = name.to_lowercase();
        if redacted.iter().any(|(seen, _)| *seen == key) {
            continue;
        }
        let presence = if matches_sensitive_key(name) {
            "present_redacted"
        } else {
            "present"
        };
        redacted.push((key, presence.to_string()));
    }
    redacted
}

/// `redact_url(value)`.
///
/// The result keeps the scheme, host, port, path and fragment, drops userinfo
/// entirely (because the netloc is rebuilt from `hostname` and `port` alone),
/// and rewrites every query value whose name looks sensitive. A URL `urlsplit`
/// or `.port` rejects degrades to `malformed_url_redacted`, never to the
/// original text.
pub fn redact_url(value: &str) -> String {
    let Ok(parsed) = urlsplit(value) else {
        return MALFORMED_URL_REDACTED.to_string();
    };
    let hostname = parsed.hostname().unwrap_or_default();
    let mut netloc = if hostname.contains(':') && !hostname.starts_with('[') {
        format!("[{hostname}]")
    } else {
        hostname
    };
    // Python swallows the `ValueError` from `.port` and keeps the host, so an
    // out-of-range port drops off the export rather than redacting the URL.
    if let Ok(Some(port)) = parsed.port() {
        netloc = format!("{netloc}:{port}");
    }
    // `;` is a legacy query separator that `parse_qsl` no longer splits on, so
    // the caller rewrites it before parsing.
    let redacted_pairs: Vec<(String, String)> =
        parse_qsl_keep_blank(&parsed.query.replace(';', "&"))
            .into_iter()
            .map(|(key, item)| {
                let item = if matches_sensitive_key(&key) {
                    "redacted".to_string()
                } else {
                    item
                };
                (key, item)
            })
            .collect();
    urlunsplit(
        &parsed.scheme,
        &netloc,
        &parsed.path,
        &urlencode(&redacted_pairs),
        &parsed.fragment,
    )
}

/// `classify_endpoint_host(value)`.
///
/// A URL `urlsplit` rejects is classified `remote_public`, the conservative
/// answer: an endpoint nobody can prove is local is treated as leaving the
/// machine.
pub fn classify_endpoint_host(value: Option<&str>) -> &'static str {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return "none";
    };
    let Ok(parsed) = urlsplit(value) else {
        return "remote_public";
    };
    let host = parsed.hostname().unwrap_or_default().to_lowercase();
    if matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") {
        return "local_loopback";
    }
    if ip_address_is_private(&host) == Some(true) {
        return "local_private";
    }
    "remote_public"
}

#[cfg(test)]
#[path = "inventory_redaction_tests.rs"]
mod tests;
