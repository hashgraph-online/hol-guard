//! CPython-exact MCP argument redaction for runtime proxy surfaces.
//!
//! Three legacy functions are ported here byte-for-byte:
//!
//! - `mcp_safe_arguments` mirrors
//!   `proxy/runtime_mcp.py::_safe_mcp_arguments` — mapping keys whose
//!   casefolded, alnum-filtered form contains a secret fragment collapse to
//!   `"*****"`; every surviving string passes through `mcp_redact_scalar`
//!   (the legacy `_redact_mcp_scalar`). Non-string leaf values pass through
//!   unchanged.
//! - `mcp_redact_scalar` mirrors `_redact_mcp_scalar` — URLs with a real
//!   scheme/netloc/query redact secret-shaped query keys, then the surviving
//!   text passes through `redact_json` (the stdio-layer `_redact_json`).
//! - `redact_json` mirrors `proxy/stdio.py::_redact_json`, which
//!   `remote.py` and `stdio.py` use for recorded traffic. Its fragment sets
//!   differ from the mcp-layer tables on purpose — both are preserved.
//!
//! `urlsplit` rejections surface as `Err(String)` carrying the Python
//! `ValueError` message: the Python originals let that exception propagate
//! to their callers, so callers treat this as an input-boundary failure
//! rather than availability loss.
//!
//! Casefold parity uses `caseless` (Unicode full case folding, UCD 16) so
//! the same keys CPython `str.casefold()` exposes as secret-shaped are
//! caught here.

use serde_json::{Map, Value};

use crate::cloud_audit_sync::{urlsplit, urlunsplit};
use crate::command_option_parsing::python_is_alphanumeric;
use crate::local_supply_chain::{parse_qsl, urlencode};

/// `_SECRET_ARGUMENT_KEY_FRAGMENTS` in `proxy/runtime_mcp.py`.
const SECRET_ARGUMENT_KEY_FRAGMENTS: &[&str] = &[
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
];

/// `_redact_scalar` substring gate in `proxy/stdio.py` (input lowercased).
const SCALAR_SECRET_FRAGMENTS: &[&str] =
    &["authorization", "api-key", "bearer ", "token", "secret"];

/// Query-pair secret fragments in stdio `_redact_json` (key lowercased).
const QUERY_SECRET_FRAGMENTS: &[&str] = &["key", "token", "auth", "secret"];

/// Mapping-key secret fragments in stdio `_redact_json` (key lowercased).
const MAP_KEY_SECRET_FRAGMENTS: &[&str] = &["authorization", "api-key", "token", "secret"];

const REDACTED: &str = "*****";

/// `_secret_shaped_argument_key` — casefold the key, drop non-alphanumeric
/// characters (Python `str.isalnum()`, Unicode Letter/Number), then test
/// the secret fragments.
pub fn secret_shaped_argument_key(key: &str) -> bool {
    let folded = caseless::default_case_fold_str(key);
    let normalized: String = folded
        .chars()
        .filter(|character| python_is_alphanumeric(*character))
        .collect();
    SECRET_ARGUMENT_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

/// `_redact_mcp_scalar` — URL query redaction for secret-shaped keys, then
/// `_redact_json` on the resulting text.
pub fn mcp_redact_scalar(value: &str) -> Result<String, String> {
    let parsed = urlsplit(value)?;
    let mut rendered = value.to_owned();
    if !parsed.scheme.is_empty() && !parsed.netloc.is_empty() && !parsed.query.is_empty() {
        let query: Vec<(String, String)> = parse_qsl(&parsed.query)
            .into_iter()
            .map(|(key, item)| {
                if secret_shaped_argument_key(&key) {
                    (key, REDACTED.to_owned())
                } else {
                    (key, item)
                }
            })
            .collect();
        rendered = urlunsplit(
            &parsed.scheme,
            &parsed.netloc,
            &parsed.path,
            &urlencode(&query),
            &parsed.fragment,
        );
    }
    match redact_json(&Value::String(rendered))? {
        Value::String(text) => Ok(text),
        _ => Ok(REDACTED.to_owned()),
    }
}

/// `_safe_mcp_arguments` — project raw MCP call arguments into the
/// display/persistence-safe representation persisted on review rows.
pub fn mcp_safe_arguments(value: &Value) -> Result<Value, String> {
    match value {
        Value::Object(entries) => {
            let mut out = Map::with_capacity(entries.len());
            for (key, item) in entries {
                let safe = if secret_shaped_argument_key(key) {
                    Value::String(REDACTED.to_owned())
                } else {
                    mcp_safe_arguments(item)?
                };
                out.insert(key.clone(), safe);
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(mcp_safe_arguments(item)?);
            }
            Ok(Value::Array(out))
        }
        Value::String(text) => Ok(Value::String(mcp_redact_scalar(text)?)),
        other => Ok(other.clone()),
    }
}

/// stdio `_redact_json` — traffic-record redaction used by `remote.py` and
/// `stdio.py`. Distinct fragment tables from the mcp-layer projections are
/// intentional: the Python functions differ and persisted rows were written
/// under this exact behavior.
///
/// Layering detail preserved from the source: a string that takes the URL
/// branch returns `urlunsplit(...)` directly — `_redact_scalar` is NOT
/// applied to the rewritten URL. Only non-URL strings reach the scalar
/// blanket gate.
pub fn redact_json(value: &Value) -> Result<Value, String> {
    match value {
        Value::String(text) => {
            let parsed = urlsplit(text)?;
            if !parsed.scheme.is_empty() && !parsed.netloc.is_empty() && !parsed.query.is_empty() {
                let pairs: Vec<(String, String)> = parse_qsl(&parsed.query)
                    .into_iter()
                    .map(|(key, item)| {
                        let lowered = key.to_lowercase();
                        if QUERY_SECRET_FRAGMENTS
                            .iter()
                            .any(|fragment| lowered.contains(fragment))
                        {
                            (key, REDACTED.to_owned())
                        } else {
                            (key, item)
                        }
                    })
                    .collect();
                return Ok(Value::String(urlunsplit(
                    &parsed.scheme,
                    &parsed.netloc,
                    &parsed.path,
                    &urlencode(&pairs),
                    &parsed.fragment,
                )));
            }
            Ok(Value::String(redact_scalar(text)))
        }
        Value::Array(items) => items
            .iter()
            .map(redact_json)
            .collect::<Result<Vec<Value>, String>>()
            .map(Value::Array),
        Value::Object(entries) => {
            let mut out = Map::with_capacity(entries.len());
            for (key, item) in entries {
                let lowered = key.to_lowercase();
                if MAP_KEY_SECRET_FRAGMENTS
                    .iter()
                    .any(|fragment| lowered.contains(fragment))
                {
                    out.insert(key.clone(), Value::String(REDACTED.to_owned()));
                    continue;
                }
                out.insert(key.clone(), redact_json(item)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

/// stdio `_redact_scalar` — blanket redact any string containing a
/// secret-shaped substring.
fn redact_scalar(value: &str) -> String {
    let lowered = value.to_lowercase();
    if SCALAR_SECRET_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
    {
        return REDACTED.to_owned();
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secret_shaped_keys_match_casefold_semantics() {
        assert!(secret_shaped_argument_key("apiKey"));
        assert!(secret_shaped_argument_key("AUTHORIZATION"));
        assert!(secret_shaped_argument_key("x-token"));
        assert!(secret_shaped_argument_key("Pass_word"));
        assert!(secret_shaped_argument_key("ſecret")); // U+017F folds to s
        assert!(!secret_shaped_argument_key("endpoint"));
        assert!(!secret_shaped_argument_key("mode"));
    }

    #[test]
    fn redact_scalar_blanket_gate() {
        assert_eq!(redact_scalar("Bearer abc123"), REDACTED);
        assert_eq!(redact_scalar("plain value"), "plain value");
    }

    #[test]
    fn redact_json_url_branch_returns_urlunsplit_directly() {
        // URL branch must NOT apply the scalar blanket gate afterwards.
        let redacted = redact_json(&json!("https://example.invalid/run?apiKey=zzz&mode=safe"))
            .expect("redacted");
        assert_eq!(
            redacted,
            json!("https://example.invalid/run?apiKey=%2A%2A%2A%2A%2A&mode=safe")
        );
    }

    #[test]
    fn redact_json_map_keys_use_stdio_fragments() {
        // "apiKey".lower() = "apikey" lacks "api-key" — kept, like Python.
        let redacted = redact_json(&json!({"apiKey": "v", "mode": "x"})).expect("redacted");
        assert_eq!(redacted["apiKey"], json!("v"));
        let redacted = redact_json(&json!({"api-key": "v"})).expect("redacted");
        assert_eq!(redacted["api-key"], json!(REDACTED));
    }

    #[test]
    fn safe_arguments_collapses_secret_keys() {
        let safe = mcp_safe_arguments(&json!({
            "endpoint": "https://example.invalid/x?token=q&keep=1",
            "password": "hunter2",
            "nested": {"API_KEY": "k", "mode": "safe"}
        }))
        .expect("safe arguments");
        assert_eq!(safe["password"], json!(REDACTED));
        assert_eq!(safe["nested"]["API_KEY"], json!(REDACTED));
        assert_eq!(safe["nested"]["mode"], json!("safe"));
    }
}
