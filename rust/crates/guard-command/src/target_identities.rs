//! `_package_target_identities` (`local_supply_chain.py` :2870-2896) and
//! `_build_command_execution_payload` (`local_supply_chain.py` :3259-3274),
//! plus the `advisory_model.py` helpers they depend on:
//! `ProtectTargetIdentity` (:19-27), `build_package_url` (:30-41), and
//! `normalize_identity_value` (:96-97).
//!
//! DUPLICATE FLAGS (do not unify here; parent decides cutover):
//! - `crate::local_supply_chain::package_target_identities` (:6574) is a
//!   divergent duplicate: it returns `Vec<Map<String, Value>>` and takes an
//!   `AdvisoryModelApi` for `build_package_url`; its `str(...)` coercion only
//!   filters `Null`/`false`, so `0`, `""`, `[]`, `{}` are rendered instead of
//!   the Python `or ""` fallback, and truthy non-strings render as JSON
//!   (`true`) instead of Python repr (`True`).
//! - `crate::local_supply_chain::build_command_execution_payload` (:7999) is
//!   a divergent duplicate: it routes redaction through a `RedactionApi`
//!   trait instead of the concrete `redacted_command_tokens::redact_text`.
//! - `AdvisoryModelApi::build_package_url` (`local_supply_chain.rs` :634) is
//!   the same helper behind a trait seam; `protect.py`'s copy
//!   (`protect.py` :1023 `ProtectTargetIdentity` construction) is out of this
//!   module's scope.
//! - `python_strip` / `py_str_repr` / `py_float_repr` are local copies of the
//!   private helpers in `mcp_decision.rs` (:82-101) and
//!   `package_manifest_diff.rs` (:285-303). Receipt projection shares this
//!   module's `py_str` and `py_truthy`; `py_float_repr` here is stricter than the
//!   `package_manifest_diff.rs` version — it reproduces CPython's `e+16`/
//!   `e-05` exponent style for shortest-repr floats.

use std::borrow::Cow;

use serde_json::{json, Map, Value};

use crate::package_intent_common::GuardArtifact;
use crate::redacted_command_tokens::redact_text;

// ---------------------------------------------------------------------------
// CPython scalar/repr shims (private; see duplicate note above).
// ---------------------------------------------------------------------------

/// CPython `str.strip()` whitespace set: the ASCII controls 0x09-0x0d and
/// 0x1c-0x1f plus every Unicode code point whose `isspace` is true.
/// `char::is_whitespace` misses 0x1c-0x1f, so `str::trim` is NOT equivalent.
fn is_python_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{09}'..='\u{0d}'
            | ' '
            | '\u{1c}'..='\u{1f}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

/// Python truthiness for JSON values (`or`/`if` semantics): `None`, `False`,
/// `0`, `0.0`, `""`, `[]`, `{}` are falsy.
pub(crate) fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Python `repr(float)`: shortest round-trip, `.0` for integral values in
/// fixed range, `e±NN` scientific outside `-4 <= exp < 16`.
fn py_float_repr(number: f64) -> String {
    if number.is_nan() {
        return "nan".to_string();
    }
    if number.is_infinite() {
        return if number < 0.0 { "-inf" } else { "inf" }.to_string();
    }
    if number == 0.0 {
        return if number.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        }
        .to_string();
    }
    // `{:e}` yields the shortest round-trip digits plus a decimal exponent
    // (`1e16`, `1.2345e-3`), matching the digits CPython's repr produces.
    let scientific = format!("{number:e}");
    let (mantissa, exponent_text) = scientific.split_once('e').unwrap_or(("0", "0"));
    let exponent: i32 = exponent_text.parse().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa
        .chars()
        .filter(|c| *c != '-' && *c != '.')
        .collect();
    let digit_count = digits.len() as i32;
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if (-4..16).contains(&exponent) {
        if exponent >= digit_count - 1 {
            out.push_str(&digits);
            for _ in 0..(exponent - digit_count + 1) {
                out.push('0');
            }
            out.push_str(".0");
        } else if exponent >= 0 {
            let split = (exponent + 1) as usize;
            out.push_str(&digits[..split]);
            out.push('.');
            out.push_str(&digits[split..]);
        } else {
            out.push_str("0.");
            for _ in 0..(-exponent - 1) {
                out.push('0');
            }
            out.push_str(&digits);
        }
    } else {
        out.push_str(&digits[..1]);
        if digit_count > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exponent < 0 { '-' } else { '+' });
        let magnitude = exponent.unsigned_abs();
        if magnitude < 10 {
            out.push('0');
        }
        out.push_str(&magnitude.to_string());
    }
    out
}

/// Python `repr(str)`: prefers single quotes, switches to double quotes only
/// when the text contains `'` and no `"`; control characters use escapes.
fn py_str_repr(text: &str) -> String {
    let has_single = text.contains('\'');
    let has_double = text.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' if quote == '\'' => out.push_str("\\'"),
            '"' if quote == '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 || (other as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out.push(quote);
    out
}

/// Python `repr(value)` for a JSON value (elements inside containers).
/// Object key order follows `serde_json::Map` iteration (sorted); CPython
/// dict repr preserves insertion order, which is already lost upstream.
fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(flag) => {
            if *flag {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                int.to_string()
            } else if let Some(uint) = number.as_u64() {
                uint.to_string()
            } else {
                py_float_repr(number.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(text) => py_str_repr(text),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(key, item)| format!("{}: {}", py_str_repr(key), py_repr(item)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Python `str(value)`: strings render bare; everything else uses `repr`.
pub(crate) fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => py_repr(other),
    }
}

/// `str(item.get(key) or "")` — truthiness-gated `str()` coercion with the
/// Python `or` fallback to `""`.
fn py_str_or_empty(item: &Map<String, Value>, key: &str) -> String {
    item.get(key)
        .filter(|v| py_truthy(v))
        .map(py_str)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// advisory_model.py helpers (:30-41, :96-97).
// ---------------------------------------------------------------------------

/// `_PACKAGE_URL_ECOSYSTEMS` (`advisory_model.py` :7-14).
fn package_url_purl_type(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "npm" | "pnpm" | "yarn" => Some("npm"),
        "pip" | "uv" => Some("pypi"),
        "go" => Some("golang"),
        _ => None,
    }
}

/// `normalize_identity_value` (`advisory_model.py` :96-97):
/// `value.strip().lower()` — only called with `str` in Python, so the
/// `isinstance` guard is implied by the signature.
fn normalize_identity_value(value: &str) -> Cow<'_, str> {
    let stripped = python_strip(value);
    if stripped
        .chars()
        .flat_map(char::to_lowercase)
        .eq(stripped.chars())
    {
        Cow::Borrowed(stripped)
    } else {
        Cow::Owned(stripped.to_lowercase())
    }
}

/// `build_package_url` (`advisory_model.py` :30-41): purl-style identifier
/// for registry package installs, `None` for unknown ecosystems.
pub fn build_package_url(
    ecosystem: &str,
    package_name: Option<&str>,
    version: Option<&str>,
) -> Option<String> {
    let package_name = package_name?;
    let purl_type = package_url_purl_type(ecosystem)?;
    let base = format!("pkg:{purl_type}/{}", normalize_identity_value(package_name));
    let stripped_version = version.map(python_strip).unwrap_or("");
    if stripped_version.is_empty() {
        return Some(base);
    }
    Some(format!("{base}@{stripped_version}"))
}

/// Concrete advisory identity authority shared by package policy consumers.
pub struct NativeAdvisoryModel;

impl crate::local_supply_chain::AdvisoryModelApi for NativeAdvisoryModel {
    fn build_package_url(
        &self,
        ecosystem: &str,
        package_name: Option<&str>,
        version: Option<&str>,
    ) -> Option<String> {
        build_package_url(ecosystem, package_name, version)
    }

    fn advisory_matches_target(&self, advisory: &Value, target: &Value) -> bool {
        advisory_matches_target(advisory, target)
    }
}

fn package_url_base(value: &str) -> Cow<'_, str> {
    let mut normalized = normalize_identity_value(value);
    let without_suffix = normalized.split(['?', '#']).next().unwrap_or("");
    let mut end = without_suffix.len();
    if let Some(at) = without_suffix.rfind('@') {
        if without_suffix.rfind('/').is_none_or(|slash| at >= slash) {
            end = at;
        }
    }
    match &mut normalized {
        Cow::Borrowed(value) => Cow::Borrowed(&value[..end]),
        Cow::Owned(value) => {
            value.truncate(end);
            normalized
        }
    }
}

fn normalized_membership(values: Option<&Value>, candidates: &[&str]) -> bool {
    values.and_then(Value::as_array).is_some_and(|values| {
        values.iter().filter_map(Value::as_str).any(|value| {
            let normalized = normalize_identity_value(value);
            !normalized.is_empty() && candidates.iter().any(|candidate| normalized == *candidate)
        })
    })
}

fn normalized_url_indicator(value: Option<&str>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    let Ok(parsed) = crate::cloud_audit_sync::urlsplit(value) else {
        return normalize_identity_value(value).into_owned();
    };
    if parsed.scheme.is_empty() || parsed.netloc.is_empty() {
        return normalize_identity_value(value).into_owned();
    }
    let indicator = format!("{}{}", parsed.netloc, parsed.path.trim_end_matches('/'));
    match normalize_identity_value(&indicator) {
        Cow::Borrowed(_) => indicator,
        Cow::Owned(normalized) => normalized,
    }
}

pub fn advisory_matches_target(advisory: &Value, target: &Value) -> bool {
    let (Some(advisory), Some(target)) = (advisory.as_object(), target.as_object()) else {
        return false;
    };
    let Some(artifact_id) = target.get("artifact_id").and_then(Value::as_str) else {
        return false;
    };
    if advisory.get("artifact_id").and_then(Value::as_str) == Some(artifact_id) {
        return true;
    }
    if let Some(ecosystem) = advisory.get("ecosystem").and_then(Value::as_str) {
        if ecosystem != "*" && target.get("ecosystem").and_then(Value::as_str) != Some(ecosystem) {
            return false;
        }
    }
    if let (Some(advisory_url), Some(target_url)) = (
        advisory.get("package_url").and_then(Value::as_str),
        target.get("package_url").and_then(Value::as_str),
    ) {
        let advisory_base = package_url_base(advisory_url);
        if !advisory_base.is_empty() && advisory_base == package_url_base(target_url) {
            return true;
        }
    }
    let package = normalize_identity_value(
        target
            .get("package_name")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    let name = normalize_identity_value(
        target
            .get("artifact_name")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    if normalized_membership(advisory.get("aliases"), &[&package, &name]) {
        return true;
    }
    let advisory_package = advisory
        .get("package")
        .filter(|value| py_truthy(value))
        .or_else(|| advisory.get("name"))
        .and_then(Value::as_str)
        .map(normalize_identity_value);
    if advisory_package
        .as_ref()
        .is_some_and(|value| !value.is_empty() && (value == &package || value == &name))
    {
        return true;
    }
    if let Some(publisher) = advisory.get("publisher").and_then(Value::as_str) {
        let publisher = normalize_identity_value(publisher);
        if !publisher.is_empty() && publisher == package {
            return true;
        }
    }
    if normalized_membership(advisory.get("publisher_identities"), &[&package]) {
        return true;
    }
    let source = target.get("source_url").and_then(Value::as_str);
    let normalized_source = normalized_url_indicator(source);
    if !normalized_source.is_empty() {
        if advisory
            .get("endpoint_indicators")
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values.iter().filter_map(Value::as_str).any(|value| {
                    let indicator = normalized_url_indicator(Some(value));
                    !indicator.is_empty()
                        && (normalized_source == indicator
                            || normalized_source
                                .strip_prefix(&indicator)
                                .is_some_and(|rest| rest.starts_with('/')))
                })
            })
        {
            return true;
        }
        if let Some(advisory_source) = advisory.get("source_url").and_then(Value::as_str) {
            return normalized_source == normalized_url_indicator(Some(advisory_source));
        }
    }
    false
}

// ---------------------------------------------------------------------------
// ProtectTargetIdentity (advisory_model.py :19-27).
// ---------------------------------------------------------------------------

/// `ProtectTargetIdentity` (`advisory_model.py` :19-27): subset of install
/// target data advisory matching needs. Fields keep dataclass order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectTargetIdentity {
    pub artifact_id: String,
    pub artifact_name: String,
    pub ecosystem: String,
    pub package_name: Option<String>,
    pub package_url: Option<String>,
    pub source_url: Option<String>,
}

impl ProtectTargetIdentity {
    /// `dataclasses.asdict` shape — keys emitted in dataclass field order.
    pub fn to_dict(&self) -> Map<String, Value> {
        let mut payload = Map::new();
        payload.insert("artifact_id".to_string(), json!(self.artifact_id));
        payload.insert("artifact_name".to_string(), json!(self.artifact_name));
        payload.insert("ecosystem".to_string(), json!(self.ecosystem));
        payload.insert("package_name".to_string(), json!(self.package_name));
        payload.insert("package_url".to_string(), json!(self.package_url));
        payload.insert("source_url".to_string(), json!(self.source_url));
        payload
    }
}

// ---------------------------------------------------------------------------
// `_package_target_identities` (local_supply_chain.py :2870-2896).
// ---------------------------------------------------------------------------

/// `_package_target_identities` (:2870): builds advisory-matchable target
/// identities from `artifact.metadata["targets"]`. Non-dict metadata/targets
/// and non-dict items are skipped exactly like the Python `isinstance`
/// guards; `item.get(...) or ...` fallbacks use Python truthiness.
pub fn package_target_identities(artifact: &GuardArtifact) -> Vec<ProtectTargetIdentity> {
    let Some(metadata) = artifact.metadata.as_object() else {
        return Vec::new();
    };
    let Some(targets) = metadata.get("targets").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut identities: Vec<ProtectTargetIdentity> = Vec::new();
    for item in targets {
        let Some(item) = item.as_object() else {
            continue;
        };
        let ecosystem = py_str_or_empty(item, "ecosystem");
        let package_name = item
            .get("package_name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        // `str(item.get("raw_spec") or package_name or "")`: `raw_spec` is
        // `str()`-coerced only when truthy; otherwise falls through to
        // `package_name` (already a str or None) then `""`.
        let raw_spec = match item.get("raw_spec").filter(|v| py_truthy(v)) {
            Some(value) => py_str(value),
            None => package_name.clone().unwrap_or_default(),
        };
        let version = item
            .get("requested_specifier")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let source_url = item
            .get("source_url")
            .and_then(Value::as_str)
            .map(str::to_owned);
        // `package_name or raw_spec`: empty string is falsy → raw_spec.
        let artifact_name = package_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(&raw_spec)
            .to_string();
        identities.push(ProtectTargetIdentity {
            artifact_id: format!("{ecosystem}:{artifact_name}"),
            artifact_name,
            ecosystem: ecosystem.clone(),
            package_url: build_package_url(&ecosystem, package_name.as_deref(), version.as_deref()),
            package_name,
            source_url,
        });
    }
    identities
}

// ---------------------------------------------------------------------------
// `_build_command_execution_payload` (local_supply_chain.py :3259-3274).
// ---------------------------------------------------------------------------

/// `_build_command_execution_payload` (:3259): command-execution result with
/// redacted stdout/stderr plus `RedactedText.to_dict` metadata. Keys are
/// emitted in the Python dict order (`returncode`, `stdout`, `stderr`,
/// `stdout_redactions`, `stderr_redactions`, `raw_output_enabled`); note
/// `serde_json::Map` serializes sorted, matching the rest of the crate's
/// ensure_ascii-canonical output. Redaction metadata is always computed even
/// when `unsafe_raw_output` keeps the raw text, mirroring Python.
pub fn build_command_execution_payload(
    stdout: &str,
    stderr: &str,
    returncode: i64,
    unsafe_raw_output: bool,
) -> Map<String, Value> {
    let redacted_stdout = redact_text(stdout);
    let redacted_stderr = redact_text(stderr);
    let stdout_redactions = redacted_stdout.to_dict();
    let stderr_redactions = redacted_stderr.to_dict();
    let mut payload = Map::new();
    payload.insert("returncode".to_string(), json!(returncode));
    payload.insert(
        "stdout".to_string(),
        Value::String(if unsafe_raw_output {
            stdout.to_string()
        } else {
            redacted_stdout.text
        }),
    );
    payload.insert(
        "stderr".to_string(),
        Value::String(if unsafe_raw_output {
            stderr.to_string()
        } else {
            redacted_stderr.text
        }),
    );
    payload.insert("stdout_redactions".to_string(), stdout_redactions);
    payload.insert("stderr_redactions".to_string(), stderr_redactions);
    payload.insert("raw_output_enabled".to_string(), json!(unsafe_raw_output));
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(metadata: Value) -> GuardArtifact {
        GuardArtifact {
            artifact_id: "a".to_string(),
            name: "n".to_string(),
            harness: "h".to_string(),
            artifact_type: "t".to_string(),
            source_scope: "s".to_string(),
            config_path: "c".to_string(),
            command: None,
            args: Vec::new(),
            url: None,
            transport: None,
            publisher: None,
            metadata,
            runtime_private_metadata: json!({}),
        }
    }

    fn identity_dicts(identities: &[ProtectTargetIdentity]) -> Value {
        Value::Array(
            identities
                .iter()
                .map(|identity| Value::Object(identity.to_dict()))
                .collect(),
        )
    }

    /// Oracle: `python3 -c "import sys, json, dataclasses; sys.path.insert(0,'src');
    /// from codex_plugin_scanner.guard.local_supply_chain import _package_target_identities"`.
    /// Non-dict/non-list guards return `()`.
    #[test]
    fn identities_empty_guards() {
        assert!(package_target_identities(&artifact(Value::Null)).is_empty());
        assert!(package_target_identities(&artifact(json!("x"))).is_empty());
        assert!(package_target_identities(&artifact(json!({}))).is_empty());
        assert!(package_target_identities(&artifact(json!({"targets": "x"}))).is_empty());
        assert!(package_target_identities(&artifact(json!({"targets": [1, "s"]}))).is_empty());
    }

    /// Oracle: `_package_target_identities` over a mixed target list —
    /// verified verbatim against the Python function.
    #[test]
    fn identities_mixed() {
        let art = artifact(json!({
            "targets": [
                "skipme",
                {"ecosystem": "npm", "package_name": "lodash",
                 "requested_specifier": "4.17.21",
                 "source_url": "https://npmjs.com/lodash"},
                {"ecosystem": "pip", "raw_spec": "requests[security]>=2"},
                {"package_name": "noeco"},
                {"ecosystem": "unknowneco", "package_name": "X",
                 "requested_specifier": "  "},
                {"ecosystem": 0, "package_name": 5, "raw_spec": false},
                {"ecosystem": true, "raw_spec": ["a", "b"],
                 "requested_specifier": 3},
                {"ecosystem": "uv", "package_name": "UP Per",
                 "requested_specifier": "1.0\u{1c}"}
            ]
        }));
        let expected: Value = serde_json::from_str(concat!(
            "[",
            r#"{"artifact_id":"npm:lodash","artifact_name":"lodash","ecosystem":"npm","package_name":"lodash","package_url":"pkg:npm/lodash@4.17.21","source_url":"https://npmjs.com/lodash"},"#,
            r#"{"artifact_id":"pip:requests[security]>=2","artifact_name":"requests[security]>=2","ecosystem":"pip","package_name":null,"package_url":null,"source_url":null},"#,
            r#"{"artifact_id":":noeco","artifact_name":"noeco","ecosystem":"","package_name":"noeco","package_url":null,"source_url":null},"#,
            r#"{"artifact_id":"unknowneco:X","artifact_name":"X","ecosystem":"unknowneco","package_name":"X","package_url":null,"source_url":null},"#,
            r#"{"artifact_id":":","artifact_name":"","ecosystem":"","package_name":null,"package_url":null,"source_url":null},"#,
            r#"{"artifact_id":"True:['a', 'b']","artifact_name":"['a', 'b']","ecosystem":"True","package_name":null,"package_url":null,"source_url":null},"#,
            r#"{"artifact_id":"uv:UP Per","artifact_name":"UP Per","ecosystem":"uv","package_name":"UP Per","package_url":"pkg:pypi/up per@1.0","source_url":null}"#,
            "]"
        ))
        .unwrap();
        assert_eq!(identity_dicts(&package_target_identities(&art)), expected);
    }

    /// Oracle: non-str scalars/containers are `str()`/`repr()`-coerced;
    /// `package_name` keeps its original (unstripped) text in artifact
    /// fields while `package_url` normalizes it.
    #[test]
    fn identities_scalar_coercion() {
        let art = artifact(json!({
            "targets": [
                {"ecosystem": 1e16, "package_name": true,
                 "raw_spec": {"k": "v"}, "requested_specifier": 2.5},
                {"ecosystem": "npm", "package_name": "  padded  ",
                 "requested_specifier": "\u{1e}1.2\u{1f}"}
            ]
        }));
        let expected: Value = serde_json::from_str(concat!(
            "[",
            r#"{"artifact_id":"1e+16:{'k': 'v'}","artifact_name":"{'k': 'v'}","ecosystem":"1e+16","package_name":null,"package_url":null,"source_url":null},"#,
            r#"{"artifact_id":"npm:  padded  ","artifact_name":"  padded  ","ecosystem":"npm","package_name":"  padded  ","package_url":"pkg:npm/padded@1.2","source_url":null}"#,
            "]"
        ))
        .unwrap();
        assert_eq!(identity_dicts(&package_target_identities(&art)), expected);
    }

    /// Oracle: empty-string `package_name` is falsy — `artifact_name` falls
    /// back to `raw_spec`, but `package_url` still uses the (empty) name.
    #[test]
    fn identities_empty_package_name() {
        let art = artifact(json!({
            "targets": [
                {"ecosystem": "npm", "package_name": "", "raw_spec": "spec",
                 "requested_specifier": "1"},
                {"ecosystem": "npm", "package_name": "", "raw_spec": ""}
            ]
        }));
        let expected: Value = serde_json::from_str(concat!(
            "[",
            r#"{"artifact_id":"npm:spec","artifact_name":"spec","ecosystem":"npm","package_name":"","package_url":"pkg:npm/@1","source_url":null},"#,
            r#"{"artifact_id":"npm:","artifact_name":"","ecosystem":"npm","package_name":"","package_url":"pkg:npm/","source_url":null}"#,
            "]"
        ))
        .unwrap();
        assert_eq!(identity_dicts(&package_target_identities(&art)), expected);
    }

    /// `build_package_url` (`advisory_model.py` :30-41) purl type map and
    /// version-strip edge cases.
    #[test]
    fn package_url() {
        assert_eq!(
            build_package_url("npm", Some("Lodash"), Some("1.0")),
            Some("pkg:npm/lodash@1.0".to_string())
        );
        assert_eq!(
            build_package_url("pnpm", Some("a"), None),
            Some("pkg:npm/a".to_string())
        );
        assert_eq!(
            build_package_url("yarn", Some("a"), Some("  ")),
            Some("pkg:npm/a".to_string())
        );
        assert_eq!(
            build_package_url("pip", Some("a"), Some("1")),
            Some("pkg:pypi/a@1".to_string())
        );
        assert_eq!(
            build_package_url("uv", Some("a"), Some("1")),
            Some("pkg:pypi/a@1".to_string())
        );
        assert_eq!(
            build_package_url("go", Some("a"), Some("1")),
            Some("pkg:golang/a@1".to_string())
        );
        assert_eq!(build_package_url("gem", Some("a"), Some("1")), None);
        assert_eq!(build_package_url("npm", None, Some("1")), None);
        // C0 separator strip parity: `"\x1f2\x1c"` strips to "2".
        assert_eq!(
            build_package_url("npm", Some("a"), Some("\u{1f}2\u{1c}")),
            Some("pkg:npm/a@2".to_string())
        );
    }

    /// Oracle: `_build_command_execution_payload` unsafe_raw_output=False.
    #[test]
    fn execution_payload_redacted() {
        let payload =
            build_command_execution_payload("ok ghp_aaaaaaaa done", "warn sk-aaaaaaaa", 1, false);
        let expected: Value = serde_json::from_str(concat!(
            "{",
            r#""returncode":1,"stdout":"ok gh***** done","stderr":"warn sk-*****","#,
            r#""stdout_redactions":{"count":1,"classifiers":["github-token"],"original_sha256":""},"#,
            r#""stderr_redactions":{"count":1,"classifiers":["openai-token"],"original_sha256":""},"#,
            r#""raw_output_enabled":false}"#
        ))
        .unwrap();
        assert_eq!(Value::Object(payload), expected);
    }

    /// Oracle: `_build_command_execution_payload` unsafe_raw_output=True —
    /// raw text kept, redaction metadata still populated.
    #[test]
    fn execution_payload_raw() {
        let payload =
            build_command_execution_payload("ok ghp_aaaaaaaa done", "warn sk-aaaaaaaa", 1, true);
        let expected: Value = serde_json::from_str(concat!(
            "{",
            r#""returncode":1,"stdout":"ok ghp_aaaaaaaa done","stderr":"warn sk-aaaaaaaa","#,
            r#""stdout_redactions":{"count":1,"classifiers":["github-token"],"original_sha256":""},"#,
            r#""stderr_redactions":{"count":1,"classifiers":["openai-token"],"original_sha256":""},"#,
            r#""raw_output_enabled":true}"#
        ))
        .unwrap();
        assert_eq!(Value::Object(payload), expected);
    }

    /// Payload keys in Python dict order.
    #[test]
    fn execution_payload_key_order() {
        let payload = build_command_execution_payload("", "", 0, false);
        let keys: Vec<&String> = payload.keys().collect();
        let mut sorted: Vec<&&String> = keys.iter().collect();
        sorted.sort();
        // BTreeMap serializes sorted; assert the full key set and that the
        // sorted order matches what the canonical writer emits.
        assert_eq!(
            keys.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
            vec![
                "raw_output_enabled",
                "returncode",
                "stderr",
                "stderr_redactions",
                "stdout",
                "stdout_redactions",
            ]
        );
        assert_eq!(payload["returncode"], json!(0));
        assert_eq!(payload["raw_output_enabled"], json!(false));
    }

    /// `py_float_repr`/`py_repr` edge cases feeding `str()` coercion.
    #[test]
    fn python_scalar_reprs() {
        assert_eq!(py_str(&json!(1e16)), "1e+16");
        assert_eq!(py_str(&json!(1e15)), "1000000000000000.0");
        assert_eq!(py_str(&json!(1e-5)), "1e-05");
        assert_eq!(py_str(&json!(0.0001)), "0.0001");
        assert_eq!(py_str(&json!(2.5)), "2.5");
        assert_eq!(py_str(&json!(-0.0)), "-0.0");
        assert_eq!(py_str(&json!(true)), "True");
        assert_eq!(py_str(&Value::Null), "None");
        assert_eq!(py_str(&json!([1, "a", null])), "[1, 'a', None]");
        assert_eq!(py_str(&json!({"k": "v"})), "{'k': 'v'}");
        // `str()` fallback: falsy values → "", containers → repr.
        let item = json!({"ecosystem": 0, "raw_spec": [], "x": {}})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(py_str_or_empty(&item, "ecosystem"), "");
        assert_eq!(py_str_or_empty(&item, "raw_spec"), "");
        assert_eq!(py_str_or_empty(&item, "missing"), "");
    }
    #[test]
    fn advisory_identity_precedence_and_scoped_purl_boundaries() {
        let target = json!({
            "artifact_id": "npm:@scope/pkg", "artifact_name": "@scope/pkg",
            "package_name": "@scope/pkg", "ecosystem": "npm",
            "package_url": "pkg:npm/@scope/pkg@2.0#integrity"
        });
        assert!(advisory_matches_target(
            &json!({"artifact_id":"npm:@scope/pkg", "ecosystem":"pypi"}),
            &target,
        ));
        assert!(!advisory_matches_target(
            &json!({"aliases":["@scope/pkg"], "ecosystem":"pypi"}),
            &target,
        ));
        assert!(advisory_matches_target(
            &json!({"package_url":"pkg:npm/@scope/pkg@1.0?arch=arm64"}),
            &target,
        ));
        assert!(!advisory_matches_target(
            &json!({"package_url":"pkg:npm/@other/pkg"}),
            &target,
        ));
    }

    #[test]
    fn advisory_endpoint_matches_only_complete_path_segments() {
        let target = json!({
            "artifact_id":"npm:pkg", "ecosystem":"npm",
            "source_url":"HTTPS://Registry.Example/repo/pkg?token=opaque#fragment"
        });
        assert!(advisory_matches_target(
            &json!({"endpoint_indicators":["http://registry.example/repo/"]}),
            &target,
        ));
        assert!(!advisory_matches_target(
            &json!({"endpoint_indicators":["https://registry.example/rep"]}),
            &target,
        ));
        assert!(!advisory_matches_target(
            &json!({"endpoint_indicators":["https://registry.example.evil/repo"]}),
            &target,
        ));
        assert!(advisory_matches_target(
            &json!({"source_url":"http://registry.example/repo/pkg/"}),
            &target,
        ));
    }

    #[test]
    fn advisory_aliases_preserve_unicode_lowercase_and_python_whitespace() {
        let target = json!({
            "artifact_id":"npm:other", "artifact_name":"ΟΣ", "package_name":"Résumé",
            "ecosystem":"npm"
        });
        assert!(advisory_matches_target(
            &json!({"aliases":["\u{1f}résumé\u{1c}"]}),
            &target
        ));
        assert!(advisory_matches_target(&json!({"aliases":["ος"]}), &target));
        assert!(!advisory_matches_target(
            &json!({"aliases":["οσ"]}),
            &target
        ));
        assert!(advisory_matches_target(
            &json!({"publisher_identities":["RÉSUMÉ"]}),
            &target
        ));
    }
}
