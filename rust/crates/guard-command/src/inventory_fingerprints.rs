//! `inventory_contract_fingerprints` mirror: the `FingerprintApi` seam.
//!
//! Every snapshot identity in the inventory contract is a sha256 over
//! `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`,
//! so the digest is only stable across the Python and native paths if the
//! encoder agrees byte for byte. Three places where a Rust encoder would
//! quietly differ are handled here rather than left to `serde_json`:
//!
//! * `ensure_ascii=True` escapes DEL and every character above it, writing
//!   astral characters as a surrogate pair. `serde_json` emits them raw.
//! * `repr(float)` uses exponent notation outside `1e-4 .. 1e16` and keeps a
//!   trailing `.0` inside it. Rust's `{}` never writes an exponent.
//! * `str.strip()` and `re.compile(r"\s+")` both test `Py_UNICODE_ISSPACE`,
//!   which covers U+001C..U+001F. Rust's `char::is_whitespace` does not.
//!
//! `rust/crates/guard-command/testdata/inventory_fingerprint_parity.json` pins
//! all three against the interpreter; regenerate it with
//! `scripts/ci/generate_inventory_fingerprint_parity.py`.
//!
//! `fingerprint_path_tree` is deliberately absent: it reads the filesystem and
//! is not part of the `FingerprintApi` seam.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::inventory_contract::{
    FingerprintApi, GuardAgentInventoryFinding, GuardAgentInventoryItem, GuardInventorySource,
};

/// Keys `_stable_snapshot_value` drops so a re-observation hashes the same.
static VOLATILE_SNAPSHOT_KEYS: &[&str] = &[
    "attestation",
    "attestationBindings",
    "capturedAt",
    "duration_ms",
    "durationMs",
    "elapsedMs",
    "evidenceHash",
    "generatedAt",
    "lastSeenAt",
    "observedAt",
    "scanDurationMs",
    "syncedAt",
];

/// `Py_UNICODE_ISSPACE`, which backs both `str.strip()` and `\s` on `str`.
///
/// This is `char::is_whitespace` plus U+001C..U+001F, the four ASCII separator
/// controls Python counts as whitespace and the Unicode `White_Space` property
/// does not.
fn is_python_space(value: char) -> bool {
    matches!(
        value,
        '\u{9}'..='\u{d}'
            | '\u{1c}'..='\u{1f}'
            | '\u{20}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// `str.strip()`.
fn python_strip(value: &str) -> &str {
    value.trim_matches(is_python_space)
}

/// `re.compile(r"\s+").sub(" ", value)`.
fn collapse_python_whitespace(value: &str) -> String {
    let mut collapsed = String::with_capacity(value.len());
    let mut in_run = false;
    for character in value.chars() {
        if is_python_space(character) {
            if !in_run {
                collapsed.push(' ');
                in_run = true;
            }
        } else {
            collapsed.push(character);
            in_run = false;
        }
    }
    collapsed
}

/// `repr(float)`.
///
/// CPython asks dtoa for the shortest round-tripping digits plus a decimal
/// point position, then writes an exponent when that position is `<= -4` or
/// `> 16` and a trailing `.0` otherwise. Rust's `{:e}` gives the same digits,
/// so the only work here is placing the point the way CPython does.
pub fn python_float_repr(value: f64) -> String {
    // `float.__repr__` spells the non-finite values out; only the finite ones
    // reach dtoa.
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-inf" } else { "inf" }.to_string();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }
    let sign = if value < 0.0 { "-" } else { "" };
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    // `value == 0.DIGITS * 10^point`, CPython's `decpt`.
    let point = exponent + 1;
    if point <= -4 || point > 16 {
        let mut rendered = String::from(sign);
        rendered.push_str(&digits[..1]);
        if digits.len() > 1 {
            rendered.push('.');
            rendered.push_str(&digits[1..]);
        }
        let exponent = point - 1;
        rendered.push('e');
        rendered.push(if exponent < 0 { '-' } else { '+' });
        rendered.push_str(&format!("{:02}", exponent.abs()));
        return rendered;
    }
    if point <= 0 {
        return format!("{sign}0.{}{digits}", "0".repeat((-point) as usize));
    }
    let point = point as usize;
    if point >= digits.len() {
        return format!("{sign}{digits}{}.0", "0".repeat(point - digits.len()));
    }
    format!("{sign}{}.{}", &digits[..point], &digits[point..])
}

/// `json.encoder.py_encode_basestring_ascii`.
fn write_python_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            ' '..='~' => output.push(character),
            _ => {
                let code = character as u32;
                if code <= 0xffff {
                    output.push_str(&format!("\\u{code:04x}"));
                } else {
                    let adjusted = code - 0x1_0000;
                    output.push_str(&format!("\\u{:04x}", 0xd800 + (adjusted >> 10)));
                    output.push_str(&format!("\\u{:04x}", 0xdc00 + (adjusted & 0x3ff)));
                }
            }
        }
    }
    output.push('"');
}

/// CPython's `(item_separator, key_separator)` pair.
#[derive(Debug, Clone, Copy)]
pub struct JsonSeparators {
    /// Written between array items and between object entries.
    pub item: &'static str,
    /// Written between an object key and its value.
    pub key: &'static str,
}

/// `json.dumps(..., separators=(",", ":"))` — the digest encoding.
pub const COMPACT_SEPARATORS: JsonSeparators = JsonSeparators {
    item: ",",
    key: ":",
};

/// `json.dumps(...)` with no `indent` and no explicit `separators`.
pub const DEFAULT_SEPARATORS: JsonSeparators = JsonSeparators {
    item: ", ",
    key: ": ",
};

fn write_python_json(value: &Value, separators: JsonSeparators, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(true) => output.push_str("true"),
        Value::Bool(false) => output.push_str("false"),
        Value::Number(number) => {
            if number.is_f64() {
                let number = number.as_f64().unwrap_or(0.0);
                // `json.dumps` writes the non-finite values with their JavaScript
                // spelling rather than `repr`. `serde_json` cannot hold one, so
                // this only guards a hand-built `Value`.
                if number.is_nan() {
                    output.push_str("NaN");
                } else if number.is_infinite() {
                    output.push_str(if number < 0.0 {
                        "-Infinity"
                    } else {
                        "Infinity"
                    });
                } else {
                    output.push_str(&python_float_repr(number));
                }
            } else {
                output.push_str(&number.to_string());
            }
        }
        Value::String(text) => write_python_string(text, output),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push_str(separators.item);
                }
                write_python_json(item, separators, output);
            }
            output.push(']');
        }
        Value::Object(entries) => {
            output.push('{');
            // `sort_keys=True` orders by code point; UTF-8 byte order agrees.
            let mut keys: Vec<&String> = entries.keys().collect();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push_str(separators.item);
                }
                write_python_string(key, output);
                output.push_str(separators.key);
                write_python_json(
                    entries.get(*key).unwrap_or(&Value::Null),
                    separators,
                    output,
                );
            }
            output.push('}');
        }
    }
}

/// `json.dumps(value, sort_keys=True, separators=..., ensure_ascii=True)`.
pub fn python_json(value: &Value, separators: JsonSeparators) -> String {
    let mut encoded = String::new();
    write_python_json(value, separators, &mut encoded);
    encoded
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub fn python_compact_json(value: &Value) -> String {
    python_json(value, COMPACT_SEPARATORS)
}

/// `fingerprint_text(value)`.
pub fn fingerprint_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// `fingerprint_mapping(value)`.
pub fn fingerprint_mapping(value: &Value) -> String {
    fingerprint_text(&python_compact_json(value))
}

/// `_stable_snapshot_value(value)`.
pub fn stable_snapshot_value(value: &Value) -> Value {
    match value {
        Value::Object(entries) => Value::Object(
            entries
                .iter()
                .filter(|(key, _)| !VOLATILE_SNAPSHOT_KEYS.contains(&key.as_str()))
                .map(|(key, item)| (key.clone(), stable_snapshot_value(item)))
                .collect(),
        ),
        Value::Array(items) => {
            let mut stable: Vec<Value> = items.iter().map(stable_snapshot_value).collect();
            stable.sort_by_cached_key(python_compact_json);
            Value::Array(stable)
        }
        other => other.clone(),
    }
}

/// `inventory_item_id(agent_type, item_kind, display_name, semantic_text)`.
pub fn inventory_item_id(
    agent_type: &str,
    item_kind: &str,
    display_name: &str,
    semantic_text: &str,
) -> String {
    let normalized_text = collapse_python_whitespace(python_strip(semantic_text));
    let digest = fingerprint_mapping(&json!({
        "agent_type": agent_type,
        "display_name": python_strip(display_name).to_lowercase(),
        "item_kind": item_kind,
        "semantic_text": normalized_text,
    }));
    format!("{agent_type}:{item_kind}:{}", &digest[..24])
}

/// `extra` carries the dataclass fields the mirror struct does not name, so a
/// missing key means the field was left at its `GuardAgentInventoryItem`
/// default rather than absent.
fn extra_or<'a>(extra: &'a Map<String, Value>, key: &str, fallback: &'a Value) -> &'a Value {
    extra.get(key).unwrap_or(fallback)
}

/// `_inventory_snapshot_content_hash(...)`.
pub fn inventory_snapshot_content_hash(
    agent_type: &str,
    items: &[GuardAgentInventoryItem],
    findings: &[GuardAgentInventoryFinding],
    sources: &[GuardInventorySource],
    runtime_version: Option<&str>,
) -> String {
    let default_risk_level = json!("info");
    let default_security_score = json!(100);
    let default_list = json!([]);
    let default_text = json!("");

    let mut ordered_items: Vec<&GuardAgentInventoryItem> = items.iter().collect();
    ordered_items.sort_by(|left, right| {
        (&left.item_kind, &left.item_id).cmp(&(&right.item_kind, &right.item_id))
    });
    let items: Vec<Value> = ordered_items
        .iter()
        .map(|item| {
            json!({
                "capability_categories": item.capability_categories,
                "content_hash": item.content_hash,
                "drift_state": item.drift_state,
                "item_id": item.item_id,
                "item_kind": item.item_kind,
                "metadata": stable_snapshot_value(&Value::Object(item.metadata.clone())),
                "risk_level": extra_or(&item.extra, "risk_level", &default_risk_level),
                "scanner_sources": extra_or(&item.extra, "scanner_sources", &default_list),
                "security_score": extra_or(&item.extra, "security_score", &default_security_score),
                "source_fingerprint": extra_or(&item.extra, "source_fingerprint", &default_text),
            })
        })
        .collect();

    let mut ordered_findings: Vec<&GuardAgentInventoryFinding> = findings.iter().collect();
    ordered_findings.sort_by(|left, right| {
        (&left.source, &left.finding_id).cmp(&(&right.source, &right.finding_id))
    });
    let findings: Vec<Value> = ordered_findings
        .iter()
        .map(|finding| {
            json!({
                "artifact_id": finding.artifact_id,
                "check_id": finding.check_id,
                "confidence": finding.confidence,
                "evidence": stable_snapshot_value(&Value::Object(finding.evidence.clone())),
                "finding_id": finding.finding_id,
                "severity": finding.severity,
                "source": finding.source,
                "summary": finding.summary,
                "title": finding.title,
            })
        })
        .collect();

    let mut ordered_sources: Vec<&GuardInventorySource> = sources.iter().collect();
    ordered_sources.sort_by(|left, right| {
        (&left.source_type, &left.source_id).cmp(&(&right.source_type, &right.source_id))
    });
    let sources: Vec<Value> = ordered_sources
        .iter()
        .map(|source| {
            json!({
                "detail": source.detail,
                "source_id": source.source_id,
                "source_type": source.source_type,
                "status": source.status,
            })
        })
        .collect();

    fingerprint_mapping(&json!({
        "agent_type": agent_type,
        "runtime_version": runtime_version,
        "items": items,
        "findings": findings,
        "sources": sources,
    }))
}

/// The native `FingerprintApi` seam for `InventoryDeps`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeFingerprints;

impl FingerprintApi for NativeFingerprints {
    fn fingerprint_text(&self, value: &str) -> String {
        fingerprint_text(value)
    }

    fn fingerprint_mapping(&self, value: &Value) -> String {
        fingerprint_mapping(value)
    }

    fn inventory_item_id(
        &self,
        agent_type: &str,
        item_kind: &str,
        display_name: &str,
        semantic_text: &str,
    ) -> String {
        inventory_item_id(agent_type, item_kind, display_name, semantic_text)
    }

    fn _inventory_snapshot_content_hash(
        &self,
        agent_type: &str,
        items: &[GuardAgentInventoryItem],
        findings: &[GuardAgentInventoryFinding],
        sources: &[GuardInventorySource],
        runtime_version: Option<&str>,
    ) -> String {
        inventory_snapshot_content_hash(agent_type, items, findings, sources, runtime_version)
    }
}

#[cfg(test)]
#[path = "inventory_fingerprints_tests.rs"]
mod tests;
