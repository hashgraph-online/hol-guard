//! Parity against `testdata/inventory_fingerprint_parity.json`, recorded by
//! `scripts/ci/generate_inventory_fingerprint_parity.py`.

use serde_json::{Map, Value};

use super::{
    fingerprint_mapping, fingerprint_text, inventory_item_id, inventory_snapshot_content_hash,
    python_compact_json, python_float_repr, stable_snapshot_value,
};
use crate::inventory_agent_types::agent_type;
use crate::inventory_contract::{
    GuardAgentInventoryFinding, GuardAgentInventoryItem, GuardInventorySource,
};

fn corpus() -> Value {
    let raw = include_str!("../testdata/inventory_fingerprint_parity.json");
    serde_json::from_str(raw).expect("the parity corpus is valid JSON")
}

fn section(document: &Value, name: &str) -> Vec<Value> {
    document
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("the corpus has a `{name}` section"))
        .clone()
}

fn text(case: &Value, key: &str) -> String {
    case.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case {case} has a string `{key}`"))
        .to_string()
}

fn object(case: &Value, key: &str) -> Map<String, Value> {
    case.get(key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn string_list(case: &Value, key: &str) -> Vec<String> {
    case.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// A fixture `null` is Python's `None`, and an empty string stays an empty
/// string: the contract hashes the two differently.
fn optional_text(case: &Value, key: &str) -> Option<String> {
    case.get(key).and_then(Value::as_str).map(str::to_string)
}

fn extra(case: &Value, keys: &[&str]) -> Map<String, Value> {
    let mut extra = Map::new();
    for key in keys {
        if let Some(value) = case.get(*key) {
            extra.insert((*key).to_string(), value.clone());
        }
    }
    extra
}

#[test]
fn python_float_repr_matches_the_interpreter() {
    for case in section(&corpus(), "float_repr") {
        let value = case
            .get("value")
            .and_then(Value::as_f64)
            .expect("each float case carries a float");
        let expected = text(&case, "repr");
        // `-0.0` survives the JSON round trip only as a sign bit.
        let value = if expected.starts_with('-') && value == 0.0 {
            -0.0
        } else {
            value
        };
        assert_eq!(python_float_repr(value), expected, "repr of {expected}");
    }
}

/// JSON cannot carry a non-finite float, so the parity fixture cannot either.
/// These are the spellings `repr` gives them in CPython 3.12.
#[test]
fn python_float_repr_spells_out_the_non_finite_values() {
    assert_eq!(python_float_repr(f64::INFINITY), "inf");
    assert_eq!(python_float_repr(f64::NEG_INFINITY), "-inf");
    assert_eq!(python_float_repr(f64::NAN), "nan");
    assert_eq!(python_float_repr(-f64::NAN), "nan");
}

#[test]
fn python_float_repr_spells_non_finite_values_like_repr() {
    assert_eq!(python_float_repr(f64::INFINITY), "inf");
    assert_eq!(python_float_repr(f64::NEG_INFINITY), "-inf");
    assert_eq!(python_float_repr(f64::NAN), "nan");
}

#[test]
fn compact_json_matches_python_dumps() {
    for case in section(&corpus(), "compact_json") {
        let value = case.get("value").cloned().unwrap_or(Value::Null);
        assert_eq!(
            python_compact_json(&value),
            text(&case, "encoded"),
            "encoding of {value}"
        );
        assert_eq!(
            fingerprint_mapping(&value),
            text(&case, "digest"),
            "digest of {value}"
        );
    }
}

#[test]
fn fingerprint_text_matches_python() {
    for case in section(&corpus(), "fingerprint_text") {
        let value = text(&case, "value");
        assert_eq!(
            fingerprint_text(&value),
            text(&case, "digest"),
            "digest of {value:?}"
        );
    }
}

#[test]
fn inventory_item_id_matches_python() {
    for case in section(&corpus(), "inventory_item_id") {
        let semantic_text = text(&case, "semantic_text");
        assert_eq!(
            inventory_item_id(
                &text(&case, "agent_type"),
                &text(&case, "item_kind"),
                &text(&case, "display_name"),
                &semantic_text,
            ),
            text(&case, "item_id"),
            "item id for {semantic_text:?}"
        );
    }
}

#[test]
fn agent_type_matches_python() {
    for case in section(&corpus(), "agent_type") {
        let value = text(&case, "value");
        assert_eq!(
            agent_type(&value),
            text(&case, "normalized"),
            "normalized {value:?}"
        );
    }
}

#[test]
fn stable_snapshot_value_matches_python() {
    for case in section(&corpus(), "stable_snapshot_value") {
        let value = case.get("value").cloned().unwrap_or(Value::Null);
        let expected = case.get("stable").cloned().unwrap_or(Value::Null);
        assert_eq!(stable_snapshot_value(&value), expected, "stable {value}");
    }
}

#[test]
fn snapshot_content_hash_matches_python() {
    for case in section(&corpus(), "snapshot_content_hash") {
        let items: Vec<GuardAgentInventoryItem> = section(&case, "items")
            .iter()
            .map(|item| GuardAgentInventoryItem {
                item_id: text(item, "item_id"),
                item_kind: text(item, "item_kind"),
                display_name: text(item, "display_name"),
                metadata: object(item, "metadata"),
                capability_categories: string_list(item, "capability_categories"),
                content_hash: text(item, "content_hash"),
                drift_state: text(item, "drift_state"),
                extra: extra(
                    item,
                    &[
                        "risk_level",
                        "scanner_sources",
                        "security_score",
                        "source_fingerprint",
                    ],
                ),
            })
            .collect();
        let findings: Vec<GuardAgentInventoryFinding> = section(&case, "findings")
            .iter()
            .map(|finding| GuardAgentInventoryFinding {
                finding_id: text(finding, "finding_id"),
                source: text(finding, "source"),
                severity: text(finding, "severity"),
                confidence: text(finding, "confidence"),
                title: text(finding, "title"),
                artifact_id: text(finding, "artifact_id"),
                check_id: text(finding, "check_id"),
                summary: optional_text(finding, "summary"),
                evidence: object(finding, "evidence"),
                extra: Map::new(),
            })
            .collect();
        let sources: Vec<GuardInventorySource> = section(&case, "sources")
            .iter()
            .map(|source| GuardInventorySource {
                source_id: text(source, "source_id"),
                source_type: text(source, "source_type"),
                status: text(source, "status"),
                detail: optional_text(source, "detail"),
                captured_at: optional_text(source, "captured_at"),
                extra: Map::new(),
            })
            .collect();
        let runtime_version = case.get("runtime_version").and_then(Value::as_str);
        assert_eq!(
            inventory_snapshot_content_hash(
                &text(&case, "agent_type"),
                &items,
                &findings,
                &sources,
                runtime_version,
            ),
            text(&case, "digest"),
            "snapshot digest for {}",
            text(&case, "agent_type")
        );
    }
}
