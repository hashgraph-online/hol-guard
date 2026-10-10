//! Column-shaped command-activity values decoded from the `guard_store`
//! request, and exact comparison against persisted rows. The Python caller
//! serializes its dataclasses as the same values it used to bind; this module
//! never derives a field the caller did not send.

use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{Row, StoreError, StoreResult};

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

pub(crate) const ACTIVITY_COLUMNS: [&str; 19] = [
    "activity_id",
    "occurred_at",
    "harness",
    "hook_phase",
    "execution_status",
    "proof_level",
    "policy_action",
    "decision_reason_code",
    "controlling_rule_id",
    "parse_confidence",
    "uncertainty_class",
    "match_count",
    "prompted",
    "approval_reuse_status",
    "receipt_link_status",
    "receipt_id",
    "evaluation_latency_bucket",
    "persistence_latency_bucket",
    "schema_version",
];

pub(crate) const MATCH_COLUMNS: [&str; 11] = [
    "activity_id",
    "ordinal",
    "extension_id",
    "extension_version",
    "rule_id",
    "rule_version",
    "match_class",
    "severity",
    "default_floor",
    "safe_variant_id",
    "schema_version",
];

pub(crate) const SHADOW_COLUMNS: [&str; 13] = [
    "activity_id",
    "occurred_at",
    "authoritative_action",
    "current_action",
    "current_disposition",
    "proposed_action",
    "proposed_disposition",
    "comparison",
    "proposal_version",
    "evaluator_schema_version",
    "control_generation",
    "sample_basis_points",
    "schema_version",
];

pub(crate) const CORRELATION_COLUMNS: [&str; 5] =
    ["activity_id", "kind", "harness", "key_id", "digest"];

/// The values of `columns` in order; a missing key is SQL NULL.
pub(crate) fn column_values(map: &Map<String, Value>, columns: &[&str]) -> StoreResult<Vec<Value>> {
    columns
        .iter()
        .map(|column| match map.get(*column) {
            None | Some(Value::Null) => Ok(Value::Null),
            Some(value @ (Value::String(_) | Value::Number(_) | Value::Bool(_))) => {
                Ok(normalize(value))
            }
            Some(_) => Err(INVALID),
        })
        .collect()
}

/// Booleans persist as SQLite integers, as the Python driver binds them.
fn normalize(value: &Value) -> Value {
    match value {
        Value::Bool(flag) => Value::from(i64::from(*flag)),
        other => other.clone(),
    }
}

fn object_of<'a>(value: &'a Value) -> StoreResult<&'a Map<String, Value>> {
    value.as_object().ok_or(INVALID)
}

pub(crate) fn text_of<'a>(map: &'a Map<String, Value>, key: &str) -> StoreResult<&'a str> {
    map.get(key).and_then(Value::as_str).ok_or(INVALID)
}

/// One local correlation handle: `(kind, harness, key_id, digest)`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Handle {
    pub(crate) kind: String,
    pub(crate) harness: String,
    pub(crate) key_id: String,
    pub(crate) digest: String,
}

impl Handle {
    pub(crate) fn from_wire(map: &Map<String, Value>) -> StoreResult<Self> {
        Ok(Self {
            kind: text_of(map, "kind")?.to_owned(),
            harness: text_of(map, "harness")?.to_owned(),
            key_id: text_of(map, "key_id")?.to_owned(),
            digest: text_of(map, "digest")?.to_owned(),
        })
    }

    pub(crate) fn from_row(row: &Row) -> StoreResult<Self> {
        Self::from_wire(row)
    }

    pub(crate) fn to_value(&self) -> Value {
        serde_json::json!({
            "kind": self.kind,
            "harness": self.harness,
            "key_id": self.key_id,
            "digest": self.digest,
        })
    }
}

pub(crate) fn optional_handle(map: &Map<String, Value>, key: &str) -> StoreResult<Option<Handle>> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Handle::from_wire(object_of(value)?).map(Some),
    }
}

/// A decoded `CommandActivityEvidence`.
pub(crate) struct Evidence<'a> {
    pub(crate) activity: &'a Map<String, Value>,
    pub(crate) matches: Vec<&'a Map<String, Value>>,
}

impl<'a> Evidence<'a> {
    pub(crate) fn from_args(args: &Args<'a>) -> StoreResult<Self> {
        let evidence = args.object("evidence")?;
        let activity = object_of(evidence.get("activity").ok_or(INVALID)?)?;
        let matches = evidence
            .get("matches")
            .and_then(Value::as_array)
            .ok_or(INVALID)?
            .iter()
            .map(object_of)
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(Self { activity, matches })
    }

    pub(crate) fn activity_id(&self) -> StoreResult<&'a str> {
        text_of(self.activity, "activity_id")
    }

    pub(crate) fn activity_values(&self) -> StoreResult<Vec<Value>> {
        column_values(self.activity, &ACTIVITY_COLUMNS)
    }

    pub(crate) fn match_values(&self) -> StoreResult<Vec<Vec<Value>>> {
        self.matches
            .iter()
            .map(|item| column_values(item, &MATCH_COLUMNS))
            .collect()
    }

    /// `(activity_id, ordinal, effect)` for every match, effects sorted.
    pub(crate) fn effect_values(&self) -> StoreResult<Vec<Vec<Value>>> {
        let mut out = Vec::new();
        for item in &self.matches {
            let mut effects = item
                .get("effects")
                .and_then(Value::as_array)
                .ok_or(INVALID)?
                .iter()
                .map(|effect| effect.as_str().ok_or(INVALID))
                .collect::<StoreResult<Vec<_>>>()?;
            effects.sort_unstable();
            for effect in effects {
                out.push(vec![
                    item.get("activity_id").cloned().unwrap_or(Value::Null),
                    item.get("ordinal").cloned().unwrap_or(Value::Null),
                    Value::from(effect),
                ]);
            }
        }
        Ok(out)
    }

    /// Request then session handle rows, in insertion order.
    pub(crate) fn correlation_values(&self) -> StoreResult<Vec<Vec<Value>>> {
        correlation_rows(self.activity)
    }
}

pub(crate) fn correlation_rows(activity: &Map<String, Value>) -> StoreResult<Vec<Vec<Value>>> {
    let id = Value::from(text_of(activity, "activity_id")?);
    let mut out = Vec::new();
    for key in ["request_correlation", "session_correlation"] {
        if let Some(handle) = optional_handle(activity, key)? {
            out.push(vec![
                id.clone(),
                Value::from(handle.kind),
                Value::from(handle.harness),
                Value::from(handle.key_id),
                Value::from(handle.digest),
            ]);
        }
    }
    Ok(out)
}

/// Whether `rows` hold exactly `expected` over `columns`, in order.
pub(crate) fn rows_equal(rows: &[Row], columns: &[&str], expected: &[Vec<Value>]) -> bool {
    rows.len() == expected.len()
        && rows.iter().zip(expected).all(|(row, values)| {
            columns
                .iter()
                .zip(values)
                .all(|(column, value)| row.get(*column).unwrap_or(&Value::Null) == value)
        })
}

pub(crate) fn row_equals(row: &Row, columns: &[&str], expected: &[Value]) -> bool {
    columns
        .iter()
        .zip(expected)
        .all(|(column, value)| row.get(*column).unwrap_or(&Value::Null) == value)
}
