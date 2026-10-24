//! Pinned Draft 2020-12 contracts from the Python benchmark source revision.

use crate::{canonicalize, ContractError};
use jsonschema::{Resource, Validator};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

const SCHEMA_BASE: &str = "https://hol-guard.example/benchmark/";
const SCHEMAS: &[(&str, &str)] = &[
    (
        "approval-variant",
        include_str!("../schemas/approval-variant.v1.json"),
    ),
    ("approval", include_str!("../schemas/approval.v1.json")),
    ("attack", include_str!("../schemas/attack.v1.json")),
    (
        "authorization",
        include_str!("../schemas/authorization.v1.json"),
    ),
    ("campaign", include_str!("../schemas/campaign.v1.json")),
    (
        "capabilities",
        include_str!("../schemas/capabilities.v1.json"),
    ),
    (
        "ci-gate-policy",
        include_str!("../schemas/ci-gate-policy.v1.json"),
    ),
    (
        "ci-runner-agent-surface-config",
        include_str!("../schemas/ci-runner-agent-surface-config.v1.json"),
    ),
    (
        "ci-runner-compact-config",
        include_str!("../schemas/ci-runner-compact-config.v1.json"),
    ),
    (
        "ci-runner-config",
        include_str!("../schemas/ci-runner-config.v1.json"),
    ),
    (
        "ci-runner-conformance-config",
        include_str!("../schemas/ci-runner-conformance-config.v1.json"),
    ),
    (
        "ci-runner-package-config",
        include_str!("../schemas/ci-runner-package-config.v1.json"),
    ),
    (
        "ci-runner-private-cell-config",
        include_str!("../schemas/ci-runner-private-cell-config.v1.json"),
    ),
    (
        "ci-runner-protocol-config",
        include_str!("../schemas/ci-runner-protocol-config.v1.json"),
    ),
    ("episode", include_str!("../schemas/episode.v1.json")),
    ("event", include_str!("../schemas/event.v1.json")),
    (
        "holdout-manifest",
        include_str!("../schemas/holdout-manifest.v1.json"),
    ),
    ("manifest", include_str!("../schemas/manifest.v1.json")),
    ("oracle", include_str!("../schemas/oracle.v1.json")),
    ("scorecard", include_str!("../schemas/scorecard.v1.json")),
    ("snapshot", include_str!("../schemas/snapshot.v1.json")),
    ("workflow", include_str!("../schemas/workflow.v1.json")),
];

struct PinnedSchemas {
    documents: BTreeMap<&'static str, Value>,
    validators: BTreeMap<&'static str, Validator>,
}

fn pinned() -> &'static PinnedSchemas {
    static PINNED: OnceLock<PinnedSchemas> = OnceLock::new();
    PINNED.get_or_init(|| {
        let documents: BTreeMap<_, _> = SCHEMAS
            .iter()
            .map(|(kind, raw)| {
                (
                    *kind,
                    serde_json::from_str(raw).expect("pinned schema parses"),
                )
            })
            .collect();
        let mut validators = BTreeMap::new();
        for (&kind, schema) in &documents {
            jsonschema::draft202012::meta::validate(schema).expect("pinned schema is valid");
            let resources = documents.iter().map(|(&name, document)| {
                (
                    format!("{SCHEMA_BASE}{name}.v1.json"),
                    Resource::from_contents(document.clone()).expect("pinned resource is valid"),
                )
            });
            let validator = jsonschema::draft202012::options()
                .with_resources(resources)
                .build(schema)
                .expect("pinned references resolve locally");
            validators.insert(kind, validator);
        }
        PinnedSchemas {
            documents,
            validators,
        }
    })
}

#[derive(Debug)]
pub enum RecordError {
    Json(ContractError),
    UnknownKind,
    InvalidRecord,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "{error}"),
            Self::UnknownKind => f.write_str("unknown versioned contract kind"),
            Self::InvalidRecord => f.write_str("record does not satisfy its pinned contract"),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<ContractError> for RecordError {
    fn from(value: ContractError) -> Self {
        Self::Json(value)
    }
}

/// A detached, validated record and its exact Python-compatible canonical bytes.
#[derive(Debug, Clone)]
pub struct Record {
    value: Value,
    canonical: Vec<u8>,
}

impl Record {
    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

pub fn schema_kinds() -> impl Iterator<Item = &'static str> {
    SCHEMAS.iter().map(|(kind, _)| *kind)
}

/// Decode a bounded inert record and enforce a pinned benchmark schema.
pub fn load_record(kind: &str, raw: &[u8]) -> Result<Record, RecordError> {
    let pinned = pinned();
    let schema = pinned.documents.get(kind).ok_or(RecordError::UnknownKind)?;
    let validator = pinned
        .validators
        .get(kind)
        .ok_or(RecordError::UnknownKind)?;
    let canonical = canonicalize(raw)?;
    let value: Value =
        serde_json::from_slice(&canonical).map_err(|_| RecordError::InvalidRecord)?;
    if !validator.is_valid(&value)
        || !strict_integer_types(&value, schema, schema, &pinned.documents, 0)
    {
        return Err(RecordError::InvalidRecord);
    }
    Ok(Record { value, canonical })
}

fn strict_integer_types(
    value: &Value,
    schema: &Value,
    root: &Value,
    documents: &BTreeMap<&'static str, Value>,
    depth: usize,
) -> bool {
    if depth > 96 {
        return false;
    }
    let Some(row) = schema.as_object() else {
        return true;
    };
    let integer_only = match row.get("type") {
        Some(Value::String(kind)) => kind == "integer",
        Some(Value::Array(kinds)) => {
            kinds.iter().any(|kind| kind == "integer") && !kinds.iter().any(|kind| kind == "number")
        }
        _ => false,
    };
    if integer_only {
        if let Value::Number(number) = value {
            let digits = number.to_string();
            if digits.contains(['.', 'e', 'E']) {
                return false;
            }
        }
    }
    if let Some(reference) = row.get("$ref").and_then(Value::as_str) {
        if let Some(pointer) = reference.strip_prefix('#') {
            let Some(target) = root.pointer(pointer) else {
                return false;
            };
            if !strict_integer_types(value, target, root, documents, depth + 1) {
                return false;
            }
        } else {
            let Some(name) = reference.strip_suffix(".v1.json") else {
                return false;
            };
            let Some(target) = documents.get(name) else {
                return false;
            };
            if !strict_integer_types(value, target, target, documents, depth + 1) {
                return false;
            }
        }
    }
    if let Some(object) = value.as_object() {
        let properties = row.get("properties").and_then(Value::as_object);
        let additional = row.get("additionalProperties");
        for (key, child) in object {
            let selected = properties
                .and_then(|properties| properties.get(key))
                .or(additional);
            if let Some(selected) = selected {
                if !strict_integer_types(child, selected, root, documents, depth + 1) {
                    return false;
                }
            }
        }
    }
    if let (Some(items), Some(array)) = (row.get("items"), value.as_array()) {
        for child in array {
            if !strict_integer_types(child, items, root, documents, depth + 1) {
                return false;
            }
        }
    }
    true
}
