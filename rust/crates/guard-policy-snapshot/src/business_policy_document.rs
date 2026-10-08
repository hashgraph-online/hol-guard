//! Whole-document native compilation. Compilation supplies no import authority,
//! signature verification, activation, or authenticated action facts.
//!
//! The current binding cannot represent co-selectors or scoped lifetimes.
//! Refuse those documents rather than projecting only `match.business`.

use crate::business_match::BusinessPolicyMatchV1;
use crate::business_policy::{
    BusinessPolicyBindingV1, BusinessPolicyRuleV1, BUSINESS_POLICY_BINDING_SCHEMA,
};
use crate::{canonical_json_bytes, digest_bytes};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub const MAX_BUSINESS_POLICY_DOCUMENT_BYTES: usize = 1_048_576;
const MAX_DOCUMENT_DEPTH: usize = 32;
const CANONICAL_SCHEMA: &str = include_str!("../../../../spec/guard-policy/v1alpha1/schema.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessDocumentError {
    Bounds,
    InvalidDocument,
    DuplicateRule,
    UnsupportedDefaults,
    UnsupportedRule,
    UnsupportedLifetime,
    UnsupportedExtension,
}

/// Retains complete source identity alongside the result. This value cannot be
/// deserialized from caller input and is not an authenticated installed policy.
#[derive(Debug)]
pub struct CompiledBusinessDocument {
    canonical_source: Vec<u8>,
    source_digest: String,
    binding: BusinessPolicyBindingV1,
}

impl CompiledBusinessDocument {
    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub fn canonical_source(&self) -> &[u8] {
        &self.canonical_source
    }

    pub fn binding(&self) -> &BusinessPolicyBindingV1 {
        &self.binding
    }
}

fn validator() -> Result<&'static jsonschema::Validator, BusinessDocumentError> {
    static VALIDATOR: OnceLock<Result<jsonschema::Validator, BusinessDocumentError>> =
        OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema: Value = serde_json::from_str(CANONICAL_SCHEMA)
                .map_err(|_| BusinessDocumentError::InvalidDocument)?;
            jsonschema::validator_for(&schema).map_err(|_| BusinessDocumentError::InvalidDocument)
        })
        .as_ref()
        .map_err(|error| *error)
}

fn validate_tree(
    value: &Value,
    depth: usize,
    budget: &mut usize,
    label_keys: bool,
) -> Result<(), BusinessDocumentError> {
    *budget = budget.saturating_add(1);
    if depth > MAX_DOCUMENT_DEPTH || *budget > MAX_BUSINESS_POLICY_DOCUMENT_BYTES {
        return Err(BusinessDocumentError::Bounds);
    }
    match value {
        Value::Array(values) => {
            if values.len() > 1000 {
                return Err(BusinessDocumentError::Bounds);
            }
            for item in values {
                validate_tree(item, depth + 1, budget, false)?;
            }
        }
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(BusinessDocumentError::Bounds);
            }
            for (key, item) in values {
                if key.len() > 128 {
                    return Err(BusinessDocumentError::Bounds);
                }
                if key.starts_with("x-") && !label_keys {
                    return Err(BusinessDocumentError::UnsupportedExtension);
                }
                *budget = budget.saturating_add(key.len());
                validate_tree(item, depth + 1, budget, key == "labels" && depth == 1)?;
            }
        }
        Value::String(value) => {
            *budget = budget.saturating_add(value.len());
            if value.chars().count() > 4096 || *budget > MAX_BUSINESS_POLICY_DOCUMENT_BYTES {
                return Err(BusinessDocumentError::Bounds);
            }
        }
        Value::Number(number) if !number.is_i64() && !number.is_u64() => {
            return Err(BusinessDocumentError::InvalidDocument);
        }
        _ => {}
    }
    Ok(())
}

// Schema validation checks the timestamp spelling; check the actual calendar
// date as well, matching canonical document validation rather than SQLite's
// permissive day normalization.
fn valid_calendar_date(timestamp: &str) -> bool {
    let part = |start, end| timestamp.get(start..end)?.parse::<u32>().ok();
    let (Some(year), Some(month), Some(day)) = (part(0, 4), part(5, 7), part(8, 10)) else {
        return false;
    };
    let days = match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return false,
    };
    year > 0 && day > 0 && day <= days
}

/// Compile a complete canonical JSON value, not a caller-selected rule fragment.
/// The transport must use its existing duplicate-rejecting JSON parser. The
/// caller must separately authenticate the whole retained source before import.
pub fn compile_business_document(
    document: &Value,
) -> Result<CompiledBusinessDocument, BusinessDocumentError> {
    validate_tree(document, 0, &mut 0, false)?;
    let canonical_source =
        canonical_json_bytes(document).map_err(|_| BusinessDocumentError::InvalidDocument)?;
    if canonical_source.len() > MAX_BUSINESS_POLICY_DOCUMENT_BYTES {
        return Err(BusinessDocumentError::Bounds);
    }
    if !validator()?.is_valid(document) {
        return Err(BusinessDocumentError::InvalidDocument);
    }
    let spec = &document["spec"];
    let defaults = spec["defaults"]
        .as_object()
        .ok_or(BusinessDocumentError::InvalidDocument)?;
    if defaults.len() != 2 || defaults.get("mode").and_then(Value::as_str) != Some("enforce") {
        return Err(BusinessDocumentError::UnsupportedDefaults);
    }
    let default_action = defaults
        .get("defaultAction")
        .and_then(Value::as_str)
        .ok_or(BusinessDocumentError::UnsupportedDefaults)?;
    let mut ids = BTreeSet::new();
    let mut rules = Vec::new();
    for rule in spec["rules"]
        .as_array()
        .ok_or(BusinessDocumentError::InvalidDocument)?
    {
        for timestamp in [
            &rule["provenance"]["createdAt"],
            &rule["provenance"]["updatedAt"],
            &rule["lifetime"]["expiresAt"],
        ] {
            if timestamp
                .as_str()
                .is_some_and(|value| !valid_calendar_date(value))
            {
                return Err(BusinessDocumentError::InvalidDocument);
            }
        }
        let id = rule["id"]
            .as_str()
            .ok_or(BusinessDocumentError::InvalidDocument)?;
        if !ids.insert(id) {
            return Err(BusinessDocumentError::DuplicateRule);
        }
        // Validate every present business selector, even in inactive rules.
        let matcher = rule["match"]
            .as_object()
            .ok_or(BusinessDocumentError::InvalidDocument)?;
        let selector = matcher
            .get("business")
            .map(|value| {
                let bytes = serde_json::to_vec(value)
                    .map_err(|_| BusinessDocumentError::InvalidDocument)?;
                BusinessPolicyMatchV1::from_bounded_json(&bytes)
                    .map_err(|_| BusinessDocumentError::InvalidDocument)
            })
            .transpose()?;
        if rule["enabled"] == false || rule["effect"] == "ignore" {
            continue;
        }
        if matcher.len() != 1 {
            return Err(BusinessDocumentError::UnsupportedRule);
        }
        let selector = selector.ok_or(BusinessDocumentError::UnsupportedRule)?;
        let expires_at = match rule["lifetime"]["mode"].as_str() {
            Some("permanent") if rule["lifetime"]["expiresAt"].is_null() => None,
            Some("until") => {
                let expiry = rule["lifetime"]["expiresAt"]
                    .as_str()
                    .ok_or(BusinessDocumentError::InvalidDocument)?;
                if guard_contracts::canonical_policy_timestamp_nanos(expiry).is_none() {
                    return Err(BusinessDocumentError::InvalidDocument);
                }
                Some(expiry.to_owned())
            }
            _ => return Err(BusinessDocumentError::UnsupportedLifetime),
        };
        rules.push(BusinessPolicyRuleV1 {
            id: id.to_owned(),
            action: rule["effect"]
                .as_str()
                .ok_or(BusinessDocumentError::InvalidDocument)?
                .to_owned(),
            selector,
            expires_at,
        });
    }
    if rules.is_empty() {
        return Err(BusinessDocumentError::UnsupportedRule);
    }
    if rules.len() > crate::POLICY_SNAPSHOT_MAX_MAP_ENTRIES {
        return Err(BusinessDocumentError::Bounds);
    }
    let source_digest = digest_bytes(&canonical_source);
    let binding = BusinessPolicyBindingV1 {
        schema: BUSINESS_POLICY_BINDING_SCHEMA.to_owned(),
        version: 1,
        default_action: default_action.to_owned(),
        rules,
        source_document_digest: Some(source_digest.clone()),
        budgets: spec
            .get("budgets")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .map_err(|_| BusinessDocumentError::InvalidDocument)?,
    };
    binding
        .validate()
        .map_err(|_| BusinessDocumentError::InvalidDocument)?;
    Ok(CompiledBusinessDocument {
        source_digest,
        canonical_source,
        binding,
    })
}

#[cfg(test)]
#[path = "business_policy_document_tests.rs"]
mod tests;
