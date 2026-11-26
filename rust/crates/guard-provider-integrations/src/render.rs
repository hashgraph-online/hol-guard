//! Request bodies built from declared fields only.
//!
//! A capability declares its body as a list of `(field, fact)` pairs. The body is a JSON object with
//! exactly those fields, in declared order, each holding the named fact of the action under review.
//! A fact the action does not carry, or carries in a shape a provider may not receive, refuses the
//! whole body: a partial request never leaves the machine. Facts the capability does not name are
//! never read.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// The longest string fact a body may carry.
pub const MAX_FACT_BYTES: usize = 2048;

/// The most strings an array fact may carry.
pub const MAX_FACT_ITEMS: usize = 32;

/// The most fields one body may declare.
pub const MAX_BODY_FIELDS: usize = 16;

/// Why a body could not be rendered. Carries the field name only, never a fact value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// More fields than `MAX_BODY_FIELDS`, or an empty field name.
    FieldsInvalid,
    /// Two declared fields share a name.
    DuplicateField(String),
    /// The action has no fact for this field.
    FactMissing(String),
    /// The fact is not a bounded string or a bounded array of bounded strings.
    FactInvalid(String),
}

impl RenderError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::FieldsInvalid => "provider_body_fields_invalid",
            Self::DuplicateField(_) => "provider_body_field_duplicate",
            Self::FactMissing(_) => "provider_body_fact_missing",
            Self::FactInvalid(_) => "provider_body_fact_invalid",
        }
    }
}

fn is_bounded_fact(value: &Value) -> bool {
    match value {
        Value::String(text) => text.len() <= MAX_FACT_BYTES,
        Value::Array(items) => {
            items.len() <= MAX_FACT_ITEMS
                && items.iter().all(|item| {
                    item.as_str()
                        .is_some_and(|text| text.len() <= MAX_FACT_BYTES)
                })
        }
        _ => false,
    }
}

/// Render the body for `fields` from `facts`.
pub fn render_body(
    fields: &[(&str, &str)],
    facts: &BTreeMap<String, Value>,
) -> Result<String, RenderError> {
    if fields.len() > MAX_BODY_FIELDS || fields.iter().any(|(field, _)| field.is_empty()) {
        return Err(RenderError::FieldsInvalid);
    }
    let mut seen = BTreeSet::new();
    let mut parts = Vec::with_capacity(fields.len());
    for (field, fact) in fields {
        if !seen.insert(*field) {
            return Err(RenderError::DuplicateField((*field).to_owned()));
        }
        let Some(value) = facts.get(*fact) else {
            return Err(RenderError::FactMissing((*field).to_owned()));
        };
        if !is_bounded_fact(value) {
            return Err(RenderError::FactInvalid((*field).to_owned()));
        }
        let key = serde_json::to_string(field).map_err(|_| RenderError::FieldsInvalid)?;
        let value = serde_json::to_string(value)
            .map_err(|_| RenderError::FactInvalid((*field).to_owned()))?;
        parts.push(format!("{key}:{value}"));
    }
    Ok(format!("{{{}}}", parts.join(",")))
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod tests;
