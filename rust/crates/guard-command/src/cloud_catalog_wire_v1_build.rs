//! Cloud v1 Extension catalog projection: a raw registry's Extensions reduced
//! to the privacy-safe wire fields, sorted, bounded and validated.
use super::{
    canonical, catalog_digest, invalid, limit, limits, reject_private_keys, sorted_by_id, validate,
    Outcome, CONTROL_SCHEMA, MAX_EXTENSIONS, MAX_PAYLOAD_BYTES, MAX_PERMISSIONS, SCHEMA,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn code_unit_sorted(value: Option<&Value>, label: &str) -> Outcome<Value> {
    let items = value.and_then(Value::as_array);
    let mut sorted = BTreeSet::new();
    for item in items.into_iter().flatten() {
        let Some(text) = item.as_str() else {
            return invalid(format!("Invalid Extension catalog {label}"));
        };
        sorted.insert(text.to_owned());
    }
    if items.is_none() {
        return invalid(format!("Invalid Extension catalog {label}"));
    }
    // UTF-8 byte order equals the code-point order the shared contract uses.
    Ok(json!(sorted))
}

fn field(raw: &Value, key: &str) -> Value {
    raw.get(key).cloned().unwrap_or(Value::Null)
}

fn project_permission(raw: &Value) -> Outcome<Value> {
    let configurable = field(raw, "configurable");
    let required = Value::Bool(!configurable.as_bool().unwrap_or(true));
    Ok(json!({
        "id": field(raw, "permission_id"), "name": field(raw, "label"),
        "configurable": configurable, "required": required,
        "riskClasses": [field(raw, "risk_tier")],
        "typedCapabilities": code_unit_sorted(raw.get("typed_capabilities"), "permission typedCapabilities")?,
    }))
}

fn project_extension(raw: &Value) -> Outcome<Value> {
    let Some(raw_permissions) = raw.get("permissions").and_then(Value::as_array) else {
        return invalid("Extension catalog permission limit exceeded");
    };
    let permissions = raw_permissions
        .iter()
        .map(project_permission)
        .collect::<Outcome<Vec<_>>>()?;
    if permissions.len() > MAX_PERMISSIONS {
        return limit("Extension catalog permission limit exceeded");
    }
    Ok(json!({
        "id": field(raw, "extension_id"), "version": field(raw, "version"),
        "name": field(raw, "name"), "source": field(raw, "source"),
        "executables": code_unit_sorted(raw.get("executables"), "executables")?,
        "ecosystemIds": code_unit_sorted(raw.get("ecosystem_ids"), "ecosystemIds")?,
        "riskClasses": code_unit_sorted(raw.get("risk_classes"), "riskClasses")?,
        "delegatedProtection": field(raw, "delegated_protection"),
        "deprecated": false, "replacementId": null,
        "permissions": sorted_by_id(&permissions),
    }))
}

/// Project raw registry Extensions without detector, command, path, or secret data.
pub fn build(raw_extensions: &Value, guard_version: &str, generated_at: &str) -> Outcome<Value> {
    let Some(items) = raw_extensions.as_array() else {
        return invalid("Invalid Extension catalog extensions");
    };
    let projected = items
        .iter()
        .map(project_extension)
        .collect::<Outcome<Vec<_>>>()?;
    if projected.len() > MAX_EXTENSIONS {
        return limit("Extension catalog limit exceeded");
    }
    let extensions = Value::Array(sorted_by_id(&projected));
    let payload = json!({
        "schemaVersion": SCHEMA, "catalogDigest": catalog_digest(&extensions)?,
        "guardVersion": guard_version, "controlSchemaVersion": CONTROL_SCHEMA,
        "generatedAt": generated_at, "limits": limits(), "extensions": extensions,
    });
    reject_private_keys(&payload)?;
    if canonical(&payload).len() > MAX_PAYLOAD_BYTES {
        return limit("Extension catalog payload limit exceeded");
    }
    validate(&payload)
}
