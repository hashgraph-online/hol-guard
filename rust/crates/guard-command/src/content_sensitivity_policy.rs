//! Closed structured-output policy and managed authority-state resolution.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::structured::{self, Field};

pub(super) const SETTING: &str = "data_control.structured_output";
pub(super) const POLICY_VERSION: &str = "hol-guard-structured-output-policy.v1";

pub(super) fn harness(value: &str) -> String {
    let normalized = value.trim().to_lowercase().replace('_', "-");
    match normalized.as_str() {
        "pi-agent" | "pi-coding-agent" => "pi".into(),
        "oh-my-pi" => "omp".into(),
        _ => normalized,
    }
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{name} must be an object"))
}

fn exact_keys(object: &serde_json::Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn string_list(value: &Value, name: &str) -> Result<Vec<String>, String> {
    let values = value
        .as_array()
        .filter(|values| !values.is_empty())
        .ok_or_else(|| format!("{name} must be a non-empty array of strings"))?;
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let value = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{name} must be a non-empty array of strings"))?;
        if !seen.insert(value) {
            return Err(format!("{name} must not contain duplicates"));
        }
        found.push(value.to_owned());
    }
    Ok(found)
}

pub(super) fn parse(value: &Value) -> Result<Value, String> {
    let root = object(value, "structured output policy")?;
    if !exact_keys(
        root,
        &[
            "version",
            "enabled",
            "harnesses",
            "event",
            "destinationRole",
            "schema",
            "onMatch",
            "onUnsupported",
        ],
    ) {
        return Err("structured output policy has unknown or missing keys".into());
    }
    if root["version"] != POLICY_VERSION {
        return Err("structured output policy version is unsupported".into());
    }
    if root["enabled"] != Value::Bool(true) {
        return Err("structured output policy must be enabled".into());
    }
    let mut harnesses = string_list(&root["harnesses"], "structured output policy harnesses")?;
    if harnesses
        .iter()
        .any(|h| !matches!(h.as_str(), "pi" | "omp"))
    {
        return Err("structured output policy harness is unsupported".into());
    }
    if root["event"] != "PostToolUse" {
        return Err("structured output policy event is unsupported".into());
    }
    if root["destinationRole"] != "model_visible_tool_result" {
        return Err("structured output policy destination role is unsupported".into());
    }
    if root["onMatch"] != "withhold" || root["onUnsupported"] != "withhold" {
        return Err("structured output policy must withhold non-clean content".into());
    }
    let schema = object(&root["schema"], "structured output policy schema")?;
    if !exact_keys(schema, &["fields"]) {
        return Err("structured output policy schema has unknown or missing keys".into());
    }
    let fields = schema["fields"]
        .as_array()
        .filter(|fields| !fields.is_empty())
        .ok_or("structured output policy schema fields must be non-empty")?;
    let mut parsed = Vec::new();
    for (index, raw) in fields.iter().enumerate() {
        let name = format!("structured output policy schema field {index}");
        let field = object(raw, &name)?;
        let role = field
            .get("role")
            .and_then(Value::as_str)
            .filter(|role| matches!(*role, "protected_personal" | "ordinary"))
            .ok_or_else(|| format!("{name} role is invalid"))?;
        let keys = if role == "protected_personal" {
            vec!["path", "role", "valueType", "category"]
        } else {
            vec!["path", "role", "valueType"]
        };
        if !exact_keys(field, &keys) {
            return Err(format!("{name} has unknown or missing keys"));
        }
        let path = field["path"]
            .as_array()
            .filter(|path| !path.is_empty() && path.iter().all(Value::is_string))
            .ok_or_else(|| format!("{name} path is invalid"))?;
        let value_type = field["valueType"]
            .as_str()
            .filter(|kind| matches!(*kind, "string" | "integer"))
            .ok_or_else(|| format!("{name} value type is invalid"))?;
        let category = field.get("category").unwrap_or(&Value::Null);
        if !category.is_null()
            && !matches!(
                category.as_str(),
                Some("person_name" | "email_address" | "employee_id")
            )
        {
            return Err(format!("{name} category is invalid"));
        }
        let value = json!({"path":path,"role":role,"value_type":value_type,"category":category});
        // The original field constructor validates each field before schema uniqueness.
        structured::fields(&json!([value]))?;
        parsed.push(value);
    }
    let fields = structured::fields(&json!(parsed))?;
    harnesses.sort();
    Ok(json!({"harnesses":harnesses,"schema":{"fields":fields}}))
}

pub(super) fn field_list(policy: &Value) -> Result<Vec<Field>, &'static str> {
    structured::fields(&policy["schema"]["fields"]).map_err(|_| "content_policy_invalid")
}

fn hash(value: &Value) -> Option<&str> {
    value.as_str().filter(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn setting(settings: &Value) -> Option<&Value> {
    settings
        .as_object()?
        .get("data_control")?
        .as_object()?
        .get("structured_output")
}

fn resolution(binding: Value, required: bool, reason: Option<&str>) -> Value {
    json!({"binding":binding,"required":required,"reason_code":reason})
}

pub(super) fn resolve(config: &Value, raw_harness: &str) -> Result<Value, &'static str> {
    let harness = harness(raw_harness);
    if !matches!(harness.as_str(), "pi" | "omp") {
        return Ok(resolution(Value::Null, false, None));
    }
    let status = config["managed_policy_status"].as_str();
    let policy = &config["managed_policy"];
    let policy_hash = &config["managed_policy_hash"];
    let reserved = config["managed_locked_settings"]
        .as_array()
        .is_some_and(|names| names.iter().any(|name| name == SETTING));
    if matches!(status, Some("invalid" | "inaccessible" | "tampered")) {
        return Ok(resolution(
            Value::Null,
            true,
            Some("structured_managed_authority_unavailable"),
        ));
    }
    if matches!(status, Some("revoked" | "removed" | "expired" | "stale")) {
        return Ok(resolution(
            Value::Null,
            true,
            Some("structured_managed_authority_revoked"),
        ));
    }
    if !matches!(status, None | Some("absent" | "active")) {
        return Ok(resolution(
            Value::Null,
            true,
            Some("structured_managed_authority_unavailable"),
        ));
    }
    if status != Some("active") {
        let revoked = reserved || !policy.is_null() || !policy_hash.is_null();
        return Ok(resolution(
            Value::Null,
            revoked,
            revoked.then_some("structured_managed_authority_revoked"),
        ));
    }
    if !reserved {
        let invalid = setting(&policy["settings"]).is_some();
        return Ok(resolution(
            Value::Null,
            invalid,
            invalid.then_some("structured_managed_policy_invalid"),
        ));
    }
    if hash(policy_hash).is_none() {
        return Ok(resolution(
            Value::Null,
            true,
            Some("structured_managed_policy_invalid"),
        ));
    }
    if policy.is_null() {
        return Ok(resolution(
            Value::Null,
            true,
            Some("structured_managed_policy_missing"),
        ));
    }
    if hash(&policy["content_hash"]).is_none()
        || policy["content_hash"] != *policy_hash
        || !policy["settings"].is_object()
    {
        return Ok(resolution(
            Value::Null,
            true,
            Some("structured_managed_policy_invalid"),
        ));
    }
    let parsed = match parse(setting(&policy["settings"]).unwrap_or(&Value::Null)) {
        Ok(parsed) => parsed,
        Err(_) => {
            return Ok(resolution(
                Value::Null,
                true,
                Some("structured_managed_policy_invalid"),
            ))
        }
    };
    if !parsed["harnesses"]
        .as_array()
        .is_some_and(|names| names.iter().any(|name| name == &harness))
    {
        return Ok(resolution(Value::Null, false, None));
    }
    let fields = field_list(&parsed)?;
    let binding = json!({"harness":harness,"managed_policy_hash":policy_hash,"policy":parsed,
        "rule_version":structured::version(Some(&fields))?});
    Ok(resolution(binding, true, None))
}
