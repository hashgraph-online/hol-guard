//! Allowlisted Cloud projection. Detector text and paths never enter the wire.
use super::{encode, Error, Result, MAX_ENTRY};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn string(value: &Value, key: &str, max: usize) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.chars().count() <= max)
        .map(str::to_owned)
        .ok_or(Error::Invalid)
}

fn array(value: &Value, key: &str) -> Result<Value> {
    strings(value, key, false)
}

fn strings(value: &Value, key: &str, deduplicate: bool) -> Result<Value> {
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or(Error::Invalid)?;
    if !deduplicate && items.len() > 128 {
        return Err(Error::Invalid);
    }
    let mut sorted = BTreeSet::new();
    for item in items {
        let s = item
            .as_str()
            .filter(|s| !s.is_empty() && s.chars().count() <= 8192)
            .ok_or(Error::Invalid)?;
        if !sorted.insert(s.to_owned()) && !deduplicate {
            return Err(Error::Invalid);
        }
    }
    if sorted.len() > 128 {
        return Err(Error::Invalid);
    }
    Ok(json!(sorted))
}

pub fn identity(id: &str) -> bool {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    id.len() <= 256
        && PATTERN
            .get_or_init(|| {
                regex::Regex::new(r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$").expect("static regex")
            })
            .is_match(id)
}

/// Raw metadata is accepted only from authenticated discovery/active adapters.
/// This is a projection, not an activation or signed-cloud authority factory.
pub fn project(raw: &Value) -> Result<Value> {
    let id = string(raw, "extension_id", 256)?;
    let permissions = raw
        .get("permissions")
        .and_then(Value::as_array)
        .ok_or(Error::Invalid)?;
    let mut output = Vec::new();
    for p in permissions {
        if p.get("extension_id").and_then(Value::as_str) != Some(&id) {
            return Err(Error::Invalid);
        }
        let configurable = p
            .get("configurable")
            .and_then(Value::as_bool)
            .ok_or(Error::Invalid)?;
        output.push(
            json!({"id": string(p,"permission_id",256)?, "name": string(p,"label",8192)?,
            "configurable":configurable,"required":!configurable,
            "riskClasses":[string(p,"risk_tier",8192)?],
            "typedCapabilities":strings(p,"typed_capabilities",true)?}),
        );
    }
    validate(
        &json!({"id":id,"version":string(raw,"version",128)?,"name":string(raw,"name",8192)?,
        "source":string(raw,"source",128)?,"executables":strings(raw,"executables",true)?,
        "ecosystemIds":strings(raw,"ecosystem_ids",true)?,
        "riskClasses":strings(raw,"risk_classes",true)?,
        "delegatedProtection":raw.get("delegated_protection").unwrap_or(&Value::Null),
        "deprecated":false,"replacementId":null,"permissions":output}),
    )
}

/// Strict wire entry seam for native contract tests and bounded legacy input.
pub fn validate(raw: &Value) -> Result<Value> {
    let fields = [
        "id",
        "version",
        "name",
        "source",
        "executables",
        "ecosystemIds",
        "riskClasses",
        "delegatedProtection",
        "deprecated",
        "replacementId",
        "permissions",
    ];
    exact(raw, &fields)?;
    let id = string(raw, "id", 256)?;
    if !identity(&id) {
        return Err(Error::Invalid);
    }
    let source = string(raw, "source", 128)?;
    if !["built-in", "local-admin", "custom"].contains(&source.as_str()) {
        return Err(Error::Invalid);
    }
    if !raw["delegatedProtection"].is_null() && raw["delegatedProtection"] != "package-firewall" {
        return Err(Error::Invalid);
    }
    let deprecated = raw["deprecated"].as_bool().ok_or(Error::Invalid)?;
    if !raw["replacementId"].is_null() {
        let replacement = raw["replacementId"].as_str().ok_or(Error::Invalid)?;
        if !deprecated || replacement == id || !identity(replacement) {
            return Err(Error::Invalid);
        }
    }
    let permissions = raw["permissions"]
        .as_array()
        .filter(|p| p.len() <= 512)
        .ok_or(Error::Invalid)?;
    let mut output = Vec::new();
    for p in permissions {
        exact(
            p,
            &[
                "id",
                "name",
                "configurable",
                "required",
                "riskClasses",
                "typedCapabilities",
            ],
        )?;
        let pid = string(p, "id", 256)?;
        let prefix = format!("{id}.permission.");
        if !identity(&pid) || !pid.starts_with(&prefix) || pid.len() == prefix.len() {
            return Err(Error::Invalid);
        }
        output.push(json!({"id":pid,"name":string(p,"name",8192)?,
            "configurable":p["configurable"].as_bool().ok_or(Error::Invalid)?,
            "required":p["required"].as_bool().ok_or(Error::Invalid)?,
            "riskClasses":array(p,"riskClasses")?,"typedCapabilities":array(p,"typedCapabilities")?}));
    }
    output.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    if output.windows(2).any(|p| p[0]["id"] == p[1]["id"]) {
        return Err(Error::Invalid);
    }
    let result = json!({"id":id,"version":string(raw,"version",128)?,"name":string(raw,"name",8192)?,
        "source":source,"executables":array(raw,"executables")?,"ecosystemIds":array(raw,"ecosystemIds")?,
        "riskClasses":array(raw,"riskClasses")?,"delegatedProtection":raw["delegatedProtection"],
        "deprecated":deprecated,"replacementId":raw["replacementId"],"permissions":output});
    if encode(&result)?.len() > MAX_ENTRY {
        return Err(Error::Limit);
    }
    Ok(result)
}

fn exact(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or(Error::Invalid)?;
    if object.len() != fields.len() || fields.iter().any(|f| !object.contains_key(*f)) {
        return Err(Error::Invalid);
    }
    Ok(())
}
