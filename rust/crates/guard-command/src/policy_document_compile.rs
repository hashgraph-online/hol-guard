//! Portable local-row compilation and source export, preserving legacy order.

use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::Instant;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{failure, text, Error};

fn error(code: &str, id: &str) -> Error {
    failure(
        "PolicyCompilationError",
        &format!("{code}: {id}"),
        Some((code, id)),
    )
}

fn optional(value: &Value) -> Option<&str> {
    value.as_str().filter(|value| !value.is_empty())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn timestamp(value: &Value, id: &str, code: &str) -> Result<String, Error> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let value = value.as_str().ok_or_else(|| error(code, id))?;
    let value = crate::workspace_inventory::python_strip(value).replace("+00:00", "Z");
    let pattern = RE.get_or_init(|| {
        Regex::new(concat!(
            r"\A[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T",
            r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?Z\z"
        ))
        .expect("static timestamp pattern")
    });
    if pattern.is_match(&value) {
        Ok(value)
    } else {
        Err(error(code, id))
    }
}

fn expiry(value: &Value, id: &str, code: &str) -> Result<Value, Error> {
    if value.is_null() {
        Ok(Value::Null)
    } else {
        timestamp(value, id, code).map(Value::String)
    }
}

fn stable_id(row: &Value) -> Result<String, Error> {
    if let Some(id) = row["policy_rule_id"].as_str().filter(|id| identifier(id)) {
        return Ok(id.into());
    }
    if let Some(id) = row["decision_id"].as_number().filter(|value| {
        let value = value.to_string();
        !value.starts_with('-') && !value.contains(['.', 'e', 'E'])
    }) {
        return Ok(format!("local-{id}"));
    }
    let mut bytes = Vec::new();
    guard_contracts::write_canonical_json(row, &mut bytes)
        .map_err(|_| failure("TypeError", "unsupported_policy_row_value", None))?;
    Ok(format!(
        "local-{}",
        &hex::encode(Sha256::digest(bytes))[..24]
    ))
}

fn source(value: &Value) -> &'static str {
    match value.as_str() {
        Some("suggested-memory") => "suggested-memory",
        Some("review-decision") => "review-decision",
        Some("builder") => "builder",
        Some("import") => "import",
        Some("legacy") => "legacy",
        Some("cloud" | "cloud-sync") => "cloud",
        Some("policy-bundle") => "policy-bundle",
        Some("policy-yaml-import") => "import",
        _ => "local",
    }
}

fn prefix(value: &str, count: usize) -> String {
    value.chars().take(count).collect()
}

fn export_rule(row: &Value, provenance: bool) -> Result<Value, Error> {
    let id = stable_id(row)?;
    if optional(&row["workspace"]).is_some() && !provenance {
        return Err(error("sensitive_local_policy_requires_provenance", &id));
    }
    if !matches!(row["action"].as_str(), Some("allow" | "block")) {
        return Err(error("unsupported_local_policy_action", &id));
    }
    let expiry = expiry(&row["expires_at"], &id, "invalid_local_policy_expiry")?;
    let mut origin = json!({"source":if provenance {source(&row["source"])} else {"export-redacted"},
        "createdAt":if provenance {timestamp(&row["updated_at"], &id, "invalid_local_policy_timestamp")?}
            else {"1970-01-01T00:00:00Z".into()}});
    if provenance {
        if let Some(owner) = optional(&row["owner"]) {
            origin["createdBy"] = json!(prefix(owner, 256));
        }
    }
    let mut extension = Map::new();
    for (field, key) in [
        ("artifactHash", "artifact_hash"),
        ("harness", "harness"),
        ("publisher", "publisher"),
        ("scope", "scope"),
    ] {
        extension.insert(field.into(), row[key].clone());
    }
    if provenance {
        for (field, key) in [
            ("owner", "owner"),
            ("reason", "reason"),
            ("source", "source"),
            ("updatedAt", "updated_at"),
            ("workspace", "workspace"),
        ] {
            extension.insert(field.into(), row[key].clone());
        }
    }
    let mut matcher = Map::new();
    for (field, key) in [
        ("artifacts", "artifact_id"),
        ("harnesses", "harness"),
        ("publishers", "publisher"),
        ("workspaces", "workspace"),
    ] {
        if field == "workspaces" && !provenance {
            continue;
        }
        if let Some(value) =
            optional(&row[key]).filter(|value| field != "harnesses" || *value != "*")
        {
            matcher.insert(field.into(), json!([value]));
        }
    }
    let mut rule = json!({"id":id,"enabled":true,"effect":row["action"],"match":matcher,
        "lifetime":{"mode":if expiry.is_null() {"permanent"} else {"until"},"expiresAt":expiry},
        "provenance":origin,"x-hol-local":extension});
    if provenance {
        if let Some(reason) = optional(&row["reason"]) {
            rule["description"] = json!(prefix(reason, 4096));
        }
    }
    Ok(rule)
}

pub(super) fn rows(body: &Value, deadline: Instant) -> Result<Value, Error> {
    let id = body
        .get("document_id")
        .and_then(Value::as_str)
        .unwrap_or("local-policy");
    if !identifier(id) {
        return Err(failure("ValueError", "policy_document_id_invalid", None));
    }
    let rows = body["rows"]
        .as_array()
        .ok_or_else(|| failure("TypeError", "policy_rows_invalid", None))?;
    let mut ordered = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let mut material = Vec::new();
        guard_contracts::write_canonical_json(row, &mut material)
            .map_err(|_| failure("TypeError", "policy_rows_invalid", None))?;
        let number = super::values::IntegerOrder::from_value(&row["decision_id"]);
        let key = (
            number,
            text(row.get("harness").unwrap_or(&json!(""))),
            text(row.get("scope").unwrap_or(&json!(""))),
            text(row.get("artifact_id").unwrap_or(&json!(""))),
            material,
            index,
        );
        ordered.push((key, row));
    }
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    let mut rules = Vec::new();
    for (_, row) in ordered {
        if Instant::now() >= deadline {
            return Err(failure("ValueError", "policy_document_deadline", None));
        }
        rules.push(export_rule(row, body["include_provenance"] == true)?);
    }
    Ok(
        json!({"apiVersion":"guard.hashgraphonline.com/v1alpha1","kind":"GuardPolicy",
        "metadata":{"id":id,"name":prefix(body.get("name").and_then(Value::as_str)
            .unwrap_or("Local Guard policy"),256),"revision":body.get("revision").cloned().unwrap_or(json!(0))},
        "spec":{"defaults":{"mode":"prompt"},"rules":rules}}),
    )
}

fn selectors(matcher: &Value, key: &str, id: &str) -> Result<Vec<Value>, Error> {
    let value = &matcher[key];
    if value.is_null() {
        return Ok(vec![Value::Null]);
    }
    let values = value
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or_else(|| error("invalid_policy_match_selector", id))?;
    if !values.iter().all(|value| optional(value).is_some()) {
        return Err(error("invalid_policy_match_selector", id));
    }
    Ok(values.clone())
}

fn artifact_selectors(matcher: &Value, id: &str) -> Result<Vec<Value>, Error> {
    let artifacts = selectors(matcher, "artifacts", id)?;
    let tools = selectors(matcher, "tools", id)?;
    if tools != [Value::Null] && (artifacts != [Value::Null] || matcher.get("publishers").is_some())
    {
        return Err(error("unsupported_policy_match", id));
    }
    if tools == [Value::Null] {
        return Ok(artifacts);
    }
    tools
        .iter()
        .map(|tool| {
            let tool = tool.as_str().unwrap_or("").to_lowercase();
            let family = match tool.as_str() {
                "file-read" | "mcp" | "mcp-tool" | "package-request" | "prompt"
                | "prompt-env-read" | "prompt-file" | "tool-action" => tool.as_str(),
                "shell" => "tool-action",
                _ => return Err(error("unsupported_policy_match", id)),
            };
            Ok(json!(format!("family:{family}")))
        })
        .collect()
}

fn scope(
    extension: &Value,
    artifact: &Value,
    workspace: &Value,
    publisher: &Value,
    harness: &Value,
) -> String {
    if artifact
        .as_str()
        .is_some_and(|artifact| artifact.starts_with("family:"))
    {
        return if workspace.is_null() {
            "harness"
        } else {
            "workspace"
        }
        .into();
    }
    if let Some(preferred) = extension["scope"].as_str().filter(|value| {
        matches!(
            *value,
            "artifact" | "workspace" | "publisher" | "harness" | "global"
        )
    }) {
        return preferred.into();
    }
    if !artifact.is_null() {
        "artifact"
    } else if !workspace.is_null() {
        "workspace"
    } else if !publisher.is_null() {
        "publisher"
    } else if !harness.is_null() {
        "harness"
    } else {
        "global"
    }
    .into()
}

pub(super) fn compile(document: &Value, deadline: Instant) -> Result<Value, Error> {
    compile_range(document, deadline, 0, 10_000).map(|(items, _)| json!(items))
}

pub(super) fn page(body: &Value, deadline: Instant) -> Result<Value, Error> {
    let offset = body["offset"]
        .as_u64()
        .filter(|value| *value <= 10_000)
        .ok_or_else(|| failure("ValueError", "policy_document_page_invalid", None))?
        as usize;
    let limit = body["limit"]
        .as_u64()
        .filter(|value| (1..=32).contains(value))
        .ok_or_else(|| failure("ValueError", "policy_document_page_invalid", None))?
        as usize;
    let (items, total) = compile_range(&body["document"], deadline, offset, limit)?;
    if offset > total {
        return Err(failure("ValueError", "policy_document_page_invalid", None));
    }
    Ok(json!({"items":items,"offset":offset,"total":total}))
}

fn compile_range(
    document: &Value,
    deadline: Instant,
    offset: usize,
    limit: usize,
) -> Result<(Vec<Value>, usize), Error> {
    let id = document["metadata"]["id"].as_str().unwrap_or("");
    let spec = document["spec"]
        .as_object()
        .ok_or_else(|| error("invalid_policy_spec", id))?;
    if spec.contains_key("budgets") {
        return Err(error("unsupported_policy_budgets", id));
    }
    let rules = spec
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| error("invalid_policy_rules", id))?;
    let mut result = Vec::new();
    let mut total = 0usize;
    let supported = BTreeSet::from([
        "artifacts",
        "harnesses",
        "publishers",
        "tools",
        "workspaces",
    ]);
    for rule in rules {
        if Instant::now() >= deadline {
            return Err(failure("ValueError", "policy_document_deadline", None));
        }
        let id = rule["id"].as_str().unwrap_or("unknown");
        if !rule["enabled"].is_boolean() {
            return Err(error("invalid_policy_enabled", id));
        }
        if rule["enabled"] == false {
            continue;
        }
        if !matches!(rule["effect"].as_str(), Some("allow" | "block")) {
            return Err(error("unsupported_policy_effect", id));
        }
        if !matches!(
            rule["lifetime"]["mode"].as_str(),
            Some("permanent" | "until")
        ) {
            return Err(error("unsupported_policy_lifetime", id));
        }
        let matcher = rule["match"]
            .as_object()
            .ok_or_else(|| error("unsupported_policy_match", id))?;
        if matcher.get("commands").is_some_and(Value::is_object) {
            return Err(error("command_expression_requires_guard_3_1_runtime", id));
        }
        if matcher.iter().any(|(key, value)| {
            !key.starts_with("x-")
                && !supported.contains(key.as_str())
                && !value.is_null()
                && value != &json!([])
        }) {
            return Err(error("unsupported_policy_match", id));
        }
        let matcher = &rule["match"];
        let artifacts = artifact_selectors(matcher, id)?;
        let harnesses = selectors(matcher, "harnesses", id)?;
        let publishers = selectors(matcher, "publishers", id)?;
        let workspaces = selectors(matcher, "workspaces", id)?;
        let extension = if rule["x-hol-local"].is_object() {
            rule["x-hol-local"].clone()
        } else {
            json!({})
        };
        let provenance = if rule["provenance"].is_object() {
            rule["provenance"].clone()
        } else {
            json!({})
        };
        let mut bytes = Vec::new();
        guard_contracts::write_canonical_json(&provenance, &mut bytes)
            .map_err(|_| failure("TypeError", "policy_provenance_invalid", None))?;
        let provenance_json = String::from_utf8(bytes)
            .map_err(|_| failure("TypeError", "policy_provenance_invalid", None))?;
        let expires = expiry(
            if rule["lifetime"]["mode"] == "until" {
                &rule["lifetime"]["expiresAt"]
            } else {
                &Value::Null
            },
            id,
            "invalid_policy_expiry",
        )?;
        for artifact in &artifacts {
            for harness in &harnesses {
                for publisher in &publishers {
                    for workspace in &workspaces {
                        if total >= 10_000 {
                            return Err(error("policy_compilation_limit", id));
                        }
                        if Instant::now() >= deadline {
                            return Err(failure("ValueError", "policy_document_deadline", None));
                        }
                        if (offset..offset + limit).contains(&total) {
                            result.push(json!({"decision":{"harness":harness.as_str().unwrap_or("*"),
                "scope":scope(&extension,artifact,workspace,publisher,harness),"action":rule["effect"],
                "artifact_id":artifact,"artifact_hash":optional(&extension["artifactHash"]),
                "workspace":workspace,"publisher":publisher,"reason":optional(&rule["description"]),
                "owner":optional(&provenance["createdBy"]),"source":"policy-yaml-import","expires_at":optional(&expires)},
                "rule_id":id,"provenance_json":provenance_json}));
                        }
                        total += 1;
                    }
                }
            }
        }
    }
    Ok((result, total))
}
