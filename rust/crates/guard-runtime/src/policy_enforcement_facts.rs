use super::{MAX_FACT_DEPTH, MAX_FACT_NODES, MAX_SELECTOR_VALUE_BYTES};
use guard_contracts::PreToolActionTypeV1;
use guard_secure_fs::sensitive_path_family;
use serde_json::{Map, Value};
use std::path::Path;

mod policy_enforcement_facts_tools;

pub(super) use policy_enforcement_facts_tools::{
    classify_tool_name, preferred_tool_name, risk_classes, tool_matches,
};

const PUBLISHER_KEYS: &[&str] = &[
    "publisher",
    "publisher_id",
    "publisherId",
    "publisher_name",
    "publisherName",
];
const ARTIFACT_KEYS: &[&str] = &[
    "artifact",
    "artifact_id",
    "artifactId",
    "package",
    "package_name",
    "packageName",
    "plugin_id",
    "pluginId",
    "extension_id",
    "extensionId",
    "skill_id",
    "skillId",
];
pub(super) const PATH_KEYS: &[&str] = &[
    "path",
    "file",
    "file_path",
    "filePath",
    "target_file",
    "targetFile",
    "target_directory",
    "targetDirectory",
];
const CHANGED_BOOL_KEYS: &[&str] = &[
    "changed",
    "hash_changed",
    "hashChanged",
    "changed_hash",
    "changedHash",
    "source_changed",
    "sourceChanged",
    "source_hash_changed",
    "sourceHashChanged",
    "content_changed",
    "contentChanged",
];
const CHANGED_CAPABILITY_KEYS: &[&str] = &["changed_capabilities", "changedCapabilities"];

#[derive(Debug, Default)]
pub(super) struct PolicyFacts {
    pub(super) publisher: Option<String>,
    pub(super) artifact: Option<String>,
    pub(super) changed_hash: bool,
    pub(super) sensitive_target: bool,
    pub(super) publisher_relevant: bool,
}

/// The same total order as the Python action lattice and the v3 snapshot
/// validator.  Keep this local to the native data plane so policy composition
/// cannot depend on a Python semantic helper.
pub(super) fn collect_fact_maps<'a>(
    value: &'a Value,
    depth: usize,
    nodes: &mut usize,
    output: &mut Vec<&'a Map<String, Value>>,
) -> Result<(), String> {
    if depth > MAX_FACT_DEPTH {
        return Err("native_policy_request_bounds_exceeded".to_owned());
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_FACT_NODES {
        return Err("native_policy_request_bounds_exceeded".to_owned());
    }
    match value {
        Value::Object(record) => {
            output.push(record);
            for child in record.values() {
                collect_fact_maps(child, depth.saturating_add(1), nodes, output)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_fact_maps(child, depth.saturating_add(1), nodes, output)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

pub(super) fn bounded_selector_value(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_SELECTOR_VALUE_BYTES
        || value.chars().count() > MAX_SELECTOR_VALUE_BYTES
    {
        return Err("native_policy_selector_invalid".to_owned());
    }
    Ok(value.to_owned())
}

pub(super) fn optional_identity(
    maps: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Option<String>, String> {
    let mut selected: Option<String> = None;
    for record in maps {
        for key in keys {
            let Some(value) = record.get(*key) else {
                continue;
            };
            // Some harnesses carry a full artifact/publisher object. It is not
            // an authenticated selector, so leave it unknown and apply the
            // conservative unknown-publisher floor instead of guessing.
            let Some(value) = value.as_str() else {
                if key.ends_with("_id") || key.ends_with("Id") {
                    return Err("native_policy_selector_invalid".to_owned());
                }
                continue;
            };
            let value = bounded_selector_value(value)?;
            if selected
                .as_deref()
                .is_some_and(|previous| previous != value)
            {
                return Err("native_policy_selector_conflict".to_owned());
            }
            selected = Some(value);
        }
    }
    Ok(selected)
}

pub(super) fn path_values_sensitive(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let mut sensitive = false;
    for record in maps {
        for key in PATH_KEYS {
            let Some(value) = record.get(*key) else {
                continue;
            };
            let values: Vec<&str> = match value {
                Value::String(value) => vec![value.as_str()],
                Value::Array(values) => values
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .ok_or_else(|| "native_policy_path_invalid".to_owned())
                    })
                    .collect::<Result<_, _>>()?,
                // An object under `file` or `path` is metadata, not a path
                // selector. The native source reader still validates it.
                Value::Object(_) | Value::Null | Value::Bool(_) | Value::Number(_) => continue,
            };
            sensitive |= values
                .into_iter()
                .any(|value| sensitive_path_family(Path::new(value)).is_some());
        }
    }
    Ok(sensitive)
}

pub(super) fn sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['_', '-'], "");
    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "privatekey",
        "apikey",
        "accesskey",
        "authorization",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

pub(super) fn payload_sensitive_target(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let mut sensitive = path_values_sensitive(maps)?;
    for record in maps {
        for (key, value) in *record {
            if key == "sensitive_target" {
                let value = value
                    .as_bool()
                    .ok_or_else(|| "native_policy_sensitive_target_invalid".to_owned())?;
                sensitive |= value;
            } else if sensitive_key(key) {
                sensitive = true;
            }
        }
    }
    Ok(sensitive)
}

pub(super) fn optional_changed_bool(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let mut selected: Option<bool> = None;
    let mut select = |value: bool| -> Result<(), String> {
        if selected.is_some_and(|previous| previous != value) {
            return Err("native_policy_changed_hash_conflict".to_owned());
        }
        selected = Some(value);
        Ok(())
    };
    for record in maps {
        for key in CHANGED_BOOL_KEYS {
            let Some(value) = record.get(*key) else {
                continue;
            };
            let value = value
                .as_bool()
                .ok_or_else(|| "native_policy_changed_hash_invalid".to_owned())?;
            select(value)?;
        }
        for key in CHANGED_CAPABILITY_KEYS {
            let Some(value) = record.get(*key) else {
                continue;
            };
            match value {
                Value::String(value) => {
                    let changed = value.trim().eq_ignore_ascii_case("changed_hash")
                        || value.trim().eq_ignore_ascii_case("hash_changed")
                        || value.trim().eq_ignore_ascii_case("source_changed");
                    if changed {
                        select(true)?;
                    }
                }
                Value::Array(values) => {
                    for item in values {
                        let item = item
                            .as_str()
                            .ok_or_else(|| "native_policy_changed_hash_invalid".to_owned())?;
                        if item.eq_ignore_ascii_case("changed_hash")
                            || item.eq_ignore_ascii_case("hash_changed")
                            || item.eq_ignore_ascii_case("source_changed")
                        {
                            select(true)?;
                        }
                    }
                }
                _ => return Err("native_policy_changed_hash_invalid".to_owned()),
            }
        }
    }
    Ok(selected.unwrap_or(false))
}

pub(super) fn optional_hash(
    maps: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Option<String>, String> {
    let mut selected: Option<String> = None;
    for record in maps {
        for key in keys {
            let Some(value) = record.get(*key) else {
                continue;
            };
            let Some(value) = value.as_str() else {
                return Err("native_policy_changed_hash_invalid".to_owned());
            };
            let value = bounded_selector_value(value)?;
            if selected
                .as_deref()
                .is_some_and(|previous| previous != value)
            {
                return Err("native_policy_changed_hash_conflict".to_owned());
            }
            selected = Some(value);
        }
    }
    Ok(selected)
}

pub(super) fn payload_changed_hash(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let explicit = optional_changed_bool(maps)?;
    let previous = optional_hash(
        maps,
        &["previous_hash", "previousHash", "prior_hash", "priorHash"],
    )?;
    let current = optional_hash(
        maps,
        &[
            "current_hash",
            "currentHash",
            "actual_hash",
            "actualHash",
            "source_hash",
            "sourceHash",
            "output_sha256",
            "outputSha256",
        ],
    )?;
    Ok(explicit || previous.is_some() && current.is_some() && previous != current)
}

pub(super) fn payload_facts(
    payload: &Value,
    action_type: PreToolActionTypeV1,
    reason_code: &str,
) -> Result<PolicyFacts, String> {
    let mut maps = Vec::new();
    let mut nodes = 0usize;
    collect_fact_maps(payload, 0, &mut nodes, &mut maps)?;
    let publisher = optional_identity(&maps, PUBLISHER_KEYS)?;
    let artifact = optional_identity(&maps, ARTIFACT_KEYS)?;
    let sensitive_target = payload_sensitive_target(&maps)?
        || reason_code.contains("secret")
        || reason_code.contains("credential")
        || reason_code.contains("exfiltration");
    let publisher_relevant = publisher.is_some()
        || artifact.is_some()
        || matches!(
            action_type,
            PreToolActionTypeV1::Package | PreToolActionTypeV1::McpTool
        );
    Ok(PolicyFacts {
        publisher,
        artifact,
        changed_hash: payload_changed_hash(&maps)?,
        sensitive_target,
        publisher_relevant,
    })
}
