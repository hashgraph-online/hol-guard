//! The package-shim manifest (`<guard-home>/package-shims/manifest.json`).

use serde_json::{Map, Value};

use super::values::{py_json_dumps, string_items};
use super::{package_shim_command, ShimContext, ShimResult};

/// Whether and how the manifest could be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManifestState {
    Absent,
    Unreadable,
    Invalid,
    Valid,
}

impl ManifestState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Unreadable => "unreadable",
            Self::Invalid => "invalid",
            Self::Valid => "valid",
        }
    }
}

/// `_load_package_shim_manifest_with_state`.
pub(crate) fn load_with_state(
    context: &ShimContext,
) -> ShimResult<(Map<String, Value>, ManifestState)> {
    let facts = &context.facts;
    let path = context.manifest_path();
    if !facts.exists(&path) {
        return Ok((Map::new(), ManifestState::Absent));
    }
    let text = match facts.read_text(&path) {
        Ok(text) => text,
        Err(super::pyfs::ReadError::Io(_)) => return Ok((Map::new(), ManifestState::Unreadable)),
        Err(error) => return Err(error.message(&path)),
    };
    let Ok(payload) = serde_json::from_str::<Value>(&text) else {
        return Ok((Map::new(), ManifestState::Unreadable));
    };
    let Value::Object(map) = payload else {
        return Ok((Map::new(), ManifestState::Invalid));
    };
    let valid = match map.get("installed_managers") {
        Some(Value::Array(items)) if !items.is_empty() => items.iter().all(|item| {
            item.as_str()
                .is_some_and(|manager| package_shim_command(manager).is_some())
        }),
        _ => false,
    };
    if valid {
        Ok((map, ManifestState::Valid))
    } else {
        Ok((Map::new(), ManifestState::Invalid))
    }
}

/// `_load_package_shim_manifest`.
pub(crate) fn load(context: &ShimContext) -> ShimResult<Map<String, Value>> {
    Ok(load_with_state(context)?.0)
}

/// `_write_package_shim_manifest`.
pub(crate) fn write(context: &ShimContext, payload: &Map<String, Value>) -> ShimResult<()> {
    let text = py_json_dumps(&Value::Object(payload.clone()), true);
    context.facts.write_text(&context.manifest_path(), &text)
}

/// The supported managers listed under `installed_managers`.
pub(crate) fn installed_managers(manifest: &Map<String, Value>) -> Vec<String> {
    string_items(manifest.get("installed_managers"))
        .into_iter()
        .filter(|manager| package_shim_command(manager).is_some())
        .collect()
}

/// `_record_package_shim_test_results`.
pub(crate) fn record_test_results(
    context: &ShimContext,
    tested_managers: &[String],
) -> ShimResult<()> {
    let mut manifest = load(context)?;
    let mut last_tests = super::values::string_map(manifest.get("last_test_at"));
    for manager in tested_managers {
        last_tests.insert(manager.clone(), context.facts.now.clone());
    }
    let map: Map<String, Value> = last_tests
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect();
    manifest.insert("last_test_at".to_owned(), Value::Object(map));
    write(context, &manifest)
}

/// `_normalize_package_shim_managers`.
pub(crate) fn normalize_managers(managers: Option<&[String]>) -> Vec<String> {
    let Some(managers) = managers.filter(|items| !items.is_empty()) else {
        return super::package_shim_supported_managers()
            .into_iter()
            .map(str::to_owned)
            .collect();
    };
    let mut normalized: Vec<String> = Vec::new();
    for manager in managers {
        let key = super::values::py_strip(manager).to_lowercase();
        if package_shim_command(&key).is_some() && !normalized.contains(&key) {
            normalized.push(key);
        }
    }
    normalized
}
