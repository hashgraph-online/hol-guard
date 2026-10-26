//! PATH-order analysis: does the shim directory precede the real binary?

use serde_json::{json, Map, Value};

use super::{
    package_shim_command, package_shim_supported_managers, ShimContext, ShimFacts, ShimResult,
};

fn has_package_shim_layout(facts: &ShimFacts, candidate: &str) -> bool {
    let parent = facts.parent(candidate);
    facts.name(&parent) == "bin" && facts.name(&facts.parent(&parent)) == "package-shims"
}

fn is_trusted_package_shim_binary(
    facts: &ShimFacts,
    candidate: &str,
    trusted_shim_dir: &str,
) -> ShimResult<bool> {
    let resolved = facts.resolve(candidate)?;
    let inside = facts.is_within(&resolved, trusted_shim_dir);
    Ok(inside && facts.is_file(candidate))
}

fn is_foreign_package_shim_binary(
    facts: &ShimFacts,
    candidate: &str,
    trusted_shim_dir: &str,
) -> ShimResult<bool> {
    Ok(has_package_shim_layout(facts, candidate)
        && !is_trusted_package_shim_binary(facts, candidate, trusted_shim_dir)?)
}

fn index_value(index: Option<usize>) -> Value {
    index.map_or(Value::Null, |value| json!(value))
}

/// `get_path_order_status`.
pub fn get_path_order_status(
    context: &ShimContext,
    manager: &str,
    path_env: Option<&str>,
) -> ShimResult<Map<String, Value>> {
    let facts = &context.facts;
    let Some(command) = package_shim_command(manager) else {
        return Ok(object(json!({
            "shim_precedes_real": false,
            "real_binary_found": false,
            "path_broken": true,
            "shim_dir": null,
        })));
    };
    let shim_dir = facts.resolve(&facts.expanduser(&context.shim_dir())?)?;
    let shim_path = facts.join(&shim_dir, command);
    let effective_path = context.search_path(path_env);
    let mut shim_dir_index: Option<usize> = None;
    let mut real_dir_index: Option<usize> = None;
    let mut foreign_shim_index: Option<usize> = None;
    let mut foreign_shim_path: Option<String> = None;
    let mut real_binary_path: Option<String> = None;
    for (index, entry) in effective_path.split(context.pathsep()).enumerate() {
        let directory = facts.resolve(&facts.expanduser(entry)?)?;
        if facts.path_eq(&directory, &shim_dir) && shim_dir_index.is_none() {
            shim_dir_index = Some(index);
            continue;
        }
        let candidate = facts.join(&directory, command);
        if !facts.exists(&candidate)
            || !facts.is_file(&candidate)
            || facts.path_eq(&candidate, &shim_path)
        {
            continue;
        }
        if is_foreign_package_shim_binary(facts, &candidate, &shim_dir)? {
            if foreign_shim_index.is_none() {
                foreign_shim_index = Some(index);
                foreign_shim_path = Some(candidate);
            }
            continue;
        }
        if is_trusted_package_shim_binary(facts, &candidate, &shim_dir)? {
            continue;
        }
        if real_dir_index.is_none() {
            real_dir_index = Some(index);
            real_binary_path = Some(candidate);
        }
    }
    let foreign_precedes = matches!(
        (foreign_shim_index, shim_dir_index),
        (Some(foreign), Some(shim)) if foreign < shim
    );
    let foreign_path = foreign_shim_path.map_or(Value::Null, Value::String);
    let real_path = real_binary_path.map_or(Value::Null, Value::String);
    let Some(shim_index) = shim_dir_index else {
        return Ok(object(json!({
            "shim_precedes_real": false,
            "real_binary_found": real_dir_index.is_some(),
            "real_binary_path": real_path,
            "real_binary_path_index": index_value(real_dir_index),
            "shim_in_path": false,
            "shim_path_index": null,
            "path_broken": true,
            "foreign_shim_bypass": foreign_shim_index.is_some(),
            "foreign_shim_path": foreign_path,
            "foreign_shim_path_index": index_value(foreign_shim_index),
            "shim_dir": shim_dir,
        })));
    };
    if foreign_precedes {
        return Ok(object(json!({
            "shim_precedes_real": false,
            "real_binary_found": real_dir_index.is_some(),
            "real_binary_path": real_path,
            "real_binary_path_index": index_value(real_dir_index),
            "shim_in_path": true,
            "shim_path_index": shim_index,
            "path_broken": true,
            "foreign_shim_bypass": true,
            "foreign_shim_path": foreign_path,
            "foreign_shim_path_index": index_value(foreign_shim_index),
            "shim_dir": shim_dir,
        })));
    }
    let Some(real_index) = real_dir_index else {
        return Ok(object(json!({
            "shim_precedes_real": true,
            "real_binary_found": false,
            "real_binary_path": null,
            "real_binary_path_index": null,
            "shim_in_path": true,
            "shim_path_index": shim_index,
            "path_broken": false,
            "foreign_shim_bypass": false,
            "foreign_shim_path": foreign_path,
            "foreign_shim_path_index": index_value(foreign_shim_index),
            "shim_dir": shim_dir,
        })));
    };
    let precedes = shim_index < real_index;
    Ok(object(json!({
        "shim_precedes_real": precedes,
        "real_binary_found": true,
        "real_binary_path": real_path,
        "real_binary_path_index": real_index,
        "shim_in_path": true,
        "shim_path_index": shim_index,
        "path_broken": !precedes,
        "foreign_shim_bypass": false,
        "foreign_shim_path": foreign_path,
        "foreign_shim_path_index": index_value(foreign_shim_index),
        "shim_dir": shim_dir,
    })))
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// `_filtered_manager_path`.
fn filtered_manager_path(context: &ShimContext, path_env: Option<&str>) -> String {
    let facts = &context.facts;
    let shim_dir_abs = facts.expanded_abspath(&context.shim_dir());
    let effective_path = context.search_path(path_env);
    let separator = context.pathsep();
    effective_path
        .split(separator)
        .filter(|entry| !entry.is_empty() && facts.expanded_abspath(entry) != shim_dir_abs)
        .collect::<Vec<_>>()
        .join(&separator.to_string())
}

/// `_detect_system_package_managers`: managers with and without a real binary.
pub(crate) fn detect_system_package_managers(
    context: &ShimContext,
    path_env: Option<&str>,
) -> (Vec<String>, Vec<String>) {
    let filtered = filtered_manager_path(context, path_env);
    if filtered.is_empty() {
        return (
            Vec::new(),
            package_shim_supported_managers()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        );
    }
    let mut detected = Vec::new();
    let mut undetected = Vec::new();
    for manager in package_shim_supported_managers() {
        if context.facts.which(manager, &filtered).is_some() {
            detected.push(manager.to_owned());
        } else {
            undetected.push(manager.to_owned());
        }
    }
    (detected, undetected)
}
