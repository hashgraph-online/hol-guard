//! Package-shim status, dashboard projection and cloud coverage.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::frozen::classify_integrity;
use super::generate::build_package_manager_python_shim;
use super::manifest::{installed_managers, load_with_state};
use super::path_order::{detect_system_package_managers, get_path_order_status};
use super::profile::{path_export_hints, profile_status};
use super::values::{dict_items, py_strip, string_items, string_map};
use super::{
    package_shim_command, package_shim_supported_managers, ShimContext, ShimFacts, ShimResult,
};

const MAX_RECOVERABLE_SHIM_BYTES: u64 = 512 * 1024;
const PACKAGE_SHIM_SOURCE_MARKERS: [&str; 3] = [
    "--package-shim-ui",
    "package_shim_command_requires_guard",
    "from codex_plugin_scanner.guard.package_shim_gate import (",
];

fn activation_path_status(
    installed: &[String],
    path_contains_shim_dir: bool,
    profile_configured: bool,
) -> &'static str {
    if !installed.is_empty() && path_contains_shim_dir {
        "in_path"
    } else if !installed.is_empty() && profile_configured {
        "restart_required"
    } else {
        "missing_from_path"
    }
}

fn flag(map: &Map<String, Value>, key: &str) -> bool {
    match map.get(key) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(items)) => !items.is_empty(),
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
    }
}

/// `package_shim_status`.
pub fn package_shim_status(
    context: &ShimContext,
    path_env: Option<&str>,
) -> ShimResult<Map<String, Value>> {
    let facts = &context.facts;
    let (manifest, manifest_state) = load_with_state(context)?;
    let installed = installed_managers(&manifest);
    let last_test_at = match manifest.get("last_test_at") {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    let (detected, undetected) = detect_system_package_managers(context, path_env);
    let shim_dir = context.shim_dir();
    let stored_hashes = string_map(manifest.get("content_hashes"));
    let mut active: Vec<String> = Vec::new();
    let mut protected: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut bypasses: Vec<Value> = Vec::new();
    let mut details: Vec<Value> = Vec::new();
    let effective_path = path_env.unwrap_or_else(|| context.env_path());
    let resolved_shim_dir = facts.resolve(&facts.expanduser(&shim_dir)?)?;
    let mut path_contains_shim_dir = false;
    for entry in effective_path
        .split(context.pathsep())
        .filter(|entry| !entry.is_empty())
    {
        if facts.path_eq(
            &facts.resolve(&facts.expanduser(entry)?)?,
            &resolved_shim_dir,
        ) {
            path_contains_shim_dir = true;
            break;
        }
    }
    for manager in &installed {
        let command = package_shim_command(manager).unwrap_or(manager);
        let shim_path = facts.join(&shim_dir, command);
        let exists = facts.exists(&shim_path);
        let path_status = get_path_order_status(context, manager, path_env)?;
        let integrity = if exists {
            active.push(manager.clone());
            let source = build_package_manager_python_shim(context, command)?;
            let wrapper = facts
                .read_bytes(&shim_path)
                .map_err(|error| error.message(&shim_path))?;
            classify_integrity(
                facts,
                &source,
                &shim_dir,
                command,
                &wrapper,
                stored_hashes.get(manager).map(String::as_str),
            )?
        } else {
            missing.push(manager.clone());
            "missing"
        };
        details.push(json!({
            "integrity": integrity,
            "last_test_at": last_test_at.get(manager).cloned().unwrap_or(Value::Null),
            "manager": manager,
            "path_active": flag(&path_status, "shim_precedes_real"),
            "path_index": path_status.get("shim_path_index").cloned().unwrap_or(Value::Null),
            "path_status": Value::Object(path_status.clone()),
            "real_binary_found": flag(&path_status, "real_binary_found"),
            "real_binary_path": path_status.get("real_binary_path").cloned().unwrap_or(Value::Null),
            "real_binary_path_index": path_status
                .get("real_binary_path_index")
                .cloned()
                .unwrap_or(Value::Null),
            "shim_path": shim_path,
            "system_binary_detected": detected.contains(manager),
        }));
        if exists && flag(&path_status, "shim_precedes_real") {
            protected.push(manager.clone());
        } else if exists {
            let reason = if flag(&path_status, "foreign_shim_bypass") {
                "foreign_shim_bypass"
            } else {
                "path_inactive"
            };
            bypasses.push(json!({ "manager": manager, "reason": reason }));
        }
    }
    let profile = profile_status(context)?;
    let profile_configured = flag(&profile, "shell_profile_configured");
    let path_active = !installed.is_empty() && protected.len() == installed.len();
    let activation = activation_path_status(&installed, path_contains_shim_dir, profile_configured);
    let process_path_status = if path_contains_shim_dir {
        "active"
    } else if activation == "restart_required" {
        "profile_staged"
    } else {
        "missing"
    };
    let supported: Vec<&str> = package_shim_supported_managers();
    let status = json!({
        "active_managers": active,
        "detected_managers": detected,
        "installed_managers": installed,
        "last_test_at": Value::Object(last_test_at),
        "protected_managers": protected,
        "path_active": path_active,
        "path_contains_shim_dir": path_contains_shim_dir,
        "path_status": activation,
        "bypasses": bypasses,
        "manager_details": details,
        "manifest_state": manifest_state.as_str(),
        "manifest_path": context.manifest_path(),
        "missing_managers": missing,
        "restart_shell_required": activation == "restart_required",
        "process_path_status": process_path_status,
        "process_restart_required": activation == "restart_required",
        "shell_profile_configured": profile_configured,
        "shell_profile_path": profile.get("shell_profile_path").cloned().unwrap_or(Value::Null),
        "shell_profile_paths": profile.get("shell_profile_paths").cloned().unwrap_or(Value::Null),
        "shell_profile_missing_paths": profile
            .get("shell_profile_missing_paths")
            .cloned()
            .unwrap_or(Value::Null),
        "shell_hints": path_export_hints(&shim_dir),
        "shim_dir": shim_dir,
        "supported_managers": supported,
        "undetected_managers": undetected,
    });
    let Value::Object(status) = status else {
        return Ok(Map::new());
    };
    enrich_status(facts, status, &manifest)
}

/// `str(value)` list filter used by the enrichment helpers.
fn string_list(value: Option<&Value>) -> Vec<String> {
    string_items(value)
}

/// `_recoverable_package_shim_managers`.
fn recoverable_managers(facts: &ShimFacts, status: &Map<String, Value>) -> Vec<String> {
    let supported = string_list(status.get("supported_managers"));
    let shim_dir_value = match status.get("shim_dir") {
        Some(Value::String(text)) if !py_strip(text).is_empty() => text.clone(),
        _ => return Vec::new(),
    };
    if supported.is_empty() {
        return Vec::new();
    }
    let Ok(shim_dir) = facts
        .expanduser(&shim_dir_value)
        .and_then(|expanded| facts.resolve(&expanded))
    else {
        return Vec::new();
    };
    if !facts.exists(&shim_dir) || !facts.is_dir(&shim_dir) {
        return Vec::new();
    }
    let mut recovered: BTreeSet<String> = BTreeSet::new();
    for manager in supported {
        let candidate = facts.join(&shim_dir, &manager);
        if facts.is_symlink(&candidate) || !facts.is_file(&candidate) {
            continue;
        }
        let Ok(resolved) = facts.resolve(&candidate) else {
            continue;
        };
        if !facts.exists(&resolved) || !facts.path_eq(&facts.parent(&resolved), &shim_dir) {
            continue;
        }
        let too_large = std::fs::metadata(facts.fs_path(&resolved))
            .map(|meta| meta.len() > MAX_RECOVERABLE_SHIM_BYTES)
            .unwrap_or(true);
        if too_large {
            continue;
        }
        let Ok(source) = facts.read_text(&resolved) else {
            continue;
        };
        if !source.contains(&format!(
            "command_name = {}",
            crate::hook_adapter_pytext::py_repr_str(&manager)
        )) {
            continue;
        }
        if PACKAGE_SHIM_SOURCE_MARKERS
            .iter()
            .all(|marker| source.contains(marker))
        {
            recovered.insert(manager);
        }
    }
    recovered.into_iter().collect()
}

fn text_or(status: &Map<String, Value>, key: &str, default: &str) -> String {
    match status.get(key) {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => default.to_owned(),
    }
}

/// `enrich_package_shim_status_payload`.
fn enrich_status(
    facts: &ShimFacts,
    status: Map<String, Value>,
    manifest: &Map<String, Value>,
) -> ShimResult<Map<String, Value>> {
    let mut status = status;
    let mut path_broken: BTreeSet<String> = match status.get("bypasses") {
        Some(Value::Array(entries)) => entries
            .iter()
            .filter_map(|entry| entry.get("manager")?.as_str().map(str::to_owned))
            .collect(),
        _ => BTreeSet::new(),
    };
    let last_test_at = match status.get("last_test_at") {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    let mut tested: Vec<String> = last_test_at.keys().cloned().collect();
    tested.sort();
    let last_audit = match manifest.get("last_audit_at") {
        Some(Value::String(text)) => Value::String(text.clone()),
        _ => Value::Null,
    };
    let installed = string_list(status.get("installed_managers"));
    let recovered: Vec<String> = recoverable_managers(facts, &status)
        .into_iter()
        .filter(|manager| !installed.contains(manager))
        .collect();
    if !recovered.is_empty() {
        let mut all_installed: BTreeSet<String> = installed.iter().cloned().collect();
        all_installed.extend(recovered.iter().cloned());
        let mut all_active: BTreeSet<String> = string_list(status.get("active_managers"))
            .into_iter()
            .collect();
        all_active.extend(recovered.iter().cloned());
        let mut details: Vec<Value> = dict_items(status.get("manager_details"))
            .into_iter()
            .map(Value::Object)
            .collect();
        let detailed: BTreeSet<String> = details
            .iter()
            .filter_map(|item| item.get("manager")?.as_str().map(str::to_owned))
            .collect();
        let detected: BTreeSet<String> = string_list(status.get("detected_managers"))
            .into_iter()
            .collect();
        let shim_dir = text_or(&status, "shim_dir", "");
        let contains_dir = flag(&status, "path_contains_shim_dir");
        for manager in &recovered {
            if detailed.contains(manager) {
                continue;
            }
            details.push(json!({
                "integrity": "stale",
                "last_test_at": null,
                "manager": manager,
                "path_active": false,
                "path_index": null,
                "path_status": {
                    "shim_precedes_real": false,
                    "shim_in_path": contains_dir,
                    "path_broken": true,
                    "shim_dir": shim_dir,
                },
                "real_binary_found": false,
                "real_binary_path": null,
                "real_binary_path_index": null,
                "shim_path": if shim_dir.is_empty() { Value::Null } else { json!(facts.join(&shim_dir, manager)) },
                "system_binary_detected": detected.contains(manager),
                "recovered_without_manifest": true,
            }));
        }
        let profile_configured = flag(&status, "shell_profile_configured");
        let mut path_status = text_or(&status, "path_status", "missing_from_path");
        let mut process_status = text_or(&status, "process_path_status", "missing");
        if contains_dir {
            path_status = "in_path".to_owned();
            process_status = "active".to_owned();
        } else if profile_configured {
            path_status = "restart_required".to_owned();
            process_status = "profile_staged".to_owned();
        }
        let restart = path_status == "restart_required";
        status.insert(
            "active_managers".into(),
            json!(all_active.into_iter().collect::<Vec<_>>()),
        );
        status.insert(
            "installed_managers".into(),
            json!(all_installed.into_iter().collect::<Vec<_>>()),
        );
        status.insert("manager_details".into(), Value::Array(details));
        status.insert("path_status".into(), json!(path_status));
        status.insert("process_path_status".into(), json!(process_status));
        status.insert("process_restart_required".into(), json!(restart));
        status.insert("recovered_managers".into(), json!(recovered));
        status.insert("restart_shell_required".into(), json!(restart));
        path_broken.extend(recovered.iter().cloned());
    }
    let path_broken: Vec<String> = path_broken.into_iter().collect();
    let proofs = Value::Object(last_test_at);
    let recovered_final = string_list(status.get("recovered_managers"));
    let mut enriched = status.clone();
    let mut put = |key: &str, value: Value| {
        enriched.insert(key.to_owned(), value);
    };
    put("path_broken_managers", json!(path_broken));
    put("tested_managers", json!(tested));
    put("pathBrokenManagers", json!(path_broken));
    put("testedManagers", json!(tested));
    put("last_intercept_proof_at", proofs.clone());
    put("lastInterceptProofAt", proofs);
    put(
        "detectedManagers",
        json!(string_list(status.get("detected_managers"))),
    );
    put(
        "protectedManagers",
        json!(string_list(status.get("protected_managers"))),
    );
    put(
        "installedManagers",
        json!(string_list(status.get("installed_managers"))),
    );
    put(
        "activeManagers",
        json!(string_list(status.get("active_managers"))),
    );
    put(
        "missingManagers",
        json!(string_list(status.get("missing_managers"))),
    );
    put(
        "undetectedManagers",
        json!(string_list(status.get("undetected_managers"))),
    );
    put("recovered_managers", json!(recovered_final));
    put("recoveredManagers", json!(recovered_final));
    put("last_audit_proof_at", last_audit.clone());
    put("lastAuditProofAt", last_audit);
    Ok(enriched)
}

/// `package_shim_dashboard_status`.
pub fn package_shim_dashboard_status(context: &ShimContext) -> ShimResult<Map<String, Value>> {
    let status = package_shim_status(context, None)?;
    if status.get("path_status").and_then(Value::as_str) != Some("restart_required")
        || !flag(&status, "shell_profile_configured")
    {
        return Ok(status);
    }
    let installed = string_items(status.get("installed_managers"));
    if installed.is_empty() || flag(&status, "missing_managers") {
        return Ok(status);
    }
    let details = dict_items(status.get("manager_details"));
    let integrity_of = |manager: &str| -> Option<String> {
        details
            .iter()
            .find(|detail| detail.get("manager").and_then(Value::as_str) == Some(manager))
            .and_then(|detail| detail.get("integrity")?.as_str().map(str::to_owned))
    };
    if installed
        .iter()
        .any(|manager| integrity_of(manager).as_deref() != Some("ok"))
    {
        return Ok(status);
    }
    let mut projected_details: Vec<Value> = Vec::new();
    for detail in &details {
        let is_installed = detail
            .get("manager")
            .and_then(Value::as_str)
            .is_some_and(|manager| installed.iter().any(|item| item == manager));
        if !is_installed {
            projected_details.push(Value::Object(detail.clone()));
            continue;
        }
        let projected_path = match detail.get("path_status") {
            Some(Value::Object(path_detail)) => {
                let mut projected = path_detail.clone();
                projected.insert("path_broken".into(), json!(false));
                projected.insert("shim_in_path".into(), json!(true));
                projected.insert("shim_precedes_real".into(), json!(true));
                projected.insert("shim_path_index".into(), Value::Null);
                projected.insert("real_binary_path_index".into(), Value::Null);
                projected.insert("foreign_shim_bypass".into(), json!(false));
                projected.insert("foreign_shim_path_index".into(), Value::Null);
                Value::Object(projected)
            }
            other => other.cloned().unwrap_or(Value::Null),
        };
        let mut projected = detail.clone();
        projected.insert("path_active".into(), json!(true));
        projected.insert("path_status".into(), projected_path);
        projected_details.push(Value::Object(projected));
    }
    let mut result = status;
    result.insert("bypasses".into(), json!([]));
    result.insert("manager_details".into(), Value::Array(projected_details));
    result.insert("path_active".into(), json!(true));
    result.insert("path_broken_managers".into(), json!([]));
    result.insert("pathBrokenManagers".into(), json!([]));
    result.insert("path_contains_shim_dir".into(), json!(true));
    result.insert("path_status".into(), json!("in_path"));
    result.insert("protected_managers".into(), json!(installed));
    result.insert("protectedManagers".into(), json!(installed));
    result.insert("restart_shell_required".into(), json!(false));
    Ok(result)
}

/// `package_shim_cloud_coverage`.
pub fn package_shim_cloud_coverage(
    context: &ShimContext,
    generated_at: Option<&str>,
) -> ShimResult<Value> {
    let status = package_shim_status(context, None)?;
    Ok(json!({
        "generatedAt": generated_at.filter(|text| !text.is_empty()).unwrap_or(&context.facts.now),
        "configuredManagers": string_items(status.get("installed_managers")),
        "protectedManagers": string_items(status.get("protected_managers")),
        "missingManagers": string_items(status.get("missing_managers")),
        "pathActive": flag(&status, "path_active"),
        "bypasses": dict_items(status.get("bypasses")),
    }))
}
