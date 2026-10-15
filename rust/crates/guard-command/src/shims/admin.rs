//! Package-shim install, repair, activation and uninstall.

use serde_json::{json, Map, Value};

use super::frozen::{installed_attestation_bytes, shell_wrapper, sidecar_path};
use super::generate::{
    build_package_manager_python_shim, build_windows_script, launcher_paths, needs_shell_wrapper,
};
use super::manifest::{self, installed_managers, normalize_managers};
use super::path_order::get_path_order_status;
use super::profile::{
    ensure_package_shim_path_in_shell_profile, path_export_hint, path_export_hints,
};
use super::status::package_shim_status;
use super::values::{dict_items, py_strip, sha256_hex, string_map};
use super::{package_shim_command, ShimContext, ShimResult};

fn flag(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(items)) => !items.is_empty(),
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
    }
}

/// `_command_program_name`.
fn command_program_name(context: &ShimContext) -> String {
    let Some(argv0) = context.facts.argv0.as_deref() else {
        return "hol-guard".to_owned();
    };
    let name = context.facts.name(argv0);
    let candidate = py_strip(&name);
    if candidate.is_empty() {
        "hol-guard".to_owned()
    } else {
        candidate.to_owned()
    }
}

/// `_write_package_manager_shim_files`; returns the POSIX launcher path.
fn write_shim_files(context: &ShimContext, command: &str, shim_dir: &str) -> ShimResult<String> {
    let facts = &context.facts;
    let python_source = build_package_manager_python_shim(context, command)?;
    let (posix_path, windows_path) = launcher_paths(facts, shim_dir, command);
    if needs_shell_wrapper(facts) {
        let python_path = sidecar_path(facts, shim_dir, command);
        facts.write_text(&python_path, &python_source)?;
        facts.write_text(&posix_path, &shell_wrapper(facts, &python_path))?;
        facts.write_text(&windows_path, &build_windows_script(facts, &python_path)?)?;
    } else {
        facts.write_text(&posix_path, &python_source)?;
        facts.write_text(&windows_path, &build_windows_script(facts, &posix_path)?)?;
    }
    facts.add_executable_bits(&posix_path)?;
    Ok(posix_path)
}

/// `install_package_shims`.
pub fn install_package_shims(
    context: &ShimContext,
    managers: Option<&[String]>,
    path_env: Option<&str>,
) -> ShimResult<Map<String, Value>> {
    let facts = &context.facts;
    let shim_dir = context.shim_dir();
    facts.mkdir_parents(&shim_dir)?;
    let normalized = normalize_managers(managers);
    let existing = manifest::load(context)?;
    let mut tracked: Vec<String> = Vec::new();
    for manager in installed_managers(&existing)
        .into_iter()
        .chain(normalized.iter().cloned())
    {
        if !tracked.contains(&manager) {
            tracked.push(manager);
        }
    }
    let mut content_hashes = string_map(existing.get("content_hashes"));
    let last_test_at = string_map(existing.get("last_test_at"));
    let mut installed: Vec<String> = Vec::new();
    for manager in &normalized {
        let command = package_shim_command(manager).unwrap_or(manager);
        let posix_path = write_shim_files(context, command, &shim_dir)?;
        let wrapper = facts
            .read_bytes(&posix_path)
            .map_err(|error| error.message(&posix_path))?;
        let attested = installed_attestation_bytes(facts, &shim_dir, command, &wrapper)?;
        content_hashes.insert(manager.clone(), sha256_hex(&attested));
        installed.push(manager.clone());
    }
    let to_object = |map: std::collections::BTreeMap<String, String>| -> Value {
        Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, Value::String(value)))
                .collect(),
        )
    };
    let mut payload = Map::new();
    payload.insert("content_hashes".into(), to_object(content_hashes));
    payload.insert("installed_managers".into(), json!(tracked));
    payload.insert("last_test_at".into(), to_object(last_test_at));
    payload.insert("shim_dir".into(), json!(shim_dir));
    manifest::write(context, &payload)?;
    let program = command_program_name(context);
    let mut path_repair_required: Vec<String> = Vec::new();
    for manager in &tracked {
        let status = get_path_order_status(context, manager, path_env)?;
        if !flag(status.get("shim_precedes_real")) {
            path_repair_required.push(manager.clone());
        }
    }
    let mut result = Map::new();
    result.insert("installed_managers".into(), json!(tracked));
    result.insert("installed_count".into(), json!(tracked.len()));
    result.insert("installed_now".into(), json!(installed));
    result.insert("installed_now_count".into(), json!(installed.len()));
    result.insert("shim_dir".into(), json!(shim_dir));
    result.insert("manifest_path".into(), json!(context.manifest_path()));
    result.insert(
        "path_export_hint".into(),
        json!(path_export_hint(facts, &shim_dir)),
    );
    result.insert(
        "restart_shell_required".into(),
        json!(!path_repair_required.is_empty()),
    );
    result.insert("path_repair_required".into(), json!(path_repair_required));
    result.insert("shell_hints".into(), path_export_hints(&shim_dir));
    result.insert(
        "status_command".into(),
        json!(format!("{program} package-shims status --json")),
    );
    result.insert(
        "uninstall_command".into(),
        json!(format!("{program} package-shims uninstall --json")),
    );
    Ok(result)
}

/// `repair_package_shims`.
pub fn repair_package_shims(
    context: &ShimContext,
    managers: Option<&[String]>,
    path_env: Option<&str>,
) -> ShimResult<Map<String, Value>> {
    let status = package_shim_status(context, path_env)?;
    let selected: Option<Vec<String>> = managers
        .filter(|items| !items.is_empty())
        .map(|items| normalize_managers(Some(items)));
    let mut to_repair: Vec<String> = Vec::new();
    let mut path_repair_required: Vec<String> = Vec::new();
    for detail in dict_items(status.get("manager_details")) {
        let Some(manager) = detail.get("manager").and_then(Value::as_str) else {
            continue;
        };
        if selected
            .as_ref()
            .is_some_and(|items| !items.iter().any(|item| item == manager))
        {
            continue;
        }
        if matches!(
            detail.get("integrity").and_then(Value::as_str),
            Some("missing" | "stale" | "tampered")
        ) {
            to_repair.push(manager.to_owned());
        } else if !flag(detail.get("path_active")) {
            path_repair_required.push(manager.to_owned());
        }
    }
    let shell_hints = status
        .get("shell_hints")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut result = Map::new();
    if to_repair.is_empty() {
        result.insert("repaired".into(), json!([]));
        result.insert("repaired_count".into(), json!(0));
        result.insert(
            "already_ok".into(),
            status
                .get("installed_managers")
                .cloned()
                .unwrap_or_else(|| json!([])),
        );
        result.insert("path_repair_required".into(), json!(path_repair_required));
        result.insert("shell_hints".into(), shell_hints);
        result.insert("nothing_to_repair".into(), json!(true));
        return Ok(result);
    }
    let install = install_package_shims(context, Some(&to_repair), path_env)?;
    result.insert("repaired".into(), json!(to_repair));
    result.insert("repaired_count".into(), json!(to_repair.len()));
    result.insert("path_repair_required".into(), json!(path_repair_required));
    result.insert("shell_hints".into(), shell_hints);
    result.insert("install_result".into(), Value::Object(install));
    Ok(result)
}

/// `activate_package_shims`.
pub fn activate_package_shims(
    context: &ShimContext,
    managers: Option<&[String]>,
    repair: bool,
) -> ShimResult<Map<String, Value>> {
    let mut result = if repair {
        repair_package_shims(context, managers, None)?
    } else {
        install_package_shims(context, managers, None)?
    };
    let profile = ensure_package_shim_path_in_shell_profile(context)?;
    let status = package_shim_status(context, None)?;
    result.insert(
        "activation_state".into(),
        status.get("path_status").cloned().unwrap_or(Value::Null),
    );
    let restart = flag(status.get("restart_shell_required"));
    result.insert("package_shims".into(), Value::Object(status));
    result.insert("profile".into(), profile);
    result.insert("restart_shell_required".into(), json!(restart));
    Ok(result)
}

/// `uninstall_package_shims`.
pub fn uninstall_package_shims(
    context: &ShimContext,
    managers: Option<&[String]>,
) -> ShimResult<Map<String, Value>> {
    let facts = &context.facts;
    let manifest_value = manifest::load(context)?;
    let manifest_managers = installed_managers(&manifest_value);
    let requested: Vec<String> = match managers.filter(|items| !items.is_empty()) {
        Some(items) => normalize_managers(Some(items)),
        None => manifest_managers.clone(),
    };
    let shim_dir = context.shim_dir();
    let mut removed_paths: Vec<String> = Vec::new();
    for manager in &requested {
        let command = package_shim_command(manager).unwrap_or(manager);
        let (posix_path, windows_path) = launcher_paths(facts, &shim_dir, command);
        for candidate in [
            posix_path,
            windows_path,
            sidecar_path(facts, &shim_dir, command),
        ] {
            if facts.exists(&candidate) {
                facts.unlink(&candidate)?;
                removed_paths.push(candidate);
            }
        }
    }
    let remaining: Vec<String> = manifest_managers
        .into_iter()
        .filter(|manager| !requested.contains(manager))
        .collect();
    let manifest_path = context.manifest_path();
    if remaining.is_empty() {
        if facts.exists(&manifest_path) {
            facts.unlink(&manifest_path)?;
        }
    } else {
        let keep = |map: std::collections::BTreeMap<String, String>| -> Value {
            Value::Object(
                map.into_iter()
                    .filter(|(manager, _)| remaining.contains(manager))
                    .map(|(key, value)| (key, Value::String(value)))
                    .collect(),
            )
        };
        let mut payload = Map::new();
        payload.insert(
            "content_hashes".into(),
            keep(string_map(manifest_value.get("content_hashes"))),
        );
        payload.insert("installed_managers".into(), json!(remaining));
        payload.insert(
            "last_test_at".into(),
            keep(string_map(manifest_value.get("last_test_at"))),
        );
        payload.insert("shim_dir".into(), json!(shim_dir));
        manifest::write(context, &payload)?;
    }
    let mut result = Map::new();
    result.insert("removed_managers".into(), json!(requested));
    result.insert("removed_paths".into(), json!(removed_paths));
    result.insert("remaining_managers".into(), json!(remaining));
    result.insert("manifest_path".into(), json!(manifest_path));
    result.insert("shim_dir".into(), json!(shim_dir));
    Ok(result)
}
