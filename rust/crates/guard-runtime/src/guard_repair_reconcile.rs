//! The `reconcile` op: the reconciliation pass's result from what each of
//! its repairs returned.

use serde_json::{json, Map, Value};

use super::*;

/// The reconciliation pass's result from what each of its repairs returned.
pub(super) fn reconcile(request: &Map<String, Value>) -> Result<Value, String> {
    let mut errors: Vec<String> = strings(request.get("launcher_errors"))
        .into_iter()
        .map(|error| format!("launcher:{error}"))
        .collect();
    let mut repaired = strings(request.get("repaired_harnesses"));
    let failed = strings(request.get("failed_harnesses"));
    if let Some(rebind) = request.get("cursor_rebind").and_then(Value::as_object) {
        if rebind.get("rebound").and_then(Value::as_bool) == Some(true)
            && !repaired.iter().any(|name| name == "cursor")
        {
            repaired.push("cursor".to_owned());
        }
        if matches!(
            text(rebind.get("reason")),
            "cursor_hook_script_rebind_failed" | "cursor_hook_script_unreadable"
        ) {
            let detail = rebind
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("failed");
            errors.push(format!("cursor:rebind:{detail}"));
        }
    }
    let package = request
        .get("package")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let mut repaired_managers = Vec::new();
    // A pass that read the manifest before it failed still reports what it read.
    let initial = package.get("initial").and_then(Value::as_object);
    match initial.and_then(|status| status.get("manifest_state")) {
        None | Some(Value::Null) => {}
        Some(Value::String(state)) if state == "absent" || state == "valid" => {}
        Some(state) => errors.push(format!("package:manifest:{}", python_str(state))),
    }
    let installed = strings(initial.and_then(|status| status.get("installed_managers")));
    if !installed.is_empty() {
        // Shims a failed pass already rewrote stay repaired.
        repaired_managers = strings(package.get("repaired"));
    }
    if package.get("failed").and_then(Value::as_bool) == Some(true) {
        errors.push("package:reconciliation_failed".to_owned());
    } else if !installed.is_empty() {
        let details = package
            .get("verified")
            .and_then(|status| status.get("manager_details"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        // A manager the final status leaves out was never verified.
        for manager in &installed {
            let reported = details.iter().any(|detail| {
                detail.get("manager").and_then(Value::as_str) == Some(manager.as_str())
            });
            if !reported {
                errors.push(format!("package:{manager}:status_missing"));
            }
        }
        for detail in details.iter().filter_map(Value::as_object) {
            let Some(manager) = detail
                .get("manager")
                .and_then(Value::as_str)
                .filter(|manager| installed.iter().any(|name| name == manager))
            else {
                continue;
            };
            if detail.get("integrity").and_then(Value::as_str) != Some("ok") {
                errors.push(format!("package:{manager}:integrity"));
            }
            if detail.get("path_active").and_then(Value::as_bool) != Some(true) {
                errors.push(format!("package:{manager}:path_inactive"));
            }
        }
    }
    Ok(json!({
        "repaired_harnesses": repaired,
        "failed_harnesses": failed,
        "repaired_package_managers": repaired_managers,
        "errors": errors,
    }))
}

/// How Python's f-string renders a JSON scalar.
fn python_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Null => "None".to_owned(),
        other => other.to_string(),
    }
}
