//! `CommandJobPlan` — resident op that plans a leased Guard Cloud command job.
//!
//! Port of the dispatch and argument checks in
//! `runtime/command_executors.py`: which operation family a job belongs to,
//! the manager, harness and surface arguments it may carry, which jobs wait
//! for a local confirmation command, and that command itself. Python still
//! runs the planned operation; this op decides what runs. Pure: no IO.

use crate::package_authority_op::request_digest_with_limit;
use guard_contracts::{
    python_strip, CommandJobPlanPayloadV1, CommandJobPlanQueryV1, CommandJobPlanRequestV1,
    CommandJobPlanResultV1, CommandJobPlanV1, COMMAND_JOB_PLAN_MAX_BYTES,
    COMMAND_JOB_PLAN_REQUEST_SCHEMA, COMMAND_JOB_PLAN_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

const PACKAGE_SHIM_OPERATIONS: [&str; 7] = [
    "guard.packageShims.status",
    "guard.packageShims.repair",
    "guard.packageShims.test",
    "guard.packageShims.sync",
    "guard.packageShims.install",
    "guard.packageShims.remove",
    "guard.packageShims.audit",
];
const APP_OPERATIONS: [&str; 6] = [
    "guard.app.status",
    "guard.app.repair",
    "guard.app.connect",
    "guard.app.remove",
    "guard.app.update",
    "guard.app.updateCheck",
];
const EXACT_CLOUD_REVIEW_OPERATION: &str = "guard.review.resolveExact";
const POLICY_MEMORY_OPERATION: &str = "guard.review.syncPolicyMemory";
const SURFACES: [&str; 2] = ["editor", "cli"];

pub(crate) fn evaluate_command_job_plan_request(
    request: &CommandJobPlanRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any work; an oversized
    // request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, COMMAND_JOB_PLAN_MAX_BYTES)
        .map_err(|_| "native_command_job_plan_too_large".to_owned())?;
    let (status, code, payload) = if request.schema == COMMAND_JOB_PLAN_REQUEST_SCHEMA {
        let CommandJobPlanQueryV1::Plan {
            operation,
            harness,
            surface,
            managers,
        } = &request.query;
        let operation = operation.as_ref().and_then(Value::as_str).unwrap_or("");
        let plan = plan(
            operation,
            harness.as_ref(),
            surface.as_ref(),
            managers.as_ref(),
        );
        ("ok", "ok", Some(CommandJobPlanPayloadV1::Plan { plan }))
    } else {
        ("error", "native_command_job_plan_schema_mismatch", None)
    };
    crate::encode_response(&CommandJobPlanResultV1 {
        schema: COMMAND_JOB_PLAN_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The plan for one job, or the failure the queue posts instead of running it.
pub(crate) fn plan(
    operation: &str,
    harness: Option<&Value>,
    surface: Option<&Value>,
    managers: Option<&Value>,
) -> CommandJobPlanV1 {
    let planned = if PACKAGE_SHIM_OPERATIONS.contains(&operation) {
        package_shim_plan(operation, managers)
    } else if APP_OPERATIONS.contains(&operation) {
        app_plan(operation, harness, surface)
    } else if operation == EXACT_CLOUD_REVIEW_OPERATION {
        Ok(run(operation, "exact_cloud_review", None, None, None))
    } else if operation == POLICY_MEMORY_OPERATION {
        Ok(run(operation, "policy_memory", None, None, None))
    } else {
        let named = if operation.is_empty() {
            "unknown"
        } else {
            operation
        };
        return fail(
            "unsupported_operation",
            format!("Unsupported Guard command operation: {named}"),
        );
    };
    planned.unwrap_or_else(|code| {
        let code = if code.is_empty() {
            "invalid_payload".to_owned()
        } else {
            code
        };
        let message = code.replace('_', " ");
        fail(&code, message)
    })
}

fn package_shim_plan(
    operation: &str,
    managers: Option<&Value>,
) -> Result<CommandJobPlanV1, String> {
    match operation {
        "guard.packageShims.install" | "guard.packageShims.repair" | "guard.packageShims.test" => {
            Ok(run(
                operation,
                "package_shims",
                Some(manager_list(managers)?),
                None,
                None,
            ))
        }
        "guard.packageShims.remove" => Ok(CommandJobPlanV1::Confirm {
            data: package_shim_remove_confirmation(manager_list(managers)?.as_deref()),
        }),
        _ => Ok(run(operation, "package_shims", None, None, None)),
    }
}

fn app_plan(
    operation: &str,
    harness: Option<&Value>,
    surface: Option<&Value>,
) -> Result<CommandJobPlanV1, String> {
    let harness = harness.and_then(optional_text);
    let surface = match surface.and_then(optional_text) {
        Some(surface) if !SURFACES.contains(&surface.as_str()) => {
            return Err("unsupported_surface".to_owned())
        }
        surface => surface,
    };
    match operation {
        "guard.app.status" => {
            if let Some(harness) = harness.as_deref() {
                registered_harness(harness)?;
            }
            return Ok(run(operation, "app", None, harness, surface));
        }
        "guard.app.update" | "guard.app.updateCheck" => {
            return Ok(run(operation, "app", None, harness, surface))
        }
        _ => {}
    }
    let Some(harness) = harness else {
        return Ok(fail(
            "harness_required",
            "App command requires a harness.".to_owned(),
        ));
    };
    registered_harness(&harness)?;
    if operation == "guard.app.remove" {
        return Ok(CommandJobPlanV1::Confirm {
            data: app_remove_confirmation(&harness, surface.as_deref()),
        });
    }
    Ok(run(operation, "app", None, Some(harness), surface))
}

/// `canonical_harness`: the name must be a registered harness id or alias,
/// spelled exactly; the queue keeps using the name as sent.
fn registered_harness(name: &str) -> Result<(), String> {
    let spelled = name.trim().to_lowercase().replace('_', "-");
    if spelled == name && guard_command::harness_identity::canonical_harness_id(name).is_some() {
        Ok(())
    } else {
        Err(format!("Unsupported harness: {name}"))
    }
}

/// `_package_shim_managers`: null for every manager, else the normalized,
/// distinct, supported names.
fn manager_list(managers: Option<&Value>) -> Result<Option<Vec<String>>, String> {
    let Some(managers) = managers.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let items = match managers {
        Value::Array(items) if !items.is_empty() => items,
        _ => return Err("invalid_managers".to_owned()),
    };
    let mut normalized: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let name = item
            .as_str()
            .map(python_strip)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "invalid_managers".to_owned())?;
        normalized.push(name.to_lowercase());
    }
    let mut distinct = normalized.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() != normalized.len() {
        return Err("duplicate_manager".to_owned());
    }
    let supported = guard_command::shims::package_shim_supported_managers();
    if !normalized
        .iter()
        .all(|name| supported.contains(&name.as_str()))
    {
        return Err("unsupported_manager".to_owned());
    }
    Ok(Some(normalized))
}

fn package_shim_remove_confirmation(managers: Option<&[String]>) -> Map<String, Value> {
    let managers = managers.unwrap_or(&[]);
    let mut command = String::from("hol-guard package-shims uninstall");
    for manager in managers {
        command.push_str(" --manager ");
        command.push_str(manager);
    }
    let summary = if managers.is_empty() {
        "Run the local package-shim uninstall command on this machine to confirm removal."
            .to_owned()
    } else {
        format!(
            "Run the local package-shim uninstall command on this machine to confirm removal for {}.",
            managers.join(", ")
        )
    };
    object(json!({
        "confirm_command": command,
        "managers": managers,
        "summary": summary,
    }))
}

fn app_remove_confirmation(harness: &str, surface: Option<&str>) -> Map<String, Value> {
    // The local disconnect gate compares `--confirm` with the canonical
    // harness, so an alias such as `claude` confirms as `claude-code`.
    let harness = guard_command::harness_identity::canonical_harness_id(harness).unwrap_or(harness);
    let phrase = format!("disconnect-{harness}");
    let mut command = format!("hol-guard apps disconnect {harness}");
    if let Some(surface) = surface {
        command.push_str(" --surface ");
        command.push_str(surface);
    }
    command.push_str(" --confirm ");
    command.push_str(&phrase);
    object(json!({
        "confirm_command": command,
        "confirmation_phrase": phrase,
        "harness": harness,
        "summary": format!(
            "Run the local disconnect command on this machine to confirm removing Guard protection for {harness}."
        ),
        "surface": surface,
    }))
}

fn run(
    operation: &str,
    family: &str,
    managers: Option<Option<Vec<String>>>,
    harness: Option<String>,
    surface: Option<String>,
) -> CommandJobPlanV1 {
    CommandJobPlanV1::Run {
        operation: operation.to_owned(),
        family: family.to_owned(),
        managers: managers.flatten(),
        harness,
        surface,
    }
}

fn fail(code: &str, message: String) -> CommandJobPlanV1 {
    CommandJobPlanV1::Fail {
        failure_code: code.to_owned(),
        failure_message: message,
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// `optional_text`: a string's stripped text, or None when it is blank or not
/// a string.
fn optional_text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(python_strip)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "command_job_plan_op_tests.rs"]
mod tests;
