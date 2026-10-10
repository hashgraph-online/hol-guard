//! Headless app action and supply-chain failure responses: which status and
//! body each failure carries, and what a completed action's state reports.

use crate::daemon_handler_op::Reply;
use crate::policy_bundle_py::py_strip;
use guard_contracts::{ManagedInstallFactV1, SyncErrorKindV1, VerificationFactV1};
use serde_json::{json, Map, Value};

fn failure(code: &str, message: &str, retryable: bool) -> Value {
    json!({
        "status": "failed",
        "error": {"code": code, "message": message, "retryable": retryable},
    })
}

pub(crate) fn headless_error(operation: &str, error_code: &str) -> Reply {
    let known = match error_code {
        "missing_harness" => Some((400, "Choose an app before retrying.")),
        "unknown_harness" => Some((404, "This app is not supported by local Guard.")),
        "confirmation_required" => Some((
            409,
            "Disconnect needs the local confirmation phrase before Guard removes protection.",
        )),
        "unsupported_operation" => Some((
            400,
            "This version of local Guard cannot run the requested app action.",
        )),
        _ => None,
    };
    if let Some((status, message)) = known {
        return Reply::reject(status, failure(error_code, message, false));
    }
    let code = if operation == "scan" {
        "proof_failed".to_owned()
    } else {
        format!("{operation}_failed")
    };
    let label = if operation == "scan" {
        "connection check"
    } else {
        operation
    };
    Reply::reject(
        400,
        failure(&code, &format!("Guard could not finish the {label}."), true),
    )
}

/// The error body for an unsupported Cursor surface; the caller adds the
/// surface the request named.
pub(crate) fn headless_cursor_surface() -> Reply {
    let mut body = failure(
        "invalid_cursor_surface",
        "Choose Cursor editor or CLI before retrying this local action.",
        false,
    );
    body["error"]["app_id"] = Value::String("cursor".to_owned());
    Reply::reject(400, body)
}

fn app_status(
    operation: &str,
    managed: &ManagedInstallFactV1,
    verification: &Option<VerificationFactV1>,
) -> &'static str {
    match operation {
        "install" | "repair" => {
            if managed.present && managed.active_truthy {
                "protected"
            } else {
                "unknown"
            }
        }
        "remove" => {
            if managed.present && managed.active_is_false {
                "inactive"
            } else {
                "unknown"
            }
        }
        _ => match verification {
            None => "unknown",
            Some(found) if found.installed => "protected",
            Some(found) if found.command_or_config => "observed",
            Some(_) => "inactive",
        },
    }
}

pub(crate) fn headless_state(
    harness: &str,
    operation: &str,
    managed: &ManagedInstallFactV1,
    verification: &Option<VerificationFactV1>,
) -> Reply {
    let status = app_status(operation, managed, verification);
    let (outcome, message, proof_status) = match operation {
        "install" => (
            "app_connected",
            format!("{harness} is connected through local Guard."),
            "pending",
        ),
        "repair" => (
            "app_repaired",
            format!("{harness} protection was refreshed."),
            "pending",
        ),
        "remove" => (
            "app_disconnected",
            format!("{harness} protection was removed."),
            "not_applicable",
        ),
        "scan" if status == "protected" => (
            "proof_passed",
            format!("{harness} connection check passed. Guard sees local protection."),
            "passed",
        ),
        "scan" => (
            "proof_failed",
            format!(
                "{harness} connection check finished, but Guard does not see active local protection yet."
            ),
            "failed",
        ),
        _ => (
            "status_checked",
            format!("{harness} status checked."),
            "not_applicable",
        ),
    };
    let fields = json!({
        "app_status": status,
        "message": message,
        "outcome": outcome,
        "proof_status": proof_status,
        "retryable": matches!(operation, "install" | "repair" | "scan"),
    });
    Reply::proceed(Value::Object(Map::new()), fields)
}

pub(crate) fn detection_statuses(values: &[String]) -> Reply {
    let mapped: Vec<&str> = values
        .iter()
        .map(|value| match value.as_str() {
            "protected" => "protected",
            "found" => "observed",
            "not_found" => "inactive",
            _ => "unknown",
        })
        .collect();
    Reply::proceed(Value::Object(Map::new()), json!({"app_statuses": mapped}))
}

pub(crate) fn supply_chain_sync_error(
    operation: &str,
    error: SyncErrorKindV1,
    message: &str,
    retryable: bool,
) -> Reply {
    let stripped = py_strip(message);
    let text = |default: &'static str| -> String {
        if stripped.is_empty() {
            default
        } else {
            stripped
        }
        .to_owned()
    };
    match error {
        SyncErrorKindV1::AuthorizationExpired => Reply::reject(
            403,
            json!({
                "error": "guard_cloud_reconnect_required",
                "message": text("Guard Cloud authorization expired."),
                "operation": operation,
            }),
        ),
        SyncErrorKindV1::NotConfigured => Reply::reject(
            403,
            json!({
                "error": "guard_cloud_connect_required",
                "message": text("Guard Cloud workspace is not connected."),
                "operation": operation,
            }),
        ),
        SyncErrorKindV1::NotAvailable => {
            let mut body = json!({
                "error": "supply_chain_sync_unavailable",
                "message": text("Supply-chain sync is not available on this device."),
                "operation": operation,
            });
            if retryable {
                body["retryable"] = Value::Bool(true);
            }
            Reply::reject(503, body)
        }
        SyncErrorKindV1::Other => Reply::reject(
            502,
            json!({
                "error": "supply_chain_sync_failed",
                "message": text("Guard supply-chain bundle sync failed."),
                "operation": operation,
            }),
        ),
    }
}

#[cfg(test)]
#[path = "daemon_handler_headless_tests.rs"]
mod tests;
