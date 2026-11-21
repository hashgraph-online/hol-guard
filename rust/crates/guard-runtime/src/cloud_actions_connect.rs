//! `cloud-actions-connect --stdin`: the Cloud actions choice made during
//! `hol-guard connect`. Ported from `cli/connect_cloud_actions.py`
//! (`parse_cloud_actions_connect_report`, `cloud_actions_connect_summary`,
//! `check_connect_cloud_workspace` and `check_connect_cloud_actions_declined`).
//!
//! A one-shot command rather than a resident kind: `hol-guard cloud-actions
//! status --offline` reads the saved answer as a pure read and must not start
//! a resident. Python keeps the stored answer next to the pairing and asks
//! this command what it means:
//!
//! - `{"op": "report", "value"}` reads `guard_cloud_actions` from a connect
//!   token response (or a stored answer) and answers `{"report"}`, `null`
//!   when Guard Cloud gave no usable answer;
//! - `{"op": "summary", "report", "paired"}` answers the summary shown by
//!   `connect` and `connect status`;
//! - `{"op": "workspace", "workspace_id", "cloud_workspace_id"}` and
//!   `{"op": "declined", "report", "declined"}` answer `{"problem"}`, the
//!   message when the browser picked another workspace or turned Cloud actions
//!   on despite `--no-cloud-actions`, or `null`.

use std::io::Read;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::daemon_lifecycle_text::py_strip;

const MAX_REQUEST_BYTES: u64 = 64 * 1024;

const CONFIGURE_COMMAND: &str = "hol-guard cloud-actions ai-tools configure <ai-tool>";
const RECONNECT_COMMAND: &str = "hol-guard connect";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    On,
    Off,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    status: Status,
    workspace_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Report {
        value: Value,
    },
    Summary {
        report: Option<Report>,
        paired: bool,
    },
    Workspace {
        workspace_id: Option<String>,
        cloud_workspace_id: Option<String>,
    },
    Declined {
        report: Option<Report>,
        declined: bool,
    },
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "cloud-actions-connect"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cloud_actions_connect_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("cloud_actions_connect_request_too_large".to_owned());
    }
    let request: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    serde_json::to_vec(&answer(request)?)
        .map_err(|_| "cloud_actions_connect_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "cloud_actions_connect_request_invalid".to_owned()
}

fn answer(request: Value) -> Result<Value, String> {
    let request: Request = serde_json::from_value(request).map_err(|_| invalid())?;
    Ok(match request {
        Request::Report { value } => json!({ "report": report(&value) }),
        Request::Summary { report, paired } => summary(report.as_ref(), paired),
        Request::Workspace {
            workspace_id,
            cloud_workspace_id,
        } => json!({
            "problem": workspace_problem(workspace_id.as_deref(), cloud_workspace_id.as_deref())
        }),
        Request::Declined { report, declined } => json!({
            "problem": declined_problem(report.as_ref(), declined)
        }),
    })
}

/// Guard Cloud leaves `guard_cloud_actions` out when Cloud actions are not
/// available, for other apps, or when it could not look the pairing up.
/// Anything malformed is treated the same way, so the CLI never claims an
/// answer it did not get.
fn report(value: &Value) -> Option<Report> {
    let status = match value.get("status")?.as_str()? {
        "on" => Status::On,
        "off" => Status::Off,
        _ => return None,
    };
    let workspace_id = value
        .get("workspace_id")
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|text| !text.is_empty())
        .map(str::to_owned);
    Some(Report {
        status,
        workspace_id,
    })
}

fn summary(report: Option<&Report>, paired: bool) -> Value {
    let (status, workspace_id, message) = match report {
        _ if !paired => (
            "off",
            None,
            format!("This computer is not paired. Run {RECONNECT_COMMAND} first."),
        ),
        None => (
            "unknown",
            None,
            "Guard Cloud did not report Cloud actions for this pairing.".to_owned(),
        ),
        Some(report) if report.status == Status::On => (
            "on",
            report.workspace_id.as_deref(),
            format!("Ready. Set up an AI tool with {CONFIGURE_COMMAND}."),
        ),
        Some(report) => (
            "off",
            report.workspace_id.as_deref(),
            format!(
                "Off. To turn them on, run {RECONNECT_COMMAND} again and choose \"Let AI tools \
                 on this computer use Cloud actions\"."
            ),
        ),
    };
    json!({ "status": status, "workspace_id": workspace_id, "message": message })
}

/// The caller checks this before the first sync and undoes the pairing, so
/// nothing from this computer reaches the wrong workspace.
fn workspace_problem(
    workspace_id: Option<&str>,
    cloud_workspace_id: Option<&str>,
) -> Option<String> {
    let cloud_workspace_id = cloud_workspace_id?;
    let paired = workspace_id.unwrap_or_default();
    if paired.to_lowercase() == cloud_workspace_id.to_lowercase() {
        return None;
    }
    let shown = if paired.is_empty() { "unknown" } else { paired };
    Some(format!(
        "Guard Cloud paired this computer to workspace {shown}, not {cloud_workspace_id}. HOL Guard \
         disconnected it before sending anything. Run {RECONNECT_COMMAND} --cloud-workspace \
         {cloud_workspace_id} again and pick that workspace in the browser."
    ))
}

/// Without a report Guard Cloud did not turn Cloud actions on for this
/// pairing, which is what `--no-cloud-actions` asked for.
fn declined_problem(report: Option<&Report>, declined: bool) -> Option<String> {
    let turned_on = report.is_some_and(|report| report.status == Status::On);
    (declined && turned_on).then(|| {
        format!(
            "Cloud actions were turned on in the browser although --no-cloud-actions was set. \
             HOL Guard disconnected this computer before sending anything. Run \
             {RECONNECT_COMMAND} --no-cloud-actions again and leave Cloud actions off in the \
             browser."
        )
    })
}

#[cfg(test)]
#[path = "cloud_actions_connect_tests.rs"]
mod tests;
