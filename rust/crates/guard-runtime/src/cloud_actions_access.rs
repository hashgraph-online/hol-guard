//! `cloud_actions_access` runner-authority kind: whether Guard Cloud's answer
//! to a Cloud actions token exchange is access Guard may use, and what a
//! refused exchange tells the person. Ported from `cli/cloud_actions_access.py`
//! (`read_cloud_actions_access` and `_exchange_refused`).
//!
//! The access token never reaches this kind. Python sends whether the answer
//! carried one, the answer's `token_type`, `expires_in` and `scope` members,
//! and the `aud` and `workspace` claims it decoded from the token (`null` when
//! absent), with the pairing's gateway `resource` and lowercase `workspace_id`:
//!
//! - `{"op": "access", ...}` answers `{"accepted": {"workspace_id", "scopes",
//!   "expires_in"}}`, or `{"refused": message}` when the answer is not Cloud
//!   actions access for this pairing's workspace;
//! - `{"op": "refused", "status", "error"}` answers the stable `reason` and
//!   the `message` for an HTTP refusal, where `error` is the refusal body's
//!   `error` member or `null`.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::daemon_lifecycle_text::{py_isspace, py_strip};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const RECONNECT_COMMAND: &str = "hol-guard connect";
const SCOPES: [&str; 4] = [
    "gateway:discover",
    "gateway:invoke",
    "gateway:execution.read",
    "gateway:connection.read",
];
const NOT_ACCESS: &str = "Guard Cloud's answer was not Cloud actions access.";
const OTHER_SCOPE: &str = "Guard Cloud granted access other than Cloud actions.";
const OTHER_AUDIENCE: &str = "Guard Cloud granted access for something else.";
const OTHER_WORKSPACE: &str = "Guard Cloud granted access for another workspace.";
/// Guard Cloud busy or briefly unavailable.
const BUSY_STATUSES: [i64; 4] = [429, 502, 503, 504];

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Access {
        token: bool,
        token_type: Value,
        expires_in: Value,
        scope: Value,
        audience: Value,
        workspace: Value,
        resource: String,
        workspace_id: Option<String>,
    },
    Refused {
        status: i64,
        error: Value,
    },
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let request: Request = serde_json::from_value(args.clone()).map_err(|_| ERR_INVALID)?;
    Ok(match request {
        Request::Access {
            token,
            token_type,
            expires_in,
            scope,
            audience,
            workspace,
            resource,
            workspace_id,
        } => match access(
            Answer {
                token,
                token_type: &token_type,
                expires_in: &expires_in,
                scope: &scope,
                audience: &audience,
                workspace: &workspace,
            },
            &resource,
            workspace_id.as_deref(),
        ) {
            Ok(accepted) => json!({ "accepted": accepted }),
            Err(message) => json!({ "refused": message }),
        },
        Request::Refused { status, error } => {
            let (reason, message) = refused(status, error.as_str());
            json!({ "reason": reason, "message": message })
        }
    })
}

/// The members of Guard Cloud's answer and the token claims this kind reads.
struct Answer<'a> {
    token: bool,
    token_type: &'a Value,
    expires_in: &'a Value,
    scope: &'a Value,
    audience: &'a Value,
    workspace: &'a Value,
}

/// `read_cloud_actions_access` without the clock: Python adds `expires_in` to
/// the time it read the answer.
fn access(answer: Answer<'_>, resource: &str, paired: Option<&str>) -> Result<Value, &'static str> {
    let bearer = answer
        .token_type
        .as_str()
        .is_some_and(|kind| kind.to_lowercase() == "bearer");
    // JSON keeps `true` apart from `1`, so a number here is never a boolean.
    let expires_in = answer.expires_in.as_i64().filter(|seconds| *seconds > 0);
    let Some(expires_in) = expires_in.filter(|_| answer.token && bearer) else {
        return Err(NOT_ACCESS);
    };
    let scopes: Vec<&str> = answer
        .scope
        .as_str()
        .map(|text| {
            text.split(py_isspace)
                .filter(|part| !part.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if scopes.is_empty() || scopes.iter().any(|scope| !SCOPES.contains(scope)) {
        return Err(OTHER_SCOPE);
    }
    let named = match answer.audience {
        Value::String(audience) => audience == resource,
        Value::Array(audiences) => audiences.iter().any(|audience| audience == resource),
        _ => false,
    };
    if !named {
        return Err(OTHER_AUDIENCE);
    }
    let workspace_id = answer
        .workspace
        .get("workspaceId")
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|text| !text.is_empty())
        .map(str::to_lowercase);
    let Some(workspace_id) = workspace_id.filter(|id| paired.is_none_or(|paired| id == paired))
    else {
        return Err(OTHER_WORKSPACE);
    };
    Ok(json!({
        "workspace_id": workspace_id,
        "scopes": scopes,
        "expires_in": expires_in,
    }))
}

/// `_exchange_refused`: the reason and message for a refused exchange.
fn refused(status: i64, error: Option<&str>) -> (&'static str, String) {
    match error {
        // The pairing is inactive, Cloud actions are off, or the member may no longer use them.
        Some("invalid_grant") => (
            "cloud_actions_not_allowed",
            format!(
                "Guard Cloud did not allow Cloud actions for this computer. Check that this \
                 computer is still paired and that your role in the workspace may use Cloud \
                 actions, then run {RECONNECT_COMMAND} again and choose \"Let AI tools on this \
                 computer use Cloud actions\"."
            ),
        ),
        Some("invalid_target") => (
            "not_available",
            "Cloud actions are not available on this Guard Cloud yet.".to_owned(),
        ),
        _ if BUSY_STATUSES.contains(&status) => (
            "cloud_unreachable",
            "Guard Cloud is busy. Try again shortly.".to_owned(),
        ),
        _ => (
            "exchange_refused",
            format!("Guard Cloud refused Cloud actions access (HTTP {status})."),
        ),
    }
}

#[cfg(test)]
#[path = "cloud_actions_access_tests.rs"]
mod tests;
