//! Validation of an approval-resolution request: which route matched, and
//! whether the scope and scope-contract fields are well formed.
//!
//! Python hands over each body field as a stripped-text tri-state; the order
//! of the checks below is the order of the error replies the daemon sends.

use crate::daemon_route_paths::segments;
use guard_contracts::{DaemonRoutePayloadV1, DaemonTextFieldV1};

const SCOPE_CONTRACT_VERSION_PREFIX: &str = "guard.approval-scopes.v";

fn text(field: &DaemonTextFieldV1) -> Option<&str> {
    match field {
        DaemonTextFieldV1::Text { value } if !value.is_empty() => Some(value),
        _ => None,
    }
}

/// `Ok(None)` when absent, `Ok(Some(text))` when usable, `Err(())` when the
/// field is present but blank or not text.
fn optional_text(field: &DaemonTextFieldV1) -> Result<Option<&str>, ()> {
    match field {
        DaemonTextFieldV1::Absent => Ok(None),
        DaemonTextFieldV1::Text { value } if !value.is_empty() => Ok(Some(value)),
        _ => Err(()),
    }
}

fn matched_route(path: &str, action: &DaemonTextFieldV1) -> Option<(String, Option<String>)> {
    let parts = segments(path);
    let n = parts.len();
    if n == 4 && parts[..2] == ["v1", "requests"] && matches!(parts[3], "approve" | "block") {
        let action = if parts[3] == "approve" {
            "allow"
        } else {
            "block"
        };
        return Some((parts[2].to_owned(), Some(action.to_owned())));
    }
    if n == 3 && parts[0] == "approvals" && parts[2] == "decision" {
        return Some((parts[1].to_owned(), text(action).map(str::to_owned)));
    }
    if n == 4 && parts[..2] == ["v1", "approvals"] && parts[3] == "decision" {
        return Some((parts[2].to_owned(), text(action).map(str::to_owned)));
    }
    None
}

fn version_is_valid(version: &str) -> bool {
    version
        .strip_prefix(SCOPE_CONTRACT_VERSION_PREFIX)
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
}

fn digest_is_valid(digest: &str) -> bool {
    digest.chars().count() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn outcome(name: &str) -> DaemonRoutePayloadV1 {
    DaemonRoutePayloadV1::ResolveRequest {
        outcome: name.to_owned(),
        request_id: None,
        action: None,
        scope: None,
        scope_contract_version: None,
        scope_contract_digest: None,
    }
}

pub(crate) fn resolve_request(
    path: &str,
    action: &DaemonTextFieldV1,
    scope: &DaemonTextFieldV1,
    version: &DaemonTextFieldV1,
    digest: &DaemonTextFieldV1,
) -> DaemonRoutePayloadV1 {
    let Some((request_id, action)) = matched_route(path, action) else {
        return outcome("not_matched");
    };
    let (Some(action), Some(scope)) = (action, text(scope)) else {
        return outcome("missing_required_fields");
    };
    let version = match optional_text(version) {
        Ok(value) if value.is_none_or(version_is_valid) => value,
        _ => return outcome("invalid_scope_contract_version"),
    };
    let digest = match optional_text(digest) {
        Ok(value) if value.is_none_or(digest_is_valid) => value,
        _ => return outcome("invalid_scope_contract_digest"),
    };
    DaemonRoutePayloadV1::ResolveRequest {
        outcome: "resolved".to_owned(),
        request_id: Some(request_id),
        action: Some(action),
        scope: Some(scope.to_owned()),
        scope_contract_version: version.map(str::to_owned),
        scope_contract_digest: digest.map(str::to_owned),
    }
}
