//! Compatibility and health payload checks for the resident daemon authority.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use super::http::http_get_json;
use super::{GUARD_DAEMON_COMPATIBILITY_VERSION, REQUIRED_DAEMON_TABLES};

/// `daemon_state_matches_current_runtime` (runtime_peer.py:105-:135).
pub(crate) fn daemon_state_matches_current_runtime(payload: &Map<String, Value>) -> bool {
    if payload.get("compatibility_version").and_then(Value::as_i64)
        != Some(GUARD_DAEMON_COMPATIBILITY_VERSION)
    {
        return false;
    }
    let fingerprint = payload.get("runtime_fingerprint").and_then(Value::as_str);
    if fingerprint.is_none_or(|f| f.trim().is_empty()) {
        return false;
    }
    payload
        .get("package_version")
        .and_then(Value::as_str)
        .is_some_and(|v| v == crate::PACKAGE_VERSION)
}

/// `_healthz_payload_is_current`.
pub(crate) fn healthz_payload_is_current(payload: &Value) -> bool {
    let Some(map) = payload.as_object() else {
        return false;
    };
    if map.get("compatibility_version").and_then(Value::as_i64)
        != Some(GUARD_DAEMON_COMPATIBILITY_VERSION)
    {
        return false;
    }
    match map.get("tables") {
        None => true,
        Some(Value::Array(tables)) => {
            let names: BTreeSet<&str> = tables.iter().filter_map(Value::as_str).collect();
            REQUIRED_DAEMON_TABLES
                .iter()
                .all(|required| names.contains(required))
        }
        Some(_) => false,
    }
}

/// `_daemon_healthz_details_match_guard_home` +
/// `_daemon_healthz_details_match_current_runtime`.
pub(crate) fn daemon_healthz_details_match(
    base_url: &str,
    auth_token: &str,
    guard_home: &Path,
    state: &Map<String, Value>,
) -> bool {
    let headers = [("X-Guard-Token", auth_token)];
    let Some(payload) = http_get_json(&format!("{base_url}/v1/healthz/details"), &headers) else {
        return false;
    };
    if !healthz_payload_matches_guard_home(&payload, guard_home) {
        return false;
    }
    let Some(details) = payload.as_object() else {
        return false;
    };
    daemon_state_matches_compatible_runtime(details)
        && healthz_details_match_state_identity(details, state)
}

/// Accept a newer Desktop-owned daemon when it is compatible with this runtime.
pub(crate) fn daemon_state_matches_compatible_runtime(payload: &Map<String, Value>) -> bool {
    if payload.get("source_root").is_none() {
        return daemon_state_matches_current_runtime(payload);
    }
    let current = Map::from_iter([(
        "package_version".to_owned(),
        Value::String(crate::PACKAGE_VERSION.to_owned()),
    )]);
    crate::daemon_manage::ensure::state_matches(&current, payload)
}

fn healthz_details_match_state_identity(
    details: &Map<String, Value>,
    state: &Map<String, Value>,
) -> bool {
    if let (Some(d), Some(s)) = (
        details.get("state_id").and_then(Value::as_str),
        state.get("state_id").and_then(Value::as_str),
    ) {
        if d != s {
            return false;
        }
    }
    true
}

/// `_healthz_payload_matches_guard_home`.
pub(crate) fn healthz_payload_matches_guard_home(payload: &Value, guard_home: &Path) -> bool {
    let Some(reported) = payload.get("guard_home").and_then(Value::as_str) else {
        return false;
    };
    if reported.trim().is_empty() {
        return false;
    }
    paths_equal_resolved(Path::new(reported), guard_home)
}

pub(crate) fn paths_equal_resolved(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(l), Ok(r)) => l == r,
        _ => left == right,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_state_matches_current_runtime_requires_matching_package_version() {
        let mut payload = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "runtime_fingerprint": "runtime-fingerprint",
            "package_version": crate::PACKAGE_VERSION,
        });
        assert!(daemon_state_matches_current_runtime(
            payload.as_object().unwrap()
        ));

        payload["package_version"] = Value::String("different-version".to_owned());
        assert!(!daemon_state_matches_current_runtime(
            payload.as_object().unwrap()
        ));

        payload["package_version"] = Value::String(crate::PACKAGE_VERSION.to_owned());
        payload["runtime_fingerprint"] = Value::String("  ".to_owned());
        assert!(!daemon_state_matches_current_runtime(
            payload.as_object().unwrap()
        ));

        payload["runtime_fingerprint"] = Value::String("runtime-fingerprint".to_owned());
        payload["compatibility_version"] = Value::from(GUARD_DAEMON_COMPATIBILITY_VERSION + 1);
        assert!(!daemon_state_matches_current_runtime(
            payload.as_object().unwrap()
        ));
    }

    #[test]
    fn compatible_newer_desktop_daemon_is_accepted() {
        let root = tempfile::tempdir().expect("tempdir");
        let source_root = root
            .path()
            .join("org.hol.guard.desktop/core/versions/99.0.0");
        fs::create_dir_all(&source_root).expect("source root");
        let payload = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "runtime_fingerprint": "runtime-fingerprint",
            "package_version": "99.0.0",
            "source_root": source_root.to_string_lossy(),
        });
        assert!(daemon_state_matches_compatible_runtime(
            payload.as_object().expect("object")
        ));
    }

    #[test]
    fn healthz_payload_requires_current_compatibility_and_required_tables() {
        let current = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "tables": REQUIRED_DAEMON_TABLES,
        });
        assert!(healthz_payload_is_current(&current));

        let without_tables = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
        });
        assert!(healthz_payload_is_current(&without_tables));

        let missing_required_table = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "tables": [],
        });
        assert!(!healthz_payload_is_current(&missing_required_table));

        let outdated_compatibility = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION + 1,
            "tables": REQUIRED_DAEMON_TABLES,
        });
        assert!(!healthz_payload_is_current(&outdated_compatibility));
    }
}
