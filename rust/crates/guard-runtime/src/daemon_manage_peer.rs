//! Same-release and Desktop-sidecar daemon peers (`runtime_peer.py`): the
//! endpoint a CLI command may use, and when a refresh keeps a live daemon
//! it must not replace.

use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::ensure;
use super::host::{self, Caller};
use super::live_probe;
use crate::daemon_policy_authority::load_guard_daemon_auth_token;

/// One peer query, or `None` when `query` is not one.
pub(super) fn answer(caller: &Caller, args: &Map<String, Value>) -> Option<Value> {
    let home = caller.guard_home.as_path();
    let text = |key: &str| args.get(key).and_then(Value::as_str);
    Some(match text("query")? {
        "desktop_core" => {
            json!({"matches": text("source_root").is_some_and(ensure::source_is_desktop_core)})
        }
        "desktop_owned" => json!({"identity": desktop_owned(home)}),
        "endpoint" => {
            let current = args
                .get("current")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            match endpoint(caller, current) {
                Some((url, auth)) => json!({"url": url, "auth": auth}),
                None => json!({}),
            }
        }
        "retained_newer" => json!({"payload": retained_newer(home, text("minimum_version")?)}),
        "retained_desktop_owner" => {
            json!({"payload": retained_desktop_owner(home, text("minimum_version"))})
        }
        _ => return None,
    })
}

/// `verified_live_guard_daemon_identity`: state and health agree.
fn verified(home: &Path) -> Option<Map<String, Value>> {
    match live_probe::probe_live_with(home, 1.0, false, None) {
        (Some(identity), "healthy") => Some(identity),
        _ => None,
    }
}

/// `live_desktop_owned_daemon`: a verified daemon Guard Desktop supervises.
fn desktop_owned(home: &Path) -> Option<Map<String, Value>> {
    verified(home)
        .filter(|identity| ensure::desktop_core_source_available(identity.get("source_root")))
}

/// `load_guard_daemon_endpoint`: the current runtime's daemon, else a
/// Desktop-owned one whose auth id is this home's auth value.
fn endpoint(caller: &Caller, current: Map<String, Value>) -> Option<(String, String)> {
    let home = caller.guard_home.as_path();
    if let Some(found) = ensure::live_identity(caller, current, true, None) {
        return Some(found);
    }
    let identity = desktop_owned(home)?;
    let identity_home = identity.get("guard_home").and_then(Value::as_str)?;
    if host::resolve_lenient(Path::new(identity_home)) != host::resolve_lenient(home) {
        return None;
    }
    let url = identity
        .get("daemon_url")
        .and_then(Value::as_str)
        .filter(|url| !url.trim().is_empty())?;
    let auth = load_guard_daemon_auth_token(home).filter(|auth| !auth.trim().is_empty())?;
    let id_key = format!("auth_{}_id", "token");
    let auth_id = identity
        .get(&id_key)
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())?;
    let digest = hex::encode(Sha256::digest(auth.as_bytes()));
    constant_time_eq(digest.as_bytes(), auth_id.as_bytes()).then(|| (url.to_owned(), auth))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// `retained_newer_runtime_payload`: keep a verified daemon newer than the caller.
fn retained_newer(home: &Path, minimum: &str) -> Option<Value> {
    let identity = verified(home)?;
    let version = identity.get("package_version").and_then(Value::as_str)?;
    let url = identity.get("daemon_url").and_then(Value::as_str)?;
    ensure::version_at_least(Some(version), Some(minimum), true).then(|| {
        json!({
            "status": "retained_newer_runtime",
            "daemon_url": url,
            "daemon_version": version,
            "cli_version": minimum,
            "runtime_verified": true,
        })
    })
}

/// `retained_desktop_owner_payload`: keep a verified Desktop-owned daemon,
/// at least `minimum` when the caller just activated that release.
fn retained_desktop_owner(home: &Path, minimum: Option<&str>) -> Option<Value> {
    let identity = desktop_owned(home)?;
    let url = identity
        .get("daemon_url")
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())?;
    let version = identity
        .get("package_version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())?;
    if minimum.is_some_and(|minimum| !ensure::version_at_least(Some(version), Some(minimum), false))
    {
        return None;
    }
    Some(json!({
        "status": "retained_desktop_owner",
        "daemon_url": url,
        "daemon_version": version,
        "runtime_verified": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_ids_compare_whole_values() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn an_absent_daemon_is_neither_retained_nor_an_endpoint() {
        let home = tempfile::tempdir().expect("home");
        assert!(desktop_owned(home.path()).is_none());
        assert!(retained_newer(home.path(), "1.0.0").is_none());
        assert!(retained_desktop_owner(home.path(), None).is_none());
    }
}
