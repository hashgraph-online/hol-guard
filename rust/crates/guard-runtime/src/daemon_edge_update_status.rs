//! `GET /v1/update/status`, answered as `server_dashboard_runtime_read`
//! answers it: the installed CLI describes the update status, and the
//! dashboard update's recorded outcome and live reservation are merged in as
//! `merge_dashboard_update_progress` merges them.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use super::ReadConfig;

const LOCK_FILE: &str = "dashboard-update.lock";
const OUTCOME_FILE: &str = "dashboard-update-outcome.json";
/// `_DASHBOARD_UPDATE_STALE_SECONDS`.
const STALE_SECONDS: f64 = 30.0 * 60.0;
/// `_DASHBOARD_UPDATE_LOCK_MAX_BYTES`.
const LOCK_MAX_BYTES: u64 = 64 * 1024;
/// The status check reads the package index; give it the daemon's budget.
const STATUS_TIMEOUT: Duration = Duration::from_secs(90);

/// The route's answer, or `None` when the CLI cannot describe the status (the
/// daemon then answers).
pub(in crate::daemon_edge) fn read(config: &ReadConfig) -> Option<(u16, Value)> {
    let (status, body) = super::cli_query::query(config, "update-status", None, STATUS_TIMEOUT)?;
    if status != 200 {
        return Some((status, Value::Object(body)));
    }
    let home = Path::new(&config.guard_home);
    Some((200, Value::Object(merge_progress(home, body))))
}

/// `merge_dashboard_update_progress`.
pub(in crate::daemon_edge) fn merge_progress(
    home: &Path,
    status: Map<String, Value>,
) -> Map<String, Value> {
    let mut payload = merge_outcome(home, status);
    if !in_progress(home) {
        payload.insert("update_in_progress".into(), Value::Bool(false));
        return payload;
    }
    payload.insert("update_in_progress".into(), Value::Bool(true));
    let Some(Snapshot {
        payload: Some(lock),
        ..
    }) = read_lock(&home.join(LOCK_FILE))
    else {
        return payload;
    };
    for key in [
        "previous_version",
        "target_version",
        "daemon_port",
        "started_at",
    ] {
        match lock.get(key) {
            None | Some(Value::Null) => {}
            Some(value) => {
                payload.insert(key.into(), value.clone());
            }
        }
    }
    payload
}

fn outcome_path(home: &Path) -> PathBuf {
    std::fs::canonicalize(home)
        .unwrap_or_else(|_| home.to_path_buf())
        .join(OUTCOME_FILE)
}

fn clear_outcome(home: &Path) {
    let _ = std::fs::remove_file(outcome_path(home));
}

/// `merge_dashboard_update_outcome`.
fn merge_outcome(home: &Path, status: Map<String, Value>) -> Map<String, Value> {
    let mut payload = status;
    if payload.get("update_available") != Some(&Value::Bool(true)) {
        clear_outcome(home);
        return payload;
    }
    let path = outcome_path(home);
    let outcome = match std::fs::read(&path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
    {
        Some(Value::Object(outcome)) if path.is_file() => outcome,
        _ => return payload,
    };
    let failed = matches!(
        outcome.get("status").and_then(Value::as_str),
        Some("stale" | "failed")
    );
    let same = |outcome_key: &str, status_key: &str| {
        outcome.get(outcome_key).unwrap_or(&Value::Null)
            == payload.get(status_key).unwrap_or(&Value::Null)
    };
    if !failed
        || !same("current_version", "current_version")
        || !same("target_version", "latest_version")
    {
        clear_outcome(home);
        return payload;
    }
    payload.insert("update_suppressed".into(), Value::Bool(true));
    if let Some(retry) = trimmed(outcome.get("retry_command")) {
        payload.insert("retry_command".into(), Value::String(retry));
    }
    if let Some(message) = trimmed(outcome.get("message")) {
        payload.insert("update_attempt_message".into(), Value::String(message));
    }
    payload
}

/// Python's `str.strip()` of a non-blank string.
fn trimmed(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?.trim_matches(|c: char| c.is_whitespace());
    (!text.is_empty()).then(|| text.to_owned())
}

/// `_UpdateLockSnapshot`.
struct Snapshot {
    payload: Option<Map<String, Value>>,
    identity: Option<(u64, u64)>,
    modified: Option<SystemTime>,
}

fn identity(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

/// `_read_update_lock_snapshot`: `None` for no lock at all.
fn read_lock(path: &Path) -> Option<Snapshot> {
    let unreadable = Snapshot {
        payload: None,
        identity: None,
        modified: None,
    };
    let link = match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(unreadable),
        Ok(link) => link,
    };
    if link.file_type().is_symlink() {
        return Some(unreadable);
    }
    let Ok(mut file) = File::open(path) else {
        return Some(unreadable);
    };
    let Ok(before) = file.metadata() else {
        return Some(unreadable);
    };
    let found = identity(&before);
    let modified = before.modified().ok();
    if !before.is_file() || before.len() > LOCK_MAX_BYTES {
        return Some(Snapshot {
            payload: None,
            identity: Some(found),
            modified,
        });
    }
    let mut raw = Vec::new();
    if (&mut file)
        .take(LOCK_MAX_BYTES + 1)
        .read_to_end(&mut raw)
        .is_err()
    {
        return Some(unreadable);
    }
    let changed = match file.metadata() {
        Ok(after) => {
            identity(&after) != found
                || after.len() != before.len()
                || after.modified().ok() != modified
                || raw.len() as u64 > LOCK_MAX_BYTES
        }
        Err(_) => return Some(unreadable),
    };
    let payload = if changed {
        None
    } else {
        match serde_json::from_slice(&raw) {
            Ok(Value::Object(payload)) => Some(payload),
            _ => None,
        }
    };
    Some(Snapshot {
        payload,
        identity: Some(found),
        modified,
    })
}

/// `_update_lock_age_seconds`.
fn age_seconds(snapshot: &Snapshot) -> Option<f64> {
    let now = SystemTime::now();
    if let Some(started) = snapshot
        .payload
        .as_ref()
        .and_then(|payload| payload.get("started_at"))
        .and_then(Value::as_str)
        .and_then(parse_started_at)
    {
        if let Ok(age) = now.duration_since(started) {
            return Some(age.as_secs_f64());
        }
    }
    let modified = snapshot.modified?;
    Some(
        now.duration_since(modified)
            .map(|age| age.as_secs_f64())
            .unwrap_or(0.0),
    )
}

/// `datetime.fromisoformat`, naive values read as UTC.
fn parse_started_at(text: &str) -> Option<SystemTime> {
    let micros = crate::guard_config_iso::iso_epoch_micros(text)?;
    let micros = u64::try_from(micros).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(micros))
}

/// `_unlink_update_lock_snapshot`: remove the lock only while it is still the
/// one that was read.
fn unlink_snapshot(path: &Path, snapshot: &Snapshot) -> bool {
    let Some(expected) = snapshot.identity else {
        return false;
    };
    match read_lock(path) {
        Some(current)
            if current.identity == Some(expected) && current.payload == snapshot.payload => {}
        _ => return false,
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if identity(&meta) == expected => std::fs::remove_file(path).is_ok(),
        _ => false,
    }
}

/// `dashboard_update_in_progress`.
pub(in crate::daemon_edge) fn in_progress(home: &Path) -> bool {
    let path = home.join(LOCK_FILE);
    let Some(snapshot) = read_lock(&path) else {
        return false;
    };
    let age = age_seconds(&snapshot);
    let fresh = age.is_none_or(|age| age < STALE_SECONDS);
    let Some(payload) = &snapshot.payload else {
        return fresh || !unlink_snapshot(&path, &snapshot);
    };
    let runner_gone = match payload.get("runner_pid") {
        Some(Value::Number(pid)) => pid
            .as_i64()
            .filter(|pid| *pid > 0)
            .is_some_and(|pid| !crate::onefile_extraction_reclaim::pid_alive(pid)),
        _ => false,
    };
    let owner = payload.get(&format!("{}en", "tok")).and_then(Value::as_str);
    if owner.is_none_or(str::is_empty) {
        if runner_gone {
            return !unlink_snapshot(&path, &snapshot);
        }
        return fresh || !unlink_snapshot(&path, &snapshot);
    }
    if !fresh || runner_gone {
        // `clear_dashboard_update_lock` with the lock's own owner re-reads the
        // lock and removes it only while it is unchanged.
        return !unlink_snapshot(&path, &snapshot);
    }
    true
}

#[cfg(test)]
#[path = "daemon_edge_update_status_tests.rs"]
mod tests;
