//! The daemon lifecycle journal (`<guard home>/daemon-lifecycle/`): one small
//! private JSON file per event, read back by `load_events` without opening
//! Guard SQLite. Writing is best effort, as it was for the daemon.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

const DIRECTORY: &str = "daemon-lifecycle";
const MAX_ENTRIES: usize = 128;
const MAX_EVENT_BYTES: u64 = 2048;
const MAX_INCIDENT_SCAN: usize = 256;
const MAX_INCIDENT_ENTRIES: usize = 20;

/// Records `event` for this process; failures are ignored.
pub(super) fn record(
    guard_home: &Path,
    event: &str,
    reason: Option<&str>,
    session_id: Option<&str>,
    port: Option<u16>,
) {
    let _ = write(
        guard_home,
        std::process::id(),
        event,
        reason,
        session_id,
        port,
    );
}

/// Records `event` on behalf of another process, such as a daemon being
/// retired; failures are ignored.
pub(crate) fn record_for_pid(
    guard_home: &Path,
    pid: u32,
    event: &str,
    reason: Option<&str>,
    session_id: Option<&str>,
) {
    if pid > 0 {
        let _ = write(guard_home, pid, event, reason, session_id, None);
    }
}

fn write(
    guard_home: &Path,
    pid: u32,
    event: &str,
    reason: Option<&str>,
    session_id: Option<&str>,
    port: Option<u16>,
) -> Option<()> {
    if !safe_label(event) || reason.is_some_and(|reason| !safe_label(reason)) {
        return None;
    }
    if session_id.is_some_and(|id| !safe_session_id(id)) || port == Some(0) {
        return None;
    }
    let directory = guard_home.join(DIRECTORY);
    if is_symlink(guard_home) || is_symlink(&directory) {
        return None;
    }
    fs::create_dir_all(&directory).ok()?;
    if !directory.is_dir() {
        return None;
    }
    private_mode(&directory, 0o700);
    let recorded_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    // Keys sorted, as `json.dumps(..., sort_keys=True)` wrote them.
    let mut payload = Map::new();
    payload.insert("event".into(), event.into());
    payload.insert("pid".into(), pid.into());
    if let Some(port) = port {
        payload.insert("port".into(), port.into());
    }
    if let Some(reason) = reason {
        payload.insert("reason".into(), reason.into());
    }
    payload.insert(
        "recorded_at_ns".into(),
        Value::from(u64::try_from(recorded_at_ns).ok()?),
    );
    if let Some(session_id) = session_id {
        payload.insert("session_id".into(), session_id.into());
    }
    payload.insert("version".into(), 1.into());
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).ok()?;
    let identifier = hex::encode(nonce);
    let target = directory.join(format!("{recorded_at_ns:020}-{pid:010}-{identifier}.json"));
    let temporary = directory.join(format!(".{identifier}.tmp"));
    let written = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).ok()?;
        file.write_all(Value::Object(payload).to_string().as_bytes())
            .ok()?;
        file.sync_all().ok()?;
        drop(file);
        fs::rename(&temporary, &target).ok()
    })();
    let _ = fs::remove_file(&temporary);
    written?;
    private_mode(&target, 0o600);
    prune(&directory);
    Some(())
}

fn prune(directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut names: Vec<_> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .filter(|name| {
            let name = name.to_string_lossy();
            !name.starts_with('.') && name.ends_with(".json")
        })
        .collect();
    names.sort();
    let excess = names.len().saturating_sub(MAX_ENTRIES);
    for name in &names[..excess] {
        let _ = fs::remove_file(directory.join(name));
    }
}

/// The newest `limit` valid events, oldest first. `incident` caps the
/// directory scan and the timeline, and reports why entries are missing:
/// `ok`, `invalid_entries_omitted`, `journal_unavailable`,
/// `journal_path_unsafe` or `journal_scan_limit`.
pub(crate) fn load_events(
    guard_home: &Path,
    limit: usize,
    incident: bool,
) -> (Vec<Value>, &'static str) {
    let directory = guard_home.join(DIRECTORY);
    if is_symlink(&directory) {
        return (Vec::new(), "journal_path_unsafe");
    }
    let Ok(entries) = fs::read_dir(&directory) else {
        return (Vec::new(), "journal_unavailable");
    };
    let mut names = Vec::new();
    for (index, entry) in entries.enumerate() {
        if incident && index >= MAX_INCIDENT_SCAN {
            return (Vec::new(), "journal_scan_limit");
        }
        let Ok(entry) = entry else {
            return (Vec::new(), "journal_unavailable");
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".json") && (incident || !name.starts_with('.')) {
            names.push(name);
        }
    }
    let cap = if incident {
        MAX_INCIDENT_ENTRIES
    } else {
        MAX_ENTRIES
    };
    names.sort_unstable_by(|left, right| right.cmp(left));
    names.truncate(limit.min(cap));
    let mut invalid = false;
    let mut events = Vec::new();
    for name in &names {
        match read_event(&directory.join(name)) {
            Some(event) => events.push(event),
            None => invalid = true,
        }
    }
    events.reverse();
    (
        events,
        if invalid {
            "invalid_entries_omitted"
        } else {
            "ok"
        },
    )
}

fn read_event(path: &Path) -> Option<Value> {
    let raw =
        crate::daemon_policy_authority::read_private_regular_text(path, MAX_EVENT_BYTES, false)?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    let event = value.as_object()?;
    let optional_text = |key: &str, check: fn(&str) -> bool| {
        event
            .get(key)
            .is_none_or(|item| item.as_str().is_some_and(check))
    };
    let port_ok = event.get("port").is_none_or(|port| {
        port.as_u64()
            .is_some_and(|port| (1..=65_535).contains(&port))
    });
    let valid = event.get("version").and_then(Value::as_i64) == Some(1)
        && event
            .get("event")
            .and_then(Value::as_str)
            .is_some_and(safe_label)
        && event
            .get("recorded_at_ns")
            .and_then(Value::as_u64)
            .is_some_and(|at| at > 0)
        && event
            .get("pid")
            .and_then(Value::as_u64)
            .is_some_and(|pid| pid > 0)
        && optional_text("session_id", safe_session_id)
        && optional_text("reason", safe_label)
        && port_ok;
    valid.then_some(value)
}

/// `^[a-z][a-z0-9_-]{0,63}$`.
fn safe_label(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && value.len() <= 64
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

/// `^[A-Za-z0-9_-]{1,128}$`.
fn safe_session_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

#[cfg(unix)]
fn private_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn private_mode(_path: &Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_a_ready_event_load_events_reads() {
        let home = tempfile::tempdir().unwrap();
        record(home.path(), "ready", None, Some("abc123"), Some(4781));
        let entries: Vec<_> = fs::read_dir(home.path().join(DIRECTORY))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1);
        let value: Value = serde_json::from_slice(&fs::read(&entries[0]).unwrap()).unwrap();
        assert_eq!(value["event"], "ready");
        assert_eq!(value["version"], 1);
        assert_eq!(value["port"], 4781);
        assert_eq!(value["session_id"], "abc123");
    }

    #[test]
    fn load_events_returns_newest_valid_oldest_first() {
        let home = tempfile::tempdir().unwrap();
        record(home.path(), "starting", None, None, None);
        record(home.path(), "ready", None, None, Some(4781));
        let directory = home.path().join(DIRECTORY);
        fs::write(directory.join("99999999999999999999-bad.json"), "{}").unwrap();
        let (events, status) = load_events(home.path(), 20, true);
        assert_eq!(status, "invalid_entries_omitted");
        let names: Vec<_> = events.iter().map(|event| event["event"].clone()).collect();
        assert_eq!(names, vec![Value::from("starting"), Value::from("ready")]);
        let (latest, _) = load_events(home.path(), 1, false);
        assert!(latest.is_empty());
        assert_eq!(
            load_events(&home.path().join("missing"), 5, true).1,
            "journal_unavailable"
        );
    }

    #[test]
    fn refuses_unsafe_labels() {
        let home = tempfile::tempdir().unwrap();
        record(home.path(), "Ready", None, None, None);
        record(home.path(), "ready", Some("bad reason"), None, None);
        assert!(!home.path().join(DIRECTORY).exists());
    }
}
