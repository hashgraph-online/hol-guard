//! The daemon lifecycle journal (`<guard home>/daemon-lifecycle/`): one small
//! private JSON file per event, read by `daemon/lifecycle_journal.py` without
//! opening Guard SQLite. Writing is best effort, as it was for the daemon.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

const DIRECTORY: &str = "daemon-lifecycle";
const MAX_ENTRIES: usize = 128;

/// Records `event` for this process; failures are ignored.
pub(super) fn record(
    guard_home: &Path,
    event: &str,
    reason: Option<&str>,
    session_id: Option<&str>,
    port: Option<u16>,
) {
    let _ = write(guard_home, event, reason, session_id, port);
}

fn write(
    guard_home: &Path,
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
    let pid = std::process::id();
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
    fn records_a_ready_event_the_python_journal_reads() {
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
    fn refuses_unsafe_labels() {
        let home = tempfile::tempdir().unwrap();
        record(home.path(), "Ready", None, None, None);
        record(home.path(), "ready", Some("bad reason"), None, None);
        assert!(!home.path().join(DIRECTORY).exists());
    }
}
