//! Codex incident report: the bounded, race-checked reads of `config.toml`
//! and `hooks.json` that `guard/cli/doctor_incident.py` made.

use std::fs::{self, Metadata};
use std::io::{ErrorKind, Read};
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::codex_toml_read;
use crate::pyjson::{self, PyVal};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// One configuration's hooks, the TOML tokens they carry and how each file read.
pub(super) struct HookRead {
    pub(super) hooks: PyVal,
    pub(super) tokens: Map<String, Value>,
    pub(super) status: Map<String, Value>,
}

/// `_read_codex_hook_files`: the TOML `[hooks]` table when there is one,
/// else `hooks.json`'s `hooks`.
pub(super) fn read_hook_files(config: &Path, hooks: &Path) -> HookRead {
    let unread = |status: Map<String, Value>| HookRead {
        hooks: PyVal::Null,
        tokens: Map::new(),
        status,
    };
    let (raw, config_status) = bounded_regular_bytes(config);
    if raw.is_none() && config_status != "missing" {
        return unread(status(&[
            ("config_status", json!(config_status)),
            ("hooks_enabled", Value::Null),
        ]));
    }
    let (payload, tokens) = match raw {
        None => (PyVal::Dict(Vec::new()), Map::new()),
        Some(bytes) => {
            let parsed = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| codex_toml_read::read(text).ok());
            match parsed {
                Some(entries) => codex_toml_read::wire(&entries),
                None => {
                    return unread(status(&[
                        ("config_status", json!("malformed")),
                        ("hooks_enabled", Value::Null),
                    ]))
                }
            }
        }
    };
    let enabled = match payload.get("features") {
        Some(features @ PyVal::Dict(_)) => {
            !matches!(features.get("hooks"), Some(PyVal::Bool(false)))
        }
        _ => true,
    };
    let base = [
        ("config_status", json!(config_status)),
        ("hooks_enabled", json!(enabled)),
    ];
    if let Some(table @ PyVal::Dict(_)) = payload.get("hooks") {
        return HookRead {
            hooks: table.clone(),
            tokens,
            status: status(&base),
        };
    }
    let with_hooks = |hooks_status: &str| {
        let mut fields = status(&base);
        fields.insert("hooks_status".into(), json!(hooks_status));
        fields
    };
    let (raw_hooks, hooks_status) = bounded_regular_bytes(hooks);
    let Some(raw_hooks) = raw_hooks else {
        return unread(with_hooks(hooks_status));
    };
    let decoded = std::str::from_utf8(&raw_hooks)
        .ok()
        .and_then(|text| pyjson::parse(text).ok());
    match decoded {
        Some(document @ PyVal::Dict(_)) => HookRead {
            hooks: document.get("hooks").cloned().unwrap_or(PyVal::Null),
            tokens: Map::new(),
            status: with_hooks("read"),
        },
        _ => unread(with_hooks("malformed")),
    }
}

pub(super) fn status(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

/// `_bounded_regular_bytes`: a regular file of at most 1 MiB, read without
/// following a link and refused when it changes while it is read.
pub(super) fn bounded_regular_bytes(path: &Path) -> (Option<Vec<u8>>, &'static str) {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return (None, "missing"),
        Err(_) => return (None, "unreadable"),
    };
    if !before.file_type().is_file() {
        return (None, "unsafe_file_type");
    }
    if before.len() > MAX_CONFIG_BYTES {
        return (None, "too_large");
    }
    // No-follow and non-blocking: a swapped-in link or FIFO is opened as
    // itself (and then refused as not a regular file) instead of followed
    // or waited on.
    let Ok(file) = crate::local_skill_index::open_no_follow(path) else {
        return (None, "unreadable");
    };
    let Ok(opened) = file.metadata() else {
        return (None, "unreadable");
    };
    if identity(&before) != identity(&opened) {
        return (None, "changed_during_read");
    }
    if !opened.file_type().is_file() {
        return (None, "unsafe_file_type");
    }
    if opened.len() > MAX_CONFIG_BYTES {
        return (None, "too_large");
    }
    let mut data = Vec::new();
    if (&file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut data)
        .is_err()
    {
        return (None, "unreadable");
    }
    let Ok(after) = file.metadata() else {
        return (None, "unreadable");
    };
    if stamp(&opened) != stamp(&after) {
        return (None, "changed_during_read");
    }
    if u64::try_from(data.len()).map_or(true, |length| length > MAX_CONFIG_BYTES) {
        return (None, "too_large");
    }
    (Some(data), "read")
}

#[cfg(unix)]
fn identity(metadata: &Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

/// Windows has no stable file index in `std`. The open does not follow a
/// reparse point, a swapped-in link is refused as not a regular file, and
/// the stamp check after the read refuses a file that changed.
#[cfg(windows)]
fn identity(_metadata: &Metadata) -> (u64, u64) {
    (0, 0)
}

#[cfg(unix)]
fn stamp(metadata: &Metadata) -> [i64; 8] {
    use std::os::unix::fs::MetadataExt;
    let wide = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    [
        wide(metadata.dev()),
        wide(metadata.ino()),
        i64::from(metadata.mode()),
        wide(metadata.size()),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ]
}

#[cfg(windows)]
fn stamp(metadata: &Metadata) -> [i64; 8] {
    use std::os::windows::fs::MetadataExt;
    let wide = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    [
        i64::from(metadata.file_attributes()),
        wide(metadata.file_size()),
        wide(metadata.last_write_time()),
        wide(metadata.creation_time()),
        0,
        0,
        0,
        0,
    ]
}
