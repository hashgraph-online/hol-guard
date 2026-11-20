//! `record_codex_mutation_identity`: the Codex authority mutation journal.
//!
//! Each line names one file a Codex install transaction changed: a digest of
//! its path, whether it existed before and after, and the content digests,
//! never the contents. The private key's digests are always withheld. The
//! journal is a bounded diagnostic: a file past 1 MiB is moved to `.jsonl.1`
//! and a fresh one started, and a failure to append is counted in
//! `dropped_events` rather than replacing the transaction's own error.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use super::inspect::{resolve_lenient, sha256_hex};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SCHEMA: &str = "hol-guard.codex-authority-mutation.v1";
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;
const MAX_MUTATIONS: usize = 1024;
const PRIVATE_KEY_NAME: &str = "hook-manifest.key";

/// The transaction the lines belong to, as the owning process holds it.
pub(super) struct Owner<'a> {
    pub(super) operation_id: &'a str,
    pub(super) config_target_id: &'a str,
    pub(super) actor: &'a str,
    pub(super) pid: u64,
    pub(super) process_identity: &'a str,
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn flag(fields: &Map<String, Value>, key: &str) -> Result<bool, &'static str> {
    fields.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID)
}

fn digest(fields: &Map<String, Value>, key: &str) -> Result<Option<String>, &'static str> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(ERR_INVALID),
    }
}

/// `_verify_lock_file`: the journal is one regular file this account owns
/// alone, and the handle is the file at the path.
fn verify(path: &Path, handle: &fs::File) -> std::io::Result<()> {
    let opened = handle.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let mut safe = opened.is_file() && current.is_file();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        safe = safe
            && opened.nlink() == 1
            && (opened.dev(), opened.ino()) == (current.dev(), current.ino())
            && opened.uid() == nix::unistd::geteuid().as_raw()
            && opened.permissions().mode() & 0o077 == 0;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        safe = safe && current.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0;
    }
    if safe {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "Codex transaction ownership file is unsafe.",
        ))
    }
}

fn open_append(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn create_new(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// One line, in the key order the Python journal wrote.
fn line(
    owner: &Owner<'_>,
    mutation: &Map<String, Value>,
    dropped: u64,
) -> Result<String, &'static str> {
    let path = PathBuf::from(text(mutation, "path")?);
    let private = path
        .file_name()
        .is_some_and(|name| name == PRIVATE_KEY_NAME);
    let before_present = flag(mutation, "before_present")?;
    let after_present = flag(mutation, "after_present")?;
    let kept = |present: bool, value: Option<String>| value.filter(|_| present && !private);
    let time_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut event = Map::new();
    let mut put = |key: &str, value: Value| {
        event.insert(key.to_owned(), value);
    };
    put("schema", SCHEMA.into());
    put("operation_id", owner.operation_id.into());
    put(
        "target_id",
        sha256_hex(resolve_lenient(&path).to_string_lossy().as_bytes()).into(),
    );
    put("config_target_id", owner.config_target_id.into());
    put("actor", owner.actor.into());
    put("pid", owner.pid.into());
    put("process_identity", owner.process_identity.into());
    put(
        "time_ns",
        serde_json::from_str::<Value>(&time_ns.to_string()).map_err(|_| ERR_INVALID)?,
    );
    put("operation", text(mutation, "operation")?.into());
    put("dropped_events", dropped.into());
    put("before_present", before_present.into());
    put("after_present", after_present.into());
    put(
        "before_digest",
        kept(before_present, digest(mutation, "before_digest")?).into(),
    );
    put(
        "after_digest",
        kept(after_present, digest(mutation, "after_digest")?).into(),
    );
    let mut rendered = serde_json::to_string(&Value::Object(event)).map_err(|_| ERR_INVALID)?;
    rendered.push('\n');
    Ok(rendered)
}

fn append(journal: &Path, line: &str) -> std::io::Result<()> {
    let mut handle = open_append(journal)?;
    verify(journal, &handle)?;
    if handle.metadata()?.len() >= MAX_JOURNAL_BYTES {
        // Only the exclusive transaction owner rotates this bounded journal.
        let backup = journal.with_extension("jsonl.1");
        if fs::symlink_metadata(&backup).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(std::io::Error::other("journal backup is a link"));
        }
        drop(handle);
        fs::rename(journal, &backup)?;
        return create_new(journal)?.write_all(line.as_bytes());
    }
    handle.write_all(line.as_bytes())
}

/// Append each mutation in order. A line that cannot be written is counted,
/// and the count carried into the next line, as the Python journal's
/// process-wide `_dropped_events` did. Answers the running count.
pub(super) fn append_all(
    guard_home: &Path,
    owner: &Owner<'_>,
    mutations: &[Value],
    mut dropped: u64,
) -> Result<u64, &'static str> {
    if mutations.len() > MAX_MUTATIONS {
        return Err(ERR_INVALID);
    }
    let journal = guard_home
        .join("managed")
        .join("codex")
        .join("authority-mutations.jsonl");
    for mutation in mutations {
        let mutation = mutation.as_object().ok_or(ERR_INVALID)?;
        let rendered = line(owner, mutation, dropped)?;
        if append(&journal, &rendered).is_err() {
            dropped += 1;
        }
    }
    Ok(dropped)
}

/// `op: "journal"`: append each mutation of a caller-described owner.
pub(super) fn dispatch(args: &Map<String, Value>) -> KindResult {
    let guard_home = PathBuf::from(text(args, "guard_home")?);
    let owner = args
        .get("owner")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let dropped = owner
        .get("dropped_events")
        .and_then(Value::as_u64)
        .ok_or(ERR_INVALID)?;
    let owner = Owner {
        operation_id: text(owner, "operation_id")?,
        config_target_id: text(owner, "config_target_id")?,
        actor: text(owner, "actor")?,
        pid: owner
            .get("pid")
            .and_then(Value::as_u64)
            .ok_or(ERR_INVALID)?,
        process_identity: text(owner, "process_identity")?,
    };
    let mutations = args
        .get("mutations")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let dropped = append_all(&guard_home, &owner, mutations, dropped)?;
    Ok(serde_json::json!({ "ok": true, "dropped_events": dropped }))
}
