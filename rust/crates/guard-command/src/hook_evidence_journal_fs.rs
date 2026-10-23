//! `daemon/runtime_hook_evidence_journal.py` — the journal's filesystem half.
//!
//! The record types and their `serialized()` bytes live in the writer; this
//! module owns the durable side: a cross-process lock, an `O_APPEND` write
//! that truncates back on failure, the private preview sidecar, and the
//! bounded reader that counts the lines it could not parse.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Map, Value};

#[cfg(unix)]
use super::JOURNAL_FILE_MODE;
use super::{
    ComposioApi, EvidenceJournalApi, EvidenceRecord, ReceiptValidationApi, EVIDENCE_SCHEMA,
};

/// `command_activity_display.INVOCATION_PREVIEW_MAX_CHARS`.
const INVOCATION_PREVIEW_MAX_CHARS: usize = 4_096;

/// The journal seam backed by this host's filesystem.
pub struct NativeEvidenceJournal {
    receipts: Arc<dyn ReceiptValidationApi + Send + Sync>,
    composio: Arc<dyn ComposioApi + Send + Sync>,
}

impl NativeEvidenceJournal {
    /// The record validators decide which journal lines survive a rewrite, so
    /// the journal shares the writer's, rather than keeping a second pair.
    pub fn new(
        receipts: Arc<dyn ReceiptValidationApi + Send + Sync>,
        composio: Arc<dyn ComposioApi + Send + Sync>,
    ) -> Self {
        Self { receipts, composio }
    }

    fn parse(&self, value: &Map<String, Value>) -> Option<EvidenceRecord> {
        EvidenceRecord::from_json(value, &*self.receipts, &*self.composio)
    }

    /// `_read_journal_records_locked` (:223-251) — decode every line, then run
    /// it through the record validators, counting both steps' failures.
    ///
    /// A line that decodes but fails validation, such as a receipt whose
    /// `decision_id` was edited on disk, is dropped by the rewrite below. It
    /// has to be counted here, or the writer deletes it without ever going
    /// degraded or recording a failure.
    fn read_journal_records(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> Result<(Vec<EvidenceRecord>, u64), io::Error> {
        let (raw, mut invalid_records) = read_journal_lines(path, max_bytes)?;
        let mut records = Vec::with_capacity(raw.len());
        for value in &raw {
            match self.parse(value) {
                Some(record) => records.push(record),
                None => invalid_records += 1,
            }
        }
        Ok((records, invalid_records))
    }
}

impl EvidenceJournalApi for NativeEvidenceJournal {
    fn append_journal(&self, path: &Path, record: &EvidenceRecord) -> Result<(), io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _lock = JournalLock::acquire(path)?;
        let mut file = open_journal_append(path)?;
        let original_size = file.metadata()?.len();
        let appended = file
            .write_all(&record.serialized())
            .and_then(|()| file.sync_all())
            .and_then(|()| append_preview_sidecar(path, record));
        if let Err(error) = appended {
            file.set_len(original_size)?;
            return Err(error);
        }
        Ok(())
    }

    fn rewrite_journal(
        &self,
        path: &Path,
        remove_record_id: &str,
        max_bytes: usize,
    ) -> Result<u64, io::Error> {
        let _lock = JournalLock::acquire(path)?;
        let (records, invalid_records) = self.read_journal_records(path, max_bytes)?;
        let remaining: Vec<EvidenceRecord> = records
            .into_iter()
            .filter(|record| record.record_id() != remove_record_id)
            .collect();
        let mut body = Vec::new();
        for record in &remaining {
            body.extend_from_slice(&record.serialized());
        }
        replace_private_file(path, &body)?;
        let keep: Vec<String> = remaining.iter().map(EvidenceRecord::record_id).collect();
        rewrite_preview_sidecar(path, &keep, max_bytes)?;
        Ok(invalid_records)
    }

    fn recover_journal_records(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> Result<(Vec<Map<String, Value>>, u64), io::Error> {
        let _lock = JournalLock::acquire(path)?;
        let (mut raw, invalid_records) = read_journal_lines(path, max_bytes)?;
        let previews = read_preview_sidecar(path, max_bytes)?;
        if !previews.is_empty() {
            for value in &mut raw {
                // Only command activity has an invocation preview. Attaching
                // one to another record's object adds a field its strict
                // parser rejects, so a sidecar entry naming an MCP discovery
                // record would delete that record's evidence on replay.
                if value.get("schema").and_then(Value::as_str) != Some(EVIDENCE_SCHEMA) {
                    continue;
                }
                let Some(record_id) = value.get("record_id").and_then(Value::as_str) else {
                    continue;
                };
                if let Some(preview) = previews.get(record_id) {
                    let preview = Value::String(preview.clone());
                    value.insert("invocation_preview".to_owned(), preview);
                }
            }
        }
        Ok((raw, invalid_records))
    }

    fn now_utc_iso(&self) -> String {
        crate::local_supply_chain::utc_now_iso()
    }
}

/// `_journal_lock` — one exclusive holder across every process that writes
/// this journal, taken on a private regular lock file beside it.
struct JournalLock {
    file: File,
}

impl JournalLock {
    fn acquire(path: &Path) -> Result<Self, io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_path = sibling(path, |name| format!(".{name}.lock"));
        let file = private_options()
            .read(true)
            .write(true)
            .create(true)
            .open(lock_path)?;
        require_private_regular_file(&file)?;
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(Self { file })
    }
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// `_open_journal(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY)`.
fn open_journal_append(path: &Path) -> Result<File, io::Error> {
    let file = private_options().append(true).create(true).open(path)?;
    require_private_regular_file(&file)?;
    Ok(file)
}

/// `_open_journal(path, os.O_RDONLY)` plus the configured size bound.
fn read_bounded(path: &Path, max_bytes: usize, label: &str) -> Result<Option<Vec<u8>>, io::Error> {
    let mut file = match private_options().read(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    require_private_regular_file(&file)?;
    if file.metadata()?.len() > max_bytes as u64 {
        return Err(io::Error::other(label.to_owned()));
    }
    let mut body = Vec::new();
    Read::by_ref(&mut file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut body)?;
    Ok(Some(body))
}

/// `_read_journal_records_locked` — the raw objects plus the line count the
/// caller's validators rejected. A line that is not a JSON object is invalid
/// here; one that parses but fails record validation is counted by the caller.
fn read_journal_lines(
    path: &Path,
    max_bytes: usize,
) -> Result<(Vec<Map<String, Value>>, u64), io::Error> {
    let Some(body) = read_bounded(
        path,
        max_bytes,
        "evidence journal exceeds the configured size limit",
    )?
    else {
        return Ok((Vec::new(), 0));
    };
    let mut records = Vec::new();
    let mut invalid_records = 0;
    for line in body.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<Value>(line) {
            Ok(Value::Object(object)) => records.push(object),
            _ => invalid_records += 1,
        }
    }
    Ok((records, invalid_records))
}

/// `_preview_sidecar_path` — `{stem}.preview{suffix}` beside the journal.
fn preview_sidecar_path(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let suffix = path
        .extension()
        .map(|suffix| format!(".{}", suffix.to_string_lossy()))
        .unwrap_or_default();
    sibling(path, |_| format!("{stem}.preview{suffix}"))
}

/// `_validated_sidecar_preview` — the sidecar never carries a NUL, an empty
/// value, or a preview longer than the display bound.
pub(super) fn validated_sidecar_preview(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.contains('\0') {
        return None;
    }
    let stripped = value.trim();
    if stripped.is_empty() || stripped.chars().count() > INVOCATION_PREVIEW_MAX_CHARS {
        return None;
    }
    Some(stripped.to_owned())
}

fn sidecar_line(record_id: &str, preview: &str) -> Vec<u8> {
    let mut line = json!({"record_id": record_id, "invocation_preview": preview}).to_string();
    line.push('\n');
    line.into_bytes()
}

/// `_append_preview_sidecar` — only a command-activity record carries one.
fn append_preview_sidecar(path: &Path, record: &EvidenceRecord) -> Result<(), io::Error> {
    let EvidenceRecord::CommandActivity(activity) = record else {
        return Ok(());
    };
    let Some(preview) = validated_sidecar_preview(activity.invocation_preview.as_deref()) else {
        return Ok(());
    };
    let mut file = private_options()
        .append(true)
        .create(true)
        .open(preview_sidecar_path(path))?;
    require_private_regular_file(&file)?;
    file.write_all(&sidecar_line(&activity.record_id, &preview))?;
    file.sync_all()
}

/// `_read_preview_sidecar` — record id to preview, in file order.
fn read_preview_sidecar(
    path: &Path,
    max_bytes: usize,
) -> Result<HashMap<String, String>, io::Error> {
    let sidecar = preview_sidecar_path(path);
    let label = "evidence journal preview sidecar exceeds the configured size limit";
    let Some(body) = read_bounded(&sidecar, max_bytes, label)? else {
        return Ok(HashMap::new());
    };
    let mut previews = HashMap::new();
    for line in body.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        let record_id = object.get("record_id").and_then(Value::as_str);
        let preview =
            validated_sidecar_preview(object.get("invocation_preview").and_then(Value::as_str));
        if let (Some(record_id), Some(preview)) = (record_id, preview) {
            previews.insert(record_id.to_owned(), preview);
        }
    }
    Ok(previews)
}

/// `_rewrite_preview_sidecar` — drop every preview whose record is gone, and
/// remove the sidecar once nothing is left to carry.
fn rewrite_preview_sidecar(
    path: &Path,
    keep: &[String],
    max_bytes: usize,
) -> Result<(), io::Error> {
    let previews = read_preview_sidecar(path, max_bytes)?;
    let sidecar = preview_sidecar_path(path);
    let mut body = Vec::new();
    for record_id in keep {
        if let Some(preview) = previews.get(record_id) {
            body.extend_from_slice(&sidecar_line(record_id, preview));
        }
    }
    if body.is_empty() {
        return match fs::remove_file(&sidecar) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        };
    }
    replace_private_file(&sidecar, &body)
}

/// The `O_EXCL` temporary plus `os.replace` both rewrites share: another
/// reader sees either the old file or the new one, never a partial one.
fn replace_private_file(path: &Path, body: &[u8]) -> Result<(), io::Error> {
    let temporary = sibling(path, |name| format!(".{name}.{}.tmp", unique_suffix()));
    let written = (|| -> Result<(), io::Error> {
        let mut file = private_options()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

/// `uuid4().hex` — a name no concurrent rewrite of this journal reuses. The
/// fallback keeps a rewrite working on a host that cannot spare entropy.
fn unique_suffix() -> String {
    let mut bytes = [0_u8; 16];
    if getrandom::fill(&mut bytes).is_ok() {
        return hex::encode(bytes);
    }
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!("{:x}{:x}", std::process::id(), elapsed)
}

fn sibling(path: &Path, name: impl FnOnce(&str) -> String) -> PathBuf {
    let current = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    match path.parent() {
        Some(parent) => parent.join(name(&current)),
        None => PathBuf::from(name(&current)),
    }
}

/// The journal, its lock and its sidecar are private regular files. A symlink
/// or a hard link in their place is a redirect, not a journal.
fn require_private_regular_file(file: &File) -> Result<(), io::Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other(
            "evidence journal is not a private regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        if metadata.nlink() != 1 {
            return Err(io::Error::other(
                "evidence journal is not a private regular file",
            ));
        }
        let mut permissions = metadata.permissions();
        if permissions.mode() & 0o777 != JOURNAL_FILE_MODE {
            permissions.set_mode(JOURNAL_FILE_MODE);
            file.set_permissions(permissions)?;
        }
    }
    Ok(())
}

fn private_options() -> OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(JOURNAL_FILE_MODE);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
}

#[cfg(all(test, unix))]
#[path = "hook_evidence_journal_fs_tests.rs"]
mod tests;
