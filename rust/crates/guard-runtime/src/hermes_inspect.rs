//! Bounded, race-checked reads of Hermes files: a complete SHA-256 and a
//! separately bounded UTF-8 preview of one regular file, and the fail-closed
//! parse of a Hermes configuration file.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::hermes_yaml::{load, load_json, Failure};
use super::pyjson::PyVal;

pub(crate) const PREVIEW_BYTES: usize = 64 * 1024;
pub(crate) const CONFIG_MAX_BYTES: usize = 2 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct FileInspection {
    pub(crate) preview: String,
    pub(crate) content: Option<String>,
    pub(crate) content_hash: Option<String>,
    pub(crate) size_bytes: u64,
    pub(crate) readable: bool,
    pub(crate) complete: bool,
    pub(crate) analysis_truncated: bool,
    pub(crate) reason: Option<&'static str>,
}

impl FileInspection {
    fn failure(reason: &'static str, preview: String, size_bytes: u64, truncated: bool) -> Self {
        Self {
            preview,
            content: None,
            content_hash: None,
            size_bytes,
            readable: false,
            complete: false,
            analysis_truncated: truncated,
            reason: Some(reason),
        }
    }

    /// Non-content metadata for artifact identity, in Python's key order.
    pub(crate) fn metadata(&self) -> Vec<(String, PyVal)> {
        let mut entries = vec![
            (
                "analysis_truncated".to_owned(),
                PyVal::Bool(self.analysis_truncated),
            ),
            ("inspection_complete".to_owned(), PyVal::Bool(self.complete)),
            ("inspection_readable".to_owned(), PyVal::Bool(self.readable)),
            (
                "preview_bytes".to_owned(),
                PyVal::Int(self.preview.len().to_string()),
            ),
            (
                "size_bytes".to_owned(),
                PyVal::Int(self.size_bytes.to_string()),
            ),
        ];
        if let Some(hash) = &self.content_hash {
            entries.push(("content_hash".to_owned(), PyVal::Str(hash.clone())));
        }
        if let Some(reason) = self.reason {
            entries.push((
                "inspection_reason".to_owned(),
                PyVal::Str(reason.to_owned()),
            ));
        }
        entries
    }
}

/// `bytes.decode("utf-8", errors="ignore")`.
pub(crate) fn decode_ignoring_errors(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
    }
    out
}

pub(crate) type StatKey = (u64, u64, u32, u64, u64, i128, i128, u32);

#[cfg(unix)]
pub(crate) fn stat_key(metadata: &Metadata) -> StatKey {
    use std::os::unix::fs::MetadataExt;
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.nlink(),
        metadata.size(),
        i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
        i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
        0,
    )
}

#[cfg(windows)]
pub(crate) fn stat_key(metadata: &Metadata) -> StatKey {
    use std::os::windows::fs::MetadataExt;
    (
        0,
        0,
        0,
        1,
        metadata.file_size(),
        i128::from(metadata.last_write_time()),
        i128::from(metadata.creation_time()),
        metadata.file_attributes(),
    )
}

fn is_regular(metadata: &Metadata) -> bool {
    metadata.file_type().is_file()
}

fn resolves_within(path: &Path, root: &Path) -> bool {
    match (fs::canonicalize(path), fs::canonicalize(root)) {
        (Ok(resolved), Ok(resolved_root)) => resolved.starts_with(resolved_root),
        _ => false,
    }
}

/// Whether the opened `file` is the file `path` names inside `root`.
///
/// On Windows an ancestor junction swapped between the scope check and the
/// open would let `path` open a file outside the scope. The path the read
/// handle itself resolves to must lie inside the scope: a second open by
/// path proves nothing about where the first one landed, since the same
/// junction can be swapped back in before it. The canonical path is then
/// opened one component at a time, holding each ancestor and refusing every
/// link, and must be that same file (volume and file ID).
#[cfg(windows)]
pub(crate) fn handle_within(file: &File, path: &Path, root: &Path) -> bool {
    use guard_runtime_windows_process::{
        handle_file_id, handle_final_path, open_bound_executable_file,
    };
    let (Ok(canonical), Ok(canonical_root)) = (fs::canonicalize(path), fs::canonicalize(root))
    else {
        return false;
    };
    if !canonical.starts_with(&canonical_root) {
        return false;
    }
    if !handle_final_path(file).is_ok_and(|opened| opened.starts_with(&canonical_root)) {
        return false;
    }
    // The bound open allows extra directory entries, as the path check does.
    let Ok(bound) = open_bound_executable_file(&canonical) else {
        return false;
    };
    matches!(
        (handle_file_id(file), handle_file_id(&bound)),
        (Ok(opened), Ok(checked)) if opened == checked
    )
}

/// POSIX keeps the path check made before the open: `O_NOFOLLOW` refuses a
/// link at the leaf.
#[cfg(not(windows))]
pub(crate) fn handle_within(_file: &File, _path: &Path, _root: &Path) -> bool {
    true
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const OPEN_ATTEMPTS: u32 = 6;
    let mut attempt = 1;
    loop {
        // Share read only: no writer or deleter can change the file under the
        // read. A reparse point is opened as itself, so it reads as not
        // regular instead of being followed.
        let opened = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path);
        match opened {
            // A writer that is just closing the file holds it briefly.
            Err(error)
                if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
                    && attempt < OPEN_ATTEMPTS =>
            {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

/// Checks UTF-8 validity over a stream of chunks, carrying a split sequence.
struct Utf8Stream {
    carry: Vec<u8>,
    invalid: bool,
}

impl Utf8Stream {
    fn feed(&mut self, chunk: &[u8]) {
        if self.invalid {
            return;
        }
        let mut data = std::mem::take(&mut self.carry);
        data.extend_from_slice(chunk);
        match std::str::from_utf8(&data) {
            Ok(_) => {}
            Err(error) if error.error_len().is_none() => {
                self.carry = data[error.valid_up_to()..].to_vec();
            }
            Err(_) => self.invalid = true,
        }
    }

    fn finish(&mut self) {
        if !self.carry.is_empty() {
            self.invalid = true;
        }
    }
}

/// Stream a regular file once, hashing every byte while retaining a preview.
/// `content_limit` decides whether complete text is kept for a parser; it
/// never limits hashing.
pub(crate) fn inspect_text_file(
    path: &Path,
    scope_root: Option<&Path>,
    content_limit: Option<usize>,
) -> FileInspection {
    let none = || String::new();
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return FileInspection::failure("file_missing", none(), 0, false);
        }
        Err(_) => return FileInspection::failure("file_unreadable", none(), 0, false),
    };
    let before_size = before.len();
    if before.file_type().is_symlink() {
        return FileInspection::failure("file_symlink_unsupported", none(), before_size, false);
    }
    if !is_regular(&before) {
        return FileInspection::failure("file_not_regular", none(), before_size, false);
    }
    if let Some(root) = scope_root {
        if !resolves_within(path, root) {
            return FileInspection::failure("file_symlink_escape", none(), before_size, false);
        }
    }
    let mut file = match open_no_follow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return FileInspection::failure("file_changed_during_read", none(), before_size, false);
        }
        Err(_) => return FileInspection::failure("file_unreadable", none(), before_size, false),
    };
    if let Some(root) = scope_root {
        if !handle_within(&file, path, root) {
            return FileInspection::failure("file_symlink_escape", none(), before_size, false);
        }
    }

    let mut preview: Vec<u8> = Vec::new();
    let mut retained: Vec<u8> = Vec::new();
    let mut digest = Sha256::new();
    let mut stream = Utf8Stream {
        carry: Vec::new(),
        invalid: false,
    };
    let mut total: u64 = 0;
    let mut changed = false;
    let Ok(opened) = file.metadata() else {
        return FileInspection::failure("file_unreadable", none(), before_size, false);
    };
    #[cfg(windows)]
    let opened_path = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return FileInspection::failure("file_changed_during_read", none(), before_size, false)
        }
    };
    #[cfg(unix)]
    let opened_path = opened.clone();
    if !is_regular(&opened) || stat_key(&opened_path) != stat_key(&before) {
        changed = true;
    }
    let mut buffer = vec![0u8; READ_CHUNK_BYTES];
    if !changed {
        loop {
            let read = match file.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return FileInspection::failure("file_unreadable", none(), total, false),
            };
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            total += read as u64;
            digest.update(chunk);
            if preview.len() < PREVIEW_BYTES {
                let room = PREVIEW_BYTES - preview.len();
                preview.extend_from_slice(&chunk[..room.min(chunk.len())]);
            }
            if let Some(limit) = content_limit {
                if retained.len() < limit {
                    let room = limit - retained.len();
                    retained.extend_from_slice(&chunk[..room.min(chunk.len())]);
                }
            }
            stream.feed(chunk);
        }
    }
    if !stream.invalid && !changed {
        stream.finish();
    }
    match file.metadata() {
        Ok(final_opened) => {
            if total != opened.len() || stat_key(&final_opened) != stat_key(&opened) {
                changed = true;
            }
        }
        Err(_) => changed = true,
    }
    drop(file);
    match fs::symlink_metadata(path) {
        Ok(after) => {
            if stat_key(&after) != stat_key(&before) {
                changed = true;
            }
        }
        Err(_) => changed = true,
    }
    let preview_text = decode_ignoring_errors(&preview);
    let truncated = total > preview.len() as u64;
    if changed {
        return FileInspection::failure("file_changed_during_read", preview_text, total, truncated);
    }
    let content_hash = Some(format!("sha256:{}", hex::encode(digest.finalize())));
    let incomplete = |reason: &'static str| FileInspection {
        preview: preview_text.clone(),
        content: None,
        content_hash: content_hash.clone(),
        size_bytes: total,
        readable: true,
        complete: false,
        analysis_truncated: truncated,
        reason: Some(reason),
    };
    if stream.invalid {
        return incomplete("file_invalid_utf8");
    }
    if content_limit.is_some_and(|limit| total > limit as u64) {
        return incomplete("file_too_large");
    }
    let content = content_limit.map(|_| String::from_utf8_lossy(&retained).into_owned());
    FileInspection {
        preview: preview_text,
        content,
        content_hash,
        size_bytes: total,
        readable: true,
        complete: true,
        analysis_truncated: truncated,
        reason: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Syntax {
    Json,
    Yaml,
}

#[derive(Debug)]
pub(crate) struct ConfigInspection {
    pub(crate) file: FileInspection,
    pub(crate) payload: Option<Vec<(String, PyVal)>>,
    pub(crate) reason: Option<&'static str>,
}

/// Parse a complete bounded config without accepting a prefix. `Err` is
/// input the Python loader raises an unrelated exception on.
pub(crate) fn inspect_config(
    path: &Path,
    syntax: Syntax,
) -> Result<ConfigInspection, &'static str> {
    inspect_config_keeping_file(path, syntax).map_err(|(_, error)| error)
}

/// Like [`inspect_config`], but a refusal keeps the inspection of the bytes
/// it refused, so the file identity reported with it is the one that failed.
pub(crate) fn inspect_config_keeping_file(
    path: &Path,
    syntax: Syntax,
) -> Result<ConfigInspection, (FileInspection, &'static str)> {
    let file = inspect_text_file(path, None, Some(CONFIG_MAX_BYTES));
    let Some(content) = file.content.as_deref().filter(|_| file.complete) else {
        let reason = file.reason;
        return Ok(ConfigInspection {
            file,
            payload: None,
            reason,
        });
    };
    let loaded = match syntax {
        Syntax::Json => load_json(content),
        Syntax::Yaml => load(content),
    };
    let loaded = match loaded {
        Ok(loaded) => loaded,
        Err(error) => return Err((file, error)),
    };
    let failure = |failure: Failure| ConfigInspection {
        file: file.clone(),
        payload: None,
        reason: Some(failure.reason()),
    };
    let parsed = match loaded {
        Ok(parsed) => parsed,
        Err(reason) => return Ok(failure(reason)),
    };
    let parsed = match (parsed, syntax) {
        (PyVal::Null, Syntax::Yaml) => PyVal::Dict(Vec::new()),
        (other, _) => other,
    };
    match parsed {
        PyVal::Dict(entries) => Ok(ConfigInspection {
            file,
            payload: Some(entries),
            reason: None,
        }),
        _ => Ok(ConfigInspection {
            file,
            payload: None,
            reason: Some("config_not_mapping"),
        }),
    }
}

/// Safely parse bounded in-memory YAML used for skill frontmatter.
pub(crate) fn parse_yaml_mapping(
    content: &str,
) -> Result<Option<Vec<(String, PyVal)>>, &'static str> {
    if content.len() > PREVIEW_BYTES {
        return Ok(None);
    }
    Ok(match load(content)? {
        Ok(PyVal::Dict(entries)) => Some(entries),
        _ => None,
    })
}
