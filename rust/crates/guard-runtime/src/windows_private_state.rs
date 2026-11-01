//! `windows-private-state --stdin`: owner-private Guard state files on
//! Windows, read, replaced and deleted through held directory handles
//! (`guard/native_policy_snapshot_windows_atomic.py` and
//! `native_policy_snapshot_storage_windows.py` before they moved here).
//!
//! - `read` answers one regular file of at most `maximum_bytes` whose owner
//!   is the current user and whose DACL is owner-only, or `null` when it is
//!   missing. Without `private_root` the directory ancestry is only held,
//!   never created or repaired; with one, the directories from that root
//!   down are created or have their ACLs repaired first, as a writer's are.
//! - `write` creates the private directories below `private_root`, writes a
//!   private temporary beside the file and replaces the file with it, so a
//!   reader sees the old content or the new, never a partial one.
//! - `delete` removes one owner-private file through its verified handle.
//! - `ensure` creates `directory` and any missing ancestors, and creates or
//!   repairs the private ACL on each directory from `private_root` down. A
//!   missing ancestor above `private_root` is created private too.
//!
//! An operational failure answers `{"error": "<code>"}`; a malformed request
//! is an error exit. Off Windows every operation answers
//! `native_windows_private_state_unsupported`.

use std::io::Read;

use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "windows-private-state.v1";
/// Above the business-source record bound (one 1 MiB document plus its envelope).
const MAX_CONTENT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_REQUEST_BYTES: u64 = 2 * MAX_CONTENT_BYTES;
const MAX_NAME_CHARS: usize = 200;
const MAX_PATH_CHARS: usize = 32_767;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    directory: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    private_root: Option<String>,
    #[serde(default)]
    maximum_bytes: Option<u64>,
    #[serde(default)]
    content_b64: Option<String>,
}

/// The file operations the answers are built from.
trait PrivateStore {
    fn read(
        &self,
        directory: &str,
        name: &str,
        maximum_bytes: u64,
        private_root: Option<&str>,
    ) -> Result<Option<Vec<u8>>, String>;
    fn write(
        &self,
        directory: &str,
        name: &str,
        content: &[u8],
        private_root: &str,
    ) -> Result<(), String>;
    fn delete(&self, directory: &str, name: &str, private_root: &str) -> Result<bool, String>;
    fn ensure(&self, directory: &str, private_root: &str) -> Result<(), String>;
}

struct SystemStore;

#[cfg(not(windows))]
impl PrivateStore for SystemStore {
    fn read(&self, _: &str, _: &str, _: u64, _: Option<&str>) -> Result<Option<Vec<u8>>, String> {
        Err(unsupported())
    }

    fn write(&self, _: &str, _: &str, _: &[u8], _: &str) -> Result<(), String> {
        Err(unsupported())
    }

    fn delete(&self, _: &str, _: &str, _: &str) -> Result<bool, String> {
        Err(unsupported())
    }

    fn ensure(&self, _: &str, _: &str) -> Result<(), String> {
        Err(unsupported())
    }
}

#[cfg(not(windows))]
fn unsupported() -> String {
    "native_windows_private_state_unsupported".to_owned()
}

#[cfg(windows)]
impl PrivateStore for SystemStore {
    fn read(
        &self,
        directory: &str,
        name: &str,
        maximum_bytes: u64,
        private_root: Option<&str>,
    ) -> Result<Option<Vec<u8>>, String> {
        system::read(directory, name, maximum_bytes, private_root)
    }

    fn write(
        &self,
        directory: &str,
        name: &str,
        content: &[u8],
        private_root: &str,
    ) -> Result<(), String> {
        system::write(directory, name, content, private_root)
    }

    fn delete(&self, directory: &str, name: &str, private_root: &str) -> Result<bool, String> {
        system::delete(directory, name, private_root)
    }

    fn ensure(&self, directory: &str, private_root: &str) -> Result<(), String> {
        system::ensure(directory, private_root)
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "windows-private-state"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "windows_private_state_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("windows_private_state_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let answer = answer(&request, &SystemStore)?;
    serde_json::to_vec(&answer)
        .map_err(|_| "windows_private_state_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "windows_private_state_request_invalid".to_owned()
}

fn answer<S: PrivateStore>(request: &Request, store: &S) -> Result<Value, String> {
    if request.schema != SCHEMA
        || !is_absolute(&request.directory)
        || request
            .private_root
            .as_deref()
            .is_some_and(|root| !is_absolute(root) || !is_within(&request.directory, root))
    {
        return Err(invalid());
    }
    let directory = request.directory.as_str();
    let private_root = request.private_root.as_deref().unwrap_or(directory);
    if request.op == "ensure" {
        if request.name.is_some()
            || request.maximum_bytes.is_some()
            || request.content_b64.is_some()
        {
            return Err(invalid());
        }
        let outcome = store
            .ensure(directory, private_root)
            .map(|()| json!({ "ensured": true }));
        return Ok(outcome.unwrap_or_else(|code| json!({ "error": code })));
    }
    let name = match request.name.as_deref() {
        Some(name) if is_child_name(name) => name,
        _ => return Err(invalid()),
    };
    let maximum_bytes = || {
        request
            .maximum_bytes
            .filter(|limit| (1..=MAX_CONTENT_BYTES).contains(limit))
            .ok_or_else(invalid)
    };
    let outcome = match request.op.as_str() {
        "read" if request.content_b64.is_none() => {
            let limit = maximum_bytes()?;
            store
                .read(directory, name, limit, request.private_root.as_deref())
                .and_then(|content| match content {
                    Some(bytes) if bytes.is_empty() || bytes.len() as u64 > limit => {
                        Err("native_windows_private_state_invalid".to_owned())
                    }
                    Some(bytes) => Ok(json!({
                        "content_b64": base64::engine::general_purpose::STANDARD.encode(bytes),
                    })),
                    None => Ok(json!({ "content_b64": null })),
                })
        }
        "write" => {
            let limit = maximum_bytes()?;
            let content = base64::engine::general_purpose::STANDARD
                .decode(request.content_b64.as_deref().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            if content.is_empty() || content.len() as u64 > limit {
                return Err(invalid());
            }
            store
                .write(directory, name, &content, private_root)
                .map(|()| json!({ "written": true }))
        }
        "delete" if request.content_b64.is_none() && request.maximum_bytes.is_none() => store
            .delete(directory, name, private_root)
            .map(|deleted| json!({ "deleted": deleted })),
        _ => return Err(invalid()),
    };
    Ok(outcome.unwrap_or_else(|code| json!({ "error": code })))
}

fn is_separator(character: char) -> bool {
    character == '\\' || character == '/'
}

/// A drive and a root, or a UNC root, and no `.`/`..` component a join
/// could climb through.
fn is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_root = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && is_separator(char::from(bytes[2]));
    let unc = path.starts_with(r"\\") || path.starts_with("//");
    (drive_root || unc)
        && path.chars().count() <= MAX_PATH_CHARS
        && !path.contains('\0')
        && path
            .split(is_separator)
            .all(|component| component != "." && component != "..")
}

/// One file name inside its directory: no separator, drive, stream or NUL.
fn is_child_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.chars().count() <= MAX_NAME_CHARS
        && !name.contains(|character: char| {
            is_separator(character) || character == ':' || character == '\0'
        })
}

/// `ntpath.normcase` without trailing separators.
fn fold(path: &str) -> String {
    path.trim_end_matches(is_separator)
        .replace('/', r"\")
        .to_lowercase()
}

fn is_within(path: &str, root: &str) -> bool {
    let (path, root) = (fold(path), fold(root));
    path == root || path.starts_with(&format!(r"{root}\"))
}

#[cfg(windows)]
mod system {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::path::Path;

    use crate::resident_state::{
        ensure_private_directory_under, open_private_read, private_file,
        remove_windows_private_file, replace_windows_private_file, verify_windows_private_file,
    };

    fn invalid() -> String {
        "native_windows_private_state_invalid".to_owned()
    }

    fn read_failed() -> String {
        "native_windows_private_state_read_failed".to_owned()
    }

    fn write_failed() -> String {
        "native_windows_private_state_write_failed".to_owned()
    }

    pub(super) fn read(
        directory: &str,
        name: &str,
        maximum_bytes: u64,
        private_root: Option<&str>,
    ) -> Result<Option<Vec<u8>>, String> {
        let directory = Path::new(directory);
        let file = match private_root {
            Some(root) => {
                let root = Path::new(root);
                ensure_private_directory_under(directory, root, true)?;
                open_private_read(&directory.join(name), maximum_bytes, "private_state", root)?
            }
            None => open_held(directory, name)?,
        };
        let Some(file) = file else {
            return Ok(None);
        };
        let length = file.metadata().map_err(|_| invalid())?.len();
        if length == 0 || length > maximum_bytes {
            return Err(invalid());
        }
        let mut content = Vec::with_capacity(length as usize);
        (&file)
            .take(maximum_bytes + 1)
            .read_to_end(&mut content)
            .map_err(|_| read_failed())?;
        if content.len() as u64 != length {
            return Err(invalid());
        }
        Ok(Some(content))
    }

    /// Open `name` while the directory ancestry is held open without creating
    /// or repairing anything.
    fn open_held(directory: &Path, name: &str) -> Result<Option<File>, String> {
        let binding = match guard_runtime_windows_process::bind_readonly_directory(directory) {
            Ok(binding) => binding,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(read_failed()),
        };
        let file = match binding.open_private_file(OsStr::new(name)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(invalid()),
        };
        if !file.metadata().map_err(|_| invalid())?.is_file() {
            return Err(invalid());
        }
        verify_windows_private_file(&file)?;
        Ok(Some(file))
    }

    pub(super) fn write(
        directory: &str,
        name: &str,
        content: &[u8],
        private_root: &str,
    ) -> Result<(), String> {
        let root = Path::new(private_root);
        let directory = Path::new(directory);
        ensure_private_directory_under(directory, root, true)?;
        let mut suffix = [0u8; 16];
        getrandom::fill(&mut suffix)
            .map_err(|_| "native_windows_private_state_random_failed".to_owned())?;
        let temporary = directory.join(format!(".{name}.{}.tmp", hex::encode(suffix)));
        let mut file = private_file(&temporary, true, root)?;
        let written = file
            .write_all(content)
            .and_then(|()| file.sync_all())
            .map_err(|_| write_failed());
        drop(file);
        let committed = written
            .and_then(|()| replace_windows_private_file(&temporary, &directory.join(name), root));
        if committed.is_err() {
            let _ = remove_windows_private_file(&temporary, root);
        }
        committed
    }

    pub(super) fn delete(directory: &str, name: &str, private_root: &str) -> Result<bool, String> {
        let directory = Path::new(directory);
        if std::fs::symlink_metadata(directory)
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        {
            return Ok(false);
        }
        remove_windows_private_file(&directory.join(name), Path::new(private_root))
    }

    /// Bind the directory privately from `private_root` down, after moving
    /// that root up over any ancestors that do not exist yet so they are
    /// created private rather than refused as missing ancestry.
    pub(super) fn ensure(directory: &str, private_root: &str) -> Result<(), String> {
        let directory = Path::new(directory);
        let mut root = Path::new(private_root);
        while let Some(parent) = root.parent() {
            match std::fs::symlink_metadata(parent) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => root = parent,
                _ => break,
            }
        }
        ensure_private_directory_under(directory, root, true).map(|_| ())
    }
}

#[cfg(test)]
#[path = "windows_private_state_tests.rs"]
mod tests;
