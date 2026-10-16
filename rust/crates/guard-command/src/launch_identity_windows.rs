//! Windows executable identity for runtime launches.
//!
//! A launch command resolves the way `shutil.which` does on Windows: an
//! explicit path against the launch cwd, a bare name through each `PATH`
//! entry and `PATHEXT` extension, and never through the working directory
//! itself. The canonical file is bound by content digest and file ID. Its
//! bytes are read through a handle that excludes writers, and the launch path
//! must still name the hashed file afterwards, so a swap fails closed.

use std::io::Read;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::launch_identity_common::strip_generated_extended_prefix;
use crate::mcp_decision::launcher_file_names;

// Same caps as the unix identity (`launch_identity.rs`).
const MAX_EXECUTABLE_HASH_BYTES: u64 = 256 * 1024 * 1024;
const EXECUTABLE_HASH_CHUNK_BYTES: usize = 1024 * 1024;

/// Why an executable could not be verified, and the path reached, if any.
pub(crate) type Unverified = (&'static str, Option<PathBuf>);

/// `PATH` from a launch environment. Windows variable names are
/// case-insensitive, so `Path` counts.
pub(crate) fn environment_path(launch_env: Option<&Value>) -> Option<String> {
    launch_env
        .and_then(Value::as_object)?
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

/// Verified identity of the executable `command` launches from `launch_cwd`.
pub(crate) fn executable_identity(
    command: &str,
    search_path: Option<&str>,
    launch_cwd: &Path,
) -> Result<Value, Unverified> {
    if command.trim().is_empty() {
        return Err(("invalid_command", None));
    }
    // `~` would need a trusted home; unix expands it from an explicit home
    // only, which no Windows launch caller supplies.
    if command.starts_with('~') {
        return Err(("unresolved_home", None));
    }
    let Some(found) = resolve(command, search_path, launch_cwd) else {
        return Err(("unresolved", None));
    };
    let launch_path = std::path::absolute(&found).map_err(|_| ("unreadable", Some(found)))?;
    let unreadable = || ("unreadable", Some(launch_path.clone()));
    let canonical = launch_path.canonicalize().map_err(|_| unreadable())?;
    // Non-UTF-8 paths cannot round-trip through the JSON identity.
    let launch_text = plain_path(&launch_path).ok_or_else(unreadable)?;
    let path = plain_path(&canonical).ok_or_else(unreadable)?;
    let failed = |status: &'static str| (status, Some(PathBuf::from(&path)));
    let name = Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    // PATHEXT decides what Windows will run; a name already carrying one of
    // its extensions is the only candidate `launcher_file_names` returns.
    if launcher_file_names(name) != [name] {
        return Err(failed("not_executable"));
    }
    // PATHEXT can also name script hosts (`.js`, `.vbs`, `.wsf`) that
    // `CreateProcessW` cannot start; only native images and batch files
    // launch directly.
    let lowered = name.to_ascii_lowercase();
    if ![".exe", ".com", ".bat", ".cmd"]
        .iter()
        .any(|extension| lowered.ends_with(extension))
    {
        return Err(failed("not_executable"));
    }
    let file = guard_runtime_windows_process::open_bound_executable_file(&canonical)
        .map_err(|_| failed("open_failed"))?;
    let file_id =
        guard_runtime_windows_process::handle_file_id(&file).map_err(|_| failed("read_failed"))?;
    let metadata = file.metadata().map_err(|_| failed("read_failed"))?;
    if !metadata.is_file() {
        return Err(failed("not_regular"));
    }
    let digest = content_digest(&file, metadata.file_size()).map_err(failed)?;
    // The handle excluded writers while hashing; the launch path must still
    // reach the same file, or a rename swapped it underneath.
    match guard_runtime_windows_process::regular_file_id(&launch_path, true) {
        Ok((current, _)) if current == file_id => {}
        _ => return Err(("path_changed", Some(launch_path))),
    }
    let native = lowered.ends_with(".exe") || lowered.ends_with(".com");
    let mut identity = Map::new();
    identity.insert("command".into(), json!(command));
    identity.insert("launch_path".into(), json!(launch_text));
    identity.insert(
        "file_format".into(),
        json!(if native { "native" } else { "script" }),
    );
    identity.insert("path".into(), json!(path));
    identity.insert("file_id".into(), json!(file_id.to_hex()));
    identity.insert("size".into(), json!(metadata.file_size()));
    identity.insert("creation_time".into(), json!(metadata.creation_time()));
    identity.insert("modified_time".into(), json!(metadata.last_write_time()));
    identity.insert("attributes".into(), json!(metadata.file_attributes()));
    identity.insert("status".into(), json!("verified"));
    identity.insert("sha256".into(), json!(digest));
    Ok(Value::Object(identity))
}

fn resolve(command: &str, search_path: Option<&str>, launch_cwd: &Path) -> Option<PathBuf> {
    let candidate = Path::new(command);
    let has_prefix = matches!(candidate.components().next(), Some(Component::Prefix(_)));
    if command.contains(['/', '\\']) || has_prefix {
        // `C:tool` names a per-drive cwd the launch cwd cannot pin.
        if has_prefix && !candidate.is_absolute() {
            return None;
        }
        return first_file(&launch_cwd.join(candidate));
    }
    let search_path = search_path
        .map(str::to_owned)
        .or_else(|| std::env::var("PATH").ok())?;
    std::env::split_paths(&search_path)
        .filter(|entry| !entry.as_os_str().is_empty())
        .find_map(|entry| first_file(&launch_cwd.join(entry).join(command)))
}

/// `base` itself when it carries a `PATHEXT` extension, else `base` plus the
/// first extension that names a file.
fn first_file(base: &Path) -> Option<PathBuf> {
    let text = base.to_str()?;
    launcher_file_names(text)
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

/// The path without the `\\?\` prefix `canonicalize` adds, as Python's
/// `realpath` reports it and as `cmd.exe` launchers accept it.
fn plain_path(path: &Path) -> Option<String> {
    Some(strip_generated_extended_prefix(
        "",
        path.to_str()?.to_owned(),
    ))
}

fn content_digest(mut file: &std::fs::File, size: u64) -> Result<String, &'static str> {
    if size > MAX_EXECUTABLE_HASH_BYTES {
        return Err("too_large");
    }
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; EXECUTABLE_HASH_CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        let read = file.read(&mut chunk).map_err(|_| "read_failed")?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > size {
            return Err("size_changed");
        }
        hasher.update(&chunk[..read]);
    }
    if total != size {
        return Err("size_changed");
    }
    Ok(hex::encode(hasher.finalize()))
}
