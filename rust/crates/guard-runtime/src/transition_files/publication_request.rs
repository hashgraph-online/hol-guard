//! The private review artifact of a captured Codex authority repair or
//! publication inverse, ported from `codex_hook_repair_request`.
//!
//! The artifact is created exclusively, private to its owner, inside a
//! private directory that must not be replaced while it is written, and is
//! read back byte for byte. It conveys review material only, never authority.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::inspect::sha256_hex;
use super::publication::Call;
use super::publication_io::{private_metadata, read_private};
use super::{Fault, Step};

const MAX_REQUEST: usize = 8 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
const PATH_INVALID: Fault = Fault::Transition("authority_repair_request_path_invalid");
const CHANGED: Fault = Fault::Transition("authority_repair_request_changed");

/// The artifact path: absolute, under a parent that already resolves to itself.
fn request_path(call: &Call<'_>) -> Step<PathBuf> {
    let path = PathBuf::from(call.text("path")?);
    let parent = path.parent().ok_or(PATH_INVALID)?;
    if !path.is_absolute()
        || path.file_name().is_none()
        || fs::canonicalize(parent).ok().as_deref() != Some(parent)
    {
        return Err(PATH_INVALID);
    }
    Ok(path)
}

/// `_stable_directory_metadata`: the same private directory, mode unchanged.
#[cfg(unix)]
fn same_directory(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    private_metadata(after, true)
        && (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode())
}

#[cfg(windows)]
fn same_directory(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    private_metadata(after, true)
        && before.file_attributes() == after.file_attributes()
        && before.creation_time() == after.creation_time()
}

/// Exclusively create `name` with mode 0600 inside the already opened parent.
#[cfg(unix)]
fn create(parent: &Path, before: &fs::Metadata, name: &std::ffi::OsStr) -> Step<fs::File> {
    use nix::fcntl::{open, openat, OFlag};
    use nix::sys::stat::Mode;
    let directory = open(
        parent,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let directory = fs::File::from(directory);
    if !same_directory(before, &directory.metadata()?) {
        return Err(PATH_INVALID);
    }
    let flags =
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let file = openat(&directory, name, flags, Mode::from_bits_truncate(0o600))
        .map_err(std::io::Error::from)?;
    Ok(fs::File::from(file))
}

#[cfg(windows)]
fn create(parent: &Path, _before: &fs::Metadata, name: &std::ffi::OsStr) -> Step<fs::File> {
    Ok(fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(parent.join(name))?)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// `publication_request_create`: write the sealed artifact exactly once and
/// answer the digest of the bytes read back.
pub(super) fn create_op(call: &mut Call<'_>) -> Step<Value> {
    call.budget.inverse()?;
    let path = request_path(call)?;
    let parent = path.parent().ok_or(PATH_INVALID)?;
    let encoded = STANDARD
        .decode(call.text("encoded")?)
        .map_err(|_| Fault::Transition("files_invalid"))?;
    if encoded.len() > MAX_REQUEST {
        return Err(Fault::Transition("authority_repair_request_too_large"));
    }
    let before = fs::symlink_metadata(parent)?;
    if !private_metadata(&before, true) {
        return Err(PATH_INVALID);
    }
    let name = path.file_name().ok_or(PATH_INVALID)?;
    let mut file = create(parent, &before, name)?;
    for chunk in encoded.chunks(CHUNK) {
        call.budget.inverse()?;
        file.write_all(chunk)?;
    }
    file.sync_all()?;
    drop(file);
    if !same_directory(&before, &fs::symlink_metadata(parent)?) {
        return Err(PATH_INVALID);
    }
    sync_directory(parent)?;
    if read_private(&path, MAX_REQUEST, true).as_deref() != Some(encoded.as_slice()) {
        return Err(CHANGED);
    }
    Ok(json!(sha256_hex(&encoded)))
}

/// `publication_request_read`: the artifact's bytes, only when they still
/// carry `expected_sha256`.
pub(super) fn read_op(call: &mut Call<'_>) -> Step<Value> {
    call.budget.inverse()?;
    let expected = call.text("expected_sha256")?;
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Fault::Transition("authority_repair_request_digest_invalid"));
    }
    let path = request_path(call)?;
    let raw = read_private(&path, MAX_REQUEST, true).ok_or(CHANGED)?;
    if sha256_hex(&raw) != expected {
        return Err(CHANGED);
    }
    Ok(json!(STANDARD.encode(raw)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transition_files::dispatch;
    use crate::transition_files::inspect::resolve_lenient;

    fn private_directory() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "publication-request-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        resolve_lenient(&root)
    }

    fn ask(request: Value) -> Result<Value, String> {
        let answer = dispatch(&request).map_err(|error| format!("{error:?}"))?;
        match answer.get("error") {
            Some(error) => Err(error.to_string()),
            None => Ok(answer["value"].clone()),
        }
    }

    #[test]
    fn an_artifact_is_created_once_and_read_back_by_digest() {
        let root = private_directory();
        let path = root.join("request.json");
        let encoded = STANDARD.encode(b"sealed");
        let create = json!({
            "op": "publication_request_create",
            "path": path.to_string_lossy(),
            "encoded": encoded,
        });
        let digest = ask(create.clone()).unwrap();
        assert_eq!(digest, json!(sha256_hex(b"sealed")));
        assert!(ask(create).is_err(), "a second create must not replace it");
        let read = |expected: &str| {
            ask(json!({
                "op": "publication_request_read",
                "path": path.to_string_lossy(),
                "expected_sha256": expected,
            }))
        };
        assert_eq!(read(digest.as_str().unwrap()).unwrap(), json!(encoded));
        let other = sha256_hex(b"other");
        assert!(read(&other)
            .unwrap_err()
            .contains("authority_repair_request_changed"));
        assert!(read("ABC")
            .unwrap_err()
            .contains("authority_repair_request_digest_invalid"));
        fs::remove_dir_all(root).unwrap();
    }
}
