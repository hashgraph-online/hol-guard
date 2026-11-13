//! The key that signs adapter lifecycle state, kept at
//! `<guard_home>/managed/adapter-state.key`.
//!
//! Port of `adapters/adapter_state_integrity.py`'s `_load_or_create_key` and
//! `_load_key`. On Unix the `managed` folder and the key file are opened
//! without following a link, the folder must be owner-only, and the key file
//! must be a private regular file; a key another user could read signs
//! nothing. Creation is exclusive, so two installs racing to create the key
//! end up sharing whichever one landed first.

use std::io::{Read, Write};
use std::path::Path;

use serde_json::{json, Value};

use crate::guard_store_json::dumps_default;

const KEY_FILENAME: &str = "adapter-state.key";
const MANAGED_DIRECTORY: &str = "managed";
const KEY_BYTES: usize = 32;
const KEY_ID_BYTES: usize = 12;
const MAX_KEY_FILE_BYTES: usize = 16_384;
const SCHEMA_VERSION: i64 = 1;

pub(crate) struct AdapterStateKey {
    pub(crate) id: String,
    pub(crate) bytes: Vec<u8>,
}

/// The existing key, or an error when it is missing or unusable.
pub(crate) fn load(guard_home: &Path) -> Result<AdapterStateKey, &'static str> {
    platform::load(guard_home)
}

/// The existing key, creating one when there is none yet.
pub(crate) fn load_or_create(guard_home: &Path) -> Result<AdapterStateKey, &'static str> {
    platform::load_or_create(guard_home)
}

/// A fresh key and the file text that stores it.
fn new_key() -> Result<(AdapterStateKey, String), &'static str> {
    use base64ct::{Base64Url, Encoding};
    let mut bytes = vec![0_u8; KEY_BYTES];
    let mut id = [0_u8; KEY_ID_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| "adapter_state_key_random_failed")?;
    getrandom::fill(&mut id).map_err(|_| "adapter_state_key_random_failed")?;
    let id = hex::encode(id);
    let document = json!({
        "key": Base64Url::encode_string(&bytes),
        "key_id": id,
        "schema_version": SCHEMA_VERSION,
    });
    let text = dumps_default(&document).ok_or("adapter_state_key_unencodable")? + "\n";
    Ok((AdapterStateKey { id, bytes }, text))
}

/// `_parse_key`: the schema version, a non-empty key id and exactly 32 bytes
/// of URL-safe base64 key material.
fn parse(raw: &[u8]) -> Result<AdapterStateKey, &'static str> {
    use base64ct::{Base64Url, Encoding};
    if raw.len() > MAX_KEY_FILE_BYTES {
        return Err("adapter_state_key_invalid_format");
    }
    let text = std::str::from_utf8(raw).map_err(|_| "adapter_state_key_invalid_format")?;
    let document: Value =
        serde_json::from_str(text).map_err(|_| "adapter_state_key_invalid_format")?;
    let Value::Object(document) = document else {
        return Err("adapter_state_key_invalid_format");
    };
    let version = document.get("schema_version");
    let version_matches = version.and_then(Value::as_i64) == Some(SCHEMA_VERSION)
        || version.and_then(Value::as_f64) == Some(SCHEMA_VERSION as f64);
    let id = document.get("key_id").and_then(Value::as_str).unwrap_or("");
    if !version_matches || id.is_empty() {
        return Err("adapter_state_key_invalid_metadata");
    }
    let encoded = document
        .get("key")
        .and_then(Value::as_str)
        .ok_or("adapter_state_key_invalid_material")?;
    let bytes = Base64Url::decode_vec(encoded).map_err(|_| "adapter_state_key_invalid_material")?;
    if bytes.len() != KEY_BYTES {
        return Err("adapter_state_key_invalid_length");
    }
    Ok(AdapterStateKey {
        id: id.to_owned(),
        bytes,
    })
}

fn read_limited(file: impl Read) -> Result<Vec<u8>, &'static str> {
    let mut raw = Vec::new();
    file.take(MAX_KEY_FILE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "adapter_state_key_unreadable")?;
    Ok(raw)
}

fn write_durably(file: &mut std::fs::File, text: &str) -> std::io::Result<()> {
    file.write_all(text.as_bytes())?;
    file.flush()?;
    file.sync_all()
}

#[cfg(unix)]
mod platform {
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::path::Path;

    use nix::errno::Errno;
    use nix::fcntl::{open, openat, OFlag};
    use nix::sys::stat::{fchmod, fstat, mkdirat, FileStat, Mode, SFlag};
    use nix::unistd::{unlinkat, UnlinkatFlags};

    use super::{
        new_key, parse, read_limited, write_durably, AdapterStateKey, KEY_FILENAME,
        MANAGED_DIRECTORY,
    };

    const DIRECTORY_FLAGS: OFlag = OFlag::O_RDONLY
        .union(OFlag::O_DIRECTORY)
        .union(OFlag::O_NOFOLLOW)
        .union(OFlag::O_CLOEXEC);

    pub(super) fn load(guard_home: &Path) -> Result<AdapterStateKey, &'static str> {
        let directory = key_directory(guard_home, false)?;
        read_key(&directory)
    }

    pub(super) fn load_or_create(guard_home: &Path) -> Result<AdapterStateKey, &'static str> {
        let directory = key_directory(guard_home, true)?;
        let (key, text) = new_key()?;
        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let descriptor = match openat(
            &directory,
            KEY_FILENAME,
            flags,
            Mode::S_IRUSR | Mode::S_IWUSR,
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::EEXIST) => return read_key(&directory),
            Err(_) => return Err("adapter_state_key_unwritable"),
        };
        let mut file = File::from(descriptor);
        if write_durably(&mut file, &text).is_err() {
            let _ = unlinkat(&directory, KEY_FILENAME, UnlinkatFlags::NoRemoveDir);
            return Err("adapter_state_key_unwritable");
        }
        Ok(key)
    }

    /// `_private_key_directory_descriptor`: `managed` reached without
    /// following a link, made owner-only when creating and required to be
    /// owner-only when only reading.
    fn key_directory(guard_home: &Path, create: bool) -> Result<OwnedFd, &'static str> {
        if create {
            std::fs::create_dir_all(guard_home).map_err(|_| "adapter_state_key_unwritable")?;
        }
        let home = open(
            guard_home,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "adapter_state_key_unavailable")?;
        if create {
            match mkdirat(&home, MANAGED_DIRECTORY, Mode::S_IRWXU) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(_) => return Err("adapter_state_key_unwritable"),
            }
        }
        let directory = openat(&home, MANAGED_DIRECTORY, DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| "adapter_state_key_unavailable")?;
        let metadata = fstat(&directory).map_err(|_| "adapter_state_key_unavailable")?;
        if file_type(&metadata) != SFlag::S_IFDIR {
            return Err("adapter_state_key_parent_not_directory");
        }
        if create {
            fchmod(&directory, Mode::S_IRWXU).map_err(|_| "adapter_state_key_unwritable")?;
        } else if metadata.st_mode & 0o077 != 0 {
            return Err("adapter_state_key_parent_not_private");
        }
        Ok(directory)
    }

    /// `_load_key_from_descriptor`.
    fn read_key(directory: &OwnedFd) -> Result<AdapterStateKey, &'static str> {
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
        let file = File::from(
            openat(directory, KEY_FILENAME, flags, Mode::empty())
                .map_err(|_| "adapter_state_key_unavailable")?,
        );
        let metadata = fstat(&file).map_err(|_| "adapter_state_key_unavailable")?;
        if file_type(&metadata) != SFlag::S_IFREG {
            return Err("adapter_state_key_not_regular");
        }
        if metadata.st_mode & 0o077 != 0 {
            return Err("adapter_state_key_not_private");
        }
        parse(&read_limited(file)?)
    }

    fn file_type(metadata: &FileStat) -> SFlag {
        SFlag::from_bits_truncate(metadata.st_mode & SFlag::S_IFMT.bits())
    }
}

#[cfg(not(unix))]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};

    use super::{
        new_key, parse, read_limited, write_durably, AdapterStateKey, KEY_FILENAME,
        MANAGED_DIRECTORY,
    };

    /// `_ensure_path_within_root`: `managed` must be a real folder inside the
    /// Guard home, never a link that carries the key somewhere else.
    fn key_path(guard_home: &Path) -> Result<PathBuf, &'static str> {
        let directory = guard_home.join(MANAGED_DIRECTORY);
        let metadata =
            std::fs::symlink_metadata(&directory).map_err(|_| "adapter_state_key_unavailable")?;
        if !metadata.file_type().is_dir() {
            return Err("adapter_state_key_parent_not_directory");
        }
        Ok(directory.join(KEY_FILENAME))
    }

    pub(super) fn load(guard_home: &Path) -> Result<AdapterStateKey, &'static str> {
        let path = key_path(guard_home)?;
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| "adapter_state_key_unavailable")?;
        if !metadata.file_type().is_file() {
            return Err("adapter_state_key_not_regular");
        }
        let file = File::open(&path).map_err(|_| "adapter_state_key_unavailable")?;
        parse(&read_limited(file)?)
    }

    pub(super) fn load_or_create(guard_home: &Path) -> Result<AdapterStateKey, &'static str> {
        std::fs::create_dir_all(guard_home.join(MANAGED_DIRECTORY))
            .map_err(|_| "adapter_state_key_unwritable")?;
        let path = key_path(guard_home)?;
        if std::fs::symlink_metadata(&path).is_ok() {
            return load(guard_home);
        }
        let (key, text) = new_key()?;
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => return load(guard_home),
            Err(_) => return Err("adapter_state_key_unwritable"),
        };
        if write_durably(&mut file, &text).is_err() {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err("adapter_state_key_unwritable");
        }
        Ok(key)
    }
}

#[cfg(test)]
#[path = "adapter_state_key_tests.rs"]
mod tests;
