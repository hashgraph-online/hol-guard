//! The Codex hook authentication key, `managed/codex/hook-manifest.key`.
//!
//! The runtime creates, reads and removes this key; no other process sees
//! its bytes. Callers get the public identity (installation id, key id and
//! a one-way fingerprint) and name the Guard home when they ask the runtime
//! to sign or open a record with it.
//!
//! The key lives in an owner-only directory as an owner-only regular file
//! holding one canonical JSON object:
//! `{"installation_id", "key" (URL-safe base64 of 32 bytes), "key_id",
//! "schema_version": 1}`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use base64::alphabet::URL_SAFE;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::{DecodePaddingMode, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
const FINGERPRINT_DOMAIN: &[u8] = b"hol-guard codex hook key fingerprint v1\0";
const URL_SAFE_ANY_PADDING: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub(crate) struct HookKey {
    pub(crate) key: Zeroizing<Vec<u8>>,
    pub(crate) key_id: String,
    pub(crate) installation_id: String,
}

impl HookKey {
    fn identity(&self) -> Value {
        let mut digest = Sha256::new();
        digest.update(FINGERPRINT_DOMAIN);
        digest.update(self.key.as_slice());
        json!({
            "installation_id": self.installation_id,
            "key_id": self.key_id,
            "fingerprint": hex::encode(digest.finalize()),
        })
    }
}

pub(crate) fn key_path(guard_home: &Path) -> PathBuf {
    guard_home
        .join("managed")
        .join("codex")
        .join("hook-manifest.key")
}

/// The key a caller named by its Guard home, refused unless its ids match
/// the ones the caller already holds.
pub(crate) fn read_matching(
    guard_home: &str,
    key_id: Option<&str>,
    installation_id: Option<&str>,
) -> Result<HookKey, &'static str> {
    let home = Path::new(guard_home);
    if !home.is_absolute() {
        return Err("codex_hook_manifest_secret_invalid");
    }
    let key = read(home)?;
    if key_id.is_some_and(|id| id != key.key_id)
        || installation_id.is_some_and(|id| id != key.installation_id)
    {
        return Err("codex_hook_manifest_key_mismatch");
    }
    Ok(key)
}

/// `key_identity`, `key_ensure` and `key_remove_if_unused` for one home.
pub(crate) fn answer(op: &str, guard_home: &str) -> Option<Value> {
    let home = Path::new(guard_home);
    if !home.is_absolute() {
        return Some(json!({"error": "codex_hook_manifest_secret_invalid"}));
    }
    let result = match op {
        "key_identity" => read(home).map(|key| key.identity()),
        "key_ensure" => ensure(home).map(|key| key.identity()),
        "key_remove_if_unused" => remove_if_unused(home).map(|removed| json!({"removed": removed})),
        _ => return None,
    };
    Some(result.unwrap_or_else(|reason| json!({"error": reason})))
}

fn read(home: &Path) -> Result<HookKey, &'static str> {
    let path = key_path(home);
    if fs::symlink_metadata(&path).is_err() {
        return Err("codex_hook_manifest_secret_missing");
    }
    check_directory(&path, false)?;
    check_file(&path)?;
    let text = read_capped(&path).map_err(|_| "codex_hook_manifest_secret_invalid")?;
    parse(&text)
}

fn ensure(home: &Path) -> Result<HookKey, &'static str> {
    let path = key_path(home);
    let directory = path
        .parent()
        .ok_or("codex_hook_manifest_directory_unsafe")?;
    fs::create_dir_all(directory).map_err(|_| "codex_hook_manifest_directory_unsafe")?;
    check_directory(&path, true)?;
    if fs::symlink_metadata(&path).is_ok() {
        return read(home);
    }
    let mut key = Zeroizing::new(vec![0u8; KEY_BYTES]);
    let mut installation = [0u8; 16];
    let mut key_id = [0u8; 12];
    for buffer in [key.as_mut_slice(), &mut installation, &mut key_id] {
        getrandom::fill(buffer).map_err(|_| "codex_hook_manifest_secret_entropy_unavailable")?;
    }
    let created = HookKey {
        key,
        key_id: hex::encode(key_id),
        installation_id: hex::encode(installation),
    };
    let encoded = Zeroizing::new(format!(
        "{{\"installation_id\":\"{}\",\"key\":\"{}\",\"key_id\":\"{}\",\"schema_version\":1}}\n",
        created.installation_id,
        Zeroizing::new(URL_SAFE_ANY_PADDING.encode(created.key.as_slice())).as_str(),
        created.key_id,
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_create(&mut options);
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return read(home),
        Err(_) => return Err("codex_hook_manifest_secret_unwritable"),
    };
    let written = file
        .write_all(encoded.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| sync_directory(directory));
    if written.is_err() {
        let _ = fs::remove_file(&path);
        return Err("codex_hook_manifest_secret_unwritable");
    }
    Ok(created)
}

/// Remove the key once no hook manifest is left beside it.
fn remove_if_unused(home: &Path) -> Result<bool, &'static str> {
    let path = key_path(home);
    let Some(directory) = path.parent() else {
        return Ok(false);
    };
    if !fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.is_dir()) {
        return Ok(false);
    }
    let entries = fs::read_dir(directory).map_err(|_| "codex_hook_manifest_directory_unsafe")?;
    for entry in entries {
        let name = entry
            .map_err(|_| "codex_hook_manifest_directory_unsafe")?
            .file_name();
        let name = name.to_string_lossy();
        if name.starts_with("hooks-") && name.ends_with(".manifest.json") {
            return Ok(false);
        }
    }
    if fs::symlink_metadata(&path).is_err() {
        return Ok(false);
    }
    check_file(&path)?;
    fs::remove_file(&path).map_err(|_| "codex_hook_manifest_secret_unwritable")?;
    sync_directory(directory).map_err(|_| "codex_hook_manifest_secret_unwritable")?;
    Ok(true)
}

fn parse(text: &str) -> Result<HookKey, &'static str> {
    let invalid = "codex_hook_manifest_secret_invalid";
    let value: Value = serde_json::from_str(text).map_err(|_| invalid)?;
    let object = value.as_object().ok_or(invalid)?;
    let version_ok = matches!(object.get("schema_version"), Some(Value::Number(n)) if n.as_f64() == Some(1.0))
        || object.get("schema_version") == Some(&Value::Bool(true));
    let installation_id = object.get("installation_id").and_then(Value::as_str);
    let key_id = object.get("key_id").and_then(Value::as_str);
    let encoded = object.get("key").and_then(Value::as_str);
    let (Some(installation_id), Some(key_id), Some(encoded)) = (installation_id, key_id, encoded)
    else {
        return Err(invalid);
    };
    if !version_ok || installation_id.chars().count() < 32 || key_id.chars().count() < 24 {
        return Err(invalid);
    }
    let key = Zeroizing::new(URL_SAFE_ANY_PADDING.decode(encoded).map_err(|_| invalid)?);
    if key.len() != KEY_BYTES {
        return Err(invalid);
    }
    Ok(HookKey {
        key,
        key_id: key_id.to_owned(),
        installation_id: installation_id.to_owned(),
    })
}

fn read_capped(path: &Path) -> io::Result<Zeroizing<String>> {
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let file: File = options.open(path)?;
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(text)
}

/// The managed directory: a real directory this user owns, owner-only.
/// `repair` narrows a wider mode instead of refusing it.
fn check_directory(path: &Path, repair: bool) -> Result<(), &'static str> {
    let directory = path
        .parent()
        .ok_or("codex_hook_manifest_directory_unsafe")?;
    let metadata =
        fs::symlink_metadata(directory).map_err(|_| "codex_hook_manifest_directory_unsafe")?;
    if !metadata.is_dir() {
        return Err("codex_hook_manifest_directory_unsafe");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err("codex_hook_manifest_directory_owner_mismatch");
        }
        if metadata.mode() & 0o077 != 0 {
            if !repair {
                return Err("codex_hook_manifest_directory_permissions_unsafe");
            }
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| "codex_hook_manifest_directory_permissions_unsafe")?;
        }
    }
    #[cfg(not(unix))]
    let _ = repair;
    Ok(())
}

/// The key file: a regular file (not a link) this user owns, owner-only.
fn check_file(path: &Path) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "codex_hook_manifest_secret_missing")?;
    if !metadata.file_type().is_file() {
        return Err("codex_hook_manifest_secret_not_regular");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err("codex_hook_manifest_secret_owner_mismatch");
        }
        if metadata.mode() & 0o077 != 0 {
            return Err("codex_hook_manifest_secret_permissions_unsafe");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn no_follow(options: &mut OpenOptions) {
    std::os::unix::fs::OpenOptionsExt::custom_flags(options, libc::O_NOFOLLOW | libc::O_CLOEXEC);
}

#[cfg(not(unix))]
fn no_follow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn private_create(options: &mut OpenOptions) {
    no_follow(options);
    std::os::unix::fs::OpenOptionsExt::mode(options, 0o600);
}

#[cfg(not(unix))]
fn private_create(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "codex_hook_key_tests.rs"]
mod tests;
