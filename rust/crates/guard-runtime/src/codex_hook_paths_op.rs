//! `codex-hook-paths --stdin`: where a Guard home keeps the Codex hook
//! identity files, the retired Python `hook_manifest_path`,
//! `hook_authority_receipt_path` and `hook_secret_path`.
//!
//! A config target owns `managed/codex/hooks-<h>.manifest.json` and its
//! `hooks-<h>.authority-receipt.json` sibling, where `<h>` is the first 24
//! hex digits of the SHA-256 of the target's canonical spelling. The hook key
//! is the one `managed/codex/hook-manifest.key`. The caller sends the Guard
//! home as it spells it (the answer joins it unchanged) and an absolute
//! `config_path` when it wants the per-target files; the key path answers
//! either way. The answer is `{manifest_path, receipt_path, key_path,
//! record_path}`, the first two `null` without a config.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::codex_hook_bridge_trust_files::canonical;

const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const KEY_FILE: &str = "hook-manifest.key";
const RECORD_FILE: &str = "pending-hook-publication.json";

pub(crate) fn is_command(command: &str) -> bool {
    command == "codex-hook-paths"
}

#[derive(Deserialize)]
struct Request {
    guard_home: String,
    #[serde(default)]
    config_path: Option<String>,
}

fn directory(home: &Path) -> PathBuf {
    home.join("managed").join("codex")
}

fn target_hash(target: &Path) -> String {
    let digest = hex::encode(Sha256::digest(
        canonical(target).as_os_str().as_encoded_bytes(),
    ));
    digest[..24].to_owned()
}

/// `hook_manifest_path`: the manifest a config target owns in a Guard home.
pub(crate) fn manifest_path(home: &Path, target: &Path) -> PathBuf {
    directory(home).join(format!("hooks-{}.manifest.json", target_hash(target)))
}

/// `hook_authority_receipt_path`: the receipt retained beside that manifest.
pub(crate) fn receipt_path(home: &Path, target: &Path) -> PathBuf {
    directory(home).join(format!(
        "hooks-{}.authority-receipt.json",
        target_hash(target)
    ))
}

/// `hook_secret_path`: the Guard home's one hook authentication key.
pub(crate) fn key_path(home: &Path) -> PathBuf {
    directory(home).join(KEY_FILE)
}

/// `_record_path`: the one pending-publication journal a Guard home keeps,
/// shared by installations of every target.
pub(crate) fn record_path(home: &Path) -> PathBuf {
    directory(home).join(RECORD_FILE)
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn plain(value: &str) -> Option<&str> {
    (!value.is_empty() && !value.contains('\0')).then_some(value)
}

fn answer(request: &Request) -> Result<Value, String> {
    let invalid = || "codex_hook_paths_request_invalid".to_owned();
    let home = Path::new(plain(&request.guard_home).ok_or_else(invalid)?);
    let target = match request.config_path.as_deref() {
        None => None,
        Some(value) => {
            let target = Path::new(plain(value).ok_or_else(invalid)?);
            if !target.is_absolute() {
                return Err(invalid());
            }
            Some(target)
        }
    };
    Ok(json!({
        "manifest_path": target.map(|target| text(&manifest_path(home, target))),
        "receipt_path": target.map(|target| text(&receipt_path(home, target))),
        "key_path": text(&key_path(home)),
        "record_path": text(&record_path(home)),
    }))
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "codex_hook_paths_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("codex_hook_paths_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "codex_hook_paths_request_invalid".to_owned())?;
    serde_json::to_vec(&answer(&request)?)
        .map_err(|_| "codex_hook_paths_response_encode_failed".to_owned())
}

#[cfg(test)]
#[path = "codex_hook_paths_op_tests.rs"]
mod tests;
