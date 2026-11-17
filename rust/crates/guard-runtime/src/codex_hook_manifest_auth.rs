//! Authenticate a Codex hook manifest under this Guard home's hook key:
//! `codex_hook_integrity.load_authenticated_hook_manifest_path` and
//! `authenticate_hook_manifest_text`. The answer is the unsigned manifest or a
//! stable reason code.

use std::fs;
use std::io::Read;
use std::path::Path;

use serde_json::{Map, Value};

use crate::codex_hook_bridge_trust_files as files;
use crate::codex_hook_key::read_matching;
use crate::local_authority_integrity_op::verify;

const MAC_ALGORITHM: &str = "hmac-sha256";
const PURPOSE: &str = "codex-managed-hook-manifest";
pub(crate) const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

type Checked<T> = Result<T, &'static str>;

/// The private regular manifest at `path`, authenticated.
pub(crate) fn load_path(guard_home: &str, path: &Path) -> Checked<Map<String, Value>> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Err("codex_hook_manifest_missing");
    };
    if !metadata.file_type().is_file() {
        return Err("codex_hook_manifest_not_regular");
    }
    files::private_to_owner(&metadata).map_err(|kind| match kind {
        files::Private::Owner => "codex_hook_manifest_owner_mismatch",
        files::Private::Mode => "codex_hook_manifest_permissions_unsafe",
    })?;
    let mut raw = String::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_MANIFEST_BYTES + 1).read_to_string(&mut raw))
        .map_err(|_| "codex_hook_manifest_invalid")?;
    authenticate_text(guard_home, &raw, None, None)
}

/// Bounded captured manifest text, authenticated under the home's key; with
/// `key_id`/`installation_id`, only under that exact key.
pub(crate) fn authenticate_text(
    guard_home: &str,
    raw: &str,
    key_id: Option<&str>,
    installation_id: Option<&str>,
) -> Checked<Map<String, Value>> {
    if raw.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("codex_hook_manifest_invalid");
    }
    let Ok(Value::Object(mut manifest)) = serde_json::from_str::<Value>(raw) else {
        return Err("codex_hook_manifest_invalid");
    };
    let Some(Value::Object(authentication)) = manifest.remove("authentication") else {
        return Err("codex_hook_manifest_authentication_missing");
    };
    if authentication.get("algorithm").and_then(Value::as_str) != Some(MAC_ALGORITHM) {
        return Err("codex_hook_manifest_authentication_invalid");
    }
    let key = read_matching(guard_home, key_id, installation_id)?;
    let unsigned = Value::Object(manifest);
    let answer = verify(
        &unsigned,
        &authentication,
        Some(key.key.as_slice()),
        Some(&key.key_id),
        PURPOSE,
    );
    match answer.get("status").and_then(Value::as_str) {
        Some("valid") => {}
        Some("missing_integrity") => return Err("codex_hook_manifest_authentication_invalid"),
        Some("unknown_key") => return Err("codex_hook_manifest_key_mismatch"),
        _ => return Err("codex_hook_manifest_mac_invalid"),
    }
    let Value::Object(mut manifest) = unsigned else {
        return Err("codex_hook_manifest_invalid");
    };
    if manifest.get("installation_id").and_then(Value::as_str) != Some(&key.installation_id) {
        return Err("codex_hook_manifest_installation_mismatch");
    }
    if authentication.get("signed_at") != manifest.get("generated_at") {
        return Err("codex_hook_manifest_authentication_invalid");
    }
    manifest.insert("authentication".to_owned(), Value::Object(authentication));
    Ok(manifest)
}

/// The unsigned manifest, as the bridge compares it.
pub(crate) fn unsigned(mut manifest: Map<String, Value>) -> Map<String, Value> {
    manifest.remove("authentication");
    manifest
}

#[cfg(test)]
#[path = "codex_hook_manifest_auth_tests.rs"]
mod tests;
