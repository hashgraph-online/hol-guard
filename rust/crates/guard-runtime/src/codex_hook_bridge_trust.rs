//! Authenticate the Codex hook registration before anything it names runs.
//!
//! Codex runs `<runtime> codex-hook-bridge <config>`. The config names the
//! daemon-start and fallback commands this bridge may run, so a config that
//! was rewritten after install must not reach them. Install writes an
//! authenticated manifest beside the hook key; this module checks that the
//! registration still matches it:
//!
//! - the manifest is the private file this Guard home's config names, and
//!   its MAC verifies under this home's hook key;
//! - one authenticated generation registers exactly this argv;
//! - the config's start and fallback commands are the ones that generation
//!   recorded, and every file it recorded is still the same file.
//!
//! The answer is a stable reason code; the bridge then fails the hook closed
//! and writes that code to stderr. It renders no verdict about the call.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{decode_config_argument, BRIDGE_COMMAND, STATE_FILE};
use crate::codex_hook_key::read_matching;
use crate::local_authority_integrity_op::verify;

use crate::codex_hook_bridge_trust_files::{
    self as files, canonical, verify_executable, verify_regular,
};

const UNAUTHENTICATED: &str = "codex_hook_launch_unauthenticated";
const MANIFEST_SCHEMA_VERSION: i64 = 2;
const MAC_ALGORITHM: &str = "hmac-sha256";
const PURPOSE: &str = "codex-managed-hook-manifest";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_GENERATIONS: usize = 8;

type Checked<T> = Result<T, &'static str>;

/// `None` when the registration authenticated, else why it did not.
pub(super) fn registration_failure(config_argument: &str) -> Option<String> {
    check(config_argument).err()
}

fn check(config_argument: &str) -> Result<(), String> {
    let config = decode_config_argument(config_argument).ok_or(UNAUTHENTICATED)?;
    let config: Value = serde_json::from_str(&config).map_err(|_| UNAUTHENTICATED)?;
    let text = |name: &str| config.get(name).and_then(Value::as_str);
    let (Some(state), Some(manifest_path)) = (text("state_path"), text("manifest_path")) else {
        return Err(UNAUTHENTICATED.to_owned());
    };
    let (guard_home, manifest_path) = managed_paths(Path::new(state), Path::new(manifest_path))?;
    let manifest = authenticated_manifest(&guard_home, &manifest_path)?;
    verify_context(&manifest, &guard_home, &manifest_path)?;
    let expected = [
        manifest_bridge_path(&manifest)?,
        BRIDGE_COMMAND,
        config_argument,
    ];
    let selected = select_generation(&manifest, &expected)?;
    verify_context(selected, &guard_home, &manifest_path)?;
    let interpreter = selected.get("interpreter").ok_or(UNAUTHENTICATED)?;
    verify_executable(interpreter)?;
    verify_packaged_files(selected)?;
    verify_commands(selected, interpreter, &config)?;
    Ok(())
}

/// `_resolve_managed_hook_paths`: the Guard home and the manifest it owns.
fn managed_paths(state: &Path, manifest: &Path) -> Checked<(PathBuf, PathBuf)> {
    if !state.is_absolute() || !manifest.is_absolute() {
        return Err(UNAUTHENTICATED);
    }
    let home = canonical(state.parent().ok_or(UNAUTHENTICATED)?);
    let directory = canonical(manifest.parent().ok_or(UNAUTHENTICATED)?);
    let name = manifest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if state.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE)
        || directory != canonical(&home.join("managed").join("codex"))
        || !name.starts_with("hooks-")
        || !name.ends_with(".manifest.json")
    {
        return Err(UNAUTHENTICATED);
    }
    Ok((home, manifest.to_path_buf()))
}

/// `load_authenticated_hook_manifest_path`.
fn authenticated_manifest(guard_home: &Path, path: &Path) -> Checked<Map<String, Value>> {
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
    if raw.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("codex_hook_manifest_invalid");
    }
    let Ok(Value::Object(mut manifest)) = serde_json::from_str::<Value>(&raw) else {
        return Err("codex_hook_manifest_invalid");
    };
    let Some(Value::Object(authentication)) = manifest.remove("authentication") else {
        return Err("codex_hook_manifest_authentication_missing");
    };
    if authentication.get("algorithm").and_then(Value::as_str) != Some(MAC_ALGORITHM) {
        return Err("codex_hook_manifest_authentication_invalid");
    }
    let home = guard_home.to_str().ok_or(UNAUTHENTICATED)?;
    let key = read_matching(home, None, None)?;
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
    let Value::Object(manifest) = unsigned else {
        return Err(UNAUTHENTICATED);
    };
    if manifest.get("installation_id").and_then(Value::as_str) != Some(&key.installation_id) {
        return Err("codex_hook_manifest_installation_mismatch");
    }
    if authentication.get("signed_at") != manifest.get("generated_at") {
        return Err("codex_hook_manifest_authentication_invalid");
    }
    Ok(manifest)
}

/// `_verify_manifest_context`: this home's Codex manifest, at the path its
/// config target names.
fn verify_context(manifest: &Map<String, Value>, home: &Path, path: &Path) -> Checked<()> {
    let object = |name: &str| manifest.get(name).and_then(Value::as_object);
    if manifest.get("schema_version").and_then(Value::as_i64) != Some(MANIFEST_SCHEMA_VERSION)
        || manifest.get("harness").and_then(Value::as_str) != Some("codex")
    {
        return Err(UNAUTHENTICATED);
    }
    let runtime_home = object("context")
        .and_then(|context| context.get("runtime_guard_home"))
        .and_then(Value::as_str);
    if runtime_home != home.to_str() {
        return Err(UNAUTHENTICATED);
    }
    let target = object("config")
        .and_then(|config| config.get("target"))
        .and_then(Value::as_str)
        .map(Path::new)
        .filter(|target| target.is_absolute())
        .ok_or(UNAUTHENTICATED)?;
    let digest = hex::encode(Sha256::digest(
        canonical(target).as_os_str().as_encoded_bytes(),
    ));
    let expected = home
        .join("managed")
        .join("codex")
        .join(format!("hooks-{}.manifest.json", &digest[..24]));
    if canonical(&expected) != canonical(path) {
        return Err(UNAUTHENTICATED);
    }
    Ok(())
}

fn manifest_bridge_path(manifest: &Map<String, Value>) -> Checked<&str> {
    bridge_path(manifest)?.ok_or(UNAUTHENTICATED)
}

/// The recorded path of a generation's `bridge` file, if it records one.
fn bridge_path(generation: &Map<String, Value>) -> Checked<Option<&str>> {
    let packaged = generation
        .get("packaged_files")
        .and_then(Value::as_array)
        .ok_or(UNAUTHENTICATED)?;
    let bridge = packaged
        .iter()
        .find(|identity| identity.get("role").and_then(Value::as_str) == Some("bridge"));
    match bridge {
        None => Ok(None),
        Some(identity) => identity
            .get("path")
            .and_then(Value::as_str)
            .map(Some)
            .ok_or(UNAUTHENTICATED),
    }
}

/// `_selected_launch_generation` and `_verify_registered_bridge_argv`: the
/// authenticated generation that registered exactly this argv.
fn select_generation<'a>(
    manifest: &'a Map<String, Value>,
    current: &[&str; 3],
) -> Checked<&'a Map<String, Value>> {
    let list = |name: &str| match manifest.get(name) {
        None => Ok(&[][..]),
        Some(Value::Array(items)) if items.len() <= MAX_GENERATIONS => Ok(items.as_slice()),
        Some(_) => Err(UNAUTHENTICATED),
    };
    let retained = list("retained_bridge_generations")?;
    let allowed = list("compatible_bridge_argv_sha256")?;
    let well_formed = |value: &Value| {
        value.as_str().is_some_and(|text| {
            text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
    };
    if !allowed.iter().all(well_formed) {
        return Err(UNAUTHENTICATED);
    }
    let candidates = std::iter::once(Ok(manifest)).chain(
        retained
            .iter()
            .rev()
            .map(|item| item.as_object().ok_or(UNAUTHENTICATED)),
    );
    for (index, candidate) in candidates.enumerate() {
        let candidate = candidate?;
        let Some(bridge) = bridge_path(candidate)? else {
            continue;
        };
        let expected = [bridge, current[1], current[2]];
        if !registers(candidate, &expected)? {
            continue;
        }
        if index == 0 || allowed.iter().any(|hash| hash == &argv_sha256(&expected)) {
            if candidate.get("installation_id") != manifest.get("installation_id")
                || candidate.get("context") != manifest.get("context")
            {
                return Err(UNAUTHENTICATED);
            }
            return Ok(candidate);
        }
    }
    // A registration the current layout does not list is accepted only by
    // the compatibility hash install recorded for it.
    if allowed.iter().any(|hash| hash == &argv_sha256(current)) {
        return Ok(manifest);
    }
    Err(UNAUTHENTICATED)
}

/// Whether every event of `generation` registers `expected`.
fn registers(generation: &Map<String, Value>, expected: &[&str; 3]) -> Checked<bool> {
    let events = generation
        .get("events")
        .and_then(Value::as_array)
        .filter(|events| !events.is_empty())
        .ok_or(UNAUTHENTICATED)?;
    let mut all = true;
    for event in events {
        let argv = event
            .get("argv")
            .and_then(Value::as_array)
            .ok_or(UNAUTHENTICATED)?;
        all &= bridge_argv(argv) == expected.as_slice();
    }
    Ok(all)
}

/// `python_bridge_argv`: the legacy Python argv inside a native prefix.
fn bridge_argv(argv: &[Value]) -> &[Value] {
    let prefixed = argv.len() > 3
        && argv[0].as_str().is_some_and(|first| !first.is_empty())
        && argv[1].as_str() == Some(BRIDGE_COMMAND);
    if prefixed {
        &argv[2..]
    } else {
        argv
    }
}

/// `bridge_argv_sha256`: SHA-256 of the argv as ASCII-only compact JSON.
fn argv_sha256(argv: &[&str; 3]) -> String {
    let mut text = String::from("[");
    for (index, item) in argv.iter().enumerate() {
        if index > 0 {
            text.push(',');
        }
        let quoted = serde_json::to_string(item).unwrap_or_default();
        for unit in quoted.chars() {
            if unit.is_ascii() {
                text.push(unit);
            } else {
                let mut buffer = [0u16; 2];
                for half in unit.encode_utf16(&mut buffer) {
                    text.push_str(&format!("\\u{half:04x}"));
                }
            }
        }
    }
    text.push(']');
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Every recorded file, each role once, is still the file install recorded.
fn verify_packaged_files(generation: &Map<String, Value>) -> Result<(), String> {
    let packaged = generation
        .get("packaged_files")
        .and_then(Value::as_array)
        .ok_or(UNAUTHENTICATED)?;
    let mut roles = Vec::new();
    for identity in packaged {
        let role = identity
            .get("role")
            .and_then(Value::as_str)
            .ok_or(UNAUTHENTICATED)?;
        if roles.contains(&role) {
            return Err(UNAUTHENTICATED.to_owned());
        }
        roles.push(role);
        verify_regular(identity)?;
    }
    Ok(())
}

/// The config's start and fallback commands are the authenticated ones, run
/// by the authenticated interpreter.
fn verify_commands(
    generation: &Map<String, Value>,
    interpreter: &Value,
    config: &Value,
) -> Checked<()> {
    for (section, field) in [
        ("fallback", "fallback_command"),
        ("daemon_start", "start_command"),
    ] {
        let recorded = generation
            .get(section)
            .and_then(Value::as_object)
            .ok_or(UNAUTHENTICATED)?;
        let argv = recorded
            .get("argv")
            .filter(|argv| argv.as_array().is_some_and(|items| !items.is_empty()));
        if argv.is_none()
            || argv != config.get(field)
            || recorded.get("interpreter") != Some(interpreter)
        {
            return Err(UNAUTHENTICATED);
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "codex_hook_bridge_trust_tests.rs"]
mod tests;
