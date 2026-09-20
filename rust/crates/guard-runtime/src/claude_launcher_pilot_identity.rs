//! Private installed registration authentication, independent of daemon availability.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use super::files::{private_text, read_file, verify_file};
use super::{auth, Failure, Result};

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::identity("claude_pilot_record_invalid"))
}

fn authenticate_record(record: &Value, guard_home: &Path) -> Result<()> {
    let secret: Value = serde_json::from_str(&private_text(
        &guard_home.join("managed/codex/hook-manifest.key"),
        4096,
    )?)
    .map_err(|_| Failure::identity("claude_pilot_manifest_key_invalid"))?;
    let encoded = text(&secret, "key")?;
    let key = crate::approval::approval_v4_crypto::decode_base64url(
        encoded.trim_end_matches('='),
        32,
        "claude_pilot_manifest_key_invalid",
    )
    .map_err(|message| Failure::identity(&message))?;
    if key.len() != 32
        || encoded
            != format!(
                "{}=",
                crate::approval::approval_v4_crypto::encode_base64url(&key)
            )
        || secret.get("schema_version").and_then(Value::as_u64) != Some(1)
        || record.get("installation_id") != secret.get("installation_id")
    {
        return Err(Failure::identity("claude_pilot_manifest_key_invalid"));
    }
    let mut unsigned = record
        .as_object()
        .cloned()
        .ok_or_else(|| Failure::identity("claude_pilot_record_invalid"))?;
    let integrity = unsigned
        .remove("authentication")
        .ok_or_else(|| Failure::identity("claude_pilot_record_unsigned"))?;
    if integrity.get("integrity_version").and_then(Value::as_u64) != Some(1)
        || integrity.get("integrity_key_id") != secret.get("key_id")
    {
        return Err(Failure::identity("claude_pilot_record_key_mismatch"));
    }
    let material = serde_json::json!({
        "domain": "hol-guard.local-authority-integrity.v1", "integrity_version": 1,
        "payload": unsigned, "purpose": "claude-native-launcher-pilot",
        "signed_at": text(&integrity, "signed_at")?,
    });
    let canonical = auth::canonical(&material)?;
    let purpose_key = crate::hmac_sha256(
        &key,
        b"hol-guard.local-authority-integrity.v1\0",
        b"claude-native-launcher-pilot",
    );
    let mac = hex::encode(crate::hmac_sha256(&purpose_key, b"", canonical.as_bytes()));
    let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    if !crate::constant_time_eq(text(&integrity, "payload_mac")?.as_bytes(), mac.as_bytes())
        || !crate::constant_time_eq(
            text(&integrity, "payload_hash")?.as_bytes(),
            digest.as_bytes(),
        )
    {
        return Err(Failure::identity(
            "claude_pilot_record_authentication_failed",
        ));
    }
    Ok(())
}

pub(super) struct Registration {
    pub(super) record: Value,
    pub(super) path: PathBuf,
}

pub(super) fn load_registration(path: &Path, event: &str) -> Result<Registration> {
    if !["PreToolUse", "PostToolUse"].contains(&event) || !path.is_absolute() {
        return Err(Failure::identity("claude_pilot_registration_invalid"));
    }
    let guard_home = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| Failure::identity("claude_pilot_record_location_invalid"))?;
    if path != guard_home.join("managed/claude-pilot/launcher.json")
        || guard_home.canonicalize().ok().as_deref() != Some(guard_home)
    {
        return Err(Failure::identity("claude_pilot_record_location_invalid"));
    }
    let record: Value = serde_json::from_str(&private_text(path, 1_000_000)?)
        .map_err(|_| Failure::identity("claude_pilot_record_invalid"))?;
    authenticate_record(&record, guard_home)?;
    if text(&record, "schema")? != "guard-claude-launcher-pilot.v1"
        || Path::new(text(&record, "guard_home")?) != guard_home
    {
        return Err(Failure::identity(
            "claude_pilot_record_installation_changed",
        ));
    }
    let files = record
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| Failure::identity("claude_pilot_files_missing"))?;
    for binding in files.values() {
        verify_file(binding)?;
    }
    let runtime = files
        .get("runtime")
        .ok_or_else(|| Failure::identity("claude_pilot_runtime_missing"))?;
    if std::env::current_exe().map_err(Failure::io)? != Path::new(text(runtime, "resolved")?) {
        return Err(Failure::identity("claude_pilot_runtime_self_mismatch"));
    }
    let manifest_binding = files
        .get("manifest")
        .ok_or_else(|| Failure::identity("claude_pilot_manifest_missing"))?;
    let manifest: Value = serde_json::from_slice(&read_file(
        Path::new(text(manifest_binding, "path")?),
        65536,
        false,
    )?)
    .map_err(|_| Failure::identity("claude_pilot_manifest_invalid"))?;
    let capabilities = serde_json::to_value(crate::capabilities())
        .map_err(|_| Failure::identity("claude_pilot_capabilities_invalid"))?;
    if manifest["schema"] != "hol-guard-native-runtime.v1"
        || manifest["runtime_sha256"] != runtime["sha256"]
        || manifest["runtime_size"] != runtime["size"]
        || manifest["package_version"] != capabilities["runtime_version"]
        || manifest["source_sha"] != capabilities["build_sha"]
        || manifest["rule_digest"] != capabilities["rule_digest"]
        || manifest["protocol_version"] != capabilities["protocol_version"]
    {
        return Err(Failure::identity("claude_pilot_manifest_runtime_mismatch"));
    }
    let configuration = read_file(Path::new(text(&record, "configuration")?), 1_000_000, false)?;
    if hex::encode(Sha256::digest(&configuration)) != text(&record, "registration_sha256")? {
        return Err(Failure::identity("claude_pilot_registration_changed"));
    }
    let configuration: Value = serde_json::from_slice(&configuration)
        .map_err(|_| Failure::identity("claude_pilot_registration_invalid"))?;
    let expected = serde_json::json!([
        text(runtime, "path")?,
        "claude-hook-pilot",
        "--registration",
        path.to_string_lossy(),
        "--event",
        event
    ]);
    if record["argv"][event] != expected {
        return Err(Failure::identity("claude_pilot_argv_mismatch"));
    }
    let groups = configuration["hooks"][event]
        .as_array()
        .ok_or_else(|| Failure::identity("claude_pilot_registration_missing"))?;
    let count = groups
        .iter()
        .filter_map(|group| group["hooks"].as_array())
        .flatten()
        .filter(|handler| {
            let mut argv = vec![handler["command"].clone()];
            if let Some(args) = handler["args"].as_array() {
                argv.extend(args.clone());
            }
            Value::Array(argv) == expected
        })
        .count();
    if count != 1 {
        return Err(Failure::identity(
            "claude_pilot_registration_missing_or_ambiguous",
        ));
    }
    Ok(Registration {
        record,
        path: path.to_owned(),
    })
}
